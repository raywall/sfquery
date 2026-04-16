package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

const (
	dateLayout       = "02/01/2006T15:04:05"
	queryPollDelay   = 2 * time.Second
	queryPollTimeout = 3 * time.Minute
	maxLogGroups     = 50
)

type options struct {
	logStream string
	msg       string
	region    string
	start     string
	end       string
	logGroups multiFlag
	timeout   time.Duration
}

type multiFlag []string

func (m *multiFlag) String() string {
	return strings.Join(*m, ",")
}

func (m *multiFlag) Set(value string) error {
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			*m = append(*m, item)
		}
	}
	return nil
}

type stepResult struct {
	ExecutionARN string
	Timestamp    time.Time
}

func main() {
	ctx := context.Background()

	opts, err := parseOptions()
	if err != nil {
		log.Fatal(err)
	}

	start, err := parseDate(opts.start)
	if err != nil {
		log.Fatalf("data inicial invalida: %v", err)
	}

	end, err := parseDate(opts.end)
	if err != nil {
		log.Fatalf("data final invalida: %v", err)
	}

	if !end.After(start) {
		log.Fatal("a data final deve ser maior que a data inicial")
	}

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(opts.region))
	if err != nil {
		log.Fatalf("erro ao carregar configuracao da AWS: %v", err)
	}

	client := cloudwatchlogs.NewFromConfig(cfg)

	logGroups := []string(opts.logGroups)
	if len(logGroups) == 0 {
		logGroups, err = discoverLogGroups(ctx, client, end)
		if err != nil {
			log.Fatalf("erro ao listar grupos de log: %v", err)
		}
	}

	if len(logGroups) == 0 {
		log.Fatal("nenhum grupo de log encontrado na regiao informada")
	}

	arns, err := findExecutionARNs(ctx, client, logGroups, opts.logStream, opts.msg, start, end, opts.timeout)
	if err != nil {
		log.Fatalf("erro ao buscar execution_arn: %v", err)
	}

	if len(arns) == 0 {
		fmt.Println("Nenhum resultado encontrado. Revise as configuracoes informadas na solicitacao.")
		return
	}

	results, err := findFirstSteps(ctx, client, logGroups, arns, start, end, opts.timeout)
	if err != nil {
		log.Fatalf("erro ao buscar timestamp do primeiro step: %v", err)
	}

	if len(results) == 0 {
		fmt.Println("Nenhum resultado encontrado. Revise as configuracoes informadas na solicitacao.")
		return
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Timestamp.After(results[j].Timestamp)
	})

	fmt.Println("URLs localizadas:")
	for _, result := range results {
		fmt.Println(buildStepFunctionsURL(opts.region, result.ExecutionARN, result.Timestamp))
	}
}

func parseOptions() (options, error) {
	var opts options
	flag.StringVar(&opts.logStream, "logstream", "", "logstream onde deseja realizar a busca")
	flag.StringVar(&opts.msg, "msg", "", "valor que deseja buscar na mensagem")
	flag.StringVar(&opts.region, "region", "", "regiao da AWS a ser utilizada")
	flag.StringVar(&opts.start, "start", "", "data inicial da busca no formato dd/mm/aaaaTHH:MM:SS")
	flag.StringVar(&opts.end, "end", "", "data final da busca no formato dd/mm/aaaaTHH:MM:SS")
	flag.Var(&opts.logGroups, "log-group", "grupo de log a consultar; pode ser informado mais de uma vez ou separado por virgulas")
	flag.DurationVar(&opts.timeout, "timeout", queryPollTimeout, "tempo maximo de espera por query do CloudWatch")
	flag.Parse()

	missing := make([]string, 0, 5)
	if opts.logStream == "" {
		missing = append(missing, "logstream")
	}
	if opts.msg == "" {
		missing = append(missing, "msg")
	}
	if opts.region == "" {
		missing = append(missing, "region")
	}
	if opts.start == "" {
		missing = append(missing, "start")
	}
	if opts.end == "" {
		missing = append(missing, "end")
	}
	if len(missing) > 0 {
		return opts, fmt.Errorf("argumentos obrigatorios ausentes: %s", strings.Join(missing, ", "))
	}

	return opts, nil
}

func parseDate(value string) (time.Time, error) {
	return time.ParseInLocation(dateLayout, value, time.Local)
}

func discoverLogGroups(ctx context.Context, client *cloudwatchlogs.Client, queryEnd time.Time) ([]string, error) {
	var names []string
	var nextToken *string

	for {
		output, err := client.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, err
		}

		for _, group := range output.LogGroups {
			if group.LogGroupName != nil && logGroupCanContainTime(group, queryEnd) {
				names = append(names, *group.LogGroupName)
			}
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return names, nil
}

func logGroupCanContainTime(group types.LogGroup, queryEnd time.Time) bool {
	if group.LogGroupClass == types.LogGroupClassDelivery {
		return false
	}

	if group.CreationTime != nil {
		createdAt := time.UnixMilli(*group.CreationTime)
		if queryEnd.Before(createdAt) {
			return false
		}
	}

	if group.RetentionInDays != nil {
		retentionStart := time.Now().AddDate(0, 0, -int(*group.RetentionInDays))
		if queryEnd.Before(retentionStart) {
			return false
		}
	}

	return true
}

func findExecutionARNs(ctx context.Context, client *cloudwatchlogs.Client, logGroups []string, logStream, msg string, start, end time.Time, timeout time.Duration) ([]string, error) {
	query := fmt.Sprintf(`fields @timestamp, execution_arn, id
| filter strcontains(@logStream, '%s')
  and @message like /%s/
| display execution_arn
| sort @timestamp desc`, escapeLogInsightsString(logStream), escapeLogInsightsRegex(msg))

	unique := make(map[string]struct{})
	for _, groupChunk := range chunks(logGroups, maxLogGroups) {
		results, err := runQueryForLogGroups(ctx, client, groupChunk, query, start, end, timeout)
		if err != nil {
			return nil, err
		}

		for _, row := range results {
			arn := fieldValue(row, "execution_arn")
			if arn != "" {
				unique[arn] = struct{}{}
			}
		}
	}

	arns := make([]string, 0, len(unique))
	for arn := range unique {
		arns = append(arns, arn)
	}
	sort.Strings(arns)
	return arns, nil
}

func findFirstSteps(ctx context.Context, client *cloudwatchlogs.Client, logGroups []string, arns []string, start, end time.Time, timeout time.Duration) ([]stepResult, error) {
	resultsByARN := make(map[string]stepResult)

	for _, arn := range arns {
		query := fmt.Sprintf(`fields @timestamp, execution_arn, @message
| filter execution_arn = '%s'
  and id = 1
| sort @timestamp asc
| limit 1
| display execution_arn, @timestamp`, escapeLogInsightsString(arn))

		for _, groupChunk := range chunks(logGroups, maxLogGroups) {
			rows, err := runQueryForLogGroups(ctx, client, groupChunk, query, start, end, timeout)
			if err != nil {
				return nil, err
			}

			for _, row := range rows {
				timestamp, err := parseCloudWatchTimestamp(fieldValue(row, "@timestamp"))
				if err != nil {
					return nil, fmt.Errorf("timestamp invalido para %s: %w", arn, err)
				}

				current, found := resultsByARN[arn]
				if !found || timestamp.Before(current.Timestamp) {
					resultsByARN[arn] = stepResult{
						ExecutionARN: arn,
						Timestamp:    timestamp,
					}
				}
			}
		}
	}

	results := make([]stepResult, 0, len(resultsByARN))
	for _, result := range resultsByARN {
		results = append(results, result)
	}

	return results, nil
}

func runQueryForLogGroups(ctx context.Context, client *cloudwatchlogs.Client, logGroups []string, query string, start, end time.Time, timeout time.Duration) ([][]types.ResultField, error) {
	results, err := runQuery(ctx, client, logGroups, query, start, end, timeout)
	if err == nil {
		return results, nil
	}

	if !isRetryableLogGroupScopeError(err) {
		return nil, err
	}

	if len(logGroups) == 1 {
		if isTimeRangeLogGroupError(err) || isUnsupportedLogClassError(err) {
			log.Printf("ignorando log group %q: %v", logGroups[0], err)
			return nil, nil
		}

		return nil, err
	}

	middle := len(logGroups) / 2
	left, err := runQueryForLogGroups(ctx, client, logGroups[:middle], query, start, end, timeout)
	if err != nil {
		return nil, err
	}

	right, err := runQueryForLogGroups(ctx, client, logGroups[middle:], query, start, end, timeout)
	if err != nil {
		return nil, err
	}

	return append(left, right...), nil
}

func runQuery(ctx context.Context, client *cloudwatchlogs.Client, logGroups []string, query string, start, end time.Time, timeout time.Duration) ([][]types.ResultField, error) {
	output, err := client.StartQuery(ctx, &cloudwatchlogs.StartQueryInput{
		LogGroupNames: logGroups,
		QueryString:   aws.String(query),
		StartTime:     aws.Int64(start.Unix()),
		EndTime:       aws.Int64(end.Unix()),
	})
	if err != nil {
		return nil, err
	}
	if output.QueryId == nil {
		return nil, errors.New("CloudWatch nao retornou query id")
	}

	pollCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(queryPollDelay)
	defer ticker.Stop()

	for {
		select {
		case <-pollCtx.Done():
			_, _ = client.StopQuery(context.Background(), &cloudwatchlogs.StopQueryInput{
				QueryId: output.QueryId,
			})
			return nil, fmt.Errorf("timeout aguardando query %s", *output.QueryId)
		case <-ticker.C:
			queryOutput, err := client.GetQueryResults(ctx, &cloudwatchlogs.GetQueryResultsInput{
				QueryId: output.QueryId,
			})
			if err != nil {
				return nil, err
			}

			switch queryOutput.Status {
			case types.QueryStatusComplete:
				return queryOutput.Results, nil
			case types.QueryStatusFailed, types.QueryStatusCancelled, types.QueryStatusTimeout, types.QueryStatusUnknown:
				return nil, fmt.Errorf("query %s terminou com status %s", *output.QueryId, queryOutput.Status)
			}
		}
	}
}

func isRetryableLogGroupScopeError(err error) bool {
	return isTimeRangeLogGroupError(err) || isMixedLogClassError(err) || isUnsupportedLogClassError(err)
}

func isTimeRangeLogGroupError(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "malformedqueryexception") &&
		strings.Contains(message, "creation time") &&
		strings.Contains(message, "retention")
}

func isMixedLogClassError(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "invalidparameterexception") &&
		strings.Contains(message, "same log class")
}

func isUnsupportedLogClassError(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "log class") &&
		(strings.Contains(message, "not supported") || strings.Contains(message, "unsupported"))
}

func chunks(values []string, size int) [][]string {
	if len(values) == 0 {
		return nil
	}

	var result [][]string
	for start := 0; start < len(values); start += size {
		end := start + size
		if end > len(values) {
			end = len(values)
		}
		result = append(result, values[start:end])
	}
	return result
}

func fieldValue(row []types.ResultField, name string) string {
	for _, field := range row {
		if field.Field != nil && *field.Field == name && field.Value != nil {
			return *field.Value
		}
	}
	return ""
}

func parseCloudWatchTimestamp(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, errors.New("timestamp vazio")
	}

	layouts := []string{
		time.RFC3339Nano,
		"2006-01-02 15:04:05.000",
		"2006-01-02 15:04:05",
	}

	for _, layout := range layouts {
		if t, err := time.Parse(layout, value); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("formato nao reconhecido: %s", value)
}

func buildStepFunctionsURL(region, arn string, timestamp time.Time) string {
	return fmt.Sprintf(
		"https://%s.console.aws.amazon.com/states/home?region=%s#/express-executions/details/%s?startDate=%s",
		region,
		region,
		arn,
		timestamp.UTC().Format(time.RFC3339Nano),
	)
}

func escapeLogInsightsString(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, `'`, `\'`)
}

func escapeLogInsightsRegex(value string) string {
	value = regexp.QuoteMeta(value)
	return strings.ReplaceAll(value, `/`, `\/`)
}
