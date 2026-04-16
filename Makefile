.PHONY: test run build

run:
	@go run . \
	 -logstream "states/orquestrador" \
	 -msg "1234" \
	 -region "us-east-1" \
	 -start "21/03/2026T00:00:00" \
	 -end "21/03/2026T23:59:59" \