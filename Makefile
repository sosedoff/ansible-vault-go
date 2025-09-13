.PHONY: setup deps test

setup:
	go mod download

deps:
	go install gotest.tools/gotestsum@v1.13.0

test:
	gotestsum --format=testname -- -race -cover -coverprofile=cover.out  ./...
