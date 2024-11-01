.PHONY: test
test: 
	go test ./... -v
lint: 
	GOFLAGS=-buildvcs=false golangci-lint run --timeout 5m0s -v
.DEFAULT_GOAL := dev
