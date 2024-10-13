.PHONY: test
test: 
	go test ./... -v

.DEFAULT_GOAL := dev
