.PHONY test
test: build-templ
	go test ./... -v

.DEFAULT_GOAL := dev  
