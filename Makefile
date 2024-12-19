.DEFAULT_GOAL := dev

.PHONY: build-basic
build-basic:
	cd examples/basic && go build ./...

.PHONY: build-validation
build-validation:
	cd examples/validation && go build ./...

.PHONY: build-m2m
build-m2m:
	cd examples/m2m && go build ./...

.PHONY: test-basic
test-basic:
	cd examples/basic && go test ./... -v

.PHONY: test-validation
test-validation:
	cd examples/validation && go test ./... -v

.PHONY: test-m2m
test-m2m:
	cd examples/m2m && go test ./... -v

.PHONY: lint-basic
lint-basic:
	cd examples/basic && GOFLAGS=-buildvcs=false golangci-lint run --timeout 5m0s -v

.PHONY: lint-validation
lint-validation:
	cd examples/validation && GOFLAGS=-buildvcs=false golangci-lint run --timeout 5m0s -v

.PHONY: lint-m2m
lint-m2m:
	cd examples/m2m && GOFLAGS=-buildvcs=false golangci-lint run --timeout 5m0s -v

.PHONY: build-examples
build-examples: build-basic build-validation build-m2m

.PHONY: test
test: test-basic test-validation test-m2m

.PHONY: lint
lint: lint-basic lint-validation lint-m2m

.PHONY: dev
dev:
	@echo "Development target (customize as needed)"
