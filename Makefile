.PHONY: test lint build dev
.DEFAULT_GOAL := dev

EXAMPLE_DIRS := $(shell find examples -name "go.mod" -exec dirname {} \;)

define generate_build_target
.PHONY: build-$(1)
build-$(1):
	cd $(1) && go build ./...
endef


#for each a seperate build target
$(foreach dir,$(EXAMPLE_DIRS),$(eval $(call generate_build_target,$(dir))))

# that is called here
build: $(patsubst %,build-%,$(EXAMPLE_DIRS))

test: 
	go test ./... -v

lint: 
	GOFLAGS=-buildvcs=false golangci-lint run --timeout 5m0s -v


dev:
	@echo "Development target (customize as needed)"
