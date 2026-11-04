VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/adeoluo/mcp-security-scanner/internal/cli.Version=$(VERSION)
COVER_MIN ?= 80

.PHONY: help all build test race vet fmt fmt-check coverage fuzz bench clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

all: fmt-check vet coverage build ## Full local gate (mirror of continuous integration)

build: ## Build bin/mcpscan
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/mcpscan ./cmd/mcpscan

test: ## Run the tests
	go test ./...

race: ## Tests with the race detector
	go test -race ./...

vet: ## go vet
	go vet ./...

fmt: ## Format the code
	gofmt -w .

fmt-check: ## Fail if gofmt would change anything
	@test -z "$$(gofmt -l .)" || (gofmt -l . && echo "run make fmt" && exit 1)

coverage: ## Tests with the race detector and the coverage gate used in CI
	go test -race -count=1 -coverprofile=coverage.out -covermode=atomic ./...
	@go tool cover -func=coverage.out | tail -1
	@go tool cover -func=coverage.out | tail -1 | awk -v min=$(COVER_MIN) '{sub("%","",$$3); if ($$3+0 < min) {print "coverage " $$3 "% is below " min "%"; exit 1}}'

fuzz: ## Run each fuzz target for 30 seconds
	go test -run '^$$' -fuzz FuzzTokenize -fuzztime 30s ./internal/lexer
	go test -run '^$$' -fuzz FuzzCheckTool -fuzztime 30s ./internal/poison

bench: ## Go microbenchmarks
	go test -run '^$$' -bench . -benchmem ./internal/...

clean: ## Remove build artifacts
	rm -rf bin dist coverage.out
