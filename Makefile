VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/adeoluo/mcp-security-scanner/internal/cli.Version=$(VERSION)
COVER_MIN ?= 80

CORPUS ?= ../.bench-data/mcp-security-scanner/corpus
PRIVATE ?= ../.bench-data/mcp-security-scanner/private
PLANTED ?= ../.bench-data/mcp-security-scanner/planted

.PHONY: help all build dist demo-server test race vet fmt fmt-check coverage fuzz microbench bench compare corpus precision speed rules-doc diagram docker demo clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

all: fmt-check vet coverage build ## Full local gate (mirror of continuous integration)

build: ## Build bin/mcpscan
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/mcpscan ./cmd/mcpscan

PLATFORMS ?= linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

dist: ## Cross-compile release archives and SHA256SUMS into dist/
	rm -rf dist && mkdir -p dist
	for p in $(PLATFORMS); do \
	  os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
	  name=mcpscan_$(VERSION)_$${os}_$${arch}; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$$name/mcpscan$$ext ./cmd/mcpscan || exit 1; \
	  cp LICENSE README.md dist/$$name/; \
	  if [ $$os = windows ]; then (cd dist && zip -qr $$name.zip $$name); else tar -C dist -czf dist/$$name.tar.gz $$name; fi; \
	  rm -rf dist/$$name; \
	done
	cd dist && shasum -a 256 mcpscan_* > SHA256SUMS

demo-server: ## Build bin/mcp-demo-server (inert demo MCP server)
	go build -trimpath -o bin/mcp-demo-server ./cmd/mcp-demo-server

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

microbench: ## Go microbenchmarks
	go test -run '^$$' -bench . -benchmem ./internal/...

bench: build ## Planted-vulnerability and tool-poisoning benchmarks (mcpscan only)
	./bin/mcpscan bench

compare: build ## Planted benchmark with Semgrep and Bandit (writes benchmarks/results/planted.*)
	uv run --project benchmarks python benchmarks/compare_planted.py --mcpscan bin/mcpscan --work $(PLANTED)

corpus: build ## Scan the cloned corpus (writes benchmarks/results/corpus.json)
	uv run --project benchmarks python benchmarks/corpus/scan_corpus.py --corpus $(CORPUS) --private $(PRIVATE)

precision: ## Score the hand labels against current corpus findings (writes benchmarks/results/precision.*)
	uv run --project benchmarks python benchmarks/precision/score.py --private $(PRIVATE) --current corpus_findings.jsonl

speed: build ## mcpscan and Semgrep on 20 corpus repositories (writes benchmarks/results/speed.json)
	uv run --project benchmarks python benchmarks/corpus/speed.py --corpus $(CORPUS) --repos 20

rules-doc: build ## Regenerate docs/RULES.md
	./bin/mcpscan rules --format markdown > docs/RULES.md

diagram: ## Render the architecture diagram
	npx -y @mermaid-js/mermaid-cli -i docs/architecture/architecture.mmd -o docs/architecture/architecture.svg \
	  -c docs/architecture/mermaid.config.json -b transparent

docker: ## Build the container image
	docker build --build-arg VERSION=$(VERSION) -t mcpscan:$(VERSION) .

demo: build demo-server ## Record the demo GIFs with vhs
	for t in docs/demo/*.tape; do vhs $$t; done

clean: ## Remove build artifacts
	rm -rf bin dist coverage.out
