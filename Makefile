# traffic-twin build entry points. Run `make help` for the list of targets.

SHELL := /bin/sh
.DEFAULT_GOAL := build

BIN_DIR  := bin
BINARY   := $(BIN_DIR)/tt
UI_DIR   := ui
UI_DIST  := internal/ui/dist

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)
GOFLAGS_BUILD := -trimpath -ldflags "$(LDFLAGS)"

export CGO_ENABLED := 0

UI_SRC := $(shell find $(UI_DIR)/src -type f 2>/dev/null) \
	$(UI_DIR)/index.html $(UI_DIR)/vite.config.ts $(UI_DIR)/svelte.config.js \
	$(UI_DIR)/tsconfig.json $(UI_DIR)/package.json

# Packages whose tests run under the race detector in CI: the concurrent ones
# (exporters, fleet, intake, egress, mock runtime, store, server) and the Go SDK.
RACE_PKGS := ./internal/sourceclient/... ./internal/fleet/... ./internal/intake/... \
	./internal/egress/... ./internal/mock/... ./internal/export/... ./internal/store/... \
	./internal/server/... ./internal/core/... ./internal/keyguard/... ./internal/sanitizer/... \
	./sdk/go/...

.PHONY: help build ui go test race vet lint fmt-check tidy-check build-all vectors clean \
	ci-local sdk-package actionlint goreleaser-check perf

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-z-]+:.*## / {printf "  %-16s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ui go ## Build the UI, then the tt binary (bin/tt)

ui: $(UI_DIST)/index.html ## Build the UI into internal/ui/dist

$(UI_DIR)/node_modules/.package-lock.json: $(UI_DIR)/package.json $(UI_DIR)/package-lock.json
	cd $(UI_DIR) && npm ci --no-audit --no-fund --ignore-scripts

$(UI_DIST)/index.html: $(UI_DIR)/node_modules/.package-lock.json $(UI_SRC)
	cd $(UI_DIR) && npm run build
	@touch $(UI_DIST)/.gitkeep

go: ## Build the tt binary only (embeds whatever is in internal/ui/dist)
	@mkdir -p $(BIN_DIR)
	go build $(GOFLAGS_BUILD) -o $(BINARY) ./cmd/tt

test: ## Run Go tests
	go test -count=1 ./...

race: ## Run the Go tests of the concurrent packages under the race detector (needs cgo)
	CGO_ENABLED=1 go test -count=1 -race -timeout 45m $(RACE_PKGS)

vet: ## Run go vet
	go vet ./...

fmt-check: ## Fail if any Go file needs gofmt
	@unformatted="$$(gofmt -l $$(find . -name '*.go' -not -path './ui/*' -not -path './.claude/*' -not -path '*/node_modules/*'))"; \
	if [ -n "$$unformatted" ]; then echo "gofmt needed on:"; echo "$$unformatted"; exit 1; fi

tidy-check: ## Fail if go.mod/go.sum are not tidy
	go mod tidy -diff

build-all: ## Compile every Go package (cgo-free)
	go build ./...

lint: vet ## gofmt check, go vet, staticcheck (if installed)
	@unformatted="$$(gofmt -l $$(git ls-files '*.go' 2>/dev/null || find . -name '*.go' -not -path './ui/*'))"; \
	if [ -n "$$unformatted" ]; then echo "gofmt needed on:"; echo "$$unformatted"; exit 1; fi
	@if command -v staticcheck >/dev/null 2>&1; then staticcheck ./...; \
	else echo "staticcheck not installed, skipping"; fi

PERF_SCALE ?= ci
PERF_OUT   ?= perf-report
perf: ## Large-dataset performance run (PERF_SCALE=smoke|ci|full), fails when a budget of test/perf/budgets.json is exceeded
	go run ./test/perf/ttperf -scale $(PERF_SCALE) -budgets test/perf/budgets.json -out $(PERF_OUT)

vectors: ## Check the sanitizer conformance vectors with the reference generator (Python 3 stdlib)
	python3 conformance/ref/gen_vectors.py --check
	python3 conformance/ref/run.py
	python3 conformance/ref/leakcheck.py

ci-local: ## Run the CI checks locally, Docker for missing runtimes (ONLY="go ui" SKIP=... MATRIX=full)
	@ONLY="$(ONLY)" SKIP="$(SKIP)" MATRIX="$(or $(MATRIX),default)" sh scripts/ci-local.sh

sdk-package: ## Packaging dry-run of every SDK into dist/sdk (publishes nothing); toolchains must be installed
	@for s in node python java dotnet php go; do sh scripts/sdk-package.sh $$s dist/sdk || exit 1; done

actionlint: ## Lint the GitHub Actions workflows (Docker)
	docker run --rm -v "$$PWD":/repo -w /repo rhysd/actionlint:1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667

goreleaser-check: ## Validate .goreleaser.yaml (Docker)
	docker run --rm -v "$$PWD":/repo -w /repo --entrypoint goreleaser goreleaser/goreleaser:v2.19.0 check

clean: ## Remove build outputs
	rm -rf $(BIN_DIR) dist
	find $(UI_DIST) -mindepth 1 ! -name .gitkeep -exec rm -rf {} +
