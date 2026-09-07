# Capsaicin — developer convenience targets.
BINARY   := capsaicin
PKG      := ./cmd/capsaicin
GOFLAGS  ?=
LDFLAGS  := -s -w

.PHONY: all build install test race cover lint vet fmt tidy clean docker run help

all: build ## Build the binary

build: ## Compile the capsaicin binary into ./bin
	@mkdir -p bin
	CGO_ENABLED=0 go build $(GOFLAGS) -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

install: ## go install the binary into GOBIN
	go install $(GOFLAGS) -ldflags "$(LDFLAGS)" $(PKG)

test: ## Run the unit test suite
	go test ./... -count=1

race: ## Run the suite under the race detector
	go test ./... -race -count=1

cover: ## Report total statement coverage
	go test ./... -coverprofile=coverage.out -covermode=atomic
	go tool cover -func=coverage.out | tail -1

lint: ## Run golangci-lint (must be installed)
	golangci-lint run ./...

vet: ## Run go vet
	go vet ./...

fmt: ## Format all Go sources
	gofmt -w internal/ cmd/

tidy: ## Tidy go.mod / go.sum
	go mod tidy

docker: ## Build the container image
	docker build -t capsaicin:latest .

run: build ## Build then show help
	./bin/$(BINARY) --help

clean: ## Remove build artifacts
	rm -rf bin coverage.out

help: ## List available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'
