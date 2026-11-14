.PHONY: build test test-race vet lint format-check security actionlint docs-check release-check release-snapshot check tools clean run docker docker-context-check docker-smoke eval eval-record

BINARY := threat-bot
VERSION ?= dev
REVISION ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
CONTAINER_ENGINE ?= docker
IMAGE ?= threat-bot:local
export GOWORK := off
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.revision=$(REVISION)
TOOLS := $(CURDIR)/.tools/bin
GOLANGCI_LINT_VERSION := v2.15.0
GOVULNCHECK_VERSION := v1.3.0
ACTIONLINT_VERSION := v1.7.12
GITLEAKS_VERSION := v8.30.1
GORELEASER_VERSION := v2.20.2
GORELEASER ?= $(TOOLS)/goreleaser

build:
	CGO_ENABLED=0 go build -trimpath -tags timetzdata -ldflags="$(LDFLAGS)" -o $(BINARY) ./cmd/threat-bot

test:
	go test -timeout=10m ./...

test-race:
	go test -race -timeout=10m ./...

vet:
	go vet ./...

# Missing tools and lint failures are errors; use `make tools` first.
lint:
	$(TOOLS)/golangci-lint run --config .github/.golangci.yml

format-check:
	python3 .github/scripts/check-format.py

security:
	$(TOOLS)/govulncheck ./...
	$(TOOLS)/gitleaks dir --redact --no-banner .

actionlint:
	$(TOOLS)/actionlint

docs-check: build
	python3 .github/scripts/check-docs.py
	./$(BINARY) -config config.example.yaml config validate

release-check:
	$(GORELEASER) check --config .github/goreleaser.yml

release-snapshot:
	$(GORELEASER) release --snapshot --clean --config .github/goreleaser.yml

check: format-check test-race vet build lint actionlint docs-check release-check security

tools:
	GOBIN=$(TOOLS) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	GOBIN=$(TOOLS) go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	GOBIN=$(TOOLS) go install github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)
	GOBIN=$(TOOLS) go install github.com/zricethezav/gitleaks/v8@$(GITLEAKS_VERSION)
	GOBIN=$(TOOLS) go install github.com/goreleaser/goreleaser/v2@$(GORELEASER_VERSION)

clean:
	rm -f $(BINARY)

run: build
	./$(BINARY) run

docker:
	$(CONTAINER_ENGINE) build --platform linux/amd64 --build-arg VERSION=$(VERSION) --build-arg REVISION=$(REVISION) -t $(IMAGE) .

docker-context-check:
	python3 .github/scripts/check-container-context.py $(CONTAINER_ENGINE)

docker-smoke: docker-context-check docker
	$(CONTAINER_ENGINE) run --rm --platform linux/amd64 --network none $(IMAGE) version
	$(CONTAINER_ENGINE) run --rm --platform linux/amd64 --network none -v $(CURDIR)/config.example.yaml:/app/config.yaml:ro $(IMAGE) -config /app/config.yaml config validate

eval:
	go run ./cmd/eval

eval-record:
	go run ./cmd/eval -record
