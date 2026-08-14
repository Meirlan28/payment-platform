.DEFAULT_GOAL := help

COMPOSE := docker compose
GO_IMAGE := golang:1.26.5-bookworm

.PHONY: help generate fmt lint test test-unit test-integration test-chaos benchmark up down logs migrate

help:
	@awk 'BEGIN {FS = ":.*##"; printf "Targets:\n"} /^[a-zA-Z_-]+:.*?##/ {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

generate: ## Generate protobuf and Go bindings in a pinned build container
	$(COMPOSE) run --rm generate

fmt: ## Format Go sources in the pinned toolchain
	docker run --rm -v "$(CURDIR):/src:z" -w /src $(GO_IMAGE) /usr/local/go/bin/gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

lint: ## Run vet and protobuf lint
	$(COMPOSE) run --rm go-toolchain go vet ./...
	$(COMPOSE) run --rm buf lint

test: test-unit test-integration ## Run the complete correctness suite

test-unit: ## Run all hermetic unit, property and deterministic chaos tests
	$(COMPOSE) run --rm go-toolchain go test -race -count=1 ./...

test-integration: up migrate ## Run CockroachDB/Kafka integration tests
	$(COMPOSE) run --rm go-toolchain go test -race -count=1 -tags=integration ./internal/...

test-chaos: up migrate ## Run fault-injection scenarios
	$(COMPOSE) run --rm go-toolchain go test -race -count=1 ./tests/chaos/...

benchmark: up migrate ## Run the local benchmark and emit measured JSON
	$(COMPOSE) run --rm go-toolchain go test -run '^$$' -bench=. -benchmem ./benchmarks/...

up: ## Start the production-component integration topology
	$(COMPOSE) up -d --wait cockroach-1 cockroach-2 cockroach-3 kafka-1 kafka-2 kafka-3

down: ## Stop the integration topology without deleting named volumes
	$(COMPOSE) down

logs: ## Follow service logs
	$(COMPOSE) logs -f --tail=200

migrate: ## Apply ordered CockroachDB migrations
	$(COMPOSE) run --rm migrator
