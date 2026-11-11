VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
IMAGE ?= ghcr.io/nicholasjackson/vault-estate

.PHONY: build
build: ## Build bin/vault-estate for this machine
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/vault-estate .

.PHONY: install
install: ## Install vault-estate into $GOBIN (or $GOPATH/bin)
	CGO_ENABLED=0 go install -trimpath -ldflags "$(LDFLAGS)" .

.PHONY: test
test: ## Run the unit tests
	go vet ./...
	go test ./...

.PHONY: integration
integration: ## Run the apply integration tests against throwaway dev Vault containers (needs docker)
	VAULT_ESTATE_INTEGRATION=1 go test ./vaultapply/ -run Apply -count=1 -v

.PHONY: docker
docker: ## Build the container image for this machine
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) .

.PHONY: help
help: ## List the targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  %-12s %s\n", $$1, $$2}'
