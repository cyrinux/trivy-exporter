.PHONY: build run test clean docker-build docker-run lint fmt help

# Variables
APP_NAME=trivy-exporter
DOCKER_IMAGE=ghcr.io/cyrinux/$(APP_NAME)
VERSION?=latest
GO_FILES=$(shell find . -name '*.go' -type f)

help: ## Display this help screen
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the binary
	@echo "Building $(APP_NAME)..."
	go build -ldflags="-w -s" -o $(APP_NAME) ./cmd/trivy-exporter
	@echo "Build complete: ./$(APP_NAME)"

run: ## Run the application
	@echo "Running $(APP_NAME)..."
	go run ./cmd/trivy-exporter

test: ## Run tests
	@echo "Running tests..."
	go test -v -race -coverprofile=coverage.txt -covermode=atomic ./...

test-coverage: test ## Run tests with coverage report
	@echo "Generating coverage report..."
	go tool cover -html=coverage.txt -o coverage.html
	@echo "Coverage report generated: coverage.html"

lint: ## Run linter (requires golangci-lint)
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed. Install it from https://golangci-lint.run/usage/install/"; \
		exit 1; \
	fi

fmt: ## Format code
	@echo "Formatting code..."
	go fmt ./...
	@echo "Code formatted"

vet: ## Run go vet
	@echo "Running go vet..."
	go vet ./...

mod-tidy: ## Tidy go modules
	@echo "Tidying modules..."
	go mod tidy

mod-download: ## Download dependencies
	@echo "Downloading dependencies..."
	go mod download

clean: ## Clean build artifacts
	@echo "Cleaning..."
	rm -f $(APP_NAME)
	rm -f coverage.txt coverage.html
	rm -rf dist/
	@echo "Clean complete"

docker-build: ## Build Docker image
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE):$(VERSION) .
	@echo "Docker image built: $(DOCKER_IMAGE):$(VERSION)"

docker-run: ## Run Docker container
	@echo "Running Docker container..."
	docker run --rm \
		-p 8080:8080 \
		-v /var/run/docker.sock:/var/run/docker.sock:ro \
		-v trivy-cache:/root/.cache/trivy \
		-v trivy-results:/results \
		$(DOCKER_IMAGE):$(VERSION)

docker-compose-up: ## Start with docker-compose
	docker-compose up -d

docker-compose-down: ## Stop docker-compose
	docker-compose down

docker-compose-logs: ## Show docker-compose logs
	docker-compose logs -f trivy-exporter

install-tools: ## Install development tools
	@echo "Installing development tools..."
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "Installing golangci-lint..."; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	fi
	@echo "Tools installed"

release-check: test lint vet ## Run all checks before release
	@echo "✅ All checks passed! Ready for release."

all: clean fmt vet test build ## Run clean, format, vet, test, and build

.DEFAULT_GOAL := help
