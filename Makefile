# Determine root directory
ROOT_DIR=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

# Gather all .go files for use in dependencies below
GO_FILES=$(shell find $(ROOT_DIR) -name '*.go')

# Load .env file if it exists
-include .env

.PHONY: mod-tidy test format lint clean

mod-tidy:
	# Needed to fetch new dependencies and add them to go.mod
	@go mod tidy

test:
	@echo "Running tests..."
	@set -a && [ -f .env ] && . ./.env; set +a && go test -v -race ./...

format: golines
	@go fmt ./...
	@gofmt -s -w $(GO_FILES)

golines:
	@golines -w --ignore-generated --chain-split-dots --max-len=80 --reformat-tags .

lint:
	@echo "Running golangci-lint..."
	@golangci-lint run

lint-fix:
	@echo "Running golangci-lint with auto-fix..."
	@golangci-lint run --fix

clean:
	@go clean -testcache