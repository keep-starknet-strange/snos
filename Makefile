# Makefile for SNOS (Starknet OS) Project
# Provides convenient commands for building, testing, and development

# Default values
RPC_URL ?= https://pathfinder-mainnet.d.karnot.xyz
RPC_URL_SEPOLIA ?= https://pathfinder-sepolia.d.karnot.xyz
NETWORK ?= mainnet
BLOCK_NUMBERS ?= 2403992,2403993,2403994,2403995

# Define comma for clarity
comma := ,

# Convert comma-separated to space-separated
BLOCK_LIST := $(subst $(comma), ,$(BLOCK_NUMBERS))

# Get first and last values
FIRST := $(word 1,$(BLOCK_LIST))
LAST := $(word $(words $(BLOCK_LIST)),$(BLOCK_LIST))

# Create output file name
OUTPUT_FILE := $(FIRST)$(if $(filter-out $(FIRST),$(LAST)),_$(LAST))
OUTPUT_FILE_PATH := "./tmp/$(NETWORK)/$(OUTPUT_FILE).zip"

# Colors for output
BLUE := \033[36m
GREEN := \033[32m
YELLOW := \033[33m
RED := \033[31m
RESET := \033[0m

.PHONY: help build check test test-quick test-e2e test-pie test-errors test-single test-multi test-all clean lint fix setup env-check

# Default target
help: ## Show this help message
	@echo "$(BLUE)SNOS (Starknet OS) Makefile$(RESET)"
	@echo ""
	@echo "$(YELLOW)Available targets:$(RESET)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)Environment variables:$(RESET)"
	@echo "  SNOS_RPC_URL = $(RPC_URL)"
	@echo "  SNOS_BLOCKS  = $(BLOCK_NUMBERS)"
	@echo "  SNOS_NETWORK = $(NETWORK)"
	@echo "  SNOS_OUTPUT  = $(OUTPUT_FILE_PATH)"
	@echo ""
	@echo "$(YELLOW)Examples:$(RESET)"
	@echo "  make test-e2e"
	@echo "  make check-env  # Check environment"

## Building and Development
build: ## Build all crates in the workspace
	@echo "$(BLUE)Building SNOS workspace...$(RESET)"
	cargo build

check: ## Run cargo check on all crates
	@echo "$(BLUE)Checking code...$(RESET)"
	cargo check --workspace

clean: ## Clean build artifacts
	@echo "$(BLUE)Cleaning build artifacts...$(RESET)"
	cargo clean
	rm -rf ./tmp/

lint: ## Run clippy linter
	@echo "$(BLUE)Running clippy...$(RESET)"
	cargo clippy --workspace --tests --no-deps -- -D warnings

fix: ## Apply automatic fixes
	@echo "$(BLUE)Applying automatic fixes...$(RESET)"
	cargo fix --workspace --allow-dirty
	cargo fmt --all

fmt: ## Format code
	@echo "$(BLUE)Formatting code...$(RESET)"
	cargo fmt --all --check

## Testing
test-workspace: ## Run all workspace unit tests
	@echo "$(BLUE)Running workspace unit tests...$(RESET)"
	RUSTFLAGS="-D warnings" \
	SNOS_RPC_URL="$(RPC_URL)" \
	cargo test --workspace --lib -- --nocapture

test-e2e: ## Run simple parameterized PIE generation tests
	@echo "$(BLUE)Running simple PIE generation tests...$(RESET)"
	@echo "$(YELLOW)Using RPC: $(RPC_URL)$(RESET)"
	RUST_LOG=info \
	SNOS_RPC_URL="$(RPC_URL)" \
	SNOS_RPC_URL_SEPOLIA="$(RPC_URL_SEPOLIA)" \
	cargo test -p e2e-tests test_pie_generation -- --nocapture

test-all: test-workspace test-e2e ## Run all tests (unit + integration + e2e)

rpc-replay-seq:
	@echo "$(BLUE)Running RPC replay in sequential mode...$(RESET)"
	@echo "$(YELLOW)Using RPC: $(RPC_URL)$(RESET)"
	RUST_LOG=info \
	cargo run -p rpc-replay -- \
	--rpc-url "$(RPC_URL)" \
	--chain "mainnet"
	--start-block 1943704

test-ci: ## Run tests suitable for CI (no long-running e2e tests)
	@echo "$(BLUE)Running CI test suite...$(RESET)"
	$(MAKE) check
	$(MAKE) test-workspace

setup: ## Set up development environment
	@echo "$(BLUE)Setting up development environment...$(RESET)"
	@if [ ! -d "venv" ]; then \
		echo "$(YELLOW)Setting up Python environment...$(RESET)"; \
		./setup-scripts/setup-cairo.sh; \
	fi
	@echo "$(GREEN)Environment setup complete!$(RESET)"
	@echo "$(YELLOW)Remember to activate the environment: source ./snos-env/bin/activate$(RESET)"

activate: ## Show command to activate Python environment
	@echo "$(YELLOW)Run this command to activate the Cairo environment:$(RESET)"
	@echo "source ./venv/bin/activate"

## PIE Generation
generate-pie: ## Generate PIE for a specific block (requires BLOCK_NUMBERS)
ifndef BLOCK_NUMBERS
	@echo "$(RED)Error: BLOCK_NUMBERS is required$(RESET)"
	@echo "Usage: make generate-pie BLOCK_NUMBERS=12345"
	@exit 1
endif
	@echo "$(BLUE)Generating PIE for blocks $(SNOS_BLOCKS), output pie will be at $(OUTPUT_FILE_PATH)  $(RESET)"
	mkdir -p ./tmp
	RUST_LOG=info \
	SNOS_RPC_URL="$(RPC_URL)" \
	SNOS_NETWORK="$(NETWORK)" \
	SNOS_BLOCKS="$(BLOCK_NUMBERS)" \
	cargo run -p generate-pie -- --output $(OUTPUT_FILE_PATH)

## Development Shortcuts
dev-check: check lint

## Documentation
docs: ## Generate and open documentation
	@echo "$(BLUE)Generating documentation...$(RESET)"
	cargo doc --workspace --open

docs-check: ## Check documentation
	@echo "$(BLUE)Checking documentation...$(RESET)"
	cargo doc --workspace --no-deps

## Release preparation
release-check: ## Run all checks for release preparation
	@echo "$(BLUE)Running release checks...$(RESET)"
	$(MAKE) clean
	$(MAKE) check
	$(MAKE) lint
	$(MAKE) test-workspace
	$(MAKE) test-e2e
	$(MAKE) docs-check
	@echo "$(GREEN)Release checks passed!$(RESET)"

## Benchmarks (if implemented)
bench: ## Run benchmarks
	@echo "$(BLUE)Running benchmarks...$(RESET)"
	cargo bench

## Debug and Analysis
debug-deps: ## Show dependency tree
	@echo "$(BLUE)Dependency tree:$(RESET)"
	cargo tree

debug-features: ## Show features for all crates
	@echo "$(BLUE)Crate features:$(RESET)"
	@for crate in $$(cargo metadata --format-version 1 | jq -r '.workspace_members[]' | cut -d' ' -f1); do \
		echo "$(GREEN)$$crate:$(RESET)"; \
		cargo metadata --format-version 1 | jq -r ".packages[] | select(.name == \"$$crate\") | .features | keys[]" | sed 's/^/  /'; \
	done

debug-versions: ## Show version information
	@echo "$(BLUE)Version information:$(RESET)"
	@echo "Rust: $$(rustc --version)"
	@echo "Cargo: $$(cargo --version)"
	@echo "Project version: $$(cargo metadata --format-version 1 | jq -r '.workspace_members[0]' | cut -d' ' -f2)"

## Aliases for common commands
te: test-e2e ## Alias for test-e2e
c: check ## Alias for check
b: build ## Alias for build
f: fmt ## Alias for fmt
l: lint ## Alias for lint