# Makefile for SNOS (Starknet OS) Project
# Provides convenient commands for building, testing, and development

# Default values
RPC_URL ?= https://pathfinder-mainnet.d.karnot.xyz
NETWORK ?= mainnet
TIMEOUT ?= 300
VERBOSE ?= false

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
	@echo "  RPC_URL=$(RPC_URL)"
	@echo "  NETWORK=$(NETWORK)"
	@echo "  TIMEOUT=$(TIMEOUT)"
	@echo "  VERBOSE=$(VERBOSE)"
	@echo ""
	@echo "$(YELLOW)Examples:$(RESET)"
	@echo "  make test-quick                           # Fast tests (no RPC)"
	@echo "  make test-e2e RPC_URL=http://localhost:9545  # Local pathfinder"
	@echo "  make test-pie VERBOSE=true               # PIE tests with output"
	@echo "  make check-env                           # Check environment"

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
	rm -f *.pie
	rm -f os_hints_*.json
	rm -f test_output_*.pie

lint: ## Run clippy linter
	@echo "$(BLUE)Running clippy...$(RESET)"
	cargo clippy --workspace -- -D warnings

fix: ## Apply automatic fixes
	@echo "$(BLUE)Applying automatic fixes...$(RESET)"
	cargo fix --workspace --allow-dirty
	cargo fmt --all

fmt: ## Format code
	@echo "$(BLUE)Formatting code...$(RESET)"
	cargo fmt --all --check

## Testing
test: test-quick ## Run default tests (quick integration tests)

test-quick: ## Run quick integration tests (no RPC required)
	@echo "$(BLUE)Running quick integration tests...$(RESET)"
	SNOS_TEST_RPC_URL="$(RPC_URL)" \
	SNOS_TEST_NETWORK="$(NETWORK)" \
	SNOS_TEST_TIMEOUT_SECS="$(TIMEOUT)" \
	cargo test -p e2e-tests --test basic_integration $(if $(filter true,$(VERBOSE)),-- --nocapture,)

test-workspace: ## Run all workspace unit tests
	@echo "$(BLUE)Running workspace unit tests...$(RESET)"
	cargo test --workspace --lib $(if $(filter true,$(VERBOSE)),-- --nocapture,)

test-e2e: ## Run full end-to-end tests (requires RPC)
	@echo "$(BLUE)Running full e2e tests (may take 30-60 minutes)...$(RESET)"
	@echo "$(YELLOW)Using RPC: $(RPC_URL)$(RESET)"
	SNOS_TEST_RPC_URL="$(RPC_URL)" \
	SNOS_TEST_NETWORK="$(NETWORK)" \
	SNOS_TEST_TIMEOUT_SECS="$(TIMEOUT)" \
	cargo test -p e2e-tests --test integration -- --ignored $(if $(filter true,$(VERBOSE)),--nocapture,)

test-pie: ## Run PIE generation tests only
	@echo "$(BLUE)Running PIE generation tests...$(RESET)"
	@echo "$(YELLOW)Using RPC: $(RPC_URL)$(RESET)"
	SNOS_TEST_RPC_URL="$(RPC_URL)" \
	SNOS_TEST_NETWORK="$(NETWORK)" \
	SNOS_TEST_TIMEOUT_SECS="$(TIMEOUT)" \
	cargo test -p e2e-tests pie_generation -- --ignored $(if $(filter true,$(VERBOSE)),--nocapture,)

test-errors: ## Run error handling tests only
	@echo "$(BLUE)Running error handling tests...$(RESET)"
	@echo "$(YELLOW)Using RPC: $(RPC_URL)$(RESET)"
	SNOS_TEST_RPC_URL="$(RPC_URL)" \
	SNOS_TEST_NETWORK="$(NETWORK)" \
	SNOS_TEST_TIMEOUT_SECS="$(TIMEOUT)" \
	cargo test -p e2e-tests error_handling -- --ignored $(if $(filter true,$(VERBOSE)),--nocapture,)

test-single: ## Run single block PIE generation test
	@echo "$(BLUE)Running single block PIE test...$(RESET)"
	@echo "$(YELLOW)Using RPC: $(RPC_URL)$(RESET)"
	SNOS_TEST_RPC_URL="$(RPC_URL)" \
	SNOS_TEST_NETWORK="$(NETWORK)" \
	SNOS_TEST_TIMEOUT_SECS="$(TIMEOUT)" \
	cargo test -p e2e-tests test_single_block_pie_generation -- --ignored $(if $(filter true,$(VERBOSE)),--nocapture,)

test-multi: ## Run multi-block PIE generation test
	@echo "$(BLUE)Running multi-block PIE test...$(RESET)"
	@echo "$(YELLOW)Using RPC: $(RPC_URL)$(RESET)"
	SNOS_TEST_RPC_URL="$(RPC_URL)" \
	SNOS_TEST_NETWORK="$(NETWORK)" \
	SNOS_TEST_TIMEOUT_SECS="$(TIMEOUT)" \
	cargo test -p e2e-tests test_multi_block_pie_generation -- --ignored $(if $(filter true,$(VERBOSE)),--nocapture,)

test-all: test-workspace test-quick test-e2e ## Run all tests (unit + integration + e2e)

test-ci: ## Run tests suitable for CI (no long-running e2e tests)
	@echo "$(BLUE)Running CI test suite...$(RESET)"
	$(MAKE) check
	$(MAKE) test-workspace
	$(MAKE) test-quick

## Environment and Setup
env-check: ## Check test environment and connectivity
	@echo "$(BLUE)Checking test environment...$(RESET)"
	./scripts/run-e2e-tests.sh check

setup: ## Set up development environment
	@echo "$(BLUE)Setting up development environment...$(RESET)"
	@if [ ! -d "snos-env" ]; then \
		echo "$(YELLOW)Setting up Cairo environment...$(RESET)"; \
		./setup-scripts/setup-cairo.sh; \
	fi
	@echo "$(GREEN)Environment setup complete!$(RESET)"
	@echo "$(YELLOW)Remember to activate the environment: source ./snos-env/bin/activate$(RESET)"

activate: ## Show command to activate Cairo environment
	@echo "$(YELLOW)Run this command to activate the Cairo environment:$(RESET)"
	@echo "source ./snos-env/bin/activate"

## PIE Generation
generate-pie: ## Generate PIE for a specific block (requires BLOCK_NUMBER)
ifndef BLOCK_NUMBER
	@echo "$(RED)Error: BLOCK_NUMBER is required$(RESET)"
	@echo "Usage: make generate-pie BLOCK_NUMBER=12345"
	@exit 1
endif
	@echo "$(BLUE)Generating PIE for block $(BLOCK_NUMBER)...$(RESET)"
	cargo run -p generate-pie -- --rpc-url $(RPC_URL) --blocks $(BLOCK_NUMBER) --output pie_block_$(BLOCK_NUMBER).zip

## Development Shortcuts
dev-check: check lint ## Quick development check (build + lint)

dev-test: test-quick ## Quick development test

dev-full: dev-check test-workspace test-quick ## Full development check

## Mainnet vs Sepolia shortcuts
test-mainnet: ## Run tests against mainnet
	$(MAKE) test-e2e RPC_URL=https://pathfinder-mainnet.d.karnot.xyz NETWORK=mainnet

test-sepolia: ## Run tests against sepolia
	$(MAKE) test-e2e RPC_URL=https://pathfinder-sepolia.d.karnot.xyz NETWORK=sepolia

test-local: ## Run tests against local pathfinder (localhost:9545)
	$(MAKE) test-e2e RPC_URL=http://localhost:9545 NETWORK=mainnet

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
	$(MAKE) test-quick
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
t: test-quick ## Alias for test-quick
tq: test-quick ## Alias for test-quick
te: test-e2e ## Alias for test-e2e
tp: test-pie ## Alias for test-pie
c: check ## Alias for check
b: build ## Alias for build
f: fmt ## Alias for fmt
l: lint ## Alias for lint