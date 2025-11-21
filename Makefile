# Makefile for SNOS (Starknet OS) Project
# Provides convenient commands for building, testing, and development

DEFAULT_NETWORK := sepolia
DEFAULT_BLOCK_NUMBERS := 924015

# Starknet Sepolia
SEPOLIA_RPC_URL ?= https://pathfinder-sepolia.d.karnot.xyz
SEPOLIA_STRK_FEE_TOKEN ?= 0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d
SEPOLIA_ETH_FEE_TOKEN ?= 0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7

# Starknet Mainnet
MAINNET_RPC_URL ?= https://pathfinder-mainnet.d.karnot.xyz
MAINNET_STRK_FEE_TOKEN ?= 0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d
MAINNET_ETH_FEE_TOKEN ?= 0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7

# Paradex Devnet
PARADEX_DEVNET_RPC_URL ?= https://pathfinder.api.nightly.paradex.trade
PARADEX_DEVNET_STRK_FEE_TOKEN ?= 0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7
PARADEX_DEVNET_ETH_FEE_TOKEN ?= 0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7

# Paradex Testnet
PARADEX_TESTNET_RPC_URL ?= https://pathfinder-paradex-sandbox-testnet.d.karnot.xyz
PARADEX_TESTNET_STRK_FEE_TOKEN ?= 0x049D36570D4e46f48e99674bd3fcc84644DdD6b96F7C741B1562B82f9e004dC7
PARADEX_TESTNET_ETH_FEE_TOKEN ?= 0x049D36570D4e46f48e99674bd3fcc84644DdD6b96F7C741B1562B82f9e004dC7

# Paradex Mainnet
PARADEX_MAINNET_RPC_URL ?= https://pathfinder-paradex-sandbox-mainnet.d.karnot.xyz
PARADEX_MAINNET_STRK_FEE_TOKEN ?= 0x049D36570D4e46f48e99674bd3fcc84644DdD6b96F7C741B1562B82f9e004dC7
PARADEX_MAINNET_ETH_FEE_TOKEN ?= 0x049D36570D4e46f48e99674bd3fcc84644DdD6b96F7C741B1562B82f9e004dC7

# Madara Devnet
MADARA_DEVNET_CHAIN_ID ?= MADARA_DEVNET
MADARA_DEVNET_RPC_URL ?= http://localhost:8888
MADARA_DEVNET_STRK_FEE_TOKEN ?= 0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d
MADARA_DEVNET_ETH_FEE_TOKEN ?= 0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7

# Define comma for clarity
comma := ,

# Function to set output file path
# Usage: $(call set_output_path,NETWORK,BLOCK_NUMBERS)
define set_output_path
$(eval _block_list := $(subst $(comma), ,$(2)))
$(eval _first := $(word 1,$(_block_list)))
$(eval _last := $(word $(words $(_block_list)),$(_block_list)))
$(eval _output_file := $(_first)$(if $(filter-out $(_first),$(_last)),_$(_last)))
$(eval OUTPUT_FILE_PATH := ./tmp/$(1)/$(_output_file).zip)
endef

# Function to set network configuration variables
# Usage: $(call set_network_config,NETWORK)
define set_network_config
$(info [set_network_config] Called with NETWORK=$(1))
$(eval SNOS_NETWORK := $(if $(filter sepolia,$(1)),sepolia,\
	$(if $(filter mainnet,$(1)),mainnet,\
	$(if $(filter paradex-devnet,$(1)),PRIVATE_SN_POTC_MOCK_SEPOLIA,\
	$(if $(filter paradex-testnet,$(1)),PRIVATE_SN_POTC_SEPOLIA,\
	$(if $(filter paradex-mainnet,$(1)),PRIVATE_SN_PARACLEAR_MAINNET,\
	$(if $(filter madara-devnet,$(1)),$(MADARA_DEVNET_CHAIN_ID),\
	$(error Invalid NETWORK: $(1). Must be one of: sepolia, mainnet, paradex-devnet, paradex-testnet, paradex-mainnet, madara-devnet))))))))
$(eval SNOS_RPC_URL := $(if $(filter sepolia,$(1)),$(SEPOLIA_RPC_URL),\
	$(if $(filter mainnet,$(1)),$(MAINNET_RPC_URL),\
	$(if $(filter paradex-devnet,$(1)),$(PARADEX_DEVNET_RPC_URL),\
	$(if $(filter paradex-testnet,$(1)),$(PARADEX_TESTNET_RPC_URL),\
	$(if $(filter madara-devnet,$(1)),$(MADARA_DEVNET_RPC_URL),\
	$(PARADEX_MAINNET_RPC_URL)))))))
$(eval SNOS_STRK_FEE_TOKEN := $(if $(filter sepolia,$(1)),$(SEPOLIA_STRK_FEE_TOKEN),\
	$(if $(filter mainnet,$(1)),$(MAINNET_STRK_FEE_TOKEN),\
	$(if $(filter paradex-devnet,$(1)),$(PARADEX_DEVNET_STRK_FEE_TOKEN),\
	$(if $(filter paradex-testnet,$(1)),$(PARADEX_TESTNET_STRK_FEE_TOKEN),\
	$(if $(filter madara-devnet,$(1)),$(MADARA_DEVNET_STRK_FEE_TOKEN),\
	$(PARADEX_MAINNET_STRK_FEE_TOKEN)))))))
$(eval SNOS_ETH_FEE_TOKEN := $(if $(filter sepolia,$(1)),$(SEPOLIA_ETH_FEE_TOKEN),\
	$(if $(filter mainnet,$(1)),$(MAINNET_ETH_FEE_TOKEN),\
	$(if $(filter paradex-devnet,$(1)),$(PARADEX_DEVNET_ETH_FEE_TOKEN),\
	$(if $(filter paradex-testnet,$(1)),$(PARADEX_TESTNET_ETH_FEE_TOKEN),\
	$(if $(filter madara-devnet,$(1)),$(MADARA_DEVNET_ETH_FEE_TOKEN),\
	$(PARADEX_MAINNET_ETH_FEE_TOKEN)))))))
endef

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
	@echo "  SNOS_RPC_URL = $(SEPOLIA_RPC_URL)"
	@echo "  SNOS_BLOCKS  = $(DEFAULT_BLOCK_NUMBERS)"
	@echo "  SNOS_NETWORK = $(DEFAULT_NETWORK)"
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
	SNOS_RPC_URL="$(MAINNET_RPC_URL)" \
	cargo test --workspace --lib -- --nocapture

test-e2e: ## Run simple parameterized PIE generation tests
	@echo "$(BLUE)Running simple E2E tests...$(RESET)"
	RUST_LOG=info \
	SNOS_RPC_URL="$(MAINNET_RPC_URL)" \
	SNOS_RPC_URL_SEPOLIA="$(SEPOLIA_RPC_URL)" \
	cargo test -p e2e-tests test_pie_generation -- --nocapture

test-all: test-workspace test-e2e ## Run all tests (unit + integration + e2e)

## PIE Generation
generate-pie:
	$(eval ARGS := $(filter-out $@,$(MAKECMDGOALS)))
	$(eval NETWORK := $(word 1,$(ARGS)))
	$(eval BLOCK_NUMBERS := $(word 2,$(ARGS)))
	@if [ -z "$(NETWORK)" ]; then \
		echo "$(RED)Error: NETWORK is required$(RESET)"; \
		echo "Usage: make generate-pie <network> <block_numbers>"; \
		echo "Example: make generate-pie sepolia 924015"; \
		exit 1; \
	fi
	@if [ -z "$(BLOCK_NUMBERS)" ]; then \
		echo "$(RED)Error: BLOCK_NUMBERS is required$(RESET)"; \
		echo "Usage: make generate-pie <network> <block_numbers>"; \
		echo "Example: make generate-pie sepolia 924015"; \
		exit 1; \
	fi
	$(call set_network_config,$(NETWORK))
	$(call set_output_path,$(SNOS_NETWORK),$(BLOCK_NUMBERS))
	$(eval LOG_FILE_BASE := $(notdir $(basename $(OUTPUT_FILE_PATH))))
	$(eval LOG_FILE_PATH := ./tmp/$(SNOS_NETWORK)/logs/$(LOG_FILE_BASE)_$$(shell date +%Y-%m-%d--%H-%M-%S).log)
	@mkdir -p ./tmp/$(SNOS_NETWORK)
	@mkdir -p ./tmp/$(SNOS_NETWORK)/logs
	@echo "$(BLUE)Generating PIE for network: $(SNOS_NETWORK), blocks: $(BLOCK_NUMBERS)$(RESET)"
	@echo "$(BLUE)RPC URL: $(SNOS_RPC_URL)$(RESET)"
	@echo "$(BLUE)Output will be at: $(OUTPUT_FILE_PATH)$(RESET)"
	RUST_LOG=info \
	SNOS_LAYOUT=all_cairo \
	SNOS_IS_L3=false \
	SNOS_RPC_URL="$(SNOS_RPC_URL)" \
	SNOS_NETWORK="$(SNOS_NETWORK)" \
	SNOS_BLOCKS="$(BLOCK_NUMBERS)" \
	SNOS_STRK_FEE_TOKEN_ADDRESS="$(SNOS_STRK_FEE_TOKEN)" \
	SNOS_ETH_FEE_TOKEN_ADDRESS="$(SNOS_ETH_FEE_TOKEN)" \
	SNOS_OUTPUT="$(OUTPUT_FILE_PATH)" \
	cargo run -p generate-pie \
	2>&1 | tee "$(LOG_FILE_PATH)"

rpc-replay-seq: ## Run RPC replay in sequential mode
	$(eval ARGS := $(filter-out $@,$(MAKECMDGOALS)))
	$(eval NETWORK := $(word 1,$(ARGS)))
	$(eval START_BLOCK := $(word 2,$(ARGS)))
	$(eval NUM_BLOCKS := $(word 3,$(ARGS)))
	@if [ -z "$(NETWORK)" ]; then \
		echo "$(RED)Error: NETWORK is required$(RESET)"; \
		echo "Usage: make rpc-replay-seq <network> <start_block> <num_blocks>"; \
		echo "Example: make rpc-replay-seq sepolia 924015 2"; \
		exit 1; \
	fi
	@if [ -z "$(START_BLOCK)" ]; then \
		echo "$(RED)Error: START_BLOCK is required$(RESET)"; \
		echo "Usage: make rpc-replay-seq <network> <start_block> <num_blocks>"; \
		echo "Example: make rpc-replay-seq sepolia 924015 2"; \
		exit 1; \
	fi
	@if [ -z "$(NUM_BLOCKS)" ]; then \
		echo "$(RED)Error: NUM_BLOCKS is required$(RESET)"; \
		echo "Usage: make rpc-replay-seq <network> <start_block> <num_blocks>"; \
		echo "Example: make rpc-replay-seq sepolia 924015 2"; \
		exit 1; \
	fi
	$(call set_network_config,$(NETWORK))
	$(eval ERROR_LOG_DIR := ./tmp/$(SNOS_NETWORK)/error)
	@mkdir -p $(ERROR_LOG_DIR)
	@echo "$(BLUE)Running RPC replay in sequential mode...$(RESET)"
	@echo "$(YELLOW)Network: $(SNOS_NETWORK)$(RESET)"
	@echo "$(YELLOW)RPC URL: $(SNOS_RPC_URL)$(RESET)"
	@echo "$(YELLOW)Start Block: $(START_BLOCK), Num Blocks: $(NUM_BLOCKS)$(RESET)"
	@echo "$(YELLOW)Error logs: $(ERROR_LOG_DIR)$(RESET)"
	RUST_LOG=info \
	cargo run -p rpc-replay -- \
	--rpc-url "$(SNOS_RPC_URL)" \
	--layout "all_cairo" \
	--is-l3 false \
	--chain "$(SNOS_NETWORK)" \
	--strk-fee-token-address "$(SNOS_STRK_FEE_TOKEN)" \
	--eth-fee-token-address "$(SNOS_ETH_FEE_TOKEN)" \
	--log-dir "$(ERROR_LOG_DIR)" \
	--start-block $(START_BLOCK) \
	--num-blocks $(NUM_BLOCKS)

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

# Catch-all target to prevent Make from complaining about unknown targets
%:
	@:
