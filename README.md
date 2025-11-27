<div align="center">
  <img src="./docs/images/SNOS.png" height="400" width="500">
  
  ### ✨ SNOS ✨
  
  A Rust toolkit for generating Cairo PIE (Program Independent Execution) from blocks on Starknet-spec compatible chains.

  [Report Bug](https://github.com/keep-starknet-strange/snos/issues/new?assignees=&labels=bug&projects=&template=bug_report.md&title=bug%3A+) · [Request Feature](https://github.com/keep-starknet-strange/snos/issues/new?labels=enhancement&title=feat%3A+)

  [![Check Workflow Status](https://github.com/keep-starknet-strange/snos/actions/workflows/check.yml/badge.svg)](https://github.com/keep-starknet-strange/snos/actions/workflows/check.yml)
[![license](https://img.shields.io/github/license/keep-starknet-strange/snos)](/LICENSE)
[![pr-welcome]](#-contributing)

[pr-welcome]: https://img.shields.io/static/v1?color=blue&label=PRs&style=flat&message=welcome

</div>

## Table of Contents

- [About](#-about)
- [Getting Started](#️-getting-started)
- [Usage](#-usage)
- [Supported Networks](#-supported-networks)
- [Testing](#-testing)
- [Architecture](#-architecture)
- [Related Projects](#-related-projects)
- [Documentation](#-documentation)
- [License](#-license)

## 📖 About

SNOS generates Cairo PIE by re-executing blocks and producing inputs for the Starknet OS. These PIE can be used to generate STARK proofs that verify block validity. It works with any Starknet-spec compatible chain, including Starknet (Mainnet/Sepolia) and custom L2/L3 networks.

The Starknet OS code is sourced from the [sequencer repository](https://github.com/starkware-libs/sequencer) at `crates/apollo_starknet_os_program/src/cairo/starkware/starknet/core/os/os.cairo`.

### Key Features

- **Multi-block Processing**: Process multiple blocks into a single PIE
- **Parallel Execution**: Concurrent block processing for improved performance  
- **Network Flexibility**: Support for Starknet Mainnet, Sepolia, and custom L2/L3 networks
- **Configurable**: Extensive CLI options and environment variable support
- **Modular Design**: Clean separation between RPC client, PIE generation, and type handling

> **Important**: SNOS generates a PIE for all blocks provided to it without awareness of prover resource limits. It is the user's/application's responsibility to determine the appropriate number of blocks per PIE based on your proving infrastructure constraints.

## 🛠️ Getting Started

### Prerequisites

- [Rust 1.87.0 or newer](https://www.rust-lang.org/tools/install)
- [Python 3.9+](https://www.python.org/downloads/) with `cairo-compile` (for building)
- Access to a Starknet-spec compatible node with storage proof support (e.g., [Pathfinder](https://github.com/eqlabs/pathfinder), [Madara](https://github.com/madara-alliance/madara), [Katana](https://github.com/dojoengine/dojo))

> **Note**: The node must have storage proofs available for the block(s) you want to process. This typically requires running the node in archive mode.

### Build Requirements

Building SNOS compiles the `apollo_starknet_os` crate which in turn compiles `os.cairo`. This requires `cairo-compile` to be available in your PATH.

**Using the setup script (recommended)**

```bash
./setup-scripts/setup-cairo.sh
source ./snos-env/bin/activate
```

This creates a virtual environment with the correct `cairo-lang` dependencies. The requirements are based on the sequencer repo's `scripts/requirements.txt` (sequencer commit is specified in `Cargo.toml`).

**Alternative: Manual setup**

If you prefer manual setup, ensure `cairo-compile` is available in your PATH. You can install `cairo-lang` in a virtual environment or system-wide.

### Installation

```bash
git clone https://github.com/keep-starknet-strange/snos.git
cd snos

# Ensure cairo-compile is available (activate venv if using one)
source venv/bin/activate  # or source ./snos-env/bin/activate

cargo build --release
```

## 🚀 Usage

### Quick Start with Makefile

The easiest way to generate PIE is using the Makefile:

```bash
# Generate PIE for a Sepolia block
make generate-pie sepolia 924015

# Generate PIE for multiple blocks (comma-separated)
make generate-pie sepolia 924015,924016,924017

# Generate PIE for Mainnet
make generate-pie mainnet 1952705

# Generate PIE for a custom L2/L3 network (e.g., madara-devnet)
make generate-pie madara-devnet 100
```

### Using the CLI Directly

```bash
cargo run -p generate-pie -- \
  --blocks 924015 \
  --rpc-url https://your-node.com \
  --output ./output.zip
```

### CLI Options

| Option | Env Variable | Description | Default |
|--------|--------------|-------------|---------|
| `-b, --blocks` | `SNOS_BLOCKS` | Block number(s) to process (comma-separated) | **Required** |
| `-r, --rpc-url` | `SNOS_RPC_URL` | RPC endpoint with storage proof support | **Required** |
| `-o, --output` | `SNOS_OUTPUT` | Output path for PIE file | None (PIE not saved to disk) |
| `-l, --layout` | `SNOS_LAYOUT` | Cairo VM layout | `all_cairo` |
| `--chain` | `SNOS_NETWORK` | Network/chain ID | `sepolia` |
| `-s, --strk-fee-token-address` | `SNOS_STRK_FEE_TOKEN_ADDRESS` | STRK fee token address | Sepolia default |
| `-e, --eth-fee-token-address` | `SNOS_ETH_FEE_TOKEN_ADDRESS` | ETH fee token address | Sepolia default |
| `-i, --is-l3` | `SNOS_IS_L3` | Whether this is an L3 chain | `false` |
| `--versioned-constants-path` | `SNOS_VERSIONED_CONSTANTS_PATH` | Custom versioned constants JSON | Auto-detect from block |

### Default Values

When not specified, these defaults are used:

| Setting | Default Value |
|---------|---------------|
| Layout | `all_cairo` |
| Chain | `sepolia` |
| STRK Fee Token | `0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d` |
| ETH Fee Token | `0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7` |
| Is L3 | `false` |
| Versioned Constants | Auto-detected from block version |

### Examples

```bash
# Minimal - single block (uses all defaults for Sepolia)
cargo run -p generate-pie -- -b 924015 -r $RPC_URL

# With output file
cargo run -p generate-pie -- -b 924015 -r $RPC_URL -o output.zip

# Multiple blocks
cargo run -p generate-pie -- -b 924015,924016,924017 -r $RPC_URL

# With verbose logging
RUST_LOG=info cargo run -p generate-pie -- -b 924015 -r $RPC_URL -o pie.zip

# Mainnet
cargo run -p generate-pie -- \
  -b 1952705 \
  -r $RPC_URL \
  --chain mainnet

# Custom L2 network
cargo run -p generate-pie -- \
  -b 1000 \
  -r https://your-l2-node.example.com \
  --chain YOUR_CUSTOM_CHAIN_ID \
  -s 0x_YOUR_STRK_FEE_TOKEN_ADDRESS \
  -e 0x_YOUR_ETH_FEE_TOKEN_ADDRESS

# Custom L3 network (important: set --is-l3 true)
cargo run -p generate-pie -- \
  -b 1000 \
  -r https://your-l3-node.example.com \
  --chain YOUR_CUSTOM_CHAIN_ID \
  -s 0x_YOUR_STRK_FEE_TOKEN_ADDRESS \
  -e 0x_YOUR_ETH_FEE_TOKEN_ADDRESS \
  --is-l3 true

# With custom layout
cargo run -p generate-pie -- \
  -b 924015 \
  -r $RPC_URL \
  -l starknet_with_keccak

# With custom versioned constants
cargo run -p generate-pie -- \
  -b 924015 \
  -r $RPC_URL \
  --versioned-constants-path ./custom_constants.json

# Using all environment variables
export SNOS_RPC_URL=https://your-node.com
export SNOS_BLOCKS=924015,924016
export SNOS_NETWORK=sepolia
export SNOS_LAYOUT=all_cairo
export SNOS_OUTPUT=./output.zip
export SNOS_IS_L3=false
cargo run -p generate-pie
```

### RPC Replay Service

For continuous block processing and correctness testing, use the `rpc-replay` binary:

```bash
# Sequential mode - process blocks starting from a specific number
make rpc-replay-seq sepolia 924015 10

# Or directly:
cargo run -p rpc-replay -- \
  --start-block 924015 \
  --num-blocks 10 \
  --rpc-url $RPC_URL \
  --log-dir ./logs
```

### Using as a Library

Add to your `Cargo.toml`:

```toml
generate-pie = { git = "https://github.com/keep-starknet-strange/snos" }
```

Example usage:

```rust
use generate_pie::{generate_pie, PieGenerationInput, ChainConfig, OsHintsConfiguration};
use cairo_vm::types::layout_name::LayoutName;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let input = PieGenerationInput {
        rpc_url: "https://your-node.com".to_string(),
        blocks: vec![924015, 924016],
        chain_config: ChainConfig::default_with_chain("sepolia"),
        os_hints_config: OsHintsConfiguration::default(),
        output_path: Some("output.zip".to_string()),
        layout: LayoutName::all_cairo,
        versioned_constants: None,
    };

    let result = generate_pie(input).await?;
    println!("Processed blocks: {:?}", result.blocks_processed);
    Ok(())
}
```

## 🌐 Supported Networks

| Network | Chain ID | Notes |
|---------|----------|-------|
| Sepolia | `sepolia` | Starknet testnet |
| Mainnet | `mainnet` | Starknet mainnet |
| Custom L2 | Your chain ID | Custom Starknet L2 networks |
| Custom L3 | Your chain ID | Set `--is-l3 true` for L3 networks |

> **Important**: For custom L3 networks, you must set `--is-l3 true` (or `SNOS_IS_L3=true`) for correct execution.

## 🧪 Testing

```bash
# Run workspace unit tests
make test-workspace

# Run E2E tests (requires RPC access)
make test-e2e

# Run all tests
make test-all

# Run CI-suitable tests
make test-ci
```

### Environment Variables for Tests

```bash
export SNOS_RPC_URL=https://your-mainnet-node.com
export SNOS_RPC_URL_SEPOLIA=https://your-sepolia-node.com
```

## 🏗️ Architecture

SNOS is organized as a Cargo workspace with the following crates:

| Crate | Description |
|-------|-------------|
| `generate-pie` | Core PIE generation library and CLI |
| `rpc-client` | Unified RPC client for Starknet-spec nodes with storage proof support |
| `rpc-replay` | Continuous block processing service for correctness testing |
| `starknet-os-types` | Type definitions and contract class abstractions |
| `e2e-tests` | End-to-end test suite |

For detailed architecture documentation including data flow, configuration options, and performance considerations, see [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md).

## 🤝 Related Projects

- [sequencer](https://github.com/starkware-libs/sequencer): Starknet sequencer containing the Starknet OS
- [cairo-vm](https://github.com/lambdaclass/cairo-vm): Cairo VM implementation in Rust
- [pathfinder](https://github.com/eqlabs/pathfinder): Starknet full node with storage proofs
- [madara](https://github.com/madara-alliance/madara): Starknet client for app-chains
- [katana](https://github.com/dojoengine/dojo): Local Starknet development node

## 📚 Documentation

### Starknet OS
- [Starknet OS in sequencer](https://github.com/starkware-libs/sequencer/tree/main/crates/apollo_starknet_os_program)

### Cairo
- [The Cairo Book](https://book.cairo-lang.org/)
- [How Cairo Works](https://docs.cairo-lang.org/how_cairo_works/index.html)
- [Cairo Whitepaper](https://eprint.iacr.org/2021/1063)

### Starknet
- [Starknet Docs](https://docs.starknet.io/)
- [Starknet State](https://docs.starknet.io/architecture-and-concepts/network-architecture/starknet-state/)

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.
