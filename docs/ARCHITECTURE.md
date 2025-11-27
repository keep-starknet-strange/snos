# SNOS Architecture

This document provides a detailed overview of the SNOS codebase architecture.

SNOS generates Cairo PIE from blocks on Starknet-spec compatible chains (Starknet L2, custom L2s, and L3 networks).

> **See Also:** For a detailed walkthrough of the code execution flow, parallelization strategies, and type conversions, see [CODE_FLOW.md](./CODE_FLOW.md).

## Workspace Structure

```
snos/
├── crates/
│   ├── core/
│   │   └── generate-pie/     # Core PIE generation library and CLI
│   ├── rpc-client/           # RPC client for Starknet-spec nodes with storage proof support
│   ├── rpc-replay/           # Block replay service for correctness testing
│   └── starknet-os-types/    # Type definitions and abstractions
├── e2e-tests/                # End-to-end test suite
├── docs/                     # Documentation
└── resources/                # Test resources and constants
```

## Crate Overview

### generate-pie

The core library for PIE generation. Processes Starknet blocks and generates Cairo PIE files.

**Key Components:**

| Module | Purpose |
|--------|---------|
| `lib.rs` | Main `generate_pie()` function and public API |
| `block_processor.rs` | Individual block processing logic |
| `cached_state.rs` | State caching and storage proof handling |
| `conversions.rs` | Type conversions between RPC and OS types |
| `state_update.rs` | State diff processing |
| `types/` | Configuration types (`ChainConfig`, `PieGenerationInput`, etc.) |
| `error.rs` | Error types (`PieGenerationError`, `BlockProcessingError`) |

**Data Flow:**

```
RPC Endpoint (with storage proof support)
    ↓
Block Info Collection (parallel per block)
    ↓
Transaction Re-execution
    ↓
State Diff Processing
    ↓
Storage Proof Collection
    ↓
OS Hints Construction
    ↓
Starknet OS Execution
    ↓
Cairo PIE Output
```

> For a detailed step-by-step breakdown with diagrams, see [CODE_FLOW.md](./CODE_FLOW.md).

### rpc-client

Unified RPC client for Starknet-spec compatible nodes with storage proof support.

**Key Components:**

| Module | Purpose |
|--------|---------|
| `client.rs` | Main `RpcClient` implementation |
| `state_reader/` | High-level state reading interface |
| `types/` | RPC response types and proof structures |
| `utils.rs` | Async utilities for blocking operations |

**Features:**
- Async/await support for all operations
- Storage and class proof verification
- Contract class fetching with parallel requests
- Compatible with any Starknet-spec node implementing storage proofs (Pathfinder, Madara, Katana, etc.)

### starknet-os-types

Generic type abstractions for Starknet contract classes.

**Key Components:**

| Module | Purpose |
|--------|---------|
| `casm_contract_class.rs` | Cairo 1 compiled classes (CASM) |
| `sierra_contract_class.rs` | Cairo 1 Sierra classes |
| `deprecated_compiled_class.rs` | Cairo 0 legacy classes |
| `hash.rs` | Hash types and utilities |
| `class_hash_utils.rs` | Class hash computation |

**Features:**
- Lazy conversion between contract class formats
- Built-in class hash computation
- Full serde support

### rpc-replay

Block replay service for verifying SNOS correctness by replaying settled blocks.

**Execution Modes:**

1. **Sequential Mode**: Processes blocks starting from a number, waiting for new blocks
2. **JSON Mode**: Processes a specific list of blocks from a file

**Features:**
- Correctness testing by replaying already-settled blocks
- Error logging to local files or S3
- Panic recovery for robustness
- Progress tracking and reporting
- Works with any Starknet-spec compatible chain (L2 or L3)

## Key Dependencies

| Dependency | Purpose |
|------------|---------|
| `starknet_os` | Starknet OS execution (from [sequencer](https://github.com/starkware-libs/sequencer)) |
| `blockifier` | Transaction execution |
| `cairo-vm` | Cairo virtual machine |
| `starknet` | Starknet RPC types |
| `tokio` | Async runtime |

The Starknet OS Cairo program is sourced from the sequencer repository at:
`crates/apollo_starknet_os_program/src/cairo/starkware/starknet/core/os/os.cairo`

## Build Requirements

Building SNOS requires `cairo-compile` to be available because:

1. The `starknet_os` crate (from sequencer) depends on `apollo_starknet_os`
2. `apollo_starknet_os` compiles `os.cairo` during build
3. `os.cairo` compilation requires `cairo-compile` from `cairo-lang`

**Dependencies:**
- Python 3.9+ with `cairo-lang` package installed
- `cairo-compile` must be available in PATH

The Python dependencies for the sequencer are defined in `scripts/requirements.txt` of the sequencer repository. The exact sequencer commit used is specified in the workspace `Cargo.toml`.

## Configuration

### Chain Configuration

The `ChainConfig` struct configures network-specific parameters:

```rust
ChainConfig {
    chain_id: ChainId,            // Network identifier
    strk_fee_token_address: Felt, // STRK token address
    eth_fee_token_address: Felt,  // ETH token address
    is_l3: bool,                  // L3 network flag (must be true for L3 chains)
}
```

> **Important**: For custom L3 networks, `is_l3` must be set to `true`.

### OS Hints Configuration

The `OsHintsConfiguration` struct controls OS execution:

```rust
OsHintsConfiguration {
    debug_mode: bool,    // Enable debug output
    full_output: bool,   // Include full output in PIE
    use_kzg_da: bool,    // Use KZG data availability
}
```

## Error Handling

SNOS uses typed errors throughout:

- `PieGenerationError`: Top-level PIE generation errors
- `BlockProcessingError`: Block-specific processing errors
- `FeltConversionError`: Numeric conversion errors
- `ToBlockifierError`: Type conversion errors

All errors implement `std::error::Error` and provide detailed context.

## Performance Considerations

1. **Parallel Block Processing**: Blocks are processed concurrently up to available CPU cores using `tokio::spawn` + `Semaphore`
2. **Concurrent RPC Requests**: Storage and class fetching uses bounded concurrency (`buffer_unordered(100)`)
3. **CPU Parallelism**: Class compilation uses `rayon::par_iter` for parallel processing
4. **Lazy Compilation**: Contract classes are compiled only when needed
5. **Semaphore-based Throttling**: Prevents overwhelming RPC endpoints

> For detailed parallelization diagrams and RPC call patterns, see [CODE_FLOW.md](./CODE_FLOW.md#parallelization-strategy).

## Important Limitations

### Prover Resource Limits

SNOS generates a single PIE for all blocks provided to it. It does **not** have awareness of prover resource limits ( execution steps, etc.).

It is the responsibility of the user/application to:
- Determine the appropriate number of blocks per PIE based on proving infrastructure constraints
- Monitor PIE size and execution resources
- Split block ranges accordingly before invoking SNOS

The generated PIE includes execution resource information that can be used for post-hoc analysis.

## Testing

- **Unit Tests**: Per-crate tests in `src/` directories
- **E2E Tests**: Full workflow tests in `e2e-tests/`
- **Integration Tests**: Network-specific tests requiring RPC access
