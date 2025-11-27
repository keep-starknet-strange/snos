# SNOS Code Flow

This document provides a detailed walkthrough of how SNOS processes blocks and generates Cairo PIE, including parallelization strategies, RPC call patterns, and type conversions.

## Table of Contents

- [Overview](#overview)
- [Entry Points](#entry-points)
- [Main Processing Flow](#main-processing-flow)
- [Parallelization Strategy](#parallelization-strategy)
- [RPC Call Patterns](#rpc-call-patterns)
- [Type Conversions](#type-conversions)
- [Detailed Code Flow Diagram](#detailed-code-flow-diagram)

---

## Overview

SNOS generates Cairo PIE through the following high-level pipeline:

```
User Input (blocks, rpc_url, config)
    ↓
Parallel Block Processing (tokio::spawn + Semaphore)
    ↓
Per-Block: Fetch → Execute → Collect Proofs → Build State
    ↓
Merge Results from All Blocks
    ↓
Build OsHints (StarknetOsInput)
    ↓
Execute Starknet OS (run_os_stateless)
    ↓
Validate & Output Cairo PIE
```

---

## Entry Points

### CLI Entry Point

**File:** `crates/core/generate-pie/src/main.rs`

```
main()
  ├── Parse CLI args (Clap)
  ├── Load versioned constants (optional)
  ├── Build PieGenerationInput
  └── Call generate_pie(input)
```

### Library Entry Point

**File:** `crates/core/generate-pie/src/lib.rs`

```rust
pub async fn generate_pie(input: PieGenerationInput) -> Result<PieGenerationResult, PieGenerationError>
```

---

## Main Processing Flow

### Step 1: Initialization

**Location:** `lib.rs::generate_pie()`

```
generate_pie(input)
    │
    ├── input.validate()                    // Validate configuration
    │
    ├── RpcClient::try_new(&input.rpc_url)  // Initialize RPC client
    │
    └── Semaphore::new(cpu_cores)           // Create parallelism limiter
```

### Step 2: Parallel Block Processing

**Location:** `lib.rs::generate_pie()`

```
for each block_number in input.blocks:
    │
    └── tokio::spawn(async {
            │
            ├── semaphore.acquire()         // Limit concurrent blocks to CPU cores
            │
            ├── collect_single_block_info() // Process single block
            │   └── Returns: (OsBlockInput, compiled_classes, deprecated_classes, 
            │                 accessed_addresses, accessed_classes, accessed_keys)
            │
            └── generate_cached_state_input() // Build cached state
                └── Returns: CachedStateInput
        })

join_all(block_tasks)  // Wait for all blocks to complete
```

### Step 3: Single Block Processing

**Location:** `block_processor.rs::collect_single_block_info()`

```
collect_single_block_info(block_number, ...)
    │
    ├── Step 1: BlockData::fetch()
    │   ├── RPC: chain_id()
    │   ├── RPC: get_block_with_txs(block_id)
    │   ├── RPC: get_block_with_tx_hashes(previous_block_id)
    │   └── RPC: get_block_with_tx_hashes(old_block_id)  // For hash buffer
    │
    ├── Step 2: block_data.build_context()
    │   └── Creates BlockContext with gas prices, chain info, versioned constants
    │
    ├── Step 3: block_data.process_transactions()
    │   ├── RPC: trace_block_transactions()
    │   ├── Extract accessed contracts from traces
    │   ├── Convert transactions (RPC types → Blockifier types)
    │   ├── Execute via TransactionExecutor
    │   └── get_formatted_state_update()
    │       ├── RPC: get_state_update()
    │       └── Compile contract classes (parallel)
    │
    ├── Step 4: tx_result.collect_proofs()
    │   ├── RPC: pathfinder_rpc().get_proof() for storage proofs
    │   └── RPC: pathfinder_rpc().get_class_proof() for class proofs
    │
    ├── Step 5: proofs.calculate_commitments()
    │   └── Build commitment info from proofs
    │
    ├── Step 6: process_contract_classes()
    │   └── Convert to starknet_api types
    │
    └── Step 7: build_os_block_input()
        └── Assemble final OsBlockInput
```

### Step 4: Cached State Generation

**Location:** `cached_state.rs::generate_cached_state_input()`

```
generate_cached_state_input(rpc_client, block_number, accessed_*, ...)
    │
    ├── If block 0: return genesis cached state
    │
    ├── Fetch storage values (concurrent)
    │   └── stream::iter(storage_requests)
    │       .map(|req| RPC: get_storage_at())
    │       .buffer_unordered(MAX_CONCURRENT_GET_STORAGE_AT_REQUESTS=100)
    │
    ├── Fetch nonces
    │   └── for each address: RPC: get_nonce()
    │
    ├── Fetch class hashes
    │   └── for each address: RPC: get_class_hash_at()
    │
    └── Compute compiled class hashes (two-phase)
        │
        ├── Phase 1: Fetch classes (async I/O parallel)
        │   └── stream::iter(class_hashes)
        │       .map(|hash| RPC: get_class())
        │       .buffer_unordered(MAX_CONCURRENT_GET_CLASS_REQUESTS=100)
        │
        └── Phase 2: Compute hashes (CPU parallel via rayon)
            └── class_fetch_results.par_iter()
                .filter_map(|class| compute_compiled_class_hash())
```

### Step 5: Merge and Build OS Hints

**Location:** `lib.rs::generate_pie()`

```
After all blocks complete:
    │
    ├── Merge results from all blocks
    │   ├── os_block_inputs.push(block_input)
    │   ├── compiled_classes.extend(block_classes)
    │   ├── deprecated_compiled_classes.extend(block_deprecated)
    │   └── cached_state_inputs.push(cached_state)
    │
    ├── Sort ABI entries for deprecated classes
    │
    └── Build OsHints
        └── OsHints {
                os_hints_config: OsHintsConfig { debug_mode, full_output, use_kzg_da, chain_info },
                os_input: StarknetOsInput {
                    os_block_inputs,
                    cached_state_inputs,
                    deprecated_compiled_classes,
                    compiled_classes,
                }
            }
```

### Step 6: OS Execution and PIE Output

**Location:** `lib.rs::generate_pie()`

```
run_os_stateless(layout, os_hints)
    │
    └── Returns: StarknetOsRunnerOutput containing CairoPIE
    
output.cairo_pie.run_validity_checks()  // Validate PIE

if output_path specified:
    output.cairo_pie.write_zip_file(path)  // Write to disk
```

---

## Parallelization Strategy

### Level 1: Block-Level Parallelism

**Mechanism:** `tokio::spawn` + `Semaphore`

```rust
// Limit parallel blocks to CPU cores
let semaphore = Arc::new(Semaphore::new(available_parallelism));

// Spawn task per block
tokio::spawn(async move {
    let _permit = semaphore.acquire().await;  // Rate limit
    // Process block...
})

// Wait for all
join_all(block_tasks).await
```

**Why:** Prevents overwhelming RPC endpoints and memory exhaustion with many blocks.

### Level 2: RPC Call Parallelism

**Mechanism:** `futures::stream::buffer_unordered`

```rust
// Concurrent storage fetches
stream::iter(storage_requests)
    .map(|(addr, key)| async { rpc.get_storage_at(addr, key).await })
    .buffer_unordered(MAX_CONCURRENT_GET_STORAGE_AT_REQUESTS)  // 100
    .collect()
    .await
```

**Constants:**
- `MAX_CONCURRENT_GET_STORAGE_AT_REQUESTS = 100`
- `MAX_CONCURRENT_GET_CLASS_REQUESTS = 100`

### Level 3: CPU Parallelism

**Mechanism:** `rayon::par_iter`

```rust
// Parallel class compilation
class_fetch_results
    .par_iter()  // rayon parallel iterator
    .filter_map(|(hash, class)| {
        compile_contract_class(class)  // CPU-intensive
    })
    .collect()
```

**Used for:**
- Sierra → CASM compilation
- Class hash computation
- Contract class processing

### Parallelization Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        generate_pie()                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │  Block 1    │  │  Block 2    │  │  Block N    │  (tokio)     │
│  │  (spawn)    │  │  (spawn)    │  │  (spawn)    │              │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘              │
│         │                │                │                      │
│         ▼                ▼                ▼                      │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │              Semaphore (CPU cores limit)                 │    │
│  └─────────────────────────────────────────────────────────┘    │
│         │                │                │                      │
│         ▼                ▼                ▼                      │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                  Per-Block Processing                     │   │
│  │  ┌─────────────────────────────────────────────────────┐ │   │
│  │  │  RPC Calls (buffer_unordered, 100 concurrent)       │ │   │
│  │  │  - get_storage_at                                   │ │   │
│  │  │  - get_class                                        │ │   │
│  │  │  - get_nonce                                        │ │   │
│  │  └─────────────────────────────────────────────────────┘ │   │
│  │  ┌─────────────────────────────────────────────────────┐ │   │
│  │  │  CPU Work (rayon par_iter)                          │ │   │
│  │  │  - compile_contract_class                           │ │   │
│  │  │  - compute_compiled_class_hash                      │ │   │
│  │  └─────────────────────────────────────────────────────┘ │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                   join_all() - Merge                      │   │
│  └──────────────────────────────────────────────────────────┘   │
│                              │                                   │
│                              ▼                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              run_os_stateless() - Single Thread           │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## RPC Call Patterns

### RPC Client Structure

**File:** `crates/rpc-client/src/client.rs`

```rust
RpcClient {
    starknet_rpc: JsonRpcClient<HttpTransport>,    // Standard Starknet RPC
    pathfinder_rpc: PathfinderRpcClient,           // Storage proof extensions
}
```

### Standard Starknet RPC Calls

| Method | Location | Purpose |
|--------|----------|---------|
| `chain_id()` | `BlockData::fetch` | Get chain identifier |
| `get_block_with_txs()` | `BlockData::fetch` | Get current block with transactions |
| `get_block_with_tx_hashes()` | `BlockData::fetch` | Get previous/old blocks |
| `trace_block_transactions()` | `process_transactions` | Get execution traces |
| `get_state_update()` | `get_formatted_state_update` | Get state diff |
| `get_storage_at()` | `generate_cached_state_input` | Fetch storage values |
| `get_nonce()` | `generate_cached_state_input` | Fetch account nonces |
| `get_class_hash_at()` | `generate_cached_state_input` | Get class hash for address |
| `get_class()` | Multiple locations | Fetch contract class |

### Pathfinder-Specific RPC Calls

| Method | Location | Purpose |
|--------|----------|---------|
| `get_proof()` | `collect_proofs` | Storage proofs for commitments |
| `get_class_proof()` | `collect_proofs` | Class proofs for commitments |

### RPC Call Flow Diagram

```
┌────────────────────────────────────────────────────────────────────┐
│                         BlockData::fetch()                          │
├────────────────────────────────────────────────────────────────────┤
│  Sequential calls:                                                  │
│  1. chain_id()                                                      │
│  2. get_block_with_txs(current)                                     │
│  3. get_block_with_tx_hashes(previous)                              │
│  4. get_block_with_tx_hashes(old)                                   │
└────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────┐
│                     process_transactions()                          │
├────────────────────────────────────────────────────────────────────┤
│  1. trace_block_transactions() - sequential                        │
│  2. For Declare txns: get_class() - per transaction                │
└────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────┐
│                   get_formatted_state_update()                      │
├────────────────────────────────────────────────────────────────────┤
│  1. get_state_update() - sequential                                 │
│  2. get_class_hash_at() - concurrent (100 max)                      │
│  3. get_class() - concurrent (100 max)                              │
└────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────┐
│                   generate_cached_state_input()                     │
├────────────────────────────────────────────────────────────────────┤
│  1. get_storage_at() - concurrent (100 max)                         │
│  2. get_nonce() - sequential per address                            │
│  3. get_class_hash_at() - sequential per address                    │
│  4. get_class() - concurrent (100 max)                              │
└────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────┐
│                        collect_proofs()                             │
├────────────────────────────────────────────────────────────────────┤
│  1. pathfinder_rpc.get_proof() - for storage proofs                │
│  2. pathfinder_rpc.get_class_proof() - for class proofs            │
└────────────────────────────────────────────────────────────────────┘
```

---

## Type Conversions

### Conversion Architecture

SNOS bridges two type ecosystems:
1. **RPC Types** - from `starknet-rs` crate (what we receive from RPC)
2. **Blockifier/OS Types** - from `sequencer` crate (what OS needs)

**File:** `crates/core/generate-pie/src/conversions.rs`

### Conversion Traits

```rust
// Synchronous conversion (no RPC needed)
pub trait TryIntoBlockifierSync<T> {
    fn try_into_blockifier(self) -> Result<T, Self::Error>;
}

// Async conversion (may need RPC calls)
#[async_trait]
pub trait TryIntoBlockifierAsync<T> {
    async fn try_into_blockifier_async(
        self,
        ctx: &ConversionContext<'_>,
        trace: &TransactionTraceWithHash,
    ) -> Result<T, Self::Error>;
}
```

### Key Type Conversions

| Source Type | Target Type | Conversion |
|-------------|-------------|------------|
| `starknet::Transaction` | `blockifier::Transaction` | Async (may fetch class) |
| `InvokeTransactionV1/V3` | `starknet_api::InvokeTransaction` | Sync |
| `DeclareTransactionV0-V3` | `starknet_api::DeclareTransaction` | Async (fetches ClassInfo) |
| `DeployAccountTransactionV1/V3` | `starknet_api::DeployAccountTransaction` | Sync |
| `L1HandlerTransaction` | `starknet_api::L1HandlerTransaction` | Sync (calculates fee) |
| `ResourceBoundsMapping` | `ValidResourceBounds` | Sync |
| `DataAvailabilityMode` | `starknet_api::DataAvailabilityMode` | Sync |

### Contract Class Conversions

**File:** `crates/starknet-os-types/src/`

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Contract Class Flow                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  RPC Response                                                        │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ starknet::core::types::ContractClass                        │    │
│  │   ├── Sierra(FlattenedSierraClass)                          │    │
│  │   └── Legacy(CompressedLegacyContractClass)                 │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                              │                                       │
│                              ▼                                       │
│  Generic Wrapper                                                     │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ starknet_os_types::                                         │    │
│  │   ├── GenericSierraContractClass                            │    │
│  │   └── GenericDeprecatedCompiledClass                        │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                              │                                       │
│              ┌───────────────┴───────────────┐                      │
│              ▼                               ▼                       │
│  ┌───────────────────────────┐   ┌───────────────────────────────┐ │
│  │ Sierra Path               │   │ Legacy Path                   │ │
│  │ .compile() → CASM         │   │ .to_starknet_api_contract_   │ │
│  │ .to_blockifier_contract_  │   │  class()                     │ │
│  │  class()                  │   │                               │ │
│  └───────────────────────────┘   └───────────────────────────────┘ │
│              │                               │                       │
│              ▼                               ▼                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ starknet_api::contract_class::ContractClass                 │    │
│  │   ├── V1 (Cairo 1 / Sierra)                                 │    │
│  │   └── V0 (Cairo 0 / Legacy)                                 │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Transaction Conversion Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Transaction Conversion                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Input: starknet::core::types::Transaction                          │
│                              │                                       │
│                              ▼                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ Transaction::try_into_blockifier_async(ctx, trace)          │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                              │                                       │
│          ┌───────────────────┼───────────────────┐                  │
│          ▼                   ▼                   ▼                   │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────┐         │
│  │ Invoke       │   │ Declare      │   │ DeployAccount    │         │
│  │ V1/V3        │   │ V0/V1/V2/V3  │   │ V1/V3            │         │
│  └──────────────┘   └──────────────┘   └──────────────────┘         │
│          │                   │                   │                   │
│          │          ┌────────┴────────┐          │                   │
│          │          ▼                 │          │                   │
│          │   fetch_class_info()       │          │                   │
│          │   (RPC: get_class)         │          │                   │
│          │          │                 │          │                   │
│          ▼          ▼                 ▼          ▼                   │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ TransactionConversionResult {                               │    │
│  │   starknet_api_tx: starknet_api::executable_transaction,    │    │
│  │   blockifier_tx: blockifier::transaction::Transaction,      │    │
│  │ }                                                            │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Detailed Code Flow Diagram

### Complete Flow: Request to PIE

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                   USER REQUEST                                   │
│                        (blocks: [100, 101], rpc_url, config)                     │
└─────────────────────────────────────────────────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                               main.rs / Library                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │ PieGenerationInput {                                                     │    │
│  │   rpc_url, blocks, chain_config, os_hints_config, layout, ...           │    │
│  │ }                                                                        │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                            lib.rs::generate_pie()                                │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌──────────────────────────────────────────────────────────────────────────┐   │
│  │ 1. INITIALIZATION                                                         │   │
│  │    input.validate()                                                       │   │
│  │    RpcClient::try_new(rpc_url)                                           │   │
│  │    Semaphore::new(cpu_cores)                                             │   │
│  └──────────────────────────────────────────────────────────────────────────┘   │
│                                         │                                        │
│                                         ▼                                        │
│  ┌──────────────────────────────────────────────────────────────────────────┐   │
│  │ 2. PARALLEL BLOCK PROCESSING                                              │   │
│  │                                                                           │   │
│  │    ┌─────────────────┐      ┌─────────────────┐                          │   │
│  │    │ tokio::spawn    │      │ tokio::spawn    │                          │   │
│  │    │ Block 100       │      │ Block 101       │                          │   │
│  │    │                 │      │                 │                          │   │
│  │    │ ┌─────────────┐ │      │ ┌─────────────┐ │                          │   │
│  │    │ │ Semaphore   │ │      │ │ Semaphore   │ │                          │   │
│  │    │ │ acquire()   │ │      │ │ acquire()   │ │                          │   │
│  │    │ └─────────────┘ │      │ └─────────────┘ │                          │   │
│  │    │       │         │      │       │         │                          │   │
│  │    │       ▼         │      │       ▼         │                          │   │
│  │    │ ┌─────────────┐ │      │ ┌─────────────┐ │                          │   │
│  │    │ │ collect_    │ │      │ │ collect_    │ │                          │   │
│  │    │ │ single_     │ │      │ │ single_     │ │                          │   │
│  │    │ │ block_info  │ │      │ │ block_info  │ │                          │   │
│  │    │ └─────────────┘ │      │ └─────────────┘ │                          │   │
│  │    │       │         │      │       │         │                          │   │
│  │    │       ▼         │      │       ▼         │                          │   │
│  │    │ ┌─────────────┐ │      │ ┌─────────────┐ │                          │   │
│  │    │ │ generate_   │ │      │ │ generate_   │ │                          │   │
│  │    │ │ cached_     │ │      │ │ cached_     │ │                          │   │
│  │    │ │ state_input │ │      │ │ state_input │ │                          │   │
│  │    │ └─────────────┘ │      │ └─────────────┘ │                          │   │
│  │    └─────────────────┘      └─────────────────┘                          │   │
│  │              │                      │                                     │   │
│  │              └──────────┬───────────┘                                     │   │
│  │                         ▼                                                 │   │
│  │                   join_all()                                              │   │
│  └──────────────────────────────────────────────────────────────────────────┘   │
│                                         │                                        │
│                                         ▼                                        │
│  ┌──────────────────────────────────────────────────────────────────────────┐   │
│  │ 3. MERGE RESULTS                                                          │   │
│  │    os_block_inputs.extend(...)                                           │   │
│  │    cached_state_inputs.extend(...)                                       │   │
│  │    compiled_classes.extend(...)                                          │   │
│  │    deprecated_compiled_classes.extend(...)                               │   │
│  └──────────────────────────────────────────────────────────────────────────┘   │
│                                         │                                        │
│                                         ▼                                        │
│  ┌──────────────────────────────────────────────────────────────────────────┐   │
│  │ 4. BUILD OS HINTS                                                         │   │
│  │    OsHints {                                                              │   │
│  │      os_hints_config: { debug_mode, full_output, use_kzg_da, chain_info },│   │
│  │      os_input: StarknetOsInput {                                         │   │
│  │        os_block_inputs,                                                   │   │
│  │        cached_state_inputs,                                               │   │
│  │        deprecated_compiled_classes,                                       │   │
│  │        compiled_classes,                                                  │   │
│  │      }                                                                    │   │
│  │    }                                                                      │   │
│  └──────────────────────────────────────────────────────────────────────────┘   │
│                                         │                                        │
│                                         ▼                                        │
│  ┌──────────────────────────────────────────────────────────────────────────┐   │
│  │ 5. EXECUTE STARKNET OS                                                    │   │
│  │    run_os_stateless(layout, os_hints)                                    │   │
│  │      └── Returns: StarknetOsRunnerOutput { cairo_pie, os_output }        │   │
│  └──────────────────────────────────────────────────────────────────────────┘   │
│                                         │                                        │
│                                         ▼                                        │
│  ┌──────────────────────────────────────────────────────────────────────────┐   │
│  │ 6. VALIDATE & OUTPUT                                                      │   │
│  │    cairo_pie.run_validity_checks()                                       │   │
│  │    if output_path: cairo_pie.write_zip_file(path)                        │   │
│  └──────────────────────────────────────────────────────────────────────────┘   │
│                                         │                                        │
│                                         ▼                                        │
│  ┌──────────────────────────────────────────────────────────────────────────┐   │
│  │ Return: PieGenerationResult { output, blocks_processed, output_path }     │   │
│  └──────────────────────────────────────────────────────────────────────────┘   │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                  CAIRO PIE                                       │
│                            (output.zip or in-memory)                             │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Summary

| Component | Parallelization | Key Files |
|-----------|-----------------|-----------|
| Block processing | `tokio::spawn` + `Semaphore` | `lib.rs` |
| RPC calls | `buffer_unordered(100)` | `cached_state.rs`, `state_update.rs` |
| Class compilation | `rayon::par_iter` | `state_update.rs`, `cached_state.rs` |
| OS execution | Single-threaded | `lib.rs` → `starknet_os::runner` |

**Type conversion chain:**
```
RPC Types (starknet-rs) 
  → Generic Types (starknet-os-types) 
  → Blockifier Types (sequencer)
  → OS Input Types (starknet_os)
```

