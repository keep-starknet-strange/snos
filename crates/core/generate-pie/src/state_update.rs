//! State Update Processing Module
//!
//! This module handles the processing of Starknet state updates, including:
//! - Fetching and formatting state updates from RPC
//! - Processing transaction traces to extract accessed contracts
//! - Compiling contract classes to CASM format
//! - Managing class hash mappings and component hashes
//!
//! The main entry point is [`get_formatted_state_update`] which orchestrates the entire
//! state update processing pipeline.

use cairo_vm::Felt252;
use log::{debug, info, warn};
use rpc_client::RpcClient;
use starknet::core::types::{
    BlockId, ExecuteInvocation, FunctionInvocation, MaybePreConfirmedStateUpdate, StarknetError, StateDiff,
    TransactionTrace, TransactionTraceWithHash,
};
use starknet::providers::Provider;
use starknet::providers::ProviderError;
use starknet_os_types::casm_contract_class::GenericCasmContractClass;
use starknet_os_types::class_hash_utils::ContractClassComponentHashes;
use starknet_os_types::compiled_class::GenericCompiledClass;
use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;
use starknet_os_types::sierra_contract_class::GenericSierraContractClass;
use starknet_types_core::felt::Felt;
use std::collections::{HashMap, HashSet};
use thiserror::Error;

// ================================================================================================
// Type Definitions
// ================================================================================================

pub type PreviousBlockId = Option<BlockId>;

/// Formatted state update containing all necessary information for PIE generation.
#[derive(Clone, Debug, Default)]
pub struct FormattedStateUpdate {
    /// Mapping from class hash to compiled class hash
    pub class_hash_to_compiled_class_hash: HashMap<Felt252, Felt252>,
    /// Compiled CASM contract classes
    pub compiled_classes: HashMap<Felt252, GenericCasmContractClass>,
    /// Deprecated (Cairo 0) compiled classes
    pub deprecated_compiled_classes: HashMap<Felt252, GenericDeprecatedCompiledClass>,
    /// Component hashes for declared classes
    pub declared_class_hash_component_hashes: HashMap<Felt252, ContractClassComponentHashes>,
}

/// Result containing processed transaction trace data.
struct TraceProcessingResult {
    accessed_addresses: HashSet<Felt252>,
    accessed_classes: HashSet<Felt252>,
}

/// Result containing compiled class data.
struct CompiledClassResult {
    compiled_classes: HashMap<Felt252, GenericCasmContractClass>,
    deprecated_compiled_classes: HashMap<Felt252, GenericDeprecatedCompiledClass>,
    declared_component_hashes: HashMap<Felt252, ContractClassComponentHashes>,
}

// ================================================================================================
// Error Types
// ================================================================================================

#[derive(Debug, Error)]
pub enum StateUpdateError {
    #[error("RPC Error: {0}")]
    RpcError(#[from] ProviderError),
    #[error("Conversion failed: {0}")]
    ConversionFailed(String),
    #[error("Block is still pending")]
    PendingBlock,
    #[error("Class compilation failed: {0}")]
    CompilationFailed(String),
}

// Legacy error type for backward compatibility
#[derive(Debug, Error)]
pub enum ProveBlockError {
    #[error("RPC Error: {0}")]
    RpcError(#[from] ProviderError),
    #[error("Conversion Failed: {0}")]
    ConversionFailed(String),
}

impl From<StateUpdateError> for ProveBlockError {
    fn from(err: StateUpdateError) -> Self {
        match err {
            StateUpdateError::RpcError(e) => ProveBlockError::RpcError(e),
            StateUpdateError::ConversionFailed(e) => ProveBlockError::ConversionFailed(e),
            _ => ProveBlockError::ConversionFailed(err.to_string()),
        }
    }
}

// ================================================================================================
// Public API
// ================================================================================================

/// Fetches and formats a state update for PIE generation.
///
/// This function orchestrates the entire state update processing pipeline:
/// 1. Fetches the state update from RPC
/// 2. Processes transaction traces to extract accessed contracts
/// 3. Compiles contract classes to CASM format
/// 4. Formats the data for OS consumption
///
/// # Arguments
///
/// * `rpc_client` - RPC client for fetching blockchain data
/// * `previous_block_id` - Previous block ID for context (None for genesis)
/// * `block_id` - Target block ID to process
/// * `accessed_addresses` - Set of contract addresses accessed in the block
/// * `accessed_classes` - Set of class hashes accessed in the block
///
/// # Returns
///
/// Returns a `FormattedStateUpdate` containing all processed state data
/// or an error if any step fails.
///
/// # Errors
///
/// This function can return various errors including
/// - `StateUpdateError::RpcError` for RPC communication failures
/// - `StateUpdateError::PendingBlock` if the block is still pending
/// - `StateUpdateError::CompilationFailed` for class compilation errors
/// - `StateUpdateError::ConversionFailed` for data conversion errors
pub(crate) async fn get_formatted_state_update(
    rpc_client: &RpcClient,
    previous_block_id: PreviousBlockId,
    block_id: BlockId,
    accessed_addresses: HashSet<Felt>,
    accessed_classes: HashSet<Felt>,
) -> Result<FormattedStateUpdate, Box<dyn std::error::Error>> {
    info!("Starting state update processing for block {:?}", block_id);

    // Handle genesis block case
    let Some(previous_block_id) = previous_block_id else {
        info!("Processing genesis block - returning empty state update");
        return Ok(FormattedStateUpdate::default());
    };

    // Fetch and validate state update
    let state_update = fetch_state_update(rpc_client, block_id).await?;
    let state_diff = &state_update.state_diff;

    // Extract declared classes
    let declared_classes = extract_declared_classes(state_diff);
    info!("Found {} declared classes", declared_classes.len());

    // Build compiled classes and mappings
    let mut class_hash_to_compiled_class_hash = HashMap::new();
    let compiled_result = build_compiled_classes(
        rpc_client,
        previous_block_id,
        block_id,
        &accessed_addresses,
        &declared_classes,
        &accessed_classes,
        &mut class_hash_to_compiled_class_hash,
    )
    .await?;

    // Format declared classes for OS consumption
    format_declared_classes(state_diff, &mut class_hash_to_compiled_class_hash);

    info!("State update processing completed successfully");

    Ok(FormattedStateUpdate {
        class_hash_to_compiled_class_hash,
        compiled_classes: compiled_result.compiled_classes,
        deprecated_compiled_classes: compiled_result.deprecated_compiled_classes,
        declared_class_hash_component_hashes: compiled_result.declared_component_hashes,
    })
}

/// Extracts accessed contract addresses and class hashes from transaction traces.
///
/// This function processes transaction traces to identify all contracts and classes
/// that were accessed during block execution, including nested function calls.
///
/// # Arguments
///
/// * `traces` - Array of transaction traces with hashes
///
/// # Returns
///
/// Returns a tuple containing:
/// - Set of accessed contract addresses
/// - Set of accessed class hashes
///
/// # Example
///
/// ```rust
/// let traces = get_block_traces(block_id).await?;
/// let (addresses, classes) = get_subcalled_contracts_from_tx_traces(&traces);
/// println!("Found {} addresses and {} classes", addresses.len(), classes.len());
/// ```
pub(crate) fn get_subcalled_contracts_from_tx_traces(
    traces: &[TransactionTraceWithHash],
) -> (HashSet<Felt252>, HashSet<Felt252>) {
    info!("Processing {} transaction traces", traces.len());

    let mut result = TraceProcessingResult { accessed_addresses: HashSet::new(), accessed_classes: HashSet::new() };

    for (index, trace) in traces.iter().enumerate() {
        debug!("Processing trace {}/{}", index + 1, traces.len());
        process_transaction_trace(&trace.trace_root, &mut result);
    }

    info!(
        "Extracted {} accessed addresses and {} accessed classes",
        result.accessed_addresses.len(),
        result.accessed_classes.len()
    );

    (result.accessed_addresses, result.accessed_classes)
}

// ================================================================================================
// Private Helper Functions
// ================================================================================================

/// Fetches state update from RPC and validates it's not pending.
async fn fetch_state_update(
    rpc_client: &RpcClient,
    block_id: BlockId,
) -> Result<starknet::core::types::StateUpdate, StateUpdateError> {
    debug!("Fetching state update for block {:?}", block_id);

    let state_update =
        rpc_client.starknet_rpc().get_state_update(block_id).await.map_err(StateUpdateError::RpcError)?;

    match state_update {
        MaybePreConfirmedStateUpdate::Update(update) => {
            debug!("Successfully fetched state update");
            Ok(update)
        }
        MaybePreConfirmedStateUpdate::PreConfirmedUpdate(_) => {
            warn!("Block {:?} is still pending", block_id);
            Err(StateUpdateError::PendingBlock)
        }
    }
}

/// Extracts declared class hashes from state diff.
fn extract_declared_classes(state_diff: &StateDiff) -> HashSet<Felt252> {
    state_diff.declared_classes.iter().map(|declared_item| declared_item.class_hash).collect()
}

/// Builds compiled classes from accessed addresses and classes.
async fn build_compiled_classes(
    rpc_client: &RpcClient,
    previous_block_id: BlockId,
    block_id: BlockId,
    accessed_addresses: &HashSet<Felt252>,
    declared_classes: &HashSet<Felt252>,
    accessed_classes: &HashSet<Felt252>,
    class_hash_to_compiled_class_hash: &mut HashMap<Felt252, Felt252>,
) -> Result<CompiledClassResult, StateUpdateError> {
    info!(
        "Building compiled classes from {} addresses and {} classes",
        accessed_addresses.len(),
        accessed_classes.len()
    );

    let mut result = CompiledClassResult {
        compiled_classes: HashMap::new(),
        deprecated_compiled_classes: HashMap::new(),
        declared_component_hashes: HashMap::new(),
    };

    // Process accessed addresses (both current and previous blocks)
    process_accessed_addresses(
        rpc_client,
        accessed_addresses,
        previous_block_id,
        block_id,
        class_hash_to_compiled_class_hash,
        &mut result,
    )
    .await?;

    // Process accessed classes
    process_accessed_classes(rpc_client, accessed_classes, block_id, class_hash_to_compiled_class_hash, &mut result)
        .await?;

    // Process declared classes for component hashes
    process_declared_classes(rpc_client, declared_classes, block_id, &mut result).await?;

    info!("Compiled classes processing completed successfully");
    Ok(result)
}

/// Processes accessed contract addresses to extract their classes.
async fn process_accessed_addresses(
    rpc_client: &RpcClient,
    accessed_addresses: &HashSet<Felt252>,
    previous_block_id: BlockId,
    block_id: BlockId,
    class_hash_to_compiled_class_hash: &mut HashMap<Felt252, Felt252>,
    result: &mut CompiledClassResult,
) -> Result<(), StateUpdateError> {
    for contract_address in accessed_addresses {
        // Skip special addresses
        if *contract_address == Felt::TWO || *contract_address == Felt::ONE {
            continue;
        }

        debug!("Processing contract address: {:?}", contract_address);

        // Try to get class from previous block (may fail if contract was deployed in current block)
        if let Err(e) = add_compiled_class_from_contract(
            rpc_client,
            *contract_address,
            previous_block_id,
            class_hash_to_compiled_class_hash,
            result,
        )
        .await
        {
            match e {
                StateUpdateError::RpcError(ProviderError::StarknetError(StarknetError::ContractNotFound)) => {
                    debug!(
                        "Contract {:?} not found in previous block (likely deployed in current block)",
                        contract_address
                    );
                }
                _ => return Err(e),
            }
        }

        // Get class from current block
        add_compiled_class_from_contract(
            rpc_client,
            *contract_address,
            block_id,
            class_hash_to_compiled_class_hash,
            result,
        )
        .await?;
    }

    Ok(())
}

/// Processes accessed class hashes directly.
async fn process_accessed_classes(
    rpc_client: &RpcClient,
    accessed_classes: &HashSet<Felt252>,
    block_id: BlockId,
    class_hash_to_compiled_class_hash: &mut HashMap<Felt252, Felt252>,
    result: &mut CompiledClassResult,
) -> Result<(), StateUpdateError> {
    for class_hash in accessed_classes {
        debug!("Processing class hash: {:?}", class_hash);

        let contract_class =
            rpc_client.starknet_rpc().get_class(block_id, class_hash).await.map_err(StateUpdateError::RpcError)?;

        add_compiled_class(*class_hash, contract_class, class_hash_to_compiled_class_hash, result)?;
    }

    Ok(())
}

/// Processes declared classes to extract component hashes.
async fn process_declared_classes(
    rpc_client: &RpcClient,
    declared_classes: &HashSet<Felt252>,
    block_id: BlockId,
    result: &mut CompiledClassResult,
) -> Result<(), StateUpdateError> {
    for class_hash in declared_classes {
        debug!("Processing declared class: {:?}", class_hash);

        let contract_class =
            rpc_client.starknet_rpc().get_class(block_id, class_hash).await.map_err(StateUpdateError::RpcError)?;

        if let starknet::core::types::ContractClass::Sierra(sierra_class) = contract_class {
            let component_hashes = ContractClassComponentHashes::from(sierra_class);
            result.declared_component_hashes.insert(*class_hash, component_hashes);
        }
    }

    Ok(())
}

/// Processes a single transaction trace to extract accessed contracts and classes.
fn process_transaction_trace(trace: &TransactionTrace, result: &mut TraceProcessingResult) {
    match trace {
        TransactionTrace::Invoke(invoke_trace) => {
            if let Some(inv) = &invoke_trace.validate_invocation {
                process_function_invocations(inv, result);
            }
            if let ExecuteInvocation::Success(inv) = &invoke_trace.execute_invocation {
                process_function_invocations(inv, result);
            }
            if let Some(inv) = &invoke_trace.fee_transfer_invocation {
                process_function_invocations(inv, result);
            }
        }
        TransactionTrace::Declare(declare_trace) => {
            if let Some(inv) = &declare_trace.validate_invocation {
                process_function_invocations(inv, result);
            }
            if let Some(inv) = &declare_trace.fee_transfer_invocation {
                process_function_invocations(inv, result);
            }
        }
        TransactionTrace::L1Handler(l1handler_trace) => {
            if let ExecuteInvocation::Success(inv) = &l1handler_trace.function_invocation {
                process_function_invocations(inv, result);
            }
        }
        TransactionTrace::DeployAccount(deploy_trace) => {
            if let Some(inv) = &deploy_trace.validate_invocation {
                process_function_invocations(inv, result);
            }
            if let Some(inv) = &deploy_trace.fee_transfer_invocation {
                process_function_invocations(inv, result);
            }
            process_function_invocations(&deploy_trace.constructor_invocation, result);
        }
    }
}

/// Recursively processes function invocations to extract contract addresses and class hashes.
fn process_function_invocations(inv: &FunctionInvocation, result: &mut TraceProcessingResult) {
    result.accessed_addresses.insert(inv.contract_address);
    result.accessed_classes.insert(inv.class_hash);

    // Recursively process nested calls
    for call in &inv.calls {
        process_function_invocations(call, result);
    }
}

/// Fetches and compiles a contract class from a contract address.
async fn add_compiled_class_from_contract(
    rpc_client: &RpcClient,
    contract_address: Felt,
    block_id: BlockId,
    class_hash_to_compiled_class_hash: &mut HashMap<Felt252, Felt252>,
    result: &mut CompiledClassResult,
) -> Result<(), StateUpdateError> {
    let class_hash = rpc_client
        .starknet_rpc()
        .get_class_hash_at(block_id, contract_address)
        .await
        .map_err(StateUpdateError::RpcError)?;

    let contract_class =
        rpc_client.starknet_rpc().get_class(block_id, class_hash).await.map_err(StateUpdateError::RpcError)?;

    add_compiled_class(class_hash, contract_class, class_hash_to_compiled_class_hash, result)
}

/// Compiles and adds a contract class to the result.
fn add_compiled_class(
    class_hash: Felt,
    contract_class: starknet::core::types::ContractClass,
    class_hash_to_compiled_class_hash: &mut HashMap<Felt252, Felt252>,
    result: &mut CompiledClassResult,
) -> Result<(), StateUpdateError> {
    // Skip if we already have this class
    if class_hash_to_compiled_class_hash.contains_key(&class_hash) {
        debug!("Class {:?} already processed, skipping", class_hash);
        return Ok(());
    }

    let compiled_class = compile_contract_class(contract_class)?;
    let compiled_class_hash = compiled_class
        .class_hash()
        .map_err(|e| StateUpdateError::CompilationFailed(format!("Failed to get class hash: {:?}", e)))?;

    match compiled_class {
        GenericCompiledClass::Cairo0(deprecated_cc) => {
            debug!("Adding deprecated class: {:?}", class_hash);
            result.deprecated_compiled_classes.insert(class_hash, deprecated_cc);
        }
        GenericCompiledClass::Cairo1(casm_cc) => {
            debug!("Adding compiled class: {:?} -> {:?}", class_hash, compiled_class_hash);
            class_hash_to_compiled_class_hash.insert(class_hash, compiled_class_hash.into());
            result.compiled_classes.insert(compiled_class_hash.into(), casm_cc);
        }
    }

    Ok(())
}

/// Compiles a contract class to CASM format.
fn compile_contract_class(
    contract_class: starknet::core::types::ContractClass,
) -> Result<GenericCompiledClass, StateUpdateError> {
    let compiled_class = match contract_class {
        starknet::core::types::ContractClass::Sierra(sierra_cc) => {
            let sierra_class = GenericSierraContractClass::from(sierra_cc);
            let compiled_class = sierra_class
                .compile()
                .map_err(|e| StateUpdateError::CompilationFailed(format!("Sierra compilation failed: {:?}", e)))?;
            GenericCompiledClass::Cairo1(compiled_class)
        }
        starknet::core::types::ContractClass::Legacy(legacy_cc) => {
            let compiled_class = GenericDeprecatedCompiledClass::try_from(legacy_cc).map_err(|e| {
                StateUpdateError::ConversionFailed(format!("Failed to convert legacy contract class: {:?}", e))
            })?;
            GenericCompiledClass::Cairo0(compiled_class)
        }
    };

    Ok(compiled_class)
}

/// Formats declared classes for OS consumption by setting compiled class hashes to zero.
fn format_declared_classes(state_diff: &StateDiff, class_hash_to_compiled_class_hash: &mut HashMap<Felt252, Felt252>) {
    debug!("Formatting {} declared classes", state_diff.declared_classes.len());

    for class in &state_diff.declared_classes {
        class_hash_to_compiled_class_hash.insert(class.class_hash, Felt::ZERO);
    }
}
