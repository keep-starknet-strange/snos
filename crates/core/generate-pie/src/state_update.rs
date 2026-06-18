//! State Update Processing Module
//!
//! This module handles the processing of Starknet state updates, including:
//! - Fetching and formatting state updates from RPC
//! - Compiling contract classes to CASM format
//! - Managing class hash mappings and component hashes
//!
//! The main entry point is [`get_formatted_state_update`] which orchestrates the entire
//! state update processing pipeline.

use cairo_vm::Felt252;
use futures::stream::{self, StreamExt};
use log::{debug, info, warn};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rpc_client::utils::execute_with_retry;
use rpc_client::RpcClient;
use starknet::core::types::{BlockId, MaybePreConfirmedStateUpdate, StarknetError, StateDiff};
use starknet::providers::Provider;
use starknet::providers::ProviderError;
use starknet_api::core::ClassHash;
use starknet_os_types::casm_contract_class::GenericCasmContractClass;
use starknet_os_types::class_hash_utils::ContractClassComponentHashes;
use starknet_os_types::compiled_class::GenericCompiledClass;
use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;
use starknet_os_types::sierra_contract_class::GenericSierraContractClass;
use starknet_types_core::felt::Felt;
use std::collections::{HashMap, HashSet};
use thiserror::Error;

use crate::constants::{is_special_contract_felt, MAX_CONCURRENT_GET_CLASS_REQUESTS};
use crate::utils::core_state_diff_to_thin_state_diff;

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
    /// Classes migrated from Poseidon to BLAKE hash (SNIP-34).
    /// Maps class_hash -> compiled_class_hash_v2 (BLAKE)
    pub migrated_compiled_classes: HashMap<Felt252, Felt252>,
    /// Thin state diff representation used for block hash commitment computation.
    pub thin_state_diff: starknet_api::state::ThinStateDiff,
}

impl FormattedStateUpdate {
    /// Processes contract classes from the state update.
    ///
    /// This function converts the raw contract classes from the state update
    /// into the proper formats needed for the OS input.
    ///
    /// # Returns
    ///
    /// Returns a `ContractClassProcessingResult` containing processed classes
    /// or an error if any conversion fails.
    #[allow(clippy::result_large_err)]
    pub fn process_contract_classes(
        &self,
    ) -> Result<ContractClassProcessingResult, crate::error::BlockProcessingError> {
        use crate::error::BlockProcessingError;
        use cairo_lang_starknet_classes::casm_contract_class::CasmContractClass;
        use log::{debug, info};
        use starknet_api::core::{ClassHash, CompiledClassHash};
        use starknet_api::deprecated_contract_class::ContractClass;
        use starknet_api::state::ContractClassComponentHashes;
        use std::collections::BTreeMap;

        info!("Processing contract classes");

        let compiled_classes = &self.compiled_classes;
        let deprecated_compiled_classes = &self.deprecated_compiled_classes;

        // Process declared class hash component hashes
        let declared_class_hash_component_hashes: HashMap<ClassHash, ContractClassComponentHashes> = self
            .declared_class_hash_component_hashes
            .iter()
            .map(|(class_hash, component_hashes)| (ClassHash(*class_hash), component_hashes.to_os_format()))
            .collect();

        // Convert compiled classes to BTreeMap with ClassHash keys
        let mut compiled_classes_btree: BTreeMap<CompiledClassHash, CasmContractClass> = BTreeMap::new();
        for (class_hash_felt, generic_class) in compiled_classes {
            debug!("Processing class hash: {:?}", class_hash_felt);
            let class_hash = CompiledClassHash(*class_hash_felt);
            let cairo_lang_class = generic_class
                .get_cairo_lang_contract_class()
                .map_err(|e| {
                    BlockProcessingError::ContractClassConversion(format!(
                        "Failed to get cairo-lang contract class: {:?}",
                        e
                    ))
                })?
                .clone();
            debug!("Converted class hash: {:?}", class_hash);
            compiled_classes_btree.insert(class_hash, cairo_lang_class);
        }

        // Convert deprecated compiled classes to BTreeMap with ClassHash keys
        let mut deprecated_compiled_classes_btree: BTreeMap<ClassHash, ContractClass> = BTreeMap::new();

        for (class_hash_felt, generic_class) in deprecated_compiled_classes {
            let class_hash = ClassHash(*class_hash_felt);
            let starknet_api_class = generic_class.clone().to_starknet_api_contract_class().map_err(|e| {
                BlockProcessingError::ContractClassConversion(format!(
                    "Failed to convert to starknet-api contract class: {:?}",
                    e
                ))
            })?;
            deprecated_compiled_classes_btree.insert(class_hash, starknet_api_class);
        }

        info!(
            "Converted {} compiled classes and {} deprecated classes",
            compiled_classes_btree.len(),
            deprecated_compiled_classes_btree.len()
        );

        Ok(ContractClassProcessingResult {
            compiled_classes: compiled_classes_btree,
            deprecated_compiled_classes: deprecated_compiled_classes_btree,
            declared_class_hash_component_hashes,
        })
    }
}

/// Result containing compiled class data.
struct CompiledClassResult {
    compiled_classes: HashMap<Felt252, GenericCasmContractClass>,
    deprecated_compiled_classes: HashMap<Felt252, GenericDeprecatedCompiledClass>,
    declared_component_hashes: HashMap<Felt252, ContractClassComponentHashes>,
}

struct CompiledClassBuildInputs<'a> {
    previous_block_id: PreviousBlockId,
    block_id: BlockId,
    accessed_addresses: &'a HashSet<Felt252>,
    pre_state_class_hashes: &'a HashMap<Felt252, ClassHash>,
    declared_classes: &'a HashSet<Felt252>,
    accessed_classes: &'a HashSet<Felt252>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StateScope {
    Previous,
    Current,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AddressBlockLookup {
    address: Felt252,
    block_id: BlockId,
    scope: StateScope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AddressClassFetch {
    address: Felt252,
    block_id: BlockId,
    scope: StateScope,
    class_hash: Felt,
}

type AddressClassFetchPlan = (Vec<AddressBlockLookup>, Vec<AddressClassFetch>);

/// Result containing processed contract class data.
pub struct ContractClassProcessingResult {
    pub compiled_classes: std::collections::BTreeMap<
        starknet_api::core::CompiledClassHash,
        cairo_lang_starknet_classes::casm_contract_class::CasmContractClass,
    >,
    pub deprecated_compiled_classes: std::collections::BTreeMap<
        starknet_api::core::ClassHash,
        starknet_api::deprecated_contract_class::ContractClass,
    >,
    pub declared_class_hash_component_hashes:
        HashMap<starknet_api::core::ClassHash, starknet_api::state::ContractClassComponentHashes>,
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

// ================================================================================================
// Public API
// ================================================================================================

/// Fetches and formats a state update for PIE generation.
///
/// This function orchestrates the entire state update processing pipeline:
/// 1. Fetches the state update from RPC
/// 2. Uses the executed-address and executed-class sets collected from Blockifier
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
    pre_state_class_hashes: &HashMap<Felt252, ClassHash>,
) -> Result<FormattedStateUpdate, Box<dyn std::error::Error>> {
    info!("Starting state update processing for block {:?}", block_id);

    // Fetch and validate state update
    let state_update = fetch_state_update(rpc_client, block_id).await?;
    let state_diff = &state_update.state_diff;
    let thin_state_diff = core_state_diff_to_thin_state_diff(state_diff)?;

    // Extract declared classes
    let declared_classes = extract_declared_classes(state_diff);
    info!("Found {} declared classes", declared_classes.len());

    // Extract migrated compiled classes (SNIP-34)
    let migrated_compiled_classes = extract_migrated_compiled_classes(state_diff);
    info!("Found {} migrated compiled classes", migrated_compiled_classes.len());

    // Build compiled classes and mappings
    let mut class_hash_to_compiled_class_hash = HashMap::new();
    let compiled_result = build_compiled_classes(
        rpc_client,
        CompiledClassBuildInputs {
            previous_block_id,
            block_id,
            accessed_addresses: &accessed_addresses,
            pre_state_class_hashes,
            declared_classes: &declared_classes,
            accessed_classes: &accessed_classes,
        },
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
        migrated_compiled_classes,
        thin_state_diff,
    })
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

    let state_update = execute_with_retry(&format!("get_state_update(block_id: {block_id:?})"), || {
        rpc_client.starknet_rpc().get_state_update(block_id)
    })
    .await
    .map_err(StateUpdateError::RpcError)?;

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

/// Extracts migrated compiled classes from state diff (SNIP-34).
/// Returns a map of class_hash -> compiled_class_hash_v2 (BLAKE).
fn extract_migrated_compiled_classes(state_diff: &StateDiff) -> HashMap<Felt252, Felt252> {
    state_diff
        .migrated_compiled_classes
        .as_ref()
        .map(|classes| classes.iter().map(|item| (item.class_hash, item.compiled_class_hash)).collect())
        .unwrap_or_default()
}

fn collect_fetched_items<K, T>(
    fetched_results: Vec<(K, Result<T, ProviderError>)>,
) -> Result<Vec<(K, T)>, StateUpdateError> {
    fetched_results
        .into_iter()
        .map(|(key, result)| result.map(|value| (key, value)).map_err(StateUpdateError::RpcError))
        .collect()
}

fn plan_accessed_address_class_fetches(
    addresses_to_process: &[Felt252],
    pre_state_class_hashes: &HashMap<Felt252, ClassHash>,
    previous_block_id: PreviousBlockId,
    block_id: BlockId,
) -> AddressClassFetchPlan {
    let mut address_block_pairs = Vec::new();
    let mut class_fetch_pairs = Vec::new();

    for address in addresses_to_process {
        if let Some(previous_block_id) = previous_block_id {
            if let Some(previous_class_hash) = pre_state_class_hashes.get(address) {
                if previous_class_hash.0 == Felt::ZERO {
                    debug!(
                        "Contract {:?} has no class hash in the previous state; skipping previous class fetch",
                        address
                    );
                } else {
                    class_fetch_pairs.push(AddressClassFetch {
                        address: *address,
                        block_id: previous_block_id,
                        scope: StateScope::Previous,
                        class_hash: previous_class_hash.0,
                    });
                }
            } else {
                address_block_pairs.push(AddressBlockLookup {
                    address: *address,
                    block_id: previous_block_id,
                    scope: StateScope::Previous,
                });
            }
        }
        address_block_pairs.push(AddressBlockLookup { address: *address, block_id, scope: StateScope::Current });
    }

    (address_block_pairs, class_fetch_pairs)
}

/// Builds compiled classes from accessed addresses and classes.
async fn build_compiled_classes(
    rpc_client: &RpcClient,
    inputs: CompiledClassBuildInputs<'_>,
    class_hash_to_compiled_class_hash: &mut HashMap<Felt252, Felt252>,
) -> Result<CompiledClassResult, StateUpdateError> {
    info!(
        "Building compiled classes from {} addresses and {} classes",
        inputs.accessed_addresses.len(),
        inputs.accessed_classes.len()
    );

    let mut result = CompiledClassResult {
        compiled_classes: HashMap::new(),
        deprecated_compiled_classes: HashMap::new(),
        declared_component_hashes: HashMap::new(),
    };

    // Process accessed addresses (both current and previous blocks)
    process_accessed_addresses(
        rpc_client,
        inputs.accessed_addresses,
        inputs.pre_state_class_hashes,
        inputs.previous_block_id,
        inputs.block_id,
        class_hash_to_compiled_class_hash,
        &mut result,
    )
    .await?;

    // Process accessed classes
    process_accessed_classes(
        rpc_client,
        inputs.accessed_classes,
        inputs.block_id,
        class_hash_to_compiled_class_hash,
        &mut result,
    )
    .await?;

    // Process declared classes for component hashes
    process_declared_classes(rpc_client, inputs.declared_classes, inputs.block_id, &mut result).await?;

    info!("Compiled classes processing completed successfully");
    Ok(result)
}

/// Processes accessed contract addresses to extract their classes.
async fn process_accessed_addresses(
    rpc_client: &RpcClient,
    accessed_addresses: &HashSet<Felt252>,
    pre_state_class_hashes: &HashMap<Felt252, ClassHash>,
    previous_block_id: PreviousBlockId,
    block_id: BlockId,
    class_hash_to_compiled_class_hash: &mut HashMap<Felt252, Felt252>,
    result: &mut CompiledClassResult,
) -> Result<(), StateUpdateError> {
    // Filter out special addresses
    let addresses_to_process: Vec<Felt252> =
        accessed_addresses.iter().filter(|addr| !is_special_contract_felt(**addr)).copied().collect();

    if addresses_to_process.is_empty() {
        return Ok(());
    }

    info!(
        "Processing {} accessed addresses with max {} concurrent requests",
        addresses_to_process.len(),
        MAX_CONCURRENT_GET_CLASS_REQUESTS
    );

    // Phase 1: Reuse pre-state class hashes from Blockifier when available, and only hit RPC
    // for the remaining previous-block lookups plus all current-block lookups.
    let (address_block_pairs, mut class_fetch_pairs) =
        plan_accessed_address_class_fetches(&addresses_to_process, pre_state_class_hashes, previous_block_id, block_id);

    let class_hash_results: Vec<(AddressBlockLookup, Result<Felt, ProviderError>)> = stream::iter(address_block_pairs)
        .map(|lookup| async move {
            let operation_name =
                format!("get_class_hash_at(block_id: {:?}, address: {:?})", lookup.block_id, lookup.address);
            let class_hash = execute_with_retry(&operation_name, || {
                rpc_client.starknet_rpc().get_class_hash_at(lookup.block_id, lookup.address)
            })
            .await;
            (lookup, class_hash)
        })
        .buffer_unordered(MAX_CONCURRENT_GET_CLASS_REQUESTS)
        .collect()
        .await;

    let mut addresses_present_in_previous_state: HashSet<Felt252> = pre_state_class_hashes
        .iter()
        .filter_map(|(address, class_hash)| (class_hash.0 != Felt::ZERO).then_some(*address))
        .collect();
    for (lookup, class_hash_result) in &class_hash_results {
        if lookup.scope == StateScope::Previous
            && matches!(class_hash_result, Ok(class_hash) if *class_hash != Felt::ZERO)
        {
            addresses_present_in_previous_state.insert(lookup.address);
        }
    }

    // Phase 2: Fetch all contract classes concurrently.
    for (lookup, class_hash_result) in class_hash_results {
        match class_hash_result {
            Ok(class_hash) => {
                class_fetch_pairs.push(AddressClassFetch {
                    address: lookup.address,
                    block_id: lookup.block_id,
                    scope: lookup.scope,
                    class_hash,
                });
            }
            Err(ProviderError::StarknetError(StarknetError::ContractNotFound)) => {
                if lookup.scope == StateScope::Previous {
                    debug!(
                        "Contract {:?} not found in previous block (likely deployed in current block)",
                        lookup.address
                    );
                } else if addresses_present_in_previous_state.contains(&lookup.address) {
                    return Err(StateUpdateError::ConversionFailed(format!(
                        "Contract {:#x} was present in the previous state but RPC reported ContractNotFound in current block {:?}",
                        lookup.address, lookup.block_id
                    )));
                } else {
                    debug!(
                        "Contract {:?} not found in current block {:?}; skipping class fetch for non-deployed accessed address",
                        lookup.address, lookup.block_id
                    );
                }
            }
            Err(e) => return Err(StateUpdateError::RpcError(e)),
        }
    }

    info!("Fetching {} contract classes concurrently...", class_fetch_pairs.len());

    let class_results: Vec<(Felt, Result<starknet::core::types::ContractClass, ProviderError>)> =
        stream::iter(class_fetch_pairs)
            .map(|fetch| async move {
                let operation_name =
                    format!("get_class(block_id: {:?}, class_hash: {:?})", fetch.block_id, fetch.class_hash);
                let contract_class = execute_with_retry(&operation_name, || {
                    rpc_client.starknet_rpc().get_class(fetch.block_id, fetch.class_hash)
                })
                .await;
                (fetch.class_hash, contract_class)
            })
            .buffer_unordered(MAX_CONCURRENT_GET_CLASS_REQUESTS)
            .collect()
            .await;

    info!("Fetched {} contract classes, now compiling in parallel...", class_results.len());

    // Phase 3: Compile classes in parallel using rayon (CPU parallelization)
    let fetched_classes = collect_fetched_items(class_results)?;

    let compilation_results: Vec<Result<(Felt, GenericCompiledClass), StateUpdateError>> = fetched_classes
        .into_par_iter()
        .map(|(class_hash, contract_class)| {
            let compiled_class = compile_contract_class(contract_class)?;
            Ok((class_hash, compiled_class))
        })
        .collect();

    // Add compiled classes to result
    for compiled_result in compilation_results {
        let (class_hash, compiled_class) = compiled_result?;
        add_compiled_class_internal(class_hash, compiled_class, class_hash_to_compiled_class_hash, result)?;
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
    if accessed_classes.is_empty() {
        return Ok(());
    }

    info!(
        "Processing {} accessed classes with max {} concurrent requests",
        accessed_classes.len(),
        MAX_CONCURRENT_GET_CLASS_REQUESTS
    );

    // Phase 1: Fetch all contract classes concurrently (network I/O parallelization)
    let class_hashes: Vec<Felt252> = accessed_classes.iter().copied().collect();
    let class_fetch_results: Vec<(Felt252, Result<starknet::core::types::ContractClass, ProviderError>)> =
        stream::iter(class_hashes.clone())
            .map(|class_hash| async move {
                debug!("Fetching class hash: {:?}", class_hash);
                let operation_name = format!("get_class(block_id: {block_id:?}, class_hash: {class_hash:?})");
                let contract_class =
                    execute_with_retry(&operation_name, || rpc_client.starknet_rpc().get_class(block_id, class_hash))
                        .await;
                (class_hash, contract_class)
            })
            .buffer_unordered(MAX_CONCURRENT_GET_CLASS_REQUESTS)
            .collect()
            .await;

    let fetched_classes = collect_fetched_items(class_fetch_results)?;

    info!("Fetched {} contract classes, now compiling in parallel...", fetched_classes.len());

    // Phase 2: Compile classes in parallel using rayon (CPU parallelization)
    let compilation_results: Vec<Result<(Felt252, GenericCompiledClass), StateUpdateError>> = fetched_classes
        .into_par_iter()
        .map(|(class_hash, contract_class)| {
            let compiled_class = compile_contract_class(contract_class)?;
            Ok((class_hash, compiled_class))
        })
        .collect();

    // Add compiled classes to result
    for compiled_result in compilation_results {
        let (class_hash, compiled_class) = compiled_result?;
        add_compiled_class_internal(class_hash, compiled_class, class_hash_to_compiled_class_hash, result)?;
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
    if declared_classes.is_empty() {
        return Ok(());
    }

    info!(
        "Processing {} declared classes with max {} concurrent requests",
        declared_classes.len(),
        MAX_CONCURRENT_GET_CLASS_REQUESTS
    );

    // Fetch all declared classes concurrently
    let class_hashes: Vec<Felt252> = declared_classes.iter().copied().collect();
    let class_fetch_results: Vec<(Felt252, Result<starknet::core::types::ContractClass, ProviderError>)> =
        stream::iter(class_hashes)
            .map(|class_hash| async move {
                debug!("Fetching declared class: {:?}", class_hash);
                let operation_name = format!("get_class(block_id: {block_id:?}, class_hash: {class_hash:?})");
                let contract_class =
                    execute_with_retry(&operation_name, || rpc_client.starknet_rpc().get_class(block_id, class_hash))
                        .await;
                (class_hash, contract_class)
            })
            .buffer_unordered(MAX_CONCURRENT_GET_CLASS_REQUESTS)
            .collect()
            .await;

    // Extract component hashes from Sierra classes
    for (class_hash, contract_class_result) in class_fetch_results {
        let contract_class = contract_class_result.map_err(StateUpdateError::RpcError)?;

        if let starknet::core::types::ContractClass::Sierra(sierra_class) = contract_class {
            let component_hashes = ContractClassComponentHashes::from(sierra_class);
            result.declared_component_hashes.insert(class_hash, component_hashes);
        }
    }

    Ok(())
}

/// Adds an already-compiled class to the result (used in optimized parallel compilation paths).
fn add_compiled_class_internal(
    class_hash: Felt,
    compiled_class: GenericCompiledClass,
    class_hash_to_compiled_class_hash: &mut HashMap<Felt252, Felt252>,
    result: &mut CompiledClassResult,
) -> Result<(), StateUpdateError> {
    if class_hash_to_compiled_class_hash.contains_key(&class_hash) {
        debug!("Class {:?} already processed, skipping", class_hash);
        return Ok(());
    }

    let compiled_class_hash = compiled_class
        .class_hash_v2()
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

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn collect_fetched_items_propagates_rpc_errors() {
        let fetched_results = vec![(Felt::ONE, Ok("ok")), (Felt::TWO, Err(ProviderError::RateLimited))];

        let error = collect_fetched_items(fetched_results).expect_err("rpc errors must not be dropped");

        assert!(matches!(error, StateUpdateError::RpcError(ProviderError::RateLimited)));
    }

    #[rstest]
    #[case::zero_pre_state_hash(ClassHash::default(), vec![])]
    #[case::non_zero_pre_state_hash(
        ClassHash(Felt::from_hex_unchecked("0x456")),
        vec![AddressClassFetch {
            address: Felt::from_hex_unchecked("0x123"),
            block_id: BlockId::Number(10),
            scope: StateScope::Previous,
            class_hash: Felt::from_hex_unchecked("0x456"),
        }]
    )]
    fn plan_accessed_address_class_fetches_respects_pre_state_class_hash(
        #[case] previous_class_hash: ClassHash,
        #[case] expected_class_fetch_pairs: Vec<AddressClassFetch>,
    ) {
        let address = Felt::from_hex_unchecked("0x123");
        let previous_block_id = Some(BlockId::Number(10));
        let block_id = BlockId::Number(11);
        let pre_state_class_hashes = HashMap::from([(address, previous_class_hash)]);

        let (address_block_pairs, class_fetch_pairs) =
            plan_accessed_address_class_fetches(&[address], &pre_state_class_hashes, previous_block_id, block_id);

        assert_eq!(class_fetch_pairs, expected_class_fetch_pairs);
        assert_eq!(address_block_pairs, vec![AddressBlockLookup { address, block_id, scope: StateScope::Current }]);
    }
}
