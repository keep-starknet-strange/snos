use std::collections::{HashMap, HashSet};

use cairo_vm::Felt252;
use starknet::core::types::{BlockId, MaybePendingStateUpdate, StateDiff};
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider};
use starknet_api::core::ContractAddress;
use starknet_os_types::casm_contract_class::GenericCasmContractClass;
use starknet_os_types::compiled_class::GenericCompiledClass;
use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;
use starknet_os_types::sierra_contract_class::GenericSierraContractClass;
use starknet_types_core::felt::Felt;

use crate::utils::get_subcalled_contracts_from_tx_traces;
use crate::ProveBlockError;

#[derive(Clone)]
pub struct FormattedStateUpdate {
    // TODO: Use more descriptive types
    pub class_hash_to_compiled_class_hash: HashMap<Felt252, Felt252>,
    pub compiled_classes: HashMap<Felt252, GenericCasmContractClass>,
}

/// Given the `block_id` of the target block to prove, it:
/// - Fetches the state update using the `starknet_getStateUpdate` RPC call.
/// - Fetches block transaction traces to obtain all accessed contract addresses in that block.
/// - Formats the RPC state updates to be "SharedState compatible."
/// - Consolidates that information into a `FormattedStateUpdate`.
pub(crate) async fn get_formatted_state_update(
    provider: &JsonRpcClient<HttpTransport>,
    previous_block_id: BlockId,
    block_id: BlockId,
) -> Result<FormattedStateUpdate, ProveBlockError> {
    let state_update = match provider.get_state_update(block_id).await.expect("Failed to get state update") {
        MaybePendingStateUpdate::Update(update) => update,
        MaybePendingStateUpdate::PendingUpdate(_) => {
            panic!("Block is still pending!")
        }
    };
    let state_diff = state_update.state_diff;

    // Extract other contracts used in our block from the block trace
    // We need this to get all the class hashes used and correctly feed address_to_class_hash
    let traces = provider.trace_block_transactions(block_id).await.expect("Failed to get block tx traces");
    let accessed_addresses: HashSet<Felt252> = get_subcalled_contracts_from_tx_traces(&traces);

    // TODO: Handle deprecated classes
    let mut class_hash_to_compiled_class_hash: HashMap<Felt252, Felt252> = format_declared_classes(&state_diff);
    let (compiled_contract_classes, _deprecated_compiled_contract_class) =
        build_compiled_class_and_maybe_update_class_hash_to_compiled_class_hash(
            provider,
            previous_block_id,
            block_id,
            &accessed_addresses,
            &mut class_hash_to_compiled_class_hash,
        )
        .await?;

    Ok(FormattedStateUpdate { class_hash_to_compiled_class_hash, compiled_classes: compiled_contract_classes })
}

/// Retrieves the compiled class associated to the contract address at a specific block
/// by getting the class from the RPC and compiling it to CASM if necessary (Cairo 1).
async fn get_compiled_class_for_contract(
    provider: &JsonRpcClient<HttpTransport>,
    block_id: BlockId,
    contract_address: ContractAddress,
) -> Result<GenericCompiledClass, ProveBlockError> {
    let class_hash = provider.get_class_hash_at(block_id, contract_address.0.key()).await?;
    let contract_class = provider.get_class(block_id, class_hash).await?;

    let compiled_class = match contract_class {
        starknet::core::types::ContractClass::Sierra(flattened_sierra_cc) => {
            let sierra_class = GenericSierraContractClass::from(flattened_sierra_cc);
            let compiled_class = sierra_class.compile()?;
            GenericCompiledClass::Cairo1(compiled_class)
        }
        starknet::core::types::ContractClass::Legacy(legacy_cc) => {
            let compiled_class = GenericDeprecatedCompiledClass::try_from(legacy_cc)?;
            GenericCompiledClass::Cairo0(compiled_class)
        }
    };

    Ok(compiled_class)
}

/// Fetches (+ compile) the contract class for the specified contract at the specified block
/// and adds it to the hashmaps that will then be added to the OS input.
async fn add_compiled_class_to_os_input(
    provider: &JsonRpcClient<HttpTransport>,
    contract_address: Felt,
    block_id: BlockId,
    class_hash_to_compiled_class_hash: &mut HashMap<Felt252, Felt252>,
    compiled_contract_classes: &mut HashMap<Felt, GenericCasmContractClass>,
    deprecated_compiled_contract_classes: &mut HashMap<Felt, GenericDeprecatedCompiledClass>,
) -> Result<(), ProveBlockError> {
    let class_hash = provider.get_class_hash_at(block_id, contract_address).await?;

    // Avoid fetching and compiling contract data if we already have this class.
    if class_hash_to_compiled_class_hash.contains_key(&class_hash) {
        return Ok(());
    }

    let compiled_class =
        get_compiled_class_for_contract(provider, block_id, contract_address.try_into().unwrap()).await?;
    let compiled_class_hash = compiled_class.class_hash()?;

    class_hash_to_compiled_class_hash.insert(class_hash, compiled_class_hash.into());

    match compiled_class {
        GenericCompiledClass::Cairo0(deprecated_cc) => {
            deprecated_compiled_contract_classes.insert(class_hash, deprecated_cc);
        }
        GenericCompiledClass::Cairo1(casm_cc) => {
            compiled_contract_classes.insert(compiled_class_hash.into(), casm_cc);
        }
    }

    Ok(())
}

/// This function processes a set of accessed contract addresses to retrieve their
/// corresponding class hashes and compile them into `GenericCasmContractClass`.
/// If the class is already present in `address_to_class_hash`, it is used directly;
/// otherwise, it is fetched from the provided `JsonRpcClient`.
///
/// The resulting compiled classes and any associated mappings are returned, while
/// the `class_hash_to_compiled_class_hash` map is updated with new entries.
async fn build_compiled_class_and_maybe_update_class_hash_to_compiled_class_hash(
    provider: &JsonRpcClient<HttpTransport>,
    previous_block_id: BlockId,
    block_id: BlockId,
    accessed_addresses: &HashSet<Felt252>,
    class_hash_to_compiled_class_hash: &mut HashMap<Felt252, Felt252>,
) -> Result<
    (HashMap<Felt252, GenericCasmContractClass>, HashMap<Felt252, GenericDeprecatedCompiledClass>),
    ProveBlockError,
> {
    let mut compiled_contract_classes: HashMap<Felt252, GenericCasmContractClass> = HashMap::new();
    let mut deprecated_compiled_contract_classes: HashMap<Felt252, GenericDeprecatedCompiledClass> = HashMap::new();

    for contract_address in accessed_addresses {
        // In case there is a class change, we need to get the compiled class for
        // the block to prove and for the previous block as they may differ.
        add_compiled_class_to_os_input(
            provider,
            *contract_address,
            previous_block_id,
            class_hash_to_compiled_class_hash,
            &mut compiled_contract_classes,
            &mut deprecated_compiled_contract_classes,
        )
        .await?;
        add_compiled_class_to_os_input(
            provider,
            *contract_address,
            block_id,
            class_hash_to_compiled_class_hash,
            &mut compiled_contract_classes,
            &mut deprecated_compiled_contract_classes,
        )
        .await?;
    }
    Ok((compiled_contract_classes, deprecated_compiled_contract_classes))
}

/// Format StateDiff's DeclaredClassItem to a HashMap<class_hash, compiled_class_hash>
fn format_declared_classes(state_diff: &StateDiff) -> HashMap<Felt252, Felt252> {
    let class_hash_to_compiled_class_hash =
        state_diff.declared_classes.iter().map(|class| (class.class_hash, class.compiled_class_hash)).collect();
    class_hash_to_compiled_class_hash
}
