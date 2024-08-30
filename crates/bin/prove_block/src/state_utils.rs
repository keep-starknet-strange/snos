use std::collections::{HashMap, HashSet};

use cairo_vm::Felt252;
use starknet::core::types::{BlockId, MaybePendingStateUpdate, StateDiff};
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider};
use starknet_os_types::casm_contract_class::GenericCasmContractClass;
use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;
use starknet_os_types::sierra_contract_class::GenericSierraContractClass;

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

    let address_to_class_hash = format_deployed_contracts(&state_diff);
    // TODO: Handle deprecated clasees
    let mut class_hash_to_compiled_class_hash: HashMap<Felt252, Felt252> = format_declared_classes(&state_diff);
    let (compiled_contract_classes, _deprecated_compiled_contract_class) =
        build_compiled_class_and_maybe_update_class_hash_to_compiled_class_hash(
            provider,
            block_id,
            &accessed_addresses,
            &address_to_class_hash,
            &mut class_hash_to_compiled_class_hash,
        )
        .await?;

    Ok(FormattedStateUpdate { class_hash_to_compiled_class_hash, compiled_classes: compiled_contract_classes })
}

/// This function processes a set of accessed contract addresses to retrieve their
/// corresponding class hashes and compile them into `GenericCasmContractClass`.
/// If the class is already present in `address_to_class_hash`, it is used directly;
/// otherwise, it is fetched from the provided `JsonRpcClient`.
///
/// The resulting compiled classes and any associated mappings are returned, while
/// the `class_hash_to_compiled_class_hash` map is updated with new entries.
/// TODO: Handle deprecated classes
async fn build_compiled_class_and_maybe_update_class_hash_to_compiled_class_hash(
    provider: &JsonRpcClient<HttpTransport>,
    block_id: BlockId,
    accessed_addresses: &HashSet<Felt252>,
    address_to_class_hash: &HashMap<Felt252, Felt252>,
    class_hash_to_compiled_class_hash: &mut HashMap<Felt252, Felt252>,
) -> Result<
    (HashMap<Felt252, GenericCasmContractClass>, HashMap<Felt252, GenericDeprecatedCompiledClass>),
    ProveBlockError,
> {
    let mut compiled_contract_classes: HashMap<Felt252, GenericCasmContractClass> = HashMap::new();
    // TODO: Handle deprecated classes
    let mut deprecated_compiled_contract_classes: HashMap<Felt252, GenericDeprecatedCompiledClass> = HashMap::new();

    for contract_address in accessed_addresses {
        let class_hash = match address_to_class_hash.get(contract_address) {
            Some(class_hash) => class_hash,
            None => &provider.get_class_hash_at(block_id, contract_address).await?,
        };

        let contract_class = provider.get_class(block_id, class_hash).await?;
        match contract_class {
            starknet::core::types::ContractClass::Sierra(flattened_sierra_cc) => {
                let generic_sierra_cc = GenericSierraContractClass::from(flattened_sierra_cc);
                let generic_sierra_cc: GenericCasmContractClass = generic_sierra_cc.compile()?;
                let compiled_contract_hash: starknet_os_types::hash::GenericClassHash =
                    generic_sierra_cc.class_hash()?;
                compiled_contract_classes.insert(compiled_contract_hash.into(), generic_sierra_cc.clone());
                // TODO: Sanity check computed hash is the same that the one provided by RPC (when available)
                // TODO: We are inserting class_hash -> compiled class hash again
                class_hash_to_compiled_class_hash.insert(*class_hash, compiled_contract_hash.into());
            }
            starknet::core::types::ContractClass::Legacy(compressed_legacy_cc) => {
                let generic_deprecated_cc = GenericDeprecatedCompiledClass::try_from(compressed_legacy_cc).unwrap();
                deprecated_compiled_contract_classes.insert(*class_hash, generic_deprecated_cc);
            }
        };
    }
    Ok((compiled_contract_classes, deprecated_compiled_contract_classes))
}

/// Format StateDiff's DeclaredClassItem to a HashMap<class_hash, compiled_class_hash>
fn format_declared_classes(state_diff: &StateDiff) -> HashMap<Felt252, Felt252> {
    let class_hash_to_compiled_class_hash =
        state_diff.declared_classes.iter().map(|class| (class.class_hash, class.compiled_class_hash)).collect();
    class_hash_to_compiled_class_hash
}

/// Formats `StateDiff`'s `DeployedContractItem` into a `HashMap<contract_address, class_hash>`.
/// It also takes all subcalled contract addresses (which may or may not have diffs)
/// and fetches the class hash if it wasn't included in the `StateDiff`.
fn format_deployed_contracts(state_diff: &StateDiff) -> HashMap<Felt252, Felt252> {
    let address_to_class_hash: HashMap<_, _> =
        state_diff.deployed_contracts.iter().map(|contract| (contract.address, contract.class_hash)).collect();
    address_to_class_hash
}
