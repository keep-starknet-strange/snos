use std::collections::{HashMap, HashSet};

use anyhow::Error;
use cairo_vm::Felt252;
use starknet::core::types::{BlockId, MaybePendingStateUpdate, StateDiff};
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider};
use starknet_os_types::casm_contract_class::GenericCasmContractClass;
use starknet_os_types::sierra_contract_class::GenericSierraContractClass;

use crate::utils::get_subcalled_contracts_from_tx_traces;

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
pub(crate) async fn get_processed_state_update(
    provider: &JsonRpcClient<HttpTransport>,
    block_id: BlockId,
) -> Result<FormattedStateUpdate, Error> {
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
    let mut class_hash_to_compiled_class_hash: HashMap<Felt252, Felt252> = format_declared_classes(&state_diff);
    let compiled_classes = build_compiled_class_and_maybe_update_class_hash_to_compiled_class_hash(
        provider,
        block_id,
        &accessed_addresses,
        &address_to_class_hash,
        &mut class_hash_to_compiled_class_hash,
    )
    .await?;

    Ok(FormattedStateUpdate { class_hash_to_compiled_class_hash, compiled_classes })
}

async fn build_compiled_class_and_maybe_update_class_hash_to_compiled_class_hash(
    provider: &JsonRpcClient<HttpTransport>,
    block_id: BlockId,
    accessed_addresses: &HashSet<Felt252>,
    address_to_class_hash: &HashMap<Felt252, Felt252>,
    class_hash_to_compiled_class_hash: &mut HashMap<Felt252, Felt252>,
) -> Result<HashMap<Felt252, GenericCasmContractClass>, Error> {
    let mut compiled_classes: HashMap<Felt252, GenericCasmContractClass> = HashMap::new();
    for contract_address in accessed_addresses {
        let class_hash = match address_to_class_hash.get(contract_address) {
            Some(class_hash) => class_hash,
            None => &provider.get_class_hash_at(block_id, contract_address).await?,
        };

        let contract_class = provider.get_class(block_id, class_hash).await?;
        let generic_sierra_cc = match contract_class {
            starknet::core::types::ContractClass::Sierra(flattened_sierra_cc) => {
                GenericSierraContractClass::from(flattened_sierra_cc)
            }
            starknet::core::types::ContractClass::Legacy(_) => {
                unimplemented!("Fixme: Support legacy contract class")
            }
        };

        let generic_cc: GenericCasmContractClass = generic_sierra_cc.compile()?;
        let compiled_contract_hash: starknet_os_types::hash::GenericClassHash = generic_cc.class_hash()?;

        // TODO: Sanity check computed hash is the same that the one provided by RPC (when available)
        // TODO: We are inserting class_hash -> compiled class hash again
        class_hash_to_compiled_class_hash.insert(*class_hash, compiled_contract_hash.into());
        compiled_classes.insert(compiled_contract_hash.into(), generic_cc.clone());
    }
    Ok(compiled_classes)
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
