use std::collections::{HashMap, HashSet};

use cairo_vm::Felt252;
use rpc_client::RpcClient;
use starknet::core::types::{BlockId, MaybePendingStateUpdate, StarknetError, StateDiff, TransactionTraceWithHash};
use starknet::providers::{Provider, ProviderError};
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
    pub deprecated_compiled_classes: HashMap<Felt252, GenericDeprecatedCompiledClass>,
}

/// Given the `block_id` of the target block to prove, it:
/// - Fetches the state update using the `starknet_getStateUpdate` RPC call.
/// - Fetches block transaction traces to obtain all accessed contract addresses in that block.
/// - Formats the RPC state updates to be "SharedState compatible."
/// - Consolidates that information into a `FormattedStateUpdate`.
pub(crate) async fn get_formatted_state_update(
    rpc_client: &RpcClient,
    previous_block_id: BlockId,
    block_id: BlockId,
) -> Result<(FormattedStateUpdate, Vec<TransactionTraceWithHash>), ProveBlockError> {
    let state_update =
        match rpc_client.starknet_rpc().get_state_update(block_id).await.expect("Failed to get state update") {
            MaybePendingStateUpdate::Update(update) => update,
            MaybePendingStateUpdate::PendingUpdate(_) => {
                panic!("Block is still pending!")
            }
        };
    let state_diff = state_update.state_diff;

    // Extract other contracts used in our block from the block trace
    // We need this to get all the class hashes used and correctly feed address_to_class_hash
    let traces =
        rpc_client.starknet_rpc().trace_block_transactions(block_id).await.expect("Failed to get block tx traces");
    let (accessed_addresses, accessed_classes) = get_subcalled_contracts_from_tx_traces(&traces);

    // TODO: Handle deprecated classes
    let mut class_hash_to_compiled_class_hash: HashMap<Felt252, Felt252> = format_declared_classes(&state_diff);
    let (compiled_contract_classes, deprecated_compiled_contract_classes) =
        build_compiled_class_and_maybe_update_class_hash_to_compiled_class_hash(
            rpc_client,
            previous_block_id,
            block_id,
            &accessed_addresses,
            &accessed_classes,
            &mut class_hash_to_compiled_class_hash,
        )
        .await?;

    Ok((
        FormattedStateUpdate {
            class_hash_to_compiled_class_hash,
            compiled_classes: compiled_contract_classes,
            deprecated_compiled_classes: deprecated_compiled_contract_classes,
        },
        traces,
    ))
}

/// Retrieves the compiled class for the given class hash at a specific block
/// by getting the class from the RPC and compiling it to CASM if necessary (Cairo 1).
async fn get_compiled_class_for_class_hash(
    provider: &RpcClient,
    block_id: BlockId,
    class_hash: Felt252,
) -> Result<GenericCompiledClass, ProveBlockError> {
    let contract_class = provider.starknet_rpc().get_class(block_id, class_hash).await?;

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
async fn add_compiled_class_from_contract_to_os_input(
    rpc_client: &RpcClient,
    contract_address: Felt,
    block_id: BlockId,
    class_hash_to_compiled_class_hash: &mut HashMap<Felt252, Felt252>,
    compiled_contract_classes: &mut HashMap<Felt, GenericCasmContractClass>,
    deprecated_compiled_contract_classes: &mut HashMap<Felt, GenericDeprecatedCompiledClass>,
) -> Result<(), ProveBlockError> {
    let class_hash = rpc_client.starknet_rpc().get_class_hash_at(block_id, contract_address).await?;
    add_compiled_class_from_class_hash_to_os_input(
        rpc_client,
        class_hash,
        block_id,
        class_hash_to_compiled_class_hash,
        compiled_contract_classes,
        deprecated_compiled_contract_classes,
    )
    .await
}

/// Fetches (+ compile) the contract class for the specified class at the specified block
/// and adds it to the hashmaps that will then be added to the OS input.
async fn add_compiled_class_from_class_hash_to_os_input(
    provider: &RpcClient,
    class_hash: Felt,
    block_id: BlockId,
    class_hash_to_compiled_class_hash: &mut HashMap<Felt252, Felt252>,
    compiled_contract_classes: &mut HashMap<Felt, GenericCasmContractClass>,
    deprecated_compiled_contract_classes: &mut HashMap<Felt, GenericDeprecatedCompiledClass>,
) -> Result<(), ProveBlockError> {
    // Avoid fetching and compiling contract data if we already have this class.
    if class_hash_to_compiled_class_hash.contains_key(&class_hash) {
        return Ok(());
    }

    let compiled_class = get_compiled_class_for_class_hash(provider, block_id, class_hash).await?;
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
    provider: &RpcClient,
    previous_block_id: BlockId,
    block_id: BlockId,
    accessed_addresses: &HashSet<Felt252>,
    accessed_classes: &HashSet<Felt252>,
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
        // Note that we must also consider the case where the contract was deployed in the current
        // block, so we can ignore "ContractNotFound" failures.
        if let Err(e) = add_compiled_class_from_contract_to_os_input(
            provider,
            *contract_address,
            previous_block_id,
            class_hash_to_compiled_class_hash,
            &mut compiled_contract_classes,
            &mut deprecated_compiled_contract_classes,
        )
        .await
        {
            match e {
                ProveBlockError::RpcError(ProviderError::StarknetError(StarknetError::ContractNotFound)) => {
                    // The contract was deployed in the current block, nothing to worry about
                }
                _ => return Err(e),
            }
        }

        add_compiled_class_from_contract_to_os_input(
            provider,
            *contract_address,
            block_id,
            class_hash_to_compiled_class_hash,
            &mut compiled_contract_classes,
            &mut deprecated_compiled_contract_classes,
        )
        .await?;
    }

    for class_hash in accessed_classes {
        add_compiled_class_from_class_hash_to_os_input(
            provider,
            *class_hash,
            previous_block_id,
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
    // The comment below explicits that the value should be 0 for new classes:
    // From execute_transactions.cairo
    // Note that prev_value=0 enforces that a class may be declared only once.
    // dict_update{dict_ptr=contract_class_changes}(
    //     key=[class_hash_ptr], prev_value=0, new_value=compiled_class_hash
    // );
    let class_hash_to_compiled_class_hash =
        state_diff.declared_classes.iter().map(|class| (class.class_hash, Felt::ZERO)).collect();
    class_hash_to_compiled_class_hash
}
