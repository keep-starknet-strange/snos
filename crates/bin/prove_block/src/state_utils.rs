use std::collections::{HashMap, HashSet};

use cairo_vm::Felt252;
use rpc_client::RpcClient;
use starknet::core::types::{BlockId, MaybePendingStateUpdate, StarknetError, StateDiff, TransactionTraceWithHash};
use starknet::providers::{Provider, ProviderError};
use starknet_os_types::casm_contract_class::GenericCasmContractClass;
use starknet_os_types::class_hash_utils::ContractClassComponentHashes;
use starknet_os_types::compiled_class::GenericCompiledClass;
use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;
use starknet_os_types::sierra_contract_class::GenericSierraContractClass;
use starknet_types_core::felt::Felt;

use crate::utils::get_subcalled_contracts_from_tx_traces;
use crate::{PreviousBlockId, ProveBlockError};

#[derive(Clone)]
pub struct FormattedStateUpdate {
    // TODO: Use more descriptive types
    pub class_hash_to_compiled_class_hash: HashMap<Felt252, Felt252>,
    pub compiled_classes: HashMap<Felt252, GenericCasmContractClass>,
    pub deprecated_compiled_classes: HashMap<Felt252, GenericDeprecatedCompiledClass>,
    pub declared_class_hash_component_hashes: HashMap<Felt252, ContractClassComponentHashes>,
}

/// Given the `block_id` of the target block to prove, it:
/// - Fetches the state update using the `starknet_getStateUpdate` RPC call.
/// - Fetches block transaction traces to obtain all accessed contract addresses in that block.
/// - Formats the RPC state updates to be "SharedState compatible."
/// - Consolidates that information into a `FormattedStateUpdate`.
pub(crate) async fn get_formatted_state_update(
    rpc_client: &RpcClient,
    previous_block_id: PreviousBlockId,
    block_id: BlockId,
) -> Result<(FormattedStateUpdate, Vec<TransactionTraceWithHash>), ProveBlockError> {
    let traces =
        rpc_client.starknet_rpc().trace_block_transactions(block_id).await.expect("Failed to get block tx traces");
    if let Some(previous_block_id) = previous_block_id {
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
        let (accessed_addresses, accessed_classes) = get_subcalled_contracts_from_tx_traces(&traces);

        let declared_classes: HashSet<_> =
            state_diff.declared_classes.iter().map(|declared_item| declared_item.class_hash).collect();

        // TODO: Handle deprecated classes
        let mut class_hash_to_compiled_class_hash: HashMap<Felt252, Felt252> = HashMap::new();
        let (compiled_contract_classes, deprecated_compiled_contract_classes, declared_class_hash_component_hashes) =
            build_compiled_class_and_maybe_update_class_hash_to_compiled_class_hash(
                rpc_client,
                previous_block_id,
                block_id,
                &accessed_addresses,
                &declared_classes,
                &accessed_classes,
                &mut class_hash_to_compiled_class_hash,
            )
            .await?;

        // OS will expect a Zero in compiled_class_hash for new classes. Overwrite the needed entries.
        format_declared_classes(&state_diff, &mut class_hash_to_compiled_class_hash);

        Ok((
            FormattedStateUpdate {
                class_hash_to_compiled_class_hash,
                compiled_classes: compiled_contract_classes,
                deprecated_compiled_classes: deprecated_compiled_contract_classes,
                declared_class_hash_component_hashes,
            },
            traces,
        ))
    } else {
        Ok((
            FormattedStateUpdate {
                class_hash_to_compiled_class_hash: Default::default(),
                compiled_classes: Default::default(),
                deprecated_compiled_classes: Default::default(),
                declared_class_hash_component_hashes: Default::default(),
            },
            traces,
        ))
    }
}

/// Retrieves the compiled class for the given class hash at a specific block
/// by getting the class from the RPC and compiling it to CASM if necessary (Cairo 1).
fn compile_contract_class(
    contract_class: starknet::core::types::ContractClass,
) -> Result<GenericCompiledClass, ProveBlockError> {
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
    let contract_class = rpc_client.starknet_rpc().get_class(block_id, class_hash).await?;

    add_compiled_class_to_os_input(
        class_hash,
        contract_class,
        class_hash_to_compiled_class_hash,
        compiled_contract_classes,
        deprecated_compiled_contract_classes,
    )
}

/// Fetches (+ compile) the contract class for the specified class at the specified block
/// and adds it to the hashmaps that will then be added to the OS input.
fn add_compiled_class_to_os_input(
    class_hash: Felt,
    contract_class: starknet::core::types::ContractClass,
    class_hash_to_compiled_class_hash: &mut HashMap<Felt252, Felt252>,
    compiled_contract_classes: &mut HashMap<Felt, GenericCasmContractClass>,
    deprecated_compiled_contract_classes: &mut HashMap<Felt, GenericDeprecatedCompiledClass>,
) -> Result<(), ProveBlockError> {
    // Avoid fetching and compiling contract data if we already have this class.
    if class_hash_to_compiled_class_hash.contains_key(&class_hash) {
        return Ok(());
    }

    let compiled_class = compile_contract_class(contract_class)?;
    let compiled_class_hash = compiled_class.class_hash()?;

    // Remove deprecated classes from HashMap
    if matches!(&compiled_class, GenericCompiledClass::Cairo0(_)) {
        log::warn!("Skipping deprecated class for ch_to_cch: 0x{:x}", class_hash);
    } else {
        class_hash_to_compiled_class_hash.insert(class_hash, compiled_class_hash.into());
    }

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
    declared_classes: &HashSet<Felt252>,
    accessed_classes: &HashSet<Felt252>,
    class_hash_to_compiled_class_hash: &mut HashMap<Felt252, Felt252>,
) -> Result<
    (
        HashMap<Felt252, GenericCasmContractClass>,
        HashMap<Felt252, GenericDeprecatedCompiledClass>,
        HashMap<Felt252, ContractClassComponentHashes>,
    ),
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
        let contract_class = provider.starknet_rpc().get_class(block_id, class_hash).await?;
        add_compiled_class_to_os_input(
            *class_hash,
            contract_class,
            class_hash_to_compiled_class_hash,
            &mut compiled_contract_classes,
            &mut deprecated_compiled_contract_classes,
        )?;
    }

    let mut declared_class_hash_to_component_hashes = HashMap::new();
    for class_hash in declared_classes {
        let contract_class = provider.starknet_rpc().get_class(block_id, class_hash).await?;
        if let starknet::core::types::ContractClass::Sierra(flattened_sierra_class) = &contract_class {
            let component_hashes = ContractClassComponentHashes::from(flattened_sierra_class.clone());
            declared_class_hash_to_component_hashes.insert(*class_hash, component_hashes);
        }
    }

    Ok((compiled_contract_classes, deprecated_compiled_contract_classes, declared_class_hash_to_component_hashes))
}

fn format_declared_classes(state_diff: &StateDiff, class_hash_to_compiled_class_hash: &mut HashMap<Felt252, Felt252>) {
    // The comment below explicits that the value should be 0 for new classes:
    // From execute_transactions.cairo
    // Note that prev_value=0 enforces that a class may be declared only once.
    // dict_update{dict_ptr=contract_class_changes}(
    //     key=[class_hash_ptr], prev_value=0, new_value=compiled_class_hash
    // );

    // class_hash_to_compiled_class_hash is already populated. However, for classes
    // that are defined in state_diff.declared_classes, we need to set the
    // compiled_class_hashes to zero as it was explain above
    for class in state_diff.declared_classes.iter() {
        class_hash_to_compiled_class_hash.insert(class.class_hash, Felt::ZERO);
    }
}
