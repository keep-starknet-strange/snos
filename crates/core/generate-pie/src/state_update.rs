use cairo_vm::Felt252;
use rpc_client::RpcClient;
use starknet::core::types::SierraEntryPoint;
use starknet::core::types::{
    BlockId, ExecuteInvocation, FunctionInvocation, MaybePendingStateUpdate, StarknetError,
    StateDiff, TransactionTrace, TransactionTraceWithHash,
};
use starknet::core::utils::starknet_keccak;
use starknet::providers::Provider;
use starknet::providers::ProviderError;
use starknet_crypto::poseidon_hash_many;
use starknet_os::io::os_input::ContractClassComponentHashes as OsContractClassComponentHashes;
use starknet_os_types::casm_contract_class::GenericCasmContractClass;
use starknet_os_types::compiled_class::GenericCompiledClass;
use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;
use starknet_os_types::sierra_contract_class::GenericSierraContractClass;
use starknet_patricia::hash::hash_trait::HashOutput;
use starknet_types_core::felt::Felt;
use std::collections::{HashMap, HashSet};
use thiserror::Error;

/// Holds the hashes of the contract class components, to be used for calculating the final hash.
/// Note: the order of the struct member must not be changed since it determines the hash order.
#[derive(Debug, Clone, PartialEq)]
pub struct ContractClassComponentHashes {
    contract_class_version: Felt,
    external_functions_hash: Felt,
    l1_handlers_hash: Felt,
    constructors_hash: Felt,
    abi_hash: Felt,
    sierra_program_hash: Felt,
}

impl ContractClassComponentHashes {
    /// Converts this `ContractClassComponentHashes` to the OS version `OsContractClassComponentHashes`
    pub fn to_os_format(&self) -> OsContractClassComponentHashes {
        OsContractClassComponentHashes {
            contract_class_version: self.contract_class_version,
            external_functions_hash: HashOutput(self.external_functions_hash),
            l1_handlers_hash: HashOutput(self.l1_handlers_hash),
            constructors_hash: HashOutput(self.constructors_hash),
            abi_hash: HashOutput(self.abi_hash),
            sierra_program_hash: HashOutput(self.sierra_program_hash),
        }
    }
}

#[derive(Debug, Error)]
pub enum ProveBlockError {
    #[error("RPC Error: {0}")]
    RpcError(#[from] ProviderError),
}

pub type PreviousBlockId = Option<BlockId>;

#[derive(Clone, Debug)]
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
    accessed_addresses: HashSet<Felt>,
    accessed_classes: HashSet<Felt>,
) -> Result<FormattedStateUpdate, Box<dyn std::error::Error>> {
    if let Some(previous_block_id) = previous_block_id {
        let state_update = match rpc_client
            .starknet_rpc()
            .get_state_update(block_id)
            .await
            .expect("Failed to get state update")
        {
            MaybePendingStateUpdate::Update(update) => update,
            MaybePendingStateUpdate::PendingUpdate(_) => {
                panic!("Block is still pending!")
            }
        };
        let state_diff = state_update.state_diff;

        let declared_classes: HashSet<_> = state_diff
            .declared_classes
            .iter()
            .map(|declared_item| declared_item.class_hash)
            .collect();

        // TODO: Handle deprecated classes
        let mut class_hash_to_compiled_class_hash: HashMap<Felt252, Felt252> = HashMap::new();
        let (
            compiled_contract_classes,
            deprecated_compiled_contract_classes,
            declared_class_hash_component_hashes,
        ) = build_compiled_class_and_maybe_update_class_hash_to_compiled_class_hash(
            rpc_client,
            previous_block_id,
            block_id,
            &accessed_addresses,
            &declared_classes,
            &accessed_classes,
            &mut class_hash_to_compiled_class_hash,
        )
        .await
        .expect("issue while building the compiled class");

        // OS will expect a Zero in compiled_class_hash for new classes. Overwrite the needed entries.
        format_declared_classes(&state_diff, &mut class_hash_to_compiled_class_hash);
        // println!("ch_to_cch mapping: {:?} and cc: {:?}", class_hash_to_compiled_class_hash, compiled_contract_classes);

        Ok(FormattedStateUpdate {
            class_hash_to_compiled_class_hash,
            compiled_classes: compiled_contract_classes,
            deprecated_compiled_classes: deprecated_compiled_contract_classes,
            declared_class_hash_component_hashes,
        })
    } else {
        Ok(FormattedStateUpdate {
            class_hash_to_compiled_class_hash: Default::default(),
            compiled_classes: Default::default(),
            deprecated_compiled_classes: Default::default(),
            declared_class_hash_component_hashes: Default::default(),
        })
    }
}

pub(crate) fn get_subcalled_contracts_from_tx_traces(
    traces: &[TransactionTraceWithHash],
) -> (HashSet<Felt252>, HashSet<Felt252>) {
    let mut contracts_subcalled: HashSet<Felt252> = HashSet::new();
    let mut classes_subcalled: HashSet<Felt252> = HashSet::new();
    for trace in traces {
        match &trace.trace_root {
            TransactionTrace::Invoke(invoke_trace) => {
                if let Some(inv) = &invoke_trace.validate_invocation {
                    process_function_invocations(
                        inv,
                        &mut contracts_subcalled,
                        &mut classes_subcalled,
                    );
                }
                if let ExecuteInvocation::Success(inv) = &invoke_trace.execute_invocation {
                    process_function_invocations(
                        inv,
                        &mut contracts_subcalled,
                        &mut classes_subcalled,
                    );
                }
                if let Some(inv) = &invoke_trace.fee_transfer_invocation {
                    process_function_invocations(
                        inv,
                        &mut contracts_subcalled,
                        &mut classes_subcalled,
                    );
                }
            }
            TransactionTrace::Declare(declare_trace) => {
                if let Some(inv) = &declare_trace.validate_invocation {
                    process_function_invocations(
                        inv,
                        &mut contracts_subcalled,
                        &mut classes_subcalled,
                    );
                }
                if let Some(inv) = &declare_trace.fee_transfer_invocation {
                    process_function_invocations(
                        inv,
                        &mut contracts_subcalled,
                        &mut classes_subcalled,
                    );
                }
            }
            TransactionTrace::L1Handler(l1handler_trace) => {
                process_function_invocations(
                    &l1handler_trace.function_invocation,
                    &mut contracts_subcalled,
                    &mut classes_subcalled,
                );
            }

            TransactionTrace::DeployAccount(deploy_trace) => {
                if let Some(inv) = &deploy_trace.validate_invocation {
                    process_function_invocations(
                        inv,
                        &mut contracts_subcalled,
                        &mut classes_subcalled,
                    );
                }
                if let Some(inv) = &deploy_trace.fee_transfer_invocation {
                    process_function_invocations(
                        inv,
                        &mut contracts_subcalled,
                        &mut classes_subcalled,
                    );
                }
                process_function_invocations(
                    &deploy_trace.constructor_invocation,
                    &mut contracts_subcalled,
                    &mut classes_subcalled,
                );
            }
        }
    }
    (contracts_subcalled, classes_subcalled)
}

/// Utility to extract all contract address in a nested call structure. Any given call can have
/// nested calls, creating a tree structure of calls, so this fn traverses this structure and
/// returns a set of all contracts encountered along the way.
fn process_function_invocations(
    inv: &FunctionInvocation,
    contracts: &mut HashSet<Felt252>,
    classes: &mut HashSet<Felt252>,
) {
    contracts.insert(inv.contract_address);
    classes.insert(inv.class_hash);
    for call in &inv.calls {
        process_function_invocations(call, contracts, classes);
    }
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
    let mut deprecated_compiled_contract_classes: HashMap<Felt252, GenericDeprecatedCompiledClass> =
        HashMap::new();

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
                ProveBlockError::RpcError(ProviderError::StarknetError(
                    StarknetError::ContractNotFound,
                )) => {
                    // The contract was deployed in the current block, nothing to worry about
                    println!("rpc error hence ignoring it?");
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
        println!("class hash we are checking out is: {:?}", class_hash);
        let contract_class = provider
            .starknet_rpc()
            .get_class(block_id, class_hash)
            .await?;
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
        let contract_class = provider
            .starknet_rpc()
            .get_class(block_id, class_hash)
            .await?;
        if let starknet::core::types::ContractClass::Sierra(flattened_sierra_class) =
            &contract_class
        {
            let component_hashes =
                ContractClassComponentHashes::from(flattened_sierra_class.clone());
            declared_class_hash_to_component_hashes.insert(*class_hash, component_hashes);
        }
    }

    // println!("compiled contract classes is: {:?}", compiled_contract_classes);

    Ok((
        compiled_contract_classes,
        deprecated_compiled_contract_classes,
        declared_class_hash_to_component_hashes,
    ))
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
    let class_hash = rpc_client
        .starknet_rpc()
        .get_class_hash_at(block_id, contract_address)
        .await?;
    println!(">>>>> class hash of certain contract is: {:?}", class_hash);
    let contract_class = rpc_client
        .starknet_rpc()
        .get_class(block_id, class_hash)
        .await?;

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

    let compiled_class =
        compile_contract_class(contract_class).expect("issue while compiled class");
    let compiled_class_hash = compiled_class
        .class_hash()
        .expect("issue while compiled class hash");

    // Remove deprecated classes from HashMap
    if matches!(&compiled_class, GenericCompiledClass::Cairo0(_)) {
        println!(
            "Skipping deprecated class for ch_to_cch: 0x{:x}",
            class_hash
        );
    } else {
        println!("adding the to the mapping of class_hash_to_compiled_class_hash with ch: {:?} and cch {:?}", class_hash, compiled_class_hash);
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

/// Retrieves the compiled class for the given class hash at a specific block
/// by getting the class from the RPC and compiling it to CASM if necessary (Cairo 1).
fn compile_contract_class(
    contract_class: starknet::core::types::ContractClass,
) -> Result<GenericCompiledClass, ProveBlockError> {
    let compiled_class = match contract_class {
        starknet::core::types::ContractClass::Sierra(flattened_sierra_cc) => {
            let sierra_class = GenericSierraContractClass::from(flattened_sierra_cc);
            let compiled_class = sierra_class
                .compile()
                .expect("something broke in the compile_contract_class");
            GenericCompiledClass::Cairo1(compiled_class)
        }
        starknet::core::types::ContractClass::Legacy(legacy_cc) => {
            let compiled_class = GenericDeprecatedCompiledClass::try_from(legacy_cc).unwrap();
            GenericCompiledClass::Cairo0(compiled_class)
        }
    };

    Ok(compiled_class)
}

fn format_declared_classes(
    state_diff: &StateDiff,
    class_hash_to_compiled_class_hash: &mut HashMap<Felt252, Felt252>,
) {
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

const CLASS_VERSION_PREFIX: &str = "CONTRACT_CLASS_V";

impl From<starknet::core::types::FlattenedSierraClass> for ContractClassComponentHashes {
    fn from(sierra_class: starknet::core::types::FlattenedSierraClass) -> Self {
        let version_str = format!(
            "{CLASS_VERSION_PREFIX}{}",
            sierra_class.contract_class_version
        );
        let contract_class_version = Felt::from_bytes_be_slice(version_str.as_bytes());

        let sierra_program_hash = poseidon_hash_many(sierra_class.sierra_program.iter());

        Self {
            contract_class_version,
            external_functions_hash: compute_hash_on_sierra_entry_points(
                sierra_class.entry_points_by_type.external.iter(),
            ),
            l1_handlers_hash: compute_hash_on_sierra_entry_points(
                sierra_class.entry_points_by_type.l1_handler.iter(),
            ),
            constructors_hash: compute_hash_on_sierra_entry_points(
                sierra_class.entry_points_by_type.constructor.iter(),
            ),
            abi_hash: hash_abi(&sierra_class.abi),
            sierra_program_hash,
        }
    }
}

/// Computes hash on a list of given entry points (starknet-core types).
fn compute_hash_on_sierra_entry_points<'a, EntryPoints: Iterator<Item = &'a SierraEntryPoint>>(
    entry_points: EntryPoints,
) -> Felt {
    let flat_entry_points: Vec<Felt> = entry_points
        .flat_map(|entry_point| [entry_point.selector, Felt::from(entry_point.function_idx)])
        .collect();

    poseidon_hash_many(flat_entry_points.iter())
}

fn hash_abi(abi: &str) -> Felt {
    starknet_keccak(abi.as_bytes())
}
