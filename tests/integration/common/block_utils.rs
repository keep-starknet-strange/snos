use std::collections::{HashMap, HashSet};

use blockifier::context::BlockContext;
use blockifier::execution::contract_class::ContractClass::{V0, V1};
use blockifier::state::cached_state::{CachedState, CommitmentStateDiff};
use blockifier::state::state_api::StateReader;
use blockifier::transaction::objects::TransactionExecutionInfo;
use cairo_vm::Felt252;
use num_bigint::BigUint;
use starknet_api::core::{ClassHash, ContractAddress, PatriciaKey};
use starknet_os::config::{StarknetGeneralConfig, StarknetOsConfig, STORED_BLOCK_HASH_BUFFER};
use starknet_os::crypto::pedersen::PedersenHash;
use starknet_os::crypto::poseidon::PoseidonHash;
use starknet_os::execution::helper::ExecutionHelperWrapper;
use starknet_os::io::input::StarknetOsInput;
use starknet_os::io::InternalTransaction;
use starknet_os::starknet::business_logic::fact_state::contract_class_objects::ContractClassLeaf;
use starknet_os::starknet::business_logic::fact_state::contract_state_objects::ContractState;
use starknet_os::starknet::business_logic::fact_state::state::SharedState;
use starknet_os::starknet::starknet_storage::{CommitmentInfo, OsSingleStarknetStorage};
use starknet_os::starkware_utils::commitment_tree::base_types::{Height, TreeIndex};
use starknet_os::storage::storage::Storage;
use starknet_os::storage::storage_utils::build_starknet_storage_async;
use starknet_os_types::casm_contract_class::GenericCasmContractClass;
use starknet_os_types::class_hash_utils::ContractClassComponentHashes;
use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;

pub async fn os_hints<S>(
    block_context: &BlockContext,
    mut blockifier_state: CachedState<SharedState<S, PedersenHash>>,
    transactions: Vec<InternalTransaction>,
    tx_execution_infos: Vec<TransactionExecutionInfo>,
    deprecated_compiled_classes: HashMap<ClassHash, GenericDeprecatedCompiledClass>,
    compiled_classes: HashMap<ClassHash, GenericCasmContractClass>,
    declared_class_hash_to_component_hashes: HashMap<ClassHash, ContractClassComponentHashes>,
) -> (StarknetOsInput, ExecutionHelperWrapper<OsSingleStarknetStorage<S, PedersenHash>>)
where
    S: Storage,
{
    let mut compiled_class_hash_to_compiled_class: HashMap<Felt252, GenericCasmContractClass> = HashMap::new();

    let mut contracts: HashMap<Felt252, ContractState> = blockifier_state
        .state
        .contract_addresses()
        .iter()
        .map(|address_biguint| {
            // TODO: biguint is exacerbating the type conversion problem, ideas...?
            let address: ContractAddress =
                ContractAddress(PatriciaKey::try_from(Felt252::from(address_biguint)).unwrap());
            let contract_state = blockifier_state.state.get_contract_state(address).unwrap();
            (*address.0.key(), contract_state)
        })
        .collect();

    // provide an empty ContractState for any newly deployed contract
    let state_diff =
        CommitmentStateDiff::from(blockifier_state.to_state_diff().expect("unable to generate state diff"));
    let deployed_addresses = state_diff.address_to_class_hash;
    for (address, _class_hash) in &deployed_addresses {
        contracts.insert(
            *address.0.key(),
            ContractState::empty(Height(251), &mut blockifier_state.state.ffc).await.unwrap(),
        );
    }

    // Initialize class_hash_to_compiled_class_hash with zero so that newly declared contracts
    // will have an initial value of 0, which is required for dict_updates
    let mut class_hash_to_compiled_class_hash: HashMap<Felt252, Felt252> = state_diff
        .class_hash_to_compiled_class_hash
        .iter()
        .map(|(class_hash, _compiled_class_hash)| (class_hash.0, Felt252::ZERO))
        .collect();

    for c in contracts.keys() {
        let address = ContractAddress(PatriciaKey::try_from(*c).unwrap());
        let class_hash = blockifier_state.get_class_hash_at(address).unwrap();
        let blockifier_class = blockifier_state.get_compiled_contract_class(class_hash).unwrap();
        match blockifier_class {
            V0(_) => {} // deprecated_compiled_classes are passed in by caller
            V1(_) => {
                let compiled_class =
                    compiled_classes.get(&class_hash).unwrap_or_else(|| panic!("No class given for {:?}", class_hash));
                let compiled_class_hash = compiled_class.class_hash().expect("Failed to compute class hash");
                let compiled_class_hash = Felt252::from(compiled_class_hash);
                class_hash_to_compiled_class_hash.insert(class_hash.0, compiled_class_hash);

                compiled_class_hash_to_compiled_class.insert(compiled_class_hash, compiled_class.clone());
            }
        };
    }

    contracts
        .insert(Felt252::from(0), ContractState::empty(Height(251), &mut blockifier_state.state.ffc).await.unwrap());
    contracts
        .insert(Felt252::from(1), ContractState::empty(Height(251), &mut blockifier_state.state.ffc).await.unwrap());

    log::debug!(
        "contracts: {:?}\ndeprecated_compiled_classes: {:?}",
        contracts.len(),
        deprecated_compiled_classes.len()
    );

    log::debug!("contracts to class_hash");
    for (a, c) in &contracts {
        log::debug!("\t{} -> {}", a, BigUint::from_bytes_be(&c.contract_hash));
    }

    log::debug!("deprecated classes");
    for c in deprecated_compiled_classes.keys() {
        log::debug!("\t{}", c);
    }

    log::debug!("classes");
    for c in compiled_classes.keys() {
        log::debug!("\t{}", c);
    }

    log::debug!("class_hash to compiled_class_hash");
    for (ch, cch) in &class_hash_to_compiled_class_hash {
        log::debug!("\t{} -> {}", ch, cch);
    }

    let default_general_config = StarknetGeneralConfig::default();

    let general_config = StarknetGeneralConfig {
        starknet_os_config: StarknetOsConfig {
            chain_id: block_context.chain_info().chain_id.clone(),
            fee_token_address: block_context.chain_info().fee_token_addresses.strk_fee_token_address,
            deprecated_fee_token_address: block_context.chain_info().fee_token_addresses.eth_fee_token_address,
        },
        ..default_general_config
    };

    let mut ffc = blockifier_state.state.ffc.clone();

    // Blockifier provides a class hash -> visited PCs map, but we need
    // the compiled class hash -> visited PCs map.
    let compiled_class_visited_pcs: HashMap<Felt252, Vec<Felt252>> = blockifier_state
        .visited_pcs
        .iter()
        .map(|(class_hash, visited_pcs)| {
            let class_hash_felt = class_hash.0;
            let compiled_class_hash_felt = class_hash_to_compiled_class_hash.get(&class_hash_felt).unwrap();
            (*compiled_class_hash_felt, visited_pcs.iter().copied().map(Felt252::from).collect::<Vec<_>>())
        })
        .collect();

    // Convert the Blockifier storage into an OS-compatible one
    let (contract_storage_map, previous_state, updated_state) =
        build_starknet_storage_async(blockifier_state).await.unwrap();

    // Pass all contract addresses as expected accessed indices
    let contract_indices: HashSet<TreeIndex> =
        contracts.keys().chain(contract_storage_map.keys()).map(|address| address.to_biguint()).collect();
    let contract_indices: Vec<TreeIndex> = contract_indices.into_iter().collect();

    let contract_state_commitment_info =
        CommitmentInfo::create_from_expected_updated_tree::<S, PedersenHash, ContractState>(
            previous_state.contract_states.clone(),
            updated_state.contract_states.clone(),
            &contract_indices,
            &mut ffc,
        )
        .await
        .unwrap_or_else(|e| panic!("Could not create contract state commitment info: {:?}", e));

    let accessed_contracts: Vec<TreeIndex> = state_diff
        .class_hash_to_compiled_class_hash
        .keys()
        .chain(compiled_classes.keys())
        .map(|class_hash| class_hash.to_biguint())
        .collect();

    let contract_class_commitment_info =
        CommitmentInfo::create_from_expected_updated_tree::<S, PoseidonHash, ContractClassLeaf>(
            previous_state.contract_classes.clone().expect("previous state should have class trie"),
            updated_state.contract_classes.clone().expect("updated state should have class trie"),
            &accessed_contracts,
            &mut ffc.clone_with_different_hash::<PoseidonHash>(),
        )
        .await
        .unwrap_or_else(|e| panic!("Could not create contract class commitment info: {:?}", e));

    let deprecated_compiled_classes: HashMap<_, _> =
        deprecated_compiled_classes.into_iter().map(|(k, v)| (k.0, v)).collect();

    let declared_class_hash_to_component_hashes: HashMap<Felt252, Vec<Felt252>> =
        declared_class_hash_to_component_hashes
            .into_iter()
            .map(|(class_hash, components)| (class_hash.0, components.to_vec()))
            .collect();

    let os_input = StarknetOsInput {
        contract_state_commitment_info,
        contract_class_commitment_info,
        deprecated_compiled_classes,
        compiled_classes: compiled_class_hash_to_compiled_class,
        compiled_class_visited_pcs,
        contracts,
        class_hash_to_compiled_class_hash,
        general_config,
        transactions,
        declared_class_hash_to_component_hashes,
        new_block_hash: Default::default(),
        prev_block_hash: Default::default(),
        full_output: false,
    };

    let execution_helper = ExecutionHelperWrapper::new(
        contract_storage_map,
        tx_execution_infos,
        block_context,
        (Felt252::from(block_context.block_info().block_number.0 - STORED_BLOCK_HASH_BUFFER), Felt252::from(66_u64)),
    );

    (os_input, execution_helper)
}
