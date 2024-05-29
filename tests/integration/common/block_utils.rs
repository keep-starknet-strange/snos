use std::collections::{HashMap, HashSet};

use blockifier::block_context::BlockContext;
use blockifier::execution::contract_class::ContractClass::{V0, V1};
use blockifier::state::cached_state::CachedState;
use blockifier::state::state_api::{State, StateReader};
use blockifier::transaction::objects::TransactionExecutionInfo;
use cairo_lang_starknet::casm_contract_class::CasmContractClass;
use cairo_vm::Felt252;
use num_bigint::BigUint;
use snos::config::{StarknetGeneralConfig, StarknetOsConfig, STORED_BLOCK_HASH_BUFFER};
use snos::crypto::pedersen::PedersenHash;
use snos::execution::helper::ExecutionHelperWrapper;
use snos::io::input::StarknetOsInput;
use snos::io::InternalTransaction;
use snos::starknet::business_logic::fact_state::contract_state_objects::ContractState;
use snos::starknet::business_logic::fact_state::state::SharedState;
use snos::starknet::starknet_storage::CommitmentInfo;
use snos::starkware_utils::commitment_tree::base_types::{Height, TreeIndex};
use snos::storage::dict_storage::DictStorage;
use snos::storage::storage_utils::build_starknet_storage_async;
use snos::utils::{felt_api2vm, felt_vm2api};
use starknet_api::core::{ClassHash, ContractAddress, PatriciaKey};
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedContractClass;
use starknet_api::hash::StarkHash;

use crate::common::transaction_utils::to_felt252;

pub async fn os_hints(
    block_context: &BlockContext,
    mut blockifier_state: CachedState<SharedState<DictStorage, PedersenHash>>,
    transactions: Vec<InternalTransaction>,
    tx_execution_infos: Vec<TransactionExecutionInfo>,
    deprecated_compiled_classes: HashMap<ClassHash, DeprecatedContractClass>,
    compiled_classes: HashMap<ClassHash, CasmContractClass>,
) -> (StarknetOsInput, ExecutionHelperWrapper) {
    let mut compiled_class_hash_to_compiled_class: HashMap<Felt252, CasmContractClass> = HashMap::new();

    let mut contracts: HashMap<Felt252, ContractState> = blockifier_state
        .state
        .contract_addresses()
        .iter()
        .map(|address_biguint| {
            // TODO: biguint is exacerbating the type conversion problem, ideas...?
            let address: ContractAddress =
                ContractAddress(PatriciaKey::try_from(felt_vm2api(Felt252::from(address_biguint))).unwrap());
            let contract_state = blockifier_state.state.get_contract_state(address).unwrap();
            (to_felt252(address.0.key()), contract_state)
        })
        .collect();

    // provide an empty ContractState for any newly deployed contract
    // TODO: review -- what can to_state_diff() give us results we don't want to use here?
    let deployed_addresses = blockifier_state.to_state_diff().address_to_class_hash;
    for (address, _class_hash) in deployed_addresses {
        contracts.insert(
            to_felt252(address.0.key()),
            ContractState::empty(Height(251), &mut blockifier_state.state.ffc).await.unwrap(),
        );
    }

    let mut class_hash_to_compiled_class_hash: HashMap<Felt252, Felt252> = Default::default();

    for c in contracts.keys() {
        let address = ContractAddress::try_from(StarkHash::new(c.to_bytes_be()).unwrap()).unwrap();
        let class_hash = blockifier_state.get_class_hash_at(address).unwrap();
        let blockifier_class = blockifier_state.get_compiled_contract_class(class_hash).unwrap();
        match blockifier_class {
            V0(_) => {} // deprecated_compiled_classes are passed in by caller
            V1(_) => {
                let class =
                    compiled_classes.get(&class_hash).expect(format!("No class given for {:?}", class_hash).as_str());
                let compiled_class_hash = Felt252::from_bytes_be(&class.compiled_class_hash().to_be_bytes());
                class_hash_to_compiled_class_hash.insert(to_felt252(&class_hash.0), compiled_class_hash);

                compiled_class_hash_to_compiled_class.insert(compiled_class_hash, class.clone());
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
    for (c, _) in &deprecated_compiled_classes {
        log::debug!("\t{}", c);
    }

    log::debug!("classes");
    for (c, _) in &compiled_classes {
        log::debug!("\t{}", c);
    }

    log::debug!("class_hash to compiled_class_hash");
    for (ch, cch) in &class_hash_to_compiled_class_hash {
        log::debug!("\t{} -> {}", ch, cch);
    }

    let default_general_config = StarknetGeneralConfig::default();

    let general_config = StarknetGeneralConfig {
        starknet_os_config: StarknetOsConfig {
            chain_id: default_general_config.starknet_os_config.chain_id,
            fee_token_address: block_context.fee_token_addresses.strk_fee_token_address,
            deprecated_fee_token_address: block_context.fee_token_addresses.eth_fee_token_address,
        },
        ..default_general_config
    };

    let deprecated_compiled_classes: HashMap<_, _> =
        deprecated_compiled_classes.into_iter().map(|(k, v)| (felt_api2vm(k.0), v)).collect();

    let mut ffc = blockifier_state.state.ffc.clone();

    // Convert the Blockifier storage into an OS-compatible one
    let (contract_storage_map, previous_state, updated_state) =
        build_starknet_storage_async(blockifier_state).await.unwrap();

    // Pass all contract addresses as expected accessed indices
    let contract_indices: HashSet<TreeIndex> =
        contracts.keys().chain(contract_storage_map.keys()).map(|address| address.to_biguint()).collect();
    let contract_indices: Vec<TreeIndex> = contract_indices.into_iter().collect();

    let contract_state_commitment_info =
        CommitmentInfo::create_from_expected_updated_tree::<DictStorage, PedersenHash, ContractState>(
            previous_state.contract_states.clone(),
            updated_state.contract_states.clone(),
            &contract_indices,
            &mut ffc,
        )
        .await
        .expect("Could not create contract state commitment info");

    let os_input = StarknetOsInput {
        contract_state_commitment_info,
        contract_class_commitment_info: Default::default(),
        deprecated_compiled_classes,
        compiled_classes: compiled_class_hash_to_compiled_class,
        compiled_class_visited_pcs: Default::default(),
        contracts,
        class_hash_to_compiled_class_hash,
        general_config,
        transactions,
        block_hash: Default::default(),
    };

    let execution_helper = ExecutionHelperWrapper::new(
        contract_storage_map,
        tx_execution_infos,
        &block_context,
        (Felt252::from(block_context.block_number.0 - STORED_BLOCK_HASH_BUFFER), Felt252::from(66_u64)),
    );

    (os_input, execution_helper)
}
