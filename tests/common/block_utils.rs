use std::collections::HashMap;
use blockifier::{block_context::BlockContext, execution::contract_class::ContractClass};
use blockifier::state::cached_state::CachedState;
use blockifier::test_utils::contracts::FeatureContract;
use blockifier::test_utils::dict_state_reader::DictStateReader;
use blockifier::test_utils::initial_test_state::fund_account;
use blockifier::transaction::objects::FeeType;
use cairo_vm::Felt252;
use starknet_api::core::{ClassHash, CompiledClassHash};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::state::EntryPointType;
use starknet_crypto::poseidon_hash_many;
use snos::io::input::{ContractState, StorageCommitment};
use crate::common;
use crate::common::transaction_utils::to_felt252;

pub fn test_state(
    block_context: &BlockContext,
    initial_balances: u128,
    contract_instances: &[(FeatureContract, u8)],
) -> CachedState<DictStateReader> {
    let mut class_hash_to_class = HashMap::new();
    let mut address_to_class_hash = HashMap::new();
    let mut class_hash_to_compiled_class_hash: HashMap<ClassHash, CompiledClassHash> = HashMap::new();

    // Declare and deploy account and ERC20 contracts.
    let erc20 = FeatureContract::ERC20;
    class_hash_to_class.insert(erc20.get_class_hash(), erc20.get_class());
    address_to_class_hash
        .insert(block_context.fee_token_address(&FeeType::Eth), erc20.get_class_hash());
    address_to_class_hash
        .insert(block_context.fee_token_address(&FeeType::Strk), erc20.get_class_hash());

    // Set up the rest of the requested contracts.
    for (contract, n_instances) in contract_instances.iter() {
        let class_hash = contract.get_class_hash();
        // assert!(!class_hash_to_class.contains_key(&class_hash));
        class_hash_to_class.insert(class_hash, contract.get_class());
        for instance in 0..*n_instances {
            let instance_address = contract.get_instance_address(instance);
            address_to_class_hash.insert(instance_address, class_hash);
        }

        // convert our FeatureContract into a deprecated_hash_utils::ContractClass
        let contract_class = match contract.get_class() {
            blockifier::execution::contract_class::ContractClass::V0(class) => {
                let contract_class = common::deprecated_hash_utils::ContractClass {
                    program: class.program,
                    hinted_class_hash: Default::default(),
                    entry_points_by_type: class.entry_points_by_type,
                    abi: None,
                };
                contract_class
            },
            _ => panic!("only deprecated class supported"),
        }

        let compiled_class_hash = crate::common::deprecated_hash_utils::compute_deprecated_class_hash(&contract_class)
            .unwrap();
        class_hash_to_compiled_class_hash.insert(class_hash, CompiledClassHash(StarkFelt::new(compiled_class_hash.to_bytes_be()).unwrap()));
    }

    let mut state = CachedState::from(DictStateReader {
        address_to_class_hash,
        class_hash_to_class,
        class_hash_to_compiled_class_hash,
        ..Default::default()
    });

    // fund the accounts.
    for (contract, n_instances) in contract_instances.iter() {
        for instance in 0..*n_instances {
            let instance_address = contract.get_instance_address(instance);
            match contract {
                FeatureContract::AccountWithLongValidate(_)
                | FeatureContract::AccountWithoutValidations(_)
                | FeatureContract::FaultyAccount(_) => {
                    fund_account(block_context, instance_address, initial_balances, &mut state);
                }
                _ => (),
            }
        }
    }

    state
}

pub fn get_contracts(state: &CachedState<DictStateReader>) -> HashMap<Felt252, ContractState> {
    state
        .state
        .address_to_class_hash
        .keys()
        .map(|address| {
            let contract_state = ContractState {
                contract_hash: to_felt252(&state.state.address_to_class_hash.get(address).unwrap().0),
                storage_commitment_tree: StorageCommitment::default(), // TODO
                nonce: 0.into(), // TODO
            };
            (to_felt252(address.0.key()), contract_state)
        })
        .collect()
}