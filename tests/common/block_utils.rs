use std::collections::HashMap;

use blockifier::{block_context::BlockContext};
use blockifier::state::cached_state::CachedState;
use blockifier::test_utils::CairoVersion;
use blockifier::test_utils::contracts::FeatureContract;
use blockifier::test_utils::contracts::FeatureContract::{AccountWithLongValidate, AccountWithoutValidations, Empty, ERC20, FaultyAccount, LegacyTestContract, SecurityTests, TestContract};
use blockifier::test_utils::dict_state_reader::DictStateReader;
use blockifier::test_utils::initial_test_state::fund_account;
use blockifier::transaction::objects::FeeType;
use cairo_vm::Felt252;
use starknet_api::core::{ClassHash, CompiledClassHash};
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedContractClass;
use starknet_api::hash::StarkHash;
use starknet_crypto::FieldElement;

use snos::io::input::{ContractState, StorageCommitment};

use crate::common::transaction_utils::to_felt252;

pub fn deprecated_class(class_hash: ClassHash) -> DeprecatedContractClass {
    let variants = vec![
        AccountWithLongValidate(CairoVersion::Cairo0),
        // AccountWithLongValidate(CairoVersion::Cairo1),
        AccountWithoutValidations(CairoVersion::Cairo0),
        // AccountWithoutValidations(CairoVersion::Cairo1),
        ERC20,
        Empty(CairoVersion::Cairo0),
        // Empty(CairoVersion::Cairo1),
        FaultyAccount(CairoVersion::Cairo0),
        // FaultyAccount(CairoVersion::Cairo1),
        // LegacyTestContract,
        SecurityTests,
        TestContract(CairoVersion::Cairo0),
        // TestContract(CairoVersion::Cairo1),
    ];

    for c in variants {
        if ClassHash(compute_deprecated_class_hash(&c)) == class_hash {
            let result: Result<DeprecatedContractClass, serde_json::Error> =
                serde_json::from_str(c.get_raw_class().as_str());
            return result.unwrap();
        }
    }
    panic!("No class found for hash: {:?}", class_hash);
}


fn compute_deprecated_class_hash(contract: &FeatureContract) -> StarkHash {
    match contract {
        // FeatureContract::AccountWithLongValidate(_) => ACCOUNT_LONG_VALIDATE_BASE,
        FeatureContract::AccountWithoutValidations(_) => {
            let fe = FieldElement::from_dec_str("3043522133089536593636086481152606703984151542874851197328605892177919922063").unwrap();
            StarkHash::from(fe)
        }
        // FeatureContract::Empty(_) => EMPTY_CONTRACT_BASE,
        FeatureContract::ERC20 => {
            let fe = FieldElement::from_dec_str("2553874082637258309275750418379019378586603706497644242041372159420778949015").unwrap();
            StarkHash::from(fe)
        },
        // FeatureContract::FaultyAccount(_) => FAULTY_ACCOUNT_BASE,
        // FeatureContract::LegacyTestContract => LEGACY_CONTRACT_BASE,
        // FeatureContract::SecurityTests => SECURITY_TEST_CONTRACT_BASE,
        FeatureContract::TestContract(_) => {
            let fe = FieldElement::from_dec_str("2847229557799212240700619257444410593768590640938595411219122975663286400357").unwrap();
            StarkHash::from(fe)
        },

        _ => contract.get_class_hash().0,
    }


}



pub fn test_state(
    block_context: &BlockContext,
    initial_balances: u128,
    contract_instances: &[(FeatureContract, u8)],
) -> CachedState<DictStateReader> {
    let mut class_hash_to_class = HashMap::new();
    let mut address_to_class_hash = HashMap::new();
    let class_hash_to_compiled_class_hash: HashMap<ClassHash, CompiledClassHash> = HashMap::new();

    // Declare and deploy account and ERC20 contracts.
    let erc20 = FeatureContract::ERC20;
    let erc20_class_hash: ClassHash = ClassHash(compute_deprecated_class_hash(&erc20));
    class_hash_to_class.insert(erc20_class_hash, erc20.get_class());
    address_to_class_hash
        .insert(block_context.fee_token_address(&FeeType::Eth), erc20_class_hash);
    address_to_class_hash
        .insert(block_context.fee_token_address(&FeeType::Strk), erc20_class_hash);

    // Set up the rest of the requested contracts.
    for (contract, n_instances) in contract_instances.iter() {
        let class_hash = ClassHash(compute_deprecated_class_hash(contract));
        // assert!(!class_hash_to_class.contains_key(&class_hash));
        class_hash_to_class.insert(class_hash, contract.get_class());
        for instance in 0..*n_instances {
            let instance_address = contract.get_instance_address(instance);
            address_to_class_hash.insert(instance_address, class_hash);
        }
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