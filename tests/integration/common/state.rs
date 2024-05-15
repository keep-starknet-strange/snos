use std::collections::HashMap;
use std::ops::Deref;

use blockifier::block_context::BlockContext;
use blockifier::state::cached_state::CachedState;
use blockifier::test_utils::contracts::FeatureContract;
use blockifier::test_utils::dict_state_reader::DictStateReader;
use blockifier::test_utils::{CairoVersion, BALANCE};
use cairo_vm::Felt252;
use rstest::fixture;
use snos::crypto::pedersen::PedersenHash;
use snos::storage::dict_storage::DictStorage;
use snos::storage::storage::FactFetchingContext;
use starknet_api::core::{ClassHash, ContractAddress};
use starknet_api::deprecated_contract_class::{self, ContractClass as DeprecatedCompiledClass};

use super::block_utils::test_state_no_feature_contracts;
use crate::common::block_context;
use crate::common::block_utils::test_state;
use crate::common::blockifier_contracts::{get_deprecated_erc20_contract_class, get_deprecated_feature_contract_class};

pub struct InitialState {
    pub state: CachedState<DictStateReader>,
    pub account_without_validations_cairo1_address: ContractAddress,
    pub test_contract_cairo1_address: ContractAddress,
    pub account_without_validations_cairo0_address: ContractAddress,
    pub test_contract_cairo0_address: ContractAddress,
    pub erc20_address: ContractAddress,
}

#[fixture]
pub fn initial_state(block_context: BlockContext) -> InitialState {
    let account_without_validations_cairo1 = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo1);
    let account_without_validations_cairo0 = FeatureContract::AccountWithoutValidations(CairoVersion::Cairo0);
    let test_contract_cairo1 = FeatureContract::TestContract(CairoVersion::Cairo1);
    let test_contract_cairo0 = FeatureContract::TestContract(CairoVersion::Cairo0);
    let erc20_cairo0 = FeatureContract::ERC20;

    let state = test_state(
        &block_context,
        BALANCE,
        &[
            (account_without_validations_cairo1, 1),
            (account_without_validations_cairo0, 1),
            (test_contract_cairo1, 1),
            (test_contract_cairo0, 1),
            (erc20_cairo0, 1),
        ],
    );

    InitialState {
        state,
        account_without_validations_cairo1_address: account_without_validations_cairo1.get_instance_address(0),
        test_contract_cairo1_address: test_contract_cairo1.get_instance_address(0),
        account_without_validations_cairo0_address: account_without_validations_cairo0.get_instance_address(0),
        test_contract_cairo0_address: test_contract_cairo0.get_instance_address(0),
        erc20_address: erc20_cairo0.get_instance_address(0),
    }
}

#[derive(Debug)]
pub struct Cairo0Contracts {
    pub account_without_validations: DeprecatedCompiledClass,
    pub test_contract: DeprecatedCompiledClass,
    pub erc20_contract: DeprecatedCompiledClass,
}

#[derive(Debug)]
pub struct Cairo0InitialState {
    pub state: CachedState<DictStateReader>,
    pub contracts: Cairo0Contracts,
    pub deployed_addresses: Vec<ContractAddress>,
    pub deprecated_contract_classes: HashMap<ClassHash, DeprecatedCompiledClass>,
}

#[fixture]
pub fn cairo0_contracts() -> Cairo0Contracts {
    let account_without_validations = get_deprecated_feature_contract_class("account_with_dummy_validate");
    let test_contract = get_deprecated_feature_contract_class("test_contract");
    let erc20_contract = get_deprecated_erc20_contract_class();

    Cairo0Contracts { account_without_validations, test_contract, erc20_contract }
}

#[fixture]
pub async fn cairo0_initial_state(
    block_context: BlockContext,
    cairo0_contracts: Cairo0Contracts,
) -> Cairo0InitialState {
    let ffc = &mut FactFetchingContext::<_, PoseidonHash>::new(DictStorage::default());
    let (mut state, deployed_addresses, deprecated_contract_classes) = test_state_no_feature_contracts(
        &block_context,
        BALANCE,
        &cairo0_contracts.erc20_contract,
        &[&cairo0_contracts.account_without_validations, &cairo0_contracts.test_contract],
        ffc,
    )
    .await
    .unwrap();

    for (k, v) in ffc.acquire_storage().await.deref().db.iter() {
        println!(
            "FFC entry - {}:{}",
            Felt252::from_bytes_be_slice(k).to_biguint(),
            Felt252::from_bytes_be_slice(v).to_biguint()
        );
    }

    Cairo0InitialState { state, deployed_addresses, contracts: cairo0_contracts, deprecated_contract_classes }
}
