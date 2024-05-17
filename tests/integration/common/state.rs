use std::collections::HashMap;

use blockifier::block_context::BlockContext;
use blockifier::state::cached_state::CachedState;
use blockifier::test_utils::dict_state_reader::DictStateReader;
use blockifier::test_utils::BALANCE;
use rstest::fixture;
use snos::crypto::pedersen::PedersenHash;
use snos::storage::dict_storage::DictStorage;
use snos::storage::storage::FactFetchingContext;
use starknet_api::core::{ClassHash, ContractAddress};
use starknet_api::state::ContractClass;
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedCompiledClass;

use super::block_utils::{test_state_cairo0, test_state_cairo1};
use crate::common::block_context;
use crate::common::blockifier_contracts::{get_deprecated_erc20_contract_class, get_deprecated_feature_contract_class, get_erc20_contract_class, get_feature_contract_class};

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
    let ffc = &mut FactFetchingContext::<_, PedersenHash>::new(DictStorage::default());
    let (state, deployed_addresses, deprecated_contract_classes) = test_state_cairo0(
        &block_context,
        BALANCE,
        &cairo0_contracts.erc20_contract,
        &[&cairo0_contracts.account_without_validations, &cairo0_contracts.test_contract],
        ffc,
    )
    .await
    .unwrap();

    Cairo0InitialState { state, deployed_addresses, contracts: cairo0_contracts, deprecated_contract_classes }
}

#[derive(Debug)]
pub struct Cairo1Contracts {
    pub account_without_validations: cairo_lang_starknet::contract_class::ContractClass,
    pub test_contract: cairo_lang_starknet::contract_class::ContractClass,
    pub erc20_contract: cairo_lang_starknet::contract_class::ContractClass,
}

#[derive(Debug)]
pub struct Cairo1InitialState {
    pub state: CachedState<DictStateReader>,
    pub contracts: Cairo1Contracts,
    pub deployed_addresses: Vec<ContractAddress>,
    pub contract_classes: HashMap<ClassHash, cairo_lang_starknet::contract_class::ContractClass>,
}

#[fixture]
pub fn cairo1_contracts() -> Cairo1Contracts {
    let account_without_validations = get_feature_contract_class("account_with_dummy_validate");
    let test_contract = get_feature_contract_class("test_contract");
    let erc20_contract = get_erc20_contract_class();

    Cairo1Contracts { account_without_validations, test_contract, erc20_contract }
}

#[fixture]
pub async fn cairo1_initial_state(
    block_context: BlockContext,
    cairo1_contracts: Cairo1Contracts,
) -> Cairo1InitialState {
    let ffc = &mut FactFetchingContext::<_, PedersenHash>::new(DictStorage::default());
    let (state, deployed_addresses, contract_classes) = test_state_cairo1(
        &block_context,
        BALANCE,
        &cairo1_contracts.erc20_contract,
        &[&cairo1_contracts.account_without_validations, &cairo1_contracts.test_contract],
        ffc,
    )
    .await
    .unwrap();

    Cairo1InitialState { state, deployed_addresses, contracts: cairo1_contracts, contract_classes }
}
