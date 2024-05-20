use std::collections::HashMap;

use blockifier::block_context::BlockContext;
use blockifier::state::cached_state::CachedState;
use blockifier::test_utils::dict_state_reader::DictStateReader;
use blockifier::test_utils::BALANCE;
use cairo_lang_starknet::casm_contract_class::CasmContractClass;
use rstest::fixture;
use snos::crypto::pedersen::PedersenHash;
use snos::storage::dict_storage::DictStorage;
use snos::storage::storage::FactFetchingContext;
use starknet_api::core::{ClassHash, ContractAddress};
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedCompiledClass;

use super::block_utils::{test_state, test_state_cairo1};
use crate::common::block_context;
use crate::common::blockifier_contracts::{get_deprecated_erc20_contract_class, get_deprecated_feature_contract_class, get_feature_contract_class};

#[derive(Debug)]
pub struct TestState {
    pub cairo0_contracts: HashMap<String, (DeprecatedCompiledClass, ContractAddress)>,
    pub cairo1_contracts: HashMap<String, (CasmContractClass, ContractAddress)>,
    pub fee_contracts: FeeContracts,

    pub blockifier_state: CachedState<DictStateReader>,
    pub deployed_addresses: Vec<ContractAddress>,
    pub deprecated_contract_classes: HashMap<ClassHash, DeprecatedCompiledClass>
}

/// ERC20 contract deployments for Eth and Strk tokens
#[derive(Debug)]
pub struct FeeContracts {
    pub erc20_contract: DeprecatedCompiledClass,
    pub eth_fee_token_address: ContractAddress,
    pub strk_fee_token_address: ContractAddress,
}

#[derive(Debug)]
pub struct Cairo0Contracts {
    pub account_without_validations: DeprecatedCompiledClass,
    pub test_contract: DeprecatedCompiledClass,
    pub erc20_contract: DeprecatedCompiledClass,

    pub account_without_validations_address: Option<ContractAddress>,
    pub test_contract_address: Option<ContractAddress>,
    pub erc20_contract_address: Option<ContractAddress>,
}

#[derive(Debug)]
pub struct Cairo0InitialState {
    pub state: CachedState<DictStateReader>,
    pub contracts: Cairo0Contracts,
    pub deprecated_contract_classes: HashMap<ClassHash, DeprecatedCompiledClass>,
}

#[fixture]
pub fn cairo0_contracts() -> Cairo0Contracts {
    let account_without_validations = get_deprecated_feature_contract_class("account_with_dummy_validate");
    let test_contract = get_deprecated_feature_contract_class("test_contract");
    let erc20_contract = get_deprecated_erc20_contract_class();

    Cairo0Contracts {
        account_without_validations,
        test_contract,
        erc20_contract,
        account_without_validations_address: None,
        test_contract_address: None,
        erc20_contract_address: None,
    }
}

#[fixture]
pub async fn initial_state(block_context: BlockContext) -> TestState {
    let ffc = &mut FactFetchingContext::<_, PedersenHash>::new(DictStorage::default());
    let test_state = test_state(
        &block_context,
        BALANCE,
        get_deprecated_erc20_contract_class(),
        &[
            ("account_with_dummy_validate", &get_deprecated_feature_contract_class("account_with_dummy_validate")),
            ("test_contract", &get_deprecated_feature_contract_class("test_contract")),
        ],
        &[
            ("account_with_dummy_validate", &get_feature_contract_class("account_with_dummy_validate")),
            ("test_contract", &get_feature_contract_class("test_contract")),
        ],
        ffc,
    )
    .await
    .unwrap();

    test_state
}

#[derive(Debug)]
pub struct Cairo1Contracts {
    pub account_without_validations: CasmContractClass,
    pub test_contract: CasmContractClass,
    pub erc20_contract: DeprecatedCompiledClass,
}

#[derive(Debug)]
pub struct Cairo1InitialState {
    pub state: CachedState<DictStateReader>,
    pub contracts: Cairo1Contracts,
    pub deployed_addresses: Vec<ContractAddress>,
    pub deprecated_contract_classes: HashMap<ClassHash, DeprecatedCompiledClass>,
}

#[fixture]
pub fn cairo1_contracts() -> Cairo1Contracts {
    let account_without_validations = get_feature_contract_class("account_with_dummy_validate");
    let test_contract = get_feature_contract_class("test_contract");
    let erc20_contract = get_deprecated_erc20_contract_class();

    Cairo1Contracts { account_without_validations, test_contract, erc20_contract }
}

#[fixture]
pub async fn cairo1_initial_state(
    block_context: BlockContext,
    cairo1_contracts: Cairo1Contracts,
) -> Cairo1InitialState {
    let ffc = &mut FactFetchingContext::<_, PedersenHash>::new(DictStorage::default());
    let (state, deployed_addresses, deprecated_contract_classes) = test_state_cairo1(
        &block_context,
        BALANCE,
        &cairo1_contracts.erc20_contract,
        &[&cairo1_contracts.account_without_validations, &cairo1_contracts.test_contract],
        ffc,
    )
    .await
    .unwrap();

    Cairo1InitialState { state, deployed_addresses, contracts: cairo1_contracts, deprecated_contract_classes }
}
