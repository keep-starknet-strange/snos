use std::collections::HashMap;

use blockifier::block_context::BlockContext;
use blockifier::state::cached_state::CachedState;
use blockifier::test_utils::contracts::FeatureContract;
use blockifier::test_utils::dict_state_reader::DictStateReader;
use blockifier::test_utils::{CairoVersion, BALANCE, BALANCE};
use cairo_lang_starknet::casm_contract_class::CasmContractClass;
use rstest::fixture;
use snos::crypto::pedersen::PedersenHash;
use snos::starknet::business_logic::fact_state::state::SharedState;
use snos::storage::dict_storage::DictStorage;
use snos::storage::storage::FactFetchingContext;
use starknet_api::core::{ClassHash, ContractAddress, ContractAddress};
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedCompiledClass;

use super::block_utils::test_state;
use crate::common::block_context;
use crate::common::blockifier_contracts::{
    get_deprecated_erc20_contract_class, get_deprecated_feature_contract_class, get_feature_contract_class,
};

/// A struct to store all test state that must be maintained between initial setup, blockifier
/// execution, and SNOS re-execution.
///
/// Some of this maintains the deployed contracts in a way that makes test writing easy, and some
/// of it maintains state that is required for execution.
#[derive(Debug)]
pub struct TestState {
    /// All deployed cairo0 contracts. Currently expects exactly one deploydment per class. String
    /// represents the contract's name (such as file or class name, but is really arbitrary).
    pub cairo0_contracts: HashMap<String, DeprecatedContractDeployment>,
    /// All deployed cairo1 contracts. Currently expects exactly one deploydment per class. String
    /// represents the contract's name (such as file or class name, but is really arbitrary).
    pub cairo1_contracts: HashMap<String, ContractDeployment>,
    /// The ERC20 fee contract deployments
    pub fee_contracts: FeeContracts,

    /// State initially created for blockifier execution
    pub blockifier_state: CachedState<DictStateReader>,
    /// All cairo0 compiled classes
    pub cairo0_compiled_classes: HashMap<ClassHash, DeprecatedCompiledClass>,
    /// All cairo1 compiled classes
    pub cairo1_compiled_classes: HashMap<ClassHash, CasmContractClass>,
}

/// Struct representing a deployed cairo1 class
#[derive(Debug)]
pub struct ContractDeployment {
    pub class_hash: ClassHash,
    pub address: ContractAddress,
    pub class: CasmContractClass,
}

/// Struct representing a deployed cairo0 class
#[derive(Debug)]
pub struct DeprecatedContractDeployment {
    pub class_hash: ClassHash,
    pub address: ContractAddress,
    pub class: DeprecatedCompiledClass,
}

/// ERC20 contract deployments for Eth and Strk tokens, as well as the compiled class. Note that
/// this is always a cairo0 contract.
#[derive(Debug)]
pub struct FeeContracts {
    pub erc20_contract: DeprecatedCompiledClass,
    pub eth_fee_token_address: ContractAddress,
    pub strk_fee_token_address: ContractAddress,
}

/// Fixture to create initial test state in which all test contracts are deployed.
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
