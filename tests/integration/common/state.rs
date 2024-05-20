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
    pub contract_classes: HashMap<ClassHash, CasmContractClass>,
    pub deprecated_contract_classes: HashMap<ClassHash, DeprecatedCompiledClass>
}

/// ERC20 contract deployments for Eth and Strk tokens
#[derive(Debug)]
pub struct FeeContracts {
    pub erc20_contract: DeprecatedCompiledClass,
    pub eth_fee_token_address: ContractAddress,
    pub strk_fee_token_address: ContractAddress,
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
