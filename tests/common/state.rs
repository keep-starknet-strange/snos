use blockifier::block_context::BlockContext;
use blockifier::state::cached_state::CachedState;
use blockifier::test_utils::contracts::FeatureContract;
use blockifier::test_utils::dict_state_reader::DictStateReader;
use blockifier::test_utils::{CairoVersion, BALANCE};
use rstest::fixture;
use starknet_api::core::ContractAddress;

use crate::common::block_context;
use crate::common::block_utils::test_state;

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
