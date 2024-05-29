use std::collections::{HashMap, HashSet};

use blockifier::abi::abi_utils::get_fee_token_var_address;
use blockifier::block_context::BlockContext;
use blockifier::state::cached_state::CachedState;
use blockifier::test_utils::dict_state_reader::DictStateReader;
use blockifier::test_utils::BALANCE;
use cairo_lang_starknet::casm_contract_class::CasmContractClass;
use cairo_lang_starknet::contract_class::ContractClass;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rstest::fixture;
use snos::config::StarknetGeneralConfig;
use snos::crypto::pedersen::PedersenHash;
use snos::starknet::business_logic::fact_state::state::SharedState;
use snos::starknet::business_logic::utils::{write_class_facts, write_deprecated_compiled_class_fact};
use snos::starkware_utils::commitment_tree::errors::TreeError;
use snos::storage::dict_storage::DictStorage;
use snos::storage::storage::{FactFetchingContext, StorageError};
use snos::storage::storage_utils::{compiled_contract_class_cl2vm, deprecated_contract_class_api2vm};
use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress};
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedCompiledClass;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;

use super::blockifier_contracts::{get_feature_casm_contract_class, get_feature_sierra_contract_class};
use crate::common::block_context;
use crate::common::blockifier_contracts::{get_deprecated_erc20_contract_class, get_deprecated_feature_contract_class};

/// A struct to store all test state that must be maintained between initial setup, blockifier
/// execution, and SNOS re-execution.
///
/// Some of this maintains the deployed contracts in a way that makes test writing easy, and some
/// of it maintains state that is required for execution.
#[derive(Debug)]
pub struct StarknetTestState {
    /// All deployed cairo0 contracts. Currently expects exactly one deployment per class. String
    /// represents the contract's name (such as file or class name, but is really arbitrary).
    pub cairo0_contracts: HashMap<String, DeprecatedContractDeployment>,
    /// All deployed cairo1 contracts. Currently expects exactly one deployment per class. String
    /// represents the contract's name (such as file or class name, but is really arbitrary).
    pub cairo1_contracts: HashMap<String, ContractDeployment>,
    /// State initially created for blockifier execution
    pub cached_state: CachedState<SharedState<DictStorage, PedersenHash>>,
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
    pub casm_class: CasmContractClass,
    pub sierra_class: ContractClass,
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

/// Helper to load a Cairo 0 contract class.
pub fn load_cairo0_contract(name: &str) -> (String, DeprecatedCompiledClass) {
    (name.to_string(), get_deprecated_feature_contract_class(name))
}

/// Helper to load a Cairo1 contract class.
pub fn load_cairo1_contract(name: &str) -> (String, ContractClass, CasmContractClass) {
    (name.to_string(), get_feature_sierra_contract_class(name), get_feature_casm_contract_class(name))
}

/// Configures the logging for integration tests.
///
/// Needs to be called explicitly from tests.
#[fixture]
#[once]
fn init_logging() {
    env_logger::builder()
        .is_test(true)
        .filter_level(log::LevelFilter::Debug)
        .format_timestamp(None)
        .try_init()
        .expect("Failed to configure env_logger");
}

#[derive(Debug)]
struct Cairo0Contract {
    deprecated_compiled_class: DeprecatedCompiledClass,
    /// Contract address to use when deploying the contract.
    address: ContractAddress,
}

#[derive(Debug)]
struct Cairo1Contract {
    contract_class: ContractClass,
    compiled_contract_class: CasmContractClass,
    /// Contract address to use when deploying the contract.
    address: ContractAddress,
}

#[derive(Debug)]
struct FeeConfig {
    strk_fee_token_address: ContractAddress,
    eth_fee_token_address: ContractAddress,
    initial_balance: u128,
}

/// Builds the initial state for OS integration tests.
///
/// This builder allows to deploy contracts and configure account balances and then generates
#[derive(Debug)]
struct StarknetStateBuilder<'a> {
    /// Cairo 0 contracts (name -> contract class).
    cairo0_contracts: HashMap<String, Cairo0Contract>,
    /// Cairo 1 contracts (name -> contract class + compiled contract class).
    cairo1_contracts: HashMap<String, Cairo1Contract>,
    /// Config for fees: initial balance, fee token contract addresses, etc.
    fee_config: Option<FeeConfig>,
    block_context: &'a BlockContext,
    /// Contract address generator.
    address_generator: StdRng,
}

impl<'a> StarknetStateBuilder<'a> {
    fn new(block_context: &'a BlockContext) -> Self {
        Self {
            cairo0_contracts: Default::default(),
            cairo1_contracts: Default::default(),
            fee_config: None,
            block_context,
            address_generator: StdRng::seed_from_u64(1),
        }
    }

    async fn build(self) -> StarknetTestState {
        let mut dict_state_reader = DictStateReader::default();
        let mut ffc: FactFetchingContext<DictStorage, PedersenHash> = FactFetchingContext::new(DictStorage::default());

        let (cairo0_deployed_contracts, cairo0_compiled_classes) =
            Self::deploy_cairo0_contracts(self.cairo0_contracts, &mut dict_state_reader, &mut ffc)
                .await
                .expect("Failed to deploy Cairo 0 contracts in storage");
        let (cairo1_deployed_contracts, cairo1_compiled_classes) =
            Self::deploy_cairo1_contracts(self.cairo1_contracts, &mut dict_state_reader, &mut ffc)
                .await
                .expect("Failed to deploy Cairo 1 contracts in storage");

        if let Some(fee_config) = self.fee_config {
            Self::fund_accounts(&fee_config, &mut dict_state_reader);
        }

        let shared_state = Self::build_shared_state(dict_state_reader, ffc)
            .await
            .expect("failed to apply initial state as updates to SharedState");

        let cached_state = CachedState::from(shared_state);

        StarknetTestState {
            cairo0_contracts: cairo0_deployed_contracts,
            cairo1_contracts: cairo1_deployed_contracts,
            cached_state,
            cairo0_compiled_classes,
            cairo1_compiled_classes,
        }
    }

    /// Generates a random contract address.
    fn generate_contract_address(&mut self) -> ContractAddress {
        self.address_generator.gen::<u32>().into()
    }

    /// Deploys Cairo 0 contracts.
    /// Adds entries in the dict state reader and the FFC for each compiled class.
    async fn deploy_cairo0_contracts(
        cairo0_contracts: HashMap<String, Cairo0Contract>,
        dict_state_reader: &mut DictStateReader,
        ffc: &mut FactFetchingContext<DictStorage, PedersenHash>,
    ) -> Result<
        (HashMap<String, DeprecatedContractDeployment>, HashMap<ClassHash, DeprecatedCompiledClass>),
        StorageError,
    > {
        let mut deployed_contracts = HashMap::<String, DeprecatedContractDeployment>::new();
        let mut compiled_contract_classes = HashMap::<ClassHash, DeprecatedCompiledClass>::new();

        for (name, contract) in cairo0_contracts {
            let class_hash =
                write_deprecated_compiled_class_fact(contract.deprecated_compiled_class.clone(), ffc).await?;
            let class_hash = ClassHash::try_from(class_hash).expect("Class hash is not in prime field");

            // Add entries in the dict state
            let vm_class = deprecated_contract_class_api2vm(&contract.deprecated_compiled_class).unwrap();
            dict_state_reader.class_hash_to_class.insert(class_hash, vm_class);
            dict_state_reader.class_hash_to_compiled_class_hash.insert(class_hash, CompiledClassHash(class_hash.0));

            log::debug!("Inserting deprecated class_hash_to_class: {:?} -> {:?}", contract.address, class_hash);
            dict_state_reader.address_to_class_hash.insert(contract.address.clone(), class_hash);

            deployed_contracts.insert(
                name.clone(),
                DeprecatedContractDeployment {
                    class_hash,
                    address: contract.address.clone(),
                    class: contract.deprecated_compiled_class.clone(),
                },
            );
            compiled_contract_classes.insert(class_hash, contract.deprecated_compiled_class.clone());
        }

        Ok((deployed_contracts, compiled_contract_classes))
    }

    /// Deploys Cairo 1 contracts.
    /// Adds entries in the dict state reader and the FFC for each contract and compiled classes.
    async fn deploy_cairo1_contracts(
        cairo1_contracts: HashMap<String, Cairo1Contract>,
        dict_state_reader: &mut DictStateReader,
        ffc: &mut FactFetchingContext<DictStorage, PedersenHash>,
    ) -> Result<(HashMap<String, ContractDeployment>, HashMap<ClassHash, CasmContractClass>), StorageError> {
        let mut deployed_contracts = HashMap::<String, ContractDeployment>::new();
        let mut compiled_contract_classes = HashMap::<ClassHash, CasmContractClass>::new();

        for (name, contract) in cairo1_contracts {
            let (contract_class_hash, compiled_class_hash) =
                write_class_facts(contract.contract_class.clone(), contract.compiled_contract_class.clone(), ffc)
                    .await?;
            let class_hash = ClassHash::try_from(contract_class_hash).expect("Class hash is not in prime field");
            let compiled_class_hash =
                CompiledClassHash::try_from(compiled_class_hash).expect("Compiled class hash is not in prime field");

            // Add entries in the dict state
            let vm_class = compiled_contract_class_cl2vm(&contract.compiled_contract_class).unwrap();
            dict_state_reader.class_hash_to_class.insert(class_hash, vm_class);
            dict_state_reader.class_hash_to_compiled_class_hash.insert(class_hash, compiled_class_hash);

            log::debug!("Inserting class_hash_to_class: {:?} -> {:?}", contract.address, class_hash);
            dict_state_reader.address_to_class_hash.insert(contract.address, class_hash);

            deployed_contracts.insert(
                name.clone(),
                ContractDeployment {
                    class_hash,
                    address: contract.address.clone(),
                    casm_class: contract.compiled_contract_class.clone(),
                    sierra_class: contract.contract_class.clone(),
                },
            );
            compiled_contract_classes.insert(class_hash, contract.compiled_contract_class.clone());
        }

        Ok((deployed_contracts, compiled_contract_classes))
    }

    /// Funds all accounts according to the test fee configuration.
    fn fund_accounts(fee_config: &FeeConfig, dict_state_reader: &mut DictStateReader) {
        let mut addresses: HashSet<ContractAddress> = Default::default();
        for address in dict_state_reader.address_to_class_hash.keys().chain(dict_state_reader.address_to_nonce.keys()) {
            addresses.insert(*address);
        }

        // fund the accounts.
        for address in addresses.iter() {
            Self::fund_account(fee_config, dict_state_reader, *address);
        }
    }

    /// Funds an account and gives it the specified balance in both STRK and ETH.
    /// Modified the storage of the dict state reader to apply the balance change.
    fn fund_account(fee_config: &FeeConfig, dict_state_reader: &mut DictStateReader, account_address: ContractAddress) {
        let storage_view = &mut dict_state_reader.storage_view;
        let balance_key = get_fee_token_var_address(account_address);
        for fee_token_address in [fee_config.strk_fee_token_address, fee_config.eth_fee_token_address] {
            storage_view.insert((fee_token_address, balance_key), stark_felt!(fee_config.initial_balance));
        }
    }

    /// Converts the dict state reader and FFC into a shared state object.
    async fn build_shared_state(
        dict_state_reader: DictStateReader,
        ffc: FactFetchingContext<DictStorage, PedersenHash>,
    ) -> Result<SharedState<DictStorage, PedersenHash>, TreeError> {
        // Build the shared state object
        // TODO: block info is not really needed in SharedState, it's a relic of the Python code.
        //       check how it can be removed.
        let block_info = Default::default();

        let default_general_config = StarknetGeneralConfig::default(); // TODO
        SharedState::from_blockifier_state(ffc, dict_state_reader, block_info, &default_general_config).await
    }

    /// Add a Cairo 0 contract to the test state.
    fn add_cairo0_contract(mut self, name: String, deprecated_compiled_class: DeprecatedCompiledClass) -> Self {
        let contract_address = self.generate_contract_address();
        self.add_cairo0_contract_with_fixed_address(name, deprecated_compiled_class, contract_address)
    }

    /// Add a Cairo 0 contract to the test state with a fixed contract address.
    fn add_cairo0_contract_with_fixed_address(
        mut self,
        name: String,
        deprecated_compiled_class: DeprecatedCompiledClass,
        contract_address: ContractAddress,
    ) -> Self {
        let cairo0_contract = Cairo0Contract { deprecated_compiled_class, address: contract_address };
        self.cairo0_contracts.insert(name, cairo0_contract);
        self
    }

    /// Add a Cairo 1 contract to the test state.
    fn add_cairo1_contract(
        mut self,
        name: String,
        contract_class: ContractClass,
        compiled_contract_class: CasmContractClass,
    ) -> Self {
        let contract_address = self.generate_contract_address();
        self.add_cairo1_contract_with_fixed_address(name, contract_class, compiled_contract_class, contract_address)
    }

    /// Add a Cairo 1 contract to the test state with a fixed contract address.
    fn add_cairo1_contract_with_fixed_address(
        mut self,
        name: String,
        contract_class: ContractClass,
        compiled_contract_class: CasmContractClass,
        contract_address: ContractAddress,
    ) -> Self {
        let cairo1_contract = Cairo1Contract { contract_class, compiled_contract_class, address: contract_address };
        self.cairo1_contracts.insert(name, cairo1_contract);
        self
    }

    fn set_initial_balance(mut self, balance: u128) -> Self {
        let erc20_contract = get_deprecated_erc20_contract_class();
        let eth_fee_token_address = self.block_context.fee_token_addresses.eth_fee_token_address;
        let strk_fee_token_address = self.block_context.fee_token_addresses.strk_fee_token_address;

        self.fee_config = Some(FeeConfig { strk_fee_token_address, eth_fee_token_address, initial_balance: balance });
        self.add_cairo0_contract_with_fixed_address(
            "erc20_eth".to_string(),
            erc20_contract.clone(),
            eth_fee_token_address,
        )
        .add_cairo0_contract_with_fixed_address(
            "erc20_strk".to_string(),
            erc20_contract,
            strk_fee_token_address,
        )
    }
}

/// Fixture to create initial test state in which all test contracts are deployed.
#[fixture]
pub async fn initial_state_cairo0(
    block_context: BlockContext,
    #[from(init_logging)] _logging: (),
) -> StarknetTestState {
    let account_with_dummy_validate = load_cairo0_contract("account_with_dummy_validate");
    let test_contract = load_cairo0_contract("test_contract");

    StarknetStateBuilder::new(&block_context)
        .add_cairo0_contract(account_with_dummy_validate.0, account_with_dummy_validate.1)
        .add_cairo0_contract(test_contract.0, test_contract.1)
        .set_initial_balance(BALANCE)
        .build()
        .await
}

/// Initial state for the basic Cairo 1 test.
/// Note that this test mixes Cairo 0 and Cairo 1 contracts. We reuse the ERC20 contract Blockifier
/// out of simplicity for our first tests, this will eventually be replaced by an equivalent
/// Cairo 1 contract if possible.

#[fixture]
pub async fn initial_state_cairo1(
    block_context: BlockContext,
    #[from(init_logging)] _logging: (),
) -> StarknetTestState {
    let test_contract = load_cairo0_contract("test_contract");
    let account_with_dummy_validate = load_cairo1_contract("account_with_dummy_validate");

    StarknetStateBuilder::new(&block_context)
        .add_cairo1_contract(
            account_with_dummy_validate.0,
            account_with_dummy_validate.1,
            account_with_dummy_validate.2,
        )
        .add_cairo0_contract(test_contract.0, test_contract.1)
        .set_initial_balance(BALANCE)
        .build()
        .await
}

/// Initial state for the syscalls test.
#[fixture]
pub async fn initial_state_syscalls(
    block_context: BlockContext,
    #[from(init_logging)] _logging: (),
) -> StarknetTestState {
    let account_with_dummy_validate = load_cairo1_contract("account_with_dummy_validate");
    let test_contract = load_cairo1_contract("test_contract");

    StarknetStateBuilder::new(&block_context)
        .add_cairo1_contract(
            account_with_dummy_validate.0,
            account_with_dummy_validate.1,
            account_with_dummy_validate.2,
        )
        .add_cairo1_contract(test_contract.0, test_contract.1, test_contract.2)
        .set_initial_balance(BALANCE)
        .build()
        .await
}
