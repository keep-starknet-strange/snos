use std::collections::{HashMap, HashSet};

use blockifier::block_context::BlockContext;
use blockifier::execution::contract_class::ContractClass::{V0, V1};
use blockifier::state::cached_state::CachedState;
use blockifier::state::state_api::{State as _, StateReader};
use blockifier::test_utils::contracts::FeatureContract;
use blockifier::test_utils::contracts::FeatureContract::{
    AccountWithLongValidate, AccountWithoutValidations, Empty, FaultyAccount, SecurityTests, TestContract, ERC20,
};
use blockifier::test_utils::dict_state_reader::DictStateReader;
use blockifier::test_utils::initial_test_state::fund_account;
use blockifier::test_utils::CairoVersion;
use blockifier::transaction::objects::{FeeType, TransactionExecutionInfo};
use cairo_lang_starknet::casm_contract_class::CasmContractClass;
use cairo_vm::Felt252;
use snos::config::{StarknetGeneralConfig, StarknetOsConfig, STORED_BLOCK_HASH_BUFFER};
use snos::execution::helper::ExecutionHelperWrapper;
use snos::io::input::{ContractState, StarknetOsInput, StorageCommitment};
use snos::io::InternalTransaction;
use snos::storage::storage_utils::build_starknet_storage;
use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress};
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedContractClass;
use starknet_api::hash::StarkHash;
use starknet_crypto::FieldElement;

use crate::common::transaction_utils::to_felt252;

pub fn deprecated_compiled_class(class_hash: ClassHash) -> DeprecatedContractClass {
    let variants = vec![
        AccountWithLongValidate(CairoVersion::Cairo0),
        AccountWithoutValidations(CairoVersion::Cairo0),
        ERC20,
        Empty(CairoVersion::Cairo0),
        FaultyAccount(CairoVersion::Cairo0),
        // LegacyTestContract,
        SecurityTests,
        TestContract(CairoVersion::Cairo0),
    ];

    for c in variants {
        if ClassHash(override_class_hash(&c)) == class_hash {
            let result: Result<DeprecatedContractClass, serde_json::Error> =
                serde_json::from_str(c.get_raw_class().as_str());
            return result.unwrap();
        }
    }
    panic!("No deprecated class found for hash: {:?}", class_hash);
}

pub fn compiled_class(class_hash: ClassHash) -> CasmContractClass {
    let variants = vec![
        AccountWithLongValidate(CairoVersion::Cairo1),
        AccountWithoutValidations(CairoVersion::Cairo1),
        Empty(CairoVersion::Cairo1),
        FaultyAccount(CairoVersion::Cairo1),
        TestContract(CairoVersion::Cairo1),
    ];

    for c in variants {
        if c.get_class_hash() == class_hash {
            let result: Result<CasmContractClass, serde_json::Error> = serde_json::from_str(c.get_raw_class().as_str());
            return result.unwrap();
        }
    }
    panic!("No class found for hash: {:?}", class_hash);
}

fn override_class_hash(contract: &FeatureContract) -> StarkHash {
    match contract {
        // FeatureContract::AccountWithLongValidate(_) => ACCOUNT_LONG_VALIDATE_BASE,
        FeatureContract::AccountWithoutValidations(CairoVersion::Cairo0) => {
            let fe = FieldElement::from_dec_str(
                "646245114977324210659279014519951538684823368221946044944492064370769527799",
            )
            .unwrap();
            StarkHash::from(fe)
        }
        // FeatureContract::Empty(_) => EMPTY_CONTRACT_BASE,
        FeatureContract::ERC20 => {
            let fe = FieldElement::from_dec_str(
                "561405978155448065164184136501758613494542063826668571171916978663245519697",
            )
            .unwrap();
            StarkHash::from(fe)
        }
        // FeatureContract::FaultyAccount(_) => FAULTY_ACCOUNT_BASE,
        // FeatureContract::LegacyTestContract => LEGACY_CONTRACT_BASE,
        // FeatureContract::SecurityTests => SECURITY_TEST_CONTRACT_BASE,
        FeatureContract::TestContract(CairoVersion::Cairo0) => {
            let fe = FieldElement::from_dec_str(
                "2988696213549450938938462798157547750390790722284970546348726091875993395870",
            )
            .unwrap();
            StarkHash::from(fe)
        }

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
    let erc20_class_hash: ClassHash = ClassHash(override_class_hash(&erc20));
    class_hash_to_class.insert(erc20_class_hash, erc20.get_class());
    address_to_class_hash.insert(block_context.fee_token_address(&FeeType::Eth), erc20_class_hash);
    address_to_class_hash.insert(block_context.fee_token_address(&FeeType::Strk), erc20_class_hash);

    // Set up the rest of the requested contracts.
    for (contract, n_instances) in contract_instances.iter() {
        let class_hash = ClassHash(override_class_hash(contract));
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

pub fn os_hints(
    block_context: &BlockContext,
    mut blockifier_state: CachedState<DictStateReader>,
    transactions: Vec<InternalTransaction>,
    tx_execution_infos: Vec<TransactionExecutionInfo>,
) -> (StarknetOsInput, ExecutionHelperWrapper) {
    let deployed_addresses = blockifier_state.to_state_diff().address_to_class_hash;
    let initial_addresses = blockifier_state.state.address_to_class_hash.keys().cloned().collect::<HashSet<_>>();
    let addresses = deployed_addresses.keys().cloned().chain(initial_addresses);

    let mut contracts: HashMap<Felt252, ContractState> = addresses
        .map(|address| {
            // os expects the contract hash to be 0 for just deployed contracts
            let contract_hash = if deployed_addresses.contains_key(&address) {
                Felt252::ZERO
            } else {
                to_felt252(&blockifier_state.get_class_hash_at(address).unwrap().0)
            };
            let contract_state = ContractState {
                contract_hash,
                storage_commitment_tree: StorageCommitment::default(), // TODO
                nonce: 0.into(),                                       // TODO
            };
            (to_felt252(address.0.key()), contract_state)
        })
        .collect();

    let mut deprecated_compiled_classes: HashMap<Felt252, DeprecatedContractClass> = Default::default();
    let mut compiled_classes: HashMap<Felt252, CasmContractClass> = Default::default();
    let mut class_hash_to_compiled_class_hash: HashMap<Felt252, Felt252> = Default::default();

    for c in contracts.keys() {
        let address = ContractAddress::try_from(StarkHash::new(c.to_bytes_be()).unwrap()).unwrap();
        let class_hash = blockifier_state.get_class_hash_at(address).unwrap();
        let blockifier_class = blockifier_state.get_compiled_contract_class(class_hash).unwrap();
        match blockifier_class {
            V0(_) => {
                deprecated_compiled_classes.insert(to_felt252(&class_hash.0), deprecated_compiled_class(class_hash));
            }
            V1(_) => {
                let class = compiled_class(class_hash);
                let compiled_class_hash = class.compiled_class_hash();
                compiled_classes.insert(Felt252::from_bytes_be(&class.compiled_class_hash().to_be_bytes()), class);
                class_hash_to_compiled_class_hash
                    .insert(to_felt252(&class_hash.0), Felt252::from_bytes_be(&compiled_class_hash.to_be_bytes()));
            }
        };
    }

    contracts.insert(Felt252::from(0), ContractState::default());
    contracts.insert(Felt252::from(1), ContractState::default());

    println!("contracts: {:?}\ndeprecated_compiled_classes: {:?}", contracts.len(), deprecated_compiled_classes.len());

    println!("contracts to class_hash");
    for (a, c) in &contracts {
        println!("\t{} -> {}", a, c.contract_hash);
    }

    println!("deprecated classes");
    for (c, _) in &deprecated_compiled_classes {
        println!("\t{}", c);
    }

    println!("classes");
    for (c, _) in &compiled_classes {
        println!("\t{}", c);
    }

    // for h in deprecated_compiled_classes.keys() {
    //     class_hash_to_compiled_class_hash.insert(h.clone(), h.clone());
    // }

    // for (h, c) in compiled_classes.iter() {
    //     class_hash_to_compiled_class_hash
    //         .insert(h.clone(), Felt252::from_bytes_be(&c.compiled_class_hash().to_be_bytes()));
    // }

    println!("class_hash to compiled_class_hash");
    for (ch, cch) in &class_hash_to_compiled_class_hash {
        println!("\t{} -> {}", ch, cch);
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

    let os_input = StarknetOsInput {
        contract_state_commitment_info: Default::default(),
        contract_class_commitment_info: Default::default(),
        deprecated_compiled_classes,
        compiled_classes,
        compiled_class_visited_pcs: Default::default(),
        contracts,
        class_hash_to_compiled_class_hash,
        general_config,
        transactions,
        block_hash: Default::default(),
    };

    // Convert the Blockifier storage into an OS-compatible one
    let contract_storage_map = build_starknet_storage(&mut blockifier_state);

    let execution_helper = ExecutionHelperWrapper::new(
        contract_storage_map,
        tx_execution_infos,
        &block_context,
        (Felt252::from(block_context.block_number.0 - STORED_BLOCK_HASH_BUFFER), Felt252::from(66_u64)),
    );

    (os_input, execution_helper)
}
