use blockifier::abi::abi_utils::selector_from_name;
use blockifier::test_utils::contracts::FeatureContract::{
    AccountWithLongValidate, AccountWithoutValidations, Empty, FaultyAccount, LegacyTestContract, SecurityTests,
    TestContract, ERC20,
};
use blockifier::test_utils::invoke::InvokeTxArgs;
use blockifier::test_utils::CairoVersion;
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::constants::EXECUTE_ENTRY_POINT_NAME;
use blockifier::transaction::test_utils;
use cairo_vm::Felt252;
use snos::io::InternalTransaction;
use starknet_api::core::ClassHash;
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedContractClass;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::TransactionVersion;

pub fn deprecated_class(class_hash: &ClassHash) -> DeprecatedContractClass {
    let variants = vec![
        AccountWithLongValidate(CairoVersion::Cairo0),
        AccountWithLongValidate(CairoVersion::Cairo1),
        AccountWithoutValidations(CairoVersion::Cairo0),
        AccountWithoutValidations(CairoVersion::Cairo1),
        ERC20,
        Empty(CairoVersion::Cairo0),
        Empty(CairoVersion::Cairo1),
        FaultyAccount(CairoVersion::Cairo0),
        FaultyAccount(CairoVersion::Cairo1),
        LegacyTestContract,
        SecurityTests,
        TestContract(CairoVersion::Cairo0),
        TestContract(CairoVersion::Cairo1),
    ];

    for c in variants {
        if &c.get_class_hash() == class_hash {
            let result: Result<DeprecatedContractClass, serde_json::Error> =
                serde_json::from_str(c.get_raw_class().as_str());
            return result.unwrap();
        }
    }
    panic!("No class found for hash: {:?}", class_hash);
}

pub fn to_felt252(stark_felt: &StarkFelt) -> Felt252 {
    Felt252::from_hex(&stark_felt.to_string()).expect("Couldn't parse bytes")
}

fn internal_account_invoke_tx(invoke_args: InvokeTxArgs) -> InternalTransaction {
    let mut hash_value: Felt252 = Felt252::default();
    let mut version: Option<Felt252> = Some(to_felt252(&invoke_args.version.0));
    let mut contract_address: Option<Felt252> = None;
    let mut contract_address_salt: Option<Felt252> = None;
    let mut contract_hash: Option<Felt252> = None;
    let mut constructor_calldata: Option<Vec<Felt252>> = None;
    let mut nonce: Option<Felt252> = Some(to_felt252(&invoke_args.nonce.0));
    let mut sender_address: Option<Felt252> = Some(to_felt252(invoke_args.sender_address.0.key()));
    let mut entry_point_selector: Option<Felt252> = None;
    let mut entry_point_type: Option<String> = Some("EXTERNAL".to_string());
    let mut signature: Option<Vec<Felt252>> = Some(invoke_args.signature.0.iter().map(|x| to_felt252(x)).collect());
    let mut class_hash: Option<Felt252> = None;
    let mut calldata: Option<Vec<Felt252>> =
        Some(invoke_args.calldata.0.iter().map(|x| to_felt252(x.into())).collect());
    let mut paid_on_l1: Option<bool> = None;
    let mut r#type: String = "INVOKE_FUNCTION".to_string();

    match invoke_args.version {
        TransactionVersion::ZERO => {
            // starknet_api::transaction::InvokeTransaction::V0(InvokeTransactionV0 {
            //     max_fee: invoke_args.max_fee,
            //     calldata: invoke_args.calldata,
            //     contract_address: invoke_args.sender_address,
            //     signature: invoke_args.signature,
            //     // V0 transactions should always select the `__execute__` entry point.
            //     entry_point_selector: selector_from_name(EXECUTE_ENTRY_POINT_NAME),
            // })
            contract_address = Some(to_felt252(invoke_args.sender_address.0.key()));
            entry_point_selector = Some(to_felt252(&selector_from_name(EXECUTE_ENTRY_POINT_NAME).0));
        }
        TransactionVersion::ONE => {
            panic!("Not implemented");
            // starknet_api::transaction::InvokeTransaction::V1(InvokeTransactionV1 {
            //     max_fee: invoke_args.max_fee,
            //     sender_address: invoke_args.sender_address,
            //     nonce: invoke_args.nonce,
            //     calldata: invoke_args.calldata,
            //     signature: invoke_args.signature,
            // })
        }
        TransactionVersion::THREE => {
            panic!("Not implemented");
            // starknet_api::transaction::InvokeTransaction::V3(InvokeTransactionV3 {
            //     resource_bounds: invoke_args.resource_bounds,
            //     calldata: invoke_args.calldata,
            //     sender_address: invoke_args.sender_address,
            //     nonce: invoke_args.nonce,
            //     signature: invoke_args.signature,
            //     tip: invoke_args.tip,
            //     nonce_data_availability_mode: invoke_args.nonce_data_availability_mode,
            //     fee_data_availability_mode: invoke_args.fee_data_availability_mode,
            //     paymaster_data: invoke_args.paymaster_data,
            //     account_deployment_data: invoke_args.account_deployment_data,
            // })
        }
        _ => panic!("Unsupported transaction version: {:?}.", invoke_args.version),
    };

    return InternalTransaction {
        hash_value,
        version,
        contract_address,
        contract_address_salt,
        contract_hash,
        constructor_calldata,
        nonce,
        sender_address,
        entry_point_selector,
        entry_point_type,
        signature,
        class_hash,
        calldata,
        paid_on_l1,
        r#type,
    };
}

pub fn account_invoke_tx(invoke_args: InvokeTxArgs) -> (AccountTransaction, InternalTransaction) {
    (test_utils::account_invoke_tx(invoke_args.clone()), internal_account_invoke_tx(invoke_args))
}
