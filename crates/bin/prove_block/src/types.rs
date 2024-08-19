use std::collections::BTreeMap;

use cairo_vm::Felt252;
use starknet::core::types::{
    DataAvailabilityMode, DeclareTransaction, DeclareTransactionV0, DeclareTransactionV1, DeclareTransactionV2,
    DeclareTransactionV3, DeployAccountTransaction, DeployAccountTransactionV1, DeployAccountTransactionV3,
    InvokeTransaction, InvokeTransactionV0, InvokeTransactionV1, InvokeTransactionV3, L1HandlerTransaction,
    ResourceBoundsMapping, Transaction,
};
use starknet_os::io::InternalTransaction;
use starknet_types_core::felt::Felt;

// entry point for "__execute__"
const EXECUTE_ENTRY_POINT_FELT: Felt252 =
    Felt252::from_hex_unchecked("0x15d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad");

fn felt_to_vm(felt: Felt) -> Felt252 {
    // Turns out that the types are the same between starknet-core and cairo-vm
    felt
}

fn da_to_felt(data_availability_mode: DataAvailabilityMode) -> Felt252 {
    match data_availability_mode {
        DataAvailabilityMode::L1 => Felt252::ZERO,
        DataAvailabilityMode::L2 => Felt252::ONE,
    }
}

fn resource_bounds_to_api(resource_bounds: ResourceBoundsMapping) -> starknet_api::transaction::ResourceBoundsMapping {
    starknet_api::transaction::ResourceBoundsMapping(BTreeMap::from([
        (
            starknet_api::transaction::Resource::L1Gas,
            starknet_api::transaction::ResourceBounds {
                max_amount: resource_bounds.l1_gas.max_amount,
                max_price_per_unit: resource_bounds.l1_gas.max_price_per_unit,
            },
        ),
        (
            starknet_api::transaction::Resource::L2Gas,
            starknet_api::transaction::ResourceBounds {
                max_amount: resource_bounds.l2_gas.max_amount,
                max_price_per_unit: resource_bounds.l2_gas.max_price_per_unit,
            },
        ),
    ]))
}

fn invoke_tx_v0_to_internal_tx(tx: InvokeTransactionV0) -> InternalTransaction {
    let signature: Vec<_> = tx.signature.into_iter().map(felt_to_vm).collect();
    let calldata: Vec<_> = tx.calldata.into_iter().map(felt_to_vm).collect();

    InternalTransaction {
        hash_value: felt_to_vm(tx.transaction_hash),
        max_fee: Some(felt_to_vm(tx.max_fee)),
        signature: Some(signature),
        contract_address: Some(felt_to_vm(tx.contract_address)),
        entry_point_selector: Some(felt_to_vm(tx.entry_point_selector)),
        calldata: Some(calldata),
        version: Some(Felt252::ZERO),
        ..Default::default()
    }
}
fn invoke_tx_v1_to_internal_tx(tx: InvokeTransactionV1) -> InternalTransaction {
    let signature: Vec<_> = tx.signature.into_iter().map(felt_to_vm).collect();
    let calldata: Vec<_> = tx.calldata.into_iter().map(felt_to_vm).collect();

    InternalTransaction {
        hash_value: felt_to_vm(tx.transaction_hash),
        version: Some(Felt252::ONE),
        contract_address: Some(tx.sender_address),
        nonce: Some(tx.nonce),
        sender_address: Some(tx.sender_address),
        entry_point_selector: Some(EXECUTE_ENTRY_POINT_FELT),
        entry_point_type: Some("EXTERNAL".to_string()),
        signature: Some(signature),
        calldata: Some(calldata),
        r#type: "INVOKE_FUNCTION".to_string(),
        max_fee: Some(tx.max_fee),
        ..Default::default()
    }
}

fn invoke_tx_v3_to_internal_tx(tx: InvokeTransactionV3) -> InternalTransaction {
    let signature: Vec<_> = tx.signature.into_iter().map(felt_to_vm).collect();
    let calldata: Vec<_> = tx.calldata.into_iter().map(felt_to_vm).collect();
    let paymaster_data: Vec<_> = tx.paymaster_data.into_iter().map(felt_to_vm).collect();
    let account_deployment_data: Vec<_> = tx.account_deployment_data.into_iter().map(felt_to_vm).collect();

    InternalTransaction {
        hash_value: felt_to_vm(tx.transaction_hash),
        sender_address: Some(felt_to_vm(tx.sender_address)),
        signature: Some(signature),
        nonce: Some(felt_to_vm(tx.nonce)),
        resource_bounds: Some(resource_bounds_to_api(tx.resource_bounds)),
        tip: Some(Felt252::from(tx.tip)),
        paymaster_data: Some(paymaster_data),
        account_deployment_data: Some(account_deployment_data),
        nonce_data_availability_mode: Some(da_to_felt(tx.nonce_data_availability_mode)),
        fee_data_availability_mode: Some(da_to_felt(tx.fee_data_availability_mode)),
        version: Some(Felt252::TWO),
        contract_address: Some(tx.sender_address),
        entry_point_selector: Some(EXECUTE_ENTRY_POINT_FELT),
        entry_point_type: Some("EXTERNAL".to_string()),
        calldata: Some(calldata),
        ..Default::default()
    }
}

fn invoke_tx_to_internal_tx(invoke_tx: InvokeTransaction) -> InternalTransaction {
    let mut internal_tx = match invoke_tx {
        InvokeTransaction::V0(invoke_v0_tx) => invoke_tx_v0_to_internal_tx(invoke_v0_tx),
        InvokeTransaction::V1(invoke_v1_tx) => invoke_tx_v1_to_internal_tx(invoke_v1_tx),
        InvokeTransaction::V3(invoke_v3_tx) => invoke_tx_v3_to_internal_tx(invoke_v3_tx),
    };
    internal_tx.r#type = "INVOKE_FUNCTION".into();

    internal_tx
}

fn l1handler_to_internal_tx(input: L1HandlerTransaction) -> InternalTransaction {
    InternalTransaction {
        hash_value: input.transaction_hash,
        version: Some(input.version),
        contract_address: Some(input.contract_address),
        nonce: Some(Felt252::from(input.nonce)),
        entry_point_selector: Some(input.entry_point_selector),
        calldata: Some(input.calldata),
        r#type: "L1_HANDLER".to_string(),
        ..Default::default()
    }
}

fn declare_v0_to_internal_tx(input: DeclareTransactionV0) -> InternalTransaction {
    InternalTransaction {
        hash_value: input.transaction_hash,
        sender_address: Some(input.sender_address),
        max_fee: Some(input.max_fee),
        signature: Some(input.signature.into_iter().map(Felt252::from).collect()),
        class_hash: Some(input.class_hash),
        r#type: "DECLARE".to_string(),
        ..Default::default()
    }
}

fn declare_v1_to_internal_tx(input: DeclareTransactionV1) -> InternalTransaction {
    InternalTransaction {
        hash_value: input.transaction_hash,
        sender_address: Some(input.sender_address),
        max_fee: Some(input.max_fee),
        signature: Some(input.signature.into_iter().map(Felt252::from).collect()),
        nonce: Some(input.nonce),
        class_hash: Some(input.class_hash),
        r#type: "DECLARE".to_string(),
        ..Default::default()
    }
}

fn declare_v2_to_internal_tx(input: DeclareTransactionV2) -> InternalTransaction {
    InternalTransaction {
        hash_value: input.transaction_hash,
        sender_address: Some(input.sender_address),
        compiled_class_hash: Some(input.compiled_class_hash),
        max_fee: Some(input.max_fee),
        signature: Some(input.signature.into_iter().map(Felt252::from).collect()),
        nonce: Some(input.nonce),
        class_hash: Some(input.class_hash),
        r#type: "DECLARE".to_string(),
        ..Default::default()
    }
}

fn declare_v3_to_internal_tx(input: DeclareTransactionV3) -> InternalTransaction {
    InternalTransaction {
        hash_value: input.transaction_hash,
        sender_address: Some(input.sender_address),
        compiled_class_hash: Some(input.compiled_class_hash),
        signature: Some(input.signature.into_iter().map(Felt252::from).collect()),
        nonce: Some(input.nonce),
        class_hash: Some(input.class_hash),
        resource_bounds: Some(resource_bounds_to_api(input.resource_bounds)),
        tip: Some(Felt252::from(input.tip)),
        paymaster_data: Some(input.paymaster_data.into_iter().map(Felt252::from).collect()),
        account_deployment_data: Some(input.account_deployment_data.into_iter().map(Felt252::from).collect()),
        nonce_data_availability_mode: Some(da_to_felt(input.nonce_data_availability_mode)),
        fee_data_availability_mode: Some(da_to_felt(input.fee_data_availability_mode)),
        r#type: "DECLARE".to_string(),
        ..Default::default()
    }
}

fn deploy_account_v1_to_internal_tx(input: DeployAccountTransactionV1) -> InternalTransaction {
    InternalTransaction {
        hash_value: input.transaction_hash,
        max_fee: Some(input.max_fee),
        signature: Some(input.signature.into_iter().map(Felt252::from).collect()),
        nonce: Some(input.nonce),
        contract_address_salt: Some(input.contract_address_salt),
        constructor_calldata: Some(input.constructor_calldata.into_iter().map(Felt252::from).collect()),
        class_hash: Some(input.class_hash),
        r#type: "DEPLOY_ACCOUNT".to_string(),
        ..Default::default()
    }
}

pub fn deploy_account_v3_to_internal_tx(input: DeployAccountTransactionV3) -> InternalTransaction {
    InternalTransaction {
        hash_value: input.transaction_hash,
        signature: Some(input.signature.into_iter().map(Felt252::from).collect()),
        nonce: Some(input.nonce),
        contract_address_salt: Some(input.contract_address_salt),
        constructor_calldata: Some(input.constructor_calldata.into_iter().map(Felt252::from).collect()),
        class_hash: Some(input.class_hash),
        resource_bounds: Some(resource_bounds_to_api(input.resource_bounds)),
        tip: Some(Felt252::from(input.tip)),
        paymaster_data: Some(input.paymaster_data.into_iter().map(Felt252::from).collect()),
        nonce_data_availability_mode: Some(da_to_felt(input.nonce_data_availability_mode)),
        fee_data_availability_mode: Some(da_to_felt(input.fee_data_availability_mode)),
        r#type: "DEPLOY_ACCOUNT".to_string(),
        ..Default::default()
    }
}

pub(crate) fn starknet_rs_tx_to_internal_tx(tx: Transaction) -> InternalTransaction {
    match tx {
        Transaction::Invoke(invoke_tx) => invoke_tx_to_internal_tx(invoke_tx),
        Transaction::L1Handler(l1_handler_tx) => l1handler_to_internal_tx(l1_handler_tx),
        Transaction::Declare(declare_tx) => match declare_tx {
            DeclareTransaction::V0(tx) => declare_v0_to_internal_tx(tx),
            DeclareTransaction::V1(tx) => declare_v1_to_internal_tx(tx),
            DeclareTransaction::V2(tx) => declare_v2_to_internal_tx(tx),
            DeclareTransaction::V3(tx) => declare_v3_to_internal_tx(tx),
        },
        Transaction::Deploy(_deploy_tx) => {
            unimplemented!("we do not plan to support deprecated deploy txs, only deploy_account")
        }
        Transaction::DeployAccount(deploy_account_tx) => match deploy_account_tx {
            DeployAccountTransaction::V1(tx) => deploy_account_v1_to_internal_tx(tx),
            DeployAccountTransaction::V3(tx) => deploy_account_v3_to_internal_tx(tx),
        },
    }
}
