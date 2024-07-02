use std::collections::BTreeMap;

use cairo_vm::Felt252;
use snos::io::InternalTransaction;
use starknet::core::types::{
    DataAvailabilityMode, InvokeTransaction, InvokeTransactionV0, InvokeTransactionV1, InvokeTransactionV3,
    ResourceBoundsMapping, Transaction,
};
use starknet_types_core::felt::Felt;

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
        ..Default::default()
    }
}
fn invoke_tx_v1_to_internal_tx(tx: InvokeTransactionV1) -> InternalTransaction {
    let signature: Vec<_> = tx.signature.into_iter().map(felt_to_vm).collect();
    let calldata: Vec<_> = tx.calldata.into_iter().map(felt_to_vm).collect();

    InternalTransaction {
        hash_value: felt_to_vm(tx.transaction_hash),
        sender_address: Some(felt_to_vm(tx.sender_address)),
        calldata: Some(calldata),
        max_fee: Some(felt_to_vm(tx.max_fee)),
        signature: Some(signature),
        nonce: Some(felt_to_vm(tx.nonce)),
        ..Default::default()
    }
}

fn invoke_tx_v3_to_internal_tx(tx: InvokeTransactionV3) -> InternalTransaction {
    //     /// Transaction hash
    //     pub transaction_hash: Felt,
    //     /// Sender address
    //     pub sender_address: Felt,
    //     /// The data expected by the account's `execute` function (in most usecases, this includes
    // the     /// called contract address and a function selector)
    //     pub calldata: Vec<Felt>,
    //     /// Signature
    //     pub signature: Vec<Felt>,
    //     /// Nonce
    //     pub nonce: Felt,
    //     /// Resource bounds for the transaction execution
    //     pub resource_bounds: ResourceBoundsMapping,
    //     /// The tip for the transaction
    //     pub tip: u64,
    //     /// Data needed to allow the paymaster to pay for the transaction in native tokens
    //     pub paymaster_data: Vec<Felt>,
    //     /// Data needed to deploy the account contract from which this tx will be initiated
    //     pub account_deployment_data: Vec<Felt>,
    //     /// The storage domain of the account's nonce (an account has a nonce per da mode)
    //     pub nonce_data_availability_mode: DataAvailabilityMode,
    //     /// The storage domain of the account's balance from which fee will be charged
    //     pub fee_data_availability_mode: DataAvailabilityMode,

    let signature: Vec<_> = tx.signature.into_iter().map(felt_to_vm).collect();
    let calldata: Vec<_> = tx.calldata.into_iter().map(felt_to_vm).collect();
    let paymaster_data: Vec<_> = tx.paymaster_data.into_iter().map(felt_to_vm).collect();
    let account_deployment_data: Vec<_> = tx.account_deployment_data.into_iter().map(felt_to_vm).collect();

    InternalTransaction {
        hash_value: felt_to_vm(tx.transaction_hash),
        sender_address: Some(felt_to_vm(tx.sender_address)),
        calldata: Some(calldata),
        signature: Some(signature),
        nonce: Some(felt_to_vm(tx.nonce)),
        resource_bounds: Some(resource_bounds_to_api(tx.resource_bounds)),
        tip: Some(Felt252::from(tx.tip)),
        paymaster_data: Some(paymaster_data),
        account_deployment_data: Some(account_deployment_data),
        nonce_data_availability_mode: Some(da_to_felt(tx.nonce_data_availability_mode)),
        fee_data_availability_mode: Some(da_to_felt(tx.fee_data_availability_mode)),
        ..Default::default()
    }
}

fn invoke_tx_to_internal_tx(invoke_tx: InvokeTransaction) -> InternalTransaction {
    match invoke_tx {
        InvokeTransaction::V0(invoke_v0_tx) => invoke_tx_v0_to_internal_tx(invoke_v0_tx),
        InvokeTransaction::V1(invoke_v1_tx) => invoke_tx_v1_to_internal_tx(invoke_v1_tx),
        InvokeTransaction::V3(invoke_v3_tx) => invoke_tx_v3_to_internal_tx(invoke_v3_tx),
    }
}

pub(crate) fn starknet_rs_tx_to_internal_tx(tx: Transaction) -> InternalTransaction {
    match tx {
        Transaction::Invoke(invoke_tx) => invoke_tx_to_internal_tx(invoke_tx),
        Transaction::L1Handler(l1_handler_tx) => {
            todo!()
        }
        Transaction::Declare(declare_tx) => {
            todo!()
        }
        Transaction::Deploy(_deploy_tx) => {
            unimplemented!("we do not plan to support deprecated deploy txs, only deploy_account")
        }
        Transaction::DeployAccount(deploy_account_tx) => {
            todo!()
        }
    }
}
