use std::collections::BTreeMap;
use std::error::Error;
use std::sync::Arc;

use blockifier::transaction::account_transaction::AccountTransaction;
use cairo_lang_starknet_classes::contract_class::ContractEntryPoints;
use cairo_lang_utils::bigint::BigUintAsHex;
use cairo_vm::Felt252;
use starknet::core::types::{
    DataAvailabilityMode, InvokeTransaction, InvokeTransactionV0, InvokeTransactionV1, InvokeTransactionV3,
    ResourceBoundsMapping, Transaction,
};
use starknet_api::core::PatriciaKey;
use starknet_api::transaction::TransactionHash;
use starknet_os::io::InternalTransaction;
use starknet_os::utils::felt_vm2api;
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

pub(crate) fn starknet_rs_tx_to_internal_tx(tx: Transaction) -> InternalTransaction {
    match tx {
        Transaction::Invoke(invoke_tx) => invoke_tx_to_internal_tx(invoke_tx),
        Transaction::L1Handler(_l1_handler_tx) => {
            todo!()
        }
        Transaction::Declare(_declare_tx) => {
            todo!()
        }
        Transaction::Deploy(_deploy_tx) => {
            unimplemented!("we do not plan to support deprecated deploy txs, only deploy_account")
        }
        Transaction::DeployAccount(_deploy_account_tx) => {
            todo!()
        }
    }
}

pub(crate) fn starknet_rs_to_blockifier(
    sn_core_tx: &starknet::core::types::Transaction,
) -> Result<blockifier::transaction::transaction_execution::Transaction, Box<dyn Error>> {
    // Map starknet_api transaction to blockifier's
    let blockifier_tx: AccountTransaction = match sn_core_tx {
        Transaction::Invoke(tx) => {
            let (tx_hash, api_tx) = match tx {
                InvokeTransaction::V0(tx) => {
                    log::warn!("v0");
                    let _tx_hash = TransactionHash(felt_vm2api(tx.transaction_hash));
                    unimplemented!();
                }
                InvokeTransaction::V1(tx) => {
                    log::warn!("v1, nonce: {}", tx.nonce);
                    let tx_hash = TransactionHash(felt_vm2api(tx.transaction_hash));
                    let api_tx = starknet_api::transaction::InvokeTransaction::V1(
                        starknet_api::transaction::InvokeTransactionV1 {
                            max_fee: starknet_api::transaction::Fee(tx.max_fee.to_biguint().try_into()?),
                            signature: starknet_api::transaction::TransactionSignature(
                                tx.signature.clone().into_iter().map(felt_vm2api).collect(),
                            ),
                            nonce: starknet_api::core::Nonce(felt_vm2api(tx.nonce)),
                            sender_address: starknet_api::core::ContractAddress(
                                PatriciaKey::try_from(felt_vm2api(tx.sender_address)).unwrap(),
                            ),
                            calldata: starknet_api::transaction::Calldata(Arc::new(
                                tx.calldata.clone().into_iter().map(felt_vm2api).collect(),
                            )),
                        },
                    );
                    (tx_hash, api_tx)
                }
                InvokeTransaction::V3(tx) => {
                    log::warn!("v3");
                    let _tx_hash = TransactionHash(felt_vm2api(tx.transaction_hash));
                    unimplemented!();
                }
            };
            let invoke =
                blockifier::transaction::transactions::InvokeTransaction { tx: api_tx, tx_hash, only_query: false };
            AccountTransaction::Invoke(invoke)
        }
        Transaction::DeployAccount(_tx) => {
            unimplemented!("starknet_rs_tx_to_blockifier() with Deploy txn");
        }
        Transaction::Declare(_tx) => {
            unimplemented!("starknet_rs_tx_to_blockifier() with Declare txn");
        }
        Transaction::L1Handler(_tx) => {
            unimplemented!("starknet_rs_tx_to_blockifier() with L1Handler txn");
        }
        _ => unimplemented!(),
    };

    Ok(blockifier::transaction::transaction_execution::Transaction::AccountTransaction(blockifier_tx))
}

#[derive(Debug, serde::Deserialize)]
pub struct MiddleSierraContractClass {
    pub sierra_program: Vec<BigUintAsHex>,
    pub contract_class_version: String,
    pub entry_points_by_type: ContractEntryPoints,
}
