use std::collections::BTreeMap;
use std::error::Error;
use std::sync::Arc;

use blockifier::transaction::account_transaction::AccountTransaction;
use starknet::core::types::{
    InvokeTransaction, InvokeTransactionV1, InvokeTransactionV3, ResourceBoundsMapping, Transaction,
};
use starknet_api::core::PatriciaKey;
use starknet_api::transaction::{Fee, TransactionHash};
use starknet_api::StarknetApiError;

use crate::utils::felt_to_u128;

pub fn resource_bounds_core_to_api(
    resource_bounds: &ResourceBoundsMapping,
) -> starknet_api::transaction::ResourceBoundsMapping {
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

fn da_mode_core_to_api(
    da_mode: starknet::core::types::DataAvailabilityMode,
) -> starknet_api::data_availability::DataAvailabilityMode {
    match da_mode {
        starknet::core::types::DataAvailabilityMode::L1 => starknet_api::data_availability::DataAvailabilityMode::L1,
        starknet::core::types::DataAvailabilityMode::L2 => starknet_api::data_availability::DataAvailabilityMode::L2,
    }
}

fn invoke_v1_to_blockifier(
    tx: &InvokeTransactionV1,
) -> Result<blockifier::transaction::transaction_execution::Transaction, StarknetApiError> {
    let tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::InvokeTransaction::V1(starknet_api::transaction::InvokeTransactionV1 {
        max_fee: Fee(felt_to_u128(&tx.max_fee)),
        signature: starknet_api::transaction::TransactionSignature(tx.signature.to_vec()),
        nonce: starknet_api::core::Nonce(tx.nonce),
        sender_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(tx.sender_address)?),
        calldata: starknet_api::transaction::Calldata(Arc::new(tx.calldata.to_vec())),
    });

    let invoke = blockifier::transaction::transactions::InvokeTransaction { tx: api_tx, tx_hash, only_query: false };
    Ok(blockifier::transaction::transaction_execution::Transaction::AccountTransaction(AccountTransaction::Invoke(
        invoke,
    )))
}

fn invoke_v3_to_blockifier(
    tx: &InvokeTransactionV3,
) -> Result<blockifier::transaction::transaction_execution::Transaction, StarknetApiError> {
    let tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::InvokeTransaction::V3(starknet_api::transaction::InvokeTransactionV3 {
        resource_bounds: resource_bounds_core_to_api(&tx.resource_bounds),
        tip: starknet_api::transaction::Tip(tx.tip),
        signature: starknet_api::transaction::TransactionSignature(tx.signature.to_vec()),
        nonce: starknet_api::core::Nonce(tx.nonce),
        sender_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(tx.sender_address)?),
        calldata: starknet_api::transaction::Calldata(Arc::new(tx.calldata.to_vec())),
        nonce_data_availability_mode: da_mode_core_to_api(tx.nonce_data_availability_mode),
        fee_data_availability_mode: da_mode_core_to_api(tx.fee_data_availability_mode),
        paymaster_data: starknet_api::transaction::PaymasterData(tx.paymaster_data.to_vec()),
        account_deployment_data: starknet_api::transaction::AccountDeploymentData(tx.account_deployment_data.to_vec()),
    });

    let invoke = blockifier::transaction::transactions::InvokeTransaction { tx: api_tx, tx_hash, only_query: false };
    Ok(blockifier::transaction::transaction_execution::Transaction::AccountTransaction(AccountTransaction::Invoke(
        invoke,
    )))
}

/// Maps starknet-core transactions to Blockifier-compatible types.
pub fn starknet_rs_to_blockifier(
    sn_core_tx: &starknet::core::types::Transaction,
) -> Result<blockifier::transaction::transaction_execution::Transaction, Box<dyn Error>> {
    let blockifier_tx = match sn_core_tx {
        Transaction::DeployAccount(_tx) => {
            unimplemented!("starknet_rs_tx_to_blockifier() with Deploy txn");
        }
        Transaction::Declare(_tx) => {
            unimplemented!("starknet_rs_tx_to_blockifier() with Declare txn");
        }
        Transaction::L1Handler(_tx) => {
            unimplemented!("starknet_rs_tx_to_blockifier() with L1Handler txn");
        }
        Transaction::Invoke(tx) => match tx {
            InvokeTransaction::V0(_) => unimplemented!("starknet_rs_to_blockifier with InvokeTransaction::V0"),
            InvokeTransaction::V1(tx) => invoke_v1_to_blockifier(tx)?,
            InvokeTransaction::V3(tx) => invoke_v3_to_blockifier(tx)?,
        },
        _ => unimplemented!(),
    };

    Ok(blockifier_tx)
}
