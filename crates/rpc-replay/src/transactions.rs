use std::collections::BTreeMap;
use std::error::Error;
use std::sync::Arc;

use blockifier::blockifier::block::GasPrices;
use blockifier::transaction::account_transaction::AccountTransaction;
use starknet::core::types::{
    Felt, InvokeTransaction, InvokeTransactionV1, InvokeTransactionV3, L1HandlerTransaction, ResourceBoundsMapping,
    Transaction, TransactionTrace, TransactionTraceWithHash,
};
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::JsonRpcClient;
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

fn l1_handler_to_blockifier(
    tx: &L1HandlerTransaction,
    trace: &TransactionTraceWithHash,
    gas_prices: &GasPrices,
) -> Result<blockifier::transaction::transaction_execution::Transaction, StarknetApiError> {
    let tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::L1HandlerTransaction {
        version: starknet_api::transaction::TransactionVersion(tx.version),
        nonce: starknet_api::core::Nonce(Felt::from(tx.nonce)),
        contract_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(tx.contract_address)?),
        entry_point_selector: starknet_api::core::EntryPointSelector(tx.entry_point_selector),
        calldata: starknet_api::transaction::Calldata(Arc::new(tx.calldata.clone())),
    };

    let (l1_gas, l1_data_gas) = match &trace.trace_root {
        TransactionTrace::L1Handler(l1_handler) => (
            l1_handler.execution_resources.data_resources.data_availability.l1_gas,
            l1_handler.execution_resources.data_resources.data_availability.l1_data_gas,
        ),
        _ => unreachable!("Expected L1Handler type for TransactionTrace"),
    };

    let fee = if l1_gas == 0 {
        gas_prices.eth_l1_data_gas_price.get() * l1_data_gas as u128
    } else if l1_data_gas == 0 {
        gas_prices.eth_l1_gas_price.get() * l1_gas as u128
    } else {
        unreachable!("Either l1_gas or l1_data_gas must be zero");
    };

    let paid_fee_on_l1 = Fee(fee);
    let l1_handler =
        blockifier::transaction::transactions::L1HandlerTransaction { tx: api_tx, tx_hash, paid_fee_on_l1 };

    Ok(blockifier::transaction::transaction_execution::Transaction::L1HandlerTransaction(l1_handler))
}

/// Maps starknet-core transactions to Blockifier-compatible types.
pub async fn starknet_rs_to_blockifier(
    sn_core_tx: &starknet::core::types::Transaction,
    trace: &TransactionTraceWithHash,
    gas_prices: &GasPrices,
    _provider: &JsonRpcClient<HttpTransport>,
    _block_number: u64,
) -> Result<blockifier::transaction::transaction_execution::Transaction, Box<dyn Error>> {
    let blockifier_tx = match sn_core_tx {
        Transaction::Invoke(tx) => match tx {
            InvokeTransaction::V0(_) => unimplemented!("starknet_rs_to_blockifier with InvokeTransaction::V0"),
            InvokeTransaction::V1(tx) => invoke_v1_to_blockifier(tx)?,
            InvokeTransaction::V3(tx) => invoke_v3_to_blockifier(tx)?,
        },
        Transaction::L1Handler(tx) => l1_handler_to_blockifier(tx, trace, gas_prices)?,
        Transaction::DeployAccount(_tx) => {
            unimplemented!("starknet_rs_tx_to_blockifier() with Deploy txn");
        }
        Transaction::Declare(_tx) => {
            unimplemented!("starknet_rs_tx_to_blockifier() with Declare txn");
        }
        _ => unimplemented!(),
    };

    Ok(blockifier_tx)
}
