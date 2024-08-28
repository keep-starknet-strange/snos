use std::collections::BTreeMap;
use std::error::Error;
use std::sync::Arc;

use blockifier::transaction::account_transaction::AccountTransaction;
use starknet::core::types::{InvokeTransaction, ResourceBoundsMapping, Transaction};
use starknet_api::core::PatriciaKey;
use starknet_api::transaction::TransactionHash;

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

/// Maps starknet-core transactions to Blockifier-compatible types.
pub fn starknet_rs_to_blockifier(
    sn_core_tx: &starknet::core::types::Transaction,
) -> Result<blockifier::transaction::transaction_execution::Transaction, Box<dyn Error>> {
    let blockifier_tx: AccountTransaction = match sn_core_tx {
        Transaction::Invoke(tx) => {
            let (tx_hash, api_tx) = match tx {
                InvokeTransaction::V0(tx) => {
                    let _tx_hash = TransactionHash(tx.transaction_hash);
                    unimplemented!("starknet_rs_to_blockifier with InvokeTransaction::V0");
                }
                InvokeTransaction::V1(tx) => {
                    let tx_hash = TransactionHash(tx.transaction_hash);
                    let api_tx = starknet_api::transaction::InvokeTransaction::V1(
                        starknet_api::transaction::InvokeTransactionV1 {
                            max_fee: starknet_api::transaction::Fee(tx.max_fee.to_biguint().try_into()?),
                            signature: starknet_api::transaction::TransactionSignature(
                                tx.signature.clone().into_iter().collect(),
                            ),
                            nonce: starknet_api::core::Nonce(tx.nonce),
                            sender_address: starknet_api::core::ContractAddress(
                                PatriciaKey::try_from(tx.sender_address).unwrap(),
                            ),
                            calldata: starknet_api::transaction::Calldata(Arc::new(
                                tx.calldata.clone().into_iter().collect(),
                            )),
                        },
                    );
                    (tx_hash, api_tx)
                }
                InvokeTransaction::V3(tx) => {
                    let tx_hash = TransactionHash(tx.transaction_hash);
                    let api_tx = starknet_api::transaction::InvokeTransaction::V3(
                        starknet_api::transaction::InvokeTransactionV3 {
                            resource_bounds: resource_bounds_core_to_api(&tx.resource_bounds),
                            tip: starknet_api::transaction::Tip(tx.tip),
                            signature: starknet_api::transaction::TransactionSignature(
                                tx.signature.to_vec(),
                            ),
                            nonce: starknet_api::core::Nonce(tx.nonce),
                            sender_address: starknet_api::core::ContractAddress(
                                PatriciaKey::try_from(tx.sender_address).unwrap(),
                            ),
                            calldata: starknet_api::transaction::Calldata(Arc::new(
                                tx.calldata.to_vec(),
                            )),
                            nonce_data_availability_mode: da_mode_core_to_api(tx.nonce_data_availability_mode),
                            fee_data_availability_mode: da_mode_core_to_api(tx.fee_data_availability_mode),
                            paymaster_data: starknet_api::transaction::PaymasterData(
                                tx.paymaster_data.to_vec(),
                            ),
                            account_deployment_data: starknet_api::transaction::AccountDeploymentData(
                                tx.account_deployment_data.to_vec(),
                            ),
                        },
                    );
                    (tx_hash, api_tx)
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
