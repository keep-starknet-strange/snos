use std::error::Error;
use std::sync::Arc;

use blockifier::transaction::account_transaction::AccountTransaction;
use starknet::core::types::{InvokeTransaction, Transaction};
use starknet_api::core::PatriciaKey;
use starknet_api::transaction::TransactionHash;

use crate::utils::felt_vm2api;

pub fn starknet_rs_to_blockifier(
    sn_core_tx: &starknet::core::types::Transaction,
) -> Result<blockifier::transaction::transaction_execution::Transaction, Box<dyn Error>> {
    // Map starknet_api transaction to blockifier's
    let blockifier_tx: AccountTransaction = match sn_core_tx {
        Transaction::Invoke(tx) => {
            let (tx_hash, api_tx) = match tx {
                InvokeTransaction::V0(tx) => {
                    let _tx_hash = TransactionHash(felt_vm2api(tx.transaction_hash));
                    unimplemented!("starknet_rs_to_blockifier with InvokeTransaction::V0");
                }
                InvokeTransaction::V1(tx) => {
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
                    let _tx_hash = TransactionHash(felt_vm2api(tx.transaction_hash));
                    unimplemented!("starknet_rs_to_blockifier with InvokeTransaction::V3");
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
