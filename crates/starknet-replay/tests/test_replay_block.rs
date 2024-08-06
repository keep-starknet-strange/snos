use std::error::Error;
use std::sync::Arc;

use blockifier::state::cached_state::CachedState;
use blockifier::transaction::account_transaction::AccountTransaction;
use blockifier::transaction::transactions::ExecutableTransaction;
use rstest::rstest;
use starknet::core::types::{BlockId, BlockWithTxs, Felt, InvokeTransaction, Transaction};
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Url};
use starknet_api::core::PatriciaKey;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::transaction::TransactionHash;
use starknet_replay::block_context::build_block_context;
use starknet_replay::rpc_state_reader::AsyncRpcStateReader;

pub fn felt_vm2api(felt: Felt) -> StarkFelt {
    stark_felt!(felt.to_hex_string().as_str())
}

pub(crate) fn starknet_rs_to_blockifier(
    sn_core_tx: &starknet::core::types::Transaction,
) -> Result<blockifier::transaction::transaction_execution::Transaction, Box<dyn Error>> {
    // Map starknet_api transaction to blockifier's
    let blockifier_tx: AccountTransaction = match sn_core_tx {
        Transaction::Invoke(tx) => {
            let (tx_hash, api_tx) = match tx {
                InvokeTransaction::V0(tx) => {
                    let _tx_hash = TransactionHash(felt_vm2api(tx.transaction_hash));
                    unimplemented!();
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
                    unimplemented!();
                }
            };
            let invoke =
                blockifier::transaction::transactions::InvokeTransaction { tx: api_tx, tx_hash, only_query: false };
            AccountTransaction::Invoke(invoke)
        }
        Transaction::DeployAccount(_tx) => {
            // let contract_address = calculate_contract_address(
            // tx.contract_address_salt(),
            // tx.class_hash(),
            // &tx.constructor_calldata(),
            // ContractAddress::default(),
            // )
            // .unwrap();
            // AccountTransaction::DeployAccount(DeployAccountTransaction {
            // only_query: false,
            // tx,
            // tx_hash,
            // contract_address,
            // })
            unimplemented!("starknet_rs_tx_to_blockifier() with Deploy txn");
        }
        Transaction::Declare(_tx) => {
            /*
            // Fetch the contract_class from the next block (as we don't have it in the previous one)
            let next_block_state_reader = RpcStateReader(
                RpcState::new_rpc(network, (block_number.next()).unwrap().into()).unwrap(),
            );
            let contract_class = next_block_state_reader
                .get_compiled_contract_class(tx.class_hash())
                .unwrap();
            let class_info = calculate_class_info_for_testing(contract_class);
            let declare = DeclareTransaction::new(tx, tx_hash, class_info).unwrap();
            AccountTransaction::Declare(declare)
            */
            unimplemented!("starknet_rs_tx_to_blockifier() with Declare txn");
        }
        Transaction::L1Handler(_tx) => {
            /*
            // As L1Hanlder is not an account transaction we execute it here and return the result
            let blockifier_tx = L1HandlerTransaction {
                tx,
                tx_hash,
                paid_fee_on_l1: starknet_api::transaction::Fee(u128::MAX),
            };
            return (
                blockifier_tx
                    .execute(&mut state, &block_context, true, true)
                    .unwrap(),
                trace,
                receipt,
            );
            */
            unimplemented!("starknet_rs_tx_to_blockifier() with L1Handler txn");
        }
        _ => unimplemented!(),
    };

    Ok(blockifier::transaction::transaction_execution::Transaction::AccountTransaction(blockifier_tx))
}

#[rstest]
#[ignore = "Requires a local Pathfinder node"]
// We need to use the multi_thread runtime to use task::block_in_place for sync -> async calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_replay_block() {
    let block_fixture = include_bytes!("./block_with_txs.json");

    let block_with_txs: BlockWithTxs = serde_json::from_slice(block_fixture).unwrap();
    println!("block: {block_with_txs:?}");

    let rpc_provider = "http://localhost:9545";
    let provider_url = format!("{}/rpc/v0_7", rpc_provider);
    println!("provider url: {}", provider_url);
    let provider = JsonRpcClient::new(HttpTransport::new(
        Url::parse(provider_url.as_str()).expect("Could not parse provider url"),
    ));
    let state_reader = AsyncRpcStateReader::new(provider, BlockId::Number(block_with_txs.block_number - 1));
    let mut state = CachedState::from(state_reader);

    let block_context = build_block_context("SN_SEPOLIA".to_string(), &block_with_txs);

    for tx in block_with_txs.transactions.iter() {
        let blockifier_tx = starknet_rs_to_blockifier(tx).unwrap();
        let tx_result = blockifier_tx.execute(&mut state, &block_context, true, true);

        match tx_result {
            Err(e) => {
                println!("Transaction failed in blockifier: {}", e);
                panic!("A transaction failed during execution");
            }
            Ok(info) => {
                if info.is_reverted() {
                    println!("Transaction reverted: {:?}", info.revert_error);
                    println!("TransactionExecutionInfo: {:?}", info);
                    panic!("A transaction reverted during execution");
                }
            }
        }
    }
}
