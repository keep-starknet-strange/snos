use blockifier::blockifier::block::GasPrices;
use blockifier::state::cached_state::CachedState;
use blockifier::transaction::transactions::ExecutableTransaction as _;
use blockifier::versioned_constants::StarknetVersion;
use rpc_replay::block_context::build_block_context;
use rpc_replay::rpc_state_reader::AsyncRpcStateReader;
use rpc_replay::transactions::starknet_rs_to_blockifier;
use rstest::rstest;
use starknet::core::types::{BlockId, BlockWithTxs};
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider, Url};
use starknet_api::core::ChainId;

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
    let block_id = BlockId::Number(block_with_txs.block_number - 1);
    let state_reader = AsyncRpcStateReader::new(provider, block_id);
    let mut state = CachedState::from(state_reader);

    let block_context = build_block_context(ChainId::Sepolia, &block_with_txs, StarknetVersion::V0_13_1);

    // Workaround for JsonRpcClient not implementing Clone
    let provider = JsonRpcClient::new(HttpTransport::new(
        Url::parse(provider_url.as_str()).expect("Could not parse provider url"),
    ));

    let traces = provider.trace_block_transactions(block_id).await.expect("Failed to get block tx traces");
    let gas_prices = GasPrices {
        eth_l1_gas_price: 1u128.try_into().unwrap(), // TODO: update with 4844
        strk_l1_gas_price: 1u128.try_into().unwrap(),
        eth_l1_data_gas_price: 1u128.try_into().unwrap(),
        strk_l1_data_gas_price: 1u128.try_into().unwrap(),
    };

    for (tx, trace) in block_with_txs.transactions.iter().zip(traces.iter()) {
        let blockifier_tx =
            starknet_rs_to_blockifier(tx, trace, &gas_prices, &provider, block_with_txs.block_number).await.unwrap();
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
