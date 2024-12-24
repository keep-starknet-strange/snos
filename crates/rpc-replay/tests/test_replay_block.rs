use std::env;

use blockifier::blockifier::block::GasPrices;
use blockifier::state::cached_state::CachedState;
use blockifier::transaction::objects::FeeType;
use blockifier::transaction::transactions::ExecutableTransaction as _;
use blockifier::versioned_constants::StarknetVersion;
use rpc_client::RpcClient;
use rpc_replay::block_context::build_block_context;
use rpc_replay::rpc_state_reader::AsyncRpcStateReader;
use rpc_replay::transactions::starknet_rs_to_blockifier;
use rstest::rstest;
use serial_test::serial;
use starknet::core::types::{BlockId, BlockWithTxs};
use starknet::providers::Provider;
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
    let rpc_client = RpcClient::new(rpc_provider);
    let previous_block_number = block_with_txs.block_number - 1;
    let previous_block_id = BlockId::Number(previous_block_number);
    let state_reader = AsyncRpcStateReader::new(rpc_client.clone(), previous_block_id);
    let mut state = CachedState::from(state_reader);

    let block_context = build_block_context(ChainId::Sepolia, &block_with_txs, StarknetVersion::V0_13_1)
        .expect("Failed to build block context");

    let traces = rpc_client
        .starknet_rpc()
        .trace_block_transactions(previous_block_id)
        .await
        .expect("Failed to get block tx traces");
    let gas_prices = GasPrices {
        eth_l1_gas_price: 1u128.try_into().unwrap(),
        strk_l1_gas_price: 1u128.try_into().unwrap(),
        eth_l1_data_gas_price: 1u128.try_into().unwrap(),
        strk_l1_data_gas_price: 1u128.try_into().unwrap(),
    };

    for (tx, trace) in block_with_txs.transactions.iter().zip(traces.iter()) {
        let blockifier_tx =
            starknet_rs_to_blockifier(tx, trace, &gas_prices, &rpc_client, previous_block_number).await.unwrap();
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

#[rstest]
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
// wrong values:  https://docs.starknet.io/tools/important-addresses/
#[case(
    "0x0782f0ddca11d9950bc3220e35ac82cf868778edb67a5e58b39838544bc4cd0f",
    "0x035c332b8de00874e702b4831c84b22281fb3246f714475496d74e644f35d492"
)]
async fn test_build_block_context_with_wrong_env_fails(
    #[case] strk_token_address: String,
    #[case] eth_token_address: String,
) {
    let strk_token_key = "SNOS_STRK_FEE_TOKEN_ADDRESS";
    env::set_var(strk_token_key, &strk_token_address);

    let eth_token_key = "SNOS_ETH_FEE_TOKEN_ADDRESS";
    env::set_var(eth_token_key, &eth_token_address);

    let block_fixture = include_bytes!("./block_with_txs.json");
    let block_with_txs: BlockWithTxs = serde_json::from_slice(block_fixture).unwrap();
    let block_context = build_block_context(ChainId::Sepolia, &block_with_txs, StarknetVersion::V0_13_1)
        .expect("Failed to build block context");

    let strk_token_contract_address = block_context.chain_info().fee_token_address(&FeeType::Strk).to_string();
    let eth_token_contract_address = block_context.chain_info().fee_token_address(&FeeType::Eth).to_string();

    let correct_strk_token_address = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
    let correct_eth_token_address = "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7";

    assert_ne!(correct_strk_token_address, strk_token_contract_address);
    assert_ne!(correct_eth_token_address, eth_token_contract_address);

    env::remove_var(strk_token_key);
    env::remove_var(eth_token_key);
}

#[rstest]
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
// correct values:  https://docs.starknet.io/tools/important-addresses/
async fn test_build_block_context_with_default_env_works() {
    let strk_token_key = "SNOS_STRK_FEE_TOKEN_ADDRESS";
    let strk_token_address = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
    env::remove_var(strk_token_key);

    let eth_token_key = "SNOS_ETH_FEE_TOKEN_ADDRESS";
    let eth_token_address = "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7";
    env::remove_var(eth_token_key);

    let block_fixture = include_bytes!("./block_with_txs.json");
    let block_with_txs: BlockWithTxs = serde_json::from_slice(block_fixture).unwrap();
    let block_context = build_block_context(ChainId::Sepolia, &block_with_txs, StarknetVersion::V0_13_1)
        .expect("Failed to build block context");

    let strk_token_contract_address = block_context.chain_info().fee_token_address(&FeeType::Strk).to_string();
    let eth_token_contract_address = block_context.chain_info().fee_token_address(&FeeType::Eth).to_string();

    assert_eq!(strk_token_address, strk_token_contract_address);
    assert_eq!(eth_token_address, eth_token_contract_address);
}
