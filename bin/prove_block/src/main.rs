use std::error::Error;

use blockifier::block::{BlockInfo, GasPrices};
use blockifier::context::{BlockContext, ChainInfo, FeeTokenAddresses};
use blockifier::versioned_constants::VersionedConstants;
use cairo_vm::types::layout_name::LayoutName;
use clap::Parser;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::json;
use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{ContractAddress, PatriciaKey};
use starknet_api::hash::{StarkFelt, StarkHash};
use starknet_api::{contract_address, patricia_key};

// use snos::{config, run_os};
use crate::types::Block;

mod types;

#[derive(Parser, Debug)]
struct Args {
    /// Block to prove.
    #[arg(long = "block-number")]
    block_number: u64,
}

fn jsonrpc_request(method: &str, params: serde_json::Value) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "id": "0",
        "method": method,
        "params": params,
    })
}

async fn post_jsonrpc_request<T: DeserializeOwned>(
    client: &reqwest::Client,
    method: &str,
    params: serde_json::Value,
) -> Result<T, reqwest::Error> {
    let request = jsonrpc_request(method, params);
    let response = client.post("http://localhost:9545/rpc/v0_7").json(&request).send().await?;

    #[derive(Deserialize)]
    struct TransactionReceiptResponse<T> {
        result: T,
    }
    println!("Response status: {}", response.status());
    let response: TransactionReceiptResponse<T> = response.json().await?;
    Ok(response.result)
}

async fn get_chain_id(client: &reqwest::Client) -> Result<String, reqwest::Error> {
    post_jsonrpc_request(client, "starknet_chainId", json!({})).await
}

async fn get_block_with_txs(client: &reqwest::Client, block_number: u64) -> Result<Block, reqwest::Error> {
    post_jsonrpc_request(client, "starknet_getBlockWithTxs", json!({ "block_id": { "block_number": block_number } }))
        .await
}

async fn get_block_context(client: &reqwest::Client, block_number: u64) -> Result<BlockContext, reqwest::Error> {
    let block = get_block_with_txs(client, block_number).await.unwrap();
    println!("{:?}", block);

    let sequencer_address =
        ContractAddress::try_from(StarkFelt::new(block.sequencer_address.to_be_bytes()).unwrap()).unwrap();

    let block_info = BlockInfo {
        block_number: BlockNumber(block.block_number),
        block_timestamp: BlockTimestamp(block.timestamp),
        sequencer_address,
        gas_prices: GasPrices {
            eth_l1_gas_price: block.l1_gas_price.price_in_wei.0.try_into().unwrap(),
            strk_l1_gas_price: block.l1_gas_price.price_in_fri.0.try_into().unwrap(),
            eth_l1_data_gas_price: block.l1_data_gas_price.price_in_wei.0.try_into().unwrap(),
            strk_l1_data_gas_price: block.l1_data_gas_price.price_in_fri.0.try_into().unwrap(),
        },
        use_kzg_da: false,
    };

    let chain_id = get_chain_id(client).await?;
    let chain_info = ChainInfo {
        chain_id: starknet_api::core::ChainId(chain_id),
        fee_token_addresses: FeeTokenAddresses {
            strk_fee_token_address: contract_address!(
                "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d"
            ),
            eth_fee_token_address: contract_address!(
                "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"
            ),
        },
    };

    let versioned_constants = VersionedConstants::latest_constants();

    Ok(BlockContext::new_unchecked(&block_info, &chain_info, &versioned_constants))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let block_number = args.block_number;
    let _layout = LayoutName::starknet_with_keccak;

    let client =
        reqwest::ClientBuilder::new().build().unwrap_or_else(|e| panic!("Could not build reqwest client: {e}"));

    // Step 1: build the block context
    let _block_context = get_block_context(&client, block_number).await.unwrap();

    // let os =
    //
    // let result = run_os(config::DEFAULT_COMPILED_OS.to_string(), layout, os_input, block_context,
    // execution_helper);

    Ok(())
}
