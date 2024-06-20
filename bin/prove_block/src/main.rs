use std::collections::HashMap;
use std::error::Error;
use std::future::Future;

use async_stream::stream;
use blockifier::block::{BlockInfo, GasPrices};
use blockifier::context::{BlockContext, ChainInfo, FeeTokenAddresses};
use blockifier::versioned_constants::VersionedConstants;
use cairo_vm::types::layout_name::LayoutName;
use clap::Parser;
use snos::storage::storage::{Storage, StorageError};
use starknet::core::types::{BlockId, BlockWithTxs, MaybePendingBlockWithTxHashes, MaybePendingBlockWithTxs};
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider, Url};
use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{ContractAddress, PatriciaKey};
use starknet_api::hash::StarkHash;
use starknet_api::{contract_address, patricia_key};
use snos::starknet::business_logic::fact_state::state::SharedState;

// use snos::{config, run_os};

mod types;

#[derive(Parser, Debug)]
struct Args {
    /// Block to prove.
    #[arg(long = "block-number")]
    block_number: u64,
}

fn felt_to_u128(felt: &starknet_types_core::felt::Felt) -> u128 {
    let digits = felt.to_be_digits();
    ((digits[2] as u128) << 64) + digits[3] as u128
}

struct RpcStorage {
    provider: JsonRpcClient<HttpTransport>,
}

impl Storage for RpcStorage {
    async fn set_value(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), StorageError> {
        log::warn!("Attempting to write storage - {:?}: {:?}", key, value);
        Ok(())
    }

    fn get_value<K: AsRef<[u8]>>(&self, _key: K) -> impl Future<Output = Result<Option<Vec<u8>>, StorageError>> + Send {
        async { todo!() }
    }

    async fn has_key<K: AsRef<[u8]>>(&self, _key: K) -> bool {
        todo!()
    }

    async fn del_value<K: AsRef<[u8]>>(&mut self, key: K) -> Result<(), StorageError> {
        log::warn!("Attempting to delete storage key: {:?}", key.as_ref().to_vec());
        Ok(())
    }

    async fn mset(&mut self, updates: HashMap<Vec<u8>, Vec<u8>>) -> Result<(), StorageError> {
        log::warn!("Attempting to write multiple updates to storage: {:?}", updates);
        Ok(())
    }

    fn mget<K, I>(&self, keys: I) -> impl futures_core::stream::Stream<Item = Result<Option<Vec<u8>>, StorageError>>
    where
        K: AsRef<[u8]>,
        I: Iterator<Item = K>,
    {
        stream! {
            for key in keys {
                yield self.get_value(key).await
            }
        }
    }
}

async fn build_block_context(chain_id: String, block: &BlockWithTxs) -> Result<BlockContext, reqwest::Error> {
    println!("{:?}", block);

    let sequencer_address = contract_address!(block.sequencer_address.to_string().as_str());

    let block_info = BlockInfo {
        block_number: BlockNumber(block.block_number),
        block_timestamp: BlockTimestamp(block.timestamp),
        sequencer_address,
        gas_prices: GasPrices {
            eth_l1_gas_price: felt_to_u128(&block.l1_gas_price.price_in_wei).try_into().unwrap(),
            strk_l1_gas_price: felt_to_u128(&block.l1_gas_price.price_in_fri).try_into().unwrap(),
            eth_l1_data_gas_price: felt_to_u128(&block.l1_data_gas_price.price_in_wei).try_into().unwrap(),
            strk_l1_data_gas_price: felt_to_u128(&block.l1_data_gas_price.price_in_fri).try_into().unwrap(),
        },
        use_kzg_da: false,
    };

    let chain_info = ChainInfo {
        chain_id: starknet_api::core::ChainId(chain_id),
        // cf. https://docs.starknet.io/tools/important-addresses/
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

fn init_logging() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .format_timestamp(None)
        .try_init()
        .expect("Failed to configure env_logger");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    init_logging();

    let args = Args::parse();

    let block_number = args.block_number;
    let _layout = LayoutName::starknet_with_keccak;

    let provider = JsonRpcClient::new(HttpTransport::new(Url::parse("http://localhost:9545/rpc/v0_7").unwrap()));

    // Step 1: build the block context
    let chain_id = provider.chain_id().await?.to_string();
    let block_with_txs = match provider.get_block_with_txs(BlockId::Number(block_number)).await? {
        MaybePendingBlockWithTxs::Block(block_with_txs) => block_with_txs,
        MaybePendingBlockWithTxs::PendingBlock(_) => {
            panic!("Block is still pending!");
        }
    };
    let previous_block = match provider.get_block_with_tx_hashes(BlockId::Number(block_number - 1)).await.unwrap() {
        MaybePendingBlockWithTxHashes::Block(block_with_txs) => block_with_txs,
        MaybePendingBlockWithTxHashes::PendingBlock(_) => {
            panic!("Block is still pending!");
        }
    };

    let _block_context = build_block_context(chain_id, &block_with_txs).await.unwrap();

    let initial_state = SharedState {}

    // let os =
    //
    // let result = run_os(config::DEFAULT_COMPILED_OS.to_string(), layout, os_input, block_context,
    // execution_helper);

    Ok(())
}
