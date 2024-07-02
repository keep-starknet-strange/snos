mod types;

use std::collections::HashMap;
use std::error::Error;
use std::future::Future;

use async_stream::stream;
use blockifier::block::{BlockInfo, GasPrices};
use blockifier::context::{BlockContext, ChainInfo, FeeTokenAddresses};
use blockifier::versioned_constants::VersionedConstants;
use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::vm::errors::cairo_run_errors::CairoRunError::VmException;
use cairo_vm::Felt252;
use clap::Parser;
use snos::config::{StarknetGeneralConfig, StarknetOsConfig};
use snos::error::SnOsError::Runner;
use snos::execution::helper::ExecutionHelperWrapper;
use snos::io::input::StarknetOsInput;
use snos::io::InternalTransaction;
use snos::starknet::business_logic::fact_state::state::SharedState;
use snos::storage::storage::{Storage, StorageError};
use snos::{config, run_os};
use starknet::core::types::{BlockId, BlockWithTxs, MaybePendingBlockWithTxs};
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider, Url};
use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{ContractAddress, PatriciaKey};
use starknet_api::hash::StarkHash;
use starknet_api::{contract_address, patricia_key};

use crate::types::starknet_rs_tx_to_internal_tx;

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

impl RpcStorage {
    pub fn new(provider: JsonRpcClient<HttpTransport>) -> Self {
        Self { provider }
    }
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
    let sequencer_address_hex = block.sequencer_address.to_hex_string();
    let sequencer_address = contract_address!(sequencer_address_hex.as_str());

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
    let layout = LayoutName::starknet_with_keccak;

    let provider = JsonRpcClient::new(HttpTransport::new(Url::parse("http://localhost:9545/rpc/v0_7").unwrap()));

    // Step 1: build the block context
    let chain_id = provider.chain_id().await?.to_string();
    let block_with_txs = match provider.get_block_with_txs(BlockId::Number(block_number)).await? {
        MaybePendingBlockWithTxs::Block(block_with_txs) => block_with_txs,
        MaybePendingBlockWithTxs::PendingBlock(_) => {
            panic!("Block is still pending!");
        }
    };
    let previous_block = match provider.get_block_with_txs(BlockId::Number(block_number - 1)).await.unwrap() {
        MaybePendingBlockWithTxs::Block(block_with_txs) => block_with_txs,
        MaybePendingBlockWithTxs::PendingBlock(_) => {
            panic!("Block is still pending!");
        }
    };

    let block_context = build_block_context(chain_id, &block_with_txs).await.unwrap();

    let state_update =
        provider.get_state_update(BlockId::Number(block_number)).await.expect("Failed to get state update");
    println!("state update: {:?}", state_update);

    let old_block_number = Felt252::from(previous_block.block_number);
    let old_block_hash = previous_block.block_hash;

    // let ffc = FactFetchingContext::new(RpcStorage::new(provider));
    // let initial_state = build_shared_state(&previous_block, )

    let default_general_config = StarknetGeneralConfig::default();

    let general_config = StarknetGeneralConfig {
        starknet_os_config: StarknetOsConfig {
            chain_id: default_general_config.starknet_os_config.chain_id,
            fee_token_address: block_context.chain_info().fee_token_addresses.strk_fee_token_address,
            deprecated_fee_token_address: block_context.chain_info().fee_token_addresses.eth_fee_token_address,
        },
        ..default_general_config
    };

    let transactions: Vec<_> = block_with_txs.transactions.into_iter().map(starknet_rs_tx_to_internal_tx).collect();

    let os_input = StarknetOsInput {
        contract_state_commitment_info: Default::default(),
        contract_class_commitment_info: Default::default(),
        deprecated_compiled_classes: Default::default(),
        compiled_classes: Default::default(),
        compiled_class_visited_pcs: Default::default(),
        contracts: Default::default(),
        class_hash_to_compiled_class_hash: Default::default(),
        general_config,
        transactions,
        block_hash: block_with_txs.block_hash,
    };
    let execution_helper = ExecutionHelperWrapper::new(
        Default::default(), // tx_execution_infos
        Default::default(), // contract_storage_map
        &block_context,
        (old_block_number, old_block_hash),
    );

    let result = run_os(config::DEFAULT_COMPILED_OS.to_string(), layout, os_input, block_context, execution_helper);

    match &result {
        Err(Runner(VmException(vme))) => {
            if let Some(traceback) = vme.traceback.as_ref() {
                log::error!("traceback:\n{}", traceback);
            }
            if let Some(inst_location) = &vme.inst_location {
                log::error!("died at: {}:{}", inst_location.input_file.filename, inst_location.start_line);
                log::error!("inst_location:\n{:?}", inst_location);
            }
        }
        Err(_) => {
            println!("exception:\n{:#?}", result);
        }
        _ => {}
    }

    result.unwrap();

    Ok(())
}
