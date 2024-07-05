use std::collections::{HashMap, HashSet};
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
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::json;
use snos::config::{StarknetGeneralConfig, StarknetOsConfig};
use snos::error::SnOsError::Runner;
use snos::execution::helper::ExecutionHelperWrapper;
use snos::io::input::StarknetOsInput;
use snos::io::InternalTransaction;
use snos::starknet::business_logic::fact_state::contract_state_objects::ContractState;
use snos::starknet::business_logic::fact_state::state::SharedState;
use snos::starkware_utils::commitment_tree::base_types::Height;
use snos::starkware_utils::commitment_tree::patricia_tree::patricia_tree::PatriciaTree;
use snos::storage::storage::{Hash, Storage, StorageError};
use snos::{config, run_os};
use starknet::core::types::{
    BlockId, BlockWithTxs, MaybePendingBlockWithTxs, MaybePendingStateUpdate, StateUpdate, StorageEntry,
};
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider, Url};
use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{ContractAddress, PatriciaKey};
use starknet_api::hash::StarkHash;
use starknet_api::{contract_address, patricia_key};
use starknet_types_core::felt::Felt;

use crate::types::starknet_rs_tx_to_internal_tx;

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
    let response_text = response.text().await?;
    let response: TransactionReceiptResponse<T> =
        serde_json::from_str(&response_text).unwrap_or_else(|_| panic!("Error: {}", response_text));
    Ok(response.result)
}

#[derive(Deserialize)]
struct EdgePath {
    len: u64,
    value: Felt252,
}

#[derive(Deserialize)]
enum ContractProofNode {
    #[serde(rename = "binary")]
    Binary { left: Felt252, right: Felt252 },
    #[serde(rename = "edge")]
    Edge { child: Felt252, path: EdgePath },
}

#[derive(Deserialize)]
struct StorageProof {
    class_commitment: Felt252,
    contract_proof: Vec<ContractProofNode>,
    state_commitment: Felt252,
}

async fn pathfinder_get_proof(
    client: &reqwest::Client,
    block_number: u64,
    contract_address: Felt,
    keys: &[Felt],
) -> Result<StorageProof, reqwest::Error> {
    post_jsonrpc_request(
        client,
        "pathfinder_getProof",
        json!({ "block_id": { "block_number": block_number }, "contract_address": contract_address, "keys": keys }),
    )
    .await
}

async fn get_storage_proofs(
    client: &reqwest::Client,
    block_number: u64,
    state_update: &StateUpdate,
) -> Result<HashMap<Felt, StorageProof>, reqwest::Error> {
    let mut storage_changes_by_contract: HashMap<Felt, Vec<StorageEntry>> = HashMap::new();

    for diff_item in &state_update.state_diff.storage_diffs {
        storage_changes_by_contract.entry(diff_item.address).or_default().extend_from_slice(&diff_item.storage_entries);
    }

    let mut storage_proofs = HashMap::new();

    for (contract_address, storage_changes) in storage_changes_by_contract {
        let keys: Vec<_> = storage_changes.iter().map(|change| change.key).collect();

        // The endpoint is limited to 100 keys at most per call
        let mut chunked_storage_proofs = Vec::new();
        for keys_chunk in keys.chunks(100) {
            chunked_storage_proofs
                .push(pathfinder_get_proof(client, block_number, contract_address, keys_chunk).await?);
        }
        let storage_proof = merge_chunked_storage_proofs(chunked_storage_proofs);

        storage_proofs.insert(contract_address, storage_proof);
    }

    Ok(storage_proofs)
}

fn merge_chunked_storage_proofs(mut storage_proofs: Vec<StorageProof>) -> StorageProof {
    let class_commitment = storage_proofs[0].class_commitment;
    let state_commitment = storage_proofs[0].state_commitment;
    let contract_proof_nodes: Vec<_> =
        storage_proofs.into_iter().map(|storage_proof| storage_proof.contract_proof).flatten().collect();

    StorageProof { class_commitment, contract_proof: contract_proof_nodes, state_commitment }
}

fn build_contract_state(contract_hash: Felt, contract_nonce: Felt, storage_proof: StorageProof) -> ContractState {
    ContractState {
        contract_hash: contract_hash.to_bytes_be().to_vec(),
        storage_commitment_tree: PatriciaTree {
            root: Hash::from_bytes_be(storage_proof.state_commitment.to_bytes_be()),
            height: Height(251),
        },
        nonce: contract_nonce,
    }
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

    async fn get_value(&self, _key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        todo!()
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

async fn get_nonce(provider: &JsonRpcClient<HttpTransport>, block_id: BlockId, contract_address: Felt) -> Felt {
    if [Felt::ZERO, Felt::ONE].contains(&contract_address) {
        return Felt::ZERO;
    }

    provider
        .get_nonce(block_id, contract_address)
        .await
        .unwrap_or_else(|e| panic!("Failed to get nonce for contract {}: {}", contract_address.to_hex_string(), e))
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
    let block_id = BlockId::Number(block_number);
    let layout = LayoutName::starknet_with_keccak;

    let provider = JsonRpcClient::new(HttpTransport::new(Url::parse("http://localhost:9545/rpc/v0_7").unwrap()));
    let pathfinder_client =
        reqwest::ClientBuilder::new().build().unwrap_or_else(|e| panic!("Could not build reqwest client: {e}"));

    // Step 1: build the block context
    let chain_id = provider.chain_id().await?.to_string();
    let block_with_txs = match provider.get_block_with_txs(block_id).await? {
        MaybePendingBlockWithTxs::Block(block_with_txs) => block_with_txs,
        MaybePendingBlockWithTxs::PendingBlock(_) => {
            panic!("Block is still pending!");
        }
    };
    let previous_block = match provider.get_block_with_txs(BlockId::Number(block_number - 10)).await.unwrap() {
        MaybePendingBlockWithTxs::Block(block_with_txs) => block_with_txs,
        MaybePendingBlockWithTxs::PendingBlock(_) => {
            panic!("Block is still pending!");
        }
    };

    let state_update = match provider.get_state_update(block_id).await.expect("Failed to get state update") {
        MaybePendingStateUpdate::Update(update) => update,
        MaybePendingStateUpdate::PendingUpdate(_) => {
            panic!("Block is still pending!")
        }
    };

    let storage_proofs = get_storage_proofs(&pathfinder_client, block_number, &state_update)
        .await
        .expect("Failed to fetch storage proofs");

    let nonce_updates: HashMap<_, _> = state_update
        .state_diff
        .nonces
        .iter()
        .map(|nonce_update| (nonce_update.contract_address, nonce_update.nonce))
        .collect();

    let mut contract_states = HashMap::new();
    for (contract_address, storage_proof) in storage_proofs {
        println!("Adding contract: {}", contract_address.to_hex_string());
        let nonce = get_nonce(&provider, block_id, contract_address).await;
        let class_hash = if contract_address == Felt::ONE {
            Felt::ZERO
        } else {
            provider.get_class_hash_at(block_id, contract_address).await?
        };
        contract_states.insert(contract_address, build_contract_state(class_hash, nonce, storage_proof));
    }

    let _traces =
        provider.trace_block_transactions(BlockId::Number(block_number)).await.expect("Failed to get block tx traces");

    let block_context = build_block_context(chain_id, &block_with_txs).await.unwrap();

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
        contracts: contract_states,
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
