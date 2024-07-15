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
use snos::config::{StarknetGeneralConfig, StarknetOsConfig, STORED_BLOCK_HASH_BUFFER};
use snos::crypto::pedersen::PedersenHash;
use snos::error::SnOsError::Runner;
use snos::execution::helper::{ContractStorageMap, ExecutionHelperWrapper};
use snos::io::input::StarknetOsInput;
use snos::io::InternalTransaction;
use snos::starknet::business_logic::fact_state::contract_class_objects::{get_ffc_for_contract_class_facts, ContractClassLeaf};
use snos::starknet::business_logic::fact_state::contract_state_objects::ContractState;
use snos::starknet::business_logic::fact_state::state::SharedState;
use snos::starknet::starknet_storage::{CommitmentInfo, OsSingleStarknetStorage, StorageLeaf};
use snos::starkware_utils::commitment_tree::base_types::{Height, Length, NodePath, TreeIndex};
use snos::starkware_utils::commitment_tree::binary_fact_tree::BinaryFactTree;
use snos::starkware_utils::commitment_tree::patricia_tree::nodes::{BinaryNodeFact, EdgeNodeFact};
use snos::starkware_utils::commitment_tree::patricia_tree::patricia_tree::PatriciaTree;
use snos::storage::cached_storage::CachedStorage;
use snos::storage::storage::{DbObject, Fact, FactFetchingContext, Storage, StorageError};
use snos::utils::felt_vm2api;
use snos::{config, run_os, storage};
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

    /// RPC endpoint to use for fact fetching
    #[arg(long = "rpc-provider", default_value="http://localhost:9545")]
    rpc_provider: String,
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
    rpc_provider: &String,
    method: &str,
    params: serde_json::Value,
) -> Result<T, reqwest::Error> {
    let request = jsonrpc_request(method, params);
    let response = client.post(format!("{}/rpc/v0_7", rpc_provider.as_str())).json(&request).send().await?;

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
}

// async fn pathfinder_

async fn pathfinder_get_proof(
    client: &reqwest::Client,
    rpc_provider: &String,
    block_number: u64,
    contract_address: Felt,
    keys: &[Felt],
) -> Result<StorageProof, reqwest::Error> {
    post_jsonrpc_request(
        client,
        rpc_provider,
        "pathfinder_getProof",
        json!({ "block_id": { "block_number": block_number }, "contract_address": contract_address, "keys": keys }),
    )
    .await
}

async fn get_storage_proofs(
    client: &reqwest::Client,
    rpc_provider: &String,
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
                .push(pathfinder_get_proof(client, rpc_provider, block_number, contract_address, keys_chunk).await?);
        }
        let storage_proof = merge_chunked_storage_proofs(chunked_storage_proofs);

        storage_proofs.insert(contract_address, storage_proof);
    }

    Ok(storage_proofs)
}

fn merge_chunked_storage_proofs(mut storage_proofs: Vec<StorageProof>) -> StorageProof {
    let class_commitment = storage_proofs[0].class_commitment;
    let contract_proof_nodes: Vec<_> =
        storage_proofs.into_iter().map(|storage_proof| storage_proof.contract_proof).flatten().collect();

    StorageProof { class_commitment, contract_proof: contract_proof_nodes }
}

fn felt_to_u128(felt: &starknet_types_core::felt::Felt) -> u128 {
    let digits = felt.to_be_digits();
    ((digits[2] as u128) << 64) + digits[3] as u128
}

#[derive(Clone)]
struct RpcStorage {
    // provider: JsonRpcClient<HttpTransport>,
    client: reqwest::Client,
    provider: String,
    block_number: u64,
}

impl RpcStorage {
    // pub fn new(provider: JsonRpcClient<HttpTransport>) -> Self {
    pub fn new(
        client: reqwest::Client,
        provider: String,
        block_number: u64,
    ) -> Self {
        Self { client, provider, block_number }
    }
}

type CachedRpcStorage = CachedStorage<RpcStorage>;

impl Storage for RpcStorage {
    async fn set_value(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), StorageError> {
        log::warn!("RpcStorage ignoring attempt to write storage - {:?}: {:?}", key, value);
        Ok(())
    }

    fn get_value(&self, key: &[u8]) -> impl Future<Output = Result<Option<Vec<u8>>, StorageError>> + Send {
        log::info!("RpcStorage get_value, key-len: {}, key: {:?}", key.len(), key);
        async {
            // let response = pathfinder_get_proof(&self.client, &self.provider, self.block_number, contract_address, keys_chunk).await
                // .map_err(|_| StorageError::ContentNotFound);
            Ok(Some(Default::default()))
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

// build state representing the end of the previous block on which the current
// block can be built.
// inspiration: TestSharedState::apply_state_updates_starknet_api()
async fn build_initial_state(
    ffc: FactFetchingContext<CachedRpcStorage, PedersenHash>,
    address_to_class_hash: HashMap<Felt252, Felt252>,
    address_to_nonce: HashMap<Felt252, Felt252>,
    class_hash_to_compiled_class_hash: HashMap<Felt252, Felt252>,
    storage_updates: HashMap<Felt252, HashMap<Felt252, Felt252>>
) -> Result<SharedState<CachedRpcStorage, PedersenHash>, Box<dyn Error>> {
    let shared_state = SharedState::empty(ffc).await?;
    
    let accessed_addresses_felts: HashSet<_> = address_to_class_hash
        .keys()
        .chain(address_to_nonce.keys())
        .chain(storage_updates.keys())
        .collect();
    let accessed_addresses: Vec<TreeIndex> = accessed_addresses_felts.iter().map(|x| x.to_biguint()).collect();

    let mut facts = None;
    let mut ffc = shared_state.ffc;
    let mut current_contract_states: HashMap<TreeIndex, ContractState> =
        shared_state.contract_states.get_leaves(&mut ffc, &accessed_addresses, &mut facts).await?;

    // Update contract storage roots with cached changes.
    let empty_updates = HashMap::new();
    let mut updated_contract_states = HashMap::new();
    for address in accessed_addresses_felts {
        // unwrap() is safe as an entry is guaranteed to be present with `get_leaves()`.
        let tree_index = address.to_biguint();
        let updates = storage_updates.get(address).unwrap_or(&empty_updates);
        let nonce = address_to_nonce.get(address).cloned();
        let class_hash = address_to_class_hash.get(address).cloned();
        let updated_contract_state = current_contract_states
            .remove(&tree_index)
            .unwrap()
            .update(&mut ffc, updates, nonce, class_hash)
            .await?;

        updated_contract_states.insert(tree_index, updated_contract_state);
    }

    // Apply contract changes on global root.
    log::debug!("Updating contract state tree with {} modifications...", accessed_addresses.len());
    let global_state_modifications: Vec<_> = updated_contract_states.into_iter().collect();

    let updated_global_contract_root =
        shared_state.contract_states.update(&mut ffc, global_state_modifications, &mut facts).await?;

    let mut ffc_for_contract_class = get_ffc_for_contract_class_facts(&ffc);

    let updated_contract_classes = match shared_state.contract_classes {
        Some(tree) => {
            log::debug!(
                "Updating contract class tree with {} modifications...",
                class_hash_to_compiled_class_hash.len()
            );
            let modifications: Vec<_> = class_hash_to_compiled_class_hash
                .into_iter()
                .map(|(key, value)| (key.to_biguint(), ContractClassLeaf::create(value)))
                .collect();
            Some(tree.update(&mut ffc_for_contract_class, modifications, &mut facts).await?)
        }
        None => {
            assert_eq!(
                class_hash_to_compiled_class_hash.len(),
                0,
                "contract_classes must be concrete before update."
            );
            None
        }
    };

    // TODO: not needed, we don't need contract_addresses (right?)
    // let accessed_addresses: HashSet<_> = accessed_addresses.into_iter().collect();
    // let contract_addresses: HashSet<_> = self.contract_addresses.union(&accessed_addresses).cloned().collect();

    Ok(SharedState {
        contract_states: updated_global_contract_root,
        contract_classes: updated_contract_classes,
        ffc,
        ffc_for_class_hash: ffc_for_contract_class,
    })
} 

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    init_logging();

    let args = Args::parse();

    let block_number = args.block_number;
    let layout = LayoutName::starknet_with_keccak;

    let provider_url = format!("{}/rpc/v0_7", args.rpc_provider);
    println!("provider url: {}", provider_url);
    let provider = JsonRpcClient::new(HttpTransport::new(Url::parse(provider_url.as_str())
        .expect("Could not parse provider url")));
    let pathfinder_client =
        reqwest::ClientBuilder::new().build().unwrap_or_else(|e| panic!("Could not build reqwest client: {e}"));

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
    let older_block = match provider.get_block_with_txs(BlockId::Number(block_number - STORED_BLOCK_HASH_BUFFER)).await.unwrap() {
        MaybePendingBlockWithTxs::Block(block_with_txs) => block_with_txs,
        MaybePendingBlockWithTxs::PendingBlock(_) => {
            panic!("Block is still pending!");
        }
    };

    let state_update =
        match provider.get_state_update(BlockId::Number(block_number)).await.expect("Failed to get state update") {
            MaybePendingStateUpdate::Update(update) => update,
            MaybePendingStateUpdate::PendingUpdate(_) => {
                panic!("Block is still pending!")
            }
        };

    let storage_proofs = get_storage_proofs(&pathfinder_client, &args.rpc_provider, block_number, &state_update)
        .await
        .expect("Failed to fetch storage proofs");

    let _traces =
        provider.trace_block_transactions(BlockId::Number(block_number)).await.expect("Failed to get block tx traces");

    let block_context = build_block_context(chain_id, &block_with_txs).await.unwrap();

    let old_block_number = Felt252::from(older_block.block_number);
    let old_block_hash = older_block.block_hash;

    // initialize storage. We use a CachedStorage with a RcpStorage as the main storage, meaning
    // that a DictStorage serves as the cache layer and we will use Pathfinder RPC for cache misses
    let rpc_storage = RpcStorage::new(pathfinder_client, provider_url, block_number);
    let cached_storage = CachedRpcStorage::new(Default::default(), rpc_storage);

    // TODO: these maps that we pass in to build_initial_state() are built only on items from the
    // state diff, but we will need all items accessed in any way during the block (right?) which
    // probably means filling in the missing details with API calls
    let address_to_class_hash = state_update
        .state_diff
        .deployed_contracts
        .iter()
        .map(|contract| (contract.address, contract.class_hash))
        .collect();

    let address_to_nonce = state_update
        .state_diff
        .nonces
        .iter()
        .map(|nonce_update| (nonce_update.contract_address, nonce_update.nonce))
        .collect();

    let class_hash_to_compiled_class_hash = state_update
        .state_diff
        .declared_classes
        .iter()
        .map(|class| (class.class_hash, class.compiled_class_hash))
        .collect();

    let storage_updates = state_update
        .state_diff
        .storage_diffs
        .iter()
        .map(|diffs| {
            let storage_entries = diffs.storage_entries.iter().map(|e| (e.key, e.value)).collect();
            (diffs.address, storage_entries)
        })
        .collect();

    let mut initial_state = build_initial_state(
        FactFetchingContext::new(cached_storage),
        address_to_class_hash,
        address_to_nonce,
        class_hash_to_compiled_class_hash,
        storage_updates,
    ).await?;
    
    // write facts from proof
    for (_contract_address, proof) in &storage_proofs {
        for node in &proof.contract_proof {
            match node {
                ContractProofNode::Binary { left, right } => {
                    log::info!("writing binary node...");
                    let fact = BinaryNodeFact::new((*left).into(), (*right).into())?;
                    fact.set_fact(&mut initial_state.ffc).await?;
                },
                ContractProofNode::Edge { child, path } => {
                    log::info!("writing edge node...");
                    let fact = EdgeNodeFact::new((*child).into(), NodePath(path.value.to_biguint()), Length(path.len))?;
                    fact.set_fact(&mut initial_state.ffc).await?;
                },
            }
        }
    }

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

    let previous_tree = &initial_state.contract_states;

    let mut contract_states = HashMap::new();
    let mut contract_storages = ContractStorageMap::new();
    
    let num_storage_diffs = state_update.state_diff.storage_diffs.len();
    let mut updates = Vec::with_capacity(num_storage_diffs);
    for i in 0..num_storage_diffs {
        let storage_diff_item = &state_update.state_diff.storage_diffs[i];
        let storage_proof = &storage_proofs[&storage_diff_item.address];
        let nonce = state_update.state_diff.nonces[i].nonce;

        let contract_address = storage_diff_item.address;
        log::warn!("contract address: {} (nonce: {})", contract_address, nonce);
        let contract_address_biguint = contract_address.to_biguint();

        let address: ContractAddress =
            ContractAddress(PatriciaKey::try_from(felt_vm2api(contract_address)).unwrap());
        let initial_contract_state = initial_state.get_contract_state(address)?;
        let initial_tree = initial_contract_state.storage_commitment_tree.clone();

        let contract_state = initial_contract_state.update(
            &mut initial_state.ffc,
            &storage_diff_item.storage_entries.iter().map(|entry| { (entry.key, entry.value) }).collect(),
            Some(nonce),
            None, // TODO: class hash
        ).await?;
        let updated_tree = contract_state.storage_commitment_tree.clone();

        if storage_proof.class_commitment != contract_state.storage_commitment_tree.root.clone().into() {
            log::error!("expected class_commitment != computed class_commitment ({:?} != {:?})",
                storage_proof.class_commitment,
                contract_state.storage_commitment_tree.root.clone());
        }

        updates.push((contract_address_biguint, contract_state.clone()));
        contract_states.insert(storage_diff_item.address, contract_state);

        let contract_storage = OsSingleStarknetStorage::new(initial_tree, updated_tree, &[], initial_state.ffc.clone()).await?;
        contract_storages.insert(contract_address, contract_storage);
    }
    
    let contract_state_commitment_info = CommitmentInfo::create_from_modifications::<CachedRpcStorage, PedersenHash, ContractState>(
        previous_tree.clone(),
        None, // TODO: do we have a source for expected?
        updates,
        &mut initial_state.ffc,
    ).await?;

    let os_input = StarknetOsInput {
        contract_state_commitment_info,
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
    let execution_helper = ExecutionHelperWrapper::<CachedRpcStorage>::new(
        contract_storages,
        Default::default(), // tx_execution_infos
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
