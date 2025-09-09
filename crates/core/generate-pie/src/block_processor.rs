use crate::api_to_blockifier_conversion::starknet_rs_to_blockifier;
use crate::commitment_utils::{compute_class_commitment, format_commitment_facts};
use crate::context_builder::{build_block_context, chain_id_from_felt};
use crate::error::BlockProcessingError;
use crate::rpc_utils::{get_accessed_keys_with_block_hash, get_class_proofs, get_storage_proofs};
use crate::state_update::{get_formatted_state_update, get_subcalled_contracts_from_tx_traces};
use blockifier::blockifier::config::TransactionExecutorConfig;
use blockifier::blockifier::transaction_executor::{TransactionExecutor, TransactionExecutorError};
use blockifier::state::cached_state::CachedState;
use blockifier::test_utils::maybe_dummy_block_hash_and_number;
use blockifier::transaction::objects::TransactionExecutionInfo;
use cairo_lang_starknet_classes::casm_contract_class::CasmContractClass;
use cairo_vm::Felt252;
use rpc_client::pathfinder::types::{PathfinderProof, PedersenHash};
use rpc_client::state_reader::AsyncRpcStateReader;
use rpc_client::RpcClient;
use serde::Serialize;
use shared_execution_objects::central_objects::CentralTransactionExecutionInfo;
use starknet::core::types::{BlockId, MaybePendingBlockWithTxHashes, MaybePendingBlockWithTxs};
use starknet::providers::Provider;
use starknet_api::block::{BlockHash, BlockNumber, StarknetVersion};
use starknet_api::core::{ClassHash, ContractAddress};
use starknet_api::deprecated_contract_class::ContractClass;
use starknet_api::state::StorageKey;
use starknet_os::io::os_input::{CommitmentInfo, ContractClassComponentHashes, OsBlockInput};
use starknet_patricia::hash::hash_trait::HashOutput;
use starknet_patricia::patricia_merkle_tree::types::SubTreeHeight;
use starknet_types_core::felt::Felt;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// Result type for block processing operations.
pub type BlockProcessingResult = Result<BlockInfoResult, BlockProcessingError>;

/// Result containing all the information collected from a single block.
#[derive(Debug)]
pub struct BlockInfoResult {
    /// The OS block input for the block.
    pub os_block_input: OsBlockInput,
    /// Compiled classes used in the block.
    pub compiled_classes: BTreeMap<ClassHash, CasmContractClass>,
    /// Deprecated compiled classes used in the block.
    pub deprecated_compiled_classes: BTreeMap<ClassHash, ContractClass>,
    /// Addresses accessed during block execution.
    pub accessed_addresses: HashSet<ContractAddress>,
    /// Class hashes accessed during block execution.
    pub accessed_classes: HashSet<ClassHash>,
    /// Storage keys accessed by each contract address.
    pub accessed_keys_by_address: HashMap<ContractAddress, HashSet<StorageKey>>,
    /// The previous block ID (if any).
    pub previous_block_id: Option<BlockId>,
}

/// Generic function to serialize any serializable object and write it to a file
///
/// # Arguments
/// * `object` - Any object that implements the Serialize trait
/// * `file_path` - Path where the file should be written
/// * `format` - Optional format specification ("json", "yaml", etc.). Defaults to JSON.
///
/// # Returns
/// * `Result<(), Box<dyn std::error::Error>>` - Ok(()) on success, error on failure
///
/// # Examples
/// ```
/// let data = vec![1, 2, 3, 4, 5];
/// write_serializable_to_file(&data, "output/numbers.json", Some("json"))?;
///
/// let traces = get_transaction_traces();
/// write_serializable_to_file(&traces, "debug/traces.json", None)?;
/// ```
pub fn write_serializable_to_file<T>(
    object: &T,
    file_path: &str,
    format: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>>
where
    T: Serialize,
{
    // Create directory if it doesn't exist
    if let Some(parent) = Path::new(file_path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = File::create(file_path)?;

    match format.unwrap_or("json") {
        "json" => {
            let json_string = serde_json::to_string_pretty(object)?;
            file.write_all(json_string.as_bytes())?;
        }
        "json-compact" => {
            let json_string = serde_json::to_string(object)?;
            file.write_all(json_string.as_bytes())?;
        }
        #[cfg(feature = "yaml")]
        "yaml" => {
            let yaml_string = serde_yaml::to_string(object)?;
            file.write_all(yaml_string.as_bytes())?;
        }
        _ => {
            return Err(format!("Unsupported format: {}", format.unwrap_or("json")).into());
        }
    }

    file.flush()?;
    log::info!("Successfully wrote serialized data to: {}", file_path);
    Ok(())
}

pub const STORED_BLOCK_HASH_BUFFER: u64 = 10;
const STATEFUL_MAPPING_START: Felt = Felt::from_hex_unchecked("0x80"); // 128

/// Helper function to populate accessed_keys_by_address with special address 0x2
/// based on accessed addresses, classes, and current storage mapping.
///
/// According to the storage mapping rules:
/// - Storage keys that require at most 127 bits and addresses of system contracts (0x1 and 0x2)
///   are not mapped and continue to be referred to directly
/// - We ignore values < 128 and address 0x1
/// - Keys are added to address 0x2 from contracts, classes, and existing storage keys
fn populate_alias_contract_keys(
    accessed_addresses: &HashSet<ContractAddress>,
    accessed_classes: &HashSet<ClassHash>,
    accessed_keys_by_address: &mut HashMap<ContractAddress, HashSet<StorageKey>>,
) {
    // Special address 0x2 for alias contract
    let alias_contract_address = ContractAddress::try_from(Felt::TWO).expect("0x2 should be a valid contract address");

    let mut alias_keys = HashSet::new();

    // Process accessed contract addresses
    for contract_address in accessed_addresses {
        let address_felt: Felt = (*contract_address).into();

        // Skip address 0x1 (system contract)
        if address_felt == Felt::ONE || address_felt == Felt::TWO {
            continue;
        }

        // Only add if value >= 128 (requires stateful mapping)
        if address_felt >= STATEFUL_MAPPING_START {
            if let Ok(storage_key) = StorageKey::try_from(address_felt) {
                alias_keys.insert(storage_key);
            }
        }
    }

    // Process accessed class hashes
    for class_hash in accessed_classes {
        let class_hash_felt: Felt = class_hash.0;

        // Skip if it's address 0x1
        if class_hash_felt == Felt::ONE {
            continue;
        }

        // Only add if value >= 128 (requires stateful mapping)
        if class_hash_felt >= STATEFUL_MAPPING_START {
            if let Ok(storage_key) = StorageKey::try_from(class_hash_felt) {
                alias_keys.insert(storage_key);
            }
        }
    }

    // Process existing storage keys from all contracts
    for (contract_addr, storage_keys) in accessed_keys_by_address.iter() {
        for storage_key in storage_keys {
            let contract_felt: Felt = (*(contract_addr)).into();

            // Skip if it's address 0x1
            if contract_felt == Felt::ONE || contract_felt == Felt::TWO {
                continue;
            }

            let key_felt: Felt = (*storage_key).into();

            // Only add if value >= 128 (requires stateful mapping)
            if key_felt >= STATEFUL_MAPPING_START {
                alias_keys.insert(*storage_key);
            }
            if contract_felt >= STATEFUL_MAPPING_START {
                alias_keys.insert(*storage_key);
            }
        }
    }

    // Add all qualifying keys to the alias contract (address 0x2)
    if !alias_keys.is_empty() {
        accessed_keys_by_address.entry(alias_contract_address).or_default().extend(alias_keys);

        log::info!(
            "Added {} keys to alias contract (0x2) for storage mapping",
            accessed_keys_by_address.get(&alias_contract_address).unwrap().len()
        );
    }
}

/// Collects all necessary information from a single block for PIE generation.
///
/// This function processes a single block and extracts all the information needed
/// to generate a Cairo PIE, including transaction execution, state updates, proofs,
/// and contract classes.
///
/// # Arguments
///
/// * `block_number` - The block number to process
/// * `is_l3` - Whether this is an L3 chain (true) or L2 chain (false)
/// * `rpc_client` - The RPC client for fetching block data
///
/// # Returns
///
/// Returns a `BlockProcessingResult` containing all the collected block information,
/// or an error if any step of the processing fails.
///
/// # Errors
///
/// This function can return various errors including:
/// - `BlockProcessingError::RpcClient` for RPC communication errors
/// - `BlockProcessingError::TransactionExecution` for transaction execution errors
/// - `BlockProcessingError::StateUpdateProcessing` for state update processing errors
/// - `BlockProcessingError::StorageProof` for storage proof errors
/// - `BlockProcessingError::ClassProof` for class proof errors
/// - `BlockProcessingError::ContractClassConversion` for contract class conversion errors
///
/// # Example
///
/// ```rust
/// use generate_pie::block_processor::collect_single_block_info;
/// use rpc_client::RpcClient;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let rpc_client = RpcClient::try_new("https://your-starknet-node.com")?;
///     let result = collect_single_block_info(12345, false, rpc_client).await?;
///     println!("Processed block with {} transactions", result.os_block_input.transactions.len());
///     Ok(())
/// }
/// ```
pub async fn collect_single_block_info(block_number: u64, is_l3: bool, rpc_client: RpcClient) -> BlockProcessingResult {
    log::info!("Starting block info collection for block {}", block_number);
    let block_id = BlockId::Number(block_number);
    let previous_block_id = if block_number == 0 { None } else { Some(BlockId::Number(block_number - 1)) };
    log::info!(
        "Block IDs configured: current={}, previous={:?}",
        block_number,
        previous_block_id.map(|id| format!("{:?}", id)).unwrap_or("None".to_string())
    );

    // Step 1: build the block context
    log::info!("Getting chain ID");
    let res = rpc_client.starknet_rpc().chain_id().await.map_err(|e| BlockProcessingError::RpcClient(Box::new(e)))?;
    log::debug!("Chain ID response: {:?}", res);
    let chain_id = chain_id_from_felt(res);
    log::debug!("Provider's chain_id: {}", chain_id);
    log::info!("Chain ID retrieved: {}", chain_id);

    log::info!("Step 2: Fetching block with transactions...");
    let block_with_txs = match rpc_client
        .starknet_rpc()
        .get_block_with_txs(block_id)
        .await
        .map_err(|e| BlockProcessingError::RpcClient(Box::new(e)))?
    {
        MaybePendingBlockWithTxs::Block(block_with_txs) => block_with_txs,
        MaybePendingBlockWithTxs::PendingBlock(_) => {
            return Err(BlockProcessingError::InvalidBlockState("Block is still pending".to_string()));
        }
    };
    log::info!("Successfully fetched block with {} transactions", block_with_txs.transactions.len());

    let starknet_version = StarknetVersion::V0_14_0; // TODO: get it from the txns itself
    log::info!("Starknet version set to: {:?}", starknet_version);

    log::info!("Step 3: Fetching previous block...");
    let previous_block = match previous_block_id {
        Some(previous_block_id) => match rpc_client
            .starknet_rpc()
            .get_block_with_tx_hashes(previous_block_id)
            .await
            .map_err(|e| BlockProcessingError::RpcClient(Box::new(e)))?
        {
            MaybePendingBlockWithTxHashes::Block(block_with_txs) => Some(block_with_txs),
            MaybePendingBlockWithTxHashes::PendingBlock(_) => {
                return Err(BlockProcessingError::InvalidBlockState("Previous block is still pending".to_string()));
            }
        },
        None => None,
    };

    // We only need to get the older block number and hash. No need to fetch all the txs
    // This is a workaorund to catch the case where the block number is less than the buffer and still preserve the check
    // The OS will also handle the case where the block number is less than the buffer.
    let older_block_number =
        if block_number <= STORED_BLOCK_HASH_BUFFER { 0 } else { block_number - STORED_BLOCK_HASH_BUFFER };

    let older_block = match rpc_client
        .starknet_rpc()
        .get_block_with_tx_hashes(BlockId::Number(older_block_number))
        .await
        .map_err(|e| BlockProcessingError::RpcClient(Box::new(e)))?
    {
        MaybePendingBlockWithTxHashes::Block(block_with_txs_hashes) => block_with_txs_hashes,
        MaybePendingBlockWithTxHashes::PendingBlock(_) => {
            return Err(BlockProcessingError::InvalidBlockState("Older block is still pending".to_string()));
        }
    };
    let old_block_number = Felt::from(older_block.block_number);
    let old_block_hash = older_block.block_hash;

    log::debug!("previous block: {:?}, older block: {:?}", previous_block, older_block);
    log::info!("Successfully fetched previous and older blocks");

    log::info!("Step 4: Building block context...");
    let block_context = build_block_context(chain_id.clone(), &block_with_txs, is_l3, starknet_version)
        .map_err(|e| BlockProcessingError::ContextBuilding(e))?;
    log::info!("Block context built successfully");

    log::info!("Step 5: Getting transaction traces...");
    let traces = rpc_client
        .starknet_rpc()
        .trace_block_transactions(block_id)
        .await
        .map_err(|e| BlockProcessingError::RpcClient(Box::new(e)))?;
    log::info!("Successfully got {} transaction traces", traces.len());

    // Extract other contracts used in our block from the block trace
    // We need this to get all the class hashes used and correctly feed address_to_class_hash
    log::info!("Step 6: Extracting accessed contracts and classes...");
    let (accessed_addresses_felt, accessed_classes_felt) = get_subcalled_contracts_from_tx_traces(&traces);

    // Convert Felt252 to proper types
    let accessed_addresses: HashSet<ContractAddress> = accessed_addresses_felt
        .iter()
        .map(|felt| {
            ContractAddress::try_from(*felt)
                .map_err(|e| BlockProcessingError::new_custom(format!("Invalid contract address: {:?}", e)))
        })
        .collect::<Result<HashSet<_>, _>>()?;

    let accessed_classes: HashSet<ClassHash> =
        accessed_classes_felt.iter().map(|felt| ClassHash((*felt).into())).collect();

    log::info!(
        "Found {} accessed addresses and {} accessed classes",
        accessed_addresses.len(),
        accessed_classes.len()
    );

    log::debug!("Accessed addresses: {:?}", accessed_addresses);
    log::debug!("Accessed classes: {:?}", accessed_classes);
    log::info!("Step 7: Getting formatted state update...");
    let processed_state_update = get_formatted_state_update(
        &rpc_client,
        previous_block_id,
        block_id,
        accessed_addresses_felt,
        accessed_classes_felt,
    )
    .await
    .map_err(|e| {
        BlockProcessingError::StateUpdateProcessing(format!("Failed to get formatted state update: {:?}", e))
    })?;
    log::info!("State update processed successfully");
    log::info!("Step 8: Converting transactions to blockifier format...");
    let mut txs = Vec::new();
    for (i, (tx, trace)) in block_with_txs.transactions.iter().zip(traces.iter()).enumerate() {
        let transaction = starknet_rs_to_blockifier(
            tx,
            trace,
            &block_context.block_info().gas_prices,
            &rpc_client,
            block_number,
            chain_id.clone(),
        )
        .await
        .map_err(|e| {
            BlockProcessingError::new_custom(format!("Failed to convert transaction to blockifier format: {:?}", e))
        })?;
        txs.push(transaction);
        if (i + 1) % 10 == 0 || i == block_with_txs.transactions.len() - 1 {
            log::info!("  📝 Converted {}/{} transactions", i + 1, block_with_txs.transactions.len());
        }
    }
    log::info!("All transactions converted to blockifier format");

    let blockifier_txns: Vec<_> = txs.iter().map(|txn_result| txn_result.blockifier_tx.clone()).collect();
    let starknet_api_txns: Vec<_> = txs.iter().map(|txn_result| txn_result.starknet_api_tx.clone()).collect();

    let _block_number_hash_pair = maybe_dummy_block_hash_and_number(BlockNumber(block_number));

    log::info!("Step 9: Creating transaction executor...");
    let config = TransactionExecutorConfig::default();
    let blockifier_state_reader = AsyncRpcStateReader::new(
        rpc_client.clone(),
        previous_block_id.ok_or_else(|| {
            BlockProcessingError::new_custom("Previous block ID is required for transaction execution")
        })?,
    );
    let mut tmp_executor =
        TransactionExecutor::new(CachedState::new(blockifier_state_reader), block_context.clone(), config);
    log::info!("Transaction executor created");

    log::info!("Step 10: Executing {} transactions...", blockifier_txns.len());
    let execution_deadline = None;
    let execution_outputs: Vec<_> = tmp_executor
        .execute_txs(&blockifier_txns, execution_deadline)
        .into_iter()
        .collect::<Result<_, TransactionExecutorError>>()
        .map_err(|e| BlockProcessingError::TransactionExecution(e))?;
    log::info!("All transactions executed successfully");

    let txn_execution_infos: Vec<TransactionExecutionInfo> =
        execution_outputs.into_iter().map(|(execution_info, _)| execution_info).collect();

    let central_txn_execution_infos: Vec<CentralTransactionExecutionInfo> =
        txn_execution_infos.clone().into_iter().map(|execution_info| execution_info.clone().into()).collect();

    log::info!("Step 11: Getting accessed keys...");
    let mut accessed_keys_by_address = get_accessed_keys_with_block_hash(&txn_execution_infos, old_block_number);
    log::info!("Got accessed keys for {} contracts", accessed_keys_by_address.len());

    // Populate accessed_keys_by_address with special address 0x2 based on accessed addresses, classes, and storage mapping
    populate_alias_contract_keys(&accessed_addresses, &accessed_classes, &mut accessed_keys_by_address);

    log::info!("Step 11b: Fetching storage proofs...");
    let storage_proofs = get_storage_proofs(&rpc_client, block_number, &accessed_keys_by_address)
        .await
        .map_err(|e| BlockProcessingError::StorageProof(format!("Failed to fetch storage proofs: {:?}", e)))?;
    log::info!("Got {} storage proofs", storage_proofs.len());

    log::info!("Step 12: Fetching previous storage proofs...");
    // TODO: add these keys to the accessed keys as well
    let previous_storage_proofs = match previous_block_id {
        Some(BlockId::Number(previous_block_id)) => {
            get_storage_proofs(&rpc_client, previous_block_id, &accessed_keys_by_address).await.map_err(|e| {
                BlockProcessingError::StorageProof(format!("Failed to fetch previous storage proofs: {:?}", e))
            })?
        }
        None => get_storage_proofs(&rpc_client, 0, &accessed_keys_by_address).await.map_err(|e| {
            BlockProcessingError::StorageProof(format!("Failed to fetch storage proofs for block 0: {:?}", e))
        })?,
        _ => {
            let mut map = HashMap::new();
            // We add a default proof for the block hash contract
            map.insert(
                Felt::ONE,
                PathfinderProof {
                    state_commitment: Default::default(),
                    class_commitment: None,
                    contract_commitment: Default::default(),
                    contract_proof: Vec::new(),
                    contract_data: None,
                },
            );
            map
        }
    };
    log::info!("Got {} previous storage proofs", previous_storage_proofs.len());

    log::info!("Step 13: Processing contract storage commitments...");
    let mut contract_address_to_class_hash = HashMap::new();
    let mut address_to_storage_commitment_info: HashMap<ContractAddress, CommitmentInfo> = HashMap::new();

    for (contract_address, storage_proof) in storage_proofs.clone() {
        let contract_address: Felt = contract_address;
        let previous_storage_proof = previous_storage_proofs.get(&contract_address).ok_or_else(|| {
            BlockProcessingError::new_custom(format!(
                "Failed to find previous storage proof for contract address: {:?}",
                contract_address
            ))
        })?;
        let previous_contract_commitment_facts = format_commitment_facts::<PedersenHash>(
            &previous_storage_proof
                .clone()
                .contract_data
                .ok_or_else(|| BlockProcessingError::new_custom("Previous storage proof missing contract data"))?
                .storage_proofs,
        );
        let current_contract_commitment_facts = format_commitment_facts::<PedersenHash>(
            &storage_proof
                .clone()
                .contract_data
                .ok_or_else(|| BlockProcessingError::new_custom("Current storage proof missing contract data"))?
                .storage_proofs,
        );
        // println!("contract_address: {:?}, previous storage proof is: {:?}", contract_address, previous_contract_commitment_facts);
        // println!("contract_address: {:?}, current storage proof is: {:?}", contract_address, current_contract_commitment_facts);
        let global_contract_commitment_facts: HashMap<HashOutput, Vec<Felt252>> = previous_contract_commitment_facts
            .into_iter()
            .chain(current_contract_commitment_facts)
            .map(|(key, value)| (HashOutput(key.into()), value))
            .collect();

        // println!("the global contract commitment facts turns out to be: {:?}", global_contract_commitment_facts);
        let previous_contract_storage_root: Felt = previous_storage_proof
            .contract_data
            .as_ref()
            .map(|contract_data| contract_data.root)
            .unwrap_or(Felt::ZERO)
            .into();

        let current_contract_storage_root: Felt =
            storage_proof.contract_data.as_ref().map(|contract_data| contract_data.root).unwrap_or(Felt::ZERO).into();

        let contract_state_commitment_info = CommitmentInfo {
            previous_root: HashOutput(previous_contract_storage_root),
            updated_root: HashOutput(current_contract_storage_root),
            tree_height: SubTreeHeight(251),
            commitment_facts: global_contract_commitment_facts,
        };

        address_to_storage_commitment_info.insert(
            ContractAddress::try_from(contract_address)
                .map_err(|e| BlockProcessingError::new_custom(format!("Invalid contract address: {:?}", e)))?,
            contract_state_commitment_info,
        );

        log::debug!(
            "Storage root 0x{:x} for contract 0x{:x} and same root in HashOutput would be: {:?}",
            Into::<Felt252>::into(previous_contract_storage_root),
            contract_address,
            HashOutput(previous_contract_storage_root)
        );
        log::debug!("Contract address: {:?}, block-id: {:?}", contract_address, block_id);

        // TODO: Check this special case handling once again - why does contract address 0x1 need class hash 0x0?
        let class_hash = if contract_address == Felt::ONE || contract_address == Felt::TWO {
            log::info!("🔧 Special case: Contract address 0x1/0x2 detected, setting class hash to 0x0 without RPC call");
            Felt::ZERO
        } else {
            rpc_client
                .starknet_rpc()
                .get_class_hash_at(block_id, contract_address)
                .await
                .map_err(|e| BlockProcessingError::RpcClient(Box::new(e)))?
        };

        contract_address_to_class_hash.insert(contract_address, class_hash);
    }
    let compiled_classes = processed_state_update.compiled_classes;
    let deprecated_compiled_classes = processed_state_update.deprecated_compiled_classes;
    let declared_class_hash_component_hashes: HashMap<ClassHash, ContractClassComponentHashes> = processed_state_update
        .declared_class_hash_component_hashes
        .into_iter()
        .map(|(class_hash, component_hashes)| (ClassHash(class_hash), component_hashes.to_os_format()))
        .collect();

    let class_hash_to_compiled_class_hash = processed_state_update.class_hash_to_compiled_class_hash;
    // query storage proofs for each accessed contract
    let class_hashes: Vec<&Felt252> = class_hash_to_compiled_class_hash.keys().collect();
    log::info!("Step 14: Fetching class proofs for {} class hashes...", class_hashes.len());
    // TODO: we fetch proofs here for block-1, but we probably also need to fetch at the current
    //       block, likely for contracts that are deployed in this block
    let class_proofs = get_class_proofs(&rpc_client, block_number, &class_hashes[..])
        .await
        .map_err(|e| BlockProcessingError::ClassProof(format!("Failed to fetch class proofs: {:?}", e)))?;
    log::info!("Got {} class proofs", class_proofs.len());

    log::info!("Step 15: Fetching previous class proofs...");
    let previous_class_proofs = match previous_block_id {
        Some(BlockId::Number(previous_block_id)) => get_class_proofs(&rpc_client, previous_block_id, &class_hashes[..])
            .await
            .map_err(|e| BlockProcessingError::ClassProof(format!("Failed to fetch previous class proofs: {:?}", e)))?,
        _ => Default::default(),
    };
    log::info!("Got {} previous class proofs", previous_class_proofs.len());

    // We can extract data from any storage proof, use the one of the block hash contract
    let block_hash_storage_proof = storage_proofs
        .get(&Felt::ONE)
        .ok_or_else(|| BlockProcessingError::new_custom("Missing storage proof for block hash contract"))?;
    let previous_block_hash_storage_proof = previous_storage_proofs
        .get(&Felt::ONE)
        .ok_or_else(|| BlockProcessingError::new_custom("Missing previous storage proof for block hash contract"))?;

    // The root of the class commitment tree for previous and current block
    // Using requested storage proof instead of getting them from class proofs
    // If the block doesn't contain transactions, `class_proofs` will be empty
    // Pathfinder will send a None on class_commitment when the tree is not initialized, ie, root is zero
    let updated_root = block_hash_storage_proof.class_commitment.unwrap_or(Felt::ZERO);
    let previous_root = previous_block_hash_storage_proof.class_commitment.unwrap_or(Felt::ZERO);

    // On devnet and until block 10, the storage_root_idx might be None and that means that contract_proof is empty
    let previous_contract_trie_root = previous_block_hash_storage_proof.contract_commitment;
    let current_contract_trie_root = block_hash_storage_proof.contract_commitment;

    let previous_contract_proofs: Vec<_> =
        previous_storage_proofs.values().map(|proof| proof.contract_proof.clone()).collect();
    let previous_state_commitment_facts = format_commitment_facts::<PedersenHash>(&previous_contract_proofs);
    let current_contract_proofs: Vec<_> = storage_proofs.values().map(|proof| proof.contract_proof.clone()).collect();
    let current_state_commitment_facts = format_commitment_facts::<PedersenHash>(&current_contract_proofs);

    let global_state_commitment_facts: HashMap<_, _> = previous_state_commitment_facts
        .into_iter()
        .chain(current_state_commitment_facts)
        .map(|(k, v)| (HashOutput(k), v))
        .collect();

    let contract_state_commitment_info = CommitmentInfo {
        previous_root: HashOutput(previous_contract_trie_root),
        updated_root: HashOutput(current_contract_trie_root),
        tree_height: SubTreeHeight(251),
        commitment_facts: global_state_commitment_facts,
    };

    log::info!("Step 16: Computing class commitments...");
    let contract_class_commitment_info =
        compute_class_commitment(&previous_class_proofs, &class_proofs, previous_root, updated_root);
    log::info!("Class commitment computed");

    log::info!("Step 17: Converting compiled classes to BTreeMap with CompiledClassHash keys...");
    let mut compiled_classes_btree: BTreeMap<ClassHash, CasmContractClass> = BTreeMap::new();

    for (class_hash_felt, generic_class) in compiled_classes {
        log::debug!("Processing class hash: {:?}", class_hash_felt);
        let class_hash = ClassHash(class_hash_felt);
        let cairo_lang_class = generic_class
            .get_cairo_lang_contract_class()
            .map_err(|e| {
                BlockProcessingError::ContractClassConversion(format!(
                    "Failed to get cairo-lang contract class: {:?}",
                    e
                ))
            })?
            .clone();
        log::debug!("Converted class hash: {:?}", class_hash);
        //
        // // 1. First check the existing class_hash_to_compiled_class_hash mapping
        // let compiled_class_hash = if let Some(&existing_compiled_hash) = class_hash_to_compiled_class_hash.get(&class_hash) {
        //     mapping_hits += 1;
        //     let compiled_class_hash = CompiledClassHash(existing_compiled_hash.into());
        //     println!("Successfully Found compiled class hash in mapping: {:?} -> {:?}", class_hash, compiled_class_hash);
        //     compiled_class_hash
        // } else {
        //     // 2. Fallback to RPC call if not in mapping
        //     rpc_calls_made += 1;
        //     println!("⚠️  Class hash {:?} not found in mapping, making RPC call...", class_hash);
        //     let state_reader = AsyncRpcStateReader::new(rpc_client.clone(), block_id);
        //     match state_reader.get_compiled_class_hash_async(class_hash).await {
        //         Ok(compiled_hash) => {
        //             println!("Successfully RPC call succeeded: {:?} -> {:?}", class_hash, compiled_hash);
        //             compiled_hash
        //         }
        //         Err(e) => {
        //             println!("❌ RPC call failed for class hash {:?}: {}", class_hash, e);
        //             continue; // Skip this class if we can't get compiled class hash
        //         }
        //     }
        // };

        compiled_classes_btree.insert(class_hash, cairo_lang_class);
    }

    let mut deprecated_compiled_classes_btree: BTreeMap<ClassHash, ContractClass> = BTreeMap::new();
    let deprecated_rpc_calls_made = 0;
    let deprecated_mapping_hits = 0;

    for (class_hash_felt, generic_class) in deprecated_compiled_classes {
        let class_hash = ClassHash(class_hash_felt);
        let starknet_api_class = generic_class.to_starknet_api_contract_class().map_err(|e| {
            BlockProcessingError::ContractClassConversion(format!(
                "Failed to convert to starknet-api contract class: {:?}",
                e
            ))
        })?;

        // 1. First check the existing class_hash_to_compiled_class_hash mapping
        // let compiled_class_hash = if let Some(&existing_compiled_hash) = class_hash_to_compiled_class_hash.get(&class_hash) {
        //     deprecated_mapping_hits += 1;
        //     let compiled_class_hash = CompiledClassHash(existing_compiled_hash.into());
        //     println!("Successfully Found deprecated compiled class hash in mapping: {:?} -> {:?}", class_hash, compiled_class_hash);
        //     compiled_class_hash
        // } else {
        //     // 2. Fallback to RPC call if not in mapping
        //     deprecated_rpc_calls_made += 1;
        //     println!("⚠️  Deprecated class hash {:?} not found in mapping, making RPC call...", class_hash);
        //     let state_reader = AsyncRpcStateReader::new(rpc_client.clone(), block_id);
        //     match state_reader.get_compiled_class_hash_async(class_hash).await {
        //         Ok(compiled_hash) => {
        //             println!("Successfully Deprecated RPC call succeeded: {:?} -> {:?}", class_hash, compiled_hash);
        //             compiled_hash
        //         }
        //         Err(e) => {
        //             println!("❌ Deprecated RPC call failed for class hash {:?}: {}", class_hash, e);
        //             continue; // Skip this class if we can't get compiled class hash
        //         }
        //     }
        // };

        deprecated_compiled_classes_btree.insert(class_hash, starknet_api_class);
    }

    log::info!(
        "Deprecated classes stats: {} mapping hits, {} RPC calls made",
        deprecated_mapping_hits, deprecated_rpc_calls_made
    );
    log::info!(
        "Converted {} compiled classes and {} deprecated classes",
        compiled_classes_btree.len(),
        deprecated_compiled_classes_btree.len()
    );

    log::info!("Step 18: Building final OsBlockInput...");
    let os_block_input = OsBlockInput {
        contract_state_commitment_info,
        contract_class_commitment_info,
        address_to_storage_commitment_info,
        transactions: starknet_api_txns,
        tx_execution_infos: central_txn_execution_infos,
        declared_class_hash_to_component_hashes: declared_class_hash_component_hashes,
        block_info: block_context.block_info().clone(),
        prev_block_hash: BlockHash(previous_block.unwrap().block_hash),
        new_block_hash: BlockHash(block_with_txs.block_hash),
        old_block_number_and_hash: Some((BlockNumber(older_block_number), BlockHash(old_block_hash))),
    };

    log::info!("collect_single_block_info: Completed successfully for block {}", block_number);

    Ok(BlockInfoResult {
        os_block_input,
        compiled_classes: compiled_classes_btree,
        deprecated_compiled_classes: deprecated_compiled_classes_btree,
        accessed_addresses,
        accessed_classes,
        accessed_keys_by_address,
        previous_block_id,
    })
}
