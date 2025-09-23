//! Block Processing Module
//!
//! This module provides functionality for processing individual Starknet blocks
//! and extracting all necessary information for PIE (Program Input/Output) generation.
//!
//! The main entry point is [`collect_single_block_info`] which orchestrates the entire
//! block processing pipeline, from fetching block data to constructing the final OS input.

use crate::constants::{DEFAULT_SEPOLIA_ETH_FEE_TOKEN, DEFAULT_SEPOLIA_STRK_FEE_TOKEN};
use crate::conversions::{ConversionContext, TryIntoBlockifierAsync};
use crate::error::{BlockProcessingError, FeltConversionError};
use crate::state_update::{
    get_formatted_state_update, get_subcalled_contracts_from_tx_traces, ContractClassProcessingResult,
};
use crate::utils::{
    build_gas_price_vector, compute_class_commitment, format_commitment_facts, get_accessed_keys_with_block_hash,
    get_class_proofs, get_storage_proofs,
};
use blockifier::blockifier::config::TransactionExecutorConfig;
use blockifier::blockifier::transaction_executor::{TransactionExecutor, TransactionExecutorError};
use blockifier::blockifier_versioned_constants::VersionedConstants;
use blockifier::bouncer::BouncerConfig;
use blockifier::context::{BlockContext, ChainInfo, FeeTokenAddresses};
use blockifier::state::cached_state::CachedState;
use blockifier::transaction::objects::TransactionExecutionInfo;
use cairo_lang_starknet_classes::casm_contract_class::CasmContractClass;
use cairo_vm::Felt252;
use log::{debug, info};
use num_traits::ToPrimitive;
use rpc_client::state_reader::AsyncRpcStateReader;
use rpc_client::types::ContractProof;
use rpc_client::RpcClient;
use shared_execution_objects::central_objects::CentralTransactionExecutionInfo;
use starknet::core::types::{BlockId, L1DataAvailabilityMode, MaybePendingBlockWithTxHashes, MaybePendingBlockWithTxs};
use starknet::providers::Provider;
use starknet_api::block::{BlockHash, BlockInfo, BlockNumber, BlockTimestamp, GasPrices, StarknetVersion};
use starknet_api::contract_address;
use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress};
use starknet_api::deprecated_contract_class::ContractClass;
use starknet_api::state::StorageKey;
use starknet_os::io::os_input::{CommitmentInfo, OsBlockInput};
use starknet_os_types::chain_id::chain_id_from_felt;
use starknet_patricia::hash::hash_trait::HashOutput;
use starknet_patricia::patricia_merkle_tree::types::SubTreeHeight;
use starknet_types_core::felt::Felt;
use std::collections::{BTreeMap, HashMap, HashSet};

// ================================================================================================
// Constants
// ================================================================================================

pub const STORED_BLOCK_HASH_BUFFER: u64 = 10;
const STATEFUL_MAPPING_START: Felt = Felt::from_hex_unchecked("0x80"); // 128

// ================================================================================================
// Type Definitions
// ================================================================================================

/// Result type for block processing operations.
pub type BlockProcessingResult = Result<BlockInfoResult, BlockProcessingError>;

/// Result containing all the information collected from a single block.
#[derive(Debug)]
pub struct BlockInfoResult {
    /// The OS block input for the block.
    pub os_block_input: OsBlockInput,
    /// Compiled classes used in the block.
    pub compiled_classes: BTreeMap<CompiledClassHash, CasmContractClass>,
    /// Deprecated compiled classes used in the block.
    pub deprecated_compiled_classes: BTreeMap<CompiledClassHash, ContractClass>,
    /// Addresses accessed during block execution.
    pub accessed_addresses: HashSet<ContractAddress>,
    /// Class hashes accessed during block execution.
    pub accessed_classes: HashSet<ClassHash>,
    /// Storage keys accessed by each contract address.
    pub accessed_keys_by_address: HashMap<ContractAddress, HashSet<StorageKey>>,
    /// The previous block ID (if any).
    pub previous_block_id: Option<BlockId>,
}

/// Result containing fetched block data needed for processing.
#[derive(Debug)]
struct BlockData {
    chain_id: starknet_api::core::ChainId,
    current_block: starknet::core::types::BlockWithTxs,
    previous_block: Option<starknet::core::types::BlockWithTxHashes>,
    old_block_number: Felt,
    old_block_hash: Felt,
    starknet_version: StarknetVersion,
}

impl BlockData {
    /// Fetches all required block data from the RPC client.
    ///
    /// This includes the current block with transactions, previous block,
    /// older block for hash buffer, and chain information.
    ///
    /// # Arguments
    ///
    /// * `block_number` - The block number to process
    /// * `rpc_client` - The RPC client for fetching data
    ///
    /// # Returns
    ///
    /// Returns a `BlockData` struct containing all fetched block information
    /// or an error if any fetch operation fails.
    pub async fn fetch(block_number: u64, rpc_client: &RpcClient) -> Result<Self, BlockProcessingError> {
        info!("Fetching block data for block {}", block_number);

        let block_id = BlockId::Number(block_number);
        let previous_block_id = if block_number == 0 { None } else { Some(BlockId::Number(block_number - 1)) };

        // Fetch chain ID from RPC
        let chain_id_result =
            rpc_client.starknet_rpc().chain_id().await.map_err(|e| BlockProcessingError::RpcClient(Box::new(e)))?;
        let chain_id = chain_id_from_felt(chain_id_result);
        info!("Provider's chain_id: {}", chain_id);

        // Fetch the current block with transactions
        let current_block = match rpc_client
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
        info!("Successfully fetched block with {} transactions", current_block.transactions.len());

        // Get starknet version from the block
        let starknet_version = StarknetVersion::try_from(current_block.starknet_version.as_str())
            .map_err(|e| BlockProcessingError::StarknetVersion(format!("Invalid starknet version: {:?}", e)))?;
        info!("Starknet version set to: {:?}", starknet_version);

        // Fetch the previous block if it exists
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

        // Fetch older block for hash buffer
        let older_block_number = block_number.saturating_sub(STORED_BLOCK_HASH_BUFFER);
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
        info!("Successfully fetched previous and older blocks");

        Ok(BlockData { chain_id, current_block, previous_block, old_block_number, old_block_hash, starknet_version })
    }

    /// Processes transactions and extracts execution information.
    ///
    /// This function fetches transaction traces, executes transactions using Blockifier,
    /// and extracts accessed data.
    ///
    /// # Arguments
    ///
    /// * `block_number` - The block number being processed
    /// * `is_l3` - Whether this is an L3 chain
    /// * `rpc_client` - The RPC client for fetching data
    /// * `block_context` - The pre-built block context to use
    ///
    /// # Returns
    ///
    /// Returns a `TransactionProcessingResult` containing all processed transaction data
    /// or an error if any processing step fails.
    pub async fn process_transactions(
        &self,
        block_number: u64,
        rpc_client: &RpcClient,
        block_context: &BlockContext,
    ) -> Result<TransactionProcessingResult, BlockProcessingError> {
        info!("Processing transactions for block {}", block_number);

        let block_id = BlockId::Number(block_number);
        let previous_block_id =
            self.previous_block.as_ref().map(|previous_block| BlockId::Number(previous_block.block_number));

        // Fetch transaction traces
        let transaction_traces = rpc_client
            .starknet_rpc()
            .trace_block_transactions(block_id)
            .await
            .map_err(|e| BlockProcessingError::RpcClient(Box::new(e)))?;
        info!("Successfully fetched {} transaction traces for block {}", transaction_traces.len(), block_number);

        // Extract accessed contracts and classes from traces
        let (mut accessed_addresses_felt, accessed_classes_felt) =
            get_subcalled_contracts_from_tx_traces(&transaction_traces);

        // Create a single conversion context for all transactions
        let conversion_ctx =
            ConversionContext::new(&self.chain_id, block_number, rpc_client, &block_context.block_info().gas_prices);

        // Convert transactions to blockifier format
        let mut transactions = Vec::new();
        for (i, (transaction, trace)) in
            self.current_block.transactions.iter().zip(transaction_traces.iter()).enumerate()
        {
            // Convert transaction using the new async trait, passing trace separately
            let transaction =
                transaction.clone().try_into_blockifier_async(&conversion_ctx, trace).await.map_err(|e| {
                    BlockProcessingError::new_custom(format!(
                        "Failed to convert transaction to blockifier format: {:?}",
                        e
                    ))
                })?;
            transactions.push(transaction);

            if (i + 1) % 10 == 0 || i == self.current_block.transactions.len() - 1 {
                debug!(
                    "📝 Converted {}/{} transactions to blockifier type",
                    i + 1,
                    self.current_block.transactions.len()
                );
            }
        }
        info!("All transactions converted to blockifier format");

        let blockifier_txns: Vec<_> = transactions.iter().map(|txn_result| txn_result.blockifier_tx.clone()).collect();
        let starknet_api_txns: Vec<_> =
            transactions.iter().map(|txn_result| txn_result.starknet_api_tx.clone()).collect();

        // Execute transactions using Blockifier
        let config = TransactionExecutorConfig::default();
        let blockifier_state_reader = AsyncRpcStateReader::new(
            rpc_client.clone(),
            previous_block_id.ok_or_else(|| {
                BlockProcessingError::new_custom("Previous block ID is required for transaction execution")
            })?,
        );

        let mut txn_executor =
            TransactionExecutor::new(CachedState::new(blockifier_state_reader), block_context.clone(), config);
        info!("Transaction executor created successfully");
        info!("Executing {} transactions using Blockifier", blockifier_txns.len());

        // Execute transactions
        let execution_deadline = None;
        let execution_outputs: Vec<_> = txn_executor
            .execute_txs(&blockifier_txns, execution_deadline)
            .into_iter()
            .collect::<Result<_, TransactionExecutorError>>()
            .map_err(BlockProcessingError::TransactionExecution)?;

        info!("{} transactions executed successfully", blockifier_txns.len());

        let txn_execution_infos: Vec<TransactionExecutionInfo> =
            execution_outputs.into_iter().map(|(execution_info, _)| execution_info).collect();

        let central_txn_execution_infos: Vec<CentralTransactionExecutionInfo> =
            txn_execution_infos.clone().into_iter().map(|execution_info| execution_info.clone().into()).collect();

        // Get accessed keys and populate alias contract keys
        let mut accessed_keys_by_address =
            get_accessed_keys_with_block_hash(&txn_execution_infos, self.old_block_number);

        info!("Got accessed keys for {} contracts", accessed_keys_by_address.len());

        accessed_addresses_felt.extend(accessed_keys_by_address.keys().map(|contract_addr| {
            let felt: Felt = (*contract_addr).into();
            felt
        }));

        let processed_state_update = get_formatted_state_update(
            rpc_client,
            previous_block_id,
            block_id,
            accessed_addresses_felt.clone(),
            accessed_classes_felt.clone(),
        )
        .await
        .map_err(|e| {
            BlockProcessingError::StateUpdateProcessing(format!("Failed to get formatted state update: {:?}", e))
        })?;
        info!("Fetched processed state update successfully");

        // Convert Felt252 to proper types
        let accessed_addresses: HashSet<ContractAddress> = accessed_addresses_felt
            .iter()
            .map(|felt| {
                ContractAddress::try_from(*felt)
                    .map_err(|e| BlockProcessingError::new_custom(format!("Invalid contract address: {:?}", e)))
            })
            .collect::<Result<HashSet<_>, _>>()?;

        let accessed_classes: HashSet<ClassHash> = accessed_classes_felt.iter().map(|felt| ClassHash(*felt)).collect();

        info!(
            "Successfully Found {} accessed addresses and {} accessed classes",
            accessed_addresses.len(),
            accessed_classes.len()
        );

        populate_alias_contract_keys(&accessed_addresses, &accessed_classes, &mut accessed_keys_by_address);

        Ok(TransactionProcessingResult {
            starknet_api_txns,
            central_txn_execution_infos,
            accessed_addresses,
            accessed_classes,
            accessed_keys_by_address,
            processed_state_update,
        })
    }

    /// Builds the block context for this block data.
    ///
    /// This function creates a `BlockContext` containing all the necessary
    /// information for transaction execution and OS input generation.
    ///
    /// # Arguments
    ///
    /// * `is_l3` - Whether this is an L3 chain
    ///
    /// # Returns
    ///
    /// Returns a `BlockContext` or an error if context building fails.
    pub fn build_context(&self, is_l3: bool) -> Result<BlockContext, FeltConversionError> {
        // Extract sequencer address
        let sequencer_address_hex = self.current_block.sequencer_address.to_hex_string();
        let sequencer_address = contract_address!(sequencer_address_hex.as_str());

        // Determine data availability mode
        let use_kzg_da = match self.current_block.l1_da_mode {
            L1DataAvailabilityMode::Blob => true,
            L1DataAvailabilityMode::Calldata => false,
        };

        // Build gas prices with proper error handling
        let eth_gas_prices = build_gas_price_vector(
            &self.current_block.l1_gas_price.price_in_wei,
            &self.current_block.l1_data_gas_price.price_in_wei,
            &self.current_block.l2_gas_price.price_in_wei,
        )?;
        let strk_gas_prices = build_gas_price_vector(
            &self.current_block.l1_gas_price.price_in_fri,
            &self.current_block.l1_data_gas_price.price_in_fri,
            &self.current_block.l2_gas_price.price_in_fri,
        )?;

        let block_info = BlockInfo {
            block_number: BlockNumber(self.current_block.block_number),
            block_timestamp: BlockTimestamp(self.current_block.timestamp),
            sequencer_address,
            gas_prices: GasPrices { eth_gas_prices, strk_gas_prices },
            use_kzg_da,
        };

        debug!("Block info created: {:?}", block_info);

        // Build chain information
        let chain_info = ChainInfo {
            chain_id: self.chain_id.clone(),
            // Fee token addresses for Sepolia testnet
            // Reference: https://docs.starknet.io/tools/important-addresses/
            // TODO: Take these from the user
            fee_token_addresses: FeeTokenAddresses {
                strk_fee_token_address: contract_address!(DEFAULT_SEPOLIA_STRK_FEE_TOKEN),
                eth_fee_token_address: contract_address!(DEFAULT_SEPOLIA_ETH_FEE_TOKEN),
            },
            is_l3,
        };

        // Get versioned constants
        // TODO: Add support for taking custom versioned constants from the user
        let versioned_constants = VersionedConstants::get(&self.starknet_version).map_err(|_| {
            FeltConversionError::new_custom(format!("Failed to get versioned constants for {}", self.starknet_version))
        })?;

        // Use maximum bouncer configuration
        // TODO: Add support for taking custom bouncer configuration from the user
        let bouncer_config = BouncerConfig::max();

        Ok(BlockContext::new(block_info, chain_info, versioned_constants.clone(), bouncer_config))
    }
}

/// Result containing processed transaction data.
#[derive(Debug)]
struct TransactionProcessingResult {
    /// Transactions in sequencer::starknet_api format
    starknet_api_txns: Vec<starknet_api::executable_transaction::Transaction>,
    central_txn_execution_infos: Vec<CentralTransactionExecutionInfo>,
    accessed_addresses: HashSet<ContractAddress>,
    accessed_classes: HashSet<ClassHash>,
    accessed_keys_by_address: HashMap<ContractAddress, HashSet<StorageKey>>,
    processed_state_update: crate::state_update::FormattedStateUpdate,
}

impl TransactionProcessingResult {
    /// Collects storage and class proofs for the current and previous blocks.
    ///
    /// This function fetches all necessary Merkle proofs for contract storage
    /// and class definitions that are accessed during block execution.
    ///
    /// # Arguments
    ///
    /// * `block_number` - The block number being processed
    /// * `rpc_client` - The RPC client for fetching proofs
    ///
    /// # Returns
    ///
    /// Returns a `ProofCollectionResult` containing all collected proofs
    /// or an error if any proof collection fails.
    pub async fn collect_proofs(
        &self,
        block_number: u64,
        rpc_client: &RpcClient,
    ) -> Result<ProofCollectionResult, BlockProcessingError> {
        info!("Collecting proofs for block {}", block_number);

        let previous_block_id = if block_number == 0 { None } else { Some(BlockId::Number(block_number - 1)) };

        // Fetch storage proofs for the current block
        let storage_proofs = get_storage_proofs(rpc_client, block_number, &self.accessed_keys_by_address)
            .await
            .map_err(|e| BlockProcessingError::StorageProof(format!("Failed to fetch storage proofs: {:?}", e)))?;
        info!("Got {} storage proofs", storage_proofs.len());

        // Fetch previous storage proofs
        let previous_storage_proofs = match previous_block_id {
            Some(BlockId::Number(previous_block_id)) => {
                get_storage_proofs(rpc_client, previous_block_id, &self.accessed_keys_by_address).await.map_err(
                    |e| BlockProcessingError::StorageProof(format!("Failed to fetch previous storage proofs: {:?}", e)),
                )?
            }
            None => get_storage_proofs(rpc_client, 0, &self.accessed_keys_by_address).await.map_err(|e| {
                BlockProcessingError::StorageProof(format!("Failed to fetch storage proofs for block 0: {:?}", e))
            })?,
            _ => {
                let mut map = HashMap::new();
                // Add a default proof for the block hash contract
                map.insert(
                    Felt::ONE,
                    ContractProof {
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
        info!("Got {} previous storage proofs", previous_storage_proofs.len());

        // Collect class hashes for proof fetching
        let class_hashes: Vec<&Felt252> =
            self.processed_state_update.class_hash_to_compiled_class_hash.keys().collect();

        // Fetch class proofs for the current block
        let class_proofs = get_class_proofs(rpc_client, block_number, &class_hashes[..])
            .await
            .map_err(|e| BlockProcessingError::ClassProof(format!("Failed to fetch class proofs: {:?}", e)))?;
        info!("Got {} class proofs for {} class hashes", class_proofs.len(), class_hashes.len());

        // Fetch previous class proofs
        let previous_class_proofs = match previous_block_id {
            Some(BlockId::Number(previous_block_id)) => {
                get_class_proofs(rpc_client, previous_block_id, &class_hashes[..]).await.map_err(|e| {
                    BlockProcessingError::ClassProof(format!("Failed to fetch previous class proofs: {:?}", e))
                })?
            }
            _ => Default::default(),
        };
        info!("Got {} previous class proofs for {} class hashes", previous_class_proofs.len(), class_hashes.len());

        Ok(ProofCollectionResult { storage_proofs, previous_storage_proofs, class_proofs, previous_class_proofs })
    }
}

/// Result containing collected proof data.
struct ProofCollectionResult {
    storage_proofs: HashMap<Felt, ContractProof>,
    previous_storage_proofs: HashMap<Felt, ContractProof>,
    class_proofs: HashMap<Felt, rpc_client::types::ClassProof>,
    previous_class_proofs: HashMap<Felt, rpc_client::types::ClassProof>,
}

impl ProofCollectionResult {
    /// Calculates commitment information for contracts and classes.
    ///
    /// This function processes storage and class proofs to calculate
    /// the various commitment trees needed for the OS input.
    ///
    /// # Arguments
    ///
    /// * `block_id` - The current block ID
    /// * `rpc_client` - The RPC client for additional data fetching
    ///
    /// # Returns
    ///
    /// Returns a `CommitmentCalculationResult` containing all commitment information
    /// or an error if any calculation fails.
    pub async fn calculate_commitments(
        &self,
        block_id: BlockId,
        rpc_client: &RpcClient,
    ) -> Result<CommitmentCalculationResult, BlockProcessingError> {
        info!("Calculating commitments");

        let mut address_to_storage_commitment_info: HashMap<ContractAddress, CommitmentInfo> = HashMap::new();

        // Process contract storage commitments
        for (contract_address, storage_proof) in self.storage_proofs.clone() {
            let contract_address: Felt = contract_address;
            let previous_storage_proof = self.previous_storage_proofs.get(&contract_address).ok_or_else(|| {
                BlockProcessingError::new_custom(format!(
                    "Failed to find previous storage proof for contract address: {:?}",
                    contract_address
                ))
            })?;

            let previous_contract_commitment_facts = format_commitment_facts(
                &previous_storage_proof
                    .clone()
                    .contract_data
                    .ok_or_else(|| BlockProcessingError::new_custom("Previous storage proof missing contract data"))?
                    .storage_proofs,
            );

            let current_contract_commitment_facts = format_commitment_facts(
                &storage_proof
                    .clone()
                    .contract_data
                    .ok_or_else(|| BlockProcessingError::new_custom("Current storage proof missing contract data"))?
                    .storage_proofs,
            );

            let global_contract_commitment_facts: HashMap<HashOutput, Vec<Felt252>> =
                previous_contract_commitment_facts
                    .into_iter()
                    .chain(current_contract_commitment_facts)
                    .map(|(key, value)| (HashOutput(key), value))
                    .collect();

            let previous_contract_storage_root: Felt = previous_storage_proof
                .contract_data
                .as_ref()
                .map(|contract_data| contract_data.root)
                .unwrap_or(Felt::ZERO);

            let current_contract_storage_root: Felt =
                storage_proof.contract_data.as_ref().map(|contract_data| contract_data.root).unwrap_or(Felt::ZERO);

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

            debug!(
                "Storage root 0x{:x} for contract 0x{:x} and same root in HashOutput would be: {:?}",
                Into::<Felt252>::into(previous_contract_storage_root),
                contract_address,
                HashOutput(previous_contract_storage_root)
            );
            debug!("Contract address: {:?}, block-id: {:?}", contract_address, block_id);

            // Special case handling for contract addresses 0x1 and 0x2
            let _class_hash = if contract_address == Felt::ONE || contract_address == Felt::TWO {
                info!("🔧 Special case: Contract address 0x1/0x2 detected, setting class hash to 0x0 without RPC call");
                Felt::ZERO
            } else {
                rpc_client
                    .starknet_rpc()
                    .get_class_hash_at(block_id, contract_address)
                    .await
                    .map_err(|e| BlockProcessingError::RpcClient(Box::new(e)))?
            };

            // Note: class_hash is fetched but not currently used in the result
        }

        // Extract commitment roots from storage proofs
        let block_hash_storage_proof = self
            .storage_proofs
            .get(&Felt::ONE)
            .ok_or_else(|| BlockProcessingError::new_custom("Missing storage proof for block hash contract"))?;

        let previous_block_hash_storage_proof = self.previous_storage_proofs.get(&Felt::ONE).ok_or_else(|| {
            BlockProcessingError::new_custom("Missing previous storage proof for block hash contract")
        })?;

        // Class commitment tree roots
        let updated_root = block_hash_storage_proof.class_commitment.unwrap_or(Felt::ZERO);
        let previous_root = previous_block_hash_storage_proof.class_commitment.unwrap_or(Felt::ZERO);

        // Contract trie roots
        let previous_contract_trie_root = previous_block_hash_storage_proof.contract_commitment;
        let current_contract_trie_root = block_hash_storage_proof.contract_commitment;

        // Process contract proofs for state commitment
        let previous_contract_proofs: Vec<_> =
            self.previous_storage_proofs.values().map(|proof| proof.contract_proof.clone()).collect();

        let previous_state_commitment_facts = format_commitment_facts(&previous_contract_proofs);

        let current_contract_proofs: Vec<_> =
            self.storage_proofs.values().map(|proof| proof.contract_proof.clone()).collect();

        let current_state_commitment_facts = format_commitment_facts(&current_contract_proofs);

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

        // Compute class commitment
        let contract_class_commitment_info =
            compute_class_commitment(&self.previous_class_proofs, &self.class_proofs, previous_root, updated_root);
        info!("Class commitment computed");

        Ok(CommitmentCalculationResult {
            address_to_storage_commitment_info,
            contract_state_commitment_info,
            contract_class_commitment_info,
        })
    }
}

/// Result containing calculated commitment information.
struct CommitmentCalculationResult {
    address_to_storage_commitment_info: HashMap<ContractAddress, CommitmentInfo>,
    contract_state_commitment_info: CommitmentInfo,
    contract_class_commitment_info: CommitmentInfo,
}

// ================================================================================================
// Public API
// ================================================================================================

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
/// Returns a `BlockProcessingResult` containing all the collected block information
/// or an error if any step of the processing fails.
///
/// # Errors
///
/// This function can return various errors including
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
    info!("Starting block info collection for block {}", block_number);

    // Step 1: Fetch all required block data
    let block_data = BlockData::fetch(block_number, &rpc_client).await?;

    // Step 2: Build block context (only once, reused throughout)
    let block_context = block_data.build_context(is_l3).map_err(BlockProcessingError::ContextBuilding)?;

    // Step 3: Process transactions and extract execution information
    let tx_result = block_data.process_transactions(block_number, &rpc_client, &block_context).await?;

    // Step 4: Collect storage and class proofs
    let proofs = tx_result.collect_proofs(block_number, &rpc_client).await?;

    // Step 5: Calculate commitment information
    let block_id = BlockId::Number(block_number);
    let commitment_result = proofs.calculate_commitments(block_id, &rpc_client).await?;

    // Step 6: Process contract classes
    let class_result = tx_result.processed_state_update.process_contract_classes()?;

    // Step 7: Extract values we need before moving ownership
    let accessed_addresses = tx_result.accessed_addresses.clone();
    let accessed_classes = tx_result.accessed_classes.clone();
    let accessed_keys_by_address = tx_result.accessed_keys_by_address.clone();
    let compiled_classes = class_result.compiled_classes.clone();
    let deprecated_compiled_classes = class_result.deprecated_compiled_classes.clone();

    // Step 8: Build final OS block input (consuming the result structs)
    let os_block_input = build_os_block_input(&block_data, tx_result, commitment_result, class_result, &block_context);

    info!("Successfully completed construction of OsBlockInput for block {}", block_number);

    Ok(BlockInfoResult {
        os_block_input,
        compiled_classes,
        deprecated_compiled_classes,
        accessed_addresses,
        accessed_classes,
        accessed_keys_by_address,
        previous_block_id: if block_number == 0 { None } else { Some(BlockId::Number(block_number - 1)) },
    })
}

// ================================================================================================
// Private Helper Functions
// ================================================================================================

/// Builds the final OS block input from all processed data.
///
/// This function constructs the `OsBlockInput` structure containing all the
/// information needed for the Starknet OS execution.
///
/// # Arguments
///
/// * `block_data` - The fetched block data
/// * `tx_result` - The processed transaction data
/// * `commitment_result` - The calculated commitment information
/// * `class_result` - The processed contract class data
/// * `block_context` - The built block context
///
/// # Returns
///
/// Returns an `OsBlockInput` ready for OS execution.
fn build_os_block_input(
    block_data: &BlockData,
    tx_result: TransactionProcessingResult,
    commitment_result: CommitmentCalculationResult,
    class_result: ContractClassProcessingResult,
    block_context: &blockifier::context::BlockContext,
) -> OsBlockInput {
    info!("Building OS block input");

    OsBlockInput {
        contract_state_commitment_info: commitment_result.contract_state_commitment_info,
        contract_class_commitment_info: commitment_result.contract_class_commitment_info,
        address_to_storage_commitment_info: commitment_result.address_to_storage_commitment_info,
        transactions: tx_result.starknet_api_txns,
        tx_execution_infos: tx_result.central_txn_execution_infos,
        declared_class_hash_to_component_hashes: class_result.declared_class_hash_component_hashes,
        block_info: block_context.block_info().clone(),
        prev_block_hash: BlockHash(block_data.previous_block.as_ref().unwrap().block_hash),
        new_block_hash: BlockHash(block_data.current_block.block_hash),
        old_block_number_and_hash: Some((
            BlockNumber(block_data.old_block_number.to_u64().unwrap()),
            BlockHash(block_data.old_block_hash),
        )),
    }
}

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

        info!(
            "Added {} keys to alias contract (0x2) for storage mapping",
            accessed_keys_by_address.get(&alias_contract_address).unwrap().len()
        );
    }
}
