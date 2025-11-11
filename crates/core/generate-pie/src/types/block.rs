use crate::constants::{STATEFUL_MAPPING_START, STORED_BLOCK_HASH_BUFFER};
use crate::conversions::{ConversionContext, TryIntoBlockifierAsync};
use crate::error::{BlockProcessingError, FeltConversionError};
use crate::state_update::{get_formatted_state_update, get_subcalled_contracts_from_tx_traces};
use crate::types::TransactionProcessingResult;
use crate::utils::{build_gas_price_vector, get_accessed_keys_with_block_hash};
use blockifier::blockifier::config::TransactionExecutorConfig;
use blockifier::blockifier::transaction_executor::{TransactionExecutor, TransactionExecutorError};
use blockifier::blockifier_versioned_constants::VersionedConstants;
use blockifier::bouncer::BouncerConfig;
use blockifier::context::{BlockContext, ChainInfo, FeeTokenAddresses};
use blockifier::state::cached_state::CachedState;
use blockifier::transaction::objects::TransactionExecutionInfo;
use log::{debug, info, warn};
use rpc_client::state_reader::AsyncRpcStateReader;
use rpc_client::RpcClient;
use shared_execution_objects::central_objects::CentralTransactionExecutionInfo;
use starknet::core::types::{
    BlockId, ConfirmedBlockId, L1DataAvailabilityMode, MaybePreConfirmedBlockWithTxHashes,
    MaybePreConfirmedBlockWithTxs,
};
use starknet::providers::Provider;
use starknet_api::block::{BlockInfo, BlockNumber, BlockTimestamp, GasPrices, StarknetVersion};
use starknet_api::contract_address;
use starknet_api::core::{ClassHash, ContractAddress};
use starknet_api::state::StorageKey;
use starknet_os_types::chain_id::chain_id_from_felt;
use starknet_types_core::felt::Felt;
use std::collections::{HashMap, HashSet};
use std::env;

const BLOCKIFIER_TXN_EXECUTOR_CONFIG_ENV: &str = "SNOS_BLOCKIFIER_TXN_EXECUTOR_CONFIG";

/// Result containing fetched block data needed for processing.
#[derive(Debug)]
pub struct BlockData {
    pub chain_id: starknet_api::core::ChainId,
    pub current_block: starknet::core::types::BlockWithTxs,
    pub previous_block: Option<starknet::core::types::BlockWithTxHashes>,
    pub old_block_number: Felt,
    pub old_block_hash: Felt,
    pub starknet_version: StarknetVersion,
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
            MaybePreConfirmedBlockWithTxs::Block(block_with_txs) => block_with_txs,
            MaybePreConfirmedBlockWithTxs::PreConfirmedBlock(_) => {
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
                MaybePreConfirmedBlockWithTxHashes::Block(block_with_txs) => Some(block_with_txs),
                MaybePreConfirmedBlockWithTxHashes::PreConfirmedBlock(_) => {
                    return Err(BlockProcessingError::InvalidBlockState("Previous block is still pending".to_string()));
                }
            },
            None => None,
        };

        // Fetch older block for hash buffer
        let old_block_number_u64 = block_number.saturating_sub(STORED_BLOCK_HASH_BUFFER);
        let old_block = match rpc_client
            .starknet_rpc()
            .get_block_with_tx_hashes(BlockId::Number(old_block_number_u64))
            .await
            .map_err(|e| BlockProcessingError::RpcClient(Box::new(e)))?
        {
            MaybePreConfirmedBlockWithTxHashes::Block(block_with_txs_hashes) => block_with_txs_hashes,
            MaybePreConfirmedBlockWithTxHashes::PreConfirmedBlock(_) => {
                return Err(BlockProcessingError::InvalidBlockState("Older block is still pending".to_string()));
            }
        };

        let old_block_number = Felt::from(old_block.block_number);
        let old_block_hash = old_block.block_hash;
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
        let confirmed_block_id = ConfirmedBlockId::Number(block_number);
        let previous_block_id =
            self.previous_block.as_ref().map(|previous_block| BlockId::Number(previous_block.block_number));

        // Fetch transaction traces
        let transaction_traces = rpc_client
            .starknet_rpc()
            .trace_block_transactions(confirmed_block_id)
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
        let config: TransactionExecutorConfig = match env::var(BLOCKIFIER_TXN_EXECUTOR_CONFIG_ENV) {
            Ok(config) => serde_json::from_str(&config).unwrap_or_else(|err| {
                warn!("Failed to serialize {} env: {}. Using default config", BLOCKIFIER_TXN_EXECUTOR_CONFIG_ENV, err);
                TransactionExecutorConfig::default()
            }),
            Err(err) => {
                warn!("Failed to read {} env: {}. Using default config.", BLOCKIFIER_TXN_EXECUTOR_CONFIG_ENV, err);
                TransactionExecutorConfig::default()
            }
        };

        let blockifier_state_reader = AsyncRpcStateReader::new(rpc_client.clone(), previous_block_id);

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
        let mut accessed_addresses: HashSet<ContractAddress> = accessed_addresses_felt
            .iter()
            .map(|felt| {
                ContractAddress::try_from(*felt)
                    .map_err(|e| BlockProcessingError::new_custom(format!("Invalid contract address: {:?}", e)))
            })
            .collect::<Result<HashSet<_>, _>>()?;
        accessed_addresses.insert(block_context.chain_info().fee_token_addresses.strk_fee_token_address);
        let mut accessed_classes: HashSet<ClassHash> =
            accessed_classes_felt.iter().map(|felt| ClassHash(*felt)).collect();
        accessed_classes
            .extend(processed_state_update.declared_class_hash_component_hashes.keys().map(|felt| ClassHash(*felt)));

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
    /// * `strk_fee_token_address` - The STRK fee token address
    /// * `eth_fee_token_address` - The ETH fee token address
    /// * `versioned_constants` - Optional versioned constants to use instead of auto-detecting from block version
    ///
    /// # Returns
    ///
    /// Returns a `BlockContext` or an error if context building fails.
    pub fn build_context(
        &self,
        is_l3: bool,
        strk_fee_token_address: &ContractAddress,
        eth_fee_token_address: &ContractAddress,
        versioned_constants: Option<VersionedConstants>,
    ) -> Result<BlockContext, FeltConversionError> {
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
            fee_token_addresses: FeeTokenAddresses {
                strk_fee_token_address: *strk_fee_token_address,
                eth_fee_token_address: *eth_fee_token_address,
            },
            is_l3,
        };

        // Get versioned constants - use provided if available, otherwise auto-detect from block version
        let versioned_constants = match versioned_constants {
            Some(constants) => {
                info!("Using provided versioned constants");
                constants
            }
            None => {
                info!("Auto-detecting versioned constants from block version: {:?}", self.starknet_version);
                VersionedConstants::get(&self.starknet_version)
                    .map_err(|_| {
                        FeltConversionError::new_custom(format!(
                            "Failed to get versioned constants for {}",
                            self.starknet_version
                        ))
                    })?
                    .clone()
            }
        };

        // Use maximum bouncer configuration
        // TODO: Add support for taking custom bouncer configuration from the user
        let bouncer_config = BouncerConfig::max();

        Ok(BlockContext::new(block_info, chain_info, versioned_constants, bouncer_config))
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
