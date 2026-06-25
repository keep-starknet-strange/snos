use crate::constants::{
    is_special_contract_felt, ALIAS_CONTRACT_ADDRESS, BLOCK_HASH_CONTRACT_ADDRESS_FELT, STATEFUL_MAPPING_START,
    STORED_BLOCK_HASH_BUFFER,
};
use crate::conversions::{transaction_receipt_hash, ConversionContext, TryIntoBlockifierAsync};
use crate::error::{BlockProcessingError, FeltConversionError};
use crate::state_update::get_formatted_state_update;
use crate::types::initial_reads::{capture_extended_initial_reads, extend_initial_reads_storage};
use crate::types::TransactionProcessingResult;
use crate::utils::{build_gas_price_vector, compute_block_hash_commitments, get_comprehensive_access_info};
use blockifier::blockifier::config::TransactionExecutorConfig;
use blockifier::blockifier::transaction_executor::{TransactionExecutor, TransactionExecutorError};
use blockifier::blockifier_versioned_constants::VersionedConstants;
use blockifier::bouncer::BouncerConfig;
use blockifier::context::{BlockContext, ChainInfo, FeeTokenAddresses};
use blockifier::state::cached_state::StateMaps;
use blockifier::transaction::objects::TransactionExecutionInfo;
use cairo_vm::Felt252;
use log::{debug, info, warn};
use num_traits::ToPrimitive;
use rpc_client::state_reader::AsyncRpcStateReader;
use rpc_client::utils::execute_with_retry;
use rpc_client::RpcClient;
use shared_execution_objects::central_objects::CentralTransactionExecutionInfo;
use starknet::core::types::{
    BlockId, L1DataAvailabilityMode, MaybePreConfirmedBlockWithReceipts, MaybePreConfirmedBlockWithTxHashes,
    MaybePreConfirmedBlockWithTxs, TransactionReceipt, TransactionResponseFlag,
};
use starknet::providers::Provider;
use starknet_api::block::{
    BlockHash, BlockHashAndNumber, BlockInfo, BlockNumber, BlockTimestamp, GasPrices, StarknetVersion,
};
use starknet_api::contract_address;
use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress};
use starknet_api::executable_transaction::Transaction;
use starknet_api::state::StorageKey;
use starknet_api::versioned_constants_logic::VersionedConstantsTrait;
use starknet_os_types::chain_id::chain_id_from_felt;
use starknet_types_core::felt::Felt;
use std::collections::{HashMap, HashSet};
use std::env;

const BLOCKIFIER_TXN_EXECUTOR_CONFIG_ENV: &str = "SNOS_BLOCKIFIER_TXN_EXECUTOR_CONFIG";
const ALIAS_INITIAL_READ_VALIDATION_RETRIES: usize = 3;

/// Result containing fetched block data needed for processing.
#[derive(Debug)]
pub struct BlockData {
    pub chain_id: starknet_api::core::ChainId,
    pub current_block: starknet::core::types::BlockWithTxs,
    pub current_block_receipts: HashMap<Felt, TransactionReceipt>,
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
        let transaction_flags = [TransactionResponseFlag::IncludeProofFacts];

        // Fetch chain ID from RPC
        let chain_id_result = execute_with_retry("chain_id", || rpc_client.starknet_rpc().chain_id())
            .await
            .map_err(|e| BlockProcessingError::RpcClient(Box::new(e)))?;
        let chain_id = chain_id_from_felt(chain_id_result);
        info!("Provider's chain_id: {}", chain_id);

        // Fetch the current block with transactions
        let current_block = match execute_with_retry("get_block_with_txs(current_block)", || {
            rpc_client.starknet_rpc().get_block_with_txs(block_id, Some(&transaction_flags))
        })
        .await
        .map_err(|e| BlockProcessingError::RpcClient(Box::new(e)))?
        {
            MaybePreConfirmedBlockWithTxs::Block(block_with_txs) => block_with_txs,
            MaybePreConfirmedBlockWithTxs::PreConfirmedBlock(_) => {
                return Err(BlockProcessingError::InvalidBlockState("Block is still pending".to_string()));
            }
        };
        info!("Successfully fetched block with {} transactions", current_block.transactions.len());

        let current_block_receipts = match execute_with_retry("get_block_with_receipts(current_block)", || {
            rpc_client.starknet_rpc().get_block_with_receipts(block_id, None)
        })
        .await
        .map_err(|e| BlockProcessingError::RpcClient(Box::new(e)))?
        {
            MaybePreConfirmedBlockWithReceipts::Block(block_with_receipts) => block_with_receipts
                .transactions
                .into_iter()
                .map(|transaction_with_receipt| {
                    let receipt = transaction_with_receipt.receipt;
                    (transaction_receipt_hash(&receipt), receipt)
                })
                .collect(),
            MaybePreConfirmedBlockWithReceipts::PreConfirmedBlock(_) => {
                return Err(BlockProcessingError::InvalidBlockState("Block receipts are still pending".to_string()));
            }
        };

        // Get starknet version from the block
        let starknet_version = StarknetVersion::try_from(current_block.starknet_version.as_str())
            .map_err(|e| BlockProcessingError::StarknetVersion(format!("Invalid starknet version: {:?}", e)))?;
        info!("Starknet version set to: {:?}", starknet_version);

        // Fetch the previous block if it exists
        let previous_block = match previous_block_id {
            Some(previous_block_id) => match execute_with_retry("get_block_with_tx_hashes(previous_block)", || {
                rpc_client.starknet_rpc().get_block_with_tx_hashes(previous_block_id)
            })
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
        let old_block = match execute_with_retry("get_block_with_tx_hashes(old_block)", || {
            rpc_client.starknet_rpc().get_block_with_tx_hashes(BlockId::Number(old_block_number_u64))
        })
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

        Ok(BlockData {
            chain_id,
            current_block,
            current_block_receipts,
            previous_block,
            old_block_number,
            old_block_hash,
            starknet_version,
        })
    }

    fn blockifier_old_block_number_and_hash(&self) -> Result<Option<BlockHashAndNumber>, BlockProcessingError> {
        Ok(self
            .old_block_number_and_hash(STORED_BLOCK_HASH_BUFFER)?
            .map(|(number, hash)| BlockHashAndNumber { number, hash }))
    }

    pub(crate) fn os_old_block_number_and_hash(
        &self,
    ) -> Result<Option<(BlockNumber, BlockHash)>, BlockProcessingError> {
        self.old_block_number_and_hash(1)
    }

    fn old_block_number_and_hash(
        &self,
        minimum_current_block_number: u64,
    ) -> Result<Option<(BlockNumber, BlockHash)>, BlockProcessingError> {
        old_block_number_and_hash(
            self.current_block.block_number,
            minimum_current_block_number,
            self.old_block_number,
            self.old_block_hash,
        )
    }

    /// Processes transactions and extracts execution information.
    ///
    /// This function converts transactions, executes them using Blockifier, and extracts
    /// the access information needed for OS input construction.
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

        // Create a single conversion context for all transactions
        let conversion_ctx =
            ConversionContext::new(&self.chain_id, block_number, rpc_client, &self.current_block_receipts);

        // Convert transactions to blockifier format
        let mut transactions = Vec::new();
        for (i, transaction) in self.current_block.transactions.iter().enumerate() {
            let transaction =
                transaction.clone().try_into_blockifier_async(&conversion_ctx).await.map_err(|source| {
                    BlockProcessingError::TransactionConversion { transaction_index: i, source: Box::new(source) }
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
        let account_contract_addresses = account_contract_addresses(&starknet_api_txns);
        info!(
            "Collected {} account contract addresses for SNOS initial-read hydration",
            account_contract_addresses.len()
        );

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

        // Blockifier must be pre-processed with the boundary old block hash so `get_block_hash`
        // syscalls observe the same block-hash mapping semantics as the official sequencer path.
        let mut txn_executor = TransactionExecutor::pre_process_and_create(
            blockifier_state_reader.clone(),
            block_context.clone(),
            self.blockifier_old_block_number_and_hash()?,
            config,
        )
        .map_err(|source| BlockProcessingError::TransactionExecutorCreation { source })?;
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

        let mut initial_reads = {
            let block_state =
                txn_executor.block_state.as_ref().ok_or(BlockProcessingError::MissingBlockStateAfterExecution)?;
            capture_extended_initial_reads(block_state, &account_contract_addresses)?
        };

        let central_txn_execution_infos: Vec<CentralTransactionExecutionInfo> =
            txn_execution_infos.clone().into_iter().map(Into::into).collect();

        let access_info = get_comprehensive_access_info(&txn_execution_infos, &initial_reads, self.old_block_number);
        let mut accessed_keys_by_address = access_info.accessed_keys_by_address;
        let accessed_classes_felt = access_info.accessed_class_hashes;
        let mut accessed_addresses_felt: HashSet<Felt> = access_info
            .accessed_contract_addresses
            .into_iter()
            .map(|contract_addr| {
                let felt: Felt = contract_addr.into();
                felt
            })
            .collect();

        info!("Got accessed keys for {} contracts", accessed_keys_by_address.len());

        accessed_addresses_felt.extend(accessed_keys_by_address.keys().map(|contract_addr| {
            let felt: Felt = (*contract_addr).into();
            felt
        }));

        let pre_state_class_hashes = initial_reads
            .class_hashes
            .iter()
            .map(|(contract_address, class_hash)| {
                let address_felt: Felt252 = (*contract_address).into();
                (address_felt, *class_hash)
            })
            .collect::<HashMap<_, _>>();

        let processed_state_update = get_formatted_state_update(
            rpc_client,
            previous_block_id,
            block_id,
            accessed_addresses_felt.clone(),
            accessed_classes_felt.clone(),
            &pre_state_class_hashes,
        )
        .await
        .map_err(BlockProcessingError::StateUpdate)?;
        info!("Fetched processed state update successfully");
        let class_hashes_to_migrate = build_class_hashes_to_migrate(&processed_state_update, &blockifier_state_reader)?;
        apply_pre_migration_compiled_class_hashes(&mut initial_reads, &class_hashes_to_migrate);

        // Revert reasons exactly as committed on-chain (keyed by tx hash). Used for the receipt
        // commitment so the recomputed block hash matches even when the sequencer's revert-reason
        // formatting differs from what re-execution would produce.
        let committed_revert_reasons: HashMap<Felt, String> = self
            .current_block_receipts
            .iter()
            .filter_map(|(tx_hash, receipt)| {
                receipt.execution_result().revert_reason().map(|reason| (*tx_hash, reason.to_string()))
            })
            .collect();

        let block_hash_commitments = compute_block_hash_commitments(
            &starknet_api_txns,
            &txn_execution_infos,
            processed_state_update.thin_state_diff.clone(),
            self.current_block.l1_da_mode,
            &self.starknet_version,
            &committed_revert_reasons,
        )
        .await
        .map_err(|e| {
            BlockProcessingError::StateUpdateProcessing(format!("Failed to compute block hash commitments: {:?}", e))
        })?;
        info!("Computed block hash commitments for block {}", block_number);

        // Convert Felt252 to proper types
        let mut accessed_addresses: HashSet<ContractAddress> = accessed_addresses_felt
            .iter()
            .map(|felt| {
                ContractAddress::try_from(*felt)
                    .map_err(|source| BlockProcessingError::InvalidContractAddress { address: *felt, source })
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
        extend_initial_reads_storage(&blockifier_state_reader, &mut initial_reads, &accessed_keys_by_address)
            .await
            .map_err(|source| BlockProcessingError::InitialReadsExtension { source })?;
        ensure_alias_contract_initial_reads_consistency(
            &blockifier_state_reader,
            &mut initial_reads,
            &processed_state_update.thin_state_diff,
        )
        .await?;

        Ok(TransactionProcessingResult {
            starknet_api_txns,
            central_txn_execution_infos,
            accessed_addresses,
            accessed_classes,
            class_hashes_to_migrate: class_hashes_to_migrate
                .iter()
                .map(|(class_hash, compiled_class_hash_v2, _)| (*class_hash, *compiled_class_hash_v2))
                .collect(),
            accessed_keys_by_address,
            initial_reads,
            block_hash_commitments,
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
            starknet_version: self.starknet_version,
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
        //
        // Note: Currently, we support a single versioned constants file. Future enhancements may
        // support multiple versioned constants files for different Starknet versions (similar to
        // how Madara and Pathfinder handle versioned constants), allowing users to provide a
        // directory or mapping of version -> constants file.
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

fn account_contract_addresses(transactions: &[Transaction]) -> HashSet<ContractAddress> {
    transactions
        .iter()
        .filter_map(|transaction| match transaction {
            Transaction::Account(account_transaction) => Some(account_transaction.sender_address()),
            Transaction::L1Handler(_) => None,
        })
        .collect()
}

fn block_number_from_felt(old_block_number: Felt) -> Result<BlockNumber, BlockProcessingError> {
    old_block_number.to_u64().map(BlockNumber).ok_or(BlockProcessingError::InvalidOldBlockNumber { old_block_number })
}

fn old_block_number_and_hash(
    current_block_number: u64,
    minimum_current_block_number: u64,
    old_block_number: Felt,
    old_block_hash: Felt,
) -> Result<Option<(BlockNumber, BlockHash)>, BlockProcessingError> {
    if current_block_number < minimum_current_block_number {
        return Ok(None);
    }

    Ok(Some((block_number_from_felt(old_block_number)?, BlockHash(old_block_hash))))
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
    let mut alias_keys = HashSet::new();

    // Process accessed contract addresses
    for contract_address in accessed_addresses {
        let address_felt: Felt = (*contract_address).into();

        // Skip address 0x1 (system contract)
        if is_special_contract_felt(address_felt) {
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

        // Skip the block-hash contract address, which is not remapped through the alias contract.
        if class_hash_felt == BLOCK_HASH_CONTRACT_ADDRESS_FELT {
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
        let contract_felt: Felt = (*contract_addr).into();

        // Skip if it's address 0x1 or 0x2.
        if is_special_contract_felt(contract_felt) {
            continue;
        }

        for storage_key in storage_keys {
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
        accessed_keys_by_address.entry(ALIAS_CONTRACT_ADDRESS).or_default().extend(alias_keys);

        info!(
            "Added {} keys to alias contract for storage mapping",
            accessed_keys_by_address.get(&ALIAS_CONTRACT_ADDRESS).unwrap().len()
        );
    }
}

fn alias_counter_storage_key() -> StorageKey {
    StorageKey::try_from(Felt::ZERO).expect("zero should always be a valid storage key")
}

fn validate_alias_contract_initial_reads(
    initial_reads: &StateMaps,
    alias_storage_diffs: &[(StorageKey, Felt)],
) -> Result<(), String> {
    if alias_storage_diffs.is_empty() {
        return Ok(());
    }

    let counter_key = alias_counter_storage_key();
    let current_counter = alias_storage_diffs
        .iter()
        .find_map(|(key, value)| (*key == counter_key).then_some(*value))
        .ok_or_else(|| "alias contract diff is missing the counter key 0x0".to_string())?;
    let previous_counter = initial_reads
        .storage
        .get(&(ALIAS_CONTRACT_ADDRESS, counter_key))
        .copied()
        .ok_or_else(|| "initial reads are missing the alias counter key 0x0".to_string())?;

    let mut alias_entries: Vec<_> =
        alias_storage_diffs.iter().filter(|(key, _)| *key != counter_key).copied().collect();
    alias_entries.sort_by_key(|(_, value)| *value);

    let mut expected_next_alias =
        if previous_counter == Felt::ZERO { STATEFUL_MAPPING_START } else { previous_counter };

    for (alias_key, new_alias_value) in &alias_entries {
        let previous_value = initial_reads
            .storage
            .get(&(ALIAS_CONTRACT_ADDRESS, *alias_key))
            .copied()
            .ok_or_else(|| format!("initial reads are missing alias key {:#x}", Into::<Felt>::into(*alias_key)))?;

        if previous_value != Felt::ZERO {
            return Err(format!(
                "alias key {:#x} should be zero in the previous state but SNOS fetched {:#x}",
                Into::<Felt>::into(*alias_key),
                previous_value
            ));
        }

        if *new_alias_value != expected_next_alias {
            return Err(format!(
                "alias key {:#x} has new value {:#x}, expected next alias {:#x}",
                Into::<Felt>::into(*alias_key),
                *new_alias_value,
                expected_next_alias
            ));
        }

        expected_next_alias += Felt::ONE;
    }

    let expected_counter = if alias_entries.is_empty() && previous_counter == Felt::ZERO {
        STATEFUL_MAPPING_START
    } else if alias_entries.is_empty() {
        previous_counter
    } else {
        expected_next_alias
    };

    if current_counter != expected_counter {
        return Err(format!(
            "alias counter advanced to {:#x}, expected {:#x} from previous counter {:#x} and {} new aliases",
            current_counter,
            expected_counter,
            previous_counter,
            alias_entries.len()
        ));
    }

    Ok(())
}

async fn ensure_alias_contract_initial_reads_consistency(
    state_reader: &AsyncRpcStateReader,
    initial_reads: &mut StateMaps,
    thin_state_diff: &starknet_api::state::ThinStateDiff,
) -> Result<(), BlockProcessingError> {
    let Some(alias_storage_diffs) = thin_state_diff.storage_diffs.get(&ALIAS_CONTRACT_ADDRESS) else {
        return Ok(());
    };

    let alias_storage_diffs: Vec<_> = alias_storage_diffs.iter().map(|(key, value)| (*key, *value)).collect();
    let keys_to_refresh: Vec<_> = alias_storage_diffs.iter().map(|(key, _)| *key).collect();
    for attempt in 1..=ALIAS_INITIAL_READ_VALIDATION_RETRIES {
        match validate_alias_contract_initial_reads(initial_reads, &alias_storage_diffs) {
            Ok(()) => return Ok(()),
            Err(details) if attempt < ALIAS_INITIAL_READ_VALIDATION_RETRIES => {
                warn!(
                    "Alias contract initial reads inconsistent on attempt {}: {}. Refetching {} alias keys.",
                    attempt,
                    details,
                    keys_to_refresh.len()
                );

                for key in &keys_to_refresh {
                    let value = state_reader
                        .get_storage_at_async(ALIAS_CONTRACT_ADDRESS, *key)
                        .await
                        .map_err(|source| BlockProcessingError::InitialReadsExtension { source })?;
                    initial_reads.storage.insert((ALIAS_CONTRACT_ADDRESS, *key), value);
                }
            }
            Err(details) => {
                return Err(BlockProcessingError::StateUpdateProcessing(format!(
                    "Alias contract initial reads remain inconsistent after {} attempts: {}",
                    attempt, details
                )));
            }
        }
    }

    Ok(())
}

fn validate_migrated_compiled_classes(
    processed_state_update: &crate::state_update::FormattedStateUpdate,
    class_hashes_to_migrate: &[(ClassHash, CompiledClassHash, CompiledClassHash)],
) -> Result<(), BlockProcessingError> {
    if processed_state_update.migrated_compiled_classes.len() != class_hashes_to_migrate.len() {
        return Err(BlockProcessingError::StateUpdateProcessing(format!(
            "Migrated compiled classes mismatch: RPC reported {} entries but Blockifier reported {}",
            processed_state_update.migrated_compiled_classes.len(),
            class_hashes_to_migrate.len()
        )));
    }

    for (class_hash, compiled_class_hash_v2, _) in class_hashes_to_migrate {
        let rpc_compiled_class_hash_v2 =
            processed_state_update.migrated_compiled_classes.get(&class_hash.0).copied().ok_or_else(|| {
                BlockProcessingError::StateUpdateProcessing(format!(
                    "Missing migrated compiled class in RPC state update for class hash {:?}",
                    class_hash
                ))
            })?;

        if rpc_compiled_class_hash_v2 != compiled_class_hash_v2.0 {
            return Err(BlockProcessingError::StateUpdateProcessing(format!(
                "Migrated compiled class hash mismatch for {:?}: RPC reported {:?}, Blockifier reported {:?}",
                class_hash, rpc_compiled_class_hash_v2, compiled_class_hash_v2
            )));
        }
    }

    Ok(())
}

fn build_class_hashes_to_migrate(
    processed_state_update: &crate::state_update::FormattedStateUpdate,
    state_reader: &AsyncRpcStateReader,
) -> Result<Vec<(ClassHash, CompiledClassHash, CompiledClassHash)>, BlockProcessingError> {
    let class_hashes_to_migrate = processed_state_update
        .migrated_compiled_classes
        .iter()
        .map(|(class_hash, compiled_class_hash_v2)| {
            let class_hash = ClassHash(*class_hash);
            let compiled_class_hash_v1 =
                state_reader.get_pre_snip34_compiled_class_hash(class_hash).map_err(|source| {
                    BlockProcessingError::StateUpdateProcessing(format!(
                        "Failed to read pre-migration compiled class hash for {:?}: {}",
                        class_hash, source
                    ))
                })?;
            Ok((class_hash, CompiledClassHash(*compiled_class_hash_v2), compiled_class_hash_v1))
        })
        .collect::<Result<Vec<_>, BlockProcessingError>>()?;

    validate_migrated_compiled_classes(processed_state_update, &class_hashes_to_migrate)?;
    Ok(class_hashes_to_migrate)
}

fn apply_pre_migration_compiled_class_hashes(
    initial_reads: &mut blockifier::state::cached_state::StateMaps,
    class_hashes_to_migrate: &[(ClassHash, CompiledClassHash, CompiledClassHash)],
) {
    for (class_hash, _, compiled_class_hash_v1) in class_hashes_to_migrate {
        initial_reads.compiled_class_hashes.insert(*class_hash, *compiled_class_hash_v1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    use starknet::core::types::{BlockStatus, BlockWithTxs, L1DataAvailabilityMode, ResourcePrice};

    fn block_data(current_block_number: u64, old_block_number: Felt, old_block_hash: Felt) -> BlockData {
        BlockData {
            chain_id: starknet_api::core::ChainId::Other("TEST".to_owned()),
            current_block: BlockWithTxs {
                status: BlockStatus::AcceptedOnL2,
                block_hash: Felt::ZERO,
                parent_hash: Felt::ZERO,
                block_number: current_block_number,
                new_root: Felt::ZERO,
                timestamp: 0,
                sequencer_address: Felt::ZERO,
                l1_gas_price: ResourcePrice { price_in_fri: Felt::ZERO, price_in_wei: Felt::ZERO },
                l2_gas_price: ResourcePrice { price_in_fri: Felt::ZERO, price_in_wei: Felt::ZERO },
                l1_data_gas_price: ResourcePrice { price_in_fri: Felt::ZERO, price_in_wei: Felt::ZERO },
                l1_da_mode: L1DataAvailabilityMode::Calldata,
                starknet_version: "0.14.2".to_owned(),
                event_commitment: Felt::ZERO,
                transaction_commitment: Felt::ZERO,
                receipt_commitment: Felt::ZERO,
                state_diff_commitment: Felt::ZERO,
                event_count: 0,
                transaction_count: 0,
                state_diff_length: 0,
                transactions: vec![],
            },
            current_block_receipts: HashMap::new(),
            previous_block: None,
            old_block_number,
            old_block_hash,
            starknet_version: StarknetVersion::V0_14_2,
        }
    }

    #[rstest]
    #[case::before_buffer(STORED_BLOCK_HASH_BUFFER - 1, Felt::ZERO, Felt::from(9_u8), None)]
    #[case::at_buffer(STORED_BLOCK_HASH_BUFFER, Felt::ZERO, Felt::from(9_u8), Some((0_u64, Felt::from(9_u8))))]
    #[case::after_buffer(STORED_BLOCK_HASH_BUFFER + 3, Felt::from(3_u8), Felt::from(12_u8), Some((3_u64, Felt::from(12_u8))))]
    fn blockifier_old_block_number_and_hash_returns_expected_pair(
        #[case] current_block_number: u64,
        #[case] old_block_number: Felt,
        #[case] old_block_hash: Felt,
        #[case] expected: Option<(u64, Felt)>,
    ) {
        let result = block_data(current_block_number, old_block_number, old_block_hash)
            .blockifier_old_block_number_and_hash()
            .unwrap();

        assert_eq!(result.map(|pair| (pair.number.0, pair.hash.0)), expected);
    }

    #[rstest]
    #[case::genesis(0, Felt::ZERO, Felt::from(9_u8), None)]
    #[case::pre_buffer_non_genesis(1, Felt::ZERO, Felt::from(9_u8), Some((0_u64, Felt::from(9_u8))))]
    #[case::after_buffer(STORED_BLOCK_HASH_BUFFER + 3, Felt::from(3_u8), Felt::from(12_u8), Some((3_u64, Felt::from(12_u8))))]
    fn os_old_block_number_and_hash_returns_expected_pair(
        #[case] current_block_number: u64,
        #[case] old_block_number: Felt,
        #[case] old_block_hash: Felt,
        #[case] expected: Option<(u64, Felt)>,
    ) {
        let result =
            block_data(current_block_number, old_block_number, old_block_hash).os_old_block_number_and_hash().unwrap();

        assert_eq!(result.map(|(number, hash)| (number.0, hash.0)), expected);
    }

    #[rstest]
    #[case(STORED_BLOCK_HASH_BUFFER)]
    fn blockifier_old_block_number_and_hash_rejects_non_u64_old_block_number(#[case] current_block_number: u64) {
        let invalid_old_block_number = Felt::from(u128::from(u64::MAX) + 1);
        let old_block_hash = Felt::from(9_u8);

        let blockifier_error = block_data(current_block_number, invalid_old_block_number, old_block_hash)
            .blockifier_old_block_number_and_hash()
            .unwrap_err();

        assert!(matches!(blockifier_error, BlockProcessingError::InvalidOldBlockNumber { .. }));
    }

    #[rstest]
    #[case(1)]
    fn os_old_block_number_and_hash_rejects_non_u64_old_block_number(#[case] current_block_number: u64) {
        let invalid_old_block_number = Felt::from(u128::from(u64::MAX) + 1);
        let old_block_hash = Felt::from(9_u8);
        let os_error = block_data(current_block_number, invalid_old_block_number, old_block_hash)
            .os_old_block_number_and_hash()
            .unwrap_err();

        assert!(matches!(os_error, BlockProcessingError::InvalidOldBlockNumber { .. }));
    }

    #[test]
    fn apply_pre_migration_compiled_class_hashes_replaces_v2_with_v1() {
        let class_hash = ClassHash(Felt::from(11_u8));
        let compiled_class_hash_v2 = CompiledClassHash(Felt::from(22_u8));
        let compiled_class_hash_v1 = CompiledClassHash(Felt::from(33_u8));
        let mut initial_reads = blockifier::state::cached_state::StateMaps::default();
        initial_reads.compiled_class_hashes.insert(class_hash, compiled_class_hash_v2);

        apply_pre_migration_compiled_class_hashes(
            &mut initial_reads,
            &[(class_hash, compiled_class_hash_v2, compiled_class_hash_v1)],
        );

        assert_eq!(initial_reads.compiled_class_hashes.get(&class_hash), Some(&compiled_class_hash_v1));
    }

    #[test]
    fn validate_migrated_compiled_classes_accepts_matching_blockifier_and_rpc_data() {
        let class_hash = ClassHash(Felt::from(11_u8));
        let compiled_class_hash_v2 = CompiledClassHash(Felt::from(22_u8));
        let compiled_class_hash_v1 = CompiledClassHash(Felt::from(33_u8));
        let processed_state_update = crate::state_update::FormattedStateUpdate {
            migrated_compiled_classes: HashMap::from([(class_hash.0, compiled_class_hash_v2.0)]),
            ..Default::default()
        };

        let result = validate_migrated_compiled_classes(
            &processed_state_update,
            &[(class_hash, compiled_class_hash_v2, compiled_class_hash_v1)],
        );

        assert!(result.is_ok());
    }

    #[test]
    fn validate_alias_contract_initial_reads_accepts_consecutive_alias_allocations() {
        let counter_key = alias_counter_storage_key();
        let alias_key_a = StorageKey::try_from(Felt::from_hex_unchecked("0x80")).unwrap();
        let alias_key_b = StorageKey::try_from(Felt::from_hex_unchecked("0x81")).unwrap();
        let mut initial_reads = StateMaps::default();
        initial_reads.storage.insert((ALIAS_CONTRACT_ADDRESS, counter_key), Felt::from(0x80_u64));
        initial_reads.storage.insert((ALIAS_CONTRACT_ADDRESS, alias_key_a), Felt::ZERO);
        initial_reads.storage.insert((ALIAS_CONTRACT_ADDRESS, alias_key_b), Felt::ZERO);

        let alias_storage_diffs = vec![
            (alias_key_a, Felt::from(0x80_u64)),
            (alias_key_b, Felt::from(0x81_u64)),
            (counter_key, Felt::from(0x82_u64)),
        ];

        assert!(validate_alias_contract_initial_reads(&initial_reads, &alias_storage_diffs).is_ok());
    }

    #[test]
    fn validate_alias_contract_initial_reads_rejects_non_zero_previous_alias_value() {
        let counter_key = alias_counter_storage_key();
        let alias_key = StorageKey::try_from(Felt::from_hex_unchecked("0x80")).unwrap();
        let mut initial_reads = StateMaps::default();
        initial_reads.storage.insert((ALIAS_CONTRACT_ADDRESS, counter_key), Felt::from(0x80_u64));
        initial_reads.storage.insert((ALIAS_CONTRACT_ADDRESS, alias_key), Felt::from(0x999_u64));

        let alias_storage_diffs = vec![(alias_key, Felt::from(0x80_u64)), (counter_key, Felt::from(0x81_u64))];

        let error = validate_alias_contract_initial_reads(&initial_reads, &alias_storage_diffs).unwrap_err();
        assert!(error.contains("should be zero in the previous state"));
    }

    #[test]
    fn validate_alias_contract_initial_reads_rejects_counter_one_too_low() {
        let counter_key = alias_counter_storage_key();
        let alias_key = StorageKey::try_from(Felt::from_hex_unchecked("0x80")).unwrap();
        let mut initial_reads = StateMaps::default();
        initial_reads.storage.insert((ALIAS_CONTRACT_ADDRESS, counter_key), Felt::from(0x80_u64));
        initial_reads.storage.insert((ALIAS_CONTRACT_ADDRESS, alias_key), Felt::ZERO);

        let alias_storage_diffs = vec![(alias_key, Felt::from(0x80_u64)), (counter_key, Felt::from(0x80_u64))];

        let error = validate_alias_contract_initial_reads(&initial_reads, &alias_storage_diffs).unwrap_err();
        assert!(error.contains("alias counter advanced"));
    }
}
