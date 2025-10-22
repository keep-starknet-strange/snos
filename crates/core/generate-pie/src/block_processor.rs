//! Block Processing Module
//!
//! This module provides functionality for processing individual Starknet blocks
//! and extracting all necessary information for PIE (Program Input/Output) generation.
//!
//! The main entry point is [`collect_single_block_info`] which orchestrates the entire
//! block processing pipeline, from fetching block data to constructing the final OS input.

use crate::error::BlockProcessingError;
use crate::state_update::ContractClassProcessingResult;
use crate::types::{BlockData, CommitmentCalculationResult, TransactionProcessingResult};
use blockifier::context::BlockContext;
use cairo_lang_starknet_classes::casm_contract_class::CasmContractClass;
use log::info;
use num_traits::ToPrimitive;
use rpc_client::RpcClient;
use starknet::core::types::BlockId;
use starknet_api::block::{BlockHash, BlockNumber};
use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress};
use starknet_api::deprecated_contract_class::ContractClass;
use starknet_api::state::StorageKey;
use starknet_os::io::os_input::OsBlockInput;
use starknet_types_core::felt::Felt;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::Write;
use std::time::Duration;
use tokio::time::Instant;
// ================================================================================================
// Type Definitions
// ================================================================================================

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
    #[allow(dead_code)]
    pub previous_block_id: Option<BlockId>,
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
pub async fn collect_single_block_info(
    block_number: u64,
    is_l3: bool,
    strk_fee_token_address: &ContractAddress,
    eth_fee_token_address: &ContractAddress,
    rpc_client: RpcClient,
) -> Result<(BlockInfoResult, Vec<Duration>), BlockProcessingError> {
    info!("Starting block info collection for block {}", block_number);

    // Step 1: Fetch all required block data
    let block_data = BlockData::fetch(block_number, &rpc_client).await?;

    // Step 2: Build block context (only once, reused throughout)
    let block_context = block_data
        .build_context(is_l3, strk_fee_token_address, eth_fee_token_address)
        .map_err(BlockProcessingError::ContextBuilding)?;

    // Step 3: Process transactions and extract execution information
    let (tx_result, mut durations_process_txns) =
        block_data.process_transactions(block_number, &rpc_client, &block_context).await?;

    // Step 4: Collect storage and class proofs
    let start = Instant::now();
    let proofs = tx_result.collect_proofs(block_number, &rpc_client).await?;
    let duration_collect_proofs = start.elapsed();

    // Step 5: Calculate commitment information
    let block_id = BlockId::Number(block_number);
    let commitment_result = proofs.calculate_commitments(block_id).await?;

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

    durations_process_txns.push(duration_collect_proofs);
    Ok((
        BlockInfoResult {
            os_block_input,
            compiled_classes,
            deprecated_compiled_classes,
            accessed_addresses,
            accessed_classes,
            accessed_keys_by_address,
            previous_block_id: if block_number == 0 { None } else { Some(BlockId::Number(block_number - 1)) },
        },
        durations_process_txns,
    ))
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
    block_context: &BlockContext,
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
        prev_block_hash: block_data
            .previous_block
            .as_ref()
            .map(|prev_block| BlockHash(prev_block.block_hash))
            .unwrap_or(BlockHash(Felt::ZERO)), // Return 0x0 when no previous block exists (block 0)
        new_block_hash: BlockHash(block_data.current_block.block_hash),
        old_block_number_and_hash: if block_data.current_block.block_number == 0 {
            None // None in case the current block is the genesis block
        } else {
            Some((BlockNumber(block_data.old_block_number.to_u64().unwrap()), BlockHash(block_data.old_block_hash)))
            // Otherwise, get the old block number and hash
        },
        class_hashes_to_migrate: HashMap::default(), // NOTE: leaving it empty because for 0.14.0 we won't have migration
    }
}
