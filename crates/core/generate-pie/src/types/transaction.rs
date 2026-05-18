use crate::error::BlockProcessingError;
use crate::types::ProofCollectionResult;
use crate::utils::{get_class_proofs, get_storage_proofs};
use cairo_vm::Felt252;
use log::info;
use rpc_client::types::ContractProof;
use rpc_client::RpcClient;
use shared_execution_objects::central_objects::CentralTransactionExecutionInfo;
use starknet::core::types::BlockId;
use starknet_api::core::{ClassHash, ContractAddress};
use starknet_api::state::StorageKey;
use starknet_types_core::felt::Felt;
use std::collections::{HashMap, HashSet};

fn summarize_accessed_keys_by_address(
    accessed_keys_by_address: &HashMap<ContractAddress, HashSet<StorageKey>>,
) -> String {
    let mut entries: Vec<String> = accessed_keys_by_address
        .iter()
        .map(|(address, keys)| format!("{:#x}({} keys)", address.0.key(), keys.len()))
        .collect();
    entries.sort();

    const LIMIT: usize = 8;
    if entries.len() > LIMIT {
        let omitted = entries.len() - LIMIT;
        entries.truncate(LIMIT);
        entries.push(format!("...(+{} more contracts)", omitted));
    }

    entries.join(", ")
}

fn summarize_class_hashes(class_hashes: &[&Felt252]) -> String {
    let mut entries: Vec<String> = class_hashes.iter().map(|class_hash| format!("{:#x}", class_hash)).collect();
    entries.sort();

    const LIMIT: usize = 8;
    if entries.len() > LIMIT {
        let omitted = entries.len() - LIMIT;
        entries.truncate(LIMIT);
        entries.push(format!("...(+{} more classes)", omitted));
    }

    entries.join(", ")
}

/// Result containing processed transaction data.
#[derive(Debug)]
pub struct TransactionProcessingResult {
    /// Transactions in sequencer::starknet_api format
    pub starknet_api_txns: Vec<starknet_api::executable_transaction::Transaction>,
    pub central_txn_execution_infos: Vec<CentralTransactionExecutionInfo>,
    pub accessed_addresses: HashSet<ContractAddress>,
    pub accessed_classes: HashSet<ClassHash>,
    pub accessed_keys_by_address: HashMap<ContractAddress, HashSet<StorageKey>>,
    pub processed_state_update: crate::state_update::FormattedStateUpdate,
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
        let storage_proof_context = summarize_accessed_keys_by_address(&self.accessed_keys_by_address);
        info!(
            "Storage proof request context for block {}: {} contracts [{}]",
            block_number,
            self.accessed_keys_by_address.len(),
            storage_proof_context
        );

        let previous_block_id = if block_number == 0 { None } else { Some(BlockId::Number(block_number - 1)) };

        // Fetch storage proofs for the current block
        let storage_proofs =
            get_storage_proofs(rpc_client, block_number, &self.accessed_keys_by_address).await.map_err(|e| {
                BlockProcessingError::StorageProof(format!(
                    "Failed to fetch storage proofs for block {} across {} contracts [{}]: {:?}",
                    block_number,
                    self.accessed_keys_by_address.len(),
                    storage_proof_context,
                    e
                ))
            })?;
        info!("Got {} storage proofs for block {}", storage_proofs.len(), block_number);

        // Fetch storage proofs for the previous block
        let previous_storage_proofs = match previous_block_id {
            Some(BlockId::Number(previous_block_id)) => {
                get_storage_proofs(rpc_client, previous_block_id, &self.accessed_keys_by_address).await.map_err(
                    |e| {
                        BlockProcessingError::StorageProof(format!(
                            "Failed to fetch previous storage proofs for block {} (current block {}) across {} contracts [{}]: {:?}",
                            previous_block_id,
                            block_number,
                            self.accessed_keys_by_address.len(),
                            storage_proof_context,
                            e
                        ))
                    },
                )?
            }
            // No previous storage proofs for block 0
            None => HashMap::new(),
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
        let class_hash_context = summarize_class_hashes(&class_hashes);
        info!(
            "Class proof request context for block {}: {} class hashes [{}]",
            block_number,
            class_hashes.len(),
            class_hash_context
        );

        // Fetch class proofs for the current block
        let class_proofs = get_class_proofs(rpc_client, block_number, &class_hashes[..]).await.map_err(|e| {
            BlockProcessingError::ClassProof(format!(
                "Failed to fetch class proofs for block {} across {} class hashes [{}]: {:?}",
                block_number,
                class_hashes.len(),
                class_hash_context,
                e
            ))
        })?;
        info!("Got {} class proofs for {} class hashes", class_proofs.len(), class_hashes.len());

        // Fetch previous class proofs
        let previous_class_proofs = match previous_block_id {
            Some(BlockId::Number(previous_block_id)) => {
                get_class_proofs(rpc_client, previous_block_id, &class_hashes[..]).await.map_err(|e| {
                    BlockProcessingError::ClassProof(format!(
                        "Failed to fetch previous class proofs for block {} (current block {}) across {} class hashes [{}]: {:?}",
                        previous_block_id,
                        block_number,
                        class_hashes.len(),
                        class_hash_context,
                        e
                    ))
                })?
            }
            _ => Default::default(),
        };
        info!("Got {} previous class proofs for {} class hashes", previous_class_proofs.len(), class_hashes.len());

        Ok(ProofCollectionResult { storage_proofs, previous_storage_proofs, class_proofs, previous_class_proofs })
    }
}
