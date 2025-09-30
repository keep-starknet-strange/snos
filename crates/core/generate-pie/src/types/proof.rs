use crate::error::BlockProcessingError;
use crate::utils::{compute_class_commitment, format_commitment_facts};
use cairo_vm::Felt252;
use log::{debug, info};
use rpc_client::types::ContractProof;
use rpc_client::RpcClient;
use starknet::core::types::BlockId;
use starknet::providers::Provider;
use starknet_api::core::ContractAddress;
use starknet_os::io::os_input::CommitmentInfo;
use starknet_patricia::hash::hash_trait::HashOutput;
use starknet_patricia::patricia_merkle_tree::types::SubTreeHeight;
use starknet_types_core::felt::Felt;
use std::collections::HashMap;

/// Result containing collected proof data.
pub struct ProofCollectionResult {
    pub storage_proofs: HashMap<Felt, ContractProof>,
    pub previous_storage_proofs: HashMap<Felt, ContractProof>,
    pub class_proofs: HashMap<Felt, rpc_client::types::ClassProof>,
    pub previous_class_proofs: HashMap<Felt, rpc_client::types::ClassProof>,
}

/// Result containing calculated commitment information.
pub struct CommitmentCalculationResult {
    pub address_to_storage_commitment_info: HashMap<ContractAddress, CommitmentInfo>,
    pub contract_state_commitment_info: CommitmentInfo,
    pub contract_class_commitment_info: CommitmentInfo,
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
