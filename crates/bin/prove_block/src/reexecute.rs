use std::collections::HashMap;
use std::error::Error;

use blockifier::context::BlockContext;
use blockifier::state::cached_state::CachedState;
use blockifier::state::state_api::StateReader;
use blockifier::transaction::objects::TransactionExecutionInfo;
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::transaction::transactions::ExecutableTransaction;
use cairo_vm::Felt252;
use reqwest::Url;
use starknet::core::types::BlockId;
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider as _};
use starknet_os::crypto::pedersen::PedersenHash;
use starknet_os::starknet::starknet_storage::{CommitmentInfo, CommitmentInfoError, PerContractStorage, StorageLeaf};
use starknet_os::starkware_utils::commitment_tree::base_types::TreeIndex;
use starknet_os::starkware_utils::commitment_tree::binary_fact_tree::BinaryFactTree as _;
use starknet_os::starkware_utils::commitment_tree::errors::TreeError;
use starknet_os::starkware_utils::commitment_tree::patricia_tree::patricia_tree::PatriciaTree;
use starknet_os::storage::storage::FactFetchingContext;

use crate::rpc_utils::CachedRpcStorage;

/// Reexecute the given transactions through Blockifier
pub fn reexecute_transactions_with_blockifier<S: StateReader>(
    state: &mut CachedState<S>,
    block_context: &BlockContext,
    txs: Vec<Transaction>,
) -> Result<Vec<TransactionExecutionInfo>, Box<dyn Error>> {
    let tx_execution_infos = txs
        .into_iter()
        .map(|tx| {
            let tx_result = tx.execute(state, block_context, true, true);
            match tx_result {
                Err(e) => {
                    panic!("Transaction failed in blockifier: {}", e);
                }
                Ok(info) => {
                    if info.is_reverted() {
                        log::error!("Transaction reverted: {:?}", info.revert_error);
                        log::warn!("TransactionExecutionInfo: {:?}", info);
                        panic!("A transaction reverted during execution: {:?}", info);
                    }
                    info
                }
            }
        })
        .collect();

    Ok(tx_execution_infos)
}

pub(crate) struct ProverPerContractStorage {
    pub provider: JsonRpcClient<HttpTransport>,
    pub block_id: BlockId,
    pub contract_address: Felt252,
    pub previous_tree: PatriciaTree,
    ffc: FactFetchingContext<CachedRpcStorage, PedersenHash>,
    ongoing_storage_changes: HashMap<TreeIndex, Felt252>,
}

impl ProverPerContractStorage {
    pub async fn new(
        block_id: BlockId,
        contract_address: Felt252,
        provider_url: String,
        previous_tree: PatriciaTree,
        accessed_addresses: &[TreeIndex],
        ffc: FactFetchingContext<CachedRpcStorage, PedersenHash>,
    ) -> Result<Self, TreeError> {
        let provider = JsonRpcClient::new(HttpTransport::new(
            Url::parse(provider_url.as_str()).expect("Could not parse provider url"),
        ));

        let mut facts = None;
        let initial_leaves: HashMap<TreeIndex, StorageLeaf> =
            previous_tree.get_leaves(&mut ffc.clone(), accessed_addresses, &mut facts).await?;
        let initial_entries: HashMap<_, _> = initial_leaves.into_iter().map(|(key, leaf)| (key, leaf.value)).collect();

        /*
        let initial_entries =
            initial_storage_values.iter().map(|(key, value)| (key.to_biguint(), *value)).collect(); 
        */

        Ok(Self {
            provider,
            block_id,
            contract_address,
            ongoing_storage_changes: initial_entries,
            previous_tree,
            ffc,
        })
    }
}

impl PerContractStorage for ProverPerContractStorage {
    async fn compute_commitment(&mut self) -> Result<CommitmentInfo, CommitmentInfoError> {
        log::debug!("compute_commitment() for contract {:x}", self.contract_address);
        let final_modifications: Vec<_> = self
            .ongoing_storage_changes
            .clone()
            .into_iter()
            .map(|(key, value)| (key, StorageLeaf::new(value)))
            .collect();

        CommitmentInfo::create_from_modifications(
            self.previous_tree.clone(),
            None,
            final_modifications,
            &mut self.ffc,
        )
        .await
    }

    async fn read(&mut self, key: TreeIndex) -> Option<Felt252> {
        if let Some(value) = self.ongoing_storage_changes.get(&key) {
            return Some(*value);
        } else {
            let key_felt = Felt252::from(key.clone());
            // TODO: this should be fallible
            let value = self.provider.get_storage_at(self.contract_address, key_felt, self.block_id).await.unwrap();
            self.ongoing_storage_changes.insert(key, value);
            Some(value)
        }
    }

    fn write(&mut self, key: TreeIndex, value: Felt252) {
        self.ongoing_storage_changes.insert(key, value);
    }
}
