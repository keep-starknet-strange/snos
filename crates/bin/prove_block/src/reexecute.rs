use std::collections::HashMap;
use std::error::Error;
use std::str::FromStr;

use blockifier::context::BlockContext;
use blockifier::state::cached_state::CachedState;
use blockifier::state::state_api::StateReader;
use blockifier::transaction::objects::TransactionExecutionInfo;
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::transaction::transactions::ExecutableTransaction;
use cairo_vm::Felt252;
use num_bigint::{BigUint, ToBigUint};
use reqwest::Url;
use starknet::core::types::BlockId;
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider as _};
use starknet_os::config::DEFAULT_STORAGE_TREE_HEIGHT;
use starknet_os::crypto::pedersen::PedersenHash;
use starknet_os::starknet::starknet_storage::{CommitmentInfo, CommitmentInfoError, PerContractStorage};
use starknet_os::starkware_utils::commitment_tree::base_types::{Length, NodePath, TreeIndex};
use starknet_os::starkware_utils::commitment_tree::errors::TreeError;
use starknet_os::starkware_utils::commitment_tree::inner_node_fact::InnerNodeFact;
use starknet_os::starkware_utils::commitment_tree::patricia_tree::nodes::{BinaryNodeFact, EdgeNodeFact};
use starknet_os::storage::dict_storage::DictStorage;
use starknet_os::storage::storage::{Fact, HashFunctionType};

use crate::rpc_utils::{PathfinderProof, TrieNode};

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
    provider: JsonRpcClient<HttpTransport>,
    block_id: BlockId,
    contract_address: Felt252,
    previous_tree_root: Felt252,
    storage_proof: PathfinderProof,
    previous_storage_proof: PathfinderProof,
    ongoing_storage_changes: HashMap<TreeIndex, Felt252>,
}

impl ProverPerContractStorage {
    pub fn new(
        block_id: BlockId,
        contract_address: Felt252,
        provider_url: String,
        previous_tree_root: Felt252,
        storage_proof: PathfinderProof,
        previous_storage_proof: PathfinderProof,
    ) -> Result<Self, TreeError> {
        let provider = JsonRpcClient::new(HttpTransport::new(
            Url::parse(provider_url.as_str()).expect("Could not parse provider url"),
        ));

        Ok(Self {
            provider,
            block_id,
            contract_address,
            previous_tree_root,
            storage_proof,
            previous_storage_proof,
            ongoing_storage_changes: Default::default(),
        })
    }
}

pub(crate) fn format_commitment_facts<H: HashFunctionType>(
    trie_nodes: &[Vec<TrieNode>],
) -> HashMap<Felt252, Vec<Felt252>> {
    let mut facts = HashMap::new();

    for nodes in trie_nodes {
        for node in nodes {
            let (key, fact_as_tuple) = match node {
                TrieNode::Binary { left, right } => {
                    // log::info!("writing binary node...");
                    let fact = BinaryNodeFact::new((*left).into(), (*right).into())
                        .expect("storage proof endpoint gave us an invalid binary node");

                    // TODO: the hash function should probably be split from the Fact trait.
                    //       we use a placeholder for the Storage trait in the meantime.
                    let node_hash = Felt252::from(<BinaryNodeFact as Fact<DictStorage, H>>::hash(&fact));
                    let fact_as_tuple = <BinaryNodeFact as InnerNodeFact<DictStorage, H>>::to_tuple(&fact);
                    log::debug!(
                        "  Inserting binary node {} - left: {}, right: {}",
                        node_hash.to_biguint(),
                        left.to_biguint(),
                        right.to_biguint()
                    );

                    (node_hash, fact_as_tuple)
                }
                TrieNode::Edge { child, path } => {
                    // log::info!("writing edge node...");
                    let fact = EdgeNodeFact::new((*child).into(), NodePath(path.value.to_biguint()), Length(path.len))
                        .expect("storage proof endpoint gave us an invalid edge node");
                    // TODO: the hash function should probably be split from the Fact trait.
                    //       we use a placeholder for the Storage trait in the meantime.
                    let node_hash = Felt252::from(<EdgeNodeFact as Fact<DictStorage, PedersenHash>>::hash(&fact));
                    let fact_as_tuple = <EdgeNodeFact as InnerNodeFact<DictStorage, PedersenHash>>::to_tuple(&fact);
                    log::debug!("  Inserting edge node {} - bottom: {}", node_hash.to_biguint(), child.to_biguint());
                    (node_hash, fact_as_tuple)
                }
            };

            let fact_as_tuple_of_felts: Vec<_> = fact_as_tuple.into_iter().map(Felt252::from).collect();
            facts.insert(Felt252::from(key), fact_as_tuple_of_felts);
        }
    }

    facts
}

impl PerContractStorage for ProverPerContractStorage {
    async fn compute_commitment(&mut self) -> Result<CommitmentInfo, CommitmentInfoError> {
        // TODO: error code
        let contract_data =
            self.storage_proof.contract_data.as_ref().expect("storage proof should have a contract_data field");
        let updated_root = contract_data.root;
        log::debug!("formatting commitment facts");

        let commitment_facts = format_commitment_facts::<PedersenHash>(&contract_data.storage_proofs);

        let previous_contract_data = self
            .previous_storage_proof
            .contract_data
            .as_ref()
            .expect("previous storage proof should have a contract_data field");

        log::debug!("formatting previous commitment facts");
        let previous_commitment_facts = format_commitment_facts::<PedersenHash>(&previous_contract_data.storage_proofs);

        let commitment_facts = commitment_facts.into_iter().chain(previous_commitment_facts.into_iter()).collect();

        Ok(CommitmentInfo {
            previous_root: self.previous_tree_root,
            updated_root,
            tree_height: DEFAULT_STORAGE_TREE_HEIGHT,
            commitment_facts,
        })
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
