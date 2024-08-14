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
use starknet_os::starknet::starknet_storage::{
    CommitmentInfo, CommitmentInfoError, PerContractStorage,
};
use starknet_os::starkware_utils::commitment_tree::base_types::TreeIndex;

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
    ongoing_storage_changes: HashMap<TreeIndex, Felt252>,
}

impl ProverPerContractStorage {
    pub fn new(block_id: BlockId, contract_address: Felt252, provider_url: String) -> Self {
        let provider = JsonRpcClient::new(HttpTransport::new(
            Url::parse(provider_url.as_str()).expect("Could not parse provider url"),
        ));

        Self { provider, block_id, contract_address, ongoing_storage_changes: HashMap::new() }
    }
}

impl PerContractStorage for ProverPerContractStorage {
    async fn compute_commitment(&mut self) -> Result<CommitmentInfo, CommitmentInfoError> {
        // TODO: take inspiration from OsSingleStarknetStorage
        Ok(Default::default())
    }

    async fn read(&mut self, key: TreeIndex) -> Option<Felt252> {
        log::debug!("PCS reading from {:x} / {:x}", self.contract_address, key);

        if let Some(value) = self.ongoing_storage_changes.get(&key) {
            log::debug!("    got changed value {:x}", value);
            return Some(*value);
        }

        let key = Felt252::from(key);
        // TODO: this should be fallible
        let value = self.provider.get_storage_at(self.contract_address, key, self.block_id).await.unwrap();
        log::debug!("    got unchanged value from RPC: {:x}", value);
        Some(value)
    }

    fn write(&mut self, key: TreeIndex, value: Felt252) {
        self.ongoing_storage_changes.insert(key, value);
    }
}
