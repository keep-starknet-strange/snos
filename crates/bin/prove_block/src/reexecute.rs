use std::collections::HashMap;
use std::error::Error;

use blockifier::context::BlockContext;
use blockifier::state::cached_state::CachedState;
use blockifier::state::state_api::{State as _, StateReader};
use blockifier::transaction::objects::TransactionExecutionInfo;
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::transaction::transactions::ExecutableTransaction;
use cairo_vm::Felt252;
use reqwest::Url;
use starknet::core::types::BlockId;
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider as _};
use starknet_os::execution::helper::ContractStorageMap;
use starknet_os::starknet::business_logic::fact_state::contract_state_objects::ContractState;
use starknet_os::starknet::business_logic::fact_state::state::SharedState;
use starknet_os::starknet::starknet_storage::{
    CommitmentInfo, CommitmentInfoError, OsSingleStarknetStorage, PerContractStorage,
};
use starknet_os::starkware_utils::commitment_tree::base_types::TreeIndex;
use starknet_os::starkware_utils::commitment_tree::binary_fact_tree::BinaryFactTree as _;
use starknet_os::starkware_utils::commitment_tree::errors::TreeError;
use starknet_os::storage::storage::{HashFunctionType, Storage};

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

pub async fn unpack_blockifier_state_async<
    S: Storage + Send + Sync,
    H: HashFunctionType + Send + Sync,
    SR: StateReader,
>(
    mut blockifier_state: CachedState<SR>,
    shared_state: SharedState<S, H>,
) -> Result<(SharedState<S, H>, SharedState<S, H>), TreeError> {
    let final_state = {
        let state = shared_state.clone();
        state.apply_commitment_state_diff(blockifier_state.to_state_diff()).await?
    };

    let initial_state = shared_state;

    Ok((initial_state, final_state))
}

/// Translates the (final) Blockifier state into an OS-compatible structure.
///
/// This function uses the fact that `CachedState` is a wrapper around a read-only `DictStateReader`
/// object. The initial state is obtained through this read-only view while the final storage
/// is obtained by extracting the state diff from the `CachedState` part.
pub async fn build_starknet_storage_async<
    S: Storage + Send + Sync,
    H: HashFunctionType + Send + Sync,
    SR: StateReader,
>(
    blockifier_state: CachedState<SR>,
    shared_state: SharedState<S, H>,
    block_id: BlockId,
    provider: JsonRpcClient<HttpTransport>,
) -> Result<(ContractStorageMap<ProverPerContractStorage>, SharedState<S, H>, SharedState<S, H>), TreeError> {
    let mut storage_by_address = ContractStorageMap::new();

    // TODO: would be cleaner if `get_leaf()` took &ffc instead of &mut ffc
    let (mut initial_state, mut final_state) = unpack_blockifier_state_async(blockifier_state, shared_state).await?;

    let all_contracts = final_state.contract_addresses();

    for contract_address in all_contracts {
        let initial_contract_state: ContractState = initial_state
            .contract_states
            .get_leaf(&mut initial_state.ffc, contract_address.clone())
            .await?
            .expect("There should be an initial state");
        let final_contract_state: ContractState = final_state
            .contract_states
            .get_leaf(&mut final_state.ffc, contract_address.clone())
            .await?
            .expect("There should be a final state");

        let initial_tree = initial_contract_state.storage_commitment_tree;
        let updated_tree = final_contract_state.storage_commitment_tree;

        // let contract_storage =
        // OsSingleStarknetStorage::new(initial_tree, updated_tree, &[],
        // final_state.ffc.clone()).await.unwrap(); storage_by_address.
        // insert(Felt252::from(contract_address), contract_storage);

        panic!("Fix me or remove");
    }

    Ok((storage_by_address, initial_state, final_state))
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
