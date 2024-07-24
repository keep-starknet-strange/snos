use std::collections::HashMap;
use std::ops::Deref;
use std::rc::Rc;
use std::vec::IntoIter;

use blockifier::context::BlockContext;
use blockifier::execution::call_info::CallInfo;
use blockifier::execution::entry_point_execution::CallResult;
use blockifier::transaction::objects::TransactionExecutionInfo;
use cairo_vm::types::relocatable::Relocatable;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::Felt252;
use starknet_api::deprecated_contract_class::EntryPointType;
use tokio::sync::RwLock;

use crate::config::STORED_BLOCK_HASH_BUFFER;
use crate::crypto::pedersen::PedersenHash;
use crate::starknet::starknet_storage::{CommitmentInfo, CommitmentInfoError, OsSingleStarknetStorage};
use crate::storage::dict_storage::DictStorage;
use crate::storage::storage::StorageError;

// TODO: make the execution helper generic over the storage and hash function types.
pub type ContractStorageMap<S, H> = HashMap<Felt252, OsSingleStarknetStorage<S, H>>;

/// Maintains the info for executing txns in the OS
#[derive(Debug)]
pub struct ExecutionHelper {
    pub _prev_block_context: Option<BlockContext>,
    // Pointer tx execution info
    pub tx_execution_info_iter: IntoIter<TransactionExecutionInfo>,
    // Tx info for transaction currently being executed
    pub tx_execution_info: Option<TransactionExecutionInfo>,
    // Pointer to the Cairo (deprecated) TxInfo struct
    // Must match the DeprecatedTxInfo pointer for system call validation in 'enter_tx'
    pub tx_info_ptr: Option<Relocatable>,
    // Pointer to the Cairo ExecutionInfo struct of the current call.
    // Must match the ExecutionInfo pointer for system call validation in 'enter_call'
    pub call_execution_info_ptr: Option<Relocatable>,
    // The block number and block hash of the (current_block_number - buffer) block, where
    // buffer=STORED_BLOCK_HASH_BUFFER.
    // It is the hash that is going to be written by this OS run.
    pub old_block_number_and_hash: Option<(Felt252, Felt252)>,
    // Iter for CallInfo
    pub call_iter: IntoIter<CallInfo>,
    // CallInfo for the call currently being executed
    pub call_info: Option<CallInfo>,
    // Iter to the results of the current call's internal calls
    pub result_iter: IntoIter<CallResult>,
    // Iter over contract addresses that were deployed during that call
    pub deployed_contracts_iter: IntoIter<Felt252>,
    // Iter to the read_values array consumed when tx code is executed
    pub execute_code_read_iter: IntoIter<Felt252>,
    // Per-contract storage
    pub storage_by_address: ContractStorageMap<DictStorage, PedersenHash>,
}

/// ExecutionHelper is wrapped in Rc<RefCell<_>> in order
/// to clone the refrence when entering and exiting vm scopes
#[derive(Clone, Debug)]
pub struct ExecutionHelperWrapper {
    pub execution_helper: Rc<RwLock<ExecutionHelper>>,
}

impl ExecutionHelperWrapper {
    pub fn new(
        contract_storage_map: ContractStorageMap<DictStorage, PedersenHash>,
        tx_execution_infos: Vec<TransactionExecutionInfo>,
        block_context: &BlockContext,
        old_block_number_and_hash: (Felt252, Felt252),
    ) -> Self {
        // Block number and block hash (current_block_number - buffer) block buffer=STORED_BLOCK_HASH_BUFFER
        // Hash that is going to be written by this OS run
        let prev_block_context = block_context
            .block_info()
            .block_number
            .0
            .checked_sub(STORED_BLOCK_HASH_BUFFER)
            .map(|_| block_context.clone());

        Self {
            execution_helper: Rc::new(RwLock::new(ExecutionHelper {
                _prev_block_context: prev_block_context,
                tx_execution_info_iter: tx_execution_infos.into_iter(),
                tx_execution_info: None,
                tx_info_ptr: None,
                call_iter: vec![].into_iter(),
                call_execution_info_ptr: None,
                old_block_number_and_hash: Some(old_block_number_and_hash),
                call_info: None,
                result_iter: vec![].into_iter(),
                deployed_contracts_iter: vec![].into_iter(),
                execute_code_read_iter: vec![].into_iter(),
                storage_by_address: contract_storage_map,
            })),
        }
    }

    pub async fn get_old_block_number_and_hash(&self) -> Result<(Felt252, Felt252), HintError> {
        let eh_ref = self.execution_helper.read().await;
        eh_ref.old_block_number_and_hash.ok_or(HintError::AssertionFailed(
            format!("Block number is probably < {STORED_BLOCK_HASH_BUFFER}.").into_boxed_str(),
        ))
    }

    pub async fn start_tx(&self, tx_info_ptr: Option<Relocatable>) {
        let mut eh_ref = self.execution_helper.write().await;
        assert!(eh_ref.tx_info_ptr.is_none());
        eh_ref.tx_info_ptr = tx_info_ptr;
        assert!(eh_ref.tx_execution_info.is_none());
        eh_ref.tx_execution_info = eh_ref.tx_execution_info_iter.next();
        eh_ref.call_iter = eh_ref.tx_execution_info.as_ref().unwrap().gen_call_iterator();
    }
    pub async fn end_tx(&self) {
        let mut eh_ref = self.execution_helper.write().await;
        assert!(eh_ref.call_iter.clone().peekable().peek().is_none());
        eh_ref.tx_info_ptr = None;
        assert!(eh_ref.tx_execution_info.is_some());
        eh_ref.tx_execution_info = None;
    }
    pub async fn skip_tx(&self) {
        self.start_tx(None).await;
        self.end_tx().await
    }
    pub async fn enter_call(&self, execution_info_ptr: Option<Relocatable>) {
        let mut eh_ref = self.execution_helper.write().await;
        assert!(eh_ref.call_execution_info_ptr.is_none());
        eh_ref.call_execution_info_ptr = execution_info_ptr;

        assert_iterators_exhausted(eh_ref.deref());

        assert!(eh_ref.call_info.is_none());
        let call_info = eh_ref.call_iter.next().unwrap();

        // unpack deployed calls
        eh_ref.deployed_contracts_iter = call_info
            .inner_calls
            .iter()
            .filter_map(|call| {
                if matches!(call.call.entry_point_type, EntryPointType::Constructor) {
                    Some(Felt252::from_bytes_be_slice(call.call.storage_address.0.key().bytes()))
                } else {
                    None
                }
            })
            .collect::<Vec<Felt252>>()
            .into_iter();

        // unpack call results
        eh_ref.result_iter = call_info
            .inner_calls
            .iter()
            .map(|call| CallResult {
                failed: call.execution.failed,
                retdata: call.execution.retdata.clone(),
                gas_consumed: call.execution.gas_consumed,
            })
            .collect::<Vec<CallResult>>()
            .into_iter();

        // unpack storage reads
        eh_ref.execute_code_read_iter = call_info
            .storage_read_values
            .iter()
            .map(|felt| Felt252::from_bytes_be_slice(felt.bytes()))
            .collect::<Vec<Felt252>>()
            .into_iter();

        eh_ref.call_info = Some(call_info);
    }
    pub async fn exit_call(&mut self) {
        let mut eh_ref = self.execution_helper.write().await;
        eh_ref.call_execution_info_ptr = None;
        assert_iterators_exhausted(&eh_ref);
        assert!(eh_ref.call_info.is_some());
        eh_ref.call_info = None;
    }
    pub async fn skip_call(&mut self) {
        self.enter_call(None).await;
        self.exit_call().await;
    }

    pub async fn read_storage_for_address(&mut self, address: Felt252, key: Felt252) -> Result<Felt252, StorageError> {
        let mut eh_ref = self.execution_helper.write().await;
        let storage_by_address = &mut eh_ref.storage_by_address;
        if let Some(storage) = storage_by_address.get_mut(&address) {
            return storage.read(key).await.ok_or(StorageError::ContentNotFound);
        }

        Err(StorageError::ContentNotFound)
    }

    pub async fn write_storage_for_address(
        &mut self,
        address: Felt252,
        key: Felt252,
        value: Felt252,
    ) -> Result<(), StorageError> {
        let mut eh_ref = self.execution_helper.write().await;
        let storage_by_address = &mut eh_ref.storage_by_address;
        if let Some(storage) = storage_by_address.get_mut(&address) {
            storage.write(key.to_biguint(), value);
            Ok(())
        } else {
            Err(StorageError::ContentNotFound)
        }
    }

    #[allow(clippy::await_holding_refcell_ref)]
    pub async fn compute_storage_commitments(&self) -> Result<HashMap<Felt252, CommitmentInfo>, CommitmentInfoError> {
        let mut eh_ref = self.execution_helper.write().await;
        let storage_by_address = &mut eh_ref.storage_by_address;

        let mut commitments = HashMap::new();
        for (key, storage) in storage_by_address.iter_mut() {
            log::debug!("key: {} ({})", key.to_hex_string(), key.to_string());
            let commitment_info = storage.compute_commitment().await?;
            commitments.insert(*key, commitment_info);
        }

        Ok(commitments)
    }
}

fn assert_iterators_exhausted(eh_ref: &ExecutionHelper) {
    assert!(eh_ref.deployed_contracts_iter.clone().peekable().peek().is_none());
    assert!(eh_ref.result_iter.clone().peekable().peek().is_none());
    assert!(eh_ref.execute_code_read_iter.clone().peekable().peek().is_none());
}

/// Required for recursive iteration on 'inner_calls'
pub trait GenCallIter {
    fn gen_call_iterator(&self) -> IntoIter<CallInfo>;
}

impl GenCallIter for TransactionExecutionInfo {
    fn gen_call_iterator(&self) -> IntoIter<CallInfo> {
        let mut call_infos = vec![];

        // Determine if we are treating a DEPLOY_ACCOUNT tx. For deployments we need
        // to order call infos differently, __validate_deploy__ is called after the constructor.
        // See https://docs.starknet.io/architecture-and-concepts/accounts/account-functions/#overview
        // for more details.
        let is_deploy = match &self.execute_call_info {
            Some(call_info) => matches!(call_info.call.entry_point_type, EntryPointType::Constructor),
            None => false,
        };

        let call_info_iter = if is_deploy {
            // For DEPLOY_ACCOUNT, validation is performed after executing the constructor
            self.execute_call_info
                .iter()
                .chain(self.validate_call_info.iter())
                .chain(self.fee_transfer_call_info.iter())
        } else {
            // For other tx types, validation comes before the execution of the call
            self.validate_call_info
                .iter()
                .chain(self.execute_call_info.iter())
                .chain(self.fee_transfer_call_info.iter())
        };

        for call_info in call_info_iter {
            call_infos.extend(call_info.clone().gen_call_topology());
        }
        call_infos.into_iter()
    }
}

trait GenCallTopology {
    fn gen_call_topology(self) -> IntoIter<CallInfo>;
}

impl GenCallTopology for CallInfo {
    fn gen_call_topology(self) -> IntoIter<CallInfo> {
        // Create a vector to store the results
        let mut results = vec![self.clone()];

        // Iterate over internal calls, recursively call gen_call_topology, and collect the results
        for call in self.inner_calls.into_iter() {
            results.extend(call.gen_call_topology());
        }

        // Convert the results vector into an iterator and return it
        results.into_iter()
    }
}
