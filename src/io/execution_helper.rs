use std::collections::HashMap;
use std::vec::IntoIter;

use blockifier::execution::cairo1_execution::CallResult;
use blockifier::execution::call_info::CallInfo;
use blockifier::transaction::objects::TransactionExecutionInfo;
use cairo_felt::Felt252;
use cairo_vm::types::relocatable::Relocatable;

use crate::state::storage::{Storage, TrieStorage};
use crate::state::trie::StarkHasher;

#[derive(Default)]
pub struct OsExecutionHelper<'a, H, S>
where
    H: StarkHasher,
    S: Storage,
{
    call_execution_info_ptr: Option<Relocatable>,
    call_info_: Option<CallInfo>,
    call_iterator: IntoIter<&'a CallInfo>,
    deployed_contracts_iterator: IntoIter<Felt252>,
    execute_code_read_iterator: IntoIter<Felt252>,
    old_block_number_and_hash: Option<(Felt252, Felt252)>,
    result_iterator: IntoIter<CallResult>,
    storage_by_address: HashMap<Felt252, OsSingleStarknetStorage<H, S>>,
    tx_execution_info: Option<TransactionExecutionInfo>,
    // use right type
    tx_execution_info_iterator: IntoIter<TransactionExecutionInfo>,
    pub tx_info_ptr: Option<Relocatable>,
}

impl<'a, H: StarkHasher, S: Storage> OsExecutionHelper<'a, H, S> {
    pub fn new(
        tx_execution_infos: Vec<TransactionExecutionInfo>,
        storage_by_address: HashMap<Felt252, OsSingleStarknetStorage<H, S>>,
        old_block_number_and_hash: Option<(Felt252, Felt252)>,
    ) -> Self {
        Self {
            call_execution_info_ptr: None,
            call_info_: None,
            call_iterator: vec![].into_iter(),
            deployed_contracts_iterator: vec![].into_iter(),
            execute_code_read_iterator: vec![].into_iter(),
            old_block_number_and_hash,
            result_iterator: vec![].into_iter(),
            storage_by_address,
            tx_execution_info: None,
            tx_execution_info_iterator: tx_execution_infos.into_iter(),
            tx_info_ptr: None,
        }
    }

    pub fn start_tx(&mut self, tx_info_ptr: Option<Relocatable>) {
        assert!(self.tx_info_ptr.is_none(), "self.tx_info_ptr should be None");
        self.tx_info_ptr = tx_info_ptr;
        assert!(self.tx_execution_info.is_none(), "self.tx_execution_info should be None");
        self.tx_execution_info = self.tx_execution_info_iterator.next();
        // TODO: uncomment this when possible
        // self.call_iterator = self.tx_execution_info.as_ref().unwrap().gen_call_iterator();
    }
}
trait GenCallIter {
    fn gen_call_iterator(&self) -> IntoIter<&CallInfo>;
}
impl GenCallIter for TransactionExecutionInfo {
    fn gen_call_iterator(&self) -> IntoIter<&CallInfo> {
        let mut call_infos = vec![];
        for call_info in self.non_optional_call_infos() {
            call_infos.extend(call_info.gen_call_topology());
        }
        call_infos.into_iter()
    }
}

trait GenCallTopology {
    fn gen_call_topology(&self) -> IntoIter<&CallInfo>;
}

impl GenCallTopology for CallInfo {
    fn gen_call_topology(&self) -> IntoIter<&CallInfo> {
        // Create a vector to store the results
        let mut results = vec![self];

        // Iterate over internal calls, recursively call gen_call_topology, and collect the results
        for call in &self.inner_calls {
            results.extend(call.gen_call_topology());
        }

        // Convert the results vector into an iterator and return it
        results.into_iter()
    }
}

pub struct OsSingleStarknetStorage<H, S>
where
    H: StarkHasher,
    S: Storage,
{
    expected_updated_root: Felt252,
    ffc: FactFetchingContext<H, S>,
    ongoing_storage_changes: HashMap<Felt252, Felt252>,
    previous_tree: TrieStorage,
}
pub struct FactFetchingContext<H, S>
where
    H: StarkHasher,
    S: Storage,
{
    hash_func: H,
    // Prob useless
    n_workers: Option<u8>,
    storage: S,
}
