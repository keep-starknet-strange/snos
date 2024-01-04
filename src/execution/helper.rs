use std::marker::Copy;
use std::slice::Iter;
use std::vec::IntoIter;

use blockifier::block_context::BlockContext;
use blockifier::execution::call_info::{CallInfo, CallInfoIter};
use blockifier::execution::entry_point_execution::CallResult;
use blockifier::transaction::objects::TransactionExecutionInfo;
use cairo_vm::felt::Felt252;
use cairo_vm::types::relocatable::Relocatable;

use crate::config::STORED_BLOCK_HASH_BUFFER;

pub struct ExecutionHelper {
    pub tx_exec_infos: IntoIter<TransactionExecutionInfo>,
    // pub prev_block_context: Option<BlockContext>,
    // pub tx_execution_info_iterator: T,
    // _call_execution_info_ptr: Option<Relocatable>,
    // _call_info: Option<CallInfo>,
    // _call_iterator: IntoIter<CallInfo>,
    // _deployed_contracts_iterator: IntoIter<Felt252>,
    // _execute_code_read_iterator: IntoIter<Felt252>,
    // _result_iterator: IntoIter<CallResult>,
    // // _storage_by_address: HashMap<Felt252, OsSingleStarknetStorage<H, S>>,
    // pub tx_execution_info: Option<TransactionExecutionInfo>,
    // tx_info_ptr: Option<Relocatable>,
}

impl ExecutionHelper {
    pub fn new(tx_exec_infos: Vec<TransactionExecutionInfo>, block_context: &BlockContext) -> Self {
        // TODO: look this up in storage_commitment_tree
        let prev_block_context =
            block_context.block_number.0.checked_sub(STORED_BLOCK_HASH_BUFFER).map(|_| block_context.clone());

        // _call_execution_info_ptr: None,
        // _call_info: None,
        // _call_iterator: vec![].into_iter(),
        // _deployed_contracts_iterator: vec![].into_iter(),
        // _execute_code_read_iterator: vec![].into_iter(),
        // _prev_block_context,
        // _result_iterator: vec![].into_iter(),
        // tx_execution_info: None,
        // tx_execution_info_iterator: tx_execution_infos.iter_mut(),
        // tx_info_ptr: None,
        // Self { prev_block_context, tx_execution_info_iterator: tx_execution_infos.into_iter() }
        Self { tx_exec_infos: tx_exec_infos.into_iter() }
    }

    pub fn start_tx(&mut self, tx_info_ptr: Option<Relocatable>) {
        println!("WE IN HERE!!!!");
        // assert!(self.tx_info_ptr.is_none(), "self.tx_info_ptr should be None");
        // self.tx_info_ptr = tx_info_ptr;
        // assert!(self.tx_execution_info.is_none(), "self.tx_execution_info should be None");
        // self.tx_execution_info = self.tx_execution_info_iterator.next();
        // self.call_iterator = self.tx_execution_info.as_ref().unwrap().gen_call_iterator();
    }
}

// assert self.tx_info_ptr is None
// self.tx_info_ptr = tx_info_ptr

// assert self.tx_execution_info is None
// self.tx_execution_info = next(self.tx_execution_info_iterator)
// self.call_iterator = self.tx_execution_info.gen_call_iterator()
