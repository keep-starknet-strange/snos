use std::vec::IntoIter;

use blockifier::block_context::BlockContext;
use blockifier::execution::call_info::CallInfo;
use blockifier::execution::entry_point_execution::CallResult;
use blockifier::transaction::objects::TransactionExecutionInfo;
use cairo_vm::felt::Felt252;
use cairo_vm::types::relocatable::Relocatable;

use crate::config::STORED_BLOCK_HASH_BUFFER;

pub struct ExecutionHelper {
    call_execution_info_ptr: Option<Relocatable>,
    call_info: Option<CallInfo>,
    call_iter: IntoIter<CallInfo>,
    deployed_contracts_iter: IntoIter<Felt252>,
    execute_code_read_iter: IntoIter<Felt252>,
    pub prev_block_context: Option<BlockContext>,
    result_iter: IntoIter<CallResult>,
    // _storage_by_address: HashMap<Felt252, OsSingleStarknetStorage<H, S>>,
    pub tx_execution_info: Option<TransactionExecutionInfo>,
    pub tx_execution_info_iter: IntoIter<TransactionExecutionInfo>,
    pub tx_info_ptr: Option<Relocatable>,
}

impl ExecutionHelper {
    pub fn new(tx_exec_infos: Vec<TransactionExecutionInfo>, block_context: &BlockContext) -> Self {
        // TODO: look this up in storage_commitment_tree
        let prev_block_context =
            block_context.block_number.0.checked_sub(STORED_BLOCK_HASH_BUFFER).map(|_| block_context.clone());

        Self {
            call_execution_info_ptr: None,
            call_info: None,
            call_iter: vec![].into_iter(),
            deployed_contracts_iter: vec![].into_iter(),
            execute_code_read_iter: vec![].into_iter(),
            prev_block_context,
            result_iter: vec![].into_iter(),
            tx_execution_info: None,
            tx_execution_info_iter: tx_exec_infos.into_iter(),
            tx_info_ptr: None,
        }
    }
    pub fn start_tx(&mut self, tx_info_ptr: Option<Relocatable>) {
        assert!(self.tx_info_ptr.is_none());
        self.tx_info_ptr = tx_info_ptr;
        assert!(self.tx_execution_info.is_none());
        self.tx_execution_info = self.tx_execution_info_iter.next();
        // self.call_iterator =
        // self.tx_execution_info.as_ref().unwrap().non_optional_call_infos().into_iter();
    }
    pub fn end_tx(&mut self) {
        // assert!(self.call_iter.clone().peekable().peek().is_some());
        self.tx_info_ptr = None;
        assert!(self.tx_execution_info.is_some());
        self.tx_execution_info = None;
    }
    pub fn skip_tx(&mut self) {
        self.start_tx(None);
        self.end_tx()
    }
    pub fn enter_call(&mut self, execution_info_ptr: Option<Relocatable>) {
        assert!(self.call_execution_info_ptr.is_none());
        self.call_execution_info_ptr = execution_info_ptr;
        self.assert_iterators_exhausted();

        assert!(self.call_info.is_none());

        // self.call_info_ = self.call_iterator.next();
        // self.deployed_contracts_iterator = self
        //     .call_info_
        //     .as_ref()
        //     .unwrap()
        //     .inner_calls
        //     .iter()
        //     .filter_map(|call| {
        //         if matches!(call.call.entry_point_type, EntryPointType::Constructor) {
        //             Some(Felt252::from_bytes_be(call.call.caller_address.0.key().bytes()))
        //         } else {
        //             None
        //         }
        //     })
        //     .collect::<Vec<Felt252>>()
        //     .into_iter();
        // self.result_iterator = self
        //     .call_info_
        //     .as_ref()
        //     .unwrap()
        //     .inner_calls
        //     .iter()
        //     .map(|call| CallResult {
        //         failed: call.execution.failed,
        //         retdata: call.execution.retdata.clone(),
        //         gas_consumed: call.execution.gas_consumed,
        //     })
        //     .collect::<Vec<CallResult>>()
        //     .into_iter();
        // self.execute_code_read_iterator = self
        //     .call_info_
        //     .as_ref()
        //     .unwrap()
        //     .storage_read_values
        //     .iter()
        //     .map(|felt| Felt252::from_bytes_be(felt.bytes()))
        //     .collect::<Vec<Felt252>>()
        //     .into_iter();
    }
    pub fn exit_call(&mut self) {
        self.call_execution_info_ptr = None;
        self.assert_iterators_exhausted();
        assert!(self.call_info.is_some());
        self.call_info = None;
    }
    pub fn skip_call(&mut self) {
        self.enter_call(None);
        self.exit_call();
    }
    pub fn assert_iterators_exhausted(&self) {
        assert!(self.deployed_contracts_iter.clone().peekable().peek().is_some());
        // TODO: request call info structs be made Clonable
        // assert!(self.result_iter.peekable().peek().is_some());
        assert!(self.execute_code_read_iter.clone().peekable().peek().is_some());
    }
}
