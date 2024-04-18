use std::cell::RefCell;
use std::rc::Rc;

use blockifier::execution::execution_utils::ReadOnlySegments;
use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;

use super::helper::ExecutionHelperWrapper;
use crate::cairo_types::structs::deprecated::{CallContract, CallContractResponse};
use crate::utils::felt_api2vm;

/// DeprecatedSyscallHandler implementation for execution of system calls in the StarkNet OS
#[derive(Debug)]
pub struct DeprecatedOsSyscallHandler {
    pub exec_wrapper: ExecutionHelperWrapper,
    pub syscall_ptr: Relocatable,
    pub _segments: ReadOnlySegments,
}

/// DeprecatedOsSyscallHandler is wrapped in Rc<RefCell<_>> in order
/// to clone the refrence when entering and exiting vm scopes
#[derive(Clone, Debug)]
pub struct DeprecatedOsSyscallHandlerWrapper {
    pub deprecated_syscall_handler: Rc<RefCell<DeprecatedOsSyscallHandler>>,
}

impl DeprecatedOsSyscallHandlerWrapper {
    // TODO(#69): implement the syscalls
    pub fn new(exec_wrapper: ExecutionHelperWrapper, syscall_ptr: Relocatable) -> Self {
        Self {
            deprecated_syscall_handler: Rc::new(RefCell::new(DeprecatedOsSyscallHandler {
                exec_wrapper,
                syscall_ptr,
                _segments: ReadOnlySegments::default(),
            })),
        }
    }
    pub fn call_contract(&self, syscall_ptr: Relocatable, vm: &mut VirtualMachine) -> Result<(), HintError> {
        let sys_hand = self.deprecated_syscall_handler.as_ref().borrow();
        let result = sys_hand
            .exec_wrapper
            .execution_helper
            .as_ref()
            .borrow_mut()
            .result_iter
            .next()
            .expect("A call execution should have a corresponding result");

        let response_offset = CallContract::response_offset();
        let retdata_size_offset = response_offset + CallContractResponse::retdata_size_offset();
        let retdata_offset = response_offset + CallContractResponse::retdata_offset();

        vm.insert_value((syscall_ptr + retdata_size_offset).unwrap(), result.retdata.0.len()).unwrap();
        let new_segment = vm.add_temporary_segment();
        let retdata = result
            .retdata
            .0
            .iter()
            .map(|sf| {
                let felt = felt_api2vm(*sf);
                MaybeRelocatable::Int(felt)
            })
            .collect();
        vm.load_data(new_segment, &retdata)?;
        vm.insert_value((syscall_ptr + retdata_offset).unwrap(), new_segment)?;

        Ok(())
    }
    #[allow(unused)]
    pub fn delegate_call(&self, syscall_ptr: Relocatable) {
        println!("delegate_call (TODO): {}", syscall_ptr);
    }
    pub fn delegate_l1_handler(&self, syscall_ptr: Relocatable) {
        println!("delegate_l1_handler (TODO): {}", syscall_ptr);
    }
    pub fn deploy(&self, syscall_ptr: Relocatable) {
        println!("deploy (TODO): {}", syscall_ptr);
    }
    pub fn emit_event(&self, syscall_ptr: Relocatable) {
        println!("emit_event (TODO): {}", syscall_ptr);
    }
    pub fn get_block_number(&self, syscall_ptr: Relocatable) {
        println!("get_block_number (TODO): {}", syscall_ptr);
    }
    pub fn get_block_timestamp(&self, syscall_ptr: Relocatable) {
        println!("get_block_timestamp (TODO): {}", syscall_ptr);
    }
    pub fn get_caller_address(&self, syscall_ptr: Relocatable, vm: &mut VirtualMachine) {
        let sys_hand = self.deprecated_syscall_handler.as_ref().borrow();
        let exec_helper = sys_hand.exec_wrapper.execution_helper.as_ref().borrow();
        let caller_address =
            exec_helper.call_info.as_ref().expect("A call should have some call info").call.caller_address.0.key();
        let caller_address = felt_api2vm(*caller_address);

        // TODO: create proper struct for this (similar to GetCallerAddress and friends)
        // TODO: abstract this similar to pythonic _write_syscall_response()

        println!("get_caller_address() syscall, syscall_ptr = {}, caller_address = {}", syscall_ptr, caller_address);

        vm.insert_value((syscall_ptr + 1usize).unwrap(), caller_address).unwrap();
    }
    pub fn get_contract_address(&self, syscall_ptr: Relocatable) {
        println!("get_contract_address (TODO): {}", syscall_ptr);
    }
    pub fn get_sequencer_address(&self, syscall_ptr: Relocatable) {
        println!("get_sequencer_address (TODO): {}", syscall_ptr);
    }
    pub fn get_tx_info(&self, syscall_ptr: Relocatable) {
        println!("get_tx_info (TODO): {}", syscall_ptr);
    }
    pub fn get_tx_signature(&self, syscall_ptr: Relocatable) {
        println!("get_tx_signature (TODO): {}", syscall_ptr);
    }
    pub fn library_call(&self, syscall_ptr: Relocatable) {
        println!("library_call (TODO): {}", syscall_ptr);
    }
    pub fn library_call_l1_handler(&self, syscall_ptr: Relocatable) {
        println!("library_call (TODO): {}", syscall_ptr);
    }
    pub fn replace_class(&self, syscall_ptr: Relocatable) {
        println!("replace_class (TODO): {}", syscall_ptr);
    }
    pub fn send_message_to_l1(&self, syscall_ptr: Relocatable) {
        println!("send_message_to_l1 (TODO): {}", syscall_ptr);
    }
    pub fn storage_read(&self, syscall_ptr: Relocatable, vm: &mut VirtualMachine) -> Result<(), HintError> {
        let sys_hand = self.deprecated_syscall_handler.as_ref().borrow();
        let value = sys_hand.exec_wrapper.execution_helper.as_ref().borrow_mut().execute_code_read_iter.next().ok_or(
            HintError::SyscallError("d: No more storage reads available to replay".to_string().into_boxed_str()),
        )?;

        println!("storage_read syscall, syscall_ptr = {}, value = {}", syscall_ptr, value);

        vm.insert_value((syscall_ptr + 2usize).unwrap(), value).unwrap();

        Ok(())
    }
    pub fn storage_write(&self, syscall_ptr: Relocatable) {
        println!("storage_write (TODO): {}", syscall_ptr);

        let sys_hand = self.deprecated_syscall_handler.as_ref().borrow();
        sys_hand.exec_wrapper.execution_helper.as_ref().borrow_mut().execute_code_read_iter.next();
    }

    pub fn set_syscall_ptr(&self, syscall_ptr: Relocatable) {
        let mut syscall_handler = self.deprecated_syscall_handler.as_ref().borrow_mut();
        syscall_handler.syscall_ptr = syscall_ptr;
    }

    #[allow(unused)]
    pub fn syscall_ptr(&self) -> Relocatable {
        self.deprecated_syscall_handler.as_ref().borrow().syscall_ptr
    }
}

#[cfg(test)]
mod test {
    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::sync::Arc;

    use blockifier::block_context::{BlockContext, FeeTokenAddresses, GasPrices};
    use blockifier::execution::call_info::Retdata;
    use blockifier::execution::entry_point_execution::CallResult;
    use cairo_vm::types::exec_scope::ExecutionScopes;
    use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
    use cairo_vm::vm::vm_core::VirtualMachine;
    use cairo_vm::Felt252;
    use rstest::{fixture, rstest};
    use starknet_api::block::{BlockNumber, BlockTimestamp};
    use starknet_api::core::{ChainId, ContractAddress, PatriciaKey};
    use starknet_api::hash::{StarkFelt, StarkHash};
    use starknet_api::{contract_address, patricia_key};

    use crate::config::STORED_BLOCK_HASH_BUFFER;
    use crate::execution::deprecated_syscall_handler::DeprecatedOsSyscallHandlerWrapper;
    use crate::execution::helper::{ContractStorageMap, ExecutionHelperWrapper};
    use crate::hints::vars;

    #[fixture]
    fn block_context() -> BlockContext {
        BlockContext {
            chain_id: ChainId("SN_GOERLI".to_string()),
            block_number: BlockNumber(1_000_000),
            block_timestamp: BlockTimestamp(1_704_067_200),
            sequencer_address: contract_address!("0x0"),
            fee_token_addresses: FeeTokenAddresses {
                eth_fee_token_address: contract_address!("0x1"),
                strk_fee_token_address: contract_address!("0x2"),
            },
            vm_resource_fee_cost: Arc::new(HashMap::new()),
            gas_prices: GasPrices { eth_l1_gas_price: 1, strk_l1_gas_price: 1 },
            invoke_tx_max_n_steps: 1,
            validate_max_n_steps: 1,
            max_recursion_depth: 50,
        }
    }

    #[fixture]
    fn old_block_number_and_hash(block_context: BlockContext) -> (Felt252, Felt252) {
        (Felt252::from(block_context.block_number.0 - STORED_BLOCK_HASH_BUFFER), Felt252::from(66_u64))
    }

    #[rstest]
    fn test_call_contract(block_context: BlockContext, old_block_number_and_hash: (Felt252, Felt252)) {
        let mut vm = VirtualMachine::new(false);
        vm.set_fp(1);
        vm.add_memory_segment();
        vm.add_memory_segment();

        let syscall_ptr = vm.add_memory_segment();

        let mut exec_scopes = ExecutionScopes::new();

        let execution_infos = Default::default();
        let exec_helper = ExecutionHelperWrapper::new(
            ContractStorageMap::default(),
            execution_infos,
            &block_context,
            old_block_number_and_hash,
        );

        // insert a call result for call_contract to replay. it should insert this into a new temporary
        // segment and insert its size somewhere in syscall_ptr.
        let call_results = vec![CallResult {
            failed: false,
            retdata: Retdata(vec![StarkFelt::THREE, StarkFelt::TWO, StarkFelt::ONE]),
            gas_consumed: 1,
        }];
        exec_helper.execution_helper.as_ref().borrow_mut().result_iter = call_results.into_iter();

        let exec_helper_box = Box::new(exec_helper);
        exec_scopes.insert_box(vars::scopes::EXECUTION_HELPER, exec_helper_box.clone());

        let syscall_handler = DeprecatedOsSyscallHandlerWrapper::new(*exec_helper_box, syscall_ptr);

        syscall_handler.call_contract(syscall_ptr, &mut vm).unwrap();

        // syscall_ptr should have been filled out syscall_ptr segment with a CallContractResponse
        let syscall_data_raw = vm.get_range(syscall_ptr, 7); // TODO: derive from struct size?
        let expected_temp_segment = Relocatable { segment_index: -1, offset: 0 };
        assert_eq!(
            syscall_data_raw,
            vec![
                None,
                None,
                None,
                None,
                None,
                Some(Cow::Borrowed(&MaybeRelocatable::Int(Felt252::THREE))),
                Some(Cow::Borrowed(&MaybeRelocatable::RelocatableValue(expected_temp_segment))),
            ]
        );

        // the retdata should have been copied into the temp segment
        let retdata_raw = vm.get_range(expected_temp_segment, 3);
        assert_eq!(
            retdata_raw,
            vec![
                Some(Cow::Borrowed(&MaybeRelocatable::Int(Felt252::THREE))),
                Some(Cow::Borrowed(&MaybeRelocatable::Int(Felt252::TWO))),
                Some(Cow::Borrowed(&MaybeRelocatable::Int(Felt252::ONE))),
            ]
        );
    }
}
