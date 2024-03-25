use std::cell::RefCell;
use std::rc::Rc;

use blockifier::execution::execution_utils::ReadOnlySegments;
use cairo_type_derive::FieldOffsetGetters;
use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;

use super::helper::ExecutionHelperWrapper;

/// DeprecatedSyscallHandlerimplementation for execution of system calls in the StarkNet OS
#[derive(Debug)]
pub struct DeprecatedOsSyscallHandler {
    pub exec_wrapper: ExecutionHelperWrapper,
    pub syscall_ptr: Relocatable,
    pub segments: ReadOnlySegments,
}

/// DeprecatedOsSyscallHandler is wrapped in Rc<RefCell<_>> in order
/// to clone the refrence when entering and exiting vm scopes
#[derive(Clone, Debug)]
pub struct DeprecatedOsSyscallHandlerWrapper {
    pub deprecated_syscall_handler: Rc<RefCell<DeprecatedOsSyscallHandler>>,
}

#[derive(FieldOffsetGetters)]
pub struct CallContractRequest {
    selector: Felt252,
    contract_address: Felt252,
    function_selector: Felt252,
    calldata_size: Felt252,
    calldata: Relocatable,
}
#[derive(FieldOffsetGetters)]
pub struct CallContractResponse {
    retdata_size: Felt252,
    retdata: Relocatable,
}
#[derive(FieldOffsetGetters)]
pub struct CallContract {
    request: CallContractRequest,
    response: CallContractResponse,
}

impl DeprecatedOsSyscallHandlerWrapper {
    // TODO(#69): implement the syscalls
    pub fn new(exec_wrapper: ExecutionHelperWrapper, syscall_ptr: Relocatable) -> Self {
        Self {
            deprecated_syscall_handler: Rc::new(RefCell::new(DeprecatedOsSyscallHandler {
                exec_wrapper,
                syscall_ptr,
                segments: ReadOnlySegments::default(),
            })),
        }
    }
    pub fn call_contract(&self, syscall_ptr: Relocatable, vm: &mut VirtualMachine) -> Result<(), HintError> {
        println!("call_contract (TODO): {}", syscall_ptr);

        let sys_hand = self.deprecated_syscall_handler.as_ref().borrow();
        let result = sys_hand.exec_wrapper.execution_helper.as_ref().borrow_mut().result_iter.next()
            .expect("A call execution should have a corresponding result"); // TODO

        let response_offset = CallContract::response_offset() * 5; // TODO: response_offset() doesn't seem to take sizeof(CallContractRequest) into account
        let retdata_size_offset = response_offset + CallContractResponse::retdata_size_offset();
        let retdata_offset = response_offset + CallContractResponse::retdata_offset();

        vm.insert_value((syscall_ptr + retdata_size_offset).unwrap(), result.retdata.0.len()).unwrap();
        let new_segment = vm.add_memory_segment();
        let retdata = result.retdata.0.iter().map(|sf| {
            // TODO: better way to StarkFelt -> Felt252?
            let felt = Felt252::from_hex(&sf.to_string()).unwrap();
            MaybeRelocatable::Int(felt)
        }).collect();
        vm.load_data(new_segment, &retdata)?;
        vm.insert_value((syscall_ptr + retdata_offset).unwrap(), new_segment)?;

        Ok(())
    }
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
    pub fn get_caller_address(&self, syscall_ptr: Relocatable) {
        println!("get_caller_address (TODO): {}", syscall_ptr);
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
    pub fn storage_read(&self, syscall_ptr: Relocatable) {
        println!("storage_read (TODO): {}", syscall_ptr);
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

    pub fn syscall_ptr(&self) -> Relocatable {
        self.deprecated_syscall_handler.as_ref().borrow().syscall_ptr
    }
}
