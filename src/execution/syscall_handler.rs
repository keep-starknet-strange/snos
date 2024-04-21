use std::cell::RefCell;
use std::rc::Rc;

use blockifier::execution::execution_utils::ReadOnlySegments;
use cairo_vm::types::relocatable::Relocatable;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;

use super::helper::ExecutionHelperWrapper;
use crate::execution::constants::{
    CALL_CONTRACT_GAS_COST, EMIT_EVENT_GAS_COST, GET_BLOCK_HASH_GAS_COST, GET_EXECUTION_INFO_GAS_COST,
    SEND_MESSAGE_TO_L1_GAS_COST, STORAGE_READ_GAS_COST, STORAGE_WRITE_GAS_COST,
};
use crate::execution::syscall_utils::{execute_syscall, felt_from_ptr, SyscallSelector};
use crate::execution::syscalls::{
    call_contract, emit_event, get_block_hash, get_execution_info, send_message_to_l1, storage_read, storage_write,
};

/// DeprecatedSyscallHandlerimplementation for execution of system calls in the StarkNet OS
#[derive(Debug)]
pub struct OsSyscallHandler {
    pub exec_wrapper: ExecutionHelperWrapper,
    pub syscall_ptr: Option<Relocatable>,
    pub segments: ReadOnlySegments,
}

/// OsSyscallHandler is wrapped in Rc<RefCell<_>> in order
/// to clone the refrence when entering and exiting vm scopes
#[derive(Clone, Debug)]
pub struct OsSyscallHandlerWrapper {
    pub syscall_handler: Rc<RefCell<OsSyscallHandler>>,
}

impl OsSyscallHandlerWrapper {
    pub fn new(exec_wrapper: ExecutionHelperWrapper) -> Self {
        Self {
            syscall_handler: Rc::new(RefCell::new(OsSyscallHandler {
                exec_wrapper,
                syscall_ptr: None,
                segments: ReadOnlySegments::default(),
            })),
        }
    }
    pub fn set_syscall_ptr(&self, syscall_ptr: Relocatable) {
        let mut syscall_handler = self.syscall_handler.as_ref().borrow_mut();
        syscall_handler.syscall_ptr = Some(syscall_ptr);
    }

    pub fn syscall_ptr(&self) -> Option<Relocatable> {
        self.syscall_handler.as_ref().borrow().syscall_ptr
    }

    pub fn validate_and_discard_syscall_ptr(&self, syscall_ptr_end: Relocatable) -> Result<(), HintError> {
        let mut syscall_handler = self.syscall_handler.as_ref().borrow_mut();
        let syscall_ptr = syscall_handler.syscall_ptr.ok_or(HintError::CustomHint(Box::from("syscall_ptr is None")))?;
        assert_eq!(syscall_ptr, syscall_ptr_end, "Bad syscall_ptr_end.");
        syscall_handler.syscall_ptr = None;
        Ok(())
    }

    pub fn syscall(&self, vm: &mut VirtualMachine, syscall_ptr: Relocatable) -> Result<(), HintError> {
        let mut syscall_handler = self.syscall_handler.as_ref().borrow_mut();
        let syscall_handler_syscall_ptr =
            &mut syscall_handler.syscall_ptr.ok_or(HintError::CustomHint(Box::from("syscall_ptr is None")))?;

        assert_eq!(*syscall_handler_syscall_ptr, syscall_ptr);

        let selector = SyscallSelector::try_from(felt_from_ptr(vm, syscall_handler_syscall_ptr)?)?;

        println!("about to execute: {:?}", selector);

        let ehw = &mut syscall_handler.exec_wrapper;

        match selector {
            SyscallSelector::CallContract => {
                execute_syscall(syscall_handler_syscall_ptr, vm, ehw, call_contract, CALL_CONTRACT_GAS_COST)
            }
            SyscallSelector::EmitEvent => {
                execute_syscall(syscall_handler_syscall_ptr, vm, ehw, emit_event, EMIT_EVENT_GAS_COST)
            }
            SyscallSelector::GetBlockHash => {
                execute_syscall(syscall_handler_syscall_ptr, vm, ehw, get_block_hash, GET_BLOCK_HASH_GAS_COST)
            }
            SyscallSelector::GetExecutionInfo => {
                execute_syscall(syscall_handler_syscall_ptr, vm, ehw, get_execution_info, GET_EXECUTION_INFO_GAS_COST)
            }
            SyscallSelector::StorageRead => {
                execute_syscall(syscall_handler_syscall_ptr, vm, ehw, storage_read, STORAGE_READ_GAS_COST)
            }
            SyscallSelector::StorageWrite => {
                execute_syscall(syscall_handler_syscall_ptr, vm, ehw, storage_write, STORAGE_WRITE_GAS_COST)
            }
            SyscallSelector::SendMessageToL1 => {
                execute_syscall(syscall_handler_syscall_ptr, vm, ehw, send_message_to_l1, SEND_MESSAGE_TO_L1_GAS_COST)
            }
            _ => Err(HintError::CustomHint(format!("Unknown syscall selector: {:?}", selector).into())),
        }?;

        syscall_handler.syscall_ptr = Some(*syscall_handler_syscall_ptr);

        Ok(())
    }
}
