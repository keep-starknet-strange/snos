use std::cell::RefCell;
use std::rc::Rc;

use blockifier::execution::execution_utils::ReadOnlySegments;
use cairo_vm::types::relocatable::Relocatable;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;

use super::helper::ExecutionHelperWrapper;
use crate::execution::gas_constants::GET_EXECUTION_INFO_GAS_COST;
use crate::execution::syscall_utils::{execute_syscall, felt_from_ptr, SyscallSelector};
use crate::execution::syscalls::get_execution_info;

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
    pub fn new(exec_wrapper: ExecutionHelperWrapper, syscall_ptr: Relocatable) -> Self {
        Self {
            syscall_handler: Rc::new(RefCell::new(OsSyscallHandler {
                exec_wrapper,
                syscall_ptr: Some(syscall_ptr),
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
        if syscall_handler.syscall_ptr != Some(syscall_ptr_end) {
            return Err(HintError::AssertionFailed("Bad syscall_ptr_end".to_string().into_boxed_str()));
        }

        syscall_handler.syscall_ptr = None;

        Ok(())
    }

    pub fn syscall(&self, vm: &mut VirtualMachine, syscall_ptr: Relocatable) -> Result<(), HintError> {
        let syscall_handler = self.syscall_handler.as_ref().borrow_mut();
        assert_eq!(syscall_handler.syscall_ptr, Some(syscall_ptr));

        let syscall_handler_syscall_ptr =
            &mut syscall_handler.syscall_ptr.ok_or(HintError::AssertionFailed(Box::from("syscall_ptr is None")))?;

        let selector = SyscallSelector::try_from(felt_from_ptr(vm, syscall_handler_syscall_ptr)?)?;

        println!("about to execute syscall: {:?}", selector);

        let ehw = syscall_handler.exec_wrapper.clone();

        match selector {
            SyscallSelector::GetExecutionInfo => {
                execute_syscall(syscall_handler_syscall_ptr, vm, ehw, get_execution_info, GET_EXECUTION_INFO_GAS_COST)
            }
            _ => Err(HintError::CustomHint(format!("Unknown syscall selector: {:?}", selector).into())),
        }
    }
}
