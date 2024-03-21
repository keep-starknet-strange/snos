use std::cell::RefCell;
use std::rc::Rc;

use blockifier::execution::execution_utils::ReadOnlySegments;
use cairo_vm::Felt252;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::Relocatable;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use num_traits::Zero;

use super::helper::ExecutionHelperWrapper;
use crate::execution::syscall_utils::{execute_syscall, SyscallSelector};
use crate::execution::syscalls::get_execution_info;

/// DeprecatedSyscallHandlerimplementation for execution of system calls in the StarkNet OS
#[derive(Debug)]
pub struct OsSyscallHandler {
    pub exec_wrapper: ExecutionHelperWrapper,
    pub syscall_ptr: Relocatable,
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
                syscall_ptr,
                segments: ReadOnlySegments::default(),
            })),
        }
    }
    pub fn set_syscall_ptr(&self, syscall_ptr: Relocatable) {
        let mut syscall_handler = self.syscall_handler.as_ref().borrow_mut();
        syscall_handler.syscall_ptr = syscall_ptr;
    }

    pub fn syscall_ptr(&self) -> Relocatable {
        self.syscall_handler.as_ref().borrow().syscall_ptr
    }

    pub fn syscall(
        &self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), HintError> {
        let mut syscall_handler = self.syscall_handler.as_ref().borrow_mut();
        assert_eq!(syscall_handler.syscall_ptr, syscall_ptr);

        let selector = SyscallSelector::try_from(vm.get_integer(syscall_ptr)?.into_owned())?;

        println!("about to execute syscall: {:?}", selector);

        let ehw = syscall_handler.exec_wrapper.clone();

        match selector {
            SyscallSelector::GetExecutionInfo => {
                execute_syscall(&mut syscall_handler.syscall_ptr, vm, ehw, get_execution_info, Felt252::ZERO)
            }
            _ => Err(HintError::CustomHint(format!("Unknown syscall selector: {:?}", selector).into())),
        }
    }
}
