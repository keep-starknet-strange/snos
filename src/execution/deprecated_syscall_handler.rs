use std::cell::RefCell;
use std::rc::Rc;

use blockifier::execution::execution_utils::ReadOnlySegments;
use cairo_vm::types::relocatable::Relocatable;

use super::helper::ExecutionHelperWrapper;

#[derive(Debug)]
pub struct DeprecatedOsSyscallHandler {
    pub exec_helper: ExecutionHelperWrapper,
    pub syscall_ptr: Relocatable,
    pub segments: ReadOnlySegments,
}

#[derive(Clone, Debug)]
pub struct DeprecatedOsSyscallHandlerWrapper {
    pub deprecated_syscall_handler: Rc<RefCell<DeprecatedOsSyscallHandler>>,
}

impl DeprecatedOsSyscallHandlerWrapper {
    pub fn new(exec_helper: ExecutionHelperWrapper, syscall_ptr: Relocatable) -> Self {
        Self {
            deprecated_syscall_handler: Rc::new(RefCell::new(DeprecatedOsSyscallHandler {
                exec_helper,
                syscall_ptr,
                segments: ReadOnlySegments::default(),
            })),
        }
    }
}
