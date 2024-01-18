use std::cell::RefCell;
use std::rc::Rc;

use blockifier::execution::execution_utils::ReadOnlySegments;
use cairo_vm::types::relocatable::Relocatable;

use super::helper::ExecutionHelperWrapper;

pub struct OsSyscallHandler {
    pub exec_manager: ExecutionHelperWrapper,
    pub syscall_ptr: Relocatable,
    pub segments: ReadOnlySegments,
}

#[derive(Clone)]
pub struct OsSyscallHandlerWrapper {
    pub syscall_handler: Rc<RefCell<OsSyscallHandler>>,
}

impl OsSyscallHandlerWrapper {
    pub fn new(exec_manager: ExecutionHelperWrapper, syscall_ptr: Relocatable) -> Self {
        Self {
            syscall_handler: Rc::new(RefCell::new(OsSyscallHandler {
                exec_manager,
                syscall_ptr,
                segments: ReadOnlySegments::default(),
            })),
        }
    }
}
