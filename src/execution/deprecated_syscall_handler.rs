use std::cell::RefCell;
use std::rc::Rc;

use blockifier::execution::execution_utils::ReadOnlySegments;
use cairo_vm::types::relocatable::Relocatable;

pub struct DeprecatedOsSyscallHandler {
    pub dep_syscall_ptr: Relocatable,
    pub ro_segments: ReadOnlySegments,
}

#[derive(Clone)]
pub struct DeprecatedOsSyscallHandlerManager {
    pub deprecated_syscall_handler: Rc<RefCell<DeprecatedOsSyscallHandler>>,
}

impl DeprecatedOsSyscallHandlerManager {
    pub fn new(dep_syscall_ptr: Relocatable) -> Self {
        Self {
            deprecated_syscall_handler: Rc::new(RefCell::new(DeprecatedOsSyscallHandler {
                dep_syscall_ptr,
                ro_segments: ReadOnlySegments::default(),
            })),
        }
    }
}
