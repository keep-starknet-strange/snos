use std::cell::RefCell;
use std::rc::Rc;

use blockifier::execution::execution_utils::ReadOnlySegments;
use cairo_vm::types::relocatable::Relocatable;

pub struct OsSyscallHandler {
    pub syscall_ptr: Relocatable,
    pub ro_segments: ReadOnlySegments,
}

#[derive(Clone)]
pub struct OsSyscallHandlerManager {
    pub syscall_handler: Rc<RefCell<OsSyscallHandler>>,
}

impl OsSyscallHandlerManager {
    pub fn new(syscall_ptr: Relocatable) -> Self {
        Self {
            syscall_handler: Rc::new(RefCell::new(OsSyscallHandler {
                syscall_ptr,
                ro_segments: ReadOnlySegments::default(),
            })),
        }
    }
}
