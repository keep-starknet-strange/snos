pub const CHECK_IS_DEPRECATED: &str =
    "is_deprecated = 1 if ids.execution_context.class_hash in __deprecated_class_hashes else 0";

pub const IS_DEPRECATED: &str = "memory[ap] = to_felt_or_relocatable(is_deprecated)";

pub const OS_CONTEXT_SEGMENTS: &str = "ids.os_context = segments.add()\nids.syscall_ptr = segments.add()";

pub const SELECTED_BUILTINS: &str = "vm_enter_scope({'n_selected_builtins': ids.n_selected_builtins})";

pub const SELECT_BUILTIN: &str =
    "# A builtin should be selected iff its encoding appears in the selected encodings list\n# and the list wasn't \
     exhausted.\n# Note that testing inclusion by a single comparison is possible since the lists are \
     sorted.\nids.select_builtin = int(\n  n_selected_builtins > 0 and memory[ids.selected_encodings] == \
     memory[ids.all_encodings])\nif ids.select_builtin:\n  n_selected_builtins = n_selected_builtins - 1";

pub const BREAKPOINT: &str = "breakpoint()";
