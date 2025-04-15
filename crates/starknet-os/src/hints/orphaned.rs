#![allow(unused)]
use indoc::indoc;

// same as "HINT_30" in unimplemented
pub const HINT_1: &str = indoc! {r#"memory[fp + 18] = to_felt_or_relocatable(syscall_handler.block_info.use_kzg_da and (
    not os_input.full_output
))"#};

// will always be considered orphaned
pub const HINT_2: &str = indoc! {r#"breakpoint()"#};

// similar to "HINT_11"
pub const HINT_3: &str = indoc! {r#"vm_enter_scope({
    "bytecode_segment_structure": bytecode_segment_structure
})"#};

// looks like "HINT_1" but needs a closer look (no enter scope, no os_input=os_input)
pub const HINT_4: &str = indoc! {r#"# This hint shouldn't be whitelisted.
vm_enter_scope(dict(
    commitment_info_by_address=execution_helper.compute_storage_commitments(),
    os_input=os_input,
))"#};

// from cairo-lang 'git diff' it looks like this has been removed
pub const HINT_6: &str = indoc! {r#"execution_helper.skip_call()"#};

// from cairo-lang 'git diff' it looks like this has been removed
pub const HINT_7: &str = indoc! {r#"memory[ap] = to_felt_or_relocatable(0 if tx.version < 3 else len(tx.resource_bounds))"#};

// ?
pub const HINT_8: &str = indoc! {r#"memory[fp + 19] = to_felt_or_relocatable(os_input.full_output)"#};

// this turned into two different hints: "HINT_11" and "HINT_4"
pub const HINT_11: &str = indoc! {r#"computed_hash = ids.compiled_class_fact.hash
expected_hash = compiled_class_hash
assert computed_hash == expected_hash, (
    "Computed compiled_class_hash is inconsistent with the hash in the os_input. "
    f"Computed hash = {computed_hash}, Expected hash = {expected_hash}.")

vm_load_program(
    compiled_class.get_runnable_program(entrypoint_builtins=[]),
    ids.compiled_class.bytecode_ptr
)"#};

// this appears to have been removed
pub const HINT_12: &str = indoc! {r#"execution_helper.enter_call(
    cairo_execution_info=ids.execution_context.execution_info)"#};

// turned into "HINT_6"
pub const HINT_13: &str = indoc! {r#"ids.is_n_updates_small = ids.n_actual_updates < ids.N_UPDATES_SMALL_PACKING_BOUND"#};

// removed
pub const HINT_14: &str = indoc! {r#"from src.starkware.starknet.core.os.transaction_hash.transaction_hash import (
    create_resource_bounds_list,
)

ids.resource_bounds = (
    0
    if tx.version < 3
    else segments.gen_arg(create_resource_bounds_list(tx.resource_bounds))
)"#};

