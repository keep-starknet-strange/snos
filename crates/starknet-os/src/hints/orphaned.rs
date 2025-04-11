#![allow(unused)]
use indoc::indoc;

// this was reduced into "HINT_10"
pub const HINT_0: &str = indoc! {r#"return_values = ids.entry_point_return_values
if return_values.failure_flag != 0:
    # Fetch the error, up to 100 elements.
    retdata_size = return_values.retdata_end - return_values.retdata_start
    error = memory.get_range(return_values.retdata_start, max(0, min(100, retdata_size)))

    print("Invalid return value in execute_entry_point:")
    print(f"  Class hash: {hex(ids.execution_context.class_hash)}")
    print(f"  Selector: {hex(ids.execution_context.execution_info.selector)}")
    print(f"  Size: {retdata_size}")
    print(f"  Error (at most 100 elements): {error}")

if execution_helper.debug_mode:
    # Validate the predicted gas cost.
    actual = ids.remaining_gas - ids.entry_point_return_values.gas_builtin
    predicted = execution_helper.call_info.gas_consumed
    assert actual == predicted, (
        "Predicted gas costs are inconsistent with the actual execution; "
        f"{predicted=}, {actual=}."
    )

# Exit call.
syscall_handler.validate_and_discard_syscall_ptr(
    syscall_ptr_end=ids.entry_point_return_values.syscall_ptr
)
execution_helper.exit_call()"#};

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

// the vm_enter_scope() part was removed, and this is now a much larger hint ("HINT_26", I think)
pub const HINT_5: &str = indoc! {r#"ids.compiled_class_facts = segments.add()
ids.n_compiled_class_facts = len(os_input.compiled_classes)
vm_enter_scope({
    'compiled_class_facts': iter(os_input.compiled_classes.items()),
    'compiled_class_visited_pcs': os_input.compiled_class_visited_pcs,
})"#};

// from cairo-lang 'git diff' it looks like this has been removed
pub const HINT_6: &str = indoc! {r#"execution_helper.skip_call()"#};

// from cairo-lang 'git diff' it looks like this has been removed
pub const HINT_7: &str = indoc! {r#"memory[ap] = to_felt_or_relocatable(0 if tx.version < 3 else len(tx.resource_bounds))"#};

// ?
pub const HINT_8: &str = indoc! {r#"memory[fp + 19] = to_felt_or_relocatable(os_input.full_output)"#};

// this hint grew into "HINT_19"
pub const HINT_9: &str = indoc! {r#"tx = next(transactions)
assert tx.tx_type.name in ('INVOKE_FUNCTION', 'L1_HANDLER', 'DEPLOY_ACCOUNT', 'DECLARE'), (
    f"Unexpected transaction type: {tx.type.name}."
)

tx_type_bytes = tx.tx_type.name.encode("ascii")
ids.tx_type = int.from_bytes(tx_type_bytes, "big")
execution_helper.os_logger.enter_tx(
    tx=tx,
    n_steps=current_step,
    builtin_ptrs=ids.builtin_ptrs,
    range_check_ptr=ids.range_check_ptr,
)

# Prepare a short callable to save code duplication.
exit_tx = lambda: execution_helper.os_logger.exit_tx(
    n_steps=current_step,
    builtin_ptrs=ids.builtin_ptrs,
    range_check_ptr=ids.range_check_ptr,
)"#};

// this hint looks like it grew into "HINT_22", but it also moved to a different fn (?) or at least
// different part of the same fn
pub const HINT_10: &str = indoc! {r#"from starkware.starknet.core.os.contract_class.compiled_class_hash import (
    create_bytecode_segment_structure,
    get_compiled_class_struct,
)

compiled_class_hash, compiled_class = next(compiled_class_facts)

bytecode_segment_structure = create_bytecode_segment_structure(
    bytecode=compiled_class.bytecode,
    bytecode_segment_lengths=compiled_class.bytecode_segment_lengths,
    visited_pcs=compiled_class_visited_pcs[compiled_class_hash],
)

cairo_contract = get_compiled_class_struct(
    identifiers=ids._context.identifiers,
    compiled_class=compiled_class,
    bytecode=bytecode_segment_structure.bytecode_with_skipped_segments()
)
ids.compiled_class = segments.gen_arg(cairo_contract)"#};

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

