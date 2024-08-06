use indoc::indoc;

#[allow(unused)]
pub const SET_AP_TO_SEGMENT_HASH: &str = indoc! {r#"
    memory[ap] = to_felt_or_relocatable(bytecode_segment_structure.hash())"#
};

#[allow(unused)]
pub const WRITE_ZKG_COMMITMENT_ADDRESS: &str = indoc! {r#"
    execution_helper.store_da_segment(
        da_segment=memory.get_range_as_ints(addr=ids.state_updates_start, size=ids.da_size)
    )
    segments.write_arg(
        ids.kzg_commitment.address_,
        execution_helper.polynomial_coefficients_to_kzg_commitment_callback(
            execution_helper.da_segment
        )
    )"#
};

#[allow(unused)]
pub const ITER_CURRENT_SEGMENT_INFO: &str = indoc! {r#"
    current_segment_info = next(bytecode_segments)

    is_used = current_segment_info.is_used
    ids.is_segment_used = 1 if is_used else 0

    is_used_leaf = is_used and isinstance(current_segment_info.inner_structure, BytecodeLeaf)
    ids.is_used_leaf = 1 if is_used_leaf else 0

    ids.segment_length = current_segment_info.segment_length
    vm_enter_scope(new_scope_locals={
        "bytecode_segment_structure": current_segment_info.inner_structure,
    })"#
};
