use indoc::indoc;


#[allow(unused)]
pub const SET_AP_TO_SEGMENT_HASH: &str = indoc! {r#"
    memory[ap] = to_felt_or_relocatable(bytecode_segment_structure.hash())"#
};

#[allow(unused)]
pub const COMPUTE_NEW_Y: &str = indoc! {r#"
    value = new_y = (slope * (x - new_x) - y) % SECP256R1_P"#
};

#[allow(unused)]
pub const COMPUTE_VALUE_DIV_MOD: &str = indoc! {r#"
    from starkware.python.math_utils import div_mod

    value = div_mod(1, x, SECP256R1_P)"#
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
pub const WRITE_NIBBLES_TO_MEM: &str = indoc! {r#"
    memory[fp + 0] = to_felt_or_relocatable(nibbles.pop())"#
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

#[allow(unused)]
pub const GENERATE_NIBBLES: &str = indoc! {r#"
    num = (ids.scalar.high << 128) + ids.scalar.low
    nibbles = [(num >> i) & 0xf for i in range(0, 256, 4)]
    ids.first_nibble = nibbles.pop()
    ids.last_nibble = nibbles[0]"#
};

// TODO: looks similar to PACK_X_PRIME (above)
#[allow(unused)]
pub const PACK_X_PRIME_2: &str = indoc! {r#"
    from starkware.cairo.common.cairo_secp.secp256r1_utils import SECP256R1_P
    from starkware.cairo.common.cairo_secp.secp_utils import pack
    value = pack(ids.x, PRIME) % SECP256R1_P"#
};

#[allow(unused)]
pub const WRITE_DIVMOD_SEGMENT: &str = indoc! {r#"
    from starkware.starknet.core.os.data_availability.bls_utils import BLS_PRIME, pack, split

    a = pack(ids.a, PRIME)
    b = pack(ids.b, PRIME)

    q, r = divmod(a * b, BLS_PRIME)

    # By the assumption: |a|, |b| < 2**104 * ((2**86) ** 2 + 2**86 + 1) < 2**276.001.
    # Therefore |q| <= |ab| / BLS_PRIME < 2**299.
    # Hence the absolute value of the high limb of split(q) < 2**127.
    segments.write_arg(ids.q.address_, split(q))
    segments.write_arg(ids.res.address_, split(r))"#
};

#[allow(unused)]
pub const CALCULATE_VALUE_2: &str = indoc! {r#"
    from starkware.cairo.common.cairo_secp.secp256r1_utils import SECP256R1_P
    from starkware.cairo.common.cairo_secp.secp_utils import pack

    slope = pack(ids.slope, SECP256R1_P)
    x = pack(ids.point.x, SECP256R1_P)
    y = pack(ids.point.y, SECP256R1_P)

    value = new_x = (pow(slope, 2, SECP256R1_P) - 2 * x) % SECP256R1_P"#
};
