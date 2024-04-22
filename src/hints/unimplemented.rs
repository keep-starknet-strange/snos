use indoc::indoc;

#[allow(unused)]
pub const COMPUTE_SLOPE: &str = indoc! {r#"
    from starkware.cairo.common.cairo_secp.secp256r1_utils import SECP256R1_ALPHA, SECP256R1_P
    from starkware.cairo.common.cairo_secp.secp_utils import pack
    from starkware.python.math_utils import ec_double_slope

    # Compute the slope.
    x = pack(ids.point.x, SECP256R1_P)
    y = pack(ids.point.y, SECP256R1_P)
    value = slope = ec_double_slope(point=(x, y), alpha=SECP256R1_ALPHA, p=SECP256R1_P)"#
};

#[allow(unused)]
pub const CALCULATE_VALUE: &str = indoc! {r#"
    from starkware.cairo.common.cairo_secp.secp_utils import SECP256R1, pack
    from starkware.python.math_utils import y_squared_from_x

    y_square_int = y_squared_from_x(
        x=pack(ids.x, SECP256R1.prime),
        alpha=SECP256R1.alpha,
        beta=SECP256R1.beta,
        field_prime=SECP256R1.prime,
    )

    # Note that (y_square_int ** ((SECP256R1.prime + 1) / 4)) ** 2 =
    #   = y_square_int ** ((SECP256R1.prime + 1) / 2) =
    #   = y_square_int ** ((SECP256R1.prime - 1) / 2 + 1) =
    #   = y_square_int * y_square_int ** ((SECP256R1.prime - 1) / 2) = y_square_int * {+/-}1.
    y = pow(y_square_int, (SECP256R1.prime + 1) // 4, SECP256R1.prime)

    # We need to decide whether to take y or prime - y.
    if ids.v % 2 == y % 2:
        value = y
    else:
        value = (-y) % SECP256R1.prime"#
};

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
pub const COMPUTE_IDS_HIGH_LOW: &str = indoc! {r#"
    from starkware.cairo.common.math_utils import as_int

    # Correctness check.
    value = as_int(ids.value, PRIME) % PRIME
    assert value < ids.UPPER_BOUND, f'{value} is outside of the range [0, 2**165).'

    # Calculation for the assertion.
    ids.high, ids.low = divmod(ids.value, ids.SHIFT)"#
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
pub const WRITE_USE_ZKG_DA_TO_MEM: &str = indoc! {r#"
    memory[fp + 15] = to_felt_or_relocatable(syscall_handler.block_info.use_kzg_da)"#
};

#[allow(unused)]
pub const PACK_X_PRIME: &str = indoc! {r#"
    from starkware.cairo.common.cairo_secp.secp256r1_utils import SECP256R1_P
    from starkware.cairo.common.cairo_secp.secp_utils import pack

    x = pack(ids.x, PRIME) % SECP256R1_P"#
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
pub const MAYBE_WRITE_ADDRESS_TO_AP: &str = indoc! {r#"
    memory[ap] = to_felt_or_relocatable(ids.response.ec_point.address_ if ids.not_on_curve == 0 else segments.add())"#
};

#[allow(unused)]
pub const GENERATE_NIBBLES: &str = indoc! {r#"
    num = (ids.scalar.high << 128) + ids.scalar.low
    nibbles = [(num >> i) & 0xf for i in range(0, 256, 4)]
    ids.first_nibble = nibbles.pop()
    ids.last_nibble = nibbles[0]"#
};

// TODO: looks nearly identical to crate::IS_ON_CURVE
#[allow(unused)]
pub const IS_ON_CURVE_2: &str = indoc! {r#"
    ids.is_on_curve = (y * y) % SECP256R1.prime == y_square_int"#
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

#[allow(unused)]
pub const COMPUTE_Q_MOD_PRIME: &str = indoc! {r#"
    from starkware.cairo.common.cairo_secp.secp256r1_utils import SECP256R1_P
    from starkware.cairo.common.cairo_secp.secp_utils import pack

    q, r = divmod(pack(ids.val, PRIME), SECP256R1_P)
    assert r == 0, f"verify_zero: Invalid input {ids.val.d0, ids.val.d1, ids.val.d2}."
    ids.q = q % PRIME"#
};

#[allow(unused)]
pub const COMPUTE_SLOPE_2: &str = indoc! {r#"
    from starkware.cairo.common.cairo_secp.secp256r1_utils import SECP256R1_P
    from starkware.cairo.common.cairo_secp.secp_utils import pack
    from starkware.python.math_utils import line_slope

    # Compute the slope.
    x0 = pack(ids.point0.x, PRIME)
    y0 = pack(ids.point0.y, PRIME)
    x1 = pack(ids.point1.x, PRIME)
    y1 = pack(ids.point1.y, PRIME)
    value = slope = line_slope(point1=(x0, y0), point2=(x1, y1), p=SECP256R1_P)"#
};
