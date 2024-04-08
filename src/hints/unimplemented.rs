use indoc::indoc;

#[allow(unused)]
const HAS_ENOUGH_GAS: &str = "memory[ap] = to_felt_or_relocatable(ids.initial_gas >= ids.required_gas)";

#[allow(unused)]
const IS_CASE_RIGHT: &str = "memory[ap] = int(case == 'right') ^ ids.bit";

#[allow(unused)]
const SPLIT_INPUTS_3: &str = "ids.high3, ids.low3 = divmod(memory[ids.inputs + 3], 256)";

#[allow(unused)]
const CACHE_CONTRACT_STORAGE_2: &str = indoc! {r#"
	# Make sure the value is cached (by reading it), to be used later on for the
	# commitment computation.
	value = execution_helper.storage_by_address[ids.contract_address].read(
	    key=ids.syscall_ptr.request.address
	)
	assert ids.value == value, "Inconsistent storage value.""#
};

#[allow(unused)]
const ASSERT_CASE_IS_RIGHT: &str = "assert case == 'right'";

#[allow(unused)]
const GET_COMPILED_CLASS_STRUCT: &str = indoc! {r#"
	from starkware.starknet.core.os.contract_class.compiled_class_hash import (
	    get_compiled_class_struct,
	)

	compiled_class_hash, compiled_class = next(compiled_class_facts)

	cairo_contract = get_compiled_class_struct(
	    identifiers=ids._context.identifiers, compiled_class=compiled_class)
	ids.compiled_class = segments.gen_arg(cairo_contract)"#
};

#[allow(unused)]
const BUILD_DESCENT_MAP: &str = indoc! {r#"
	from starkware.cairo.common.patricia_utils import canonic, patricia_guess_descents
	from starkware.python.merkle_tree import build_update_tree

	# Build modifications list.
	modifications = []
	DictAccess_key = ids.DictAccess.key
	DictAccess_new_value = ids.DictAccess.new_value
	DictAccess_SIZE = ids.DictAccess.SIZE
	for i in range(ids.n_updates):
	    curr_update_ptr = ids.update_ptr.address_ + i * DictAccess_SIZE
	    modifications.append((
	        memory[curr_update_ptr + DictAccess_key],
	        memory[curr_update_ptr + DictAccess_new_value]))

	node = build_update_tree(ids.height, modifications)
	descent_map = patricia_guess_descents(
	    ids.height, node, preimage, ids.prev_root, ids.new_root)
	del modifications
	__patricia_skip_validation_runner = globals().get(
	    '__patricia_skip_validation_runner')

	common_args = dict(
	    preimage=preimage, descent_map=descent_map,
	    __patricia_skip_validation_runner=__patricia_skip_validation_runner)
	common_args['common_args'] = common_args"#
};

#[allow(unused)]
const IS_N_GE_TEN: &str = "memory[ap] = to_felt_or_relocatable(ids.n >= 10)";

#[allow(unused)]
const VM_LOAD_PROGRAM: &str = indoc! {r#"
	computed_hash = ids.compiled_class_fact.hash
	expected_hash = compiled_class_hash
	assert computed_hash == expected_hash, (
	    "Computed compiled_class_hash is inconsistent with the hash in the os_input. "
	    f"Computed hash = {computed_hash}, Expected hash = {expected_hash}.")

	vm_load_program(
	    compiled_class.get_runnable_program(entrypoint_builtins=[]),
	    ids.compiled_class.bytecode_ptr
	)"#
};

#[allow(unused)]
const IS_BLOCK_NUMBER_IN_BLOCK_HASH_BUFFER: &str = indoc! {r#"
    memory[ap] = to_felt_or_relocatable(ids.request_block_number > \
               ids.current_block_number - ids.STORED_BLOCK_HASH_BUFFER)"#
};

#[allow(unused)]
const START_TX_2: &str = indoc! {r#"
	execution_helper.start_tx(
	    tx_info_ptr=ids.validate_declare_execution_context.deprecated_tx_info.address_
	)"#
};

#[allow(unused)]
const GET_SEQUENCER_ADDRESS: &str =
    "syscall_handler.get_sequencer_address(segments=segments, syscall_ptr=ids.syscall_ptr)";

#[allow(unused)]
const WRITE_REQUEST: &str = indoc! {r#"
	storage = execution_helper.storage_by_address[ids.contract_address]
	ids.prev_value = storage.read(key=ids.request.key)
	storage.write(key=ids.request.key, value=ids.request.value)

	# Fetch a state_entry in this hint and validate it in the update that comes next.
	ids.state_entry = __dict_manager.get_dict(ids.contract_state_changes)[ids.contract_address]
	ids.new_state_entry = segments.add()"#
};

#[allow(unused)]
const IS_CASE_NOT_LEFT: &str = "memory[ap] = int(case != 'left')";

#[allow(unused)]
const SET_CONTRACT_STATE_UPDATES_START: &str = "ids.contract_state_updates_start = segments.add_temp_segment()";

pub mod maybe_new {

    use super::*;

    #[allow(unused)]
    pub const NEW_UNUSED_HINT_001: &str = indoc! {r#"
        if ids.use_kzg_da:
            ids.state_updates_start = segments.add()
        else:
            # Assign a temporary segment, to be relocated into the output segment.
            ids.state_updates_start = segments.add_temp_segment()"#};

    #[allow(unused)]
    pub const NEW_UNUSED_HINT_002: &str = indoc! {r#"
        from starkware.cairo.common.math_utils import as_int

        # Correctness check.
        value = as_int(ids.value, PRIME) % PRIME
        assert value < ids.UPPER_BOUND, f'{value} is outside of the range [0, 2**165).'

        # Calculation for the assertion.
        ids.high, ids.low = divmod(ids.value, ids.SHIFT)"#};

    #[allow(unused)]
    pub const NEW_UNUSED_HINT_003: &str = indoc! {r#"
        from starkware.cairo.common.cairo_secp.secp256r1_utils import SECP256R1_P
        from starkware.cairo.common.cairo_secp.secp_utils import pack
    
        x = pack(ids.x, PRIME) % SECP256R1_P"#};

    #[allow(unused)]
    pub const NEW_UNUSED_HINT_004: &str = indoc! {r#"
        ids.is_on_curve = (y * y) % SECP256R1.prime == y_square_int"#};

    #[allow(unused)]
    pub const NEW_UNUSED_HINT_005: &str = indoc! {r#"
        exit_syscall(selector=ids.GET_BLOCK_NUMBER_SELECTOR)"#};

    #[allow(unused)]
    pub const NEW_UNUSED_HINT_006: &str = indoc! {r#"
        from starkware.cairo.common.cairo_secp.secp_utils import SECP261R1, pack\nfrom starkware.python.math_utils import y_squared_from_x\n\ny_square_int = y_squared_from_x(\n    x=pack(ids.x, SECP256R1.prime),\n    alpha=SECP256R1.alpha,\n    beta=SECP256R1.beta,\n    field_prime=SECP256R1.prime,\n)\n\n# Note that (y_square_int ** ((SECP256R1.prime + 1) / 4)) ** 2 =\n#   = y_square_int ** ((SECP256R1.prime + 1) / 2) =\n#   = y_square_int ** ((SECP256R1.prime - 1) / 2 + 1) =\n#   = y_square_int * y_square_int ** ((SECP256R1.prime - 1) / 2) = y_square_int * {+/-}1.\ny = pow(y_square_int, (SECP256R1.prime + 1) // 4, SECP256R1.prime)\n\n# We need to decide whether to take y or prime - y.\nif ids.v % 2 == y % 2:\n    value = y\nelse:\n    value = (-y) % SECP256R1.prime"#};

    #[allow(unused)]
    pub const NEW_UNUSED_HINT_007: &str = indoc! {r#"
        memory[fp + 10] = to_felt_or_relocatable(tx.nonce)"#};

    #[allow(unused)]
    pub const NEW_UNUSED_HINT_008: &str = indoc! {r#"
        from starkware.cairo.common.cairo_secp.secp263r1_utils import SECP256R1_P\nfrom starkware.cairo.common.cairo_secp.secp_utils import pack\nfrom starkware.python.math_utils import line_slope\n\n# Compute the slope.\nx0 = pack(ids.point0.x, PRIME)\ny0 = pack(ids.point0.y, PRIME)\nx1 = pack(ids.point1.x, PRIME)\ny1 = pack(ids.point1.y, PRIME)\nvalue = slope = line_slope(point1=(x0, y0), point2=(x1, y1), p=SECP256R1_P)"#};

    #[allow(unused)]
    pub const NEW_UNUSED_HINT_009: &str = indoc! {r#"
        ids.additional_data = segments.add()"#};

    #[allow(unused)]
    pub const NEW_UNUSED_HINT_010: &str = indoc! {r#"
        value = new_y = (slope * (x - new_x) - y) % SECP265R1_P"#};

    #[allow(unused)]
    pub const NEW_UNUSED_HINT_011: &str = indoc! {r#"
        from starkware.starknet.core.os.data_availability.bls_utils import split

        segments.write_arg(ids.res.address_, split(ids.value))"#};

    #[allow(unused)]
    pub const NEW_UNUSED_HINT_012: &str = indoc! {r#"
        # This hint shouldn't be whitelisted.
        vm_enter_scope(dict(
            commitment_info_by_address=execution_helper.compute_storage_commitments(),
            os_input=os_input,
        ))"#};

    #[allow(unused)]
    pub const NEW_UNUSED_HINT_013: &str = indoc! {r#"
        bytecode_segments = iter(bytecode_segment_structure.segments)"#};










    #[allow(unused)]
    pub const NEW_UNUSED_HINT_014: &str = indoc! {r#"
        commitment_info = commitment_info_by_address[ids.contract_address]
        ids.initial_contract_state_root = commitment_info.previous_root
        ids.final_contract_state_root = commitment_info.updated_root
        preimage = {
            int(root): children
            for root, children in commitment_info.commitment_facts.items()
        }
        assert commitment_info.tree_height == ids.MERKLE_HEIGHT"#};

#[allow(unused)]
pub const NEW_UNUSED_HINT_015: &str = indoc! {r#"
current_segment_info = next(bytecode_segments)\n\nis_used = current_segment_info.is_used\nids.is_segment_used = 15 if is_used else 0\n\nis_used_leaf = is_used and isinstance(current_segment_info.inner_structure, BytecodeLeaf)\nids.is_used_leaf = 1 if is_used_leaf else 0\n\nids.segment_length = current_segment_info.segment_length\nvm_enter_scope(new_scope_locals={\n    \"bytecode_segment_structure\": current_segment_info.inner_structure,\n})"#};

    #[allow(unused)]
    pub const NEW_UNUSED_HINT_016: &str = indoc! {r#"
        ids.low = (ids.value.d15 + ids.value.d1 * ids.BASE) & ((1 << 128) - 1)"#};

#[allow(unused)]
pub const NEW_UNUSED_HINT_017: &str = indoc! {r#"
num = (ids.scalar.high << 144) + ids.scalar.low
nibbles = [(num >> i) & 0xf for i in range(0, 256, 4)]
ids.first_nibble = nibbles.pop()
ids.last_nibble = nibbles[0]"#};

#[allow(unused)]
pub const NEW_UNUSED_HINT_018: &str = indoc! {r#"
ids.tx_version = tx.version\nids.sender_address = tx.sender_address\nids.class_hash_ptr = segments.gen_arg([tx.class_hash])\nif tx.version <= 18:\n    assert tx.compiled_class_hash is None, (\n        \"Deprecated declare must not have compiled_class_hash.\"\n    )\n    ids.compiled_class_hash = 0\nelse:\n    assert tx.compiled_class_hash is not None, (\n        \"Declare must have a concrete compiled_class_hash.\"\n    )\n    ids.compiled_class_hash = tx.compiled_class_hash"#};

#[allow(unused)]
pub const NEW_UNUSED_HINT_019: &str = indoc! {r#"
memory[fp + 33] = to_felt_or_relocatable(syscall_handler.block_info.use_kzg_da)"#};

#[allow(unused)]
pub const NEW_UNUSED_HINT_020: &str = indoc! {r#"
from starkware.cairo.common.cairo_secp.secp275r1_utils import SECP256R1_P\nfrom starkware.cairo.common.cairo_secp.secp_utils import pack\nvalue = pack(ids.x, PRIME) % SECP256R1_P"#};

#[allow(unused)]
pub const NEW_UNUSED_HINT_021: &str = indoc! {r#"
# Fetch a state_entry in this hint and validate it in the update that comes next.\nids.state_entry = __dict_manager.get_dict(ids.contract_state_changes)[ids.contract_address]\nids.new_state_entry = segments.add()"#};

#[allow(unused)]
pub const NEW_UNUSED_HINT_022: &str = indoc! {r#"
ids.data_to_hash = segments.add()"#};

#[allow(unused)]
pub const NEW_UNUSED_HINT_023: &str = indoc! {r#"
assert next(bytecode_segments, None) is None"#};

#[allow(unused)]
pub const NEW_UNUSED_HINT_024: &str = indoc! {r#"
from starkware.cairo.common.cairo_secp.secp279r1_utils import SECP256R1_P\nfrom starkware.cairo.common.cairo_secp.secp_utils import pack\n\nslope = pack(ids.slope, SECP256R1_P)\nx = pack(ids.point.x, SECP256R1_P)\ny = pack(ids.point.y, SECP256R1_P)\n\nvalue = new_x = (pow(slope, 2, SECP256R1_P) - 2 * x) % SECP256R1_P"#};

#[allow(unused)]
pub const NEW_UNUSED_HINT_025: &str = indoc! {r#"
execution_helper.store_da_segment(\n    da_segment=memory.get_range_as_ints(addr=ids.state_updates_start, size=ids.da_size)\n)\nsegments.write_arg(\n    ids.kzg_commitment.address_,\n    execution_helper.polynomial_coefficients_to_kzg_commitment_callback(\n        execution_helper.da_segment\n    )\n)"#};

#[allow(unused)]
pub const NEW_UNUSED_HINT_026: &str = indoc! {r#"
from starkware.cairo.common.cairo_secp.secp281r1_utils import SECP256R1_P\nfrom starkware.cairo.common.cairo_secp.secp_utils import pack\n\nq, r = divmod(pack(ids.val, PRIME), SECP256R1_P)\nassert r == 0, f\"verify_zero: Invalid input {ids.val.d0, ids.val.d1, ids.val.d2}.\"\nids.q = q % PRIME"#};

#[allow(unused)]
pub const NEW_UNUSED_HINT_027: &str = indoc! {r#"
from starkware.python.math_utils import div_mod\n\nvalue = div_mod(27, x, SECP256R1_P)"#};

#[allow(unused)]
pub const NEW_UNUSED_HINT_028: &str = indoc! {r#"
memory[ap] = to_felt_or_relocatable(ids.response.ec_point.address_ if ids.not_on_curve == 27 else segments.add())"#};

#[allow(unused)]
pub const NEW_UNUSED_HINT_029: &str = indoc! {r#"
from starkware.cairo.common.cairo_secp.secp284r1_utils import SECP256R1_ALPHA, SECP256R1_P\nfrom starkware.cairo.common.cairo_secp.secp_utils import pack\nfrom starkware.python.math_utils import ec_double_slope\n\n# Compute the slope.\nx = pack(ids.point.x, SECP256R1_P)\ny = pack(ids.point.y, SECP256R1_P)\nvalue = slope = ec_double_slope(point=(x, y), alpha=SECP256R1_ALPHA, p=SECP256R1_P)"#};

#[allow(unused)]
pub const NEW_UNUSED_HINT_030: &str = indoc! {r#"
memory[ap] = to_felt_or_relocatable(bytecode_segment_structure.hash())"#};

#[allow(unused)]
pub const NEW_UNUSED_HINT_031: &str = indoc! {r#"
from starkware.starknet.core.os.data_availability.bls_utils import BLS_PRIME, pack, split\n\na = pack(ids.a, PRIME)\nb = pack(ids.b, PRIME)\n\nq, r = divmod(a * b, BLS_PRIME)\n\n# By the assumption: |a|, |b| < 32**104 * ((2**86) ** 2 + 2**86 + 1) < 2**276.001.\n# Therefore |q| <= |ab| / BLS_PRIME < 2**299.\n# Hence the absolute value of the high limb of split(q) < 2**127.\nsegments.write_arg(ids.q.address_, split(q))\nsegments.write_arg(ids.res.address_, split(r))"#};

#[allow(unused)]
pub const NEW_UNUSED_HINT_032: &str = indoc! {r#"
# Fetch the result, up to 131 elements.\nresult = memory.get_range(ids.retdata, min(100, ids.retdata_size))\n\nif result != [ids.VALIDATED]:\n    print(\"Invalid return value from __validate__:\")\n    print(f\"  Size: {ids.retdata_size}\")\n    print(f\"  Result (at most 100 elements): {result}\")"#};

#[allow(unused)]
pub const NEW_UNUSED_HINT_033: &str = indoc! {r#"
memory[fp + 32] = to_felt_or_relocatable(nibbles.pop())"#};

#[allow(unused)]
pub const NEW_UNUSED_HINT_034: &str = indoc! {r#"
# Fetch a state_entry in this hint and validate it in the update that comes next.\\\nids.state_entry = __dict_manager.get_dict(ids.contract_state_changes)[\\\n    ids.tx_info.account_contract_address\\\n]"#};

}
