#![allow(unused)]
use indoc::indoc;

// This file is intended to list all the unimplemented hints found by the `hint_tool` binary

pub const HINT_0: &str = indoc! {r#"memory[fp + 25] = to_felt_or_relocatable(os_input.full_output)"#};

pub const HINT_1: &str = indoc! {r#"commitment_info_by_address=execution_helper.compute_storage_commitments()"#};

pub const HINT_2: &str = indoc! {r#"memory[ap] = to_felt_or_relocatable(ids.remaining_gas > ids.max_gas)"#};

pub const HINT_3: &str = indoc! {r#"memory[fp + 0] = to_felt_or_relocatable(aliases.read(key=ids.key))"#};

pub const HINT_4: &str = indoc! {r#"vm_exit_scope()

computed_hash = ids.hash
expected_hash = ids.compiled_class_fact.hash
assert computed_hash == expected_hash, (
    "Computed compiled_class_hash is inconsistent with the hash in the os_input. "
    f"Computed hash = {computed_hash}, Expected hash = {expected_hash}.")"#};

pub const HINT_5: &str = indoc! {r#"if execution_helper.debug_mode:
    expected_initial_gas = execution_helper.call_info.call.initial_gas
    call_initial_gas = ids.remaining_gas
    assert expected_initial_gas == call_initial_gas, (
        f"Expected remaining_gas {expected_initial_gas}. Got: {call_initial_gas}.\n"
        f"{execution_helper.call_info=}"
    )"#};

pub const HINT_6: &str = indoc! {r#"ids.is_n_updates_small = ids.n_updates < ids.N_UPDATES_SMALL_PACKING_BOUND"#};

pub const HINT_7: &str = indoc! {r#"del memory.data[ids.data_ptr]"#};

pub const HINT_8: &str = indoc! {r#"ids.aliases_entry = __dict_manager.get_dict(ids.os_state_update.contract_state_changes_end)[
    ids.ALIAS_CONTRACT_ADDRESS
]"#};

pub const HINT_9: &str = indoc! {r#"memory[ap] = to_felt_or_relocatable(ids.contract_address <= ids.MAX_NON_COMPRESSED_CONTRACT_ADDRESS)"#};


pub const HINT_11: &str = indoc! {r#"vm_enter_scope({
    "bytecode_segment_structure": bytecode_segment_structures[ids.compiled_class_fact.hash]
})"#};

pub const HINT_12: &str = indoc! {r#"memory[ap] = to_felt_or_relocatable(aliases.read(key=ids.ALIAS_COUNTER_STORAGE_KEY))"#};

pub const HINT_13: &str = indoc! {r#"memory[ap] = to_felt_or_relocatable(ids.key < ids.MIN_VALUE_FOR_ALIAS_ALLOC)"#};

pub const HINT_14: &str = indoc! {r#"exit_syscall(selector=ids.GET_CLASS_HASH_AT_SELECTOR)"#};

pub const HINT_15: &str = indoc! {r#"aliases.write(key=ids.key, value=ids.next_available_alias)"#};

pub const HINT_16: &str = indoc! {r#"aliases.write(key=ids.ALIAS_COUNTER_STORAGE_KEY, value=ids.next_available_alias)"#};

pub const HINT_17: &str = indoc! {r#"memory[ap] = to_felt_or_relocatable(storage.read(key=ids.storage_key))"#};

pub const HINT_18: &str = indoc! {r#"from starkware.cairo.common.cairo_secp.secp_utils import SECP256R1, pack
from starkware.python.math_utils import y_squared_from_x

y_square_int = y_squared_from_x(
    x=pack(ids.x, PRIME),
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
    value = (-y) % SECP256R1.prime"#};

pub const HINT_19: &str = indoc! {r#"from src.starkware.starknet.core.os.transaction_hash.transaction_hash import (
    create_resource_bounds_list,
)
tx = next(transactions)
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
)

# Guess the resource bounds.
if tx.tx_type.name == 'L1_HANDLER' or tx.version < 3:
    ids.resource_bounds = 0
    ids.n_resource_bounds = 0
else:
    ids.resource_bounds = segments.gen_arg(create_resource_bounds_list(tx.resource_bounds))
    ids.n_resource_bounds = len(tx.resource_bounds)"#};

pub const HINT_20: &str = indoc! {r#"execution_helper.enter_call(cairo_execution_info=ids.execution_context.execution_info)"#};

pub const HINT_21: &str = indoc! {r#"from starkware.cairo.common.cairo_secp.secp256r1_utils import SECP256R1_ALPHA, SECP256R1_P
from starkware.cairo.common.cairo_secp.secp_utils import pack
from starkware.python.math_utils import ec_double_slope

# Compute the slope.
x = pack(ids.point.x, PRIME)
y = pack(ids.point.y, PRIME)
value = slope = ec_double_slope(point=(x, y), alpha=SECP256R1_ALPHA, p=SECP256R1_P)"#};

pub const HINT_22: &str = indoc! {r#"from starkware.cairo.lang.vm.relocatable import RelocatableValue

bytecode_segment_to_length = {}
compiled_hash_to_bytecode_segment = {}
for i in range(ids.n_compiled_class_facts):
    fact = ids.compiled_class_facts[i]
    bytecode_segment = fact.compiled_class.bytecode_ptr.segment_index
    bytecode_segment_to_length[bytecode_segment] = fact.compiled_class.bytecode_length
    compiled_hash_to_bytecode_segment[fact.hash] = bytecode_segment

bytecode_segment_to_visited_pcs = {
    bytecode_segment: [] for bytecode_segment in bytecode_segment_to_length
}
for addr in iter_accessed_addresses():
    if (
        isinstance(addr, RelocatableValue)
        and addr.segment_index in bytecode_segment_to_visited_pcs
    ):
        bytecode_segment_to_visited_pcs[addr.segment_index].append(addr.offset)

# Sort and remove the program extra data, which is not part of the hash.
for bytecode_segment, visited_pcs in bytecode_segment_to_visited_pcs.items():
    visited_pcs.sort()
    while (
        len(visited_pcs) > 0
        and visited_pcs[-1] >= bytecode_segment_to_length[bytecode_segment]
    ):
        visited_pcs.pop()

# Build the bytecode segment structures based on the execution info.
bytecode_segment_structures = {
    compiled_hash: create_bytecode_segment_structure(
        bytecode=compiled_class.bytecode,
        bytecode_segment_lengths=compiled_class.bytecode_segment_lengths,
        visited_pcs=bytecode_segment_to_visited_pcs[
            compiled_hash_to_bytecode_segment[compiled_hash]
        ],
    ) for compiled_hash, compiled_class in os_input.compiled_classes.items()
}"#};

pub const HINT_23: &str = indoc! {r#"memory[ap] = to_felt_or_relocatable(segments.gen_arg([[], 0]))"#};

pub const HINT_24: &str = indoc! {r#"ids.is_sierra_gas_mode = execution_helper.call_info.tracked_resource.is_sierra_gas()"#};

pub const HINT_25: &str = indoc! {r#"from starkware.cairo.common.cairo_secp.secp256r1_utils import SECP256R1_P
from starkware.cairo.common.cairo_secp.secp_utils import pack

slope = pack(ids.slope, PRIME)
x = pack(ids.point.x, PRIME)
y = pack(ids.point.y, PRIME)

value = new_x = (pow(slope, 2, SECP256R1_P) - 2 * x) % SECP256R1_P"#};

pub const HINT_26: &str = indoc! {r#"from starkware.starknet.core.os.contract_class.compiled_class_hash import (
    create_bytecode_segment_structure,
    get_compiled_class_struct,
)

ids.n_compiled_class_facts = len(os_input.compiled_classes)
ids.compiled_class_facts = (compiled_class_facts_end := segments.add())
for i, (compiled_class_hash, compiled_class) in enumerate(
    os_input.compiled_classes.items()
):
    # Load the compiled class.
    cairo_contract = get_compiled_class_struct(
        identifiers=ids._context.identifiers,
        compiled_class=compiled_class,
        # Load the entire bytecode - the unaccessed segments will be overriden and skipped
        # after the execution, in `validate_compiled_class_facts_post_execution`.
        bytecode=compiled_class.bytecode,
    )
    segments.load_data(
        ptr=ids.compiled_class_facts[i].address_,
        data=(compiled_class_hash, segments.gen_arg(cairo_contract))
    )

    bytecode_ptr = ids.compiled_class_facts[i].compiled_class.bytecode_ptr
    # Compiled classes are expected to end with a `ret` opcode followed by a pointer to
    # the builtin costs.
    segments.load_data(
        ptr=bytecode_ptr + cairo_contract.bytecode_length,
        data=[0x208b7fff7fff7ffe, ids.builtin_costs]
    )

    # Load hints and debug info.
    vm_load_program(
        compiled_class.get_runnable_program(entrypoint_builtins=[]), bytecode_ptr)"#};

pub const HINT_27: &str = indoc! {r#"storage.write(key=ids.storage_key, value=ids.value)"#};

pub const HINT_28: &str = indoc! {r#"assert ids.key >= ids.MIN_VALUE_FOR_ALIAS_ALLOC, f"Key {ids.key} is too small.""#};

pub const HINT_29: &str = indoc! {r#"from starkware.starknet.definitions.constants import ALIAS_CONTRACT_ADDRESS

# This hint shouldn't be whitelisted.
vm_enter_scope(dict(
    aliases=execution_helper.storage_by_address[ALIAS_CONTRACT_ADDRESS],
    execution_helper=execution_helper,
    __dict_manager=__dict_manager,
    os_input=os_input,
))"#};

pub const HINT_30: &str = indoc! {r#"# Fetch a state_entry in this hint and validate it in the update that comes next.
ids.state_entry = __dict_manager.get_dict(ids.contract_state_changes)[ids.contract_address]
ids.new_state_entry = segments.add()

# Fetch the relevant storage.
storage = execution_helper.storage_by_address[ids.contract_address]"#};

pub const HINT_31: &str = indoc! {r#"memory[fp + 24] = to_felt_or_relocatable(syscall_handler.block_info.use_kzg_da and (
    not os_input.full_output
))"#};

pub const HINT_32: &str = indoc! {r#"memory[ap] = to_felt_or_relocatable(ids.remaining_gas < ids.ENTRY_POINT_INITIAL_BUDGET)"#};

pub const HINT_33: &str = indoc! {r#"aliases.write(key=ids.ALIAS_COUNTER_STORAGE_KEY, value=ids.INITIAL_AVAILABLE_ALIAS)"#};

