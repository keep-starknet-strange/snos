use indoc::indoc;

#[allow(unused)]
pub const HINT_0: &str = indoc! {r#"memory[ap] = to_felt_or_relocatable(os_input.new_block_hash)"#};

#[allow(unused)]
pub const HINT_1: &str = indoc! {r#"# Add dummy pairs of input and output.
from starkware.cairo.common.cairo_sha256.sha256_utils import (
    IV,
    compute_message_schedule,
    sha2_compress_function,
)

number_of_missing_blocks = (-ids.n) % ids.BATCH_SIZE
assert 0 <= number_of_missing_blocks < 20
_sha256_input_chunk_size_felts = ids.SHA256_INPUT_CHUNK_SIZE_FELTS
assert 0 <= _sha256_input_chunk_size_felts < 100

message = [0] * _sha256_input_chunk_size_felts
w = compute_message_schedule(message)
output = sha2_compress_function(IV, w)
padding = (message + IV + output) * number_of_missing_blocks
segments.write_arg(ids.sha256_ptr_end, padding)"#};

#[allow(unused)]
pub const HINT_2: &str = indoc! {r#"execution_helper.enter_call(
cairo_execution_info=ids.execution_context.execution_info)"#};

#[allow(unused)]
pub const HINT_3: &str = indoc! {r#"memory[ap] = to_felt_or_relocatable(os_input.prev_block_hash)"#};

#[allow(unused)]
pub const HINT_4: &str = indoc! {r#"exit_syscall(selector=ids.SHA256_PROCESS_BLOCK_SELECTOR)"#};

#[allow(unused)]
pub const HINT_5: &str = indoc! {r#"__serialize_data_availability_create_pages__ = True
kzg_manager = execution_helper.kzg_manager"#};

#[allow(unused)]
pub const HINT_6: &str = indoc! {r#"print(f"execute_transactions_inner: {ids.n_txs} transactions remaining.")"#};

#[allow(unused)]
pub const HINT_7: &str = indoc! {r#"rc96_ptr = ids.range_check96_ptr
segment_size = rc96_ptr.offset
base = rc96_ptr - segment_size

for i in range(segment_size):
    memory.setdefault(base + i, 0)"#};

#[allow(unused)]
pub const HINT_9: &str = indoc! {r#"import itertools

from starkware.python.utils import blockify

kzg_manager.store_da_segment(
    da_segment=memory.get_range_as_ints(addr=ids.state_updates_start, size=ids.da_size)
)
kzg_commitments = [
    kzg_manager.polynomial_coefficients_to_kzg_commitment_callback(chunk)
    for chunk in blockify(kzg_manager.da_segment, chunk_size=ids.BLOB_LENGTH)
]

ids.n_blobs = len(kzg_commitments)
ids.kzg_commitments = segments.add_temp_segment()
ids.evals = segments.add_temp_segment()

segments.write_arg(ids.kzg_commitments.address_, list(itertools.chain(*kzg_commitments)))"#};

#[allow(unused)]
pub const HINT_10: &str = indoc! {r#"memory[fp + 12] = to_felt_or_relocatable(len(os_input.transactions))"#};

#[allow(unused)]
pub const HINT_11: &str = indoc! {r#"memory[fp + 19] = to_felt_or_relocatable(os_input.full_output)"#};

#[allow(unused)]
pub const HINT_12: &str = indoc! {r#"array_ptr = ids.array_ptr
elm_size = ids.elm_size
assert isinstance(elm_size, int) and elm_size > 0, \
    f'Invalid value for elm_size. Got: {elm_size}.'

n_elms = ids.n_elms
assert isinstance(n_elms, int) and n_elms >= 0, \
    f'Invalid value for n_elms. Got: {n_elms}.'
if '__find_element_max_size' in globals():
    assert n_elms <= __find_element_max_size, \
f'find_element() can only be used with n_elms<={__find_element_max_size}. ' \
        f'Got: n_elms={n_elms}.'

for i in range(n_elms):
    if memory[array_ptr + elm_size * i] >= ids.key:
        ids.index = i
        ids.exists = 1 if memory[array_ptr + elm_size * i] == ids.key else 0
        break
else:
    ids.index = n_elms
    ids.exists = 0"#};

#[allow(unused)]
pub const HINT_13: &str = indoc! {r#"from starkware.python.math_utils import div_ceil

if __serialize_data_availability_create_pages__:
    onchain_data_start = ids.da_start
    onchain_data_size = ids.output_ptr - onchain_data_start

    max_page_size = 3800
    n_pages = div_ceil(onchain_data_size, max_page_size)
    for i in range(n_pages):
        start_offset = i * max_page_size
        output_builtin.add_page(
            page_id=1 + i,
            page_start=onchain_data_start + start_offset,
            page_size=min(onchain_data_size - start_offset, max_page_size),
        )
    # Set the tree structure to a root with two children:
    # * A leaf which represents the main part
    # * An inner node for the onchain data part (which contains n_pages children).
    #
    # This is encoded using the following sequence:
    output_builtin.add_attribute('gps_fact_topology', [
        # Push 1 + n_pages pages (all of the pages).
        1 + n_pages,
        # Create a parent node for the last n_pages.
        n_pages,
        # Don't push additional pages.
        0,
        # Take the first page (the main part) and the node that was created (onchain data)
        # and use them to construct the root of the fact tree.
        2,
    ])"#};

#[allow(unused)]
pub const HINT_14: &str = indoc! {r#"memory[fp + 18] = to_felt_or_relocatable(syscall_handler.block_info.use_kzg_da and (
    not os_input.full_output
))"#};
