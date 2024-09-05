use indoc::indoc;

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
pub const HINT_4: &str = indoc! {r#"exit_syscall(selector=ids.SHA256_PROCESS_BLOCK_SELECTOR)"#};

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
