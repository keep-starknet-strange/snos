use indoc::indoc;

#[allow(unused)]
const LOG2_CEIL: &str = indoc! {r#"
	from starkware.python.math_utils import log2_ceil
    ids.res = log2_ceil(ids.value)"#
};

#[allow(unused)]
const COMPRESS: &str = indoc! {r#"
	from starkware.starknet.core.os.data_availability.compression import compress
    data = memory.get_range_as_ints(addr=ids.data_start, size=ids.data_end - ids.data_start)
    segments.write_arg(ids.compressed_dst, compress(data))"#
};

#[allow(unused)]
pub const DICTIONARY_FROM_BUCKET: &str =
    indoc! {r#"initial_dict = {bucket_index: 0 for bucket_index in range(ids.TOTAL_N_BUCKETS)}"#};

#[allow(unused)]
const GET_PREV_OFFSET: &str = indoc! {r#"
	dict_tracker = __dict_manager.get_tracker(ids.dict_ptr)
    ids.prev_offset = dict_tracker.data[ids.bucket_index]"#
};
