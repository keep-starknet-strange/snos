use std::collections::HashMap;

use cairo_vm::hint_processor::builtin_hint_processor::dict_manager::Dictionary;
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_integer_from_var_name, get_maybe_relocatable_from_var_name, get_ptr_from_var_name, insert_value_from_var_name,
};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::hint_processor::hint_processor_utils::felt_to_usize;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::MaybeRelocatable;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use indoc::indoc;

use crate::hints::vars;
use crate::utils::custom_hint_error;

pub const N_UNIQUE_VALUE_BUCKETS: u64 = 6;
pub const TOTAL_N_BUCKETS: u64 = N_UNIQUE_VALUE_BUCKETS + 1;

pub const DICTIONARY_FROM_BUCKET: &str =
    indoc! {r#"initial_dict = {bucket_index: 0 for bucket_index in range(ids.TOTAL_N_BUCKETS)}"#};
pub fn dictionary_from_bucket(
    _vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let initial_dict: HashMap<MaybeRelocatable, MaybeRelocatable> =
        (0..TOTAL_N_BUCKETS).map(|bucket_index| (Felt252::from(bucket_index).into(), Felt252::ZERO.into())).collect();
    exec_scopes.insert_box(vars::scopes::INITIAL_DICT, Box::new(initial_dict));
    Ok(())
}

pub const GET_PREV_OFFSET: &str = indoc! {r#"
	dict_tracker = __dict_manager.get_tracker(ids.dict_ptr)
    ids.prev_offset = dict_tracker.data[ids.bucket_index]"#
};

pub fn get_prev_offset(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let dict_ptr = get_ptr_from_var_name(vars::ids::DICT_PTR, vm, ids_data, ap_tracking)?;

    let dict_tracker = match exec_scopes.get_dict_manager()?.borrow().get_tracker(dict_ptr)?.data.clone() {
        Dictionary::SimpleDictionary(hash_map) => hash_map,
        Dictionary::DefaultDictionary { dict, .. } => dict,
    };

    let bucket_index = get_maybe_relocatable_from_var_name(vars::ids::BUCKET_INDEX, vm, ids_data, ap_tracking)?;

    let prev_offset = match dict_tracker.get(&bucket_index) {
        Some(offset) => offset.clone(),
        None => return Err(custom_hint_error("No prev_offset found for the given bucket_index")),
    };

    exec_scopes.insert_box(vars::scopes::DICT_TRACKER, Box::new(dict_tracker));
    insert_value_from_var_name(vars::ids::PREV_OFFSET, prev_offset, vm, ids_data, ap_tracking)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use cairo_vm::hint_processor::builtin_hint_processor::dict_manager::DictManager;
    use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::get_integer_from_var_name;
    use cairo_vm::types::relocatable::Relocatable;
    use rstest::rstest;

    use super::*;

    #[rstest]
    fn test_dictionary_from_bucket() {
        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_fp(2);

        let ap_tracking = ApTracking::new();
        let constants = HashMap::new();
        let ids_data = HashMap::new();

        vm.insert_value(Relocatable::from((1, 0)), Felt252::from(2)).unwrap();

        let mut exec_scopes: ExecutionScopes = Default::default();

        dictionary_from_bucket(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants).unwrap();

        let initial_dict: HashMap<MaybeRelocatable, MaybeRelocatable> =
            exec_scopes.get(vars::scopes::INITIAL_DICT).unwrap();

        assert_eq!(
            initial_dict,
            HashMap::from_iter(
                [(0, 0), (1, 0), (2, 0), (3, 0), (4, 0), (5, 0), (6, 0)]
                    .map(|v| (Felt252::from(v.0).into(), Felt252::from(v.1).into()))
            )
        );
    }

    #[rstest]
    fn test_get_prev_offset() {
        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_fp(3);

        let ap_tracking = ApTracking::new();
        let constants = HashMap::new();
        let ids_data = HashMap::from([
            (vars::ids::DICT_PTR.to_string(), HintReference::new_simple(-3)),
            (vars::ids::BUCKET_INDEX.to_string(), HintReference::new_simple(-2)),
            (vars::ids::PREV_OFFSET.to_string(), HintReference::new_simple(-1)),
        ]);

        let mut exec_scopes: ExecutionScopes = Default::default();

        let mut dict_manager = DictManager::new();

        let dict_ptr =
            dict_manager.new_dict(&mut vm, HashMap::from([((1, 0).into(), MaybeRelocatable::from(123))])).unwrap();

        insert_value_from_var_name(vars::ids::DICT_PTR, dict_ptr, &mut vm, &ids_data, &ap_tracking).unwrap();

        insert_value_from_var_name(vars::ids::BUCKET_INDEX, (1, 0), &mut vm, &ids_data, &ap_tracking).unwrap();

        exec_scopes.insert_value(vars::scopes::DICT_MANAGER, Rc::new(RefCell::new(dict_manager)));

        get_prev_offset(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants).unwrap();

        let offset = get_integer_from_var_name(vars::ids::PREV_OFFSET, &vm, &ids_data, &ap_tracking).unwrap();

        assert_eq!(offset, Felt252::from(123));
    }
}

use crate::utils::get_constant;

const COMPRESSION_VERSION: u8 = 0;
const MAX_N_BITS: usize = 251;
const N_UNIQUE_VALUE_BUCKETS: usize = 6;
const TOTAL_N_BUCKETS: usize = N_UNIQUE_VALUE_BUCKETS + 1;

#[derive(Debug, Clone)]
struct UniqueValueBucket {
    n_bits: Felt252,
    value_to_index: HashMap<Felt252, usize>,
}

impl UniqueValueBucket {
    fn new(n_bits: Felt252) -> Self {
        Self { n_bits, value_to_index: HashMap::new() }
    }

    fn add(&mut self, value: &Felt252) {
        if !self.value_to_index.contains_key(value) {
            let next_index = self.value_to_index.len();
            self.value_to_index.insert(*value, next_index);
        }
    }

    fn get_index(&self, value: &Felt252) -> Option<usize> {
        self.value_to_index.get(value).copied()
    }

    fn pack_in_felts(&self) -> Vec<&Felt252> {
        let mut values: Vec<&Felt252> = self.value_to_index.keys().collect();
        values.sort_by_key(|&v| self.value_to_index[v]);
        values
    }
}

struct CompressionSet {
    buckets: Vec<UniqueValueBucket>,
    sorted_buckets: Vec<(usize, UniqueValueBucket)>,
    repeating_value_locations: Vec<(usize, usize)>,
    bucket_index_per_elm: Vec<usize>,
    finalized: bool,
}

impl CompressionSet {
    fn new(n_bits_per_bucket: Vec<Felt252>) -> Self {
        let buckets: Vec<UniqueValueBucket> =
            n_bits_per_bucket.iter().map(|&n_bits| UniqueValueBucket::new(n_bits)).collect();

        let mut indexed_buckets: Vec<(usize, UniqueValueBucket)> = Vec::new();
        for (index, bucket) in buckets.iter().enumerate() {
            indexed_buckets.push((index, bucket.clone()));
        }
        indexed_buckets.sort_by(|a, b| a.1.n_bits.cmp(&b.1.n_bits));

        CompressionSet {
            buckets,
            sorted_buckets: indexed_buckets,
            repeating_value_locations: Vec::new(),
            bucket_index_per_elm: Vec::new(),
            finalized: false,
        }
    }

    fn update(&mut self, values: Vec<Felt252>) {
        assert!(!self.finalized, "Cannot add values after finalizing.");
        let buckets_len = self.buckets.len();
        for value in values.iter() {
            for (bucket_index, bucket) in self.sorted_buckets.iter_mut() {
                if Felt252::from(value.bits()) <= bucket.n_bits {
                    if bucket.value_to_index.contains_key(value) {
                        // Repeated value; add the location of the first added copy.
                        if let Some(index) = bucket.get_index(value) {
                            self.repeating_value_locations.push((*bucket_index, index));
                            self.bucket_index_per_elm.push(buckets_len);
                        }
                    } else {
                        // First appearance of this value.
                        bucket.add(value);
                        self.bucket_index_per_elm.push(*bucket_index);
                    }
                }
            }
        }
    }

    fn finalize(&mut self) {
        self.finalized = true;
    }
    pub fn get_bucket_index_per_elm(&self) -> Vec<usize> {
        assert!(self.finalized, "Cannot get bucket_index_per_elm before finalizing.");
        self.bucket_index_per_elm.clone()
    }

    pub fn get_unique_value_bucket_lengths(&self) -> Vec<usize> {
        self.sorted_buckets.iter().map(|elem| elem.1.value_to_index.len()).collect()
    }

    pub fn get_repeating_value_bucket_length(&self) -> usize {
        self.repeating_value_locations.len()
    }

    pub fn pack_unique_values(&self) -> Vec<Felt252> {
        assert!(self.finalized, "Cannot pack before finalizing.");
        // Chain the packed felts from each bucket into a single vector.
        self.buckets.iter().flat_map(|bucket| bucket.pack_in_felts()).cloned().collect()
    }

    /// Returns a list of pointers corresponding to the repeating values.
    /// The pointers point to the chained unique value buckets.
    pub fn get_repeating_value_pointers(&self) -> Vec<usize> {
        assert!(self.finalized, "Cannot get pointers before finalizing.");

        let unique_value_bucket_lengths = self.get_unique_value_bucket_lengths();
        let bucket_offsets = get_bucket_offsets(unique_value_bucket_lengths);

        let mut pointers = Vec::new();
        for (bucket_index, index_in_bucket) in self.repeating_value_locations.iter() {
            pointers.push(bucket_offsets[*bucket_index] + index_in_bucket);
        }

        pointers
    }
}

fn pack_in_felt(elms: Vec<usize>, elm_bound: usize) -> Felt252 {
    let mut res = Felt252::ZERO;
    for (i, &elm) in elms.iter().enumerate() {
        res += Felt252::from(elm * elm_bound.pow(i as u32));
    }
    assert!(res.to_biguint() < Felt252::prime(), "Out of bound packing.");
    res
}

fn pack_in_felts(elms: Vec<usize>, elm_bound: usize) -> Vec<Felt252> {
    assert!(elms.iter().all(|&elm| elm < elm_bound), "Element out of bound.");

    elms.chunks(get_n_elms_per_felt(elm_bound)).map(|chunk| pack_in_felt(chunk.to_vec(), elm_bound)).collect()
}

fn get_bucket_offsets(bucket_lengths: Vec<usize>) -> Vec<usize> {
    let mut offsets = Vec::new();
    let mut sum = 0;
    for length in bucket_lengths {
        offsets.push(sum);
        sum += length;
    }
    offsets
}

fn log2_ceil(x: usize) -> usize {
    assert!(x > 0);
    (x - 1).count_ones() as usize
}

fn get_n_elms_per_felt(elm_bound: usize) -> usize {
    if elm_bound <= 1 {
        return MAX_N_BITS;
    }
    if elm_bound > 2_usize.pow(MAX_N_BITS as u32) {
        return 1;
    }

    MAX_N_BITS / log2_ceil(elm_bound)
}

fn compression(
    data: Vec<Felt252>,
    data_size: usize,
    constants: &HashMap<String, Felt252>,
) -> Result<Vec<Felt252>, HintError> {
    let n_bits_per_bucket = vec![
        Felt252::from(252),
        Felt252::from(125),
        Felt252::from(83),
        Felt252::from(62),
        Felt252::from(31),
        Felt252::from(15),
    ];
    let header_elm_n_bits = felt_to_usize(get_constant(vars::constants::HEADER_ELM_N_BITS, constants)?)?;
    let header_elm_bound = 1usize << header_elm_n_bits;

    assert!(data_size < header_elm_bound, "Data length exceeds the header element bound");

    let mut compression_set = CompressionSet::new(n_bits_per_bucket);
    compression_set.update(data);
    compression_set.finalize();

    let bucket_index_per_elm = compression_set.get_bucket_index_per_elm();

    let unique_value_bucket_lengths = compression_set.get_unique_value_bucket_lengths();
    let n_unique_values = unique_value_bucket_lengths.iter().sum::<usize>();

    let mut header = vec![COMPRESSION_VERSION as usize, data_size];
    header.extend(unique_value_bucket_lengths.iter().cloned());
    header.push(compression_set.get_repeating_value_bucket_length());

    let packed_header = vec![pack_in_felt(header, header_elm_bound)];

    let packed_repeating_value_pointers =
        pack_in_felts(compression_set.get_repeating_value_pointers(), n_unique_values);

    let packed_bucket_index_per_elm = pack_in_felts(bucket_index_per_elm, TOTAL_N_BUCKETS);

    let compressed_data = packed_header
        .into_iter()
        .chain(compression_set.pack_unique_values().into_iter())
        .chain(packed_repeating_value_pointers.into_iter())
        .chain(packed_bucket_index_per_elm.into_iter())
        .collect::<Vec<Felt252>>();

    Ok(compressed_data)
}

pub const COMPRESS: &str = indoc! {r#"from starkware.starknet.core.os.data_availability.compression import compress
    data = memory.get_range_as_ints(addr=ids.data_start, size=ids.data_end - ids.data_start)
    segments.write_arg(ids.compressed_dst, compress(data))"#};

pub fn compress(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let data_start = get_ptr_from_var_name(vars::ids::DATA_START, vm, ids_data, ap_tracking)?;
    let data_end = get_ptr_from_var_name(vars::ids::DATA_END, vm, ids_data, ap_tracking)?;
    let data_size = (data_end - data_start)?;

    let compressed_dst = get_ptr_from_var_name(vars::ids::COMPRESSED_DST, vm, ids_data, ap_tracking)?;

    let data: Vec<Felt252> = vm.get_integer_range(data_start, data_size)?.into_iter().map(|s| *s).collect();
    let compress_result = compression(data, data_size, constants)?
        .into_iter()
        .map(MaybeRelocatable::Int)
        .collect::<Vec<MaybeRelocatable>>();

    vm.write_arg(compressed_dst, &compress_result)?;

    Ok(())
}

pub const SET_DECOMPRESSED_DST: &str = indoc! {r#"memory[ids.decompressed_dst] = ids.packed_felt % ids.elm_bound"#
};

pub fn set_decompressed_dst(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let decompressed_dst = get_ptr_from_var_name(vars::ids::DECOMPRESSED_DST, vm, ids_data, ap_tracking)?;

    let packed_felt = get_integer_from_var_name(vars::ids::PACKED_FELT, vm, ids_data, ap_tracking)?.to_biguint();
    let elm_bound = get_integer_from_var_name(vars::ids::ELM_BOUND, vm, ids_data, ap_tracking)?.to_biguint();

    vm.insert_value(decompressed_dst, Felt252::from(packed_felt % elm_bound))?;
    Ok(())
}
