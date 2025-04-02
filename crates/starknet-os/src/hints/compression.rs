/// This file represents a re-implementation of the python compression module
/// https://github.com/starkware-libs/cairo-lang/blob/master/src/starkware/starknet/core/os/data_availability/compression.py
use std::collections::HashMap;
use std::iter::once;

use cairo_vm::Felt252;
use cairo_vm::hint_processor::builtin_hint_processor::dict_manager::Dictionary;
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_integer_from_var_name, get_maybe_relocatable_from_var_name, get_ptr_from_var_name, insert_value_from_var_name,
};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::MaybeRelocatable;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use indoc::indoc;
use lazy_static::lazy_static;
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, ToPrimitive, Zero};

use crate::hints::vars;
use crate::utils::custom_hint_error;

const COMPRESSION_VERSION: u8 = 0;
const MAX_N_BITS: usize = 251;
const HEADER_ELM_N_BITS: usize = 20;

/// Array that specifies the number of bits allocated to each bucket.
/// Values requiring fewer bits will be placed in smaller-bit buckets,
/// and values requiring more bits will be placed in larger-bit buckets.
const N_BITS_PER_BUCKET: [usize; 6] = [252, 125, 83, 62, 31, 15];
const TOTAL_N_BUCKETS: usize = N_BITS_PER_BUCKET.len() + 1;
const HEADER_LEN: usize = 1 + 1 + TOTAL_N_BUCKETS;

lazy_static! {
    static ref HEADER_ELM_BOUND: BigUint = BigUint::one() << HEADER_ELM_N_BITS;
}

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

pub const GET_PREV_OFFSET: &str = indoc! {r#"dict_tracker = __dict_manager.get_tracker(ids.dict_ptr)
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

/// A set-like data structure that preserves the insertion order.
/// Holds values of `n_bits` bit length or less.
#[derive(Default, Clone, Debug)]
struct UniqueValueBucket {
    n_bits: usize,
    value_to_index: indexmap::IndexMap<BigUint, usize>,
}

impl UniqueValueBucket {
    /// `n_bits` is an individual value associated with a specific bucket,
    /// that specifies the maximum number of bits that values in that bucket can have.
    /// It ensures that only values whose bit width is less than or equal are added to the corresponding bucket.
    fn new(n_bits: usize) -> Self {
        Self { n_bits, value_to_index: Default::default() }
    }

    fn contains(&self, value: &BigUint) -> bool {
        self.value_to_index.contains_key(value)
    }

    fn len(&self) -> usize {
        self.value_to_index.len()
    }

    fn add(&mut self, value: BigUint) {
        if !self.contains(&value) {
            let next_index = self.value_to_index.len();
            self.value_to_index.insert(value, next_index);
        }
    }

    fn get_index(&self, value: &BigUint) -> usize {
        *self.value_to_index.get(value).expect("The value provided is not in the index")
    }

    fn pack_in_felts(&self) -> Vec<BigUint> {
        let values: Vec<BigUint> = self.value_to_index.keys().cloned().collect();
        pack_in_felts(&values, &(BigUint::one() << self.n_bits))
    }
}

/// A utility class for compression.
/// Used to manage and store the unique values in seperate buckets according to their bit length.
#[derive(Default, Clone, Debug)]
struct CompressionSet {
    buckets: Vec<UniqueValueBucket>,
    sorted_buckets: Vec<(usize, UniqueValueBucket)>,
    repeating_value_locations: Vec<(usize, usize)>,
    bucket_index_per_elm: Vec<usize>,
    finalized: bool,
}

impl CompressionSet {
    /// Creates a new Compression set given an array of the n_bits per each bucket in the set
    fn new(n_bits_per_bucket: &[usize]) -> Self {
        let buckets: Vec<UniqueValueBucket> =
            n_bits_per_bucket.iter().map(|&n_bits| UniqueValueBucket::new(n_bits)).collect();

        let mut sorted_buckets: Vec<(usize, UniqueValueBucket)> = buckets.clone().into_iter().enumerate().collect();

        sorted_buckets.sort_by_key(|(_, bucket)| bucket.n_bits);
        Self {
            buckets,
            sorted_buckets,
            repeating_value_locations: Vec::new(),
            bucket_index_per_elm: Vec::new(),
            finalized: false,
        }
    }

    /// Returns the bucket indices of the added values.
    fn get_bucket_index_per_elm(&self) -> Vec<usize> {
        assert!(self.finalized, "Cannot get bucket_index_per_elm before finalizing.");
        self.bucket_index_per_elm.clone()
    }

    fn repeating_values_bucket_index(&self) -> usize {
        self.buckets.len()
    }

    /// This method iterates over the provided values and assigns each value to the appropriate bucket
    /// based on the number of bits required to represent it. If a value is already in a bucket, it is
    /// recorded as a repeating value. Otherwise, it is added to the appropriate bucket.
    fn update(&mut self, values: &[BigUint]) {
        assert!(!self.finalized, "Cannot add values after finalizing.");

        for value in values {
            for (bucket_index, bucket) in &mut self.sorted_buckets {
                if value.bits() as usize <= bucket.n_bits {
                    if bucket.contains(value) {
                        self.repeating_value_locations.push((*bucket_index, bucket.get_index(value)));
                        self.bucket_index_per_elm.push(self.repeating_values_bucket_index());
                    } else {
                        self.buckets[*bucket_index].add(value.clone());
                        bucket.add(value.clone());
                        self.bucket_index_per_elm.push(*bucket_index);
                    }
                    break;
                }
            }
        }
    }

    fn get_unique_value_bucket_lengths(&self) -> Vec<usize> {
        self.buckets.iter().map(|bucket| bucket.len()).collect()
    }

    fn get_repeating_value_bucket_length(&self) -> usize {
        self.repeating_value_locations.len()
    }

    /// Returns a list of BigUint corresponding to the repeating values.
    /// The BigUint point to the chained unique value buckets.
    fn get_repeating_value_pointers(&self) -> Vec<BigUint> {
        assert!(self.finalized, "Cannot get pointers before finalizing.");

        let unique_value_bucket_lengths = self.get_unique_value_bucket_lengths();
        let bucket_offsets = get_bucket_offsets(&unique_value_bucket_lengths);

        self.repeating_value_locations
            .iter()
            .map(|&(bucket_index, index_in_bucket)| &bucket_offsets[bucket_index] + BigUint::from(index_in_bucket))
            .collect()
    }

    fn pack_unique_values(&self) -> Vec<BigUint> {
        assert!(self.finalized, "Cannot pack before finalizing.");
        self.buckets.iter().flat_map(|bucket| bucket.pack_in_felts()).collect()
    }

    fn finalize(&mut self) {
        self.finalized = true;
    }
}

/// Compresses the data provided to output a Vec of compressed Felts
fn compress(data: &[BigUint]) -> Vec<BigUint> {
    assert!(data.len() < HEADER_ELM_BOUND.to_usize().unwrap(), "Data is too long.");

    let mut compression_set = CompressionSet::new(&N_BITS_PER_BUCKET);
    compression_set.update(data);
    compression_set.finalize();

    let bucket_index_per_elm = compression_set.get_bucket_index_per_elm();
    let unique_value_bucket_lengths = compression_set.get_unique_value_bucket_lengths();
    let n_unique_values: usize = unique_value_bucket_lengths.iter().sum();

    let mut header: Vec<BigUint> = vec![BigUint::from(COMPRESSION_VERSION), BigUint::from(data.len())];
    header.extend(unique_value_bucket_lengths.iter().map(|&len| BigUint::from(len)));
    header.push(BigUint::from(compression_set.get_repeating_value_bucket_length()));

    let packed_header = pack_in_felts(&header, &HEADER_ELM_BOUND);
    let packed_repeating_value_pointers =
        pack_in_felts(&compression_set.get_repeating_value_pointers(), &BigUint::from(n_unique_values));
    let packed_bucket_index_per_elm = pack_in_felts(
        &bucket_index_per_elm.into_iter().map(BigUint::from).collect::<Vec<_>>(),
        &BigUint::from(TOTAL_N_BUCKETS),
    );

    let unique_values = compression_set.pack_unique_values();
    let mut result = Vec::new();
    result.extend(packed_header);
    result.extend(unique_values);
    result.extend(packed_repeating_value_pointers);
    result.extend(packed_bucket_index_per_elm);
    result
}

/// Decompresses the given compressed data.
pub fn decompress(compressed: &mut impl Iterator<Item = BigUint>) -> Vec<BigUint> {
    fn unpack_chunk(
        compressed: &mut impl Iterator<Item = BigUint>,
        n_elms: usize,
        elm_bound: &BigUint,
    ) -> Vec<BigUint> {
        let n_packed_felts = n_elms.div_ceil(get_n_elms_per_felt(elm_bound));

        let mut compressed_chunk = Vec::new();
        for _ in 0..n_packed_felts {
            if let Some(felt) = compressed.next() {
                dbg!(&felt);
                compressed_chunk.push(felt);
            }
        }
        unpack_felts(&compressed_chunk, elm_bound, n_elms)
    }

    let header = unpack_chunk(compressed, HEADER_LEN, &HEADER_ELM_BOUND);
    let version = &header[0];
    assert!(version == &BigUint::from(COMPRESSION_VERSION), "Unsupported compression version.");

    let data_len = header[1].to_usize().expect("Must have a data length");
    let unique_value_bucket_lengths: Vec<usize> =
        header[2..2 + N_BITS_PER_BUCKET.len()].iter().map(|x| x.to_usize().expect("Should fit in usize")).collect();
    let n_repeating_values = header[2 + N_BITS_PER_BUCKET.len()].to_usize().expect("Should fit in usize");

    let mut unique_values = Vec::new();
    for (&length, &n_bits) in unique_value_bucket_lengths.iter().zip(&N_BITS_PER_BUCKET) {
        unique_values.extend(unpack_chunk(compressed, length, &(&BigUint::one() << n_bits)));
    }

    let repeating_value_pointers = unpack_chunk(compressed, n_repeating_values, &BigUint::from(unique_values.len()));

    let repeating_values: Vec<BigUint> = repeating_value_pointers
        .iter()
        .map(|ptr| unique_values[ptr.to_usize().expect("Should fit in usize")].clone())
        .collect();

    let mut all_values = unique_values;
    all_values.extend(repeating_values);

    let bucket_index_per_elm: Vec<usize> = unpack_chunk(compressed, data_len, &BigUint::from(TOTAL_N_BUCKETS))
        .iter()
        .map(|x| x.to_usize().expect("Should fit in usize"))
        .collect();

    let all_bucket_lengths: Vec<usize> =
        unique_value_bucket_lengths.iter().cloned().chain(once(n_repeating_values)).collect();

    let bucket_offsets = get_bucket_offsets(&all_bucket_lengths);

    let mut bucket_offset_iterators: Vec<BigUint> = bucket_offsets;

    bucket_index_per_elm
        .iter()
        .map(|&bucket_index| {
            let offset = &mut bucket_offset_iterators[bucket_index];
            let value = all_values[offset.to_usize().unwrap()].clone();
            *offset += BigUint::one();
            value
        })
        .collect()
}

fn unpack_felts(compressed: &[BigUint], elm_bound: &BigUint, n_elms: usize) -> Vec<BigUint> {
    let n_elms_per_felt = get_n_elms_per_felt(elm_bound);
    let mut result = Vec::with_capacity(n_elms);

    for felt in compressed {
        let mut remaining = felt.clone();
        for _ in 0..n_elms_per_felt {
            let (new_remaining, value) = remaining.div_rem(elm_bound);
            result.push(value);
            remaining = new_remaining;

            if result.len() == n_elms {
                break;
            }
        }

        if result.len() == n_elms {
            break;
        }
    }

    result
}

/// Packs a list of elements into multiple felts, ensuring that each felt contains as many elements as can fit
fn pack_in_felts(elms: &[BigUint], elm_bound: &BigUint) -> Vec<BigUint> {
    elms.chunks(get_n_elms_per_felt(elm_bound)).map(|chunk| pack_in_felt(chunk, elm_bound)).collect()
}

/// Packs a chunk of elements into a single felt.
fn pack_in_felt(elms: &[BigUint], elm_bound: &BigUint) -> BigUint {
    elms.iter().enumerate().fold(BigUint::zero(), |acc, (i, elm)| acc + elm * elm_bound.pow(i as u32))
}

/// Computes the starting offsets for each bucket in a list of buckets, based on their lengths.
fn get_bucket_offsets(bucket_lengths: &[usize]) -> Vec<BigUint> {
    let mut offsets = Vec::with_capacity(bucket_lengths.len());
    let mut current = BigUint::zero();

    for &length in bucket_lengths {
        offsets.push(current.clone());
        current += BigUint::from(length);
    }

    offsets
}

/// Calculates the number of elements that can fit in a single felt value, given the element bound.
fn get_n_elms_per_felt(elm_bound: &BigUint) -> usize {
    if elm_bound <= &BigUint::one() {
        return MAX_N_BITS;
    }
    if elm_bound > &(BigUint::one() << MAX_N_BITS) {
        return 1;
    }
    MAX_N_BITS / ((elm_bound.bits() as f64).log2().ceil() as usize)
}

pub const COMPRESSION_HINT: &str = indoc! {r#"from starkware.starknet.core.os.data_availability.compression import compress
    data = memory.get_range_as_ints(addr=ids.data_start, size=ids.data_end - ids.data_start)
    segments.write_arg(ids.compressed_dst, compress(data))"#};

pub fn compression_hint(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let data_start = get_ptr_from_var_name(vars::ids::DATA_START, vm, ids_data, ap_tracking)?;
    let data_end = get_ptr_from_var_name(vars::ids::DATA_END, vm, ids_data, ap_tracking)?;
    let data_size = (data_end - data_start)?;

    let compressed_dst = get_ptr_from_var_name(vars::ids::COMPRESSED_DST, vm, ids_data, ap_tracking)?;
    let data: Vec<BigUint> = vm.get_integer_range(data_start, data_size)?.iter().map(|s| s.to_biguint()).collect();
    let compress_result =
        compress(&data).into_iter().map(|s| MaybeRelocatable::Int(Felt252::from(s))).collect::<Vec<MaybeRelocatable>>();

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

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::str::FromStr;

    use cairo_vm::hint_processor::builtin_hint_processor::dict_manager::DictManager;
    use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::get_integer_from_var_name;
    use cairo_vm::types::relocatable::Relocatable;
    use num_traits::FromPrimitive;
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case(0, MAX_N_BITS)]
    #[case(1, MAX_N_BITS)]
    #[case(16, 83)]
    #[case(10, 125)]
    #[case(100, 83)]
    #[case(500, 62)]
    #[case(10000, 62)]
    #[case(125789, 50)]
    fn test_get_n_elms_per_felt(#[case] input: usize, #[case] expected: usize) {
        assert_eq!(get_n_elms_per_felt(&BigUint::from(input)), expected);
    }

    // These values are calculated by importing the module and running the compression method
    // ```py
    // # import compress from compression
    // def main() -> int:
    //     print(compress([2,3,1]))
    //     return 0
    // ```
    #[rstest]
    #[case::single_value_1(vec![1u32], vec!["1393796574908163946345982392040522595172352", "1", "5"])]
    #[case::single_value_2(vec![2u32], vec!["1393796574908163946345982392040522595172352", "2", "5"])]
    #[case::single_value_3(vec![10u32], vec!["1393796574908163946345982392040522595172352", "10", "5"])]
    #[case::two_values(vec![1u32, 2], vec!["2787593149816327892691964784081045190344704", "65537", "40"])]
    #[case::three_values(vec![2u32, 3, 1], vec!["4181389724724491839037947176121567785517056", "1073840130", "285"])]
    #[case::four_values(vec![1u32, 2, 3, 4], vec!["5575186299632655785383929568162090380689408", "140740709646337", "2000"])]
    #[case::extracted_kzg_example(vec![1u32, 1, 6, 1991, 66, 0], vec!["1461508606313777459023416562628243222268909453312", "2324306378031105", "0", "98047"])]

    fn test_compress_decompress(#[case] input: Vec<u32>, #[case] expected: Vec<&str>) {
        let data: Vec<BigUint> = input.into_iter().map(BigUint::from).collect();

        let compressed = compress(&data);

        let expected: Vec<_> = expected.iter().map(|s| BigUint::from_str(s).unwrap()).collect();

        assert_eq!(compressed, expected);

        let decompressed = decompress(&mut compressed.into_iter());

        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_get_bucket_offsets() {
        let lengths = vec![2, 3, 5];
        let offsets = get_bucket_offsets(&lengths);
        assert_eq!(offsets.len(), lengths.len());
        assert_eq!(offsets[0], BigUint::from(0u32));
        assert_eq!(offsets[1], BigUint::from(2u32));
        assert_eq!(offsets[2], BigUint::from(5u32));
    }

    #[test]
    fn test_update_with_unique_values() {
        let mut compression_set = CompressionSet::new(&[8, 16, 32]);
        let values = vec![
            BigUint::from_u32(42).unwrap(),
            BigUint::from_u64(12833943439439439).unwrap(),
            BigUint::from_u32(1283394343).unwrap(),
        ];

        compression_set.update(&values);

        let unique_lengths = compression_set.get_unique_value_bucket_lengths();
        assert_eq!(unique_lengths, vec![1, 0, 1]);
    }

    #[test]
    fn test_update_with_repeated_values() {
        let mut compression_set = CompressionSet::new(&[8, 16, 32]);
        let values = vec![BigUint::from_u32(42).unwrap(), BigUint::from_u32(42).unwrap()];

        compression_set.update(&values);

        let unique_lengths = compression_set.get_unique_value_bucket_lengths();
        assert_eq!(unique_lengths, vec![1, 0, 0]);
        assert_eq!(compression_set.get_repeating_value_bucket_length(), 1);
    }

    #[test]
    fn test_get_repeating_value_pointers_with_repeated_values() {
        let mut compression_set = CompressionSet::new(&[8, 16, 32]);
        let values = vec![BigUint::from_u32(42).unwrap(), BigUint::from_u32(42).unwrap()];

        compression_set.update(&values);
        compression_set.finalize();

        let pointers = compression_set.get_repeating_value_pointers();
        assert_eq!(pointers.len(), 1);
        assert_eq!(pointers[0], BigUint::from(0u32));
    }

    #[test]
    fn test_get_repeating_value_pointers_with_no_repeated_values() {
        let mut compression_set = CompressionSet::new(&[8, 16, 32]);
        let values = vec![BigUint::from_u32(42).unwrap(), BigUint::from_u32(128).unwrap()];

        compression_set.update(&values);
        compression_set.finalize();

        let pointers = compression_set.get_repeating_value_pointers();
        assert!(pointers.is_empty());
    }

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
