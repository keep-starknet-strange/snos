use std::any::Any;
use std::collections::HashMap;

use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_integer_from_var_name, get_ptr_from_var_name, get_relocatable_from_var_name, insert_value_from_var_name,
};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::errors::math_errors::MathError;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::MaybeRelocatable;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use indoc::indoc;
use num_bigint::BigInt;
use num_traits::{Num, One, Zero};

use crate::execution::helper::ExecutionHelperWrapper;
use crate::hints::vars;
use crate::starknet::core::os::contract_class::compiled_class_hash_objects::{BytecodeSegment, BytecodeSegmentedNode};
use crate::storage::storage::Storage;
use crate::utils::execute_coroutine;

const FIELD_ELEMENTS_PER_BLOB: usize = 4096;
const COMMITMENT_BYTES_LENGTH: usize = 48;
const COMMITMENT_LOW_BIT_LENGTH: usize = (COMMITMENT_BYTES_LENGTH * 8) / 2;
const BLOB_SUBGROUP_GENERATOR: &str = "39033254847818212395286706435128746857159659164139250548781411570340225835782";
const CKZG_VERSION: &str = "1.0.0";

fn serialize_blob(blob: Vec<BigInt>) -> Vec<u8> {
    assert_eq!(blob.len(), FIELD_ELEMENTS_PER_BLOB, "Bad blob size.");

    blob.into_iter().flat_map(|x| x.to_bytes_le().1).collect()
}

fn is_power_of_2(n: usize) -> bool {
    n > 0 && (n & (n - 1)) == 0
}

fn fft(coeffs: Vec<BigInt>, generator: BigInt, prime: BigInt, bit_reversed: bool) -> Vec<BigInt> {
    fn _fft(coeffs: &[BigInt], group: &[BigInt], prime: &BigInt) -> Vec<BigInt> {
        if coeffs.len() == 1 {
            return coeffs.to_vec();
        }

        let f_even = _fft(
            &coeffs.iter().step_by(2).cloned().collect::<Vec<_>>(),
            &group.iter().step_by(2).cloned().collect::<Vec<_>>(),
            prime,
        );
        let f_odd = _fft(
            &coeffs.iter().skip(1).step_by(2).cloned().collect::<Vec<_>>(),
            &group.iter().step_by(2).cloned().collect::<Vec<_>>(),
            prime,
        );

        let group_mul_f_odd: Vec<BigInt> =
            group.iter().take(f_odd.len()).zip(f_odd.iter()).map(|(g, f)| (g * f) % prime).collect();

        let mut result = Vec::with_capacity(coeffs.len());
        for i in 0..f_even.len() {
            result.push((f_even[i].clone() + &group_mul_f_odd[i]) % prime);
        }
        for i in 0..f_even.len() {
            result.push((f_even[i].clone() - &group_mul_f_odd[i]) % prime);
        }

        result
    }

    if coeffs.is_empty() {
        return vec![];
    }

    let coeffs_len = coeffs.len();
    assert!(is_power_of_2(coeffs_len), "Length is not a power of two.");

    let mut group = vec![BigInt::one()];
    for _ in 1..coeffs_len {
        let last = group.last().unwrap();
        group.push((last * &generator) % &prime);
    }

    let mut values = _fft(&coeffs, &group, &prime);

    if bit_reversed {
        let width = coeffs_len.trailing_zeros() as usize;
        let perm: Vec<usize> = (0..coeffs_len)
            .map(|i| {
                let binary = format!("{:0width$b}", i, width = width);
                usize::from_str_radix(&binary.chars().rev().collect::<String>(), 2).unwrap()
            })
            .collect();
        values = perm.into_iter().map(|i| values[i].clone()).collect();
    }

    values
}

fn split_commitment(num: BigInt) -> (BigInt, BigInt) {
    let low_part = &num % (BigInt::one() << COMMITMENT_LOW_BIT_LENGTH);
    let high_part = &num >> COMMITMENT_LOW_BIT_LENGTH;
    (low_part, high_part)
}

pub fn polynomial_coefficients_to_kzg_commitment(coefficients: Vec<BigInt>) -> (BigInt, BigInt) {
    let generator = BigInt::from_str_radix(BLOB_SUBGROUP_GENERATOR, 10).unwrap();
    let prime = BigInt::from(2).pow(255) - BigInt::from(19);

    // Perform FFT on the polynomial coefficients
    let fft_values = fft(coefficients, generator, prime.clone(), true);

    // Combine the FFT result to get the commitment (example combining method, replace with your
    // specific method)
    let commitment_value = fft_values.iter().fold(BigInt::zero(), |acc, x| (acc + x) % &prime);

    // Split the commitment value into two parts
    split_commitment(commitment_value)
}

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

pub async fn write_zkg_commitment_address_async<S: Storage + 'static>(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    use num_traits::ToPrimitive;
    let state_updates_start = get_relocatable_from_var_name("state_updates_start", vm, ids_data, ap_tracking)?;
    let da_size = get_integer_from_var_name("da_size", vm, ids_data, ap_tracking)?;
    let range: Vec<MaybeRelocatable> = vm
        .get_range(
            state_updates_start,
            da_size.to_u64().ok_or(MathError::Felt252ToU64Conversion(Box::new(da_size)))?.try_into().unwrap(),
        )
        .into_iter()
        .map(|s| s.unwrap().into_owned())
        .collect();

    let execution_helper = exec_scopes.get::<ExecutionHelperWrapper<S>>(vars::scopes::EXECUTION_HELPER)?;
    let ehw = execution_helper.execution_helper.write().await;
    ehw.da_segment.set(range).expect("DA segment is already initialized.");

    let kzg_ptr = get_ptr_from_var_name("kzg_commitment", vm, ids_data, ap_tracking)?;

    let da_segment = ehw.da_segment.get().unwrap().into_iter().map(|c| c.get_int().unwrap().to_bigint()).collect();
    let commitments = polynomial_coefficients_to_kzg_commitment(da_segment);
    let splits: Vec<MaybeRelocatable> = [commitments.0.into(), commitments.1.into()]
        .into_iter()
        .map(MaybeRelocatable::Int)
        .collect::<Vec<MaybeRelocatable>>();
    vm.write_arg(kzg_ptr, &splits)?;

    Ok(())
}

pub fn write_zkg_commitment_address<S>(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError>
where
    S: Storage + 'static,
{
    execute_coroutine(write_zkg_commitment_address_async::<S>(vm, exec_scopes, ids_data, ap_tracking, _constants))?
}

pub const SET_AP_TO_SEGMENT_HASH: &str = indoc! {r#"
    memory[ap] = to_felt_or_relocatable(bytecode_segment_structure.hash())"#
};

pub async fn set_ap_to_segment<S: Storage + 'static>(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let bytecode_segment_structure: BytecodeSegmentedNode =
        exec_scopes.get(vars::scopes::BYTECODE_SEGMENT_STRUCTURE)?;

    // insert_value_into_ap(vm, Felt252::from(bytecode_segment_structure.hash()))?;
    Ok(())
}

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

pub async fn iter_current_segment_info<S: Storage + 'static>(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let bytecode_segments: BytecodeSegment = exec_scopes.get(vars::scopes::BYTECODE_SEGMENTS)?;
    let bytecode_segment_structure: &mut BytecodeSegmentedNode =
        exec_scopes.get_mut_ref(vars::scopes::BYTECODE_SEGMENT_STRUCTURE)?;

    let current_segment_info = bytecode_segment_structure.segments.iter_mut().next().unwrap();

    let is_used_leaf = Felt252::from(current_segment_info.is_used);

    insert_value_from_var_name("is_used_leaf", is_used_leaf, vm, ids_data, ap_tracking)?;

    let len: usize = current_segment_info.segment_length.0.try_into().unwrap();

    insert_value_from_var_name("segment_length", len, vm, ids_data, ap_tracking)?;
    let inner_structure: Box<dyn Any> = Box::new(current_segment_info.inner_structure.clone());
    exec_scopes.enter_scope(HashMap::from([(String::from("bytecode_segment_structure"), inner_structure)]));

    Ok(())
}
