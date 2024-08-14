use std::cell::OnceCell;
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

use c_kzg::{Blob, KzgCommitment};
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_integer_from_var_name, get_ptr_from_var_name, get_relocatable_from_var_name,
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
use crate::storage::storage::Storage;
use crate::utils::execute_coroutine;

const FIELD_ELEMENTS_PER_BLOB: usize = 4096;
const COMMITMENT_BYTES_LENGTH: usize = 48;
const COMMITMENT_LOW_BIT_LENGTH: usize = (COMMITMENT_BYTES_LENGTH * 8) / 2;
const BLOB_SUBGROUP_GENERATOR: &str = "39033254847818212395286706435128746857159659164139250548781411570340225835782";

fn is_power_of_2(n: usize) -> bool {
    n > 0 && (n & (n - 1)) == 0
}

fn fft(coeffs: &[BigInt], generator: &BigInt, prime: &BigInt, bit_reversed: bool) -> Vec<BigInt> {
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
        group.push((last * generator) % prime);
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

fn polynomial_coefficients_to_kzg_commitment(coefficients: Vec<BigInt>) -> Result<(BigInt, BigInt), &'static str> {
    let blob = polynomial_coefficients_to_blob(coefficients).unwrap();
    let commitment_bytes = blob_to_kzg_commitment(&Blob::from_bytes(&blob).unwrap()).unwrap();

    assert_eq!(commitment_bytes.len(), COMMITMENT_BYTES_LENGTH, "Bad commitment bytes length.");
    let commitment_by: Result<Vec<_>, _> = commitment_bytes.bytes().collect();
    Ok(split_commitment(from_bytes(&commitment_by.unwrap())))
}

fn polynomial_coefficients_to_blob(coefficients: Vec<BigInt>) -> Result<Vec<u8>, &'static str> {
    if coefficients.len() > FIELD_ELEMENTS_PER_BLOB {
        return Err("Too many coefficients.");
    }

    // Pad with zeros to complete FIELD_ELEMENTS_PER_BLOB coefficients
    let mut padded_coefficients = coefficients;
    padded_coefficients.resize(FIELD_ELEMENTS_PER_BLOB, BigInt::zero());

    // Perform FFT on the coefficients
    let generator = BigInt::from_str_radix(BLOB_SUBGROUP_GENERATOR, 10).unwrap();
    const BLS_PRIME: &str = "52435875175126190479447740508185965837690552500527637822603658699938581184513";
    let prime = BigInt::from_str_radix(BLS_PRIME, 10).unwrap();
    let fft_result = fft(&padded_coefficients, &generator, &prime, true);

    // Serialize the FFT result into a blob
    Ok(serialize_blob(fft_result))
}

pub fn blob_to_kzg_commitment(blob: &Blob) -> Result<KzgCommitment, c_kzg::Error> {
    c_kzg::KzgCommitment::blob_to_kzg_commitment(
        blob,
        &c_kzg::KzgSettings::load_trusted_setup_file(Path::new(
            "/crates/starknet-os/src/hints/gpoints/trusted_setup.txt",
        ))
        .expect("failed to load trusted setup"),
    )
}

fn from_bytes(bytes: &[u8]) -> BigInt {
    BigInt::from_bytes_le(num_bigint::Sign::Plus, bytes)
}

fn serialize_blob(blob: Vec<BigInt>) -> Vec<u8> {
    assert_eq!(blob.len(), FIELD_ELEMENTS_PER_BLOB, "Bad blob size.");

    let mut bytes: Vec<_> = blob.into_iter().flat_map(|x| x.to_signed_bytes_le()).collect();
    // bytes.resize(c_kzg::BYTES_PER_BLOB, 0);
    bytes
}

pub const WRITE_KZG_COMMITMENT_ADDRESS: &str = indoc! {r#"
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

async fn write_kzg_commitment_address_async<S: Storage + 'static>(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    use num_traits::ToPrimitive;
    let state_updates_start = get_ptr_from_var_name("state_updates_start", vm, ids_data, ap_tracking)?;
    let state_updates_end = get_ptr_from_var_name("state_updates_end", vm, ids_data, ap_tracking)?;
    let range: Vec<MaybeRelocatable> = vm
        .get_range(state_updates_start, state_updates_end.offset - state_updates_start.offset)
        .into_iter()
        .map(|s| s.unwrap().into_owned())
        .collect();

    let execution_helper = exec_scopes.get::<ExecutionHelperWrapper<S>>(vars::scopes::EXECUTION_HELPER)?;
    let ehw = execution_helper.execution_helper.write().await;
    ehw.da_segment.set(range).expect("DA segment is already initialized.");

    let kzg_ptr = get_relocatable_from_var_name("kzg_commitment", vm, ids_data, ap_tracking)?;

    let da_segment = ehw.da_segment.get().unwrap().iter().map(|c| c.get_int().unwrap().to_bigint()).collect();
    let commitments = polynomial_coefficients_to_kzg_commitment(da_segment).unwrap();
    let splits: Vec<MaybeRelocatable> = [commitments.0.into(), commitments.1.into()]
        .into_iter()
        .map(MaybeRelocatable::Int)
        .collect::<Vec<MaybeRelocatable>>();
    vm.write_arg(kzg_ptr, &splits)?;

    Ok(())
}

pub fn write_kzg_commitment_address<S>(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError>
where
    S: Storage + 'static,
{
    execute_coroutine(write_kzg_commitment_address_async::<S>(vm, exec_scopes, ids_data, ap_tracking, _constants))?
}

#[cfg(test)]
mod test {
    use std::iter::repeat_with;
    use super::*;
    use num_traits::One;
    use rstest::rstest;

    const PRIME: &str = "52435875175126190479447740508185965837690552500527637822603658699938581184513";
    const GENERATOR: &str = "39033254847818212395286706435128746857159659164139250548781411570340225835782";
    const WIDTH: usize = 12;
    const ORDER: usize = 1 << WIDTH;

    fn generate(generator: &BigInt) -> Vec<BigInt> {
        let mut array = vec![BigInt::one()];
        for _ in 1..ORDER {
            let last = array.last().unwrap().clone();
            let next = (generator * &last) % BigInt::from_str_radix(PRIME, 10).unwrap();
            array.push(next);
        }
        array
    }


    #[rstest]
    #[case(true)]
    #[case(false)]
    fn test_fft(#[case] bit_reversed: bool) {
        let prime = BigInt::from_str_radix(PRIME, 10).unwrap();
        let generator = BigInt::from_str_radix(GENERATOR, 10).unwrap();

        let mut subgroup = generate(&generator);
        if bit_reversed {
            let perm: Vec<usize> = (0..ORDER)
                .map(|i| {
                    let binary = format!("{:0width$b}", i, width = WIDTH);
                    usize::from_str_radix(&binary.chars().rev().collect::<String>(), 2).unwrap()
                })
                .collect();
            subgroup = perm.iter().map(|&i| subgroup[i].clone()).collect();
        }

        // Sanity checks
        assert_eq!((&generator.modpow(&BigInt::from(ORDER), &prime)), &BigInt::one());
        assert_eq!(subgroup.len(), subgroup.iter().collect::<std::collections::HashSet<_>>().len());

        let coeffs: Vec<BigInt> = repeat_with(|| BigInt::from(rand::random::<u64>()) % &prime).take(ORDER).collect();

        // Evaluate naively
        let mut expected_eval = vec![BigInt::zero(); ORDER];
        for (i, x) in subgroup.iter().enumerate() {
            let eval = generate(x);
            expected_eval[i] = coeffs.iter().zip(eval.iter()).map(|(c, e)| c * e).sum::<BigInt>() % &prime;
        }

        // Evaluate using FFT
        let actual_eval = fft(&coeffs, &generator, &prime, bit_reversed);

        assert_eq!(actual_eval[0], expected_eval[0]);

        // Trivial cases
        // assert_eq!(*&actual_eval[0], &coeffs.iter().sum::<BigInt>() % &prime);
        // assert_eq!(fft(&vec![BigInt::zero(); ORDER], &generator, &prime, bit_reversed), vec![BigInt::zero(); ORDER]);
        // assert_eq!(
        //     fft(&vec![BigInt::from(121212u64)], &BigInt::one(), &prime, bit_reversed),
        //     vec![BigInt::from(121212u64)]
        // );
    }
}
