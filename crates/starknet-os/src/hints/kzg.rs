use std::collections::HashMap;
use std::io::{self, Read};
use std::num::ParseIntError;
use std::path::Path;

use c_kzg::{Blob, KzgCommitment, BYTES_PER_FIELD_ELEMENT};
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_ptr_from_var_name, get_relocatable_from_var_name,
};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::MaybeRelocatable;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use indoc::indoc;
use num_bigint::{BigInt, ParseBigIntError};
use num_traits::{Num, One, Zero};

use super::vars;

const FIELD_ELEMENTS_PER_BLOB: usize = 4096;
const COMMITMENT_BYTES_LENGTH: usize = 48;
const COMMITMENT_LOW_BIT_LENGTH: usize = (COMMITMENT_BYTES_LENGTH * 8) / 2;
const BLOB_SUBGROUP_GENERATOR: &str = "39033254847818212395286706435128746857159659164139250548781411570340225835782";
const BLS_PRIME: &str = "52435875175126190479447740508185965837690552500527637822603658699938581184513";

#[derive(Debug, thiserror::Error)]
pub enum FftError {
    #[error("Group is missing last element")]
    GroupMissingLastElement,

    #[error("Invalid binary cast to usize: {0}")]
    InvalidBinaryToUsize(ParseIntError),

    #[error("Could not parse BigInt: {0}")]
    ParseBigIntError(ParseBigIntError),

    #[error("Encountered a c_kzg error: {0}")]
    CKzgError(c_kzg::Error),

    #[error("Encountered an internal io error: {0}")]
    IoError(io::Error),

    #[error("Too many coefficients")]
    TooManyCoefficients,
}

fn inner_fft(coeffs: &[BigInt], group: &[BigInt], prime: &BigInt) -> Vec<BigInt> {
    if coeffs.len() == 1 {
        return coeffs.to_vec();
    }

    // These calls involve a clone and a collect
    // This not cheap and can possibly be improved with using `T: Iter<BigInt>`.
    // It is tricky though as the method is very recursive and would require
    // increasing the `recursive_limit` to crazy numbers
    let f_even = inner_fft(
        &coeffs.iter().step_by(2).cloned().collect::<Vec<_>>(),
        &group.iter().step_by(2).cloned().collect::<Vec<_>>(),
        prime,
    );
    let f_odd = inner_fft(
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
        // Ensure non-negative diff by adding prime to the value before applying the modulo
        let diff = (f_even[i].clone() - &group_mul_f_odd[i] + prime) % prime;
        result.push(diff);
    }

    result
}

/// Computes the FFT of `coeffs`, assuming the size of the coefficient array is a power of two and
/// equals to the generator's multiplicative order.
/// 
/// See more: https://github.com/starkware-libs/cairo-lang/blob/v0.13.2/src/starkware/python/math_utils.py#L304
fn fft(coeffs: &[BigInt], generator: &BigInt, prime: &BigInt, bit_reversed: bool) -> Result<Vec<BigInt>, FftError> {
    if coeffs.is_empty() {
        return Ok(vec![]);
    }

    let coeffs_len = coeffs.len();
    assert!(coeffs_len.is_power_of_two(), "Length is not a power of two.");

    let mut group = vec![BigInt::one()];
    for _ in 0..(coeffs_len - 1) {
        let last = group.last().ok_or(FftError::GroupMissingLastElement)?;
        group.push((last * generator) % prime);
    }

    let mut values = inner_fft(coeffs, &group, prime);

    if bit_reversed {
        // Python equivalent: width = coeffs_len.bit_length() - 1.
        // Since coeffs_len is a power of two, width is set to the position of the last set bit.
        let width = coeffs_len.trailing_zeros() as usize;
        let perm = (0..coeffs_len)
            .map(|i| {
                let binary = format!("{:0width$b}", i, width = width);
                usize::from_str_radix(&binary.chars().rev().collect::<String>(), 2)
                    .map_err(FftError::InvalidBinaryToUsize)
            })
            .collect::<Result<Vec<_>, _>>()?;
        values = perm.into_iter().map(|i| values[i].clone()).collect();
    }

    Ok(values)
}

fn split_commitment(num: BigInt) -> (BigInt, BigInt) {
    let low_part = &num % (BigInt::one() << COMMITMENT_LOW_BIT_LENGTH);
    let high_part = &num >> COMMITMENT_LOW_BIT_LENGTH;
    (low_part, high_part)
}

fn polynomial_coefficients_to_kzg_commitment(coefficients: Vec<BigInt>) -> Result<(BigInt, BigInt), FftError> {
    let blob = polynomial_coefficients_to_blob(coefficients)?;
    let commitment_bytes =
        blob_to_kzg_commitment(&Blob::from_bytes(&blob).map_err(FftError::CKzgError)?).map_err(FftError::CKzgError)?;

    assert_eq!(commitment_bytes.len(), COMMITMENT_BYTES_LENGTH, "Bad commitment bytes length.");
    let commitment_by: Result<Vec<_>, _> = commitment_bytes.bytes().collect();
    Ok(split_commitment(from_bytes(&commitment_by.map_err(FftError::IoError)?)))
}

fn polynomial_coefficients_to_blob(coefficients: Vec<BigInt>) -> Result<Vec<u8>, FftError> {
    if coefficients.len() > FIELD_ELEMENTS_PER_BLOB {
        return Err(FftError::TooManyCoefficients);
    }

    // Pad with zeros to complete FIELD_ELEMENTS_PER_BLOB coefficients
    let mut padded_coefficients = coefficients;
    padded_coefficients.resize(FIELD_ELEMENTS_PER_BLOB, BigInt::zero());

    // Perform FFT on the coefficients
    let generator = BigInt::from_str_radix(BLOB_SUBGROUP_GENERATOR, 10).map_err(FftError::ParseBigIntError)?;
    let prime = BigInt::from_str_radix(BLS_PRIME, 10).map_err(FftError::ParseBigIntError)?;
    let fft_result = fft(&padded_coefficients, &generator, &prime, true)?;

    // Serialize the FFT result into a blob
    Ok(serialize_blob(&fft_result))
}

pub fn blob_to_kzg_commitment(blob: &Blob) -> Result<KzgCommitment, c_kzg::Error> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("kzg").join("trusted_setup.txt");
    c_kzg::KzgCommitment::blob_to_kzg_commitment(blob, &c_kzg::KzgSettings::load_trusted_setup_file(&path)?)
}

fn from_bytes(bytes: &[u8]) -> BigInt {
    BigInt::from_bytes_le(num_bigint::Sign::Plus, bytes)
}

fn to_bytes(x: &BigInt, length: usize) -> Vec<u8> {
    use std::iter::repeat;
    let mut bytes = x.to_bytes_be().1;
    let padding = length.saturating_sub(bytes.len());
    if padding > 0 {
        let mut padded_bytes = repeat(0u8).take(padding).collect::<Vec<u8>>();
        padded_bytes.extend(bytes);
        bytes = padded_bytes;
    }
    bytes
}

fn serialize_blob(blob: &[BigInt]) -> Vec<u8> {
    assert_eq!(blob.len(), FIELD_ELEMENTS_PER_BLOB, "Bad blob size.");
    blob.iter().flat_map(|x| to_bytes(x, BYTES_PER_FIELD_ELEMENT)).collect()
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

pub fn write_kzg_commitment_address(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let state_updates_start = get_ptr_from_var_name(vars::ids::STATE_UPDATES_START, vm, ids_data, ap_tracking)?;
    // NOTE: This hint uses `ids.da_size` but the references provided are not valid
    // NOTE: We end up using `state_updates_end` after referencing the cairo code
    let state_updates_end = get_ptr_from_var_name(vars::ids::STATE_UPDATES_END, vm, ids_data, ap_tracking)?;
    let range: Vec<MaybeRelocatable> = vm
        .get_integer_range(state_updates_start, state_updates_end.offset - state_updates_start.offset)?
        .into_iter()
        .map(|s| MaybeRelocatable::Int(*s))
        .collect();

    let kzg_ptr = get_relocatable_from_var_name(vars::ids::KZG_COMMITMENT, vm, ids_data, ap_tracking)?;

    let da_segment = range
        .iter()
        .map(|c| {
            c.get_int().map(|i| i.to_bigint()).ok_or(HintError::CustomHint(
                "DA segment must contain only integer entries".to_owned().into_boxed_str(),
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let commitments = polynomial_coefficients_to_kzg_commitment(da_segment)
        .map_err(|e| HintError::CustomHint(e.to_string().into_boxed_str()))?;
    let splits: Vec<MaybeRelocatable> = [commitments.0.into(), commitments.1.into()]
        .into_iter()
        .map(MaybeRelocatable::Int)
        .collect::<Vec<MaybeRelocatable>>();
    vm.write_arg(kzg_ptr, &splits)?;

    Ok(())
}

#[cfg(test)]
mod test {
    use std::iter::repeat_with;

    use num_traits::One;
    use rstest::rstest;

    use super::*;
    const GENERATOR: &str = "39033254847818212395286706435128746857159659164139250548781411570340225835782";
    const WIDTH: usize = 12;
    const ORDER: usize = 1 << WIDTH;

    fn generate(generator: &BigInt) -> Vec<BigInt> {
        let mut array = vec![BigInt::one()];
        for _ in 1..ORDER {
            let last = array.last().unwrap().clone();
            let next = (generator * &last) % BigInt::from_str_radix(BLS_PRIME, 10).unwrap();
            array.push(next);
        }
        array
    }

    #[rstest]
    #[case(true)]
    #[case(false)]
    fn test_fft(#[case] bit_reversed: bool) {
        let prime = BigInt::from_str_radix(BLS_PRIME, 10).unwrap();
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
        let actual_eval = fft(&coeffs, &generator, &prime, bit_reversed).unwrap();

        assert_eq!(actual_eval, expected_eval);

        // Trivial cases
        assert_eq!(actual_eval[0], coeffs.iter().sum::<BigInt>() % &prime);
        assert_eq!(
            fft(&vec![BigInt::zero(); ORDER], &generator, &prime, bit_reversed).unwrap(),
            vec![BigInt::zero(); ORDER]
        );
        assert_eq!(
            fft(&[BigInt::from(121212u64)], &BigInt::one(), &prime, bit_reversed).unwrap(),
            vec![BigInt::from(121212u64)]
        );
    }
}
