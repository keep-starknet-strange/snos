use cairo_vm::{vm::errors::hint_errors::HintError, Felt252};

use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::Signed;

/// Takes an integer and returns its canonical representation as:
///    d0 + d1 * BASE + d2 * BASE**2.
/// d2 can be in the range (-2**127, 2**127).
pub fn split(num: Felt252) -> Result<Vec<Felt252>, HintError> {

    let base: BigInt = BigInt::from(2).pow(86);

    let mut a = Vec::with_capacity(3);
    let mut num = num.to_bigint();
    for _ in 0..2 {
        let (q, residue) = num.div_mod_floor(&base);
        num = q;
        a.push(residue);
    }
    if num.abs() >= BigInt::from(2).pow(127) {
        return Err(HintError::AssertionFailed(
            "remainder should be less than 2**127".to_string().into_boxed_str(),
        ));
    }
    a.push(num);

    Ok(a.into_iter().map(|big| big.into()).collect())
}

