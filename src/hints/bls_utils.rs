use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::Felt252;
use lazy_static::lazy_static;
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::Signed;

lazy_static! {
    static ref BASE: BigInt = BigInt::from(2).pow(86);
}

/// Takes an integer and returns its canonical representation as:
///    d0 + d1 * BASE + d2 * BASE**2.
/// d2 can be in the range (-2**127, 2**127).
pub fn split(num: Felt252) -> Result<Vec<Felt252>, HintError> {
    let mut a = Vec::with_capacity(3);
    let mut num = num.to_bigint();
    for _ in 0..2 {
        let (q, residue) = num.div_mod_floor(&BASE);
        num = q;
        a.push(residue);
    }
    if num.abs() >= BigInt::from(2).pow(127) {
        return Err(HintError::AssertionFailed("remainder should be less than 2**127".to_string().into_boxed_str()));
    }
    a.push(num);

    Ok(a.into_iter().map(|big| big.into()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_zero() {
        let splits = split(Felt252::ZERO).unwrap();
        assert_eq!(splits.len(), 3);
        assert_eq!(splits, vec![Felt252::ZERO, Felt252::ZERO, Felt252::ZERO]);
    }

    #[test]
    fn test_split_large_num() {
        // 1 + 2*BASE + 3*(BASE^2) == 17958932119522135058886879379160190656204633450479617
        let large = Felt252::from_dec_str("17958932119522135058886879379160190656204633450479617").unwrap();
        let splits = split(large).unwrap();
        assert_eq!(splits.len(), 3);
        assert_eq!(splits, vec![Felt252::ONE, Felt252::TWO, Felt252::THREE]);
    }
}
