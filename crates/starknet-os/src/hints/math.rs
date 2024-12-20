use std::collections::HashMap;

use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_integer_from_var_name, insert_value_from_var_name,
};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use indoc::indoc;
use num_bigint::BigUint;
use num_traits::{One, Zero};

use crate::hints::vars;

pub const LOG2_CEIL: &str = indoc! {r#"from starkware.python.math_utils import log2_ceil
    ids.res = log2_ceil(ids.value)"#
};
pub fn log2_ceil(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let value = get_integer_from_var_name(vars::ids::VALUE, vm, ids_data, ap_tracking)?;
    let res = log2_ceil_internal(&value.to_biguint());
    insert_value_from_var_name(vars::ids::RES, Felt252::from(res), vm, ids_data, ap_tracking)?;
    Ok(())
}

fn log2_ceil_internal(value: &BigUint) -> u64 {
    assert!(!value.is_zero(), "log2_ceil is not defined for zero.");

    // bits() returns the number of bits required to represent `value`, which equals floor(log2(value)) + 1.
    let bits = value.bits();

    // Check if value is a power of two.
    // A power of two in binary looks like: 1000...0. Subtracting one gives: 0111...1
    // The AND of these two should be zero if it's truly a power of two.
    let is_power_of_two = {
        if value == &BigUint::one() {
            true // 1 is a power of two (2^0).
        } else {
            let val_minus_one = value - BigUint::one();
            (value & val_minus_one).is_zero()
        }
    };

    if is_power_of_two {
        // If it's a power of two, log2_ceil(value) = floor_log2(value) = bits - 1.
        bits - 1
    } else {
        // Otherwise, log2_ceil(value) = floor_log2(value) + 1 = bits
        bits
    }
}

#[cfg(test)]
mod tests {
    use cairo_vm::types::relocatable::Relocatable;
    use num_bigint::BigUint;
    use rstest::rstest;

    use super::*;

    #[rstest]
    // Powers of two
    #[case(1, 0)] // 1 = 2^0
    #[case(2, 1)] // 2 = 2^1
    #[case(4, 2)] // 4 = 2^2
    #[case(8, 3)] // 8 = 2^3
    #[case(1024, 10)] // 1024 = 2^10

    // Non-powers of two
    #[case(3, 2)] // between 2 and 4, floor(log2(3))=1 => log2_ceil=2
    #[case(5, 3)] // between 4 and 8, floor(log2(5))=2 => log2_ceil=3
    #[case(6, 3)] // between 4 and 8, floor(log2(6))=2 => log2_ceil=3
    #[case(9, 4)] // between 8 and 16, floor(log2(9))=3 => log2_ceil=4
    fn test_log2_ceil_parameterized(#[case] value: u64, #[case] expected: u64) {
        let val = BigUint::from(value);
        assert_eq!(log2_ceil_internal(&val), expected);
        test_log2_ceil_hint(value, expected);
    }

    #[test]
    #[should_panic(expected = "not defined for zero")]
    fn test_log2_ceil_zero() {
        let zero = BigUint::from(0u64);
        log2_ceil_internal(&zero);
    }

    fn test_log2_ceil_hint(value: u64, expected: u64) {
        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_fp(2);

        let ap_tracking = ApTracking::new();
        let constants = HashMap::new();
        let ids_data = HashMap::from([
            (vars::ids::VALUE.to_string(), HintReference::new_simple(-2)),
            (vars::ids::RES.to_string(), HintReference::new_simple(-1)),
        ]);

        vm.insert_value(Relocatable::from((1, 0)), Felt252::from(value)).unwrap();

        let mut exec_scopes: ExecutionScopes = Default::default();

        log2_ceil(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants).unwrap();

        let exp = get_integer_from_var_name(vars::ids::RES, &vm, &ids_data, &ap_tracking).unwrap();

        assert_eq!(exp, Felt252::from(expected))
    }
}
