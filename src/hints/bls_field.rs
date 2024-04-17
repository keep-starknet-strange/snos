use std::collections::HashMap;

use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_relocatable_from_var_name, insert_value_from_var_name,
};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use indoc::indoc;
use num_bigint::BigUint;

use crate::cairo_types::bigint::BigInt3;
use crate::hints::vars;
use crate::utils::get_constant;

pub const COMPUTE_IDS_LOW: &str = indoc! {r#"
    ids.low = (ids.value.d0 + ids.value.d1 * ids.BASE) & ((1 << 128) - 1)"#
};

/// From the Cairo code, we can make the current assumptions:
///
/// * The limbs of value are in the range [0, BASE * 3).
/// * value is in the range [0, 2 ** 256).
pub fn compute_ids_low(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let value_ptr = get_relocatable_from_var_name(vars::ids::VALUE, vm, ids_data, ap_tracking)?;
    let d0 = vm.get_integer((value_ptr + BigInt3::d0_offset())?)?;
    let d1 = vm.get_integer((value_ptr + BigInt3::d1_offset())?)?;

    let base = get_constant(vars::constants::BASE, constants)?;

    let mask = (BigUint::from(1u64) << 128) - BigUint::from(1u64);
    let low = (d0.as_ref() + d1.as_ref() * base).to_biguint() & mask;

    insert_value_from_var_name(vars::ids::LOW, Felt252::from(low), vm, ids_data, ap_tracking)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use cairo_vm::hint_processor::hint_processor_definition::HintReference;
    use cairo_vm::serde::deserialize_program::ApTracking;
    use cairo_vm::types::exec_scope::ExecutionScopes;
    use cairo_vm::types::relocatable::Relocatable;
    use cairo_vm::vm::vm_core::VirtualMachine;
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::smaller_than_u128(1, 1, (1u128 << 86) + 1)]
    #[case::bigger_than_u128(1234, 1 << 63, 1234)]
    fn test_compute_ids_low(#[case] d0: u64, #[case] d1: u64, #[case] expected: u128) {
        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_fp(4);

        let ap_tracking = ApTracking::new();
        let constants = HashMap::from([(vars::constants::BASE.to_string(), Felt252::from(1u128 << 86))]);

        let ids_data = HashMap::from([
            (vars::ids::VALUE.to_string(), HintReference::new_simple(-4)),
            (vars::ids::LOW.to_string(), HintReference::new_simple(-1)),
        ]);

        vm.insert_value(Relocatable::from((1, 0)), Felt252::from(d0)).unwrap();
        vm.insert_value(Relocatable::from((1, 1)), Felt252::from(d1)).unwrap();

        let mut exec_scopes: ExecutionScopes = Default::default();

        compute_ids_low(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants).expect("Hint should not fail");

        let low = vm.get_integer(Relocatable::from((1, 3))).unwrap();
        assert_eq!(low.as_ref(), &Felt252::from(expected), "expected: {}, actual: {}", expected, low.to_biguint());
    }
}
