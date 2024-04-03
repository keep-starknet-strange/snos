use std::collections::HashMap;

use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_integer_from_var_name, get_ptr_from_var_name, insert_value_from_var_name, insert_value_into_ap,
};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;

use crate::hints::vars;
use crate::starkware_utils::commitment_tree::update_tree::DecodeNodeCase;

pub const SET_SIBLINGS: &str = "memory[ids.siblings], ids.word = descend";

pub type Descend = (Felt252, Felt252);

pub fn set_siblings(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let descend: Descend = exec_scopes.get(vars::scopes::DESCEND)?;

    let siblings = get_ptr_from_var_name(vars::ids::SIBLINGS, vm, ids_data, ap_tracking)?;
    vm.insert_value(siblings, descend.0)?;

    insert_value_from_var_name(vars::ids::WORD, descend.1, vm, ids_data, ap_tracking)?;

    Ok(())
}

pub const IS_CASE_RIGHT: &str = "memory[ap] = int(case == 'right') ^ ids.bit";

pub fn is_case_right(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let case: DecodeNodeCase = exec_scopes.get(vars::scopes::CASE)?;
    let bit = get_integer_from_var_name(vars::ids::BIT, vm, ids_data, ap_tracking)?.into_owned();

    let case_felt = match case {
        DecodeNodeCase::Right => Felt252::ONE,
        _ => Felt252::ZERO,
    };

    // Felts do not support XOR, perform the computation on biguints.
    let value = bit.to_biguint() ^ case_felt.to_biguint();
    let value_felt = Felt252::from(&value);
    insert_value_into_ap(vm, value_felt)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::insert_value_from_var_name;
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case(DecodeNodeCase::Left, 0, 0)]
    #[case(DecodeNodeCase::Left, 1, 1)]
    #[case(DecodeNodeCase::Right, 0, 1)]
    #[case(DecodeNodeCase::Right, 1, 0)]
    fn test_is_case_right(#[case] case: DecodeNodeCase, #[case] bit: u64, #[case] expected: u64) {
        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_ap(1);
        vm.set_fp(1);

        let ap_tracking = ApTracking::new();
        let constants = HashMap::new();

        let ids_data = HashMap::from([(vars::ids::BIT.to_string(), HintReference::new_simple(-1))]);

        insert_value_from_var_name(vars::ids::BIT, Felt252::from(bit), &mut vm, &ids_data, &ap_tracking).unwrap();

        let mut exec_scopes: ExecutionScopes = Default::default();
        exec_scopes.insert_value(vars::scopes::CASE, case);

        // Just make sure that the hint goes through, all meaningful assertions are
        // in the implementation of the hint
        is_case_right(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants).expect("Hint should succeed");

        assert_eq!(vm.get_integer(vm.get_ap()).unwrap().into_owned(), Felt252::from(expected));
    }
}
