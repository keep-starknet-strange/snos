use std::collections::HashMap;

use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_integer_from_var_name, get_ptr_from_var_name, insert_value_from_var_name,
};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::hint_processor::hint_processor_utils::felt_to_usize;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use indoc::indoc;

use crate::hints::vars;
use crate::utils::get_variable_from_root_exec_scope;

#[rustfmt::skip]

pub const SEARCH_SORTED_OPTIMISTIC: &str = indoc! {r#"array_ptr = ids.array_ptr
elm_size = ids.elm_size
assert isinstance(elm_size, int) and elm_size > 0, \
    f'Invalid value for elm_size. Got: {elm_size}.'

n_elms = ids.n_elms
assert isinstance(n_elms, int) and n_elms >= 0, \
    f'Invalid value for n_elms. Got: {n_elms}.'
if '__find_element_max_size' in globals():
    assert n_elms <= __find_element_max_size, \
        f'find_element() can only be used with n_elms<={__find_element_max_size}. ' \
        f'Got: n_elms={n_elms}.'

for i in range(n_elms):
    if memory[array_ptr + elm_size * i] >= ids.key:
        ids.index = i
        ids.exists = 1 if memory[array_ptr + elm_size * i] == ids.key else 0
        break
else:
    ids.index = n_elms
    ids.exists = 0"#};

pub fn search_sorted_optimistic(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let array_ptr = get_ptr_from_var_name(vars::ids::ARRAY_PTR, vm, ids_data, ap_tracking)?;
    let elm_size = felt_to_usize(&get_integer_from_var_name(vars::ids::ELM_SIZE, vm, ids_data, ap_tracking)?)?;

    if elm_size == 0 {
        return Err(HintError::AssertionFailed("elm_size is zero".to_string().into_boxed_str()));
    }

    let n_elms = felt_to_usize(&get_integer_from_var_name(vars::ids::N_ELMS, vm, ids_data, ap_tracking)?)?;
    let find_element_max_size: Option<usize> =
        get_variable_from_root_exec_scope(exec_scopes, vars::scopes::FIND_ELEMENT_MAX_SIZE)?;

    if let Some(max_size) = find_element_max_size {
        if n_elms > max_size {
            return Err(HintError::AssertionFailed(
                format!("find_element() can only be used with n_elms<={}. Got: n_elms={}.", max_size, n_elms)
                    .into_boxed_str(),
            ));
        }
    }

    let key = &get_integer_from_var_name(vars::ids::KEY, vm, ids_data, ap_tracking)?;

    let mut index = n_elms;
    let mut exists = false;

    for i in 0..n_elms {
        let address = (array_ptr + (elm_size * i))?;
        let value = vm.get_integer(address)?;

        if value.as_ref() >= key {
            index = i;
            exists = value.as_ref() == key;

            break;
        }
    }

    let exists_felt = if exists { Felt252::ONE } else { Felt252::ZERO };

    insert_value_from_var_name(vars::ids::INDEX, index, vm, ids_data, ap_tracking)?;
    insert_value_from_var_name(vars::ids::EXISTS, exists_felt, vm, ids_data, ap_tracking)?;

    Ok(())
}
