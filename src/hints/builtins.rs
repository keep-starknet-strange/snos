use std::any::Any;
use std::collections::HashMap;
use std::ops::AddAssign;

use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_integer_from_var_name, get_ptr_from_var_name, insert_value_from_var_name,
};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::hint_processor::hint_processor_utils::felt_to_usize;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::MaybeRelocatable;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use indoc::indoc;
use num_traits::Zero;

use crate::cairo_types::structs::BuiltinParams;

pub const SELECTED_BUILTINS: &str = "vm_enter_scope({'n_selected_builtins': ids.n_selected_builtins})";
pub fn selected_builtins(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let n_selected_builtins: Box<dyn Any> =
        Box::new(get_integer_from_var_name("n_selected_builtins", vm, ids_data, ap_tracking)?);
    exec_scopes.enter_scope(HashMap::from_iter([(String::from("n_selected_builtins"), n_selected_builtins)]));
    Ok(())
}

pub const SELECT_BUILTIN: &str = indoc! {r##"
    # A builtin should be selected iff its encoding appears in the selected encodings list
    # and the list wasn't exhausted.
    # Note that testing inclusion by a single comparison is possible since the lists are sorted.
    ids.select_builtin = int(
      n_selected_builtins > 0 and memory[ids.selected_encodings] == memory[ids.all_encodings])
    if ids.select_builtin:
      n_selected_builtins = n_selected_builtins - 1"##
};
pub fn select_builtin(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let selected_encodings = get_ptr_from_var_name("selected_encodings", vm, ids_data, ap_tracking)?;
    let all_encodings = get_ptr_from_var_name("all_encodings", vm, ids_data, ap_tracking)?;
    let n_selected_builtins = exec_scopes.get_mut_ref::<Felt252>("n_selected_builtins")?;
    let select_builtin = n_selected_builtins > &mut Felt252::zero()
        && vm.get_maybe(&selected_encodings).unwrap() == vm.get_maybe(&all_encodings).unwrap();
    insert_value_from_var_name("select_builtin", Felt252::from(select_builtin), vm, ids_data, ap_tracking)?;
    if select_builtin {
        n_selected_builtins.add_assign(-Felt252::ONE);
    }

    Ok(())
}

pub const UPDATE_BUILTIN_PTRS: &str = indoc! {r#"
    from starkware.starknet.core.os.os_utils import update_builtin_pointers

    # Fill the values of all builtin pointers after the current transaction.
    ids.return_builtin_ptrs = segments.gen_arg(
        update_builtin_pointers(
            memory=memory,
            n_builtins=ids.n_builtins,
            builtins_encoding_addr=ids.builtin_params.builtin_encodings.address_,
            n_selected_builtins=ids.n_selected_builtins,
            selected_builtins_encoding_addr=ids.selected_encodings,
            orig_builtin_ptrs_addr=ids.builtin_ptrs.selectable.address_,
            selected_builtin_ptrs_addr=ids.selected_ptrs,
            ),
        )"#
};
pub fn update_builtin_ptrs(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let n_builtins = get_integer_from_var_name("n_builtins", vm, ids_data, ap_tracking)?;

    let builtin_params = get_ptr_from_var_name("builtin_params", vm, ids_data, ap_tracking)?;
    let builtins_encoding_addr = vm.get_relocatable((builtin_params + BuiltinParams::builtin_encodings_offset())?)?;

    let n_selected_builtins = get_integer_from_var_name("n_selected_builtins", vm, ids_data, ap_tracking)?;

    let selected_encodings = get_ptr_from_var_name("selected_encodings", vm, ids_data, ap_tracking)?;

    let builtin_ptrs = get_ptr_from_var_name("builtin_ptrs", vm, ids_data, ap_tracking)?;

    let orig_builtin_ptrs = builtin_ptrs;

    let selected_ptrs = get_ptr_from_var_name("selected_ptrs", vm, ids_data, ap_tracking)?;

    let all_builtins = vm.get_continuous_range(builtins_encoding_addr, felt_to_usize(&n_builtins)?)?;

    let selected_builtins = vm.get_continuous_range(selected_encodings, felt_to_usize(&n_selected_builtins)?)?;

    let mut returned_builtins: Vec<MaybeRelocatable> = Vec::new();
    let mut selected_builtin_offset: usize = 0;

    for (i, builtin) in all_builtins.iter().enumerate() {
        if selected_builtins.contains(builtin) {
            returned_builtins.push(vm.get_maybe(&(selected_ptrs + selected_builtin_offset)?).unwrap());
            selected_builtin_offset += 1;
        } else {
            returned_builtins.push(vm.get_maybe(&(orig_builtin_ptrs + i)?).unwrap());
        }
    }

    let return_builtin_ptrs_base = vm.add_memory_segment();
    vm.load_data(return_builtin_ptrs_base, &returned_builtins)?;
    insert_value_from_var_name("return_builtin_ptrs", return_builtin_ptrs_base, vm, ids_data, ap_tracking)
}
