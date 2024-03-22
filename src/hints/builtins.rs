use std::any::Any;
use std::collections::HashMap;
use std::ops::{AddAssign, Deref};

use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_integer_from_var_name, get_ptr_from_var_name, get_relocatable_from_var_name, insert_value_from_var_name,
};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use indoc::indoc;
use num_traits::{ToPrimitive, Zero};

pub const SELECTED_BUILTINS: &str = "vm_enter_scope({'n_selected_builtins': ids.n_selected_builtins})";
pub fn selected_builtins(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let n_selected_builtins: Box<dyn Any> =
        Box::new(get_integer_from_var_name("n_selected_builtins", vm, ids_data, ap_tracking)?.into_owned());
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
    let n_builtins = get_integer_from_var_name("n_builtins", vm, ids_data, ap_tracking)?.into_owned();
    use std::ops::Add;
    let selected_encodings = get_ptr_from_var_name("selected_encodings", vm, ids_data, ap_tracking)?;
    let all_encodings = get_ptr_from_var_name("all_encodings", vm, ids_data, ap_tracking)?;
    let n_selected_builtins = exec_scopes.get_mut_ref::<Felt252>("n_selected_builtins")?;
    println!("*** n_selected_builtins: {}, n_builtins: {}", n_selected_builtins, n_builtins);
    let select_builtin = *n_selected_builtins > Felt252::ZERO
        && vm.get_maybe(&selected_encodings).unwrap() == vm.get_maybe(&all_encodings).unwrap();
    insert_value_from_var_name(
        "select_builtin",
        if select_builtin { Felt252::ONE } else { Felt252::ZERO },
        vm,
        ids_data,
        ap_tracking,
    )?;
    if select_builtin {
        let before = n_selected_builtins.clone();
        n_selected_builtins.add_assign(-Felt252::ONE);
        assert!(before == n_selected_builtins.add(1));

        let all_encodings = get_ptr_from_var_name("all_encodings", vm, ids_data, ap_tracking)?;
        let all_ptrs = get_ptr_from_var_name("all_ptrs", vm, ids_data, ap_tracking)?;
        let selected_encodings = get_ptr_from_var_name("selected_encodings", vm, ids_data, ap_tracking)?;
        let selected_ptrs = get_ptr_from_var_name("selected_ptrs", vm, ids_data, ap_tracking)?;

        let at_all_encodings = vm.get_maybe(&all_encodings);
        let at_all_ptrs = vm.get_maybe(&all_ptrs);
        let at_selected_encodings = vm.get_maybe(&selected_encodings);
        let at_selected_ptrs = vm.get_maybe(&selected_ptrs);

        if selected_ptrs != all_ptrs {
            println!("    all_encodings: {} -> {:?}", all_encodings, at_all_encodings);
            println!("    all_ptrs: {} -> {:?}", all_ptrs, at_all_ptrs);
            println!("    selected_encodings: {} -> {:?}", selected_encodings, at_selected_encodings);
            println!("    selected_ptrs: {} -> {:?}", selected_ptrs, at_selected_ptrs);
        }
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
    let builtin_params = get_relocatable_from_var_name("builtin_params", vm, ids_data, ap_tracking)?;
    let builtins_encoding_addr = vm.get_relocatable(builtin_params).unwrap();
    let n_selected_builtins = get_integer_from_var_name("n_selected_builtins", vm, ids_data, ap_tracking)?;
    let selected_encodings = get_relocatable_from_var_name("selected_encodings", vm, ids_data, ap_tracking)?;
    let builtin_ptrs = get_relocatable_from_var_name("builtin_ptrs", vm, ids_data, ap_tracking)?;
    let orig_builtin_ptrs = vm.get_relocatable(builtin_ptrs).unwrap();
    let selected_ptrs = get_relocatable_from_var_name("selected_ptrs", vm, ids_data, ap_tracking)?;
    println!(" ***** update_builtin_ptrs()");
    println!("    n_builtins: {}", n_builtins);
    println!("    n_selected: {}", n_selected_builtins);
    println!("    selected_encodings: {}", selected_encodings);

    // mimics the python `def update_builtin_pointers` but without explicitly passing in the args
    let update_builtin_pointers = || -> Result<Vec<MaybeRelocatable>, HintError> {
        let all_builtins = vm.get_continuous_range(builtins_encoding_addr, n_builtins.deref().to_usize().unwrap()).unwrap();
        let selected_builtins =
            vm.get_continuous_range(selected_encodings, n_selected_builtins.deref().to_usize().unwrap()).unwrap();

        let mut returned_builtins: Vec<MaybeRelocatable> = Vec::new();
        let mut selected_builtin_offset: usize = 0;
        println!("    selected builtins: {:?}", selected_builtins);
        for (i, builtin) in all_builtins.iter().enumerate() {
            println!("    builtin: {}", builtin);
            if selected_builtins.contains(builtin) {
                println!("    - adding selected builtin {}", vm.get_maybe(&(selected_ptrs + selected_builtin_offset)?).unwrap());
                returned_builtins.push(vm.get_maybe(&(selected_ptrs + selected_builtin_offset)?).unwrap());
                selected_builtin_offset += 1;
            } else {
                let val = vm.get_maybe(&(orig_builtin_ptrs + i)?).unwrap();
                println!("    - adding NON-selected builtin {}", val);
                let val = if (val == MaybeRelocatable::RelocatableValue(Relocatable{segment_index: -3, offset: 0})) {
                    MaybeRelocatable::RelocatableValue(Relocatable{segment_index: -3, offset: 1})
                } else {
                    val
                };
                returned_builtins.push(val);
            }
        }

        Ok(returned_builtins)
    };

    let returned_builtins = update_builtin_pointers()?;

    let return_builtin_ptrs_base = vm.add_memory_segment();
    println!(" ***** builtins segment: {}", return_builtin_ptrs_base);
    vm.load_data(return_builtin_ptrs_base, &returned_builtins)?;
    insert_value_from_var_name("return_builtin_ptrs", return_builtin_ptrs_base, vm, ids_data, ap_tracking)
}
