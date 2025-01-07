use std::collections::HashMap;

use cairo_vm::hint_processor::builtin_hint_processor::dict_manager::Dictionary;
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_maybe_relocatable_from_var_name, get_ptr_from_var_name, insert_value_from_var_name,
};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::MaybeRelocatable;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use indoc::indoc;

use crate::hints::vars;
use crate::utils::custom_hint_error;

pub const N_UNIQUE_VALUE_BUCKETS: u64 = 6;
pub const TOTAL_N_BUCKETS: u64 = N_UNIQUE_VALUE_BUCKETS + 1;

pub const DICTIONARY_FROM_BUCKET: &str =
    indoc! {r#"initial_dict = {bucket_index: 0 for bucket_index in range(ids.TOTAL_N_BUCKETS)}"#};
pub fn dictionary_from_bucket(
    _vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let initial_dict: HashMap<MaybeRelocatable, MaybeRelocatable> =
        (0..TOTAL_N_BUCKETS).map(|bucket_index| (Felt252::from(bucket_index).into(), Felt252::ZERO.into())).collect();
    exec_scopes.insert_box(vars::scopes::INITIAL_DICT, Box::new(initial_dict));
    Ok(())
}

pub const GET_PREV_OFFSET: &str = indoc! {r#"
	dict_tracker = __dict_manager.get_tracker(ids.dict_ptr)
    ids.prev_offset = dict_tracker.data[ids.bucket_index]"#
};

pub fn get_prev_offset(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let dict_ptr = get_ptr_from_var_name(vars::ids::DICT_PTR, vm, ids_data, ap_tracking)?;

    let dict_tracker = match exec_scopes.get_dict_manager()?.borrow().get_tracker(dict_ptr)?.data.clone() {
        Dictionary::SimpleDictionary(hash_map) => hash_map,
        Dictionary::DefaultDictionary { dict, .. } => dict,
    };

    let bucket_index = get_maybe_relocatable_from_var_name(vars::ids::BUCKET_INDEX, vm, ids_data, ap_tracking)?;

    let prev_offset = match dict_tracker.get(&bucket_index) {
        Some(offset) => offset.clone(),
        None => return Err(custom_hint_error("No prev_offset found for the given bucket_index")),
    };

    exec_scopes.insert_box(vars::scopes::DICT_TRACKER, Box::new(dict_tracker));
    insert_value_from_var_name(vars::ids::PREV_OFFSET, prev_offset, vm, ids_data, ap_tracking)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use cairo_vm::hint_processor::builtin_hint_processor::dict_manager::DictManager;
    use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::get_integer_from_var_name;
    use cairo_vm::types::relocatable::Relocatable;
    use rstest::rstest;

    use super::*;

    #[rstest]
    fn test_dictionary_from_bucket() {
        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_fp(2);

        let ap_tracking = ApTracking::new();
        let constants = HashMap::new();
        let ids_data = HashMap::new();

        vm.insert_value(Relocatable::from((1, 0)), Felt252::from(2)).unwrap();

        let mut exec_scopes: ExecutionScopes = Default::default();

        dictionary_from_bucket(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants).unwrap();

        let initial_dict: HashMap<MaybeRelocatable, MaybeRelocatable> =
            exec_scopes.get(vars::scopes::INITIAL_DICT).unwrap();

        assert_eq!(
            initial_dict,
            HashMap::from_iter(
                [(0, 0), (1, 0), (2, 0), (3, 0), (4, 0), (5, 0), (6, 0)]
                    .map(|v| (Felt252::from(v.0).into(), Felt252::from(v.1).into()))
            )
        );
    }

    #[rstest]
    fn test_get_prev_offset() {
        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_fp(3);

        let ap_tracking = ApTracking::new();
        let constants = HashMap::new();
        let ids_data = HashMap::from([
            (vars::ids::DICT_PTR.to_string(), HintReference::new_simple(-3)),
            (vars::ids::BUCKET_INDEX.to_string(), HintReference::new_simple(-2)),
            (vars::ids::PREV_OFFSET.to_string(), HintReference::new_simple(-1)),
        ]);

        let mut exec_scopes: ExecutionScopes = Default::default();

        let mut dict_manager = DictManager::new();

        let dict_ptr =
            dict_manager.new_dict(&mut vm, HashMap::from([((1, 0).into(), MaybeRelocatable::from(123))])).unwrap();

        insert_value_from_var_name(vars::ids::DICT_PTR, dict_ptr, &mut vm, &ids_data, &ap_tracking).unwrap();

        insert_value_from_var_name(vars::ids::BUCKET_INDEX, (1, 0), &mut vm, &ids_data, &ap_tracking).unwrap();

        exec_scopes.insert_value(vars::scopes::DICT_MANAGER, Rc::new(RefCell::new(dict_manager)));

        get_prev_offset(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants).unwrap();

        let offset = get_integer_from_var_name(vars::ids::PREV_OFFSET, &vm, &ids_data, &ap_tracking).unwrap();

        assert_eq!(offset, Felt252::from(123));
    }
}
