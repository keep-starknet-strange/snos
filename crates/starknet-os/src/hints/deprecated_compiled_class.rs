use std::any::Any;
use std::collections::hash_map::IntoIter;
use std::collections::{HashMap, HashSet};

use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{get_ptr_from_var_name, insert_value_from_var_name};
use cairo_vm::hint_processor::hint_processor_definition::{HintExtension, HintProcessor, HintReference};
use cairo_vm::serde::deserialize_program::{ApTracking, HintParams, ReferenceManager};
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::Relocatable;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use indoc::indoc;
use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;

use crate::hints::vars;
use crate::io::classes::get_deprecated_contract_class_struct;
use crate::io::input::StarknetOsInput;
use crate::utils::custom_hint_error;

pub const LOAD_DEPRECATED_CLASS_FACTS: &str = indoc! {r##"
    # Creates a set of deprecated class hashes to distinguish calls to deprecated entry points.
    __deprecated_class_hashes=set(os_input.deprecated_compiled_classes.keys())
    ids.compiled_class_facts = segments.add()
    ids.n_compiled_class_facts = len(os_input.deprecated_compiled_classes)
    vm_enter_scope({
        'compiled_class_facts': iter(os_input.deprecated_compiled_classes.items()),
    })"##
};

pub fn load_deprecated_class_facts(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_input = exec_scopes.get::<StarknetOsInput>(vars::scopes::OS_INPUT)?;
    let deprecated_class_hashes: HashSet<Felt252> =
        HashSet::from_iter(os_input.deprecated_compiled_classes.keys().cloned());
    exec_scopes.insert_value(vars::scopes::DEPRECATED_CLASS_HASHES, deprecated_class_hashes);

    insert_value_from_var_name(vars::ids::COMPILED_CLASS_FACTS, vm.add_memory_segment(), vm, ids_data, ap_tracking)?;
    insert_value_from_var_name(
        vars::ids::N_COMPILED_CLASS_FACTS,
        os_input.deprecated_compiled_classes.len(),
        vm,
        ids_data,
        ap_tracking,
    )?;
    let scoped_classes: Box<dyn Any> = Box::new(os_input.deprecated_compiled_classes.into_iter());
    exec_scopes.enter_scope(HashMap::from([(String::from(vars::scopes::COMPILED_CLASS_FACTS), scoped_classes)]));

    Ok(())
}

pub const LOAD_DEPRECATED_CLASS_INNER: &str = indoc! {r#"
    from starkware.starknet.core.os.contract_class.deprecated_class_hash import (
        get_deprecated_contract_class_struct,
    )

    compiled_class_hash, compiled_class = next(compiled_class_facts)

    cairo_contract = get_deprecated_contract_class_struct(
        identifiers=ids._context.identifiers, contract_class=compiled_class)
    ids.compiled_class = segments.gen_arg(cairo_contract)"#
};

pub fn load_deprecated_class_inner(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let deprecated_class_iter = exec_scopes
        .get_mut_ref::<IntoIter<Felt252, GenericDeprecatedCompiledClass>>(vars::scopes::COMPILED_CLASS_FACTS)?;

    let (class_hash, deprecated_class) = deprecated_class_iter.next().unwrap();

    exec_scopes.insert_value(vars::scopes::COMPILED_CLASS_HASH, class_hash);
    exec_scopes.insert_value(vars::scopes::COMPILED_CLASS, deprecated_class.clone());

    let dep_class_base = vm.add_memory_segment();
    let starknet_api_class =
        deprecated_class.to_starknet_api_contract_class().map_err(|e| custom_hint_error(e.to_string()))?;
    get_deprecated_contract_class_struct(vm, dep_class_base, starknet_api_class)?;

    insert_value_from_var_name(vars::ids::COMPILED_CLASS, dep_class_base, vm, ids_data, ap_tracking)
}

pub const LOAD_DEPRECATED_CLASS: &str = indoc! {r#"
    from starkware.python.utils import from_bytes

    computed_hash = ids.compiled_class_fact.hash
    expected_hash = compiled_class_hash
    assert computed_hash == expected_hash, (
        "Computed compiled_class_hash is inconsistent with the hash in the os_input. "
        f"Computed hash = {computed_hash}, Expected hash = {expected_hash}.")

    vm_load_program(compiled_class.program, ids.compiled_class.bytecode_ptr)"#
};

pub fn load_deprecated_class(
    hint_processor: &dyn HintProcessor,
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<HintExtension, HintError> {
    let computed_hash_addr = get_ptr_from_var_name(vars::ids::COMPILED_CLASS_FACT, vm, ids_data, ap_tracking)?;
    let computed_hash = vm.get_integer(computed_hash_addr)?;
    let expected_hash = exec_scopes.get::<Felt252>(vars::scopes::COMPILED_CLASS_HASH).unwrap();

    if computed_hash.as_ref() != &expected_hash {
        return Err(HintError::AssertionFailed(
            format!(
                "Computed compiled_class_hash is inconsistent with the hash in the os_input. Computed hash = \
                 {computed_hash}, Expected hash = {expected_hash}."
            )
            .into_boxed_str(),
        ));
    }

    let dep_class = exec_scopes.get::<GenericDeprecatedCompiledClass>(vars::scopes::COMPILED_CLASS)?;
    let dep_class = dep_class.to_starknet_api_contract_class().map_err(|e| custom_hint_error(e.to_string()))?;

    let hints: HashMap<String, Vec<HintParams>> = serde_json::from_value(dep_class.program.hints).unwrap();
    let ref_manager: ReferenceManager = serde_json::from_value(dep_class.program.reference_manager).unwrap();
    let refs = ref_manager.references.iter().map(|r| HintReference::from(r.clone())).collect::<Vec<HintReference>>();

    let compiled_class_ptr = get_ptr_from_var_name(vars::ids::COMPILED_CLASS, vm, ids_data, ap_tracking)?;
    let byte_code_ptr = vm.get_relocatable((compiled_class_ptr + 11)?)?; //TODO: manage offset in a better way

    let mut hint_extension = HintExtension::new();

    for (pc, hints_params) in hints.into_iter() {
        let rel_pc = pc.parse().map_err(|_| HintError::WrongHintData)?;
        let abs_pc = Relocatable::from((byte_code_ptr.segment_index, rel_pc));
        let mut compiled_hints = Vec::new();
        for params in hints_params.into_iter() {
            let compiled_hint = hint_processor.compile_hint(
                &params.code,
                &params.flow_tracking_data.ap_tracking,
                &params.flow_tracking_data.reference_ids,
                &refs,
            )?;
            compiled_hints.push(compiled_hint);
        }
        hint_extension.insert(abs_pc, compiled_hints);
    }

    Ok(hint_extension)
}
