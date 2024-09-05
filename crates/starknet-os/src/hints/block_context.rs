use core::panic;
use std::any::Any;
use std::collections::hash_map::IntoIter;
use std::collections::HashMap;

use blockifier::context::BlockContext;
use cairo_vm::hint_processor::builtin_hint_processor::dict_manager::Dictionary;
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_ptr_from_var_name, get_relocatable_from_var_name, insert_value_from_var_name, insert_value_into_ap,
};
use cairo_vm::hint_processor::hint_processor_definition::{HintExtension, HintProcessor, HintReference};
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::{any_box, Felt252};
use indoc::indoc;
use starknet_os_types::casm_contract_class::GenericCasmContractClass;
use starknet_os_types::chain_id::chain_id_to_felt;

use crate::cairo_types::structs::{CompiledClass, CompiledClassFact};
use crate::hints::vars;
use crate::io::classes::write_class;
use crate::io::input::StarknetOsInput;
use crate::starknet::core::os::contract_class::compiled_class_hash_objects::BytecodeSegmentStructureImpl;
use crate::utils::{custom_hint_error, get_constant};

pub const LOAD_CLASS_FACTS: &str = indoc! {r#"
    ids.compiled_class_facts = segments.add()
    ids.n_compiled_class_facts = len(os_input.compiled_classes)
    vm_enter_scope({
        'compiled_class_facts': iter(os_input.compiled_classes.items()),
        'compiled_class_visited_pcs': os_input.compiled_class_visited_pcs,
    })"#
};
pub fn load_class_facts(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_input = exec_scopes.get::<StarknetOsInput>(vars::scopes::OS_INPUT)?;
    let compiled_class_facts_ptr = vm.add_memory_segment();
    insert_value_from_var_name(vars::ids::COMPILED_CLASS_FACTS, compiled_class_facts_ptr, vm, ids_data, ap_tracking)?;

    insert_value_from_var_name(
        vars::ids::N_COMPILED_CLASS_FACTS,
        os_input.compiled_classes.len(),
        vm,
        ids_data,
        ap_tracking,
    )?;

    let compiled_class_facts: Box<dyn Any> = Box::new(os_input.compiled_classes.into_iter());
    let compiled_class_visited_pcs: Box<dyn Any> = Box::new(os_input.compiled_class_visited_pcs);
    exec_scopes.enter_scope(HashMap::from([
        (String::from(vars::scopes::COMPILED_CLASS_FACTS), compiled_class_facts),
        (String::from(vars::scopes::COMPILED_CLASS_VISITED_PCS), compiled_class_visited_pcs),
    ]));
    Ok(())
}

//
pub const LOAD_CLASS_INNER: &str = indoc! {r#"
    from starkware.starknet.core.os.contract_class.compiled_class_hash import (
        create_bytecode_segment_structure,
        get_compiled_class_struct,
    )

    compiled_class_hash, compiled_class = next(compiled_class_facts)

    bytecode_segment_structure = create_bytecode_segment_structure(
        bytecode=compiled_class.bytecode,
        bytecode_segment_lengths=compiled_class.bytecode_segment_lengths,
        visited_pcs=compiled_class_visited_pcs[compiled_class_hash],
    )

    cairo_contract = get_compiled_class_struct(
        identifiers=ids._context.identifiers,
        compiled_class=compiled_class,
        bytecode=bytecode_segment_structure.bytecode_with_skipped_segments()
    )
    ids.compiled_class = segments.gen_arg(cairo_contract)"#
};
pub fn load_class_inner(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let class_iter =
        exec_scopes.get_mut_ref::<IntoIter<Felt252, GenericCasmContractClass>>(vars::ids::COMPILED_CLASS_FACTS)?;

    let (compiled_class_hash, class) = class_iter
        .next()
        .ok_or(HintError::CustomHint("Compiled class iterator exhausted".to_string().into_boxed_str()))?;

    exec_scopes.insert_value(vars::scopes::COMPILED_CLASS_HASH, compiled_class_hash);
    exec_scopes.insert_value(vars::scopes::COMPILED_CLASS, class.clone());

    let class_base = vm.add_memory_segment();
    let compiled_class_visited_pcs: &HashMap<Felt252, Vec<Felt252>> =
        exec_scopes.get_ref(vars::scopes::COMPILED_CLASS_VISITED_PCS)?;
    let visited_pcs = compiled_class_visited_pcs.get(&compiled_class_hash).cloned();

    let bytecode_segment_structure = write_class(vm, class_base, class, visited_pcs)?;
    exec_scopes.insert_value(vars::scopes::BYTECODE_SEGMENT_STRUCTURE, bytecode_segment_structure);

    insert_value_from_var_name(vars::ids::COMPILED_CLASS, class_base, vm, ids_data, ap_tracking)
}

pub const BYTECODE_SEGMENT_STRUCTURE: &str = indoc! {r#"
    vm_enter_scope({
        "bytecode_segment_structure": bytecode_segment_structure
    })"#
};
pub fn bytecode_segment_structure(
    _vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let bytecode_segment_structure: BytecodeSegmentStructureImpl =
        exec_scopes.get(vars::scopes::BYTECODE_SEGMENT_STRUCTURE)?;

    exec_scopes.enter_scope(HashMap::from([(
        vars::scopes::BYTECODE_SEGMENT_STRUCTURE.to_string(),
        any_box!(bytecode_segment_structure),
    )]));
    Ok(())
}

pub const LOAD_CLASS: &str = indoc! {r#"
    computed_hash = ids.compiled_class_fact.hash
    expected_hash = compiled_class_hash
    assert computed_hash == expected_hash, (
        "Computed compiled_class_hash is inconsistent with the hash in the os_input. "
        f"Computed hash = {computed_hash}, Expected hash = {expected_hash}.")

    vm_load_program(
        compiled_class.get_runnable_program(entrypoint_builtins=[]),
        ids.compiled_class.bytecode_ptr
    )"#
};
pub fn load_class(
    _hint_processor: &dyn HintProcessor,
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<HintExtension, HintError> {
    let compiled_class_fact_addr =
        get_relocatable_from_var_name(vars::ids::COMPILED_CLASS_FACT, vm, ids_data, ap_tracking)?;
    let computed_hash = vm.get_integer((compiled_class_fact_addr + CompiledClassFact::hash_offset())?)?;
    let expected_hash = exec_scopes.get::<Felt252>(vars::scopes::COMPILED_CLASS_HASH).unwrap();

    if computed_hash.as_ref() != &expected_hash {
        return Err(HintError::AssertionFailed(
            format!(
                "Computed compiled_class_hash is inconsistent with the hash in the os_input. Computed hash \
                 ={computed_hash}, Expected hash = {expected_hash}"
            )
            .into_boxed_str(),
        ));
    }

    let class = exec_scopes.get::<GenericCasmContractClass>(vars::scopes::COMPILED_CLASS)?;

    let compiled_class_ptr = get_ptr_from_var_name(vars::ids::COMPILED_CLASS, vm, ids_data, ap_tracking)?;
    let byte_code_ptr = vm.get_relocatable((compiled_class_ptr + CompiledClass::bytecode_ptr_offset())?)?;

    let mut hint_extension = HintExtension::new();

    let cairo_lang_class = class.to_cairo_lang_contract_class().map_err(|e| custom_hint_error(e.to_string()))?;

    for (rel_pc, hints) in cairo_lang_class.hints.into_iter() {
        let abs_pc = Relocatable::from((byte_code_ptr.segment_index, rel_pc));
        hint_extension.insert(abs_pc, hints.iter().map(|h| any_box!(h.clone())).collect());
    }

    Ok(hint_extension)
}

pub const BLOCK_NUMBER: &str = "memory[ap] = to_felt_or_relocatable(syscall_handler.block_info.block_number)";
pub fn block_number(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    // TODO: replace w/ block context from syscall handler
    let block_context = exec_scopes.get_ref::<BlockContext>(vars::scopes::BLOCK_CONTEXT)?;
    insert_value_into_ap(vm, Felt252::from(block_context.block_info().block_number.0))
}

pub const BLOCK_TIMESTAMP: &str = "memory[ap] = to_felt_or_relocatable(syscall_handler.block_info.block_timestamp)";
pub fn block_timestamp(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let block_context = exec_scopes.get_ref::<BlockContext>(vars::scopes::BLOCK_CONTEXT)?;
    insert_value_into_ap(vm, Felt252::from(block_context.block_info().block_timestamp.0))
}

pub const CHAIN_ID: &str = "memory[ap] = to_felt_or_relocatable(os_input.general_config.chain_id.value)";
pub fn chain_id(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_input = exec_scopes.get::<StarknetOsInput>(vars::scopes::OS_INPUT)?;
    let chain_id = chain_id_to_felt(&os_input.general_config.starknet_os_config.chain_id);
    insert_value_into_ap(vm, chain_id)
}

pub const FEE_TOKEN_ADDRESS: &str = "memory[ap] = to_felt_or_relocatable(os_input.general_config.fee_token_address)";
pub fn fee_token_address(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_input = exec_scopes.get::<StarknetOsInput>(vars::scopes::OS_INPUT)?;
    let fee_token_address = *os_input.general_config.starknet_os_config.fee_token_address.0.key();
    log::debug!("fee_token_address: {}", fee_token_address);
    insert_value_into_ap(vm, fee_token_address)
}

pub const DEPRECATED_FEE_TOKEN_ADDRESS: &str =
    "memory[ap] = to_felt_or_relocatable(os_input.general_config.deprecated_fee_token_address)";
pub fn deprecated_fee_token_address(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_input = exec_scopes.get::<StarknetOsInput>(vars::scopes::OS_INPUT)?;
    let deprecated_fee_token_address = *os_input.general_config.starknet_os_config.deprecated_fee_token_address.0.key();
    log::debug!("deprecated_fee_token_address: {}", deprecated_fee_token_address);
    insert_value_into_ap(vm, deprecated_fee_token_address)
}

pub const SEQUENCER_ADDRESS: &str = "memory[ap] = to_felt_or_relocatable(syscall_handler.block_info.sequencer_address)";
pub fn sequencer_address(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let block_context = exec_scopes.get_ref::<BlockContext>(vars::scopes::BLOCK_CONTEXT)?;
    insert_value_into_ap(vm, *block_context.block_info().sequencer_address.0.key())
}

pub const GET_BLOCK_MAPPING: &str = indoc! {r#"
    ids.state_entry = __dict_manager.get_dict(ids.contract_state_changes)[
        ids.BLOCK_HASH_CONTRACT_ADDRESS
    ]"#
};

pub fn get_block_mapping(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let key = get_constant(vars::constants::BLOCK_HASH_CONTRACT_ADDRESS, constants)?;
    let dict_ptr = get_ptr_from_var_name(vars::ids::CONTRACT_STATE_CHANGES, vm, ids_data, ap_tracking)?;
    let val = match exec_scopes.get_dict_manager()?.borrow().get_tracker(dict_ptr)?.data.clone() {
        Dictionary::SimpleDictionary(dict) => dict
            .get(&MaybeRelocatable::Int(*key))
            .ok_or_else(|| {
                HintError::CustomHint("State changes dictionary shouldn't be None".to_string().into_boxed_str())
            })?
            .clone(),
        Dictionary::DefaultDictionary { dict: _d, default_value: _v } => {
            panic!("State changes dict shouldn't be a default dict")
        }
    };
    insert_value_from_var_name(vars::ids::STATE_ENTRY, val, vm, ids_data, ap_tracking)
}

pub const ELEMENTS_GE_10: &str = "memory[ap] = to_felt_or_relocatable(ids.elements_end - ids.elements >= 10)";
pub fn elements_ge_10(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let elements_end = get_ptr_from_var_name(vars::ids::ELEMENTS_END, vm, ids_data, _ap_tracking)?;
    let elements = get_ptr_from_var_name(vars::ids::ELEMENTS, vm, ids_data, _ap_tracking)?;
    insert_value_into_ap(vm, Felt252::from((elements_end - elements)? >= 10))
}

pub const ELEMENTS_GE_2: &str = "memory[ap] = to_felt_or_relocatable(ids.elements_end - ids.elements >= 2)";
pub fn elements_ge_2(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let elements_end = get_ptr_from_var_name(vars::ids::ELEMENTS_END, vm, ids_data, _ap_tracking)?;
    let elements = get_ptr_from_var_name(vars::ids::ELEMENTS, vm, ids_data, _ap_tracking)?;
    insert_value_into_ap(vm, Felt252::from((elements_end - elements)? >= 2))
}

pub const IS_LEAF: &str = indoc! {r#"
    from starkware.starknet.core.os.contract_class.compiled_class_hash_objects import (
        BytecodeLeaf,
    )
    ids.is_leaf = 1 if isinstance(bytecode_segment_structure, BytecodeLeaf) else 0"#
};
pub fn is_leaf(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let bytecode_segment_structure: &BytecodeSegmentStructureImpl =
        exec_scopes.get_ref(vars::scopes::BYTECODE_SEGMENT_STRUCTURE)?;
    let is_leaf = match bytecode_segment_structure {
        BytecodeSegmentStructureImpl::SegmentedNode(_) => Felt252::ZERO,
        BytecodeSegmentStructureImpl::Leaf(_) => Felt252::ONE,
    };

    insert_value_from_var_name(vars::ids::IS_LEAF, is_leaf, vm, ids_data, ap_tracking)
}

pub const WRITE_USE_KZG_DA_TO_MEM: &str = indoc! {r#"
    memory[fp + 18] = to_felt_or_relocatable(syscall_handler.block_info.use_kzg_da and (
        not os_input.full_output
    ))"#
};
pub fn write_use_kzg_da_to_mem(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let block_context = exec_scopes.get_ref::<BlockContext>(vars::scopes::BLOCK_CONTEXT)?;
    let use_kzg_da = block_context.block_info().use_kzg_da;

    let os_input: &StarknetOsInput = exec_scopes.get_ref(vars::scopes::OS_INPUT)?;
    let full_output = os_input.full_output;

    let use_kzg_da_felt = if use_kzg_da && !full_output { Felt252::ONE } else { Felt252::ZERO };

    vm.insert_value((vm.get_fp() + 18)?, use_kzg_da_felt).map_err(HintError::Memory)
}
