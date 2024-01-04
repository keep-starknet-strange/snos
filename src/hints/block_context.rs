use core::panic;
use std::any::Any;
use std::collections::hash_map::IntoIter;
use std::collections::{HashMap, HashSet};

use blockifier::block_context::BlockContext;
use cairo_vm::hint_processor::builtin_hint_processor::dict_manager::Dictionary;
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_ptr_from_var_name, insert_value_from_var_name, insert_value_into_ap,
};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::MaybeRelocatable;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use indoc::indoc;
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedContractClass;

use crate::io::classes::write_deprecated_class;
use crate::io::input::StarknetOsInput;
use crate::utils::felt_api2vm;

pub const LOAD_CLASS_FACTS: &str = indoc! {r#"
    ids.compiled_class_facts = segments.add()
    ids.n_compiled_class_facts = len(os_input.compiled_classes)
    vm_enter_scope({
        'compiled_class_facts': iter(os_input.compiled_classes.items()),
    })"#
};
pub fn load_class_facts(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_input = exec_scopes.get::<StarknetOsInput>("os_input")?;
    let compiled_class_facts_ptr = vm.add_memory_segment();
    insert_value_from_var_name("compiled_class_facts", compiled_class_facts_ptr, vm, ids_data, ap_tracking)?;

    insert_value_from_var_name("n_compiled_class_facts", os_input.compiled_classes.len(), vm, ids_data, ap_tracking)?;

    let scoped_classes: Box<dyn Any> = Box::new(os_input.compiled_classes.into_iter());
    exec_scopes.enter_scope(HashMap::from([(String::from("compiled_class_facts"), scoped_classes)]));

    Ok(())
}

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
    let os_input = exec_scopes.get::<StarknetOsInput>("os_input")?;
    let deprecated_class_hashes: HashSet<Felt252> =
        HashSet::from_iter(os_input.deprecated_compiled_classes.keys().cloned());
    exec_scopes.insert_value("__deprecated_class_hashes", deprecated_class_hashes);

    insert_value_from_var_name("compiled_class_facts", vm.add_memory_segment(), vm, ids_data, ap_tracking)?;
    insert_value_from_var_name(
        "n_compiled_class_facts",
        os_input.deprecated_compiled_classes.len(),
        vm,
        ids_data,
        ap_tracking,
    )?;
    let scoped_classes: Box<dyn Any> = Box::new(os_input.deprecated_compiled_classes.into_iter());
    exec_scopes.enter_scope(HashMap::from([(String::from("compiled_class_facts"), scoped_classes)]));

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
pub fn load_deprecated_inner(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let deprecated_class_iter =
        exec_scopes.get_mut_ref::<IntoIter<Felt252, DeprecatedContractClass>>("compiled_class_facts").unwrap();

    let (class_hash, deprecated_class) = deprecated_class_iter.next().unwrap();

    exec_scopes.insert_value("compiled_class_hash", class_hash);
    exec_scopes.insert_value("compiled_class", deprecated_class.clone());

    let dep_class_base = vm.add_memory_segment();
    write_deprecated_class(vm, dep_class_base, deprecated_class)?;
    println!("{dep_class_base:}");

    insert_value_from_var_name("compiled_class", dep_class_base, vm, ids_data, ap_tracking)
}

pub const DEPRECATED_BLOCK_NUMBER: &str =
    "memory[ap] = to_felt_or_relocatable(deprecated_syscall_handler.block_info.block_number)";
pub fn block_number(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    // TODO: replace w/ block context from syscall handler
    let block_context = exec_scopes.get::<BlockContext>("block_context")?;
    insert_value_into_ap(vm, Felt252::from(block_context.block_number.0))
}

pub const DEPRECATED_BLOCK_TIMESTAMP: &str =
    "memory[ap] = to_felt_or_relocatable(deprecated_syscall_handler.block_info.block_timestamp)";
pub fn block_timestamp(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let block_context = exec_scopes.get::<BlockContext>("block_context")?;
    insert_value_into_ap(vm, Felt252::from(block_context.block_timestamp.0))
}

pub const CHAIN_ID: &str = "memory[ap] = to_felt_or_relocatable(os_input.general_config.chain_id.value)";
pub fn chain_id(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_input = exec_scopes.get::<StarknetOsInput>("os_input")?;
    let chain_id =
        Felt252::from(u128::from_str_radix(&os_input.general_config.starknet_os_config.chain_id.0, 16).unwrap());
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
    let os_input = exec_scopes.get::<StarknetOsInput>("os_input")?;
    insert_value_into_ap(vm, felt_api2vm(*os_input.general_config.starknet_os_config.fee_token_address.0.key()))
}

pub const SEQUENCER_ADDRESS: &str = "memory[ap] = to_felt_or_relocatable(os_input.general_config.sequencer_address)";
pub fn sequencer_address(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_input = exec_scopes.get::<StarknetOsInput>("os_input")?;

    insert_value_into_ap(
        vm,
        MaybeRelocatable::Int(Felt252::from_bytes_be_slice(os_input.general_config.sequencer_address.0.key().bytes())),
    )
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
    let key = constants
        .get("starkware.starknet.core.os.constants.BLOCK_HASH_CONTRACT_ADDRESS")
        .expect("BLOCK_HASH_CONTRACT_ADDRESS should be in the context");
    let dict_ptr = get_ptr_from_var_name("contract_state_changes", vm, ids_data, ap_tracking)?;
    // def get_dict(self, dict_ptr) -> dict:
    //     Gets the python dict that corresponds to dict_ptr.
    //     return self.get_tracker(dict_ptr).data
    let val = match exec_scopes.get_dict_manager()?.borrow().get_tracker(dict_ptr)?.data.clone() {
        Dictionary::SimpleDictionary(dict) => {
            dict.get(&MaybeRelocatable::Int(key.clone())).expect("State changes dictionnary shouldn't be None").clone()
        }
        Dictionary::DefaultDictionary { dict: _d, default_value: _v } => {
            panic!("State changes dict shouldn't be a default dict")
        }
    };
    insert_value_from_var_name("state_entry", val, vm, ids_data, ap_tracking)
}
