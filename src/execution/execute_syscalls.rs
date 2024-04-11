use std::collections::HashMap;

use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{get_integer_from_var_name, insert_value_into_ap};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use indoc::indoc;
use vars::constants::STORED_BLOCK_HASH_BUFFER;
use vars::ids::{CURRENT_BLOCK_NUMBER, REQUEST_BLOCK_NUMBER};

use crate::hints::vars;

pub const IS_BLOCK_NUMBER_IN_BLOCK_HASH_BUFFER: &str = indoc! {r#"
    memory[ap] = to_felt_or_relocatable(ids.request_block_number > \
               ids.current_block_number - ids.STORED_BLOCK_HASH_BUFFER)"#
};

pub fn is_block_number_in_block_hash_buffer(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let request_block_number = get_integer_from_var_name(REQUEST_BLOCK_NUMBER, vm, ids_data, ap_tracking)?;
    let _current_block_number = get_integer_from_var_name(CURRENT_BLOCK_NUMBER, vm, ids_data, ap_tracking);
    // TODO: above returns UnknownIdentifier("current_block_number"), seems like we have a cairo-vm
    // issue here Relevant cairo code is here: https://github.com/starkware-libs/cairo-lang/blob/efa9648f57568aad8f8a13fbf027d2de7c63c2c0/src/starkware/starknet/core/os/execution/execute_syscalls.cairo#L800
    // Hint reference in ids_data looks strange: HintReference { offset1: Value(0), offset2: Value(0),
    // dereference: true, ap_tracking_data: None, cairo_type: Some("felt") } while from compiled
    // json file, it looks like it should be: [cast([[fp + (-3)] + 5], felt*)]

    // diagnostics
    println!("hint reference for `current_block_number`: {:?}", ids_data.get(CURRENT_BLOCK_NUMBER).unwrap());

    // workaround:
    let current_block_number = vm.get_integer(vm.get_relocatable((vm.get_relocatable((vm.get_fp() - 3)?)? + 5)?)?)?;

    let stored_block_hash_buffer = constants
        .get(STORED_BLOCK_HASH_BUFFER)
        .ok_or_else(|| HintError::MissingConstant(Box::new(STORED_BLOCK_HASH_BUFFER)))?;

    let result = request_block_number > *current_block_number - *stored_block_hash_buffer;

    insert_value_into_ap(vm, if result { Felt252::ONE } else { Felt252::ZERO })?;

    Ok(())
}
