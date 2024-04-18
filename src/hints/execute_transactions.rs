use std::collections::HashMap;

use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::get_relocatable_from_var_name;
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use indoc::indoc;

use crate::cairo_types::structs::ExecutionContext;
use crate::execution::helper::ExecutionHelperWrapper;
use crate::hints::vars;

pub const START_TX_VALIDATE_DECLARE_EXECUTION_CONTEXT: &str = indoc! {r#"
    execution_helper.start_tx(
           tx_info_ptr=ids.validate_declare_execution_context.deprecated_tx_info.address_
    )"#
};
pub fn start_tx_validate_declare_execution_context(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let execution_helper: ExecutionHelperWrapper = exec_scopes.get(vars::scopes::EXECUTION_HELPER)?;
    let execution_context_ptr =
        get_relocatable_from_var_name(vars::ids::VALIDATE_DECLARE_EXECUTION_CONTEXT, vm, ids_data, ap_tracking)?;
    let deprecated_tx_info_ptr = (execution_context_ptr + ExecutionContext::deprecated_tx_info_offset())?;

    execution_helper.start_tx(Some(deprecated_tx_info_ptr));

    Ok(())
}
