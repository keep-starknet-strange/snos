use std::collections::HashMap;

use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{get_ptr_from_var_name, insert_value_from_var_name};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use indoc::indoc;

// state related hints
// see: https://github.com/starkware-libs/cairo-lang/blob/27a157d761ae49b242026bcbe5fca6e60c1e98bd/src/starkware/starknet/core/os/state.cairo#L143

// see: https://github.com/starkware-libs/cairo-lang/blob/27a157d761ae49b242026bcbe5fca6e60c1e98bd/src/starkware/starknet/core/os/state.cairo#L419
pub const COMMITMENT_INFO: &str = indoc! {"
    commitment_info = commitment_info_by_address[ids.state_changes.key]
    ids.initial_contract_state_root = commitment_info.previous_root
    ids.final_contract_state_root = commitment_info.updated_root
    preimage = {
        int(root): children
        for root, children in commitment_info.commitment_facts.items()
    }
    assert commitment_info.tree_height == ids.MERKLE_HEIGHT"
};

// Where:
// * `state_changes: DictAccess*`

pub fn commitment_info(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let state_changes = get_ptr_from_var_name("state_changes", vm, ids_data, ap_tracking)?;
    let address = vm
        .get_integer(state_changes)
        .map_err(|_| HintError::IdentifierHasNoMember(Box::new(("state_changes".to_string(), "key".to_string()))))?;
    // TODO: remove!
    insert_value_from_var_name("address", address.into_owned(), vm, ids_data, ap_tracking)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::assert_matches::assert_matches;

    use cairo_vm::any_box;
    use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::HintProcessorData;
    use cairo_vm::hint_processor::hint_processor_definition::HintProcessorLogic;
    use cairo_vm::vm::vm_core::VirtualMachineBuilder;

    use super::*;
    use crate::hints::state_update::utils::test_utils::*;
    use crate::hints::SnosHintProcessor;

    #[test]
    fn commitment_info_test() {
        let segments = segments![((1, 0), (2, 0)), ((2, 0), 123)];
        let mut vm = VirtualMachineBuilder::default().segments(segments).build();
        vm.set_fp(2);
        let ids_data = ids_data!["state_changes", "address"];
        assert_matches!(run_sn_hint!(vm, ids_data, COMMITMENT_INFO), Ok(_));
        assert_eq!(vm.get_integer((1, 1).into()).unwrap().into_owned(), 123.into());
    }
}
