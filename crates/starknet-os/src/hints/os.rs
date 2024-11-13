use std::collections::HashMap;
use std::rc::Rc;

use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::insert_value_into_ap;
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use indoc::indoc;

use crate::hints::vars;
use crate::io::input::StarknetOsInput;
use crate::utils::{execute_coroutine, set_variable_in_root_exec_scope};

pub const WRITE_FULL_OUTPUT_TO_MEM: &str = indoc! {r#"memory[fp + 19] = to_felt_or_relocatable(os_input.full_output)"#};

pub fn write_full_output_to_mem(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_input: Rc<StarknetOsInput> = exec_scopes.get(vars::scopes::OS_INPUT)?;
    let full_output = os_input.full_output;

    vm.insert_value((vm.get_fp() + 19)?, Felt252::from(full_output)).map_err(HintError::Memory)
}

pub const CONFIGURE_KZG_MANAGER: &str = indoc! {r#"__serialize_data_availability_create_pages__ = True
kzg_manager = execution_helper.kzg_manager"#};

pub fn configure_kzg_manager(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    execute_coroutine(configure_kzg_manager_async(vm, exec_scopes, ids_data, ap_tracking, constants))?
}
pub async fn configure_kzg_manager_async(
    _vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    set_variable_in_root_exec_scope(exec_scopes, vars::scopes::SERIALIZE_DATA_AVAILABILITY_CREATE_PAGES, true);

    // We don't leave kzg_manager in scope here, it can be obtained through execution_helper later

    Ok(())
}

pub const SET_AP_TO_PREV_BLOCK_HASH: &str = indoc! {r#"memory[ap] = to_felt_or_relocatable(os_input.prev_block_hash)"#};

pub fn set_ap_to_prev_block_hash(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_input: Rc<StarknetOsInput> = exec_scopes.get(vars::scopes::OS_INPUT)?;
    insert_value_into_ap(vm, os_input.prev_block_hash)?;

    Ok(())
}

pub const SET_AP_TO_NEW_BLOCK_HASH: &str = "memory[ap] = to_felt_or_relocatable(os_input.new_block_hash)";

pub fn set_ap_to_new_block_hash(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_input: Rc<StarknetOsInput> = exec_scopes.get(vars::scopes::OS_INPUT)?;
    insert_value_into_ap(vm, os_input.new_block_hash)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use cairo_vm::hint_processor::hint_processor_definition::HintReference;
    use cairo_vm::serde::deserialize_program::ApTracking;
    use cairo_vm::types::errors::math_errors::MathError;
    use cairo_vm::types::exec_scope::ExecutionScopes;
    use cairo_vm::types::relocatable::Relocatable;
    use cairo_vm::vm::vm_core::VirtualMachine;
    use cairo_vm::Felt252;
    use rstest::{fixture, rstest};

    use super::*;
    use crate::utils::get_variable_from_root_exec_scope;

    #[fixture]
    fn os_input() -> StarknetOsInput {
        StarknetOsInput {
            new_block_hash: Felt252::from(3),
            prev_block_hash: Felt252::from(1),
            full_output: true,
            ..Default::default()
        }
    }

    #[rstest]
    fn test_write_full_output_to_mem(os_input: StarknetOsInput) {
        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_fp(1);

        let ap_tracking = ApTracking::new();
        let constants = HashMap::new();
        let ids_data = HashMap::from([(vars::ids::BIT.to_string(), HintReference::new_simple(-1))]);

        let result = Felt252::from(os_input.full_output);

        let mut exec_scopes: ExecutionScopes = Default::default();
        exec_scopes.insert_value(vars::scopes::OS_INPUT, Rc::new(os_input));

        write_full_output_to_mem(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants)
            .expect("Hint should succeed");

        // Rust can't infer the type, so we need to assign it manually here
        let fp: Result<Relocatable, MathError> = vm.get_fp() + 19;

        assert_eq!(vm.get_integer(fp.unwrap()).unwrap().into_owned(), result);
    }

    #[rstest]
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_configure_kzg_manager() {
        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.set_fp(1);

        let ap_tracking = ApTracking::new();
        let constants = HashMap::new();
        let ids_data = HashMap::from([(vars::ids::BIT.to_string(), HintReference::new_simple(-1))]);

        let mut exec_scopes: ExecutionScopes = Default::default();

        configure_kzg_manager(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants)
            .expect("Hint should succeed");

        // Rust can't infer the type, so we need to assign it manually here
        let result: bool =
            get_variable_from_root_exec_scope(&exec_scopes, vars::scopes::SERIALIZE_DATA_AVAILABILITY_CREATE_PAGES)
                .unwrap();

        assert!(result)
    }

    #[rstest]
    fn test_set_ap_to_prev_block_hash(os_input: StarknetOsInput) {
        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_ap(1);
        vm.set_fp(1);

        let ap_tracking = ApTracking::new();
        let constants = HashMap::new();
        let ids_data = HashMap::from([(vars::ids::BIT.to_string(), HintReference::new_simple(-1))]);

        let result = os_input.prev_block_hash;

        let mut exec_scopes: ExecutionScopes = Default::default();
        exec_scopes.insert_value(vars::scopes::OS_INPUT, Rc::new(os_input));

        set_ap_to_prev_block_hash(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants)
            .expect("Hint should succeed");

        assert_eq!(vm.get_integer(vm.get_ap()).unwrap().into_owned(), result);
    }

    #[rstest]
    fn test_set_ap_to_new_block_hash(os_input: StarknetOsInput) {
        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_ap(1);
        vm.set_fp(1);

        let ap_tracking = ApTracking::new();
        let constants = HashMap::new();
        let ids_data = HashMap::from([(vars::ids::BIT.to_string(), HintReference::new_simple(-1))]);

        let result = os_input.new_block_hash;

        let mut exec_scopes: ExecutionScopes = Default::default();
        exec_scopes.insert_value(vars::scopes::OS_INPUT, Rc::new(os_input));

        set_ap_to_new_block_hash(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants)
            .expect("Hint should succeed");

        assert_eq!(vm.get_integer(vm.get_ap()).unwrap().into_owned(), result);
    }
}
