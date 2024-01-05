pub mod block_context;
pub mod execution;

use std::any::Any;
use std::collections::HashMap;

use cairo_vm::felt::Felt252;
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
    BuiltinHintProcessor, HintProcessorData,
};
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::*;
use cairo_vm::hint_processor::hint_processor_definition::{
    HintExtension, HintProcessor, HintProcessorLogic, HintReference,
};
use cairo_vm::serde::deserialize_program::{ApTracking, HintParams, ReferenceManager};
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::MaybeRelocatable;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::runners::cairo_runner::{ResourceTracker, RunResources};
use cairo_vm::vm::vm_core::VirtualMachine;
use indoc::indoc;
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedContractClass;

use crate::config::DEFAULT_INPUT_PATH;
use crate::io::input::StarknetOsInput;

/// Hint Extensions extend the current map of hints used by the VM.
/// This behaviour achieves what the `vm_load_data` primitive does for cairo-lang
/// and is needed to implement os hints like `vm_load_program`.
#[derive(Default)]
pub struct SnosHintProcessor {
    sn_hint_processor: SnosSimpleHintProcessor,
    run_resources: RunResources,
}

impl ResourceTracker for SnosHintProcessor {
    fn consumed(&self) -> bool {
        self.run_resources.consumed()
    }

    fn consume_step(&mut self) {
        self.run_resources.consume_step()
    }

    fn get_n_steps(&self) -> Option<usize> {
        self.run_resources.get_n_steps()
    }

    fn run_resources(&self) -> &RunResources {
        &self.run_resources
    }
}

impl HintProcessorLogic for SnosHintProcessor {
    // stub for trait impl
    fn execute_hint(
        &mut self,
        _vm: &mut VirtualMachine,
        _exec_scopes: &mut ExecutionScopes,
        _hint_data: &Box<dyn core::any::Any>,
        _constants: &HashMap<String, Felt252>,
    ) -> Result<(), HintError> {
        Ok(())
    }

    fn execute_hint_extensive(
        &mut self,
        vm: &mut VirtualMachine,
        exec_scopes: &mut ExecutionScopes,
        hint_data: &Box<dyn core::any::Any>,
        constants: &HashMap<String, Felt252>,
    ) -> Result<HintExtension, HintError> {
        // First attempt to execute with builtin hint processor
        match self.sn_hint_processor.execute_hint(vm, exec_scopes, hint_data, constants) {
            Err(HintError::UnknownHint(_)) => {}
            res => return res.map(|_| HintExtension::default()),
        }
        // Execute os-specific hints
        let hint_data = hint_data.downcast_ref::<HintProcessorData>().ok_or(HintError::WrongHintData)?;
        match &*hint_data.code {
            CHECK_DEPRECATED_CLASS_HASH => {
                check_deprecated_class_hash(self, vm, exec_scopes, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            code => Err(HintError::UnknownHint(code.to_string().into_boxed_str())),
        }
    }
}

pub struct SnosSimpleHintProcessor {
    builtin_hint_proc: BuiltinHintProcessor,
    run_resources: RunResources,
}

impl ResourceTracker for SnosSimpleHintProcessor {
    fn consumed(&self) -> bool {
        self.run_resources.consumed()
    }

    fn consume_step(&mut self) {
        self.run_resources.consume_step()
    }

    fn get_n_steps(&self) -> Option<usize> {
        self.run_resources.get_n_steps()
    }

    fn run_resources(&self) -> &RunResources {
        &self.run_resources
    }
}

impl Default for SnosSimpleHintProcessor {
    fn default() -> Self {
        Self { builtin_hint_proc: BuiltinHintProcessor::new_empty(), run_resources: Default::default() }
    }
}

impl HintProcessorLogic for SnosSimpleHintProcessor {
    fn execute_hint(
        &mut self,
        vm: &mut VirtualMachine,
        exec_scopes: &mut ExecutionScopes,
        hint_data: &Box<dyn core::any::Any>,
        constants: &HashMap<String, Felt252>,
    ) -> Result<(), HintError> {
        match self.builtin_hint_proc.execute_hint(vm, exec_scopes, hint_data, constants) {
            Err(HintError::UnknownHint(_)) => {}
            res => return res,
        }
        let hint_data = hint_data.downcast_ref::<HintProcessorData>().ok_or(HintError::WrongHintData)?;

        let hint_func = match &*hint_data.code {
            STARKNET_OS_INPUT => starknet_os_input,
            INITIALIZE_STATE_CHANGES => initialize_state_changes,
            INITIALIZE_CLASS_HASHES => initialize_class_hashes,
            SEGMENTS_ADD => segments_add,
            SEGMENTS_ADD_TEMP => segments_add_temp,
            TRANSACTIONS_LEN => transactions_len,
            block_context::LOAD_CLASS_FACTS => block_context::load_class_facts,
            block_context::LOAD_DEPRECATED_CLASS_FACTS => block_context::load_deprecated_class_facts,
            block_context::LOAD_DEPRECATED_CLASS_INNER => block_context::load_deprecated_inner,
            block_context::DEPRECATED_BLOCK_NUMBER => block_context::block_number,
            block_context::DEPRECATED_BLOCK_TIMESTAMP => block_context::block_timestamp,
            block_context::SEQUENCER_ADDRESS => block_context::sequencer_address,
            block_context::CHAIN_ID => block_context::chain_id,
            block_context::FEE_TOKEN_ADDRESS => block_context::fee_token_address,
            block_context::GET_BLOCK_MAPPING => block_context::get_block_mapping,
            execution::ENTER_SYSCALL_SCOPES => execution::enter_syscall_scopes,
            execution::GET_STATE_ENTRY => execution::get_state_entry,
            execution::CHECK_IS_DEPRECATED => execution::check_is_deprecated,
            execution::IS_DEPRECATED => execution::is_deprecated,
            execution::OS_CONTEXT_SEGMENTS => execution::os_context_segments,
            execution::SELECTED_BUILTINS => execution::selected_builtins,
            execution::SELECT_BUILTIN => execution::select_builtin,
            execution::LOAD_NEXT_TX => execution::load_next_tx,
            execution::PREPARE_CONSTRUCTOR_EXECUTION => execution::prepare_constructor_execution,
            execution::TRANSACTION_VERSION => execution::transaction_version,
            execution::ASSERT_TRANSACTION_HASH => execution::assert_transaction_hash,
            execution::ENTER_SCOPE_SYSCALL_HANDLER => execution::enter_scope_syscall_handler,
            code => return Err(HintError::UnknownHint(code.to_string().into_boxed_str())),
        };
        hint_func(vm, exec_scopes, &hint_data.ids_data, &hint_data.ap_tracking, constants)
    }
}

pub const STARKNET_OS_INPUT: &str = indoc! {r#"
    from starkware.starknet.core.os.os_input import StarknetOsInput

    os_input = StarknetOsInput.load(data=program_input)

    ids.initial_carried_outputs.messages_to_l1 = segments.add_temp_segment()
    ids.initial_carried_outputs.messages_to_l2 = segments.add_temp_segment()"#
};
pub fn starknet_os_input(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let input_path =
        std::path::PathBuf::from(exec_scopes.get::<String>("input_path").unwrap_or(DEFAULT_INPUT_PATH.to_string()));

    let os_input = Box::new(
        StarknetOsInput::load(&input_path).map_err(|e| HintError::CustomHint(e.to_string().into_boxed_str()))?,
    );
    exec_scopes.assign_or_update_variable("os_input", os_input);

    let initial_carried_outputs_ptr = get_ptr_from_var_name("initial_carried_outputs", vm, ids_data, ap_tracking)?;

    let messages_to_l1 = initial_carried_outputs_ptr;
    let temp_segment = vm.add_temporary_segment();
    vm.insert_value(messages_to_l1, temp_segment)?;

    let messages_to_l2 = (initial_carried_outputs_ptr + 1_i32)?;
    let temp_segment = vm.add_temporary_segment();
    vm.insert_value(messages_to_l2, temp_segment).map_err(|e| e.into())
}

pub const CHECK_DEPRECATED_CLASS_HASH: &str = indoc! {r#"
    from starkware.python.utils import from_bytes

    computed_hash = ids.compiled_class_fact.hash
    expected_hash = compiled_class_hash
    assert computed_hash == expected_hash, (
        "Computed compiled_class_hash is inconsistent with the hash in the os_input. "
        f"Computed hash = {computed_hash}, Expected hash = {expected_hash}.")

    vm_load_program(compiled_class.program, ids.compiled_class.bytecode_ptr)"#
};
pub fn check_deprecated_class_hash(
    hint_processor: &dyn HintProcessor,
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<HintExtension, HintError> {
    // TODO(#61): fix comp class hash
    // let computed_hash_addr = get_ptr_from_var_name("compiled_class_fact", vm, ids_data,
    // ap_tracking)?; let computed_hash = vm.get_integer(computed_hash_addr)?;
    // let expected_hash = exec_scopes.get::<Felt252>("compiled_class_hash").unwrap();
    // if computed_hash.as_ref() != &expected_hash {
    //     return Err(HintError::AssertionFailed(
    //         format!("Compiled_class_hash mismatch comp={computed_hash}
    // exp={expected_hash}").into_boxed_str(),     ));
    // }

    let dep_class = exec_scopes.get::<DeprecatedContractClass>("compiled_class").unwrap();
    let hints: HashMap<String, Vec<HintParams>> = serde_json::from_value(dep_class.program.hints).unwrap();
    let ref_manager: ReferenceManager = serde_json::from_value(dep_class.program.reference_manager).unwrap();
    let refs = ref_manager.references.iter().map(|r| HintReference::from(r.clone())).collect::<Vec<HintReference>>();
    let mut deprecated_compiled_hints: Vec<Box<dyn Any>> = Vec::new();
    for (_hint_pc, hint_params) in hints.into_iter() {
        let compiled_hint = hint_processor.compile_hint(
            &hint_params[0].code,
            &hint_params[0].flow_tracking_data.ap_tracking,
            &hint_params[0].flow_tracking_data.reference_ids,
            &refs,
        )?;

        deprecated_compiled_hints.push(compiled_hint);
    }

    let compiled_class_ptr = get_ptr_from_var_name("compiled_class", vm, ids_data, ap_tracking)?;
    let byte_code_ptr = vm.get_relocatable((compiled_class_ptr + 11)?)?;
    println!("dep class byte_ptr: {byte_code_ptr:?}");
    let hint_extension = HashMap::from([(byte_code_ptr, deprecated_compiled_hints)]);

    Ok(hint_extension)
}

pub const INITIALIZE_STATE_CHANGES: &str = indoc! {r#"
    from starkware.python.utils import from_bytes

    initial_dict = {
        address: segments.gen_arg(
            (from_bytes(contract.contract_hash), segments.add(), contract.nonce))
        for address, contract in os_input.contracts.items()
    }"#
};
pub fn initialize_state_changes(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_input = exec_scopes.get::<StarknetOsInput>("os_input")?;
    let mut state_dict: HashMap<MaybeRelocatable, MaybeRelocatable> = HashMap::new();
    for (addr, contract_state) in os_input.contracts {
        let change_base = vm.add_memory_segment();
        vm.insert_value(change_base, contract_state.contract_hash)?;
        let storage_commitment_base = vm.add_memory_segment();
        vm.insert_value((change_base + 1)?, storage_commitment_base)?;
        vm.insert_value((change_base + 2)?, contract_state.nonce)?;

        state_dict.insert(MaybeRelocatable::from(addr), MaybeRelocatable::from(change_base));
    }

    exec_scopes.insert_box("initial_dict", Box::new(state_dict));
    Ok(())
}

pub const INITIALIZE_CLASS_HASHES: &str = "initial_dict = os_input.class_hash_to_compiled_class_hash";
pub fn initialize_class_hashes(
    _vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_input = exec_scopes.get::<StarknetOsInput>("os_input")?;
    let mut class_dict: HashMap<MaybeRelocatable, MaybeRelocatable> = HashMap::new();
    for (class_hash, compiled_class_hash) in os_input.class_hash_to_compiled_class_hash {
        class_dict.insert(MaybeRelocatable::from(class_hash), MaybeRelocatable::from(compiled_class_hash));
    }

    exec_scopes.insert_box("initial_dict", Box::new(class_dict));
    Ok(())
}

pub const SEGMENTS_ADD: &str = "memory[ap] = to_felt_or_relocatable(segments.add())";
pub fn segments_add(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let segment = vm.add_memory_segment();
    insert_value_into_ap(vm, segment)
}

pub const SEGMENTS_ADD_TEMP: &str = "memory[ap] = to_felt_or_relocatable(segments.add_temp_segment())";
pub fn segments_add_temp(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let temp_segment = vm.add_temporary_segment();
    insert_value_into_ap(vm, temp_segment)
}

pub const TRANSACTIONS_LEN: &str = "memory[ap] = to_felt_or_relocatable(len(os_input.transactions))";
pub fn transactions_len(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_input = exec_scopes.get::<StarknetOsInput>("os_input")?;

    insert_value_into_ap(vm, os_input.transactions.len())
}

pub const BREAKPOINT: &str = "breakpoint()";
pub fn breakpoint(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let add = get_ptr_from_var_name("compiled_class", vm, ids_data, ap_tracking)?;
    println!("compiled class {add:}");
    let temp = vm.get_integer(add)?;
    println!("temp {temp:}");
    let add = (add + 11usize).unwrap();
    let add = vm.get_relocatable(add)?;
    let jump_dest = get_ptr_from_var_name("contract_entry_point", vm, ids_data, ap_tracking)?;
    println!("jump dest {jump_dest:}");
    println!("val deref {:}", vm.get_integer(jump_dest)?);
    println!("add {add:}");
    Ok(())
}
