use std::collections::{HashMap, HashSet};

use cairo_lang_casm::hints::{Hint, StarknetHint};
use cairo_lang_casm::operand::{BinOpOperand, DerefOrImmediate, Operation, Register, ResOperand};
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
    BuiltinHintProcessor, HintProcessorData,
};
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::*;
use cairo_vm::hint_processor::cairo_1_hint_processor::hint_processor::Cairo1HintProcessor;
use cairo_vm::hint_processor::hint_processor_definition::{
    HintExtension, HintProcessor, HintProcessorLogic, HintReference,
};
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::runners::cairo_runner::{ResourceTracker, RunResources};
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use indoc::indoc;
use num_bigint::BigInt;

use crate::execution::helper::ExecutionHelperWrapper;
use crate::execution::syscall_handler::OsSyscallHandlerWrapper;
use crate::hints::block_context::is_leaf;
use crate::io::input::StarknetOsInput;

pub mod block_context;
pub mod builtins;
pub mod execution;
mod output;
mod patricia;
pub mod state;
pub mod syscalls;
#[cfg(test)]
mod tests;
mod types;
mod unimplemented;
mod vars;

type HintImpl = fn(
    &mut VirtualMachine,
    &mut ExecutionScopes,
    &HashMap<String, HintReference>,
    &ApTracking,
    &HashMap<String, Felt252>,
) -> Result<(), HintError>;

static HINTS: [(&str, HintImpl); 102] = [
    (INITIALIZE_CLASS_HASHES, initialize_class_hashes),
    (INITIALIZE_STATE_CHANGES, initialize_state_changes),
    (IS_N_GE_TWO, is_n_ge_two),
    (IS_ON_CURVE, is_on_curve),
    (OS_INPUT_TRANSACTIONS, os_input_transactions),
    (SEGMENTS_ADD, segments_add),
    (SEGMENTS_ADD_TEMP, segments_add_temp),
    (SET_AP_TO_ACTUAL_FEE, set_ap_to_actual_fee),
    (SKIP_CALL, skip_call),
    (SKIP_TX, skip_tx),
    (STARKNET_OS_INPUT, starknet_os_input),
    (START_TX, start_tx),
    (block_context::BLOCK_NUMBER, block_context::block_number),
    (block_context::BLOCK_TIMESTAMP, block_context::block_timestamp),
    (block_context::CHAIN_ID, block_context::chain_id),
    (block_context::DEPRECATED_FEE_TOKEN_ADDRESS, block_context::deprecated_fee_token_address),
    (block_context::FEE_TOKEN_ADDRESS, block_context::fee_token_address),
    (block_context::GET_BLOCK_MAPPING, block_context::get_block_mapping),
    (block_context::LOAD_CLASS_FACTS, block_context::load_class_facts),
    (block_context::LOAD_DEPRECATED_CLASS_FACTS, block_context::load_deprecated_class_facts),
    (block_context::LOAD_DEPRECATED_CLASS_INNER, block_context::load_deprecated_class_inner),
    (block_context::LOAD_CLASS_INNER, block_context::load_class_inner),
    (block_context::BYTECODE_SEGMENT_STRUCTURE, block_context::bytecode_segment_structure),
    (block_context::SEQUENCER_ADDRESS, block_context::sequencer_address),
    (block_context::ELEMENTS_GE_10, block_context::elements_ge_10),
    (block_context::ELEMENTS_GE_2, block_context::elements_ge_2),
    (block_context::IS_LEAF, is_leaf),
    (builtins::SELECTED_BUILTINS, builtins::selected_builtins),
    (builtins::SELECT_BUILTIN, builtins::select_builtin),
    (builtins::UPDATE_BUILTIN_PTRS, builtins::update_builtin_ptrs),
    (execution::ADD_RELOCATION_RULE, execution::add_relocation_rule),
    (execution::ASSERT_TRANSACTION_HASH, execution::assert_transaction_hash),
    (execution::ASSERT_TRANSACTION_HASH, execution::assert_transaction_hash),
    (execution::CHECK_IS_DEPRECATED, execution::check_is_deprecated),
    (execution::CACHE_CONTRACT_STORAGE, execution::cache_contract_storage),
    (execution::CONTRACT_ADDRESS, execution::contract_address),
    (execution::END_TX, execution::end_tx),
    (execution::ENTER_CALL, execution::enter_call),
    (execution::ENTER_SCOPE_DEPRECATED_SYSCALL_HANDLER, execution::enter_scope_deprecated_syscall_handler),
    (execution::ENTER_SCOPE_NEW_NODE, execution::enter_scope_new_node),
    (execution::ENTER_SCOPE_SYSCALL_HANDLER, execution::enter_scope_syscall_handler),
    (execution::ENTER_SYSCALL_SCOPES, execution::enter_syscall_scopes),
    (execution::EXIT_CALL, execution::exit_call),
    (execution::GEN_NONCE_ARG, execution::gen_nonce_arg),
    (execution::GEN_SIGNATURE_ARG, execution::gen_signature_arg),
    (execution::GET_CONTRACT_ADDRESS_STATE_ENTRY, execution::get_contract_address_state_entry),
    (execution::GET_CONTRACT_ADDRESS_STATE_ENTRY_2, execution::get_contract_address_state_entry),
    (
        execution::GET_BLOCK_HASH_CONTRACT_ADDRESS_STATE_ENTRY_AND_SET_NEW_STATE_ENTRY,
        execution::get_block_hash_contract_address_state_entry_and_set_new_state_entry,
    ),
    (execution::GET_CONTRACT_ADDRESS_STATE_ENTRY, execution::get_contract_address_state_entry_and_set_new_state_entry),
    (
        execution::GET_CONTRACT_ADDRESS_STATE_ENTRY_2,
        execution::get_contract_address_state_entry_and_set_new_state_entry,
    ),
    (execution::IS_DEPRECATED, execution::is_deprecated),
    (execution::IS_REVERTED, execution::is_reverted),
    (execution::LOAD_NEXT_TX, execution::load_next_tx),
    (execution::OS_CONTEXT_SEGMENTS, execution::os_context_segments),
    (execution::PREPARE_CONSTRUCTOR_EXECUTION, execution::prepare_constructor_execution),
    (execution::RESOURCE_BOUNDS, execution::resource_bounds),
    (execution::SET_AP_TO_TX_NONCE, execution::set_ap_to_tx_nonce),
    (execution::START_TX, execution::start_tx),
    (execution::TRANSACTION_VERSION, execution::transaction_version),
    (execution::TX_ACCOUNT_DEPLOYMENT_DATA, execution::tx_account_deployment_data),
    (execution::TX_ACCOUNT_DEPLOYMENT_DATA_LEN, execution::tx_account_deployment_data_len),
    (execution::TX_CALLDATA, execution::tx_calldata),
    (execution::TX_CALLDATA_LEN, execution::tx_calldata_len),
    (execution::TX_ENTRY_POINT_SELECTOR, execution::tx_entry_point_selector),
    (execution::TX_FEE_DATA_AVAILABILITY_MODE, execution::tx_fee_data_availability_mode),
    (execution::TX_MAX_FEE, execution::tx_max_fee),
    (execution::TX_NONCE, execution::tx_nonce),
    (execution::TX_NONCE_DATA_AVAILABILITY_MODE, execution::tx_nonce_data_availability_mode),
    (execution::TX_PAYMASTER_DATA, execution::tx_paymaster_data),
    (execution::TX_PAYMASTER_DATA_LEN, execution::tx_paymaster_data_len),
    (execution::TX_RESOURCE_BOUNDS_LEN, execution::tx_resource_bounds_len),
    (execution::TX_TIP, execution::tx_tip),
    (execution::WRITE_SYSCALL_RESULT, execution::write_syscall_result),
    (output::SET_TREE_STRUCTURE, output::set_tree_structure),
    (patricia::IS_CASE_RIGHT, patricia::is_case_right),
    (patricia::SET_SIBLINGS, patricia::set_siblings),
    (state::LOAD_EDGE, state::load_edge),
    (state::SET_PREIMAGE_FOR_CLASS_COMMITMENTS, state::set_preimage_for_class_commitments),
    (state::SET_PREIMAGE_FOR_CURRENT_COMMITMENT_INFO, state::set_preimage_for_current_commitment_info),
    (state::SET_PREIMAGE_FOR_STATE_COMMITMENTS, state::set_preimage_for_state_commitments),
    (state::DECODE_NODE, state::decode_node_hint),
    (state::DECODE_NODE_2, state::decode_node_hint),
    (state::SET_INITIAL_STATE_UPDATES_PTR, state::set_initial_state_updates_ptr),
    (syscalls::CALL_CONTRACT, syscalls::call_contract),
    (syscalls::DELEGATE_CALL, syscalls::delegate_call),
    (syscalls::DELEGATE_L1_HANDLER, syscalls::delegate_l1_handler),
    (syscalls::DEPLOY, syscalls::deploy),
    (syscalls::EMIT_EVENT, syscalls::emit_event),
    (syscalls::GET_BLOCK_NUMBER, syscalls::get_block_number),
    (syscalls::GET_BLOCK_TIMESTAMP, syscalls::get_block_timestamp),
    (syscalls::GET_CALLER_ADDRESS, syscalls::get_caller_address),
    (syscalls::GET_CONTRACT_ADDRESS, syscalls::get_contract_address),
    (syscalls::GET_TX_INFO, syscalls::get_tx_info),
    (syscalls::GET_TX_SIGNATURE, syscalls::get_tx_signature),
    (syscalls::LIBRARY, syscalls::library_call),
    (syscalls::LIBRARY_CALL_L1_HANDLER, syscalls::library_call_l1_handler),
    (syscalls::REPLACE_CLASS, syscalls::replace_class),
    (syscalls::SEND_MESSAGE_TO_L1, syscalls::send_message_to_l1),
    (syscalls::STORAGE_READ, syscalls::storage_read),
    (syscalls::STORAGE_WRITE, syscalls::storage_write),
    (syscalls::SET_SYSCALL_PTR, syscalls::set_syscall_ptr),
    (BREAKPOINT, breakpoint),
];

/// Hint Extensions extend the current map of hints used by the VM.
/// This behaviour achieves what the `vm_load_data` primitive does for cairo-lang
/// and is needed to implement os hints like `vm_load_program`.
type ExtensiveHintImpl = fn(
    &dyn HintProcessor,
    &mut VirtualMachine,
    &mut ExecutionScopes,
    &HashMap<String, HintReference>,
    &ApTracking,
) -> Result<HintExtension, HintError>;

static EXTENSIVE_HINTS: [(&str, ExtensiveHintImpl); 2] = [
    (block_context::LOAD_DEPRECATED_CLASS, block_context::load_deprecated_class),
    (block_context::LOAD_CLASS, block_context::load_class),
];

pub struct SnosHintProcessor {
    builtin_hint_proc: BuiltinHintProcessor,
    cairo1_builtin_hint_proc: Cairo1HintProcessor,
    hints: HashMap<String, HintImpl>,
    extensive_hints: HashMap<String, ExtensiveHintImpl>,
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

impl Default for SnosHintProcessor {
    fn default() -> Self {
        let hints = HINTS.into_iter().map(|(h, i)| (h.to_string(), i)).collect();
        let extensive_hints = EXTENSIVE_HINTS.into_iter().map(|(h, i)| (h.to_string(), i)).collect();
        Self {
            builtin_hint_proc: BuiltinHintProcessor::new_empty(),
            cairo1_builtin_hint_proc: Cairo1HintProcessor::new(Default::default(), Default::default()),
            hints,
            extensive_hints,
            run_resources: Default::default(),
        }
    }
}

// from blockifier/cairo-vm:
fn get_ptr_from_res_operand(vm: &mut VirtualMachine, res: &ResOperand) -> Result<Relocatable, HintError> {
    let (cell, base_offset) = match res {
        ResOperand::Deref(cell) => (cell, Felt252::ZERO),
        ResOperand::BinOp(BinOpOperand { op: Operation::Add, a, b: DerefOrImmediate::Immediate(b) }) => {
            (a, Felt252::from(&b.value))
        }
        _ => {
            return Err(HintError::CustomHint(
                "Failed to extract buffer, expected ResOperand of BinOp type to have Inmediate b value"
                    .to_owned()
                    .into_boxed_str(),
            ));
        }
    };
    let base = match cell.register {
        Register::AP => vm.get_ap(),
        Register::FP => vm.get_fp(),
    };
    let cell_reloc = (base + (i32::from(cell.offset)))?;
    (vm.get_relocatable(cell_reloc)? + &base_offset).map_err(|e| e.into())
}

impl SnosHintProcessor {
    pub fn hints(&self) -> HashSet<String> {
        self.hints
            .keys()
            .cloned()
            .collect::<HashSet<_>>()
            .union(&self.extensive_hints.keys().cloned().collect::<HashSet<_>>())
            .cloned()
            .collect::<HashSet<_>>()
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
        if let Some(hpd) = hint_data.downcast_ref::<HintProcessorData>() {
            let hint_code = hpd.code.as_str();
            if let Some(hint_impl) = self.hints.get(hint_code) {
                return hint_impl(vm, exec_scopes, &hpd.ids_data, &hpd.ap_tracking, constants)
                    .map(|_| HintExtension::default());
            }

            if let Some(hint_impl) = self.extensive_hints.get(hint_code) {
                return hint_impl(self, vm, exec_scopes, &hpd.ids_data, &hpd.ap_tracking);
            }

            return self
                .builtin_hint_proc
                .execute_hint(vm, exec_scopes, hint_data, constants)
                .map(|_| HintExtension::default());
        }

        if let Some(hint) = hint_data.downcast_ref::<Hint>() {
            if let Hint::Starknet(StarknetHint::SystemCall { system }) = hint {
                let syscall_ptr = get_ptr_from_res_operand(vm, system)?;
                let syscall_handler = exec_scopes.get::<OsSyscallHandlerWrapper>("syscall_handler")?;
                return syscall_handler.syscall(vm, syscall_ptr).map(|_| HintExtension::default());
            } else {
                return self.cairo1_builtin_hint_proc.execute(vm, exec_scopes, hint).map(|_| HintExtension::default());
            }
        }

        Err(HintError::WrongHintData)
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
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let initial_carried_outputs_ptr = get_ptr_from_var_name("initial_carried_outputs", vm, ids_data, ap_tracking)?;

    let messages_to_l1 = initial_carried_outputs_ptr;
    let temp_segment = vm.add_temporary_segment();
    vm.insert_value(messages_to_l1, temp_segment)?;

    let messages_to_l2 = (initial_carried_outputs_ptr + 1_i32)?;
    let temp_segment = vm.add_temporary_segment();
    vm.insert_value(messages_to_l2, temp_segment).map_err(|e| e.into())
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

pub const BREAKPOINT: &str = "breakpoint()";

pub fn breakpoint(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let pc = vm.get_pc();
    let fp = vm.get_fp();
    let ap = vm.get_ap();
    println!("-----------BEGIN BREAKPOINT-----------");
    println!("\tpc -> {}, fp -> {}, ap -> {}", pc, fp, ap);
    // println!("\tnum_constants -> {:?}", constants.len());

    // print!("\tbuiltins -> ");
    // vm.get_builtin_runners().iter().for_each(|builtin| print!("{}(base {:?}), ", builtin.name(),
    // builtin.base()));

    // let range_check_ptr = get_maybe_relocatable_from_var_name("range_check_ptr", vm, ids_data,
    // ap_tracking)?; println!("range_check_ptr -> {:?} ", range_check_ptr);

    // println!("\tap_tracking -> {ap_tracking:?}");
    // println!("\texec_scops -> {:?}", exec_scopes.get_local_variables().unwrap().keys());
    // println!("\tids -> {:?}", ids_data);
    println!("-----------END BREAKPOINT-----------");
    Ok(())
}

pub const IS_N_GE_TWO: &str = "memory[ap] = to_felt_or_relocatable(ids.n >= 2)";

pub fn is_n_ge_two(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let n = get_integer_from_var_name(vars::ids::N, vm, ids_data, ap_tracking)?.into_owned();
    let value = if n >= Felt252::TWO { Felt252::ONE } else { Felt252::ZERO };
    insert_value_into_ap(vm, value)?;
    Ok(())
}

pub const SET_AP_TO_ACTUAL_FEE: &str =
    "memory[ap] = to_felt_or_relocatable(execution_helper.tx_execution_info.actual_fee)";

pub fn set_ap_to_actual_fee(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let execution_helper = exec_scopes.get::<ExecutionHelperWrapper>(vars::scopes::EXECUTION_HELPER)?;
    let actual_fee = execution_helper
        .execution_helper
        .borrow()
        .tx_execution_info
        .as_ref()
        .ok_or(HintError::CustomHint("ExecutionHelper should have tx_execution_info".to_owned().into_boxed_str()))?
        .actual_fee;

    insert_value_into_ap(vm, Felt252::from(actual_fee.0))
}

pub const IS_ON_CURVE: &str = "ids.is_on_curve = (y * y) % SECP_P == y_square_int";

pub fn is_on_curve(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let y: BigInt = exec_scopes.get(vars::ids::Y)?;
    let y_square_int: BigInt = exec_scopes.get(vars::ids::Y_SQUARE_INT)?;
    let sec_p: BigInt = exec_scopes.get(vars::ids::SECP_P)?;

    let is_on_curve = (y.clone() * y) % sec_p == y_square_int;
    let is_on_curve: Felt252 = if is_on_curve { Felt252::ONE } else { Felt252::ZERO };
    insert_value_from_var_name(vars::ids::IS_ON_CURVE, is_on_curve, vm, ids_data, ap_tracking)?;

    Ok(())
}

const START_TX: &str = "execution_helper.start_tx(tx_info_ptr=ids.deprecated_tx_info.address_)";

pub fn start_tx(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let deprecated_tx_info_ptr =
        get_relocatable_from_var_name(vars::ids::DEPRECATED_TX_INFO, vm, ids_data, ap_tracking)?;

    let execution_helper = exec_scopes.get::<ExecutionHelperWrapper>(vars::scopes::EXECUTION_HELPER)?;
    execution_helper.start_tx(Some(deprecated_tx_info_ptr));

    Ok(())
}

const SKIP_TX: &str = "execution_helper.skip_tx()";

pub fn skip_tx(
    _vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let execution_helper = exec_scopes.get::<ExecutionHelperWrapper>(vars::scopes::EXECUTION_HELPER)?;
    execution_helper.skip_tx();

    Ok(())
}

const SKIP_CALL: &str = "execution_helper.skip_call()";

pub fn skip_call(
    _vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let mut execution_helper = exec_scopes.get::<ExecutionHelperWrapper>(vars::scopes::EXECUTION_HELPER)?;
    execution_helper.skip_call();

    Ok(())
}

const OS_INPUT_TRANSACTIONS: &str = "memory[fp + 8] = to_felt_or_relocatable(len(os_input.transactions))";

pub fn os_input_transactions(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_input = exec_scopes.get::<StarknetOsInput>("os_input")?;
    let num_txns = os_input.transactions.len();
    vm.insert_value((vm.get_fp() + 8)?, num_txns).map_err(HintError::Memory)
}
