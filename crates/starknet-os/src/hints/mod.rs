use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::rc::Rc;

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

use crate::execution::execute_syscalls;
use crate::execution::helper::ExecutionHelperWrapper;
use crate::execution::syscall_handler::OsSyscallHandlerWrapper;
use crate::hints::block_context::is_leaf;
use crate::io::input::StarknetOsInput;
use crate::starknet::starknet_storage::PerContractStorage;
use crate::utils::execute_coroutine;

pub mod block_context;
mod bls_field;
mod bls_utils;
pub mod builtins;
mod compiled_class;
mod deprecated_compiled_class;
mod execute_transactions;
pub mod execution;
mod find_element;
mod kzg;
mod os;
mod output;
mod patricia;
mod secp;
pub mod state;
pub mod syscalls;
#[cfg(test)]
#[allow(clippy::module_inception)] // Use the same name as the parent module
mod tests;
mod transaction_hash;
pub mod types;
mod unimplemented;
pub mod vars;

pub type HintImpl = fn(
    &mut VirtualMachine,
    &mut ExecutionScopes,
    &HashMap<String, HintReference>,
    &ApTracking,
    &HashMap<String, Felt252>,
) -> Result<(), HintError>;

#[rustfmt::skip]
fn hints<PCS>() -> HashMap<String, HintImpl> where
    PCS: PerContractStorage + 'static {
    let mut hints = HashMap::<String, HintImpl>::new();
    hints.insert(BREAKPOINT.into(), breakpoint);
    hints.insert(INITIALIZE_CLASS_HASHES.into(), initialize_class_hashes);
    hints.insert(INITIALIZE_STATE_CHANGES.into(), initialize_state_changes);
    hints.insert(IS_ON_CURVE.into(), is_on_curve);
    hints.insert(OS_INPUT_TRANSACTIONS.into(), os_input_transactions);
    hints.insert(SEGMENTS_ADD.into(), segments_add);
    hints.insert(SEGMENTS_ADD_TEMP.into(), segments_add_temp);
    hints.insert(SET_AP_TO_ACTUAL_FEE.into(), set_ap_to_actual_fee::<PCS>);
    hints.insert(SKIP_CALL.into(), skip_call::<PCS>);
    hints.insert(SKIP_TX.into(), skip_tx::<PCS>);
    hints.insert(STARKNET_OS_INPUT.into(), starknet_os_input);
    hints.insert(START_TX.into(), start_tx::<PCS>);
    hints.insert(block_context::BLOCK_NUMBER.into(), block_context::block_number);
    hints.insert(block_context::BLOCK_TIMESTAMP.into(), block_context::block_timestamp);
    hints.insert(block_context::BYTECODE_SEGMENT_STRUCTURE.into(), block_context::bytecode_segment_structure);
    hints.insert(block_context::CHAIN_ID.into(), block_context::chain_id);
    hints.insert(block_context::DEPRECATED_FEE_TOKEN_ADDRESS.into(), block_context::deprecated_fee_token_address);
    hints.insert(block_context::ELEMENTS_GE_10.into(), block_context::elements_ge_10);
    hints.insert(block_context::ELEMENTS_GE_2.into(), block_context::elements_ge_2);
    hints.insert(block_context::FEE_TOKEN_ADDRESS.into(), block_context::fee_token_address);
    hints.insert(block_context::GET_BLOCK_MAPPING.into(), block_context::get_block_mapping);
    hints.insert(block_context::IS_LEAF.into(), is_leaf);
    hints.insert(block_context::LOAD_CLASS_FACTS.into(), block_context::load_class_facts);
    hints.insert(block_context::LOAD_CLASS_INNER.into(), block_context::load_class_inner);
    hints.insert(block_context::SEQUENCER_ADDRESS.into(), block_context::sequencer_address);
    hints.insert(bls_field::COMPUTE_IDS_LOW.into(), bls_field::compute_ids_low);
    hints.insert(builtins::SELECTED_BUILTINS.into(), builtins::selected_builtins);
    hints.insert(builtins::SELECT_BUILTIN.into(), builtins::select_builtin);
    hints.insert(builtins::UPDATE_BUILTIN_PTRS.into(), builtins::update_builtin_ptrs);
    hints.insert(compiled_class::ASSIGN_BYTECODE_SEGMENTS.into(), compiled_class::assign_bytecode_segments);
    hints.insert(compiled_class::ASSERT_END_OF_BYTECODE_SEGMENTS.into(), compiled_class::assert_end_of_bytecode_segments);
    hints.insert(compiled_class::ITER_CURRENT_SEGMENT_INFO.into(), compiled_class::iter_current_segment_info);
    hints.insert(deprecated_compiled_class::LOAD_DEPRECATED_CLASS_FACTS.into(), deprecated_compiled_class::load_deprecated_class_facts);
    hints.insert(deprecated_compiled_class::LOAD_DEPRECATED_CLASS_INNER.into(), deprecated_compiled_class::load_deprecated_class_inner);
    hints.insert(execute_syscalls::IS_BLOCK_NUMBER_IN_BLOCK_HASH_BUFFER.into(), execute_syscalls::is_block_number_in_block_hash_buffer);
    hints.insert(execute_transactions::FILL_HOLES_IN_RC96_SEGMENT.into(), execute_transactions::fill_holes_in_rc96_segment);
    hints.insert(execute_transactions::LOG_REMAINING_TXS.into(), execute_transactions::log_remaining_txs);
    hints.insert(execute_transactions::SET_COMPONENT_HASHES.into(), execute_transactions::set_component_hashes);
    hints.insert(execute_transactions::SET_SHA256_SEGMENT_IN_SYSCALL_HANDLER.into(), execute_transactions::set_sha256_segment_in_syscall_handler::<PCS>);
    hints.insert(execute_transactions::START_TX_VALIDATE_DECLARE_EXECUTION_CONTEXT.into(), execute_transactions::start_tx_validate_declare_execution_context::<PCS>);
    hints.insert(execution::ADD_RELOCATION_RULE.into(), execution::add_relocation_rule);
    hints.insert(execution::ASSERT_TRANSACTION_HASH.into(), execution::assert_transaction_hash);
    hints.insert(execution::CACHE_CONTRACT_STORAGE_REQUEST_KEY.into(), execution::cache_contract_storage_request_key::<PCS>);
    hints.insert(execution::CACHE_CONTRACT_STORAGE_SYSCALL_REQUEST_ADDRESS.into(), execution::cache_contract_storage_syscall_request_address::<PCS>);
    hints.insert(execution::CHECK_EXECUTION.into(), execution::check_execution::<PCS>);
    hints.insert(execution::CHECK_IS_DEPRECATED.into(), execution::check_is_deprecated);
    hints.insert(execution::CHECK_NEW_DEPLOY_RESPONSE.into(), execution::check_new_deploy_response);
    hints.insert(execution::CHECK_NEW_SYSCALL_RESPONSE.into(), execution::check_new_syscall_response);
    hints.insert(execution::CHECK_SYSCALL_RESPONSE.into(), execution::check_syscall_response);
    hints.insert(execution::CONTRACT_ADDRESS.into(), execution::contract_address);
    hints.insert(execution::END_TX.into(), execution::end_tx::<PCS>);
    hints.insert(execution::ENTER_CALL.into(), execution::enter_call::<PCS>);
    hints.insert(execution::ENTER_SCOPE_DEPRECATED_SYSCALL_HANDLER.into(), execution::enter_scope_deprecated_syscall_handler::<PCS>);
    hints.insert(execution::ENTER_SCOPE_DESCEND_EDGE.into(), execution::enter_scope_descend_edge);
    hints.insert(execution::ENTER_SCOPE_LEFT_CHILD.into(), execution::enter_scope_left_child);
    hints.insert(execution::ENTER_SCOPE_NEW_NODE.into(), execution::enter_scope_new_node);
    hints.insert(execution::ENTER_SCOPE_NEXT_NODE_BIT_0.into(), execution::enter_scope_next_node_bit_0);
    hints.insert(execution::ENTER_SCOPE_NEXT_NODE_BIT_1.into(), execution::enter_scope_next_node_bit_1);
    hints.insert(execution::ENTER_SCOPE_NODE.into(), execution::enter_scope_node_hint);
    hints.insert(execution::ENTER_SCOPE_RIGHT_CHILD.into(), execution::enter_scope_right_child);
    hints.insert(execution::ENTER_SCOPE_SYSCALL_HANDLER.into(), execution::enter_scope_syscall_handler::<PCS>);
    hints.insert(execution::ENTER_SYSCALL_SCOPES.into(), execution::enter_syscall_scopes::<PCS>);
    hints.insert(execution::EXIT_CALL.into(), execution::exit_call::<PCS>);
    hints.insert(execution::EXIT_TX.into(), execution::exit_tx);
    hints.insert(execution::FETCH_RESULT.into(), execution::fetch_result);
    hints.insert(execution::GEN_CLASS_HASH_ARG.into(), execution::gen_class_hash_arg);
    hints.insert(execution::GEN_SIGNATURE_ARG.into(), execution::gen_signature_arg);
    hints.insert(execution::GET_BLOCK_HASH_CONTRACT_ADDRESS_STATE_ENTRY_AND_SET_NEW_STATE_ENTRY.into(), execution::get_block_hash_contract_address_state_entry_and_set_new_state_entry);
    hints.insert(execution::GET_CONTRACT_ADDRESS_STATE_ENTRY.into(), execution::get_contract_address_state_entry);
    hints.insert(execution::GET_CONTRACT_ADDRESS_STATE_ENTRY_AND_SET_NEW_STATE_ENTRY.into(), execution::get_contract_address_state_entry_and_set_new_state_entry);
    hints.insert(execution::GET_CONTRACT_ADDRESS_STATE_ENTRY_AND_SET_NEW_STATE_ENTRY_2.into(), execution::get_contract_address_state_entry_and_set_new_state_entry);
    hints.insert(execution::GET_OLD_BLOCK_NUMBER_AND_HASH.into(), execution::get_old_block_number_and_hash::<PCS>);
    hints.insert(execution::INITIAL_GE_REQUIRED_GAS.into(), execution::initial_ge_required_gas);
    hints.insert(execution::IS_DEPRECATED.into(), execution::is_deprecated);
    hints.insert(execution::IS_REVERTED.into(), execution::is_reverted::<PCS>);
    hints.insert(execution::LOAD_NEXT_TX.into(), execution::load_next_tx);
    hints.insert(execution::LOG_ENTER_SYSCALL.into(), execution::log_enter_syscall);
    hints.insert(execution::OS_CONTEXT_SEGMENTS.into(), execution::os_context_segments);
    hints.insert(execution::PREPARE_CONSTRUCTOR_EXECUTION.into(), execution::prepare_constructor_execution);
    hints.insert(execution::RESOURCE_BOUNDS.into(), execution::resource_bounds);
    hints.insert(execution::SET_AP_TO_TX_NONCE.into(), execution::set_ap_to_tx_nonce);
    hints.insert(execution::SET_FP_PLUS_4_TO_TX_NONCE.into(), execution::set_fp_plus_4_to_tx_nonce);
    hints.insert(execution::SET_STATE_ENTRY_TO_ACCOUNT_CONTRACT_ADDRESS.into(), execution::set_state_entry_to_account_contract_address);
    hints.insert(execution::START_TX.into(), execution::start_tx::<PCS>);
    hints.insert(execution::TRANSACTION_VERSION.into(), execution::transaction_version);
    hints.insert(execution::TX_ACCOUNT_DEPLOYMENT_DATA.into(), execution::tx_account_deployment_data);
    hints.insert(execution::TX_ACCOUNT_DEPLOYMENT_DATA_LEN.into(), execution::tx_account_deployment_data_len);
    hints.insert(execution::TX_CALLDATA.into(), execution::tx_calldata);
    hints.insert(execution::TX_CALLDATA_LEN.into(), execution::tx_calldata_len);
    hints.insert(execution::TX_ENTRY_POINT_SELECTOR.into(), execution::tx_entry_point_selector);
    hints.insert(execution::TX_FEE_DATA_AVAILABILITY_MODE.into(), execution::tx_fee_data_availability_mode);
    hints.insert(execution::TX_MAX_FEE.into(), execution::tx_max_fee);
    hints.insert(execution::TX_NONCE.into(), execution::tx_nonce);
    hints.insert(execution::TX_NONCE_DATA_AVAILABILITY_MODE.into(), execution::tx_nonce_data_availability_mode);
    hints.insert(execution::TX_PAYMASTER_DATA.into(), execution::tx_paymaster_data);
    hints.insert(execution::TX_PAYMASTER_DATA_LEN.into(), execution::tx_paymaster_data_len);
    hints.insert(execution::TX_RESOURCE_BOUNDS_LEN.into(), execution::tx_resource_bounds_len);
    hints.insert(execution::TX_TIP.into(), execution::tx_tip);
    hints.insert(execution::WRITE_OLD_BLOCK_TO_STORAGE.into(), execution::write_old_block_to_storage::<PCS>);
    hints.insert(execution::WRITE_SYSCALL_RESULT.into(), execution::write_syscall_result::<PCS>);
    hints.insert(execution::WRITE_SYSCALL_RESULT_DEPRECATED.into(), execution::write_syscall_result_deprecated::<PCS>);
    hints.insert(find_element::SEARCH_SORTED_OPTIMISTIC.into(), find_element::search_sorted_optimistic);
    hints.insert(os::CONFIGURE_KZG_MANAGER.into(), os::configure_kzg_manager);
    hints.insert(os::WRITE_FULL_OUTPUT_TO_MEM.into(), os::write_full_output_to_mem);
    hints.insert(os::SET_AP_TO_NEW_BLOCK_HASH.into(), os::set_ap_to_new_block_hash);
    hints.insert(os::SET_AP_TO_PREV_BLOCK_HASH.into(), os::set_ap_to_prev_block_hash);
    hints.insert(kzg::STORE_DA_SEGMENT.into(), kzg::store_da_segment::<PCS>);
    hints.insert(output::SET_STATE_UPDATES_START.into(), output::set_state_updates_start);
    hints.insert(output::SET_TREE_STRUCTURE.into(), output::set_tree_structure);
    hints.insert(patricia::ASSERT_CASE_IS_RIGHT.into(), patricia::assert_case_is_right);
    hints.insert(patricia::BUILD_DESCENT_MAP.into(), patricia::build_descent_map);
    hints.insert(patricia::HEIGHT_IS_ZERO_OR_LEN_NODE_PREIMAGE_IS_TWO.into(), patricia::height_is_zero_or_len_node_preimage_is_two);
    hints.insert(patricia::IS_CASE_RIGHT.into(), patricia::is_case_right);
    hints.insert(patricia::PREPARE_PREIMAGE_VALIDATION_NON_DETERMINISTIC_HASHES.into(), patricia::prepare_preimage_validation_non_deterministic_hashes);
    hints.insert(patricia::SET_AP_TO_DESCEND.into(), patricia::set_ap_to_descend);
    hints.insert(patricia::SET_BIT.into(), patricia::set_bit);
    hints.insert(patricia::SET_SIBLINGS.into(), patricia::set_siblings);
    hints.insert(patricia::SPLIT_DESCEND.into(), patricia::split_descend);
    hints.insert(patricia::WRITE_CASE_NOT_LEFT_TO_AP.into(), patricia::write_case_not_left_to_ap);
    hints.insert(state::DECODE_NODE.into(), state::decode_node_hint);
    hints.insert(state::DECODE_NODE_2.into(), state::decode_node_hint);
    hints.insert(state::ENTER_SCOPE_COMMITMENT_INFO_BY_ADDRESS.into(), state::enter_scope_commitment_info_by_address::<PCS>);
    hints.insert(state::LOAD_BOTTOM.into(), state::load_bottom);
    hints.insert(state::LOAD_EDGE.into(), state::load_edge);
    hints.insert(state::SET_PREIMAGE_FOR_CLASS_COMMITMENTS.into(), state::set_preimage_for_class_commitments);
    hints.insert(state::SET_PREIMAGE_FOR_CURRENT_COMMITMENT_INFO.into(), state::set_preimage_for_current_commitment_info);
    hints.insert(state::SET_PREIMAGE_FOR_STATE_COMMITMENTS.into(), state::set_preimage_for_state_commitments);
    hints.insert(state::WRITE_SPLIT_RESULT.into(), state::write_split_result);
    hints.insert(syscalls::CALL_CONTRACT.into(), syscalls::call_contract::<PCS>);
    hints.insert(syscalls::DELEGATE_CALL.into(), syscalls::delegate_call::<PCS>);
    hints.insert(syscalls::DELEGATE_L1_HANDLER.into(), syscalls::delegate_l1_handler::<PCS>);
    hints.insert(syscalls::DEPLOY.into(), syscalls::deploy::<PCS>);
    hints.insert(syscalls::EMIT_EVENT.into(), syscalls::emit_event::<PCS>);
    hints.insert(syscalls::EXIT_CALL_CONTRACT_SYSCALL.into(), syscalls::exit_call_contract_syscall);
    hints.insert(syscalls::EXIT_DELEGATE_CALL_SYSCALL.into(), syscalls::exit_delegate_call_syscall);
    hints.insert(syscalls::EXIT_DELEGATE_L1_HANDLER_SYSCALL.into(), syscalls::exit_delegate_l1_handler_syscall);
    hints.insert(syscalls::EXIT_DEPLOY_SYSCALL.into(), syscalls::exit_deploy_syscall);
    hints.insert(syscalls::EXIT_EMIT_EVENT_SYSCALL.into(), syscalls::exit_emit_event_syscall);
    hints.insert(syscalls::EXIT_GET_BLOCK_HASH_SYSCALL.into(), syscalls::exit_get_block_hash_syscall);
    hints.insert(syscalls::EXIT_GET_BLOCK_NUMBER_SYSCALL.into(), syscalls::exit_get_block_number_syscall);
    hints.insert(syscalls::EXIT_GET_BLOCK_TIMESTAMP_SYSCALL.into(), syscalls::exit_get_block_timestamp_syscall);
    hints.insert(syscalls::EXIT_GET_CALLER_ADDRESS_SYSCALL.into(), syscalls::exit_get_caller_address_syscall);
    hints.insert(syscalls::EXIT_GET_CONTRACT_ADDRESS_SYSCALL.into(), syscalls::exit_get_contract_address_syscall);
    hints.insert(syscalls::EXIT_GET_EXECUTION_INFO_SYSCALL.into(), syscalls::exit_get_execution_info_syscall);
    hints.insert(syscalls::EXIT_GET_SEQUENCER_ADDRESS_SYSCALL.into(), syscalls::exit_get_sequencer_address_syscall);
    hints.insert(syscalls::EXIT_GET_TX_INFO_SYSCALL.into(), syscalls::exit_get_tx_info_syscall);
    hints.insert(syscalls::EXIT_GET_TX_SIGNATURE_SYSCALL.into(), syscalls::exit_get_tx_signature_syscall);
    hints.insert(syscalls::EXIT_KECCAK_SYSCALL.into(), syscalls::exit_keccak_syscall);
    hints.insert(syscalls::EXIT_LIBRARY_CALL_L1_HANDLER_SYSCALL.into(), syscalls::exit_library_call_l1_handler_syscall);
    hints.insert(syscalls::EXIT_LIBRARY_CALL_SYSCALL.into(), syscalls::exit_library_call_syscall);
    hints.insert(syscalls::EXIT_REPLACE_CLASS_SYSCALL.into(), syscalls::exit_replace_class_syscall);
    hints.insert(syscalls::EXIT_SECP256K1_ADD_SYSCALL.into(), syscalls::exit_sha256_process_block_syscall);
    hints.insert(syscalls::EXIT_SHA256_PROCESS_BLOCK_SYSCALL.into(), syscalls::exit_secp256k1_add_syscall);
    hints.insert(syscalls::EXIT_SECP256K1_GET_POINT_FROM_X_SYSCALL.into(), syscalls::exit_secp256k1_get_point_from_x_syscall);
    hints.insert(syscalls::EXIT_SECP256K1_GET_XY_SYSCALL.into(), syscalls::exit_secp256k1_get_xy_syscall);
    hints.insert(syscalls::EXIT_SECP256K1_MUL_SYSCALL.into(), syscalls::exit_secp256k1_mul_syscall);
    hints.insert(syscalls::EXIT_SECP256K1_NEW_SYSCALL.into(), syscalls::exit_secp256k1_new_syscall);
    hints.insert(syscalls::EXIT_SECP256R1_ADD_SYSCALL.into(), syscalls::exit_secp256r1_add_syscall);
    hints.insert(syscalls::EXIT_SECP256R1_GET_POINT_FROM_X_SYSCALL.into(), syscalls::exit_secp256r1_get_point_from_x_syscall);
    hints.insert(syscalls::EXIT_SECP256R1_GET_XY_SYSCALL.into(), syscalls::exit_secp256r1_get_xy_syscall);
    hints.insert(syscalls::EXIT_SECP256R1_MUL_SYSCALL.into(), syscalls::exit_secp256r1_mul_syscall);
    hints.insert(syscalls::EXIT_SECP256R1_NEW_SYSCALL.into(), syscalls::exit_secp256r1_new_syscall);
    hints.insert(syscalls::EXIT_SEND_MESSAGE_TO_L1_SYSCALL.into(), syscalls::exit_send_message_to_l1_syscall);
    hints.insert(syscalls::EXIT_STORAGE_READ_SYSCALL.into(), syscalls::exit_storage_read_syscall);
    hints.insert(syscalls::EXIT_STORAGE_WRITE_SYSCALL.into(), syscalls::exit_storage_write_syscall);
    hints.insert(syscalls::GET_BLOCK_NUMBER.into(), syscalls::get_block_number::<PCS>);
    hints.insert(syscalls::GET_BLOCK_TIMESTAMP.into(), syscalls::get_block_timestamp::<PCS>);
    hints.insert(syscalls::GET_CALLER_ADDRESS.into(), syscalls::get_caller_address::<PCS>);
    hints.insert(syscalls::GET_CONTRACT_ADDRESS.into(), syscalls::get_contract_address::<PCS>);
    hints.insert(syscalls::GET_SEQUENCER_ADDRESS.into(), syscalls::get_sequencer_address::<PCS>);
    hints.insert(syscalls::GET_TX_INFO.into(), syscalls::get_tx_info::<PCS>);
    hints.insert(syscalls::GET_TX_SIGNATURE.into(), syscalls::get_tx_signature::<PCS>);
    hints.insert(syscalls::LIBRARY.into(), syscalls::library_call::<PCS>);
    hints.insert(syscalls::LIBRARY_CALL_L1_HANDLER.into(), syscalls::library_call_l1_handler::<PCS>);
    hints.insert(syscalls::OS_LOGGER_ENTER_SYSCALL_PREPRARE_EXIT_SYSCALL.into(), syscalls::os_logger_enter_syscall_preprare_exit_syscall);
    hints.insert(syscalls::REPLACE_CLASS.into(), syscalls::replace_class::<PCS>);
    hints.insert(syscalls::SEND_MESSAGE_TO_L1.into(), syscalls::send_message_to_l1::<PCS>);
    hints.insert(syscalls::SET_SYSCALL_PTR.into(), syscalls::set_syscall_ptr::<PCS>);
    hints.insert(syscalls::STORAGE_READ.into(), syscalls::storage_read::<PCS>);
    hints.insert(syscalls::STORAGE_WRITE.into(), syscalls::storage_write::<PCS>);
    hints.insert(transaction_hash::ADDITIONAL_DATA_NEW_SEGMENT.into(), transaction_hash::additional_data_new_segment);
    hints.insert(transaction_hash::DATA_TO_HASH_NEW_SEGMENT.into(), transaction_hash::data_to_hash_new_segment);
    hints.insert(block_context::WRITE_USE_KZG_DA_TO_MEM.into(), block_context::write_use_kzg_da_to_mem);
    hints.insert(compiled_class::SET_AP_TO_SEGMENT_HASH.into(), compiled_class::set_ap_to_segment_hash);
    hints.insert(secp::READ_EC_POINT_ADDRESS.into(), secp::read_ec_point_from_address);
    hints.insert(execute_transactions::SHA2_FINALIZE.into(), execute_transactions::sha2_finalize);
    hints
}

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
    (block_context::LOAD_CLASS, block_context::load_class),
    (deprecated_compiled_class::LOAD_DEPRECATED_CLASS, deprecated_compiled_class::load_deprecated_class),
];

pub struct SnosHintProcessor<PCS>
where
    PCS: PerContractStorage,
{
    builtin_hint_proc: BuiltinHintProcessor,
    cairo1_builtin_hint_proc: Cairo1HintProcessor,
    hints: HashMap<String, HintImpl>,
    extensive_hints: HashMap<String, ExtensiveHintImpl>,
    run_resources: RunResources,
    _phantom: PhantomData<PCS>,
}

impl<PCS> ResourceTracker for SnosHintProcessor<PCS>
where
    PCS: PerContractStorage,
{
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

impl<PCS> Default for SnosHintProcessor<PCS>
where
    PCS: PerContractStorage + 'static,
{
    fn default() -> Self {
        let hints = hints::<PCS>();
        let extensive_hints = EXTENSIVE_HINTS.into_iter().map(|(h, i)| (h.to_string(), i)).collect();
        Self {
            builtin_hint_proc: BuiltinHintProcessor::new_empty(),
            cairo1_builtin_hint_proc: Cairo1HintProcessor::new(Default::default(), Default::default(), true),
            hints,
            extensive_hints,
            run_resources: Default::default(),
            _phantom: Default::default(),
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

impl<PCS> SnosHintProcessor<PCS>
where
    PCS: PerContractStorage,
{
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

impl<PCS> HintProcessorLogic for SnosHintProcessor<PCS>
where
    PCS: PerContractStorage + 'static,
{
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
                let r = hint_impl(self, vm, exec_scopes, &hpd.ids_data, &hpd.ap_tracking);
                return r;
            }

            return self
                .builtin_hint_proc
                .execute_hint(vm, exec_scopes, hint_data, constants)
                .map(|_| HintExtension::default());
        }

        if let Some(hint) = hint_data.downcast_ref::<Hint>() {
            if let Hint::Starknet(StarknetHint::SystemCall { system }) = hint {
                let syscall_ptr = get_ptr_from_res_operand(vm, system)?;
                // TODO: need to be generic here
                let syscall_handler = exec_scopes.get::<OsSyscallHandlerWrapper<PCS>>(vars::scopes::SYSCALL_HANDLER)?;

                return execute_coroutine(syscall_handler.execute_syscall(vm, syscall_ptr))?
                    .map(|_| HintExtension::default());
            } else {
                return self.cairo1_builtin_hint_proc.execute(vm, exec_scopes, hint).map(|_| HintExtension::default());
            }
        }

        Err(HintError::WrongHintData)
    }
}

pub fn hint_stub(
    _vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    Err(HintError::CustomHint("Hint stubbed but not implemented".to_string().into_boxed_str()))
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
    let initial_carried_outputs_ptr =
        get_ptr_from_var_name(vars::ids::INITIAL_CARRIED_OUTPUTS, vm, ids_data, ap_tracking)?;

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
    let os_input = exec_scopes.get::<Rc<StarknetOsInput>>(vars::scopes::OS_INPUT)?;
    let mut state_dict: HashMap<MaybeRelocatable, MaybeRelocatable> = HashMap::new();
    for (addr, contract_state) in &os_input.contracts {
        let change_base = vm.add_memory_segment();
        vm.insert_value(change_base, Felt252::from_bytes_be_slice(&contract_state.contract_hash))?;
        let storage_commitment_base = vm.add_memory_segment();
        vm.insert_value((change_base + 1)?, storage_commitment_base)?;
        vm.insert_value((change_base + 2)?, contract_state.nonce)?;

        state_dict.insert(MaybeRelocatable::from(addr), MaybeRelocatable::from(change_base));
    }

    exec_scopes.insert_box(vars::scopes::INITIAL_DICT, Box::new(state_dict));
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
    let os_input = exec_scopes.get::<Rc<StarknetOsInput>>(vars::scopes::OS_INPUT)?;
    let mut class_dict: HashMap<MaybeRelocatable, MaybeRelocatable> = HashMap::new();
    for (class_hash, compiled_class_hash) in &os_input.class_hash_to_compiled_class_hash {
        class_dict.insert(MaybeRelocatable::from(class_hash), MaybeRelocatable::from(compiled_class_hash));
    }

    exec_scopes.insert_box(vars::scopes::INITIAL_DICT, Box::new(class_dict));
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
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let pc = vm.get_pc();
    let fp = vm.get_fp();
    let ap = vm.get_ap();
    log::debug!("-----------BEGIN BREAKPOINT-----------");
    log::debug!("\tpc -> {}, fp -> {}, ap -> {}", pc, fp, ap);
    // println!("\tnum_constants -> {:?}", constants.len());

    // print!("\tbuiltins -> ");
    // vm.get_builtin_runners().iter().for_each(|builtin| print!("{}(base {:?}), ", builtin.name(),
    // builtin.base()));

    // let range_check_ptr = get_maybe_relocatable_from_var_name("range_check_ptr", vm, ids_data,
    // ap_tracking)?; println!("range_check_ptr -> {:?} ", range_check_ptr);

    // println!("\tap_tracking -> {ap_tracking:?}");
    // println!("\texec_scops -> {:?}", exec_scopes.get_local_variables().unwrap().keys());
    // println!("\tids -> {:?}", ids_data);

    log::debug!("\tids_data ({}):", ids_data.len());
    for (i, (k, _v)) in ids_data.iter().enumerate() {
        let value = get_maybe_relocatable_from_var_name(k, vm, ids_data, ap_tracking)?;
        log::debug!("\t\t[{}] \"{}\": \"{:?}\"", i, k, value);
    }

    log::debug!("-----------END BREAKPOINT-----------");
    Ok(())
}

pub const SET_AP_TO_ACTUAL_FEE: &str =
    "memory[ap] = to_felt_or_relocatable(execution_helper.tx_execution_info.actual_fee)";

pub fn set_ap_to_actual_fee<PCS>(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError>
where
    PCS: PerContractStorage + 'static,
{
    let execution_helper = exec_scopes.get::<ExecutionHelperWrapper<PCS>>(vars::scopes::EXECUTION_HELPER)?;
    let actual_fee = execute_coroutine(async {
        let eh_ref = execution_helper.execution_helper.read().await;
        eh_ref
            .tx_execution_info
            .as_ref()
            .ok_or(HintError::CustomHint("ExecutionHelper should have tx_execution_info".to_owned().into_boxed_str()))
            .map(|tx_execution_info| tx_execution_info.transaction_receipt.fee)
    })??;

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
    insert_value_from_var_name(vars::ids::IS_ON_CURVE, Felt252::from(is_on_curve), vm, ids_data, ap_tracking)?;

    Ok(())
}

const START_TX: &str = "execution_helper.start_tx(tx_info_ptr=ids.deprecated_tx_info.address_)";

pub async fn start_tx_async<PCS>(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), HintError>
where
    PCS: PerContractStorage + 'static,
{
    let deprecated_tx_info_ptr = get_ptr_from_var_name(vars::ids::DEPRECATED_TX_INFO, vm, ids_data, ap_tracking)?;

    let execution_helper = exec_scopes.get::<ExecutionHelperWrapper<PCS>>(vars::scopes::EXECUTION_HELPER)?;
    execution_helper.start_tx(Some(deprecated_tx_info_ptr)).await;

    Ok(())
}

pub fn start_tx<PCS>(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError>
where
    PCS: PerContractStorage + 'static,
{
    execute_coroutine(start_tx_async::<PCS>(vm, exec_scopes, ids_data, ap_tracking))?
}

const SKIP_TX: &str = "execution_helper.skip_tx()";

pub async fn skip_tx_async<PCS>(exec_scopes: &mut ExecutionScopes) -> Result<(), HintError>
where
    PCS: PerContractStorage + 'static,
{
    let execution_helper = exec_scopes.get::<ExecutionHelperWrapper<PCS>>(vars::scopes::EXECUTION_HELPER)?;
    execution_helper.skip_tx().await;

    Ok(())
}

pub fn skip_tx<PCS>(
    _vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError>
where
    PCS: PerContractStorage + 'static,
{
    execute_coroutine(skip_tx_async::<PCS>(exec_scopes))?
}

const SKIP_CALL: &str = "execution_helper.skip_call()";

pub async fn skip_call_async<PCS>(exec_scopes: &mut ExecutionScopes) -> Result<(), HintError>
where
    PCS: PerContractStorage + 'static,
{
    let mut execution_helper = exec_scopes.get::<ExecutionHelperWrapper<PCS>>(vars::scopes::EXECUTION_HELPER)?;
    execution_helper.skip_call().await;

    Ok(())
}

pub fn skip_call<PCS>(
    _vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError>
where
    PCS: PerContractStorage + 'static,
{
    execute_coroutine(skip_call_async::<PCS>(exec_scopes))?
}

const OS_INPUT_TRANSACTIONS: &str = "memory[fp + 12] = to_felt_or_relocatable(len(os_input.transactions))";

pub fn os_input_transactions(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_input = exec_scopes.get::<Rc<StarknetOsInput>>(vars::scopes::OS_INPUT)?;
    let num_txns = os_input.transactions.len();
    vm.insert_value((vm.get_fp() + 12)?, num_txns).map_err(HintError::Memory)
}
