use std::fs;

use blockifier::context::BlockContext;
use cairo_vm::cairo_run::CairoRunConfig;
use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::types::program::Program;
use cairo_vm::vm::errors::vm_exception::VmException;
use cairo_vm::vm::runners::cairo_pie::CairoPie;
use cairo_vm::vm::runners::cairo_runner::CairoRunner;
use cairo_vm::Felt252;
use error::SnOsError;
use execution::deprecated_syscall_handler::DeprecatedOsSyscallHandlerWrapper;
use execution::helper::ExecutionHelperWrapper;
use io::output::StarknetOsOutput;

use crate::execution::syscall_handler::OsSyscallHandlerWrapper;
use crate::hints::types::{PatriciaSkipValidationRunner, PatriciaTreeMode};
use crate::hints::vars;
use crate::io::input::StarknetOsInput;
use crate::io::output::ContractChanges;

mod cairo_types;
pub mod config;
pub mod crypto;
pub mod error;
pub mod execution;
pub mod hints;
pub mod io;
pub mod sharp;
pub mod starknet;
pub mod starkware_utils;
pub mod storage;
pub mod utils;

fn log_contract_changes(contract_changes: &ContractChanges) {
    log::debug!("  contract address: {}", contract_changes.addr.to_hex_string());
    log::debug!("    nonce: {}", contract_changes.nonce.to_biguint());
    log::debug!("    class_hash: {:?}", contract_changes.class_hash.map(|felt| felt.to_biguint()));
    log::debug!("    # storage changes: {}", contract_changes.storage_changes.len());
}

fn log_output(os_output: &StarknetOsOutput) {
    log::debug!("OS output:");
    log::debug!("  initial root: {}", os_output.initial_root.to_hex_string());
    log::debug!("  final root: {}", os_output.final_root.to_hex_string());
    log::debug!("  block number: {}", os_output.block_number.to_biguint());
    log::debug!("  block hash: {}", os_output.block_hash.to_hex_string());
    log::debug!("  starknet os config hash: {}", os_output.starknet_os_config_hash.to_hex_string());
    let use_kzg_da = os_output.use_kzg_da != Felt252::ZERO;
    log::debug!("  use kzg da: {}", use_kzg_da);
    log::debug!("  # messages to L1: {} - {:?}", os_output.messages_to_l1.len(), os_output.messages_to_l1);
    log::debug!("  # messages to L2: {} - {:?}", os_output.messages_to_l2.len(), os_output.messages_to_l2);
    log::debug!("  # contract changes: {}", os_output.contracts.len());
    for contract_changes in &os_output.contracts {
        log_contract_changes(contract_changes);
    }

    log::debug!("  # class changes: {}", os_output.classes.len());
    for (class_hash, compiled_class_hash) in &os_output.classes {
        log::debug!("    {} -> {}", class_hash.to_hex_string(), compiled_class_hash.to_hex_string());
    }
}

pub fn run_os(
    os_path: String,
    layout: LayoutName,
    os_input: StarknetOsInput,
    block_context: BlockContext,
    execution_helper: ExecutionHelperWrapper,
) -> Result<(CairoPie, StarknetOsOutput), SnOsError> {
    // Init CairoRunConfig
    let cairo_run_config = CairoRunConfig { layout, relocate_mem: true, trace_enabled: true, ..Default::default() };
    let allow_missing_builtins = cairo_run_config.allow_missing_builtins.unwrap_or(false);

    // Load the Starknet OS Program
    let starknet_os = fs::read(os_path).map_err(|e| SnOsError::CatchAll(format!("{e}")))?;
    let program = Program::from_bytes(&starknet_os, Some(cairo_run_config.entrypoint))
        .map_err(|e| SnOsError::Runner(e.into()))?;

    // Init cairo runner
    let mut cairo_runner = CairoRunner::new(
        &program,
        cairo_run_config.layout,
        cairo_run_config.proof_mode,
        cairo_run_config.trace_enabled,
    )
    .map_err(|e| SnOsError::Runner(e.into()))?;

    // Init the Cairo VM
    let end = cairo_runner.initialize(allow_missing_builtins).map_err(|e| SnOsError::Runner(e.into()))?;

    // Setup Depsyscall Handler
    let deprecated_syscall_handler = DeprecatedOsSyscallHandlerWrapper::new(
        execution_helper.clone(),
        cairo_runner.vm.add_memory_segment(),
        block_context.block_info().clone(),
    );

    let syscall_handler = OsSyscallHandlerWrapper::new(execution_helper.clone());

    // Setup Globals
    cairo_runner.exec_scopes.insert_value(vars::scopes::OS_INPUT, os_input);
    cairo_runner.exec_scopes.insert_box(vars::scopes::BLOCK_CONTEXT, Box::new(block_context));
    cairo_runner.exec_scopes.insert_value(vars::scopes::EXECUTION_HELPER, execution_helper);
    cairo_runner.exec_scopes.insert_value(vars::scopes::DEPRECATED_SYSCALL_HANDLER, deprecated_syscall_handler);
    cairo_runner.exec_scopes.insert_value(vars::scopes::SYSCALL_HANDLER, syscall_handler);
    cairo_runner
        .exec_scopes
        .insert_value(vars::scopes::PATRICIA_SKIP_VALIDATION_RUNNER, None::<PatriciaSkipValidationRunner>);
    cairo_runner.exec_scopes.insert_value(vars::scopes::PATRICIA_TREE_MODE, PatriciaTreeMode::State);

    // Run the Cairo VM
    let mut sn_hint_processor = hints::SnosHintProcessor::default();
    cairo_runner
        .run_until_pc(end, &mut sn_hint_processor)
        .map_err(|err| VmException::from_vm_error(&cairo_runner, err))
        .map_err(|e| SnOsError::Runner(e.into()))?;

    // End the Cairo VM run
    cairo_runner
        .end_run(cairo_run_config.disable_trace_padding, false, &mut sn_hint_processor)
        .map_err(|e| SnOsError::Runner(e.into()))?;

    if cairo_run_config.proof_mode {
        cairo_runner.finalize_segments().map_err(|e| SnOsError::Runner(e.into()))?;
    }

    // Prepare and check expected output.
    let os_output = StarknetOsOutput::from_run(&cairo_runner.vm)?;

    log::debug!("output: {:?}", os_output);
    log_output(&os_output);

    cairo_runner.vm.verify_auto_deductions().map_err(|e| SnOsError::Runner(e.into()))?;
    cairo_runner.read_return_values(allow_missing_builtins).map_err(|e| SnOsError::Runner(e.into()))?;
    cairo_runner.relocate(cairo_run_config.relocate_mem).map_err(|e| SnOsError::Runner(e.into()))?;

    // Parse the Cairo VM output
    let pie = cairo_runner.get_cairo_pie().map_err(|e| SnOsError::PieParsing(format!("{e}")))?;

    Ok((pie, os_output))
}
