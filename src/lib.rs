use std::fs;

use blockifier::context::BlockContext;
use cairo_vm::cairo_run::CairoRunConfig;
use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::types::program::Program;
use cairo_vm::vm::errors::vm_exception::VmException;
use cairo_vm::vm::runners::cairo_pie::CairoPie;
use cairo_vm::vm::runners::cairo_runner::CairoRunner;
use error::SnOsError;
use execution::deprecated_syscall_handler::DeprecatedOsSyscallHandlerWrapper;
use execution::helper::ExecutionHelperWrapper;
use io::output::StarknetOsOutput;

use crate::execution::syscall_handler::OsSyscallHandlerWrapper;
use crate::hints::types::{PatriciaSkipValidationRunner, PatriciaTreeMode};
use crate::hints::vars;
use crate::io::input::StarknetOsInput;

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

pub fn run_os(
    os_path: String,
    layout: LayoutName,
    os_input: StarknetOsInput,
    block_context: BlockContext,
    execution_helper: ExecutionHelperWrapper,
) -> Result<CairoPie, SnOsError> {
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
    let deprecated_syscall_handler =
        DeprecatedOsSyscallHandlerWrapper::new(execution_helper.clone(), cairo_runner.vm.add_memory_segment());

    let syscall_handler = OsSyscallHandlerWrapper::new(execution_helper.clone());

    // Setup Globals
    cairo_runner.exec_scopes.insert_value("os_input", os_input);
    cairo_runner.exec_scopes.insert_box("block_context", Box::new(block_context));
    cairo_runner.exec_scopes.insert_value("execution_helper", execution_helper);
    cairo_runner.exec_scopes.insert_value("deprecated_syscall_handler", deprecated_syscall_handler);
    cairo_runner.exec_scopes.insert_value("syscall_handler", syscall_handler);
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

    cairo_runner.vm.verify_auto_deductions().map_err(|e| SnOsError::Runner(e.into()))?;
    cairo_runner.read_return_values(allow_missing_builtins).map_err(|e| SnOsError::Runner(e.into()))?;
    cairo_runner.relocate(cairo_run_config.relocate_mem).map_err(|e| SnOsError::Runner(e.into()))?;

    // Parse the Cairo VM output
    let pie = cairo_runner.get_cairo_pie().map_err(|e| SnOsError::PieParsing(format!("{e}")))?;

    Ok(pie)
}
