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
use crate::storage::storage::Storage;

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

pub fn run_os<S>(
    compiled_os: &[u8],
    layout: LayoutName,
    os_input: StarknetOsInput,
    block_context: BlockContext,
    execution_helper: ExecutionHelperWrapper<S>,
) -> Result<(CairoPie, StarknetOsOutput), SnOsError>
where
    S: Storage + 'static,
{
    // Init CairoRunConfig
    let cairo_run_config = CairoRunConfig { layout, relocate_mem: true, trace_enabled: true, ..Default::default() };
    let allow_missing_builtins = cairo_run_config.allow_missing_builtins.unwrap_or(false);

    // Load the Starknet OS Program
    let os_program =
        Program::from_bytes(compiled_os, Some(cairo_run_config.entrypoint)).map_err(|e| SnOsError::Runner(e.into()))?;

    // Init cairo runner
    let mut cairo_runner = CairoRunner::new(
        &os_program,
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
    let mut sn_hint_processor = hints::SnosHintProcessor::<S>::default();
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

    log::debug!("output: {}", serde_json::to_string_pretty(&os_output).unwrap());

    cairo_runner.vm.verify_auto_deductions().map_err(|e| SnOsError::Runner(e.into()))?;
    cairo_runner.read_return_values(allow_missing_builtins).map_err(|e| SnOsError::Runner(e.into()))?;
    cairo_runner.relocate(cairo_run_config.relocate_mem).map_err(|e| SnOsError::Runner(e.into()))?;

    // Parse the Cairo VM output
    let pie = cairo_runner.get_cairo_pie().map_err(|e| SnOsError::PieParsing(format!("{e}")))?;

    Ok((pie, os_output))
}
