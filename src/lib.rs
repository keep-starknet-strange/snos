use std::fs;

use blockifier::block_context::BlockContext;
use cairo_vm::cairo_run::CairoRunConfig;
use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::types::program::Program;
use cairo_vm::vm::errors::vm_exception::VmException;
use cairo_vm::vm::runners::cairo_pie::CairoPie;
use cairo_vm::vm::runners::cairo_runner::CairoRunner;
use cairo_vm::vm::vm_core::VirtualMachine;
use error::SnOsError;
use execution::deprecated_syscall_handler::DeprecatedOsSyscallHandlerWrapper;
use execution::helper::ExecutionHelperWrapper;
use io::output::StarknetOsOutput;

use crate::execution::syscall_handler::OsSyscallHandlerWrapper;
use crate::hints::types::PatriciaSkipValidationRunner;
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
pub mod state;
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

    // Load the Starknet OS Program
    let starknet_os = fs::read(os_path).map_err(|e| SnOsError::CatchAll(format!("{e}")))?;
    let program = Program::from_bytes(&starknet_os, Some(cairo_run_config.entrypoint))
        .map_err(|e| SnOsError::Runner(e.into()))?;

    // Init cairo runner
    let mut cairo_runner = CairoRunner::new(&program, cairo_run_config.layout, cairo_run_config.proof_mode)
        .map_err(|e| SnOsError::Runner(e.into()))?;

    // Init the Cairo VM
    let mut vm = VirtualMachine::new(cairo_run_config.trace_enabled);
    let end = cairo_runner.initialize(&mut vm, false).map_err(|e| SnOsError::Runner(e.into()))?;

    // Setup Depsyscall Handler
    let deprecated_syscall_handler =
        DeprecatedOsSyscallHandlerWrapper::new(execution_helper.clone(), vm.add_memory_segment());

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

    // Run the Cairo VM
    let mut sn_hint_processor = hints::SnosHintProcessor::default();
    cairo_runner
        .run_until_pc(end, &mut vm, &mut sn_hint_processor)
        .map_err(|err| VmException::from_vm_error(&cairo_runner, &vm, err))
        .map_err(|e| SnOsError::Runner(e.into()))?;

    // End the Cairo VM run
    cairo_runner
        .end_run(cairo_run_config.disable_trace_padding, false, &mut vm, &mut sn_hint_processor)
        .map_err(|e| SnOsError::Runner(e.into()))?;

    if cairo_run_config.proof_mode {
        cairo_runner.finalize_segments(&mut vm).map_err(|e| SnOsError::Runner(e.into()))?;
    }

    // Prepare and check expected output.
    let os_output = StarknetOsOutput::from_run(&vm)?;

    println!("output: {:?}", os_output);

    vm.verify_auto_deductions().map_err(|e| SnOsError::Runner(e.into()))?;
    cairo_runner.read_return_values(&mut vm, false).map_err(|e| SnOsError::Runner(e.into()))?;
    cairo_runner.relocate(&mut vm, cairo_run_config.relocate_mem).map_err(|e| SnOsError::Runner(e.into()))?;

    // Parse the Cairo VM output
    let pie = cairo_runner.get_cairo_pie(&vm).map_err(|e| SnOsError::PieParsing(format!("{e}")))?;

    Ok(pie)
}
