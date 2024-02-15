mod common;

use std::fs;

use blockifier::block_context::BlockContext;
use blockifier::test_utils::dict_state_reader::DictStateReader;
use blockifier::transaction::objects::TransactionExecutionInfo;
use cairo_vm::cairo_run::CairoRunConfig;
use cairo_vm::types::program::Program;
use cairo_vm::vm::errors::vm_exception::VmException;
use cairo_vm::vm::runners::cairo_runner::CairoRunner;
use cairo_vm::vm::vm_core::VirtualMachine;
use common::load_input;
use common::prepared_os_test::{block_context, prepare_os_test};
use rstest::rstest;
use snos::execution::deprecated_syscall_handler::DeprecatedOsSyscallHandlerWrapper;
use snos::execution::helper::ExecutionHelperWrapper;
use snos::hints::SnosHintProcessor;
use snos::io::input::StarknetOsInput;
use snos::state::SharedState;
use starknet_api::block::{BlockNumber, BlockTimestamp};

#[rstest]
fn block_context_test(
    _load_input: &StarknetOsInput,
    mut block_context: BlockContext,
    prepare_os_test: (SharedState<DictStateReader>, Vec<TransactionExecutionInfo>),
) {
    let cairo_run_config = CairoRunConfig {
        layout: "starknet_with_keccak",
        relocate_mem: true,
        trace_enabled: true,
        ..Default::default()
    };

    let program =
        Program::from_bytes(&fs::read("build/programs/block_context.json").unwrap(), Some(cairo_run_config.entrypoint))
            .unwrap();

    let mut cairo_runner = CairoRunner::new(&program, cairo_run_config.layout, cairo_run_config.proof_mode).unwrap();
    let mut vm = VirtualMachine::new(cairo_run_config.trace_enabled);
    let end = cairo_runner.initialize(&mut vm, false).unwrap();
    // Setup Block Context
    block_context.block_number = BlockNumber(2);
    block_context.block_timestamp = BlockTimestamp(3);
    cairo_runner.exec_scopes.insert_box("block_context", Box::new(block_context.clone()));
    cairo_runner.exec_scopes.insert_value("input_path", "build/input.json");

    // Setup Execution Helper
    let exec_helper = ExecutionHelperWrapper::new(prepare_os_test.1, &block_context);
    cairo_runner.exec_scopes.insert_value("execution_helper", exec_helper.clone());

    // Setup Depsyscall Handler
    let dep_syscall_ptr = vm.add_memory_segment();
    cairo_runner.exec_scopes.insert_value(
        "deprecated_syscall_handler",
        DeprecatedOsSyscallHandlerWrapper::new(exec_helper, dep_syscall_ptr),
    );

    let mut sn_hint_processor = SnosHintProcessor::default();

    cairo_runner
        .run_until_pc(end, &mut vm, &mut sn_hint_processor)
        .map_err(|err| VmException::from_vm_error(&cairo_runner, &vm, err))
        .unwrap();
    cairo_runner.end_run(cairo_run_config.disable_trace_padding, false, &mut vm, &mut sn_hint_processor).unwrap();

    vm.verify_auto_deductions().unwrap();
    cairo_runner.read_return_values(&mut vm).unwrap();
    if cairo_run_config.proof_mode {
        cairo_runner.finalize_segments(&mut vm).unwrap();
    }

    cairo_runner.relocate(&mut vm, cairo_run_config.relocate_mem).unwrap();

    let mut rs_output = String::new();
    let _ = vm.write_output(&mut rs_output);

    println!("\n-------------------------------RUST PROGRAM OUTPUT-------------------------------\n");
    println!("Program output:");
    println!("{rs_output}");
}
