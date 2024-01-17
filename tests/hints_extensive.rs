mod common;

use std::fs;

use blockifier::block_context::BlockContext;
use blockifier::test_utils::dict_state_reader::DictStateReader;
use blockifier::transaction::objects::TransactionExecutionInfo;
use cairo_vm::cairo_run::{cairo_run, CairoRunConfig};
use cairo_vm::types::program::Program;
use cairo_vm::vm::errors::vm_exception::VmException;
use cairo_vm::vm::runners::cairo_runner::CairoRunner;
use cairo_vm::vm::vm_core::VirtualMachine;
use common::load_input;
use common::prepared_os_test::{block_context, prepare_os_test};
use common::utils::check_output_vs_python;
use rstest::rstest;
use snos::hints::SnosHintProcessor;
use snos::io::input::StarknetOsInput;
use snos::state::SharedState;

#[rstest]
fn load_deprecated_class_test() {
    let program = "build/programs/load_deprecated_class.json";

    let mut sn_hint_processor = SnosHintProcessor::default();

    let run_output = cairo_run(
        &fs::read(program).unwrap(),
        &CairoRunConfig { layout: "starknet", relocate_mem: true, trace_enabled: true, ..Default::default() },
        &mut sn_hint_processor,
    );
    check_output_vs_python(run_output, program, true);
}

#[rstest]
fn dep_exec_entry_point_test() {
    let program = "build/programs/dep_exec_entry_point.json";

    let mut sn_hint_processor = SnosHintProcessor::default();

    let run_output = cairo_run(
        &fs::read(program).unwrap(),
        &CairoRunConfig { layout: "starknet", relocate_mem: true, trace_enabled: true, ..Default::default() },
        &mut sn_hint_processor,
    );
    check_output_vs_python(run_output, program, true);
}

#[rstest]
fn exec_deploy_tx_test(block_context: BlockContext, load_input: &StarknetOsInput) {
    let cairo_run_config = CairoRunConfig {
        layout: "starknet_with_keccak",
        relocate_mem: true,
        trace_enabled: true,
        ..Default::default()
    };

    let program = Program::from_bytes(
        &fs::read("build/programs/exec_deploy_tx.json").unwrap(),
        Some(cairo_run_config.entrypoint),
    )
    .unwrap();

    let mut cairo_runner = CairoRunner::new(&program, cairo_run_config.layout, cairo_run_config.proof_mode).unwrap();
    let mut vm = VirtualMachine::new(cairo_run_config.trace_enabled);
    let end = cairo_runner.initialize(&mut vm).unwrap();
    cairo_runner.exec_scopes.insert_value("input_path", "build/input.json");
    cairo_runner.exec_scopes.insert_value("tx", load_input.transactions[0].clone());
    cairo_runner.exec_scopes.insert_box("block_context", Box::new(block_context));

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
