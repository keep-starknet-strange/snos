mod common;

use std::fs;
use std::rc::Rc;

use cairo_vm::cairo_run::{cairo_run, CairoRunConfig};
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
    BuiltinHintProcessor, HintFunc,
};
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::*;
use common::utils::{check_output_vs_python, deprecated_cairo_python_run};
use common::{load_input, load_output};
use rstest::{fixture, rstest};
use snos::hints::block_context::*;
use snos::hints::execution::*;
use snos::hints::{
    initialize_class_hashes, initialize_state_changes, starknet_os_input, INITIALIZE_CLASS_HASHES,
    INITIALIZE_STATE_CHANGES, STARKNET_OS_INPUT,
};
use snos::io::input::StarknetOsInput;
use snos::io::output::StarknetOsOutput;

#[fixture]
fn os_input_hint_processor(_load_input: &StarknetOsInput) -> BuiltinHintProcessor {
    let mut hint_processor = BuiltinHintProcessor::new_empty();

    let starknet_os_input_hint = HintFunc(Box::new(starknet_os_input));
    hint_processor.add_hint(String::from(STARKNET_OS_INPUT), Rc::new(starknet_os_input_hint));

    hint_processor
}

#[rstest]
#[should_panic]
fn bad_output_test() {
    let program = "build/programs/bad_output.json";
    let mut bad_hint_processor = BuiltinHintProcessor::new_empty();
    let bad_hint = HintFunc(Box::new(|vm, _exec_scopes, ids_data, ap_tracking, _| {
        insert_value_from_var_name("a", 69, vm, ids_data, ap_tracking)?;
        Ok(())
    }));
    bad_hint_processor.add_hint(String::from("ids.a = 420"), Rc::new(bad_hint));

    let bad_hint_run = cairo_run(
        &fs::read(program).unwrap(),
        &CairoRunConfig { layout: "all_cairo", ..Default::default() },
        &mut bad_hint_processor,
    );
    check_output_vs_python(bad_hint_run, program, false);
}

#[rstest]
fn initialize_state_changes_test(mut os_input_hint_processor: BuiltinHintProcessor) {
    let program = "build/programs/initialize_state_changes.json";

    let initialize_state_changes_hint = HintFunc(Box::new(initialize_state_changes));
    os_input_hint_processor.add_hint(String::from(INITIALIZE_STATE_CHANGES), Rc::new(initialize_state_changes_hint));

    let initialize_class_hashes_hint = HintFunc(Box::new(initialize_class_hashes));
    os_input_hint_processor.add_hint(String::from(INITIALIZE_CLASS_HASHES), Rc::new(initialize_class_hashes_hint));

    let run_output = cairo_run(
        &fs::read(program).unwrap(),
        &CairoRunConfig { layout: "starknet", relocate_mem: true, trace_enabled: true, ..Default::default() },
        &mut os_input_hint_processor,
    );
    check_output_vs_python(run_output, program, true);
}

#[rstest]
fn get_block_mapping_test(mut os_input_hint_processor: BuiltinHintProcessor) {
    let program = "build/programs/get_block_mapping.json";

    let initialize_state_changes_hint = HintFunc(Box::new(initialize_state_changes));
    os_input_hint_processor.add_hint(String::from(INITIALIZE_STATE_CHANGES), Rc::new(initialize_state_changes_hint));

    let initialize_class_hashes_hint = HintFunc(Box::new(initialize_class_hashes));
    os_input_hint_processor.add_hint(String::from(INITIALIZE_CLASS_HASHES), Rc::new(initialize_class_hashes_hint));

    let get_block_mapping_hint = HintFunc(Box::new(get_block_mapping));
    os_input_hint_processor.add_hint(String::from(GET_BLOCK_MAPPING), Rc::new(get_block_mapping_hint));

    let run_output = cairo_run(
        &fs::read(program).unwrap(),
        &CairoRunConfig { layout: "starknet", relocate_mem: true, trace_enabled: true, ..Default::default() },
        &mut os_input_hint_processor,
    );
    check_output_vs_python(run_output, program, true);
}

#[rstest]
#[ignore]
fn load_next_tx_test(mut os_input_hint_processor: BuiltinHintProcessor) {
    let program = "build/programs/load_next_tx.json";

    let load_os_input = HintFunc(Box::new(starknet_os_input));
    os_input_hint_processor.add_hint(String::from(STARKNET_OS_INPUT), Rc::new(load_os_input));

    let load_scopes = HintFunc(Box::new(enter_syscall_scopes));
    os_input_hint_processor.add_hint(String::from(ENTER_SYSCALL_SCOPES), Rc::new(load_scopes));

    let load_transaction = HintFunc(Box::new(load_next_tx));
    os_input_hint_processor.add_hint(String::from(LOAD_NEXT_TX), Rc::new(load_transaction));

    let run_output = cairo_run(
        &fs::read(program).unwrap(),
        &CairoRunConfig { layout: "starknet", relocate_mem: true, trace_enabled: true, ..Default::default() },
        &mut os_input_hint_processor,
    );
    check_output_vs_python(run_output, program, true);
}

#[rstest]
#[ignore]
fn format_os_output_test(mut os_input_hint_processor: BuiltinHintProcessor, load_output: StarknetOsOutput) {
    let program = r#"build/programs/format_os_output.json"#;

    let load_os_input = HintFunc(Box::new(starknet_os_input));
    os_input_hint_processor.add_hint(String::from(STARKNET_OS_INPUT), Rc::new(load_os_input));

    // TODO: FORMAT_OUTPUT_PTR
    // let format_os_output_hint = HintFunc(Box::new(format_os_output));
    // os_input_hint_processor.add_hint(String::from(FORMAT_OS_OUTPUT), Rc::new(format_os_output_hint));

    let (_runner, vm) = cairo_run(
        &fs::read(program).unwrap(),
        &CairoRunConfig { layout: "starknet", relocate_mem: true, trace_enabled: true, ..Default::default() },
        &mut os_input_hint_processor,
    )
    .unwrap();
    println!("-------- python output ----------------");
    println!("{:?}\n----------------------------\n", deprecated_cairo_python_run(program, true));

    let os_output = StarknetOsOutput::from_run(&vm).unwrap();
    assert_eq!(load_output.config_hash, os_output.config_hash);
}
