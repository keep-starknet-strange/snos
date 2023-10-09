mod common;

use blockifier::test_utils::DictStateReader;
use common::{initial_state, prepare_os_test, utils::check_output_vs_python, utils::print_a_hint};

use cairo_vm::cairo_run::{cairo_run, CairoRunConfig};
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
    BuiltinHintProcessor, HintFunc,
};

use snos::{state::SharedState, SnOsRunner};
use starknet_api::block::BlockNumber;
use starknet_api::transaction::Calldata;

use std::fs;
use std::rc::Rc;

use rstest::*;

#[rstest]
#[ignore]
fn snos_ok(_initial_state: SharedState<DictStateReader>) {
    let snos_runner = SnOsRunner::with_os_path("build/os_debug.json");
    let _runner_res = snos_runner.run();
}

#[rstest]
fn prepared_os_test(prepare_os_test: (SharedState<DictStateReader>, Vec<Calldata>)) {
    let (mut shared_state, txns) = prepare_os_test;
    assert_eq!(23, txns.len());

    shared_state.apply_diff();
    assert_eq!(BlockNumber(2), shared_state.get_block_num())
}

#[rstest]
fn custom_hint_ok() {
    let program_content = fs::read("build/hint.json").unwrap();

    // Wrap the Rust hint implementation in a Box smart pointer inside a HintFunc
    let hint = HintFunc(Box::new(print_a_hint));

    //Instantiate the hint processor
    let mut hint_processor = BuiltinHintProcessor::new_empty();

    //Add the custom hint, together with the Python code
    hint_processor.add_hint(String::from("print(ids.a)"), Rc::new(hint));

    //Run the cairo program
    let (_cairo_runner, virtual_machine) = cairo_run(
        &program_content,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_processor,
    )
    .expect("Couldn't run program");
    check_output_vs_python("build/hint.json", virtual_machine);
}

#[rstest]
#[should_panic(expected = "Output #0 is different")]
fn test_different_outputs() {
    let program_content = fs::read("build/hint.json").unwrap();

    // Wrap the Rust hint implementation in a Box smart pointer inside a HintFunc
    let hint = HintFunc(Box::new(print_a_hint));

    //Instantiate the hint processor
    let mut hint_processor = BuiltinHintProcessor::new_empty();

    //Add the custom hint, together with the Python code
    hint_processor.add_hint(String::from("print(ids.a)"), Rc::new(hint));

    //Run the cairo program
    let (_cairo_runner, virtual_machine) = cairo_run(
        &program_content,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_processor,
    )
    .expect("Couldn't run program");
    check_output_vs_python("build/different_output.json", virtual_machine);
}
