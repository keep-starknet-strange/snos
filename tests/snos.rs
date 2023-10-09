mod common;

use blockifier::state::state_api::State;
use common::{
    initial_state, prepare_os_test, utils::check_output_vs_python, utils::print_a_hint,
    TestingContext,
};

use cairo_vm::cairo_run::{cairo_run, CairoRunConfig};
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
    BuiltinHintProcessor, HintFunc,
};

use snos::DEFAULT_LAYOUT;
use snos::{state::SharedState, SnOsRunner};
use starknet_api::block::BlockNumber;
use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;
use starknet_api::transaction::Calldata;

use std::fs;
use std::rc::Rc;

use rstest::*;

#[rstest]
#[ignore]
fn snos_ok(_initial_state: TestingContext) {
    let snos_runner = SnOsRunner::new(DEFAULT_LAYOUT.to_string(), "build/os_debug.json");
    let _runner_res = snos_runner.run();
}

#[rstest]
fn shared_state(initial_state: TestingContext) {
    let mut shared_state = SharedState::new(
        initial_state.block_context.chain_id,
        Box::new(initial_state.state),
    );
    let commitment = shared_state.apply_diff(BlockNumber(1));

    // expected root parsed from current os_test.py & test_utils.py(0.12.2)
    assert_eq!(
        stark_felt!("473010ec333f16b84334f9924912d7a13ce8296b0809c2091563ddfb63011d"),
        commitment
    );
}

#[rstest]
fn prepared_os_test(mut prepare_os_test: (TestingContext, Vec<Calldata>)) {
    let _diff = prepare_os_test.0.state.to_state_diff();
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
