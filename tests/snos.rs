mod common;

use blockifier::block_context::BlockContext;
use blockifier::state::cached_state::CachedState;
use blockifier::state::state_api::State;
use blockifier::test_utils::DictStateReader;

use pathfinder_common::{felt, StorageCommitment};

use common::{
    initial_state, prepare_os_test, raw_state, utils::check_output_vs_python, utils::print_a_hint,
    TestingContext,
};

use cairo_vm::cairo_run::{cairo_run, CairoRunConfig};
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
    BuiltinHintProcessor, HintFunc,
};

use snos::path_state::SharedState;
use snos::DEFAULT_LAYOUT;
use snos::{pap_state, SnOsRunner};
use starknet_api::core::ClassHash;
use starknet_api::state::DeprecatedDeclaredClasses;
use starknet_api::transaction::Calldata;
use std::fs;
use std::path::PathBuf;
use std::rc::Rc;

use rstest::*;

// #[rstest]
// fn snos_ok(_initial_state: TestingContext) {
//     let snos_runner = SnOsRunner::new(
//         DEFAULT_LAYOUT.to_string(),
//         PathBuf::from("build/os_debug.json"),
//     );
//     let _runner_res = snos_runner.run();
// }

#[rstest]
fn shared_state(mut initial_state: TestingContext) {
    let state_diff = initial_state.state.to_state_diff();

    let shared_state = SharedState::new();
    let commitment = shared_state.apply_diff(state_diff.clone());

    assert_eq!(
        StorageCommitment(felt!(
            "473010ec333f16b84334f9924912d7a13ce8296b0809c2091563ddfb63011d"
        )),
        commitment
    );
}

#[rstest]
fn shared_state_pap(mut initial_state: TestingContext, raw_state: DeprecatedDeclaredClasses) {
    let mut shared_state = pap_state::PapSharedState::new(
        initial_state.block_context.chain_id,
        Box::new(initial_state.state),
    );

    shared_state.apply_diff(Some(raw_state));
}

// #[rstest]
// fn prepared_os_test(mut prepare_os_test: (TestingContext, Vec<Calldata>)) {
//     println!("VEC: {:?} {}", prepare_os_test.1, prepare_os_test.1.len());
// }

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
