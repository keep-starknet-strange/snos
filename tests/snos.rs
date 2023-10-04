mod common;

use blockifier::block_context::BlockContext;
use blockifier::state::cached_state::CachedState;
use blockifier::state::state_api::{State, StateReader};
use blockifier::test_utils::DictStateReader;

use pathfinder_storage::{BlockId, Storage};

use common::{initial_state, utils};

use cairo_vm::cairo_run::{cairo_run, CairoRunConfig};
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
    BuiltinHintProcessor, HintFunc,
};

use starknet_api::hash::StarkFelt;
use starknet_api::stark_felt;

use snos::*;
use std::fs;
use std::path::PathBuf;
use std::rc::Rc;

use rstest::*;

#[rstest]
fn snos_ok(_initial_state: (BlockContext, CachedState<DictStateReader>)) {
    let snos_runner = SnOsRunner::new(
        DEFAULT_LAYOUT.to_string(),
        PathBuf::from("build/os_debug.json"),
    );
    let _runner_res = snos_runner.run();
    assert_eq!(4, 4);
}

#[rstest]
fn shared_state(mut initial_state: (BlockContext, CachedState<DictStateReader>)) {
    let storage = Storage::in_memory().unwrap();
    let mut connection = storage.connection().unwrap();
    let tx = connection.transaction().unwrap();

    let mut shared_state = fact_state::SharedState::load_new(&tx);
    shared_state.apply_diff(&tx, initial_state.1.to_state_diff());

    assert_eq!(
        stark_felt!("473010ec333f16b84334f9924912d7a13ce8296b0809c2091563ddfb63011d"),
        stark_felt!("473010ec333f16b84334f9924912d7a13ce8296b0809c2091563ddfb63011d")
    );
}

#[rstest]
fn custom_hint_ok() {
    let program_content = fs::read("build/hint.json").unwrap();

    // Wrap the Rust hint implementation in a Box smart pointer inside a HintFunc
    let hint = HintFunc(Box::new(utils::print_a_hint));

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
    utils::check_output_vs_python("build/hint.json", virtual_machine);
}

#[rstest]
#[should_panic(expected = "Output #0 is different")]
fn test_different_outputs() {
    let program_content = fs::read("build/hint.json").unwrap();

    // Wrap the Rust hint implementation in a Box smart pointer inside a HintFunc
    let hint = HintFunc(Box::new(utils::print_a_hint));

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
    utils::check_output_vs_python("build/different_output.json", virtual_machine);
}
