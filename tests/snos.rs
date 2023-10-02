mod common;
use cairo_vm::cairo_run::{cairo_run, CairoRunConfig};
use cairo_vm::felt::Felt252;
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
    BuiltinHintProcessor, HintFunc,
};
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::get_integer_from_var_name;
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::vm::{errors::hint_errors::HintError, vm_core::VirtualMachine};
use common::{check_output_vs_python, compile_contracts};
use snos::*;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::rc::Rc;

use rstest::*;

// Create the function that implements the custom hint
fn print_a_hint(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let a = get_integer_from_var_name("a", vm, ids_data, ap_tracking)?;
    println!("{}", a);
    Ok(())
}

#[rstest]
fn snos_ok() {
    let snos_runner = SnOsRunner::new(
        DEFAULT_LAYOUT.to_string(),
        PathBuf::from("build/os_debug.json"),
    );
    let _runner_res = snos_runner.run();
    assert_eq!(4, 4);
}

#[rstest]
fn custom_hint_ok(_compile_contracts: ()) {
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
fn test_different_outputs(_compile_contracts: ()) {
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
