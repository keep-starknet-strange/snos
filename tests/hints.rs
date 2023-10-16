mod common;
use std::collections::HashMap;
use std::fs;
use std::rc::Rc;

use cairo_felt::Felt252;
use cairo_vm::cairo_run::{cairo_run, CairoRunConfig};
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
    BuiltinHintProcessor, HintFunc,
};
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::insert_value_from_var_name;
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use common::load_and_write_input;
use common::utils::check_output_vs_python;
use rstest::{fixture, rstest};
use snos::hints::block_context::{load_deprecated_class_facts, load_deprecated_inner, sequencer_address};
use snos::hints::hints_raw::*;
use snos::hints::{check_deprecated_class_hash, starknet_os_input};
use snos::io::StarknetOsInput;

#[fixture]
fn os_input_hint_processor(_load_and_write_input: &(StarknetOsInput, String)) -> BuiltinHintProcessor {
    let mut hint_processor = BuiltinHintProcessor::new_empty();

    let starknet_os_input_hint = HintFunc(Box::new(starknet_os_input));
    hint_processor.add_hint(String::from(STARKNET_OS_INPUT), Rc::new(starknet_os_input_hint));

    hint_processor
}

#[rstest]
fn block_context_test(mut os_input_hint_processor: BuiltinHintProcessor) {
    let program = "build/programs/load_deprecated_class.json";

    let load_deprecated_class_facts_hint = HintFunc(Box::new(load_deprecated_class_facts));
    os_input_hint_processor
        .add_hint(String::from(LOAD_DEPRECATED_CLASS_FACTS), Rc::new(load_deprecated_class_facts_hint));

    let load_deprecated_class_inner_hint = HintFunc(Box::new(load_deprecated_inner));
    os_input_hint_processor
        .add_hint(String::from(LOAD_DEPRECATED_CLASS_INNER), Rc::new(load_deprecated_class_inner_hint));

    let check_deprecated_class_hash_hint = HintFunc(Box::new(check_deprecated_class_hash));
    os_input_hint_processor
        .add_hint(String::from(CHECK_DEPRECATED_CLASS_HASH), Rc::new(check_deprecated_class_hash_hint));

    let sequencer_address_hint = HintFunc(Box::new(sequencer_address));
    os_input_hint_processor.add_hint(String::from(SEQUENCER_ADDRESS), Rc::new(sequencer_address_hint));

    let run_output = cairo_run(
        &fs::read(program).unwrap(),
        &CairoRunConfig { layout: "starknet", relocate_mem: true, trace_enabled: true, ..Default::default() },
        &mut os_input_hint_processor,
    );
    check_output_vs_python(run_output, program, true);
}

#[rstest]
#[should_panic]
fn bad_output_test() {
    let program = "build/programs/bad_output.json";
    let mut bad_hint_processor = BuiltinHintProcessor::new_empty();
    let bad_hint = HintFunc(Box::new(bad_hint));
    bad_hint_processor.add_hint(String::from("ids.a = 420"), Rc::new(bad_hint));

    let bad_hint_run = cairo_run(
        &fs::read(program).unwrap(),
        &CairoRunConfig { layout: "all_cairo", ..Default::default() },
        &mut bad_hint_processor,
    );
    check_output_vs_python(bad_hint_run, program, false);
}

#[allow(unused)]
pub fn bad_hint(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    insert_value_from_var_name("a", 69, vm, ids_data, ap_tracking)?;
    Ok(())
}
