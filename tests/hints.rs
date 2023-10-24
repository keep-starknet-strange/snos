mod common;

use std::fs;
use std::rc::Rc;

use cairo_vm::cairo_run::{cairo_run, CairoRunConfig};
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
    BuiltinHintProcessor, HintFunc,
};
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::*;
use common::load_input;
use common::utils::check_output_vs_python;
use rstest::{fixture, rstest};
use snos::hints::block_context::{
    get_block_mapping, load_deprecated_class_facts, load_deprecated_inner, sequencer_address,
};
use snos::hints::hints_raw::*;
use snos::hints::{
    check_deprecated_class_hash, enter_syscall_scopes, initialize_class_hashes, initialize_state_changes, load_next_tx,
    starknet_os_input,
};
use snos::io::StarknetOsInput;

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
