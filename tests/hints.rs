mod common;
use common::{load_and_write_input, utils::check_output_vs_python};

use cairo_vm::cairo_run::{cairo_run, CairoRunConfig};
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
    BuiltinHintProcessor, HintFunc,
};

use snos::hints::{
    hints_raw::*, load_deprecated_class_facts, load_deprecated_inner, starknet_os_input,
};
use snos::io::StarknetOsInput;

use std::fs;
use std::rc::Rc;

use rstest::*;

#[fixture]
fn os_input_hint_processor(
    _load_and_write_input: &(StarknetOsInput, String),
) -> BuiltinHintProcessor {
    let mut hint_processor = BuiltinHintProcessor::new_empty();

    let starknet_os_input_hint = HintFunc(Box::new(starknet_os_input));
    hint_processor.add_hint(
        String::from(STARKNET_OS_INPUT),
        Rc::new(starknet_os_input_hint),
    );

    hint_processor
}

#[rstest]
fn load_deprecated_class_test(mut os_input_hint_processor: BuiltinHintProcessor) {
    let program = "build/programs/load_deprecated_class.json";

    let load_deprecated_class_facts_hint = HintFunc(Box::new(load_deprecated_class_facts));
    os_input_hint_processor.add_hint(
        String::from(LOAD_DEPRECATED_CLASS_FACTS),
        Rc::new(load_deprecated_class_facts_hint),
    );

    let load_deprecated_class_inner_hint = HintFunc(Box::new(load_deprecated_inner));
    os_input_hint_processor.add_hint(
        String::from(LOAD_DEPRECATED_CLASS_INNER),
        Rc::new(load_deprecated_class_inner_hint),
    );

    match cairo_run(
        &fs::read(program).unwrap(),
        &CairoRunConfig {
            layout: "starknet",
            relocate_mem: true,
            trace_enabled: true,
            ..Default::default()
        },
        &mut os_input_hint_processor,
    ) {
        Ok((_runner, vm)) => check_output_vs_python(program, vm, true),
        Err(e) => eprint!("{e:#?}"),
    };
}
