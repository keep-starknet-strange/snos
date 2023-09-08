use cairo_vm::cairo_run::{cairo_run, CairoRunConfig};
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
use cairo_vm::vm::runners::cairo_pie::CairoPie;

pub fn setup_pie() -> CairoPie {
    // Load the test program
    let program_content = include_bytes!("../contracts/build/fact.json");

    let mut hint_processor = BuiltinHintProcessor::new_empty();

    // Run the program
    let result = cairo_run(
        program_content,
        &CairoRunConfig {
            layout: "small",
            ..Default::default()
        },
        &mut hint_processor,
    );
    let (runner, vm) = result.unwrap();
    let result = runner.get_cairo_pie(&vm);
    result.unwrap()
}
