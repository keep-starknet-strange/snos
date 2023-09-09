use snos::RelocatedMemory;

use cairo_vm::cairo_run::{cairo_run, CairoRunConfig};
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
use cairo_vm::vm::runners::cairo_pie::CairoPie;
use cairo_vm::vm::runners::cairo_runner::CairoRunner;
use cairo_vm::vm::vm_core::VirtualMachine;

pub fn setup_runner() -> (CairoRunner, VirtualMachine) {
    // Load the test program
    let program_content = include_bytes!("../contracts/build/fact.json");

    let mut hint_processor = BuiltinHintProcessor::new_empty();

    // Run the program
    cairo_run(
        program_content,
        &CairoRunConfig {
            entrypoint: "main",
            trace_enabled: true,
            relocate_mem: true,
            layout: "small",
            proof_mode: false,
            secure_run: None,
            disable_trace_padding: false,
        },
        &mut hint_processor,
    )
    .unwrap()
}


pub fn setup_pie() -> (CairoPie, RelocatedMemory) {
    // Run the runner
    let (runner, vm) = setup_runner();

    (runner.get_cairo_pie(&vm).unwrap(), runner.relocated_memory)
}