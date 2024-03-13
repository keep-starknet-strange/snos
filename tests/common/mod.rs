use std::fs;

use cairo_vm::cairo_run::{cairo_run, CairoRunConfig};
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
use cairo_vm::vm::runners::cairo_pie::CairoPie;
use cairo_vm::vm::runners::cairo_runner::CairoRunner;
use cairo_vm::vm::vm_core::VirtualMachine;
use rstest::fixture;

use snos::io::output::{decode_output, StarknetOsOutput};

pub mod blocks;
pub mod serde_utils;
mod transaction_utils;
pub mod utils;

#[fixture]
pub fn setup_runner() -> (CairoRunner, VirtualMachine) {
    let program_content = fs::read("build/programs/fact.json").unwrap();

    let mut hint_processor = BuiltinHintProcessor::new_empty();

    // Run the program
    cairo_run(
        &program_content,
        &CairoRunConfig {
            entrypoint: "main",
            trace_enabled: true,
            relocate_mem: true,
            layout: "small",
            proof_mode: false,
            secure_run: Some(true),
            disable_trace_padding: false,
            allow_missing_builtins: None,
        },
        &mut hint_processor,
    )
    .unwrap()
}

#[fixture]
pub fn setup_pie(setup_runner: (CairoRunner, VirtualMachine)) -> CairoPie {
    // Run the runner
    let (runner, vm) = setup_runner;

    runner.get_cairo_pie(&vm).unwrap()
}

#[fixture]
pub fn load_output() -> StarknetOsOutput {
    let buf = fs::read_to_string("tests/common/data/os_output.json").unwrap();
    let raw_output: serde_utils::RawOsOutput = serde_json::from_str(&buf).unwrap();

    decode_output(raw_output.0).unwrap()
}

#[fixture]
pub fn os_pie_string() -> String {
    std::fs::read_to_string("tests/common/data/output_pie.b64").unwrap()
}
