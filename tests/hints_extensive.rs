mod common;

use std::fs;

use cairo_vm::cairo_run::{cairo_run, CairoRunConfig};
use common::utils::check_output_vs_python;
use rstest::rstest;
use snos::hints::SnosHintProcessor;

#[rstest]
fn load_deprecated_class_test() {
    let program = "build/programs/load_deprecated_class.json";

    let mut sn_hint_processor = SnosHintProcessor::default();

    let run_output = cairo_run(
        &fs::read(program).unwrap(),
        &CairoRunConfig { layout: "starknet", relocate_mem: true, trace_enabled: true, ..Default::default() },
        &mut sn_hint_processor,
    );
    check_output_vs_python(run_output, program, true);
}
