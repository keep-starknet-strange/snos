mod hints;
mod hints_raw;
pub mod pie;

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::rc::Rc;

use cairo_vm::cairo_run::{cairo_run, CairoRunConfig};
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
    BuiltinHintProcessor, HintFunc,
};

pub fn run_os() {
    let sn_input = HintFunc(Box::new(hints::starknet_os_input));

    let mut hint_processor = BuiltinHintProcessor::new_empty();

    hint_processor.add_hint(String::from(hints_raw::SN_INPUT_RAW), Rc::new(sn_input));

    let os_file = File::open(Path::new("contracts/build/os_compiled.json")).unwrap();
    let mut reader = BufReader::new(os_file);
    let mut buffer = Vec::<u8>::new();
    reader.read_to_end(&mut buffer).unwrap();

    let _run_output = cairo_run(
        &buffer,
        &CairoRunConfig {
            layout: "starknet_with_keccak",
            ..Default::default()
        },
        &mut hint_processor,
    )
    .unwrap();
    log::debug!("successful run...");
}
