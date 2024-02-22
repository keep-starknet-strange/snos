pub mod defs;
pub mod prepared_os_test;
pub mod serde_utils;
pub mod utils;

use std::fs;

use blockifier::state::state_api::State;
use blockifier::test_utils::dict_state_reader::DictStateReader;
use cairo_vm::cairo_run::{cairo_run, CairoRunConfig};
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
use cairo_vm::vm::runners::cairo_pie::CairoPie;
use cairo_vm::vm::runners::cairo_runner::CairoRunner;
use cairo_vm::vm::vm_core::VirtualMachine;
use rstest::fixture;
use snos::config::DEFAULT_INPUT_PATH;
use snos::io::input::StarknetOsInput;
use snos::io::output::{decode_output, StarknetOsOutput};
use snos::state::SharedState;
use starknet_api::core::{calculate_contract_address, ClassHash, PatriciaKey};
use starknet_api::hash::StarkHash;
use starknet_api::transaction::{Calldata, ContractAddressSalt};
use starknet_api::{calldata, contract_address, patricia_key};

#[fixture]
#[once]
pub fn load_and_write_input() {
    let os_input = serde_utils::StarknetOsInputUtil::load("tests/common/data/os_input.json");
    os_input.dump(DEFAULT_INPUT_PATH).unwrap();
}

#[fixture]
#[once]
pub fn load_input(_load_and_write_input: ()) -> StarknetOsInput {
    StarknetOsInput::load(std::path::Path::new(DEFAULT_INPUT_PATH)).unwrap()
}

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
