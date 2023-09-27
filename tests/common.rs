use cairo_vm::cairo_run::{cairo_run, CairoRunConfig};
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
use cairo_vm::vm::runners::cairo_pie::CairoPie;
use cairo_vm::vm::runners::cairo_runner::CairoRunner;
use cairo_vm::vm::vm_core::VirtualMachine;

use std::fs;
use std::path;
use std::process;

use rstest::*;

const BUILD_DIR: &str = "build/";
const CAIRO_COMPILE_CMD: &str = "cairo-compile";
const TEST_CONTRACTS_DIR: &str = "tests/contracts/";

#[fixture]
#[once]
pub fn compile_contracts() {
    let contracts = fs::read_dir(TEST_CONTRACTS_DIR).unwrap();

    for contract in contracts {
        let contract_path = contract.unwrap().path();
        let stem = contract_path.file_stem().unwrap();

        let contract_out_fmt = format!("{BUILD_DIR}{}.json", stem.to_str().unwrap());
        let contract_out = path::PathBuf::from(&contract_out_fmt);

        if !contract_out.exists() {
            let cmd_check = process::Command::new(CAIRO_COMPILE_CMD).arg("-v").output();
            assert!(cmd_check.is_ok());

            let out = process::Command::new(CAIRO_COMPILE_CMD)
                .args([
                    contract_path.to_str().unwrap(),
                    "--output",
                    contract_out.to_str().unwrap(),
                    "--no_debug_info",
                ])
                .output();
            assert!(out.is_ok());
        }
    }
}

#[fixture]
pub fn setup_runner(_compile_contracts: ()) -> (CairoRunner, VirtualMachine) {
    let program_content = fs::read("build/fact.json").unwrap();

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

#[allow(unused)]
pub fn check_output_vs_python(program: &str, mut vm: VirtualMachine) {
    let mut rs_output = String::new();
    vm.write_output(&mut rs_output).unwrap();
    let rs_output = rs_output.split('\n').filter(|&x| !x.is_empty());
    let python_output = std::process::Command::new("cairo-run")
        .arg("--layout=small")
        .arg(format!("--program={program:}"))
        .arg("--print_output")
        .output()
        .expect("failed to run python vm");
    let python_output = unsafe { std::str::from_utf8_unchecked(&python_output.stdout) }.to_string();
    let python_output = python_output
        .split('\n')
        .into_iter()
        .skip_while(|&x| x != "Program output:")
        .skip(1)
        .filter(|&x| !x.trim().is_empty())
        .into_iter();
    for (i, (rs, py)) in rs_output.zip(python_output).enumerate() {
        let py = py.to_string().trim().to_string();
        pretty_assertions::assert_eq!(*rs, py, "Output #{i:} is different");
    }
}
