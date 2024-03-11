use std::{env, path};

use blockifier::execution::contract_class::{ContractClass, ContractClassV0};
use cairo_vm::vm::errors::cairo_run_errors::CairoRunError;
use starknet_api::core::ContractAddress;
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedContractClass;

use super::*;

pub fn load_class_v0(path: &str) -> ContractClass {
    ContractClassV0::try_from_json_string(&load_class_raw(path)).unwrap().into()
}

#[allow(unused)]
pub fn load_deprecated_class(path: &str) -> DeprecatedContractClass {
    serde_json::from_str(&load_class_raw(path)).unwrap()
}

pub fn load_class_raw(path: &str) -> String {
    fs::read_to_string(path::PathBuf::from(path)).unwrap()
}

#[allow(unused)]
pub fn check_output_vs_python(
    run_output: Result<(CairoRunner, VirtualMachine), CairoRunError>,
    program: &str,
    with_input: bool,
) {
    let mut rs_output = String::new();
    match run_output {
        Ok((_, mut vm)) => vm.write_output(&mut rs_output),
        Err(e) => Ok(rs_output.push_str(&format!("{e:#?}"))),
    };

    println!("\n-------------------------------RUST PROGRAM OUTPUT-------------------------------\n");
    println!("Program output:");
    println!("{rs_output}");

    let py_output = deprecated_cairo_python_run(program, with_input);
    println!("\n------------------------------PYTHON PROGRAM OUTPUT------------------------------\n");
    println!("Program output:");
    println!("{py_output}\n");

    println!("\n--------------------------------------------------------------------------------\n");

    for (i, (rs, py)) in rs_output.split('\n').zip(py_output.split('\n')).enumerate() {
        pretty_assertions::assert_eq!(rs, py, "Output Differs({i})");
    }
}

pub fn deprecated_cairo_python_run(program: &str, with_input: bool) -> String {
    env::set_var("PYTHONPATH", "cairo-lang/src");
    let mut run_cmd = std::process::Command::new("cairo-run");
    run_cmd.arg(format!("--program={program}")).arg("--layout=starknet").arg("--print_output");

    if with_input {
        run_cmd.arg("--program_input=build/input.json");
    }

    let cmd_out = run_cmd.output().expect("failed to run python vm");
    let mut raw = String::from_utf8(cmd_out.stdout).unwrap();
    raw.push_str(&String::from_utf8(cmd_out.stderr).unwrap());

    raw.trim_start_matches("Program output:").trim_start_matches("\n  ").trim_end_matches("\n\n").replace(' ', "")
}

pub fn raw_deploy(
    shared_state: &mut SharedState<DictStateReader>,
    class_path: &str,
    class_hash: ClassHash,
) -> ContractAddress {
    let contract_class = load_class_v0(class_path);
    shared_state.cache.set_contract_class(class_hash, contract_class).unwrap();

    let contract_addr =
        calculate_contract_address(ContractAddressSalt::default(), class_hash, &calldata![], contract_address!(0_u32))
            .unwrap();
    shared_state.cache.set_class_hash_at(contract_addr, class_hash).unwrap();

    contract_addr
}
