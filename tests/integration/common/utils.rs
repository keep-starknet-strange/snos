use std::env;

use cairo_vm::vm::errors::cairo_run_errors::CairoRunError;

use super::*;

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
