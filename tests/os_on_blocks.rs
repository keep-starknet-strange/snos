mod common;

use blockifier::block_context::BlockContext;
use cairo_vm::vm::errors::cairo_run_errors::CairoRunError::VmException;
use common::blocks::{block_context, simple_block};
use rstest::rstest;
use snos::error::SnOsError::Runner;
use snos::execution::helper::ExecutionHelperWrapper;
use snos::io::input::StarknetOsInput;
use snos::{config, run_os};

#[rstest]
fn run_os_on_simple_block(block_context: BlockContext, simple_block: (StarknetOsInput, ExecutionHelperWrapper)) {
    let (os_input, execution_helper) = simple_block;

    let result = run_os(
        config::DEFAULT_COMPILED_OS.to_string(),
        config::DEFAULT_LAYOUT.to_string(),
        os_input,
        block_context,
        execution_helper,
    );

    if let Err(ref e) = result {
        if let Runner(ref r) = e {
            if let VmException(ref vme) = r {
                println!("traceback:\n{}", vme.traceback.as_ref().unwrap());
            }
        }
    }

    println!("exception:\n{:#?}", result);
}
