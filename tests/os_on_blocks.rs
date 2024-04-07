mod common;

use blockifier::block_context::BlockContext;
use cairo_vm::vm::errors::cairo_run_errors::CairoRunError::VmException;
use common::blocks::{block_context, simple_block};
use rstest::rstest;
use snos::error::SnOsError::Runner;
use snos::execution::helper::ExecutionHelperWrapper;
use snos::io::input::StarknetOsInput;
use snos::{config, run_os};

use crate::common::blocks::simple_block_cairo1;
use crate::common::syscalls_blocks::cairo1_syscalls_block;

fn run_os_on_block(block_context: BlockContext, block: (StarknetOsInput, ExecutionHelperWrapper)) {
    let (os_input, execution_helper) = block;

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
                if let Some(traceback) = vme.traceback.as_ref() {
                    println!("traceback:\n{}", traceback);
                }
            }
        }
    }

    println!("exception:\n{:#?}", result);
}

#[rstest]
#[ignore]
fn run_os_on_simple_block(block_context: BlockContext, simple_block: (StarknetOsInput, ExecutionHelperWrapper)) {
    run_os_on_block(block_context, simple_block);
}

#[rstest]
#[ignore]
fn run_os_on_simple_block_cairo1(
    block_context: BlockContext,
    simple_block_cairo1: (StarknetOsInput, ExecutionHelperWrapper),
) {
    run_os_on_block(block_context, simple_block_cairo1);
}

#[rstest]
#[ignore]
fn run_os_on_cairo1_syscalls_block(
    block_context: BlockContext,
    cairo1_syscalls_block: (StarknetOsInput, ExecutionHelperWrapper),
) {
    run_os_on_block(block_context, cairo1_syscalls_block);
}
