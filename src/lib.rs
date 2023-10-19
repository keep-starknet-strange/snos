pub mod config;
pub mod error;
pub mod hints;
pub mod io;
pub mod sharp;
pub mod state;
pub mod utils;

use core::panic;
use std::fs;

use blockifier::block_context::BlockContext;
use blockifier::state::state_api::StateReader;
use cairo_felt::Felt252;
use cairo_vm::cairo_run::CairoRunConfig;
use cairo_vm::types::program::Program;
use cairo_vm::types::relocatable::MaybeRelocatable;
use cairo_vm::vm::errors::vm_exception::VmException;
use cairo_vm::vm::runners::builtin_runner::BuiltinRunner;
use cairo_vm::vm::runners::cairo_pie::CairoPie;
use cairo_vm::vm::runners::cairo_runner::CairoRunner;
use cairo_vm::vm::vm_core::VirtualMachine;
use config::StarknetGeneralConfig;
use error::SnOsError;
use state::SharedState;

use crate::io::StarknetOsOutput;

pub struct SnOsRunner {
    layout: String,
    os_path: String,
    input_path: String,
    pub block_context: BlockContext,
}

impl SnOsRunner {
    pub fn with_layout(layout: &str) -> Self {
        Self { layout: layout.to_string(), ..Self::default() }
    }

    pub fn with_os_path(os_path: &str) -> Self {
        Self { os_path: os_path.to_string(), ..Self::default() }
    }

    pub fn with_input_path(input_path: &str) -> Self {
        Self { input_path: input_path.to_string(), ..Self::default() }
    }

    pub fn with_block_context(block_context: BlockContext) -> Self {
        Self { block_context, ..Self::default() }
    }

    pub fn run(&self, shared_state: SharedState<impl StateReader>) -> Result<CairoPie, SnOsError> {
        // Init CairoRunConfig
        let cairo_run_config = CairoRunConfig {
            layout: self.layout.as_str(),
            relocate_mem: true,
            trace_enabled: true,
            ..Default::default()
        };

        // Load the Starknet OS Program
        let starknet_os = fs::read(&self.os_path).map_err(|e| SnOsError::CatchAll(format!("{e}")))?;
        let program = Program::from_bytes(&starknet_os, Some(cairo_run_config.entrypoint))
            .map_err(|e| SnOsError::Runner(e.into()))?;

        // Init cairo runner
        let mut cairo_runner = CairoRunner::new(&program, cairo_run_config.layout, cairo_run_config.proof_mode)
            .map_err(|e| SnOsError::Runner(e.into()))?;

        // Init the Cairo VM
        let mut vm = VirtualMachine::new(cairo_run_config.trace_enabled);
        let end = cairo_runner.initialize(&mut vm).map_err(|e| SnOsError::Runner(e.into()))?;
        cairo_runner.exec_scopes.insert_value("input_path", self.input_path.clone());
        cairo_runner.exec_scopes.insert_box("block_context", Box::new(shared_state.block_context));

        // Run the Cairo VM
        let mut sn_hint_processor = hints::sn_hint_processor();
        cairo_runner
            .run_until_pc(end, &mut vm, &mut sn_hint_processor)
            .map_err(|err| VmException::from_vm_error(&cairo_runner, &vm, err))
            .map_err(|e| SnOsError::Runner(e.into()))?;
        cairo_runner
            .end_run(cairo_run_config.disable_trace_padding, false, &mut vm, &mut sn_hint_processor)
            .map_err(|e| SnOsError::Runner(e.into()))?;

        if cairo_run_config.proof_mode {
            cairo_runner.finalize_segments(&mut vm).map_err(|e| SnOsError::Runner(e.into()))?;
        }

        // Prepare and check expected output.
        // os_output = runner.vm_memory.get_range_as_ints(
        //     addr=runner.output_builtin.base, size=builtin_end_ptrs[0] - runner.output_builtin.base
        // )
        let builtin_end_ptrs = vm.get_return_values(8).map_err(|e| SnOsError::CatchAll(e.to_string()))?;
        let output_base = vm
            .get_builtin_runners()
            .iter()
            .find(|&elt| matches!(elt, BuiltinRunner::Output(_)))
            .expect("Os vm should have the output builtin")
            .base();
        let size_bound_up = match builtin_end_ptrs.last().unwrap() {
            MaybeRelocatable::Int(val) => val,
            _ => panic!("Value should be an int"),
        };
        // Get is input and check that everything is an integer.
        let os_output = vm.get_range(
            (output_base as isize, 0).into(),
            <usize>::from_be_bytes((size_bound_up.clone() - output_base).to_be_bytes()[..8].try_into().unwrap()),
        );
        let os_output: Vec<Felt252> = os_output
            .iter()
            .map(|x| {
                if let MaybeRelocatable::Int(val) = x.clone().unwrap().into_owned() {
                    val
                } else {
                    panic!("Output should be all integers")
                }
            })
            .collect();
        let prev_state_root = os_output[0].clone();
        let new_state_root = os_output[1].clone();
        let block_number = os_output[2].clone();
        let block_hash = os_output[3].clone();
        let config_hash = os_output[4].clone();
        let os_output = &os_output[5..];
        let messages_to_l1_size = <usize>::from_be_bytes(os_output[0].to_be_bytes()[..8].try_into().unwrap());
        let messages_to_l1 = os_output[1..messages_to_l1_size].to_vec();

        let os_output = &os_output[messages_to_l1_size + 1..];
        let messages_to_l2 =
            os_output[1..<usize>::from_be_bytes(os_output[0].to_be_bytes()[..8].try_into().unwrap())].to_vec();
        StarknetOsOutput::new(
            prev_state_root,
            new_state_root,
            block_number,
            block_hash,
            config_hash,
            messages_to_l1,
            messages_to_l2,
        );

        vm.verify_auto_deductions().map_err(|e| SnOsError::Runner(e.into()))?;
        cairo_runner.read_return_values(&mut vm).map_err(|e| SnOsError::Runner(e.into()))?;
        cairo_runner.relocate(&mut vm, cairo_run_config.relocate_mem).map_err(|e| SnOsError::Runner(e.into()))?;

        // Parse the Cairo VM output
        let pie = cairo_runner.get_cairo_pie(&vm).map_err(|e| SnOsError::PieParsing(format!("{e}")))?;

        Ok(pie)
    }
}

impl Default for SnOsRunner {
    fn default() -> Self {
        Self {
            layout: config::DEFAULT_LAYOUT.to_string(),
            os_path: config::DEFAULT_COMPILED_OS.to_string(),
            input_path: config::DEFAULT_INPUT_PATH.to_string(),
            block_context: StarknetGeneralConfig::default().empty_block_context(),
        }
    }
}
