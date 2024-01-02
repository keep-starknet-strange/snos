pub mod config;
pub mod error;
pub mod hints;
pub mod io;
pub mod sharp;
pub mod state;
pub mod utils;

use std::fs;

use blockifier::block_context::BlockContext;
use blockifier::state::state_api::StateReader;
use blockifier::transaction::objects::TransactionExecutionInfo;
use cairo_vm::cairo_run::CairoRunConfig;
use cairo_vm::types::program::Program;
use cairo_vm::vm::errors::vm_exception::VmException;
use cairo_vm::vm::runners::cairo_pie::CairoPie;
use cairo_vm::vm::runners::cairo_runner::CairoRunner;
use cairo_vm::vm::vm_core::VirtualMachine;
use config::StarknetGeneralConfig;
use error::SnOsError;
use io::output::StarknetOsOutput;
use state::SharedState;

pub struct SnOsRunner {
    layout: String,
    os_path: String,
    input_path: String,
    pub block_context: BlockContext,
}

impl SnOsRunner {
    pub fn run(
        &self,
        shared_state: SharedState<impl StateReader>,
        _execution_infos: Vec<TransactionExecutionInfo>,
    ) -> Result<CairoPie, SnOsError> {
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
        let mut sn_hint_processor = hints::SnosHintProcessor::default();
        cairo_runner
            .run_until_pc(end, &mut vm, &mut sn_hint_processor)
            .map_err(|err| VmException::from_vm_error(&cairo_runner, &vm, err))
            .map_err(|e| SnOsError::Runner(e.into()))?;

        // End the Cairo VM run
        cairo_runner
            .end_run(cairo_run_config.disable_trace_padding, false, &mut vm, &mut sn_hint_processor)
            .map_err(|e| SnOsError::Runner(e.into()))?;

        if cairo_run_config.proof_mode {
            cairo_runner.finalize_segments(&mut vm).map_err(|e| SnOsError::Runner(e.into()))?;
        }

        // Prepare and check expected output.
        let _os_output = StarknetOsOutput::from_run(&vm)?;

        println!("{:?}", _os_output);

        vm.verify_auto_deductions().map_err(|e| SnOsError::Runner(e.into()))?;
        cairo_runner.read_return_values(&mut vm).map_err(|e| SnOsError::Runner(e.into()))?;
        cairo_runner.relocate(&mut vm, cairo_run_config.relocate_mem).map_err(|e| SnOsError::Runner(e.into()))?;

        // Parse the Cairo VM output
        let pie = cairo_runner.get_cairo_pie(&vm).map_err(|e| SnOsError::PieParsing(format!("{e}")))?;

        Ok(pie)
    }

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
