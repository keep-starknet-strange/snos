use cairo_vm::cairo_run::CairoRunConfig;
use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::types::program::Program;
use cairo_vm::vm::errors::vm_exception::VmException;
use cairo_vm::vm::runners::cairo_runner::CairoRunner;
use cairo_vm::Felt252;
use clap::Parser;
use starknet_os::error::SnOsError;
use starknet_os::hints;
use starknet_os::starknet::starknet_storage::{CommitmentInfo, CommitmentInfoError, PerContractStorage};
use starknet_os::starkware_utils::commitment_tree::base_types::TreeIndex;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    input: String,
}

fn init_logging() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        .format_timestamp(None)
        .try_init()
        .expect("Failed to configure env_logger");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logging();

    let args = Args::parse();

    let program_bytes = std::fs::read_to_string(args.input).expect("Failed to read input file");

    let layout = LayoutName::all_cairo;

    // Init CairoRunConfig
    let cairo_run_config = CairoRunConfig { layout, relocate_mem: true, trace_enabled: true, ..Default::default() };
    let allow_missing_builtins = cairo_run_config.allow_missing_builtins.unwrap_or(false);

    // Load the Starknet OS Program
    let program = Program::from_bytes(program_bytes.as_bytes(), Some(cairo_run_config.entrypoint))
        .map_err(|e| SnOsError::Runner(e.into()))?;

    // Init cairo runner
    let mut cairo_runner = CairoRunner::new(
        &program,
        cairo_run_config.layout,
        cairo_run_config.proof_mode,
        cairo_run_config.trace_enabled,
    )
    .map_err(|e| SnOsError::Runner(e.into()))?;

    // Init the Cairo VM
    let end = cairo_runner.initialize(allow_missing_builtins).map_err(|e| SnOsError::Runner(e.into()))?;

    // Run the Cairo VM
    let mut hint_processor = hints::SnosHintProcessor::<DummyPCS>::default();
    cairo_runner
        .run_until_pc(end, &mut hint_processor)
        .map_err(|err| VmException::from_vm_error(&cairo_runner, err))
        .map_err(|e| SnOsError::Runner(e.into()))?;

    // End the Cairo VM run
    cairo_runner
        .end_run(cairo_run_config.disable_trace_padding, false, &mut hint_processor)
        .map_err(|e| SnOsError::Runner(e.into()))?;

    if cairo_run_config.proof_mode {
        cairo_runner.finalize_segments().map_err(|e| SnOsError::Runner(e.into()))?;
    }

    Ok(())
}

struct DummyPCS {}

impl PerContractStorage for DummyPCS {
    async fn compute_commitment(&mut self) -> Result<CommitmentInfo, CommitmentInfoError> {
        unimplemented!();
    }
    async fn read(&mut self, _key: TreeIndex) -> Option<Felt252> {
        unimplemented!();
    }
    fn write(&mut self, _key: TreeIndex, _value: Felt252) {
        unimplemented!();
    }
}
