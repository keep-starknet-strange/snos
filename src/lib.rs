pub mod error;
pub mod hints;
pub mod storage;
pub mod pie;
pub mod os_input;

use error::SnOsError;
use std::fs;
use std::path::PathBuf;

use cairo_vm::cairo_run::{cairo_run, CairoRunConfig};

pub struct SnOsRunner {
    layout: String,
    os_path: PathBuf,
}

impl SnOsRunner {
    pub fn new(layout: String, os_path: PathBuf) -> Self {
        Self { layout, os_path }
    }

    pub fn run(&self) -> Result<(), SnOsError> {
        let mut sn_hint_processor = hints::sn_hint_processor();

        // Load the Starknet OS
        let starknet_os = fs::read_to_string(self.os_path.as_path())
            .map_err(|e| SnOsError::CatchAll(format!("{e}")))?;

        println!("Running the OS");

        let _run_output = cairo_run(
            starknet_os.as_bytes(),
            &CairoRunConfig {
                layout: self.layout.as_str(),
                relocate_mem: true,
                trace_enabled: true,
                ..Default::default()
            },
            &mut sn_hint_processor,
        )
        .expect("Couldn't run program");

        println!("successful run...");

        Ok(())
    }
}

impl Default for SnOsRunner {
    fn default() -> Self {
        Self {
            layout: "starknet_with_keccak".to_string(),
            os_path: PathBuf::from("build/os_compiled.json"),
        }
    }
}
