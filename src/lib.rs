#![feature(async_fn_in_trait)]

pub mod error;
pub mod hints;
pub mod os_input;
pub mod sharp;
pub mod storage;
pub mod utils;

use error::SnOsError;
use std::fs;
use std::path::PathBuf;

use cairo_vm::cairo_run::{cairo_run, CairoRunConfig};
use cairo_vm::vm::runners::cairo_pie::CairoPie;

pub struct SnOsRunner {
    layout: String,
    os_path: PathBuf,
}

impl SnOsRunner {
    pub fn new(layout: String, os_path: PathBuf) -> Self {
        Self { layout, os_path }
    }

    pub fn run(&self) -> Result<CairoPie, SnOsError> {
        let mut sn_hint_processor = hints::sn_hint_processor();

        // Load the Starknet OS
        let starknet_os = fs::read_to_string(self.os_path.as_path())
            .map_err(|e| SnOsError::CatchAll(format!("{e}")))?;

        let (runner, vm) = cairo_run(
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

        let pie = runner
            .get_cairo_pie(&vm)
            .map_err(|e| SnOsError::PieParsing(format!("{e}")))?;

        // TODO: also return program output
        Ok(pie)
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
