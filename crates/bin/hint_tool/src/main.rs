use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufReader, Write};
use std::path::PathBuf;

use blockifier::execution::hint_code;
use cairo_vm::any_box;
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::HintProcessorData;
use cairo_vm::hint_processor::hint_processor_definition::HintProcessorLogic;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachineBuilder;
use cairo_vm::vm::vm_memory::memory_segments::MemorySegmentManager;
use clap::Parser;
use serde::Deserialize;
use starknet_os::hints::SnosHintProcessor;
use starknet_os::storage::dict_storage::DictStorage;

#[derive(Clone, Copy, Debug, Default, clap::ValueEnum, PartialEq)]
enum HintFilter {
    Implemented,
    Unimplemented,
    ImplementedExternally,
    ImplementedLocally,
    Orphaned,
    #[default]
    All,
}

#[derive(Clone, Copy, Debug, Default, clap::ValueEnum, PartialEq)]
enum OutputType {
    /// Print a JSON Array of hints
    #[default]
    Json,

    /// Print the hints as Rust source code.
    /// This helps avoid whitespace issues when matching hint strings
    Rust,
}

#[derive(Parser, Debug)]
struct Args {
    /// Subset of hints to report
    #[arg(long)]
    subset: Option<HintFilter>,

    /// Output type
    #[arg(long)]
    out_type: Option<OutputType>,

    /// Output file to write matched hints to
    #[arg(long)]
    out_file: Option<PathBuf>,

    /// Input JSON file (e.g. "os_latest.json")
    #[arg(long)]
    #[clap(default_value = Some("../../build/os_latest.json"))]
    in_file: PathBuf,
}

#[derive(Deserialize)]
struct Hint {
    code: Box<str>,
}

#[derive(Deserialize)]
struct Os {
    hints: HashMap<String, Vec<Hint>>,
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let subset = args.subset.unwrap_or_default();

    let mut hint_processor = SnosHintProcessor::<DictStorage>::default();
    let snos_hints = hint_processor.hints();

    let mut result = Vec::new();

    let os: Os =
        serde_json::from_reader(BufReader::new(File::open(args.in_file)?)).expect("Failed to parse os_latest.json");
    let os_hints = os.hints.into_values().flatten().map(|h| h.code.to_string()).collect::<HashSet<_>>();
    let syscall_hints = hint_code::SYSCALL_HINTS.into_iter().map(|h| h.to_string()).collect::<HashSet<_>>();

    let segments = MemorySegmentManager::new();
    let mut vm = VirtualMachineBuilder::default().segments(segments).build();

    let mut known_to_hint_processor = |code: &String| {
        let r = hint_processor.execute_hint_extensive(
            &mut vm,
            &mut ExecutionScopes::new(),
            &any_box!(HintProcessorData::new_default(code.clone(), HashMap::new())),
            &HashMap::new(),
        );
        if let Err(HintError::UnknownHint(_)) = r {
            return false;
        }
        true
    };

    if subset == HintFilter::Orphaned {
        for code in snos_hints.iter() {
            if !os_hints.contains(code) && !syscall_hints.contains(code) {
                result.push(code);
            }
        }
    } else {
        for code in os_hints.union(&syscall_hints).collect::<HashSet<_>>() {
            let add = match subset {
                HintFilter::All => true,
                HintFilter::Implemented => known_to_hint_processor(code),
                HintFilter::Unimplemented => !known_to_hint_processor(code),
                HintFilter::ImplementedExternally => known_to_hint_processor(code) && !snos_hints.contains(code),
                HintFilter::ImplementedLocally => snos_hints.contains(code),
                _ => unreachable!(),
            };
            if add {
                result.push(code);
            }
        }
    }

    println!("Number of HintStatus::{:?} results: {}", subset, result.len());

    if let Some(filepath) = args.out_file {
        let buf = match args.out_type.unwrap_or_default() {
            OutputType::Json => serde_json::to_string(&result)?,
            OutputType::Rust => generate_hints_as_rust(&result),
        };
        let mut output = File::create(filepath)?;
        write!(output, "{}", buf.as_str())?;
    }

    Ok(())
}

fn generate_hints_as_rust(hints: &[&String]) -> String {
    let mut buf = String::new();
    for (count, hint) in hints.iter().enumerate() {
        buf.push_str(&format!("pub const HINT_{}", count));
        buf.push_str(": &str = indoc! {r#\"");
        buf.push_str(hint.as_str());
        buf.push_str("\"#};\n\n");
    }

    buf
}
