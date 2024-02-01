use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::BufReader;

use blockifier::execution::hint_code;
use cairo_vm::any_box;
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::HintProcessorData;
use cairo_vm::hint_processor::hint_processor_definition::HintProcessorLogic;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachineBuilder;
use cairo_vm::vm::vm_memory::memory_segments::MemorySegmentManager;
use serde::Deserialize;
use snos::hints::SnosHintProcessor;

#[derive(Deserialize)]
struct Hint {
    code: Box<str>,
}

#[derive(Deserialize)]
struct Os {
    hints: HashMap<String, Vec<Hint>>,
}

fn main() -> std::io::Result<()> {
    let subset = std::env::args().nth(1).expect(
        "choose what you need: all, implemented, unimplemented, implemented_externally, implemented_in_snos, orphans",
    );

    let mut hint_processor = SnosHintProcessor::default();
    let snos_hints = hint_processor.hints();

    let mut result = HashSet::new();

    let os: Os = serde_json::from_reader(BufReader::new(File::open("build/os_latest.json")?))
        .expect("Failed to parse os_latest.json");
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
        if let Err(e) = r {
            if let HintError::UnknownHint(_) = e {
                return false;
            }
        }
        true
    };

    if subset == "orphans" {
        for code in snos_hints.iter() {
            if !os_hints.contains(code) && !syscall_hints.contains(code) {
                result.insert(code);
            }
        }
    } else {
        for code in os_hints.union(&syscall_hints).collect::<HashSet<_>>() {
            if subset == "all"
                || subset == "implemented" && known_to_hint_processor(code)
                || subset == "unimplemented" && !known_to_hint_processor(code)
                || subset == "implemented_externally" && (known_to_hint_processor(code) && !snos_hints.contains(code))
                || subset == "implemented_in_snos" && snos_hints.contains(code)
            {
                result.insert(code);
            }
        }
    }

    println!("{}", serde_json::to_string(&result)?);

    Ok(())
}
