use std::collections::{HashMap, HashSet};
use std::fs::{read_dir, File};
use std::io::BufReader;

use blockifier::execution::hint_code;
use serde::Deserialize;
use serde_json::Value;
use snos::hints::SnosHintProcessor;

const WHITELISTS_PATH: &str = "cairo-lang/src/starkware/starknet/security/whitelists";

#[derive(Deserialize)]
struct AllowedHintExpression {
    #[serde(rename(deserialize = "allowed_expressions"))]
    _allowed_expressions: Option<Value>,
    hint_lines: Vec<Box<str>>,
}

#[derive(Deserialize)]
struct Whitelist {
    #[serde(rename(deserialize = "allowed_reference_expressions_for_hint"))]
    allowed_hint_expressions: Vec<AllowedHintExpression>,
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
    let subset = std::env::args().nth(1).expect(
        "choose what you need: all, implemented, unimplemented, implemented_externally, implemented_in_snos, orphans",
    );

    // whitelisted hints
    let whitelist_paths = read_dir(WHITELISTS_PATH).expect("Failed to read whitelist directory");
    let mut whitelists = Vec::new();
    for path in whitelist_paths {
        let path = path.expect("Failed to get path").path();
        if path.to_str().unwrap_or_default().ends_with(".json") {
            let file = File::open(path).expect("Failed to open whitelist file");
            let mut reader = BufReader::new(file);

            let whitelist_file: Whitelist = serde_json::from_reader(&mut reader).expect("Failed to parse whitelist");
            whitelists.push(whitelist_file.allowed_hint_expressions);
        }
    }

    let whitelisted_hints =
        whitelists.into_iter().flatten().map(|ahe| ahe.hint_lines.join("\n")).collect::<HashSet<_>>();
    let snos_hints = SnosHintProcessor::default().hints();
    // let implemented_hints = whitelisted_hints.union(&snos_hints).collect::<HashSet<_>>();

    let mut result = HashSet::new();

    let os: Os = serde_json::from_reader(BufReader::new(File::open("build/os_latest.json")?))
        .expect("Failed to parse os_latest.json");
    let os_hints = os.hints.into_values().flatten().map(|h| h.code.to_string()).collect::<HashSet<_>>();
    let syscall_hints = hint_code::SYSCALL_HINTS.into_iter().map(|h| h.to_string()).collect::<HashSet<_>>();

    let externally_implemented = |code| whitelisted_hints.contains(code) && !syscall_hints.contains(code);

    if subset == "orphans" {
        for code in snos_hints.iter() {
            if !os_hints.contains(code) && !syscall_hints.contains(code) {
                result.insert(code);
            }
        }
    } else {
        for code in os_hints.union(&syscall_hints).collect::<HashSet<_>>() {
            if subset == "all"
                || subset == "implemented" && (snos_hints.contains(code) || externally_implemented(code))
                || subset == "unimplemented" && !(snos_hints.contains(code) || externally_implemented(code))
                || subset == "implemented_externally" && externally_implemented(code)
                || subset == "implemented_in_snos" && snos_hints.contains(code)
            {
                result.insert(code);
            }
        }
    }

    println!("{}", serde_json::to_string(&result)?);

    Ok(())
}
