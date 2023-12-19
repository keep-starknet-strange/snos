use std::collections::{HashMap, HashSet};
use std::fs::{read_dir, File};
use std::io::BufReader;

use serde::Deserialize;
use serde_json::Value;
use snos::hints::sn_hint_processor;

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
    let subset = std::env::args()
        .nth(1)
        .expect("choose what you need: all, implemented, unimplemented, whitelisted, snos, orphans");

    // whitelisted hints implemented by the vm
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
    let snos_hints = sn_hint_processor().extra_hints.keys().cloned().collect::<HashSet<_>>();
    let implemented_hints = whitelisted_hints.union(&snos_hints).collect::<HashSet<_>>();

    let mut result = HashSet::new();

    let os: Os = serde_json::from_reader(BufReader::new(File::open("build/os_latest.json")?))
        .expect("Failed to parse os_latest.json");
    let hints = os.hints.into_values().flatten().map(|h| h.code.to_string()).collect::<HashSet<_>>();

    if subset == "orphans" {
        for code in snos_hints {
            if !hints.contains(&code) {
                result.insert(code);
            }
        }
    } else {
        for code in hints {
            if subset == "all"
                || subset == "implemented" && implemented_hints.contains(&code)
                || subset == "unimplemented" && !implemented_hints.contains(&code)
                || subset == "whitelisted" && whitelisted_hints.contains(&code)
                || subset == "snos" && snos_hints.contains(&code)
            {
                result.insert(code);
            }
        }
    }

    println!("{}", serde_json::to_string(&result)?);

    Ok(())
}
