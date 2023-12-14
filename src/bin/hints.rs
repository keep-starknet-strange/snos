use std::collections::HashSet;
use std::fs::{read_dir, File};
use std::io::{BufReader, Read};

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

fn main() -> std::io::Result<()> {
    let subset = std::env::args().nth(1).expect("choose what you need: all, implemented, unimplemented");

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

    let mut file = File::open("build/os_latest.json")?;
    let mut data = String::new();
    let _ = file.read_to_string(&mut data);
    let json: Value = serde_json::from_str(&data)?;
    let hints = json.get("hints").unwrap().as_object();
    for (_, hint_value) in hints.unwrap() {
        for hint in hint_value.as_array().unwrap() {
            let code = hint.get("code").unwrap().as_str().unwrap().to_string();
            if subset == "all"
                || subset == "implemented" && implemented_hints.contains(&code)
                || subset == "unimplemented" && !implemented_hints.contains(&code)
            {
                result.insert(code);
            }
        }
    }

    println!("{}", serde_json::to_string(&result)?);

    Ok(())
}
