use std::collections::HashSet;
use std::fs::File;
use std::io::Read;

use serde_json::Value;
use snos::hints::sn_hint_processor;

fn main() -> std::io::Result<()> {
    let subset = std::env::args().nth(1).expect("choose what you need: all, implemented, unimplemented");

    let implemented_hints = sn_hint_processor().extra_hints;
    let mut result = HashSet::new();

    let mut file = File::open("build/os_latest.json")?;
    let mut data = String::new();
    let _ = file.read_to_string(&mut data);
    let json: Value = serde_json::from_str(&data)?;
    let hints = json.get("hints").unwrap().as_object();
    for (_, hint_value) in hints.unwrap() {
        for hint in hint_value.as_array().unwrap() {
            let code = hint.get("code").unwrap().as_str().unwrap();
            if subset == "all"
                || subset == "implemented" && implemented_hints.contains_key(code)
                || subset == "unimplemented" && !implemented_hints.contains_key(code)
            {
                result.insert(code);
            }
        }
    }

    println!("{}", serde_json::to_string(&result)?);

    Ok(())
}
