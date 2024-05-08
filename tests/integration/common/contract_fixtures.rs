use std::path::{Path, PathBuf};

use snos::starknet::services::api::contract_class::contract_class::DeprecatedCompiledClass;

pub fn get_contracts_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("integration").join("contracts")
}

pub fn get_deprecated_compiled_class(contract_rel_path: &Path) -> DeprecatedCompiledClass {
    // Keep using Blockifier fixtures for now.
    let contracts_dir = get_contracts_dir();
    let contract_path = contracts_dir.join(contract_rel_path);

    let content = std::fs::read(&contract_path).unwrap_or_else(|e| {
        panic!("Failed to read fixture {}: {e}", contract_path.to_string_lossy().as_ref());
    });

    serde_json::from_slice(&content).unwrap_or_else(|e| panic!("Failed to load deprecated compiled class: {e}"))
}
