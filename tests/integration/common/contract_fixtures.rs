use std::path::{Path, PathBuf};

use cairo_lang_starknet_classes::contract_class::ContractClass;
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedCompiledClass;

pub fn get_contracts_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("integration").join("contracts")
}

fn read_contract(contract_rel_path: &Path) -> Vec<u8> {
    // Keep using Blockifier fixtures for now.
    let contracts_dir = get_contracts_dir();
    let contract_path = contracts_dir.join(contract_rel_path);

    std::fs::read(&contract_path).unwrap_or_else(|e| {
        panic!("Failed to read fixture {}: {e}", contract_path.to_string_lossy().as_ref());
    })
}

pub fn get_deprecated_compiled_class(contract_rel_path: &Path) -> DeprecatedCompiledClass {
    let content = read_contract(contract_rel_path);
    serde_json::from_slice(&content).unwrap_or_else(|e| panic!("Failed to load deprecated compiled class: {e}"))
}

pub fn get_compiled_sierra_class(contract_rel_path: &Path) -> ContractClass {
    let content = read_contract(contract_rel_path);
    serde_json::from_slice(&content).unwrap_or_else(|e| panic!("Failed to load deprecated compiled class: {e}"))
}
