use std::path::{Path, PathBuf};

use cairo_lang_starknet_classes::casm_contract_class::{CasmContractClass, StarknetSierraCompilationError};
use cairo_lang_starknet_classes::contract_class::ContractClass;
use starknet_os_types::casm_contract_class::GenericCasmContractClass;
use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;

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

pub fn get_deprecated_compiled_class(contract_rel_path: &Path) -> GenericDeprecatedCompiledClass {
    let content = read_contract(contract_rel_path);
    serde_json::from_slice(&content).unwrap_or_else(|e| panic!("Failed to load deprecated compiled class: {e}"))
}

pub fn get_compiled_sierra_class(contract_rel_path: &Path) -> ContractClass {
    let content = read_contract(contract_rel_path);
    serde_json::from_slice(&content).unwrap_or_else(|e| panic!("Failed to load deprecated compiled class: {e}"))
}

/// Compiles a Sierra class to CASM.
pub(crate) fn compile_sierra_contract_class(
    sierra_contract_class: ContractClass,
) -> Result<GenericCasmContractClass, StarknetSierraCompilationError> {
    // Values taken from the defaults of `starknet-sierra-compile`, see here:
    // https://github.com/starkware-libs/cairo/blob/main/crates/bin/starknet-sierra-compile/src/main.rs
    let add_pythonic_hints = false;
    let max_bytecode_size = 180000;
    let casm_contract_class =
        CasmContractClass::from_contract_class(sierra_contract_class, add_pythonic_hints, max_bytecode_size)?;

    Ok(GenericCasmContractClass::from(casm_contract_class))
}

/// Helper to load a Cairo1 contract class.
pub(crate) fn load_cairo1_contract(contract_path: &Path) -> (ContractClass, GenericCasmContractClass) {
    let sierra_contract_class = get_compiled_sierra_class(contract_path);
    let casm_contract_class = compile_sierra_contract_class(sierra_contract_class.clone())
        .unwrap_or_else(|e| panic!("Failed to compile Sierra contract {}: {}", contract_path.to_string_lossy(), e));
    (sierra_contract_class, casm_contract_class)
}
