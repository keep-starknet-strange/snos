use std::path::{Path, PathBuf};

use cairo_lang_starknet_classes::contract_class::ContractClass;
use starknet_os_types::casm_contract_class::GenericCasmContractClass;
use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;

use crate::common::contract_fixtures::{get_deprecated_compiled_class, load_cairo1_contract};

fn get_deprecated_feature_contract_path(contract_name: &str) -> PathBuf {
    let filename = format!("{contract_name}_compiled.json");
    Path::new("blockifier_contracts").join("feature_contracts").join("cairo0").join("compiled").join(filename)
}

pub fn get_deprecated_erc20_contract_class() -> GenericDeprecatedCompiledClass {
    let contract_rel_path = Path::new("blockifier_contracts")
        .join("ERC20_without_some_syscalls")
        .join("ERC20")
        .join("erc20_contract_without_some_syscalls_compiled.json");
    get_deprecated_compiled_class(&contract_rel_path)
}

fn get_feature_sierra_contract_path(contract_name: &str) -> PathBuf {
    let filename = format!("{contract_name}.sierra");
    Path::new("blockifier_contracts").join("feature_contracts").join("cairo1").join("compiled").join(filename)
}

/// Helper to load a Cairo 0 contract class.
pub(crate) fn load_cairo0_feature_contract(name: &str) -> (String, GenericDeprecatedCompiledClass) {
    let contract_path = get_deprecated_feature_contract_path(name);
    let compiled_class = get_deprecated_compiled_class(&contract_path);
    (name.to_string(), compiled_class)
}

/// Helper to load a Cairo1 contract class.
pub(crate) fn load_cairo1_feature_contract(name: &str) -> (String, ContractClass, GenericCasmContractClass) {
    let sierra_contract_path = get_feature_sierra_contract_path(name);
    let (sierra_contract_class, casm_contract_class) = load_cairo1_contract(&sierra_contract_path);
    (name.to_string(), sierra_contract_class, casm_contract_class)
}
