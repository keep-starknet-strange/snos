use std::path::Path;

use cairo_lang_starknet_classes::contract_class::ContractClass;
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedCompiledClass;

use crate::common::contract_fixtures::{get_compiled_sierra_class, get_deprecated_compiled_class};

pub fn get_deprecated_feature_contract_class(contract_name: &str) -> DeprecatedCompiledClass {
    let filename = format!("{contract_name}_compiled.json");
    let contract_rel_path =
        Path::new("blockifier_contracts").join("feature_contracts").join("cairo0").join("compiled").join(filename);
    log::debug!("Getting contract at {:?}", contract_rel_path);
    get_deprecated_compiled_class(&contract_rel_path)
}

pub fn get_deprecated_erc20_contract_class() -> DeprecatedCompiledClass {
    let contract_rel_path = Path::new("blockifier_contracts")
        .join("ERC20_without_some_syscalls")
        .join("ERC20")
        .join("erc20_contract_without_some_syscalls_compiled.json");
    get_deprecated_compiled_class(&contract_rel_path)
}

pub fn get_feature_sierra_contract_class(contract_name: &str) -> ContractClass {
    let filename = format!("{contract_name}.sierra");
    let contract_rel_path =
        Path::new("blockifier_contracts").join("feature_contracts").join("cairo1").join("compiled").join(filename);
    log::debug!("Getting contract at {:?}", contract_rel_path);
    get_compiled_sierra_class(&contract_rel_path)
}

/// Helper to load a Cairo 0 contract class.
pub fn load_cairo0_feature_contract(name: &str) -> (String, DeprecatedCompiledClass) {
    (name.to_string(), get_deprecated_feature_contract_class(name))
}
