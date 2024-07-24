use std::path::Path;

use starknet_api::deprecated_contract_class::ContractClass as DeprecatedCompiledClass;

use crate::common::contract_fixtures::get_deprecated_compiled_class;

fn get_deprecated_os_itest_contract_class(contract_name: &str) -> DeprecatedCompiledClass {
    let filename = format!("{contract_name}_compiled.json");
    let contract_rel_path = Path::new("os_itest_contracts").join("compiled").join(filename);
    log::debug!("Getting contract at {:?}", contract_rel_path);
    get_deprecated_compiled_class(&contract_rel_path)
}

/// Helper to load a Cairo 0 contract class.
pub fn load_os_itest_contract(name: &str) -> (String, DeprecatedCompiledClass) {
    (name.to_string(), get_deprecated_os_itest_contract_class(name))
}
