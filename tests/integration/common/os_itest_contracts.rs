use std::path::{Path, PathBuf};

use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;

use crate::common::contract_fixtures::get_deprecated_compiled_class;

fn get_deprecated_os_itest_contract_path(contract_name: &str) -> PathBuf {
    let filename = format!("{contract_name}_compiled.json");
    Path::new("os_itest_contracts").join("compiled").join(filename)
}

/// Helper to load a Cairo 0 contract class.
pub fn load_os_itest_contract(name: &str) -> (String, GenericDeprecatedCompiledClass) {
    let contract_path = get_deprecated_os_itest_contract_path(name);
    (name.to_string(), get_deprecated_compiled_class(&contract_path))
}
