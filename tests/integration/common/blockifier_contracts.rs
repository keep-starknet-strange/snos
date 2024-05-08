use std::path::Path;

use snos::starknet::services::api::contract_class::contract_class::DeprecatedCompiledClass;

use crate::common::contract_fixtures::get_deprecated_compiled_class;

pub fn get_deprecated_feature_contract_class(contract_name: &str) -> DeprecatedCompiledClass {
    let filename = format!("{contract_name}_compiled.json");
    let contract_rel_path =
        Path::new("blockifier_contracts").join("feature_contracts").join("cairo0").join("compiled").join(filename);
    get_deprecated_compiled_class(&contract_rel_path)
}

pub fn get_deprecated_erc20_contract_class() -> DeprecatedCompiledClass {
    let contract_rel_path = Path::new("blockifier_contracts")
        .join("ERC20_without_some_syscalls")
        .join("ERC20")
        .join("erc20_contract_without_some_syscalls_compiled.json");
    get_deprecated_compiled_class(&contract_rel_path)
}
