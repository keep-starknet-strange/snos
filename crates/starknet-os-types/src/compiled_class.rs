use crate::casm_contract_class::GenericCasmContractClass;
use crate::deprecated_compiled_class::GenericDeprecatedCompiledClass;
use crate::error::ContractClassError;
use crate::hash::GenericClassHash;

/// A generic compiled class encapsulating Cairo 0 or Cairo 1 classes.
#[derive(Clone)]
pub enum GenericCompiledClass {
    Cairo0(GenericDeprecatedCompiledClass),
    Cairo1(GenericCasmContractClass),
}

impl GenericCompiledClass {
    pub fn class_hash(&self) -> Result<GenericClassHash, ContractClassError> {
        match self {
            GenericCompiledClass::Cairo0(deprecated_class) => deprecated_class.class_hash(),
            GenericCompiledClass::Cairo1(casm_class) => casm_class.class_hash(),
        }
    }
}
