use std::cell::OnceCell;
use std::rc::Rc;

use pathfinder_gateway_types::class_hash::compute_class_hash;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::casm_contract_class::{CairoLangCasmClass, GenericCasmContractClass};
use crate::error::ContractClassError;
use crate::hash::GenericClassHash;

pub type CairoLangSierraContractClass = cairo_lang_starknet_classes::contract_class::ContractClass;
pub type StarknetCoreSierraContractClass = starknet_core::types::FlattenedSierraClass;

/// A generic Sierra contract class that supports conversion to/from the most commonly used
/// contract class types in Starknet and provides utility methods.
/// Operations are implemented as lazily as possible, i.e. we only convert
/// between different types if strictly necessary.
/// Fields are boxed in an RC for cheap cloning.
#[derive(Debug, Clone)]
pub struct GenericSierraContractClass {
    cairo_lang_contract_class: OnceCell<Rc<CairoLangSierraContractClass>>,
    starknet_core_contract_class: OnceCell<Rc<StarknetCoreSierraContractClass>>,
    serialized_class: OnceCell<Vec<u8>>,
    class_hash: OnceCell<GenericClassHash>,
}

impl GenericSierraContractClass {
    pub fn from_bytes(serialized_class: Vec<u8>) -> Self {
        Self {
            cairo_lang_contract_class: Default::default(),
            starknet_core_contract_class: Default::default(),
            serialized_class: OnceCell::from(serialized_class),
            class_hash: OnceCell::new(),
        }
    }

    fn build_cairo_lang_class(&self) -> Result<CairoLangSierraContractClass, ContractClassError> {
        if let Some(serialized_class) = self.serialized_class.get() {
            let contract_class = serde_json::from_slice(serialized_class)?;
            return Ok(contract_class);
        }

        Err(ContractClassError::NoPossibleConversion)
    }

    pub fn get_serialized_contract_class(&self) -> Result<&Vec<u8>, ContractClassError> {
        self.serialized_class.get_or_try_init(|| serde_json::to_vec(self)).map_err(Into::into)
    }

    fn build_starknet_core_class(&self) -> Result<StarknetCoreSierraContractClass, ContractClassError> {
        let serialized_class = self.get_serialized_contract_class()?;
        serde_json::from_slice(serialized_class).map_err(Into::into)
    }
    pub fn get_cairo_lang_contract_class(&self) -> Result<&CairoLangSierraContractClass, ContractClassError> {
        self.cairo_lang_contract_class
            .get_or_try_init(|| self.build_cairo_lang_class().map(Rc::new))
            .map(|boxed| boxed.as_ref())
    }

    pub fn get_starknet_core_contract_class(&self) -> Result<&StarknetCoreSierraContractClass, ContractClassError> {
        self.starknet_core_contract_class
            .get_or_try_init(|| self.build_starknet_core_class().map(Rc::new))
            .map(|boxed| boxed.as_ref())
    }

    pub fn to_cairo_lang_contract_class(self) -> Result<CairoLangSierraContractClass, ContractClassError> {
        let cairo_lang_class = self.get_cairo_lang_contract_class()?;
        Ok(cairo_lang_class.clone())
    }

    pub fn to_starknet_core_contract_class(self) -> Result<StarknetCoreSierraContractClass, ContractClassError> {
        let blockifier_class = self.get_starknet_core_contract_class()?;
        Ok(blockifier_class.clone())
    }

    fn compute_class_hash(&self) -> Result<GenericClassHash, ContractClassError> {
        let serialized_class = self.get_serialized_contract_class()?;
        let class_hash =
            compute_class_hash(serialized_class).map_err(|e| ContractClassError::HashError(e.to_string()))?;

        Ok(GenericClassHash::from_bytes_be(class_hash.hash().0.to_be_bytes()))
    }

    pub fn class_hash(&self) -> Result<GenericClassHash, ContractClassError> {
        self.class_hash.get_or_try_init(|| self.compute_class_hash()).copied()
    }

    pub fn compile(&self) -> Result<GenericCasmContractClass, ContractClassError> {
        let cairo_lang_class = self.get_cairo_lang_contract_class()?.clone();
        // Values taken from the defaults of `starknet-sierra-compile`, see here:
        // https://github.com/starkware-libs/cairo/blob/main/crates/bin/starknet-sierra-compile/src/main.rs
        let add_pythonic_hints = false;
        let max_bytecode_size = 180000;
        let casm_contract_class =
            CairoLangCasmClass::from_contract_class(cairo_lang_class, add_pythonic_hints, max_bytecode_size)?;

        Ok(GenericCasmContractClass::from(casm_contract_class))
    }
}

impl Serialize for GenericSierraContractClass {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // It seems like there is no way to just pass the `serialized_class` field as the output
        // of `serialize()`, so we are forced to serialize an actual class instance.
        let cairo_lang_class =
            self.get_cairo_lang_contract_class().map_err(|e| serde::ser::Error::custom(e.to_string()))?;
        cairo_lang_class.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for GenericSierraContractClass {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let cairo_lang_class = CairoLangSierraContractClass::deserialize(deserializer)?;
        Ok(Self::from(cairo_lang_class))
    }
}

impl From<CairoLangSierraContractClass> for GenericSierraContractClass {
    fn from(cairo_lang_class: CairoLangSierraContractClass) -> Self {
        Self {
            cairo_lang_contract_class: OnceCell::from(Rc::new(cairo_lang_class)),
            starknet_core_contract_class: Default::default(),
            serialized_class: Default::default(),
            class_hash: Default::default(),
        }
    }
}

impl From<StarknetCoreSierraContractClass> for GenericSierraContractClass {
    fn from(starknet_core_class: StarknetCoreSierraContractClass) -> Self {
        Self {
            cairo_lang_contract_class: Default::default(),
            starknet_core_contract_class: OnceCell::from(Rc::new(starknet_core_class)),
            serialized_class: Default::default(),
            class_hash: Default::default(),
        }
    }
}

impl TryFrom<GenericSierraContractClass> for StarknetCoreSierraContractClass {
    type Error = ContractClassError;

    fn try_from(contract_class: GenericSierraContractClass) -> Result<Self, Self::Error> {
        contract_class.to_starknet_core_contract_class()
    }
}
