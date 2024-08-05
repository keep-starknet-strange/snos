use std::cell::OnceCell;
use std::rc::Rc;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::ContractClassError;
use crate::hash::GenericClassHash;

pub type CairoLangCasmClass = cairo_lang_starknet_classes::casm_contract_class::CasmContractClass;
pub type BlockifierCasmClass = blockifier::execution::contract_class::ContractClassV1;

/// A generic contract class that supports conversion to/from the most commonly used
/// contract class types in Starknet and provides utility methods.
/// Operations are implemented as lazily as possible, i.e. we only convert
/// between different types if strictly necessary.
/// Fields are boxed in an RC for cheap cloning.
#[derive(Debug, Clone)]
pub struct GenericCasmContractClass {
    blockifier_contract_class: OnceCell<Rc<BlockifierCasmClass>>,
    cairo_lang_contract_class: OnceCell<Rc<CairoLangCasmClass>>,
    serialized_class: OnceCell<Rc<Vec<u8>>>,
    class_hash: OnceCell<GenericClassHash>,
}

fn blockifier_contract_class_from_cairo_lang_class(
    cairo_lang_class: CairoLangCasmClass,
) -> Result<BlockifierCasmClass, ContractClassError> {
    let blockifier_class: BlockifierCasmClass =
        cairo_lang_class.try_into().map_err(|_| ContractClassError::BlockifierConversionError)?;
    Ok(blockifier_class)
}

fn cairo_lang_contract_class_from_bytes(bytes: &[u8]) -> Result<CairoLangCasmClass, ContractClassError> {
    let contract_class = serde_json::from_slice(bytes)?;
    Ok(contract_class)
}

impl GenericCasmContractClass {
    pub fn from_bytes(serialized_class: Vec<u8>) -> Self {
        Self {
            blockifier_contract_class: OnceCell::new(),
            cairo_lang_contract_class: OnceCell::new(),
            serialized_class: OnceCell::from(Rc::new(serialized_class)),
            class_hash: OnceCell::new(),
        }
    }

    fn build_cairo_lang_class(&self) -> Result<CairoLangCasmClass, ContractClassError> {
        if let Some(serialized_class) = self.serialized_class.get() {
            let contract_class = serde_json::from_slice(serialized_class)?;
            return Ok(contract_class);
        }

        Err(ContractClassError::NoPossibleConversion)
    }

    fn build_blockifier_class(&self) -> Result<BlockifierCasmClass, ContractClassError> {
        if let Some(cairo_lang_class) = self.cairo_lang_contract_class.get() {
            return blockifier_contract_class_from_cairo_lang_class(cairo_lang_class.as_ref().clone());
        }

        if let Some(serialized_class) = &self.serialized_class.get() {
            let cairo_lang_class = cairo_lang_contract_class_from_bytes(serialized_class)?;
            self.cairo_lang_contract_class
                .set(Rc::new(cairo_lang_class.clone()))
                .expect("cairo-lang class is already set");
            return blockifier_contract_class_from_cairo_lang_class(cairo_lang_class);
        }

        Err(ContractClassError::NoPossibleConversion)
    }
    pub fn get_cairo_lang_contract_class(&self) -> Result<&CairoLangCasmClass, ContractClassError> {
        self.cairo_lang_contract_class
            .get_or_try_init(|| self.build_cairo_lang_class().map(Rc::new))
            .map(|boxed| boxed.as_ref())
    }

    pub fn get_blockifier_contract_class(&self) -> Result<&BlockifierCasmClass, ContractClassError> {
        self.blockifier_contract_class
            .get_or_try_init(|| self.build_blockifier_class().map(Rc::new))
            .map(|boxed| boxed.as_ref())
    }

    pub fn to_cairo_lang_contract_class(self) -> Result<CairoLangCasmClass, ContractClassError> {
        let cairo_lang_class = self.get_cairo_lang_contract_class()?;
        Ok(cairo_lang_class.clone())
    }

    pub fn to_blockifier_contract_class(self) -> Result<BlockifierCasmClass, ContractClassError> {
        let blockifier_class = self.get_blockifier_contract_class()?;
        Ok(blockifier_class.clone())
    }

    fn compute_class_hash(&self) -> Result<GenericClassHash, ContractClassError> {
        let compiled_class = self.get_cairo_lang_contract_class()?;
        let class_hash_felt = compiled_class.compiled_class_hash();

        Ok(GenericClassHash::from_bytes_be(class_hash_felt.to_be_bytes()))
    }

    pub fn class_hash(&self) -> Result<GenericClassHash, ContractClassError> {
        self.class_hash.get_or_try_init(|| self.compute_class_hash()).copied()
    }
}

impl Serialize for GenericCasmContractClass {
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

impl<'de> Deserialize<'de> for GenericCasmContractClass {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let cairo_lang_class = CairoLangCasmClass::deserialize(deserializer)?;
        Ok(Self::from(cairo_lang_class))
    }
}

impl From<CairoLangCasmClass> for GenericCasmContractClass {
    fn from(cairo_lang_class: CairoLangCasmClass) -> Self {
        Self {
            blockifier_contract_class: Default::default(),
            cairo_lang_contract_class: OnceCell::from(Rc::new(cairo_lang_class)),
            serialized_class: Default::default(),
            class_hash: Default::default(),
        }
    }
}

impl From<BlockifierCasmClass> for GenericCasmContractClass {
    fn from(blockifier_class: BlockifierCasmClass) -> Self {
        Self {
            blockifier_contract_class: OnceCell::from(Rc::new(blockifier_class)),
            cairo_lang_contract_class: Default::default(),
            serialized_class: Default::default(),
            class_hash: Default::default(),
        }
    }
}

impl TryFrom<GenericCasmContractClass> for BlockifierCasmClass {
    type Error = ContractClassError;

    fn try_from(contract_class: GenericCasmContractClass) -> Result<Self, Self::Error> {
        contract_class.to_blockifier_contract_class()
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use starknet_types_core::felt::Felt;

    use super::*;

    const CONTRACT_BYTES: &[u8] = include_bytes!(
        "../../../tests/integration/contracts/blockifier_contracts/feature_contracts/cairo1/compiled/test_contract.\
         casm.json"
    );

    #[test]
    fn test_serialize_and_deserialize() {
        let generic_class = GenericCasmContractClass::from_bytes(CONTRACT_BYTES.to_vec());

        let serialized_class = serde_json::to_vec(&generic_class).unwrap();
        // Check that the deserialization works
        let _deserialized_class: GenericCasmContractClass = serde_json::from_slice(&serialized_class).unwrap();
    }

    #[test]
    fn test_compare_serde_formats() {
        let generic_class = GenericCasmContractClass::from_bytes(CONTRACT_BYTES.to_vec());
        let cairo_lang_class: CairoLangCasmClass = serde_json::from_slice(CONTRACT_BYTES).unwrap();

        let generated_cairo_lang_class = generic_class.to_cairo_lang_contract_class().unwrap();

        assert_eq!(generated_cairo_lang_class, cairo_lang_class);

        let deserialized_generic_class: GenericCasmContractClass = serde_json::from_slice(CONTRACT_BYTES).unwrap();
        let deserialized_cairo_lang_class = deserialized_generic_class.to_cairo_lang_contract_class().unwrap();

        assert_eq!(deserialized_cairo_lang_class, cairo_lang_class);
    }

    #[test]
    fn test_class_hash() {
        let generic_class = GenericCasmContractClass::from_bytes(CONTRACT_BYTES.to_vec());
        let class_hash = generic_class.class_hash().unwrap();

        // Some weird type conversions here to load the class hash from string easily, may be
        // improved with more methods on `Hash` / `GenericClassHash`.
        let expected_class_hash =
            Felt::from_str("0x607c67298d45092cca5b2ae6804373dd8a2cbe7d2ec4072b3f67097461d5ff4").unwrap();
        assert_eq!(Felt::from(*class_hash), expected_class_hash);
    }
}
