use once_cell::sync::OnceCell;
use std::sync::Arc;

use pathfinder_gateway_types::class_hash::compute_class_hash;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{ContractClassError, ConversionError};
use crate::hash::GenericClassHash;
use crate::starknet_core_addons::{decompress_starknet_core_contract_class, LegacyContractDecompressionError};

pub type StarknetApiDeprecatedClass = starknet_api::deprecated_contract_class::ContractClass;
pub type StarknetCoreDeprecatedClass = starknet_core::types::contract::legacy::LegacyContractClass;
pub type CompressedStarknetCoreDeprecatedClass = starknet_core::types::CompressedLegacyContractClass;
pub type BlockifierDeprecatedClass = blockifier::execution::contract_class::ContractClassV0;

/// A generic contract class that supports conversion to/from the most commonly used
/// contract class types in Starknet and provides utility methods.
///
/// Operations are implemented as lazily as possible, i.e. we only convert
/// between different types if strictly necessary.
/// Fields are boxed in an RC for cheap cloning.
#[derive(Debug, Clone)]
pub struct GenericDeprecatedCompiledClass {
    blockifier_contract_class: OnceCell<Arc<BlockifierDeprecatedClass>>,
    starknet_api_contract_class: OnceCell<Arc<StarknetApiDeprecatedClass>>,
    starknet_core_contract_class: OnceCell<Arc<StarknetCoreDeprecatedClass>>,
    serialized_class: OnceCell<Vec<u8>>,
    class_hash: OnceCell<GenericClassHash>,
}

impl GenericDeprecatedCompiledClass {
    pub fn from_bytes(serialized_class: Vec<u8>) -> Self {
        Self {
            blockifier_contract_class: Default::default(),
            starknet_api_contract_class: Default::default(),
            starknet_core_contract_class: Default::default(),
            serialized_class: OnceCell::from(serialized_class),
            class_hash: OnceCell::new(),
        }
    }

    fn build_starknet_api_class(&self) -> Result<StarknetApiDeprecatedClass, ContractClassError> {
        if let Some(serialized_class) = self.serialized_class.get() {
            let contract_class = serde_json::from_slice(serialized_class)?;
            return Ok(contract_class);
        }

        Err(ContractClassError::ConversionError(ConversionError::StarknetClassMissing))
    }

    fn build_blockifier_class(&self) -> Result<BlockifierDeprecatedClass, ContractClassError> {
        let serialized_class = self.serialized_class.get_or_try_init(|| serde_json::to_vec(self))?;

        let blockifier_class: BlockifierDeprecatedClass = serde_json::from_slice(serialized_class)?;
        Ok(blockifier_class)
    }

    pub fn get_starknet_api_contract_class(&self) -> Result<&StarknetApiDeprecatedClass, ContractClassError> {
        self.starknet_api_contract_class
            .get_or_try_init(|| self.build_starknet_api_class().map(Arc::new))
            .map(|boxed| boxed.as_ref())
    }

    pub fn get_blockifier_contract_class(&self) -> Result<&BlockifierDeprecatedClass, ContractClassError> {
        self.blockifier_contract_class
            .get_or_try_init(|| self.build_blockifier_class().map(Arc::new))
            .map(|boxed| boxed.as_ref())
    }

    pub fn get_serialized_contract_class(&self) -> Result<&Vec<u8>, ContractClassError> {
        self.serialized_class.get_or_try_init(|| serde_json::to_vec(self)).map_err(Into::into)
    }

    pub fn to_starknet_api_contract_class(self) -> Result<StarknetApiDeprecatedClass, ContractClassError> {
        let cairo_lang_class = self.get_starknet_api_contract_class()?;
        Ok(cairo_lang_class.clone())
    }

    pub fn to_blockifier_contract_class(self) -> Result<BlockifierDeprecatedClass, ContractClassError> {
        let blockifier_class = self.get_blockifier_contract_class()?;
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
}

impl Serialize for GenericDeprecatedCompiledClass {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Some(starknet_api_class) = self.starknet_api_contract_class.get() {
            starknet_api_class.serialize(serializer)
        } else if let Some(starknet_core_class) = self.starknet_core_contract_class.get() {
            starknet_core_class.serialize(serializer)
        } else if self.serialized_class.get().is_some() {
            // It seems like there is no way to just pass the `serialized_class` field as the output
            // of `serialize()`, so we are forced to serialize an actual class instance.
            let starknet_api_class =
                self.get_starknet_api_contract_class().map_err(|e| serde::ser::Error::custom(e.to_string()))?;
            starknet_api_class.serialize(serializer)
        } else {
            Err(serde::ser::Error::custom("No conversion found"))
        }
    }
}

impl<'de> Deserialize<'de> for GenericDeprecatedCompiledClass {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let starknet_api_class = StarknetApiDeprecatedClass::deserialize(deserializer)?;
        Ok(Self::from(starknet_api_class))
    }
}

impl From<StarknetApiDeprecatedClass> for GenericDeprecatedCompiledClass {
    fn from(starknet_api_class: StarknetApiDeprecatedClass) -> Self {
        Self {
            blockifier_contract_class: Default::default(),
            starknet_api_contract_class: OnceCell::from(Arc::new(starknet_api_class)),
            starknet_core_contract_class: Default::default(),
            serialized_class: Default::default(),
            class_hash: Default::default(),
        }
    }
}

/// Builds a generic deprecated compiled class from a starknet-core compressed class.
/// Decompresses the compressed class then builds a generic class from it. Refer
/// to the doc of `decompress_starknet_core_contract_class` for more details.
impl TryFrom<CompressedStarknetCoreDeprecatedClass> for GenericDeprecatedCompiledClass {
    type Error = LegacyContractDecompressionError;

    fn try_from(compressed_legacy_class: CompressedStarknetCoreDeprecatedClass) -> Result<Self, Self::Error> {
        let legacy_class = decompress_starknet_core_contract_class(compressed_legacy_class)?;
        Ok(Self::from(legacy_class))
    }
}

impl From<BlockifierDeprecatedClass> for GenericDeprecatedCompiledClass {
    fn from(blockifier_class: BlockifierDeprecatedClass) -> Self {
        Self {
            blockifier_contract_class: OnceCell::from(Arc::new(blockifier_class)),
            starknet_api_contract_class: Default::default(),
            starknet_core_contract_class: Default::default(),
            serialized_class: Default::default(),
            class_hash: Default::default(),
        }
    }
}

impl From<StarknetCoreDeprecatedClass> for GenericDeprecatedCompiledClass {
    fn from(starknet_core_class: StarknetCoreDeprecatedClass) -> Self {
        Self {
            blockifier_contract_class: Default::default(),
            starknet_api_contract_class: Default::default(),
            starknet_core_contract_class: OnceCell::from(Arc::new(starknet_core_class)),
            serialized_class: Default::default(),
            class_hash: Default::default(),
        }
    }
}

impl TryFrom<GenericDeprecatedCompiledClass> for BlockifierDeprecatedClass {
    type Error = ContractClassError;

    fn try_from(contract_class: GenericDeprecatedCompiledClass) -> Result<Self, Self::Error> {
        contract_class.to_blockifier_contract_class()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEPRECATED_CLASS: &[u8] = include_bytes!(
        "../../../tests/integration/contracts/blockifier_contracts/feature_contracts/cairo0/compiled/\
         test_contract_compiled.json"
    );

    #[test]
    /// Tests that building a Blockifier deprecated contract class from a generic class yields
    /// the same output independently of the way it was built.
    fn test_conversion_to_blockifier_class() {
        // We expect the output to be equal to deserializing to the Blockifier format directly.
        let expected_blockifier_contract_class: BlockifierDeprecatedClass =
            serde_json::from_slice(DEPRECATED_CLASS).unwrap();

        let starknet_core_contract_class: StarknetCoreDeprecatedClass =
            serde_json::from_slice(DEPRECATED_CLASS).unwrap();

        let generic_contract_class_from_serialized =
            GenericDeprecatedCompiledClass::from_bytes(DEPRECATED_CLASS.to_vec());
        let generic_contract_class_from_starknet_core =
            GenericDeprecatedCompiledClass::from(starknet_core_contract_class);
        let generic_contract_class_from_blockifier =
            GenericDeprecatedCompiledClass::from(expected_blockifier_contract_class.clone());

        let blockifier_class_from_generic_serialized =
            generic_contract_class_from_serialized.to_blockifier_contract_class().unwrap();
        let blockifier_class_from_generic_starknet_core =
            generic_contract_class_from_starknet_core.to_blockifier_contract_class().unwrap();
        let blockifier_class_from_generic_blockifier =
            generic_contract_class_from_blockifier.to_blockifier_contract_class().unwrap();

        assert_eq!(blockifier_class_from_generic_serialized, expected_blockifier_contract_class);
        assert_eq!(blockifier_class_from_generic_starknet_core, expected_blockifier_contract_class);
        assert_eq!(blockifier_class_from_generic_blockifier, expected_blockifier_contract_class);
    }
}
