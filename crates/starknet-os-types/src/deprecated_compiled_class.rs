//! Cairo 0 legacy (deprecated) contract class types and utilities.

use once_cell::sync::OnceCell;
use std::sync::Arc;

use crate::error::{ContractClassError, ConversionError};
use crate::hash::GenericClassHash;
use crate::starknet_core_addons::{decompress_starknet_core_contract_class, LegacyContractDecompressionError};
use pathfinder_gateway_types::class_hash::compute_class_hash;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Type alias for StarknetAPI deprecated contract class.
pub type StarknetApiDeprecatedClass = starknet_api::deprecated_contract_class::ContractClass;

/// Type alias for StarknetCore deprecated contract class.
pub type StarknetCoreDeprecatedClass = starknet_core::types::contract::legacy::LegacyContractClass;

/// Type alias for a compressed StarknetCore deprecated contract class.
pub type CompressedStarknetCoreDeprecatedClass = starknet_core::types::CompressedLegacyContractClass;

/// Type alias for Blockifier deprecated contract class.
/// Note: This is the same as StarknetApiDeprecatedClass, but kept for clarity.
pub type BlockifierDeprecatedClass = starknet_api::deprecated_contract_class::ContractClass;

/// A generic deprecated contract class that supports conversion between different formats.
///
/// This struct provides a unified interface for working with Cairo 0 legacy contract classes
/// across different Starknet implementations. It supports lazy conversion between different
/// formats and provides utilities for handling compressed contract classes.
///
/// The struct uses `OnceCell` for lazy initialization of different representations and `Arc` for
/// inexpensive cloning of the underlying data.
///
/// # Examples
///
/// ```rust
/// use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;
///
/// // Create from serialized bytes
/// let contract_bytes = include_bytes!("path/to/contract.json");
/// let contract_class = GenericDeprecatedCompiledClass::from_bytes(contract_bytes.to_vec());
///
/// // Get the class hash
/// let class_hash = contract_class.class_hash()?;
///
/// // Convert to Blockifier format
/// let blockifier_class = contract_class.get_blockifier_contract_class()?;
/// ```
#[derive(Debug, Clone)]
pub struct GenericDeprecatedCompiledClass {
    /// Lazy-initialized Blockifier contract class.
    blockifier_contract_class: OnceCell<Arc<BlockifierDeprecatedClass>>,
    /// Lazy-initialized StarknetAPI contract class.
    starknet_api_contract_class: OnceCell<Arc<StarknetApiDeprecatedClass>>,
    /// Lazy-initialized StarknetCore contract class.
    #[allow(dead_code)]
    starknet_core_contract_class: OnceCell<Arc<StarknetCoreDeprecatedClass>>,
    /// Lazy-initialized serialized contract class bytes.
    serialized_class: OnceCell<Vec<u8>>,
    /// Lazy-initialized computed class hash.
    class_hash: OnceCell<GenericClassHash>,
}

impl GenericDeprecatedCompiledClass {
    /// Creates a new generic deprecated contract class from serialized bytes.
    ///
    /// # Arguments
    ///
    /// * `serialized_class` - The serialized contract class bytes
    ///
    /// # Returns
    ///
    /// A new `GenericDeprecatedCompiledClass` instance.
    ///
    /// # Example
    ///
    /// ```rust
    /// use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;
    ///
    /// let contract_bytes = include_bytes!("path/to/contract.json");
    /// let contract_class = GenericDeprecatedCompiledClass::from_bytes(contract_bytes.to_vec());
    /// ```
    #[must_use]
    pub fn from_bytes(serialized_class: Vec<u8>) -> Self {
        Self {
            blockifier_contract_class: Default::default(),
            starknet_api_contract_class: Default::default(),
            starknet_core_contract_class: Default::default(),
            serialized_class: OnceCell::from(serialized_class),
            class_hash: OnceCell::new(),
        }
    }

    /// Builds the StarknetAPI contract class from available data.
    ///
    /// # Returns
    ///
    /// The StarknetAPI contract class, or an error if it cannot be built.
    ///
    /// # Errors
    ///
    /// Returns a `ContractClassError` if the StarknetAPI class cannot be built.
    fn build_starknet_api_class(&self) -> Result<StarknetApiDeprecatedClass, ContractClassError> {
        if let Some(serialized_class) = self.serialized_class.get() {
            return serde_json::from_slice(serialized_class).map_err(ContractClassError::SerdeError);
        }

        Err(ContractClassError::ConversionError(ConversionError::StarknetClassMissing))
    }

    /// Builds the Blockifier contract class from available data.
    ///
    /// # Returns
    ///
    /// The Blockifier contract class, or an error if it cannot be built.
    ///
    /// # Errors
    ///
    /// Returns a `ContractClassError` if the Blockifier class cannot be built.
    fn build_blockifier_class(&self) -> Result<BlockifierDeprecatedClass, ContractClassError> {
        let serialized_class = self.serialized_class.get_or_try_init(|| serde_json::to_vec(self))?;

        serde_json::from_slice(serialized_class).map_err(ContractClassError::SerdeError)
    }

    /// Gets a reference to the StarknetAPI contract class, building it if necessary.
    ///
    /// # Returns
    ///
    /// A reference to the StarknetAPI contract class, or an error if it cannot be built.
    ///
    /// # Errors
    ///
    /// Returns a `ContractClassError` if the StarknetAPI class cannot be built.
    ///
    /// # Example
    ///
    /// ```rust
    /// use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;
    ///
    /// let contract_class = GenericDeprecatedCompiledClass::from_bytes(vec![0]);
    /// let starknet_api_class = contract_class.get_starknet_api_contract_class()?;
    /// ```
    pub fn get_starknet_api_contract_class(&self) -> Result<&StarknetApiDeprecatedClass, ContractClassError> {
        self.starknet_api_contract_class
            .get_or_try_init(|| self.build_starknet_api_class().map(Arc::new))
            .map(|arc| arc.as_ref())
    }

    /// Gets a reference to the Blockifier contract class, building it if necessary.
    ///
    /// # Returns
    ///
    /// A reference to the Blockifier contract class, or an error if it cannot be built.
    ///
    /// # Errors
    ///
    /// Returns a `ContractClassError` if the Blockifier class cannot be built.
    ///
    /// # Example
    ///
    /// ```rust
    /// use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;
    ///
    /// let contract_class = GenericDeprecatedCompiledClass::from_bytes(vec![0]);
    /// let blockifier_class = contract_class.get_blockifier_contract_class()?;
    /// ```
    pub fn get_blockifier_contract_class(&self) -> Result<&BlockifierDeprecatedClass, ContractClassError> {
        self.blockifier_contract_class
            .get_or_try_init(|| self.build_blockifier_class().map(Arc::new))
            .map(|arc| arc.as_ref())
    }

    /// Gets a reference to the serialized contract class bytes, serializing if necessary.
    ///
    /// # Returns
    ///
    /// A reference to the serialized contract class bytes, or an error if serialization fails.
    ///
    /// # Errors
    ///
    /// Returns a `ContractClassError` if serialization fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;
    ///
    /// let contract_class = GenericDeprecatedCompiledClass::from_bytes(vec![0]);
    /// let serialized = contract_class.get_serialized_contract_class()?;
    /// ```
    pub fn get_serialized_contract_class(&self) -> Result<&Vec<u8>, ContractClassError> {
        self.serialized_class.get_or_try_init(|| serde_json::to_vec(self)).map_err(Into::into)
    }

    /// Converts this generic class to a StarknetAPI contract class.
    ///
    /// # Returns
    ///
    /// The StarknetAPI contract class, or an error if conversion fails.
    ///
    /// # Errors
    ///
    /// Returns a `ContractClassError` if the conversion fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;
    ///
    /// let contract_class = GenericDeprecatedCompiledClass::from_bytes(vec![0]);
    /// let starknet_api_class = contract_class.to_starknet_api_contract_class()?;
    /// ```
    pub fn to_starknet_api_contract_class(self) -> Result<StarknetApiDeprecatedClass, ContractClassError> {
        let starknet_api_class = self.get_starknet_api_contract_class()?;
        Ok(starknet_api_class.clone())
    }

    /// Converts this generic class to a Blockifier contract class.
    ///
    /// # Returns
    ///
    /// The Blockifier contract class, or an error if conversion fails.
    ///
    /// # Errors
    ///
    /// Returns a `ContractClassError` if the conversion fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;
    ///
    /// let contract_class = GenericDeprecatedCompiledClass::from_bytes(vec![0]);
    /// let blockifier_class = contract_class.to_blockifier_contract_class()?;
    /// ```
    pub fn to_blockifier_contract_class(self) -> Result<BlockifierDeprecatedClass, ContractClassError> {
        let blockifier_class = self.get_blockifier_contract_class()?;
        Ok(blockifier_class.clone())
    }

    /// Computes the class hash for this contract class.
    ///
    /// # Returns
    ///
    /// The computed class hash, or an error if computation fails.
    ///
    /// # Errors
    ///
    /// Returns a `ContractClassError` if the class hash computation fails.
    fn compute_class_hash(&self) -> Result<GenericClassHash, ContractClassError> {
        let serialized_class = self.get_serialized_contract_class()?;
        let class_hash =
            compute_class_hash(serialized_class).map_err(|e| ContractClassError::HashError(e.to_string()))?;

        Ok(GenericClassHash::from_bytes_be(class_hash.hash().0.to_be_bytes()))
    }

    /// Gets the class hash for this contract class, computing it if necessary.
    ///
    /// # Returns
    ///
    /// The class hash, or an error if computation fails.
    ///
    /// # Errors
    ///
    /// Returns a `ContractClassError` if the class hash computation fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;
    ///
    /// let contract_class = GenericDeprecatedCompiledClass::from_bytes(vec![0]);
    /// let class_hash = contract_class.class_hash()?;
    /// ```
    pub fn class_hash(&self) -> Result<GenericClassHash, ContractClassError> {
        self.class_hash.get_or_try_init(|| self.compute_class_hash()).copied()
    }
}

impl Serialize for GenericDeprecatedCompiledClass {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Try to serialize using a StarknetAPI class first
        if let Some(starknet_api_class) = self.starknet_api_contract_class.get() {
            starknet_api_class.serialize(serializer)
        } else {
            // Fall back to serializing the raw bytes
            let serialized_class =
                self.get_serialized_contract_class().map_err(|e| serde::ser::Error::custom(e.to_string()))?;
            serializer.serialize_bytes(serialized_class)
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

impl TryFrom<CompressedStarknetCoreDeprecatedClass> for GenericDeprecatedCompiledClass {
    type Error = LegacyContractDecompressionError;

    fn try_from(compressed_class: CompressedStarknetCoreDeprecatedClass) -> Result<Self, Self::Error> {
        let decompressed_class = decompress_starknet_core_contract_class(compressed_class)?;
        Ok(Self::from(decompressed_class))
    }
}

impl TryFrom<GenericDeprecatedCompiledClass> for StarknetApiDeprecatedClass {
    type Error = ContractClassError;

    fn try_from(contract_class: GenericDeprecatedCompiledClass) -> Result<Self, Self::Error> {
        contract_class.to_starknet_api_contract_class()
    }
}

impl TryFrom<GenericDeprecatedCompiledClass> for StarknetCoreDeprecatedClass {
    type Error = ContractClassError;

    fn try_from(_contract_class: GenericDeprecatedCompiledClass) -> Result<Self, Self::Error> {
        // This would need to be implemented based on the specific conversion logic
        // For now, we'll return an error indicating this conversion is not yet supported
        Err(ContractClassError::ConversionError(ConversionError::InvalidFormat(
            "Conversion to StarknetCoreDeprecatedClass not yet implemented".to_string(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEPRECATED_CLASS: &[u8] = include_bytes!("../../../resources/test_contract_compiled.json");

    #[ignore = "This test takes a lot of time. Ignoring for now"]
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
