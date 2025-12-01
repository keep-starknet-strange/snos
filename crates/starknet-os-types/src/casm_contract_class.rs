//! Cairo 1 compiled contract class (CASM) types and utilities.

use once_cell::sync::OnceCell;
use std::sync::Arc;

use crate::error::{ContractClassError, ConversionError};
use crate::hash::GenericClassHash;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use starknet_api::contract_class::compiled_class_hash::{HashVersion, HashableCompiledClass};
use starknet_api::contract_class::SierraVersion;

/// Type alias for CairoLang CASM contract class.
pub type CairoLangCasmClass = cairo_lang_starknet_classes::casm_contract_class::CasmContractClass;

/// Type alias for Blockifier CASM contract class.
pub type BlockifierCasmClass = starknet_api::contract_class::VersionedCasm;

/// A generic CASM contract class that supports conversion between different formats.
///
/// This struct provides a unified interface for working with Cairo 1 compiled contract classes
/// (CASM format) across different Starknet implementations. It supports lazy conversion between
/// CairoLang and Blockifier formats, only performing conversions when necessary.
///
/// The struct uses `OnceCell` for lazy initialization of different representations and `Arc` for
/// inexpensive cloning of the underlying data.
///
/// # Examples
///
/// ```rust
/// use starknet_os_types::casm_contract_class::GenericCasmContractClass;
/// use starknet_api::contract_class::SierraVersion;
///
/// // Create from serialized bytes
/// let casm_bytes = include_bytes!("path/to/contract.casm.json");
/// let casm_class = GenericCasmContractClass::from_bytes(casm_bytes.to_vec());
///
/// // Get the class hash
/// let class_hash = casm_class.class_hash()?;
///
/// // Convert to Blockifier format
/// let blockifier_class = casm_class.get_blockifier_contract_class(SierraVersion::LATEST)?;
/// ```
#[derive(Debug, Clone)]
pub struct GenericCasmContractClass {
    /// Lazy-initialized Blockifier contract class.
    blockifier_contract_class: OnceCell<Arc<BlockifierCasmClass>>,
    /// Lazy-initialized CairoLang contract class.
    cairo_lang_contract_class: OnceCell<Arc<CairoLangCasmClass>>,
    /// Lazy-initialized serialized contract class bytes.
    serialized_class: OnceCell<Arc<Vec<u8>>>,
    /// Lazy-initialized computed class hash (Poseidon - pre-SNIP-34).
    class_hash: OnceCell<GenericClassHash>,
    /// Lazy-initialized computed class hash v2 (BLAKE2s - post-SNIP-34).
    class_hash_v2: OnceCell<GenericClassHash>,
}

/// Converts a CairoLang CASM class to a Blockifier CASM class.
///
/// # Arguments
///
/// * `cairo_lang_class` - The CairoLang contract class to convert
/// * `sierra_version` - The Sierra version to use for the conversion
///
/// # Returns
///
/// The converted Blockifier contract class, or an error if conversion fails.
///
/// # Errors
///
/// Returns a `ContractClassError` if the conversion fails.
fn blockifier_contract_class_from_cairo_lang_class(
    cairo_lang_class: CairoLangCasmClass,
    sierra_version: SierraVersion,
) -> Result<BlockifierCasmClass, ContractClassError> {
    BlockifierCasmClass::try_from((cairo_lang_class, sierra_version))
        .map_err(|e| ContractClassError::ConversionError(ConversionError::BlockifierError(Box::new(e))))
}

/// Deserializes a CairoLang CASM class from bytes.
///
/// # Arguments
///
/// * `bytes` - The serialized contract class bytes
///
/// # Returns
///
/// The deserialized CairoLang contract class, or an error if deserialization fails.
///
/// # Errors
///
/// Returns a `ContractClassError` if deserialization fails.
fn cairo_lang_contract_class_from_bytes(bytes: &[u8]) -> Result<CairoLangCasmClass, ContractClassError> {
    serde_json::from_slice(bytes).map_err(ContractClassError::SerdeError)
}

impl GenericCasmContractClass {
    /// Creates a new generic CASM contract class from serialized bytes.
    ///
    /// # Arguments
    ///
    /// * `serialized_class` - The serialized contract class bytes
    ///
    /// # Returns
    ///
    /// A new `GenericCasmContractClass` instance.
    ///
    /// # Example
    ///
    /// ```rust
    /// use starknet_os_types::casm_contract_class::GenericCasmContractClass;
    ///
    /// let casm_bytes = include_bytes!("path/to/contract.casm.json");
    /// let casm_class = GenericCasmContractClass::from_bytes(casm_bytes.to_vec());
    /// ```
    #[must_use]
    pub fn from_bytes(serialized_class: Vec<u8>) -> Self {
        Self {
            blockifier_contract_class: OnceCell::new(),
            cairo_lang_contract_class: OnceCell::new(),
            serialized_class: OnceCell::from(Arc::new(serialized_class)),
            class_hash: OnceCell::new(),
            class_hash_v2: OnceCell::new(),
        }
    }

    /// Builds the CairoLang contract class from available data.
    ///
    /// # Returns
    ///
    /// The CairoLang contract class, or an error if it cannot be built.
    ///
    /// # Errors
    ///
    /// Returns a `ContractClassError` if the CairoLang class cannot be built.
    fn build_cairo_lang_class(&self) -> Result<CairoLangCasmClass, ContractClassError> {
        if let Some(serialized_class) = self.serialized_class.get() {
            return cairo_lang_contract_class_from_bytes(serialized_class);
        }

        Err(ContractClassError::ConversionError(ConversionError::CairoLangClassMissing))
    }

    /// Builds the Blockifier contract class from available data.
    ///
    /// # Arguments
    ///
    /// * `sierra_version` - The Sierra version to use for the conversion
    ///
    /// # Returns
    ///
    /// The Blockifier contract class, or an error if it cannot be built.
    ///
    /// # Errors
    ///
    /// Returns a `ContractClassError` if the Blockifier class cannot be built.
    fn build_blockifier_class(&self, sierra_version: SierraVersion) -> Result<BlockifierCasmClass, ContractClassError> {
        // Try to get from existing CairoLang class first
        if let Some(cairo_lang_class) = self.cairo_lang_contract_class.get() {
            return blockifier_contract_class_from_cairo_lang_class(cairo_lang_class.as_ref().clone(), sierra_version);
        }

        // Try to build from serialized data
        if let Some(serialized_class) = self.serialized_class.get() {
            let cairo_lang_class = cairo_lang_contract_class_from_bytes(serialized_class)?;

            // Cache the CairoLang class for future use
            self.cairo_lang_contract_class
                .set(Arc::new(cairo_lang_class.clone()))
                .expect("cairo-lang class should not be set yet");

            return blockifier_contract_class_from_cairo_lang_class(cairo_lang_class, sierra_version);
        }

        Err(ContractClassError::ConversionError(ConversionError::BlockifierClassMissing))
    }

    /// Gets a reference to the CairoLang contract class, building it if necessary.
    ///
    /// # Returns
    ///
    /// A reference to the CairoLang contract class, or an error if it cannot be built.
    ///
    /// # Errors
    ///
    /// Returns a `ContractClassError` if the CairoLang class cannot be built.
    ///
    /// # Example
    ///
    /// ```rust
    /// use starknet_os_types::casm_contract_class::GenericCasmContractClass;
    ///
    /// let casm_class = GenericCasmContractClass::from_bytes(vec![]);
    /// let cairo_lang_class = casm_class.get_cairo_lang_contract_class()?;
    /// ```
    pub fn get_cairo_lang_contract_class(&self) -> Result<&CairoLangCasmClass, ContractClassError> {
        self.cairo_lang_contract_class
            .get_or_try_init(|| self.build_cairo_lang_class().map(Arc::new))
            .map(|arc| arc.as_ref())
    }

    /// Gets a reference to the Blockifier contract class, building it if necessary.
    ///
    /// # Arguments
    ///
    /// * `sierra_version` - The Sierra version to use for the conversion
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
    /// use starknet_os_types::casm_contract_class::GenericCasmContractClass;
    /// use starknet_api::contract_class::SierraVersion;
    ///
    /// let casm_class = GenericCasmContractClass::from_bytes(vec![]);
    /// let blockifier_class = casm_class.get_blockifier_contract_class(SierraVersion::LATEST)?;
    /// ```
    pub fn get_blockifier_contract_class(
        &self,
        sierra_version: SierraVersion,
    ) -> Result<&BlockifierCasmClass, ContractClassError> {
        self.blockifier_contract_class
            .get_or_try_init(|| self.build_blockifier_class(sierra_version).map(Arc::new))
            .map(|arc| arc.as_ref())
    }

    /// Converts this generic class to a CairoLang contract class.
    ///
    /// # Returns
    ///
    /// The CairoLang contract class, or an error if conversion fails.
    ///
    /// # Errors
    ///
    /// Returns a `ContractClassError` if the conversion fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use starknet_os_types::casm_contract_class::GenericCasmContractClass;
    ///
    /// let casm_class = GenericCasmContractClass::from_bytes(vec![]);
    /// let cairo_lang_class = casm_class.to_cairo_lang_contract_class()?;
    /// ```
    pub fn to_cairo_lang_contract_class(self) -> Result<CairoLangCasmClass, ContractClassError> {
        let cairo_lang_class = self.get_cairo_lang_contract_class()?;
        Ok(cairo_lang_class.clone())
    }

    /// Converts this generic class to a Blockifier contract class.
    ///
    /// # Arguments
    ///
    /// * `sierra_version` - The Sierra version to use for the conversion
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
    /// use starknet_os_types::casm_contract_class::GenericCasmContractClass;
    /// use starknet_api::contract_class::SierraVersion;
    ///
    /// let casm_class = GenericCasmContractClass::from_bytes(vec![]);
    /// let blockifier_class = casm_class.to_blockifier_contract_class(SierraVersion::LATEST)?;
    /// ```
    pub fn to_blockifier_contract_class(
        self,
        sierra_version: SierraVersion,
    ) -> Result<BlockifierCasmClass, ContractClassError> {
        let blockifier_class = self.get_blockifier_contract_class(sierra_version)?;
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
        let compiled_class = self.get_cairo_lang_contract_class()?;
        let class_hash_felt = compiled_class.compiled_class_hash();

        Ok(GenericClassHash::from_bytes_be(class_hash_felt.to_bytes_be()))
    }

    /// Gets the class hash for this contract class, computing it if necessary.
    ///
    /// This returns the **Poseidon hash** (pre-SNIP-34). For the BLAKE2s hash
    /// (post-SNIP-34), use [`class_hash_v2`](Self::class_hash_v2).
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
    /// use starknet_os_types::casm_contract_class::GenericCasmContractClass;
    ///
    /// let casm_class = GenericCasmContractClass::from_bytes(vec![]);
    /// let class_hash = casm_class.class_hash()?;
    /// ```
    pub fn class_hash(&self) -> Result<GenericClassHash, ContractClassError> {
        self.class_hash.get_or_try_init(|| self.compute_class_hash()).copied()
    }

    /// Computes the class hash v2 (BLAKE2s) for this contract class.
    ///
    /// This is the SNIP-34 compliant hash using BLAKE2s instead of Poseidon.
    ///
    /// # Returns
    ///
    /// The computed class hash, or an error if computation fails.
    ///
    /// # Errors
    ///
    /// Returns a `ContractClassError` if the class hash computation fails.
    fn compute_class_hash_v2(&self) -> Result<GenericClassHash, ContractClassError> {
        let compiled_class = self.get_cairo_lang_contract_class()?;
        let class_hash = compiled_class.hash(&HashVersion::V2);

        Ok(GenericClassHash::from_bytes_be(class_hash.0.to_bytes_be()))
    }

    /// Gets the class hash v2 (BLAKE2s) for this contract class, computing it if necessary.
    ///
    /// This returns the **BLAKE2s hash** (post-SNIP-34) as specified in SNIP-34.
    /// For the legacy Poseidon hash (pre-SNIP-34), use [`class_hash`](Self::class_hash).
    ///
    /// # Returns
    ///
    /// The BLAKE2s class hash, or an error if computation fails.
    ///
    /// # Errors
    ///
    /// Returns a `ContractClassError` if the class hash computation fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use starknet_os_types::casm_contract_class::GenericCasmContractClass;
    ///
    /// let casm_class = GenericCasmContractClass::from_bytes(vec![]);
    /// // Get BLAKE2s hash (SNIP-34)
    /// let class_hash_v2 = casm_class.class_hash_v2()?;
    /// ```
    pub fn class_hash_v2(&self) -> Result<GenericClassHash, ContractClassError> {
        self.class_hash_v2.get_or_try_init(|| self.compute_class_hash_v2()).copied()
    }
}

impl Serialize for GenericCasmContractClass {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize the CairoLang class as it's the most standard format
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
            cairo_lang_contract_class: OnceCell::from(Arc::new(cairo_lang_class)),
            serialized_class: Default::default(),
            class_hash: Default::default(),
            class_hash_v2: Default::default(),
        }
    }
}

impl From<BlockifierCasmClass> for GenericCasmContractClass {
    fn from(blockifier_class: BlockifierCasmClass) -> Self {
        Self {
            blockifier_contract_class: OnceCell::from(Arc::new(blockifier_class)),
            cairo_lang_contract_class: Default::default(),
            serialized_class: Default::default(),
            class_hash: Default::default(),
            class_hash_v2: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use indoc::indoc;
    use rstest::rstest;
    use starknet_types_core::felt::Felt;

    use super::*;
    use crate::hash::Hash;

    const CONTRACT_BYTES: &[u8] = include_bytes!("../../../resources/test_contract.casm.json");

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

        // Some eccentric type conversions here to load the class hash from string easily, may be
        // improved with more methods on `Hash` / `GenericClassHash`.
        let expected_class_hash =
            Felt::from_str("0x607c67298d45092cca5b2ae6804373dd8a2cbe7d2ec4072b3f67097461d5ff4").unwrap();
        assert_eq!(Felt::from(*class_hash), expected_class_hash);
    }

    const TEST_CONTRACT_WITHOUT_SEGMENTATION: &str = indoc! {r#"
        {
          "prime": "0x800000000000011000000000000000000000000000000000000000000000001",
          "compiler_version": "",
          "bytecode": [
            "0x1",
            "0x2",
            "0x3",
            "0x4",
            "0x5",
            "0x6",
            "0x7",
            "0x8",
            "0x9",
            "0xa"
          ],
          "hints": [],
          "entry_points_by_type": {
            "EXTERNAL": [
              {
                "selector": "0x1",
                "offset": 1,
                "builtins": [
                  "237"
                ]
              }
            ],
            "L1_HANDLER": [],
            "CONSTRUCTOR": [
              {
                "selector": "0x5",
                "offset": 0,
                "builtins": []
              }
            ]
          }
        }
        "#
    };

    const TEST_CONTRACT_WITH_SEGMENTATION: &str = indoc! {r#"
        {
          "prime": "0x800000000000011000000000000000000000000000000000000000000000001",
          "compiler_version": "",
          "bytecode": [
            "0x1",
            "0x2",
            "0x3",
            "0x4",
            "0x5",
            "0x6",
            "0x7",
            "0x8",
            "0x9",
            "0xa"
          ],
          "bytecode_segment_lengths": [3, [1, 1, [1]], 4],
          "hints": [],
          "entry_points_by_type": {
            "EXTERNAL": [
              {
                "selector": "0x1",
                "offset": 1,
                "builtins": [
                  "237"
                ]
              }
            ],
            "L1_HANDLER": [],
            "CONSTRUCTOR": [
              {
                "selector": "0x5",
                "offset": 0,
                "builtins": []
              }
            ]
          }
        }
        "#
    };

    #[rstest]
    #[case::without_segmentation(
        TEST_CONTRACT_WITHOUT_SEGMENTATION,
        "0xB268995DD0EE80DEBFB8718852750B5FD22082D0C729121C48A0487A4D2F64"
    )]
    #[case::with_segmentation(
        TEST_CONTRACT_WITH_SEGMENTATION,
        "0x5517AD8471C9AA4D1ADD31837240DEAD9DC6653854169E489A813DB4376BE9C"
    )]
    fn test_compiled_class_hash_without_segmentation(#[case] test_contract: &str, #[case] expected_hash_str: &str) {
        let expected_hash = Felt::from_hex(expected_hash_str).unwrap();
        let expected_compiled_class_hash = GenericClassHash::new(Hash::from(expected_hash));

        let casm_class: GenericCasmContractClass = serde_json::from_str(test_contract).unwrap();
        let compiled_class_hash = casm_class.class_hash().unwrap();

        assert_eq!(compiled_class_hash, expected_compiled_class_hash);
    }
}
