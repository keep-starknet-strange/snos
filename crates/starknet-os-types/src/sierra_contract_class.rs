//! Cairo 1 Sierra contract class types and utilities.

use once_cell::sync::OnceCell;
use std::sync::Arc;

use serde::ser::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::serde_as;
use starknet_core::types::{EntryPointsByType, FlattenedSierraClass};
use starknet_types_core::felt::Felt;

use crate::casm_contract_class::{CairoLangCasmClass, GenericCasmContractClass};
use crate::error::ContractClassError;
use crate::hash::GenericClassHash;

/// Type alias for CairoLang Sierra contract class.
pub type CairoLangSierraContractClass = cairo_lang_starknet_classes::contract_class::ContractClass;

/// Type alias for StarknetCore Sierra contract class.
pub type StarknetCoreSierraContractClass = FlattenedSierraClass;

/// A generic Sierra contract class that supports conversion between different formats.
///
/// This struct provides a unified interface for working with Cairo 1 Sierra contract classes
/// across different Starknet implementations. It supports lazy conversion between CairoLang
/// and StarknetCore formats, only performing conversions when necessary.
///
/// The struct uses `OnceCell` for lazy initialization of different representations and `Arc` for
/// inexpensive cloning of the underlying data.
///
/// # Examples
///
/// ```rust
/// use starknet_os_types::sierra_contract_class::GenericSierraContractClass;
///
/// // Create from serialized bytes
/// let sierra_bytes = include_bytes!("path/to/contract.sierra");
/// let sierra_class = GenericSierraContractClass::from_bytes(sierra_bytes.to_vec());
///
/// // Get the class hash
/// let class_hash = sierra_class.class_hash()?;
///
/// // Compile to CASM
/// let casm_class = sierra_class.compile()?;
/// ```
#[derive(Debug, Clone)]
pub struct GenericSierraContractClass {
    /// Lazy-initialized CairoLang contract class.
    cairo_lang_contract_class: OnceCell<Arc<CairoLangSierraContractClass>>,
    /// Lazy-initialized StarknetCore contract class.
    starknet_core_contract_class: OnceCell<Arc<StarknetCoreSierraContractClass>>,
    /// Lazy-initialized serialized contract class bytes.
    serialized_class: OnceCell<Vec<u8>>,
    /// Lazy-initialized computed class hash.
    class_hash: OnceCell<GenericClassHash>,
}

impl GenericSierraContractClass {
    /// Creates a new generic Sierra contract class from serialized bytes.
    ///
    /// # Arguments
    ///
    /// * `serialized_class` - The serialized contract class bytes
    ///
    /// # Returns
    ///
    /// A new `GenericSierraContractClass` instance.
    ///
    /// # Example
    ///
    /// ```rust
    /// use starknet_os_types::sierra_contract_class::GenericSierraContractClass;
    ///
    /// let sierra_bytes = include_bytes!("path/to/contract.sierra");
    /// let sierra_class = GenericSierraContractClass::from_bytes(sierra_bytes.to_vec());
    /// ```
    #[must_use]
    pub fn from_bytes(serialized_class: Vec<u8>) -> Self {
        Self {
            cairo_lang_contract_class: Default::default(),
            starknet_core_contract_class: Default::default(),
            serialized_class: OnceCell::from(serialized_class),
            class_hash: OnceCell::new(),
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
    fn build_cairo_lang_class(&self) -> Result<CairoLangSierraContractClass, ContractClassError> {
        self.get_serialized_contract_class().and_then(|serialized_class| {
            serde_json::from_slice(serialized_class).map_err(ContractClassError::SerdeError)
        })
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
    pub fn get_serialized_contract_class(&self) -> Result<&Vec<u8>, ContractClassError> {
        self.serialized_class.get_or_try_init(|| serde_json::to_vec(self)).map_err(Into::into)
    }

    /// Builds the StarknetCore contract class from available data.
    ///
    /// # Returns
    ///
    /// The StarknetCore contract class, or an error if it cannot be built.
    ///
    /// # Errors
    ///
    /// Returns a `ContractClassError` if the StarknetCore class cannot be built.
    fn build_starknet_core_class(&self) -> Result<StarknetCoreSierraContractClass, ContractClassError> {
        let serialized_class = self.get_serialized_contract_class()?;
        let sierra_class: starknet_core::types::contract::SierraClass =
            serde_json::from_slice(serialized_class).map_err(ContractClassError::SerdeError)?;

        sierra_class.flatten().map_err(|e| ContractClassError::SerdeError(serde_json::Error::custom(e)))
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
    /// use starknet_os_types::sierra_contract_class::GenericSierraContractClass;
    ///
    /// let sierra_class = GenericSierraContractClass::from_bytes(vec![0]);
    /// let cairo_lang_class = sierra_class.get_cairo_lang_contract_class()?;
    /// ```
    pub fn get_cairo_lang_contract_class(&self) -> Result<&CairoLangSierraContractClass, ContractClassError> {
        self.cairo_lang_contract_class
            .get_or_try_init(|| self.build_cairo_lang_class().map(Arc::new))
            .map(|arc| arc.as_ref())
    }

    /// Gets a reference to the StarknetCore contract class, building it if necessary.
    ///
    /// # Returns
    ///
    /// A reference to the StarknetCore contract class, or an error if it cannot be built.
    ///
    /// # Errors
    ///
    /// Returns a `ContractClassError` if the StarknetCore class cannot be built.
    ///
    /// # Example
    ///
    /// ```rust
    /// use starknet_os_types::sierra_contract_class::GenericSierraContractClass;
    ///
    /// let sierra_class = GenericSierraContractClass::from_bytes(vec![0]);
    /// let starknet_core_class = sierra_class.get_starknet_core_contract_class()?;
    /// ```
    pub fn get_starknet_core_contract_class(&self) -> Result<&StarknetCoreSierraContractClass, ContractClassError> {
        self.starknet_core_contract_class
            .get_or_try_init(|| self.build_starknet_core_class().map(Arc::new))
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
    /// use starknet_os_types::sierra_contract_class::GenericSierraContractClass;
    ///
    /// let sierra_class = GenericSierraContractClass::from_bytes(vec![0]);
    /// let cairo_lang_class = sierra_class.to_cairo_lang_contract_class()?;
    /// ```
    pub fn to_cairo_lang_contract_class(self) -> Result<CairoLangSierraContractClass, ContractClassError> {
        let cairo_lang_class = self.get_cairo_lang_contract_class()?;
        Ok(cairo_lang_class.clone())
    }

    /// Converts this generic class to a StarknetCore contract class.
    ///
    /// # Returns
    ///
    /// The StarknetCore contract class, or an error if conversion fails.
    ///
    /// # Errors
    ///
    /// Returns a `ContractClassError` if the conversion fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use starknet_os_types::sierra_contract_class::GenericSierraContractClass;
    ///
    /// let sierra_class = GenericSierraContractClass::from_bytes(vec![0]);
    /// let starknet_core_class = sierra_class.to_starknet_core_contract_class()?;
    /// ```
    pub fn to_starknet_core_contract_class(self) -> Result<StarknetCoreSierraContractClass, ContractClassError> {
        let starknet_core_class = self.get_starknet_core_contract_class()?;
        Ok(starknet_core_class.clone())
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
        let starknet_core_contract_class = self.get_starknet_core_contract_class()?;
        let class_hash = starknet_core_contract_class.class_hash();
        Ok(GenericClassHash::new(class_hash.into()))
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
    /// use starknet_os_types::sierra_contract_class::GenericSierraContractClass;
    ///
    /// let sierra_class = GenericSierraContractClass::from_bytes(vec![0]);
    /// let class_hash = sierra_class.class_hash()?;
    /// ```
    pub fn class_hash(&self) -> Result<GenericClassHash, ContractClassError> {
        self.class_hash.get_or_try_init(|| self.compute_class_hash()).copied()
    }

    /// Compiles this Sierra contract class to a CASM contract class.
    ///
    /// This method compiles the Sierra program to CASM bytecode using the CairoLang compiler.
    /// The compilation uses default settings that are compatible with most Starknet contracts.
    ///
    /// # Returns
    ///
    /// The compiled CASM contract class, or an error if compilation fails.
    ///
    /// # Errors
    ///
    /// Returns a `ContractClassError` if the compilation fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use starknet_os_types::sierra_contract_class::GenericSierraContractClass;
    ///
    /// let sierra_class = GenericSierraContractClass::from_bytes(vec![0]);
    /// let casm_class = sierra_class.compile()?;
    /// ```
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

/// A flattened Sierra class with deserialized ABI.
///
/// This struct represents a Sierra contract class with the ABI field deserialized
/// into a proper contract ABI structure rather than a JSON string.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlattenedSierraClassWithAbi {
    /// The list of Sierra instructions that make up the program.
    pub sierra_program: Vec<Felt>,
    /// The version of the contract class object. Currently, Starknet supports version 0.1.0.
    pub contract_class_version: String,
    /// Entry points organized by type (external, constructor, L1 handler).
    pub entry_points_by_type: EntryPointsByType,
    /// The contract ABI, deserialized from JSON.
    pub abi: Option<cairo_lang_starknet_classes::abi::Contract>,
}

impl TryFrom<&FlattenedSierraClass> for FlattenedSierraClassWithAbi {
    type Error = serde_json::error::Error;

    fn try_from(sierra_class: &FlattenedSierraClass) -> Result<Self, Self::Error> {
        let abi: Option<cairo_lang_starknet_classes::abi::Contract> =
            serde_json::from_str(&sierra_class.abi).unwrap_or_default();

        Ok(Self {
            sierra_program: sierra_class.sierra_program.clone(),
            contract_class_version: sierra_class.contract_class_version.clone(),
            entry_points_by_type: sierra_class.entry_points_by_type.clone(),
            abi,
        })
    }
}

impl Serialize for GenericSierraContractClass {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Try to serialize using CairoLang class first
        if let Some(cairo_lang_class) = self.cairo_lang_contract_class.get() {
            cairo_lang_class.serialize(serializer)
        } else if let Some(starknet_core_class) = self.starknet_core_contract_class.get() {
            // Fall back to StarknetCore class with ABI deserialization
            let class_with_abi = FlattenedSierraClassWithAbi::try_from(starknet_core_class.as_ref())
                .map_err(|e| Error::custom(e.to_string()))?;
            class_with_abi.serialize(serializer)
        } else {
            Err(Error::custom("No contract class available for serialization"))
        }
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
            cairo_lang_contract_class: OnceCell::from(Arc::new(cairo_lang_class)),
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
            starknet_core_contract_class: OnceCell::from(Arc::new(starknet_core_class)),
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
