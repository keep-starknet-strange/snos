//! Generic compiled class types for both Cairo 0 and Cairo 1 contracts.

use crate::casm_contract_class::GenericCasmContractClass;
use crate::deprecated_compiled_class::GenericDeprecatedCompiledClass;
use crate::error::ContractClassError;
use crate::hash::GenericClassHash;

/// A generic compiled class that can represent either Cairo 0 or Cairo 1 contract classes.
///
/// This enum provides a unified interface for working with different contract class formats,
/// allowing for type-safe handling of both legacy Cairo 0 contracts and modern Cairo 1 contracts.
///
/// # Examples
///
/// ```rust
/// use starknet_os_types::compiled_class::GenericCompiledClass;
/// use starknet_os_types::casm_contract_class::GenericCasmContractClass;
///
/// // Create a Cairo 1 compiled class
/// let casm_bytes = include_bytes!("path/to/contract.casm.json");
/// let casm_class = GenericCasmContractClass::from_bytes(casm_bytes.to_vec());
/// let compiled_class = GenericCompiledClass::Cairo1(casm_class);
///
/// // Compute the class hash
/// let class_hash = compiled_class.class_hash()?;
/// ```
#[derive(Clone, Debug)]
pub enum GenericCompiledClass {
    /// Cairo 0 legacy contract class (deprecated format).
    Cairo0(GenericDeprecatedCompiledClass),
    /// Cairo 1 compiled contract class (CASM format).
    Cairo1(GenericCasmContractClass),
}

impl GenericCompiledClass {
    /// Computes the class hash for this compiled class.
    ///
    /// The class hash is computed differently depending on the contract class type:
    /// - For Cairo 0 contracts: Uses the legacy hash computation algorithm
    /// - For Cairo 1 contracts: Uses the CASM hash computation algorithm
    ///
    /// # Returns
    ///
    /// Returns the computed class hash, or an error if the computation fails.
    ///
    /// # Errors
    ///
    /// Returns a `ContractClassError` if the class hash computation fails due to
    /// invalid contract data, serialization issues, or other internal errors.
    ///
    /// # Example
    ///
    /// ```rust
    /// use starknet_os_types::compiled_class::GenericCompiledClass;
    /// use starknet_os_types::casm_contract_class::GenericCasmContractClass;
    ///
    /// let compiled_class = GenericCompiledClass::Cairo1(GenericCasmContractClass::from_bytes(vec![0]);
    /// match compiled_class.class_hash() {
    ///     Ok(hash) => println!("Class hash: {:?}", hash),
    ///     Err(e) => eprintln!("Failed to compute class hash: {}", e),
    /// }
    /// ```
    pub fn class_hash(&self) -> Result<GenericClassHash, ContractClassError> {
        match self {
            GenericCompiledClass::Cairo0(deprecated_class) => deprecated_class.class_hash(),
            GenericCompiledClass::Cairo1(casm_class) => casm_class.class_hash(),
        }
    }

    /// Returns `true` if this is a Cairo 0 contract class.
    ///
    /// # Example
    ///
    /// ```rust
    /// use starknet_os_types::compiled_class::GenericCompiledClass;
    /// use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;
    ///
    /// let compiled_class = GenericCompiledClass::Cairo0(GenericDeprecatedCompiledClass::from_bytes(vec![0]));
    /// assert!(compiled_class.is_cairo0());
    /// ```
    #[must_use]
    pub fn is_cairo0(&self) -> bool {
        matches!(self, Self::Cairo0(_))
    }

    /// Returns `true` if this is a Cairo 1 contract class.
    ///
    /// # Example
    ///
    /// ```rust
    /// use starknet_os_types::compiled_class::GenericCompiledClass;
    /// use starknet_os_types::casm_contract_class::GenericCasmContractClass;
    ///
    /// let compiled_class = GenericCompiledClass::Cairo1(GenericCasmContractClass::from_bytes(vec![0]);
    /// assert!(compiled_class.is_cairo1());
    /// ```
    #[must_use]
    pub fn is_cairo1(&self) -> bool {
        matches!(self, Self::Cairo1(_))
    }
}
