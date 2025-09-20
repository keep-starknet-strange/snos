//! Utilities for computing class hashes and related operations.

use starknet_core::types::SierraEntryPoint;
use starknet_core::utils::starknet_keccak;
use starknet_crypto::poseidon_hash_many;
use starknet_os::io::os_input::ContractClassComponentHashes as OsContractClassComponentHashes;
use starknet_patricia::hash::hash_trait::HashOutput;
use starknet_types_core::felt::Felt;

/// The prefix used for contract class version strings.
const CLASS_VERSION_PREFIX: &str = "CONTRACT_CLASS_V";

/// Computes a hash over a list of Sierra entry points.
///
/// This function flattens the entry points into a sequence of selectors and function indices,
/// then computes a Poseidon hash over the resulting felts.
///
/// # Arguments
///
/// * `entry_points` - An iterator over Sierra entry points
///
/// # Returns
///
/// A `Felt` representing the hash of the entry points.
///
/// # Example
///
/// ```rust
/// use starknet_core::types::SierraEntryPoint;
/// use starknet_types_core::felt::Felt;
///
/// # // Redefining, for example
/// # fn compute_hash_on_sierra_entry_points<'a, EntryPoints: Iterator<Item = &'a SierraEntryPoint>>(
/// #     entry_points: EntryPoints,
/// # ) -> Felt {
/// #     Felt::from(0)
/// # }
///
/// let entry_points = vec![
///     SierraEntryPoint {
///         selector: Felt::from(1u64),
///         function_idx: 0,
///     },
///     SierraEntryPoint {
///         selector: Felt::from(2u64),
///         function_idx: 1,
///     },
/// ];
///
/// let hash = compute_hash_on_sierra_entry_points(entry_points.iter());
/// ```
pub fn compute_hash_on_sierra_entry_points<'a, EntryPoints: Iterator<Item = &'a SierraEntryPoint>>(
    entry_points: EntryPoints,
) -> Felt {
    let flat_entry_points: Vec<Felt> =
        entry_points.flat_map(|entry_point| [entry_point.selector, Felt::from(entry_point.function_idx)]).collect();

    poseidon_hash_many(flat_entry_points.iter())
}

/// Computes a Keccak hash of the ABI string.
///
/// # Arguments
///
/// * `abi` - The ABI string to hash
///
/// # Returns
///
/// A `Felt` representing the hash of the ABI.
fn hash_abi(abi: &str) -> Felt {
    starknet_keccak(abi.as_bytes())
}

/// Holds the component hashes of a contract class for final hash calculation.
///
/// This struct contains the individual hashes of each component of a Sierra contract class.
/// The order of the struct members is critical as it determines the hash computation order.
///
/// # Note
///
/// The order of struct members must not be changed as it affects the final hash computation.
#[derive(Debug, Clone, PartialEq)]
pub struct ContractClassComponentHashes {
    /// Hash of the contract class version string.
    contract_class_version: Felt,
    /// Hash of external function entry points.
    external_functions_hash: Felt,
    /// Hash of L1 handler entry points.
    l1_handlers_hash: Felt,
    /// Hash of constructor entry points.
    constructors_hash: Felt,
    /// Hash of the ABI.
    abi_hash: Felt,
    /// Hash of the Sierra program.
    sierra_program_hash: Felt,
}

impl ContractClassComponentHashes {
    /// Converts the component hashes to a vector in the correct order.
    ///
    /// # Returns
    ///
    /// A vector containing all component hashes in the order required for final hash computation.
    #[must_use]
    pub fn to_vec(self) -> Vec<Felt> {
        vec![
            self.contract_class_version,
            self.external_functions_hash,
            self.l1_handlers_hash,
            self.constructors_hash,
            self.abi_hash,
            self.sierra_program_hash,
        ]
    }

    /// Returns a reference to the contract class version hash.
    #[must_use]
    pub fn contract_class_version(&self) -> &Felt {
        &self.contract_class_version
    }

    /// Returns a reference to the external functions hash.
    #[must_use]
    pub fn external_functions_hash(&self) -> &Felt {
        &self.external_functions_hash
    }

    /// Returns a reference to the L1 handlers hash.
    #[must_use]
    pub fn l1_handlers_hash(&self) -> &Felt {
        &self.l1_handlers_hash
    }

    /// Returns a reference to the constructor's hash.
    #[must_use]
    pub fn constructors_hash(&self) -> &Felt {
        &self.constructors_hash
    }

    /// Returns a reference to the ABI hash.
    #[must_use]
    pub fn abi_hash(&self) -> &Felt {
        &self.abi_hash
    }

    /// Returns a reference to the Sierra program hash.
    #[must_use]
    pub fn sierra_program_hash(&self) -> &Felt {
        &self.sierra_program_hash
    }

    /// Converts this `ContractClassComponentHashes` to the OS version.
    pub fn to_os_format(&self) -> OsContractClassComponentHashes {
        OsContractClassComponentHashes {
            contract_class_version: self.contract_class_version,
            external_functions_hash: HashOutput(self.external_functions_hash),
            l1_handlers_hash: HashOutput(self.l1_handlers_hash),
            constructors_hash: HashOutput(self.constructors_hash),
            abi_hash: HashOutput(self.abi_hash),
            sierra_program_hash: HashOutput(self.sierra_program_hash),
        }
    }
}

impl From<starknet_core::types::FlattenedSierraClass> for ContractClassComponentHashes {
    fn from(sierra_class: starknet_core::types::FlattenedSierraClass) -> Self {
        // Create the version string and hash it
        let version_str = format!("{CLASS_VERSION_PREFIX}{}", sierra_class.contract_class_version);
        let contract_class_version = Felt::from_bytes_be_slice(version_str.as_bytes());

        // Hash the Sierra program
        let sierra_program_hash = poseidon_hash_many(sierra_class.sierra_program.iter());

        Self {
            contract_class_version,
            external_functions_hash: compute_hash_on_sierra_entry_points(
                sierra_class.entry_points_by_type.external.iter(),
            ),
            l1_handlers_hash: compute_hash_on_sierra_entry_points(sierra_class.entry_points_by_type.l1_handler.iter()),
            constructors_hash: compute_hash_on_sierra_entry_points(
                sierra_class.entry_points_by_type.constructor.iter(),
            ),
            abi_hash: hash_abi(&sierra_class.abi),
            sierra_program_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use starknet_core::types::contract::SierraClass;

    use super::*;

    const TEST_CONTRACT_SIERRA_CLASS: &[u8] = include_bytes!("../../../resources/test_contract.sierra");
    const EMPTY_CONTRACT_SIERRA_CLASS: &[u8] = include_bytes!("../../../resources/empty_contract.sierra");

    /// Tests that component hashing works correctly.
    ///
    /// The following hashes were generated manually by using the following Python snippet:
    /// ```python
    /// sierra_path = <path to test_contract.sierra>
    /// contract_class = load_sierra(sierra_path)
    /// py_compute_class_hash(contract_class)
    /// ```
    #[rstest]
    #[case::test_contract(
        TEST_CONTRACT_SIERRA_CLASS,
        ContractClassComponentHashes {
            contract_class_version: Felt::from_hex_unchecked("0x434f4e54524143545f434c4153535f56302e312e30"),
            external_functions_hash: Felt::from_hex_unchecked("0x22ea1c879b5fdb2f25faa8c85f749e4d9e5216827e4920456523679da537054"),
            l1_handlers_hash: Felt::from_hex_unchecked("0x5a1be23d9907cf863d6547a10e0da2e5b20f2e2a3079102e98c46b4eab8d9a3"),
            constructors_hash: Felt::from_hex_unchecked("0x32efa33857ba35a456c993af69ba93f2f936a4208070afb7b28fa10bcae83f0"),
            abi_hash: Felt::from_hex_unchecked("0x6e6ccf79d27ce45711cda5964b29bf1558f01938ca005bee0ae17de6915199"),
            sierra_program_hash: Felt::from_hex_unchecked("0x50d763c8720c24bb5c895be3dbfd68d296499a381d1e00ff626be93fbbec762"),
        }
    )]
    #[case::empty_contract(
        EMPTY_CONTRACT_SIERRA_CLASS,
        ContractClassComponentHashes {
            contract_class_version: Felt::from_hex_unchecked("0x434f4e54524143545f434c4153535f56302e312e30"),
            external_functions_hash: Felt::from_hex_unchecked("0x2272be0f580fd156823304800919530eaa97430e972d7213ee13f4fbf7a5dbc"),
            l1_handlers_hash: Felt::from_hex_unchecked("0x2272be0f580fd156823304800919530eaa97430e972d7213ee13f4fbf7a5dbc"),
            constructors_hash: Felt::from_hex_unchecked("0x2272be0f580fd156823304800919530eaa97430e972d7213ee13f4fbf7a5dbc"),
            abi_hash: Felt::from_hex_unchecked("0x21a74ba4fe8685313cf0f0c2a7da1284740c54d5009bd312585e6302274e946"),
            sierra_program_hash: Felt::from_hex_unchecked("0x49eead8efbb63e415f263237a9e6a010afa0557c69cabee04abbdbcb64c34e8"),
        }
    )]
    fn test_component_hashes_from_sierra_class(
        #[case] sierra_class_bytes: &[u8],
        #[case] expected_component_hashes: ContractClassComponentHashes,
    ) {
        let sierra_class: SierraClass = serde_json::from_slice(sierra_class_bytes).unwrap();
        let flattened_sierra_class = sierra_class.flatten().unwrap();

        let component_hashes = ContractClassComponentHashes::from(flattened_sierra_class);
        assert_eq!(component_hashes, expected_component_hashes);
    }

    #[test]
    fn test_component_hashes_getters() {
        let component_hashes = ContractClassComponentHashes {
            contract_class_version: Felt::from(1u64),
            external_functions_hash: Felt::from(2u64),
            l1_handlers_hash: Felt::from(3u64),
            constructors_hash: Felt::from(4u64),
            abi_hash: Felt::from(5u64),
            sierra_program_hash: Felt::from(6u64),
        };

        assert_eq!(*component_hashes.contract_class_version(), Felt::from(1u64));
        assert_eq!(*component_hashes.external_functions_hash(), Felt::from(2u64));
        assert_eq!(*component_hashes.l1_handlers_hash(), Felt::from(3u64));
        assert_eq!(*component_hashes.constructors_hash(), Felt::from(4u64));
        assert_eq!(*component_hashes.abi_hash(), Felt::from(5u64));
        assert_eq!(*component_hashes.sierra_program_hash(), Felt::from(6u64));
    }

    #[test]
    fn test_component_hashes_to_vec() {
        let component_hashes = ContractClassComponentHashes {
            contract_class_version: Felt::from(1u64),
            external_functions_hash: Felt::from(2u64),
            l1_handlers_hash: Felt::from(3u64),
            constructors_hash: Felt::from(4u64),
            abi_hash: Felt::from(5u64),
            sierra_program_hash: Felt::from(6u64),
        };

        let vec = component_hashes.to_vec();
        assert_eq!(vec.len(), 6);
        assert_eq!(vec[0], Felt::from(1u64));
        assert_eq!(vec[1], Felt::from(2u64));
        assert_eq!(vec[2], Felt::from(3u64));
        assert_eq!(vec[3], Felt::from(4u64));
        assert_eq!(vec[4], Felt::from(5u64));
        assert_eq!(vec[5], Felt::from(6u64));
    }
}
