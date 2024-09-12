use starknet_core::types::SierraEntryPoint;
use starknet_core::utils::starknet_keccak;
use starknet_crypto::{poseidon_hash_many, FieldElement};
use starknet_types_core::felt::Felt;

const CLASS_VERSION_PREFIX: &str = "CONTRACT_CLASS_V";

/// A convenience function that computes a Poseidon hash over Felts rather than starknet-crypto
/// FieldElement types. There is no `From` implementation between these types so this function
/// masks some ugly byte mashing.
fn poseidon_hash_many_felts<FeltIter: Iterator<Item = Felt>>(felts: FeltIter) -> Felt {
    let field_elements: Vec<_> = felts.map(|x| FieldElement::from_bytes_be(&x.to_bytes_be()).unwrap()).collect();
    let hash = poseidon_hash_many(&field_elements);

    Felt::from_bytes_be(&hash.to_bytes_be())
}

/// Computes hash on a list of given entry points (starknet-core types).
fn compute_hash_on_sierra_entry_points<'a, EntryPoints: Iterator<Item = &'a SierraEntryPoint>>(
    entry_points: EntryPoints,
) -> Felt {
    let flat_entry_points =
        entry_points.flat_map(|entry_point| [entry_point.selector, Felt::from(entry_point.function_idx)]);

    poseidon_hash_many_felts(flat_entry_points)
}

fn hash_abi(abi: &str) -> Felt {
    starknet_keccak(abi.as_bytes())
}

/// Holds the hashes of the contract class components, to be used for calculating the final hash.
/// Note: the order of the struct member must not be changed since it determines the hash order.
#[derive(Debug, PartialEq)]
pub struct ContractClassComponentHashes {
    contract_class_version: Felt,
    external_functions_hash: Felt,
    l1_handlers_hash: Felt,
    constructors_hash: Felt,
    abi_hash: Felt,
    sierra_program_hash: Felt,
}

impl ContractClassComponentHashes {
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
}

impl From<starknet_core::types::FlattenedSierraClass> for ContractClassComponentHashes {
    fn from(sierra_class: starknet_core::types::FlattenedSierraClass) -> Self {
        let version_str = format!("{CLASS_VERSION_PREFIX}{}", sierra_class.contract_class_version);
        let contract_class_version = Felt::from_bytes_be_slice(version_str.as_bytes());

        let sierra_program_hash = poseidon_hash_many_felts(sierra_class.sierra_program.into_iter());

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

    const TEST_CONTRACT_SIERRA_CLASS: &[u8] = include_bytes!(
        "../../../tests/integration/contracts/blockifier_contracts/feature_contracts/cairo1/compiled/test_contract.\
         sierra"
    );

    const EMPTY_CONTRACT_SIERRA_CLASS: &[u8] = include_bytes!(
        "../../../tests/integration/contracts/blockifier_contracts/feature_contracts/cairo1/compiled/empty_contract.\
         sierra"
    );

    /// Tests that component hashing works.
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
            external_functions_hash: Felt::from_hex_unchecked("0x370b584bc5249817d1e14a4af2313713d26f5ff2a23706cd3a4245f7b941119"),
            l1_handlers_hash: Felt::from_hex_unchecked("0x2461f0657352958f4bd24f8bc8e595f9b0282f89d108a3a1c56c7c36a991c51"),
            constructors_hash: Felt::from_hex_unchecked("0x33307d0ffeafc7e10284cf096023309a5b7a3c8dec507551518e4d3965a660"),
            abi_hash: Felt::from_hex_unchecked("0x3993a88597ef45083b570b7c265cc641dc7dd91795540f0b1eea5c85437c8ac"),
            sierra_program_hash: Felt::from_hex_unchecked("0x44dadb1dfc3bd7f8b3cd171a346d7bdaa94dcc3805dee9f538fa0cef60a0072"),
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
        assert_eq!(component_hashes, expected_component_hashes)
    }
}
