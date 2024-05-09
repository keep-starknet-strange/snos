use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use sha3::Digest as _;
use starknet_api::{core::ClassHash, deprecated_contract_class::ContractClass as DeprecatedCompiledClass, hash::{poseidon_hash_array, StarkFelt}, state::{ContractClass, EntryPointType}};
use starknet_crypto::FieldElement;

use crate::storage::storage::{DbObject, Fact, HashFunctionType, Storage};

/// Represents a single deprecated compiled contract class which is stored in the Starknet state.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeprecatedCompiledClassFact {
    contract_definition: DeprecatedCompiledClass,
}

impl DbObject for DeprecatedCompiledClassFact {}
impl<S, H> Fact<S, H> for DeprecatedCompiledClassFact
where
    S: Storage,
    H: HashFunctionType,
{
    fn hash(&self) -> Vec<u8> {
        calculate_class_hash(&self.contract_definition).0.bytes().into()
    }
}

lazy_static! {
    static ref API_VERSION: StarkFelt = StarkFelt::from(
        FieldElement::from_byte_slice_be(b"CONTRACT_CLASS_V0.1.0")
            .expect("CONTRACT_CLASS_V0.1.0 is valid StarkFelt."),
    );
}

/// Calculate the hash of a contract (v0 or v1). Inspired by the Papyrus implementation.
pub fn calculate_class_hash(class: &ContractClass) -> ClassHash {
    let external_entry_points_hash = entry_points_hash(class, &EntryPointType::External);
    let l1_handler_entry_points_hash = entry_points_hash(class, &EntryPointType::L1Handler);
    let constructor_entry_points_hash = entry_points_hash(class, &EntryPointType::Constructor);
    let abi_keccak = sha3::Keccak256::default().chain_update(class.abi.as_bytes()).finalize();
    let abi_hash = truncated_keccak(abi_keccak.into());
    let program_hash = poseidon_hash_array(class.sierra_program.as_slice());

    let class_hash = poseidon_hash_array(&[
        *API_VERSION,
        external_entry_points_hash.0,
        l1_handler_entry_points_hash.0,
        constructor_entry_points_hash.0,
        abi_hash,
        program_hash.0,
    ]);
    // TODO: Modify ClassHash Be be PoseidonHash instead of StarkFelt.
    ClassHash(class_hash.0)
}

fn entry_points_hash(class: &ContractClass, entry_point_type: &EntryPointType) -> starknet_api::hash::PoseidonHash {
    poseidon_hash_array(
        class
            .entry_point_by_type
            .get(entry_point_type)
            .unwrap_or(&vec![])
            .iter()
            .flat_map(|ep| [ep.selector.0, usize_into_felt(ep.function_idx.0)])
            .collect::<Vec<_>>()
            .as_slice(),
    )
}

// Python code masks with (2**250 - 1) which starts 0x03 and is followed by 31 0xff in be.
// Truncation is needed not to overflow the field element.
fn truncated_keccak(mut plain: [u8; 32]) -> StarkFelt {
    plain[0] &= 0x03;
    StarkFelt::new(plain).unwrap()
}

pub(crate) fn usize_into_felt(u: usize) -> StarkFelt {
    u128::try_from(u).expect("Expect at most 128 bits").into()
}
