use lazy_static::lazy_static;
use sha3::Digest as _;
use starknet_api::{core::ClassHash, deprecated_contract_class::ContractClass as DeprecatedCompiledClass, hash::{pedersen_hash_array, poseidon_hash_array, StarkFelt}, deprecated_contract_class::EntryPointType};
use starknet_crypto::FieldElement;

lazy_static! {
    // TODO: is this the same for deprecated class hash?
    static ref API_VERSION: StarkFelt = StarkFelt::from(
        FieldElement::from_byte_slice_be(b"CONTRACT_CLASS_V0.1.0")
            .expect("CONTRACT_CLASS_V0.1.0 is valid StarkFelt."),
    );
}

/// Calculate the hash of a contract v0. Inspired by the Papyrus implementation.
/// TODO: WARNING: this needs to be rewritten, there are many details missing. It's definitely wrong.
pub fn calculate_deprecated_class_hash(class: &DeprecatedCompiledClass) -> ClassHash {
    let mut hash_chain = Vec::new();
    hash_chain.push(*API_VERSION);

    hash_chain.push(deprecated_entry_points_hash(class, &EntryPointType::External).0);
    hash_chain.push(deprecated_entry_points_hash(class, &EntryPointType::L1Handler).0);
    hash_chain.push(deprecated_entry_points_hash(class, &EntryPointType::Constructor).0);

    // TODO: review -- what should be done when no ABI is given?
    if let Some(abi) = &class.abi {
        // TODO: wrong
        let abi_serialized = serde_json::to_string(&abi).expect("Serialized Cairo0 program should be deserializable");

        let abi_keccak = sha3::Keccak256::default().chain_update(abi_serialized.as_bytes()).finalize();
        let as_bytes: [u8; 32] = abi_keccak[..32].try_into().unwrap();
        hash_chain.push(truncated_keccak(as_bytes));
    }

    // TODO: definitely wrong...
    let bytecode_hash = pedersen_hash_array(&serde_json::to_string(&class.program.data).unwrap().as_bytes().into_iter().map(|b| StarkFelt::from(*b)).collect::<Vec<StarkFelt>>()[..]);
    hash_chain.push(bytecode_hash);

    let class_hash = pedersen_hash_array(&hash_chain[..]);
    // TODO: Modify ClassHash Be be PoseidonHash instead of StarkFelt.
    ClassHash(class_hash.into())
}

fn deprecated_entry_points_hash(class: &DeprecatedCompiledClass, entry_point_type: &EntryPointType) -> starknet_api::hash::PoseidonHash {
    poseidon_hash_array(
        class
            .entry_points_by_type
            .get(entry_point_type)
            .unwrap_or(&vec![])
            .iter()
            .flat_map(|ep| [ep.selector.0, usize_into_felt(ep.offset.0)])
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
