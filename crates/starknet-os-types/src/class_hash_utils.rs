use cairo_lang_starknet_classes::contract_class::ContractEntryPoint;
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
        entry_points.flat_map(|entry_point| [Felt::from(entry_point.selector), Felt::from(entry_point.function_idx)]);

    poseidon_hash_many_felts(flat_entry_points)
}

/// Computes hash on a list of given entry points (cairo-lang types).
fn compute_hash_on_contract_entry_points<'a, EntryPoints: Iterator<Item = &'a ContractEntryPoint>>(
    entry_points: EntryPoints,
) -> Felt {
    let flat_entry_points = entry_points
        .flat_map(|entry_point| [Felt::from(entry_point.selector.clone()), Felt::from(entry_point.function_idx)]);

    poseidon_hash_many_felts(flat_entry_points)
}

fn hash_abi(abi: &str) -> Felt {
    starknet_keccak(abi.as_bytes())
}

/// Holds the hashes of the contract class components, to be used for calculating the final hash.
/// Note: the order of the struct member must not be changed since it determines the hash order.
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

impl From<cairo_lang_starknet_classes::contract_class::ContractClass> for ContractClassComponentHashes {
    fn from(contract_class: cairo_lang_starknet_classes::contract_class::ContractClass) -> Self {
        let version_str = format!("{CLASS_VERSION_PREFIX}{}", contract_class.contract_class_version);
        let contract_class_version = Felt::from_bytes_be_slice(version_str.as_bytes());

        let sierra_program_hash =
            poseidon_hash_many_felts(contract_class.sierra_program.into_iter().map(|x| Felt::from(x.value)));

        let abi_str = match contract_class.abi {
            Some(abi) => serde_json::to_string(&abi).unwrap(),
            None => String::new(),
        };

        Self {
            contract_class_version,
            external_functions_hash: compute_hash_on_contract_entry_points(
                contract_class.entry_points_by_type.external.iter(),
            ),
            l1_handlers_hash: compute_hash_on_contract_entry_points(
                contract_class.entry_points_by_type.l1_handler.iter(),
            ),
            constructors_hash: compute_hash_on_contract_entry_points(
                contract_class.entry_points_by_type.constructor.iter(),
            ),
            abi_hash: hash_abi(&abi_str),
            sierra_program_hash,
        }
    }
}
