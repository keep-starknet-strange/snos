use std::collections::HashMap;

use cairo_vm::types::program::Program;
use cairo_vm::Felt252;
use getset::{CopyGetters, Getters};
use starknet_api::deprecated_contract_class::ContractClassAbiEntry;
use starknet_crypto::{pedersen_hash, FieldElement};
use thiserror::Error;

pub type AbiType = Vec<ContractClassAbiEntry>;

#[derive(Debug, Error)]
pub enum HashError {
    #[error("Failed to compute hash {0}")]
    FailedToComputeHash(String),
}

#[derive(Debug, Error)]
pub enum ContractAddressError {
    #[error("None existing EntryPointType")]
    NoneExistingEntryPointType,
    #[error("Invalid offset: {0}")]
    InvalidOffset(usize),
    #[error("Could not remove suffix from builtin")]
    BuiltinSuffix,
    #[error("MaybeRelocatable is not an Int variant")]
    NoneIntMaybeRelocatable,
    #[error("Couldn't compute hash: {0}")]
    HashError(HashError),
}
impl From<HashError> for ContractAddressError {
    fn from(error: HashError) -> Self {
        ContractAddressError::HashError(error)
    }
}

#[derive(Clone, CopyGetters, Debug, Default, Eq, Getters, Hash, PartialEq)]
pub struct ContractEntryPoint {
    #[getset(get = "pub")]
    selector: Felt252,
    #[getset(get_copy = "pub")]
    offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryPointType {
    External,
    L1Handler,
    Constructor,
}

#[derive(Clone, Debug, Eq, Getters, PartialEq)]
pub struct ContractClass {
    #[getset(get = "pub")]
    pub(crate) program: Program,
    #[getset(get = "pub")]
    pub(crate) hinted_class_hash: Felt252,
    #[getset(get = "pub")]
    pub(crate) entry_points_by_type: HashMap<EntryPointType, Vec<ContractEntryPoint>>,
    #[getset(get = "pub")]
    pub(crate) abi: Option<AbiType>,
}

/// Computes Pedersen hash for a slice of `Felt252` elements.
///
/// # Arguments
///
/// * `vec` - A slice of `Felt252` elements representing the input vector.
///
/// # Returns
///
/// Returns a `Result` containing the computed Pedersen hash value as `Felt252`.
/// If any errors occur during the conversion or hash computation, an `Err` variant containing a
/// `SyscallHandlerError` is returned.
///
/// # Examples
///
/// ```
/// use starknet_in_rust::hash_utils::compute_hash_on_elements;
/// use starknet_in_rust::Felt252;
///
/// let input_vec = vec![Felt252::from(10_u16), Felt252::from(20_u16), Felt252::from(30_u16)];
///
/// match compute_hash_on_elements(&input_vec) {
///     Ok(hash_value) => {
///         println!("Computed hash value: {:?}", hash_value);
///     }
///     Err(err) => {
///         println!("Error occurred: {:?}", err);
///     }
/// }
/// ```
#[allow(unused)]
pub fn compute_hash_on_elements(vec: &[Felt252]) -> Result<Felt252, HashError> {
    let mut felt_vec = vec
        .iter()
        .map(|num| {
            FieldElement::from_bytes_be(&num.to_bytes_be()).map_err(|e| HashError::FailedToComputeHash(e.to_string()))
        })
        .collect::<Result<Vec<FieldElement>, HashError>>()?;

    felt_vec.push(FieldElement::from(felt_vec.len()));
    felt_vec.insert(0, FieldElement::from(0_u16));

    let felt_result = felt_vec
        .into_iter()
        .reduce(|x, y| pedersen_hash(&x, &y))
        .ok_or_else(|| HashError::FailedToComputeHash("Failed to compute Pedersen hash.".to_string()))?;

    let result = Felt252::from_bytes_be(&felt_result.to_bytes_be());
    Ok(result)
}

/// Instead of doing a Mask with 250 bits, we are only masking the most significant byte.
#[allow(unused)]
pub const MASK_3: u8 = 0x03;

/// Returns the contract entry points.
#[allow(unused)]
fn get_contract_entry_points(
    contract_class: &ContractClass,
    entry_point_type: &EntryPointType,
) -> Result<Vec<ContractEntryPoint>, ContractAddressError> {
    let entry_points = contract_class
        .entry_points_by_type()
        .get(entry_point_type)
        .ok_or(ContractAddressError::NoneExistingEntryPointType)?;

    let program_len = contract_class.program().iter_data().count();

    for entry_point in entry_points {
        if entry_point.offset() > program_len {
            return Err(ContractAddressError::InvalidOffset(entry_point.offset()));
        }
    }
    Ok(entry_points.to_owned())
}

/// Returns the hashed entry points of a contract class.
#[allow(unused)]
fn get_contract_entry_points_hashed(
    contract_class: &ContractClass,
    entry_point_type: &EntryPointType,
) -> Result<Felt252, ContractAddressError> {
    Ok(compute_hash_on_elements(
        &get_contract_entry_points(contract_class, entry_point_type)?
            .iter()
            .flat_map(|contract_entry_point| {
                vec![*contract_entry_point.selector(), Felt252::from(contract_entry_point.offset())]
            })
            .collect::<Vec<Felt252>>(),
    )?)
}

/// Compute the hash for a deprecated contract class.
#[allow(unused)]
pub fn compute_deprecated_class_hash(contract_class: &ContractClass) -> Result<Felt252, ContractAddressError> {
    // Deprecated API version.
    let api_version = Felt252::ZERO;

    // Entrypoints by type, hashed.
    let external_functions = get_contract_entry_points_hashed(contract_class, &EntryPointType::External)?;
    let l1_handlers = get_contract_entry_points_hashed(contract_class, &EntryPointType::L1Handler)?;
    let constructors = get_contract_entry_points_hashed(contract_class, &EntryPointType::Constructor)?;

    // Builtin list but with the "_builtin" suffix removed.
    // This could be Vec::with_capacity when using the latest version of cairo-vm which includes
    // .builtins_len() method for Program.
    let mut builtin_list_vec = Vec::new();

    for builtin_name in contract_class.program().iter_builtins() {
        builtin_list_vec.push(Felt252::from_bytes_be_slice(
            builtin_name.name().strip_suffix("_builtin").ok_or(ContractAddressError::BuiltinSuffix)?.as_bytes(),
        ));
    }

    let builtin_list = compute_hash_on_elements(&builtin_list_vec)?;

    let hinted_class_hash = contract_class.hinted_class_hash();

    let mut bytecode_vector = Vec::new();

    for data in contract_class.program().iter_data() {
        bytecode_vector.push(*data.get_int_ref().ok_or(ContractAddressError::NoneIntMaybeRelocatable)?);
    }

    let bytecode = compute_hash_on_elements(&bytecode_vector)?;

    let flatted_contract_class: Vec<Felt252> =
        vec![api_version, external_functions, l1_handlers, constructors, builtin_list, *hinted_class_hash, bytecode];

    Ok(compute_hash_on_elements(&flatted_contract_class)?)
}

// #[cfg(test)]
// mod tests {
// use super::*;
// use cairo_vm::Felt252;
// use coverage_helper::test;
//
// #[test]
// fn test_compute_hinted_class_hash_with_abi() {
// let contract_class =
// ContractClass::from_path("starknet_programs/raw_contract_classes/class_with_abi.json")
// .unwrap();
//
// assert_eq!(
// contract_class.hinted_class_hash(),
// &Felt252::from_dec_str(
// "1164033593603051336816641706326288678020608687718343927364853957751413025239",
// )
// .unwrap()
// );
// }
//
// #[test]
// fn test_compute_class_hash_1354433237b0039baa138bf95b98fe4a8ae3df7ac4fd4d4845f0b41cd11bec4() {
// let contract_class =
// ContractClass::from_path("starknet_programs/raw_contract_classes/
// 0x1354433237b0039baa138bf95b98fe4a8ae3df7ac4fd4d4845f0b41cd11bec4.json").unwrap();
//
// assert_eq!(
// compute_deprecated_class_hash(&contract_class).unwrap(),
// Felt252::from_hex("1354433237b0039baa138bf95b98fe4a8ae3df7ac4fd4d4845f0b41cd11bec4")
// .unwrap()
// );
// }
//
// #[test]
// fn test_compute_class_hash_0x03131fa018d520a037686ce3efddeab8f28895662f019ca3ca18a626650f7d1e()
// {
// let contract_class =
// ContractClass::from_path("starknet_programs/raw_contract_classes/
// 0x03131fa018d520a037686ce3efddeab8f28895662f019ca3ca18a626650f7d1e.json").unwrap();
//
// assert_eq!(
// compute_deprecated_class_hash(&contract_class).unwrap(),
// Felt252::from_hex("03131fa018d520a037686ce3efddeab8f28895662f019ca3ca18a626650f7d1e")
// .unwrap()
// );
// }
//
// #[test]
// fn test_compute_class_hash_0x025ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918()
// {
// let contract_class =
// ContractClass::from_path("starknet_programs/raw_contract_classes/
// 0x025ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918.json").unwrap();
//
// assert_eq!(
// compute_deprecated_class_hash(&contract_class).unwrap(),
// Felt252::from_hex(
// "0x025ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918",
// )
// .unwrap()
// );
// }
//
// #[test]
// fn test_compute_class_hash_0x02c3348ad109f7f3967df6494b3c48741d61675d9a7915b265aa7101a631dc33()
// {
// let contract_class =
// ContractClass::from_path("starknet_programs/raw_contract_classes/
// 0x02c3348ad109f7f3967df6494b3c48741d61675d9a7915b265aa7101a631dc33.json").unwrap();
//
// assert_eq!(
// compute_deprecated_class_hash(&contract_class).unwrap(),
// Felt252::from_hex("0x02c3348ad109f7f3967df6494b3c48741d61675d9a7915b265aa7101a631dc33")
// .unwrap()
// );
// }
//
// This was the contract class that caused an outage in Mainnet.
// More info in EqLabs report: https://eqlabs.github.io/pathfinder/blog/2023-06-17_mainnet_incident.html
// #[test]
// fn test_compute_class_hash_0x00801ad5dc7c995addf7fbce1c4c74413586acb44f9ff44ba903a08a6153fa80()
// {
// let contract_class =
// ContractClass::from_path("starknet_programs/raw_contract_classes/
// 0x00801ad5dc7c995addf7fbce1c4c74413586acb44f9ff44ba903a08a6153fa80.json").unwrap();
//
// assert_eq!(
// compute_deprecated_class_hash(&contract_class).unwrap(),
// Felt252::from_dec_str(
// "226341635385251092193534262877925620859725853394183386505497817801290939008"
// )
// .unwrap()
// );
// }
//
// #[test]
// fn test_compute_class_hash_0x4d07e40e93398ed3c76981e72dd1fd22557a78ce36c0515f679e27f0bb5bc5f_mainnet(
// ) {
// let contract_class = ContractClass::from_path(
// "starknet_programs/raw_contract_classes/
// 0x04d07e40e93398ed3c76981e72dd1fd22557a78ce36c0515f679e27f0bb5bc5f_mainnet.json" ).unwrap();
//
// assert_eq!(
// compute_deprecated_class_hash(&contract_class).unwrap(),
// Felt252::from_hex("0x4d07e40e93398ed3c76981e72dd1fd22557a78ce36c0515f679e27f0bb5bc5f",)
// .unwrap()
// );
// }
//
// #[test]
// fn test_compute_class_hash_0x4d07e40e93398ed3c76981e72dd1fd22557a78ce36c0515f679e27f0bb5bc5f_goerli(
// ) {
// let contract_class = ContractClass::from_path(
// "starknet_programs/raw_contract_classes/
// 0x04d07e40e93398ed3c76981e72dd1fd22557a78ce36c0515f679e27f0bb5bc5f_goerli.json" ).unwrap();
//
// assert_eq!(
// compute_deprecated_class_hash(&contract_class).unwrap(),
// Felt252::from_hex("0x4d07e40e93398ed3c76981e72dd1fd22557a78ce36c0515f679e27f0bb5bc5f")
// .unwrap()
// );
// }
// }
