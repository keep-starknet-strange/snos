use std::collections::HashMap;

use cairo_vm::types::relocatable::MaybeRelocatable;
use cairo_vm::vm::runners::builtin_runner::BuiltinRunner;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};

use crate::error::SnOsError;

const PREVIOUS_MERKLE_UPDATE_OFFSET: usize = 0;
const NEW_MERKLE_UPDATE_OFFSET: usize = 1;
const BLOCK_NUMBER_OFFSET: usize = 2;
const BLOCK_HASH_OFFSET: usize = 3;
const CONFIG_HASH_OFFSET: usize = 4;
const USE_KZG_DA_OFFSET: usize = 5;
const HEADER_SIZE: usize = 6;

/// Represents the changes in a contract instance.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ContractChanges {
    /// The address of the contract.
    pub addr: Felt252,
    /// The new nonce of the contract (for account contracts).
    pub nonce: Felt252,
    /// The new class hash (if changed).
    pub class_hash: Option<Felt252>,
    /// A map from storage key to its new value.
    pub storage_changes: HashMap<Felt252, Felt252>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct StarknetOsOutput {
    /// The root before.
    pub initial_root: Felt252,
    /// The root after.
    pub final_root: Felt252,
    /// The block number.
    pub block_number: Felt252,
    /// The block hash.
    pub block_hash: Felt252,
    /// The hash of the OS config.
    pub starknet_os_config_hash: Felt252,
    /// Whether KZG data availability was used.
    pub use_kzg_da: Felt252,
    /// Messages from L2 to L1.
    pub messages_to_l1: Vec<Felt252>,
    /// Messages from L1 to L2.
    pub messages_to_l2: Vec<Felt252>,
    /// The list of contracts that were changed.
    pub contracts: Vec<ContractChanges>,
    /// The list of classes that were declared. A map from class hash to compiled class hash.
    pub classes: HashMap<Felt252, Felt252>,
}

impl StarknetOsOutput {
    pub fn from_run(vm: &VirtualMachine) -> Result<Self, SnOsError> {
        let (output_base, output_size) = get_output_info(vm)?;
        let raw_output = get_raw_output(vm, output_base, output_size)?;
        decode_output(raw_output.into_iter())
    }
}

/// Gets the output base segment and the output size from the VM return values and the VM
/// output builtin.
fn get_output_info(vm: &VirtualMachine) -> Result<(usize, usize), SnOsError> {
    let n_builtins = vm.get_builtin_runners().len();
    let builtin_end_ptrs = vm.get_return_values(n_builtins).map_err(|e| SnOsError::CatchAll(e.to_string()))?;
    let output_base = vm
        .get_builtin_runners()
        .iter()
        .find(|&elt| matches!(elt, BuiltinRunner::Output(_)))
        .expect("Os vm should have the output builtin")
        .base();

    let output_size = match builtin_end_ptrs[0] {
        MaybeRelocatable::Int(_) => {
            return Err(SnOsError::CatchAll("expected a relocatable as output builtin end pointer".to_string()));
        }
        MaybeRelocatable::RelocatableValue(address) => {
            if address.segment_index as usize != output_base {
                return Err(SnOsError::CatchAll(format!(
                    "output builtin end pointer ({address}) is not on the expected segment ({output_base})"
                )));
            }
            address.offset
        }
    };

    Ok((output_base, output_size))
}

/// Gets the OS output as an array of felts based on the output base and size.
fn get_raw_output(vm: &VirtualMachine, output_base: usize, output_size: usize) -> Result<Vec<Felt252>, SnOsError> {
    // Get output and check that everything is an integer.
    let raw_output = vm.get_range((output_base as isize, 0).into(), output_size);
    let raw_output: Result<Vec<Felt252>, _> = raw_output
        .iter()
        .map(|x| {
            if let MaybeRelocatable::Int(val) = x.clone().unwrap().into_owned() {
                Ok(val)
            } else {
                Err(SnOsError::CatchAll("Output should be all integers".to_string()))
            }
        })
        .collect();

    raw_output
}

fn next_or_fail<T, I: Iterator<Item = T>>(output_iter: &mut I, item_name: &str) -> Result<T, SnOsError> {
    output_iter.next().ok_or(SnOsError::CatchAll(format!("Could not read {item_name} field")))
}

fn next_as_usize<I: Iterator<Item = Felt252>>(output_iter: &mut I, item_name: &str) -> Result<usize, SnOsError> {
    output_iter
        .next()
        .ok_or(SnOsError::CatchAll(format!("Could not read {item_name} segment size")))?
        .to_usize()
        .ok_or(SnOsError::CatchAll(format!("{item_name} segment size is too large")))
}

fn parse_contract_changes<I: Iterator<Item = Felt252>>(output_iter: &mut I) -> Result<ContractChanges, SnOsError> {
    let addr = next_or_fail(output_iter, "contract change addr")?;
    let class_nonce_n_changes = next_or_fail(output_iter, "contract change class_nonce_n_changes")?;

    let two_exp_64 =
        Felt252::from(1u128 << 64).try_into().expect("2**64 should be considered non-zero. Did you change the value?");
    let (class_nonce, n_changes) = class_nonce_n_changes.div_rem(&two_exp_64);
    let (class_updated, nonce) = class_nonce.div_rem(&two_exp_64);

    let class_hash = if class_updated != Felt252::ZERO {
        Some(next_or_fail(output_iter, "contract change class_hash")?)
    } else {
        None
    };

    let n_changes =
        n_changes.to_usize().expect("n_changes should be 64-bit by definition. Did you modify the parsing above?");
    let mut storage_changes = HashMap::with_capacity(n_changes);

    for i in 0..n_changes {
        let key = next_or_fail(output_iter, &format!("contract change key #{i}"))?;
        let value = next_or_fail(output_iter, &format!("contract change value #{i}"))?;

        storage_changes.insert(key, value);
    }

    Ok(ContractChanges { addr, nonce, class_hash, storage_changes })
}

fn parse_all_contract_changes<I: Iterator<Item = Felt252>>(
    output_iter: &mut I,
) -> Result<Vec<ContractChanges>, SnOsError> {
    let n_contract_changes = next_as_usize(output_iter, "contracts")?;
    let mut contracts = Vec::with_capacity(n_contract_changes);

    for _ in 0..n_contract_changes {
        contracts.push(parse_contract_changes(output_iter)?)
    }

    Ok(contracts)
}

fn parse_all_class_changes<I: Iterator<Item = Felt252>>(
    output_iter: &mut I,
) -> Result<HashMap<Felt252, Felt252>, SnOsError> {
    let n_class_changes = next_as_usize(output_iter, "classes")?;

    let mut classes = HashMap::new();

    for i in 0..n_class_changes {
        let class_hash = next_or_fail(output_iter, &format!("class hash #{i}"))?;
        let compiled_class_hash = next_or_fail(output_iter, &format!("compiled class hash #{i}"))?;

        classes.insert(class_hash, compiled_class_hash);
    }

    Ok(classes)
}

pub fn decode_output<I: Iterator<Item = Felt252>>(mut output_iter: I) -> Result<StarknetOsOutput, SnOsError> {
    /// Reads a section with a variable length from the iterator.
    /// Some sections start with a length field N followed by N items.
    fn read_variable_length_segment<I: Iterator<Item = Felt252>>(
        output_iter: &mut I,
        item_name: &str,
    ) -> Result<Vec<Felt252>, SnOsError> {
        let n_items = next_as_usize(output_iter, item_name)?;
        let items = output_iter.by_ref().take(n_items).collect();

        Ok(items)
    }

    let header: Vec<Felt252> = output_iter.by_ref().take(HEADER_SIZE).collect();
    if header.len() != HEADER_SIZE {
        return Err(SnOsError::CatchAll(format!(
            "Expected the header to have {} elements, could only read {}",
            HEADER_SIZE,
            header.len()
        )));
    }

    let use_kzg_da = {
        let use_kzg_da_felt = header[USE_KZG_DA_OFFSET];
        if use_kzg_da_felt == Felt252::ZERO {
            false
        } else if use_kzg_da_felt == Felt252::ONE {
            true
        } else {
            return Err(SnOsError::CatchAll(format!("Invalid KZG flag: {}", use_kzg_da_felt.to_biguint())));
        }
    };

    if use_kzg_da {
        // Skip KZG data.
        _ = output_iter.by_ref().take(5);
    }

    let messages_to_l1 = read_variable_length_segment(&mut output_iter, "L1 messages")?;
    let messages_to_l2 = read_variable_length_segment(&mut output_iter, "L2 messages")?;

    let (contracts, classes) = if !use_kzg_da {
        let contracts = parse_all_contract_changes(&mut output_iter)?;
        let classes = parse_all_class_changes(&mut output_iter)?;
        (contracts, classes)
    } else {
        (vec![], HashMap::default())
    };

    Ok(StarknetOsOutput {
        initial_root: header[PREVIOUS_MERKLE_UPDATE_OFFSET],
        final_root: header[NEW_MERKLE_UPDATE_OFFSET],
        block_number: header[BLOCK_NUMBER_OFFSET],
        block_hash: header[BLOCK_HASH_OFFSET],
        starknet_os_config_hash: header[CONFIG_HASH_OFFSET],
        use_kzg_da: header[USE_KZG_DA_OFFSET],
        messages_to_l1,
        messages_to_l2,
        contracts,
        classes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Tests that the OS output can be serialized and deserialized properly to JSON.
    fn os_output_serde_json() {
        let os_output = StarknetOsOutput {
            initial_root: Felt252::from_hex_unchecked(
                "0x5594a2d89ad4eff183ea6a7f4d4bf247fb799f3db54bc6d94ea441e0c99a4ac",
            ),
            final_root: Felt252::from_hex_unchecked(
                "0x12b31d0ff0c0f5aa076d2e7039d2e19329a8a4a4ada68f42f2e0b6b8af304fd",
            ),
            block_number: Felt252::from(10000),
            block_hash: Felt252::from_hex_unchecked("0x123456"),
            starknet_os_config_hash: Felt252::from_hex_unchecked(
                "0x5d4d0b87442f4c6c120e8d207e27c0e01796ad1e57c5323292ecaf655b53b05",
            ),
            use_kzg_da: Felt252::ONE,
            messages_to_l1: vec![
                Felt252::from(1234),
                Felt252::from(5678),
                Felt252::from(2),
                Felt252::from(42),
                Felt252::from(27),
            ],
            messages_to_l2: vec![],
            contracts: vec![ContractChanges {
                addr: Felt252::ONE,
                nonce: Felt252::from(100),
                class_hash: None,
                storage_changes: HashMap::from([
                    (
                        Felt252::from_hex_unchecked(
                            "0x723973208639b7839ce298f7ffea61e3f9533872defd7abdb91023db4658812",
                        ),
                        Felt252::from_hex_unchecked("0x1f67eee3d0800"),
                    ),
                    (
                        Felt252::from_hex_unchecked(
                            "0x27e66af6f5df3e043d32367d68ece7e13645cca1ca9f80dfdaff9013fddf0c5",
                        ),
                        Felt252::from_hex_unchecked("0xddec034b926f800"),
                    ),
                ]),
            }],
            classes: Default::default(),
        };

        let os_output_str = serde_json::to_string(&os_output).expect("OS output serialization failed");
        let deserialized_os_output: StarknetOsOutput =
            serde_json::from_str(&os_output_str).expect("OS output deserialization failed");

        assert_eq!(deserialized_os_output, os_output);
    }
}
