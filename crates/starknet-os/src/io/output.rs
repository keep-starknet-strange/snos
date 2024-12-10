use std::collections::HashMap;

use cairo_vm::types::relocatable::MaybeRelocatable;
use cairo_vm::vm::runners::builtin_runner::BuiltinRunner;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use num_traits::{ToPrimitive, Zero};
use serde::{Deserialize, Serialize};

use crate::error::SnOsError;

const PREVIOUS_MERKLE_UPDATE_OFFSET: usize = 0;
const NEW_MERKLE_UPDATE_OFFSET: usize = 1;
const PREV_BLOCK_NUMBER_OFFSET: usize = 2;
const NEW_BLOCK_NUMBER_OFFSET: usize = 3;
const PREV_BLOCK_HASH_OFFSET: usize = 4;
const NEW_BLOCK_HASH_OFFSET: usize = 5;
const OS_PROGRAM_HASH_OFFSET: usize = 6;
const CONFIG_HASH_OFFSET: usize = 7;
const USE_KZG_DA_OFFSET: usize = 8;
const FULL_OUTPUT_OFFSET: usize = 9;
const HEADER_SIZE: usize = 10;
const KZG_N_BLOBS_OFFSET: usize = 1;

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

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, Default)]
pub struct OsStateDiff {
    /// The list of contracts that were changed.
    pub contract_changes: Vec<ContractChanges>,
    /// The list of classes that were declared. A map from class hash to compiled class hash.
    pub classes: HashMap<Felt252, Felt252>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct StarknetOsOutput {
    /// The root before.
    pub initial_root: Felt252,
    /// The root after.
    pub final_root: Felt252,
    /// The previous block number.
    pub prev_block_number: Felt252,
    /// The current block number.
    pub new_block_number: Felt252,
    /// The previous block hash.
    pub prev_block_hash: Felt252,
    /// The current block hash.
    pub new_block_hash: Felt252,
    /// The hash of the OS program, if the aggregator was used. Zero if the OS was used directly.
    pub os_program_hash: Felt252,
    /// The hash of the OS config.
    pub starknet_os_config_hash: Felt252,
    /// Whether KZG data availability was used.
    pub use_kzg_da: Felt252,
    /// Indicates whether previous state values are included in the state update information.
    pub full_output: Felt252,
    /// Messages from L2 to L1.
    pub messages_to_l1: Vec<Felt252>,
    /// Messages from L1 to L2.
    pub messages_to_l2: Vec<Felt252>,
    /// The state diff.
    pub state_diff: Option<OsStateDiff>,
}

impl StarknetOsOutput {
    pub fn from_run(vm: &VirtualMachine) -> Result<Self, SnOsError> {
        let (output_base, output_size) = get_output_info(vm)?;
        let raw_output = get_raw_output(vm, output_base, output_size)?;
        deserialize_os_output(&mut raw_output.into_iter())
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

// Reverse of output_contract_state_inner in state/output.cairo
fn deserialize_contract_state_inner<I: Iterator<Item = Felt252>>(
    output_iter: &mut I,
    full_output: Felt252,
) -> Result<ContractChanges, SnOsError> {
    let bound =
        Felt252::from(1u128 << 64).try_into().expect("2**64 should be considered non-zero. Did you change the value?");
    let n_updates_small_packing_bound =
        Felt252::from(1u128 << 8).try_into().expect("2**8 should be considered non-zero. Did you change the value?");
    let flag_bound =
        Felt252::from(1u128 << 1).try_into().expect("2**1 should be considered non-zero. Did you change the value?");

    let addr = next_or_fail(output_iter, "contract change addr")?;
    let nonce_n_changes_two_flags = next_or_fail(output_iter, "contract nonce_n_changes_two_flags")?;

    // Parse flags
    let (nonce_n_changes_one_flag, was_class_updated) = nonce_n_changes_two_flags.div_rem(&flag_bound);
    let (nonce_n_changes, is_n_updates_small) = nonce_n_changes_one_flag.div_rem(&flag_bound);

    // Parse n_changes
    let n_updates_bound = if is_n_updates_small == Felt252::ZERO { n_updates_small_packing_bound } else { bound };
    let (nonce, n_changes) = nonce_n_changes.div_rem(&n_updates_bound);

    // Parse nonces
    let new_state_nonce = if !full_output.is_zero() {
        // | old_nonce | new_nonce |
        let (_old_nonce, new_nonce) = nonce.div_rem(&bound);
        new_nonce
    } else {
        // | new_nonce | or Zero
        nonce
    };

    #[allow(clippy::collapsible_else_if)] // Mirror the Cairo code as much as possible
    let new_state_class_hash = if !full_output.is_zero() {
        next_or_fail(output_iter, "contract change prev_state.class_hash")?;
        Some(next_or_fail(output_iter, "contract change new_state.class_hash")?)
    } else {
        if !was_class_updated.is_zero() {
            Some(next_or_fail(output_iter, "contract change new_state.class_hash")?)
        } else {
            None
        }
    };

    let n_changes =
        n_changes.to_usize().expect("n_updates should be 8 or 64-bit by definition. Did you modify the parsing above?");
    let storage_changes = deserialize_da_changes(output_iter, n_changes, full_output)?;

    Ok(ContractChanges { addr, nonce: new_state_nonce, class_hash: new_state_class_hash, storage_changes })
}

// Reverse of serialize_da_changes in state/output.cairo
fn deserialize_da_changes<I: Iterator<Item = Felt252>>(
    output_iter: &mut I,
    n_updates: usize,
    full_output: Felt252,
) -> Result<HashMap<Felt252, Felt252>, SnOsError> {
    let mut storage_changes = HashMap::with_capacity(n_updates);

    for i in 0..n_updates {
        let key = next_or_fail(output_iter, &format!("contract change key #{i}"))?;
        if !full_output.is_zero() {
            next_or_fail(output_iter, &format!("contract change prev_value #{i}"))?;
        }
        let new_value = next_or_fail(output_iter, &format!("contract change new_value #{i}"))?;
        storage_changes.insert(key, new_value);
    }

    Ok(storage_changes)
}

// Reverse of output_contract_state in state/output.cairo
fn deserialize_contract_state<I: Iterator<Item = Felt252>>(
    output_iter: &mut I,
    full_output: Felt252,
) -> Result<Vec<ContractChanges>, SnOsError> {
    let output_n_updates = next_as_usize(output_iter, "output_n_updates")?;
    let mut contract_changes = Vec::with_capacity(output_n_updates);

    for _ in 0..output_n_updates {
        contract_changes.push(deserialize_contract_state_inner(output_iter, full_output)?)
    }

    Ok(contract_changes)
}

// Reverse of output_contract_class_da_changes in state/output.cairo
fn deserialize_contract_class_da_changes<I: Iterator<Item = Felt252>>(
    output_iter: &mut I,
    full_output: Felt252,
) -> Result<HashMap<Felt252, Felt252>, SnOsError> {
    let n_actual_updates = next_as_usize(output_iter, "n_actual_updates")?;

    let mut classes = HashMap::with_capacity(n_actual_updates);

    for i in 0..n_actual_updates {
        let class_hash = next_or_fail(output_iter, &format!("class hash #{i}"))?;
        if !full_output.is_zero() {
            next_or_fail(output_iter, &format!("previous compiled class hash #{i}"))?;
        }
        let compiled_class_hash = next_or_fail(output_iter, &format!("compiled class hash #{i}"))?;
        classes.insert(class_hash, compiled_class_hash);
    }

    Ok(classes)
}

// Reverse of serialize_messages in os/output.cairo
fn deserialize_messages<I>(output_iter: &mut I) -> Result<(Vec<Felt252>, Vec<Felt252>), SnOsError>
where
    I: Iterator<Item = Felt252>,
{
    /// Reads a section with a variable length from the iterator.
    /// Some sections start with a length field N followed by N items.
    fn read_variable_length_segment<I: Iterator<Item = Felt252>>(
        output_iter: &mut I,
        item_name: &str,
    ) -> Result<Vec<Felt252>, SnOsError> {
        let n_items = next_as_usize(output_iter, item_name)?;
        read_segment(output_iter, n_items, item_name)
    }

    let messages_to_l1 = read_variable_length_segment(output_iter, "L1 messages")?;
    let messages_to_l2 = read_variable_length_segment(output_iter, "L2 messages")?;
    Ok((messages_to_l1, messages_to_l2))
}

fn read_segment<I: Iterator<Item = Felt252>>(
    output_iter: &mut I,
    length: usize,
    item_name: &str,
) -> Result<Vec<Felt252>, SnOsError> {
    let segment = output_iter.by_ref().take(length).collect::<Vec<_>>();
    if segment.len() != length {
        return Err(SnOsError::CatchAll(format!(
            "Expected {} {}, could only read {}",
            length,
            item_name,
            segment.len()
        )));
    }
    Ok(segment)
}

fn deserialize_os_state_diff<I: Iterator<Item = Felt252>>(
    output_iter: &mut I,
    full_output: Felt252,
) -> Result<Option<OsStateDiff>, SnOsError> {
    // If not full_output
    if full_output == Felt252::ZERO {
        // state_diff = decompress(compressed=output_iter)
        // output_iter = itertools.chain(iter(state_diff), output_iter)
        return Ok(None);
    }

    // Contract changes
    let contract_changes = deserialize_contract_state(output_iter, full_output)?;
    // Class changes
    let classes = deserialize_contract_class_da_changes(output_iter, full_output)?;

    Ok(Some(OsStateDiff { contract_changes, classes }))
}

// Reverse of serialize_os_output in os/output.cairo
pub fn deserialize_os_output<I>(output_iter: &mut I) -> Result<StarknetOsOutput, SnOsError>
where
    I: Iterator<Item = Felt252>,
{
    let header = read_segment(output_iter, HEADER_SIZE, "header elements")?;
    let use_kzg_da = header[USE_KZG_DA_OFFSET];
    let full_output = header[FULL_OUTPUT_OFFSET];

    if !use_kzg_da.is_zero() {
        // Skip KZG data.
        let kzg_segment: Vec<_> = output_iter.by_ref().take(2).collect();
        let n_blobs: usize = kzg_segment
            .get(KZG_N_BLOBS_OFFSET)
            .expect("Should have n_blobs in header when using kzg da")
            .to_biguint()
            .try_into()
            .expect("n_blobs should fit in a usize");
        // Skip 'n_blobs' commitments and evaluations.
        let _: Vec<_> = output_iter.by_ref().take(2 * 2 * n_blobs).collect();
    }

    let (messages_to_l1, messages_to_l2) = deserialize_messages(output_iter)?;

    let state_diff = deserialize_os_state_diff(output_iter, full_output)?;

    Ok(StarknetOsOutput {
        initial_root: header[PREVIOUS_MERKLE_UPDATE_OFFSET],
        final_root: header[NEW_MERKLE_UPDATE_OFFSET],
        prev_block_number: header[PREV_BLOCK_NUMBER_OFFSET],
        new_block_number: header[NEW_BLOCK_NUMBER_OFFSET],
        prev_block_hash: header[PREV_BLOCK_HASH_OFFSET],
        new_block_hash: header[NEW_BLOCK_HASH_OFFSET],
        os_program_hash: header[OS_PROGRAM_HASH_OFFSET],
        starknet_os_config_hash: header[CONFIG_HASH_OFFSET],
        use_kzg_da,
        full_output,
        messages_to_l1,
        messages_to_l2,
        state_diff,
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
            prev_block_number: Felt252::from(9999),
            new_block_number: Felt252::from(10000),
            prev_block_hash: Felt252::from_hex_unchecked("0x654321"),
            new_block_hash: Felt252::from_hex_unchecked("0x123456"),
            os_program_hash: Felt252::ZERO,
            starknet_os_config_hash: Felt252::from_hex_unchecked(
                "0x5d4d0b87442f4c6c120e8d207e27c0e01796ad1e57c5323292ecaf655b53b05",
            ),
            use_kzg_da: Felt252::ONE,
            full_output: Felt252::ZERO,
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
