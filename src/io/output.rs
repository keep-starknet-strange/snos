use cairo_vm::types::relocatable::MaybeRelocatable;
use cairo_vm::vm::runners::builtin_runner::BuiltinRunner;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use num_traits::ToPrimitive;

use crate::error::SnOsError;

const PREVIOUS_MERKLE_UPDATE_OFFSET: usize = 0;
const NEW_MERKLE_UPDATE_OFFSET: usize = 1;
const BLOCK_NUMBER_OFFSET: usize = 2;
const BLOCK_HASH_OFFSET: usize = 3;
const CONFIG_HASH_OFFSET: usize = 4;
const USE_KZG_DA_OFFSET: usize = 5;
const HEADER_SIZE: usize = 6;

#[derive(Debug)]
pub struct StarknetOsOutput {
    /// The state commitment before this block.
    pub initial_root: Felt252,
    /// The state commitment after this block.
    pub final_root: Felt252,
    /// The number (height) of this block.
    pub block_number: Felt252,
    /// The hash of this block.
    pub block_hash: Felt252,
    /// The Starknet chain config hash
    pub starknet_os_config_hash: Felt252,
    /// Whether KZG data availability was used.
    pub use_kzg_da: Felt252,
    /// List of messages sent to L1 in this block
    pub messages_to_l1: Vec<Felt252>,
    /// List of messages from L1 handled in this block
    pub messages_to_l2: Vec<Felt252>,
    /// List of the storage updates.
    pub contracts: Vec<Felt252>,
    /// List of the newly declared contract classes.
    pub classes: Vec<Felt252>,
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

pub fn decode_output<I: Iterator<Item = Felt252>>(mut output_iter: I) -> Result<StarknetOsOutput, SnOsError> {
    /// Reads a section with a variable length from the iterator.
    /// Some sections start with a length field N followed by N items.
    fn read_variable_length_segment<I: Iterator<Item = Felt252>>(
        output_iter: &mut I,
        item_name: &str,
    ) -> Result<Vec<Felt252>, SnOsError> {
        let n_items = output_iter
            .next()
            .ok_or(SnOsError::CatchAll(format!("Could not read {item_name} segment size")))?
            .to_usize()
            .ok_or(SnOsError::CatchAll(format!("{item_name} segment size is too large")))?;
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
        let contracts = read_variable_length_segment(&mut output_iter, "contracts")?;
        let classes = read_variable_length_segment(&mut output_iter, "classes")?;
        (contracts, classes)
    } else {
        (vec![], vec![])
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
