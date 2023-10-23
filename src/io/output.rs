use cairo_felt::Felt252;
use cairo_vm::types::relocatable::MaybeRelocatable;
use cairo_vm::vm::runners::builtin_runner::BuiltinRunner;
use cairo_vm::vm::vm_core::VirtualMachine;

use super::StarknetOsOutput;
use crate::error::SnOsError;

const PREVIOUS_MERKLE_UPDATE_OFFSET: usize = 0;
const NEW_MERKLE_UPDATE_OFFSET: usize = 1;
const BLOCK_NUMBER_OFFSET: usize = 2;
const BLOCK_HASH_OFFSET: usize = 3;
const CONFIG_HASH_OFFSET: usize = 4;
const HEADER_SIZE: usize = 5;

impl StarknetOsOutput {
    pub fn from_run(vm: &VirtualMachine) -> Result<Self, SnOsError> {
        // os_output = runner.vm_memory.get_range_as_ints(
        //     addr=runner.output_builtin.base, size=builtin_end_ptrs[0] - runner.output_builtin.base
        // )
        let builtin_end_ptrs = vm.get_return_values(8).map_err(|e| SnOsError::CatchAll(e.to_string()))?;
        let output_base = vm
            .get_builtin_runners()
            .iter()
            .find(|&elt| matches!(elt, BuiltinRunner::Output(_)))
            .expect("Os vm should have the output builtin")
            .base();
        let size_bound_up = match builtin_end_ptrs.last().unwrap() {
            MaybeRelocatable::Int(val) => val,
            _ => panic!("Value should be an int"),
        };

        // Get is input and check that everything is an integer.
        let raw_output = vm.get_range(
            (output_base as isize, 0).into(),
            <usize>::from_be_bytes((size_bound_up.clone() - output_base).to_be_bytes()[..8].try_into().unwrap()),
        );
        let raw_output: Vec<Felt252> = raw_output
            .iter()
            .map(|x| {
                if let MaybeRelocatable::Int(val) = x.clone().unwrap().into_owned() {
                    val
                } else {
                    panic!("Output should be all integers")
                }
            })
            .collect();

        decode_output(raw_output)
    }
}

pub fn decode_output(raw_output: Vec<Felt252>) -> Result<Self, SnOsError> {
    let os_output = &raw_output[HEADER_SIZE..];
    let messages_to_l1_size = <usize>::from_be_bytes(os_output[0].to_be_bytes()[..8].try_into().unwrap());
    let messages_to_l1 = os_output[1..1 + messages_to_l1_size].to_vec();

    let os_output = &os_output[messages_to_l1_size + 1..];
    let messages_to_l2_size = <usize>::from_be_bytes(os_output[0].to_be_bytes()[..8].try_into().unwrap());
    let messages_to_l2 = os_output[1..1 + messages_to_l2_size].to_vec();
    let os_output = &os_output[messages_to_l2_size + 1..];

    let state_updates_size = <usize>::from_be_bytes(os_output[0].to_be_bytes()[..8].try_into().unwrap());
    let state_updates = os_output[1..1 + state_updates_size].to_vec();
    let os_output = &os_output[state_updates_size + 1..];

    let contract_class_diff_size = <usize>::from_be_bytes(os_output[0].to_be_bytes()[..8].try_into().unwrap());
    let contract_class_diff = os_output[1..1 + contract_class_diff_size].to_vec();

    Ok(Self {
        messages_to_l1,
        messages_to_l2,
        state_updates,
        contract_class_diff,
        prev_state_root: raw_output[PREVIOUS_MERKLE_UPDATE_OFFSET].clone(),
        new_state_root: raw_output[NEW_MERKLE_UPDATE_OFFSET].clone(),
        block_number: raw_output[BLOCK_NUMBER_OFFSET].clone(),
        block_hash: raw_output[BLOCK_HASH_OFFSET].clone(),
        config_hash: raw_output[CONFIG_HASH_OFFSET].clone(),
    })
}
