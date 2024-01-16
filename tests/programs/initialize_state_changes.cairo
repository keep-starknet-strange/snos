%builtins output

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.segments import relocate_segment
from starkware.starknet.core.os.output import OsCarriedOutputs
from starkware.cairo.common.dict import dict_new, dict_read, dict_update
from starkware.cairo.common.dict_access import DictAccess
from starkware.starknet.core.os.state import StateEntry
from starkware.starknet.core.os.block_context import BlockContext
from starkware.cairo.common.serialize import serialize_word
from starkware.starknet.core.os.constants import (
    BLOCK_HASH_CONTRACT_ADDRESS,
    STORED_BLOCK_HASH_BUFFER,
)
from starkware.cairo.common.math_cmp import is_nn
from starkware.cairo.common.bool import FALSE

func main{output_ptr: felt*}() {
    alloc_locals;

    let (initial_carried_outputs: OsCarriedOutputs*) = alloc();
    %{
        from starkware.starknet.core.os.os_input import StarknetOsInput

        os_input = StarknetOsInput.load(data=program_input)

        ids.initial_carried_outputs.messages_to_l1 = segments.add_temp_segment()
        ids.initial_carried_outputs.messages_to_l2 = segments.add_temp_segment()
    %}

    %{
        from starkware.python.utils import from_bytes

        initial_dict = {
            address: segments.gen_arg(
                (from_bytes(contract.contract_hash), segments.add(), contract.nonce))
            for address, contract in os_input.contracts.items()
        }
    %}

    // A dictionary from contract address to a dict of storage changes of type StateEntry.
    let (contract_state_changes: DictAccess*) = dict_new();

    %{ initial_dict = os_input.class_hash_to_compiled_class_hash %}

    let (state_entry: StateEntry*) = dict_read{dict_ptr=contract_state_changes}(
        key=1470089414715992704702781317133162679047468004062084455026636858461958198968
    );

    assert state_entry.nonce = 2;

    // let (
    //     contract_state_changes: DictAccess*, contract_class_changes: DictAccess*
    // ) = initialize_state_changes();

    // // Keep a reference to the start of contract_state_changes and contract_class_changes.
    // let contract_state_changes_start = contract_state_changes;
    // let contract_class_changes_start = contract_class_changes;

    // // Pre-process block.
    // with contract_state_changes {
    //     write_block_number_to_block_hash_mapping(block_context=block_context);
    // }

    relocate_segment(src_ptr=initial_carried_outputs.messages_to_l1, dest_ptr=output_ptr);
    relocate_segment(src_ptr=initial_carried_outputs.messages_to_l2, dest_ptr=output_ptr);

    return ();
}

// Writes the hash of the (current_block_number - buffer) block under its block number in the
// dedicated contract state, where buffer=STORED_BLOCK_HASH_BUFFER.
func write_block_number_to_block_hash_mapping{range_check_ptr, contract_state_changes: DictAccess*}(
    block_context: BlockContext*
) {
    alloc_locals;
    tempvar old_block_number = block_context.block_info.block_number - STORED_BLOCK_HASH_BUFFER;
    let is_old_block_number_non_negative = is_nn(old_block_number);
    if (is_old_block_number_non_negative == FALSE) {
        // Not enough blocks in the system - nothing to write.
        return ();
    }

    // Fetch the (block number -> block hash) mapping contract state.
    local state_entry: StateEntry*;
    %{
        ids.state_entry = __dict_manager.get_dict(ids.contract_state_changes)[
            ids.BLOCK_HASH_CONTRACT_ADDRESS
        ]
    %}

    // Currently, the block hash mapping is not enforced by the OS.
    // TODO(Yoni, 1/12/2023): output this hash.
    local old_block_hash;
    %{
        (
            old_block_number, old_block_hash
        ) = execution_helper.get_old_block_number_and_hash()
        assert old_block_number == ids.old_block_number,(
            "Inconsistent block number. "
            "The constant STORED_BLOCK_HASH_BUFFER is probably out of sync."
        )
        ids.old_block_hash = old_block_hash
    %}

    // Update mapping.
    assert state_entry.class_hash = 0;
    assert state_entry.nonce = 0;
    tempvar storage_ptr = state_entry.storage_ptr;
    assert [storage_ptr] = DictAccess(key=old_block_number, prev_value=0, new_value=old_block_hash);
    let storage_ptr = storage_ptr + DictAccess.SIZE;
    %{
        storage = execution_helper.storage_by_address[ids.BLOCK_HASH_CONTRACT_ADDRESS]
        storage.write(key=ids.old_block_number, value=ids.old_block_hash)
    %}

    // Update contract state.
    tempvar new_state_entry = new StateEntry(class_hash=0, storage_ptr=storage_ptr, nonce=0);
    dict_update{dict_ptr=contract_state_changes}(
        key=BLOCK_HASH_CONTRACT_ADDRESS,
        prev_value=cast(state_entry, felt),
        new_value=cast(new_state_entry, felt),
    );
    return ();
}
