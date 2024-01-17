%builtins output pedersen range_check poseidon

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import assert_not_zero
from starkware.cairo.common.segments import relocate_segment
from starkware.cairo.common.cairo_builtins import HashBuiltin, PoseidonBuiltin
from starkware.cairo.common.registers import get_label_location
from starkware.starknet.core.os.output import OsCarriedOutputs
from starkware.starknet.core.os.execution.execute_syscalls import execute_syscalls
from starkware.starknet.core.os.execution.deprecated_execute_syscalls import (
    execute_deprecated_syscalls,
)
from starkware.starknet.core.os.block_context import BlockContext, get_block_context

func main{
    output_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, poseidon_ptr: PoseidonBuiltin*
}() {
    alloc_locals;

    let (initial_carried_outputs: OsCarriedOutputs*) = alloc();
    %{
        from starkware.starknet.core.os.os_input import StarknetOsInput

        os_input = StarknetOsInput.load(data=program_input)

        ids.initial_carried_outputs.messages_to_l1 = segments.add_temp_segment()
        ids.initial_carried_outputs.messages_to_l2 = segments.add_temp_segment()
    %}

    // -------------------------- START TEST LOGIC --------------------------

    // Build block context:
    let (execute_syscalls_ptr) = get_label_location(label_value=execute_syscalls);
    let (execute_deprecated_syscalls_ptr) = get_label_location(
        label_value=execute_deprecated_syscalls
    );
    let (block_context: BlockContext*) = get_block_context(
        execute_syscalls_ptr=execute_syscalls_ptr,
        execute_deprecated_syscalls_ptr=execute_deprecated_syscalls_ptr,
    );

    // Test Block Info:
    assert block_context.block_info.block_number = 2;
    assert block_context.block_info.block_timestamp = 3;
    assert_not_zero(block_context.block_info.sequencer_address);

    // Test Starknet Config:
    assert_not_zero(block_context.starknet_os_config.chain_id);

    relocate_segment(src_ptr=initial_carried_outputs.messages_to_l1, dest_ptr=output_ptr);
    relocate_segment(src_ptr=initial_carried_outputs.messages_to_l2, dest_ptr=output_ptr);

    return ();
}
