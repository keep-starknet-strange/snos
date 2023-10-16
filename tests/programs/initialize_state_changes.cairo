%builtins output

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.segments import relocate_segment
from starkware.starknet.core.os.output import OsCarriedOutputs
from starkware.cairo.common.dict import dict_read

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

    relocate_segment(src_ptr=initial_carried_outputs.messages_to_l1, dest_ptr=output_ptr);
    relocate_segment(src_ptr=initial_carried_outputs.messages_to_l2, dest_ptr=output_ptr);

    return ();
}
