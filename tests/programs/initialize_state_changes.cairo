%builtins output

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.segments import relocate_segment
from starkware.starknet.core.os.output import OsCarriedOutputs
from starkware.cairo.common.dict import dict_new, dict_read
from starkware.cairo.common.dict_access import DictAccess
from starkware.starknet.core.os.state import StateEntry

from starkware.cairo.common.serialize import serialize_word

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

    relocate_segment(src_ptr=initial_carried_outputs.messages_to_l1, dest_ptr=output_ptr);
    relocate_segment(src_ptr=initial_carried_outputs.messages_to_l2, dest_ptr=output_ptr);

    return ();
}
