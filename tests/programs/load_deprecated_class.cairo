%builtins output pedersen range_check

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.segments import relocate_segment
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.starknet.core.os.output import OsCarriedOutputs, os_output_serialize
from starkware.cairo.common.serialize import serialize_word

from starkware.starknet.core.os.contract_class.deprecated_compiled_class import (
    DeprecatedCompiledClassFact,
    deprecated_load_compiled_class_facts,
)

func main{output_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    alloc_locals;

    let (initial_carried_outputs: OsCarriedOutputs*) = alloc();
    %{
        from starkware.starknet.core.os.os_input import StarknetOsInput

        os_input = StarknetOsInput.load(data=program_input)

        ids.initial_carried_outputs.messages_to_l1 = segments.add_temp_segment()
        ids.initial_carried_outputs.messages_to_l2 = segments.add_temp_segment()
    %}

    local n_compiled_class_facts;
    local compiled_class_facts: DeprecatedCompiledClassFact*;
    %{
        # Creates a set of deprecated class hashes to distinguish calls to deprecated entry points.
        __deprecated_class_hashes=set(os_input.deprecated_compiled_classes.keys())
        ids.compiled_class_facts = segments.add()
        ids.n_compiled_class_facts = len(os_input.deprecated_compiled_classes)
        vm_enter_scope({
            'compiled_class_facts': iter(os_input.deprecated_compiled_classes.items()),
        })
    %}

    serialize_word(n_compiled_class_facts);
    serialize_word(n_compiled_class_facts + 1);
    serialize_word(n_compiled_class_facts + 14);

    // deprecated_load_compiled_class_facts_inner(
    //     n_compiled_class_facts=n_compiled_class_facts, compiled_class_facts=compiled_class_facts
    // );
    %{ vm_exit_scope() %}

    relocate_segment(src_ptr=initial_carried_outputs.messages_to_l1, dest_ptr=output_ptr);
    relocate_segment(src_ptr=initial_carried_outputs.messages_to_l2, dest_ptr=output_ptr);

    return ();
}
