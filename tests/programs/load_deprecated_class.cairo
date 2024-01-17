%builtins output pedersen range_check

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.segments import relocate_segment
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.starknet.core.os.output import OsCarriedOutputs

from starkware.starknet.core.os.contract_class.deprecated_compiled_class import (
    DeprecatedCompiledClassFact,
    deprecated_validate_entry_points,
    deprecated_compiled_class_hash,
    DeprecatedContractEntryPoint,
)

const DEPRECATED_COMPILED_CLASS_VERSION = 0;

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

    deprecated_load_compiled_class_facts_inner(
        n_compiled_class_facts=n_compiled_class_facts, compiled_class_facts=compiled_class_facts
    );
    %{ vm_exit_scope() %}

    relocate_segment(src_ptr=initial_carried_outputs.messages_to_l1, dest_ptr=output_ptr);
    relocate_segment(src_ptr=initial_carried_outputs.messages_to_l2, dest_ptr=output_ptr);

    assert n_compiled_class_facts = 5;

    tempvar sequencer_address = nondet %{ os_input.general_config.sequencer_address %};

    return ();
}

func deprecated_load_compiled_class_facts_inner{
    output_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr
}(n_compiled_class_facts, compiled_class_facts: DeprecatedCompiledClassFact*) {
    if (n_compiled_class_facts == 0) {
        return ();
    }
    alloc_locals;

    let compiled_class_fact = compiled_class_facts;
    let compiled_class = compiled_class_fact.compiled_class;

    // Fetch contract data form hints.
    %{
        from starkware.starknet.core.os.contract_class.deprecated_class_hash import (
            get_deprecated_contract_class_struct,
        )

        compiled_class_hash, compiled_class = next(compiled_class_facts)

        cairo_contract = get_deprecated_contract_class_struct(
            identifiers=ids._context.identifiers, contract_class=compiled_class)
        ids.compiled_class = segments.gen_arg(cairo_contract)
    %}

    assert compiled_class.compiled_class_version = DEPRECATED_COMPILED_CLASS_VERSION;

    deprecated_validate_entry_points(
        n_entry_points=compiled_class.n_external_functions,
        entry_points=compiled_class.external_functions,
    );

    deprecated_validate_entry_points(
        n_entry_points=compiled_class.n_l1_handlers, entry_points=compiled_class.l1_handlers
    );

    let (hash) = deprecated_compiled_class_hash{hash_ptr=pedersen_ptr}(compiled_class);
    compiled_class_fact.hash = hash;

    %{
        from starkware.python.utils import from_bytes

        computed_hash = ids.compiled_class_fact.hash
        expected_hash = compiled_class_hash
        assert computed_hash == expected_hash, (
            "Computed compiled_class_hash is inconsistent with the hash in the os_input. "
            f"Computed hash = {computed_hash}, Expected hash = {expected_hash}.")

        print(ids.compiled_class.n_contructors)
        vm_load_program(compiled_class.program, ids.compiled_class.bytecode_ptr)
    %}

    return deprecated_load_compiled_class_facts_inner(
        n_compiled_class_facts=n_compiled_class_facts - 1,
        compiled_class_facts=compiled_class_facts + DeprecatedCompiledClassFact.SIZE,
    );
}
