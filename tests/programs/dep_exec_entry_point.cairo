%builtins output pedersen range_check

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.segments import relocate_segment
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.starknet.core.os.output import OsCarriedOutputs
from starkware.starknet.core.os.block_context import BlockContext, get_block_context
from starkware.starknet.core.os.execution.execute_entry_point import ExecutionContext
from starkware.starknet.core.os.builtins import BuiltinPointers
from starkware.cairo.common.dict_access import DictAccess
from starkware.cairo.common.registers import get_label_location
from starkware.starknet.core.os.execution.execute_syscalls import execute_syscalls
from starkware.starknet.core.os.execution.deprecated_execute_syscalls import (
    execute_deprecated_syscalls,
)
from starkware.starknet.core.os.contract_class.deprecated_compiled_class import (
    DeprecatedCompiledClassFact,
)
from starkware.cairo.common.find_element import find_element

func main{output_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    alloc_locals;

    let (initial_carried_outputs: OsCarriedOutputs*) = alloc();
    %{
        from starkware.starknet.core.os.os_input import StarknetOsInput

        os_input = StarknetOsInput.load(data=program_input)

        ids.initial_carried_outputs.messages_to_l1 = segments.add_temp_segment()
        ids.initial_carried_outputs.messages_to_l2 = segments.add_temp_segment()
    %}

    // -------------------------- START TEST LOGIC --------------------------
    // TODO: check if we need to populate
    local execution_context: ExecutionContext*;

    // Build block context.
    let (execute_syscalls_ptr) = get_label_location(label_value=execute_syscalls);
    let (execute_deprecated_syscalls_ptr) = get_label_location(
        label_value=execute_deprecated_syscalls
    );
    let (block_context: BlockContext*) = get_block_context(
        execute_syscalls_ptr=execute_syscalls_ptr,
        execute_deprecated_syscalls_ptr=execute_deprecated_syscalls_ptr,
    );

    %{
        vm_enter_scope({
            '__deprecated_class_hashes': __deprecated_class_hashes,
            'transactions': iter(os_input.transactions),
            'execution_helper': execution_helper,
            'deprecated_syscall_handler': deprecated_syscall_handler,
            'syscall_handler': syscall_handler,
             '__dict_manager': __dict_manager,
        })
    %}

    // The key must be at offset 0.
    static_assert DeprecatedCompiledClassFact.hash == 0;
    let (compiled_class_fact: DeprecatedCompiledClassFact*) = find_element(
        array_ptr=block_context.deprecated_compiled_class_facts,
        elm_size=DeprecatedCompiledClassFact.SIZE,
        n_elms=block_context.n_deprecated_compiled_class_facts,
        key=execution_context.class_hash,
    );
    local compiled_class: DeprecatedCompiledClass* = compiled_class_fact.compiled_class;

    let (entry_point_offset) = get_entry_point_offset(
        compiled_class=compiled_class, execution_context=execution_context
    );

    if (entry_point_offset == NOP_ENTRY_POINT_OFFSET) {
        // Assert that there is no call data in the case of NOP entry point.
        assert execution_context.calldata_size = 0;
        %{ execution_helper.skip_call() %}
        return (retdata_size=0, retdata=cast(0, felt*));
    }

    local range_check_ptr = range_check_ptr;
    local contract_entry_point: felt* = compiled_class.bytecode_ptr + entry_point_offset;

    local os_context: felt*;
    local syscall_ptr: felt*;

    %{
        ids.os_context = segments.add()
        ids.syscall_ptr = segments.add()
    %}
    assert [os_context] = cast(syscall_ptr, felt);

    let n_builtins = BuiltinEncodings.SIZE;
    local builtin_params: BuiltinParams* = block_context.builtin_params;
    select_builtins(
        n_builtins=n_builtins,
        all_encodings=builtin_params.builtin_encodings,
        all_ptrs=builtin_ptrs,
        n_selected_builtins=compiled_class.n_builtins,
        selected_encodings=compiled_class.builtin_list,
        selected_ptrs=os_context + 1,
    );

    // Use tempvar to pass arguments to contract_entry_point().
    tempvar selector = execution_context.execution_info.selector;
    tempvar context = os_context;
    tempvar calldata_size = execution_context.calldata_size;
    tempvar calldata = execution_context.calldata;

    %{
        execution_helper.enter_call(
            execution_info_ptr=ids.execution_context.execution_info.address_)
    %}
    %{ vm_enter_scope({'syscall_handler': deprecated_syscall_handler}) %}
    call abs contract_entry_point;
    %{ vm_exit_scope() %}
    %{ execution_helper.exit_call() %}

    // Retrieve returned_builtin_ptrs_subset.
    // Note that returned_builtin_ptrs_subset cannot be set in a hint because doing so will allow a
    // malicious prover to lie about the storage changes of a valid contract.
    let (ap_val) = get_ap();
    local returned_builtin_ptrs_subset: felt* = cast(ap_val - compiled_class.n_builtins - 2, felt*);
    local retdata_size: felt = [ap_val - 2];
    local retdata: felt* = cast([ap_val - 1], felt*);

    let return_builtin_ptrs = update_builtin_ptrs(
        builtin_params=builtin_params,
        builtin_ptrs=builtin_ptrs,
        n_selected_builtins=compiled_class.n_builtins,
        selected_encodings=compiled_class.builtin_list,
        selected_ptrs=returned_builtin_ptrs_subset,
    );

    // Validate that segment_arena builtin was not used.
    assert builtin_ptrs.selectable.segment_arena = return_builtin_ptrs.selectable.segment_arena;

    let syscall_end = cast([returned_builtin_ptrs_subset - 1], felt*);

    let builtin_ptrs = return_builtin_ptrs;
    call_execute_deprecated_syscalls(
        block_context=block_context,
        execution_context=execution_context,
        syscall_size=syscall_end - syscall_ptr,
        syscall_ptr=syscall_ptr,
    );

    return ();
}
