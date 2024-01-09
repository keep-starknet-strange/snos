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

    %{
        tx_info_ptr = ids.tx_execution_context.deprecated_tx_info.address_
        execution_helper.start_tx(tx_info_ptr=tx_info_ptr)
    %}

    run_validate(block_context=block_context, tx_execution_context=tx_execution_context);

    %{
        execution_helper.enter_call(
            execution_info_ptr=ids.execution_context.execution_info.address_)
    %}
    %{ vm_enter_scope({'syscall_handler': deprecated_syscall_handler}) %}
    call abs contract_entry_point;
    %{ vm_exit_scope() %}
    %{ execution_helper.exit_call() %}

    charge_fee(block_context=block_context, tx_execution_context=tx_execution_context);
    %{ execution_helper.end_tx() %}

    %{ vm_exit_scope() %}

    return ();
}
