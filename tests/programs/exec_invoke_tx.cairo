%builtins output pedersen range_check poseidon

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.segments import relocate_segment
from starkware.cairo.common.cairo_builtins import HashBuiltin, PoseidonBuiltin
from starkware.starknet.core.os.output import OsCarriedOutputs
from starkware.starknet.core.os.block_context import BlockContext, get_block_context
from starkware.starknet.core.os.execution.execute_entry_point import ExecutionContext
from starkware.starknet.core.os.builtins import BuiltinPointers
from starkware.cairo.common.dict_access import DictAccess
from starkware.cairo.common.registers import get_label_location
from starkware.starknet.core.os.execution.execute_syscalls import execute_syscalls
from starkware.starknet.core.os.execution.execute_transactions import charge_fee, run_validate
from starkware.starknet.core.os.execution.deprecated_execute_syscalls import (
    execute_deprecated_syscalls,
    select_execute_entry_point_func,
)
from starkware.starknet.core.os.constants import (
    ENTRY_POINT_TYPE_EXTERNAL,
    VALIDATE_ENTRY_POINT_SELECTOR,
    VALIDATED,
    SIERRA_ARRAY_LEN_BOUND,
)
from starkware.starknet.common.constants import ORIGIN_ADDRESS
from starkware.starknet.common.new_syscalls import ExecutionInfo, TxInfo
from starkware.cairo.common.dict import dict_read
from starkware.cairo.common.math import assert_nn, assert_nn_le

func main{
    output_ptr: felt*, pedersen_ptr: HashBuiltin*, poseidon_ptr: PoseidonBuiltin*, range_check_ptr
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

    // TODO: check if we need to populate
    local contract_state_changes: DictAccess*;
    local contract_class_changes: DictAccess*;

    let (local tx_execution_context: ExecutionContext*) = get_invoke_tx_execution_context(
        block_context=block_context, entry_point_type=ENTRY_POINT_TYPE_EXTERNAL
    );

    %{
        tx_info_ptr = ids.tx_execution_context.deprecated_tx_info.address_
        execution_helper.start_tx(tx_info_ptr=tx_info_ptr)
    %}

    run_validate(block_context=block_context, tx_execution_context=tx_execution_context);

    // Execute only non-reverted transactions.
    if (nondet %{ execution_helper.tx_execution_info.is_reverted %} == 0) {
        select_execute_entry_point_func(
            block_context=block_context, execution_context=tx_execution_context
        );
    } else {
        // Align the stack with the if branch to avoid revoked references.
        tempvar range_check_ptr = range_check_ptr;
        tempvar remaining_gas = remaining_gas;
        tempvar builtin_ptrs = builtin_ptrs;
        tempvar contract_state_changes = contract_state_changes;
        tempvar contract_class_changes = contract_class_changes;
        tempvar outputs = outputs;
        tempvar _dummy_return_value: select_execute_entry_point_func.Return;
    }
    local remaining_gas = remaining_gas;

    charge_fee(block_context=block_context, tx_execution_context=tx_execution_context);

    %{ execution_helper.end_tx() %}

    %{ vm_exit_scope() %}

    return ();
}

// Guess the execution context of an invoke transaction (either invoke function or L1 handler).
// Leaves 'execution_info.tx_info' and 'deprecated_tx_info' empty - should be
// filled later on.
func get_invoke_tx_execution_context{range_check_ptr, contract_state_changes: DictAccess*}(
    block_context: BlockContext*, entry_point_type: felt
) -> (tx_execution_context: ExecutionContext*) {
    alloc_locals;
    local contract_address;
    %{
        from starkware.starknet.business_logic.transaction.objects import InternalL1Handler
        ids.contract_address = (
            tx.contract_address if isinstance(tx, InternalL1Handler) else tx.sender_address
        )
    %}
    let (state_entry: StateEntry*) = dict_read{dict_ptr=contract_state_changes}(
        key=contract_address
    );
    local tx_execution_context: ExecutionContext* = new ExecutionContext(
        entry_point_type=entry_point_type,
        class_hash=state_entry.class_hash,
        calldata_size=nondet %{ len(tx.calldata) %},
        calldata=cast(nondet %{ segments.gen_arg(tx.calldata) %}, felt*),
        execution_info=new ExecutionInfo(
            block_info=block_context.block_info,
            tx_info=cast(nondet %{ segments.add() %}, TxInfo*),
            caller_address=ORIGIN_ADDRESS,
            contract_address=contract_address,
            selector=nondet %{ tx.entry_point_selector %},
        ),
        deprecated_tx_info=cast(nondet %{ segments.add() %}, DeprecatedTxInfo*),
    );
    assert_nn_le(tx_execution_context.calldata_size, SIERRA_ARRAY_LEN_BOUND - 1);

    return (tx_execution_context=tx_execution_context);
}
