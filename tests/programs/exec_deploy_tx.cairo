%builtins output pedersen range_check ecdsa bitwise ec_op keccak poseidon

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import assert_not_zero, assert_nn, assert_nn_le
from starkware.cairo.common.segments import relocate_segment
from starkware.cairo.common.default_dict import default_dict_new
from starkware.cairo.common.cairo_builtins import (
    BitwiseBuiltin,
    HashBuiltin,
    KeccakBuiltin,
    PoseidonBuiltin,
)
from starkware.cairo.common.dict import dict_update, dict_new
from starkware.cairo.common.dict_access import DictAccess
from starkware.cairo.common.registers import get_label_location, get_ap
from starkware.starknet.core.os.output import OsCarriedOutputs
from starkware.starknet.core.os.block_context import BlockContext, get_block_context
from starkware.starknet.core.os.execution.execute_entry_point import (
    ExecutionContext,
    execute_entry_point,
)
from starkware.starknet.core.os.builtins import (
    BuiltinEncodings,
    BuiltinParams,
    BuiltinPointers,
    SelectableBuiltins,
    NonSelectableBuiltins,
    update_builtin_ptrs,
)
from starkware.starknet.core.os.execution.execute_syscalls import execute_syscalls
from starkware.starknet.core.os.execution.execute_transactions import (
    validate_transaction_version,
    compute_transaction_hash,
    fill_deprecated_tx_info,
    prepare_constructor_execution_context,
)
from starkware.starknet.core.os.execution.deprecated_execute_syscalls import (
    execute_deprecated_syscalls,
)
from starkware.starknet.core.os.execution.deprecated_execute_entry_point import (
    get_entry_point_offset,
    select_execute_entry_point_func,
)
from starkware.starknet.core.os.constants import (
    BLOCK_HASH_CONTRACT_ADDRESS,
    INITIAL_GAS_COST,
    TRANSACTION_GAS_COST,
    NOP_ENTRY_POINT_OFFSET,
)
from starkware.starknet.common.constants import ORIGIN_ADDRESS
from starkware.starknet.common.new_syscalls import ExecutionInfo, TxInfo
from starkware.starknet.core.os.state import StateEntry, UNINITIALIZED_CLASS_HASH
from starkware.starknet.common.constants import DEPLOY_HASH_PREFIX
from starkware.starknet.core.os.constants import CONSTRUCTOR_ENTRY_POINT_SELECTOR
from starkware.starknet.builtins.segment_arena.segment_arena import new_arena
from starkware.cairo.common.registers import get_fp_and_pc
from starkware.starknet.core.os.contract_class.deprecated_compiled_class import (
    DeprecatedCompiledClass,
    DeprecatedCompiledClassFact,
)
from starkware.cairo.common.find_element import find_element
from starkware.cairo.builtin_selection.select_builtins import select_builtins

func main{
    output_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr,
    ecdsa_ptr,
    bitwise_ptr: BitwiseBuiltin*,
    ec_op_ptr,
    keccak_ptr: KeccakBuiltin*,
    poseidon_ptr: PoseidonBuiltin*,
}() {
    alloc_locals;

    let (initial_carried_outputs: OsCarriedOutputs*) = alloc();
    %{
        from starkware.starknet.core.os.os_input import StarknetOsInput

        os_input = StarknetOsInput.load(data=program_input)

        ids.initial_carried_outputs.messages_to_l1 = segments.add_temp_segment()
        ids.initial_carried_outputs.messages_to_l2 = segments.add_temp_segment()
    %}

    // Build block context:
    let (execute_syscalls_ptr) = get_label_location(label_value=execute_syscalls);
    let (execute_deprecated_syscalls_ptr) = get_label_location(
        label_value=execute_deprecated_syscalls
    );
    let (block_context: BlockContext*) = get_block_context(
        execute_syscalls_ptr=execute_syscalls_ptr,
        execute_deprecated_syscalls_ptr=execute_deprecated_syscalls_ptr,
    );

    let (
        contract_state_changes: DictAccess*, contract_class_changes: DictAccess*
    ) = initialize_state_changes();

    let segment_arena_ptr = new_arena();

    let (__fp__, _) = get_fp_and_pc();
    local local_builtin_ptrs: BuiltinPointers = BuiltinPointers(
        selectable=SelectableBuiltins(
            pedersen=pedersen_ptr,
            range_check=nondet %{ segments.add_temp_segment() %},
            ecdsa=ecdsa_ptr,
            bitwise=bitwise_ptr,
            ec_op=ec_op_ptr,
            poseidon=poseidon_ptr,
            segment_arena=segment_arena_ptr,
        ),
        non_selectable=NonSelectableBuiltins(keccak=keccak_ptr),
    );

    // Dummy dict
    let (local my_dict: DictAccess*) = default_dict_new(17);

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

    local tx_type;
    // Guess the current transaction's type.
    %{
        tx = next(transactions)
        tx_type_bytes = tx.tx_type.name.encode("ascii")
        ids.tx_type = int.from_bytes(tx_type_bytes, "big")
    %}

    let builtin_ptrs = &local_builtin_ptrs;
    with builtin_ptrs {
        let (
            local constructor_execution_context: ExecutionContext*, _
        ) = prepare_constructor_execution_context(block_context=block_context);
        // Guess tx version and make sure it's valid.
        local tx_version = nondet %{ tx.version %};
        validate_transaction_version(tx_version=tx_version);

        let nullptr = cast(0, felt*);
        local chain_id = block_context.starknet_os_config.chain_id;

        let (transaction_hash) = compute_transaction_hash(
            tx_hash_prefix=DEPLOY_HASH_PREFIX,
            version=tx_version,
            execution_context=constructor_execution_context,
            entry_point_selector_field=CONSTRUCTOR_ENTRY_POINT_SELECTOR,
            max_fee=0,
            chain_id=chain_id,
            additional_data_size=0,
            additional_data=nullptr,
        );
    }

    // Write the transaction info and complete the ExecutionInfo struct.
    tempvar tx_info = constructor_execution_context.execution_info.tx_info;
    assert [tx_info] = TxInfo(
        version=tx_version,
        account_contract_address=ORIGIN_ADDRESS,
        max_fee=0,
        signature_start=nullptr,
        signature_end=nullptr,
        transaction_hash=transaction_hash,
        chain_id=chain_id,
        nonce=0,
    );
    fill_deprecated_tx_info(tx_info=tx_info, dst=constructor_execution_context.deprecated_tx_info);

    %{
        execution_helper.start_tx(
            tx_info_ptr=ids.constructor_execution_context.deprecated_tx_info.address_
        )
    %}

    // // Keep a reference to the start of contract_state_changes and contract_class_changes.
    let builtin_ptrs = &local_builtin_ptrs;
    let outputs = initial_carried_outputs;
    let remaining_gas = INITIAL_GAS_COST - TRANSACTION_GAS_COST;
    with remaining_gas, builtin_ptrs, contract_state_changes, contract_class_changes, outputs {
        deploy_contract(
            block_context=block_context, constructor_execution_context=constructor_execution_context
        );
    }
    %{ execution_helper.end_tx() %}

    // relocate_segment(src_ptr=initial_carried_outputs.messages_to_l1, dest_ptr=output_ptr);
    // relocate_segment(src_ptr=initial_carried_outputs.messages_to_l2, dest_ptr=output_ptr);

    return ();
}

func call_execute_deprecated_syscalls{
    range_check_ptr,
    builtin_ptrs: BuiltinPointers*,
    contract_state_changes: DictAccess*,
    contract_class_changes: DictAccess*,
    outputs: OsCarriedOutputs*,
}(
    block_context: BlockContext*,
    execution_context: ExecutionContext*,
    syscall_size,
    syscall_ptr: felt*,
) {
    jmp abs block_context.execute_deprecated_syscalls_ptr;
}

// Deploys a contract and invokes its constructor.
// Returns the constructor's return data.
func deploy_contract{
    range_check_ptr,
    remaining_gas: felt,
    builtin_ptrs: BuiltinPointers*,
    contract_state_changes: DictAccess*,
    contract_class_changes: DictAccess*,
    outputs: OsCarriedOutputs*,
}(block_context: BlockContext*, constructor_execution_context: ExecutionContext*) -> (
    retdata_size: felt, retdata: felt*
) {
    alloc_locals;

    local contract_address = constructor_execution_context.execution_info.contract_address;

    // Try to comment this
    // Assert that we don't deploy to one of the reserved addresses.
    assert_not_zero(
        (contract_address - ORIGIN_ADDRESS) * (contract_address - BLOCK_HASH_CONTRACT_ADDRESS)
    );

    %{ breakpoint() %}

    local state_entry: StateEntry*;
    %{
        # Fetch a state_entry in this hint and validate it in the update at the end
        # of this function.
        ids.state_entry = __dict_manager.get_dict(ids.contract_state_changes)[ids.contract_address]
    %}
    assert state_entry.class_hash = UNINITIALIZED_CLASS_HASH;
    assert state_entry.nonce = 0;

    tempvar new_state_entry = new StateEntry(
        class_hash=constructor_execution_context.class_hash,
        storage_ptr=state_entry.storage_ptr,
        nonce=0,
    );

    dict_update{dict_ptr=contract_state_changes}(
        key=contract_address,
        prev_value=cast(state_entry, felt),
        new_value=cast(new_state_entry, felt),
    );

    let (retdata_size, retdata, _is_deprecated) = select_execute_entry_point_func(
        block_context=block_context, execution_context=constructor_execution_context
    );
    return (retdata_size=retdata_size, retdata=retdata);
}

func deprecated_execute_entry_point{
    range_check_ptr,
    builtin_ptrs: BuiltinPointers*,
    contract_state_changes: DictAccess*,
    contract_class_changes: DictAccess*,
    outputs: OsCarriedOutputs*,
}(block_context: BlockContext*, execution_context: ExecutionContext*) -> (
    retdata_size: felt, retdata: felt*
) {
    alloc_locals;

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

    return (retdata_size=retdata_size, retdata=retdata);
}

func initialize_state_changes() -> (
    contract_state_changes: DictAccess*, contract_class_changes: DictAccess*
) {
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
    // A dictionary from class hash to compiled class hash (Casm).
    let (contract_class_changes: DictAccess*) = dict_new();

    return (
        contract_state_changes=contract_state_changes, contract_class_changes=contract_class_changes
    );
}
