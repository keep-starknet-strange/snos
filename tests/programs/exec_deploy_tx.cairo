%builtins output pedersen range_check ecdsa bitwise ec_op keccak poseidon

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import assert_not_zero
from starkware.cairo.common.segments import relocate_segment
from starkware.cairo.common.cairo_builtins import (
    BitwiseBuiltin,
    HashBuiltin,
    KeccakBuiltin,
    PoseidonBuiltin,
)
from starkware.cairo.common.dict import dict_read, dict_update, dict_new
from starkware.cairo.common.dict_access import DictAccess
from starkware.cairo.common.registers import get_label_location
from starkware.starknet.core.os.output import OsCarriedOutputs
from starkware.starknet.core.os.block_context import BlockContext, get_block_context
from starkware.starknet.core.os.execution.execute_entry_point import ExecutionContext
from starkware.starknet.core.os.builtins import (
    BuiltinPointers,
    SelectableBuiltins,
    NonSelectableBuiltins,
)
from starkware.starknet.core.os.execution.execute_syscalls import execute_syscalls
from starkware.starknet.core.os.execution.execute_transactions import (
    validate_transaction_version,
    compute_transaction_hash,
    fill_deprecated_tx_info,
)
from starkware.starknet.core.os.execution.deprecated_execute_syscalls import (
    execute_deprecated_syscalls,
    select_execute_entry_point_func,
)
from starkware.starknet.core.os.constants import (
    ENTRY_POINT_TYPE_EXTERNAL,
    VALIDATE_ENTRY_POINT_SELECTOR,
    VALIDATED,
    SIERRA_ARRAY_LEN_BOUND,
    BLOCK_HASH_CONTRACT_ADDRESS,
    ENTRY_POINT_TYPE_CONSTRUCTOR,
    INITIAL_GAS_COST,
    TRANSACTION_GAS_COST,
)
from starkware.starknet.common.constants import ORIGIN_ADDRESS
from starkware.starknet.common.new_syscalls import ExecutionInfo, TxInfo
from starkware.cairo.common.math import assert_nn, assert_nn_le
from starkware.starknet.core.os.state import StateEntry, UNINITIALIZED_CLASS_HASH
from starkware.starknet.common.syscalls import TxInfo as DeprecatedTxInfo
from starkware.starknet.common.constants import DEPLOY_HASH_PREFIX
from starkware.starknet.core.os.constants import CONSTRUCTOR_ENTRY_POINT_SELECTOR
from starkware.starknet.core.os.contract_address.contract_address import get_contract_address
from starkware.starknet.builtins.segment_arena.segment_arena import new_arena
from starkware.cairo.common.registers import get_fp_and_pc

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

    let builtin_ptrs = &local_builtin_ptrs;
    with builtin_ptrs {
        let (
            local constructor_execution_context: ExecutionContext*, _
        ) = prepare_constructor_execution_context(block_context=block_context);
    }

    // Guess tx version and make sure it's valid.
    local tx_version = nondet %{ tx.version %};
    validate_transaction_version(tx_version=tx_version);

    let nullptr = cast(0, felt*);
    local chain_id = block_context.starknet_os_config.chain_id;

    let builtin_ptrs = &local_builtin_ptrs;
    with builtin_ptrs {
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

    let (
        contract_state_changes: DictAccess*, contract_class_changes: DictAccess*
    ) = initialize_state_changes();

    // // Keep a reference to the start of contract_state_changes and contract_class_changes.
    // let contract_state_changes_start = contract_state_changes;
    // let contract_class_changes_start = contract_class_changes;
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

// Deploys a contract and invokes its constructor.
// Returns the constructor's return data.
//
// Arguments:
// block_context - A global context that is fixed throughout the block.
// constructor_execution_context - The ExecutionContext of the constructor.
// TODO(Yoni, 1/7/2023): move to another location and handle failures.
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

    // Invoke the contract constructor.
    // TODO(Yoni, 1/4/2023): invoke the constructor before marking the contract as deployed.
    //   Do that in the BL as well.
    let (retdata_size, retdata, _is_deprecated) = select_execute_entry_point_func(
        block_context=block_context, execution_context=constructor_execution_context
    );
    return (retdata_size=retdata_size, retdata=retdata);
}

// Prepares a constructor execution context based on the 'tx' hint variable.
// Leaves 'execution_info.tx_info' and 'deprecated_tx_info' empty - should be filled later on.
func prepare_constructor_execution_context{range_check_ptr, builtin_ptrs: BuiltinPointers*}(
    block_context: BlockContext*
) -> (constructor_execution_context: ExecutionContext*, salt: felt) {
    alloc_locals;

    local contract_address_salt;
    local class_hash;
    local constructor_calldata_size;
    local constructor_calldata: felt*;
    %{
        ids.contract_address_salt = tx.contract_address_salt
        ids.class_hash = tx.class_hash
        ids.constructor_calldata_size = len(tx.constructor_calldata)
        ids.constructor_calldata = segments.gen_arg(arg=tx.constructor_calldata)
    %}
    assert_nn_le(constructor_calldata_size, SIERRA_ARRAY_LEN_BOUND - 1);

    let selectable_builtins = &builtin_ptrs.selectable;
    let hash_ptr = selectable_builtins.pedersen;
    with hash_ptr {
        let (contract_address) = get_contract_address(
            salt=contract_address_salt,
            class_hash=class_hash,
            constructor_calldata_size=constructor_calldata_size,
            constructor_calldata=constructor_calldata,
            deployer_address=0,
        );
    }
    tempvar builtin_ptrs = new BuiltinPointers(
        selectable=SelectableBuiltins(
            pedersen=hash_ptr,
            range_check=selectable_builtins.range_check,
            ecdsa=selectable_builtins.ecdsa,
            bitwise=selectable_builtins.bitwise,
            ec_op=selectable_builtins.ec_op,
            poseidon=selectable_builtins.poseidon,
            segment_arena=selectable_builtins.segment_arena,
        ),
        non_selectable=builtin_ptrs.non_selectable,
    );

    tempvar constructor_execution_context = new ExecutionContext(
        entry_point_type=ENTRY_POINT_TYPE_CONSTRUCTOR,
        class_hash=class_hash,
        calldata_size=constructor_calldata_size,
        calldata=constructor_calldata,
        execution_info=new ExecutionInfo(
            block_info=block_context.block_info,
            tx_info=cast(nondet %{ segments.add() %}, TxInfo*),
            caller_address=ORIGIN_ADDRESS,
            contract_address=contract_address,
            selector=CONSTRUCTOR_ENTRY_POINT_SELECTOR,
        ),
        deprecated_tx_info=cast(nondet %{ segments.add() %}, DeprecatedTxInfo*),
    );

    return (
        constructor_execution_context=constructor_execution_context, salt=contract_address_salt
    );
}

// Initializes state changes dictionaries.
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
