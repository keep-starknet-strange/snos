from typing import NamedTuple, Optional, cast

import pytest

from starkware.cairo.common.cairo_secp import secp_utils
from starkware.cairo.common.structs import CairoStructProxy
from starkware.cairo.lang.cairo_constants import DEFAULT_PRIME
from starkware.cairo.lang.compiler.test_utils import short_string_to_felt
from starkware.cairo.lang.vm.memory_dict import MemoryDict
from starkware.cairo.lang.vm.memory_segments import MemorySegmentManager
from starkware.cairo.lang.vm.relocatable import RelocatableValue
from starkware.python.math_utils import EC_INFINITY
from starkware.python.utils import snake_to_camel_case
from starkware.starknet.business_logic.execution.execute_entry_point import ExecuteEntryPoint
from starkware.starknet.business_logic.execution.objects import (
    ExecutionResourcesManager,
    OrderedEvent,
    OrderedL2ToL1Message,
    TransactionExecutionContext,
)
from starkware.starknet.business_logic.state.state import CachedSyncState
from starkware.starknet.business_logic.state.state_api import SyncState
from starkware.starknet.business_logic.state.state_api_objects import BlockInfo
from starkware.starknet.business_logic.state.storage_domain import StorageDomain
from starkware.starknet.business_logic.state.test_utils import EmptySyncStateReader
from starkware.starknet.core.os.syscall_handler import (
    KECCAK_FULL_RATE_IN_U64S,
    BusinessLogicSyscallHandler,
    to_uint256,
)
from starkware.starknet.definitions import constants
from starkware.starknet.definitions.constants import GasCost
from starkware.starknet.definitions.error_codes import CairoErrorCode
from starkware.starknet.definitions.general_config import StarknetGeneralConfig
from starkware.starknet.services.api.contract_class.contract_class import CompiledClass
from starkware.starknet.services.api.contract_class.contract_class_test_utils import (
    get_compiled_class_by_name,
)

CURRENT_BLOCK_NUMBER = 40  # Some number bigger then STORED_BLOCK_HASH_BUFFER.
CONTRACT_ADDRESS = 1991


# Fixtures.


@pytest.fixture(scope="module")
def general_config() -> StarknetGeneralConfig:
    return StarknetGeneralConfig()


@pytest.fixture(scope="module")
def compiled_class() -> CompiledClass:
    return get_compiled_class_by_name("test_contract")


@pytest.fixture
def state(compiled_class: CompiledClass) -> CachedSyncState:
    """
    Returns a state with a deployed contract.
    """
    block_timestamp = 1
    state = CachedSyncState(
        state_reader=EmptySyncStateReader(),
        block_info=BlockInfo.create_for_testing(
            block_number=CURRENT_BLOCK_NUMBER, block_timestamp=block_timestamp
        ),
        compiled_class_cache={},
    )
    class_hash = 28
    compiled_class_hash = 6

    # Declare new version class.
    state.compiled_classes[compiled_class_hash] = compiled_class
    state.set_compiled_class_hash(class_hash=class_hash, compiled_class_hash=compiled_class_hash)
    # Deploy.
    state.deploy_contract(contract_address=CONTRACT_ADDRESS, class_hash=class_hash)

    return state


@pytest.fixture
def tx_execution_context() -> TransactionExecutionContext:
    return TransactionExecutionContext.create_for_testing(
        account_contract_address=11, max_fee=22, nonce=33
    )


@pytest.fixture
def entry_point() -> ExecuteEntryPoint:
    return ExecuteEntryPoint.create_for_testing(
        contract_address=CONTRACT_ADDRESS, calldata=[1], entry_point_selector=2, caller_address=3
    )


@pytest.fixture
def syscall_handler(
    state: CachedSyncState,
    tx_execution_context: TransactionExecutionContext,
    general_config: StarknetGeneralConfig,
    entry_point: ExecuteEntryPoint,
) -> BusinessLogicSyscallHandler:
    segments = MemorySegmentManager(memory=MemoryDict({}), prime=DEFAULT_PRIME)
    return BusinessLogicSyscallHandler(
        state=state,
        resources_manager=ExecutionResourcesManager.empty(),
        segments=segments,
        tx_execution_context=tx_execution_context,
        initial_syscall_ptr=segments.add(),
        entry_point=entry_point,
        general_config=general_config,
        support_reverted=True,
    )


def test_storage_write(state: SyncState, syscall_handler: BusinessLogicSyscallHandler):
    """
    Tests the SyscallHandler's storage_write syscall.
    """
    # Positive flow.
    key, value = 1970, 555
    syscall_handler_test_body(
        syscall_handler=syscall_handler,
        syscall_name="storage_write",
        request=syscall_handler.structs.StorageWriteRequest(reserved=0, key=key, value=value),
    )
    assert (
        state.get_storage_at(
            storage_domain=StorageDomain.ON_CHAIN, contract_address=CONTRACT_ADDRESS, key=key
        )
        == value
    )

    # Negative flow - out of gas.
    new_value = 777
    syscall_handler_test_body(
        syscall_handler=syscall_handler,
        syscall_name="storage_write",
        request=syscall_handler.structs.StorageWriteRequest(reserved=0, key=key, value=new_value),
        out_of_gas=True,
    )
    # Storage should not be changed.
    assert (
        state.get_storage_at(
            storage_domain=StorageDomain.ON_CHAIN, contract_address=CONTRACT_ADDRESS, key=key
        )
        == value
    )


def test_storage_read(state: SyncState, syscall_handler: BusinessLogicSyscallHandler):
    """
    Tests the SyscallHandler's storage_read syscall.
    """
    # Set a non-trivial value to storage.
    key, value = 2023, 777
    state.set_storage_at(
        storage_domain=StorageDomain.ON_CHAIN,
        contract_address=CONTRACT_ADDRESS,
        key=key,
        value=value,
    )

    structs = syscall_handler.structs

    # Positive flow.
    syscall_handler_test_body(
        syscall_handler=syscall_handler,
        syscall_name="storage_read",
        request=structs.StorageReadRequest(reserved=0, key=key),
        response_struct=structs.StorageReadResponse,
        expected_response=structs.StorageReadResponse(value=value),
    )

    # Negative flow - out of gas.
    syscall_handler_test_body(
        syscall_handler=syscall_handler,
        syscall_name="storage_read",
        request=structs.StorageReadRequest(reserved=0, key=key),
        out_of_gas=True,
    )


def test_emit_event(syscall_handler: BusinessLogicSyscallHandler):
    """
    Tests the SyscallHandler's emit_event syscall.
    """
    structs = syscall_handler.structs
    keys_start = syscall_handler.segments.add()
    keys = [5]
    keys_end = syscall_handler.segments.load_data(ptr=keys_start, data=keys)
    data_start = syscall_handler.segments.add()
    data = [6]
    data_end = syscall_handler.segments.load_data(ptr=data_start, data=data)
    syscall_handler_test_body(
        syscall_handler=syscall_handler,
        syscall_name="emit_event",
        request=structs.EmitEventRequest(
            keys_start=keys_start, keys_end=keys_end, data_start=data_start, data_end=data_end
        ),
        response_struct=None,
        expected_response=None,
    )

    assert len(syscall_handler.events) == 1
    assert syscall_handler.events == [OrderedEvent(order=0, keys=keys, data=data)]


def test_send_message_to_l1(syscall_handler: BusinessLogicSyscallHandler):
    """
    Tests the SyscallHandler's send_message_to_l1 syscall.
    """
    structs = syscall_handler.structs
    to_address = 0
    payload_start = syscall_handler.segments.add()
    payload = [5]
    payload_end = syscall_handler.segments.load_data(ptr=payload_start, data=payload)
    syscall_handler_test_body(
        syscall_handler=syscall_handler,
        syscall_name="send_message_to_l1",
        request=structs.SendMessageToL1Request(
            to_address=to_address, payload_start=payload_start, payload_end=payload_end
        ),
        response_struct=None,
        expected_response=None,
    )

    assert len(syscall_handler.l2_to_l1_messages) == 1
    assert syscall_handler.l2_to_l1_messages == [
        OrderedL2ToL1Message(order=0, to_address=to_address, payload=payload)
    ]


def test_get_block_hash(syscall_handler: BusinessLogicSyscallHandler):
    """
    Tests the SyscallHandler's get_block_hash syscall.
    """
    structs = syscall_handler.structs

    # Positive flow.

    # Initialize block number -> block hash entry.
    block_number = CURRENT_BLOCK_NUMBER - constants.STORED_BLOCK_HASH_BUFFER
    block_hash = 1995
    syscall_handler.state.set_storage_at(
        StorageDomain.ON_CHAIN,
        contract_address=constants.BLOCK_HASH_CONTRACT_ADDRESS,
        key=block_number,
        value=block_hash,
    )

    syscall_handler_test_body(
        syscall_handler=syscall_handler,
        syscall_name="get_block_hash",
        request=structs.GetBlockHashRequest(block_number=block_number),
        response_struct=structs.GetBlockHashResponse,
        expected_response=structs.GetBlockHashResponse(block_hash=block_hash),
    )

    # Negative flow - requested block hash is out of range.

    block_number = CURRENT_BLOCK_NUMBER - constants.STORED_BLOCK_HASH_BUFFER + 1
    syscall_handler_failure_test(
        syscall_handler=syscall_handler,
        syscall_name="get_block_hash",
        request=structs.GetBlockHashRequest(block_number=block_number),
        initial_gas=GasCost.GET_BLOCK_HASH.value,
        expected_error_code=CairoErrorCode.BLOCK_NUMBER_OUT_OF_RANGE,
    )


def test_get_execution_info(
    syscall_handler: BusinessLogicSyscallHandler,
    state: SyncState,
    tx_execution_context: TransactionExecutionContext,
    general_config: StarknetGeneralConfig,
    entry_point: ExecuteEntryPoint,
):
    """
    Tests the SyscallHandler's get_execution_info syscall.
    """
    structs = syscall_handler.structs
    syscall_handler_test_body(
        syscall_handler=syscall_handler,
        syscall_name="get_execution_info",
        request=structs.EmptyRequest(),
        response_struct=structs.GetExecutionInfoResponse,
    )

    # Read and check response.
    memory = syscall_handler.segments.memory
    response = structs.GetExecutionInfoResponse.from_ptr(
        memory=memory, addr=syscall_handler.syscall_ptr - 1
    )
    execution_info = structs.ExecutionInfo.from_ptr(memory=memory, addr=response.execution_info)
    assert execution_info == structs.ExecutionInfo(
        block_info=execution_info.block_info,
        tx_info=execution_info.tx_info,
        caller_address=entry_point.caller_address,
        contract_address=entry_point.contract_address,
        selector=entry_point.entry_point_selector,
    )
    block_info = structs.BlockInfo.from_ptr(memory=memory, addr=execution_info.block_info)
    assert block_info == structs.BlockInfo(
        block_number=state.block_info.block_number,
        block_timestamp=state.block_info.block_timestamp,
        sequencer_address=state.block_info.sequencer_address,
    )
    tx_info = structs.TxInfo.from_ptr(memory=memory, addr=execution_info.tx_info)
    assert tx_info == structs.TxInfo(
        version=tx_execution_context.version,
        account_contract_address=tx_execution_context.account_contract_address,
        max_fee=tx_execution_context.max_fee,
        signature_start=tx_info.signature_start,
        signature_end=tx_info.signature_end,
        transaction_hash=tx_execution_context.transaction_hash,
        chain_id=general_config.chain_id.value,
        nonce=tx_execution_context.nonce,
    )
    signature_len = tx_info.signature_end - tx_info.signature_start
    signature = memory.get_range_as_ints(addr=tx_info.signature_start, size=signature_len)
    assert signature == tx_execution_context.signature


def test_secp256k1_syscalls(
    syscall_handler: BusinessLogicSyscallHandler,
):
    """
    Tests the SyscallHandler's secp256k1 syscalls.
    """

    structs = syscall_handler.structs
    segments = syscall_handler.segments
    memory = segments.memory

    # Negative flow - invalid argument.
    syscall_handler_failure_test(
        syscall_handler=syscall_handler,
        syscall_name="secp256k1_new",
        request=structs.Secp256k1NewRequest(
            x=to_uint256(structs, secp_utils.SECP_P), y=to_uint256(structs, 0)
        ),
        initial_gas=GasCost.SECP256K1_NEW.value,
        expected_error_code=CairoErrorCode.INVALID_ARGUMENT,
    )

    # Positive flow - (0, 0) is the point at infinity.
    syscall_handler_test_body(
        syscall_handler=syscall_handler,
        syscall_name="secp256k1_new",
        request=structs.Secp256k1NewRequest(x=to_uint256(structs, 0), y=to_uint256(structs, 0)),
        response_struct=structs.Secp256k1NewResponse,
    )
    # We cannot use expected_response since the response is a newly allocated segment,
    # so we test it manually.
    response = structs.Secp256k1NewResponse.from_ptr(
        memory, syscall_handler.syscall_ptr - structs.Secp256k1NewResponse.size
    )
    assert response.not_on_curve == 0
    p0 = response.ec_point
    assert syscall_handler.ec_points[p0] == EC_INFINITY

    x = 0xF728B4FA42485E3A0A5D2F346BAA9455E3E70682C2094CAC629F6FBED82C07CD
    y = 0x8E182CA967F38E1BD6A49583F43F187608E031AB54FC0C4A8F0DC94FAD0D0611

    # Positive flow - a point on the curve.
    syscall_handler_test_body(
        syscall_handler=syscall_handler,
        syscall_name="secp256k1_new",
        request=structs.Secp256k1NewRequest(x=to_uint256(structs, x), y=to_uint256(structs, y)),
        response_struct=structs.Secp256k1NewResponse,
    )

    # Check the expected response.
    response = structs.Secp256k1NewResponse.from_ptr(
        memory, syscall_handler.syscall_ptr - structs.Secp256k1NewResponse.size
    )

    assert response.not_on_curve == 0
    p1 = response.ec_point
    assert syscall_handler.ec_points[p1] == (x, y)

    # Positive flow - a point on the curve.
    syscall_handler_test_body(
        syscall_handler=syscall_handler,
        syscall_name="secp256k1_get_point_from_x",
        request=structs.Secp256k1GetPointFromXRequest(x=to_uint256(structs, x), y_parity=1),
        response_struct=structs.Secp256k1NewResponse,
    )

    # Check the expected response.
    response = structs.Secp256k1NewResponse.from_ptr(
        memory, syscall_handler.syscall_ptr - structs.Secp256k1NewResponse.size
    )
    assert response.not_on_curve == 0
    assert syscall_handler.ec_points[response.ec_point] == (x, y)

    syscall_handler_test_body(
        syscall_handler=syscall_handler,
        syscall_name="secp256k1_get_xy",
        request=structs.Secp256k1GetXyRequest(ec_point=response.ec_point),
        response_struct=structs.Secp256k1GetXyResponse,
        expected_response=structs.Secp256k1GetXyResponse(
            x=to_uint256(structs, x), y=to_uint256(structs, y)
        ),
    )

    # Positive flow - Add two points.
    syscall_handler_test_body(
        syscall_handler=syscall_handler,
        syscall_name="secp256k1_add",
        request=structs.Secp256k1AddRequest(p0=p0, p1=p1),
        response_struct=structs.Secp256k1OpResponse,
    )

    # Positive flow - 17 * p0.
    syscall_handler_test_body(
        syscall_handler=syscall_handler,
        syscall_name="secp256k1_mul",
        request=structs.Secp256k1MulRequest(p=p0, scalar=to_uint256(structs, 17)),
        response_struct=structs.Secp256k1OpResponse,
    )


def test_keccak_good_case(
    syscall_handler: BusinessLogicSyscallHandler,
):
    """
    Tests the SyscallHandler's keccak syscall.
    """

    structs = syscall_handler.structs

    data = list(range(1, 3 * KECCAK_FULL_RATE_IN_U64S + 1))
    start = syscall_handler.segments.gen_arg(data)

    # Positive flow.
    syscall_handler_test_body(
        syscall_handler=syscall_handler,
        syscall_name="keccak",
        request=structs.KeccakRequest(
            input_start=start, input_end=start + KECCAK_FULL_RATE_IN_U64S
        ),
        response_struct=structs.KeccakResponse,
        expected_response=structs.KeccakResponse(
            result_low=0xEC687BE9C50D2218388DA73622E8FDD5,
            result_high=0xD2EB808DFBA4703C528D145DFE6571AF,
        ),
        additional_gas=GasCost.KECCAK_ROUND_COST.value,
    )

    assert syscall_handler.resources_manager.syscall_counter["keccak"] == 1

    # Positive flow.
    syscall_handler_test_body(
        syscall_handler=syscall_handler,
        syscall_name="keccak",
        request=structs.KeccakRequest(
            input_start=start, input_end=start + 3 * KECCAK_FULL_RATE_IN_U64S
        ),
        response_struct=structs.KeccakResponse,
        expected_response=structs.KeccakResponse(
            result_low=0xEB56A947B570E88C145BD535C9831146,
            result_high=0xF7BA51D4400150464F414250B163C1CB,
        ),
        additional_gas=3 * GasCost.KECCAK_ROUND_COST.value,
    )

    # We expected the syscall above to count as 3 as it does 3 keccak rounds.
    assert syscall_handler.resources_manager.syscall_counter["keccak"] == 4


@pytest.mark.parametrize("input_len", [1, KECCAK_FULL_RATE_IN_U64S - 1])
def test_keccak_invalid_input_lengh(
    syscall_handler: BusinessLogicSyscallHandler,
    input_len,
):
    structs = syscall_handler.structs

    data = list(range(input_len))
    start = syscall_handler.segments.gen_arg(data)
    initial_gas = GasCost.KECCAK_ROUND_COST.value

    syscall_handler_failure_test(
        syscall_handler=syscall_handler,
        syscall_name="keccak",
        request=structs.KeccakRequest(input_start=start, input_end=start + len(data)),
        initial_gas=initial_gas,
        expected_error_code=CairoErrorCode.INVALID_INPUT_LEN,
    )


def test_keccak_out_of_gas(
    syscall_handler: BusinessLogicSyscallHandler,
):
    structs = syscall_handler.structs
    n_blocks = 2
    data = list(range(n_blocks * KECCAK_FULL_RATE_IN_U64S))
    start = syscall_handler.segments.gen_arg(data)

    syscall_handler_test_body(
        syscall_handler=syscall_handler,
        syscall_name="keccak",
        request=structs.KeccakRequest(input_start=start, input_end=start + len(data)),
        out_of_gas=True,
        additional_gas=n_blocks * GasCost.KECCAK_ROUND_COST.value,
    )


def test_replace_class(
    state: CachedSyncState,
    compiled_class: CompiledClass,
    syscall_handler: BusinessLogicSyscallHandler,
):
    """
    Tests the SyscallHandler's replace_class syscall.
    """
    # Declare new version class.
    class_hash = 10028
    compiled_class_hash = 10006

    state.compiled_classes[compiled_class_hash] = compiled_class
    state.set_compiled_class_hash(class_hash=class_hash, compiled_class_hash=compiled_class_hash)

    # Check that the contract's class does not match the class hash before the replacement.
    assert state.get_class_hash_at(contract_address=CONTRACT_ADDRESS) != class_hash

    # Positive flow.
    syscall_handler_test_body(
        syscall_handler=syscall_handler,
        syscall_name="replace_class",
        request=syscall_handler.structs.ReplaceClassRequest(class_hash=class_hash),
    )

    assert state.get_class_hash_at(contract_address=CONTRACT_ADDRESS) == class_hash


# Utilities.


def execute_syscall(
    syscall_handler: BusinessLogicSyscallHandler,
    syscall_name: str,
    request: tuple,
    initial_gas: int,
) -> RelocatableValue:
    syscall_ptr = syscall_handler.syscall_ptr
    segments = syscall_handler.segments
    structs = syscall_handler.structs

    # Prepare request.
    selector = short_string_to_felt(snake_to_camel_case(syscall_name))
    request_header = structs.RequestHeader(selector=selector, gas=initial_gas)

    # Write request.
    segments.write_arg(ptr=syscall_ptr, arg=request_header)
    updated_syscall_ptr = syscall_ptr + len(request_header)

    flat_request = segments.gen_typed_args(cast(NamedTuple, request))
    segments.write_arg(ptr=updated_syscall_ptr, arg=flat_request)
    updated_syscall_ptr += len(flat_request)

    # Execute.
    syscall_handler.syscall(syscall_ptr=syscall_ptr)

    return updated_syscall_ptr


def syscall_handler_test_body(
    syscall_handler: BusinessLogicSyscallHandler,
    syscall_name: str,
    request: tuple,
    out_of_gas: bool = False,
    response_struct: Optional[CairoStructProxy] = None,
    expected_response: Optional[tuple] = None,
    additional_gas: Optional[int] = None,
):
    required_gas = GasCost[syscall_name.upper()].int_value - GasCost.SYSCALL_BASE.value
    if additional_gas is not None:
        required_gas += additional_gas
    if out_of_gas:
        initial_gas = required_gas - 1
        final_gas = initial_gas
        failure_flag = 1
    else:
        initial_gas = required_gas
        final_gas = 0
        failure_flag = 0

    updated_syscall_ptr = execute_syscall(
        syscall_handler=syscall_handler,
        syscall_name=syscall_name,
        request=request,
        initial_gas=initial_gas,
    )

    structs = syscall_handler.structs
    segments = syscall_handler.segments

    # Read and validate response header.
    response_header = structs.ResponseHeader.from_ptr(
        memory=segments.memory, addr=updated_syscall_ptr
    )
    updated_syscall_ptr += len(response_header)
    assert response_header == structs.ResponseHeader(gas=final_gas, failure_flag=failure_flag)

    # Read and validate response body.
    if out_of_gas:
        assert response_struct is None and expected_response is None
        response = structs.FailureReason.from_ptr(memory=segments.memory, addr=updated_syscall_ptr)
        updated_syscall_ptr += len(response)
        array = segments.memory.get_range(response.start, response.end - response.start)
        assert array == [CairoErrorCode.OUT_OF_GAS.to_felt()]
    else:
        if response_struct is not None:
            response = response_struct.from_ptr(memory=segments.memory, addr=updated_syscall_ptr)
            updated_syscall_ptr += response_struct.size
            if expected_response is not None:
                assert response == expected_response

    # Validate that the handler advanced the syscall pointer correctly.
    assert syscall_handler.syscall_ptr == updated_syscall_ptr


def syscall_handler_failure_test(
    syscall_handler: BusinessLogicSyscallHandler,
    syscall_name: str,
    request: tuple,
    initial_gas: int,
    expected_error_code: CairoErrorCode,
):
    updated_syscall_ptr = execute_syscall(
        syscall_handler=syscall_handler,
        syscall_name=syscall_name,
        request=request,
        initial_gas=initial_gas,
    )

    required_gas = GasCost[syscall_name.upper()].int_value - GasCost.SYSCALL_BASE.value

    structs = syscall_handler.structs
    segments = syscall_handler.segments

    # Read and validate response header.
    response_header = structs.ResponseHeader.from_ptr(
        memory=segments.memory, addr=updated_syscall_ptr
    )
    updated_syscall_ptr += len(response_header)
    assert response_header == structs.ResponseHeader(gas=initial_gas - required_gas, failure_flag=1)

    response = structs.FailureReason.from_ptr(memory=segments.memory, addr=updated_syscall_ptr)
    updated_syscall_ptr += len(response)
    array = segments.memory.get_range(response.start, response.end - response.start)
    assert array == [expected_error_code.to_felt()]

    # Validate that the handler advanced the syscall pointer correctly.
    assert syscall_handler.syscall_ptr == updated_syscall_ptr
