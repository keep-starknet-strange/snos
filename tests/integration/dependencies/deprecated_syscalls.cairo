// Contains deprecated system calls that are still backward-compatible;
// for internal use only.

from starkware.starknet.common.syscalls import (
    DELEGATE_CALL_SELECTOR,
    DELEGATE_L1_HANDLER_SELECTOR,
    CallContract,
    CallContractRequest,
)

func delegate_call{syscall_ptr: felt*}(
    contract_address: felt, function_selector: felt, calldata_size: felt, calldata: felt*
) -> (retdata_size: felt, retdata: felt*) {
    let syscall = [cast(syscall_ptr, CallContract*)];
    assert syscall.request = CallContractRequest(
        selector=DELEGATE_CALL_SELECTOR,
        contract_address=contract_address,
        function_selector=function_selector,
        calldata_size=calldata_size,
        calldata=calldata,
    );
    %{ syscall_handler.delegate_call(segments=segments, syscall_ptr=ids.syscall_ptr) %}
    let response = syscall.response;

    let syscall_ptr = syscall_ptr + CallContract.SIZE;
    return (retdata_size=response.retdata_size, retdata=response.retdata);
}

func delegate_l1_handler{syscall_ptr: felt*}(
    contract_address: felt, function_selector: felt, calldata_size: felt, calldata: felt*
) -> (retdata_size: felt, retdata: felt*) {
    let syscall = [cast(syscall_ptr, CallContract*)];
    assert syscall.request = CallContractRequest(
        selector=DELEGATE_L1_HANDLER_SELECTOR,
        contract_address=contract_address,
        function_selector=function_selector,
        calldata_size=calldata_size,
        calldata=calldata,
    );
    %{ syscall_handler.delegate_l1_handler(segments=segments, syscall_ptr=ids.syscall_ptr) %}
    let response = syscall.response;

    let syscall_ptr = syscall_ptr + CallContract.SIZE;
    return (retdata_size=response.retdata_size, retdata=response.retdata);
}
