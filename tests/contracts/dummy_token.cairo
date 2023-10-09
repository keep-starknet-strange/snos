%lang starknet

// Include account functions to be able to deploy this contract using `DeployAccount` transaction.
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.uint256 import Uint256
from starkware.starknet.core.test_contract.dummy_account import (
    __execute__,
    __validate__,
    __validate_declare__,
    __validate_deploy__,
)

@view
func balanceOf{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(account: felt) -> (
    balance: Uint256
) {
    return (balance=Uint256(low=2 ** 127, high=0));
}

@external
func transfer{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    recipient: felt, amount: Uint256
) -> (success: felt) {
    return (success=1);
}
