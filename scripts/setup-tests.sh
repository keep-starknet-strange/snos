#!/bin/bash

if ! command -v cairo-compile > /dev/null
then
    echo "please start cairo dev environment"
    exit 1
fi

if ! command -v starknet-compile-deprecated > /dev/null
then
    echo "please start cairo dev environment"
    exit 1
fi

git submodule update --init

# setup test_contract path
cp tests/dependencies/test_contract_interface.cairo cairo-lang/src/starkware/starknet/core/test_contract/
cp tests/dependencies/deprecated_syscalls.cairo cairo-lang/src/starkware/starknet/core/test_contract/

starknet-compile-deprecated --no_debug_info tests/contracts/test_contract.cairo --output build/test_contract.json --cairo_path cairo-lang/src

# setup token_for_testing path
mkdir -p cairo-lang/src/starkware/starknet/std_contracts/ERC20
cp tests/dependencies/ERC20.cairo cairo-lang/src/starkware/starknet/std_contracts/ERC20/
cp tests/dependencies/ERC20_base.cairo cairo-lang/src/starkware/starknet/std_contracts/ERC20/
cp tests/dependencies/permitted.cairo cairo-lang/src/starkware/starknet/std_contracts/ERC20/
mkdir -p cairo-lang/src/starkware/starknet/std_contracts/upgradability_proxy
cp tests/dependencies/initializable.cairo cairo-lang/src/starkware/starknet/std_contracts/upgradability_proxy

# compile starknet contract
starknet-compile-deprecated --no_debug_info tests/contracts/token_for_testing.cairo --output build/token_for_testing.json --cairo_path cairo-lang/src --account_contract
starknet-compile-deprecated --no_debug_info tests/contracts/dummy_account.cairo --output build/dummy_account.json --cairo_path cairo-lang/src --account_contract
starknet-compile-deprecated --no_debug_info tests/contracts/dummy_token.cairo --output build/dummy_token.json --cairo_path cairo-lang/src --account_contract

# compile os with debug info
cairo-compile cairo-lang/src/starkware/starknet/core/os/os.cairo --output build/os_debug.json --cairo_path cairo-lang/src

# compile cairo programs
cairo-compile tests/programs/different_output.cairo --output build/different_output.json
cairo-compile tests/programs/fact.cairo --output build/fact.json
cairo-compile tests/programs/hint.cairo --output build/hint.json

