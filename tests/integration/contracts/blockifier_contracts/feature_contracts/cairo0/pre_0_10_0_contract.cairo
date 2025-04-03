%lang starknet


@constructor
func constructor{syscall_ptr: felt*}(value: felt):
    assert value = 42
    return ()
end

@external
func with_arg(num: felt):
    assert num = 25
    return ()
end