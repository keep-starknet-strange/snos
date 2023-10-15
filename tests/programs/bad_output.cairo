%builtins output

func main{output_ptr: felt*}() {
    alloc_locals;
    local a;

    // rust exec will write the incorrect val
    %{ ids.a = 420 %}

    assert [output_ptr] = a;
    let output_ptr = output_ptr + 1;

    return ();
}
