%builtins output

func main(output_ptr: felt*) -> (output_ptr: felt*) {
    tempvar a = 17;
    a = [output_ptr], ap++;

    // Use custom hint to print the value of a
    %{ print(ids.a) %}
    let output_ptr = output_ptr + 1;

    return(output_ptr = output_ptr);
}
