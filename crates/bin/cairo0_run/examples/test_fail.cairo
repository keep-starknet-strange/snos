%builtins output


func main{output_ptr: felt*}() -> () {

    alloc_locals;
    local use_kzg_da = 1;
    local full_output = 1;
    let compress_state_updates = 1 - full_output;

    local state_updates_start: felt*;
    let state_updates_ptr = state_updates_start;
    %{
        # `use_kzg_da` is used in a hint in `process_data_availability`.
        use_kzg_da = ids.use_kzg_da
        if use_kzg_da or ids.compress_state_updates:
            ids.state_updates_start = segments.add()
        else:
            # Assign a temporary segment, to be relocated into the output segment.
            ids.state_updates_start = segments.add_temp_segment()
    %}

    return();
}