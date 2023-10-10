%builtins output

func main(output_ptr: felt*) -> (output_ptr: felt*) {
    alloc_locals;
    local compiled_class_facts;
    local n_compiled_class_facts;
    %{
          ids.compiled_class_facts = segments.add()
          ids.n_compiled_class_facts = len(os_input.compiled_classes)
          vm_enter_scope({
              'compiled_class_facts': iter(os_input.compiled_classes.items()),
          })
    %}
    // When entering a scope we need to exit it afterwards otherwise the vm panics.
    %{ vm_exit_scope() %}
    return(output_ptr = output_ptr);
}
