#[cfg(test)]
mod tests {
    use cairo_vm::serde::deserialize_program::ApTracking;
    use cairo_vm::types::exec_scope::ExecutionScopes;
    use rstest::rstest;

    use crate::hints::*;

    macro_rules! references {
        ($num:expr) => {{
            let mut references = cairo_vm::stdlib::collections::HashMap::<usize, HintReference>::new();
            for i in 0..$num {
                references.insert(i as usize, HintReference::new_simple((i as i32 - $num)));
            }
            references
        }};
    }

    macro_rules! ids_data {
        ( $( $name: expr ),* ) => {
            {
                let ids_names = vec![$( $name ),*];
                let references = references!(ids_names.len() as i32);
                let mut ids_data = cairo_vm::stdlib::collections::HashMap::<cairo_vm::stdlib::string::String, HintReference>::new();
                for (i, name) in ids_names.iter().enumerate() {
                    ids_data.insert(cairo_vm::stdlib::string::ToString::to_string(name), references.get(&i).unwrap().clone());
                }
                ids_data
            }
        };
    }
    #[rstest]
    #[case(Felt252::TWO, Felt252::ONE)]
    #[case(Felt252::THREE, Felt252::ONE)]
    #[case(Felt252::ZERO, Felt252::ZERO)]
    fn test_is_n_ge_two(#[case] input: Felt252, #[case] expected: Felt252) {
        let mut vm = VirtualMachine::new(false);
        let ids_data = ids_data!["n"];
        let ap_tracking = ApTracking::default();
        let mut exec_scopes: ExecutionScopes = ExecutionScopes::new();

        vm.set_fp(1);
        vm.set_ap(1);
        vm.add_memory_segment();
        vm.add_memory_segment();
        // Create ids_data
        let _ = insert_value_from_var_name("n", input, &mut vm, &ids_data, &ap_tracking);
        is_n_ge_two(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &Default::default())
            .expect("is_n_ge_two() failed");

        let relocatable = vm.get_ap();

        let result = vm.get_integer(relocatable).unwrap().into_owned();
        assert_eq!(result, expected);
    }
}
