#[cfg(test)]
mod tests {
    use cairo_vm::serde::deserialize_program::ApTracking;
    use cairo_vm::types::exec_scope::ExecutionScopes;
    use num_bigint::BigInt;
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

    #[test]
    fn test_is_on_curve() {
        let mut vm = VirtualMachine::new(false);
        vm.set_fp(1);
        vm.add_memory_segment();
        vm.add_memory_segment();

        let ids_data = ids_data![vars::ids::IS_ON_CURVE];
        let ap_tracking = ApTracking::default();

        let mut exec_scopes = ExecutionScopes::new();

        let y = BigInt::from(1234);
        let y_square_int = y.clone() * y.clone();

        exec_scopes.insert_value(vars::ids::Y, y);
        exec_scopes.insert_value(vars::ids::Y_SQUARE_INT, y_square_int);

        // TODO: use an appropriate constant for SECP_P. Also see TODO in `fn is_on_curve` -- should it be
        // in exec_scopes to begin with, or should it implicitly exist in the hint itself?
        use std::str::FromStr;
        let secp_p =
            BigInt::from_str("115792089237316195423570985008687907853269984665640564039457584007908834671663").unwrap();
        exec_scopes.insert_value(vars::ids::SECP_P, secp_p);

        is_on_curve(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &Default::default())
            .expect("is_on_curve() failed");

        let is_on_curve: Felt252 = get_integer_from_var_name(vars::ids::IS_ON_CURVE, &vm, &ids_data, &ap_tracking)
            .expect("is_on_curve should be put in ids_data")
            .into_owned();
        assert_eq!(is_on_curve, 1.into());
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
