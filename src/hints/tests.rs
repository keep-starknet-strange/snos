#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;

    use blockifier::block_context::{BlockContext, FeeTokenAddresses, GasPrices};
    use blockifier::transaction::objects::TransactionExecutionInfo;
    use rstest::{fixture, rstest};
    use starknet_api::block::{BlockNumber, BlockTimestamp};
    use starknet_api::core::{ChainId, ContractAddress, PatriciaKey};
    use starknet_api::hash::StarkHash;
    use starknet_api::transaction::Fee;
    use starknet_api::{contract_address, patricia_key};

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

    #[fixture]
    pub fn block_context() -> BlockContext {
        BlockContext {
            chain_id: ChainId("SN_GOERLI".to_string()),
            block_number: BlockNumber(1_000_000),
            block_timestamp: BlockTimestamp(1_704_067_200),
            sequencer_address: contract_address!("0x0"),
            fee_token_addresses: FeeTokenAddresses {
                eth_fee_token_address: contract_address!("0x1"),
                strk_fee_token_address: contract_address!("0x2"),
            },
            vm_resource_fee_cost: Arc::new(HashMap::new()),
            gas_prices: GasPrices { eth_l1_gas_price: 1, strk_l1_gas_price: 1 },
            invoke_tx_max_n_steps: 1,
            validate_max_n_steps: 1,
            max_recursion_depth: 50,
        }
    }

    #[fixture]
    fn transaction_execution_info() -> TransactionExecutionInfo {
        TransactionExecutionInfo {
            validate_call_info: None,
            execute_call_info: None,
            fee_transfer_call_info: None,
            actual_fee: Fee(1234),
            actual_resources: Default::default(),
            revert_error: None,
        }
    }

    #[rstest]
    fn test_set_ap_to_actual_fee_hint(
        block_context: BlockContext,
        transaction_execution_info: TransactionExecutionInfo,
    ) {
        let mut vm = VirtualMachine::new(false);
        vm.set_fp(1);
        vm.add_memory_segment();
        vm.add_memory_segment();

        let ids_data = Default::default();
        let ap_tracking = ApTracking::default();

        let mut exec_scopes = ExecutionScopes::new();

        // inject txn execution info with a fee for hint to use
        let execution_infos = vec![transaction_execution_info];
        let exec_helper = ExecutionHelperWrapper::new(execution_infos, &block_context);
        exec_helper.start_tx(None);
        exec_scopes.insert_box(vars::scopes::EXECUTION_HELPER, Box::new(exec_helper));

        set_ap_to_actual_fee(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &Default::default())
            .expect("set_ap_to_actual_fee() failed");

        let ap = vm.get_ap();

        let fee = vm.get_integer(ap).unwrap().into_owned();
        assert_eq!(fee, 1234.into());
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
