#[cfg(test)]
pub mod tests {
    use std::sync::Arc;

    use blockifier::block_context::{BlockContext, FeeTokenAddresses, GasPrices};
    use blockifier::transaction::objects::TransactionExecutionInfo;
    use cairo_vm::serde::deserialize_program::ApTracking;
    use cairo_vm::types::exec_scope::ExecutionScopes;
    use num_bigint::BigInt;
    use rstest::{fixture, rstest};
    use starknet_api::block::{BlockNumber, BlockTimestamp};
    use starknet_api::core::{ChainId, ContractAddress, PatriciaKey};
    use starknet_api::hash::StarkHash;
    use starknet_api::transaction::Fee;
    use starknet_api::{contract_address, patricia_key};

    use crate::config::STORED_BLOCK_HASH_BUFFER;
    use crate::execution::helper::ContractStorageMap;
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
    pub fn old_block_number_and_hash(block_context: BlockContext) -> (Felt252, Felt252) {
        (Felt252::from(block_context.block_number.0 - STORED_BLOCK_HASH_BUFFER), Felt252::from(66_u64))
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
        old_block_number_and_hash: (Felt252, Felt252),
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
        let exec_helper = ExecutionHelperWrapper::new(
            ContractStorageMap::default(),
            execution_infos,
            &block_context,
            old_block_number_and_hash,
        );
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
            .expect("is_on_curve should be put in ids_data");
        assert_eq!(is_on_curve, 1.into());
    }

    #[rstest]
    fn test_start_tx(
        block_context: BlockContext,
        transaction_execution_info: TransactionExecutionInfo,
        old_block_number_and_hash: (Felt252, Felt252),
    ) {
        let mut vm = VirtualMachine::new(false);
        vm.set_fp(1);
        vm.add_memory_segment();
        vm.add_memory_segment();

        let ids_data = ids_data![vars::ids::DEPRECATED_TX_INFO];
        let ap_tracking = ApTracking::default();

        let mut exec_scopes = ExecutionScopes::new();

        // we need an execution info in order to start a tx
        let execution_infos = vec![transaction_execution_info];
        let exec_helper = ExecutionHelperWrapper::new(
            ContractStorageMap::default(),
            execution_infos,
            &block_context,
            old_block_number_and_hash,
        );
        let exec_helper_box = Box::new(exec_helper);
        exec_scopes.insert_box(vars::scopes::EXECUTION_HELPER, exec_helper_box.clone());

        // before starting tx, tx_execution_info should be none
        assert!(exec_helper_box.execution_helper.borrow().tx_execution_info.is_none());

        start_tx(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &Default::default()).expect("start_tx");

        // after starting tx, tx_execution_info should be some
        assert!(exec_helper_box.execution_helper.borrow().tx_execution_info.is_some());
    }

    #[rstest]
    fn test_skip_tx(
        block_context: BlockContext,
        transaction_execution_info: TransactionExecutionInfo,
        old_block_number_and_hash: (Felt252, Felt252),
    ) {
        let mut vm = VirtualMachine::new(false);
        vm.set_fp(1);
        vm.add_memory_segment();
        vm.add_memory_segment();

        let ids_data = ids_data![vars::ids::DEPRECATED_TX_INFO];
        let ap_tracking = ApTracking::default();

        let mut exec_scopes = ExecutionScopes::new();

        // skipping a tx is the same as starting and immediately ending it, so we need one
        // execution info to chew through
        let execution_infos = vec![transaction_execution_info];
        let exec_helper = ExecutionHelperWrapper::new(
            ContractStorageMap::default(),
            execution_infos,
            &block_context,
            old_block_number_and_hash,
        );
        let exec_helper_box = Box::new(exec_helper);
        exec_scopes.insert_box(vars::scopes::EXECUTION_HELPER, exec_helper_box.clone());

        // before skipping a tx, tx_execution_info should be none and iter should have a next()
        assert!(exec_helper_box.execution_helper.borrow().tx_execution_info.is_none());
        assert!(exec_helper_box.execution_helper.borrow().tx_execution_info_iter.clone().peekable().peek().is_some());

        skip_tx(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &Default::default()).expect("skip_tx");

        // after skipping a tx, tx_execution_info should be some and iter should not have a next()
        assert!(exec_helper_box.execution_helper.borrow().tx_execution_info.is_none());
        assert!(exec_helper_box.execution_helper.borrow().tx_execution_info_iter.clone().peekable().peek().is_none());
    }

    #[rstest]
    fn test_skip_call(
        block_context: BlockContext,
        transaction_execution_info: TransactionExecutionInfo,
        old_block_number_and_hash: (Felt252, Felt252),
    ) {
        let mut vm = VirtualMachine::new(false);
        vm.set_fp(1);
        vm.add_memory_segment();
        vm.add_memory_segment();

        let ids_data = ids_data![vars::ids::DEPRECATED_TX_INFO];
        let ap_tracking = ApTracking::default();

        let mut exec_scopes = ExecutionScopes::new();

        // specify a call to execute -- default should suffice since we are skipping it
        let mut transaction_execution_info = transaction_execution_info.clone();
        transaction_execution_info.execute_call_info = Some(Default::default());

        let execution_infos = vec![transaction_execution_info];
        let exec_helper = ExecutionHelperWrapper::new(
            ContractStorageMap::default(),
            execution_infos,
            &block_context,
            old_block_number_and_hash,
        );
        let exec_helper_box = Box::new(exec_helper);
        exec_scopes.insert_box(vars::scopes::EXECUTION_HELPER, exec_helper_box.clone());

        start_tx(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &Default::default()).expect("start_tx");

        // we should have a call next
        assert!(exec_helper_box.execution_helper.borrow().call_iter.clone().peekable().peek().is_some());

        skip_call(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &Default::default()).expect("skip_call");

        // our only call should have been consumed
        assert!(exec_helper_box.execution_helper.borrow().call_iter.clone().peekable().peek().is_none());
    }

    #[test]
    fn test_built_in_hints_have_no_duplicates() {
        // find all occurences of a hint in HINTS
        fn find_matching_indices(hint_to_match: &str) -> Vec<usize> {
            let mut indices = Vec::new();
            let mut i = 0;
            for (hint, _) in &HINTS {
                if hint_to_match == *hint {
                    indices.push(i);
                }
                i += 1;
            }
            indices
        }

        // look for any duplicatses in HINTS and print out all occurences if found
        let mut hints: HashMap<String, HintImpl> = HashMap::new();
        for (hint, hint_impl) in &HINTS {
            let hint_str = hint.to_string();
            let existed = hints.insert(hint_str, *hint_impl);
            assert!(
                existed.is_none(),
                "Duplicate hint (indices {:?}) detected:\n-----\n\n{}\n\n-----\n",
                find_matching_indices(hint),
                hint
            );
        }
    }

    #[test]
    fn test_built_in_extensive_hints_have_no_duplicates() {
        // find all occurences of a hint in EXTENSIVE_HINTS
        fn find_matching_indices(hint_to_match: &str) -> Vec<usize> {
            let mut indices = Vec::new();
            let mut i = 0;
            for (hint, _) in &EXTENSIVE_HINTS {
                if hint_to_match == *hint {
                    indices.push(i);
                }
                i += 1;
            }
            indices
        }

        // look for any duplicatses in EXTENSIVE_HINTS and print out all occurences if found
        let mut hints: HashMap<String, ExtensiveHintImpl> = HashMap::new();
        for (hint, hint_impl) in &EXTENSIVE_HINTS {
            let hint_str = hint.to_string();
            let existed = hints.insert(hint_str, *hint_impl);
            assert!(
                existed.is_none(),
                "Duplicate extensive hint (indices {:?}) detected:\n-----\n\n{}\n\n-----\n",
                find_matching_indices(hint),
                hint
            );
        }
    }
}
