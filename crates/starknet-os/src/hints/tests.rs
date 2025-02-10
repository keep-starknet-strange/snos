#[cfg(test)]
pub mod tests {
    use blockifier::context::BlockContext;
    use blockifier::fee::actual_cost::TransactionReceipt;
    use blockifier::transaction::objects::TransactionExecutionInfo;
    use cairo_vm::serde::deserialize_program::ApTracking;
    use cairo_vm::types::exec_scope::ExecutionScopes;
    use num_bigint::BigInt;
    use rstest::{fixture, rstest};
    use starknet_api::transaction::Fee;
    use vars::ids::{ARRAY_PTR, ELM_SIZE, EXISTS, INDEX, KEY, N_ELMS};

    use crate::config::STORED_BLOCK_HASH_BUFFER;
    use crate::crypto::pedersen::PedersenHash;
    use crate::execution::helper::ContractStorageMap;
    use crate::hints::execute_transactions::fill_holes_in_rc96_segment;
    use crate::hints::find_element::search_sorted_optimistic;
    use crate::hints::*;
    use crate::starknet::starknet_storage::OsSingleStarknetStorage;
    use crate::storage::dict_storage::DictStorage;
    use crate::utils::set_variable_in_root_exec_scope;

    #[allow(clippy::upper_case_acronyms)]
    type PCS = OsSingleStarknetStorage<DictStorage, PedersenHash>;
    #[allow(clippy::upper_case_acronyms)]
    type EHW = ExecutionHelperWrapper<PCS>;

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
        BlockContext::create_for_account_testing()
    }

    #[fixture]
    pub fn old_block_number_and_hash(block_context: BlockContext) -> (Felt252, Felt252) {
        (Felt252::from(block_context.block_info().block_number.0 - STORED_BLOCK_HASH_BUFFER), Felt252::from(66_u64))
    }

    #[fixture]
    fn transaction_execution_info() -> TransactionExecutionInfo {
        TransactionExecutionInfo {
            validate_call_info: None,
            execute_call_info: None,
            fee_transfer_call_info: None,
            revert_error: None,
            transaction_receipt: TransactionReceipt {
                fee: Fee(1234),
                gas: Default::default(),
                da_gas: Default::default(),
                resources: Default::default(),
            },
        }
    }

    #[rstest]
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_set_ap_to_actual_fee_hint(
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
        let exec_helper = ExecutionHelperWrapper::<PCS>::new(
            ContractStorageMap::default(),
            execution_infos,
            &block_context,
            None,
            old_block_number_and_hash,
        );
        exec_helper.start_tx(None).await;
        exec_scopes.insert_box(vars::scopes::EXECUTION_HELPER, Box::new(exec_helper));

        set_ap_to_actual_fee::<PCS>(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &Default::default())
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
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_start_tx(
        block_context: BlockContext,
        transaction_execution_info: TransactionExecutionInfo,
        old_block_number_and_hash: (Felt252, Felt252),
    ) {
        let mut vm = VirtualMachine::new(false);
        vm.set_fp(1);
        vm.add_memory_segment();
        vm.add_memory_segment();

        let mut ids_data = HashMap::new();
        ids_data.insert(vars::ids::DEPRECATED_TX_INFO.to_owned(), HintReference::new(0, 0, false, false));

        let ap_tracking = ApTracking::default();

        let mut exec_scopes = ExecutionScopes::new();

        // we need an execution info in order to start a tx
        let execution_infos = vec![transaction_execution_info];
        let exec_helper =
            EHW::new(ContractStorageMap::default(), execution_infos, &block_context, None, old_block_number_and_hash);
        let exec_helper_box = Box::new(exec_helper);
        exec_scopes.insert_box(vars::scopes::EXECUTION_HELPER, exec_helper_box.clone());

        // before starting tx, tx_execution_info should be none
        assert!(exec_helper_box.execution_helper.read().await.tx_execution_info.is_none());

        start_tx::<PCS>(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &Default::default()).expect("start_tx");

        // after starting tx, tx_execution_info should be some
        assert!(exec_helper_box.execution_helper.read().await.tx_execution_info.is_some());
    }

    #[rstest]
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_skip_tx(
        block_context: BlockContext,
        transaction_execution_info: TransactionExecutionInfo,
        old_block_number_and_hash: (Felt252, Felt252),
    ) {
        let mut vm = VirtualMachine::new(false);
        vm.set_fp(1);
        vm.add_memory_segment();
        vm.add_memory_segment();

        let mut ids_data = HashMap::new();
        ids_data.insert(vars::ids::DEPRECATED_TX_INFO.to_owned(), HintReference::new(0, 0, false, false));
        let ap_tracking = ApTracking::default();

        let mut exec_scopes = ExecutionScopes::new();

        // skipping a tx is the same as starting and immediately ending it, so we need one
        // execution info to chew through
        let execution_infos = vec![transaction_execution_info];
        let exec_helper =
            EHW::new(ContractStorageMap::default(), execution_infos, &block_context, None, old_block_number_and_hash);
        let exec_helper_box = Box::new(exec_helper);
        exec_scopes.insert_box(vars::scopes::EXECUTION_HELPER, exec_helper_box.clone());

        // before skipping a tx, tx_execution_info should be none and iter should have a next()
        assert!(exec_helper_box.execution_helper.read().await.tx_execution_info.is_none());
        assert!(exec_helper_box
            .execution_helper
            .read()
            .await
            .tx_execution_info_iter
            .clone()
            .peekable()
            .peek()
            .is_some());

        skip_tx::<PCS>(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &Default::default()).expect("skip_tx");

        // after skipping a tx, tx_execution_info should be some and iter should not have a next()
        assert!(exec_helper_box.execution_helper.read().await.tx_execution_info.is_none());
        assert!(exec_helper_box
            .execution_helper
            .read()
            .await
            .tx_execution_info_iter
            .clone()
            .peekable()
            .peek()
            .is_none());
    }

    #[rstest]
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_skip_call(
        block_context: BlockContext,
        transaction_execution_info: TransactionExecutionInfo,
        old_block_number_and_hash: (Felt252, Felt252),
    ) {
        let mut vm = VirtualMachine::new(false);
        vm.set_fp(1);
        vm.add_memory_segment();
        vm.add_memory_segment();

        let mut ids_data = HashMap::new();
        ids_data.insert(vars::ids::DEPRECATED_TX_INFO.to_owned(), HintReference::new(0, 0, false, false));

        let ap_tracking = ApTracking::default();

        let mut exec_scopes = ExecutionScopes::new();

        // specify a call to execute -- default should suffice since we are skipping it
        let mut transaction_execution_info = transaction_execution_info.clone();
        transaction_execution_info.execute_call_info = Some(Default::default());

        let execution_infos = vec![transaction_execution_info];
        let exec_helper =
            EHW::new(ContractStorageMap::default(), execution_infos, &block_context, None, old_block_number_and_hash);
        let exec_helper_box = Box::new(exec_helper);
        exec_scopes.insert_box(vars::scopes::EXECUTION_HELPER, exec_helper_box.clone());

        start_tx::<PCS>(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &Default::default()).expect("start_tx");

        // we should have a call next
        assert!(exec_helper_box.execution_helper.read().await.call_iter.clone().peekable().peek().is_some());

        skip_call::<PCS>(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &Default::default()).expect("skip_call");

        // our only call should have been consumed
        assert!(exec_helper_box.execution_helper.read().await.call_iter.clone().peekable().peek().is_none());
    }

    #[test]
    fn test_built_in_extensive_hints_have_no_duplicates() {
        // find all occurrences of a hint in EXTENSIVE_HINTS
        fn find_matching_indices(hint_to_match: &str) -> Vec<usize> {
            let mut indices = Vec::new();
            for (i, (hint, _)) in EXTENSIVE_HINTS.iter().enumerate() {
                if hint_to_match == *hint {
                    indices.push(i);
                }
            }
            indices
        }

        // look for any duplicates in EXTENSIVE_HINTS and print out all occurrences if found
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

    #[test]
    fn test_fill_holes_in_rc96_segment() {
        let mut vm = VirtualMachine::new(false);
        vm.set_fp(1);
        vm.add_memory_segment();
        vm.add_memory_segment();

        let mut exec_scopes = ExecutionScopes::new();
        let ids_data = ids_data![vars::ids::RANGE_CHECK96_PTR];
        let ap_tracking = ApTracking::default();
        let constants = HashMap::new();

        let mut rc96_segment = vm.add_memory_segment();
        let rc96_segment_size = 10;
        rc96_segment.offset = rc96_segment_size;
        insert_value_from_var_name(vars::ids::RANGE_CHECK96_PTR, rc96_segment, &mut vm, &ids_data, &ap_tracking)
            .expect("insert_value_from_var_name");

        let rc96_base = with_offset(rc96_segment, 0);
        vm.insert_value(rc96_base, Felt252::THREE).expect("insert value at base");
        for i in 1..rc96_segment.offset {
            let address = with_offset(rc96_segment, i);
            assert_eq!(vm.get_maybe(&address), None);
        }

        fill_holes_in_rc96_segment(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants)
            .expect("fill_holes_in_rc96_segment failed");

        // Make sure existing value isn't overwritten
        assert_eq!(vm.get_maybe(&rc96_base), Some(Felt252::THREE.into()));

        for i in 1..rc96_segment_size {
            let address = with_offset(rc96_segment, i);
            assert_eq!(vm.get_maybe(&address), Some(Felt252::ZERO.into()));
        }
    }

    #[test]
    fn test_search_sorted_optimistic_with_zero_sized_elements() {
        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_fp(2);

        let mut exec_scopes = ExecutionScopes::new();
        let ids_data = ids_data![ARRAY_PTR, ELM_SIZE];
        let ap_tracking = ApTracking::default();
        let constants = HashMap::new();

        let array_ptr = vm.add_memory_segment();
        insert_value_from_var_name(ARRAY_PTR, array_ptr, &mut vm, &ids_data, &ap_tracking).unwrap();
        insert_value_from_var_name(ELM_SIZE, Felt252::ZERO, &mut vm, &ids_data, &ap_tracking).unwrap();

        let result = search_sorted_optimistic(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants);
        match result {
            Err(HintError::AssertionFailed(msg)) => assert_eq!(msg.as_ref(), "elm_size is zero"),
            _ => panic!("{:?}", result),
        }
    }

    #[test]
    fn test_search_sorted_optimistic_with_too_many_elements() {
        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_fp(3);

        let mut exec_scopes = ExecutionScopes::new();
        set_variable_in_root_exec_scope(&mut exec_scopes, vars::scopes::FIND_ELEMENT_MAX_SIZE, Some(2usize));
        let ids_data = ids_data![ARRAY_PTR, ELM_SIZE, N_ELMS];
        let ap_tracking = ApTracking::default();
        let constants = HashMap::new();

        let array_ptr = vm.add_memory_segment();
        insert_value_from_var_name(ARRAY_PTR, array_ptr, &mut vm, &ids_data, &ap_tracking).unwrap();
        insert_value_from_var_name(ELM_SIZE, Felt252::ONE, &mut vm, &ids_data, &ap_tracking).unwrap();
        insert_value_from_var_name(N_ELMS, Felt252::THREE, &mut vm, &ids_data, &ap_tracking).unwrap();

        let result = search_sorted_optimistic(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants);
        match result {
            Err(HintError::AssertionFailed(msg)) => assert!(msg.as_ref().contains("can only be used with n_elms<=2")),
            _ => panic!("{:?}", result),
        }
    }

    #[test]
    fn test_search_sorted_optimistic_present() {
        let (index, exists) = exec_search_sorted_optimistic_on_2_4_6_array(Felt252::from(6)).unwrap();
        assert_eq!(index, Felt252::TWO);
        assert_eq!(exists, Felt252::ONE);
    }

    #[test]
    fn test_search_sorted_optimistic_smaller_value_present() {
        let (index, exists) = exec_search_sorted_optimistic_on_2_4_6_array(Felt252::from(3)).unwrap();
        assert_eq!(index, Felt252::ONE);
        assert_eq!(exists, Felt252::ZERO);
    }

    #[test]
    fn test_search_sorted_optimistic_smaller_value_not_present() {
        let (index, exists) = exec_search_sorted_optimistic_on_2_4_6_array(Felt252::ONE).unwrap();
        assert_eq!(index, Felt252::ZERO);
        assert_eq!(exists, Felt252::ZERO);
    }

    fn exec_search_sorted_optimistic_on_2_4_6_array(key: Felt252) -> Result<(Felt252, Felt252), HintError> {
        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_fp(6);

        let mut exec_scopes = ExecutionScopes::new();
        set_variable_in_root_exec_scope(&mut exec_scopes, vars::scopes::FIND_ELEMENT_MAX_SIZE, Some(3usize));
        let ids_data = ids_data![ARRAY_PTR, ELM_SIZE, N_ELMS, KEY, INDEX, EXISTS];
        let ap_tracking = ApTracking::default();
        let constants = HashMap::new();

        let array_ptr = vm.add_memory_segment();
        vm.insert_value(with_offset(array_ptr, 0), Felt252::from(2))?;
        vm.insert_value(with_offset(array_ptr, 1), Felt252::from(4))?;
        vm.insert_value(with_offset(array_ptr, 2), Felt252::from(6))?;
        insert_value_from_var_name(ARRAY_PTR, array_ptr, &mut vm, &ids_data, &ap_tracking)?;
        insert_value_from_var_name(ELM_SIZE, Felt252::ONE, &mut vm, &ids_data, &ap_tracking)?;
        insert_value_from_var_name(N_ELMS, Felt252::THREE, &mut vm, &ids_data, &ap_tracking)?;
        insert_value_from_var_name(KEY, key, &mut vm, &ids_data, &ap_tracking)?;

        search_sorted_optimistic(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants)?;

        let index = get_integer_from_var_name(INDEX, &vm, &ids_data, &ap_tracking)?;
        let exists = get_integer_from_var_name(EXISTS, &vm, &ids_data, &ap_tracking)?;
        Ok((index, exists))
    }

    fn with_offset(mut relocatable: Relocatable, offset: usize) -> Relocatable {
        relocatable.offset = offset;
        relocatable
    }
}
