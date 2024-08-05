use std::rc::Rc;

use blockifier::block::BlockInfo;
use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use tokio::sync::RwLock;

use super::helper::ExecutionHelperWrapper;
use crate::cairo_types::syscalls::{
    CallContract, CallContractResponse, Deploy, DeployResponse, GetBlockNumber, GetBlockNumberResponse,
    GetBlockTimestamp, GetBlockTimestampResponse, GetContractAddress, GetContractAddressResponse, GetSequencerAddress,
    GetSequencerAddressResponse, GetTxInfo, GetTxInfoResponse, GetTxSignature, GetTxSignatureResponse, LibraryCall,
    TxInfo,
};
use crate::storage::storage::Storage;
use crate::utils::felt_api2vm;

/// DeprecatedSyscallHandler implementation for execution of system calls in the StarkNet OS
#[derive(Debug)]
pub struct DeprecatedOsSyscallHandler<S>
where
    S: Storage,
{
    pub exec_wrapper: ExecutionHelperWrapper<S>,
    pub syscall_ptr: Relocatable,
    block_info: BlockInfo,
}

/// DeprecatedOsSyscallHandler is wrapped in Rc<RefCell<_>> in order
/// to clone the reference when entering and exiting vm scopes
#[derive(Debug)]
pub struct DeprecatedOsSyscallHandlerWrapper<S: Storage>
where
    S: Storage,
{
    pub deprecated_syscall_handler: Rc<RwLock<DeprecatedOsSyscallHandler<S>>>,
}

impl<S> Clone for DeprecatedOsSyscallHandlerWrapper<S>
where
    S: Storage,
{
    fn clone(&self) -> Self {
        Self { deprecated_syscall_handler: self.deprecated_syscall_handler.clone() }
    }
}

impl<S> DeprecatedOsSyscallHandlerWrapper<S>
where
    S: Storage,
{
    // TODO(#69): implement the syscalls
    pub fn new(exec_wrapper: ExecutionHelperWrapper<S>, syscall_ptr: Relocatable, block_info: BlockInfo) -> Self {
        Self {
            deprecated_syscall_handler: Rc::new(RwLock::new(DeprecatedOsSyscallHandler {
                exec_wrapper,
                syscall_ptr,
                block_info,
            })),
        }
    }

    async fn call_contract_and_write_response(
        &self,
        syscall_ptr: Relocatable,
        response_offset: usize,
        vm: &mut VirtualMachine,
    ) -> Result<(), HintError> {
        let syscall_handler = self.deprecated_syscall_handler.write().await;
        let result =
            syscall_handler.exec_wrapper.execution_helper.write().await.result_iter.next().ok_or(
                HintError::SyscallError("Expected a result when calling contract".to_string().into_boxed_str()),
            )?;

        let retdata_size_offset = response_offset + CallContractResponse::retdata_size_offset();
        let retdata_offset = response_offset + CallContractResponse::retdata_offset();

        // Write the result to the VM memory. First write the length of the result then
        // the result array.
        vm.insert_value((syscall_ptr + retdata_size_offset)?, result.retdata.0.len())?;
        let new_segment = vm.add_temporary_segment();
        let retdata = result
            .retdata
            .0
            .iter()
            .map(|sf| {
                let felt = felt_api2vm(*sf);
                MaybeRelocatable::Int(felt)
            })
            .collect();
        vm.load_data(new_segment, &retdata)?;
        vm.insert_value((syscall_ptr + retdata_offset)?, new_segment)?;

        Ok(())
    }

    pub async fn call_contract(&self, syscall_ptr: Relocatable, vm: &mut VirtualMachine) -> Result<(), HintError> {
        self.call_contract_and_write_response(syscall_ptr, CallContract::response_offset(), vm).await
    }
    #[allow(unused)]
    pub async fn delegate_call(&self, syscall_ptr: Relocatable, vm: &mut VirtualMachine) -> Result<(), HintError> {
        self.call_contract_and_write_response(syscall_ptr, CallContract::response_offset(), vm).await
    }
    pub async fn delegate_l1_handler(
        &self,
        syscall_ptr: Relocatable,
        vm: &mut VirtualMachine,
    ) -> Result<(), HintError> {
        self.call_contract_and_write_response(syscall_ptr, CallContract::response_offset(), vm).await
    }
    pub async fn deploy(&self, syscall_ptr: Relocatable, vm: &mut VirtualMachine) -> Result<(), HintError> {
        let syscall_handler = self.deprecated_syscall_handler.read().await;
        let mut execution_helper = syscall_handler.exec_wrapper.execution_helper.write().await;

        // Advance the result iterator
        execution_helper
            .result_iter
            .next()
            .ok_or(HintError::SyscallError("No matching result for deploy syscall".to_string().into_boxed_str()))?;

        let contract_address = execution_helper
            .deployed_contracts_iter
            .next()
            .ok_or(HintError::SyscallError("Could not find matching deployed contract".to_string().into_boxed_str()))?;

        let contract_address_offset = Deploy::response_offset() + DeployResponse::contract_address_offset();
        let constructor_retdata_size_offset =
            Deploy::response_offset() + DeployResponse::constructor_retdata_size_offset();
        let constructor_retdata_offset = Deploy::response_offset() + DeployResponse::constructor_retdata_offset();

        vm.insert_value((syscall_ptr + contract_address_offset)?, contract_address)?;
        vm.insert_value((syscall_ptr + constructor_retdata_size_offset)?, Felt252::ZERO)?;
        vm.insert_value((syscall_ptr + constructor_retdata_offset)?, Felt252::ZERO)?;

        Ok(())
    }

    pub fn emit_event(&self) {
        // Nothing to do
    }

    pub async fn get_block_number(&self, syscall_ptr: Relocatable, vm: &mut VirtualMachine) -> Result<(), HintError> {
        let syscall_handler = self.deprecated_syscall_handler.read().await;

        let block_number = syscall_handler.block_info.block_number;

        let response_offset = GetBlockNumber::response_offset() + GetBlockNumberResponse::block_number_offset();
        vm.insert_value((syscall_ptr + response_offset)?, Felt252::from(block_number.0))?;

        Ok(())
    }

    pub async fn get_block_timestamp(
        &self,
        syscall_ptr: Relocatable,
        vm: &mut VirtualMachine,
    ) -> Result<(), HintError> {
        let syscall_handler = self.deprecated_syscall_handler.read().await;

        let block_timestamp = syscall_handler.block_info.block_timestamp;

        let response_offset =
            GetBlockTimestamp::response_offset() + GetBlockTimestampResponse::block_timestamp_offset();
        vm.insert_value((syscall_ptr + response_offset)?, Felt252::from(block_timestamp.0))?;

        Ok(())
    }

    pub async fn get_caller_address(&self, syscall_ptr: Relocatable, vm: &mut VirtualMachine) {
        let sys_hand = self.deprecated_syscall_handler.read().await;
        let exec_helper = sys_hand.exec_wrapper.execution_helper.read().await;
        let caller_address =
            exec_helper.call_info.as_ref().expect("A call should have some call info").call.caller_address.0.key();
        let caller_address = felt_api2vm(*caller_address);

        // TODO: create proper struct for this (similar to GetCallerAddress and friends)
        // TODO: abstract this similar to pythonic _write_syscall_response()

        log::debug!("get_caller_address() syscall, syscall_ptr = {}, caller_address = {}", syscall_ptr, caller_address);

        vm.insert_value((syscall_ptr + 1usize).unwrap(), caller_address).unwrap();
    }
    pub async fn get_contract_address(
        &self,
        syscall_ptr: Relocatable,
        vm: &mut VirtualMachine,
    ) -> Result<(), HintError> {
        let syscall_handler = self.deprecated_syscall_handler.read().await;
        let exec_helper = syscall_handler.exec_wrapper.execution_helper.read().await;

        let contract_address =
            exec_helper.call_info.as_ref().map(|info| info.call.storage_address).ok_or(HintError::SyscallError(
                "Missing storage address from call info".to_string().into_boxed_str(),
            ))?;
        let contract_address_felt = felt_api2vm(*contract_address.0.key());

        let response_offset =
            GetContractAddress::response_offset() + GetContractAddressResponse::contract_address_offset();
        vm.insert_value((syscall_ptr + response_offset)?, contract_address_felt)?;

        Ok(())
    }
    pub async fn get_sequencer_address(
        &self,
        syscall_ptr: Relocatable,
        vm: &mut VirtualMachine,
    ) -> Result<(), HintError> {
        let syscall_handler = self.deprecated_syscall_handler.read().await;

        let sequencer_address = felt_api2vm(*syscall_handler.block_info.sequencer_address.0.key());

        let response_offset =
            GetSequencerAddress::response_offset() + GetSequencerAddressResponse::sequencer_address_offset();
        vm.insert_value((syscall_ptr + response_offset)?, sequencer_address)?;

        Ok(())
    }
    pub async fn get_tx_info(&self, syscall_ptr: Relocatable, vm: &mut VirtualMachine) -> Result<(), HintError> {
        let syscall_handler = self.deprecated_syscall_handler.read().await;
        let execution_helper = syscall_handler.exec_wrapper.execution_helper.read().await;

        let tx_info_ptr = execution_helper
            .tx_info_ptr
            .ok_or(HintError::SyscallError("Tx info pointer not set".to_string().into_boxed_str()))?;

        let response_offset = GetTxInfo::response_offset() + GetTxInfoResponse::tx_info_offset();
        vm.insert_value((syscall_ptr + response_offset)?, tx_info_ptr)?;

        Ok(())
    }

    pub async fn get_tx_signature(&self, syscall_ptr: Relocatable, vm: &mut VirtualMachine) -> Result<(), HintError> {
        let syscall_handler = self.deprecated_syscall_handler.read().await;
        let execution_helper = syscall_handler.exec_wrapper.execution_helper.read().await;

        let tx_info_ptr = execution_helper
            .tx_info_ptr
            .ok_or(HintError::SyscallError("Tx info pointer not set".to_string().into_boxed_str()))?;

        let signature_len = vm.get_integer((tx_info_ptr + TxInfo::signature_len_offset())?)?.into_owned();
        let signature = vm.get_relocatable((tx_info_ptr + TxInfo::signature_offset())?)?;

        let signature_len_offset = GetTxSignature::response_offset() + GetTxSignatureResponse::signature_len_offset();
        let signature_offset = GetTxSignature::response_offset() + GetTxSignatureResponse::signature_offset();

        vm.insert_value((syscall_ptr + signature_len_offset)?, signature_len)?;
        vm.insert_value((syscall_ptr + signature_offset)?, signature)?;

        Ok(())
    }
    pub async fn library_call(&self, syscall_ptr: Relocatable, vm: &mut VirtualMachine) -> Result<(), HintError> {
        self.call_contract_and_write_response(syscall_ptr, LibraryCall::response_offset(), vm).await
    }
    pub async fn library_call_l1_handler(
        &self,
        syscall_ptr: Relocatable,
        vm: &mut VirtualMachine,
    ) -> Result<(), HintError> {
        self.call_contract_and_write_response(syscall_ptr, LibraryCall::response_offset(), vm).await
    }
    pub fn replace_class(&self) {
        // Nothing to do.
    }
    pub fn send_message_to_l1(&self) {
        // Nothing to do
    }
    pub async fn storage_read(&self, syscall_ptr: Relocatable, vm: &mut VirtualMachine) -> Result<(), HintError> {
        let sys_hand = self.deprecated_syscall_handler.write().await;
        let value =
            sys_hand.exec_wrapper.execution_helper.write().await.execute_code_read_iter.next().ok_or(
                HintError::SyscallError("No more storage reads available to replay".to_string().into_boxed_str()),
            )?;

        vm.insert_value((syscall_ptr + 2usize).unwrap(), value).unwrap();

        Ok(())
    }
    pub async fn storage_write(&self, _syscall_ptr: Relocatable) -> Result<(), HintError> {
        let sys_hand = self.deprecated_syscall_handler.write().await;

        let _ = sys_hand.exec_wrapper.execution_helper.write().await.execute_code_read_iter.next().ok_or(
            HintError::SyscallError("No more storage writes available to replay".to_string().into_boxed_str()),
        )?;

        Ok(())
    }

    pub async fn set_syscall_ptr(&self, syscall_ptr: Relocatable) {
        let mut syscall_handler = self.deprecated_syscall_handler.write().await;
        syscall_handler.syscall_ptr = syscall_ptr;
    }

    #[allow(unused)]
    pub async fn syscall_ptr(&self) -> Relocatable {
        self.deprecated_syscall_handler.read().await.syscall_ptr
    }
}

#[cfg(test)]
mod test {
    use std::borrow::Cow;

    use blockifier::block::{BlockInfo, GasPrices};
    use blockifier::context::{BlockContext, ChainInfo, FeeTokenAddresses};
    use blockifier::execution::call_info::Retdata;
    use blockifier::execution::entry_point_execution::CallResult;
    use blockifier::versioned_constants::VersionedConstants;
    use cairo_vm::types::exec_scope::ExecutionScopes;
    use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
    use cairo_vm::vm::vm_core::VirtualMachine;
    use cairo_vm::Felt252;
    use rstest::{fixture, rstest};
    use starknet_api::block::{BlockNumber, BlockTimestamp};
    use starknet_api::core::{ChainId, ContractAddress, PatriciaKey};
    use starknet_api::hash::{StarkFelt, StarkHash};
    use starknet_api::{contract_address, patricia_key};

    use crate::config::STORED_BLOCK_HASH_BUFFER;
    use crate::execution::deprecated_syscall_handler::DeprecatedOsSyscallHandlerWrapper;
    use crate::execution::helper::{ContractStorageMap, ExecutionHelperWrapper};
    use crate::hints::vars;
    use crate::storage::dict_storage::DictStorage;

    #[fixture]
    fn block_context() -> BlockContext {
        let chain_info = ChainInfo {
            chain_id: ChainId("SN_GOERLI".to_string()),
            fee_token_addresses: FeeTokenAddresses {
                strk_fee_token_address: contract_address!("0x1"),
                eth_fee_token_address: contract_address!("0x2"),
            },
        };

        let block_info = BlockInfo {
            block_number: BlockNumber(1_000_000),
            block_timestamp: BlockTimestamp(1_704_067_200),
            sequencer_address: contract_address!("0x0"),
            gas_prices: GasPrices {
                eth_l1_gas_price: 1u128.try_into().unwrap(),
                strk_l1_gas_price: 1u128.try_into().unwrap(),
                eth_l1_data_gas_price: 1u128.try_into().unwrap(),
                strk_l1_data_gas_price: 1u128.try_into().unwrap(),
            },
            use_kzg_da: false,
        };

        BlockContext::new_unchecked(&block_info, &chain_info, VersionedConstants::latest_constants())
    }

    #[fixture]
    fn old_block_number_and_hash(block_context: BlockContext) -> (Felt252, Felt252) {
        (Felt252::from(block_context.block_info().block_number.0 - STORED_BLOCK_HASH_BUFFER), Felt252::from(66_u64))
    }

    #[rstest]
    #[tokio::test]
    async fn test_call_contract(block_context: BlockContext, old_block_number_and_hash: (Felt252, Felt252)) {
        let mut vm = VirtualMachine::new(false);
        vm.set_fp(1);
        vm.add_memory_segment();
        vm.add_memory_segment();

        let syscall_ptr = vm.add_memory_segment();

        let mut exec_scopes = ExecutionScopes::new();

        let execution_infos = Default::default();
        let exec_helper = ExecutionHelperWrapper::<DictStorage>::new(
            ContractStorageMap::default(),
            execution_infos,
            &block_context,
            old_block_number_and_hash,
        );

        // insert a call result for call_contract to replay. it should insert this into a new temporary
        // segment and insert its size somewhere in syscall_ptr.
        let call_results = vec![CallResult {
            failed: false,
            retdata: Retdata(vec![StarkFelt::THREE, StarkFelt::TWO, StarkFelt::ONE]),
            gas_consumed: 1,
        }];
        exec_helper.execution_helper.write().await.result_iter = call_results.into_iter();

        let exec_helper_box = Box::new(exec_helper);
        exec_scopes.insert_box(vars::scopes::EXECUTION_HELPER, exec_helper_box.clone());

        let syscall_handler =
            DeprecatedOsSyscallHandlerWrapper::new(*exec_helper_box, syscall_ptr, block_context.block_info().clone());

        syscall_handler.call_contract(syscall_ptr, &mut vm).await.unwrap();

        // syscall_ptr should have been filled out syscall_ptr segment with a CallContractResponse
        let syscall_data_raw = vm.get_range(syscall_ptr, 7); // TODO: derive from struct size?
        let expected_temp_segment = Relocatable { segment_index: -1, offset: 0 };
        assert_eq!(
            syscall_data_raw,
            vec![
                None,
                None,
                None,
                None,
                None,
                Some(Cow::Borrowed(&MaybeRelocatable::Int(Felt252::THREE))),
                Some(Cow::Borrowed(&MaybeRelocatable::RelocatableValue(expected_temp_segment))),
            ]
        );

        // the retdata should have been copied into the temp segment
        let retdata_raw = vm.get_range(expected_temp_segment, 3);
        assert_eq!(
            retdata_raw,
            vec![
                Some(Cow::Borrowed(&MaybeRelocatable::Int(Felt252::THREE))),
                Some(Cow::Borrowed(&MaybeRelocatable::Int(Felt252::TWO))),
                Some(Cow::Borrowed(&MaybeRelocatable::Int(Felt252::ONE))),
            ]
        );
    }
}
