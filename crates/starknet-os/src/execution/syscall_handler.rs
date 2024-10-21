use std::rc::Rc;

use blockifier::execution::execution_utils::ReadOnlySegments;
use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use tokio::sync::RwLock;

use super::helper::ExecutionHelperWrapper;
use crate::cairo_types::new_syscalls::{self};
use crate::execution::constants::{
    BLOCK_HASH_CONTRACT_ADDRESS, CALL_CONTRACT_GAS_COST, DEPLOY_GAS_COST, EMIT_EVENT_GAS_COST, GET_BLOCK_HASH_GAS_COST,
    GET_EXECUTION_INFO_GAS_COST, INVALID_INPUT_LENGTH_ERROR, KECCAK_FULL_RATE_IN_U64S, KECCAK_GAS_COST,
    KECCAK_ROUND_COST_GAS_COST, LIBRARY_CALL_GAS_COST, REPLACE_CLASS_GAS_COST, SECP256K1_ADD_GAS_COST,
    SECP256K1_GET_POINT_FROM_X_GAS_COST, SECP256K1_GET_XY_GAS_COST, SECP256K1_MUL_GAS_COST, SECP256K1_NEW_GAS_COST,
    SECP256R1_ADD_GAS_COST, SECP256R1_GET_POINT_FROM_X_GAS_COST, SECP256R1_GET_XY_GAS_COST, SECP256R1_MUL_GAS_COST,
    SECP256R1_NEW_GAS_COST, SEND_MESSAGE_TO_L1_GAS_COST, SHA256_PROCESS_BLOCK_GAS_COST, STORAGE_READ_GAS_COST,
    STORAGE_WRITE_GAS_COST,
};
use crate::execution::secp_handler::{
    SecpAddHandler, SecpGetPointFromXHandler, SecpGetXyHandler, SecpMulHandler, SecpNewHandler,
};
use crate::execution::syscall_handler_utils::{
    felt_from_ptr, run_handler, write_felt, write_maybe_relocatable, write_segment, EmptyRequest, EmptyResponse,
    ReadOnlySegment, SyscallExecutionError, SyscallHandler, SyscallResult, SyscallSelector, WriteResponseResult,
};
use crate::starknet::starknet_storage::PerContractStorage;

/// DeprecatedSyscallHandler implementation for execution of system calls in the StarkNet OS
#[derive(Debug)]
pub struct OsSyscallHandler<PCS: PerContractStorage>
where
    PCS: PerContractStorage,
{
    pub exec_wrapper: ExecutionHelperWrapper<PCS>,
    pub syscall_ptr: Option<Relocatable>,
    pub segments: ReadOnlySegments,
}

/// OsSyscallHandler is wrapped in Rc<RefCell<_>> in order
/// to clone the reference when entering and exiting vm scopes
#[derive(Debug)]
pub struct OsSyscallHandlerWrapper<PCS>
where
    PCS: PerContractStorage,
{
    pub syscall_handler: Rc<RwLock<OsSyscallHandler<PCS>>>,
}

impl<PCS> Clone for OsSyscallHandlerWrapper<PCS>
where
    PCS: PerContractStorage,
{
    fn clone(&self) -> Self {
        Self { syscall_handler: self.syscall_handler.clone() }
    }
}

impl<PCS> OsSyscallHandlerWrapper<PCS>
where
    PCS: PerContractStorage + 'static,
{
    pub fn new(exec_wrapper: ExecutionHelperWrapper<PCS>) -> Self {
        Self {
            syscall_handler: Rc::new(RwLock::new(OsSyscallHandler {
                exec_wrapper,
                syscall_ptr: None,
                segments: ReadOnlySegments::default(),
            })),
        }
    }
    pub async fn set_syscall_ptr(&self, syscall_ptr: Relocatable) {
        let mut syscall_handler = self.syscall_handler.write().await;
        syscall_handler.syscall_ptr = Some(syscall_ptr);
    }

    pub async fn syscall_ptr(&self) -> Option<Relocatable> {
        let syscall_handler = self.syscall_handler.read().await;
        syscall_handler.syscall_ptr
    }

    pub async fn set_sha256_segment(&self, sha256_segment: Relocatable) {
        let syscall_handler = self.syscall_handler.write().await;
        let mut execution_helper = syscall_handler.exec_wrapper.execution_helper.write().await;
        execution_helper.sha256_segment = Some(sha256_segment);
    }

    pub async fn validate_and_discard_syscall_ptr(&self, syscall_ptr_end: Relocatable) -> Result<(), HintError> {
        let mut syscall_handler = self.syscall_handler.write().await;
        let syscall_ptr = syscall_handler.syscall_ptr.ok_or(HintError::CustomHint(Box::from("syscall_ptr is None")))?;
        assert_eq!(syscall_ptr, syscall_ptr_end, "Bad syscall_ptr_end.");
        syscall_handler.syscall_ptr = None;
        Ok(())
    }

    pub async fn execute_syscall(&self, vm: &mut VirtualMachine, syscall_ptr: Relocatable) -> Result<(), HintError> {
        let mut syscall_handler = self.syscall_handler.write().await;
        let ptr = &mut syscall_handler.syscall_ptr.ok_or(HintError::CustomHint(Box::from("syscall_ptr is None")))?;

        assert_eq!(*ptr, syscall_ptr);

        let selector = SyscallSelector::try_from(felt_from_ptr(vm, ptr)?)?;

        let ehw = &mut syscall_handler.exec_wrapper;

        match selector {
            SyscallSelector::CallContract => {
                run_handler::<CallContractHandler, PCS>(ptr, vm, ehw, CALL_CONTRACT_GAS_COST).await
            }
            SyscallSelector::Deploy => run_handler::<DeployHandler, PCS>(ptr, vm, ehw, DEPLOY_GAS_COST).await,
            SyscallSelector::EmitEvent => run_handler::<EmitEventHandler, PCS>(ptr, vm, ehw, EMIT_EVENT_GAS_COST).await,
            SyscallSelector::GetBlockHash => {
                run_handler::<GetBlockHashHandler, PCS>(ptr, vm, ehw, GET_BLOCK_HASH_GAS_COST).await
            }
            SyscallSelector::LibraryCall => {
                run_handler::<LibraryCallHandler, PCS>(ptr, vm, ehw, LIBRARY_CALL_GAS_COST).await
            }
            SyscallSelector::GetExecutionInfo => {
                run_handler::<GetExecutionInfoHandler, PCS>(ptr, vm, ehw, GET_EXECUTION_INFO_GAS_COST).await
            }
            SyscallSelector::StorageRead => {
                run_handler::<StorageReadHandler, PCS>(ptr, vm, ehw, STORAGE_READ_GAS_COST).await
            }
            SyscallSelector::StorageWrite => {
                run_handler::<StorageWriteHandler, PCS>(ptr, vm, ehw, STORAGE_WRITE_GAS_COST).await
            }
            SyscallSelector::SendMessageToL1 => {
                run_handler::<SendMessageToL1Handler, PCS>(ptr, vm, ehw, SEND_MESSAGE_TO_L1_GAS_COST).await
            }
            SyscallSelector::ReplaceClass => {
                run_handler::<ReplaceClassHandler, PCS>(ptr, vm, ehw, REPLACE_CLASS_GAS_COST).await
            }
            SyscallSelector::LibraryCallL1Handler => {
                run_handler::<LibraryCallHandler, PCS>(ptr, vm, ehw, LIBRARY_CALL_GAS_COST).await
            }
            SyscallSelector::Keccak => run_handler::<KeccakHandler, PCS>(ptr, vm, ehw, KECCAK_GAS_COST).await,
            SyscallSelector::Secp256k1New => {
                run_handler::<SecpNewHandler<ark_secp256k1::Config>, PCS>(ptr, vm, ehw, SECP256K1_NEW_GAS_COST).await
            }
            SyscallSelector::Secp256k1GetXy => {
                run_handler::<SecpGetXyHandler<ark_secp256k1::Config>, PCS>(ptr, vm, ehw, SECP256K1_GET_XY_GAS_COST)
                    .await
            }
            SyscallSelector::Secp256k1GetPointFromX => {
                run_handler::<SecpGetPointFromXHandler<ark_secp256k1::Config>, PCS>(
                    ptr,
                    vm,
                    ehw,
                    SECP256K1_GET_POINT_FROM_X_GAS_COST,
                )
                .await
            }
            SyscallSelector::Secp256k1Mul => {
                run_handler::<SecpMulHandler<ark_secp256k1::Config>, PCS>(ptr, vm, ehw, SECP256K1_MUL_GAS_COST).await
            }
            SyscallSelector::Secp256k1Add => {
                run_handler::<SecpAddHandler<ark_secp256k1::Config>, PCS>(ptr, vm, ehw, SECP256K1_ADD_GAS_COST).await
            }

            SyscallSelector::Secp256r1New => {
                run_handler::<SecpNewHandler<ark_secp256r1::Config>, PCS>(ptr, vm, ehw, SECP256R1_NEW_GAS_COST).await
            }
            SyscallSelector::Secp256r1GetXy => {
                run_handler::<SecpGetXyHandler<ark_secp256r1::Config>, PCS>(ptr, vm, ehw, SECP256R1_GET_XY_GAS_COST)
                    .await
            }
            SyscallSelector::Secp256r1GetPointFromX => {
                run_handler::<SecpGetPointFromXHandler<ark_secp256r1::Config>, PCS>(
                    ptr,
                    vm,
                    ehw,
                    SECP256R1_GET_POINT_FROM_X_GAS_COST,
                )
                .await
            }
            SyscallSelector::Secp256r1Mul => {
                run_handler::<SecpMulHandler<ark_secp256r1::Config>, PCS>(ptr, vm, ehw, SECP256R1_MUL_GAS_COST).await
            }
            SyscallSelector::Secp256r1Add => {
                run_handler::<SecpAddHandler<ark_secp256r1::Config>, PCS>(ptr, vm, ehw, SECP256R1_ADD_GAS_COST).await
            }
            SyscallSelector::Sha256ProcessBlock => {
                run_handler::<Sha256ProcessBlockHandler, PCS>(ptr, vm, ehw, SHA256_PROCESS_BLOCK_GAS_COST).await
            }

            _ => Err(HintError::CustomHint(format!("Unknown syscall selector: {:?}", selector).into())),
        }?;

        syscall_handler.syscall_ptr = Some(*ptr);

        Ok(())
    }
}
struct CallContractHandler;

impl<PCS> SyscallHandler<PCS> for CallContractHandler
where
    PCS: PerContractStorage + 'static,
{
    type Request = EmptyRequest;
    type Response = ReadOnlySegment;

    fn read_request(_vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<EmptyRequest> {
        *ptr = (*ptr + new_syscalls::CallContractRequest::cairo_size())?;
        Ok(EmptyRequest)
    }

    async fn execute(
        _request: EmptyRequest,
        vm: &mut VirtualMachine,
        exec_wrapper: &mut ExecutionHelperWrapper<PCS>,
        remaining_gas: &mut u64,
    ) -> SyscallResult<ReadOnlySegment> {
        let mut eh_ref = exec_wrapper.execution_helper.write().await;
        let result_iter = &mut eh_ref.result_iter;
        let result = result_iter
            .next()
            .ok_or(SyscallExecutionError::InternalError(Box::from("No result left in the result iterator.")))?;

        *remaining_gas -= result.gas_consumed;

        let retdata = result.retdata.0;

        if result.failed {
            return Err(SyscallExecutionError::SyscallError { error_data: retdata });
        }

        let start_ptr = vm.add_temporary_segment();
        vm.load_data(start_ptr, &retdata.iter().map(MaybeRelocatable::from).collect::<Vec<_>>())?;
        Ok(ReadOnlySegment { start_ptr, length: retdata.len() })
    }

    fn write_response(
        response: ReadOnlySegment,
        vm: &mut VirtualMachine,
        ptr: &mut Relocatable,
    ) -> WriteResponseResult {
        write_segment(vm, ptr, response)
    }
}

pub struct DeployHandler;

pub struct DeployResponse {
    pub contract_address: Felt252,
    pub constructor_retdata: ReadOnlySegment,
    pub need_retdata_hack: bool,
}

impl<PCS> SyscallHandler<PCS> for DeployHandler
where
    PCS: PerContractStorage + 'static,
{
    type Request = EmptyRequest;
    type Response = DeployResponse;

    fn read_request(_vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Self::Request> {
        *ptr = (*ptr + new_syscalls::DeployRequest::cairo_size())?;
        Ok(EmptyRequest)
    }

    async fn execute(
        _request: Self::Request,
        vm: &mut VirtualMachine,
        exec_wrapper: &mut ExecutionHelperWrapper<PCS>,
        remaining_gas: &mut u64,
    ) -> SyscallResult<Self::Response> {
        let mut execution_helper = exec_wrapper.execution_helper.write().await;

        let result = execution_helper
            .result_iter
            .next()
            .ok_or(SyscallExecutionError::InternalError(Box::from("No result left in the result iterator.")))?;

        *remaining_gas -= result.gas_consumed;

        let retdata = result.retdata.0;

        if result.failed {
            return Err(SyscallExecutionError::SyscallError { error_data: retdata });
        }

        let start_ptr = vm.add_temporary_segment();
        vm.load_data(start_ptr, &retdata.iter().map(MaybeRelocatable::from).collect::<Vec<_>>())?;

        let constructor_retdata = ReadOnlySegment { start_ptr, length: retdata.len() };

        let contract_address = execution_helper.deployed_contracts_iter.next().ok_or(HintError::SyscallError(
            "No more deployed contracts available to replay".to_string().into_boxed_str(),
        ))?;

        let need_retdata_hack = if let Some(os_input) = execution_helper.os_input.as_ref() {
            let class_hash = os_input
                .contract_address_to_class_hash
                .get(&contract_address)
                .expect("No class_hash for contract_address");
            let num_constructors =
                if let Some(compiled_class_hash) = os_input.class_hash_to_compiled_class_hash.get(class_hash) {
                    let casm = os_input.compiled_classes.get(compiled_class_hash).expect("No CASM");
                    let num_constructors = casm
                        .get_cairo_lang_contract_class()
                        .expect("couldn't get cairo lang class")
                        .entry_points_by_type
                        .constructor
                        .len();
                    num_constructors
                } else {
                    let deprecated_cc = os_input.deprecated_compiled_classes.get(class_hash).expect("no deprecated CC");
                    let num_constructors = deprecated_cc
                        .get_starknet_api_contract_class()
                        .expect("couldn't get starknet api class")
                        .entry_points_by_type
                        .get(&starknet_api::deprecated_contract_class::EntryPointType::Constructor)
                        .expect("should have constructor list")
                        .len();
                    num_constructors
                };

            // we need the hack if there are no constructor entry points
            num_constructors == 0
        } else {
            false
        };

        Ok(DeployResponse { contract_address, constructor_retdata, need_retdata_hack })
    }

    fn write_response(response: Self::Response, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_felt(vm, ptr, response.contract_address)?;

        // Bugfix:
        // When retdata size is 0, the OS will return retdata as a Int(0) instead of a relocatable
        // as a result of `cast(0, felt*)`. To work around this, we can write the same here so that
        // later the OS will assert this value is the same as retdata; that is, both need to be the
        // same value which is Int(0).
        //
        // retdata is cast here: https://github.com/starkware-libs/cairo-lang/blob/a86e92bfde9c171c0856d7b46580c66e004922f3/src/starkware/starknet/core/os/execution/execute_entry_point.cairo#L170
        if response.need_retdata_hack {
            log::warn!("Writing Felt::ZERO instead of pointer since retdata size is 0");
            write_felt(vm, ptr, Felt252::ZERO)?; // casted pointer
            write_felt(vm, ptr, Felt252::ZERO)?; // size
        } else {
            write_segment(vm, ptr, response.constructor_retdata)?;
        }
        Ok(())
    }
}

pub struct EmitEventHandler;

impl<PCS> SyscallHandler<PCS> for EmitEventHandler
where
    PCS: PerContractStorage + 'static,
{
    type Request = EmptyRequest;
    type Response = EmptyResponse;

    fn read_request(_vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Self::Request> {
        *ptr = (*ptr + new_syscalls::EmitEventRequest::cairo_size())?;
        Ok(EmptyRequest)
    }

    async fn execute(
        _request: Self::Request,
        _vm: &mut VirtualMachine,
        _exec_wrapper: &mut ExecutionHelperWrapper<PCS>,
        _remaining_gas: &mut u64,
    ) -> SyscallResult<Self::Response> {
        Ok(crate::execution::syscall_handler_utils::EmptyResponse {})
    }

    fn write_response(
        _response: Self::Response,
        _vm: &mut VirtualMachine,
        _ptr: &mut Relocatable,
    ) -> WriteResponseResult {
        Ok(())
    }
}

pub struct GetBlockHashHandler;

pub struct GetBlockHashRequest {
    pub block_number: Felt252,
}
pub struct GetBlockHashResponse {
    pub block_hash: Felt252,
}

impl<PCS> SyscallHandler<PCS> for GetBlockHashHandler
where
    PCS: PerContractStorage + 'static,
{
    type Request = GetBlockHashRequest;
    type Response = GetBlockHashResponse;

    fn read_request(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<GetBlockHashRequest> {
        let block_number = vm.get_integer(*ptr)?.into_owned();
        *ptr = (*ptr + new_syscalls::GetBlockHashRequest::cairo_size())?;
        Ok(GetBlockHashRequest { block_number })
    }

    async fn execute(
        request: GetBlockHashRequest,
        _vm: &mut VirtualMachine,
        exec_wrapper: &mut ExecutionHelperWrapper<PCS>,
        _remaining_gas: &mut u64,
    ) -> SyscallResult<Self::Response> {
        // # The syscall handler should not directly read from the storage during the execution of
        // # transactions because the order in which reads and writes occur is not strictly linear.
        // # However, for the "block hash contract," this rule does not apply. This contract is updated
        // # only at the start of each block before other transactions are executed.
        let block_hash = exec_wrapper
            .read_storage_for_address(Felt252::from(BLOCK_HASH_CONTRACT_ADDRESS), request.block_number)
            .await?;
        Ok(GetBlockHashResponse { block_hash })
    }

    fn write_response(response: Self::Response, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_felt(vm, ptr, response.block_hash)?;
        Ok(())
    }
}

pub struct GetExecutionInfoHandler;

#[derive(Debug, Eq, PartialEq)]
pub struct GetExecutionInfoResponse {
    pub execution_info_ptr: Relocatable,
}

impl<PCS> SyscallHandler<PCS> for GetExecutionInfoHandler
where
    PCS: PerContractStorage + 'static,
{
    type Request = EmptyRequest;
    type Response = GetExecutionInfoResponse;

    fn read_request(_vm: &VirtualMachine, _ptr: &mut Relocatable) -> SyscallResult<Self::Request> {
        Ok(EmptyRequest)
    }

    async fn execute(
        _request: Self::Request,
        _vm: &mut VirtualMachine,
        exec_wrapper: &mut ExecutionHelperWrapper<PCS>,
        _remaining_gas: &mut u64,
    ) -> SyscallResult<Self::Response> {
        let eh_ref = exec_wrapper.execution_helper.read().await;
        let execution_info_ptr = eh_ref.call_execution_info_ptr.unwrap();
        Ok(GetExecutionInfoResponse { execution_info_ptr })
    }

    fn write_response(response: Self::Response, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_maybe_relocatable(vm, ptr, response.execution_info_ptr)?;
        Ok(())
    }
}

struct LibraryCallHandler;

impl<PCS> SyscallHandler<PCS> for LibraryCallHandler
where
    PCS: PerContractStorage + 'static,
{
    type Request = EmptyRequest;
    type Response = ReadOnlySegment;

    fn read_request(_vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Self::Request> {
        *ptr = (*ptr + new_syscalls::LibraryCallRequest::cairo_size())?;
        Ok(EmptyRequest)
    }

    async fn execute(
        _request: Self::Request,
        vm: &mut VirtualMachine,
        exec_wrapper: &mut ExecutionHelperWrapper<PCS>,
        remaining_gas: &mut u64,
    ) -> SyscallResult<Self::Response> {
        let mut eh_ref = exec_wrapper.execution_helper.write().await;
        let result_iter = &mut eh_ref.result_iter;
        let result = result_iter
            .next()
            .ok_or(SyscallExecutionError::InternalError(Box::from("No result left in the result iterator.")))?;

        *remaining_gas -= result.gas_consumed;

        let retdata = result.retdata.0;

        if result.failed {
            return Err(SyscallExecutionError::SyscallError { error_data: retdata });
        }

        let start_ptr = vm.add_temporary_segment();
        vm.load_data(start_ptr, &retdata.iter().map(MaybeRelocatable::from).collect::<Vec<_>>())?;
        Ok(ReadOnlySegment { start_ptr, length: retdata.len() })
    }

    fn write_response(response: Self::Response, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_segment(vm, ptr, response)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ReplaceClassHandler;

impl<PCS> SyscallHandler<PCS> for ReplaceClassHandler
where
    PCS: PerContractStorage + 'static,
{
    type Request = EmptyRequest;
    type Response = EmptyResponse;
    fn read_request(_vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Self::Request> {
        *ptr = (*ptr + new_syscalls::ReplaceClassRequest::cairo_size())?;
        Ok(EmptyRequest)
    }

    async fn execute(
        _request: Self::Request,
        _vm: &mut VirtualMachine,
        _exec_wrapper: &mut ExecutionHelperWrapper<PCS>,
        _remaining_gas: &mut u64,
    ) -> SyscallResult<Self::Response> {
        Ok(crate::execution::syscall_handler_utils::EmptyResponse {})
    }

    fn write_response(
        _response: Self::Response,
        _vm: &mut VirtualMachine,
        _ptr: &mut Relocatable,
    ) -> WriteResponseResult {
        Ok(())
    }
}

struct SendMessageToL1Handler;

impl<PCS> SyscallHandler<PCS> for SendMessageToL1Handler
where
    PCS: PerContractStorage + 'static,
{
    type Request = EmptyRequest;
    type Response = EmptyResponse;

    fn read_request(_vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Self::Request> {
        *ptr = (*ptr + new_syscalls::SendMessageToL1Request::cairo_size())?;
        Ok(EmptyRequest)
    }

    async fn execute(
        _request: Self::Request,
        _vm: &mut VirtualMachine,
        _exec_wrapper: &mut ExecutionHelperWrapper<PCS>,
        _remaining_gas: &mut u64,
    ) -> SyscallResult<Self::Response> {
        Ok(crate::execution::syscall_handler_utils::EmptyResponse {})
    }

    fn write_response(
        _response: Self::Response,
        _vm: &mut VirtualMachine,
        _ptr: &mut Relocatable,
    ) -> WriteResponseResult {
        Ok(())
    }
}

pub struct StorageReadHandler;
pub struct StorageReadResponse {
    pub value: Felt252,
}

impl<PCS> SyscallHandler<PCS> for StorageReadHandler
where
    PCS: PerContractStorage + 'static,
{
    type Request = EmptyRequest;
    type Response = StorageReadResponse;

    fn read_request(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<EmptyRequest> {
        let address_domain = vm.get_integer(*ptr)?.into_owned();
        if address_domain != Felt252::ZERO {
            return Err(SyscallExecutionError::InvalidAddressDomain { address_domain });
        }
        *ptr = (*ptr + new_syscalls::StorageReadRequest::cairo_size())?;
        Ok(EmptyRequest)
    }

    async fn execute(
        _request: EmptyRequest,
        _vm: &mut VirtualMachine,
        exec_wrapper: &mut ExecutionHelperWrapper<PCS>,
        _remaining_gas: &mut u64,
    ) -> SyscallResult<StorageReadResponse> {
        let mut eh_ref = exec_wrapper.execution_helper.write().await;

        let value = eh_ref.execute_code_read_iter.next().ok_or(HintError::SyscallError(
            "n: No more storage reads available to replay".to_string().into_boxed_str(),
        ))?;
        Ok(StorageReadResponse { value })
    }
    fn write_response(
        response: StorageReadResponse,
        vm: &mut VirtualMachine,
        ptr: &mut Relocatable,
    ) -> WriteResponseResult {
        write_felt(vm, ptr, response.value)?;
        Ok(())
    }
}

pub struct StorageWriteHandler;
impl<PCS> SyscallHandler<PCS> for StorageWriteHandler
where
    PCS: PerContractStorage + 'static,
{
    type Request = EmptyRequest;
    type Response = EmptyResponse;

    fn read_request(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<EmptyRequest> {
        let address_domain = vm.get_integer(*ptr)?.into_owned();
        if address_domain != Felt252::ZERO {
            return Err(SyscallExecutionError::InvalidAddressDomain { address_domain });
        }
        *ptr = (*ptr + new_syscalls::StorageWriteRequest::cairo_size())?;
        Ok(EmptyRequest)
    }

    async fn execute(
        _request: EmptyRequest,
        _vm: &mut VirtualMachine,
        _exec_wrapper: &mut ExecutionHelperWrapper<PCS>,
        _remaining_gas: &mut u64,
    ) -> SyscallResult<EmptyResponse> {
        Ok(EmptyResponse {})
    }
    fn write_response(
        _response: Self::Response,
        _vm: &mut VirtualMachine,
        _ptr: &mut Relocatable,
    ) -> WriteResponseResult {
        Ok(())
    }
}

pub struct KeccakHandler;
pub struct KeccakRequest {
    pub input_start: Relocatable,
    pub input_end: Relocatable,
}
pub struct KeccakResponse {
    pub result_low: Felt252,
    pub result_high: Felt252,
}

impl<PCS> SyscallHandler<PCS> for KeccakHandler
where
    PCS: PerContractStorage + 'static,
{
    type Request = KeccakRequest;
    type Response = KeccakResponse;

    fn read_request(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Self::Request> {
        let input_start = vm.get_relocatable(*ptr)?;
        *ptr = (*ptr + 1)?;
        let input_end = vm.get_relocatable(*ptr)?;
        *ptr = (*ptr + 1)?;
        Ok(KeccakRequest { input_start, input_end })
    }

    async fn execute(
        request: Self::Request,
        vm: &mut VirtualMachine,
        _exec_wrapper: &mut ExecutionHelperWrapper<PCS>,
        remaining_gas: &mut u64,
    ) -> SyscallResult<Self::Response> {
        let input_len = (request.input_end - request.input_start)?;
        // The to_usize unwrap will not fail as the constant value is 17
        let (n_rounds, remainder) = num_integer::div_rem(input_len, KECCAK_FULL_RATE_IN_U64S.to_usize().unwrap());

        if remainder != 0 {
            return Err(SyscallExecutionError::SyscallError {
                error_data: vec![Felt252::from_hex_unchecked(INVALID_INPUT_LENGTH_ERROR)],
            });
        }
        let n_rounds = u64::try_from(n_rounds)?;
        let gas_cost = n_rounds * KECCAK_ROUND_COST_GAS_COST;

        if gas_cost > *remaining_gas {
            return Err(SyscallExecutionError::OutOfGas { remaining_gas: (*remaining_gas) });
        }
        *remaining_gas -= gas_cost;

        let input_felt_array = vm.get_integer_range(request.input_start, input_len)?;

        // Keccak state function consist of 25 words 64 bits each for SHA-3 (200 bytes/1600 bits)
        // Sponge Function [https://en.wikipedia.org/wiki/Sponge_function]
        // SHA3 [https://en.wikipedia.org/wiki/SHA-3]
        let mut state = [0u64; 25];
        for chunk in input_felt_array.chunks(KECCAK_FULL_RATE_IN_U64S.to_usize().unwrap()) {
            for (i, val) in chunk.iter().enumerate() {
                state[i] ^= val.to_u64().ok_or_else(|| SyscallExecutionError::InvalidSyscallInput {
                    input: *val.clone(),
                    info: String::from("Invalid input for the keccak syscall."),
                })?;
            }
            keccak::f1600(&mut state)
        }
        // We keep 256 bits (128 high and 128 low)
        let result_low = (BigUint::from(state[1]) << 64u32) + BigUint::from(state[0]);
        let result_high = (BigUint::from(state[3]) << 64u32) + BigUint::from(state[2]);

        Ok(KeccakResponse { result_low: (Felt252::from(result_low)), result_high: (Felt252::from(result_high)) })
    }

    fn write_response(response: Self::Response, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_felt(vm, ptr, response.result_low)?;
        write_felt(vm, ptr, response.result_high)?;
        Ok(())
    }
}

pub struct Sha256ProcessBlockHandler;

#[derive(Debug, Eq, PartialEq)]
pub struct Sha256ProcessBlockRequest {
    pub state_ptr: Relocatable,
    pub input_start: Relocatable,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Sha256ProcessBlockResponse {
    pub state_ptr: Relocatable,
}

impl<PCS> SyscallHandler<PCS> for Sha256ProcessBlockHandler
where
    PCS: PerContractStorage + 'static,
{
    type Request = Sha256ProcessBlockRequest;
    type Response = Sha256ProcessBlockResponse;

    fn read_request(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Self::Request> {
        let state_ptr = vm.get_relocatable(*ptr)?;
        *ptr = (*ptr + 1)?;
        let input_start = vm.get_relocatable(*ptr)?;
        *ptr = (*ptr + 1)?;
        Ok(Sha256ProcessBlockRequest { state_ptr, input_start })
    }

    fn write_response(response: Self::Response, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_maybe_relocatable(vm, ptr, response.state_ptr)?;
        Ok(())
    }

    async fn execute(
        request: Self::Request,
        vm: &mut VirtualMachine,
        exec_wrapper: &mut ExecutionHelperWrapper<PCS>,
        _remaining_gas: &mut u64,
    ) -> SyscallResult<Self::Response> {
        let mut eh_ref = exec_wrapper.execution_helper.write().await;
        const SHA256_BLOCK_SIZE: usize = 16;

        let data = vm.get_integer_range(request.input_start, SHA256_BLOCK_SIZE)?;
        const SHA256_STATE_SIZE: usize = 8;
        let prev_state = vm.get_integer_range(request.state_ptr, SHA256_STATE_SIZE)?;

        let data_as_bytes = sha2::digest::generic_array::GenericArray::from_exact_iter(data.iter().flat_map(|felt| {
            felt.to_bigint().to_u32().expect("libfunc should ensure the input is an [u32; 16].").to_be_bytes()
        }))
        .expect("u32.to_be_bytes() returns 4 bytes, and data.len() == 16. So data contains 64 bytes.");

        let mut state_as_words: [u32; SHA256_STATE_SIZE] = core::array::from_fn(|i| {
            prev_state[i]
                .to_bigint()
                .to_u32()
                .expect("libfunc only accepts SHA256StateHandle which can only be created from an Array<u32>.")
        });

        sha2::compress256(&mut state_as_words, &[data_as_bytes]);

        let segment = eh_ref.sha256_segment.unwrap_or(vm.add_memory_segment());

        let response = (segment + 24)?; // 'out_state' is 24 bytes into 'struct Sha256ProcessBlock'
        let data: Vec<MaybeRelocatable> =
            state_as_words.iter().map(|&arg| MaybeRelocatable::from(Felt252::from(arg))).collect();

        // side effect: this advances sha256_segment by 32 bytes (the size of struct Sha256ProcessBlock)
        eh_ref.sha256_segment = Some(vm.load_data(response, &data)?);

        Ok(Sha256ProcessBlockResponse { state_ptr: response })
    }
}
