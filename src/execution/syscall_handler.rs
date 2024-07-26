use std::rc::Rc;

use blockifier::execution::execution_utils::ReadOnlySegments;
use blockifier::execution::syscalls::hint_processor::INVALID_ARGUMENT;
use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::errors::memory_errors::MemoryError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use secp::{SecpAddHandler, SecpGetPointFromXHandler, SecpGetXyHandler, SecpMulHandler, SecpNewHandler};
use tokio::sync::RwLock;

use super::helper::ExecutionHelperWrapper;
use crate::cairo_types::new_syscalls::{self, EcPointCoordinates};
use crate::execution::constants::{
    BLOCK_HASH_CONTRACT_ADDRESS, CALL_CONTRACT_GAS_COST, DEPLOY_GAS_COST, EMIT_EVENT_GAS_COST, GET_BLOCK_HASH_GAS_COST,
    GET_EXECUTION_INFO_GAS_COST, LIBRARY_CALL_GAS_COST, REPLACE_CLASS_GAS_COST, SECP256K1_ADD_GAS_COST,
    SECP256K1_GET_POINT_FROM_X_GAS_COST, SECP256K1_GET_XY_GAS_COST, SECP256K1_MUL_GAS_COST, SECP256K1_NEW_GAS_COST,
    SECP256R1_ADD_GAS_COST, SECP256R1_GET_POINT_FROM_X_GAS_COST, SECP256R1_GET_XY_GAS_COST, SECP256R1_MUL_GAS_COST,
    SECP256R1_NEW_GAS_COST, SEND_MESSAGE_TO_L1_GAS_COST, STORAGE_READ_GAS_COST, STORAGE_WRITE_GAS_COST,
};
use crate::execution::syscall_handler_utils::{
    felt_from_ptr, run_handler, write_felt, write_maybe_relocatable, write_segment, EmptyRequest, EmptyResponse,
    ReadOnlySegment, SyscallExecutionError, SyscallHandler, SyscallResult, SyscallSelector, WriteResponseResult,
};
use crate::utils::felt_api2vm;

/// DeprecatedSyscallHandler implementation for execution of system calls in the StarkNet OS
#[derive(Debug)]
pub struct OsSyscallHandler {
    pub exec_wrapper: ExecutionHelperWrapper,
    pub syscall_ptr: Option<Relocatable>,
    pub segments: ReadOnlySegments,
}

/// OsSyscallHandler is wrapped in Rc<RefCell<_>> in order
/// to clone the reference when entering and exiting vm scopes
#[derive(Clone, Debug)]
pub struct OsSyscallHandlerWrapper {
    pub syscall_handler: Rc<RwLock<OsSyscallHandler>>,
}

impl OsSyscallHandlerWrapper {
    pub fn new(exec_wrapper: ExecutionHelperWrapper) -> Self {
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
                run_handler::<CallContractHandler>(ptr, vm, ehw, CALL_CONTRACT_GAS_COST).await
            }
            SyscallSelector::Deploy => run_handler::<DeployHandler>(ptr, vm, ehw, DEPLOY_GAS_COST).await,
            SyscallSelector::EmitEvent => run_handler::<EmitEventHandler>(ptr, vm, ehw, EMIT_EVENT_GAS_COST).await,
            SyscallSelector::GetBlockHash => {
                run_handler::<GetBlockHashHandler>(ptr, vm, ehw, GET_BLOCK_HASH_GAS_COST).await
            }
            SyscallSelector::LibraryCall => {
                run_handler::<LibraryCallHandler>(ptr, vm, ehw, LIBRARY_CALL_GAS_COST).await
            }
            SyscallSelector::GetExecutionInfo => {
                run_handler::<GetExecutionInfoHandler>(ptr, vm, ehw, GET_EXECUTION_INFO_GAS_COST).await
            }
            SyscallSelector::StorageRead => {
                run_handler::<StorageReadHandler>(ptr, vm, ehw, STORAGE_READ_GAS_COST).await
            }
            SyscallSelector::StorageWrite => {
                run_handler::<StorageWriteHandler>(ptr, vm, ehw, STORAGE_WRITE_GAS_COST).await
            }
            SyscallSelector::SendMessageToL1 => {
                run_handler::<SendMessageToL1Handler>(ptr, vm, ehw, SEND_MESSAGE_TO_L1_GAS_COST).await
            }
            SyscallSelector::ReplaceClass => {
                run_handler::<ReplaceClassHandler>(ptr, vm, ehw, REPLACE_CLASS_GAS_COST).await
            }
            SyscallSelector::LibraryCallL1Handler => {
                run_handler::<LibraryCallHandler>(ptr, vm, ehw, LIBRARY_CALL_GAS_COST).await
            }
            SyscallSelector::Secp256k1New => {
                run_handler::<SecpNewHandler<ark_secp256k1::Config>>(ptr, vm, ehw, SECP256K1_NEW_GAS_COST).await
            }
            SyscallSelector::Secp256k1GetXy => {
                run_handler::<SecpGetXyHandler<ark_secp256k1::Config>>(ptr, vm, ehw, SECP256K1_GET_XY_GAS_COST).await
            }
            SyscallSelector::Secp256k1GetPointFromX => {
                run_handler::<SecpGetPointFromXHandler<ark_secp256k1::Config>>(
                    ptr,
                    vm,
                    ehw,
                    SECP256K1_GET_POINT_FROM_X_GAS_COST,
                )
                .await
            }
            SyscallSelector::Secp256k1Mul => {
                run_handler::<SecpMulHandler<ark_secp256k1::Config>>(ptr, vm, ehw, SECP256K1_MUL_GAS_COST).await
            }
            SyscallSelector::Secp256k1Add => {
                run_handler::<SecpAddHandler<ark_secp256k1::Config>>(ptr, vm, ehw, SECP256K1_ADD_GAS_COST).await
            }

            SyscallSelector::Secp256r1New => {
                run_handler::<SecpNewHandler<ark_secp256r1::Config>>(ptr, vm, ehw, SECP256R1_NEW_GAS_COST).await
            }
            SyscallSelector::Secp256r1GetXy => {
                run_handler::<SecpGetXyHandler<ark_secp256r1::Config>>(ptr, vm, ehw, SECP256R1_GET_XY_GAS_COST).await
            }
            SyscallSelector::Secp256r1GetPointFromX => {
                run_handler::<SecpGetPointFromXHandler<ark_secp256r1::Config>>(
                    ptr,
                    vm,
                    ehw,
                    SECP256R1_GET_POINT_FROM_X_GAS_COST,
                )
                .await
            }
            SyscallSelector::Secp256r1Mul => {
                run_handler::<SecpMulHandler<ark_secp256r1::Config>>(ptr, vm, ehw, SECP256R1_MUL_GAS_COST).await
            }
            SyscallSelector::Secp256r1Add => {
                run_handler::<SecpAddHandler<ark_secp256r1::Config>>(ptr, vm, ehw, SECP256R1_ADD_GAS_COST).await
            }

            _ => Err(HintError::CustomHint(format!("Unknown syscall selector: {:?}", selector).into())),
        }?;

        syscall_handler.syscall_ptr = Some(*ptr);

        Ok(())
    }
}
struct CallContractHandler;

impl SyscallHandler for CallContractHandler {
    type Request = EmptyRequest;
    type Response = ReadOnlySegment;

    fn read_request(_vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<EmptyRequest> {
        *ptr = (*ptr + new_syscalls::CallContractRequest::cairo_size())?;
        Ok(EmptyRequest)
    }

    async fn execute(
        _request: EmptyRequest,
        vm: &mut VirtualMachine,
        exec_wrapper: &mut ExecutionHelperWrapper,
        remaining_gas: &mut u64,
    ) -> SyscallResult<ReadOnlySegment> {
        let mut eh_ref = exec_wrapper.execution_helper.write().await;
        let result_iter = &mut eh_ref.result_iter;
        let result = result_iter
            .next()
            .ok_or(SyscallExecutionError::InternalError(Box::from("No result left in the result iterator.")))?;

        *remaining_gas -= result.gas_consumed;

        let retdata = result.retdata.0.iter().map(|sf| felt_api2vm(*sf)).collect();

        if result.failed {
            return Err(SyscallExecutionError::SyscallError { error_data: retdata });
        }

        let start_ptr = vm.add_temporary_segment();
        vm.load_data(start_ptr, &retdata.iter().map(MaybeRelocatable::from).collect())?;
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
}

impl SyscallHandler for DeployHandler {
    type Request = EmptyRequest;
    type Response = DeployResponse;

    fn read_request(_vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Self::Request> {
        *ptr = (*ptr + new_syscalls::DeployRequest::cairo_size())?;
        Ok(EmptyRequest)
    }

    async fn execute(
        _request: Self::Request,
        vm: &mut VirtualMachine,
        exec_wrapper: &mut ExecutionHelperWrapper,
        remaining_gas: &mut u64,
    ) -> SyscallResult<Self::Response> {
        let mut execution_helper = exec_wrapper.execution_helper.write().await;

        let result = execution_helper
            .result_iter
            .next()
            .ok_or(SyscallExecutionError::InternalError(Box::from("No result left in the result iterator.")))?;

        *remaining_gas -= result.gas_consumed;

        let retdata = result.retdata.0.iter().map(|sf| felt_api2vm(*sf)).collect();

        if result.failed {
            return Err(SyscallExecutionError::SyscallError { error_data: retdata });
        }

        let start_ptr = vm.add_temporary_segment();
        vm.load_data(start_ptr, &retdata.iter().map(MaybeRelocatable::from).collect())?;

        let constructor_retdata = ReadOnlySegment { start_ptr, length: retdata.len() };

        let contract_address = execution_helper.deployed_contracts_iter.next().ok_or(HintError::SyscallError(
            "No more deployed contracts available to replay".to_string().into_boxed_str(),
        ))?;

        Ok(DeployResponse { contract_address, constructor_retdata })
    }

    fn write_response(response: Self::Response, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_felt(vm, ptr, response.contract_address)?;
        write_segment(vm, ptr, response.constructor_retdata)?;
        Ok(())
    }
}

pub struct EmitEventHandler;

impl SyscallHandler for EmitEventHandler {
    type Request = EmptyRequest;
    type Response = EmptyResponse;

    fn read_request(_vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Self::Request> {
        *ptr = (*ptr + new_syscalls::EmitEventRequest::cairo_size())?;
        Ok(EmptyRequest)
    }

    async fn execute(
        _request: Self::Request,
        _vm: &mut VirtualMachine,
        _exec_wrapper: &mut ExecutionHelperWrapper,
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

impl SyscallHandler for GetBlockHashHandler {
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
        exec_wrapper: &mut ExecutionHelperWrapper,
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

impl SyscallHandler for GetExecutionInfoHandler {
    type Request = EmptyRequest;
    type Response = GetExecutionInfoResponse;

    fn read_request(_vm: &VirtualMachine, _ptr: &mut Relocatable) -> SyscallResult<Self::Request> {
        Ok(EmptyRequest)
    }

    async fn execute(
        _request: Self::Request,
        _vm: &mut VirtualMachine,
        exec_wrapper: &mut ExecutionHelperWrapper,
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

impl SyscallHandler for LibraryCallHandler {
    type Request = EmptyRequest;
    type Response = ReadOnlySegment;

    fn read_request(_vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Self::Request> {
        *ptr = (*ptr + new_syscalls::LibraryCallRequest::cairo_size())?;
        Ok(EmptyRequest)
    }

    async fn execute(
        _request: Self::Request,
        vm: &mut VirtualMachine,
        exec_wrapper: &mut ExecutionHelperWrapper,
        remaining_gas: &mut u64,
    ) -> SyscallResult<Self::Response> {
        let mut eh_ref = exec_wrapper.execution_helper.write().await;
        let result_iter = &mut eh_ref.result_iter;
        let result = result_iter
            .next()
            .ok_or(SyscallExecutionError::InternalError(Box::from("No result left in the result iterator.")))?;

        *remaining_gas -= result.gas_consumed;

        let retdata = result.retdata.0.iter().map(|sf| felt_api2vm(*sf)).collect();

        if result.failed {
            return Err(SyscallExecutionError::SyscallError { error_data: retdata });
        }

        let start_ptr = vm.add_temporary_segment();
        vm.load_data(start_ptr, &retdata.iter().map(MaybeRelocatable::from).collect())?;
        Ok(ReadOnlySegment { start_ptr, length: retdata.len() })
    }

    fn write_response(response: Self::Response, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_segment(vm, ptr, response)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ReplaceClassHandler;

impl SyscallHandler for ReplaceClassHandler {
    type Request = EmptyRequest;
    type Response = EmptyResponse;
    fn read_request(_vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Self::Request> {
        *ptr = (*ptr + new_syscalls::ReplaceClassRequest::cairo_size())?;
        Ok(EmptyRequest)
    }

    async fn execute(
        _request: Self::Request,
        _vm: &mut VirtualMachine,
        _exec_wrapper: &mut ExecutionHelperWrapper,
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

impl SyscallHandler for SendMessageToL1Handler {
    type Request = EmptyRequest;
    type Response = EmptyResponse;

    fn read_request(_vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Self::Request> {
        *ptr = (*ptr + new_syscalls::SendMessageToL1Request::cairo_size())?;
        Ok(EmptyRequest)
    }

    async fn execute(
        _request: Self::Request,
        _vm: &mut VirtualMachine,
        _exec_wrapper: &mut ExecutionHelperWrapper,
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

impl SyscallHandler for StorageReadHandler {
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
        exec_wrapper: &mut ExecutionHelperWrapper,
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
impl SyscallHandler for StorageWriteHandler {
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
        _exec_wrapper: &mut ExecutionHelperWrapper,
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

pub mod secp {

    use std::any::TypeId;
    use std::marker::PhantomData;
    use std::vec::Vec;

    use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
    use ark_ff::{BigInteger, PrimeField};
    use num_bigint::BigUint;
    use num_traits::{ToPrimitive, Zero};

    use super::*;
    use crate::execution::helper::ExecutionHelper;

    #[cfg(test)]
    fn create_point<Curve: SWCurveConfig>(x: BigUint, y: BigUint) -> Affine<Curve>
    where
        Curve::BaseField: PrimeField,
    {
        Affine::<Curve>::new_unchecked(Curve::BaseField::from(x), Curve::BaseField::from(y))
    }

    fn with_hint_processor<C: 'static, T, F>(
        eh_ref: &mut ExecutionHelper,
        callback: F,
    ) -> Result<T, SyscallExecutionError>
    where
        F: FnOnce(&mut SecpHintProcessor) -> Result<T, SyscallExecutionError>,
    {
        let processor = eh_ref
            .secp_hint_processors
            .get_mut(&TypeId::of::<C>())
            .ok_or(SyscallExecutionError::InternalError("Failed to find Curve type".into()))?;

        callback(processor)
    }

    #[derive(Debug, Default, Eq, PartialEq)]
    pub struct SecpHintProcessorInner<Curve: SWCurveConfig> {
        points: Vec<Affine<Curve>>,
    }

    pub enum SecpHintProcessor {
        Secp256k1(SecpHintProcessorInner<ark_secp256k1::Config>),
        Secp256r1(SecpHintProcessorInner<ark_secp256r1::Config>),
    }

    impl SecpHintProcessor {
        pub fn new_secp256k1() -> Self {
            SecpHintProcessor::Secp256k1(SecpHintProcessorInner::<ark_secp256k1::Config>::new())
        }

        pub fn new_secp256r1() -> Self {
            SecpHintProcessor::Secp256r1(SecpHintProcessorInner::<ark_secp256r1::Config>::new())
        }

        pub fn secp_add(&mut self, request: SecpAddRequest) -> SyscallResult<SecpOpRespone> {
            match self {
                SecpHintProcessor::Secp256k1(inner) => inner.secp_add(request),
                SecpHintProcessor::Secp256r1(inner) => inner.secp_add(request),
            }
        }

        pub fn secp_mul(&mut self, request: SecpMulRequest) -> SyscallResult<SecpOpRespone> {
            match self {
                SecpHintProcessor::Secp256k1(inner) => inner.secp_mul(request),
                SecpHintProcessor::Secp256r1(inner) => inner.secp_mul(request),
            }
        }

        pub fn secp_get_point_from_x(
            &mut self,
            request: SecpGetPointFromXRequest,
        ) -> SyscallResult<SecpGetPointFromXResponse> {
            match self {
                SecpHintProcessor::Secp256k1(inner) => inner.secp_get_point_from_x(request),
                SecpHintProcessor::Secp256r1(inner) => inner.secp_get_point_from_x(request),
            }
        }

        pub fn secp_get_xy(&mut self, request: SecpGetXyRequest) -> SyscallResult<EcPointCoordinates> {
            match self {
                SecpHintProcessor::Secp256k1(inner) => inner.secp_get_xy(request),
                SecpHintProcessor::Secp256r1(inner) => inner.secp_get_xy(request),
            }
        }

        pub fn secp_new(&mut self, request: EcPointCoordinates) -> SyscallResult<SecpNewResponse> {
            match self {
                SecpHintProcessor::Secp256k1(inner) => inner.secp_new(request),
                SecpHintProcessor::Secp256r1(inner) => inner.secp_new(request),
            }
        }
        #[cfg(test)]
        fn allocate_point(&mut self, ec_point: (BigUint, BigUint)) -> usize {
            match self {
                SecpHintProcessor::Secp256k1(inner) => inner.allocate_point(create_point(ec_point.0, ec_point.1)),
                SecpHintProcessor::Secp256r1(inner) => inner.allocate_point(create_point(ec_point.0, ec_point.1)),
            }
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    pub struct SecpNewResponse {
        pub optional_ec_point: Option<usize>,
    }

    #[derive(Debug, Eq, PartialEq)]
    pub struct SecpGetPointFromXResponse {
        pub optional_ec_point_id: Option<Felt252>,
    }

    #[derive(Debug, Eq, PartialEq)]
    pub struct SecpGetPointFromXRequest {
        pub x: BigUint,
        pub y_parity: bool,
    }

    #[derive(Debug, Eq, PartialEq)]
    pub struct SecpAddRequest {
        pub p0: Felt252,
        pub p1: Felt252,
    }

    #[derive(Debug, Eq, PartialEq)]
    pub struct SecpOpRespone {
        pub ec_point: Felt252,
    }

    #[derive(Debug, Eq, PartialEq)]
    pub struct SecpMulRequest {
        pub ec_point_id: Felt252,
        pub scalar: BigUint,
    }

    #[derive(Debug, Eq, PartialEq)]
    pub struct SecpGetXyRequest {
        pub ec_point_id: Felt252,
    }

    impl<Curve: SWCurveConfig> SecpHintProcessorInner<Curve>
    where
        Curve::BaseField: PrimeField,
    {
        pub fn new() -> Self {
            Self { points: Vec::new() }
        }

        pub fn secp_add(&mut self, request: SecpAddRequest) -> SyscallResult<SecpOpRespone> {
            let lhs = self.get_point_by_id(request.p0)?;
            let rhs = self.get_point_by_id(request.p1)?;
            let result = *lhs + *rhs;
            let ec_point = self.allocate_point(result.into());
            Ok(SecpOpRespone { ec_point: ec_point.into() })
        }

        pub fn secp_mul(&mut self, request: SecpMulRequest) -> SyscallResult<SecpOpRespone> {
            let ep_point = self.get_point_by_id(request.ec_point_id)?;
            let result = *ep_point * Curve::ScalarField::from(request.scalar);
            let ec_point_id = self.allocate_point(result.into());
            Ok(SecpOpRespone { ec_point: ec_point_id.into() })
        }

        pub fn secp_get_point_from_x(
            &mut self,
            request: SecpGetPointFromXRequest,
        ) -> SyscallResult<SecpGetPointFromXResponse> {
            let modulos = Curve::BaseField::MODULUS.into();

            if request.x >= modulos {
                return Err(SyscallExecutionError::SyscallError {
                    error_data: vec![Felt252::from_hex(INVALID_ARGUMENT).unwrap()],
                });
            }

            let x = request.x.into();
            let maybe_ec_point = Affine::<Curve>::get_ys_from_x_unchecked(x)
                .map(
                    |(smaller, greater)| {
                        if smaller.into_bigint().is_odd() == request.y_parity { smaller } else { greater }
                    },
                )
                .map(|y| Affine::<Curve>::new_unchecked(x, y))
                .filter(|p| p.is_in_correct_subgroup_assuming_on_curve());

            Ok(SecpGetPointFromXResponse {
                optional_ec_point_id: maybe_ec_point.map(|ec_point| self.allocate_point(ec_point).into()),
            })
        }

        pub fn secp_get_xy(&mut self, request: SecpGetXyRequest) -> SyscallResult<EcPointCoordinates> {
            let ec_point = self.get_point_by_id(request.ec_point_id)?;
            Ok(EcPointCoordinates { x: ec_point.x.into(), y: ec_point.y.into() })
        }

        pub fn secp_new(&mut self, request: EcPointCoordinates) -> SyscallResult<SecpNewResponse> {
            let modulos = Curve::BaseField::MODULUS.into();
            let (x, y): (BigUint, BigUint) = (request.x, request.y);
            if x >= modulos || y >= modulos {
                return Err(SyscallExecutionError::SyscallError {
                    error_data: vec![Felt252::from_hex(INVALID_ARGUMENT).unwrap()],
                });
            }
            let ec_point = if x.is_zero() && y.is_zero() {
                Affine::<Curve>::identity()
            } else {
                Affine::<Curve>::new_unchecked(x.into(), y.into())
            };
            let optional_ec_point = if ec_point.is_on_curve() && ec_point.is_in_correct_subgroup_assuming_on_curve() {
                Some(self.allocate_point(ec_point))
            } else {
                None
            };
            Ok(SecpNewResponse { optional_ec_point })
        }

        fn allocate_point(&mut self, ec_point: Affine<Curve>) -> usize {
            let id = self.points.len();
            self.points.push(ec_point);
            id
        }

        fn get_point_by_id(&self, ec_point_id: Felt252) -> SyscallResult<&Affine<Curve>> {
            ec_point_id.to_usize().and_then(|id| self.points.get(id)).ok_or_else(|| {
                SyscallExecutionError::InvalidSyscallInput {
                    input: ec_point_id,
                    info: "Invalid Secp point ID".to_string(),
                }
            })
        }
    }

    fn pack(low: Felt252, high: Felt252) -> BigUint {
        (high.to_biguint() << 128) + low.to_biguint()
    }

    pub struct SecpNewHandler<C> {
        _c: PhantomData<C>,
    }
    impl<C: SWCurveConfig> SyscallHandler for SecpNewHandler<C> {
        type Request = EcPointCoordinates;
        type Response = SecpNewResponse;

        fn read_request(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Self::Request> {
            let x = {
                let low = felt_from_ptr(vm, ptr)?;
                let high = felt_from_ptr(vm, ptr)?;
                (low, high)
            };
            let y = {
                let low = felt_from_ptr(vm, ptr)?;
                let high = felt_from_ptr(vm, ptr)?;
                (low, high)
            };
            Ok(EcPointCoordinates { x: pack(x.0, x.1), y: pack(y.0, y.1) })
        }
        async fn execute(
            request: EcPointCoordinates,
            _vm: &mut VirtualMachine,
            exec_wrapper: &mut ExecutionHelperWrapper,
            _remaining_gas: &mut u64,
        ) -> SyscallResult<Self::Response> {
            let mut eh_ref = exec_wrapper.execution_helper.write().await;
            let res = with_hint_processor::<C, _, _>(&mut eh_ref, |p| p.secp_new(request))?;
            Ok(res)
        }
        fn write_response(
            response: Self::Response,
            vm: &mut VirtualMachine,
            ptr: &mut Relocatable,
        ) -> WriteResponseResult {
            match response.optional_ec_point {
                Some(id) => {
                    write_maybe_relocatable(vm, ptr, 0)?;
                    write_maybe_relocatable(vm, ptr, id)?;
                }
                None => {
                    write_maybe_relocatable(vm, ptr, 1)?;
                    write_maybe_relocatable(vm, ptr, 0)?;
                }
            };
            Ok(())
        }
    }
    pub struct SecpGetPointFromXHandler<C> {
        _c: PhantomData<C>,
    }
    impl<C: SWCurveConfig> SyscallHandler for SecpGetPointFromXHandler<C> {
        type Request = SecpGetPointFromXRequest;

        type Response = SecpGetPointFromXResponse;

        fn read_request(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Self::Request> {
            let x = {
                let low = felt_from_ptr(vm, ptr)?;
                let high = felt_from_ptr(vm, ptr)?;
                (low, high)
            };
            pub fn felt_to_bool(felt: Felt252, error_info: &str) -> SyscallResult<bool> {
                if felt == Felt252::from(0_u8) {
                    Ok(false)
                } else if felt == Felt252::from(1_u8) {
                    Ok(true)
                } else {
                    Err(SyscallExecutionError::InvalidSyscallInput { input: felt, info: error_info.into() })
                }
            }

            let y_parity = felt_to_bool(felt_from_ptr(vm, ptr)?, "Invalid y parity")?;
            Ok(SecpGetPointFromXRequest { x: pack(x.0, x.1), y_parity })
        }

        async fn execute(
            request: Self::Request,
            _vm: &mut VirtualMachine,
            exec_wrapper: &mut ExecutionHelperWrapper,
            _remaining_gas: &mut u64,
        ) -> SyscallResult<Self::Response> {
            let mut eh_ref = exec_wrapper.execution_helper.write().await;
            let res = with_hint_processor::<C, _, _>(&mut eh_ref, |p| p.secp_get_point_from_x(request))?;
            Ok(res)
        }

        fn write_response(
            response: Self::Response,
            vm: &mut VirtualMachine,
            ptr: &mut Relocatable,
        ) -> WriteResponseResult {
            match response.optional_ec_point_id {
                Some(id) => {
                    write_maybe_relocatable(vm, ptr, 0)?;
                    write_maybe_relocatable(vm, ptr, id)?;
                }
                None => {
                    write_maybe_relocatable(vm, ptr, 1)?;
                    write_maybe_relocatable(vm, ptr, 0)?;
                }
            };
            Ok(())
        }
    }

    pub struct SecpMulHandler<C> {
        _c: PhantomData<C>,
    }

    impl<C: SWCurveConfig> SyscallHandler for SecpMulHandler<C> {
        type Request = SecpMulRequest;

        type Response = SecpOpRespone;

        fn read_request(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Self::Request> {
            let ec_point_id = felt_from_ptr(vm, ptr)?;
            let scalar = {
                let low = felt_from_ptr(vm, ptr)?;
                let high = felt_from_ptr(vm, ptr)?;
                (low, high)
            };
            Ok(SecpMulRequest { ec_point_id, scalar: pack(scalar.0, scalar.1) })
        }

        async fn execute(
            request: Self::Request,
            _vm: &mut VirtualMachine,
            exec_wrapper: &mut ExecutionHelperWrapper,
            _remaining_gas: &mut u64,
        ) -> SyscallResult<Self::Response> {
            let mut eh_ref = exec_wrapper.execution_helper.write().await;
            let res = with_hint_processor::<C, _, _>(&mut eh_ref, |p| p.secp_mul(request))?;
            Ok(res)
        }

        fn write_response(
            response: Self::Response,
            vm: &mut VirtualMachine,
            ptr: &mut Relocatable,
        ) -> WriteResponseResult {
            write_maybe_relocatable(vm, ptr, response.ec_point)?;
            Ok(())
        }
    }

    pub struct SecpAddHandler<C> {
        _c: PhantomData<C>,
    }

    impl<C: SWCurveConfig> SyscallHandler for SecpAddHandler<C> {
        type Request = SecpAddRequest;

        type Response = SecpOpRespone;

        fn read_request(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Self::Request> {
            Ok(SecpAddRequest { p0: felt_from_ptr(vm, ptr)?, p1: felt_from_ptr(vm, ptr)? })
        }

        async fn execute(
            request: Self::Request,
            _vm: &mut VirtualMachine,
            exec_wrapper: &mut ExecutionHelperWrapper,
            _remaining_gas: &mut u64,
        ) -> SyscallResult<Self::Response> {
            let mut eh_ref = exec_wrapper.execution_helper.write().await;
            let res = with_hint_processor::<C, _, _>(&mut eh_ref, |p| p.secp_add(request))?;

            Ok(res)
        }

        fn write_response(
            response: Self::Response,
            vm: &mut VirtualMachine,
            ptr: &mut Relocatable,
        ) -> WriteResponseResult {
            write_maybe_relocatable(vm, ptr, response.ec_point)?;
            Ok(())
        }
    }

    pub struct SecpGetXyHandler<C> {
        _c: PhantomData<C>,
    }

    impl<C: SWCurveConfig> SyscallHandler for SecpGetXyHandler<C> {
        type Request = SecpGetXyRequest;
        type Response = EcPointCoordinates;

        fn read_request(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Self::Request> {
            Ok(SecpGetXyRequest { ec_point_id: felt_from_ptr(vm, ptr)? })
        }
        async fn execute(
            request: Self::Request,
            _vm: &mut VirtualMachine,
            exec_wrapper: &mut ExecutionHelperWrapper,
            _remaining_gas: &mut u64,
        ) -> SyscallResult<Self::Response> {
            let mut eh_ref = exec_wrapper.execution_helper.write().await;
            let res = with_hint_processor::<C, _, _>(&mut eh_ref, |p| p.secp_get_xy(request))?;
            Ok(res)
        }
        fn write_response(
            response: Self::Response,
            vm: &mut VirtualMachine,
            ptr: &mut Relocatable,
        ) -> WriteResponseResult {
            pub fn write_u256(
                vm: &mut VirtualMachine,
                ptr: &mut Relocatable,
                value: BigUint,
            ) -> Result<(), MemoryError> {
                write_felt(vm, ptr, Felt252::from(&value & BigUint::from(u128::MAX)))?;
                write_felt(vm, ptr, Felt252::from(value >> 128))
            }
            write_u256(vm, ptr, response.x)?;
            write_u256(vm, ptr, response.y)?;

            Ok(())
        }
    }

    // Tests
    #[cfg(test)]
    mod tests {

        use ark_ff::One;
        use num_bigint::BigUint;
        use num_traits::{FromPrimitive, Num};
        use rstest::rstest;

        use super::*;

        fn parse_hex(hex_str: &str) -> BigUint {
            let trimmed_hex_str = hex_str.trim_start_matches("0x");
            BigUint::from_str_radix(trimmed_hex_str, 16).unwrap()
        }

        const K1_X_POINT: &str = "0xF728B4FA42485E3A0A5D2F346BAA9455E3E70682C2094CAC629F6FBED82C07CD";
        const K1_Y_POINT: &str = "0x8E182CA967F38E1BD6A49583F43F187608E031AB54FC0C4A8F0DC94FAD0D0611";

        const R1_X_POINT: &str = "0x502A43CE77C6F5C736A82F847FA95F8C2D483FE223B12B91047D83258A958B0F";
        const R1_Y_POINT: &str = "0xDB0A2E6710C71BA80AFEB3ABDF69D306CE729C7704F4DDF2EAAF0B76209FE1B0";

        #[rstest]
        #[case::secp256k1(SecpHintProcessor::Secp256k1(SecpHintProcessorInner::<ark_secp256k1::Config>::new()))]
        #[case::secp256r1(SecpHintProcessor::Secp256r1(SecpHintProcessorInner::<ark_secp256r1::Config>::new()))]
        fn test_secp_add(#[case] mut processor: SecpHintProcessor) {
            let p0 = processor.allocate_point((1u32.into(), 2u32.into())).into();
            let p1 = processor.allocate_point((3u32.into(), 4u32.into())).into();
            let request = SecpAddRequest { p0, p1 };
            let response = processor.secp_add(request).unwrap();
            assert_eq!(response.ec_point, 2.into());
        }

        #[rstest]
        #[case::secp256k1(
            SecpHintProcessor::Secp256k1(SecpHintProcessorInner::<ark_secp256k1::Config>::new()),
            parse_hex(K1_X_POINT),
            parse_hex(K1_Y_POINT)
        )]
        #[case::secp256r1(
            SecpHintProcessor::Secp256r1(SecpHintProcessorInner::<ark_secp256r1::Config>::new()),
            parse_hex(R1_X_POINT),
            parse_hex(R1_Y_POINT)
        )]
        fn test_secp_mul(#[case] mut processor: SecpHintProcessor, #[case] x: BigUint, #[case] y: BigUint) {
            let ec_point_id = processor.allocate_point((x, y)).into();
            let request = SecpMulRequest { ec_point_id, scalar: BigUint::from_u32(3).unwrap() };
            let response = processor.secp_mul(request).unwrap();
            assert_eq!(response.ec_point, 1.into());
            let res = processor.secp_get_xy(SecpGetXyRequest { ec_point_id: response.ec_point });
            assert!(res.is_ok())
        }

        #[rstest]
        #[case::secp256k1(
            SecpHintProcessor::Secp256k1(SecpHintProcessorInner::<ark_secp256k1::Config>::new()),
            parse_hex(K1_X_POINT)
        )]
        #[case::secp256r1(
            SecpHintProcessor::Secp256r1(SecpHintProcessorInner::<ark_secp256r1::Config>::new()),
            parse_hex(R1_X_POINT)
        )]
        fn test_secp_get_point_from_x(#[case] mut processor: SecpHintProcessor, #[case] x: BigUint) {
            let request = SecpGetPointFromXRequest { x, y_parity: true };
            let response = processor.secp_get_point_from_x(request).unwrap();
            assert!(response.optional_ec_point_id.is_some());
            let res = processor.secp_get_xy(SecpGetXyRequest { ec_point_id: response.optional_ec_point_id.unwrap() });
            assert!(res.is_ok())
        }

        #[rstest]
        #[case::secp256k1(
            SecpHintProcessor::Secp256k1(SecpHintProcessorInner::<ark_secp256k1::Config>::new()),
            parse_hex(K1_X_POINT),
            parse_hex(K1_Y_POINT)
        )]
        #[case::secp256r1(
            SecpHintProcessor::Secp256r1(SecpHintProcessorInner::<ark_secp256r1::Config>::new()),
            parse_hex(R1_X_POINT),
            parse_hex(R1_Y_POINT)
        )]
        fn test_secp_get_xy(#[case] mut processor: SecpHintProcessor, #[case] x: BigUint, #[case] y: BigUint) {
            let request = EcPointCoordinates { x: x.clone(), y: y.clone() };
            let ec_point_id = processor.secp_new(request).unwrap().optional_ec_point.unwrap().into();
            let request = SecpGetXyRequest { ec_point_id };
            let response: EcPointCoordinates = processor.secp_get_xy(request).unwrap();
            assert_eq!(response.x, x);
            assert_eq!(response.y, y);
        }

        #[rstest]
        #[case::secp256k1(SecpHintProcessor::Secp256k1(SecpHintProcessorInner::<ark_secp256k1::Config>::new()))]
        #[case::secp256r1(SecpHintProcessor::Secp256r1(SecpHintProcessorInner::<ark_secp256r1::Config>::new()))]
        fn test_secp_new(#[case] mut processor: SecpHintProcessor) {
            let request = EcPointCoordinates { x: BigUint::ZERO, y: BigUint::one() };
            let response = processor.secp_new(request).unwrap();
            assert!(response.optional_ec_point.is_none());
        }

        #[rstest]
        #[case::secp256k1(SecpHintProcessor::Secp256k1(SecpHintProcessorInner::<ark_secp256k1::Config>::new()))]
        #[case::secp256r1(SecpHintProcessor::Secp256r1(SecpHintProcessorInner::<ark_secp256r1::Config>::new()))]
        fn test_invalid_secp_new(#[case] mut processor: SecpHintProcessor) {
            let hex_str = "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
            let request = EcPointCoordinates { x: parse_hex(hex_str), y: BigUint::one() };
            let response = processor.secp_new(request);
            assert!(response.is_err());
        }
    }
}
