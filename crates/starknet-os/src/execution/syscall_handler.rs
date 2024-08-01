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
use crate::cairo_types::new_syscalls;
use crate::execution::constants::{
    BLOCK_HASH_CONTRACT_ADDRESS, CALL_CONTRACT_GAS_COST, DEPLOY_GAS_COST, EMIT_EVENT_GAS_COST, GET_BLOCK_HASH_GAS_COST,
    GET_EXECUTION_INFO_GAS_COST, INVALID_INPUT_LENGTH_ERROR, KECCAK_FULL_RATE_IN_U64S, KECCAK_GAS_COST,
    KECCAK_ROUND_COST_GAS_COST, LIBRARY_CALL_GAS_COST, REPLACE_CLASS_GAS_COST, SEND_MESSAGE_TO_L1_GAS_COST,
    STORAGE_READ_GAS_COST, STORAGE_WRITE_GAS_COST,
};
use crate::execution::syscall_handler_utils::{
    felt_from_ptr, run_handler, write_felt, write_maybe_relocatable, write_segment, EmptyRequest, EmptyResponse,
    ReadOnlySegment, SyscallExecutionError, SyscallHandler, SyscallResult, SyscallSelector, WriteResponseResult,
};
use crate::storage::storage::Storage;
use crate::utils::felt_api2vm;

/// DeprecatedSyscallHandler implementation for execution of system calls in the StarkNet OS
#[derive(Debug)]
pub struct OsSyscallHandler<S: Storage>
where
    S: Storage,
{
    pub exec_wrapper: ExecutionHelperWrapper<S>,
    pub syscall_ptr: Option<Relocatable>,
    pub segments: ReadOnlySegments,
}

/// OsSyscallHandler is wrapped in Rc<RefCell<_>> in order
/// to clone the reference when entering and exiting vm scopes
#[derive(Debug)]
pub struct OsSyscallHandlerWrapper<S>
where
    S: Storage,
{
    pub syscall_handler: Rc<RwLock<OsSyscallHandler<S>>>,
}

impl<S> Clone for OsSyscallHandlerWrapper<S>
where
    S: Storage,
{
    fn clone(&self) -> Self {
        Self { syscall_handler: self.syscall_handler.clone() }
    }
}

impl<S> OsSyscallHandlerWrapper<S>
where
    S: Storage + 'static,
{
    pub fn new(exec_wrapper: ExecutionHelperWrapper<S>) -> Self {
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
                run_handler::<CallContractHandler, S>(ptr, vm, ehw, CALL_CONTRACT_GAS_COST).await
            }
            SyscallSelector::Deploy => run_handler::<DeployHandler, S>(ptr, vm, ehw, DEPLOY_GAS_COST).await,
            SyscallSelector::EmitEvent => run_handler::<EmitEventHandler, S>(ptr, vm, ehw, EMIT_EVENT_GAS_COST).await,
            SyscallSelector::GetBlockHash => {
                run_handler::<GetBlockHashHandler, S>(ptr, vm, ehw, GET_BLOCK_HASH_GAS_COST).await
            }
            SyscallSelector::LibraryCall => {
                run_handler::<LibraryCallHandler, S>(ptr, vm, ehw, LIBRARY_CALL_GAS_COST).await
            }
            SyscallSelector::GetExecutionInfo => {
                run_handler::<GetExecutionInfoHandler, S>(ptr, vm, ehw, GET_EXECUTION_INFO_GAS_COST).await
            }
            SyscallSelector::StorageRead => {
                run_handler::<StorageReadHandler, S>(ptr, vm, ehw, STORAGE_READ_GAS_COST).await
            }
            SyscallSelector::StorageWrite => {
                run_handler::<StorageWriteHandler, S>(ptr, vm, ehw, STORAGE_WRITE_GAS_COST).await
            }
            SyscallSelector::SendMessageToL1 => {
                run_handler::<SendMessageToL1Handler, S>(ptr, vm, ehw, SEND_MESSAGE_TO_L1_GAS_COST).await
            }
            SyscallSelector::ReplaceClass => {
                run_handler::<ReplaceClassHandler, S>(ptr, vm, ehw, REPLACE_CLASS_GAS_COST).await
            }
            SyscallSelector::LibraryCallL1Handler => {
                run_handler::<LibraryCallHandler, S>(ptr, vm, ehw, LIBRARY_CALL_GAS_COST).await
            }
            SyscallSelector::Keccak => run_handler::<KeccakHandler, S>(ptr, vm, ehw, KECCAK_GAS_COST).await,
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

    async fn execute<S>(
        _request: EmptyRequest,
        vm: &mut VirtualMachine,
        exec_wrapper: &mut ExecutionHelperWrapper<S>,
        remaining_gas: &mut u64,
    ) -> SyscallResult<ReadOnlySegment>
    where
        S: Storage + 'static,
    {
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

    async fn execute<S>(
        _request: Self::Request,
        vm: &mut VirtualMachine,
        exec_wrapper: &mut ExecutionHelperWrapper<S>,
        remaining_gas: &mut u64,
    ) -> SyscallResult<Self::Response>
    where
        S: Storage + 'static,
    {
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

    async fn execute<S>(
        _request: Self::Request,
        _vm: &mut VirtualMachine,
        _exec_wrapper: &mut ExecutionHelperWrapper<S>,
        _remaining_gas: &mut u64,
    ) -> SyscallResult<Self::Response>
    where
        S: Storage + 'static,
    {
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

    async fn execute<S: Storage + 'static>(
        request: GetBlockHashRequest,
        _vm: &mut VirtualMachine,
        exec_wrapper: &mut ExecutionHelperWrapper<S>,
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

    async fn execute<S>(
        _request: Self::Request,
        _vm: &mut VirtualMachine,
        exec_wrapper: &mut ExecutionHelperWrapper<S>,
        _remaining_gas: &mut u64,
    ) -> SyscallResult<Self::Response>
    where
        S: Storage + 'static,
    {
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

    async fn execute<S>(
        _request: Self::Request,
        vm: &mut VirtualMachine,
        exec_wrapper: &mut ExecutionHelperWrapper<S>,
        remaining_gas: &mut u64,
    ) -> SyscallResult<Self::Response>
    where
        S: Storage + 'static,
    {
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

    async fn execute<S>(
        _request: Self::Request,
        _vm: &mut VirtualMachine,
        _exec_wrapper: &mut ExecutionHelperWrapper<S>,
        _remaining_gas: &mut u64,
    ) -> SyscallResult<Self::Response>
    where
        S: Storage + 'static,
    {
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

    async fn execute<S>(
        _request: Self::Request,
        _vm: &mut VirtualMachine,
        _exec_wrapper: &mut ExecutionHelperWrapper<S>,
        _remaining_gas: &mut u64,
    ) -> SyscallResult<Self::Response>
    where
        S: Storage + 'static,
    {
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
    async fn execute<S>(
        _request: EmptyRequest,
        _vm: &mut VirtualMachine,
        exec_wrapper: &mut ExecutionHelperWrapper<S>,
        _remaining_gas: &mut u64,
    ) -> SyscallResult<StorageReadResponse>
    where
        S: Storage + 'static,
    {
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
    async fn execute<S>(
        _request: EmptyRequest,
        _vm: &mut VirtualMachine,
        _exec_wrapper: &mut ExecutionHelperWrapper<S>,
        _remaining_gas: &mut u64,
    ) -> SyscallResult<EmptyResponse>
    where
        S: Storage + 'static,
    {
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

impl SyscallHandler for KeccakHandler {
    type Request = KeccakRequest;
    type Response = KeccakResponse;

    fn read_request(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Self::Request> {
        let input_start = vm.get_relocatable(*ptr)?;
        *ptr = (*ptr + 1)?;
        let input_end = vm.get_relocatable(*ptr)?;
        *ptr = (*ptr + 1)?;
        Ok(KeccakRequest { input_start, input_end })
    }

    async fn execute<S>(
        request: Self::Request,
        vm: &mut VirtualMachine,
        _exec_wrapper: &mut ExecutionHelperWrapper<S>,
        remaining_gas: &mut u64,
    ) -> SyscallResult<Self::Response>
    where
        S: Storage + 'static,
    {
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

// TODO: SecpAdd syscall.
// #[derive(Debug, Eq, PartialEq)]
// pub struct SecpAddRequest {
//     pub lhs_id: Felt252,
//     pub rhs_id: Felt252,
// }
//
// impl SyscallRequest for SecpAddRequest {
//     fn read(vm: &VirtualMachine, ptr: &mut Relocatable) ->
// blockifier::execution::syscalls::SyscallResult<SecpAddRequest> {         Ok(SecpAddRequest {
// lhs_id: felt_from_ptr(vm, ptr)?, rhs_id: felt_from_ptr(vm, ptr)? })     }
// }
//
// type SecpAddResponse = SecpOpRespone;
//
// pub fn secp256k1_add(
//     request: SecpAddRequest,
//     _vm: &mut VirtualMachine,
//     syscall_handler: &mut SyscallHintProcessor<'_>,
//     _remaining_gas: &mut u64,
// ) -> blockifier::execution::syscalls::SyscallResult<SecpOpRespone> {
//     syscall_handler.secp256k1_hint_processor.secp_add(request)
// }
//
// pub fn secp256r1_add(
//     request: SecpAddRequest,
//     _vm: &mut VirtualMachine,
//     syscall_handler: &mut SyscallHintProcessor<'_>,
//     _remaining_gas: &mut u64,
// ) -> blockifier::execution::syscalls::SyscallResult<SecpOpRespone> {
//     syscall_handler.secp256r1_hint_processor.secp_add(request)
// }

// TODO: SecpGetPointFromXRequest syscall.
// #[derive(Debug, Eq, PartialEq)]
// pub struct SecpGetPointFromXRequest {
//     x: BigUint,
//     // The parity of the y coordinate, assuming a point with the given x coordinate exists.
//     // True means the y coordinate is odd.
//     y_parity: bool,
// }
//
// impl SyscallRequest for SecpGetPointFromXRequest {
//     fn read(vm: &VirtualMachine, ptr: &mut Relocatable) ->
// blockifier::execution::syscalls::SyscallResult<SecpGetPointFromXRequest> {         let x =
// SierraU256::from_memory(vm, ptr)?.to_biguint();
//
//         let y_parity = felt_to_bool(stark_felt_from_ptr(vm, ptr)?, "Invalid y parity")?;
//         Ok(SecpGetPointFromXRequest { x, y_parity })
//     }
// }
//
// type SecpGetPointFromXResponse = SecpOptionalEcPointResponse;
//
// pub fn secp256k1_get_point_from_x(
//     request: SecpGetPointFromXRequest,
//     _vm: &mut VirtualMachine,
//     syscall_handler: &mut SyscallHintProcessor<'_>,
//     _remaining_gas: &mut u64,
// ) -> blockifier::execution::syscalls::SyscallResult<SecpGetPointFromXResponse> {
//     syscall_handler.secp256k1_hint_processor.secp_get_point_from_x(request)
// }
//
// pub fn secp256r1_get_point_from_x(
//     request: SecpGetPointFromXRequest,
//     _vm: &mut VirtualMachine,
//     syscall_handler: &mut SyscallHintProcessor<'_>,
//     _remaining_gas: &mut u64,
// ) -> blockifier::execution::syscalls::SyscallResult<SecpGetPointFromXResponse> {
//     syscall_handler.secp256r1_hint_processor.secp_get_point_from_x(request)
// }

// TODO: SecpGetXy syscall.
// #[derive(Debug, Eq, PartialEq)]
// pub struct SecpGetXyRequest {
//     pub ec_point_id: Felt252,
// }
//
// impl SyscallRequest for SecpGetXyRequest {
//     fn read(vm: &VirtualMachine, ptr: &mut Relocatable) ->
// blockifier::execution::syscalls::SyscallResult<SecpGetXyRequest> {         Ok(SecpGetXyRequest {
// ec_point_id: felt_from_ptr(vm, ptr)? })     }
// }
//
// type SecpGetXyResponse = EcPointCoordinates;
//
// impl SyscallResponse for SecpGetXyResponse {
//     fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) ->
// blockifier::execution::syscalls::WriteResponseResult {         write_u256(vm, ptr, self.x)?;
//         write_u256(vm, ptr, self.y)?;
//         Ok(())
//     }
// }
//
// pub fn secp256k1_get_xy(
//     request: SecpGetXyRequest,
//     _vm: &mut VirtualMachine,
//     syscall_handler: &mut SyscallHintProcessor<'_>,
//     _remaining_gas: &mut u64,
// ) -> blockifier::execution::syscalls::SyscallResult<SecpGetXyResponse> {
// }
//
// pub fn secp256r1_get_xy(
//     request: SecpGetXyRequest,
//     _vm: &mut VirtualMachine,
//     syscall_handler: &mut SyscallHintProcessor<'_>,
//     _remaining_gas: &mut u64,
// ) -> blockifier::execution::syscalls::SyscallResult<SecpGetXyResponse> {
// }

// TODO: SecpMul syscall.
// #[derive(Debug, Eq, PartialEq)]
// pub struct SecpMulRequest {
//     pub ec_point_id: Felt252,
//     pub multiplier: BigUint,
// }
//
// impl blockifier::execution::syscalls::SyscallRequest for SecpMulRequest {
//     fn read(vm: &VirtualMachine, ptr: &mut Relocatable) ->
// blockifier::execution::syscalls::SyscallResult<SecpMulRequest> {         let ec_point_id =
// felt_from_ptr(vm, ptr)?;         let multiplier = SierraU256::from_memory(vm, ptr)?.to_biguint();
//         Ok(SecpMulRequest { ec_point_id, multiplier })
//     }
// }
//
// type SecpMulResponse = SecpOpRespone;
//
// pub fn secp256k1_mul(
//     request: SecpMulRequest,
//     _vm: &mut VirtualMachine,
//     syscall_handler: &mut SyscallHintProcessor<'_>,
//     _remaining_gas: &mut u64,
// ) -> blockifier::execution::syscalls::SyscallResult<SecpMulResponse> {
// }
//
// pub fn secp256r1_mul(
//     request: SecpMulRequest,
//     _vm: &mut VirtualMachine,
//     syscall_handler: &mut SyscallHintProcessor<'_>,
//     _remaining_gas: &mut u64,
// ) -> blockifier::execution::syscalls::SyscallResult<SecpMulResponse> {
// }

// TODO: SecpNew syscall.
// type SecpNewRequest = EcPointCoordinates;
//
// impl blockifier::execution::syscalls::SyscallRequest for SecpNewRequest {
//     fn read(vm: &VirtualMachine, ptr: &mut Relocatable) ->
// blockifier::execution::syscalls::SyscallResult<SecpNewRequest> {         let x =
// SierraU256::from_memory(vm, ptr)?.to_biguint();         let y = SierraU256::from_memory(vm,
// ptr)?.to_biguint();         Ok(SecpNewRequest { x, y })
//     }
// }
//
// type SecpNewResponse = SecpOptionalEcPointResponse;
//
// pub fn secp256k1_new(
//     request: SecpNewRequest,
//     _vm: &mut VirtualMachine,
//     syscall_handler: &mut SyscallHintProcessor<'_>,
//     _remaining_gas: &mut u64,
// ) -> blockifier::execution::syscalls::SyscallResult<SecpNewResponse> {
// }
//
// type Secp256r1NewRequest = EcPointCoordinates;
// type Secp256r1NewResponse = SecpOptionalEcPointResponse;
//
// pub fn secp256r1_new(
//     request: Secp256r1NewRequest,
//     _vm: &mut VirtualMachine,
//     syscall_handler: &mut SyscallHintProcessor<'_>,
//     _remaining_gas: &mut u64,
// ) -> blockifier::execution::syscalls::SyscallResult<Secp256r1NewResponse> {
// }
