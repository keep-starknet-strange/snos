use std::rc::Rc;

use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use blockifier::abi::sierra_types::{felt_to_u128, SierraType, SierraU128};
use blockifier::execution::execution_utils::{write_u256, ReadOnlySegments};
use blockifier::execution::syscalls::hint_processor::INVALID_ARGUMENT;
use cairo_vm::math_utils::pow2_const_nz;
use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::errors::memory_errors::MemoryError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use num_bigint::BigUint;
use num_traits::Zero;
use tokio::sync::RwLock;

use super::helper::ExecutionHelperWrapper;
use crate::cairo_types::new_syscalls::{self, EcPointCoordinates, SecpGetXyRequest, Uint256};
use crate::execution::constants::{
    BLOCK_HASH_CONTRACT_ADDRESS, CALL_CONTRACT_GAS_COST, DEPLOY_GAS_COST, EMIT_EVENT_GAS_COST, GET_BLOCK_HASH_GAS_COST,
    GET_EXECUTION_INFO_GAS_COST, LIBRARY_CALL_GAS_COST, REPLACE_CLASS_GAS_COST, SECP256K1_GET_XY_GAS_COST,
    SECP256K1_NEW_GAS_COST, SEND_MESSAGE_TO_L1_GAS_COST, STORAGE_READ_GAS_COST, STORAGE_WRITE_GAS_COST,
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
            SyscallSelector::Secp256k1New => run_handler::<SecpNewHandler>(ptr, vm, ehw, SECP256K1_NEW_GAS_COST).await,
            SyscallSelector::Secp256k1GetXy => {
                run_handler::<SecpGetXyHandler>(ptr, vm, ehw, SECP256K1_GET_XY_GAS_COST).await
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

// TODO: Keccak syscall.
// #[derive(Debug, Eq, PartialEq)]
// pub struct KeccakRequest {
//     pub input_start: Relocatable,
//     pub input_end: Relocatable,
// }
//
// impl SyscallRequest for KeccakRequest {
//     fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<KeccakRequest> {
//         let input_start = vm.get_relocatable(*ptr)?;
//         *ptr = (*ptr + 1)?;
//         let input_end = vm.get_relocatable(*ptr)?;
//         *ptr = (*ptr + 1)?;
//         Ok(KeccakRequest { input_start, input_end })
//     }
// }
//
// #[derive(Debug, Eq, PartialEq)]
// pub struct KeccakResponse {
//     pub result_low: Felt252,
//     pub result_high: Felt252,
// }
//
// impl SyscallResponse for KeccakResponse {
//     fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
//         write_felt(vm, ptr, self.result_low)?;
//         write_felt(vm, ptr, self.result_high)?;
//         Ok(())
//     }
// }
//
// pub fn keccak(
//     request: KeccakRequest,
//     vm: &mut VirtualMachine,
//     syscall_handler: &mut SyscallHintProcessor<'_>,
//     remaining_gas: &mut u64,
// ) -> SyscallResult<KeccakResponse> {
// }

// #[derive(Debug, Eq, PartialEq)]
// pub struct SecpAddCall;
// #[derive(Debug, Eq, PartialEq)]
// pub struct SecpAddRequest {
//     pub lhs_id: Felt252,
//     pub rhs_id: Felt252,
// }

// struct SecpAddRequest {
//     p0: EcPoint*,
//     p1: EcPoint*,
// }

// impl SyscallHandler for SecpAddCall {
//     type Request = SecpAddRequest;
//     type Response = SecpOpResponse;
//     fn read_request(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Self::Request> {
//         Ok(SecpAddRequest { lhs_id: felt_from_ptr(vm, ptr)?, rhs_id: felt_from_ptr(vm, ptr)? })
//     }
//     async fn execute(
//         request: SecpAddRequest,
//         vm: &mut VirtualMachine,
//         _exec_wrapper: &mut ExecutionHelperWrapper,
//         _remaining_gas: &mut u64,
//     ) -> SyscallResult<SecpOpResponse> {
//         let modulos = Curve::BaseField::MODULUS.into();
//         let (x, y) = (request.lhs_id, request.rhs_id);
//         if x >= modulos || y >= modulos {
//             return Err(SyscallExecutionError::SyscallError {
//                 error_data: vec![
//                     Felt252::from_hex(INVALID_ARGUMENT).map_err(SyscallExecutionError::from)?,
//                 ],
//             });
//         }
//         let ec_point = if x.is_zero() && y.is_zero() {
//             short_weierstrass::Affine::<Curve>::identity()
//         } else {
//             short_weierstrass::Affine::<Curve>::new_unchecked(x.into(), y.into())
//         };
//         let optional_ec_point_id =
//             if ec_point.is_on_curve() && ec_point.is_in_correct_subgroup_assuming_on_curve() {
//                 Some(self.allocate_point(ec_point))
//             } else {
//                 None
//             };
//         Ok(SecpOpResponse { optional_ec_point_id })
//         // todo!()
//     }
//     fn write_response(response: Self::Response, vm: &mut VirtualMachine, ptr: &mut Relocatable)
// -> WriteResponseResult {         write_felt(vm, ptr, response.ec_point_id.into())?;
//         // write_felt(vm, ptr, response.result_high)?;
//         Ok(())
//     }
// }

// #[derive(Debug, Eq, PartialEq)]
// pub struct SecpOpResponse {
//     pub optional_ec_point_id: usize,
// }

// pub fn secp256k1_add(
//     request: SecpAddRequest,
//     _vm: &mut VirtualMachine,
//     syscall_handler: &mut SyscallHintProcessor<'_>,
//     _remaining_gas: &mut u64,
// ) -> blockifier::execution::syscalls::SyscallResult<SecpOpRespone> {
//     syscall_handler.secp256k1_hint_processor.secp_add(request)
// }

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

#[derive(Debug, Default, Eq, PartialEq)]
pub struct SecpHintProcessor<Curve: SWCurveConfig> {
    points: Vec<ark_ec::short_weierstrass::Affine<Curve>>,
}

struct SecpOpRespone {
    ec_point_id: usize,
}
#[derive(Debug, Eq, PartialEq)]

pub struct SecpNewResponse {
    pub optional_ec_point: Option<usize>,
}

fn pack(u: Uint256) -> BigUint {
    (u.high.to_biguint() << 128) + u.low.to_biguint()
}
impl<Curve: SWCurveConfig> SecpHintProcessor<Curve>
where
    Curve::BaseField: PrimeField,
{
    // pub fn secp_add(&mut self, request: SecpAddRequest) -> SyscallResult<SecpAddResponse> {
    //     let lhs = self.get_point_by_id(request.lhs_id)?;
    //     let rhs = self.get_point_by_id(request.rhs_id)?;
    //     let result = *lhs + *rhs;
    //     let ec_point_id = self.allocate_point(result.into());
    //     Ok(SecpOpRespone { ec_point_id })
    // }

    // pub fn secp_mul(&mut self, request: SecpMulRequest) -> SyscallResult<SecpMulResponse> {
    //     let ep_point = self.get_point_by_id(request.ec_point_id)?;
    //     let result = *ep_point * Curve::ScalarField::from(request.multiplier);
    //     let ec_point_id = self.allocate_point(result.into());
    //     Ok(SecpOpRespone { ec_point_id })
    // }

    // pub fn secp_get_point_from_x(
    //     &mut self,
    //     request: SecpGetPointFromXRequest,
    // ) -> SyscallResult<SecpGetPointFromXResponse> {
    //     let modulos = Curve::BaseField::MODULUS.into();

    //     if request.x >= modulos {
    //         return Err(SyscallExecutionError::SyscallError {
    //             error_data:
    // vec![Felt::from_hex(INVALID_ARGUMENT).map_err(SyscallExecutionError::from)?],         });
    //     }

    //     let x = request.x.into();
    //     let maybe_ec_point = short_weierstrass::Affine::<Curve>::get_ys_from_x_unchecked(x)
    //         .map(|(smaller, greater)| {
    //             // Return the correct y coordinate based on the parity.
    //             if smaller.into_bigint().is_odd() == request.y_parity { smaller } else { greater }
    //         })
    //         .map(|y| short_weierstrass::Affine::<Curve>::new_unchecked(x, y))
    //         .filter(|p| p.is_in_correct_subgroup_assuming_on_curve());

    //     Ok(SecpGetPointFromXResponse {
    //         optional_ec_point_id: maybe_ec_point.map(|ec_point| self.allocate_point(ec_point)),
    //     })
    // }

    pub fn secp_get_xy(&mut self, request: SecpGetXyRequest) -> SyscallResult<EcPointCoordinates> {
        let ec_point = self.get_point_by_id(request.ec_point_id)?;

        fn unpack(b: BigUint) -> Uint256 {
            let low_mask = BigUint::from(1u128) << 128 - 1u128; // Create a mask for the lower 128 bits
            let low = Felt252::from(&b & &low_mask);
            let high = Felt252::from(b >> 128);
            Uint256 { high, low }
        }

        Ok(EcPointCoordinates { x: unpack(ec_point.x.into()), y: unpack(ec_point.y.into()) })
    }

    pub fn secp_new(&mut self, request: EcPointCoordinates) -> SyscallResult<SecpNewResponse> {
        let modulos = Curve::BaseField::MODULUS.into();
        let (x, y): (BigUint, BigUint) = (pack(request.x), pack(request.y));
        if x >= modulos.clone().into() || y >= modulos.into() {
            return Err(SyscallExecutionError::SyscallError {
                error_data: vec![Felt252::from_hex(INVALID_ARGUMENT).unwrap()],
            });
        }
        let ec_point = if x.is_zero() && y.is_zero() {
            ark_ec::short_weierstrass::Affine::<Curve>::identity()
        } else {
            ark_ec::short_weierstrass::Affine::<Curve>::new_unchecked(x.into(), y.into())
        };
        let optional_ec_point = if ec_point.is_on_curve() && ec_point.is_in_correct_subgroup_assuming_on_curve() {
            Some(self.allocate_point(ec_point))
        } else {
            None
        };
        Ok(SecpNewResponse { optional_ec_point })
    }

    fn allocate_point(&mut self, ec_point: ark_ec::short_weierstrass::Affine<Curve>) -> usize {
        let points = &mut self.points;
        let id = points.len();
        points.push(ec_point);
        id
    }

    fn get_point_by_id(&self, ec_point_id: Felt252) -> SyscallResult<&ark_ec::short_weierstrass::Affine<Curve>> {
        use num_traits::ToPrimitive;
        ec_point_id.to_usize().and_then(|id| self.points.get(id)).ok_or_else(|| {
            SyscallExecutionError::InvalidSyscallInput { input: ec_point_id, info: "Invalid Secp point ID".to_string() }
        })
    }
}

pub struct SecpGetXyHandler;

impl SyscallHandler for SecpGetXyHandler {
    type Request = SecpGetXyRequest;
    type Response = EcPointCoordinates;

    fn read_request(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Self::Request> {
        Ok(SecpGetXyRequest { ec_point_id: felt_from_ptr(vm, ptr)? })
    }
    async fn execute(
        request: Self::Request,
        vm: &mut VirtualMachine,
        exec_wrapper: &mut ExecutionHelperWrapper,
        remaining_gas: &mut u64,
    ) -> SyscallResult<Self::Response> {
        let mut eh_ref = exec_wrapper.execution_helper.write().await;
        let res = eh_ref.secp256k1_hint_processor.secp_get_xy(request)?;
        Ok(res)
    }
    fn write_response(response: Self::Response, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        pub fn write_u256(vm: &mut VirtualMachine, ptr: &mut Relocatable, value: BigUint) -> Result<(), MemoryError> {
            write_felt(vm, ptr, Felt252::from(&value & BigUint::from(u128::MAX)))?;
            write_felt(vm, ptr, Felt252::from(value >> 128))
        }
        write_u256(vm, ptr, pack(response.x))?;
        write_u256(vm, ptr, pack(response.y))?;

        Ok(())
    }
}

pub struct SecpNewHandler;
impl SyscallHandler for SecpNewHandler {
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
        Ok(EcPointCoordinates { x: Uint256 { low: x.0, high: x.1 }, y: Uint256 { low: y.0, high: y.1 } })
    }
    async fn execute(
        request: EcPointCoordinates,
        vm: &mut VirtualMachine,
        exec_wrapper: &mut ExecutionHelperWrapper,
        _remaining_gas: &mut u64,
    ) -> SyscallResult<Self::Response> {
        let mut eh_ref = exec_wrapper.execution_helper.write().await;
        let res = eh_ref.secp256k1_hint_processor.secp_new(request)?;
        Ok(res)
    }
    fn write_response(response: Self::Response, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        match response.optional_ec_point {
            Some(id) => {
                // Cairo 1 representation of Some(id).
                write_maybe_relocatable(vm, ptr, 0)?;
                write_maybe_relocatable(vm, ptr, id)?;
            }
            None => {
                // Cairo 1 representation of None.
                write_maybe_relocatable(vm, ptr, 1)?;
                write_maybe_relocatable(vm, ptr, 0)?;
            }
        };
        Ok(())
    }
}
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
