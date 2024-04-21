use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;

use crate::execution::constants::BLOCK_HASH_CONTRACT_ADDRESS;
use crate::execution::helper::ExecutionHelperWrapper;
use crate::execution::syscall_utils::{
    felt_from_ptr, ignore_felt, ignore_felt_array, read_call_params, write_felt, write_maybe_relocatable, EmptyRequest,
    EmptyResponse, ReadOnlySegment, SingleSegmentResponse, SyscallExecutionError, SyscallRequest, SyscallResponse,
    SyscallResult, WriteResponseResult,
};
use crate::utils::felt_api2vm;

// CallContract syscall.
#[derive(Debug, Eq, PartialEq)]
pub struct CallContractRequest {
    pub contract_address: Felt252,
    pub function_selector: Felt252,
    pub calldata: Vec<Felt252>,
}

impl SyscallRequest for CallContractRequest {
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<CallContractRequest> {
        let contract_address = felt_from_ptr(vm, ptr)?;
        let (function_selector, calldata) = read_call_params(vm, ptr)?;
        Ok(CallContractRequest { contract_address, function_selector, calldata })
    }
}

pub type CallContractResponse = SingleSegmentResponse;

pub fn call_contract(
    request: CallContractRequest,
    vm: &mut VirtualMachine,
    exec_wrapper: &mut ExecutionHelperWrapper,
    remaining_gas: &mut u64,
) -> SyscallResult<CallContractResponse> {
    let result_iter = &mut exec_wrapper.execution_helper.as_ref().borrow_mut().result_iter;
    let result = result_iter
        .next()
        .ok_or(SyscallExecutionError::InternalError(Box::from("No result left in the result iterator.")))?;

    *remaining_gas -= result.gas_consumed;

    let retdata = result.retdata.0.iter().map(|sf| felt_api2vm(*sf)).collect();

    if result.failed {
        return Err(SyscallExecutionError::SyscallError { error_data: retdata });
    }

    println!(
        "CallContract syscall, contract address: {}, selector: {} -> failed: {}, {:?}?",
        request.contract_address,
        request.function_selector.to_hex_string(),
        result.failed,
        result.retdata
    );

    let start_ptr = vm.add_temporary_segment();
    vm.load_data(start_ptr, &retdata.iter().map(MaybeRelocatable::from).collect())?;
    Ok(CallContractResponse { segment: ReadOnlySegment { start_ptr, length: retdata.len() } })
}

// TODO: Deploy syscall.
// #[derive(Debug, Eq, PartialEq)]
// pub struct DeployRequest {
//     pub class_hash: ClassHash,
//     pub contract_address_salt: ContractAddressSalt,
//     pub constructor_calldata: Calldata,
//     pub deploy_from_zero: bool,
// }
//
// impl SyscallRequest for DeployRequest {
//     fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<DeployRequest> {
//         let class_hash = ClassHash(stark_felt_from_ptr(vm, ptr)?);
//         let contract_address_salt = ContractAddressSalt(stark_felt_from_ptr(vm, ptr)?);
//         let constructor_calldata = read_calldata(vm, ptr)?;
//         let deploy_from_zero = stark_felt_from_ptr(vm, ptr)?;
//
//         Ok(DeployRequest {
//             class_hash,
//             contract_address_salt,
//             constructor_calldata,
//             deploy_from_zero: felt_to_bool(
//                 deploy_from_zero,
//                 "The deploy_from_zero field in the deploy system call must be 0 or 1.",
//             )?,
//         })
//     }
// }
//
// #[derive(Debug)]
// pub struct DeployResponse {
//     pub contract_address: ContractAddress,
//     pub constructor_retdata: ReadOnlySegment,
// }
//
// impl SyscallResponse for DeployResponse {
//     fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
//         write_stark_felt(vm, ptr, *self.contract_address.0.key())?;
//         write_segment(vm, ptr, self.constructor_retdata)
//     }
// }
//
// pub fn deploy(
//     request: DeployRequest,
//     vm: &mut VirtualMachine,
//     syscall_handler: &mut SyscallHintProcessor<'_>,
//     remaining_gas: &mut u64,
// ) -> SyscallResult<DeployResponse> {
//
//     Ok(DeployResponse { contract_address: deployed_contract_address, constructor_retdata })
// }

type EmitEventRequest = EmptyResponse;

impl SyscallRequest for EmitEventRequest {
    fn read(_vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<EmitEventRequest> {
        ignore_felt_array(ptr)?;
        ignore_felt_array(ptr)?;
        Ok(EmitEventRequest {})
    }
}

type EmitEventResponse = EmptyResponse;

pub fn emit_event(
    _request: EmitEventRequest,
    _vm: &mut VirtualMachine,
    _exec_wrapper: &mut ExecutionHelperWrapper,
    _remaining_gas: &mut u64,
) -> SyscallResult<EmitEventResponse> {
    Ok(EmitEventResponse {})
}

#[derive(Debug, Eq, PartialEq)]
pub struct GetBlockHashRequest {
    pub block_number: Felt252,
}

impl SyscallRequest for GetBlockHashRequest {
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<GetBlockHashRequest> {
        let block_number = felt_from_ptr(vm, ptr)?;
        Ok(GetBlockHashRequest { block_number })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct GetBlockHashResponse {
    pub block_hash: Felt252,
}

impl SyscallResponse for GetBlockHashResponse {
    fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_felt(vm, ptr, self.block_hash)?;
        Ok(())
    }
}

pub fn get_block_hash(
    request: GetBlockHashRequest,
    _vm: &mut VirtualMachine,
    exec_wrapper: &mut ExecutionHelperWrapper,
    _remaining_gas: &mut u64,
) -> SyscallResult<GetBlockHashResponse> {
    // # The syscall handler should not directly read from the storage during the execution of
    // # transactions because the order in which reads and writes occur is not strictly linear.
    // # However, for the "block hash contract," this rule does not apply. This contract is updated
    // # only at the start of each block before other transactions are executed.
    let block_hash =
        exec_wrapper.read_storage_for_address(Felt252::from(BLOCK_HASH_CONTRACT_ADDRESS), request.block_number)?;
    Ok(GetBlockHashResponse { block_hash })
}

// GetExecutionInfo syscall.
type GetExecutionInfoRequest = EmptyRequest;

#[derive(Debug, Eq, PartialEq)]
pub struct GetExecutionInfoResponse {
    pub execution_info_ptr: Relocatable,
}

impl SyscallResponse for GetExecutionInfoResponse {
    fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_maybe_relocatable(vm, ptr, self.execution_info_ptr)?;
        Ok(())
    }
}

pub fn get_execution_info(
    _request: GetExecutionInfoRequest,
    _vm: &mut VirtualMachine,
    exec_wrapper: &mut ExecutionHelperWrapper,
    _remaining_gas: &mut u64,
) -> SyscallResult<GetExecutionInfoResponse> {
    let eh_ref = exec_wrapper.execution_helper.as_ref().borrow();
    let execution_info_ptr = eh_ref.call_execution_info_ptr.unwrap();
    Ok(GetExecutionInfoResponse { execution_info_ptr })
}

// TODO: LibraryCall syscall.
// #[derive(Debug, Eq, PartialEq)]
// pub struct LibraryCallRequest {
//     pub class_hash: ClassHash,
//     pub function_selector: EntryPointSelector,
//     pub calldata: Calldata,
// }
//
// impl SyscallRequest for LibraryCallRequest {
//     fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<LibraryCallRequest> {
//         let class_hash = ClassHash(stark_felt_from_ptr(vm, ptr)?);
//         let (function_selector, calldata) = read_call_params(vm, ptr)?;
//
//         Ok(LibraryCallRequest { class_hash, function_selector, calldata })
//     }
// }
//
// type LibraryCallResponse = CallContractResponse;
//
// pub fn library_call(
//     request: LibraryCallRequest,
//     vm: &mut VirtualMachine,
//     syscall_handler: &mut SyscallHintProcessor<'_>,
//     remaining_gas: &mut u64,
// ) -> SyscallResult<LibraryCallResponse> {
//     Ok(LibraryCallResponse { segment: retdata_segment })
// }

// TODO: LibraryCallL1Handler syscall.
// pub fn library_call_l1_handler(
//     request: LibraryCallRequest,
//     vm: &mut VirtualMachine,
//     syscall_handler: &mut SyscallHintProcessor<'_>,
//     remaining_gas: &mut u64,
// ) -> SyscallResult<LibraryCallResponse> {
//     let call_to_external = false;
//     let retdata_segment = execute_library_call(
//         syscall_handler,
//         vm,
//         request.class_hash,
//         call_to_external,
//         request.function_selector,
//         request.calldata,
//         remaining_gas,
//     )?;
//
//     Ok(LibraryCallResponse { segment: retdata_segment })
// }

// TODO: ReplaceClass syscall.
//
// #[derive(Debug, Eq, PartialEq)]
// pub struct ReplaceClassRequest {
//     pub class_hash: ClassHash,
// }
//
// impl SyscallRequest for ReplaceClassRequest {
//     fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<ReplaceClassRequest> {
//         let class_hash = ClassHash(stark_felt_from_ptr(vm, ptr)?);
//
//         Ok(ReplaceClassRequest { class_hash })
//     }
// }
//
// pub type ReplaceClassResponse = EmptyResponse;
//
// pub fn replace_class(
//     request: ReplaceClassRequest,
//     _vm: &mut VirtualMachine,
//     syscall_handler: &mut SyscallHintProcessor<'_>,
//     _remaining_gas: &mut u64,
// ) -> SyscallResult<ReplaceClassResponse> {
// }

#[derive(Debug, Eq, PartialEq)]
pub struct SendMessageToL1Request {}

impl SyscallRequest for SendMessageToL1Request {
    // The Cairo struct contains: `to_address`, `payload_start`, `payload_end`.
    fn read(_vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<SendMessageToL1Request> {
        ignore_felt(ptr)?; // to_address
        ignore_felt_array(ptr)?; // payload
        Ok(SendMessageToL1Request {})
    }
}
type SendMessageToL1Response = EmptyResponse;

pub fn send_message_to_l1(
    _request: SendMessageToL1Request,
    _vm: &mut VirtualMachine,
    _exec_wrapper: &mut ExecutionHelperWrapper,
    _remaining_gas: &mut u64,
) -> SyscallResult<SendMessageToL1Response> {
    Ok(SendMessageToL1Response {})
}

#[derive(Debug, Eq, PartialEq)]
pub struct StorageReadRequest {
    pub address_domain: Felt252, // to be ignored
    pub address: Felt252,
}

impl SyscallRequest for StorageReadRequest {
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<StorageReadRequest> {
        let address_domain = felt_from_ptr(vm, ptr)?;
        if address_domain != Felt252::ZERO {
            return Err(SyscallExecutionError::InvalidAddressDomain { address_domain });
        }
        let address = felt_from_ptr(vm, ptr)?;
        Ok(StorageReadRequest { address_domain, address })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct StorageReadResponse {
    pub value: Felt252,
}

impl SyscallResponse for StorageReadResponse {
    fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_felt(vm, ptr, self.value)?;
        Ok(())
    }
}

pub fn storage_read(
    _request: StorageReadRequest,
    _vm: &mut VirtualMachine,
    exec_wrapper: &mut ExecutionHelperWrapper,
    _remaining_gas: &mut u64,
) -> SyscallResult<StorageReadResponse> {
    let value =
        exec_wrapper.execution_helper.as_ref().borrow_mut().execute_code_read_iter.next().ok_or(
            HintError::SyscallError("n: No more storage reads available to replay".to_string().into_boxed_str()),
        )?;
    Ok(StorageReadResponse { value })
}

#[derive(Debug, Eq, PartialEq)]
pub struct StorageWriteRequest {
    pub address_domain: Felt252,
    pub address: Felt252,
    pub value: Felt252,
}

impl SyscallRequest for StorageWriteRequest {
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<StorageWriteRequest> {
        let address_domain = felt_from_ptr(vm, ptr)?;
        if address_domain != Felt252::ZERO {
            return Err(SyscallExecutionError::InvalidAddressDomain { address_domain });
        }
        let address = felt_from_ptr(vm, ptr)?;
        let value = felt_from_ptr(vm, ptr)?;

        Ok(StorageWriteRequest { address_domain, address, value })
    }
}

pub type StorageWriteResponse = EmptyResponse;

pub fn storage_write(
    _request: StorageWriteRequest,
    _vm: &mut VirtualMachine,
    _exec_wrapper: &mut ExecutionHelperWrapper,
    _remaining_gas: &mut u64,
) -> SyscallResult<StorageWriteResponse> {
    Ok(StorageWriteResponse {})
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
