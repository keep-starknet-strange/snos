use cairo_vm::Felt252;
use cairo_vm::types::relocatable::Relocatable;
use cairo_vm::vm::vm_core::VirtualMachine;

use crate::execution::helper::ExecutionHelperWrapper;
use crate::execution::syscall_utils::{write_maybe_relocatable, EmptyRequest, SyscallResponse, SyscallResult, WriteResponseResult, felt_from_ptr, SyscallRequest, SingleSegmentResponse, ReadOnlySegment, read_call_params};

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
    _exec_wrapper: ExecutionHelperWrapper,
    remaining_gas: &mut u64,
) -> SyscallResult<CallContractResponse> {
    println!("CallContract syscall, contract_address: {}", request.contract_address);
    // TODO: return non empty response
    let start_ptr = vm.add_memory_segment();
    vm.insert_value(start_ptr, 2)?;
    Ok(CallContractResponse { segment: ReadOnlySegment { start_ptr, length: 1 } })
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

// TODO: EmitEvent syscall.
// #[derive(Debug, Eq, PartialEq)]
// pub struct EmitEventRequest {
//     pub content: EventContent,
// }
//
// impl SyscallRequest for EmitEventRequest {
//     // The Cairo struct contains: `keys_len`, `keys`, `data_len`, `data`·
//     fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<EmitEventRequest> {
//         let keys =
//             read_felt_array::<SyscallExecutionError>(vm,
// ptr)?.into_iter().map(EventKey).collect();         let data =
// EventData(read_felt_array::<SyscallExecutionError>(vm, ptr)?);
//
//         Ok(EmitEventRequest { content: EventContent { keys, data } })
//     }
// }
//
// type EmitEventResponse = EmptyResponse;
//
// pub fn emit_event(
//     request: EmitEventRequest,
//     _vm: &mut VirtualMachine,
//     syscall_handler: &mut SyscallHintProcessor<'_>,
//     _remaining_gas: &mut u64,
// ) -> SyscallResult<EmitEventResponse> {
//     Ok(EmitEventResponse {})
// }

// TODO: GetBlockHash syscall.
//
// #[derive(Debug, Eq, PartialEq)]
// pub struct GetBlockHashRequest {
//     pub block_number: BlockNumber,
// }
//
// impl SyscallRequest for GetBlockHashRequest {
//     fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<GetBlockHashRequest> {
//         let felt = felt_from_ptr(vm, ptr)?;
//         let block_number = BlockNumber(felt.to_u64().ok_or_else(|| {
//             SyscallExecutionError::InvalidSyscallInput {
//                 input: felt_to_stark_felt(&felt),
//                 info: String::from("Block number must fit within 64 bits."),
//             }
//         })?);
//
//         Ok(GetBlockHashRequest { block_number })
//     }
// }
//
// #[derive(Debug, Eq, PartialEq)]
// pub struct GetBlockHashResponse {
//     pub block_hash: BlockHash,
// }
//
// impl SyscallResponse for GetBlockHashResponse {
//     fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
//         write_stark_felt(vm, ptr, self.block_hash.0)?;
//         Ok(())
//     }
// }
//
// /// Returns the block hash of a given block_number.
// /// Returns the expected block hash if the given block was created at least
// /// [constants::STORED_BLOCK_HASH_BUFFER] blocks before the current block. Otherwise, returns an
// /// error.
// pub fn get_block_hash(
//     request: GetBlockHashRequest,
//     _vm: &mut VirtualMachine,
//     syscall_handler: &mut SyscallHintProcessor<'_>,
//     _remaining_gas: &mut u64,
// ) -> SyscallResult<GetBlockHashResponse> {
//     Ok(GetBlockHashResponse { block_hash })
// }

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
    exec_wrapper: ExecutionHelperWrapper,
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

// TODO: SendMessageToL1 syscall.
// #[derive(Debug, Eq, PartialEq)]
// pub struct SendMessageToL1Request {
//     pub message: MessageToL1,
// }
//
// impl SyscallRequest for SendMessageToL1Request {
//     // The Cairo struct contains: `to_address`, `payload_size`, `payload`.
//     fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<SendMessageToL1Request>
// {         let to_address = EthAddress::try_from(stark_felt_from_ptr(vm, ptr)?)?;
//         let payload = L2ToL1Payload(read_felt_array::<SyscallExecutionError>(vm, ptr)?);
//
//         Ok(SendMessageToL1Request { message: MessageToL1 { to_address, payload } })
//     }
// }
//
// type SendMessageToL1Response = EmptyResponse;
//
// pub fn send_message_to_l1(
//     request: SendMessageToL1Request,
//     _vm: &mut VirtualMachine,
//     syscall_handler: &mut SyscallHintProcessor<'_>,
//     _remaining_gas: &mut u64,
// ) -> SyscallResult<SendMessageToL1Response> {
//     Ok(SendMessageToL1Response {})
// }

// TODO: StorageRead syscall.
// #[derive(Debug, Eq, PartialEq)]
// pub struct StorageReadRequest {
//     pub address_domain: StarkFelt,
//     pub address: StorageKey,
// }
//
// impl SyscallRequest for StorageReadRequest {
//     fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<StorageReadRequest> {
//         let address_domain = stark_felt_from_ptr(vm, ptr)?;
//         if address_domain != StarkFelt::from(0_u8) {
//             return Err(SyscallExecutionError::InvalidAddressDomain { address_domain });
//         }
//         let address = StorageKey::try_from(stark_felt_from_ptr(vm, ptr)?)?;
//         Ok(StorageReadRequest { address_domain, address })
//     }
// }
//
// #[derive(Debug, Eq, PartialEq)]
// pub struct StorageReadResponse {
//     pub value: StarkFelt,
// }
//
// impl SyscallResponse for StorageReadResponse {
//     fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
//         write_stark_felt(vm, ptr, self.value)?;
//         Ok(())
//     }
// }
//
// pub fn storage_read(
//     request: StorageReadRequest,
//     _vm: &mut VirtualMachine,
//     syscall_handler: &mut SyscallHintProcessor<'_>,
//     _remaining_gas: &mut u64,
// ) -> SyscallResult<StorageReadResponse> {
// }

// TODO: StorageWrite syscall.
// #[derive(Debug, Eq, PartialEq)]
// pub struct StorageWriteRequest {
//     pub address_domain: StarkFelt,
//     pub address: StorageKey,
//     pub value: StarkFelt,
// }
//
// impl SyscallRequest for StorageWriteRequest {
//     fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<StorageWriteRequest> {
//         let address_domain = stark_felt_from_ptr(vm, ptr)?;
//         if address_domain != StarkFelt::from(0_u8) {
//             return Err(SyscallExecutionError::InvalidAddressDomain { address_domain });
//         }
//         let address = StorageKey::try_from(stark_felt_from_ptr(vm, ptr)?)?;
//         let value = stark_felt_from_ptr(vm, ptr)?;
//         Ok(StorageWriteRequest { address_domain, address, value })
//     }
// }
//
// pub type StorageWriteResponse = EmptyResponse;
//
// pub fn storage_write(
//     request: StorageWriteRequest,
//     _vm: &mut VirtualMachine,
//     syscall_handler: &mut SyscallHintProcessor<'_>,
//     _remaining_gas: &mut u64,
// ) -> SyscallResult<StorageWriteResponse> {
// }

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
