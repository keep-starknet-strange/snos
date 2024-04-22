use cairo_vm::types::errors::math_errors::MathError;
use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::errors::memory_errors::MemoryError;
use cairo_vm::vm::errors::vm_errors::VirtualMachineError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use num_traits::ToPrimitive;
use thiserror::Error;

use crate::execution::constants::SYSCALL_BASE_GAS_COST;
use crate::execution::helper::ExecutionHelperWrapper;
use crate::storage::storage::StorageError;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SyscallSelector {
    CallContract,
    DelegateCall,
    DelegateL1Handler,
    Deploy,
    EmitEvent,
    GetBlockHash,
    GetBlockNumber,
    GetBlockTimestamp,
    GetCallerAddress,
    GetContractAddress,
    GetExecutionInfo,
    GetSequencerAddress,
    GetTxInfo,
    GetTxSignature,
    Keccak,
    LibraryCall,
    LibraryCallL1Handler,
    ReplaceClass,
    Secp256k1Add,
    Secp256k1GetPointFromX,
    Secp256k1GetXy,
    Secp256k1Mul,
    Secp256k1New,
    Secp256r1Add,
    Secp256r1GetPointFromX,
    Secp256r1GetXy,
    Secp256r1Mul,
    Secp256r1New,
    SendMessageToL1,
    StorageRead,
    StorageWrite,
}

impl TryFrom<Felt252> for SyscallSelector {
    type Error = HintError;
    fn try_from(raw_selector: Felt252) -> Result<Self, Self::Error> {
        // Remove leading zero bytes from selector.
        let selector_bytes = raw_selector.to_bytes_be();
        let first_non_zero = selector_bytes.iter().position(|&byte| byte != b'\0').unwrap_or(32);

        match &selector_bytes[first_non_zero..] {
            b"CallContract" => Ok(Self::CallContract),
            b"DelegateCall" => Ok(Self::DelegateCall),
            b"DelegateL1Handler" => Ok(Self::DelegateL1Handler),
            b"Deploy" => Ok(Self::Deploy),
            b"EmitEvent" => Ok(Self::EmitEvent),
            b"GetBlockHash" => Ok(Self::GetBlockHash),
            b"GetBlockNumber" => Ok(Self::GetBlockNumber),
            b"GetBlockTimestamp" => Ok(Self::GetBlockTimestamp),
            b"GetCallerAddress" => Ok(Self::GetCallerAddress),
            b"GetContractAddress" => Ok(Self::GetContractAddress),
            b"GetExecutionInfo" => Ok(Self::GetExecutionInfo),
            b"GetSequencerAddress" => Ok(Self::GetSequencerAddress),
            b"GetTxInfo" => Ok(Self::GetTxInfo),
            b"GetTxSignature" => Ok(Self::GetTxSignature),
            b"Keccak" => Ok(Self::Keccak),
            b"LibraryCall" => Ok(Self::LibraryCall),
            b"LibraryCallL1Handler" => Ok(Self::LibraryCallL1Handler),
            b"ReplaceClass" => Ok(Self::ReplaceClass),
            b"Secp256k1Add" => Ok(Self::Secp256k1Add),
            b"Secp256k1GetPointFromX" => Ok(Self::Secp256k1GetPointFromX),
            b"Secp256k1GetXy" => Ok(Self::Secp256k1GetXy),
            b"Secp256k1Mul" => Ok(Self::Secp256k1Mul),
            b"Secp256k1New" => Ok(Self::Secp256k1New),
            b"Secp256r1Add" => Ok(Self::Secp256r1Add),
            b"Secp256r1GetPointFromX" => Ok(Self::Secp256r1GetPointFromX),
            b"Secp256r1GetXy" => Ok(Self::Secp256r1GetXy),
            b"Secp256r1Mul" => Ok(Self::Secp256r1Mul),
            b"Secp256r1New" => Ok(Self::Secp256r1New),
            b"SendMessageToL1" => Ok(Self::SendMessageToL1),
            b"StorageRead" => Ok(Self::StorageRead),
            b"StorageWrite" => Ok(Self::StorageWrite),
            _ => Err(HintError::CustomHint(format!("Unknown syscall selector: {}", raw_selector).into())),
        }
    }
}

pub fn felt_from_ptr(vm: &VirtualMachine, ptr: &mut Relocatable) -> Result<Felt252, MemoryError> {
    let felt = vm.get_integer(*ptr)?.into_owned();
    *ptr = (*ptr + 1)?;
    Ok(felt)
}

pub fn ignore_felt(ptr: &mut Relocatable) -> SyscallResult<()> {
    *ptr = (*ptr + 1)?;
    Ok(())
}

pub fn read_felt_array<TErr>(vm: &VirtualMachine, ptr: &mut Relocatable) -> Result<Vec<Felt252>, TErr>
where
    TErr: From<VirtualMachineError> + From<MemoryError> + From<MathError>,
{
    let array_data_start_ptr = vm.get_relocatable(*ptr)?;
    *ptr = (*ptr + 1)?;
    let array_data_end_ptr = vm.get_relocatable(*ptr)?;
    *ptr = (*ptr + 1)?;
    let array_size = (array_data_end_ptr - array_data_start_ptr)?;

    let values = vm.get_integer_range(array_data_start_ptr, array_size)?;

    Ok(values.into_iter().map(|felt| felt.into_owned()).collect())
}

pub fn ignore_felt_array(ptr: &mut Relocatable) -> SyscallResult<()> {
    // skip data start and end pointers, see `read_felt_array` function above.
    *ptr = (*ptr + 2)?;
    Ok(())
}

pub fn read_calldata(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Vec<Felt252>> {
    read_felt_array::<SyscallExecutionError>(vm, ptr)
}

pub fn read_call_params(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<(Felt252, Vec<Felt252>)> {
    let function_selector = felt_from_ptr(vm, ptr)?;
    let calldata = read_calldata(vm, ptr)?;

    Ok((function_selector, calldata))
}

pub fn write_felt(vm: &mut VirtualMachine, ptr: &mut Relocatable, felt: Felt252) -> Result<(), MemoryError> {
    write_maybe_relocatable(vm, ptr, felt)
}

pub fn write_maybe_relocatable<T: Into<MaybeRelocatable>>(
    vm: &mut VirtualMachine,
    ptr: &mut Relocatable,
    value: T,
) -> Result<(), MemoryError> {
    vm.insert_value(*ptr, value.into())?;
    *ptr = (*ptr + 1)?;
    Ok(())
}

#[derive(Debug, Error)]
pub enum SyscallExecutionError {
    #[error("Internal Error: {0}")]
    InternalError(Box<str>),
    #[error("Invalid address domain: {address_domain:?}")]
    InvalidAddressDomain { address_domain: Felt252 },
    #[error("Invalid syscall input: {input:?}; {info}")]
    InvalidSyscallInput { input: Felt252, info: String },
    #[error("Syscall error.")]
    SyscallError { error_data: Vec<Felt252> },
}

impl From<MemoryError> for SyscallExecutionError {
    fn from(error: MemoryError) -> Self {
        Self::InternalError(format!("Memory error: {}", error).into())
    }
}

impl From<SyscallExecutionError> for HintError {
    fn from(error: SyscallExecutionError) -> Self {
        HintError::CustomHint(format!("SyscallExecution error: {}", error).into())
    }
}

impl From<HintError> for SyscallExecutionError {
    fn from(error: HintError) -> Self {
        Self::InternalError(format!("Hint error: {}", error).into())
    }
}

impl From<VirtualMachineError> for SyscallExecutionError {
    fn from(error: VirtualMachineError) -> Self {
        Self::InternalError(format!("VirtualMachine error: {}", error).into())
    }
}

impl From<MathError> for SyscallExecutionError {
    fn from(error: MathError) -> Self {
        Self::InternalError(format!("MathError error: {}", error).into())
    }
}

impl From<StorageError> for SyscallExecutionError {
    fn from(error: StorageError) -> Self {
        Self::InternalError(format!("StorageError error: {}", error).into())
    }
}

pub type SyscallResult<T> = Result<T, SyscallExecutionError>;
pub type WriteResponseResult = SyscallResult<()>;

// type SyscallSelector = DeprecatedSyscallSelector;

pub trait SyscallRequest: Sized {
    fn read(_vm: &VirtualMachine, _ptr: &mut Relocatable) -> SyscallResult<Self>
    where
        Self: Sized;
}

pub trait SyscallResponse {
    fn write(self, _vm: &mut VirtualMachine, _ptr: &mut Relocatable) -> WriteResponseResult;
}

// Syscall header structs.
pub struct SyscallRequestWrapper<T: SyscallRequest> {
    pub gas_counter: u64,
    pub request: T,
}
impl<T: SyscallRequest> SyscallRequest for SyscallRequestWrapper<T> {
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Self> {
        let gas_counter = felt_from_ptr(vm, ptr)?;
        let gas_counter = gas_counter.to_u64().ok_or_else(|| SyscallExecutionError::InvalidSyscallInput {
            input: gas_counter,
            info: String::from("Unexpected gas."),
        })?;
        let request = T::read(vm, ptr)?;
        Ok(Self { gas_counter, request })
    }
}

pub enum SyscallResponseWrapper<T: SyscallResponse> {
    Success { gas_counter: u64, response: T },
    Failure { gas_counter: u64, error_data: Vec<Felt252> },
}
impl<T: SyscallResponse> SyscallResponse for SyscallResponseWrapper<T> {
    fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        match self {
            Self::Success { gas_counter, response } => {
                write_felt(vm, ptr, Felt252::from(gas_counter))?;
                // 0 to indicate success.
                write_felt(vm, ptr, Felt252::ZERO)?;
                response.write(vm, ptr)
            }
            Self::Failure { gas_counter, error_data } => {
                write_felt(vm, ptr, Felt252::from(gas_counter))?;
                // 1 to indicate failure.
                write_felt(vm, ptr, Felt252::ONE)?;

                // Write the error data to a new memory segment.
                let revert_reason_start = vm.add_memory_segment();
                let revert_reason_end =
                    vm.load_data(revert_reason_start, &error_data.into_iter().map(Into::into).collect())?;

                // Write the start and end pointers of the error data.
                write_maybe_relocatable(vm, ptr, revert_reason_start)?;
                write_maybe_relocatable(vm, ptr, revert_reason_end)?;
                Ok(())
            }
        }
    }
}

// Common structs.

#[derive(Debug, Eq, PartialEq)]
pub struct EmptyRequest;

impl SyscallRequest for EmptyRequest {
    fn read(_vm: &VirtualMachine, _ptr: &mut Relocatable) -> SyscallResult<EmptyRequest> {
        Ok(EmptyRequest)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct EmptyResponse;

impl SyscallResponse for EmptyResponse {
    fn write(self, _vm: &mut VirtualMachine, _ptr: &mut Relocatable) -> WriteResponseResult {
        Ok(())
    }
}

#[derive(Debug)]
// Invariant: read-only.
pub struct ReadOnlySegment {
    pub start_ptr: Relocatable,
    pub length: usize,
}

#[derive(Debug)]
pub struct SingleSegmentResponse {
    pub segment: ReadOnlySegment,
}

fn write_segment(vm: &mut VirtualMachine, ptr: &mut Relocatable, segment: ReadOnlySegment) -> SyscallResult<()> {
    write_maybe_relocatable(vm, ptr, segment.start_ptr)?;
    let segment_end_ptr = (segment.start_ptr + segment.length)?;
    write_maybe_relocatable(vm, ptr, segment_end_ptr)?;

    Ok(())
}

impl SyscallResponse for SingleSegmentResponse {
    fn write(self, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_segment(vm, ptr, self.segment)
    }
}

pub const OUT_OF_GAS_ERROR: &str = "0x000000000000000000000000000000000000000000004f7574206f6620676173";

pub fn execute_syscall<Request, Response, ExecuteCallback>(
    syscall_ptr: &mut Relocatable,
    vm: &mut VirtualMachine,
    exec_wrapper: &mut ExecutionHelperWrapper,
    execute_callback: ExecuteCallback,
    syscall_gas_cost: u64,
) -> Result<(), HintError>
where
    Request: SyscallRequest + std::fmt::Debug,
    Response: SyscallResponse + std::fmt::Debug,
    ExecuteCallback:
        FnOnce(Request, &mut VirtualMachine, &mut ExecutionHelperWrapper, &mut u64) -> SyscallResult<Response>,
{
    // Refund `SYSCALL_BASE_GAS_COST` as it was pre-charged.
    let required_gas = syscall_gas_cost - SYSCALL_BASE_GAS_COST;

    let SyscallRequestWrapper { gas_counter, request } = SyscallRequestWrapper::<Request>::read(vm, syscall_ptr)?;

    if gas_counter < required_gas {
        //  Out of gas failure.
        let out_of_gas_error = Felt252::from_hex(OUT_OF_GAS_ERROR).unwrap();
        let response: SyscallResponseWrapper<Response> =
            SyscallResponseWrapper::Failure { gas_counter, error_data: vec![out_of_gas_error] };
        response.write(vm, syscall_ptr)?;

        return Ok(());
    }

    // Execute.
    let mut remaining_gas = gas_counter - required_gas;
    let original_response = execute_callback(request, vm, exec_wrapper, &mut remaining_gas);
    let response = match original_response {
        Ok(response) => SyscallResponseWrapper::Success { gas_counter: remaining_gas, response },
        Err(SyscallExecutionError::SyscallError { error_data: data }) => {
            SyscallResponseWrapper::Failure { gas_counter: remaining_gas, error_data: data }
        }
        Err(error) => return Err(error.into()),
    };

    response.write(vm, syscall_ptr)?;

    Ok(())
}
