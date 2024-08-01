use std::num::TryFromIntError;

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
use crate::storage::storage::{Storage, StorageError};

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
    #[error("Out of Gas in Syscall execution. Remaining gas is {remaining_gas}")]
    OutOfGas { remaining_gas: u64 },
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

impl From<TryFromIntError> for SyscallExecutionError {
    fn from(error: TryFromIntError) -> Self {
        Self::InternalError(format!("TryFromIntError error: {}", error).into())
    }
}

pub type SyscallResult<T> = Result<T, SyscallExecutionError>;
pub type WriteResponseResult = SyscallResult<()>;

// Common structs.

#[derive(Debug, Eq, PartialEq)]
pub struct EmptyRequest;

#[derive(Debug, Eq, PartialEq)]
pub struct EmptyResponse;

#[derive(Debug)]
// Invariant: read-only.
pub struct ReadOnlySegment {
    pub start_ptr: Relocatable,
    pub length: usize,
}

pub fn write_segment(vm: &mut VirtualMachine, ptr: &mut Relocatable, segment: ReadOnlySegment) -> SyscallResult<()> {
    write_maybe_relocatable(vm, ptr, segment.start_ptr)?;
    let segment_end_ptr = (segment.start_ptr + segment.length)?;
    write_maybe_relocatable(vm, ptr, segment_end_ptr)?;

    Ok(())
}

#[allow(async_fn_in_trait)]
pub trait SyscallHandler {
    type Request;
    type Response;
    fn read_request(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Self::Request>;
    async fn execute<S>(
        request: Self::Request,
        vm: &mut VirtualMachine,
        exec_wrapper: &mut ExecutionHelperWrapper<S>,
        remaining_gas: &mut u64,
    ) -> SyscallResult<Self::Response>
    where
        S: Storage + 'static;
    fn write_response(response: Self::Response, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult;
}

fn write_failure(
    gas_counter: u64,
    error_data: Vec<Felt252>,
    vm: &mut VirtualMachine,
    ptr: &mut Relocatable,
) -> SyscallResult<()> {
    write_felt(vm, ptr, Felt252::from(gas_counter))?;
    // 1 to indicate failure.
    write_felt(vm, ptr, Felt252::ONE)?;

    // Write the error data to a new memory segment.
    let revert_reason_start = vm.add_memory_segment();
    let revert_reason_end = vm.load_data(revert_reason_start, &error_data.into_iter().map(Into::into).collect())?;

    // Write the start and end pointers of the error data.
    write_maybe_relocatable(vm, ptr, revert_reason_start)?;
    write_maybe_relocatable(vm, ptr, revert_reason_end)?;

    Ok(())
}

pub const OUT_OF_GAS_ERROR: &str = "0x000000000000000000000000000000000000000000004f7574206f6620676173";

pub async fn run_handler<SH, S>(
    syscall_ptr: &mut Relocatable,
    vm: &mut VirtualMachine,
    exec_wrapper: &mut ExecutionHelperWrapper<S>,
    syscall_gas_cost: u64,
) -> Result<(), HintError>
where
    SH: SyscallHandler,
    S: Storage + 'static,
{
    // Refund `SYSCALL_BASE_GAS_COST` as it was pre-charged.
    let required_gas = syscall_gas_cost - SYSCALL_BASE_GAS_COST;

    let gas_counter = felt_from_ptr(vm, syscall_ptr)?;
    let gas_counter = gas_counter.to_u64().ok_or_else(|| SyscallExecutionError::InvalidSyscallInput {
        input: gas_counter,
        info: String::from("Unexpected gas."),
    })?;

    if gas_counter < required_gas {
        //  Out of gas failure.
        let out_of_gas_error = Felt252::from_hex(OUT_OF_GAS_ERROR).unwrap();
        write_failure(gas_counter, vec![out_of_gas_error], vm, syscall_ptr)?;
        return Ok(());
    }

    let request = SH::read_request(vm, syscall_ptr)?;

    // Execute.
    let mut remaining_gas = gas_counter - required_gas;

    let syscall_result = SH::execute(request, vm, exec_wrapper, &mut remaining_gas).await;

    match syscall_result {
        Ok(response) => {
            write_felt(vm, syscall_ptr, Felt252::from(remaining_gas))?;
            // 0 to indicate success.
            write_felt(vm, syscall_ptr, Felt252::ZERO)?;
            SH::write_response(response, vm, syscall_ptr)?
        }
        Err(SyscallExecutionError::SyscallError { error_data: data }) => {
            write_failure(remaining_gas, data, vm, syscall_ptr)?;
        }
        Err(error) => return Err(error.into()),
    };

    Ok(())
}
