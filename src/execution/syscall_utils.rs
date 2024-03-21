use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::errors::memory_errors::MemoryError;
use cairo_vm::vm::errors::vm_errors::VirtualMachineError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use starknet_api::StarknetApiError;
use thiserror::Error;
use crate::execution::helper::ExecutionHelperWrapper;

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

pub fn write_felt(vm: &mut VirtualMachine, ptr: &mut Relocatable, felt: Felt252) -> Result<(), MemoryError> {
    write_maybe_relocatable(vm, ptr, felt)
}

pub fn write_maybe_relocatable<T: Into<MaybeRelocatable>>(
    vm: &mut VirtualMachine,
    ptr: &mut Relocatable,
    value: T,
) -> Result<(), MemoryError> {
    vm.insert_value(*ptr, value)?;
    *ptr = (*ptr + 1)?;
    Ok(())
}

#[derive(Debug, Error)]
pub enum SyscallExecutionError {
    #[error("Internal Error: {0}")]
    InternalError(Box<str>),
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
        HintError::CustomHint(format!("Memory error: {}", error).into())
    }
}

impl From<HintError> for SyscallExecutionError {
    fn from(error: HintError) -> Self {
        Self::InternalError(format!("Memory error: {}", error).into())
    }
}


pub type SyscallResult<T> = Result<T, SyscallExecutionError>;
pub type WriteResponseResult = SyscallResult<()>;

// type SyscallSelector = DeprecatedSyscallSelector;

pub trait SyscallRequest: Sized {
    fn read(_vm: &VirtualMachine, _ptr: &mut Relocatable) -> SyscallResult<Self> where Self: Sized;
}

pub trait SyscallResponse {
    fn write(self, _vm: &mut VirtualMachine, _ptr: &mut Relocatable) -> WriteResponseResult;
}

// Syscall header structs.
pub struct SyscallRequestWrapper<T: SyscallRequest> {
    pub gas_counter: Felt252,
    pub request: T,
}
impl<T: SyscallRequest> SyscallRequest for SyscallRequestWrapper<T> {
    fn read(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Self> {
        let gas_counter = felt_from_ptr(vm, ptr)?;
        let request = T::read(vm, ptr)?;
        Ok(Self { gas_counter, request })
    }
}

pub enum SyscallResponseWrapper<T: SyscallResponse> {
    Success { gas_counter: Felt252, response: T },
    Failure { gas_counter: Felt252, error_data: Vec<Felt252> },
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

pub fn execute_syscall<Request, Response, ExecuteCallback>(
    syscall_ptr: &mut Relocatable,
    vm: &mut VirtualMachine,
    exec_wrapper: ExecutionHelperWrapper,
    execute_callback: ExecuteCallback,
    _syscall_gas_cost: Felt252,
) -> Result<(), HintError>
where
    Request: SyscallRequest + std::fmt::Debug,
    Response: SyscallResponse + std::fmt::Debug,
    ExecuteCallback:
        FnOnce(Request, &mut VirtualMachine, ExecutionHelperWrapper, &mut Felt252) -> SyscallResult<Response>,
{
    // Refund `SYSCALL_BASE_GAS_COST` as it was pre-charged.
    // TODO: Uncomment once we we know what to do
    // let required_gas = syscall_gas_cost - self.context.get_gas_cost("syscall_base_gas_cost");

    let SyscallRequestWrapper { gas_counter, request } = SyscallRequestWrapper::<Request>::read(vm, syscall_ptr)?;

    // TODO: Uncomment once we we know what to do
    // if gas_counter < required_gas {
    //     //  Out of gas failure.
    //     let out_of_gas_error =
    //         StarkFelt::try_from(OUT_OF_GAS_ERROR).map_err(SyscallExecutionError::from)?;
    //     let response: SyscallResponseWrapper<Response> =
    //         SyscallResponseWrapper::Failure { gas_counter, error_data: vec![out_of_gas_error] };
    //     response.write(vm, &mut self.syscall_ptr)?;
    //
    //     return Ok(());
    // }

    // Execute.
    // let mut remaining_gas = gas_counter - required_gas;
    let mut remaining_gas = gas_counter;
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
