use std::marker::PhantomData;

use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ff::PrimeField;
use blockifier::execution::syscalls::secp::{
    EcPointCoordinates, SecpAddRequest, SecpGetPointFromXRequest, SecpGetXyRequest, SecpHintProcessor, SecpMulRequest,
    SecpOpRespone, SecpOptionalEcPointResponse,
};
use cairo_vm::types::relocatable::Relocatable;
use cairo_vm::vm::errors::memory_errors::MemoryError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use num_bigint::BigUint;

use super::helper::ExecutionHelperWrapper;
use super::syscall_handler_utils::{
    felt_from_ptr, write_maybe_relocatable, SyscallHandler, SyscallResult, WriteResponseResult,
};
use crate::execution::helper::ExecutionHelper;
use crate::execution::syscall_handler_utils::{write_felt, SyscallExecutionError};
use crate::starknet::starknet_storage::PerContractStorage;

/// This trait is private and not callable outside this module.
trait GetSecpSyscallHandler<C: SWCurveConfig> {
    fn get_secp_handler(&mut self) -> &mut SecpHintProcessor<C>;
}

impl<PCS> GetSecpSyscallHandler<ark_secp256k1::Config> for ExecutionHelper<PCS>
where
    PCS: PerContractStorage,
{
    fn get_secp_handler(&mut self) -> &mut SecpHintProcessor<ark_secp256k1::Config> {
        &mut self.secp256k1_syscall_processor
    }
}

impl<PCS> GetSecpSyscallHandler<ark_secp256r1::Config> for ExecutionHelper<PCS>
where
    PCS: PerContractStorage,
{
    fn get_secp_handler(&mut self) -> &mut SecpHintProcessor<ark_secp256r1::Config> {
        &mut self.secp256r1_syscall_processor
    }
}

fn pack(low: Felt252, high: Felt252) -> BigUint {
    (high.to_biguint() << 128) + low.to_biguint()
}

pub struct SecpNewHandler<C> {
    _c: PhantomData<C>,
}
impl<C: SWCurveConfig, PCS: PerContractStorage + 'static> SyscallHandler<PCS> for SecpNewHandler<C>
where
    C::BaseField: PrimeField,
    ExecutionHelper<PCS>: GetSecpSyscallHandler<C>,
{
    type Request = EcPointCoordinates;
    type Response = SecpOptionalEcPointResponse;

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
        exec_wrapper: &mut ExecutionHelperWrapper<PCS>,
        _remaining_gas: &mut u64,
    ) -> SyscallResult<Self::Response>
    where
        PCS: PerContractStorage,
    {
        let mut eh_ref = exec_wrapper.execution_helper.write().await;
        let secp_handler = <ExecutionHelper<PCS> as GetSecpSyscallHandler<C>>::get_secp_handler(&mut eh_ref);
        let res = secp_handler.secp_new(request)?;
        Ok(res)
    }
    fn write_response(response: Self::Response, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
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
pub struct SecpGetPointFromXHandler<C> {
    _c: PhantomData<C>,
}
impl<C: SWCurveConfig, PCS: PerContractStorage + 'static> SyscallHandler<PCS> for SecpGetPointFromXHandler<C>
where
    C::BaseField: PrimeField,
    ExecutionHelper<PCS>: GetSecpSyscallHandler<C>,
{
    type Request = SecpGetPointFromXRequest;

    type Response = SecpOptionalEcPointResponse;

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
        exec_wrapper: &mut ExecutionHelperWrapper<PCS>,
        _remaining_gas: &mut u64,
    ) -> SyscallResult<Self::Response> {
        let mut eh_ref = exec_wrapper.execution_helper.write().await;
        let secp_handler = <ExecutionHelper<PCS> as GetSecpSyscallHandler<C>>::get_secp_handler(&mut eh_ref);
        let res = secp_handler.secp_get_point_from_x(request)?;
        Ok(res)
    }

    fn write_response(response: Self::Response, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
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

impl<C: SWCurveConfig, PCS: PerContractStorage + 'static> SyscallHandler<PCS> for SecpMulHandler<C>
where
    C::BaseField: PrimeField,
    ExecutionHelper<PCS>: GetSecpSyscallHandler<C>,
{
    type Request = SecpMulRequest;

    type Response = SecpOpRespone;

    fn read_request(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Self::Request> {
        let ec_point_id = felt_from_ptr(vm, ptr)?.to_biguint().into();
        let scalar = {
            let low = felt_from_ptr(vm, ptr)?;
            let high = felt_from_ptr(vm, ptr)?;
            (low, high)
        };
        Ok(SecpMulRequest { ec_point_id, multiplier: pack(scalar.0, scalar.1) })
    }

    async fn execute(
        request: Self::Request,
        _vm: &mut VirtualMachine,
        exec_wrapper: &mut ExecutionHelperWrapper<PCS>,
        _remaining_gas: &mut u64,
    ) -> SyscallResult<Self::Response>
    where
        PCS: PerContractStorage,
    {
        let mut eh_ref = exec_wrapper.execution_helper.write().await;
        let secp_handler = <ExecutionHelper<PCS> as GetSecpSyscallHandler<C>>::get_secp_handler(&mut eh_ref);
        let res = secp_handler.secp_mul(request)?;
        Ok(res)
    }

    fn write_response(response: Self::Response, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_maybe_relocatable(vm, ptr, response.ec_point_id)?;
        Ok(())
    }
}

pub struct SecpAddHandler<C> {
    _c: PhantomData<C>,
}

impl<C: SWCurveConfig, PCS: PerContractStorage + 'static> SyscallHandler<PCS> for SecpAddHandler<C>
where
    C::BaseField: PrimeField,
    ExecutionHelper<PCS>: GetSecpSyscallHandler<C>,
{
    type Request = SecpAddRequest;

    type Response = SecpOpRespone;

    fn read_request(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Self::Request> {
        Ok(SecpAddRequest {
            lhs_id: felt_from_ptr(vm, ptr)?.to_biguint().into(),
            rhs_id: felt_from_ptr(vm, ptr)?.to_biguint().into(),
        })
    }

    async fn execute(
        request: Self::Request,
        _vm: &mut VirtualMachine,
        exec_wrapper: &mut ExecutionHelperWrapper<PCS>,
        _remaining_gas: &mut u64,
    ) -> SyscallResult<Self::Response>
    where
        PCS: PerContractStorage,
    {
        let mut eh_ref = exec_wrapper.execution_helper.write().await;
        let secp_handler = <ExecutionHelper<PCS> as GetSecpSyscallHandler<C>>::get_secp_handler(&mut eh_ref);
        let res = secp_handler.secp_add(request)?;

        Ok(res)
    }

    fn write_response(response: Self::Response, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        write_maybe_relocatable(vm, ptr, response.ec_point_id)?;
        Ok(())
    }
}

pub struct SecpGetXyHandler<C> {
    _c: PhantomData<C>,
}

impl<C: SWCurveConfig, PCS: PerContractStorage + 'static> SyscallHandler<PCS> for SecpGetXyHandler<C>
where
    C::BaseField: PrimeField,
    ExecutionHelper<PCS>: GetSecpSyscallHandler<C>,
{
    type Request = SecpGetXyRequest;
    type Response = EcPointCoordinates;

    fn read_request(vm: &VirtualMachine, ptr: &mut Relocatable) -> SyscallResult<Self::Request> {
        Ok(SecpGetXyRequest { ec_point_id: felt_from_ptr(vm, ptr).map(|c| c.to_biguint().into())? })
    }
    async fn execute(
        request: Self::Request,
        _vm: &mut VirtualMachine,
        exec_wrapper: &mut ExecutionHelperWrapper<PCS>,
        _remaining_gas: &mut u64,
    ) -> SyscallResult<Self::Response>
    where
        PCS: PerContractStorage,
    {
        let mut eh_ref = exec_wrapper.execution_helper.write().await;
        let secp_handler = <ExecutionHelper<PCS> as GetSecpSyscallHandler<C>>::get_secp_handler(&mut eh_ref);
        let res = secp_handler.secp_get_xy(request)?;
        Ok(res)
    }
    fn write_response(response: Self::Response, vm: &mut VirtualMachine, ptr: &mut Relocatable) -> WriteResponseResult {
        pub fn write_u256(vm: &mut VirtualMachine, ptr: &mut Relocatable, value: BigUint) -> Result<(), MemoryError> {
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
    use blockifier::execution::syscalls::SyscallResult;
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

    /// A helper enum since rstest doesn't play well with generics
    /// Prevents duplication of tests
    pub enum SecpTestProcessor {
        Secp256k1(SecpHintProcessor<ark_secp256k1::Config>),
        Secp256r1(SecpHintProcessor<ark_secp256r1::Config>),
    }

    fn create_point(x: BigUint, y: BigUint) -> EcPointCoordinates {
        EcPointCoordinates { x, y }
    }

    impl SecpTestProcessor {
        pub fn new_secp256k1() -> Self {
            SecpTestProcessor::Secp256k1(Default::default())
        }

        pub fn new_secp256r1() -> Self {
            SecpTestProcessor::Secp256r1(Default::default())
        }

        pub fn secp_add(&mut self, request: SecpAddRequest) -> SyscallResult<SecpOpRespone> {
            match self {
                SecpTestProcessor::Secp256k1(inner) => inner.secp_add(request),
                SecpTestProcessor::Secp256r1(inner) => inner.secp_add(request),
            }
        }

        pub fn secp_mul(&mut self, request: SecpMulRequest) -> SyscallResult<SecpOpRespone> {
            match self {
                SecpTestProcessor::Secp256k1(inner) => inner.secp_mul(request),
                SecpTestProcessor::Secp256r1(inner) => inner.secp_mul(request),
            }
        }

        pub fn secp_get_point_from_x(
            &mut self,
            request: SecpGetPointFromXRequest,
        ) -> SyscallResult<SecpOptionalEcPointResponse> {
            match self {
                SecpTestProcessor::Secp256k1(inner) => inner.secp_get_point_from_x(request),
                SecpTestProcessor::Secp256r1(inner) => inner.secp_get_point_from_x(request),
            }
        }

        pub fn secp_get_xy(&mut self, request: SecpGetXyRequest) -> SyscallResult<EcPointCoordinates> {
            match self {
                SecpTestProcessor::Secp256k1(inner) => inner.secp_get_xy(request),
                SecpTestProcessor::Secp256r1(inner) => inner.secp_get_xy(request),
            }
        }

        pub fn secp_new(&mut self, request: EcPointCoordinates) -> SyscallResult<SecpOptionalEcPointResponse> {
            match self {
                SecpTestProcessor::Secp256k1(inner) => inner.secp_new(request),
                SecpTestProcessor::Secp256r1(inner) => inner.secp_new(request),
            }
        }

        fn new_point(&mut self, ec_point: (BigUint, BigUint)) -> usize {
            match self {
                SecpTestProcessor::Secp256k1(inner) => {
                    inner.secp_new(create_point(ec_point.0, ec_point.1)).unwrap().optional_ec_point_id.unwrap()
                }
                SecpTestProcessor::Secp256r1(inner) => {
                    inner.secp_new(create_point(ec_point.0, ec_point.1)).unwrap().optional_ec_point_id.unwrap()
                }
            }
        }
    }

    #[rstest]
    #[case::secp256k1(SecpTestProcessor::new_secp256k1(), parse_hex(K1_X_POINT), parse_hex(K1_Y_POINT))]
    #[case::secp256r1(SecpTestProcessor::new_secp256r1(), parse_hex(R1_X_POINT), parse_hex(R1_Y_POINT))]
    fn test_secp_add(#[case] mut processor: SecpTestProcessor, #[case] x: BigUint, #[case] y: BigUint) {
        let lhs_id = processor.new_point((x.clone(), y.clone())).into();
        let rhs_id = processor.new_point((x, y)).into();
        let request = SecpAddRequest { lhs_id, rhs_id };
        let response = processor.secp_add(request).unwrap();
        assert_eq!(response.ec_point_id, 2);
    }

    #[rstest]
    #[case::secp256k1(SecpTestProcessor::new_secp256k1(), parse_hex(K1_X_POINT), parse_hex(K1_Y_POINT))]
    #[case::secp256r1(SecpTestProcessor::new_secp256r1(), parse_hex(R1_X_POINT), parse_hex(R1_Y_POINT))]
    fn test_secp_mul(#[case] mut processor: SecpTestProcessor, #[case] x: BigUint, #[case] y: BigUint) {
        let ec_point_id = processor.new_point((x, y)).into();
        let request = SecpMulRequest { ec_point_id, multiplier: BigUint::from_u32(3).unwrap() };
        let response = processor.secp_mul(request).unwrap();
        assert_eq!(response.ec_point_id, 1);
        let res = processor.secp_get_xy(SecpGetXyRequest { ec_point_id: response.ec_point_id.into() });
        assert!(res.is_ok())
    }

    #[rstest]
    #[case::secp256k1(SecpTestProcessor::new_secp256k1(), parse_hex(K1_X_POINT))]
    #[case::secp256r1(SecpTestProcessor::new_secp256r1(), parse_hex(R1_X_POINT))]
    fn test_secp_get_point_from_x(#[case] mut processor: SecpTestProcessor, #[case] x: BigUint) {
        let request = SecpGetPointFromXRequest { x, y_parity: true };
        let response = processor.secp_get_point_from_x(request).unwrap();
        let res =
            processor.secp_get_xy(SecpGetXyRequest { ec_point_id: response.optional_ec_point_id.unwrap().into() });
        assert!(res.is_ok())
    }

    #[rstest]
    #[case::secp256k1(SecpTestProcessor::new_secp256k1(), parse_hex(K1_X_POINT), parse_hex(K1_Y_POINT))]
    #[case::secp256r1(SecpTestProcessor::new_secp256r1(), parse_hex(R1_X_POINT), parse_hex(R1_Y_POINT))]
    fn test_secp_get_xy(#[case] mut processor: SecpTestProcessor, #[case] x: BigUint, #[case] y: BigUint) {
        let request = EcPointCoordinates { x: x.clone(), y: y.clone() };
        let ec_point_id = processor.secp_new(request).unwrap().optional_ec_point_id.unwrap().into();
        let request = SecpGetXyRequest { ec_point_id };
        let response: EcPointCoordinates = processor.secp_get_xy(request).unwrap();
        assert_eq!(response.x, x);
        assert_eq!(response.y, y);
    }

    #[rstest]
    #[case::secp256k1(SecpTestProcessor::new_secp256k1())]
    #[case::secp256r1(SecpTestProcessor::new_secp256r1())]
    fn test_secp_new(#[case] mut processor: SecpTestProcessor) {
        let request = EcPointCoordinates { x: BigUint::ZERO, y: BigUint::one() };
        let response = processor.secp_new(request).unwrap();
        assert!(response.optional_ec_point_id.is_none());
    }

    #[rstest]
    #[case::secp256k1(SecpTestProcessor::new_secp256k1())]
    #[case::secp256r1(SecpTestProcessor::new_secp256r1())]
    fn test_invalid_secp_new(#[case] mut processor: SecpTestProcessor) {
        let hex_str = "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
        let request = EcPointCoordinates { x: parse_hex(hex_str), y: BigUint::one() };
        let response = processor.secp_new(request);
        assert!(response.is_err());
    }
}
