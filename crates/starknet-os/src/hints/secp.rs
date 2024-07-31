use std::borrow::Cow;
use std::collections::HashMap;
use std::str::FromStr;

use ark_ff::Zero;
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_constant_from_var_name, get_integer_from_var_name, get_relocatable_from_var_name, insert_value_from_var_name,
    insert_value_into_ap,
};
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::math_utils::signed_felt;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::errors::math_errors::MathError;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::Relocatable;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use indoc::indoc;
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{Num, One};

use crate::cairo_types::syscalls::SecpNewResponse;
use crate::hints::Felt252;

pub const MAYBE_WRITE_ADDRESS_TO_AP: &str = indoc! {r#"
    memory[ap] = to_felt_or_relocatable(ids.response.ec_point.address_ if ids.not_on_curve == 0 else segments.add())"#
};
pub fn maybe_write_address_to_ap(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let not_on_curve = get_integer_from_var_name("not_on_curve", vm, ids_data, _ap_tracking)?;
    if not_on_curve == Felt252::ZERO {
        let response = get_relocatable_from_var_name("response", vm, ids_data, _ap_tracking)?;
        let ec_point = vm.get_relocatable((response + SecpNewResponse::ec_point_offset())?)?; //TODO: Use actual struct offset
        insert_value_into_ap(vm, ec_point)?;
    } else {
        let segment = vm.add_memory_segment();
        insert_value_into_ap(vm, segment)?;
    }
    Ok(())
}

// Copied from Cairovm
// TODO: make pub?
use num_bigint::BigUint;

use super::vars;

pub(crate) type BigInt3<'a> = BigIntN<'a, 3>;
pub(crate) type Uint384<'a> = BigIntN<'a, 3>;
pub(crate) type Uint512<'a> = BigIntN<'a, 4>;
pub(crate) type BigInt5<'a> = BigIntN<'a, 5>;
pub(crate) type Uint768<'a> = BigIntN<'a, 6>;

#[derive(Debug, PartialEq)]
pub(crate) struct BigIntN<'a, const NUM_LIMBS: usize> {
    pub(crate) limbs: [Cow<'a, Felt252>; NUM_LIMBS],
}

impl<const NUM_LIMBS: usize> BigIntN<'_, NUM_LIMBS> {
    pub(crate) fn from_base_addr<'a>(
        addr: Relocatable,
        name: &str,
        vm: &'a VirtualMachine,
    ) -> Result<BigIntN<'a, NUM_LIMBS>, HintError> {
        let mut limbs = vec![];
        for i in 0..NUM_LIMBS {
            limbs.push(
                vm.get_integer((addr + i)?)
                    .map_err(|_| HintError::IdentifierHasNoMember(Box::new((name.to_string(), format!("d{}", i)))))?,
            )
        }
        Ok(BigIntN { limbs: limbs.try_into().map_err(|_| HintError::FixedSizeArrayFail(NUM_LIMBS))? })
    }

    pub(crate) fn from_var_name<'a>(
        name: &str,
        vm: &'a VirtualMachine,
        ids_data: &HashMap<String, HintReference>,
        ap_tracking: &ApTracking,
    ) -> Result<BigIntN<'a, NUM_LIMBS>, HintError> {
        let base_addr = get_relocatable_from_var_name(name, vm, ids_data, ap_tracking)?;
        BigIntN::from_base_addr(base_addr, name, vm)
    }

    pub(crate) fn from_values(limbs: [Felt252; NUM_LIMBS]) -> Self {
        Self { limbs: limbs.map(Cow::Owned) }
    }

    pub(crate) fn insert_from_var_name(
        self,
        var_name: &str,
        vm: &mut VirtualMachine,
        ids_data: &HashMap<String, HintReference>,
        ap_tracking: &ApTracking,
    ) -> Result<(), HintError> {
        let addr = get_relocatable_from_var_name(var_name, vm, ids_data, ap_tracking)?;
        for i in 0..NUM_LIMBS {
            vm.insert_value((addr + i)?, *self.limbs[i].as_ref())?;
        }
        Ok(())
    }

    pub(crate) fn pack(self) -> BigUint {
        pack(self.limbs, 128)
    }

    pub(crate) fn pack86(self) -> BigInt {
        use std::ops::Shl;
        self.limbs.into_iter().take(3).enumerate().map(|(idx, value)| signed_felt(*value).shl(idx * 86)).sum()
    }

    pub(crate) fn split(num: &BigUint) -> Self {
        let limbs = split(num, 128);
        Self::from_values(limbs)
    }
}

impl<'a, const NUM_LIMBS: usize> From<&'a BigUint> for BigIntN<'a, NUM_LIMBS> {
    fn from(value: &'a BigUint) -> Self {
        Self::split(value)
    }
}

pub(crate) fn split<const N: usize>(num: &BigUint, num_bits_shift: u32) -> [Felt252; N] {
    use num_traits::One;
    let mut num = num.clone();
    let bitmask = &((BigUint::one() << num_bits_shift) - 1_u32);
    [0; N].map(|_| {
        let a = &num & bitmask;
        num >>= num_bits_shift;
        Felt252::from(&a)
    })
}

pub(crate) fn pack<const N: usize>(limbs: [impl AsRef<Felt252>; N], num_bits_shift: usize) -> BigUint {
    limbs.into_iter().enumerate().map(|(i, limb)| limb.as_ref().to_biguint() << (i * num_bits_shift)).sum()
}

pub const PACK_X_PRIME: &str = indoc! {r#"
    from starkware.cairo.common.cairo_secp.secp256r1_utils import SECP256R1_P
    from starkware.cairo.common.cairo_secp.secp_utils import pack
    value = pack(ids.x, PRIME) % SECP256R1_P"#
};
pub fn pack_x_prime(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let SECP256R1_P: BigInt =
        BigInt::from_str("115792089210356248762697446949407573530086143415290314195533631308867097853951").unwrap();
    let x = BigInt3::from_var_name("x", vm, ids_data, ap_tracking)?.pack86();
    exec_scopes.insert_value("value", x.mod_floor(&SECP256R1_P));
    Ok(())
}

pub const COMPUTE_Q_MOD_PRIME: &str = indoc! {r#"
    from starkware.cairo.common.cairo_secp.secp256r1_utils import SECP256R1_P
    from starkware.cairo.common.cairo_secp.secp_utils import pack

    q, r = divmod(pack(ids.val, PRIME), SECP256R1_P)
    assert r == 0, f"verify_zero: Invalid input {ids.val.d0, ids.val.d1, ids.val.d2}."
    ids.q = q % PRIME"#
};
pub fn compute_q_mod_prime(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let SECP256R1_P: BigInt =
        BigInt::from_str("115792089210356248762697446949407573530086143415290314195533631308867097853951").unwrap();
    let val = BigInt3::from_var_name("val", vm, ids_data, ap_tracking)?.pack86();
    let (q, r) = val.div_rem(&SECP256R1_P);
    if !r.is_zero() {
        return Err(HintError::SecpVerifyZero(Box::new(val)));
    }
    insert_value_from_var_name("q", Felt252::from(&q), vm, ids_data, ap_tracking)?;
    Ok(())
}

pub const COMPUTE_IDS_HIGH_LOW: &str = indoc! {r#"
        from starkware.cairo.common.math_utils import as_int

        # Correctness check.
        value = as_int(ids.value, PRIME) % PRIME
        assert value < ids.UPPER_BOUND, f'{value} is outside of the range [0, 2**165).'

        # Calculation for the assertion.
        ids.high, ids.low = divmod(ids.value, ids.SHIFT)"#
};
pub fn compute_ids_high_low(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    const UPPER_BOUND: &str = "starkware.cairo.common.math.assert_250_bit.UPPER_BOUND";
    let upper_bound =
        constants.get(UPPER_BOUND).map_or_else(|| get_constant_from_var_name("UPPER_BOUND", constants), Ok)?;
    let value = Felt252::from(&signed_felt(get_integer_from_var_name("value", vm, ids_data, ap_tracking)?));
    if &value > upper_bound {
        return Err(HintError::ValueOutside250BitRange(Box::new(value)));
    }
    const SHIFT: &str = "starkware.cairo.common.math.assert_250_bit.SHIFT";
    let shift = constants.get(SHIFT).map_or_else(|| get_constant_from_var_name("SHIFT", constants), Ok)?;
    let (high, low) = value.div_rem(&shift.try_into().map_err(|_| MathError::DividedByZero)?);
    insert_value_from_var_name("high", high, vm, ids_data, ap_tracking)?;
    insert_value_from_var_name("low", low, vm, ids_data, ap_tracking)?;
    Ok(())
}

pub const CALCULATE_VALUE: &str = indoc! {r#"
    from starkware.cairo.common.cairo_secp.secp_utils import SECP256R1, pack
    from starkware.python.math_utils import y_squared_from_x

    y_square_int = y_squared_from_x(
        x=pack(ids.x, SECP256R1.prime),
        alpha=SECP256R1.alpha,
        beta=SECP256R1.beta,
        field_prime=SECP256R1.prime,
    )

    # Note that (y_square_int ** ((SECP256R1.prime + 1) / 4)) ** 2 =
    #   = y_square_int ** ((SECP256R1.prime + 1) / 2) =
    #   = y_square_int ** ((SECP256R1.prime - 1) / 2 + 1) =
    #   = y_square_int * y_square_int ** ((SECP256R1.prime - 1) / 2) = y_square_int * {+/-}1.
    y = pow(y_square_int, (SECP256R1.prime + 1) // 4, SECP256R1.prime)

    # We need to decide whether to take y or prime - y.
    if ids.v % 2 == y % 2:
        value = y
    else:
        value = (-y) % SECP256R1.prime"#
};

pub fn calculate_value(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let SECP256R1_P: BigInt =
        BigInt::from_str("115792089210356248762697446949407573530086143415290314195533631308867097853951").unwrap();
    fn get_y_squared_from_x(x: &BigInt) -> BigInt {
        let SECP256R1_P: BigInt =
            BigInt::from_str("115792089210356248762697446949407573530086143415290314195533631308867097853951").unwrap();
        let SECP256R1_ALPHA: BigInt =
            BigInt::from_str("115792089210356248762697446949407573530086143415290314195533631308867097853948").unwrap();
        let SECP256R1_B: BigInt =
            BigInt::from_str_radix("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16).unwrap();
        (x.modpow(&BigInt::from(3), &SECP256R1_P) + SECP256R1_ALPHA * x + SECP256R1_B).mod_floor(&SECP256R1_P)
    }

    let x = pack_from_var_name("x", ids_data, vm, ap_tracking, &SECP256R1_P)?;

    let y_square_int = get_y_squared_from_x(&x);
    exec_scopes.insert_value::<BigInt>("y_square_int", y_square_int.clone());

    // Calculate (prime + 1) // 4
    let exp = (&SECP256R1_P + BigInt::one()).div_floor(&BigInt::from(4));
    // Calculate pow(y_square_int, exp, prime)
    let y = y_square_int.modpow(&exp, &SECP256R1_P);
    exec_scopes.insert_value::<BigInt>("y", y.clone());

    let v = get_integer_from_var_name("v", vm, ids_data, ap_tracking)?;
    let v = BigInt::from(v.to_biguint());
    if v % 2 == y.clone() % 2 {
        exec_scopes.insert_value("value", y);
    } else {
        let value = (-y).mod_floor(&SECP256R1_P);
        exec_scopes.insert_value("value", value);
    }
    Ok(())
}

pub const IS_ON_CURVE_2: &str = indoc! {
    r#"ids.is_on_curve = (y * y) % SECP256R1.prime == y_square_int"#
};

pub fn is_on_curve_2(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let y: BigInt = exec_scopes.get(vars::ids::Y)?;
    let y_square_int: BigInt = exec_scopes.get(vars::ids::Y_SQUARE_INT)?;
    let SECP256R1_P: BigInt =
        BigInt::from_str("115792089210356248762697446949407573530086143415290314195533631308867097853951").unwrap();

    let is_on_curve = (y.pow(2)) % SECP256R1_P == y_square_int;
    insert_value_from_var_name(vars::ids::IS_ON_CURVE, Felt252::from(is_on_curve), vm, ids_data, ap_tracking)?;

    Ok(())
}

fn pack_b(d0: &BigInt, d1: &BigInt, d2: &BigInt, prime: &BigInt) -> BigInt {
    let unreduced_big_int_3 = vec![d0, d1, d2];

    unreduced_big_int_3.iter().enumerate().map(|(idx, value)| as_int(value, prime) << (idx * 86)).sum()
}

/// Returns the lift of the given field element, val, as an integer in the range (-prime/2,
/// prime/2).
fn as_int(val: &BigInt, prime: &BigInt) -> BigInt {
    use std::ops::Shr;
    // n.shr(1) = n.div_floor(2)
    if *val < prime.shr(1) { val.clone() } else { val - prime }
}

fn pack_from_var_name(
    name: &str,
    ids: &HashMap<String, HintReference>,
    vm: &VirtualMachine,
    hint_ap_tracking: &ApTracking,
    prime: &BigInt,
) -> Result<BigInt, HintError> {
    let to_pack = get_relocatable_from_var_name(name, vm, ids, hint_ap_tracking)?;

    let d0 = vm.get_integer(to_pack)?;
    let d1 = vm.get_integer((to_pack + 1)?)?;
    let d2 = vm.get_integer((to_pack + 2)?)?;

    Ok(pack_b(&d0.to_bigint(), &d1.to_bigint(), &d2.to_bigint(), prime))
}
