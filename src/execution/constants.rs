// Gas Cost.
// See documentation in core/os/constants.cairo.
pub const BLOCK_HASH_CONTRACT_ADDRESS: u64 = 1;

#[allow(unused)]
pub const STEP_GAS_COST: u64 = 100;
#[allow(unused)]
pub const RANGE_CHECK_GAS_COST: u64 = 70;

#[allow(unused)]
pub const MEMORY_HOLE_GAS_COST: u64 = 10;

// An estimation of the initial gas for a transaction to run with. This solution is temporary and
// this value will become a field of the transaction.
#[allow(unused)]
pub const INITIAL_GAS_COST: u64 = 10_u64.pow(8) * STEP_GAS_COST;
// Compiler gas costs.
#[allow(unused)]
pub const ENTRY_POINT_INITIAL_BUDGET: u64 = 100 * STEP_GAS_COST;
// The initial gas budget for a system call (this value is hard-coded by the compiler).
// This needs to be high enough to cover OS costs in the case of failure due to out of gas.
#[allow(unused)]
pub const SYSCALL_BASE_GAS_COST: u64 = 100 * STEP_GAS_COST;
// OS gas costs.
#[allow(unused)]
pub const ENTRY_POINT_GAS_COST: u64 = blockifier::abi::constants::ENTRY_POINT_INITIAL_BUDGET + 500 * STEP_GAS_COST;
#[allow(unused)]
pub const FEE_TRANSFER_GAS_COST: u64 = ENTRY_POINT_GAS_COST + 100 * STEP_GAS_COST;
#[allow(unused)]
pub const TRANSACTION_GAS_COST: u64 =
    (2 * ENTRY_POINT_GAS_COST) + blockifier::abi::constants::FEE_TRANSFER_GAS_COST + (100 * STEP_GAS_COST);
// The required gas for each syscall.
#[allow(unused)]
pub const CALL_CONTRACT_GAS_COST: u64 = SYSCALL_BASE_GAS_COST + 10 * STEP_GAS_COST + ENTRY_POINT_GAS_COST;
#[allow(unused)]
pub const DEPLOY_GAS_COST: u64 = SYSCALL_BASE_GAS_COST + 200 * STEP_GAS_COST + ENTRY_POINT_GAS_COST;
#[allow(unused)]
pub const EMIT_EVENT_GAS_COST: u64 = SYSCALL_BASE_GAS_COST + 10 * STEP_GAS_COST;
#[allow(unused)]
pub const GET_BLOCK_HASH_GAS_COST: u64 = SYSCALL_BASE_GAS_COST + 50 * STEP_GAS_COST;
#[allow(unused)]
pub const GET_EXECUTION_INFO_GAS_COST: u64 = SYSCALL_BASE_GAS_COST + 10 * STEP_GAS_COST;
#[allow(unused)]
pub const KECCAK_GAS_COST: u64 = SYSCALL_BASE_GAS_COST;
#[allow(unused)]
pub const KECCAK_ROUND_COST_GAS_COST: u64 = 180000;
#[allow(unused)]
pub const LIBRARY_CALL_GAS_COST: u64 = CALL_CONTRACT_GAS_COST;
#[allow(unused)]
pub const REPLACE_CLASS_GAS_COST: u64 = SYSCALL_BASE_GAS_COST + 50 * STEP_GAS_COST;
#[allow(unused)]
pub const SECP256K1_ADD_GAS_COST: u64 = 406 * STEP_GAS_COST + 29 * RANGE_CHECK_GAS_COST;
#[allow(unused)]
pub const SECP256K1_GET_POINT_FROM_X_GAS_COST: u64 =
    391 * STEP_GAS_COST + 30 * RANGE_CHECK_GAS_COST + 20 * blockifier::abi::constants::MEMORY_HOLE_GAS_COST;
#[allow(unused)]
pub const SECP256K1_GET_XY_GAS_COST: u64 =
    239 * STEP_GAS_COST + 11 * RANGE_CHECK_GAS_COST + 40 * blockifier::abi::constants::MEMORY_HOLE_GAS_COST;
#[allow(unused)]
pub const SECP256K1_MUL_GAS_COST: u64 =
    76501 * STEP_GAS_COST + 7045 * RANGE_CHECK_GAS_COST + 2 * blockifier::abi::constants::MEMORY_HOLE_GAS_COST;
#[allow(unused)]
pub const SECP256K1_NEW_GAS_COST: u64 =
    475 * STEP_GAS_COST + 35 * RANGE_CHECK_GAS_COST + 40 * blockifier::abi::constants::MEMORY_HOLE_GAS_COST;
#[allow(unused)]
pub const SECP256R1_ADD_GAS_COST: u64 = 589 * STEP_GAS_COST + 57 * RANGE_CHECK_GAS_COST;
#[allow(unused)]
pub const SECP256R1_GET_POINT_FROM_X_GAS_COST: u64 =
    510 * STEP_GAS_COST + 44 * RANGE_CHECK_GAS_COST + 20 * blockifier::abi::constants::MEMORY_HOLE_GAS_COST;
#[allow(unused)]
pub const SECP256R1_GET_XY_GAS_COST: u64 =
    241 * STEP_GAS_COST + 11 * RANGE_CHECK_GAS_COST + 40 * blockifier::abi::constants::MEMORY_HOLE_GAS_COST;
#[allow(unused)]
pub const SECP256R1_MUL_GAS_COST: u64 =
    125340 * STEP_GAS_COST + 13961 * RANGE_CHECK_GAS_COST + 2 * blockifier::abi::constants::MEMORY_HOLE_GAS_COST;
#[allow(unused)]
pub const SECP256R1_NEW_GAS_COST: u64 =
    594 * STEP_GAS_COST + 49 * RANGE_CHECK_GAS_COST + 40 * blockifier::abi::constants::MEMORY_HOLE_GAS_COST;

#[allow(unused)]
pub const SEND_MESSAGE_TO_L1_GAS_COST: u64 = SYSCALL_BASE_GAS_COST + 50 * STEP_GAS_COST;
#[allow(unused)]
pub const STORAGE_READ_GAS_COST: u64 = SYSCALL_BASE_GAS_COST + 50 * STEP_GAS_COST;
#[allow(unused)]
pub const STORAGE_WRITE_GAS_COST: u64 = SYSCALL_BASE_GAS_COST + 50 * STEP_GAS_COST;
