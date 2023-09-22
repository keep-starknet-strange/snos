use cairo_felt::{FIELD_HIGH, FIELD_LOW};

use crate::storage::HASH_BYTES;

// TODO: Use ruint or types-rs field type

pub const STARKNET_LANG_DIRECTIVE: &str = "starknet";

// TODO: add real value
pub const FIELD_SIZE: u128 = 123456;

pub const FIELD_SIZE_BITS: usize = 251;
pub const ADDRESS_BITS: usize = FIELD_SIZE_BITS;
pub const CONTRACT_ADDRESS_BITS: usize = ADDRESS_BITS;
pub const NONCE_BITS: usize = FIELD_SIZE_BITS;

pub const FELT_LOWER_BOUND: u128 = FIELD_LOW;
pub const FELT_UPPER_BOUND: u128 = FIELD_HIGH;
pub const BLOCK_HASH_LOWER_BOUND: u128 = 0;
pub const BLOCK_HASH_UPPER_BOUND: u128 = FIELD_SIZE;

// Address 0 is reserved to distinguish an external transaction from an inner (L2<>L2) one.
pub const L2_ADDRESS_LOWER_BOUND: u128 = 1;
// The address upper bound is defined to be congruent with the storage var address upper bound (see
// storage.cairo).
pub const L2_ADDRESS_UPPER_BOUND: u128 = (2u8.pow(CONTRACT_ADDRESS_BITS as u32) - 256u8) as u128;

pub const CLASS_HASH_BYTES: [u8; 4] = HASH_BYTES;
pub const CLASS_HASH_UPPER_BOUND: u128 = FIELD_SIZE;

pub const CONTRACT_STATES_COMMITMENT_TREE_HEIGHT: usize = FIELD_SIZE_BITS;
pub const COMPILED_CLASS_HASH_UPPER_BOUND: usize = FIELD_SIZE_BITS;
pub const COMPILED_CLASS_HASH_COMMITMENT_TREE_HEIGHT: usize = FIELD_SIZE_BITS;

pub const ENTRY_POINT_FUNCTION_IDX_LOWER_BOUND: u128 = 0;
pub const ENTRY_POINT_FUNCTION_IDX_UPPER_BOUND: u128 = FIELD_SIZE;
pub const ENTRY_POINT_OFFSET_LOWER_BOUND: u128 = 0;
pub const ENTRY_POINT_OFFSET_UPPER_BOUND: u128 = FIELD_SIZE;
pub const ENTRY_POINT_SELECTOR_LOWER_BOUND: u128 = 0;
pub const ENTRY_POINT_SELECTOR_UPPER_BOUND: u128 = FIELD_SIZE;

pub const EVENT_COMMITMENT_TREE_HEIGHT: usize = 64;
pub const FEE_LOWER_BOUND: u128 = 0;
pub const FEE_UPPER_BOUND: u128 = 2u8.pow(128) as u128;

// Default hash to fill the parent_hash field of the first block in the sequence.
pub const GENESIS_PARENT_BLOCK_HASH: u128 = 0;
pub const GAS_PRICE_LOWER_BOUND: u128 = 0;
pub const GAS_PRICE_UPPER_BOUND: u128 = 2u8.pow(128) as u128;

pub const MAX_MESSAGE_TO_L1_LENGTH: usize = 100;
pub const NONCE_LOWER_BOUND: u128 = 0;
pub const NONCE_UPPER_BOUND: u128 = 2u8.pow(NONCE_BITS as u32) as u128;

pub const SIERRA_ARRAY_LEN_BOUND: usize = 2usize.pow(32);
pub const SYSCALL_SELECTOR_UPPER_BOUND: u128 = FIELD_SIZE;

pub const TRANSACTION_COMMITMENT_TREE_HEIGHT: usize = 64;
pub const TRANSACTION_HASH_LOWER_BOUND: u128 = 0;
pub const TRANSACTION_HASH_UPPER_BOUND: u128 = FIELD_SIZE;
pub const TRANSACTION_VERSION_LOWER_BOUND: u128 = 0;
pub const TRANSACTION_VERSION_UPPER_BOUND: u128 = FIELD_SIZE;

pub const ADDRESS_LOWER_BOUND: u128 = 0;
pub const ADDRESS_UPPER_BOUND: u128 = 2u8.pow(ADDRESS_BITS as u32) as u128;

pub const UNINITIALIZED_CLASS_HASH: [u8; 4] = HASH_BYTES;

// In order to identify transactions from unsupported versions.
pub const TRANSACTION_VERSION: u8 = 1;
// The version is considered 0 for L1-Handler transaction hash calculation purposes.
pub const L1_HANDLER_VERSION: u8 = 0;
// Indentation for transactions meant to query and not addressed to the OS.
pub const DECLARE_VERSION: u8 = 2;
pub const QUERY_VERSION_BASE: u128 = 2u8.pow(128) as u128;
pub const QUERY_VERSION: u128 = QUERY_VERSION_BASE + TRANSACTION_VERSION as u128;
pub const QUERY_DECLARE_VERSION: u128 = QUERY_VERSION_BASE + DECLARE_VERSION as u128;
pub const DEPRECATED_DECLARE_VERSIONS: [u128; 4] =
    [0, 1, QUERY_VERSION_BASE, QUERY_VERSION_BASE + 1];

// Sierra -> Casm compilation version.
pub const SIERRA_VERSION: [u8; 3] = [1, 3, 0];
// Contract classes with sierra version older than MIN_SIERRA_VERSION are not supported.
pub const MIN_SIERRA_VERSION: [u8; 3] = [1, 1, 0];

// The version of contract class leaf.
pub const CONTRACT_CLASS_LEAF_VERSION: &[u8] = b"CONTRACT_CLASS_LEAF_V0";

// The version of the Starknet global state.
pub const GLOBAL_STATE_VERSION: &[u8] = b"STARKNET_STATE_V0";

// The version of a compiled class.
pub const COMPILED_CLASS_VERSION: &[u8] = b"COMPILED_CLASS_V1";

// State diff commitment.
pub const BLOCK_SIGNATURE_VERSION: u8 = 0;

// OS-related constants.
pub const L1_TO_L2_MSG_HEADER_SIZE: usize = 5;
pub const L2_TO_L1_MSG_HEADER_SIZE: usize = 3;
pub const CLASS_UPDATE_SIZE: usize = 1;

// OS reserved contract addresses.
pub const ORIGIN_ADDRESS: u128 = 0;
pub const BLOCK_HASH_CONTRACT_ADDRESS: u128 = 1;
pub const OS_RESERVED_CONTRACT_ADDRESSES: [u128; 2] = [ORIGIN_ADDRESS, BLOCK_HASH_CONTRACT_ADDRESS];

// StarkNet solidity contract-related constants.
pub const N_DEFAULT_TOPICS: usize = 1; // Events have one default topic.
                                       // Excluding the default topic.
pub const LOG_MSG_TO_L1_N_TOPICS: usize = 2;
pub const CONSUMED_MSG_TO_L2_N_TOPICS: usize = 3;
// The headers include the payload size, so we need to add +1 since arrays are encoded with two
// additional parameters (offset and length) in solidity.
pub const LOG_MSG_TO_L1_ENCODED_DATA_SIZE: usize =
    (L2_TO_L1_MSG_HEADER_SIZE + 1) - LOG_MSG_TO_L1_N_TOPICS;
pub const CONSUMED_MSG_TO_L2_ENCODED_DATA_SIZE: usize =
    (L1_TO_L2_MSG_HEADER_SIZE + 1) - CONSUMED_MSG_TO_L2_N_TOPICS;

// The (empirical) L1 gas cost of each Cairo step.
pub const N_STEPS_FEE_WEIGHT: f64 = 0.01;

// Expected return values of a 'validate' entry point.
pub const VALIDATE_RETDATA: &[u8] = b"VALID";

// The block number -> block hash mapping is written for the current block number minus this number.
pub const STORED_BLOCK_HASH_BUFFER: u8 = 10;

pub enum OsOutputConstant {
    MerkleUpdateOffset = 0,
    BlockNumberOffset = 2,
    BlockHashOffset = 3,
    ConfigHashOffset = 4,
    HeaderSize = 5,
}

const STEP: u128 = 100;
const RANGE_CHECK: u128 = 70;
const INITIAL: u128 = 10u128.pow(8) * STEP;
const SYSCALL_BASE: u128 = 100 * STEP;
const ENTRY_POINT_INITIAL_BUDGET: u128 = 100 * STEP;
const ENTRY_POINT: u128 = ENTRY_POINT_INITIAL_BUDGET + 500 * STEP;
const FEE_TRANSFER: u128 = ENTRY_POINT + 100 * STEP;
const TRANSACTION: u128 = (2 * ENTRY_POINT_INITIAL_BUDGET) + FEE_TRANSFER + (100 * STEP);
const CALL_CONTRACT: u128 = SYSCALL_BASE + 10 * STEP + ENTRY_POINT;
const DEPLOY: u128 = SYSCALL_BASE + 200 * STEP + ENTRY_POINT;
const GET_BLOCK_HASH: u128 = SYSCALL_BASE + 50 * STEP;
const GET_EXECUTION_INFO: u128 = SYSCALL_BASE + 10 * STEP;
const SECP256K1_ADD: u128 = SYSCALL_BASE + 254 * STEP + 29 * RANGE_CHECK;
const SECP256K1_GET_POINT_FROM_X: u128 = SYSCALL_BASE + 260 * STEP + 30 * RANGE_CHECK;
const SECP256K1_GET_XY: u128 = SYSCALL_BASE + 24 * STEP + 9 * RANGE_CHECK;
const SECP256K1_MUL: u128 = SYSCALL_BASE + 121810 * STEP + 10739 * RANGE_CHECK;
const SECP256K1_NEW: u128 = SYSCALL_BASE + 340 * STEP + 36 * RANGE_CHECK;
const KECCAK: u128 = SYSCALL_BASE;
const KECCAK_ROUND_COST: u128 = 180000;
const LIBRARY_CALL: u128 = CALL_CONTRACT;
const REPLACE_CLASS: u128 = SYSCALL_BASE + 50 * STEP;
const STORAGE_READ: u128 = SYSCALL_BASE + 50 * STEP;
const STORAGE_WRITE: u128 = SYSCALL_BASE + 50 * STEP;
const EMIT_EVENT: u128 = SYSCALL_BASE + 10 * STEP;
const SEND_MESSAGE_TO_L1: u128 = SYSCALL_BASE + 50 * STEP;

pub struct GasCost {
    pub step: u128,
    pub range_check: u128,
    pub initial: u128,
    pub syscall_base: u128,
    pub entry_point_initial_budget: u128,
    pub entry_point: u128,
    pub fee_transfer: u128,
    pub transaction: u128,
    pub call_contract: u128,
    pub deploy: u128,
    pub get_block_hash: u128,
    pub get_execution_info: u128,
    pub secp256k1_add: u128,
    pub secp256k1_get_point_from_x: u128,
    pub secp256k1_get_xy: u128,
    pub secp256k1_mul: u128,
    pub secp256k1_new: u128,
    pub keccak: u128,
    pub keccak_round_cost: u128,
    pub library_call: u128,
    pub replace_class: u128,
    pub storage_read: u128,
    pub storage_write: u128,
    pub emit_event: u128,
    pub send_message_to_l1: u128,
    pub n_steps_fee_weight: f64,
}

impl GasCost {
    pub fn new() -> Self {
        Self {
            step: STEP,
            range_check: RANGE_CHECK,
            initial: INITIAL,
            syscall_base: SYSCALL_BASE,
            entry_point_initial_budget: ENTRY_POINT_INITIAL_BUDGET,
            entry_point: ENTRY_POINT,
            fee_transfer: FEE_TRANSFER,
            transaction: TRANSACTION,
            call_contract: CALL_CONTRACT,
            deploy: DEPLOY,
            get_block_hash: GET_BLOCK_HASH,
            get_execution_info: GET_EXECUTION_INFO,
            secp256k1_add: SECP256K1_ADD,
            secp256k1_get_point_from_x: SECP256K1_GET_POINT_FROM_X,
            secp256k1_get_xy: SECP256K1_GET_XY,
            secp256k1_mul: SECP256K1_MUL,
            secp256k1_new: SECP256K1_NEW,
            keccak: KECCAK,
            keccak_round_cost: KECCAK_ROUND_COST,
            library_call: LIBRARY_CALL,
            replace_class: REPLACE_CLASS,
            storage_read: STORAGE_READ,
            storage_write: STORAGE_WRITE,
            emit_event: EMIT_EVENT,
            send_message_to_l1: SEND_MESSAGE_TO_L1,
            n_steps_fee_weight: N_STEPS_FEE_WEIGHT,
        }
    }
}

impl Default for GasCost {
    fn default() -> Self {
        Self::new()
    }
}
