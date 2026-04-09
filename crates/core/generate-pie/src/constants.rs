use starknet_api::core::{ContractAddress, PatriciaKey, BLOCK_HASH_TABLE_ADDRESS};
use starknet_types_core::felt::Felt;

/// Threshold for warning when CairoPIE execution steps exceed this value.
pub const MAX_EXECUTION_STEPS_WARNING_THRESHOLD: usize = 50_000_000;

/// Default Sepolia STRK fee token address.
pub const DEFAULT_SEPOLIA_STRK_FEE_TOKEN: &str = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";

/// Default Sepolia ETH fee token address.
pub const DEFAULT_SEPOLIA_ETH_FEE_TOKEN: &str = "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7";

pub const STORED_BLOCK_HASH_BUFFER: u64 = 10;
pub const STATEFUL_MAPPING_START: Felt = Felt::from_hex_unchecked("0x80"); // 128

/// System contract that stores historical block hashes.
pub const BLOCK_HASH_CONTRACT_ADDRESS: ContractAddress = BLOCK_HASH_TABLE_ADDRESS;

/// System alias contract used by stateful storage/class mapping.
pub const ALIAS_CONTRACT_ADDRESS: ContractAddress = ContractAddress(PatriciaKey::TWO);

/// Special system contracts that need dedicated handling during block processing.
pub const SPECIAL_CONTRACT_ADDRESSES: [ContractAddress; 2] = [BLOCK_HASH_CONTRACT_ADDRESS, ALIAS_CONTRACT_ADDRESS];

/// Felt representation of the block-hash contract address.
pub const BLOCK_HASH_CONTRACT_ADDRESS_FELT: Felt = Felt::ONE;

/// Felt representation of the alias contract address.
pub const ALIAS_CONTRACT_ADDRESS_FELT: Felt = Felt::TWO;

/// Felt representations of special system contracts that need dedicated handling.
pub const SPECIAL_CONTRACT_ADDRESS_FELTS: [Felt; 2] = [BLOCK_HASH_CONTRACT_ADDRESS_FELT, ALIAS_CONTRACT_ADDRESS_FELT];

pub fn is_special_contract_felt(address: Felt) -> bool {
    SPECIAL_CONTRACT_ADDRESS_FELTS.contains(&address)
}

/// Maximum number of concurrent RPC requests to send at a time when fetching storage values.
///
/// This constant defines the limit on the number of concurrent RPC requests
/// that can be made when fetching storage values.
/// Higher values increase throughput but may overwhelm the RPC server.
pub const MAX_CONCURRENT_GET_STORAGE_AT_REQUESTS: usize = 100;

/// Maximum number of concurrent RPC requests to send at a time when backfilling
/// synthetic `initial_reads.storage` entries after Blockifier execution.
pub const MAX_CONCURRENT_INITIAL_READ_STORAGE_FETCHES: usize = 32;

/// Maximum number of concurrent RPC requests to send at a time when fetching contract classes.
///
/// This constant defines the limit on the number of concurrent get_class RPC requests.
/// The actual classes are fetched concurrently, then compiled/hashed in parallel using CPU cores.
pub const MAX_CONCURRENT_GET_CLASS_REQUESTS: usize = 100;

/// Fallback fee to use for L1 handlers when a receipt reports zero `actual_fee`.
///
/// Some historical receipts expose zero here even though Blockifier expects a non-zero
/// `paid_fee_on_l1` to build the executable transaction.
pub const DEFAULT_PAID_FEE_ON_L1: u128 = 1_000_000_000_000u128;

/// Default value of maximum blocks to process in parallel to construct the OS input
pub const DEFAULT_MAX_PARALLEL_BLOCKS: usize = 4;
