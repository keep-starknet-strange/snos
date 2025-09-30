use starknet_types_core::felt::Felt;

/// Maximum number of blocks that can be processed in a single PIE generation.
pub const MAX_BLOCKS_PER_PIE: usize = 100;

/// Default Sepolia STRK fee token address.
pub const DEFAULT_SEPOLIA_STRK_FEE_TOKEN: &str = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";

/// Default Sepolia ETH fee token address.
pub const DEFAULT_SEPOLIA_ETH_FEE_TOKEN: &str = "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7";

pub const STORED_BLOCK_HASH_BUFFER: u64 = 10;
pub const STATEFUL_MAPPING_START: Felt = Felt::from_hex_unchecked("0x80"); // 128
