/// Default timeout for RPC requests in seconds.
pub const DEFAULT_RPC_TIMEOUT_SECONDS: u64 = 30;

/// Maximum number of blocks that can be processed in a single PIE generation.
pub const MAX_BLOCKS_PER_PIE: usize = 100;

/// Default layout name for Cairo execution.
pub const DEFAULT_CAIRO_LAYOUT: &str = "all_cairo";

/// Default Sepolia STRK fee token address.
pub const DEFAULT_SEPOLIA_STRK_FEE_TOKEN: &str = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";

/// Default L2 gas price for ETH (in wei).
pub const DEFAULT_ETH_L2_GAS_PRICE: &str = "0x199fe";

/// Default L2 gas price for STRK (in wei).
pub const DEFAULT_STRK_L2_GAS_PRICE: &str = "0xb2d05e00";

/// Default Sepolia ETH fee token address.
pub const DEFAULT_SEPOLIA_ETH_FEE_TOKEN: &str = "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7";