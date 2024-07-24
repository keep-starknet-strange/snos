use cairo_vm::Felt252;
use starknet_api::block::BlockTimestamp;

#[derive(Default, Clone, Debug)]
pub struct ResourcePrice {
    pub price_in_wei: u128,
    pub price_in_fri: u128,
}

#[derive(Default, Clone, Debug)]
pub struct BlockInfo {
    /// The sequence number of the last block created.
    pub block_number: i64,
    /// Timestamp of the beginning of the last block creation attempt.
    pub block_timestamp: BlockTimestamp,
    /// L1 gas price measured at the beginning of the last block creation attempt.
    pub l1_gas_price: ResourcePrice,
    /// L1 data gas price measured at the beginning of the last block creation attempt.
    pub l1_data_gas_price: ResourcePrice,
    /// The sequencer address of this block.
    pub sequencer_address: Option<Felt252>,
    /// Indicates whether to use KZG commitment scheme for the block's Data Avilability.
    pub use_kzg_da: bool,
}

impl BlockInfo {
    /// Returns an empty BlockInfo object; i.e., the one before the first in the chain.
    pub fn empty(sequencer_address: Option<Felt252>, use_kzg_da: bool) -> Self {
        Self {
            block_number: -1,
            block_timestamp: BlockTimestamp(0),
            l1_gas_price: ResourcePrice { price_in_wei: 1, price_in_fri: 1 },
            l1_data_gas_price: ResourcePrice { price_in_wei: 1, price_in_fri: 1 },
            sequencer_address,
            use_kzg_da,
        }
    }
}
