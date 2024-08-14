use starknet::core::types::Felt;
use starknet_api::hash::StarkFelt;

/// Executes a coroutine from a synchronous context.
/// Fails if no Tokio runtime is present.
pub(crate) fn execute_coroutine<F, T>(coroutine: F) -> Result<T, tokio::runtime::TryCurrentError>
where
    F: std::future::Future<Output = T>,
{
    let tokio_runtime_handle = tokio::runtime::Handle::try_current()?;
    Ok(tokio::task::block_in_place(|| tokio_runtime_handle.block_on(coroutine)))
}

pub fn felt_api2vm(felt: StarkFelt) -> Felt {
    Felt::from_bytes_be_slice(felt.bytes())
}

pub fn felt_vm2api(felt: Felt) -> StarkFelt {
    StarkFelt::new_unchecked(felt.to_bytes_be())
}

pub fn felt_to_u128(felt: &Felt) -> u128 {
    let digits = felt.to_be_digits();
    ((digits[2] as u128) << 64) + digits[3] as u128
}
