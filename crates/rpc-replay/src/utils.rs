use starknet::core::types::Felt;
use thiserror::Error;

/// Executes a coroutine from a synchronous context.
/// Fails if no Tokio runtime is present.
pub(crate) fn execute_coroutine<F, T>(coroutine: F) -> Result<T, tokio::runtime::TryCurrentError>
where
    F: std::future::Future<Output = T>,
{
    let tokio_runtime_handle = tokio::runtime::Handle::try_current()?;
    Ok(tokio::task::block_in_place(|| tokio_runtime_handle.block_on(coroutine)))
}

#[derive(Error, Debug)]
pub enum FeltConversionError {
    #[error("Overflow Error: Felt exceeds u128 max value")]
    OverflowError,
}

pub fn felt_to_u128(felt: &Felt) -> Result<u128, FeltConversionError> {
    let digits = felt.to_be_digits();

    // Check if there are any significant bits in the higher 128 bits
    if digits[0] != 0 || digits[1] != 0 {
        return Err(FeltConversionError::OverflowError);
    }

    // Safe conversion since we've checked for overflow
    Ok(((digits[2] as u128) << 64) + digits[3] as u128)
}

#[cfg(test)]
mod tests {
    use starknet::core::types::Felt;

    use super::*;

    #[test]
    fn test_felt_to_u128_overflow() {
        // digits[0] || digits[1] != 0
        let overflow_felt = Felt::from(u128::MAX) + Felt::ONE;
        assert!(felt_to_u128(&overflow_felt).is_err());
    }

    #[test]
    fn test_felt_to_u128_ok() {
        let felt_ok = Felt::from(u128::MAX);
        assert!(felt_to_u128(&felt_ok).is_ok());

        let felt_ok = Felt::from(123);
        assert!(felt_to_u128(&felt_ok).is_ok());

        let felt_ok = Felt::from(456789);
        assert!(felt_to_u128(&felt_ok).is_ok());

        let felt_ok = Felt::from(987654321);
        assert!(felt_to_u128(&felt_ok).is_ok());

        let felt_ok = Felt::from(123456789012345678u128);
        assert!(felt_to_u128(&felt_ok).is_ok());
    }
}
