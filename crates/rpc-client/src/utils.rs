//! Utility functions for async operations and coroutine execution.

use log::{debug, warn};
use starknet::core::types::StarknetError;
use starknet::providers::ProviderError;
use std::future::Future;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::time::sleep;

/// Global Tokio runtime for executing async operations in non-async contexts.
/// This is used when there's no current runtime available (e.g., in worker threads).
static GLOBAL_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

/// Maximum number of retry attempts for RPC calls.
const MAX_RETRY_ATTEMPTS: u32 = 3;

/// Initial delay for exponential backoff (in milliseconds).
const INITIAL_BACKOFF_MS: u64 = 100;

/// Maximum delay for exponential backoff (in milliseconds).
const MAX_BACKOFF_MS: u64 = 5000;

/// Gets or creates the global Tokio runtime.
fn get_global_runtime() -> &'static tokio::runtime::Runtime {
    GLOBAL_RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("Failed to create global Tokio runtime")
    })
}

/// Executes a coroutine (future) in a Tokio runtime context.
///
/// This function is useful for executing async code in contexts where you need to get a
/// block on a coroutine but want to maintain the current runtime context. It's particularly
/// helpful when integrating async code with synchronous interfaces.
///
/// This function works in two modes:
/// 1. If called from within a Tokio runtime context, it uses the current runtime
/// 2. If called from outside a runtime (e.g., worker threads), it uses a global runtime
///
/// # Arguments
///
/// * `coroutine` - The future to execute
///
/// # Returns
///
/// Returns the result of the coroutine execution.
///
/// # Note
///
/// This function will create a global multi-threaded Tokio runtime on first use
/// if called outside a runtime context. This makes it safe to use from any thread,
/// including worker threads spawned by external libraries.
pub fn execute_coroutine<F, T>(coroutine: F) -> T
where
    F: std::future::Future<Output = T>,
{
    // Try to use the current runtime if available (e.g., when in an async context)
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            // We're in a runtime context, use block_in_place for efficiency
            tokio::task::block_in_place(|| handle.block_on(coroutine))
        }
        Err(_) => {
            // No current runtime (e.g., called from a worker thread), use global runtime
            let runtime = get_global_runtime();
            runtime.block_on(coroutine)
        }
    }
}

/// Executes an RPC call with exponential backoff retry logic.
pub async fn execute_with_retry<T, F, Fut>(operation_name: &str, f: F) -> Result<T, ProviderError>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, ProviderError>>,
{
    let mut attempts = 0;
    let mut backoff_ms = INITIAL_BACKOFF_MS;

    loop {
        attempts += 1;

        match f().await {
            Ok(result) => {
                if attempts > 1 {
                    debug!("{operation_name}: succeeded after {attempts} attempts");
                }
                return Ok(result);
            }
            Err(e) => {
                let is_retryable = !matches!(
                    &e,
                    ProviderError::StarknetError(StarknetError::ContractNotFound)
                        | ProviderError::StarknetError(StarknetError::ClassHashNotFound)
                );

                if !is_retryable || attempts >= MAX_RETRY_ATTEMPTS {
                    if attempts > 1 {
                        warn!("{operation_name}: failed after {attempts} attempts with error: {e:?}");
                    }
                    return Err(e);
                }

                warn!("{operation_name}: attempt {attempts} failed with error: {e:?}, retrying in {backoff_ms}ms...");
                sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
            }
        }
    }
}
