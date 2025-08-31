//! Utility functions for async operations and coroutine execution.

/// Executes a coroutine (future) in the current tokio runtime context.
///
/// This function is useful for executing async code in contexts where you need to get a
/// block on a coroutine but want to maintain the current runtime context. It's particularly
/// helpful when integrating async code with synchronous interfaces.
///
/// # Arguments
///
/// * `coroutine` - The future to execute
///
/// # Returns
///
/// Returns the result of the coroutine execution, or an error if the runtime handle
/// cannot be obtained.
///
/// # Errors
///
/// Returns a `tokio::runtime::TryCurrentError` if there is no current tokio runtime
/// available in the current thread.
///
/// # Example
///
/// ```rust
/// use rpc_client::utils::execute_coroutine;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // Execute an async operation in a blocking context
///     let result = execute_coroutine(async {
///         // Some async operation
///         tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
///         42
///     })?;
///
///     assert_eq!(result, 42);
///     Ok(())
/// }
/// ```
///
/// # Note
///
/// This function requires a tokio runtime to be available in the current thread.
/// It will return an error if called outside a tokio runtime context.
pub fn execute_coroutine<F, T>(coroutine: F) -> Result<T, tokio::runtime::TryCurrentError>
where
    F: std::future::Future<Output = T>,
{
    let tokio_runtime_handle = tokio::runtime::Handle::try_current()?;
    Ok(tokio::task::block_in_place(|| tokio_runtime_handle.block_on(coroutine)))
}
