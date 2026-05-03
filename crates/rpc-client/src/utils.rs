//! Utility functions for async operations and coroutine execution.

/// Executes a coroutine (future) in a Tokio runtime context.
///
/// This function is useful for executing async code in contexts where you need to get a
/// block on a coroutine but want to maintain the current runtime context. It's particularly
/// helpful when integrating async code with synchronous interfaces.
///
/// This function works in two modes:
/// 1. If called from within a Tokio runtime context, it uses the current runtime.
/// 2. If called from outside a runtime (e.g., worker threads), it creates a local
///    current-thread runtime for this call.
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
/// Avoid sharing a global runtime across Blockifier worker threads. Those threads
/// synchronously block while fetching RPC state, and a shared runtime can leave
/// one worker parked behind another long-running synchronous execution path.
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
            // No current runtime (e.g., called from a worker thread), use a local runtime.
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to create local Tokio runtime")
                .block_on(coroutine)
        }
    }
}
