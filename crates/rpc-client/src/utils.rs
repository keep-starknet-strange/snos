//! Utility functions for async operations and coroutine execution.

/// Executes a coroutine (future) in a Tokio runtime context.
///
/// This function is useful for executing async code in contexts where you need to get a
/// block on a coroutine but want to maintain the current runtime context. It's particularly
/// helpful when integrating async code with synchronous interfaces.
///
/// This function uses a local current-thread runtime for each synchronous bridge call.
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
/// Avoid sharing or re-entering the caller runtime across Blockifier worker threads. Those
/// threads synchronously block while fetching RPC state, and reusing the caller runtime can
/// leave the job parked behind another long-running synchronous execution path.
pub fn execute_coroutine<F, T>(coroutine: F) -> T
where
    F: std::future::Future<Output = T>,
{
    let run = || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create local Tokio runtime")
            .block_on(coroutine)
    };

    if tokio::runtime::Handle::try_current().is_ok() {
        tokio::task::block_in_place(run)
    } else {
        run()
    }
}
