/// Runs synchronous execution without parking an async worker needed by RPC I/O.
///
/// In particular, Blockifier can join an external worker that is waiting for an RPC
/// response on a connection established by the caller's async runtime.
///
/// Like `spawn_blocking`, dropping this future does not stop an already-running
/// closure. Callers must account for that when imposing execution deadlines.
pub(crate) async fn run_blocking<F, T>(execute: F) -> Result<T, tokio::task::JoinError>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(execute).await
}

#[cfg(test)]
mod tests {
    use super::run_blocking;
    use std::sync::mpsc;
    use std::time::Duration;

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn external_worker_join_leaves_async_rpc_driver_runnable() {
        let (request_tx, request_rx) = tokio::sync::oneshot::channel();
        let (response_tx, response_rx) = mpsc::channel();

        // Model a connection driver on the caller's runtime. It must still run
        // while synchronous execution joins the thread waiting for its response.
        let driver = tokio::spawn(async move {
            request_rx.await.unwrap();
            let _ = response_tx.send(42);
        });
        let execution = tokio::spawn(async move {
            run_blocking(move || {
                std::thread::spawn(move || {
                    request_tx.send(()).unwrap();
                    // Bound the test even if execution accidentally blocks the
                    // sole async worker again.
                    response_rx.recv_timeout(Duration::from_secs(2))
                })
                .join()
                .unwrap()
            })
            .await
            .unwrap()
        });

        assert_eq!(execution.await.unwrap().unwrap(), 42);
        driver.await.unwrap();
    }

    #[tokio::test]
    async fn execution_errors_are_preserved() {
        let result = run_blocking(|| Err::<(), _>("execution failed")).await.unwrap();
        assert_eq!(result, Err("execution failed"));
    }

    #[tokio::test]
    async fn execution_panics_are_reported_as_join_errors() {
        let error = run_blocking(|| panic!("executor panicked")).await.unwrap_err();
        assert!(error.is_panic());
    }
}
