//! Utility functions for async operations and coroutine execution.

use log::warn;
use starknet::core::types::StarknetError;
use starknet::providers::ProviderError;
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::time::sleep;

/// Global Tokio runtime for executing async operations in non-async contexts.
/// This is used when there's no current runtime available (e.g., in worker threads).
static GLOBAL_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
static RPC_TIMING_STATE: OnceLock<Mutex<RpcTimingState>> = OnceLock::new();

/// Maximum number of retry attempts for RPC calls.
const MAX_RETRY_ATTEMPTS: u32 = 5;

/// Initial delay for exponential backoff (in milliseconds).
const INITIAL_BACKOFF_MS: u64 = 100;

/// Maximum delay for exponential backoff (in milliseconds).
const MAX_BACKOFF_MS: u64 = 5000;

#[derive(Debug, Clone, Default)]
pub struct RpcTimingSnapshot {
    pub wait_elapsed: Duration,
    pub cumulative_call_elapsed: Duration,
    pub calls: u64,
    pub calls_by_method: HashMap<String, u64>,
}

#[derive(Debug, Default)]
struct RpcTimingState {
    active_calls: u64,
    wait_started_at: Option<Instant>,
    wait_elapsed: Duration,
    cumulative_call_elapsed: Duration,
    calls: u64,
    calls_by_method: HashMap<String, u64>,
}

/// Gets or creates the global Tokio runtime.
fn get_global_runtime() -> &'static tokio::runtime::Runtime {
    GLOBAL_RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("Failed to create global Tokio runtime")
    })
}

fn rpc_timing_state() -> &'static Mutex<RpcTimingState> {
    RPC_TIMING_STATE.get_or_init(|| Mutex::new(RpcTimingState::default()))
}

pub fn reset_rpc_timing() {
    *rpc_timing_state().lock().expect("RPC timing mutex poisoned") = RpcTimingState::default();
}

pub fn rpc_timing_snapshot() -> RpcTimingSnapshot {
    let state = rpc_timing_state().lock().expect("RPC timing mutex poisoned");
    let mut wait_elapsed = state.wait_elapsed;

    if let Some(wait_started_at) = state.wait_started_at {
        wait_elapsed += wait_started_at.elapsed();
    }

    RpcTimingSnapshot {
        wait_elapsed,
        cumulative_call_elapsed: state.cumulative_call_elapsed,
        calls: state.calls,
        calls_by_method: state.calls_by_method.clone(),
    }
}

fn record_rpc_call_started(operation_name: &str) -> (Instant, String) {
    let now = Instant::now();
    let mut state = rpc_timing_state().lock().expect("RPC timing mutex poisoned");

    if state.active_calls == 0 {
        state.wait_started_at = Some(now);
    }
    state.active_calls += 1;

    (now, rpc_method_name(operation_name).to_string())
}

fn record_rpc_call_finished(call_started_at: Instant, method_name: &str) {
    let now = Instant::now();
    let mut state = rpc_timing_state().lock().expect("RPC timing mutex poisoned");

    state.calls += 1;
    *state.calls_by_method.entry(method_name.to_string()).or_default() += 1;
    state.cumulative_call_elapsed += now.duration_since(call_started_at);
    state.active_calls = state.active_calls.saturating_sub(1);

    if state.active_calls == 0 {
        if let Some(wait_started_at) = state.wait_started_at.take() {
            state.wait_elapsed += now.duration_since(wait_started_at);
        }
    }
}

fn rpc_method_name(operation_name: &str) -> &str {
    let base_name = operation_name.split(['(', ' ']).next().unwrap_or(operation_name);

    match base_name {
        "get_nonce_at" => "get_nonce",
        "get_compiled_class"
        | "get_pre_snip34_compiled_class_hash"
        | "get_compiled_class_hash_v1"
        | "get_compiled_class_hash_v2" => "get_class",
        method_name => method_name,
    }
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

        let (call_started_at, method_name) = record_rpc_call_started(operation_name);
        let result = f().await;
        record_rpc_call_finished(call_started_at, &method_name);

        match result {
            Ok(result) => {
                if attempts > 1 {
                    warn!("{operation_name}: succeeded after {attempts} attempts");
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
                    } else {
                        warn!(
                            "{operation_name}: failed on first attempt with error: {e:?} (retryable: {is_retryable})"
                        );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rpc_timing_tracks_successful_rpc_wait() {
        let before = rpc_timing_snapshot();

        execute_with_retry("timed_sleep", || async {
            sleep(Duration::from_millis(5)).await;
            Ok::<_, ProviderError>(())
        })
        .await
        .unwrap();

        let after = rpc_timing_snapshot();
        assert!(after.calls >= before.calls + 1);
        assert!(
            after.calls_by_method.get("timed_sleep").copied().unwrap_or_default()
                >= before.calls_by_method.get("timed_sleep").copied().unwrap_or_default() + 1
        );
        assert!(after.wait_elapsed >= before.wait_elapsed);
        assert!(after.cumulative_call_elapsed >= before.cumulative_call_elapsed + Duration::from_millis(5));
    }

    #[tokio::test]
    async fn rpc_timing_counts_overlapped_wait_once_for_wall_clock_summary() {
        let before = rpc_timing_snapshot();

        let first = execute_with_retry("timed_sleep_1", || async {
            sleep(Duration::from_millis(20)).await;
            Ok::<_, ProviderError>(())
        });
        let second = execute_with_retry("timed_sleep_2", || async {
            sleep(Duration::from_millis(20)).await;
            Ok::<_, ProviderError>(())
        });

        let (first_result, second_result) = tokio::join!(first, second);
        first_result.unwrap();
        second_result.unwrap();

        let after = rpc_timing_snapshot();
        assert!(after.calls >= before.calls + 2);
        assert!(
            after.calls_by_method.get("timed_sleep_1").copied().unwrap_or_default()
                >= before.calls_by_method.get("timed_sleep_1").copied().unwrap_or_default() + 1
        );
        assert!(
            after.calls_by_method.get("timed_sleep_2").copied().unwrap_or_default()
                >= before.calls_by_method.get("timed_sleep_2").copied().unwrap_or_default() + 1
        );
        assert!(after.wait_elapsed >= before.wait_elapsed);
        assert!(after.cumulative_call_elapsed >= before.cumulative_call_elapsed + Duration::from_millis(40));
    }

    #[test]
    fn rpc_method_name_normalizes_state_reader_helpers_to_rpc_methods() {
        assert_eq!(rpc_method_name("get_nonce_at(contract: 0x123)"), "get_nonce");
        assert_eq!(rpc_method_name("get_compiled_class_hash_v2(class_hash: 0x456)"), "get_class");
        assert_eq!(rpc_method_name("get_proof(block_number: 1, keys: 3)"), "get_proof");
    }
}
