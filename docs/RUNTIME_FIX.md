# Runtime Fix for E2E Tests

## Problem

The e2e tests were failing with the error:
```
thread 'e2e::pie_generation::test_os_hints_variations' panicked at crates/rpc-client/src/utils.rs:51:8:
can call blocking only when running on the multi-threaded runtime
```

## Root Cause

The issue was in the `execute_coroutine` function in `rpc-client/src/utils.rs`:

```rust
pub fn execute_coroutine<F, T>(coroutine: F) -> Result<T, tokio::runtime::TryCurrentError>
where
    F: std::future::Future<Output = T>,
{
    let tokio_runtime_handle = tokio::runtime::Handle::try_current()?;
    Ok(tokio::task::block_in_place(|| tokio_runtime_handle.block_on(coroutine))) // <- This line
}
```

The `tokio::task::block_in_place` function requires a **multi-threaded** Tokio runtime, but the `#[tokio::test]` macro by default creates a **single-threaded** runtime.

## Solution

Changed all `#[tokio::test]` annotations to `#[tokio::test(flavor = "multi_thread")]` in the following files:

### Files Updated:
1. `e2e-tests/tests/basic_integration.rs`
2. `e2e-tests/tests/integration.rs`
3. `e2e-tests/tests/e2e/pie_generation.rs`
4. `e2e-tests/tests/e2e/error_handling.rs`

### Before:
```rust
#[tokio::test]
async fn test_function() {
    // test code
}
```

### After:
```rust
#[tokio::test(flavor = "multi_thread")]
async fn test_function() {
    // test code
}
```

## Why This Matters

The `block_in_place` function is used to run blocking operations within an async context. It's specifically designed for scenarios where you need to call synchronous code from within async code without blocking the entire runtime.

However, this function requires:
1. A multi-threaded runtime (so blocking one thread doesn't block everything)
2. Being called from within a Tokio runtime context

## Alternative Solutions (Not Used)

1. **Modify the `execute_coroutine` function**: We could have changed the implementation to detect runtime type and handle accordingly, but this would complicate the RPC client code.

2. **Use `Handle::block_on` directly**: This would work but wouldn't be as efficient since it doesn't yield the current thread.

3. **Make everything fully async**: This would require significant changes to the codebase.

## Testing

After the fix:
```bash
make test-quick  # ✅ Now works without runtime errors
```

The tests now run successfully on a multi-threaded runtime, which is also more representative of how the code will run in production.

## Impact

- ✅ All async e2e tests now work correctly
- ✅ No changes needed to production code
- ✅ More realistic test environment (multi-threaded like production)
- ✅ Better performance for tests that do actual async work

This fix ensures that the e2e tests can properly exercise the full async functionality of the generate-pie crate without runtime compatibility issues.