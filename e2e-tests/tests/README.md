# End-to-End Tests for SNOS

This directory contains comprehensive end-to-end tests for the SNOS (Starknet OS) workspace, testing the complete PIE generation workflow.

## Test Structure

```
tests/
├── README.md                 # This file
├── integration.rs            # Main integration test entry point
├── e2e/                     # End-to-end test modules
│   ├── mod.rs
│   ├── pie_generation.rs    # PIE generation e2e tests
│   └── error_handling.rs    # Error handling e2e tests
├── test_data/               # Test data and utilities
│   └── mod.rs
└── mocks/                   # Mock utilities
    └── mod.rs
```

## Running Tests

### Quick Tests (No RPC Required)

Run basic integration tests that don't require external RPC endpoints:

```bash
cargo test --test integration
```

### Full End-to-End Tests (Requires RPC)

Run complete e2e tests including PIE generation:

```bash
# Using default public RPC endpoint
cargo test --test integration -- --ignored

# Using custom RPC endpoint
SNOS_TEST_RPC_URL=https://your-rpc-endpoint.com cargo test --test integration -- --ignored

# Using local Pathfinder instance
SNOS_TEST_RPC_URL=http://localhost:9545 cargo test --test integration -- --ignored
```

### Specific Test Categories

```bash
# Run only PIE generation tests
cargo test --test integration pie_generation -- --ignored

# Run only error handling tests
cargo test --test integration error_handling -- --ignored

# Run specific test
cargo test --test integration test_single_block_pie_generation -- --ignored
```

## Environment Variables

Configure tests using these environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `SNOS_TEST_RPC_URL` | RPC endpoint for testing | `https://pathfinder-mainnet.d.karnot.xyz` |
| `SNOS_TEST_NETWORK` | Network (mainnet/sepolia) | `mainnet` |
| `SNOS_TEST_TIMEOUT_SECS` | Test timeout in seconds | `300` (5 minutes) |
| `SNOS_TEST_OUTPUT_DIR` | Directory for test output files | `/tmp` |
| `SNOS_SKIP_RPC_TESTS` | Skip all RPC-dependent tests | (unset) |

## Test Categories

### 1. Integration Tests (`integration.rs`)

Fast tests that verify component integration without external dependencies:
- Workspace integration
- Error handling integration
- Configuration presets
- Mock utilities
- Performance utilities

### 2. PIE Generation E2E Tests (`e2e/pie_generation.rs`)

Complete workflow tests (require RPC endpoint):
- Single block PIE generation
- Multi-block PIE generation
- Different chain configurations
- Different OS hints configurations
- In-memory PIE generation

### 3. Error Handling E2E Tests (`e2e/error_handling.rs`)

Error scenario tests:
- Invalid RPC endpoints
- Nonexistent blocks
- Input validation errors
- Filesystem errors
- Network timeout scenarios
- Concurrent generation tests

## Setting up Test Environment

### For Local Testing

1. Set up a local Pathfinder node:
```bash
# See pathfinder documentation for setup
PATHFINDER_ETHEREUM_API_URL="YOUR_KEY" ./target/release/pathfinder \
  --data-directory /home/user/pathfinder-data \
  --http-rpc 0.0.0.0:9545 \
  --storage.state-tries archive
```

2. Run tests:
```bash
SNOS_TEST_RPC_URL=http://localhost:9545 cargo test --test integration -- --ignored
```

### For CI/CD

Use public endpoints with appropriate timeouts:
```bash
export SNOS_TEST_RPC_URL=https://pathfinder-mainnet.d.karnot.xyz
export SNOS_TEST_TIMEOUT_SECS=600  # Longer timeout for CI
cargo test --test integration -- --ignored
```

## Test Output

Tests create temporary files during execution:
- PIE files: `test_output_*_blocks_*.pie`
- OS hints JSON: `os_hints_blocks_*.json`

These files are automatically cleaned up after tests complete.

## Performance Considerations

- Single block tests: ~2-5 minutes
- Multi-block tests: ~5-15 minutes
- Full test suite: ~30-60 minutes

Tests include timeouts to prevent hanging in CI environments.

## Troubleshooting

### Common Issues

1. **RPC Connection Errors**
   - Check RPC URL is accessible
   - Verify RPC supports required methods (`starknet_*`, `pathfinder_*`)
   - Check network connectivity

2. **Block Not Found Errors**
   - Ensure block numbers exist on target network
   - Use appropriate blocks for mainnet/sepolia

3. **Timeout Errors**
   - Increase `SNOS_TEST_TIMEOUT_SECS`
   - Use faster RPC endpoint
   - Test with smaller/earlier blocks

4. **Permission Errors**
   - Ensure output directory is writable
   - Check disk space availability

### Debug Mode

Enable detailed logging:
```bash
RUST_LOG=debug cargo test --test integration -- --ignored --nocapture
```

### Skip Problematic Tests

Skip RPC tests in environments without reliable connectivity:
```bash
SNOS_SKIP_RPC_TESTS=1 cargo test --test integration
```

## Contributing

When adding new e2e tests:

1. Add fast unit-level integration tests to `integration.rs`
2. Add slow RPC-dependent tests to appropriate `e2e/` modules
3. Use `#[ignore]` for tests requiring external RPC
4. Add comprehensive error handling
5. Include cleanup for any created files
6. Update this README with new environment variables or requirements