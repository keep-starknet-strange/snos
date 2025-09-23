# SNOS Testing Guide

This document provides a comprehensive guide to testing the SNOS (Starknet OS) project.

## 🚀 Quick Start

```bash
# Run quick tests (no external dependencies)
make test-quick

# Check your test environment
make env-check

# Run full end-to-end tests
make test-e2e
```

## 🧪 Test Structure

The project includes several types of tests:

### 1. **Quick Integration Tests** ⚡
- **Location**: `e2e-tests/tests/basic_integration.rs`
- **Runtime**: ~1 second
- **Dependencies**: None (no RPC required)
- **Purpose**: Verify workspace integration, type system, error handling

```bash
make test-quick        # or make t (alias)
```

### 2. **End-to-End PIE Generation Tests** 🎯
- **Location**: `e2e-tests/tests/e2e/pie_generation.rs`
- **Runtime**: 5-60 minutes
- **Dependencies**: Working Starknet RPC endpoint
- **Purpose**: Complete PIE generation workflow testing

```bash
make test-e2e          # Full e2e suite
make test-pie          # PIE generation only
make test-single       # Single block test
make test-multi        # Multi-block test
```

### 3. **Error Handling Tests** ⚠️
- **Location**: `e2e-tests/tests/e2e/error_handling.rs`
- **Runtime**: 1-10 minutes
- **Dependencies**: Various (some require RPC)
- **Purpose**: Comprehensive error scenario coverage

```bash
make test-errors       # Error handling tests
```

### 4. **Workspace Unit Tests** 🔧
- **Location**: Individual crate `src/` directories
- **Runtime**: ~10 seconds
- **Dependencies**: None
- **Purpose**: Individual crate functionality

```bash
make test-workspace    # All unit tests
```

## 🛠️ Makefile Commands

### Testing Commands
| Command | Description | Time | Dependencies |
|---------|-------------|------|--------------|
| `make test-quick` | Quick integration tests | ~1s | None |
| `make test-e2e` | Full e2e tests | 30-60m | RPC |
| `make test-pie` | PIE generation tests | 10-30m | RPC |
| `make test-errors` | Error handling tests | 5-10m | Varies |
| `make test-single` | Single block PIE test | 5m | RPC |
| `make test-multi` | Multi-block PIE test | 10-15m | RPC |
| `make test-all` | All tests | 60m+ | RPC |

### Development Commands
| Command | Description |
|---------|-------------|
| `make check` | Run cargo check |
| `make build` | Build workspace |
| `make lint` | Run clippy |
| `make fmt` | Format code |
| `make clean` | Clean artifacts |

### Network-Specific Tests
| Command | Description |
|---------|-------------|
| `make test-mainnet` | Test against mainnet |
| `make test-sepolia` | Test against sepolia |
| `make test-local` | Test against localhost:9545 |

### Environment
| Command | Description |
|---------|-------------|
| `make env-check` | Check test environment |
| `make setup` | Set up dev environment |
| `make help` | Show all commands |

## 🔧 Configuration

### Environment Variables
```bash
export SNOS_TEST_RPC_URL=https://your-rpc-endpoint.com
export SNOS_TEST_NETWORK=mainnet  # or sepolia
export SNOS_TEST_TIMEOUT_SECS=600
export SNOS_TEST_OUTPUT_DIR=/tmp
```

### Makefile Variables
```bash
make test-e2e RPC_URL=http://localhost:9545 VERBOSE=true TIMEOUT=900
```

## 🚦 CI/CD Integration

### For CI Pipelines
```bash
# Fast CI tests (no RPC)
make test-ci

# Full release validation
make release-check
```

### GitHub Actions Example
```yaml
- name: Quick Tests
  run: make test-ci

- name: E2E Tests
  run: make test-e2e
  env:
    SNOS_TEST_RPC_URL: ${{ secrets.RPC_URL }}
  if: github.event_name == 'push' && github.ref == 'refs/heads/main'
```

## 📊 Test Coverage

### Current Coverage
- ✅ **Basic Integration**: Workspace, RPC client, error handling
- ✅ **PIE Generation**: Single/multi-block workflows
- ✅ **Error Scenarios**: Invalid inputs, network issues, timeouts
- ✅ **Configuration**: Chain configs, OS hints variations
- ✅ **Performance**: Timing and resource monitoring

### Missing Coverage (Future Work)
- [ ] Benchmark tests
- [ ] Property-based tests
- [ ] Stress tests with large blocks
- [ ] Memory usage analysis
- [ ] Concurrent generation testing

## 🐛 Troubleshooting

### Common Issues

1. **RPC Connection Errors**
   ```bash
   make env-check  # Verify connectivity
   ```

2. **Test Timeouts**
   ```bash
   make test-e2e TIMEOUT=900  # Increase timeout
   ```

3. **Permission Errors**
   ```bash
   # Check output directory permissions
   ls -la /tmp
   ```

4. **Build Failures**
   ```bash
   make clean
   make check
   ```

### Debug Mode
```bash
# Verbose test output
make test-quick VERBOSE=true

# Check versions
make debug-versions

# Show dependencies
make debug-deps
```

## 📈 Performance Guidelines

### Expected Test Times
- **Quick Integration**: < 5 seconds
- **Single Block PIE**: 2-5 minutes
- **Multi-Block PIE**: 5-15 minutes
- **Full E2E Suite**: 30-60 minutes
- **Error Tests**: 5-10 minutes

### Performance Tips
- Use local Pathfinder for faster tests
- Run quick tests during development
- Use specific test targets for focused testing
- Consider test parallelization for CI

## 🔗 Related Files

- [`Makefile`](./Makefile) - Main build and test commands
- [`e2e-tests/`](./e2e-tests/) - Test implementation
- [`scripts/run-e2e-tests.sh`](./scripts/run-e2e-tests.sh) - Advanced test runner
- [`e2e-tests/tests/README.md`](./e2e-tests/tests/README.md) - Detailed test documentation

---

For more detailed information, see the comprehensive test documentation in `e2e-tests/tests/README.md`.