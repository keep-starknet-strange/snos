# Contributing to SNOS

Thanks for contributing to SNOS.

This guide is focused on making local development, validation, and PR preparation predictable for contributors.

## 1. Prerequisites

- Rust toolchain from `rust-toolchain` (currently `1.87` with `rustfmt` and `clippy`)
- Python 3.9+ with `cairo-compile` available in `PATH`
- Access to Starknet-spec RPC endpoints with required history/proof support for network-backed tests

## 2. Local Setup

```bash
git clone https://github.com/keep-starknet-strange/snos.git
cd snos
./setup-scripts/setup-cairo.sh
source ./venv/bin/activate
```

Then build:

```bash
cargo build --release
```

## 3. Repository Structure

- `crates/core/generate-pie`: core PIE generation library + CLI
- `crates/rpc-client`: Starknet RPC + proof retrieval helpers
- `crates/starknet-os-types`: shared class/type abstractions
- `crates/rpc-replay`: replay service for settled-block correctness runs
- `e2e-tests`: network-backed E2E coverage
- `docs`: architecture and code-flow docs

## 4. Common Workflows

### Code quality checks

```bash
cargo fmt --all -- --check
cargo clippy --workspace --tests --no-deps -- -D warnings
cargo check --workspace
```

### Unit tests

```bash
make test-workspace
```

### E2E tests (requires RPC env vars)

```bash
export SNOS_RPC_URL=https://your-mainnet-node.com
export SNOS_RPC_URL_SEPOLIA=https://your-sepolia-node.com
make test-e2e
```

### CI-like local run

```bash
make test-ci
```

## 5. Documentation Expectations

If behavior changes, update docs in the same PR:

1. `README.md` for user-facing CLI/workflow changes.
2. `docs/ARCHITECTURE.md` for crate/module ownership or system-shape changes.
3. `docs/CODE_FLOW.md` for execution pipeline/concurrency/RPC flow changes.
4. This file (`CONTRIBUTING.md`) for contributor workflow changes.

For agent-facing guidance, see `CLAUDE.md`.

## 6. PR Checklist

- [ ] Formatting passes (`cargo fmt --all -- --check`)
- [ ] Lints pass (`clippy` with warnings denied)
- [ ] Relevant tests pass
- [ ] Docs updated where behavior changed
- [ ] No local-only artifact files committed
- [ ] PR description explains impact and validation performed

## 7. Notes on Runtime/Tooling Failures

- Build/test failures around Cairo often come from local `cairo-lang` version mismatches.
- If a command fails in `apollo_starknet_os_program` build scripts, verify your active Python environment and `cairo-compile` version.
- Keep RPC-dependent tests separate from pure unit-test expectations when diagnosing failures.
