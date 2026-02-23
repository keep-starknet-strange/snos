# CLAUDE.md

Practical guidance for agents and contributors working in this repository.

## 1) What This Repo Does

SNOS generates Cairo PIE by replaying Starknet blocks and executing Starknet OS with reconstructed inputs.

Primary flow:
1. Fetch and re-execute blocks.
2. Build OS inputs/hints and cached state.
3. Run Starknet OS.
4. Validate/export PIE.

## 2) Start Here (Reading Order)

1. `README.md` for usage and prerequisites.
2. `docs/ARCHITECTURE.md` for crate-level structure.
3. `docs/CODE_FLOW.md` for execution and concurrency details.
4. `crates/core/generate-pie/src/lib.rs` for the main pipeline entrypoint.
5. `crates/core/generate-pie/src/main.rs` for CLI wiring.

## 3) Workspace Map

- `crates/core/generate-pie`
  - Main crate. Library + CLI for PIE generation.
  - Entry points:
    - `src/lib.rs` (`generate_pie`)
    - `src/main.rs` (CLI)
- `crates/rpc-client`
  - Starknet RPC + storage/class proof access.
  - Entry point:
    - `src/client.rs` (`RpcClient`, `ProofClient`)
- `crates/starknet-os-types`
  - Contract class abstractions and conversions.
- `crates/rpc-replay`
  - Replay service for correctness runs on settled blocks.
  - Entry point:
    - `src/main.rs`
- `e2e-tests`
  - Slow network-backed tests for end-to-end validation.

## 4) Task Routing (Where to Edit)

- CLI argument changes (`generate-pie` flags/env vars):
  - `crates/core/generate-pie/src/main.rs`
  - `README.md` CLI table/examples
  - `Makefile` wrappers (if applicable)
- Core replay/PIE behavior:
  - `crates/core/generate-pie/src/lib.rs`
  - `src/block_processor.rs`
  - `src/cached_state.rs`
  - `src/state_update.rs`
- RPC/proof behavior:
  - `crates/rpc-client/src/client.rs`
  - `crates/rpc-client/src/types/proofs/*`
- Contract class conversions/hashing:
  - `crates/starknet-os-types/src/*`
- Replay service behavior:
  - `crates/rpc-replay/src/main.rs`
- Architecture/code-flow docs:
  - `docs/ARCHITECTURE.md`
  - `docs/CODE_FLOW.md`

## 5) Local Setup and Environment

- Rust toolchain is pinned in `rust-toolchain` (1.87 + `rustfmt`, `clippy`).
- Cairo build prerequisite:
  - `./setup-scripts/setup-cairo.sh`
  - `source ./venv/bin/activate`
- `cairo-compile` must be available in `PATH` for builds touching Starknet OS dependencies.
- E2E tests require RPC access and appropriate env vars:
  - `SNOS_RPC_URL`
  - `SNOS_RPC_URL_SEPOLIA`

## 6) Validation Commands

Fast/local checks:

```bash
cargo fmt --all --check
cargo check --workspace
make test-ci
```

Targeted checks:

```bash
cargo test -p generate-pie --lib
cargo test -p rpc-client
cargo test -p e2e-tests test_pie_generation -- --nocapture
```

Notes:
- `e2e-tests` are slower and require network/RPC readiness.
- CI workflows are in `.github/workflows/`.

## 7) Known Gotchas

- RPC endpoints must support storage proofs; archive/history availability matters.
- Build/test failures around Cairo often come from Python dependency/version drift.
- `make setup` and activation should use `./venv/bin/activate`.
- `rpc-replay` has two modes (sequential and JSON-driven); avoid mixing arguments.

## 8) Documentation Update Checklist

When changing behavior, update all relevant surfaces together:
1. CLI/API code.
2. `README.md` usage/options/examples.
3. `docs/ARCHITECTURE.md` / `docs/CODE_FLOW.md` if flow/ownership changed.
4. Any Makefile targets affected.

## 9) Scope Hygiene for Agents

- Prefer narrow, targeted edits over broad refactors.
- Run the smallest meaningful validation first.
- Do not assume external RPC availability in local environments.
- Keep docs aligned with current code paths and command names.
