<div align="center">
    <h1>SNOS</h1>
    <br>
    [![CI Action Status](https://github.com/keep-starknet-strange/snos/actions/workflows/ci.yml/badge.svg)](https://github.com/keep-starknet-strange/snos/actions/workflows/ci.yml)
    [![Check Workflow Status](https://github.com/keep-starknet-strange/snos/actions/workflows/check.yml/badge.svg)](https://github.com/keep-starknet-strange/snos/actions/workflows/check.yml)
    ![starknet-version-v0.12.2](https://img.shields.io/badge/Starknet_Version-v0.12.2-2ea44f?logo=ethereum)
</div>

Rust Library for running the [Starknet OS](https://hackmd.io/@pragma/ByP-iux1T) via the [Cairo VM](https://github.com/lambdaclass/cairo-vm).

## Test Setup

**Cairo Env**
(see: https://docs.cairo-lang.org/0.12.0/quickstart.html)

```bash
poetry install
poetry shell
```

**Run Tests**

```bash
./scripts/setup-tests.sh

cargo test
```

**Reset Tests**

```bash
./scripts/reset-tests.sh
```

**Debug Single Cairo Program**

```bash
./scripts/debug-hint.sh load_deprecated_class
```
