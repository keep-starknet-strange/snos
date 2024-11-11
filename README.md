<div align="center">
<img src="./docs/images/SNOS.png" height="400" width="500">


### ⚡ SNOS ⚡

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
