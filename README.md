<div align="center">
    <h1>SNOS</h1>
    <br>
</div>

Rust Library for running the [Starknet OS](https://hackmd.io/@pragma/ByP-iux1T) via the [Cairo VM](https://github.com/lambdaclass/cairo-vm).

## Test Setup

**Cairo [Env]**

See: (https://docs.cairo-lang.org/0.12.0/quickstart.html)

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
./scripts/teardown-tests.sh
```

**Debug Single Cairo Program**

```bash
./scripts/debug-hint.sh load_deprecated_class
```
