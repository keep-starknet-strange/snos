<div align="center">
    <h1>SNOS</h1>
    <br>
</div>

Rust Library for running the Starknet OS via the [Cairo VM](https://github.com/lambdaclass/cairo-vm).


## Setup

***Cairo [Env](https://docs.cairo-lang.org/0.12.0/quickstart.html)***

```bash
git submodule update --init
```

## Env

To define an alternative OS from the [default(v0.12.2)](build/os_latest.json) set the `SNOS_PATH` environment variable.

```bash
SNOS_PATH="build/alt_os.json" cargo build
```

## Tests

***compile os w/ debug info***

```bash
CAIRO_PATH=cairo-lang/src cairo-compile cairo-lang/src/starkware/starknet/core/os/os.cairo --output build/os_debug.json
```

***compile/run test contracts***

```bash
cargo test
```

