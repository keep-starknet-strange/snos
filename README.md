<div align="center">
    <h1>SNOS</h1>
    <br>
</div>

Rust Library for running the Starknet OS via the [Cairo VM](https://github.com/lambdaclass/cairo-vm).


## Setup

***Cairo 0 [Env](https://docs.cairo-lang.org/0.12.0/quickstart.html)***

```bash
git submodule update --init

CAIRO_PATH=cairo-lang/src cairo-compile cairo-lang/src/starkware/starknet/core/os/os.cairo --output build/os_compiled.json
```

## Tests

***compile/run test contracts***

```bash
cargo test -- --nocapture
```

