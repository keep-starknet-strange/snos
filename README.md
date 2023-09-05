<div align="center">
    <h1>SNOS</h1>
    <br>
</div>

Rust Library for running the Starknet OS via the [Cairo VM](https://github.com/lambdaclass/cairo-vm).


## Tests

***compile/run test contracts***

```bash
cairo-compile tests/contracts/fact.cairo --output contracts/build/fact.json
cairo-run --program contracts/build/fact.json --layout=small --cairo_pie_output=contracts/build/fact.pie.zip
unzip contracts/build/fact.pie.zip -d contracts/build
```
