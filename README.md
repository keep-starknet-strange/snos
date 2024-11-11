<div align="center">
<img src="./docs/images/SNOS.png" height="400" width="500">


### ✨ SNOS ✨

A Rust Library for running the [Starknet OS](https://github.com/starkware-libs/cairo-lang/blob/master/src/starkware/starknet/core/os/os.cairo).

[Report Bug](https://github.com/keep-starknet-strange/snos/issues/new?assignees=&labels=bug&projects=&template=bug_report.md&title=bug%3A+) · [Request Feature](https://github.com/keep-starknet-strange/snos/issues/new?labels=enhancement&title=feat%3A+)

[![Check Workflow Status](https://github.com/keep-starknet-strange/snos/actions/workflows/check.yml/badge.svg)](https://github.com/keep-starknet-strange/snos/actions/workflows/check.yml)
[![license](https://img.shields.io/github/license/keep-starknet-strange/snos)](/LICENSE)
[![pr-welcome]](#-contributing)

[pr-welcome]: https://img.shields.io/static/v1?color=blue&label=PRs&style=flat&message=welcome

</div>

## 📖 About

The [Starknet OS](https://github.com/starkware-libs/cairo-lang/blob/master/src/starkware/starknet/core/os/os.cairo) is a [Cairo program](https://www.cairo-lang.org/) responsible for proving the integrity of the computation required to transition from the state of a previous block to the state of the next block.

It accomplishes this by re-executing the transactions included in the block and verifying the consistency of the Starknet state.

Executing this program yields a PIE (Program Independent Execution), which can later be used to generate a Stark proof of execution integrity.

If this proof is accepted by the Starknet L1 verifiers, the block is considered valid, and the Starknet state root is updated in the [StarknetCore contract](https://etherscan.io/address/0xc662c410c0ecf747543f5ba90660f6abebd9c8c4#code).



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
