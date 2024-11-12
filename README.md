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

Executing this program yields a [PIE](https://github.com/starkware-libs/cairo-lang/blob/a86e92bfde9c171c0856d7b46580c66e004922f3/src/starkware/cairo/lang/vm/cairo_pie.py#L219-L225) ([Program Independent Execution](https://github.com/lambdaclass/cairo-vm/blob/60252573255bdf77cf980d689db5b8539dde5e52/vm/src/vm/runners/cairo_pie.rs#L132-L138)), which can later be used to generate a Stark proof of execution integrity.

If this proof is accepted by the Starknet L1 verifiers, the block is considered valid, and the Starknet state root is updated in the [StarknetCore contract](https://etherscan.io/address/0xc662c410c0ecf747543f5ba90660f6abebd9c8c4#code).

## 🛠️ Getting Started 
### Dependencies

- [Rust 1.76.0 or newer](https://www.rust-lang.org/tools/install)
- Cargo

#### For simpler setup
- [pyenv](https://github.com/pyenv/pyenv-installer?tab=readme-ov-file#install)

### Installation
- Clone the repository recursively
```bash
git clone https://github.com/keep-starknet-strange/snos.git --recursive
```

#### Install project dependencies
In order to compile the starknet os cairo program, you need to install the cairo compiler.

- Either follow [cairo docs](https://docs.cairo-lang.org/quickstart.html)
- Or use the provided Makefile  
```bash
make deps
```

This will create a virtual environment needed to compile the cairo program.

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
