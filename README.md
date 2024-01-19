<div align="center">
<h1>
    SNOS
    <br>

![SN_Ver_0.12.2](https://img.shields.io/badge/SN_Ver_0.12.2-0C0C4F.svg?logo=data:image/svg%2bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZlcnNpb249IjEiIHdpZHRoPSI2MDAiIGhlaWdodD0iNjAwIj48cGF0aCBkPSJNMTI5IDExMWMtNTUgNC05MyA2Ni05MyA3OEwwIDM5OGMtMiA3MCAzNiA5MiA2OSA5MWgxYzc5IDAgODctNTcgMTMwLTEyOGgyMDFjNDMgNzEgNTAgMTI4IDEyOSAxMjhoMWMzMyAxIDcxLTIxIDY5LTkxbC0zNi0yMDljMC0xMi00MC03OC05OC03OGgtMTBjLTYzIDAtOTIgMzUtOTIgNDJIMjM2YzAtNy0yOS00Mi05Mi00MmgtMTV6IiBmaWxsPSIjZmZmIi8+PC9zdmc+)
![by_SW_Exploration](https://img.shields.io/badge/by_SW_Exploration-0C0C4F.svg?logo=ethereum)

[![Check Workflow Status](https://github.com/keep-starknet-strange/snos/actions/workflows/check.yml/badge.svg)](https://github.com/keep-starknet-strange/snos/actions/workflows/check.yml)

</h1>
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
