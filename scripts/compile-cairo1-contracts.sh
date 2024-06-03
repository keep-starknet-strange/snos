#!/usr/bin/env bash
# Compiles Cairo 1 contracts in the tests/integration/contracts/blockifier_contracts directory.

set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
CONTRACTS_DIR="${SCRIPT_DIR}/../tests/integration/contracts/blockifier_contracts/feature_contracts/cairo1"

for cairo_file in "${CONTRACTS_DIR}"/*.cairo; do
  sierra_filename=$(basename "${cairo_file}" .cairo).sierra
  sierra_file="${CONTRACTS_DIR}/compiled/${sierra_filename}"
  starknet-compile \
    --single-file \
    --replace-ids \
    --allow-warnings \
    "${cairo_file}" \
    "${sierra_file}"
done
