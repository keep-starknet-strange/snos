#!/bin/bash

# Check if the correct number of arguments is provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <starting_id> <n_runs>"
    exit 1
fi

PROGRAM="cargo run --package prove_block --release --bin prove_block -- --block-number"
START_ID=$1
RUNS=$2
FAILURES=0

# Create a directory to store output files
OUTPUT_DIR="output_files"
mkdir -p "$OUTPUT_DIR"
export RPC_ENDPOINT_TESTNET="http://localhost:9545"

for ((i=0; i<RUNS; i++)); do
    CURRENT_ID=$((START_ID + i))
    OUTPUT_FILE="$OUTPUT_DIR/output_$CURRENT_ID.txt"
    
    # Run the program and redirect output to file
    if ! $PROGRAM $CURRENT_ID > "$OUTPUT_FILE" 2>&1; then
        echo "Run $CURRENT_ID failed"
        FAILURES=$((FAILURES + 1))
    else
        echo "Run $CURRENT_ID completed successfully"
    fi
done

echo "Total runs: $RUNS"
echo "Total failures: $FAILURES"
echo "Output files are stored in the '$OUTPUT_DIR' directory"

