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

# Create a directory to store output and error files
OUTPUT_DIR="output_files"
ERROR_DIR="error_files"
mkdir -p "$OUTPUT_DIR"
mkdir -p "$ERROR_DIR"
export RPC_ENDPOINT_TESTNET="http://localhost:9545"

for ((i=0; i<RUNS; i++)); do
    CURRENT_ID=$((START_ID + i))
    OUTPUT_FILE="$OUTPUT_DIR/output_$CURRENT_ID.txt"
    ERROR_FILE="$ERROR_DIR/error_$CURRENT_ID.txt"

    # Run the program and redirect output to a file
    if ! $PROGRAM $CURRENT_ID > "$OUTPUT_FILE" 2>&1; then
        # Capture only the last few lines of the error log (e.g., last 10 lines)
        tail -n 4 "$OUTPUT_FILE" > "$ERROR_FILE"
        echo "Run $CURRENT_ID failed. Error message stored in $ERROR_FILE"
        FAILURES=$((FAILURES + 1))
    else
        tail -n 4 "$OUTPUT_FILE" > "$OUTPUT_FILE"
        echo "Run $CURRENT_ID completed successfully"
        # Remove error file if run was successful
        rm -f "$ERROR_FILE"
    fi
done

echo "Total runs: $RUNS"
echo "Total failures: $FAILURES"
echo "Output files are stored in the '$OUTPUT_DIR' directory"
echo "Error files are stored in the '$ERROR_DIR' directory"