#!/bin/bash

# Check if the correct number of arguments is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <file_with_block_numbers>"
    exit 1
fi

RPC_ENDPOINT_TESTNET="http://localhost:9545"
PROGRAM="cargo run --package prove_block --release --bin prove_block -- --rpc-provider $RPC_ENDPOINT_TESTNET --block-number"
BLOCK_NUMBERS_FILE=$1
FAILURES=0

# Create a directory to store output and error files
OUTPUT_DIR="output_files"
ERROR_DIR="error_files"
mkdir -p "$OUTPUT_DIR"
mkdir -p "$ERROR_DIR"


# Read each block number from the file and process it
while IFS= read -r CURRENT_ID; do
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
done < "$BLOCK_NUMBERS_FILE"

echo "Total failures: $FAILURES"
echo "Output files are stored in the '$OUTPUT_DIR' directory"
echo "Error files are stored in the '$ERROR_DIR' directory"
