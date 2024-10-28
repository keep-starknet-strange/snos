#!/bin/bash

# Set the base directory and report file
BASE_DIR="./crates/bin/output_segment/reference-pies"
REPORT_FILE="report.log"

# Clear the report file if it exists
> "$REPORT_FILE"

# Iterate over each file in the directory
for FILE in "$BASE_DIR"/*; do
    if [[ -f "$FILE" ]]; then
        echo "Processing $FILE..."

        # Run the command with the current file path
        RUST_LOG="debug,minilp::solver=info" cargo run -p output_segment --release -- --pie-path "$FILE"
        
        # Check if the command was successful
        if [[ $? -eq 0 ]]; then
            echo "Success: $FILE" | tee -a "$REPORT_FILE"
        else
            echo "Failure: $FILE" | tee -a "$REPORT_FILE"
        fi
    fi
done

echo "Report written to $REPORT_FILE"

