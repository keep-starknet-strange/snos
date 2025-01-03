#!/bin/bash

# Usage: SFTP_USER="" SFTP_SERVER="" NAMESPACE="" YEAR="" MONTH="" DAY="" RPC_PROVIDER="" ./compare_output.sh

if [[ -z "$SFTP_USER" ]]; then
    echo "Please provide the SFTP_USER."
    exit 1
fi

if [[ -z "$SFTP_SERVER" ]]; then
    echo "Please provide the SFTP_SERVER"
    exit 1
fi

if [[ -z "$NAMESPACE" ]]; then
    echo "Please provide the NAMESPACE"
    exit 1
fi

if [[ -z "$YEAR" ]]; then
    echo "Please provide the YEAR"
    exit 1
fi

if [[ -z "$MONTH" ]]; then
    echo "Please provide the MONTH"
    exit 1
fi

if [[ -z "$DAY" ]]; then
    echo "Please provide the DAY"
    exit 1
fi

if [[ -z "$RPC_PROVIDER" ]]; then
    echo "Please provide the RPC_PROVIDER"
    exit 1
fi

REMOTE_PATH="/sharp-starknet-pies/files/namespace=${NAMESPACE}/year=${YEAR}/month=${MONTH}/day=${DAY}/"
LOCAL_DIR="./downloaded_files"
LOG_FILE="./snos_run_${MONTH}_${YEAR}.log"

# CSV file to record success/failure + message + block number
CSV_FILE="./results_${MONTH}_${YEAR}.csv"

# Create local directory
mkdir -p "$LOCAL_DIR"

# If the CSV file doesn't exist, create it with a header row
if [[ ! -f "$CSV_FILE" ]]; then
  echo "filename,block_number,year,month,day,status,message" > "$CSV_FILE"
fi

FILES=$(sftp -b - "$SFTP_USER@$SFTP_SERVER" <<EOF
cd $REMOTE_PATH
ls -1
EOF
)

CLEANED_FILES=$(echo "$FILES" | grep -v '^sftp>' | grep -v '^Changing' | grep -v '^\s*$')

while IFS= read -r file; do
    [[ -z "$file" ]] && continue

    echo "Processing $file..."

    # Download the file from SFTP
    sftp -b - "$SFTP_USER@$SFTP_SERVER" <<EOF
cd $REMOTE_PATH
lcd $LOCAL_DIR
get $file
EOF

    if [ $? -eq 0 ]; then
        echo "Successfully downloaded $file"

        # 1) Capture the command output (including both stdout & stderr).
        #    This allows us to extract the line with the blocknumber and the error
        OUTPUT=$(RUST_LOG="debug,minilp::solver=info" \
            cargo run -p output_segment --release -- \
            --rpc-provider "$RPC_PROVIDER" \
            --pie-path "$LOCAL_DIR/$file" \
            2>&1
        )
        # Store the exit status for the run
        RUN_EXIT_CODE=$?

        # 2) Parse out the BLOCKNUMBER from the logs (if it exists).
        # After (looking for "Runnin SNOS for block number: 12345")
        BLOCK_NUMBER=$(echo "$OUTPUT" | grep -Po "Runnin SNOS for block number: \K\d+")

        # 3) Check exit code to determine success/failure.
        if [[ $RUN_EXIT_CODE -eq 0 ]]; then
            echo "Successfully processed $file" | tee -a "$LOG_FILE"
            # Append success to CSV including the block_number
            echo "$file,$BLOCK_NUMBER,$YEAR,$MONTH,$DAY,success," >> "$CSV_FILE"
        else
            echo "Failed to process $YEAR/$MONTH/$DAY/$file" | tee -a "$LOG_FILE"
            echo "$file,$BLOCK_NUMBER,$YEAR,$MONTH,$DAY,failure,Failed to process file" >> "$CSV_FILE"
        fi

        # Remove the file to avoid clutter
        rm "$LOCAL_DIR/$file"
        echo "Deleted $file after processing."

    else
        echo "Failed to download $file" | tee -a "$LOG_FILE"
        # Append failure to CSV with a message; no block number in this case
        echo "$file,,$YEAR,$MONTH,$DAY,failure,Failed to download file" >> "$CSV_FILE"
    fi
done <<< "$CLEANED_FILES"

echo "Script execution completed." | tee -a "$LOG_FILE"
