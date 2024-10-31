#!/bin/bash

# Check Configuration is supplied
if [[ -z "$SFTP_USER" ]]; then
    echo "Please provide the SFTP_USER."
    exit 1
fi

if [[ -z "$SFTP_SERVER" ]]; then
    echo "Please provide the SFTP_SERVER"
    exit 1
fi

if [[ -z "$REMOTE_PATH" ]]; then
    echo "Please provide the REMOTE_PATH"
    exit 1
fi

LOCAL_DIR="./downloaded_files"
LOG_FILE="./snos_run.log"

# Create local directory if it does not exist
mkdir -p "$LOCAL_DIR"

# Start the SFTP session to list files
# echo "Starting SFTP session to list files..." | tee -a "$LOG_FILE"
# sftp $SFTP_USER@$SFTP_SERVER << EOF > temp_file_list.txt
# cd $REMOTE_PATH
# ls
# EOF

# Read each line in the file list as a file to download and process
while read -r file; do
    echo "Processing $file..." 

    # Download the file
    sftp $SFTP_USER@$SFTP_SERVER << EOF
cd $REMOTE_PATH
lcd $LOCAL_DIR
get $file
EOF

    # Check if download succeeded
    if [ $? -eq 0 ]; then
        echo "Successfully downloaded $file" 

        # Run the Rust program with the downloaded file using the specified command
        if RUST_LOG="debug,minilp::solver=info" cargo run -p output_segment --release -- --rpc-provider "http://81.16.176.130:9545" --pie-path "$LOCAL_DIR/$file"; then
            echo "Successfully processed $file" | tee -a "$LOG_FILE"
        else
            echo "Failed to process $file" | tee -a "$LOG_FILE"
        fi

        # Delete the file after processing
        rm "$LOCAL_DIR/$file"
        echo "Deleted $file after processing." 
    else
        echo "Failed to download $file" | tee -a "$LOG_FILE"
    fi
done < temp_file_list.txt

# Clean up
rm temp_file_list.txt
echo "Script execution completed." | tee -a "$LOG_FILE"

