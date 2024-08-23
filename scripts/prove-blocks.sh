#!/bin/bash

# Function to show usage
usage() {
  echo "Usage: $0 -p <rpc-provider> -b <block-number1,block-number2,...>"
  exit 1
}

# Parse command-line options
while getopts "p:b:" opt; do
  case ${opt} in
    p )
      PROVIDER=$OPTARG
      ;;
    b )
      IFS=',' read -r -a BLOCK_NUMBERS <<< "$OPTARG"
      ;;
    * )
      usage
      ;;
  esac done

# Check if both provider and block numbers are provided
if [ -z "$PROVIDER" ] || [ -z "$BLOCK_NUMBERS" ]; then
  usage
fi

# Loop through each block number and execute the cargo command
for BLOCK_NUMBER in "${BLOCK_NUMBERS[@]}"; do
  echo "Executing for block number: $BLOCK_NUMBER"
  cargo run -p prove_block -- --block-number "$BLOCK_NUMBER" --rpc-provider "$PROVIDER"
  
  # Check if the cargo command failed
  if [ $? -ne 0 ]; then
    echo "Command failed for block number: $BLOCK_NUMBER. Exiting."
    exit 1
  fi
done

echo "All blocks proved successfully."
