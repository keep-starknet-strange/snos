#!/bin/bash

# Usage: SFTP_USER="" SFTP_SERVER="" RPC_PROVIDER="" ./run_v0_13_3.sh

if [[ -z "$SFTP_USER" ]]; then
    echo "Please provide the SFTP_USER."
    exit 1
fi

if [[ -z "$SFTP_SERVER" ]]; then
    echo "Please provide the SFTP_SERVER"
    exit 1
fi

if [[ -z "$RPC_PROVIDER" ]]; then
    echo "Please provide the RPC_PROVIDER"
    exit 1
fi

YEAR="2024"
NAMESPACE="sharp6-sepolia"

for DAY in {11..30}; do # We start from the 11th of Nov
    NAMESPACE="$NAMESPACE" \
    YEAR="$YEAR" \
    MONTH="11" \ # November
    DAY="$DAY" \
    SFTP_USER="$SFTP_USER" \
    SFTP_SERVER="$SFTP_SERVER" \
    RPC_PROVIDER="$RPC_PROVIDER" \
    ./compare_output.sh
done

for DAY in {1..31}; do
    NAMESPACE="$NAMESPACE" \
    YEAR="$YEAR" \
    MONTH="12" \ # December
    DAY="$DAY" \
    SFTP_USER="$SFTP_USER" \
    SFTP_SERVER="$SFTP_SERVER" \
    RPC_PROVIDER="$RPC_PROVIDER" \
    ./compare_output.sh
done
