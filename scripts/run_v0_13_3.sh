#!/usr/bin/env bash

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

# Generate the list of tasks
YEAR="2024"
NAMESPACE="sharp6-sepolia"
TASKS=()

for DAY in {17..30}; do
    TASKS+=("$NAMESPACE $YEAR 11 $DAY")
done

for DAY in {01..31}; do
    TASKS+=("$NAMESPACE $YEAR 12 $DAY")
done

export SFTP_USER SFTP_SERVER RPC_PROVIDER

# Run tasks in parallel with a limit of 4 concurrent jobs
printf "%s\n" "${TASKS[@]}" | xargs -n1 -P4 bash -c '
    IFS=" " read -r NAMESPACE YEAR MONTH DAY <<< "$0"
    NAMESPACE="$NAMESPACE" \
    YEAR="$YEAR" \
    MONTH="$MONTH" \
    DAY="$DAY" \
    SFTP_USER="$SFTP_USER" \
    SFTP_SERVER="$SFTP_SERVER" \
    RPC_PROVIDER="$RPC_PROVIDER" \
    ./compare_output.sh
'
