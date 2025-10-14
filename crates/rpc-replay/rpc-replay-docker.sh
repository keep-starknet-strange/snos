#!/bin/bash

# Check if correct number of arguments provided
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <network> <start-block> <num-blocks>"
    echo "Networks: sepolia, mainnet, paradex-testnet"
    exit 1
fi

# Parse arguments
NETWORK=$1
START_BLOCK=$2
NUM_BLOCKS=$3

# Starknet Sepolia
SEPOLIA_RPC_URL=https://pathfinder-sepolia.d.karnot.xyz
SEPOLIA_STRK_FEE_TOKEN=0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d
SEPOLIA_ETH_FEE_TOKEN=0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7
SEPOLIA_CHAIN=sepolia

# Starknet Mainnet
MAINNET_RPC_URL=https://pathfinder-mainnet.d.karnot.xyz
MAINNET_STRK_FEE_TOKEN=0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d
MAINNET_ETH_FEE_TOKEN=0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7
MAINNET_CHAIN=mainnet

# Paradex Testnet
PARADEX_TESTNET_RPC_URL=https://pathfinder-paradex-sandbox-testnet.d.karnot.xyz
PARADEX_TESTNET_STRK_FEE_TOKEN=0x049D36570D4e46f48e99674bd3fcc84644DdD6b96F7C741B1562B82f9e004dC7
PARADEX_TESTNET_ETH_FEE_TOKEN=0x049D36570D4e46f48e99674bd3fcc84644DdD6b96F7C741B1562B82f9e004dC7
PARADEX_TESTNET_CHAIN=PRIVATE_SN_POTC_SEPOLIA

# Select network configuration
case $NETWORK in
    starknet-sepolia)
        RPC_URL=$SEPOLIA_RPC_URL
        STRK_FEE_TOKEN=$SEPOLIA_STRK_FEE_TOKEN
        ETH_FEE_TOKEN=$SEPOLIA_ETH_FEE_TOKEN
        CHAIN=$SEPOLIA_CHAIN
        ;;
    starknet-mainnet)
        RPC_URL=$MAINNET_RPC_URL
        STRK_FEE_TOKEN=$MAINNET_STRK_FEE_TOKEN
        ETH_FEE_TOKEN=$MAINNET_ETH_FEE_TOKEN
        CHAIN=$MAINNET_CHAIN
        ;;
    paradex-testnet)
        RPC_URL=$PARADEX_TESTNET_RPC_URL
        STRK_FEE_TOKEN=$PARADEX_TESTNET_STRK_FEE_TOKEN
        ETH_FEE_TOKEN=$PARADEX_TESTNET_ETH_FEE_TOKEN
        CHAIN=$PARADEX_TESTNET_CHAIN
        ;;
    *)
        echo "Error: Invalid network '$NETWORK'"
        echo "Valid options: sepolia, mainnet, paradex-testnet"
        exit 1
        ;;
esac

echo "Starting RPC replay for $NETWORK network"
echo "RPC URL: $RPC_URL"
echo "Chain: $CHAIN"
echo "Start Block: $START_BLOCK"
echo "Number of Blocks: $NUM_BLOCKS"

# Create directories
mkdir -p $NETWORK-logs/ $NETWORK-output/

sudo chown -R 1000:1000 $NETWORK-logs/ $NETWORK-output/

# Run docker container
docker run -d \
--name rpc-replay-$NETWORK \
-v ./$NETWORK-logs:/app/logs \
-v ./$NETWORK-output:/app/output \
-e RUST_LOG=info \
rpc-replay \
--rpc-url $RPC_URL \
--chain $CHAIN \
--start-block $START_BLOCK \
--num-blocks $NUM_BLOCKS \
--strk-fee-token-address $STRK_FEE_TOKEN \
--eth-fee-token-address $ETH_FEE_TOKEN \
--log-dir /app/logs

echo "Docker container 'rpc-replay-$NETWORK' started successfully"
