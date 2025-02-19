#!/bin/bash

# This script automates the process of adding a new node to an existing MPC Dev cluster.
# It performs two main operations:
# 1. Issues a join request from the candidate node using its credentials and public keys
# 2. Collects votes from existing cluster nodes to approve the candidate's membership
#
# Usage: ./join_vote.sh <candidate_index>
# Where candidate_index is the numeric identifier of the node to be added
#
# Prerequisites:
# - Requires an existing deployment (nodes.tfvars.json must exist)
# - The near CLI must be configured and available
# - jq must be installed for JSON parsing

set -exo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

# Check if argument is provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 <candidate_index>"
    exit 1
fi

INDEX=$1
NODES_CONFIG="devnet_configs/nodes.tfvars.json"

# Load existing deployment info
if [ ! -f "$NODES_CONFIG" ]; then
    echo "Error: No existing deployment found. Run deploy.sh first to initialize the cluster."
    exit 1
fi

# Helper function from add_nodes.sh
hex_public_key_to_json_byte_array() {
    echo -n "["
    for i in $(seq 1 2 ${#1}); do
        echo -n "$((0x${1:i-1:2}))"
        [ $((i + 1)) -lt ${#1} ] && echo -n ","
    done
    echo "]"
}

SUFFIX=$(jq -r '.nodes_uuid' "$NODES_CONFIG")
SIGNER=$(jq -r '.mpc_contract_signer' "$NODES_CONFIG")
CANDIDATE="mpc-test${INDEX}-${SUFFIX}.testnet"

# Extract candidate's information from nodes.tfvars.json
NODE_INFO=$(jq -r --arg idx "$INDEX" '.mpc_nodes[] | select(.account == "mpc-test\($idx)-'"$SUFFIX"'.testnet")' "$NODES_CONFIG")

if [ -z "$NODE_INFO" ]; then
    echo "Error: Candidate node not found in nodes.tfvars.json"
    exit 1
fi

# First, issue join request from the candidate
CIPHER_PK=$(hex_public_key_to_json_byte_array $(echo "$NODE_INFO" | jq -r '.cipher_pk'))
SIGN_PK=$(echo "$NODE_INFO" | jq -r '.sign_pk')
URL=$(echo "$NODE_INFO" | jq -r '.url')
ACCOUNT_PK=$(echo "$NODE_INFO" | jq -r '.account_pk')
ACCOUNT_SK=$(echo "$NODE_INFO" | jq -r '.account_sk')

echo "Issuing join request for candidate $CANDIDATE..."
near contract call-function as-transaction "$SIGNER" join json-args "{
    \"url\": \"$URL\",
    \"cipher_pk\": $CIPHER_PK,
    \"sign_pk\": \"$SIGN_PK\"
}" prepaid-gas '50.0 Tgas' attached-deposit '0 NEAR' sign-as "$CANDIDATE" network-config testnet sign-with-plaintext-private-key --signer-public-key "$ACCOUNT_PK" --signer-private-key "$ACCOUNT_SK" send

# Continue with voting process
EXISTING_NODES=$(jq -r '.mpc_nodes[] | select(.account != "'"$CANDIDATE"'")' "$NODES_CONFIG")

# Issue vote_join commands for each existing node. It is expected that after threshold is reached, the next vote will fail. Nevertheless, the process is successful.
echo "$EXISTING_NODES" | jq -c '.' | while read -r node; do
    MPC_NAME=$(echo "$node" | jq -r '.account')
    ACCOUNT_PK=$(echo "$node" | jq -r '.account_pk')
    ACCOUNT_SK=$(echo "$node" | jq -r '.account_sk')
    
    echo "Voting from node: $MPC_NAME"
    near contract call-function as-transaction "$SIGNER" vote_join json-args "{ \"candidate\": \"$CANDIDATE\" }" \
        prepaid-gas '50.0 Tgas' \
        attached-deposit '0 NEAR' \
        sign-as "$MPC_NAME" \
        network-config testnet \
        sign-with-plaintext-private-key \
        --signer-public-key "$ACCOUNT_PK" \
        --signer-private-key "$ACCOUNT_SK" \
        send
done

echo "Completed join and voting process for candidate: $CANDIDATE" 
