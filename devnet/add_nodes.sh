#!/bin/bash
set -exo pipefail

# This script automates the process of adding multiple new nodes to an MPC Dev cluster.
# It performs two main operations:
# 1. Generates cryptographic keys and updates the deployment configuration for each new node
# 2. Creates NEAR accounts and issues join requests for each new node
#
# Usage: ./add_nodes.sh <number_of_nodes>
# Where number_of_nodes is how many new nodes to add to the cluster
#
# Prerequisites:
# - Requires an existing deployment (nodes.tfvars.json must exist)
# - The near CLI must be configured and available
# - jq must be installed for JSON parsing
# - Rust toolchain for key generation


SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

# Load existing deployment info
if [ ! -f "devnet_configs/nodes.tfvars.json" ]; then
    echo "Error: No existing deployment found. Run deploy.sh first to initialize the cluster."
    exit 1
fi

# Check if argument is provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 <number_of_nodes>"
    exit 1
fi

PARTICIPANTS=$1
SUFFIX=$(jq -r '.nodes_uuid' devnet_configs/nodes.tfvars.json)
SIGNER=$(jq -r '.mpc_contract_signer' devnet_configs/nodes.tfvars.json)

##########################################################################################
# Functions block (reused from deploy.sh)
##########################################################################################

generate_key() {
    cd "$SCRIPT_DIR/generate_keys"

    KEYGEN_OUTPUT=$(cargo run)

    CIPHER_PUBLIC_KEY=$(echo "$KEYGEN_OUTPUT" | sed -n 's/.*cipher public key: //p')
    CIPHER_PRIVATE_KEY=$(echo "$KEYGEN_OUTPUT" | sed -n 's/.*cipher private key: //p')
    SIGN_PUBLIC_KEY=$(echo "$KEYGEN_OUTPUT" | sed -n 's/.*sign public key sign_pk: //p')
    SIGN_SECRET_KEY=$(echo "$KEYGEN_OUTPUT" | sed -n 's/.*sign secret key sign_sk: //p')
    NEAR_ACCOUNT_PUBLIC_KEY=$(echo "$KEYGEN_OUTPUT" | sed -n 's/.*near account public key: //p')
    NEAR_ACCOUNT_SECRET_KEY=$(echo "$KEYGEN_OUTPUT" | sed -n 's/.*near account secret key: //p')

    echo "{
        \"cipher_public_key\": \"$CIPHER_PUBLIC_KEY\",
        \"cipher_private_key\": \"$CIPHER_PRIVATE_KEY\",
        \"sign_public_key\": \"$SIGN_PUBLIC_KEY\",
        \"sign_secret_key\": \"$SIGN_SECRET_KEY\",
        \"near_account_public_key\": \"$NEAR_ACCOUNT_PUBLIC_KEY\",
        \"near_account_secret_key\": \"$NEAR_ACCOUNT_SECRET_KEY\",
        \"url\": \"http://mpc-node-$1.service.mpc.consul:3000\"
    }"
}

hex_public_key_to_json_byte_array() {
    echo -n "["
    for i in $(seq 1 2 ${#1}); do
        echo -n "$((0x${1:i-1:2}))"
        [ $((i + 1)) -lt ${#1} ] && echo -n ","
    done
    echo "]"
}

# Load existing nodes
EXISTING_NODES=$(jq -r '.mpc_nodes' devnet_configs/nodes.tfvars.json)
START_INDEX=$(echo "$EXISTING_NODES" | jq length)

##########################################################################################
# Step 1: Generate all keys and update tfvars
##########################################################################################

# Initialize array to store new node data
declare -a NODE_DATA=()

# Generate new nodes
for i in $(seq $START_INDEX $((START_INDEX + PARTICIPANTS - 1))); do
    echo "Generating key for participant $i"
    KEY_DATA=$(generate_key "$i")
    NODE_DATA+=("$KEY_DATA")
done

# Update nodes.tfvars.json with new nodes
nodes='{
  "mpc_nodes": ['

for i in $(seq $START_INDEX $((START_INDEX + PARTICIPANTS - 1))); do
    node=$(echo "${NODE_DATA[$i-$START_INDEX]}" | jq --arg i "$i" --arg s "$SUFFIX" '
    {
      account: "mpc-test\($i)-\($s).testnet",
      account_pk: .near_account_public_key,
      account_sk: .near_account_secret_key,
      cipher_pk: .cipher_public_key,
      cipher_sk: .cipher_private_key,
      sign_pk: .sign_public_key,
      sign_sk: .sign_secret_key,
      url: .url
    }')
    nodes+="$node,"
done

# Remove trailing comma and add existing nodes
nodes=${nodes%,}
nodes+='],'
nodes+="\"mpc_contract_signer\": \"$SIGNER\","
nodes+="\"nodes_uuid\": \"$SUFFIX\""
nodes+='}'

# Merge with existing nodes
nodes=$(echo "$nodes" | jq --argjson existing "$EXISTING_NODES" '.mpc_nodes = $existing + .mpc_nodes')
echo "$nodes" | jq >devnet_configs/nodes.tfvars.json

##########################################################################################
# Step 2: Create accounts and join network
##########################################################################################

for i in $(seq $START_INDEX $((START_INDEX + PARTICIPANTS - 1))); do
    KEY_DATA="${NODE_DATA[$i-$START_INDEX]}"
    MPC_NAME="mpc-test$i-$SUFFIX.testnet"
    
    # Create account
    near account create-account sponsor-by-faucet-service "$MPC_NAME" use-manually-provided-public-key $(echo "$KEY_DATA" | jq -r '.near_account_public_key') network-config testnet create
    
    # Call join function
    CIPHER_PK=$(hex_public_key_to_json_byte_array $(echo "$KEY_DATA" | jq -r '.cipher_public_key'))
    SIGN_PK=$(echo "$KEY_DATA" | jq -r '.sign_public_key')
    URL=$(echo "$KEY_DATA" | jq -r '.url')
    ACCOUNT_PK=$(echo "$KEY_DATA" | jq -r '.near_account_public_key')
    ACCOUNT_SK=$(echo "$KEY_DATA" | jq -r '.near_account_secret_key')
    
    
    near contract call-function as-transaction "$SIGNER" join json-args "{
        \"url\": \"$URL\",
        \"cipher_pk\": $CIPHER_PK,
        \"sign_pk\": \"$SIGN_PK\"
    }" prepaid-gas '50.0 Tgas' attached-deposit '0 NEAR' sign-as "$MPC_NAME" network-config testnet sign-with-plaintext-private-key --signer-public-key "$ACCOUNT_PK" --signer-private-key "$ACCOUNT_SK" send
done

echo "Successfully added $PARTICIPANTS new node(s) to the cluster and issues join requests."
echo "Updated nodes.tfvars.json with new nodes."
echo "To deploy the new nodes, run:"
echo "tf apply -var-file=\$path_to_nodes.tfvars.json for both infra and Nomad jobs." 
