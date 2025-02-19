#!/bin/bash
set -exo pipefail

# This script deploys and initializes a Multi-Party Computation contract on NEAR testnet.
# It performs the following tasks:
# 1. Creates a signer account
# 2. Compiles and deploys the MPC contract
# 3. Generates cryptographic keys for each participant
# 4. Creates participant accounts on testnet
# 5. Initializes the contract with participant data and threshold
# 6. Generates a nodes.tfvars.json file for infrastructure deployment
#
# Usage: ./deploy.sh [-t threshold] [-p participants]

# Default values
THRESHOLD=2
PARTICIPANTS=2
SUFFIX=$(uuidgen | tr '[:upper:]' '[:lower:]')
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
SIGNER="signer-$SUFFIX.testnet"


show_help() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -h, --help           Display this help message"
    echo "  -t, --threshold      Specify a threshold for signing contract. (default: $THRESHOLD)"
    echo "  -p, --participants   Number of participants to generate. (default: $PARTICIPANTS)"
}

while [ ! -z "$1" ]; do
    if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
        show_help
        exit 0
    elif [[ $1 == "-t" ]] || [[ "$1" == "--threshold" ]]; then
        THRESHOLD="$2"
        shift
    elif [[ $1 == "-p" ]] || [[ "$1" == "--participants" ]]; then
        PARTICIPANTS="$2"
        shift
    else
        echo "Incorrect input provided $1"
        show_help
        exit 0
    fi
    shift
done


compile_contract() {
    cd "$SCRIPT_DIR/../libs/chain-signatures"
    cargo build -p mpc-contract --target wasm32-unknown-unknown --release
    echo "$SCRIPT_DIR/../libs/chain-signatures/target/wasm32-unknown-unknown/release/mpc_contract.wasm"
}

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

##########################################################################################
# Main code block
##########################################################################################

near account create-account sponsor-by-faucet-service "$SIGNER" autogenerate-new-keypair save-to-legacy-keychain network-config testnet create

near deploy "$SIGNER" "$(compile_contract)"


# Initialize arrays to store data
declare -a NODE_DATA=()
CANDIDATES="{"

for i in $(seq 0 $((PARTICIPANTS - 1))); do
    echo "Generating key for participant $i"
    KEY_DATA=$(generate_key "$i")
    NODE_DATA+=("$KEY_DATA")
    
    MPC_NAME="mpc-test$i-$SUFFIX.testnet"
    near account create-account sponsor-by-faucet-service "$MPC_NAME" use-manually-provided-public-key $(echo "$KEY_DATA" | jq -r '.near_account_public_key') network-config testnet create
    
    # Build candidates JSON
    CANDIDATES+="\"$MPC_NAME\": {
        \"account_id\": \"$MPC_NAME\",
        \"cipher_pk\": $(hex_public_key_to_json_byte_array $(echo "$KEY_DATA" | jq -r '.cipher_public_key')),
        \"sign_pk\": \"$(echo "$KEY_DATA" | jq -r '.sign_public_key')\",
        \"url\": \"$(echo "$KEY_DATA" | jq -r '.url')\"
    }"
    if [ $((i + 1)) -lt "$PARTICIPANTS" ]; then CANDIDATES+=","; fi
done

CANDIDATES+="}"

# Create nodes.tfvars.json
mkdir -p devnet_configs
nodes='{
  "mpc_nodes": ['

for i in $(seq 0 $((PARTICIPANTS - 1))); do
    node=$(echo "${NODE_DATA[$i]}" | jq --arg i "$i" --arg s "$SUFFIX" '
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

    if [ $((i + 1)) -lt "$PARTICIPANTS" ]; then
        nodes+="$node,"
    else
        nodes+="$node"
    fi
done

nodes+='
  ],
  "mpc_contract_signer": "'$SIGNER'",
  "nodes_uuid": "'$SUFFIX'"
}'

echo "$nodes" | jq >devnet_configs/nodes.tfvars.json

INIT_ARGS=$(jq -n --argjson candidates "$CANDIDATES" --argjson threshold "$THRESHOLD" '{ "candidates": $candidates, "threshold": $threshold }')
near call "$SIGNER" init "$INIT_ARGS" --use-account "$SIGNER"

echo "The signer account is $SIGNER."
echo "The signer account is required in the sign_request.sh script. Please retain it until the completion of the process."
echo "The script has generated the nodes.tfvars.json file."
echo "This should be used from Infra-Ops Terraform directories when starting Nomad cluster:"
echo "tf apply -var-file=\$path_to_nodes.tfvars.json"
echo "infra-ops/provisioning/nomad/mpc/"
echo "infra-ops/provisioning/terraform/infra/mpc/base-mpc-cluster"
