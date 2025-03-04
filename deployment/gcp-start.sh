#!/bin/bash
set -eo pipefail


# This script is intended to be used for running nearone/mpc in a GCP environment. 
# It will initialize the Near node in case it is not initialized yet and start the MPC node.


HOME_DIR="/data"
MPC_NODE_CONFIG_FILE="$HOME_DIR/config.yaml"
NEAR_NODE_CONFIG_FILE="$HOME_DIR/config.json"

initialize_near_node() {
    ./mpc-node init --dir $1 --chain-id $MPC_ENV --download-genesis --download-config
    python3 << EOF
import json;
config = json.load(open("$NEAR_NODE_CONFIG_FILE"))

# boot nodes must be filled in or else the node will not have any peers.
config['network']['boot_nodes'] = "${NEAR_BOOT_NODES}"

config['state_sync']['sync']['ExternalStorage']['external_storage_fallback_threshold'] = 0

# Track whichever shard the contract account is on.
config['tracked_shards'] = []
config['tracked_accounts'] = ["$MPC_CONTRACT_ID"]
json.dump(config, open("$NEAR_NODE_CONFIG_FILE", 'w'), indent=2)
EOF
}

initialize_mpc_config() {
  cat <<EOF > "$1"
# Configuration File
my_near_account_id: $MPC_ACCOUNT_ID
web_ui:
  host: 0.0.0.0
  port: 8080
triple:
  concurrency: 2
  desired_triples_to_buffer: 1000000
  timeout_sec: 60
  parallel_triple_generation_stagger_time_sec: 1
presignature:
  concurrency: 16
  desired_presignatures_to_buffer: 8192
  timeout_sec: 60
signature:
  timeout_sec: 60
indexer:
  validate_genesis: false
  sync_mode: Latest
  concurrency: 1
  mpc_contract_id: $MPC_CONTRACT_ID
  port_override: 80
  finality: optimistic
cores: 12
EOF
}

if [ -r "$NEAR_NODE_CONFIG_FILE" ] && [ -r "$MPC_NODE_CONFIG_FILE" ]; then
    echo "Near and MPC nodes are already initialized"
else
    echo "Initializing Near and MPC nodes"
    initialize_near_node $HOME_DIR && echo "Near node initialized"
    initialize_mpc_config $MPC_NODE_CONFIG_FILE && echo "MPC node initialized"
fi

# Check if MPC_SECRET_STORE_KEY is empty - if so, fetch from GCP Secret Manager
if [ -z "${MPC_SECRET_STORE_KEY}" ]; then
  echo "MPC_SECRET_STORE_KEY not provided in environment, will fetch from GCP Secret Manager..."
  export MPC_SECRET_STORE_KEY=$(gcloud secrets versions access latest --project $GCP_PROJECT_ID --secret=$GCP_LOCAL_ENCRYPTION_KEY_SECRET_ID)
else
  echo "Using provided MPC_SECRET_STORE_KEY from environment"
fi

# Check if MPC_P2P_PRIVATE_KEY is empty - if so, fetch from GCP Secret Manager
if [ -z "${MPC_P2P_PRIVATE_KEY}" ]; then
  echo "MPC_P2P_PRIVATE_KEY not provided in environment, will fetch from GCP Secret Manager..."
  export MPC_P2P_PRIVATE_KEY=$(gcloud secrets versions access latest --project $GCP_PROJECT_ID --secret=$GCP_P2P_PRIVATE_KEY_SECRET_ID)
else
  echo "Using provided MPC_P2P_PRIVATE_KEY from environment"
fi

# Check if MPC_ACCOUNT_SK is empty - if so, fetch from GCP Secret Manager
if [ -z "${MPC_ACCOUNT_SK}" ]; then
  echo "MPC_ACCOUNT_SK not provided in environment, will fetch from GCP Secret Manager..."
  export MPC_ACCOUNT_SK=$(gcloud secrets versions access latest --project $GCP_PROJECT_ID --secret=$GCP_ACCOUNT_SK_SECRET_ID)
else
  echo "Using provided MPC_ACCOUNT_SK from environment"
fi


echo "Starting mpc node..."
/app/mpc-node start
