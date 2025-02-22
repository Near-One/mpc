#!/bin/bash
set -eo pipefail


# This script is intended to be used for running nearone/mpc in a GCP environment. 
# It will initialize the Near node in case it is not initialized yet and start the MPC node.


HOME_DIR="/data"
MPC_NODE_CONFIG_FILE="$HOME_DIR/config.yaml"
NEAR_NODE_CONFIG_FILE="$HOME_DIR/config.json"

initialize_near_node() {
    ./mpc-node init --dir $1 --chain-id $MPC_ENV --download-genesis --download-config && echo "Near node initialized"
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

# Check and initialize Near node config if needed
if [ -r "$NEAR_NODE_CONFIG_FILE" ]; then
    echo "Near node is already initialized"
else
    echo "Initializing Near node"
    initialize_near_node $HOME_DIR && echo "Near node initialized"
fi

# Check and initialize MPC config if needed
if [ -r "$MPC_NODE_CONFIG_FILE" ]; then
    echo "MPC node is already initialized"
else
    echo "Initializing MPC node"
    initialize_mpc_config $MPC_NODE_CONFIG_FILE && echo "MPC node initialized"
fi

# GCP_PROJECT_ID: the project name (used to fetch secrets below).
# Same as MPC_GCP_PROJECT_ID in the near/mpc deployment.
echo Using GCP_PROJECT_ID=${GCP_PROJECT_ID:?"GCP_PROJECT_ID is required"}
# GCP_KEYSHARE_SECRET_ID: the secret id for the root keyshare.
# Same as MPC_SK_SHARE_SECRET_ID in the near/mpc deployment.
echo Using GCP_KEYSHARE_SECRET_ID=${GCP_KEYSHARE_SECRET_ID:?"GCP_KEYSHARE_SECRET_ID is required"}
# GCP_LOCAL_ENCRYPTION_KEY_SECRET_ID: asymmetric AES key for local DB encryption.
# **This is a new secret**. Prior to running nearone/mpc, you need to create this
# secret to be any random 16 bytes, hex-encoded as a 32 character string. This is
# used to encrypt the local database containing triples and presignatures.
echo Using GCP_LOCAL_ENCRYPTION_KEY_SECRET_ID=${GCP_LOCAL_ENCRYPTION_KEY_SECRET_ID:?"GCP_LOCAL_ENCRYPTION_KEY_SECRET_ID is required"}
# GCP_P2P_PRIVATE_KEY_SECRET_ID: the secret id for the P2P private key.
# nearone/mpc uses TLS instead of custom encryption for mesh communication.
# Therefore, only one key is needed rather than two before.
# The previous GCP secret ID whose value would be passed to MPC_SIGN_SK for
# the near/mpc binary should be passed in here. The secret's payload should
# be a private key in the format of ed25519:<base58 encoded private key>.
echo Using GCP_P2P_PRIVATE_KEY_SECRET_ID=${GCP_P2P_PRIVATE_KEY_SECRET_ID:?"GCP_P2P_PRIVATE_KEY_SECRET_ID is required"}
# GCP_ACCOUNT_SK_SECRET_ID: the secret id for the Near account secret key.
# The previous GCP secret ID whose value would be passed to MPC_ACCOUNT_SK
# for the near/mpc binary should be passed in here. The secret's payload should
# be a private key in the format of ed25519:<base58 encoded private key>.
echo Using GCP_ACCOUNT_SK_SECRET_ID=${GCP_ACCOUNT_SK_SECRET_ID:?"GCP_ACCOUNT_SK_SECRET_ID is required"}

# Note that other non-secret configurations are passed in config.yaml.

echo "Fetching local encryption key from GCP secret manager..."
LOCAL_ENCRYPTION_KEY=$(gcloud secrets versions access latest --project $GCP_PROJECT_ID --secret=$GCP_LOCAL_ENCRYPTION_KEY_SECRET_ID)
echo "Fetching P2P private key from GCP secret manager..."
P2P_PRIVATE_KEY=$(gcloud secrets versions access latest --project $GCP_PROJECT_ID --secret=$GCP_P2P_PRIVATE_KEY_SECRET_ID)
echo "Fetching account secret key from GCP secret manager..."
ACCOUNT_SK=$(gcloud secrets versions access latest --project $GCP_PROJECT_ID --secret=$GCP_ACCOUNT_SK_SECRET_ID)

echo "Starting mpc node..."
GCP_PROJECT_ID="${GCP_PROJECT_ID}" \
GCP_KEYSHARE_SECRET_ID="${GCP_KEYSHARE_SECRET_ID}" \
MPC_SECRET_STORE_KEY=${LOCAL_ENCRYPTION_KEY} \
MPC_P2P_PRIVATE_KEY=${P2P_PRIVATE_KEY} \
MPC_ACCOUNT_SK=${ACCOUNT_SK} \
/app/mpc-node start
