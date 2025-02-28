env             = "mainnet"
project_id      = "nearone-multichain"
network         = "default"
subnetwork      = "default"
image           = "docker.io/nearone/mpc-node-gcp:mainnet-release"
region          = "europe-west1"
zone            = "europe-west1-b"
near_boot_nodes = "ed25519:DHowcbPk8DXYbefJgy7p74rqAn1wpJweeYuWmch6DEYd@65.109.70.223:24567,ed25519:2q7pyVVqW2vqYW6KPnoVu1HaPFaTkN2mnD9o76XAy88c@198.244.165.131:24567"
# These will be specific to your node
node_configs = [
  {
    account = "n1-multichain.near"
    # These 4 values below should match your secret names in google secrets manager
    gcp_local_encryption_key_secret_id = "mainnet-multichain-local-encryption-key-0"
    gcp_account_sk_secret_id           = "multichain-account-sk-mainnet-0"
    gcp_p2p_private_key_secret_id      = "multichain-sign-sk-mainnet-0"
    gcp_keyshare_secret_id             = "multichain-sk-share-mainnet-0"
    domain                             = "http://multichain-testnet-0.nearone.org"
  },
]
