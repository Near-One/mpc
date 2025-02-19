# MPC Cluster Management Scripts

This directory contains scripts for deploying and managing a Dev MPC cluster on NEAR testnet. These scripts automate the process of creating, deploying, and managing MPC nodes.

## Prerequisites

- NEAR CLI installed and configured
- Rust toolchain with `wasm32-unknown-unknown` target
- `jq` for JSON processing
- `uuidgen` utility
- Bash shell environment

## Scripts Overview

### 1. deploy.sh

Initializes a new MPC cluster from scratch.

Options:
- `-t, --threshold`: Number of signatures required (default: 2)
- `-p, --participants`: Number of initial participants (default: 2)

This script:
- Creates a signer account
- Deploys the MPC contract
- Generates cryptographic keys for participants
- Creates participant accounts
- Initializes the contract
- Generates `nodes.tfvars.json` for infrastructure deployment

### 2. add_nodes.sh

Adds new nodes to an existing MPC cluster.

This script:
- Generates new keys for additional nodes
- Updates the `nodes.tfvars.json` configuration
- Creates NEAR accounts for new nodes
- Issues join requests for new nodes

### 3. join_vote.sh

Manages the voting process for adding a new node to the cluster.

```bash
./join_vote.sh <candidate_index>
```

This script:
- Issues a join request for the candidate node
- Collects votes from existing cluster members

## Typical Workflow

1. **Initial Deployment**
   ```bash
   # Deploy a new cluster with 3 nodes and threshold of 2
   ./deploy.sh -p 3 -t 2
   ```

2. **Adding New Nodes**
   ```bash
   # Add 2 more nodes to the cluster
   ./add_nodes.sh 2
   ```

3. **Infrastructure Deployment**
   ```bash
   # Use updated `nodes.tfvars.json` with Terraform:
   run tf apply -var-file=\$path_to_nodes.tfvars.json in your cluster infra and nomad jobs folders
   ```

1. **Voting Process** (if needed)
   ```bash
   # Process votes for node index 3
   ./join_vote.sh 3
   ```

## Configuration Files

The scripts generate and use a `devnet_configs/nodes.tfvars.json` file containing:
- Node account information
- Node keys
- Contract configuration
- Cluster UUID

## Important Notes

- Keep the signer account information secure
- Backup the `nodes.tfvars.json` file
- The threshold must be less than or equal to the number of participants
- New nodes require approval votes from existing nodes to join the cluster

## Error Handling

If a script fails:
1. Check the error message
2. Verify all prerequisites are installed
3. Ensure NEAR CLI is properly configured
4. Confirm the `nodes.tfvars.json` exists when adding nodes
