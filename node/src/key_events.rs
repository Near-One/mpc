use std::{str::FromStr, sync::Arc};

use k256::AffinePoint;
use mpc_contract::primitives::key_state::{KeyEventId, Keyset};
use tokio::sync::{mpsc, watch};

use crate::{
    config::ParticipantsConfig,
    hkdf::affine_point_to_public_key,
    indexer::{
        participants::ContractKeyEventInstance,
        types::{
            ChainSendTransactionRequest, ChainStartKeygenArgs, ChainStartReshareArgs,
            ChainVotePkArgs, ChainVoteResharedArgs,
        },
    },
    keyshare::{Keyshare, KeyshareData, KeyshareStorage},
    network::{MeshNetworkClient, NetworkTaskChannel},
    primitives::{MpcTaskId, ParticipantId},
    providers::{
        ecdsa::key_resharing::public_key_to_affine_point, EcdsaSignatureProvider, EcdsaTaskId,
        SignatureProvider,
    },
};

/// Handles the leader side of an ECDSA key generation task.
/// - Initiates a new network channel for key generation with all participants.
/// - Broadcasts the start of the key generation process on-chain.
/// - Executes the key generation protocol using the provided threshold.
/// - Stores the generated keyshare in local storage.
/// - Signals completion by voting on-chain with the generated public key.
pub async fn keygen_leader(
    key_id: KeyEventId,
    chain_txn_sender: &mpsc::Sender<ChainSendTransactionRequest>,
    network_client: Arc<MeshNetworkClient>,
    threshold: usize,
    keyshare_storage: &KeyshareStorage,
) -> anyhow::Result<()> {
    tracing::info!("Leader is starting ecdsa secp256k1 keygen {:?}", key_id);
    // open the channel
    let channel = network_client.new_channel_for_task(
        EcdsaTaskId::KeyGeneration { key_event: key_id },
        network_client.all_participant_ids(),
    )?;
    tracing::info!("leader vote starts keygen: {:?}", channel.task_id());
    chain_txn_sender
        .send(ChainSendTransactionRequest::StartKeygen(
            ChainStartKeygenArgs {},
        ))
        .await?;
    tracing::info!("sent start keygen, starting computation");
    let res = EcdsaSignatureProvider::run_key_generation_client(threshold, channel).await;
    let res = match res {
        Ok(res) => res,
        Err(e) => anyhow::bail!("error: {}", e),
    };
    tracing::info!("leader concluded computation, storing keyshare.");
    let keyshare = Keyshare {
        key_id,
        data: KeyshareData::Secp256k1(res.clone()),
    };
    keyshare_storage.store_key(keyshare).await?;
    tracing::info!("leader stored keyshare.");
    let my_public_key = affine_point_to_public_key(res.public_key)?;
    tracing::info!("Key generation complete; Leader calls vote_pk.");
    chain_txn_sender
        .send(ChainSendTransactionRequest::VotePk(ChainVotePkArgs {
            key_event_id: key_id,
            public_key: my_public_key,
        }))
        .await?;
    Ok(())
}

/// Handles the follower side of an ECDSA key generation task.
/// - Waits for a new network task channel from `channel_receiver`.
/// - Ignores non-key generation tasks until a valid one is received.
/// - Waits for the corresponding key event from `key_event_receiver` to begin.
/// - Skips execution if this participant has already completed the key generation.
/// - Executes the key generation protocol using the received channel and threshold.
/// - Stores the generated keyshare in local storage.
/// - Signals completion by voting on-chain with the generated public key.
pub async fn keygen_follower(
    chain_txn_sender: &mpsc::Sender<ChainSendTransactionRequest>,
    threshold: usize,
    my_participant_id: ParticipantId,
    keyshare_storage: &KeyshareStorage,
    key_event_receiver: &mut watch::Receiver<ContractKeyEventInstance>,
    channel_receiver: &mut mpsc::UnboundedReceiver<NetworkTaskChannel>,
) -> anyhow::Result<()> {
    let channel = channel_receiver.recv().await.unwrap();
    let key_id = loop {
        let task_id = channel.task_id();
        if let MpcTaskId::EcdsaTaskId(EcdsaTaskId::KeyGeneration { key_event: key_id }) = task_id {
            break key_id;
        } else {
            tracing::info!(
                "Expected Keygeneration task id, received: {:?}; ignoring.",
                task_id,
            );
        };
    };
    tracing::info!(
        "Received Keygeneration task id: {:?}. Our id; {:?}",
        key_id,
        my_participant_id,
    );
    let contract_event = wait_for_start(key_event_receiver, key_id).await?;
    tracing::info!(
        "Key Generation {:?} started on contract. Our id: {}",
        key_id,
        my_participant_id
    );
    if contract_event.completed.contains(&my_participant_id) {
        anyhow::bail!("We already completed this key generation. Why is there a second attempt?");
    }
    tracing::info!(
        "Joining ecdsa secp256k1 key generation for key id {:?} as follower: {:?}",
        contract_event.id,
        my_participant_id
    );
    let res = EcdsaSignatureProvider::run_key_generation_client(threshold, channel).await?;
    tracing::info!("Ecdsa secp256k1 key generation completed.");
    let keyshare = Keyshare {
        key_id: contract_event.id,
        data: KeyshareData::Secp256k1(res.clone()),
    };
    keyshare_storage.store_key(keyshare).await?;
    tracing::info!("Key generation complete; Follower calls vote_pk.");
    chain_txn_sender
        .send(ChainSendTransactionRequest::VotePk(ChainVotePkArgs {
            key_event_id: contract_event.id,
            public_key: affine_point_to_public_key(res.public_key)?,
        }))
        .await?;
    Ok(())
}

/// Handles the leader side of a key resharing task.
/// - Checks if the resharing has already started; exits if this participant has already completed it.
/// - Initiates a new network channel for resharing with all participants.
/// - Broadcasts the start of the resharing process on-chain.
/// - Executes the resharing protocol using the existing keyshare and public key.
/// - Stores the resulting new keyshare.
/// - Signals resharing completion by voting on-chain.
pub async fn resharing_leader(
    keys: &ResharingKeys,
    args: &ResharingArgs,
    my_participant_id: ParticipantId,
    contract_event: ContractKeyEventInstance,
    chain_txn_sender: &mpsc::Sender<ChainSendTransactionRequest>,
    network_client: &Arc<MeshNetworkClient>,
) -> anyhow::Result<()> {
    if contract_event.started {
        if !contract_event.completed.contains(&my_participant_id) {
            // todo: vote abort on the contract
            anyhow::bail!("should not happen");
        } else {
            return Ok(());
        }
    }
    let key_id = contract_event.id;
    tracing::info!(
        "leader {} is starting resharing for key {:?} with keyshare {:?}",
        my_participant_id,
        key_id,
        keys.existing_keyshares
    );
    let channel = network_client.new_channel_for_task(
        EcdsaTaskId::KeyResharing { key_event: key_id },
        network_client.all_participant_ids(),
    )?;
    chain_txn_sender
        .send(ChainSendTransactionRequest::StartReshare(
            ChainStartReshareArgs {},
        ))
        .await?;
    let my_share = keys
        .existing_keyshares
        .iter()
        .find(|share| share.key_id.domain_id == key_id.domain_id)
        .map(|share| share.data.clone())
        .map(|KeyshareData::Secp256k1(data)| data.private_share);
    let public_key = convert(&keys.previous_keyset.public_key(key_id.domain_id).unwrap())?;
    let res = EcdsaSignatureProvider::run_key_resharing_client(
        args.new_threshold,
        my_share,
        public_key,
        &args.old_participants,
        channel,
    )
    .await?;
    let keyshare = Keyshare {
        key_id,
        data: KeyshareData::Secp256k1(res.clone()),
    };
    keys.keyshare_storage.store_key(keyshare).await?;
    tracing::info!("Key resharing complete; Leader votes for completion.");
    chain_txn_sender
        .send(ChainSendTransactionRequest::VoteReshared(
            crate::indexer::types::ChainVoteResharedArgs {
                key_event_id: key_id,
            },
        ))
        .await?;
    Ok(())
}

/// Waits for the specified key event to start.
/// - Listens for updates on `key_event_receiver` until the event with `key_event_id` is marked as started.
/// - Times out after 60 seconds if the event does not start.
/// - Returns the updated `ContractKeyEventInstance` once started, or errors if the event ID changes or times out.
async fn wait_for_start(
    key_event_receiver: &mut watch::Receiver<ContractKeyEventInstance>,
    key_event_id: KeyEventId,
) -> anyhow::Result<ContractKeyEventInstance> {
    let contract_event = key_event_receiver
        .wait_for(|contract_event| contract_event.started || (contract_event.id != key_event_id))
        .await?;
    if contract_event.id != key_event_id {
        anyhow::bail!(
            "Computation's key event ({:?}) does not match current from contract ({:?})",
            key_event_id,
            contract_event.id
        );
    }
    Ok(contract_event.clone())
}

fn convert(public_key: &near_sdk::PublicKey) -> anyhow::Result<AffinePoint> {
    let public_key = near_crypto::PublicKey::from_str(&String::from(public_key));
    public_key_to_affine_point(public_key.unwrap())
}

pub struct ResharingKeys {
    pub previous_keyset: Keyset,
    pub existing_keyshares: Vec<Keyshare>,
    pub keyshare_storage: KeyshareStorage,
}

pub struct ResharingArgs {
    pub new_threshold: usize,
    pub old_participants: ParticipantsConfig,
}

/// Handles the follower side of a key resharing task.
/// - Waits for a new network task channel from `channel_receiver`.
/// - Ignores non-resharing tasks until a resharing task is received.
/// - Waits for the corresponding key event from `key_event_receiver` to begin.
/// - Skips execution if this participant has already completed the resharing.
/// - Executes the resharing protocol using existing keyshares and the provided channel.
/// - Stores the new keyshare and signals completion via a chain transaction vote.
pub async fn resharing_follower(
    keys: &ResharingKeys,
    args: &ResharingArgs,
    my_participant_id: ParticipantId,
    chain_txn_sender: &mpsc::Sender<ChainSendTransactionRequest>,
    key_event_receiver: &mut watch::Receiver<ContractKeyEventInstance>,
    channel_receiver: &mut mpsc::UnboundedReceiver<NetworkTaskChannel>,
) -> anyhow::Result<()> {
    let channel = channel_receiver.recv().await.unwrap();
    let key_id = loop {
        let task_id = channel.task_id();
        if let MpcTaskId::EcdsaTaskId(EcdsaTaskId::KeyResharing { key_event: key_id }) = task_id {
            break key_id;
        } else {
            tracing::info!(
                "Expected Key resharing task id, received: {:?}; ignoring.",
                task_id,
            );
        };
    };
    let contract_event = wait_for_start(key_event_receiver, key_id).await?;
    if contract_event.completed.contains(&my_participant_id) {
        // just return and wait.
        anyhow::bail!("We already completed this resharing. Why is there a second attempt?");
    }
    tracing::info!(
        "Joining ecdsa secp256k1 key resharing for key id {:?} as follower: {} and keyshares: {:?}",
        contract_event.id,
        my_participant_id,
        keys.existing_keyshares
    );
    // join computation
    let my_share = keys
        .existing_keyshares
        .clone()
        .iter()
        .find(|share| share.key_id.domain_id == contract_event.id.domain_id)
        .map(|share| share.data.clone())
        .map(|KeyshareData::Secp256k1(data)| data.private_share);
    let public_key = convert(&keys.previous_keyset.public_key(key_id.domain_id).unwrap())?;
    let res = EcdsaSignatureProvider::run_key_resharing_client(
        args.new_threshold,
        my_share,
        public_key,
        &args.old_participants,
        channel,
    )
    .await?;
    let keyshare = Keyshare {
        key_id: contract_event.id,
        data: KeyshareData::Secp256k1(res),
    };
    keys.keyshare_storage.store_key(keyshare).await?;
    tracing::info!("Key resharing complete; Follower calls vote_pk.");
    chain_txn_sender
        .send(ChainSendTransactionRequest::VoteReshared(
            ChainVoteResharedArgs {
                key_event_id: contract_event.id,
            },
        ))
        .await?;
    Ok(())
}
