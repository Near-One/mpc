use crate::indexer::participants::KeyEventIdComparisonResult;
use crate::indexer::types::{
    ChainStartKeygenArgs, ChainStartReshareArgs, ChainVoteAbortKeyEventArgs,
};
use crate::network::MeshNetworkClient;
use crate::providers::eddsa::{EddsaSignatureProvider, EddsaTaskId};
use crate::providers::{EcdsaTaskId, PublicKeyConversion};
use crate::tracking::AutoAbortTaskCollection;
use crate::{
    config::ParticipantsConfig,
    indexer::{
        participants::ContractKeyEventInstance,
        types::{ChainSendTransactionRequest, ChainVotePkArgs, ChainVoteResharedArgs},
    },
    keyshare::{Keyshare, KeyshareData, KeyshareStorage},
    network::NetworkTaskChannel,
    providers::{EcdsaSignatureProvider, SignatureProvider},
};
use cait_sith::{frost_ed25519, frost_secp256k1};
use mpc_contract::primitives::domain::{DomainConfig, SignatureScheme};
use mpc_contract::primitives::key_state::{KeyEventId, KeyForDomain, Keyset};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

/// The key generation computation (same for both leader and follower) for a single key generation
/// attempt:
/// - reserves the key_id in keyshare_storage and performs sanity checks
/// - runs the distributed computation with other participants
/// - commits the new keyshare to storage.
/// - votes for the generated public key.
pub async fn keygen_computation_inner(
    channel: NetworkTaskChannel,
    keyshare_storage: Arc<KeyshareStorage>,
    chain_txn_sender: mpsc::Sender<ChainSendTransactionRequest>,
    generated_keys: Vec<KeyForDomain>,
    key_id: KeyEventId,
    domain: DomainConfig,
    threshold: usize,
) -> anyhow::Result<()> {
    anyhow::ensure!(key_id.domain_id == domain.id, "Domain mismatch");
    let keyshare_handle = keyshare_storage
        .start_generating_key(&generated_keys, key_id)
        .await?;
    tracing::info!(
        "Key generation attempt {:?}: starting key generation.",
        key_id
    );

    let (keyshare, public_key) = match domain.scheme {
        SignatureScheme::Secp256k1 => {
            let keyshare =
                EcdsaSignatureProvider::run_key_generation_client(threshold, channel).await?;
            let public_key = keyshare.public_key.to_near_public_key()?;
            (KeyshareData::Secp256k1(keyshare), public_key)
        }
        SignatureScheme::Ed25519 => {
            let keyshare =
                EddsaSignatureProvider::run_key_generation_client(threshold, channel).await?;
            let public_key = keyshare.public_key.to_near_public_key()?;
            (KeyshareData::Ed25519(keyshare), public_key)
        }
    };

    tracing::info!("Key generation attempt {:?}: committing keyshare.", key_id);
    keyshare_handle
        .commit_keyshare(Keyshare {
            key_id,
            data: keyshare,
        })
        .await?;
    tracing::info!(
        "Key generation attempt {:?}: sending vote_pk transaction.",
        key_id
    );
    chain_txn_sender
        .send(ChainSendTransactionRequest::VotePk(ChainVotePkArgs {
            key_event_id: key_id,
            public_key,
        }))
        .await?;
    Ok(())
}

/// Wrapper around `keygen_computation_inner` which
///  - Waits for the key event to start.
///  - Interrupts the inner computation if the key event expires.
///  - Sends a `vote_abort_key_event_instance` transaction if the inner computation fails.
async fn keygen_computation(
    mut contract_key_event_id: watch::Receiver<ContractKeyEventInstance>,
    channel: NetworkTaskChannel,
    keyshare_storage: Arc<KeyshareStorage>,
    chain_txn_sender: mpsc::Sender<ChainSendTransactionRequest>,
    key_id: KeyEventId,
    threshold: usize,
) -> anyhow::Result<()> {
    let key_event = wait_for_contract_catchup(&mut contract_key_event_id, key_id).await;
    let inner = keygen_computation_inner(
        channel,
        keyshare_storage,
        chain_txn_sender.clone(),
        key_event.completed_domains,
        key_id,
        key_event.domain,
        threshold,
    );
    let expiration = key_event_id_expiration(contract_key_event_id, key_id);
    tokio::select! {
        res = inner => {
            match res {
                Ok(()) => {
                    tracing::info!("Key generation attempt {:?} completed successfully.", key_id);
                },
                Err(err) => {
                    tracing::error!("Key generation attempt {:?} failed: {:?}; sending vote_abort_key_event_instance", key_id, err);
                    chain_txn_sender.send(ChainSendTransactionRequest::VoteAbortKeyEvent(ChainVoteAbortKeyEventArgs {
                        key_event_id: key_id,
                    })).await?;
                },
            }
        },
        _ = expiration => anyhow::bail!("Key event expired before computation completed."),
    }
    Ok(())
}

#[derive(Clone)]
pub struct ResharingArgs {
    pub previous_keyset: Keyset,
    pub existing_keyshares: Option<Vec<Keyshare>>,
    pub new_threshold: usize,
    pub old_participants: ParticipantsConfig,
}

/// The key resharing computation (same for both leader and follower) for a single key resharing
/// attempt:
/// - reserves the key_id in keyshare_storage and performs sanity checks
/// - runs the key resharing distributed computation with other participants
/// - commits the new keyshare to storage
/// - votes on the contract to conclude the resharing.
///
/// If existing keyshares in `ResharingArgs` is not None, then they must contain a matching keyshare
/// of same domain as `key_id`.
async fn resharing_computation_inner(
    channel: NetworkTaskChannel,
    keyshare_storage: Arc<KeyshareStorage>,
    chain_txn_sender: mpsc::Sender<ChainSendTransactionRequest>,
    reshared_keys: Vec<KeyForDomain>,
    key_id: KeyEventId,
    domain: DomainConfig,
    args: Arc<ResharingArgs>,
) -> anyhow::Result<()> {
    anyhow::ensure!(key_id.domain_id == domain.id, "Domain mismatch");
    let keyshare_handle = keyshare_storage
        .start_resharing_key(&reshared_keys, key_id)
        .await?;
    tracing::info!(
        "Key resharing attempt {:?}: starting key resharing.",
        key_id
    );
    let existing_keyshare = match &args.existing_keyshares {
        Some(existing_keyshares) => Some(
            existing_keyshares
                .iter()
                .find(|keyshare| keyshare.key_id.domain_id == key_id.domain_id)
                .cloned()
                .ok_or_else(|| {
                    anyhow::anyhow!("Expected existing keyshare for {:?} not found", key_id)
                })?,
        ),
        None => None,
    };

    let previous_public_key = &args
        .previous_keyset
        .public_key(key_id.domain_id)
        .map_err(|_| anyhow::anyhow!("Previous keyset does not contain key for {:?}", key_id))?;

    let near_public_key = previous_public_key.as_ref();

    let keyshare_data = match domain.scheme {
        SignatureScheme::Secp256k1 => {
            let public_key = frost_secp256k1::VerifyingKey::from_near_sdk(near_public_key)?;
            let my_share = existing_keyshare
                .map(|keyshare| match keyshare.data {
                    KeyshareData::Secp256k1(data) => Ok(data.private_share),
                    _ => Err(anyhow::anyhow!("Expected ecdsa keyshare!")),
                })
                .transpose()?;
            let res = EcdsaSignatureProvider::run_key_resharing_client(
                args.new_threshold,
                my_share,
                public_key,
                &args.old_participants,
                channel,
            )
            .await?;
            KeyshareData::Secp256k1(res)
        }
        SignatureScheme::Ed25519 => {
            let public_key = frost_ed25519::VerifyingKey::from_near_sdk(near_public_key)?;
            let my_share = existing_keyshare
                .map(|keyshare| match keyshare.data {
                    KeyshareData::Ed25519(data) => Ok(data.private_share),
                    _ => Err(anyhow::anyhow!("Expected eddsa keyshare!")),
                })
                .transpose()?;
            let res = EddsaSignatureProvider::run_key_resharing_client(
                args.new_threshold,
                my_share,
                public_key,
                &args.old_participants,
                channel,
            )
            .await?;
            KeyshareData::Ed25519(res)
        }
    };
    tracing::info!("Key resharing attempt {:?}: committing keyshare.", key_id);
    keyshare_handle
        .commit_keyshare(Keyshare {
            key_id,
            data: keyshare_data,
        })
        .await?;
    tracing::info!(
        "Key resharing attempt {:?}: sending vote_reshared transaction.",
        key_id
    );
    chain_txn_sender
        .send(ChainSendTransactionRequest::VoteReshared(
            ChainVoteResharedArgs {
                key_event_id: key_id,
            },
        ))
        .await?;
    Ok(())
}

/// Wrapper around `resharing_computation_inner` which
///  - Waits for the key event to start.
///  - Interrupts the inner computation if the key event expires.
///  - Sends a `vote_abort_key_event_instance` transaction if the inner computation fails.
async fn resharing_computation(
    mut contract_key_event_id: watch::Receiver<ContractKeyEventInstance>,
    channel: NetworkTaskChannel,
    keyshare_storage: Arc<KeyshareStorage>,
    chain_txn_sender: mpsc::Sender<ChainSendTransactionRequest>,
    key_id: KeyEventId,
    args: Arc<ResharingArgs>,
) -> anyhow::Result<()> {
    let key_event = wait_for_contract_catchup(&mut contract_key_event_id, key_id).await;
    let inner = resharing_computation_inner(
        channel,
        keyshare_storage,
        chain_txn_sender.clone(),
        key_event.completed_domains,
        key_id,
        key_event.domain,
        args,
    );
    let expiration = key_event_id_expiration(contract_key_event_id, key_id);
    tokio::select! {
        res = inner => {
            match res {
                Ok(()) => {
                    tracing::info!("Key resharing attempt {:?} completed successfully.", key_id);
                },
                Err(err) => {
                    tracing::error!("Key resharing attempt {:?} failed: {:?}; sending vote_abort_key_event_instance", key_id, err);
                    chain_txn_sender.send(ChainSendTransactionRequest::VoteAbortKeyEvent(ChainVoteAbortKeyEventArgs {
                        key_event_id: key_id,
                    })).await?;
                },
            }
        },
        _ = expiration => anyhow::bail!("Key event expired before computation completed."),
    }
    Ok(())
}

/// Waits until the contract is no longer behind the key event ID.
///
/// By the time this function exits, it's possible the contract is already ahead of the key event
/// ID; that is fine.
async fn wait_for_contract_catchup(
    key_event_receiver: &mut watch::Receiver<ContractKeyEventInstance>,
    key_event_id: KeyEventId,
) -> ContractKeyEventInstance {
    key_event_receiver
        .wait_for(|contract_event| {
            !matches!(
                contract_event.compare_to_expected_key_event_id(&key_event_id),
                KeyEventIdComparisonResult::RemoteBehind
            )
        })
        .await
        .expect("Should not fail since closure does not panic")
        .clone()
}

/// Resolves as soon as the contract has moved past the key event ID.
async fn key_event_id_expiration(
    mut key_event_receiver: watch::Receiver<ContractKeyEventInstance>,
    key_event_id: KeyEventId,
) {
    key_event_receiver
        .wait_for(|contract_event| {
            matches!(
                contract_event.compare_to_expected_key_event_id(&key_event_id),
                KeyEventIdComparisonResult::RemoteAhead
            )
        })
        .await
        .expect("Should not fail since closure does not panic");
}

/// The leader waits for at most this amount of time for the start transaction to materialize,
/// before retrying.
const MAX_LATENCY_BEFORE_EXPECTING_TRANSACTION_TO_FINALIZE: Duration = Duration::from_secs(20);

/// The leader logic for an entire key generation (initializing) state.
/// Handles multiple domains and attempts. It does not return, except in case of catastrophic
/// failure (node shutting down). The coordinator is expected to interrupt this when the
/// contract state transitions out of the key generation state.
pub async fn keygen_leader(
    client: Arc<MeshNetworkClient>,
    keyshare_storage: Arc<KeyshareStorage>,
    mut key_event_receiver: watch::Receiver<ContractKeyEventInstance>,
    chain_txn_sender: mpsc::Sender<ChainSendTransactionRequest>,
    threshold: usize,
) -> anyhow::Result<()> {
    loop {
        // Wait for all participants to be connected. Otherwise, computations are most likely going
        // to fail so don't waste the effort.
        client.leader_wait_for_all_connected().await?;

        // Wait for the contract to have no active key event instance.
        let key_event_id = key_event_receiver
            .wait_for(|contract_event| !contract_event.started)
            .await?
            .id;
        // Send txn to start the keygen instance. This may or may not end up in the chain; we'll
        // wait for it. If it doesn't happen after some time, we try again.
        chain_txn_sender
            .send(ChainSendTransactionRequest::StartKeygen(
                ChainStartKeygenArgs { key_event_id },
            ))
            .await?;

        match timeout(
            MAX_LATENCY_BEFORE_EXPECTING_TRANSACTION_TO_FINALIZE,
            key_event_receiver.wait_for(|contract_event| contract_event.started),
        )
        .await
        {
            Ok(res) => {
                let contract_key_event_id = res?.id;
                if contract_key_event_id != key_event_id {
                    tracing::warn!(
                        "Activated key event {:?} does not match expected {:?}; retrying.",
                        contract_key_event_id,
                        key_event_id
                    );
                    continue;
                }
            }
            Err(_) => {
                tracing::warn!(
                    "Key event {:?} did not activate in time; retrying.",
                    key_event_id
                );
                continue;
            }
        }

        // Start the keygen computation.
        let Ok(channel) = client.new_channel_for_task(
            EcdsaTaskId::KeyGeneration {
                key_event: key_event_id,
            },
            client.all_participant_ids(),
        ) else {
            tracing::warn!("Failed to create channel for keygen computation; retrying.");
            continue;
        };

        if let Err(e) = keygen_computation(
            key_event_receiver.clone(),
            channel,
            keyshare_storage.clone(),
            chain_txn_sender.clone(),
            key_event_id,
            threshold,
        )
        .await
        {
            tracing::warn!(
                "Leader keygen computation {:?} failed, retrying: {:?}",
                key_event_id,
                e
            );
        }
    }
}

/// The follower logic for an entire key generation (initializing) state.
/// See `keygen_leader` for more details that are in common.
pub async fn keygen_follower(
    mut channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannel>,
    keyshare_storage: Arc<KeyshareStorage>,
    key_event_receiver: watch::Receiver<ContractKeyEventInstance>,
    chain_txn_sender: mpsc::Sender<ChainSendTransactionRequest>,
    threshold: usize,
) -> anyhow::Result<()> {
    let mut tasks = AutoAbortTaskCollection::new();
    loop {
        let channel = channel_receiver
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("Channel receiver closed unexpectedly; exiting."))?;
        let key_event_id = match channel.task_id() {
            crate::primitives::MpcTaskId::EcdsaTaskId(EcdsaTaskId::KeyGeneration { key_event }) => {
                key_event
            }
            crate::primitives::MpcTaskId::EddsaTaskId(EddsaTaskId::KeyGeneration { key_event }) => {
                key_event
            }
            _ => {
                tracing::info!("Ignoring non-keygen task {:?}", channel.task_id());
                continue;
            }
        };

        tasks.spawn_checked(
            &format!("Key generation follower for {:?}", key_event_id),
            keygen_computation(
                key_event_receiver.clone(),
                channel,
                keyshare_storage.clone(),
                chain_txn_sender.clone(),
                key_event_id,
                threshold,
            ),
        );
    }
}

/// The leader logic for an entire key resharing state.
/// See `keygen_leader` for more details that are in common.
pub async fn resharing_leader(
    client: Arc<MeshNetworkClient>,
    keyshare_storage: Arc<KeyshareStorage>,
    mut key_event_receiver: watch::Receiver<ContractKeyEventInstance>,
    chain_txn_sender: mpsc::Sender<ChainSendTransactionRequest>,
    args: Arc<ResharingArgs>,
) -> anyhow::Result<()> {
    loop {
        // Wait for all participants to be connected. Otherwise, computations are most likely going
        // to fail so don't waste the effort.
        client.leader_wait_for_all_connected().await?;

        // Wait for the contract to have no active key event instance.
        let key_event_id = key_event_receiver
            .wait_for(|contract_event| !contract_event.started)
            .await?
            .id;
        // Send txn to start the resharing instance. This may or may not end up in the chain; we'll
        // wait for it. If it doesn't happen after some time, we try again.
        chain_txn_sender
            .send(ChainSendTransactionRequest::StartReshare(
                ChainStartReshareArgs { key_event_id },
            ))
            .await?;

        match timeout(
            MAX_LATENCY_BEFORE_EXPECTING_TRANSACTION_TO_FINALIZE,
            key_event_receiver.wait_for(|contract_event| contract_event.id == key_event_id),
        )
        .await
        {
            Ok(res) => {
                res?;
            }
            Err(_) => {
                tracing::warn!(
                    "Key event {:?} did not activate in time; retrying.",
                    key_event_id
                );
                continue;
            }
        }

        // Start the resharing computation.
        let Ok(channel) = client.new_channel_for_task(
            EcdsaTaskId::KeyResharing {
                key_event: key_event_id,
            },
            client.all_participant_ids(),
        ) else {
            tracing::warn!("Failed to create channel for resharing computation; retrying.");
            continue;
        };

        if let Err(e) = resharing_computation(
            key_event_receiver.clone(),
            channel,
            keyshare_storage.clone(),
            chain_txn_sender.clone(),
            key_event_id,
            args.clone(),
        )
        .await
        {
            tracing::warn!(
                "Leader resharing computation {:?} failed, retrying: {:?}",
                key_event_id,
                e
            );
        }
    }
}

/// The follower logic for an entire key resharing state.
/// See `keygen_leader` for more details that are in common.
pub async fn resharing_follower(
    mut channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannel>,
    keyshare_storage: Arc<KeyshareStorage>,
    key_event_receiver: watch::Receiver<ContractKeyEventInstance>,
    chain_txn_sender: mpsc::Sender<ChainSendTransactionRequest>,
    args: Arc<ResharingArgs>,
) -> anyhow::Result<()> {
    let mut tasks = AutoAbortTaskCollection::new();
    loop {
        let channel = channel_receiver
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("Channel receiver closed unexpectedly; exiting."))?;
        let key_event_id = match channel.task_id() {
            crate::primitives::MpcTaskId::EcdsaTaskId(EcdsaTaskId::KeyResharing { key_event }) => {
                key_event
            }
            crate::primitives::MpcTaskId::EddsaTaskId(EddsaTaskId::KeyResharing { key_event }) => {
                key_event
            }
            _ => {
                // TODO: Make a new type, such that the channel only sends resharing tasks.
                tracing::info!("Ignoring non-resharing task {:?}", channel.task_id());
                continue;
            }
        };

        tasks.spawn_checked(
            &format!("Key resharing follower for {:?}", key_event_id),
            resharing_computation(
                key_event_receiver.clone(),
                channel,
                keyshare_storage.clone(),
                chain_txn_sender.clone(),
                key_event_id,
                args.clone(),
            ),
        );
    }
}
