use crate::config::{ParticipantInfo, ParticipantsConfig};
use crate::indexer::lib::{get_mpc_contract_state, wait_for_contract_code, wait_for_full_sync};
use crate::primitives::ParticipantId;
use anyhow::Context;
use legacy_mpc_contract;
use near_indexer_primitives::types::AccountId;
use std::collections::{BTreeMap, HashSet};
use std::str::FromStr;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractRunningState {
    pub epoch: u64,
    pub participants: ParticipantsConfig,
    pub root_public_key: near_crypto::PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractInitializingState {
    pub participants: ParticipantsConfig,
    pub pk_votes: BTreeMap<near_crypto::PublicKey, HashSet<AccountId>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractResharingState {
    pub old_epoch: u64,
    pub old_participants: ParticipantsConfig,
    pub new_participants: ParticipantsConfig,
    pub public_key: near_crypto::PublicKey,
    pub finished_votes: std::collections::HashSet<AccountId>,
}

/// A stripped-down version of the contract state, containing only the state
/// that the MPC node cares about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractState {
    WaitingForSync,
    Invalid,
    Initializing(ContractInitializingState),
    Running(ContractRunningState),
    Resharing(ContractResharingState),
}

/// Continuously monitors the contract state. Every time the state changes,
/// sends the new state via the provided sender. This is a long-running task.
pub async fn monitor_chain_state(
    mpc_contract_id: AccountId,
    port_override: Option<u16>,
    view_client: actix::Addr<near_client::ViewClientActor>,
    client: actix::Addr<near_client::ClientActor>,
    contract_state_sender: tokio::sync::watch::Sender<ContractState>,
) -> anyhow::Result<()> {
    const CONTRACT_STATE_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
    let mut prev_state = ContractState::Invalid;
    loop {
        let result = read_contract_state_from_chain(
            mpc_contract_id.clone(),
            port_override,
            view_client.clone(),
            client.clone(),
        )
        .await;
        match result {
            Ok(state) => {
                if state != prev_state {
                    tracing::info!("Contract state changed: {:?}", state);
                    contract_state_sender.send(state.clone()).unwrap();
                    prev_state = state;
                }
            }
            Err(e) => {
                tracing::error!(target: "mpc", "error reading config from chain: {:?}", e);
            }
        }
        tokio::time::sleep(CONTRACT_STATE_REFRESH_INTERVAL).await;
    }
}

async fn read_contract_state_from_chain(
    mpc_contract_id: AccountId,
    port_override: Option<u16>,
    view_client: actix::Addr<near_client::ViewClientActor>,
    client: actix::Addr<near_client::ClientActor>,
) -> anyhow::Result<ContractState> {
    // We wait first to catch up to the chain to avoid reading the participants from an outdated state.
    // We currently assume the participant set is static and do not detect or support any updates.
    tracing::debug!(target: "indexer", "awaiting full sync to read mpc contract state");
    wait_for_full_sync(&client).await;

    // In tests it is possible to catch up to the chain before the contract is even deployed.
    tracing::debug!(target: "indexer", "awaiting mpc contract state");
    wait_for_contract_code(mpc_contract_id.clone(), &view_client).await;

    let state = get_mpc_contract_state(mpc_contract_id.clone(), &view_client).await?;
    tracing::debug!(target: "indexer", "got mpc contract state {:?}", state);
    let state = match state {
        legacy_mpc_contract::ProtocolContractState::NotInitialized => ContractState::Invalid,
        legacy_mpc_contract::ProtocolContractState::Initializing(state) => {
            let mut pk_votes = BTreeMap::new();
            for (pk, votes) in state.pk_votes.votes {
                pk_votes.insert(
                    near_crypto::PublicKey::from_str(&String::from(&pk))
                        .context("parse public key")?,
                    votes.into_iter().collect(),
                );
            }
            ContractState::Initializing(ContractInitializingState {
                participants: convert_participant_infos(
                    state.candidates.into(),
                    port_override,
                    state.threshold,
                )?,
                pk_votes,
            })
        }
        legacy_mpc_contract::ProtocolContractState::Running(state) => {
            ContractState::Running(ContractRunningState {
                epoch: state.epoch,
                participants: convert_participant_infos(
                    state.participants,
                    port_override,
                    state.threshold,
                )?,
                root_public_key: String::from(&state.public_key)
                    .parse()
                    .context("parse public key")?,
            })
        }
        legacy_mpc_contract::ProtocolContractState::Resharing(state) => {
            ContractState::Resharing(ContractResharingState {
                old_epoch: state.old_epoch,
                old_participants: convert_participant_infos(
                    state.old_participants,
                    port_override,
                    state.threshold,
                )?,
                new_participants: convert_participant_infos(
                    state.new_participants,
                    port_override,
                    state.threshold,
                )?,
                public_key: String::from(&state.public_key)
                    .parse()
                    .context("parse public key")?,
                finished_votes: state.finished_votes,
            })
        }
    };
    Ok(state)
}

fn convert_participant_infos(
    participants: legacy_mpc_contract::primitives::Participants,
    port_override: Option<u16>,
    threshold: usize,
) -> anyhow::Result<ParticipantsConfig> {
    let mut converted = Vec::new();
    for (account_id, p) in participants.participants {
        let url = Url::parse(&p.url)
            .with_context(|| format!("could not parse participant url {}", p.url))?;
        let Some(address) = url.host_str() else {
            anyhow::bail!("no host found in participant url {}", p.url);
        };
        let Some(port) = port_override.or(url.port_or_known_default()) else {
            anyhow::bail!("no port found in participant url {}", p.url);
        };
        // Here we need to turn the near_sdk::PublicKey used in the smart contract into a
        // near_crypto::PublicKey used by the mpc nodes. For some reason near_sdk has an
        // impl TryFrom<near_sdk::PublicKey> for near_crypto::PublicKey but it's test-only.
        // For lack of better option we use this to-string from-string conversion instead.
        let Ok(p2p_public_key) = near_crypto::PublicKey::from_str(&String::from(&p.sign_pk)) else {
            anyhow::bail!("invalid participant public key {:?}", p.sign_pk);
        };
        let Some(participant_id) = participants.account_to_participant_id.get(&account_id) else {
            anyhow::bail!(
                "participant account id not found in account_to_participant_id {:?}",
                account_id
            );
        };
        converted.push(ParticipantInfo {
            id: ParticipantId::from_raw(*participant_id),
            address: address.to_string(),
            port,
            p2p_public_key,
            near_account_id: account_id,
        });
    }
    Ok(ParticipantsConfig {
        participants: converted,
        threshold: threshold.try_into()?,
    })
}

#[cfg(test)]
mod tests {
    use crate::indexer::participants::convert_participant_infos;
    use near_indexer_primitives::types::AccountId;
    use std::collections::HashMap;
    use std::str::FromStr;

    fn create_participant_data_raw() -> Vec<(u32, String, String, [u8; 32], String)> {
        vec![
            (
                2,
                "multichain-node-dev-0.testnet".to_string(),
                "http://10.101.0.56:3000".to_string(),
                [
                    90, 157, 29, 39, 252, 60, 149, 46, 122, 247, 162, 241, 200, 79, 85, 41, 40,
                    238, 194, 50, 195, 242, 195, 231, 135, 244, 161, 93, 130, 168, 41, 22,
                ],
                "ed25519:4upBpJYUrjPBzqNYaY8pvJGQtep7YMT3j9zRsopYQqfG".to_string(),
            ),
            (
                1,
                "multichain-node-dev-1.testnet".to_string(),
                "http://10.101.0.81:3000".to_string(),
                [
                    52, 159, 137, 246, 113, 122, 2, 170, 247, 166, 73, 185, 138, 199, 175, 9, 230,
                    81, 127, 253, 76, 183, 234, 138, 159, 110, 222, 232, 248, 74, 51, 12,
                ],
                "ed25519:6sqMFXkswuH9b7Pnn6dGAy1vA1X3N2CSrKDDkdHzTcrv".to_string(),
            ),
            (
                0,
                "multichain-node-dev-2.testnet".to_string(),
                "http://10.101.0.57:3000".to_string(),
                [
                    120, 174, 103, 211, 138, 250, 166, 211, 41, 187, 160, 23, 92, 32, 10, 140, 36,
                    138, 90, 130, 215, 143, 187, 143, 113, 224, 96, 230, 193, 134, 216, 0,
                ],
                "ed25519:Fru1RoC6dw1xY2J6C6ZSBUt5PEysxTLX2kDexxqoDN6k".to_string(),
            ),
        ]
    }

    fn create_invalid_participant_data_raw() -> Vec<(u32, String, String, [u8; 32], String)> {
        // The on-chain participant data is strongly typed with AccountId and near_sdk::PublicKey.
        // It's really only possible to have bad data in the urls, which are arbitrary strings.
        vec![
            // Bad URL format (missing port)
            (
                2,
                "multichain-node-dev-4.testnet".to_string(),
                "http://10.101.0.124".to_string(),
                [
                    77, 77, 246, 133, 91, 43, 56, 37, 237, 43, 127, 75, 236, 251, 226, 234, 124,
                    148, 8, 23, 187, 84, 234, 165, 196, 186, 239, 124, 115, 223, 66, 107,
                ],
                "ed25519:4NfJteMHBr8vvpczkUf7cN2eV6d8wTi3ZCWGPsJRzcMg".to_string(),
            ),
            // Bad URL format (missing host)
            (
                1,
                "multichain-node-dev-5.testnet".to_string(),
                "http://:3000".to_string(),
                [
                    52, 159, 137, 246, 113, 122, 2, 170, 247, 166, 73, 185, 138, 199, 175, 9, 230,
                    81, 127, 253, 76, 183, 234, 138, 159, 110, 222, 232, 248, 74, 51, 12,
                ],
                "ed25519:5op5eGtWrVAWmNjyaLhZMm4itc8bWottr8PGUJEzcKHd".to_string(),
            ),
            // Bad URL format (missing http prefix)
            (
                0,
                "multichain-node-dev-6.testnet".to_string(),
                "10.101.0.122:3000".to_string(),
                [
                    73, 12, 220, 236, 69, 28, 157, 52, 209, 134, 175, 75, 7, 71, 248, 44, 61, 188,
                    69, 223, 13, 154, 109, 75, 140, 214, 138, 120, 53, 146, 7, 59,
                ],
                "ed25519:41VQ8NxWF11cjse5WjiJBtbrGDPKLQ712Kg1oGyM9w9P".to_string(),
            ),
        ]
    }

    fn create_chain_participant_infos_from_raw(
        raw: Vec<(u32, String, String, [u8; 32], String)>,
    ) -> legacy_mpc_contract::primitives::Participants {
        let mut participants = legacy_mpc_contract::primitives::Participants::new();
        for (participant_id, account_id, url, cipher_pk, pk) in raw {
            let account_id = AccountId::from_str(&account_id).unwrap();
            let url = url.to_string();
            let sign_pk = near_sdk::PublicKey::from_str(&pk).unwrap();
            participants.participants.insert(
                account_id.clone(),
                legacy_mpc_contract::primitives::ParticipantInfo {
                    account_id: account_id.clone(),
                    url,
                    cipher_pk,
                    sign_pk,
                },
            );
            participants
                .account_to_participant_id
                .insert(account_id, participant_id);
            participants.next_id = participants.next_id.max(participant_id + 1);
        }
        participants
    }

    fn create_chain_participant_infos() -> legacy_mpc_contract::primitives::Participants {
        create_chain_participant_infos_from_raw(create_participant_data_raw())
    }

    fn create_invalid_chain_participant_infos() -> legacy_mpc_contract::primitives::Participants {
        create_chain_participant_infos_from_raw(create_invalid_participant_data_raw())
    }

    // Check that the participant ids are assigned 0 to N-1 by AccountId order
    #[test]
    fn test_participant_ids() {
        let chain_infos = create_chain_participant_infos();
        let mut account_ids: Vec<AccountId> = vec![];
        let mut account_id_to_pk = HashMap::<AccountId, near_sdk::PublicKey>::default();
        for (account_id, info) in &chain_infos.participants {
            account_ids.push(account_id.clone());
            account_id_to_pk.insert(account_id.clone(), info.sign_pk.clone());
        }
        assert!(account_ids.is_sorted());

        let converted = convert_participant_infos(chain_infos.clone(), None, 3).unwrap();
        assert_eq!(converted.threshold, 3);
        for (i, p) in converted.participants.iter().enumerate() {
            assert!(p.near_account_id == account_ids[i]);
            assert!(
                p.p2p_public_key.to_string() == String::from(&account_id_to_pk[&account_ids[i]])
            );
            assert!(p.id.raw() == chain_infos.account_to_participant_id[&account_ids[i]]);
        }
    }

    // Check that the port override is applied
    #[test]
    fn test_port_override() {
        let chain_infos = create_chain_participant_infos();

        let converted = convert_participant_infos(chain_infos.clone(), None, 1)
            .unwrap()
            .participants;
        converted.into_iter().for_each(|p| assert!(p.port == 3000));

        let with_override = convert_participant_infos(chain_infos, Some(443), 1)
            .unwrap()
            .participants;
        with_override
            .into_iter()
            .for_each(|p| assert!(p.port == 443));
    }

    // It is fatal if any of the participants has bad data, even if the others are OK
    #[test]
    fn test_bad_participant_data() {
        let chain_infos = create_chain_participant_infos();
        for (account_id, bad_data) in create_invalid_chain_participant_infos().participants {
            let mut chain_infos = chain_infos.clone();
            chain_infos.participants.insert(account_id, bad_data);
            assert!(convert_participant_infos(chain_infos, None, 1).is_err());
        }
    }
}
