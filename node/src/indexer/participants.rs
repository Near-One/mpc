use crate::config::{ParticipantInfo, ParticipantsConfig};
use crate::indexer::lib::{get_mpc_contract_state, wait_for_contract_code, wait_for_full_sync};
use crate::primitives::ParticipantId;
use anyhow::Context;
use mpc_contract::primitives::key_state::{KeyEventId, Keyset};
use mpc_contract::primitives::thresholds::ThresholdParameters;
use mpc_contract::state::key_event::KeyEvent;
use mpc_contract::state::ProtocolContractState;
use near_indexer_primitives::types::AccountId;
use std::collections::BTreeSet;
use std::str::FromStr;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractKeyEventInstance {
    pub id: KeyEventId,
    pub started: bool,
    pub completed: BTreeSet<ParticipantId>,
}

pub fn convert_key_event_to_instance(key_event: &KeyEvent) -> ContractKeyEventInstance {
    let epoch_id = key_event.epoch_id();
    let domain_id = key_event.domain_id();
    let (attempt_id, started, completed) = if let Some(current_instance) = key_event.instance() {
        (
            current_instance.attempt_id(),
            true,
            current_instance
                .completed()
                .iter()
                .map(|p| p.get().into())
                .collect(),
        )
    } else {
        (key_event.next_attempt_id(), false, BTreeSet::new())
    };
    let id = KeyEventId {
        epoch_id,
        domain_id,
        attempt_id,
    };
    ContractKeyEventInstance {
        id,
        started,
        completed,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractRunningState {
    pub keyset: Keyset,
    pub participants: ParticipantsConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractInitializingState {
    pub generated_keyset: Keyset,
    pub participants: ParticipantsConfig,
    pub key_event: ContractKeyEventInstance,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractResharingState {
    pub previous_running_state: ContractRunningState,
    pub new_participants: ParticipantsConfig,
    pub reshared_keys: Keyset,
    pub key_event: ContractKeyEventInstance,
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
        ProtocolContractState::NotInitialized => ContractState::Invalid,
        ProtocolContractState::Initializing(state) => {
            ContractState::Initializing(ContractInitializingState {
                generated_keyset: Keyset {
                    epoch_id: state.epoch_id,
                    domains: state.generated_keys.clone(),
                },
                participants: convert_participant_infos(
                    state.generating_key.proposed_parameters().clone(),
                    port_override,
                )?,
                key_event: convert_key_event_to_instance(&state.generating_key),
            })
        }
        ProtocolContractState::Running(state) => ContractState::Running(ContractRunningState {
            keyset: state.keyset.clone(),
            participants: convert_participant_infos(state.parameters.clone(), port_override)?,
        }),
        ProtocolContractState::Resharing(state) => {
            ContractState::Resharing(ContractResharingState {
                previous_running_state: ContractRunningState {
                    keyset: state.previous_running_state.keyset.clone(),
                    participants: convert_participant_infos(
                        state.previous_running_state.parameters.clone(),
                        port_override,
                    )?,
                },
                new_participants: convert_participant_infos(
                    state.resharing_key.proposed_parameters().clone(),
                    port_override,
                )?,
                reshared_keys: Keyset {
                    epoch_id: state.prospective_epoch_id(),
                    domains: state.reshared_keys.clone(),
                },
                key_event: convert_key_event_to_instance(&state.resharing_key),
            })
        }
    };
    Ok(state)
}

pub fn convert_participant_infos(
    threshold_parameters: ThresholdParameters,
    port_override: Option<u16>,
) -> anyhow::Result<ParticipantsConfig> {
    let mut converted = Vec::new();
    for (account_id, id, info) in threshold_parameters.participants().participants() {
        let url = Url::parse(&info.url)
            .with_context(|| format!("could not parse participant url {}", info.url))?;
        let Some(address) = url.host_str() else {
            anyhow::bail!("no host found in participant url {}", info.url);
        };
        let Some(port) = port_override.or(url.port_or_known_default()) else {
            anyhow::bail!("no port found in participant url {}", info.url);
        };
        // Here we need to turn the near_sdk::PublicKey used in the smart contract into a
        // near_crypto::PublicKey used by the mpc nodes. For some reason near_sdk has an
        // impl TryFrom<near_sdk::PublicKey> for near_crypto::PublicKey but it's test-only.
        // For lack of better option we use this to-string from-string conversion instead.
        let Ok(p2p_public_key) = near_crypto::PublicKey::from_str(&String::from(&info.sign_pk))
        else {
            anyhow::bail!("invalid participant public key {:?}", info.sign_pk);
        };
        converted.push(ParticipantInfo {
            id: ParticipantId::from_raw(id.get()),
            address: address.to_string(),
            port,
            p2p_public_key,
            near_account_id: account_id.clone(),
        });
    }
    Ok(ParticipantsConfig {
        participants: converted,
        threshold: threshold_parameters.threshold().value(),
    })
}

#[cfg(test)]
mod tests {
    use crate::indexer::participants::convert_participant_infos;
    use mpc_contract::primitives::participants::{ParticipantInfo, Participants};
    use mpc_contract::primitives::thresholds::{Threshold, ThresholdParameters};
    use near_indexer_primitives::types::AccountId;
    use std::collections::HashMap;
    use std::str::FromStr;

    fn create_participant_data_raw() -> Vec<(String, String, [u8; 32], String)> {
        vec![
            (
                "multichain-node-dev-0.testnet".to_string(),
                "http://10.101.0.56:3000".to_string(),
                [
                    90, 157, 29, 39, 252, 60, 149, 46, 122, 247, 162, 241, 200, 79, 85, 41, 40,
                    238, 194, 50, 195, 242, 195, 231, 135, 244, 161, 93, 130, 168, 41, 22,
                ],
                "ed25519:4upBpJYUrjPBzqNYaY8pvJGQtep7YMT3j9zRsopYQqfG".to_string(),
            ),
            (
                "multichain-node-dev-1.testnet".to_string(),
                "http://10.101.0.81:3000".to_string(),
                [
                    52, 159, 137, 246, 113, 122, 2, 170, 247, 166, 73, 185, 138, 199, 175, 9, 230,
                    81, 127, 253, 76, 183, 234, 138, 159, 110, 222, 232, 248, 74, 51, 12,
                ],
                "ed25519:6sqMFXkswuH9b7Pnn6dGAy1vA1X3N2CSrKDDkdHzTcrv".to_string(),
            ),
            (
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

    fn create_invalid_participant_data_raw() -> Vec<(String, String, [u8; 32], String)> {
        // The on-chain participant data is strongly typed with AccountId and near_sdk::PublicKey.
        // It's really only possible to have bad data in the urls, which are arbitrary strings.
        vec![
            // Bad URL format (missing host)
            (
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
        raw: Vec<(String, String, [u8; 32], String)>,
    ) -> Participants {
        let mut participants = Participants::new();
        for (account_id, url, cipher_pk, pk) in raw {
            let account_id = AccountId::from_str(&account_id).unwrap();
            let url = url.to_string();
            let sign_pk = near_sdk::PublicKey::from_str(&pk).unwrap();
            participants
                .insert(
                    account_id.clone(),
                    ParticipantInfo {
                        url,
                        cipher_pk,
                        sign_pk,
                    },
                )
                .unwrap();
        }
        participants
    }

    fn create_chain_participant_infos() -> Participants {
        create_chain_participant_infos_from_raw(create_participant_data_raw())
    }

    fn create_invalid_chain_participant_infos() -> Participants {
        create_chain_participant_infos_from_raw(create_invalid_participant_data_raw())
    }

    // Check that the participant ids are assigned 0 to N-1 by AccountId order
    #[test]
    fn test_participant_ids() {
        let chain_infos = create_chain_participant_infos();
        let mut account_ids: Vec<AccountId> = vec![];
        let mut account_id_to_pk = HashMap::<AccountId, near_sdk::PublicKey>::default();
        for (account_id, _, info) in chain_infos.participants() {
            account_ids.push(account_id.clone());
            account_id_to_pk.insert(account_id.clone(), info.sign_pk.clone());
        }
        assert!(account_ids.is_sorted());
        let params = ThresholdParameters::new(chain_infos.clone(), Threshold::new(3)).unwrap();

        let converted = convert_participant_infos(params, None).unwrap();
        assert_eq!(converted.threshold, 3);
        for (i, p) in converted.participants.iter().enumerate() {
            assert!(p.near_account_id == account_ids[i]);
            assert!(
                p.p2p_public_key.to_string() == String::from(&account_id_to_pk[&account_ids[i]])
            );
            let expected = chain_infos
                .participants()
                .iter()
                .find(|(a_id, _, _)| a_id == &account_ids[i])
                .map(|(_, p_id, _)| p_id.clone())
                .unwrap();
            assert!(p.id.raw() == expected.get());
        }
    }

    // Check that the port override is applied
    #[test]
    fn test_port_override() {
        let chain_infos = create_chain_participant_infos();

        let params = ThresholdParameters::new(chain_infos.clone(), Threshold::new(3)).unwrap();
        let converted = convert_participant_infos(params.clone(), None)
            .unwrap()
            .participants;
        converted.into_iter().for_each(|p| assert!(p.port == 3000));

        let with_override = convert_participant_infos(params, Some(443))
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
        for (account_id, _, bad_data) in create_invalid_chain_participant_infos().participants() {
            let mut new_infos = chain_infos.clone();
            new_infos
                .insert(account_id.clone(), bad_data.clone())
                .unwrap();
            let params = ThresholdParameters::new(new_infos.clone(), Threshold::new(3)).unwrap();
            print!("\n\nmy params: \n{:?}\n", params);
            let converted = convert_participant_infos(params, None);
            print!("\n\nmyconverted: \n{:?}\n", converted);
            assert!(converted.is_err());
        }
    }
}
