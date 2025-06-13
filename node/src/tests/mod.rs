use cait_sith::ecdsa::presign::PresignOutput;
use cait_sith::ecdsa::triples::TripleGenerationOutput;
use cait_sith::protocol::{run_protocol, Participant, Protocol};
use k256::{AffinePoint, Scalar, Secp256k1};
use mpc_contract::state::ProtocolContractState;
use std::collections::HashMap;

use crate::config::{
    ConfigFile, IndexerConfig, KeygenConfig, ParticipantsConfig, PresignatureConfig, SecretsConfig,
    SignatureConfig, SyncMode, TripleConfig, WebUIConfig,
};
use crate::coordinator::Coordinator;
use crate::db::SecretDB;
use crate::indexer::fake::FakeIndexerManager;
use crate::indexer::handler::{SignArgs, SignatureRequestFromChain};
use crate::indexer::IndexerAPI;
use crate::keyshare::KeyStorageConfig;
use crate::p2p::testing::{generate_test_p2p_configs, PortSeed};
use crate::primitives::ParticipantId;
use crate::tracking::{self, start_root_task, AutoAbortTask};
use crate::web::start_web_server;
use cait_sith::ecdsa::presign::PresignArguments;
use cait_sith::ecdsa::sign::FullSignature;
use cait_sith::{ecdsa, eddsa};
use mpc_contract::primitives::domain::{DomainConfig, SignatureScheme};
use mpc_contract::primitives::signature::{Bytes, Payload};
use near_indexer_primitives::types::Finality;
use near_indexer_primitives::CryptoHash;
use near_sdk::AccountId;
use near_time::Clock;
use rand::{Rng, RngCore};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::time::timeout;

mod basic_cluster;
mod benchmark;
mod faulty;
mod multidomain;
mod research;
mod resharing;

/// Convenient test utilities to generate keys, triples, presignatures, and signatures.
pub struct TestGenerators {
    pub participants: Vec<Participant>,
    pub threshold: usize,
}

type ParticipantAndProtocol<T> = (Participant, Box<dyn Protocol<Output = T>>);

impl TestGenerators {
    pub fn new(num_participants: usize, threshold: usize) -> Self {
        Self {
            participants: (0..num_participants)
                .map(|_| Participant::from(rand::random::<u32>()))
                .collect::<Vec<_>>(),
            threshold,
        }
    }

    pub fn new_contiguous_participant_ids(num_participants: usize, threshold: usize) -> Self {
        Self {
            participants: (0..num_participants)
                .map(|i| Participant::from(i as u32))
                .collect::<Vec<_>>(),
            threshold,
        }
    }

    pub fn participant_ids(&self) -> Vec<ParticipantId> {
        self.participants.iter().map(|p| (*p).into()).collect()
    }

    pub fn make_ecdsa_keygens(&self) -> HashMap<Participant, ecdsa::KeygenOutput> {
        let mut protocols: Vec<ParticipantAndProtocol<ecdsa::KeygenOutput>> = Vec::new();
        for participant in &self.participants {
            protocols.push((
                *participant,
                Box::new(
                    ecdsa::dkg_ecdsa::keygen(&self.participants, *participant, self.threshold)
                        .unwrap(),
                ),
            ));
        }
        run_protocol(protocols).unwrap().into_iter().collect()
    }

    pub fn make_eddsa_keygens(&self) -> HashMap<Participant, eddsa::KeygenOutput> {
        let mut protocols: Vec<ParticipantAndProtocol<eddsa::KeygenOutput>> = Vec::new();
        for participant in &self.participants {
            protocols.push((
                *participant,
                Box::new(
                    eddsa::dkg_ed25519::keygen(&self.participants, *participant, self.threshold)
                        .unwrap(),
                ),
            ));
        }
        run_protocol(protocols).unwrap().into_iter().collect()
    }

    pub fn make_triples(&self) -> HashMap<Participant, TripleGenerationOutput<Secp256k1>> {
        let mut protocols: Vec<ParticipantAndProtocol<TripleGenerationOutput<Secp256k1>>> =
            Vec::new();
        for participant in &self.participants {
            protocols.push((
                *participant,
                Box::new(
                    ecdsa::triples::generate_triple::<Secp256k1>(
                        &self.participants,
                        *participant,
                        self.threshold,
                    )
                    .unwrap(),
                ),
            ));
        }
        run_protocol(protocols).unwrap().into_iter().collect()
    }

    pub fn make_presignatures(
        &self,
        triple0s: &HashMap<Participant, TripleGenerationOutput<Secp256k1>>,
        triple1s: &HashMap<Participant, TripleGenerationOutput<Secp256k1>>,
        keygens: &HashMap<Participant, ecdsa::KeygenOutput>,
    ) -> HashMap<Participant, PresignOutput<Secp256k1>> {
        let mut protocols: Vec<ParticipantAndProtocol<PresignOutput<Secp256k1>>> = Vec::new();
        for participant in &self.participants {
            protocols.push((
                *participant,
                Box::new(
                    ecdsa::presign::presign(
                        &self.participants,
                        *participant,
                        &self.participants,
                        *participant,
                        PresignArguments {
                            triple0: triple0s[participant].clone(),
                            triple1: triple1s[participant].clone(),
                            keygen_out: keygens[participant].clone(),
                            threshold: self.threshold,
                        },
                    )
                    .unwrap(),
                ),
            ));
        }
        run_protocol(protocols).unwrap().into_iter().collect()
    }

    pub fn make_signature(
        &self,
        presignatures: &HashMap<Participant, PresignOutput<Secp256k1>>,
        public_key: AffinePoint,
        msg_hash: Scalar,
    ) -> FullSignature<Secp256k1> {
        let mut protocols: Vec<ParticipantAndProtocol<FullSignature<Secp256k1>>> = Vec::new();
        for participant in &self.participants {
            protocols.push((
                *participant,
                Box::new(
                    ecdsa::sign::sign(
                        &self.participants,
                        *participant,
                        public_key,
                        presignatures[participant].clone(),
                        msg_hash,
                    )
                    .unwrap(),
                ),
            ));
        }
        run_protocol(protocols)
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
            .1
    }
}

/// Data needed to start running a test node.
pub struct OneNodeTestConfig {
    clock: Clock,
    home_dir: PathBuf,
    pub config: ConfigFile,
    secrets: SecretsConfig,
    indexer: IndexerAPI,
    indexer_task: AutoAbortTask<()>,
    currently_running_job_name: Arc<std::sync::Mutex<String>>,
}

impl OneNodeTestConfig {
    pub async fn run(self) -> anyhow::Result<()> {
        let OneNodeTestConfig {
            clock,
            home_dir,
            config,
            secrets,
            indexer,
            indexer_task: _indexer_task,
            currently_running_job_name,
        } = self;
        let my_account_id = config.my_near_account_id.clone();
        std::fs::create_dir_all(&home_dir)?;
        async move {
            let root_future = async move {
                let root_task_handle = tracking::current_task();
                let (signature_debug_request_sender, _) = tokio::sync::broadcast::channel(10);
                let (_, web_contract_receiver) =
                    tokio::sync::watch::channel(ProtocolContractState::NotInitialized);
                let web_server = start_web_server(
                    root_task_handle,
                    signature_debug_request_sender.clone(),
                    config.web_ui.clone(),
                    web_contract_receiver.clone(),
                )
                .await?;
                let _web_server = tracking::spawn_checked("web server", web_server);

                let secret_db = SecretDB::new(&home_dir, secrets.local_storage_aes_key)?;

                let key_storage_config = KeyStorageConfig {
                    home_dir: home_dir.clone(),
                    local_encryption_key: secrets.local_storage_aes_key,
                    gcp: None,
                };

                let coordinator = Coordinator {
                    clock,
                    config_file: config,
                    secrets,
                    secret_db,
                    key_storage_config,
                    indexer,
                    currently_running_job_name,
                    signature_debug_request_sender,
                };
                coordinator.run().await
            };
            start_root_task(&format!("root for {}", my_account_id), root_future)
                .0
                .await?;
            Ok(())
        }
        .await
    }
}

/// Test fixture for integration tests, includes a fake indexer and a set of
/// nodes.
pub struct IntegrationTestSetup {
    pub indexer: FakeIndexerManager,
    pub configs: Vec<OneNodeTestConfig>,
    pub participants: ParticipantsConfig,
}

impl IntegrationTestSetup {
    /// Generates test node configs and a fake indexer; each config can then be used
    /// to start running the node.
    pub fn new(
        clock: Clock,
        temp_dir: &Path,
        participant_accounts: Vec<AccountId>,
        threshold: usize,
        txn_delay_blocks: u64,
        port_seed: PortSeed,
    ) -> IntegrationTestSetup {
        let p2p_configs =
            generate_test_p2p_configs(&participant_accounts, threshold, port_seed, None).unwrap();
        let participants = p2p_configs[0].0.participants.clone();
        let mut indexer_manager = FakeIndexerManager::new(clock.clone(), txn_delay_blocks);

        let mut configs = Vec::new();
        for (i, (_, p2p_key)) in p2p_configs.into_iter().enumerate() {
            let config = ConfigFile {
                cores: Some(4),
                // Indexer config is just a dummy.
                indexer: IndexerConfig {
                    concurrency: 1.try_into().unwrap(),
                    finality: Finality::Final,
                    mpc_contract_id: "test".parse().unwrap(),
                    port_override: None,
                    sync_mode: SyncMode::Latest,
                    validate_genesis: false,
                },
                keygen: KeygenConfig { timeout_sec: 60 },
                my_near_account_id: participant_accounts[i].clone(),
                presignature: PresignatureConfig {
                    concurrency: 1,
                    desired_presignatures_to_buffer: 5,
                    timeout_sec: 60,
                },
                signature: SignatureConfig { timeout_sec: 60 },
                triple: TripleConfig {
                    concurrency: 1,
                    desired_triples_to_buffer: 10,
                    parallel_triple_generation_stagger_time_sec: 1,
                    timeout_sec: 60,
                },
                web_ui: WebUIConfig {
                    host: "0.0.0.0".to_string(),
                    port: port_seed.web_port(i),
                },
            };
            let secrets = SecretsConfig {
                local_storage_aes_key: rand::random(),
                p2p_private_key: p2p_key,
            };
            let (indexer_api, task, currently_running_job_name) =
                indexer_manager.add_indexer_node(participant_accounts[i].clone());
            configs.push(OneNodeTestConfig {
                clock: clock.clone(),
                config,
                home_dir: temp_dir.join(format!("{}", i)),
                secrets,
                indexer: indexer_api,
                indexer_task: task,
                currently_running_job_name,
            });
        }
        IntegrationTestSetup {
            indexer: indexer_manager,
            configs,
            participants,
        }
    }
}

/// Request a signature from the indexer and wait for the response.
/// Returns the time taken to receive the response, or None if timed out.
pub async fn request_signature_and_await_response(
    indexer: &mut FakeIndexerManager,
    user: &str,
    domain: &DomainConfig,
    timeout_sec: std::time::Duration,
) -> Option<std::time::Duration> {
    let payload = match domain.scheme {
        SignatureScheme::Secp256k1 => {
            let mut payload = [0; 32];
            rand::thread_rng().fill_bytes(payload.as_mut());
            Payload::Ecdsa(Bytes::new(payload.to_vec()).unwrap())
        }
        SignatureScheme::Ed25519 => {
            let len = rand::thread_rng().gen_range(32..1232);
            let mut payload = vec![0; len];
            rand::thread_rng().fill_bytes(payload.as_mut());
            Payload::Eddsa(Bytes::new(payload.to_vec()).unwrap())
        }
    };
    let request = SignatureRequestFromChain {
        entropy: rand::random(),
        signature_id: CryptoHash(rand::random()),
        receipt_id: CryptoHash(rand::random()),
        predecessor_id: user.parse().unwrap(),
        timestamp_nanosec: rand::random(),
        request: SignArgs {
            domain_id: domain.id,
            path: "m/44'/60'/0'/0/0".to_string(),
            payload,
        },
    };
    tracing::info!(
        "Sending signature request from user {}, payload {:?}",
        user,
        request.request.payload
    );
    indexer.request_signature(request.clone());
    let start_time = std::time::Instant::now();
    loop {
        match timeout(timeout_sec, indexer.next_response()).await {
            Ok(signature) => {
                if signature.request.payload != request.request.payload {
                    // This can legitimately happen when multiple nodes submit responses
                    // for the same signature request. In tests this can happen if the
                    // secondary leader thinks the primary leader is offline when in fact
                    // the network just has not yet been fully established.
                    tracing::info!(
                        "Received signature is not for the signature request we sent (user {})
                         Expected {:?}, actual {:?}",
                        user,
                        request.request.payload,
                        signature.request.payload
                    );
                    continue;
                }
                if signature.request.domain_id != domain.id {
                    tracing::info!(
                        "Received signature is not for the domain we requested (user {})
                         Expected {:?}, actual {:?}",
                        user,
                        domain.id,
                        signature.request.domain_id
                    );
                    continue;
                }
                tracing::info!("Got signature response for user {}", user);
                return Some(start_time.elapsed());
            }
            Err(_) => {
                tracing::info!("Timed out waiting for signature respnse for user {}", user);
                return None;
            }
        }
    }
}
