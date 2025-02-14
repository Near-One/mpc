use crate::{
    config::{
        load_config_file, BlockArgs, ConfigFile, IndexerConfig, KeygenConfig, ParticipantsConfig,
        PresignatureConfig, SecretsConfig, SignatureConfig, SyncMode, TripleConfig, WebUIConfig,
    },
    coordinator::Coordinator,
    db::SecretDB,
    indexer::{real::spawn_real_indexer, IndexerAPI},
    keyshare::KeyshareStorageFactory,
    p2p::testing::{generate_test_p2p_configs, PortSeed},
    tracking::{self, start_root_task},
    web::start_web_server,
};
use clap::Parser;
use near_crypto::SecretKey;
use near_indexer_primitives::types::Finality;
use near_sdk::AccountId;
use near_time::Clock;
use std::{
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex},
};

#[derive(Parser, Debug)]
pub enum Cli {
    Start(StartCmd),
    /// Generates/downloads required files for Near node to run
    Init(InitConfigArgs),
    /// Generates a set of test configurations suitable for running MPC in
    /// an integration test.
    GenerateTestConfigs {
        #[arg(long)]
        output_dir: String,
        #[arg(long, value_delimiter = ',')]
        participants: Vec<AccountId>,
        #[arg(long)]
        threshold: usize,
    },
}

#[derive(Parser, Debug)]
pub struct InitConfigArgs {
    #[arg(long, env("MPC_HOME_DIR"))]
    pub dir: std::path::PathBuf,
    /// chain/network id (localnet, testnet, devnet, betanet)
    #[arg(long)]
    pub chain_id: Option<String>,
    /// Genesis file to use when initialize testnet (including downloading)
    #[arg(long)]
    pub genesis: Option<String>,
    /// Download the verified NEAR config file automatically.
    #[arg(long)]
    pub download_config: bool,
    #[arg(long)]
    pub download_config_url: Option<String>,
    /// Download the verified NEAR genesis file automatically.
    #[arg(long)]
    pub download_genesis: bool,
    /// Specify a custom download URL for the genesis-file.
    #[arg(long)]
    pub download_genesis_url: Option<String>,
    #[arg(long)]
    pub donwload_genesis_records_url: Option<String>,
}

#[derive(Parser, Debug)]
pub struct StartCmd {
    #[arg(long, env("MPC_HOME_DIR"))]
    pub home_dir: String,
    /// Hex-encoded 16 byte AES key for local storage encryption.
    /// This key should come from a secure secret storage.
    #[arg(env("MPC_SECRET_STORE_KEY"))]
    pub secret_store_key_hex: String,
    /// If provided, the root keyshare is stored on GCP.
    /// This requires GCP_PROJECT_ID to be set as well.
    #[arg(env("GCP_KEYSHARE_SECRET_ID"))]
    pub gcp_keyshare_secret_id: Option<String>,
    #[arg(env("GCP_PROJECT_ID"))]
    pub gcp_project_id: Option<String>,
    /// p2p private key for TLS. It must be in the format of "ed25519:...".
    #[arg(env("MPC_P2P_PRIVATE_KEY"))]
    pub p2p_private_key: SecretKey,
    /// Near account secret key. Must correspond to the my_near_account_id
    /// specified in the config.
    #[arg(env("MPC_ACCOUNT_SK"))]
    pub account_secret_key: SecretKey,
}

impl StartCmd {
    async fn run(self) -> anyhow::Result<()> {
        let home_dir = PathBuf::from(self.home_dir.clone());
        let secrets =
            SecretsConfig::from_cli(&self.secret_store_key_hex, self.p2p_private_key.clone())?;
        let config = load_config_file(&home_dir)?;

        let (indexer_handle, indexer_api) = spawn_real_indexer(
            home_dir.clone(),
            config.indexer.clone(),
            config.my_near_account_id.clone(),
            self.account_secret_key.clone(),
        );

        let root_future = self.create_root_future(
            home_dir.clone(),
            config.clone(),
            secrets.clone(),
            indexer_api,
        );

        let root_runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()?;

        let root_task = root_runtime.spawn(start_root_task("root", root_future).0);
        let indexer_handle = root_runtime.spawn_blocking(move || {
            if let Err(e) = indexer_handle.join() {
                anyhow::bail!("Indexer thread failed: {:?}", e);
            }
            anyhow::Ok(())
        });

        tokio::select! {
            res = root_task => {
                res??;
            }
            res = indexer_handle => {
                res??;
            }
        }
        Ok(())
    }

    fn create_root_future(
        &self,
        home_dir: PathBuf,
        config: ConfigFile,
        secrets: SecretsConfig,
        indexer_api: IndexerAPI,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>> {
        let gcp_keyshare_secret_id = self.gcp_keyshare_secret_id.clone();
        let gcp_project_id = self.gcp_project_id.clone();

        Box::pin(async move {
            let root_task_handle = tracking::current_task();
            let web_server = start_web_server(root_task_handle, config.web_ui.clone()).await?;
            let _web_server = tracking::spawn_checked("web server", web_server);

            let secret_db = SecretDB::new(&home_dir, secrets.local_storage_aes_key)?;

            let keyshare_storage_factory = if let Some(secret_id) = gcp_keyshare_secret_id {
                let project_id = gcp_project_id.ok_or_else(|| {
                    anyhow::anyhow!(
                        "GCP_PROJECT_ID must be specified to use GCP_KEYSHARE_SECRET_ID"
                    )
                })?;
                KeyshareStorageFactory::Gcp {
                    project_id,
                    secret_id,
                }
            } else {
                KeyshareStorageFactory::Local {
                    home_dir: home_dir.clone(),
                    encryption_key: secrets.local_storage_aes_key,
                }
            };

            let coordinator = Coordinator {
                clock: Clock::real(),
                config_file: config,
                secrets,
                secret_db,
                keyshare_storage_factory,
                indexer: indexer_api,
                currently_running_job_name: Arc::new(Mutex::new(String::new())),
            };
            coordinator.run().await
        })
    }
}

impl Cli {
    pub async fn run(self) -> anyhow::Result<()> {
        match self {
            Cli::Start(start) => start.run().await,
            Cli::Init(config) => near_indexer::init_configs(
                &config.dir,
                config.chain_id,
                None,
                None,
                1,
                false,
                config.genesis.as_ref().map(AsRef::as_ref),
                config.download_genesis,
                config.download_genesis_url.as_ref().map(AsRef::as_ref),
                config
                    .donwload_genesis_records_url
                    .as_ref()
                    .map(AsRef::as_ref),
                Some(near_config_utils::DownloadConfigType::RPC),
                config.download_config_url.as_ref().map(AsRef::as_ref),
                None,
                None,
            ),
            Cli::GenerateTestConfigs {
                ref output_dir,
                ref participants,
                threshold,
            } => {
                self.run_generate_test_configs(output_dir, participants, threshold)
                    .await
            }
        }
    }

    async fn run_generate_test_configs(
        &self,
        output_dir: &str,
        participants: &[AccountId],
        threshold: usize,
    ) -> anyhow::Result<()> {
        let configs = generate_test_p2p_configs(participants, threshold, PortSeed::CLI_FOR_PYTEST)?;
        let participants_config = configs[0].0.participants.clone();
        for (i, (_, p2p_private_key)) in configs.into_iter().enumerate() {
            let subdir = format!("{}/{}", output_dir, i);
            std::fs::create_dir_all(&subdir)?;
            let file_config = self.create_file_config(&participants[i], i)?;
            let secret_key = SecretKey::ED25519(p2p_private_key.clone());
            self.write_config_files(&subdir, &file_config, &secret_key)?;
        }
        self.write_participants_config(output_dir, &participants_config)?;
        Ok(())
    }

    fn create_file_config(
        &self,
        participant: &AccountId,
        index: usize,
    ) -> anyhow::Result<ConfigFile> {
        Ok(ConfigFile {
            my_near_account_id: participant.clone(),
            web_ui: WebUIConfig {
                host: "127.0.0.1".to_owned(),
                port: 21000 + index as u16,
            },
            indexer: IndexerConfig {
                validate_genesis: true,
                sync_mode: SyncMode::Block(BlockArgs { height: 0 }),
                concurrency: 1.try_into().unwrap(),
                mpc_contract_id: "test0".parse().unwrap(),
                finality: Finality::None,
                port_override: None,
            },
            triple: TripleConfig {
                concurrency: 2,
                desired_triples_to_buffer: 65536,
                timeout_sec: 60,
                parallel_triple_generation_stagger_time_sec: 1,
            },
            presignature: PresignatureConfig {
                concurrency: 2,
                desired_presignatures_to_buffer: 8192,
                timeout_sec: 60,
            },
            signature: SignatureConfig { timeout_sec: 60 },
            keygen: KeygenConfig { timeout_sec: 60 },
            cores: Some(4),
        })
    }

    fn write_config_files(
        &self,
        subdir: &str,
        file_config: &ConfigFile,
        p2p_private_key: &SecretKey,
    ) -> anyhow::Result<()> {
        std::fs::write(format!("{}/p2p_key", subdir), p2p_private_key.to_string())?;
        std::fs::write(
            format!("{}/config.yaml", subdir),
            serde_yaml::to_string(file_config)?,
        )?;
        Ok(())
    }

    fn write_participants_config(
        &self,
        output_dir: &str,
        participants_config: &ParticipantsConfig,
        // participants_config: &Vec<AccountId>,
    ) -> anyhow::Result<()> {
        std::fs::write(
            format!("{}/participants.json", output_dir),
            serde_json::to_string(participants_config)?,
        )?;
        Ok(())
    }
}
