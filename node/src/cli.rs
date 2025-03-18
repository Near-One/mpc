use crate::config::{
    load_config_file, BlockArgs, KeygenConfig, PresignatureConfig, SecretsConfig, SignatureConfig,
    SyncMode, TripleConfig, WebUIConfig,
};
use crate::config::{ConfigFile, IndexerConfig};
use crate::coordinator::Coordinator;
use crate::db::SecretDB;
use crate::indexer::{real::spawn_real_indexer, IndexerAPI};
use crate::keyshare::{
    local::LocalKeyshareStorage, KeyshareStorage, KeyshareStorageFactory, RootKeyshareData,
};
use crate::p2p::testing::{generate_test_p2p_configs, PortSeed};
use crate::tracking::{self, start_root_task};
use crate::web::start_web_server;
use clap::Parser;
use hex::FromHex;
use near_crypto::SecretKey;
use near_indexer_primitives::types::Finality;
use near_sdk::AccountId;
use near_time::Clock;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Parser, Debug)]
pub enum Cli {
    Start(StartCmd),
    /// Generates/downloads required files for Near node to run
    Init(InitConfigArgs),
    /// Imports a keyshare from JSON and stores it in the local encrypted storage
    ImportKeyshare(ImportKeyshareCmd),
    /// Exports a keyshare from local encrypted storage and prints it to the console
    ExportKeyshare(ExportKeyshareCmd),
    /// Generates a set of test configurations suitable for running MPC in
    /// an integration test.
    GenerateTestConfigs {
        #[arg(long)]
        output_dir: String,
        #[arg(long, value_delimiter = ',')]
        participants: Vec<AccountId>,
        #[arg(long)]
        threshold: usize,
        #[arg(long, default_value = "65536")]
        desired_triples_to_buffer: usize,
        #[arg(long, default_value = "8192")]
        desired_presignatures_to_buffer: usize,
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

#[derive(Parser, Debug)]
pub struct ImportKeyshareCmd {
    /// Path to home directory
    #[arg(long, env("MPC_HOME_DIR"))]
    pub home_dir: String,

    /// JSON string containing the keyshare to import
    #[arg(
        help = "JSON string with the keyshare in format: {\"epoch\":1,\"private_share\":\"...\",\"public_key\":\"...\"}"
    )]
    pub keyshare_json: String,

    /// Hex-encoded 16 byte AES key for local storage encryption
    #[arg(help = "Hex-encoded 16 byte AES key for local storage encryption")]
    pub local_encryption_key_hex: String,
}

#[derive(Parser, Debug)]
pub struct ExportKeyshareCmd {
    /// Path to home directory
    #[arg(long, env("MPC_HOME_DIR"))]
    pub home_dir: String,

    /// Hex-encoded 16 byte AES key for local storage encryption
    #[arg(help = "Hex-encoded 16 byte AES key for local storage encryption")]
    pub local_encryption_key_hex: String,
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

        let root_future = Self::create_root_future(
            home_dir.clone(),
            config.clone(),
            secrets.clone(),
            indexer_api,
            self.gcp_keyshare_secret_id.clone(),
            self.gcp_project_id.clone(),
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

    async fn create_root_future(
        home_dir: PathBuf,
        config: ConfigFile,
        secrets: SecretsConfig,
        indexer_api: IndexerAPI,
        gcp_keyshare_secret_id: Option<String>,
        gcp_project_id: Option<String>,
    ) -> anyhow::Result<()> {
        let root_task_handle = tracking::current_task();
        let (signature_debug_request_sender, _) = tokio::sync::broadcast::channel(10);
        let web_server = start_web_server(
            root_task_handle,
            signature_debug_request_sender.clone(),
            config.web_ui.clone(),
        )
        .await?;
        let _web_server = tracking::spawn_checked("web server", web_server);

        let secret_db = SecretDB::new(&home_dir, secrets.local_storage_aes_key)?;

        let keyshare_storage_factory = if let Some(secret_id) = gcp_keyshare_secret_id {
            let project_id = gcp_project_id.ok_or_else(|| {
                anyhow::anyhow!("GCP_PROJECT_ID must be specified to use GCP_KEYSHARE_SECRET_ID")
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
            signature_debug_request_sender,
        };
        coordinator.run().await
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
            Cli::ImportKeyshare(cmd) => cmd.run().await,
            Cli::ExportKeyshare(cmd) => cmd.run().await,
            Cli::GenerateTestConfigs {
                ref output_dir,
                ref participants,
                threshold,
                desired_triples_to_buffer,
                desired_presignatures_to_buffer,
            } => {
                self.run_generate_test_configs(
                    output_dir,
                    participants,
                    threshold,
                    desired_triples_to_buffer,
                    desired_presignatures_to_buffer,
                )
                .await
            }
        }
    }

    async fn run_generate_test_configs(
        &self,
        output_dir: &str,
        participants: &[AccountId],
        threshold: usize,
        desired_triples_to_buffer: usize,
        desired_presignatures_to_buffer: usize,
    ) -> anyhow::Result<()> {
        let configs = generate_test_p2p_configs(participants, threshold, PortSeed::CLI_FOR_PYTEST)?;
        let participants_config = configs[0].0.participants.clone();
        for (i, (_, p2p_private_key)) in configs.into_iter().enumerate() {
            let subdir = format!("{}/{}", output_dir, i);
            std::fs::create_dir_all(&subdir)?;
            let file_config = self.create_file_config(
                &participants[i],
                i,
                desired_triples_to_buffer,
                desired_presignatures_to_buffer,
            )?;
            let secret_key = SecretKey::ED25519(p2p_private_key.clone());
            std::fs::write(format!("{}/p2p_key", subdir), secret_key.to_string())?;
            std::fs::write(
                format!("{}/config.yaml", subdir),
                serde_yaml::to_string(&file_config)?,
            )?;
        }
        std::fs::write(
            format!("{}/participants.json", output_dir),
            serde_json::to_string(&participants_config)?,
        )?;
        Ok(())
    }

    fn create_file_config(
        &self,
        participant: &AccountId,
        index: usize,
        desired_triples_to_buffer: usize,
        desired_presignatures_to_buffer: usize,
    ) -> anyhow::Result<ConfigFile> {
        Ok(ConfigFile {
            my_near_account_id: participant.clone(),
            web_ui: WebUIConfig {
                host: "127.0.0.1".to_owned(),
                port: PortSeed::CLI_FOR_PYTEST.web_port(index),
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
                desired_triples_to_buffer,
                timeout_sec: 60,
                parallel_triple_generation_stagger_time_sec: 1,
            },
            presignature: PresignatureConfig {
                concurrency: 2,
                desired_presignatures_to_buffer,
                timeout_sec: 60,
            },
            signature: SignatureConfig { timeout_sec: 60 },
            keygen: KeygenConfig { timeout_sec: 60 },
            cores: Some(4),
        })
    }
}

impl ImportKeyshareCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        println!("Importing keyshare to local storage...");

        // Parse the encryption key
        let encryption_key_bytes =
            <[u8; 16]>::from_hex(&self.local_encryption_key_hex).map_err(|_| {
                anyhow::anyhow!("Invalid encryption key: must be 32 hex characters (16 bytes)")
            })?;

        // Parse the keyshare JSON
        let keyshare: RootKeyshareData = serde_json::from_str(&self.keyshare_json)
            .map_err(|e| anyhow::anyhow!("Failed to parse keyshare JSON: {}", e))?;

        println!("Parsed keyshare for epoch {}", keyshare.epoch);

        // Create the local storage and store the keyshare
        let home_dir = PathBuf::from(&self.home_dir);

        // Ensure the directory exists
        if !home_dir.exists() {
            std::fs::create_dir_all(&home_dir).map_err(|e| {
                anyhow::anyhow!("Failed to create directory {}: {}", home_dir.display(), e)
            })?;
        }

        let storage = LocalKeyshareStorage::new(home_dir.clone(), encryption_key_bytes);

        // Check for existing keyshare
        if let Some(existing) = storage.load().await? {
            println!("Found existing keyshare with epoch {}", existing.epoch);
            if existing.epoch >= keyshare.epoch {
                return Err(anyhow::anyhow!(
                    "Refusing to overwrite existing keyshare of epoch {} with new keyshare of older or same epoch {}",
                    existing.epoch,
                    keyshare.epoch
                ));
            }
        }

        // Store the keyshare
        storage.store(&keyshare).await?;
        println!("Successfully imported keyshare to {}", home_dir.display());

        Ok(())
    }
}

impl ExportKeyshareCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        println!("Exporting keyshare from local storage...");

        // Parse the encryption key
        let encryption_key_bytes =
            <[u8; 16]>::from_hex(&self.local_encryption_key_hex).map_err(|_| {
                anyhow::anyhow!("Invalid encryption key: must be 32 hex characters (16 bytes)")
            })?;

        // Create the local storage
        let home_dir = PathBuf::from(&self.home_dir);

        // Check if directory exists
        if !home_dir.exists() {
            return Err(anyhow::anyhow!(
                "Directory {} does not exist",
                home_dir.display()
            ));
        }

        let storage = LocalKeyshareStorage::new(home_dir.clone(), encryption_key_bytes);

        // Load the keyshare
        let keyshare = storage
            .load()
            .await?
            .ok_or_else(|| anyhow::anyhow!("No keyshare found in {}", home_dir.display()))?;

        // Print the keyshare to console
        let json = serde_json::to_string_pretty(&keyshare)
            .map_err(|e| anyhow::anyhow!("Failed to serialize keyshare: {}", e))?;

        println!("{}", json);
        println!(
            "\nKeyshare for epoch {} successfully exported.",
            keyshare.epoch
        );

        Ok(())
    }
}
