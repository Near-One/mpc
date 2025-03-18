use super::{migrate_root_key_share_data, KeyShare, KeyshareStorage, RootKeyshareData};
use anyhow::Context;
use gcloud_sdk::google::cloud::secretmanager::v1::secret_manager_service_client::SecretManagerServiceClient;
use gcloud_sdk::google::cloud::secretmanager::v1::secret_version::State;
use gcloud_sdk::google::cloud::secretmanager::v1::{
    AccessSecretVersionRequest, AddSecretVersionRequest, ListSecretVersionsRequest,
};
use gcloud_sdk::proto_ext::secretmanager::SecretPayload;
use gcloud_sdk::{GoogleApi, GoogleAuthMiddleware, SecretValue};

/// Keyshare storage that loads and stores the key from Google Secret Manager.
pub struct GcpKeyshareStorage {
    secrets_client: GoogleApi<SecretManagerServiceClient<GoogleAuthMiddleware>>,
    project_id: String,
    secret_id: String,
}

impl GcpKeyshareStorage {
    pub async fn new(project_id: String, secret_id: String) -> anyhow::Result<Self> {
        let secrets_client = GoogleApi::from_function(
            SecretManagerServiceClient::new,
            "https://secretmanager.googleapis.com",
            None,
        )
        .await
        .context("Failed to create SecretManagerServiceClient")?;

        Ok(Self {
            secrets_client,
            project_id,
            secret_id,
        })
    }
}

#[async_trait::async_trait]
impl KeyshareStorage for GcpKeyshareStorage {
    async fn load(&self) -> anyhow::Result<Option<KeyShare>> {
        let secret_name = format!("projects/{}/secrets/{}", self.project_id, self.secret_id);
        let versions = self
            .secrets_client
            .get()
            .list_secret_versions(ListSecretVersionsRequest {
                parent: secret_name,
                ..Default::default()
            })
            .await
            .context("Failed to list secret versions")?
            .into_inner();

        let Some(latest_version) = versions
            .versions
            .into_iter()
            .find(|version| version.state() == State::Enabled)
        else {
            return Ok(None);
        };
        let secret = self
            .secrets_client
            .get()
            .access_secret_version(AccessSecretVersionRequest {
                name: latest_version.name,
            })
            .await
            .context("Failed to access secret version")?
            .into_inner()
            .payload
            .ok_or_else(|| anyhow::anyhow!("Secret version has no payload"))?;

        if let Ok(keyshare) =
            serde_json::from_slice::<RootKeyshareData>(secret.data.as_sensitive_bytes())
        {
            Ok(Some(migrate_root_key_share_data(keyshare)))
        } else if let Ok(keyshare) =
            serde_json::from_slice::<KeyShare>(secret.data.as_sensitive_bytes())
        {
            Ok(Some(keyshare))
        } else {
            anyhow::bail!("Failed to parse keygen")
        }
    }

    async fn store(&self, root_keyshare: &KeyShare) -> anyhow::Result<()> {
        let existing = self.load().await.context("Checking existing keyshare")?;
        if let Some(existing) = existing {
            if existing.epoch_id().get() > root_keyshare.epoch_id().get()
                || (existing.epoch_id() == root_keyshare.epoch_id()
                    && existing.attempt_id().get() >= root_keyshare.attempt_id().get())
            {
                return Err(anyhow::anyhow!(
                    "Refusing to overwrite existing keyshare of id {:?} with new keyshare of older id {:?}",
                    existing.key_id,
                    root_keyshare.key_id,
                ));
            }
        }
        let secret_name = format!("projects/{}/secrets/{}", self.project_id, self.secret_id);
        let data = serde_json::to_vec(&root_keyshare).context("Failed to serialize keygen")?;
        self.secrets_client
            .get()
            .add_secret_version(AddSecretVersionRequest {
                parent: secret_name,
                payload: Some(SecretPayload {
                    data: SecretValue::new(data),
                    ..Default::default()
                }),
            })
            .await
            .context("Failed to create secret version")?;
        Ok(())
    }
}
