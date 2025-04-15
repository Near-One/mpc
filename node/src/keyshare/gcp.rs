use super::permanent::PermanentKeyStorageBackend;
use anyhow::Context;
use gcloud_sdk::google::cloud::secretmanager::v1::secret_manager_service_client::SecretManagerServiceClient;
use gcloud_sdk::google::cloud::secretmanager::v1::secret_version::State;
use gcloud_sdk::google::cloud::secretmanager::v1::{
    AccessSecretVersionRequest, AddSecretVersionRequest, ListSecretVersionsRequest,
};
use gcloud_sdk::proto_ext::secretmanager::SecretPayload;
use gcloud_sdk::{GoogleApi, GoogleAuthMiddleware, SecretValue};

/// Keyshare storage that loads and stores the key from Google Secret Manager.
pub struct GcpPermanentKeyStorageBackend {
    secrets_client: GoogleApi<SecretManagerServiceClient<GoogleAuthMiddleware>>,
    project_id: String,
    secret_id: String,
}

impl std::fmt::Debug for GcpPermanentKeyStorageBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpPermanentKeyStorageBackend")
            .field("project_id", &self.project_id)
            .field("secret_id", &self.secret_id)
            .finish()
    }
}

impl GcpPermanentKeyStorageBackend {
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
impl PermanentKeyStorageBackend for GcpPermanentKeyStorageBackend {
    async fn load(&self) -> anyhow::Result<Option<Vec<u8>>> {
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

        Ok(Some(secret.data.as_sensitive_bytes().to_vec()))
    }

    async fn store(&self, data: &[u8], _identifier: &str) -> anyhow::Result<()> {
        let secret_name = format!("projects/{}/secrets/{}", self.project_id, self.secret_id);
        self.secrets_client
            .get()
            .add_secret_version(AddSecretVersionRequest {
                parent: secret_name,
                payload: Some(SecretPayload {
                    data: SecretValue::new(data.to_vec()),
                    ..Default::default()
                }),
            })
            .await
            .context("Failed to create secret version")?;
        Ok(())
    }
}
