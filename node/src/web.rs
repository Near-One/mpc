use crate::config::WebUIConfig;
use crate::mpc_client::{MpcClient, SignatureResult};
use crate::sign_request::{SignatureId, SignatureRequest};
use crate::tracking::{self, TaskHandle};
use anyhow::Context;
use axum::body::Body;
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use axum::{extract::{Query, State}, routing::get, Json, Router};
use futures::future::BoxFuture;
use futures::{stream, FutureExt, StreamExt, TryStreamExt};
use k256::elliptic_curve::scalar::FromUintUnchecked;
use k256::sha2::{Digest, Sha256};
use k256::{U256};
use prometheus::{default_registry, Encoder, TextEncoder};
use rand::Rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use axum::routing::post;
use futures_util::future::join_all;
use tokio::sync::OnceCell;
use tokio::{join, time};
use crate::frost;
use crate::sign::derive_ecdsa_key;
use crate::validation::ProofModel;

/// Wrapper to make Axum understand how to convert anyhow::Error into a 500
/// response.
struct AnyhowErrorWrapper(anyhow::Error);

impl From<anyhow::Error> for AnyhowErrorWrapper {
    fn from(e: anyhow::Error) -> Self {
        AnyhowErrorWrapper(e)
    }
}

impl IntoResponse for AnyhowErrorWrapper {
    fn into_response(self) -> Response<Body> {
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from(format!("{:?}", self.0)))
            .unwrap()
    }
}

async fn metrics() -> String {
    let metric_families = default_registry().gather();
    let mut buffer = vec![];
    let encoder = TextEncoder::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

async fn debug_tasks(State(state): State<WebServerState>) -> String {
    format!("{:?}", state.root_task_handle.report())
}

fn generate_ids(repeat: usize, seed: u64) -> Vec<[u8; 32]> {
    let mut rng: rand_xorshift::XorShiftRng = rand::SeedableRng::seed_from_u64(seed);
    (0..repeat).map(|_| rng.gen::<[u8; 32]>()).collect()
}

// ------------------------------------------------------------

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Ecdsa = 0,
    Ed25519 = 1,
}

impl TryFrom<u8> for KeyType {
    type Error = &'static str;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(KeyType::Ecdsa),
            1 => Ok(KeyType::Ed25519),
            _ => Err("Invalid curve type. Expected 0 (Ecdsa) or 1 (Ed25519)."),
        }
    }
}

impl Serialize for KeyType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(*self as u8)
    }
}

impl<'de> Deserialize<'de> for KeyType {
    fn deserialize<D>(deserializer: D) -> Result<KeyType, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u8::deserialize(deserializer)?;
        KeyType::try_from(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserSignatureRequest {
    pub uid: String,
    pub message: k256::Scalar,
    pub proof: ProofModel,
    pub key_type: KeyType
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexRequest {
    user_signature_request: UserSignatureRequest,
    id: SignatureId,
    entropy: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct EcdsaResponse {
    pub big_r: k256::AffinePoint,
    pub signature: k256::Scalar,
    pub public_key: k256::AffinePoint,
}

#[derive(Serialize, Deserialize)]
struct EddsaResponse {
    pub signature: frost_ed25519::Signature,
    pub public_key: frost_ed25519::VerifyingKey,
}


#[derive(Serialize, Deserialize)]
pub enum SignatureResponse {
    Ecdsa(EcdsaResponse),
    Eddsa(EddsaResponse),
}

async fn announce_signature_to_us(
    client: Arc<MpcClient>,
    index_request: IndexRequest
) -> Result<(), AnyhowErrorWrapper> {
    validate(client.clone(), index_request.user_signature_request.clone()).await?;

    let tweak = from_uid_to_scalar(&index_request.user_signature_request.uid);
    client.add_sign_request(&SignatureRequest {
        id: index_request.id,
        msg_hash: index_request.user_signature_request.message.to_bytes().try_into().unwrap(),
        tweak,
        entropy: index_request.entropy,
        timestamp_nanosec: 0,
        key_type: index_request.user_signature_request.key_type,
    });

    Ok(())
}

async fn announce_signature_to_others(
    mpc_client: Arc<MpcClient>,
    index_request: IndexRequest
) {
    let config = mpc_client.get_config();
    let web_client = mpc_client.get_web_client();
    let web_ui_port = config.web_ui.port;

    let post_calls = config
        .mpc
        .participants
        .participants
        .iter()
        .filter(|participant| participant.id != config.mpc.my_participant_id)
        .map(|participant| {
            let address = &participant.address;
            let url = format!("http://{}:{}/index", address, web_ui_port);
            let data = serde_json::to_value(index_request.clone()).unwrap();
            let web_client = web_client.clone();
            async move {
                let response = web_client
                    .post(&url)
                    .json(&data)
                    .send()
                    .await?;

                if response.status().is_success() {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!(
                        "Failed to notify participant at {}: {}",
                        address,
                        response.status()
                    ))
                }
            }
        });

    let results: Vec<Result<(), anyhow::Error>> = join_all(post_calls).await;

    for result in results {
        if let Err(e) = result {
            eprintln!("Error in announcing signature: {}", e);
        }
    }
}

pub fn from_uid_to_scalar(uid: &String) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(uid);
    let tweak = k256::Scalar::from_uint_unchecked(U256::from_le_slice(&hasher.finalize()));
    // wtf line. We needed to convert from Scalar type to [u8; 32] type, and this way I try to ensure validity of the cast.
    // hope it will be substituted with something sane in the future.
    let tweak = tweak.to_bytes().try_into().unwrap();
    tweak
}

fn current_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64
}

async fn validate(
    mpc_client: Arc<MpcClient>,
    user_signature_request: UserSignatureRequest,
) -> Result<(), AnyhowErrorWrapper> {
    mpc_client
        .clone()
        .get_validation().verify(
        user_signature_request.uid,
        hex::encode(user_signature_request.message.to_bytes()),
        user_signature_request.proof,
    )
        .await?;
    Ok(())
}

async fn index(
    State(state): State<WebServerState>,
    Json(index_request): Json<IndexRequest>,
) -> Result<(), AnyhowErrorWrapper> {
    let Some(mpc_client) = state.mpc_client.unwrap().get().cloned() else {
        return Err(anyhow::anyhow!("MPC client not ready").into());
    };
    let client = Arc::new(mpc_client);
    announce_signature_to_us(client, index_request).await
}

async fn sign(
    State(state): State<WebServerState>,
    Json(user_signature_request): Json<UserSignatureRequest>,
) -> Result<Json<SignatureResponse>, AnyhowErrorWrapper> {
    let Some(mpc_client) = state.mpc_client.unwrap().get().cloned() else {
        return Err(anyhow::anyhow!("MPC client not ready").into());
    };
    let mpc_client = Arc::new(mpc_client);

    let entropy = generate_ids(1, current_time_millis())[0];
    let id = SignatureId::from(entropy.clone());

    let index_request = IndexRequest {
        user_signature_request,
        id,
        entropy,
    };

    let (validation_succeeded_on_us, _) = join!(
        announce_signature_to_us(mpc_client.clone(), index_request.clone()),
        announce_signature_to_others(mpc_client.clone(), index_request)
    );
    validation_succeeded_on_us?;

    let result = state
        .task_handle
        .scope("debug_sign", async move {
            let timeout = Duration::from_secs(10);
            let signature = time::timeout(timeout, {
                tracking::spawn(
                    &format!("sign #{:?}", id),
                    mpc_client.clone().make_signature(id),
                )
                    .map(|result| anyhow::Ok(result??))
            })
                .await
                .context("timeout")?
                .context("signature failed")?;

            match signature {
                SignatureResult::Ecdsa(result) => {
                    anyhow::Ok(Json(
                        SignatureResponse::Ecdsa(
                            EcdsaResponse {
                                big_r: result.signature.big_r,
                                signature: result.signature.s,
                                public_key: result.public_key,
                            })
                    ))
                }
                SignatureResult::Eddsa(result) => {
                    anyhow::Ok(Json(
                        SignatureResponse::Eddsa(
                            EddsaResponse {
                                signature: result.signature,
                                public_key: result.public_key,
                            }
                        )
                    ))
                }
            }
        })
        .await?;

    Ok(result)
}

#[derive(Serialize, Deserialize)]
pub struct PublicKeyRequest {
    pub uid: String
}

#[derive(Serialize, Deserialize)]
pub struct PublicKeyResponse {
    pub eddsa: frost_ed25519::VerifyingKey,
    pub ecdsa: k256::AffinePoint,
}

async fn public_key(
    State(state): State<WebServerState>,
    Json(public_key_request): Json<PublicKeyRequest>,
) -> Result<Json<PublicKeyResponse>, AnyhowErrorWrapper> {
    let Some(mpc_client) = state.mpc_client.unwrap().get().cloned() else {
        return Err(anyhow::anyhow!("MPC client not ready").into());
    };
    let tweak = from_uid_to_scalar(&public_key_request.uid);
    let (eddsa_pk, ecdsa_pk) = mpc_client.get_public_key();

    let eddsa_pk = frost::kdf::derive_public_key_package(&eddsa_pk, tweak);
    let ecdsa_pk = derive_ecdsa_key(ecdsa_pk, tweak);

    Ok(Json(PublicKeyResponse {
        eddsa: eddsa_pk.verifying_key().clone(),
        ecdsa: ecdsa_pk,
    }))
}

// ------------------------------------------------------------

fn sha256hash(data: &[u8]) -> k256::Scalar {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    k256::Scalar::from_uint_unchecked(U256::from_be_slice(&bytes))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DebugIndexRequest {
    #[serde(default)]
    repeat: Option<usize>,
    #[serde(default)]
    seed: u64,
    msg: String,
    #[serde(default)]
    tweak: k256::Scalar,
    #[serde(default)]
    entropy: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DebugSignatureRequest {
    #[serde(default)]
    repeat: Option<usize>,
    #[serde(default)]
    seed: u64,
    #[serde(default)]
    parallelism: Option<usize>,
    #[serde(default)]
    timeout: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DebugSignatureOutput {
    big_r: String,
    s: String,
    public_key: String,
}

#[derive(Clone)]
struct WebServerState {
    /// Task handle for the task that runs the web server.
    task_handle: Arc<TaskHandle>,
    /// Root task handle for the whole program.
    root_task_handle: Arc<TaskHandle>,
    /// MPC client, for signing. We take a OnceCell, so that we can start the
    /// web server (for debugging) before the MPC client is ready.
    mpc_client: Option<Arc<OnceCell<MpcClient>>>,
}

/// Starts the web server. This is an async function that returns a future.
/// The function itself will return error if the server cannot be started.
///
/// The returned future is the one that actually serves. It will be
/// long-running, and is typically not expected to return. However, dropping
/// the returned future will stop the web server.
pub async fn start_web_server(
    root_task_handle: Arc<TaskHandle>,
    config: WebUIConfig,
    mpc_client: Option<Arc<OnceCell<MpcClient>>>,
) -> anyhow::Result<BoxFuture<'static, anyhow::Result<()>>> {
    let web_server_state = WebServerState {
        task_handle: tracking::current_task(),
        root_task_handle,
        mpc_client: mpc_client.clone(),
    };

    let router = Router::new()
        .route("/metrics", get(metrics))
        .route("/debug/tasks", get(debug_tasks));
    let router = if mpc_client.is_some() {
        router
            .route("/sign", post(sign))
            .route("/index", post(index))
            .route("/public_key", post(public_key))
    } else {
        router
    };
    let router = router.with_state(web_server_state);

    let tcp_listener =
        tokio::net::TcpListener::bind(&format!("{}:{}", config.host, config.port)).await?;
    Ok(async move {
        axum::serve(tcp_listener, router).await?;
        anyhow::Ok(())
    }
    .boxed())
}
