use crate::config::WebUIConfig;
use crate::tracking::TaskHandle;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use axum::serve;
use futures::future::BoxFuture;
use mpc_contract::state::ProtocolContractState;
use mpc_contract::utils::protocol_state_to_string;
use prometheus::{default_registry, Encoder, TextEncoder};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, watch};

/// Wrapper to make Axum understand how to convert anyhow::Error into a 500
/// response.
pub(crate) struct AnyhowErrorWrapper(anyhow::Error);

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

pub(crate) async fn metrics() -> String {
    let metric_families = default_registry().gather();
    let mut buffer = vec![];
    let encoder = TextEncoder::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

#[derive(Clone)]
struct WebServerState {
    /// Root task handle for the whole program.
    root_task_handle: Arc<TaskHandle>,
    /// Sender for debug requests that need the MPC client to respond.
    signature_debug_request_sender: broadcast::Sender<SignatureDebugRequest>,
    /// Receiver for contract state
    contract_state_receiver: watch::Receiver<ProtocolContractState>,
}

async fn debug_tasks(State(state): State<WebServerState>) -> String {
    format!("{:?}", state.root_task_handle.report())
}

#[derive(Clone)]
pub struct SignatureDebugRequest {
    pub kind: SignatureDebugRequestKind,
    responder: mpsc::Sender<String>,
}

impl SignatureDebugRequest {
    pub fn respond(self, response: String) {
        let _ = self.responder.try_send(response);
    }
}

#[derive(Clone)]
pub enum SignatureDebugRequestKind {
    RecentBlocks,
    RecentSignatures,
}

async fn debug_request_from_node(
    State(state): State<WebServerState>,
    request: SignatureDebugRequestKind,
) -> Result<String, AnyhowErrorWrapper> {
    let (sender, mut receiver) = mpsc::channel(1);
    let request = SignatureDebugRequest {
        kind: request,
        responder: sender,
    };
    if state.signature_debug_request_sender.send(request).is_err() {
        return Err(anyhow::anyhow!("Error: node not in the Running state").into());
    }
    let Some(response) = receiver.recv().await else {
        return Err(anyhow::anyhow!("Node dropped the debug request").into());
    };
    Ok(response)
}

async fn debug_blocks(state: State<WebServerState>) -> Result<String, AnyhowErrorWrapper> {
    debug_request_from_node(state, SignatureDebugRequestKind::RecentBlocks).await
}

async fn debug_signatures(state: State<WebServerState>) -> Result<String, AnyhowErrorWrapper> {
    debug_request_from_node(state, SignatureDebugRequestKind::RecentSignatures).await
}

async fn contract_state(mut state: State<WebServerState>) -> Result<String, AnyhowErrorWrapper> {
    Ok(protocol_state_to_string(
        &state.contract_state_receiver.borrow_and_update(),
    ))
}

/// Starts the web server. This is an async function that returns a future.
/// The function itself will return error if the server cannot be started.
///
/// The returned future is the one that actually serves. It will be
/// long-running, and is typically not expected to return. However, dropping
/// the returned future will stop the web server.
pub async fn start_web_server(
    root_task_handle: Arc<crate::tracking::TaskHandle>,
    signature_debug_request_sender: broadcast::Sender<SignatureDebugRequest>,
    config: WebUIConfig,
    contract_state_receiver: watch::Receiver<ProtocolContractState>,
) -> anyhow::Result<BoxFuture<'static, anyhow::Result<()>>> {
    use futures::FutureExt;

    let router = axum::Router::new()
        .route("/metrics", axum::routing::get(metrics))
        .route("/debug/tasks", axum::routing::get(debug_tasks))
        .route("/debug/blocks", axum::routing::get(debug_blocks))
        .route("/debug/signatures", axum::routing::get(debug_signatures))
        .route("/debug/contract", axum::routing::get(contract_state))
        .route("/health", axum::routing::get(|| async { "OK" }))
        .with_state(WebServerState {
            root_task_handle,
            signature_debug_request_sender,
            contract_state_receiver,
        });

    let tcp_listener = TcpListener::bind(&format!("{}:{}", config.host, config.port)).await?;
    Ok(async move {
        serve(tcp_listener, router).await?;
        anyhow::Ok(())
    }
    .boxed())
}
