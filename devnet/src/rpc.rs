use crate::types::RpcConfig;
use futures::future::BoxFuture;
use futures::FutureExt;
use near_jsonrpc_client::{methods, JsonRpcClient, MethodCallResult};
use std::ops::Deref;
use std::sync::Arc;

/// An aggregation of multiple RPC endpoints, each with its own QPS and concurrency limits.
/// When using this aggregated client, any request will be automatically subject to these limits,
/// and will use as many RPC endpoints as needed to saturate each client's limits.
pub struct NearRpcClients {
    rpcs: Vec<NearRpcClient>,
}

/// A single RPC endpoint with its own QPS and concurrency limits.
struct NearRpcClient {
    client: Arc<JsonRpcClient>,
    /// Rate limiter. The way it works is we can receive a token when we're allowed to send per
    /// the rate limit.
    receiver: flume::Receiver<()>,
    /// Concurrency limiter. In-flight requests have a semaphore permit.
    concurrency: Arc<tokio::sync::Semaphore>,
    rate_limit: usize,
}

impl NearRpcClient {
    fn new(config: RpcConfig) -> Self {
        let client = JsonRpcClient::connect(config.url);
        let concurrency = tokio::sync::Semaphore::new(config.max_concurrency);
        let (sender, receiver) = flume::bounded(config.rate_limit);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                std::time::Duration::from_secs(1).div_f64(config.rate_limit as f64),
            );
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                if sender.send_async(()).await.is_err() {
                    break;
                }
            }
        });
        Self {
            client: Arc::new(client),
            receiver,
            concurrency: Arc::new(concurrency),
            rate_limit: config.rate_limit,
        }
    }

    /// Wait until we're both allowed to send a request and there is enough concurrency remaining.
    async fn ready(&self) -> RpcClientPermit {
        let concurrency_permit = self.concurrency.clone().acquire_owned().await.unwrap();
        self.receiver.recv_async().await.unwrap();
        RpcClientPermit {
            _concurrency_permit: concurrency_permit,
            client: self.client.clone(),
        }
    }
}

/// Represents that we're allowed to send a request per both rate limit and concurrency control.
pub struct RpcClientPermit {
    _concurrency_permit: tokio::sync::OwnedSemaphorePermit,
    client: Arc<JsonRpcClient>,
}

impl Deref for RpcClientPermit {
    type Target = JsonRpcClient;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl NearRpcClients {
    pub async fn new(rpcs: Vec<RpcConfig>) -> Self {
        let rpcs = rpcs.into_iter().map(NearRpcClient::new).collect();
        Self { rpcs }
    }

    /// Requests a permit to send a request, subject to rate limit and concurrency control.
    /// A request can be immediately sent after this function returns.
    pub async fn lease(&self) -> RpcClientPermit {
        let (permit, _, _) =
            futures::future::select_all(self.rpcs.iter().map(|rpc| rpc.ready().boxed())).await;
        permit
    }

    pub async fn submit<M>(&self, method: M) -> MethodCallResult<M::Response, M::Error>
    where
        M: methods::RpcMethod,
    {
        let rpc = self.lease().await;
        rpc.call(method).await
    }

    /// Convenient function to perform a request with retries. Each request is subject to the same
    /// limits as lease().
    pub async fn with_retry<T>(
        &self,
        max_retries: usize,
        f: impl for<'a> Fn(&'a JsonRpcClient) -> BoxFuture<'a, anyhow::Result<T>>,
    ) -> anyhow::Result<T> {
        let mut retries = 0;
        loop {
            let permit = self.lease().await;
            match f(&permit).await {
                Ok(result) => return Ok(result),
                Err(err) => {
                    retries += 1;
                    if retries >= max_retries {
                        return Err(err);
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }

    /// Total QPS the system can handle.
    pub fn total_qps(&self) -> usize {
        self.rpcs.iter().map(|rpc| rpc.rate_limit).sum()
    }
}
