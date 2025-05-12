use std::sync::Arc;

use crate::rpc::NearRpcClients;
use anyhow::anyhow;
use near_jsonrpc_client::methods::query::RpcQueryRequest;
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_primitives::{
    types::{BlockReference, Finality},
    views::{ContractCodeView, QueryRequest},
};
use near_sdk::AccountId;

/// fetches the contract code and hash from `target`.
pub async fn get_contract_code(
    client: &Arc<NearRpcClients>,
    target: AccountId,
) -> anyhow::Result<ContractCodeView> {
    let request = RpcQueryRequest {
        block_reference: BlockReference::Finality(Finality::Final),
        request: QueryRequest::ViewCode { account_id: target },
    };
    match client.submit(request).await?.kind {
        QueryResponseKind::ViewCode(code) => Ok(code),
        _ => Err(anyhow!("unexpected response")),
    }
}
