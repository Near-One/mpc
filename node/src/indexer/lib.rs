use actix::Addr;
use anyhow::bail;
use mpc_contract::state::ProtocolContractState;
use near_client::ClientActor;
use near_client::Status;
use near_indexer_primitives::types;
use near_indexer_primitives::types::AccountId;
use near_indexer_primitives::views::QueryRequest;
use near_indexer_primitives::views::QueryResponseKind::CallResult;
use near_o11y::WithSpanContextExt;
use std::time::Duration;
use tokio::time;

const INTERVAL: Duration = Duration::from_millis(500);

pub(crate) async fn wait_for_full_sync(client: &Addr<ClientActor>) {
    loop {
        time::sleep(INTERVAL).await;

        let Ok(Ok(status)) = client
            .send(
                Status {
                    is_health_check: false,
                    detailed: false,
                }
                .with_span_context(),
            )
            .await
        else {
            continue;
        };

        if !status.sync_info.syncing {
            return;
        }
    }
}

pub(crate) async fn get_mpc_contract_state(
    mpc_contract_id: AccountId,
    client: &actix::Addr<near_client::ViewClientActor>,
) -> anyhow::Result<ProtocolContractState> {
    let request = QueryRequest::CallFunction {
        account_id: mpc_contract_id,
        method_name: "state".to_string(),
        args: vec![].into(),
    };
    let query = near_client::Query {
        block_reference: types::BlockReference::Finality(types::Finality::Final),
        request,
    };
    let response = client.send(query.with_span_context()).await??;
    match response.kind {
        CallResult(result) => Ok(serde_json::from_slice(&result.result)?),
        _ => {
            bail!("got unexpected response querying mpc contract state")
        }
    }
}

pub(crate) async fn wait_for_contract_code(
    contract_id: AccountId,
    client: &actix::Addr<near_client::ViewClientActor>,
) {
    loop {
        time::sleep(INTERVAL).await;
        if get_mpc_contract_state(contract_id.clone(), client)
            .await
            .is_ok()
        {
            return;
        }
    }
}
