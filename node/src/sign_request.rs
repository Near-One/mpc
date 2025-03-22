use crate::db::{DBCol, SecretDB};
use crate::metrics;
use mpc_contract::primitives::signature::{PayloadHash, Tweak};
use near_indexer_primitives::CryptoHash;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::broadcast;

pub type SignatureId = CryptoHash;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignatureRequest {
    /// The unique ID that identifies the signature, and can also uniquely identify the response.
    pub id: SignatureId,
    /// The receipt that generated the signature request, which can be used to look up on chain.
    pub receipt_id: CryptoHash,
    pub msg_hash: PayloadHash,
    pub tweak: Tweak,
    pub entropy: [u8; 32],
    pub timestamp_nanosec: u64,
}

pub struct SignRequestStorage {
    db: Arc<SecretDB>,
    add_sender: broadcast::Sender<SignatureId>,
}

impl SignRequestStorage {
    pub fn new(db: Arc<SecretDB>) -> anyhow::Result<Self> {
        let (tx, _) = tokio::sync::broadcast::channel(500);
        Ok(Self { db, add_sender: tx })
    }

    /// If given request is already in the database, returns false.
    /// Otherwise, inserts the request and returns true.
    pub fn add(&self, request: &SignatureRequest) -> bool {
        let key = borsh::to_vec(&request.id).unwrap();
        if self
            .db
            .get(DBCol::SignRequest, &key)
            .expect("Unrecoverable error reading from database")
            .is_some()
        {
            return false;
        }
        let value_ser = serde_json::to_vec(&request).unwrap();
        let mut update = self.db.update();
        update.put(DBCol::SignRequest, &key, &value_ser);
        update
            .commit()
            .expect("Unrecoverable error writing to database");
        let _ = self.add_sender.send(request.id);
        true
    }

    /// Blocks until a signature request with given id is present, then returns it.
    /// This behavior is necessary because a peer might initiate computation for a signature
    /// request before our indexer has caught up to the request. We need proof of the request
    /// from on-chain in order to participate in the computation.
    pub async fn get(&self, id: SignatureId) -> Result<SignatureRequest, anyhow::Error> {
        let key = borsh::to_vec(&id)?;
        let mut rx = self.add_sender.subscribe();
        if let Some(request_ser) = self.db.get(DBCol::SignRequest, &key)? {
            return Ok(serde_json::from_slice(&request_ser)?);
        }
        loop {
            let added_id = match rx.recv().await {
                Ok(added_id) => added_id,
                Err(e) => {
                    metrics::SIGN_REQUEST_CHANNEL_FAILED.inc();
                    return Err(anyhow::anyhow!("Error in sign_request channel recv, {}", e));
                }
            };
            if added_id == id {
                break;
            }
        }
        let request_ser = self.db.get(DBCol::SignRequest, &key)?.unwrap();
        Ok(serde_json::from_slice(&request_ser)?)
    }
}
