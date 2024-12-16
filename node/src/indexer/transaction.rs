use near_crypto::{InMemorySigner, SecretKey, Signer};
use near_indexer::near_primitives::account::AccessKey;
use near_indexer_primitives::near_primitives::transaction::{
    FunctionCallAction, SignedTransaction, Transaction, TransactionV0,
};
use near_indexer_primitives::types::AccountId;
use near_indexer_primitives::CryptoHash;
use std::sync::Mutex;

pub(crate) struct TransactionSigner {
    signer: Signer,
    nonce: Mutex<u64>,
}

impl TransactionSigner {
    pub(crate) fn from_key(account_id: AccountId, key: SecretKey) -> Self {
        TransactionSigner {
            signer: InMemorySigner::from_secret_key(account_id, key),
            nonce: Mutex::new(0),
        }
    }

    /// Atomically increments the nonce and returns the previous value
    fn make_nonce(&self, last_known_block_height: u64) -> u64 {
        let min_nonce = AccessKey::ACCESS_KEY_NONCE_RANGE_MULTIPLIER * last_known_block_height;
        let mut nonce = self.nonce.lock().unwrap();
        let new_nonce = std::cmp::max(min_nonce, *nonce + 1);
        *nonce = new_nonce;
        new_nonce
    }

    pub(crate) fn create_and_sign_function_call_tx(
        &self,
        receiver_id: AccountId,
        method_name: String,
        args: Vec<u8>,
        block_hash: CryptoHash,
        block_height: u64,
    ) -> SignedTransaction {
        let action = FunctionCallAction {
            method_name,
            args,
            gas: 300000000000000,
            deposit: 0,
        };
        let signer_id = match &self.signer {
            Signer::InMemory(InMemorySigner { account_id, .. }) => account_id.clone(),
            _ => unreachable!(),
        };
        let transaction = Transaction::V0(TransactionV0 {
            signer_id,
            public_key: self.signer.public_key().clone(),
            nonce: self.make_nonce(block_height),
            receiver_id,
            block_hash,
            actions: vec![action.into()],
        });

        let tx_hash = transaction.get_hash_and_size().0;
        let signature = self.signer.sign(tx_hash.as_ref());

        SignedTransaction::new(signature, transaction.clone())
    }
}
