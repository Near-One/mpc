use super::permanent::LegacyRootKeyshareData;
use super::{Keyshare, KeyshareData};
use cait_sith::KeygenOutput;
use mpc_contract::primitives::domain::DomainId;
use mpc_contract::primitives::key_state::{AttemptId, EpochId, KeyEventId};

/// For compatibility while we perform the refactoring.
/// Converts the new format keyshares array to the old format.
pub fn legacy_ecdsa_key_from_keyshares(
    keyshares: &[Keyshare],
) -> anyhow::Result<LegacyRootKeyshareData> {
    if keyshares.len() != 1 {
        anyhow::bail!("Expected exactly one keyshare, got {}", keyshares.len());
    }
    let keyshare = &keyshares[0];
    if keyshare.key_id.domain_id != DomainId::legacy_ecdsa_id() {
        anyhow::bail!(
            "Expected keyshare for legacy ECDSA domain, got {:?}",
            keyshare.key_id.domain_id
        );
    }
    let KeyshareData::Secp256k1(secp256k1_data) = &keyshare.data;
    Ok(LegacyRootKeyshareData {
        epoch: keyshare.key_id.epoch_id.get(),
        private_share: secp256k1_data.private_share,
        public_key: secp256k1_data.public_key,
    })
}

//impl KeyshareStorage {
//    /// For compatibility with the rest of the MPC codebase while we perform refactoring.
//    /// Loads the keyshare and converts it to legacy format.
//    pub async fn compat_load_legacy_keyshare(
//        &self,
//        epoch_id: u64,
//        public_key: near_crypto::PublicKey,
//    ) -> anyhow::Result<LegacyRootKeyshareData> {
//        let keyset = Keyset {
//            epoch_id: EpochId::new(epoch_id),
//            domains: vec![KeyForDomain {
//                domain_id: DomainId::legacy_ecdsa_id(),
//                key: public_key.to_string().parse()?,
//                attempt: AttemptId::legacy_attempt_id(),
//            }],
//        };
//        let keyshares = self.load_keyset(&keyset).await?;
//        legacy_ecdsa_key_from_keyshares(&keyshares)
//    }
//}

impl Keyshare {
    /// Converts the legacy keyshare to a keyshare in the new format.
    pub fn from_legacy(legacy: &LegacyRootKeyshareData) -> Self {
        Self {
            key_id: KeyEventId::new(
                EpochId::new(legacy.epoch),
                DomainId::legacy_ecdsa_id(),
                AttemptId::legacy_attempt_id(),
            ),
            data: KeyshareData::Secp256k1(KeygenOutput {
                private_share: legacy.private_share,
                public_key: legacy.public_key,
            }),
        }
    }
}
