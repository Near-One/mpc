use near_sdk::{near, PublicKey};
pub mod hpke {
    pub type PublicKey = [u8; 32];
}
#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct ParticipantInfoV2 {
    pub url: String,
    /// The public key used for encrypting messages.
    pub cipher_pk: hpke::PublicKey,
    /// The public key used for verifying messages.
    pub sign_pk: PublicKey,
}
/* Migration helpers */
impl From<&legacy_contract::primitives::CandidateInfo> for ParticipantInfoV2 {
    fn from(info: &legacy_contract::primitives::CandidateInfo) -> ParticipantInfoV2 {
        ParticipantInfoV2 {
            url: info.url.clone(),
            cipher_pk: info.cipher_pk,
            sign_pk: info.sign_pk.clone(),
        }
    }
}
impl From<&legacy_contract::primitives::ParticipantInfo> for ParticipantInfoV2 {
    fn from(info: &legacy_contract::primitives::ParticipantInfo) -> ParticipantInfoV2 {
        ParticipantInfoV2 {
            url: info.url.clone(),
            cipher_pk: info.cipher_pk,
            sign_pk: info.sign_pk.clone(),
        }
    }
}
