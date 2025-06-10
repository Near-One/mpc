use crate::{
    errors::{Error, InvalidCandidateSet},
    get_collateral,
};
use dcap_qvl::verify::{self, VerifiedReport};
use near_sdk::{env, near, NearToken};
use std::fmt::{self};

#[near(serializers=[borsh, json])]
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Default)]
pub struct TeeParticipantInfo {
    /// TEE Remote Attestation Quote that proves the participant's identity.
    pub tee_quote: Vec<u8>,
    /// Supplemental data for the TEE quote, including Intel certificates to verify it came from
    /// genuine Intel hardware, along with details about the Trusted Computing Base (TCB)
    /// versioning, status, and other relevant info.
    pub quote_collateral: String,
    /// Dstack event log.
    pub raw_tcb_info: String,
}

/// Without this, the following tests fail with HostError(TotalLogLengthExceeded { length: 31510, limit: 16384 }):
/// - tests::test_signature_simple
/// - tests::test_signature_simple_legacy
/// - tests::test_signature_timeout
impl fmt::Debug for TeeParticipantInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn hex_preview(bytes: &[u8], max: usize) -> String {
            if bytes.len() <= max {
                format!("{:02x?}", bytes)
            } else {
                format!("{:02x?}… ({} bytes)", &bytes[..max], bytes.len())
            }
        }
        fn str_preview(s: &str, max: usize) -> String {
            if s.len() <= max {
                format!("{:?}", s)
            } else {
                format!("{:?}… ({} chars)", &s[..max], s.len())
            }
        }
        f.debug_struct("TeeParticipantInfo")
            .field("tee_quote", &hex_preview(&self.tee_quote, 128))
            .field(
                "quote_collateral",
                &str_preview(&self.quote_collateral, 128),
            )
            .field("raw_tcb_info", &str_preview(&self.raw_tcb_info, 128))
            .finish()
    }
}

impl TeeParticipantInfo {
    pub fn verify_quote(&self, timestamp: u64) -> Result<VerifiedReport, Error> {
        let tee_collateral = get_collateral(self.quote_collateral.clone());
        let verification_result = verify::verify(&self.tee_quote, &tee_collateral, timestamp);
        verification_result.map_err(|_| InvalidCandidateSet::InvalidParticipantsTeeQuote.into())
    }

    pub fn required_deposit(&self) -> NearToken {
        let bytes_used = std::mem::size_of::<Self>() as u128; // TODO is it a correct estimate?
        env::storage_byte_cost().saturating_mul(bytes_used)
    }
}
