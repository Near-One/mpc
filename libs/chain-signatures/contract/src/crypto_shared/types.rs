use std::fmt::Display;

use borsh::{BorshDeserialize, BorshSerialize};
use curve25519_dalek::EdwardsPoint;
use k256::{
    elliptic_curve::{bigint::ArrayEncoding, group::GroupEncoding, CurveArithmetic, PrimeField},
    AffinePoint, Secp256k1, U256,
};
use near_sdk::near;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum SignatureResponse {
    Secp256k1(k256_types::SignatureResponse),
    Edd25519(edd25519_types::SignatureResponse),
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum PublicKeyExtended {
    Secp256k1 {
        near_public_key: near_sdk::PublicKey,
    },
    // Invariant: `edwards_point` is always the decompressed representation of `near_public_key_compressed`.
    Ed25519 {
        /// Serialized compressed Edwards-y point.
        near_public_key_compressed: near_sdk::PublicKey,
        /// Decompressed Edwards point used for curve arithmetic operations.
        edwards_point: EdwardsPoint,
    },
}

#[derive(Clone, Debug)]
pub enum PublicKeyExtendedConversionError {
    PublicKeyLengthMalformed,
    FailedDecompressingToEdwardsPoint,
}

impl Display for PublicKeyExtendedConversionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::PublicKeyLengthMalformed => "Provided public key has malformed length.",
            Self::FailedDecompressingToEdwardsPoint => {
                "The provided compressed key can not be decompressed to an edwards point."
            }
        };

        f.write_str(message)
    }
}

impl From<PublicKeyExtended> for near_sdk::PublicKey {
    fn from(public_key_extended: PublicKeyExtended) -> Self {
        match public_key_extended {
            PublicKeyExtended::Secp256k1 { near_public_key } => near_public_key,
            PublicKeyExtended::Ed25519 {
                near_public_key_compressed,
                ..
            } => near_public_key_compressed,
        }
    }
}

impl TryFrom<near_sdk::PublicKey> for PublicKeyExtended {
    type Error = PublicKeyExtendedConversionError;
    fn try_from(near_public_key: near_sdk::PublicKey) -> Result<Self, Self::Error> {
        let extended_key = match near_public_key.curve_type() {
            near_sdk::CurveType::ED25519 => {
                let public_key_bytes: &[u8; 32] = near_public_key
                    .as_bytes()
                    .get(1..)
                    .map(TryInto::try_into)
                    .ok_or(PublicKeyExtendedConversionError::PublicKeyLengthMalformed)?
                    .map_err(|_| PublicKeyExtendedConversionError::PublicKeyLengthMalformed)?;

                let edwards_point = curve25519_dalek::EdwardsPoint::from_bytes(public_key_bytes)
                    .into_option()
                    .ok_or(PublicKeyExtendedConversionError::FailedDecompressingToEdwardsPoint)?;

                Self::Ed25519 {
                    near_public_key_compressed: near_public_key,
                    edwards_point,
                }
            }
            near_sdk::CurveType::SECP256K1 => Self::Secp256k1 { near_public_key },
        };

        Ok(extended_key)
    }
}

impl PublicKeyExtended {
    pub fn near_public_key_ref(&self) -> &near_sdk::PublicKey {
        match self {
            PublicKeyExtended::Secp256k1 { near_public_key } => near_public_key,
            PublicKeyExtended::Ed25519 {
                near_public_key_compressed,
                ..
            } => near_public_key_compressed,
        }
    }
}

/// Module that adds implementation of [`BorshSerialize`] and [`BorshDeserialize`] for
/// [`PublicKeyExtended`].
mod serialize {
    use super::*;

    #[near(serializers=[borsh, json])]
    #[derive(Debug, PartialEq, Eq, Clone)]
    enum PublicKeyExtendedHelper {
        Secp256k1 {
            near_public_key: near_sdk::PublicKey,
        },
        Ed25519 {
            near_public_key_compressed: near_sdk::PublicKey,
            edwards_point: SerializableEdwardsPoint,
        },
    }

    impl BorshSerialize for PublicKeyExtended {
        fn serialize<W: std::io::prelude::Write>(&self, writer: &mut W) -> std::io::Result<()> {
            let serializable_helper_representation = match self.clone() {
                PublicKeyExtended::Secp256k1 { near_public_key } => {
                    PublicKeyExtendedHelper::Secp256k1 { near_public_key }
                }
                PublicKeyExtended::Ed25519 {
                    near_public_key_compressed,
                    edwards_point,
                } => PublicKeyExtendedHelper::Ed25519 {
                    near_public_key_compressed,
                    edwards_point: SerializableEdwardsPoint(edwards_point),
                },
            };
            let to_ser: Vec<u8> = serde_json::to_vec(&serializable_helper_representation)?;
            BorshSerialize::serialize(&to_ser, writer)
        }
    }

    impl BorshDeserialize for PublicKeyExtended {
        fn deserialize_reader<R: std::io::prelude::Read>(reader: &mut R) -> std::io::Result<Self> {
            let from_ser: Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
            let deserializable_helper_representation: PublicKeyExtendedHelper =
                serde_json::from_slice(&from_ser)?;

            let public_key_extended = match deserializable_helper_representation {
                PublicKeyExtendedHelper::Secp256k1 { near_public_key } => {
                    PublicKeyExtended::Secp256k1 { near_public_key }
                }
                PublicKeyExtendedHelper::Ed25519 {
                    near_public_key_compressed,
                    edwards_point,
                } => PublicKeyExtended::Ed25519 {
                    near_public_key_compressed,
                    edwards_point: edwards_point.0,
                },
            };

            Ok(public_key_extended)
        }
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize, Eq, Clone, Copy)]
    pub struct SerializableEdwardsPoint(EdwardsPoint);

    impl BorshSerialize for SerializableEdwardsPoint {
        fn serialize<W: std::io::prelude::Write>(&self, writer: &mut W) -> std::io::Result<()> {
            let to_ser: Vec<u8> = serde_json::to_vec(&self.0)?;
            BorshSerialize::serialize(&to_ser, writer)
        }
    }

    impl BorshDeserialize for SerializableEdwardsPoint {
        fn deserialize_reader<R: std::io::prelude::Read>(reader: &mut R) -> std::io::Result<Self> {
            let from_ser: Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
            let edwards_point = serde_json::from_slice(&from_ser)?;
            Ok(SerializableEdwardsPoint(edwards_point))
        }
    }
}

pub trait ScalarExt: Sized {
    fn from_bytes(bytes: [u8; 32]) -> Option<Self>;
    fn from_non_biased(bytes: [u8; 32]) -> Self;
    fn to_bytes(&self) -> [u8; 32];
}

pub mod k256_types {
    use super::*;
    use k256::Scalar;

    pub type PublicKey = <Secp256k1 as CurveArithmetic>::AffinePoint;

    impl ScalarExt for Scalar {
        /// Returns nothing if the bytes are greater than the field size of Secp256k1.
        /// This will be very rare with random bytes as the field size is 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
        fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
            let bytes = U256::from_be_slice(bytes.as_slice());
            Self::from_repr(bytes.to_be_byte_array()).into_option()
        }

        /// When the user can't directly select the value, this will always work
        /// Use cases are things that we know have been hashed
        fn from_non_biased(hash: [u8; 32]) -> Self {
            // This should never happen.
            // The space of inputs is 2^256, the space of the field is ~2^256 - 2^129.
            // This mean that you'd have to run 2^127 hashes to find a value that causes this to fail.
            Self::from_bytes(hash).expect("Derived scalar value falls outside of the field")
        }

        fn to_bytes(&self) -> [u8; 32] {
            self.to_bytes().into()
        }
    }

    // Is there a better way to force a borsh serialization?
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy, Ord, PartialOrd)]
    pub struct SerializableScalar {
        pub scalar: Scalar,
    }

    impl SerializableScalar {
        pub fn new(scalar: Scalar) -> Self {
            Self { scalar }
        }
    }

    impl From<Scalar> for SerializableScalar {
        fn from(scalar: Scalar) -> Self {
            Self { scalar }
        }
    }

    impl BorshSerialize for SerializableScalar {
        fn serialize<W: std::io::prelude::Write>(&self, writer: &mut W) -> std::io::Result<()> {
            let to_ser: [u8; 32] = self.scalar.to_bytes().into();
            BorshSerialize::serialize(&to_ser, writer)
        }
    }

    impl BorshDeserialize for SerializableScalar {
        fn deserialize_reader<R: std::io::prelude::Read>(reader: &mut R) -> std::io::Result<Self> {
            let from_ser: [u8; 32] = BorshDeserialize::deserialize_reader(reader)?;
            let scalar = Scalar::from_bytes(from_ser).ok_or(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "The given scalar is not in the field of Secp256k1",
            ))?;
            Ok(SerializableScalar { scalar })
        }
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy)]
    pub struct SerializableAffinePoint {
        pub affine_point: AffinePoint,
    }

    impl BorshSerialize for SerializableAffinePoint {
        fn serialize<W: std::io::prelude::Write>(&self, writer: &mut W) -> std::io::Result<()> {
            let to_ser: Vec<u8> = serde_json::to_vec(&self.affine_point)?;
            BorshSerialize::serialize(&to_ser, writer)
        }
    }

    impl BorshDeserialize for SerializableAffinePoint {
        fn deserialize_reader<R: std::io::prelude::Read>(reader: &mut R) -> std::io::Result<Self> {
            let from_ser: Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
            let affine_point = serde_json::from_slice(&from_ser)?;
            Ok(SerializableAffinePoint { affine_point })
        }
    }
    #[derive(
        BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq,
    )]
    pub struct SignatureResponse {
        pub big_r: SerializableAffinePoint,
        pub s: SerializableScalar,
        pub recovery_id: u8,
    }

    impl SignatureResponse {
        pub fn new(big_r: AffinePoint, s: k256::Scalar, recovery_id: u8) -> Self {
            SignatureResponse {
                big_r: SerializableAffinePoint {
                    affine_point: big_r,
                },
                s: s.into(),
                recovery_id,
            }
        }
    }
}

pub mod edd25519_types {
    use super::*;
    use curve25519_dalek::Scalar;

    impl ScalarExt for Scalar {
        fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
            Self::from_repr(bytes).into_option()
        }

        /// When the user can't directly select the value, this will always work
        /// Use cases are things that we know have been hashed
        fn from_non_biased(hash: [u8; 32]) -> Self {
            // This should never happen.
            // The space of inputs is 2^256, the space of the field is ~2^256 - 2^129.
            // This mean that you'd have to run 2^127 hashes to find a value that causes this to fail.
            Self::from_bytes(hash)
                .expect("Derived scalar value falls outside of the field of edd25519")
        }

        fn to_bytes(&self) -> [u8; 32] {
            self.to_bytes()
        }
    }

    // Is there a better way to force a borsh serialization?
    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Copy)]
    pub struct SerializableScalar {
        scalar: Scalar,
    }

    impl SerializableScalar {
        pub fn new(scalar: Scalar) -> Self {
            Self { scalar }
        }
    }

    impl From<Scalar> for SerializableScalar {
        fn from(scalar: Scalar) -> Self {
            Self { scalar }
        }
    }

    impl BorshSerialize for SerializableScalar {
        fn serialize<W: std::io::prelude::Write>(&self, writer: &mut W) -> std::io::Result<()> {
            let to_ser: [u8; 32] = self.scalar.to_bytes();
            BorshSerialize::serialize(&to_ser, writer)
        }
    }

    impl BorshDeserialize for SerializableScalar {
        fn deserialize_reader<R: std::io::prelude::Read>(reader: &mut R) -> std::io::Result<Self> {
            let from_ser: [u8; 32] = BorshDeserialize::deserialize_reader(reader)?;
            let scalar = Scalar::from_bytes(from_ser).ok_or(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "The given scalar is not in the field of edd25519",
            ))?;
            Ok(SerializableScalar { scalar })
        }
    }

    impl Ord for SerializableScalar {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            self.scalar.as_bytes().cmp(other.scalar.as_bytes())
        }
    }

    impl PartialOrd for SerializableScalar {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    #[serde_as]
    #[derive(
        BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq,
    )]
    pub struct SignatureResponse(#[serde_as(as = "[_; 64]")] pub [u8; 64]);

    impl SignatureResponse {
        pub fn as_bytes(&self) -> &[u8; 64] {
            &self.0
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn serializeable_scalar_roundtrip() {
        use k256::elliptic_curve::PrimeField;
        let test_vec = vec![
            k256::Scalar::ZERO,
            k256::Scalar::ONE,
            k256::Scalar::from_u128(u128::MAX),
            k256::Scalar::from_bytes([3; 32]).unwrap(),
        ];

        for scalar in test_vec.into_iter() {
            let input = k256_types::SerializableScalar { scalar };
            // Test borsh
            {
                let serialized = borsh::to_vec(&input).unwrap();
                let output: k256_types::SerializableScalar =
                    borsh::from_slice(&serialized).unwrap();
                assert_eq!(input, output, "Failed on {:?}", scalar);
            }
        }
    }
}
