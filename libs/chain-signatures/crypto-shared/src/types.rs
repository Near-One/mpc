use borsh::{BorshDeserialize, BorshSerialize};
use curve25519_dalek::edwards::EdwardsPoint;
use k256::{
    elliptic_curve::{bigint::ArrayEncoding, CurveArithmetic, PrimeField},
    AffinePoint, Secp256k1, U256,
};
use near_sdk::near;
use serde::{Deserialize, Serialize};

pub type Secp256k1PublicKey = <Secp256k1 as CurveArithmetic>::AffinePoint;
// TODO: This key will be much bigger. It's VerifyingKey plus "Frost header"
pub type Ed25519PublicKey = frost_ed25519::keys::PublicKeyPackage;

#[derive(Default, Clone, Debug)]
#[near(serializers=[borsh, json])]
pub enum Scheme {
    #[default]
    Secp256k1,
    Ed25519,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum SignatureResponse {
    Secp256k1(k256_types::SignatureResponse),
    Edd25519(curve25519_types::SignatureResponse),
}

pub trait ScalarExt: Sized {
    fn from_bytes(bytes: [u8; 32]) -> Option<Self>;
    fn from_non_biased(bytes: [u8; 32]) -> Self;
    fn to_bytes(&self) -> [u8; 32];
    fn name() -> &'static str;
}

pub mod k256_types {
    use super::*;
    use k256::Scalar;
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
            Self::from_bytes(hash).expect("Derived epsilon value falls outside of the field")
        }

        fn to_bytes(&self) -> [u8; 32] {
            self.to_bytes().into()
        }

        fn name() -> &'static str {
            "k256"
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
                format!("The given scalar is not in the field of {}", Scalar::name(),),
            ))?;
            Ok(SerializableScalar { scalar })
        }
    }

    // TODO: Is there a better way to force a borsh serialization?
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

pub mod curve25519_types {
    use std::fmt;

    use super::*;
    use curve25519_dalek::Scalar;
    use serde::{
        de::{Error, Visitor},
        ser, Deserializer, Serializer,
    };

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
            Self::from_bytes(hash).expect("Derived epsilon value falls outside of the field")
        }

        fn to_bytes(&self) -> [u8; 32] {
            self.to_bytes()
        }

        fn name() -> &'static str {
            "edd25519"
        }
    }

    // Is there a better way to force a borsh serialization?
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
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
            let to_ser: [u8; 32] = self.scalar.to_bytes().into();
            BorshSerialize::serialize(&to_ser, writer)
        }
    }

    impl BorshDeserialize for SerializableScalar {
        fn deserialize_reader<R: std::io::prelude::Read>(reader: &mut R) -> std::io::Result<Self> {
            let from_ser: [u8; 32] = BorshDeserialize::deserialize_reader(reader)?;
            let scalar = Scalar::from_bytes(from_ser).ok_or(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("The given scalar is not in the field of {}", Scalar::name(),),
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
            self.scalar.as_bytes().partial_cmp(&other.scalar.as_bytes())
        }
    }

    impl Serialize for SerializableScalar {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            // Convert the Scalar to bytes and serialize those
            let bytes = self.scalar.to_bytes();
            serializer.serialize_bytes(&bytes)
        }
    }

    impl<'de> Deserialize<'de> for SerializableScalar {
        fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            todo!()
        }
    }

    #[derive(
        BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq,
    )]
    // TODO: What fields go in here?
    pub struct SignatureResponse {}
}

// Ed25519 EdwardsPoint serialization (equivalent to AffinePoint for Ed25519)
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct SerializableEdwardsPoint {
    pub edwards_point: EdwardsPoint,
}

impl BorshSerialize for SerializableEdwardsPoint {
    fn serialize<W: std::io::prelude::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let to_ser: [u8; 32] = self.edwards_point.compress().to_bytes();
        BorshSerialize::serialize(&to_ser, writer)
    }
}

impl BorshDeserialize for SerializableEdwardsPoint {
    fn deserialize_reader<R: std::io::prelude::Read>(reader: &mut R) -> std::io::Result<Self> {
        let from_ser: [u8; 32] = BorshDeserialize::deserialize_reader(reader)?;
        let compressed = curve25519_dalek::edwards::CompressedEdwardsY(from_ser);
        let edwards_point = compressed.decompress().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid compressed EdwardsPoint",
        ))?;
        Ok(SerializableEdwardsPoint { edwards_point })
    }
}

// pub trait SignatureExt {}
// impl SignatureExt for Secp256k1SignatureResponse {}
// impl SignatureExt for Ed25519SignatureResponse {}

// #[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
// pub struct Ed25519SignatureResponse {
//     pub big_r: SerializableEdwardsPoint,
//     pub s: SerializableScalar<curve25519_dalek::Scalar>,
// }

// impl Ed25519SignatureResponse {
//     pub fn new(big_r: EdwardsPoint, s: curve25519_dalek::Scalar) -> Self {
//         Ed25519SignatureResponse {
//             big_r: SerializableEdwardsPoint {
//                 edwards_point: big_r,
//             },
//             s: s.into(),
//         }
//     }

//     // Helper to convert from a standard Ed25519 signature
//     pub fn from_signature(signature: &Ed25519Signature) -> std::io::Result<Self> {
//         let sig_bytes = signature.to_bytes();
//         // First 32 bytes are R (big_r), second 32 bytes are s
//         let r_bytes = sig_bytes[0..32].try_into().map_err(|_| {
//             std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid signature R bytes")
//         })?;
//         let s_bytes = sig_bytes[32..64].try_into().map_err(|_| {
//             std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid signature S bytes")
//         })?;

//         // Convert R to EdwardsPoint
//         let compressed_r = curve25519_dalek::edwards::CompressedEdwardsY(r_bytes);
//         let edwards_r = compressed_r.decompress().ok_or(std::io::Error::new(
//             std::io::ErrorKind::InvalidData,
//             "Invalid R point in signature",
//         ))?;

//         // Convert s to Scalar
//         let scalar_s = curve25519_dalek::Scalar::from_bytes(s_bytes).ok_or(std::io::Error::new(
//             std::io::ErrorKind::InvalidData,
//             "Invalid S scalar in signature",
//         ))?;

//         Ok(Self::new(edwards_r, scalar_s))
//     }

//     // Convert back to a standard Ed25519 signature
//     pub fn to_signature(&self) -> Ed25519Signature {
//         let r_bytes = self.big_r.edwards_point.compress().to_bytes();
//         let s_bytes = self.s.scalar.to_bytes();

//         let mut sig_bytes = [0u8; 64];
//         sig_bytes[0..32].copy_from_slice(&r_bytes);
//         sig_bytes[32..64].copy_from_slice(&s_bytes);

//         Ed25519Signature::from_bytes(&sig_bytes)
//     }
// }

// // For backward compatibility
// // pub type SignatureResponse = Secp256k1SignatureResponse;
// pub struct SignatureResponse<Scheme: SignatureExt> {
//     inner: Scheme,
// }

// impl<Scheme> SignatureResponse<Scheme>
// where
//     Scheme: SignatureExt,
// {
//     pub fn new(signature: Scheme) -> Self {
//         Self { inner: signature }
//     }
// }

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

    // TODO: Are the tests needed?
    //
    // #[test]
    // fn serializeable_ed25519_scalar_roundtrip() {
    //     let test_vec = vec![
    //         curve25519_dalek::Scalar::ZERO,
    //         curve25519_dalek::Scalar::ONE,
    //         curve25519_dalek::Scalar::from_bytes_mod_order([3; 32]),
    //     ];

    //     for scalar in test_vec.into_iter() {
    //         let input = SerializableScalar { scalar };
    //         // Test borsh
    //         {
    //             let serialized = borsh::to_vec(&input).unwrap();
    //             let output: SerializableScalar = borsh::from_slice(&serialized).unwrap();
    //             assert_eq!(input, output, "Failed on {:?}", scalar);
    //         }

    //         // Test Serde via JSON
    //         {
    //             let serialized = serde_json::to_vec(&input).unwrap();
    //             let output: SerializableScalar =
    //                 serde_json::from_slice(&serialized).unwrap();
    //             assert_eq!(input, output, "Failed on {:?}", scalar);
    //         }
    //     }
    // }

    // #[test]
    // fn ed25519_signature_roundtrip() {
    //     use rand::rngs::OsRng;

    //     let mut csprng = OsRng;
    //     let signing_key = SigningKey::generate(&mut csprng);
    //     let verifying_key = signing_key.verifying_key();
    //     let message = b"test message";

    //     // Generate a signature
    //     let signature = signing_key.sign(message);

    //     // Convert to our custom format
    //     let sig_response = Ed25519SignatureResponse::from_signature(&signature).unwrap();

    //     // Convert back to standard signature
    //     let recovered_signature = sig_response.to_signature();

    //     // Verify it still works
    //     assert!(verifying_key.verify(message, &recovered_signature).is_ok());
    // }
}
