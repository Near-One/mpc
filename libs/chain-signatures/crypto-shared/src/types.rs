use borsh::{BorshDeserialize, BorshSerialize};
use k256::{
    elliptic_curve::{bigint::ArrayEncoding, CurveArithmetic, PrimeField},
    AffinePoint, Scalar, Secp256k1, U256,
};
use serde::{Deserialize, Serialize};

pub type PublicKey = <Secp256k1 as CurveArithmetic>::AffinePoint;

pub trait ScalarExt: Sized {
    fn from_bytes(bytes: [u8; 32]) -> Option<Self>;
    fn from_non_biased(bytes: [u8; 32]) -> Self;
}

impl ScalarExt for Scalar {
    /// Returns nothing if the bytes are greater than the field size of Secp256k1.
    /// This will be very rare with random bytes as the field size is 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
    fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        let bytes = U256::from_be_slice(bytes.as_slice());
        Scalar::from_repr(bytes.to_be_byte_array()).into_option()
    }

    /// When the user can't directly select the value, this will always work
    /// Use cases are things that we know have been hashed
    fn from_non_biased(hash: [u8; 32]) -> Self {
        // This should never happen.
        // The space of inputs is 2^256, the space of the field is ~2^256 - 2^129.
        // This mean that you'd have to run 2^127 hashes to find a value that causes this to fail.
        Scalar::from_bytes(hash).expect("Derived epsilon value falls outside of the field")
    }
}

#[test]
fn scalar_fails_as_expected() {
    let too_high = [0xFF; 32];
    assert!(Scalar::from_bytes(too_high).is_none());

    let mut not_too_high = [0xFF; 32];
    // Order is of k256 is FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    //                                                  [15]
    not_too_high[15] = 0xFD;
    assert!(Scalar::from_bytes(not_too_high).is_some());
}

// Is there a better way to force a borsh serialization?
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy, Ord, PartialOrd)]
pub struct SerializableScalar {
    pub scalar: Scalar,
}

impl From<Scalar> for SerializableScalar {
    fn from(scalar: Scalar) -> Self {
        SerializableScalar { scalar }
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
            "Scalar bytes are not in the k256 field",
        ))?;
        Ok(SerializableScalar { scalar })
    }
}

// Is there a better way to force a borsh serialization?
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

#[test]
fn serializeable_scalar_roundtrip() {
    use k256::elliptic_curve::PrimeField;
    let test_vec = vec![
        Scalar::ZERO,
        Scalar::ONE,
        Scalar::from_u128(u128::MAX),
        Scalar::from_bytes([3; 32]).unwrap(),
    ];

    for scalar in test_vec.into_iter() {
        let input = SerializableScalar { scalar };
        // Test borsh
        {
            let serialized = borsh::to_vec(&input).unwrap();
            let output: SerializableScalar = borsh::from_slice(&serialized).unwrap();
            assert_eq!(input, output, "Failed on {:?}", scalar);
        }

        // Test Serde via JSON
        {
            let serialized = serde_json::to_vec(&input).unwrap();
            let output: SerializableScalar = serde_json::from_slice(&serialized).unwrap();
            assert_eq!(input, output, "Failed on {:?}", scalar);
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SignatureResponse {
    pub big_r: SerializableAffinePoint,
    pub s: SerializableScalar,
    pub recovery_id: u8,
}

impl SignatureResponse {
    pub fn new(big_r: AffinePoint, s: Scalar, recovery_id: u8) -> Self {
        SignatureResponse {
            big_r: SerializableAffinePoint {
                affine_point: big_r,
            },
            s: SerializableScalar { scalar: s },
            recovery_id,
        }
    }
}
