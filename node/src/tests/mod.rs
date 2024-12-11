use crate::hkdf::derive_public_key;
use cait_sith::protocol::{run_protocol, Participant, Protocol};
use cait_sith::triples::TripleGenerationOutput;
use cait_sith::{FullSignature, KeygenOutput, PresignArguments, PresignOutput};
use k256::{AffinePoint, Scalar, Secp256k1};
use std::collections::HashMap;

mod basic_cluster;
mod benchmark;
mod contract;
mod research;

/// Convenient test utilities to generate keys, triples, presignatures, and signatures.
pub struct TestGenerators {
    num_participants: usize,
    threshold: usize,
}

type ParticipantAndProtocol<T> = (Participant, Box<dyn Protocol<Output = T>>);

impl TestGenerators {
    pub fn new(num_participants: usize, threshold: usize) -> Self {
        Self {
            num_participants,
            threshold,
        }
    }

    pub fn make_keygens(&self) -> HashMap<Participant, KeygenOutput<Secp256k1>> {
        let mut protocols: Vec<ParticipantAndProtocol<KeygenOutput<Secp256k1>>> = Vec::new();
        let participants = (0..self.num_participants)
            .map(|i| Participant::from(i as u32))
            .collect::<Vec<_>>();
        for i in 0..self.num_participants {
            protocols.push((
                participants[i],
                Box::new(
                    cait_sith::keygen::<Secp256k1>(&participants, participants[i], self.threshold)
                        .unwrap(),
                ),
            ));
        }
        run_protocol(protocols).unwrap().into_iter().collect()
    }

    pub fn make_triples(&self) -> HashMap<Participant, TripleGenerationOutput<Secp256k1>> {
        let mut protocols: Vec<ParticipantAndProtocol<TripleGenerationOutput<Secp256k1>>> =
            Vec::new();
        let participants = (0..self.num_participants)
            .map(|i| Participant::from(i as u32))
            .collect::<Vec<_>>();
        for i in 0..self.num_participants {
            protocols.push((
                participants[i],
                Box::new(
                    cait_sith::triples::generate_triple::<Secp256k1>(
                        &participants,
                        participants[i],
                        self.threshold,
                    )
                    .unwrap(),
                ),
            ));
        }
        run_protocol(protocols).unwrap().into_iter().collect()
    }

    pub fn make_presignatures(
        &self,
        triple0s: &HashMap<Participant, TripleGenerationOutput<Secp256k1>>,
        triple1s: &HashMap<Participant, TripleGenerationOutput<Secp256k1>>,
        keygens: &HashMap<Participant, KeygenOutput<Secp256k1>>,
    ) -> HashMap<Participant, PresignOutput<Secp256k1>> {
        let mut protocols: Vec<ParticipantAndProtocol<PresignOutput<Secp256k1>>> = Vec::new();
        let participants = (0..self.num_participants)
            .map(|i| Participant::from(i as u32))
            .collect::<Vec<_>>();
        for i in 0..self.num_participants {
            protocols.push((
                participants[i],
                Box::new(
                    cait_sith::presign::<Secp256k1>(
                        &participants,
                        participants[i],
                        &participants,
                        participants[i],
                        PresignArguments {
                            triple0: triple0s[&participants[i]].clone(),
                            triple1: triple1s[&participants[i]].clone(),
                            keygen_out: keygens[&participants[i]].clone(),
                            threshold: self.threshold,
                        },
                    )
                    .unwrap(),
                ),
            ));
        }
        run_protocol(protocols).unwrap().into_iter().collect()
    }

    pub fn make_signature(
        &self,
        presignatures: &HashMap<Participant, PresignOutput<Secp256k1>>,
        public_key: AffinePoint,
        tweak: Scalar,
        msg_hash: Scalar,
    ) -> FullSignature<Secp256k1> {
        let mut protocols: Vec<ParticipantAndProtocol<FullSignature<Secp256k1>>> = Vec::new();
        let participants = (0..self.num_participants)
            .map(|i| Participant::from(i as u32))
            .collect::<Vec<_>>();
        let derived_public_key = derive_public_key(public_key, tweak);
        for i in 0..self.num_participants {
            let original_presig = &presignatures[&participants[i]];
            let tweaked_presig = PresignOutput {
                big_r: original_presig.big_r,
                k: original_presig.k,
                sigma: original_presig.sigma + tweak * original_presig.k,
            };
            protocols.push((
                participants[i],
                Box::new(
                    cait_sith::sign::<Secp256k1>(
                        &participants,
                        participants[i],
                        derived_public_key,
                        tweaked_presig,
                        msg_hash,
                    )
                    .unwrap(),
                ),
            ));
        }
        run_protocol(protocols)
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
            .1
    }
}
