use cait_sith::protocol::{run_protocol, Participant, Protocol};
use cait_sith::triples::TripleGenerationOutput;
use cait_sith::{FullSignature, KeygenOutput, PresignArguments, PresignOutput};
use k256::{AffinePoint, Scalar, Secp256k1};
use std::collections::HashMap;

mod basic_cluster;
mod benchmark;
mod faulty;
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
        msg_hash: Scalar,
    ) -> FullSignature<Secp256k1> {
        let mut protocols: Vec<ParticipantAndProtocol<FullSignature<Secp256k1>>> = Vec::new();
        let participants = (0..self.num_participants)
            .map(|i| Participant::from(i as u32))
            .collect::<Vec<_>>();
        for i in 0..self.num_participants {
            protocols.push((
                participants[i],
                Box::new(
                    cait_sith::sign::<Secp256k1>(
                        &participants,
                        participants[i],
                        public_key,
                        presignatures[&participants[i]].clone(),
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

pub async fn wait_till_udp_port_free(port: u16) {
    let mut retries_left = 20;
    while retries_left > 0 {
        tracing::info!("Waiting for port {} to be free...", port);
        let result = std::net::UdpSocket::bind(format!("0.0.0.0:{}", port));
        if result.is_ok() {
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        retries_left -= 1;
    }
    tracing::info!("Port {} is free", port);
    assert!(retries_left > 0, "Failed to free port {}", port);
}
