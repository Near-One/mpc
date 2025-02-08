use crate::tests::TestGenerators;
use cait_sith::{
    protocol::{Participant, Protocol},
    PresignArguments,
};
use k256::elliptic_curve::PrimeField;
use k256::{Scalar, Secp256k1};
use serde::Serialize;
use std::collections::VecDeque;

#[derive(Debug, Serialize)]
pub struct NetworkResearchReport {
    pub num_participants: usize,
    pub steps: Vec<NetworkStep>,
}

#[derive(Debug, Serialize)]
pub struct NetworkStep {
    pub peer_to_peer: Vec<Vec<PeerToPeerMessageStats>>,
}

#[derive(Debug, Serialize)]
pub struct PeerToPeerMessageStats {
    pub num_messages: usize,
    pub total_bytes: usize,
}

/// Simulates a network of participants doing a cait-sith MPC computation,
/// and writes out a file for the network communication statistics for each
/// round of communication, which can be visualized in a tool.
///
/// The difference between the best case and worst case is:
/// - In the best case, in each round we have each participant receive as
///   many messages as possible before proceeding. This gives the minimum
///   possible number of rounds of communication that is absolutely
///   necessary.
/// - In the worst case, in each round we have each participant receive only
///   as many messages as needed to make any progress. This gives some kind
///   of worst-case estimate, even though it's not the absolute worst (which
///   is kind of hard to define). It can result in many more rounds of
///   communication.
fn run_protocol_and_generate_network_report_for_best_case<P>(
    mut protocols: Vec<P>,
) -> NetworkResearchReport
where
    P: Protocol,
{
    let mut steps = Vec::<NetworkStep>::new();
    let mut completed = vec![false; protocols.len()];
    loop {
        if completed.iter().all(|&b| b) {
            break;
        }
        let mut p2p_messages_to_send =
            vec![vec![Vec::<Vec<u8>>::new(); protocols.len()]; protocols.len()];
        for i in 0..protocols.len() {
            if completed[i] {
                continue;
            }
            loop {
                match protocols[i].poke().unwrap() {
                    cait_sith::protocol::Action::Wait => break,
                    cait_sith::protocol::Action::SendMany(vec) => {
                        for j in 0..protocols.len() {
                            if i == j {
                                continue;
                            }
                            p2p_messages_to_send[i][j].push(vec.clone());
                        }
                    }
                    cait_sith::protocol::Action::SendPrivate(participant, vec) => {
                        p2p_messages_to_send[i][u32::from(participant) as usize].push(vec);
                    }
                    cait_sith::protocol::Action::Return(_) => {
                        completed[i] = true;
                        break;
                    }
                }
            }
        }

        let mut step = NetworkStep {
            peer_to_peer: Vec::new(),
        };
        for (i, messages) in p2p_messages_to_send.into_iter().enumerate() {
            let mut peer_messages = Vec::new();
            for (j, messages) in messages.into_iter().enumerate() {
                for message in &messages {
                    protocols[j].message(Participant::from(i as u32), message.clone());
                }
                let num_messages = messages.len();
                let total_bytes = messages.iter().map(|v| v.len()).sum();
                peer_messages.push(PeerToPeerMessageStats {
                    num_messages,
                    total_bytes,
                });
            }
            step.peer_to_peer.push(peer_messages);
        }
        steps.push(step);
    }
    NetworkResearchReport {
        num_participants: protocols.len(),
        steps,
    }
}

fn run_protocol_and_generate_network_report_for_worst_case(
    mut protocols: Vec<impl Protocol>,
) -> NetworkResearchReport {
    let mut steps = Vec::<NetworkStep>::new();
    let mut completed = vec![false; protocols.len()];
    let mut p2p_messages_to_receive = vec![VecDeque::<(usize, Vec<u8>)>::new(); protocols.len()];
    loop {
        if completed.iter().all(|&b| b) {
            break;
        }
        let mut p2p_messages_to_send =
            vec![vec![Vec::<Vec<u8>>::new(); protocols.len()]; protocols.len()];
        for i in 0..protocols.len() {
            if completed[i] {
                continue;
            }
            loop {
                let mut made_progress = false;
                loop {
                    match protocols[i].poke().unwrap() {
                        cait_sith::protocol::Action::Wait => break,
                        cait_sith::protocol::Action::SendMany(vec) => {
                            for j in 0..protocols.len() {
                                if i == j {
                                    continue;
                                }
                                p2p_messages_to_send[i][j].push(vec.clone());
                                made_progress = true;
                            }
                        }
                        cait_sith::protocol::Action::SendPrivate(participant, vec) => {
                            p2p_messages_to_send[i][u32::from(participant) as usize].push(vec);
                            made_progress = true;
                        }
                        cait_sith::protocol::Action::Return(_) => {
                            completed[i] = true;
                            made_progress = true;
                            break;
                        }
                    }
                }
                if made_progress {
                    break;
                }
                if let Some((from, message)) = p2p_messages_to_receive[i].pop_front() {
                    protocols[i].message(Participant::from(from as u32), message);
                } else {
                    break;
                }
            }
        }

        let mut step = NetworkStep {
            peer_to_peer: Vec::new(),
        };
        for (i, messages) in p2p_messages_to_send.into_iter().enumerate() {
            let mut peer_messages = Vec::new();
            for (j, messages) in messages.into_iter().enumerate() {
                for message in &messages {
                    p2p_messages_to_receive[j].push_back((i, message.clone()));
                }
                let num_messages = messages.len();
                let total_bytes = messages.iter().map(|v| v.len()).sum();
                peer_messages.push(PeerToPeerMessageStats {
                    num_messages,
                    total_bytes,
                });
            }
            step.peer_to_peer.push(peer_messages);
        }
        steps.push(step);
    }
    NetworkResearchReport {
        num_participants: protocols.len(),
        steps,
    }
}

const NUM_PARTICIPANTS: usize = 10;
const THRESHOLD: usize = 7;

#[test]
fn triple_network_research_best_case() {
    let mut protocols = Vec::new();
    let participants = (0..NUM_PARTICIPANTS)
        .map(|i| Participant::from(i as u32))
        .collect::<Vec<_>>();
    for i in 0..NUM_PARTICIPANTS {
        protocols.push(
            cait_sith::triples::generate_triple_many::<Secp256k1, 4>(
                &participants,
                participants[i],
                THRESHOLD,
            )
            .unwrap(),
        );
    }

    let report = run_protocol_and_generate_network_report_for_best_case(protocols);
    std::fs::write(
        "triple_network_report_best_case.json",
        serde_json::to_string_pretty(&report).unwrap(),
    )
    .unwrap();
    eprintln!(
        "Report written to {}/triple_network_report_best_case.json",
        std::env::current_dir().unwrap().to_string_lossy()
    );
}

#[test]
fn triple_network_research_worst_case() {
    let mut protocols = Vec::new();
    let participants = (0..NUM_PARTICIPANTS)
        .map(|i| Participant::from(i as u32))
        .collect::<Vec<_>>();
    for i in 0..NUM_PARTICIPANTS {
        protocols.push(
            cait_sith::triples::generate_triple_many::<Secp256k1, 4>(
                &participants,
                participants[i],
                THRESHOLD,
            )
            .unwrap(),
        );
    }

    let report = run_protocol_and_generate_network_report_for_worst_case(protocols);
    std::fs::write(
        "triple_network_report_worst_case.json",
        serde_json::to_string_pretty(&report).unwrap(),
    )
    .unwrap();
    eprintln!(
        "Report written to {}/triple_network_report_worst_case.json",
        std::env::current_dir().unwrap().to_string_lossy()
    );
}

#[test]
fn presignature_network_research_best_case() {
    let generator = TestGenerators::new(NUM_PARTICIPANTS, THRESHOLD);
    let keygens = generator.make_ecdsa_keygens();
    let triple0s = generator.make_triples();
    let triple1s = generator.make_triples();

    let mut protocols = Vec::new();
    let participants = (0..NUM_PARTICIPANTS)
        .map(|i| Participant::from(i as u32))
        .collect::<Vec<_>>();

    for i in 0..NUM_PARTICIPANTS {
        protocols.push(
            cait_sith::presign::<Secp256k1>(
                &participants,
                participants[i],
                &participants,
                participants[i],
                PresignArguments {
                    triple0: triple0s[&participants[i]].clone(),
                    triple1: triple1s[&participants[i]].clone(),
                    keygen_out: keygens[&participants[i]].clone(),
                    threshold: THRESHOLD,
                },
            )
            .unwrap(),
        );
    }
    let report = run_protocol_and_generate_network_report_for_best_case(protocols);
    std::fs::write(
        "presignature_network_report_best_case.json",
        serde_json::to_string_pretty(&report).unwrap(),
    )
    .unwrap();
    eprintln!(
        "Report written to {}/presignature_network_report_best_case.json",
        std::env::current_dir().unwrap().to_string_lossy()
    );
}

#[test]
fn signature_network_research_best_case() {
    let generator = TestGenerators::new(NUM_PARTICIPANTS, THRESHOLD);
    let keygens = generator.make_ecdsa_keygens();
    let triple0s = generator.make_triples();
    let triple1s = generator.make_triples();
    let presignatures = generator.make_presignatures(&triple0s, &triple1s, &keygens);

    let mut protocols = Vec::new();
    let participants = (0..NUM_PARTICIPANTS)
        .map(|i| Participant::from(i as u32))
        .collect::<Vec<_>>();
    for i in 0..NUM_PARTICIPANTS {
        protocols.push(
            cait_sith::sign::<Secp256k1>(
                &participants,
                participants[i],
                keygens[&participants[i]].public_key,
                presignatures[&participants[i]].clone(),
                Scalar::from_u128(100000),
            )
            .unwrap(),
        );
    }
    let report = run_protocol_and_generate_network_report_for_best_case(protocols);
    std::fs::write(
        "signature_network_report_best_case.json",
        serde_json::to_string_pretty(&report).unwrap(),
    )
    .unwrap();
    eprintln!(
        "Report written to {}/signature_network_report_best_case.json",
        std::env::current_dir().unwrap().to_string_lossy()
    );
}
