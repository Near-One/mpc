#[cfg(test)]
mod tests {
    use crate::frost::dkg::build_dkg_protocols;
    use crate::frost::sign::build_sign_protocols;
    use crate::frost::SignatureOutput;
    use cait_sith::protocol::{run_protocol, Participant};
    use frost_ed25519::Identifier;
    use near_indexer::near_primitives::hash::hash;

    #[test]
    fn verify_stability_of_identifier_derivation() {
        let participant = Participant::from(1e9 as u32);
        let identifier = Identifier::derive(participant.bytes().as_slice()).unwrap();
        assert_eq!(
            identifier.serialize(),
            vec![
                96, 203, 29, 92, 230, 35, 120, 169, 19, 185, 45, 28, 48, 68, 84, 190, 12, 186, 169,
                192, 196, 21, 238, 181, 134, 181, 203, 236, 162, 68, 212, 4
            ]
        );
    }

    #[test]
    fn dkg_and_sign() {
        let max_signers = 9;
        let threshold = 6;

        let dkg_protocols = build_dkg_protocols(max_signers, threshold);
        let keys = run_protocol(dkg_protocols).unwrap();

        let group_public_key = keys.first().unwrap().1.public_key_package.verifying_key();

        let sign_protocols = build_sign_protocols(&keys, threshold, |idx| idx == 0);
        let signature = run_protocol(sign_protocols)
            .unwrap()
            .into_iter()
            .filter_map(|(_, s)| match s {
                SignatureOutput::Coordinator(signature) => Some(signature),
                SignatureOutput::Participant => None,
            })
            .next()
            .unwrap();

        let msg = "hello_near";
        let msg_hash = hash(msg.as_bytes());

        group_public_key
            .verify(msg_hash.as_bytes(), &signature)
            .unwrap();
    }
}
