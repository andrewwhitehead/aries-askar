#[cfg(feature = "getrandom")]
#[test]
fn prove_single_signature_hidden_message() {
    use askar_bbs::{DynGenerators, Message, Nonce, SignatureBuilder, SignatureProof};
    use askar_crypto::{
        alg::bls::{BlsKeyPair, G2},
        buffer::Writer,
        repr::FromSecretBytes,
    };
    use hex_literal::hex;

    let keypair = BlsKeyPair::<G2>::from_secret_bytes(&hex!(
        "0011223344556677889900112233445566778899001122334455667788990011"
    ))
    .unwrap();
    let messages = [Message::hash("hello"), Message::hash("there")];
    let gens = DynGenerators::new(&keypair, messages.len());
    let mut builder = SignatureBuilder::new(&gens, &keypair);
    builder
        .append_messages(messages.iter().copied())
        .expect("Error building signature");
    let sig = builder.to_signature().expect("Error creating signature");

    // verifier creates a nonce for the proof presentation
    let nonce = Nonce::random();

    // prover constructs the proof and challenge value for an independent proof
    let mut prover = sig.prover(&gens);
    prover.push_hidden_message(messages[0]).unwrap();
    prover.push_message(messages[1]).unwrap();
    let (challenge, proof) = prover
        .complete(nonce)
        .expect("Error creating signature pok");

    // verifier checks the proof with the challenge value
    let mut verifier = proof.verifier(&gens, challenge).unwrap();
    verifier.push_hidden_count(1).unwrap();
    verifier.push_revealed(messages[1]).unwrap();
    let challenge_v = verifier
        .complete(nonce)
        .expect("Error creating verification challenge");
    verifier
        .verify(challenge_v)
        .expect("Error verifying signature PoK");
    // double check challenge comparison for testing
    assert_eq!(challenge, challenge_v);

    // test serialization round trip
    let mut buf = [0u8; 1024];
    let mut w = Writer::from_slice(&mut buf);
    proof.write_bytes(&mut w).expect("Error serializing proof");
    let proof_len = w.position();
    let proof_de =
        SignatureProof::from_bytes(&buf[..proof_len]).expect("Error deserializing proof");
    assert_eq!(proof, proof_de);
}

#[cfg(feature = "getrandom")]
#[test]
fn multi_proof_matching_hidden_message() {
    use askar_bbs::{Blinding, DynGenerators, Message, Nonce, ProofChallenge, SignatureBuilder};
    use askar_crypto::{
        alg::bls::{BlsKeyPair, G2},
        repr::FromSecretBytes,
    };
    use hex_literal::hex;

    let test_proof_dst = b"test proof";
    let keypair = BlsKeyPair::<G2>::from_secret_bytes(&hex!(
        "0011223344556677889900112233445566778899001122334455667788990011"
    ))
    .unwrap();
    let messages_1 = [Message::hash("hello"), Message::hash("there")];
    let messages_2 = [
        Message::hash("indeed"),
        Message::hash("hello"),
        Message::hash("stranger"),
    ];
    let gens_1 = DynGenerators::new(&keypair, messages_1.len());
    let gens_2 = DynGenerators::new(&keypair, messages_2.len());
    let sig_1 = SignatureBuilder::sign(&gens_1, &keypair, messages_1.iter().copied())
        .expect("Error creating signature");
    let sig_2 = SignatureBuilder::sign(&gens_2, &keypair, messages_2.iter().copied())
        .expect("Error creating signature");

    // verifier creates a nonce for the proof presentation
    let nonce = Nonce::random();

    // a common blinding value for the two messages to be proven equal
    let msg_blind = Blinding::random();

    // construct provers for the two signatures
    let mut prover_1 = sig_1.prover(&gens_1);
    prover_1
        .push_hidden_message_with(messages_1[0], msg_blind)
        .unwrap();
    prover_1.push_message(messages_1[1]).unwrap();
    let prepare_1 = prover_1.prepare().unwrap();
    let mut prover_2 = sig_2.prover(&gens_2);
    prover_2.push_hidden_message(messages_2[0]).unwrap();
    prover_2
        .push_hidden_message_with(messages_2[1], msg_blind)
        .unwrap();
    prover_2.push_message(messages_2[2]).unwrap();
    let prepare_2 = prover_2.prepare().unwrap();

    // prover creates a combined challenge value for the two sub-proofs
    let challenge = ProofChallenge::create(&[&prepare_1, &prepare_2], nonce, Some(test_proof_dst))
        .expect("Error creating proof challenge");
    let proof_1 = prepare_1
        .complete(challenge)
        .expect("Error completing signature pok");
    let proof_2 = prepare_2
        .complete(challenge)
        .expect("Error completing signature pok");

    // construct verifiers for the two sub-proofs
    let mut verifier_1 = proof_1.verifier(&gens_1, challenge).unwrap();
    verifier_1.push_hidden_count(1).unwrap();
    verifier_1.push_revealed(messages_1[1]).unwrap();
    let mut verifier_2 = proof_2.verifier(&gens_2, challenge).unwrap();
    verifier_2.push_hidden_count(2).unwrap();
    verifier_2.push_revealed(messages_2[2]).unwrap();

    // now verifier computes the challenge value
    let challenge_v =
        ProofChallenge::create(&[&verifier_1, &verifier_2], nonce, Some(test_proof_dst))
            .expect("Error creating proof challenge");
    // check the proofs
    verifier_1
        .verify(challenge_v)
        .expect("Error verifying signature PoK");
    verifier_2
        .verify(challenge_v)
        .expect("Error verifying signature PoK");
    // double check challenge comparison for testing
    assert_eq!(challenge, challenge_v);

    // check that the responses match, meaning that the hidden messages also match
    assert_eq!(
        proof_1.get_response(0).unwrap(),
        proof_2.get_response(1).unwrap()
    );
}
