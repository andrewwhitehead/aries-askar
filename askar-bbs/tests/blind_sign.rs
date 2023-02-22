#[cfg(feature = "getrandom")]
use askar_bbs::{
    CommitmentBuilder, CommitmentProof, DynGenerators, Message, Nonce, SignatureBuilder,
};

#[cfg(feature = "getrandom")]
use askar_crypto::{
    alg::bls::{BlsKeyPair, G2},
    buffer::Writer,
    key::KeyGen,
};

#[cfg(feature = "getrandom")]
#[test]
fn test_commitment_verify() {
    let keypair = BlsKeyPair::<G2>::random().unwrap();
    let gens = DynGenerators::new(&keypair, 5);
    let nonce = Nonce::random();
    let commit_messages = [(0, Message::hash(b"hello"))];
    let mut committer = CommitmentBuilder::new(&gens);
    for (index, message) in commit_messages.iter().copied() {
        committer.add_message(index, message).unwrap();
    }
    let (challenge, _blinding, commitment, proof) = committer
        .complete(nonce)
        .expect("Error completing commitment");
    proof
        .verify(&gens, commitment, [0].iter().copied(), challenge, nonce)
        .expect("Error verifying commitment");

    // test serialization round trip
    let mut buf = [0u8; 1024];
    let mut w = Writer::from_slice(&mut buf);
    proof.write_bytes(&mut w).expect("Error serializing proof");
    let proof_len = w.position();
    let proof_de =
        CommitmentProof::from_bytes(&buf[..proof_len]).expect("Error deserializing proof");
    assert_eq!(proof, proof_de);
}

#[cfg(feature = "getrandom")]
#[test]
fn test_blind_signature() {
    let keypair = BlsKeyPair::<G2>::random().unwrap();
    let gens = DynGenerators::new(&keypair, 2);
    let nonce = Nonce::random();
    let commit_messages = [(0, Message::hash(b"hello"))];
    let mut committer = CommitmentBuilder::new(&gens);
    for (index, message) in commit_messages.iter().copied() {
        committer.add_message(index, message).unwrap();
    }
    let (challenge, blinding, commitment, proof) = committer
        .complete(nonce)
        .expect("Error completing commitment");
    proof
        .verify(&gens, commitment, [0].iter().copied(), challenge, nonce)
        .expect("Error verifying commitment");

    let sign_messages = [Message::hash(b"world")];
    let mut signer = SignatureBuilder::from_commitment(&gens, &keypair, commitment);
    signer.push_committed_count(1).unwrap();
    signer
        .append_messages(sign_messages.iter().copied())
        .unwrap();
    let blind_signature = signer.to_signature().expect("Error creating signature");

    let signature = blind_signature.unblind(blinding);
    let mut verifier = signature.verifier(&gens);
    verifier.push_message(commit_messages[0].1).unwrap();
    verifier
        .append_messages(sign_messages.iter().copied())
        .unwrap();
    verifier.verify().expect("Error verifying signature");
}
