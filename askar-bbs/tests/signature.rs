#[test]
fn sign_verify_expected() {
    use askar_bbs::{io::FixedLengthBytes, DynGenerators, Message, Signature, SignatureBuilder};
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
    let messages = [Message::hash("hello")];
    let gens = DynGenerators::new(&keypair, messages.len());
    let sig = SignatureBuilder::sign(&gens, &keypair, messages.iter().copied())
        .expect("Error creating signature");

    let mut verifier = sig.verifier(&gens);
    verifier
        .append_messages(messages.iter().copied())
        .expect("Error verifying signature");
    verifier.verify().expect("Error verifying signature");

    // test serialization round trip
    let mut buf = [0u8; 112];
    let mut w = Writer::from_slice(&mut buf);
    sig.write_bytes(&mut w)
        .expect("Error serializing signature");
    let sig_len = w.position();
    assert_eq!(sig_len, 112);
    let sig_de = Signature::from_bytes(&buf).expect("Error deserializing signature");
    assert_eq!(sig, sig_de);
}
