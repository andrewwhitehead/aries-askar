#[macro_use]
extern crate criterion;

use askar_bbs::{CommitmentBuilder, DynGenerators, Message, Nonce, SignatureBuilder};
use askar_crypto::{
    alg::bls::{BlsKeyPair, G2},
    key::KeyGen,
};
use rand::{rngs::OsRng, RngCore};

use criterion::Criterion;

fn criterion_benchmark(c: &mut Criterion) {
    let keypair = BlsKeyPair::<G2>::generate(OsRng).unwrap();

    for message_count in vec![5, 25, 125] {
        let gens = DynGenerators::new(&keypair, message_count)
            .to_vec()
            .unwrap();
        let commit_msg = Message::from(OsRng.next_u64());
        let nonce = Nonce::random();

        if message_count == 5 {
            c.bench_function("create commitment", |b| {
                b.iter(|| {
                    let mut committer = CommitmentBuilder::new(&gens);
                    committer.add_message(0, commit_msg).unwrap();
                    let (_challenge, _blind, _commit, _proof) = committer.complete(nonce).unwrap();
                });
            });
        }

        let mut committer = CommitmentBuilder::new(&gens);
        committer.add_message(0, commit_msg).unwrap();
        let (challenge, blinding, commitment, proof) = committer.complete(nonce).unwrap();

        if message_count == 5 {
            c.bench_function(&format!("verify commitment"), |b| {
                b.iter(|| {
                    proof
                        .verify(&gens, commitment, [0].iter().copied(), challenge, nonce)
                        .unwrap()
                });
            });
        }

        let messages: Vec<Message> = (1..message_count)
            .map(|_| Message::from(OsRng.next_u64()))
            .collect();
        c.bench_function(&format!("blind sign for {} messages", message_count), |b| {
            b.iter(|| {
                let mut signer = SignatureBuilder::from_commitment(&gens, &keypair, commitment);
                signer.push_committed_count(1).unwrap();
                signer.append_messages(messages.iter().copied()).unwrap();
                signer.to_signature().unwrap()
            });
        });

        let mut signer = SignatureBuilder::from_commitment(&gens, &keypair, commitment);
        signer.push_committed_count(1).unwrap();
        signer.append_messages(messages.iter().copied()).unwrap();
        let sig = signer.to_signature().unwrap();

        c.bench_function(
            &format!("unblind and verify for {} messages", message_count),
            |b| {
                b.iter(|| {
                    let sig = sig.unblind(blinding);
                    let mut verifier = sig.verifier(&gens);
                    verifier.push_message(commit_msg).unwrap();
                    verifier.append_messages(messages.iter().copied()).unwrap();
                    verifier.verify().unwrap()
                });
            },
        );
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
