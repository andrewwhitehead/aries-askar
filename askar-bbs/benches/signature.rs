#[macro_use]
extern crate criterion;

use askar_bbs::{DynGenerators, Message, SignatureBuilder};
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
        let messages: Vec<Message> = (0..message_count)
            .map(|_| Message::from(OsRng.next_u64()))
            .collect();

        c.bench_function(&format!("sign for {} messages", message_count), |b| {
            b.iter(|| {
                let mut signer = SignatureBuilder::new(&gens, &keypair);
                signer.append_messages(messages.iter().copied()).unwrap();
                signer.to_signature().unwrap();
            });
        });

        let mut signer = SignatureBuilder::new(&gens, &keypair);
        signer.append_messages(messages.iter().copied()).unwrap();
        let sig = signer.to_signature().unwrap();
        c.bench_function(&format!("verify for {} messages", message_count), |b| {
            b.iter(|| sig.verify(&gens, messages.iter().copied()).unwrap());
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
