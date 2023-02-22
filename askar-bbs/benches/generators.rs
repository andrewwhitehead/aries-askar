#[macro_use]
extern crate criterion;

use askar_bbs::{DynGenerators, Generators};
use askar_crypto::{
    alg::bls::{BlsKeyPair, G2},
    repr::FromSecretBytes,
};
use hex_literal::hex;

use criterion::{black_box, Criterion};

fn criterion_benchmark(c: &mut Criterion) {
    let keypair = BlsKeyPair::<G2>::from_secret_bytes(&hex!(
        "0011223344556677889900112233445566778899001122334455667788990011"
    ))
    .unwrap();

    for message_count in vec![5, 25, 125] {
        c.bench_function(&format!("keygen for {} messages", message_count), |b| {
            b.iter(|| {
                for gen in DynGenerators::new(&keypair, message_count).iter() {
                    black_box(gen);
                }
            });
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
