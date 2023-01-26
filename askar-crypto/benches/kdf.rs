#[macro_use]
extern crate criterion;

use askar_crypto::kdf::concat::{ConcatKDF, ConcatKDFParams};
use sha2::Sha256;

use criterion::{black_box, Criterion};

fn criterion_benchmark(c: &mut Criterion) {
    {
        let message = b"test message for encrypting";

        let params = ConcatKDFParams {
            alg: b"A256GCM",
            apu: b"sender name",
            apv: b"recipient name",
            pub_info: &(256u32).to_be_bytes(),
            prv_info: &[],
        };

        c.bench_function("concat kdf sha256", move |b| {
            b.iter(|| {
                let mut output = [0u8; 32];
                ConcatKDF::<Sha256>::derive_key(black_box(message), black_box(params), &mut output)
                    .unwrap();
            })
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
