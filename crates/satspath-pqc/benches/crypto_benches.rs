use criterion::{criterion_group, criterion_main, Criterion};
use satspath_pqc::hybrid_sig::{generate_hybrid_keypair, hybrid_sign, hybrid_verify};
use std::hint::black_box;

fn bench_hybrid_keygen(c: &mut Criterion) {
    c.bench_function("hybrid_keygen_ml_dsa_65_schnorr", |b| {
        b.iter(|| {
            let keypair = generate_hybrid_keypair();
            black_box(keypair)
        })
    });
}

fn bench_hybrid_sign(c: &mut Criterion) {
    let keypair = generate_hybrid_keypair();
    let message = b"test message for signing benchmark";

    c.bench_function("hybrid_sign_ml_dsa_65_schnorr", |b| {
        b.iter(|| {
            let signature = hybrid_sign(black_box(message), &keypair);
            black_box(signature)
        })
    });
}

fn bench_hybrid_verify(c: &mut Criterion) {
    let keypair = generate_hybrid_keypair();
    let pubkey = keypair.public_key();
    let message = b"test message for verifying benchmark";
    let signature = hybrid_sign(message, &keypair);

    c.bench_function("hybrid_verify_ml_dsa_65_schnorr", |b| {
        b.iter(|| {
            let valid = hybrid_verify(black_box(message), black_box(&signature), &pubkey);
            assert!(valid);
            black_box(valid)
        })
    });
}

criterion_group!(
    benches,
    bench_hybrid_keygen,
    bench_hybrid_sign,
    bench_hybrid_verify
);
criterion_main!(benches);
