use criterion::{criterion_group, criterion_main, Criterion};
use satspath_core::ssrf::validate_url;
use std::hint::black_box;

fn bench_ssrf_validator(c: &mut Criterion) {
    let valid_url = "https://rodrigo.satspath.dev/profile.json";
    let ipv4_loopback = "http://127.0.0.1:8080/profile.json";
    let ipv6_loopback = "http://[::1]/profile";
    let internal_meta = "http://169.254.169.254/latest/meta-data/";

    c.bench_function("validate_url_valid", |b| {
        b.iter(|| {
            let res = validate_url(black_box(valid_url), true);
            black_box(res)
        })
    });

    c.bench_function("validate_url_ipv4_loopback", |b| {
        b.iter(|| {
            let res = validate_url(black_box(ipv4_loopback), true);
            black_box(res)
        })
    });

    c.bench_function("validate_url_ipv6_loopback", |b| {
        b.iter(|| {
            let res = validate_url(black_box(ipv6_loopback), true);
            black_box(res)
        })
    });

    c.bench_function("validate_url_internal_meta", |b| {
        b.iter(|| {
            let res = validate_url(black_box(internal_meta), true);
            black_box(res)
        })
    });
}

criterion_group!(benches, bench_ssrf_validator);
criterion_main!(benches);
