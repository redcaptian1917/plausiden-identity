use criterion::{black_box, criterion_group, criterion_main, Criterion};
use plausiden_identity::{generate_commitment, generate_salt, generate_fingerprint, generate_nullifier};
use plausiden_identity::types::IdentityAttributes;

fn bench_commitment(c: &mut Criterion) {
    let attrs = IdentityAttributes {
        given_name: "John".to_string(),
        family_name: "Smith".to_string(),
        date_of_birth: "1990-01-15".to_string(),
        document_id: Some("DL123456".to_string()),
        document_type: Some("drivers_license".to_string()),
        extra_claims: vec![],
    };
    let salt = generate_salt();

    c.bench_function("generate_commitment", |b| {
        b.iter(|| generate_commitment(black_box(&attrs), black_box(&salt)))
    });

    c.bench_function("generate_fingerprint", |b| {
        b.iter(|| generate_fingerprint(black_box(&attrs)))
    });

    let commitment = generate_commitment(&attrs, &salt);
    c.bench_function("generate_nullifier", |b| {
        b.iter(|| generate_nullifier(black_box(&commitment), black_box("election-2026")))
    });
}

criterion_group!(benches, bench_commitment);
criterion_main!(benches);
