use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};

use sequoia_openpgp as openpgp;
use openpgp::cert::Cert;
use openpgp::parse::Parse;

use crate::common::encrypt;

pub fn sign_by_testy(bytes: &[u8]) {
    let testy = Cert::from_bytes(
        &include_bytes!("../tests/data/keys/testy-new-private.pgp")[..],
    )
    .unwrap();
    encrypt::sign(bytes, &testy).unwrap();
}

fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign message");

    for message in encrypt::messages() {
        group.throughput(Throughput::Bytes(message.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("cert", message.len()),
            &message,
            |b, m| b.iter(|| sign_by_testy(m)),
        );
    }
    group.finish();
}

criterion_group!(benches, bench_sign);
criterion_main!(benches);
