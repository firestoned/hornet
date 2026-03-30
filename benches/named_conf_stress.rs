// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: MIT

//! Stress benchmarks for very large named.conf inputs (10 000 and 100 000 zones).
//!
//! Each iteration takes multiple seconds, so Criterion is configured with the
//! minimum `sample_size(10)` and a capped `measurement_time`. These benchmarks
//! are **not** run in CI — use `make bench-stress` to run them locally.
//!
//! | Size               | Zones  | ~Input size |
//! |--------------------|--------|-------------|
//! | xxlarge_10k_zones  | 10 000 | ~1.3 MB     |
//! | xxxlarge_50k_zones | 50 000 | ~6.5 MB     |

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use hornet_bind9::parse_named_conf;

/// Build a named.conf string containing `zone_count` zone statements.
fn gen_zones(zone_count: usize) -> String {
    use std::fmt::Write as FmtWrite;
    let mut s = String::with_capacity(zone_count * 130 + 256);
    s.push_str(
        "options {\n\
         \x20   directory \"/var/cache/bind\";\n\
         \x20   recursion yes;\n\
         \x20   allow-query { any; };\n\
         };\n\n",
    );
    for i in 0..zone_count {
        let octet = (i % 254) + 1;
        write!(
            s,
            "zone \"zone{i}.example.com\" {{\n\
             \x20   type primary;\n\
             \x20   file \"/etc/bind/zones/zone{i}.db\";\n\
             \x20   allow-transfer {{ 10.0.0.{octet}; }};\n\
             }};\n\n"
        )
        .unwrap();
    }
    s
}

fn bench_parse_stress(c: &mut Criterion) {
    let zones_10k = gen_zones(10_000);
    let zones_50k = gen_zones(50_000);

    let fixtures: &[(&str, &str)] = &[
        ("xxlarge_10k_zones", &zones_10k),
        ("xxxlarge_50k_zones", &zones_50k),
    ];

    let mut group = c.benchmark_group("parse_named_conf_stress");
    group.sample_size(10);
    group.warm_up_time(std::time::Duration::from_secs(1));
    group.measurement_time(std::time::Duration::from_secs(30));
    for (name, input) in fixtures {
        group.throughput(Throughput::Bytes(input.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), input, |b, i| {
            b.iter(|| parse_named_conf(black_box(i)).unwrap());
        });
    }
    group.finish();
}

criterion_group!(benches, bench_parse_stress);
criterion_main!(benches);
