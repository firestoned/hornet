// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: MIT

//! Benchmarks for zone file parsing, writing, and validation.
//!
//! Five fixture sizes exercise the parser across realistic input ranges:
//!
//! | Size               | Description                            |  ~Bytes |
//! |--------------------|----------------------------------------|---------|
//! | tiny               | SOA + NS + 2 A records                 |     200 |
//! | small              | Typical domain (~20 records)           |   1 000 |
//! | medium             | 100 A records (generated)              |   6 000 |
//! | large_1k_records   | 1 000 A records (generated)            |  60 000 |
//! | xlarge_10k_records | 10 000 A records (generated)           | 600 000 |

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use hornet::writer::WriteOptions;
use hornet::{parse_zone_file, validate_zone_file, write_zone_file};

// ── Fixtures ─────────────────────────────────────────────────────────────────

const TINY: &str = "$ORIGIN example.com.\n\
$TTL 3600\n\
@ IN SOA ns1.example.com. hostmaster.example.com. (2024010101 86400 7200 2419200 300)\n\
@ IN NS  ns1.example.com.\n\
@ IN A   93.184.216.34\n\
ns1 IN A   93.184.216.35\n";

const SMALL: &str = r#"$ORIGIN example.com.
$TTL 3600

@       IN  SOA  ns1.example.com. hostmaster.example.com. (
                    2024010101  ; serial
                    86400       ; refresh
                    7200        ; retry
                    2419200     ; expire
                    300 )       ; minimum

; Name servers
@       IN  NS   ns1.example.com.
@       IN  NS   ns2.example.com.

; IPv4
@       IN  A    93.184.216.34
www     IN  A    93.184.216.34
mail    IN  A    93.184.216.37
ftp     IN  A    93.184.216.38
vpn     IN  A    93.184.216.39
ns1     IN  A    93.184.216.35
ns2     IN  A    93.184.216.36

; IPv6
@       IN  AAAA 2606:2800:220:1:248:1893:25c8:1946
www     IN  AAAA 2606:2800:220:1:248:1893:25c8:1946

; Mail
@       IN  MX   10 mail.example.com.
@       IN  MX   20 mail2.example.com.

; Aliases
ftp     IN  CNAME www.example.com.

; Text records
@       IN  TXT  "v=spf1 a mx ip4:93.184.216.0/24 -all"
_dmarc  IN  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"

; Services
_http._tcp  IN  SRV  10 5 80 www.example.com.
_https._tcp IN  SRV  10 5 443 www.example.com.

; CAA
@       IN  CAA  0 issue "letsencrypt.org"
@       IN  CAA  0 issuewild ";"
"#;

/// Build a zone file with a SOA/NS header followed by `record_count` A records.
fn gen_records(record_count: usize) -> String {
    use std::fmt::Write as FmtWrite;
    let mut s = String::with_capacity(record_count * 50 + 256);
    s.push_str(
        "$ORIGIN example.com.\n\
         $TTL 300\n\
         @ IN SOA ns1.example.com. hostmaster.example.com. (2024010101 86400 7200 2419200 300)\n\
         @ IN NS  ns1.example.com.\n\
         @ IN NS  ns2.example.com.\n\n",
    );
    for i in 0..record_count {
        let a = (i / (256 * 256)) % 256;
        let b = (i / 256) % 256;
        let c = i % 256;
        writeln!(s, "host{i} IN A 10.{a}.{b}.{c}").unwrap();
    }
    s
}

// ── Benchmark groups ──────────────────────────────────────────────────────────

fn bench_parse(c: &mut Criterion) {
    let medium = gen_records(100);
    let large = gen_records(1_000);
    let xlarge = gen_records(10_000);

    let fixtures: &[(&str, &str)] = &[
        ("tiny", TINY),
        ("small", SMALL),
        ("medium_100_records", &medium),
        ("large_1k_records", &large),
        ("xlarge_10k_records", &xlarge),
    ];

    let mut group = c.benchmark_group("parse_zone_file");
    for (name, input) in fixtures {
        group.throughput(Throughput::Bytes(input.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), input, |b, i| {
            b.iter(|| parse_zone_file(black_box(i)).unwrap());
        });
    }
    group.finish();
}

fn bench_write(c: &mut Criterion) {
    let medium_input = gen_records(100);
    let zone = parse_zone_file(&medium_input).unwrap();
    let opts = WriteOptions::default();

    let mut group = c.benchmark_group("write_zone_file");
    group.throughput(Throughput::Bytes(medium_input.len() as u64));
    group.bench_function("medium_100_records", |b| {
        b.iter(|| write_zone_file(black_box(&zone), black_box(&opts)));
    });
    group.finish();
}

fn bench_validate(c: &mut Criterion) {
    let medium_input = gen_records(100);
    let zone = parse_zone_file(&medium_input).unwrap();

    let mut group = c.benchmark_group("validate_zone_file");
    group.throughput(Throughput::Bytes(medium_input.len() as u64));
    group.bench_function("medium_100_records", |b| {
        b.iter(|| validate_zone_file(black_box(&zone)));
    });
    group.finish();
}

fn bench_roundtrip(c: &mut Criterion) {
    let medium_input = gen_records(100);
    let opts = WriteOptions::default();

    let mut group = c.benchmark_group("roundtrip_zone_file");
    group.throughput(Throughput::Bytes(medium_input.len() as u64));
    group.bench_function("medium_100_records_parse_write", |b| {
        b.iter(|| {
            let zone = parse_zone_file(black_box(&medium_input)).unwrap();
            write_zone_file(&zone, black_box(&opts))
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_parse,
    bench_write,
    bench_validate,
    bench_roundtrip
);
criterion_main!(benches);
