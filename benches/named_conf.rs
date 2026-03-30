// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: MIT

//! Benchmarks for named.conf parsing, writing, and validation.
//!
//! Five fixture sizes exercise the parser across realistic input ranges:
//!
//! | Size                 | Description                            |   ~Bytes |
//! |----------------------|----------------------------------------|----------|
//! | tiny                 | Single options block                   |       90 |
//! | small                | Simple server: options + 3 zones       |      600 |
//! | medium               | Production: views, acls, logging, keys |    4 500 |
//! | large_100_zones      | 100 zones (generated)                  |   15 000 |
//! | xlarge_1000_zones    | 1 000 zones (generated)                |  150 000 |
//! | xxlarge_10k_zones   | 10 000 zones (generated) — stress      | 1 300 000|
//! | xxxlarge_50k_zones  | 50 000 zones (generated) — stress      | 6 500 000|

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use hornet_bind9::writer::WriteOptions;
use hornet_bind9::{parse_named_conf, validate_named_conf, write_named_conf};

// ── Fixtures ─────────────────────────────────────────────────────────────────

const TINY: &str = "options {\n    directory \"/var/cache/bind\";\n    recursion yes;\n};";

const SMALL: &str = r#"options {
    directory "/var/cache/bind";
    recursion yes;
    allow-query { any; };
    forwarders { 8.8.8.8; 8.8.4.4; };
    forward only;
    dnssec-validation auto;
};

acl "trusted" {
    192.168.0.0/16;
    10.0.0.0/8;
    localhost;
};

zone "example.com" {
    type primary;
    file "/etc/bind/zones/example.com.db";
    allow-transfer { 192.168.0.2; };
};

zone "example.org" {
    type secondary;
    file "/etc/bind/zones/example.org.db";
};

zone "." {
    type hint;
    file "/etc/bind/db.root";
};

logging {
    channel default_log {
        file "/var/log/named/default.log" versions 3 size 10m;
        severity info;
        print-time yes;
    };
    category default { "default_log"; };
};
"#;

const MEDIUM: &str = r#"options {
    directory "/var/cache/bind";
    recursion yes;
    allow-query { any; };
    allow-recursion { trusted; };
    forwarders { 8.8.8.8; 8.8.4.4; 1.1.1.1; };
    forward only;
    dnssec-validation auto;
    listen-on port 53 { any; };
    listen-on-v6 port 53 { any; };
};

acl "trusted" {
    192.168.0.0/16;
    10.0.0.0/8;
    172.16.0.0/12;
    localhost;
    localnets;
};

acl "secondaries" {
    192.168.1.100;
    192.168.1.101;
    10.0.0.50;
};

key "rndc-key" {
    algorithm hmac-sha256;
    secret "aBcDeFgHiJkLmNoPqRsTuVwXyZ==";
};

key "transfer-key" {
    algorithm hmac-sha256;
    secret "ZyXwVuTsRqPoNmLkJiHgFeDcBa==";
};

controls {
    inet 127.0.0.1 port 953 allow { 127.0.0.1; };
};

logging {
    channel default_log {
        file "/var/log/named/default.log" versions 5 size 20m;
        severity dynamic;
        print-time yes;
        print-severity yes;
        print-category yes;
    };
    channel security_log {
        file "/var/log/named/security.log" versions 3 size 10m;
        severity dynamic;
        print-time yes;
        print-severity yes;
    };
    channel query_log {
        file "/var/log/named/query.log" versions 3 size 50m;
        severity dynamic;
        print-time yes;
    };
    category default { "default_log"; };
    category security { "security_log"; };
    category queries { "query_log"; };
    category lame-servers { "null"; };
    category dnssec { "security_log"; };
};

view "internal" {
    match-clients { trusted; };
    recursion yes;

    zone "example.com" {
        type primary;
        file "/etc/bind/internal/example.com.db";
        allow-transfer { secondaries; };
    };

    zone "example.org" {
        type primary;
        file "/etc/bind/internal/example.org.db";
        allow-transfer { secondaries; };
    };

    zone "corp.internal" {
        type primary;
        file "/etc/bind/internal/corp.internal.db";
    };

    zone "dev.internal" {
        type primary;
        file "/etc/bind/internal/dev.internal.db";
    };

    zone "staging.internal" {
        type primary;
        file "/etc/bind/internal/staging.internal.db";
    };

    zone "1.168.192.in-addr.arpa" {
        type primary;
        file "/etc/bind/internal/rev.192.168.1.db";
    };

    zone "0.10.in-addr.arpa" {
        type primary;
        file "/etc/bind/internal/rev.10.0.db";
    };

    zone "." {
        type hint;
        file "/etc/bind/db.root";
    };
};

view "external" {
    match-clients { any; };
    recursion no;

    zone "example.com" {
        type primary;
        file "/etc/bind/external/example.com.db";
        allow-transfer { none; };
    };

    zone "example.org" {
        type primary;
        file "/etc/bind/external/example.org.db";
        allow-transfer { none; };
    };

    zone "." {
        type hint;
        file "/etc/bind/db.root";
    };
};
"#;

/// Build a named.conf string containing `zone_count` zone statements.
fn gen_zones(zone_count: usize) -> String {
    use std::fmt::Write as FmtWrite;
    let mut s = String::with_capacity(zone_count * 120 + 256);
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

// ── Benchmark groups ──────────────────────────────────────────────────────────

fn bench_parse(c: &mut Criterion) {
    let large = gen_zones(100);
    let xlarge = gen_zones(1_000);

    let fixtures: &[(&str, &str)] = &[
        ("tiny", TINY),
        ("small", SMALL),
        ("medium", MEDIUM),
        ("large_100_zones", &large),
        ("xlarge_1000_zones", &xlarge),
    ];

    let mut group = c.benchmark_group("parse_named_conf");
    for (name, input) in fixtures {
        group.throughput(Throughput::Bytes(input.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), input, |b, i| {
            b.iter(|| parse_named_conf(black_box(i)).unwrap());
        });
    }
    group.finish();
}

fn bench_write(c: &mut Criterion) {
    let conf = parse_named_conf(MEDIUM).unwrap();
    let opts = WriteOptions::default();

    let mut group = c.benchmark_group("write_named_conf");
    group.throughput(Throughput::Bytes(MEDIUM.len() as u64));
    group.bench_function("medium", |b| {
        b.iter(|| write_named_conf(black_box(&conf), black_box(&opts)));
    });
    group.finish();
}

fn bench_validate(c: &mut Criterion) {
    let conf = parse_named_conf(MEDIUM).unwrap();

    let mut group = c.benchmark_group("validate_named_conf");
    group.throughput(Throughput::Bytes(MEDIUM.len() as u64));
    group.bench_function("medium", |b| {
        b.iter(|| validate_named_conf(black_box(&conf)));
    });
    group.finish();
}

fn bench_roundtrip(c: &mut Criterion) {
    let opts = WriteOptions::default();

    let mut group = c.benchmark_group("roundtrip_named_conf");
    group.throughput(Throughput::Bytes(MEDIUM.len() as u64));
    group.bench_function("medium_parse_write", |b| {
        b.iter(|| {
            let conf = parse_named_conf(black_box(MEDIUM)).unwrap();
            write_named_conf(&conf, black_box(&opts))
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
