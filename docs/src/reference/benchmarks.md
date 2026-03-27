# Performance Benchmarks

Hornet is built on [winnow](https://docs.rs/winnow), a zero-copy, monomorphising parser combinator
library designed for throughput. Benchmarks are measured with
[Criterion.rs](https://bheisler.github.io/criterion.rs/book/) (100 statistical samples per group).

---

## Test environment

| Property | Value |
|---|---|
| Platform | macOS 15 (Apple M-series) |
| Rust | stable (1.86+) |
| Profile | `release` (`opt-level = 3`) |
| Criterion warm-up | 3 s |
| Criterion measurement | 5 s |

!!! note
    Linux `x86_64` builds show comparable throughput. CI benchmarks run on `ubuntu-latest`
    and results are uploaded as workflow artifacts for reference.

---

## `named.conf` — parsing

Seven fixture sizes from a trivial single-block config up to a 50 000-zone stress test.
The first five (`tiny` → `xlarge`) are run in standard CI; the last two are run via
`make bench-stress` only.

| Fixture | Input size | Median time | Throughput | CI? |
|---|---|---|---|---|
| `tiny` — single options block | 60 B | **596 ns** | 102 MiB/s | ✓ |
| `small` — options + ACL + 3 zones + logging | ~700 B | **7.9 µs** | 87 MiB/s | ✓ |
| `medium` — views, ACLs, keys, logging, 11 zones | ~2.8 KB | **34 µs** | 81 MiB/s | ✓ |
| `large` — 100 zones | ~12 KB | **218 µs** | 54 MiB/s | ✓ |
| `xlarge` — 1 000 zones | ~124 KB | **13.8 ms** | 8.7 MiB/s | ✓ |
| `xxlarge` — 10 000 zones (stress) | ~1.3 MB | **1.19 s** | 1.02 MiB/s | — |
| `xxxlarge` — 50 000 zones (stress) | ~6.5 MB | **30.5 s** | 207 KiB/s | — |

!!! tip "Typical production configs"
    Real-world `named.conf` files rarely exceed 50 KB. At the `medium` fixture scale (a realistic
    multi-view production config), hornet parses in **under 35 µs**.

!!! note "Scaling behaviour beyond 1 000 zones"
    Throughput drops significantly past ~1 000 zones due to heap allocation pressure and CPU
    cache spill as the in-memory AST grows. For configs in that range, consider splitting across
    multiple `include` files or using the `view` mechanism to partition zones.

---

## `named.conf` — writing and validation

Using the `medium` fixture (~2.8 KB, 11 zones across 2 views).

| Operation | Median time | Throughput |
|---|---|---|
| `write_named_conf` | **12.9 µs** | 212 MiB/s |
| `validate_named_conf` | **967 ns** | 2.77 GiB/s |
| Round-trip (parse + write) | **46.6 µs** | 59 MiB/s |

---

## Zone files — parsing

Five fixture sizes from a minimal zone (SOA + NS + 2 A records) up to 10 000 host records.

| Fixture | Input size | Median time | Throughput |
|---|---|---|---|
| `tiny` — SOA + NS + 2 A records | ~200 B | **2.1 µs** | 85 MiB/s |
| `small` — 20 records, all major types | ~1 KB | **8.4 µs** | 134 MiB/s |
| `medium` — 100 A records | ~5.5 KB | **24.7 µs** | 91 MiB/s |
| `large` — 1 000 A records | ~55 KB | **228 µs** | 99 MiB/s |
| `xlarge` — 10 000 A records | ~550 KB | **2.3 ms** | 104 MiB/s |

!!! tip "Consistent linear scaling"
    Zone file throughput stays in the **85–106 MiB/s** band across four orders of magnitude of
    input size, demonstrating the linear complexity of the winnow parser combinators.

---

## Zone files — writing and validation

Using the `medium` fixture (100 records, ~5.5 KB).

| Operation | Median time | Throughput |
|---|---|---|
| `write_zone_file` | **18.5 µs** | 121 MiB/s |
| `validate_zone_file` | **110 ns** | 19.7 GiB/s |
| Round-trip (parse + write) | **45.4 µs** | 49 MiB/s |

---

## Running the benchmarks yourself

```sh
# Full run (uses Criterion defaults: 3 s warm-up, 5 s measurement)
make bench

# Abbreviated run, standard fixtures only (used in CI)
make bench-quick

# Stress fixtures only — 10k and 50k zones (slow)
make bench-stress

# Compile only — verify bench code builds without running
make bench-compile
```

Criterion generates an interactive HTML report at `target/criterion/report/index.html`.

### Comparing against a baseline

```sh
# Save a baseline labelled "main"
cargo bench -- --save-baseline main

# Later, compare a branch against it
cargo bench -- --load-baseline main --baseline main
```

---

## Source

Benchmark source lives in [`benches/`](https://github.com/firestoned/hornet/tree/main/benches):

- `benches/named_conf.rs` — parse, write, validate, round-trip (tiny → xlarge 1k zones)
- `benches/named_conf_stress.rs` — stress fixtures (10k and 50k zones, not run in CI)
- `benches/zone_file.rs` — parse, write, validate, round-trip for zone files
