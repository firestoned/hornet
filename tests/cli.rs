// Copyright (c) 2025 Erick Bourgeois, firestoned
// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for the `hornet` CLI binary: every subcommand, flag and
//! exit code, driven through the real executable.

#![cfg(feature = "cli")]

use std::io::Write;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

// ── Fixtures ──────────────────────────────────────────────────────────────────

/// A config with no diagnostics at all.
const CLEAN_CONF: &str = r#"zone "example.com" {
    type primary;
    file "/etc/bind/example.com.db";
};
"#;

/// A legacy-keyword config: `type master` plus a `masters` list.
const LEGACY_CONF: &str = r#"zone "example.com" {
    type master;
    file "/etc/bind/example.com.db";
};
zone "example.org" {
    type slave;
    masters { 192.0.2.1; };
    file "/etc/bind/example.org.db";
};
"#;

/// Produces a single warning (primary zone without a `file`).
const WARNING_CONF: &str = r#"zone "example.com" {
    type primary;
};
"#;

/// Produces an error (reference to an undefined ACL).
const ERROR_CONF: &str = "options {
    allow-query { nosuchacl; };
};
";

/// Produces only an informational diagnostic (file channel without severity).
const INFO_CONF: &str = r#"logging {
    channel main_log {
        file "/var/log/named.log";
    };
    category default { main_log; };
};
"#;

/// Rejected by the parser (stray closing brace).
const UNPARSEABLE_CONF: &str = "}\n";

const CLEAN_ZONE: &str = "$TTL 3600
@ IN SOA ns1.example.com. hostmaster.example.com. (
    2024010101 7200 3600 1209600 300 )
@ IN NS ns1.example.com.
ns1 IN A 192.0.2.1
www IN A 192.0.2.2
";

/// Valid zone with a warning: MX exchange is the root.
const WARNING_ZONE: &str = "$TTL 3600
@ IN SOA ns1.example.com. hostmaster.example.com. (
    2024010101 7200 3600 1209600 300 )
@ IN NS ns1.example.com.
@ IN MX 0 .
ns1 IN A 192.0.2.1
";

/// Zone with an error: no SOA record.
const ERROR_ZONE: &str = "$TTL 3600
@ IN NS ns1.example.com.
ns1 IN A 192.0.2.1
";

// ── Helpers ───────────────────────────────────────────────────────────────────

struct Fixture {
    _dir: TempDir,
    path: PathBuf,
}

fn fixture(name: &str, contents: &str) -> Fixture {
    let dir = tempfile::tempdir().expect("create temp dir");
    let path = dir.path().join(name);
    let mut file = std::fs::File::create(&path).expect("create fixture");
    file.write_all(contents.as_bytes()).expect("write fixture");
    Fixture { _dir: dir, path }
}

fn hornet() -> Command {
    Command::cargo_bin("hornet").expect("hornet binary is built")
}

fn missing(dir: &TempDir) -> PathBuf {
    dir.path().join("missing.conf")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).expect("read fixture back")
}

/// Make `path` read-only so an in-place write fails.
fn make_read_only(path: &Path) {
    let mut perms = std::fs::metadata(path).expect("stat fixture").permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(path, perms).expect("chmod fixture");
}

/// Running as root ignores file permissions, so write-failure tests are
/// meaningless there.
fn running_as_root() -> bool {
    #[cfg(unix)]
    {
        std::process::Command::new("id")
            .arg("-u")
            .output()
            .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
    }
    #[cfg(not(unix))]
    {
        false
    }
}

// ── Top level ─────────────────────────────────────────────────────────────────

#[test]
fn no_arguments_prints_usage_and_fails() {
    hornet()
        .assert()
        .failure()
        .stderr(predicate::str::contains("Usage"));
}

#[test]
fn version_flag_prints_version() {
    hornet()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn help_flag_lists_every_subcommand() {
    let assert = hornet().arg("--help").assert().success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    for sub in ["parse", "zone", "check", "check-zone", "fmt", "convert"] {
        assert!(out.contains(sub), "--help is missing `{sub}`:\n{out}");
    }
}

// ── parse ─────────────────────────────────────────────────────────────────────

#[test]
fn parse_prints_formatted_config() {
    let f = fixture("named.conf", CLEAN_CONF);
    hornet()
        .arg("parse")
        .arg(&f.path)
        .assert()
        .success()
        .stdout(predicate::str::contains("zone \"example.com\""))
        .stdout(predicate::str::contains("type primary;"));
}

#[test]
fn parse_alias_p_works() {
    let f = fixture("named.conf", CLEAN_CONF);
    hornet()
        .arg("p")
        .arg(&f.path)
        .assert()
        .success()
        .stdout(predicate::str::contains("type primary;"));
}

#[test]
fn parse_modernises_legacy_keywords_by_default() {
    let f = fixture("named.conf", LEGACY_CONF);
    hornet()
        .arg("parse")
        .arg(&f.path)
        .assert()
        .success()
        .stdout(predicate::str::contains("type primary;"))
        .stdout(predicate::str::contains("type secondary;"))
        .stdout(predicate::str::contains("master").not());
}

#[test]
fn parse_explicit_modern_flag_modernises() {
    let f = fixture("named.conf", LEGACY_CONF);
    hornet()
        .args(["parse", "--modern"])
        .arg(&f.path)
        .assert()
        .success()
        .stdout(predicate::str::contains("type primary;"));
}

#[test]
fn parse_no_modern_keeps_legacy_keywords() {
    let f = fixture("named.conf", LEGACY_CONF);
    hornet()
        .args(["parse", "--no-modern"])
        .arg(&f.path)
        .assert()
        .success()
        .stdout(predicate::str::contains("type master;"))
        .stdout(predicate::str::contains("type slave;"))
        .stdout(predicate::str::contains("masters { 192.0.2.1; };"))
        .stdout(predicate::str::contains("primaries").not());
}

#[test]
fn parse_last_of_modern_and_no_modern_wins() {
    let f = fixture("named.conf", LEGACY_CONF);
    hornet()
        .args(["parse", "--no-modern", "--modern"])
        .arg(&f.path)
        .assert()
        .success()
        .stdout(predicate::str::contains("type primary;"));
    hornet()
        .args(["parse", "--modern", "--no-modern"])
        .arg(&f.path)
        .assert()
        .success()
        .stdout(predicate::str::contains("type master;"));
}

#[test]
fn parse_indent_controls_indentation() {
    let f = fixture("named.conf", CLEAN_CONF);
    hornet()
        .args(["parse", "--indent", "2"])
        .arg(&f.path)
        .assert()
        .success()
        .stdout(predicate::str::contains("\n  type primary;"));
    hornet()
        .args(["parse", "-i", "8"])
        .arg(&f.path)
        .assert()
        .success()
        .stdout(predicate::str::contains("\n        type primary;"));
}

#[test]
fn parse_missing_file_fails_with_error() {
    let dir = tempfile::tempdir().unwrap();
    hornet()
        .arg("parse")
        .arg(missing(&dir))
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::starts_with("Error:"));
}

#[test]
fn parse_unparseable_file_fails_with_parse_error() {
    let f = fixture("named.conf", UNPARSEABLE_CONF);
    hornet()
        .arg("parse")
        .arg(&f.path)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("Parse error"));
}

#[test]
fn parse_non_numeric_indent_is_a_usage_error() {
    let f = fixture("named.conf", CLEAN_CONF);
    hornet()
        .args(["parse", "--indent", "wide"])
        .arg(&f.path)
        .assert()
        .failure()
        .code(2);
}

// ── zone ──────────────────────────────────────────────────────────────────────

#[test]
fn zone_prints_formatted_zone() {
    let f = fixture("example.com.zone", CLEAN_ZONE);
    hornet()
        .arg("zone")
        .arg(&f.path)
        .assert()
        .success()
        .stdout(predicate::str::contains("SOA"))
        .stdout(predicate::str::contains("192.0.2.2"));
}

#[test]
fn zone_alias_z_and_indent_work() {
    let f = fixture("example.com.zone", CLEAN_ZONE);
    hornet()
        .args(["z", "--indent", "2"])
        .arg(&f.path)
        .assert()
        .success()
        .stdout(predicate::str::contains("SOA"));
}

#[test]
fn zone_missing_file_fails() {
    let dir = tempfile::tempdir().unwrap();
    hornet()
        .arg("zone")
        .arg(missing(&dir))
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::starts_with("Error:"));
}

#[test]
fn zone_unparseable_line_fails_naming_file_and_line() {
    let f = fixture("bad.zone", "$TTL 3600\nwww A 192.0.2.1\nlonely\n");
    hornet()
        .arg("zone")
        .arg(&f.path)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("line 3"))
        .stderr(predicate::str::contains("bad.zone"));
}

// ── check ─────────────────────────────────────────────────────────────────────

#[test]
fn check_clean_config_succeeds() {
    let f = fixture("named.conf", CLEAN_CONF);
    hornet()
        .arg("check")
        .arg(&f.path)
        .assert()
        .success()
        .stderr(predicate::str::contains("no issues found"));
}

#[test]
fn check_alias_c_works() {
    let f = fixture("named.conf", CLEAN_CONF);
    hornet().arg("c").arg(&f.path).assert().success();
}

#[test]
fn check_warning_fails_without_allow_warnings() {
    let f = fixture("named.conf", WARNING_CONF);
    hornet()
        .arg("check")
        .arg(&f.path)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("warning"))
        .stderr(predicate::str::contains("has no 'file' directive"))
        .stderr(predicate::str::contains("1 diagnostic(s) found"));
}

#[test]
fn check_warning_passes_with_allow_warnings() {
    let f = fixture("named.conf", WARNING_CONF);
    hornet()
        .args(["check", "--allow-warnings"])
        .arg(&f.path)
        .assert()
        .success()
        .stderr(predicate::str::contains("has no 'file' directive"));
}

#[test]
fn check_error_fails_even_with_allow_warnings() {
    let f = fixture("named.conf", ERROR_CONF);
    hornet()
        .args(["check", "--allow-warnings"])
        .arg(&f.path)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("error"))
        .stderr(predicate::str::contains("undefined ACL \"nosuchacl\""));
}

#[test]
fn check_info_only_succeeds_and_reports_info() {
    let f = fixture("named.conf", INFO_CONF);
    hornet()
        .arg("check")
        .arg(&f.path)
        .assert()
        .success()
        .stderr(predicate::str::contains("info"))
        .stderr(predicate::str::contains("1 diagnostic(s) found"));
}

#[test]
fn check_min_severity_error_hides_warnings_and_passes() {
    let f = fixture("named.conf", WARNING_CONF);
    hornet()
        .args(["check", "--min-severity", "error"])
        .arg(&f.path)
        .assert()
        .success()
        .stderr(predicate::str::contains("has no 'file' directive").not());
}

#[test]
fn check_min_severity_warning_hides_info() {
    let f = fixture("named.conf", INFO_CONF);
    for level in ["warning", "warn", "WARNING"] {
        hornet()
            .args(["check", "--min-severity", level])
            .arg(&f.path)
            .assert()
            .success()
            .stderr(predicate::str::contains("info:").not());
    }
}

#[test]
fn check_min_severity_unknown_falls_back_to_info() {
    let f = fixture("named.conf", INFO_CONF);
    hornet()
        .args(["check", "--min-severity", "verbose"])
        .arg(&f.path)
        .assert()
        .success()
        .stderr(predicate::str::contains("info"));
}

#[test]
fn check_unparseable_file_fails() {
    let f = fixture("named.conf", UNPARSEABLE_CONF);
    hornet()
        .arg("check")
        .arg(&f.path)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("Parse error"));
}

#[test]
fn check_missing_file_fails() {
    let dir = tempfile::tempdir().unwrap();
    hornet()
        .arg("check")
        .arg(missing(&dir))
        .assert()
        .failure()
        .code(1);
}

// ── check-zone ────────────────────────────────────────────────────────────────

#[test]
fn check_zone_clean_zone_succeeds() {
    let f = fixture("example.com.zone", CLEAN_ZONE);
    hornet()
        .arg("check-zone")
        .arg(&f.path)
        .assert()
        .success()
        .stderr(predicate::str::contains("no issues found"));
}

#[test]
fn check_zone_warning_fails_without_allow_warnings() {
    let f = fixture("example.com.zone", WARNING_ZONE);
    hornet()
        .arg("check-zone")
        .arg(&f.path)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("warning"))
        .stderr(predicate::str::contains("MX exchange"));
}

#[test]
fn check_zone_warning_passes_with_allow_warnings() {
    let f = fixture("example.com.zone", WARNING_ZONE);
    hornet()
        .args(["check-zone", "--allow-warnings"])
        .arg(&f.path)
        .assert()
        .success()
        .stderr(predicate::str::contains("MX exchange"));
}

#[test]
fn check_zone_error_fails_even_with_allow_warnings() {
    let f = fixture("example.com.zone", ERROR_ZONE);
    hornet()
        .args(["check-zone", "--allow-warnings"])
        .arg(&f.path)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("missing a SOA record"));
}

#[test]
fn check_zone_missing_file_fails() {
    let dir = tempfile::tempdir().unwrap();
    hornet()
        .arg("check-zone")
        .arg(missing(&dir))
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::starts_with("Error:"));
}

// ── fmt ───────────────────────────────────────────────────────────────────────

/// What `hornet parse` prints for `contents` with default options.
fn canonical(contents: &str) -> String {
    let f = fixture("named.conf", contents);
    let out = hornet().arg("parse").arg(&f.path).output().unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn fmt_rewrites_file_in_place() {
    let f = fixture("named.conf", LEGACY_CONF);
    hornet()
        .arg("fmt")
        .arg(&f.path)
        .assert()
        .success()
        .stderr(predicate::str::contains("Formatted"));
    let after = read(&f.path);
    assert_eq!(after, canonical(LEGACY_CONF));
    assert!(after.contains("type primary;"));
}

#[test]
fn fmt_no_modern_keeps_legacy_keywords() {
    let f = fixture("named.conf", LEGACY_CONF);
    hornet()
        .args(["fmt", "--no-modern"])
        .arg(&f.path)
        .assert()
        .success();
    let after = read(&f.path);
    assert!(after.contains("type master;"), "{after}");
}

#[test]
fn fmt_indent_is_applied() {
    let f = fixture("named.conf", CLEAN_CONF);
    hornet()
        .args(["fmt", "--indent", "2"])
        .arg(&f.path)
        .assert()
        .success();
    assert!(read(&f.path).contains("\n  type primary;"));
}

#[test]
fn fmt_check_passes_on_formatted_file_and_leaves_it_alone() {
    let formatted = canonical(CLEAN_CONF);
    let f = fixture("named.conf", &formatted);
    hornet()
        .args(["fmt", "--check"])
        .arg(&f.path)
        .assert()
        .success()
        .stderr(predicate::str::contains("already formatted"));
    assert_eq!(read(&f.path), formatted);
}

#[test]
fn fmt_check_fails_on_unformatted_file_and_leaves_it_alone() {
    let f = fixture("named.conf", LEGACY_CONF);
    hornet()
        .args(["fmt", "--check"])
        .arg(&f.path)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("would be reformatted"));
    assert_eq!(read(&f.path), LEGACY_CONF);
}

#[test]
fn fmt_missing_file_fails() {
    let dir = tempfile::tempdir().unwrap();
    hornet()
        .arg("fmt")
        .arg(missing(&dir))
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::starts_with("Error:"));
}

#[test]
fn fmt_unparseable_file_fails_and_leaves_it_alone() {
    let f = fixture("named.conf", UNPARSEABLE_CONF);
    hornet()
        .arg("fmt")
        .arg(&f.path)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("Parse error"));
    assert_eq!(read(&f.path), UNPARSEABLE_CONF);
}

#[test]
fn fmt_read_only_file_fails_to_write() {
    if running_as_root() {
        return;
    }
    let f = fixture("named.conf", LEGACY_CONF);
    make_read_only(&f.path);
    hornet()
        .arg("fmt")
        .arg(&f.path)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::starts_with("Error:"));
    assert_eq!(read(&f.path), LEGACY_CONF);
}

// ── convert ───────────────────────────────────────────────────────────────────

#[test]
fn convert_prints_modern_config_and_leaves_file_alone() {
    let f = fixture("named.conf", LEGACY_CONF);
    hornet()
        .arg("convert")
        .arg(&f.path)
        .assert()
        .success()
        .stdout(predicate::str::contains("type primary;"))
        .stdout(predicate::str::contains("type secondary;"))
        .stdout(predicate::str::contains("primaries"));
    assert_eq!(read(&f.path), LEGACY_CONF);
}

#[test]
fn convert_in_place_rewrites_file() {
    let f = fixture("named.conf", LEGACY_CONF);
    hornet()
        .args(["convert", "--in-place"])
        .arg(&f.path)
        .assert()
        .success()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("Converted"));
    let after = read(&f.path);
    assert!(after.contains("type primary;"));
    assert!(!after.contains("master"));
}

#[test]
fn convert_missing_file_fails() {
    let dir = tempfile::tempdir().unwrap();
    hornet()
        .arg("convert")
        .arg(missing(&dir))
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::starts_with("Error:"));
}

#[test]
fn convert_unparseable_config_fails() {
    let f = fixture("named.conf", UNPARSEABLE_CONF);
    hornet()
        .arg("convert")
        .arg(&f.path)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::starts_with("Error:"));
}

#[test]
fn convert_in_place_read_only_file_fails() {
    if running_as_root() {
        return;
    }
    let f = fixture("named.conf", LEGACY_CONF);
    make_read_only(&f.path);
    hornet()
        .args(["convert", "--in-place"])
        .arg(&f.path)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::starts_with("Error:"));
    assert_eq!(read(&f.path), LEGACY_CONF);
}

// ── comments (hornet does not preserve them) ──────────────────────────────────

const COMMENTED_CONF: &str = r#"# Primary zones
zone "example.com" {
    type master; // legacy keyword
    file "/etc/bind/example.com.db";
};
/* end */
"#;

const COMMENTED_ZONE: &str = "$TTL 3600
; apex
@ IN SOA ns1.example.com. admin.example.com. ( 1 3600 900 604800 300 )
@ IN NS ns1.example.com.
ns1 IN A 192.0.2.1 ; name server
";

/// A comment marker inside a quoted string is data, not a comment.
const QUOTED_MARKER_CONF: &str = r#"zone "example.com" {
    type primary;
    file "/etc/bind/db#1//x";
};
"#;

#[test]
fn fmt_refuses_to_rewrite_file_with_comments() {
    let f = fixture("named.conf", COMMENTED_CONF);
    hornet()
        .arg("fmt")
        .arg(&f.path)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("contains comments"))
        .stderr(predicate::str::contains("--force"));
    assert_eq!(read(&f.path), COMMENTED_CONF);
}

#[test]
fn fmt_force_rewrites_file_with_comments_and_warns() {
    let f = fixture("named.conf", COMMENTED_CONF);
    hornet()
        .args(["fmt", "--force"])
        .arg(&f.path)
        .assert()
        .success()
        .stderr(predicate::str::contains("comments were removed"))
        .stderr(predicate::str::contains("Formatted"));
    let after = read(&f.path);
    assert_eq!(after, canonical(COMMENTED_CONF));
    assert!(!after.contains("legacy keyword"), "{after}");
}

#[test]
fn fmt_force_without_comments_does_not_warn() {
    let f = fixture("named.conf", LEGACY_CONF);
    hornet()
        .args(["fmt", "--force"])
        .arg(&f.path)
        .assert()
        .success()
        .stderr(predicate::str::contains("comments").not());
}

#[test]
fn fmt_rewrites_file_with_quoted_comment_markers() {
    let f = fixture("named.conf", QUOTED_MARKER_CONF);
    hornet().arg("fmt").arg(&f.path).assert().success();
    assert!(read(&f.path).contains(r#""/etc/bind/db#1//x""#));
}

#[test]
fn fmt_check_ignores_comments_on_otherwise_formatted_file() {
    let formatted = canonical(CLEAN_CONF);
    let with_comments = format!("# managed by hornet\n{formatted}");
    let f = fixture("named.conf", &with_comments);
    hornet()
        .args(["fmt", "--check"])
        .arg(&f.path)
        .assert()
        .success()
        .stderr(predicate::str::contains("comments are ignored by --check"))
        .stderr(predicate::str::contains("already formatted"));
    assert_eq!(read(&f.path), with_comments);
}

#[test]
fn fmt_check_still_fails_on_unformatted_file_with_comments() {
    let f = fixture("named.conf", COMMENTED_CONF);
    hornet()
        .args(["fmt", "--check"])
        .arg(&f.path)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("would be reformatted"));
    assert_eq!(read(&f.path), COMMENTED_CONF);
}

#[test]
fn convert_in_place_refuses_file_with_comments() {
    let f = fixture("named.conf", COMMENTED_CONF);
    hornet()
        .args(["convert", "--in-place"])
        .arg(&f.path)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("contains comments"));
    assert_eq!(read(&f.path), COMMENTED_CONF);
}

#[test]
fn convert_in_place_force_rewrites_file_with_comments() {
    let f = fixture("named.conf", COMMENTED_CONF);
    hornet()
        .args(["convert", "--in-place", "--force"])
        .arg(&f.path)
        .assert()
        .success()
        .stderr(predicate::str::contains("comments were removed"))
        .stderr(predicate::str::contains("Converted"));
    let after = read(&f.path);
    assert!(after.contains("type primary;"), "{after}");
    assert!(!after.contains('#'), "{after}");
}

#[test]
fn convert_stdout_warns_when_comments_are_omitted() {
    let f = fixture("named.conf", COMMENTED_CONF);
    hornet()
        .arg("convert")
        .arg(&f.path)
        .assert()
        .success()
        .stdout(predicate::str::contains("type primary;"))
        .stderr(predicate::str::contains("not included in the output"));
    assert_eq!(read(&f.path), COMMENTED_CONF);
}

#[test]
fn parse_warns_when_comments_are_omitted() {
    let f = fixture("named.conf", COMMENTED_CONF);
    hornet()
        .arg("parse")
        .arg(&f.path)
        .assert()
        .success()
        .stdout(predicate::str::contains("legacy keyword").not())
        .stderr(predicate::str::contains("not included in the output"));
}

#[test]
fn parse_without_comments_does_not_warn() {
    let f = fixture("named.conf", QUOTED_MARKER_CONF);
    hornet()
        .arg("parse")
        .arg(&f.path)
        .assert()
        .success()
        .stderr(predicate::str::is_empty());
}

#[test]
fn zone_warns_when_comments_are_omitted() {
    let f = fixture("example.com.zone", COMMENTED_ZONE);
    hornet()
        .arg("zone")
        .arg(&f.path)
        .assert()
        .success()
        .stdout(predicate::str::contains("SOA"))
        .stderr(predicate::str::contains("not included in the output"));
}

#[test]
fn zone_without_comments_does_not_warn() {
    let f = fixture("example.com.zone", CLEAN_ZONE);
    hornet()
        .arg("zone")
        .arg(&f.path)
        .assert()
        .success()
        .stderr(predicate::str::is_empty());
}
