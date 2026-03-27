//! `bind9` — CLI for parsing, validating and formatting BIND9 config files.
//!
//! Usage:
//!   hornet parse   <file>           Parse and pretty-print a named.conf
//!   hornet zone    <file>           Parse and pretty-print a zone file
//!   hornet check   <file>           Validate a named.conf, print diagnostics
//!   hornet fmt     <file>           Reformat a named.conf in-place
//!   hornet convert <file>           Normalise legacy keywords (master→primary)

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use miette::IntoDiagnostic;

use hornet::{
    error::Severity, parse_named_conf_file, parse_zone_file_from_path, validate_named_conf,
    validate_zone_file, write_named_conf, write_zone_file, writer::WriteOptions,
};

// ── CLI definition ─────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "hornet",
    version,
    about = "Parse, validate, and format BIND9 configuration files",
    long_about = "A fast Rust-based tool for working with BIND9 named.conf and zone files.\n\nPass --help to any subcommand for detailed usage."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Parse a named.conf and print the re-formatted output.
    #[command(visible_alias = "p")]
    Parse {
        /// Path to named.conf
        file: PathBuf,
        /// Indent size (default: 4)
        #[arg(short, long, default_value_t = 4)]
        indent: usize,
        /// Use modern keyword aliases (primary/secondary instead of master/slave)
        #[arg(long, default_value_t = true)]
        modern: bool,
    },
    /// Parse a zone file and print the re-formatted output.
    #[command(visible_alias = "z")]
    Zone {
        /// Path to zone file
        file: PathBuf,
        #[arg(short, long, default_value_t = 4)]
        indent: usize,
    },
    /// Validate a named.conf and report any errors or warnings.
    #[command(visible_alias = "c")]
    Check {
        /// Path to named.conf
        file: PathBuf,
        /// Exit with code 0 even if warnings are found (errors still fail)
        #[arg(long)]
        allow_warnings: bool,
        /// Minimum severity to report: info | warning | error
        #[arg(long, default_value = "info")]
        min_severity: String,
    },
    /// Validate a zone file and report any errors or warnings.
    CheckZone {
        /// Path to zone file
        file: PathBuf,
        #[arg(long)]
        allow_warnings: bool,
    },
    /// Reformat a named.conf file in-place.
    Fmt {
        /// Path to named.conf
        file: PathBuf,
        /// Indent size (default: 4)
        #[arg(short, long, default_value_t = 4)]
        indent: usize,
        /// Check formatting only; exit 1 if file would change
        #[arg(long)]
        check: bool,
        /// Use modern keyword aliases
        #[arg(long, default_value_t = true)]
        modern: bool,
    },
    /// Convert legacy BIND8/9 keywords to modern equivalents.
    Convert {
        /// Path to named.conf
        file: PathBuf,
        /// Write output in-place instead of stdout
        #[arg(long)]
        in_place: bool,
    },
}

// ── Main ───────────────────────────────────────────────────────────────────────

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli.command) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[allow(clippy::too_many_lines)]
fn run(cmd: Command) -> miette::Result<ExitCode> {
    match cmd {
        Command::Parse {
            file,
            indent,
            modern,
        } => {
            let conf = parse_named_conf_file(&file).into_diagnostic()?;
            let opts = WriteOptions {
                indent,
                modern_keywords: modern,
                ..Default::default()
            };
            print!("{}", write_named_conf(&conf, &opts));
            Ok(ExitCode::SUCCESS)
        }

        Command::Zone { file, indent } => {
            let zone = parse_zone_file_from_path(&file).into_diagnostic()?;
            let opts = WriteOptions {
                indent,
                ..Default::default()
            };
            print!("{}", write_zone_file(&zone, &opts));
            Ok(ExitCode::SUCCESS)
        }

        Command::Check {
            file,
            allow_warnings,
            min_severity,
        } => {
            let conf = parse_named_conf_file(&file).into_diagnostic()?;
            let diags = validate_named_conf(&conf);
            let min_sev = parse_severity(&min_severity);
            let mut worst = Severity::Info;
            for d in &diags {
                if d.severity >= min_sev {
                    let prefix = match d.severity {
                        Severity::Error => "\x1b[31merror\x1b[0m",
                        Severity::Warning => "\x1b[33mwarning\x1b[0m",
                        Severity::Info => "\x1b[36minfo\x1b[0m",
                    };
                    eprintln!("{prefix}: {}", d.message);
                    if d.severity > worst {
                        worst = d.severity.clone();
                    }
                }
            }
            if diags.is_empty() {
                eprintln!("\x1b[32mOK\x1b[0m  {} — no issues found", file.display());
            } else {
                eprintln!(
                    "\n{} diagnostic(s) found in {}",
                    diags.len(),
                    file.display()
                );
            }
            if worst == Severity::Error || (!allow_warnings && worst == Severity::Warning) {
                Ok(ExitCode::FAILURE)
            } else {
                Ok(ExitCode::SUCCESS)
            }
        }

        Command::CheckZone {
            file,
            allow_warnings,
        } => {
            let zone = parse_zone_file_from_path(&file).into_diagnostic()?;
            let diags = validate_zone_file(&zone);
            let mut has_error = false;
            let mut has_warning = false;
            for d in &diags {
                let prefix = match d.severity {
                    Severity::Error => {
                        has_error = true;
                        "\x1b[31merror\x1b[0m"
                    }
                    Severity::Warning => {
                        has_warning = true;
                        "\x1b[33mwarning\x1b[0m"
                    }
                    Severity::Info => "\x1b[36minfo\x1b[0m",
                };
                eprintln!("{prefix}: {}", d.message);
            }
            if diags.is_empty() {
                eprintln!("\x1b[32mOK\x1b[0m  {} — no issues found", file.display());
            }
            if has_error || (!allow_warnings && has_warning) {
                Ok(ExitCode::FAILURE)
            } else {
                Ok(ExitCode::SUCCESS)
            }
        }

        Command::Fmt {
            file,
            indent,
            check,
            modern,
        } => {
            let original = std::fs::read_to_string(&file).into_diagnostic()?;
            let conf = parse_named_conf_file(&file).into_diagnostic()?;
            let opts = WriteOptions {
                indent,
                modern_keywords: modern,
                ..Default::default()
            };
            let formatted = write_named_conf(&conf, &opts);
            if check {
                if formatted == original {
                    eprintln!("\x1b[32mOK\x1b[0m  {} is already formatted", file.display());
                    Ok(ExitCode::SUCCESS)
                } else {
                    eprintln!(
                        "\x1b[31mFAIL\x1b[0m {} would be reformatted",
                        file.display()
                    );
                    Ok(ExitCode::FAILURE)
                }
            } else {
                std::fs::write(&file, &formatted).into_diagnostic()?;
                eprintln!("Formatted {}", file.display());
                Ok(ExitCode::SUCCESS)
            }
        }

        Command::Convert { file, in_place } => {
            let conf = parse_named_conf_file(&file).into_diagnostic()?;
            let opts = WriteOptions {
                modern_keywords: true,
                ..Default::default()
            };
            let output = write_named_conf(&conf, &opts);
            if in_place {
                std::fs::write(&file, &output).into_diagnostic()?;
                eprintln!("Converted {} to modern keywords", file.display());
            } else {
                print!("{output}");
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn parse_severity(s: &str) -> Severity {
    match s.to_ascii_lowercase().as_str() {
        "error" => Severity::Error,
        "warning" | "warn" => Severity::Warning,
        _ => Severity::Info,
    }
}
