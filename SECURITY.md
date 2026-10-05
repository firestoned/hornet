# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Do not** open a public GitHub issue for security vulnerabilities.

Report them by email to **security@firestoned.io**, or through GitHub's
private vulnerability reporting on this repository. Include:

- a description of the vulnerability;
- steps or an input that reproduces it;
- the potential impact (for hornet this is usually what an attacker can make
  BIND9 load, or how much CPU or memory an input costs);
- a suggested fix, if you have one.

### Disclosure Policy

- We practice coordinated disclosure.
- Open findings are tracked privately until a fix is released, then published
  in the threat model and, where warranted, as a GitHub security advisory.
- We credit reporters unless they prefer to remain anonymous.

## Security Documentation

- **[Threat model](docs/src/security/threat-model.md)**: assets, actors, trust
  boundaries, STRIDE analysis, accepted risks and supply-chain controls.
- **[ADR-0001](docs/adr/0001-single-build-workflow-and-bind9-e2e-oracle.md)**:
  the CI design, including SHA-pinned actions and the BIND9 e2e oracle.

## Security Measures

- **Signed commits:** every commit must be GPG- or SSH-signed and signed off;
  CI verifies signatures on pull requests, pushes and releases.
- **Dependency scanning:** `cargo audit` and `cargo deny` run in CI.
- **License compliance:** SPDX headers (Apache-2.0) are enforced in CI.
- **Release integrity:** binary tarballs are Cosign-signed (keyless), ship
  with CycloneDX SBOMs and SLSA build provenance, and are checksummed.
