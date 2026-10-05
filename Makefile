.DEFAULT_GOAL := help

# Cargo.lock is committed: every cargo invocation builds exactly the locked
# dependency graph and fails if Cargo.toml and the lockfile disagree. Override
# with CARGO_LOCKED= to let cargo update the lockfile.
CARGO_LOCKED ?= --locked

##@ General

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Build

.PHONY: build
build: ## Build (debug) — library + CLI binary
	cargo build $(CARGO_LOCKED)

.PHONY: build-release
build-release: ## Build (release) — library + CLI binary
	cargo build $(CARGO_LOCKED) --release

.PHONY: build-target
build-target: ## Build the release CLI binary for TARGET (usage: make build-target TARGET=aarch64-apple-darwin)
	@if [ -z "$(TARGET)" ]; then echo "Error: TARGET required"; exit 1; fi
	cargo build $(CARGO_LOCKED) --release --target $(TARGET)

.PHONY: build-all
build-all: ## Build every target (lib, bin, tests, benches) with all features; used by CodeQL
	cargo build $(CARGO_LOCKED) --all-features --all-targets

.PHONY: build-lib
build-lib: ## Build library only (no CLI binary)
	cargo build $(CARGO_LOCKED) --no-default-features

##@ Quality

.PHONY: fmt
fmt: ## Format all code
	cargo fmt --all

.PHONY: fmt-check
fmt-check: ## Check formatting without modifying files
	cargo fmt --all -- --check

.PHONY: clippy
clippy: ## Run clippy with strict warnings
	cargo clippy $(CARGO_LOCKED) --all-targets --all-features -- -D warnings -W clippy::pedantic -A clippy::module_name_repetitions -A clippy::assert_is_empty

.PHONY: test
test: ## Run all tests
	cargo test $(CARGO_LOCKED) --all-features

.PHONY: test-release
test-release: ## Run all tests in the release profile for TARGET (CI: reuses the release build's rlibs)
	@if [ -z "$(TARGET)" ]; then echo "Error: TARGET required, e.g. TARGET=x86_64-unknown-linux-gnu"; exit 1; fi
	cargo test $(CARGO_LOCKED) --release --all-features --target $(TARGET)

.PHONY: quality
quality: fmt clippy test ## Run fmt, clippy, and test (full quality gate)

##@ Development

.PHONY: check
check: ## Fast syntax/type check (no codegen)
	cargo check $(CARGO_LOCKED) --all-features

.PHONY: clean
clean: ## Remove build artifacts
	cargo clean

.PHONY: doc
doc: ## Build rustdoc (opens browser)
	cargo doc $(CARGO_LOCKED) --no-deps --all-features --open

##@ Benchmarks

.PHONY: bench
bench: ## Run all benchmarks including stress tests (full criterion timing)
	cargo bench $(CARGO_LOCKED) --all-features

.PHONY: bench-quick
bench-quick: ## Run standard benchmarks only, no stress tests (CI mode)
	cargo bench $(CARGO_LOCKED) --bench named_conf --bench zone_file

.PHONY: bench-stress
bench-stress: ## Run stress benchmarks only — 10k and 100k zones (slow, not run in CI)
	cargo bench $(CARGO_LOCKED) --bench named_conf_stress

.PHONY: bench-compile
bench-compile: ## Compile all benchmarks without running them (fast CI check)
	cargo bench $(CARGO_LOCKED) --no-run --all-features

##@ Coverage

# Coverage policy: docs/adr/0002-coverage-policy-and-per-suite-reports.md.
# Unit + integration together are gated on lines and functions; regions are
# reported, not gated. Each suite also gets its own report so CI can show
# what each kind of test actually exercises.
COVERAGE_DIR           ?= target/coverage
COVERAGE_MIN_LINES     ?= 100
COVERAGE_MIN_FUNCTIONS ?= 100
# Test-only files are not product code; their unreached panic arms would
# otherwise count as missed lines.
COVERAGE_IGNORE        ?= (_tests\.rs|/tests/|/benches/)
LLVM_COV_IGNORE        := --ignore-filename-regex '$(COVERAGE_IGNORE)'
LLVM_COV_FLAGS         := --all-features $(CARGO_LOCKED)

# coverage_report <suite>: write lcov, json and html for the profiles
# collected so far into $(COVERAGE_DIR)/<suite>/.
define coverage_report
	@mkdir -p $(COVERAGE_DIR)/$(1)
	cargo llvm-cov report $(LLVM_COV_IGNORE) --lcov --output-path $(COVERAGE_DIR)/$(1)/lcov.info
	cargo llvm-cov report $(LLVM_COV_IGNORE) --json --output-path $(COVERAGE_DIR)/$(1)/coverage.json
	cargo llvm-cov report $(LLVM_COV_IGNORE) --html --output-dir $(COVERAGE_DIR)/$(1)
	cargo llvm-cov report $(LLVM_COV_IGNORE) --summary-only
endef

.PHONY: coverage-unit
coverage-unit: ## Coverage of the library unit tests (src/**/*_tests.rs) into target/coverage/unit/
	cargo llvm-cov clean --workspace
	cargo llvm-cov $(LLVM_COV_FLAGS) --lib --no-report
	$(call coverage_report,unit)

.PHONY: coverage-integration
coverage-integration: ## Coverage of the integration tests (tests/*.rs, incl. CLI runs) into target/coverage/integration/
	cargo llvm-cov clean --workspace
	cargo llvm-cov $(LLVM_COV_FLAGS) --test '*' --no-report
	$(call coverage_report,integration)

.PHONY: coverage
coverage: ## Unit + integration coverage into target/coverage/all/, gated on COVERAGE_MIN_LINES / COVERAGE_MIN_FUNCTIONS (default 100)
	cargo llvm-cov clean --workspace
	cargo llvm-cov $(LLVM_COV_FLAGS) --lib --bins --test '*' --no-report
	$(call coverage_report,all)
	cargo llvm-cov report $(LLVM_COV_IGNORE) --summary-only \
		--fail-under-lines $(COVERAGE_MIN_LINES) --fail-under-functions $(COVERAGE_MIN_FUNCTIONS)

.PHONY: coverage-lcov
coverage-lcov: coverage ## Alias: combined coverage; LCOV at target/coverage/all/lcov.info

.PHONY: coverage-html
coverage-html: coverage ## Alias: combined coverage; HTML at target/coverage/all/html/index.html

COVERAGE_JSON  ?= $(COVERAGE_DIR)/all/coverage.json
COVERAGE_LCOV  ?= $(patsubst %/coverage.json,%/lcov.info,$(COVERAGE_JSON))
COVERAGE_TITLE ?= Coverage

.PHONY: coverage-summary
coverage-summary: ## Print a Markdown coverage table (usage: make coverage-summary COVERAGE_JSON=target/coverage/unit/coverage.json COVERAGE_TITLE=Unit)
	@./scripts/coverage-summary.sh "$(COVERAGE_JSON)" "$(COVERAGE_TITLE)" "$(COVERAGE_LCOV)"

# ── e2e coverage ─────────────────────────────────────────────────────────────
# The e2e suite drives a real hornet binary from a shell script, so
# cargo-llvm-cov's test runner is not involved: build an instrumented binary,
# point LLVM_PROFILE_FILE at a directory, run the suite, then merge and export
# with the rustup llvm-tools directly. Every step works from files alone, so CI
# can build, run and report in different jobs.
COVERAGE_E2E_DIR     ?= $(COVERAGE_DIR)/e2e
COVERAGE_E2E_BIN     ?= $(COVERAGE_E2E_DIR)/bin/hornet
COVERAGE_E2E_PROFRAW ?= $(COVERAGE_E2E_DIR)/profraw

.PHONY: coverage-e2e
coverage-e2e: coverage-e2e-build ## e2e coverage: instrumented hornet through every BIND_VERSIONS run, report in target/coverage/e2e/ (not gated)
	@rm -rf $(COVERAGE_E2E_PROFRAW)
	@set -e; for v in $(BIND_VERSIONS); do \
		$(MAKE) --no-print-directory coverage-e2e-run BIND_VERSION=$$v; \
	done
	@$(MAKE) --no-print-directory coverage-e2e-report

.PHONY: coverage-e2e-build
coverage-e2e-build: ## Build a coverage-instrumented hornet at target/coverage/e2e/bin/hornet
	./scripts/coverage-e2e.sh build "$(COVERAGE_E2E_DIR)"

.PHONY: coverage-e2e-run
coverage-e2e-run: ## Run the e2e suite once with the instrumented binary, collecting profiles (BIND_VERSION=...)
	./scripts/coverage-e2e.sh run "$(COVERAGE_E2E_DIR)" "$(BIND_VERSION)" "$(CONTAINER_RUNTIME)"

.PHONY: coverage-e2e-report
coverage-e2e-report: ## Merge e2e profiles into lcov, json and html under target/coverage/e2e/
	./scripts/coverage-e2e.sh report "$(COVERAGE_E2E_DIR)" '$(COVERAGE_IGNORE)'

##@ Supply chain

SBOM_DIR   ?= sbom
CRATE_NAME := hornet-bind9

.PHONY: version-info
version-info: ## Print version=/short-sha= from Cargo.toml (fails if RELEASE_TAG is set and disagrees)
	@version=$$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | select(.name == "$(CRATE_NAME)") | .version'); \
	if [ -n "$(RELEASE_TAG)" ] && [ "$(RELEASE_TAG)" != "v$$version" ] && [ "$(RELEASE_TAG)" != "$$version" ]; then \
		echo "Error: release tag $(RELEASE_TAG) does not match Cargo.toml version $$version" >&2; exit 1; \
	fi; \
	echo "version=$$version"; \
	echo "short-sha=$$(git rev-parse --short=7 HEAD)"

.PHONY: sbom-stage
sbom-stage: ## Stage and sanity-check the CycloneDX SBOM (usage: make sbom-stage SBOM_NAME=hornet-linux-amd64)
	@if [ -z "$(SBOM_NAME)" ]; then echo "Error: SBOM_NAME required, e.g. SBOM_NAME=hornet-linux-amd64"; exit 1; fi
	@test -f $(CRATE_NAME).cdx.json || { echo "Error: $(CRATE_NAME).cdx.json not found; generate it first"; exit 1; }
	@mkdir -p $(SBOM_DIR)
	@cp $(CRATE_NAME).cdx.json $(SBOM_DIR)/$(SBOM_NAME).cdx.json
	@jq -e '.bomFormat == "CycloneDX" and .metadata.component.name == "$(CRATE_NAME)" and (.components | length > 0)' \
		$(SBOM_DIR)/$(SBOM_NAME).cdx.json >/dev/null \
		|| { echo "Error: $(SBOM_DIR)/$(SBOM_NAME).cdx.json is not a usable CycloneDX SBOM for $(CRATE_NAME)"; exit 1; }
	@echo "✓ SBOM staged at $(SBOM_DIR)/$(SBOM_NAME).cdx.json"

.PHONY: release-tarball
release-tarball: ## Tar one release binary for signing (usage: make release-tarball DIR=artifacts/x NAME=hornet-linux-amd64 BINARY=hornet)
	@if [ -z "$(DIR)" ] || [ -z "$(NAME)" ] || [ -z "$(BINARY)" ]; then echo "Error: DIR, NAME and BINARY required"; exit 1; fi
	@test -f "$(DIR)/$(BINARY)" || { echo "Error: $(BINARY) not found in $(DIR)"; ls -la "$(DIR)"; exit 1; }
	@chmod +x "$(DIR)/$(BINARY)"
	@tar czf "$(DIR)/$(NAME).tar.gz" -C "$(DIR)" "$(BINARY)"
	@ls -lh "$(DIR)/$(NAME).tar.gz"

.PHONY: provenance-subjects
provenance-subjects: ## Write base64 SLSA subjects for every file in DIR (signature bundles excluded) to OUT
	@if [ -z "$(DIR)" ] || [ -z "$(OUT)" ]; then echo "Error: DIR and OUT required"; exit 1; fi
	@cd "$(DIR)" && find . -maxdepth 1 -type f ! -name '.*' ! -name '*.bundle' -print0 | sort -z \
		| xargs -0 sha256sum | sed 's| \./| |' > "$(CURDIR)/subjects.sha256"
	@cat "$(CURDIR)/subjects.sha256"
	@base64 -w0 < "$(CURDIR)/subjects.sha256" > "$(OUT)"
	@echo "✓ $$(wc -l < "$(CURDIR)/subjects.sha256" | tr -d ' ') provenance subjects written to $(OUT)"

.PHONY: release-assets
release-assets: ## Arrange downloaded release artifacts in DIR into release/ sboms/ signatures/ provenance/ with checksums
	@if [ -z "$(DIR)" ]; then echo "Error: DIR required"; exit 1; fi
	@cd "$(DIR)" && mkdir -p release sboms signatures provenance \
		&& cp hornet-*-signed/*.tar.gz release/ \
		&& cp hornet-*-signed/*.tar.gz.bundle signatures/ \
		&& cp sbom-*/*.cdx.json sboms/ \
		&& { find . -path ./provenance -prune -o -name '*.intoto.jsonl' -type f -exec cp {} provenance/ \; ; } \
		&& ( cd release && sha256sum *.tar.gz > checksums.sha256 ) \
		&& ( cd sboms && sha256sum *.cdx.json >> ../release/checksums.sha256 ) \
		&& ( cd signatures && sha256sum *.bundle >> ../release/checksums.sha256 ) \
		&& ( cd provenance && if ls *.intoto.jsonl >/dev/null 2>&1; then sha256sum *.intoto.jsonl >> ../release/checksums.sha256; fi ) \
		&& cat release/checksums.sha256

.PHONY: cargo-deny
cargo-deny: ## Check dependencies for advisories, licenses, bans and sources (.cargo/deny.toml)
	@command -v cargo-deny >/dev/null 2>&1 || { echo "Installing cargo-deny..."; cargo install cargo-deny --locked; }
	cargo deny --all-features --config .cargo/deny.toml check

.PHONY: license-check
license-check: ## Fail if any dependency is under a prohibited (copyleft) license
	@command -v cargo-license >/dev/null 2>&1 || { echo "Installing cargo-license..."; cargo install cargo-license --locked; }
	@VIOLATIONS=$$(cargo license --json 2>/dev/null | \
		jq -r '.[] | select(.license | test("(^| )GPL|AGPL|SSPL|EUPL|CDDL"; "i")) | "\(.name) \(.version): \(.license)"'); \
	if [ -n "$$VIOLATIONS" ]; then \
		echo "Prohibited license(s) found:"; echo "$$VIOLATIONS"; exit 1; \
	fi; \
	echo "✓ All dependency licenses are compliant"

.PHONY: license-report
license-report: ## Write a license report for every dependency to licenses.json
	@command -v cargo-license >/dev/null 2>&1 || { echo "Installing cargo-license..."; cargo install cargo-license --locked; }
	@cargo license --json > licenses.json
	@echo "✓ License report written to licenses.json"

##@ Publishing

.PHONY: publish
publish: ## Publish the hornet crate to crates.io
	cargo publish $(CARGO_LOCKED)

##@ Documentation

.PHONY: docs
docs: ## Build MkDocs documentation site
	cd docs && poetry run mkdocs build

DOCS_PORT ?= 8000

.PHONY: docs-serve
docs-serve: ## Serve MkDocs documentation with live reload (dirtyreload: only rebuilds changed pages)
	cd docs && poetry run mkdocs serve --dirtyreload --dev-addr 127.0.0.1:$(DOCS_PORT)

.PHONY: docs-serve-dev
docs-serve-dev: ## Serve docs in fast dev mode — disables git-revision-date plugin for instant rebuilds
	cd docs && ENABLED_GIT_DATES=false poetry run mkdocs serve --dirtyreload --dev-addr 127.0.0.1:$(DOCS_PORT)

.PHONY: docs-install
docs-install: ## Install documentation dependencies via Poetry
	cd docs && poetry install --no-interaction --no-ansi

##@ End-to-end

BIND_VERSIONS     ?= 9.18 9.20
BIND_VERSION      ?= 9.20
CONTAINER_RUNTIME ?= docker
HORNET_BIN        ?= target/release/hornet

.PHONY: e2e
e2e: build-release ## Round-trip every fixture through hornet and real BIND9 (all BIND_VERSIONS)
	@set -e; for v in $(BIND_VERSIONS); do \
		$(MAKE) --no-print-directory e2e-run BIND_VERSION=$$v; \
	done

.PHONY: e2e-bind
e2e-bind: build-release ## Round-trip against one BIND9 version (usage: make e2e-bind BIND_VERSION=9.18)
	@$(MAKE) --no-print-directory e2e-run BIND_VERSION=$(BIND_VERSION)

.PHONY: e2e-run
e2e-run: ## Run the e2e suite with an already-built HORNET_BIN (CI: binary comes from the build job)
	@chmod +x $(HORNET_BIN)  # artifact downloads drop the executable bit
	BIND_VERSION=$(BIND_VERSION) CONTAINER_RUNTIME=$(CONTAINER_RUNTIME) HORNET_BIN=$(HORNET_BIN) \
		./tests/e2e/run.sh
