.DEFAULT_GOAL := help

##@ General

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Build

.PHONY: build
build: ## Build (debug) — library + CLI binary
	cargo build

.PHONY: build-release
build-release: ## Build (release) — library + CLI binary
	cargo build --release

.PHONY: build-target
build-target: ## Build the release CLI binary for TARGET (usage: make build-target TARGET=aarch64-apple-darwin)
	@if [ -z "$(TARGET)" ]; then echo "Error: TARGET required"; exit 1; fi
	cargo build --release --target $(TARGET)

.PHONY: build-lib
build-lib: ## Build library only (no CLI binary)
	cargo build --no-default-features

##@ Quality

.PHONY: fmt
fmt: ## Format all code
	cargo fmt --all

.PHONY: fmt-check
fmt-check: ## Check formatting without modifying files
	cargo fmt --all -- --check

.PHONY: clippy
clippy: ## Run clippy with strict warnings
	cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic -A clippy::module_name_repetitions -A clippy::assert_is_empty

.PHONY: test
test: ## Run all tests
	cargo test --all-features

.PHONY: test-release
test-release: ## Run all tests in the release profile for TARGET (CI: reuses the release build's rlibs)
	@if [ -z "$(TARGET)" ]; then echo "Error: TARGET required, e.g. TARGET=x86_64-unknown-linux-gnu"; exit 1; fi
	cargo test --release --all-features --target $(TARGET)

.PHONY: quality
quality: fmt clippy test ## Run fmt, clippy, and test (full quality gate)

##@ Development

.PHONY: check
check: ## Fast syntax/type check (no codegen)
	cargo check --all-features

.PHONY: clean
clean: ## Remove build artifacts
	cargo clean

.PHONY: doc
doc: ## Build rustdoc (opens browser)
	cargo doc --no-deps --all-features --open

##@ Benchmarks

.PHONY: bench
bench: ## Run all benchmarks including stress tests (full criterion timing)
	cargo bench --all-features

.PHONY: bench-quick
bench-quick: ## Run standard benchmarks only, no stress tests (CI mode)
	cargo bench --bench named_conf --bench zone_file

.PHONY: bench-stress
bench-stress: ## Run stress benchmarks only — 10k and 100k zones (slow, not run in CI)
	cargo bench --bench named_conf_stress

.PHONY: bench-compile
bench-compile: ## Compile all benchmarks without running them (fast CI check)
	cargo bench --no-run --all-features

##@ Coverage

.PHONY: coverage-lcov
coverage-lcov: ## Generate LCOV coverage report (lcov.info)
	cargo llvm-cov --all-features --lcov --output-path lcov.info

.PHONY: coverage-html
coverage-html: ## Generate HTML coverage report
	cargo llvm-cov --all-features --html

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
	cargo publish

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
