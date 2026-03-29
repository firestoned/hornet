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
	cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic -A clippy::module_name_repetitions

.PHONY: test
test: ## Run all tests
	cargo test --all-features

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
