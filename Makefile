# Sampan Trust checkout: build, test and security targets.
# See docs/MILESTONES.md (workflow) and docs/SECURITY.md (section 5, tooling).
# Shared steps are separate targets, so `make check security` runs each once.
SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := check

.PHONY: check build build-checker build-wasm wasm-release testnet-m3 vectors-check lint fmt clippy banned test-contract test-web security supply-chain coverage mutants fuzz hooks install

install:            ## Install JS dependencies exactly as locked
	pnpm install --frozen-lockfile

build:              ## Build all Rust crates
	cargo build --workspace --locked

fmt:
	cargo fmt --all -- --check

clippy:             ## Host and wasm (wasm32-only code paths are linted too)
	cargo clippy --workspace --all-targets --locked -- -D warnings
	cargo clippy -p sampan-gate -p sampan-formats --lib --locked --target wasm32-unknown-unknown -- -D warnings

build-checker:      ## The receipt checker as one static file (apps/checker/dist/index.html)
	node apps/checker/build.mjs

build-wasm:         ## The contract compiles for wasm (checked by make check)
	cargo build -p sampan-gate --locked --release --target wasm32-unknown-unknown

wasm-release:       ## The contract as deployed: MVP wasm features only (NEAR runtime), stripped
	RUSTFLAGS="-C target-cpu=mvp -C link-arg=-s" cargo build -p sampan-gate --locked --release --target wasm32-unknown-unknown

testnet-m3: wasm-release   ## Deploy and exercise the gate on testnet (needs the testnet secret)
	node scripts/m3/testnet-run.mjs

banned:             ## Unsafe code patterns and banned wording
	node scripts/lint-banned.mjs

lint: fmt clippy banned

test-contract:      ## Rust unit tests (sandbox tests join in M3)
	cargo test --workspace --locked

test-web:           ## TypeScript and script tests (Playwright joins in M5/M6)
	pnpm exec vitest run

vectors-check:      ## Generator reproduces every committed vector; no extras (M2-04)
	node scripts/gen-vectors.ts --check

check: lint build-wasm build-checker vectors-check test-contract test-web   ## Everything; must pass before any PR

supply-chain:       ## Advisories, licences, sources, secrets
	cargo audit --deny warnings
	cargo deny --locked check
	# All packages, dev tools too: they run where test keys live (M0-04).
	pnpm audit --audit-level low
	scripts/secrets-scan.sh --history

security: clippy banned supply-chain   ## Full security check (docs/SECURITY.md 5)

# Coverage floors (docs/SECURITY.md 5): 90% lines for the formats crate and packages.
coverage:
	cargo llvm-cov --locked -p sampan-formats --fail-under-lines 90 --summary-only
	cargo llvm-cov --locked -p sampan-gate --fail-under-lines 90 --summary-only
	pnpm exec vitest run --coverage --coverage.include='packages/*/src/**' --coverage.exclude='**/*.test.ts' \
	  --coverage.thresholds.lines=90 --coverage.thresholds.branches=85

# Mutation testing on the formats crate and the gate contract: every surviving mutant
# needs a test or a written reason in the milestone audit.
mutants:
	cargo mutants -p sampan-formats --no-shuffle --timeout 120 --jobs 4 -- --locked
	cargo mutants -p sampan-gate --no-shuffle --timeout 180 --jobs 4 -- --locked

# Fuzzing (docs/SECURITY.md 5): cargo-fuzz targets on the pinned nightly toolchain, then
# the property tests with many more cases in both languages. FUZZ_SECONDS per target.
FUZZ_SECONDS ?= 60
fuzz:
	cd crates/formats/fuzz && for t in parse_documents canonical_roundtrip; do \
	  cargo +nightly-2026-11-01 fuzz run $$t -- -max_total_time=$(FUZZ_SECONDS) -max_len=4200 || exit 1; done
	PROPTEST_CASES=50000 cargo test --locked -p sampan-formats --release --test properties
	PROPTEST_CASES=5000 cargo test --locked -p sampan-gate --release --lib invariants_hold
	FC_NUM_RUNS=20000 pnpm exec vitest run packages/mandate/src/vectors.test.ts

hooks:              ## Use the repository's git hooks (pre-commit secrets scan)
	git config core.hooksPath .githooks
