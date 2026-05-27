# Hearth — Build Targets
# Requires: cargo, cargo-nextest, buf, protoc

PROTOC ?= protoc
CARGO_FLAGS ?=
BUF := buf

.PHONY: setup build test clippy fmt check css css-check css-watch tailwind-install proto-gen proto-lint proto-breaking proto-check sdk-test test-quality ci-fast bench-gate cluster-route-check ci-standard ci-local-fast ci-local-full sdk-smoke-local dev dev-reset ui-test ui-test-smoke ui-coverage-check ui-test-visual ui-test-cross-browser

# ── Contributor Setup ─────────────────────────────────

## One-time contributor setup: enable repo-managed git hooks.
setup:
	git config core.hooksPath .githooks
	@echo "✓ Git hooks enabled (.githooks/pre-commit)"

# ── Tailwind CSS ──────────────────────────────────────

## Build Tailwind CSS (minified output → embedded asset).
## Must cd into ui/ so Tailwind resolves content paths relative to the config file.
css:
	cd ui && ./tailwindcss -i input.css -o ../src/protocol/web/assets/app.css --minify

## Watch mode for local development (auto-rebuilds on template change).
css-watch:
	cd ui && ./tailwindcss -i input.css -o ../src/protocol/web/assets/app.css --watch

## CI gate: rebuild app.css and fail if the working tree drifts.
## Catches the failure mode where templates reference a utility class
## but app.css was last rebuilt before that class was introduced.
css-check: css
	@if git diff --quiet src/protocol/web/assets/app.css; then \
		echo "✓ src/protocol/web/assets/app.css is up to date."; \
	else \
		echo "ERROR: src/protocol/web/assets/app.css is stale. Run 'make css' and commit the result."; \
		git diff --stat src/protocol/web/assets/app.css; \
		exit 1; \
	fi

## Download Tailwind standalone CLI (platform-specific).
tailwind-install:
	@mkdir -p ui
	@OS=$$(uname -s | tr '[:upper:]' '[:lower:]'); \
	ARCH=$$(uname -m); \
	case "$$OS-$$ARCH" in \
		linux-x86_64)  BIN=tailwindcss-linux-x64 ;; \
		linux-aarch64) BIN=tailwindcss-linux-arm64 ;; \
		darwin-x86_64) BIN=tailwindcss-macos-x64 ;; \
		darwin-arm64)  BIN=tailwindcss-macos-arm64 ;; \
		*) echo "Unsupported platform: $$OS-$$ARCH" && exit 1 ;; \
	esac; \
	curl -sLo ui/tailwindcss "https://github.com/tailwindlabs/tailwindcss/releases/download/v3.4.17/$$BIN" && \
	chmod +x ui/tailwindcss && \
	echo "✓ Tailwind CLI installed at ui/tailwindcss ($$BIN)"

# ── Rust ──────────────────────────────────────────────

build: css
	PROTOC=$(PROTOC) cargo build $(CARGO_FLAGS)

## Run every Rust test across both workspace crates (main + simulation)
## via nextest. Doctests are intentionally excluded — Hearth favors
## regular `#[cfg(test)] mod tests` blocks over doctest round-trips:
## same coverage, faster compile, shared helpers, single runner.
## Runnable documentation examples live under `examples/`.
test:
	PROTOC=$(PROTOC) cargo nextest run --workspace $(CARGO_FLAGS)

clippy:
	PROTOC=$(PROTOC) cargo clippy --all-targets $(CARGO_FLAGS) -- -D warnings

fmt:
	cargo fmt --check

## Run all Rust checks (build + clippy + fmt + tests + test-quality guardrail).
check: clippy fmt test-quality test

## Grep-based guardrail against false-confidence test patterns
## (weak is_ok/is_err asserts, unconditional sleeps, untracked #[ignore]).
## See docs/specs/TESTING.md § "Test Quality Anti-Patterns" and HEA-571.
test-quality:
	@bash scripts/check-test-quality.sh

# ── Proto ─────────────────────────────────────────────

## Generate SDK types from .proto files (TypeScript + Go).
proto-gen:
	cd proto && $(BUF) generate

## Lint .proto files against STANDARD rules.
proto-lint:
	cd proto && $(BUF) lint

## Check for backwards-incompatible proto changes vs main.
proto-breaking:
	cd proto && $(BUF) breaking --against '../.git#branch=main,subdir=proto'

## Verify generated SDK code is up-to-date with .proto files.
proto-check:
	@echo "Checking generated code is up-to-date..."
	cd proto && $(BUF) generate
	@if git diff --quiet sdks/typescript/src/generated sdks/go/generated; then \
		echo "Generated code is up-to-date."; \
	else \
		echo "ERROR: Generated code is out of date. Run 'make proto-gen' and commit."; \
		git diff --stat sdks/typescript/src/generated sdks/go/generated; \
		exit 1; \
	fi

# ── SDK Tests ─────────────────────────────────────────

## Run TypeScript and Go SDK integration tests.
sdk-test:
	cd sdks/typescript && PROTOC=$(PROTOC) npm test
	cd sdks/go && PROTOC=$(PROTOC) go test ./...

# ── CI Tiers ──────────────────────────────────────────

## CI fast tier: lint + fmt + proto lint + css freshness + test-quality (every commit).
ci-fast: fmt clippy proto-lint css-check test-quality

## CI benchmark gate: compile and run hot-path perf threshold gates.
##
## Four bench binaries run in sequence; each asserts p50/p99 targets
## before Criterion sampling begins. Non-zero exit fails the Standard CI tier.
##
## rbac_check gates:
##   resolve_permissions p99 ≤ 1 ms
##   hasPermission p99       ≤ 1 µs
##
## storage_gate gates:
##   storage hot-tier lookup   p50 ≤ 10 µs, p99 ≤ 100 µs
##   session lookup by ID      p50 ≤ 10 µs, p99 ≤ 100 µs
##   user lookup by ID         p50 ≤ 20 µs, p99 ≤ 200 µs
##   user lookup by email      p50 ≤ 20 µs, p99 ≤ 200 µs
##
## demotion_latency gates:
##   pre-demotion read p99     ≤ 500 µs
##   during-demotion read p99  ≤ 500 µs
##   post-demotion read p99    ≤ 500 µs
##
## validate_token gates (HEA-739):
##   validate_token latency    p99 ≤ 1 ms  (1×runner headroom over 500 µs production target)
##   validate_token allocs     ≤ 64 allocs/call (regression ceiling)
bench-gate:
	PROTOC=$(PROTOC) cargo bench --bench rbac_check $(CARGO_FLAGS)
	PROTOC=$(PROTOC) cargo bench --bench storage_gate $(CARGO_FLAGS)
	PROTOC=$(PROTOC) cargo bench --bench demotion_latency $(CARGO_FLAGS)
	PROTOC=$(PROTOC) cargo bench --bench validate_token $(CARGO_FLAGS)

## Cluster admin route presence gate: builds the binary, starts it in single-node dev mode,
## and verifies every route documented in docs/guides/clustering.md returns non-404.
## Routes return 503 in single-node mode (expected); 404 means the route is not registered.
cluster-route-check:
	@bash scripts/check-cluster-routes.sh

## CI standard tier: fast + tests + SDK tests + proto breaking + perf gate + cluster route check (merge).
ci-standard: ci-fast test proto-breaking sdk-test proto-check bench-gate cluster-route-check

## Host-side reproduction of PR-blocking CI checks (~5 min cold).
## Mirrors the seven checks that gate every PR: test-quality, check (clippy+fmt+nextest),
## css-check, proto-check, cargo deny, sdk-conformance, and sdk-smoke.
## For full reproduction including workflow files and matrix legs: make ci-local-full
ci-local-fast: ## Run host-side checks that mirror PR-blocking CI (~5 min)
	@echo "==> test-quality"              && $(MAKE) test-quality
	@echo "==> check (clippy + fmt + nextest)" && $(MAKE) check
	@echo "==> css-check"                && $(MAKE) css-check
	@echo "==> proto-check"              && $(MAKE) proto-check
	@echo "==> cargo deny"               && cargo deny check
	@echo "==> sdk-conformance"          && bash scripts/check-sdk-conformance.sh
	@echo "==> sdk-smoke-local"          && $(MAKE) sdk-smoke-local
	@echo ""
	@echo "ci-local-fast OK. For full reproduction (workflow files, toolchain drift),"
	@echo "run: make ci-local-full"

## Full container reproduction of PR-blocking GHA workflows via nektos/act (~10-15 min cold).
## Requires act: brew install act | mise install act | gh extension install nektos/gh-act
## Catches bugs ci-local-fast cannot: workflow-file errors, toolchain drift, missing install steps.
## See CONTRIBUTING.md § "Full container CI reproduction (ci-local-full)" for details.
ci-local-full: ## Run PR-blocking workflows in containers via act (~10-15 min)
	@command -v act >/dev/null || { echo "act not found. Install: 'brew install act' or 'mise install act'"; exit 1; }
	act pull_request \
	  -W .github/workflows/ci.yml \
	  -W .github/workflows/sdk-smoke.yml \
	  --artifact-server-path /tmp/act-artifacts

## Build hearth, boot --dev on a random free port, run TS + Go SDK example
## smoke checks, then tear down. Called by ci-local-fast; safe to run standalone.
sdk-smoke-local: ## Build hearth, boot --dev, run TS + Go SDK examples, tear down
	@bash scripts/sdk-smoke-local.sh

## Run Hearth in local dev mode with persistent storage (./data/dev).
## Data survives restarts. Use `make dev-reset` to wipe it.
## Emails are captured in-process — mailcatcher inbox at http://127.0.0.1:8420/dev/mail
## No Docker required.
dev:
	HEARTH_DEV_DATA_DIR=./data/dev cargo run -- serve --dev

## Wipe the persistent dev data directory (irreversible).
dev-reset:
	rm -rf ./data/dev
	@echo "Dev data wiped. Run make dev for a fresh start."

# ── UI Tests ──────────────────────────────────────────
#
# All ui-test-* targets delegate browser setup to tests/ui/pw-run.sh.
# That script handles cross-platform detection automatically:
#   NixOS   → re-invokes itself inside nix-shell (transparent, no pre-step needed)
#   Debian  → npx playwright install --with-deps chromium
#   macOS   → npx playwright install chromium
# Just run the target — no manual nix-shell entry required.

## Run the full UI test suite: smoke + regression + components + destructive.
## Requires a running dev server (make dev).
## HTML report: tests/ui/reports/html/
ui-test:
	@command -v node >/dev/null 2>&1 || (echo "ERROR: node not found — install Node.js 20+" && exit 1)
	cd tests/ui && npm install
	cd tests/ui && npx wait-on http://127.0.0.1:8420/health --timeout 30000
	bash tests/ui/pw-run.sh test \
		--project=smoke --project=flows --project=regression \
		--project=components --project=destructive --project=accessibility

## Run the Playwright crawler smoke suite against a running dev server.
## Waits up to 30 s for the server, then crawls all nav-reachable pages.
## HTML report: tests/ui/reports/html/   Manifest: tests/ui/reports/crawl-manifest.json
ui-test-smoke:
	@command -v node >/dev/null 2>&1 || (echo "ERROR: node not found — install Node.js 20+" && exit 1)
	cd tests/ui && npm install
	cd tests/ui && npx wait-on http://127.0.0.1:8420/health --timeout 30000
	bash tests/ui/pw-run.sh test --project=smoke

## Diff crawl-manifest.json vs declared GET routes in web/mod.rs.
## Emits reports/coverage-gaps.txt (non-blocking — exits 0 even when gaps exist).
## Requires ui-test-smoke to have run first.
ui-coverage-check:
	cd tests/ui && npx tsx scripts/extract-routes.ts
	cd tests/ui && npx tsx scripts/coverage-check.ts || true

## Run axe-core accessibility audit against a running dev server.
## Critical/serious violations fail the run; minor/moderate are logged as warnings.
## HTML report: tests/ui/reports/html/   Axe JSONs: tests/ui/reports/axe-*.json
ui-test-accessibility:
	@command -v node >/dev/null 2>&1 || (echo "ERROR: node not found — install Node.js 20+" && exit 1)
	cd tests/ui && npm install
	cd tests/ui && npx wait-on http://127.0.0.1:8420/health --timeout 30000
	bash tests/ui/pw-run.sh test --project=accessibility

## Run the exploratory deep crawl (non-blocking) against a running dev server.
## Discovers forms and pagination links; writes reports/deep-crawl-gaps.txt.
ui-test-exploratory:
	@command -v node >/dev/null 2>&1 || (echo "ERROR: node not found — install Node.js 20+" && exit 1)
	cd tests/ui && npm install
	cd tests/ui && npx wait-on http://127.0.0.1:8420/health --timeout 30000
	bash tests/ui/pw-run.sh test --project=exploratory || true

## Run visual regression baselines against a running dev server.
## First run generates snapshots/; subsequent runs diff against them.
## To lock/update baselines: make ui-test-visual UPDATE=1
## HTML report: tests/ui/reports/html/
ui-test-visual:
	@command -v node >/dev/null 2>&1 || (echo "ERROR: node not found — install Node.js 20+" && exit 1)
	cd tests/ui && npm install
	cd tests/ui && npx wait-on http://127.0.0.1:8420/health --timeout 30000
	@if [ "$(UPDATE)" = "1" ]; then \
		bash tests/ui/pw-run.sh test --project=visual --update-snapshots; \
	else \
		bash tests/ui/pw-run.sh test --project=visual; \
	fi

## Run smoke + flows + regression suite against Firefox and WebKit browsers.
## Requires a running dev server. pw-run.sh installs all three browsers platform-aware.
## Note: Firefox/WebKit on NixOS require additional nixpkgs packages beyond shell.nix defaults.
ui-test-cross-browser:
	@command -v node >/dev/null 2>&1 || (echo "ERROR: node not found — install Node.js 20+" && exit 1)
	cd tests/ui && npm install
	cd tests/ui && npx wait-on http://127.0.0.1:8420/health --timeout 30000
	@if command -v apt-get >/dev/null 2>&1; then \
		cd tests/ui && npx playwright install --with-deps chromium firefox webkit; \
	else \
		cd tests/ui && npx playwright install chromium firefox webkit; \
	fi
	bash tests/ui/pw-run.sh test --project=smoke --project=flows --project=regression
