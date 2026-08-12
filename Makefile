# Hearth — Build Targets
# Requires: cargo, cargo-nextest, buf, protoc

PROTOC ?= protoc
CARGO_FLAGS ?=
BUF := buf

.PHONY: setup build test clippy fmt loadtest loadtest-check loadtest-smoke seed check coverage css css-check css-watch tailwind-install openapi openapi-check proto-gen proto-lint proto-format proto-format-check proto-breaking proto-check sdk-test test-quality abuse-check auth-discard-check security-gate notice notice-check ci-fast bench-gate cluster-route-check cluster-smoke ci-standard ci-local-fast ci-local-full sdk-smoke-local dev dev-reset seed-large seed-large-reset ui-test ui-test-smoke ui-coverage-check ui-test-visual ui-test-cross-browser helm-lint helm-template

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

## `make loadtest` — that's the whole contract. Nothing else is required: no
## running server, no bootstrap, no seed, no ARGS, no env vars, no free port.
## It builds a release Hearth, boots a throwaway instance on a free loopback
## port, seeds a deterministic corpus, runs the Goose journeys, writes
## report.json + HTML, and tears the server down.
##
## Optional env-var tuning only (defaults always produce a valid report):
## `make loadtest MODE=ramp`. Optional advanced/attach usage via ARGS invokes
## the binary directly: `make loadtest ARGS="--help"` (see loadtest/README.md).
loadtest:
ifeq ($(strip $(ARGS)),)
	PROTOC=$(PROTOC) loadtest/scripts/run-loadtest.sh
else
	PROTOC=$(PROTOC) cargo run --release --manifest-path loadtest/Cargo.toml $(CARGO_FLAGS) -- $(ARGS)
endif

## Check the loadtest crate: typecheck + unit tests.
## Unit tests cover LoadContext construction and scenario weights — a pure
## cargo check cannot catch runtime "no live tokens" aborts (HEA-1991).
loadtest-check:
	PROTOC=$(PROTOC) cargo check --manifest-path loadtest/Cargo.toml $(CARGO_FLAGS)
	PROTOC=$(PROTOC) cargo nextest run --manifest-path loadtest/Cargo.toml $(CARGO_FLAGS)

## Run a short loadtest smoke against a fresh dev instance (CI gate, HEA-1991).
## Small corpus (500 users total), 20 concurrent Goose users, 15 s — enough to
## prove the harness is alive without taking CI minutes. Corpus knobs keep
## build+seed time short; USERS_PER_REALM=50 keeps the token pool small.
loadtest-smoke:
ifeq ($(strip $(ARGS)),)
	PROTOC=$(PROTOC) USERS=20 RUN_TIME=15s \
	  CORPUS_ACME=200 CORPUS_GLOBEX=150 CORPUS_INITECH=100 CORPUS_UMBRELLA=50 \
	  USERS_PER_REALM=50 SEED_WAIT=120 \
	  loadtest/scripts/run-loadtest.sh
else
	PROTOC=$(PROTOC) cargo run --release --manifest-path loadtest/Cargo.toml $(CARGO_FLAGS) -- $(ARGS)
endif

## Seed a deterministic, parameterized corpus onto a running dev Hearth and
## write a JSON seed-handle (HEA-1789). Requires a dev instance already running
## (`make dev`); pass params via ARGS, e.g.
## `make seed ARGS="--realms 1 --users-per-realm 500 --sessions-frac 0.5"`.
## For a large multi-subject corpus, boot `make seed-large` first, then attach
## with `make seed ARGS="--target-host http://127.0.0.1:8420 ..."`.
## The seed-handle holds live tokens — keep it out of git (loadtest/reports/).
seed:
	PROTOC=$(PROTOC) cargo run --release --manifest-path loadtest/Cargo.toml $(CARGO_FLAGS) -- seed $(ARGS)

## Run test coverage locally (requires cargo-llvm-cov + cargo-nextest).
## Install: cargo install cargo-llvm-cov && rustup component add llvm-tools-preview
## Output: coverage/html/index.html  coverage/lcov.info
coverage:
	mkdir -p coverage
	PROTOC=$(PROTOC) cargo llvm-cov nextest \
		--workspace \
		--ignore-filename-regex 'src/protocol/generated/' \
		--html \
		--output-dir coverage/html \
		--lcov \
		--output-path coverage/lcov.info
	@echo ""
	@echo "✓ HTML report: coverage/html/index.html"
	@echo "✓ LCOV data:   coverage/lcov.info"

fmt:
	cargo fmt --check

## Run all Rust checks (build + clippy + fmt + tests + test-quality guardrail).
check: clippy fmt test-quality test

## Grep-based guardrail against false-confidence test patterns
## (weak is_ok/is_err asserts, unconditional sleeps, untracked #[ignore]).
## See docs/specs/TESTING.md § "Test Quality Anti-Patterns" and HEA-571.
test-quality:
	@bash scripts/check-test-quality.sh

## §3.41 adversarial test-quality gate: every A-N row in the abuse-prevention
## plan (docs/plans/HEA-1114-abuse-prevention.md) must have at least one
## adversarial test in tests/abuse_*.rs that references the row identifier.
## Rollback: set SKIP_ABUSE_COVERAGE_CHECK=1 (see scripts/check-abuse-coverage.sh).
abuse-check:
	@bash scripts/check-abuse-coverage.sh

## Guard: auth results in protocol handler files must never be discarded (HEA-1657).
## Fails on `let _auth`, `let _ = extract_admin_auth(...)`, or unbound auth calls in
## src/protocol/http/admin.rs and src/protocol/grpc/*.rs.
auth-discard-check: ## Lint for discarded authentication results (HEA-1657)
	@bash scripts/check-auth-discard.sh

## Guard: the ROPC (RFC 6749 §4.3) password grant must be absent from both the
## config allowlist (VALID_GRANT_TYPES) and the HTTP token dispatch. Config and
## dispatch drifted apart once already — see HEA-1862.
security-gate: ## Assert the ROPC password grant is unreachable (HEA-1814/1816/1862)
	@bash scripts/check-ropc-ban.sh

## Guard: RBAC-graph mutations in src/rbac/engine.rs must route through the
## invalidating write_* helpers so the resolution decision cache is bumped
## (HEA-1781, follow-up to HEA-1777). A raw self.storage.put/delete call would
## leave a stale cached resolution live — a privilege-escalation bug.
rbac-storage-check: ## Lint for un-invalidating RBAC storage writes (HEA-1781)
	@bash scripts/check-rbac-storage-writes.sh

# ── Proto ─────────────────────────────────────────────

## Generate SDK types from .proto files (TypeScript + Go).
proto-gen:
	cd proto && $(BUF) generate

## Lint .proto files against STANDARD rules.
proto-lint:
	cd proto && $(BUF) lint

## Format .proto files in-place (run before committing).
proto-format:
	cd proto && $(BUF) format -w

## Check proto formatting without modifying files (CI gate).
proto-format-check:
	cd proto && $(BUF) format --diff --exit-code

## Check for backwards-incompatible proto changes vs main.
proto-breaking:
	cd proto && $(BUF) breaking --against '../.git#branch=origin/main,subdir=proto'

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

# ── OpenAPI ───────────────────────────────────────────

## (Re)generate docs/api/openapi.json from proto-derived + supplement sources.
## Requires: python3 + PyYAML.  On Nix machines it finds pyyaml from the store;
## elsewhere it installs it via pip (quiet, user-level).
openapi:
	@python3 -c "import yaml" 2>/dev/null \
	  || nix-shell -p python3Packages.pyyaml --run true 2>/dev/null \
	  || pip3 install --user --quiet pyyaml
	@if command -v nix-shell >/dev/null 2>&1 && ! python3 -c "import yaml" 2>/dev/null; then \
		nix-shell -p python3Packages.pyyaml --run "python3 scripts/merge_openapi.py"; \
	else \
		python3 scripts/merge_openapi.py; \
	fi

## CI gate: regenerate and fail if docs/api/openapi.json is stale.
openapi-check: openapi
	@if git diff --quiet docs/api/openapi.json; then \
		echo "✓ docs/api/openapi.json is up to date."; \
	else \
		echo "ERROR: docs/api/openapi.json is stale. Run 'make openapi' and commit the result."; \
		git diff --stat docs/api/openapi.json; \
		exit 1; \
	fi

# ── License Attribution ───────────────────────────────

## Regenerate THIRD_PARTY_LICENSES from the current Cargo.lock (requires cargo-about).
## Also updates THIRD_PARTY_LICENSES.sha256 for the staleness check.
## Run after any dependency update: `cargo update && make notice`.
notice:
	@command -v cargo-about >/dev/null 2>&1 || cargo install cargo-about --features cli
	cargo about generate about.hbs -o THIRD_PARTY_LICENSES
	sha256sum Cargo.lock > THIRD_PARTY_LICENSES.sha256
	@echo "✓ THIRD_PARTY_LICENSES regenerated. Commit both files if the tree changed."

## CI gate: fail if THIRD_PARTY_LICENSES is stale relative to Cargo.lock.
## Does not regenerate — just checks the stored sha256 fingerprint.
notice-check:
	@if [ ! -f THIRD_PARTY_LICENSES ]; then \
		echo "ERROR: THIRD_PARTY_LICENSES missing. Run 'make notice' and commit."; \
		exit 1; \
	fi
	@if [ ! -f THIRD_PARTY_LICENSES.sha256 ]; then \
		echo "ERROR: THIRD_PARTY_LICENSES.sha256 missing. Run 'make notice' and commit."; \
		exit 1; \
	fi
	@STORED=$$(awk '{print $$1}' THIRD_PARTY_LICENSES.sha256); \
	CURRENT=$$(sha256sum Cargo.lock | awk '{print $$1}'); \
	if [ "$$STORED" != "$$CURRENT" ]; then \
		echo "ERROR: THIRD_PARTY_LICENSES is stale (Cargo.lock changed). Run 'make notice' and commit."; \
		exit 1; \
	fi
	@echo "✓ THIRD_PARTY_LICENSES is up to date."

# ── SDK Tests ─────────────────────────────────────────

## Run TypeScript and Go SDK integration tests.
sdk-test:
	cd sdks/typescript && PROTOC=$(PROTOC) npm test
	cd sdks/go && PROTOC=$(PROTOC) go test ./...

# ── CI Tiers ──────────────────────────────────────────

## CI fast tier: lint + fmt + proto lint + css freshness + test-quality + §3.41 abuse gate (every commit).
ci-fast: fmt clippy proto-lint css-check test-quality abuse-check security-gate

## CI benchmark gate: compile and run hot-path perf threshold gates.
##
## Five bench binaries run in sequence; each asserts p50/p99 and (where
## applicable) per-call allocation targets before Criterion sampling begins.
## Non-zero exit fails the Standard CI tier. Together they lock the §2 Big-O
## endpoint baseline (E1/E2/E7) in CI so hot-path regressions are caught
## automatically (HEA-1776).
##
## rbac_check gates (E7):
##   resolve_permissions p99 ≤ 1 ms
##   hasPermission p99       ≤ 1 µs
##   hasPermission allocs    ≤ 0 allocs/call (zero-alloc proof)
##
## session_lookup gates (E2, HEA-1776):
##   session lookup p99      ≤ 1 ms  (1×runner headroom over 100 µs prod target)
##   session lookup allocs   ≤ 0 allocs/call (warm-path zero-alloc proof)
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
	PROTOC=$(PROTOC) cargo bench --bench session_lookup $(CARGO_FLAGS)
	PROTOC=$(PROTOC) cargo bench --bench storage_gate $(CARGO_FLAGS)
	PROTOC=$(PROTOC) cargo bench --bench demotion_latency $(CARGO_FLAGS)
	PROTOC=$(PROTOC) cargo bench --bench validate_token $(CARGO_FLAGS)

## Cluster admin route presence gate: builds the binary, starts it in single-node dev mode,
## and verifies every route documented in docs/guides/clustering.md returns non-404.
## Routes return 503 in single-node mode (expected); 404 means the route is not registered.
cluster-route-check:
	@bash scripts/check-cluster-routes.sh

## Raft cluster operational smoke test + chaos validation (Gap C-1, HEA-1323).
##
## Runs the full in-process cluster simulation suite:
##   - AC-1: network partition and convergence
##   - AC-2: leader kill and re-election
##   - AC-3: rolling restart with zero read errors
##   - AC-4: snapshot catch-up for a cold follower
##   - AC-5: leader kill mid-write-sequence (committed writes never lost)
##   - AC-6: WAL replay after node crash
##   - AC-7: write contention across two sequential leadership changes
##
## All tests run in-process (no real ports, no TLS). Exit 1 if any scenario fails.
## Estimated runtime: ~60 s on a laptop (election timeouts dominate).
cluster-smoke:
	PROTOC=$(PROTOC) cargo nextest run --package hearth-simulation --test-threads=1 $(CARGO_FLAGS) -E 'test(~simulation)'

## CI standard tier: fast + tests + SDK tests + proto breaking + perf gate + cluster route check (merge).
ci-standard: ci-fast test proto-breaking sdk-test proto-check bench-gate cluster-route-check

## Host-side reproduction of PR-blocking CI checks (~5 min cold).
## Mirrors the seven checks that gate every PR: test-quality, check (clippy+fmt+nextest),
## css-check, proto-check, cargo deny, sdk-conformance, and sdk-smoke.
## For full reproduction including workflow files and matrix legs: make ci-local-full
ci-local-fast: ## Run host-side checks that mirror PR-blocking CI (~5 min)
	@echo "==> test-quality"              && $(MAKE) test-quality
	@echo "==> abuse-check (§3.41)"       && $(MAKE) abuse-check
	@echo "==> auth-discard-check (HEA-1657)" && $(MAKE) auth-discard-check
	@echo "==> rbac-storage-check (HEA-1781)" && $(MAKE) rbac-storage-check
	@echo "==> check (clippy + fmt + nextest)" && $(MAKE) check
	@echo "==> css-check"                && $(MAKE) css-check
	@echo "==> proto-check"              && $(MAKE) proto-check
	@echo "==> notice-check"             && $(MAKE) notice-check
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
	@command -v gh >/dev/null || { echo "gh CLI not found. Install: https://cli.github.com"; exit 1; }
	@gh extension list 2>/dev/null | grep -q 'nektos/gh-act' || { echo "gh-act extension not found. Install: 'gh extension install nektos/gh-act'"; exit 1; }
	gh act pull_request \
	  --verbose \
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

## Seed a large multi-realm demo instance into ./data/demo, then serve it.
## Realms, roles, groups, OAuth clients, and per-realm user counts all come
## from examples/large-scale-demo/hearth.yaml (gated by `demo.enabled: true`).
## First run seeds millions of users (use --release; takes a while); later runs
## are instant thanks to a per-realm sentinel. Browse at http://127.0.0.1:8420
## and log in as user0000001@acme.demo / DemoPassw0rd!
seed-large:
	HEARTH_DEV_DATA_DIR=./data/demo cargo run --release -- serve --dev \
		--config examples/large-scale-demo/hearth.yaml

## Wipe the large demo data directory (forces a fresh re-seed).
seed-large-reset:
	rm -rf ./data/demo
	@echo "Demo data wiped. Run make seed-large to re-seed."

# ── Helm ──────────────────────────────────────────────

HELM ?= helm
HELM_CHART := deploy/helm/hearth

## Lint the Hearth Helm chart. Exits non-zero on any warning or error.
helm-lint:
	@command -v $(HELM) >/dev/null 2>&1 || (echo "ERROR: helm not found — install Helm 3.10+ (https://helm.sh/docs/intro/install/)" && exit 1)
	$(HELM) lint $(HELM_CHART)

## Render Helm templates and diff against committed snapshots.
## Fails if rendered output differs from deploy/helm/hearth/tests/*.yaml.
## To update snapshots after intentional chart changes: make helm-template UPDATE=1
helm-template:
	@command -v $(HELM) >/dev/null 2>&1 || (echo "ERROR: helm not found — install Helm 3.10+ (https://helm.sh/docs/intro/install/)" && exit 1)
	@if [ "$(UPDATE)" = "1" ]; then \
		echo "Updating Helm snapshots..."; \
		$(HELM) template hearth $(HELM_CHART) --namespace hearth \
			> $(HELM_CHART)/tests/default.yaml; \
		$(HELM) template hearth $(HELM_CHART) -f $(HELM_CHART)/values-prod.yaml --namespace hearth \
			> $(HELM_CHART)/tests/prod.yaml; \
		echo "✓ Snapshots updated: $(HELM_CHART)/tests/"; \
	else \
		tmp_dir=$$(mktemp -d); \
		$(HELM) template hearth $(HELM_CHART) --namespace hearth \
			> $$tmp_dir/default.yaml; \
		$(HELM) template hearth $(HELM_CHART) -f $(HELM_CHART)/values-prod.yaml --namespace hearth \
			> $$tmp_dir/prod.yaml; \
		diff $(HELM_CHART)/tests/default.yaml $$tmp_dir/default.yaml \
			|| (echo "ERROR: default.yaml snapshot drift. Run: make helm-template UPDATE=1" && rm -rf $$tmp_dir && exit 1); \
		diff $(HELM_CHART)/tests/prod.yaml $$tmp_dir/prod.yaml \
			|| (echo "ERROR: prod.yaml snapshot drift. Run: make helm-template UPDATE=1" && rm -rf $$tmp_dir && exit 1); \
		rm -rf $$tmp_dir; \
		echo "✓ Helm snapshots match."; \
	fi
	@echo "Checking single-writer guard (replicaCount > 1 must fail to render)..."
	@if $(HELM) template hearth $(HELM_CHART) --set replicaCount=2 --namespace hearth >/dev/null 2>&1; then \
		echo "ERROR: chart rendered with replicaCount=2. Hearth is single-writer (exclusive"; \
		echo "       data_dir lock, HEA-2107) — a second replica on the ReadWriteOnce PVC"; \
		echo "       crash-loops with AlreadyLocked. Restore the guard in templates/deployment.yaml."; \
		exit 1; \
	fi
	@echo "✓ replicaCount > 1 is rejected at render time."

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
