## CLI Commands & Flags

Binary: `hearth` (`#[command(name = "hearth", version, about)]`, `src/main.rs:40-45`). Top-level subcommands enum `Commands` at `src/main.rs:48-122`.

| Command/Subcommand | Flags/Args | File:line | Purpose |
|--------------------|-----------|-----------|---------|
| `serve` | `--dev` (**dev-only**), `--config/-c <path>`, `--port <u16>`, `--bind <str>`, `--verbose/-v`, `--allow-reflection-in-prod` (**dev/debug-only**) | src/main.rs:51-83 | Start the Hearth identity server. `--dev` = in-memory storage, relaxed security, debug logging, mailcatcher. `--allow-reflection-in-prod` forces gRPC reflection on in prod (A-43) — never for real deployments |
| `realm` | subcommand `RealmAction` | src/main.rs:85-88 | Manage realms |
| `realm create` | (none) | src/main.rs:278-281 | Create a new realm (generates a UUID) |
| `app` | subcommand `AppAction` | src/main.rs:90-93 | Manage OAuth 2.0 applications (clients) |
| `app create` | `--server <url>`, `--realm-id <str>`, `--name <str>`, `--redirect-uri <str>`, `--token <str>` | src/main.rs:363-388 | Register a new OAuth 2.0 client against a running server. `--token` is a privileged admin bearer token (`hearth.clients.admin`/`hearth.admin`) |
| `migrate` | subcommand `MigrateSource` | src/main.rs:95-98 | Import data from another identity provider |
| `migrate keycloak` | `--file <path>`, `--data-dir <path>`, `--realm <str>`, `--dry-run` | src/main.rs:207-229 | Import a Keycloak realm export (JSON) |
| `migrate auth0` | `--file <path>`, `--data-dir <path>`, `--realm <str>`, `--dry-run` | src/main.rs:234-255 | Import an Auth0 tenant bundle (JSON) |
| `migrate rotate-pepper` | `--data-dir <path>`, `--summary-only` | src/main.rs:265-273 | Audit credentials needing Argon2 pepper rotation. Exit 0/1/2 |
| `config` | subcommand `ConfigAction` | src/main.rs:100-103 | Configuration management |
| `config reload` | `--url <str>`, `--pid-file <path>` | src/main.rs:290-301 | Hot-reload config via SIGHUP (PID file) or POST /admin/api/config/reload (`--url`) |
| `config validate` | `<file>` positional (default `hearth.yaml`) | src/main.rs:307-311 | Validate a config file without starting the server. Exit 1 on error |
| `config example` | `--output/-o <path>` | src/main.rs:317-321 | Print annotated example hearth.yaml to stdout or `--output` |
| `rbac` | subcommand `RbacAction` | src/main.rs:105-108 | RBAC maintenance |
| `rbac orphans` | subcommand `OrphansAction` | src/main.rs:329-332 | List/purge orphaned runtime references |
| `rbac orphans list` | `--realm <str>`, `--data-dir <path>` (default `data`) | src/main.rs:339-346 | List orphaned references across realms |
| `rbac orphans purge` | `--realm <str>`, `--data-dir <path>` (default `data`), `--dry-run` | src/main.rs:348-358 | Purge orphaned references |
| `backup` | subcommand `BackupAction` | src/main.rs:110-113 | Create, restore, and inspect backup archives |
| `backup create` | `--output/-o <path>`, `--realm <str>`, `--include-audit`, `--encrypt`, `--data-dir <path>` (default `data`) | src/main.rs:128-157 | Export realm data to `.hearth-backup`. `--encrypt` = passphrase-wrapped DEK (Argon2id/AES-256-GCM) |
| `backup restore` | `--input/-i <path>`, `--realm <str>`, `--mode <str>` (default `skip`), `--dry-run`, `--data-dir <path>` (default `data`) | src/main.rs:159-185 | Restore from archive. Modes: skip/overwrite/merge |
| `backup verify` | `--input/-i <path>` | src/main.rs:189-193 | Recompute SHA-256 checksums. Exit 0/3 |
| `backup inspect` | `--input/-i <path>` | src/main.rs:197-201 | Print archive manifest as a table |
| `completions` | `<shell>` positional (`clap_complete::Shell`) | src/main.rs:118-121 | Print a shell completion script to stdout |

### Notes
- **Dev-only flags:** `serve --dev` (in-memory, relaxed security, debug logging, auto-mailcatcher). `serve --allow-reflection-in-prod` is a dev/debug escape hatch that permits gRPC reflection in production mode (A-43) — explicitly documented "never enable in real deployments."
- No `--admin-token` flag exists on this binary; privileged operations use `app create --token`. (`--admin-token` referenced in the task lives in the seed/loadtest tooling, not `src/main.rs`.)
- No hidden (`#[arg(hide = true)]`) flags found in `src/main.rs`.
