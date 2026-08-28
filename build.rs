use std::path::PathBuf;
use std::process::Command;

const GENERATED_DIR: &str = "src/protocol/generated";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Version stamping — three-tier resolution (first match wins):
    //
    //   1. HEARTH_RELEASE_VERSION env var — set by release.yml from the git tag
    //      (e.g. HEARTH_RELEASE_VERSION=1.6.9).  Used for official release builds.
    //
    //   2. `git describe --tags` — used for source/dev builds from a checkout that
    //      has tags (e.g. full-history clone).  CI's quality job uses fetch-depth: 0
    //      so this resolves in every `cargo nextest run` run there.  Output is either
    //      "1.6.9" (clean tag) or "1.6.9-3-gabcde12" (commits ahead of tag).
    //
    //   3. Cargo.toml `version` field — last resort for shallow clones or offline
    //      builds.  Must be kept close to the latest release so it is a useful
    //      approximation rather than a stale placeholder.  Update it when cutting a
    //      release (the .releaserc.json prepareCmd edits it during semantic-release,
    //      but without @semantic-release/git the change is never committed back — so
    //      it must also be updated manually as a release-checklist step).
    //
    // Tradeoff: tier 2 requires `git` on PATH and tags reachable from HEAD.
    // Tier 1 is the only path that guarantees an exact match in every environment.
    if let Ok(v) = std::env::var("HEARTH_RELEASE_VERSION") {
        println!("cargo:rustc-env=CARGO_PKG_VERSION={v}");
    } else if let Some(v) = git_describe_version() {
        println!("cargo:rustc-env=CARGO_PKG_VERSION={v}");
    }
    println!("cargo:rerun-if-env-changed=HEARTH_RELEASE_VERSION");
    // Rebuild when the checked-out tag or HEAD changes so `git describe` stays current.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/tags");
    println!("cargo:rerun-if-changed=.git/packed-refs");

    compile_tailwind_if_available();

    // When SKIP_PROTO_BUILD is set, skip protoc and pbjson.  The generated
    // Rust files in src/protocol/generated/ are used directly by include!().
    if std::env::var("SKIP_PROTO_BUILD").is_ok() {
        println!(
            "cargo:warning=SKIP_PROTO_BUILD set — using checked-in generated files in src/protocol/generated/"
        );
        println!("cargo:rerun-if-changed=proto/");
        println!("cargo:rerun-if-changed=build.rs");
        return Ok(());
    }

    let proto_dir = PathBuf::from("proto");
    let protos = &[
        "proto/hearth/identity/v1/identity.proto",
        "proto/hearth/identity/v1/oauth.proto",
        "proto/hearth/rbac/v1/rbac.proto",
        "proto/hearth/events/v1/audit.proto",
    ];

    // Generated Rust lives under src/ so IDEs (RustRover, VS Code, Zed) can
    // statically index it. The files are gitignored; `cargo build` is the
    // source of truth for generation.
    let generated = PathBuf::from(GENERATED_DIR);
    std::fs::create_dir_all(&generated)?;

    // File descriptor set is consumed by both pbjson (for JSON codec) and
    // tonic-reflection (for runtime service discovery), so we write it into
    // the generated dir as a checked-in-but-gitignored artifact. It also
    // stays in OUT_DIR for pbjson-build.
    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    let descriptor_path = out_dir.join("proto_descriptor.bin");
    let reflection_descriptor_path = generated.join("proto_descriptor.bin");

    // Compile proto files with tonic_build (wraps prost). Emits both message
    // types and service traits/clients. The file descriptor set is shared
    // with pbjson below.
    let proto_dir_str = proto_dir.to_str().expect("proto dir is valid UTF-8");
    let mut includes: Vec<String> = vec![proto_dir_str.to_string()];

    // Include googleapis protos (needed for google.api.http annotations).
    // Accept colon-separated overrides via PROTOC_INCLUDE, then fall back to
    // the buf module cache at ~/.cache/buf/v3/modules/.
    if let Ok(extra) = std::env::var("PROTOC_INCLUDE") {
        for p in extra.split(':').filter(|s| !s.is_empty()) {
            includes.push(p.to_string());
        }
    } else {
        if let Some(path) = find_googleapis_in_buf_cache() {
            includes.push(path);
        }
        // Also include standard protobuf WKT (google/protobuf/descriptor.proto etc.).
        // Some protoc binaries (statically-linked, Nix-packaged) don't bundle these.
        if let Some(wkt) = find_protobuf_wkt_includes() {
            includes.push(wkt);
        }
    }

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir(&generated)
        .file_descriptor_set_path(&descriptor_path)
        .compile_protos(
            protos,
            includes
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice(),
        )?;

    // Duplicate the descriptor set into the generated dir so tonic-reflection
    // can `include_bytes!` it at compile time without relying on OUT_DIR
    // layout leaking into source code.
    std::fs::copy(&descriptor_path, &reflection_descriptor_path)?;

    // Generate serde (JSON) implementations from the descriptor set.
    let descriptor_set = std::fs::read(&descriptor_path)?;
    pbjson_build::Builder::new()
        .register_descriptors(&descriptor_set)?
        .preserve_proto_field_names()
        .out_dir(&generated)
        .build(&[
            ".hearth.identity.v1",
            ".hearth.rbac.v1",
            ".hearth.events.v1",
        ])?;

    // Re-run build if any proto file changes.
    println!("cargo:rerun-if-changed=proto/");
    println!("cargo:rerun-if-changed=build.rs");
    Ok(())
}

/// Returns the version from `git describe --tags --match 'v[0-9]*'`,
/// stripping the leading "v".
///
/// Returns `None` if git is unavailable, the repo has no matching tags, or
/// the output does not start with `v` followed by a digit (e.g. a bare commit
/// SHA from `--always` with no reachable tags).
fn git_describe_version() -> Option<String> {
    let output = Command::new("git")
        .args(["describe", "--tags", "--match", "v[0-9]*", "--always"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw = String::from_utf8(output.stdout).ok()?;
    let s = raw.trim();
    // A plain commit SHA (40 hex chars) starts with a hex digit but not "v";
    // reject it so we don't stamp a commit hash as the version string.
    if s.starts_with('v') && s[1..].starts_with(|c: char| c.is_ascii_digit()) {
        Some(s[1..].to_string())
    } else {
        None
    }
}

/// Finds the standard protobuf WKT include directory.
///
/// `google/protobuf/descriptor.proto` is required by `google/api/annotations.proto`.
/// Some protoc binaries (statically-linked, Nix-packaged) do not bundle these, so
/// we search for them in common system and Nix-store locations.
fn find_protobuf_wkt_includes() -> Option<String> {
    // Explicit env override takes priority.
    if let Ok(p) = std::env::var("PROTOBUF_INCLUDE") {
        let candidate = PathBuf::from(&p);
        if candidate.join("google/protobuf/descriptor.proto").exists() {
            return Some(p);
        }
    }

    // Search Nix store — any versioned protobuf package has `include/`.
    if let Ok(entries) = std::fs::read_dir("/nix/store") {
        let mut candidates: Vec<PathBuf> = entries
            .flatten()
            .filter_map(|e| {
                let name = e.file_name();
                let n = name.to_string_lossy();
                if n.contains("protobuf-") && !n.contains("protobuf-c") {
                    let p = e.path().join("include");
                    if p.join("google/protobuf/descriptor.proto").exists() {
                        return Some(p);
                    }
                }
                None
            })
            .collect();
        // Prefer highest version number (last lexicographically among vNN.M paths).
        candidates.sort();
        if let Some(best) = candidates.last() {
            if let Some(s) = best.to_str() {
                return Some(s.to_string());
            }
        }
    }

    // Fall back to common Unix system paths.
    for dir in &["/usr/include", "/usr/local/include"] {
        let p = PathBuf::from(dir);
        if p.join("google/protobuf/descriptor.proto").exists() {
            if let Some(s) = p.to_str() {
                return Some(s.to_string());
            }
        }
    }

    None
}

/// Finds the googleapis proto include directory from buf's module cache.
///
/// Buf caches remote modules under `~/.cache/buf/v3/modules/`. The googleapis
/// module lives under `buf.build/googleapis/googleapis/<digest>/files`. We
/// scan for a digest directory that contains `google/api/annotations.proto`.
fn find_googleapis_in_buf_cache() -> Option<String> {
    let home = std::env::var("HOME").ok()?;
    let base = PathBuf::from(home).join(".cache/buf/v3/modules");
    // Walk two levels of hash-bucketed directories to find the googleapis module.
    for bucket in std::fs::read_dir(&base).ok()?.flatten() {
        let googleapis_dir = bucket.path().join("buf.build/googleapis/googleapis");
        if !googleapis_dir.is_dir() {
            continue;
        }
        for digest in std::fs::read_dir(&googleapis_dir).ok()?.flatten() {
            let files_dir = digest.path().join("files");
            if files_dir.join("google/api/annotations.proto").exists() {
                if let Some(s) = files_dir.to_str() {
                    return Some(s.to_string());
                }
            }
        }
    }
    None
}

/// Compiles `ui/input.css` → `src/protocol/web/assets/app.css` when the
/// Tailwind CLI shim is present. No-op on fresh clones without the CLI, so
/// `cargo build` still works for anyone who just wants the server binary —
/// the checked-in `app.css` is used as-is. Emits `rerun-if-changed` markers
/// so an edit to `input.css`, the Tailwind config, or any template triggers
/// a rebuild of the stylesheet on the next `cargo build`.
fn compile_tailwind_if_available() {
    // Always watch these paths — whether or not the CLI exists today, we want
    // the next build to pick up changes if the CLI is added later.
    println!("cargo:rerun-if-changed=ui/input.css");
    println!("cargo:rerun-if-changed=ui/tailwind.config.js");
    println!("cargo:rerun-if-changed=templates");

    let cli = PathBuf::from("ui/tailwindcss");
    if !cli.exists() {
        println!(
            "cargo:warning=ui/tailwindcss not found — skipping Tailwind build. \
             Using checked-in src/protocol/web/assets/app.css."
        );
        return;
    }

    let output = Command::new("./tailwindcss")
        .current_dir("ui")
        .args([
            "-i",
            "input.css",
            "-o",
            "../src/protocol/web/assets/app.css",
            "--minify",
        ])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            println!("cargo:warning=Tailwind CSS rebuilt");
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            println!(
                "cargo:warning=Tailwind build exited with {} — continuing with existing app.css. stderr: {}",
                out.status, stderr
            );
        }
        Err(e) => {
            println!(
                "cargo:warning=failed to invoke ui/tailwindcss ({e}) — continuing with existing app.css"
            );
        }
    }
}
