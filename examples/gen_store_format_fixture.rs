//! Writes the store-format fixture (#646) into `tests/fixtures/store-format/`.
//!
//! Run it with `scripts/regen-store-format-fixture.sh`, and only together with
//! a bump of `hearth::storage::format::STORE_FORMAT_VERSION`.

#[path = "../tests/store_format/fixture.rs"]
mod fixture;

use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = Path::new(env!("CARGO_MANIFEST_DIR")).join(fixture::FIXTURE_DIR);
    if out.exists() {
        std::fs::remove_dir_all(&out)?;
    }
    let manifest = fixture::generate(&out)?;
    // The lock file is created at each open; the fixture does not need it.
    let _ = std::fs::remove_file(out.join("LOCK"));
    std::fs::write(
        out.join(fixture::MANIFEST_FILE),
        serde_json::to_string_pretty(&manifest)? + "\n",
    )?;
    Ok(())
}
