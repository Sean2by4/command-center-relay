use std::process::Command;

/// Embed the git short sha so `/health` reports what is actually running.
/// `CARGO_PKG_VERSION` alone sat at "0.1.0" for every deploy, which made
/// version skew (the 2026-08-25 standalone-flag incident) unverifiable from
/// the outside. Falls back to "unknown" outside a git checkout (e.g. a source
/// tarball build) rather than failing the build.
fn main() {
    let sha = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=GIT_SHA={sha}");
    // Re-run when HEAD moves so the sha never goes stale in an incremental build.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");
}
