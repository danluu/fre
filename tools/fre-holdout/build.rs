use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};
#[cfg(unix)]
use std::{ffi::OsString, os::unix::ffi::OsStringExt};

use sha2::{Digest, Sha256};

fn main() {
    let manifest = env::var("CARGO_MANIFEST_DIR").expect("Cargo sets CARGO_MANIFEST_DIR");
    let workspace = Path::new(&manifest)
        .parent()
        .and_then(Path::parent)
        .expect("fre-holdout is two directories below its workspace");
    emit_source_rerun_dependencies(workspace);
    let source_commit = command(workspace, "git", &["rev-parse", "HEAD"]);
    let snapshot = source_snapshot(workspace);
    let source_tree = if snapshot.status.is_empty() {
        "clean"
    } else {
        "dirty"
    };
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let rustc_version = command(workspace, &rustc, &["--version"]);
    emit("SOURCE_COMMIT", &source_commit);
    emit("SOURCE_TREE", source_tree);
    emit("SOURCE_STATUS_SHA256", &sha256(&snapshot.status));
    emit("SOURCE_DIFF_SHA256", &sha256(&snapshot.diff));
    emit("SOURCE_UNTRACKED_SHA256", &sha256(&snapshot.untracked));
    emit(
        "BUILD_PROFILE",
        &env::var("PROFILE").unwrap_or_else(|_| "unknown".to_string()),
    );
    emit(
        "BUILD_TARGET",
        &env::var("TARGET").unwrap_or_else(|_| "unknown".to_string()),
    );
    emit(
        "BUILD_HOST",
        &env::var("HOST").unwrap_or_else(|_| "unknown".to_string()),
    );
    emit("RUSTC_VERSION", &rustc_version);
}

struct SourceSnapshot {
    status: Vec<u8>,
    diff: Vec<u8>,
    untracked: Vec<u8>,
}

/// Capture the exact dirty patch compiled into the executable. The status,
/// tracked binary diff, and path/content-framed untracked source are kept
/// separate so a later dirty patch with the same clean/dirty disposition
/// cannot be mistaken for the build input.
fn source_snapshot(workspace: &Path) -> SourceSnapshot {
    SourceSnapshot {
        status: checked_command_bytes(
            workspace,
            "git",
            &["status", "--porcelain=v1", "--untracked-files=all"],
        ),
        diff: checked_command_bytes(
            workspace,
            "git",
            &["diff", "--no-ext-diff", "--no-textconv", "--binary", "HEAD"],
        ),
        untracked: untracked_source(workspace),
    }
}

#[allow(
    clippy::unnecessary_debug_formatting,
    reason = "debug formatting preserves evidence about non-UTF-8 path bytes on a fatal read error"
)]
fn untracked_source(workspace: &Path) -> Vec<u8> {
    let paths = checked_command_bytes(
        workspace,
        "git",
        &["ls-files", "-z", "--others", "--exclude-standard"],
    );
    let mut output = b"\0FRE-UNTRACKED-SOURCE-V1\0".to_vec();
    for path in paths
        .split(|&byte| byte == 0)
        .filter(|path| !path.is_empty())
    {
        output.extend_from_slice(&u64::try_from(path.len()).unwrap_or(u64::MAX).to_le_bytes());
        output.extend_from_slice(path);
        let relative = git_relative_path(path);
        let bytes = fs::read(workspace.join(&relative)).unwrap_or_else(|error| {
            panic!(
                "read untracked source path {:?}: {error}",
                relative.as_os_str()
            )
        });
        output.extend_from_slice(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
        output.extend_from_slice(&bytes);
    }
    output
}

#[cfg(unix)]
fn git_relative_path(path: &[u8]) -> PathBuf {
    PathBuf::from(OsString::from_vec(path.to_vec()))
}

#[cfg(not(unix))]
fn git_relative_path(path: &[u8]) -> PathBuf {
    let path = std::str::from_utf8(path).unwrap_or_else(|error| {
        panic!("Git returned a non-UTF-8 untracked path on this platform: {error}")
    });
    PathBuf::from(path)
}

fn checked_command_bytes(directory: &Path, program: &str, arguments: &[&str]) -> Vec<u8> {
    let output = Command::new(program)
        .args(arguments)
        .current_dir(directory)
        .output()
        .unwrap_or_else(|error| panic!("launch {program} {arguments:?}: {error}"));
    assert!(
        output.status.success(),
        "{program} {arguments:?} failed: status={}, stderr_bytes={}, stderr_sha256={}",
        output.status,
        output.stderr.len(),
        sha256(&output.stderr)
    );
    output.stdout
}

fn sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Make the embedded commit and build-tree disposition follow both ordinary
/// repositories and linked Git worktrees. In a linked worktree, `HEAD` and
/// `index` live in the per-worktree gitdir while the resolved branch ref and
/// `packed-refs` live in the common gitdir.
fn emit_source_rerun_dependencies(workspace: &Path) {
    for relative in [
        ".cargo",
        ".gitignore",
        "Cargo.toml",
        "Cargo.lock",
        "README.md",
        "WORLD_FASTEST_REGEX_DESIGN.md",
        "crates",
        "docs",
        "gates",
        "notes",
        "research",
        "rust-toolchain.toml",
        "rustfmt.toml",
        "scripts",
        "tools",
    ] {
        rerun_if_changed(&workspace.join(relative));
    }

    let Some(git_dir) = git_path(workspace, &["rev-parse", "--absolute-git-dir"]) else {
        return;
    };
    let Some(common_dir) = git_path(workspace, &["rev-parse", "--git-common-dir"]) else {
        return;
    };
    let common_dir = if common_dir.is_absolute() {
        common_dir
    } else {
        workspace.join(common_dir)
    };

    let head = git_dir.join("HEAD");
    rerun_if_changed(&head);
    rerun_if_changed(&git_dir.join("index"));
    rerun_if_changed(&git_dir.join("commondir"));
    rerun_if_changed(&common_dir.join("packed-refs"));
    if let Ok(contents) = fs::read_to_string(&head)
        && let Some(reference) = contents.trim().strip_prefix("ref: ")
    {
        rerun_if_changed(&common_dir.join(reference));
    }
}

fn git_path(workspace: &Path, arguments: &[&str]) -> Option<PathBuf> {
    let output = Command::new("git")
        .args(arguments)
        .current_dir(workspace)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8(output.stdout).ok()?;
    let path = path.trim();
    (!path.is_empty()).then(|| PathBuf::from(path))
}

fn rerun_if_changed(path: &Path) {
    println!("cargo:rerun-if-changed={}", path.display());
}

fn command(directory: &Path, program: &str, arguments: &[&str]) -> String {
    match Command::new(program)
        .args(arguments)
        .current_dir(directory)
        .output()
    {
        Ok(output) if output.status.success() => String::from_utf8(output.stdout)
            .unwrap_or_else(|error| panic!("{program} returned non-UTF-8 text: {error}"))
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" "),
        Ok(output) => format!("unavailable-status-{}", output.status),
        Err(error) => format!("unavailable-error-{error}"),
    }
}

fn emit(name: &str, value: &str) {
    println!("cargo:rustc-env=FRE_HOLDOUT_{name}={value}");
}
