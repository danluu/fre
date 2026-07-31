use std::{
    env, fs, io,
    os::unix::ffi::OsStrExt as _,
    os::unix::fs::PermissionsExt as _,
    path::{Component, Path, PathBuf},
};

use sha2::{Digest as _, Sha256};

const SOURCE_SET_DOMAIN: &[u8] = b"FRE-V26-EVIDENCE-FULL-REPOSITORY-SOURCE-SET\0\x01";

fn repository_root(manifest_directory: &Path) -> io::Result<PathBuf> {
    for ancestor in manifest_directory.ancestors() {
        if ancestor.join("crates/fre-jit-aarch64/Cargo.toml").is_file()
            && ancestor
                .join("research/aot/search-v26-width-cost-rule-r1/synthetic-runner/Cargo.toml")
                .is_file()
        {
            return Ok(ancestor.to_path_buf());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "cannot locate the V26 repository root",
    ))
}

fn excluded(relative: &Path) -> bool {
    matches!(
        relative.components().next(),
        Some(Component::Normal(name)) if name == ".git"
    )
}

fn collect_paths(root: &Path, directory: &Path, paths: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|error| io::Error::other(error.to_string()))?;
        if excluded(relative) {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_dir() {
            collect_paths(root, &path, paths)?;
        } else if metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            paths.push(path);
        } else {
            return Err(io::Error::other(format!(
                "unsupported repository file type: {}",
                relative.display()
            )));
        }
    }
    Ok(())
}

fn relative_bytes(root: &Path, path: &Path) -> io::Result<Vec<u8>> {
    let relative = path
        .strip_prefix(root)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let mut encoded = Vec::new();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(io::Error::other("repository path is not canonical"));
        };
        if !encoded.is_empty() {
            encoded.push(b'/');
        }
        encoded.extend_from_slice(name.as_bytes());
    }
    Ok(encoded)
}

fn source_set_sha256(root: &Path) -> io::Result<String> {
    let mut paths = Vec::new();
    collect_paths(root, root, &mut paths)?;
    paths.sort_by_key(|path| relative_bytes(root, path).unwrap_or_default());
    let mut hasher = Sha256::new();
    hasher.update(SOURCE_SET_DOMAIN);
    for path in paths {
        let relative = relative_bytes(root, &path)?;
        let metadata = fs::symlink_metadata(&path)?;
        let (mode, content) = if metadata.file_type().is_symlink() {
            (
                b"120000".as_slice(),
                fs::read_link(&path)?.as_os_str().as_bytes().to_vec(),
            )
        } else {
            let executable = metadata.permissions().mode() & 0o111 != 0;
            (
                if executable {
                    b"100755".as_slice()
                } else {
                    b"100644".as_slice()
                },
                fs::read(&path)?,
            )
        };
        let path_bytes = u32::try_from(relative.len())
            .map_err(|_| io::Error::other("repository path exceeds u32"))?;
        let content_bytes = u64::try_from(content.len())
            .map_err(|_| io::Error::other("repository file exceeds u64"))?;
        hasher.update(mode);
        hasher.update(path_bytes.to_le_bytes());
        hasher.update(&relative);
        hasher.update(content_bytes.to_le_bytes());
        hasher.update(&content);
        println!("cargo:rerun-if-changed={}", path.display());
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn main() -> io::Result<()> {
    let evidence_names = [
        "FRE_V26_EVIDENCE_SOURCE_ARCHIVE_SHA256",
        "FRE_V26_EVIDENCE_SOURCE_COMMIT",
        "FRE_V26_EVIDENCE_SOURCE_TREE",
    ];
    for name in evidence_names {
        println!("cargo:rerun-if-env-changed={name}");
    }
    println!("cargo:rerun-if-env-changed=CARGO_TARGET_DIR");
    let manifest_directory = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR")
            .ok_or_else(|| io::Error::other("CARGO_MANIFEST_DIR is unavailable"))?,
    );
    let root = fs::canonicalize(repository_root(&manifest_directory)?)?;
    let evidence_values = evidence_names.map(env::var_os);
    if evidence_values.iter().all(Option::is_none) {
        println!(
            "cargo:rustc-env=FRE_V26_COMPILED_SOURCE_SET_SHA256={}",
            "0".repeat(64)
        );
        return Ok(());
    }
    if evidence_values.iter().any(Option::is_none) {
        return Err(io::Error::other(
            "V26 evidence source labels must be either all set or all unset",
        ));
    }
    let target_directory = PathBuf::from(env::var_os("CARGO_TARGET_DIR").ok_or_else(|| {
        io::Error::other("V26 evidence builds require an explicit external CARGO_TARGET_DIR")
    })?);
    if !target_directory.is_absolute() || !target_directory.is_dir() {
        return Err(io::Error::other(
            "V26 evidence CARGO_TARGET_DIR must be an existing absolute directory",
        ));
    }
    let target_directory = fs::canonicalize(target_directory)?;
    if target_directory.starts_with(&root) {
        return Err(io::Error::other(
            "V26 evidence CARGO_TARGET_DIR resolves inside the source tree",
        ));
    }
    let source_set_sha256 = source_set_sha256(&root)?;
    println!("cargo:rustc-env=FRE_V26_COMPILED_SOURCE_SET_SHA256={source_set_sha256}");
    Ok(())
}
