use std::{
    env, fs,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::Command,
};

use sha2::{Digest as _, Sha256};

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(
        bytes
            .len()
            .checked_mul(2)
            .expect("hex output length fits usize"),
    );
    for &byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn command_identity(program: &str, argument: &str) -> String {
    let output = Command::new(program)
        .arg(argument)
        .output()
        .unwrap_or_else(|error| panic!("cannot execute {program} {argument}: {error}"));
    assert!(
        output.status.success(),
        "{program} {argument} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    hex(&Sha256::digest(&output.stdout))
}

fn collect_source_files(root: &Path, directory: &Path, files: &mut Vec<PathBuf>) {
    let mut entries = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", directory.display()))
        .map(|entry| entry.expect("source directory entry").path())
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        let relative = path
            .strip_prefix(root)
            .expect("runner source path is below repository root");
        if relative
            .components()
            .any(|component| component.as_os_str() == "target")
        {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)
            .unwrap_or_else(|error| panic!("cannot stat {}: {error}", path.display()));
        assert!(
            !metadata.file_type().is_symlink(),
            "runner source set forbids symlink {}",
            path.display()
        );
        if metadata.is_dir() {
            collect_source_files(root, &path, files);
        } else if metadata.is_file() {
            println!("cargo:rerun-if-changed={}", path.display());
            files.push(path);
        } else {
            panic!("runner source set contains non-regular {}", path.display());
        }
    }
}

fn source_set_identity(root: &Path) -> String {
    let mut files = Vec::new();
    for relative in [
        "crates",
        "research/aot/search-v26-width-cost-rule-r1/synthetic-runner",
        "research/aot/search-v26-width-cost-rule-r1/development-gate/runner",
    ] {
        collect_source_files(root, &root.join(relative), &mut files);
    }
    for relative in [".cargo/config.toml", "Cargo.toml", "rust-toolchain.toml"] {
        let path = root.join(relative);
        let metadata = fs::symlink_metadata(&path)
            .unwrap_or_else(|error| panic!("cannot stat {}: {error}", path.display()));
        assert!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "root build input must be regular: {}",
            path.display()
        );
        println!("cargo:rerun-if-changed={}", path.display());
        files.push(path);
    }
    files.sort();
    let mut hasher = Sha256::new();
    hasher.update(b"FRE-V26-RUNNER-SOURCE-SET-V2\0\x01");
    for path in files {
        let relative = path
            .strip_prefix(root)
            .expect("source-set path is below manifest root");
        let relative = relative
            .to_str()
            .expect("runner source-set path is UTF-8")
            .as_bytes();
        let bytes = fs::read(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
        let executable = fs::metadata(&path)
            .unwrap_or_else(|error| panic!("cannot stat {}: {error}", path.display()))
            .permissions()
            .mode()
            & 0o111
            != 0;
        hasher.update(
            u64::try_from(relative.len())
                .expect("relative path length fits u64")
                .to_le_bytes(),
        );
        hasher.update(relative);
        hasher.update(b"F");
        hasher.update([u8::from(executable)]);
        hasher.update(
            u64::try_from(bytes.len())
                .expect("source file length fits u64")
                .to_le_bytes(),
        );
        hasher.update(bytes);
    }
    hex(&hasher.finalize())
}

fn build_configuration_identity() -> String {
    let mut entries = env::vars()
        .filter(|(name, _)| {
            matches!(
                name.as_str(),
                "PROFILE"
                    | "OPT_LEVEL"
                    | "DEBUG"
                    | "TARGET"
                    | "HOST"
                    | "RUSTFLAGS"
                    | "CARGO_ENCODED_RUSTFLAGS"
            ) || name.starts_with("CARGO_FEATURE_")
                || name.starts_with("CARGO_PROFILE_")
                || name.starts_with("CARGO_CFG_TARGET_")
        })
        .collect::<Vec<_>>();
    entries.sort();
    let mut hasher = Sha256::new();
    hasher.update(b"FRE-V26-RUNNER-BUILD-CONFIGURATION-V1\0\x01");
    for (name, value) in entries {
        hasher.update(
            u64::try_from(name.len())
                .expect("environment name length fits u64")
                .to_le_bytes(),
        );
        hasher.update(name.as_bytes());
        hasher.update(
            u64::try_from(value.len())
                .expect("environment value length fits u64")
                .to_le_bytes(),
        );
        hasher.update(value.as_bytes());
    }
    hex(&hasher.finalize())
}

fn export(name: &str, value: &str) {
    println!("cargo:rustc-env={name}={value}");
}

fn main() {
    for name in [
        "FRE_V26_SOURCE_COMMIT",
        "FRE_V26_SOURCE_TREE",
        "FRE_V26_SOURCE_ARCHIVE_SHA256",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
        export(
            name,
            &env::var(name).unwrap_or_else(|_| "UNSEALED".to_owned()),
        );
    }
    let manifest_root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let root = manifest_root
        .ancestors()
        .find(|candidate| {
            candidate
                .join("crates/fre-jit-aarch64/Cargo.toml")
                .is_file()
        })
        .expect("repository root containing fre-jit-aarch64");
    let rustc = env::var("RUSTC").expect("RUSTC");
    let cargo = env::var("CARGO").expect("CARGO");
    export("FRE_V26_BUILD_TARGET", &env::var("TARGET").expect("TARGET"));
    export("FRE_V26_BUILD_HOST", &env::var("HOST").expect("HOST"));
    export(
        "FRE_V26_BUILD_PROFILE",
        &env::var("PROFILE").expect("PROFILE"),
    );
    export(
        "FRE_V26_BUILD_OPT_LEVEL",
        &env::var("OPT_LEVEL").expect("OPT_LEVEL"),
    );
    export("FRE_V26_BUILD_DEBUG", &env::var("DEBUG").expect("DEBUG"));
    export(
        "FRE_V26_RUSTC_IDENTITY_SHA256",
        &command_identity(&rustc, "-vV"),
    );
    export(
        "FRE_V26_CARGO_IDENTITY_SHA256",
        &command_identity(&cargo, "-V"),
    );
    export(
        "FRE_V26_RUNNER_SOURCE_SET_SHA256",
        &source_set_identity(root),
    );
    export(
        "FRE_V26_BUILD_CONFIGURATION_SHA256",
        &build_configuration_identity(),
    );
}
