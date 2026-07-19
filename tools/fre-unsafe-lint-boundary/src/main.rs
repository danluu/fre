//! Fail-closed audit of Cargo targets and package-local unsafe-lint exceptions.

#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Read as _},
    path::{Path, PathBuf},
    process::ExitCode,
};

use serde::Deserialize;
use sha2::{Digest as _, Sha256};

const KERNEL_PACKAGE: &str = "fre-kernels";
const KERNEL_LIBRARY: &str = "fre_kernels";
const EXACT_ALLOC_PACKAGE: &str = "fre-exact-alloc";
const EXACT_ALLOC_LIBRARY: &str = "fre_exact_alloc";
const FORBID_ATTRIBUTE: &str = "#![forbid(unsafe_code)]";
const DENY_ATTRIBUTE: &str = "#![deny(unsafe_code)]";
const EXACT_ALLOC_SOURCE_SHA256: [u8; 32] = [
    0xe3, 0x49, 0xb8, 0xae, 0x70, 0x47, 0xd9, 0x31, 0x72, 0x6b, 0x6a, 0xf3, 0xe4, 0xb5, 0x5c, 0xbc,
    0xfb, 0x20, 0xd4, 0xdb, 0x60, 0x2b, 0x64, 0x77, 0x4f, 0x9b, 0x68, 0x16, 0x58, 0x0f, 0xbd, 0xa2,
];
const EXACT_VEC_REVIEWED_BLOCK: &str = r#"#[allow(
    unsafe_code,
    reason = "this reviewed function owns FRE's exact-layout typed allocation boundary"
)]
fn exact_vec_with_capacity<T>(
    capacity: usize,
    force_failure: bool,
) -> Result<ExactVec<T>, CopyError> {
    if size_of::<T>() == 0 {
        return Err(CopyError::LayoutOverflow);
    }
    if capacity == 0 {
        return Ok(ExactVec { inner: Vec::new() });
    }
    let layout = Layout::array::<T>(capacity).map_err(|_| CopyError::LayoutOverflow)?;
    let allocation = if force_failure {
        ptr::null_mut()
    } else {
        unsafe { alloc(layout) }
    };
    if allocation.is_null() {
        return Err(CopyError::AllocationFailed);
    }
    // SAFETY: `alloc` returned exactly `layout`; a zero-length Vec owns the
    // uninitialized spare capacity and later deallocates with the same layout.
    let inner = unsafe { Vec::from_raw_parts(allocation.cast::<T>(), 0, capacity) };
    Ok(ExactVec { inner })
}"#;
const ZEROED_EXACT_REVIEWED_BLOCK: &str = r#"#[allow(
    unsafe_code,
    reason = "this reviewed function owns FRE's exact-layout zero-initialization boundary"
)]
fn zeroed_exact_with(len: usize, force_failure: bool) -> Result<Vec<u8>, CopyError> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let layout = Layout::array::<u8>(len).map_err(|_| CopyError::LayoutOverflow)?;
    let allocation = if force_failure {
        ptr::null_mut()
    } else {
        unsafe { alloc_zeroed(layout) }
    };
    if allocation.is_null() {
        return Err(CopyError::AllocationFailed);
    }

    // SAFETY: `alloc_zeroed` returned a fresh allocation for exactly `layout`
    // and initialized every byte. With `len == capacity`, `Vec` later uses the
    // identical layout for deallocation.
    unsafe { Ok(Vec::from_raw_parts(allocation, len, len)) }
}"#;
const COPY_EXACT_REVIEWED_BLOCK: &str = r#"#[allow(
    unsafe_code,
    reason = "this one reviewed function owns FRE's exact-layout allocation boundary"
)]
fn copy_exact_with(bytes: &[u8], force_failure: bool) -> Result<Vec<u8>, CopyError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let layout = Layout::array::<u8>(bytes.len()).map_err(|_| CopyError::LayoutOverflow)?;
    let allocation = if force_failure {
        ptr::null_mut()
    } else {
        unsafe { alloc(layout) }
    };
    if allocation.is_null() {
        return Err(CopyError::AllocationFailed);
    }

    // SAFETY: `alloc` returned a fresh global allocation for exactly `layout`.
    // Every `u8` alignment is valid, the allocation is disjoint from the input,
    // and the copy initializes all `len` bytes. No panicking operation occurs
    // between successful allocation and `Vec` ownership. Since `len == capacity`,
    // `Vec` later deallocates with the same layout.
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), allocation, bytes.len());
        Ok(Vec::from_raw_parts(allocation, bytes.len(), bytes.len()))
    }
}"#;
const EXACT_ALLOC_REVIEWED_BLOCKS: [&str; 3] = [
    EXACT_VEC_REVIEWED_BLOCK,
    ZEROED_EXACT_REVIEWED_BLOCK,
    COPY_EXACT_REVIEWED_BLOCK,
];
const EXACT_ALLOC_UNSAFE_CODE_SPELLINGS: usize = 4;

const KERNEL_LINTS: &str = r#"
[lints.rust]
unsafe_code = "forbid"
missing_debug_implementations = "warn"
rust_2018_idioms = { level = "deny", priority = -1 }
unreachable_pub = "warn"

[lints.clippy]
all = { level = "warn", priority = -1 }
pedantic = { level = "warn", priority = -1 }
allow_attributes_without_reason = "warn"
arithmetic_side_effects = "warn"
as_conversions = "warn"
missing_errors_doc = "allow"
missing_panics_doc = "allow"
module_name_repetitions = "allow"
"#;

const WARN_UNSAFE_LINTS: &str = r#"
[lints.rust]
unsafe_code = "warn"
unsafe_op_in_unsafe_fn = "deny"
missing_debug_implementations = "warn"
rust_2018_idioms = { level = "deny", priority = -1 }
unreachable_pub = "warn"

[lints.clippy]
all = { level = "warn", priority = -1 }
pedantic = { level = "warn", priority = -1 }
allow_attributes_without_reason = "warn"
arithmetic_side_effects = "warn"
as_conversions = "warn"
missing_errors_doc = "allow"
missing_panics_doc = "allow"
module_name_repetitions = "allow"
"#;

const EXACT_ALLOC_LINTS: &str = r#"
[lints.rust]
unsafe_code = "deny"
missing_debug_implementations = "warn"
rust_2018_idioms = { level = "deny", priority = -1 }
unreachable_pub = "warn"

[lints.clippy]
all = { level = "warn", priority = -1 }
pedantic = { level = "warn", priority = -1 }
allow_attributes_without_reason = "warn"
arithmetic_side_effects = "warn"
as_conversions = "warn"
missing_errors_doc = "allow"
missing_panics_doc = "allow"
module_name_repetitions = "allow"
"#;

#[derive(Debug, Deserialize)]
struct Metadata {
    workspace_root: PathBuf,
    workspace_members: Vec<String>,
    packages: Vec<Package>,
}

#[derive(Debug, Deserialize)]
struct Package {
    id: String,
    name: String,
    manifest_path: PathBuf,
    dependencies: Vec<serde_json::Value>,
    targets: Vec<Target>,
}

#[derive(Debug, Deserialize)]
struct Target {
    name: String,
    kind: Vec<String>,
    src_path: PathBuf,
}

#[derive(Clone, Copy, Debug)]
struct LocalException {
    package: &'static str,
    manifest: &'static str,
    expected_lints: &'static str,
}

const LOCAL_EXCEPTIONS: [LocalException; 3] = [
    LocalException {
        package: "fre-capi",
        manifest: "crates/fre-capi/Cargo.toml",
        expected_lints: WARN_UNSAFE_LINTS,
    },
    LocalException {
        package: "fre-jit-runtime",
        manifest: "crates/fre-jit-runtime/Cargo.toml",
        expected_lints: WARN_UNSAFE_LINTS,
    },
    LocalException {
        package: EXACT_ALLOC_PACKAGE,
        manifest: "crates/fre-exact-alloc/Cargo.toml",
        expected_lints: EXACT_ALLOC_LINTS,
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuditSummary {
    workspace_packages: usize,
    local_exceptions: usize,
    kernel_targets: usize,
    protected_kernel_targets: usize,
}

fn main() -> ExitCode {
    match read_and_audit() {
        Ok(summary) => {
            println!(
                "PASS metadata-packages={} local-exceptions={} kernel-targets={} protected-nonlib={}",
                summary.workspace_packages,
                summary.local_exceptions,
                summary.kernel_targets,
                summary.protected_kernel_targets
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("unsafe lint metadata failure: {error}");
            ExitCode::FAILURE
        }
    }
}

fn read_and_audit() -> Result<AuditSummary, String> {
    let mut input = Vec::new();
    io::stdin()
        .read_to_end(&mut input)
        .map_err(|error| format!("read Cargo metadata from stdin: {error}"))?;
    let metadata: Metadata = serde_json::from_slice(&input)
        .map_err(|error| format!("parse Cargo metadata JSON: {error}"))?;
    audit(&metadata)
}

fn audit(metadata: &Metadata) -> Result<AuditSummary, String> {
    let workspace_root = canonical(&metadata.workspace_root, "workspace root")?;
    let packages_by_id = index_packages(&metadata.packages)?;
    let mut member_ids = BTreeSet::new();
    let mut members = Vec::with_capacity(metadata.workspace_members.len());
    for id in &metadata.workspace_members {
        if !member_ids.insert(id.as_str()) {
            return Err(format!("duplicate workspace member id: {id}"));
        }
        members.push(
            *packages_by_id
                .get(id.as_str())
                .ok_or_else(|| format!("workspace member missing from packages: {id}"))?,
        );
    }
    if members.is_empty() {
        return Err("Cargo metadata contains no workspace members".to_owned());
    }

    let mut packages_by_name = BTreeMap::new();
    for package in &members {
        if packages_by_name
            .insert(package.name.as_str(), *package)
            .is_some()
        {
            return Err(format!(
                "duplicate workspace package name: {}",
                package.name
            ));
        }
        let manifest = canonical(
            &package.manifest_path,
            &format!("manifest for {}", package.name),
        )?;
        if !manifest.starts_with(&workspace_root) {
            return Err(format!(
                "workspace package {} has manifest outside workspace root: {}",
                package.name,
                manifest.display()
            ));
        }
    }

    audit_package_lint_inheritance(&workspace_root, &packages_by_name)?;
    let kernel = packages_by_name
        .get(KERNEL_PACKAGE)
        .ok_or_else(|| format!("missing {KERNEL_PACKAGE} workspace package"))?;
    let protected_kernel_targets = audit_kernel_targets(kernel, &workspace_root)?;
    audit_kernel_sources(&workspace_root)?;
    audit_exact_allocator(&packages_by_name, &workspace_root)?;

    Ok(AuditSummary {
        workspace_packages: members.len(),
        local_exceptions: LOCAL_EXCEPTIONS.len(),
        kernel_targets: kernel.targets.len(),
        protected_kernel_targets,
    })
}

fn index_packages(packages: &[Package]) -> Result<BTreeMap<&str, &Package>, String> {
    let mut indexed = BTreeMap::new();
    for package in packages {
        if indexed.insert(package.id.as_str(), package).is_some() {
            return Err(format!("duplicate Cargo package id: {}", package.id));
        }
    }
    Ok(indexed)
}

fn audit_package_lint_inheritance(
    workspace_root: &Path,
    packages: &BTreeMap<&str, &Package>,
) -> Result<(), String> {
    let exceptions: BTreeMap<_, _> = LOCAL_EXCEPTIONS
        .iter()
        .map(|exception| (exception.package, exception))
        .collect();
    if exceptions.len() != LOCAL_EXCEPTIONS.len() {
        return Err("duplicate package in local lint exception allowlist".to_owned());
    }

    let mut observed_exceptions = BTreeSet::new();
    for (name, package) in packages {
        let manifest_path = canonical(&package.manifest_path, &format!("manifest for {name}"))?;
        let manifest_bytes = fs::read(&manifest_path)
            .map_err(|error| format!("read {}: {error}", manifest_path.display()))?;
        let manifest_text = std::str::from_utf8(&manifest_bytes)
            .map_err(|error| format!("{} is not UTF-8: {error}", manifest_path.display()))?;
        let manifest: toml::Value = toml::from_str(manifest_text)
            .map_err(|error| format!("parse {} as TOML: {error}", manifest_path.display()))?;
        let lints = manifest
            .get("lints")
            .and_then(toml::Value::as_table)
            .ok_or_else(|| format!("package {name} has no [lints] table"))?;

        if let Some(exception) = exceptions.get(name) {
            observed_exceptions.insert(*name);
            let expected_manifest = canonical(
                &workspace_root.join(exception.manifest),
                &format!("expected manifest for {name}"),
            )?;
            if manifest_path != expected_manifest {
                return Err(format!(
                    "local lint exception {name} moved from {} to {}",
                    expected_manifest.display(),
                    manifest_path.display()
                ));
            }
            require_exact_lints(name, lints, exception.expected_lints)?;
        } else if *name == KERNEL_PACKAGE {
            require_exact_lints(name, lints, KERNEL_LINTS)?;
        } else if lints.len() != 1
            || lints.get("workspace").and_then(toml::Value::as_bool) != Some(true)
        {
            return Err(format!(
                "workspace package {name} must inherit [lints] workspace = true"
            ));
        }
    }

    let expected_exceptions: BTreeSet<_> = exceptions.keys().copied().collect();
    if observed_exceptions != expected_exceptions {
        return Err(format!(
            "local lint exceptions differ: observed={observed_exceptions:?} expected={expected_exceptions:?}"
        ));
    }
    Ok(())
}

fn require_exact_lints(
    package: &str,
    actual: &toml::map::Map<String, toml::Value>,
    expected_source: &str,
) -> Result<(), String> {
    let expected_document: toml::Value = toml::from_str(expected_source)
        .map_err(|error| format!("parse expected lint table for {package}: {error}"))?;
    let expected = expected_document
        .get("lints")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| format!("expected lint table for {package} is malformed"))?;
    if actual != expected {
        return Err(format!(
            "local lint table for {package} drifted: actual={actual:?} expected={expected:?}"
        ));
    }
    Ok(())
}

fn audit_kernel_targets(package: &Package, workspace_root: &Path) -> Result<usize, String> {
    let kernel_root = canonical(
        &workspace_root.join("crates/fre-kernels"),
        "fre-kernels package root",
    )?;
    let expected_library = canonical(
        &kernel_root.join("src/lib.rs"),
        "expected fre-kernels library",
    )?;
    let mut library_count = 0_usize;
    let mut protected = 0_usize;

    for target in &package.targets {
        let source = canonical(
            &target.src_path,
            &format!("source for fre-kernels target {}", target.name),
        )?;
        if !source.starts_with(&kernel_root) {
            return Err(format!(
                "fre-kernels target {} escapes its package root: {}",
                target.name,
                source.display()
            ));
        }

        if source == expected_library {
            library_count = library_count
                .checked_add(1)
                .ok_or_else(|| "fre-kernels library count overflow".to_owned())?;
            if target.name != KERNEL_LIBRARY || target.kind.as_slice() != ["lib"] {
                return Err(format!(
                    "expected library path belongs to unexpected target {} kind {:?}",
                    target.name, target.kind
                ));
            }
            require_attribute(&source, FORBID_ATTRIBUTE, false, &target.name)?;
            continue;
        }

        if target.kind.iter().any(|kind| kind == "lib") {
            return Err(format!(
                "unexpected additional fre-kernels library target {} at {}",
                target.name,
                source.display()
            ));
        }
        require_attribute(&source, FORBID_ATTRIBUTE, true, &target.name)?;
        protected = protected
            .checked_add(1)
            .ok_or_else(|| "protected target count overflow".to_owned())?;
    }

    if library_count != 1 {
        return Err(format!(
            "expected exactly one fre-kernels library target, observed {library_count}"
        ));
    }
    Ok(protected)
}

fn audit_kernel_sources(workspace_root: &Path) -> Result<(), String> {
    let source_root = canonical(
        &workspace_root.join("crates/fre-kernels/src"),
        "fre-kernels source root",
    )?;
    let library = canonical(&source_root.join("lib.rs"), "fre-kernels library source")?;
    let mut files = BTreeSet::new();
    collect_regular_files(&source_root, &source_root, &mut files)?;
    for relative in files {
        if relative
            .extension()
            .and_then(|extension| extension.to_str())
            != Some("rs")
        {
            return Err(format!(
                "unexpected non-Rust file in fre-kernels source root: {}",
                relative.display()
            ));
        }
        let path = source_root.join(&relative);
        let source = fs::read_to_string(&path)
            .map_err(|error| format!("read kernel source {}: {error}", path.display()))?;
        if path == library {
            if source.matches("unsafe_code").count() != 1 || !source.contains(FORBID_ATTRIBUTE) {
                return Err("fre-kernels library unsafe boundary drifted".to_owned());
            }
        } else if source.contains("unsafe_code") {
            return Err(format!(
                "fre-kernels source {} contains an unsafe lint lowering",
                path.display()
            ));
        }
        for forbidden in ["unsafe {", "unsafe fn", "unsafe impl", "unsafe trait"] {
            if source.contains(forbidden) {
                return Err(format!(
                    "fre-kernels source {} contains forbidden token {forbidden:?}",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

fn audit_exact_allocator(
    packages: &BTreeMap<&str, &Package>,
    workspace_root: &Path,
) -> Result<(), String> {
    let package = packages
        .get(EXACT_ALLOC_PACKAGE)
        .ok_or_else(|| format!("missing {EXACT_ALLOC_PACKAGE} workspace package"))?;
    if !package.dependencies.is_empty() {
        return Err(format!(
            "{EXACT_ALLOC_PACKAGE} must have no dependencies, observed {}",
            package.dependencies.len()
        ));
    }
    if package.targets.len() != 1 {
        return Err(format!(
            "{EXACT_ALLOC_PACKAGE} must have exactly one target, observed {}",
            package.targets.len()
        ));
    }

    let package_root = canonical(
        &workspace_root.join("crates/fre-exact-alloc"),
        "fre-exact-alloc package root",
    )?;
    let expected_manifest =
        canonical(&package_root.join("Cargo.toml"), "fre-exact-alloc manifest")?;
    if canonical(&package.manifest_path, "fre-exact-alloc package manifest")? != expected_manifest {
        return Err("fre-exact-alloc manifest path drifted".to_owned());
    }
    let expected_source = canonical(
        &package_root.join("src/lib.rs"),
        "fre-exact-alloc library source",
    )?;
    let target = &package.targets[0];
    if target.name != EXACT_ALLOC_LIBRARY
        || target.kind.as_slice() != ["lib"]
        || canonical(&target.src_path, "fre-exact-alloc target source")? != expected_source
    {
        return Err(format!(
            "unexpected fre-exact-alloc target {} kind {:?} source {}",
            target.name,
            target.kind,
            target.src_path.display()
        ));
    }

    let mut files = BTreeSet::new();
    collect_regular_files(&package_root, &package_root, &mut files)?;
    let expected_files = BTreeSet::from([PathBuf::from("Cargo.toml"), PathBuf::from("src/lib.rs")]);
    if files != expected_files {
        return Err(format!(
            "fre-exact-alloc file inventory drifted: actual={files:?} expected={expected_files:?}"
        ));
    }
    audit_exact_allocator_source(&expected_source)
}

fn audit_exact_allocator_source(source_path: &Path) -> Result<(), String> {
    let source_bytes =
        fs::read(source_path).map_err(|error| format!("read exact allocator source: {error}"))?;
    if Sha256::digest(&source_bytes)[..] != EXACT_ALLOC_SOURCE_SHA256 {
        return Err("exact allocator complete source digest drifted".to_owned());
    }
    let source = std::str::from_utf8(&source_bytes)
        .map_err(|error| format!("exact allocator source is not UTF-8: {error}"))?;
    audit_exact_allocator_source_text(source)
}

fn audit_exact_allocator_source_text(source: &str) -> Result<(), String> {
    if source.matches(DENY_ATTRIBUTE).count() != 1
        || source
            .lines()
            .filter(|line| *line == DENY_ATTRIBUTE)
            .count()
            != 1
    {
        return Err(format!(
            "exact allocator source must contain exactly one {DENY_ATTRIBUTE}"
        ));
    }
    if source.matches("unsafe_code").count() != EXACT_ALLOC_UNSAFE_CODE_SPELLINGS {
        return Err("exact allocator unsafe-lint lowering inventory drifted".to_owned());
    }
    let mut prior_end = 0;
    for block in EXACT_ALLOC_REVIEWED_BLOCKS {
        if source.matches(block).count() != 1 {
            return Err("exact allocator reviewed unsafe site binding drifted".to_owned());
        }
        let offset = source
            .find(block)
            .ok_or_else(|| "exact allocator reviewed unsafe site disappeared".to_owned())?;
        if offset < prior_end {
            return Err("exact allocator reviewed unsafe site order drifted".to_owned());
        }
        prior_end = offset
            .checked_add(block.len())
            .ok_or_else(|| "exact allocator reviewed unsafe site offset overflow".to_owned())?;
    }
    for forbidden in [
        "include!",
        "include_bytes!",
        "include_str!",
        "#[path",
        "macro_rules!",
        "proc_macro",
        "env!",
        "option_env!",
    ] {
        if source.contains(forbidden) {
            return Err(format!(
                "exact allocator source contains forbidden expansion path {forbidden:?}"
            ));
        }
    }
    Ok(())
}

fn collect_regular_files(
    root: &Path,
    directory: &Path,
    files: &mut BTreeSet<PathBuf>,
) -> Result<(), String> {
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("read directory {}: {error}", directory.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("read directory entry: {error}"))?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("read file type for {}: {error}", entry.path().display()))?;
        let path = entry.path();
        if file_type.is_symlink() {
            return Err(format!(
                "symlink is forbidden in audited source: {}",
                path.display()
            ));
        }
        if file_type.is_dir() {
            collect_regular_files(root, &path, files)?;
        } else if file_type.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|error| format!("strip source root from {}: {error}", path.display()))?;
            if !files.insert(relative.to_path_buf()) {
                return Err(format!("duplicate audited source file: {}", path.display()));
            }
        } else {
            return Err(format!("unexpected filesystem entry: {}", path.display()));
        }
    }
    Ok(())
}

fn require_attribute(
    path: &Path,
    attribute: &str,
    must_be_first_line: bool,
    target: &str,
) -> Result<(), String> {
    let source = fs::read_to_string(path)
        .map_err(|error| format!("read target {target} at {}: {error}", path.display()))?;
    let present = if must_be_first_line {
        source.lines().next() == Some(attribute)
    } else {
        source.lines().any(|line| line == attribute)
    };
    if !present {
        let placement = if must_be_first_line {
            "as its first line"
        } else {
            "as an exact crate attribute"
        };
        return Err(format!(
            "target {target} at {} must contain {attribute} {placement}",
            path.display()
        ));
    }
    Ok(())
}

fn canonical(path: &Path, description: &str) -> Result<PathBuf, String> {
    path.canonicalize()
        .map_err(|error| format!("canonicalize {description} {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::{
        COPY_EXACT_REVIEWED_BLOCK, DENY_ATTRIBUTE, EXACT_ALLOC_LINTS, EXACT_VEC_REVIEWED_BLOCK,
        Package, Target, WARN_UNSAFE_LINTS, ZEROED_EXACT_REVIEWED_BLOCK, audit_exact_allocator,
        audit_exact_allocator_source, audit_exact_allocator_source_text, audit_kernel_targets,
        require_exact_lints,
    };
    use std::{
        collections::BTreeMap,
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_TREE: AtomicU64 = AtomicU64::new(0);

    struct TestTree(PathBuf);

    impl TestTree {
        fn new() -> Self {
            for _ in 0..100 {
                let sequence = NEXT_TREE.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "fre-unsafe-lint-boundary-test-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("create test tree {}: {error}", path.display()),
                }
            }
            panic!("could not create unique lint-boundary test tree");
        }

        fn root(&self) -> &Path {
            &self.0
        }

        fn write(&self, relative: &str, source: &str) -> PathBuf {
            let path = self.0.join(relative);
            fs::create_dir_all(path.parent().expect("fixture path has a parent"))
                .expect("create fixture parent");
            fs::write(&path, source).expect("write fixture source");
            path
        }
    }

    impl Drop for TestTree {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove lint-boundary test tree");
        }
    }

    fn kernel_package(tree: &TestTree, additional: Vec<Target>) -> Package {
        let library = tree.write(
            "crates/fre-kernels/src/lib.rs",
            "//! fixture\n#![forbid(unsafe_code)]\n",
        );
        let manifest = tree.write(
            "crates/fre-kernels/Cargo.toml",
            "[package]\nname='fixture'\n",
        );
        let mut targets = vec![Target {
            name: "fre_kernels".to_owned(),
            kind: vec!["lib".to_owned()],
            src_path: library,
        }];
        targets.extend(additional);
        Package {
            id: "fixture fre-kernels".to_owned(),
            name: "fre-kernels".to_owned(),
            manifest_path: manifest,
            dependencies: Vec::new(),
            targets,
        }
    }

    fn target(name: &str, kind: &str, source: PathBuf) -> Target {
        Target {
            name: name.to_owned(),
            kind: vec![kind.to_owned()],
            src_path: source,
        }
    }

    fn exact_source() -> String {
        format!(
            "//! fixture\n#![deny(unsafe_code)]\n\n\
             {EXACT_VEC_REVIEWED_BLOCK}\n\n\
             {ZEROED_EXACT_REVIEWED_BLOCK}\n\n\
             {COPY_EXACT_REVIEWED_BLOCK}\n"
        )
    }

    fn canonical_exact_source() -> &'static str {
        include_str!("../../../crates/fre-exact-alloc/src/lib.rs")
    }

    fn assert_exact_source_rejected(source: &str) {
        assert!(audit_exact_allocator_source_text(source).is_err());
    }

    fn exact_package(tree: &TestTree, additional: Vec<Target>) -> Package {
        let source = tree.write(
            "crates/fre-exact-alloc/src/lib.rs",
            canonical_exact_source(),
        );
        let manifest = tree.write(
            "crates/fre-exact-alloc/Cargo.toml",
            "[package]\nname='fre-exact-alloc'\n",
        );
        let mut targets = vec![Target {
            name: "fre_exact_alloc".to_owned(),
            kind: vec!["lib".to_owned()],
            src_path: source,
        }];
        targets.extend(additional);
        Package {
            id: "fixture fre-exact-alloc".to_owned(),
            name: "fre-exact-alloc".to_owned(),
            manifest_path: manifest,
            dependencies: Vec::new(),
            targets,
        }
    }

    #[test]
    fn integration_test_escape_is_rejected() {
        let tree = TestTree::new();
        let escape = tree.write(
            "crates/fre-kernels/tests/lint_escape.rs",
            "#![allow(unsafe_code)]\nfn escape() {}\n",
        );
        let package = kernel_package(&tree, vec![target("lint_escape", "test", escape)]);
        let error = audit_kernel_targets(&package, tree.root()).unwrap_err();
        assert!(error.contains("lint_escape"));
        assert!(error.contains("#![forbid(unsafe_code)]"));
    }

    #[test]
    fn manifest_declared_custom_target_escape_is_rejected() {
        let tree = TestTree::new();
        let escape = tree.write(
            "crates/fre-kernels/custom/escape.rs",
            "#![allow(unsafe_code)]\nfn main() {}\n",
        );
        let package = kernel_package(&tree, vec![target("custom_escape", "example", escape)]);
        let error = audit_kernel_targets(&package, tree.root()).unwrap_err();
        assert!(error.contains("custom_escape"));
        assert!(error.contains("#![forbid(unsafe_code)]"));
    }

    #[test]
    fn every_nonlibrary_metadata_target_with_first_line_forbid_is_accepted() {
        let tree = TestTree::new();
        let integration = tree.write(
            "crates/fre-kernels/tests/protected.rs",
            "#![forbid(unsafe_code)]\n#[test]\nfn protected() {}\n",
        );
        let custom = tree.write(
            "crates/fre-kernels/custom/protected.rs",
            "#![forbid(unsafe_code)]\nfn main() {}\n",
        );
        let package = kernel_package(
            &tree,
            vec![
                target("protected", "test", integration),
                target("custom_protected", "example", custom),
            ],
        );
        assert_eq!(audit_kernel_targets(&package, tree.root()), Ok(2));
    }

    #[test]
    fn additional_unsafe_lowering_is_rejected() {
        let source = format!(
            "{}\n#[allow(unsafe_code)]\nunsafe fn escaped() {{}}\n",
            exact_source()
        );
        let error = audit_exact_allocator_source_text(&source).unwrap_err();
        assert!(error.contains("lowering inventory drifted"));
    }

    #[test]
    fn exactly_three_reviewed_unsafe_blocks_in_order_are_accepted() {
        assert_eq!(audit_exact_allocator_source_text(&exact_source()), Ok(()));
    }

    #[test]
    fn canonical_complete_source_digest_is_accepted() {
        let tree = TestTree::new();
        let path = tree.write(
            "crates/fre-exact-alloc/src/lib.rs",
            canonical_exact_source(),
        );
        assert_eq!(audit_exact_allocator_source(&path), Ok(()));
    }

    #[test]
    fn inactive_or_replaced_reviewed_blocks_fail_complete_digest() {
        let tree = TestTree::new();
        let cfg_test = canonical_exact_source().replace(
            "#[allow(\n    unsafe_code,",
            "#[cfg(test)]\n#[allow(\n    unsafe_code,",
        );
        let cfg_pair = format!(
            "{cfg_test}\n\
             #[cfg(not(test))]\nfn exact_vec_with_capacity<T>(_: usize, _: bool) -> Result<ExactVec<T>, CopyError> {{ unreachable!() }}\n\
             #[cfg(not(test))]\nfn zeroed_exact_with(_: usize, _: bool) -> Result<Vec<u8>, CopyError> {{ unreachable!() }}\n\
             #[cfg(not(test))]\nfn copy_exact_with(_: &[u8], _: bool) -> Result<Vec<u8>, CopyError> {{ unreachable!() }}\n"
        );
        let cfg_attr = canonical_exact_source().replace(
            "#[allow(\n    unsafe_code,",
            "#[cfg_attr(not(test), cfg(any()))]\n#[allow(\n    unsafe_code,",
        );
        let commented = canonical_exact_source().replacen(
            EXACT_VEC_REVIEWED_BLOCK,
            &format!("/*\n{EXACT_VEC_REVIEWED_BLOCK}\n*/"),
            1,
        );
        let string_inert = canonical_exact_source().replacen(
            EXACT_VEC_REVIEWED_BLOCK,
            &format!(
                "const INERT_REVIEWED_BLOCK: &str = r###\"{EXACT_VEC_REVIEWED_BLOCK}\"###;\n\
                 fn exact_vec_with_capacity<T>(_: usize, _: bool) -> Result<ExactVec<T>, CopyError> {{ unreachable!() }}"
            ),
            1,
        );
        for (name, source) in [
            ("cfg-test-and-active-replacement.rs", cfg_pair),
            ("cfg-attr.rs", cfg_attr),
            ("comment-inert.rs", commented),
            ("string-inert-and-active-replacement.rs", string_inert),
        ] {
            let path = tree.write(name, &source);
            assert!(
                audit_exact_allocator_source(&path)
                    .unwrap_err()
                    .contains("complete source digest")
            );
        }
    }

    #[test]
    fn every_missing_or_duplicated_reviewed_unsafe_block_is_rejected() {
        for block in [
            EXACT_VEC_REVIEWED_BLOCK,
            ZEROED_EXACT_REVIEWED_BLOCK,
            COPY_EXACT_REVIEWED_BLOCK,
        ] {
            assert_exact_source_rejected(&exact_source().replace(block, ""));
            assert_exact_source_rejected(&format!("{}\n{block}\n", exact_source()));
        }
    }

    #[test]
    fn reviewed_unsafe_block_order_and_alternate_allowance_are_rejected() {
        let reordered = exact_source().replace(
            &format!("{EXACT_VEC_REVIEWED_BLOCK}\n\n{ZEROED_EXACT_REVIEWED_BLOCK}"),
            &format!("{ZEROED_EXACT_REVIEWED_BLOCK}\n\n{EXACT_VEC_REVIEWED_BLOCK}"),
        );
        assert_exact_source_rejected(&reordered);
        assert_exact_source_rejected(&format!(
            "{}\n#[allow( unsafe_code, reason = \"fourth\" )]\nunsafe fn fourth() {{}}\n",
            exact_source()
        ));
        assert_exact_source_rejected(&exact_source().replacen(
            "#[allow(\n    unsafe_code,",
            "#[allow( unsafe_code,",
            1,
        ));
    }

    #[test]
    fn every_reviewed_function_name_and_reason_is_exact() {
        for (original, replacement) in [
            ("fn exact_vec_with_capacity<T>(", "fn renamed_exact_vec<T>("),
            ("fn zeroed_exact_with(", "fn renamed_zeroed_exact_with("),
            ("fn copy_exact_with(", "fn renamed_copy_exact_with("),
            (
                "this reviewed function owns FRE's exact-layout typed allocation boundary",
                "changed typed allocation boundary",
            ),
            (
                "this reviewed function owns FRE's exact-layout zero-initialization boundary",
                "changed zero-initialization boundary",
            ),
            (
                "this one reviewed function owns FRE's exact-layout allocation boundary",
                "changed copy allocation boundary",
            ),
        ] {
            let mutated = exact_source().replacen(original, replacement, 1);
            assert_ne!(mutated, exact_source());
            assert_exact_source_rejected(&mutated);
        }
    }

    #[test]
    fn every_reviewed_unsafe_body_is_exact() {
        for (original, replacement) in [
            (
                "unsafe { alloc(layout) }",
                "unsafe { alloc_zeroed(layout) }",
            ),
            ("ptr::null_mut()", "core::ptr::null_mut()"),
            (
                "Vec::from_raw_parts(allocation.cast::<T>(), 0, capacity)",
                "Vec::from_raw_parts(allocation.cast::<T>(), 0, capacity - 1)",
            ),
            (
                "Vec::from_raw_parts(allocation, len, len)",
                "Vec::from_raw_parts(allocation, len, len + 1)",
            ),
            (
                "ptr::copy_nonoverlapping(bytes.as_ptr(), allocation, bytes.len());",
                "ptr::copy(bytes.as_ptr(), allocation, bytes.len());",
            ),
            (
                "Vec::from_raw_parts(allocation, bytes.len(), bytes.len())",
                "Vec::from_raw_parts(allocation, bytes.len(), bytes.len() + 1)",
            ),
        ] {
            let mutated = exact_source().replacen(original, replacement, 1);
            assert_ne!(mutated, exact_source());
            assert_exact_source_rejected(&mutated);
        }
    }

    #[test]
    fn exact_allocator_deny_attribute_is_unique() {
        assert_exact_source_rejected(&exact_source().replace(DENY_ATTRIBUTE, ""));
        assert_exact_source_rejected(&format!("{DENY_ATTRIBUTE}\n{}", exact_source()));
        assert_exact_source_rejected(
            &exact_source().replace(DENY_ATTRIBUTE, &format!("// {DENY_ATTRIBUTE}")),
        );
    }

    #[test]
    fn missing_reviewed_unsafe_lowering_is_rejected() {
        let source = exact_source().replace(ZEROED_EXACT_REVIEWED_BLOCK, "");
        let error = audit_exact_allocator_source_text(&source).unwrap_err();
        assert!(error.contains("lowering inventory drifted"));
    }

    #[test]
    fn reviewed_unsafe_lowering_reason_drift_is_rejected() {
        let source = exact_source().replace(
            "exact-layout zero-initialization boundary",
            "changed boundary",
        );
        let error = audit_exact_allocator_source_text(&source).unwrap_err();
        assert!(error.contains("reviewed unsafe site binding drifted"));
    }

    #[test]
    fn reviewed_unsafe_lowering_function_binding_drift_is_rejected() {
        let source =
            exact_source().replace("fn zeroed_exact_with(", "fn renamed_zeroed_exact_with(");
        let error = audit_exact_allocator_source_text(&source).unwrap_err();
        assert!(error.contains("reviewed unsafe site binding drifted"));
    }

    #[test]
    fn generated_or_additional_allocator_target_is_rejected() {
        let tree = TestTree::new();
        let generated = tree.write(
            "crates/fre-exact-alloc/build.rs",
            "#![forbid(unsafe_code)]\nfn main() {}\n",
        );
        let package = exact_package(
            &tree,
            vec![target("build-script-build", "custom-build", generated)],
        );
        let packages = BTreeMap::from([("fre-exact-alloc", &package)]);
        let error = audit_exact_allocator(&packages, tree.root()).unwrap_err();
        assert!(error.contains("exactly one target"));
    }

    #[test]
    fn local_exception_lint_drift_is_rejected() {
        let document: toml::Value = toml::from_str(WARN_UNSAFE_LINTS).unwrap();
        let mut actual = document.get("lints").unwrap().as_table().unwrap().clone();
        actual
            .get_mut("rust")
            .unwrap()
            .as_table_mut()
            .unwrap()
            .insert(
                "unsafe_op_in_unsafe_fn".to_owned(),
                toml::Value::String("allow".to_owned()),
            );
        let error = require_exact_lints("fre-capi", &actual, WARN_UNSAFE_LINTS).unwrap_err();
        assert!(error.contains("drifted"));
    }

    #[test]
    fn exact_allocator_layout_is_accepted() {
        let tree = TestTree::new();
        let package = exact_package(&tree, Vec::new());
        let packages = BTreeMap::from([("fre-exact-alloc", &package)]);
        assert_eq!(audit_exact_allocator(&packages, tree.root()), Ok(()));

        let document: toml::Value = toml::from_str(EXACT_ALLOC_LINTS).unwrap();
        let actual = document.get("lints").unwrap().as_table().unwrap();
        assert_eq!(
            require_exact_lints("fre-exact-alloc", actual, EXACT_ALLOC_LINTS),
            Ok(())
        );
    }

    #[test]
    fn allocator_dependency_and_source_expansion_are_rejected() {
        let tree = TestTree::new();
        let mut package = exact_package(&tree, Vec::new());
        package
            .dependencies
            .push(serde_json::json!({"name": "escape"}));
        let packages = BTreeMap::from([("fre-exact-alloc", &package)]);
        assert!(
            audit_exact_allocator(&packages, tree.root())
                .unwrap_err()
                .contains("no dependencies")
        );

        drop(packages);
        package.dependencies.clear();
        tree.write(
            "crates/fre-exact-alloc/src/escape.rs",
            "pub fn escape() {}\n",
        );
        let packages = BTreeMap::from([("fre-exact-alloc", &package)]);
        assert!(
            audit_exact_allocator(&packages, tree.root())
                .unwrap_err()
                .contains("file inventory")
        );
    }

    #[test]
    fn include_and_macro_expansion_paths_are_rejected() {
        let source = format!("{}\ninclude!(\"generated.rs\");\n", exact_source());
        assert!(
            audit_exact_allocator_source_text(&source)
                .unwrap_err()
                .contains("expansion path")
        );
    }
}
