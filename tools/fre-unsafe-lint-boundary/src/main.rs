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

const KERNEL_PACKAGE: &str = "fre-kernels";
const KERNEL_LIBRARY: &str = "fre_kernels";
const DENY_ATTRIBUTE: &str = "#![deny(unsafe_code)]";
const FORBID_ATTRIBUTE: &str = "#![forbid(unsafe_code)]";

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
    unsafe_level: &'static str,
}

const LOCAL_EXCEPTIONS: [LocalException; 3] = [
    LocalException {
        package: "fre-capi",
        manifest: "crates/fre-capi/Cargo.toml",
        unsafe_level: "warn",
    },
    LocalException {
        package: "fre-jit-runtime",
        manifest: "crates/fre-jit-runtime/Cargo.toml",
        unsafe_level: "warn",
    },
    LocalException {
        package: KERNEL_PACKAGE,
        manifest: "crates/fre-kernels/Cargo.toml",
        unsafe_level: "deny",
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
            if lints.contains_key("workspace") {
                return Err(format!(
                    "local lint exception {name} unexpectedly inherits workspace lints"
                ));
            }
            let actual_level = lints
                .get("rust")
                .and_then(toml::Value::as_table)
                .and_then(|rust| rust.get("unsafe_code"))
                .and_then(toml::Value::as_str)
                .ok_or_else(|| format!("local lint exception {name} has no unsafe_code level"))?;
            if actual_level != exception.unsafe_level {
                return Err(format!(
                    "local lint exception {name} uses unsafe_code={actual_level:?}, expected {:?}",
                    exception.unsafe_level
                ));
            }
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
            if target.name != KERNEL_LIBRARY || !target.kind.iter().any(|kind| kind == "lib") {
                return Err(format!(
                    "expected library path belongs to unexpected target {} kind {:?}",
                    target.name, target.kind
                ));
            }
            require_attribute(&source, DENY_ATTRIBUTE, false, &target.name)?;
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
    use super::{Package, Target, audit_kernel_targets};
    use std::{
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

    fn package(tree: &TestTree, additional: Vec<Target>) -> Package {
        let library = tree.write(
            "crates/fre-kernels/src/lib.rs",
            "//! fixture\n#![deny(unsafe_code)]\n",
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

    #[test]
    fn integration_test_escape_is_rejected() {
        let tree = TestTree::new();
        let escape = tree.write(
            "crates/fre-kernels/tests/lint_escape.rs",
            "#![allow(unsafe_code)]\nfn escape() {}\n",
        );
        let package = package(&tree, vec![target("lint_escape", "test", escape)]);
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
        let package = package(&tree, vec![target("custom_escape", "example", escape)]);
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
        let package = package(
            &tree,
            vec![
                target("protected", "test", integration),
                target("custom_protected", "example", custom),
            ],
        );
        assert_eq!(audit_kernel_targets(&package, tree.root()), Ok(2));
    }
}
