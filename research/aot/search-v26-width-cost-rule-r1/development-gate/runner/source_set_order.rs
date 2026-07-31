use std::path::{Path, PathBuf};

pub(crate) fn canonical_relative_source_name<'a>(root: &Path, path: &'a Path) -> &'a str {
    path.strip_prefix(root)
        .expect("source-set path is below manifest root")
        .to_str()
        .expect("runner source-set path is UTF-8")
}

pub(crate) fn sort_source_paths(root: &Path, paths: &mut [PathBuf]) {
    paths.sort_by(|left, right| {
        canonical_relative_source_name(root, left)
            .as_bytes()
            .cmp(canonical_relative_source_name(root, right).as_bytes())
    });
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{canonical_relative_source_name, sort_source_paths};

    #[test]
    fn canonical_full_path_bytes_override_component_order() {
        let root = Path::new("/repo");
        let aggregate = root.join("crates/fre-aggregate/Cargo.toml");
        let fre = root.join("crates/fre/Cargo.toml");
        let mut component_order = vec![aggregate.clone(), fre.clone()];
        component_order.sort();
        assert_eq!(component_order, [fre.clone(), aggregate.clone()]);

        sort_source_paths(root, &mut component_order);
        assert_eq!(component_order, [aggregate, fre]);
        assert_eq!(
            component_order
                .iter()
                .map(|path| canonical_relative_source_name(root, path))
                .collect::<Vec<_>>(),
            ["crates/fre-aggregate/Cargo.toml", "crates/fre/Cargo.toml",]
        );
    }

    #[cfg(unix)]
    #[test]
    #[should_panic(expected = "runner source-set path is UTF-8")]
    fn non_utf8_relative_path_is_rejected() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt as _};

        let root = Path::new("/repo");
        let invalid = root.join(PathBuf::from(OsString::from_vec(vec![0xff])));
        let _ = canonical_relative_source_name(root, &invalid);
    }
}
