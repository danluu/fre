//! Domain-separated, raw-free identity for one manifest pattern/profile key.

use sha2::{Digest, Sha256};

const MANIFEST_PROFILE_KEY_DOMAIN: &[u8] =
    b"FRE-RIPGREP-AOT-THIN-MANIFEST-PROFILE-KEY\0\x01";
const EXACT64_SET_REGISTRY_KEY_DOMAIN: &[u8] =
    b"FRE-RIPGREP-AOT-THIN-EXACT64-SET-REGISTRY-KEY\0\x01";
const EXACT64_SET_SUPPORTED_PROFILE_V1: &[u8] =
    b"optimizing-exists/rust-regex-bytes-1.12.4/lf/raw/unicode/case-v1";

pub(crate) fn manifest_profile_key(pattern: &str, case_insensitive: bool) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(MANIFEST_PROFILE_KEY_DOMAIN);
    digest.update([u8::from(case_insensitive)]);
    digest.update(pattern.as_bytes());
    digest.finalize().into()
}

/// Bind one supported exact64 set to its complete ordered source vector.
///
/// The profile domain fixes every supported semantic option except the one
/// explicit case bit. A source count and one width before every source make
/// order, duplicates, and otherwise concatenation-equivalent vectors distinct.
pub(crate) fn exact64_set_registry_key(patterns: &[&str], case_insensitive: bool) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(EXACT64_SET_REGISTRY_KEY_DOMAIN);
    digest.update(EXACT64_SET_SUPPORTED_PROFILE_V1);
    digest.update([u8::from(case_insensitive)]);
    digest.update(
        u64::try_from(patterns.len())
            .expect("supported targets represent an exact64 source count as u64")
            .to_le_bytes(),
    );
    for pattern in patterns {
        digest.update(
            u64::try_from(pattern.len())
                .expect("supported targets represent a regex source width as u64")
                .to_le_bytes(),
        );
        digest.update(pattern.as_bytes());
    }
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact64_key_binds_order_duplicates_boundaries_and_case_profile() {
        let ordered = exact64_set_registry_key(&["a", "bc"], false);
        assert_ne!(ordered, exact64_set_registry_key(&["ab", "c"], false));
        assert_ne!(ordered, exact64_set_registry_key(&["bc", "a"], false));
        assert_ne!(ordered, exact64_set_registry_key(&["a", "bc", "bc"], false));
        assert_ne!(ordered, exact64_set_registry_key(&["a", "bc"], true));
        assert_eq!(
            exact64_set_registry_key(&["dup", "dup"], false),
            exact64_set_registry_key(&["dup", "dup"], false)
        );
    }
}
