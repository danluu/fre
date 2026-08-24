//! Domain-separated, raw-free identity for one manifest pattern/profile key.

use sha2::{Digest, Sha256};

const MANIFEST_PROFILE_KEY_DOMAIN: &[u8] =
    b"FRE-RIPGREP-AOT-THIN-MANIFEST-PROFILE-KEY\0\x01";

pub(crate) fn manifest_profile_key(pattern: &str, case_insensitive: bool) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(MANIFEST_PROFILE_KEY_DOMAIN);
    digest.update([u8::from(case_insensitive)]);
    digest.update(pattern.as_bytes());
    digest.finalize().into()
}
