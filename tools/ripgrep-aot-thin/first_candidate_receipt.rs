//! Canonical raw-free identity for a first-candidate build receipt.

use sha2::{Digest, Sha256};

const FIRST_CANDIDATE_RECEIPT_IDENTITY_DOMAIN: &[u8] =
    b"FRE-RIPGREP-AOT-THIN-EXACT-SINGLETON-FIRST-CANDIDATE-RECEIPT\0\x01";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FirstCandidateReceiptIdentityInputV1 {
    pub(crate) manifest_profile_key: [u8; 32],
    pub(crate) case_insensitive: bool,
    pub(crate) schema_version: u32,
    pub(crate) strategy: u8,
    pub(crate) semantics: u8,
    pub(crate) abi: u8,
    pub(crate) miss_sentinel: u64,
    pub(crate) literal_bytes: usize,
    pub(crate) literal_sha256: [u8; 32],
    pub(crate) target_architecture: u8,
    pub(crate) target_operating_system: u8,
    pub(crate) target_features: u64,
    pub(crate) required_features: u64,
    pub(crate) emitted_isa: u8,
    pub(crate) cursor_register: u8,
    pub(crate) success_edge_count: u8,
    pub(crate) success_edges_sha256: [u8; 32],
    pub(crate) trusted_core_offset: usize,
    pub(crate) trusted_core_sha256: [u8; 32],
    pub(crate) ordinary_entry_symbol_sha256: [u8; 32],
    pub(crate) ordinary_entry_code_sha256: [u8; 32],
    pub(crate) wrapper_entry_offset: usize,
    pub(crate) wrapper_bytes: usize,
    pub(crate) wrapper_sha256: [u8; 32],
    pub(crate) endpoint_symbol_sha256: [u8; 32],
    pub(crate) native_code_sha256: [u8; 32],
    pub(crate) relocations_sha256: [u8; 32],
    pub(crate) object_sha256: [u8; 32],
    pub(crate) runtime_call_count: u8,
}

impl FirstCandidateReceiptIdentityInputV1 {
    pub(crate) fn identity(self) -> Option<[u8; 32]> {
        let mut digest = Sha256::new();
        digest.update(FIRST_CANDIDATE_RECEIPT_IDENTITY_DOMAIN);
        digest.update(self.manifest_profile_key);
        digest.update([u8::from(self.case_insensitive)]);
        digest.update(self.schema_version.to_le_bytes());
        digest.update([self.strategy, self.semantics, self.abi]);
        digest.update(self.miss_sentinel.to_le_bytes());
        update_usize(&mut digest, self.literal_bytes)?;
        digest.update(self.literal_sha256);
        digest.update([self.target_architecture, self.target_operating_system]);
        digest.update(self.target_features.to_le_bytes());
        digest.update(self.required_features.to_le_bytes());
        digest.update([self.emitted_isa, self.cursor_register]);
        digest.update([self.success_edge_count]);
        digest.update(self.success_edges_sha256);
        update_usize(&mut digest, self.trusted_core_offset)?;
        digest.update(self.trusted_core_sha256);
        digest.update(self.ordinary_entry_symbol_sha256);
        digest.update(self.ordinary_entry_code_sha256);
        update_usize(&mut digest, self.wrapper_entry_offset)?;
        update_usize(&mut digest, self.wrapper_bytes)?;
        digest.update(self.wrapper_sha256);
        digest.update(self.endpoint_symbol_sha256);
        digest.update(self.native_code_sha256);
        digest.update(self.relocations_sha256);
        digest.update(self.object_sha256);
        digest.update([self.runtime_call_count]);
        Some(digest.finalize().into())
    }
}

fn update_usize(digest: &mut Sha256, value: usize) -> Option<()> {
    digest.update(u64::try_from(value).ok()?.to_le_bytes());
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> FirstCandidateReceiptIdentityInputV1 {
        FirstCandidateReceiptIdentityInputV1 {
            manifest_profile_key: [1; 32],
            case_insensitive: false,
            schema_version: 1,
            strategy: 1,
            semantics: 1,
            abi: 1,
            miss_sentinel: u64::MAX,
            literal_bytes: 7,
            literal_sha256: [2; 32],
            target_architecture: 1,
            target_operating_system: 2,
            target_features: 3,
            required_features: 1,
            emitted_isa: 2,
            cursor_register: 2,
            success_edge_count: 4,
            success_edges_sha256: [3; 32],
            trusted_core_offset: 5,
            trusted_core_sha256: [4; 32],
            ordinary_entry_symbol_sha256: [5; 32],
            ordinary_entry_code_sha256: [6; 32],
            wrapper_entry_offset: 7,
            wrapper_bytes: 8,
            wrapper_sha256: [7; 32],
            endpoint_symbol_sha256: [8; 32],
            native_code_sha256: [9; 32],
            relocations_sha256: [10; 32],
            object_sha256: [11; 32],
            runtime_call_count: 0,
        }
    }

    #[test]
    fn identity_binds_early_middle_and_late_fields() {
        let original = input();
        let expected = original.identity().expect("identity");
        let mut changed = original;
        changed.manifest_profile_key[0] ^= 1;
        assert_ne!(changed.identity().expect("changed key"), expected);
        let mut changed = original;
        changed.trusted_core_offset += 1;
        assert_ne!(changed.identity().expect("changed core"), expected);
        let mut changed = original;
        changed.object_sha256[31] ^= 1;
        assert_ne!(changed.identity().expect("changed object"), expected);
    }
}
