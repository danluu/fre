//! Canonical raw-free identity for a matching-LF-line witness receipt.

use sha2::{Digest, Sha256};

const MATCHING_LF_LINE_WITNESS_RECEIPT_IDENTITY_DOMAIN: &[u8] =
    b"FRE-RIPGREP-AOT-THIN-MATCHING-LF-LINE-WITNESS-RECEIPT\0\x01";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MatchingLfLineWitnessReceiptIdentityInputV1 {
    pub(crate) manifest_profile_key: [u8; 32],
    pub(crate) case_insensitive: bool,
    pub(crate) source_count: usize,
    pub(crate) source_bytes: usize,
    pub(crate) minimum_width: usize,
    pub(crate) maximum_width: usize,
    pub(crate) source_language_sha256: [u8; 32],
    pub(crate) compiler_literal_sha256: [u8; 32],
    pub(crate) compiler_source_count: usize,
    pub(crate) compiler_source_bytes: usize,
    pub(crate) compiler_minimum_width: usize,
    pub(crate) compiler_maximum_width: usize,
    pub(crate) schema_version: u32,
    pub(crate) strategy: u8,
    pub(crate) semantics: u8,
    pub(crate) abi: u8,
    pub(crate) miss_sentinel: u64,
    pub(crate) target_architecture: u8,
    pub(crate) target_operating_system: u8,
    pub(crate) target_features: u64,
    pub(crate) program_bytes: usize,
    pub(crate) program_sha256: [u8; 32],
    pub(crate) cursor_register: u8,
    pub(crate) success_edge_count: u8,
    pub(crate) inside_match_edge_count: u8,
    pub(crate) exclusive_end_edge_count: u8,
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

impl MatchingLfLineWitnessReceiptIdentityInputV1 {
    pub(crate) fn identity(self) -> Option<[u8; 32]> {
        let mut digest = Sha256::new();
        digest.update(MATCHING_LF_LINE_WITNESS_RECEIPT_IDENTITY_DOMAIN);
        digest.update(self.manifest_profile_key);
        digest.update([u8::from(self.case_insensitive)]);
        update_usize(&mut digest, self.source_count)?;
        update_usize(&mut digest, self.source_bytes)?;
        update_usize(&mut digest, self.minimum_width)?;
        update_usize(&mut digest, self.maximum_width)?;
        digest.update(self.source_language_sha256);
        digest.update(self.compiler_literal_sha256);
        update_usize(&mut digest, self.compiler_source_count)?;
        update_usize(&mut digest, self.compiler_source_bytes)?;
        update_usize(&mut digest, self.compiler_minimum_width)?;
        update_usize(&mut digest, self.compiler_maximum_width)?;
        digest.update(self.schema_version.to_le_bytes());
        digest.update([self.strategy, self.semantics, self.abi]);
        digest.update(self.miss_sentinel.to_le_bytes());
        digest.update([self.target_architecture, self.target_operating_system]);
        digest.update(self.target_features.to_le_bytes());
        update_usize(&mut digest, self.program_bytes)?;
        digest.update(self.program_sha256);
        digest.update([self.cursor_register]);
        digest.update([
            self.success_edge_count,
            self.inside_match_edge_count,
            self.exclusive_end_edge_count,
        ]);
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

    fn input() -> MatchingLfLineWitnessReceiptIdentityInputV1 {
        MatchingLfLineWitnessReceiptIdentityInputV1 {
            manifest_profile_key: [1; 32],
            case_insensitive: false,
            source_count: 3,
            source_bytes: 17,
            minimum_width: 4,
            maximum_width: 8,
            source_language_sha256: [2; 32],
            compiler_literal_sha256: [13; 32],
            compiler_source_count: 3,
            compiler_source_bytes: 17,
            compiler_minimum_width: 4,
            compiler_maximum_width: 8,
            schema_version: 2,
            strategy: 2,
            semantics: 1,
            abi: 1,
            miss_sentinel: u64::MAX,
            target_architecture: 2,
            target_operating_system: 2,
            target_features: 3,
            program_bytes: 101,
            program_sha256: [3; 32],
            cursor_register: 1,
            success_edge_count: 4,
            inside_match_edge_count: 2,
            exclusive_end_edge_count: 2,
            success_edges_sha256: [4; 32],
            trusted_core_offset: 5,
            trusted_core_sha256: [5; 32],
            ordinary_entry_symbol_sha256: [6; 32],
            ordinary_entry_code_sha256: [7; 32],
            wrapper_entry_offset: 8,
            wrapper_bytes: 9,
            wrapper_sha256: [8; 32],
            endpoint_symbol_sha256: [9; 32],
            native_code_sha256: [10; 32],
            relocations_sha256: [11; 32],
            object_sha256: [12; 32],
            runtime_call_count: 0,
        }
    }

    #[test]
    fn identity_binds_source_routes_and_object() {
        let original = input();
        let expected = original.identity().expect("identity");
        let mut changed = original;
        changed.source_language_sha256[0] ^= 1;
        assert_ne!(changed.identity().expect("changed source"), expected);
        let mut changed = original;
        changed.compiler_literal_sha256[0] ^= 1;
        assert_ne!(
            changed.identity().expect("changed compiler language"),
            expected
        );
        let mut changed = original;
        changed.exclusive_end_edge_count += 1;
        assert_ne!(changed.identity().expect("changed route"), expected);
        let mut changed = original;
        changed.object_sha256[31] ^= 1;
        assert_ne!(changed.identity().expect("changed object"), expected);
    }
}
