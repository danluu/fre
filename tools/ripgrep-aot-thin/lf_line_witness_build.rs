//! Build transaction for stateless matching-LF-line witness entries.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use fre_aot_regex::{
    Architecture, CompileMode, CompiledRegex, MATCHING_LF_LINE_WITNESS_AOT_SCHEMA_VERSION,
    MATCHING_LF_LINE_WITNESS_MISS, MatchingLfLineWitnessAbi, MatchingLfLineWitnessCursorRegister,
    MatchingLfLineWitnessSemantics, MatchingLfLineWitnessStrategy, OperatingSystem, OutputContract,
    Target,
};
use sha2::{Digest, Sha256};

use crate::build_proof::MatchingLfLineWitnessSourceProof;
use crate::build_support::Pattern;
use crate::lf_line_witness_receipt::MatchingLfLineWitnessReceiptIdentityInputV1;
use crate::registry_key::manifest_profile_key;

pub(crate) struct MatchingLfLineWitnessRegistryBuild {
    declarations: String,
    rows: String,
    admitted_keys: BTreeSet<[u8; 32]>,
    independently_eligible: usize,
    admitted: usize,
}

impl MatchingLfLineWitnessRegistryBuild {
    pub(crate) const fn new() -> Self {
        Self {
            declarations: String::new(),
            rows: String::new(),
            admitted_keys: BTreeSet::new(),
            independently_eligible: 0,
            admitted: 0,
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "independent language proof and complete compiler/object authentication form one fail-closed admission"
    )]
    pub(crate) fn consider(
        &mut self,
        pattern: &Pattern,
        target: Target,
        compiled: &CompiledRegex,
        independent_proof: Option<MatchingLfLineWitnessSourceProof>,
    ) {
        let module = compiled.module();
        let receipt = compiled.receipt();
        let symbol = module.direct_matching_lf_line_witness_symbol();
        let strategy = module.direct_matching_lf_line_witness_strategy();
        let module_report = module.direct_matching_lf_line_witness_aot_report();
        let receipt_report = receipt.matching_lf_line_witness_aot.as_ref();

        let Some(proof) = independent_proof else {
            // Compiler availability is never a substitute for this adapter's
            // independent exact-language proof.
            return;
        };
        self.independently_eligible += 1;

        let (symbol, module_report, receipt_report) =
            match (symbol, strategy, module_report, receipt_report) {
                (None, None, None, None) => return,
                (
                    Some(symbol),
                    Some(MatchingLfLineWitnessStrategy::NativeCompleteDfaTrustedCoreV1),
                    Some(module_report),
                    Some(receipt_report),
                ) => (symbol, module_report, receipt_report),
                _ => panic!("compiler published an incomplete matching-LF-line witness receipt"),
            };

        let serialized_program = compiled
            .program()
            .serialize()
            .expect("a compiled program remains serializable during registry admission");
        let program_sha256: [u8; 32] = Sha256::digest(&serialized_program).into();
        let endpoint_symbol_sha256: [u8; 32] = Sha256::digest(symbol.as_bytes()).into();
        let ordinary_entry_symbol_sha256: [u8; 32] =
            Sha256::digest(module.entry_symbol().as_bytes()).into();
        let object_sha256: [u8; 32] = Sha256::digest(compiled.object()).into();
        let hashes = [
            proof.language_sha256,
            module_report.program_sha256,
            module_report.success_edges_sha256,
            module_report.trusted_core_sha256,
            module_report.ordinary_entry_symbol_sha256,
            module_report.ordinary_entry_code_sha256,
            module_report.wrapper_sha256,
            module_report.endpoint_symbol_sha256,
            module_report.native_code_sha256,
            module_report.relocations_sha256,
            receipt.object_sha256,
        ];
        assert!(
            module_report == receipt_report
                && module_report.schema_version == MATCHING_LF_LINE_WITNESS_AOT_SCHEMA_VERSION
                && module_report.semantics == MatchingLfLineWitnessSemantics::MatchingLfLineByteV1
                && module_report.abi == MatchingLfLineWitnessAbi::HaystackLenU64OutStatusV1
                && module_report.miss_sentinel == MATCHING_LF_LINE_WITNESS_MISS
                && module_report.target == target
                && receipt.mode == CompileMode::Optimizing
                && receipt.output == OutputContract::Exists
                && receipt.target == target
                && receipt.line_terminator == b'\n'
                && proof.source_count != 0
                && proof.source_bytes != 0
                && proof.minimum_width != 0
                && proof.minimum_width <= proof.maximum_width
                && module_report.program_bytes == serialized_program.len()
                && module_report.program_sha256 == program_sha256
                && receipt.program_sha256 == program_sha256
                && cursor_matches_architecture(target.architecture, module_report.cursor_register)
                && module_report.success_edge_count != 0
                && u16::from(module_report.inside_match_edge_count)
                    + u16::from(module_report.exclusive_end_edge_count)
                    == u16::from(module_report.success_edge_count)
                && module_report.wrapper_bytes != 0
                && module_report.ordinary_entry_symbol_sha256 == ordinary_entry_symbol_sha256
                && module_report.endpoint_symbol_sha256 == endpoint_symbol_sha256
                && module_report.runtime_call_count == 0
                && receipt.object_sha256 == object_sha256
                && receipt.object_bytes == compiled.object().len()
                && !receipt.runtime_helper_required
                && module.required_runtime_symbols().next().is_none()
                && module.required_runtime_program().is_none()
                && hashes.iter().all(|hash| *hash != [0; 32]),
            "matching-LF-line witness compiler report/object authentication failed"
        );

        let registry_key = manifest_profile_key(&pattern.source, pattern.case_insensitive);
        if !self.admitted_keys.insert(registry_key) {
            return;
        }
        let declaration = format!("matching_lf_line_witness_{}", self.admitted);
        writeln!(
            &mut self.declarations,
            "    #[link_name = {symbol:?}] fn {declaration}(haystack: *const u8, haystack_len: usize, position: *mut u64) -> u32;"
        )
        .expect("String writes cannot fail");
        let description = format!(
            "mode=optimizing,output=exists,route=direct-native,api=matching-lf-line-witness-v1,proof=independent-exact-finite-nonempty-assertion-free-lf-free,sources={},source_bytes={},width={}..={},target={}-{},features={:#x}",
            proof.source_count,
            proof.source_bytes,
            proof.minimum_width,
            proof.maximum_width,
            architecture_name(target.architecture),
            os_name(target.operating_system),
            target.features.bits(),
        );
        let receipt_identity_sha256 = MatchingLfLineWitnessReceiptIdentityInputV1 {
            manifest_profile_key: registry_key,
            case_insensitive: pattern.case_insensitive,
            source_count: proof.source_count,
            source_bytes: proof.source_bytes,
            minimum_width: proof.minimum_width,
            maximum_width: proof.maximum_width,
            source_language_sha256: proof.language_sha256,
            schema_version: module_report.schema_version,
            strategy: strategy_code(MatchingLfLineWitnessStrategy::NativeCompleteDfaTrustedCoreV1),
            semantics: semantics_code(module_report.semantics),
            abi: abi_code(module_report.abi),
            miss_sentinel: module_report.miss_sentinel,
            target_architecture: architecture_code(target.architecture),
            target_operating_system: os_code(target.operating_system),
            target_features: target.features.bits(),
            program_bytes: module_report.program_bytes,
            program_sha256: module_report.program_sha256,
            cursor_register: cursor_code(module_report.cursor_register),
            success_edge_count: module_report.success_edge_count,
            inside_match_edge_count: module_report.inside_match_edge_count,
            exclusive_end_edge_count: module_report.exclusive_end_edge_count,
            success_edges_sha256: module_report.success_edges_sha256,
            trusted_core_offset: module_report.trusted_core_offset,
            trusted_core_sha256: module_report.trusted_core_sha256,
            ordinary_entry_symbol_sha256: module_report.ordinary_entry_symbol_sha256,
            ordinary_entry_code_sha256: module_report.ordinary_entry_code_sha256,
            wrapper_entry_offset: module_report.wrapper_entry_offset,
            wrapper_bytes: module_report.wrapper_bytes,
            wrapper_sha256: module_report.wrapper_sha256,
            endpoint_symbol_sha256: module_report.endpoint_symbol_sha256,
            native_code_sha256: module_report.native_code_sha256,
            relocations_sha256: module_report.relocations_sha256,
            object_sha256: receipt.object_sha256,
            runtime_call_count: module_report.runtime_call_count,
        }
        .identity()
        .expect("supported targets represent every receipt width as u64");
        assert_ne!(
            receipt_identity_sha256, [0; 32],
            "matching-LF-line witness receipt identity must be nonzero"
        );
        writeln!(
            &mut self.rows,
            "    MatchingLfLineWitnessSpec {{ manifest_profile_key: {registry_key:?}, description: {description:?}, entry_symbol: {symbol:?}, entry: {declaration}, receipt: AotMatchingLfLineWitnessReceiptV1 {{ manifest_profile_key: {registry_key:?}, case_insensitive: {}, source_count: {}, source_bytes: {}, minimum_width: {}, maximum_width: {}, source_language_sha256: {:?}, schema_version: {}, strategy: {}, semantics: {}, abi: {}, miss_sentinel: {}, target_architecture: {}, target_operating_system: {}, target_features: {}, program_bytes: {}, program_sha256: {:?}, cursor_register: {}, success_edge_count: {}, inside_match_edge_count: {}, exclusive_end_edge_count: {}, success_edges_sha256: {:?}, trusted_core_offset: {}, trusted_core_sha256: {:?}, ordinary_entry_symbol_sha256: {:?}, ordinary_entry_code_sha256: {:?}, wrapper_entry_offset: {}, wrapper_bytes: {}, wrapper_sha256: {:?}, endpoint_symbol_sha256: {:?}, native_code_sha256: {:?}, relocations_sha256: {:?}, object_sha256: {:?}, runtime_call_count: {}, receipt_identity_sha256: {receipt_identity_sha256:?} }} }},",
            pattern.case_insensitive,
            proof.source_count,
            proof.source_bytes,
            proof.minimum_width,
            proof.maximum_width,
            proof.language_sha256,
            module_report.schema_version,
            strategy_code(MatchingLfLineWitnessStrategy::NativeCompleteDfaTrustedCoreV1),
            semantics_code(module_report.semantics),
            abi_code(module_report.abi),
            module_report.miss_sentinel,
            architecture_code(target.architecture),
            os_code(target.operating_system),
            target.features.bits(),
            module_report.program_bytes,
            module_report.program_sha256,
            cursor_code(module_report.cursor_register),
            module_report.success_edge_count,
            module_report.inside_match_edge_count,
            module_report.exclusive_end_edge_count,
            module_report.success_edges_sha256,
            module_report.trusted_core_offset,
            module_report.trusted_core_sha256,
            module_report.ordinary_entry_symbol_sha256,
            module_report.ordinary_entry_code_sha256,
            module_report.wrapper_entry_offset,
            module_report.wrapper_bytes,
            module_report.wrapper_sha256,
            module_report.endpoint_symbol_sha256,
            module_report.native_code_sha256,
            module_report.relocations_sha256,
            receipt.object_sha256,
            module_report.runtime_call_count,
        )
        .expect("String writes cannot fail");
        self.admitted += 1;
    }

    pub(crate) fn finish(self, target: Target, public_fixture_selected: bool) -> String {
        let mut source = format!(
            "#[allow(unused_imports, reason = \"the matching-LF-line witness registry may be empty\")]\nuse super::{{AotMatchingLfLineWitnessReceiptV1, MatchingLfLineWitnessSpec}};\n\n#[allow(dead_code, reason = \"pins runtime authentication to the exact build target\")]\npub(super) const BUILD_LF_LINE_WITNESS_TARGET_FEATURES: u64 = {};\n#[allow(dead_code, reason = \"checked by focused generated-registry tests\")]\npub(super) const BUILD_LF_LINE_WITNESS_PUBLIC_FIXTURE_SELECTED: bool = {};\n#[allow(dead_code, reason = \"checked by focused generated-registry tests\")]\npub(super) const BUILD_LF_LINE_WITNESS_INDEPENDENTLY_ELIGIBLE_COUNT: usize = {};\n#[allow(dead_code, reason = \"checked by focused generated-registry tests\")]\npub(super) const BUILD_LF_LINE_WITNESS_ADMITTED_COUNT: usize = {};\n",
            target.features.bits(),
            public_fixture_selected,
            self.independently_eligible,
            self.admitted,
        );
        if !self.declarations.is_empty() {
            source.push_str(
                "\n#[allow(unsafe_code, reason = \"audited declarations for compiler-authenticated stateless matching-LF-line entries\")]\nunsafe extern \"C\" {\n",
            );
            source.push_str(&self.declarations);
            source.push_str("}\n");
        }
        source.push_str(
            "\npub(super) const MATCHING_LF_LINE_WITNESS_SPECS: &[MatchingLfLineWitnessSpec] = &[\n",
        );
        source.push_str(&self.rows);
        source.push_str("];\n");
        source
    }
}

const fn strategy_code(value: MatchingLfLineWitnessStrategy) -> u8 {
    match value {
        MatchingLfLineWitnessStrategy::NativeCompleteDfaTrustedCoreV1 => 1,
    }
}

const fn semantics_code(value: MatchingLfLineWitnessSemantics) -> u8 {
    match value {
        MatchingLfLineWitnessSemantics::MatchingLfLineByteV1 => 1,
    }
}

const fn abi_code(value: MatchingLfLineWitnessAbi) -> u8 {
    match value {
        MatchingLfLineWitnessAbi::HaystackLenU64OutStatusV1 => 1,
    }
}

const fn cursor_code(value: MatchingLfLineWitnessCursorRegister) -> u8 {
    match value {
        MatchingLfLineWitnessCursorRegister::X86Rdx => 1,
        MatchingLfLineWitnessCursorRegister::Aarch64X2 => 2,
    }
}

const fn cursor_matches_architecture(
    architecture: Architecture,
    cursor: MatchingLfLineWitnessCursorRegister,
) -> bool {
    matches!(
        (architecture, cursor),
        (
            Architecture::X86_64,
            MatchingLfLineWitnessCursorRegister::X86Rdx
        ) | (
            Architecture::Aarch64,
            MatchingLfLineWitnessCursorRegister::Aarch64X2
        )
    )
}

const fn architecture_code(value: Architecture) -> u8 {
    match value {
        Architecture::Aarch64 => 1,
        Architecture::X86_64 => 2,
    }
}

const fn os_code(value: OperatingSystem) -> u8 {
    match value {
        OperatingSystem::Linux => 1,
        OperatingSystem::Macos => 2,
    }
}

const fn architecture_name(value: Architecture) -> &'static str {
    match value {
        Architecture::Aarch64 => "aarch64",
        Architecture::X86_64 => "x86_64",
    }
}

const fn os_name(value: OperatingSystem) -> &'static str {
    match value {
        OperatingSystem::Linux => "linux",
        OperatingSystem::Macos => "macos",
    }
}
