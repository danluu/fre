//! Build transaction for stateless exact-singleton first-candidate entries.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use fre_aot_regex::{
    Architecture, CompiledRegex, CpuFeature, EXACT_SINGLETON_FIRST_CANDIDATE_AOT_SCHEMA_VERSION,
    EXACT_SINGLETON_FIRST_CANDIDATE_MISS, ExactSingleLiteralAotIsa,
    ExactSingletonFirstCandidateAbi, ExactSingletonFirstCandidateCursorRegister,
    ExactSingletonFirstCandidateSemantics, ExactSingletonFirstCandidateStrategy, OperatingSystem,
    Target,
};
use sha2::{Digest, Sha256};

use crate::build_support::Pattern;
use crate::first_candidate_receipt::FirstCandidateReceiptIdentityInputV1;
use crate::registry_key::manifest_profile_key;

pub(crate) struct FirstCandidateRegistryBuild {
    declarations: String,
    rows: String,
    admitted_keys: BTreeSet<[u8; 32]>,
    independently_eligible: usize,
    admitted: usize,
}

impl FirstCandidateRegistryBuild {
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
        reason = "independent proof, compiler report, object closure, and raw-free publication are one fail-closed admission"
    )]
    pub(crate) fn consider(
        &mut self,
        pattern: &Pattern,
        target: Target,
        compiled: &CompiledRegex,
        independent_literal: Option<&[u8]>,
    ) {
        let module = compiled.module();
        let receipt = compiled.receipt();
        let symbol = module.direct_exact_singleton_first_candidate_symbol();
        let strategy = module.direct_exact_singleton_first_candidate_strategy();
        let module_report = module.direct_exact_singleton_first_candidate_aot_report();
        let receipt_report = receipt.exact_singleton_first_candidate_aot.as_ref();

        let Some(literal) = independent_literal else {
            // The compiler may possess a different bounded proof portfolio.
            // Without this adapter's independent exact-language proof, the
            // additive registry simply does not publish its endpoint.
            return;
        };
        self.independently_eligible += 1;

        let (symbol, module_report, receipt_report) = match (
            symbol,
            strategy,
            module_report,
            receipt_report,
        ) {
            (None, None, None, None) => return,
            (
                Some(symbol),
                Some(ExactSingletonFirstCandidateStrategy::NativeTwoWayTrustedCoreV1),
                Some(module_report),
                Some(receipt_report),
            ) => (symbol, module_report, receipt_report),
            _ => panic!(
                "compiler published an incomplete exact-singleton first-candidate endpoint receipt"
            ),
        };

        let literal_sha256: [u8; 32] = Sha256::digest(literal).into();
        let endpoint_symbol_sha256: [u8; 32] = Sha256::digest(symbol.as_bytes()).into();
        let ordinary_entry_symbol_sha256: [u8; 32] =
            Sha256::digest(module.entry_symbol().as_bytes()).into();
        let object_sha256: [u8; 32] = Sha256::digest(compiled.object()).into();
        let hashes = [
            module_report.literal_sha256,
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
                && module_report.schema_version
                    == EXACT_SINGLETON_FIRST_CANDIDATE_AOT_SCHEMA_VERSION
                && module_report.semantics
                    == ExactSingletonFirstCandidateSemantics::EarliestInclusiveFinalByteV1
                && module_report.abi == ExactSingletonFirstCandidateAbi::HaystackLenU64OutStatusV1
                && module_report.miss_sentinel == EXACT_SINGLETON_FIRST_CANDIDATE_MISS
                && module_report.target == target
                && target.features.contains(module_report.required_features)
                && module_report.required_features
                    == required_features_for_isa(module_report.emitted_isa)
                && isa_matches_architecture(target.architecture, module_report.emitted_isa)
                && cursor_matches_architecture(
                    target.architecture,
                    module_report.cursor_register,
                )
                && module_report.literal_bytes == literal.len()
                && module_report.literal_sha256 == literal_sha256
                && module_report.success_edge_count != 0
                && module_report.wrapper_bytes != 0
                && module_report.ordinary_entry_symbol_sha256 == ordinary_entry_symbol_sha256
                && module_report.endpoint_symbol_sha256 == endpoint_symbol_sha256
                && module_report.runtime_call_count == 0
                && receipt.object_sha256 == object_sha256
                && receipt.object_bytes == compiled.object().len()
                && module.required_runtime_symbols().next().is_none()
                && module.required_runtime_program().is_none()
                && hashes.iter().all(|hash| *hash != [0; 32]),
            "exact-singleton first-candidate compiler report/object authentication failed"
        );

        let registry_key = manifest_profile_key(&pattern.source, pattern.case_insensitive);
        // Multiple manifest IDs may intentionally name the same source and
        // case profile. They select the same stateless endpoint contract, so
        // publish one key instead of making the additive registry ambiguous.
        if !self.admitted_keys.insert(registry_key) {
            return;
        }
        let declaration = format!("exact_singleton_first_candidate_{}", self.admitted);
        writeln!(
            &mut self.declarations,
            "    #[link_name = {symbol:?}] fn {declaration}(haystack: *const u8, haystack_len: usize, position: *mut u64) -> u32;"
        )
        .expect("String writes cannot fail");
        let description = format!(
            "mode=optimizing,output=exists,route=direct-native,api=exact-singleton-first-candidate-v1,proof=independent-and-compiler-exact-nonempty-lf-free,literal_bytes={},target={}-{},features={:#x},isa={}",
            literal.len(),
            architecture_name(target.architecture),
            os_name(target.operating_system),
            target.features.bits(),
            isa_name(module_report.emitted_isa),
        );
        let receipt_identity_sha256 = FirstCandidateReceiptIdentityInputV1 {
            manifest_profile_key: registry_key,
            case_insensitive: pattern.case_insensitive,
            schema_version: module_report.schema_version,
            strategy: strategy_code(
                ExactSingletonFirstCandidateStrategy::NativeTwoWayTrustedCoreV1,
            ),
            semantics: semantics_code(module_report.semantics),
            abi: abi_code(module_report.abi),
            miss_sentinel: module_report.miss_sentinel,
            literal_bytes: module_report.literal_bytes,
            literal_sha256: module_report.literal_sha256,
            target_architecture: architecture_code(target.architecture),
            target_operating_system: os_code(target.operating_system),
            target_features: target.features.bits(),
            required_features: module_report.required_features.bits(),
            emitted_isa: isa_code(module_report.emitted_isa),
            cursor_register: cursor_code(module_report.cursor_register),
            success_edge_count: module_report.success_edge_count,
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
        writeln!(
            &mut self.rows,
            "    ExactSingletonFirstCandidateSpec {{ manifest_profile_key: {registry_key:?}, description: {description:?}, entry_symbol: {symbol:?}, entry: {declaration}, receipt: AotExactSingletonFirstCandidateReceiptV1 {{ manifest_profile_key: {registry_key:?}, case_insensitive: {}, schema_version: {}, strategy: {}, semantics: {}, abi: {}, miss_sentinel: {}, literal_bytes: {}, literal_sha256: {:?}, target_architecture: {}, target_operating_system: {}, target_features: {}, required_features: {}, emitted_isa: {}, cursor_register: {}, success_edge_count: {}, success_edges_sha256: {:?}, trusted_core_offset: {}, trusted_core_sha256: {:?}, ordinary_entry_symbol_sha256: {:?}, ordinary_entry_code_sha256: {:?}, wrapper_entry_offset: {}, wrapper_bytes: {}, wrapper_sha256: {:?}, endpoint_symbol_sha256: {:?}, native_code_sha256: {:?}, relocations_sha256: {:?}, object_sha256: {:?}, runtime_call_count: {}, receipt_identity_sha256: {receipt_identity_sha256:?} }} }},",
            pattern.case_insensitive,
            module_report.schema_version,
            strategy_code(ExactSingletonFirstCandidateStrategy::NativeTwoWayTrustedCoreV1),
            semantics_code(module_report.semantics),
            abi_code(module_report.abi),
            module_report.miss_sentinel,
            module_report.literal_bytes,
            module_report.literal_sha256,
            architecture_code(target.architecture),
            os_code(target.operating_system),
            target.features.bits(),
            module_report.required_features.bits(),
            isa_code(module_report.emitted_isa),
            cursor_code(module_report.cursor_register),
            module_report.success_edge_count,
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
            "#[allow(unused_imports, reason = \"the exact-singleton first-candidate registry may be empty\")]\nuse super::{{AotExactSingletonFirstCandidateReceiptV1, ExactSingletonFirstCandidateSpec}};\n\n#[allow(dead_code, reason = \"pins runtime authentication to the exact build target\")]\npub(super) const BUILD_FIRST_CANDIDATE_TARGET_FEATURES: u64 = {};\n#[allow(dead_code, reason = \"checked by focused generated-registry tests\")]\npub(super) const BUILD_FIRST_CANDIDATE_PUBLIC_FIXTURE_SELECTED: bool = {};\n#[allow(dead_code, reason = \"checked by focused generated-registry tests\")]\npub(super) const BUILD_FIRST_CANDIDATE_INDEPENDENTLY_ELIGIBLE_COUNT: usize = {};\n#[allow(dead_code, reason = \"checked by focused generated-registry tests\")]\npub(super) const BUILD_FIRST_CANDIDATE_ADMITTED_COUNT: usize = {};\n",
            target.features.bits(),
            public_fixture_selected,
            self.independently_eligible,
            self.admitted,
        );
        if !self.declarations.is_empty() {
            source.push_str(
                "\n#[allow(unsafe_code, reason = \"audited declarations for compiler-authenticated stateless exact-singleton entries\")]\nunsafe extern \"C\" {\n",
            );
            source.push_str(&self.declarations);
            source.push_str("}\n");
        }
        source.push_str(
            "\npub(super) const FIRST_CANDIDATE_SPECS: &[ExactSingletonFirstCandidateSpec] = &[\n",
        );
        source.push_str(&self.rows);
        source.push_str("];\n");
        source
    }
}

const fn strategy_code(value: ExactSingletonFirstCandidateStrategy) -> u8 {
    match value {
        ExactSingletonFirstCandidateStrategy::NativeTwoWayTrustedCoreV1 => 1,
    }
}

const fn semantics_code(value: ExactSingletonFirstCandidateSemantics) -> u8 {
    match value {
        ExactSingletonFirstCandidateSemantics::EarliestInclusiveFinalByteV1 => 1,
    }
}

const fn abi_code(value: ExactSingletonFirstCandidateAbi) -> u8 {
    match value {
        ExactSingletonFirstCandidateAbi::HaystackLenU64OutStatusV1 => 1,
    }
}

const fn cursor_code(value: ExactSingletonFirstCandidateCursorRegister) -> u8 {
    match value {
        ExactSingletonFirstCandidateCursorRegister::X86Rdx => 1,
        ExactSingletonFirstCandidateCursorRegister::Aarch64X2 => 2,
    }
}

const fn isa_code(value: ExactSingleLiteralAotIsa) -> u8 {
    match value {
        ExactSingleLiteralAotIsa::X86Scalar => 1,
        ExactSingleLiteralAotIsa::Aarch64Scalar => 2,
        ExactSingleLiteralAotIsa::Aarch64AsimdPairPrefilter => 3,
    }
}

const fn required_features_for_isa(value: ExactSingleLiteralAotIsa) -> fre_aot_regex::FeatureSet {
    match value {
        ExactSingleLiteralAotIsa::X86Scalar | ExactSingleLiteralAotIsa::Aarch64Scalar => {
            fre_aot_regex::FeatureSet::EMPTY
        }
        ExactSingleLiteralAotIsa::Aarch64AsimdPairPrefilter => {
            fre_aot_regex::FeatureSet::of(CpuFeature::Aarch64Asimd)
        }
    }
}

const fn isa_matches_architecture(
    architecture: Architecture,
    isa: ExactSingleLiteralAotIsa,
) -> bool {
    matches!(
        (architecture, isa),
        (Architecture::X86_64, ExactSingleLiteralAotIsa::X86Scalar)
            | (
                Architecture::Aarch64,
                ExactSingleLiteralAotIsa::Aarch64Scalar
                    | ExactSingleLiteralAotIsa::Aarch64AsimdPairPrefilter
            )
    )
}

const fn cursor_matches_architecture(
    architecture: Architecture,
    cursor: ExactSingletonFirstCandidateCursorRegister,
) -> bool {
    matches!(
        (architecture, cursor),
        (
            Architecture::X86_64,
            ExactSingletonFirstCandidateCursorRegister::X86Rdx
        ) | (
            Architecture::Aarch64,
            ExactSingletonFirstCandidateCursorRegister::Aarch64X2
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

const fn isa_name(value: ExactSingleLiteralAotIsa) -> &'static str {
    match value {
        ExactSingleLiteralAotIsa::X86Scalar => "x86-scalar",
        ExactSingleLiteralAotIsa::Aarch64Scalar => "aarch64-scalar",
        ExactSingleLiteralAotIsa::Aarch64AsimdPairPrefilter => "aarch64-asimd-pair-prefilter",
    }
}
