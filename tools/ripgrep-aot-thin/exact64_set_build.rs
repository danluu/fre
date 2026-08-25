//! Build transaction for the strictly opt-in exact64 first-any registry.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use fre_aot_regex::{
    Architecture, CompileMode, OperatingSystem, REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_ABI_VERSION,
    REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_LINE_TERMINATOR,
    REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_NO_MATCH,
    REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_POSITION_FINAL_BYTE, REGEX_SET_EXACT64_MAX_PATTERNS,
    REGEX_SET_EXACT64_MIN_PATTERNS, REGEX_SET_EXACT64_SCHEMA_VERSION, RegexSetCompileRequest,
    RegexSetExact64AotLimitsV1, RegexSetExact64CompileDisposition,
    RegexSetExact64FirstAnyAotCompileDispositionV1, RegexSetExact64Limits, Target,
    compile_regex_set_exact64_first_any_aot_v1, compile_regex_set_exact64_reported,
};

use crate::build_proof::{exact_nonempty_lf_free_singleton, ripgrep_exact64_set_profile};
use crate::build_support::Exact64Set;
use crate::registry_key::exact64_set_registry_key;

pub(crate) struct GeneratedExact64Sets {
    pub(crate) source: String,
    pub(crate) objects: Vec<PathBuf>,
}

#[allow(
    clippy::too_many_lines,
    reason = "independent proof, compiler selection, object closure, and raw-free registry publication are one fail-closed build transaction"
)]
pub(crate) fn generate(
    sets: &[Exact64Set],
    target: Target,
    out_dir: &Path,
    manifest_selected: bool,
) -> GeneratedExact64Sets {
    let mut declarations = String::new();
    let mut rows = String::new();
    let mut objects = Vec::new();
    let mut admitted_keys = BTreeSet::new();
    let mut independently_eligible = 0_usize;
    let mut admitted = 0_usize;

    for set in sets {
        let profile = ripgrep_exact64_set_profile(set.case_insensitive);
        if !set
            .sources
            .iter()
            .all(|source| exact_nonempty_lf_free_singleton(source, &profile))
        {
            continue;
        }
        independently_eligible += 1;
        let request = RegexSetCompileRequest::new(set.sources.clone())
            .profile(profile)
            .mode(CompileMode::Optimizing);
        let disposition =
            compile_regex_set_exact64_reported(request, RegexSetExact64Limits::default())
                .unwrap_or_else(|_| {
                    panic!(
                        "exact64 set {} compiler transaction failed after independent proof",
                        set.id
                    )
                });
        let program = match disposition {
            RegexSetExact64CompileDisposition::Selected(program) => program,
            RegexSetExact64CompileDisposition::Declined { .. } => continue,
        };
        let disposition = compile_regex_set_exact64_first_any_aot_v1(
            program,
            target,
            RegexSetExact64AotLimitsV1::default(),
        )
        .unwrap_or_else(|_| {
            panic!(
                "exact64 set {} first-any transaction failed after exact64 selection",
                set.id
            )
        });
        let artifact = match disposition {
            RegexSetExact64FirstAnyAotCompileDispositionV1::Selected(artifact) => artifact,
            RegexSetExact64FirstAnyAotCompileDispositionV1::Declined { .. } => continue,
        };
        let receipt = artifact.receipt();
        let source_receipt = receipt.source_receipt();
        let module = artifact.module();
        let object = artifact.object();
        let pattern_count = set.sources.len();
        assert!(
            (REGEX_SET_EXACT64_MIN_PATTERNS..=REGEX_SET_EXACT64_MAX_PATTERNS)
                .contains(&pattern_count)
                && artifact.authenticates_receipt()
                && artifact.program().authenticate().is_ok()
                && receipt.abi_version() == REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_ABI_VERSION
                && receipt.target() == target
                && receipt.line_terminator() == REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_LINE_TERMINATOR
                && receipt.position_semantics()
                    == REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_POSITION_FINAL_BYTE
                && receipt.no_match() == REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_NO_MATCH
                && receipt.semantic_runtime_calls() == 0
                && source_receipt.schema_version() == REGEX_SET_EXACT64_SCHEMA_VERSION
                && usize::from(source_receipt.pattern_count()) == pattern_count
                && source_receipt.all_pattern_mask() == all_pattern_mask(pattern_count)
                && module.target() == target
                && module.entry_symbol() == receipt.entry_symbol()
                && module.required_runtime_symbols().next().is_none()
                && module.required_runtime_program().is_none()
                && receipt.object_bytes() == object.len()
                && receipt.state_count() != 0
                && receipt.dense_transition_cells() != 0
                && receipt.dense_data_bytes() != 0
                && receipt.code_bytes() != 0
                && receipt.object_bytes() != 0
                && receipt.operation_identity_sha256() != [0; 32]
                && receipt.artifact_identity_sha256() != [0; 32]
                && receipt.dense_data_sha256() != [0; 32]
                && receipt.code_sha256() != [0; 32]
                && receipt.object_sha256() != [0; 32],
            "exact64 set {} failed receipt/object authentication",
            set.id
        );

        let source_refs = set.sources.iter().map(String::as_str).collect::<Vec<_>>();
        let registry_key = exact64_set_registry_key(&source_refs, set.case_insensitive);
        assert!(
            admitted_keys.insert(registry_key),
            "exact64 set {} duplicates an already admitted ordered source/profile key",
            set.id
        );
        let stem = format!("{}_exact64_first_any", set.id);
        let object_path = out_dir.join(format!("{stem}.o"));
        fs::write(&object_path, object).unwrap_or_else(|error| {
            panic!(
                "write exact64 set object {}: {error}",
                object_path.display()
            )
        });
        let written = fs::read(&object_path).unwrap_or_else(|error| {
            panic!(
                "read back exact64 set object {}: {error}",
                object_path.display()
            )
        });
        assert_eq!(
            written.as_slice(),
            object,
            "exact64 set {} object changed during publication",
            set.id
        );
        objects.push(object_path);

        let declaration = format!("exact64_first_any_{}", set.id);
        writeln!(
            &mut declarations,
            "    #[link_name = {:?}] fn {declaration}(haystack: *const u8, haystack_len: usize, window_start: usize, window_end: usize, position: *mut u64) -> u32;",
            receipt.entry_symbol()
        )
        .expect("String writes cannot fail");
        let description = format!(
            "mode=optimizing,output=exists,route=direct-native,api=exact64-first-any-v1,proof=independent-and-compiler-exact-nonempty-lf-free,patterns={pattern_count},target={}-{},features={:#x},states={},dense_cells={}",
            architecture_name(target.architecture),
            os_name(target.operating_system),
            target.features.bits(),
            receipt.state_count(),
            receipt.dense_transition_cells(),
        );
        writeln!(
            &mut rows,
            "    Exact64SetSpec {{ registry_key: {registry_key:?}, description: {description:?}, entry_symbol: {:?}, entry: {declaration}, receipt: AotExact64SetReceiptV1 {{ registry_key: {registry_key:?}, case_insensitive: {}, pattern_count: {}, all_pattern_mask: {}, source_schema_version: {}, abi_version: {}, target_architecture: {}, target_operating_system: {}, target_features: {}, line_terminator: {}, position_semantics: {}, no_match: {}, source_artifact_sha256: {:?}, exact64_artifact_sha256: {:?}, source_mapping_sha256: {:?}, operation_identity_sha256: {:?}, artifact_identity_sha256: {:?}, dense_data_sha256: {:?}, code_sha256: {:?}, object_sha256: {:?}, state_count: {}, dense_transition_cells: {}, dense_data_bytes: {}, code_bytes: {}, object_bytes: {}, semantic_runtime_calls: {} }} }},",
            receipt.entry_symbol(),
            set.case_insensitive,
            source_receipt.pattern_count(),
            source_receipt.all_pattern_mask(),
            source_receipt.schema_version(),
            receipt.abi_version(),
            architecture_code(target.architecture),
            os_code(target.operating_system),
            target.features.bits(),
            receipt.line_terminator(),
            receipt.position_semantics(),
            receipt.no_match(),
            source_receipt.source_artifact().into_bytes(),
            source_receipt.artifact_identity().into_bytes(),
            source_receipt.source_mapping_digest(),
            receipt.operation_identity_sha256(),
            receipt.artifact_identity_sha256(),
            receipt.dense_data_sha256(),
            receipt.code_sha256(),
            receipt.object_sha256(),
            receipt.state_count(),
            receipt.dense_transition_cells(),
            receipt.dense_data_bytes(),
            receipt.code_bytes(),
            receipt.object_bytes(),
            receipt.semantic_runtime_calls(),
        )
        .expect("String writes cannot fail");
        admitted += 1;
    }

    let mut source = format!(
        "#[allow(unused_imports, reason = \"the opt-in exact64 registry may be empty\")]\nuse super::{{AotExact64SetReceiptV1, Exact64SetSpec}};\n\n#[allow(dead_code, reason = \"reported by public build-validation tests\")]\npub(super) const BUILD_EXACT64_SET_MANIFEST_SELECTED: bool = {manifest_selected};\n#[allow(dead_code, reason = \"reported by public build-validation tests\")]\npub(super) const BUILD_EXACT64_SET_MANIFEST_COUNT: usize = {};\n#[allow(dead_code, reason = \"reported by public build-validation tests\")]\npub(super) const BUILD_EXACT64_SET_INDEPENDENTLY_ELIGIBLE_COUNT: usize = {independently_eligible};\n#[allow(dead_code, reason = \"reported by public build-validation tests\")]\npub(super) const BUILD_EXACT64_SET_ADMITTED_COUNT: usize = {admitted};\n",
        sets.len()
    );
    if !declarations.is_empty() {
        source.push_str(
            "\n#[allow(unsafe_code, reason = \"audited declarations for authenticated compiler-produced exact64 first-any objects\")]\nunsafe extern \"C\" {\n",
        );
        source.push_str(&declarations);
        source.push_str("}\n");
    }
    source.push_str("\npub(super) const EXACT64_SET_SPECS: &[Exact64SetSpec] = &[\n");
    source.push_str(&rows);
    source.push_str("];\n");
    GeneratedExact64Sets { source, objects }
}

const fn all_pattern_mask(pattern_count: usize) -> u64 {
    if pattern_count == 64 {
        u64::MAX
    } else {
        (1_u64 << pattern_count) - 1
    }
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
