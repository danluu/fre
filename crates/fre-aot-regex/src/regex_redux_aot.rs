//! Whole-operation native lowering for Rebar's fixed regex-redux pipeline.
//!
//! This is deliberately a specialized operation compiler rather than a
//! runtime operation-set interpreter. The emitted entry directly calls the
//! fifteen identity-suffixed ordinary Span entries, owns every exhaustive
//! iterator and replacement copy, formats the canonical report, and publishes
//! one receipt only after the complete pipeline succeeds.

use core::fmt;

use fre_syntax::RustProfile;
use sha2::{Digest, Sha256};

use crate::{
    CompileError, CompileLimitsV1, CompileMode, CompileRequest, CompiledModule, CompiledRegex,
    ObjectError, ObjectFormat, OutputContract, SectionKind, SymbolKind, Target, compile,
    emit_object,
};

/// Domain separator for the immutable operation identity.
pub const NATIVE_REGEX_REDUX_AOT_V1_IDENTITY_DOMAIN: &[u8] =
    b"fre-aot-regex/native-regex-redux-operation/v1\0";
/// Single-pointer native request ABI version.
pub const NATIVE_REGEX_REDUX_AOT_V1_ABI_VERSION: u32 = 1;
/// Exact fixed component count: flatten, nine variants, and five substitutions.
pub const NATIVE_REGEX_REDUX_AOT_V1_COMPONENTS: usize = 15;
/// Bytes in the caller request described by this API.
pub const NATIVE_REGEX_REDUX_AOT_V1_REQUEST_BYTES: usize = 72;
/// Bytes transactionally published by the native entry on success.
pub const NATIVE_REGEX_REDUX_AOT_V1_RECEIPT_BYTES: usize = 144;
/// Minimum caller report capacity; only the exact formatted length is written.
pub const NATIVE_REGEX_REDUX_AOT_V1_REPORT_BYTES: usize = 1024;
/// Complete operation success; report and receipt are published.
pub const NATIVE_REGEX_REDUX_AOT_V1_STATUS_SUCCESS: u32 = 0;
/// Request pointers, capacities, alignment, or overlap are invalid.
pub const NATIVE_REGEX_REDUX_AOT_V1_STATUS_INVALID_ARGUMENT: u32 = 2;
/// A fixed component or checked stage invariant failed at execution time.
pub const NATIVE_REGEX_REDUX_AOT_V1_STATUS_RUNTIME_FAILURE: u32 = 3;

/// Exact single-pointer request consumed by the emitted operation entry.
///
/// Both scratch buffers must have capacity at least `haystack_len +
/// haystack_len / 2`. The reducer owns their contents for the duration of the
/// call and leaves the final substituted sequence in `scratch_b` on success.
/// Their contents are unspecified on an error return.
/// All six declared ranges (this request, haystack, both scratch buffers,
/// report, and receipt) must be pairwise disjoint. `report_capacity` must be
/// at least [`NATIVE_REGEX_REDUX_AOT_V1_REPORT_BYTES`]. The report receives
/// exactly `receipt_out.report_length` bytes, and the receipt is the final
/// commit record; neither range is touched on an error return.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NativeRegexReduxRequestV1 {
    pub haystack: *const u8,
    pub haystack_len: usize,
    pub scratch_a: *mut u8,
    pub scratch_a_capacity: usize,
    pub scratch_b: *mut u8,
    pub scratch_b_capacity: usize,
    pub report: *mut u8,
    pub report_capacity: usize,
    pub receipt_out: *mut NativeRegexReduxRunReceiptV1,
}

/// Transactionally published execution evidence for the fixed operation.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeRegexReduxRunReceiptV1 {
    pub input_length: u64,
    pub clean_length: u64,
    pub variant_counts: [u64; 9],
    pub substitution_lengths: [u64; 5],
    pub final_length: u64,
    pub report_length: u64,
}

/// Fixed Rebar variant sources, in report and execution order.
pub const NATIVE_REGEX_REDUX_VARIANTS_V1: [&str; 9] = [
    r"agggtaaa|tttaccct",
    r"[cgt]gggtaaa|tttaccc[acg]",
    r"a[act]ggtaaa|tttacc[agt]t",
    r"ag[act]gtaaa|tttac[agt]ct",
    r"agg[act]taaa|ttta[agt]cct",
    r"aggg[acg]aaa|ttt[cgt]ccct",
    r"agggt[cgt]aa|tt[acg]accct",
    r"agggta[cgt]a|t[acg]taccct",
    r"agggtaa[cgt]|[acg]ttaccct",
];

/// Fixed FASTA-header/newline removal source.
pub const NATIVE_REGEX_REDUX_FLATTEN_V1: &str = r">[^\n]*\n|\n";

/// Fixed substitution sources and literal replacement bytes.
pub const NATIVE_REGEX_REDUX_SUBSTITUTIONS_V1: [(&str, &[u8]); 5] = [
    (r"tHa[Nt]", b"<4>"),
    (r"aND|caN|Ha[DS]|WaS", b"<3>"),
    (r"a[NSt]|BY", b"<2>"),
    (r"<[^>]*>", b"|"),
    (r"\|[^|][^|]*\|", b"-"),
];

const COMPONENT_SOURCES: [&str; NATIVE_REGEX_REDUX_AOT_V1_COMPONENTS] = [
    NATIVE_REGEX_REDUX_FLATTEN_V1,
    NATIVE_REGEX_REDUX_VARIANTS_V1[0],
    NATIVE_REGEX_REDUX_VARIANTS_V1[1],
    NATIVE_REGEX_REDUX_VARIANTS_V1[2],
    NATIVE_REGEX_REDUX_VARIANTS_V1[3],
    NATIVE_REGEX_REDUX_VARIANTS_V1[4],
    NATIVE_REGEX_REDUX_VARIANTS_V1[5],
    NATIVE_REGEX_REDUX_VARIANTS_V1[6],
    NATIVE_REGEX_REDUX_VARIANTS_V1[7],
    NATIVE_REGEX_REDUX_VARIANTS_V1[8],
    NATIVE_REGEX_REDUX_SUBSTITUTIONS_V1[0].0,
    NATIVE_REGEX_REDUX_SUBSTITUTIONS_V1[1].0,
    NATIVE_REGEX_REDUX_SUBSTITUTIONS_V1[2].0,
    NATIVE_REGEX_REDUX_SUBSTITUTIONS_V1[3].0,
    NATIVE_REGEX_REDUX_SUBSTITUTIONS_V1[4].0,
];

/// Explicit resource envelope for the fixed component suite and reducer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeRegexReduxAotLimitsV1 {
    pub component: CompileLimitsV1,
    pub max_reducer_object_bytes: usize,
}

impl Default for NativeRegexReduxAotLimitsV1 {
    fn default() -> Self {
        Self {
            component: CompileLimitsV1::default(),
            max_reducer_object_bytes: 4 * 1024 * 1024,
        }
    }
}

/// Exact compiler and link receipt for the whole-operation entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeRegexReduxAotReceiptV1 {
    pub abi_version: u32,
    pub target: Target,
    pub operation_identity: [u8; 32],
    pub reducer_symbol: String,
    pub component_entry_symbols: Box<[String]>,
    pub component_program_sha256: Box<[[u8; 32]]>,
    pub component_object_sha256: Box<[[u8; 32]]>,
    pub reducer_code_sha256: [u8; 32],
    pub reducer_data_sha256: [u8; 32],
    pub reducer_object_sha256: [u8; 32],
    pub reducer_relocation_count: usize,
    pub request_bytes: usize,
    pub receipt_bytes: usize,
    pub report_bytes: usize,
}

/// Complete fixed suite plus the separately linkable whole-operation object.
#[derive(Clone, Debug)]
pub struct NativeRegexReduxAotArtifactV1 {
    components: Box<[CompiledRegex]>,
    reducer_module: CompiledModule,
    reducer_object: Box<[u8]>,
    receipt: NativeRegexReduxAotReceiptV1,
}

impl NativeRegexReduxAotArtifactV1 {
    #[must_use]
    pub fn components(&self) -> &[CompiledRegex] {
        &self.components
    }

    #[must_use]
    pub const fn reducer_module(&self) -> &CompiledModule {
        &self.reducer_module
    }

    #[must_use]
    pub fn reducer_object(&self) -> &[u8] {
        &self.reducer_object
    }

    #[must_use]
    pub const fn receipt(&self) -> &NativeRegexReduxAotReceiptV1 {
        &self.receipt
    }
}

/// Typed terminal failure; no partial artifact is ever returned.
#[derive(Debug)]
pub enum NativeRegexReduxAotErrorV1 {
    Component {
        component: usize,
        error: CompileError,
    },
    Object(ObjectError),
    Invariant(&'static str),
}

impl fmt::Display for NativeRegexReduxAotErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Component { component, error } => {
                write!(
                    formatter,
                    "regex-redux component {component} failed: {error}"
                )
            }
            Self::Object(error) => write!(formatter, "regex-redux reducer object failed: {error}"),
            Self::Invariant(detail) => {
                write!(formatter, "regex-redux reducer invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for NativeRegexReduxAotErrorV1 {}

impl From<ObjectError> for NativeRegexReduxAotErrorV1 {
    fn from(error: ObjectError) -> Self {
        Self::Object(error)
    }
}

fn digest_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
}

fn operation_identity(
    target: Target,
    components: &[CompiledRegex],
) -> Result<[u8; 32], NativeRegexReduxAotErrorV1> {
    let mut hasher = Sha256::new();
    hasher.update(NATIVE_REGEX_REDUX_AOT_V1_IDENTITY_DOMAIN);
    hasher.update(NATIVE_REGEX_REDUX_AOT_V1_ABI_VERSION.to_le_bytes());
    hasher.update([
        target.architecture as u8,
        target.operating_system as u8,
        target.abi as u8,
    ]);
    hasher.update(target.features.bits().to_le_bytes());
    for (source, component) in COMPONENT_SOURCES.iter().zip(components) {
        digest_len_prefixed(&mut hasher, source.as_bytes());
        digest_len_prefixed(&mut hasher, component.module().entry_symbol().as_bytes());
        hasher.update(component.receipt().program_sha256);
        hasher.update(component.receipt().object_sha256);
    }
    for (_, replacement) in NATIVE_REGEX_REDUX_SUBSTITUTIONS_V1 {
        digest_len_prefixed(&mut hasher, replacement);
    }
    Ok(hasher.finalize().into())
}

/// Compile the exact public Rebar regex-redux suite and one helper-free native
/// operation entry for the requested target.
///
/// The emitted symbol uses the target C ABI and has the signature
/// `uint32_t entry(const NativeRegexReduxRequestV1 *request)`. Its status is
/// one of the three `NATIVE_REGEX_REDUX_AOT_V1_STATUS_*` constants.
///
/// The returned reducer object has exactly fifteen semantic call relocations,
/// one to each independently compiled direct ordinary Span entry. It does not
/// declare a runtime semantic helper.
pub fn compile_native_regex_redux_aot_v1(
    target: Target,
    limits: NativeRegexReduxAotLimitsV1,
) -> Result<NativeRegexReduxAotArtifactV1, NativeRegexReduxAotErrorV1> {
    let mut components = Vec::new();
    components
        .try_reserve_exact(NATIVE_REGEX_REDUX_AOT_V1_COMPONENTS)
        .map_err(|_| ObjectError::Allocation("regex-redux component artifacts"))?;
    for (component, source) in COMPONENT_SOURCES.into_iter().enumerate() {
        let mut profile = RustProfile::rebar_1_12_4();
        profile.options.unicode = false;
        profile.options.case_insensitive = false;
        let compiled = compile(
            CompileRequest::new(source, target)
                .profile(profile)
                .output(OutputContract::Span)
                .mode(CompileMode::Optimizing)
                .limits(limits.component),
        )
        .map_err(|error| NativeRegexReduxAotErrorV1::Component { component, error })?;
        let module = compiled.module();
        if module.required_runtime_symbols().next().is_some()
            || module.required_runtime_program().is_some()
            || module.prepared_entry_symbol().is_some()
            || !module.prepared_aggregate_exports().is_empty()
            || compiled.receipt().output != OutputContract::Span
            || module
                .symbols()
                .iter()
                .enumerate()
                .any(|(symbol, definition)| {
                    definition.section.is_none()
                        && module
                            .relocations()
                            .iter()
                            .any(|relocation| relocation.symbol == symbol)
                })
        {
            return Err(NativeRegexReduxAotErrorV1::Invariant(
                "component is not a closed direct ordinary Span artifact",
            ));
        }
        components.push(compiled);
    }
    let identity = operation_identity(target, &components)?;
    let entries = components
        .iter()
        .map(|component| component.module().entry_symbol().to_owned())
        .collect::<Vec<_>>();
    if entries
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        != entries.len()
    {
        return Err(NativeRegexReduxAotErrorV1::Invariant(
            "component entry symbols are not unique",
        ));
    }
    let reducer_module = crate::module::lower_native_regex_redux_operation_v1(
        target,
        identity,
        &entries,
        &NATIVE_REGEX_REDUX_VARIANTS_V1,
        &NATIVE_REGEX_REDUX_SUBSTITUTIONS_V1,
    )?;
    if reducer_module
        .required_runtime_symbols()
        .ne(entries.iter().map(String::as_str))
        || reducer_module.relocations().len()
            != NATIVE_REGEX_REDUX_AOT_V1_COMPONENTS
                + if target.architecture == crate::Architecture::X86_64 {
                    1
                } else {
                    2
                }
    {
        return Err(NativeRegexReduxAotErrorV1::Invariant(
            "reducer relocation closure is not exact",
        ));
    }
    let reducer_object = emit_object(
        &reducer_module,
        ObjectFormat::for_target(target),
        limits.max_reducer_object_bytes,
    )?;
    let code = reducer_module
        .sections()
        .iter()
        .find(|section| section.kind == SectionKind::Text)
        .ok_or(NativeRegexReduxAotErrorV1::Invariant("reducer has no text"))?;
    let data = reducer_module
        .sections()
        .iter()
        .find(|section| section.kind == SectionKind::ReadOnlyData)
        .ok_or(NativeRegexReduxAotErrorV1::Invariant("reducer has no data"))?;
    let entry = reducer_module
        .symbols()
        .iter()
        .find(|symbol| {
            symbol.name == reducer_module.entry_symbol()
                && symbol.kind == SymbolKind::Function
                && symbol.section.is_some()
        })
        .ok_or(NativeRegexReduxAotErrorV1::Invariant(
            "reducer entry is not defined text",
        ))?;
    if usize::try_from(entry.size).ok() != Some(code.bytes().len()) {
        return Err(NativeRegexReduxAotErrorV1::Invariant(
            "reducer entry does not close text extent",
        ));
    }
    let receipt = NativeRegexReduxAotReceiptV1 {
        abi_version: NATIVE_REGEX_REDUX_AOT_V1_ABI_VERSION,
        target,
        operation_identity: identity,
        reducer_symbol: reducer_module.entry_symbol().to_owned(),
        component_entry_symbols: entries.into_boxed_slice(),
        component_program_sha256: components
            .iter()
            .map(|component| component.receipt().program_sha256)
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        component_object_sha256: components
            .iter()
            .map(|component| component.receipt().object_sha256)
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        reducer_code_sha256: Sha256::digest(code.bytes()).into(),
        reducer_data_sha256: Sha256::digest(data.bytes()).into(),
        reducer_object_sha256: Sha256::digest(&reducer_object).into(),
        reducer_relocation_count: reducer_module.relocations().len(),
        request_bytes: NATIVE_REGEX_REDUX_AOT_V1_REQUEST_BYTES,
        receipt_bytes: NATIVE_REGEX_REDUX_AOT_V1_RECEIPT_BYTES,
        report_bytes: NATIVE_REGEX_REDUX_AOT_V1_REPORT_BYTES,
    };
    Ok(NativeRegexReduxAotArtifactV1 {
        components: components.into_boxed_slice(),
        reducer_module,
        reducer_object: reducer_object.into_boxed_slice(),
        receipt,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        fmt::Write as _,
        mem::{align_of, size_of},
    };

    use super::*;
    use crate::{
        module::NATIVE_TEXT_LINK_ALIGNMENT_BYTES,
        Architecture, RelocationKind, SectionKind, SymbolBinding,
    };

    #[test]
    fn execution_abi_has_exact_word_layout() {
        assert_eq!(
            size_of::<NativeRegexReduxRequestV1>(),
            NATIVE_REGEX_REDUX_AOT_V1_REQUEST_BYTES
        );
        assert_eq!(align_of::<NativeRegexReduxRequestV1>(), align_of::<usize>());
        assert_eq!(std::mem::offset_of!(NativeRegexReduxRequestV1, haystack), 0);
        assert_eq!(
            std::mem::offset_of!(NativeRegexReduxRequestV1, haystack_len),
            8
        );
        assert_eq!(
            std::mem::offset_of!(NativeRegexReduxRequestV1, scratch_a),
            16
        );
        assert_eq!(
            std::mem::offset_of!(NativeRegexReduxRequestV1, scratch_a_capacity),
            24,
        );
        assert_eq!(
            std::mem::offset_of!(NativeRegexReduxRequestV1, scratch_b),
            32
        );
        assert_eq!(
            std::mem::offset_of!(NativeRegexReduxRequestV1, scratch_b_capacity),
            40,
        );
        assert_eq!(std::mem::offset_of!(NativeRegexReduxRequestV1, report), 48);
        assert_eq!(
            std::mem::offset_of!(NativeRegexReduxRequestV1, report_capacity),
            56,
        );
        assert_eq!(
            std::mem::offset_of!(NativeRegexReduxRequestV1, receipt_out),
            64
        );

        assert_eq!(
            size_of::<NativeRegexReduxRunReceiptV1>(),
            NATIVE_REGEX_REDUX_AOT_V1_RECEIPT_BYTES,
        );
        assert_eq!(
            align_of::<NativeRegexReduxRunReceiptV1>(),
            align_of::<u64>()
        );
        assert_eq!(
            std::mem::offset_of!(NativeRegexReduxRunReceiptV1, input_length),
            0,
        );
        assert_eq!(
            std::mem::offset_of!(NativeRegexReduxRunReceiptV1, clean_length),
            8,
        );
        assert_eq!(
            std::mem::offset_of!(NativeRegexReduxRunReceiptV1, variant_counts),
            16,
        );
        assert_eq!(
            std::mem::offset_of!(NativeRegexReduxRunReceiptV1, substitution_lengths),
            88,
        );
        assert_eq!(
            std::mem::offset_of!(NativeRegexReduxRunReceiptV1, final_length),
            128,
        );
        assert_eq!(
            std::mem::offset_of!(NativeRegexReduxRunReceiptV1, report_length),
            136,
        );
    }

    fn assert_reducer_closure(target: Target) {
        let artifact =
            compile_native_regex_redux_aot_v1(target, NativeRegexReduxAotLimitsV1::default())
                .expect("compile fixed regex-redux operation");
        let data_relocations = if target.architecture == Architecture::X86_64 {
            1
        } else {
            2
        };
        assert_eq!(
            artifact.components().len(),
            NATIVE_REGEX_REDUX_AOT_V1_COMPONENTS
        );
        assert_eq!(
            artifact.receipt().component_entry_symbols.len(),
            NATIVE_REGEX_REDUX_AOT_V1_COMPONENTS,
        );
        assert_eq!(
            artifact.receipt().reducer_relocation_count,
            NATIVE_REGEX_REDUX_AOT_V1_COMPONENTS + data_relocations,
        );
        assert_eq!(
            artifact.receipt().request_bytes,
            size_of::<NativeRegexReduxRequestV1>()
        );
        assert_eq!(
            artifact.receipt().receipt_bytes,
            size_of::<NativeRegexReduxRunReceiptV1>(),
        );
        assert!(!artifact.reducer_object().is_empty());

        for (component, expected_symbol) in artifact
            .components()
            .iter()
            .zip(artifact.receipt().component_entry_symbols.iter())
        {
            assert_eq!(component.module().entry_symbol(), expected_symbol);
            assert!(
                component
                    .module()
                    .required_runtime_symbols()
                    .next()
                    .is_none()
            );
            assert!(component.module().required_runtime_program().is_none());
            assert!(component.module().prepared_entry_symbol().is_none());
            assert!(component.module().prepared_aggregate_exports().is_empty());
            assert!(
                component
                    .module()
                    .symbols()
                    .iter()
                    .enumerate()
                    .all(|(symbol, definition)| definition.section.is_some()
                        || !component
                            .module()
                            .relocations()
                            .iter()
                            .any(|relocation| relocation.symbol == symbol)),
            );
        }

        let module = artifact.reducer_module();
        assert_eq!(
            module
                .sections()
                .iter()
                .find(|section| section.kind == SectionKind::Text)
                .expect("reducer text section")
                .alignment,
            NATIVE_TEXT_LINK_ALIGNMENT_BYTES,
        );
        assert_eq!(module.entry_symbol(), artifact.receipt().reducer_symbol);
        assert!(
            module.required_runtime_symbols().eq(artifact
                .receipt()
                .component_entry_symbols
                .iter()
                .map(String::as_str))
        );
        assert!(module.required_runtime_program().is_none());
        assert_eq!(
            module.symbols().len(),
            NATIVE_REGEX_REDUX_AOT_V1_COMPONENTS + 2
        );
        assert_eq!(module.symbols()[0].binding, SymbolBinding::Global);
        assert!(module.symbols()[0].section.is_some());
        assert!(module.symbols()[1].section.is_some());
        for (component, symbol) in module.symbols()[2..].iter().enumerate() {
            assert_eq!(
                symbol.name,
                artifact.receipt().component_entry_symbols[component],
            );
            assert_eq!(symbol.binding, SymbolBinding::Global);
            assert!(symbol.section.is_none());
        }

        let relocations = module.relocations();
        assert_eq!(
            relocations.len(),
            NATIVE_REGEX_REDUX_AOT_V1_COMPONENTS + data_relocations,
        );
        match target.architecture {
            Architecture::X86_64 => {
                assert_eq!(relocations[0].kind, RelocationKind::X86PcRelative32);
                assert_eq!(relocations[0].symbol, 1);
                assert_eq!(relocations[0].addend, -4);
            }
            Architecture::Aarch64 => {
                assert_eq!(relocations[0].kind, RelocationKind::Aarch64Page21);
                assert_eq!(relocations[0].symbol, 1);
                assert_eq!(relocations[0].addend, 0);
                assert_eq!(relocations[1].kind, RelocationKind::Aarch64PageOff12);
                assert_eq!(relocations[1].symbol, 1);
                assert_eq!(relocations[1].addend, 0);
            }
        }
        let text = module
            .sections()
            .iter()
            .find(|section| section.kind == SectionKind::Text)
            .expect("regex-redux text")
            .bytes();
        match target.architecture {
            Architecture::X86_64 => {
                let data_offset = usize::try_from(relocations[0].offset).unwrap();
                assert_eq!(&text[data_offset - 3..data_offset], &[0x4c, 0x8d, 0x2d]);
            }
            Architecture::Aarch64 => {
                let page = usize::try_from(relocations[0].offset).unwrap();
                let page_offset = usize::try_from(relocations[1].offset).unwrap();
                assert_eq!(
                    u32::from_le_bytes(text[page..page + 4].try_into().unwrap()),
                    0x9000_0015,
                );
                assert_eq!(
                    u32::from_le_bytes(text[page_offset..page_offset + 4].try_into().unwrap()),
                    0x9100_02b5,
                );
            }
        }
        for (component, relocation) in relocations[data_relocations..].iter().enumerate() {
            assert_eq!(
                relocation.kind,
                if target.architecture == Architecture::X86_64 {
                    RelocationKind::X86PltRelative32
                } else {
                    RelocationKind::Aarch64Branch26
                },
            );
            assert_eq!(relocation.symbol, component + 2);
            assert_eq!(
                relocation.addend,
                if target.architecture == Architecture::X86_64 {
                    -4
                } else {
                    0
                },
            );
            let offset = usize::try_from(relocation.offset).unwrap();
            assert!(offset + 4 <= text.len());
            match target.architecture {
                Architecture::X86_64 => {
                    assert!(offset >= 1);
                    assert_eq!(text[offset - 1], 0xe8);
                }
                Architecture::Aarch64 => {
                    assert_eq!(offset % 4, 0);
                    assert_eq!(
                        u32::from_le_bytes(text[offset..offset + 4].try_into().unwrap()),
                        0x9400_0000,
                    );
                }
            }
        }
    }

    #[test]
    fn x86_reducer_has_exact_cross_format_object_closure() {
        assert_reducer_closure(Target::x86_64_linux());
        assert_reducer_closure(Target::x86_64_macos());
    }

    #[test]
    fn aarch64_reducer_has_exact_cross_format_object_closure() {
        assert_reducer_closure(Target::aarch64_linux());
        assert_reducer_closure(Target::aarch64_macos());
    }

    fn reference_receipt(haystack: &[u8]) -> (NativeRegexReduxRunReceiptV1, Vec<u8>, String) {
        use regex::bytes::{NoExpand, RegexBuilder};

        let compile = |source: &str| {
            RegexBuilder::new(source)
                .unicode(false)
                .build()
                .expect("compile independent regex-redux reference")
        };
        let input_length = u64::try_from(haystack.len()).unwrap();
        let mut sequence = compile(NATIVE_REGEX_REDUX_FLATTEN_V1)
            .replace_all(haystack, NoExpand(b""))
            .into_owned();
        let clean_length = u64::try_from(sequence.len()).unwrap();
        let mut variant_counts = [0_u64; 9];
        let mut report = String::new();
        for (variant, source) in NATIVE_REGEX_REDUX_VARIANTS_V1.iter().enumerate() {
            variant_counts[variant] =
                u64::try_from(compile(source).find_iter(&sequence).count()).unwrap();
            writeln!(&mut report, "{source} {}", variant_counts[variant]).unwrap();
        }
        let mut substitution_lengths = [0_u64; 5];
        for (substitution, &(source, replacement)) in
            NATIVE_REGEX_REDUX_SUBSTITUTIONS_V1.iter().enumerate()
        {
            sequence = compile(source)
                .replace_all(&sequence, NoExpand(replacement))
                .into_owned();
            substitution_lengths[substitution] = u64::try_from(sequence.len()).unwrap();
        }
        let final_length = u64::try_from(sequence.len()).unwrap();
        writeln!(
            &mut report,
            "\n{input_length}\n{clean_length}\n{final_length}",
        )
        .unwrap();
        let receipt = NativeRegexReduxRunReceiptV1 {
            input_length,
            clean_length,
            variant_counts,
            substitution_lengths,
            final_length,
            report_length: u64::try_from(report.len()).unwrap(),
        };
        (receipt, sequence, report)
    }

    #[test]
    fn fixed_suite_has_canonical_public_semantics() {
        let (receipt, sequence, report) = reference_receipt(b">test\nagggtaaa\n");
        let expected_report = concat!(
            "agggtaaa|tttaccct 1\n",
            "[cgt]gggtaaa|tttaccc[acg] 0\n",
            "a[act]ggtaaa|tttacc[agt]t 0\n",
            "ag[act]gtaaa|tttac[agt]ct 0\n",
            "agg[act]taaa|ttta[agt]cct 0\n",
            "aggg[acg]aaa|ttt[cgt]ccct 0\n",
            "agggt[cgt]aa|tt[acg]accct 0\n",
            "agggta[cgt]a|t[acg]taccct 0\n",
            "agggtaa[cgt]|[acg]ttaccct 0\n",
            "\n15\n8\n8\n",
        );
        assert_eq!(receipt.input_length, 15);
        assert_eq!(receipt.clean_length, 8);
        assert_eq!(receipt.variant_counts, [1, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(receipt.substitution_lengths, [8; 5]);
        assert_eq!(receipt.final_length, 8);
        assert_eq!(receipt.report_length, expected_report.len() as u64);
        assert_eq!(sequence, b"agggtaaa");
        assert_eq!(report, expected_report);
    }

    fn c_bytes(bytes: &[u8]) -> String {
        if bytes.is_empty() {
            return "0".to_owned();
        }
        bytes
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }

    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        any(target_os = "linux", target_os = "macos")
    ))]
    #[test]
    #[ignore = "links all sixteen fixed objects and executes the complete helper-free operation"]
    fn linked_host_reducer_matches_independent_operation() {
        use std::{fs, process::Command, time::SystemTime};

        let target = if cfg!(all(target_arch = "x86_64", target_os = "linux")) {
            Target::x86_64_linux()
        } else if cfg!(all(target_arch = "x86_64", target_os = "macos")) {
            Target::x86_64_macos()
        } else if cfg!(target_os = "linux") {
            Target::aarch64_linux()
        } else {
            Target::aarch64_macos()
        };
        let artifact =
            compile_native_regex_redux_aot_v1(target, NativeRegexReduxAotLimitsV1::default())
                .expect("compile linked regex-redux fixture");
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "fre-native-regex-redux-{}-{nonce}",
            std::process::id(),
        ));
        fs::create_dir_all(&directory).expect("create regex-redux link directory");
        let reducer = directory.join("reducer.o");
        fs::write(&reducer, artifact.reducer_object()).expect("write reducer object");
        let mut objects = vec![reducer.clone()];
        for (component, compiled) in artifact.components().iter().enumerate() {
            let path = directory.join(format!("component-{component:02}.o"));
            fs::write(&path, compiled.object()).expect("write component object");
            objects.push(path);
        }

        let fixtures: &[&[u8]] = &[
            b"",
            b">test\nagggtaaa\n",
            b">one\ntttaccctBYtHaNt\n>two\naNDaNS<tag>|abc|\n",
            b"BYBYBY aND caN HaD HaS WaS tHaNt tHaNa <x> |xyz|",
        ];
        let symbol = artifact.reducer_module().entry_symbol();
        let mut source = format!(
            "#include <stdint.h>\n#include <stddef.h>\n#include <stdlib.h>\n#include <string.h>\nextern uint32_t {symbol}(const uintptr_t*);\n",
        );
        source.push_str(
            "static int run_case(const unsigned char*h,size_t n,const uint64_t*e,const unsigned char*ef,size_t efn,const unsigned char*er,size_t ern){\n\
             size_t cap=n+n/2;if(cap==0)cap=1;unsigned char*a=malloc(cap),*b=malloc(cap);if(!a||!b)return 90;\n\
             unsigned char report[1024];uint64_t receipt[18];memset(a,0x91,cap);memset(b,0x92,cap);memset(report,0xa5,sizeof(report));memset(receipt,0xa6,sizeof(receipt));\n\
             uintptr_t q[9]={(uintptr_t)h,n,(uintptr_t)a,cap,(uintptr_t)b,cap,(uintptr_t)report,sizeof(report),(uintptr_t)receipt};\n\
             uint32_t s=",
        );
        writeln!(
            &mut source,
            "{symbol}(q);if(s!=0)return 10;if(memcmp(receipt,e,sizeof(receipt)))return 11;if(receipt[17]!=ern)return 12;if(memcmp(report,er,ern))return 13;"
        )
        .unwrap();
        source.push_str(
            "for(size_t i=ern;i<sizeof(report);i++)if(report[i]!=0xa5)return 14;if(receipt[16]!=efn||memcmp(b,ef,efn))return 15;free(a);free(b);return 0;}\n",
        );
        let mut main = String::from("int main(void){int r;\n");
        for (case, &fixture) in fixtures.iter().enumerate() {
            let (receipt, final_sequence, report) = reference_receipt(fixture);
            let receipt_words = [
                &[receipt.input_length, receipt.clean_length][..],
                &receipt.variant_counts,
                &receipt.substitution_lengths,
                &[receipt.final_length, receipt.report_length],
            ]
            .concat();
            writeln!(
                &mut source,
                "static const unsigned char h{case}[]={{ {} }};",
                c_bytes(fixture),
            )
            .unwrap();
            writeln!(
                &mut source,
                "static const unsigned char f{case}[]={{ {} }};",
                c_bytes(&final_sequence),
            )
            .unwrap();
            writeln!(
                &mut source,
                "static const unsigned char p{case}[]={{ {} }};",
                c_bytes(report.as_bytes()),
            )
            .unwrap();
            writeln!(
                &mut source,
                "static const uint64_t e{case}[18]={{{}}};",
                receipt_words
                    .iter()
                    .map(u64::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            )
            .unwrap();
            writeln!(
                &mut main,
                "r=run_case(h{case},{},e{case},f{case},{},p{case},{});if(r)return r+{};",
                fixture.len(),
                final_sequence.len(),
                report.len(),
                case * 20,
            )
            .unwrap();
        }
        main.push_str(
            "unsigned char z[1]={0},report[1024];uint64_t receipt[18];memset(report,0x5a,sizeof(report));memset(receipt,0x5b,sizeof(receipt));\n\
             uintptr_t bad[9]={(uintptr_t)h0,0,(uintptr_t)z,1,(uintptr_t)z,1,(uintptr_t)report,sizeof(report),(uintptr_t)receipt};\n",
        );
        writeln!(
            &mut main,
            "if({symbol}(bad)!=2)return 97;for(size_t i=0;i<sizeof(report);i++)if(report[i]!=0x5a)return 98;for(size_t i=0;i<sizeof(receipt);i++)if(((unsigned char*)receipt)[i]!=0x5b)return 99;return 0;}}",
        )
        .unwrap();
        source.push_str(&main);

        let c_path = directory.join("differential.c");
        let executable = directory.join("differential");
        fs::write(&c_path, source).expect("write linked differential");
        let output = Command::new("cc")
            .arg("-O2")
            .arg(&c_path)
            .args(&objects)
            .arg("-o")
            .arg(&executable)
            .output()
            .expect("run host linker");
        assert!(
            output.status.success(),
            "link failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        let output = Command::new(&executable)
            .output()
            .expect("run linked regex-redux differential");
        assert!(
            output.status.success(),
            "linked differential failed: status={:?} stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );

        // Independently link the reducer against ABI-compatible component
        // stubs. Flatten reports no match, so it copies the byte to scratch A;
        // the first variant then fails. Report and receipt must remain wholly
        // unpublished on that runtime-failure edge.
        let mut failure_source = format!(
            "#include <stdint.h>\n#include <stddef.h>\n#include <string.h>\ntypedef struct{{size_t start;size_t end;}} result_t;\nextern uint32_t {symbol}(const uintptr_t*);\n",
        );
        for (component, component_symbol) in artifact
            .receipt()
            .component_entry_symbols
            .iter()
            .enumerate()
        {
            writeln!(
                &mut failure_source,
                "uint32_t {component_symbol}(const unsigned char*p,size_t n,size_t s,size_t e,result_t*r){{(void)p;(void)n;(void)s;(void)e;(void)r;return {}U;}}",
                if component == 1 { 3 } else { 0 },
            )
            .unwrap();
        }
        writeln!(
            &mut failure_source,
            "int main(void){{unsigned char h[1]={{'x'}},a[1]={{0}},b[1]={{0}},report[1024],unaligned[80];uint64_t receipt[18];memset(report,0x6a,sizeof(report));memset(receipt,0x6b,sizeof(receipt));uintptr_t q[9]={{(uintptr_t)h,1,(uintptr_t)a,1,(uintptr_t)b,1,(uintptr_t)report,sizeof(report),(uintptr_t)receipt}};if({symbol}((const uintptr_t*)0)!=2U)return 31;if({symbol}((const uintptr_t*)(unaligned+1))!=2U)return 32;if({symbol}(q)!=3U)return 33;for(size_t i=0;i<sizeof(report);i++)if(report[i]!=0x6a)return 34;for(size_t i=0;i<sizeof(receipt);i++)if(((unsigned char*)receipt)[i]!=0x6b)return 35;return 0;}}",
        )
        .unwrap();
        let failure_c = directory.join("runtime-failure.c");
        let failure_executable = directory.join("runtime-failure");
        fs::write(&failure_c, failure_source).expect("write runtime-failure transaction test");
        let output = Command::new("cc")
            .arg("-O2")
            .arg(&failure_c)
            .arg(&reducer)
            .arg("-o")
            .arg(&failure_executable)
            .output()
            .expect("link runtime-failure transaction test");
        assert!(
            output.status.success(),
            "runtime-failure link failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        let output = Command::new(&failure_executable)
            .output()
            .expect("run runtime-failure transaction test");
        assert!(
            output.status.success(),
            "runtime-failure transaction failed: status={:?} stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        fs::remove_dir_all(directory).expect("remove regex-redux link directory");
    }
}
