//! Safe dispatch over the precompiled ripgrep-suite general-AOT registry.

#![warn(unsafe_code)]

use std::marker::PhantomData;
use std::mem::MaybeUninit;

use fre_aot_regex::{
    EXACT_SINGLETON_FIRST_CANDIDATE_AOT_SCHEMA_VERSION, EXACT_SINGLETON_FIRST_CANDIDATE_MISS,
    MATCHING_LF_LINE_WITNESS_AOT_SCHEMA_VERSION, MATCHING_LF_LINE_WITNESS_MISS, MatchResult,
    PREPARED_CAPABILITY_ORDERED_NFA_V15, REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_ABI_VERSION,
    REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_LINE_TERMINATOR,
    REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_NO_MATCH,
    REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_POSITION_FINAL_BYTE,
    REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_STATUS_SUCCESS, REGEX_SET_EXACT64_MAX_PATTERNS,
    REGEX_SET_EXACT64_MIN_PATTERNS, REGEX_SET_EXACT64_SCHEMA_VERSION, SearchWindow,
};
pub use fre_aot_regex_runtime::AotMatch;
use fre_aot_regex_runtime::{
    FreAotRegexExactSingletonFirstCandidateV1, FreAotRegexExclusiveExistsBatchV1,
    FreAotRegexExclusiveGrepCountV1, FreAotRegexExclusiveHandleV1, FreAotRegexExclusiveSpanFillV1,
    FreAotRegexHaystackV1, FreAotRegexIndependentExistsBatchV1,
    FreAotRegexIndependentSpanFillV1, FreAotRegexIterStateV1,
    FreAotRegexMatchingLfLineWitnessV1, FreAotRegexPrepareConfigV3, FreAotRegexResultV1,
    ITER_FINISHED, ITER_HAS_LAST, ITER_KNOWN_FLAGS, ITER_PENDING_EMPTY,
    PREPARE_CAPABILITY_KNOWN_FLAGS, PREPARE_CAPABILITY_ORDERED_NFA_V15, PREPARE_OPERATION_COUNT,
    PREPARE_OPERATION_SPAN_SUM, PreparedAotMatches, PreparedAotRegex,
    fre_aot_regex_runtime_destroy_exclusive_v1, fre_aot_regex_runtime_prepare_exclusive_v1,
    fre_aot_regex_runtime_prepare_exclusive_v3,
};
use sha2::{Digest, Sha256};

const _: () = assert!(
    PREPARED_CAPABILITY_ORDERED_NFA_V15 == PREPARE_CAPABILITY_ORDERED_NFA_V15,
    "compiler/runtime Ordered-NFA V15 capability bits must remain identical"
);

#[path = "../registry_key.rs"]
mod registry_key;

#[path = "../first_candidate_receipt.rs"]
mod first_candidate_receipt;

#[path = "../lf_line_witness_receipt.rs"]
mod lf_line_witness_receipt;

use first_candidate_receipt::FirstCandidateReceiptIdentityInputV1;
use lf_line_witness_receipt::MatchingLfLineWitnessReceiptIdentityInputV1;
use registry_key::{exact64_set_registry_key, manifest_profile_key};

/// Explicit general-AOT compilation policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AotMode {
    /// Fast compilation to the universal ordered TNFA and prepared runtime.
    Fast,
    /// Optimizing compilation to native DFA code when complete determinization succeeds.
    Optimizing,
}

/// Search result contract selected at AOT compilation time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AotOutput {
    /// Return only whether a match exists.
    Exists,
    /// Return the selected leftmost-first half-open span.
    Span,
}

/// Matcher implementation selected by the enclosing ripgrep request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RipgrepAotMatcherModeV1 {
    /// Rust `regex::bytes::RegexSet` syntax and semantics.
    RustRegex,
    /// Literal fixed-string matching (`-F`/`--fixed-strings`).
    FixedStrings,
}

/// Whether the supplied haystack bytes are already the matcher input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RipgrepAotEncodingV1 {
    /// No decoding, BOM rewriting, or other transcoding remains.
    RawBytes,
    /// Encoding selection or transcoding may change the input bytes.
    AmbiguousOrTranscoded,
}

/// Complete versioned ripgrep semantics checked before exact64 set selection.
///
/// V1 admits exactly one profile: Optimizing/Exists Rust byte-regex matching
/// over independently delineated LF domains, Unicode enabled, with optional
/// case-insensitivity and no enclosing semantic transformations. Fields are
/// intentionally explicit so an integration cannot silently omit an
/// unsupported flag when it maps a parsed ripgrep request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the fail-closed adapter surface mirrors distinct ripgrep semantic switches"
)]
pub struct RipgrepAotExact64SetProfileV1 {
    pub matcher_mode: RipgrepAotMatcherModeV1,
    pub case_insensitive: bool,
    pub invert_match: bool,
    pub multiline: bool,
    pub dot_matches_new_line: bool,
    pub unicode: bool,
    pub crlf: bool,
    pub null_data: bool,
    pub encoding: RipgrepAotEncodingV1,
    pub word_regexp: bool,
    pub line_regexp: bool,
    pub pcre2: bool,
}

impl RipgrepAotExact64SetProfileV1 {
    /// Construct the sole supported semantics after the enclosing adapter has
    /// independently established that no input decoding remains.
    #[must_use]
    pub const fn supported_rust_regex(case_insensitive: bool) -> Self {
        Self {
            matcher_mode: RipgrepAotMatcherModeV1::RustRegex,
            case_insensitive,
            invert_match: false,
            multiline: false,
            dot_matches_new_line: false,
            unicode: true,
            crlf: false,
            null_data: false,
            encoding: RipgrepAotEncodingV1::RawBytes,
            word_regexp: false,
            line_regexp: false,
            pcre2: false,
        }
    }

    const fn is_supported(self) -> bool {
        matches!(self.matcher_mode, RipgrepAotMatcherModeV1::RustRegex)
            && !self.invert_match
            && !self.multiline
            && !self.dot_matches_new_line
            && self.unicode
            && !self.crlf
            && !self.null_data
            && matches!(self.encoding, RipgrepAotEncodingV1::RawBytes)
            && !self.word_regexp
            && !self.line_regexp
            && !self.pcre2
    }
}

type NativeExact64FirstAny =
    unsafe extern "C" fn(*const u8, usize, usize, usize, *mut u64) -> u32;

const EXACT64_SET_TARGET_AARCH64: u8 = 1;
const EXACT64_SET_TARGET_LINUX: u8 = 1;
const EXACT64_SET_TARGET_MACOS: u8 = 2;

const fn exact64_set_runtime_target_os() -> u8 {
    if cfg!(target_os = "linux") {
        EXACT64_SET_TARGET_LINUX
    } else if cfg!(target_os = "macos") {
        EXACT64_SET_TARGET_MACOS
    } else {
        0
    }
}

/// Raw-free build receipt for one statically linked exact64 first-any object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AotExact64SetReceiptV1 {
    registry_key: [u8; 32],
    case_insensitive: bool,
    pattern_count: u8,
    all_pattern_mask: u64,
    source_schema_version: u32,
    abi_version: u32,
    target_architecture: u8,
    target_operating_system: u8,
    target_features: u64,
    line_terminator: u8,
    position_semantics: u32,
    no_match: u64,
    source_artifact_sha256: [u8; 32],
    exact64_artifact_sha256: [u8; 32],
    source_mapping_sha256: [u8; 32],
    operation_identity_sha256: [u8; 32],
    artifact_identity_sha256: [u8; 32],
    dense_data_sha256: [u8; 32],
    code_sha256: [u8; 32],
    object_sha256: [u8; 32],
    state_count: usize,
    dense_transition_cells: usize,
    dense_data_bytes: usize,
    code_bytes: usize,
    object_bytes: usize,
    semantic_runtime_calls: usize,
}

impl AotExact64SetReceiptV1 {
    /// Ordered source/profile registry identity.
    #[must_use]
    pub const fn registry_key(self) -> [u8; 32] {
        self.registry_key
    }

    /// Number of ordered source rows, including duplicates.
    #[must_use]
    pub const fn pattern_count(self) -> u8 {
        self.pattern_count
    }

    /// Common case-insensitive option authenticated for every source row.
    #[must_use]
    pub const fn case_insensitive(self) -> bool {
        self.case_insensitive
    }

    /// Deterministic first-any object digest authenticated at build time.
    #[must_use]
    pub const fn object_sha256(self) -> [u8; 32] {
        self.object_sha256
    }

    /// Deterministic first-any artifact identity authenticated at build time.
    #[must_use]
    pub const fn artifact_identity_sha256(self) -> [u8; 32] {
        self.artifact_identity_sha256
    }

    /// FRE target feature mask incorporated into the authenticated artifact.
    #[must_use]
    pub const fn target_features(self) -> u64 {
        self.target_features
    }

    fn authenticates_request(
        self,
        registry_key: [u8; 32],
        profile: RipgrepAotExact64SetProfileV1,
        pattern_count: usize,
    ) -> bool {
        if !(REGEX_SET_EXACT64_MIN_PATTERNS..=REGEX_SET_EXACT64_MAX_PATTERNS)
            .contains(&pattern_count)
        {
            return false;
        }
        let Ok(pattern_count_u8) = u8::try_from(pattern_count) else {
            return false;
        };
        let all_pattern_mask = if pattern_count == 64 {
            u64::MAX
        } else {
            (1_u64 << pattern_count) - 1
        };
        let hashes = [
            self.source_artifact_sha256,
            self.exact64_artifact_sha256,
            self.source_mapping_sha256,
            self.operation_identity_sha256,
            self.artifact_identity_sha256,
            self.dense_data_sha256,
            self.code_sha256,
            self.object_sha256,
        ];
        self.registry_key == registry_key
            && profile.is_supported()
            && self.case_insensitive == profile.case_insensitive
            && self.pattern_count == pattern_count_u8
            && self.all_pattern_mask == all_pattern_mask
            && self.source_schema_version == REGEX_SET_EXACT64_SCHEMA_VERSION
            && self.abi_version == REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_ABI_VERSION
            && self.target_architecture == EXACT64_SET_TARGET_AARCH64
            && self.target_operating_system == exact64_set_runtime_target_os()
            && self.target_features == generated_exact64_sets::BUILD_EXACT64_SET_TARGET_FEATURES
            && self.line_terminator == REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_LINE_TERMINATOR
            && self.position_semantics
                == REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_POSITION_FINAL_BYTE
            && self.no_match == REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_NO_MATCH
            && hashes.iter().all(|hash| *hash != [0; 32])
            && self.state_count != 0
            && self.dense_transition_cells != 0
            && self.dense_data_bytes != 0
            && self.code_bytes != 0
            && self.object_bytes != 0
            && self.semantic_runtime_calls == 0
    }
}

#[derive(Clone, Copy, Debug)]
struct Exact64SetSpec {
    registry_key: [u8; 32],
    description: &'static str,
    entry_symbol: &'static str,
    entry: NativeExact64FirstAny,
    receipt: AotExact64SetReceiptV1,
}

/// Safe result of the exact64 first-any prefilter.
///
/// A candidate is never a confirmed match: the stock ripgrep matcher remains
/// authoritative for matching lines, selected pattern IDs, spans, and
/// captures. A miss is authoritative because registry admission proved every
/// row is one exact nonempty LF-free literal and authenticated the shared scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AotExact64SetOutcome {
    /// No source row occurs in the supplied LF-domain bytes.
    ConfirmedMiss,
    /// Final byte of the earliest-completing possible match. Stock must verify.
    Candidate { position: usize },
}

/// Authenticated stateless handle to one opt-in exact64 set object.
#[derive(Clone, Copy, Debug)]
pub struct AotExact64SetFactory {
    spec: &'static Exact64SetSpec,
}

type NativeExactSingletonFirstCandidate = FreAotRegexExactSingletonFirstCandidateV1;

const FIRST_CANDIDATE_STRATEGY_NATIVE_TWO_WAY_TRUSTED_CORE_V1: u8 = 1;
const FIRST_CANDIDATE_SEMANTICS_EARLIEST_INCLUSIVE_FINAL_BYTE_V1: u8 = 1;
const FIRST_CANDIDATE_ABI_HAYSTACK_LEN_U64_OUT_STATUS_V1: u8 = 1;
const FIRST_CANDIDATE_ISA_X86_SCALAR: u8 = 1;
const FIRST_CANDIDATE_ISA_AARCH64_SCALAR: u8 = 2;
const FIRST_CANDIDATE_ISA_AARCH64_ASIMD_PAIR_PREFILTER: u8 = 3;
const FIRST_CANDIDATE_CURSOR_X86_RDX: u8 = 1;
const FIRST_CANDIDATE_CURSOR_AARCH64_X2: u8 = 2;
const FIRST_CANDIDATE_TARGET_AARCH64: u8 = 1;
const FIRST_CANDIDATE_TARGET_X86_64: u8 = 2;
const FIRST_CANDIDATE_TARGET_LINUX: u8 = 1;
const FIRST_CANDIDATE_TARGET_MACOS: u8 = 2;

const fn first_candidate_runtime_target_architecture() -> u8 {
    if cfg!(target_arch = "aarch64") {
        FIRST_CANDIDATE_TARGET_AARCH64
    } else if cfg!(target_arch = "x86_64") {
        FIRST_CANDIDATE_TARGET_X86_64
    } else {
        0
    }
}

const fn first_candidate_runtime_target_os() -> u8 {
    if cfg!(target_os = "linux") {
        FIRST_CANDIDATE_TARGET_LINUX
    } else if cfg!(target_os = "macos") {
        FIRST_CANDIDATE_TARGET_MACOS
    } else {
        0
    }
}

/// Raw-free build receipt for one stateless exact-singleton first-candidate
/// endpoint linked from the ordinary Optimizing/Exists object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AotExactSingletonFirstCandidateReceiptV1 {
    manifest_profile_key: [u8; 32],
    case_insensitive: bool,
    schema_version: u32,
    strategy: u8,
    semantics: u8,
    abi: u8,
    miss_sentinel: u64,
    literal_bytes: usize,
    literal_sha256: [u8; 32],
    target_architecture: u8,
    target_operating_system: u8,
    target_features: u64,
    required_features: u64,
    emitted_isa: u8,
    cursor_register: u8,
    success_edge_count: u8,
    success_edges_sha256: [u8; 32],
    trusted_core_offset: usize,
    trusted_core_sha256: [u8; 32],
    ordinary_entry_symbol_sha256: [u8; 32],
    ordinary_entry_code_sha256: [u8; 32],
    wrapper_entry_offset: usize,
    wrapper_bytes: usize,
    wrapper_sha256: [u8; 32],
    endpoint_symbol_sha256: [u8; 32],
    native_code_sha256: [u8; 32],
    relocations_sha256: [u8; 32],
    object_sha256: [u8; 32],
    runtime_call_count: u8,
    receipt_identity_sha256: [u8; 32],
}

impl AotExactSingletonFirstCandidateReceiptV1 {
    /// Domain-separated identity of the raw manifest source and case profile.
    #[must_use]
    pub const fn manifest_profile_key(self) -> [u8; 32] {
        self.manifest_profile_key
    }

    /// Exact independently proved literal width in bytes.
    #[must_use]
    pub const fn literal_bytes(self) -> usize {
        self.literal_bytes
    }

    /// SHA-256 of the exact independently proved literal bytes.
    #[must_use]
    pub const fn literal_sha256(self) -> [u8; 32] {
        self.literal_sha256
    }

    /// Complete linked object identity authenticated by the compiler receipt.
    #[must_use]
    pub const fn object_sha256(self) -> [u8; 32] {
        self.object_sha256
    }

    /// Exact target feature mask authenticated by the compiler and build.
    #[must_use]
    pub const fn target_features(self) -> u64 {
        self.target_features
    }

    /// Minimum feature mask required by the emitted instruction family.
    #[must_use]
    pub const fn required_features(self) -> u64 {
        self.required_features
    }

    fn identity_input(self) -> FirstCandidateReceiptIdentityInputV1 {
        FirstCandidateReceiptIdentityInputV1 {
            manifest_profile_key: self.manifest_profile_key,
            case_insensitive: self.case_insensitive,
            schema_version: self.schema_version,
            strategy: self.strategy,
            semantics: self.semantics,
            abi: self.abi,
            miss_sentinel: self.miss_sentinel,
            literal_bytes: self.literal_bytes,
            literal_sha256: self.literal_sha256,
            target_architecture: self.target_architecture,
            target_operating_system: self.target_operating_system,
            target_features: self.target_features,
            required_features: self.required_features,
            emitted_isa: self.emitted_isa,
            cursor_register: self.cursor_register,
            success_edge_count: self.success_edge_count,
            success_edges_sha256: self.success_edges_sha256,
            trusted_core_offset: self.trusted_core_offset,
            trusted_core_sha256: self.trusted_core_sha256,
            ordinary_entry_symbol_sha256: self.ordinary_entry_symbol_sha256,
            ordinary_entry_code_sha256: self.ordinary_entry_code_sha256,
            wrapper_entry_offset: self.wrapper_entry_offset,
            wrapper_bytes: self.wrapper_bytes,
            wrapper_sha256: self.wrapper_sha256,
            endpoint_symbol_sha256: self.endpoint_symbol_sha256,
            native_code_sha256: self.native_code_sha256,
            relocations_sha256: self.relocations_sha256,
            object_sha256: self.object_sha256,
            runtime_call_count: self.runtime_call_count,
        }
    }

    fn authenticates_request(
        self,
        request_key: [u8; 32],
        case_insensitive: bool,
        configured_literal: &[u8],
        entry_symbol: &str,
    ) -> bool {
        if configured_literal.is_empty() || configured_literal.contains(&b'\n') {
            return false;
        }
        let configured_literal_sha256: [u8; 32] = Sha256::digest(configured_literal).into();
        let endpoint_symbol_sha256: [u8; 32] = Sha256::digest(entry_symbol.as_bytes()).into();
        let hashes = [
            self.literal_sha256,
            self.success_edges_sha256,
            self.trusted_core_sha256,
            self.ordinary_entry_symbol_sha256,
            self.ordinary_entry_code_sha256,
            self.wrapper_sha256,
            self.endpoint_symbol_sha256,
            self.native_code_sha256,
            self.relocations_sha256,
            self.object_sha256,
            self.receipt_identity_sha256,
        ];
        let target_shape = match self.target_architecture {
            FIRST_CANDIDATE_TARGET_X86_64 => {
                self.emitted_isa == FIRST_CANDIDATE_ISA_X86_SCALAR
                    && self.required_features == 0
                    && self.cursor_register == FIRST_CANDIDATE_CURSOR_X86_RDX
            }
            FIRST_CANDIDATE_TARGET_AARCH64 => {
                (self.emitted_isa == FIRST_CANDIDATE_ISA_AARCH64_SCALAR
                    && self.required_features == 0
                    || self.emitted_isa == FIRST_CANDIDATE_ISA_AARCH64_ASIMD_PAIR_PREFILTER
                        && self.required_features == 1_u64 << 32)
                    && self.cursor_register == FIRST_CANDIDATE_CURSOR_AARCH64_X2
            }
            _ => false,
        };
        self.manifest_profile_key == request_key
            && self.case_insensitive == case_insensitive
            && self.schema_version == EXACT_SINGLETON_FIRST_CANDIDATE_AOT_SCHEMA_VERSION
            && self.strategy == FIRST_CANDIDATE_STRATEGY_NATIVE_TWO_WAY_TRUSTED_CORE_V1
            && self.semantics == FIRST_CANDIDATE_SEMANTICS_EARLIEST_INCLUSIVE_FINAL_BYTE_V1
            && self.abi == FIRST_CANDIDATE_ABI_HAYSTACK_LEN_U64_OUT_STATUS_V1
            && self.miss_sentinel == EXACT_SINGLETON_FIRST_CANDIDATE_MISS
            && self.literal_bytes == configured_literal.len()
            && self.literal_sha256 == configured_literal_sha256
            && self.target_architecture == first_candidate_runtime_target_architecture()
            && self.target_operating_system == first_candidate_runtime_target_os()
            && self.target_features
                == generated_first_candidates::BUILD_FIRST_CANDIDATE_TARGET_FEATURES
            && self.target_features & self.required_features == self.required_features
            && target_shape
            && self.success_edge_count != 0
            && self.wrapper_bytes != 0
            && hashes.iter().all(|hash| *hash != [0; 32])
            && self.endpoint_symbol_sha256 == endpoint_symbol_sha256
            && self.runtime_call_count == 0
            && self.identity_input().identity() == Some(self.receipt_identity_sha256)
    }
}

#[derive(Clone, Copy, Debug)]
struct ExactSingletonFirstCandidateSpec {
    manifest_profile_key: [u8; 32],
    description: &'static str,
    entry_symbol: &'static str,
    entry: NativeExactSingletonFirstCandidate,
    receipt: AotExactSingletonFirstCandidateReceiptV1,
}

/// Safe result of the exact-singleton whole-buffer candidate endpoint.
///
/// A positive position is never a confirmed match. Stock ripgrep remains
/// authoritative for matching-line, span, and capture semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AotExactSingletonFirstCandidateOutcome {
    /// The authenticated exact literal does not occur in the supplied bytes.
    ConfirmedMiss,
    /// Inclusive final byte of a possible match. Stock must verify it.
    Candidate { position: usize },
}

/// Authenticated stateless handle to one exact-singleton first-candidate
/// endpoint emitted beside an ordinary Optimizing/Exists registry row.
#[derive(Clone, Copy, Debug)]
pub struct AotExactSingletonFirstCandidateFactory {
    spec: &'static ExactSingletonFirstCandidateSpec,
}

type NativeMatchingLfLineWitness = FreAotRegexMatchingLfLineWitnessV1;

const LF_LINE_WITNESS_STRATEGY_NATIVE_COMPLETE_DFA_TRUSTED_CORE_V1: u8 = 1;
const LF_LINE_WITNESS_STRATEGY_NATIVE_TEDDY_TRUSTED_CORE_V1: u8 = 2;
const LF_LINE_WITNESS_SEMANTICS_MATCHING_LF_LINE_BYTE_V1: u8 = 1;
const LF_LINE_WITNESS_ABI_HAYSTACK_LEN_U64_OUT_STATUS_V1: u8 = 1;
const LF_LINE_WITNESS_CURSOR_X86_RDX: u8 = 1;
const LF_LINE_WITNESS_CURSOR_AARCH64_X2: u8 = 2;
const LF_LINE_WITNESS_TARGET_AARCH64: u8 = 1;
const LF_LINE_WITNESS_TARGET_X86_64: u8 = 2;
const LF_LINE_WITNESS_TARGET_LINUX: u8 = 1;
const LF_LINE_WITNESS_TARGET_MACOS: u8 = 2;

const fn lf_line_witness_runtime_target_architecture() -> u8 {
    if cfg!(target_arch = "aarch64") {
        LF_LINE_WITNESS_TARGET_AARCH64
    } else if cfg!(target_arch = "x86_64") {
        LF_LINE_WITNESS_TARGET_X86_64
    } else {
        0
    }
}

const fn lf_line_witness_runtime_target_os() -> u8 {
    if cfg!(target_os = "linux") {
        LF_LINE_WITNESS_TARGET_LINUX
    } else if cfg!(target_os = "macos") {
        LF_LINE_WITNESS_TARGET_MACOS
    } else {
        0
    }
}

/// Raw-free build receipt for one stateless matching-LF-line witness endpoint
/// linked from an ordinary Optimizing/Exists object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AotMatchingLfLineWitnessReceiptV1 {
    manifest_profile_key: [u8; 32],
    case_insensitive: bool,
    source_count: usize,
    source_bytes: usize,
    minimum_width: usize,
    maximum_width: usize,
    source_language_sha256: [u8; 32],
    compiler_literal_sha256: [u8; 32],
    compiler_source_count: usize,
    compiler_source_bytes: usize,
    compiler_minimum_width: usize,
    compiler_maximum_width: usize,
    schema_version: u32,
    strategy: u8,
    semantics: u8,
    abi: u8,
    miss_sentinel: u64,
    target_architecture: u8,
    target_operating_system: u8,
    target_features: u64,
    program_bytes: usize,
    program_sha256: [u8; 32],
    cursor_register: u8,
    success_edge_count: u8,
    inside_match_edge_count: u8,
    exclusive_end_edge_count: u8,
    success_edges_sha256: [u8; 32],
    trusted_core_offset: usize,
    trusted_core_sha256: [u8; 32],
    ordinary_entry_symbol_sha256: [u8; 32],
    ordinary_entry_code_sha256: [u8; 32],
    wrapper_entry_offset: usize,
    wrapper_bytes: usize,
    wrapper_sha256: [u8; 32],
    endpoint_symbol_sha256: [u8; 32],
    native_code_sha256: [u8; 32],
    relocations_sha256: [u8; 32],
    object_sha256: [u8; 32],
    runtime_call_count: u8,
    receipt_identity_sha256: [u8; 32],
}

impl AotMatchingLfLineWitnessReceiptV1 {
    /// Domain-separated identity of the raw manifest source and case profile.
    #[must_use]
    pub const fn manifest_profile_key(self) -> [u8; 32] {
        self.manifest_profile_key
    }

    /// Number of members in the independently proved finite language.
    #[must_use]
    pub const fn source_count(self) -> usize {
        self.source_count
    }

    /// Total bytes across the independently proved finite language.
    #[must_use]
    pub const fn source_bytes(self) -> usize {
        self.source_bytes
    }

    /// Minimum independently proved member width.
    #[must_use]
    pub const fn minimum_width(self) -> usize {
        self.minimum_width
    }

    /// Maximum independently proved member width.
    #[must_use]
    pub const fn maximum_width(self) -> usize {
        self.maximum_width
    }

    /// Raw-free identity of the independently proved finite language.
    #[must_use]
    pub const fn source_language_sha256(self) -> [u8; 32] {
        self.source_language_sha256
    }

    /// Complete linked object identity authenticated by the compiler receipt.
    #[must_use]
    pub const fn object_sha256(self) -> [u8; 32] {
        self.object_sha256
    }

    /// Exact target feature mask authenticated by the compiler and build.
    #[must_use]
    pub const fn target_features(self) -> u64 {
        self.target_features
    }

    fn identity_input(self) -> MatchingLfLineWitnessReceiptIdentityInputV1 {
        MatchingLfLineWitnessReceiptIdentityInputV1 {
            manifest_profile_key: self.manifest_profile_key,
            case_insensitive: self.case_insensitive,
            source_count: self.source_count,
            source_bytes: self.source_bytes,
            minimum_width: self.minimum_width,
            maximum_width: self.maximum_width,
            source_language_sha256: self.source_language_sha256,
            compiler_literal_sha256: self.compiler_literal_sha256,
            compiler_source_count: self.compiler_source_count,
            compiler_source_bytes: self.compiler_source_bytes,
            compiler_minimum_width: self.compiler_minimum_width,
            compiler_maximum_width: self.compiler_maximum_width,
            schema_version: self.schema_version,
            strategy: self.strategy,
            semantics: self.semantics,
            abi: self.abi,
            miss_sentinel: self.miss_sentinel,
            target_architecture: self.target_architecture,
            target_operating_system: self.target_operating_system,
            target_features: self.target_features,
            program_bytes: self.program_bytes,
            program_sha256: self.program_sha256,
            cursor_register: self.cursor_register,
            success_edge_count: self.success_edge_count,
            inside_match_edge_count: self.inside_match_edge_count,
            exclusive_end_edge_count: self.exclusive_end_edge_count,
            success_edges_sha256: self.success_edges_sha256,
            trusted_core_offset: self.trusted_core_offset,
            trusted_core_sha256: self.trusted_core_sha256,
            ordinary_entry_symbol_sha256: self.ordinary_entry_symbol_sha256,
            ordinary_entry_code_sha256: self.ordinary_entry_code_sha256,
            wrapper_entry_offset: self.wrapper_entry_offset,
            wrapper_bytes: self.wrapper_bytes,
            wrapper_sha256: self.wrapper_sha256,
            endpoint_symbol_sha256: self.endpoint_symbol_sha256,
            native_code_sha256: self.native_code_sha256,
            relocations_sha256: self.relocations_sha256,
            object_sha256: self.object_sha256,
            runtime_call_count: self.runtime_call_count,
        }
    }

    fn authenticates_request(
        self,
        request_key: [u8; 32],
        case_insensitive: bool,
        entry_symbol: &str,
    ) -> bool {
        let endpoint_symbol_sha256: [u8; 32] = Sha256::digest(entry_symbol.as_bytes()).into();
        let hashes = [
            self.source_language_sha256,
            self.program_sha256,
            self.success_edges_sha256,
            self.trusted_core_sha256,
            self.ordinary_entry_symbol_sha256,
            self.ordinary_entry_code_sha256,
            self.wrapper_sha256,
            self.endpoint_symbol_sha256,
            self.native_code_sha256,
            self.relocations_sha256,
            self.object_sha256,
            self.receipt_identity_sha256,
        ];
        let compiler_language_binding = match self.strategy {
            LF_LINE_WITNESS_STRATEGY_NATIVE_COMPLETE_DFA_TRUSTED_CORE_V1 => {
                self.compiler_literal_sha256 == [0; 32]
                    && self.compiler_source_count == 0
                    && self.compiler_source_bytes == 0
                    && self.compiler_minimum_width == 0
                    && self.compiler_maximum_width == 0
            }
            LF_LINE_WITNESS_STRATEGY_NATIVE_TEDDY_TRUSTED_CORE_V1 => {
                self.compiler_literal_sha256 != [0; 32]
                    && self.compiler_source_count == self.source_count
                    && self.compiler_source_bytes == self.source_bytes
                    && self.compiler_minimum_width == self.minimum_width
                    && self.compiler_maximum_width == self.maximum_width
            }
            _ => false,
        };
        let target_shape = matches!(
            (self.target_architecture, self.cursor_register),
            (
                LF_LINE_WITNESS_TARGET_X86_64,
                LF_LINE_WITNESS_CURSOR_X86_RDX
            ) | (
                LF_LINE_WITNESS_TARGET_AARCH64,
                LF_LINE_WITNESS_CURSOR_AARCH64_X2
            )
        );
        let source_geometry = self.source_count != 0
            && self.source_bytes != 0
            && self.minimum_width != 0
            && self.minimum_width <= self.maximum_width
            && self
                .source_count
                .checked_mul(self.minimum_width)
                .is_some_and(|minimum_bytes| minimum_bytes <= self.source_bytes)
            && self
                .source_count
                .checked_mul(self.maximum_width)
                .is_some_and(|maximum_bytes| self.source_bytes <= maximum_bytes);
        self.manifest_profile_key == request_key
            && self.case_insensitive == case_insensitive
            && source_geometry
            && self.schema_version == MATCHING_LF_LINE_WITNESS_AOT_SCHEMA_VERSION
            && compiler_language_binding
            && self.semantics == LF_LINE_WITNESS_SEMANTICS_MATCHING_LF_LINE_BYTE_V1
            && self.abi == LF_LINE_WITNESS_ABI_HAYSTACK_LEN_U64_OUT_STATUS_V1
            && self.miss_sentinel == MATCHING_LF_LINE_WITNESS_MISS
            && self.target_architecture == lf_line_witness_runtime_target_architecture()
            && self.target_operating_system == lf_line_witness_runtime_target_os()
            && self.target_features
                == generated_lf_line_witnesses::BUILD_LF_LINE_WITNESS_TARGET_FEATURES
            && target_shape
            && self.program_bytes != 0
            && self.success_edge_count != 0
            && u16::from(self.inside_match_edge_count) + u16::from(self.exclusive_end_edge_count)
                == u16::from(self.success_edge_count)
            && self.wrapper_bytes != 0
            && hashes.iter().all(|hash| *hash != [0; 32])
            && self.endpoint_symbol_sha256 == endpoint_symbol_sha256
            && self.runtime_call_count == 0
            && self.identity_input().identity() == Some(self.receipt_identity_sha256)
    }
}

#[derive(Clone, Copy, Debug)]
struct MatchingLfLineWitnessSpec {
    manifest_profile_key: [u8; 32],
    description: &'static str,
    entry_symbol: &'static str,
    entry: NativeMatchingLfLineWitness,
    receipt: AotMatchingLfLineWitnessReceiptV1,
}

/// Safe result of a whole-buffer matching-LF-line witness endpoint.
///
/// A candidate is never a confirmed match. Stock ripgrep remains
/// authoritative for matching-line, span, and capture semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AotMatchingLfLineWitnessOutcome {
    /// The independently authenticated finite language does not occur.
    ConfirmedMiss,
    /// One byte in an LF-delimited line that may contain a match.
    Candidate { position: usize },
}

/// Authenticated stateless handle to one matching-LF-line witness endpoint.
#[derive(Clone, Copy, Debug)]
pub struct AotMatchingLfLineWitnessFactory {
    spec: &'static MatchingLfLineWitnessSpec,
}

type AbiResult = FreAotRegexResultV1;
type AbiHaystack = FreAotRegexHaystackV1;
type NativeIterState = FreAotRegexIterStateV1;

/// A reusable, lifetime-bound view of one haystack for batched AOT searches.
///
/// Constructing this view records the native batch ABI's pointer and length
/// once. Passing a slice of views to [`AotMatcher::is_match_descriptor_batch`]
/// lets a compiled batch entry consume those descriptors directly, without
/// the adapter copying a slice of Rust fat pointers into an intermediate
/// descriptor array on every call. The referenced bytes remain borrowed for
/// the complete lifetime of the view.
///
/// The fields are private so safe code cannot forge an invalid pointer/length
/// pair. Use [`AotHaystack::from`] (or `slice.into()`) to construct a view.
///
/// ```compile_fail
/// use fre_ripgrep_aot_thin::AotHaystack;
///
/// fn dangling<'a>() -> AotHaystack<'a> {
///     let bytes = vec![b'x'];
///     AotHaystack::from(bytes.as_slice())
/// }
/// ```
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct AotHaystack<'a> {
    abi: AbiHaystack,
    lifetime: PhantomData<&'a [u8]>,
}

impl<'a> From<&'a [u8]> for AotHaystack<'a> {
    fn from(haystack: &'a [u8]) -> Self {
        Self {
            abi: AbiHaystack {
                ptr: haystack.as_ptr(),
                len: haystack.len(),
            },
            lifetime: PhantomData,
        }
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for AotHaystack<'a> {
    fn from(haystack: &'a [u8; N]) -> Self {
        Self::from(haystack.as_slice())
    }
}

impl AotHaystack<'_> {
    #[allow(
        unsafe_code,
        reason = "the private descriptor can only be constructed from a live shared byte slice"
    )]
    fn as_slice(&self) -> &[u8] {
        // SAFETY: the private fields were obtained from a shared slice, and
        // the phantom lifetime prevents this view from outliving that slice.
        // Copying the view cannot mutate or extend the referenced storage.
        unsafe { std::slice::from_raw_parts(self.abi.ptr, self.abi.len) }
    }
}

type NativeSearch = unsafe extern "C" fn(*const u8, usize, usize, usize, *mut AbiResult) -> u32;
type NativeExistsBatch = FreAotRegexIndependentExistsBatchV1;
type DirectSpanFill = FreAotRegexIndependentSpanFillV1;
type NativeFill =
    fn(&[u8], &mut NativeIterState, &mut [MaybeUninit<AbiResult>]) -> NativeFillOutcome;
type PreparedCompatSpanFill = fn(
    FreAotRegexExclusiveHandleV1,
    &[u8],
    &mut NativeIterState,
    &mut [MaybeUninit<AbiResult>],
) -> NativeFillOutcome;
type PreparedSpanFill = FreAotRegexExclusiveSpanFillV1;
type PreparedExistsBatch = FreAotRegexExclusiveExistsBatchV1;
type PreparedGrepCount = FreAotRegexExclusiveGrepCountV1;
type PreparedSearch = unsafe extern "C" fn(
    FreAotRegexExclusiveHandleV1,
    *const u8,
    usize,
    usize,
    usize,
    *mut AbiResult,
) -> u32;
type PrepareExclusiveV1 =
    unsafe extern "C" fn(*const u8, usize, *mut FreAotRegexExclusiveHandleV1) -> u32;
type PrepareExclusiveV3 = unsafe extern "C" fn(
    *const u8,
    usize,
    *const FreAotRegexPrepareConfigV3,
    *mut FreAotRegexExclusiveHandleV1,
) -> u32;
const NATIVE_SPAN_BUFFER_CAPACITY: usize = 64;
/// Maximum number of line haystacks the thin adapter sends through one
/// compiled Exists-batch invocation.
pub const EXISTS_BATCH_CAPACITY: usize = 64;

// The direct batch ABI publishes compiler-authenticated 0/1 bytes directly
// into caller-owned Boolean storage. Keep that representation dependency a
// compile-time condition instead of silently assuming it in pointer math.
const _: () = {
    assert!(std::mem::size_of::<bool>() == std::mem::size_of::<u8>());
    assert!(std::mem::align_of::<bool>() == std::mem::align_of::<u8>());
};

#[derive(Clone, Copy, Debug)]
#[allow(
    dead_code,
    reason = "compatibility-only registries do not construct the additive compiled fill variant"
)]
enum PreparedSpanFillFactory {
    Compiled(PreparedSpanFill),
    Compatibility(PreparedCompatSpanFill),
}

#[derive(Clone, Copy, Debug)]
#[allow(
    dead_code,
    reason = "the explicit aggregate-only build profile constructs no ordinary matcher backend"
)]
enum BackendFactory {
    Native {
        search: NativeSearch,
        fill: Option<NativeFill>,
        exists_batch: Option<NativeExistsBatch>,
    },
    Prepared {
        search: PreparedSearch,
        program: &'static [u8],
        span_fill: Option<PreparedSpanFillFactory>,
        exists_batch: Option<PreparedExistsBatch>,
        required_prepare_capabilities: u64,
    },
    #[allow(
        dead_code,
        reason = "future or legacy artifacts without any compiled entry retain an explicit labeled portable fallback"
    )]
    Runtime(&'static [u8]),
}

#[derive(Clone, Copy, Debug)]
struct CompiledSpec {
    mode: AotMode,
    output: AotOutput,
    pattern: &'static str,
    case_insensitive: bool,
    description: &'static str,
    backend: BackendFactory,
}

#[derive(Clone, Copy, Debug)]
struct GrepCountSpec {
    mode: AotMode,
    pattern: &'static str,
    case_insensitive: bool,
    description: &'static str,
    entry: PreparedGrepCount,
    program: &'static [u8],
}

#[allow(
    unsafe_code,
    reason = "generated declarations are bound to compiler-produced objects with the stable V1 ABI"
)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/registry.rs"));
}

#[allow(
    unsafe_code,
    reason = "generated declarations are bound to authenticated exact64 first-any objects"
)]
mod generated_exact64_sets {
    include!(concat!(env!("OUT_DIR"), "/exact64_set_registry.rs"));
}

#[allow(
    unsafe_code,
    reason = "generated declarations are bound to authenticated stateless exact-singleton candidate entries"
)]
mod generated_first_candidates {
    include!(concat!(env!("OUT_DIR"), "/first_candidate_registry.rs"));
}

#[allow(
    unsafe_code,
    reason = "generated declarations are bound to authenticated stateless matching-LF-line witness entries"
)]
mod generated_lf_line_witnesses {
    include!(concat!(env!("OUT_DIR"), "/lf_line_witness_registry.rs"));
}

#[cfg(test)]
#[allow(
    dead_code,
    reason = "the library test target exercises only pure build-input helpers"
)]
#[path = "../build_support.rs"]
mod build_support_tests;

#[cfg(test)]
#[allow(
    dead_code,
    reason = "the library test target includes the build-time proof for its focused unit tests"
)]
#[path = "../build_proof.rs"]
mod build_proof_tests;

#[cfg(test)]
#[allow(
    dead_code,
    reason = "the library test target exercises only pure target-feature helpers"
)]
#[path = "../build_target.rs"]
mod build_target_tests;

#[cfg(test)]
#[path = "../prepared_factory.rs"]
mod prepared_factory_tests;

#[derive(Debug)]
enum Backend {
    Native {
        search: NativeSearch,
        fill: Option<NativeFill>,
        exists_batch: Option<NativeExistsBatch>,
    },
    Prepared(PreparedNative),
    Runtime(Box<PreparedAotRegex>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PreparedHandlePreparation {
    V1,
    V3(FreAotRegexPrepareConfigV3),
}

fn prepared_handle_preparation(
    output: AotOutput,
    span_fill: Option<PreparedSpanFillFactory>,
    exists_batch: Option<PreparedExistsBatch>,
    required_prepare_capabilities: u64,
) -> Result<PreparedHandlePreparation, String> {
    if required_prepare_capabilities == 0 {
        return Ok(PreparedHandlePreparation::V1);
    }
    if required_prepare_capabilities & !PREPARE_CAPABILITY_KNOWN_FLAGS != 0 {
        return Err(format!(
            "compiled prepared factory requires unknown runtime capabilities {required_prepare_capabilities:#x}"
        ));
    }
    if required_prepare_capabilities != PREPARE_CAPABILITY_ORDERED_NFA_V15 {
        return Err(format!(
            "compiled prepared factory requires unsupported runtime capability combination {required_prepare_capabilities:#x}"
        ));
    }
    if output != AotOutput::Span
        || !matches!(span_fill, Some(PreparedSpanFillFactory::Compiled(_)))
        || exists_batch.is_some()
    {
        return Err(
            "compiled Ordered-NFA V15 factory is incompatible with its required Span/SpanFill shape"
                .to_owned(),
        );
    }

    let mut config =
        FreAotRegexPrepareConfigV3::new(PREPARE_OPERATION_COUNT | PREPARE_OPERATION_SPAN_SUM);
    config.required_capabilities = PREPARE_CAPABILITY_ORDERED_NFA_V15;
    Ok(PreparedHandlePreparation::V3(config))
}

#[allow(
    unsafe_code,
    reason = "the selected runtime prepare ABI validates and copies compiler-exported program bytes"
)]
fn prepare_exclusive_handle_with(
    program: &[u8],
    preparation: PreparedHandlePreparation,
    prepare_v1: PrepareExclusiveV1,
    prepare_v3: PrepareExclusiveV3,
) -> Result<FreAotRegexExclusiveHandleV1, String> {
    let mut handle = FreAotRegexExclusiveHandleV1::INVALID;
    match preparation {
        PreparedHandlePreparation::V1 => {
            // SAFETY: the caller supplies a readable complete program extent,
            // and `handle` is aligned, writable, and disjoint.
            let status = unsafe { prepare_v1(program.as_ptr(), program.len(), &raw mut handle) };
            if status != 0 || handle.is_invalid() {
                return Err(format!(
                    "prepare compiled AOT exclusive handle failed with status {status}"
                ));
            }
        }
        PreparedHandlePreparation::V3(config) => {
            // SAFETY: the caller supplies a readable complete program extent;
            // `config` is aligned and readable, while `handle` is aligned,
            // writable, and disjoint from both sources.
            let status = unsafe {
                prepare_v3(
                    program.as_ptr(),
                    program.len(),
                    &raw const config,
                    &raw mut handle,
                )
            };
            if status != 0 || handle.is_invalid() {
                return Err(format!(
                    "prepare compiled AOT exclusive V3 handle failed with status {status}"
                ));
            }
        }
    }
    Ok(handle)
}

#[derive(Debug)]
struct PreparedNative {
    search: PreparedSearch,
    span_fill: Option<PreparedSpanFillFactory>,
    exists_batch: Option<PreparedExistsBatch>,
    handle: FreAotRegexExclusiveHandleV1,
}

// SAFETY: this owner can move between threads only as a whole. Every search
// requires `&mut self`, an iterator retains that mutable borrow, and Drop also
// requires exclusive ownership, so no call can remain active across a move.
#[allow(
    unsafe_code,
    reason = "the exclusive runtime ABI permits moving an idle, uniquely owned handle between threads"
)]
unsafe impl Send for PreparedNative {}

impl PreparedNative {
    #[allow(
        unsafe_code,
        reason = "the runtime copies and validates the exact compiler-exported program before returning an exclusively owned handle"
    )]
    fn new(
        output: AotOutput,
        search: PreparedSearch,
        program: &'static [u8],
        span_fill: Option<PreparedSpanFillFactory>,
        exists_batch: Option<PreparedExistsBatch>,
        required_prepare_capabilities: u64,
    ) -> Result<Self, String> {
        let preparation = prepared_handle_preparation(
            output,
            span_fill,
            exists_batch,
            required_prepare_capabilities,
        )?;
        let handle = prepare_exclusive_handle_with(
            program,
            preparation,
            fre_aot_regex_runtime_prepare_exclusive_v1,
            fre_aot_regex_runtime_prepare_exclusive_v3,
        )?;
        Ok(Self {
            search,
            span_fill,
            exists_batch,
            handle,
        })
    }
}

#[allow(
    unsafe_code,
    reason = "this owner destroys its live exclusive runtime handle exactly once"
)]
impl Drop for PreparedNative {
    fn drop(&mut self) {
        let handle = std::mem::replace(&mut self.handle, FreAotRegexExclusiveHandleV1::INVALID);
        if !handle.is_invalid() {
            // SAFETY: `PreparedNative` exclusively owns this live handle, and
            // its mutable borrow prevents an overlapping search or iterator.
            let _status = unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) };
        }
    }
}

trait NativeIterStateExt {
    fn has_last_match(self) -> bool;
    fn pending_empty_progress(self) -> bool;
    fn finished(self) -> bool;
    #[allow(
        dead_code,
        reason = "the aggregate-only build profile omits every span-iteration caller"
    )]
    fn set_pending_empty_progress(&mut self, pending: bool);
    fn finish(&mut self);
}

impl NativeIterStateExt for NativeIterState {
    fn has_last_match(self) -> bool {
        self.flags & ITER_HAS_LAST != 0
    }

    fn pending_empty_progress(self) -> bool {
        self.flags & ITER_PENDING_EMPTY != 0
    }

    fn finished(self) -> bool {
        self.flags & ITER_FINISHED != 0
    }

    fn set_pending_empty_progress(&mut self, pending: bool) {
        if pending {
            self.flags |= ITER_PENDING_EMPTY;
        } else {
            self.flags &= !ITER_PENDING_EMPTY;
        }
    }

    fn finish(&mut self) {
        self.flags = (self.flags & ITER_HAS_LAST) | ITER_FINISHED;
    }
}

#[derive(Debug)]
struct NativeFillOutcome {
    written: usize,
    error: Option<String>,
}

/// Fill a caller-owned span buffer using one statically selected native entry.
///
/// Generated shims monomorphize this function with a closure that names one
/// linked AOT symbol directly. Consequently the iterator makes one indirect
/// Rust call per refill while the calls inside the refill are direct.
///
/// # Safety
///
/// `search` must implement the compiler-produced Span ABI: status 1 must
/// initialize the supplied result slot, and it must not retain any argument.
#[inline(always)]
#[allow(
    clippy::inline_always,
    dead_code,
    unsafe_code,
    reason = "generated monomorphic shims must inline this loop so their AOT entry calls remain direct; the aggregate-only profile emits no shim; status 1 guarantees an initialized result"
)]
unsafe fn fill_native_spans<Search>(
    haystack: &[u8],
    state: &mut NativeIterState,
    output: &mut [MaybeUninit<AbiResult>],
    mut search: Search,
) -> NativeFillOutcome
where
    Search: FnMut(&[u8], usize, *mut AbiResult) -> u32,
{
    let mut written = 0;
    while written < output.len() && !state.finished() {
        if state.pending_empty_progress() {
            state.set_pending_empty_progress(false);
            if state.next_start == haystack.len() {
                state.finish();
                break;
            }
            state.next_start += 1;
        }

        let search_start = state.next_start;
        let status = search(haystack, search_start, output[written].as_mut_ptr());
        match status {
            0 => {
                state.finish();
                break;
            }
            1 => {
                // Compiler-produced Span entries initialize exactly one result
                // on status 1. The generated shim is the only caller.
                let result = unsafe { output[written].assume_init_ref() };
                if search_start > result.start
                    || result.start > result.end
                    || result.end > haystack.len()
                {
                    state.finish();
                    return NativeFillOutcome {
                        written,
                        error: Some(format!(
                            "native AOT entry returned an invalid result: status={status} start={} end={} window={search_start}..{}",
                            result.start,
                            result.end,
                            haystack.len()
                        )),
                    };
                }

                if result.start == result.end
                    && state.has_last_match()
                    && state.last_match_end == result.end
                {
                    if state.next_start == haystack.len() {
                        state.finish();
                        break;
                    }
                    state.next_start += 1;
                    continue;
                }

                state.next_start = result.end;
                state.last_match_end = result.end;
                state.flags |= ITER_HAS_LAST;
                state.set_pending_empty_progress(result.start == result.end);
                written += 1;
            }
            _ => {
                state.finish();
                return NativeFillOutcome {
                    written,
                    error: Some(format!("native AOT entry failed with status {status}")),
                };
            }
        }
    }
    NativeFillOutcome {
        written,
        error: None,
    }
}

#[allow(
    unsafe_code,
    reason = "the shared validator reads only the initialized prefix published by the compiler-produced fill"
)]
fn fill_compiled_spans<Fill>(
    haystack: &[u8],
    state: &mut NativeIterState,
    output: &mut [MaybeUninit<AbiResult>],
    fill: Fill,
) -> NativeFillOutcome
where
    Fill: FnOnce(
        *const u8,
        usize,
        *mut NativeIterState,
        *mut AbiResult,
        usize,
        *mut usize,
    ) -> u32,
{
    if output.is_empty() {
        state.finish();
        return NativeFillOutcome {
            written: 0,
            error: Some("compiled Span refill received an empty output buffer".to_owned()),
        };
    }

    let mut written = 0;
    let status = fill(
        haystack.as_ptr(),
        haystack.len(),
        state,
        output.as_mut_ptr().cast::<AbiResult>(),
        output.len(),
        &raw mut written,
    );
    if written > output.len() {
        state.finish();
        return NativeFillOutcome {
            written: 0,
            error: Some(format!(
                "compiled Span refill overreported its initialized prefix: {written} > {}",
                output.len()
            )),
        };
    }
    if state.reserved != 0
        || state.flags & !ITER_KNOWN_FLAGS != 0
        || state.next_start > haystack.len()
        || state.last_match_end > haystack.len()
        || (state.pending_empty_progress()
            && (!state.has_last_match()
                || state.finished()
                || state.next_start != state.last_match_end))
        || (!state.has_last_match() && (state.next_start != 0 || state.last_match_end != 0))
        || (state.has_last_match() && state.next_start < state.last_match_end)
    {
        state.finish();
        return NativeFillOutcome {
            written: 0,
            error: Some("compiled Span refill returned invalid iterator state".to_owned()),
        };
    }
    if written != 0 {
        // The fill ABI guarantees that exactly the published prefix is
        // initialized. Checking its final element is enough to tie the
        // returned iterator state to the spans the caller will consume,
        // without adding a second walk over the hot-path result buffer.
        let last = unsafe { output[written - 1].assume_init_ref() };
        if last.start > last.end
            || last.end > haystack.len()
            || !state.has_last_match()
            || state.last_match_end != last.end
            || (status == 1 && state.next_start != last.end)
        {
            state.finish();
            return NativeFillOutcome {
                written: 0,
                error: Some(
                    "compiled Span refill returned an inconsistent final span/state".to_owned(),
                ),
            };
        }
    }

    let error = match status {
        0 if state.finished() => None,
        1 if written == output.len() && !state.finished() => None,
        0 => {
            Some("compiled Span refill returned terminal status without finishing state".to_owned())
        }
        1 => Some(format!(
            "compiled Span refill returned continuation status after writing {written}/{} spans",
            output.len()
        )),
        _ => Some(format!("compiled Span refill failed with status {status}")),
    };
    if error.is_some() {
        state.finish();
    }
    NativeFillOutcome { written, error }
}

#[allow(
    unsafe_code,
    reason = "single checked call boundary for a compiler-produced prepared Span-fill entry"
)]
fn fill_prepared_spans(
    fill: PreparedSpanFill,
    handle: FreAotRegexExclusiveHandleV1,
    haystack: &[u8],
    state: &mut NativeIterState,
    output: &mut [MaybeUninit<AbiResult>],
) -> NativeFillOutcome {
    fill_compiled_spans(
        haystack,
        state,
        output,
        |haystack, haystack_len, state, results, capacity, written| {
            // SAFETY: `PreparedNative` exclusively owns `handle`; every
            // pointer/extent comes from the live arguments validated above.
            unsafe {
                fill(
                    handle,
                    haystack,
                    haystack_len,
                    state,
                    results,
                    capacity,
                    written,
                )
            }
        },
    )
}

#[allow(
    unsafe_code,
    reason = "single checked call boundary for a compiler-produced handle-free Span-fill entry"
)]
fn fill_direct_spans(
    fill: DirectSpanFill,
    haystack: &[u8],
    state: &mut NativeIterState,
    output: &mut [MaybeUninit<AbiResult>],
) -> NativeFillOutcome {
    fill_compiled_spans(
        haystack,
        state,
        output,
        |haystack, haystack_len, state, results, capacity, written| {
            // SAFETY: every pointer and extent is derived from the live
            // borrowed arguments. The compiler-produced entry retains none
            // and initializes exactly the prefix it publishes in `written`.
            unsafe {
                fill(
                    haystack,
                    haystack_len,
                    state,
                    results,
                    capacity,
                    written,
                )
            }
        },
    )
}

impl AotExactSingletonFirstCandidateFactory {
    /// Select one stateless whole-buffer endpoint before acquiring a haystack.
    ///
    /// The caller supplies the exact configured-HIR literal bytes established
    /// independently by its stock matcher integration. Only
    /// Optimizing/Exists tuples can be selected. An absent or compiler-declined
    /// endpoint returns `Ok(None)`; once a raw manifest tuple is present, every
    /// receipt, target, ABI, symbol, and literal mismatch is terminal.
    ///
    /// # Errors
    ///
    /// Returns a raw-free error for an ambiguous, malformed, or stale present
    /// registry row.
    pub fn select(
        mode: AotMode,
        output: AotOutput,
        pattern: &str,
        case_insensitive: bool,
        configured_literal: &[u8],
    ) -> Result<Option<Self>, String> {
        select_exact_singleton_first_candidate_spec(
            generated_first_candidates::FIRST_CANDIDATE_SPECS,
            mode,
            output,
            pattern,
            case_insensitive,
            configured_literal,
        )
        .map(|spec| spec.map(|spec| Self { spec }))
    }

    /// Raw-free structural route description.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        self.spec.description
    }

    /// Authenticated build receipt for the selected stateless endpoint.
    #[must_use]
    pub const fn receipt(&self) -> AotExactSingletonFirstCandidateReceiptV1 {
        self.spec.receipt
    }

    /// Find the earliest-completing possible exact-literal match.
    ///
    /// `ConfirmedMiss` is authoritative only under the receipt's independent
    /// exact nonempty LF-free singleton proof. A positive result is always a
    /// candidate whose containing line must be checked by stock ripgrep.
    ///
    /// # Errors
    ///
    /// Any native failure, malformed sentinel, or out-of-range success after
    /// receiving the haystack is terminal and is never converted to fallback.
    pub fn find(&self, haystack: &[u8]) -> Result<AotExactSingletonFirstCandidateOutcome, String> {
        native_exact_singleton_first_candidate(
            self.spec.entry,
            self.spec.receipt.literal_bytes,
            haystack,
        )
    }
}

fn select_exact_singleton_first_candidate_spec<'a>(
    specs: &'a [ExactSingletonFirstCandidateSpec],
    mode: AotMode,
    output: AotOutput,
    pattern: &str,
    case_insensitive: bool,
    configured_literal: &[u8],
) -> Result<Option<&'a ExactSingletonFirstCandidateSpec>, String> {
    if mode != AotMode::Optimizing || output != AotOutput::Exists {
        return Ok(None);
    }
    let request_key = manifest_profile_key(pattern, case_insensitive);
    let mut matching = specs
        .iter()
        .filter(|spec| spec.manifest_profile_key == request_key);
    let Some(spec) = matching.next() else {
        return Ok(None);
    };
    if matching.next().is_some() {
        return Err(
            "exact-singleton first-candidate registry contains an ambiguous profile key".to_owned(),
        );
    }
    if spec.receipt.manifest_profile_key != spec.manifest_profile_key
        || !spec.receipt.authenticates_request(
            request_key,
            case_insensitive,
            configured_literal,
            spec.entry_symbol,
        )
    {
        return Err(
            "exact-singleton first-candidate registry receipt authentication failed".to_owned(),
        );
    }
    Ok(Some(spec))
}

#[allow(
    unsafe_code,
    reason = "single checked call boundary for an authenticated compiler-produced stateless exact-singleton entry"
)]
fn native_exact_singleton_first_candidate(
    entry: NativeExactSingletonFirstCandidate,
    literal_bytes: usize,
    haystack: &[u8],
) -> Result<AotExactSingletonFirstCandidateOutcome, String> {
    let mut position = MaybeUninit::<u64>::uninit();
    // SAFETY: the slice is readable for its complete extent and `position` is
    // aligned, writable, and disjoint. The authenticated V1 entry retains no
    // argument and initializes the result exactly when returning status zero.
    let status = unsafe { entry(haystack.as_ptr(), haystack.len(), position.as_mut_ptr()) };
    if status != 0 {
        return Err(format!(
            "compiled exact-singleton first-candidate entry failed with status {status}"
        ));
    }
    // The compiler-produced ABI initializes the result exactly on success.
    let position = unsafe { position.assume_init() };
    if position == EXACT_SINGLETON_FIRST_CANDIDATE_MISS {
        return Ok(AotExactSingletonFirstCandidateOutcome::ConfirmedMiss);
    }
    let position = usize::try_from(position).map_err(|_| {
        "compiled exact-singleton first-candidate entry returned an invalid position".to_owned()
    })?;
    if position >= haystack.len()
        || position
            .checked_add(1)
            .is_none_or(|match_end| match_end < literal_bytes)
    {
        return Err(
            "compiled exact-singleton first-candidate entry returned an invalid position"
                .to_owned(),
        );
    }
    Ok(AotExactSingletonFirstCandidateOutcome::Candidate { position })
}

impl AotMatchingLfLineWitnessFactory {
    /// Select one stateless whole-buffer witness before acquiring a haystack.
    ///
    /// Only Optimizing/Exists tuples independently proved at build time to be
    /// assertion-free exact finite nonempty LF-free languages can appear.
    /// An absent or compiler-declined endpoint returns `Ok(None)`; every
    /// mismatch in a present raw-free receipt is terminal.
    ///
    /// # Errors
    ///
    /// Returns a raw-free error for an ambiguous, malformed, or stale present
    /// registry row.
    pub fn select(
        mode: AotMode,
        output: AotOutput,
        pattern: &str,
        case_insensitive: bool,
    ) -> Result<Option<Self>, String> {
        select_matching_lf_line_witness_spec(
            generated_lf_line_witnesses::MATCHING_LF_LINE_WITNESS_SPECS,
            mode,
            output,
            pattern,
            case_insensitive,
        )
        .map(|spec| spec.map(|spec| Self { spec }))
    }

    /// Raw-free structural route description.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        self.spec.description
    }

    /// Authenticated build receipt for the selected stateless endpoint.
    #[must_use]
    pub const fn receipt(&self) -> AotMatchingLfLineWitnessReceiptV1 {
        self.spec.receipt
    }

    /// Find one byte in an LF-delimited line that may contain a match.
    ///
    /// `ConfirmedMiss` is authoritative under the receipt's independent
    /// exact finite nonempty LF-free language proof. A positive result remains
    /// a candidate whose containing line must be checked by stock ripgrep.
    ///
    /// # Errors
    ///
    /// Any native failure, malformed sentinel, or out-of-range or
    /// delimiter-valued success after receiving the haystack is terminal and
    /// is never converted to fallback.
    pub fn find(&self, haystack: &[u8]) -> Result<AotMatchingLfLineWitnessOutcome, String> {
        native_matching_lf_line_witness(self.spec.entry, haystack)
    }
}

fn select_matching_lf_line_witness_spec<'a>(
    specs: &'a [MatchingLfLineWitnessSpec],
    mode: AotMode,
    output: AotOutput,
    pattern: &str,
    case_insensitive: bool,
) -> Result<Option<&'a MatchingLfLineWitnessSpec>, String> {
    if mode != AotMode::Optimizing || output != AotOutput::Exists {
        return Ok(None);
    }
    let request_key = manifest_profile_key(pattern, case_insensitive);
    let mut matching = specs
        .iter()
        .filter(|spec| spec.manifest_profile_key == request_key);
    let Some(spec) = matching.next() else {
        return Ok(None);
    };
    if matching.next().is_some() {
        return Err(
            "matching-LF-line witness registry contains an ambiguous profile key".to_owned(),
        );
    }
    if spec.receipt.manifest_profile_key != spec.manifest_profile_key
        || !spec
            .receipt
            .authenticates_request(request_key, case_insensitive, spec.entry_symbol)
    {
        return Err("matching-LF-line witness registry receipt authentication failed".to_owned());
    }
    Ok(Some(spec))
}

#[allow(
    unsafe_code,
    reason = "single checked call boundary for an authenticated compiler-produced stateless matching-LF-line entry"
)]
fn native_matching_lf_line_witness(
    entry: NativeMatchingLfLineWitness,
    haystack: &[u8],
) -> Result<AotMatchingLfLineWitnessOutcome, String> {
    let mut position = MaybeUninit::<u64>::uninit();
    // SAFETY: the slice is readable for its complete extent and `position` is
    // aligned, writable, and disjoint. The authenticated V1 entry retains no
    // argument and initializes the result exactly when returning status zero.
    let status = unsafe { entry(haystack.as_ptr(), haystack.len(), position.as_mut_ptr()) };
    if status != 0 {
        return Err(format!(
            "compiled matching-LF-line witness entry failed with status {status}"
        ));
    }
    // The compiler-produced ABI initializes the result exactly on success.
    let position = unsafe { position.assume_init() };
    if position == MATCHING_LF_LINE_WITNESS_MISS {
        return Ok(AotMatchingLfLineWitnessOutcome::ConfirmedMiss);
    }
    let position = usize::try_from(position).map_err(|_| {
        "compiled matching-LF-line witness entry returned an invalid position".to_owned()
    })?;
    if position >= haystack.len() || haystack[position] == b'\n' {
        return Err(
            "compiled matching-LF-line witness entry returned an invalid position".to_owned(),
        );
    }
    Ok(AotMatchingLfLineWitnessOutcome::Candidate { position })
}

impl AotExact64SetFactory {
    /// Select one exact ordered source vector and complete ripgrep profile.
    ///
    /// Unsupported request semantics and absent/declined vectors return
    /// `Ok(None)` before any haystack is acquired or inspected. A registry row
    /// whose raw-free receipt no longer authenticates is a terminal error.
    ///
    /// # Errors
    ///
    /// Returns an error when a linked registry row is ambiguous or fails its
    /// receipt/ABI authentication. Diagnostics never contain regex sources.
    pub fn select(
        mode: AotMode,
        output: AotOutput,
        patterns: &[&str],
        profile: RipgrepAotExact64SetProfileV1,
    ) -> Result<Option<Self>, String> {
        select_exact64_set_spec(
            generated_exact64_sets::EXACT64_SET_SPECS,
            mode,
            output,
            patterns,
            profile,
        )
        .map(|spec| spec.map(|spec| Self { spec }))
    }

    /// Raw-free structural route description.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        self.spec.description
    }

    /// Authenticated build receipt for the selected static object.
    #[must_use]
    pub const fn receipt(&self) -> AotExact64SetReceiptV1 {
        self.spec.receipt
    }

    /// Run the stateless native first-any prefilter over a complete byte slice.
    ///
    /// A returned [`AotExact64SetOutcome::Candidate`] is only a hint to ask the
    /// stock matcher to verify the containing line. It never authorizes a match,
    /// pattern ID, span, or capture. `ConfirmedMiss` is authoritative under the
    /// receipt's exact nonempty LF-free proof.
    ///
    /// # Errors
    ///
    /// Every native status or malformed success result is terminal after this
    /// method receives the haystack. The adapter never converts such a failure
    /// into a stock fallback, which prevents a second access under weaker proof.
    pub fn prefilter(&self, haystack: &[u8]) -> Result<AotExact64SetOutcome, String> {
        native_exact64_first_any(self.spec.entry, haystack)
    }
}

fn select_exact64_set_spec<'a>(
    specs: &'a [Exact64SetSpec],
    mode: AotMode,
    output: AotOutput,
    patterns: &[&str],
    profile: RipgrepAotExact64SetProfileV1,
) -> Result<Option<&'a Exact64SetSpec>, String> {
    if mode != AotMode::Optimizing
        || output != AotOutput::Exists
        || !profile.is_supported()
        || !(REGEX_SET_EXACT64_MIN_PATTERNS..=REGEX_SET_EXACT64_MAX_PATTERNS)
            .contains(&patterns.len())
    {
        return Ok(None);
    }
    let registry_key = exact64_set_registry_key(patterns, profile.case_insensitive);
    let mut matching = specs.iter().filter(|spec| spec.registry_key == registry_key);
    let Some(spec) = matching.next() else {
        return Ok(None);
    };
    if matching.next().is_some() {
        return Err("exact64 set registry contains an ambiguous authenticated key".to_owned());
    }
    if !spec.entry_symbol.starts_with("fre_aot_regex_set_exact64_first_any_v1_")
        || !spec
            .receipt
            .authenticates_request(registry_key, profile, patterns.len())
    {
        return Err("exact64 set registry receipt authentication failed".to_owned());
    }
    Ok(Some(spec))
}

#[allow(
    unsafe_code,
    reason = "single checked call boundary for an authenticated compiler-produced exact64 first-any entry"
)]
fn native_exact64_first_any(
    entry: NativeExact64FirstAny,
    haystack: &[u8],
) -> Result<AotExact64SetOutcome, String> {
    let mut position = MaybeUninit::<u64>::uninit();
    // SAFETY: the slice is readable for its complete extent and `position` is
    // aligned, writable, and disjoint. The authenticated V1 entry retains no
    // argument and publishes the word transactionally only on status zero.
    let status = unsafe {
        entry(
            haystack.as_ptr(),
            haystack.len(),
            0,
            haystack.len(),
            position.as_mut_ptr(),
        )
    };
    if status != REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_STATUS_SUCCESS {
        return Err(format!(
            "compiled exact64 first-any entry failed with status {status}"
        ));
    }
    // The compiler-produced ABI initializes the result exactly on success.
    let position = unsafe { position.assume_init() };
    if position == REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_NO_MATCH {
        return Ok(AotExact64SetOutcome::ConfirmedMiss);
    }
    let position = usize::try_from(position)
        .map_err(|_| "compiled exact64 first-any entry returned an invalid position".to_owned())?;
    if position >= haystack.len() {
        return Err("compiled exact64 first-any entry returned an invalid position".to_owned());
    }
    Ok(AotExact64SetOutcome::Candidate { position })
}

/// Build-time-authenticated factory for one aggregate-only native `GrepCount`
/// artifact.
///
/// Selection is structural: a missing tuple means the build did not emit the
/// endpoint or one of its two independent exact-language admissions declined.
/// No haystack is inspected during selection.
#[derive(Clone, Copy, Debug)]
pub struct AotGrepCountFactory {
    spec: &'static GrepCountSpec,
}

impl AotGrepCountFactory {
    /// Select an exact pattern/profile tuple from the opt-in `GrepCount`
    /// registry.
    ///
    /// Only [`AotMode::Optimizing`] can be present. `None` is the complete
    /// structural decline; callers may choose another implementation before
    /// acquiring or inspecting a haystack.
    #[must_use]
    pub fn select(mode: AotMode, pattern: &str, case_insensitive: bool) -> Option<Self> {
        generated::GREP_COUNT_SPECS
            .iter()
            .find(|spec| {
                spec.mode == mode
                    && spec.pattern == pattern
                    && spec.case_insensitive == case_insensitive
            })
            .map(|spec| Self { spec })
    }

    /// Structural compiler and effective aggregate-route description.
    #[must_use]
    pub const fn description(self) -> &'static str {
        self.spec.description
    }

    /// Validate the embedded exact program and allocate its exclusive runtime
    /// handle.
    ///
    /// # Errors
    ///
    /// A preparation failure is terminal for the selected endpoint. It is
    /// never converted into a late structural decline.
    #[allow(
        unsafe_code,
        reason = "preparation validates and owns the exact compiler-exported immutable program"
    )]
    pub fn prepare(self) -> Result<AotGrepCount, String> {
        let mut handle = FreAotRegexExclusiveHandleV1::INVALID;
        // SAFETY: the generated spec borrows the complete immutable program
        // symbol exported by the same authenticated object as `entry`, and
        // `handle` is aligned, writable, and disjoint.
        let status = unsafe {
            fre_aot_regex_runtime_prepare_exclusive_v1(
                self.spec.program.as_ptr(),
                self.spec.program.len(),
                &raw mut handle,
            )
        };
        if status != 0 || handle.is_invalid() {
            return Err(format!(
                "prepare compiled AOT GrepCount handle failed with status {status}"
            ));
        }
        Ok(AotGrepCount {
            description: self.spec.description,
            entry: self.spec.entry,
            handle,
        })
    }
}

/// Exclusively prepared aggregate-only matching-line counter.
///
/// The build admits this handle only after independent `fre-syntax`/
/// `fre-lower` proof and compiler report/identity/export authentication of a
/// non-empty, non-nullable, assertion-free exact finite byte language with no
/// CR or LF member. It intentionally exposes no match spans or captures.
#[derive(Debug)]
pub struct AotGrepCount {
    description: &'static str,
    entry: PreparedGrepCount,
    handle: FreAotRegexExclusiveHandleV1,
}

// SAFETY: this owner moves only while idle. Every native call requires
// `&mut self`, and Drop also requires exclusive ownership, so no operation can
// overlap a cross-thread move or destruction.
#[allow(
    unsafe_code,
    reason = "the exclusive GrepCount ABI permits moving an idle uniquely owned handle"
)]
unsafe impl Send for AotGrepCount {}

impl AotGrepCount {
    /// Structural compiler and effective aggregate-route description.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        self.description
    }

    /// Count LF/CRLF semantic line domains containing at least one match.
    ///
    /// # Errors
    ///
    /// Any native status failure is terminal and returned directly. This
    /// selected handle never retries through the ordinary matcher.
    pub fn count_matching_lines(&mut self, haystack: &[u8]) -> Result<u64, String> {
        native_grep_count(self.entry, self.handle, haystack)
    }
}

#[allow(
    unsafe_code,
    reason = "single checked call boundary for a compiler-produced prepared GrepCount entry"
)]
fn native_grep_count(
    entry: PreparedGrepCount,
    handle: FreAotRegexExclusiveHandleV1,
    haystack: &[u8],
) -> Result<u64, String> {
    let mut value = MaybeUninit::<u64>::uninit();
    // SAFETY: the prepared owner exclusively holds the live handle; the
    // haystack is readable for its complete extent; `value` is aligned,
    // writable, disjoint, and read only after status zero publishes it.
    let status = unsafe {
        entry(
            handle,
            haystack.as_ptr(),
            haystack.len(),
            value.as_mut_ptr(),
        )
    };
    if status != 0 {
        return Err(format!(
            "compiled AOT GrepCount entry failed with status {status}"
        ));
    }
    // The compiler-produced ABI initializes the output exactly on status zero.
    Ok(unsafe { value.assume_init() })
}

#[allow(
    unsafe_code,
    reason = "this owner destroys its live exclusive GrepCount handle exactly once"
)]
impl Drop for AotGrepCount {
    fn drop(&mut self) {
        let handle = std::mem::replace(&mut self.handle, FreAotRegexExclusiveHandleV1::INVALID);
        if !handle.is_invalid() {
            // SAFETY: this value exclusively owns the live handle, and Drop's
            // mutable borrow excludes an overlapping aggregate call.
            let _status = unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) };
        }
    }
}

/// One prepared matcher selected from the fixed ripgrep-suite registry.
#[derive(Debug)]
pub struct AotMatcher {
    output: AotOutput,
    description: &'static str,
    backend: Backend,
}

impl AotMatcher {
    /// Select and prepare an exact precompiled pattern/profile/output tuple.
    ///
    /// # Errors
    ///
    /// Returns an error when the tuple is absent or a runtime-backed artifact
    /// cannot be validated and prepared.
    pub fn new(
        mode: AotMode,
        output: AotOutput,
        pattern: &str,
        case_insensitive: bool,
    ) -> Result<Self, String> {
        let spec = generated::SPECS
            .iter()
            .find(|spec| {
                spec.mode == mode
                    && spec.output == output
                    && spec.pattern == pattern
                    && spec.case_insensitive == case_insensitive
            })
            .ok_or_else(|| missing_spec_error(mode, output, pattern, case_insensitive))?;
        let backend = match spec.backend {
            BackendFactory::Native {
                search,
                fill,
                exists_batch,
            } => Backend::Native {
                search,
                fill,
                exists_batch,
            },
            BackendFactory::Prepared {
                search,
                program,
                span_fill,
                exists_batch,
                required_prepare_capabilities,
            } => Backend::Prepared(PreparedNative::new(
                spec.output,
                search,
                program,
                span_fill,
                exists_batch,
                required_prepare_capabilities,
            )?),
            BackendFactory::Runtime(bytes) => Backend::Runtime(Box::new(
                PreparedAotRegex::deserialize(bytes)
                    .map_err(|error| format!("prepare compiled AOT program: {error}"))?,
            )),
        };
        Ok(Self {
            output,
            description: spec.description,
            backend,
        })
    }

    /// Structural compiler and effective execution-route description.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        self.description
    }

    /// Search an `Exists` artifact over the complete haystack.
    ///
    /// # Errors
    ///
    /// Returns an error for an output-contract mismatch or execution failure.
    pub fn is_match(&mut self, haystack: &[u8]) -> Result<bool, String> {
        if self.output != AotOutput::Exists {
            return Err("AOT matcher was not compiled for Exists".to_owned());
        }
        match self.search(haystack, 0)? {
            MatchResult::Exists(found) => Ok(found),
            _ => Err("AOT Exists artifact returned a different result contract".to_owned()),
        }
    }

    /// Search up to [`EXISTS_BATCH_CAPACITY`] independent line haystacks.
    ///
    /// A one-haystack request uses the scalar entry. Compiled prepared and
    /// self-contained direct artifacts execute every larger complete batch
    /// through one native invocation. Other artifact routes preserve
    /// identical behavior with a checked per-haystack compatibility loop.
    ///
    /// # Errors
    ///
    /// Returns an error for an output-contract mismatch, unequal input/output
    /// lengths, an oversized batch, or any execution/ABI failure.
    #[allow(
        unsafe_code,
        reason = "the initialized prefix of the bounded stack descriptor array is tracked exactly"
    )]
    pub fn is_match_batch(
        &mut self,
        haystacks: &[&[u8]],
        matched: &mut [bool],
    ) -> Result<(), String> {
        self.validate_exists_batch_request(haystacks.len(), matched.len())?;
        if haystacks.is_empty() {
            return Ok(());
        }

        let mut descriptors =
            [const { MaybeUninit::<AotHaystack<'_>>::uninit() }; EXISTS_BATCH_CAPACITY];
        for (descriptor, haystack) in descriptors.iter_mut().zip(haystacks) {
            descriptor.write(AotHaystack::from(*haystack));
        }
        // SAFETY: the loop initialized exactly the prefix selected here. Each
        // view borrows its corresponding input slice, and the private dispatch
        // retains neither descriptors nor byte pointers after it returns.
        let descriptors = unsafe {
            std::slice::from_raw_parts(
                descriptors.as_ptr().cast::<AotHaystack<'_>>(),
                haystacks.len(),
            )
        };
        if descriptors.len() > 1
            && let Backend::Native {
                exists_batch: Some(batch),
                ..
            } = &self.backend
        {
            return direct_native_is_match_descriptor_batch(*batch, descriptors, matched);
        }
        self.is_match_descriptor_batch_validated(descriptors, matched)
    }

    /// Search reusable haystack descriptors without an adapter-side copy.
    ///
    /// A caller that batches the same line buffers across matchers or repeated
    /// searches can construct [`AotHaystack`] values once and reuse them.
    /// Compiled prepared and self-contained direct batch entries read this
    /// descriptor slice in place. Scalar and portable compatibility routes
    /// retain identical matching behavior by reading the lifetime-bound byte
    /// slices represented by each descriptor.
    ///
    /// A one-haystack request continues to use the scalar entry. Empty batches
    /// are accepted and leave the output unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error for an output-contract mismatch, unequal input/output
    /// lengths, an oversized batch, or any execution/ABI failure. If a native
    /// batch reports an error after publishing a valid prefix, that prefix is
    /// retained in `matched` and the remaining output elements are unchanged.
    #[inline]
    pub fn is_match_descriptor_batch(
        &mut self,
        haystacks: &[AotHaystack<'_>],
        matched: &mut [bool],
    ) -> Result<(), String> {
        // Keep the selector frameless in optimized builds. A singleton should
        // enter the scalar adapter directly, while larger requests retain the
        // zero-copy descriptor batch path and its independently sized frame.
        if haystacks.len() == 1 && matched.len() == 1 {
            return self.is_match_descriptor_single(&haystacks[0], &mut matched[0]);
        }
        // Keep the authenticated direct-native batch route out of the large
        // compatibility dispatcher. All request checks remain explicit here;
        // malformed and non-direct requests enter the exact old path below.
        if self.output == AotOutput::Exists
            && haystacks.len() == matched.len()
            && (2..=EXISTS_BATCH_CAPACITY).contains(&haystacks.len())
            && let Backend::Native {
                exists_batch: Some(batch),
                ..
            } = &self.backend
        {
            return direct_native_is_match_descriptor_batch(*batch, haystacks, matched);
        }
        self.is_match_descriptor_batch_non_single(haystacks, matched)
    }

    #[inline(never)]
    fn is_match_descriptor_batch_non_single(
        &mut self,
        haystacks: &[AotHaystack<'_>],
        matched: &mut [bool],
    ) -> Result<(), String> {
        self.validate_exists_batch_request(haystacks.len(), matched.len())?;
        if haystacks.is_empty() {
            return Ok(());
        }
        self.is_match_descriptor_batch_validated(haystacks, matched)
    }

    fn validate_exists_batch_request(
        &self,
        haystack_len: usize,
        matched_len: usize,
    ) -> Result<(), String> {
        if self.output != AotOutput::Exists {
            return Err("AOT matcher was not compiled for Exists".to_owned());
        }
        if haystack_len != matched_len {
            return Err(format!(
                "AOT Exists batch input/output length mismatch: {} != {}",
                haystack_len, matched_len
            ));
        }
        if haystack_len > EXISTS_BATCH_CAPACITY {
            return Err(format!(
                "AOT Exists batch length {} exceeds capacity {EXISTS_BATCH_CAPACITY}",
                haystack_len
            ));
        }
        Ok(())
    }

    #[inline(never)]
    fn is_match_descriptor_batch_validated(
        &mut self,
        haystacks: &[AotHaystack<'_>],
        matched: &mut [bool],
    ) -> Result<(), String> {
        debug_assert_eq!(haystacks.len(), matched.len());
        debug_assert!(!haystacks.is_empty());
        debug_assert!(haystacks.len() <= EXISTS_BATCH_CAPACITY);
        match &mut self.backend {
            Backend::Prepared(prepared) => {
                if haystacks.len() > 1
                    && let Some(batch) = prepared.exists_batch
                {
                    return prepared_native_is_match_descriptor_batch(
                        batch,
                        prepared.handle,
                        haystacks,
                        matched,
                    );
                }
                for (haystack, matched) in haystacks.iter().zip(matched) {
                    let haystack = haystack.as_slice();
                    *matched = match prepared_native_search(
                        prepared.search,
                        prepared.handle,
                        AotOutput::Exists,
                        haystack,
                        0,
                    )? {
                        MatchResult::Exists(found) => found,
                        _ => {
                            return Err("AOT Exists artifact returned a different result contract"
                                .to_owned());
                        }
                    };
                }
            }
            Backend::Native {
                search,
                exists_batch,
                ..
            } => {
                if haystacks.len() > 1
                    && let Some(batch) = exists_batch
                {
                    return direct_native_is_match_descriptor_batch(*batch, haystacks, matched);
                }
                for (haystack, matched) in haystacks.iter().zip(matched) {
                    let haystack = haystack.as_slice();
                    *matched = match native_search(*search, AotOutput::Exists, haystack, 0)? {
                        MatchResult::Exists(found) => found,
                        _ => {
                            return Err("AOT Exists artifact returned a different result contract"
                                .to_owned());
                        }
                    };
                }
            }
            Backend::Runtime(prepared) => {
                for (haystack, matched) in haystacks.iter().zip(matched) {
                    let haystack = haystack.as_slice();
                    *matched = match prepared
                        .search(haystack, SearchWindow::new(0, haystack.len()))
                        .map_err(|error| format!("prepared AOT search: {error}"))?
                    {
                        MatchResult::Exists(found) => found,
                        _ => {
                            return Err("AOT Exists artifact returned a different result contract"
                                .to_owned());
                        }
                    };
                }
            }
        }
        Ok(())
    }

    #[inline(never)]
    fn is_match_descriptor_single(
        &mut self,
        haystack: &AotHaystack<'_>,
        matched: &mut bool,
    ) -> Result<(), String> {
        if self.output != AotOutput::Exists {
            return Err("AOT matcher was not compiled for Exists".to_owned());
        }
        let haystack = haystack.as_slice();
        *matched = match &mut self.backend {
            Backend::Prepared(prepared) => match prepared_native_search(
                prepared.search,
                prepared.handle,
                AotOutput::Exists,
                haystack,
                0,
            )? {
                MatchResult::Exists(found) => found,
                _ => {
                    return Err(
                        "AOT Exists artifact returned a different result contract".to_owned()
                    );
                }
            },
            Backend::Native { search, .. } => {
                match native_search(*search, AotOutput::Exists, haystack, 0)? {
                    MatchResult::Exists(found) => found,
                    _ => {
                        return Err(
                            "AOT Exists artifact returned a different result contract".to_owned()
                        );
                    }
                }
            }
            Backend::Runtime(prepared) => match prepared
                .search(haystack, SearchWindow::new(0, haystack.len()))
                .map_err(|error| format!("prepared AOT search: {error}"))?
            {
                MatchResult::Exists(found) => found,
                _ => {
                    return Err(
                        "AOT Exists artifact returned a different result contract".to_owned()
                    );
                }
            },
        };
        Ok(())
    }

    /// Find the first selected span in the complete haystack.
    ///
    /// # Errors
    ///
    /// Returns an error for an output-contract mismatch or execution failure.
    pub fn find<'h>(&mut self, haystack: &'h [u8]) -> Result<Option<AotMatch<'h>>, String> {
        self.find_at(haystack, 0)
    }

    /// Find the first selected span at or after `start` in the original haystack.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid start, output-contract mismatch, or
    /// execution failure.
    pub fn find_at<'h>(
        &mut self,
        haystack: &'h [u8],
        start: usize,
    ) -> Result<Option<AotMatch<'h>>, String> {
        if self.output != AotOutput::Span {
            return Err("AOT matcher was not compiled for Span".to_owned());
        }
        match self.search(haystack, start)? {
            MatchResult::Span(span) => span
                .map(|(match_start, match_end)| {
                    AotMatch::from_span(haystack, match_start, match_end).ok_or_else(|| {
                        "AOT Span artifact returned a match outside its haystack".to_owned()
                    })
                })
                .transpose(),
            _ => Err("AOT Span artifact returned a different result contract".to_owned()),
        }
    }

    /// Iterate over every non-overlapping match using Rust byte-regex empty
    /// match progress.
    ///
    /// Portable and compiled-prepared artifacts retain their workspace for
    /// the full iterator lifetime. Both compiled routes refill 64 spans at a
    /// time, amortizing indirect dispatch with bounded read-ahead.
    ///
    /// # Errors
    ///
    /// Returns an error unless this matcher was compiled for spans and has a
    /// compatible iterator backend. Execution failures remain iterator items.
    pub fn find_iter<'m, 'h>(
        &'m mut self,
        haystack: &'h [u8],
    ) -> Result<AotMatches<'m, 'h>, String> {
        self.find_iter_at(haystack, 0)
    }

    /// Iterate over every non-overlapping match at or after `start` in the
    /// original haystack.
    ///
    /// The complete haystack remains visible to absolute, line, and
    /// word-boundary assertions. Only the initial search cursor advances.
    /// Empty-match progress remains identical to [`Self::find_iter`].
    ///
    /// # Errors
    ///
    /// Returns an error for an out-of-bounds start, or unless this matcher was
    /// compiled for spans and has a compatible iterator backend. Execution
    /// failures remain iterator items.
    pub fn find_iter_at<'m, 'h>(
        &'m mut self,
        haystack: &'h [u8],
        start: usize,
    ) -> Result<AotMatches<'m, 'h>, String> {
        if self.output != AotOutput::Span {
            return Err("AOT matcher was not compiled for Span".to_owned());
        }
        let state = NativeIterState::initial_at(start, haystack.len())
            .map_err(|error| format!("initialize AOT Span iterator: {error}"))?;
        let backend = match &mut self.backend {
            Backend::Runtime(prepared) => AotMatchesBackend::Runtime(
                prepared
                    .find_iter_at(haystack, start)
                    .map_err(|error| error.to_string())?,
            ),
            Backend::Prepared(prepared) if prepared.span_fill.is_some() => {
                AotMatchesBackend::Native(NativeMatches::prepared(prepared, haystack, state))
            }
            Backend::Prepared(_) => {
                return Err("compiled-prepared Span artifact has no iterator entry".to_owned());
            }
            Backend::Native {
                fill: Some(fill), ..
            } => AotMatchesBackend::Native(NativeMatches::direct(*fill, haystack, state)),
            Backend::Native { fill: None, .. } => {
                return Err("AOT Span artifact has no native iterator entry".to_owned());
            }
        };
        Ok(AotMatches { backend })
    }

    fn search(&mut self, haystack: &[u8], start: usize) -> Result<MatchResult, String> {
        if start > haystack.len() {
            return Err(format!(
                "AOT search start {start} exceeds haystack length {}",
                haystack.len()
            ));
        }
        match &mut self.backend {
            Backend::Runtime(prepared) => prepared
                .search(haystack, SearchWindow::new(start, haystack.len()))
                .map_err(|error| format!("prepared AOT search: {error}")),
            Backend::Prepared(prepared) => prepared_native_search(
                prepared.search,
                prepared.handle,
                self.output,
                haystack,
                start,
            ),
            Backend::Native { search, .. } => native_search(*search, self.output, haystack, start),
        }
    }
}

fn missing_spec_error(
    mode: AotMode,
    output: AotOutput,
    pattern: &str,
    case_insensitive: bool,
) -> String {
    missing_spec_error_from(
        generated::SPECS,
        generated::ALL_MANIFEST_PROFILE_KEYS,
        generated::BUILD_VARIANT_POLICY,
        mode,
        output,
        pattern,
        case_insensitive,
    )
}

fn missing_spec_error_from(
    specs: &[CompiledSpec],
    all_manifest_profile_keys: &[[u8; 32]],
    build_variant_policy: &str,
    mode: AotMode,
    output: AotOutput,
    pattern: &str,
    case_insensitive: bool,
) -> String {
    let known_manifest_profile = all_manifest_profile_keys
        .contains(&manifest_profile_key(pattern, case_insensitive));
    if build_variant_policy == "optimizing-grep-count" && known_manifest_profile {
        return format!(
            "requested ordinary AOT variant was not emitted by this aggregate-only build: mode={mode:?} output={output:?} case_insensitive={case_insensitive} pattern={pattern:?}; build_variant_policy=optimizing-grep-count; ordinary_available_variants=none; rebuild with FRE_RIPGREP_AOT_VARIANTS=all to emit ordinary Fast/Optimizing Exists/Span variants"
        );
    }
    let available = specs
        .iter()
        .filter(|spec| spec.pattern == pattern && spec.case_insensitive == case_insensitive)
        .map(|spec| format!("{:?}+{:?}", spec.mode, spec.output))
        .collect::<Vec<_>>();
    if available.is_empty() {
        format!(
            "pattern/profile is not in the ripgrep AOT registry: mode={mode:?} output={output:?} case_insensitive={case_insensitive} pattern={pattern:?}"
        )
    } else {
        format!(
            "requested AOT variant was not emitted by this build: mode={mode:?} output={output:?} case_insensitive={case_insensitive} pattern={pattern:?}; build_variant_policy={}; available_variants={}; rebuild with FRE_RIPGREP_AOT_VARIANTS=all to emit every variant",
            build_variant_policy,
            available.join(","),
        )
    }
}

/// Stateful iterator over non-overlapping AOT matches.
#[derive(Debug)]
pub struct AotMatches<'m, 'h> {
    backend: AotMatchesBackend<'m, 'h>,
}

#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "the inline native buffer deliberately avoids one heap allocation per scanned file"
)]
enum AotMatchesBackend<'m, 'h> {
    Native(NativeMatches<'m, 'h>),
    Runtime(PreparedAotMatches<'m, 'h>),
}

#[derive(Debug)]
enum NativeMatchesFill<'m> {
    Direct(NativeFill),
    Prepared(&'m mut PreparedNative),
}

#[derive(Debug)]
struct NativeMatches<'m, 'h> {
    fill: NativeMatchesFill<'m>,
    haystack: &'h [u8],
    state: NativeIterState,
    spans: [MaybeUninit<AbiResult>; NATIVE_SPAN_BUFFER_CAPACITY],
    next: usize,
    filled: usize,
    pending_error: Option<String>,
}

impl<'m, 'h> NativeMatches<'m, 'h> {
    fn direct(fill: NativeFill, haystack: &'h [u8], state: NativeIterState) -> Self {
        Self {
            fill: NativeMatchesFill::Direct(fill),
            haystack,
            state,
            spans: [const { MaybeUninit::uninit() }; NATIVE_SPAN_BUFFER_CAPACITY],
            next: 0,
            filled: 0,
            pending_error: None,
        }
    }

    fn prepared(
        prepared: &'m mut PreparedNative,
        haystack: &'h [u8],
        state: NativeIterState,
    ) -> Self {
        NativeMatches {
            fill: NativeMatchesFill::Prepared(prepared),
            haystack,
            state,
            spans: [const { MaybeUninit::uninit() }; NATIVE_SPAN_BUFFER_CAPACITY],
            next: 0,
            filled: 0,
            pending_error: None,
        }
    }

    fn fail(&mut self, error: String) -> Result<AotMatch<'h>, String> {
        self.state.finish();
        self.next = self.filled;
        self.pending_error = None;
        Err(error)
    }
}

#[allow(
    unsafe_code,
    reason = "the iterator reads only the initialized prefix returned by its trusted native fill shim"
)]
impl<'h> Iterator for NativeMatches<'_, 'h> {
    type Item = Result<AotMatch<'h>, String>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.next < self.filled {
                // Only the `written` prefix reported by the refill is read.
                let span = unsafe { self.spans[self.next].assume_init() };
                self.next += 1;
                let Some(matched) = AotMatch::from_span(self.haystack, span.start, span.end) else {
                    return Some(self.fail(
                        "native AOT iterator buffered a match outside its haystack".to_owned(),
                    ));
                };
                return Some(Ok(matched));
            }
            if let Some(error) = self.pending_error.take() {
                return Some(self.fail(error));
            }
            if self.state.finished() {
                return None;
            }

            self.next = 0;
            let outcome = match &mut self.fill {
                NativeMatchesFill::Direct(fill) => {
                    fill(self.haystack, &mut self.state, &mut self.spans)
                }
                NativeMatchesFill::Prepared(prepared) => {
                    let fill = prepared
                        .span_fill
                        .expect("prepared iterator construction requires a fill entry");
                    match fill {
                        PreparedSpanFillFactory::Compiled(fill) => fill_prepared_spans(
                            fill,
                            prepared.handle,
                            self.haystack,
                            &mut self.state,
                            &mut self.spans,
                        ),
                        PreparedSpanFillFactory::Compatibility(fill) => fill(
                            prepared.handle,
                            self.haystack,
                            &mut self.state,
                            &mut self.spans,
                        ),
                    }
                }
            };
            self.filled = outcome.written;
            self.pending_error = outcome.error;
            if self.filled == 0 && self.pending_error.is_none() && !self.state.finished() {
                return Some(self.fail("native AOT iterator refill made no progress".to_owned()));
            }
        }
    }
}

impl<'h> Iterator for AotMatches<'_, 'h> {
    type Item = Result<AotMatch<'h>, String>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.backend {
            AotMatchesBackend::Native(matches) => matches.next(),
            AotMatchesBackend::Runtime(matches) => matches
                .next()
                .map(|result| result.map_err(|error| error.to_string())),
        }
    }
}

impl std::iter::FusedIterator for NativeMatches<'_, '_> {}
impl std::iter::FusedIterator for AotMatches<'_, '_> {}

#[allow(
    unsafe_code,
    reason = "single checked call boundary for compiler-produced V1 object entries"
)]
fn native_search(
    search: NativeSearch,
    output: AotOutput,
    haystack: &[u8],
    start: usize,
) -> Result<MatchResult, String> {
    let mut result = MaybeUninit::<AbiResult>::uninit();
    // SAFETY: compiler-produced entries use this exact C ABI. The slice gives
    // a non-null readable extent, the checked window is contained in it, and
    // `result` is aligned, writable, and disjoint for the duration of the call.
    let status = unsafe {
        search(
            haystack.as_ptr(),
            haystack.len(),
            start,
            haystack.len(),
            result.as_mut_ptr(),
        )
    };
    decode_search_result(output, status, haystack.len(), start, result)
}

#[allow(
    unsafe_code,
    reason = "single checked call boundary for compiler-produced prepared V1 object entries"
)]
fn prepared_native_search(
    search: PreparedSearch,
    handle: FreAotRegexExclusiveHandleV1,
    output: AotOutput,
    haystack: &[u8],
    start: usize,
) -> Result<MatchResult, String> {
    let mut result = MaybeUninit::<AbiResult>::uninit();
    // SAFETY: `PreparedNative` owns the live handle and is mutably borrowed
    // for this call. The remaining arguments satisfy the generated entry's
    // stable six-argument prepared ABI and are retained by neither side.
    let status = unsafe {
        search(
            handle,
            haystack.as_ptr(),
            haystack.len(),
            start,
            haystack.len(),
            result.as_mut_ptr(),
        )
    };
    decode_search_result(output, status, haystack.len(), start, result)
}

#[allow(
    unsafe_code,
    reason = "single checked call boundary for a compiler-produced direct Exists-batch entry"
)]
#[inline(never)]
fn direct_native_is_match_descriptor_batch(
    batch: NativeExistsBatch,
    haystacks: &[AotHaystack<'_>],
    matched: &mut [bool],
) -> Result<(), String> {
    debug_assert_eq!(haystacks.len(), matched.len());
    debug_assert!(!haystacks.is_empty());
    debug_assert!(haystacks.len() <= EXISTS_BATCH_CAPACITY);

    let mut processed = 0;
    // SAFETY: `AotHaystack` is transparent over `AbiHaystack`; its private
    // constructor and lifetime guarantee every descriptor names a live
    // readable slice. The batch ABI retains no pointer. This compiler-produced
    // entry writes only the valid Boolean representations 0 and 1 to the live
    // output prefix; the untouched tail remains initialized by the safe caller.
    let status = unsafe {
        batch(
            haystacks.as_ptr().cast::<AbiHaystack>(),
            haystacks.len(),
            matched.as_mut_ptr().cast::<u8>(),
            &raw mut processed,
        )
    };
    if status == 0 && processed == haystacks.len() {
        Ok(())
    } else {
        direct_exists_batch_failure(status, processed, haystacks.len())
    }
}

#[cold]
#[inline(never)]
fn direct_exists_batch_failure(
    status: u32,
    processed: usize,
    count: usize,
) -> Result<(), String> {
    if processed > count {
        return Err(format!(
            "compiled Exists batch overreported its initialized prefix: {processed} > {count}"
        ));
    }
    if status != 0 {
        return Err(format!(
            "compiled Exists batch failed with status {status} after {processed}/{count} haystacks"
        ));
    }
    debug_assert_ne!(processed, count);
    Err(format!(
        "compiled Exists batch returned success after {processed}/{count} haystacks"
    ))
}

#[allow(
    unsafe_code,
    reason = "single checked call boundary for a compiler-produced prepared Exists-batch entry"
)]
fn prepared_native_is_match_descriptor_batch(
    batch: PreparedExistsBatch,
    handle: FreAotRegexExclusiveHandleV1,
    haystacks: &[AotHaystack<'_>],
    matched: &mut [bool],
) -> Result<(), String> {
    debug_assert_eq!(haystacks.len(), matched.len());
    debug_assert!(!haystacks.is_empty());
    debug_assert!(haystacks.len() <= EXISTS_BATCH_CAPACITY);

    let mut encoded = [0xff_u8; EXISTS_BATCH_CAPACITY];
    let mut processed = 0;
    // SAFETY: `PreparedNative` exclusively owns `handle`. `AotHaystack` is
    // transparent over `AbiHaystack`; its private constructor and lifetime
    // guarantee every descriptor names a live readable slice. The batch ABI
    // retains no pointer. `encoded` has `count` writable bytes, and the
    // generated entry initializes exactly the prefix published in `processed`.
    let status = unsafe {
        batch(
            handle,
            haystacks.as_ptr().cast::<AbiHaystack>(),
            haystacks.len(),
            encoded.as_mut_ptr(),
            &raw mut processed,
        )
    };
    decode_exists_batch(status, processed, haystacks.len(), &encoded, matched)
}

fn decode_exists_batch(
    status: u32,
    processed: usize,
    count: usize,
    encoded: &[u8; EXISTS_BATCH_CAPACITY],
    matched: &mut [bool],
) -> Result<(), String> {
    if processed > count {
        return Err(format!(
            "compiled Exists batch overreported its initialized prefix: {processed} > {count}"
        ));
    }
    for (index, encoded) in encoded[..processed].iter().copied().enumerate() {
        matched[index] = match encoded {
            0 => false,
            1 => true,
            other => {
                return Err(format!(
                    "compiled Exists batch returned invalid boolean {other} at index {index}"
                ));
            }
        };
    }
    if status != 0 {
        return Err(format!(
            "compiled Exists batch failed with status {status} after {processed}/{count} haystacks"
        ));
    }
    if processed != count {
        return Err(format!(
            "compiled Exists batch returned success after {processed}/{count} haystacks"
        ));
    }
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "status 1 from either compiler-produced entry guarantees an initialized result"
)]
// Scalar Exists calls should fold the two valid statuses at their ABI call
// site instead of paying a generic result-decoder call after the native entry.
#[inline(always)]
fn decode_search_result(
    output: AotOutput,
    status: u32,
    haystack_len: usize,
    start: usize,
    result: MaybeUninit<AbiResult>,
) -> Result<MatchResult, String> {
    match (output, status) {
        (AotOutput::Exists, 0) => Ok(MatchResult::Exists(false)),
        (AotOutput::Exists, 1) => Ok(MatchResult::Exists(true)),
        (AotOutput::Span, 0) => Ok(MatchResult::Span(None)),
        (AotOutput::Span, 1) => {
            // Compiler-produced Span entries initialize the result on status
            // 1. Other statuses never read it.
            let result = unsafe { result.assume_init() };
            if start <= result.start && result.start <= result.end && result.end <= haystack_len {
                Ok(MatchResult::Span(Some((result.start, result.end))))
            } else {
                Err(format!(
                    "native AOT entry returned an invalid result: status={status} start={} end={} window={start}..{}",
                    result.start, result.end, haystack_len
                ))
            }
        }
        _ => Err(format!("native AOT entry failed with status {status}")),
    }
}

#[cfg(test)]
#[allow(
    unsafe_code,
    reason = "tests provide small audited stand-ins for compiler-produced native entries"
)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    const fn assert_send<T: Send>() {}
    const fn assert_sync<T: Sync>() {}

    const _: () = assert_send::<AotMatcher>();
    const _: () = assert_send::<AotGrepCount>();
    const _: () = assert_send::<AotExact64SetFactory>();
    const _: () = assert_sync::<AotExact64SetFactory>();
    const _: () = assert_send::<AotExactSingletonFirstCandidateFactory>();
    const _: () = assert_sync::<AotExactSingletonFirstCandidateFactory>();
    const _: () = assert_send::<AotMatchingLfLineWitnessFactory>();
    const _: () = assert_sync::<AotMatchingLfLineWitnessFactory>();

    static SEARCH_CALLS: AtomicUsize = AtomicUsize::new(0);
    static FILL_CALLS: AtomicUsize = AtomicUsize::new(0);
    static DIRECT_SPAN_FILL_CALLS: AtomicUsize = AtomicUsize::new(0);
    static DIRECT_SPAN_FILL_COUNTER_TEST_LOCK: Mutex<()> = Mutex::new(());
    static PREPARED_SPAN_FILL_CALLS: AtomicUsize = AtomicUsize::new(0);
    static PREPARED_EXACT_CAPACITY_FILL_CALLS: AtomicUsize = AtomicUsize::new(0);
    static PREPARED_EXISTS_BATCH_CALLS: AtomicUsize = AtomicUsize::new(0);
    static DIRECT_EXISTS_BATCH_CALLS: AtomicUsize = AtomicUsize::new(0);
    static EXISTS_BATCH_COUNTER_TEST_LOCK: Mutex<()> = Mutex::new(());
    static PREPARE_V1_CALLS: AtomicUsize = AtomicUsize::new(0);
    static PREPARE_V3_CALLS: AtomicUsize = AtomicUsize::new(0);
    static PREPARE_SELECTION_TEST_LOCK: Mutex<()> = Mutex::new(());
    static SINGLETON_EXISTS_SCALAR_CALLS: AtomicUsize = AtomicUsize::new(0);
    static SINGLETON_EXISTS_BATCH_CALLS: AtomicUsize = AtomicUsize::new(0);
    static EXACT64_FIRST_ANY_CALLS: AtomicUsize = AtomicUsize::new(0);
    static EXACT64_SELECTION_ENTRY_CALLS: AtomicUsize = AtomicUsize::new(0);
    static FIRST_CANDIDATE_SELECTION_ENTRY_CALLS: AtomicUsize = AtomicUsize::new(0);
    static LF_LINE_WITNESS_SELECTION_ENTRY_CALLS: AtomicUsize = AtomicUsize::new(0);
    const EXACT64_PUBLIC_RAW_SENTINELS: [&str; 3] = [
        "fixture_raw_sentinel_one",
        "fixture_raw_sentinel_one_suffix",
        "fixture_raw_sentinel_two",
    ];

    unsafe extern "C" fn exact64_candidate_entry(
        _haystack: *const u8,
        haystack_len: usize,
        window_start: usize,
        window_end: usize,
        position: *mut u64,
    ) -> u32 {
        EXACT64_FIRST_ANY_CALLS.fetch_add(1, Ordering::Relaxed);
        if position.is_null() || window_start > window_end || window_end > haystack_len {
            return fre_aot_regex::REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_STATUS_INVALID_ARGUMENT;
        }
        let result = if haystack_len >= 3 {
            2
        } else {
            REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_NO_MATCH
        };
        unsafe { position.write(result) };
        REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_STATUS_SUCCESS
    }

    unsafe extern "C" fn exact64_selection_entry(
        _haystack: *const u8,
        _haystack_len: usize,
        _window_start: usize,
        _window_end: usize,
        _position: *mut u64,
    ) -> u32 {
        EXACT64_SELECTION_ENTRY_CALLS.fetch_add(1, Ordering::Relaxed);
        fre_aot_regex::REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_STATUS_INVALID_ARGUMENT
    }

    unsafe extern "C" fn exact64_miss_entry(
        _haystack: *const u8,
        _haystack_len: usize,
        _window_start: usize,
        _window_end: usize,
        position: *mut u64,
    ) -> u32 {
        unsafe { position.write(REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_NO_MATCH) };
        REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_STATUS_SUCCESS
    }

    unsafe extern "C" fn exact64_failure_after_write_entry(
        _haystack: *const u8,
        _haystack_len: usize,
        _window_start: usize,
        _window_end: usize,
        position: *mut u64,
    ) -> u32 {
        unsafe { position.write(0) };
        9
    }

    unsafe extern "C" fn exact64_invalid_position_entry(
        _haystack: *const u8,
        haystack_len: usize,
        _window_start: usize,
        _window_end: usize,
        position: *mut u64,
    ) -> u32 {
        unsafe { position.write(u64::try_from(haystack_len).unwrap_or(u64::MAX - 1)) };
        REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_STATUS_SUCCESS
    }

    unsafe extern "C" fn first_candidate_entry(
        _haystack: *const u8,
        haystack_len: usize,
        position: *mut u64,
    ) -> u32 {
        if position.is_null() {
            return 2;
        }
        let value = if haystack_len >= 5 {
            4
        } else {
            EXACT_SINGLETON_FIRST_CANDIDATE_MISS
        };
        unsafe { position.write(value) };
        0
    }

    unsafe extern "C" fn first_candidate_selection_entry(
        _haystack: *const u8,
        _haystack_len: usize,
        _position: *mut u64,
    ) -> u32 {
        FIRST_CANDIDATE_SELECTION_ENTRY_CALLS.fetch_add(1, Ordering::Relaxed);
        2
    }

    unsafe extern "C" fn first_candidate_failure_after_write_entry(
        _haystack: *const u8,
        _haystack_len: usize,
        position: *mut u64,
    ) -> u32 {
        unsafe { position.write(0) };
        9
    }

    unsafe extern "C" fn first_candidate_out_of_range_entry(
        _haystack: *const u8,
        haystack_len: usize,
        position: *mut u64,
    ) -> u32 {
        unsafe { position.write(u64::try_from(haystack_len).unwrap_or(u64::MAX - 1)) };
        0
    }

    unsafe extern "C" fn first_candidate_before_literal_width_entry(
        _haystack: *const u8,
        _haystack_len: usize,
        position: *mut u64,
    ) -> u32 {
        unsafe { position.write(1) };
        0
    }

    unsafe extern "C" fn lf_line_witness_entry(
        _haystack: *const u8,
        haystack_len: usize,
        position: *mut u64,
    ) -> u32 {
        if position.is_null() {
            return 2;
        }
        let value = if haystack_len >= 5 {
            2
        } else {
            MATCHING_LF_LINE_WITNESS_MISS
        };
        unsafe { position.write(value) };
        0
    }

    unsafe extern "C" fn lf_line_witness_selection_entry(
        _haystack: *const u8,
        _haystack_len: usize,
        _position: *mut u64,
    ) -> u32 {
        LF_LINE_WITNESS_SELECTION_ENTRY_CALLS.fetch_add(1, Ordering::Relaxed);
        2
    }

    unsafe extern "C" fn lf_line_witness_failure_after_write_entry(
        _haystack: *const u8,
        _haystack_len: usize,
        position: *mut u64,
    ) -> u32 {
        unsafe { position.write(0) };
        9
    }

    unsafe extern "C" fn lf_line_witness_out_of_range_entry(
        _haystack: *const u8,
        haystack_len: usize,
        position: *mut u64,
    ) -> u32 {
        unsafe { position.write(u64::try_from(haystack_len).unwrap_or(u64::MAX - 1)) };
        0
    }

    fn first_candidate_test_spec(
        pattern: &str,
        case_insensitive: bool,
        literal: &[u8],
        entry: NativeExactSingletonFirstCandidate,
    ) -> ExactSingletonFirstCandidateSpec {
        const ENTRY_SYMBOL: &str = "fre_aot_regex_exact_singleton_first_candidate_v1_public_test";
        let manifest_profile_key = manifest_profile_key(pattern, case_insensitive);
        let literal_sha256: [u8; 32] = Sha256::digest(literal).into();
        let endpoint_symbol_sha256: [u8; 32] = Sha256::digest(ENTRY_SYMBOL.as_bytes()).into();
        let (emitted_isa, cursor_register) = if cfg!(target_arch = "x86_64") {
            (
                FIRST_CANDIDATE_ISA_X86_SCALAR,
                FIRST_CANDIDATE_CURSOR_X86_RDX,
            )
        } else {
            (
                FIRST_CANDIDATE_ISA_AARCH64_SCALAR,
                FIRST_CANDIDATE_CURSOR_AARCH64_X2,
            )
        };
        let mut receipt = AotExactSingletonFirstCandidateReceiptV1 {
            manifest_profile_key,
            case_insensitive,
            schema_version: EXACT_SINGLETON_FIRST_CANDIDATE_AOT_SCHEMA_VERSION,
            strategy: FIRST_CANDIDATE_STRATEGY_NATIVE_TWO_WAY_TRUSTED_CORE_V1,
            semantics: FIRST_CANDIDATE_SEMANTICS_EARLIEST_INCLUSIVE_FINAL_BYTE_V1,
            abi: FIRST_CANDIDATE_ABI_HAYSTACK_LEN_U64_OUT_STATUS_V1,
            miss_sentinel: EXACT_SINGLETON_FIRST_CANDIDATE_MISS,
            literal_bytes: literal.len(),
            literal_sha256,
            target_architecture: first_candidate_runtime_target_architecture(),
            target_operating_system: first_candidate_runtime_target_os(),
            target_features: generated_first_candidates::BUILD_FIRST_CANDIDATE_TARGET_FEATURES,
            required_features: 0,
            emitted_isa,
            cursor_register,
            success_edge_count: 2,
            success_edges_sha256: [1; 32],
            trusted_core_offset: 17,
            trusted_core_sha256: [2; 32],
            ordinary_entry_symbol_sha256: [3; 32],
            ordinary_entry_code_sha256: [4; 32],
            wrapper_entry_offset: 31,
            wrapper_bytes: 48,
            wrapper_sha256: [5; 32],
            endpoint_symbol_sha256,
            native_code_sha256: [6; 32],
            relocations_sha256: [7; 32],
            object_sha256: [8; 32],
            runtime_call_count: 0,
            receipt_identity_sha256: [0; 32],
        };
        receipt.receipt_identity_sha256 = receipt
            .identity_input()
            .identity()
            .expect("test receipt identity");
        ExactSingletonFirstCandidateSpec {
            manifest_profile_key,
            description: "public-test-exact-singleton-first-candidate",
            entry_symbol: ENTRY_SYMBOL,
            entry,
            receipt,
        }
    }

    fn lf_line_witness_test_spec(
        pattern: &str,
        case_insensitive: bool,
        entry: NativeMatchingLfLineWitness,
    ) -> MatchingLfLineWitnessSpec {
        const ENTRY_SYMBOL: &str = "fre_aot_regex_matching_lf_line_witness_v1_public_test";
        let manifest_profile_key = manifest_profile_key(pattern, case_insensitive);
        let endpoint_symbol_sha256: [u8; 32] = Sha256::digest(ENTRY_SYMBOL.as_bytes()).into();
        let cursor_register = if cfg!(target_arch = "x86_64") {
            LF_LINE_WITNESS_CURSOR_X86_RDX
        } else {
            LF_LINE_WITNESS_CURSOR_AARCH64_X2
        };
        let mut receipt = AotMatchingLfLineWitnessReceiptV1 {
            manifest_profile_key,
            case_insensitive,
            source_count: 2,
            source_bytes: 9,
            minimum_width: 4,
            maximum_width: 5,
            source_language_sha256: [1; 32],
            compiler_literal_sha256: [0; 32],
            compiler_source_count: 0,
            compiler_source_bytes: 0,
            compiler_minimum_width: 0,
            compiler_maximum_width: 0,
            schema_version: MATCHING_LF_LINE_WITNESS_AOT_SCHEMA_VERSION,
            strategy: LF_LINE_WITNESS_STRATEGY_NATIVE_COMPLETE_DFA_TRUSTED_CORE_V1,
            semantics: LF_LINE_WITNESS_SEMANTICS_MATCHING_LF_LINE_BYTE_V1,
            abi: LF_LINE_WITNESS_ABI_HAYSTACK_LEN_U64_OUT_STATUS_V1,
            miss_sentinel: MATCHING_LF_LINE_WITNESS_MISS,
            target_architecture: lf_line_witness_runtime_target_architecture(),
            target_operating_system: lf_line_witness_runtime_target_os(),
            target_features: generated_lf_line_witnesses::BUILD_LF_LINE_WITNESS_TARGET_FEATURES,
            program_bytes: 101,
            program_sha256: [2; 32],
            cursor_register,
            success_edge_count: 4,
            inside_match_edge_count: 2,
            exclusive_end_edge_count: 2,
            success_edges_sha256: [3; 32],
            trusted_core_offset: 17,
            trusted_core_sha256: [4; 32],
            ordinary_entry_symbol_sha256: [5; 32],
            ordinary_entry_code_sha256: [6; 32],
            wrapper_entry_offset: 31,
            wrapper_bytes: 48,
            wrapper_sha256: [7; 32],
            endpoint_symbol_sha256,
            native_code_sha256: [8; 32],
            relocations_sha256: [9; 32],
            object_sha256: [10; 32],
            runtime_call_count: 0,
            receipt_identity_sha256: [0; 32],
        };
        receipt.receipt_identity_sha256 = receipt
            .identity_input()
            .identity()
            .expect("test receipt identity");
        MatchingLfLineWitnessSpec {
            manifest_profile_key,
            description: "public-test-matching-lf-line-witness",
            entry_symbol: ENTRY_SYMBOL,
            entry,
            receipt,
        }
    }

    fn exact64_test_spec(
        patterns: &[&str],
        profile: RipgrepAotExact64SetProfileV1,
        entry: NativeExact64FirstAny,
    ) -> Exact64SetSpec {
        let registry_key = exact64_set_registry_key(patterns, profile.case_insensitive);
        let pattern_count = patterns.len();
        Exact64SetSpec {
            registry_key,
            description: "public-test-exact64-first-any",
            entry_symbol: "fre_aot_regex_set_exact64_first_any_v1_public_test",
            entry,
            receipt: AotExact64SetReceiptV1 {
                registry_key,
                case_insensitive: profile.case_insensitive,
                pattern_count: u8::try_from(pattern_count).expect("test pattern count"),
                all_pattern_mask: if pattern_count == 64 {
                    u64::MAX
                } else {
                    (1_u64 << pattern_count) - 1
                },
                source_schema_version: REGEX_SET_EXACT64_SCHEMA_VERSION,
                abi_version: REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_ABI_VERSION,
                target_architecture: EXACT64_SET_TARGET_AARCH64,
                target_operating_system: exact64_set_runtime_target_os(),
                target_features: generated_exact64_sets::BUILD_EXACT64_SET_TARGET_FEATURES,
                line_terminator: REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_LINE_TERMINATOR,
                position_semantics: REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_POSITION_FINAL_BYTE,
                no_match: REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_NO_MATCH,
                source_artifact_sha256: [1; 32],
                exact64_artifact_sha256: [2; 32],
                source_mapping_sha256: [3; 32],
                operation_identity_sha256: [4; 32],
                artifact_identity_sha256: [5; 32],
                dense_data_sha256: [6; 32],
                code_sha256: [7; 32],
                object_sha256: [8; 32],
                state_count: 3,
                dense_transition_cells: 768,
                dense_data_bytes: 3_200,
                code_bytes: 128,
                object_bytes: 4_096,
                semantic_runtime_calls: 0,
            },
        }
    }

    unsafe extern "C" fn successful_grep_count(
        _handle: FreAotRegexExclusiveHandleV1,
        _haystack: *const u8,
        _haystack_len: usize,
        value: *mut u64,
    ) -> u32 {
        unsafe { value.write(17) };
        0
    }

    unsafe extern "C" fn failing_grep_count(
        _handle: FreAotRegexExclusiveHandleV1,
        _haystack: *const u8,
        _haystack_len: usize,
        value: *mut u64,
    ) -> u32 {
        // Deliberately violate the success-only publication rule. The safe
        // boundary must still treat the status as terminal and never read or
        // expose this value.
        unsafe { value.write(99) };
        7
    }

    unsafe extern "C" fn one_byte_search(
        _haystack: *const u8,
        haystack_len: usize,
        window_start: usize,
        window_end: usize,
        result: *mut AbiResult,
    ) -> u32 {
        if window_start >= window_end || window_start >= haystack_len {
            return 0;
        }
        unsafe {
            result.write(AbiResult {
                start: window_start,
                end: window_start + 1,
            });
        }
        1
    }

    unsafe extern "C" fn counted_one_byte_search(
        haystack: *const u8,
        haystack_len: usize,
        window_start: usize,
        window_end: usize,
        result: *mut AbiResult,
    ) -> u32 {
        SEARCH_CALLS.fetch_add(1, Ordering::Relaxed);
        unsafe { one_byte_search(haystack, haystack_len, window_start, window_end, result) }
    }

    unsafe extern "C" fn counted_one_byte_prepared_search(
        _handle: FreAotRegexExclusiveHandleV1,
        haystack: *const u8,
        haystack_len: usize,
        window_start: usize,
        window_end: usize,
        result: *mut AbiResult,
    ) -> u32 {
        unsafe { counted_one_byte_search(haystack, haystack_len, window_start, window_end, result) }
    }

    unsafe extern "C" fn singleton_one_byte_search(
        haystack: *const u8,
        haystack_len: usize,
        window_start: usize,
        window_end: usize,
        result: *mut AbiResult,
    ) -> u32 {
        SINGLETON_EXISTS_SCALAR_CALLS.fetch_add(1, Ordering::Relaxed);
        unsafe { one_byte_search(haystack, haystack_len, window_start, window_end, result) }
    }

    unsafe extern "C" fn singleton_one_byte_prepared_search(
        _handle: FreAotRegexExclusiveHandleV1,
        haystack: *const u8,
        haystack_len: usize,
        window_start: usize,
        window_end: usize,
        result: *mut AbiResult,
    ) -> u32 {
        unsafe { singleton_one_byte_search(haystack, haystack_len, window_start, window_end, result) }
    }

    fn dense_fill(
        haystack: &[u8],
        state: &mut NativeIterState,
        output: &mut [MaybeUninit<AbiResult>],
    ) -> NativeFillOutcome {
        FILL_CALLS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the test entry initializes `result` on every status-1 return
        // and retains none of the borrowed arguments.
        unsafe {
            fill_native_spans(haystack, state, output, |haystack, start, result| {
                counted_one_byte_search(
                    haystack.as_ptr(),
                    haystack.len(),
                    start,
                    haystack.len(),
                    result,
                )
            })
        }
    }

    fn one_byte_fill(
        haystack: &[u8],
        state: &mut NativeIterState,
        output: &mut [MaybeUninit<AbiResult>],
    ) -> NativeFillOutcome {
        // SAFETY: the test entry initializes `result` on every status-1 return
        // and retains none of the borrowed arguments.
        unsafe {
            fill_native_spans(haystack, state, output, |haystack, start, result| {
                one_byte_search(
                    haystack.as_ptr(),
                    haystack.len(),
                    start,
                    haystack.len(),
                    result,
                )
            })
        }
    }

    unsafe fn mock_prepared_span_fill(
        search: NativeSearch,
        haystack: *const u8,
        haystack_len: usize,
        state: *mut NativeIterState,
        results: *mut AbiResult,
        capacity: usize,
        written: *mut usize,
    ) -> u32 {
        let haystack = unsafe { std::slice::from_raw_parts(haystack, haystack_len) };
        let state = unsafe { &mut *state };
        let output = unsafe {
            std::slice::from_raw_parts_mut(results.cast::<MaybeUninit<AbiResult>>(), capacity)
        };
        let outcome = unsafe {
            fill_native_spans(haystack, state, output, |haystack, start, result| {
                search(
                    haystack.as_ptr(),
                    haystack.len(),
                    start,
                    haystack.len(),
                    result,
                )
            })
        };
        unsafe { written.write(outcome.written) };
        if outcome.error.is_some() {
            2
        } else {
            u32::from(!state.finished())
        }
    }

    unsafe extern "C" fn dense_prepared_span_fill(
        _handle: FreAotRegexExclusiveHandleV1,
        haystack: *const u8,
        haystack_len: usize,
        state: *mut NativeIterState,
        results: *mut AbiResult,
        capacity: usize,
        written: *mut usize,
    ) -> u32 {
        PREPARED_SPAN_FILL_CALLS.fetch_add(1, Ordering::Relaxed);
        unsafe {
            mock_prepared_span_fill(
                one_byte_search,
                haystack,
                haystack_len,
                state,
                results,
                capacity,
                written,
            )
        }
    }

    unsafe extern "C" fn dense_direct_span_fill(
        haystack: *const u8,
        haystack_len: usize,
        state: *mut NativeIterState,
        results: *mut AbiResult,
        capacity: usize,
        written: *mut usize,
    ) -> u32 {
        DIRECT_SPAN_FILL_CALLS.fetch_add(1, Ordering::Relaxed);
        unsafe {
            mock_prepared_span_fill(
                one_byte_search,
                haystack,
                haystack_len,
                state,
                results,
                capacity,
                written,
            )
        }
    }

    unsafe extern "C" fn nullable_direct_span_fill(
        haystack: *const u8,
        haystack_len: usize,
        state: *mut NativeIterState,
        results: *mut AbiResult,
        capacity: usize,
        written: *mut usize,
    ) -> u32 {
        unsafe {
            mock_prepared_span_fill(
                nullable_search,
                haystack,
                haystack_len,
                state,
                results,
                capacity,
                written,
            )
        }
    }

    unsafe extern "C" fn two_then_error_direct_span_fill(
        haystack: *const u8,
        haystack_len: usize,
        state: *mut NativeIterState,
        results: *mut AbiResult,
        capacity: usize,
        written: *mut usize,
    ) -> u32 {
        unsafe {
            mock_prepared_span_fill(
                two_then_error_search,
                haystack,
                haystack_len,
                state,
                results,
                capacity,
                written,
            )
        }
    }

    unsafe extern "C" fn two_then_status3_direct_span_fill(
        _haystack: *const u8,
        haystack_len: usize,
        state: *mut NativeIterState,
        results: *mut AbiResult,
        capacity: usize,
        written: *mut usize,
    ) -> u32 {
        assert!(haystack_len >= 2);
        assert!(capacity >= 2);
        unsafe {
            results.write(AbiResult { start: 0, end: 1 });
            results.add(1).write(AbiResult { start: 1, end: 2 });
            state.write(NativeIterState {
                next_start: 2,
                last_match_end: 2,
                flags: ITER_HAS_LAST | ITER_FINISHED,
                reserved: 0,
            });
            written.write(2);
        }
        3
    }

    unsafe extern "C" fn invalid_state_direct_span_fill(
        _haystack: *const u8,
        _haystack_len: usize,
        state: *mut NativeIterState,
        results: *mut AbiResult,
        _capacity: usize,
        written: *mut usize,
    ) -> u32 {
        unsafe {
            results.write(AbiResult { start: 0, end: 1 });
            state.write(NativeIterState {
                next_start: 1,
                last_match_end: 0,
                flags: ITER_HAS_LAST | ITER_PENDING_EMPTY | ITER_FINISHED,
                reserved: 0,
            });
            written.write(1);
        }
        0
    }

    unsafe extern "C" fn overreported_direct_span_fill(
        _haystack: *const u8,
        _haystack_len: usize,
        _state: *mut NativeIterState,
        _results: *mut AbiResult,
        capacity: usize,
        written: *mut usize,
    ) -> u32 {
        unsafe { written.write(capacity.saturating_add(1)) };
        1
    }

    fn dense_direct_fill(
        haystack: &[u8],
        state: &mut NativeIterState,
        output: &mut [MaybeUninit<AbiResult>],
    ) -> NativeFillOutcome {
        fill_direct_spans(dense_direct_span_fill, haystack, state, output)
    }

    fn nullable_direct_fill(
        haystack: &[u8],
        state: &mut NativeIterState,
        output: &mut [MaybeUninit<AbiResult>],
    ) -> NativeFillOutcome {
        fill_direct_spans(nullable_direct_span_fill, haystack, state, output)
    }

    fn two_then_error_direct_fill(
        haystack: &[u8],
        state: &mut NativeIterState,
        output: &mut [MaybeUninit<AbiResult>],
    ) -> NativeFillOutcome {
        fill_direct_spans(two_then_error_direct_span_fill, haystack, state, output)
    }

    fn two_then_status3_direct_fill(
        haystack: &[u8],
        state: &mut NativeIterState,
        output: &mut [MaybeUninit<AbiResult>],
    ) -> NativeFillOutcome {
        fill_direct_spans(two_then_status3_direct_span_fill, haystack, state, output)
    }

    fn invalid_state_direct_fill(
        haystack: &[u8],
        state: &mut NativeIterState,
        output: &mut [MaybeUninit<AbiResult>],
    ) -> NativeFillOutcome {
        fill_direct_spans(invalid_state_direct_span_fill, haystack, state, output)
    }

    unsafe extern "C" fn one_byte_prepared_span_fill(
        _handle: FreAotRegexExclusiveHandleV1,
        haystack: *const u8,
        haystack_len: usize,
        state: *mut NativeIterState,
        results: *mut AbiResult,
        capacity: usize,
        written: *mut usize,
    ) -> u32 {
        unsafe {
            mock_prepared_span_fill(
                one_byte_search,
                haystack,
                haystack_len,
                state,
                results,
                capacity,
                written,
            )
        }
    }

    unsafe extern "C" fn exact_capacity_prepared_span_fill(
        _handle: FreAotRegexExclusiveHandleV1,
        haystack: *const u8,
        haystack_len: usize,
        state: *mut NativeIterState,
        results: *mut AbiResult,
        capacity: usize,
        written: *mut usize,
    ) -> u32 {
        PREPARED_EXACT_CAPACITY_FILL_CALLS.fetch_add(1, Ordering::Relaxed);
        unsafe {
            mock_prepared_span_fill(
                one_byte_search,
                haystack,
                haystack_len,
                state,
                results,
                capacity,
                written,
            )
        }
    }

    unsafe extern "C" fn nullable_prepared_span_fill(
        _handle: FreAotRegexExclusiveHandleV1,
        haystack: *const u8,
        haystack_len: usize,
        state: *mut NativeIterState,
        results: *mut AbiResult,
        capacity: usize,
        written: *mut usize,
    ) -> u32 {
        unsafe {
            mock_prepared_span_fill(
                nullable_search,
                haystack,
                haystack_len,
                state,
                results,
                capacity,
                written,
            )
        }
    }

    unsafe extern "C" fn two_then_error_prepared_span_fill(
        _handle: FreAotRegexExclusiveHandleV1,
        haystack: *const u8,
        haystack_len: usize,
        state: *mut NativeIterState,
        results: *mut AbiResult,
        capacity: usize,
        written: *mut usize,
    ) -> u32 {
        unsafe {
            mock_prepared_span_fill(
                two_then_error_search,
                haystack,
                haystack_len,
                state,
                results,
                capacity,
                written,
            )
        }
    }

    unsafe extern "C" fn invalid_state_prepared_span_fill(
        _handle: FreAotRegexExclusiveHandleV1,
        _haystack: *const u8,
        _haystack_len: usize,
        state: *mut NativeIterState,
        results: *mut AbiResult,
        _capacity: usize,
        written: *mut usize,
    ) -> u32 {
        unsafe {
            results.write(AbiResult { start: 0, end: 1 });
            state.write(NativeIterState {
                next_start: 1,
                last_match_end: 0,
                flags: ITER_HAS_LAST | ITER_PENDING_EMPTY | ITER_FINISHED,
                reserved: 0,
            });
            written.write(1);
        }
        0
    }

    unsafe extern "C" fn mismatched_last_span_prepared_fill(
        _handle: FreAotRegexExclusiveHandleV1,
        _haystack: *const u8,
        _haystack_len: usize,
        state: *mut NativeIterState,
        results: *mut AbiResult,
        _capacity: usize,
        written: *mut usize,
    ) -> u32 {
        unsafe {
            results.write(AbiResult { start: 0, end: 1 });
            state.write(NativeIterState {
                next_start: 2,
                last_match_end: 2,
                flags: ITER_HAS_LAST | ITER_FINISHED,
                reserved: 0,
            });
            written.write(1);
        }
        0
    }

    unsafe extern "C" fn contains_x_prepared_exists_batch(
        _handle: FreAotRegexExclusiveHandleV1,
        haystacks: *const AbiHaystack,
        count: usize,
        matched: *mut u8,
        processed: *mut usize,
    ) -> u32 {
        PREPARED_EXISTS_BATCH_CALLS.fetch_add(1, Ordering::Relaxed);
        let haystacks = unsafe { std::slice::from_raw_parts(haystacks, count) };
        let matched = unsafe { std::slice::from_raw_parts_mut(matched, count) };
        for (index, haystack) in haystacks.iter().enumerate() {
            let bytes = unsafe { std::slice::from_raw_parts(haystack.ptr, haystack.len) };
            matched[index] = u8::from(bytes.contains(&b'x'));
        }
        unsafe { processed.write(count) };
        0
    }

    unsafe extern "C" fn contains_x_direct_exists_batch(
        haystacks: *const AbiHaystack,
        count: usize,
        matched: *mut u8,
        processed: *mut usize,
    ) -> u32 {
        DIRECT_EXISTS_BATCH_CALLS.fetch_add(1, Ordering::Relaxed);
        let haystacks = unsafe { std::slice::from_raw_parts(haystacks, count) };
        let matched = unsafe { std::slice::from_raw_parts_mut(matched, count) };
        for (index, haystack) in haystacks.iter().enumerate() {
            let bytes = unsafe { std::slice::from_raw_parts(haystack.ptr, haystack.len) };
            matched[index] = u8::from(bytes.contains(&b'x'));
        }
        unsafe { processed.write(count) };
        0
    }

    unsafe extern "C" fn one_then_error_direct_exists_batch(
        _haystacks: *const AbiHaystack,
        count: usize,
        matched: *mut u8,
        processed: *mut usize,
    ) -> u32 {
        if count == 0 {
            unsafe { processed.write(0) };
        } else {
            unsafe {
                matched.write(1);
                processed.write(1);
            }
        }
        7
    }

    unsafe extern "C" fn singleton_prepared_exists_batch(
        _handle: FreAotRegexExclusiveHandleV1,
        _haystacks: *const AbiHaystack,
        count: usize,
        matched: *mut u8,
        processed: *mut usize,
    ) -> u32 {
        SINGLETON_EXISTS_BATCH_CALLS.fetch_add(1, Ordering::Relaxed);
        unsafe {
            std::ptr::write_bytes(matched, 0, count);
            processed.write(count);
        }
        0
    }

    unsafe extern "C" fn singleton_direct_exists_batch(
        _haystacks: *const AbiHaystack,
        count: usize,
        matched: *mut u8,
        processed: *mut usize,
    ) -> u32 {
        SINGLETON_EXISTS_BATCH_CALLS.fetch_add(1, Ordering::Relaxed);
        unsafe {
            std::ptr::write_bytes(matched, 0, count);
            processed.write(count);
        }
        0
    }

    unsafe extern "C" fn nullable_search(
        _haystack: *const u8,
        haystack_len: usize,
        window_start: usize,
        _window_end: usize,
        result: *mut AbiResult,
    ) -> u32 {
        let span = if haystack_len == 1 && window_start == 0 {
            AbiResult { start: 0, end: 1 }
        } else if window_start <= haystack_len {
            AbiResult {
                start: window_start,
                end: window_start,
            }
        } else {
            return 0;
        };
        unsafe { result.write(span) };
        1
    }

    fn nullable_fill(
        haystack: &[u8],
        state: &mut NativeIterState,
        output: &mut [MaybeUninit<AbiResult>],
    ) -> NativeFillOutcome {
        // SAFETY: the test entry initializes `result` on every status-1 return
        // and retains none of the borrowed arguments.
        unsafe {
            fill_native_spans(haystack, state, output, |haystack, start, result| {
                nullable_search(
                    haystack.as_ptr(),
                    haystack.len(),
                    start,
                    haystack.len(),
                    result,
                )
            })
        }
    }

    unsafe extern "C" fn dense_then_empty_search(
        haystack: *const u8,
        haystack_len: usize,
        window_start: usize,
        window_end: usize,
        result: *mut AbiResult,
    ) -> u32 {
        if window_start < haystack_len {
            return unsafe {
                one_byte_search(haystack, haystack_len, window_start, window_end, result)
            };
        }
        if window_start == haystack_len {
            unsafe {
                result.write(AbiResult {
                    start: window_start,
                    end: window_start,
                });
            }
            return 1;
        }
        0
    }

    fn dense_then_empty_fill(
        haystack: &[u8],
        state: &mut NativeIterState,
        output: &mut [MaybeUninit<AbiResult>],
    ) -> NativeFillOutcome {
        // SAFETY: the test entry initializes `result` on every status-1 return
        // and retains none of the borrowed arguments.
        unsafe {
            fill_native_spans(haystack, state, output, |haystack, start, result| {
                dense_then_empty_search(
                    haystack.as_ptr(),
                    haystack.len(),
                    start,
                    haystack.len(),
                    result,
                )
            })
        }
    }

    unsafe extern "C" fn two_then_error_search(
        _haystack: *const u8,
        _haystack_len: usize,
        window_start: usize,
        _window_end: usize,
        result: *mut AbiResult,
    ) -> u32 {
        if window_start < 2 {
            unsafe {
                result.write(AbiResult {
                    start: window_start,
                    end: window_start + 1,
                });
            }
            1
        } else {
            2
        }
    }

    fn two_then_error_fill(
        haystack: &[u8],
        state: &mut NativeIterState,
        output: &mut [MaybeUninit<AbiResult>],
    ) -> NativeFillOutcome {
        // SAFETY: the test entry initializes `result` on every status-1 return
        // and retains none of the borrowed arguments.
        unsafe {
            fill_native_spans(haystack, state, output, |haystack, start, result| {
                two_then_error_search(
                    haystack.as_ptr(),
                    haystack.len(),
                    start,
                    haystack.len(),
                    result,
                )
            })
        }
    }

    unsafe extern "C" fn invalid_search(
        _haystack: *const u8,
        _haystack_len: usize,
        window_start: usize,
        _window_end: usize,
        result: *mut AbiResult,
    ) -> u32 {
        unsafe {
            result.write(AbiResult {
                start: window_start.saturating_add(1),
                end: window_start,
            });
        }
        1
    }

    fn invalid_fill(
        haystack: &[u8],
        state: &mut NativeIterState,
        output: &mut [MaybeUninit<AbiResult>],
    ) -> NativeFillOutcome {
        // SAFETY: the deliberately invalid semantic span is still fully
        // initialized on status 1 and no borrowed argument is retained.
        unsafe {
            fill_native_spans(haystack, state, output, |haystack, start, result| {
                invalid_search(
                    haystack.as_ptr(),
                    haystack.len(),
                    start,
                    haystack.len(),
                    result,
                )
            })
        }
    }

    unsafe extern "C" fn rejecting_prepare_v1(
        _program: *const u8,
        _program_len: usize,
        _handle: *mut FreAotRegexExclusiveHandleV1,
    ) -> u32 {
        PREPARE_V1_CALLS.fetch_add(1, Ordering::Relaxed);
        41
    }

    unsafe extern "C" fn rejecting_expected_v15_prepare_v3(
        _program: *const u8,
        _program_len: usize,
        config: *const FreAotRegexPrepareConfigV3,
        _handle: *mut FreAotRegexExclusiveHandleV1,
    ) -> u32 {
        PREPARE_V3_CALLS.fetch_add(1, Ordering::Relaxed);
        if config.is_null() {
            return 43;
        }
        // SAFETY: the preparation seam supplies one aligned readable config
        // for the duration of this stand-in call.
        let config = unsafe { config.read() };
        if config.operation_flags == PREPARE_OPERATION_COUNT | PREPARE_OPERATION_SPAN_SUM
            && config.required_capabilities == PREPARE_CAPABILITY_ORDERED_NFA_V15
        {
            42
        } else {
            43
        }
    }

    unsafe extern "C" fn unavailable_prepare_v3(
        _program: *const u8,
        _program_len: usize,
        _config: *const FreAotRegexPrepareConfigV3,
        _handle: *mut FreAotRegexExclusiveHandleV1,
    ) -> u32 {
        PREPARE_V3_CALLS.fetch_add(1, Ordering::Relaxed);
        77
    }

    fn native_matcher(search: NativeSearch, fill: NativeFill) -> AotMatcher {
        AotMatcher {
            output: AotOutput::Span,
            description: "test-native",
            backend: Backend::Native {
                search,
                fill: Some(fill),
                exists_batch: None,
            },
        }
    }

    fn prepared_test_matcher(
        output: AotOutput,
        span_fill: Option<PreparedSpanFill>,
        exists_batch: Option<PreparedExistsBatch>,
    ) -> AotMatcher {
        AotMatcher {
            output,
            description: "test-compiled-prepared",
            backend: Backend::Prepared(PreparedNative {
                search: counted_one_byte_prepared_search,
                span_fill: span_fill.map(PreparedSpanFillFactory::Compiled),
                exists_batch,
                handle: FreAotRegexExclusiveHandleV1::INVALID,
            }),
        }
    }

    fn runtime_test_matcher(pattern: &str) -> AotMatcher {
        let compiled = fre_aot_regex::compile(
            fre_aot_regex::CompileRequest::new(pattern, fre_aot_regex::Target::x86_64_linux())
                .mode(fre_aot_regex::CompileMode::Fast)
                .output(fre_aot_regex::OutputContract::Span),
        )
        .expect("compile test runtime program");
        let serialized = compiled
            .program()
            .serialize()
            .expect("serialize test program");
        AotMatcher {
            output: AotOutput::Span,
            description: "test-runtime",
            backend: Backend::Runtime(Box::new(
                PreparedAotRegex::deserialize(&serialized).expect("prepare test runtime program"),
            )),
        }
    }

    #[test]
    fn zero_prepare_capabilities_keep_the_exact_v1_prepare_path() {
        let _guard = PREPARE_SELECTION_TEST_LOCK
            .lock()
            .expect("prepare test lock");
        PREPARE_V1_CALLS.store(0, Ordering::Relaxed);
        PREPARE_V3_CALLS.store(0, Ordering::Relaxed);
        let preparation = prepared_handle_preparation(AotOutput::Exists, None, None, 0)
            .expect("legacy preparation selection");
        assert_eq!(preparation, PreparedHandlePreparation::V1);

        let error = prepare_exclusive_handle_with(
            b"public synthetic program",
            preparation,
            rejecting_prepare_v1,
            rejecting_expected_v15_prepare_v3,
        )
        .expect_err("stand-in V1 prepare rejects");
        assert_eq!(
            error,
            "prepare compiled AOT exclusive handle failed with status 41"
        );
        assert_eq!(PREPARE_V1_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(PREPARE_V3_CALLS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn ordered_nfa_v15_selects_v3_with_exact_count_span_sum_declaration() {
        let _guard = PREPARE_SELECTION_TEST_LOCK
            .lock()
            .expect("prepare test lock");
        PREPARE_V1_CALLS.store(0, Ordering::Relaxed);
        PREPARE_V3_CALLS.store(0, Ordering::Relaxed);
        let preparation = prepared_handle_preparation(
            AotOutput::Span,
            Some(PreparedSpanFillFactory::Compiled(dense_prepared_span_fill)),
            None,
            PREPARE_CAPABILITY_ORDERED_NFA_V15,
        )
        .expect("Ordered-NFA V15 preparation selection");
        let PreparedHandlePreparation::V3(config) = preparation else {
            panic!("V15 capability selected legacy V1 preparation");
        };
        assert_eq!(
            config.operation_flags,
            PREPARE_OPERATION_COUNT | PREPARE_OPERATION_SPAN_SUM
        );
        assert_eq!(
            config.required_capabilities,
            PREPARE_CAPABILITY_ORDERED_NFA_V15
        );

        let error = prepare_exclusive_handle_with(
            b"public synthetic program",
            preparation,
            rejecting_prepare_v1,
            rejecting_expected_v15_prepare_v3,
        )
        .expect_err("stand-in V3 prepare rejects after checking config");
        assert_eq!(
            error,
            "prepare compiled AOT exclusive V3 handle failed with status 42"
        );
        assert_eq!(PREPARE_V1_CALLS.load(Ordering::Relaxed), 0);
        assert_eq!(PREPARE_V3_CALLS.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn ordered_nfa_v15_prepare_failure_is_terminal_without_v1_fallback() {
        let _guard = PREPARE_SELECTION_TEST_LOCK
            .lock()
            .expect("prepare test lock");
        PREPARE_V1_CALLS.store(0, Ordering::Relaxed);
        PREPARE_V3_CALLS.store(0, Ordering::Relaxed);
        let preparation = prepared_handle_preparation(
            AotOutput::Span,
            Some(PreparedSpanFillFactory::Compiled(dense_prepared_span_fill)),
            None,
            PREPARE_CAPABILITY_ORDERED_NFA_V15,
        )
        .expect("Ordered-NFA V15 preparation selection");

        let error = prepare_exclusive_handle_with(
            b"public synthetic program",
            preparation,
            rejecting_prepare_v1,
            unavailable_prepare_v3,
        )
        .expect_err("unavailable V15 capability must fail closed");
        assert_eq!(
            error,
            "prepare compiled AOT exclusive V3 handle failed with status 77"
        );
        assert_eq!(PREPARE_V1_CALLS.load(Ordering::Relaxed), 0);
        assert_eq!(PREPARE_V3_CALLS.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn nonzero_prepare_capabilities_reject_unknown_bits_and_wrong_factory_shape() {
        let unknown = prepared_handle_preparation(
            AotOutput::Span,
            Some(PreparedSpanFillFactory::Compiled(dense_prepared_span_fill)),
            None,
            PREPARE_CAPABILITY_ORDERED_NFA_V15 | (1 << 9),
        )
        .expect_err("unknown prepare capability must fail closed");
        assert!(
            unknown.contains("unknown runtime capabilities"),
            "{unknown:?}"
        );

        let wrong_shape = prepared_handle_preparation(
            AotOutput::Exists,
            None,
            Some(contains_x_prepared_exists_batch),
            PREPARE_CAPABILITY_ORDERED_NFA_V15,
        )
        .expect_err("V15 Exists factory must fail closed");
        assert!(
            wrong_shape.contains("incompatible with its required Span/SpanFill shape"),
            "{wrong_shape:?}"
        );
    }

    fn direct_exists_test_matcher(batch: NativeExistsBatch) -> AotMatcher {
        AotMatcher {
            output: AotOutput::Exists,
            description: "test-direct-native",
            backend: Backend::Native {
                search: counted_one_byte_search,
                fill: None,
                exists_batch: Some(batch),
            },
        }
    }

    #[test]
    fn exact64_profile_rejects_every_unsupported_ripgrep_semantic() {
        let patterns = ["alpha", "beta"];
        let supported = RipgrepAotExact64SetProfileV1::supported_rust_regex(false);
        let spec = exact64_test_spec(&patterns, supported, exact64_candidate_entry);
        assert!(
            select_exact64_set_spec(
                std::slice::from_ref(&spec),
                AotMode::Optimizing,
                AotOutput::Exists,
                &patterns,
                supported,
            )
            .expect("supported selection")
            .is_some()
        );

        let mut unsupported = Vec::new();
        let mut profile = supported;
        profile.matcher_mode = RipgrepAotMatcherModeV1::FixedStrings;
        unsupported.push(profile);
        let mut profile = supported;
        profile.invert_match = true;
        unsupported.push(profile);
        let mut profile = supported;
        profile.multiline = true;
        unsupported.push(profile);
        let mut profile = supported;
        profile.dot_matches_new_line = true;
        unsupported.push(profile);
        let mut profile = supported;
        profile.unicode = false;
        unsupported.push(profile);
        let mut profile = supported;
        profile.crlf = true;
        unsupported.push(profile);
        let mut profile = supported;
        profile.null_data = true;
        unsupported.push(profile);
        let mut profile = supported;
        profile.encoding = RipgrepAotEncodingV1::AmbiguousOrTranscoded;
        unsupported.push(profile);
        let mut profile = supported;
        profile.word_regexp = true;
        unsupported.push(profile);
        let mut profile = supported;
        profile.line_regexp = true;
        unsupported.push(profile);
        let mut profile = supported;
        profile.pcre2 = true;
        unsupported.push(profile);

        for profile in unsupported {
            assert!(
                select_exact64_set_spec(
                    std::slice::from_ref(&spec),
                    AotMode::Optimizing,
                    AotOutput::Exists,
                    &patterns,
                    profile,
                )
                .expect("unsupported profile is a structural decline")
                .is_none()
            );
        }
        assert!(
            select_exact64_set_spec(
                std::slice::from_ref(&spec),
                AotMode::Fast,
                AotOutput::Exists,
                &patterns,
                supported,
            )
            .expect("Fast decline")
            .is_none()
        );
        assert!(
            select_exact64_set_spec(
                std::slice::from_ref(&spec),
                AotMode::Optimizing,
                AotOutput::Span,
                &patterns,
                supported,
            )
            .expect("Span decline")
            .is_none()
        );
        assert!(
            select_exact64_set_spec(
                std::slice::from_ref(&spec),
                AotMode::Optimizing,
                AotOutput::Exists,
                &["alpha"],
                supported,
            )
            .expect("singleton decline")
            .is_none()
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one mutation table covers every field in the raw-free receipt identity"
    )]
    fn first_candidate_selection_is_structural_and_every_receipt_field_is_bound() {
        const RAW_SENTINEL: &str = "fixture_raw_first_candidate_sentinel";
        const LITERAL: &[u8] = b"public-literal";
        FIRST_CANDIDATE_SELECTION_ENTRY_CALLS.store(0, Ordering::Relaxed);
        let spec = first_candidate_test_spec(
            RAW_SENTINEL,
            false,
            LITERAL,
            first_candidate_selection_entry,
        );
        let selected = select_exact_singleton_first_candidate_spec(
            std::slice::from_ref(&spec),
            AotMode::Optimizing,
            AotOutput::Exists,
            RAW_SENTINEL,
            false,
            LITERAL,
        )
        .expect("authenticated selection")
        .expect("known tuple");
        assert_eq!(selected.manifest_profile_key, spec.manifest_profile_key);

        for (mode, output) in [
            (AotMode::Fast, AotOutput::Exists),
            (AotMode::Optimizing, AotOutput::Span),
        ] {
            assert!(
                select_exact_singleton_first_candidate_spec(
                    std::slice::from_ref(&spec),
                    mode,
                    output,
                    RAW_SENTINEL,
                    false,
                    LITERAL,
                )
                .expect("unsupported route is a structural decline")
                .is_none()
            );
        }
        assert!(
            select_exact_singleton_first_candidate_spec(
                std::slice::from_ref(&spec),
                AotMode::Optimizing,
                AotOutput::Exists,
                "absent-public-pattern",
                false,
                LITERAL,
            )
            .expect("absent row")
            .is_none()
        );
        for configured_literal in [b"wrong".as_slice(), b"", b"line\nbreak"] {
            let error = select_exact_singleton_first_candidate_spec(
                std::slice::from_ref(&spec),
                AotMode::Optimizing,
                AotOutput::Exists,
                RAW_SENTINEL,
                false,
                configured_literal,
            )
            .expect_err("a present literal mismatch is terminal");
            assert!(error.contains("receipt authentication failed"));
            assert!(!error.contains(RAW_SENTINEL));
        }

        type MutateReceipt = fn(&mut AotExactSingletonFirstCandidateReceiptV1);
        let mutations: &[MutateReceipt] = &[
            |value| value.manifest_profile_key[0] ^= 1,
            |value| value.case_insensitive = !value.case_insensitive,
            |value| value.schema_version ^= 1,
            |value| value.strategy ^= 1,
            |value| value.semantics ^= 1,
            |value| value.abi ^= 1,
            |value| value.miss_sentinel ^= 1,
            |value| value.literal_bytes += 1,
            |value| value.literal_sha256[0] ^= 1,
            |value| value.target_architecture ^= 1,
            |value| value.target_operating_system ^= 1,
            |value| value.target_features ^= 1,
            |value| value.required_features ^= 1,
            |value| value.emitted_isa ^= 1,
            |value| value.cursor_register ^= 1,
            |value| value.success_edge_count += 1,
            |value| value.success_edges_sha256[0] ^= 1,
            |value| value.trusted_core_offset += 1,
            |value| value.trusted_core_sha256[0] ^= 1,
            |value| value.ordinary_entry_symbol_sha256[0] ^= 1,
            |value| value.ordinary_entry_code_sha256[0] ^= 1,
            |value| value.wrapper_entry_offset += 1,
            |value| value.wrapper_bytes += 1,
            |value| value.wrapper_sha256[0] ^= 1,
            |value| value.endpoint_symbol_sha256[0] ^= 1,
            |value| value.native_code_sha256[0] ^= 1,
            |value| value.relocations_sha256[0] ^= 1,
            |value| value.object_sha256[0] ^= 1,
            |value| value.runtime_call_count += 1,
            |value| value.receipt_identity_sha256[0] ^= 1,
        ];
        for mutate in mutations {
            let mut corrupted = spec;
            mutate(&mut corrupted.receipt);
            let error = select_exact_singleton_first_candidate_spec(
                std::slice::from_ref(&corrupted),
                AotMode::Optimizing,
                AotOutput::Exists,
                RAW_SENTINEL,
                false,
                LITERAL,
            )
            .expect_err("every receipt mutation is terminal");
            assert!(error.contains("receipt authentication failed"), "{error}");
            assert!(!error.contains(RAW_SENTINEL));
        }

        let mut wrong_symbol = spec;
        wrong_symbol.entry_symbol = "public_wrong_first_candidate_symbol";
        assert!(
            select_exact_singleton_first_candidate_spec(
                std::slice::from_ref(&wrong_symbol),
                AotMode::Optimizing,
                AotOutput::Exists,
                RAW_SENTINEL,
                false,
                LITERAL,
            )
            .expect_err("entry-symbol substitution is terminal")
            .contains("receipt authentication failed")
        );
        let duplicate_specs = [spec, spec];
        assert!(
            select_exact_singleton_first_candidate_spec(
                &duplicate_specs,
                AotMode::Optimizing,
                AotOutput::Exists,
                RAW_SENTINEL,
                false,
                LITERAL,
            )
            .expect_err("duplicate profile key is terminal")
            .contains("ambiguous profile key")
        );
        assert_eq!(
            FIRST_CANDIDATE_SELECTION_ENTRY_CALLS.load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn first_candidate_native_boundary_returns_only_miss_or_unconfirmed_valid_position() {
        assert_eq!(
            native_exact_singleton_first_candidate(first_candidate_entry, 3, b"abcde")
                .expect("candidate success"),
            AotExactSingletonFirstCandidateOutcome::Candidate { position: 4 }
        );
        assert_eq!(
            native_exact_singleton_first_candidate(first_candidate_entry, 3, b"abcd")
                .expect("short miss"),
            AotExactSingletonFirstCandidateOutcome::ConfirmedMiss
        );
        let failure = native_exact_singleton_first_candidate(
            first_candidate_failure_after_write_entry,
            1,
            b"haystack",
        )
        .expect_err("nonzero status is terminal despite an output write");
        assert!(failure.contains("status 9"));
        assert!(
            native_exact_singleton_first_candidate(
                first_candidate_out_of_range_entry,
                1,
                b"haystack",
            )
            .expect_err("out-of-range position")
            .contains("invalid position")
        );
        assert!(
            native_exact_singleton_first_candidate(
                first_candidate_before_literal_width_entry,
                3,
                b"haystack",
            )
            .expect_err("candidate cannot end before one literal width")
            .contains("invalid position")
        );
    }

    #[test]
    fn generated_first_candidate_registry_is_raw_free_and_receipt_closed() {
        let generated_source =
            include_str!(concat!(env!("OUT_DIR"), "/first_candidate_registry.rs"));
        for raw_source in [
            "PM_RESUME",
            "Sherlock Holmes",
            "Шерлок Холмс",
            "alpha",
            "bravo",
            "FirstCandidatePublicShape",
            "PublicSingletonNeedle",
            "wide_alpha",
            "escaped_wide",
        ] {
            assert!(
                !generated_source.contains(raw_source),
                "first-candidate registry leaked a raw source"
            );
        }
        assert_eq!(
            generated_first_candidates::BUILD_FIRST_CANDIDATE_ADMITTED_COUNT,
            generated_first_candidates::FIRST_CANDIDATE_SPECS.len()
        );
        assert!(
            generated_first_candidates::BUILD_FIRST_CANDIDATE_ADMITTED_COUNT
                <= generated_first_candidates::BUILD_FIRST_CANDIDATE_INDEPENDENTLY_ELIGIBLE_COUNT
        );
        if generated_first_candidates::BUILD_FIRST_CANDIDATE_PUBLIC_FIXTURE_SELECTED
            && generated::BUILD_VARIANT_POLICY != "optimizing-grep-count"
            && generated::BUILD_PATTERN_COUNT == 4
        {
            assert_eq!(
                generated_first_candidates::BUILD_FIRST_CANDIDATE_INDEPENDENTLY_ELIGIBLE_COUNT,
                3
            );
            assert!(
                !generated_first_candidates::FIRST_CANDIDATE_SPECS.is_empty(),
                "wide public fixture must exercise at least one linked endpoint"
            );
        }
        for spec in generated_first_candidates::FIRST_CANDIDATE_SPECS {
            let receipt = spec.receipt;
            assert_eq!(spec.manifest_profile_key, receipt.manifest_profile_key());
            assert!(
                generated::ALL_MANIFEST_PROFILE_KEYS.contains(&spec.manifest_profile_key),
                "candidate row has no selected manifest profile"
            );
            assert_eq!(
                receipt.target_features(),
                generated_first_candidates::BUILD_FIRST_CANDIDATE_TARGET_FEATURES
            );
            assert_ne!(receipt.literal_bytes(), 0);
            assert_ne!(receipt.literal_sha256(), [0; 32]);
            assert_ne!(receipt.object_sha256(), [0; 32]);
            assert_eq!(
                receipt.identity_input().identity(),
                Some(receipt.receipt_identity_sha256)
            );
            let endpoint_symbol_sha256: [u8; 32] =
                Sha256::digest(spec.entry_symbol.as_bytes()).into();
            assert_eq!(endpoint_symbol_sha256, receipt.endpoint_symbol_sha256);
            assert!(!spec.description.contains("pattern="));
            // SAFETY: null output is invalid independently of the deliberately
            // null zero-length haystack and must be rejected before scanning.
            let status = unsafe { (spec.entry)(std::ptr::null(), 0, std::ptr::null_mut()) };
            assert_eq!(status, 2);
        }

        for (pattern, literal) in [
            ("PM_RESUME", b"PM_RESUME".as_slice()),
            ("Sherlock Holmes", b"Sherlock Holmes".as_slice()),
            ("Шерлок Холмс", "Шерлок Холмс".as_bytes()),
        ] {
            let Some(factory) = AotExactSingletonFirstCandidateFactory::select(
                AotMode::Optimizing,
                AotOutput::Exists,
                pattern,
                false,
                literal,
            )
            .expect("known public tuple receipt") else {
                continue;
            };
            assert!(
                factory
                    .description()
                    .contains("api=exact-singleton-first-candidate-v1")
            );
            assert_eq!(factory.receipt().literal_bytes(), literal.len());
            let mut hit = b"--".to_vec();
            hit.extend_from_slice(literal);
            hit.extend_from_slice(b"--");
            assert_eq!(
                factory.find(&hit).expect("linked candidate hit"),
                AotExactSingletonFirstCandidateOutcome::Candidate {
                    position: 2 + literal.len() - 1,
                }
            );
            assert_eq!(
                factory.find(b"unrelated").expect("linked candidate miss"),
                AotExactSingletonFirstCandidateOutcome::ConfirmedMiss
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one mutation table covers every field in the raw-free witness receipt identity"
    )]
    fn lf_line_witness_selection_is_structural_and_every_receipt_field_is_bound() {
        const RAW_SENTINEL: &str = "fixture_raw_lf_line_witness_sentinel";
        LF_LINE_WITNESS_SELECTION_ENTRY_CALLS.store(0, Ordering::Relaxed);
        let spec = lf_line_witness_test_spec(RAW_SENTINEL, false, lf_line_witness_selection_entry);
        let selected = select_matching_lf_line_witness_spec(
            std::slice::from_ref(&spec),
            AotMode::Optimizing,
            AotOutput::Exists,
            RAW_SENTINEL,
            false,
        )
        .expect("authenticated selection")
        .expect("known tuple");
        assert_eq!(selected.manifest_profile_key, spec.manifest_profile_key);

        let mut teddy_spec = spec;
        teddy_spec.receipt.strategy = LF_LINE_WITNESS_STRATEGY_NATIVE_TEDDY_TRUSTED_CORE_V1;
        teddy_spec.receipt.compiler_literal_sha256 = [11; 32];
        teddy_spec.receipt.compiler_source_count = teddy_spec.receipt.source_count;
        teddy_spec.receipt.compiler_source_bytes = teddy_spec.receipt.source_bytes;
        teddy_spec.receipt.compiler_minimum_width = teddy_spec.receipt.minimum_width;
        teddy_spec.receipt.compiler_maximum_width = teddy_spec.receipt.maximum_width;
        teddy_spec.receipt.receipt_identity_sha256 = teddy_spec
            .receipt
            .identity_input()
            .identity()
            .expect("Teddy test receipt identity");
        assert!(
            select_matching_lf_line_witness_spec(
                std::slice::from_ref(&teddy_spec),
                AotMode::Optimizing,
                AotOutput::Exists,
                RAW_SENTINEL,
                false,
            )
            .expect("authenticated Teddy selection")
            .is_some()
        );

        let mut forged_teddy_binding = teddy_spec;
        forged_teddy_binding.receipt.compiler_source_bytes += 1;
        forged_teddy_binding.receipt.receipt_identity_sha256 = forged_teddy_binding
            .receipt
            .identity_input()
            .identity()
            .expect("self-consistent forged Teddy receipt identity");
        assert!(
            select_matching_lf_line_witness_spec(
                std::slice::from_ref(&forged_teddy_binding),
                AotMode::Optimizing,
                AotOutput::Exists,
                RAW_SENTINEL,
                false,
            )
            .expect_err("Teddy compiler/source geometry mismatch is terminal")
            .contains("receipt authentication failed")
        );

        for (mode, output) in [
            (AotMode::Fast, AotOutput::Exists),
            (AotMode::Optimizing, AotOutput::Span),
        ] {
            assert!(
                select_matching_lf_line_witness_spec(
                    std::slice::from_ref(&spec),
                    mode,
                    output,
                    RAW_SENTINEL,
                    false,
                )
                .expect("unsupported route is a structural decline")
                .is_none()
            );
        }
        assert!(
            select_matching_lf_line_witness_spec(
                std::slice::from_ref(&spec),
                AotMode::Optimizing,
                AotOutput::Exists,
                "absent-public-pattern",
                false,
            )
            .expect("absent row")
            .is_none()
        );

        type MutateReceipt = fn(&mut AotMatchingLfLineWitnessReceiptV1);
        let mutations: &[MutateReceipt] = &[
            |value| value.manifest_profile_key[0] ^= 1,
            |value| value.case_insensitive = !value.case_insensitive,
            |value| value.source_count += 1,
            |value| value.source_bytes += 1,
            |value| value.minimum_width += 1,
            |value| value.maximum_width += 1,
            |value| value.source_language_sha256[0] ^= 1,
            |value| value.compiler_literal_sha256[0] ^= 1,
            |value| value.compiler_source_count += 1,
            |value| value.compiler_source_bytes += 1,
            |value| value.compiler_minimum_width += 1,
            |value| value.compiler_maximum_width += 1,
            |value| value.schema_version ^= 1,
            |value| value.strategy ^= 1,
            |value| value.semantics ^= 1,
            |value| value.abi ^= 1,
            |value| value.miss_sentinel ^= 1,
            |value| value.target_architecture ^= 1,
            |value| value.target_operating_system ^= 1,
            |value| value.target_features ^= 1,
            |value| value.program_bytes += 1,
            |value| value.program_sha256[0] ^= 1,
            |value| value.cursor_register ^= 1,
            |value| value.success_edge_count += 1,
            |value| value.inside_match_edge_count += 1,
            |value| value.exclusive_end_edge_count += 1,
            |value| value.success_edges_sha256[0] ^= 1,
            |value| value.trusted_core_offset += 1,
            |value| value.trusted_core_sha256[0] ^= 1,
            |value| value.ordinary_entry_symbol_sha256[0] ^= 1,
            |value| value.ordinary_entry_code_sha256[0] ^= 1,
            |value| value.wrapper_entry_offset += 1,
            |value| value.wrapper_bytes += 1,
            |value| value.wrapper_sha256[0] ^= 1,
            |value| value.endpoint_symbol_sha256[0] ^= 1,
            |value| value.native_code_sha256[0] ^= 1,
            |value| value.relocations_sha256[0] ^= 1,
            |value| value.object_sha256[0] ^= 1,
            |value| value.runtime_call_count += 1,
            |value| value.receipt_identity_sha256[0] ^= 1,
        ];
        for mutate in mutations {
            let mut corrupted = spec;
            mutate(&mut corrupted.receipt);
            let error = select_matching_lf_line_witness_spec(
                std::slice::from_ref(&corrupted),
                AotMode::Optimizing,
                AotOutput::Exists,
                RAW_SENTINEL,
                false,
            )
            .expect_err("every receipt mutation is terminal");
            assert!(error.contains("receipt authentication failed"), "{error}");
            assert!(!error.contains(RAW_SENTINEL));
        }

        let mut wrong_symbol = spec;
        wrong_symbol.entry_symbol = "public_wrong_lf_line_witness_symbol";
        assert!(
            select_matching_lf_line_witness_spec(
                std::slice::from_ref(&wrong_symbol),
                AotMode::Optimizing,
                AotOutput::Exists,
                RAW_SENTINEL,
                false,
            )
            .expect_err("entry-symbol substitution is terminal")
            .contains("receipt authentication failed")
        );
        let duplicate_specs = [spec, spec];
        assert!(
            select_matching_lf_line_witness_spec(
                &duplicate_specs,
                AotMode::Optimizing,
                AotOutput::Exists,
                RAW_SENTINEL,
                false,
            )
            .expect_err("duplicate profile key is terminal")
            .contains("ambiguous profile key")
        );
        assert_eq!(
            LF_LINE_WITNESS_SELECTION_ENTRY_CALLS.load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn lf_line_witness_native_boundary_returns_only_miss_or_unconfirmed_valid_position() {
        assert_eq!(
            native_matching_lf_line_witness(lf_line_witness_entry, b"abcde")
                .expect("candidate success"),
            AotMatchingLfLineWitnessOutcome::Candidate { position: 2 }
        );
        assert_eq!(
            native_matching_lf_line_witness(lf_line_witness_entry, b"abcd").expect("short miss"),
            AotMatchingLfLineWitnessOutcome::ConfirmedMiss
        );
        assert!(
            native_matching_lf_line_witness(lf_line_witness_entry, b"ab\ncd")
                .expect_err("an LF byte is not a valid line witness")
                .contains("invalid position")
        );
        let failure =
            native_matching_lf_line_witness(lf_line_witness_failure_after_write_entry, b"haystack")
                .expect_err("nonzero status is terminal despite an output write");
        assert!(failure.contains("status 9"));
        assert!(
            native_matching_lf_line_witness(lf_line_witness_out_of_range_entry, b"haystack")
                .expect_err("out-of-range position")
                .contains("invalid position")
        );
        assert!(
            native_matching_lf_line_witness(lf_line_witness_out_of_range_entry, b"")
                .expect_err("a non-sentinel empty-haystack position is invalid")
                .contains("invalid position")
        );
    }

    #[test]
    fn generated_lf_line_witness_registry_is_raw_free_and_receipt_closed() {
        let generated_source =
            include_str!(concat!(env!("OUT_DIR"), "/lf_line_witness_registry.rs"));
        for raw_source in [
            "PM_RESUME",
            "Sherlock Holmes",
            "Шерлок Холмс",
            "FirstCandidatePublicShape",
            "PublicSingletonNeedle",
            "FirstCandidatePublicAlpha",
            "FirstCandidatePublicBravo",
        ] {
            assert!(
                !generated_source.contains(raw_source),
                "matching-LF-line witness registry leaked a raw source"
            );
        }
        assert_eq!(
            generated_lf_line_witnesses::BUILD_LF_LINE_WITNESS_ADMITTED_COUNT,
            generated_lf_line_witnesses::MATCHING_LF_LINE_WITNESS_SPECS.len()
        );
        assert!(
            generated_lf_line_witnesses::BUILD_LF_LINE_WITNESS_ADMITTED_COUNT
                <= generated_lf_line_witnesses::BUILD_LF_LINE_WITNESS_INDEPENDENTLY_ELIGIBLE_COUNT
        );
        if generated_lf_line_witnesses::BUILD_LF_LINE_WITNESS_PUBLIC_FIXTURE_SELECTED
            && generated::BUILD_VARIANT_POLICY != "optimizing-grep-count"
            && generated::BUILD_PATTERN_COUNT == 4
        {
            assert_eq!(
                generated_lf_line_witnesses::BUILD_LF_LINE_WITNESS_INDEPENDENTLY_ELIGIBLE_COUNT,
                4
            );
            assert!(
                !generated_lf_line_witnesses::MATCHING_LF_LINE_WITNESS_SPECS.is_empty(),
                "public finite-language fixture must exercise a linked witness endpoint"
            );
        }
        for spec in generated_lf_line_witnesses::MATCHING_LF_LINE_WITNESS_SPECS {
            let receipt = spec.receipt;
            assert_eq!(spec.manifest_profile_key, receipt.manifest_profile_key());
            assert!(
                generated::ALL_MANIFEST_PROFILE_KEYS.contains(&spec.manifest_profile_key),
                "witness row has no selected manifest profile"
            );
            assert_eq!(
                receipt.target_features(),
                generated_lf_line_witnesses::BUILD_LF_LINE_WITNESS_TARGET_FEATURES
            );
            assert_ne!(receipt.source_count(), 0);
            assert_ne!(receipt.source_bytes(), 0);
            assert_ne!(receipt.minimum_width(), 0);
            assert!(receipt.minimum_width() <= receipt.maximum_width());
            assert_ne!(receipt.source_language_sha256(), [0; 32]);
            assert_ne!(receipt.object_sha256(), [0; 32]);
            assert_eq!(
                receipt.identity_input().identity(),
                Some(receipt.receipt_identity_sha256)
            );
            let endpoint_symbol_sha256: [u8; 32] =
                Sha256::digest(spec.entry_symbol.as_bytes()).into();
            assert_eq!(endpoint_symbol_sha256, receipt.endpoint_symbol_sha256);
            assert!(!spec.description.contains("pattern="));
            // SAFETY: null output is invalid independently of the deliberately
            // null zero-length haystack and must be rejected before scanning.
            let status = unsafe { (spec.entry)(std::ptr::null(), 0, std::ptr::null_mut()) };
            assert_eq!(status, 2);
        }

        if generated_lf_line_witnesses::BUILD_LF_LINE_WITNESS_PUBLIC_FIXTURE_SELECTED
            && generated::BUILD_VARIANT_POLICY != "optimizing-grep-count"
            && generated::BUILD_PATTERN_COUNT == 4
        {
            let factory = AotMatchingLfLineWitnessFactory::select(
                AotMode::Optimizing,
                AotOutput::Exists,
                "(?:FirstCandidatePublicAlpha|FirstCandidatePublicBravo)",
                false,
            )
            .expect("known public tuple receipt")
            .expect("public finite alternation witness");
            assert!(
                factory
                    .description()
                    .contains("api=matching-lf-line-witness-v1")
            );
            let hit = b"head\n--FirstCandidatePublicBravo--\ntail";
            let line_start = 5;
            let line_end = hit
                .iter()
                .rposition(|&byte| byte == b'\n')
                .expect("matching-line terminator");
            let AotMatchingLfLineWitnessOutcome::Candidate { position } =
                factory.find(hit).expect("linked witness hit")
            else {
                panic!("known matching line returned a miss");
            };
            assert!((line_start..line_end).contains(&position));
            assert_eq!(
                factory
                    .find(b"unrelated\nbytes")
                    .expect("linked witness miss"),
                AotMatchingLfLineWitnessOutcome::ConfirmedMiss
            );
        }
    }

    #[test]
    fn exact64_selection_authenticates_ordered_vector_and_receipt_before_haystack() {
        // This counter belongs only to this test. The native-boundary test
        // deliberately calls a different entry and may execute in parallel.
        EXACT64_SELECTION_ENTRY_CALLS.store(0, Ordering::Relaxed);
        let patterns = [
            EXACT64_PUBLIC_RAW_SENTINELS[0],
            EXACT64_PUBLIC_RAW_SENTINELS[1],
            EXACT64_PUBLIC_RAW_SENTINELS[0],
        ];
        let profile = RipgrepAotExact64SetProfileV1::supported_rust_regex(false);
        let spec = exact64_test_spec(&patterns, profile, exact64_selection_entry);
        let selected = select_exact64_set_spec(
            std::slice::from_ref(&spec),
            AotMode::Optimizing,
            AotOutput::Exists,
            &patterns,
            profile,
        )
        .expect("authenticated selection")
        .expect("known vector");
        assert_eq!(selected.registry_key, spec.registry_key);
        for mismatch in [
            [
                EXACT64_PUBLIC_RAW_SENTINELS[0],
                EXACT64_PUBLIC_RAW_SENTINELS[0],
                EXACT64_PUBLIC_RAW_SENTINELS[1],
            ]
            .as_slice(),
            [
                "fixture_raw_sentinel",
                "_onefixture_raw_sentinel_one_suffix",
                EXACT64_PUBLIC_RAW_SENTINELS[0],
            ]
            .as_slice(),
            [
                EXACT64_PUBLIC_RAW_SENTINELS[0],
                EXACT64_PUBLIC_RAW_SENTINELS[1],
                EXACT64_PUBLIC_RAW_SENTINELS[1],
            ]
            .as_slice(),
        ] {
            assert!(
                select_exact64_set_spec(
                    std::slice::from_ref(&spec),
                    AotMode::Optimizing,
                    AotOutput::Exists,
                    mismatch,
                    profile,
                )
                .expect("mismatch is absent")
                .is_none()
            );
        }
        assert_eq!(EXACT64_SELECTION_ENTRY_CALLS.load(Ordering::Relaxed), 0);

        let mut corrupted = spec;
        corrupted.receipt.object_sha256 = [0; 32];
        let error = select_exact64_set_spec(
            std::slice::from_ref(&corrupted),
            AotMode::Optimizing,
            AotOutput::Exists,
            &patterns,
            profile,
        )
        .expect_err("receipt mismatch is terminal");
        assert!(error.contains("receipt authentication failed"));
        for sentinel in EXACT64_PUBLIC_RAW_SENTINELS {
            assert!(!error.contains(sentinel));
        }

        let mut wrong_features = spec;
        wrong_features.receipt.target_features ^= 1_u64 << 32;
        assert!(
            select_exact64_set_spec(
                std::slice::from_ref(&wrong_features),
                AotMode::Optimizing,
                AotOutput::Exists,
                &patterns,
                profile,
            )
            .expect_err("target feature mismatch is terminal")
            .contains("receipt authentication failed")
        );

        let duplicate_specs = [spec, spec];
        assert!(
            select_exact64_set_spec(
                &duplicate_specs,
                AotMode::Optimizing,
                AotOutput::Exists,
                &patterns,
                profile,
            )
            .expect_err("duplicate key is terminal")
            .contains("ambiguous authenticated key")
        );
    }

    #[test]
    fn exact64_native_boundary_publishes_candidate_or_miss_and_keeps_failures_terminal() {
        assert_eq!(
            native_exact64_first_any(exact64_candidate_entry, b"abc")
                .expect("candidate success"),
            AotExact64SetOutcome::Candidate { position: 2 }
        );
        assert_eq!(
            native_exact64_first_any(exact64_candidate_entry, b"ab").expect("short miss"),
            AotExact64SetOutcome::ConfirmedMiss
        );
        assert_eq!(
            native_exact64_first_any(exact64_miss_entry, b"anything").expect("explicit miss"),
            AotExact64SetOutcome::ConfirmedMiss
        );
        let failure = native_exact64_first_any(exact64_failure_after_write_entry, b"haystack")
            .expect_err("nonzero status is terminal despite output write");
        assert!(failure.contains("status 9"));
        assert!(
            native_exact64_first_any(exact64_invalid_position_entry, b"haystack")
                .expect_err("out-of-range success is terminal")
                .contains("invalid position")
        );
    }

    #[test]
    fn generated_exact64_registry_is_raw_free_closed_and_uses_first_any_objects() {
        let generated_source = include_str!(concat!(env!("OUT_DIR"), "/exact64_set_registry.rs"));
        let generated_filenames = std::fs::read_dir(env!("OUT_DIR"))
            .expect("read generated artifact directory")
            .map(|entry| {
                entry
                    .expect("read generated artifact entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        for sentinel in EXACT64_PUBLIC_RAW_SENTINELS {
            assert!(!generated_source.contains(sentinel));
            assert!(
                generated_filenames
                    .iter()
                    .all(|filename| !filename.contains(sentinel))
            );
        }
        assert_eq!(
            generated_exact64_sets::BUILD_EXACT64_SET_ADMITTED_COUNT,
            generated_exact64_sets::EXACT64_SET_SPECS.len()
        );
        assert!(
            generated_exact64_sets::BUILD_EXACT64_SET_INDEPENDENTLY_ELIGIBLE_COUNT
                <= generated_exact64_sets::BUILD_EXACT64_SET_MANIFEST_COUNT
        );
        assert!(
            generated_exact64_sets::BUILD_EXACT64_SET_ADMITTED_COUNT
                <= generated_exact64_sets::BUILD_EXACT64_SET_INDEPENDENTLY_ELIGIBLE_COUNT
        );
        if !generated_exact64_sets::BUILD_EXACT64_SET_MANIFEST_SELECTED {
            assert_eq!(generated_exact64_sets::BUILD_EXACT64_SET_MANIFEST_COUNT, 0);
            assert!(generated_exact64_sets::EXACT64_SET_SPECS.is_empty());
        }
        for spec in generated_exact64_sets::EXACT64_SET_SPECS {
            assert_eq!(spec.registry_key, spec.receipt.registry_key());
            assert!(
                spec.entry_symbol
                    .starts_with("fre_aot_regex_set_exact64_first_any_v1_")
            );
            assert_ne!(spec.receipt.object_sha256(), [0; 32]);
            assert_ne!(spec.receipt.artifact_identity_sha256(), [0; 32]);
            assert_eq!(
                spec.receipt.target_features(),
                generated_exact64_sets::BUILD_EXACT64_SET_TARGET_FEATURES
            );
            assert!((2..=64).contains(&spec.receipt.pattern_count()));
            for sentinel in EXACT64_PUBLIC_RAW_SENTINELS {
                assert!(!spec.description.contains(sentinel));
                assert!(!spec.entry_symbol.contains(sentinel));
            }
            // SAFETY: the authenticated V1 entry must reject the null output
            // before scanning the deliberately invalid haystack extent.
            let status = unsafe {
                (spec.entry)(
                    std::ptr::null(),
                    usize::MAX,
                    0,
                    usize::MAX,
                    std::ptr::null_mut(),
                )
            };
            assert_eq!(
                status,
                fre_aot_regex::REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_STATUS_INVALID_ARGUMENT
            );
        }

        if cfg!(target_arch = "aarch64")
            && generated_exact64_sets::BUILD_EXACT64_SET_PUBLIC_FIXTURE_SELECTED
        {
            assert_eq!(generated_exact64_sets::EXACT64_SET_SPECS.len(), 2);
            let public = [
                EXACT64_PUBLIC_RAW_SENTINELS[0],
                EXACT64_PUBLIC_RAW_SENTINELS[1],
                EXACT64_PUBLIC_RAW_SENTINELS[0],
                EXACT64_PUBLIC_RAW_SENTINELS[2],
            ];
            let factory = AotExact64SetFactory::select(
                AotMode::Optimizing,
                AotOutput::Exists,
                &public,
                RipgrepAotExact64SetProfileV1::supported_rust_regex(false),
            )
            .expect("public overlap registry authentication")
            .expect("AArch64 public overlap set must be admitted");
            assert!(factory.description().contains("api=exact64-first-any-v1"));
            assert_eq!(factory.receipt().pattern_count(), 4);
            let hit = format!("--{}--", EXACT64_PUBLIC_RAW_SENTINELS[1]);
            assert_eq!(
                factory
                    .prefilter(hit.as_bytes())
                    .expect("public overlap hit"),
                AotExact64SetOutcome::Candidate {
                    position: 2 + EXACT64_PUBLIC_RAW_SENTINELS[0].len() - 1,
                }
            );
            assert_eq!(
                factory.prefilter(b"unrelated").expect("public miss"),
                AotExact64SetOutcome::ConfirmedMiss
            );

            let case_neutral = ["1234", "5678"];
            let case_neutral_factory = AotExact64SetFactory::select(
                AotMode::Optimizing,
                AotOutput::Exists,
                &case_neutral,
                RipgrepAotExact64SetProfileV1::supported_rust_regex(true),
            )
            .expect("public case-neutral registry authentication")
            .expect("AArch64 public case-neutral set must be admitted");
            assert_eq!(case_neutral_factory.receipt().pattern_count(), 2);
            assert_eq!(
                case_neutral_factory
                    .prefilter(b"xx5678")
                    .expect("public case-neutral hit"),
                AotExact64SetOutcome::Candidate { position: 5 }
            );
        }
    }

    #[test]
    fn grep_count_native_boundary_publishes_only_success_and_keeps_errors_terminal() {
        assert_eq!(
            native_grep_count(
                successful_grep_count,
                FreAotRegexExclusiveHandleV1::INVALID,
                b"public fixture",
            )
            .expect("successful aggregate"),
            17
        );
        let error = native_grep_count(
            failing_grep_count,
            FreAotRegexExclusiveHandleV1::INVALID,
            b"public fixture",
        )
        .expect_err("nonzero native status is terminal");
        assert!(error.contains("status 7"));
    }

    #[test]
    fn offset_iterator_is_equivalent_across_runtime_direct_and_prepared_backends() {
        let collect = |matcher: &mut AotMatcher, haystack: &[u8], start| {
            matcher
                .find_iter_at(haystack, start)
                .expect("offset Span iterator")
                .map(|matched| matched.expect("offset match").range())
                .collect::<Vec<_>>()
        };

        let expected = [2..3, 3..4, 4..5];
        for mut matcher in [
            runtime_test_matcher(r"(?-u:.)"),
            native_matcher(one_byte_search, one_byte_fill),
            native_matcher(one_byte_search, dense_direct_fill),
            prepared_test_matcher(AotOutput::Span, Some(one_byte_prepared_span_fill), None),
        ] {
            assert_eq!(collect(&mut matcher, b"abcde", 2), expected);
            assert!(collect(&mut matcher, b"abcde", 5).is_empty());
            let error = matcher
                .find_iter_at(b"abcde", 6)
                .expect_err("out-of-bounds iterator start");
            assert!(error.contains("invalid search window 6..5 for haystack length 5"));
        }

        let nullable_expected = [2..2, 3..3];
        for mut matcher in [
            runtime_test_matcher(""),
            native_matcher(nullable_search, nullable_fill),
            native_matcher(nullable_search, nullable_direct_fill),
            prepared_test_matcher(AotOutput::Span, Some(nullable_prepared_span_fill), None),
        ] {
            assert_eq!(collect(&mut matcher, b"xyz", 2), nullable_expected);
            assert_eq!(collect(&mut matcher, b"xyz", 3), [3..3]);
        }
    }

    #[test]
    fn offset_iterator_releases_matcher_after_callback_stop_and_error() {
        let mut matcher = native_matcher(one_byte_search, dense_direct_fill);
        {
            let mut matches = matcher
                .find_iter_at(b"abcde", 2)
                .expect("offset Span iterator");
            assert_eq!(
                matches
                    .next()
                    .expect("callback item")
                    .expect("match")
                    .range(),
                2..3,
            );
            // Dropping here models a callback requesting an early stop.
        }
        assert_eq!(
            matcher
                .find_at(b"abcde", 1)
                .expect("find after callback stop")
                .expect("match after callback stop")
                .range(),
            1..2,
        );

        let callback_result: Result<(), String> = matcher
            .find_iter_at(b"abcde", 2)
            .expect("second offset iterator")
            .try_for_each(|matched| {
                let matched = matched?;
                if matched.start() == 3 {
                    Err("public callback failure".to_owned())
                } else {
                    Ok(())
                }
            });
        assert_eq!(callback_result, Err("public callback failure".to_owned()));
        assert_eq!(
            matcher
                .find_at(b"abcde", 0)
                .expect("find after callback error")
                .expect("match after callback error")
                .range(),
            0..1,
        );
    }

    #[test]
    fn native_iterator_batches_indirect_refills() {
        SEARCH_CALLS.store(0, Ordering::Relaxed);
        FILL_CALLS.store(0, Ordering::Relaxed);
        let haystack = vec![b'a'; NATIVE_SPAN_BUFFER_CAPACITY * 2 + 2];
        let mut matcher = native_matcher(counted_one_byte_search, dense_fill);
        let spans = matcher
            .find_iter(&haystack)
            .expect("Span iterator")
            .map(|matched| matched.expect("native match").range())
            .collect::<Vec<_>>();
        assert_eq!(spans.len(), haystack.len());
        assert_eq!(spans.first(), Some(&(0..1)));
        assert_eq!(spans.last(), Some(&((haystack.len() - 1)..haystack.len())));
        assert_eq!(FILL_CALLS.load(Ordering::Relaxed), 3);
        assert_eq!(SEARCH_CALLS.load(Ordering::Relaxed), haystack.len() + 1);
    }

    #[test]
    fn prepared_iterator_crosses_native_fill_abi_once_per_refill() {
        PREPARED_SPAN_FILL_CALLS.store(0, Ordering::Relaxed);
        let haystack = vec![b'a'; NATIVE_SPAN_BUFFER_CAPACITY * 2 + 2];
        let mut matcher =
            prepared_test_matcher(AotOutput::Span, Some(dense_prepared_span_fill), None);
        let spans = matcher
            .find_iter(&haystack)
            .expect("prepared Span iterator")
            .map(|matched| matched.expect("prepared native match").range())
            .collect::<Vec<_>>();
        assert_eq!(spans.len(), haystack.len());
        assert_eq!(PREPARED_SPAN_FILL_CALLS.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn direct_iterator_crosses_native_fill_abi_once_per_refill() {
        let _counter_guard = DIRECT_SPAN_FILL_COUNTER_TEST_LOCK
            .lock()
            .expect("direct Span-fill counter lock");
        DIRECT_SPAN_FILL_CALLS.store(0, Ordering::Relaxed);
        let haystack = vec![b'a'; NATIVE_SPAN_BUFFER_CAPACITY * 2 + 2];
        let mut matcher = native_matcher(one_byte_search, dense_direct_fill);
        let spans = matcher
            .find_iter(&haystack)
            .expect("direct Span iterator")
            .map(|matched| matched.expect("direct native match").range())
            .collect::<Vec<_>>();
        assert_eq!(spans.len(), haystack.len());
        assert_eq!(spans.first(), Some(&(0..1)));
        assert_eq!(spans.last(), Some(&((haystack.len() - 1)..haystack.len())));
        assert_eq!(DIRECT_SPAN_FILL_CALLS.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn direct_span_fill_boundary_fails_closed_before_or_after_one_raw_call() {
        let _counter_guard = DIRECT_SPAN_FILL_COUNTER_TEST_LOCK
            .lock()
            .expect("direct Span-fill counter lock");
        DIRECT_SPAN_FILL_CALLS.store(0, Ordering::Relaxed);
        let mut state = NativeIterState::initial_at(0, 1).expect("valid initial state");
        let mut empty = [];
        let outcome = fill_direct_spans(
            dense_direct_span_fill,
            b"a",
            &mut state,
            &mut empty,
        );
        assert_eq!(outcome.written, 0);
        assert!(
            outcome
                .error
                .as_deref()
                .is_some_and(|error| error.contains("empty output buffer"))
        );
        assert!(state.finished());
        assert_eq!(DIRECT_SPAN_FILL_CALLS.load(Ordering::Relaxed), 0);

        let mut state = NativeIterState::initial_at(0, 1).expect("valid initial state");
        let mut output = [MaybeUninit::uninit(); 1];
        let outcome = fill_direct_spans(
            overreported_direct_span_fill,
            b"a",
            &mut state,
            &mut output,
        );
        assert_eq!(outcome.written, 0);
        assert!(
            outcome
                .error
                .as_deref()
                .is_some_and(|error| error.contains("overreported its initialized prefix"))
        );
        assert!(state.finished());

        let mut matcher = native_matcher(one_byte_search, invalid_state_direct_fill);
        let mut matches = matcher.find_iter(b"a").expect("direct Span iterator");
        assert!(
            matches
                .next()
                .expect("one error")
                .expect_err("invalid state")
                .contains("invalid iterator state")
        );
        assert!(matches.next().is_none());
    }

    #[test]
    fn prepared_iterator_exact_capacity_requires_terminal_refill() {
        PREPARED_EXACT_CAPACITY_FILL_CALLS.store(0, Ordering::Relaxed);
        let haystack = vec![b'a'; NATIVE_SPAN_BUFFER_CAPACITY];
        let mut matcher = prepared_test_matcher(
            AotOutput::Span,
            Some(exact_capacity_prepared_span_fill),
            None,
        );
        let spans = matcher
            .find_iter(&haystack)
            .expect("prepared exact-capacity iterator")
            .map(|matched| matched.expect("prepared native match").range())
            .collect::<Vec<_>>();
        assert_eq!(spans.len(), NATIVE_SPAN_BUFFER_CAPACITY);
        assert_eq!(
            PREPARED_EXACT_CAPACITY_FILL_CALLS.load(Ordering::Relaxed),
            2
        );
    }

    #[test]
    fn prepared_iterator_preserves_nullable_empty_progress() {
        let mut matcher =
            prepared_test_matcher(AotOutput::Span, Some(nullable_prepared_span_fill), None);
        let spans = matcher
            .find_iter(b"a")
            .expect("prepared nullable iterator")
            .map(|matched| matched.expect("prepared match").range())
            .collect::<Vec<_>>();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0], 0..1);

        let mut matcher =
            prepared_test_matcher(AotOutput::Span, Some(nullable_prepared_span_fill), None);
        let spans = matcher
            .find_iter(&[0xe2, 0x98, 0x83])
            .expect("prepared empty iterator")
            .map(|matched| matched.expect("prepared empty match").range())
            .collect::<Vec<_>>();
        assert_eq!(spans, [0..0, 1..1, 2..2, 3..3]);
    }

    #[test]
    fn prepared_iterator_yields_initialized_prefix_before_error() {
        let mut prepared = prepared_test_matcher(
            AotOutput::Span,
            Some(two_then_error_prepared_span_fill),
            None,
        );
        let mut iteration = prepared.find_iter(b"aaa").expect("prepared iterator");
        assert_eq!(
            iteration
                .next()
                .expect("first item")
                .expect("first match")
                .range(),
            0..1
        );
        assert_eq!(
            iteration
                .next()
                .expect("second item")
                .expect("second match")
                .range(),
            1..2
        );
        assert!(
            iteration
                .next()
                .expect("deferred error")
                .expect_err("status error")
                .contains("status 2")
        );
        assert!(iteration.next().is_none());
    }

    #[test]
    fn direct_iterator_yields_initialized_prefix_before_error() {
        let mut direct = native_matcher(two_then_error_search, two_then_error_direct_fill);
        let mut iteration = direct.find_iter(b"aaa").expect("direct iterator");
        assert_eq!(
            iteration
                .next()
                .expect("first item")
                .expect("first match")
                .range(),
            0..1
        );
        assert_eq!(
            iteration
                .next()
                .expect("second item")
                .expect("second match")
                .range(),
            1..2
        );
        assert!(
            iteration
                .next()
                .expect("deferred error")
                .expect_err("status error")
                .contains("status 2")
        );
        assert!(iteration.next().is_none());

        let mut direct = native_matcher(one_byte_search, two_then_status3_direct_fill);
        let mut iteration = direct.find_iter(b"aaa").expect("direct status-3 iterator");
        assert_eq!(
            iteration
                .next()
                .expect("first status-3 prefix item")
                .expect("first status-3 prefix match")
                .range(),
            0..1
        );
        assert_eq!(
            iteration
                .next()
                .expect("second status-3 prefix item")
                .expect("second status-3 prefix match")
                .range(),
            1..2
        );
        assert!(
            iteration
                .next()
                .expect("deferred status-3 error")
                .expect_err("status-3 failure")
                .contains("status 3")
        );
        assert!(iteration.next().is_none());
    }

    #[test]
    fn prepared_iterator_rejects_inconsistent_native_state_and_fuses() {
        let mut prepared = prepared_test_matcher(
            AotOutput::Span,
            Some(invalid_state_prepared_span_fill),
            None,
        );
        let mut iteration = prepared.find_iter(b"a").expect("prepared iterator");
        assert!(
            iteration
                .next()
                .expect("one error")
                .expect_err("invalid state")
                .contains("invalid iterator state")
        );
        assert!(iteration.next().is_none());
    }

    #[test]
    fn prepared_iterator_rejects_incoherent_last_span_and_fuses() {
        let mut prepared = prepared_test_matcher(
            AotOutput::Span,
            Some(mismatched_last_span_prepared_fill),
            None,
        );
        let mut iteration = prepared.find_iter(b"aa").expect("prepared iterator");
        assert!(
            iteration
                .next()
                .expect("one error")
                .expect_err("inconsistent final span/state")
                .contains("inconsistent final span/state")
        );
        assert!(iteration.next().is_none());
    }

    #[test]
    fn aot_haystack_is_an_exact_lifetime_bound_abi_view() {
        assert_eq!(
            std::mem::size_of::<AotHaystack<'_>>(),
            std::mem::size_of::<AbiHaystack>()
        );
        assert_eq!(
            std::mem::align_of::<AotHaystack<'_>>(),
            std::mem::align_of::<AbiHaystack>()
        );

        let bytes = [0x00, 0x7f, 0xff];
        let descriptor = AotHaystack::from(bytes.as_slice());
        assert_eq!(descriptor.abi.ptr, bytes.as_ptr());
        assert_eq!(descriptor.abi.len, bytes.len());
        assert_eq!(descriptor.as_slice(), bytes);

        let empty = AotHaystack::from([].as_slice());
        assert_eq!(empty.abi.len, 0);
        assert!(empty.as_slice().is_empty());
    }

    #[test]
    fn descriptor_batch_accepts_empty_and_rejects_invalid_lengths() {
        let mut direct = direct_exists_test_matcher(contains_x_direct_exists_batch);
        direct
            .is_match_descriptor_batch(&[], &mut [])
            .expect("empty descriptor batch");

        let one = [AotHaystack::from(b"x")];
        let mut span = native_matcher(one_byte_search, dense_fill);
        let mut outcome = [true];
        let error = span
            .is_match_descriptor_batch(&one, &mut outcome)
            .expect_err("descriptor singleton output-contract mismatch");
        assert_eq!(error, "AOT matcher was not compiled for Exists");
        assert_eq!(outcome, [true]);

        let two = [AotHaystack::from(b"x"), AotHaystack::from(b"no")];
        let error = direct
            .is_match_descriptor_batch(&two, &mut [false])
            .expect_err("descriptor/output length mismatch");
        assert!(error.contains("length mismatch: 2 != 1"));

        let oversized = vec![AotHaystack::from(b""); EXISTS_BATCH_CAPACITY + 1];
        let mut outcomes = vec![true; oversized.len()];
        let error = direct
            .is_match_descriptor_batch(&oversized, &mut outcomes)
            .expect_err("oversized descriptor batch");
        assert!(error.contains("exceeds capacity"));
        assert!(outcomes.iter().all(|&matched| matched));
    }

    #[test]
    fn descriptor_batch_publishes_mixed_prepared_and_direct_results() {
        let _counter_guard = EXISTS_BATCH_COUNTER_TEST_LOCK
            .lock()
            .expect("Exists batch counter test lock");
        let lines = [b"x".as_slice(), b"no".as_slice(), b"suffix-x".as_slice()];
        let descriptors = lines.map(AotHaystack::from);

        PREPARED_EXISTS_BATCH_CALLS.store(0, Ordering::Relaxed);
        let mut prepared = prepared_test_matcher(
            AotOutput::Exists,
            None,
            Some(contains_x_prepared_exists_batch),
        );
        let mut prepared_outcomes = [false; 3];
        prepared
            .is_match_descriptor_batch(&descriptors, &mut prepared_outcomes)
            .expect("prepared descriptor batch");
        assert_eq!(prepared_outcomes, [true, false, true]);
        assert_eq!(PREPARED_EXISTS_BATCH_CALLS.load(Ordering::Relaxed), 1);

        DIRECT_EXISTS_BATCH_CALLS.store(0, Ordering::Relaxed);
        let mut direct = direct_exists_test_matcher(contains_x_direct_exists_batch);
        let mut direct_outcomes = [false; 3];
        direct
            .is_match_descriptor_batch(&descriptors, &mut direct_outcomes)
            .expect("direct descriptor batch");
        assert_eq!(direct_outcomes, prepared_outcomes);
        assert_eq!(DIRECT_EXISTS_BATCH_CALLS.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn descriptor_batch_failure_preserves_valid_boolean_prefix_and_tail() {
        let descriptors = [
            AotHaystack::from(b"first"),
            AotHaystack::from(b"second"),
            AotHaystack::from(b"third"),
        ];
        let mut outcomes = [false, true, false];
        let mut direct = direct_exists_test_matcher(one_then_error_direct_exists_batch);
        let error = direct
            .is_match_descriptor_batch(&descriptors, &mut outcomes)
            .expect_err("native failure after one Boolean result");
        assert!(error.contains("status 7 after 1/3"));
        assert_eq!(outcomes, [true, true, false]);
    }

    #[test]
    fn descriptor_batch_scalar_fallback_reads_the_borrowed_slices() {
        let descriptors = [AotHaystack::from(b""), AotHaystack::from(b"nonempty")];
        let mut outcomes = [true, false];
        let mut direct = AotMatcher {
            output: AotOutput::Exists,
            description: "test-direct-scalar-fallback",
            backend: Backend::Native {
                search: one_byte_search,
                fill: None,
                exists_batch: None,
            },
        };
        direct
            .is_match_descriptor_batch(&descriptors, &mut outcomes)
            .expect("descriptor scalar fallback");
        assert_eq!(outcomes, [false, true]);
    }

    #[test]
    fn prepared_exists_batch_crosses_native_abi_once_for_64_lines() {
        let _counter_guard = EXISTS_BATCH_COUNTER_TEST_LOCK
            .lock()
            .expect("Exists batch counter test lock");
        PREPARED_EXISTS_BATCH_CALLS.store(0, Ordering::Relaxed);
        let lines = (0..EXISTS_BATCH_CAPACITY)
            .map(|index| {
                if index % 3 == 0 {
                    b"x".as_slice()
                } else {
                    b"no".as_slice()
                }
            })
            .collect::<Vec<_>>();
        let mut outcomes = [false; EXISTS_BATCH_CAPACITY];
        let mut prepared = prepared_test_matcher(
            AotOutput::Exists,
            None,
            Some(contains_x_prepared_exists_batch),
        );
        prepared
            .is_match_batch(&lines, &mut outcomes)
            .expect("prepared Exists batch");
        for (index, matched) in outcomes.into_iter().enumerate() {
            assert_eq!(matched, index % 3 == 0);
        }
        assert_eq!(PREPARED_EXISTS_BATCH_CALLS.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn direct_exists_batch_crosses_native_abi_once_for_64_lines() {
        let _counter_guard = EXISTS_BATCH_COUNTER_TEST_LOCK
            .lock()
            .expect("Exists batch counter test lock");
        DIRECT_EXISTS_BATCH_CALLS.store(0, Ordering::Relaxed);
        let lines = (0..EXISTS_BATCH_CAPACITY)
            .map(|index| {
                if index % 3 == 0 {
                    b"x".as_slice()
                } else {
                    b"no".as_slice()
                }
            })
            .collect::<Vec<_>>();
        let mut outcomes = [false; EXISTS_BATCH_CAPACITY];
        let mut direct = direct_exists_test_matcher(contains_x_direct_exists_batch);
        direct
            .is_match_batch(&lines, &mut outcomes)
            .expect("direct Exists batch");
        for (index, matched) in outcomes.into_iter().enumerate() {
            assert_eq!(matched, index % 3 == 0);
        }
        assert_eq!(DIRECT_EXISTS_BATCH_CALLS.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn direct_exists_batch_failure_preserves_valid_boolean_prefix_and_tail() {
        let lines = [b"first".as_slice(), b"second".as_slice(), b"third".as_slice()];
        let mut outcomes = [false, true, false];
        let mut direct = direct_exists_test_matcher(one_then_error_direct_exists_batch);
        let error = direct
            .is_match_batch(&lines, &mut outcomes)
            .expect_err("native failure after one Boolean result");
        assert!(error.contains("status 7 after 1/3"));
        assert_eq!(outcomes, [true, true, false]);
    }

    #[test]
    fn one_haystack_exists_batches_use_the_backend_scalar_entry() {
        SINGLETON_EXISTS_SCALAR_CALLS.store(0, Ordering::Relaxed);
        SINGLETON_EXISTS_BATCH_CALLS.store(0, Ordering::Relaxed);

        let mut prepared = AotMatcher {
            output: AotOutput::Exists,
            description: "test-singleton-prepared",
            backend: Backend::Prepared(PreparedNative {
                search: singleton_one_byte_prepared_search,
                span_fill: None,
                exists_batch: Some(singleton_prepared_exists_batch),
                handle: FreAotRegexExclusiveHandleV1::INVALID,
            }),
        };
        let mut prepared_outcome = [false];
        prepared
            .is_match_batch(&[b"no"], &mut prepared_outcome)
            .expect("one-haystack prepared Exists request");

        let mut direct = AotMatcher {
            output: AotOutput::Exists,
            description: "test-singleton-direct",
            backend: Backend::Native {
                search: singleton_one_byte_search,
                fill: None,
                exists_batch: Some(singleton_direct_exists_batch),
            },
        };
        let mut direct_outcome = [false];
        direct
            .is_match_batch(&[b"no"], &mut direct_outcome)
            .expect("one-haystack direct Exists request");

        let descriptor = [AotHaystack::from(b"no")];
        let mut prepared_descriptor_outcome = [false];
        prepared
            .is_match_descriptor_batch(&descriptor, &mut prepared_descriptor_outcome)
            .expect("one-descriptor prepared Exists request");
        let mut direct_descriptor_outcome = [false];
        direct
            .is_match_descriptor_batch(&descriptor, &mut direct_descriptor_outcome)
            .expect("one-descriptor direct Exists request");

        assert_eq!(prepared_outcome, [true]);
        assert_eq!(direct_outcome, [true]);
        assert_eq!(prepared_descriptor_outcome, [true]);
        assert_eq!(direct_descriptor_outcome, [true]);
        assert_eq!(SINGLETON_EXISTS_SCALAR_CALLS.load(Ordering::Relaxed), 4);
        assert_eq!(SINGLETON_EXISTS_BATCH_CALLS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn exists_batch_decoder_accepts_only_the_published_boolean_prefix() {
        let mut encoded = [0xff_u8; EXISTS_BATCH_CAPACITY];
        let mut matched = [false; 3];

        let error = decode_exists_batch(0, 4, 3, &encoded, &mut matched)
            .expect_err("overreported prefix");
        assert!(error.contains("overreported"));
        assert_eq!(matched, [false; 3]);

        encoded[0] = 1;
        encoded[1] = 2;
        let error = decode_exists_batch(0, 2, 3, &encoded, &mut matched)
            .expect_err("invalid Boolean");
        assert!(error.contains("invalid boolean 2 at index 1"));
        assert_eq!(matched, [true, false, false]);

        matched = [false; 3];
        let error = decode_exists_batch(7, 1, 3, &encoded, &mut matched)
            .expect_err("native failure after one result");
        assert!(error.contains("status 7 after 1/3"));
        assert_eq!(matched, [true, false, false]);

        let error = decode_exists_batch(0, 1, 3, &encoded, &mut matched)
            .expect_err("partial success is invalid");
        assert!(error.contains("success after 1/3"));
        assert_eq!(matched, [true, false, false]);

        encoded[1] = 0;
        encoded[2] = 1;
        decode_exists_batch(0, 3, 3, &encoded, &mut matched).expect("complete Boolean prefix");
        assert_eq!(matched, [true, false, true]);
    }

    #[test]
    fn generated_direct_exists_batches_match_their_scalar_entries() {
        if generated::BUILD_VARIANT_POLICY == "optimizing-grep-count" {
            assert!(generated::SPECS.is_empty());
            return;
        }
        const CASES: [&[u8]; 10] = [
            b"",
            b"a",
            b"needle",
            b"\n",
            b"\n\n",
            b"a\n",
            b"a\r\nb",
            b"late needle",
            &[0xff, 0x00, b'a'],
            &[b'x'; 65],
        ];
        let mut exercised = 0;
        for spec in generated::SPECS {
            if spec.output != AotOutput::Exists
                || !matches!(
                    spec.backend,
                    BackendFactory::Native {
                        exists_batch: Some(_),
                        ..
                    }
                )
            {
                continue;
            }
            exercised += 1;
            for count in [1, 63, 64] {
                let haystacks = (0..count)
                    .map(|index| CASES[index % CASES.len()])
                    .collect::<Vec<_>>();
                let mut scalar = AotMatcher::new(
                    spec.mode,
                    spec.output,
                    spec.pattern,
                    spec.case_insensitive,
                )
                .expect("direct scalar matcher");
                let expected = haystacks
                    .iter()
                    .map(|haystack| scalar.is_match(haystack).expect("direct scalar search"))
                    .collect::<Vec<_>>();
                let mut batch = AotMatcher::new(
                    spec.mode,
                    spec.output,
                    spec.pattern,
                    spec.case_insensitive,
                )
                .expect("direct batch matcher");
                let mut actual = vec![false; count];
                batch
                    .is_match_batch(&haystacks, &mut actual)
                    .expect("direct native batch search");
                assert_eq!(actual, expected);
            }
        }
        assert!(exercised > 0, "generated registry has no direct Exists batch");
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one raw-ABI test keeps top-level, prefix, descriptor, and signed-domain failure ordering together"
    )]
    fn generated_direct_exists_batch_raw_abi_fails_closed() {
        if generated::BUILD_VARIANT_POLICY == "optimizing-grep-count" {
            assert!(generated::SPECS.is_empty());
            return;
        }
        let batch = generated::SPECS
            .iter()
            .find_map(|spec| match spec.backend {
                BackendFactory::Native {
                    exists_batch: Some(batch),
                    ..
                } if spec.output == AotOutput::Exists => Some(batch),
                _ => None,
            })
            .expect("generated direct Exists batch");
        let mut processed = usize::MAX;
        // SAFETY: zero count permits null descriptor and output arrays; the
        // processed word is live, aligned, and writable.
        let status = unsafe {
            batch(
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                &raw mut processed,
            )
        };
        assert_eq!(status, 0);
        assert_eq!(processed, 0);

        let mut output = [0xa5_u8; 2];
        processed = usize::MAX;
        // SAFETY: deliberately invalid top-level arguments are never
        // dereferenced by the validated compiler boundary.
        let status = unsafe {
            batch(
                std::ptr::null(),
                1,
                output.as_mut_ptr(),
                &raw mut processed,
            )
        };
        assert_eq!(status, 2);
        assert_eq!(processed, usize::MAX);
        assert_eq!(output, [0xa5; 2]);

        let valid = b"needle";
        let descriptors = [
            AbiHaystack {
                ptr: valid.as_ptr(),
                len: valid.len(),
            },
            AbiHaystack {
                ptr: std::ptr::null(),
                len: 0,
            },
        ];
        processed = usize::MAX;
        // SAFETY: the first descriptor is valid. The second is deliberately
        // invalid and must stop before source access or tail publication.
        let status = unsafe {
            batch(
                descriptors.as_ptr(),
                descriptors.len(),
                output.as_mut_ptr(),
                &raw mut processed,
            )
        };
        assert_eq!(status, 2);
        assert_eq!(processed, 1);
        assert!(output[0] <= 1);
        assert_eq!(output[1], 0xa5);

        let oversized = [AbiHaystack {
            ptr: std::ptr::NonNull::<u8>::dangling().as_ptr().cast_const(),
            len: (isize::MAX as usize) + 1,
        }];
        output[0] = 0xa5;
        processed = usize::MAX;
        // SAFETY: the signed-domain length is rejected before the dangling
        // source pointer can be dereferenced.
        let status = unsafe {
            batch(
                oversized.as_ptr(),
                1,
                output.as_mut_ptr(),
                &raw mut processed,
            )
        };
        assert_eq!(status, 2);
        assert_eq!(processed, 0);
        assert_eq!(output[0], 0xa5);

        // SAFETY: both deliberately misaligned pointers are rejected before
        // dereference. Count overflow is checked before descriptor access.
        assert_eq!(
            unsafe {
                batch(
                    std::ptr::without_provenance::<AbiHaystack>(1),
                    1,
                    output.as_mut_ptr(),
                    &raw mut processed,
                )
            },
            2
        );
        assert_eq!(
            unsafe {
                batch(
                    std::ptr::null(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::without_provenance_mut::<usize>(1),
                )
            },
            2
        );
        assert_eq!(
            unsafe {
                batch(
                    std::ptr::null(),
                    (isize::MAX as usize / 16) + 1,
                    std::ptr::null_mut(),
                    &raw mut processed,
                )
            },
            2
        );
    }

    #[test]
    fn native_iterator_matches_rust_empty_progress_across_refills() {
        let mut matcher = native_matcher(nullable_search, nullable_fill);
        let spans = matcher
            .find_iter(b"a")
            .expect("Span iterator")
            .map(|matched| matched.expect("native match").range())
            .collect::<Vec<_>>();
        assert_eq!(spans, [0..1]);

        let mut matcher = native_matcher(nullable_search, nullable_fill);
        let spans = matcher
            .find_iter(&[0xe2, 0x98, 0x83])
            .expect("Span iterator")
            .map(|matched| matched.expect("native empty match").range())
            .collect::<Vec<_>>();
        assert_eq!(spans, [0..0, 1..1, 2..2, 3..3]);

        let haystack = vec![b'a'; NATIVE_SPAN_BUFFER_CAPACITY];
        let mut matcher = native_matcher(dense_then_empty_search, dense_then_empty_fill);
        let spans = matcher
            .find_iter(&haystack)
            .expect("Span iterator")
            .map(|matched| matched.expect("native boundary match").range())
            .collect::<Vec<_>>();
        assert_eq!(spans.len(), haystack.len());
        assert_eq!(spans.last(), Some(&((haystack.len() - 1)..haystack.len())));
    }

    #[test]
    fn native_iterator_reports_validation_error_once_and_fuses() {
        let mut matcher = native_matcher(invalid_search, invalid_fill);
        let mut matches = matcher.find_iter(b"aa").expect("Span iterator");
        let error = matches
            .next()
            .expect("one error")
            .expect_err("invalid span");
        assert!(error.contains("invalid result"));
        assert!(matches.next().is_none());
        assert!(matches.next().is_none());

        let mut matcher = native_matcher(two_then_error_search, two_then_error_fill);
        let mut matches = matcher.find_iter(b"aaa").expect("Span iterator");
        assert_eq!(
            matches
                .next()
                .expect("first item")
                .expect("first match")
                .range(),
            0..1
        );
        assert_eq!(
            matches
                .next()
                .expect("second item")
                .expect("second match")
                .range(),
            1..2
        );
        assert!(
            matches
                .next()
                .expect("deferred error")
                .expect_err("status error")
                .contains("status 2")
        );
        assert!(matches.next().is_none());
    }

    #[test]
    fn native_find_returns_borrowed_match_and_checks_contract() {
        let mut matcher = native_matcher(one_byte_search, dense_fill);
        let matched = matcher.find(b"ab").expect("find").expect("match");
        assert_eq!(matched.range(), 0..1);
        assert_eq!(matched.as_bytes(), b"a");

        matcher.output = AotOutput::Exists;
        assert!(
            matcher
                .find_iter(b"ab")
                .expect_err("Span required")
                .contains("not compiled for Span")
        );
    }

    #[test]
    fn missing_build_variant_error_names_policy_and_available_variant() {
        let specs = [CompiledSpec {
            mode: AotMode::Optimizing,
            output: AotOutput::Exists,
            pattern: "shape(?:one|two|three)",
            case_insensitive: false,
            description: "test-only",
            backend: BackendFactory::Runtime(&[]),
        }];
        let error = missing_spec_error_from(
            &specs,
            &[],
            "optimizing-exists",
            AotMode::Fast,
            AotOutput::Span,
            "shape(?:one|two|three)",
            false,
        );
        assert!(error.contains("requested AOT variant was not emitted"));
        assert!(error.contains("build_variant_policy=optimizing-exists"));
        assert!(error.contains("available_variants=Optimizing+Exists"));
        assert!(error.contains("FRE_RIPGREP_AOT_VARIANTS=all"));

        let absent = missing_spec_error_from(
            &specs,
            &[],
            "optimizing-exists",
            AotMode::Optimizing,
            AotOutput::Exists,
            "different-shape",
            false,
        );
        assert!(absent.contains("pattern/profile is not in the ripgrep AOT registry"));
        assert!(!absent.contains("requested AOT variant was not emitted"));

        let known_profile_keys = [manifest_profile_key("public-shape-only", false)];
        let aggregate_only = missing_spec_error_from(
            &[],
            &known_profile_keys,
            "optimizing-grep-count",
            AotMode::Optimizing,
            AotOutput::Exists,
            "public-shape-only",
            false,
        );
        assert!(aggregate_only.contains("requested ordinary AOT variant was not emitted"));
        assert!(aggregate_only.contains("aggregate-only build"));
        assert!(aggregate_only.contains("build_variant_policy=optimizing-grep-count"));
        assert!(aggregate_only.contains("ordinary_available_variants=none"));
        assert!(aggregate_only.contains("FRE_RIPGREP_AOT_VARIANTS=all"));
        assert!(!aggregate_only.contains("pattern/profile is not in the ripgrep AOT registry"));

        let aggregate_absent = missing_spec_error_from(
            &[],
            &known_profile_keys,
            "optimizing-grep-count",
            AotMode::Optimizing,
            AotOutput::Exists,
            "different-public-shape",
            false,
        );
        assert!(aggregate_absent.contains("pattern/profile is not in the ripgrep AOT registry"));
        assert!(!aggregate_absent.contains("requested ordinary AOT variant was not emitted"));

        let aggregate_wrong_profile = missing_spec_error_from(
            &[],
            &known_profile_keys,
            "optimizing-grep-count",
            AotMode::Optimizing,
            AotOutput::Exists,
            "public-shape-only",
            true,
        );
        assert!(
            aggregate_wrong_profile.contains("pattern/profile is not in the ripgrep AOT registry")
        );
        assert!(
            !aggregate_wrong_profile.contains("requested ordinary AOT variant was not emitted")
        );
    }

    #[test]
    fn aggregate_only_registry_reports_ordinary_variants_omitted_by_policy() {
        if generated::BUILD_VARIANT_POLICY != "optimizing-grep-count" {
            return;
        }
        let Some(known) = generated::GREP_COUNT_SPECS.first() else {
            return;
        };
        let error = AotMatcher::new(
            AotMode::Optimizing,
            AotOutput::Exists,
            known.pattern,
            known.case_insensitive,
        )
        .expect_err("aggregate-only builds omit the known ordinary matcher variant");
        assert!(error.contains("requested ordinary AOT variant was not emitted"));
        assert!(error.contains("build_variant_policy=optimizing-grep-count"));
        assert!(!error.contains("pattern/profile is not in the ripgrep AOT registry"));

        let mut absent = "public-shape-not-in-manifest".to_owned();
        while generated::ALL_MANIFEST_PROFILE_KEYS.contains(&manifest_profile_key(&absent, false)) {
            absent.push('x');
        }
        let absent_error = AotMatcher::new(
            AotMode::Optimizing,
            AotOutput::Exists,
            &absent,
            false,
        )
        .expect_err("unknown manifest profile must remain absent");
        assert!(absent_error.contains("pattern/profile is not in the ripgrep AOT registry"));
        assert!(!absent_error.contains("requested ordinary AOT variant was not emitted"));
    }

    #[test]
    fn generated_registry_routes_compiled_prepared_entries() {
        assert_eq!(
            generated::ALL_MANIFEST_PROFILE_KEYS.len(),
            generated::BUILD_MANIFEST_PATTERN_COUNT,
            "raw-free key table must cover every unfiltered manifest row"
        );
        assert!(
            generated::BUILD_MANIFEST_PATTERN_COUNT >= generated::BUILD_PATTERN_COUNT,
            "filtered build pattern count exceeds its complete manifest"
        );
        let variants_per_pattern = match generated::BUILD_VARIANT_POLICY {
            "all" => 4,
            "optimizing-exists" => {
                assert!(!generated::SPECS.is_empty());
                assert!(generated::SPECS.iter().all(|spec| {
                    spec.mode == AotMode::Optimizing && spec.output == AotOutput::Exists
                }));
                1
            }
            "optimizing-grep-count" => {
                assert!(generated::SPECS.is_empty());
                0
            }
            other => panic!("unknown generated build variant policy: {other:?}"),
        };
        assert_eq!(
            generated::SPECS.len(),
            generated::BUILD_PATTERN_COUNT * variants_per_pattern,
            "generated registry cardinality does not match its frozen pattern/variant policy"
        );
        if generated::BUILD_VARIANT_POLICY != "all" {
            return;
        }
        let mut prepared = 0;
        let mut fast = 0;
        let mut fast_runtime_bulk = 0;
        let mut fast_native_prepared_loop = 0;
        let mut optimizing_prepared = 0;
        let mut optimizing_runtime_bulk = 0;
        let mut optimizing_native_prepared_loop = 0;
        for spec in generated::SPECS {
            if spec.mode == AotMode::Fast {
                fast += 1;
                assert!(
                    matches!(spec.backend, BackendFactory::Prepared { .. }),
                    "Fast artifact silently bypassed its compiled prepared entry: {}",
                    spec.pattern
                );
            }
            match spec.backend {
                BackendFactory::Prepared {
                    span_fill,
                    exists_batch,
                    ..
                } => {
                    prepared += 1;
                    optimizing_prepared += usize::from(spec.mode == AotMode::Optimizing);
                    assert!(
                        spec.description.contains("route=compiled-prepared,api="),
                        "prepared route family changed: {}",
                        spec.description
                    );
                    let runtime_bulk = spec.description.contains("bulk=runtime-helper");
                    let native_bulk_strategies = [
                        "bulk=native-prepared-loop",
                        "bulk=native-trusted-preflight-loop",
                        "bulk=native-trusted-preflight-runtime-bulk",
                        "bulk=native-frozen-loop",
                        "bulk=native-ordered-nfa-loop",
                    ]
                    .into_iter()
                    .filter(|bulk| spec.description.contains(bulk))
                    .count();
                    let native_bulk = native_bulk_strategies == 1;
                    assert_ne!(
                        runtime_bulk, native_bulk,
                        "prepared bulk strategy is missing or ambiguous: {}",
                        spec.description
                    );
                    match spec.mode {
                        AotMode::Fast => {
                            if runtime_bulk {
                                fast_runtime_bulk += 1;
                            } else {
                                fast_native_prepared_loop += 1;
                            }
                        }
                        AotMode::Optimizing if runtime_bulk => optimizing_runtime_bulk += 1,
                        AotMode::Optimizing => optimizing_native_prepared_loop += 1,
                    }
                    match spec.output {
                        AotOutput::Exists => {
                            assert!(span_fill.is_none());
                            assert!(exists_batch.is_some());
                            assert!(spec.description.contains("api=exists-batch-v1"));
                        }
                        AotOutput::Span => {
                            assert!(exists_batch.is_none());
                            assert!(matches!(
                                span_fill,
                                Some(PreparedSpanFillFactory::Compiled(_))
                            ));
                            assert!(spec.description.contains("api=span-fill-v1"));
                        }
                    }
                }
                BackendFactory::Native {
                    fill, exists_batch, ..
                } => {
                    assert!(spec.description.contains("route=direct-native"));
                    match spec.output {
                        AotOutput::Exists => {
                            assert!(fill.is_none());
                            if exists_batch.is_some() {
                                assert!(spec.description.contains("api=direct-exists-batch-v1"));
                                assert!(
                                    spec.description
                                        .contains("bulk=native-direct-trusted-full-window-loop")
                                );
                            } else {
                                // A direct ordinary entry does not imply that
                                // its additive batch lowering is available.
                                // Context-sensitive and other unsupported
                                // cores retain the exact scalar entry and
                                // advertise the closed per-haystack route.
                                assert!(spec.description.contains("api=per-haystack"));
                                assert!(spec.description.contains("bulk=none"));
                            }
                        }
                        AotOutput::Span => {
                            assert!(exists_batch.is_none());
                            assert!(fill.is_some());
                            let direct_fill =
                                spec.description.contains("api=direct-span-fill-v1");
                            let rust_fill =
                                spec.description.contains("api=rust-span-fill");
                            assert_ne!(direct_fill, rust_fill);
                            if direct_fill {
                                let generic = spec
                                    .description
                                    .contains("bulk=native-direct-trusted-core-loop");
                                let continuous = spec
                                    .description
                                    .contains("bulk=native-continuous-complete-dfa-fill-v1");
                                assert_ne!(generic, continuous);
                            } else {
                                assert!(spec.description.contains("bulk=none"));
                            }
                        }
                    }
                }
                BackendFactory::Runtime(_) => {
                    assert!(spec.description.contains("route=portable-runtime"));
                    assert!(spec.description.contains("bulk=none"));
                }
            }
        }
        assert!(fast > 0, "test registry must contain a Fast entry");
        assert_eq!(
            fast,
            fast_runtime_bulk + fast_native_prepared_loop,
            "Fast prepared bulk strategy census did not cover every entry"
        );
        assert!(prepared > 0, "test registry must contain a prepared entry");
        assert_eq!(
            optimizing_prepared,
            optimizing_runtime_bulk + optimizing_native_prepared_loop,
            "Optimizing prepared bulk strategy census did not cover every prepared entry"
        );
        let has_mixed_strategy_fixture = [
            "PM_RESUME",
            r"\b(?:PM_RESUME)\b",
            r"\w{5}\s+\w{5}\s+\w{5}\s+\w{5}\s+\w{5}",
        ]
        .into_iter()
        .all(|pattern| generated::SPECS.iter().any(|spec| spec.pattern == pattern));
        if has_mixed_strategy_fixture {
            assert!(fast_runtime_bulk > 0);
            assert!(fast_native_prepared_loop > 0);
            assert!(optimizing_runtime_bulk > 0);
            assert!(optimizing_native_prepared_loop > 0);
        }
        if generated::SPECS
            .iter()
            .any(|spec| spec.mode == AotMode::Optimizing && spec.pattern == r"\b(?:PM_RESUME)\b")
        {
            assert!(
                optimizing_runtime_bulk > 0,
                "Optimizing fallback silently bypassed its runtime-owned bulk entry"
            );
        }
    }

    #[test]
    fn generated_prepared_factories_carry_authenticated_prepare_capabilities() {
        if generated::BUILD_VARIANT_POLICY == "optimizing-grep-count" {
            assert!(generated::SPECS.is_empty());
            return;
        }
        let mut v15_factories = 0;
        for spec in generated::SPECS {
            let BackendFactory::Prepared {
                span_fill,
                exists_batch,
                required_prepare_capabilities,
                ..
            } = spec.backend
            else {
                continue;
            };
            let ordered_nfa = spec.description.contains("bulk=native-ordered-nfa-loop");
            match required_prepare_capabilities {
                0 => assert!(
                    !ordered_nfa,
                    "Ordered-NFA factory lost its required V15 bit: {}",
                    spec.description
                ),
                PREPARE_CAPABILITY_ORDERED_NFA_V15 => {
                    v15_factories += 1;
                    assert!(ordered_nfa, "V15 bit attached to non-Ordered-NFA factory");
                    assert_eq!(spec.output, AotOutput::Span);
                    assert!(matches!(
                        span_fill,
                        Some(PreparedSpanFillFactory::Compiled(_))
                    ));
                    assert!(exists_batch.is_none());
                    AotMatcher::new(spec.mode, spec.output, spec.pattern, spec.case_insensitive)
                        .expect("authenticated generated V15 factory must prepare through V3");
                }
                other => panic!("generated factory carries unknown capability mask {other:#x}"),
            }
        }
        if generated::BUILD_VARIANT_POLICY == "all" {
            assert!(
                v15_factories > 0,
                "default public registry must exercise real V3 preparation"
            );
        }
    }

    #[test]
    fn public_generated_ordered_nfa_v15_span_fill_executes_end_to_end() {
        const PATTERN: &str = r"\b(?:PM_RESUME)\b";
        if generated::BUILD_VARIANT_POLICY != "all" {
            return;
        }
        let pattern_is_selected = generated::SPECS
            .iter()
            .any(|spec| spec.pattern == PATTERN && !spec.case_insensitive);
        if !pattern_is_selected {
            // External manifests are permitted and need not contain the
            // package's public Ordered-NFA fixture.
            return;
        }
        let spec = generated::SPECS
            .iter()
            .find(|spec| {
                spec.pattern == PATTERN
                    && !spec.case_insensitive
                    && spec.output == AotOutput::Span
                    && matches!(
                        spec.backend,
                        BackendFactory::Prepared {
                            required_prepare_capabilities: PREPARE_CAPABILITY_ORDERED_NFA_V15,
                            span_fill: Some(PreparedSpanFillFactory::Compiled(_)),
                            exists_batch: None,
                            ..
                        }
                    )
            })
            .expect("public Ordered-NFA fixture must retain its authenticated V15 Span-fill");
        assert!(spec.description.contains("bulk=native-ordered-nfa-loop"));
        assert!(spec.description.contains("api=span-fill-v1"));

        let haystack = b"xx PM_RESUME yy PM_RESUME";
        let mut matcher = AotMatcher::new(spec.mode, AotOutput::Span, PATTERN, false)
            .expect("prepare public generated V15 matcher");
        let all = matcher
            .find_iter(haystack)
            .expect("compiled public Span-fill")
            .map(|matched| matched.expect("compiled public span").range())
            .collect::<Vec<_>>();
        assert_eq!(all, [3..12, 16..25]);

        let offset = matcher
            .find_iter_at(haystack, 4)
            .expect("compiled public offset Span-fill")
            .map(|matched| matched.expect("compiled public offset span").range())
            .collect::<Vec<_>>();
        assert_eq!(offset, [16..25]);
    }

    #[test]
    fn generated_grep_count_registry_is_opt_in_authenticated_and_aggregate_only() {
        assert_eq!(
            generated::BUILD_GREP_COUNT_ADMITTED_COUNT,
            generated::GREP_COUNT_SPECS.len()
        );
        if generated::BUILD_VARIANT_POLICY != "optimizing-grep-count" {
            assert!(generated::GREP_COUNT_SPECS.is_empty());
            return;
        }

        assert!(generated::SPECS.is_empty());
        assert!(generated::GREP_COUNT_SPECS.len() <= generated::BUILD_PATTERN_COUNT);
        for spec in generated::GREP_COUNT_SPECS {
            assert_eq!(spec.mode, AotMode::Optimizing);
            assert!(
                spec.description.contains(
                    "route=compiled-prepared,api=grep-count-v1,aggregate=native-fused"
                ),
                "{}",
                spec.description
            );
            assert!(spec.description.contains(
                "proof=exact-finite-nonempty-nonnullable-assertion-free-crlf-free"
            ));
            assert!(
                AotGrepCountFactory::select(
                    AotMode::Optimizing,
                    spec.pattern,
                    spec.case_insensitive,
                )
                .is_some()
            );
            assert!(
                AotGrepCountFactory::select(AotMode::Fast, spec.pattern, spec.case_insensitive)
                    .is_none()
            );

            // SAFETY: the authenticated entry must reject the invalid handle
            // before inspecting any deliberately invalid remaining argument.
            let status = unsafe {
                (spec.entry)(
                    FreAotRegexExclusiveHandleV1::INVALID,
                    std::ptr::null(),
                    usize::MAX,
                    std::ptr::null_mut(),
                )
            };
            assert_eq!(status, fre_aot_regex_runtime::STATUS_INVALID_HANDLE);
        }

        if let Some(factory) =
            AotGrepCountFactory::select(AotMode::Optimizing, "PM_RESUME", false)
        {
            assert_eq!(factory.description(), {
                generated::GREP_COUNT_SPECS
                    .iter()
                    .find(|spec| spec.pattern == "PM_RESUME" && !spec.case_insensitive)
                    .expect("selected public fixture")
                    .description
            });
            let mut counter = factory.prepare().expect("prepare public GrepCount fixture");
            assert_eq!(counter.description(), factory.description());
            for (haystack, expected) in [
                (b"".as_slice(), 0),
                (b"unrelated".as_slice(), 0),
                (b"PM_RESUME".as_slice(), 1),
                (b"xPM_RESUMEx".as_slice(), 1),
                (b"PM_RESUME\nmiss\nPM_RESUME\n".as_slice(), 2),
                (b"PM_RESUME\r\nmiss\r\nPM_RESUME".as_slice(), 2),
            ] {
                assert_eq!(
                    counter
                        .count_matching_lines(haystack)
                        .expect("native GrepCount call"),
                    expected
                );
            }
        }
        if let Some(factory) =
            AotGrepCountFactory::select(AotMode::Optimizing, "PM_RESUME", true)
        {
            let mut counter = factory
                .prepare()
                .expect("prepare public case-insensitive GrepCount fixture");
            assert_eq!(
                counter
                    .count_matching_lines(b"pm_resume\nmiss\nPm_ReSuMe")
                    .expect("case-insensitive native GrepCount call"),
                2
            );
        }
    }

    #[test]
    fn generated_pruned_registry_rejects_absent_variant_clearly() {
        if generated::BUILD_VARIANT_POLICY != "optimizing-exists" {
            return;
        }
        let selected = generated::SPECS
            .first()
            .expect("nonempty generated registry");
        let error = AotMatcher::new(
            AotMode::Fast,
            AotOutput::Span,
            selected.pattern,
            selected.case_insensitive,
        )
        .expect_err("pruned Fast+Span variant must be absent");
        assert!(error.contains("requested AOT variant was not emitted"));
        assert!(error.contains("build_variant_policy=optimizing-exists"));
        assert!(error.contains("available_variants=Optimizing+Exists"));
    }

    #[test]
    fn compiled_prepared_bulk_invalid_handle_precedes_other_validation() {
        if generated::BUILD_VARIANT_POLICY == "optimizing-grep-count" {
            return;
        }
        let mut compiled_calls = 0;
        let mut saw_runtime_span = false;
        let mut saw_runtime_exists = false;
        let mut saw_native_span = false;
        let mut saw_native_exists = false;
        for spec in generated::SPECS {
            let BackendFactory::Prepared {
                span_fill,
                exists_batch,
                ..
            } = spec.backend
            else {
                continue;
            };
            let runtime_bulk = spec.description.contains("bulk=runtime-helper");
            let native_bulk = [
                "bulk=native-prepared-loop",
                "bulk=native-trusted-preflight-loop",
                "bulk=native-trusted-preflight-runtime-bulk",
                "bulk=native-frozen-loop",
                "bulk=native-ordered-nfa-loop",
            ]
            .into_iter()
            .filter(|bulk| spec.description.contains(bulk))
            .count()
                == 1;
            assert_ne!(runtime_bulk, native_bulk, "{}", spec.description);
            let status = match (spec.output, span_fill, exists_batch) {
                (AotOutput::Span, Some(PreparedSpanFillFactory::Compiled(fill)), None) => {
                    compiled_calls += 1;
                    if runtime_bulk {
                        saw_runtime_span = true;
                    } else {
                        saw_native_span = true;
                    }
                    // SAFETY: the compiled ABI promises to reject an invalid
                    // exclusive handle before inspecting any remaining raw
                    // argument. Deliberately invalid arguments make that
                    // precedence observable in the host-linked object.
                    unsafe {
                        fill(
                            FreAotRegexExclusiveHandleV1::INVALID,
                            std::ptr::null(),
                            usize::MAX,
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                            usize::MAX,
                            std::ptr::null_mut(),
                        )
                    }
                }
                (AotOutput::Exists, None, Some(batch)) => {
                    compiled_calls += 1;
                    if runtime_bulk {
                        saw_runtime_exists = true;
                    } else {
                        saw_native_exists = true;
                    }
                    // SAFETY: as above, no pointer or extent after the invalid
                    // handle may be inspected by the compiler-produced entry.
                    unsafe {
                        batch(
                            FreAotRegexExclusiveHandleV1::INVALID,
                            std::ptr::null(),
                            usize::MAX,
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                        )
                    }
                }
                _ => continue,
            };
            assert_eq!(
                status,
                fre_aot_regex_runtime::STATUS_INVALID_HANDLE,
                "invalid-handle precedence changed for {}",
                spec.description
            );
        }
        let has_mixed_strategy_fixture = [
            "PM_RESUME",
            r"\b(?:PM_RESUME)\b",
            r"\w{5}\s+\w{5}\s+\w{5}\s+\w{5}\s+\w{5}",
        ]
        .into_iter()
        .all(|pattern| generated::SPECS.iter().any(|spec| spec.pattern == pattern));
        if compiled_calls == 0 {
            assert!(
                !has_mixed_strategy_fixture,
                "default mixed-strategy fixture has no compiled bulk entry"
            );
            return;
        }
        if has_mixed_strategy_fixture {
            assert!(saw_runtime_span || saw_native_span);
            assert!(saw_runtime_exists || saw_native_exists);
            assert!(saw_runtime_span || saw_runtime_exists);
            assert!(saw_native_span || saw_native_exists);
        }
    }

    #[test]
    fn compiled_prepared_fast_finds_dense_matches_across_refills() {
        let pattern = "PM_RESUME";
        if !generated::SPECS.iter().any(|spec| {
            spec.mode == AotMode::Fast
                && spec.output == AotOutput::Span
                && spec.pattern == pattern
                && !spec.case_insensitive
        }) {
            return;
        }

        let mut matcher = AotMatcher::new(AotMode::Fast, AotOutput::Span, pattern, false)
            .expect("prepare Fast Span entry");
        assert!(matcher.description().contains("route=compiled-prepared"));
        assert!(matcher.description().contains("api=span-fill-v1"));
        assert!(
            matcher.description().contains("bulk=runtime-helper")
                || matcher.description().contains("bulk=native-prepared-loop")
                || matcher.description().contains("bulk=native-frozen-loop")
        );
        let haystack = pattern
            .as_bytes()
            .repeat(NATIVE_SPAN_BUFFER_CAPACITY * 2 + 2);
        let spans = matcher
            .find_iter(&haystack)
            .expect("compiled-prepared iterator")
            .map(|matched| matched.expect("compiled-prepared match").range())
            .collect::<Vec<_>>();
        assert_eq!(spans.len(), NATIVE_SPAN_BUFFER_CAPACITY * 2 + 2);
        assert_eq!(spans.first(), Some(&(0..pattern.len())));
        assert_eq!(
            spans.last(),
            Some(&((haystack.len() - pattern.len())..haystack.len()))
        );

        let empty = matcher
            .find_iter(b"")
            .expect("compiled-prepared empty iterator")
            .collect::<Result<Vec<_>, _>>()
            .expect("compiled-prepared empty search");
        assert!(empty.is_empty());

        let mut exists = AotMatcher::new(AotMode::Fast, AotOutput::Exists, pattern, false)
            .expect("prepare frozen-loop Exists entry");
        assert!(exists.description().contains("bulk=native-frozen-loop"));
        let valid = pattern.as_bytes();
        let invalid = b"PM_PAUSE".as_slice();
        let empty = b"".as_slice();
        let lines = (0..EXISTS_BATCH_CAPACITY)
            .map(|index| match index % 3 {
                0 => valid,
                1 => invalid,
                _ => empty,
            })
            .collect::<Vec<_>>();
        let mut outcomes = [false; EXISTS_BATCH_CAPACITY];
        exists
            .is_match_batch(&lines, &mut outcomes)
            .expect("frozen-loop Exists batch");
        for (index, matched) in outcomes.into_iter().enumerate() {
            assert_eq!(matched, index % 3 == 0);
        }
    }

    #[test]
    fn generated_direct_span_fill_matches_scalar_and_refills_dense_inputs() {
        const PATTERN: &str = "Sherlock Holmes";
        if generated::BUILD_VARIANT_POLICY != "all" {
            return;
        }
        if !generated::SPECS
            .iter()
            .any(|spec| spec.pattern == PATTERN && !spec.case_insensitive)
        {
            // External manifests need not contain the package's public direct
            // Span-fill fixture.
            return;
        }
        let spec = generated::SPECS
            .iter()
            .find(|spec| {
                spec.mode == AotMode::Optimizing
                    && spec.output == AotOutput::Span
                    && spec.pattern == PATTERN
                    && !spec.case_insensitive
            })
            .expect("public direct Span fixture must have an Optimizing Span row");
        assert!(matches!(
            spec.backend,
            BackendFactory::Native {
                fill: Some(_),
                exists_batch: None,
                ..
            }
        ));
        assert!(spec.description.contains("api=direct-span-fill-v1"));
        assert!(
            spec.description
                .contains("bulk=native-continuous-complete-dfa-fill-v1")
        );

        let repeats = NATIVE_SPAN_BUFFER_CAPACITY * 2 + 2;
        let haystack = PATTERN.as_bytes().repeat(repeats);
        let expected = (0..repeats)
            .map(|index| {
                let start = index * PATTERN.len();
                start..start + PATTERN.len()
            })
            .collect::<Vec<_>>();
        let mut matcher =
            AotMatcher::new(AotMode::Optimizing, AotOutput::Span, PATTERN, false)
                .expect("construct public direct Span matcher");
        let spans = matcher
            .find_iter(&haystack)
            .expect("public direct Span iterator")
            .map(|matched| matched.expect("public direct span").range())
            .collect::<Vec<_>>();
        assert_eq!(spans, expected);
        assert_eq!(
            matcher
                .find_at(&haystack, 1)
                .expect("public scalar offset search")
                .expect("public scalar offset match")
                .range(),
            expected[1]
        );
        assert_eq!(
            matcher
                .find_iter_at(&haystack, 1)
                .expect("public direct offset iterator")
                .map(|matched| matched.expect("public direct offset span").range())
                .collect::<Vec<_>>(),
            expected[1..]
        );
        assert!(
            matcher
                .find_iter_at(&haystack, haystack.len())
                .expect("public direct EOF iterator")
                .next()
                .is_none()
        );
        assert!(
            matcher
                .find_iter(b"")
                .expect("public direct empty iterator")
                .next()
                .is_none()
        );
    }

    #[test]
    fn generated_direct_span_fill_raw_abi_validates_and_supports_progress_probes() {
        for &(fill, _) in generated::DIRECT_SPAN_FILL_ENTRIES {
            let mut state = NativeIterState::initial_at(0, 0).expect("empty initial state");
            let mut written = usize::MAX;
            let status = unsafe {
                fill(
                    b"".as_ptr(),
                    0,
                    &raw mut state,
                    std::ptr::null_mut(),
                    0,
                    &raw mut written,
                )
            };
            assert_eq!(status, 1, "unfinished zero-capacity probe must continue");
            assert_eq!(written, 0);
            assert!(!state.finished());

            state.flags = ITER_FINISHED;
            written = usize::MAX;
            let status = unsafe {
                fill(
                    b"".as_ptr(),
                    0,
                    &raw mut state,
                    std::ptr::null_mut(),
                    0,
                    &raw mut written,
                )
            };
            assert_eq!(status, 0, "finished zero-capacity probe must terminate");
            assert_eq!(written, 0);

            let mut pending = NativeIterState {
                next_start: 0,
                last_match_end: 0,
                flags: ITER_HAS_LAST | ITER_PENDING_EMPTY,
                reserved: 0,
            };
            let pending_before_probe = pending;
            written = usize::MAX;
            let status = unsafe {
                fill(
                    b"".as_ptr(),
                    0,
                    &raw mut pending,
                    std::ptr::null_mut(),
                    0,
                    &raw mut written,
                )
            };
            assert_eq!(status, 1, "zero capacity must not consume pending progress");
            assert_eq!(written, 0);
            assert_eq!(pending, pending_before_probe);

            let mut pending_output = MaybeUninit::<AbiResult>::uninit();
            written = usize::MAX;
            let status = unsafe {
                fill(
                    b"".as_ptr(),
                    0,
                    &raw mut pending,
                    pending_output.as_mut_ptr(),
                    1,
                    &raw mut written,
                )
            };
            assert_eq!(status, 0, "pending progress at EOF must finish");
            assert_eq!(written, 0);
            assert!(pending.has_last_match());
            assert!(!pending.pending_empty_progress());
            assert!(pending.finished());

            let mut invalid_state = NativeIterState {
                next_start: 0,
                last_match_end: 0,
                flags: 8,
                reserved: 0,
            };
            written = usize::MAX;
            assert_eq!(
                unsafe {
                    fill(
                        b"".as_ptr(),
                        0,
                        &raw mut invalid_state,
                        std::ptr::null_mut(),
                        0,
                        &raw mut written,
                    )
                },
                2,
                "unknown state flags must fail closed"
            );

            let mut valid_state = NativeIterState::initial_at(0, 0).expect("empty initial state");
            assert_eq!(
                unsafe {
                    fill(
                        std::ptr::null(),
                        0,
                        &raw mut valid_state,
                        std::ptr::null_mut(),
                        0,
                        &raw mut written,
                    )
                },
                2,
                "null haystack must fail even at zero length"
            );
        }
    }

    #[test]
    fn generated_continuous_exact_span_fill_raw_abi_refills_and_resumes() {
        const PATTERN: &[u8] = b"Sherlock Holmes";
        let Some(fill) = generated::PUBLIC_CONTINUOUS_SPAN_FILL_ENTRY else {
            return;
        };

        let exact_capacity_haystack = PATTERN.repeat(2);
        let mut state = NativeIterState::initial_at(0, exact_capacity_haystack.len())
            .expect("exact-capacity initial state");
        let mut output = [MaybeUninit::<AbiResult>::uninit(); 2];
        let mut written = usize::MAX;
        let status = unsafe {
            fill(
                exact_capacity_haystack.as_ptr(),
                exact_capacity_haystack.len(),
                &raw mut state,
                output.as_mut_ptr().cast::<AbiResult>(),
                output.len(),
                &raw mut written,
            )
        };
        assert_eq!(status, 1, "an exact-capacity prefix requires a terminal probe");
        assert_eq!(written, output.len());
        assert!(!state.finished());
        for (index, slot) in output.iter().enumerate() {
            let result = unsafe { slot.assume_init_ref() };
            let start = index * PATTERN.len();
            assert_eq!((result.start, result.end), (start, start + PATTERN.len()));
        }
        written = usize::MAX;
        let status = unsafe {
            fill(
                exact_capacity_haystack.as_ptr(),
                exact_capacity_haystack.len(),
                &raw mut state,
                output.as_mut_ptr().cast::<AbiResult>(),
                output.len(),
                &raw mut written,
            )
        };
        assert_eq!(status, 0);
        assert_eq!(written, 0);
        assert!(state.finished());

        let dense_repeats = 7;
        let dense_haystack = PATTERN.repeat(dense_repeats);
        let sentinel = AbiResult {
            start: usize::MAX - 1,
            end: usize::MAX,
        };
        let mut state = NativeIterState::initial_at(0, dense_haystack.len())
            .expect("dense initial state");
        let mut spans = Vec::new();
        let mut calls = 0;
        loop {
            calls += 1;
            let mut output = [MaybeUninit::new(sentinel); 2];
            written = usize::MAX;
            let status = unsafe {
                fill(
                    dense_haystack.as_ptr(),
                    dense_haystack.len(),
                    &raw mut state,
                    output.as_mut_ptr().cast::<AbiResult>(),
                    output.len(),
                    &raw mut written,
                )
            };
            assert!(written <= output.len());
            for slot in &output[..written] {
                let result = unsafe { slot.assume_init_ref() };
                spans.push(result.start..result.end);
            }
            for slot in &output[written..] {
                assert_eq!(unsafe { slot.assume_init_ref() }, &sentinel);
            }
            if status == 0 {
                assert!(state.finished());
                break;
            }
            assert_eq!(status, 1);
            assert_eq!(written, output.len());
            assert!(!state.finished());
        }
        assert!(calls > 2, "dense exact fixture must exercise multiple refills");
        assert_eq!(
            spans,
            (0..dense_repeats)
                .map(|index| {
                    let start = index * PATTERN.len();
                    start..start + PATTERN.len()
                })
                .collect::<Vec<_>>()
        );

        let mut state = NativeIterState::initial_at(1, dense_haystack.len())
            .expect("positive-offset state");
        let mut output = [MaybeUninit::<AbiResult>::uninit(); 1];
        written = usize::MAX;
        let status = unsafe {
            fill(
                dense_haystack.as_ptr(),
                dense_haystack.len(),
                &raw mut state,
                output.as_mut_ptr().cast::<AbiResult>(),
                output.len(),
                &raw mut written,
            )
        };
        assert_eq!(status, 1);
        assert_eq!(written, 1);
        let result = unsafe { output[0].assume_init_ref() };
        assert_eq!((result.start, result.end), (PATTERN.len(), PATTERN.len() * 2));

        let mut state = NativeIterState {
            next_start: 0,
            last_match_end: 0,
            flags: ITER_HAS_LAST | ITER_PENDING_EMPTY,
            reserved: 0,
        };
        written = usize::MAX;
        let status = unsafe {
            fill(
                dense_haystack.as_ptr(),
                dense_haystack.len(),
                &raw mut state,
                output.as_mut_ptr().cast::<AbiResult>(),
                output.len(),
                &raw mut written,
            )
        };
        assert_eq!(status, 1);
        assert_eq!(written, 1);
        assert!(!state.pending_empty_progress());
        let result = unsafe { output[0].assume_init_ref() };
        assert_eq!((result.start, result.end), (PATTERN.len(), PATTERN.len() * 2));
    }

    fn assert_continuous_span_fill_matches_trusted_core_generic_state_for_state(
        pattern: &str,
        fill: DirectSpanFill,
    ) {
        let spec = generated::SPECS
            .iter()
            .find(|spec| {
                spec.mode == AotMode::Optimizing
                    && spec.output == AotOutput::Span
                    && spec.pattern == pattern
                    && !spec.case_insensitive
            })
            .expect("public continuous Span fixture");
        let search = match spec.backend {
            BackendFactory::Native { search, .. } => search,
            _ => panic!("public continuous Span fixture lost its direct ordinary entry"),
        };
        let literal = pattern.as_bytes();
        let dense = literal.repeat(7);
        let exact_capacity = literal.repeat(2);
        let mut false_survivor = literal.to_vec();
        false_survivor[0] ^= 1;
        let mut repeated_near_miss = false_survivor.repeat(257);
        repeated_near_miss.extend_from_slice(literal);
        let scenarios = [
            (
                dense.as_slice(),
                NativeIterState::initial_at(0, dense.len()).expect("dense initial state"),
                2,
            ),
            (
                dense.as_slice(),
                NativeIterState::initial_at(1, dense.len()).expect("offset initial state"),
                3,
            ),
            (
                dense.as_slice(),
                NativeIterState {
                    next_start: 0,
                    last_match_end: 0,
                    flags: ITER_HAS_LAST | ITER_PENDING_EMPTY,
                    reserved: 0,
                },
                2,
            ),
            (
                exact_capacity.as_slice(),
                NativeIterState::initial_at(0, exact_capacity.len())
                    .expect("exact-capacity initial state"),
                2,
            ),
            (
                repeated_near_miss.as_slice(),
                NativeIterState::initial_at(0, repeated_near_miss.len())
                    .expect("near-miss initial state"),
                2,
            ),
        ];
        for (haystack, initial, capacity) in scenarios {
            let mut continuous_state = initial;
            let mut generic_state = initial;
            let mut refills = 0;
            loop {
                refills += 1;
                assert!(refills <= 16, "Span-fill differential did not terminate");
                let mut continuous_output = vec![MaybeUninit::<AbiResult>::uninit(); capacity];
                let mut generic_output = vec![MaybeUninit::<AbiResult>::uninit(); capacity];
                let continuous = fill_direct_spans(
                    fill,
                    haystack,
                    &mut continuous_state,
                    &mut continuous_output,
                );
                let generic = unsafe {
                    fill_native_spans(
                        haystack,
                        &mut generic_state,
                        &mut generic_output,
                        |haystack, start, result| {
                            search(
                                haystack.as_ptr(),
                                haystack.len(),
                                start,
                                haystack.len(),
                                result,
                            )
                        },
                    )
                };
                assert_eq!(continuous.written, generic.written);
                assert_eq!(continuous.error, generic.error);
                assert_eq!(continuous_state, generic_state);
                for index in 0..continuous.written {
                    assert_eq!(
                        unsafe { continuous_output[index].assume_init_ref() },
                        unsafe { generic_output[index].assume_init_ref() },
                    );
                }
                if continuous.error.is_some() || continuous_state.finished() {
                    break;
                }
                assert_eq!(continuous.written, capacity);
            }
            if capacity == 2 && haystack.len() == dense.len() && initial.next_start == 0 {
                assert!(refills > 2, "dense differential must cross multiple refills");
            }
        }
    }

    #[test]
    fn generated_continuous_span_fill_matches_trusted_core_generic_state_for_state() {
        let Some(fill) = generated::PUBLIC_CONTINUOUS_SPAN_FILL_ENTRY else {
            return;
        };
        assert_continuous_span_fill_matches_trusted_core_generic_state_for_state(
            "Sherlock Holmes",
            fill,
        );
    }

    #[test]
    fn generated_long_continuous_span_fill_matches_trusted_core_generic_state_for_state() {
        let Some(fill) = generated::PUBLIC_LONG_CONTINUOUS_SPAN_FILL_ENTRY else {
            return;
        };
        assert_continuous_span_fill_matches_trusted_core_generic_state_for_state(
            "Шерлок Холмс",
            fill,
        );
    }

    #[test]
    fn compiled_prepared_fast_trusted_hybrid_matches_short_and_large_inputs() {
        let pattern = r"\w{5}\s+\w{5}\s+\w{5}\s+\w{5}\s+\w{5}";
        if !generated::SPECS.iter().any(|spec| {
            spec.mode == AotMode::Fast
                && spec.output == AotOutput::Span
                && spec.pattern == pattern
                && !spec.case_insensitive
        }) {
            return;
        }

        let unit = b"aaaaa bbbbb ccccc ddddd eeeee";
        let mut span = AotMatcher::new(AotMode::Fast, AotOutput::Span, pattern, false)
            .expect("prepare trusted-hybrid Span entry");
        assert!(
            span.description()
                .contains("bulk=native-trusted-preflight-runtime-bulk")
        );
        for repeats in [2, 160] {
            let haystack = unit.repeat(repeats);
            let spans = span
                .find_iter(&haystack)
                .expect("trusted-hybrid iterator")
                .map(|matched| matched.expect("trusted-hybrid match").range())
                .collect::<Vec<_>>();
            assert_eq!(spans.len(), repeats);
            for (index, range) in spans.into_iter().enumerate() {
                let start = index * unit.len();
                assert_eq!(range, start..start + unit.len());
            }
        }
        assert!(
            span.find_iter(b"")
                .expect("trusted-hybrid empty iterator")
                .collect::<Result<Vec<_>, _>>()
                .expect("trusted-hybrid empty search")
                .is_empty()
        );
        let mut exists = AotMatcher::new(AotMode::Fast, AotOutput::Exists, pattern, false)
            .expect("prepare trusted-preflight Exists entry");
        assert!(
            exists
                .description()
                .contains("bulk=native-trusted-preflight-loop")
        );
        let long_unit = b"aaaaa    bbbbb    ccccc    ddddd    eeeee";
        let invalid = b"aaaaa bbbbb";
        let empty = b"";
        for (line, expected) in [
            (long_unit.as_slice(), true),
            (invalid.as_slice(), false),
            (empty.as_slice(), false),
        ] {
            let mut one = [false; 1];
            exists
                .is_match_batch(&[line], &mut one)
                .expect("trusted-preflight Exists single");
            assert_eq!(one, [expected]);
        }
        let lines = (0..EXISTS_BATCH_CAPACITY)
            .map(|index| match index % 3 {
                0 => long_unit.as_slice(),
                1 => invalid.as_slice(),
                _ => empty.as_slice(),
            })
            .collect::<Vec<_>>();
        let mut outcomes = [false; EXISTS_BATCH_CAPACITY];
        exists
            .is_match_batch(&lines, &mut outcomes)
            .expect("trusted-preflight Exists batch");
        for (index, matched) in outcomes.into_iter().enumerate() {
            assert_eq!(matched, index % 3 == 0);
        }

        for length in [0_usize, 31, 32, 33] {
            let matching = if length == 0 {
                Vec::new()
            } else {
                format!("aaaaa{}bbbbb ccccc ddddd eeeee", " ".repeat(length - 28)).into_bytes()
            };
            assert_eq!(matching.len(), length);
            let mut nonmatching = matching.clone();
            if let Some(first) = nonmatching.first_mut() {
                *first = b'!';
            }
            for (haystack, expected) in [(&matching, length != 0), (&nonmatching, false)] {
                let mut span = AotMatcher::new(AotMode::Fast, AotOutput::Span, pattern, false)
                    .expect("prepare boundary Span entry");
                let spans = span
                    .find_iter(haystack)
                    .expect("boundary Span iterator")
                    .map(|matched| matched.expect("boundary Span match").range())
                    .collect::<Vec<_>>();
                let expected_spans = expected
                    .then_some(0..length)
                    .into_iter()
                    .collect::<Vec<_>>();
                assert_eq!(spans, expected_spans);

                let mut exists = AotMatcher::new(AotMode::Fast, AotOutput::Exists, pattern, false)
                    .expect("prepare boundary Exists entry");
                let mut outcome = [false; 1];
                exists
                    .is_match_batch(&[haystack], &mut outcome)
                    .expect("boundary Exists batch");
                assert_eq!(outcome, [expected]);
            }
        }
    }

    #[test]
    fn compiled_prepared_optimizing_fallback_finds_nonempty_match() {
        let pattern = r"\b(?:PM_RESUME)\b";
        if !generated::SPECS.iter().any(|spec| {
            spec.mode == AotMode::Optimizing
                && spec.output == AotOutput::Span
                && spec.pattern == pattern
                && !spec.case_insensitive
        }) {
            return;
        }

        let mut exists = AotMatcher::new(AotMode::Optimizing, AotOutput::Exists, pattern, false)
            .expect("prepare Optimizing Exists fallback");
        assert!(exists.description().contains("route=compiled-prepared"));
        assert!(exists.description().contains("api=exists-batch-v1"));
        assert!(exists.description().contains("bulk=runtime-helper"));
        assert!(exists.is_match(b"PM_RESUME").expect("Exists search"));

        let mut span = AotMatcher::new(AotMode::Optimizing, AotOutput::Span, pattern, false)
            .expect("prepare Optimizing Span fallback");
        assert!(span.description().contains("route=compiled-prepared"));
        assert!(span.description().contains("api=span-fill-v1"));
        assert!(
            span.description().contains("bulk=runtime-helper")
                || span.description().contains("bulk=native-ordered-nfa-loop")
        );
        assert_eq!(
            span.find(b"PM_RESUME")
                .expect("Span search")
                .expect("word match")
                .range(),
            0..9
        );
    }
}
