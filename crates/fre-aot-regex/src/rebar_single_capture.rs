//! Cardinality-authenticated single-pattern Rebar capture AOT.
//!
//! This route is deliberately separate from [`crate::compile_captures`]. A
//! Rebar meta profile describes an ordered `build_many` constructor, while the
//! native capture V1 result has no pattern-id field. The request below can only
//! be constructed after an exact one-element manifest has been proved. Its
//! successful artifact is always a selected, helper-free native route; an
//! unsupported shape is an error instead of a replay or negative artifact.

use core::fmt;

use fre_syntax::{RustOptions, RustProfile};
use sha2::{Digest, Sha256};

use crate::{
    Architecture, CaptureCompileError, CaptureCompileLimits, CaptureCompileRequest, CaptureLevel,
    CaptureOnePassDisposition, CompileMode, CompiledModule, NativeCaptureAotDeclineV1,
    NativeCaptureAotError, NativeCaptureAotLimitsV1, NativeCaptureAotReceiptV1,
    NativeCaptureAotStrategyV1, NativeCaptureBundleV1View, NativeCaptureDescriptorV1,
    NativeParticipationAotArtifactV1, NativeParticipationAotDeclineV1,
    NativeParticipationAotErrorV1, NativeParticipationAotLimitsV1, NativeParticipationAotReceiptV1,
    NativeParticipationAotStrategyV1, ObjectError, ObjectFormat, OnePassCaptureBuildError,
    OnePassCaptureBuildFailure, OutputContract, Target, emit_object,
};

pub const REBAR_SINGLE_CAPTURE_AOT_V1_SOURCE_CARDINALITY: usize = 1;
pub const REBAR_SINGLE_CAPTURE_AOT_V1_IDENTITY_DOMAIN: &[u8] =
    b"fre-aot-regex/rebar-single-capture-aot-v1\0";
pub const REBAR_SINGLE_CAPTURE_PARTICIPATION_AOT_V1_IDENTITY_DOMAIN: &[u8] =
    b"fre-aot-regex/rebar-single-capture-participation-aot-v1\0";
pub const REBAR_SINGLE_CAPTURE_REDUCER_AOT_V1_IDENTITY_DOMAIN: &[u8] =
    b"fre-aot-regex/rebar-single-capture-reducer-aot-v1\0";

const DIGEST_BYTES: usize = 32;
const REBAR_PROFILE_IDENTITY: &[u8] =
    b"rebar@463d00f31887e84c38467805b9e3122c314b9521/regex-1.12.4/meta-build-many-ordered\0";

/// Exact empty-match iterator obligation for the native capture V1 ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RebarSingleCaptureEmptyProgressV1 {
    /// Advance by one byte after a selected empty match, or fuse at end.
    Byte = 1,
}

/// A manifest did not contain exactly one source expression.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RebarSingleCaptureCardinalityError {
    actual: usize,
}

impl RebarSingleCaptureCardinalityError {
    #[must_use]
    pub const fn actual(self) -> usize {
        self.actual
    }

    #[must_use]
    pub const fn required(self) -> usize {
        REBAR_SINGLE_CAPTURE_AOT_V1_SOURCE_CARDINALITY
    }
}

impl fmt::Display for RebarSingleCaptureCardinalityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Rebar native capture V1 requires exactly one source pattern, got {}",
            self.actual,
        )
    }
}

impl std::error::Error for RebarSingleCaptureCardinalityError {}

/// Complete type-enforced request for one pinned Rebar capture artifact.
#[derive(Clone, Eq, PartialEq)]
pub struct RebarSingleCaptureAotRequestV1 {
    pattern: String,
    target: Target,
    options: RustOptions,
    compile_limits: CaptureCompileLimits,
    native_limits: NativeCaptureAotLimitsV1,
}

impl fmt::Debug for RebarSingleCaptureAotRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RebarSingleCaptureAotRequestV1")
            .field("source_cardinality", &1)
            .field("source_bytes", &self.pattern.len())
            .field("target", &self.target)
            .field("options", &self.options)
            .field("compile_limits", &self.compile_limits)
            .field("native_limits", &self.native_limits)
            .finish_non_exhaustive()
    }
}

impl RebarSingleCaptureAotRequestV1 {
    /// Construct from an array whose length proves source cardinality at the
    /// Rust type boundary.
    #[must_use]
    pub fn new(patterns: [String; 1], target: Target) -> Self {
        let [pattern] = patterns;
        Self {
            pattern,
            target,
            options: RustProfile::rebar_1_12_4().options,
            compile_limits: CaptureCompileLimits::default(),
            native_limits: NativeCaptureAotLimitsV1::default(),
        }
    }

    /// Consume a dynamic manifest only when its exact cardinality is one.
    pub fn try_from_patterns(
        patterns: Vec<String>,
        target: Target,
    ) -> Result<Self, RebarSingleCaptureCardinalityError> {
        let actual = patterns.len();
        let patterns = <[String; 1]>::try_from(patterns)
            .map_err(|_| RebarSingleCaptureCardinalityError { actual })?;
        Ok(Self::new(patterns, target))
    }

    /// Replace the complete pinned Rebar syntax-builder option set.
    #[must_use]
    pub fn options(mut self, options: RustOptions) -> Self {
        self.options = options;
        self
    }

    #[must_use]
    pub fn case_insensitive(mut self, yes: bool) -> Self {
        self.options.case_insensitive = yes;
        self
    }

    #[must_use]
    pub fn unicode(mut self, yes: bool) -> Self {
        self.options.unicode = yes;
        self
    }

    #[must_use]
    pub const fn compile_limits(mut self, limits: CaptureCompileLimits) -> Self {
        self.compile_limits = limits;
        self
    }

    #[must_use]
    pub const fn native_limits(mut self, limits: NativeCaptureAotLimitsV1) -> Self {
        self.native_limits = limits;
        self
    }

    #[must_use]
    pub const fn target(&self) -> Target {
        self.target
    }

    #[must_use]
    pub const fn options_ref(&self) -> &RustOptions {
        &self.options
    }

    #[must_use]
    pub fn source_bytes(&self) -> usize {
        self.pattern.len()
    }
}

/// Immutable cross-layer receipt for a selected single-pattern Rebar route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RebarSingleCaptureAotReceiptV1 {
    source_cardinality: usize,
    source_bytes: usize,
    source_sha256: [u8; DIGEST_BYTES],
    profile: RustProfile,
    target: Target,
    capture_level: CaptureLevel,
    group_count: usize,
    result_slot_count: usize,
    raw_tag_slot_count: usize,
    can_match_empty: bool,
    empty_progress: RebarSingleCaptureEmptyProgressV1,
    selector_sha256: [u8; DIGEST_BYTES],
    capture_sha256: [u8; DIGEST_BYTES],
    plan_sha256: [u8; DIGEST_BYTES],
    selector_object_sha256: [u8; DIGEST_BYTES],
    bundle_sha256: [u8; DIGEST_BYTES],
    export_identity_sha256: [u8; DIGEST_BYTES],
    object_sha256: [u8; DIGEST_BYTES],
    artifact_identity_sha256: [u8; DIGEST_BYTES],
}

impl RebarSingleCaptureAotReceiptV1 {
    #[must_use]
    pub const fn source_cardinality(&self) -> usize {
        self.source_cardinality
    }

    #[must_use]
    pub const fn source_bytes(&self) -> usize {
        self.source_bytes
    }

    #[must_use]
    pub const fn source_sha256(&self) -> [u8; DIGEST_BYTES] {
        self.source_sha256
    }

    #[must_use]
    pub const fn profile(&self) -> &RustProfile {
        &self.profile
    }

    #[must_use]
    pub const fn target(&self) -> Target {
        self.target
    }

    #[must_use]
    pub const fn capture_level(&self) -> CaptureLevel {
        self.capture_level
    }

    /// Result slots, including group zero, supplied to `capture_next_v1`.
    #[must_use]
    pub const fn group_count(&self) -> usize {
        self.group_count
    }

    /// Exact result array length for `capture_next_v1`. Slot zero is group
    /// zero; every other slot participates unless both offsets are
    /// [`crate::NATIVE_CAPTURE_AOT_V1_UNSET`].
    #[must_use]
    pub const fn result_slot_count(&self) -> usize {
        self.result_slot_count
    }

    /// Raw start/end tag words used by the object-local materializer.
    #[must_use]
    pub const fn raw_tag_slot_count(&self) -> usize {
        self.raw_tag_slot_count
    }

    #[must_use]
    pub const fn includes_group_zero(&self) -> bool {
        self.group_count != 0 && self.result_slot_count == self.group_count
    }

    #[must_use]
    pub const fn can_match_empty(&self) -> bool {
        self.can_match_empty
    }

    #[must_use]
    pub const fn empty_progress(&self) -> RebarSingleCaptureEmptyProgressV1 {
        self.empty_progress
    }

    #[must_use]
    pub const fn selector_sha256(&self) -> [u8; DIGEST_BYTES] {
        self.selector_sha256
    }

    #[must_use]
    pub const fn capture_sha256(&self) -> [u8; DIGEST_BYTES] {
        self.capture_sha256
    }

    #[must_use]
    pub const fn plan_sha256(&self) -> [u8; DIGEST_BYTES] {
        self.plan_sha256
    }

    #[must_use]
    pub const fn selector_object_sha256(&self) -> [u8; DIGEST_BYTES] {
        self.selector_object_sha256
    }

    #[must_use]
    pub const fn bundle_sha256(&self) -> [u8; DIGEST_BYTES] {
        self.bundle_sha256
    }

    #[must_use]
    pub const fn export_identity_sha256(&self) -> [u8; DIGEST_BYTES] {
        self.export_identity_sha256
    }

    #[must_use]
    pub const fn object_sha256(&self) -> [u8; DIGEST_BYTES] {
        self.object_sha256
    }

    #[must_use]
    pub const fn artifact_identity_sha256(&self) -> [u8; DIGEST_BYTES] {
        self.artifact_identity_sha256
    }
}

/// Selected, immutable helper-free artifact for one Rebar source pattern.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RebarSingleCaptureAotArtifactV1 {
    native: crate::NativeCaptureAotArtifactV1,
    receipt: RebarSingleCaptureAotReceiptV1,
}

impl RebarSingleCaptureAotArtifactV1 {
    #[must_use]
    pub fn object(&self) -> &[u8] {
        self.native.object()
    }

    #[must_use]
    pub fn bundle(&self) -> &[u8] {
        self.native.bundle()
    }

    #[must_use]
    pub const fn module(&self) -> &CompiledModule {
        self.native.module()
    }

    #[must_use]
    pub const fn descriptor(&self) -> NativeCaptureDescriptorV1 {
        self.native.descriptor()
    }

    #[must_use]
    pub const fn native_receipt(&self) -> NativeCaptureAotReceiptV1 {
        self.native.receipt()
    }

    #[must_use]
    pub const fn receipt(&self) -> &RebarSingleCaptureAotReceiptV1 {
        &self.receipt
    }

    #[must_use]
    pub fn bundle_symbol(&self) -> &str {
        self.native.bundle_symbol()
    }

    #[must_use]
    pub fn selector_entry_symbol(&self) -> &str {
        self.native.selector_entry_symbol()
    }

    #[must_use]
    pub fn capture_next_symbol(&self) -> &str {
        self.native.capture_next_symbol()
    }

    #[must_use]
    pub fn capture_materialize_symbol(&self) -> &str {
        self.native.capture_materialize_symbol()
    }

    /// Recheck profile/cardinality/schema/progress and the complete underlying
    /// native bundle, module route, and object receipt.
    #[must_use]
    pub fn authenticates_receipt(&self) -> bool {
        rebar_single_artifact_authenticates(self)
    }
}

/// Rebar/profile/cardinality closure around one exact-span participation
/// artifact. The embedded native receipt remains authoritative for its sealed
/// bundle, object and exported symbols; this additive receipt proves that it
/// was compiled by the pinned one-source Rebar transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RebarSingleCaptureParticipationAotReceiptV1 {
    source_cardinality: usize,
    source_bytes: usize,
    source_sha256: [u8; DIGEST_BYTES],
    profile: RustProfile,
    target: Target,
    capture_level: CaptureLevel,
    group_count: usize,
    can_match_empty: bool,
    native: NativeParticipationAotReceiptV1,
    artifact_identity_sha256: [u8; DIGEST_BYTES],
}

impl RebarSingleCaptureParticipationAotReceiptV1 {
    #[must_use]
    pub const fn source_cardinality(&self) -> usize {
        self.source_cardinality
    }

    #[must_use]
    pub const fn source_bytes(&self) -> usize {
        self.source_bytes
    }

    #[must_use]
    pub const fn source_sha256(&self) -> [u8; DIGEST_BYTES] {
        self.source_sha256
    }

    #[must_use]
    pub const fn profile(&self) -> &RustProfile {
        &self.profile
    }

    #[must_use]
    pub const fn target(&self) -> Target {
        self.target
    }

    #[must_use]
    pub const fn capture_level(&self) -> CaptureLevel {
        self.capture_level
    }

    #[must_use]
    pub const fn group_count(&self) -> usize {
        self.group_count
    }

    #[must_use]
    pub const fn can_match_empty(&self) -> bool {
        self.can_match_empty
    }

    #[must_use]
    pub const fn native(&self) -> NativeParticipationAotReceiptV1 {
        self.native
    }

    #[must_use]
    pub const fn artifact_identity_sha256(&self) -> [u8; DIGEST_BYTES] {
        self.artifact_identity_sha256
    }
}

/// One cardinality-authenticated Rebar selector plus an additive helper-free
/// exact-span participation export. A negative native strategy is retained as
/// an authenticated semantic decline and is never executable through this
/// wrapper merely because construction otherwise succeeded.
#[derive(Debug)]
pub struct RebarSingleCaptureParticipationAotArtifactV1 {
    native: NativeParticipationAotArtifactV1,
    receipt: RebarSingleCaptureParticipationAotReceiptV1,
}

impl RebarSingleCaptureParticipationAotArtifactV1 {
    #[must_use]
    pub fn object(&self) -> &[u8] {
        self.native.object()
    }

    #[must_use]
    pub fn bundle(&self) -> &[u8] {
        self.native.bundle()
    }

    #[must_use]
    pub const fn module(&self) -> &CompiledModule {
        self.native.module()
    }

    #[must_use]
    pub const fn native_receipt(&self) -> NativeParticipationAotReceiptV1 {
        self.native.receipt()
    }

    #[must_use]
    pub const fn receipt(&self) -> &RebarSingleCaptureParticipationAotReceiptV1 {
        &self.receipt
    }

    #[must_use]
    pub fn bundle_symbol(&self) -> &str {
        self.native.bundle_symbol()
    }

    #[must_use]
    pub fn selector_entry_symbol(&self) -> &str {
        self.native.selector_entry_symbol()
    }

    #[must_use]
    pub fn participation_entry_symbol(&self) -> &str {
        self.native.participation_entry_symbol()
    }

    /// Recheck the exact Rebar source/profile/schema identity and the complete
    /// underlying native bundle/module/object/export closure.
    #[must_use]
    pub fn authenticates_receipt(&self) -> bool {
        rebar_single_participation_artifact_authenticates(self)
    }
}

/// Whole-operation scalar projection owned by one exact Rebar capture source.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum RebarSingleCaptureReducerOperationV1 {
    CountCaptures = 1,
    GrepCaptures = 2,
}

impl RebarSingleCaptureReducerOperationV1 {
    #[must_use]
    pub const fn domain(self) -> RebarSingleCaptureReducerDomainV1 {
        match self {
            Self::CountCaptures => RebarSingleCaptureReducerDomainV1::WholeHaystack,
            Self::GrepCaptures => RebarSingleCaptureReducerDomainV1::ByteSliceLinesLfCrLf,
        }
    }

    const fn native_domain(self) -> crate::module::NativeCaptureReducerDomainV1 {
        match self {
            Self::CountCaptures => crate::module::NativeCaptureReducerDomainV1::WholeHaystack,
            Self::GrepCaptures => crate::module::NativeCaptureReducerDomainV1::ByteSliceLines,
        }
    }
}

/// Exact byte domain owned by the one-call reducer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum RebarSingleCaptureReducerDomainV1 {
    WholeHaystack = 1,
    /// Rust `bstr::ByteSlice::lines`: LF-delimited, one immediately preceding
    /// CR stripped, no line for empty input, and no extra line after final LF.
    ByteSliceLinesLfCrLf = 2,
}

/// Distinct authenticated child closure used inside the generated reducer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum RebarSingleCaptureReducerSourceRouteV1 {
    /// Ordinary Span selection followed by exact-span participation replay.
    ExactSpanParticipationV1 = 1,
    /// Strict object-local capture iterator with private state and slots.
    CaptureNextV1 = 2,
}

/// Fully authenticated source artifact consumed by one reducer transaction.
///
/// The enum is intentionally route-bearing rather than a generic module. A
/// participation negative remains an explicit terminal route-unavailable
/// result and can never be reinterpreted as `capture_next` or a helper edge.
#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "boxing would allocate between source authentication and final module construction"
)]
pub enum RebarSingleCaptureReducerSourceArtifactV1 {
    ExactSpanParticipation(RebarSingleCaptureParticipationAotArtifactV1),
    CaptureNext(RebarSingleCaptureAotArtifactV1),
}

impl From<RebarSingleCaptureParticipationAotArtifactV1>
    for RebarSingleCaptureReducerSourceArtifactV1
{
    fn from(value: RebarSingleCaptureParticipationAotArtifactV1) -> Self {
        Self::ExactSpanParticipation(value)
    }
}

impl From<RebarSingleCaptureAotArtifactV1> for RebarSingleCaptureReducerSourceArtifactV1 {
    fn from(value: RebarSingleCaptureAotArtifactV1) -> Self {
        Self::CaptureNext(value)
    }
}

impl RebarSingleCaptureReducerSourceArtifactV1 {
    #[must_use]
    pub const fn route(&self) -> RebarSingleCaptureReducerSourceRouteV1 {
        match self {
            Self::ExactSpanParticipation(_) => {
                RebarSingleCaptureReducerSourceRouteV1::ExactSpanParticipationV1
            }
            Self::CaptureNext(_) => RebarSingleCaptureReducerSourceRouteV1::CaptureNextV1,
        }
    }

    #[must_use]
    pub const fn module(&self) -> &CompiledModule {
        match self {
            Self::ExactSpanParticipation(source) => source.module(),
            Self::CaptureNext(source) => source.module(),
        }
    }

    #[must_use]
    pub fn object(&self) -> &[u8] {
        match self {
            Self::ExactSpanParticipation(source) => source.object(),
            Self::CaptureNext(source) => source.object(),
        }
    }

    #[must_use]
    pub fn authenticates_receipt(&self) -> bool {
        match self {
            Self::ExactSpanParticipation(source) => source.authenticates_receipt(),
            Self::CaptureNext(source) => source.authenticates_receipt(),
        }
    }

    fn source_cardinality(&self) -> usize {
        match self {
            Self::ExactSpanParticipation(source) => source.receipt().source_cardinality(),
            Self::CaptureNext(source) => source.receipt().source_cardinality(),
        }
    }

    fn source_bytes(&self) -> usize {
        match self {
            Self::ExactSpanParticipation(source) => source.receipt().source_bytes(),
            Self::CaptureNext(source) => source.receipt().source_bytes(),
        }
    }

    fn source_sha256(&self) -> [u8; DIGEST_BYTES] {
        match self {
            Self::ExactSpanParticipation(source) => source.receipt().source_sha256(),
            Self::CaptureNext(source) => source.receipt().source_sha256(),
        }
    }

    fn profile(&self) -> &RustProfile {
        match self {
            Self::ExactSpanParticipation(source) => source.receipt().profile(),
            Self::CaptureNext(source) => source.receipt().profile(),
        }
    }

    fn target(&self) -> Target {
        match self {
            Self::ExactSpanParticipation(source) => source.receipt().target(),
            Self::CaptureNext(source) => source.receipt().target(),
        }
    }

    fn capture_level(&self) -> CaptureLevel {
        match self {
            Self::ExactSpanParticipation(source) => source.receipt().capture_level(),
            Self::CaptureNext(source) => source.receipt().capture_level(),
        }
    }

    fn group_count(&self) -> usize {
        match self {
            Self::ExactSpanParticipation(source) => source.receipt().group_count(),
            Self::CaptureNext(source) => source.receipt().group_count(),
        }
    }

    fn can_match_empty(&self) -> bool {
        match self {
            Self::ExactSpanParticipation(source) => source.receipt().can_match_empty(),
            Self::CaptureNext(source) => source.receipt().can_match_empty(),
        }
    }

    fn selector_sha256(&self) -> [u8; DIGEST_BYTES] {
        match self {
            Self::ExactSpanParticipation(source) => source.native_receipt().selector_sha256,
            Self::CaptureNext(source) => source.receipt().selector_sha256(),
        }
    }

    fn capture_sha256(&self) -> [u8; DIGEST_BYTES] {
        match self {
            Self::ExactSpanParticipation(source) => source.native_receipt().capture_sha256,
            Self::CaptureNext(source) => source.receipt().capture_sha256(),
        }
    }

    fn artifact_identity_sha256(&self) -> [u8; DIGEST_BYTES] {
        match self {
            Self::ExactSpanParticipation(source) => source.receipt().artifact_identity_sha256(),
            Self::CaptureNext(source) => source.receipt().artifact_identity_sha256(),
        }
    }

    fn object_sha256(&self) -> [u8; DIGEST_BYTES] {
        match self {
            Self::ExactSpanParticipation(source) => source.native_receipt().object_sha256,
            Self::CaptureNext(source) => source.receipt().object_sha256(),
        }
    }

    fn native_source(&self) -> crate::module::NativeCaptureReducerSourceV1<'_> {
        match self {
            Self::ExactSpanParticipation(source) => {
                crate::module::NativeCaptureReducerSourceV1::ExactSpanParticipation {
                    selector_symbol: source.selector_entry_symbol(),
                    bundle_symbol: source.bundle_symbol(),
                    participation_symbol: source.participation_entry_symbol(),
                    group_count: source.receipt().group_count(),
                }
            }
            Self::CaptureNext(source) => crate::module::NativeCaptureReducerSourceV1::CaptureNext {
                capture_next_symbol: source.capture_next_symbol(),
                group_count: source.receipt().group_count(),
            },
        }
    }

    fn symbols(&self) -> [&str; 3] {
        match self {
            Self::ExactSpanParticipation(source) => [
                source.selector_entry_symbol(),
                source.bundle_symbol(),
                source.participation_entry_symbol(),
            ],
            Self::CaptureNext(source) => [source.capture_next_symbol(), "", ""],
        }
    }
}

/// Immutable source/schema/operation receipt for one whole-operation reducer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RebarSingleCaptureReducerAotReceiptV1 {
    operation: RebarSingleCaptureReducerOperationV1,
    domain: RebarSingleCaptureReducerDomainV1,
    source_route: RebarSingleCaptureReducerSourceRouteV1,
    source_cardinality: usize,
    source_bytes: usize,
    source_sha256: [u8; DIGEST_BYTES],
    profile: RustProfile,
    target: Target,
    capture_level: CaptureLevel,
    group_count: usize,
    can_match_empty: bool,
    empty_progress: RebarSingleCaptureEmptyProgressV1,
    semantic_runtime_calls: usize,
    private_participation_scratch_bytes: usize,
    private_iterator_state_bytes: usize,
    private_result_slot_count: usize,
    private_result_slot_bytes: usize,
    selector_sha256: [u8; DIGEST_BYTES],
    capture_sha256: [u8; DIGEST_BYTES],
    source_artifact_identity_sha256: [u8; DIGEST_BYTES],
    source_object_sha256: [u8; DIGEST_BYTES],
    reducer_symbol_sha256: [u8; DIGEST_BYTES],
    object_sha256: [u8; DIGEST_BYTES],
    object_bytes: usize,
    max_object_bytes: usize,
    artifact_identity_sha256: [u8; DIGEST_BYTES],
}

impl RebarSingleCaptureReducerAotReceiptV1 {
    #[must_use]
    pub const fn operation(&self) -> RebarSingleCaptureReducerOperationV1 {
        self.operation
    }

    #[must_use]
    pub const fn domain(&self) -> RebarSingleCaptureReducerDomainV1 {
        self.domain
    }

    #[must_use]
    pub const fn source_route(&self) -> RebarSingleCaptureReducerSourceRouteV1 {
        self.source_route
    }

    #[must_use]
    pub const fn source_cardinality(&self) -> usize {
        self.source_cardinality
    }

    #[must_use]
    pub const fn source_bytes(&self) -> usize {
        self.source_bytes
    }

    #[must_use]
    pub const fn source_sha256(&self) -> [u8; DIGEST_BYTES] {
        self.source_sha256
    }

    #[must_use]
    pub const fn profile(&self) -> &RustProfile {
        &self.profile
    }

    #[must_use]
    pub const fn target(&self) -> Target {
        self.target
    }

    #[must_use]
    pub const fn capture_level(&self) -> CaptureLevel {
        self.capture_level
    }

    #[must_use]
    pub const fn group_count(&self) -> usize {
        self.group_count
    }

    #[must_use]
    pub const fn can_match_empty(&self) -> bool {
        self.can_match_empty
    }

    #[must_use]
    pub const fn empty_progress(&self) -> RebarSingleCaptureEmptyProgressV1 {
        self.empty_progress
    }

    #[must_use]
    pub const fn semantic_runtime_calls(&self) -> usize {
        self.semantic_runtime_calls
    }

    #[must_use]
    pub const fn private_participation_scratch_bytes(&self) -> usize {
        self.private_participation_scratch_bytes
    }

    #[must_use]
    pub const fn private_iterator_state_bytes(&self) -> usize {
        self.private_iterator_state_bytes
    }

    #[must_use]
    pub const fn private_result_slot_count(&self) -> usize {
        self.private_result_slot_count
    }

    #[must_use]
    pub const fn private_result_slot_bytes(&self) -> usize {
        self.private_result_slot_bytes
    }

    #[must_use]
    pub const fn selector_sha256(&self) -> [u8; DIGEST_BYTES] {
        self.selector_sha256
    }

    #[must_use]
    pub const fn capture_sha256(&self) -> [u8; DIGEST_BYTES] {
        self.capture_sha256
    }

    #[must_use]
    pub const fn source_artifact_identity_sha256(&self) -> [u8; DIGEST_BYTES] {
        self.source_artifact_identity_sha256
    }

    #[must_use]
    pub const fn source_object_sha256(&self) -> [u8; DIGEST_BYTES] {
        self.source_object_sha256
    }

    #[must_use]
    pub const fn reducer_symbol_sha256(&self) -> [u8; DIGEST_BYTES] {
        self.reducer_symbol_sha256
    }

    #[must_use]
    pub const fn object_sha256(&self) -> [u8; DIGEST_BYTES] {
        self.object_sha256
    }

    #[must_use]
    pub const fn object_bytes(&self) -> usize {
        self.object_bytes
    }

    #[must_use]
    pub const fn max_object_bytes(&self) -> usize {
        self.max_object_bytes
    }

    #[must_use]
    pub const fn artifact_identity_sha256(&self) -> [u8; DIGEST_BYTES] {
        self.artifact_identity_sha256
    }
}

/// One exact retained Rebar source closure plus its one-call native reducer.
#[derive(Debug)]
pub struct RebarSingleCaptureReducerAotArtifactV1 {
    source: RebarSingleCaptureReducerSourceArtifactV1,
    module: CompiledModule,
    object: Box<[u8]>,
    reducer_symbol: String,
    receipt: RebarSingleCaptureReducerAotReceiptV1,
}

impl RebarSingleCaptureReducerAotArtifactV1 {
    #[must_use]
    pub const fn source(&self) -> &RebarSingleCaptureReducerSourceArtifactV1 {
        &self.source
    }

    #[must_use]
    pub const fn module(&self) -> &CompiledModule {
        &self.module
    }

    #[must_use]
    pub fn object(&self) -> &[u8] {
        &self.object
    }

    #[must_use]
    pub fn reducer_symbol(&self) -> &str {
        &self.reducer_symbol
    }

    #[must_use]
    pub const fn receipt(&self) -> &RebarSingleCaptureReducerAotReceiptV1 {
        &self.receipt
    }

    /// Re-authenticate the retained source artifact, deterministically append
    /// the exact route again, and compare the complete module/object receipt.
    #[must_use]
    pub fn authenticates_receipt(&self) -> bool {
        rebar_single_capture_reducer_artifact_authenticates(self)
    }
}

/// Terminal reducer construction failure. No variant authorizes another
/// source route, a runtime helper, or a Rust-loop fallback.
#[derive(Debug)]
pub enum RebarSingleCaptureReducerAotErrorV1 {
    ParticipationUnavailable(NativeParticipationAotDeclineV1),
    SourceAuthentication(&'static str),
    Object(ObjectError),
    ArithmeticOverflow(&'static str),
    Authentication(&'static str),
}

impl fmt::Display for RebarSingleCaptureReducerAotErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Rebar single-pattern capture reducer AOT failed: {self:?}",
        )
    }
}

impl std::error::Error for RebarSingleCaptureReducerAotErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Object(source) => Some(source),
            Self::ParticipationUnavailable(_)
            | Self::SourceAuthentication(_)
            | Self::ArithmeticOverflow(_)
            | Self::Authentication(_) => None,
        }
    }
}

impl From<ObjectError> for RebarSingleCaptureReducerAotErrorV1 {
    fn from(value: ObjectError) -> Self {
        Self::Object(value)
    }
}

/// Failure before publishing a Rebar exact-span participation artifact.
/// Semantic native declines are successful authenticated negative artifacts,
/// not members of this error type.
#[derive(Debug)]
pub enum RebarSingleCaptureParticipationAotErrorV1 {
    Capture(CaptureCompileError),
    Participation(NativeParticipationAotErrorV1),
    ArithmeticOverflow(&'static str),
    Authentication(&'static str),
}

impl fmt::Display for RebarSingleCaptureParticipationAotErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Rebar single-pattern native participation AOT failed: {self:?}",
        )
    }
}

impl std::error::Error for RebarSingleCaptureParticipationAotErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Capture(source) => Some(source),
            Self::Participation(source) => Some(source),
            Self::ArithmeticOverflow(_) | Self::Authentication(_) => None,
        }
    }
}

impl From<CaptureCompileError> for RebarSingleCaptureParticipationAotErrorV1 {
    fn from(value: CaptureCompileError) -> Self {
        Self::Capture(value)
    }
}

impl From<NativeParticipationAotErrorV1> for RebarSingleCaptureParticipationAotErrorV1 {
    fn from(value: NativeParticipationAotErrorV1) -> Self {
        Self::Participation(value)
    }
}

#[derive(Debug)]
pub enum RebarSingleCaptureAotError {
    Capture(CaptureCompileError),
    OnePassResource(OnePassCaptureBuildFailure),
    Native(NativeCaptureAotError),
    Declined(NativeCaptureAotDeclineV1),
    SemanticRuntimeHelper,
    ArithmeticOverflow(&'static str),
    Authentication(&'static str),
}

impl fmt::Display for RebarSingleCaptureAotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Rebar single-pattern native capture AOT failed: {self:?}",
        )
    }
}

impl std::error::Error for RebarSingleCaptureAotError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Capture(source) => Some(source),
            Self::OnePassResource(source) => Some(source),
            Self::Native(source) => Some(source),
            Self::Declined(_)
            | Self::SemanticRuntimeHelper
            | Self::ArithmeticOverflow(_)
            | Self::Authentication(_) => None,
        }
    }
}

impl From<CaptureCompileError> for RebarSingleCaptureAotError {
    fn from(value: CaptureCompileError) -> Self {
        Self::Capture(value)
    }
}

impl From<NativeCaptureAotError> for RebarSingleCaptureAotError {
    fn from(value: NativeCaptureAotError) -> Self {
        Self::Native(value)
    }
}

/// Compile and publish one cardinality-authenticated Rebar exact-span
/// participation artifact.
///
/// The pinned Rebar meta profile and one-source guard are the same transaction
/// used by [`compile_rebar_single_capture_aot_v1`]. Unlike that stricter
/// one-pass route, an authenticated negative participation artifact is
/// returned to the caller so it can preserve its pre-existing fallback. No
/// construction, resource, allocation, object or authentication error is
/// converted into that semantic decline.
pub fn compile_rebar_single_capture_participation_aot_v1(
    request: RebarSingleCaptureAotRequestV1,
    participation_limits: NativeParticipationAotLimitsV1,
) -> Result<RebarSingleCaptureParticipationAotArtifactV1, RebarSingleCaptureParticipationAotErrorV1>
{
    let RebarSingleCaptureAotRequestV1 {
        pattern,
        target,
        options,
        compile_limits,
        native_limits: _,
    } = request;
    let source_bytes = pattern.len();
    let source_sha256 = participation_source_digest(&pattern)?;
    let mut profile = RustProfile::rebar_1_12_4();
    profile.options = options;
    let compiled = crate::captures::compile_rebar_single_captures(
        CaptureCompileRequest::new(pattern, target)
            .profile(profile.clone())
            .mode(CompileMode::Optimizing)
            .limits(compile_limits),
    )?;
    compiled.authenticate().map_err(|_| {
        RebarSingleCaptureParticipationAotErrorV1::Authentication("compiled capture composite")
    })?;
    let compile_receipt = compiled.receipt();
    let identity = compile_receipt.identity;
    let selector_receipt = compiled.selector().receipt();
    if compile_receipt.profile != profile
        || compile_receipt.source_bytes != source_bytes
        || identity.level() != CaptureLevel::All
        || selector_receipt.mode != CompileMode::Optimizing
        || selector_receipt.output != OutputContract::Span
        || selector_receipt.target != target
        || selector_receipt.source_bytes != source_bytes
    {
        return Err(RebarSingleCaptureParticipationAotErrorV1::Authentication(
            "single-pattern parse/profile/selector receipt",
        ));
    }
    let can_match_empty = compile_receipt.can_match_empty;
    let native = compiled.emit_native_participation_aot_v1(participation_limits)?;
    if !native.authenticates_receipt() {
        return Err(RebarSingleCaptureParticipationAotErrorV1::Authentication(
            "native participation bundle/module/object route",
        ));
    }
    let native_receipt = native.receipt();
    if native_receipt.target != target
        || native_receipt.groups != identity.groups()
        || native_receipt.capture_sha256 != identity.capture_sha256()
        || native_receipt.selector_sha256 != identity.selector_sha256()
        || native_receipt.semantic_runtime_calls != 0
    {
        return Err(RebarSingleCaptureParticipationAotErrorV1::Authentication(
            "native participation descriptor/capture schema",
        ));
    }
    let mut receipt = RebarSingleCaptureParticipationAotReceiptV1 {
        source_cardinality: REBAR_SINGLE_CAPTURE_AOT_V1_SOURCE_CARDINALITY,
        source_bytes,
        source_sha256,
        profile,
        target,
        capture_level: identity.level(),
        group_count: identity.groups(),
        can_match_empty,
        native: native_receipt,
        artifact_identity_sha256: [0; DIGEST_BYTES],
    };
    receipt.artifact_identity_sha256 =
        rebar_single_participation_artifact_identity(&receipt, &native)?;
    let artifact = RebarSingleCaptureParticipationAotArtifactV1 { native, receipt };
    if !artifact.authenticates_receipt() {
        return Err(RebarSingleCaptureParticipationAotErrorV1::Authentication(
            "fresh Rebar single-pattern participation artifact",
        ));
    }
    Ok(artifact)
}

/// Compile and publish one strictly selected helper-free Rebar capture route.
pub fn compile_rebar_single_capture_aot_v1(
    request: RebarSingleCaptureAotRequestV1,
) -> Result<RebarSingleCaptureAotArtifactV1, RebarSingleCaptureAotError> {
    let RebarSingleCaptureAotRequestV1 {
        pattern,
        target,
        options,
        compile_limits,
        native_limits,
    } = request;
    let source_bytes = pattern.len();
    let source_sha256 = source_digest(&pattern)?;
    let mut profile = RustProfile::rebar_1_12_4();
    profile.options = options;
    let compiled = crate::captures::compile_rebar_single_captures(
        CaptureCompileRequest::new(pattern, target)
            .profile(profile.clone())
            .mode(CompileMode::Optimizing)
            .limits(compile_limits),
    )?;
    compiled
        .authenticate()
        .map_err(|_| RebarSingleCaptureAotError::Authentication("compiled capture composite"))?;
    let compile_receipt = compiled.receipt();
    let identity = compile_receipt.identity;
    let selector_receipt = compiled.selector().receipt();
    if compile_receipt.profile != profile
        || compile_receipt.source_bytes != source_bytes
        || identity.level() != CaptureLevel::All
        || selector_receipt.mode != CompileMode::Optimizing
        || selector_receipt.output != OutputContract::Span
        || selector_receipt.target != target
        || selector_receipt.source_bytes != source_bytes
    {
        return Err(RebarSingleCaptureAotError::Authentication(
            "single-pattern parse/profile/selector receipt",
        ));
    }
    let can_match_empty = compile_receipt.can_match_empty;
    if let CaptureOnePassDisposition::Declined {
        source: source @ OnePassCaptureBuildError::Resource { .. },
        compile_work,
    } = &compile_receipt.onepass
    {
        return Err(RebarSingleCaptureAotError::OnePassResource(
            OnePassCaptureBuildFailure {
                source: source.clone(),
                compile_work: *compile_work,
            },
        ));
    }
    let native = compiled.emit_native_aot_v1(native_limits)?;
    if native.receipt().strategy == NativeCaptureAotStrategyV1::NegativeEntry {
        return Err(RebarSingleCaptureAotError::Declined(
            native
                .receipt()
                .decline
                .ok_or(RebarSingleCaptureAotError::Authentication(
                    "negative decline receipt",
                ))?,
        ));
    }
    if native.receipt().decline.is_some()
        || native.receipt().semantic_runtime_calls != 0
        || native.module().required_runtime_symbols().next().is_some()
    {
        return Err(RebarSingleCaptureAotError::SemanticRuntimeHelper);
    }
    if !native.authenticates_receipt() {
        return Err(RebarSingleCaptureAotError::Authentication(
            "native bundle/module/object route",
        ));
    }
    let descriptor = native.descriptor();
    if descriptor.selector_sha256() != identity.selector_sha256()
        || descriptor.capture_sha256() != identity.capture_sha256()
        || descriptor.group_count() != identity.groups()
        || descriptor.capture_tag_slot_count() != identity.slots()
        || descriptor.slot_count() != identity.groups()
    {
        return Err(RebarSingleCaptureAotError::Authentication(
            "native descriptor/capture schema",
        ));
    }
    let native_receipt = native.receipt();
    let mut receipt = RebarSingleCaptureAotReceiptV1 {
        source_cardinality: REBAR_SINGLE_CAPTURE_AOT_V1_SOURCE_CARDINALITY,
        source_bytes,
        source_sha256,
        profile,
        target,
        capture_level: identity.level(),
        group_count: identity.groups(),
        result_slot_count: descriptor.slot_count(),
        raw_tag_slot_count: identity.slots(),
        can_match_empty,
        empty_progress: RebarSingleCaptureEmptyProgressV1::Byte,
        selector_sha256: descriptor.selector_sha256(),
        capture_sha256: descriptor.capture_sha256(),
        plan_sha256: descriptor.plan_sha256(),
        selector_object_sha256: native_receipt.selector_object_sha256,
        bundle_sha256: descriptor.bundle_sha256(),
        export_identity_sha256: native_receipt.export_identity_sha256,
        object_sha256: native_receipt.object_sha256,
        artifact_identity_sha256: [0; DIGEST_BYTES],
    };
    receipt.artifact_identity_sha256 = rebar_single_artifact_identity(&receipt, &native)?;
    let artifact = RebarSingleCaptureAotArtifactV1 { native, receipt };
    if !artifact.authenticates_receipt() {
        return Err(RebarSingleCaptureAotError::Authentication(
            "fresh Rebar single-pattern artifact",
        ));
    }
    Ok(artifact)
}

/// Append one one-call whole-operation reducer to an exact retained Rebar
/// capture source artifact.
///
/// The source variant fixes the only permitted child graph. A selected
/// participation artifact uses ordinary Span plus exact-span replay; a strict
/// capture artifact uses only `capture_next` with private state and exact
/// receipt-sized slots. No decline or construction failure selects the other
/// route, and the final object is published only after deterministic module
/// reconstruction and receipt authentication.
pub fn compile_rebar_single_capture_reducer_aot_v1(
    source: RebarSingleCaptureReducerSourceArtifactV1,
    operation: RebarSingleCaptureReducerOperationV1,
    max_object_bytes: usize,
) -> Result<RebarSingleCaptureReducerAotArtifactV1, RebarSingleCaptureReducerAotErrorV1> {
    authenticate_reducer_source(&source)?;
    let source_route = source.route();
    let source_cardinality = source.source_cardinality();
    let source_bytes = source.source_bytes();
    let source_sha256 = source.source_sha256();
    let profile = source.profile().clone();
    let target = source.target();
    let capture_level = source.capture_level();
    let group_count = source.group_count();
    let can_match_empty = source.can_match_empty();
    let selector_sha256 = source.selector_sha256();
    let capture_sha256 = source.capture_sha256();
    let source_artifact_identity_sha256 = source.artifact_identity_sha256();
    let source_object_sha256 = source.object_sha256();
    let (
        private_participation_scratch_bytes,
        private_iterator_state_bytes,
        private_result_slot_count,
        private_result_slot_bytes,
    ) = reducer_private_schema(&source)?;
    let native_domain = operation.native_domain();
    let (module, reducer_symbol) = {
        let native_source = source.native_source();
        let (module, reducer_symbol) = source.module().clone().append_native_capture_reducer_v1(
            native_domain,
            native_source,
            source_artifact_identity_sha256,
        )?;
        module
            .authenticate_native_capture_reducer_v1(
                source.module(),
                native_domain,
                native_source,
                source_artifact_identity_sha256,
                &reducer_symbol,
            )
            .map_err(|_| {
                RebarSingleCaptureReducerAotErrorV1::Authentication(
                    "fresh deterministic native closure",
                )
            })?;
        (module, reducer_symbol)
    };
    let object = emit_object(&module, ObjectFormat::for_target(target), max_object_bytes)?;
    let object_sha256 = reducer_sha256(&object);
    let mut receipt = RebarSingleCaptureReducerAotReceiptV1 {
        operation,
        domain: operation.domain(),
        source_route,
        source_cardinality,
        source_bytes,
        source_sha256,
        profile,
        target,
        capture_level,
        group_count,
        can_match_empty,
        empty_progress: RebarSingleCaptureEmptyProgressV1::Byte,
        semantic_runtime_calls: 0,
        private_participation_scratch_bytes,
        private_iterator_state_bytes,
        private_result_slot_count,
        private_result_slot_bytes,
        selector_sha256,
        capture_sha256,
        source_artifact_identity_sha256,
        source_object_sha256,
        reducer_symbol_sha256: reducer_sha256(reducer_symbol.as_bytes()),
        object_sha256,
        object_bytes: object.len(),
        max_object_bytes,
        artifact_identity_sha256: [0; DIGEST_BYTES],
    };
    receipt.artifact_identity_sha256 =
        rebar_single_capture_reducer_artifact_identity(&receipt, &source, &reducer_symbol)?;
    let artifact = RebarSingleCaptureReducerAotArtifactV1 {
        source,
        module,
        object: object.into_boxed_slice(),
        reducer_symbol,
        receipt,
    };
    if !artifact.authenticates_receipt() {
        return Err(RebarSingleCaptureReducerAotErrorV1::Authentication(
            "fresh Rebar whole-operation reducer artifact",
        ));
    }
    Ok(artifact)
}

fn authenticate_reducer_source(
    source: &RebarSingleCaptureReducerSourceArtifactV1,
) -> Result<(), RebarSingleCaptureReducerAotErrorV1> {
    if !source.authenticates_receipt() {
        return Err(RebarSingleCaptureReducerAotErrorV1::SourceAuthentication(
            "retained source receipt",
        ));
    }
    let mut expected_profile = RustProfile::rebar_1_12_4();
    expected_profile.options = source.profile().options.clone();
    if source.source_cardinality() != REBAR_SINGLE_CAPTURE_AOT_V1_SOURCE_CARDINALITY
        || source.source_sha256() == [0; DIGEST_BYTES]
        || source.profile() != &expected_profile
        || source.capture_level() != CaptureLevel::All
        || source.group_count() == 0
        || source.selector_sha256() == [0; DIGEST_BYTES]
        || source.capture_sha256() == [0; DIGEST_BYTES]
        || source.artifact_identity_sha256() == [0; DIGEST_BYTES]
        || source.object_sha256() == [0; DIGEST_BYTES]
        || source.object().is_empty()
        || reducer_sha256(source.object()) != source.object_sha256()
        || source.module().target() != source.target()
        || source.module().required_runtime_symbols().next().is_some()
        || source.module().required_runtime_program().is_some()
        || source.module().prepared_entry_symbol().is_some()
        || source.module().prepared_aggregate_exports() != crate::PreparedAggregateExports::NONE
        || source.module().required_prepare_capabilities() != 0
    {
        return Err(RebarSingleCaptureReducerAotErrorV1::SourceAuthentication(
            "source profile/schema/helper closure",
        ));
    }
    match source {
        RebarSingleCaptureReducerSourceArtifactV1::ExactSpanParticipation(source) => {
            let native = source.native_receipt();
            if native.strategy == NativeParticipationAotStrategyV1::NegativeEntry {
                return Err(
                    RebarSingleCaptureReducerAotErrorV1::ParticipationUnavailable(
                        native.decline.ok_or(
                            RebarSingleCaptureReducerAotErrorV1::SourceAuthentication(
                                "negative participation decline",
                            ),
                        )?,
                    ),
                );
            }
            let expected = match native.target.architecture {
                Architecture::X86_64 => NativeParticipationAotStrategyV1::DfaX86_64,
                Architecture::Aarch64 => NativeParticipationAotStrategyV1::DfaAarch64,
            };
            if native.strategy != expected
                || native.decline.is_some()
                || native.semantic_runtime_calls != 0
                || native.groups != source.receipt().group_count()
                || native.scratch_bytes != crate::NATIVE_PARTICIPATION_AOT_V1_SCRATCH_BYTES
                || !(1..=64).contains(&native.groups)
            {
                return Err(RebarSingleCaptureReducerAotErrorV1::SourceAuthentication(
                    "selected exact-span participation route",
                ));
            }
        }
        RebarSingleCaptureReducerSourceArtifactV1::CaptureNext(source) => {
            let native = source.native_receipt();
            let expected = match native.target.architecture {
                Architecture::X86_64 => NativeCaptureAotStrategyV1::NativeOnePassX86_64,
                Architecture::Aarch64 => NativeCaptureAotStrategyV1::NativeOnePassAarch64,
            };
            if native.strategy != expected
                || native.decline.is_some()
                || native.semantic_runtime_calls != 0
                || source.receipt().result_slot_count() != source.receipt().group_count()
                || source.receipt().group_count().checked_mul(2)
                    != Some(source.receipt().raw_tag_slot_count())
                || !(1..=16).contains(&source.receipt().group_count())
            {
                return Err(RebarSingleCaptureReducerAotErrorV1::SourceAuthentication(
                    "selected strict capture-next route",
                ));
            }
        }
    }
    Ok(())
}

fn reducer_private_schema(
    source: &RebarSingleCaptureReducerSourceArtifactV1,
) -> Result<(usize, usize, usize, usize), RebarSingleCaptureReducerAotErrorV1> {
    match source {
        RebarSingleCaptureReducerSourceArtifactV1::ExactSpanParticipation(_) => {
            Ok((crate::NATIVE_PARTICIPATION_AOT_V1_SCRATCH_BYTES, 0, 0, 0))
        }
        RebarSingleCaptureReducerSourceArtifactV1::CaptureNext(source) => {
            let slots = source.receipt().group_count();
            let state_bytes = usize::try_from(crate::NATIVE_CAPTURE_AOT_V1_ITER_STATE_BYTES)
                .map_err(|_| {
                    RebarSingleCaptureReducerAotErrorV1::ArithmeticOverflow(
                        "private capture iterator state",
                    )
                })?;
            let slot_width = usize::try_from(crate::NATIVE_CAPTURE_AOT_V1_RESULT_SLOT_BYTES)
                .map_err(|_| {
                    RebarSingleCaptureReducerAotErrorV1::ArithmeticOverflow(
                        "private capture result slot width",
                    )
                })?;
            let bytes = slots.checked_mul(slot_width).ok_or(
                RebarSingleCaptureReducerAotErrorV1::ArithmeticOverflow(
                    "private capture result slots",
                ),
            )?;
            Ok((0, state_bytes, slots, bytes))
        }
    }
}

fn rebar_single_capture_reducer_artifact_authenticates(
    artifact: &RebarSingleCaptureReducerAotArtifactV1,
) -> bool {
    let receipt = &artifact.receipt;
    let source = &artifact.source;
    let Ok((scratch_bytes, state_bytes, slot_count, slot_bytes)) = reducer_private_schema(source)
    else {
        return false;
    };
    if authenticate_reducer_source(source).is_err()
        || receipt.operation.domain() != receipt.domain
        || receipt.source_route != source.route()
        || receipt.source_cardinality != source.source_cardinality()
        || receipt.source_bytes != source.source_bytes()
        || receipt.source_sha256 != source.source_sha256()
        || &receipt.profile != source.profile()
        || receipt.target != source.target()
        || receipt.target != artifact.module.target()
        || receipt.capture_level != source.capture_level()
        || receipt.group_count != source.group_count()
        || receipt.can_match_empty != source.can_match_empty()
        || receipt.empty_progress != RebarSingleCaptureEmptyProgressV1::Byte
        || receipt.semantic_runtime_calls != 0
        || receipt.private_participation_scratch_bytes != scratch_bytes
        || receipt.private_iterator_state_bytes != state_bytes
        || receipt.private_result_slot_count != slot_count
        || receipt.private_result_slot_bytes != slot_bytes
        || receipt.selector_sha256 != source.selector_sha256()
        || receipt.capture_sha256 != source.capture_sha256()
        || receipt.source_artifact_identity_sha256 != source.artifact_identity_sha256()
        || receipt.source_object_sha256 != source.object_sha256()
        || receipt.reducer_symbol_sha256 != reducer_sha256(artifact.reducer_symbol.as_bytes())
        || receipt.object_bytes != artifact.object.len()
        || receipt.object_bytes == 0
        || receipt.object_bytes > receipt.max_object_bytes
        || receipt.object_sha256 != reducer_sha256(&artifact.object)
        || artifact.module.required_runtime_symbols().next().is_some()
        || artifact.module.required_runtime_program().is_some()
        || artifact.module.prepared_entry_symbol().is_some()
        || artifact.module.prepared_aggregate_exports() != crate::PreparedAggregateExports::NONE
        || artifact.module.required_prepare_capabilities() != 0
    {
        return false;
    }
    let native_source = source.native_source();
    if artifact
        .module
        .authenticate_native_capture_reducer_v1(
            source.module(),
            receipt.operation.native_domain(),
            native_source,
            receipt.source_artifact_identity_sha256,
            &artifact.reducer_symbol,
        )
        .is_err()
    {
        return false;
    }
    if !emit_object(
        &artifact.module,
        ObjectFormat::for_target(receipt.target),
        receipt.max_object_bytes,
    )
    .is_ok_and(|expected| expected.as_slice() == artifact.object.as_ref())
    {
        return false;
    }
    rebar_single_capture_reducer_artifact_identity(receipt, source, &artifact.reducer_symbol)
        .is_ok_and(|identity| identity == receipt.artifact_identity_sha256)
}

fn rebar_single_capture_reducer_artifact_identity(
    receipt: &RebarSingleCaptureReducerAotReceiptV1,
    source: &RebarSingleCaptureReducerSourceArtifactV1,
    reducer_symbol: &str,
) -> Result<[u8; DIGEST_BYTES], RebarSingleCaptureReducerAotErrorV1> {
    let mut digest = Sha256::new();
    digest.update(REBAR_SINGLE_CAPTURE_REDUCER_AOT_V1_IDENTITY_DOMAIN);
    digest.update(REBAR_PROFILE_IDENTITY);
    digest.update([
        receipt.operation as u8,
        receipt.domain as u8,
        receipt.source_route as u8,
        match receipt.capture_level {
            CaptureLevel::All => 1,
        },
        u8::from(receipt.can_match_empty),
        receipt.empty_progress as u8,
    ]);
    hash_options(&mut digest, &receipt.profile.options);
    hash_target(&mut digest, receipt.target);
    for value in [
        receipt.source_cardinality,
        receipt.source_bytes,
        receipt.group_count,
        receipt.semantic_runtime_calls,
        receipt.private_participation_scratch_bytes,
        receipt.private_iterator_state_bytes,
        receipt.private_result_slot_count,
        receipt.private_result_slot_bytes,
        receipt.object_bytes,
        receipt.max_object_bytes,
    ] {
        digest.update(reducer_usize_u64(value, "capture reducer receipt")?.to_le_bytes());
    }
    for identity in [
        receipt.source_sha256,
        receipt.selector_sha256,
        receipt.capture_sha256,
        receipt.source_artifact_identity_sha256,
        receipt.source_object_sha256,
        receipt.reducer_symbol_sha256,
        receipt.object_sha256,
    ] {
        digest.update(identity);
    }
    for symbol in source
        .symbols()
        .into_iter()
        .chain(core::iter::once(reducer_symbol))
    {
        digest.update(
            reducer_usize_u64(symbol.len(), "capture reducer symbol identity")?.to_le_bytes(),
        );
        digest.update(symbol.as_bytes());
    }
    Ok(digest.finalize().into())
}

fn reducer_usize_u64(
    value: usize,
    site: &'static str,
) -> Result<u64, RebarSingleCaptureReducerAotErrorV1> {
    u64::try_from(value).map_err(|_| RebarSingleCaptureReducerAotErrorV1::ArithmeticOverflow(site))
}

fn reducer_sha256(bytes: &[u8]) -> [u8; DIGEST_BYTES] {
    Sha256::digest(bytes).into()
}

fn rebar_single_artifact_authenticates(artifact: &RebarSingleCaptureAotArtifactV1) -> bool {
    let receipt = &artifact.receipt;
    let native = &artifact.native;
    let descriptor = native.descriptor();
    let native_receipt = native.receipt();
    let mut expected_profile = RustProfile::rebar_1_12_4();
    expected_profile.options = receipt.profile.options.clone();
    let expected_strategy = match receipt.target.architecture {
        Architecture::X86_64 => NativeCaptureAotStrategyV1::NativeOnePassX86_64,
        Architecture::Aarch64 => NativeCaptureAotStrategyV1::NativeOnePassAarch64,
    };
    receipt.source_cardinality == REBAR_SINGLE_CAPTURE_AOT_V1_SOURCE_CARDINALITY
        && receipt.profile == expected_profile
        && receipt.target == native_receipt.target
        && receipt.target == native.module().target()
        && receipt.capture_level == CaptureLevel::All
        && receipt.group_count != 0
        && receipt.result_slot_count == receipt.group_count
        && receipt.raw_tag_slot_count == receipt.group_count.checked_mul(2).unwrap_or(usize::MAX)
        && receipt.includes_group_zero()
        && receipt.empty_progress == RebarSingleCaptureEmptyProgressV1::Byte
        && native_receipt.strategy == expected_strategy
        && native_receipt.decline.is_none()
        && native_receipt.semantic_runtime_calls == 0
        && native.module().required_runtime_symbols().next().is_none()
        && descriptor.strategy() == expected_strategy
        && descriptor.decline().is_none()
        && descriptor.group_count() == receipt.group_count
        && descriptor.slot_count() == receipt.result_slot_count
        && descriptor.capture_tag_slot_count() == receipt.raw_tag_slot_count
        && descriptor.selector_sha256() == receipt.selector_sha256
        && descriptor.capture_sha256() == receipt.capture_sha256
        && descriptor.plan_sha256() == receipt.plan_sha256
        && descriptor.bundle_sha256() == receipt.bundle_sha256
        && native_receipt.selector_object_sha256 == receipt.selector_object_sha256
        && native_receipt.bundle_sha256 == receipt.bundle_sha256
        && native_receipt.export_identity_sha256 == receipt.export_identity_sha256
        && native_receipt.object_sha256 == receipt.object_sha256
        && native.authenticates_receipt()
        && NativeCaptureBundleV1View::from_bytes(native.bundle())
            .is_ok_and(|view| view.descriptor() == descriptor)
        && rebar_single_artifact_identity(receipt, native)
            .is_ok_and(|identity| identity == receipt.artifact_identity_sha256)
}

fn rebar_single_participation_artifact_authenticates(
    artifact: &RebarSingleCaptureParticipationAotArtifactV1,
) -> bool {
    let receipt = &artifact.receipt;
    let native = &artifact.native;
    let native_receipt = native.receipt();
    let mut expected_profile = RustProfile::rebar_1_12_4();
    expected_profile.options = receipt.profile.options.clone();
    let selected_strategy = match receipt.target.architecture {
        Architecture::X86_64 => NativeParticipationAotStrategyV1::DfaX86_64,
        Architecture::Aarch64 => NativeParticipationAotStrategyV1::DfaAarch64,
    };
    let route_closes = if native_receipt.strategy == selected_strategy {
        native_receipt.decline.is_none()
            && native.module().required_runtime_symbols().next().is_none()
            && native.module().required_runtime_program().is_none()
    } else {
        native_receipt.strategy == NativeParticipationAotStrategyV1::NegativeEntry
            && native_receipt.decline.is_some()
    };
    receipt.source_cardinality == REBAR_SINGLE_CAPTURE_AOT_V1_SOURCE_CARDINALITY
        && receipt.source_sha256 != [0; DIGEST_BYTES]
        && receipt.profile == expected_profile
        && receipt.target == native_receipt.target
        && receipt.target == native.module().target()
        && receipt.capture_level == CaptureLevel::All
        && receipt.group_count != 0
        && receipt.group_count == native_receipt.groups
        && receipt.native == native_receipt
        && native_receipt.capture_sha256 != [0; DIGEST_BYTES]
        && native_receipt.selector_sha256 != [0; DIGEST_BYTES]
        && native_receipt.selector_object_sha256 != [0; DIGEST_BYTES]
        && native_receipt.bundle_sha256 != [0; DIGEST_BYTES]
        && native_receipt.export_identity_sha256 != [0; DIGEST_BYTES]
        && native_receipt.object_sha256 != [0; DIGEST_BYTES]
        && native_receipt.semantic_runtime_calls == 0
        && route_closes
        && native.authenticates_receipt()
        && rebar_single_participation_artifact_identity(receipt, native)
            .is_ok_and(|identity| identity == receipt.artifact_identity_sha256)
}

fn participation_source_digest(
    source: &str,
) -> Result<[u8; DIGEST_BYTES], RebarSingleCaptureParticipationAotErrorV1> {
    let mut digest = Sha256::new();
    digest.update(b"fre-aot-regex/rebar-single-capture-source-v1\0");
    digest.update(participation_usize_u64(source.len(), "source digest extent")?.to_le_bytes());
    digest.update(source.as_bytes());
    Ok(digest.finalize().into())
}

fn rebar_single_participation_artifact_identity(
    receipt: &RebarSingleCaptureParticipationAotReceiptV1,
    native: &NativeParticipationAotArtifactV1,
) -> Result<[u8; DIGEST_BYTES], RebarSingleCaptureParticipationAotErrorV1> {
    let mut digest = Sha256::new();
    digest.update(REBAR_SINGLE_CAPTURE_PARTICIPATION_AOT_V1_IDENTITY_DOMAIN);
    digest.update(REBAR_PROFILE_IDENTITY);
    digest.update(
        participation_usize_u64(receipt.source_cardinality, "source cardinality")?.to_le_bytes(),
    );
    digest.update(participation_usize_u64(receipt.source_bytes, "source bytes")?.to_le_bytes());
    digest.update(receipt.source_sha256);
    hash_options(&mut digest, &receipt.profile.options);
    hash_target(&mut digest, receipt.target);
    digest.update([
        match receipt.capture_level {
            CaptureLevel::All => 1,
        },
        u8::from(receipt.can_match_empty),
    ]);
    digest.update(
        participation_usize_u64(receipt.group_count, "capture group identity")?.to_le_bytes(),
    );
    let native_receipt = receipt.native;
    digest.update(
        match native_receipt.strategy {
            NativeParticipationAotStrategyV1::DfaX86_64 => 1_u16,
            NativeParticipationAotStrategyV1::DfaAarch64 => 2_u16,
            NativeParticipationAotStrategyV1::NegativeEntry => 3_u16,
        }
        .to_le_bytes(),
    );
    digest.update(
        match native_receipt.decline {
            None => 0_u16,
            Some(crate::NativeParticipationAotDeclineV1::SchemaTooWide) => 1_u16,
            Some(crate::NativeParticipationAotDeclineV1::SelectorRequiresRuntime) => 2_u16,
            Some(crate::NativeParticipationAotDeclineV1::UnsupportedAssertion) => 3_u16,
        }
        .to_le_bytes(),
    );
    for value in [
        native_receipt.semantic_runtime_calls,
        native_receipt.groups,
        native_receipt.assertions,
        native_receipt.assertion_signatures,
        native_receipt.byte_classes,
        native_receipt.dfa_states,
        native_receipt.transition_cells,
        native_receipt.build_work,
        native_receipt.scratch_bytes,
        native_receipt.plan_bytes,
    ] {
        digest
            .update(participation_usize_u64(value, "native participation identity")?.to_le_bytes());
    }
    for identity in [
        native_receipt.capture_sha256,
        native_receipt.selector_sha256,
        native_receipt.selector_object_sha256,
        native_receipt.bundle_sha256,
        native_receipt.export_identity_sha256,
        native_receipt.object_sha256,
    ] {
        digest.update(identity);
    }
    for symbol in [
        native.selector_entry_symbol(),
        native.bundle_symbol(),
        native.participation_entry_symbol(),
    ] {
        digest
            .update(participation_usize_u64(symbol.len(), "route symbol identity")?.to_le_bytes());
        digest.update(symbol.as_bytes());
    }
    Ok(digest.finalize().into())
}

fn participation_usize_u64(
    value: usize,
    site: &'static str,
) -> Result<u64, RebarSingleCaptureParticipationAotErrorV1> {
    u64::try_from(value)
        .map_err(|_| RebarSingleCaptureParticipationAotErrorV1::ArithmeticOverflow(site))
}

fn source_digest(source: &str) -> Result<[u8; DIGEST_BYTES], RebarSingleCaptureAotError> {
    let mut digest = Sha256::new();
    digest.update(b"fre-aot-regex/rebar-single-capture-source-v1\0");
    digest.update(usize_u64(source.len(), "source digest extent")?.to_le_bytes());
    digest.update(source.as_bytes());
    Ok(digest.finalize().into())
}

fn rebar_single_artifact_identity(
    receipt: &RebarSingleCaptureAotReceiptV1,
    native: &crate::NativeCaptureAotArtifactV1,
) -> Result<[u8; DIGEST_BYTES], RebarSingleCaptureAotError> {
    let mut digest = Sha256::new();
    digest.update(REBAR_SINGLE_CAPTURE_AOT_V1_IDENTITY_DOMAIN);
    digest.update(REBAR_PROFILE_IDENTITY);
    digest.update(usize_u64(receipt.source_cardinality, "source cardinality")?.to_le_bytes());
    digest.update(usize_u64(receipt.source_bytes, "source bytes")?.to_le_bytes());
    digest.update(receipt.source_sha256);
    hash_options(&mut digest, &receipt.profile.options);
    hash_target(&mut digest, receipt.target);
    digest.update([
        match receipt.capture_level {
            CaptureLevel::All => 1,
        },
        u8::from(receipt.can_match_empty),
        receipt.empty_progress as u8,
    ]);
    for value in [
        receipt.group_count,
        receipt.result_slot_count,
        receipt.raw_tag_slot_count,
    ] {
        digest.update(usize_u64(value, "capture schema identity")?.to_le_bytes());
    }
    for identity in [
        receipt.selector_sha256,
        receipt.capture_sha256,
        receipt.plan_sha256,
        receipt.selector_object_sha256,
        receipt.bundle_sha256,
        receipt.export_identity_sha256,
        receipt.object_sha256,
    ] {
        digest.update(identity);
    }
    for symbol in [
        native.selector_entry_symbol(),
        native.bundle_symbol(),
        native.capture_next_symbol(),
        native.capture_materialize_symbol(),
    ] {
        digest.update(usize_u64(symbol.len(), "route symbol identity")?.to_le_bytes());
        digest.update(symbol.as_bytes());
    }
    Ok(digest.finalize().into())
}

fn hash_options(digest: &mut Sha256, options: &RustOptions) {
    digest.update([
        u8::from(options.case_insensitive),
        u8::from(options.multi_line),
        u8::from(options.dot_matches_new_line),
        u8::from(options.crlf),
        options.line_terminator,
        u8::from(options.swap_greed),
        u8::from(options.ignore_whitespace),
        u8::from(options.unicode),
        u8::from(options.octal),
    ]);
    digest.update(options.nest_limit.to_le_bytes());
}

fn hash_target(digest: &mut Sha256, target: Target) {
    digest.update([
        match target.architecture {
            Architecture::X86_64 => 1,
            Architecture::Aarch64 => 2,
        },
        match target.operating_system {
            crate::OperatingSystem::Linux => 1,
            crate::OperatingSystem::Macos => 2,
        },
        match target.abi {
            crate::CallAbi::SystemV => 1,
            crate::CallAbi::Aapcs64 => 2,
        },
    ]);
    digest.update(target.features.bits().to_le_bytes());
}

fn usize_u64(value: usize, site: &'static str) -> Result<u64, RebarSingleCaptureAotError> {
    u64::try_from(value).map_err(|_| RebarSingleCaptureAotError::ArithmeticOverflow(site))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CaptureCompileRequest, NativeCaptureAotLimitsV1, compile_captures};

    fn request(pattern: &str) -> RebarSingleCaptureAotRequestV1 {
        RebarSingleCaptureAotRequestV1::new([pattern.to_owned()], Target::x86_64_linux())
    }

    fn compile(pattern: &str) -> RebarSingleCaptureAotArtifactV1 {
        compile_rebar_single_capture_aot_v1(request(pattern)).expect("selected Rebar capture")
    }

    #[test]
    fn ordinary_capture_entry_remains_closed_to_rebar_meta() {
        let error = compile_captures(
            CaptureCompileRequest::new("(a)", Target::x86_64_linux())
                .profile(RustProfile::rebar_1_12_4()),
        )
        .expect_err("ordinary route must not admit Rebar meta");
        assert!(matches!(error, CaptureCompileError::UnsupportedProfile(_)));
        assert!(compile("(a)").authenticates_receipt());
    }

    #[test]
    fn manifest_cardinality_is_checked_before_compilation() {
        for patterns in [
            Vec::<String>::new(),
            vec!["(a)".to_owned(), "(b)".to_owned()],
        ] {
            let expected = patterns.len();
            let error =
                RebarSingleCaptureAotRequestV1::try_from_patterns(patterns, Target::x86_64_linux())
                    .expect_err("wrong cardinality");
            assert_eq!(error.actual(), expected);
            assert_eq!(error.required(), 1);
        }
        assert!(
            RebarSingleCaptureAotRequestV1::try_from_patterns(
                vec!["(a)".to_owned()],
                Target::x86_64_linux(),
            )
            .is_ok()
        );
    }

    #[test]
    fn selected_shapes_bind_schema_and_byte_empty_progress() {
        for (pattern, expected_groups, nullable) in [
            (r"", 1, true),
            (r"(ab)(c*)", 3, false),
            (r"(?-u:(\xFF)?)(b+)", 3, false),
            (r"((a*)b)", 3, false),
            (r"((ab)+)", 3, false),
            (r"(a*)", 2, true),
        ] {
            let artifact = compile(pattern);
            let receipt = artifact.receipt();
            assert!(artifact.authenticates_receipt(), "{pattern}");
            assert_eq!(receipt.source_cardinality(), 1, "{pattern}");
            assert_eq!(receipt.group_count(), expected_groups, "{pattern}");
            assert_eq!(receipt.result_slot_count(), expected_groups, "{pattern}");
            assert_eq!(
                receipt.raw_tag_slot_count(),
                expected_groups * 2,
                "{pattern}"
            );
            assert!(receipt.includes_group_zero(), "{pattern}");
            assert_eq!(receipt.can_match_empty(), nullable, "{pattern}");
            assert_eq!(
                receipt.empty_progress(),
                RebarSingleCaptureEmptyProgressV1::Byte,
                "{pattern}",
            );
            assert!(
                artifact
                    .module()
                    .required_runtime_symbols()
                    .next()
                    .is_none()
            );
            assert!(!artifact.capture_next_symbol().is_empty());
            assert!(!artifact.capture_materialize_symbol().is_empty());
        }
    }

    #[test]
    fn profile_options_and_target_are_part_of_the_outer_identity() {
        let default = compile("(a)");
        let configured = compile_rebar_single_capture_aot_v1(
            request("(a)").case_insensitive(true).unicode(false),
        )
        .expect("configured artifact");
        assert!(configured.authenticates_receipt());
        assert!(configured.receipt().profile().options.case_insensitive);
        assert!(!configured.receipt().profile().options.unicode);
        assert_ne!(
            default.receipt().artifact_identity_sha256(),
            configured.receipt().artifact_identity_sha256(),
        );
    }

    #[test]
    fn participation_wrapper_binds_exact_rebar_profile_and_selected_route() {
        let mut artifact = compile_rebar_single_capture_participation_aot_v1(
            request(r"(?:(a)|(ab))(b)?").case_insensitive(true),
            NativeParticipationAotLimitsV1::default(),
        )
        .expect("selected Rebar participation");
        let receipt = artifact.receipt();
        assert!(artifact.authenticates_receipt());
        assert_eq!(receipt.source_cardinality(), 1);
        assert_eq!(
            receipt.profile().constructor,
            RustProfile::rebar_1_12_4().constructor
        );
        assert!(receipt.profile().options.case_insensitive);
        assert_eq!(receipt.group_count(), 4);
        assert_eq!(
            receipt.native().strategy,
            NativeParticipationAotStrategyV1::DfaX86_64,
        );
        assert!(receipt.native().decline.is_none());
        assert_eq!(receipt.native().semantic_runtime_calls, 0);
        assert!(
            artifact
                .module()
                .required_runtime_symbols()
                .next()
                .is_none()
        );
        assert!(artifact.module().required_runtime_program().is_none());
        assert!(!artifact.selector_entry_symbol().is_empty());
        assert!(!artifact.bundle_symbol().is_empty());
        assert!(!artifact.participation_entry_symbol().is_empty());

        artifact.receipt.native.build_work += 1;
        assert!(!artifact.authenticates_receipt());
    }

    #[test]
    fn participation_negative_is_explicit_but_construction_errors_are_terminal() {
        let negative = compile_rebar_single_capture_participation_aot_v1(
            request(r"(?m)^((?:ab)+)$"),
            NativeParticipationAotLimitsV1::default(),
        )
        .expect("authenticated Rebar participation decline");
        assert!(negative.authenticates_receipt());
        assert_eq!(
            negative.native_receipt().strategy,
            NativeParticipationAotStrategyV1::NegativeEntry,
        );
        assert_eq!(
            negative.native_receipt().decline,
            Some(crate::NativeParticipationAotDeclineV1::UnsupportedAssertion),
        );

        assert!(matches!(
            compile_rebar_single_capture_participation_aot_v1(
                request("(a)"),
                NativeParticipationAotLimitsV1 {
                    max_plan_bytes: 0,
                    ..NativeParticipationAotLimitsV1::default()
                },
            ),
            Err(RebarSingleCaptureParticipationAotErrorV1::Participation(
                NativeParticipationAotErrorV1::Resource { .. }
            ))
        ));
    }

    #[test]
    fn semantic_decline_and_resource_error_publish_no_wrapper() {
        assert!(matches!(
            compile_rebar_single_capture_aot_v1(request(r"^(a)$")),
            Err(RebarSingleCaptureAotError::Declined(
                NativeCaptureAotDeclineV1::UnsupportedOnePassShape
            ))
        ));
        assert!(matches!(
            compile_rebar_single_capture_aot_v1(request("(a)").native_limits(
                NativeCaptureAotLimitsV1 {
                    max_bundle_bytes: 0,
                    ..NativeCaptureAotLimitsV1::default()
                }
            )),
            Err(RebarSingleCaptureAotError::Native(
                NativeCaptureAotError::Resource { .. }
            ))
        ));

        let mut compile_limits = CaptureCompileLimits::default();
        compile_limits.onepass.max_states = 0;
        assert!(matches!(
            compile_rebar_single_capture_aot_v1(request("(a)").compile_limits(compile_limits)),
            Err(RebarSingleCaptureAotError::OnePassResource(
                OnePassCaptureBuildFailure {
                    source: OnePassCaptureBuildError::Resource { .. },
                    ..
                }
            ))
        ));
    }

    #[test]
    fn receipt_rejects_wrong_cardinality_schema_and_route_object() {
        let artifact = compile("(a)");

        let mut changed = artifact.clone();
        changed.receipt.source_cardinality = 2;
        assert!(!changed.authenticates_receipt());

        let mut changed = artifact.clone();
        changed.receipt.result_slot_count += 1;
        assert!(!changed.authenticates_receipt());

        let mut changed = artifact.clone();
        changed.receipt.target = Target::aarch64_linux();
        assert!(!changed.authenticates_receipt());

        let mut changed = artifact;
        changed.native = compile("(b)").native;
        assert!(!changed.authenticates_receipt());
    }
}
