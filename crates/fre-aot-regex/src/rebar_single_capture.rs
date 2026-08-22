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
    OnePassCaptureBuildError, OnePassCaptureBuildFailure, OutputContract, Target,
};

pub const REBAR_SINGLE_CAPTURE_AOT_V1_SOURCE_CARDINALITY: usize = 1;
pub const REBAR_SINGLE_CAPTURE_AOT_V1_IDENTITY_DOMAIN: &[u8] =
    b"fre-aot-regex/rebar-single-capture-aot-v1\0";

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
