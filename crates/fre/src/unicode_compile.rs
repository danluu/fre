use std::sync::Arc;

use fre_syntax::{
    AdmissionPolicy, AdmissionStatus, CacheKey, CanonicalPattern, CompatibilityProfile,
    ParseSummary, RustProfile, SafetyEnvelope,
};
use regex_syntax::hir::{Class, Hir, HirKind};

const MAGIC: &[u8; 16] = b"FREUCOMPv1\0\0\0\0\0\0";
const HEADER_BYTES: usize = MAGIC.len() + 8;
const RECORD_HEADER_BYTES: usize = 9;
const TAG_EMPTY: u8 = 0;
const TAG_LITERAL: u8 = 1;
const TAG_SCALAR_CLASS: u8 = 2;
const TAG_LOOK: u8 = 3;
const TAG_CAPTURE: u8 = 4;
const TAG_REPETITION: u8 = 5;
const TAG_CONCAT: u8 = 6;
const TAG_ALTERNATION: u8 = 7;

/// Separately limited Unicode compile-artifact construction resource.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum UnicodeCompileResource {
    /// Exact retained byte encoding.
    ArtifactBytes,
    /// Preflight and encoding work.
    Work,
    /// Literal scalars and class-range endpoints.
    ScalarEncodings,
}

/// Complete limits for one fresh Unicode compile artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnicodeCompileBuildLimits {
    /// Syntax admission policy retained in the construction identity.
    pub admission: AdmissionPolicy,
    /// Non-configurable parser safety envelope.
    pub syntax_safety: SafetyEnvelope,
    /// Maximum exact retained artifact bytes.
    pub max_artifact_bytes: usize,
    /// Maximum preflight and encoding work.
    pub max_work: usize,
    /// Maximum literal scalars plus class-range endpoints.
    pub max_scalar_encodings: usize,
}

impl Default for UnicodeCompileBuildLimits {
    fn default() -> Self {
        Self {
            admission: AdmissionPolicy::default(),
            syntax_safety: SafetyEnvelope::default(),
            max_artifact_bytes: 16 << 20,
            max_work: 16 << 20,
            max_scalar_encodings: 1 << 20,
        }
    }
}

/// Typed construction refusal for a compile-only Unicode artifact.
#[derive(Debug)]
pub enum UnicodeCompileBuildError {
    /// Canonical pinned syntax construction refused the request.
    Syntax(fre_syntax::ParseError),
    /// The supplied profile disabled Unicode mode.
    UnicodeDisabled,
    /// The supplied constructor was not the pinned Rebar Rust-byte surface.
    ProfileMismatch,
    /// A locally byte-oriented literal could match invalid UTF-8.
    InvalidUtf8Literal,
    /// A locally byte-oriented class could match invalid UTF-8.
    InvalidByteClass,
    /// Exact preflight exceeded a named construction resource.
    ResourceLimit {
        /// Exhausted resource.
        resource: UnicodeCompileResource,
        /// Exact required value.
        required: usize,
        /// Supplied limit.
        limit: usize,
    },
    /// Checked construction arithmetic overflowed.
    ArithmeticOverflow(UnicodeCompileResource),
    /// Artifact storage allocation failed after successful preflight.
    AllocationFailed {
        /// Exact bytes requested after successful preflight.
        bytes: usize,
    },
    /// Independently checked construction facts disagreed.
    InternalInvariant(&'static str),
}

impl core::fmt::Display for UnicodeCompileBuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Syntax(error) => write!(f, "Unicode compile syntax failed: {error}"),
            Self::UnicodeDisabled => f.write_str("Unicode compile artifact requires Unicode mode"),
            Self::ProfileMismatch => {
                f.write_str("Unicode compile artifact requires the pinned Rebar constructor")
            }
            Self::InvalidUtf8Literal => {
                f.write_str("Unicode compile artifact excludes an invalid UTF-8 literal")
            }
            Self::InvalidByteClass => {
                f.write_str("Unicode compile artifact excludes non-ASCII byte classes")
            }
            Self::ResourceLimit {
                resource,
                required,
                limit,
            } => write!(f, "Unicode compile resource {resource:?} needs {required}, limit {limit}"),
            Self::ArithmeticOverflow(resource) => {
                write!(f, "Unicode compile resource {resource:?} overflowed")
            }
            Self::AllocationFailed { bytes } => {
                write!(f, "allocator refused {bytes} Unicode artifact bytes")
            }
            Self::InternalInvariant(detail) => {
                write!(f, "Unicode compile invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for UnicodeCompileBuildError {}

/// Stable identity of complete compile-artifact bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UnicodeCompileArtifactId([u8; 16]);

impl UnicodeCompileArtifactId {
    /// Raw stable identity bytes.
    #[must_use]
    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }
}

/// Complete construction receipt for one artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnicodeCompileBuildReport {
    /// Exact source/profile/admission key from pinned syntax construction.
    pub syntax_key: Arc<CacheKey>,
    /// Admission status established by syntax construction.
    pub admission: AdmissionStatus,
    /// Complete bounded canonical-HIR summary.
    pub syntax: ParseSummary,
    /// Stable identity of exact retained bytes.
    pub artifact_id: UnicodeCompileArtifactId,
    /// Exact retained artifact length.
    pub artifact_bytes: usize,
    /// Exact encoded canonical-HIR node count.
    pub hir_nodes: usize,
    /// Literal scalars plus scalar-class range endpoints.
    pub scalar_encodings: usize,
    /// Exact preflight construction work.
    pub work: usize,
}

/// Fresh builder for a compile-only canonical Unicode artifact.
#[derive(Clone, Debug)]
pub struct UnicodeCompileArtifactBuilder {
    pattern: String,
    profile: RustProfile,
    limits: UnicodeCompileBuildLimits,
}

impl UnicodeCompileArtifactBuilder {
    /// Start from the pinned Rust profile with Unicode mode enabled.
    #[must_use]
    pub fn new(pattern: impl Into<String>) -> Self {
        let mut profile = RustProfile::rebar_1_12_4();
        profile.options.unicode = true;
        Self {
            pattern: pattern.into(),
            profile,
            limits: UnicodeCompileBuildLimits::default(),
        }
    }

    /// Select the exact Rust release-stack and syntax options.
    #[must_use]
    pub fn profile(mut self, profile: RustProfile) -> Self {
        self.profile = profile;
        self
    }

    /// Replace all checked artifact-construction limits.
    #[must_use]
    pub const fn limits(mut self, limits: UnicodeCompileBuildLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Construct and publish a complete artifact without deferred lowering.
    ///
    /// # Errors
    ///
    /// Returns a typed syntax, invalid-byte, resource, allocation or invariant
    /// refusal. Exact artifact bytes and work are preflighted before artifact
    /// storage is requested.
    pub fn build(self) -> Result<UnicodeCompileArtifact, UnicodeCompileBuildError> {
        if !self.profile.options.unicode {
            return Err(UnicodeCompileBuildError::UnicodeDisabled);
        }
        if !matches!(
            &self.profile.constructor,
            fre_syntax::RustConstructor::RebarMeta { .. }
        ) {
            return Err(UnicodeCompileBuildError::ProfileMismatch);
        }
        let request = fre_syntax::ParseRequest::rust(
            self.pattern,
            CompatibilityProfile::RustBytes(self.profile),
        )
        .with_admission(self.limits.admission)
        .with_safety_envelope(self.limits.syntax_safety);
        let parsed = fre_syntax::parse(request).map_err(UnicodeCompileBuildError::Syntax)?;
        let syntax_key = Arc::new(parsed.key);
        let admission = parsed.admission_status;
        let syntax = parsed.summary;
        let CanonicalPattern::Rust(rust) = parsed.pattern else {
            return Err(UnicodeCompileBuildError::InternalInvariant(
                "Rust request produced another canonical pattern family",
            ));
        };
        let mut measure = Measure::new(self.limits)?;
        measure_hir(&rust.hir, &mut measure)?;
        let expected_nodes = usize::try_from(syntax.hir_nodes).map_err(|_| {
            UnicodeCompileBuildError::ArithmeticOverflow(UnicodeCompileResource::Work)
        })?;
        if measure.nodes != expected_nodes {
            return Err(UnicodeCompileBuildError::InternalInvariant(
                "syntax and artifact HIR node counts differ",
            ));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(measure.bytes)
            .map_err(|_| UnicodeCompileBuildError::AllocationFailed {
                bytes: measure.bytes,
            })?;
        bytes.extend_from_slice(MAGIC);
        put_u64(&mut bytes, measure.nodes)?;
        encode_hir(&rust.hir, &mut bytes)?;
        if bytes.len() != measure.bytes {
            return Err(UnicodeCompileBuildError::InternalInvariant(
                "artifact encoding differs from exact preflight",
            ));
        }
        let bytes = bytes.into_boxed_slice();
        let artifact_id = artifact_identity(&bytes);
        let report = UnicodeCompileBuildReport {
            syntax_key,
            admission,
            syntax,
            artifact_id,
            artifact_bytes: bytes.len(),
            hir_nodes: measure.nodes,
            scalar_encodings: measure.scalars,
            work: measure.work,
        };
        let artifact = UnicodeCompileArtifact { bytes, report };
        artifact
            .verify_complete()
            .map_err(UnicodeCompileBuildError::InternalInvariant)?;
        Ok(artifact)
    }
}

/// Complete immutable compile-only Unicode artifact.
#[derive(Debug)]
pub struct UnicodeCompileArtifact {
    bytes: Box<[u8]>,
    report: UnicodeCompileBuildReport,
}

impl UnicodeCompileArtifact {
    /// Complete immutable construction receipt.
    #[must_use]
    pub const fn report(&self) -> &UnicodeCompileBuildReport {
        &self.report
    }

    /// Exact retained artifact bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Iterate every canonical literal scalar and class-range endpoint.
    #[must_use]
    pub fn scalar_encodings(&self) -> UnicodeScalarIter<'_> {
        UnicodeScalarIter::new(&self.bytes)
    }

    /// Recheck complete framing, scalar encodings and byte identity.
    ///
    /// This is a structural verification seam, not a matcher and not part of
    /// the construction timing boundary.
    pub fn verify_complete(&self) -> Result<(), &'static str> {
        let bytes = self.bytes();
        if bytes.len() != self.report.artifact_bytes {
            return Err("artifact byte count differs");
        }
        if bytes.get(..MAGIC.len()) != Some(MAGIC.as_slice()) {
            return Err("artifact magic differs");
        }
        let expected_nodes = read_u64(bytes, MAGIC.len()).ok_or("artifact node count missing")?;
        let expected_nodes = usize::try_from(expected_nodes).map_err(|_| "node count overflow")?;
        let mut offset = HEADER_BYTES;
        let mut nodes = 0_usize;
        while offset < bytes.len() {
            let tag = *bytes.get(offset).ok_or("record tag missing")?;
            if tag > TAG_ALTERNATION {
                return Err("record tag unknown");
            }
            let length_at = offset.checked_add(1).ok_or("record offset overflow")?;
            let payload_len = read_u64(bytes, length_at).ok_or("record length missing")?;
            let payload_len = usize::try_from(payload_len).map_err(|_| "record length overflow")?;
            let payload = offset.checked_add(RECORD_HEADER_BYTES).ok_or("record overflow")?;
            offset = payload.checked_add(payload_len).ok_or("record overflow")?;
            if offset > bytes.len() {
                return Err("record outside artifact");
            }
            nodes = nodes.checked_add(1).ok_or("node count overflow")?;
        }
        if offset != bytes.len() || nodes != expected_nodes || nodes != self.report.hir_nodes {
            return Err("artifact framing count differs");
        }
        let mut scalars = 0_usize;
        for scalar in self.scalar_encodings() {
            let text = core::str::from_utf8(scalar.as_bytes()).map_err(|_| "invalid scalar UTF-8")?;
            let mut chars = text.chars();
            let character = chars.next().ok_or("empty scalar encoding")?;
            if chars.next().is_some() {
                return Err("scalar encoding contains multiple scalars");
            }
            let mut canonical = [0_u8; 4];
            if character.encode_utf8(&mut canonical).as_bytes() != scalar.as_bytes() {
                return Err("scalar encoding is not canonical UTF-8");
            }
            scalars = scalars.checked_add(1).ok_or("scalar count overflow")?;
        }
        if scalars != self.report.scalar_encodings {
            return Err("scalar count differs");
        }
        if artifact_identity(bytes) != self.report.artifact_id {
            return Err("artifact identity differs");
        }
        Ok(())
    }
}

/// One canonical UTF-8 scalar retained by the artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnicodeScalarEncoding {
    bytes: [u8; 4],
    len: u8,
}

impl UnicodeScalarEncoding {
    /// Exact canonical one-scalar UTF-8 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

/// Iterator over literal scalars and scalar-class range endpoints.
#[derive(Clone, Debug)]
pub struct UnicodeScalarIter<'a> {
    bytes: &'a [u8],
    record: usize,
    scalar: usize,
    scalar_end: usize,
    remaining: usize,
}

impl<'a> UnicodeScalarIter<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            record: HEADER_BYTES,
            scalar: 0,
            scalar_end: 0,
            remaining: 0,
        }
    }
}

impl Iterator for UnicodeScalarIter<'_> {
    type Item = UnicodeScalarEncoding;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.remaining > 0 {
                let width = usize::from(*self.bytes.get(self.scalar)?);
                let start = self.scalar.checked_add(1)?;
                let end = start.checked_add(width)?;
                if width == 0 || width > 4 || end > self.scalar_end {
                    self.remaining = 0;
                    return None;
                }
                let mut bytes = [0_u8; 4];
                bytes[..width].copy_from_slice(self.bytes.get(start..end)?);
                self.scalar = end;
                self.remaining -= 1;
                return Some(UnicodeScalarEncoding {
                    bytes,
                    len: u8::try_from(width).ok()?,
                });
            }
            if self.record >= self.bytes.len() {
                return None;
            }
            let tag = *self.bytes.get(self.record)?;
            let length_at = self.record.checked_add(1)?;
            let payload_len = usize::try_from(read_u64(self.bytes, length_at)?).ok()?;
            let payload = self.record.checked_add(RECORD_HEADER_BYTES)?;
            let end = payload.checked_add(payload_len)?;
            if end > self.bytes.len() {
                return None;
            }
            self.record = end;
            if matches!(tag, TAG_LITERAL | TAG_SCALAR_CLASS) {
                let units = usize::try_from(read_u64(self.bytes, payload)?).ok()?;
                self.remaining = if tag == TAG_SCALAR_CLASS {
                    units.checked_mul(2)?
                } else {
                    units
                };
                self.scalar = payload.checked_add(8)?;
                self.scalar_end = end;
            }
        }
    }
}

#[derive(Clone, Copy)]
struct Measure {
    limits: UnicodeCompileBuildLimits,
    bytes: usize,
    nodes: usize,
    scalars: usize,
    work: usize,
}

impl Measure {
    fn new(limits: UnicodeCompileBuildLimits) -> Result<Self, UnicodeCompileBuildError> {
        enforce(HEADER_BYTES, limits.max_artifact_bytes, UnicodeCompileResource::ArtifactBytes)?;
        Ok(Self {
            limits,
            bytes: HEADER_BYTES,
            nodes: 0,
            scalars: 0,
            work: 0,
        })
    }

    fn record(&mut self, payload: usize) -> Result<(), UnicodeCompileBuildError> {
        self.nodes = checked_add(self.nodes, 1, UnicodeCompileResource::Work)?;
        self.work = checked_add(self.work, 1, UnicodeCompileResource::Work)?;
        enforce(self.work, self.limits.max_work, UnicodeCompileResource::Work)?;
        self.bytes = checked_add(
            self.bytes,
            checked_add(RECORD_HEADER_BYTES, payload, UnicodeCompileResource::ArtifactBytes)?,
            UnicodeCompileResource::ArtifactBytes,
        )?;
        enforce(
            self.bytes,
            self.limits.max_artifact_bytes,
            UnicodeCompileResource::ArtifactBytes,
        )
    }

    fn scalar(&mut self, width: usize) -> Result<(), UnicodeCompileBuildError> {
        self.scalars = checked_add(self.scalars, 1, UnicodeCompileResource::ScalarEncodings)?;
        enforce(
            self.scalars,
            self.limits.max_scalar_encodings,
            UnicodeCompileResource::ScalarEncodings,
        )?;
        self.work = checked_add(self.work, width, UnicodeCompileResource::Work)?;
        enforce(self.work, self.limits.max_work, UnicodeCompileResource::Work)
    }
}

fn measure_hir(hir: &Hir, measure: &mut Measure) -> Result<(), UnicodeCompileBuildError> {
    match hir.kind() {
        HirKind::Empty => measure.record(0),
        HirKind::Literal(literal) => {
            let text = core::str::from_utf8(&literal.0)
                .map_err(|_| UnicodeCompileBuildError::InvalidUtf8Literal)?;
            let mut payload = 8_usize;
            for scalar in text.chars() {
                let width = scalar.len_utf8();
                measure.scalar(width)?;
                payload = checked_add(
                    payload,
                    checked_add(1, width, UnicodeCompileResource::ArtifactBytes)?,
                    UnicodeCompileResource::ArtifactBytes,
                )?;
            }
            measure.record(payload)
        }
        HirKind::Class(Class::Unicode(class)) => {
            let mut payload = 8_usize;
            for range in class.ranges() {
                for scalar in [range.start(), range.end()] {
                    let width = scalar.len_utf8();
                    measure.scalar(width)?;
                    payload = checked_add(
                        payload,
                        checked_add(1, width, UnicodeCompileResource::ArtifactBytes)?,
                        UnicodeCompileResource::ArtifactBytes,
                    )?;
                }
            }
            measure.record(payload)
        }
        HirKind::Class(Class::Bytes(class)) => {
            let mut payload = 8_usize;
            for range in class.ranges() {
                if !range.end().is_ascii() {
                    return Err(UnicodeCompileBuildError::InvalidByteClass);
                }
                for scalar in [char::from(range.start()), char::from(range.end())] {
                    measure.scalar(1)?;
                    payload = checked_add(payload, 2, UnicodeCompileResource::ArtifactBytes)?;
                    let _ = scalar;
                }
            }
            measure.record(payload)
        }
        HirKind::Look(_) => measure.record(4),
        HirKind::Capture(capture) => {
            let name = capture.name.as_deref().unwrap_or("");
            let payload = checked_add(12, name.len(), UnicodeCompileResource::ArtifactBytes)?;
            measure.record(payload)?;
            measure_hir(capture.sub.as_ref(), measure)
        }
        HirKind::Repetition(repetition) => {
            measure.record(10)?;
            measure_hir(repetition.sub.as_ref(), measure)
        }
        HirKind::Concat(children) | HirKind::Alternation(children) => {
            measure.record(8)?;
            for child in children {
                measure_hir(child, measure)?;
            }
            Ok(())
        }
    }
}

fn encode_hir(hir: &Hir, output: &mut Vec<u8>) -> Result<(), UnicodeCompileBuildError> {
    match hir.kind() {
        HirKind::Empty => record(output, TAG_EMPTY, &[]),
        HirKind::Literal(literal) => {
            let text = core::str::from_utf8(&literal.0)
                .map_err(|_| UnicodeCompileBuildError::InvalidUtf8Literal)?;
            let scalar_count = text.chars().count();
            let payload_len = text.chars().try_fold(8_usize, |total, scalar| {
                checked_add(
                    total,
                    checked_add(1, scalar.len_utf8(), UnicodeCompileResource::ArtifactBytes)?,
                    UnicodeCompileResource::ArtifactBytes,
                )
            })?;
            record_header(output, TAG_LITERAL, payload_len)?;
            put_u64(output, scalar_count)?;
            for scalar in text.chars() {
                put_scalar(output, scalar)?;
            }
            Ok(())
        }
        HirKind::Class(Class::Unicode(class)) => {
            let payload_len = class.ranges().iter().try_fold(8_usize, |total, range| {
                let start = checked_add(
                    1,
                    range.start().len_utf8(),
                    UnicodeCompileResource::ArtifactBytes,
                )?;
                let end = checked_add(
                    1,
                    range.end().len_utf8(),
                    UnicodeCompileResource::ArtifactBytes,
                )?;
                checked_add(
                    checked_add(total, start, UnicodeCompileResource::ArtifactBytes)?,
                    end,
                    UnicodeCompileResource::ArtifactBytes,
                )
            })?;
            record_header(output, TAG_SCALAR_CLASS, payload_len)?;
            put_u64(output, class.ranges().len())?;
            for range in class.ranges() {
                put_scalar(output, range.start())?;
                put_scalar(output, range.end())?;
            }
            Ok(())
        }
        HirKind::Class(Class::Bytes(class)) => {
            let pairs = class.ranges().len().checked_mul(4).ok_or(
                UnicodeCompileBuildError::ArithmeticOverflow(
                    UnicodeCompileResource::ArtifactBytes,
                ),
            )?;
            let payload_len = checked_add(8, pairs, UnicodeCompileResource::ArtifactBytes)?;
            record_header(output, TAG_SCALAR_CLASS, payload_len)?;
            put_u64(output, class.ranges().len())?;
            for range in class.ranges() {
                if !range.end().is_ascii() {
                    return Err(UnicodeCompileBuildError::InvalidByteClass);
                }
                put_scalar(output, char::from(range.start()))?;
                put_scalar(output, char::from(range.end()))?;
            }
            Ok(())
        }
        HirKind::Look(look) => record(output, TAG_LOOK, &look.as_repr().to_le_bytes()),
        HirKind::Capture(capture) => {
            let name = capture.name.as_deref().unwrap_or("").as_bytes();
            let payload_len = checked_add(12, name.len(), UnicodeCompileResource::ArtifactBytes)?;
            record_header(output, TAG_CAPTURE, payload_len)?;
            output.extend_from_slice(&capture.index.to_le_bytes());
            put_u64(output, name.len())?;
            output.extend_from_slice(name);
            encode_hir(capture.sub.as_ref(), output)
        }
        HirKind::Repetition(repetition) => {
            record_header(output, TAG_REPETITION, 10)?;
            output.extend_from_slice(&repetition.min.to_le_bytes());
            output.push(u8::from(repetition.max.is_some()));
            output.extend_from_slice(&repetition.max.unwrap_or(0).to_le_bytes());
            output.push(u8::from(repetition.greedy));
            encode_hir(repetition.sub.as_ref(), output)
        }
        HirKind::Concat(children) | HirKind::Alternation(children) => {
            let tag = if matches!(hir.kind(), HirKind::Concat(_)) {
                TAG_CONCAT
            } else {
                TAG_ALTERNATION
            };
            record_header(output, tag, 8)?;
            put_u64(output, children.len())?;
            for child in children {
                encode_hir(child, output)?;
            }
            Ok(())
        }
    }
}

fn record(output: &mut Vec<u8>, tag: u8, payload: &[u8]) -> Result<(), UnicodeCompileBuildError> {
    record_header(output, tag, payload.len())?;
    output.extend_from_slice(payload);
    Ok(())
}

fn record_header(
    output: &mut Vec<u8>,
    tag: u8,
    payload_len: usize,
) -> Result<(), UnicodeCompileBuildError> {
    output.push(tag);
    put_u64(output, payload_len)
}

fn put_scalar(output: &mut Vec<u8>, scalar: char) -> Result<(), UnicodeCompileBuildError> {
    let mut encoded = [0_u8; 4];
    let bytes = scalar.encode_utf8(&mut encoded).as_bytes();
    output.push(u8::try_from(bytes.len()).map_err(|_| {
        UnicodeCompileBuildError::InternalInvariant("UTF-8 scalar width does not fit u8")
    })?);
    output.extend_from_slice(bytes);
    Ok(())
}

fn put_u64(output: &mut Vec<u8>, value: usize) -> Result<(), UnicodeCompileBuildError> {
    let value = u64::try_from(value).map_err(|_| {
        UnicodeCompileBuildError::ArithmeticOverflow(UnicodeCompileResource::ArtifactBytes)
    })?;
    output.extend_from_slice(&value.to_le_bytes());
    Ok(())
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let raw: [u8; 8] = bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_le_bytes(raw))
}

fn checked_add(
    left: usize,
    right: usize,
    resource: UnicodeCompileResource,
) -> Result<usize, UnicodeCompileBuildError> {
    left.checked_add(right)
        .ok_or(UnicodeCompileBuildError::ArithmeticOverflow(resource))
}

fn enforce(
    required: usize,
    limit: usize,
    resource: UnicodeCompileResource,
) -> Result<(), UnicodeCompileBuildError> {
    if required > limit {
        return Err(UnicodeCompileBuildError::ResourceLimit {
            resource,
            required,
            limit,
        });
    }
    Ok(())
}

fn artifact_identity(bytes: &[u8]) -> UnicodeCompileArtifactId {
    let mut first = 0xcbf2_9ce4_8422_2325_u64;
    let mut second = 0x8422_2325_cbf2_9ce4_u64;
    for &byte in b"fre.unicode.compile-artifact.rust-bytes.v1".iter().chain(bytes) {
        first ^= u64::from(byte);
        first = first.wrapping_mul(0x0000_0100_0000_01B3);
        second ^= u64::from(byte).rotate_left(3);
        second = second.wrapping_mul(0x9E37_79B1_85EB_CA87);
    }
    let mut identity = [0_u8; 16];
    identity[..8].copy_from_slice(&first.to_le_bytes());
    identity[8..].copy_from_slice(&second.to_le_bytes());
    UnicodeCompileArtifactId(identity)
}
    /// Replace all checked artifact-construction limits.
    /// Exact retained artifact bytes.
    /// Iterate every canonical literal scalar and class-range endpoint.
