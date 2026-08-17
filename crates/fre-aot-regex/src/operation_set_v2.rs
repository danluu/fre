//! Canonical V2 operation-set wire with capture-program membership.
//!
//! V2 preserves V1's one-stage/one-output scalar roots and exact contiguous
//! table envelope. It adds a second member kind and exactly one capture
//! operation: whole-domain capture-participation Count. Capture members are
//! accepted only after an allocation-free full-wire census proves that every
//! match consumes at least one byte. Per-line capture participation, capture
//! tuple outputs, many-pattern composition, native lowering, and runtime
//! session preparation are deliberately outside this wire/semantic layer.

use core::{cmp::Ordering, fmt};
use std::collections::HashMap;

use fre_capture_lab::{
    CAPTURE_PROGRAM_V1_HEADER_BYTES, CaptureProgramV1, CaptureProgramV1Census,
    CaptureProgramV1Error, CaptureProgramV1Limits,
};
use sha2::{Digest, Sha256};

use crate::operation_set::{
    AotOperationSetEnvelopeError, AotOperationSetEnvelopeLayout, AotOperationSetEnvelopeSpec,
    HEADER_BYTES_OFFSET, HEADER_FLAGS_OFFSET, HEADER_MEMBER_COUNT_OFFSET,
    HEADER_MEMBER_TABLE_OFFSET, HEADER_OUTPUT_COUNT_OFFSET, HEADER_OUTPUT_TABLE_OFFSET,
    HEADER_PAYLOAD_OFFSET, HEADER_RESERVED_OFFSET, HEADER_RESERVED0_OFFSET,
    HEADER_ROOT_COUNT_OFFSET, HEADER_ROOT_TABLE_OFFSET, HEADER_SHARED_COUNT_OFFSET,
    HEADER_SHARED_TABLE_OFFSET, HEADER_STAGE_COUNT_OFFSET, HEADER_STAGE_TABLE_OFFSET,
    HEADER_TOTAL_BYTES_OFFSET, HEADER_VERSION_OFFSET, validate_operation_set_envelope,
};
use crate::{CompiledProgram, OutputContract, PROGRAM_HEADER_LEN, ProgramFormatError};

/// Fixed magic at byte zero of every V2 operation set.
pub const AOT_OPERATION_SET_V2_MAGIC: [u8; 8] = *b"FREAOS2\0";
/// Stable wire version encoded in the fixed header.
pub const AOT_OPERATION_SET_V2_VERSION: u16 = 2;
/// Bytes in the fixed V2 header.
pub const AOT_OPERATION_SET_V2_HEADER_BYTES: usize = 128;
/// Bytes in one V2 member descriptor.
pub const AOT_OPERATION_SET_V2_MEMBER_DESCRIPTOR_BYTES: usize = 32;
/// Bytes in one reserved shared-member descriptor.
pub const AOT_OPERATION_SET_V2_SHARED_DESCRIPTOR_BYTES: usize = 24;
/// Bytes in one V2 root descriptor.
pub const AOT_OPERATION_SET_V2_ROOT_DESCRIPTOR_BYTES: usize = 24;
/// Bytes in one V2 stage descriptor.
pub const AOT_OPERATION_SET_V2_STAGE_DESCRIPTOR_BYTES: usize = 40;
/// Bytes in one V2 output descriptor.
pub const AOT_OPERATION_SET_V2_OUTPUT_DESCRIPTOR_BYTES: usize = 16;
/// Sentinel used when a member references no shared or auxiliary object.
pub const AOT_OPERATION_SET_V2_NONE_INDEX: u32 = u32::MAX;
/// Maximum complete V2 wire accepted by the builder or strict reader.
pub const MAX_AOT_OPERATION_SET_V2_BYTES: usize = 1024 * 1024 * 1024;
/// Domain separating a V2 set identity from V1 and from member identities.
pub const AOT_OPERATION_SET_V2_IDENTITY_DOMAIN: &[u8] = b"fre.aot-operation-set.v2\0";

const MEMBER_KIND_COMPILED_PROGRAM: u32 = 1;
const MEMBER_KIND_CAPTURE_PROGRAM_V1: u32 = 2;
const OUTPUT_KIND_ONE_RECORD: u16 = 1;
const OUTPUT_KIND_SCALAR_U64: u16 = 2;
const BUILDER_INITIAL_ROOT_RESERVE_LIMIT: usize = 4_096;

#[cfg(test)]
std::thread_local! {
    static TEST_STRUCTURE_MEMBER_HASHES: core::cell::Cell<usize> = const {
        core::cell::Cell::new(0)
    };
}

const AOT_OPERATION_SET_V2_ENVELOPE_SPEC: AotOperationSetEnvelopeSpec =
    AotOperationSetEnvelopeSpec {
        magic: AOT_OPERATION_SET_V2_MAGIC,
        version: AOT_OPERATION_SET_V2_VERSION,
        header_bytes: AOT_OPERATION_SET_V2_HEADER_BYTES,
        member_descriptor_bytes: AOT_OPERATION_SET_V2_MEMBER_DESCRIPTOR_BYTES,
        root_descriptor_bytes: AOT_OPERATION_SET_V2_ROOT_DESCRIPTOR_BYTES,
        stage_descriptor_bytes: AOT_OPERATION_SET_V2_STAGE_DESCRIPTOR_BYTES,
        output_descriptor_bytes: AOT_OPERATION_SET_V2_OUTPUT_DESCRIPTOR_BYTES,
        max_wire_bytes: MAX_AOT_OPERATION_SET_V2_BYTES,
        count_mismatch: "V2 root, stage, and output counts differ",
    };

// V2 deliberately reuses the shared fixed-header field map. Keep these
// compile-time assertions beside its version-specific descriptor geometry so
// a future envelope edit cannot silently move only one reader or emitter.
#[allow(
    clippy::assertions_on_constants,
    reason = "these assertions intentionally make cross-version layout drift a compile error"
)]
const _: () = {
    assert!(HEADER_VERSION_OFFSET == 8);
    assert!(HEADER_BYTES_OFFSET == 10);
    assert!(HEADER_FLAGS_OFFSET == 12);
    assert!(HEADER_TOTAL_BYTES_OFFSET == 16);
    assert!(HEADER_MEMBER_COUNT_OFFSET == 24);
    assert!(HEADER_SHARED_COUNT_OFFSET == 28);
    assert!(HEADER_ROOT_COUNT_OFFSET == 32);
    assert!(HEADER_STAGE_COUNT_OFFSET == 36);
    assert!(HEADER_OUTPUT_COUNT_OFFSET == 40);
    assert!(HEADER_RESERVED0_OFFSET == 44);
    assert!(HEADER_MEMBER_TABLE_OFFSET == 48);
    assert!(HEADER_SHARED_TABLE_OFFSET == 56);
    assert!(HEADER_ROOT_TABLE_OFFSET == 64);
    assert!(HEADER_STAGE_TABLE_OFFSET == 72);
    assert!(HEADER_OUTPUT_TABLE_OFFSET == 80);
    assert!(HEADER_PAYLOAD_OFFSET == 88);
    assert!(HEADER_RESERVED_OFFSET == 96);
    assert!(AOT_OPERATION_SET_V2_HEADER_BYTES == 128);
};

/// Stable V2 member family.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u32)]
pub enum AotOperationSetMemberKindV2 {
    /// Capture-free [`CompiledProgram`] wire.
    CompiledProgram = MEMBER_KIND_COMPILED_PROGRAM,
    /// Stable [`CaptureProgramV1`] wire.
    CaptureProgramV1 = MEMBER_KIND_CAPTURE_PROGRAM_V1,
}

impl AotOperationSetMemberKindV2 {
    const fn tag(self) -> u32 {
        match self {
            Self::CompiledProgram => MEMBER_KIND_COMPILED_PROGRAM,
            Self::CaptureProgramV1 => MEMBER_KIND_CAPTURE_PROGRAM_V1,
        }
    }

    fn from_tag(tag: u32, index: u32) -> Result<Self, AotOperationSetV2Error> {
        match tag {
            MEMBER_KIND_COMPILED_PROGRAM => Ok(Self::CompiledProgram),
            MEMBER_KIND_CAPTURE_PROGRAM_V1 => Ok(Self::CaptureProgramV1),
            _ => Err(AotOperationSetV2Error::UnsupportedTag {
                table: "member",
                index,
                tag,
            }),
        }
    }
}

/// Builder input retaining the member wire's declared family.
#[derive(Clone, Copy, Debug)]
pub enum AotOperationSetMemberInputV2<B> {
    /// One capture-free compiled scalar program.
    CompiledProgram(B),
    /// One stable capture program.
    CaptureProgramV1(B),
}

impl<B: AsRef<[u8]>> AotOperationSetMemberInputV2<B> {
    fn kind(&self) -> AotOperationSetMemberKindV2 {
        match self {
            Self::CompiledProgram(_) => AotOperationSetMemberKindV2::CompiledProgram,
            Self::CaptureProgramV1(_) => AotOperationSetMemberKindV2::CaptureProgramV1,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        match self {
            Self::CompiledProgram(bytes) | Self::CaptureProgramV1(bytes) => bytes.as_ref(),
        }
    }
}

/// Reduction axis of one V2 operation stage.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum AotReducerV2 {
    /// Select at most one result under a compiled program's output contract.
    SelectOne = 1,
    /// Count selected values.
    Count = 2,
    /// Sum selected Span widths.
    SpanSum = 3,
}

impl AotReducerV2 {
    const fn tag(self) -> u16 {
        match self {
            Self::SelectOne => 1,
            Self::Count => 2,
            Self::SpanSum => 3,
        }
    }

    fn from_tag(tag: u16, index: u32) -> Result<Self, AotOperationSetV2Error> {
        match tag {
            1 => Ok(Self::SelectOne),
            2 => Ok(Self::Count),
            3 => Ok(Self::SpanSum),
            _ => Err(AotOperationSetV2Error::UnsupportedTag {
                table: "stage reducer",
                index,
                tag: u32::from(tag),
            }),
        }
    }
}

/// Projection axis of one V2 operation stage.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum AotProjectionV2 {
    /// Preserve a compiled member's declared scalar output contract.
    ProgramOutput = 1,
    /// Project non-overlapping compiled matches as Spans.
    Span = 2,
    /// Project each capture-program match to its participating group count,
    /// including group zero.
    CaptureParticipation = 3,
}

impl AotProjectionV2 {
    const fn tag(self) -> u16 {
        match self {
            Self::ProgramOutput => 1,
            Self::Span => 2,
            Self::CaptureParticipation => 3,
        }
    }

    fn from_tag(tag: u16, index: u32) -> Result<Self, AotOperationSetV2Error> {
        match tag {
            1 => Ok(Self::ProgramOutput),
            2 => Ok(Self::Span),
            3 => Ok(Self::CaptureParticipation),
            _ => Err(AotOperationSetV2Error::UnsupportedTag {
                table: "stage projection",
                index,
                tag: u32::from(tag),
            }),
        }
    }
}

/// Input-domain axis of one V2 operation stage.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum AotDomainV2 {
    /// Apply the operation once to the whole supplied source domain.
    Whole = 1,
    /// Apply matching independently to canonical LF/CRLF line domains.
    PerLine = 2,
}

impl AotDomainV2 {
    const fn tag(self) -> u16 {
        match self {
            Self::Whole => 1,
            Self::PerLine => 2,
        }
    }

    fn from_tag(tag: u16, index: u32) -> Result<Self, AotOperationSetV2Error> {
        match tag {
            1 => Ok(Self::Whole),
            2 => Ok(Self::PerLine),
            _ => Err(AotOperationSetV2Error::UnsupportedTag {
                table: "stage domain",
                index,
                tag: u32::from(tag),
            }),
        }
    }
}

/// Orthogonal operation axes encoded by one V2 scalar stage.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AotOperationAxesV2 {
    reducer: AotReducerV2,
    projection: AotProjectionV2,
    domain: AotDomainV2,
}

impl AotOperationAxesV2 {
    /// Ordinary one-result search through a compiled program.
    pub const SEARCH: Self = Self::new(
        AotReducerV2::SelectOne,
        AotProjectionV2::ProgramOutput,
        AotDomainV2::Whole,
    );
    /// Count non-overlapping compiled Span matches.
    pub const COUNT: Self = Self::new(
        AotReducerV2::Count,
        AotProjectionV2::Span,
        AotDomainV2::Whole,
    );
    /// Sum non-overlapping compiled Span widths.
    pub const SPAN_SUM: Self = Self::new(
        AotReducerV2::SpanSum,
        AotProjectionV2::Span,
        AotDomainV2::Whole,
    );
    /// Count line domains accepted by a compiled program.
    pub const GREP: Self = Self::new(
        AotReducerV2::Count,
        AotProjectionV2::ProgramOutput,
        AotDomainV2::PerLine,
    );
    /// Sum participating groups (including group zero) over non-overlapping
    /// whole-domain matches.
    pub const CAPTURE_PARTICIPATION_COUNT: Self = Self::new(
        AotReducerV2::Count,
        AotProjectionV2::CaptureParticipation,
        AotDomainV2::Whole,
    );

    /// Construct an axis tuple. V2 admits only its five named tuples.
    #[must_use]
    pub const fn new(
        reducer: AotReducerV2,
        projection: AotProjectionV2,
        domain: AotDomainV2,
    ) -> Self {
        Self {
            reducer,
            projection,
            domain,
        }
    }

    /// Reduction axis.
    #[must_use]
    pub const fn reducer(self) -> AotReducerV2 {
        self.reducer
    }

    /// Projection axis.
    #[must_use]
    pub const fn projection(self) -> AotProjectionV2 {
        self.projection
    }

    /// Input-domain axis.
    #[must_use]
    pub const fn domain(self) -> AotDomainV2 {
        self.domain
    }

    const fn output_kind(self) -> Option<AotOperationOutputV2> {
        if self.reducer.tag() == AotReducerV2::SelectOne.tag()
            && self.projection.tag() == AotProjectionV2::ProgramOutput.tag()
            && self.domain.tag() == AotDomainV2::Whole.tag()
        {
            Some(AotOperationOutputV2::OneRecord)
        } else if (self.reducer.tag() == AotReducerV2::Count.tag()
            && self.projection.tag() == AotProjectionV2::Span.tag()
            && self.domain.tag() == AotDomainV2::Whole.tag())
            || (self.reducer.tag() == AotReducerV2::SpanSum.tag()
                && self.projection.tag() == AotProjectionV2::Span.tag()
                && self.domain.tag() == AotDomainV2::Whole.tag())
            || (self.reducer.tag() == AotReducerV2::Count.tag()
                && self.projection.tag() == AotProjectionV2::ProgramOutput.tag()
                && self.domain.tag() == AotDomainV2::PerLine.tag())
            || (self.reducer.tag() == AotReducerV2::Count.tag()
                && self.projection.tag() == AotProjectionV2::CaptureParticipation.tag()
                && self.domain.tag() == AotDomainV2::Whole.tag())
        {
            Some(AotOperationOutputV2::ScalarU64)
        } else {
            None
        }
    }

    fn validate(self, index: u32) -> Result<AotOperationOutputV2, AotOperationSetV2Error> {
        self.output_kind()
            .ok_or(AotOperationSetV2Error::UnsupportedOperationAxes {
                index,
                reducer: self.reducer.tag(),
                projection: self.projection.tag(),
                domain: self.domain.tag(),
            })
    }
}

/// Caller-visible sink family derived from one V2 operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum AotOperationOutputV2 {
    /// One result record carrying a compiled member's search output.
    OneRecord = OUTPUT_KIND_ONE_RECORD,
    /// One unsigned 64-bit aggregate.
    ScalarU64 = OUTPUT_KIND_SCALAR_U64,
}

impl AotOperationOutputV2 {
    const fn tag(self) -> u16 {
        match self {
            Self::OneRecord => OUTPUT_KIND_ONE_RECORD,
            Self::ScalarU64 => OUTPUT_KIND_SCALAR_U64,
        }
    }

    fn from_tag(tag: u16, index: u32) -> Result<Self, AotOperationSetV2Error> {
        match tag {
            OUTPUT_KIND_ONE_RECORD => Ok(Self::OneRecord),
            OUTPUT_KIND_SCALAR_U64 => Ok(Self::ScalarU64),
            _ => Err(AotOperationSetV2Error::UnsupportedTag {
                table: "output",
                index,
                tag: u32::from(tag),
            }),
        }
    }
}

/// Random-access description of one validated V2 semantic root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AotOperationRootV2 {
    member_index: u32,
    axes: AotOperationAxesV2,
    output: AotOperationOutputV2,
}

impl AotOperationRootV2 {
    /// Canonical member-table index consumed by this root.
    #[must_use]
    pub const fn member_index(self) -> u32 {
        self.member_index
    }

    /// Operation axes executed by this root.
    #[must_use]
    pub const fn axes(self) -> AotOperationAxesV2 {
        self.axes
    }

    /// Exact scalar output sink.
    #[must_use]
    pub const fn output(self) -> AotOperationOutputV2 {
        self.output
    }
}

/// Borrowed description of one exact V2 member payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AotOperationSetMemberV2View<'a> {
    index: u32,
    kind: AotOperationSetMemberKindV2,
    payload_offset: usize,
    payload: &'a [u8],
    identity: [u8; 32],
}

impl<'a> AotOperationSetMemberV2View<'a> {
    /// Canonical member-table index.
    #[must_use]
    pub const fn index(self) -> u32 {
        self.index
    }

    /// Stable member family.
    #[must_use]
    pub const fn kind(self) -> AotOperationSetMemberKindV2 {
        self.kind
    }

    /// Byte offset of this payload in the complete set wire.
    #[must_use]
    pub const fn payload_offset(self) -> usize {
        self.payload_offset
    }

    /// Exact verbatim member bytes.
    #[must_use]
    pub const fn as_bytes(self) -> &'a [u8] {
        self.payload
    }

    /// SHA-256 identity of the exact member bytes.
    #[must_use]
    pub const fn identity(self) -> [u8; 32] {
        self.identity
    }
}

/// Borrowed V2 stage descriptor after canonical validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AotOperationStageV2 {
    member_index: u32,
    axes: AotOperationAxesV2,
    output_index: u32,
}

impl AotOperationStageV2 {
    /// Canonical member index consumed by this stage.
    #[must_use]
    pub const fn member_index(self) -> u32 {
        self.member_index
    }

    /// Operation axes executed by this stage.
    #[must_use]
    pub const fn axes(self) -> AotOperationAxesV2 {
        self.axes
    }

    /// Root-aligned output descriptor index.
    #[must_use]
    pub const fn output_index(self) -> u32 {
        self.output_index
    }
}

/// Borrowed V2 output descriptor after canonical validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AotOperationOutputRecordV2 {
    output: AotOperationOutputV2,
    stage_index: u32,
    record_count: u64,
}

impl AotOperationOutputRecordV2 {
    /// Exact caller-visible sink family.
    #[must_use]
    pub const fn output(self) -> AotOperationOutputV2 {
        self.output
    }

    /// Root-aligned producing stage index.
    #[must_use]
    pub const fn stage_index(self) -> u32 {
        self.stage_index
    }

    /// Number of caller-visible records produced for this root.
    #[must_use]
    pub const fn record_count(self) -> u64 {
        self.record_count
    }
}

/// Failure while building or reconstructing a canonical V2 operation set.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AotOperationSetV2Error {
    /// A fixed field, extent, relationship, or canonical ordering is invalid.
    Malformed(&'static str),
    /// The fixed header names an unsupported format version.
    UnsupportedVersion(u16),
    /// A future table or semantic feature is well tagged but unsupported.
    UnsupportedFeature(&'static str),
    /// A future nonzero flag set was encountered.
    UnsupportedFlags {
        /// Stable table or record name.
        table: &'static str,
        /// Record index, or `u32::MAX` for the fixed header.
        index: u32,
        /// Complete unsupported flag word.
        flags: u32,
    },
    /// A tagged field names an unknown future value.
    UnsupportedTag {
        /// Stable table or axis name.
        table: &'static str,
        /// Record index containing the tag.
        index: u32,
        /// Complete unknown tag value.
        tag: u32,
    },
    /// Known axis tags form a tuple outside V2's admitted scalar operations.
    UnsupportedOperationAxes {
        /// Stage/root index containing the tuple.
        index: u32,
        /// Reducer tag.
        reducer: u16,
        /// Projection tag.
        projection: u16,
        /// Domain tag.
        domain: u16,
    },
    /// A valid operation tuple was paired with the wrong member family.
    IncompatibleMemberKind {
        /// Semantic root index.
        root: u32,
        /// Actual member family.
        actual: AotOperationSetMemberKindV2,
    },
    /// Compiled `Count` or `SpanSum` was paired with a non-`Span` program.
    IncompatibleProgramOutput {
        /// Semantic root index.
        root: u32,
        /// Actual compiled-program output contract.
        actual: OutputContract,
    },
    /// A capture member can match without consuming a byte.
    NullableCaptureProgram {
        /// Canonical member-table index while reading, or first root while building.
        member: u32,
    },
    /// One compiled member failed strict program validation.
    MemberCompiledProgram {
        /// Canonical member-table index while reading, or first root while building.
        member: u32,
        /// Exact child format failure.
        source: ProgramFormatError,
    },
    /// One capture member failed stable V1 census validation.
    MemberCaptureProgram {
        /// Canonical member-table index while reading, or first root while building.
        member: u32,
        /// Exact capture-program failure.
        source: CaptureProgramV1Error,
    },
    /// Caller-owned scratch cannot hold the largest capture-member census.
    CaptureValidationScratch {
        /// Maximum exact `u32` words required by any capture member.
        required_words: usize,
        /// Words supplied by the caller.
        available_words: usize,
    },
    /// Checked wire-size arithmetic was not representable.
    ArithmeticOverflow(&'static str),
    /// A complete aggregate wire exceeds its stable byte envelope.
    ResourceLimit {
        /// Stable bounded resource name.
        resource: &'static str,
        /// Maximum accepted bytes.
        limit: usize,
        /// Exact requested or declared bytes.
        required: usize,
    },
    /// A bounded reconstruction allocation was refused.
    Allocation(&'static str),
}

impl fmt::Display for AotOperationSetV2Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(detail) => {
                write!(formatter, "malformed AOT operation set V2: {detail}")
            }
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "unsupported AOT operation-set V2 version {version}"
                )
            }
            Self::UnsupportedFeature(feature) => {
                write!(
                    formatter,
                    "unsupported AOT operation-set V2 feature: {feature}"
                )
            }
            Self::UnsupportedFlags {
                table,
                index,
                flags,
            } => write!(
                formatter,
                "unsupported AOT operation-set V2 flags {flags:#x} in {table} record {index}"
            ),
            Self::UnsupportedTag { table, index, tag } => write!(
                formatter,
                "unsupported AOT operation-set V2 tag {tag} in {table} record {index}"
            ),
            Self::UnsupportedOperationAxes {
                index,
                reducer,
                projection,
                domain,
            } => write!(
                formatter,
                "unsupported AOT operation-set V2 axes at stage {index}: reducer={reducer}, projection={projection}, domain={domain}"
            ),
            Self::IncompatibleMemberKind { root, actual } => write!(
                formatter,
                "AOT operation-set V2 root {root} is incompatible with {actual:?}"
            ),
            Self::IncompatibleProgramOutput { root, actual } => write!(
                formatter,
                "AOT operation-set V2 root {root} requires Span output, found {actual:?}"
            ),
            Self::NullableCaptureProgram { member } => write!(
                formatter,
                "AOT operation-set V2 capture member {member} can match empty"
            ),
            Self::MemberCompiledProgram { member, source } => write!(
                formatter,
                "invalid AOT operation-set V2 compiled member {member}: {source}"
            ),
            Self::MemberCaptureProgram { member, source } => write!(
                formatter,
                "invalid AOT operation-set V2 capture member {member}: {source}"
            ),
            Self::CaptureValidationScratch {
                required_words,
                available_words,
            } => write!(
                formatter,
                "AOT operation-set V2 capture validation needs {required_words} u32 words, only {available_words} are available"
            ),
            Self::ArithmeticOverflow(computation) => write!(
                formatter,
                "AOT operation-set V2 arithmetic overflow at {computation}"
            ),
            Self::ResourceLimit {
                resource,
                limit,
                required,
            } => write!(
                formatter,
                "AOT operation-set V2 {resource} requires {required} bytes, limit is {limit}"
            ),
            Self::Allocation(owner) => write!(
                formatter,
                "could not allocate bounded AOT operation-set V2 {owner}"
            ),
        }
    }
}

impl std::error::Error for AotOperationSetV2Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MemberCompiledProgram { source, .. } => Some(source),
            Self::MemberCaptureProgram { source, .. } => Some(source),
            Self::Malformed(_)
            | Self::UnsupportedVersion(_)
            | Self::UnsupportedFeature(_)
            | Self::UnsupportedFlags { .. }
            | Self::UnsupportedTag { .. }
            | Self::UnsupportedOperationAxes { .. }
            | Self::IncompatibleMemberKind { .. }
            | Self::IncompatibleProgramOutput { .. }
            | Self::NullableCaptureProgram { .. }
            | Self::CaptureValidationScratch { .. }
            | Self::ArithmeticOverflow(_)
            | Self::ResourceLimit { .. }
            | Self::Allocation(_) => None,
        }
    }
}

impl From<AotOperationSetEnvelopeError> for AotOperationSetV2Error {
    fn from(error: AotOperationSetEnvelopeError) -> Self {
        match error {
            AotOperationSetEnvelopeError::Malformed(detail) => Self::Malformed(detail),
            AotOperationSetEnvelopeError::UnsupportedVersion(version) => {
                Self::UnsupportedVersion(version)
            }
            AotOperationSetEnvelopeError::UnsupportedFeature(feature) => {
                Self::UnsupportedFeature(feature)
            }
            AotOperationSetEnvelopeError::UnsupportedFlags {
                table,
                index,
                flags,
            } => Self::UnsupportedFlags {
                table,
                index,
                flags,
            },
            AotOperationSetEnvelopeError::ArithmeticOverflow(computation) => {
                Self::ArithmeticOverflow(computation)
            }
            AotOperationSetEnvelopeError::ResourceLimit {
                resource,
                limit,
                required,
            } => Self::ResourceLimit {
                resource,
                limit,
                required,
            },
        }
    }
}

/// Allocation-free borrowed preflight of one candidate V2 operation set.
///
/// The view validates the common canonical envelope, every descriptor and
/// fixed member extent, canonical member ordering, every root relationship,
/// and every capture member's complete authenticated body. Capture validation
/// uses only the caller-provided scratch prefix. As in V1, allocation-free
/// preflight checks only the fixed header of a compiled member and defers its
/// complete graph decode plus global member reachability to
/// [`AotOperationSetV2::deserialize`].
#[derive(Clone, Copy, Debug)]
pub struct AotOperationSetV2View<'a> {
    wire: &'a [u8],
    identity: [u8; 32],
    layout: AotOperationSetEnvelopeLayout,
}

impl<'a> AotOperationSetV2View<'a> {
    /// Discover the maximum capture-census scratch prefix from fixed member
    /// headers without allocating or semantically validating capture bodies.
    ///
    /// This still strictly validates the V2 envelope, descriptors, canonical
    /// member order (including each payload hash), and root semantics. Success
    /// is a sizing result, not full capture-program authentication.
    pub fn capture_validation_scratch_words_from_wire(
        bytes: &[u8],
        capture_limits: CaptureProgramV1Limits,
    ) -> Result<usize, AotOperationSetV2Error> {
        let (_, scratch_words) = validate_operation_set_v2_structure(bytes, capture_limits)?;
        Ok(scratch_words)
    }

    /// Allocation-free strict V2 preflight with caller-owned capture scratch.
    ///
    /// Scratch may be mutated on failure. An oversized slice is accepted, but
    /// each capture census uses only its own exact prefix.
    pub fn deserialize(
        bytes: &'a [u8],
        capture_limits: CaptureProgramV1Limits,
        capture_scratch: &mut [u32],
    ) -> Result<Self, AotOperationSetV2Error> {
        let (layout, required_words) = validate_operation_set_v2_structure(bytes, capture_limits)?;
        require_capture_scratch(required_words, capture_scratch.len())?;
        validate_capture_members(bytes, layout, capture_limits, capture_scratch)?;
        Ok(Self::from_validated(bytes, layout))
    }

    fn from_validated(bytes: &'a [u8], layout: AotOperationSetEnvelopeLayout) -> Self {
        Self {
            wire: bytes,
            identity: operation_set_v2_identity(bytes),
            layout,
        }
    }

    /// Exact borrowed wire authenticated by this preflight.
    #[must_use]
    pub const fn as_bytes(self) -> &'a [u8] {
        self.wire
    }

    /// Domain-separated identity of the complete exact V2 wire.
    #[must_use]
    pub const fn identity(self) -> [u8; 32] {
        self.identity
    }

    /// Number of unique canonical members.
    #[must_use]
    pub const fn member_count(self) -> usize {
        self.layout.member_count
    }

    /// Number of semantic roots, stages, and output records.
    #[must_use]
    pub const fn operation_count(self) -> usize {
        self.layout.root_count
    }

    /// Reconstruct one borrowed member record without allocating.
    #[must_use]
    pub fn member(self, index: usize) -> Option<AotOperationSetMemberV2View<'a>> {
        member_view(self.wire, self.layout, index).ok()
    }

    /// Decode one already-validated semantic root without allocating.
    #[must_use]
    pub fn root(self, index: usize) -> Option<AotOperationRootV2> {
        if index >= self.layout.root_count {
            return None;
        }
        let stage = stage_record(self.wire, self.layout, index).ok()?;
        let output = output_record(self.wire, self.layout, index).ok()?;
        Some(AotOperationRootV2 {
            member_index: stage.member_index,
            axes: stage.axes,
            output: output.output,
        })
    }

    /// Decode one already-validated stage record without allocating.
    #[must_use]
    pub fn stage(self, index: usize) -> Option<AotOperationStageV2> {
        if index >= self.layout.root_count {
            return None;
        }
        stage_record(self.wire, self.layout, index).ok()
    }

    /// Decode one already-validated output record without allocating.
    #[must_use]
    pub fn output(self, index: usize) -> Option<AotOperationOutputRecordV2> {
        if index >= self.layout.root_count {
            return None;
        }
        output_record(self.wire, self.layout, index).ok()
    }

    /// Iterate borrowed members in canonical table order.
    #[must_use]
    pub fn members(self) -> impl ExactSizeIterator<Item = AotOperationSetMemberV2View<'a>> + 'a {
        (0..self.layout.member_count).map(move |index| {
            self.member(index)
                .expect("validated operation-set V2 member descriptor")
        })
    }

    /// Iterate semantic roots in exact wire order.
    #[must_use]
    pub fn roots(self) -> impl ExactSizeIterator<Item = AotOperationRootV2> + 'a {
        (0..self.layout.root_count).map(move |index| {
            self.root(index)
                .expect("validated operation-set V2 root descriptor")
        })
    }
}

/// One retained V2 member descriptor and exact payload extent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AotOperationSetMemberV2 {
    payload_start: usize,
    payload_end: usize,
    identity: [u8; 32],
    kind: AotOperationSetMemberKindV2,
}

impl AotOperationSetMemberV2 {
    /// Stable member family.
    #[must_use]
    pub const fn kind(self) -> AotOperationSetMemberKindV2 {
        self.kind
    }

    /// SHA-256 identity of the exact retained member bytes.
    #[must_use]
    pub const fn identity(self) -> [u8; 32] {
        self.identity
    }
}

/// Owned, strictly validated canonical V2 wire/semantic artifact.
///
/// This layer intentionally retains no prepared capture session or runtime
/// ABI. Compiled members are fully decoded during reconstruction and capture
/// members are fully censused, but only the canonical wire and scalar root
/// metadata are retained.
#[derive(Debug)]
pub struct AotOperationSetV2 {
    wire: Box<[u8]>,
    identity: [u8; 32],
    members: Vec<AotOperationSetMemberV2>,
    roots: Vec<AotOperationRootV2>,
}

impl AotOperationSetV2 {
    /// Strictly reconstruct a canonical V2 operation set.
    ///
    /// Canonical envelope, descriptor, fixed-header, and reachability checks
    /// precede every full member-body validation. An unreachable member is
    /// therefore rejected without capture census or compiled-program decode.
    pub fn deserialize(
        bytes: &[u8],
        capture_limits: CaptureProgramV1Limits,
    ) -> Result<Self, AotOperationSetV2Error> {
        let layout = validate_operation_set_envelope(bytes, AOT_OPERATION_SET_V2_ENVELOPE_SPEC)
            .map_err(AotOperationSetV2Error::from)?;
        let mut members = Vec::new();
        members
            .try_reserve_exact(layout.member_count)
            .map_err(|_| AotOperationSetV2Error::Allocation("member table"))?;
        let mut roots = Vec::new();
        roots
            .try_reserve_exact(layout.root_count)
            .map_err(|_| AotOperationSetV2Error::Allocation("root table"))?;
        let required_words = validate_operation_set_v2_structure_body(
            bytes,
            layout,
            capture_limits,
            Some(&mut members),
            Some(&mut roots),
        )?;
        if members.len() != layout.member_count {
            return Err(AotOperationSetV2Error::Malformed(
                "structural validation retained the wrong member count",
            ));
        }
        if roots.len() != layout.root_count {
            return Err(AotOperationSetV2Error::Malformed(
                "structural validation retained the wrong root count",
            ));
        }

        let mut reached_members = Vec::new();
        reached_members
            .try_reserve_exact(layout.member_count)
            .map_err(|_| AotOperationSetV2Error::Allocation("member reachability"))?;
        reached_members.resize(layout.member_count, false);
        for root in &roots {
            let member_index = usize_from_u32(root.member_index())?;
            let reached =
                reached_members
                    .get_mut(member_index)
                    .ok_or(AotOperationSetV2Error::Malformed(
                        "stage member index is out of bounds",
                    ))?;
            *reached = true;
        }
        if reached_members.iter().any(|reached| !reached) {
            return Err(AotOperationSetV2Error::Malformed(
                "member table contains an unreachable payload",
            ));
        }

        let mut capture_scratch = Vec::new();
        capture_scratch
            .try_reserve_exact(required_words)
            .map_err(|_| AotOperationSetV2Error::Allocation("capture validation scratch"))?;
        capture_scratch.resize(required_words, 0);
        validate_capture_members(bytes, layout, capture_limits, &mut capture_scratch)?;

        for (index, member) in members.iter().enumerate() {
            if member.kind == AotOperationSetMemberKindV2::CompiledProgram {
                let member_u32 = u32::try_from(index).map_err(|_| {
                    AotOperationSetV2Error::ArithmeticOverflow("compiled member index conversion")
                })?;
                let payload = bytes.get(member.payload_start..member.payload_end).ok_or(
                    AotOperationSetV2Error::Malformed(
                        "retained member extent exceeds the supplied wire",
                    ),
                )?;
                CompiledProgram::deserialize(payload).map_err(|source| {
                    AotOperationSetV2Error::MemberCompiledProgram {
                        member: member_u32,
                        source,
                    }
                })?;
            }
        }

        let mut wire = Vec::new();
        wire.try_reserve_exact(bytes.len())
            .map_err(|_| AotOperationSetV2Error::Allocation("wire owner"))?;
        wire.extend_from_slice(bytes);
        Ok(Self {
            wire: wire.into_boxed_slice(),
            identity: operation_set_v2_identity(bytes),
            members,
            roots,
        })
    }

    /// Build canonical V2 wire from semantic-order operation/member pairs.
    ///
    /// Exact duplicate `(kind, payload)` members are stored once. Roots retain
    /// input order while members are sorted by their stable canonical key.
    #[allow(
        clippy::too_many_lines,
        reason = "bounded member admission and canonical emission are one auditable transaction"
    )]
    pub fn from_operations<I, B>(
        operations: I,
        capture_limits: CaptureProgramV1Limits,
    ) -> Result<Self, AotOperationSetV2Error>
    where
        I: IntoIterator<Item = (AotOperationAxesV2, AotOperationSetMemberInputV2<B>)>,
        B: AsRef<[u8]>,
    {
        let iterator = operations.into_iter();
        let (minimum, _) = iterator.size_hint();
        let mut roots = Vec::new();
        roots
            .try_reserve(minimum.min(BUILDER_INITIAL_ROOT_RESERVE_LIMIT))
            .map_err(|_| AotOperationSetV2Error::Allocation("builder roots"))?;
        let mut members = Vec::<BuilderMember>::new();
        let mut member_buckets =
            HashMap::<(AotOperationSetMemberKindV2, [u8; 32]), Vec<usize>>::new();
        let mut capture_scratch = Vec::<u32>::new();
        let mut unique_payload_bytes = 0usize;

        for (axes, input) in iterator {
            let root = u32::try_from(roots.len())
                .map_err(|_| AotOperationSetV2Error::ArithmeticOverflow("builder root count"))?;
            let _ = axes.validate(root)?;
            let kind = input.kind();
            let bytes = input.as_bytes();
            let identity: [u8; 32] = Sha256::digest(bytes).into();
            let bucket_key = (kind, identity);
            let existing_member = member_buckets.get(&bucket_key).and_then(|bucket| {
                bucket
                    .iter()
                    .copied()
                    .find(|index| members[*index].payload.as_slice() == bytes)
            });
            let adds_member = existing_member.is_none();
            let added_member_count = usize::from(u8::from(adds_member));
            let prospective_member_count = members.len().checked_add(added_member_count).ok_or(
                AotOperationSetV2Error::ArithmeticOverflow("builder prospective member count"),
            )?;
            let prospective_root_count =
                roots
                    .len()
                    .checked_add(1)
                    .ok_or(AotOperationSetV2Error::ArithmeticOverflow(
                        "builder prospective root count",
                    ))?;
            let prospective_payload_bytes = if adds_member {
                unique_payload_bytes.checked_add(bytes.len()).ok_or(
                    AotOperationSetV2Error::ArithmeticOverflow(
                        "builder prospective unique payload bytes",
                    ),
                )?
            } else {
                unique_payload_bytes
            };
            let prospective_wire_bytes = operation_set_v2_wire_bytes(
                prospective_member_count,
                prospective_root_count,
                prospective_payload_bytes,
            )?;
            if prospective_wire_bytes > MAX_AOT_OPERATION_SET_V2_BYTES {
                return Err(AotOperationSetV2Error::ResourceLimit {
                    resource: "wire bytes",
                    limit: MAX_AOT_OPERATION_SET_V2_BYTES,
                    required: prospective_wire_bytes,
                });
            }

            let member_index = if let Some(existing_member) = existing_member {
                existing_member
            } else {
                let semantic = validate_builder_member(
                    kind,
                    bytes,
                    root,
                    capture_limits,
                    &mut capture_scratch,
                )?;
                let mut payload = Vec::new();
                payload
                    .try_reserve_exact(bytes.len())
                    .map_err(|_| AotOperationSetV2Error::Allocation("builder member payload"))?;
                payload.extend_from_slice(bytes);
                members
                    .try_reserve(1)
                    .map_err(|_| AotOperationSetV2Error::Allocation("builder members"))?;
                let member_index = members.len();
                members.push(BuilderMember {
                    kind,
                    identity,
                    payload,
                    semantic,
                    ingestion_index: member_index,
                });
                if let Some(bucket) = member_buckets.get_mut(&bucket_key) {
                    bucket.try_reserve(1).map_err(|_| {
                        AotOperationSetV2Error::Allocation("builder digest collision bucket")
                    })?;
                    bucket.push(member_index);
                } else {
                    member_buckets.try_reserve(1).map_err(|_| {
                        AotOperationSetV2Error::Allocation("builder member digest index")
                    })?;
                    let mut bucket = Vec::new();
                    bucket
                        .try_reserve_exact(1)
                        .map_err(|_| AotOperationSetV2Error::Allocation("builder digest bucket"))?;
                    bucket.push(member_index);
                    member_buckets.insert(bucket_key, bucket);
                }
                unique_payload_bytes = prospective_payload_bytes;
                member_index
            };
            validate_axes_for_member(root, axes, kind, members[member_index].semantic)?;
            roots
                .try_reserve(1)
                .map_err(|_| AotOperationSetV2Error::Allocation("builder roots"))?;
            roots.push(BuilderRoot { axes, member_index });
        }
        if roots.is_empty() {
            return Err(AotOperationSetV2Error::Malformed(
                "operation set has no semantic roots",
            ));
        }
        drop(member_buckets);

        members.sort_unstable_by(compare_builder_members);
        debug_assert!(
            members
                .windows(2)
                .all(|pair| compare_builder_members(&pair[0], &pair[1]) == Ordering::Less)
        );
        let member_count_u32 = u32::try_from(members.len())
            .map_err(|_| AotOperationSetV2Error::ArithmeticOverflow("builder member count"))?;
        let root_count_u32 = u32::try_from(roots.len())
            .map_err(|_| AotOperationSetV2Error::ArithmeticOverflow("builder root count"))?;
        let mut canonical_index_by_member = Vec::new();
        canonical_index_by_member
            .try_reserve_exact(members.len())
            .map_err(|_| AotOperationSetV2Error::Allocation("builder member remap"))?;
        canonical_index_by_member.resize(members.len(), 0usize);
        for (canonical_index, member) in members.iter().enumerate() {
            canonical_index_by_member[member.ingestion_index] = canonical_index;
        }

        let member_table_offset = AOT_OPERATION_SET_V2_HEADER_BYTES;
        let shared_table_offset = table_end(
            member_table_offset,
            members.len(),
            AOT_OPERATION_SET_V2_MEMBER_DESCRIPTOR_BYTES,
            "builder member table",
        )?;
        let root_table_offset = shared_table_offset;
        let stage_table_offset = table_end(
            root_table_offset,
            roots.len(),
            AOT_OPERATION_SET_V2_ROOT_DESCRIPTOR_BYTES,
            "builder root table",
        )?;
        let output_table_offset = table_end(
            stage_table_offset,
            roots.len(),
            AOT_OPERATION_SET_V2_STAGE_DESCRIPTOR_BYTES,
            "builder stage table",
        )?;
        let payload_offset = table_end(
            output_table_offset,
            roots.len(),
            AOT_OPERATION_SET_V2_OUTPUT_DESCRIPTOR_BYTES,
            "builder output table",
        )?;
        let total_bytes = payload_offset.checked_add(unique_payload_bytes).ok_or(
            AotOperationSetV2Error::ArithmeticOverflow("builder payload total"),
        )?;
        if total_bytes > MAX_AOT_OPERATION_SET_V2_BYTES {
            return Err(AotOperationSetV2Error::ResourceLimit {
                resource: "wire bytes",
                limit: MAX_AOT_OPERATION_SET_V2_BYTES,
                required: total_bytes,
            });
        }

        let mut wire = Vec::new();
        wire.try_reserve_exact(total_bytes)
            .map_err(|_| AotOperationSetV2Error::Allocation("builder wire"))?;
        emit_header(
            &mut wire,
            total_bytes,
            member_count_u32,
            root_count_u32,
            member_table_offset,
            shared_table_offset,
            root_table_offset,
            stage_table_offset,
            output_table_offset,
            payload_offset,
        )?;

        let mut member_payload_offset = payload_offset;
        for member in &members {
            put_u32(&mut wire, member.kind.tag());
            put_u32(&mut wire, 0);
            put_u32(&mut wire, AOT_OPERATION_SET_V2_NONE_INDEX);
            put_u32(&mut wire, AOT_OPERATION_SET_V2_NONE_INDEX);
            put_usize_as_u64(&mut wire, member_payload_offset)?;
            put_usize_as_u64(&mut wire, member.payload.len())?;
            member_payload_offset = member_payload_offset
                .checked_add(member.payload.len())
                .ok_or(AotOperationSetV2Error::ArithmeticOverflow(
                    "builder member payload offset",
                ))?;
        }

        for root in 0..roots.len() {
            let root_u32 = u32::try_from(root)
                .map_err(|_| AotOperationSetV2Error::ArithmeticOverflow("builder root index"))?;
            put_u32(&mut wire, root_u32);
            put_u32(&mut wire, 1);
            put_u32(&mut wire, root_u32);
            put_u32(&mut wire, 1);
            put_u32(&mut wire, 0);
            put_u32(&mut wire, 0);
        }

        for (root, entry) in roots.iter().enumerate() {
            let root_u32 = u32::try_from(root)
                .map_err(|_| AotOperationSetV2Error::ArithmeticOverflow("builder stage index"))?;
            let member_index = *canonical_index_by_member.get(entry.member_index).ok_or(
                AotOperationSetV2Error::Malformed(
                    "builder could not remap a root to its canonical member",
                ),
            )?;
            put_u32(
                &mut wire,
                u32::try_from(member_index).map_err(|_| {
                    AotOperationSetV2Error::ArithmeticOverflow("builder member index")
                })?,
            );
            put_u16(&mut wire, entry.axes.reducer().tag());
            put_u16(&mut wire, entry.axes.projection().tag());
            put_u16(&mut wire, entry.axes.domain().tag());
            put_u16(&mut wire, 0);
            put_u32(&mut wire, root_u32);
            put_u64(&mut wire, 0);
            put_u64(&mut wire, 0);
            put_u64(&mut wire, 0);
        }

        for (root, entry) in roots.iter().enumerate() {
            let root_u32 = u32::try_from(root)
                .map_err(|_| AotOperationSetV2Error::ArithmeticOverflow("builder output index"))?;
            let output = entry.axes.validate(root_u32)?;
            put_u16(&mut wire, output.tag());
            put_u16(&mut wire, 0);
            put_u32(&mut wire, root_u32);
            put_u64(&mut wire, 1);
        }

        let mut decoded_members = Vec::new();
        decoded_members
            .try_reserve_exact(members.len())
            .map_err(|_| AotOperationSetV2Error::Allocation("builder retained members"))?;
        let mut member_payload_start = payload_offset;
        for member in members {
            wire.extend_from_slice(&member.payload);
            let member_payload_end = member_payload_start
                .checked_add(member.payload.len())
                .ok_or(AotOperationSetV2Error::ArithmeticOverflow(
                    "builder retained member extent",
                ))?;
            decoded_members.push(AotOperationSetMemberV2 {
                payload_start: member_payload_start,
                payload_end: member_payload_end,
                identity: member.identity,
                kind: member.kind,
            });
            member_payload_start = member_payload_end;
        }
        if wire.len() != total_bytes || member_payload_start != total_bytes {
            return Err(AotOperationSetV2Error::Malformed(
                "builder emitted an unexpected total extent",
            ));
        }

        let mut decoded_roots = Vec::new();
        decoded_roots
            .try_reserve_exact(roots.len())
            .map_err(|_| AotOperationSetV2Error::Allocation("builder retained roots"))?;
        for (root_index, root) in roots.into_iter().enumerate() {
            let root_u32 = u32::try_from(root_index)
                .map_err(|_| AotOperationSetV2Error::ArithmeticOverflow("builder root index"))?;
            let canonical_member = *canonical_index_by_member.get(root.member_index).ok_or(
                AotOperationSetV2Error::Malformed(
                    "builder could not retain a root's canonical member",
                ),
            )?;
            decoded_roots.push(AotOperationRootV2 {
                member_index: u32::try_from(canonical_member).map_err(|_| {
                    AotOperationSetV2Error::ArithmeticOverflow("builder member index")
                })?,
                axes: root.axes,
                output: root.axes.validate(root_u32)?,
            });
        }

        let identity = operation_set_v2_identity(&wire);
        Ok(Self {
            wire: wire.into_boxed_slice(),
            identity,
            members: decoded_members,
            roots: decoded_roots,
        })
    }

    /// Exact stable V2 wire, including verbatim member payloads.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire
    }

    /// Domain-separated SHA-256 identity of the exact V2 wire.
    #[must_use]
    pub const fn identity(&self) -> [u8; 32] {
        self.identity
    }

    /// Number of deduplicated members.
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Number of semantic roots, retained in builder input order.
    #[must_use]
    pub fn operation_count(&self) -> usize {
        self.roots.len()
    }

    /// Return one root descriptor in constant time.
    #[must_use]
    pub fn operation(&self, index: usize) -> Option<AotOperationRootV2> {
        self.roots.get(index).copied()
    }

    /// Iterate roots in their semantic order.
    #[must_use]
    pub fn operations(&self) -> impl ExactSizeIterator<Item = AotOperationRootV2> + '_ {
        self.roots.iter().copied()
    }

    /// Return one retained member descriptor in constant time.
    #[must_use]
    pub fn member(&self, index: usize) -> Option<AotOperationSetMemberV2> {
        self.members.get(index).copied()
    }

    /// Return one exact verbatim member payload in constant time.
    #[must_use]
    pub fn member_bytes(&self, index: usize) -> Option<&[u8]> {
        let member = self.members.get(index)?;
        self.wire.get(member.payload_start..member.payload_end)
    }

    /// Return the SHA-256 identity of one exact member payload.
    #[must_use]
    pub fn member_identity(&self, index: usize) -> Option<[u8; 32]> {
        self.members.get(index).map(|member| member.identity)
    }
}

#[derive(Clone, Copy, Debug)]
enum MemberOperationSemantic {
    Compiled(OutputContract),
    Capture,
}

#[derive(Debug)]
struct BuilderMember {
    kind: AotOperationSetMemberKindV2,
    identity: [u8; 32],
    payload: Vec<u8>,
    semantic: MemberOperationSemantic,
    ingestion_index: usize,
}

#[derive(Clone, Copy, Debug)]
struct BuilderRoot {
    axes: AotOperationAxesV2,
    member_index: usize,
}

fn validate_builder_member(
    kind: AotOperationSetMemberKindV2,
    bytes: &[u8],
    first_root: u32,
    capture_limits: CaptureProgramV1Limits,
    capture_scratch: &mut Vec<u32>,
) -> Result<MemberOperationSemantic, AotOperationSetV2Error> {
    match kind {
        AotOperationSetMemberKindV2::CompiledProgram => {
            let program = CompiledProgram::deserialize(bytes).map_err(|source| {
                AotOperationSetV2Error::MemberCompiledProgram {
                    member: first_root,
                    source,
                }
            })?;
            Ok(MemberOperationSemantic::Compiled(program.output_contract()))
        }
        AotOperationSetMemberKindV2::CaptureProgramV1 => {
            let header = capture_header(bytes, first_root)?;
            let required_words =
                CaptureProgramV1Census::scratch_words_from_header(header, capture_limits).map_err(
                    |source| AotOperationSetV2Error::MemberCaptureProgram {
                        member: first_root,
                        source,
                    },
                )?;
            if capture_scratch.len() < required_words {
                let additional_words = required_words
                    .checked_sub(capture_scratch.len())
                    .expect("short scratch has a positive exact deficit");
                capture_scratch
                    .try_reserve_exact(additional_words)
                    .map_err(|_| {
                        AotOperationSetV2Error::Allocation("builder capture validation scratch")
                    })?;
                capture_scratch.resize(required_words, 0);
            }
            let census = CaptureProgramV1Census::from_wire(
                bytes,
                capture_limits,
                capture_scratch.as_mut_slice(),
            )
            .map_err(|source| AotOperationSetV2Error::MemberCaptureProgram {
                member: first_root,
                source,
            })?;
            if census.can_match_empty() {
                return Err(AotOperationSetV2Error::NullableCaptureProgram { member: first_root });
            }
            Ok(MemberOperationSemantic::Capture)
        }
    }
}

fn validate_axes_for_member(
    root: u32,
    axes: AotOperationAxesV2,
    kind: AotOperationSetMemberKindV2,
    semantic: MemberOperationSemantic,
) -> Result<(), AotOperationSetV2Error> {
    let _ = axes.validate(root)?;
    match (kind, semantic) {
        (
            AotOperationSetMemberKindV2::CompiledProgram,
            MemberOperationSemantic::Compiled(output),
        ) => {
            if axes == AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT {
                return Err(AotOperationSetV2Error::IncompatibleMemberKind { root, actual: kind });
            }
            if matches!(
                axes,
                AotOperationAxesV2::COUNT | AotOperationAxesV2::SPAN_SUM
            ) && output != OutputContract::Span
            {
                return Err(AotOperationSetV2Error::IncompatibleProgramOutput {
                    root,
                    actual: output,
                });
            }
            Ok(())
        }
        (AotOperationSetMemberKindV2::CaptureProgramV1, MemberOperationSemantic::Capture)
            if axes == AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT =>
        {
            Ok(())
        }
        (actual, _) => Err(AotOperationSetV2Error::IncompatibleMemberKind { root, actual }),
    }
}

fn compare_builder_members(left: &BuilderMember, right: &BuilderMember) -> Ordering {
    compare_member_key(
        &left.identity,
        left.kind,
        &left.payload,
        &right.identity,
        right.kind,
        &right.payload,
    )
}

fn compare_member_key(
    left_identity: &[u8; 32],
    left_kind: AotOperationSetMemberKindV2,
    left_payload: &[u8],
    right_identity: &[u8; 32],
    right_kind: AotOperationSetMemberKindV2,
    right_payload: &[u8],
) -> Ordering {
    left_identity
        .cmp(right_identity)
        .then_with(|| left_kind.tag().cmp(&right_kind.tag()))
        .then_with(|| left_payload.cmp(right_payload))
}

fn operation_set_v2_identity(bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(AOT_OPERATION_SET_V2_IDENTITY_DOMAIN);
    digest.update(bytes);
    digest.finalize().into()
}

fn operation_set_v2_wire_bytes(
    member_count: usize,
    root_count: usize,
    payload_bytes: usize,
) -> Result<usize, AotOperationSetV2Error> {
    let member_end = table_end(
        AOT_OPERATION_SET_V2_HEADER_BYTES,
        member_count,
        AOT_OPERATION_SET_V2_MEMBER_DESCRIPTOR_BYTES,
        "prospective member table",
    )?;
    let root_end = table_end(
        member_end,
        root_count,
        AOT_OPERATION_SET_V2_ROOT_DESCRIPTOR_BYTES,
        "prospective root table",
    )?;
    let stage_end = table_end(
        root_end,
        root_count,
        AOT_OPERATION_SET_V2_STAGE_DESCRIPTOR_BYTES,
        "prospective stage table",
    )?;
    let output_end = table_end(
        stage_end,
        root_count,
        AOT_OPERATION_SET_V2_OUTPUT_DESCRIPTOR_BYTES,
        "prospective output table",
    )?;
    output_end
        .checked_add(payload_bytes)
        .ok_or(AotOperationSetV2Error::ArithmeticOverflow(
            "prospective payload total",
        ))
}

#[derive(Clone, Copy, Debug)]
enum FixedMemberSemantic {
    Compiled(OutputContract),
    Capture { scratch_words: usize },
}

impl FixedMemberSemantic {
    const fn operation(self) -> MemberOperationSemantic {
        match self {
            Self::Compiled(output) => MemberOperationSemantic::Compiled(output),
            Self::Capture { .. } => MemberOperationSemantic::Capture,
        }
    }
}

fn validate_operation_set_v2_structure(
    bytes: &[u8],
    capture_limits: CaptureProgramV1Limits,
) -> Result<(AotOperationSetEnvelopeLayout, usize), AotOperationSetV2Error> {
    let layout = validate_operation_set_envelope(bytes, AOT_OPERATION_SET_V2_ENVELOPE_SPEC)
        .map_err(AotOperationSetV2Error::from)?;
    let capture_scratch_words =
        validate_operation_set_v2_structure_body(bytes, layout, capture_limits, None, None)?;
    Ok((layout, capture_scratch_words))
}

fn validate_operation_set_v2_structure_body(
    bytes: &[u8],
    layout: AotOperationSetEnvelopeLayout,
    capture_limits: CaptureProgramV1Limits,
    mut retained_members: Option<&mut Vec<AotOperationSetMemberV2>>,
    mut retained_roots: Option<&mut Vec<AotOperationRootV2>>,
) -> Result<usize, AotOperationSetV2Error> {
    let mut next_payload = layout.payload_offset;
    let mut prior_member: Option<([u8; 32], AotOperationSetMemberKindV2, &[u8])> = None;
    let mut capture_scratch_words = 0usize;
    for index in 0..layout.member_count {
        let member = member_record(bytes, layout, index)?;
        if member.payload_offset != next_payload {
            return Err(AotOperationSetV2Error::Malformed(
                "member payloads are not contiguous in descriptor order",
            ));
        }
        let semantic =
            validate_member_fixed(member.kind, member.payload, member.index, capture_limits)?;
        let identity = member_payload_identity(member.payload);
        if let Some((prior_identity, prior_kind, prior_payload)) = prior_member
            && compare_member_key(
                &prior_identity,
                prior_kind,
                prior_payload,
                &identity,
                member.kind,
                member.payload,
            ) != Ordering::Less
        {
            return Err(AotOperationSetV2Error::Malformed(
                "member payloads are duplicate or not in canonical digest-kind-byte order",
            ));
        }
        if let FixedMemberSemantic::Capture { scratch_words } = semantic {
            capture_scratch_words = capture_scratch_words.max(scratch_words);
        }
        let payload_end = member
            .payload_offset
            .checked_add(member.payload.len())
            .ok_or(AotOperationSetV2Error::ArithmeticOverflow(
                "member payload end",
            ))?;
        if let Some(members) = &mut retained_members {
            members.push(AotOperationSetMemberV2 {
                payload_start: member.payload_offset,
                payload_end,
                identity,
                kind: member.kind,
            });
        }
        next_payload = payload_end;
        prior_member = Some((identity, member.kind, member.payload));
    }
    if next_payload != bytes.len() {
        return Err(AotOperationSetV2Error::Malformed(
            "unclaimed bytes follow the canonical member payloads",
        ));
    }

    for index in 0..layout.root_count {
        validate_root_record(bytes, layout, index)?;
        let root_u32 = u32::try_from(index)
            .map_err(|_| AotOperationSetV2Error::ArithmeticOverflow("root index conversion"))?;
        let stage = stage_record(bytes, layout, index)?;
        let expected_output = stage.axes.validate(root_u32)?;
        let output = output_record(bytes, layout, index)?;
        if output.output != expected_output {
            return Err(AotOperationSetV2Error::Malformed(
                "output descriptor does not exactly match its producing stage",
            ));
        }
        let member_index = usize_from_u32(stage.member_index)?;
        let member = member_record(bytes, layout, member_index)?;
        let semantic =
            validate_member_fixed(member.kind, member.payload, member.index, capture_limits)?;
        validate_axes_for_member(root_u32, stage.axes, member.kind, semantic.operation())?;
        if let Some(roots) = &mut retained_roots {
            roots.push(AotOperationRootV2 {
                member_index: stage.member_index(),
                axes: stage.axes(),
                output: output.output(),
            });
        }
    }
    Ok(capture_scratch_words)
}

fn validate_capture_members(
    bytes: &[u8],
    layout: AotOperationSetEnvelopeLayout,
    capture_limits: CaptureProgramV1Limits,
    capture_scratch: &mut [u32],
) -> Result<(), AotOperationSetV2Error> {
    for index in 0..layout.member_count {
        let member = member_record(bytes, layout, index)?;
        if member.kind != AotOperationSetMemberKindV2::CaptureProgramV1 {
            continue;
        }
        let census =
            CaptureProgramV1Census::from_wire(member.payload, capture_limits, capture_scratch)
                .map_err(|source| AotOperationSetV2Error::MemberCaptureProgram {
                    member: member.index,
                    source,
                })?;
        if census.can_match_empty() {
            return Err(AotOperationSetV2Error::NullableCaptureProgram {
                member: member.index,
            });
        }
    }
    Ok(())
}

fn require_capture_scratch(
    required_words: usize,
    available_words: usize,
) -> Result<(), AotOperationSetV2Error> {
    if available_words < required_words {
        Err(AotOperationSetV2Error::CaptureValidationScratch {
            required_words,
            available_words,
        })
    } else {
        Ok(())
    }
}

fn member_view(
    bytes: &[u8],
    layout: AotOperationSetEnvelopeLayout,
    index: usize,
) -> Result<AotOperationSetMemberV2View<'_>, AotOperationSetV2Error> {
    let member = member_record(bytes, layout, index)?;
    Ok(AotOperationSetMemberV2View {
        index: member.index,
        kind: member.kind,
        payload_offset: member.payload_offset,
        payload: member.payload,
        identity: member_payload_identity(member.payload),
    })
}

fn member_payload_identity(payload: &[u8]) -> [u8; 32] {
    #[cfg(test)]
    TEST_STRUCTURE_MEMBER_HASHES.with(|hashes| hashes.set(hashes.get().saturating_add(1)));
    Sha256::digest(payload).into()
}

#[derive(Clone, Copy, Debug)]
struct AotOperationSetMemberRecordV2<'a> {
    index: u32,
    kind: AotOperationSetMemberKindV2,
    payload_offset: usize,
    payload: &'a [u8],
}

/// Parse a member descriptor and its exact extent without hashing its body.
/// Canonical member-order validation hashes each member once; root checks use
/// this fixed-cost record so repeated roots cannot amplify payload work.
fn member_record(
    bytes: &[u8],
    layout: AotOperationSetEnvelopeLayout,
    index: usize,
) -> Result<AotOperationSetMemberRecordV2<'_>, AotOperationSetV2Error> {
    if index >= layout.member_count {
        return Err(AotOperationSetV2Error::Malformed(
            "member index is out of bounds",
        ));
    }
    let index_u32 = u32::try_from(index)
        .map_err(|_| AotOperationSetV2Error::ArithmeticOverflow("member index conversion"))?;
    let descriptor = record(
        bytes,
        layout.member_table_offset,
        index,
        AOT_OPERATION_SET_V2_MEMBER_DESCRIPTOR_BYTES,
        "member descriptor is truncated",
    )?;
    let kind = AotOperationSetMemberKindV2::from_tag(read_u32(descriptor, 0)?, index_u32)?;
    let flags = read_u32(descriptor, 4)?;
    if flags != 0 {
        return Err(AotOperationSetV2Error::UnsupportedFlags {
            table: "member",
            index: index_u32,
            flags,
        });
    }
    if read_u32(descriptor, 8)? != AOT_OPERATION_SET_V2_NONE_INDEX
        || read_u32(descriptor, 12)? != AOT_OPERATION_SET_V2_NONE_INDEX
    {
        return Err(AotOperationSetV2Error::Malformed(
            "member references shared or auxiliary storage",
        ));
    }
    let payload_offset = usize_from_u64(read_u64(descriptor, 16)?)?;
    let payload_len = usize_from_u64(read_u64(descriptor, 24)?)?;
    let payload_end = payload_offset.checked_add(payload_len).ok_or(
        AotOperationSetV2Error::ArithmeticOverflow("member payload end"),
    )?;
    let payload =
        bytes
            .get(payload_offset..payload_end)
            .ok_or(AotOperationSetV2Error::Malformed(
                "member payload exceeds the supplied extent",
            ))?;
    Ok(AotOperationSetMemberRecordV2 {
        index: index_u32,
        kind,
        payload_offset,
        payload,
    })
}

fn validate_member_fixed(
    kind: AotOperationSetMemberKindV2,
    payload: &[u8],
    member: u32,
    capture_limits: CaptureProgramV1Limits,
) -> Result<FixedMemberSemantic, AotOperationSetV2Error> {
    match kind {
        AotOperationSetMemberKindV2::CompiledProgram => Ok(FixedMemberSemantic::Compiled(
            compiled_member_output_contract(payload, member)?,
        )),
        AotOperationSetMemberKindV2::CaptureProgramV1 => {
            let header = capture_header(payload, member)?;
            let declared =
                CaptureProgramV1::serialized_len_from_header(header, capture_limits).map_err(
                    |source| AotOperationSetV2Error::MemberCaptureProgram { member, source },
                )?;
            if declared != payload.len() {
                return Err(AotOperationSetV2Error::Malformed(
                    "capture member declared extent does not match its descriptor",
                ));
            }
            let scratch_words =
                CaptureProgramV1Census::scratch_words_from_header(header, capture_limits).map_err(
                    |source| AotOperationSetV2Error::MemberCaptureProgram { member, source },
                )?;
            Ok(FixedMemberSemantic::Capture { scratch_words })
        }
    }
}

fn capture_header(payload: &[u8], member: u32) -> Result<&[u8], AotOperationSetV2Error> {
    payload.get(..CAPTURE_PROGRAM_V1_HEADER_BYTES).ok_or(
        AotOperationSetV2Error::MemberCaptureProgram {
            member,
            source: CaptureProgramV1Error::Format(
                fre_capture_lab::CaptureProgramV1FormatError::Truncated(
                    "fixed header is truncated",
                ),
            ),
        },
    )
}

fn compiled_member_output_contract(
    payload: &[u8],
    member: u32,
) -> Result<OutputContract, AotOperationSetV2Error> {
    let header = payload.get(..PROGRAM_HEADER_LEN).ok_or_else(|| {
        compiled_member_error(
            member,
            ProgramFormatError::Malformed("program header is truncated"),
        )
    })?;
    let declared = CompiledProgram::serialized_len_from_header(header)
        .map_err(|source| compiled_member_error(member, source))?;
    if declared != payload.len() {
        return Err(compiled_member_error(
            member,
            ProgramFormatError::Malformed(
                "declared program length does not match the supplied extent",
            ),
        ));
    }
    OutputContract::from_tag(header[13]).map_err(|source| compiled_member_error(member, source))
}

fn compiled_member_error(member: u32, source: ProgramFormatError) -> AotOperationSetV2Error {
    AotOperationSetV2Error::MemberCompiledProgram { member, source }
}

fn validate_root_record(
    bytes: &[u8],
    layout: AotOperationSetEnvelopeLayout,
    index: usize,
) -> Result<(), AotOperationSetV2Error> {
    let index_u32 = u32::try_from(index)
        .map_err(|_| AotOperationSetV2Error::ArithmeticOverflow("root index conversion"))?;
    let descriptor = record(
        bytes,
        layout.root_table_offset,
        index,
        AOT_OPERATION_SET_V2_ROOT_DESCRIPTOR_BYTES,
        "root descriptor is truncated",
    )?;
    if read_u32(descriptor, 0)? != index_u32
        || read_u32(descriptor, 4)? != 1
        || read_u32(descriptor, 8)? != index_u32
        || read_u32(descriptor, 12)? != 1
    {
        return Err(AotOperationSetV2Error::Malformed(
            "roots do not own exactly one root-aligned stage and output",
        ));
    }
    let flags = read_u32(descriptor, 16)?;
    if flags != 0 {
        return Err(AotOperationSetV2Error::UnsupportedFlags {
            table: "root",
            index: index_u32,
            flags,
        });
    }
    if read_u32(descriptor, 20)? != 0 {
        return Err(AotOperationSetV2Error::Malformed(
            "root reserved field is nonzero",
        ));
    }
    Ok(())
}

fn stage_record(
    bytes: &[u8],
    layout: AotOperationSetEnvelopeLayout,
    index: usize,
) -> Result<AotOperationStageV2, AotOperationSetV2Error> {
    let index_u32 = u32::try_from(index)
        .map_err(|_| AotOperationSetV2Error::ArithmeticOverflow("stage index conversion"))?;
    let descriptor = record(
        bytes,
        layout.stage_table_offset,
        index,
        AOT_OPERATION_SET_V2_STAGE_DESCRIPTOR_BYTES,
        "stage descriptor is truncated",
    )?;
    let member_index = read_u32(descriptor, 0)?;
    if usize_from_u32(member_index)? >= layout.member_count {
        return Err(AotOperationSetV2Error::Malformed(
            "stage member index is out of bounds",
        ));
    }
    let reducer = AotReducerV2::from_tag(read_u16(descriptor, 4)?, index_u32)?;
    let projection = AotProjectionV2::from_tag(read_u16(descriptor, 6)?, index_u32)?;
    let domain = AotDomainV2::from_tag(read_u16(descriptor, 8)?, index_u32)?;
    let flags = read_u16(descriptor, 10)?;
    if flags != 0 {
        return Err(AotOperationSetV2Error::UnsupportedFlags {
            table: "stage",
            index: index_u32,
            flags: u32::from(flags),
        });
    }
    let output_index = read_u32(descriptor, 12)?;
    if output_index != index_u32 {
        return Err(AotOperationSetV2Error::Malformed(
            "stage output index is not root aligned",
        ));
    }
    if read_u64(descriptor, 16)? != 0
        || read_u64(descriptor, 24)? != 0
        || read_u64(descriptor, 32)? != 0
    {
        return Err(AotOperationSetV2Error::Malformed(
            "V2 stage parameters or reserved field are nonzero",
        ));
    }
    Ok(AotOperationStageV2 {
        member_index,
        axes: AotOperationAxesV2::new(reducer, projection, domain),
        output_index,
    })
}

fn output_record(
    bytes: &[u8],
    layout: AotOperationSetEnvelopeLayout,
    index: usize,
) -> Result<AotOperationOutputRecordV2, AotOperationSetV2Error> {
    let index_u32 = u32::try_from(index)
        .map_err(|_| AotOperationSetV2Error::ArithmeticOverflow("output index conversion"))?;
    let descriptor = record(
        bytes,
        layout.output_table_offset,
        index,
        AOT_OPERATION_SET_V2_OUTPUT_DESCRIPTOR_BYTES,
        "output descriptor is truncated",
    )?;
    let output = AotOperationOutputV2::from_tag(read_u16(descriptor, 0)?, index_u32)?;
    let flags = read_u16(descriptor, 2)?;
    if flags != 0 {
        return Err(AotOperationSetV2Error::UnsupportedFlags {
            table: "output",
            index: index_u32,
            flags: u32::from(flags),
        });
    }
    let stage_index = read_u32(descriptor, 4)?;
    let record_count = read_u64(descriptor, 8)?;
    if stage_index != index_u32 || record_count != 1 {
        return Err(AotOperationSetV2Error::Malformed(
            "output descriptor does not exactly match its producing stage",
        ));
    }
    Ok(AotOperationOutputRecordV2 {
        output,
        stage_index,
        record_count,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "the fixed canonical header carries these exact independent offsets"
)]
fn emit_header(
    wire: &mut Vec<u8>,
    total_bytes: usize,
    member_count: u32,
    root_count: u32,
    member_table_offset: usize,
    shared_table_offset: usize,
    root_table_offset: usize,
    stage_table_offset: usize,
    output_table_offset: usize,
    payload_offset: usize,
) -> Result<(), AotOperationSetV2Error> {
    wire.extend_from_slice(&AOT_OPERATION_SET_V2_MAGIC);
    put_u16(wire, AOT_OPERATION_SET_V2_VERSION);
    put_u16(
        wire,
        u16::try_from(AOT_OPERATION_SET_V2_HEADER_BYTES)
            .map_err(|_| AotOperationSetV2Error::ArithmeticOverflow("header byte conversion"))?,
    );
    put_u32(wire, 0);
    put_usize_as_u64(wire, total_bytes)?;
    put_u32(wire, member_count);
    put_u32(wire, 0);
    put_u32(wire, root_count);
    put_u32(wire, root_count);
    put_u32(wire, root_count);
    put_u32(wire, 0);
    put_usize_as_u64(wire, member_table_offset)?;
    put_usize_as_u64(wire, shared_table_offset)?;
    put_usize_as_u64(wire, root_table_offset)?;
    put_usize_as_u64(wire, stage_table_offset)?;
    put_usize_as_u64(wire, output_table_offset)?;
    put_usize_as_u64(wire, payload_offset)?;
    for _ in 0..4 {
        put_u64(wire, 0);
    }
    if wire.len() != AOT_OPERATION_SET_V2_HEADER_BYTES {
        return Err(AotOperationSetV2Error::Malformed(
            "builder emitted the wrong fixed-header size",
        ));
    }
    Ok(())
}

fn record<'a>(
    bytes: &'a [u8],
    table_offset: usize,
    index: usize,
    record_bytes: usize,
    truncated: &'static str,
) -> Result<&'a [u8], AotOperationSetV2Error> {
    let start = index
        .checked_mul(record_bytes)
        .and_then(|relative| table_offset.checked_add(relative))
        .ok_or(AotOperationSetV2Error::ArithmeticOverflow(
            "table record offset",
        ))?;
    let end = start
        .checked_add(record_bytes)
        .ok_or(AotOperationSetV2Error::ArithmeticOverflow(
            "table record end",
        ))?;
    bytes
        .get(start..end)
        .ok_or(AotOperationSetV2Error::Malformed(truncated))
}

fn table_end(
    start: usize,
    count: usize,
    item_bytes: usize,
    computation: &'static str,
) -> Result<usize, AotOperationSetV2Error> {
    count
        .checked_mul(item_bytes)
        .and_then(|extent| start.checked_add(extent))
        .ok_or(AotOperationSetV2Error::ArithmeticOverflow(computation))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, AotOperationSetV2Error> {
    let end = offset
        .checked_add(2)
        .ok_or(AotOperationSetV2Error::ArithmeticOverflow("u16 field end"))?;
    let raw: [u8; 2] = bytes
        .get(offset..end)
        .ok_or(AotOperationSetV2Error::Malformed("u16 field is truncated"))?
        .try_into()
        .map_err(|_| AotOperationSetV2Error::Malformed("u16 field has the wrong size"))?;
    Ok(u16::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, AotOperationSetV2Error> {
    let end = offset
        .checked_add(4)
        .ok_or(AotOperationSetV2Error::ArithmeticOverflow("u32 field end"))?;
    let raw: [u8; 4] = bytes
        .get(offset..end)
        .ok_or(AotOperationSetV2Error::Malformed("u32 field is truncated"))?
        .try_into()
        .map_err(|_| AotOperationSetV2Error::Malformed("u32 field has the wrong size"))?;
    Ok(u32::from_le_bytes(raw))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, AotOperationSetV2Error> {
    let end = offset
        .checked_add(8)
        .ok_or(AotOperationSetV2Error::ArithmeticOverflow("u64 field end"))?;
    let raw: [u8; 8] = bytes
        .get(offset..end)
        .ok_or(AotOperationSetV2Error::Malformed("u64 field is truncated"))?
        .try_into()
        .map_err(|_| AotOperationSetV2Error::Malformed("u64 field has the wrong size"))?;
    Ok(u64::from_le_bytes(raw))
}

fn usize_from_u32(value: u32) -> Result<usize, AotOperationSetV2Error> {
    usize::try_from(value)
        .map_err(|_| AotOperationSetV2Error::Malformed("u32 index does not fit this host"))
}

fn usize_from_u64(value: u64) -> Result<usize, AotOperationSetV2Error> {
    usize::try_from(value)
        .map_err(|_| AotOperationSetV2Error::Malformed("u64 extent does not fit this host"))
}

fn put_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_usize_as_u64(bytes: &mut Vec<u8>, value: usize) -> Result<(), AotOperationSetV2Error> {
    put_u64(
        bytes,
        u64::try_from(value)
            .map_err(|_| AotOperationSetV2Error::ArithmeticOverflow("wire extent conversion"))?,
    );
    Ok(())
}

#[cfg(test)]
mod tests;
