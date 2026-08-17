//! Canonical operation-set wire for prepared scalar AOT execution.
//!
//! Version 1 deliberately admits only capture-free [`CompiledProgram`]
//! members and one scalar stage/output per root. The table layout already
//! leaves explicit positions for shared members and longer stage sequences,
//! but this reader rejects those future features instead of guessing at their
//! semantics.

use core::{cmp::Ordering, fmt};
use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::{CompiledProgram, OutputContract, ProgramFormatError};

/// Fixed magic at byte zero of every V1 operation set.
pub const AOT_OPERATION_SET_V1_MAGIC: [u8; 8] = *b"FREAOS1\0";
/// Stable wire version encoded in the fixed header.
pub const AOT_OPERATION_SET_V1_VERSION: u16 = 1;
/// Bytes in the fixed V1 header.
pub const AOT_OPERATION_SET_V1_HEADER_BYTES: usize = 128;
/// Bytes in one scalar-member descriptor.
pub const AOT_OPERATION_SET_V1_MEMBER_DESCRIPTOR_BYTES: usize = 32;
/// Bytes in one future shared-member descriptor.
pub const AOT_OPERATION_SET_V1_SHARED_DESCRIPTOR_BYTES: usize = 24;
/// Bytes in one root descriptor.
pub const AOT_OPERATION_SET_V1_ROOT_DESCRIPTOR_BYTES: usize = 24;
/// Bytes in one stage descriptor.
pub const AOT_OPERATION_SET_V1_STAGE_DESCRIPTOR_BYTES: usize = 40;
/// Bytes in one output descriptor.
pub const AOT_OPERATION_SET_V1_OUTPUT_DESCRIPTOR_BYTES: usize = 16;
/// Sentinel used by a scalar member that references no shared or auxiliary object.
pub const AOT_OPERATION_SET_V1_NONE_INDEX: u32 = u32::MAX;
/// Maximum complete V1 wire accepted by the builder or strict reader.
pub const MAX_AOT_OPERATION_SET_V1_BYTES: usize = 1024 * 1024 * 1024;
/// Domain separating an operation-set identity from a member-program identity.
pub const AOT_OPERATION_SET_V1_IDENTITY_DOMAIN: &[u8] = b"fre.aot-operation-set.v1\0";

const MEMBER_KIND_COMPILED_PROGRAM: u32 = 1;
const OUTPUT_KIND_ONE_RECORD: u16 = 1;
const OUTPUT_KIND_SCALAR_U64: u16 = 2;
const BUILDER_INITIAL_ROOT_RESERVE_LIMIT: usize = 4_096;

#[cfg(test)]
std::thread_local! {
    static TEST_BUILDER_UNIQUE_PROGRAM_DECODES: core::cell::Cell<usize> = const {
        core::cell::Cell::new(0)
    };
}

const HEADER_VERSION_OFFSET: usize = 8;
const HEADER_BYTES_OFFSET: usize = 10;
const HEADER_FLAGS_OFFSET: usize = 12;
const HEADER_TOTAL_BYTES_OFFSET: usize = 16;
const HEADER_MEMBER_COUNT_OFFSET: usize = 24;
const HEADER_SHARED_COUNT_OFFSET: usize = 28;
const HEADER_ROOT_COUNT_OFFSET: usize = 32;
const HEADER_STAGE_COUNT_OFFSET: usize = 36;
const HEADER_OUTPUT_COUNT_OFFSET: usize = 40;
const HEADER_RESERVED0_OFFSET: usize = 44;
const HEADER_MEMBER_TABLE_OFFSET: usize = 48;
const HEADER_SHARED_TABLE_OFFSET: usize = 56;
const HEADER_ROOT_TABLE_OFFSET: usize = 64;
const HEADER_STAGE_TABLE_OFFSET: usize = 72;
const HEADER_OUTPUT_TABLE_OFFSET: usize = 80;
const HEADER_PAYLOAD_OFFSET: usize = 88;
const HEADER_RESERVED_OFFSET: usize = 96;

/// Reduction axis of one operation stage.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum AotReducerV1 {
    /// Select at most one result under the member program's output contract.
    SelectOne = 1,
    /// Count selected domains.
    Count = 2,
    /// Sum selected Span widths.
    SpanSum = 3,
}

impl AotReducerV1 {
    const fn tag(self) -> u16 {
        match self {
            Self::SelectOne => 1,
            Self::Count => 2,
            Self::SpanSum => 3,
        }
    }

    fn from_tag(tag: u16, index: u32) -> Result<Self, AotOperationSetV1Error> {
        match tag {
            1 => Ok(Self::SelectOne),
            2 => Ok(Self::Count),
            3 => Ok(Self::SpanSum),
            _ => Err(AotOperationSetV1Error::UnsupportedTag {
                table: "stage reducer",
                index,
                tag: u32::from(tag),
            }),
        }
    }
}

/// Projection axis of one operation stage.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum AotProjectionV1 {
    /// Preserve the member program's declared scalar output contract.
    ProgramOutput = 1,
    /// Project non-overlapping selected matches as Spans before reduction.
    Span = 2,
}

impl AotProjectionV1 {
    const fn tag(self) -> u16 {
        match self {
            Self::ProgramOutput => 1,
            Self::Span => 2,
        }
    }

    fn from_tag(tag: u16, index: u32) -> Result<Self, AotOperationSetV1Error> {
        match tag {
            1 => Ok(Self::ProgramOutput),
            2 => Ok(Self::Span),
            _ => Err(AotOperationSetV1Error::UnsupportedTag {
                table: "stage projection",
                index,
                tag: u32::from(tag),
            }),
        }
    }
}

/// Input-domain axis of one operation stage.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum AotDomainV1 {
    /// Apply the operation once to the whole supplied source domain.
    Whole = 1,
    /// Apply matching independently to canonical LF/CRLF line domains.
    PerLine = 2,
}

impl AotDomainV1 {
    const fn tag(self) -> u16 {
        match self {
            Self::Whole => 1,
            Self::PerLine => 2,
        }
    }

    fn from_tag(tag: u16, index: u32) -> Result<Self, AotOperationSetV1Error> {
        match tag {
            1 => Ok(Self::Whole),
            2 => Ok(Self::PerLine),
            _ => Err(AotOperationSetV1Error::UnsupportedTag {
                table: "stage domain",
                index,
                tag: u32::from(tag),
            }),
        }
    }
}

/// Orthogonal operation axes encoded by one V1 scalar stage.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AotOperationAxesV1 {
    reducer: AotReducerV1,
    projection: AotProjectionV1,
    domain: AotDomainV1,
}

impl AotOperationAxesV1 {
    /// Ordinary one-result search through the program's output contract.
    pub const SEARCH: Self = Self::new(
        AotReducerV1::SelectOne,
        AotProjectionV1::ProgramOutput,
        AotDomainV1::Whole,
    );
    /// Count non-overlapping selected Spans over the whole source.
    pub const COUNT: Self = Self::new(
        AotReducerV1::Count,
        AotProjectionV1::Span,
        AotDomainV1::Whole,
    );
    /// Sum non-overlapping selected Span widths over the whole source.
    pub const SPAN_SUM: Self = Self::new(
        AotReducerV1::SpanSum,
        AotProjectionV1::Span,
        AotDomainV1::Whole,
    );
    /// Count canonical line domains whose contents match the program.
    pub const GREP: Self = Self::new(
        AotReducerV1::Count,
        AotProjectionV1::ProgramOutput,
        AotDomainV1::PerLine,
    );
    /// Alias naming the scalar result produced by [`Self::GREP`].
    pub const GREP_COUNT: Self = Self::GREP;

    /// Construct an axis tuple. Serialization accepts only the four V1 tuples.
    #[must_use]
    pub const fn new(
        reducer: AotReducerV1,
        projection: AotProjectionV1,
        domain: AotDomainV1,
    ) -> Self {
        Self {
            reducer,
            projection,
            domain,
        }
    }

    /// Reduction axis.
    #[must_use]
    pub const fn reducer(self) -> AotReducerV1 {
        self.reducer
    }

    /// Projection axis.
    #[must_use]
    pub const fn projection(self) -> AotProjectionV1 {
        self.projection
    }

    /// Input-domain axis.
    #[must_use]
    pub const fn domain(self) -> AotDomainV1 {
        self.domain
    }

    const fn output_kind(self) -> Option<AotOperationOutputV1> {
        if self.reducer.tag() == AotReducerV1::SelectOne.tag()
            && self.projection.tag() == AotProjectionV1::ProgramOutput.tag()
            && self.domain.tag() == AotDomainV1::Whole.tag()
        {
            Some(AotOperationOutputV1::OneRecord)
        } else if (self.reducer.tag() == AotReducerV1::Count.tag()
            && self.projection.tag() == AotProjectionV1::Span.tag()
            && self.domain.tag() == AotDomainV1::Whole.tag())
            || (self.reducer.tag() == AotReducerV1::SpanSum.tag()
                && self.projection.tag() == AotProjectionV1::Span.tag()
                && self.domain.tag() == AotDomainV1::Whole.tag())
            || (self.reducer.tag() == AotReducerV1::Count.tag()
                && self.projection.tag() == AotProjectionV1::ProgramOutput.tag()
                && self.domain.tag() == AotDomainV1::PerLine.tag())
        {
            Some(AotOperationOutputV1::ScalarU64)
        } else {
            None
        }
    }

    fn validate(self, index: u32) -> Result<AotOperationOutputV1, AotOperationSetV1Error> {
        self.output_kind()
            .ok_or(AotOperationSetV1Error::UnsupportedOperationAxes {
                index,
                reducer: self.reducer.tag(),
                projection: self.projection.tag(),
                domain: self.domain.tag(),
            })
    }
}

/// Caller-visible sink family derived from one admitted Stage-1 operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum AotOperationOutputV1 {
    /// One result record carrying the member program's scalar search output.
    OneRecord = 1,
    /// One unsigned 64-bit aggregate.
    ScalarU64 = 2,
}

impl AotOperationOutputV1 {
    const fn tag(self) -> u16 {
        match self {
            Self::OneRecord => OUTPUT_KIND_ONE_RECORD,
            Self::ScalarU64 => OUTPUT_KIND_SCALAR_U64,
        }
    }

    fn from_tag(tag: u16, index: u32) -> Result<Self, AotOperationSetV1Error> {
        match tag {
            OUTPUT_KIND_ONE_RECORD => Ok(Self::OneRecord),
            OUTPUT_KIND_SCALAR_U64 => Ok(Self::ScalarU64),
            _ => Err(AotOperationSetV1Error::UnsupportedTag {
                table: "output",
                index,
                tag: u32::from(tag),
            }),
        }
    }
}

/// Random-access description of one semantic root in a validated set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AotOperationRootV1 {
    member_index: u32,
    axes: AotOperationAxesV1,
    output: AotOperationOutputV1,
}

impl AotOperationRootV1 {
    /// Canonical member-table index consumed by this root.
    #[must_use]
    pub const fn member_index(self) -> u32 {
        self.member_index
    }

    /// Operation axes executed by this root.
    #[must_use]
    pub const fn axes(self) -> AotOperationAxesV1 {
        self.axes
    }

    /// Exact derived output sink.
    #[must_use]
    pub const fn output(self) -> AotOperationOutputV1 {
        self.output
    }
}

/// Failure while building or reconstructing a stable V1 operation set.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AotOperationSetV1Error {
    /// A fixed field, extent, relationship, or canonical ordering is invalid.
    Malformed(&'static str),
    /// The fixed header names a newer unsupported format version.
    UnsupportedVersion(u16),
    /// A future table or semantic feature is well tagged but unsupported by Stage 1.
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
    /// All individual axis tags are known, but their tuple is not a V1 operation.
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
    /// Count or SpanSum was paired with a non-Span member program.
    IncompatibleProgramOutput {
        /// Semantic root index.
        root: u32,
        /// Actual member output contract.
        actual: OutputContract,
    },
    /// One embedded scalar member failed strict `CompiledProgram` validation.
    MemberProgram {
        /// Canonical member-table index while reading, or the semantic root
        /// that first introduced this payload while building.
        member: u32,
        /// Exact child format failure.
        source: ProgramFormatError,
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

impl fmt::Display for AotOperationSetV1Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(detail) => write!(formatter, "malformed AOT operation set: {detail}"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported AOT operation-set version {version}")
            }
            Self::UnsupportedFeature(feature) => {
                write!(
                    formatter,
                    "unsupported AOT operation-set feature: {feature}"
                )
            }
            Self::UnsupportedFlags {
                table,
                index,
                flags,
            } => write!(
                formatter,
                "unsupported AOT operation-set flags {flags:#x} in {table} record {index}"
            ),
            Self::UnsupportedTag { table, index, tag } => write!(
                formatter,
                "unsupported AOT operation-set tag {tag} in {table} record {index}"
            ),
            Self::UnsupportedOperationAxes {
                index,
                reducer,
                projection,
                domain,
            } => write!(
                formatter,
                "unsupported AOT operation-set axes at stage {index}: reducer={reducer}, projection={projection}, domain={domain}"
            ),
            Self::IncompatibleProgramOutput { root, actual } => write!(
                formatter,
                "AOT operation-set root {root} requires Span output, found {actual:?}"
            ),
            Self::MemberProgram { member, source } => {
                write!(
                    formatter,
                    "invalid AOT operation-set member {member}: {source}"
                )
            }
            Self::ArithmeticOverflow(computation) => write!(
                formatter,
                "AOT operation-set arithmetic overflow at {computation}"
            ),
            Self::ResourceLimit {
                resource,
                limit,
                required,
            } => write!(
                formatter,
                "AOT operation-set {resource} requires {required} bytes, limit is {limit}"
            ),
            Self::Allocation(owner) => {
                write!(
                    formatter,
                    "could not allocate bounded AOT operation-set {owner}"
                )
            }
        }
    }
}

impl std::error::Error for AotOperationSetV1Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MemberProgram { source, .. } => Some(source),
            Self::Malformed(_)
            | Self::UnsupportedVersion(_)
            | Self::UnsupportedFeature(_)
            | Self::UnsupportedFlags { .. }
            | Self::UnsupportedTag { .. }
            | Self::UnsupportedOperationAxes { .. }
            | Self::IncompatibleProgramOutput { .. }
            | Self::ArithmeticOverflow(_)
            | Self::ResourceLimit { .. }
            | Self::Allocation(_) => None,
        }
    }
}

/// One decoded scalar member retained by an ownership-preserving handoff.
#[doc(hidden)]
#[derive(Debug)]
pub struct AotOperationSetMemberV1 {
    payload_start: usize,
    payload_end: usize,
    identity: [u8; 32],
    program: CompiledProgram,
}

impl AotOperationSetMemberV1 {
    /// SHA-256 identity of the exact member bytes validated by the set.
    #[doc(hidden)]
    #[must_use]
    pub const fn identity(&self) -> [u8; 32] {
        self.identity
    }

    /// Borrow the already-decoded semantic program.
    #[doc(hidden)]
    #[must_use]
    pub const fn program(&self) -> &CompiledProgram {
        &self.program
    }

    /// Consume this owner without cloning or deserializing its program.
    #[doc(hidden)]
    #[must_use]
    pub fn into_program(self) -> CompiledProgram {
        self.program
    }
}

/// Ownership-preserving runtime handoff from one validated operation set.
#[doc(hidden)]
#[derive(Debug)]
pub struct AotOperationSetV1Parts {
    wire: Box<[u8]>,
    identity: [u8; 32],
    members: Vec<AotOperationSetMemberV1>,
    roots: Vec<AotOperationRootV1>,
}

impl AotOperationSetV1Parts {
    /// Domain-separated identity of the complete exact set wire.
    #[doc(hidden)]
    #[must_use]
    pub const fn identity(&self) -> [u8; 32] {
        self.identity
    }

    /// Already-decoded members in canonical member-table order.
    #[doc(hidden)]
    #[must_use]
    pub fn members(&self) -> &[AotOperationSetMemberV1] {
        &self.members
    }

    /// Semantic roots in exact wire order.
    #[doc(hidden)]
    #[must_use]
    pub fn roots(&self) -> &[AotOperationRootV1] {
        &self.roots
    }

    /// Exact verbatim bytes for one retained member.
    #[doc(hidden)]
    #[must_use]
    pub fn member_bytes(&self, index: usize) -> Option<&[u8]> {
        let member = self.members.get(index)?;
        self.wire.get(member.payload_start..member.payload_end)
    }

    /// Move every decoded program, member identity, root, and set identity
    /// into the runtime without cloning or reparsing. The exact wire owner is
    /// released because no returned program borrows it.
    #[doc(hidden)]
    #[must_use]
    pub fn into_components(
        self,
    ) -> (
        [u8; 32],
        Vec<AotOperationSetMemberV1>,
        Vec<AotOperationRootV1>,
    ) {
        (self.identity, self.members, self.roots)
    }
}

/// Owned, strictly validated canonical V1 operation-set artifact.
///
/// The tables are shaped for later shared members and stage sequences, but
/// V1 strictly accepts only scalar [`CompiledProgram`] members, an empty
/// shared table, and exactly one stage and output for each nonempty root.
#[derive(Debug)]
pub struct AotOperationSetV1 {
    wire: Box<[u8]>,
    identity: [u8; 32],
    members: Vec<AotOperationSetMemberV1>,
    roots: Vec<AotOperationRootV1>,
}

impl AotOperationSetV1 {
    /// Strictly reconstruct a canonical operation set while retaining every
    /// embedded member byte verbatim.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, AotOperationSetV1Error> {
        let header = bytes.get(..AOT_OPERATION_SET_V1_HEADER_BYTES).ok_or(
            AotOperationSetV1Error::Malformed("fixed header is truncated"),
        )?;
        if header.get(..8) != Some(AOT_OPERATION_SET_V1_MAGIC.as_slice()) {
            return Err(AotOperationSetV1Error::Malformed("bad operation-set magic"));
        }
        let version = read_u16(header, HEADER_VERSION_OFFSET)?;
        if version != AOT_OPERATION_SET_V1_VERSION {
            return Err(AotOperationSetV1Error::UnsupportedVersion(version));
        }
        if usize::from(read_u16(header, HEADER_BYTES_OFFSET)?) != AOT_OPERATION_SET_V1_HEADER_BYTES
        {
            return Err(AotOperationSetV1Error::Malformed(
                "fixed header has the wrong byte size",
            ));
        }
        let header_flags = read_u32(header, HEADER_FLAGS_OFFSET)?;
        if header_flags != 0 {
            return Err(AotOperationSetV1Error::UnsupportedFlags {
                table: "header",
                index: u32::MAX,
                flags: header_flags,
            });
        }
        let total_bytes = usize_from_u64(read_u64(header, HEADER_TOTAL_BYTES_OFFSET)?)?;
        if total_bytes > MAX_AOT_OPERATION_SET_V1_BYTES {
            return Err(AotOperationSetV1Error::ResourceLimit {
                resource: "wire bytes",
                limit: MAX_AOT_OPERATION_SET_V1_BYTES,
                required: total_bytes,
            });
        }
        if total_bytes != bytes.len() {
            return Err(AotOperationSetV1Error::Malformed(
                "declared total length does not match the supplied extent",
            ));
        }

        let member_count_u32 = read_u32(header, HEADER_MEMBER_COUNT_OFFSET)?;
        let shared_count = read_u32(header, HEADER_SHARED_COUNT_OFFSET)?;
        let root_count_u32 = read_u32(header, HEADER_ROOT_COUNT_OFFSET)?;
        let stage_count_u32 = read_u32(header, HEADER_STAGE_COUNT_OFFSET)?;
        let output_count_u32 = read_u32(header, HEADER_OUTPUT_COUNT_OFFSET)?;
        if read_u32(header, HEADER_RESERVED0_OFFSET)? != 0 {
            return Err(AotOperationSetV1Error::Malformed(
                "fixed header reserved fields are nonzero",
            ));
        }
        for word in 0..4 {
            if read_u64(header, HEADER_RESERVED_OFFSET + word * 8)? != 0 {
                return Err(AotOperationSetV1Error::Malformed(
                    "fixed header reserved fields are nonzero",
                ));
            }
        }
        if shared_count != 0 {
            return Err(AotOperationSetV1Error::UnsupportedFeature(
                "shared-member records",
            ));
        }
        if root_count_u32 != stage_count_u32 || root_count_u32 != output_count_u32 {
            return Err(AotOperationSetV1Error::Malformed(
                "Stage-1 root, stage, and output counts differ",
            ));
        }
        if root_count_u32 == 0 {
            return Err(AotOperationSetV1Error::Malformed(
                "operation set has no semantic roots",
            ));
        }
        if member_count_u32 > root_count_u32 {
            return Err(AotOperationSetV1Error::Malformed(
                "member count exceeds the number of reachable roots",
            ));
        }
        let member_count = usize_from_u32(member_count_u32)?;
        let root_count = usize_from_u32(root_count_u32)?;

        let member_table_offset = usize_from_u64(read_u64(header, HEADER_MEMBER_TABLE_OFFSET)?)?;
        let shared_table_offset = usize_from_u64(read_u64(header, HEADER_SHARED_TABLE_OFFSET)?)?;
        let root_table_offset = usize_from_u64(read_u64(header, HEADER_ROOT_TABLE_OFFSET)?)?;
        let stage_table_offset = usize_from_u64(read_u64(header, HEADER_STAGE_TABLE_OFFSET)?)?;
        let output_table_offset = usize_from_u64(read_u64(header, HEADER_OUTPUT_TABLE_OFFSET)?)?;
        let payload_offset = usize_from_u64(read_u64(header, HEADER_PAYLOAD_OFFSET)?)?;

        let expected_member_offset = AOT_OPERATION_SET_V1_HEADER_BYTES;
        let expected_shared_offset = table_end(
            expected_member_offset,
            member_count,
            AOT_OPERATION_SET_V1_MEMBER_DESCRIPTOR_BYTES,
            "member table extent",
        )?;
        let expected_root_offset = expected_shared_offset;
        let expected_stage_offset = table_end(
            expected_root_offset,
            root_count,
            AOT_OPERATION_SET_V1_ROOT_DESCRIPTOR_BYTES,
            "root table extent",
        )?;
        let expected_output_offset = table_end(
            expected_stage_offset,
            root_count,
            AOT_OPERATION_SET_V1_STAGE_DESCRIPTOR_BYTES,
            "stage table extent",
        )?;
        let expected_payload_offset = table_end(
            expected_output_offset,
            root_count,
            AOT_OPERATION_SET_V1_OUTPUT_DESCRIPTOR_BYTES,
            "output table extent",
        )?;
        if member_table_offset != expected_member_offset
            || shared_table_offset != expected_shared_offset
            || root_table_offset != expected_root_offset
            || stage_table_offset != expected_stage_offset
            || output_table_offset != expected_output_offset
            || payload_offset != expected_payload_offset
        {
            return Err(AotOperationSetV1Error::Malformed(
                "table offsets are not the exact canonical contiguous layout",
            ));
        }
        if payload_offset > bytes.len() {
            return Err(AotOperationSetV1Error::Malformed(
                "descriptor tables exceed the supplied extent",
            ));
        }

        let mut members = Vec::new();
        members
            .try_reserve_exact(member_count)
            .map_err(|_| AotOperationSetV1Error::Allocation("member table"))?;
        let mut next_payload = payload_offset;
        let mut prior_member: Option<([u8; 32], usize, usize)> = None;
        for member_index in 0..member_count {
            let index_u32 = u32::try_from(member_index).map_err(|_| {
                AotOperationSetV1Error::ArithmeticOverflow("member index conversion")
            })?;
            let descriptor = record(
                bytes,
                member_table_offset,
                member_index,
                AOT_OPERATION_SET_V1_MEMBER_DESCRIPTOR_BYTES,
                "member descriptor is truncated",
            )?;
            let kind = read_u32(descriptor, 0)?;
            if kind != MEMBER_KIND_COMPILED_PROGRAM {
                return Err(AotOperationSetV1Error::UnsupportedTag {
                    table: "member",
                    index: index_u32,
                    tag: kind,
                });
            }
            let flags = read_u32(descriptor, 4)?;
            if flags != 0 {
                return Err(AotOperationSetV1Error::UnsupportedFlags {
                    table: "member",
                    index: index_u32,
                    flags,
                });
            }
            if read_u32(descriptor, 8)? != AOT_OPERATION_SET_V1_NONE_INDEX
                || read_u32(descriptor, 12)? != AOT_OPERATION_SET_V1_NONE_INDEX
            {
                return Err(AotOperationSetV1Error::Malformed(
                    "scalar member references shared or auxiliary storage",
                ));
            }
            let member_offset = usize_from_u64(read_u64(descriptor, 16)?)?;
            let member_len = usize_from_u64(read_u64(descriptor, 24)?)?;
            if member_offset != next_payload {
                return Err(AotOperationSetV1Error::Malformed(
                    "member payloads are not contiguous in descriptor order",
                ));
            }
            let member_end = member_offset.checked_add(member_len).ok_or(
                AotOperationSetV1Error::ArithmeticOverflow("member payload end"),
            )?;
            let payload =
                bytes
                    .get(member_offset..member_end)
                    .ok_or(AotOperationSetV1Error::Malformed(
                        "member payload exceeds the supplied extent",
                    ))?;
            let program = CompiledProgram::deserialize(payload).map_err(|source| {
                AotOperationSetV1Error::MemberProgram {
                    member: index_u32,
                    source,
                }
            })?;
            let member_identity: [u8; 32] = Sha256::digest(payload).into();
            if let Some((prior_identity, prior_start, prior_end)) = prior_member {
                let prior_payload =
                    bytes
                        .get(prior_start..prior_end)
                        .ok_or(AotOperationSetV1Error::Malformed(
                            "prior canonical member payload exceeds the supplied extent",
                        ))?;
                if compare_member_key(&prior_identity, prior_payload, &member_identity, payload)
                    != Ordering::Less
                {
                    return Err(AotOperationSetV1Error::Malformed(
                        "member payloads are duplicate or not in canonical digest-byte order",
                    ));
                }
            }
            members.push(AotOperationSetMemberV1 {
                payload_start: member_offset,
                payload_end: member_end,
                identity: member_identity,
                program,
            });
            prior_member = Some((member_identity, member_offset, member_end));
            next_payload = member_end;
        }
        if next_payload != bytes.len() {
            return Err(AotOperationSetV1Error::Malformed(
                "unclaimed bytes follow the canonical member payloads",
            ));
        }

        let mut reached_members = Vec::new();
        reached_members
            .try_reserve_exact(member_count)
            .map_err(|_| AotOperationSetV1Error::Allocation("member reachability"))?;
        reached_members.resize(member_count, false);
        let mut roots = Vec::new();
        roots
            .try_reserve_exact(root_count)
            .map_err(|_| AotOperationSetV1Error::Allocation("root table"))?;
        for root_index in 0..root_count {
            let index_u32 = u32::try_from(root_index)
                .map_err(|_| AotOperationSetV1Error::ArithmeticOverflow("root index conversion"))?;
            let root_descriptor = record(
                bytes,
                root_table_offset,
                root_index,
                AOT_OPERATION_SET_V1_ROOT_DESCRIPTOR_BYTES,
                "root descriptor is truncated",
            )?;
            if read_u32(root_descriptor, 0)? != index_u32
                || read_u32(root_descriptor, 4)? != 1
                || read_u32(root_descriptor, 8)? != index_u32
                || read_u32(root_descriptor, 12)? != 1
            {
                return Err(AotOperationSetV1Error::Malformed(
                    "roots do not own exactly one root-aligned stage and output",
                ));
            }
            let root_flags = read_u32(root_descriptor, 16)?;
            if root_flags != 0 {
                return Err(AotOperationSetV1Error::UnsupportedFlags {
                    table: "root",
                    index: index_u32,
                    flags: root_flags,
                });
            }
            if read_u32(root_descriptor, 20)? != 0 {
                return Err(AotOperationSetV1Error::Malformed(
                    "root reserved field is nonzero",
                ));
            }

            let stage_descriptor = record(
                bytes,
                stage_table_offset,
                root_index,
                AOT_OPERATION_SET_V1_STAGE_DESCRIPTOR_BYTES,
                "stage descriptor is truncated",
            )?;
            let member_index_u32 = read_u32(stage_descriptor, 0)?;
            let member_index = usize_from_u32(member_index_u32)?;
            let member = members
                .get(member_index)
                .ok_or(AotOperationSetV1Error::Malformed(
                    "stage member index is out of bounds",
                ))?;
            let reducer = AotReducerV1::from_tag(read_u16(stage_descriptor, 4)?, index_u32)?;
            let projection = AotProjectionV1::from_tag(read_u16(stage_descriptor, 6)?, index_u32)?;
            let domain = AotDomainV1::from_tag(read_u16(stage_descriptor, 8)?, index_u32)?;
            let stage_flags = read_u16(stage_descriptor, 10)?;
            if stage_flags != 0 {
                return Err(AotOperationSetV1Error::UnsupportedFlags {
                    table: "stage",
                    index: index_u32,
                    flags: u32::from(stage_flags),
                });
            }
            if read_u32(stage_descriptor, 12)? != index_u32 {
                return Err(AotOperationSetV1Error::Malformed(
                    "stage output index is not root aligned",
                ));
            }
            if read_u64(stage_descriptor, 16)? != 0
                || read_u64(stage_descriptor, 24)? != 0
                || read_u64(stage_descriptor, 32)? != 0
            {
                return Err(AotOperationSetV1Error::Malformed(
                    "Stage-1 stage parameters or reserved field are nonzero",
                ));
            }
            let axes = AotOperationAxesV1::new(reducer, projection, domain);
            let expected_output = axes.validate(index_u32)?;
            if matches!(
                axes,
                AotOperationAxesV1::COUNT | AotOperationAxesV1::SPAN_SUM
            ) && member.program.output_contract() != OutputContract::Span
            {
                return Err(AotOperationSetV1Error::IncompatibleProgramOutput {
                    root: index_u32,
                    actual: member.program.output_contract(),
                });
            }

            let output_descriptor = record(
                bytes,
                output_table_offset,
                root_index,
                AOT_OPERATION_SET_V1_OUTPUT_DESCRIPTOR_BYTES,
                "output descriptor is truncated",
            )?;
            let output =
                AotOperationOutputV1::from_tag(read_u16(output_descriptor, 0)?, index_u32)?;
            let output_flags = read_u16(output_descriptor, 2)?;
            if output_flags != 0 {
                return Err(AotOperationSetV1Error::UnsupportedFlags {
                    table: "output",
                    index: index_u32,
                    flags: u32::from(output_flags),
                });
            }
            if output != expected_output
                || read_u32(output_descriptor, 4)? != index_u32
                || read_u64(output_descriptor, 8)? != 1
            {
                return Err(AotOperationSetV1Error::Malformed(
                    "output descriptor does not exactly match its producing stage",
                ));
            }
            reached_members[member_index] = true;
            roots.push(AotOperationRootV1 {
                member_index: member_index_u32,
                axes,
                output,
            });
        }
        if reached_members.iter().any(|reached| !reached) {
            return Err(AotOperationSetV1Error::Malformed(
                "member table contains an unreachable payload",
            ));
        }

        let mut wire = Vec::new();
        wire.try_reserve_exact(bytes.len())
            .map_err(|_| AotOperationSetV1Error::Allocation("wire owner"))?;
        wire.extend_from_slice(bytes);
        let identity = operation_set_identity(bytes);
        Ok(Self {
            wire: wire.into_boxed_slice(),
            identity,
            members,
            roots,
        })
    }

    /// Build the canonical wire from semantic-order operation/program pairs.
    /// Exact duplicate member payloads are stored once; roots retain input
    /// order, and each unique program is decoded once into the returned owner.
    pub fn from_operations<I, B>(operations: I) -> Result<Self, AotOperationSetV1Error>
    where
        I: IntoIterator<Item = (AotOperationAxesV1, B)>,
        B: AsRef<[u8]>,
    {
        let iterator = operations.into_iter();
        let (minimum, _) = iterator.size_hint();
        let mut roots = Vec::new();
        roots
            .try_reserve(minimum.min(BUILDER_INITIAL_ROOT_RESERVE_LIMIT))
            .map_err(|_| AotOperationSetV1Error::Allocation("builder roots"))?;
        let mut members = Vec::<BuilderMember>::new();
        let mut member_buckets = HashMap::<[u8; 32], Vec<usize>>::new();
        let mut unique_payload_bytes = 0usize;
        for (axes, bytes) in iterator {
            let root = u32::try_from(roots.len())
                .map_err(|_| AotOperationSetV1Error::ArithmeticOverflow("builder root count"))?;
            let _ = axes.validate(root)?;
            let bytes = bytes.as_ref();
            let identity: [u8; 32] = Sha256::digest(bytes).into();
            let existing_member = member_buckets.get(&identity).and_then(|bucket| {
                bucket
                    .iter()
                    .copied()
                    .find(|index| members[*index].payload.as_slice() == bytes)
            });
            let adds_member = existing_member.is_none();
            let added_member_count = if adds_member { 1 } else { 0 };
            let prospective_member_count = members.len().checked_add(added_member_count).ok_or(
                AotOperationSetV1Error::ArithmeticOverflow("builder prospective member count"),
            )?;
            let prospective_root_count =
                roots
                    .len()
                    .checked_add(1)
                    .ok_or(AotOperationSetV1Error::ArithmeticOverflow(
                        "builder prospective root count",
                    ))?;
            let prospective_payload_bytes = if adds_member {
                unique_payload_bytes.checked_add(bytes.len()).ok_or(
                    AotOperationSetV1Error::ArithmeticOverflow(
                        "builder prospective unique payload bytes",
                    ),
                )?
            } else {
                unique_payload_bytes
            };
            let prospective_wire_bytes = operation_set_wire_bytes(
                prospective_member_count,
                prospective_root_count,
                prospective_payload_bytes,
            )?;
            if prospective_wire_bytes > MAX_AOT_OPERATION_SET_V1_BYTES {
                return Err(AotOperationSetV1Error::ResourceLimit {
                    resource: "wire bytes",
                    limit: MAX_AOT_OPERATION_SET_V1_BYTES,
                    required: prospective_wire_bytes,
                });
            }

            let member_index = if let Some(existing_member) = existing_member {
                existing_member
            } else {
                #[cfg(test)]
                TEST_BUILDER_UNIQUE_PROGRAM_DECODES.with(|decodes| {
                    decodes.set(decodes.get().saturating_add(1));
                });
                let program = CompiledProgram::deserialize(bytes).map_err(|source| {
                    AotOperationSetV1Error::MemberProgram {
                        member: root,
                        source,
                    }
                })?;
                let mut payload = Vec::new();
                payload
                    .try_reserve_exact(bytes.len())
                    .map_err(|_| AotOperationSetV1Error::Allocation("builder member payload"))?;
                payload.extend_from_slice(bytes);
                members
                    .try_reserve(1)
                    .map_err(|_| AotOperationSetV1Error::Allocation("builder members"))?;
                let member_index = members.len();
                members.push(BuilderMember {
                    identity,
                    payload,
                    program,
                    ingestion_index: member_index,
                });
                if let Some(bucket) = member_buckets.get_mut(&identity) {
                    bucket.try_reserve(1).map_err(|_| {
                        AotOperationSetV1Error::Allocation("builder digest collision bucket")
                    })?;
                    bucket.push(member_index);
                } else {
                    member_buckets.try_reserve(1).map_err(|_| {
                        AotOperationSetV1Error::Allocation("builder member digest index")
                    })?;
                    let mut bucket = Vec::new();
                    bucket
                        .try_reserve_exact(1)
                        .map_err(|_| AotOperationSetV1Error::Allocation("builder digest bucket"))?;
                    bucket.push(member_index);
                    member_buckets.insert(identity, bucket);
                }
                unique_payload_bytes = prospective_payload_bytes;
                member_index
            };
            let output_contract = members[member_index].program.output_contract();
            if matches!(
                axes,
                AotOperationAxesV1::COUNT | AotOperationAxesV1::SPAN_SUM
            ) && output_contract != OutputContract::Span
            {
                return Err(AotOperationSetV1Error::IncompatibleProgramOutput {
                    root,
                    actual: output_contract,
                });
            }
            roots
                .try_reserve(1)
                .map_err(|_| AotOperationSetV1Error::Allocation("builder roots"))?;
            roots.push(BuilderRoot { axes, member_index });
        }
        if roots.is_empty() {
            return Err(AotOperationSetV1Error::Malformed(
                "operation set has no semantic roots",
            ));
        }
        drop(member_buckets);
        let root_count_u32 = u32::try_from(roots.len())
            .map_err(|_| AotOperationSetV1Error::ArithmeticOverflow("builder root count"))?;

        members.sort_unstable_by(compare_builder_members);
        debug_assert!(
            members
                .windows(2)
                .all(|pair| compare_builder_members(&pair[0], &pair[1]) == Ordering::Less)
        );
        let member_count_u32 = u32::try_from(members.len())
            .map_err(|_| AotOperationSetV1Error::ArithmeticOverflow("builder member count"))?;
        let mut canonical_index_by_member = Vec::new();
        canonical_index_by_member
            .try_reserve_exact(members.len())
            .map_err(|_| AotOperationSetV1Error::Allocation("builder member remap"))?;
        canonical_index_by_member.resize(members.len(), 0usize);
        for (canonical_index, member) in members.iter().enumerate() {
            canonical_index_by_member[member.ingestion_index] = canonical_index;
        }

        let member_table_offset = AOT_OPERATION_SET_V1_HEADER_BYTES;
        let shared_table_offset = table_end(
            member_table_offset,
            members.len(),
            AOT_OPERATION_SET_V1_MEMBER_DESCRIPTOR_BYTES,
            "builder member table",
        )?;
        let root_table_offset = shared_table_offset;
        let stage_table_offset = table_end(
            root_table_offset,
            roots.len(),
            AOT_OPERATION_SET_V1_ROOT_DESCRIPTOR_BYTES,
            "builder root table",
        )?;
        let output_table_offset = table_end(
            stage_table_offset,
            roots.len(),
            AOT_OPERATION_SET_V1_STAGE_DESCRIPTOR_BYTES,
            "builder stage table",
        )?;
        let payload_offset = table_end(
            output_table_offset,
            roots.len(),
            AOT_OPERATION_SET_V1_OUTPUT_DESCRIPTOR_BYTES,
            "builder output table",
        )?;
        let total_bytes = payload_offset.checked_add(unique_payload_bytes).ok_or(
            AotOperationSetV1Error::ArithmeticOverflow("builder payload total"),
        )?;
        if total_bytes > MAX_AOT_OPERATION_SET_V1_BYTES {
            return Err(AotOperationSetV1Error::ResourceLimit {
                resource: "wire bytes",
                limit: MAX_AOT_OPERATION_SET_V1_BYTES,
                required: total_bytes,
            });
        }

        let mut wire = Vec::new();
        wire.try_reserve_exact(total_bytes)
            .map_err(|_| AotOperationSetV1Error::Allocation("builder wire"))?;
        wire.extend_from_slice(&AOT_OPERATION_SET_V1_MAGIC);
        put_u16(&mut wire, AOT_OPERATION_SET_V1_VERSION);
        put_u16(
            &mut wire,
            u16::try_from(AOT_OPERATION_SET_V1_HEADER_BYTES).map_err(|_| {
                AotOperationSetV1Error::ArithmeticOverflow("header byte conversion")
            })?,
        );
        put_u32(&mut wire, 0);
        put_usize_as_u64(&mut wire, total_bytes)?;
        put_u32(&mut wire, member_count_u32);
        put_u32(&mut wire, 0);
        put_u32(&mut wire, root_count_u32);
        put_u32(&mut wire, root_count_u32);
        put_u32(&mut wire, root_count_u32);
        put_u32(&mut wire, 0);
        put_usize_as_u64(&mut wire, member_table_offset)?;
        put_usize_as_u64(&mut wire, shared_table_offset)?;
        put_usize_as_u64(&mut wire, root_table_offset)?;
        put_usize_as_u64(&mut wire, stage_table_offset)?;
        put_usize_as_u64(&mut wire, output_table_offset)?;
        put_usize_as_u64(&mut wire, payload_offset)?;
        for _ in 0..4 {
            put_u64(&mut wire, 0);
        }
        if wire.len() != AOT_OPERATION_SET_V1_HEADER_BYTES {
            return Err(AotOperationSetV1Error::Malformed(
                "builder emitted the wrong fixed-header size",
            ));
        }

        let mut member_payload_offset = payload_offset;
        for member in &members {
            put_u32(&mut wire, MEMBER_KIND_COMPILED_PROGRAM);
            put_u32(&mut wire, 0);
            put_u32(&mut wire, AOT_OPERATION_SET_V1_NONE_INDEX);
            put_u32(&mut wire, AOT_OPERATION_SET_V1_NONE_INDEX);
            put_usize_as_u64(&mut wire, member_payload_offset)?;
            put_usize_as_u64(&mut wire, member.payload.len())?;
            member_payload_offset = member_payload_offset
                .checked_add(member.payload.len())
                .ok_or(AotOperationSetV1Error::ArithmeticOverflow(
                    "builder member payload offset",
                ))?;
        }

        for root in 0..roots.len() {
            let root_u32 = u32::try_from(root)
                .map_err(|_| AotOperationSetV1Error::ArithmeticOverflow("builder root index"))?;
            put_u32(&mut wire, root_u32);
            put_u32(&mut wire, 1);
            put_u32(&mut wire, root_u32);
            put_u32(&mut wire, 1);
            put_u32(&mut wire, 0);
            put_u32(&mut wire, 0);
        }

        for (root, entry) in roots.iter().enumerate() {
            let root_u32 = u32::try_from(root)
                .map_err(|_| AotOperationSetV1Error::ArithmeticOverflow("builder stage index"))?;
            let member_index = *canonical_index_by_member.get(entry.member_index).ok_or(
                AotOperationSetV1Error::Malformed(
                    "builder could not remap a root to its canonical member",
                ),
            )?;
            put_u32(
                &mut wire,
                u32::try_from(member_index).map_err(|_| {
                    AotOperationSetV1Error::ArithmeticOverflow("builder member index")
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
                .map_err(|_| AotOperationSetV1Error::ArithmeticOverflow("builder output index"))?;
            let output = entry.axes.validate(root_u32)?;
            put_u16(&mut wire, output.tag());
            put_u16(&mut wire, 0);
            put_u32(&mut wire, root_u32);
            put_u64(&mut wire, 1);
        }
        let mut decoded_members = Vec::new();
        decoded_members
            .try_reserve_exact(members.len())
            .map_err(|_| AotOperationSetV1Error::Allocation("builder decoded members"))?;
        let mut member_payload_start = payload_offset;
        for member in members {
            wire.extend_from_slice(&member.payload);
            let member_payload_end = member_payload_start
                .checked_add(member.payload.len())
                .ok_or(AotOperationSetV1Error::ArithmeticOverflow(
                    "builder decoded member extent",
                ))?;
            decoded_members.push(AotOperationSetMemberV1 {
                payload_start: member_payload_start,
                payload_end: member_payload_end,
                identity: member.identity,
                program: member.program,
            });
            member_payload_start = member_payload_end;
        }
        if wire.len() != total_bytes || member_payload_start != total_bytes {
            return Err(AotOperationSetV1Error::Malformed(
                "builder emitted an unexpected total extent",
            ));
        }

        let mut decoded_roots = Vec::new();
        decoded_roots
            .try_reserve_exact(roots.len())
            .map_err(|_| AotOperationSetV1Error::Allocation("builder decoded roots"))?;
        for (root_index, root) in roots.into_iter().enumerate() {
            let root_u32 = u32::try_from(root_index)
                .map_err(|_| AotOperationSetV1Error::ArithmeticOverflow("builder root index"))?;
            let canonical_member = *canonical_index_by_member.get(root.member_index).ok_or(
                AotOperationSetV1Error::Malformed(
                    "builder could not retain a root's canonical member",
                ),
            )?;
            decoded_roots.push(AotOperationRootV1 {
                member_index: u32::try_from(canonical_member).map_err(|_| {
                    AotOperationSetV1Error::ArithmeticOverflow("builder member index")
                })?,
                axes: root.axes,
                output: root.axes.validate(root_u32)?,
            });
        }

        let identity = operation_set_identity(&wire);
        Ok(Self {
            wire: wire.into_boxed_slice(),
            identity,
            members: decoded_members,
            roots: decoded_roots,
        })
    }

    /// Exact stable wire, including verbatim member payloads.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire
    }

    /// Domain-separated SHA-256 of the exact stable wire.
    #[must_use]
    pub const fn identity(&self) -> [u8; 32] {
        self.identity
    }

    /// Number of deduplicated scalar members.
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
    pub fn operation(&self, index: usize) -> Option<AotOperationRootV1> {
        self.roots.get(index).copied()
    }

    /// Iterate roots in their semantic order.
    pub fn operations(&self) -> impl ExactSizeIterator<Item = AotOperationRootV1> + '_ {
        self.roots.iter().copied()
    }

    /// Return one strictly decoded scalar member in constant time.
    #[must_use]
    pub fn member_program(&self, index: usize) -> Option<&CompiledProgram> {
        self.members.get(index).map(|member| &member.program)
    }

    /// Return one exact verbatim member payload in constant time.
    #[must_use]
    pub fn member_bytes(&self, index: usize) -> Option<&[u8]> {
        let member = self.members.get(index)?;
        self.wire.get(member.payload_start..member.payload_end)
    }

    /// Return the SHA-256 identity of one exact member payload in constant time.
    #[must_use]
    pub fn member_identity(&self, index: usize) -> Option<[u8; 32]> {
        self.members.get(index).map(|member| member.identity)
    }

    /// Consume this validated owner for runtime preparation without cloning
    /// or reparsing any embedded program.
    #[doc(hidden)]
    #[must_use]
    pub fn into_parts(self) -> AotOperationSetV1Parts {
        AotOperationSetV1Parts {
            wire: self.wire,
            identity: self.identity,
            members: self.members,
            roots: self.roots,
        }
    }
}

#[derive(Debug)]
struct BuilderMember {
    identity: [u8; 32],
    payload: Vec<u8>,
    program: CompiledProgram,
    ingestion_index: usize,
}

#[derive(Clone, Copy, Debug)]
struct BuilderRoot {
    axes: AotOperationAxesV1,
    member_index: usize,
}

fn compare_builder_members(left: &BuilderMember, right: &BuilderMember) -> Ordering {
    compare_member_key(
        &left.identity,
        &left.payload,
        &right.identity,
        &right.payload,
    )
}

fn operation_set_wire_bytes(
    member_count: usize,
    root_count: usize,
    payload_bytes: usize,
) -> Result<usize, AotOperationSetV1Error> {
    let member_end = table_end(
        AOT_OPERATION_SET_V1_HEADER_BYTES,
        member_count,
        AOT_OPERATION_SET_V1_MEMBER_DESCRIPTOR_BYTES,
        "prospective member table",
    )?;
    let root_end = table_end(
        member_end,
        root_count,
        AOT_OPERATION_SET_V1_ROOT_DESCRIPTOR_BYTES,
        "prospective root table",
    )?;
    let stage_end = table_end(
        root_end,
        root_count,
        AOT_OPERATION_SET_V1_STAGE_DESCRIPTOR_BYTES,
        "prospective stage table",
    )?;
    let output_end = table_end(
        stage_end,
        root_count,
        AOT_OPERATION_SET_V1_OUTPUT_DESCRIPTOR_BYTES,
        "prospective output table",
    )?;
    output_end
        .checked_add(payload_bytes)
        .ok_or(AotOperationSetV1Error::ArithmeticOverflow(
            "prospective payload total",
        ))
}

fn compare_member_key(
    left_identity: &[u8; 32],
    left_payload: &[u8],
    right_identity: &[u8; 32],
    right_payload: &[u8],
) -> Ordering {
    left_identity
        .cmp(right_identity)
        .then_with(|| left_payload.cmp(right_payload))
}

fn operation_set_identity(bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(AOT_OPERATION_SET_V1_IDENTITY_DOMAIN);
    digest.update(bytes);
    digest.finalize().into()
}

fn record<'a>(
    bytes: &'a [u8],
    table_offset: usize,
    index: usize,
    record_bytes: usize,
    truncated: &'static str,
) -> Result<&'a [u8], AotOperationSetV1Error> {
    let start = index
        .checked_mul(record_bytes)
        .and_then(|relative| table_offset.checked_add(relative))
        .ok_or(AotOperationSetV1Error::ArithmeticOverflow(
            "table record offset",
        ))?;
    let end = start
        .checked_add(record_bytes)
        .ok_or(AotOperationSetV1Error::ArithmeticOverflow(
            "table record end",
        ))?;
    bytes
        .get(start..end)
        .ok_or(AotOperationSetV1Error::Malformed(truncated))
}

fn table_end(
    start: usize,
    count: usize,
    item_bytes: usize,
    computation: &'static str,
) -> Result<usize, AotOperationSetV1Error> {
    count
        .checked_mul(item_bytes)
        .and_then(|extent| start.checked_add(extent))
        .ok_or(AotOperationSetV1Error::ArithmeticOverflow(computation))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, AotOperationSetV1Error> {
    let end = offset
        .checked_add(2)
        .ok_or(AotOperationSetV1Error::ArithmeticOverflow("u16 field end"))?;
    let raw: [u8; 2] = bytes
        .get(offset..end)
        .ok_or(AotOperationSetV1Error::Malformed("u16 field is truncated"))?
        .try_into()
        .map_err(|_| AotOperationSetV1Error::Malformed("u16 field has the wrong size"))?;
    Ok(u16::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, AotOperationSetV1Error> {
    let end = offset
        .checked_add(4)
        .ok_or(AotOperationSetV1Error::ArithmeticOverflow("u32 field end"))?;
    let raw: [u8; 4] = bytes
        .get(offset..end)
        .ok_or(AotOperationSetV1Error::Malformed("u32 field is truncated"))?
        .try_into()
        .map_err(|_| AotOperationSetV1Error::Malformed("u32 field has the wrong size"))?;
    Ok(u32::from_le_bytes(raw))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, AotOperationSetV1Error> {
    let end = offset
        .checked_add(8)
        .ok_or(AotOperationSetV1Error::ArithmeticOverflow("u64 field end"))?;
    let raw: [u8; 8] = bytes
        .get(offset..end)
        .ok_or(AotOperationSetV1Error::Malformed("u64 field is truncated"))?
        .try_into()
        .map_err(|_| AotOperationSetV1Error::Malformed("u64 field has the wrong size"))?;
    Ok(u64::from_le_bytes(raw))
}

fn usize_from_u32(value: u32) -> Result<usize, AotOperationSetV1Error> {
    usize::try_from(value)
        .map_err(|_| AotOperationSetV1Error::Malformed("u32 index does not fit this host"))
}

fn usize_from_u64(value: u64) -> Result<usize, AotOperationSetV1Error> {
    usize::try_from(value)
        .map_err(|_| AotOperationSetV1Error::Malformed("u64 extent does not fit this host"))
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

fn put_usize_as_u64(bytes: &mut Vec<u8>, value: usize) -> Result<(), AotOperationSetV1Error> {
    put_u64(
        bytes,
        u64::try_from(value)
            .map_err(|_| AotOperationSetV1Error::ArithmeticOverflow("wire extent conversion"))?,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CompileMode, CompileRequest, Target, compile};

    fn program(pattern: &str, output: OutputContract) -> Vec<u8> {
        compile(
            CompileRequest::new(pattern, Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(output),
        )
        .expect("compile operation-set fixture")
        .program()
        .serialize()
        .expect("serialize operation-set fixture")
    }

    fn overwrite_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn overwrite_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn overwrite_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    struct HostileSizeHint<T> {
        item: Option<T>,
    }

    impl<T> Iterator for HostileSizeHint<T> {
        type Item = T;

        fn next(&mut self) -> Option<Self::Item> {
            self.item.take()
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            (usize::MAX, None)
        }
    }

    #[test]
    fn one_member_four_scalar_operations_have_exact_axes_and_wire() {
        let exists = program("a+", OutputContract::Exists);
        let span = program("a+", OutputContract::Span);
        for (axes, member, expected_output) in [
            (
                AotOperationAxesV1::SEARCH,
                exists.as_slice(),
                AotOperationOutputV1::OneRecord,
            ),
            (
                AotOperationAxesV1::COUNT,
                span.as_slice(),
                AotOperationOutputV1::ScalarU64,
            ),
            (
                AotOperationAxesV1::SPAN_SUM,
                span.as_slice(),
                AotOperationOutputV1::ScalarU64,
            ),
            (
                AotOperationAxesV1::GREP,
                exists.as_slice(),
                AotOperationOutputV1::ScalarU64,
            ),
        ] {
            let set = AotOperationSetV1::from_operations([(axes, member)])
                .expect("build one-operation set");
            assert_eq!(set.member_count(), 1);
            assert_eq!(set.operation_count(), 1);
            assert_eq!(set.member_bytes(0), Some(member));
            assert_eq!(set.operation(0).expect("root").axes(), axes);
            assert_eq!(set.operation(0).expect("root").output(), expected_output);
            assert_eq!(&set.as_bytes()[..8], &AOT_OPERATION_SET_V1_MAGIC);
            assert_eq!(read_u16(set.as_bytes(), HEADER_VERSION_OFFSET), Ok(1));
            assert_eq!(read_u16(set.as_bytes(), HEADER_BYTES_OFFSET), Ok(128));
            assert_eq!(read_u32(set.as_bytes(), HEADER_MEMBER_COUNT_OFFSET), Ok(1));
            assert_eq!(read_u32(set.as_bytes(), HEADER_SHARED_COUNT_OFFSET), Ok(0));
            assert_eq!(read_u32(set.as_bytes(), HEADER_ROOT_COUNT_OFFSET), Ok(1));
            assert_eq!(read_u32(set.as_bytes(), HEADER_STAGE_COUNT_OFFSET), Ok(1));
            assert_eq!(read_u32(set.as_bytes(), HEADER_OUTPUT_COUNT_OFFSET), Ok(1));
            let member_table_offset = AOT_OPERATION_SET_V1_HEADER_BYTES;
            let shared_table_offset =
                member_table_offset + AOT_OPERATION_SET_V1_MEMBER_DESCRIPTOR_BYTES;
            let root_table_offset = shared_table_offset;
            let stage_table_offset = root_table_offset + AOT_OPERATION_SET_V1_ROOT_DESCRIPTOR_BYTES;
            let output_table_offset =
                stage_table_offset + AOT_OPERATION_SET_V1_STAGE_DESCRIPTOR_BYTES;
            let payload_offset = output_table_offset + AOT_OPERATION_SET_V1_OUTPUT_DESCRIPTOR_BYTES;
            assert_eq!(
                read_u64(set.as_bytes(), HEADER_MEMBER_TABLE_OFFSET),
                Ok(u64::try_from(member_table_offset).expect("member table offset"))
            );
            assert_eq!(
                read_u64(set.as_bytes(), HEADER_SHARED_TABLE_OFFSET),
                Ok(u64::try_from(shared_table_offset).expect("shared table offset"))
            );
            assert_eq!(
                read_u64(set.as_bytes(), HEADER_ROOT_TABLE_OFFSET),
                Ok(u64::try_from(root_table_offset).expect("root table offset"))
            );
            assert_eq!(
                read_u64(set.as_bytes(), HEADER_STAGE_TABLE_OFFSET),
                Ok(u64::try_from(stage_table_offset).expect("stage table offset"))
            );
            assert_eq!(
                read_u64(set.as_bytes(), HEADER_OUTPUT_TABLE_OFFSET),
                Ok(u64::try_from(output_table_offset).expect("output table offset"))
            );
            assert_eq!(
                read_u64(set.as_bytes(), HEADER_PAYLOAD_OFFSET),
                Ok(u64::try_from(payload_offset).expect("payload offset"))
            );
            assert_eq!(read_u32(set.as_bytes(), member_table_offset), Ok(1));
            assert_eq!(
                read_u32(set.as_bytes(), member_table_offset + 8),
                Ok(AOT_OPERATION_SET_V1_NONE_INDEX)
            );
            assert_eq!(
                read_u32(set.as_bytes(), member_table_offset + 12),
                Ok(AOT_OPERATION_SET_V1_NONE_INDEX)
            );
            assert_eq!(read_u32(set.as_bytes(), root_table_offset), Ok(0));
            assert_eq!(read_u32(set.as_bytes(), root_table_offset + 4), Ok(1));
            assert_eq!(read_u32(set.as_bytes(), root_table_offset + 8), Ok(0));
            assert_eq!(read_u32(set.as_bytes(), root_table_offset + 12), Ok(1));
            assert_eq!(
                read_u16(set.as_bytes(), stage_table_offset + 4),
                Ok(axes.reducer().tag())
            );
            assert_eq!(
                read_u16(set.as_bytes(), stage_table_offset + 6),
                Ok(axes.projection().tag())
            );
            assert_eq!(
                read_u16(set.as_bytes(), stage_table_offset + 8),
                Ok(axes.domain().tag())
            );
            assert_eq!(
                read_u16(set.as_bytes(), output_table_offset),
                Ok(expected_output.tag())
            );
            assert_eq!(read_u32(set.as_bytes(), output_table_offset + 4), Ok(0));
            assert_eq!(read_u64(set.as_bytes(), output_table_offset + 8), Ok(1));
            assert_eq!(set.as_bytes().len(), payload_offset + member.len());
            let mut independent_identity = Sha256::new();
            independent_identity.update(AOT_OPERATION_SET_V1_IDENTITY_DOMAIN);
            independent_identity.update(set.as_bytes());
            let independent_identity: [u8; 32] = independent_identity.finalize().into();
            assert_eq!(set.identity(), independent_identity);
            let restored = AotOperationSetV1::deserialize(set.as_bytes())
                .expect("round trip exact operation set");
            assert_eq!(restored.as_bytes(), set.as_bytes());
            assert_eq!(restored.identity(), set.identity());
        }
    }

    #[test]
    fn many_roots_deduplicate_sort_and_randomly_access_verbatim_members() {
        let alpha_span = program("alpha+", OutputContract::Span);
        let beta_exists = program("beta+", OutputContract::Exists);
        let gamma_exists = program("gamma+", OutputContract::Exists);
        let set = AotOperationSetV1::from_operations([
            (AotOperationAxesV1::SEARCH, beta_exists.as_slice()),
            (AotOperationAxesV1::COUNT, alpha_span.as_slice()),
            (AotOperationAxesV1::SPAN_SUM, alpha_span.as_slice()),
            (AotOperationAxesV1::GREP, gamma_exists.as_slice()),
            (AotOperationAxesV1::SEARCH, beta_exists.as_slice()),
        ])
        .expect("build deduplicated operation set");
        assert_eq!(set.member_count(), 3);
        assert_eq!(set.operation_count(), 5);
        assert_eq!(
            set.operations()
                .map(AotOperationRootV1::axes)
                .collect::<Vec<_>>(),
            vec![
                AotOperationAxesV1::SEARCH,
                AotOperationAxesV1::COUNT,
                AotOperationAxesV1::SPAN_SUM,
                AotOperationAxesV1::GREP,
                AotOperationAxesV1::SEARCH,
            ]
        );
        let first_beta = set.operation(0).expect("first beta").member_index();
        let second_beta = set.operation(4).expect("second beta").member_index();
        let first_alpha = set.operation(1).expect("first alpha").member_index();
        let second_alpha = set.operation(2).expect("second alpha").member_index();
        assert_eq!(first_beta, second_beta);
        assert_eq!(first_alpha, second_alpha);
        assert_eq!(
            set.member_bytes(usize::try_from(first_beta).expect("beta index")),
            Some(beta_exists.as_slice())
        );
        assert_eq!(
            set.member_bytes(usize::try_from(first_alpha).expect("alpha index")),
            Some(alpha_span.as_slice())
        );
        for pair in 0..set.member_count().saturating_sub(1) {
            let left_identity = set.member_identity(pair).expect("left identity");
            let right_identity = set.member_identity(pair + 1).expect("right identity");
            assert_eq!(
                compare_member_key(
                    &left_identity,
                    set.member_bytes(pair).expect("left payload"),
                    &right_identity,
                    set.member_bytes(pair + 1).expect("right payload"),
                ),
                Ordering::Less
            );
        }
        let restored = AotOperationSetV1::deserialize(set.as_bytes())
            .expect("strictly reconstruct multi-root operation set");
        assert_eq!(restored.as_bytes(), set.as_bytes());
        assert_eq!(restored.identity(), set.identity());
        assert_eq!(restored.member_count(), set.member_count());
        assert_eq!(
            restored.operations().collect::<Vec<_>>(),
            set.operations().collect::<Vec<_>>()
        );
        for member in 0..set.member_count() {
            assert_eq!(
                restored.member_identity(member),
                set.member_identity(member)
            );
            assert_eq!(restored.member_bytes(member), set.member_bytes(member));
        }
    }

    #[test]
    fn ten_thousand_duplicate_roots_store_and_decode_one_unique_member() {
        let exists = program("shared-member", OutputContract::Exists);
        let prior_decodes = TEST_BUILDER_UNIQUE_PROGRAM_DECODES.with(core::cell::Cell::get);
        let set = AotOperationSetV1::from_operations(
            (0..10_000).map(|_| (AotOperationAxesV1::SEARCH, exists.as_slice())),
        )
        .expect("build large duplicate-root set");
        let completed_decodes = TEST_BUILDER_UNIQUE_PROGRAM_DECODES.with(core::cell::Cell::get);
        assert_eq!(completed_decodes.saturating_sub(prior_decodes), 1);
        assert_eq!(set.member_count(), 1);
        assert_eq!(set.operation_count(), 10_000);
        let expected_bytes = AOT_OPERATION_SET_V1_HEADER_BYTES
            + AOT_OPERATION_SET_V1_MEMBER_DESCRIPTOR_BYTES
            + 10_000
                * (AOT_OPERATION_SET_V1_ROOT_DESCRIPTOR_BYTES
                    + AOT_OPERATION_SET_V1_STAGE_DESCRIPTOR_BYTES
                    + AOT_OPERATION_SET_V1_OUTPUT_DESCRIPTOR_BYTES)
            + exists.len();
        assert_eq!(set.as_bytes().len(), expected_bytes);
        assert!(
            set.operations()
                .all(|root| root.member_index() == 0 && root.axes() == AotOperationAxesV1::SEARCH)
        );
    }

    #[test]
    fn builder_rejects_incompatible_output_and_unknown_axis_tuple() {
        let exists = program("a+", OutputContract::Exists);
        assert!(matches!(
            AotOperationSetV1::from_operations([(AotOperationAxesV1::COUNT, exists.as_slice())]),
            Err(AotOperationSetV1Error::IncompatibleProgramOutput { .. })
        ));
        let unsupported = AotOperationAxesV1::new(
            AotReducerV1::SelectOne,
            AotProjectionV1::Span,
            AotDomainV1::Whole,
        );
        assert!(matches!(
            AotOperationSetV1::from_operations([(unsupported, exists.as_slice())]),
            Err(AotOperationSetV1Error::UnsupportedOperationAxes { .. })
        ));
    }

    #[test]
    fn empty_and_over_cap_sets_are_rejected_before_member_work() {
        let empty = std::iter::empty::<(AotOperationAxesV1, &[u8])>();
        assert!(matches!(
            AotOperationSetV1::from_operations(empty),
            Err(AotOperationSetV1Error::Malformed(
                "operation set has no semantic roots"
            ))
        ));

        let span = program("a+", OutputContract::Span);
        let valid =
            AotOperationSetV1::from_operations([(AotOperationAxesV1::COUNT, span.as_slice())])
                .expect("build resource mutation fixture");
        let mut over_cap = valid.as_bytes().to_vec();
        overwrite_u64(
            &mut over_cap,
            HEADER_TOTAL_BYTES_OFFSET,
            u64::try_from(MAX_AOT_OPERATION_SET_V1_BYTES).expect("stable cap fits u64") + 1,
        );
        assert!(matches!(
            AotOperationSetV1::deserialize(&over_cap),
            Err(AotOperationSetV1Error::ResourceLimit {
                resource: "wire bytes",
                limit: MAX_AOT_OPERATION_SET_V1_BYTES,
                required,
            }) if required == MAX_AOT_OPERATION_SET_V1_BYTES + 1
        ));
    }

    #[test]
    fn builder_bounds_an_untrusted_iterator_size_hint() {
        let exists = program("a+", OutputContract::Exists);
        let set = AotOperationSetV1::from_operations(HostileSizeHint {
            item: Some((AotOperationAxesV1::SEARCH, exists.as_slice())),
        })
        .expect("build despite a hostile allocation hint");
        assert_eq!(set.member_count(), 1);
        assert_eq!(set.operation_count(), 1);
    }

    #[test]
    fn consuming_parts_preserves_decoded_members_identities_and_root_order() {
        let exists = program("a+", OutputContract::Exists);
        let span = program("b+", OutputContract::Span);
        let set = AotOperationSetV1::from_operations([
            (AotOperationAxesV1::SEARCH, exists.as_slice()),
            (AotOperationAxesV1::COUNT, span.as_slice()),
            (AotOperationAxesV1::GREP_COUNT, exists.as_slice()),
        ])
        .expect("build ownership handoff fixture");
        let set_identity = set.identity();
        let member_identities = (0..set.member_count())
            .map(|index| set.member_identity(index).expect("member identity"))
            .collect::<Vec<_>>();
        let roots = set.operations().collect::<Vec<_>>();
        let parts = set.into_parts();
        assert_eq!(parts.identity(), set_identity);
        assert_eq!(parts.roots(), roots);
        assert_eq!(parts.members().len(), member_identities.len());
        for (index, expected_identity) in member_identities.iter().copied().enumerate() {
            assert_eq!(parts.members()[index].identity(), expected_identity);
            let actual_identity: [u8; 32] =
                Sha256::digest(parts.member_bytes(index).expect("verbatim member")).into();
            assert_eq!(actual_identity, expected_identity);
        }
        let (moved_identity, moved_members, moved_roots) = parts.into_components();
        assert_eq!(moved_identity, set_identity);
        assert_eq!(moved_roots, roots);
        assert_eq!(moved_members.len(), member_identities.len());
        for (member, expected_identity) in moved_members.into_iter().zip(member_identities) {
            assert_eq!(member.identity(), expected_identity);
            let output = member.program().output_contract();
            assert!(matches!(
                output,
                OutputContract::Exists | OutputContract::Span
            ));
            let _owned_program = member.into_program();
        }
    }

    #[test]
    fn strict_reader_rejects_noncanonical_header_and_record_mutations() {
        let span = program("a+", OutputContract::Span);
        let valid =
            AotOperationSetV1::from_operations([(AotOperationAxesV1::COUNT, span.as_slice())])
                .expect("build mutation fixture");
        for truncated in 0..AOT_OPERATION_SET_V1_HEADER_BYTES {
            assert!(AotOperationSetV1::deserialize(&valid.as_bytes()[..truncated]).is_err());
        }

        let mutate = |offset: usize, width: usize, value: u64| {
            let mut bytes = valid.as_bytes().to_vec();
            match width {
                2 => overwrite_u16(&mut bytes, offset, u16::try_from(value).expect("u16 value")),
                4 => overwrite_u32(&mut bytes, offset, u32::try_from(value).expect("u32 value")),
                8 => overwrite_u64(&mut bytes, offset, value),
                _ => unreachable!("test field width"),
            }
            AotOperationSetV1::deserialize(&bytes)
        };
        assert!(matches!(
            mutate(HEADER_VERSION_OFFSET, 2, 2),
            Err(AotOperationSetV1Error::UnsupportedVersion(2))
        ));
        assert!(matches!(
            mutate(HEADER_FLAGS_OFFSET, 4, 1),
            Err(AotOperationSetV1Error::UnsupportedFlags {
                table: "header",
                ..
            })
        ));
        assert!(matches!(
            mutate(HEADER_SHARED_COUNT_OFFSET, 4, 1),
            Err(AotOperationSetV1Error::UnsupportedFeature(
                "shared-member records"
            ))
        ));
        for offset in [
            HEADER_MEMBER_TABLE_OFFSET,
            HEADER_SHARED_TABLE_OFFSET,
            HEADER_ROOT_TABLE_OFFSET,
            HEADER_STAGE_TABLE_OFFSET,
            HEADER_OUTPUT_TABLE_OFFSET,
            HEADER_PAYLOAD_OFFSET,
        ] {
            assert!(mutate(offset, 8, 0).is_err(), "offset {offset}");
        }
        let member_offset = AOT_OPERATION_SET_V1_HEADER_BYTES;
        assert!(matches!(
            mutate(member_offset, 4, 99),
            Err(AotOperationSetV1Error::UnsupportedTag {
                table: "member",
                ..
            })
        ));
        assert!(mutate(member_offset + 8, 4, 0).is_err());
        let root_offset = usize_from_u64(
            read_u64(valid.as_bytes(), HEADER_ROOT_TABLE_OFFSET).expect("root offset"),
        )
        .expect("host root offset");
        assert!(mutate(root_offset + 4, 4, 2).is_err());
        let stage_offset = usize_from_u64(
            read_u64(valid.as_bytes(), HEADER_STAGE_TABLE_OFFSET).expect("stage offset"),
        )
        .expect("host stage offset");
        assert!(matches!(
            mutate(stage_offset + 4, 2, 99),
            Err(AotOperationSetV1Error::UnsupportedTag {
                table: "stage reducer",
                ..
            })
        ));
        assert!(mutate(stage_offset + 16, 8, 1).is_err());
        let output_offset = usize_from_u64(
            read_u64(valid.as_bytes(), HEADER_OUTPUT_TABLE_OFFSET).expect("output offset"),
        )
        .expect("host output offset");
        assert!(mutate(output_offset + 8, 8, 2).is_err());

        let mut trailing = valid.as_bytes().to_vec();
        trailing.push(0);
        assert!(AotOperationSetV1::deserialize(&trailing).is_err());
        let payload_offset = usize_from_u64(
            read_u64(valid.as_bytes(), HEADER_PAYLOAD_OFFSET).expect("payload offset"),
        )
        .expect("host payload offset");
        let mut malformed_child = valid.as_bytes().to_vec();
        malformed_child[payload_offset] ^= 1;
        assert!(matches!(
            AotOperationSetV1::deserialize(&malformed_child),
            Err(AotOperationSetV1Error::MemberProgram { .. })
        ));
    }

    #[test]
    fn strict_reader_rejects_duplicate_or_unreachable_members() {
        let first = program("alpha", OutputContract::Exists);
        let second = program("beta", OutputContract::Exists);
        let set = AotOperationSetV1::from_operations([
            (AotOperationAxesV1::SEARCH, first.as_slice()),
            (AotOperationAxesV1::SEARCH, second.as_slice()),
        ])
        .expect("build two-member mutation fixture");
        let mut unreachable = set.as_bytes().to_vec();
        let stage_offset = usize_from_u64(
            read_u64(&unreachable, HEADER_STAGE_TABLE_OFFSET).expect("stage offset"),
        )
        .expect("host stage offset");
        let first_member = read_u32(&unreachable, stage_offset).expect("first member");
        overwrite_u32(
            &mut unreachable,
            stage_offset + AOT_OPERATION_SET_V1_STAGE_DESCRIPTOR_BYTES,
            first_member,
        );
        assert!(matches!(
            AotOperationSetV1::deserialize(&unreachable),
            Err(AotOperationSetV1Error::Malformed(
                "member table contains an unreachable payload"
            ))
        ));

        // Reversing descriptors while leaving their contiguous payloads in
        // place is never another encoding: each descriptor now names the
        // wrong child extent or violates the digest-byte ordering.
        let mut nonascending = set.as_bytes().to_vec();
        let left = nonascending[AOT_OPERATION_SET_V1_HEADER_BYTES
            ..AOT_OPERATION_SET_V1_HEADER_BYTES + AOT_OPERATION_SET_V1_MEMBER_DESCRIPTOR_BYTES]
            .to_vec();
        let right_start =
            AOT_OPERATION_SET_V1_HEADER_BYTES + AOT_OPERATION_SET_V1_MEMBER_DESCRIPTOR_BYTES;
        let right = nonascending
            [right_start..right_start + AOT_OPERATION_SET_V1_MEMBER_DESCRIPTOR_BYTES]
            .to_vec();
        nonascending[AOT_OPERATION_SET_V1_HEADER_BYTES
            ..AOT_OPERATION_SET_V1_HEADER_BYTES + AOT_OPERATION_SET_V1_MEMBER_DESCRIPTOR_BYTES]
            .copy_from_slice(&right);
        nonascending[right_start..right_start + AOT_OPERATION_SET_V1_MEMBER_DESCRIPTOR_BYTES]
            .copy_from_slice(&left);
        assert!(AotOperationSetV1::deserialize(&nonascending).is_err());

        let alpha = program("alpha", OutputContract::Exists);
        let omega = program("omega", OutputContract::Exists);
        assert_eq!(alpha.len(), omega.len());
        let duplicate_fixture = AotOperationSetV1::from_operations([
            (AotOperationAxesV1::SEARCH, alpha.as_slice()),
            (AotOperationAxesV1::SEARCH, omega.as_slice()),
        ])
        .expect("build equal-length duplicate mutation fixture");
        let mut duplicate = duplicate_fixture.as_bytes().to_vec();
        let first_payload_offset = usize_from_u64(
            read_u64(&duplicate, AOT_OPERATION_SET_V1_HEADER_BYTES + 16)
                .expect("first payload offset"),
        )
        .expect("host first payload offset");
        let first_payload_len = usize_from_u64(
            read_u64(&duplicate, AOT_OPERATION_SET_V1_HEADER_BYTES + 24)
                .expect("first payload length"),
        )
        .expect("host first payload length");
        let second_descriptor =
            AOT_OPERATION_SET_V1_HEADER_BYTES + AOT_OPERATION_SET_V1_MEMBER_DESCRIPTOR_BYTES;
        let second_payload_offset = usize_from_u64(
            read_u64(&duplicate, second_descriptor + 16).expect("second payload offset"),
        )
        .expect("host second payload offset");
        let second_payload_len = usize_from_u64(
            read_u64(&duplicate, second_descriptor + 24).expect("second payload length"),
        )
        .expect("host second payload length");
        assert_eq!(first_payload_len, second_payload_len);
        let copied =
            duplicate[first_payload_offset..first_payload_offset + first_payload_len].to_vec();
        duplicate[second_payload_offset..second_payload_offset + second_payload_len]
            .copy_from_slice(&copied);
        assert!(matches!(
            AotOperationSetV1::deserialize(&duplicate),
            Err(AotOperationSetV1Error::Malformed(
                "member payloads are duplicate or not in canonical digest-byte order"
            ))
        ));
    }
}
