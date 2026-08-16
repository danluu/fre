//! Stable V1 serialization for immutable capture programs.
//!
//! The wire image contains only execution semantics: profile, capture schema,
//! prioritized Thompson instructions, byte ranges, and the compiler-derived
//! start prefilter. Incidental AST construction accounting is deliberately
//! excluded. Restoration publishes no program until the complete extent,
//! digest, schema, graph, resource envelope, and canonical re-encoding agree.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "all variable format arithmetic is checked; remaining arithmetic uses proved fixed record widths, validated indices, or the 256-byte domain"
)]

use core::fmt;
use std::mem::size_of;

use sha2::{Digest, Sha256};

use crate::ast::Assertion;
use crate::compile::{GroupMeta, Program, State, valid_name};
use crate::error::SearchError;
use crate::history::{
    HistoryExactWorkspace, HistoryExactWorkspaceBinding, HistoryExactWorkspaceUsage,
    derive_history_exact_workspace_usage, execute_exact_with_workspace,
    prepare_history_exact_workspace,
};
use crate::limits::SearchLimits;
use crate::model::{CaptureGroupSlot, ExactCaptureSlotsOutcome, Span, Window};
use crate::onepass::{
    OnePassCaptureBuildFailure, OnePassCaptureBuildLimits, OnePassCapturePlan,
    OnePassCaptureWorkspace,
};
use crate::profile::CaptureProfile;
use crate::runtime::commit_capture_group_slots;

const MAGIC: [u8; 8] = *b"FRECAP\0\x01";
const FORMAT_VERSION: u16 = 1;
const PROFILE_RUST_REGEX_BYTES_1_12_4: u8 = 1;
const FLAGS: u8 = 0;
const SCHEMA_ENTRY_BYTES: usize = 16;
const STATE_ENTRY_BYTES: usize = 24;
const RANGE_BYTES: usize = 2;
const DIGEST_OFFSET: usize = 64;
const DIGEST_BYTES: usize = 32;
const DIGEST_DOMAIN: &[u8] = b"fre-capture-lab/capture-program-v1\0";
const HARD_MAX_SERIALIZED_BYTES: usize = 64 * 1024 * 1024;
const EXACT_PREFIX_2_TAG: u8 = 0x82;
const EXACT_PREFIX_3_TAG: u8 = 0x83;

const OPCODE_BYTE: u8 = 1;
const OPCODE_SPLIT: u8 = 2;
const OPCODE_SAVE: u8 = 3;
const OPCODE_ASSERT: u8 = 4;
const OPCODE_EPSILON: u8 = 5;
const OPCODE_MATCH: u8 = 6;
const OPCODE_FAIL: u8 = 7;

/// Fixed bytes needed to discover a V1 artifact's exact extent.
pub const CAPTURE_PROGRAM_V1_HEADER_BYTES: usize = 96;

/// Independent stable-program resource ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureProgramV1Limits {
    /// Maximum exact serialized extent.
    pub max_serialized_bytes: usize,
    /// Maximum Thompson instruction count.
    pub max_states: usize,
    /// Maximum total byte-class range count.
    pub max_byte_ranges: usize,
    /// Maximum schema groups, including implicit group zero.
    pub max_groups: usize,
    /// Maximum capture slots, including group-zero start/end slots.
    pub max_slots: usize,
    /// Maximum aggregate capture-name payload bytes.
    pub max_name_bytes: usize,
    /// Maximum versioned source-independent validation work.
    pub max_validation_work: usize,
    /// Maximum conservative reconstructed immutable-program bytes.
    pub max_program_bytes: usize,
}

impl Default for CaptureProgramV1Limits {
    fn default() -> Self {
        Self {
            max_serialized_bytes: 16 * 1024 * 1024,
            max_states: 65_536,
            max_byte_ranges: 1_000_000,
            // BuildLimits admits 64 user groups. The stable schema also owns
            // implicit group zero and its two slots.
            max_groups: 65,
            max_slots: 130,
            max_name_bytes: 1024 * 1024,
            max_validation_work: 4_000_000,
            max_program_bytes: 16 * 1024 * 1024,
        }
    }
}

/// One independently limited stable-program dimension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureProgramV1Resource {
    /// Exact wire bytes.
    SerializedBytes,
    /// Thompson instructions.
    States,
    /// Inclusive byte ranges.
    ByteRanges,
    /// Schema groups, including implicit group zero.
    Groups,
    /// Start/end slots, including group zero's two slots.
    Slots,
    /// Aggregate capture-name payload bytes.
    NameBytes,
    /// Versioned validation work.
    ValidationWork,
    /// Conservative reconstructed immutable-program bytes.
    ProgramBytes,
}

/// Fallible allocation site while sealing or restoring a V1 artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureProgramV1Allocation {
    /// Canonical serialized bytes.
    SerializedBytes,
    /// Immutable program instruction vector.
    ProgramStates,
    /// One instruction's byte-range vector.
    ByteRanges,
    /// Immutable program schema vector.
    ProgramGroups,
    /// Public immutable schema snapshot.
    SchemaGroups,
    /// One owned capture name.
    GroupName,
    /// Graph reachability or prefilter-proof scratch.
    ValidationScratch,
}

/// Typed malformed-wire failure.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CaptureProgramV1FormatError {
    /// The fixed header or a section record is truncated.
    Truncated(&'static str),
    /// The artifact magic is not V1 capture-program magic.
    BadMagic,
    /// The format version is unsupported.
    UnsupportedVersion(u16),
    /// The fixed header-size field is not V1's size.
    InvalidHeaderBytes(u16),
    /// The semantic profile tag is unknown or pending.
    UnsupportedProfile(u8),
    /// A flag bit is not defined by V1.
    UnknownFlags(u8),
    /// A reserved field is nonzero.
    NonZeroReserved(&'static str),
    /// The declared total and supplied or derived exact extent disagree.
    ExtentMismatch {
        /// Extent declared in the header.
        declared: usize,
        /// Supplied or section-derived extent.
        actual: usize,
    },
    /// The domain-separated SHA-256 does not authenticate the artifact.
    DigestMismatch,
    /// A schema invariant is invalid.
    InvalidSchema(&'static str),
    /// A named-group payload is not UTF-8.
    InvalidNameUtf8,
    /// A name violates the capture compiler's admitted name contract.
    InvalidName,
    /// Two named groups have the same admitted name.
    DuplicateName,
    /// An instruction opcode is unknown.
    UnknownOpcode(u8),
    /// An assertion tag is unknown.
    UnknownAssertion(u8),
    /// A target does not name an instruction.
    InvalidTarget,
    /// A byte-range slice or interval is invalid.
    InvalidRange,
    /// A Save instruction does not map to the declared schema slots.
    InvalidSlot,
    /// The canonical group-zero start/end or terminal Match shape is invalid.
    InvalidProgramShape(&'static str),
    /// The retained start prefilter is not the exact graph-derived proof.
    InvalidStartPrefilter,
    /// At least one serialized instruction is not reachable from the start.
    UnreachableState,
    /// Decoding and canonical re-encoding did not reproduce every byte.
    NonCanonicalEncoding,
}

impl fmt::Display for CaptureProgramV1FormatError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for CaptureProgramV1FormatError {}

/// Checked V1 seal/restore failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaptureProgramV1Error {
    /// Malformed or noncanonical wire data.
    Format(CaptureProgramV1FormatError),
    /// One independent stable-program ceiling would be exceeded.
    Resource {
        /// Limited dimension.
        resource: CaptureProgramV1Resource,
        /// Required amount, or [`usize::MAX`] after checked overflow.
        required: usize,
        /// Effective maximum.
        limit: usize,
    },
    /// A fallible reservation failed after resource admission.
    Allocation {
        /// Structure being reserved.
        allocation: CaptureProgramV1Allocation,
        /// Requested item count.
        items: usize,
    },
    /// Checked format or resource arithmetic overflowed.
    ArithmeticOverflow(&'static str),
    /// A trusted in-memory program violates the compiler/wire contract.
    InternalInvariant(&'static str),
}

impl fmt::Display for CaptureProgramV1Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format(error) => write!(formatter, "invalid capture program V1: {error}"),
            Self::Resource {
                resource,
                required,
                limit,
            } => write!(
                formatter,
                "capture program V1 resource {resource:?} requires {required}, limit is {limit}"
            ),
            Self::Allocation { allocation, items } => write!(
                formatter,
                "capture program V1 failed to reserve {items} {allocation:?} items"
            ),
            Self::ArithmeticOverflow(site) => {
                write!(
                    formatter,
                    "capture program V1 arithmetic overflow at {site}"
                )
            }
            Self::InternalInvariant(detail) => {
                write!(formatter, "capture program V1 invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for CaptureProgramV1Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Format(error) => Some(error),
            Self::Resource { .. }
            | Self::Allocation { .. }
            | Self::ArithmeticOverflow(_)
            | Self::InternalInvariant(_) => None,
        }
    }
}

impl From<CaptureProgramV1FormatError> for CaptureProgramV1Error {
    fn from(error: CaptureProgramV1FormatError) -> Self {
        Self::Format(error)
    }
}

/// Exact source-independent dimensions of one V1 artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureProgramV1Usage {
    /// Exact stable bytes.
    pub serialized_bytes: usize,
    /// Thompson instructions.
    pub states: usize,
    /// Inclusive byte ranges.
    pub byte_ranges: usize,
    /// Schema groups, including implicit group zero.
    pub groups: usize,
    /// Capture slots, including group zero's start/end slots.
    pub slots: usize,
    /// Aggregate capture-name bytes.
    pub name_bytes: usize,
    /// Versioned validation work.
    pub validation_work: usize,
    /// Conservative reconstructed immutable-program bytes.
    pub program_bytes: usize,
}

/// One immutable capture-schema entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureGroupSchema {
    index: u32,
    name: Option<String>,
}

impl CaptureGroupSchema {
    /// Numeric group index. Group zero is the implicit overall match.
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }

    /// Optional admitted capture name.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
}

/// Immutable capture schema suitable for retention by a later prepared handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureSchema {
    groups: Vec<CaptureGroupSchema>,
    slot_count: usize,
}

impl CaptureSchema {
    /// All groups in numeric order, including implicit group zero.
    #[must_use]
    pub fn groups(&self) -> &[CaptureGroupSchema] {
        &self.groups
    }

    /// Group count including implicit group zero.
    #[must_use]
    pub const fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// User group count excluding implicit group zero.
    #[must_use]
    pub fn user_group_count(&self) -> usize {
        self.groups.len().saturating_sub(1)
    }

    /// Start/end slot count including group zero's two slots.
    #[must_use]
    pub const fn slot_count(&self) -> usize {
        self.slot_count
    }

    /// Lookup one group by its numeric index.
    #[must_use]
    pub fn group(&self, index: usize) -> Option<&CaptureGroupSchema> {
        self.groups.get(index)
    }
}

/// One validated, canonical V1 capture program.
#[derive(Debug)]
pub struct CaptureProgramV1 {
    program: Program,
    schema: CaptureSchema,
    usage: CaptureProgramV1Usage,
    semantic_digest: [u8; DIGEST_BYTES],
    bytes: Vec<u8>,
}

impl CaptureProgramV1 {
    /// Seal one compiler-produced immutable program into canonical V1 bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed resource, allocation, arithmetic, or trusted-program
    /// invariant failure. The program is not published on failure.
    pub fn from_program(
        program: Program,
        limits: CaptureProgramV1Limits,
    ) -> Result<Self, CaptureProgramV1Error> {
        if !program.build_report_closes() {
            return Err(CaptureProgramV1Error::InternalInvariant(
                "compiler program accounting does not close",
            ));
        }
        let usage = usage_from_program(&program, limits)?;
        validate_program(&program, usage.validation_work)?;
        let schema = snapshot_schema(&program.groups)?;
        let encoded = encode_program(&program, usage)?;
        let semantic_digest = digest_from_header(&encoded)?;
        Ok(Self {
            program,
            schema,
            usage,
            semantic_digest,
            bytes: encoded,
        })
    }

    /// Strictly restore one exact V1 artifact.
    ///
    /// Header, exact extent, every ceiling, and the domain-separated digest
    /// are checked before any reconstruction allocation. Publication then
    /// requires complete schema/graph validation and byte-identical canonical
    /// re-encoding.
    ///
    /// # Errors
    ///
    /// Returns [`CaptureProgramV1Error`] for malformed or unsupported input,
    /// a resource refusal, failed bounded allocation, or arithmetic overflow.
    pub fn deserialize(
        bytes: &[u8],
        limits: CaptureProgramV1Limits,
    ) -> Result<Self, CaptureProgramV1Error> {
        let header = parse_header(bytes, limits)?;
        verify_digest(bytes, header.digest)?;
        validate_schema_wire(bytes, header)?;
        validate_state_wire(bytes, header)?;

        let groups = decode_groups(bytes, header)?;
        let schema = snapshot_schema(&groups)?;
        let states = decode_states(bytes, header)?;
        let program = Program::from_validated_v1_parts(
            states,
            header.start,
            header.usage.slots,
            groups,
            header.profile,
            header.usage.program_bytes,
            header.usage.validation_work,
        );
        validate_program(&program, header.usage.validation_work)?;
        if !program.build_report_closes() {
            return Err(CaptureProgramV1Error::InternalInvariant(
                "restored program accounting does not close",
            ));
        }
        let canonical = encode_program(&program, header.usage)?;
        if canonical.as_slice() != bytes {
            return Err(CaptureProgramV1FormatError::NonCanonicalEncoding.into());
        }
        Ok(Self {
            program,
            schema,
            usage: header.usage,
            semantic_digest: header.digest,
            bytes: canonical,
        })
    }

    /// Discover the exact extent from one fixed V1 header without allocation.
    ///
    /// # Errors
    ///
    /// Rejects a non-exact fixed header, malformed fixed fields, inconsistent
    /// section arithmetic, or a resource ceiling violation.
    pub fn serialized_len_from_header(
        header: &[u8],
        limits: CaptureProgramV1Limits,
    ) -> Result<usize, CaptureProgramV1Error> {
        if header.len() != CAPTURE_PROGRAM_V1_HEADER_BYTES {
            return Err(CaptureProgramV1FormatError::Truncated(
                "fixed header has the wrong extent",
            )
            .into());
        }
        Ok(parse_fixed_header(header, limits)?.usage.serialized_bytes)
    }

    /// Borrow the executable immutable capture program.
    #[must_use]
    pub const fn program(&self) -> &Program {
        &self.program
    }

    /// Borrow the immutable capture schema.
    #[must_use]
    pub const fn schema(&self) -> &CaptureSchema {
        &self.schema
    }

    /// Borrow exact V1 resource accounting.
    #[must_use]
    pub const fn usage(&self) -> CaptureProgramV1Usage {
        self.usage
    }

    /// Domain-separated SHA-256 of the canonical semantic artifact.
    #[must_use]
    pub const fn semantic_digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.semantic_digest
    }

    /// Borrow exact canonical serialized bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Fallibly copy exact canonical serialized bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed allocation failure if the output cannot be reserved.
    pub fn serialize(&self) -> Result<Vec<u8>, CaptureProgramV1Error> {
        let mut bytes = Vec::new();
        reserve_exact(
            &mut bytes,
            self.bytes.len(),
            CaptureProgramV1Allocation::SerializedBytes,
        )?;
        bytes.extend_from_slice(&self.bytes);
        Ok(bytes)
    }

    /// Derive exact persistent-history workspace dimensions and execution
    /// admission without allocating or inspecting source bytes.
    pub fn history_exact_workspace_usage(
        &self,
        max_span_bytes: usize,
        limits: SearchLimits,
    ) -> Result<HistoryExactWorkspaceUsage, SearchError> {
        derive_history_exact_workspace_usage(&self.program, max_span_bytes, limits)
    }

    /// Prepare allocation-free persistent-history replay bound to this exact
    /// semantic digest after its source-independent usage can be admitted by
    /// an outer owner through [`Self::history_exact_workspace_usage`].
    ///
    /// A byte-identical independently restored V1 artifact may use the same
    /// workspace. A different digest or program shape is rejected before
    /// source access.
    pub fn prepare_history_exact_workspace(
        &self,
        max_span_bytes: usize,
        limits: SearchLimits,
    ) -> Result<HistoryExactWorkspace, SearchError> {
        prepare_history_exact_workspace(
            &self.program,
            HistoryExactWorkspaceBinding::CaptureProgramV1(self.semantic_digest),
            max_span_bytes,
            limits,
        )
    }

    /// Replay one exact span with fixed history storage and transactionally
    /// publish one typed result per schema group.
    pub fn captures_exact_slots_with_history_workspace(
        &self,
        workspace: &mut HistoryExactWorkspace,
        haystack: &[u8],
        window: Window,
        span: Span,
        output: &mut [CaptureGroupSlot],
    ) -> Result<ExactCaptureSlotsOutcome, SearchError> {
        if output.len() != self.schema.group_count() {
            return Err(SearchError::InvalidProgram);
        }
        let outcome = execute_exact_with_workspace(
            &self.program,
            HistoryExactWorkspaceBinding::CaptureProgramV1(self.semantic_digest),
            workspace,
            haystack,
            window,
            span,
        )?;
        if outcome.matched {
            commit_capture_group_slots(&self.program, &workspace.slots, usize::MAX, span, output)?;
        } else {
            output.fill(CaptureGroupSlot::UNMATCHED);
        }
        Ok(outcome)
    }

    /// Attempt a complete detached one-pass sidecar over this artifact's
    /// authoritative Program. The sidecar retains only its derived tables,
    /// slot/schema dimensions, stable digest, and shape—not another Thompson
    /// graph.
    pub fn try_onepass_capture_plan_accounted(
        &self,
        limits: OnePassCaptureBuildLimits,
    ) -> Result<OnePassCapturePlan, OnePassCaptureBuildFailure> {
        OnePassCapturePlan::try_from_capture_program_v1_accounted(
            &self.program,
            self.semantic_digest,
            limits,
        )
    }

    /// Replay through a detached one-pass sidecar bound to this stable digest
    /// and transactionally publish fixed group slots.
    #[allow(
        clippy::too_many_arguments,
        reason = "the detached plan, workspace, source domain, output, and limits are independent contracts"
    )]
    pub fn captures_exact_slots_with_onepass_workspace(
        &self,
        plan: &OnePassCapturePlan,
        workspace: &mut OnePassCaptureWorkspace,
        haystack: &[u8],
        window: Window,
        span: Span,
        output: &mut [CaptureGroupSlot],
        limits: SearchLimits,
    ) -> Result<ExactCaptureSlotsOutcome, SearchError> {
        plan.captures_exact_slots_capture_program_v1(
            &self.program,
            self.semantic_digest,
            workspace,
            haystack,
            window,
            span,
            output,
            limits,
        )
    }

    /// Consume the artifact and return exact canonical serialized bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Consume the artifact and return the executable program.
    #[must_use]
    pub fn into_program(self) -> Program {
        self.program
    }
}

#[derive(Clone, Copy)]
struct Header {
    profile: CaptureProfile,
    start: usize,
    digest: [u8; DIGEST_BYTES],
    schema_offset: usize,
    states_offset: usize,
    ranges_offset: usize,
    names_offset: usize,
    usage: CaptureProgramV1Usage,
}

fn parse_header(
    bytes: &[u8],
    limits: CaptureProgramV1Limits,
) -> Result<Header, CaptureProgramV1Error> {
    let fixed = bytes
        .get(..CAPTURE_PROGRAM_V1_HEADER_BYTES)
        .ok_or(CaptureProgramV1FormatError::Truncated("program header"))?;
    let header = parse_fixed_header(fixed, limits)?;
    if header.usage.serialized_bytes != bytes.len() {
        return Err(CaptureProgramV1FormatError::ExtentMismatch {
            declared: header.usage.serialized_bytes,
            actual: bytes.len(),
        }
        .into());
    }
    Ok(header)
}

#[allow(
    clippy::too_many_lines,
    reason = "all fixed V1 header fields and resource arithmetic remain locally auditable"
)]
fn parse_fixed_header(
    bytes: &[u8],
    limits: CaptureProgramV1Limits,
) -> Result<Header, CaptureProgramV1Error> {
    if bytes.len() != CAPTURE_PROGRAM_V1_HEADER_BYTES {
        return Err(CaptureProgramV1FormatError::Truncated("fixed program header").into());
    }
    if bytes.get(..8) != Some(MAGIC.as_slice()) {
        return Err(CaptureProgramV1FormatError::BadMagic.into());
    }
    let version = read_u16(bytes, 8, "format version")?;
    if version != FORMAT_VERSION {
        return Err(CaptureProgramV1FormatError::UnsupportedVersion(version).into());
    }
    let header_bytes = read_u16(bytes, 10, "header bytes")?;
    if usize::from(header_bytes) != CAPTURE_PROGRAM_V1_HEADER_BYTES {
        return Err(CaptureProgramV1FormatError::InvalidHeaderBytes(header_bytes).into());
    }
    let profile_tag = read_u8(bytes, 12, "profile tag")?;
    let profile = profile_from_tag(profile_tag)?;
    let flags = read_u8(bytes, 13, "flags")?;
    if flags != FLAGS {
        return Err(CaptureProgramV1FormatError::UnknownFlags(flags).into());
    }
    if read_u16(bytes, 14, "header reserved u16")? != 0 {
        return Err(CaptureProgramV1FormatError::NonZeroReserved("header reserved u16").into());
    }
    if read_u64(bytes, 48, "header reserved u64 0")? != 0 {
        return Err(CaptureProgramV1FormatError::NonZeroReserved("header reserved u64 0").into());
    }
    if read_u64(bytes, 56, "header reserved u64 1")? != 0 {
        return Err(CaptureProgramV1FormatError::NonZeroReserved("header reserved u64 1").into());
    }

    let declared = usize_from_u64(read_u64(bytes, 16, "total extent")?, "total extent")?;
    let states = usize_from_u32(read_u32(bytes, 24, "state count")?)?;
    let start = usize_from_u32(read_u32(bytes, 28, "start state")?)?;
    let groups = usize_from_u32(read_u32(bytes, 32, "group count")?)?;
    let slots = usize_from_u32(read_u32(bytes, 36, "slot count")?)?;
    let byte_ranges = usize_from_u32(read_u32(bytes, 40, "range count")?)?;
    let name_bytes = usize_from_u32(read_u32(bytes, 44, "name byte count")?)?;

    check_resource(
        CaptureProgramV1Resource::SerializedBytes,
        declared,
        limits.max_serialized_bytes.min(HARD_MAX_SERIALIZED_BYTES),
    )?;
    check_resource(CaptureProgramV1Resource::States, states, limits.max_states)?;
    check_resource(
        CaptureProgramV1Resource::ByteRanges,
        byte_ranges,
        limits.max_byte_ranges,
    )?;
    check_resource(CaptureProgramV1Resource::Groups, groups, limits.max_groups)?;
    check_resource(CaptureProgramV1Resource::Slots, slots, limits.max_slots)?;
    check_resource(
        CaptureProgramV1Resource::NameBytes,
        name_bytes,
        limits.max_name_bytes,
    )?;

    let validation_work = validation_work(states, byte_ranges, groups, name_bytes)?;
    check_resource(
        CaptureProgramV1Resource::ValidationWork,
        validation_work,
        limits.max_validation_work,
    )?;
    let program_bytes = program_bytes(states, byte_ranges, groups, name_bytes)?;
    check_resource(
        CaptureProgramV1Resource::ProgramBytes,
        program_bytes,
        limits.max_program_bytes,
    )?;

    let schema_offset = CAPTURE_PROGRAM_V1_HEADER_BYTES;
    let schema_bytes =
        groups
            .checked_mul(SCHEMA_ENTRY_BYTES)
            .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
                "schema byte count",
            ))?;
    let states_offset = schema_offset.checked_add(schema_bytes).ok_or(
        CaptureProgramV1Error::ArithmeticOverflow("state section offset"),
    )?;
    let state_bytes =
        states
            .checked_mul(STATE_ENTRY_BYTES)
            .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
                "state byte count",
            ))?;
    let ranges_offset =
        states_offset
            .checked_add(state_bytes)
            .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
                "range section offset",
            ))?;
    let range_bytes =
        byte_ranges
            .checked_mul(RANGE_BYTES)
            .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
                "range byte count",
            ))?;
    let names_offset =
        ranges_offset
            .checked_add(range_bytes)
            .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
                "name section offset",
            ))?;
    let derived = names_offset
        .checked_add(name_bytes)
        .ok_or(CaptureProgramV1Error::ArithmeticOverflow("total extent"))?;
    if declared != derived {
        return Err(CaptureProgramV1FormatError::ExtentMismatch {
            declared,
            actual: derived,
        }
        .into());
    }

    let digest_slice = bytes
        .get(DIGEST_OFFSET..DIGEST_OFFSET + DIGEST_BYTES)
        .ok_or(CaptureProgramV1FormatError::Truncated("semantic digest"))?;
    let digest = <[u8; DIGEST_BYTES]>::try_from(digest_slice)
        .map_err(|_| CaptureProgramV1FormatError::Truncated("semantic digest"))?;
    Ok(Header {
        profile,
        start,
        digest,
        schema_offset,
        states_offset,
        ranges_offset,
        names_offset,
        usage: CaptureProgramV1Usage {
            serialized_bytes: declared,
            states,
            byte_ranges,
            groups,
            slots,
            name_bytes,
            validation_work,
            program_bytes,
        },
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "one source-independent pass closes every in-memory V1 resource dimension"
)]
fn usage_from_program(
    program: &Program,
    limits: CaptureProgramV1Limits,
) -> Result<CaptureProgramV1Usage, CaptureProgramV1Error> {
    let states = program.states.len();
    let groups = program.groups.len();
    let slots = program.slot_count;
    let byte_ranges = program.states.iter().try_fold(0_usize, |total, state| {
        let count = match state {
            State::Byte { ranges, .. } => ranges.len(),
            _ => 0,
        };
        total
            .checked_add(count)
            .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
                "in-memory byte-range count",
            ))
    })?;
    let name_bytes = program.groups.iter().try_fold(0_usize, |total, group| {
        total
            .checked_add(group.name.as_ref().map_or(0, String::len))
            .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
                "in-memory name byte count",
            ))
    })?;
    let schema_bytes =
        groups
            .checked_mul(SCHEMA_ENTRY_BYTES)
            .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
                "schema byte count",
            ))?;
    let state_bytes =
        states
            .checked_mul(STATE_ENTRY_BYTES)
            .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
                "state byte count",
            ))?;
    let range_bytes =
        byte_ranges
            .checked_mul(RANGE_BYTES)
            .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
                "range byte count",
            ))?;
    let serialized_bytes = CAPTURE_PROGRAM_V1_HEADER_BYTES
        .checked_add(schema_bytes)
        .and_then(|bytes| bytes.checked_add(state_bytes))
        .and_then(|bytes| bytes.checked_add(range_bytes))
        .and_then(|bytes| bytes.checked_add(name_bytes))
        .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
            "serialized byte count",
        ))?;
    let validation_work = validation_work(states, byte_ranges, groups, name_bytes)?;
    let program_bytes = program_bytes(states, byte_ranges, groups, name_bytes)?;
    for (resource, required, limit) in [
        (
            CaptureProgramV1Resource::SerializedBytes,
            serialized_bytes,
            limits.max_serialized_bytes.min(HARD_MAX_SERIALIZED_BYTES),
        ),
        (CaptureProgramV1Resource::States, states, limits.max_states),
        (
            CaptureProgramV1Resource::ByteRanges,
            byte_ranges,
            limits.max_byte_ranges,
        ),
        (CaptureProgramV1Resource::Groups, groups, limits.max_groups),
        (CaptureProgramV1Resource::Slots, slots, limits.max_slots),
        (
            CaptureProgramV1Resource::NameBytes,
            name_bytes,
            limits.max_name_bytes,
        ),
        (
            CaptureProgramV1Resource::ValidationWork,
            validation_work,
            limits.max_validation_work,
        ),
        (
            CaptureProgramV1Resource::ProgramBytes,
            program_bytes,
            limits.max_program_bytes,
        ),
    ] {
        check_resource(resource, required, limit)?;
    }
    for (value, site) in [
        (states, "state count"),
        (program.start, "start state"),
        (groups, "group count"),
        (slots, "slot count"),
        (byte_ranges, "range count"),
        (name_bytes, "name byte count"),
    ] {
        u32::try_from(value).map_err(|_| CaptureProgramV1Error::ArithmeticOverflow(site))?;
    }
    u64::try_from(serialized_bytes)
        .map_err(|_| CaptureProgramV1Error::ArithmeticOverflow("serialized extent"))?;
    Ok(CaptureProgramV1Usage {
        serialized_bytes,
        states,
        byte_ranges,
        groups,
        slots,
        name_bytes,
        validation_work,
        program_bytes,
    })
}

fn validation_work(
    states: usize,
    byte_ranges: usize,
    groups: usize,
    name_bytes: usize,
) -> Result<usize, CaptureProgramV1Error> {
    // Three prefix closures can each expand all 256 bytes in every range.
    // Graph reachability, both wire/in-memory record passes, and both
    // no-allocation name-uniqueness passes fit the remaining coefficients.
    states
        .checked_mul(8)
        .and_then(|work| {
            byte_ranges
                .checked_mul(772)
                .and_then(|ranges| work.checked_add(ranges))
        })
        .and_then(|work| {
            groups
                .checked_mul(name_bytes)?
                .checked_mul(2)?
                .checked_add(work)
        })
        .and_then(|work| groups.checked_mul(groups)?.checked_add(work))
        .and_then(|work| work.checked_add(groups))
        .and_then(|work| work.checked_add(1))
        .ok_or(CaptureProgramV1Error::ArithmeticOverflow("validation work"))
}

fn program_bytes(
    states: usize,
    byte_ranges: usize,
    groups: usize,
    name_bytes: usize,
) -> Result<usize, CaptureProgramV1Error> {
    states
        .checked_mul(size_of::<State>())
        .and_then(|bytes| {
            groups
                .checked_mul(size_of::<GroupMeta>())
                .and_then(|group_bytes| bytes.checked_add(group_bytes))
        })
        .and_then(|bytes| {
            byte_ranges
                .checked_mul(size_of::<(u8, u8)>())
                .and_then(|range_bytes| bytes.checked_add(range_bytes))
        })
        .and_then(|bytes| bytes.checked_add(name_bytes))
        .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
            "reconstructed program bytes",
        ))
}

fn check_resource(
    resource: CaptureProgramV1Resource,
    required: usize,
    limit: usize,
) -> Result<(), CaptureProgramV1Error> {
    if required > limit {
        return Err(CaptureProgramV1Error::Resource {
            resource,
            required,
            limit,
        });
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the complete fixed-width V1 encoder stays in one auditable wire-order function"
)]
fn encode_program(
    program: &Program,
    usage: CaptureProgramV1Usage,
) -> Result<Vec<u8>, CaptureProgramV1Error> {
    let mut bytes = Vec::new();
    reserve_exact(
        &mut bytes,
        usage.serialized_bytes,
        CaptureProgramV1Allocation::SerializedBytes,
    )?;
    bytes.extend_from_slice(&MAGIC);
    put_u16(&mut bytes, FORMAT_VERSION);
    put_u16(
        &mut bytes,
        u16::try_from(CAPTURE_PROGRAM_V1_HEADER_BYTES)
            .map_err(|_| CaptureProgramV1Error::ArithmeticOverflow("fixed header byte count"))?,
    );
    bytes.push(profile_tag(program.profile()));
    bytes.push(FLAGS);
    put_u16(&mut bytes, 0);
    put_u64(
        &mut bytes,
        u64::try_from(usage.serialized_bytes)
            .map_err(|_| CaptureProgramV1Error::ArithmeticOverflow("serialized extent"))?,
    );
    put_u32(&mut bytes, u32_value(usage.states, "state count")?);
    put_u32(&mut bytes, u32_value(program.start, "start state")?);
    put_u32(&mut bytes, u32_value(usage.groups, "group count")?);
    put_u32(&mut bytes, u32_value(usage.slots, "slot count")?);
    put_u32(&mut bytes, u32_value(usage.byte_ranges, "range count")?);
    put_u32(&mut bytes, u32_value(usage.name_bytes, "name byte count")?);
    put_u64(&mut bytes, 0);
    put_u64(&mut bytes, 0);
    bytes.extend_from_slice(&[0; DIGEST_BYTES]);
    if bytes.len() != CAPTURE_PROGRAM_V1_HEADER_BYTES {
        return Err(CaptureProgramV1Error::InternalInvariant(
            "encoder emitted the wrong fixed header extent",
        ));
    }

    let mut name_offset = 0_usize;
    for group in &program.groups {
        put_u32(&mut bytes, group.index);
        let name_len = group.name.as_ref().map_or(0, String::len);
        put_u16(&mut bytes, u16::from(group.name.is_some()));
        put_u16(&mut bytes, 0);
        put_u32(&mut bytes, u32_value(name_offset, "name offset")?);
        put_u32(&mut bytes, u32_value(name_len, "name length")?);
        name_offset = name_offset
            .checked_add(name_len)
            .ok_or(CaptureProgramV1Error::ArithmeticOverflow("name offset"))?;
    }
    if name_offset != usage.name_bytes {
        return Err(CaptureProgramV1Error::InternalInvariant(
            "schema name bytes diverge from admitted usage",
        ));
    }

    let mut range_offset = 0_usize;
    for state in &program.states {
        let (opcode, assertion, target0, target1, value0, value1) = match state {
            State::Byte { ranges, next } => {
                let offset = range_offset;
                range_offset = range_offset.checked_add(ranges.len()).ok_or(
                    CaptureProgramV1Error::ArithmeticOverflow("range table offset"),
                )?;
                (OPCODE_BYTE, 0, *next, 0, offset, ranges.len())
            }
            State::Split { first, second } => (OPCODE_SPLIT, 0, *first, *second, 0, 0),
            State::Save {
                slot,
                next,
                start_prefilter,
            } => (
                OPCODE_SAVE,
                0,
                *next,
                0,
                *slot,
                usize::try_from(*start_prefilter)
                    .map_err(|_| CaptureProgramV1Error::ArithmeticOverflow("start prefilter"))?,
            ),
            State::Assert { assertion, next } => {
                let (tag, data) = assertion_parts(*assertion);
                (OPCODE_ASSERT, tag, *next, 0, usize::from(data), 0)
            }
            State::Epsilon { next } => (OPCODE_EPSILON, 0, *next, 0, 0, 0),
            State::Match => (OPCODE_MATCH, 0, 0, 0, 0, 0),
            State::Fail => (OPCODE_FAIL, 0, 0, 0, 0, 0),
        };
        bytes.push(opcode);
        bytes.push(assertion);
        put_u16(&mut bytes, 0);
        put_u32(&mut bytes, u32_value(target0, "instruction target 0")?);
        put_u32(&mut bytes, u32_value(target1, "instruction target 1")?);
        put_u32(&mut bytes, u32_value(value0, "instruction value 0")?);
        put_u32(&mut bytes, u32_value(value1, "instruction value 1")?);
        put_u32(&mut bytes, 0);
    }
    if range_offset != usage.byte_ranges {
        return Err(CaptureProgramV1Error::InternalInvariant(
            "state ranges diverge from admitted usage",
        ));
    }
    for state in &program.states {
        if let State::Byte { ranges, .. } = state {
            for &(start, end) in ranges {
                bytes.extend_from_slice(&[start, end]);
            }
        }
    }
    for group in &program.groups {
        if let Some(name) = &group.name {
            bytes.extend_from_slice(name.as_bytes());
        }
    }
    if bytes.len() != usage.serialized_bytes {
        return Err(CaptureProgramV1Error::InternalInvariant(
            "encoder emitted an unexpected byte count",
        ));
    }
    let digest = semantic_digest(&bytes)?;
    bytes[DIGEST_OFFSET..DIGEST_OFFSET + DIGEST_BYTES].copy_from_slice(&digest);
    Ok(bytes)
}

fn semantic_digest(bytes: &[u8]) -> Result<[u8; DIGEST_BYTES], CaptureProgramV1Error> {
    let prefix = bytes
        .get(..DIGEST_OFFSET)
        .ok_or(CaptureProgramV1Error::InternalInvariant(
            "semantic digest prefix is truncated",
        ))?;
    let suffix = bytes.get(DIGEST_OFFSET + DIGEST_BYTES..).ok_or(
        CaptureProgramV1Error::InternalInvariant("semantic digest suffix is truncated"),
    )?;
    let mut digest = Sha256::new();
    digest.update(DIGEST_DOMAIN);
    digest.update(prefix);
    digest.update([0; DIGEST_BYTES]);
    digest.update(suffix);
    Ok(digest.finalize().into())
}

fn verify_digest(bytes: &[u8], expected: [u8; DIGEST_BYTES]) -> Result<(), CaptureProgramV1Error> {
    if semantic_digest(bytes)? != expected {
        return Err(CaptureProgramV1FormatError::DigestMismatch.into());
    }
    Ok(())
}

fn digest_from_header(bytes: &[u8]) -> Result<[u8; DIGEST_BYTES], CaptureProgramV1Error> {
    let digest = bytes
        .get(DIGEST_OFFSET..DIGEST_OFFSET + DIGEST_BYTES)
        .ok_or(CaptureProgramV1Error::InternalInvariant(
            "encoded semantic digest is truncated",
        ))?;
    <[u8; DIGEST_BYTES]>::try_from(digest).map_err(|_| {
        CaptureProgramV1Error::InternalInvariant("encoded semantic digest has the wrong extent")
    })
}

fn snapshot_schema(groups: &[GroupMeta]) -> Result<CaptureSchema, CaptureProgramV1Error> {
    let mut snapshot = Vec::new();
    reserve_exact(
        &mut snapshot,
        groups.len(),
        CaptureProgramV1Allocation::SchemaGroups,
    )?;
    for group in groups {
        snapshot.push(CaptureGroupSchema {
            index: group.index,
            name: group.name.as_deref().map(copy_name).transpose()?,
        });
    }
    let slot_count =
        groups
            .len()
            .checked_mul(2)
            .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
                "schema slot count",
            ))?;
    Ok(CaptureSchema {
        groups: snapshot,
        slot_count,
    })
}

fn copy_name(name: &str) -> Result<String, CaptureProgramV1Error> {
    let mut copied = String::new();
    copied
        .try_reserve_exact(name.len())
        .map_err(|_| CaptureProgramV1Error::Allocation {
            allocation: CaptureProgramV1Allocation::GroupName,
            items: name.len(),
        })?;
    if copied.capacity() != name.len() {
        return Err(CaptureProgramV1Error::Allocation {
            allocation: CaptureProgramV1Allocation::GroupName,
            items: name.len(),
        });
    }
    copied.push_str(name);
    Ok(copied)
}

#[allow(
    clippy::too_many_lines,
    reason = "schema offsets, UTF-8, names, uniqueness, group zero, and exact extent stay in one auditable pass"
)]
fn validate_schema_wire(bytes: &[u8], header: Header) -> Result<(), CaptureProgramV1Error> {
    if header.usage.groups == 0 {
        return Err(
            CaptureProgramV1FormatError::InvalidSchema("implicit group zero is missing").into(),
        );
    }
    let expected_slots =
        header
            .usage
            .groups
            .checked_mul(2)
            .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
                "schema slot count",
            ))?;
    if header.usage.slots != expected_slots {
        return Err(CaptureProgramV1FormatError::InvalidSchema(
            "slot count is not twice the group count",
        )
        .into());
    }
    let names = bytes
        .get(header.names_offset..header.usage.serialized_bytes)
        .ok_or(CaptureProgramV1FormatError::Truncated("name payload"))?;
    let mut expected_name_offset = 0_usize;
    for group_index in 0..header.usage.groups {
        let record = schema_record(bytes, header, group_index)?;
        let encoded_index = read_u32(record, 0, "group index")?;
        if usize_from_u32(encoded_index)? != group_index {
            return Err(CaptureProgramV1FormatError::InvalidSchema(
                "group indices are not contiguous from zero",
            )
            .into());
        }
        let flags = read_u16(record, 4, "group flags")?;
        if flags & !1 != 0 {
            return Err(CaptureProgramV1FormatError::InvalidSchema(
                "group flags contain an unknown bit",
            )
            .into());
        }
        if read_u16(record, 6, "group reserved")? != 0 {
            return Err(CaptureProgramV1FormatError::NonZeroReserved(
                "schema entry reserved field",
            )
            .into());
        }
        let name_offset = usize_from_u32(read_u32(record, 8, "group name offset")?)?;
        let name_len = usize_from_u32(read_u32(record, 12, "group name length")?)?;
        if name_offset != expected_name_offset {
            return Err(CaptureProgramV1FormatError::InvalidSchema(
                "group names are not contiguous and ordered",
            )
            .into());
        }
        if flags == 0 {
            if name_len != 0 {
                return Err(CaptureProgramV1FormatError::InvalidSchema(
                    "unnamed group has name bytes",
                )
                .into());
            }
        } else {
            if group_index == 0 {
                return Err(CaptureProgramV1FormatError::InvalidSchema(
                    "implicit group zero must be unnamed",
                )
                .into());
            }
            if name_len == 0 {
                return Err(CaptureProgramV1FormatError::InvalidSchema(
                    "named group has an empty payload",
                )
                .into());
            }
            let end = name_offset.checked_add(name_len).ok_or(
                CaptureProgramV1Error::ArithmeticOverflow("group name extent"),
            )?;
            let name_bytes =
                names
                    .get(name_offset..end)
                    .ok_or(CaptureProgramV1FormatError::InvalidSchema(
                        "group name exceeds the name section",
                    ))?;
            let name = std::str::from_utf8(name_bytes)
                .map_err(|_| CaptureProgramV1FormatError::InvalidNameUtf8)?;
            if !valid_name(name) {
                return Err(CaptureProgramV1FormatError::InvalidName.into());
            }
            for previous in 0..group_index {
                if wire_group_name(bytes, header, previous)? == Some(name) {
                    return Err(CaptureProgramV1FormatError::DuplicateName.into());
                }
            }
        }
        expected_name_offset = expected_name_offset.checked_add(name_len).ok_or(
            CaptureProgramV1Error::ArithmeticOverflow("group name offset"),
        )?;
    }
    if expected_name_offset != header.usage.name_bytes {
        return Err(CaptureProgramV1FormatError::InvalidSchema(
            "schema does not consume the exact name section",
        )
        .into());
    }
    Ok(())
}

fn wire_group_name(
    bytes: &[u8],
    header: Header,
    index: usize,
) -> Result<Option<&str>, CaptureProgramV1Error> {
    let record = schema_record(bytes, header, index)?;
    if read_u16(record, 4, "group flags")? & 1 == 0 {
        return Ok(None);
    }
    let offset = usize_from_u32(read_u32(record, 8, "group name offset")?)?;
    let length = usize_from_u32(read_u32(record, 12, "group name length")?)?;
    let end = offset
        .checked_add(length)
        .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
            "group name extent",
        ))?;
    let names = bytes
        .get(header.names_offset..header.usage.serialized_bytes)
        .ok_or(CaptureProgramV1FormatError::Truncated("name payload"))?;
    let value = names
        .get(offset..end)
        .ok_or(CaptureProgramV1FormatError::InvalidSchema(
            "group name exceeds the name section",
        ))?;
    Ok(Some(std::str::from_utf8(value).map_err(|_| {
        CaptureProgramV1FormatError::InvalidNameUtf8
    })?))
}

#[allow(
    clippy::too_many_lines,
    reason = "all opcode-specific field, target, slot, and range checks remain locally auditable"
)]
fn validate_state_wire(bytes: &[u8], header: Header) -> Result<(), CaptureProgramV1Error> {
    if header.usage.states < 4 {
        return Err(CaptureProgramV1FormatError::InvalidProgramShape(
            "capture program has fewer than four canonical states",
        )
        .into());
    }
    if header.start >= header.usage.states {
        return Err(CaptureProgramV1FormatError::InvalidTarget.into());
    }
    let mut expected_range_offset = 0_usize;
    let mut match_count = 0_usize;
    for state_index in 0..header.usage.states {
        let record = state_record(bytes, header, state_index)?;
        let opcode = read_u8(record, 0, "instruction opcode")?;
        let assertion = read_u8(record, 1, "instruction assertion tag")?;
        if read_u16(record, 2, "instruction flags")? != 0 {
            return Err(CaptureProgramV1FormatError::NonZeroReserved("instruction flags").into());
        }
        let target0 = usize_from_u32(read_u32(record, 4, "instruction target 0")?)?;
        let target1 = usize_from_u32(read_u32(record, 8, "instruction target 1")?)?;
        let value0 = usize_from_u32(read_u32(record, 12, "instruction value 0")?)?;
        let value1 = read_u32(record, 16, "instruction value 1")?;
        if read_u32(record, 20, "instruction reserved")? != 0 {
            return Err(
                CaptureProgramV1FormatError::NonZeroReserved("instruction reserved field").into(),
            );
        }
        match opcode {
            OPCODE_BYTE => {
                require_zero(&assertion, "Byte assertion tag")?;
                require_zero(&target1, "Byte target 1")?;
                require_target(target0, header.usage.states)?;
                if value0 != expected_range_offset {
                    return Err(CaptureProgramV1FormatError::InvalidRange.into());
                }
                let range_count = usize_from_u32(value1)?;
                let range_end = value0.checked_add(range_count).ok_or(
                    CaptureProgramV1Error::ArithmeticOverflow("state range extent"),
                )?;
                if range_end > header.usage.byte_ranges {
                    return Err(CaptureProgramV1FormatError::InvalidRange.into());
                }
                let mut previous_end = None;
                for range_index in value0..range_end {
                    let (start, end) = wire_range(bytes, header, range_index)?;
                    if start > end || previous_end.is_some_and(|old| old >= start) {
                        return Err(CaptureProgramV1FormatError::InvalidRange.into());
                    }
                    previous_end = Some(end);
                }
                expected_range_offset = range_end;
            }
            OPCODE_SPLIT => {
                require_zero(&assertion, "Split assertion tag")?;
                require_zero(&value0, "Split value 0")?;
                require_zero(&value1, "Split value 1")?;
                require_target(target0, header.usage.states)?;
                require_target(target1, header.usage.states)?;
            }
            OPCODE_SAVE => {
                require_zero(&assertion, "Save assertion tag")?;
                require_zero(&target1, "Save target 1")?;
                require_target(target0, header.usage.states)?;
                if value0 >= header.usage.slots {
                    return Err(CaptureProgramV1FormatError::InvalidSlot.into());
                }
                if state_index != header.start && value1 != 0 {
                    return Err(CaptureProgramV1FormatError::InvalidStartPrefilter.into());
                }
                if value0 < 2
                    && !((state_index == header.start && value0 == 0)
                        || (state_index == header.usage.states - 3 && value0 == 1))
                {
                    return Err(CaptureProgramV1FormatError::InvalidSlot.into());
                }
            }
            OPCODE_ASSERT => {
                require_zero(&target1, "Assert target 1")?;
                require_zero(&value1, "Assert value 1")?;
                require_target(target0, header.usage.states)?;
                assertion_from_parts(assertion, u32_value(value0, "assertion data")?)?;
            }
            OPCODE_EPSILON => {
                require_zero(&assertion, "Epsilon assertion tag")?;
                require_zero(&target1, "Epsilon target 1")?;
                require_zero(&value0, "Epsilon value 0")?;
                require_zero(&value1, "Epsilon value 1")?;
                require_target(target0, header.usage.states)?;
            }
            OPCODE_MATCH | OPCODE_FAIL => {
                require_zero(&assertion, "terminal assertion tag")?;
                require_zero(&target0, "terminal target 0")?;
                require_zero(&target1, "terminal target 1")?;
                require_zero(&value0, "terminal value 0")?;
                require_zero(&value1, "terminal value 1")?;
                if opcode == OPCODE_MATCH {
                    match_count = match_count.checked_add(1).ok_or(
                        CaptureProgramV1Error::ArithmeticOverflow("Match instruction count"),
                    )?;
                }
            }
            unknown => return Err(CaptureProgramV1FormatError::UnknownOpcode(unknown).into()),
        }
    }
    if expected_range_offset != header.usage.byte_ranges {
        return Err(CaptureProgramV1FormatError::InvalidRange.into());
    }
    if header.start != header.usage.states - 1 {
        return Err(CaptureProgramV1FormatError::InvalidProgramShape(
            "start Save is not the final instruction",
        )
        .into());
    }
    let start = state_record(bytes, header, header.start)?;
    if read_u8(start, 0, "start opcode")? != OPCODE_SAVE || read_u32(start, 12, "start slot")? != 0
    {
        return Err(CaptureProgramV1FormatError::InvalidProgramShape(
            "start instruction is not group-zero start Save",
        )
        .into());
    }
    let match_index = header.usage.states - 2;
    if match_count != 1
        || read_u8(state_record(bytes, header, match_index)?, 0, "Match opcode")? != OPCODE_MATCH
    {
        return Err(CaptureProgramV1FormatError::InvalidProgramShape(
            "terminal Match is not unique and penultimate",
        )
        .into());
    }
    let end_save = state_record(bytes, header, header.usage.states - 3)?;
    if read_u8(end_save, 0, "end Save opcode")? != OPCODE_SAVE
        || read_u32(end_save, 4, "end Save target")? != u32_value(match_index, "Match index")?
        || read_u32(end_save, 12, "end Save slot")? != 1
        || read_u32(end_save, 16, "end Save prefilter")? != 0
    {
        return Err(CaptureProgramV1FormatError::InvalidProgramShape(
            "group-zero end Save is not canonical",
        )
        .into());
    }
    Ok(())
}

fn decode_groups(bytes: &[u8], header: Header) -> Result<Vec<GroupMeta>, CaptureProgramV1Error> {
    let mut groups = Vec::new();
    reserve_exact(
        &mut groups,
        header.usage.groups,
        CaptureProgramV1Allocation::ProgramGroups,
    )?;
    for index in 0..header.usage.groups {
        let record = schema_record(bytes, header, index)?;
        let numeric = read_u32(record, 0, "group index")?;
        let name = wire_group_name(bytes, header, index)?
            .map(copy_name)
            .transpose()?;
        groups.push(GroupMeta {
            index: numeric,
            name,
        });
    }
    Ok(groups)
}

fn decode_states(bytes: &[u8], header: Header) -> Result<Vec<State>, CaptureProgramV1Error> {
    let mut states = Vec::new();
    reserve_exact(
        &mut states,
        header.usage.states,
        CaptureProgramV1Allocation::ProgramStates,
    )?;
    for index in 0..header.usage.states {
        let record = state_record(bytes, header, index)?;
        let opcode = read_u8(record, 0, "instruction opcode")?;
        let assertion_tag = read_u8(record, 1, "instruction assertion tag")?;
        let target0 = usize_from_u32(read_u32(record, 4, "instruction target 0")?)?;
        let target1 = usize_from_u32(read_u32(record, 8, "instruction target 1")?)?;
        let value0 = usize_from_u32(read_u32(record, 12, "instruction value 0")?)?;
        let value1 = read_u32(record, 16, "instruction value 1")?;
        let state = match opcode {
            OPCODE_BYTE => {
                let range_count = usize_from_u32(value1)?;
                let range_end = value0.checked_add(range_count).ok_or(
                    CaptureProgramV1Error::ArithmeticOverflow("state range extent"),
                )?;
                let mut ranges = Vec::new();
                reserve_exact(
                    &mut ranges,
                    range_count,
                    CaptureProgramV1Allocation::ByteRanges,
                )?;
                for range_index in value0..range_end {
                    ranges.push(wire_range(bytes, header, range_index)?);
                }
                State::Byte {
                    ranges,
                    next: target0,
                }
            }
            OPCODE_SPLIT => State::Split {
                first: target0,
                second: target1,
            },
            OPCODE_SAVE => State::Save {
                slot: value0,
                next: target0,
                start_prefilter: value1,
            },
            OPCODE_ASSERT => State::Assert {
                assertion: assertion_from_parts(
                    assertion_tag,
                    u32_value(value0, "assertion data")?,
                )?,
                next: target0,
            },
            OPCODE_EPSILON => State::Epsilon { next: target0 },
            OPCODE_MATCH => State::Match,
            OPCODE_FAIL => State::Fail,
            unknown => return Err(CaptureProgramV1FormatError::UnknownOpcode(unknown).into()),
        };
        states.push(state);
    }
    Ok(states)
}

fn validate_program(
    program: &Program,
    _validation_work: usize,
) -> Result<(), CaptureProgramV1Error> {
    if program.profile() != CaptureProfile::RustRegexBytes1_12_4 {
        return Err(CaptureProgramV1Error::InternalInvariant(
            "only the admitted Rust byte profile has a V1 tag",
        ));
    }
    validate_program_schema(program)?;
    validate_program_states(program)?;
    validate_reachability(program)?;
    let derived = derive_start_prefilter(program)?;
    let retained = match program.states.get(program.start) {
        Some(State::Save {
            start_prefilter, ..
        }) => *start_prefilter,
        _ => {
            return Err(CaptureProgramV1Error::InternalInvariant(
                "program start is not a Save",
            ));
        }
    };
    if derived != retained {
        return Err(CaptureProgramV1FormatError::InvalidStartPrefilter.into());
    }
    Ok(())
}

fn validate_program_schema(program: &Program) -> Result<(), CaptureProgramV1Error> {
    if program.groups.is_empty() {
        return Err(
            CaptureProgramV1FormatError::InvalidSchema("implicit group zero is missing").into(),
        );
    }
    if program.slot_count
        != program
            .groups
            .len()
            .checked_mul(2)
            .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
                "schema slot count",
            ))?
    {
        return Err(CaptureProgramV1FormatError::InvalidSchema(
            "slot count is not twice the group count",
        )
        .into());
    }
    for (index, group) in program.groups.iter().enumerate() {
        if usize::try_from(group.index) != Ok(index) {
            return Err(CaptureProgramV1FormatError::InvalidSchema(
                "group indices are not contiguous from zero",
            )
            .into());
        }
        if index == 0 && group.name.is_some() {
            return Err(CaptureProgramV1FormatError::InvalidSchema(
                "implicit group zero must be unnamed",
            )
            .into());
        }
        if let Some(name) = group.name.as_deref() {
            if !valid_name(name) {
                return Err(CaptureProgramV1FormatError::InvalidName.into());
            }
            if program.groups[..index]
                .iter()
                .any(|previous| previous.name.as_deref() == Some(name))
            {
                return Err(CaptureProgramV1FormatError::DuplicateName.into());
            }
        }
    }
    Ok(())
}

fn validate_program_states(program: &Program) -> Result<(), CaptureProgramV1Error> {
    let state_count = program.states.len();
    if state_count < 4 || program.start != state_count - 1 {
        return Err(CaptureProgramV1FormatError::InvalidProgramShape(
            "start Save is not the final instruction",
        )
        .into());
    }
    let mut matches = 0_usize;
    for (index, state) in program.states.iter().enumerate() {
        match state {
            State::Byte { ranges, next } => {
                require_target(*next, state_count)?;
                let mut previous_end = None;
                for &(start, end) in ranges {
                    if start > end || previous_end.is_some_and(|old| old >= start) {
                        return Err(CaptureProgramV1FormatError::InvalidRange.into());
                    }
                    previous_end = Some(end);
                }
            }
            State::Split { first, second } => {
                require_target(*first, state_count)?;
                require_target(*second, state_count)?;
            }
            State::Save {
                slot,
                next,
                start_prefilter,
            } => {
                require_target(*next, state_count)?;
                if *slot >= program.slot_count {
                    return Err(CaptureProgramV1FormatError::InvalidSlot.into());
                }
                if index != program.start && *start_prefilter != 0 {
                    return Err(CaptureProgramV1FormatError::InvalidStartPrefilter.into());
                }
                if *slot < 2
                    && !((index == program.start && *slot == 0)
                        || (index == state_count - 3 && *slot == 1))
                {
                    return Err(CaptureProgramV1FormatError::InvalidSlot.into());
                }
            }
            State::Assert { next, .. } | State::Epsilon { next } => {
                require_target(*next, state_count)?;
            }
            State::Match => matches = matches.saturating_add(1),
            State::Fail => {}
        }
    }
    if !matches.eq(&1) || !matches!(program.states[state_count - 2], State::Match) {
        return Err(CaptureProgramV1FormatError::InvalidProgramShape(
            "terminal Match is not unique and penultimate",
        )
        .into());
    }
    if !matches!(
        program.states.get(program.start),
        Some(State::Save { slot: 0, .. })
    ) {
        return Err(CaptureProgramV1FormatError::InvalidProgramShape(
            "start instruction is not group-zero start Save",
        )
        .into());
    }
    if !matches!(
        program.states.get(state_count - 3),
        Some(State::Save {
            slot: 1,
            next,
            start_prefilter: 0,
        }) if *next == state_count - 2
    ) {
        return Err(CaptureProgramV1FormatError::InvalidProgramShape(
            "group-zero end Save is not canonical",
        )
        .into());
    }
    Ok(())
}

fn validate_reachability(program: &Program) -> Result<(), CaptureProgramV1Error> {
    let mut seen = Vec::new();
    reserve_exact(
        &mut seen,
        program.states.len(),
        CaptureProgramV1Allocation::ValidationScratch,
    )?;
    seen.resize(program.states.len(), false);
    let mut stack = Vec::new();
    reserve_exact(
        &mut stack,
        program.states.len(),
        CaptureProgramV1Allocation::ValidationScratch,
    )?;
    seen[program.start] = true;
    stack.push(program.start);
    while let Some(state) = stack.pop() {
        match &program.states[state] {
            State::Byte { next, .. }
            | State::Save { next, .. }
            | State::Assert { next, .. }
            | State::Epsilon { next } => push_unseen(*next, &mut seen, &mut stack),
            State::Split { first, second } => {
                push_unseen(*second, &mut seen, &mut stack);
                push_unseen(*first, &mut seen, &mut stack);
            }
            State::Match | State::Fail => {}
        }
    }
    if seen.iter().any(|visited| !visited) {
        return Err(CaptureProgramV1FormatError::UnreachableState.into());
    }
    Ok(())
}

/// Rederive the compiler's complete three-byte start proof from the graph.
/// Assertions are conservatively traversed as epsilon edges, exactly as the
/// AST proof treats them for source-independent candidate admission.
#[allow(
    clippy::too_many_lines,
    reason = "the complete graph-derived three-byte proof stays in one bounded formulation"
)]
fn derive_start_prefilter(program: &Program) -> Result<u32, CaptureProgramV1Error> {
    let states = program.states.len();
    let mut frontier = bool_scratch(states)?;
    let mut closure = bool_scratch(states)?;
    let mut stack = Vec::new();
    reserve_exact(
        &mut stack,
        states,
        CaptureProgramV1Allocation::ValidationScratch,
    )?;
    frontier[program.start] = true;
    let mut first_bytes = [false; 256];
    let mut first_nullable = false;
    let mut common = [0_u8; 3];
    let mut common_len = 0_usize;

    for (depth, common_byte) in common.iter_mut().enumerate() {
        closure.fill(false);
        stack.clear();
        for (state, &active) in frontier.iter().enumerate() {
            if active && !closure[state] {
                closure[state] = true;
                stack.push(state);
            }
        }
        while let Some(state) = stack.pop() {
            match &program.states[state] {
                State::Save { next, .. } | State::Assert { next, .. } | State::Epsilon { next } => {
                    push_unseen(*next, &mut closure, &mut stack);
                }
                State::Split { first, second } => {
                    push_unseen(*second, &mut closure, &mut stack);
                    push_unseen(*first, &mut closure, &mut stack);
                }
                State::Byte { .. } | State::Match | State::Fail => {}
            }
        }

        let nullable = closure
            .iter()
            .enumerate()
            .any(|(state, &active)| active && matches!(program.states[state], State::Match));
        let mut possible = [false; 256];
        for (state, &active) in closure.iter().enumerate() {
            if !active {
                continue;
            }
            if let State::Byte { ranges, .. } = &program.states[state] {
                for &(start, end) in ranges {
                    for byte in start..=end {
                        possible[usize::from(byte)] = true;
                    }
                }
            }
        }
        if depth == 0 {
            first_bytes = possible;
            first_nullable = nullable;
        }
        let mut candidates = possible
            .iter()
            .enumerate()
            .filter_map(|(byte, &present)| present.then_some(byte));
        let Some(singleton) = candidates.next() else {
            break;
        };
        if nullable || candidates.next().is_some() {
            break;
        }
        let singleton = u8::try_from(singleton).map_err(|_| {
            CaptureProgramV1Error::InternalInvariant("byte proof escaped the u8 domain")
        })?;
        *common_byte = singleton;
        common_len = depth + 1;
        frontier.fill(false);
        for (state, &active) in closure.iter().enumerate() {
            if !active {
                continue;
            }
            if let State::Byte { ranges, next } = &program.states[state]
                && ranges
                    .iter()
                    .any(|&(start, end)| start <= singleton && singleton <= end)
            {
                frontier[*next] = true;
            }
        }
    }

    if !first_nullable && matches!(common_len, 2 | 3) {
        let tag = if common_len == 2 {
            EXACT_PREFIX_2_TAG
        } else {
            EXACT_PREFIX_3_TAG
        };
        return Ok(u32::from_le_bytes([common[0], common[1], common[2], tag]));
    }
    if first_nullable {
        return Ok(0);
    }
    let mut bytes = [0_u8; 3];
    let mut count = 0_usize;
    for (byte, &present) in first_bytes.iter().enumerate() {
        if present {
            if count == bytes.len() {
                return Ok(0);
            }
            bytes[count] = u8::try_from(byte).map_err(|_| {
                CaptureProgramV1Error::InternalInvariant("byte proof escaped the u8 domain")
            })?;
            count += 1;
        }
    }
    if count == 0 {
        return Ok(0);
    }
    Ok(u32::from_le_bytes([
        bytes[0],
        bytes[1],
        bytes[2],
        u8::try_from(count).map_err(|_| {
            CaptureProgramV1Error::InternalInvariant("prefilter count exceeded three")
        })?,
    ]))
}

fn bool_scratch(items: usize) -> Result<Vec<bool>, CaptureProgramV1Error> {
    let mut scratch = Vec::new();
    reserve_exact(
        &mut scratch,
        items,
        CaptureProgramV1Allocation::ValidationScratch,
    )?;
    scratch.resize(items, false);
    Ok(scratch)
}

fn push_unseen(state: usize, seen: &mut [bool], stack: &mut Vec<usize>) {
    if !seen[state] {
        seen[state] = true;
        stack.push(state);
    }
}

fn schema_record(
    bytes: &[u8],
    header: Header,
    index: usize,
) -> Result<&[u8], CaptureProgramV1Error> {
    fixed_record(
        bytes,
        header.schema_offset,
        index,
        SCHEMA_ENTRY_BYTES,
        "schema entry",
    )
}

fn state_record(
    bytes: &[u8],
    header: Header,
    index: usize,
) -> Result<&[u8], CaptureProgramV1Error> {
    fixed_record(
        bytes,
        header.states_offset,
        index,
        STATE_ENTRY_BYTES,
        "instruction record",
    )
}

fn fixed_record<'a>(
    bytes: &'a [u8],
    section: usize,
    index: usize,
    width: usize,
    field: &'static str,
) -> Result<&'a [u8], CaptureProgramV1Error> {
    let offset = index
        .checked_mul(width)
        .and_then(|offset| section.checked_add(offset))
        .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
            "fixed record offset",
        ))?;
    let end = offset
        .checked_add(width)
        .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
            "fixed record extent",
        ))?;
    bytes
        .get(offset..end)
        .ok_or(CaptureProgramV1FormatError::Truncated(field).into())
}

fn wire_range(
    bytes: &[u8],
    header: Header,
    index: usize,
) -> Result<(u8, u8), CaptureProgramV1Error> {
    let offset = index
        .checked_mul(RANGE_BYTES)
        .and_then(|offset| header.ranges_offset.checked_add(offset))
        .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
            "range record offset",
        ))?;
    let range = bytes
        .get(offset..offset.saturating_add(RANGE_BYTES))
        .ok_or(CaptureProgramV1FormatError::Truncated("range record"))?;
    Ok((range[0], range[1]))
}

fn require_target(target: usize, states: usize) -> Result<(), CaptureProgramV1Error> {
    if target >= states {
        return Err(CaptureProgramV1FormatError::InvalidTarget.into());
    }
    Ok(())
}

fn require_zero<T>(value: &T, field: &'static str) -> Result<(), CaptureProgramV1Error>
where
    T: From<u8> + PartialEq,
{
    if value != &T::from(0) {
        return Err(CaptureProgramV1FormatError::NonZeroReserved(field).into());
    }
    Ok(())
}

fn profile_tag(profile: CaptureProfile) -> u8 {
    match profile {
        CaptureProfile::RustRegexBytes1_12_4 => PROFILE_RUST_REGEX_BYTES_1_12_4,
        CaptureProfile::Re2Commit972a15Pending => 0,
    }
}

fn profile_from_tag(tag: u8) -> Result<CaptureProfile, CaptureProgramV1Error> {
    match tag {
        PROFILE_RUST_REGEX_BYTES_1_12_4 => Ok(CaptureProfile::RustRegexBytes1_12_4),
        unknown => Err(CaptureProgramV1FormatError::UnsupportedProfile(unknown).into()),
    }
}

fn assertion_parts(assertion: Assertion) -> (u8, u8) {
    match assertion {
        Assertion::Start => (1, 0),
        Assertion::End => (2, 0),
        Assertion::StartLf => (3, 0),
        Assertion::EndLf => (4, 0),
        Assertion::StartLine(byte) => (5, byte),
        Assertion::EndLine(byte) => (6, byte),
        Assertion::StartCrlf => (7, 0),
        Assertion::EndCrlf => (8, 0),
        Assertion::WordAscii => (9, 0),
        Assertion::WordAsciiNegate => (10, 0),
        Assertion::WordStartAscii => (11, 0),
        Assertion::WordEndAscii => (12, 0),
        Assertion::WordStartHalfAscii => (13, 0),
        Assertion::WordEndHalfAscii => (14, 0),
        Assertion::WordUnicode => (15, 0),
        Assertion::WordUnicodeNegate => (16, 0),
        Assertion::WordStartUnicode => (17, 0),
        Assertion::WordEndUnicode => (18, 0),
        Assertion::WordStartHalfUnicode => (19, 0),
        Assertion::WordEndHalfUnicode => (20, 0),
    }
}

fn assertion_from_parts(tag: u8, data: u32) -> Result<Assertion, CaptureProgramV1Error> {
    let no_data = || -> Result<(), CaptureProgramV1Error> {
        if data == 0 {
            Ok(())
        } else {
            Err(CaptureProgramV1FormatError::NonZeroReserved("assertion data").into())
        }
    };
    match tag {
        1 => {
            no_data()?;
            Ok(Assertion::Start)
        }
        2 => {
            no_data()?;
            Ok(Assertion::End)
        }
        3 => {
            no_data()?;
            Ok(Assertion::StartLf)
        }
        4 => {
            no_data()?;
            Ok(Assertion::EndLf)
        }
        5 => Ok(Assertion::StartLine(u8::try_from(data).map_err(|_| {
            CaptureProgramV1FormatError::NonZeroReserved("StartLine assertion high data")
        })?)),
        6 => Ok(Assertion::EndLine(u8::try_from(data).map_err(|_| {
            CaptureProgramV1FormatError::NonZeroReserved("EndLine assertion high data")
        })?)),
        7 => {
            no_data()?;
            Ok(Assertion::StartCrlf)
        }
        8 => {
            no_data()?;
            Ok(Assertion::EndCrlf)
        }
        9 => {
            no_data()?;
            Ok(Assertion::WordAscii)
        }
        10 => {
            no_data()?;
            Ok(Assertion::WordAsciiNegate)
        }
        11 => {
            no_data()?;
            Ok(Assertion::WordStartAscii)
        }
        12 => {
            no_data()?;
            Ok(Assertion::WordEndAscii)
        }
        13 => {
            no_data()?;
            Ok(Assertion::WordStartHalfAscii)
        }
        14 => {
            no_data()?;
            Ok(Assertion::WordEndHalfAscii)
        }
        15 => {
            no_data()?;
            Ok(Assertion::WordUnicode)
        }
        16 => {
            no_data()?;
            Ok(Assertion::WordUnicodeNegate)
        }
        17 => {
            no_data()?;
            Ok(Assertion::WordStartUnicode)
        }
        18 => {
            no_data()?;
            Ok(Assertion::WordEndUnicode)
        }
        19 => {
            no_data()?;
            Ok(Assertion::WordStartHalfUnicode)
        }
        20 => {
            no_data()?;
            Ok(Assertion::WordEndHalfUnicode)
        }
        unknown => Err(CaptureProgramV1FormatError::UnknownAssertion(unknown).into()),
    }
}

fn reserve_exact<T>(
    vector: &mut Vec<T>,
    items: usize,
    allocation: CaptureProgramV1Allocation,
) -> Result<(), CaptureProgramV1Error> {
    vector
        .try_reserve_exact(items)
        .map_err(|_| CaptureProgramV1Error::Allocation { allocation, items })?;
    if allocation != CaptureProgramV1Allocation::ValidationScratch && vector.capacity() != items {
        return Err(CaptureProgramV1Error::Allocation { allocation, items });
    }
    Ok(())
}

fn u32_value(value: usize, site: &'static str) -> Result<u32, CaptureProgramV1Error> {
    u32::try_from(value).map_err(|_| CaptureProgramV1Error::ArithmeticOverflow(site))
}

fn usize_from_u32(value: u32) -> Result<usize, CaptureProgramV1Error> {
    usize::try_from(value)
        .map_err(|_| CaptureProgramV1Error::ArithmeticOverflow("u32 to usize conversion"))
}

fn usize_from_u64(value: u64, site: &'static str) -> Result<usize, CaptureProgramV1Error> {
    usize::try_from(value).map_err(|_| CaptureProgramV1Error::ArithmeticOverflow(site))
}

fn read_u8(bytes: &[u8], offset: usize, field: &'static str) -> Result<u8, CaptureProgramV1Error> {
    bytes
        .get(offset)
        .copied()
        .ok_or(CaptureProgramV1FormatError::Truncated(field).into())
}

fn read_u16(
    bytes: &[u8],
    offset: usize,
    field: &'static str,
) -> Result<u16, CaptureProgramV1Error> {
    let value = bytes
        .get(offset..offset.saturating_add(2))
        .ok_or(CaptureProgramV1FormatError::Truncated(field))?;
    Ok(u16::from_le_bytes(value.try_into().map_err(|_| {
        CaptureProgramV1FormatError::Truncated(field)
    })?))
}

fn read_u32(
    bytes: &[u8],
    offset: usize,
    field: &'static str,
) -> Result<u32, CaptureProgramV1Error> {
    let value = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or(CaptureProgramV1FormatError::Truncated(field))?;
    Ok(u32::from_le_bytes(value.try_into().map_err(|_| {
        CaptureProgramV1FormatError::Truncated(field)
    })?))
}

fn read_u64(
    bytes: &[u8],
    offset: usize,
    field: &'static str,
) -> Result<u64, CaptureProgramV1Error> {
    let value = bytes
        .get(offset..offset.saturating_add(8))
        .ok_or(CaptureProgramV1FormatError::Truncated(field))?;
    Ok(u64::from_le_bytes(value.try_into().map_err(|_| {
        CaptureProgramV1FormatError::Truncated(field)
    })?))
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

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::{
        CaptureProgramV1, CaptureProgramV1Error, CaptureProgramV1FormatError,
        CaptureProgramV1Limits, DIGEST_BYTES, DIGEST_OFFSET, OPCODE_ASSERT, OPCODE_BYTE,
        OPCODE_SAVE, STATE_ENTRY_BYTES, encode_program, parse_header, semantic_digest,
    };
    use crate::{Assertion, Ast, BuildLimits, Program};

    fn artifact() -> CaptureProgramV1 {
        let ast = Ast::concat([
            Ast::Assert(Assertion::Start),
            Ast::Class(vec![(b'a', b'c'), (b'x', b'z')]).named(1, "_two9"),
            Ast::Byte(b'q').named(2, "other"),
        ]);
        let program = Program::compile(&ast, BuildLimits::default()).expect("fixture compile");
        CaptureProgramV1::from_program(program, CaptureProgramV1Limits::default())
            .expect("fixture seal")
    }

    fn resign(bytes: &mut [u8]) {
        bytes[DIGEST_OFFSET..DIGEST_OFFSET + DIGEST_BYTES].fill(0);
        let digest = semantic_digest(bytes).expect("test digest");
        bytes[DIGEST_OFFSET..DIGEST_OFFSET + DIGEST_BYTES].copy_from_slice(&digest);
    }

    fn format_error(bytes: &[u8]) -> CaptureProgramV1FormatError {
        match CaptureProgramV1::deserialize(bytes, CaptureProgramV1Limits::default())
            .expect_err("mutated artifact must fail")
        {
            CaptureProgramV1Error::Format(error) => error,
            other => panic!("expected format error, got {other:?}"),
        }
    }

    fn state_with_opcode(bytes: &[u8], opcode: u8) -> usize {
        let header = parse_header(bytes, CaptureProgramV1Limits::default()).expect("test header");
        (0..header.usage.states)
            .map(|index| header.states_offset + index * STATE_ENTRY_BYTES)
            .find(|&offset| bytes[offset] == opcode)
            .expect("fixture opcode")
    }

    #[test]
    fn header_extent_digest_and_arbitrary_mutations_are_strict() {
        let artifact = artifact();
        let original = artifact.as_bytes();
        assert_ne!(
            artifact.semantic_digest().as_slice(),
            Sha256::digest(original).as_slice(),
            "the semantic digest must be domain separated and zero its field"
        );
        assert!(matches!(
            format_error(&original[..original.len() - 1]),
            CaptureProgramV1FormatError::ExtentMismatch { .. }
        ));
        let mut trailing = original.to_vec();
        trailing.push(0);
        assert!(matches!(
            format_error(&trailing),
            CaptureProgramV1FormatError::ExtentMismatch { .. }
        ));

        for (offset, value, expected) in [
            (0, b'X', CaptureProgramV1FormatError::BadMagic),
            (8, 2, CaptureProgramV1FormatError::UnsupportedVersion(2)),
            (13, 1, CaptureProgramV1FormatError::UnknownFlags(1)),
            (
                48,
                1,
                CaptureProgramV1FormatError::NonZeroReserved("header reserved u64 0"),
            ),
        ] {
            let mut bytes = original.to_vec();
            bytes[offset] = value;
            assert_eq!(format_error(&bytes), expected);
        }

        let mut unauthenticated = original.to_vec();
        let final_byte = unauthenticated.len() - 1;
        unauthenticated[final_byte] ^= 1;
        assert_eq!(
            format_error(&unauthenticated),
            CaptureProgramV1FormatError::DigestMismatch
        );

        for offset in 0..original.len() {
            let mut bytes = original.to_vec();
            bytes[offset] ^= 1;
            assert!(
                CaptureProgramV1::deserialize(&bytes, CaptureProgramV1Limits::default()).is_err(),
                "one-byte mutation at {offset} was accepted"
            );
        }
    }

    #[test]
    fn schema_names_utf8_slots_and_reserved_fields_are_checked_after_digest() {
        let artifact = artifact();
        let header = parse_header(artifact.as_bytes(), CaptureProgramV1Limits::default())
            .expect("test header");

        let mut bad_index = artifact.as_bytes().to_vec();
        bad_index[header.schema_offset + 16..header.schema_offset + 20]
            .copy_from_slice(&9_u32.to_le_bytes());
        resign(&mut bad_index);
        assert!(matches!(
            format_error(&bad_index),
            CaptureProgramV1FormatError::InvalidSchema(_)
        ));

        let mut bad_schema_reserved = artifact.as_bytes().to_vec();
        bad_schema_reserved[header.schema_offset + 16 + 6] = 1;
        resign(&mut bad_schema_reserved);
        assert_eq!(
            format_error(&bad_schema_reserved),
            CaptureProgramV1FormatError::NonZeroReserved("schema entry reserved field")
        );

        let mut bad_slots = artifact.as_bytes().to_vec();
        let extra_slots = u32::try_from(header.usage.slots + 2).expect("small slots");
        bad_slots[36..40].copy_from_slice(&extra_slots.to_le_bytes());
        resign(&mut bad_slots);
        assert!(matches!(
            format_error(&bad_slots),
            CaptureProgramV1FormatError::InvalidSchema(_)
        ));

        let mut invalid_utf8 = artifact.as_bytes().to_vec();
        invalid_utf8[header.names_offset] = 0xff;
        resign(&mut invalid_utf8);
        assert_eq!(
            format_error(&invalid_utf8),
            CaptureProgramV1FormatError::InvalidNameUtf8
        );

        let mut invalid_name = artifact.as_bytes().to_vec();
        invalid_name[header.names_offset] = b'9';
        resign(&mut invalid_name);
        assert_eq!(
            format_error(&invalid_name),
            CaptureProgramV1FormatError::InvalidName
        );

        let mut duplicate = artifact.as_bytes().to_vec();
        let first_name = duplicate[header.names_offset..header.names_offset + 5].to_vec();
        duplicate[header.names_offset + 5..header.names_offset + 10].copy_from_slice(&first_name);
        resign(&mut duplicate);
        assert_eq!(
            format_error(&duplicate),
            CaptureProgramV1FormatError::DuplicateName
        );
    }

    #[test]
    fn opcodes_assertions_targets_ranges_slots_and_prefilter_are_checked() {
        let artifact = artifact();
        let header = parse_header(artifact.as_bytes(), CaptureProgramV1Limits::default())
            .expect("test header");
        let byte_state = state_with_opcode(artifact.as_bytes(), OPCODE_BYTE);
        let assert_state = state_with_opcode(artifact.as_bytes(), OPCODE_ASSERT);
        let capture_save = (0..header.usage.states)
            .map(|index| header.states_offset + index * STATE_ENTRY_BYTES)
            .find(|&offset| {
                artifact.as_bytes()[offset] == OPCODE_SAVE
                    && u32::from_le_bytes(
                        artifact.as_bytes()[offset + 12..offset + 16]
                            .try_into()
                            .expect("slot field"),
                    ) >= 2
            })
            .expect("capture Save");

        let mut unknown_opcode = artifact.as_bytes().to_vec();
        unknown_opcode[byte_state] = 0xff;
        resign(&mut unknown_opcode);
        assert_eq!(
            format_error(&unknown_opcode),
            CaptureProgramV1FormatError::UnknownOpcode(0xff)
        );

        let mut unknown_assertion = artifact.as_bytes().to_vec();
        unknown_assertion[assert_state + 1] = 0xff;
        resign(&mut unknown_assertion);
        assert_eq!(
            format_error(&unknown_assertion),
            CaptureProgramV1FormatError::UnknownAssertion(0xff)
        );

        let mut bad_target = artifact.as_bytes().to_vec();
        bad_target[byte_state + 4..byte_state + 8].copy_from_slice(
            &u32::try_from(header.usage.states)
                .expect("small state count")
                .to_le_bytes(),
        );
        resign(&mut bad_target);
        assert_eq!(
            format_error(&bad_target),
            CaptureProgramV1FormatError::InvalidTarget
        );

        let mut bad_slot = artifact.as_bytes().to_vec();
        bad_slot[capture_save + 12..capture_save + 16].copy_from_slice(
            &u32::try_from(header.usage.slots)
                .expect("small slot count")
                .to_le_bytes(),
        );
        resign(&mut bad_slot);
        assert_eq!(
            format_error(&bad_slot),
            CaptureProgramV1FormatError::InvalidSlot
        );

        let mut reversed_range = artifact.as_bytes().to_vec();
        reversed_range[header.ranges_offset..header.ranges_offset + 2].copy_from_slice(b"za");
        resign(&mut reversed_range);
        assert_eq!(
            format_error(&reversed_range),
            CaptureProgramV1FormatError::InvalidRange
        );

        let mut overlapping_range = artifact.as_bytes().to_vec();
        overlapping_range[header.ranges_offset + 2] = b'c';
        resign(&mut overlapping_range);
        assert_eq!(
            format_error(&overlapping_range),
            CaptureProgramV1FormatError::InvalidRange
        );

        let mut state_reserved = artifact.as_bytes().to_vec();
        state_reserved[byte_state + 20] = 1;
        resign(&mut state_reserved);
        assert_eq!(
            format_error(&state_reserved),
            CaptureProgramV1FormatError::NonZeroReserved("instruction reserved field")
        );

        let mut bad_prefilter = artifact.as_bytes().to_vec();
        let start_record = header.states_offset + header.start * STATE_ENTRY_BYTES;
        bad_prefilter[start_record + 16..start_record + 20]
            .copy_from_slice(&u32::from_le_bytes([b'a', 0, 0, 1]).to_le_bytes());
        resign(&mut bad_prefilter);
        assert_eq!(
            format_error(&bad_prefilter),
            CaptureProgramV1FormatError::InvalidStartPrefilter
        );

        let mut unreachable = artifact.as_bytes().to_vec();
        unreachable[start_record + 4..start_record + 8].copy_from_slice(
            &u32::try_from(header.usage.states - 3)
                .expect("small state count")
                .to_le_bytes(),
        );
        unreachable[start_record + 16..start_record + 20].fill(0);
        resign(&mut unreachable);
        assert_eq!(
            format_error(&unreachable),
            CaptureProgramV1FormatError::UnreachableState
        );
    }

    #[test]
    fn canonical_encoder_is_byte_identical_after_restore() {
        let artifact = artifact();
        let restored =
            CaptureProgramV1::deserialize(artifact.as_bytes(), CaptureProgramV1Limits::default())
                .expect("restore fixture");
        let encoded = encode_program(restored.program(), restored.usage()).expect("re-encode");
        assert_eq!(encoded, artifact.as_bytes());
    }

    #[test]
    fn converging_split_graph_uses_state_bounded_validation_scratch() {
        let branches = (0_u8..=127).map(Ast::Byte).collect::<Vec<_>>();
        let program = Program::compile(&Ast::Alt(branches), BuildLimits::default())
            .expect("split-heavy fixture compile");
        let artifact = CaptureProgramV1::from_program(program, CaptureProgramV1Limits::default())
            .expect("split-heavy fixture seal");
        let restored =
            CaptureProgramV1::deserialize(artifact.as_bytes(), CaptureProgramV1Limits::default())
                .expect("split-heavy fixture restore");
        assert!(restored.program().build_report_closes());
        assert_eq!(restored.as_bytes(), artifact.as_bytes());
    }
}
