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

use fre_exact_alloc::ExactVec;
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
use crate::participation_native::{
    ExactSpanParticipationNativeV1Error, ExactSpanParticipationNativeV1Limits,
    ExactSpanParticipationNativeV1View,
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
const VALIDATION_BITMAP_BITS: usize = 32;

/// Fixed bytes needed to discover a V1 artifact's exact extent.
pub const CAPTURE_PROGRAM_V1_HEADER_BYTES: usize = 96;

/// Stable accounting identity for the allocation-free full-wire census.
pub const CAPTURE_PROGRAM_V1_CENSUS_ACCOUNTING_ID: &str =
    "fre-capture-lab.capture-program-v1-census.v1";

/// Stable accounting identity for actual retained owner capacities.
pub const CAPTURE_PROGRAM_V1_RETAINED_OWNER_ACCOUNTING_ID: &str =
    "fre-capture-lab.capture-program-v1-retained-owner.v1";

/// Stable identity for the full-wire validation-work upper bound.
///
/// V2 adds the authenticated wire-byte pass and complete allocation-free
/// reachability/prefilter passes to V1's earlier under-specified state term.
/// This accounting revision does not change any `CaptureProgramV1` wire byte.
pub const CAPTURE_PROGRAM_V1_VALIDATION_ACCOUNTING_ID: &str =
    "fre-capture-lab.capture-program-v1-validation.v2";

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
    /// Actual nested retained heap payload after owned reconstruction.
    ///
    /// This excludes the top-level inline [`CaptureProgramV1`] value and any
    /// future outer `Box`/`Arc` control block, padding, or allocator rounding.
    RetainedHeapBytes,
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
    /// Caller-owned census scratch cannot hold the admitted graph shape.
    ValidationScratch {
        /// Exact `u32` words required by the shared validator.
        required_words: usize,
        /// Words supplied by the caller.
        available_words: usize,
    },
    /// A supplied full-wire census does not describe the exact wire image.
    CensusMismatch,
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
            Self::ValidationScratch {
                required_words,
                available_words,
            } => write!(
                formatter,
                "capture program V1 validation needs {required_words} u32 scratch words, only {available_words} are available"
            ),
            Self::CensusMismatch => {
                formatter.write_str("capture program V1 census does not authenticate the wire")
            }
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
            | Self::ValidationScratch { .. }
            | Self::CensusMismatch
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
    /// Versioned full-wire validation-work upper bound identified by
    /// [`CAPTURE_PROGRAM_V1_VALIDATION_ACCOUNTING_ID`].
    pub validation_work: usize,
    /// Conservative reconstructed immutable-program bytes.
    pub program_bytes: usize,
}

/// Allocation-free full-body census of one canonical V1 wire image.
///
/// The census authenticates the exact extent and digest and runs the same
/// schema, instruction, reachability, and graph-derived start-prefilter
/// validator as owned deserialization. It owns no heap storage.
///
/// `validation_scratch_logical_bytes` is the exact prefix of caller-owned
/// `u32` storage the validator uses. `owned_retained_logical_bytes` is the
/// prospective payload requested for the returned program's canonical byte
/// vector, state/group/schema arrays, range arrays, and two owned copies of
/// each capture name. Array element sizes include their embedded `Vec` or
/// `String` descriptors, while the referenced range/name payload is counted
/// separately. These are logical payloads, not allocator receipts: they
/// exclude the borrowed input, transient scratch, top-level inline structs,
/// any later `Arc`, allocator metadata, usable-size rounding, and
/// reallocations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureProgramV1Census {
    accounting_id: &'static str,
    validation_accounting_id: &'static str,
    profile: CaptureProfile,
    start: usize,
    start_prefilter: u32,
    can_match_empty: bool,
    usage: CaptureProgramV1Usage,
    semantic_digest: [u8; DIGEST_BYTES],
    validation_scratch_words: usize,
    validation_scratch_logical_bytes: usize,
    byte_range_vectors: usize,
    nonempty_byte_range_vectors: usize,
    named_groups: usize,
    owned_deserialize_reservation_calls: usize,
    owned_deserialize_nonempty_reservations: usize,
    owned_retained_logical_bytes: usize,
}

impl CaptureProgramV1Census {
    /// Derive the exact scratch prefix required by the declared state count.
    ///
    /// This is strictly a fixed-header, extent-arithmetic, and resource-cap
    /// check. It does not authenticate the digest or inspect any body byte.
    ///
    /// # Errors
    ///
    /// Returns the same fixed-header format, arithmetic, and resource errors
    /// as V1 extent discovery.
    pub fn scratch_words_from_header(
        header: &[u8],
        limits: CaptureProgramV1Limits,
    ) -> Result<usize, CaptureProgramV1Error> {
        if header.len() != CAPTURE_PROGRAM_V1_HEADER_BYTES {
            return Err(CaptureProgramV1FormatError::Truncated(
                "fixed header has the wrong extent",
            )
            .into());
        }
        let header = parse_fixed_header(header, limits)?;
        validation_scratch_words(header.usage.states)
    }

    /// Validate and census one complete canonical V1 wire image without
    /// allocating.
    ///
    /// At least [`Self::scratch_words_from_header`] `u32` words must be
    /// supplied. An oversized slice is accepted, but only the exact required
    /// prefix is read or written. Scratch is transient caller-owned storage,
    /// is excluded from retained-byte accounting, and may be mutated even
    /// when validation returns an error.
    ///
    /// # Errors
    ///
    /// Returns the shared V1 format/resource/arithmetic taxonomy, or
    /// [`CaptureProgramV1Error::ValidationScratch`] before any indexed scratch
    /// access when the supplied slice is too short.
    pub fn from_wire(
        bytes: &[u8],
        limits: CaptureProgramV1Limits,
        scratch: &mut [u32],
    ) -> Result<Self, CaptureProgramV1Error> {
        let header = parse_header(bytes, limits)?;
        let required_words = validation_scratch_words(header.usage.states)?;
        require_validation_scratch(required_words, scratch.len())?;
        verify_digest(bytes, header.digest)?;
        let available_words = scratch.len();
        let scratch =
            scratch
                .get_mut(..required_words)
                .ok_or(CaptureProgramV1Error::ValidationScratch {
                    required_words,
                    available_words,
                })?;
        let wire = validate_full_wire(bytes, header, scratch)?;
        let census = census_from_validated_wire(header, wire)?;
        if !census.closes(limits) {
            return Err(CaptureProgramV1Error::InternalInvariant(
                "capture-program census accounting does not close",
            ));
        }
        Ok(census)
    }

    /// Stable accounting identity for this census schema.
    #[must_use]
    pub const fn accounting_id(self) -> &'static str {
        self.accounting_id
    }

    /// Stable identity of [`CaptureProgramV1Usage::validation_work`].
    #[must_use]
    pub const fn validation_accounting_id(self) -> &'static str {
        self.validation_accounting_id
    }

    /// Pinned semantic profile authenticated by the wire.
    #[must_use]
    pub const fn profile(self) -> CaptureProfile {
        self.profile
    }

    /// Canonical start-state index.
    #[must_use]
    pub const fn start(self) -> usize {
        self.start
    }

    /// Canonical graph-derived start-prefilter encoding retained in the start
    /// Save instruction. Zero is intentionally ambiguous.
    #[must_use]
    pub const fn start_prefilter(self) -> u32 {
        self.start_prefilter
    }

    /// Whether the assertion-relaxed start closure can reach Match without
    /// consuming a byte.
    ///
    /// `false` proves every semantic match consumes at least one byte. `true`
    /// is conservative because a boundary assertion can still reject a
    /// particular source position.
    #[must_use]
    pub const fn can_match_empty(self) -> bool {
        self.can_match_empty
    }

    /// Exact source-independent wire and reconstructed-program dimensions.
    #[must_use]
    pub const fn usage(self) -> CaptureProgramV1Usage {
        self.usage
    }

    /// Authenticated domain-separated semantic digest.
    #[must_use]
    pub const fn semantic_digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.semantic_digest
    }

    /// Exact transient caller-owned `u32` scratch prefix.
    #[must_use]
    pub const fn validation_scratch_words(self) -> usize {
        self.validation_scratch_words
    }

    /// Logical bytes in the exact transient scratch prefix.
    #[must_use]
    pub const fn validation_scratch_logical_bytes(self) -> usize {
        self.validation_scratch_logical_bytes
    }

    /// Byte instructions whose owned decode performs a range-vector
    /// reservation call, including zero-range byte instructions.
    #[must_use]
    pub const fn byte_range_vectors(self) -> usize {
        self.byte_range_vectors
    }

    /// Byte instructions whose range-vector reservation is nonempty.
    #[must_use]
    pub const fn nonempty_byte_range_vectors(self) -> usize {
        self.nonempty_byte_range_vectors
    }

    /// Schema groups whose nonempty name is copied into both owned schemas.
    #[must_use]
    pub const fn named_groups(self) -> usize {
        self.named_groups
    }

    /// Exact number of owned-deserialize reservation calls, including the
    /// transient validation scratch and zero-length range reservations.
    ///
    /// This is a call count, not proof of allocator calls or reallocations.
    #[must_use]
    pub const fn owned_deserialize_reservation_calls(self) -> usize {
        self.owned_deserialize_reservation_calls
    }

    /// Reservation calls with a nonzero requested payload.
    ///
    /// This remains a request count rather than an allocator receipt.
    #[must_use]
    pub const fn owned_deserialize_nonempty_reservations(self) -> usize {
        self.owned_deserialize_nonempty_reservations
    }

    /// Prospective retained logical heap payload after owned deserialization.
    #[must_use]
    pub const fn owned_retained_logical_bytes(self) -> usize {
        self.owned_retained_logical_bytes
    }

    /// Allocation-free exact-wire identity check.
    ///
    /// This authenticates unchanged bytes against an already validated
    /// census; it is not a replacement for full validation of new bytes.
    #[must_use]
    pub fn authenticates_wire(&self, bytes: &[u8]) -> bool {
        bytes.len() == self.usage.serialized_bytes
            && digest_from_header(bytes).ok() == Some(self.semantic_digest)
            && semantic_digest(bytes).ok() == Some(self.semantic_digest)
    }

    /// Whether every derived dimension still closes under `limits` and this
    /// accounting schema's internal identities.
    #[must_use]
    pub fn closes(self, limits: CaptureProgramV1Limits) -> bool {
        self.accounting_id == CAPTURE_PROGRAM_V1_CENSUS_ACCOUNTING_ID
            && self.validation_accounting_id == CAPTURE_PROGRAM_V1_VALIDATION_ACCOUNTING_ID
            && self.profile == CaptureProfile::RustRegexBytes1_12_4
            && self.start < self.usage.states
            && (!self.can_match_empty || self.start_prefilter == 0)
            && self.usage.serialized_bytes
                <= limits.max_serialized_bytes.min(HARD_MAX_SERIALIZED_BYTES)
            && self.usage.states <= limits.max_states
            && self.usage.byte_ranges <= limits.max_byte_ranges
            && self.usage.groups <= limits.max_groups
            && self.usage.slots <= limits.max_slots
            && self.usage.name_bytes <= limits.max_name_bytes
            && self.usage.validation_work <= limits.max_validation_work
            && self.usage.program_bytes <= limits.max_program_bytes
            && self.usage.groups.checked_mul(2) == Some(self.usage.slots)
            && validation_scratch_words(self.usage.states) == Ok(self.validation_scratch_words)
            && self.validation_scratch_words.checked_mul(size_of::<u32>())
                == Some(self.validation_scratch_logical_bytes)
            && self.byte_range_vectors <= self.usage.states
            && self.nonempty_byte_range_vectors <= self.byte_range_vectors
            && self.named_groups <= self.usage.groups
            && owned_deserialize_reservation_calls(self.byte_range_vectors, self.named_groups)
                == Ok(self.owned_deserialize_reservation_calls)
            && owned_deserialize_nonempty_reservations(
                self.nonempty_byte_range_vectors,
                self.named_groups,
            ) == Ok(self.owned_deserialize_nonempty_reservations)
            && owned_retained_logical_bytes(self.usage) == Ok(self.owned_retained_logical_bytes)
    }
}

/// Actual capacity receipt for one unpublished owned V1 reconstruction.
///
/// Every nested charge is derived from the allocator-reported capacity of the
/// retained `Vec` or `String`, not from its logical length. State, program
/// group, and public-schema capacity bytes include the inline descriptors of
/// their nested range vectors and names; the referenced range and name
/// payload capacities are charged separately.
///
/// [`Self::nested_retained_heap_bytes`] is the independently cappable retained
/// heap boundary. [`Self::top_level_inline_bytes`] is the exact
/// `CaptureProgramV1` value that a later outer owner stores inline. The sum is
/// exposed as [`Self::retained_owner_payload_bytes`], but neither figure
/// claims this returned receipt value, an `Arc` control block,
/// outer-allocation padding, allocator metadata, or allocator usable-size
/// rounding. A later handle retaining the receipt or wrapping the program in
/// `Arc` must account for those inline and outer details separately. Unlike
/// the census's prospective logical payload, successful reconstruction
/// requires every exact-capacity retained owner to close against its logical
/// length; this receipt proves the measured total is equal before publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureProgramV1RetainedOwnerReceipt {
    accounting_id: &'static str,
    census: CaptureProgramV1Census,
    canonical_bytes_capacity: usize,
    program_states_capacity: usize,
    program_states_capacity_bytes: usize,
    program_groups_capacity: usize,
    program_groups_capacity_bytes: usize,
    schema_groups_capacity: usize,
    schema_groups_capacity_bytes: usize,
    byte_range_vectors: usize,
    nonempty_byte_range_vectors: usize,
    byte_range_payload_capacity: usize,
    byte_range_payload_capacity_bytes: usize,
    program_named_groups: usize,
    schema_named_groups: usize,
    program_name_capacity_bytes: usize,
    schema_name_capacity_bytes: usize,
    nested_retained_heap_bytes: usize,
    top_level_inline_bytes: usize,
    retained_owner_payload_bytes: usize,
}

impl CaptureProgramV1RetainedOwnerReceipt {
    /// Stable identity of this actual-capacity accounting schema.
    #[must_use]
    pub const fn accounting_id(&self) -> &'static str {
        self.accounting_id
    }

    /// Complete full-wire census authenticated by this receipt.
    #[must_use]
    pub const fn census(&self) -> &CaptureProgramV1Census {
        &self.census
    }

    /// Allocator-reported capacity of the canonical byte vector.
    #[must_use]
    pub const fn canonical_bytes_capacity(&self) -> usize {
        self.canonical_bytes_capacity
    }

    /// Allocator-reported state-vector capacity in `State` elements.
    #[must_use]
    pub const fn program_states_capacity(&self) -> usize {
        self.program_states_capacity
    }

    /// Payload bytes in the state-vector capacity, including inline range
    /// `Vec` descriptors but excluding their separately charged payloads.
    #[must_use]
    pub const fn program_states_capacity_bytes(&self) -> usize {
        self.program_states_capacity_bytes
    }

    /// Allocator-reported private program-group capacity in elements.
    #[must_use]
    pub const fn program_groups_capacity(&self) -> usize {
        self.program_groups_capacity
    }

    /// Payload bytes in the private program-group vector capacity, including
    /// inline `String` descriptors but excluding their payloads.
    #[must_use]
    pub const fn program_groups_capacity_bytes(&self) -> usize {
        self.program_groups_capacity_bytes
    }

    /// Allocator-reported public schema-group capacity in elements.
    #[must_use]
    pub const fn schema_groups_capacity(&self) -> usize {
        self.schema_groups_capacity
    }

    /// Payload bytes in the public schema-group vector capacity, including
    /// inline `String` descriptors but excluding their payloads.
    #[must_use]
    pub const fn schema_groups_capacity_bytes(&self) -> usize {
        self.schema_groups_capacity_bytes
    }

    /// Retained range-vector owners, including zero-capacity byte states.
    #[must_use]
    pub const fn byte_range_vectors(&self) -> usize {
        self.byte_range_vectors
    }

    /// Retained range-vector owners whose reported capacity is nonzero.
    #[must_use]
    pub const fn nonempty_byte_range_vectors(&self) -> usize {
        self.nonempty_byte_range_vectors
    }

    /// Sum of allocator-reported range-vector capacities in range elements.
    #[must_use]
    pub const fn byte_range_payload_capacity(&self) -> usize {
        self.byte_range_payload_capacity
    }

    /// Payload bytes in all retained range-vector capacities.
    #[must_use]
    pub const fn byte_range_payload_capacity_bytes(&self) -> usize {
        self.byte_range_payload_capacity_bytes
    }

    /// Private program names whose `String` owners are retained.
    #[must_use]
    pub const fn program_named_groups(&self) -> usize {
        self.program_named_groups
    }

    /// Duplicated public-schema names whose `String` owners are retained.
    #[must_use]
    pub const fn schema_named_groups(&self) -> usize {
        self.schema_named_groups
    }

    /// Sum of allocator-reported private program-name capacities.
    #[must_use]
    pub const fn program_name_capacity_bytes(&self) -> usize {
        self.program_name_capacity_bytes
    }

    /// Sum of allocator-reported duplicated public-schema name capacities.
    #[must_use]
    pub const fn schema_name_capacity_bytes(&self) -> usize {
        self.schema_name_capacity_bytes
    }

    /// Actual nested retained heap payload.
    ///
    /// This is the cap enforced by
    /// [`CaptureProgramV1::deserialize_with_census`]. It excludes the
    /// top-level inline value and every possible outer owner.
    #[must_use]
    pub const fn nested_retained_heap_bytes(&self) -> usize {
        self.nested_retained_heap_bytes
    }

    /// Exact inline size of the top-level [`CaptureProgramV1`] value.
    #[must_use]
    pub const fn top_level_inline_bytes(&self) -> usize {
        self.top_level_inline_bytes
    }

    /// Nested retained payload plus the top-level inline value.
    ///
    /// This excludes the [`CaptureProgramV1RetainedOwnerReceipt`] value
    /// itself. For a future `Arc<CaptureProgramV1>`, it also excludes the
    /// `Arc` control block, its padding, and allocator rounding.
    #[must_use]
    pub const fn retained_owner_payload_bytes(&self) -> usize {
        self.retained_owner_payload_bytes
    }

    /// Check every census field, the exact wire identity, and every receipt
    /// arithmetic identity without allocating.
    #[must_use]
    pub fn authenticates_census_and_wire(
        &self,
        census: &CaptureProgramV1Census,
        bytes: &[u8],
    ) -> bool {
        self.closes_census_accounting(census) && census.authenticates_wire(bytes)
    }

    /// Check every receipt/census accounting identity without rehashing wire.
    ///
    /// This narrow seam is intended only for a caller that received this
    /// receipt directly from [`CaptureProgramV1::deserialize_with_census`].
    /// That safe constructor has already independently authenticated the full
    /// wire, matched the supplied census, reconstructed a byte-identical
    /// canonical owner, and closed this same receipt before returning. A caller
    /// that has not established that provenance must instead use
    /// [`Self::authenticates_census_and_wire`].
    #[doc(hidden)]
    #[must_use]
    pub fn authenticates_census_accounting(&self, census: &CaptureProgramV1Census) -> bool {
        self.closes_census_accounting(census)
    }

    fn closes_census_accounting(&self, census: &CaptureProgramV1Census) -> bool {
        let usage = census.usage();
        self.accounting_id == CAPTURE_PROGRAM_V1_RETAINED_OWNER_ACCOUNTING_ID
            && self.census == *census
            && self.canonical_bytes_capacity == usage.serialized_bytes
            && self.program_states_capacity == usage.states
            && self.program_states_capacity.checked_mul(size_of::<State>())
                == Some(self.program_states_capacity_bytes)
            && self.program_groups_capacity == usage.groups
            && self
                .program_groups_capacity
                .checked_mul(size_of::<GroupMeta>())
                == Some(self.program_groups_capacity_bytes)
            && self.schema_groups_capacity == usage.groups
            && self
                .schema_groups_capacity
                .checked_mul(size_of::<CaptureGroupSchema>())
                == Some(self.schema_groups_capacity_bytes)
            && self.byte_range_vectors == census.byte_range_vectors()
            && self.nonempty_byte_range_vectors == census.nonempty_byte_range_vectors()
            && self.byte_range_payload_capacity == usage.byte_ranges
            && self
                .byte_range_payload_capacity
                .checked_mul(size_of::<(u8, u8)>())
                == Some(self.byte_range_payload_capacity_bytes)
            && self.program_named_groups == census.named_groups()
            && self.schema_named_groups == census.named_groups()
            && self.program_name_capacity_bytes == usage.name_bytes
            && self.schema_name_capacity_bytes == usage.name_bytes
            && retained_heap_bytes_from_capacity_receipt(self)
                == Some(self.nested_retained_heap_bytes)
            && self.nested_retained_heap_bytes == census.owned_retained_logical_bytes()
            && self.top_level_inline_bytes == size_of::<CaptureProgramV1>()
            && self
                .nested_retained_heap_bytes
                .checked_add(self.top_level_inline_bytes)
                == Some(self.retained_owner_payload_bytes)
    }
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
        validate_wire_for_owned_decode(bytes, header)?;
        reconstruct_validated_owner(bytes, header)
    }

    /// Strictly restore one exact V1 artifact under an authenticated census
    /// and actual nested retained-heap cap.
    ///
    /// The complete census is independently rederived from the exact wire,
    /// including reachability, start-prefilter, and assertion-relaxed
    /// nullability, before any retained owner is decoded. This currently uses
    /// one bounded transient validation-scratch allocation; that scratch is
    /// excluded from `max_nested_retained_heap_bytes` and from the returned
    /// receipt.
    ///
    /// The census logical retained payload is checked before reconstruction.
    /// After all exact-capacity owners have been built, their actual reported
    /// capacities are measured and checked again while the artifact remains
    /// unpublished. Failure drops the complete temporary owner and returns no
    /// receipt.
    ///
    /// `max_nested_retained_heap_bytes` covers only nested retained `Vec` and
    /// `String` payload capacity. It excludes the top-level inline value and
    /// any future `Box`/`Arc` control block, padding, allocator metadata, or
    /// allocator usable-size rounding; the receipt exposes the inline boundary
    /// separately. Neither boundary includes the returned receipt value
    /// itself.
    ///
    /// # Errors
    ///
    /// Returns the ordinary V1 validation/allocation taxonomy, census mismatch
    /// when any supplied field disagrees with the independently derived full
    /// census, or a retained-heap resource refusal. No owner is published on
    /// failure.
    pub fn deserialize_with_census(
        bytes: &[u8],
        limits: CaptureProgramV1Limits,
        census: &CaptureProgramV1Census,
        max_nested_retained_heap_bytes: usize,
    ) -> Result<(Self, CaptureProgramV1RetainedOwnerReceipt), CaptureProgramV1Error> {
        let header = parse_header(bytes, limits)?;
        let wire = validate_wire_for_owned_decode(bytes, header)?;
        let derived = census_from_validated_wire(header, wire)?;
        if derived != *census {
            return Err(CaptureProgramV1Error::CensusMismatch);
        }
        check_resource(
            CaptureProgramV1Resource::RetainedHeapBytes,
            census.owned_retained_logical_bytes(),
            max_nested_retained_heap_bytes,
        )?;

        let owner = reconstruct_validated_owner(bytes, header)?;
        let receipt = retained_owner_receipt(&owner, *census)?;
        // The input digest/full graph and byte-identical canonical re-encode
        // already proved the exact wire. Close only owner/receipt accounting
        // here instead of hashing the same potentially large artifact again.
        if !owned_owner_authenticates_census(&owner, census)
            || !receipt.closes_census_accounting(census)
        {
            return Err(CaptureProgramV1Error::InternalInvariant(
                "restored owner does not close against its authenticated census",
            ));
        }
        check_resource(
            CaptureProgramV1Resource::RetainedHeapBytes,
            receipt.nested_retained_heap_bytes(),
            max_nested_retained_heap_bytes,
        )?;
        Ok((owner, receipt))
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

    /// Borrow an authenticated construction view for helper-free exact-span
    /// capture-participation replay.
    ///
    /// The ordinary span selector remains authoritative. This allocation-free
    /// projection supplies only the prioritized capture graph, stable capture
    /// digest, and exact fixed-scratch geometry needed to replay one already
    /// selected span. `Ok(None)` is a source-independent schema decline (more
    /// than 64 groups); resource errors are terminal for this candidate.
    #[doc(hidden)]
    pub fn exact_span_participation_native_v1_view(
        &self,
        limits: ExactSpanParticipationNativeV1Limits,
    ) -> Result<Option<ExactSpanParticipationNativeV1View<'_>>, ExactSpanParticipationNativeV1Error>
    {
        crate::participation_native::native_v1_view(
            self,
            &self.program,
            self.usage,
            &self.semantic_digest,
            limits,
        )
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

fn validate_wire_for_owned_decode(
    bytes: &[u8],
    header: Header,
) -> Result<ValidatedWireStats, CaptureProgramV1Error> {
    // Preserve the historical owned-deserialize order: authenticate the exact
    // bytes, allocate only bounded transient scratch, run the complete shared
    // validator, and release scratch before any retained decode.
    verify_digest(bytes, header.digest)?;
    let required_words = validation_scratch_words(header.usage.states)?;
    let mut scratch = exact_validation_scratch(required_words)?;
    let wire = validate_full_wire(bytes, header, scratch.as_mut_slice())?;
    drop(scratch);
    Ok(wire)
}

fn reconstruct_validated_owner(
    bytes: &[u8],
    header: Header,
) -> Result<CaptureProgramV1, CaptureProgramV1Error> {
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
    if !program.build_report_closes() {
        return Err(CaptureProgramV1Error::InternalInvariant(
            "restored program accounting does not close",
        ));
    }
    let canonical = encode_program(&program, header.usage)?;
    if canonical.as_slice() != bytes {
        return Err(CaptureProgramV1FormatError::NonCanonicalEncoding.into());
    }
    Ok(CaptureProgramV1 {
        program,
        schema,
        usage: header.usage,
        semantic_digest: header.digest,
        bytes: canonical,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "every independently retained Vec/String capacity remains explicit in one audited receipt"
)]
fn retained_owner_receipt(
    owner: &CaptureProgramV1,
    census: CaptureProgramV1Census,
) -> Result<CaptureProgramV1RetainedOwnerReceipt, CaptureProgramV1Error> {
    let program_states_capacity = owner.program.states.capacity();
    let program_states_capacity_bytes = program_states_capacity
        .checked_mul(size_of::<State>())
        .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
            "retained state-vector capacity bytes",
        ))?;
    let program_groups_capacity = owner.program.groups.capacity();
    let program_groups_capacity_bytes = program_groups_capacity
        .checked_mul(size_of::<GroupMeta>())
        .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
            "retained program-group capacity bytes",
        ))?;
    let schema_groups_capacity = owner.schema.groups.capacity();
    let schema_groups_capacity_bytes = schema_groups_capacity
        .checked_mul(size_of::<CaptureGroupSchema>())
        .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
            "retained schema-group capacity bytes",
        ))?;

    let mut byte_range_vectors = 0_usize;
    let mut nonempty_byte_range_vectors = 0_usize;
    let mut byte_range_payload_capacity = 0_usize;
    for state in &owner.program.states {
        let State::Byte { ranges, .. } = state else {
            continue;
        };
        byte_range_vectors =
            byte_range_vectors
                .checked_add(1)
                .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
                    "retained range-vector count",
                ))?;
        if ranges.capacity() != 0 {
            nonempty_byte_range_vectors = nonempty_byte_range_vectors.checked_add(1).ok_or(
                CaptureProgramV1Error::ArithmeticOverflow("retained nonempty range-vector count"),
            )?;
        }
        byte_range_payload_capacity = byte_range_payload_capacity
            .checked_add(ranges.capacity())
            .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
                "retained range payload capacity",
            ))?;
    }
    let byte_range_payload_capacity_bytes = byte_range_payload_capacity
        .checked_mul(size_of::<(u8, u8)>())
        .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
            "retained range payload capacity bytes",
        ))?;

    let (program_named_groups, program_name_capacity_bytes) =
        retained_name_capacities(owner.program.groups.iter().map(|group| &group.name))?;
    let (schema_named_groups, schema_name_capacity_bytes) =
        retained_name_capacities(owner.schema.groups.iter().map(|group| &group.name))?;

    let mut receipt = CaptureProgramV1RetainedOwnerReceipt {
        accounting_id: CAPTURE_PROGRAM_V1_RETAINED_OWNER_ACCOUNTING_ID,
        census,
        canonical_bytes_capacity: owner.bytes.capacity(),
        program_states_capacity,
        program_states_capacity_bytes,
        program_groups_capacity,
        program_groups_capacity_bytes,
        schema_groups_capacity,
        schema_groups_capacity_bytes,
        byte_range_vectors,
        nonempty_byte_range_vectors,
        byte_range_payload_capacity,
        byte_range_payload_capacity_bytes,
        program_named_groups,
        schema_named_groups,
        program_name_capacity_bytes,
        schema_name_capacity_bytes,
        nested_retained_heap_bytes: 0,
        top_level_inline_bytes: size_of::<CaptureProgramV1>(),
        retained_owner_payload_bytes: 0,
    };
    receipt.nested_retained_heap_bytes = retained_heap_bytes_from_capacity_receipt(&receipt)
        .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
            "nested retained owner capacity bytes",
        ))?;
    receipt.retained_owner_payload_bytes = receipt
        .nested_retained_heap_bytes
        .checked_add(receipt.top_level_inline_bytes)
        .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
            "retained owner payload bytes",
        ))?;
    Ok(receipt)
}

fn retained_name_capacities<'a>(
    mut names: impl Iterator<Item = &'a Option<String>>,
) -> Result<(usize, usize), CaptureProgramV1Error> {
    names.try_fold((0_usize, 0_usize), |(named, capacity), name| {
        match name.as_ref() {
            Some(name) => Ok((
                named
                    .checked_add(1)
                    .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
                        "retained named-group count",
                    ))?,
                capacity.checked_add(name.capacity()).ok_or(
                    CaptureProgramV1Error::ArithmeticOverflow(
                        "retained name payload capacity bytes",
                    ),
                )?,
            )),
            None => Ok((named, capacity)),
        }
    })
}

fn retained_heap_bytes_from_capacity_receipt(
    receipt: &CaptureProgramV1RetainedOwnerReceipt,
) -> Option<usize> {
    receipt
        .canonical_bytes_capacity
        .checked_add(receipt.program_states_capacity_bytes)?
        .checked_add(receipt.program_groups_capacity_bytes)?
        .checked_add(receipt.schema_groups_capacity_bytes)?
        .checked_add(receipt.byte_range_payload_capacity_bytes)?
        .checked_add(receipt.program_name_capacity_bytes)?
        .checked_add(receipt.schema_name_capacity_bytes)
}

fn owned_owner_authenticates_census(
    owner: &CaptureProgramV1,
    census: &CaptureProgramV1Census,
) -> bool {
    let start_prefilter = match owner.program.states.get(owner.program.start) {
        Some(State::Save {
            start_prefilter, ..
        }) => *start_prefilter,
        _ => return false,
    };
    owner.usage == census.usage()
        && owner.semantic_digest == *census.semantic_digest()
        && owner.program.profile() == census.profile()
        && owner.program.start == census.start()
        && start_prefilter == census.start_prefilter()
        && owner.program.states.len() == census.usage().states
        && owner.program.groups.len() == census.usage().groups
        && owner.program.slot_count == census.usage().slots
        && owner.schema.groups.len() == census.usage().groups
        && owner.schema.slot_count == census.usage().slots
        && owner.program.build_report_closes()
        && owner
            .program
            .groups
            .iter()
            .zip(&owner.schema.groups)
            .all(|(program, schema)| program.index == schema.index && program.name == schema.name)
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

    let validation_work = validation_work(declared, states, byte_ranges, groups, name_bytes)?;
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
    let validation_work =
        validation_work(serialized_bytes, states, byte_ranges, groups, name_bytes)?;
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
    serialized_bytes: usize,
    states: usize,
    byte_ranges: usize,
    groups: usize,
    name_bytes: usize,
) -> Result<usize, CaptureProgramV1Error> {
    // The stable upper bound charges every authenticated wire byte, complete
    // header/schema/state/reachability passes, three prefix closures (each of
    // which may visit two targets per state and expand all 256 bytes in every
    // range), and quadratic no-allocation name uniqueness. Coefficients are
    // deliberately representation-level rather than CPU-instruction counts.
    serialized_bytes
        .checked_add(
            states
                .checked_mul(64)
                .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
                    "validation state work",
                ))?,
        )
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
        .and_then(|work| work.checked_add(1_024))
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

#[derive(Clone, Copy)]
struct WireSchemaStats {
    named_groups: usize,
}

#[derive(Clone, Copy)]
struct WireStateStats {
    byte_range_vectors: usize,
    nonempty_byte_range_vectors: usize,
}

#[derive(Clone, Copy)]
struct ValidatedWireStats {
    named_groups: usize,
    byte_range_vectors: usize,
    nonempty_byte_range_vectors: usize,
    start_prefilter: u32,
    can_match_empty: bool,
}

#[derive(Clone, Copy)]
struct WireStartFacts {
    prefilter: u32,
    can_match_empty: bool,
}

#[allow(
    clippy::too_many_lines,
    reason = "schema offsets, UTF-8, names, uniqueness, group zero, and exact extent stay in one auditable pass"
)]
fn validate_schema_wire(
    bytes: &[u8],
    header: Header,
) -> Result<WireSchemaStats, CaptureProgramV1Error> {
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
    let mut named_groups = 0_usize;
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
            named_groups =
                named_groups
                    .checked_add(1)
                    .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
                        "named group count",
                    ))?;
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
    Ok(WireSchemaStats { named_groups })
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
fn validate_state_wire(
    bytes: &[u8],
    header: Header,
) -> Result<WireStateStats, CaptureProgramV1Error> {
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
    let mut byte_range_vectors = 0_usize;
    let mut nonempty_byte_range_vectors = 0_usize;
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
                byte_range_vectors = byte_range_vectors.checked_add(1).ok_or(
                    CaptureProgramV1Error::ArithmeticOverflow("byte range-vector count"),
                )?;
                require_zero(&assertion, "Byte assertion tag")?;
                require_zero(&target1, "Byte target 1")?;
                require_target(target0, header.usage.states)?;
                if value0 != expected_range_offset {
                    return Err(CaptureProgramV1FormatError::InvalidRange.into());
                }
                let range_count = usize_from_u32(value1)?;
                if range_count != 0 {
                    nonempty_byte_range_vectors = nonempty_byte_range_vectors
                        .checked_add(1)
                        .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
                            "nonempty byte range-vector count",
                        ))?;
                }
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
    Ok(WireStateStats {
        byte_range_vectors,
        nonempty_byte_range_vectors,
    })
}

struct ValidationScratchSlices<'a> {
    first: &'a mut [u32],
    second: &'a mut [u32],
    stack: &'a mut [u32],
}

fn validation_bitmap_words(states: usize) -> Result<usize, CaptureProgramV1Error> {
    states
        .checked_add(VALIDATION_BITMAP_BITS - 1)
        .map(|rounded| rounded / VALIDATION_BITMAP_BITS)
        .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
            "validation bitmap words",
        ))
}

fn validation_scratch_words(states: usize) -> Result<usize, CaptureProgramV1Error> {
    let bitmap_words = validation_bitmap_words(states)?;
    bitmap_words
        .checked_mul(2)
        .and_then(|words| words.checked_add(states))
        .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
            "validation scratch words",
        ))
}

fn require_validation_scratch(
    required_words: usize,
    available_words: usize,
) -> Result<(), CaptureProgramV1Error> {
    if available_words < required_words {
        return Err(CaptureProgramV1Error::ValidationScratch {
            required_words,
            available_words,
        });
    }
    Ok(())
}

fn validation_scratch_slices(
    scratch: &mut [u32],
    states: usize,
) -> Result<ValidationScratchSlices<'_>, CaptureProgramV1Error> {
    let bitmap_words = validation_bitmap_words(states)?;
    let required_words = validation_scratch_words(states)?;
    require_validation_scratch(required_words, scratch.len())?;
    let (first, remaining) = scratch.split_at_mut(bitmap_words);
    let (second, remaining) = remaining.split_at_mut(bitmap_words);
    let (stack, _) = remaining.split_at_mut(states);
    Ok(ValidationScratchSlices {
        first,
        second,
        stack,
    })
}

fn bitmap_contains(bitmap: &[u32], state: usize) -> bool {
    let word = state / VALIDATION_BITMAP_BITS;
    let bit = state % VALIDATION_BITMAP_BITS;
    bitmap[word] & (1_u32 << bit) != 0
}

fn bitmap_insert(bitmap: &mut [u32], state: usize) -> bool {
    let word = state / VALIDATION_BITMAP_BITS;
    let bit = state % VALIDATION_BITMAP_BITS;
    let mask = 1_u32 << bit;
    let inserted = bitmap[word] & mask == 0;
    bitmap[word] |= mask;
    inserted
}

fn push_wire_state(
    state: usize,
    seen: &mut [u32],
    stack: &mut [u32],
    stack_len: &mut usize,
) -> Result<(), CaptureProgramV1Error> {
    if !bitmap_insert(seen, state) {
        return Ok(());
    }
    let slot = stack
        .get_mut(*stack_len)
        .ok_or(CaptureProgramV1Error::InternalInvariant(
            "wire traversal stack exceeded the admitted state count",
        ))?;
    *slot = u32_value(state, "wire traversal state")?;
    *stack_len = (*stack_len)
        .checked_add(1)
        .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
            "wire traversal stack length",
        ))?;
    Ok(())
}

fn wire_target(record: &[u8], offset: usize) -> Result<usize, CaptureProgramV1Error> {
    usize_from_u32(read_u32(record, offset, "wire traversal target")?)
}

fn validate_wire_reachability(
    bytes: &[u8],
    header: Header,
    scratch: &mut [u32],
) -> Result<(), CaptureProgramV1Error> {
    let ValidationScratchSlices {
        first: seen, stack, ..
    } = validation_scratch_slices(scratch, header.usage.states)?;
    seen.fill(0);
    let mut stack_len = 0_usize;
    push_wire_state(header.start, seen, stack, &mut stack_len)?;
    while stack_len != 0 {
        stack_len -= 1;
        let state = usize_from_u32(stack[stack_len])?;
        let record = state_record(bytes, header, state)?;
        match read_u8(record, 0, "wire traversal opcode")? {
            OPCODE_BYTE | OPCODE_SAVE | OPCODE_ASSERT | OPCODE_EPSILON => {
                push_wire_state(wire_target(record, 4)?, seen, stack, &mut stack_len)?;
            }
            OPCODE_SPLIT => {
                push_wire_state(wire_target(record, 8)?, seen, stack, &mut stack_len)?;
                push_wire_state(wire_target(record, 4)?, seen, stack, &mut stack_len)?;
            }
            OPCODE_MATCH | OPCODE_FAIL => {}
            unknown => return Err(CaptureProgramV1FormatError::UnknownOpcode(unknown).into()),
        }
    }
    if (0..header.usage.states).any(|state| !bitmap_contains(seen, state)) {
        return Err(CaptureProgramV1FormatError::UnreachableState.into());
    }
    Ok(())
}

fn wire_byte_range_extent(record: &[u8]) -> Result<core::ops::Range<usize>, CaptureProgramV1Error> {
    let begin = usize_from_u32(read_u32(record, 12, "wire byte-range offset")?)?;
    let count = usize_from_u32(read_u32(record, 16, "wire byte-range count")?)?;
    let end = begin
        .checked_add(count)
        .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
            "wire byte-range extent",
        ))?;
    Ok(begin..end)
}

fn wire_byte_state_contains(
    bytes: &[u8],
    header: Header,
    record: &[u8],
    byte: u8,
) -> Result<bool, CaptureProgramV1Error> {
    for range_index in wire_byte_range_extent(record)? {
        let (start, end) = wire_range(bytes, header, range_index)?;
        if start <= byte && byte <= end {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Rederive the complete compiler start proof directly from validated wire.
#[allow(
    clippy::too_many_lines,
    reason = "the three fixed prefix closures share one caller-owned scratch transaction"
)]
fn derive_wire_start_prefilter(
    bytes: &[u8],
    header: Header,
    scratch: &mut [u32],
) -> Result<WireStartFacts, CaptureProgramV1Error> {
    let ValidationScratchSlices {
        first: frontier,
        second: closure,
        stack,
    } = validation_scratch_slices(scratch, header.usage.states)?;
    frontier.fill(0);
    closure.fill(0);
    bitmap_insert(frontier, header.start);
    let mut first_bytes = [false; 256];
    let mut first_nullable = false;
    let mut common = [0_u8; 3];
    let mut common_len = 0_usize;

    for (depth, common_byte) in common.iter_mut().enumerate() {
        closure.fill(0);
        let mut stack_len = 0_usize;
        for state in 0..header.usage.states {
            if bitmap_contains(frontier, state) {
                push_wire_state(state, closure, stack, &mut stack_len)?;
            }
        }
        while stack_len != 0 {
            stack_len -= 1;
            let state = usize_from_u32(stack[stack_len])?;
            let record = state_record(bytes, header, state)?;
            match read_u8(record, 0, "prefilter closure opcode")? {
                OPCODE_SAVE | OPCODE_ASSERT | OPCODE_EPSILON => {
                    push_wire_state(wire_target(record, 4)?, closure, stack, &mut stack_len)?;
                }
                OPCODE_SPLIT => {
                    push_wire_state(wire_target(record, 8)?, closure, stack, &mut stack_len)?;
                    push_wire_state(wire_target(record, 4)?, closure, stack, &mut stack_len)?;
                }
                OPCODE_BYTE | OPCODE_MATCH | OPCODE_FAIL => {}
                unknown => {
                    return Err(CaptureProgramV1FormatError::UnknownOpcode(unknown).into());
                }
            }
        }

        let mut nullable = false;
        let mut possible = [false; 256];
        for state in 0..header.usage.states {
            if !bitmap_contains(closure, state) {
                continue;
            }
            let record = state_record(bytes, header, state)?;
            match read_u8(record, 0, "prefilter state opcode")? {
                OPCODE_MATCH => nullable = true,
                OPCODE_BYTE => {
                    for range_index in wire_byte_range_extent(record)? {
                        let (start, end) = wire_range(bytes, header, range_index)?;
                        for byte in start..=end {
                            possible[usize::from(byte)] = true;
                        }
                    }
                }
                _ => {}
            }
        }
        if depth == 0 {
            first_bytes = possible;
            first_nullable = nullable;
        }
        let mut singleton = None;
        for (byte, &present) in possible.iter().enumerate() {
            if !present {
                continue;
            }
            if singleton.is_some() {
                singleton = None;
                break;
            }
            singleton = Some(byte);
        }
        let Some(singleton) = singleton else {
            break;
        };
        if nullable {
            break;
        }
        let singleton = u8::try_from(singleton).map_err(|_| {
            CaptureProgramV1Error::InternalInvariant("wire byte proof escaped the u8 domain")
        })?;
        *common_byte = singleton;
        common_len = depth + 1;
        frontier.fill(0);
        for state in 0..header.usage.states {
            if !bitmap_contains(closure, state) {
                continue;
            }
            let record = state_record(bytes, header, state)?;
            if read_u8(record, 0, "prefilter transition opcode")? == OPCODE_BYTE
                && wire_byte_state_contains(bytes, header, record, singleton)?
            {
                bitmap_insert(frontier, wire_target(record, 4)?);
            }
        }
    }

    if !first_nullable && matches!(common_len, 2 | 3) {
        let tag = if common_len == 2 {
            EXACT_PREFIX_2_TAG
        } else {
            EXACT_PREFIX_3_TAG
        };
        return Ok(WireStartFacts {
            prefilter: u32::from_le_bytes([common[0], common[1], common[2], tag]),
            can_match_empty: false,
        });
    }
    if first_nullable {
        return Ok(WireStartFacts {
            prefilter: 0,
            can_match_empty: true,
        });
    }
    let mut bytes = [0_u8; 3];
    let mut count = 0_usize;
    for (byte, &present) in first_bytes.iter().enumerate() {
        if !present {
            continue;
        }
        if count == bytes.len() {
            return Ok(WireStartFacts {
                prefilter: 0,
                can_match_empty: false,
            });
        }
        bytes[count] = u8::try_from(byte).map_err(|_| {
            CaptureProgramV1Error::InternalInvariant("wire byte proof escaped the u8 domain")
        })?;
        count += 1;
    }
    if count == 0 {
        return Ok(WireStartFacts {
            prefilter: 0,
            can_match_empty: false,
        });
    }
    Ok(WireStartFacts {
        prefilter: u32::from_le_bytes([
            bytes[0],
            bytes[1],
            bytes[2],
            u8::try_from(count).map_err(|_| {
                CaptureProgramV1Error::InternalInvariant("wire prefilter count exceeded three")
            })?,
        ]),
        can_match_empty: false,
    })
}

fn validate_full_wire(
    bytes: &[u8],
    header: Header,
    scratch: &mut [u32],
) -> Result<ValidatedWireStats, CaptureProgramV1Error> {
    let required_words = validation_scratch_words(header.usage.states)?;
    require_validation_scratch(required_words, scratch.len())?;
    let schema = validate_schema_wire(bytes, header)?;
    let states = validate_state_wire(bytes, header)?;
    validate_wire_reachability(bytes, header, scratch)?;
    let derived = derive_wire_start_prefilter(bytes, header, scratch)?;
    let start = state_record(bytes, header, header.start)?;
    let retained = read_u32(start, 16, "start prefilter")?;
    if derived.prefilter != retained {
        return Err(CaptureProgramV1FormatError::InvalidStartPrefilter.into());
    }
    Ok(ValidatedWireStats {
        named_groups: schema.named_groups,
        byte_range_vectors: states.byte_range_vectors,
        nonempty_byte_range_vectors: states.nonempty_byte_range_vectors,
        start_prefilter: derived.prefilter,
        can_match_empty: derived.can_match_empty,
    })
}

fn census_from_validated_wire(
    header: Header,
    wire: ValidatedWireStats,
) -> Result<CaptureProgramV1Census, CaptureProgramV1Error> {
    let validation_scratch_words = validation_scratch_words(header.usage.states)?;
    let validation_scratch_logical_bytes = validation_scratch_words
        .checked_mul(size_of::<u32>())
        .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
        "validation scratch logical bytes",
    ))?;
    Ok(CaptureProgramV1Census {
        accounting_id: CAPTURE_PROGRAM_V1_CENSUS_ACCOUNTING_ID,
        validation_accounting_id: CAPTURE_PROGRAM_V1_VALIDATION_ACCOUNTING_ID,
        profile: header.profile,
        start: header.start,
        start_prefilter: wire.start_prefilter,
        can_match_empty: wire.can_match_empty,
        usage: header.usage,
        semantic_digest: header.digest,
        validation_scratch_words,
        validation_scratch_logical_bytes,
        byte_range_vectors: wire.byte_range_vectors,
        nonempty_byte_range_vectors: wire.nonempty_byte_range_vectors,
        named_groups: wire.named_groups,
        owned_deserialize_reservation_calls: owned_deserialize_reservation_calls(
            wire.byte_range_vectors,
            wire.named_groups,
        )?,
        owned_deserialize_nonempty_reservations: owned_deserialize_nonempty_reservations(
            wire.nonempty_byte_range_vectors,
            wire.named_groups,
        )?,
        owned_retained_logical_bytes: owned_retained_logical_bytes(header.usage)?,
    })
}

fn owned_deserialize_reservation_calls(
    byte_range_vectors: usize,
    named_groups: usize,
) -> Result<usize, CaptureProgramV1Error> {
    // Scratch, program groups/states, public schema, and canonical bytes.
    5_usize
        .checked_add(byte_range_vectors)
        .and_then(|calls| named_groups.checked_mul(2)?.checked_add(calls))
        .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
            "owned deserialize reservation calls",
        ))
}

fn owned_deserialize_nonempty_reservations(
    nonempty_byte_range_vectors: usize,
    named_groups: usize,
) -> Result<usize, CaptureProgramV1Error> {
    5_usize
        .checked_add(nonempty_byte_range_vectors)
        .and_then(|calls| named_groups.checked_mul(2)?.checked_add(calls))
        .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
            "owned deserialize nonempty reservations",
        ))
}

fn owned_retained_logical_bytes(
    usage: CaptureProgramV1Usage,
) -> Result<usize, CaptureProgramV1Error> {
    usage
        .groups
        .checked_mul(size_of::<CaptureGroupSchema>())
        .and_then(|schema| schema.checked_add(usage.name_bytes))
        .and_then(|schema| schema.checked_add(usage.program_bytes))
        .and_then(|retained| retained.checked_add(usage.serialized_bytes))
        .ok_or(CaptureProgramV1Error::ArithmeticOverflow(
            "owned retained logical bytes",
        ))
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

fn exact_validation_scratch(words: usize) -> Result<ExactVec<u32>, CaptureProgramV1Error> {
    let mut scratch =
        ExactVec::try_with_capacity(words).map_err(|_| CaptureProgramV1Error::Allocation {
            allocation: CaptureProgramV1Allocation::ValidationScratch,
            items: words,
        })?;
    for _ in 0..words {
        scratch.try_push(0).map_err(|_| {
            CaptureProgramV1Error::InternalInvariant(
                "exact validation scratch refused admitted initialization",
            )
        })?;
    }
    Ok(scratch)
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
    use std::mem::size_of;

    use sha2::{Digest, Sha256};

    use super::{
        CAPTURE_PROGRAM_V1_HEADER_BYTES, CAPTURE_PROGRAM_V1_RETAINED_OWNER_ACCOUNTING_ID,
        CAPTURE_PROGRAM_V1_VALIDATION_ACCOUNTING_ID, CaptureGroupSchema, CaptureProgramV1,
        CaptureProgramV1Census, CaptureProgramV1Error, CaptureProgramV1FormatError,
        CaptureProgramV1Limits, CaptureProgramV1Resource, DIGEST_BYTES, DIGEST_OFFSET,
        HARD_MAX_SERIALIZED_BYTES, OPCODE_ASSERT, OPCODE_BYTE, OPCODE_SAVE, SCHEMA_ENTRY_BYTES,
        STATE_ENTRY_BYTES, VALIDATION_BITMAP_BITS, encode_program, parse_header, semantic_digest,
        validation_scratch_words,
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
        let limits = CaptureProgramV1Limits::default();
        let mut scratch = vec![0_u32; validation_scratch_words(limits.max_states).unwrap()];
        let census = CaptureProgramV1Census::from_wire(bytes, limits, &mut scratch).map(|_| ());
        let deserialize = CaptureProgramV1::deserialize(bytes, limits).map(|_| ());
        assert_eq!(census, deserialize, "census/owned validation parity");
        match deserialize.expect_err("mutated artifact must fail") {
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

    fn census(artifact: &CaptureProgramV1) -> CaptureProgramV1Census {
        let limits = CaptureProgramV1Limits::default();
        let required = CaptureProgramV1Census::scratch_words_from_header(
            &artifact.as_bytes()[..CAPTURE_PROGRAM_V1_HEADER_BYTES],
            limits,
        )
        .expect("fixture scratch shape");
        CaptureProgramV1Census::from_wire(artifact.as_bytes(), limits, &mut vec![0_u32; required])
            .expect("fixture census")
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

        let mut scratch =
            vec![
                0_u32;
                validation_scratch_words(CaptureProgramV1Limits::default().max_states).unwrap()
            ];
        for offset in 0..original.len() {
            for bit in 0..8 {
                let mut bytes = original.to_vec();
                bytes[offset] ^= 1_u8 << bit;
                let census = CaptureProgramV1Census::from_wire(
                    &bytes,
                    CaptureProgramV1Limits::default(),
                    &mut scratch,
                )
                .map(|_| ());
                let deserialize =
                    CaptureProgramV1::deserialize(&bytes, CaptureProgramV1Limits::default())
                        .map(|_| ());
                assert_eq!(
                    census, deserialize,
                    "validation parity at byte {offset}, bit {bit}"
                );
                assert!(
                    deserialize.is_err(),
                    "one-bit mutation at byte {offset}, bit {bit} was accepted"
                );
            }
        }
    }

    #[test]
    fn every_resigned_single_bit_mutation_has_census_owned_canonical_parity() {
        let artifact = artifact();
        let original = artifact.as_bytes();
        let limits = CaptureProgramV1Limits::default();
        let mut scratch = vec![0_u32; validation_scratch_words(limits.max_states).unwrap()];
        for offset in 0..original.len() {
            for bit in 0..8 {
                let mut candidate = original.to_vec();
                candidate[offset] ^= 1_u8 << bit;
                resign(&mut candidate);
                match CaptureProgramV1Census::from_wire(&candidate, limits, &mut scratch) {
                    Ok(census) => {
                        let restored = CaptureProgramV1::deserialize(&candidate, limits)
                            .expect("census-admitted mutation must restore");
                        assert_eq!(restored.as_bytes(), candidate);
                        assert!(census.authenticates_wire(&candidate));
                        assert_eq!(census.usage(), restored.usage());
                    }
                    Err(census_error) => {
                        let owned_error = CaptureProgramV1::deserialize(&candidate, limits)
                            .expect_err("census-refused mutation must not restore");
                        assert_eq!(
                            census_error, owned_error,
                            "resigned validation parity at byte {offset}, bit {bit}"
                        );
                    }
                }
            }
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
    fn census_authenticates_nullable_and_nonnullable_start_facts() {
        let limits = CaptureProgramV1Limits::default();
        for (label, ast, expected_nullable, expected_zero_prefilter) in [
            ("empty", Ast::Empty, true, true),
            ("assertion-only", Ast::Assert(Assertion::Start), true, true),
            ("one-byte", Ast::Byte(b'x'), false, false),
            (
                "wide-first-byte-set",
                Ast::Class(vec![(b'a', b'z')]),
                false,
                true,
            ),
        ] {
            let program = Program::compile(&ast, BuildLimits::default())
                .unwrap_or_else(|error| panic!("{label} fixture compile: {error}"));
            let artifact = CaptureProgramV1::from_program(program, limits)
                .unwrap_or_else(|error| panic!("{label} fixture seal: {error}"));
            let required = CaptureProgramV1Census::scratch_words_from_header(
                &artifact.as_bytes()[..CAPTURE_PROGRAM_V1_HEADER_BYTES],
                limits,
            )
            .unwrap_or_else(|error| panic!("{label} scratch shape: {error}"));
            let mut scratch = vec![0_u32; required];
            let census =
                CaptureProgramV1Census::from_wire(artifact.as_bytes(), limits, &mut scratch)
                    .unwrap_or_else(|error| panic!("{label} census: {error}"));
            assert_eq!(
                census.can_match_empty(),
                expected_nullable,
                "{label} nullability"
            );
            assert_eq!(
                census.start_prefilter() == 0,
                expected_zero_prefilter,
                "{label} prefilter"
            );
            assert!(census.closes(limits), "{label} accounting closure");
            assert!(
                census.authenticates_wire(artifact.as_bytes()),
                "{label} wire identity"
            );

            let restored = CaptureProgramV1::deserialize(artifact.as_bytes(), limits)
                .unwrap_or_else(|error| panic!("{label} owned restore: {error}"));
            assert_eq!(restored.as_bytes(), artifact.as_bytes(), "{label} bytes");
            let restored_census =
                CaptureProgramV1Census::from_wire(restored.as_bytes(), limits, &mut scratch)
                    .unwrap_or_else(|error| panic!("{label} restored census: {error}"));
            assert_eq!(restored_census, census, "{label} shared facts");
        }
    }

    #[test]
    fn nullable_prefilter_corruption_and_resigned_mutations_have_owned_parity() {
        let limits = CaptureProgramV1Limits::default();
        let program = Program::compile(&Ast::Empty, BuildLimits::default())
            .expect("nullable fixture compile");
        let artifact =
            CaptureProgramV1::from_program(program, limits).expect("nullable fixture seal");
        let header = parse_header(artifact.as_bytes(), limits).expect("nullable header");
        let start_record = header.states_offset + header.start * STATE_ENTRY_BYTES;

        let mut bad_prefilter = artifact.as_bytes().to_vec();
        bad_prefilter[start_record + 16..start_record + 20]
            .copy_from_slice(&u32::from_le_bytes([b'x', 0, 0, 1]).to_le_bytes());
        resign(&mut bad_prefilter);
        assert_eq!(
            format_error(&bad_prefilter),
            CaptureProgramV1FormatError::InvalidStartPrefilter
        );

        let required = CaptureProgramV1Census::scratch_words_from_header(
            &artifact.as_bytes()[..CAPTURE_PROGRAM_V1_HEADER_BYTES],
            limits,
        )
        .expect("nullable scratch shape");
        let mut scratch = vec![0_u32; required];
        for offset in 0..artifact.as_bytes().len() {
            for bit in 0..8 {
                let mut candidate = artifact.as_bytes().to_vec();
                candidate[offset] ^= 1_u8 << bit;
                resign(&mut candidate);
                let census = CaptureProgramV1Census::from_wire(&candidate, limits, &mut scratch);
                let owned = CaptureProgramV1::deserialize(&candidate, limits);
                match (census, owned) {
                    (Ok(census), Ok(restored)) => {
                        assert_eq!(restored.as_bytes(), candidate);
                        assert!(census.authenticates_wire(&candidate));
                    }
                    (Err(census_error), Err(owned_error)) => assert_eq!(
                        census_error, owned_error,
                        "nullable resigned validation parity at byte {offset}, bit {bit}"
                    ),
                    (census, owned) => panic!(
                        "nullable census/owned divergence at byte {offset}, bit {bit}: census={census:?}, owned={owned:?}"
                    ),
                }
            }
        }
    }

    #[test]
    fn census_scratch_policy_accounting_and_identity_are_exact() {
        let artifact = artifact();
        let limits = CaptureProgramV1Limits::default();
        let fixed = &artifact.as_bytes()[..CAPTURE_PROGRAM_V1_HEADER_BYTES];
        let required = CaptureProgramV1Census::scratch_words_from_header(fixed, limits)
            .expect("scratch shape");
        let mut exact = vec![u32::MAX; required];
        let census = CaptureProgramV1Census::from_wire(artifact.as_bytes(), limits, &mut exact)
            .expect("exact scratch census");
        assert!(census.closes(limits));
        assert_eq!(census.usage(), artifact.usage());
        assert_eq!(census.semantic_digest(), artifact.semantic_digest());
        assert_eq!(census.validation_scratch_words(), required);
        assert_eq!(
            census.validation_scratch_logical_bytes(),
            required * size_of::<u32>()
        );
        assert_eq!(
            census.owned_retained_logical_bytes(),
            census.usage().serialized_bytes
                + census.usage().program_bytes
                + census.usage().groups * size_of::<CaptureGroupSchema>()
                + census.usage().name_bytes
        );

        let mut short = vec![0_u32; required - 1];
        assert_eq!(
            CaptureProgramV1Census::from_wire(artifact.as_bytes(), limits, &mut short),
            Err(CaptureProgramV1Error::ValidationScratch {
                required_words: required,
                available_words: required - 1,
            })
        );
        let mut oversized = vec![0xa5a5_a5a5; required + 7];
        let oversized_census =
            CaptureProgramV1Census::from_wire(artifact.as_bytes(), limits, &mut oversized)
                .expect("oversized scratch census");
        assert_eq!(oversized_census, census);
        assert_eq!(&oversized[required..], &[0xa5a5_a5a5; 7]);

        assert!(census.authenticates_wire(artifact.as_bytes()));
        let mut changed = artifact.as_bytes().to_vec();
        let final_byte = changed.len() - 1;
        changed[final_byte] ^= 1;
        assert!(!census.authenticates_wire(&changed));
        let mut changed_digest = artifact.as_bytes().to_vec();
        changed_digest[DIGEST_OFFSET] ^= 1;
        assert!(!census.authenticates_wire(&changed_digest));
        let mut forged = census;
        forged.semantic_digest[0] ^= 1;
        assert!(!forged.authenticates_wire(artifact.as_bytes()));
    }

    #[test]
    fn retained_owner_receipt_reports_actual_capacities_and_exact_cap() {
        let artifact = artifact();
        let census = census(&artifact);
        let limits = CaptureProgramV1Limits::default();
        let wire_before = artifact.as_bytes().to_vec();
        let exact = census.owned_retained_logical_bytes();

        assert_eq!(
            CaptureProgramV1::deserialize_with_census(
                artifact.as_bytes(),
                limits,
                &census,
                exact - 1,
            )
            .expect_err("one-below retained cap must refuse"),
            CaptureProgramV1Error::Resource {
                resource: CaptureProgramV1Resource::RetainedHeapBytes,
                required: exact,
                limit: exact - 1,
            }
        );

        let (restored, receipt) =
            CaptureProgramV1::deserialize_with_census(artifact.as_bytes(), limits, &census, exact)
                .expect("exact retained cap");
        assert_eq!(artifact.as_bytes(), wire_before);
        assert_eq!(restored.as_bytes(), wire_before);
        assert_eq!(
            receipt.accounting_id(),
            CAPTURE_PROGRAM_V1_RETAINED_OWNER_ACCOUNTING_ID
        );
        assert_eq!(receipt.census(), &census);
        assert!(receipt.authenticates_census_and_wire(&census, restored.as_bytes()));
        assert_eq!(
            receipt.canonical_bytes_capacity(),
            census.usage().serialized_bytes
        );
        assert_eq!(receipt.program_states_capacity(), census.usage().states);
        assert_eq!(receipt.program_groups_capacity(), census.usage().groups);
        assert_eq!(receipt.schema_groups_capacity(), census.usage().groups);
        assert_eq!(receipt.byte_range_vectors(), census.byte_range_vectors());
        assert_eq!(
            receipt.nonempty_byte_range_vectors(),
            census.nonempty_byte_range_vectors()
        );
        assert_eq!(
            receipt.byte_range_payload_capacity(),
            census.usage().byte_ranges
        );
        assert_eq!(receipt.program_named_groups(), census.named_groups());
        assert_eq!(receipt.schema_named_groups(), census.named_groups());
        assert_eq!(
            receipt.program_name_capacity_bytes(),
            census.usage().name_bytes
        );
        assert_eq!(
            receipt.schema_name_capacity_bytes(),
            census.usage().name_bytes
        );
        assert_eq!(receipt.nested_retained_heap_bytes(), exact);
        assert_eq!(
            receipt.top_level_inline_bytes(),
            size_of::<CaptureProgramV1>()
        );
        assert_eq!(
            receipt.retained_owner_payload_bytes(),
            exact + size_of::<CaptureProgramV1>()
        );
        let mut tampered = restored.as_bytes().to_vec();
        let final_byte = tampered.last_mut().expect("nonempty canonical wire");
        *final_byte ^= 1;
        assert!(!receipt.authenticates_census_and_wire(&census, &tampered));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "every private receipt field has one explicit authentication forgery"
    )]
    fn retained_owner_receipt_rejects_every_forged_field() {
        let artifact = artifact();
        let census = census(&artifact);
        let (_, receipt) = CaptureProgramV1::deserialize_with_census(
            artifact.as_bytes(),
            CaptureProgramV1Limits::default(),
            &census,
            census.owned_retained_logical_bytes(),
        )
        .expect("authentic retained owner");
        assert!(receipt.authenticates_census_and_wire(&census, artifact.as_bytes()));
        assert!(receipt.authenticates_census_accounting(&census));

        let mut forgeries = Vec::new();
        let mut push = |label, forged| forgeries.push((label, forged));

        let mut forged = receipt.clone();
        forged.accounting_id = "forged retained-owner accounting";
        push("accounting id", forged);
        let mut forged = receipt.clone();
        forged.census.accounting_id = "forged embedded census";
        push("embedded census", forged);
        let mut forged = receipt.clone();
        forged.canonical_bytes_capacity += 1;
        push("canonical byte capacity", forged);
        let mut forged = receipt.clone();
        forged.program_states_capacity += 1;
        push("state capacity", forged);
        let mut forged = receipt.clone();
        forged.program_states_capacity_bytes += 1;
        push("state capacity bytes", forged);
        let mut forged = receipt.clone();
        forged.program_groups_capacity += 1;
        push("program-group capacity", forged);
        let mut forged = receipt.clone();
        forged.program_groups_capacity_bytes += 1;
        push("program-group capacity bytes", forged);
        let mut forged = receipt.clone();
        forged.schema_groups_capacity += 1;
        push("schema-group capacity", forged);
        let mut forged = receipt.clone();
        forged.schema_groups_capacity_bytes += 1;
        push("schema-group capacity bytes", forged);
        let mut forged = receipt.clone();
        forged.byte_range_vectors += 1;
        push("range-vector count", forged);
        let mut forged = receipt.clone();
        forged.nonempty_byte_range_vectors += 1;
        push("nonempty range-vector count", forged);
        let mut forged = receipt.clone();
        forged.byte_range_payload_capacity += 1;
        push("range payload capacity", forged);
        let mut forged = receipt.clone();
        forged.byte_range_payload_capacity_bytes += 1;
        push("range payload capacity bytes", forged);
        let mut forged = receipt.clone();
        forged.program_named_groups += 1;
        push("program named-group count", forged);
        let mut forged = receipt.clone();
        forged.schema_named_groups += 1;
        push("schema named-group count", forged);
        let mut forged = receipt.clone();
        forged.program_name_capacity_bytes += 1;
        push("program name capacity bytes", forged);
        let mut forged = receipt.clone();
        forged.schema_name_capacity_bytes += 1;
        push("schema name capacity bytes", forged);
        let mut forged = receipt.clone();
        forged.nested_retained_heap_bytes += 1;
        push("nested retained heap bytes", forged);
        let mut forged = receipt.clone();
        forged.top_level_inline_bytes += 1;
        push("top-level inline bytes", forged);
        let mut forged = receipt.clone();
        forged.retained_owner_payload_bytes += 1;
        push("combined retained owner payload bytes", forged);

        for (label, forged) in forgeries {
            assert!(
                !forged.authenticates_census_accounting(&census),
                "receipt census accounting accepted forged {label}",
            );
            assert!(
                !forged.authenticates_census_and_wire(&census, artifact.as_bytes()),
                "receipt authentication accepted forged {label}",
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "every private full-census field has one explicit reconstruction forgery"
    )]
    fn retained_owner_reconstruction_rejects_every_forged_census_field() {
        type UsageForgery = (&'static str, fn(&mut super::CaptureProgramV1Usage));

        let artifact = artifact();
        let census = census(&artifact);
        let mut forgeries = Vec::new();
        let mut push = |label, forged| forgeries.push((label, forged));

        let mut forged = census;
        forged.accounting_id = "forged census accounting";
        push("accounting id", forged);
        let mut forged = census;
        forged.validation_accounting_id = "forged validation accounting";
        push("validation accounting id", forged);
        let mut forged = census;
        forged.profile = crate::CaptureProfile::Re2Commit972a15Pending;
        push("profile", forged);
        let mut forged = census;
        forged.start = (forged.start + 1) % forged.usage.states;
        push("start", forged);
        let mut forged = census;
        forged.start_prefilter ^= 1;
        push("start prefilter", forged);
        let mut forged = census;
        forged.can_match_empty = !forged.can_match_empty;
        push("can match empty", forged);

        let usage_forgeries: [UsageForgery; 8] = [
            (
                "serialized bytes",
                |usage: &mut super::CaptureProgramV1Usage| usage.serialized_bytes += 1,
            ),
            ("states", |usage: &mut super::CaptureProgramV1Usage| {
                usage.states += 1;
            }),
            ("byte ranges", |usage: &mut super::CaptureProgramV1Usage| {
                usage.byte_ranges += 1;
            }),
            ("groups", |usage: &mut super::CaptureProgramV1Usage| {
                usage.groups += 1;
            }),
            ("slots", |usage: &mut super::CaptureProgramV1Usage| {
                usage.slots += 1;
            }),
            ("name bytes", |usage: &mut super::CaptureProgramV1Usage| {
                usage.name_bytes += 1;
            }),
            (
                "validation work",
                |usage: &mut super::CaptureProgramV1Usage| usage.validation_work += 1,
            ),
            (
                "program bytes",
                |usage: &mut super::CaptureProgramV1Usage| usage.program_bytes += 1,
            ),
        ];
        for (label, mutate) in usage_forgeries {
            let mut forged = census;
            mutate(&mut forged.usage);
            push(label, forged);
        }

        let mut forged = census;
        forged.semantic_digest[0] ^= 1;
        push("semantic digest", forged);
        let mut forged = census;
        forged.validation_scratch_words += 1;
        push("scratch words", forged);
        let mut forged = census;
        forged.validation_scratch_logical_bytes += 1;
        push("scratch bytes", forged);
        let mut forged = census;
        forged.byte_range_vectors += 1;
        push("range-vector count", forged);
        let mut forged = census;
        forged.nonempty_byte_range_vectors += 1;
        push("nonempty range-vector count", forged);
        let mut forged = census;
        forged.named_groups += 1;
        push("named-group count", forged);
        let mut forged = census;
        forged.owned_deserialize_reservation_calls += 1;
        push("reservation calls", forged);
        let mut forged = census;
        forged.owned_deserialize_nonempty_reservations += 1;
        push("nonempty reservation calls", forged);
        let mut forged = census;
        forged.owned_retained_logical_bytes += 1;
        push("logical retained bytes", forged);

        let exact = census.owned_retained_logical_bytes();
        let (_, receipt) = CaptureProgramV1::deserialize_with_census(
            artifact.as_bytes(),
            CaptureProgramV1Limits::default(),
            &census,
            exact,
        )
        .expect("authentic census");
        for (label, forged) in forgeries {
            assert_eq!(
                CaptureProgramV1::deserialize_with_census(
                    artifact.as_bytes(),
                    CaptureProgramV1Limits::default(),
                    &forged,
                    usize::MAX,
                )
                .expect_err("forged census must refuse"),
                CaptureProgramV1Error::CensusMismatch,
                "owned reconstruction accepted forged {label}",
            );
            assert!(
                !receipt.authenticates_census_and_wire(&forged, artifact.as_bytes()),
                "receipt accepted forged {label}",
            );
        }
    }

    #[test]
    fn validation_accounting_v2_is_explicit_wire_neutral_and_stricter() {
        let artifact = artifact();
        let usage = artifact.usage();
        let legacy_work = usage
            .states
            .checked_mul(8)
            .and_then(|work| usage.byte_ranges.checked_mul(772)?.checked_add(work))
            .and_then(|work| {
                usage
                    .groups
                    .checked_mul(usage.name_bytes)?
                    .checked_mul(2)?
                    .checked_add(work)
            })
            .and_then(|work| usage.groups.checked_mul(usage.groups)?.checked_add(work))
            .and_then(|work| work.checked_add(usage.groups))
            .and_then(|work| work.checked_add(1))
            .expect("legacy fixture work");
        assert!(legacy_work < usage.validation_work);

        let mut scratch = vec![
            0_u32;
            CaptureProgramV1Census::scratch_words_from_header(
                &artifact.as_bytes()[..CAPTURE_PROGRAM_V1_HEADER_BYTES],
                CaptureProgramV1Limits::default(),
            )
            .unwrap()
        ];
        let census = CaptureProgramV1Census::from_wire(
            artifact.as_bytes(),
            CaptureProgramV1Limits::default(),
            &mut scratch,
        )
        .unwrap();
        assert_eq!(
            census.validation_accounting_id(),
            CAPTURE_PROGRAM_V1_VALIDATION_ACCOUNTING_ID
        );

        let underreported = CaptureProgramV1Limits {
            max_validation_work: legacy_work,
            ..CaptureProgramV1Limits::default()
        };
        let expected = CaptureProgramV1Error::Resource {
            resource: CaptureProgramV1Resource::ValidationWork,
            required: usage.validation_work,
            limit: legacy_work,
        };
        assert_eq!(
            CaptureProgramV1Census::from_wire(artifact.as_bytes(), underreported, &mut scratch,),
            Err(expected.clone())
        );
        assert_eq!(
            CaptureProgramV1::deserialize(artifact.as_bytes(), underreported)
                .expect_err("legacy-underreported owned work must refuse"),
            expected
        );

        let mut legacy_usage = usage;
        legacy_usage.validation_work = legacy_work;
        assert_eq!(
            encode_program(artifact.program(), legacy_usage).unwrap(),
            artifact.as_bytes(),
            "validation accounting is not a V1 wire field"
        );
    }

    #[test]
    fn census_rejects_zero_and_one_state_bodies_with_owned_parity() {
        for states in [0_usize, 1] {
            let artifact = artifact();
            let mut bytes = artifact.as_bytes()[..CAPTURE_PROGRAM_V1_HEADER_BYTES].to_vec();
            bytes[24..28].copy_from_slice(&u32::try_from(states).unwrap().to_le_bytes());
            bytes[28..32].fill(0);
            bytes[32..36].copy_from_slice(&1_u32.to_le_bytes());
            bytes[36..40].copy_from_slice(&2_u32.to_le_bytes());
            bytes[40..48].fill(0);
            let extent =
                CAPTURE_PROGRAM_V1_HEADER_BYTES + SCHEMA_ENTRY_BYTES + states * STATE_ENTRY_BYTES;
            bytes[16..24].copy_from_slice(&u64::try_from(extent).unwrap().to_le_bytes());
            bytes.resize(extent, 0);
            resign(&mut bytes);
            assert!(matches!(
                format_error(&bytes),
                CaptureProgramV1FormatError::InvalidProgramShape(
                    "capture program has fewer than four canonical states"
                )
            ));
        }
    }

    #[test]
    fn maximum_header_admitted_state_count_has_checked_scratch_arithmetic() {
        let artifact = artifact();
        let mut header = artifact.as_bytes()[..CAPTURE_PROGRAM_V1_HEADER_BYTES].to_vec();
        let states =
            (HARD_MAX_SERIALIZED_BYTES - CAPTURE_PROGRAM_V1_HEADER_BYTES) / STATE_ENTRY_BYTES;
        let extent = CAPTURE_PROGRAM_V1_HEADER_BYTES + states * STATE_ENTRY_BYTES;
        header[16..24].copy_from_slice(&u64::try_from(extent).unwrap().to_le_bytes());
        header[24..28].copy_from_slice(&u32::try_from(states).unwrap().to_le_bytes());
        header[28..48].fill(0);
        let limits = CaptureProgramV1Limits {
            max_serialized_bytes: usize::MAX,
            max_states: states,
            max_byte_ranges: usize::MAX,
            max_groups: usize::MAX,
            max_slots: usize::MAX,
            max_name_bytes: usize::MAX,
            max_validation_work: usize::MAX,
            max_program_bytes: usize::MAX,
        };
        let words = CaptureProgramV1Census::scratch_words_from_header(&header, limits)
            .expect("maximum admitted state scratch");
        assert_eq!(words, states + 2 * states.div_ceil(VALIDATION_BITMAP_BITS));

        let rejected_states = states + 1;
        let rejected_extent = CAPTURE_PROGRAM_V1_HEADER_BYTES + rejected_states * STATE_ENTRY_BYTES;
        header[16..24].copy_from_slice(&u64::try_from(rejected_extent).unwrap().to_le_bytes());
        header[24..28].copy_from_slice(&u32::try_from(rejected_states).unwrap().to_le_bytes());
        assert!(matches!(
            CaptureProgramV1Census::scratch_words_from_header(
                &header,
                CaptureProgramV1Limits {
                    max_states: rejected_states,
                    ..limits
                }
            ),
            Err(CaptureProgramV1Error::Resource {
                resource: super::CaptureProgramV1Resource::SerializedBytes,
                ..
            })
        ));
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
