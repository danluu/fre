//! Stable target-neutral wire for one source-ordered literal language.
//!
//! This artifact records normalized literal semantics, not compiled native
//! code, a frozen sparse automaton, or a zero-setup runtime image. Restoring a
//! sparse execution plan still performs one explicitly bounded construction.
//! Source ordinals define priority. Caller IDs and any runtime ABI remain an
//! outer concern.
//!
//! V1 is entirely little-endian. Its exact wire is a 64-byte header followed by
//! `pattern_count + 1` cumulative `u32` offsets and the concatenated literal
//! bytes. Header byte ranges are: magic `0..8`, version `8..10`, header bytes
//! `10..12`, flags `12..16`, total bytes `16..24`, pattern count `24..28`, the
//! three one-byte semantic tags plus one reserved byte `28..32`, offset-table
//! start `32..40`, literal-payload start `40..48`, literal-payload bytes
//! `48..56`, and a reserved word `56..64`. The first cumulative offset is zero,
//! the last equals payload bytes, and equal adjacent offsets canonically encode
//! empty literals without losing their source ordinals. Flags and reserved
//! fields are zero; the match, iteration, and boundary semantic tags are each
//! one.

#![allow(
    clippy::result_large_err,
    reason = "terminal sparse failures retain their complete inline receipt so reporting a failed allocation never requires another allocation"
)]

use core::{fmt, mem::size_of};

use fre_kernels::{
    SPARSE_ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID,
    SPARSE_ORDERED_LITERAL_AGGREGATE_BUILD_ATTEMPT_ACCOUNTING_VERSION,
    SPARSE_ORDERED_LITERAL_AGGREGATE_BUILD_ATTEMPT_ALGORITHM_VERSION,
    SPARSE_ORDERED_LITERAL_COUNT_PLAN_ID,
    SparseOrderedLiteralAggregateBuildAttemptError as SparseBuildAttemptError,
    SparseOrderedLiteralAggregateBuildAttemptIdentity as SparseBuildAttemptIdentity,
    SparseOrderedLiteralAggregateBuildAttemptReceipt as SparseBuildAttemptReceipt,
    SparseOrderedLiteralAggregateBuildLimits as SparseBuildLimits,
    SparseOrderedLiteralAggregateOperation as SparseOperation,
    SparseOrderedLiteralCountBuildAttempt, SparseOrderedLiteralCountPlan,
};
use sha2::{Digest, Sha256};

/// Fixed magic at byte zero of every ordered-literal V1 artifact.
pub const ORDERED_LITERAL_ARTIFACT_V1_MAGIC: [u8; 8] = *b"FRELTM1\0";
/// Stable wire version encoded in the fixed header.
pub const ORDERED_LITERAL_ARTIFACT_V1_VERSION: u16 = 1;
/// Bytes in the fixed V1 header.
pub const ORDERED_LITERAL_ARTIFACT_V1_HEADER_BYTES: usize = 64;
/// Bytes in each cumulative little-endian V1 literal offset.
pub const ORDERED_LITERAL_ARTIFACT_V1_OFFSET_BYTES: usize = size_of::<u32>();
/// Maximum complete V1 wire accepted by any builder or reader.
pub const MAX_ORDERED_LITERAL_ARTIFACT_V1_BYTES: usize = 1024 * 1024 * 1024;
/// Maximum source-pattern count representable under the fixed V1 wire cap.
pub const MAX_ORDERED_LITERAL_ARTIFACT_V1_PATTERNS: usize = (MAX_ORDERED_LITERAL_ARTIFACT_V1_BYTES
    - ORDERED_LITERAL_ARTIFACT_V1_HEADER_BYTES)
    / ORDERED_LITERAL_ARTIFACT_V1_OFFSET_BYTES
    - 1;
/// Domain separating an ordered-literal SHA-256 identity from an untyped digest.
pub const ORDERED_LITERAL_ARTIFACT_V1_IDENTITY_DOMAIN: &[u8] = b"fre.aot-ordered-literal.v1\0";

/// Stable semantic format identity carried by every validated V1 census.
pub const ORDERED_LITERAL_ARTIFACT_V1_FORMAT_ID: &str = "fre-aot-regex.ordered-literal-artifact.v1";
/// Stable accounting identity for one owned V1 wire.
pub const ORDERED_LITERAL_ARTIFACT_V1_OWNED_ACCOUNTING_ID: &str =
    "fre-aot-regex.ordered-literal-artifact-owned.v1";
/// Stable accounting identity for the artifact-to-sparse-plan seam.
pub const ORDERED_LITERAL_ARTIFACT_V1_RECONSTRUCTION_ACCOUNTING_ID: &str =
    "fre-aot-regex.ordered-literal-artifact-sparse-reconstruction.v1";
/// Stable accounting identity for allocation-free borrowed validation.
pub const ORDERED_LITERAL_ARTIFACT_V1_VALIDATION_ACCOUNTING_ID: &str =
    "fre-aot-regex.ordered-literal-artifact-validation.v1";
/// Version of allocation-free borrowed-validation accounting.
pub const ORDERED_LITERAL_ARTIFACT_V1_VALIDATION_ACCOUNTING_VERSION: u32 = 1;
/// Version of owned-wire accounting.
pub const ORDERED_LITERAL_ARTIFACT_V1_OWNED_ACCOUNTING_VERSION: u32 = 1;
/// Version of artifact-to-sparse-plan reconstruction accounting.
pub const ORDERED_LITERAL_ARTIFACT_V1_RECONSTRUCTION_ACCOUNTING_VERSION: u32 = 1;
const OFFSET_BYTES: usize = ORDERED_LITERAL_ARTIFACT_V1_OFFSET_BYTES;
const MAX_FORMAT_PATTERNS: usize = MAX_ORDERED_LITERAL_ARTIFACT_V1_PATTERNS;

const HEADER_MAGIC_OFFSET: usize = 0;
const HEADER_VERSION_OFFSET: usize = 8;
const HEADER_BYTES_OFFSET: usize = 10;
const HEADER_FLAGS_OFFSET: usize = 12;
const HEADER_TOTAL_BYTES_OFFSET: usize = 16;
const HEADER_PATTERN_COUNT_OFFSET: usize = 24;
const HEADER_MATCH_SEMANTICS_OFFSET: usize = 28;
const HEADER_ITERATION_SEMANTICS_OFFSET: usize = 29;
const HEADER_BOUNDARY_SEMANTICS_OFFSET: usize = 30;
const HEADER_SEMANTICS_RESERVED_OFFSET: usize = 31;
const HEADER_OFFSET_TABLE_OFFSET: usize = 32;
const HEADER_LITERAL_PAYLOAD_OFFSET: usize = 40;
const HEADER_LITERAL_PAYLOAD_BYTES_OFFSET: usize = 48;
const HEADER_RESERVED_OFFSET: usize = 56;

const FLAGS: u32 = 0;
const MATCH_SEMANTICS_TAG: u8 = 1;
const ITERATION_SEMANTICS_TAG: u8 = 1;
const BOUNDARY_SEMANTICS_TAG: u8 = 1;

const _: () = {
    assert!(size_of::<u32>() == 4);
    assert!(HEADER_MAGIC_OFFSET == 0);
    assert!(HEADER_VERSION_OFFSET == HEADER_MAGIC_OFFSET + size_of::<[u8; 8]>());
    assert!(HEADER_BYTES_OFFSET == HEADER_VERSION_OFFSET + size_of::<u16>());
    assert!(HEADER_FLAGS_OFFSET == HEADER_BYTES_OFFSET + size_of::<u16>());
    assert!(HEADER_TOTAL_BYTES_OFFSET == HEADER_FLAGS_OFFSET + size_of::<u32>());
    assert!(HEADER_PATTERN_COUNT_OFFSET == HEADER_TOTAL_BYTES_OFFSET + size_of::<u64>());
    assert!(HEADER_MATCH_SEMANTICS_OFFSET == HEADER_PATTERN_COUNT_OFFSET + size_of::<u32>());
    assert!(HEADER_ITERATION_SEMANTICS_OFFSET == HEADER_MATCH_SEMANTICS_OFFSET + 1);
    assert!(HEADER_BOUNDARY_SEMANTICS_OFFSET == HEADER_ITERATION_SEMANTICS_OFFSET + 1);
    assert!(HEADER_SEMANTICS_RESERVED_OFFSET == HEADER_BOUNDARY_SEMANTICS_OFFSET + 1);
    assert!(HEADER_OFFSET_TABLE_OFFSET == HEADER_SEMANTICS_RESERVED_OFFSET + 1);
    assert!(HEADER_LITERAL_PAYLOAD_OFFSET == HEADER_OFFSET_TABLE_OFFSET + size_of::<u64>());
    assert!(
        HEADER_LITERAL_PAYLOAD_BYTES_OFFSET == HEADER_LITERAL_PAYLOAD_OFFSET + size_of::<u64>()
    );
    assert!(HEADER_RESERVED_OFFSET == HEADER_LITERAL_PAYLOAD_BYTES_OFFSET + size_of::<u64>());
    assert!(ORDERED_LITERAL_ARTIFACT_V1_HEADER_BYTES == HEADER_RESERVED_OFFSET + size_of::<u64>());
    assert!(MAX_ORDERED_LITERAL_ARTIFACT_V1_BYTES <= 4_294_967_295_usize);
};

/// Source-order tie breaking after the leftmost start is selected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrderedLiteralArtifactMatchSemantics {
    /// The lowest source ordinal wins at one leftmost start.
    SourceOrderLeftmostFirst,
}

/// Iteration policy represented by V1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrderedLiteralIterationSemantics {
    /// Publish successive non-overlapping matches.
    NonOverlapping,
}

/// Byte-boundary and empty-match policy represented by V1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrderedLiteralArtifactBoundarySemantics {
    /// Every byte boundary is eligible under Unicode-off byte semantics.
    ///
    /// After selecting `[start, end)`, matching resumes at `end`. An empty
    /// candidate at that same boundary is suppressed. A selected empty match
    /// `[at, at)` therefore makes progress to the next byte boundary before
    /// another empty match can be published. At end-of-source there is no next
    /// boundary. This is the exact empty-progress rule represented by V1.
    ByteProgressSuppressEmptyAfterNonemptyEnd,
}

/// Complete normalized semantic contract of the V1 wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderedLiteralArtifactSemantics {
    pub match_semantics: OrderedLiteralArtifactMatchSemantics,
    pub iteration_semantics: OrderedLiteralIterationSemantics,
    pub boundary_semantics: OrderedLiteralArtifactBoundarySemantics,
}

impl OrderedLiteralArtifactSemantics {
    /// The only semantic contract accepted by V1.
    pub const RUST_BYTES_UNICODE_OFF: Self = Self {
        match_semantics: OrderedLiteralArtifactMatchSemantics::SourceOrderLeftmostFirst,
        iteration_semantics: OrderedLiteralIterationSemantics::NonOverlapping,
        boundary_semantics:
            OrderedLiteralArtifactBoundarySemantics::ByteProgressSuppressEmptyAfterNonemptyEnd,
    };
}

/// Resource classified by one artifact refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrderedLiteralArtifactResource {
    Patterns,
    SingleLiteralBytes,
    LiteralBytes,
    WireBytes,
    Work,
    AllocationAttempts,
    RetainedBytes,
    PeakBytes,
    SourceReferenceBytes,
}

/// Limits shared by borrowed validation, canonical construction, and restore.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderedLiteralArtifactLimits {
    pub max_patterns: usize,
    pub max_single_literal_bytes: usize,
    pub max_literal_bytes: usize,
    pub max_wire_bytes: usize,
    pub max_work: usize,
    pub max_allocation_attempts: usize,
    pub max_retained_bytes: usize,
    pub max_peak_bytes: usize,
}

impl OrderedLiteralArtifactLimits {
    /// Disable caller-selected limits while retaining the fixed format cap.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_patterns: MAX_FORMAT_PATTERNS,
            max_single_literal_bytes: usize::MAX,
            max_literal_bytes: usize::MAX,
            max_wire_bytes: MAX_ORDERED_LITERAL_ARTIFACT_V1_BYTES,
            max_work: usize::MAX,
            max_allocation_attempts: usize::MAX,
            max_retained_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for OrderedLiteralArtifactLimits {
    fn default() -> Self {
        Self {
            max_patterns: 1_000_000,
            max_single_literal_bytes: 4 * 1024 * 1024,
            max_literal_bytes: 4 * 1024 * 1024,
            max_wire_bytes: 16 * 1024 * 1024,
            max_work: 64 * 1024 * 1024,
            max_allocation_attempts: 1,
            max_retained_bytes: 16 * 1024 * 1024,
            max_peak_bytes: 16 * 1024 * 1024,
        }
    }
}

/// Exact allocation-free structural-validation ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderedLiteralArtifactValidationAccounting {
    pub accounting_id: &'static str,
    pub accounting_version: u32,
    pub input_bytes: usize,
    pub header_bytes: usize,
    pub offset_entries: usize,
    pub offset_table_bytes: usize,
    pub hash_input_bytes: usize,
    pub work: usize,
}

impl OrderedLiteralArtifactValidationAccounting {
    /// Verify the fixed accounting equation without rereading the wire.
    #[must_use]
    pub fn closes(self) -> bool {
        let hash_input_bytes = ORDERED_LITERAL_ARTIFACT_V1_IDENTITY_DOMAIN
            .len()
            .checked_add(self.input_bytes);
        let work = self
            .header_bytes
            .checked_add(self.offset_table_bytes)
            .and_then(|value| value.checked_add(hash_input_bytes?));
        self.accounting_id == ORDERED_LITERAL_ARTIFACT_V1_VALIDATION_ACCOUNTING_ID
            && self.accounting_version == ORDERED_LITERAL_ARTIFACT_V1_VALIDATION_ACCOUNTING_VERSION
            && self.header_bytes == ORDERED_LITERAL_ARTIFACT_V1_HEADER_BYTES
            && self.offset_entries != 0
            && self.offset_entries.checked_mul(OFFSET_BYTES) == Some(self.offset_table_bytes)
            && hash_input_bytes == Some(self.hash_input_bytes)
            && work == Some(self.work)
    }
}

/// Allocation-free census of one canonical ordered-literal artifact.
///
/// `artifact_identity` is an external exact-wire binding. V1 does not contain
/// an embedded checksum and validation does not claim to detect an attacker
/// who can replace both the wire and its separately stored expected identity.
/// The exact formula is `SHA-256(identity_domain || complete_wire)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderedLiteralArtifactCensus {
    artifact_identity: [u8; 32],
    wire_bytes: usize,
    patterns: usize,
    offset_entries: usize,
    offset_table_bytes: usize,
    literal_payload_offset: usize,
    literal_bytes: usize,
    max_pattern_bytes: usize,
    min_nonempty_pattern_bytes: Option<usize>,
    has_empty_pattern: bool,
    validation: OrderedLiteralArtifactValidationAccounting,
}

impl OrderedLiteralArtifactCensus {
    #[must_use]
    pub const fn format_id(self) -> &'static str {
        ORDERED_LITERAL_ARTIFACT_V1_FORMAT_ID
    }

    #[must_use]
    pub const fn semantics(self) -> OrderedLiteralArtifactSemantics {
        OrderedLiteralArtifactSemantics::RUST_BYTES_UNICODE_OFF
    }

    #[must_use]
    pub const fn artifact_identity(self) -> [u8; 32] {
        self.artifact_identity
    }

    #[must_use]
    pub const fn wire_bytes(self) -> usize {
        self.wire_bytes
    }

    #[must_use]
    pub const fn patterns(self) -> usize {
        self.patterns
    }

    #[must_use]
    pub const fn offset_entries(self) -> usize {
        self.offset_entries
    }

    #[must_use]
    pub const fn offset_table_bytes(self) -> usize {
        self.offset_table_bytes
    }

    #[must_use]
    pub const fn literal_payload_offset(self) -> usize {
        self.literal_payload_offset
    }

    #[must_use]
    pub const fn literal_bytes(self) -> usize {
        self.literal_bytes
    }

    #[must_use]
    pub const fn max_pattern_bytes(self) -> usize {
        self.max_pattern_bytes
    }

    #[must_use]
    pub const fn min_nonempty_pattern_bytes(self) -> Option<usize> {
        self.min_nonempty_pattern_bytes
    }

    #[must_use]
    pub const fn has_empty_pattern(self) -> bool {
        self.has_empty_pattern
    }

    #[must_use]
    pub const fn validation_accounting(self) -> OrderedLiteralArtifactValidationAccounting {
        self.validation
    }

    /// Authenticate one exact complete wire without repeating structural scans.
    ///
    /// This hashes the input but does not allocate.
    #[must_use]
    pub fn authenticates_wire(self, bytes: &[u8]) -> bool {
        bytes.len() == self.wire_bytes && artifact_identity(bytes) == self.artifact_identity
    }
}

/// How an owned canonical wire was produced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrderedLiteralArtifactOwnedOperation {
    Build,
    Deserialize,
}

/// Exact observed capacity and abstract work of one owned artifact.
///
/// Retained and peak bytes are the observed byte-vector capacity. Allocator
/// metadata and size-class rounding are outside this logical receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderedLiteralArtifactOwnedAccounting {
    pub accounting_id: &'static str,
    pub accounting_version: u32,
    pub operation: OrderedLiteralArtifactOwnedOperation,
    pub wire_logical_bytes: usize,
    pub wire_capacity_bytes: usize,
    pub retained_bytes: usize,
    pub peak_bytes: usize,
    pub work: usize,
    pub allocation_attempts: usize,
    pub initialized_bytes: usize,
    pub copied_bytes: usize,
}

impl OrderedLiteralArtifactOwnedAccounting {
    #[must_use]
    pub fn closes(self, census: OrderedLiteralArtifactCensus) -> bool {
        let expected_work = match self.operation {
            OrderedLiteralArtifactOwnedOperation::Build => census
                .patterns
                .checked_add(census.wire_bytes)
                .and_then(|value| value.checked_add(census.validation.work)),
            OrderedLiteralArtifactOwnedOperation::Deserialize => {
                census.validation.work.checked_add(census.wire_bytes)
            }
        };
        let expected_copied = match self.operation {
            OrderedLiteralArtifactOwnedOperation::Build => census.literal_bytes,
            OrderedLiteralArtifactOwnedOperation::Deserialize => census.wire_bytes,
        };
        self.accounting_id == ORDERED_LITERAL_ARTIFACT_V1_OWNED_ACCOUNTING_ID
            && self.accounting_version == ORDERED_LITERAL_ARTIFACT_V1_OWNED_ACCOUNTING_VERSION
            && self.wire_logical_bytes == census.wire_bytes
            && self.wire_capacity_bytes == self.wire_logical_bytes
            && self.retained_bytes == self.wire_capacity_bytes
            && self.peak_bytes == self.retained_bytes
            && expected_work == Some(self.work)
            && self.allocation_attempts == 1
            && self.initialized_bytes == census.wire_bytes
            && self.copied_bytes == expected_copied
    }
}

/// Checked artifact construction or validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OrderedLiteralArtifactError {
    TooShort {
        needed: usize,
        actual: usize,
    },
    FormatWireLimit {
        needed: usize,
        limit: usize,
    },
    InvalidMagic,
    UnsupportedVersion {
        found: u16,
    },
    HeaderBytes {
        found: u16,
    },
    UnsupportedFlags {
        found: u32,
    },
    UnsupportedSemantics {
        match_tag: u8,
        iteration_tag: u8,
        boundary_tag: u8,
    },
    ReservedNonzero {
        field: &'static str,
        value: u64,
    },
    EmptyPatternSet,
    RepresentationLimit {
        structure: &'static str,
        needed: u64,
    },
    TotalBytesMismatch {
        declared: u64,
        actual: usize,
    },
    ExtentMismatch {
        field: &'static str,
        expected: usize,
        actual: u64,
    },
    FirstOffsetNonzero {
        found: u32,
    },
    OffsetDecreases {
        index: usize,
        previous: u32,
        current: u32,
    },
    OffsetOutOfBounds {
        index: usize,
        offset: u32,
        literal_bytes: usize,
    },
    FinalOffsetMismatch {
        expected: usize,
        actual: u32,
    },
    ResourceLimit {
        resource: OrderedLiteralArtifactResource,
        needed: usize,
        limit: usize,
    },
    AllocationFailed {
        structure: &'static str,
        bytes: usize,
    },
    NonExactCapacity {
        structure: &'static str,
        requested: usize,
        actual: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    InternalInvariant {
        detail: &'static str,
    },
}

impl fmt::Display for OrderedLiteralArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ordered-literal artifact error: {self:?}")
    }
}

impl std::error::Error for OrderedLiteralArtifactError {}

/// Strict allocation-free view of one canonical complete V1 wire.
#[derive(Clone, Copy, Debug)]
pub struct OrderedLiteralArtifactV1View<'wire> {
    wire: &'wire [u8],
    census: OrderedLiteralArtifactCensus,
}

impl<'wire> OrderedLiteralArtifactV1View<'wire> {
    /// Validate a borrowed wire under explicit resource limits.
    ///
    /// The fixed 1-GiB cap is checked before count-plus-one or table-size
    /// arithmetic. The parser then validates the fixed header and exact
    /// extents, admits prospective work, scans canonical offsets, and finally
    /// computes the external domain-separated identity. No step allocates.
    pub fn from_wire(
        wire: &'wire [u8],
        limits: OrderedLiteralArtifactLimits,
    ) -> Result<Self, OrderedLiteralArtifactError> {
        validate_wire(wire, limits).map(|census| Self { wire, census })
    }

    #[must_use]
    pub const fn as_bytes(self) -> &'wire [u8] {
        self.wire
    }

    #[must_use]
    pub const fn census(self) -> OrderedLiteralArtifactCensus {
        self.census
    }

    /// Return one source-ordinal literal in O(1), without hashing or allocation.
    #[must_use]
    pub fn pattern(self, source_ordinal: usize) -> Option<&'wire [u8]> {
        if source_ordinal >= self.census.patterns {
            return None;
        }
        let start = self.offset(source_ordinal)?;
        let end = self.offset(source_ordinal.checked_add(1)?)?;
        self.wire.get(
            self.census.literal_payload_offset.checked_add(start)?
                ..self.census.literal_payload_offset.checked_add(end)?,
        )
    }

    /// Iterate literals in exact source-priority order without rehashing.
    #[must_use]
    pub fn patterns(self) -> impl ExactSizeIterator<Item = &'wire [u8]> + 'wire {
        (0..self.census.patterns).map(move |index| {
            self.pattern(index)
                .expect("validated canonical offset table covers every source ordinal")
        })
    }

    fn offset(self, index: usize) -> Option<usize> {
        let byte = ORDERED_LITERAL_ARTIFACT_V1_HEADER_BYTES
            .checked_add(index.checked_mul(OFFSET_BYTES)?)?;
        read_u32_at(self.wire, byte).map(|value| usize::try_from(value).expect("u32 fits usize"))
    }

    /// Reconstruct the current sparse count plan under separate seam and plan limits.
    ///
    /// The temporary reference vector is allocated exactly once by this seam.
    /// Its observed capacity bytes are then charged once as external scratch by
    /// the sparse builder; they must not be added to that plan's peak again.
    pub fn build_sparse_count_plan(
        self,
        reconstruction_limits: OrderedLiteralCountPlanReconstructionLimits,
        plan_limits: SparseBuildLimits,
    ) -> Result<OrderedLiteralCountPlanBuild, OrderedLiteralCountPlanReconstructionError> {
        reconstruct_count_plan(self, reconstruction_limits, plan_limits)
    }
}

/// Owned, immutable canonical V1 wire.
///
/// This owner deliberately does not implement `Clone`: an implicit clone would
/// allocate without returning the exact owned accounting receipt. Call
/// [`Self::deserialize`] on [`Self::as_bytes`] for an explicitly limited and
/// receipted copy.
pub struct OrderedLiteralArtifactV1 {
    wire: Vec<u8>,
    census: OrderedLiteralArtifactCensus,
    accounting: OrderedLiteralArtifactOwnedAccounting,
}

impl fmt::Debug for OrderedLiteralArtifactV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OrderedLiteralArtifactV1")
            .field("census", &self.census)
            .field("accounting", &self.accounting)
            .finish_non_exhaustive()
    }
}

impl OrderedLiteralArtifactV1 {
    /// Build one canonical source-ordered artifact from borrowed literal bytes.
    pub fn build(
        patterns: &[&[u8]],
        limits: OrderedLiteralArtifactLimits,
    ) -> Result<Self, OrderedLiteralArtifactError> {
        let preflight = preflight_build(patterns, limits)?;
        check_owned_preallocation(preflight.wire_bytes, limits)?;
        let mut wire = reserve_wire(preflight.wire_bytes)?;
        check_owned_observed(wire.capacity(), limits)?;
        append_header(&mut wire, preflight.patterns, preflight.literal_bytes)?;
        append_u32(&mut wire, 0)?;
        let mut cumulative = 0_usize;
        for pattern in patterns {
            cumulative = cumulative.checked_add(pattern.len()).ok_or(
                OrderedLiteralArtifactError::ArithmeticOverflow {
                    computation: "builder cumulative literal offset",
                },
            )?;
            append_u32(
                &mut wire,
                u32::try_from(cumulative).map_err(|_| {
                    OrderedLiteralArtifactError::RepresentationLimit {
                        structure: "literal offset",
                        needed: u64::try_from(cumulative).unwrap_or(u64::MAX),
                    }
                })?,
            )?;
        }
        for pattern in patterns {
            append_bytes(&mut wire, pattern)?;
        }
        if wire.len() != preflight.wire_bytes {
            return Err(OrderedLiteralArtifactError::InternalInvariant {
                detail: "canonical builder did not initialize its exact wire extent",
            });
        }
        let view = OrderedLiteralArtifactV1View::from_wire(&wire, limits)?;
        if view.census.validation.work != preflight.validation_work {
            return Err(OrderedLiteralArtifactError::InternalInvariant {
                detail: "builder and borrowed validator disagree on work",
            });
        }
        let census = view.census;
        let accounting = OrderedLiteralArtifactOwnedAccounting {
            accounting_id: ORDERED_LITERAL_ARTIFACT_V1_OWNED_ACCOUNTING_ID,
            accounting_version: ORDERED_LITERAL_ARTIFACT_V1_OWNED_ACCOUNTING_VERSION,
            operation: OrderedLiteralArtifactOwnedOperation::Build,
            wire_logical_bytes: wire.len(),
            wire_capacity_bytes: wire.capacity(),
            retained_bytes: wire.capacity(),
            peak_bytes: wire.capacity(),
            work: preflight.work,
            allocation_attempts: 1,
            initialized_bytes: wire.len(),
            copied_bytes: preflight.literal_bytes,
        };
        if !accounting.closes(census) {
            return Err(OrderedLiteralArtifactError::InternalInvariant {
                detail: "owned builder accounting did not close",
            });
        }
        Ok(Self {
            wire,
            census,
            accounting,
        })
    }

    /// Validate and transactionally copy one exact canonical wire.
    pub fn deserialize(
        bytes: &[u8],
        limits: OrderedLiteralArtifactLimits,
    ) -> Result<Self, OrderedLiteralArtifactError> {
        let view = OrderedLiteralArtifactV1View::from_wire(bytes, limits)?;
        let work = view.census.validation.work.checked_add(bytes.len()).ok_or(
            OrderedLiteralArtifactError::ArithmeticOverflow {
                computation: "owned deserialize work",
            },
        )?;
        check_resource(OrderedLiteralArtifactResource::Work, work, limits.max_work)?;
        check_owned_preallocation(bytes.len(), limits)?;
        let mut wire = reserve_wire(bytes.len())?;
        check_owned_observed(wire.capacity(), limits)?;
        append_bytes(&mut wire, bytes)?;
        let census = view.census;
        let accounting = OrderedLiteralArtifactOwnedAccounting {
            accounting_id: ORDERED_LITERAL_ARTIFACT_V1_OWNED_ACCOUNTING_ID,
            accounting_version: ORDERED_LITERAL_ARTIFACT_V1_OWNED_ACCOUNTING_VERSION,
            operation: OrderedLiteralArtifactOwnedOperation::Deserialize,
            wire_logical_bytes: wire.len(),
            wire_capacity_bytes: wire.capacity(),
            retained_bytes: wire.capacity(),
            peak_bytes: wire.capacity(),
            work,
            allocation_attempts: 1,
            initialized_bytes: wire.len(),
            copied_bytes: wire.len(),
        };
        if !accounting.closes(census) {
            return Err(OrderedLiteralArtifactError::InternalInvariant {
                detail: "owned deserialize accounting did not close",
            });
        }
        Ok(Self {
            wire,
            census,
            accounting,
        })
    }

    #[must_use]
    pub fn as_view(&self) -> OrderedLiteralArtifactV1View<'_> {
        OrderedLiteralArtifactV1View {
            wire: &self.wire,
            census: self.census,
        }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire
    }

    #[must_use]
    pub const fn census(&self) -> OrderedLiteralArtifactCensus {
        self.census
    }

    #[must_use]
    pub const fn accounting(&self) -> OrderedLiteralArtifactOwnedAccounting {
        self.accounting
    }
}

/// Limits for the one temporary borrowed-reference vector used during restore.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderedLiteralCountPlanReconstructionLimits {
    pub max_work: usize,
    pub max_allocation_attempts: usize,
    pub max_source_reference_bytes: usize,
}

impl OrderedLiteralCountPlanReconstructionLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_work: usize::MAX,
            max_allocation_attempts: usize::MAX,
            max_source_reference_bytes: usize::MAX,
        }
    }
}

impl Default for OrderedLiteralCountPlanReconstructionLimits {
    fn default() -> Self {
        Self {
            max_work: 64 * 1024 * 1024,
            max_allocation_attempts: 1,
            max_source_reference_bytes: 16 * 1024 * 1024,
        }
    }
}

/// Receipt for the artifact-to-sparse-plan reconstruction seam.
///
/// Seam work excludes sparse automaton construction, which remains completely
/// covered by the accompanying kernel build-attempt receipt and its independent
/// limits. `prospective_work` admits reference copying plus the mandatory
/// success authentication before the reference allocation. `actual_work`
/// excludes authentication when the sparse builder fails before publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderedLiteralCountPlanReconstructionReceipt {
    accounting_id: &'static str,
    accounting_version: u32,
    limits: OrderedLiteralCountPlanReconstructionLimits,
    artifact_identity: [u8; 32],
    artifact_wire_bytes: usize,
    patterns: usize,
    literal_bytes: usize,
    source_reference_entries: usize,
    source_reference_capacity: usize,
    source_reference_bytes: usize,
    allocation_attempts: usize,
    reference_copy_work: usize,
    plan_authentication_work: usize,
    prospective_work: usize,
    actual_work: usize,
    plan_build_identity: SparseBuildAttemptIdentity,
    plan_cache_format_version: Option<u32>,
    plan_encoded_patterns_bytes: Option<usize>,
    published: bool,
}

impl OrderedLiteralCountPlanReconstructionReceipt {
    #[must_use]
    pub const fn accounting_id(self) -> &'static str {
        self.accounting_id
    }

    #[must_use]
    pub const fn accounting_version(self) -> u32 {
        self.accounting_version
    }

    #[must_use]
    pub const fn limits(self) -> OrderedLiteralCountPlanReconstructionLimits {
        self.limits
    }

    #[must_use]
    pub const fn artifact_identity(self) -> [u8; 32] {
        self.artifact_identity
    }

    #[must_use]
    pub const fn artifact_wire_bytes(self) -> usize {
        self.artifact_wire_bytes
    }

    #[must_use]
    pub const fn patterns(self) -> usize {
        self.patterns
    }

    #[must_use]
    pub const fn literal_bytes(self) -> usize {
        self.literal_bytes
    }

    #[must_use]
    pub const fn source_reference_entries(self) -> usize {
        self.source_reference_entries
    }

    #[must_use]
    pub const fn source_reference_capacity(self) -> usize {
        self.source_reference_capacity
    }

    #[must_use]
    pub const fn source_reference_bytes(self) -> usize {
        self.source_reference_bytes
    }

    #[must_use]
    pub const fn allocation_attempts(self) -> usize {
        self.allocation_attempts
    }

    #[must_use]
    pub const fn reference_copy_work(self) -> usize {
        self.reference_copy_work
    }

    #[must_use]
    pub const fn plan_authentication_work(self) -> usize {
        self.plan_authentication_work
    }

    #[must_use]
    pub const fn prospective_work(self) -> usize {
        self.prospective_work
    }

    #[must_use]
    pub const fn actual_work(self) -> usize {
        self.actual_work
    }

    #[must_use]
    pub const fn plan_build_identity(self) -> SparseBuildAttemptIdentity {
        self.plan_build_identity
    }

    #[must_use]
    pub const fn plan_cache_format_version(self) -> Option<u32> {
        self.plan_cache_format_version
    }

    #[must_use]
    pub const fn plan_encoded_patterns_bytes(self) -> Option<usize> {
        self.plan_encoded_patterns_bytes
    }

    #[must_use]
    pub const fn published(self) -> bool {
        self.published
    }

    /// Verify the self-contained reconstruction and build-identity equations.
    #[must_use]
    pub fn closes(self) -> bool {
        let table = self
            .patterns
            .checked_add(1)
            .and_then(|entries| entries.checked_mul(OFFSET_BYTES));
        let wire = table
            .and_then(|bytes| bytes.checked_add(ORDERED_LITERAL_ARTIFACT_V1_HEADER_BYTES))
            .and_then(|bytes| bytes.checked_add(self.literal_bytes));
        let reference_bytes = self
            .source_reference_capacity
            .checked_mul(size_of::<&[u8]>());
        let base_work = self
            .reference_copy_work
            .checked_add(self.allocation_attempts);
        let plan_authentication_work = reconstruction_plan_authentication_work(
            self.patterns,
            self.literal_bytes,
            self.artifact_wire_bytes,
        );
        let prospective_work = base_work
            .and_then(|work| plan_authentication_work.and_then(|auth| work.checked_add(auth)));
        let actual_work = base_work.and_then(|work| {
            if self.published {
                plan_authentication_work.and_then(|auth| work.checked_add(auth))
            } else {
                Some(work)
            }
        });
        let encoded_patterns_bytes = self
            .patterns
            .checked_add(1)
            .and_then(|prefixes| prefixes.checked_mul(size_of::<u64>()))
            .and_then(|bytes| bytes.checked_add(self.literal_bytes));
        let trie_states_upper_bound = self.literal_bytes.checked_add(1);
        let cache_fields_close = if self.published {
            self.plan_cache_format_version.is_some()
                && self.plan_encoded_patterns_bytes == encoded_patterns_bytes
        } else {
            self.plan_cache_format_version.is_none() && self.plan_encoded_patterns_bytes.is_none()
        };
        let published_admission_closes = !self.published
            || (self.patterns <= self.plan_build_identity.limits.max_patterns
                && self.literal_bytes <= self.plan_build_identity.limits.max_pattern_bytes
                && encoded_patterns_bytes.is_some_and(|bytes| {
                    bytes <= self.plan_build_identity.limits.max_identity_bytes
                })
                && trie_states_upper_bound.is_some_and(|states| {
                    states <= self.plan_build_identity.limits.max_trie_states
                })
                && self.literal_bytes <= self.plan_build_identity.limits.max_sparse_edges
                && self.source_reference_bytes
                    <= self.plan_build_identity.limits.max_scratch_bytes);
        self.accounting_id == ORDERED_LITERAL_ARTIFACT_V1_RECONSTRUCTION_ACCOUNTING_ID
            && self.accounting_version
                == ORDERED_LITERAL_ARTIFACT_V1_RECONSTRUCTION_ACCOUNTING_VERSION
            && self.patterns != 0
            && wire == Some(self.artifact_wire_bytes)
            && self.source_reference_entries == self.patterns
            && self.source_reference_capacity == self.source_reference_entries
            && reference_bytes == Some(self.source_reference_bytes)
            && self.allocation_attempts == 1
            && self.reference_copy_work == self.patterns
            && plan_authentication_work == Some(self.plan_authentication_work)
            && prospective_work == Some(self.prospective_work)
            && actual_work == Some(self.actual_work)
            && self.source_reference_bytes <= self.limits.max_source_reference_bytes
            && self.allocation_attempts <= self.limits.max_allocation_attempts
            && self.prospective_work <= self.limits.max_work
            && self.plan_build_identity.algorithm_id
                == SPARSE_ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID
            && self.plan_build_identity.plan_id == SPARSE_ORDERED_LITERAL_COUNT_PLAN_ID
            && self.plan_build_identity.operation == SparseOperation::Count
            && self.plan_build_identity.algorithm_version
                == SPARSE_ORDERED_LITERAL_AGGREGATE_BUILD_ATTEMPT_ALGORITHM_VERSION
            && self.plan_build_identity.accounting_version
                == SPARSE_ORDERED_LITERAL_AGGREGATE_BUILD_ATTEMPT_ACCOUNTING_VERSION
            && published_admission_closes
            && cache_fields_close
    }
}

/// Successful sparse reconstruction with both artifact and kernel receipts.
#[derive(Debug)]
pub struct OrderedLiteralCountPlanBuild {
    attempt: SparseOrderedLiteralCountBuildAttempt,
    reconstruction: OrderedLiteralCountPlanReconstructionReceipt,
    census: OrderedLiteralArtifactCensus,
}

impl OrderedLiteralCountPlanBuild {
    #[must_use]
    pub const fn plan(&self) -> &SparseOrderedLiteralCountPlan {
        self.attempt.plan()
    }

    #[must_use]
    pub const fn plan_build_receipt(&self) -> &SparseBuildAttemptReceipt {
        self.attempt.receipt()
    }

    #[must_use]
    pub const fn reconstruction_receipt(&self) -> OrderedLiteralCountPlanReconstructionReceipt {
        self.reconstruction
    }

    /// Reauthenticate the reconstructed plan language against the exact artifact identity.
    ///
    /// This repeats the allocation-free two-pass plan-language authentication
    /// performed before publication. The byte-visit portion has the exact
    /// abstract charge returned by
    /// [`OrderedLiteralCountPlanReconstructionReceipt::plan_authentication_work`];
    /// fixed-size receipt comparisons are outside that byte-visit ledger.
    #[must_use]
    pub fn closes(&self) -> bool {
        let plan = self.attempt.plan();
        let cache = plan.cache_identity();
        self.attempt.closes()
            && self.reconstruction.closes()
            && self.reconstruction.published
            && self.reconstruction.artifact_identity == self.census.artifact_identity
            && self.reconstruction.artifact_wire_bytes == self.census.wire_bytes
            && self.reconstruction.patterns == self.census.patterns
            && self.reconstruction.literal_bytes == self.census.literal_bytes
            && self.reconstruction.plan_build_identity == self.attempt.receipt().identity()
            && self.reconstruction.plan_cache_format_version == Some(cache.cache_format_version)
            && self.reconstruction.plan_encoded_patterns_bytes == Some(cache.encoded_patterns.len())
            && cache.algorithm_id == self.reconstruction.plan_build_identity.algorithm_id
            && cache.plan_id == self.reconstruction.plan_build_identity.plan_id
            && cache.operation == self.reconstruction.plan_build_identity.operation
            && plan.build_accounting().patterns == self.census.patterns
            && plan.build_accounting().pattern_bytes == self.census.literal_bytes
            && self.reconstruction.source_reference_bytes <= plan.build_accounting().scratch_bytes
            && hash_plan_as_artifact(plan, self.census) == Some(self.census.artifact_identity)
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        SparseOrderedLiteralCountPlan,
        SparseBuildAttemptReceipt,
        OrderedLiteralCountPlanReconstructionReceipt,
    ) {
        let (plan, build) = self.attempt.into_parts();
        (plan, build, self.reconstruction)
    }
}

/// Failure before a sparse count plan is published.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[allow(
    clippy::large_enum_variant,
    reason = "the sparse failure and its complete receipt remain inline so allocation failure can always be reported without another allocation"
)]
pub enum OrderedLiteralCountPlanReconstructionError {
    ResourceLimit {
        resource: OrderedLiteralArtifactResource,
        needed: usize,
        limit: usize,
    },
    AllocationFailed {
        entries: usize,
    },
    NonExactCapacity {
        structure: &'static str,
        requested: usize,
        actual: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    Sparse {
        source: SparseBuildAttemptError,
        receipt: OrderedLiteralCountPlanReconstructionReceipt,
    },
    InternalInvariant {
        detail: &'static str,
    },
}

impl fmt::Display for OrderedLiteralCountPlanReconstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "ordered-literal sparse reconstruction error: {self:?}"
        )
    }
}

impl std::error::Error for OrderedLiteralCountPlanReconstructionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sparse { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct BuildPreflight {
    patterns: usize,
    literal_bytes: usize,
    wire_bytes: usize,
    validation_work: usize,
    work: usize,
}

#[derive(Clone, Copy, Debug)]
struct ReconstructionPreflight {
    limits: OrderedLiteralCountPlanReconstructionLimits,
    reference_copy_work: usize,
    plan_authentication_work: usize,
    base_work: usize,
    prospective_work: usize,
}

fn preflight_build(
    patterns: &[&[u8]],
    limits: OrderedLiteralArtifactLimits,
) -> Result<BuildPreflight, OrderedLiteralArtifactError> {
    if patterns.is_empty() {
        return Err(OrderedLiteralArtifactError::EmptyPatternSet);
    }
    check_format_pattern_count(patterns.len())?;
    check_resource(
        OrderedLiteralArtifactResource::Patterns,
        patterns.len(),
        limits.max_patterns,
    )?;
    let (_, minimum_offset_table_bytes, _, minimum_wire_bytes) =
        canonical_layout(patterns.len(), 0)?;
    let minimum_validation_work = validation_work(minimum_wire_bytes, minimum_offset_table_bytes)?;
    let minimum_work = patterns
        .len()
        .checked_add(minimum_wire_bytes)
        .and_then(|value| value.checked_add(minimum_validation_work))
        .ok_or(OrderedLiteralArtifactError::ArithmeticOverflow {
            computation: "minimum builder work",
        })?;
    // Admit the complete count scan before visiting any caller-owned row.
    check_resource(
        OrderedLiteralArtifactResource::Work,
        minimum_work,
        limits.max_work,
    )?;
    let mut literal_bytes = 0_usize;
    for pattern in patterns {
        check_resource(
            OrderedLiteralArtifactResource::SingleLiteralBytes,
            pattern.len(),
            limits.max_single_literal_bytes,
        )?;
        literal_bytes = literal_bytes.checked_add(pattern.len()).ok_or(
            OrderedLiteralArtifactError::ArithmeticOverflow {
                computation: "builder literal bytes",
            },
        )?;
        check_resource(
            OrderedLiteralArtifactResource::LiteralBytes,
            literal_bytes,
            limits.max_literal_bytes,
        )?;
    }
    let (offset_entries, offset_table_bytes, payload_offset, wire_bytes) =
        canonical_layout(patterns.len(), literal_bytes)?;
    let _ = offset_entries;
    let _ = payload_offset;
    check_wire_limits(wire_bytes, limits)?;
    let validation_work = validation_work(wire_bytes, offset_table_bytes)?;
    let work = patterns
        .len()
        .checked_add(wire_bytes)
        .and_then(|value| value.checked_add(validation_work))
        .ok_or(OrderedLiteralArtifactError::ArithmeticOverflow {
            computation: "builder work",
        })?;
    check_resource(OrderedLiteralArtifactResource::Work, work, limits.max_work)?;
    Ok(BuildPreflight {
        patterns: patterns.len(),
        literal_bytes,
        wire_bytes,
        validation_work,
        work,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "fixed-header precedence, exact extent proof, resource admission, canonical offset scan, and census publication remain one auditable validation transaction"
)]
fn validate_wire(
    wire: &[u8],
    limits: OrderedLiteralArtifactLimits,
) -> Result<OrderedLiteralArtifactCensus, OrderedLiteralArtifactError> {
    check_outer_wire_extent(wire.len(), limits)?;
    if wire.get(HEADER_MAGIC_OFFSET..HEADER_VERSION_OFFSET)
        != Some(ORDERED_LITERAL_ARTIFACT_V1_MAGIC.as_slice())
    {
        return Err(OrderedLiteralArtifactError::InvalidMagic);
    }
    let version = read_u16(wire, HEADER_VERSION_OFFSET)?;
    if version != ORDERED_LITERAL_ARTIFACT_V1_VERSION {
        return Err(OrderedLiteralArtifactError::UnsupportedVersion { found: version });
    }
    let header_bytes = read_u16(wire, HEADER_BYTES_OFFSET)?;
    if usize::from(header_bytes) != ORDERED_LITERAL_ARTIFACT_V1_HEADER_BYTES {
        return Err(OrderedLiteralArtifactError::HeaderBytes {
            found: header_bytes,
        });
    }
    let flags = read_u32(wire, HEADER_FLAGS_OFFSET)?;
    if flags != FLAGS {
        return Err(OrderedLiteralArtifactError::UnsupportedFlags { found: flags });
    }
    let match_tag = wire[HEADER_MATCH_SEMANTICS_OFFSET];
    let iteration_tag = wire[HEADER_ITERATION_SEMANTICS_OFFSET];
    let boundary_tag = wire[HEADER_BOUNDARY_SEMANTICS_OFFSET];
    if match_tag != MATCH_SEMANTICS_TAG
        || iteration_tag != ITERATION_SEMANTICS_TAG
        || boundary_tag != BOUNDARY_SEMANTICS_TAG
    {
        return Err(OrderedLiteralArtifactError::UnsupportedSemantics {
            match_tag,
            iteration_tag,
            boundary_tag,
        });
    }
    let semantics_reserved = wire[HEADER_SEMANTICS_RESERVED_OFFSET];
    if semantics_reserved != 0 {
        return Err(OrderedLiteralArtifactError::ReservedNonzero {
            field: "semantics reserved byte",
            value: u64::from(semantics_reserved),
        });
    }
    let reserved = read_u64(wire, HEADER_RESERVED_OFFSET)?;
    if reserved != 0 {
        return Err(OrderedLiteralArtifactError::ReservedNonzero {
            field: "header reserved word",
            value: reserved,
        });
    }
    let declared_total = read_u64(wire, HEADER_TOTAL_BYTES_OFFSET)?;
    if declared_total != u64::try_from(wire.len()).unwrap_or(u64::MAX) {
        return Err(OrderedLiteralArtifactError::TotalBytesMismatch {
            declared: declared_total,
            actual: wire.len(),
        });
    }
    let patterns_u32 = read_u32(wire, HEADER_PATTERN_COUNT_OFFSET)?;
    if patterns_u32 == 0 {
        return Err(OrderedLiteralArtifactError::EmptyPatternSet);
    }
    let patterns = usize::try_from(patterns_u32).map_err(|_| {
        OrderedLiteralArtifactError::RepresentationLimit {
            structure: "pattern count",
            needed: u64::from(patterns_u32),
        }
    })?;
    check_format_pattern_count(patterns)?;
    check_resource(
        OrderedLiteralArtifactResource::Patterns,
        patterns,
        limits.max_patterns,
    )?;

    let (offset_entries, offset_table_bytes, payload_offset, _) = canonical_layout(patterns, 0)?;
    let declared_table = read_u64(wire, HEADER_OFFSET_TABLE_OFFSET)?;
    if declared_table != u64::try_from(ORDERED_LITERAL_ARTIFACT_V1_HEADER_BYTES).unwrap_or(u64::MAX)
    {
        return Err(OrderedLiteralArtifactError::ExtentMismatch {
            field: "offset table",
            expected: ORDERED_LITERAL_ARTIFACT_V1_HEADER_BYTES,
            actual: declared_table,
        });
    }
    let declared_payload = read_u64(wire, HEADER_LITERAL_PAYLOAD_OFFSET)?;
    if declared_payload != u64::try_from(payload_offset).unwrap_or(u64::MAX) {
        return Err(OrderedLiteralArtifactError::ExtentMismatch {
            field: "literal payload",
            expected: payload_offset,
            actual: declared_payload,
        });
    }
    let literal_bytes_u64 = read_u64(wire, HEADER_LITERAL_PAYLOAD_BYTES_OFFSET)?;
    let literal_bytes = usize::try_from(literal_bytes_u64).map_err(|_| {
        OrderedLiteralArtifactError::RepresentationLimit {
            structure: "literal payload bytes",
            needed: literal_bytes_u64,
        }
    })?;
    let expected_total = payload_offset.checked_add(literal_bytes).ok_or(
        OrderedLiteralArtifactError::ArithmeticOverflow {
            computation: "wire payload extent",
        },
    )?;
    if expected_total != wire.len() {
        return Err(OrderedLiteralArtifactError::ExtentMismatch {
            field: "complete wire",
            expected: wire.len(),
            actual: u64::try_from(expected_total).unwrap_or(u64::MAX),
        });
    }
    check_resource(
        OrderedLiteralArtifactResource::LiteralBytes,
        literal_bytes,
        limits.max_literal_bytes,
    )?;
    let work = validation_work(wire.len(), offset_table_bytes)?;
    check_resource(OrderedLiteralArtifactResource::Work, work, limits.max_work)?;

    let first = read_offset(wire, 0)?;
    if first != 0 {
        return Err(OrderedLiteralArtifactError::FirstOffsetNonzero { found: first });
    }
    let mut previous = first;
    let mut max_pattern_bytes = 0_usize;
    let mut min_nonempty_pattern_bytes = None::<usize>;
    let mut has_empty_pattern = false;
    for index in 1..offset_entries {
        let current = read_offset(wire, index)?;
        if current < previous {
            return Err(OrderedLiteralArtifactError::OffsetDecreases {
                index,
                previous,
                current,
            });
        }
        if usize::try_from(current).unwrap_or(usize::MAX) > literal_bytes {
            return Err(OrderedLiteralArtifactError::OffsetOutOfBounds {
                index,
                offset: current,
                literal_bytes,
            });
        }
        let length = usize::try_from(
            current
                .checked_sub(previous)
                .expect("canonical offsets are nondecreasing"),
        )
        .expect("u32 difference fits usize");
        check_resource(
            OrderedLiteralArtifactResource::SingleLiteralBytes,
            length,
            limits.max_single_literal_bytes,
        )?;
        max_pattern_bytes = max_pattern_bytes.max(length);
        if length == 0 {
            has_empty_pattern = true;
        } else {
            min_nonempty_pattern_bytes =
                Some(min_nonempty_pattern_bytes.map_or(length, |minimum| minimum.min(length)));
        }
        previous = current;
    }
    if usize::try_from(previous).unwrap_or(usize::MAX) != literal_bytes {
        return Err(OrderedLiteralArtifactError::FinalOffsetMismatch {
            expected: literal_bytes,
            actual: previous,
        });
    }
    let hash_input_bytes = ORDERED_LITERAL_ARTIFACT_V1_IDENTITY_DOMAIN
        .len()
        .checked_add(wire.len())
        .ok_or(OrderedLiteralArtifactError::ArithmeticOverflow {
            computation: "validation hash input bytes",
        })?;
    let validation = OrderedLiteralArtifactValidationAccounting {
        accounting_id: ORDERED_LITERAL_ARTIFACT_V1_VALIDATION_ACCOUNTING_ID,
        accounting_version: ORDERED_LITERAL_ARTIFACT_V1_VALIDATION_ACCOUNTING_VERSION,
        input_bytes: wire.len(),
        header_bytes: ORDERED_LITERAL_ARTIFACT_V1_HEADER_BYTES,
        offset_entries,
        offset_table_bytes,
        hash_input_bytes,
        work,
    };
    if !validation.closes() {
        return Err(OrderedLiteralArtifactError::InternalInvariant {
            detail: "borrowed validation accounting did not close",
        });
    }
    Ok(OrderedLiteralArtifactCensus {
        artifact_identity: artifact_identity(wire),
        wire_bytes: wire.len(),
        patterns,
        offset_entries,
        offset_table_bytes,
        literal_payload_offset: payload_offset,
        literal_bytes,
        max_pattern_bytes,
        min_nonempty_pattern_bytes,
        has_empty_pattern,
        validation,
    })
}

fn check_outer_wire_extent(
    wire_bytes: usize,
    limits: OrderedLiteralArtifactLimits,
) -> Result<(), OrderedLiteralArtifactError> {
    // This fixed cap deliberately precedes count-plus-one and table arithmetic.
    if wire_bytes > MAX_ORDERED_LITERAL_ARTIFACT_V1_BYTES {
        return Err(OrderedLiteralArtifactError::FormatWireLimit {
            needed: wire_bytes,
            limit: MAX_ORDERED_LITERAL_ARTIFACT_V1_BYTES,
        });
    }
    if wire_bytes < ORDERED_LITERAL_ARTIFACT_V1_HEADER_BYTES {
        return Err(OrderedLiteralArtifactError::TooShort {
            needed: ORDERED_LITERAL_ARTIFACT_V1_HEADER_BYTES,
            actual: wire_bytes,
        });
    }
    check_resource(
        OrderedLiteralArtifactResource::WireBytes,
        wire_bytes,
        limits.max_wire_bytes,
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "prospective seam admission, exact reference ownership, sparse build receipt binding, and authenticated publication remain one transaction"
)]
fn reconstruct_count_plan(
    view: OrderedLiteralArtifactV1View<'_>,
    limits: OrderedLiteralCountPlanReconstructionLimits,
    plan_limits: SparseBuildLimits,
) -> Result<OrderedLiteralCountPlanBuild, OrderedLiteralCountPlanReconstructionError> {
    let entries = view.census.patterns;
    let requested_reference_bytes = entries.checked_mul(size_of::<&[u8]>()).ok_or(
        OrderedLiteralCountPlanReconstructionError::ArithmeticOverflow {
            computation: "source reference vector bytes",
        },
    )?;
    check_reconstruction_resource(
        OrderedLiteralArtifactResource::SourceReferenceBytes,
        requested_reference_bytes,
        limits.max_source_reference_bytes,
    )?;
    check_reconstruction_resource(
        OrderedLiteralArtifactResource::AllocationAttempts,
        1,
        limits.max_allocation_attempts,
    )?;
    let reference_copy_work = entries;
    let base_work = reference_copy_work.checked_add(1).ok_or(
        OrderedLiteralCountPlanReconstructionError::ArithmeticOverflow {
            computation: "reconstruction base work",
        },
    )?;
    let plan_authentication_work = reconstruction_plan_authentication_work(
        view.census.patterns,
        view.census.literal_bytes,
        view.census.wire_bytes,
    )
    .ok_or(
        OrderedLiteralCountPlanReconstructionError::ArithmeticOverflow {
            computation: "reconstruction plan authentication work",
        },
    )?;
    let prospective_work = base_work.checked_add(plan_authentication_work).ok_or(
        OrderedLiteralCountPlanReconstructionError::ArithmeticOverflow {
            computation: "reconstruction prospective work",
        },
    )?;
    check_reconstruction_resource(
        OrderedLiteralArtifactResource::Work,
        prospective_work,
        limits.max_work,
    )?;
    let preflight = ReconstructionPreflight {
        limits,
        reference_copy_work,
        plan_authentication_work,
        base_work,
        prospective_work,
    };
    let mut references = Vec::<&[u8]>::new();
    references
        .try_reserve_exact(entries)
        .map_err(|_| OrderedLiteralCountPlanReconstructionError::AllocationFailed { entries })?;
    if references.capacity() != entries {
        return Err(
            OrderedLiteralCountPlanReconstructionError::NonExactCapacity {
                structure: "source reference vector",
                requested: entries,
                actual: references.capacity(),
            },
        );
    }
    let source_reference_bytes = references
        .capacity()
        .checked_mul(size_of::<&[u8]>())
        .ok_or(
            OrderedLiteralCountPlanReconstructionError::ArithmeticOverflow {
                computation: "observed source reference vector bytes",
            },
        )?;
    check_reconstruction_resource(
        OrderedLiteralArtifactResource::SourceReferenceBytes,
        source_reference_bytes,
        limits.max_source_reference_bytes,
    )?;
    references.extend(view.patterns());
    if references.capacity() != entries {
        return Err(
            OrderedLiteralCountPlanReconstructionError::NonExactCapacity {
                structure: "populated source reference vector",
                requested: entries,
                actual: references.capacity(),
            },
        );
    }
    if references.len() != entries {
        return Err(
            OrderedLiteralCountPlanReconstructionError::InternalInvariant {
                detail: "reconstruction did not populate every source ordinal",
            },
        );
    }
    let source_reference_capacity = references.capacity();
    match SparseOrderedLiteralCountPlan::build_attempt(references, plan_limits) {
        Ok(attempt) => {
            let cache = attempt.plan().cache_identity();
            let receipt = reconstruction_receipt(
                view.census,
                source_reference_capacity,
                source_reference_bytes,
                preflight,
                attempt.receipt().identity(),
                Some((cache.cache_format_version, cache.encoded_patterns.len())),
            );
            let result = OrderedLiteralCountPlanBuild {
                attempt,
                reconstruction: receipt,
                census: view.census,
            };
            if !result.closes() {
                return Err(
                    OrderedLiteralCountPlanReconstructionError::InternalInvariant {
                        detail: "published sparse reconstruction did not close",
                    },
                );
            }
            Ok(result)
        }
        Err(source) => {
            let receipt = reconstruction_receipt(
                view.census,
                source_reference_capacity,
                source_reference_bytes,
                preflight,
                source.receipt().identity(),
                None,
            );
            if !receipt.closes() || !source.closes() {
                return Err(
                    OrderedLiteralCountPlanReconstructionError::InternalInvariant {
                        detail: "failed sparse reconstruction receipt did not close",
                    },
                );
            }
            Err(OrderedLiteralCountPlanReconstructionError::Sparse { source, receipt })
        }
    }
}

fn reconstruction_receipt(
    census: OrderedLiteralArtifactCensus,
    source_reference_capacity: usize,
    source_reference_bytes: usize,
    preflight: ReconstructionPreflight,
    plan_build_identity: SparseBuildAttemptIdentity,
    cache: Option<(u32, usize)>,
) -> OrderedLiteralCountPlanReconstructionReceipt {
    OrderedLiteralCountPlanReconstructionReceipt {
        accounting_id: ORDERED_LITERAL_ARTIFACT_V1_RECONSTRUCTION_ACCOUNTING_ID,
        accounting_version: ORDERED_LITERAL_ARTIFACT_V1_RECONSTRUCTION_ACCOUNTING_VERSION,
        limits: preflight.limits,
        artifact_identity: census.artifact_identity,
        artifact_wire_bytes: census.wire_bytes,
        patterns: census.patterns,
        literal_bytes: census.literal_bytes,
        source_reference_entries: census.patterns,
        source_reference_capacity,
        source_reference_bytes,
        allocation_attempts: 1,
        reference_copy_work: preflight.reference_copy_work,
        plan_authentication_work: preflight.plan_authentication_work,
        prospective_work: preflight.prospective_work,
        actual_work: if cache.is_some() {
            preflight.prospective_work
        } else {
            preflight.base_work
        },
        plan_build_identity,
        plan_cache_format_version: cache.map(|(version, _)| version),
        plan_encoded_patterns_bytes: cache.map(|(_, bytes)| bytes),
        published: cache.is_some(),
    }
}

/// Exact abstract work of one allocation-free plan-language authentication.
///
/// The charge is one unit per initialized canonical-header byte, cache count
/// prefix byte, length-prefix byte in each of two cache passes, first-pass
/// literal extent byte, and domain-separated artifact hash byte.
fn reconstruction_plan_authentication_work(
    patterns: usize,
    literal_bytes: usize,
    artifact_wire_bytes: usize,
) -> Option<usize> {
    let length_prefix_bytes = patterns.checked_mul(size_of::<u64>())?.checked_mul(2)?;
    let artifact_hash_bytes = ORDERED_LITERAL_ARTIFACT_V1_IDENTITY_DOMAIN
        .len()
        .checked_add(artifact_wire_bytes)?;
    ORDERED_LITERAL_ARTIFACT_V1_HEADER_BYTES
        .checked_add(size_of::<u64>())?
        .checked_add(length_prefix_bytes)?
        .checked_add(literal_bytes)?
        .checked_add(artifact_hash_bytes)
}

fn hash_plan_as_artifact(
    plan: &SparseOrderedLiteralCountPlan,
    census: OrderedLiteralArtifactCensus,
) -> Option<[u8; 32]> {
    let encoded = plan.cache_identity().encoded_patterns;
    let encoded_count = read_u64_at(encoded, 0)?;
    if usize::try_from(encoded_count).ok()? != census.patterns {
        return None;
    }
    let header = canonical_header(census.patterns, census.literal_bytes).ok()?;
    let mut digest = Sha256::new();
    digest.update(ORDERED_LITERAL_ARTIFACT_V1_IDENTITY_DOMAIN);
    digest.update(header);
    digest.update(0_u32.to_le_bytes());

    let mut cursor = size_of::<u64>();
    let mut cumulative = 0_usize;
    for _ in 0..census.patterns {
        let length_u64 = read_u64_at(encoded, cursor)?;
        cursor = cursor.checked_add(size_of::<u64>())?;
        let length = usize::try_from(length_u64).ok()?;
        let end = cursor.checked_add(length)?;
        encoded.get(cursor..end)?;
        cumulative = cumulative.checked_add(length)?;
        digest.update(u32::try_from(cumulative).ok()?.to_le_bytes());
        cursor = end;
    }
    if cursor != encoded.len() || cumulative != census.literal_bytes {
        return None;
    }
    cursor = size_of::<u64>();
    for _ in 0..census.patterns {
        let length = usize::try_from(read_u64_at(encoded, cursor)?).ok()?;
        cursor = cursor.checked_add(size_of::<u64>())?;
        let end = cursor.checked_add(length)?;
        digest.update(encoded.get(cursor..end)?);
        cursor = end;
    }
    (cursor == encoded.len()).then(|| digest.finalize().into())
}

fn canonical_layout(
    patterns: usize,
    literal_bytes: usize,
) -> Result<(usize, usize, usize, usize), OrderedLiteralArtifactError> {
    check_format_pattern_count(patterns)?;
    let offset_entries =
        patterns
            .checked_add(1)
            .ok_or(OrderedLiteralArtifactError::ArithmeticOverflow {
                computation: "offset entry count",
            })?;
    let offset_table_bytes = offset_entries.checked_mul(OFFSET_BYTES).ok_or(
        OrderedLiteralArtifactError::ArithmeticOverflow {
            computation: "offset table bytes",
        },
    )?;
    let payload_offset = ORDERED_LITERAL_ARTIFACT_V1_HEADER_BYTES
        .checked_add(offset_table_bytes)
        .ok_or(OrderedLiteralArtifactError::ArithmeticOverflow {
            computation: "literal payload offset",
        })?;
    let wire_bytes = payload_offset.checked_add(literal_bytes).ok_or(
        OrderedLiteralArtifactError::ArithmeticOverflow {
            computation: "complete wire bytes",
        },
    )?;
    Ok((
        offset_entries,
        offset_table_bytes,
        payload_offset,
        wire_bytes,
    ))
}

fn check_format_pattern_count(patterns: usize) -> Result<(), OrderedLiteralArtifactError> {
    if patterns > MAX_FORMAT_PATTERNS {
        return Err(OrderedLiteralArtifactError::RepresentationLimit {
            structure: "V1 offset table pattern count",
            needed: u64::try_from(patterns).unwrap_or(u64::MAX),
        });
    }
    Ok(())
}

fn validation_work(
    wire_bytes: usize,
    offset_table_bytes: usize,
) -> Result<usize, OrderedLiteralArtifactError> {
    ORDERED_LITERAL_ARTIFACT_V1_HEADER_BYTES
        .checked_add(offset_table_bytes)
        .and_then(|value| value.checked_add(ORDERED_LITERAL_ARTIFACT_V1_IDENTITY_DOMAIN.len()))
        .and_then(|value| value.checked_add(wire_bytes))
        .ok_or(OrderedLiteralArtifactError::ArithmeticOverflow {
            computation: "borrowed validation work",
        })
}

fn check_wire_limits(
    wire_bytes: usize,
    limits: OrderedLiteralArtifactLimits,
) -> Result<(), OrderedLiteralArtifactError> {
    if wire_bytes > MAX_ORDERED_LITERAL_ARTIFACT_V1_BYTES {
        return Err(OrderedLiteralArtifactError::FormatWireLimit {
            needed: wire_bytes,
            limit: MAX_ORDERED_LITERAL_ARTIFACT_V1_BYTES,
        });
    }
    check_resource(
        OrderedLiteralArtifactResource::WireBytes,
        wire_bytes,
        limits.max_wire_bytes,
    )
}

fn check_owned_preallocation(
    wire_bytes: usize,
    limits: OrderedLiteralArtifactLimits,
) -> Result<(), OrderedLiteralArtifactError> {
    check_resource(
        OrderedLiteralArtifactResource::AllocationAttempts,
        1,
        limits.max_allocation_attempts,
    )?;
    check_resource(
        OrderedLiteralArtifactResource::RetainedBytes,
        wire_bytes,
        limits.max_retained_bytes,
    )?;
    check_resource(
        OrderedLiteralArtifactResource::PeakBytes,
        wire_bytes,
        limits.max_peak_bytes,
    )
}

fn check_owned_observed(
    capacity: usize,
    limits: OrderedLiteralArtifactLimits,
) -> Result<(), OrderedLiteralArtifactError> {
    check_resource(
        OrderedLiteralArtifactResource::RetainedBytes,
        capacity,
        limits.max_retained_bytes,
    )?;
    check_resource(
        OrderedLiteralArtifactResource::PeakBytes,
        capacity,
        limits.max_peak_bytes,
    )
}

fn check_resource(
    resource: OrderedLiteralArtifactResource,
    needed: usize,
    limit: usize,
) -> Result<(), OrderedLiteralArtifactError> {
    if needed > limit {
        return Err(OrderedLiteralArtifactError::ResourceLimit {
            resource,
            needed,
            limit,
        });
    }
    Ok(())
}

fn check_reconstruction_resource(
    resource: OrderedLiteralArtifactResource,
    needed: usize,
    limit: usize,
) -> Result<(), OrderedLiteralCountPlanReconstructionError> {
    if needed > limit {
        return Err(OrderedLiteralCountPlanReconstructionError::ResourceLimit {
            resource,
            needed,
            limit,
        });
    }
    Ok(())
}

fn reserve_wire(bytes: usize) -> Result<Vec<u8>, OrderedLiteralArtifactError> {
    let mut wire = Vec::new();
    wire.try_reserve_exact(bytes)
        .map_err(|_| OrderedLiteralArtifactError::AllocationFailed {
            structure: "owned canonical wire",
            bytes,
        })?;
    if wire.capacity() != bytes {
        return Err(OrderedLiteralArtifactError::NonExactCapacity {
            structure: "owned canonical wire",
            requested: bytes,
            actual: wire.capacity(),
        });
    }
    Ok(wire)
}

fn append_header(
    wire: &mut Vec<u8>,
    patterns: usize,
    literal_bytes: usize,
) -> Result<(), OrderedLiteralArtifactError> {
    append_bytes(wire, &canonical_header(patterns, literal_bytes)?)
}

fn canonical_header(
    patterns: usize,
    literal_bytes: usize,
) -> Result<[u8; ORDERED_LITERAL_ARTIFACT_V1_HEADER_BYTES], OrderedLiteralArtifactError> {
    let (_, _, payload_offset, wire_bytes) = canonical_layout(patterns, literal_bytes)?;
    let mut header = [0_u8; ORDERED_LITERAL_ARTIFACT_V1_HEADER_BYTES];
    header[HEADER_MAGIC_OFFSET..HEADER_VERSION_OFFSET]
        .copy_from_slice(&ORDERED_LITERAL_ARTIFACT_V1_MAGIC);
    write_u16_at(
        &mut header,
        HEADER_VERSION_OFFSET,
        ORDERED_LITERAL_ARTIFACT_V1_VERSION,
    );
    write_u16_at(
        &mut header,
        HEADER_BYTES_OFFSET,
        u16::try_from(ORDERED_LITERAL_ARTIFACT_V1_HEADER_BYTES).map_err(|_| {
            OrderedLiteralArtifactError::InternalInvariant {
                detail: "fixed header bytes fit u16",
            }
        })?,
    );
    write_u32_at(&mut header, HEADER_FLAGS_OFFSET, FLAGS);
    write_u64_at(
        &mut header,
        HEADER_TOTAL_BYTES_OFFSET,
        u64::try_from(wire_bytes).map_err(|_| {
            OrderedLiteralArtifactError::RepresentationLimit {
                structure: "complete wire bytes",
                needed: u64::MAX,
            }
        })?,
    );
    write_u32_at(
        &mut header,
        HEADER_PATTERN_COUNT_OFFSET,
        u32::try_from(patterns).map_err(|_| OrderedLiteralArtifactError::RepresentationLimit {
            structure: "pattern count",
            needed: u64::try_from(patterns).unwrap_or(u64::MAX),
        })?,
    );
    header[HEADER_MATCH_SEMANTICS_OFFSET] = MATCH_SEMANTICS_TAG;
    header[HEADER_ITERATION_SEMANTICS_OFFSET] = ITERATION_SEMANTICS_TAG;
    header[HEADER_BOUNDARY_SEMANTICS_OFFSET] = BOUNDARY_SEMANTICS_TAG;
    write_u64_at(
        &mut header,
        HEADER_OFFSET_TABLE_OFFSET,
        u64::try_from(ORDERED_LITERAL_ARTIFACT_V1_HEADER_BYTES).map_err(|_| {
            OrderedLiteralArtifactError::InternalInvariant {
                detail: "fixed header bytes fit u64",
            }
        })?,
    );
    write_u64_at(
        &mut header,
        HEADER_LITERAL_PAYLOAD_OFFSET,
        u64::try_from(payload_offset).map_err(|_| {
            OrderedLiteralArtifactError::RepresentationLimit {
                structure: "literal payload offset",
                needed: u64::MAX,
            }
        })?,
    );
    write_u64_at(
        &mut header,
        HEADER_LITERAL_PAYLOAD_BYTES_OFFSET,
        u64::try_from(literal_bytes).map_err(|_| {
            OrderedLiteralArtifactError::RepresentationLimit {
                structure: "literal payload bytes",
                needed: u64::MAX,
            }
        })?,
    );
    Ok(header)
}

fn append_u32(wire: &mut Vec<u8>, value: u32) -> Result<(), OrderedLiteralArtifactError> {
    append_bytes(wire, &value.to_le_bytes())
}

fn append_bytes(wire: &mut Vec<u8>, bytes: &[u8]) -> Result<(), OrderedLiteralArtifactError> {
    let needed = wire.len().checked_add(bytes.len()).ok_or(
        OrderedLiteralArtifactError::ArithmeticOverflow {
            computation: "owned wire append",
        },
    )?;
    if needed > wire.capacity() {
        return Err(OrderedLiteralArtifactError::InternalInvariant {
            detail: "owned wire append escaped its exact reservation",
        });
    }
    wire.extend_from_slice(bytes);
    Ok(())
}

fn artifact_identity(wire: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(ORDERED_LITERAL_ARTIFACT_V1_IDENTITY_DOMAIN);
    digest.update(wire);
    digest.finalize().into()
}

fn read_offset(wire: &[u8], index: usize) -> Result<u32, OrderedLiteralArtifactError> {
    let offset = ORDERED_LITERAL_ARTIFACT_V1_HEADER_BYTES
        .checked_add(index.checked_mul(OFFSET_BYTES).ok_or(
            OrderedLiteralArtifactError::ArithmeticOverflow {
                computation: "offset table index bytes",
            },
        )?)
        .ok_or(OrderedLiteralArtifactError::ArithmeticOverflow {
            computation: "offset table entry address",
        })?;
    read_u32(wire, offset)
}

fn read_u16(wire: &[u8], offset: usize) -> Result<u16, OrderedLiteralArtifactError> {
    let end = offset.checked_add(size_of::<u16>()).ok_or(
        OrderedLiteralArtifactError::ArithmeticOverflow {
            computation: "u16 field extent",
        },
    )?;
    let bytes = wire
        .get(offset..end)
        .ok_or(OrderedLiteralArtifactError::TooShort {
            needed: end,
            actual: wire.len(),
        })?;
    Ok(u16::from_le_bytes(
        bytes
            .try_into()
            .expect("fixed-width u16 slice has exact length"),
    ))
}

fn read_u32(wire: &[u8], offset: usize) -> Result<u32, OrderedLiteralArtifactError> {
    let end = offset.checked_add(size_of::<u32>()).ok_or(
        OrderedLiteralArtifactError::ArithmeticOverflow {
            computation: "u32 field extent",
        },
    )?;
    read_u32_at(wire, offset).ok_or(OrderedLiteralArtifactError::TooShort {
        needed: end,
        actual: wire.len(),
    })
}

fn read_u64(wire: &[u8], offset: usize) -> Result<u64, OrderedLiteralArtifactError> {
    let end = offset.checked_add(size_of::<u64>()).ok_or(
        OrderedLiteralArtifactError::ArithmeticOverflow {
            computation: "u64 field extent",
        },
    )?;
    read_u64_at(wire, offset).ok_or(OrderedLiteralArtifactError::TooShort {
        needed: end,
        actual: wire.len(),
    })
}

fn read_u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes
            .get(offset..offset.checked_add(size_of::<u32>())?)?
            .try_into()
            .ok()?,
    ))
}

fn read_u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes
            .get(offset..offset.checked_add(size_of::<u64>())?)?
            .try_into()
            .ok()?,
    ))
}

fn write_u16_at(bytes: &mut [u8], offset: usize, value: u16) {
    let end = offset
        .checked_add(size_of::<u16>())
        .expect("fixed-width u16 write extent fits usize");
    bytes[offset..end].copy_from_slice(&value.to_le_bytes());
}

fn write_u32_at(bytes: &mut [u8], offset: usize, value: u32) {
    let end = offset
        .checked_add(size_of::<u32>())
        .expect("fixed-width u32 write extent fits usize");
    bytes[offset..end].copy_from_slice(&value.to_le_bytes());
}

fn write_u64_at(bytes: &mut [u8], offset: usize, value: u64) {
    let end = offset
        .checked_add(size_of::<u64>())
        .expect("fixed-width u64 write extent fits usize");
    bytes[offset..end].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use fre_kernels::{
        SparseOrderedLiteralAggregateBuildError as SparseBuildError,
        SparseOrderedLiteralAggregateReduceLimits as SparseReduceLimits,
        SparseOrderedLiteralTraceWorkspaceLimits as SparseTraceWorkspaceLimits,
    };

    const GOLDEN_WIRE: [u8; 84] = [
        0x46, 0x52, 0x45, 0x4c, 0x54, 0x4d, 0x31, 0x00, 0x01, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x01,
        0x01, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
        0x00, 0x04, 0x00, 0x00, 0x00, 0x61, 0x62, 0x00, 0xff,
    ];
    const GOLDEN_IDENTITY: [u8; 32] = [
        0xdf, 0xd6, 0x5e, 0xbe, 0x7b, 0x5e, 0x27, 0xd0, 0x36, 0xae, 0x51, 0xc4, 0x2a, 0x45, 0xf0,
        0xdf, 0x42, 0xb7, 0x4a, 0x32, 0xed, 0x94, 0xa1, 0x46, 0xc7, 0xd7, 0xf0, 0xc1, 0x4c, 0x21,
        0xc9, 0xf5,
    ];

    fn golden_patterns() -> [&'static [u8]; 3] {
        [b"", b"ab", b"\x00\xff"]
    }

    fn golden_artifact() -> OrderedLiteralArtifactV1 {
        OrderedLiteralArtifactV1::build(
            &golden_patterns(),
            OrderedLiteralArtifactLimits::unlimited(),
        )
        .expect("build canonical golden artifact")
    }

    fn assert_wire_error(wire: &[u8], expected: OrderedLiteralArtifactError) {
        assert_eq!(
            OrderedLiteralArtifactV1View::from_wire(
                wire,
                OrderedLiteralArtifactLimits::unlimited(),
            )
            .expect_err("corrupt wire must fail"),
            expected,
        );
    }

    #[test]
    fn exact_v1_golden_wire_identity_semantics_and_accounting_close() {
        let artifact = golden_artifact();
        assert_eq!(artifact.as_bytes(), GOLDEN_WIRE);
        let census = artifact.census();
        assert_eq!(census.format_id(), ORDERED_LITERAL_ARTIFACT_V1_FORMAT_ID);
        assert_eq!(
            census.semantics(),
            OrderedLiteralArtifactSemantics::RUST_BYTES_UNICODE_OFF
        );
        assert_eq!(census.artifact_identity(), GOLDEN_IDENTITY);
        assert_eq!(census.wire_bytes(), GOLDEN_WIRE.len());
        assert_eq!(census.patterns(), 3);
        assert_eq!(census.offset_entries(), 4);
        assert_eq!(census.offset_table_bytes(), 16);
        assert_eq!(census.literal_payload_offset(), 80);
        assert_eq!(census.literal_bytes(), 4);
        assert_eq!(census.max_pattern_bytes(), 2);
        assert_eq!(census.min_nonempty_pattern_bytes(), Some(2));
        assert!(census.has_empty_pattern());
        assert!(census.authenticates_wire(&GOLDEN_WIRE));

        let validation = census.validation_accounting();
        assert!(validation.closes());
        assert_eq!(
            validation.accounting_id,
            ORDERED_LITERAL_ARTIFACT_V1_VALIDATION_ACCOUNTING_ID,
        );
        assert_eq!(validation.hash_input_bytes, 27 + GOLDEN_WIRE.len());
        assert_eq!(validation.work, 64 + 16 + 27 + GOLDEN_WIRE.len());

        let accounting = artifact.accounting();
        assert!(accounting.closes(census));
        assert_eq!(
            accounting.operation,
            OrderedLiteralArtifactOwnedOperation::Build
        );
        assert_eq!(accounting.wire_capacity_bytes, GOLDEN_WIRE.len());
        assert_eq!(accounting.initialized_bytes, GOLDEN_WIRE.len());
        assert_eq!(accounting.copied_bytes, 4);
        assert_eq!(accounting.work, 3 + GOLDEN_WIRE.len() + validation.work);

        let view = artifact.as_view();
        assert_eq!(view.pattern(0), Some(b"".as_slice()));
        assert_eq!(view.pattern(1), Some(b"ab".as_slice()));
        assert_eq!(view.pattern(2), Some(b"\x00\xff".as_slice()));
        assert_eq!(view.pattern(3), None);
        assert!(view.patterns().eq(golden_patterns()));

        let copied = OrderedLiteralArtifactV1::deserialize(
            &GOLDEN_WIRE,
            OrderedLiteralArtifactLimits::unlimited(),
        )
        .expect("deserialize golden artifact");
        assert_eq!(copied.as_bytes(), GOLDEN_WIRE);
        assert_eq!(copied.census(), census);
        assert_eq!(
            copied.accounting().operation,
            OrderedLiteralArtifactOwnedOperation::Deserialize,
        );
        assert_eq!(copied.accounting().copied_bytes, GOLDEN_WIRE.len());
        assert!(copied.accounting().closes(census));

        let mut changed = GOLDEN_WIRE;
        changed[83] ^= 1;
        assert!(!census.authenticates_wire(&changed));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one corruption matrix pins the fixed parser's exact field precedence"
    )]
    fn strict_reader_rejects_every_header_extent_and_offset_corruption() {
        assert_wire_error(
            &GOLDEN_WIRE[..63],
            OrderedLiteralArtifactError::TooShort {
                needed: 64,
                actual: 63,
            },
        );
        assert_eq!(
            check_outer_wire_extent(
                MAX_ORDERED_LITERAL_ARTIFACT_V1_BYTES + 1,
                OrderedLiteralArtifactLimits::unlimited(),
            ),
            Err(OrderedLiteralArtifactError::FormatWireLimit {
                needed: MAX_ORDERED_LITERAL_ARTIFACT_V1_BYTES + 1,
                limit: MAX_ORDERED_LITERAL_ARTIFACT_V1_BYTES,
            }),
        );

        let mut wire = GOLDEN_WIRE;
        wire[0] ^= 1;
        assert_wire_error(&wire, OrderedLiteralArtifactError::InvalidMagic);

        let mut wire = GOLDEN_WIRE;
        write_u16_at(&mut wire, HEADER_VERSION_OFFSET, 2);
        assert_wire_error(
            &wire,
            OrderedLiteralArtifactError::UnsupportedVersion { found: 2 },
        );

        let mut wire = GOLDEN_WIRE;
        write_u16_at(&mut wire, HEADER_BYTES_OFFSET, 63);
        assert_wire_error(
            &wire,
            OrderedLiteralArtifactError::HeaderBytes { found: 63 },
        );

        let mut wire = GOLDEN_WIRE;
        write_u32_at(&mut wire, HEADER_FLAGS_OFFSET, 1);
        assert_wire_error(
            &wire,
            OrderedLiteralArtifactError::UnsupportedFlags { found: 1 },
        );

        let mut wire = GOLDEN_WIRE;
        wire[HEADER_MATCH_SEMANTICS_OFFSET] = 2;
        assert_wire_error(
            &wire,
            OrderedLiteralArtifactError::UnsupportedSemantics {
                match_tag: 2,
                iteration_tag: 1,
                boundary_tag: 1,
            },
        );

        let mut wire = GOLDEN_WIRE;
        wire[HEADER_ITERATION_SEMANTICS_OFFSET] = 2;
        assert_wire_error(
            &wire,
            OrderedLiteralArtifactError::UnsupportedSemantics {
                match_tag: 1,
                iteration_tag: 2,
                boundary_tag: 1,
            },
        );

        let mut wire = GOLDEN_WIRE;
        wire[HEADER_BOUNDARY_SEMANTICS_OFFSET] = 2;
        assert_wire_error(
            &wire,
            OrderedLiteralArtifactError::UnsupportedSemantics {
                match_tag: 1,
                iteration_tag: 1,
                boundary_tag: 2,
            },
        );

        let mut wire = GOLDEN_WIRE;
        wire[HEADER_SEMANTICS_RESERVED_OFFSET] = 7;
        assert_wire_error(
            &wire,
            OrderedLiteralArtifactError::ReservedNonzero {
                field: "semantics reserved byte",
                value: 7,
            },
        );

        let mut wire = GOLDEN_WIRE;
        write_u64_at(&mut wire, HEADER_RESERVED_OFFSET, 9);
        assert_wire_error(
            &wire,
            OrderedLiteralArtifactError::ReservedNonzero {
                field: "header reserved word",
                value: 9,
            },
        );

        let mut wire = GOLDEN_WIRE;
        write_u64_at(&mut wire, HEADER_TOTAL_BYTES_OFFSET, 83);
        assert_wire_error(
            &wire,
            OrderedLiteralArtifactError::TotalBytesMismatch {
                declared: 83,
                actual: 84,
            },
        );

        let mut wire = GOLDEN_WIRE;
        write_u32_at(&mut wire, HEADER_PATTERN_COUNT_OFFSET, 0);
        assert_wire_error(&wire, OrderedLiteralArtifactError::EmptyPatternSet);

        let mut wire = GOLDEN_WIRE;
        write_u64_at(&mut wire, HEADER_OFFSET_TABLE_OFFSET, 63);
        assert_wire_error(
            &wire,
            OrderedLiteralArtifactError::ExtentMismatch {
                field: "offset table",
                expected: 64,
                actual: 63,
            },
        );

        let mut wire = GOLDEN_WIRE;
        write_u64_at(&mut wire, HEADER_LITERAL_PAYLOAD_OFFSET, 79);
        assert_wire_error(
            &wire,
            OrderedLiteralArtifactError::ExtentMismatch {
                field: "literal payload",
                expected: 80,
                actual: 79,
            },
        );

        let mut wire = GOLDEN_WIRE;
        write_u64_at(&mut wire, HEADER_LITERAL_PAYLOAD_BYTES_OFFSET, 5);
        assert_wire_error(
            &wire,
            OrderedLiteralArtifactError::ExtentMismatch {
                field: "complete wire",
                expected: 84,
                actual: 85,
            },
        );

        let mut wire = GOLDEN_WIRE;
        write_u32_at(&mut wire, 64, 1);
        assert_wire_error(
            &wire,
            OrderedLiteralArtifactError::FirstOffsetNonzero { found: 1 },
        );

        let mut wire = GOLDEN_WIRE;
        write_u32_at(&mut wire, 68, 3);
        assert_wire_error(
            &wire,
            OrderedLiteralArtifactError::OffsetDecreases {
                index: 2,
                previous: 3,
                current: 2,
            },
        );

        let mut wire = GOLDEN_WIRE;
        write_u32_at(&mut wire, 68, 5);
        assert_wire_error(
            &wire,
            OrderedLiteralArtifactError::OffsetOutOfBounds {
                index: 1,
                offset: 5,
                literal_bytes: 4,
            },
        );

        let mut wire = GOLDEN_WIRE;
        write_u32_at(&mut wire, 76, 3);
        assert_wire_error(
            &wire,
            OrderedLiteralArtifactError::FinalOffsetMismatch {
                expected: 4,
                actual: 3,
            },
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one resource matrix pins construction, borrowed validation, and owned-deserialization precedence together"
    )]
    fn build_validate_and_deserialize_limit_precedence_is_exact() {
        let patterns = golden_patterns();
        let mut limits = OrderedLiteralArtifactLimits::unlimited();
        limits.max_patterns = 0;
        assert_eq!(
            OrderedLiteralArtifactV1::build(&[], limits).expect_err("empty set wins"),
            OrderedLiteralArtifactError::EmptyPatternSet,
        );

        let mut limits = OrderedLiteralArtifactLimits::unlimited();
        limits.max_patterns = 2;
        assert_eq!(
            OrderedLiteralArtifactV1::build(&patterns, limits).expect_err("pattern cap"),
            OrderedLiteralArtifactError::ResourceLimit {
                resource: OrderedLiteralArtifactResource::Patterns,
                needed: 3,
                limit: 2,
            },
        );

        let (_, minimum_offset_table_bytes, _, minimum_wire_bytes) =
            canonical_layout(patterns.len(), 0).expect("small minimum layout");
        let minimum_validation_work =
            validation_work(minimum_wire_bytes, minimum_offset_table_bytes)
                .expect("small minimum validation work");
        let minimum_build_work = patterns.len() + minimum_wire_bytes + minimum_validation_work;
        let mut limits = OrderedLiteralArtifactLimits::unlimited();
        limits.max_work = minimum_build_work - 1;
        limits.max_single_literal_bytes = 1;
        assert_eq!(
            OrderedLiteralArtifactV1::build(&patterns, limits)
                .expect_err("minimum work gate precedes the later literal cap"),
            OrderedLiteralArtifactError::ResourceLimit {
                resource: OrderedLiteralArtifactResource::Work,
                needed: minimum_build_work,
                limit: minimum_build_work - 1,
            },
        );

        limits.max_work = minimum_build_work;
        assert_eq!(
            OrderedLiteralArtifactV1::build(&patterns, limits)
                .expect_err("exact minimum work admits the literal census"),
            OrderedLiteralArtifactError::ResourceLimit {
                resource: OrderedLiteralArtifactResource::SingleLiteralBytes,
                needed: 2,
                limit: 1,
            },
        );

        let mut limits = OrderedLiteralArtifactLimits::unlimited();
        limits.max_literal_bytes = 1;
        assert_eq!(
            OrderedLiteralArtifactV1::build(&patterns, limits).expect_err("payload cap"),
            OrderedLiteralArtifactError::ResourceLimit {
                resource: OrderedLiteralArtifactResource::LiteralBytes,
                needed: 2,
                limit: 1,
            },
        );

        let mut limits = OrderedLiteralArtifactLimits::unlimited();
        limits.max_wire_bytes = 83;
        assert_eq!(
            OrderedLiteralArtifactV1::build(&patterns, limits).expect_err("wire cap"),
            OrderedLiteralArtifactError::ResourceLimit {
                resource: OrderedLiteralArtifactResource::WireBytes,
                needed: 84,
                limit: 83,
            },
        );

        let validation_work = 64 + 16 + 27 + GOLDEN_WIRE.len();
        let build_work = patterns.len() + GOLDEN_WIRE.len() + validation_work;
        let mut limits = OrderedLiteralArtifactLimits::unlimited();
        limits.max_work = build_work - 1;
        assert_eq!(
            OrderedLiteralArtifactV1::build(&patterns, limits).expect_err("work cap"),
            OrderedLiteralArtifactError::ResourceLimit {
                resource: OrderedLiteralArtifactResource::Work,
                needed: build_work,
                limit: build_work - 1,
            },
        );

        for (resource, mutate) in [
            (OrderedLiteralArtifactResource::AllocationAttempts, 0_usize),
            (OrderedLiteralArtifactResource::RetainedBytes, 83),
            (OrderedLiteralArtifactResource::PeakBytes, 83),
        ] {
            let mut limits = OrderedLiteralArtifactLimits::unlimited();
            match resource {
                OrderedLiteralArtifactResource::AllocationAttempts => {
                    limits.max_allocation_attempts = mutate;
                }
                OrderedLiteralArtifactResource::RetainedBytes => {
                    limits.max_retained_bytes = mutate;
                }
                OrderedLiteralArtifactResource::PeakBytes => limits.max_peak_bytes = mutate,
                _ => unreachable!(),
            }
            let expected_needed = if resource == OrderedLiteralArtifactResource::AllocationAttempts
            {
                1
            } else {
                84
            };
            assert_eq!(
                OrderedLiteralArtifactV1::build(&patterns, limits).expect_err("owned resource cap"),
                OrderedLiteralArtifactError::ResourceLimit {
                    resource,
                    needed: expected_needed,
                    limit: mutate,
                },
            );
        }

        let mut corrupt = GOLDEN_WIRE;
        corrupt[0] ^= 1;
        let mut limits = OrderedLiteralArtifactLimits::unlimited();
        limits.max_wire_bytes = 83;
        assert_eq!(
            OrderedLiteralArtifactV1View::from_wire(&corrupt, limits)
                .expect_err("outer resource check wins"),
            OrderedLiteralArtifactError::ResourceLimit {
                resource: OrderedLiteralArtifactResource::WireBytes,
                needed: 84,
                limit: 83,
            },
        );

        let mut limits = OrderedLiteralArtifactLimits::unlimited();
        limits.max_patterns = 2;
        assert_eq!(
            OrderedLiteralArtifactV1View::from_wire(&GOLDEN_WIRE, limits)
                .expect_err("borrowed pattern cap"),
            OrderedLiteralArtifactError::ResourceLimit {
                resource: OrderedLiteralArtifactResource::Patterns,
                needed: 3,
                limit: 2,
            },
        );

        let mut limits = OrderedLiteralArtifactLimits::unlimited();
        limits.max_literal_bytes = 3;
        assert_eq!(
            OrderedLiteralArtifactV1View::from_wire(&GOLDEN_WIRE, limits)
                .expect_err("borrowed payload cap"),
            OrderedLiteralArtifactError::ResourceLimit {
                resource: OrderedLiteralArtifactResource::LiteralBytes,
                needed: 4,
                limit: 3,
            },
        );

        let mut malformed_extent = GOLDEN_WIRE;
        write_u64_at(
            &mut malformed_extent,
            HEADER_LITERAL_PAYLOAD_BYTES_OFFSET,
            5,
        );
        assert_eq!(
            OrderedLiteralArtifactV1View::from_wire(&malformed_extent, limits)
                .expect_err("malformed extent wins over caller payload cap"),
            OrderedLiteralArtifactError::ExtentMismatch {
                field: "complete wire",
                expected: 84,
                actual: 85,
            },
        );

        let mut limits = OrderedLiteralArtifactLimits::unlimited();
        limits.max_work = validation_work - 1;
        assert_eq!(
            OrderedLiteralArtifactV1View::from_wire(&GOLDEN_WIRE, limits)
                .expect_err("borrowed work cap"),
            OrderedLiteralArtifactError::ResourceLimit {
                resource: OrderedLiteralArtifactResource::Work,
                needed: validation_work,
                limit: validation_work - 1,
            },
        );

        let mut limits = OrderedLiteralArtifactLimits::unlimited();
        limits.max_single_literal_bytes = 1;
        assert_eq!(
            OrderedLiteralArtifactV1View::from_wire(&GOLDEN_WIRE, limits)
                .expect_err("borrowed per-row cap"),
            OrderedLiteralArtifactError::ResourceLimit {
                resource: OrderedLiteralArtifactResource::SingleLiteralBytes,
                needed: 2,
                limit: 1,
            },
        );

        let deserialize_work = validation_work + GOLDEN_WIRE.len();
        let mut limits = OrderedLiteralArtifactLimits::unlimited();
        limits.max_work = deserialize_work - 1;
        assert_eq!(
            OrderedLiteralArtifactV1::deserialize(&GOLDEN_WIRE, limits)
                .expect_err("deserialize total work cap"),
            OrderedLiteralArtifactError::ResourceLimit {
                resource: OrderedLiteralArtifactResource::Work,
                needed: deserialize_work,
                limit: deserialize_work - 1,
            },
        );

        for (resource, limit) in [
            (OrderedLiteralArtifactResource::AllocationAttempts, 0_usize),
            (OrderedLiteralArtifactResource::RetainedBytes, 83),
            (OrderedLiteralArtifactResource::PeakBytes, 83),
        ] {
            let mut limits = OrderedLiteralArtifactLimits::unlimited();
            match resource {
                OrderedLiteralArtifactResource::AllocationAttempts => {
                    limits.max_allocation_attempts = limit;
                }
                OrderedLiteralArtifactResource::RetainedBytes => {
                    limits.max_retained_bytes = limit;
                }
                OrderedLiteralArtifactResource::PeakBytes => limits.max_peak_bytes = limit,
                _ => unreachable!(),
            }
            let needed = if resource == OrderedLiteralArtifactResource::AllocationAttempts {
                1
            } else {
                84
            };
            assert_eq!(
                OrderedLiteralArtifactV1::deserialize(&GOLDEN_WIRE, limits)
                    .expect_err("deserialize owned resource cap"),
                OrderedLiteralArtifactError::ResourceLimit {
                    resource,
                    needed,
                    limit,
                },
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "success, empty semantics, and the paired sparse-failure receipt share one reconstruction fixture"
    )]
    fn reconstruction_closes_exact_language_capacity_and_sparse_attempts() {
        let patterns = [b"ab".as_slice(), b"a".as_slice(), b"".as_slice()];
        let artifact =
            OrderedLiteralArtifactV1::build(&patterns, OrderedLiteralArtifactLimits::unlimited())
                .expect("artifact");
        let build = artifact
            .as_view()
            .build_sparse_count_plan(
                OrderedLiteralCountPlanReconstructionLimits::unlimited(),
                SparseBuildLimits::unlimited(),
            )
            .expect("reconstruct sparse plan");
        assert!(build.closes());
        assert!(build.plan_build_receipt().published());
        let receipt = build.reconstruction_receipt();
        assert!(receipt.closes());
        assert_eq!(
            receipt.accounting_id(),
            ORDERED_LITERAL_ARTIFACT_V1_RECONSTRUCTION_ACCOUNTING_ID,
        );
        assert_eq!(
            receipt.artifact_identity(),
            artifact.census().artifact_identity()
        );
        assert_eq!(receipt.patterns(), patterns.len());
        assert_eq!(receipt.literal_bytes(), 3);
        assert_eq!(receipt.source_reference_entries(), patterns.len());
        assert_eq!(receipt.source_reference_capacity(), patterns.len());
        assert_eq!(
            receipt.source_reference_bytes(),
            patterns.len() * size_of::<&[u8]>(),
        );
        assert_eq!(receipt.allocation_attempts(), 1);
        assert_eq!(receipt.reference_copy_work(), patterns.len());
        let expected_authentication_work = ORDERED_LITERAL_ARTIFACT_V1_HEADER_BYTES
            + size_of::<u64>()
            + patterns.len() * size_of::<u64>() * 2
            + artifact.census().literal_bytes()
            + ORDERED_LITERAL_ARTIFACT_V1_IDENTITY_DOMAIN.len()
            + artifact.census().wire_bytes();
        assert_eq!(
            receipt.plan_authentication_work(),
            expected_authentication_work,
        );
        assert_eq!(
            receipt.prospective_work(),
            patterns.len() + 1 + expected_authentication_work,
        );
        assert_eq!(receipt.actual_work(), receipt.prospective_work());
        assert!(receipt.published());
        assert_eq!(
            receipt.plan_encoded_patterns_bytes(),
            Some((patterns.len() + 1) * size_of::<u64>() + 3),
        );
        assert_eq!(
            build
                .plan()
                .count(b"abab", SparseReduceLimits::unlimited())
                .expect("count")
                .count,
            2,
        );

        let empty_artifact = OrderedLiteralArtifactV1::build(
            &[b"".as_slice()],
            OrderedLiteralArtifactLimits::unlimited(),
        )
        .expect("empty-language artifact");
        let empty_plan = empty_artifact
            .as_view()
            .build_sparse_count_plan(
                OrderedLiteralCountPlanReconstructionLimits::unlimited(),
                SparseBuildLimits::unlimited(),
            )
            .expect("empty sparse plan");
        assert_eq!(
            empty_plan
                .plan()
                .count(b"ab", SparseReduceLimits::unlimited())
                .expect("empty count")
                .count,
            3,
        );

        let mut failing_limits = SparseBuildLimits::unlimited();
        failing_limits.max_patterns = 2;
        let failure = artifact
            .as_view()
            .build_sparse_count_plan(
                OrderedLiteralCountPlanReconstructionLimits::unlimited(),
                failing_limits,
            )
            .expect_err("sparse pattern refusal");
        match failure {
            OrderedLiteralCountPlanReconstructionError::Sparse { source, receipt } => {
                assert!(source.closes());
                assert!(receipt.closes());
                assert!(!receipt.published());
                assert_eq!(
                    receipt.actual_work(),
                    receipt.reference_copy_work() + receipt.allocation_attempts(),
                );
                assert_eq!(
                    receipt.prospective_work(),
                    receipt.actual_work() + receipt.plan_authentication_work(),
                );
                assert!(matches!(
                    source.source(),
                    SparseBuildError::PatternLimit {
                        needed: 3,
                        limit: 2,
                    }
                ));
            }
            other => panic!("unexpected reconstruction failure: {other:?}"),
        }
    }

    #[test]
    fn reconstructed_trace_preserves_duplicate_and_empty_source_ordinals() {
        let patterns = [
            b"a".as_slice(),
            b"a".as_slice(),
            b"".as_slice(),
            b"z".as_slice(),
        ];
        let artifact =
            OrderedLiteralArtifactV1::build(&patterns, OrderedLiteralArtifactLimits::unlimited())
                .expect("duplicate/empty artifact");
        let build = artifact
            .as_view()
            .build_sparse_count_plan(
                OrderedLiteralCountPlanReconstructionLimits::unlimited(),
                SparseBuildLimits::unlimited(),
            )
            .expect("duplicate/empty reconstruction");
        let mut workspace = build
            .plan()
            .prepare_trace_workspace(2, SparseTraceWorkspaceLimits::unlimited())
            .expect("trace workspace");
        let report = build
            .plan()
            .execute_trace_with_workspace(b"ab", SparseReduceLimits::unlimited(), &mut workspace)
            .expect("trace duplicate/empty language");
        assert!(report.closes());
        assert_eq!(report.matches().len(), 2);
        assert_eq!(report.matches()[0].ordinal(), 0);
        assert_eq!(
            (report.matches()[0].start(), report.matches()[0].end()),
            (0, 1)
        );
        assert_eq!(report.matches()[1].ordinal(), 2);
        assert_eq!(
            (report.matches()[1].start(), report.matches()[1].end()),
            (2, 2)
        );
    }

    #[test]
    fn reconstruction_seam_refuses_resources_before_allocation_or_sparse_build() {
        let artifact = golden_artifact();
        let reference_bytes = 3 * size_of::<&[u8]>();
        let plan_authentication_work = reconstruction_plan_authentication_work(
            artifact.census().patterns(),
            artifact.census().literal_bytes(),
            artifact.census().wire_bytes(),
        )
        .expect("small authentication work");
        let prospective_work = artifact.census().patterns() + 1 + plan_authentication_work;
        let cases = [
            (
                OrderedLiteralCountPlanReconstructionLimits {
                    max_work: usize::MAX,
                    max_allocation_attempts: usize::MAX,
                    max_source_reference_bytes: reference_bytes - 1,
                },
                OrderedLiteralArtifactResource::SourceReferenceBytes,
                reference_bytes,
                reference_bytes - 1,
            ),
            (
                OrderedLiteralCountPlanReconstructionLimits {
                    max_work: usize::MAX,
                    max_allocation_attempts: 0,
                    max_source_reference_bytes: usize::MAX,
                },
                OrderedLiteralArtifactResource::AllocationAttempts,
                1,
                0,
            ),
            (
                OrderedLiteralCountPlanReconstructionLimits {
                    max_work: prospective_work - 1,
                    max_allocation_attempts: usize::MAX,
                    max_source_reference_bytes: usize::MAX,
                },
                OrderedLiteralArtifactResource::Work,
                prospective_work,
                prospective_work - 1,
            ),
        ];
        for (limits, resource, needed, limit) in cases {
            assert_eq!(
                artifact
                    .as_view()
                    .build_sparse_count_plan(limits, SparseBuildLimits::unlimited())
                    .expect_err("seam resource refusal"),
                OrderedLiteralCountPlanReconstructionError::ResourceLimit {
                    resource,
                    needed,
                    limit,
                },
            );
        }
    }

    #[test]
    fn public_accounting_closers_reject_overflow_and_capacity_forgeries() {
        let overflowing_entries = usize::MAX / OFFSET_BYTES + 1;
        let forged_validation = OrderedLiteralArtifactValidationAccounting {
            accounting_id: ORDERED_LITERAL_ARTIFACT_V1_VALIDATION_ACCOUNTING_ID,
            accounting_version: ORDERED_LITERAL_ARTIFACT_V1_VALIDATION_ACCOUNTING_VERSION,
            input_bytes: 0,
            header_bytes: ORDERED_LITERAL_ARTIFACT_V1_HEADER_BYTES,
            offset_entries: overflowing_entries,
            offset_table_bytes: 0,
            hash_input_bytes: ORDERED_LITERAL_ARTIFACT_V1_IDENTITY_DOMAIN.len(),
            work: ORDERED_LITERAL_ARTIFACT_V1_HEADER_BYTES
                + ORDERED_LITERAL_ARTIFACT_V1_IDENTITY_DOMAIN.len(),
        };
        assert!(!forged_validation.closes());

        let artifact = golden_artifact();
        let mut forged_owned = artifact.accounting();
        forged_owned.wire_capacity_bytes += 1;
        forged_owned.retained_bytes += 1;
        forged_owned.peak_bytes += 1;
        assert!(!forged_owned.closes(artifact.census()));

        let build = artifact
            .as_view()
            .build_sparse_count_plan(
                OrderedLiteralCountPlanReconstructionLimits::unlimited(),
                SparseBuildLimits::unlimited(),
            )
            .expect("reconstruct for receipt forgery checks");
        let mut forged_reconstruction = build.reconstruction_receipt();
        forged_reconstruction.source_reference_capacity += 1;
        forged_reconstruction.source_reference_bytes += size_of::<&[u8]>();
        assert!(!forged_reconstruction.closes());

        let mut forged_reconstruction = build.reconstruction_receipt();
        forged_reconstruction.plan_encoded_patterns_bytes = forged_reconstruction
            .plan_encoded_patterns_bytes
            .and_then(|bytes| bytes.checked_add(1));
        assert!(!forged_reconstruction.closes());

        let mut forged_reconstruction = build.reconstruction_receipt();
        forged_reconstruction.prospective_work -= 1;
        assert!(!forged_reconstruction.closes());

        let mut forged_reconstruction = build.reconstruction_receipt();
        forged_reconstruction.actual_work -= forged_reconstruction.plan_authentication_work;
        assert!(!forged_reconstruction.closes());

        let mut forged_reconstruction = build.reconstruction_receipt();
        forged_reconstruction
            .plan_build_identity
            .limits
            .max_scratch_bytes = forged_reconstruction.source_reference_bytes - 1;
        assert!(!forged_reconstruction.closes());

        let mut forged_build = build;
        forged_build.reconstruction.artifact_identity[0] ^= 1;
        assert!(!forged_build.closes());
    }
}
