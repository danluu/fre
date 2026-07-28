//! Fixed-work reducers whose candidates are fixed by absolute text anchors.
//!
//! Every descriptor is closed over the original haystack domain. A [`Window`]
//! can exclude an absolute candidate, but it can never rebase `StartText` or
//! `EndText` onto a surrogate slice. Reduction preflight receives only the
//! haystack length, publishes a complete prospective receipt, and checks all
//! caller limits before any byte can be read. The selected operation then
//! allocates no memory and returns exact counters validated against that
//! receipt.

use core::{fmt, mem::size_of};

use fre_exact_alloc::{CopyError, ExactVec};

use crate::{Window, forward_anchored::ByteClass};

pub const PLAN_ID: &str = "fixed-absolute-domain.original-haystack.v1";
pub const ALGORITHM_VERSION: u32 = 1;
pub const ACCOUNTING_VERSION: u32 = 1;
pub const COUNT_OPERATION_ID: &str = "fixed-absolute-domain.count.v1";
pub const SPAN_SUM_OPERATION_ID: &str = "fixed-absolute-domain.span-sum.v1";

/// A normalized 256-bit positional byte predicate.
pub type ByteMask = ByteClass;

/// One of the eight closed absolute-domain theorems.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DescriptorKind {
    EndMaskSequence,
    EndOneByteMask,
    EndGreedyClassLiteral,
    WholeByteRepeat,
    WholeOrderedWords,
    StartOrderedPrefix,
    WholeScalarEnvelope,
    StartMaskSequence,
}

/// Whole-match reduction selected before construction.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Operation {
    Count,
    SpanSum,
}

/// Declared branch available after construction and before source access.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DeclaredResidual {
    None,
    PrepublishedContinuation,
}

/// Allocation-free content token retained in every operation identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContentDigest {
    lane0: u64,
    lane1: u64,
}

/// Incremental content-token construction used by the facade's already
/// metered canonical-HIR inspection.
#[doc(hidden)]
pub(crate) struct ContentDigestBuilder {
    lane0: u64,
    lane1: u64,
}

impl ContentDigestBuilder {
    #[must_use]
    pub(crate) const fn new(kind: DescriptorKind) -> Self {
        let domain = match kind {
            DescriptorKind::EndMaskSequence => 1,
            DescriptorKind::EndOneByteMask => 2,
            DescriptorKind::WholeByteRepeat => 3,
            DescriptorKind::WholeOrderedWords => 4,
            DescriptorKind::StartOrderedPrefix => 5,
            DescriptorKind::WholeScalarEnvelope => 6,
            DescriptorKind::EndGreedyClassLiteral => 7,
            DescriptorKind::StartMaskSequence => 8,
        };
        Self {
            lane0: 0xcbf2_9ce4_8422_2325_u64 ^ domain,
            lane1: 0x6eed_0e9d_a4d9_4a4f_u64 ^ domain.rotate_left(17),
        }
    }

    pub(crate) fn write_byte(&mut self, byte: u8) {
        self.lane0 ^= u64::from(byte);
        self.lane0 = self.lane0.wrapping_mul(0x0000_0100_0000_01b3);
        self.lane1 ^= u64::from(byte).wrapping_add(0x9e37_79b9_7f4a_7c15);
        self.lane1 = self
            .lane1
            .rotate_left(13)
            .wrapping_mul(0xff51_afd7_ed55_8ccd);
    }

    pub(crate) fn write_u32(&mut self, value: u32) {
        for byte in value.to_le_bytes() {
            self.write_byte(byte);
        }
    }

    pub(crate) fn write_u64(&mut self, value: u64) {
        for byte in value.to_le_bytes() {
            self.write_byte(byte);
        }
    }

    pub(crate) fn write_usize(&mut self, value: usize) {
        for byte in value.to_le_bytes() {
            self.write_byte(byte);
        }
    }

    #[must_use]
    pub(crate) const fn finish(self) -> ContentDigest {
        ContentDigest {
            lane0: self.lane0,
            lane1: self.lane1,
        }
    }
}

/// Closed descriptor dimensions retained in the operation identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DescriptorIdentity {
    EndMaskSequence {
        width: usize,
    },
    EndOneByteMask,
    EndGreedyClassLiteral {
        suffix_bytes: usize,
    },
    WholeByteRepeat {
        byte: u8,
        minimum: u32,
        maximum: u32,
    },
    WholeOrderedWords {
        words: usize,
        word_bytes: usize,
    },
    StartOrderedPrefix {
        width: usize,
        alternatives: usize,
    },
    StartMaskSequence {
        width: usize,
    },
    WholeScalarEnvelope {
        scalars: u32,
        minimum_bytes: usize,
        maximum_bytes: usize,
    },
}

impl DescriptorIdentity {
    #[must_use]
    pub const fn kind(self) -> DescriptorKind {
        match self {
            Self::EndMaskSequence { .. } => DescriptorKind::EndMaskSequence,
            Self::EndOneByteMask => DescriptorKind::EndOneByteMask,
            Self::EndGreedyClassLiteral { .. } => DescriptorKind::EndGreedyClassLiteral,
            Self::WholeByteRepeat { .. } => DescriptorKind::WholeByteRepeat,
            Self::WholeOrderedWords { .. } => DescriptorKind::WholeOrderedWords,
            Self::StartOrderedPrefix { .. } => DescriptorKind::StartOrderedPrefix,
            Self::WholeScalarEnvelope { .. } => DescriptorKind::WholeScalarEnvelope,
            Self::StartMaskSequence { .. } => DescriptorKind::StartMaskSequence,
        }
    }
}

const FIXED_IDENTITY_BYTES: usize = size_of::<DescriptorIdentity>() + size_of::<ContentDigest>();

/// Stable algorithm, accounting, descriptor, operation and residual identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OperationIdentity {
    pub plan_id: &'static str,
    pub algorithm_version: u32,
    pub accounting_version: u32,
    pub operation_id: &'static str,
    pub operation: Operation,
    pub descriptor: DescriptorIdentity,
    pub content_digest: ContentDigest,
    pub residual: DeclaredResidual,
    pub original_haystack_anchors: bool,
    pub non_overlapping: bool,
}

/// Construction limits for the new route. These are independent of every
/// incumbent selector and therefore cannot widen or consume an old quota.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub max_items: usize,
    pub max_payload_bytes: usize,
    pub max_identity_bytes: usize,
    pub max_copied_bytes: usize,
    pub max_allocations: usize,
    pub max_initialized_bytes: usize,
    pub max_build_work: u64,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            max_items: 1_000,
            max_payload_bytes: 4 << 20,
            max_identity_bytes: 8 << 20,
            max_copied_bytes: 4 << 20,
            max_allocations: 4_096,
            max_initialized_bytes: 8 << 20,
            max_build_work: 64 << 20,
            max_persistent_bytes: 192 << 20,
            max_peak_bytes: 224 << 20,
        }
    }
}

/// Complete construction envelope checked before the first allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildProspective {
    pub descriptor: DescriptorIdentity,
    pub items: usize,
    pub payload_bytes: usize,
    pub identity_bytes: usize,
    pub retained_heap_bytes: usize,
    pub copied_bytes: usize,
    pub allocations: usize,
    pub initialized_bytes: usize,
    pub build_work: u64,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Exact construction resources observed before transactional publication.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BuildActual {
    pub items: usize,
    pub payload_bytes: usize,
    pub identity_bytes: usize,
    pub retained_heap_bytes: usize,
    pub copied_bytes: usize,
    pub allocations: usize,
    pub initialized_bytes: usize,
    pub build_work: u64,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
    pub published: bool,
}

/// Prospective and actual construction receipts retained by the immutable
/// plan. Every actual dimension is checked, not merely debug asserted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub prospective: BuildProspective,
    pub actual: BuildActual,
}

/// The construction resource that refused publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildResource {
    Items,
    PayloadBytes,
    IdentityBytes,
    CopiedBytes,
    Allocations,
    InitializedBytes,
    Work,
    PersistentBytes,
    PeakBytes,
}

/// Typed construction failure with proof that no partial artifact escaped.
/// Structural validation that prevents descriptor dimensions from being
/// closed has no prospective receipt and a zero actual ledger; once a
/// prospective receipt exists, `actual` is the exact cumulative admitted
/// construction ledger through the failing step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildError {
    pub kind: BuildErrorKind,
    pub prospective: Option<BuildProspective>,
    pub actual: BuildActual,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuildErrorKind {
    EmptyDescriptor,
    ReversedRepeat {
        minimum: u32,
        maximum: u32,
    },
    ZeroScalarCount,
    EmptyWord {
        index: usize,
    },
    DimensionMismatch {
        dimension: &'static str,
        declared: usize,
        observed: usize,
    },
    ResourceLimit {
        resource: BuildResource,
        needed: u64,
        limit: u64,
    },
    AllocationFailed {
        structure: &'static str,
        additional: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    InternalInvariant(&'static str),
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            BuildErrorKind::EmptyDescriptor => {
                formatter.write_str("fixed absolute descriptor is empty")
            }
            BuildErrorKind::ReversedRepeat { minimum, maximum } => write!(
                formatter,
                "fixed absolute repeat {minimum}..={maximum} is reversed"
            ),
            BuildErrorKind::ZeroScalarCount => {
                formatter.write_str("fixed absolute scalar envelope count is zero")
            }
            BuildErrorKind::EmptyWord { index } => {
                write!(formatter, "fixed absolute word {index} is empty")
            }
            BuildErrorKind::DimensionMismatch {
                dimension,
                declared,
                observed,
            } => write!(
                formatter,
                "fixed absolute ordered-word {dimension} declared {declared}, observed {observed}"
            ),
            BuildErrorKind::ResourceLimit {
                resource,
                needed,
                limit,
            } => write!(
                formatter,
                "fixed absolute {resource:?} needs {needed}, limit is {limit}"
            ),
            BuildErrorKind::AllocationFailed {
                structure,
                additional,
            } => write!(
                formatter,
                "fixed absolute failed to allocate {additional} items for {structure}"
            ),
            BuildErrorKind::ArithmeticOverflow { computation } => write!(
                formatter,
                "fixed absolute construction overflow in {computation}"
            ),
            BuildErrorKind::InternalInvariant(detail) => {
                write!(
                    formatter,
                    "fixed absolute construction invariant failed: {detail}"
                )
            }
        }
    }
}

impl std::error::Error for BuildError {}

/// Limits checked using length and immutable plan metadata before source
/// access. The selected operation never allocates scratch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceLimits {
    pub max_byte_probes: usize,
    pub max_branch_checks: usize,
    pub max_match_events: usize,
    pub max_count: u64,
    pub max_span_sum: u64,
    pub max_reducer_steps: usize,
    pub max_total_work: usize,
    pub max_scratch_bytes: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl Default for ReduceLimits {
    fn default() -> Self {
        Self {
            max_byte_probes: 128 << 20,
            max_branch_checks: 128 << 20,
            max_match_events: 128 << 20,
            max_count: 128 << 20,
            max_span_sum: 128 << 20,
            max_reducer_steps: (128 << 20) + 1,
            max_total_work: 320 << 20,
            max_scratch_bytes: 0,
            max_persistent_bytes: 192 << 20,
            max_peak_bytes: 256 << 20,
        }
    }
}

/// Whether the fixed theorem completes the operation or selects its declared
/// residual before any source byte is read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
    Complete,
    PrepublishedContinuation,
}

/// Complete resource receipt admitted before source access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceProspective {
    pub disposition: Disposition,
    pub byte_probes: usize,
    pub branch_checks: usize,
    pub match_events: usize,
    pub count: u64,
    pub span_sum: u64,
    pub reducer_steps: usize,
    pub total_work: usize,
    pub allocations: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Exact post-operation receipt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReduceActual {
    pub byte_probes: usize,
    pub source_accesses: usize,
    pub branch_checks: usize,
    pub match_events: usize,
    pub count: u64,
    pub span_sum: u64,
    pub reducer_steps: usize,
    pub total_work: usize,
    pub allocations: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
    pub selected_branch_ordinal: Option<usize>,
}

impl ReduceActual {
    /// Check every actual dimension against the pre-source envelope.
    #[must_use]
    pub const fn fits(self, upper: ReduceProspective) -> bool {
        self.byte_probes <= upper.byte_probes
            && self.source_accesses <= upper.byte_probes
            && self.branch_checks <= upper.branch_checks
            && self.match_events <= upper.match_events
            && self.count <= upper.count
            && self.span_sum <= upper.span_sum
            && self.reducer_steps <= upper.reducer_steps
            && self.total_work <= upper.total_work
            && self.allocations <= upper.allocations
            && self.scratch_bytes <= upper.scratch_bytes
            && self.persistent_bytes <= upper.persistent_bytes
            && self.peak_bytes <= upper.peak_bytes
    }
}

/// Auditable immutable-identity execution result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceAccounting {
    pub identity: OperationIdentity,
    pub window: Window,
    pub haystack_len: usize,
    pub prospective: ReduceProspective,
    pub actual: ReduceActual,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountResult {
    pub outcome: CountOutcome,
    pub accounting: ReduceAccounting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CountOutcome {
    Complete { count: u64 },
    PrepublishedContinuation,
}

impl CountResult {
    #[must_use]
    pub const fn count(self) -> Option<u64> {
        match self.outcome {
            CountOutcome::Complete { count } => Some(count),
            CountOutcome::PrepublishedContinuation => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanSumResult {
    pub span_sum: u64,
    pub disposition: Disposition,
    pub accounting: ReduceAccounting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CompactMatch {
    matched: bool,
    variable_span: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ValueAdmission {
    prospective: ReduceProspective,
    candidate_active: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReduceResource {
    ByteProbes,
    BranchChecks,
    MatchEvents,
    Count,
    SpanSum,
    ReducerSteps,
    TotalWork,
    ScratchBytes,
    PersistentBytes,
    PeakBytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReduceError {
    pub kind: ReduceErrorKind,
    pub receipt: ReduceFailureReceipt,
}

/// Terminal failure evidence bound to the attempted immutable operation and
/// original-haystack invocation. Resource refusals and every failure after
/// admission retain the prospective receipt; pre-admission structural errors
/// retain the same route/window/length context with no prospective receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceFailureReceipt {
    pub identity: OperationIdentity,
    pub window: Window,
    pub haystack_len: usize,
    pub prospective: Option<ReduceProspective>,
    pub actual: ReduceActual,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReduceErrorKind {
    InvalidWindow {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
    OperationMismatch {
        descriptor: DescriptorKind,
        operation: Operation,
    },
    ResourceLimit {
        resource: ReduceResource,
        needed: u64,
        limit: u64,
    },
    AdmissionMismatch,
    ArithmeticOverflow {
        computation: &'static str,
    },
    ActualExceedsProspective,
}

impl fmt::Display for ReduceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ReduceErrorKind::InvalidWindow {
                start,
                end,
                haystack_len,
            } => write!(
                formatter,
                "fixed absolute window {start}..{end} is invalid for {haystack_len} bytes"
            ),
            ReduceErrorKind::OperationMismatch {
                descriptor,
                operation,
            } => write!(
                formatter,
                "fixed absolute descriptor {descriptor:?} does not implement {operation:?}"
            ),
            ReduceErrorKind::ResourceLimit {
                resource,
                needed,
                limit,
            } => write!(
                formatter,
                "fixed absolute {resource:?} needs {needed}, limit is {limit}"
            ),
            ReduceErrorKind::AdmissionMismatch => {
                formatter.write_str("fixed absolute admission does not match this invocation")
            }
            ReduceErrorKind::ArithmeticOverflow { computation } => {
                write!(
                    formatter,
                    "fixed absolute execution overflow in {computation}"
                )
            }
            ReduceErrorKind::ActualExceedsProspective => {
                formatter.write_str("fixed absolute actual receipt exceeds its prospective receipt")
            }
        }
    }
}

impl std::error::Error for ReduceError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Word {
    start: usize,
    end: usize,
}

#[derive(Debug)]
enum Descriptor {
    MaskSequence(ExactVec<ByteMask>),
    EndOneByteMask(ByteMask),
    EndGreedyClassLiteral {
        class: ByteMask,
        suffix: ExactVec<u8>,
    },
    WholeByteRepeat {
        byte: u8,
        minimum: u32,
        maximum: u32,
    },
    WholeOrderedWords {
        bytes: ExactVec<u8>,
        words: ExactVec<Word>,
    },
    StartOrderedPrefix {
        prefix: ExactVec<u8>,
        alternatives: ExactVec<u8>,
    },
    WholeScalarEnvelope {
        minimum_bytes: usize,
        maximum_bytes: usize,
    },
}

/// Immutable descriptor and its transactionally published build receipt.
#[derive(Debug)]
pub struct FixedAbsoluteDomainPlan {
    descriptor: Descriptor,
    identity: DescriptorIdentity,
    content_digest: ContentDigest,
    build: BuildAccounting,
}

#[allow(
    clippy::result_large_err,
    reason = "public build and reduction errors intentionally retain complete prospective and actual receipts"
)]
impl FixedAbsoluteDomainPlan {
    /// Allocation-free construction prospective for an end-mask sequence.
    #[doc(hidden)]
    pub fn end_mask_sequence_prospective(count: usize) -> Result<BuildProspective, BuildError> {
        if count == 0 {
            return Err(build_error(BuildErrorKind::EmptyDescriptor));
        }
        if count == 1 {
            return Err(build_error(BuildErrorKind::InternalInvariant(
                "one-byte endpoint must use EndOneByteMask",
            )));
        }
        let identity = DescriptorIdentity::EndMaskSequence { width: count };
        let payload = count.checked_mul(size_of::<ByteMask>()).ok_or_else(|| {
            build_error(BuildErrorKind::ArithmeticOverflow {
                computation: "mask payload bytes",
            })
        })?;
        let work = count
            .checked_add(1)
            .and_then(|work| u64::try_from(work).ok())
            .ok_or_else(|| {
                build_error(BuildErrorKind::ArithmeticOverflow {
                    computation: "mask build work",
                })
            })?;
        prospective(identity, count, payload, payload, payload, 1, payload, work)
    }

    pub fn build_end_mask_sequence(
        masks: impl ExactSizeIterator<Item = ByteMask>,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        Self::build_masks(masks, false, limits)
    }

    /// Allocation-free construction prospective for a start-mask sequence.
    #[doc(hidden)]
    pub fn start_mask_sequence_prospective(count: usize) -> Result<BuildProspective, BuildError> {
        if count == 0 {
            return Err(build_error(BuildErrorKind::EmptyDescriptor));
        }
        let identity = DescriptorIdentity::StartMaskSequence { width: count };
        let payload = count.checked_mul(size_of::<ByteMask>()).ok_or_else(|| {
            build_error(BuildErrorKind::ArithmeticOverflow {
                computation: "start mask payload bytes",
            })
        })?;
        let work = count
            .checked_add(1)
            .and_then(|work| u64::try_from(work).ok())
            .ok_or_else(|| {
                build_error(BuildErrorKind::ArithmeticOverflow {
                    computation: "start mask build work",
                })
            })?;
        prospective(identity, count, payload, payload, payload, 1, payload, work)
    }

    /// Build a non-empty positional byte predicate anchored to byte zero of
    /// the original haystack.
    pub fn build_start_mask_sequence(
        masks: impl ExactSizeIterator<Item = ByteMask>,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        Self::build_masks(masks, true, limits)
    }

    pub fn build_end_one_byte_mask(
        mask: ByteMask,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        let prospective = Self::end_one_byte_mask_prospective(mask)?;
        enforce_build(prospective, limits)?;
        let identity = prospective.descriptor;
        let mut digest = ContentDigestBuilder::new(DescriptorKind::EndOneByteMask);
        for word in mask.words() {
            digest.write_u64(word);
        }
        let content_digest = digest.finish();
        let actual = published_actual(prospective);
        Ok(Self {
            descriptor: Descriptor::EndOneByteMask(mask),
            identity,
            content_digest,
            build: BuildAccounting {
                prospective,
                actual,
            },
        })
    }

    /// Allocation-free construction prospective for one endpoint mask.
    #[doc(hidden)]
    pub fn end_one_byte_mask_prospective(mask: ByteMask) -> Result<BuildProspective, BuildError> {
        if mask.is_empty() {
            return Err(build_error(BuildErrorKind::EmptyDescriptor));
        }
        let identity = DescriptorIdentity::EndOneByteMask;
        let mask_bytes = size_of::<ByteMask>();
        prospective(identity, 1, mask_bytes, 0, 0, 0, mask_bytes, 1)
    }

    /// Complete construction envelope for a greedy byte-class run followed
    /// by one nonempty literal at the original end of text.
    #[doc(hidden)]
    pub fn end_greedy_class_literal_prospective(
        class: ByteMask,
        suffix_bytes: usize,
    ) -> Result<BuildProspective, BuildError> {
        if class.is_empty() || suffix_bytes == 0 {
            return Err(build_error(BuildErrorKind::EmptyDescriptor));
        }
        let items = suffix_bytes.checked_add(1).ok_or_else(|| {
            build_error(BuildErrorKind::ArithmeticOverflow {
                computation: "terminal greedy item count",
            })
        })?;
        let payload_bytes = suffix_bytes
            .checked_add(size_of::<ByteMask>())
            .ok_or_else(|| {
                build_error(BuildErrorKind::ArithmeticOverflow {
                    computation: "terminal greedy payload bytes",
                })
            })?;
        let build_work = suffix_bytes
            .checked_add(class.words().len())
            .and_then(|work| work.checked_add(1))
            .and_then(|work| u64::try_from(work).ok())
            .ok_or_else(|| {
                build_error(BuildErrorKind::ArithmeticOverflow {
                    computation: "terminal greedy build work",
                })
            })?;
        prospective(
            DescriptorIdentity::EndGreedyClassLiteral { suffix_bytes },
            items,
            payload_bytes,
            suffix_bytes,
            suffix_bytes,
            1,
            payload_bytes,
            build_work,
        )
    }

    /// Transactionally retain the suffix only after the complete descriptor
    /// envelope has passed every caller limit. The byte class remains inline.
    #[allow(
        clippy::result_large_err,
        clippy::too_many_lines,
        reason = "one transaction keeps suffix retention and its cumulative fixed-domain receipt auditable"
    )]
    pub fn build_end_greedy_class_literal(
        class: ByteMask,
        suffix: &[u8],
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        let prospective = Self::end_greedy_class_literal_prospective(class, suffix.len())?;
        enforce_build(prospective, limits)?;
        let identity = prospective.descriptor;
        let mut actual = BuildActual {
            identity_bytes: FIXED_IDENTITY_BYTES,
            ..BuildActual::default()
        };
        let mut retained = allocate_exact(suffix.len()).map_err(|error| {
            allocation_error(
                error,
                "terminal greedy suffix",
                suffix.len(),
                prospective,
                actual,
            )
        })?;
        actual.allocations = 1;
        actual.retained_heap_bytes = suffix.len();
        actual.persistent_bytes = suffix.len();
        actual.peak_bytes = suffix.len();

        let mut digest = ContentDigestBuilder::new(DescriptorKind::EndGreedyClassLiteral);
        digest.write_usize(suffix.len());
        for word in class.words() {
            digest.write_u64(word);
            actual.build_work = add_build_u64(
                actual.build_work,
                1,
                "terminal greedy class identity work",
                prospective,
                actual,
            )?;
        }
        actual.items = 1;
        actual.payload_bytes = size_of::<ByteMask>();
        actual.identity_bytes = actual
            .identity_bytes
            .checked_add(size_of::<ByteMask>())
            .ok_or_else(|| {
                build_error_with(
                    BuildErrorKind::ArithmeticOverflow {
                        computation: "terminal greedy class identity bytes",
                    },
                    prospective,
                    actual,
                )
            })?;
        actual.initialized_bytes = size_of::<ByteMask>();

        for &byte in suffix {
            actual.build_work = add_build_u64(
                actual.build_work,
                1,
                "terminal greedy suffix copy work",
                prospective,
                actual,
            )?;
            digest.write_byte(byte);
            retained.try_push(byte).map_err(|_| {
                build_error_with(
                    BuildErrorKind::InternalInvariant("exact terminal suffix capacity changed"),
                    prospective,
                    actual,
                )
            })?;
            actual.items = add_build_usize(
                actual.items,
                1,
                "terminal greedy copied items",
                prospective,
                actual,
            )?;
            actual.payload_bytes = add_build_usize(
                actual.payload_bytes,
                1,
                "terminal greedy payload bytes",
                prospective,
                actual,
            )?;
            actual.identity_bytes = add_build_usize(
                actual.identity_bytes,
                1,
                "terminal greedy identity bytes",
                prospective,
                actual,
            )?;
            actual.copied_bytes = add_build_usize(
                actual.copied_bytes,
                1,
                "terminal greedy copied bytes",
                prospective,
                actual,
            )?;
            actual.initialized_bytes = add_build_usize(
                actual.initialized_bytes,
                1,
                "terminal greedy initialized bytes",
                prospective,
                actual,
            )?;
        }
        actual.build_work = add_build_u64(
            actual.build_work,
            1,
            "terminal greedy publication work",
            prospective,
            actual,
        )?;
        actual.items = prospective.items;
        actual.payload_bytes = prospective.payload_bytes;
        actual.identity_bytes = prospective.identity_bytes;
        actual.retained_heap_bytes = prospective.retained_heap_bytes;
        actual.copied_bytes = prospective.copied_bytes;
        actual.allocations = prospective.allocations;
        actual.initialized_bytes = prospective.initialized_bytes;
        actual.build_work = prospective.build_work;
        actual.persistent_bytes = prospective.persistent_bytes;
        actual.peak_bytes = prospective.peak_bytes;
        actual.published = true;
        validate_build_actual(prospective, actual)?;
        Ok(Self {
            descriptor: Descriptor::EndGreedyClassLiteral {
                class,
                suffix: retained,
            },
            identity,
            content_digest: digest.finish(),
            build: BuildAccounting {
                prospective,
                actual,
            },
        })
    }

    pub fn build_whole_byte_repeat(
        byte: u8,
        minimum: u32,
        maximum: u32,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        let prospective = Self::whole_byte_repeat_prospective(byte, minimum, maximum)?;
        enforce_build(prospective, limits)?;
        let identity = prospective.descriptor;
        let mut digest = ContentDigestBuilder::new(DescriptorKind::WholeByteRepeat);
        digest.write_byte(byte);
        digest.write_u32(minimum);
        digest.write_u32(maximum);
        let content_digest = digest.finish();
        let actual = published_actual(prospective);
        Ok(Self {
            descriptor: Descriptor::WholeByteRepeat {
                byte,
                minimum,
                maximum,
            },
            identity,
            content_digest,
            build: BuildAccounting {
                prospective,
                actual,
            },
        })
    }

    /// Allocation-free construction prospective for a whole-byte repeat.
    #[doc(hidden)]
    pub fn whole_byte_repeat_prospective(
        byte: u8,
        minimum: u32,
        maximum: u32,
    ) -> Result<BuildProspective, BuildError> {
        if minimum > maximum {
            return Err(build_error(BuildErrorKind::ReversedRepeat {
                minimum,
                maximum,
            }));
        }
        let identity = DescriptorIdentity::WholeByteRepeat {
            byte,
            minimum,
            maximum,
        };
        let repeat_payload = size_of::<u8>()
            .checked_add(size_of::<u32>().checked_mul(2).ok_or_else(|| {
                build_error(BuildErrorKind::ArithmeticOverflow {
                    computation: "repeat payload bytes",
                })
            })?)
            .ok_or_else(|| {
                build_error(BuildErrorKind::ArithmeticOverflow {
                    computation: "repeat payload bytes",
                })
            })?;
        let repeat_items = usize::try_from(maximum).map_err(|_| {
            build_error(BuildErrorKind::ArithmeticOverflow {
                computation: "repeat maximum as items",
            })
        })?;
        prospective(
            identity,
            repeat_items,
            repeat_payload,
            0,
            0,
            0,
            repeat_payload,
            1,
        )
    }

    /// Allocation-free construction prospective for precounted ordered words.
    #[doc(hidden)]
    pub fn whole_ordered_words_prospective(
        word_count: usize,
        word_bytes: usize,
    ) -> Result<BuildProspective, BuildError> {
        if word_count == 0 {
            return Err(build_error(BuildErrorKind::EmptyDescriptor));
        }
        let identity = DescriptorIdentity::WholeOrderedWords {
            words: word_count,
            word_bytes,
        };
        let word_storage = word_count.checked_mul(size_of::<Word>()).ok_or_else(|| {
            build_error(BuildErrorKind::ArithmeticOverflow {
                computation: "ordered word metadata bytes",
            })
        })?;
        let retained_heap = word_bytes.checked_add(word_storage).ok_or_else(|| {
            build_error(BuildErrorKind::ArithmeticOverflow {
                computation: "ordered word payload bytes",
            })
        })?;
        let allocations = usize::from(word_bytes != 0)
            .checked_add(usize::from(word_count != 0))
            .ok_or_else(|| {
                build_error(BuildErrorKind::ArithmeticOverflow {
                    computation: "ordered word allocations",
                })
            })?;
        let traversal_work = word_bytes
            .checked_add(word_count)
            .and_then(|work| work.checked_add(2))
            .ok_or_else(|| {
                build_error(BuildErrorKind::ArithmeticOverflow {
                    computation: "ordered word traversal work",
                })
            })?;
        let expected_build_work = u64::try_from(traversal_work).map_err(|_| {
            build_error(BuildErrorKind::ArithmeticOverflow {
                computation: "ordered word build work",
            })
        })?;
        prospective(
            identity,
            word_count,
            word_bytes,
            retained_heap,
            word_bytes,
            allocations,
            retained_heap,
            expected_build_work,
        )
    }

    /// Build an ordered-word descriptor from dimensions proved by the caller.
    /// The complete prospective receipt is enforced before `source` is
    /// consumed, and the single copy pass validates both declarations.
    /// Allocation-free construction prospective for an ordered start prefix.
    #[doc(hidden)]
    pub fn start_ordered_prefix_prospective(
        prefix_bytes: usize,
        alternative_count: usize,
    ) -> Result<BuildProspective, BuildError> {
        if prefix_bytes == 0 || alternative_count == 0 {
            return Err(build_error(BuildErrorKind::EmptyDescriptor));
        }
        let width = prefix_bytes.checked_add(1).ok_or_else(|| {
            build_error(BuildErrorKind::ArithmeticOverflow {
                computation: "ordered prefix width",
            })
        })?;
        let items = prefix_bytes.checked_add(alternative_count).ok_or_else(|| {
            build_error(BuildErrorKind::ArithmeticOverflow {
                computation: "ordered prefix item count",
            })
        })?;
        let identity = DescriptorIdentity::StartOrderedPrefix {
            width,
            alternatives: alternative_count,
        };
        let work = items
            .checked_add(1)
            .and_then(|work| u64::try_from(work).ok())
            .ok_or_else(|| {
                build_error(BuildErrorKind::ArithmeticOverflow {
                    computation: "ordered prefix build work",
                })
            })?;
        prospective(identity, items, items, items, items, 2, items, work)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the transactional builder maintains one explicit cumulative receipt ledger"
    )]
    pub fn build_whole_ordered_words_precounted<'a>(
        word_count: usize,
        word_bytes: usize,
        mut source: impl ExactSizeIterator<Item = &'a [u8]>,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        if word_count == 0 {
            return Err(build_error(BuildErrorKind::EmptyDescriptor));
        }
        let identity = DescriptorIdentity::WholeOrderedWords {
            words: word_count,
            word_bytes,
        };
        let word_storage = word_count.checked_mul(size_of::<Word>()).ok_or_else(|| {
            build_error(BuildErrorKind::ArithmeticOverflow {
                computation: "ordered word metadata bytes",
            })
        })?;
        let retained_heap = word_bytes.checked_add(word_storage).ok_or_else(|| {
            build_error(BuildErrorKind::ArithmeticOverflow {
                computation: "ordered word payload bytes",
            })
        })?;
        let allocations = usize::from(word_bytes != 0)
            .checked_add(usize::from(word_count != 0))
            .ok_or_else(|| {
                build_error(BuildErrorKind::ArithmeticOverflow {
                    computation: "ordered word allocations",
                })
            })?;
        let traversal_work = word_bytes
            .checked_add(word_count)
            .and_then(|work| work.checked_add(2))
            .ok_or_else(|| {
                build_error(BuildErrorKind::ArithmeticOverflow {
                    computation: "ordered word traversal work",
                })
            })?;
        let expected_build_work = u64::try_from(traversal_work).map_err(|_| {
            build_error(BuildErrorKind::ArithmeticOverflow {
                computation: "ordered word build work",
            })
        })?;
        let prospective = Self::whole_ordered_words_prospective(word_count, word_bytes)?;
        enforce_build(prospective, limits)?;

        let mut actual = BuildActual {
            identity_bytes: FIXED_IDENTITY_BYTES,
            build_work: 1,
            ..BuildActual::default()
        };
        let source_word_count = source.len();
        if source_word_count != word_count {
            return Err(build_error_with(
                BuildErrorKind::DimensionMismatch {
                    dimension: "word count",
                    declared: word_count,
                    observed: source_word_count,
                },
                prospective,
                actual,
            ));
        }
        let mut digest = ContentDigestBuilder::new(DescriptorKind::WholeOrderedWords);
        digest.write_usize(word_count);
        digest.write_usize(word_bytes);
        let mut words = allocate_exact(word_count).map_err(|error| {
            allocation_error(
                error,
                "ordered word metadata",
                word_count,
                prospective,
                actual,
            )
        })?;
        actual.allocations = usize::from(word_count != 0);
        actual.retained_heap_bytes = word_storage;
        actual.persistent_bytes = word_storage;
        actual.peak_bytes = word_storage;
        let mut bytes = allocate_exact(word_bytes).map_err(|error| {
            allocation_error(error, "ordered word bytes", word_bytes, prospective, actual)
        })?;
        actual.allocations = allocations;
        actual.retained_heap_bytes = retained_heap;
        actual.persistent_bytes = retained_heap;
        actual.peak_bytes = retained_heap;
        let mut start = 0_usize;
        for index in 0..word_count {
            actual.build_work = add_build_u64(
                actual.build_work,
                1,
                "ordered word metadata work",
                prospective,
                actual,
            )?;
            let Some(word) = source.next() else {
                return Err(build_error_with(
                    BuildErrorKind::DimensionMismatch {
                        dimension: "word count",
                        declared: word_count,
                        observed: index,
                    },
                    prospective,
                    actual,
                ));
            };
            if word.is_empty() {
                return Err(build_error_with(
                    BuildErrorKind::EmptyWord { index },
                    prospective,
                    actual,
                ));
            }
            digest.write_usize(word.len());
            let end = start.checked_add(word.len()).ok_or_else(|| {
                build_error_with(
                    BuildErrorKind::ArithmeticOverflow {
                        computation: "ordered word end",
                    },
                    prospective,
                    actual,
                )
            })?;
            if end > word_bytes {
                return Err(build_error_with(
                    BuildErrorKind::DimensionMismatch {
                        dimension: "word bytes",
                        declared: word_bytes,
                        observed: end,
                    },
                    prospective,
                    actual,
                ));
            }
            words.try_push(Word { start, end }).map_err(|_| {
                build_error_with(
                    BuildErrorKind::InternalInvariant("exact word metadata capacity changed"),
                    prospective,
                    actual,
                )
            })?;
            actual.items = add_build_usize(
                actual.items,
                1,
                "ordered word copied items",
                prospective,
                actual,
            )?;
            actual.initialized_bytes = add_build_usize(
                actual.initialized_bytes,
                size_of::<Word>(),
                "ordered word initialized metadata",
                prospective,
                actual,
            )?;
            for &byte in word {
                digest.write_byte(byte);
                actual.build_work = add_build_u64(
                    actual.build_work,
                    1,
                    "ordered word byte work",
                    prospective,
                    actual,
                )?;
                bytes.try_push(byte).map_err(|_| {
                    build_error_with(
                        BuildErrorKind::InternalInvariant("exact word byte capacity changed"),
                        prospective,
                        actual,
                    )
                })?;
                actual.payload_bytes = add_build_usize(
                    actual.payload_bytes,
                    1,
                    "ordered word payload bytes",
                    prospective,
                    actual,
                )?;
                actual.identity_bytes = add_build_usize(
                    actual.identity_bytes,
                    1,
                    "ordered word identity bytes",
                    prospective,
                    actual,
                )?;
                actual.copied_bytes = add_build_usize(
                    actual.copied_bytes,
                    1,
                    "ordered word copied bytes",
                    prospective,
                    actual,
                )?;
                actual.initialized_bytes = add_build_usize(
                    actual.initialized_bytes,
                    1,
                    "ordered word initialized bytes",
                    prospective,
                    actual,
                )?;
            }
            start = end;
        }
        actual.build_work = add_build_u64(
            actual.build_work,
            1,
            "ordered word exhaustion validation",
            prospective,
            actual,
        )?;
        if source.next().is_some() {
            let observed = word_count.checked_add(1).ok_or_else(|| {
                build_error_with(
                    BuildErrorKind::ArithmeticOverflow {
                        computation: "observed ordered word count",
                    },
                    prospective,
                    actual,
                )
            })?;
            return Err(build_error_with(
                BuildErrorKind::DimensionMismatch {
                    dimension: "word count",
                    declared: word_count,
                    observed,
                },
                prospective,
                actual,
            ));
        }
        if bytes.len() != word_bytes {
            return Err(build_error_with(
                BuildErrorKind::DimensionMismatch {
                    dimension: "word bytes",
                    declared: word_bytes,
                    observed: bytes.len(),
                },
                prospective,
                actual,
            ));
        }
        actual.items = word_count;
        actual.copied_bytes = word_bytes;
        actual.payload_bytes = word_bytes;
        actual.identity_bytes = prospective.identity_bytes;
        actual.retained_heap_bytes = retained_heap;
        actual.initialized_bytes = retained_heap;
        actual.build_work = expected_build_work;
        actual.persistent_bytes = prospective.persistent_bytes;
        actual.peak_bytes = prospective.peak_bytes;
        actual.published = true;
        validate_build_actual(prospective, actual)?;
        Ok(Self {
            descriptor: Descriptor::WholeOrderedWords { bytes, words },
            identity,
            content_digest: digest.finish(),
            build: BuildAccounting {
                prospective,
                actual,
            },
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the transactional builder maintains one explicit cumulative receipt ledger"
    )]
    pub fn build_start_ordered_prefix(
        prefix: &[u8],
        mut alternatives: impl ExactSizeIterator<Item = u8>,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        let alternative_count = alternatives.len();
        if prefix.is_empty() || alternative_count == 0 {
            return Err(build_error(BuildErrorKind::EmptyDescriptor));
        }
        let width = prefix.len().checked_add(1).ok_or_else(|| {
            build_error(BuildErrorKind::ArithmeticOverflow {
                computation: "ordered prefix width",
            })
        })?;
        let items = prefix.len().checked_add(alternative_count).ok_or_else(|| {
            build_error(BuildErrorKind::ArithmeticOverflow {
                computation: "ordered prefix item count",
            })
        })?;
        let identity = DescriptorIdentity::StartOrderedPrefix {
            width,
            alternatives: alternative_count,
        };
        let payload = items;
        let work = items
            .checked_add(1)
            .and_then(|work| u64::try_from(work).ok())
            .ok_or_else(|| {
                build_error(BuildErrorKind::ArithmeticOverflow {
                    computation: "ordered prefix build work",
                })
            })?;
        let prospective = Self::start_ordered_prefix_prospective(prefix.len(), alternative_count)?;
        enforce_build(prospective, limits)?;
        let mut digest = ContentDigestBuilder::new(DescriptorKind::StartOrderedPrefix);
        digest.write_usize(width);
        digest.write_usize(alternative_count);
        let mut actual = BuildActual {
            identity_bytes: FIXED_IDENTITY_BYTES,
            ..BuildActual::default()
        };
        let mut retained_prefix = allocate_exact(prefix.len()).map_err(|error| {
            allocation_error(
                error,
                "ordered prefix bytes",
                prefix.len(),
                prospective,
                actual,
            )
        })?;
        actual.allocations = 1;
        actual.retained_heap_bytes = prefix.len();
        actual.persistent_bytes = prefix.len();
        actual.peak_bytes = prefix.len();
        for &byte in prefix {
            digest.write_byte(byte);
            actual.build_work = add_build_u64(
                actual.build_work,
                1,
                "ordered prefix byte work",
                prospective,
                actual,
            )?;
            retained_prefix.try_push(byte).map_err(|_| {
                build_error_with(
                    BuildErrorKind::InternalInvariant("exact prefix capacity changed"),
                    prospective,
                    actual,
                )
            })?;
            actual.items = add_build_usize(
                actual.items,
                1,
                "ordered prefix copied items",
                prospective,
                actual,
            )?;
            actual.payload_bytes = add_build_usize(
                actual.payload_bytes,
                1,
                "ordered prefix payload bytes",
                prospective,
                actual,
            )?;
            actual.identity_bytes = add_build_usize(
                actual.identity_bytes,
                1,
                "ordered prefix identity bytes",
                prospective,
                actual,
            )?;
            actual.copied_bytes = add_build_usize(
                actual.copied_bytes,
                1,
                "ordered prefix copied bytes",
                prospective,
                actual,
            )?;
            actual.initialized_bytes = add_build_usize(
                actual.initialized_bytes,
                1,
                "ordered prefix initialized bytes",
                prospective,
                actual,
            )?;
        }
        let mut retained_alternatives = allocate_exact(alternative_count).map_err(|error| {
            allocation_error(
                error,
                "ordered prefix alternatives",
                alternative_count,
                prospective,
                actual,
            )
        })?;
        actual.allocations = 2;
        actual.retained_heap_bytes = payload;
        actual.persistent_bytes = payload;
        actual.peak_bytes = payload;
        for index in 0..alternative_count {
            actual.build_work = add_build_u64(
                actual.build_work,
                1,
                "ordered prefix alternative work",
                prospective,
                actual,
            )?;
            let Some(byte) = alternatives.next() else {
                return Err(build_error_with(
                    BuildErrorKind::DimensionMismatch {
                        dimension: "prefix alternative count",
                        declared: alternative_count,
                        observed: index,
                    },
                    prospective,
                    actual,
                ));
            };
            digest.write_byte(byte);
            retained_alternatives.try_push(byte).map_err(|_| {
                build_error_with(
                    BuildErrorKind::InternalInvariant("exact prefix alternative capacity changed"),
                    prospective,
                    actual,
                )
            })?;
            actual.items = add_build_usize(
                actual.items,
                1,
                "ordered prefix alternative items",
                prospective,
                actual,
            )?;
            actual.payload_bytes = add_build_usize(
                actual.payload_bytes,
                1,
                "ordered prefix alternative payload",
                prospective,
                actual,
            )?;
            actual.identity_bytes = add_build_usize(
                actual.identity_bytes,
                1,
                "ordered prefix alternative identity",
                prospective,
                actual,
            )?;
            actual.copied_bytes = add_build_usize(
                actual.copied_bytes,
                1,
                "ordered prefix alternative copy",
                prospective,
                actual,
            )?;
            actual.initialized_bytes = add_build_usize(
                actual.initialized_bytes,
                1,
                "ordered prefix alternative initialization",
                prospective,
                actual,
            )?;
        }
        actual.build_work = add_build_u64(
            actual.build_work,
            1,
            "ordered prefix exhaustion validation",
            prospective,
            actual,
        )?;
        if alternatives.next().is_some() {
            let observed = alternative_count.checked_add(1).ok_or_else(|| {
                build_error_with(
                    BuildErrorKind::ArithmeticOverflow {
                        computation: "observed prefix alternative count",
                    },
                    prospective,
                    actual,
                )
            })?;
            return Err(build_error_with(
                BuildErrorKind::DimensionMismatch {
                    dimension: "prefix alternative count",
                    declared: alternative_count,
                    observed,
                },
                prospective,
                actual,
            ));
        }
        actual.items = items;
        actual.payload_bytes = payload;
        actual.identity_bytes = prospective.identity_bytes;
        actual.retained_heap_bytes = payload;
        actual.copied_bytes = payload;
        actual.allocations = 2;
        actual.initialized_bytes = payload;
        actual.build_work = work;
        actual.persistent_bytes = prospective.persistent_bytes;
        actual.peak_bytes = prospective.peak_bytes;
        actual.published = true;
        validate_build_actual(prospective, actual)?;
        Ok(Self {
            descriptor: Descriptor::StartOrderedPrefix {
                prefix: retained_prefix,
                alternatives: retained_alternatives,
            },
            identity,
            content_digest: digest.finish(),
            build: BuildAccounting {
                prospective,
                actual,
            },
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the transactional scalar builder retains one explicit cumulative receipt ledger"
    )]
    pub fn build_whole_scalar_envelope_precounted(
        scalars: u32,
        range_count: usize,
        mut ranges: impl ExactSizeIterator<Item = (u32, u32)>,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        let prospective = Self::whole_scalar_envelope_prospective(scalars, range_count)?;
        enforce_build(prospective, limits)?;
        let mut actual = BuildActual {
            identity_bytes: FIXED_IDENTITY_BYTES,
            build_work: 1,
            ..BuildActual::default()
        };
        let source_range_count = ranges.len();
        if source_range_count != range_count {
            return Err(build_error_with(
                BuildErrorKind::DimensionMismatch {
                    dimension: "scalar range count",
                    declared: range_count,
                    observed: source_range_count,
                },
                prospective,
                actual,
            ));
        }
        let mut digest = ContentDigestBuilder::new(DescriptorKind::WholeScalarEnvelope);
        digest.write_u32(scalars);
        digest.write_usize(range_count);
        for index in 0..range_count {
            actual.build_work = add_build_u64(
                actual.build_work,
                1,
                "scalar range content work",
                prospective,
                actual,
            )?;
            let Some((start, end)) = ranges.next() else {
                return Err(build_error_with(
                    BuildErrorKind::DimensionMismatch {
                        dimension: "scalar range count",
                        declared: range_count,
                        observed: index,
                    },
                    prospective,
                    actual,
                ));
            };
            digest.write_u32(start);
            digest.write_u32(end);
        }
        actual.build_work = add_build_u64(
            actual.build_work,
            1,
            "scalar range exhaustion validation",
            prospective,
            actual,
        )?;
        if ranges.next().is_some() {
            let observed = range_count.checked_add(1).ok_or_else(|| {
                build_error_with(
                    BuildErrorKind::ArithmeticOverflow {
                        computation: "observed scalar range count",
                    },
                    prospective,
                    actual,
                )
            })?;
            return Err(build_error_with(
                BuildErrorKind::DimensionMismatch {
                    dimension: "scalar range count",
                    declared: range_count,
                    observed,
                },
                prospective,
                actual,
            ));
        }
        actual.items = prospective.items;
        actual.payload_bytes = prospective.payload_bytes;
        actual.identity_bytes = prospective.identity_bytes;
        actual.retained_heap_bytes = prospective.retained_heap_bytes;
        actual.copied_bytes = prospective.copied_bytes;
        actual.allocations = prospective.allocations;
        actual.initialized_bytes = prospective.initialized_bytes;
        actual.build_work = prospective.build_work;
        actual.scratch_bytes = prospective.scratch_bytes;
        actual.persistent_bytes = prospective.persistent_bytes;
        actual.peak_bytes = prospective.peak_bytes;
        actual.published = true;
        validate_build_actual(prospective, actual)?;
        let DescriptorIdentity::WholeScalarEnvelope {
            minimum_bytes,
            maximum_bytes,
            ..
        } = prospective.descriptor
        else {
            return Err(build_error_with(
                BuildErrorKind::InternalInvariant("scalar prospective changed descriptor family"),
                prospective,
                BuildActual::default(),
            ));
        };
        Ok(Self {
            descriptor: Descriptor::WholeScalarEnvelope {
                minimum_bytes,
                maximum_bytes,
            },
            identity: prospective.descriptor,
            content_digest: digest.finish(),
            build: BuildAccounting {
                prospective,
                actual,
            },
        })
    }

    /// Allocation-free construction prospective for the scalar guard.
    #[doc(hidden)]
    pub fn whole_scalar_envelope_prospective(
        scalars: u32,
        range_count: usize,
    ) -> Result<BuildProspective, BuildError> {
        if scalars == 0 {
            return Err(build_error(BuildErrorKind::ZeroScalarCount));
        }
        if range_count == 0 {
            return Err(build_error(BuildErrorKind::EmptyDescriptor));
        }
        let minimum_bytes = usize::try_from(scalars).map_err(|_| {
            build_error(BuildErrorKind::ArithmeticOverflow {
                computation: "scalar envelope minimum bytes",
            })
        })?;
        let maximum_bytes = minimum_bytes.checked_mul(4).ok_or_else(|| {
            build_error(BuildErrorKind::ArithmeticOverflow {
                computation: "scalar envelope maximum bytes",
            })
        })?;
        let identity = DescriptorIdentity::WholeScalarEnvelope {
            scalars,
            minimum_bytes,
            maximum_bytes,
        };
        let scalar_payload = size_of::<u32>();
        let scalar_items = usize::try_from(scalars).map_err(|_| {
            build_error(BuildErrorKind::ArithmeticOverflow {
                computation: "scalar count as items",
            })
        })?;
        let build_work = range_count
            .checked_add(2)
            .and_then(|work| u64::try_from(work).ok())
            .ok_or_else(|| {
                build_error(BuildErrorKind::ArithmeticOverflow {
                    computation: "scalar range content work",
                })
            })?;
        prospective(
            identity,
            scalar_items,
            scalar_payload,
            0,
            0,
            0,
            scalar_payload,
            build_work,
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the transactional builder maintains one explicit cumulative receipt ledger"
    )]
    fn build_masks(
        mut masks: impl ExactSizeIterator<Item = ByteMask>,
        start_anchored: bool,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        let count = masks.len();
        if count == 0 {
            return Err(build_error(BuildErrorKind::EmptyDescriptor));
        }
        if !start_anchored && count == 1 {
            return Err(build_error(BuildErrorKind::InternalInvariant(
                "one-byte endpoint must use EndOneByteMask",
            )));
        }
        let identity = if start_anchored {
            DescriptorIdentity::StartMaskSequence { width: count }
        } else {
            DescriptorIdentity::EndMaskSequence { width: count }
        };
        let kind = if start_anchored {
            DescriptorKind::StartMaskSequence
        } else {
            DescriptorKind::EndMaskSequence
        };
        let payload = count.checked_mul(size_of::<ByteMask>()).ok_or_else(|| {
            build_error(BuildErrorKind::ArithmeticOverflow {
                computation: "mask payload bytes",
            })
        })?;
        let work = count
            .checked_add(1)
            .and_then(|work| u64::try_from(work).ok())
            .ok_or_else(|| {
                build_error(BuildErrorKind::ArithmeticOverflow {
                    computation: "mask build work",
                })
            })?;
        let prospective = if start_anchored {
            Self::start_mask_sequence_prospective(count)?
        } else {
            Self::end_mask_sequence_prospective(count)?
        };
        enforce_build(prospective, limits)?;
        let mut digest = ContentDigestBuilder::new(kind);
        digest.write_usize(count);
        let mut actual = BuildActual {
            identity_bytes: FIXED_IDENTITY_BYTES,
            ..BuildActual::default()
        };
        let mut retained = allocate_exact(count).map_err(|error| {
            allocation_error(error, "positional masks", count, prospective, actual)
        })?;
        actual.allocations = 1;
        actual.retained_heap_bytes = payload;
        actual.persistent_bytes = payload;
        actual.peak_bytes = payload;
        for index in 0..count {
            actual.build_work = add_build_u64(
                actual.build_work,
                1,
                "positional mask copy work",
                prospective,
                actual,
            )?;
            let Some(mask) = masks.next() else {
                return Err(build_error_with(
                    BuildErrorKind::DimensionMismatch {
                        dimension: "mask count",
                        declared: count,
                        observed: index,
                    },
                    prospective,
                    actual,
                ));
            };
            if mask.is_empty() {
                return Err(build_error_with(
                    BuildErrorKind::EmptyDescriptor,
                    prospective,
                    actual,
                ));
            }
            for word in mask.words() {
                digest.write_u64(word);
            }
            retained.try_push(mask).map_err(|_| {
                build_error_with(
                    BuildErrorKind::InternalInvariant("exact mask capacity changed"),
                    prospective,
                    actual,
                )
            })?;
            actual.items = add_build_usize(
                actual.items,
                1,
                "positional mask copied items",
                prospective,
                actual,
            )?;
            actual.payload_bytes = add_build_usize(
                actual.payload_bytes,
                size_of::<ByteMask>(),
                "positional mask payload bytes",
                prospective,
                actual,
            )?;
            actual.identity_bytes = add_build_usize(
                actual.identity_bytes,
                size_of::<ByteMask>(),
                "positional mask identity bytes",
                prospective,
                actual,
            )?;
            actual.copied_bytes = add_build_usize(
                actual.copied_bytes,
                size_of::<ByteMask>(),
                "positional mask copied bytes",
                prospective,
                actual,
            )?;
            actual.initialized_bytes = add_build_usize(
                actual.initialized_bytes,
                size_of::<ByteMask>(),
                "positional mask initialized bytes",
                prospective,
                actual,
            )?;
        }
        actual.build_work = add_build_u64(
            actual.build_work,
            1,
            "mask iterator exhaustion validation",
            prospective,
            actual,
        )?;
        if masks.next().is_some() {
            let observed = count.checked_add(1).ok_or_else(|| {
                build_error_with(
                    BuildErrorKind::ArithmeticOverflow {
                        computation: "observed mask count",
                    },
                    prospective,
                    actual,
                )
            })?;
            return Err(build_error_with(
                BuildErrorKind::DimensionMismatch {
                    dimension: "mask count",
                    declared: count,
                    observed,
                },
                prospective,
                actual,
            ));
        }
        actual.items = count;
        actual.payload_bytes = payload;
        actual.identity_bytes = prospective.identity_bytes;
        actual.retained_heap_bytes = payload;
        actual.copied_bytes = payload;
        actual.initialized_bytes = payload;
        actual.build_work = work;
        actual.persistent_bytes = prospective.persistent_bytes;
        actual.peak_bytes = prospective.peak_bytes;
        actual.published = true;
        validate_build_actual(prospective, actual)?;
        let descriptor = Descriptor::MaskSequence(retained);
        Ok(Self {
            descriptor,
            identity,
            content_digest: digest.finish(),
            build: BuildAccounting {
                prospective,
                actual,
            },
        })
    }

    #[must_use]
    pub const fn descriptor_identity(&self) -> DescriptorIdentity {
        self.identity
    }

    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.build
    }

    #[must_use]
    pub const fn count_identity(&self) -> OperationIdentity {
        self.operation_identity(Operation::Count)
    }

    #[must_use]
    pub const fn span_sum_identity(&self) -> OperationIdentity {
        self.operation_identity(Operation::SpanSum)
    }

    const fn operation_identity(&self, operation: Operation) -> OperationIdentity {
        OperationIdentity {
            plan_id: PLAN_ID,
            algorithm_version: ALGORITHM_VERSION,
            accounting_version: ACCOUNTING_VERSION,
            operation_id: match operation {
                Operation::Count => COUNT_OPERATION_ID,
                Operation::SpanSum => SPAN_SUM_OPERATION_ID,
            },
            operation,
            descriptor: self.identity,
            content_digest: self.content_digest,
            residual: if matches!(
                self.identity,
                DescriptorIdentity::WholeScalarEnvelope { .. }
            ) {
                DeclaredResidual::PrepublishedContinuation
            } else {
                DeclaredResidual::None
            },
            original_haystack_anchors: true,
            non_overlapping: true,
        }
    }

    pub fn count(&self, haystack: &[u8], limits: ReduceLimits) -> Result<CountResult, ReduceError> {
        self.count_in(haystack, Window::full(haystack), limits)
    }

    /// Return only a successfully admitted complete count without
    /// materializing a success receipt.
    ///
    /// `None` deliberately carries no terminal error and also represents the
    /// prepublished-continuation disposition. Callers that publish an error or
    /// continue a residual must replay [`Self::count`] with the same arguments
    /// so the operation retains its complete authenticated receipt.
    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub fn count_value_success(&self, haystack: &[u8], limits: ReduceLimits) -> Option<u64> {
        let admission = self.value_preflight(haystack, Operation::Count, limits)?;
        if admission.prospective.disposition != Disposition::Complete {
            return None;
        }
        let compact = self.compact_value_match(haystack, admission.candidate_active)?;
        let count = u64::from(compact.matched);
        (compact.variable_span.is_none()
            && count <= admission.prospective.count
            && usize::try_from(count).ok()? <= admission.prospective.match_events)
            .then_some(count)
    }

    pub fn count_in(
        &self,
        haystack: &[u8],
        window: Window,
        limits: ReduceLimits,
    ) -> Result<CountResult, ReduceError> {
        let admission = self.preflight(haystack.len(), window, Operation::Count, limits)?;
        self.count_admitted(haystack, admission)
    }

    /// Complete a count admission without repeating or changing branch
    /// selection. The scalar-envelope disposition performs no source access.
    pub fn count_admitted(
        &self,
        haystack: &[u8],
        admission: Admission<'_>,
    ) -> Result<CountResult, ReduceError> {
        if admission.operation != Operation::Count {
            return Err(invocation_error(
                ReduceErrorKind::AdmissionMismatch,
                admission.invocation(haystack.len()),
                Some(admission.prospective),
                ReduceActual::default(),
            ));
        }
        let actual = self.execute(haystack, &admission)?;
        let outcome = match admission.prospective.disposition {
            Disposition::Complete => CountOutcome::Complete {
                count: actual.count,
            },
            Disposition::PrepublishedContinuation => CountOutcome::PrepublishedContinuation,
        };
        Ok(CountResult {
            outcome,
            accounting: ReduceAccounting {
                identity: self.count_identity(),
                window: admission.window,
                haystack_len: haystack.len(),
                prospective: admission.prospective,
                actual,
            },
        })
    }

    pub fn span_sum(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<SpanSumResult, ReduceError> {
        self.span_sum_in(haystack, Window::full(haystack), limits)
    }

    /// Return only a successfully admitted span sum without materializing a
    /// success receipt.
    ///
    /// `None` deliberately carries no terminal error. Callers that publish an
    /// error must replay [`Self::span_sum`] with the same arguments so the
    /// refusal retains its complete authenticated receipt.
    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub fn span_sum_value_success(&self, haystack: &[u8], limits: ReduceLimits) -> Option<u64> {
        let admission = self.value_preflight(haystack, Operation::SpanSum, limits)?;
        if admission.prospective.disposition != Disposition::Complete {
            return None;
        }
        let compact = self.compact_value_match(haystack, admission.candidate_active)?;
        let span_sum = if compact.matched {
            match compact.variable_span {
                Some(span) => u64::try_from(span).ok()?,
                None => admission.prospective.span_sum,
            }
        } else {
            0
        };
        (span_sum <= admission.prospective.span_sum).then_some(span_sum)
    }

    pub fn span_sum_in(
        &self,
        haystack: &[u8],
        window: Window,
        limits: ReduceLimits,
    ) -> Result<SpanSumResult, ReduceError> {
        let admission = self.preflight(haystack.len(), window, Operation::SpanSum, limits)?;
        self.span_sum_admitted(haystack, admission)
    }

    /// Complete an already published span-sum admission.
    pub fn span_sum_admitted(
        &self,
        haystack: &[u8],
        admission: Admission<'_>,
    ) -> Result<SpanSumResult, ReduceError> {
        if admission.operation != Operation::SpanSum {
            return Err(invocation_error(
                ReduceErrorKind::AdmissionMismatch,
                admission.invocation(haystack.len()),
                Some(admission.prospective),
                ReduceActual::default(),
            ));
        }
        let actual = self.execute(haystack, &admission)?;
        Ok(SpanSumResult {
            span_sum: actual.span_sum,
            disposition: admission.prospective.disposition,
            accounting: ReduceAccounting {
                identity: self.span_sum_identity(),
                window: admission.window,
                haystack_len: haystack.len(),
                prospective: admission.prospective,
                actual,
            },
        })
    }

    /// Publish a complete length-only receipt. A successful admission does
    /// not borrow or inspect the source.
    pub fn preflight(
        &self,
        haystack_len: usize,
        window: Window,
        operation: Operation,
        limits: ReduceLimits,
    ) -> Result<Admission<'_>, ReduceError> {
        let invocation = Invocation {
            identity: self.operation_identity(operation),
            window,
            haystack_len,
        };
        if window.start() > window.end() || window.end() > haystack_len {
            return Err(invocation_error(
                ReduceErrorKind::InvalidWindow {
                    start: window.start(),
                    end: window.end(),
                    haystack_len,
                },
                invocation,
                None,
                ReduceActual::default(),
            ));
        }
        self.check_operation(operation)
            .map_err(|kind| invocation_error(kind, invocation, None, ReduceActual::default()))?;
        let candidate = self
            .candidate(haystack_len, window)
            .map_err(|kind| invocation_error(kind, invocation, None, ReduceActual::default()))?;
        let result_span = if operation == Operation::SpanSum {
            u64::try_from(candidate.span_sum).map_err(|_| {
                invocation_error(
                    ReduceErrorKind::ArithmeticOverflow {
                        computation: "prospective span sum",
                    },
                    invocation,
                    None,
                    ReduceActual::default(),
                )
            })?
        } else {
            0
        };
        let reducer_steps = 1_usize;
        let total_work = candidate
            .byte_probes
            .checked_add(candidate.branch_checks)
            .and_then(|work| work.checked_add(reducer_steps))
            .ok_or_else(|| {
                invocation_error(
                    ReduceErrorKind::ArithmeticOverflow {
                        computation: "prospective total work",
                    },
                    invocation,
                    None,
                    ReduceActual::default(),
                )
            })?;
        let persistent_bytes = self.build.actual.persistent_bytes;
        let prospective = ReduceProspective {
            disposition: candidate.disposition,
            byte_probes: candidate.byte_probes,
            branch_checks: candidate.branch_checks,
            match_events: candidate.match_events,
            count: candidate.count,
            span_sum: result_span,
            reducer_steps,
            total_work,
            allocations: 0,
            scratch_bytes: 0,
            persistent_bytes,
            peak_bytes: persistent_bytes,
        };
        enforce_reduce(prospective, limits, invocation)?;
        Ok(Admission {
            owner: self,
            identity: invocation.identity,
            haystack_len,
            window,
            operation,
            prospective,
            guard_checks: candidate.guard_checks,
            candidate_active: candidate.active,
        })
    }

    fn check_operation(&self, operation: Operation) -> Result<(), ReduceErrorKind> {
        let valid = match self.identity.kind() {
            DescriptorKind::EndMaskSequence
            | DescriptorKind::EndOneByteMask
            | DescriptorKind::EndGreedyClassLiteral
            | DescriptorKind::StartOrderedPrefix => operation == Operation::SpanSum,
            DescriptorKind::StartMaskSequence => {
                matches!(operation, Operation::Count | Operation::SpanSum)
            }
            DescriptorKind::WholeByteRepeat
            | DescriptorKind::WholeOrderedWords
            | DescriptorKind::WholeScalarEnvelope => operation == Operation::Count,
        };
        if valid {
            Ok(())
        } else {
            Err(ReduceErrorKind::OperationMismatch {
                descriptor: self.identity.kind(),
                operation,
            })
        }
    }

    fn candidate(&self, haystack_len: usize, window: Window) -> Result<Candidate, ReduceErrorKind> {
        let full = window.start() == 0 && window.end() == haystack_len;
        match &self.descriptor {
            Descriptor::MaskSequence(masks) => {
                if matches!(self.identity, DescriptorIdentity::StartMaskSequence { .. }) {
                    start_mask_candidate(haystack_len, window, masks.len())
                } else {
                    endpoint_candidate(haystack_len, window, masks.len())
                }
            }
            Descriptor::EndOneByteMask(_) => endpoint_candidate(haystack_len, window, 1),
            Descriptor::EndGreedyClassLiteral { suffix, .. } => {
                let Some(suffix_start) = haystack_len.checked_sub(suffix.len()) else {
                    return Ok(Candidate::complete_zero(1));
                };
                if window.end() == haystack_len && window.start() <= suffix_start {
                    // Admission deliberately reserves the complete original
                    // haystack even though a short observed tail may stop the
                    // reverse scan almost immediately.
                    Candidate::verify(haystack_len, 1, 0, haystack_len)
                } else {
                    Ok(Candidate::complete_zero(1))
                }
            }
            Descriptor::WholeByteRepeat {
                minimum, maximum, ..
            } => {
                let length = u32::try_from(haystack_len).ok();
                let eligible =
                    full && length.is_some_and(|length| *minimum <= length && length <= *maximum);
                Ok(if eligible {
                    Candidate::verify(haystack_len, 1, 0, haystack_len)?
                } else {
                    Candidate::complete_zero(1)
                })
            }
            Descriptor::WholeOrderedWords { words, .. } => {
                if !full {
                    return Ok(Candidate::complete_zero(1));
                }
                let mut probes = 0_usize;
                let mut branches = 0_usize;
                for word in words {
                    let length = word.end.checked_sub(word.start).ok_or(
                        ReduceErrorKind::ArithmeticOverflow {
                            computation: "ordered word length",
                        },
                    )?;
                    if length == haystack_len {
                        probes = probes.checked_add(length).ok_or(
                            ReduceErrorKind::ArithmeticOverflow {
                                computation: "ordered word probe bound",
                            },
                        )?;
                        branches =
                            branches
                                .checked_add(1)
                                .ok_or(ReduceErrorKind::ArithmeticOverflow {
                                    computation: "ordered word branch bound",
                                })?;
                    }
                }
                Ok(if branches == 0 {
                    Candidate::complete_zero(words.len())
                } else {
                    Candidate::verify(probes, words.len(), words.len(), haystack_len)?
                })
            }
            Descriptor::StartOrderedPrefix {
                prefix,
                alternatives,
            } => start_ordered_prefix_candidate(
                haystack_len,
                window,
                prefix.len(),
                alternatives.len(),
            ),
            Descriptor::WholeScalarEnvelope {
                minimum_bytes,
                maximum_bytes,
                ..
            } => {
                if full && *minimum_bytes <= haystack_len && haystack_len <= *maximum_bytes {
                    Ok(Candidate::delegate())
                } else {
                    Ok(Candidate::complete_zero(1))
                }
            }
        }
    }

    #[inline]
    fn value_preflight(
        &self,
        haystack: &[u8],
        operation: Operation,
        limits: ReduceLimits,
    ) -> Option<ValueAdmission> {
        self.check_operation(operation).ok()?;
        let candidate = self
            .candidate(haystack.len(), Window::full(haystack))
            .ok()?;
        let span_sum = if operation == Operation::SpanSum {
            u64::try_from(candidate.span_sum).ok()?
        } else {
            0
        };
        let reducer_steps = 1_usize;
        let total_work = candidate
            .byte_probes
            .checked_add(candidate.branch_checks)?
            .checked_add(reducer_steps)?;
        let persistent_bytes = self.build.actual.persistent_bytes;
        let prospective = ReduceProspective {
            disposition: candidate.disposition,
            byte_probes: candidate.byte_probes,
            branch_checks: candidate.branch_checks,
            match_events: candidate.match_events,
            count: candidate.count,
            span_sum,
            reducer_steps,
            total_work,
            allocations: 0,
            scratch_bytes: 0,
            persistent_bytes,
            peak_bytes: persistent_bytes,
        };
        if prospective.byte_probes > limits.max_byte_probes
            || prospective.branch_checks > limits.max_branch_checks
            || prospective.match_events > limits.max_match_events
            || prospective.count > limits.max_count
            || prospective.span_sum > limits.max_span_sum
            || prospective.reducer_steps > limits.max_reducer_steps
            || prospective.total_work > limits.max_total_work
            || prospective.scratch_bytes > limits.max_scratch_bytes
            || prospective.persistent_bytes > limits.max_persistent_bytes
            || prospective.peak_bytes > limits.max_peak_bytes
        {
            return None;
        }
        Some(ValueAdmission {
            prospective,
            candidate_active: candidate.active,
        })
    }

    #[inline]
    fn compact_value_match(&self, haystack: &[u8], candidate_active: bool) -> Option<CompactMatch> {
        if !candidate_active {
            return Some(CompactMatch {
                matched: false,
                variable_span: None,
            });
        }
        let result = match &self.descriptor {
            Descriptor::MaskSequence(masks) => {
                if matches!(self.identity, DescriptorIdentity::StartMaskSequence { .. }) {
                    let source = haystack.get(..masks.len())?;
                    source
                        .iter()
                        .zip(masks.iter())
                        .all(|(&byte, mask)| mask.contains(byte))
                } else {
                    let start = haystack.len().checked_sub(masks.len())?;
                    let source = haystack.get(start..)?;
                    source
                        .iter()
                        .zip(masks.iter())
                        .all(|(&byte, mask)| mask.contains(byte))
                }
            }
            Descriptor::EndOneByteMask(mask) => {
                let index = haystack.len().checked_sub(1)?;
                mask.contains(*haystack.get(index)?)
            }
            Descriptor::EndGreedyClassLiteral { class, suffix } => {
                let suffix_start = haystack.len().checked_sub(suffix.len())?;
                if haystack.get(suffix_start..)? != &**suffix {
                    return Some(CompactMatch {
                        matched: false,
                        variable_span: None,
                    });
                }
                let mut start = suffix_start;
                while start > 0 {
                    let index = start.checked_sub(1)?;
                    if !class.contains(*haystack.get(index)?) {
                        break;
                    }
                    start = index;
                }
                return Some(CompactMatch {
                    matched: true,
                    variable_span: Some(haystack.len().checked_sub(start)?),
                });
            }
            Descriptor::WholeByteRepeat { byte, .. } => {
                haystack.iter().all(|candidate| candidate == byte)
            }
            Descriptor::WholeOrderedWords { bytes, words } => words.iter().any(|word| {
                bytes
                    .get(word.start..word.end)
                    .is_some_and(|source| source == haystack)
            }),
            Descriptor::StartOrderedPrefix {
                prefix,
                alternatives,
            } => {
                let candidate = *haystack.get(prefix.len())?;
                haystack.get(..prefix.len())? == &**prefix && alternatives.contains(&candidate)
            }
            Descriptor::WholeScalarEnvelope { .. } => return None,
        };
        Some(CompactMatch {
            matched: result,
            variable_span: None,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "execution keeps admission validation, source accounting, and receipt validation together"
    )]
    fn execute(
        &self,
        haystack: &[u8],
        admission: &Admission<'_>,
    ) -> Result<ReduceActual, ReduceError> {
        if !core::ptr::eq(self, admission.owner)
            || admission.identity != self.operation_identity(admission.operation)
            || admission.haystack_len != haystack.len()
        {
            return Err(invocation_error(
                ReduceErrorKind::AdmissionMismatch,
                admission.invocation(haystack.len()),
                Some(admission.prospective),
                ReduceActual::default(),
            ));
        }
        let invocation = admission.invocation(haystack.len());
        let mut actual = ReduceActual {
            branch_checks: admission.guard_checks,
            reducer_steps: 1,
            persistent_bytes: admission.prospective.persistent_bytes,
            peak_bytes: admission.prospective.persistent_bytes,
            ..ReduceActual::default()
        };
        if admission.prospective.disposition == Disposition::PrepublishedContinuation {
            actual.total_work = actual
                .branch_checks
                .checked_add(actual.reducer_steps)
                .ok_or_else(|| {
                    invocation_error(
                        ReduceErrorKind::ArithmeticOverflow {
                            computation: "continuation guard work",
                        },
                        invocation,
                        Some(admission.prospective),
                        actual,
                    )
                })?;
            validate_actual(admission.prospective, actual, invocation)?;
            return Ok(actual);
        }
        let verified = if admission.candidate_active {
            match &self.descriptor {
                Descriptor::MaskSequence(masks) => {
                    if matches!(self.identity, DescriptorIdentity::StartMaskSequence { .. }) {
                        verify_start_masks(haystack, admission.window, masks, &mut actual)
                            .map(|matched| (matched, None))
                    } else {
                        verify_endpoint_masks(haystack, admission.window, masks, &mut actual)
                            .map(|matched| (matched, None))
                    }
                }
                Descriptor::EndOneByteMask(mask) => {
                    verify_endpoint_one(haystack, admission.window, *mask, &mut actual)
                        .map(|matched| (matched, None))
                }
                Descriptor::EndGreedyClassLiteral { class, suffix } => {
                    verify_end_greedy_class_literal(
                        haystack,
                        admission.window,
                        *class,
                        suffix,
                        &mut actual,
                    )
                    .map(|span| (span.is_some(), span))
                }
                Descriptor::WholeByteRepeat { byte, .. } => {
                    verify_whole_repeat(haystack, admission.window, *byte, &mut actual)
                        .map(|matched| (matched, None))
                }
                Descriptor::WholeOrderedWords { bytes, words } => {
                    verify_whole_words(haystack, admission.window, bytes, words, &mut actual)
                        .map(|matched| (matched, None))
                }
                Descriptor::StartOrderedPrefix {
                    prefix,
                    alternatives,
                } => verify_start_prefix(
                    haystack,
                    admission.window,
                    prefix,
                    alternatives,
                    &mut actual,
                )
                .map(|matched| (matched, None)),
                Descriptor::WholeScalarEnvelope { .. } => Ok((false, None)),
            }
        } else {
            Ok((false, None))
        };
        let (matched, verified_span) = match verified {
            Ok(value) => value,
            Err(kind) => {
                return Err(invocation_error(
                    kind,
                    invocation,
                    Some(admission.prospective),
                    actual,
                ));
            }
        };
        if matched {
            actual.match_events = 1;
            actual.count = 1;
            if admission.operation == Operation::SpanSum {
                actual.span_sum = if let Some(span) = verified_span {
                    u64::try_from(span).map_err(|_| {
                        invocation_error(
                            ReduceErrorKind::ArithmeticOverflow {
                                computation: "actual span sum",
                            },
                            invocation,
                            Some(admission.prospective),
                            actual,
                        )
                    })?
                } else {
                    admission.prospective.span_sum
                };
            }
        }
        actual.total_work = actual
            .byte_probes
            .checked_add(actual.branch_checks)
            .and_then(|work| work.checked_add(actual.reducer_steps))
            .ok_or_else(|| {
                invocation_error(
                    ReduceErrorKind::ArithmeticOverflow {
                        computation: "actual total work",
                    },
                    invocation,
                    Some(admission.prospective),
                    actual,
                )
            })?;
        validate_actual(admission.prospective, actual, invocation)?;
        Ok(actual)
    }
}

/// Immutable proof that every caller limit accepted a specific invocation.
#[derive(Clone, Copy, Debug)]
pub struct Admission<'plan> {
    owner: &'plan FixedAbsoluteDomainPlan,
    identity: OperationIdentity,
    haystack_len: usize,
    window: Window,
    operation: Operation,
    prospective: ReduceProspective,
    guard_checks: usize,
    candidate_active: bool,
}

impl Admission<'_> {
    #[must_use]
    pub const fn disposition(&self) -> Disposition {
        self.prospective.disposition
    }

    #[must_use]
    pub const fn prospective(&self) -> ReduceProspective {
        self.prospective
    }

    const fn invocation(&self, haystack_len: usize) -> Invocation {
        Invocation {
            identity: self.identity,
            window: self.window,
            haystack_len,
        }
    }
}

#[derive(Clone, Copy)]
struct Invocation {
    identity: OperationIdentity,
    window: Window,
    haystack_len: usize,
}

#[derive(Clone, Copy)]
struct Candidate {
    disposition: Disposition,
    guard_checks: usize,
    active: bool,
    byte_probes: usize,
    branch_checks: usize,
    match_events: usize,
    count: u64,
    span_sum: usize,
}

impl Candidate {
    const fn complete_zero(guard_checks: usize) -> Self {
        Self {
            disposition: Disposition::Complete,
            guard_checks,
            active: false,
            byte_probes: 0,
            branch_checks: guard_checks,
            match_events: 0,
            count: 0,
            span_sum: 0,
        }
    }

    fn verify(
        byte_probes: usize,
        guard_checks: usize,
        verifier_branch_checks: usize,
        span_sum: usize,
    ) -> Result<Self, ReduceErrorKind> {
        let branch_checks = guard_checks.checked_add(verifier_branch_checks).ok_or(
            ReduceErrorKind::ArithmeticOverflow {
                computation: "candidate branch checks",
            },
        )?;
        Ok(Self {
            disposition: Disposition::Complete,
            guard_checks,
            active: true,
            byte_probes,
            branch_checks,
            match_events: 1,
            count: 1,
            span_sum,
        })
    }

    const fn delegate() -> Self {
        Self {
            disposition: Disposition::PrepublishedContinuation,
            guard_checks: 1,
            active: false,
            byte_probes: 0,
            branch_checks: 1,
            match_events: 0,
            count: 0,
            span_sum: 0,
        }
    }
}

fn endpoint_candidate(
    haystack_len: usize,
    window: Window,
    width: usize,
) -> Result<Candidate, ReduceErrorKind> {
    let Some(start) = haystack_len.checked_sub(width) else {
        return Ok(Candidate::complete_zero(1));
    };
    if window.start() <= start && window.end() == haystack_len {
        Candidate::verify(width, 1, 0, width)
    } else {
        Ok(Candidate::complete_zero(1))
    }
}

fn start_mask_candidate(
    haystack_len: usize,
    window: Window,
    width: usize,
) -> Result<Candidate, ReduceErrorKind> {
    let eligible = window.start() == 0 && width <= window.end() && width <= haystack_len;
    Ok(if eligible {
        Candidate::verify(width, 1, 0, width)?
    } else {
        Candidate::complete_zero(1)
    })
}

fn start_ordered_prefix_candidate(
    haystack_len: usize,
    window: Window,
    prefix_bytes: usize,
    alternatives: usize,
) -> Result<Candidate, ReduceErrorKind> {
    let width = prefix_bytes
        .checked_add(1)
        .ok_or(ReduceErrorKind::ArithmeticOverflow {
            computation: "ordered prefix width",
        })?;
    let eligible = window.start() == 0 && width <= window.end() && width <= haystack_len;
    Ok(if eligible {
        let probes =
            prefix_bytes
                .checked_add(alternatives)
                .ok_or(ReduceErrorKind::ArithmeticOverflow {
                    computation: "ordered prefix probe bound",
                })?;
        Candidate::verify(probes, 1, alternatives, width)?
    } else {
        Candidate::complete_zero(1)
    })
}

fn verify_endpoint_masks(
    haystack: &[u8],
    window: Window,
    masks: &[ByteMask],
    actual: &mut ReduceActual,
) -> Result<bool, ReduceErrorKind> {
    let Some(start) = haystack.len().checked_sub(masks.len()) else {
        return Ok(false);
    };
    if window.start() > start || window.end() != haystack.len() {
        return Ok(false);
    }
    for (offset, mask) in masks.iter().enumerate() {
        let index = start
            .checked_add(offset)
            .ok_or(ReduceErrorKind::ArithmeticOverflow {
                computation: "endpoint mask index",
            })?;
        let byte = *haystack
            .get(index)
            .ok_or(ReduceErrorKind::ArithmeticOverflow {
                computation: "endpoint source access",
            })?;
        record_probe(actual)?;
        if !mask.contains(byte) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn verify_start_masks(
    haystack: &[u8],
    window: Window,
    masks: &[ByteMask],
    actual: &mut ReduceActual,
) -> Result<bool, ReduceErrorKind> {
    if window.start() != 0 || masks.len() > window.end() || masks.len() > haystack.len() {
        return Ok(false);
    }
    for (index, mask) in masks.iter().enumerate() {
        let byte = *haystack
            .get(index)
            .ok_or(ReduceErrorKind::ArithmeticOverflow {
                computation: "start mask source access",
            })?;
        record_probe(actual)?;
        if !mask.contains(byte) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn verify_endpoint_one(
    haystack: &[u8],
    window: Window,
    mask: ByteMask,
    actual: &mut ReduceActual,
) -> Result<bool, ReduceErrorKind> {
    let Some(index) = haystack.len().checked_sub(1) else {
        return Ok(false);
    };
    if window.start() > index || window.end() != haystack.len() {
        return Ok(false);
    }
    let byte = *haystack
        .get(index)
        .ok_or(ReduceErrorKind::ArithmeticOverflow {
            computation: "one-byte endpoint access",
        })?;
    record_probe(actual)?;
    Ok(mask.contains(byte))
}

fn verify_end_greedy_class_literal(
    haystack: &[u8],
    window: Window,
    class: ByteMask,
    suffix: &[u8],
    actual: &mut ReduceActual,
) -> Result<Option<usize>, ReduceErrorKind> {
    let Some(suffix_start) = haystack.len().checked_sub(suffix.len()) else {
        return Ok(None);
    };
    if window.end() != haystack.len() || window.start() > suffix_start {
        return Ok(None);
    }
    for (offset, &expected) in suffix.iter().enumerate() {
        let index =
            suffix_start
                .checked_add(offset)
                .ok_or(ReduceErrorKind::ArithmeticOverflow {
                    computation: "terminal suffix index",
                })?;
        let byte = *haystack
            .get(index)
            .ok_or(ReduceErrorKind::ArithmeticOverflow {
                computation: "terminal suffix source access",
            })?;
        record_probe(actual)?;
        if byte != expected {
            return Ok(None);
        }
    }

    let mut start = suffix_start;
    while start > window.start() {
        let index = start
            .checked_sub(1)
            .ok_or(ReduceErrorKind::ArithmeticOverflow {
                computation: "terminal predecessor index",
            })?;
        let byte = *haystack
            .get(index)
            .ok_or(ReduceErrorKind::ArithmeticOverflow {
                computation: "terminal predecessor source access",
            })?;
        record_probe(actual)?;
        if !class.contains(byte) {
            break;
        }
        start = index;
    }
    haystack
        .len()
        .checked_sub(start)
        .map(Some)
        .ok_or(ReduceErrorKind::ArithmeticOverflow {
            computation: "terminal greedy span",
        })
}

fn verify_whole_repeat(
    haystack: &[u8],
    window: Window,
    byte: u8,
    actual: &mut ReduceActual,
) -> Result<bool, ReduceErrorKind> {
    if window.start() != 0 || window.end() != haystack.len() {
        return Ok(false);
    }
    if haystack.is_empty() {
        return Ok(true);
    }
    for &candidate in haystack {
        record_probe(actual)?;
        if candidate != byte {
            return Ok(false);
        }
    }
    Ok(true)
}

fn verify_whole_words(
    haystack: &[u8],
    window: Window,
    bytes: &[u8],
    words: &[Word],
    actual: &mut ReduceActual,
) -> Result<bool, ReduceErrorKind> {
    if window.start() != 0 || window.end() != haystack.len() {
        return Ok(false);
    }
    for (ordinal, word) in words.iter().enumerate() {
        actual.branch_checks =
            actual
                .branch_checks
                .checked_add(1)
                .ok_or(ReduceErrorKind::ArithmeticOverflow {
                    computation: "actual ordered word branch checks",
                })?;
        let source =
            bytes
                .get(word.start..word.end)
                .ok_or(ReduceErrorKind::ArithmeticOverflow {
                    computation: "ordered word source range",
                })?;
        if source.len() != haystack.len() {
            continue;
        }
        let mut matches = true;
        for (&left, &right) in haystack.iter().zip(source) {
            record_probe(actual)?;
            if left != right {
                matches = false;
                break;
            }
        }
        if matches {
            actual.selected_branch_ordinal = Some(ordinal);
            return Ok(true);
        }
    }
    Ok(false)
}

fn verify_start_prefix(
    haystack: &[u8],
    window: Window,
    prefix: &[u8],
    alternatives: &[u8],
    actual: &mut ReduceActual,
) -> Result<bool, ReduceErrorKind> {
    let Some(width) = prefix.len().checked_add(1) else {
        return Err(ReduceErrorKind::ArithmeticOverflow {
            computation: "actual ordered prefix width",
        });
    };
    if window.start() != 0 || width > window.end() || width > haystack.len() {
        return Ok(false);
    }
    for (index, &expected) in prefix.iter().enumerate() {
        let byte = *haystack
            .get(index)
            .ok_or(ReduceErrorKind::ArithmeticOverflow {
                computation: "start prefix source access",
            })?;
        record_probe(actual)?;
        if expected != byte {
            return Ok(false);
        }
    }
    let candidate = *haystack
        .get(prefix.len())
        .ok_or(ReduceErrorKind::ArithmeticOverflow {
            computation: "start prefix alternative access",
        })?;
    record_source_access(actual)?;
    for (ordinal, &expected) in alternatives.iter().enumerate() {
        actual.branch_checks =
            actual
                .branch_checks
                .checked_add(1)
                .ok_or(ReduceErrorKind::ArithmeticOverflow {
                    computation: "start prefix alternative checks",
                })?;
        record_byte_probe(actual)?;
        if expected == candidate {
            actual.selected_branch_ordinal = Some(ordinal);
            return Ok(true);
        }
    }
    Ok(false)
}

fn record_probe(actual: &mut ReduceActual) -> Result<(), ReduceErrorKind> {
    record_byte_probe(actual)?;
    record_source_access(actual)
}

fn record_byte_probe(actual: &mut ReduceActual) -> Result<(), ReduceErrorKind> {
    actual.byte_probes =
        actual
            .byte_probes
            .checked_add(1)
            .ok_or(ReduceErrorKind::ArithmeticOverflow {
                computation: "actual byte probes",
            })?;
    Ok(())
}

fn record_source_access(actual: &mut ReduceActual) -> Result<(), ReduceErrorKind> {
    actual.source_accesses =
        actual
            .source_accesses
            .checked_add(1)
            .ok_or(ReduceErrorKind::ArithmeticOverflow {
                computation: "actual source accesses",
            })?;
    Ok(())
}

#[allow(
    clippy::result_large_err,
    clippy::too_many_arguments,
    reason = "the closed prospective receipt keeps every independently limited construction dimension explicit"
)]
fn prospective(
    descriptor: DescriptorIdentity,
    items: usize,
    payload_bytes: usize,
    retained_heap_bytes: usize,
    copied_bytes: usize,
    allocations: usize,
    initialized_bytes: usize,
    build_work: u64,
) -> Result<BuildProspective, BuildError> {
    let identity_bytes = FIXED_IDENTITY_BYTES
        .checked_add(payload_bytes)
        .ok_or_else(|| {
            build_error(BuildErrorKind::ArithmeticOverflow {
                computation: "identity bytes",
            })
        })?;
    let persistent_bytes = size_of::<FixedAbsoluteDomainPlan>()
        .checked_add(retained_heap_bytes)
        .ok_or_else(|| {
            build_error(BuildErrorKind::ArithmeticOverflow {
                computation: "persistent bytes",
            })
        })?;
    Ok(BuildProspective {
        descriptor,
        items,
        payload_bytes,
        identity_bytes,
        retained_heap_bytes,
        copied_bytes,
        allocations,
        initialized_bytes,
        build_work,
        scratch_bytes: 0,
        persistent_bytes,
        peak_bytes: persistent_bytes,
    })
}

fn allocate_exact<T>(capacity: usize) -> Result<ExactVec<T>, CopyError> {
    #[cfg(test)]
    {
        exact_allocation_probe::record();
        if let Some(error) = exact_allocation_probe::take_failure() {
            return Err(error);
        }
    }
    ExactVec::try_with_capacity(capacity)
}

#[cfg(test)]
mod exact_allocation_probe {
    use fre_exact_alloc::CopyError;
    use std::cell::Cell;

    std::thread_local! {
        static CALLS: Cell<usize> = const { Cell::new(0) };
        static FAILURE: Cell<Option<(usize, CopyError)>> = const { Cell::new(None) };
    }

    pub(super) fn record() {
        CALLS.set(CALLS.get().checked_add(1).expect("test probe overflow"));
    }

    pub(super) fn reset() {
        CALLS.set(0);
        FAILURE.set(None);
    }

    pub(super) fn calls() -> usize {
        CALLS.get()
    }

    pub(super) fn fail_call(call: usize, error: CopyError) {
        FAILURE.set(Some((call, error)));
    }

    pub(super) fn take_failure() -> Option<CopyError> {
        let calls = CALLS.get();
        let failure = FAILURE.get();
        if failure.is_some_and(|(call, _)| call == calls) {
            FAILURE.set(None);
            failure.map(|(_, error)| error)
        } else {
            None
        }
    }
}

fn published_actual(prospective: BuildProspective) -> BuildActual {
    BuildActual {
        items: prospective.items,
        payload_bytes: prospective.payload_bytes,
        identity_bytes: prospective.identity_bytes,
        retained_heap_bytes: prospective.retained_heap_bytes,
        copied_bytes: prospective.copied_bytes,
        allocations: prospective.allocations,
        initialized_bytes: prospective.initialized_bytes,
        build_work: prospective.build_work,
        scratch_bytes: prospective.scratch_bytes,
        persistent_bytes: prospective.persistent_bytes,
        peak_bytes: prospective.peak_bytes,
        published: true,
    }
}

#[allow(
    clippy::result_large_err,
    reason = "construction arithmetic failures retain the complete prospective and actual receipts"
)]
fn add_build_usize(
    current: usize,
    amount: usize,
    computation: &'static str,
    prospective: BuildProspective,
    actual: BuildActual,
) -> Result<usize, BuildError> {
    current.checked_add(amount).ok_or_else(|| {
        build_error_with(
            BuildErrorKind::ArithmeticOverflow { computation },
            prospective,
            actual,
        )
    })
}

#[allow(
    clippy::result_large_err,
    reason = "construction arithmetic failures retain the complete prospective and actual receipts"
)]
fn add_build_u64(
    current: u64,
    amount: u64,
    computation: &'static str,
    prospective: BuildProspective,
    actual: BuildActual,
) -> Result<u64, BuildError> {
    current.checked_add(amount).ok_or_else(|| {
        build_error_with(
            BuildErrorKind::ArithmeticOverflow { computation },
            prospective,
            actual,
        )
    })
}

#[allow(
    clippy::result_large_err,
    reason = "construction validation failures retain the complete prospective and actual receipts"
)]
fn validate_build_actual(
    prospective: BuildProspective,
    actual: BuildActual,
) -> Result<(), BuildError> {
    if actual == published_actual(prospective) {
        Ok(())
    } else {
        Err(build_error_with(
            BuildErrorKind::InternalInvariant(
                "published actual receipt differs from prospective receipt",
            ),
            prospective,
            actual,
        ))
    }
}

#[allow(
    clippy::result_large_err,
    reason = "construction admission failures retain the complete prospective and actual receipts"
)]
fn enforce_build(prospective: BuildProspective, limits: BuildLimits) -> Result<(), BuildError> {
    let checks = [
        (
            BuildResource::Items,
            u64::try_from(prospective.items),
            u64::try_from(limits.max_items),
        ),
        (
            BuildResource::PayloadBytes,
            u64::try_from(prospective.payload_bytes),
            u64::try_from(limits.max_payload_bytes),
        ),
        (
            BuildResource::IdentityBytes,
            u64::try_from(prospective.identity_bytes),
            u64::try_from(limits.max_identity_bytes),
        ),
        (
            BuildResource::CopiedBytes,
            u64::try_from(prospective.copied_bytes),
            u64::try_from(limits.max_copied_bytes),
        ),
        (
            BuildResource::Allocations,
            u64::try_from(prospective.allocations),
            u64::try_from(limits.max_allocations),
        ),
        (
            BuildResource::InitializedBytes,
            u64::try_from(prospective.initialized_bytes),
            u64::try_from(limits.max_initialized_bytes),
        ),
        (
            BuildResource::Work,
            Ok(prospective.build_work),
            Ok(limits.max_build_work),
        ),
        (
            BuildResource::PersistentBytes,
            u64::try_from(prospective.persistent_bytes),
            u64::try_from(limits.max_persistent_bytes),
        ),
        (
            BuildResource::PeakBytes,
            u64::try_from(prospective.peak_bytes),
            u64::try_from(limits.max_peak_bytes),
        ),
    ];
    for (resource, needed, limit) in checks {
        let needed = needed.map_err(|_| {
            build_error_with(
                BuildErrorKind::ArithmeticOverflow {
                    computation: "build resource as u64",
                },
                prospective,
                BuildActual::default(),
            )
        })?;
        let limit = limit.map_err(|_| {
            build_error_with(
                BuildErrorKind::ArithmeticOverflow {
                    computation: "build limit as u64",
                },
                prospective,
                BuildActual::default(),
            )
        })?;
        if needed > limit {
            return Err(build_error_with(
                BuildErrorKind::ResourceLimit {
                    resource,
                    needed,
                    limit,
                },
                prospective,
                BuildActual::default(),
            ));
        }
    }
    Ok(())
}

#[allow(
    clippy::result_large_err,
    reason = "reduction admission failures retain the complete invocation, prospective, and actual receipts"
)]
fn enforce_reduce(
    prospective: ReduceProspective,
    limits: ReduceLimits,
    invocation: Invocation,
) -> Result<(), ReduceError> {
    let checks = [
        (
            ReduceResource::ByteProbes,
            u64::try_from(prospective.byte_probes),
            u64::try_from(limits.max_byte_probes),
        ),
        (
            ReduceResource::BranchChecks,
            u64::try_from(prospective.branch_checks),
            u64::try_from(limits.max_branch_checks),
        ),
        (
            ReduceResource::MatchEvents,
            u64::try_from(prospective.match_events),
            u64::try_from(limits.max_match_events),
        ),
        (
            ReduceResource::Count,
            Ok(prospective.count),
            Ok(limits.max_count),
        ),
        (
            ReduceResource::SpanSum,
            Ok(prospective.span_sum),
            Ok(limits.max_span_sum),
        ),
        (
            ReduceResource::ReducerSteps,
            u64::try_from(prospective.reducer_steps),
            u64::try_from(limits.max_reducer_steps),
        ),
        (
            ReduceResource::TotalWork,
            u64::try_from(prospective.total_work),
            u64::try_from(limits.max_total_work),
        ),
        (
            ReduceResource::ScratchBytes,
            u64::try_from(prospective.scratch_bytes),
            u64::try_from(limits.max_scratch_bytes),
        ),
        (
            ReduceResource::PersistentBytes,
            u64::try_from(prospective.persistent_bytes),
            u64::try_from(limits.max_persistent_bytes),
        ),
        (
            ReduceResource::PeakBytes,
            u64::try_from(prospective.peak_bytes),
            u64::try_from(limits.max_peak_bytes),
        ),
    ];
    for (resource, needed, limit) in checks {
        let needed = needed.map_err(|_| {
            invocation_error(
                ReduceErrorKind::ArithmeticOverflow {
                    computation: "prospective resource as u64",
                },
                invocation,
                Some(prospective),
                ReduceActual::default(),
            )
        })?;
        let limit = limit.map_err(|_| {
            invocation_error(
                ReduceErrorKind::ArithmeticOverflow {
                    computation: "reduce limit as u64",
                },
                invocation,
                Some(prospective),
                ReduceActual::default(),
            )
        })?;
        if needed > limit {
            return Err(invocation_error(
                ReduceErrorKind::ResourceLimit {
                    resource,
                    needed,
                    limit,
                },
                invocation,
                Some(prospective),
                ReduceActual::default(),
            ));
        }
    }
    Ok(())
}

#[allow(
    clippy::result_large_err,
    reason = "reduction validation failures retain the complete invocation, prospective, and actual receipts"
)]
fn validate_actual(
    prospective: ReduceProspective,
    actual: ReduceActual,
    invocation: Invocation,
) -> Result<(), ReduceError> {
    if actual.fits(prospective) {
        Ok(())
    } else {
        Err(invocation_error(
            ReduceErrorKind::ActualExceedsProspective,
            invocation,
            Some(prospective),
            actual,
        ))
    }
}

fn allocation_error(
    error: CopyError,
    structure: &'static str,
    additional: usize,
    prospective: BuildProspective,
    actual: BuildActual,
) -> BuildError {
    let kind = match error {
        CopyError::AllocationFailed => BuildErrorKind::AllocationFailed {
            structure,
            additional,
        },
        CopyError::LayoutOverflow => BuildErrorKind::ArithmeticOverflow {
            computation: "exact allocation layout",
        },
    };
    build_error_with(kind, prospective, actual)
}

fn build_error(kind: BuildErrorKind) -> BuildError {
    BuildError {
        kind,
        prospective: None,
        actual: BuildActual::default(),
    }
}

fn build_error_with(
    kind: BuildErrorKind,
    prospective: BuildProspective,
    mut actual: BuildActual,
) -> BuildError {
    actual.published = false;
    BuildError {
        kind,
        prospective: Some(prospective),
        actual,
    }
}

fn invocation_error(
    kind: ReduceErrorKind,
    invocation: Invocation,
    prospective: Option<ReduceProspective>,
    actual: ReduceActual,
) -> ReduceError {
    ReduceError {
        kind,
        receipt: ReduceFailureReceipt {
            identity: invocation.identity,
            window: invocation.window,
            haystack_len: invocation.haystack_len,
            prospective,
            actual,
        },
    }
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use fre_exact_alloc::CopyError;

    use super::{
        BuildActual, BuildError, BuildErrorKind, BuildLimits, BuildProspective, BuildResource,
        ByteMask, Descriptor, FixedAbsoluteDomainPlan, Word, exact_allocation_probe,
    };

    fn singleton(byte: u8) -> ByteMask {
        ByteMask::inclusive(byte, byte)
    }

    fn exact_build_limits(upper: BuildProspective) -> BuildLimits {
        BuildLimits {
            max_items: upper.items,
            max_payload_bytes: upper.payload_bytes,
            max_identity_bytes: upper.identity_bytes,
            max_copied_bytes: upper.copied_bytes,
            max_allocations: upper.allocations,
            max_initialized_bytes: upper.initialized_bytes,
            max_build_work: upper.build_work,
            max_persistent_bytes: upper.persistent_bytes,
            max_peak_bytes: upper.peak_bytes,
        }
    }

    #[allow(
        clippy::arithmetic_side_effects,
        clippy::too_many_lines,
        reason = "each subtraction is guarded by a positive upper bound in the exhaustive fence table"
    )]
    fn assert_every_build_fence(
        name: &str,
        build: impl Fn(BuildLimits) -> Result<FixedAbsoluteDomainPlan, BuildError>,
    ) {
        exact_allocation_probe::reset();
        let baseline = build(BuildLimits::default()).unwrap();
        let upper = baseline.build_accounting().prospective;
        let exact = exact_build_limits(upper);
        let replay = build(exact).unwrap();
        assert_eq!(
            replay.build_accounting(),
            baseline.build_accounting(),
            "{name}"
        );

        let mut below = Vec::new();
        if upper.items > 0 {
            below.push((
                BuildResource::Items,
                BuildLimits {
                    max_items: upper.items - 1,
                    ..exact
                },
            ));
        }
        if upper.payload_bytes > 0 {
            below.push((
                BuildResource::PayloadBytes,
                BuildLimits {
                    max_payload_bytes: upper.payload_bytes - 1,
                    ..exact
                },
            ));
        }
        if upper.identity_bytes > 0 {
            below.push((
                BuildResource::IdentityBytes,
                BuildLimits {
                    max_identity_bytes: upper.identity_bytes - 1,
                    ..exact
                },
            ));
        }
        if upper.copied_bytes > 0 {
            below.push((
                BuildResource::CopiedBytes,
                BuildLimits {
                    max_copied_bytes: upper.copied_bytes - 1,
                    ..exact
                },
            ));
        }
        if upper.allocations > 0 {
            below.push((
                BuildResource::Allocations,
                BuildLimits {
                    max_allocations: upper.allocations - 1,
                    ..exact
                },
            ));
        }
        if upper.initialized_bytes > 0 {
            below.push((
                BuildResource::InitializedBytes,
                BuildLimits {
                    max_initialized_bytes: upper.initialized_bytes - 1,
                    ..exact
                },
            ));
        }
        if upper.build_work > 0 {
            below.push((
                BuildResource::Work,
                BuildLimits {
                    max_build_work: upper.build_work - 1,
                    ..exact
                },
            ));
        }
        if upper.persistent_bytes > 0 {
            below.push((
                BuildResource::PersistentBytes,
                BuildLimits {
                    max_persistent_bytes: upper.persistent_bytes - 1,
                    ..exact
                },
            ));
        }
        if upper.peak_bytes > 0 {
            below.push((
                BuildResource::PeakBytes,
                BuildLimits {
                    max_peak_bytes: upper.peak_bytes - 1,
                    ..exact
                },
            ));
        }
        for (resource, limits) in below {
            exact_allocation_probe::reset();
            exact_allocation_probe::fail_call(1, CopyError::AllocationFailed);
            let error = build(limits).expect_err("every positive one-below build fence refuses");
            assert!(
                matches!(
                    error.kind,
                    BuildErrorKind::ResourceLimit { resource: actual, .. }
                        if actual == resource
                ),
                "{name}/{resource:?}: {error:?}"
            );
            assert_eq!(error.prospective, Some(upper), "{name}/{resource:?}");
            assert_eq!(error.actual.allocations, 0, "{name}/{resource:?}");
            assert_eq!(exact_allocation_probe::calls(), 0, "{name}/{resource:?}");
            exact_allocation_probe::reset();
        }
    }

    #[test]
    fn endpoint_mask_failure_retains_cumulative_construction_actual() {
        let empty = ByteMask::default();
        let error = FixedAbsoluteDomainPlan::build_end_mask_sequence(
            [singleton(b'a'), empty, singleton(b'c')].into_iter(),
            BuildLimits::default(),
        )
        .unwrap_err();
        let prospective = error.prospective.expect("post-admission failure has P");
        let mask_bytes = size_of::<ByteMask>();
        assert_eq!(error.kind, BuildErrorKind::EmptyDescriptor);
        assert_eq!(error.actual.allocations, 1);
        assert_eq!(
            error.actual.retained_heap_bytes,
            prospective.retained_heap_bytes
        );
        assert_eq!(error.actual.items, 1);
        assert_eq!(error.actual.payload_bytes, mask_bytes);
        assert_eq!(error.actual.copied_bytes, mask_bytes);
        assert_eq!(error.actual.initialized_bytes, mask_bytes);
        assert_eq!(error.actual.build_work, 2);
        assert_eq!(
            error.actual.persistent_bytes,
            prospective.retained_heap_bytes
        );
        assert_eq!(error.actual.peak_bytes, prospective.retained_heap_bytes);
        assert!(!error.actual.published);
    }

    #[test]
    fn endpoint_prefix_copy_preserves_reversed_and_duplicate_hir_ordinals() {
        let plan = FixedAbsoluteDomainPlan::build_start_ordered_prefix(
            b"zbc",
            [b'e', b'd', b'd'].into_iter(),
            BuildLimits::default(),
        )
        .unwrap();
        let Descriptor::StartOrderedPrefix {
            prefix,
            alternatives,
        } = &plan.descriptor
        else {
            panic!("expected ordered-prefix descriptor");
        };
        assert_eq!(&**prefix, b"zbc");
        assert_eq!(&**alternatives, b"edd");
        assert!(plan.build_accounting().actual.published);
    }

    #[test]
    fn endpoint_operation_identity_binds_equal_dimension_descriptor_content() {
        let end_one_a = FixedAbsoluteDomainPlan::build_end_one_byte_mask(
            singleton(b'a'),
            BuildLimits::default(),
        )
        .unwrap();
        let end_one_b = FixedAbsoluteDomainPlan::build_end_one_byte_mask(
            singleton(b'b'),
            BuildLimits::default(),
        )
        .unwrap();
        assert_eq!(
            end_one_a.descriptor_identity(),
            end_one_b.descriptor_identity()
        );
        assert_ne!(end_one_a.span_sum_identity(), end_one_b.span_sum_identity());

        let masks_ab = FixedAbsoluteDomainPlan::build_end_mask_sequence(
            [singleton(b'a'), singleton(b'b')].into_iter(),
            BuildLimits::default(),
        )
        .unwrap();
        let masks_cd = FixedAbsoluteDomainPlan::build_end_mask_sequence(
            [singleton(b'c'), singleton(b'd')].into_iter(),
            BuildLimits::default(),
        )
        .unwrap();
        assert_eq!(
            masks_ab.descriptor_identity(),
            masks_cd.descriptor_identity()
        );
        assert_ne!(masks_ab.span_sum_identity(), masks_cd.span_sum_identity());

        let words_a = FixedAbsoluteDomainPlan::build_whole_ordered_words_precounted(
            2,
            4,
            [b"aa".as_slice(), b"bb".as_slice()].into_iter(),
            BuildLimits::default(),
        )
        .unwrap();
        let words_b = FixedAbsoluteDomainPlan::build_whole_ordered_words_precounted(
            2,
            4,
            [b"ab".as_slice(), b"ba".as_slice()].into_iter(),
            BuildLimits::default(),
        )
        .unwrap();
        assert_eq!(words_a.descriptor_identity(), words_b.descriptor_identity());
        assert_ne!(words_a.count_identity(), words_b.count_identity());

        let prefix_a = FixedAbsoluteDomainPlan::build_start_ordered_prefix(
            b"abc",
            [b'd', b'e'].into_iter(),
            BuildLimits::default(),
        )
        .unwrap();
        let prefix_b = FixedAbsoluteDomainPlan::build_start_ordered_prefix(
            b"xyz",
            [b'd', b'e'].into_iter(),
            BuildLimits::default(),
        )
        .unwrap();
        assert_eq!(
            prefix_a.descriptor_identity(),
            prefix_b.descriptor_identity()
        );
        assert_ne!(prefix_a.span_sum_identity(), prefix_b.span_sum_identity());

        let scalar_lower = FixedAbsoluteDomainPlan::build_whole_scalar_envelope_precounted(
            249,
            1,
            [(u32::from('a'), u32::from('z'))].into_iter(),
            BuildLimits::default(),
        )
        .unwrap();
        let scalar_upper = FixedAbsoluteDomainPlan::build_whole_scalar_envelope_precounted(
            249,
            1,
            [(u32::from('A'), u32::from('Z'))].into_iter(),
            BuildLimits::default(),
        )
        .unwrap();
        assert_eq!(
            scalar_lower.descriptor_identity(),
            scalar_upper.descriptor_identity()
        );
        assert_ne!(scalar_lower.count_identity(), scalar_upper.count_identity());
    }

    #[test]
    fn endpoint_second_word_allocation_failure_retains_first_allocation_and_planning_work() {
        exact_allocation_probe::reset();
        exact_allocation_probe::fail_call(2, CopyError::AllocationFailed);
        let error = FixedAbsoluteDomainPlan::build_whole_ordered_words_precounted(
            2,
            2,
            [b"a".as_slice(), b"b".as_slice()].into_iter(),
            BuildLimits::default(),
        )
        .unwrap_err();
        assert_eq!(exact_allocation_probe::calls(), 2);
        let prospective = error.prospective.expect("allocation failure has P");
        assert!(matches!(
            error.kind,
            BuildErrorKind::AllocationFailed {
                structure: "ordered word bytes",
                additional: 2
            }
        ));
        let metadata_bytes = 2 * size_of::<Word>();
        assert_eq!(error.actual.allocations, 1);
        assert_eq!(error.actual.retained_heap_bytes, metadata_bytes);
        assert_eq!(error.actual.initialized_bytes, 0);
        assert_eq!(error.actual.build_work, 1);
        assert_eq!(error.actual.persistent_bytes, metadata_bytes);
        assert_eq!(error.actual.peak_bytes, metadata_bytes);
        assert!(error.actual.peak_bytes <= prospective.peak_bytes);
        assert!(!error.actual.published);
        exact_allocation_probe::reset();
    }

    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        clippy::too_many_lines,
        reason = "the fixture's exact prospective dimensions are positive and its cumulative mismatch ledger is intentionally exhaustive"
    )]
    fn endpoint_precounted_words_publish_before_source_and_retain_mismatch_actuals() {
        use std::cell::Cell;

        let calls = Cell::new(0_usize);
        let source = [b"aaa".as_slice(), b"aa".as_slice()]
            .into_iter()
            .inspect(|_| calls.set(calls.get() + 1));
        let baseline = FixedAbsoluteDomainPlan::build_whole_ordered_words_precounted(
            2,
            5,
            source,
            BuildLimits::default(),
        )
        .unwrap();
        let prospective = baseline.build_accounting().prospective;
        assert_eq!(calls.get(), 2);
        assert_eq!(prospective.build_work, 9);

        let exact = exact_build_limits(prospective);
        let below = [
            (
                BuildResource::Items,
                BuildLimits {
                    max_items: prospective.items - 1,
                    ..exact
                },
            ),
            (
                BuildResource::PayloadBytes,
                BuildLimits {
                    max_payload_bytes: prospective.payload_bytes - 1,
                    ..exact
                },
            ),
            (
                BuildResource::IdentityBytes,
                BuildLimits {
                    max_identity_bytes: prospective.identity_bytes - 1,
                    ..exact
                },
            ),
            (
                BuildResource::CopiedBytes,
                BuildLimits {
                    max_copied_bytes: prospective.copied_bytes - 1,
                    ..exact
                },
            ),
            (
                BuildResource::Allocations,
                BuildLimits {
                    max_allocations: prospective.allocations - 1,
                    ..exact
                },
            ),
            (
                BuildResource::InitializedBytes,
                BuildLimits {
                    max_initialized_bytes: prospective.initialized_bytes - 1,
                    ..exact
                },
            ),
            (
                BuildResource::Work,
                BuildLimits {
                    max_build_work: prospective.build_work - 1,
                    ..exact
                },
            ),
            (
                BuildResource::PersistentBytes,
                BuildLimits {
                    max_persistent_bytes: prospective.persistent_bytes - 1,
                    ..exact
                },
            ),
            (
                BuildResource::PeakBytes,
                BuildLimits {
                    max_peak_bytes: prospective.peak_bytes - 1,
                    ..exact
                },
            ),
        ];
        for (resource, limits) in below {
            calls.set(0);
            let source = [b"aaa".as_slice(), b"aa".as_slice()]
                .into_iter()
                .inspect(|_| calls.set(calls.get() + 1));
            let error =
                FixedAbsoluteDomainPlan::build_whole_ordered_words_precounted(2, 5, source, limits)
                    .unwrap_err();
            assert!(matches!(
                error.kind,
                BuildErrorKind::ResourceLimit {
                    resource: actual,
                    ..
                } if actual == resource
            ));
            assert_eq!(error.prospective, Some(prospective));
            assert_eq!(error.actual, BuildActual::default());
            assert_eq!(calls.get(), 0, "{resource:?}");
        }

        let too_few = FixedAbsoluteDomainPlan::build_whole_ordered_words_precounted(
            3,
            5,
            [b"aaa".as_slice(), b"aa".as_slice()].into_iter(),
            BuildLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(
            too_few.kind,
            BuildErrorKind::DimensionMismatch {
                dimension: "word count",
                declared: 3,
                observed: 2,
            }
        ));
        assert!(too_few.prospective.is_some());
        assert_eq!(too_few.actual.allocations, 0);
        assert_eq!(too_few.actual.build_work, 1);
        assert!(!too_few.actual.published);

        let too_many_bytes = FixedAbsoluteDomainPlan::build_whole_ordered_words_precounted(
            2,
            4,
            [b"aaa".as_slice(), b"aa".as_slice()].into_iter(),
            BuildLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(
            too_many_bytes.kind,
            BuildErrorKind::DimensionMismatch {
                dimension: "word bytes",
                declared: 4,
                observed: 5,
            }
        ));
        assert!(too_many_bytes.prospective.is_some());
        assert_eq!(too_many_bytes.actual.allocations, 2);
        assert_eq!(too_many_bytes.actual.items, 1);
        assert_eq!(too_many_bytes.actual.copied_bytes, 3);
        assert_eq!(too_many_bytes.actual.build_work, 6);
        assert!(!too_many_bytes.actual.published);

        let too_few_bytes = FixedAbsoluteDomainPlan::build_whole_ordered_words_precounted(
            2,
            6,
            [b"aaa".as_slice(), b"aa".as_slice()].into_iter(),
            BuildLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(
            too_few_bytes.kind,
            BuildErrorKind::DimensionMismatch {
                dimension: "word bytes",
                declared: 6,
                observed: 5,
            }
        ));
        assert!(too_few_bytes.prospective.is_some());
        assert_eq!(too_few_bytes.actual.allocations, 2);
        assert_eq!(too_few_bytes.actual.items, 2);
        assert_eq!(too_few_bytes.actual.copied_bytes, 5);
        assert_eq!(too_few_bytes.actual.build_work, 9);
        assert!(!too_few_bytes.actual.published);
    }

    #[test]
    fn endpoint_successful_manual_build_receipts_equal_every_prospective_dimension() {
        let plans = [
            FixedAbsoluteDomainPlan::build_end_mask_sequence(
                [singleton(b'a'), singleton(b'b')].into_iter(),
                BuildLimits::default(),
            )
            .unwrap(),
            FixedAbsoluteDomainPlan::build_end_greedy_class_literal(
                ByteMask::inclusive(b'a', b'z'),
                b"XYZ",
                BuildLimits::default(),
            )
            .unwrap(),
            FixedAbsoluteDomainPlan::build_start_ordered_prefix(
                b"zbc",
                [b'd', b'e'].into_iter(),
                BuildLimits::default(),
            )
            .unwrap(),
            FixedAbsoluteDomainPlan::build_whole_ordered_words_precounted(
                2,
                5,
                [b"aaa".as_slice(), b"aa".as_slice()].into_iter(),
                BuildLimits::default(),
            )
            .unwrap(),
        ];
        for plan in plans {
            let accounting = plan.build_accounting();
            assert_eq!(accounting.actual.items, accounting.prospective.items);
            assert_eq!(
                accounting.actual.payload_bytes,
                accounting.prospective.payload_bytes
            );
            assert_eq!(
                accounting.actual.identity_bytes,
                accounting.prospective.identity_bytes
            );
            assert_eq!(
                accounting.actual.retained_heap_bytes,
                accounting.prospective.retained_heap_bytes
            );
            assert_eq!(
                accounting.actual.copied_bytes,
                accounting.prospective.copied_bytes
            );
            assert_eq!(
                accounting.actual.allocations,
                accounting.prospective.allocations
            );
            assert_eq!(
                accounting.actual.initialized_bytes,
                accounting.prospective.initialized_bytes
            );
            assert_eq!(
                accounting.actual.build_work,
                accounting.prospective.build_work
            );
            assert_eq!(
                accounting.actual.persistent_bytes,
                accounting.prospective.persistent_bytes
            );
            assert_eq!(
                accounting.actual.peak_bytes,
                accounting.prospective.peak_bytes
            );
            assert!(accounting.actual.published);
        }
    }

    #[test]
    fn endpoint_every_descriptor_build_fence_is_preallocation_and_exact() {
        assert_every_build_fence("end-mask-sequence", |limits| {
            FixedAbsoluteDomainPlan::build_end_mask_sequence(
                [singleton(b'a'), singleton(b'b')].into_iter(),
                limits,
            )
        });
        assert_every_build_fence("end-one-byte-mask", |limits| {
            FixedAbsoluteDomainPlan::build_end_one_byte_mask(singleton(b'a'), limits)
        });
        assert_every_build_fence("end-greedy-class-literal", |limits| {
            FixedAbsoluteDomainPlan::build_end_greedy_class_literal(
                ByteMask::inclusive(b'a', b'z'),
                b"XYZ",
                limits,
            )
        });
        assert_every_build_fence("whole-byte-repeat", |limits| {
            FixedAbsoluteDomainPlan::build_whole_byte_repeat(b'a', 2, 5, limits)
        });
        assert_every_build_fence("whole-ordered-words", |limits| {
            FixedAbsoluteDomainPlan::build_whole_ordered_words_precounted(
                2,
                5,
                [b"aaa".as_slice(), b"aa".as_slice()].into_iter(),
                limits,
            )
        });
        assert_every_build_fence("start-ordered-prefix", |limits| {
            FixedAbsoluteDomainPlan::build_start_ordered_prefix(
                b"zbc",
                [b'd', b'e'].into_iter(),
                limits,
            )
        });
        assert_every_build_fence("start-mask-sequence", |limits| {
            FixedAbsoluteDomainPlan::build_start_mask_sequence(
                [
                    ByteMask::inclusive(0, u8::MAX),
                    singleton(b'b'),
                    singleton(b'c'),
                    ByteMask::inclusive(b'd', b'e'),
                ]
                .into_iter(),
                limits,
            )
        });
        assert_every_build_fence("whole-scalar-envelope", |limits| {
            FixedAbsoluteDomainPlan::build_whole_scalar_envelope_precounted(
                249,
                1,
                [(0, 0x10_FFFF)].into_iter(),
                limits,
            )
        });
    }
}
