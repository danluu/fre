//! SIMD packed ordered finite-literal search with explicit refusal.

use core::{fmt, mem::size_of};

use aho_corasick::packed::Searcher;
use memchr::{
    memchr, memchr2, memchr3,
    memmem::{Finder, FinderBuilder},
};

use crate::Window;
#[cfg(not(feature = "static-dispatch"))]
use crate::packed_ordered_literal_aggregate::{
    UNIFORM_WORD64_MAX_DISTINCT_PATTERN_BYTES, UNIFORM_WORD64_MIN_ALPHABET_REUSE,
    UNIFORM_WORD64_MIN_ANCHOR_FREQUENCY_RANK, UNIFORM_WORD64_MIN_PATTERN_BYTES,
    select_anchor_offset,
};

const BUILD_FACTOR: usize = 256;
const PATTERN_BYTE_ENVELOPE: usize = 64;
const PATTERN_ENTRY_ENVELOPE: usize = 1_024;
const FIXED_BUILD_ENVELOPE: usize = 1024 * 1024;
// The pinned aho-corasick Teddy builder uses at most four bytes of every
// pattern in its SIMD filter and refuses more than 64 patterns in one
// searcher. Above that ceiling, only a complete fixed-width column product
// with the full four-byte filter enters the factored path. This makes the
// alternate route a language proof and bounded cost decision, rather than an
// arbitrary increase to Teddy's cardinality heuristic.
const FULL_TEDDY_FILTER_BYTES: usize = 4;
const TEDDY_PATTERNS_PER_SEARCHER: usize = 64;
const MAX_FACTORED_PATTERNS: usize = TEDDY_PATTERNS_PER_SEARCHER * 2;
/// Largest finite language that any packed literal-set engine can retain.
pub const CERTIFIED_MAX_PATTERNS: usize = MAX_FACTORED_PATTERNS;
const MAX_FACTORED_COLUMNS: usize = 16;
const MAX_FACTORED_ANCHOR_BYTES: usize = 3;
const FACTORED_SIMD_MINIMUM_HAYSTACK_BYTES: usize = 32;
// A native side filter verifies a bounded number of candidates itself. Exact
// shared columns may continue beyond that budget only while each adjacent
// candidate gap independently buys the complete bounded envelope. If the
// service gate closes, the packed searcher resumes after the last candidate
// already disproved.
const NATIVE_FILTER_CANDIDATE_BUDGET: usize = 4;
const NATIVE_FILTER_MAX_RETAINED_PATTERN_BYTES: usize = 4 * 1024;
// Retain only filters whose exact source-order verification fits in two
// 16-byte blocks. Exact shared-column continuation requires every adjacent
// candidate gap to amortize its own verification.
const NATIVE_FILTER_MAX_CANDIDATE_VERIFICATION_WORK: usize = 32;
// Public long-fragment receipts deliberately describe only subengines whose
// exact common substring is wide enough to justify whole-buffer routing.
const LONG_SHARED_FRAGMENT_RECEIPT_MIN_BYTES: usize = 8;
// A one-byte common fragment is already represented by `SparseAnchor`. Two
// bytes are the smallest exact fragment whose occurrence stream can prove
// strictly more impossible starts than that byte-set route.
const SHARED_FRAGMENT_MIN_BYTES: usize = 2;
/// Stable identity of the incumbent packed literal-set implementation.
pub const RUNTIME_IMPLEMENTATION_ID: &str = "packed-literal-set";
/// Stable identity of the equal-width scalar Shift-And search implementation.
pub const UNIFORM_WORD64_RUNTIME_IMPLEMENTATION_ID: &str =
    "packed-literal-set.uniform-word64-search.v1";
/// Stable identity of the optional retained adaptive iterator operation.
pub const RETAINED_ITER_RUNTIME_IMPLEMENTATION_ID: &str =
    "packed-literal-set.retained-adaptive-iterator.v1";
/// Stable identity of the opt-in dual-engine retained build capability.
pub const RETAINED_ITER_BUILD_CAPABILITY_ID: &str =
    "packed-literal-set.retained-adaptive-build.v1";
/// Stable identity of the selected long shared-fragment build capability.
pub const LONG_SHARED_FRAGMENT_BUILD_CAPABILITY_ID: &str =
    "packed-literal-set.long-shared-fragment-build.v1";
#[cfg(not(feature = "static-dispatch"))]
const UNIFORM_WORD64_STATE_BITS: usize = u64::BITS as usize;
#[cfg(not(feature = "static-dispatch"))]
const UNIFORM_WORD64_MASK_BYTES: usize = 256 * size_of::<u64>();
#[cfg(not(feature = "static-dispatch"))]
const RETAINED_ITER_DENSE_GAP_BYTES: usize = 64;
#[cfg(not(feature = "static-dispatch"))]
const RETAINED_ITER_DENSE_MATCHES: u8 = 2;
// UniformWord64 admits at least two equal-width literals in one word, so no
// retained literal is wider than half its state. After nearby hits, keep the
// native short-tail path only when even that widest literal cannot fit.
#[cfg(not(feature = "static-dispatch"))]
const RETAINED_ITER_UNIFORM_MIN_WINDOW_BYTES: usize = UNIFORM_WORD64_STATE_BITS / 2;
#[cfg(not(feature = "static-dispatch"))]
const RETAINED_ORDINARY_UNIFORM_PREFIX_STARTS: usize = 8;

/// Frozen general-purpose byte-frequency rank used by packed finite-language
/// anchor selectors. Lower values identify bytes expected to be rarer.
///
/// Facades that prove a different exact acceptance predicate can reuse this
/// immutable ranking without retaining the packed engine's private candidate
/// metadata or verification policy.
#[must_use]
pub fn packed_literal_anchor_frequency_rank(byte: u8) -> u8 {
    crate::packed_ordered_literal_aggregate::byte_frequency_rank(byte)
}

/// Return the packed builder's conservative work envelope from already
/// authenticated language dimensions, without reading any pattern bytes.
///
/// Composite planners can use this prospective before publishing borrowed
/// pattern references or invoking [`PackedLiteralSetPlan::new`]. The returned
/// bound is identical to the one enforced by the packed builder's own
/// preflight.
pub fn packed_literal_set_build_work_upper_bound_from_dimensions(
    patterns: usize,
    pattern_bytes: usize,
) -> Result<usize, PackedLiteralSetError> {
    if patterns == 0 {
        return Err(PackedLiteralSetError::EmptyPatternSet);
    }
    if pattern_bytes == 0 {
        return Err(PackedLiteralSetError::EmptyPattern { index: 0 });
    }
    pattern_bytes
        .checked_add(patterns)
        .and_then(|work| work.checked_mul(BUILD_FACTOR))
        .ok_or(PackedLiteralSetError::ArithmeticOverflow {
            computation: "packed literal build work",
        })
}

/// Hard limits for a packed finite-literal plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackedLiteralSetBuildLimits {
    /// Maximum ordered nonempty alternatives admitted to the builder.
    pub max_patterns: usize,
    /// Maximum sum of all alternative byte lengths.
    pub max_pattern_bytes: usize,
    /// Maximum conservative build-work envelope.
    pub max_build_work: usize,
    /// Maximum conservative peak-build byte envelope.
    pub max_build_bytes: usize,
    /// Maximum persistent bytes reported by the completed packed searcher.
    pub max_persistent_bytes: usize,
}

impl Default for PackedLiteralSetBuildLimits {
    fn default() -> Self {
        Self {
            max_patterns: 128,
            max_pattern_bytes: 4 * 1024 * 1024,
            max_build_work: 128 * 1024 * 1024,
            max_build_bytes: 256 * 1024 * 1024,
            max_persistent_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Checked construction facts for a packed finite-literal plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackedLiteralSetBuildAccounting {
    /// Number of ordered alternatives.
    pub patterns: usize,
    /// Sum of alternative byte lengths.
    pub pattern_bytes: usize,
    /// Longest alternative, used in the verification bound.
    pub max_pattern_bytes: usize,
    /// Conservative construction work.
    pub build_work_upper_bound: usize,
    /// Conservative pinned-implementation peak-build byte envelope.
    pub build_bytes_upper_bound: usize,
    /// Persistent bytes reported by the completed searcher.
    pub persistent_bytes: usize,
    /// Minimum haystack length at which the SIMD searcher is used. Zero means
    /// that the selected implementation is scalar and has no SIMD threshold.
    pub simd_minimum_haystack_bytes: usize,
}

/// Additional construction resources retained only for adaptive iteration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackedLiteralSetRetainedIterBuildAccounting {
    /// Versioned opt-in build capability.
    pub capability_id: &'static str,
    /// Versioned retained-iterator runtime selected by this capability.
    pub runtime_implementation_id: &'static str,
    /// Additional conservative construction work beyond the ordinary plan.
    pub additional_build_work: usize,
    /// Additional peak-build bytes beyond the ordinary plan.
    pub additional_build_bytes: usize,
    /// Additional persistent bytes beyond the ordinary plan.
    pub additional_persistent_bytes: usize,
}

/// Immutable receipt for a selected long shared-fragment subengine.
///
/// This receipt is present only when construction retained an exact common
/// fragment of at least eight bytes and the packed runtime will use that
/// fragment for long-haystack candidate discovery. Callers can therefore gate
/// whole-buffer searches on an authenticated stored-plan fact instead of
/// re-parsing the pattern or inferring a private planner decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackedLiteralSetLongSharedFragmentBuildReceipt {
    /// Versioned identity of this optional build capability.
    pub capability_id: &'static str,
    /// Fixed byte offset of the common fragment in every retained literal.
    pub fragment_offset: usize,
    /// Exact common-fragment width.
    pub fragment_bytes: usize,
    /// Shortest retained literal width.
    pub minimum_pattern_bytes: usize,
    /// Maximum exact verification work for one fragment candidate.
    pub maximum_candidate_verification_work: usize,
    /// Complete short-input/native-prefix extent retained by the subengine.
    pub native_prefix_bytes: usize,
}

/// Per-search bound for a packed finite-literal invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackedLiteralSetSearchLimits {
    /// Maximum conservative filter-plus-verification work.
    pub max_work: usize,
}

impl PackedLiteralSetSearchLimits {
    /// Disable the caller-selected cap; checked arithmetic remains active.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_work: usize::MAX,
        }
    }
}

impl Default for PackedLiteralSetSearchLimits {
    fn default() -> Self {
        Self {
            max_work: 512 * 1024 * 1024,
        }
    }
}

/// Conservative search certificate for one packed invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackedLiteralSetAccounting {
    /// Bytes in the searched window.
    pub searched_bytes: usize,
    /// Candidate positions, including the terminal empty position.
    pub positions_upper_bound: usize,
    /// Bytes that could be checked when verifying all alternatives once.
    pub verification_bytes_per_position: usize,
    /// Conservative total filter-plus-verification work.
    pub work_upper_bound: usize,
    /// External heap scratch required by the immutable search call.
    pub scratch_bytes: usize,
    /// Whether the selected execution is a fixed-width byte-column product.
    pub factored_columns: bool,
    /// Whether this window is long enough for the packed SIMD implementation.
    pub simd_eligible_length: bool,
}

/// Packed literal-set build or search failure.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PackedLiteralSetError {
    EmptyPatternSet,
    EmptyPattern {
        index: usize,
    },
    PatternLimit {
        needed: usize,
        limit: usize,
    },
    PatternBytesLimit {
        needed: usize,
        limit: usize,
    },
    BuildWorkLimit {
        needed: usize,
        limit: usize,
    },
    BuildBytesLimit {
        needed: usize,
        limit: usize,
    },
    PersistentBytesLimit {
        needed: usize,
        limit: usize,
    },
    UnsupportedTargetOrShape,
    InvalidWindow {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
    WorkLimit {
        needed: usize,
        limit: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for PackedLiteralSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPatternSet => write!(f, "a packed literal set needs at least one pattern"),
            Self::EmptyPattern { index } => {
                write!(f, "packed literal alternative {index} is empty")
            }
            Self::PatternLimit { needed, limit } => {
                write!(
                    f,
                    "packed literal set needs {needed} patterns, exceeding {limit}"
                )
            }
            Self::PatternBytesLimit { needed, limit } => write!(
                f,
                "packed literal set needs {needed} pattern bytes, exceeding {limit}"
            ),
            Self::BuildWorkLimit { needed, limit } => write!(
                f,
                "packed literal construction needs at most {needed} work units, exceeding {limit}"
            ),
            Self::BuildBytesLimit { needed, limit } => write!(
                f,
                "packed literal construction needs at most {needed} bytes, exceeding {limit}"
            ),
            Self::PersistentBytesLimit { needed, limit } => write!(
                f,
                "packed literal searcher retained {needed} bytes, exceeding {limit}"
            ),
            Self::UnsupportedTargetOrShape => write!(
                f,
                "the pinned packed searcher does not support this target or pattern shape"
            ),
            Self::InvalidWindow {
                start,
                end,
                haystack_len,
            } => write!(
                f,
                "packed literal window {start}..{end} is invalid for {haystack_len} bytes"
            ),
            Self::WorkLimit { needed, limit } => write!(
                f,
                "packed literal search needs at most {needed} work units, exceeding {limit}"
            ),
            Self::ArithmeticOverflow { computation } => {
                write!(f, "arithmetic overflow while computing {computation}")
            }
        }
    }
}

impl std::error::Error for PackedLiteralSetError {}

#[derive(Clone, Copy, Debug)]
struct FactoredColumns {
    columns: [[u64; 4]; MAX_FACTORED_COLUMNS],
    width: u8,
    anchor_offset: u8,
    anchor_bytes: [u8; MAX_FACTORED_ANCHOR_BYTES],
    anchor_len: u8,
}

/// A fixed-offset byte set present in every native literal.
///
/// Scanning from `offset` finds the earliest position that could belong to a
/// match. Subtracting the offset therefore skips only starts proved
/// impossible, while the unchanged ordered searcher retains source priority.
#[derive(Clone, Debug)]
struct SparseAnchor {
    offset: usize,
    bytes: [u8; MAX_FACTORED_ANCHOR_BYTES],
    len: u8,
    minimum_pattern_width: usize,
    // End offsets for anchor-byte groups in `patterns`. Every group preserves
    // source order; patterns in other groups cannot match the candidate.
    group_ends: [u16; MAX_FACTORED_ANCHOR_BYTES],
    maximum_candidate_verification_work: usize,
    // Patterns encoded as a little-endian u16 width followed by the bytes.
    // Native packed sets contain at most 64 patterns; the explicit retained
    // byte cap keeps exact candidate verification bounded.
    patterns: Box<[u8]>,
}

/// A longest exact byte run occurring at one fixed offset in every literal.
///
/// Short sources remain entirely native. On longer sources a bounded native
/// prefix proves early starts before one monotone substring scan finds the only
/// remaining starts at which any alternative can match. The fragment itself
/// needs no second comparison, so source-order verification reads only bytes
/// outside it. Dense false occurrences hand back to the native searcher.
#[derive(Clone, Debug)]
struct SharedFragment {
    offset: usize,
    width: usize,
    minimum_pattern_width: usize,
    maximum_candidate_verification_work: usize,
    // Exclusive start boundary proved by the native prefix search.
    native_start_budget: usize,
    // Maximum source length kept wholly on the native engine and, on longer
    // sources, the prefix byte extent. This includes the exact right overlap
    // needed to prove every start below `native_start_budget`. Construction
    // computes it once so an early native match has no arithmetic tail.
    native_prefix_bytes: usize,
    finder: Finder<'static>,
    // Source-order patterns encoded as a little-endian u16 width followed by
    // the bytes. The retained-byte and candidate-work proofs are shared with
    // `SparseAnchor`.
    patterns: Box<[u8]>,
}

/// Exact source-pattern identities admitted by one fixed byte column.
///
/// Intersecting these masks across a candidate word preserves correlations
/// between columns. This is stronger than checking only the marginal byte
/// classes: a nonempty final mask proves that one original literal equals the
/// complete candidate.
#[derive(Clone, Debug)]
struct SharedColumnMask {
    offset: usize,
    by_byte: [u64; 256],
}

/// A fixed-width literal set factored around one byte common to every word.
///
/// The common byte supplies one monotone `memchr` stream. Every remaining
/// column maps its observed byte to the source-patterns containing that byte;
/// intersecting the maps verifies the complete word without rereading the
/// anchor or walking the retained alternatives.
#[derive(Clone, Debug)]
struct SharedColumns {
    width: usize,
    anchor_offset: usize,
    anchor_byte: u8,
    pattern_mask: u64,
    #[allow(
        dead_code,
        reason = "retained as an exact construction certificate and asserted by tests"
    )]
    maximum_candidate_verification_work: usize,
    // Starts between two rejected exact-column probes that pay one unit of
    // candidate work across a minimum native packed-search service. An
    // unbounded continuation pays this coefficient for every probe in the
    // complete frozen side-filter envelope.
    minimum_candidate_skip: usize,
    // Maximum complete haystack kept wholly on the native engine. Longer
    // haystacks start with the monotone common-byte proof and invoke the
    // native engine at most once, on the first start not disproved by the
    // service-admitted exact-column filter.
    native_haystack_bytes: usize,
    columns: Box<[SharedColumnMask]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SharedColumnsFilterResult {
    Exhausted,
    Match { start: usize, end: usize },
    ResumeAt(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LongSharedFragmentFilterResult {
    Exhausted,
    Match { start: usize, end: usize },
    ResumeAt(usize),
}

impl SparseAnchor {
    fn earliest_possible_start_from(&self, haystack: &[u8], minimum_start: usize) -> Option<usize> {
        let last_start = haystack.len().checked_sub(self.minimum_pattern_width)?;
        if minimum_start > last_start {
            return None;
        }
        let scan_start = minimum_start.checked_add(self.offset)?;
        let scan_end = last_start.checked_add(self.offset)?.checked_add(1)?;
        let suffix = haystack.get(scan_start..scan_end)?;
        let relative = match self.len {
            1 => memchr(self.bytes[0], suffix),
            2 => memchr2(self.bytes[0], self.bytes[1], suffix),
            3 => memchr3(self.bytes[0], self.bytes[1], self.bytes[2], suffix),
            _ => None,
        }?;
        minimum_start.checked_add(relative)
    }

    fn verify_at(&self, haystack: &[u8], start: usize) -> Option<usize> {
        let anchor_byte = *haystack.get(start.checked_add(self.offset)?)?;
        let group = self.bytes[..usize::from(self.len)]
            .iter()
            .position(|&byte| byte == anchor_byte)?;
        let group_start = if group == 0 {
            0
        } else {
            usize::from(self.group_ends[group - 1])
        };
        let group_end = usize::from(self.group_ends[group]);
        let mut encoded = self.patterns.get(group_start..group_end)?;
        while !encoded.is_empty() {
            let (&low, rest) = encoded.split_first()?;
            let (&high, rest) = rest.split_first()?;
            let width = usize::from(u16::from_le_bytes([low, high]));
            let (pattern, rest) = rest.split_at_checked(width)?;
            encoded = rest;
            let end = start.checked_add(width);
            if end.and_then(|end| haystack.get(start..end)) == Some(pattern) {
                return end;
            }
        }
        None
    }

    fn persistent_bytes(&self) -> usize {
        size_of::<Self>()
            .checked_add(self.patterns.len())
            .expect("the sparse-anchor construction cap proves its persistent bytes")
    }
}

impl SharedFragment {
    fn earliest_possible_start_from(&self, haystack: &[u8], minimum_start: usize) -> Option<usize> {
        let last_start = haystack.len().checked_sub(self.minimum_pattern_width)?;
        if minimum_start > last_start {
            return None;
        }
        let scan_start = minimum_start.checked_add(self.offset)?;
        let scan_end = last_start
            .checked_add(self.offset)?
            .checked_add(self.width)?;
        let relative = self.finder.find(haystack.get(scan_start..scan_end)?)?;
        minimum_start.checked_add(relative)
    }

    fn verify_at(&self, haystack: &[u8], start: usize) -> Option<usize> {
        let fragment_end = self.offset.checked_add(self.width)?;
        let mut encoded = self.patterns.as_ref();
        while !encoded.is_empty() {
            let (&low, rest) = encoded.split_first()?;
            let (&high, rest) = rest.split_first()?;
            let width = usize::from(u16::from_le_bytes([low, high]));
            let (pattern, rest) = rest.split_at_checked(width)?;
            encoded = rest;
            let end = start.checked_add(width)?;
            let Some(candidate) = haystack.get(start..end) else {
                continue;
            };
            if candidate.get(..self.offset) == pattern.get(..self.offset)
                && candidate.get(fragment_end..) == pattern.get(fragment_end..)
            {
                return Some(end);
            }
        }
        None
    }

    fn persistent_bytes(&self) -> usize {
        size_of::<Self>()
            .checked_add(self.patterns.len())
            .and_then(|bytes| bytes.checked_add(self.width))
            .expect("the shared-fragment construction caps prove its persistent bytes")
    }
}

impl SharedColumns {
    fn earliest_possible_start_from(&self, haystack: &[u8], minimum_start: usize) -> Option<usize> {
        let last_start = haystack.len().checked_sub(self.width)?;
        if minimum_start > last_start {
            return None;
        }
        let scan_start = minimum_start.checked_add(self.anchor_offset)?;
        let scan_end = last_start
            .checked_add(self.anchor_offset)?
            .checked_add(1)?;
        let relative = memchr(self.anchor_byte, haystack.get(scan_start..scan_end)?)?;
        minimum_start.checked_add(relative)
    }

    fn verify_at(&self, haystack: &[u8], start: usize) -> Option<usize> {
        let end = start.checked_add(self.width)?;
        let candidate = haystack.get(start..end)?;
        let mut matching_patterns = self.pattern_mask;
        for column in self.columns.as_ref() {
            let byte = *candidate.get(column.offset)?;
            matching_patterns &= column.by_byte[usize::from(byte)];
            if matching_patterns == 0 {
                return None;
            }
        }
        // The least significant surviving bit is the first source pattern.
        // All admitted patterns have the same width, so every surviving bit
        // yields the same observable span while retaining source priority.
        debug_assert!(matching_patterns.trailing_zeros() < u64::BITS);
        Some(end)
    }

    fn minimum_continuation_skip(&self) -> Option<usize> {
        self.minimum_candidate_skip
            .checked_mul(NATIVE_FILTER_CANDIDATE_BUDGET)
    }

    fn continuation_is_amortized(&self, candidate: usize, next: usize) -> Option<bool> {
        let proved_skip = next.checked_sub(candidate)?;
        Some(proved_skip >= self.minimum_continuation_skip()?)
    }

    fn find_amortized(&self, haystack: &[u8]) -> SharedColumnsFilterResult {
        // Candidate starts and the common-byte scan advance monotonically.
        // Verify the current candidate first so an early exact match does not
        // pay a look-ahead scan. After a rejection, continue only when the
        // distance to the next candidate independently buys one native SIMD
        // service quantum for every probe in the complete bounded side-filter
        // envelope.
        // No earlier gap can subsidize a later dense cluster. On rejection,
        // resume the native engine at the exact next candidate, the first
        // start not disproved by the monotone scan. The complete-native
        // threshold above pays for the first bounded probe on every source
        // entering the side filter.
        let Some(mut candidate) = self.earliest_possible_start_from(haystack, 0) else {
            return SharedColumnsFilterResult::Exhausted;
        };
        loop {
            if let Some(end) = self.verify_at(haystack, candidate) {
                return SharedColumnsFilterResult::Match {
                    start: candidate,
                    end,
                };
            }
            let Some(after_candidate) = candidate.checked_add(1) else {
                return SharedColumnsFilterResult::ResumeAt(candidate);
            };
            let Some(next) = self.earliest_possible_start_from(haystack, after_candidate) else {
                return SharedColumnsFilterResult::Exhausted;
            };
            if !self
                .continuation_is_amortized(candidate, next)
                .unwrap_or(false)
            {
                return SharedColumnsFilterResult::ResumeAt(next);
            }
            candidate = next;
        }
    }

    fn persistent_bytes(&self) -> usize {
        size_of::<Self>()
            .checked_add(
                self.columns
                    .len()
                    .checked_mul(size_of::<SharedColumnMask>())
                    .expect("the shared-column work cap proves its column bytes"),
            )
            .expect("the shared-column construction caps prove its persistent bytes")
    }
}

impl FactoredColumns {
    fn find(&self, haystack: &[u8]) -> Option<(usize, usize)> {
        let width = usize::from(self.width);
        if haystack.len() < width {
            return None;
        }
        let anchor_offset = usize::from(self.anchor_offset);
        let trailing = width.checked_sub(anchor_offset)?.checked_sub(1)?;
        let mut cursor = anchor_offset;
        let anchor_end = haystack.len().checked_sub(trailing)?;
        while cursor < anchor_end {
            let relative = match self.anchor_len {
                1 => memchr(self.anchor_bytes[0], &haystack[cursor..anchor_end]),
                2 => memchr2(
                    self.anchor_bytes[0],
                    self.anchor_bytes[1],
                    &haystack[cursor..anchor_end],
                ),
                3 => memchr3(
                    self.anchor_bytes[0],
                    self.anchor_bytes[1],
                    self.anchor_bytes[2],
                    &haystack[cursor..anchor_end],
                ),
                _ => None,
            }?;
            let anchor = cursor.checked_add(relative)?;
            let start = anchor.checked_sub(anchor_offset)?;
            let end = start.checked_add(width)?;
            let candidate = &haystack[start..end];
            if self.columns[..width]
                .iter()
                .zip(candidate)
                .all(|(class, &byte)| class_contains(class, byte))
            {
                return Some((start, end));
            }
            cursor = anchor.checked_add(1)?;
        }
        None
    }
}

#[cfg(not(feature = "static-dispatch"))]
#[derive(Clone, Debug)]
struct UniformWord64 {
    masks: Box<[u64; 256]>,
    start_mask: u64,
    accept_mask: u64,
    width: usize,
}

#[cfg(not(feature = "static-dispatch"))]
impl UniformWord64 {
    fn find(&self, haystack: &[u8]) -> Option<(usize, usize)> {
        // Equal widths make the first accepting end the leftmost start. If
        // several lanes accept together, source priority and duplicates are
        // unobservable because every accepting lane denotes the same span.
        let mut state = 0_u64;
        for (index, &byte) in haystack.iter().enumerate() {
            // The first accepting transition returns immediately, so a terminal
            // bit can never shift across the boundary between adjacent lanes.
            debug_assert_eq!(state & self.accept_mask, 0);
            state = (state.wrapping_shl(1) | self.start_mask) & self.masks[usize::from(byte)];
            if state & self.accept_mask != 0 {
                let end = index.checked_add(1)?;
                return Some((end.checked_sub(self.width)?, end));
            }
        }
        None
    }
}

#[cfg(not(feature = "static-dispatch"))]
fn find_retained_ordinary(
    uniform: &UniformWord64,
    native: &Searcher,
    haystack: &[u8],
) -> Option<(usize, usize)> {
    let native_start = RETAINED_ORDINARY_UNIFORM_PREFIX_STARTS.min(haystack.len());
    let overlap = uniform.width.checked_sub(1)?;
    let uniform_end = native_start.checked_add(overlap)?.min(haystack.len());
    if let Some(matched) = uniform.find(&haystack[..uniform_end]) {
        return Some(matched);
    }
    let matched = native.find(&haystack[native_start..])?;
    Some((
        native_start.checked_add(matched.start())?,
        native_start.checked_add(matched.end())?,
    ))
}

#[cfg(not(feature = "static-dispatch"))]
fn try_build_uniform_word64<P: AsRef<[u8]>>(
    patterns: &[P],
    build: &PackedLiteralSetBuildAccounting,
    limits: PackedLiteralSetBuildLimits,
) -> Option<UniformWord64> {
    if patterns.len() < 2 || build.pattern_bytes > UNIFORM_WORD64_STATE_BITS {
        return None;
    }
    let width = patterns.first()?.as_ref().len();
    if width < UNIFORM_WORD64_MIN_PATTERN_BYTES
        || patterns
            .iter()
            .any(|pattern| pattern.as_ref().len() != width)
    {
        return None;
    }
    let state_extent = width.checked_mul(patterns.len())?;
    if state_extent != build.pattern_bytes || state_extent > UNIFORM_WORD64_STATE_BITS {
        return None;
    }

    let anchor_offset = select_anchor_offset(patterns, width);
    if patterns.iter().any(|pattern| {
        packed_literal_anchor_frequency_rank(pattern.as_ref()[anchor_offset])
            < UNIFORM_WORD64_MIN_ANCHOR_FREQUENCY_RANK
    }) {
        return None;
    }

    let mut present = [false; 256];
    let mut distinct = 0_usize;
    for pattern in patterns {
        for &byte in pattern.as_ref() {
            let slot = &mut present[usize::from(byte)];
            if !*slot {
                *slot = true;
                distinct = distinct.checked_add(1)?;
            }
        }
    }
    if distinct == 0
        || distinct > UNIFORM_WORD64_MAX_DISTINCT_PATTERN_BYTES
        || distinct
            .checked_mul(UNIFORM_WORD64_MIN_ALPHABET_REUSE)
            .is_none_or(|needed| build.pattern_bytes < needed)
        || UNIFORM_WORD64_MASK_BYTES > limits.max_persistent_bytes
    {
        return None;
    }

    let mut masks = allocate_uniform_word64_masks()?;
    let mut start_mask = 0_u64;
    let mut accept_mask = 0_u64;
    let mut state_offset = 0_usize;
    for pattern in patterns {
        start_mask |= 1_u64.checked_shl(u32::try_from(state_offset).ok()?)?;
        for (position, &byte) in pattern.as_ref().iter().enumerate() {
            let state_position = state_offset.checked_add(position)?;
            masks[usize::from(byte)] |=
                1_u64.checked_shl(u32::try_from(state_position).ok()?)?;
        }
        let accept_position = state_offset.checked_add(width)?.checked_sub(1)?;
        accept_mask |= 1_u64.checked_shl(u32::try_from(accept_position).ok()?)?;
        state_offset = state_offset.checked_add(width)?;
    }
    debug_assert_eq!(state_offset, state_extent);
    debug_assert!(start_mask != 0 && accept_mask != 0);
    Some(UniformWord64 {
        masks,
        start_mask,
        accept_mask,
        width,
    })
}

#[cfg(not(feature = "static-dispatch"))]
fn allocate_uniform_word64_masks() -> Option<Box<[u64; 256]>> {
    #[cfg(test)]
    if uniform_word64_allocation_probe::take_failure() {
        return None;
    }
    fre_exact_alloc::try_box_preserve([0_u64; 256]).ok()
}

#[cfg(not(feature = "static-dispatch"))]
fn try_build_retained_iter_native<P: AsRef<[u8]>>(
    patterns: &[P],
    base: PackedLiteralSetBuildAccounting,
    limits: PackedLiteralSetBuildLimits,
    max_additional_build_work: usize,
) -> Option<(Box<Searcher>, PackedLiteralSetBuildAccounting)> {
    // The original envelope pays for one complete engine construction. A
    // retained dual owner admits another complete copy of that work, and the
    // scalar masks remain live across the native builder's peak.
    let mut dual = base;
    if base.build_work_upper_bound > max_additional_build_work {
        return None;
    }
    dual.build_work_upper_bound = base.build_work_upper_bound.checked_mul(2)?;
    if dual.build_work_upper_bound > limits.max_build_work {
        return None;
    }
    dual.build_bytes_upper_bound = base
        .build_bytes_upper_bound
        .checked_add(UNIFORM_WORD64_MASK_BYTES)?
        .checked_add(size_of::<Searcher>())?;
    if dual.build_bytes_upper_bound > limits.max_build_bytes {
        return None;
    }
    let native = Searcher::new(patterns.iter().map(AsRef::as_ref))?;
    dual.persistent_bytes = UNIFORM_WORD64_MASK_BYTES
        .checked_add(size_of::<Searcher>())?
        .checked_add(native.memory_usage())?;
    if dual.persistent_bytes > limits.max_persistent_bytes {
        return None;
    }
    let native = allocate_retained_iter_native(native).ok()?;
    Some((native, dual))
}

#[cfg(not(feature = "static-dispatch"))]
fn allocate_retained_iter_native(native: Searcher) -> Result<Box<Searcher>, Searcher> {
    #[cfg(test)]
    if retained_iter_owner_allocation_probe::take_failure() {
        return Err(native);
    }
    fre_exact_alloc::try_box_preserve(native).map_err(|(_, native)| native)
}

#[derive(Clone, Debug)]
enum PackedLiteralEngine {
    #[cfg(not(feature = "static-dispatch"))]
    UniformWord64(UniformWord64),
    #[cfg(not(feature = "static-dispatch"))]
    UniformWord64Retained {
        uniform: UniformWord64,
        native: Box<Searcher>,
    },
    Native(Searcher),
    NativeSparse {
        searcher: Searcher,
        sparse_anchor: Box<SparseAnchor>,
    },
    NativeSharedFragment {
        searcher: Searcher,
        shared_fragment: Box<SharedFragment>,
    },
    NativeSharedColumns {
        searcher: Searcher,
        shared_columns: Box<SharedColumns>,
    },
    Factored(Box<FactoredColumns>),
}

/// Immutable SIMD packed ordered-literal plan.
///
/// This is a shared native primitive, not pattern-specialized JIT code. The
/// pinned implementation uses Teddy on supported x86-64/AArch64 haystacks and
/// a bounded Rabin-Karp path for short inputs. Native sets may first scan a
/// proved shared fixed-offset fragment or intersect exact correlated columns
/// before source-order tail verification. Larger complete byte-column products
/// use one native byte-set scan plus exact column verification. Construction
/// refuses unsupported targets/shapes and search never changes plan after
/// selection.
#[derive(Clone, Debug)]
pub struct PackedLiteralSetPlan {
    engine: PackedLiteralEngine,
    build: PackedLiteralSetBuildAccounting,
    verification_bytes_per_position: usize,
}

/// Borrowed engine for ordinary unlimited packed literal-set searches.
///
/// Construction already sealed nonempty ordered literals and the selected
/// immutable engine. This projection therefore validates only source windows
/// and never computes finite-work or diagnostic accounting.
#[derive(Clone, Copy, Debug)]
pub struct PackedLiteralSetOrdinaryExecutor<'a> {
    plan: &'a PackedLiteralSetPlan,
}

/// Allocation-free cursor over a packed literal set's retained dual engine.
///
/// This cursor exists only when construction admitted both the selected
/// equal-width scalar engine and the incumbent native engine. It samples with
/// the native engine, keeps sparse/no-match suffixes on that engine, and uses
/// the scalar engine only after two adjacent matches prove a dense local run.
#[cfg(not(feature = "static-dispatch"))]
#[derive(Clone, Copy, Debug)]
pub struct PackedLiteralSetSearchCursor<'p, 'h> {
    plan: &'p PackedLiteralSetPlan,
    native: &'p Searcher,
    haystack: &'h [u8],
    last_start: Option<usize>,
    close_matches: u8,
    dense: bool,
}

impl PackedLiteralSetPlan {
    /// Build a packed ordered-literal searcher.
    ///
    /// # Errors
    ///
    /// Returns a checked limit error before construction or an explicit
    /// unsupported result when the pinned packed builder cannot build.
    pub fn new<P: AsRef<[u8]>>(
        patterns: &[P],
        limits: PackedLiteralSetBuildLimits,
    ) -> Result<Self, PackedLiteralSetError> {
        Self::new_with_retained_iter(patterns, limits, None)
    }

    /// Build a packed plan that may retain a separately accounted native
    /// engine for allocation-free adaptive iteration.
    ///
    /// When the additional work/peak/persistent envelope does not fit, this
    /// returns the ordinary selected plan instead of changing its refusal.
    /// If native construction or the final owner allocation fails after that
    /// envelope is admitted, the bounded attempt is discarded and the same
    /// Uniform plan is returned without a retained-capability receipt.
    ///
    /// # Errors
    ///
    /// Returns the same checked base-plan errors as [`Self::new`].
    pub fn new_retained_iter<P: AsRef<[u8]>>(
        patterns: &[P],
        limits: PackedLiteralSetBuildLimits,
        max_additional_build_work: usize,
    ) -> Result<Self, PackedLiteralSetError> {
        Self::new_with_retained_iter(patterns, limits, Some(max_additional_build_work))
    }

    fn new_with_retained_iter<P: AsRef<[u8]>>(
        patterns: &[P],
        limits: PackedLiteralSetBuildLimits,
        max_additional_build_work: Option<usize>,
    ) -> Result<Self, PackedLiteralSetError> {
        let mut build = preflight(patterns, limits)?;
        #[cfg(not(feature = "static-dispatch"))]
        if let Some(uniform) = try_build_uniform_word64(patterns, &build, limits) {
            build.persistent_bytes = UNIFORM_WORD64_MASK_BYTES;
            // A tight persistent cap continues to admit the original scalar
            // plan. With room for both engines, account the complete retained
            // footprint before publishing the adaptive iterator cursor.
            let retained = max_additional_build_work.and_then(|additional_work| {
                try_build_retained_iter_native(patterns, build, limits, additional_work)
            });
            let verification_bytes_per_position = build
                .pattern_bytes
                .checked_add(build.patterns)
                .expect("successful preflight proved the packed verification coefficient");
            let engine = if let Some((native, dual_build)) = retained {
                build = dual_build;
                PackedLiteralEngine::UniformWord64Retained { uniform, native }
            } else {
                PackedLiteralEngine::UniformWord64(uniform)
            };
            return Ok(Self {
                engine,
                build,
                verification_bytes_per_position,
            });
        }
        let engine =
            if let Some(native_searcher) = Searcher::new(patterns.iter().map(AsRef::as_ref)) {
                // Preserve an already-admitted sparse anchor: a rare byte at
                // another offset can be more selective than a common fragment.
                // Fixed-width sets next get exact correlated column masks;
                // variable widths retain the common-fragment verifier.
                let sparse_anchor = select_sparse_anchor(patterns).map(Box::new);
                let shared_columns = if sparse_anchor.is_some() {
                    None
                } else {
                    select_shared_columns(patterns, native_searcher.minimum_len()).map(Box::new)
                };
                let shared_fragment = if sparse_anchor.is_some() || shared_columns.is_some() {
                    None
                } else {
                    select_shared_fragment(patterns, native_searcher.minimum_len()).map(Box::new)
                };
                let sidecar_bytes = sparse_anchor.as_ref().map_or_else(
                    || {
                        shared_columns.as_ref().map_or_else(
                            || {
                                shared_fragment
                                    .as_ref()
                                    .map_or(0, |fragment| fragment.persistent_bytes())
                            },
                            |columns| columns.persistent_bytes(),
                        )
                    },
                    |anchor| anchor.persistent_bytes(),
                );
                build.persistent_bytes = native_searcher
                    .memory_usage()
                    .checked_add(sidecar_bytes)
                    .ok_or(PackedLiteralSetError::ArithmeticOverflow {
                        computation: "packed literal persistent bytes",
                    })?;
                build.simd_minimum_haystack_bytes = native_searcher.minimum_len();
                enforce_persistent_limit(&build, limits)?;
                if let Some(sparse_anchor) = sparse_anchor {
                    PackedLiteralEngine::NativeSparse {
                        searcher: native_searcher,
                        sparse_anchor,
                    }
                } else if let Some(shared_columns) = shared_columns {
                    PackedLiteralEngine::NativeSharedColumns {
                        searcher: native_searcher,
                        shared_columns,
                    }
                } else if let Some(shared_fragment) = shared_fragment {
                    PackedLiteralEngine::NativeSharedFragment {
                        searcher: native_searcher,
                        shared_fragment,
                    }
                } else {
                    PackedLiteralEngine::Native(native_searcher)
                }
            } else if let Some(factored) = factor_complete_columns(patterns, &build) {
                build.persistent_bytes = size_of::<FactoredColumns>();
                build.simd_minimum_haystack_bytes = FACTORED_SIMD_MINIMUM_HAYSTACK_BYTES;
                enforce_persistent_limit(&build, limits)?;
                PackedLiteralEngine::Factored(Box::new(factored))
            } else {
                return Err(PackedLiteralSetError::UnsupportedTargetOrShape);
            };
        let verification_bytes_per_position = build
            .pattern_bytes
            .checked_add(build.patterns)
            .expect("successful preflight proved the packed verification coefficient");
        Ok(Self {
            engine,
            build,
            verification_bytes_per_position,
        })
    }

    /// Checked construction facts and actual persistent footprint.
    #[must_use]
    pub const fn build_accounting(&self) -> PackedLiteralSetBuildAccounting {
        self.build
    }

    /// Exact immutable receipt for the selected long shared-fragment engine.
    #[must_use]
    pub const fn long_shared_fragment_build_receipt(
        &self,
    ) -> Option<PackedLiteralSetLongSharedFragmentBuildReceipt> {
        let PackedLiteralEngine::NativeSharedFragment {
            shared_fragment, ..
        } = &self.engine
        else {
            return None;
        };
        if shared_fragment.width < LONG_SHARED_FRAGMENT_RECEIPT_MIN_BYTES {
            return None;
        }
        Some(PackedLiteralSetLongSharedFragmentBuildReceipt {
            capability_id: LONG_SHARED_FRAGMENT_BUILD_CAPABILITY_ID,
            fragment_offset: shared_fragment.offset,
            fragment_bytes: shared_fragment.width,
            minimum_pattern_bytes: shared_fragment.minimum_pattern_width,
            maximum_candidate_verification_work: shared_fragment
                .maximum_candidate_verification_work,
            native_prefix_bytes: shared_fragment.native_prefix_bytes,
        })
    }

    /// Stable identity of the construction-selected runtime implementation.
    #[must_use]
    pub const fn runtime_implementation_id(&self) -> &'static str {
        match &self.engine {
            #[cfg(not(feature = "static-dispatch"))]
            PackedLiteralEngine::UniformWord64(_)
            | PackedLiteralEngine::UniformWord64Retained { .. } => {
                UNIFORM_WORD64_RUNTIME_IMPLEMENTATION_ID
            }
            _ => RUNTIME_IMPLEMENTATION_ID,
        }
    }

    /// Bind the direct ordinary-search engine to this immutable plan.
    #[doc(hidden)]
    #[must_use]
    pub const fn ordinary_executor(&self) -> PackedLiteralSetOrdinaryExecutor<'_> {
        PackedLiteralSetOrdinaryExecutor { plan: self }
    }

    /// Return an allocation-free adaptive cursor when both uniform and native
    /// packed engines were admitted during construction.
    #[cfg(not(feature = "static-dispatch"))]
    #[must_use]
    pub fn search_cursor<'p, 'h>(
        &'p self,
        haystack: &'h [u8],
    ) -> Option<PackedLiteralSetSearchCursor<'p, 'h>> {
        let PackedLiteralEngine::UniformWord64Retained { native, .. } = &self.engine else {
            return None;
        };
        Some(PackedLiteralSetSearchCursor {
            plan: self,
            native,
            haystack,
            last_start: None,
            close_matches: 0,
            dense: false,
        })
    }

    /// Identity of the optional build capability retained by this plan.
    #[cfg(not(feature = "static-dispatch"))]
    #[must_use]
    pub const fn retained_iter_build_capability_id(&self) -> Option<&'static str> {
        match self.retained_iter_build_accounting() {
            Some(accounting) => Some(accounting.capability_id),
            None => None,
        }
    }

    /// Additional planner work charged for the retained native engine.
    #[cfg(not(feature = "static-dispatch"))]
    #[must_use]
    pub const fn retained_iter_additional_build_work(&self) -> Option<usize> {
        match self.retained_iter_build_accounting() {
            Some(accounting) => Some(accounting.additional_build_work),
            None => None,
        }
    }

    /// Separately versioned resources of the optional retained iterator.
    #[cfg(not(feature = "static-dispatch"))]
    #[must_use]
    pub const fn retained_iter_build_accounting(
        &self,
    ) -> Option<PackedLiteralSetRetainedIterBuildAccounting> {
        match &self.engine {
            PackedLiteralEngine::UniformWord64Retained { .. } => {
                Some(PackedLiteralSetRetainedIterBuildAccounting {
                    capability_id: RETAINED_ITER_BUILD_CAPABILITY_ID,
                    runtime_implementation_id: RETAINED_ITER_RUNTIME_IMPLEMENTATION_ID,
                    additional_build_work: self.build.build_work_upper_bound / 2,
                    additional_build_bytes: UNIFORM_WORD64_MASK_BYTES + size_of::<Searcher>(),
                    additional_persistent_bytes: self
                        .build
                        .persistent_bytes
                        .checked_sub(UNIFORM_WORD64_MASK_BYTES)
                        .expect("retained dual construction includes the scalar masks"),
                })
            }
            _ => None,
        }
    }

    /// Find the first ordered-alternation match in a complete haystack.
    ///
    /// # Errors
    ///
    /// Returns a checked resource error before searching.
    pub fn find(
        &self,
        haystack: &[u8],
        limits: PackedLiteralSetSearchLimits,
    ) -> Result<(Option<(usize, usize)>, PackedLiteralSetAccounting), PackedLiteralSetError> {
        self.find_window(haystack, Window::full(haystack), limits)
    }

    /// Find the first ordered-alternation match inside a byte range.
    ///
    /// # Errors
    ///
    /// Returns a checked window, arithmetic, or work-limit error before
    /// searching.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the validated slice and packed engine contracts prove these window-relative additions"
    )]
    pub fn find_window(
        &self,
        haystack: &[u8],
        window: Window,
        limits: PackedLiteralSetSearchLimits,
    ) -> Result<(Option<(usize, usize)>, PackedLiteralSetAccounting), PackedLiteralSetError> {
        self.find_window_with_native(haystack, window, limits, None)
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the validated slice and packed engine contracts prove these window-relative additions"
    )]
    fn find_window_value_unmetered_with_native(
        &self,
        haystack: &[u8],
        window: Window,
        iterator_native: Option<&Searcher>,
    ) -> Result<Option<(usize, usize)>, PackedLiteralSetError> {
        validate_window(window, haystack.len())?;
        let window_bytes = &haystack[window.start()..window.end()];
        let matched = if let Some(native) = iterator_native {
            native
                .find(window_bytes)
                .map(|matched| (matched.start(), matched.end()))
        } else {
            match &self.engine {
                #[cfg(not(feature = "static-dispatch"))]
                PackedLiteralEngine::UniformWord64(uniform) => uniform.find(window_bytes),
                #[cfg(not(feature = "static-dispatch"))]
                PackedLiteralEngine::UniformWord64Retained { uniform, native } => {
                    find_retained_ordinary(uniform, native, window_bytes)
                }
                PackedLiteralEngine::Native(searcher) => searcher
                    .find(window_bytes)
                    .map(|matched| (matched.start(), matched.end())),
                PackedLiteralEngine::NativeSparse {
                    searcher,
                    sparse_anchor,
                } => find_native(searcher, sparse_anchor, window_bytes),
                PackedLiteralEngine::NativeSharedFragment {
                    searcher,
                    shared_fragment,
                } => find_native_shared_fragment(searcher, shared_fragment, window_bytes),
                PackedLiteralEngine::NativeSharedColumns {
                    searcher,
                    shared_columns,
                } => find_native_shared_columns(searcher, shared_columns, window_bytes),
                PackedLiteralEngine::Factored(factored) => factored.find(window_bytes),
            }
        };
        Ok(matched.map(|(relative_start, relative_end)| {
            (
                window.start() + relative_start,
                window.start() + relative_end,
            )
        }))
    }

    #[cfg(not(feature = "static-dispatch"))]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the validated slice and packed engine contracts prove these window-relative additions"
    )]
    fn find_window_value_unmetered_uniform(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<Option<(usize, usize)>, PackedLiteralSetError> {
        validate_window(window, haystack.len())?;
        let PackedLiteralEngine::UniformWord64Retained { uniform, .. } = &self.engine else {
            unreachable!("only retained uniform plans construct adaptive cursors");
        };
        Ok(uniform
            .find(&haystack[window.start()..window.end()])
            .map(|(relative_start, relative_end)| {
                (
                    window.start() + relative_start,
                    window.start() + relative_end,
                )
            }))
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the validated slice and packed engine contracts prove these window-relative additions"
    )]
    fn find_window_with_native(
        &self,
        haystack: &[u8],
        window: Window,
        limits: PackedLiteralSetSearchLimits,
        iterator_native: Option<&Searcher>,
    ) -> Result<(Option<(usize, usize)>, PackedLiteralSetAccounting), PackedLiteralSetError> {
        if window.start() > window.end() || window.end() > haystack.len() {
            return Err(PackedLiteralSetError::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len: haystack.len(),
            });
        }
        let searched_bytes = window.end() - window.start();
        let positions_upper_bound = searched_bytes + 1;
        let verification_bytes_per_position = self.verification_bytes_per_position;
        let work_upper_bound = positions_upper_bound
            .checked_mul(verification_bytes_per_position)
            .ok_or(PackedLiteralSetError::ArithmeticOverflow {
                computation: "packed literal search work",
            })?;
        if work_upper_bound > limits.max_work {
            return Err(PackedLiteralSetError::WorkLimit {
                needed: work_upper_bound,
                limit: limits.max_work,
            });
        }
        let simd_eligible_length = iterator_native.map_or_else(
            || match &self.engine {
                #[cfg(not(feature = "static-dispatch"))]
                PackedLiteralEngine::UniformWord64(_)
                | PackedLiteralEngine::UniformWord64Retained { .. } => false,
                _ => searched_bytes >= self.build.simd_minimum_haystack_bytes,
            },
            |native| searched_bytes >= native.minimum_len(),
        );
        let mut accounting = PackedLiteralSetAccounting {
            searched_bytes,
            positions_upper_bound,
            verification_bytes_per_position,
            work_upper_bound,
            scratch_bytes: 0,
            factored_columns: false,
            simd_eligible_length,
        };
        let window_bytes = &haystack[window.start()..window.end()];
        let matched = if let Some(native) = iterator_native {
            native
                .find(window_bytes)
                .map(|matched| (matched.start(), matched.end()))
        } else {
            match &self.engine {
                #[cfg(not(feature = "static-dispatch"))]
                PackedLiteralEngine::UniformWord64(uniform) => uniform.find(window_bytes),
                #[cfg(not(feature = "static-dispatch"))]
                PackedLiteralEngine::UniformWord64Retained { uniform, .. } => {
                    uniform.find(window_bytes)
                }
                PackedLiteralEngine::Native(searcher) => searcher
                    .find(window_bytes)
                    .map(|matched| (matched.start(), matched.end())),
                PackedLiteralEngine::NativeSparse {
                    searcher,
                    sparse_anchor,
                } => find_native(searcher, sparse_anchor, window_bytes),
                PackedLiteralEngine::NativeSharedFragment {
                    searcher,
                    shared_fragment,
                } => find_native_shared_fragment(searcher, shared_fragment, window_bytes),
                PackedLiteralEngine::NativeSharedColumns {
                    searcher,
                    shared_columns,
                } => find_native_shared_columns(searcher, shared_columns, window_bytes),
                PackedLiteralEngine::Factored(factored) => {
                    accounting.factored_columns = true;
                    factored.find(window_bytes)
                }
            }
        };
        let matched = matched.map(|(relative_start, relative_end)| {
            (
                window.start() + relative_start,
                window.start() + relative_end,
            )
        });
        Ok((matched, accounting))
    }
}

#[cfg(not(feature = "static-dispatch"))]
impl PackedLiteralSetSearchCursor<'_, '_> {
    /// Stable identity of this retained iterator operation.
    #[must_use]
    pub const fn runtime_implementation_id(&self) -> &'static str {
        RETAINED_ITER_RUNTIME_IMPLEMENTATION_ID
    }

    /// Search at `start`, preserving the plan's checked work envelope.
    /// Density changes only which already-admitted engine consumes the bytes.
    pub fn find_at(
        &mut self,
        start: usize,
        limits: PackedLiteralSetSearchLimits,
    ) -> Result<(Option<(usize, usize)>, PackedLiteralSetAccounting), PackedLiteralSetError> {
        if self.last_start.is_some_and(|previous| start < previous) {
            self.close_matches = 0;
            self.dense = false;
        }
        self.last_start = Some(start);
        let remaining = self.haystack.len().saturating_sub(start);
        let use_uniform = self.dense && remaining >= RETAINED_ITER_UNIFORM_MIN_WINDOW_BYTES;
        let result = self.plan.find_window_with_native(
            self.haystack,
            Window::new(start, self.haystack.len()),
            limits,
            (!use_uniform).then_some(self.native),
        )?;
        if let Some((matched_start, _)) = result.0 {
            let gap = matched_start.saturating_sub(start);
            if gap <= RETAINED_ITER_DENSE_GAP_BYTES {
                self.close_matches = self.close_matches.saturating_add(1);
                self.dense = self.close_matches >= RETAINED_ITER_DENSE_MATCHES;
            } else {
                self.close_matches = 0;
                self.dense = false;
            }
        }
        Ok(result)
    }

    /// Value-only companion to [`Self::find_at`].
    pub fn find_at_value(
        &mut self,
        start: usize,
        limits: PackedLiteralSetSearchLimits,
    ) -> Result<Option<(usize, usize)>, PackedLiteralSetError> {
        self.find_at(start, limits).map(|(matched, _)| matched)
    }

    /// Search at `start` without finite-work or diagnostic accounting.
    #[doc(hidden)]
    pub fn find_at_value_unmetered(
        &mut self,
        start: usize,
    ) -> Result<Option<(usize, usize)>, PackedLiteralSetError> {
        if self.last_start.is_some_and(|previous| start < previous) {
            self.close_matches = 0;
            self.dense = false;
        }
        self.last_start = Some(start);
        let remaining = self.haystack.len().saturating_sub(start);
        let use_uniform = self.dense && remaining >= RETAINED_ITER_UNIFORM_MIN_WINDOW_BYTES;
        let window = Window::new(start, self.haystack.len());
        let matched = if use_uniform {
            self.plan
                .find_window_value_unmetered_uniform(self.haystack, window)?
        } else {
            self.plan.find_window_value_unmetered_with_native(
                self.haystack,
                window,
                Some(self.native),
            )?
        };
        if let Some((matched_start, _)) = matched {
            let gap = matched_start.saturating_sub(start);
            if gap <= RETAINED_ITER_DENSE_GAP_BYTES {
                self.close_matches = self.close_matches.saturating_add(1);
                self.dense = self.close_matches >= RETAINED_ITER_DENSE_MATCHES;
            } else {
                self.close_matches = 0;
                self.dense = false;
            }
        }
        Ok(matched)
    }
}

impl PackedLiteralSetOrdinaryExecutor<'_> {
    /// Return the selected ordered span wholly inside `window` without
    /// finite-work or diagnostic accounting.
    #[doc(hidden)]
    #[inline]
    pub fn find_window_value(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<Option<(usize, usize)>, PackedLiteralSetError> {
        self.plan
            .find_window_value_unmetered_with_native(haystack, window, None)
    }

    /// Return whether a selected ordered span exists inside `window`.
    #[doc(hidden)]
    #[inline]
    pub fn exists_window_value(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<bool, PackedLiteralSetError> {
        self.find_window_value(haystack, window)
            .map(|matched| matched.is_some())
    }

    /// Return only the selected ordered span's endpoint inside `window`.
    #[doc(hidden)]
    #[inline]
    pub fn selected_end_window_value(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<Option<usize>, PackedLiteralSetError> {
        self.find_window_value(haystack, window)
            .map(|matched| matched.map(|(_, end)| end))
    }

    /// Visit non-overlapping positive-width spans without finite accounting.
    #[doc(hidden)]
    pub fn try_visit_spans_window_value<F, E>(
        &self,
        haystack: &[u8],
        window: Window,
        mut visitor: F,
    ) -> Result<Result<(), E>, PackedLiteralSetError>
    where
        F: FnMut((usize, usize)) -> Result<bool, E>,
    {
        validate_window(window, haystack.len())?;
        #[cfg(not(feature = "static-dispatch"))]
        let mut retained = self.plan.search_cursor(&haystack[..window.end()]);
        let mut start = window.start();
        loop {
            #[cfg(not(feature = "static-dispatch"))]
            let matched = if let Some(cursor) = retained.as_mut() {
                cursor.find_at_value_unmetered(start)?
            } else {
                self.find_window_value(haystack, Window::new(start, window.end()))?
            };
            #[cfg(feature = "static-dispatch")]
            let matched =
                self.find_window_value(haystack, Window::new(start, window.end()))?;
            let Some(matched) = matched else {
                return Ok(Ok(()));
            };
            if matched.1 <= start {
                return Err(PackedLiteralSetError::ArithmeticOverflow {
                    computation: "packed ordinary positive-width iterator progress",
                });
            }
            start = matched.1;
            match visitor(matched) {
                Ok(true) => {}
                Ok(false) => return Ok(Ok(())),
                Err(error) => return Ok(Err(error)),
            }
        }
    }

    /// Count non-overlapping positive-width selected spans without accounting.
    #[doc(hidden)]
    pub fn count_spans_window_value(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<u64, PackedLiteralSetError> {
        let mut count = 0_u64;
        self.try_visit_spans_window_value(haystack, window, |_| {
            count = count
                .checked_add(1)
                .ok_or(PackedLiteralSetError::ArithmeticOverflow {
                    computation: "packed ordinary match count",
                })?;
            Ok::<bool, PackedLiteralSetError>(true)
        })??;
        Ok(count)
    }
}

fn validate_window(window: Window, haystack_len: usize) -> Result<(), PackedLiteralSetError> {
    if window.start() > window.end() || window.end() > haystack_len {
        return Err(PackedLiteralSetError::InvalidWindow {
            start: window.start(),
            end: window.end(),
            haystack_len,
        });
    }
    Ok(())
}

#[inline]
fn find_native_shared_columns(
    searcher: &Searcher,
    columns: &SharedColumns,
    haystack: &[u8],
) -> Option<(usize, usize)> {
    if haystack.len() <= columns.native_haystack_bytes {
        return searcher
            .find(haystack)
            .map(|matched| (matched.start(), matched.end()));
    }

    let minimum_start = match columns.find_amortized(haystack) {
        SharedColumnsFilterResult::Exhausted => return None,
        SharedColumnsFilterResult::Match { start, end } => return Some((start, end)),
        SharedColumnsFilterResult::ResumeAt(start) => start,
    };
    searcher.find(&haystack[minimum_start..]).and_then(|matched| {
        Some((
            minimum_start.checked_add(matched.start())?,
            minimum_start.checked_add(matched.end())?,
        ))
    })
}

#[inline]
fn find_native_shared_fragment(
    searcher: &Searcher,
    fragment: &SharedFragment,
    haystack: &[u8],
) -> Option<(usize, usize)> {
    if fragment.width >= LONG_SHARED_FRAGMENT_RECEIPT_MIN_BYTES {
        return find_native_long_shared_fragment(searcher, fragment, haystack);
    }
    let native_start_budget = fragment.native_start_budget;
    let native_prefix_bytes = fragment.native_prefix_bytes;
    if haystack.len() <= native_prefix_bytes {
        return searcher
            .find(haystack)
            .map(|matched| (matched.start(), matched.end()));
    }
    if let Some(matched) = searcher.find(&haystack[..native_prefix_bytes]) {
        if matched.start() < native_start_budget {
            // Every alternative at this start fits in the right overlap, so
            // the prefix engine observed the same source-priority choice as a
            // search of the complete source.
            return Some((matched.start(), matched.end()));
        }
    }

    // The public certificate charges every alternative at every possible
    // start. The bounded native prefix includes `maximum_pattern_width - 1`
    // bytes of right overlap, proving every start below `native_start_budget`.
    // The remaining envelope covers the monotone fragment pass, at most four
    // bounded outside-fragment verifications, and one packed fallback over a
    // suffix whose earlier starts have already been disproved.
    let fragment_haystack = haystack.get(native_start_budget..)?;
    let mut minimum_start = 0_usize;
    for attempt in 0..NATIVE_FILTER_CANDIDATE_BUDGET {
        let candidate = fragment.earliest_possible_start_from(fragment_haystack, minimum_start)?;
        let after_candidate = candidate.checked_add(1)?;
        let verification_attempts = attempt.checked_add(1)?;
        let required_skip = fragment
            .maximum_candidate_verification_work
            .checked_mul(verification_attempts)?;
        // Do not pay an exact probe that its proved source skip cannot
        // amortize. The native fallback restarts at the first unverified start,
        // so an actual match at this candidate and all overlaps remain visible.
        if after_candidate < required_skip {
            break;
        }
        if let Some(end) = fragment.verify_at(fragment_haystack, candidate) {
            return Some((
                native_start_budget.checked_add(candidate)?,
                native_start_budget.checked_add(end)?,
            ));
        }
        minimum_start = after_candidate;
    }
    let fallback_start = native_start_budget.checked_add(minimum_start)?;
    searcher
        .find(&haystack[fallback_start..])
        .and_then(|matched| {
            Some((
                fallback_start.checked_add(matched.start())?,
                fallback_start.checked_add(matched.end())?,
            ))
        })
}

#[inline]
fn find_native_long_shared_fragment(
    searcher: &Searcher,
    fragment: &SharedFragment,
    haystack: &[u8],
) -> Option<(usize, usize)> {
    // Preserve the frozen native service for every input in its existing
    // prefix envelope. The fragment-first route removes a repeated prefix scan
    // only for long buffers on an already-selected shared-fragment plan.
    if haystack.len() <= fragment.native_prefix_bytes {
        return searcher
            .find(haystack)
            .map(|matched| (matched.start(), matched.end()));
    }
    let minimum_start = match find_bounded_long_shared_fragment(fragment, haystack)? {
        LongSharedFragmentFilterResult::Exhausted => return None,
        LongSharedFragmentFilterResult::Match { start, end } => return Some((start, end)),
        LongSharedFragmentFilterResult::ResumeAt(start) => start,
    };
    searcher
        .find(&haystack[minimum_start..])
        .and_then(|matched| {
            Some((
                minimum_start.checked_add(matched.start())?,
                minimum_start.checked_add(matched.end())?,
            ))
        })
}

fn find_bounded_long_shared_fragment(
    fragment: &SharedFragment,
    haystack: &[u8],
) -> Option<LongSharedFragmentFilterResult> {
    let Some(first) = fragment.earliest_possible_start_from(haystack, 0) else {
        return Some(LongSharedFragmentFilterResult::Exhausted);
    };
    let after_first = first.checked_add(1)?;
    if let Some(end) = fragment.verify_at(haystack, first) {
        return Some(LongSharedFragmentFilterResult::Match { start: first, end });
    }
    let Some(second) = fragment.earliest_possible_start_from(haystack, after_first) else {
        return Some(LongSharedFragmentFilterResult::Exhausted);
    };
    if second < first.saturating_add(fragment.width) {
        // Overlapping occurrences are a saturated stream. Native
        // resumes after the one exactly disproved start instead of buying four
        // exact probes that advance only a handful of bytes.
        return Some(LongSharedFragmentFilterResult::ResumeAt(after_first));
    }

    let mut pending_candidate = Some(second);
    let mut minimum_start = after_first;
    for _ in 1..NATIVE_FILTER_CANDIDATE_BUDGET {
        let candidate = if let Some(candidate) = pending_candidate.take() {
            candidate
        } else {
            let Some(candidate) =
                fragment.earliest_possible_start_from(haystack, minimum_start)
            else {
                return Some(LongSharedFragmentFilterResult::Exhausted);
            };
            candidate
        };
        let after_candidate = candidate.checked_add(1)?;
        if let Some(end) = fragment.verify_at(haystack, candidate) {
            return Some(LongSharedFragmentFilterResult::Match {
                start: candidate,
                end,
            });
        }
        minimum_start = after_candidate;
    }
    Some(LongSharedFragmentFilterResult::ResumeAt(minimum_start))
}

fn shared_fragment_native_start_budget(
    native_minimum_haystack_bytes: usize,
    maximum_candidate_verification_work: usize,
) -> usize {
    // `minimum_len` is the native engine's smallest packed-effective service
    // quantum. A fragment probe may directly visit at most
    // `NATIVE_FILTER_CANDIDATE_BUDGET` candidates, each with the retained
    // worst-case verification work. Only a source longer than that complete
    // bounded filter envelope pays for a second engine.
    maximum_candidate_verification_work
        .saturating_mul(NATIVE_FILTER_CANDIDATE_BUDGET)
        .saturating_mul(native_minimum_haystack_bytes)
}

#[inline]
fn find_native(
    searcher: &Searcher,
    anchor: &SparseAnchor,
    haystack: &[u8],
) -> Option<(usize, usize)> {
    let mut minimum_start = 0_usize;
    for attempt in 0..NATIVE_FILTER_CANDIDATE_BUDGET {
        let candidate = anchor.earliest_possible_start_from(haystack, minimum_start)?;
        if let Some(end) = anchor.verify_at(haystack, candidate) {
            return Some((candidate, end));
        }
        minimum_start = candidate.checked_add(1)?;
        let verification_attempts = attempt.checked_add(1)?;
        let required_skip = anchor
            .maximum_candidate_verification_work
            .checked_mul(verification_attempts)?;
        if minimum_start < required_skip {
            break;
        }
    }
    searcher
        .find(&haystack[minimum_start..])
        .and_then(|matched| {
            Some((
                minimum_start.checked_add(matched.start())?,
                minimum_start.checked_add(matched.end())?,
            ))
        })
}

fn enforce_persistent_limit(
    build: &PackedLiteralSetBuildAccounting,
    limits: PackedLiteralSetBuildLimits,
) -> Result<(), PackedLiteralSetError> {
    if build.persistent_bytes > limits.max_persistent_bytes {
        Err(PackedLiteralSetError::PersistentBytesLimit {
            needed: build.persistent_bytes,
            limit: limits.max_persistent_bytes,
        })
    } else {
        Ok(())
    }
}

const fn factored_search_is_cost_admitted(build: &PackedLiteralSetBuildAccounting) -> bool {
    build.patterns > TEDDY_PATTERNS_PER_SEARCHER && build.patterns <= MAX_FACTORED_PATTERNS
}

fn select_sparse_anchor<P: AsRef<[u8]>>(patterns: &[P]) -> Option<SparseAnchor> {
    let retained_pattern_bytes = patterns.iter().try_fold(0_usize, |total, pattern| {
        let width = pattern.as_ref().len();
        let _ = u16::try_from(width).ok()?;
        total.checked_add(width)?.checked_add(size_of::<u16>())
    })?;
    if retained_pattern_bytes > NATIVE_FILTER_MAX_RETAINED_PATTERN_BYTES {
        return None;
    }
    let minimum_width = patterns
        .iter()
        .map(|pattern| pattern.as_ref().len())
        .min()?;
    let mut best = None;
    let mut best_score = (u64::MAX, usize::MAX, usize::MAX);
    for offset in 0..minimum_width {
        let mut bytes = [0_u8; MAX_FACTORED_ANCHOR_BYTES];
        let mut len = 0_usize;
        let mut eligible = true;
        for pattern in patterns {
            let byte = pattern.as_ref()[offset];
            if bytes[..len].contains(&byte) {
                continue;
            }
            let Some(slot) = bytes.get_mut(len) else {
                eligible = false;
                break;
            };
            *slot = byte;
            len = len.checked_add(1)?;
        }
        if !eligible || len == 0 {
            continue;
        }
        let frequency_score = bytes[..len]
            .iter()
            .map(|&byte| {
                u64::from(crate::packed_ordered_literal_aggregate::byte_frequency_rank(byte)) + 1
            })
            .sum();
        let score = (frequency_score, len, offset);
        if score < best_score {
            best_score = score;
            best = Some((offset, bytes, u8::try_from(len).ok()?));
        }
    }
    let (offset, bytes, len) = best?;
    let mut retained = Vec::with_capacity(retained_pattern_bytes);
    let mut group_ends = [0_u16; MAX_FACTORED_ANCHOR_BYTES];
    let mut maximum_candidate_verification_work = 0_usize;
    for (group, &anchor_byte) in bytes[..usize::from(len)].iter().enumerate() {
        let mut group_work = 0_usize;
        for pattern in patterns {
            let pattern = pattern.as_ref();
            if pattern[offset] != anchor_byte {
                continue;
            }
            retained.extend_from_slice(&u16::try_from(pattern.len()).ok()?.to_le_bytes());
            retained.extend_from_slice(pattern);
            group_work = group_work.checked_add(pattern.len())?.checked_add(1)?;
        }
        group_ends[group] = u16::try_from(retained.len()).ok()?;
        maximum_candidate_verification_work = maximum_candidate_verification_work.max(group_work);
    }
    debug_assert_eq!(retained.len(), retained_pattern_bytes);
    if maximum_candidate_verification_work > NATIVE_FILTER_MAX_CANDIDATE_VERIFICATION_WORK {
        return None;
    }
    Some(SparseAnchor {
        offset,
        bytes,
        len,
        minimum_pattern_width: minimum_width,
        group_ends,
        maximum_candidate_verification_work,
        patterns: retained.into_boxed_slice(),
    })
}

fn select_shared_columns<P: AsRef<[u8]>>(
    patterns: &[P],
    native_minimum_haystack_bytes: usize,
) -> Option<SharedColumns> {
    if patterns.len() < 2 || patterns.len() > TEDDY_PATTERNS_PER_SEARCHER {
        return None;
    }
    let first = patterns.first()?.as_ref();
    let width = first.len();
    if width < 2
        || patterns
            .iter()
            .any(|pattern| pattern.as_ref().len() != width)
        || patterns
            .iter()
            .skip(1)
            .all(|pattern| pattern.as_ref() == first)
    {
        return None;
    }

    // One mask lookup is charged for every non-anchor column plus the final
    // nonempty-mask decision. This derives the admitted width from the same
    // bounded candidate-work theorem used by the incumbent native filters.
    let maximum_candidate_verification_work = width;
    if maximum_candidate_verification_work > NATIVE_FILTER_MAX_CANDIDATE_VERIFICATION_WORK {
        return None;
    }

    let mut anchor = None;
    let mut anchor_score = (u8::MAX, usize::MAX);
    for offset in 0..width {
        let byte = first[offset];
        if patterns
            .iter()
            .all(|pattern| pattern.as_ref()[offset] == byte)
        {
            let score = (
                crate::packed_ordered_literal_aggregate::byte_frequency_rank(byte),
                offset,
            );
            if score < anchor_score {
                anchor_score = score;
                anchor = Some((offset, byte));
            }
        }
    }
    let (anchor_offset, anchor_byte) = anchor?;

    let pattern_mask = if patterns.len() == usize::try_from(u64::BITS).ok()? {
        u64::MAX
    } else {
        1_u64
            .checked_shl(u32::try_from(patterns.len()).ok()?)?
            .checked_sub(1)?
    };
    let mut ordered_columns = Vec::with_capacity(width.checked_sub(1)?);
    for offset in 0..width {
        if offset == anchor_offset {
            continue;
        }
        let mut by_byte = [0_u64; 256];
        for (pattern_index, pattern) in patterns.iter().enumerate() {
            let bit = 1_u64.checked_shl(u32::try_from(pattern_index).ok()?)?;
            let byte = pattern.as_ref()[offset];
            by_byte[usize::from(byte)] |= bit;
        }
        let maximum_bucket = by_byte.iter().try_fold(0_usize, |maximum, mask| {
            Some(maximum.max(usize::try_from(mask.count_ones()).ok()?))
        })?;
        let frequency_score = by_byte.iter().enumerate().try_fold(
            0_u64,
            |score, (byte, &mask)| {
                if mask == 0 {
                    Some(score)
                } else {
                    let rank = u64::from(
                        crate::packed_ordered_literal_aggregate::byte_frequency_rank(
                            u8::try_from(byte).ok()?,
                        ),
                    );
                    score.checked_add(rank.checked_add(1)?)
                }
            },
        )?;
        let score = (maximum_bucket, frequency_score, offset);
        ordered_columns.push((score, SharedColumnMask { offset, by_byte }));
    }
    // A column that isolates fewer alternatives is consumed first. This can
    // reject a false anchor after one lookup, while every successful path
    // still intersects every column and therefore proves an original word.
    ordered_columns.sort_by_key(|(score, _)| *score);
    let columns = ordered_columns
        .into_iter()
        .map(|(_, column)| column)
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let minimum_candidate_skip = maximum_candidate_verification_work
        .checked_mul(native_minimum_haystack_bytes)?;
    let native_start_budget = shared_fragment_native_start_budget(
        native_minimum_haystack_bytes,
        maximum_candidate_verification_work,
    );
    let native_haystack_bytes = width
        .checked_sub(1)?
        .checked_add(native_start_budget)?;
    Some(SharedColumns {
        width,
        anchor_offset,
        anchor_byte,
        pattern_mask,
        maximum_candidate_verification_work,
        minimum_candidate_skip,
        native_haystack_bytes,
        columns,
    })
}

fn select_shared_fragment<P: AsRef<[u8]>>(
    patterns: &[P],
    native_minimum_haystack_bytes: usize,
) -> Option<SharedFragment> {
    if patterns.len() < 2 {
        return None;
    }
    let retained_pattern_bytes = patterns.iter().try_fold(0_usize, |total, pattern| {
        let width = pattern.as_ref().len();
        let _ = u16::try_from(width).ok()?;
        total.checked_add(width)?.checked_add(size_of::<u16>())
    })?;
    if retained_pattern_bytes > NATIVE_FILTER_MAX_RETAINED_PATTERN_BYTES {
        return None;
    }
    let first = patterns.first()?.as_ref();
    let minimum_pattern_width = patterns
        .iter()
        .map(|pattern| pattern.as_ref().len())
        .min()?;
    let maximum_pattern_width = patterns
        .iter()
        .map(|pattern| pattern.as_ref().len())
        .max()?;
    let mut best_offset = 0_usize;
    let mut best_width = 0_usize;
    let mut best_frequency_score = u64::MAX;
    let mut column = 0_usize;
    while column < minimum_pattern_width {
        if patterns
            .iter()
            .any(|pattern| pattern.as_ref()[column] != first[column])
        {
            column = column.checked_add(1)?;
            continue;
        }
        let run_start = column;
        let mut frequency_score = 0_u64;
        while column < minimum_pattern_width
            && patterns
                .iter()
                .all(|pattern| pattern.as_ref()[column] == first[column])
        {
            frequency_score = frequency_score.checked_add(
                u64::from(crate::packed_ordered_literal_aggregate::byte_frequency_rank(
                    first[column],
                )) + 1,
            )?;
            column = column.checked_add(1)?;
        }
        let run_width = column.checked_sub(run_start)?;
        if run_width > best_width
            || (run_width == best_width
                && (frequency_score, run_start) < (best_frequency_score, best_offset))
        {
            best_offset = run_start;
            best_width = run_width;
            best_frequency_score = frequency_score;
        }
    }
    if best_width < SHARED_FRAGMENT_MIN_BYTES {
        return None;
    }
    let maximum_candidate_verification_work = patterns.iter().try_fold(
        0_usize,
        |work, pattern| {
            pattern
                .as_ref()
                .len()
                .checked_sub(best_width)?
                .checked_add(1)?
                .checked_add(work)
        },
    )?;
    if maximum_candidate_verification_work > NATIVE_FILTER_MAX_CANDIDATE_VERIFICATION_WORK {
        return None;
    }
    let native_start_budget = shared_fragment_native_start_budget(
        native_minimum_haystack_bytes,
        maximum_candidate_verification_work,
    );
    let native_prefix_bytes = maximum_pattern_width
        .checked_sub(1)?
        .checked_add(native_start_budget)?;

    let mut retained = Vec::with_capacity(retained_pattern_bytes);
    for pattern in patterns {
        let pattern = pattern.as_ref();
        retained.extend_from_slice(&u16::try_from(pattern.len()).ok()?.to_le_bytes());
        retained.extend_from_slice(pattern);
    }
    let fragment_end = best_offset.checked_add(best_width)?;
    let mut needle = Vec::with_capacity(best_width);
    needle.extend_from_slice(first.get(best_offset..fragment_end)?);
    Some(SharedFragment {
        offset: best_offset,
        width: best_width,
        minimum_pattern_width,
        maximum_candidate_verification_work,
        native_start_budget,
        native_prefix_bytes,
        finder: FinderBuilder::new().build_forward_owned(needle),
        patterns: retained.into_boxed_slice(),
    })
}

fn factor_complete_columns<P: AsRef<[u8]>>(
    patterns: &[P],
    build: &PackedLiteralSetBuildAccounting,
) -> Option<FactoredColumns> {
    if !factored_search_is_cost_admitted(build) {
        return None;
    }
    let width = patterns.first()?.as_ref().len();
    if !(FULL_TEDDY_FILTER_BYTES..=MAX_FACTORED_COLUMNS).contains(&width)
        || patterns
            .iter()
            .any(|pattern| pattern.as_ref().len() != width)
    {
        return None;
    }

    let mut columns = [[0_u64; 4]; MAX_FACTORED_COLUMNS];
    for pattern in patterns {
        for (column, &byte) in pattern.as_ref().iter().enumerate() {
            let word = usize::from(byte) >> 6;
            columns[column][word] |= 1_u64 << (byte & 63);
        }
    }
    let mut cardinalities = [0_usize; MAX_FACTORED_COLUMNS];
    let mut product = 1_usize;
    for column in 0..width {
        cardinalities[column] = columns[column].iter().map(|word| population(*word)).sum();
        product = product.checked_mul(cardinalities[column])?;
        if product > patterns.len() {
            return None;
        }
    }
    if product != patterns.len() {
        return None;
    }

    // Prove that every mixed-radix tuple occurs exactly once. Equal marginal
    // cardinality alone is insufficient in the presence of a duplicate and a
    // missing combination. Every admitted word has the same width, so source
    // priority cannot change the observable span after this proof succeeds.
    let mut seen = [0_u64; 2];
    for pattern in patterns {
        let mut tuple = 0_usize;
        for (column, &byte) in pattern.as_ref().iter().enumerate() {
            tuple = tuple
                .checked_mul(cardinalities[column])?
                .checked_add(class_rank(&columns[column], byte))?;
        }
        let word = tuple >> 6;
        let bit = 1_u64 << (tuple & 63);
        if seen[word] & bit != 0 {
            return None;
        }
        seen[word] |= bit;
    }

    let mut anchor_offset = None;
    let mut anchor_score = (u64::MAX, usize::MAX);
    for column in 0..width {
        let cardinality = cardinalities[column];
        if cardinality > MAX_FACTORED_ANCHOR_BYTES {
            continue;
        }
        let frequency_score = class_bytes(&columns[column])
            .map(|byte| {
                u64::from(crate::packed_ordered_literal_aggregate::byte_frequency_rank(byte)) + 1
            })
            .sum();
        let score = (frequency_score, cardinality);
        if score < anchor_score {
            anchor_score = score;
            anchor_offset = Some(column);
        }
    }
    let anchor_offset = anchor_offset?;
    let mut anchor_bytes = [0_u8; MAX_FACTORED_ANCHOR_BYTES];
    let mut anchor_len = 0_usize;
    for byte in class_bytes(&columns[anchor_offset]) {
        *anchor_bytes.get_mut(anchor_len)? = byte;
        anchor_len = anchor_len.checked_add(1)?;
    }
    Some(FactoredColumns {
        columns,
        width: u8::try_from(width).ok()?,
        anchor_offset: u8::try_from(anchor_offset).ok()?,
        anchor_bytes,
        anchor_len: u8::try_from(anchor_len).ok()?,
    })
}

fn class_contains(class: &[u64; 4], byte: u8) -> bool {
    let word = usize::from(byte) >> 6;
    class[word] & (1_u64 << (byte & 63)) != 0
}

fn class_rank(class: &[u64; 4], byte: u8) -> usize {
    let word = usize::from(byte) >> 6;
    let preceding_words = class[..word]
        .iter()
        .map(|bits| population(*bits))
        .sum::<usize>();
    let preceding_bits = class[word] & ((1_u64 << (byte & 63)).wrapping_sub(1));
    preceding_words
        .checked_add(population(preceding_bits))
        .expect("a byte-class rank is at most 255")
}

fn population(bits: u64) -> usize {
    usize::try_from(bits.count_ones()).expect("a u64 population count fits usize")
}

fn class_bytes(class: &[u64; 4]) -> impl Iterator<Item = u8> + '_ {
    (0_u16..=u16::from(u8::MAX))
        .map(|byte| u8::try_from(byte).expect("the bounded byte domain fits u8"))
        .filter(|&byte| class_contains(class, byte))
}

fn preflight<P: AsRef<[u8]>>(
    patterns: &[P],
    limits: PackedLiteralSetBuildLimits,
) -> Result<PackedLiteralSetBuildAccounting, PackedLiteralSetError> {
    if patterns.is_empty() {
        return Err(PackedLiteralSetError::EmptyPatternSet);
    }
    if patterns.len() > limits.max_patterns {
        return Err(PackedLiteralSetError::PatternLimit {
            needed: patterns.len(),
            limit: limits.max_patterns,
        });
    }
    let mut pattern_bytes = 0_usize;
    let mut max_pattern_bytes = 0_usize;
    for (index, pattern) in patterns.iter().enumerate() {
        let bytes = pattern.as_ref();
        if bytes.is_empty() {
            return Err(PackedLiteralSetError::EmptyPattern { index });
        }
        pattern_bytes = pattern_bytes.checked_add(bytes.len()).ok_or(
            PackedLiteralSetError::ArithmeticOverflow {
                computation: "packed literal pattern bytes",
            },
        )?;
        max_pattern_bytes = max_pattern_bytes.max(bytes.len());
    }
    if pattern_bytes > limits.max_pattern_bytes {
        return Err(PackedLiteralSetError::PatternBytesLimit {
            needed: pattern_bytes,
            limit: limits.max_pattern_bytes,
        });
    }
    let build_work_upper_bound =
        packed_literal_set_build_work_upper_bound_from_dimensions(patterns.len(), pattern_bytes)?;
    if build_work_upper_bound > limits.max_build_work {
        return Err(PackedLiteralSetError::BuildWorkLimit {
            needed: build_work_upper_bound,
            limit: limits.max_build_work,
        });
    }
    let pattern_storage = pattern_bytes.checked_mul(PATTERN_BYTE_ENVELOPE).ok_or(
        PackedLiteralSetError::ArithmeticOverflow {
            computation: "packed literal pattern storage envelope",
        },
    )?;
    let entry_storage = patterns.len().checked_mul(PATTERN_ENTRY_ENVELOPE).ok_or(
        PackedLiteralSetError::ArithmeticOverflow {
            computation: "packed literal entry storage envelope",
        },
    )?;
    let build_bytes_upper_bound = pattern_storage
        .checked_add(entry_storage)
        .and_then(|bytes| bytes.checked_add(FIXED_BUILD_ENVELOPE))
        .ok_or(PackedLiteralSetError::ArithmeticOverflow {
            computation: "packed literal peak-build byte envelope",
        })?;
    if build_bytes_upper_bound > limits.max_build_bytes {
        return Err(PackedLiteralSetError::BuildBytesLimit {
            needed: build_bytes_upper_bound,
            limit: limits.max_build_bytes,
        });
    }
    Ok(PackedLiteralSetBuildAccounting {
        patterns: patterns.len(),
        pattern_bytes,
        max_pattern_bytes,
        build_work_upper_bound,
        build_bytes_upper_bound,
        persistent_bytes: 0,
        simd_minimum_haystack_bytes: 0,
    })
}

#[cfg(all(test, not(feature = "static-dispatch")))]
mod uniform_word64_allocation_probe {
    use std::cell::Cell;

    thread_local! {
        static FAIL_NEXT: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) struct Guard;

    impl Drop for Guard {
        fn drop(&mut self) {
            FAIL_NEXT.with(|fail| fail.set(false));
        }
    }

    pub(super) fn fail_next() -> Guard {
        FAIL_NEXT.with(|fail| fail.set(true));
        Guard
    }

    pub(super) fn take_failure() -> bool {
        FAIL_NEXT.with(|fail| fail.replace(false))
    }
}

#[cfg(all(test, not(feature = "static-dispatch")))]
mod retained_iter_owner_allocation_probe {
    use std::cell::Cell;

    thread_local! {
        static FAIL_NEXT: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) struct Guard;

    impl Drop for Guard {
        fn drop(&mut self) {
            FAIL_NEXT.with(|fail| fail.set(false));
        }
    }

    pub(super) fn fail_next() -> Guard {
        FAIL_NEXT.with(|fail| {
            assert!(!fail.replace(true));
        });
        Guard
    }

    pub(super) fn take_failure() -> bool {
        FAIL_NEXT.with(|fail| fail.replace(false))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BUILD_FACTOR, LONG_SHARED_FRAGMENT_BUILD_CAPABILITY_ID,
        LONG_SHARED_FRAGMENT_RECEIPT_MIN_BYTES, NATIVE_FILTER_CANDIDATE_BUDGET,
        LongSharedFragmentFilterResult, PackedLiteralEngine,
        PackedLiteralSetAccounting, PackedLiteralSetBuildLimits, PackedLiteralSetError,
        PackedLiteralSetLongSharedFragmentBuildReceipt, PackedLiteralSetPlan,
        PackedLiteralSetSearchLimits, RUNTIME_IMPLEMENTATION_ID,
        find_bounded_long_shared_fragment,
        packed_literal_set_build_work_upper_bound_from_dimensions, select_shared_columns,
        select_shared_fragment, select_sparse_anchor, shared_fragment_native_start_budget,
    };
    #[cfg(not(feature = "static-dispatch"))]
    use super::{
        RETAINED_ITER_BUILD_CAPABILITY_ID, RETAINED_ITER_RUNTIME_IMPLEMENTATION_ID,
        UNIFORM_WORD64_MASK_BYTES, UNIFORM_WORD64_RUNTIME_IMPLEMENTATION_ID,
        retained_iter_owner_allocation_probe, uniform_word64_allocation_probe,
    };
    use crate::Window;

    fn plan(patterns: &[&[u8]]) -> Option<PackedLiteralSetPlan> {
        match PackedLiteralSetPlan::new(patterns, PackedLiteralSetBuildLimits::default()) {
            Ok(plan) => Some(plan),
            Err(PackedLiteralSetError::UnsupportedTargetOrShape) => None,
            Err(error) => panic!("unexpected packed-plan error: {error}"),
        }
    }

    fn fixed_patterns(count: usize, width: usize) -> Vec<Vec<u8>> {
        assert!(width >= 3);
        let third_from_end = width.checked_sub(3).unwrap();
        let second_from_end = width.checked_sub(2).unwrap();
        let last = width.checked_sub(1).unwrap();
        (0..count)
            .map(|index| {
                let mut pattern = vec![b'p'; width];
                pattern[third_from_end] = u8::try_from(index).unwrap();
                let mixed = index.checked_mul(193).unwrap() % 251;
                pattern[second_from_end] = u8::try_from(mixed).unwrap();
                pattern[last] = b'x';
                pattern
            })
            .collect()
    }

    fn pattern_refs(patterns: &[Vec<u8>]) -> Vec<&[u8]> {
        patterns.iter().map(Vec::as_slice).collect()
    }

    fn shared_prefix_patterns() -> [&'static [u8]; 8] {
        [
            b"aa00x", b"aa11", b"aa22", b"aa33", b"aa44", b"aa55", b"aa66", b"aa77",
        ]
    }

    fn cartesian_patterns() -> Vec<Vec<u8>> {
        let mut patterns = Vec::new();
        for first in b'm'..=b'r' {
            for second in b'3'..=b'8' {
                for fourth in [b'u', b'v'] {
                    patterns.push(vec![first, second, b'T', fourth]);
                }
            }
        }
        patterns
    }

    fn cartesian_grid(rows: u8, columns: u8) -> Vec<Vec<u8>> {
        let mut patterns = Vec::new();
        for row in 0..rows {
            for column in 0..columns {
                patterns.push(vec![row, column, b'Q', b'x']);
            }
        }
        patterns
    }

    fn high_byte_suffix_patterns() -> Vec<Vec<u8>> {
        (0x80_u8..=0x9f).map(|byte| vec![byte, b'Q']).collect()
    }

    fn cartesian_four(classes: [&[u8]; 4]) -> Vec<Vec<u8>> {
        let mut patterns = Vec::new();
        for &first in classes[0] {
            for &second in classes[1] {
                for &third in classes[2] {
                    for &fourth in classes[3] {
                        patterns.push(vec![first, second, third, fourth]);
                    }
                }
            }
        }
        patterns
    }

    fn assert_invalid_windows_precede_work(plan: &PackedLiteralSetPlan, haystack: &[u8]) {
        let zero_work = PackedLiteralSetSearchLimits { max_work: 0 };
        assert_eq!(
            plan.find_window(haystack, Window::new(1, 0), zero_work),
            Err(PackedLiteralSetError::InvalidWindow {
                start: 1,
                end: 0,
                haystack_len: haystack.len(),
            })
        );
        let past_end = haystack.len().checked_add(1).unwrap();
        assert_eq!(
            plan.find_window(haystack, Window::new(0, past_end), zero_work),
            Err(PackedLiteralSetError::InvalidWindow {
                start: 0,
                end: past_end,
                haystack_len: haystack.len(),
            })
        );
    }

    #[cfg(not(feature = "static-dispatch"))]
    fn fixed_width_oracle(
        patterns: &[&[u8]],
        haystack: &[u8],
        window: Window,
    ) -> Option<(usize, usize)> {
        let width = patterns.first()?.len();
        let last_start = window.end().checked_sub(width)?;
        if window.start() > last_start {
            return None;
        }
        for start in window.start()..=last_start {
            let end = start.checked_add(width)?;
            let candidate = haystack.get(start..end)?;
            if patterns.contains(&candidate) {
                return Some((start, end));
            }
        }
        None
    }

    fn assert_search_certificate(
        plan: &PackedLiteralSetPlan,
        factored_columns: bool,
        haystack: &[u8],
        window: Window,
        expected_match: Option<(usize, usize)>,
    ) {
        let (matched, accounting) = plan
            .find_window(haystack, window, PackedLiteralSetSearchLimits::unlimited())
            .unwrap();
        assert_eq!(matched, expected_match);
        let build = plan.build_accounting();
        let searched_bytes = window.end().checked_sub(window.start()).unwrap();
        let positions_upper_bound = searched_bytes.checked_add(1).unwrap();
        let verification_bytes_per_position =
            build.pattern_bytes.checked_add(build.patterns).unwrap();
        let work_upper_bound = positions_upper_bound
            .checked_mul(verification_bytes_per_position)
            .unwrap();
        assert_eq!(
            plan.verification_bytes_per_position
                .checked_mul(BUILD_FACTOR),
            Some(build.build_work_upper_bound)
        );
        assert_eq!(
            accounting,
            PackedLiteralSetAccounting {
                searched_bytes,
                positions_upper_bound,
                verification_bytes_per_position,
                work_upper_bound,
                scratch_bytes: 0,
                factored_columns,
                simd_eligible_length: searched_bytes >= build.simd_minimum_haystack_bytes,
            }
        );
        assert_eq!(
            plan.find_window(
                haystack,
                window,
                PackedLiteralSetSearchLimits {
                    max_work: work_upper_bound,
                },
            ),
            Ok((expected_match, accounting))
        );
        let one_below = work_upper_bound.checked_sub(1).unwrap();
        assert_eq!(
            plan.find_window(
                haystack,
                window,
                PackedLiteralSetSearchLimits {
                    max_work: one_below,
                },
            ),
            Err(PackedLiteralSetError::WorkLimit {
                needed: work_upper_bound,
                limit: one_below,
            })
        );
    }

    fn assert_native_anchor_matches_unfiltered(plan: &PackedLiteralSetPlan, haystack: &[u8]) {
        let searcher = match &plan.engine {
            #[cfg(not(feature = "static-dispatch"))]
            PackedLiteralEngine::UniformWord64(_)
            | PackedLiteralEngine::UniformWord64Retained { .. } => {
                panic!("differential helper requires a native packed plan")
            }
            PackedLiteralEngine::Native(searcher)
            | PackedLiteralEngine::NativeSparse { searcher, .. }
            | PackedLiteralEngine::NativeSharedFragment { searcher, .. }
            | PackedLiteralEngine::NativeSharedColumns { searcher, .. } => searcher,
            PackedLiteralEngine::Factored(_) => {
                panic!("differential helper requires a native packed plan")
            }
        };
        for start in 0..=haystack.len() {
            for end in start..=haystack.len() {
                let expected = searcher.find(&haystack[start..end]).map(|matched| {
                    (
                        start.checked_add(matched.start()).unwrap(),
                        start.checked_add(matched.end()).unwrap(),
                    )
                });
                let actual = plan
                    .find_window(
                        haystack,
                        Window::new(start, end),
                        PackedLiteralSetSearchLimits::unlimited(),
                    )
                    .unwrap()
                    .0;
                assert_eq!(actual, expected, "window={start}..{end}");
            }
        }
    }

    #[test]
    fn dimension_only_build_work_matches_packed_preflight() {
        assert_eq!(
            packed_literal_set_build_work_upper_bound_from_dimensions(0, 0),
            Err(PackedLiteralSetError::EmptyPatternSet),
        );
        assert_eq!(
            packed_literal_set_build_work_upper_bound_from_dimensions(1, 0),
            Err(PackedLiteralSetError::EmptyPattern { index: 0 }),
        );
        for pattern_bytes in [usize::MAX, usize::MAX / BUILD_FACTOR] {
            assert!(matches!(
                packed_literal_set_build_work_upper_bound_from_dimensions(1, pattern_bytes),
                Err(PackedLiteralSetError::ArithmeticOverflow {
                    computation: "packed literal build work",
                }),
            ));
        }

        let patterns: &[&[u8]] = &[b"a", b"bc", b"def"];
        let pattern_bytes = 6_usize;
        let expected = pattern_bytes
            .checked_add(patterns.len())
            .and_then(|work| work.checked_mul(BUILD_FACTOR))
            .unwrap();
        assert_eq!(
            packed_literal_set_build_work_upper_bound_from_dimensions(
                patterns.len(),
                pattern_bytes,
            ),
            Ok(expected),
        );
        assert!(matches!(
            PackedLiteralSetPlan::new(
                patterns,
                PackedLiteralSetBuildLimits {
                    max_build_work: expected - 1,
                    ..PackedLiteralSetBuildLimits::default()
                },
            ),
            Err(PackedLiteralSetError::BuildWorkLimit { needed, limit })
                if needed == expected && limit == expected - 1,
        ));
    }

    #[test]
    fn native_and_factored_certificates_preserve_windows_limits_and_accounting() {
        let Some(native) = plan(&[b"ab", b"cd"]) else {
            return;
        };
        assert!(matches!(
            &native.engine,
            PackedLiteralEngine::Native(_) | PackedLiteralEngine::NativeSparse { .. }
        ));
        let native_haystack = b"ab--cd";
        assert_invalid_windows_precede_work(&native, native_haystack);
        for (window, expected) in [
            (Window::full(native_haystack), Some((0, 2))),
            (Window::new(4, 6), Some((4, 6))),
            (Window::new(2, 4), None),
        ] {
            assert_search_certificate(&native, false, native_haystack, window, expected);
        }

        let patterns = cartesian_patterns();
        let refs = pattern_refs(&patterns);
        let factored =
            PackedLiteralSetPlan::new(&refs, PackedLiteralSetBuildLimits::default()).unwrap();
        assert!(matches!(&factored.engine, PackedLiteralEngine::Factored(_)));
        let factored_haystack = b"m3Tu--r8Tv";
        assert_invalid_windows_precede_work(&factored, factored_haystack);
        for (window, expected) in [
            (Window::full(factored_haystack), Some((0, 4))),
            (Window::new(6, 10), Some((6, 10))),
            (Window::new(4, 6), None),
        ] {
            assert_search_certificate(&factored, true, factored_haystack, window, expected);
        }
    }

    #[test]
    fn native_sparse_anchor_skips_only_proved_impossible_starts() {
        let patterns = [b"aQ".as_slice(), b"bQ".as_slice(), b"cQ".as_slice()];
        let Some(plan) = plan(&patterns) else {
            return;
        };
        let PackedLiteralEngine::NativeSparse {
            sparse_anchor: anchor,
            ..
        } = &plan.engine
        else {
            panic!("native language did not retain its sparse anchor")
        };
        assert_eq!(anchor.offset, 1);
        assert_eq!(anchor.len, 1);
        assert_eq!(anchor.bytes[0], b'Q');
        let persistent = plan.build_accounting().persistent_bytes;
        assert_eq!(
            PackedLiteralSetPlan::new(
                &patterns,
                PackedLiteralSetBuildLimits {
                    max_persistent_bytes: persistent,
                    ..PackedLiteralSetBuildLimits::default()
                },
            )
            .unwrap()
            .build_accounting()
            .persistent_bytes,
            persistent
        );
        assert!(matches!(
            PackedLiteralSetPlan::new(
                &patterns,
                PackedLiteralSetBuildLimits {
                    max_persistent_bytes: persistent - 1,
                    ..PackedLiteralSetBuildLimits::default()
                },
            ),
            Err(PackedLiteralSetError::PersistentBytesLimit { needed, limit })
                if needed == persistent && limit == persistent - 1
        ));

        let mut haystack = vec![b'.'; 384];
        assert_native_anchor_matches_unfiltered(&plan, &haystack);
        let (matched, accounting) = plan
            .find(&haystack, PackedLiteralSetSearchLimits::unlimited())
            .unwrap();
        assert_eq!(matched, None);
        assert_eq!(
            plan.find(
                &haystack,
                PackedLiteralSetSearchLimits {
                    max_work: accounting.work_upper_bound.checked_sub(1).unwrap(),
                },
            ),
            Err(PackedLiteralSetError::WorkLimit {
                needed: accounting.work_upper_bound,
                limit: accounting.work_upper_bound.checked_sub(1).unwrap(),
            })
        );

        // An early anchor that cannot complete a word may reduce the prefix,
        // but the unchanged ordered searcher still finds the later match.
        for anchor in [13_usize, 25, 37, 49] {
            haystack[anchor] = b'Q';
        }
        haystack[96] = b'b';
        haystack[97] = b'Q';
        assert_native_anchor_matches_unfiltered(&plan, &haystack);
        assert_eq!(
            plan.find(&haystack, PackedLiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            Some((96, 98))
        );
        assert_eq!(
            plan.find_window(
                &haystack,
                Window::new(34, 96),
                PackedLiteralSetSearchLimits::unlimited(),
            )
            .unwrap()
            .0,
            None
        );

        // Reusing the same allocation after mutation cannot retain a prior
        // negative decision because the anchor owns no haystack-derived state.
        haystack.fill(b'.');
        haystack[12] = b'a';
        haystack[13] = b'Q';
        assert_native_anchor_matches_unfiltered(&plan, &haystack);
        assert_eq!(
            plan.find(&haystack, PackedLiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            Some((12, 14))
        );

        // Four clustered false candidates exhaust the largest admitted
        // direct-verification budget. Teddy resumes strictly after them and
        // still reports the later leftmost match.
        let mut dense_decoys = vec![b'.'; 1_536];
        for anchor in [13_usize, 25, 37, 49] {
            dense_decoys[anchor] = b'Q';
        }
        dense_decoys[700] = b'c';
        dense_decoys[701] = b'Q';
        assert_eq!(
            plan.find(&dense_decoys, PackedLiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            Some((700, 702))
        );
    }

    #[test]
    fn sparse_anchor_selects_one_two_and_three_byte_columns() {
        let one_patterns = [b"aQ".as_slice(), b"bQ".as_slice(), b"cQ".as_slice()];
        let one = select_sparse_anchor(&one_patterns).unwrap();
        assert_eq!((one.offset, one.len), (1, 1));
        assert_eq!(one.maximum_candidate_verification_work, 9);

        let too_expensive = high_byte_suffix_patterns();
        let too_expensive_refs = pattern_refs(&too_expensive);
        assert!(select_sparse_anchor(&too_expensive_refs).is_none());

        let two_patterns = [
            [b'a', 0x80, b'w'],
            [b'b', 0x81, b'x'],
            [b'c', 0x80, b'y'],
            [b'd', 0x81, b'z'],
        ];
        let two_anchor = select_sparse_anchor(&two_patterns).unwrap();
        assert_eq!((two_anchor.offset, two_anchor.len), (1, 2));

        let three_patterns = [
            [b'a', 0x80, b'w'],
            [b'b', 0x81, b'x'],
            [b'c', 0x82, b'y'],
            [b'd', 0x80, b'z'],
        ];
        let three_anchor = select_sparse_anchor(&three_patterns).unwrap();
        assert_eq!((three_anchor.offset, three_anchor.len), (1, 3));

        let mut beyond = select_sparse_anchor(&[b"Q"]).unwrap();
        beyond.offset = 8;
        assert_eq!(beyond.earliest_possible_start_from(b"short", 0), None);

        for patterns in [two_patterns.as_slice(), three_patterns.as_slice()] {
            let refs: Vec<&[u8]> = patterns.iter().map(|pattern| pattern.as_slice()).collect();
            let Some(plan) = plan(&refs) else {
                return;
            };
            let mut haystack = vec![b'.'; 192];
            haystack[25] = patterns[0][1];
            haystack[140..143].copy_from_slice(&patterns[2]);
            let expected = Some((140, 143));
            assert_eq!(
                plan.find(&haystack, PackedLiteralSetSearchLimits::unlimited())
                    .unwrap()
                    .0,
                expected
            );
            assert_eq!(
                plan.find_window(
                    &haystack,
                    Window::new(12, 180),
                    PackedLiteralSetSearchLimits::unlimited(),
                )
                .unwrap()
                .0,
                expected
            );
        }
    }

    #[test]
    fn shared_fragment_selects_the_longest_fixed_offset_run() {
        let prefix_patterns = [
            b"xy00".as_slice(),
            b"xy11".as_slice(),
            b"xy22".as_slice(),
            b"xy33".as_slice(),
            b"xy44".as_slice(),
            b"xy55".as_slice(),
            b"xy66".as_slice(),
            b"xy77".as_slice(),
        ];
        let prefix = select_shared_fragment(&prefix_patterns, 1).unwrap();
        assert_eq!((prefix.offset, prefix.width), (0, 2));
        assert_eq!(prefix.maximum_candidate_verification_work, 24);

        let interior_patterns = [
            b"aQR0".as_slice(),
            b"bQR1".as_slice(),
            b"cQR2".as_slice(),
        ];
        let interior = select_shared_fragment(&interior_patterns, 1).unwrap();
        assert_eq!((interior.offset, interior.width), (1, 2));
        assert_eq!(interior.maximum_candidate_verification_work, 9);
        assert!(select_sparse_anchor(&interior_patterns).is_some());
        if let Some(incumbent) = plan(&interior_patterns) {
            assert!(matches!(
                &incumbent.engine,
                PackedLiteralEngine::NativeSparse { .. }
            ));
        }

        let expensive = [
            b"xy00".as_slice(),
            b"xy11".as_slice(),
            b"xy22".as_slice(),
            b"xy33".as_slice(),
            b"xy44".as_slice(),
            b"xy55".as_slice(),
            b"xy66".as_slice(),
            b"xy77".as_slice(),
            b"xy88".as_slice(),
            b"xy99".as_slice(),
            b"xyAA".as_slice(),
        ];
        assert!(select_shared_fragment(&expensive, 1).is_none());
        assert!(
            select_shared_fragment(&[b"ab".as_slice(), b"ac".as_slice()], 1).is_none()
        );
    }

    #[test]
    fn long_shared_fragment_selection_has_an_exact_public_receipt() {
        let patterns = [
            b"longpref0".as_slice(),
            b"longpref11".as_slice(),
            b"longpref222".as_slice(),
            b"longpref3333".as_slice(),
        ];
        assert!(select_sparse_anchor(&patterns).is_none());
        let Some(plan) = plan(&patterns) else {
            return;
        };
        let PackedLiteralEngine::NativeSharedFragment {
            shared_fragment, ..
        } = &plan.engine
        else {
            panic!("long common fragment did not select its shared-fragment engine")
        };
        assert!(shared_fragment.width >= LONG_SHARED_FRAGMENT_RECEIPT_MIN_BYTES);
        assert_eq!(
            plan.long_shared_fragment_build_receipt(),
            Some(PackedLiteralSetLongSharedFragmentBuildReceipt {
                capability_id: LONG_SHARED_FRAGMENT_BUILD_CAPABILITY_ID,
                fragment_offset: shared_fragment.offset,
                fragment_bytes: shared_fragment.width,
                minimum_pattern_bytes: shared_fragment.minimum_pattern_width,
                maximum_candidate_verification_work: shared_fragment
                    .maximum_candidate_verification_work,
                native_prefix_bytes: shared_fragment.native_prefix_bytes,
            })
        );
    }

    #[test]
    fn frozen_planner_keeps_rare_anchor_over_common_long_fragment() {
        let patterns = [
            b"longpref\x1ctail".as_slice(),
            b"longpref\x1dtail".as_slice(),
            b"longpref\x1etail".as_slice(),
        ];
        assert!(select_sparse_anchor(&patterns).is_some());
        let Some(plan) = plan(&patterns) else {
            return;
        };
        assert!(matches!(
            &plan.engine,
            PackedLiteralEngine::NativeSparse { .. }
        ));
        assert_eq!(plan.long_shared_fragment_build_receipt(), None);
        assert_native_anchor_matches_unfiltered(&plan, b"longprefxlongpref\x1dtail");
    }

    #[test]
    fn selected_long_fragment_handles_sparse_late_dense_and_saturated_streams() {
        let patterns = [
            b"longpref0".as_slice(),
            b"longpref11".as_slice(),
            b"longpref222".as_slice(),
            b"longpref3333".as_slice(),
        ];
        let Some(selected_plan) = plan(&patterns) else {
            return;
        };
        let PackedLiteralEngine::NativeSharedFragment {
            searcher,
            shared_fragment,
        } = &selected_plan.engine
        else {
            panic!("long common fragment did not select its shared-fragment engine")
        };

        let sparse = vec![b'.'; 64 * 1024];
        assert_eq!(
            find_bounded_long_shared_fragment(shared_fragment, &sparse),
            Some(LongSharedFragmentFilterResult::Exhausted),
        );
        assert_eq!(
            selected_plan.find(&sparse, PackedLiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            None,
        );

        let late_start = sparse.len() - patterns[2].len();
        let late_end = late_start + patterns[2].len();
        let mut late = sparse;
        late[late_start..late_end].copy_from_slice(patterns[2]);
        assert_eq!(
            find_bounded_long_shared_fragment(shared_fragment, &late),
            Some(LongSharedFragmentFilterResult::Match {
                start: late_start,
                end: late_end,
            }),
        );

        let decoy = b"longprefx";
        let match_start = shared_fragment.native_prefix_bytes + 73;
        let match_end = match_start + patterns[3].len();
        let mut dense = vec![b'.'; match_end + 17];
        for start in [0, decoy.len(), decoy.len() * 2, decoy.len() * 3] {
            dense[start..start + decoy.len()].copy_from_slice(decoy);
        }
        dense[match_start..match_end].copy_from_slice(patterns[3]);
        let expected = searcher
            .find(&dense)
            .map(|matched| (matched.start(), matched.end()));
        assert_eq!(expected, Some((match_start, match_end)));
        assert_eq!(
            selected_plan.find(&dense, PackedLiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            expected,
        );

        let saturated_patterns = [
            b"aaaaaaaa0".as_slice(),
            b"aaaaaaaa11".as_slice(),
            b"aaaaaaaa222".as_slice(),
            b"aaaaaaaa3333".as_slice(),
        ];
        let Some(saturated_plan) = plan(&saturated_patterns) else {
            return;
        };
        let PackedLiteralEngine::NativeSharedFragment {
            searcher,
            shared_fragment,
        } = &saturated_plan.engine
        else {
            panic!("saturated language did not select its shared-fragment engine")
        };
        let saturated = vec![b'a'; shared_fragment.native_prefix_bytes + 97];
        assert_eq!(
            find_bounded_long_shared_fragment(shared_fragment, &saturated),
            Some(LongSharedFragmentFilterResult::ResumeAt(1)),
        );
        let expected = searcher
            .find(&saturated)
            .map(|matched| (matched.start(), matched.end()));
        assert_eq!(
            saturated_plan
                .find(&saturated, PackedLiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            expected,
        );
    }

    #[test]
    fn long_fragment_prefix_boundary_and_interior_offset_match_native() {
        let patterns = [
            b"a_sharedfrag0".as_slice(),
            b"b_sharedfrag11".as_slice(),
            b"c_sharedfrag222".as_slice(),
            b"d_sharedfrag3333".as_slice(),
        ];
        let Some(plan) = plan(&patterns) else {
            return;
        };
        let PackedLiteralEngine::NativeSharedFragment {
            searcher,
            shared_fragment,
        } = &plan.engine
        else {
            panic!("interior long fragment did not select its sidecar")
        };
        assert_eq!(shared_fragment.offset, 1);
        assert!(shared_fragment.width >= LONG_SHARED_FRAGMENT_RECEIPT_MIN_BYTES);
        assert!(plan.long_shared_fragment_build_receipt().is_some());

        let boundary = shared_fragment.native_prefix_bytes;
        for length in [boundary - 1, boundary, boundary + 1] {
            let mut haystack = vec![b'.'; length];
            if length >= patterns[0].len() {
                let start = length - patterns[0].len();
                haystack[start..].copy_from_slice(patterns[0]);
            }
            let expected = searcher
                .find(&haystack)
                .map(|matched| (matched.start(), matched.end()));
            assert_eq!(
                plan.find(&haystack, PackedLiteralSetSearchLimits::unlimited())
                    .unwrap()
                    .0,
                expected,
                "native-prefix boundary length {length}",
            );
        }
    }

    #[test]
    fn long_fragment_receipt_equals_runtime_dispatch() {
        let selected = [
            b"longpref0".as_slice(),
            b"longpref11".as_slice(),
            b"longpref222".as_slice(),
            b"longpref3333".as_slice(),
        ];
        let rare_anchor = [
            b"longpref\x1ctail".as_slice(),
            b"longpref\x1dtail".as_slice(),
            b"longpref\x1etail".as_slice(),
        ];
        for patterns in [selected.as_slice(), rare_anchor.as_slice()] {
            let Some(plan) = plan(patterns) else {
                return;
            };
            let dispatched = matches!(
                &plan.engine,
                PackedLiteralEngine::NativeSharedFragment {
                    shared_fragment,
                    ..
                } if shared_fragment.width >= LONG_SHARED_FRAGMENT_RECEIPT_MIN_BYTES
            );
            assert_eq!(plan.long_shared_fragment_build_receipt().is_some(), dispatched);
            assert_native_anchor_matches_unfiltered(&plan, b"..longprefx..longpref3333..");
        }
    }

    #[test]
    fn shared_columns_intersect_correlated_fixed_words_exactly() {
        let patterns = [
            [0x91, 0x00, 0x10, 0xf0],
            [0x91, 0x01, 0x21, 0xe1],
            [0x91, 0x02, 0x32, 0xd2],
            [0x91, 0x03, 0x43, 0xc3],
            [0x91, 0x04, 0x54, 0xb4],
            [0x91, 0x05, 0x65, 0xa5],
            [0x91, 0x06, 0x76, 0x96],
            [0x91, 0x07, 0x87, 0x87],
        ];
        let refs = patterns
            .iter()
            .map(|pattern| pattern.as_slice())
            .collect::<Vec<_>>();
        assert!(select_sparse_anchor(&refs).is_none());
        let columns = select_shared_columns(&refs, 7).unwrap();
        assert_eq!((columns.width, columns.anchor_offset), (4, 0));
        assert_eq!(columns.anchor_byte, 0x91);
        assert_eq!(columns.maximum_candidate_verification_work, 4);
        assert_eq!(columns.minimum_candidate_skip, 28);
        assert_eq!(columns.columns.len(), 3);
        assert_eq!(columns.native_haystack_bytes, 115);
        for pattern in &patterns {
            assert_eq!(columns.verify_at(pattern, 0), Some(4));
        }
        // Every byte occurs in its marginal column, but no one source word
        // contains this cross-pattern tuple. Independent byte classes would
        // accept it; correlated source masks must reject it.
        let mixed_tuple = [0x91, patterns[0][1], patterns[1][2], patterns[2][3]];
        assert_eq!(columns.verify_at(&mixed_tuple, 0), None);
    }

    #[test]
    fn native_shared_columns_preserve_bounds_and_use_one_fallback() {
        let patterns = [
            b"qbma".as_slice(),
            b"qbdb".as_slice(),
            b"qbuc".as_slice(),
            b"qbld".as_slice(),
            b"qbce".as_slice(),
            b"qbtf".as_slice(),
            b"qbkg".as_slice(),
            b"qbbh".as_slice(),
        ];
        let Some(plan) = plan(&patterns) else {
            return;
        };
        let PackedLiteralEngine::NativeSharedColumns {
            searcher,
            shared_columns,
        } = &plan.engine
        else {
            panic!("fixed shared-prefix language did not retain correlated columns")
        };
        assert_eq!((shared_columns.width, shared_columns.anchor_offset), (4, 0));
        assert_eq!(shared_columns.anchor_byte, b'q');
        assert_eq!(shared_columns.maximum_candidate_verification_work, 4);
        let minimum_candidate_skip = shared_columns
            .maximum_candidate_verification_work
            .checked_mul(searcher.minimum_len())
            .unwrap();
        assert_eq!(shared_columns.minimum_candidate_skip, minimum_candidate_skip);
        assert_eq!(
            shared_columns.native_haystack_bytes,
            shared_fragment_native_start_budget(searcher.minimum_len(), 4)
                .checked_add(3)
                .unwrap()
        );

        let persistent = plan.build_accounting().persistent_bytes;
        let exact_sidecar_bytes = core::mem::size_of::<super::SharedColumns>()
            .checked_add(
                shared_columns
                    .columns
                    .len()
                    .checked_mul(core::mem::size_of::<super::SharedColumnMask>())
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(
            persistent,
            searcher
                .memory_usage()
                .checked_add(exact_sidecar_bytes)
                .unwrap()
        );
        assert_eq!(
            PackedLiteralSetPlan::new(
                &patterns,
                PackedLiteralSetBuildLimits {
                    max_persistent_bytes: persistent,
                    ..PackedLiteralSetBuildLimits::default()
                },
            )
            .unwrap()
            .build_accounting()
            .persistent_bytes,
            persistent
        );
        assert!(matches!(
            PackedLiteralSetPlan::new(
                &patterns,
                PackedLiteralSetBuildLimits {
                    max_persistent_bytes: persistent - 1,
                    ..PackedLiteralSetBuildLimits::default()
                },
            ),
            Err(PackedLiteralSetError::PersistentBytesLimit { needed, limit })
                if needed == persistent && limit == persistent - 1
        ));

        let native_haystack_bytes = shared_columns.native_haystack_bytes;

        // Admission is local rather than cumulative. Every adjacent candidate
        // gap must independently buy both one native service quantum and the
        // complete bounded side-filter envelope. One byte below that exact
        // boundary rejects continuation.
        let minimum_continuation_skip = minimum_candidate_skip
            .checked_mul(NATIVE_FILTER_CANDIDATE_BUDGET)
            .unwrap();
        assert_eq!(
            shared_columns.minimum_continuation_skip(),
            Some(minimum_continuation_skip)
        );
        assert_eq!(
            shared_columns.continuation_is_amortized(
                17,
                17_usize
                    .checked_add(minimum_continuation_skip)
                    .unwrap()
                    .checked_sub(1)
                    .unwrap(),
            ),
            Some(false)
        );
        assert_eq!(
            shared_columns.continuation_is_amortized(
                17,
                17_usize
                    .checked_add(minimum_continuation_skip)
                    .unwrap(),
            ),
            Some(true)
        );

        // An early exact candidate remains observable without paying the
        // continuation look-ahead.
        let early_start = 17_usize;
        let early_end = early_start.checked_add(4).unwrap();
        let mut early = vec![b'!'; native_haystack_bytes.checked_add(29).unwrap()];
        early[early_start..early_end].copy_from_slice(b"qbuc");
        assert_eq!(
            plan.find(&early, PackedLiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            Some((early_start, early_end))
        );

        // No common byte is an exact negative proof; no native fallback is
        // needed after the monotone anchor scan exhausts the source.
        let absent = vec![b'!'; native_haystack_bytes.checked_add(29).unwrap()];
        assert_eq!(
            shared_columns.find_amortized(&absent),
            super::SharedColumnsFilterResult::Exhausted,
        );
        assert_eq!(
            plan.find(&absent, PackedLiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            None
        );

        // A window is its own immutable haystack for the side filter. A match
        // before it must not influence either candidate positions or offsets.
        let window_start = 19_usize;
        let decoy_start = window_start.checked_add(37).unwrap();
        let match_start = window_start
            .checked_add(native_haystack_bytes)
            .unwrap()
            .checked_add(29)
            .unwrap();
        let match_end = match_start.checked_add(4).unwrap();
        let mut haystack = vec![b'!'; match_end.checked_add(29).unwrap()];
        haystack[..4].copy_from_slice(b"qbma");
        haystack[decoy_start..decoy_start.checked_add(4).unwrap()].copy_from_slice(b"qbzz");
        haystack[match_start..match_end].copy_from_slice(b"qbce");
        let window = Window::new(window_start, haystack.len());
        let (matched, accounting) = plan
            .find_window(
                &haystack,
                window,
                PackedLiteralSetSearchLimits::unlimited(),
            )
            .unwrap();
        assert_eq!(matched, Some((match_start, match_end)));
        let searched_bytes = haystack.len().checked_sub(window_start).unwrap();
        let verification_bytes_per_position = patterns
            .iter()
            .map(|pattern| pattern.len().checked_add(1).unwrap())
            .sum::<usize>();
        let exact_work = searched_bytes
            .checked_add(1)
            .unwrap()
            .checked_mul(verification_bytes_per_position)
            .unwrap();
        assert_eq!(
            accounting,
            PackedLiteralSetAccounting {
                searched_bytes,
                positions_upper_bound: searched_bytes.checked_add(1).unwrap(),
                verification_bytes_per_position,
                work_upper_bound: exact_work,
                scratch_bytes: 0,
                factored_columns: false,
                simd_eligible_length: true,
            }
        );
        assert_eq!(
            plan.find_window(
                &haystack,
                window,
                PackedLiteralSetSearchLimits {
                    max_work: exact_work,
                },
            )
            .unwrap()
            .0,
            Some((match_start, match_end))
        );
        assert!(matches!(
            plan.find_window(
                &haystack,
                window,
                PackedLiteralSetSearchLimits {
                    max_work: exact_work - 1,
                },
            ),
            Err(PackedLiteralSetError::WorkLimit { needed, limit })
                if needed == exact_work && limit == exact_work - 1
        ));
        assert_eq!(
            plan.find_window(
                &haystack,
                Window::new(window_start, match_end.checked_sub(1).unwrap()),
                PackedLiteralSetSearchLimits::unlimited(),
            )
            .unwrap()
            .0,
            None
        );

        // An adjacent common byte cannot amortize continuation. The first
        // candidate was exactly rejected, so the single native fallback starts
        // at the exact next unverified candidate.
        let dense_match = native_haystack_bytes.checked_add(73).unwrap();
        let dense_end = dense_match.checked_add(4).unwrap();
        let mut dense = vec![b'q'; dense_end.checked_add(16).unwrap()];
        dense[dense_match..dense_end].copy_from_slice(b"qbbh");
        assert_eq!(
            shared_columns.find_amortized(&dense),
            super::SharedColumnsFilterResult::ResumeAt(1),
        );
        let expected = searcher
            .find(&dense)
            .map(|matched| (matched.start(), matched.end()));
        assert_eq!(expected, Some((dense_match, dense_end)));
        assert_eq!(
            plan.find(&dense, PackedLiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            expected
        );

        // A large earlier gap cannot subsidize a later dense cluster. The
        // native fallback resumes at the exact first candidate not covered by
        // an independently paid rejection, rather than rescanning the proved
        // sparse prefix.
        let first_sparse = 0_usize;
        let second_sparse = minimum_continuation_skip.checked_mul(2).unwrap();
        let dense_after_credit = second_sparse.checked_add(1).unwrap();
        let mut clustered = vec![b'!'; dense_after_credit.checked_add(37).unwrap()];
        for start in [first_sparse, second_sparse, dense_after_credit] {
            clustered[start..start.checked_add(4).unwrap()].copy_from_slice(b"qbzz");
        }
        assert_eq!(
            shared_columns.find_amortized(&clustered),
            super::SharedColumnsFilterResult::ResumeAt(dense_after_credit),
        );

        // Sparse candidates keep paying the exact-column continuation gate.
        // More than the generic four-candidate side-filter budget remains on
        // this one monotone common-byte stream; no unconditional native
        // rescan is introduced before the later exact match.
        const SPARSE_DECOYS: usize = 12;
        let sparse_decoys = core::array::from_fn::<_, SPARSE_DECOYS, _>(
            |attempt| {
                minimum_continuation_skip
                    .checked_mul(attempt.checked_add(1).unwrap())
                    .unwrap()
                    .checked_sub(1)
                    .unwrap()
            },
        );
        let sparse_match = minimum_continuation_skip
            .checked_mul(SPARSE_DECOYS.checked_add(1).unwrap())
            .unwrap()
            .checked_sub(1)
            .unwrap();
        let sparse_end = sparse_match.checked_add(4).unwrap();
        let mut sparse = vec![b'!'; sparse_end.checked_add(23).unwrap()];
        for start in sparse_decoys {
            sparse[start..start.checked_add(4).unwrap()].copy_from_slice(b"qbzz");
        }
        sparse[sparse_match..sparse_end].copy_from_slice(b"qbkg");
        assert_eq!(
            shared_columns.find_amortized(&sparse),
            super::SharedColumnsFilterResult::Match {
                start: sparse_match,
                end: sparse_end,
            }
        );
        assert_eq!(
            plan.find(&sparse, PackedLiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            Some((sparse_match, sparse_end))
        );
    }

    #[test]
    fn native_shared_fragment_cost_and_persistence_are_bounded() {
        let patterns = shared_prefix_patterns();
        let Some(plan) = plan(&patterns) else {
            return;
        };
        let PackedLiteralEngine::NativeSharedFragment {
            searcher,
            shared_fragment: fragment,
        } = &plan.engine
        else {
            panic!("shared-prefix language did not retain its common fragment")
        };
        assert_eq!((fragment.offset, fragment.width), (0, 2));
        let native_start_budget = fragment.native_start_budget;
        let expected_quanta = fragment
            .maximum_candidate_verification_work
            .checked_mul(NATIVE_FILTER_CANDIDATE_BUDGET)
            .unwrap();
        assert_eq!(
            native_start_budget,
            shared_fragment_native_start_budget(
                searcher.minimum_len(),
                fragment.maximum_candidate_verification_work,
            )
        );
        assert_eq!(
            native_start_budget,
            searcher.minimum_len().checked_mul(expected_quanta).unwrap()
        );
        assert_eq!(
            fragment.native_prefix_bytes,
            native_start_budget
                .checked_add(
                    patterns
                        .iter()
                        .map(|pattern| pattern.len())
                        .max()
                        .unwrap()
                        .checked_sub(1)
                        .unwrap(),
                )
                .unwrap()
        );
        let persistent = plan.build_accounting().persistent_bytes;
        assert_eq!(
            PackedLiteralSetPlan::new(
                &patterns,
                PackedLiteralSetBuildLimits {
                    max_persistent_bytes: persistent,
                    ..PackedLiteralSetBuildLimits::default()
                },
            )
            .unwrap()
            .build_accounting()
            .persistent_bytes,
            persistent
        );
        assert!(matches!(
            PackedLiteralSetPlan::new(
                &patterns,
                PackedLiteralSetBuildLimits {
                    max_persistent_bytes: persistent - 1,
                    ..PackedLiteralSetBuildLimits::default()
                },
            ),
            Err(PackedLiteralSetError::PersistentBytesLimit { needed, limit })
                if needed == persistent && limit == persistent - 1
        ));
    }

    #[test]
    fn native_shared_fragment_preserves_priority_windows_and_dense_fallback() {
        let patterns = shared_prefix_patterns();
        let Some(plan) = plan(&patterns) else {
            return;
        };
        let PackedLiteralEngine::NativeSharedFragment {
            shared_fragment,
            ..
        } = &plan.engine
        else {
            panic!("shared-prefix language did not retain its common fragment")
        };
        let native_start_budget = shared_fragment.native_start_budget;
        let decoy_start = native_start_budget.checked_add(128).unwrap();
        let decoy_end = decoy_start.checked_add(12).unwrap();
        let match_start = native_start_budget.checked_add(300).unwrap();
        let match_end = match_start.checked_add(4).unwrap();
        let haystack_len = match_end.checked_add(60).unwrap();
        let mut haystack = vec![b'.'; haystack_len];
        // The native prefix first proves all earlier starts. The distant run
        // then supplies overlapping fragment occurrences; four are verified
        // before the packed fallback resumes beyond starts already disproved.
        haystack[decoy_start..decoy_end].fill(b'a');
        haystack[match_start..match_end].copy_from_slice(b"aa77");
        assert_native_anchor_matches_unfiltered(&plan, b"aazz....aa77");
        assert_eq!(
            plan.find(&haystack, PackedLiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            Some((match_start, match_end))
        );
        assert_search_certificate(
            &plan,
            false,
            &haystack,
            Window::full(&haystack),
            Some((match_start, match_end)),
        );
        assert_eq!(
            plan.find_window(
                &haystack,
                Window::new(41, match_end),
                PackedLiteralSetSearchLimits::unlimited(),
            )
            .unwrap()
            .0,
            Some((match_start, match_end))
        );
        assert_eq!(
            plan.find_window(
                &haystack,
                Window::new(41, match_end.checked_sub(1).unwrap()),
                PackedLiteralSetSearchLimits::unlimited(),
            )
            .unwrap()
            .0,
            None
        );

        haystack.fill(b'.');
        haystack[7..11].copy_from_slice(b"aa22");
        assert_native_anchor_matches_unfiltered(&plan, &haystack[..48]);
        assert_eq!(
            plan.find(&haystack, PackedLiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            Some((7, 11))
        );
    }

    #[test]
    fn native_shared_fragment_prefix_boundary_has_exact_right_overlap() {
        let patterns = shared_prefix_patterns();
        let Some(plan) = plan(&patterns) else {
            return;
        };
        let PackedLiteralEngine::NativeSharedFragment {
            searcher,
            shared_fragment,
        } = &plan.engine
        else {
            panic!("shared-prefix language did not retain its common fragment")
        };
        let native_start_budget = shared_fragment.native_start_budget;
        let short_match_start = native_start_budget.checked_sub(4).unwrap();
        let mut short_haystack = vec![b'.'; native_start_budget];
        short_haystack[short_match_start..native_start_budget].copy_from_slice(b"aa11");
        assert_eq!(
            plan.find(
                &short_haystack,
                PackedLiteralSetSearchLimits::unlimited(),
            )
            .unwrap()
            .0,
            Some((short_match_start, native_start_budget))
        );

        let haystack_len = native_start_budget.checked_add(64).unwrap();
        for match_start in [
            native_start_budget.checked_sub(1).unwrap(),
            native_start_budget,
            native_start_budget.checked_add(1).unwrap(),
        ] {
            let mut haystack = vec![b'.'; haystack_len];
            let match_end = match_start.checked_add(4).unwrap();
            haystack[match_start..match_end].copy_from_slice(b"aa22");
            let expected = searcher
                .find(&haystack)
                .map(|matched| (matched.start(), matched.end()));
            assert_eq!(expected, Some((match_start, match_end)));
            assert_eq!(
                plan.find(&haystack, PackedLiteralSetSearchLimits::unlimited())
                    .unwrap()
                    .0,
                expected
            );
        }
        let miss = vec![b'.'; haystack_len];
        assert_eq!(
            plan.find(&miss, PackedLiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            None
        );

        let window_start = 17_usize;
        let match_start = window_start
            .checked_add(native_start_budget)
            .and_then(|start| start.checked_sub(1))
            .unwrap();
        let match_end = match_start.checked_add(4).unwrap();
        let mut windowed = vec![b'.'; window_start.checked_add(haystack_len).unwrap()];
        windowed[match_start..match_end].copy_from_slice(b"aa44");
        assert_eq!(
            plan.find_window(
                &windowed,
                Window::new(window_start, windowed.len()),
                PackedLiteralSetSearchLimits::unlimited(),
            )
            .unwrap()
            .0,
            Some((match_start, match_end))
        );
        assert_eq!(
            plan.find_window(
                &windowed,
                Window::new(window_start, match_end.checked_sub(1).unwrap()),
                PackedLiteralSetSearchLimits::unlimited(),
            )
            .unwrap()
            .0,
            None
        );
    }

    #[test]
    fn shared_fragment_verification_keeps_source_order() {
        let long_first_patterns = [
            b"xy00".as_slice(),
            b"xy".as_slice(),
            b"xy11".as_slice(),
            b"xy22".as_slice(),
            b"xy33".as_slice(),
            b"xy44".as_slice(),
            b"xy55".as_slice(),
            b"xy66".as_slice(),
        ];
        let Some(long_first) = plan(&long_first_patterns) else {
            return;
        };
        let PackedLiteralEngine::NativeSharedFragment {
            shared_fragment,
            ..
        } = &long_first.engine
        else {
            panic!("shared-prefix language did not retain its common fragment")
        };
        let native_start_budget = shared_fragment.native_start_budget;
        let native_prefix_bytes = shared_fragment.native_prefix_bytes;
        let overlap_match_start = native_start_budget;
        let overlap_match_end = overlap_match_start.checked_add(4).unwrap();
        let mut overlap_haystack = vec![b'.'; native_prefix_bytes.checked_add(48).unwrap()];
        overlap_haystack[overlap_match_start..overlap_match_end].copy_from_slice(b"xy00");
        assert_eq!(
            long_first
                .find(
                    &overlap_haystack,
                    PackedLiteralSetSearchLimits::unlimited(),
                )
                .unwrap()
                .0,
            Some((overlap_match_start, overlap_match_end))
        );
        let match_start = native_start_budget.checked_add(48).unwrap();
        let match_end = match_start.checked_add(4).unwrap();
        let mut priority_haystack = vec![b'.'; match_end.checked_add(48).unwrap()];
        priority_haystack[match_start..match_end].copy_from_slice(b"xy00");
        assert_eq!(
            long_first
                .find(
                    &priority_haystack,
                    PackedLiteralSetSearchLimits::unlimited(),
                )
                .unwrap()
                .0,
            Some((match_start, match_end))
        );
        let short_first_patterns = [
            b"xy".as_slice(),
            b"xy00".as_slice(),
            b"xy11".as_slice(),
            b"xy22".as_slice(),
            b"xy33".as_slice(),
            b"xy44".as_slice(),
            b"xy55".as_slice(),
            b"xy66".as_slice(),
        ];
        let Some(short_first) = plan(&short_first_patterns) else {
            return;
        };
        let PackedLiteralEngine::NativeSharedFragment {
            shared_fragment,
            ..
        } = &short_first.engine
        else {
            panic!("reordered shared-prefix language lost its common fragment")
        };
        assert_eq!(
            shared_fragment.native_start_budget,
            native_start_budget
        );
        assert_eq!(shared_fragment.native_prefix_bytes, native_prefix_bytes);
        assert_eq!(
            short_first
                .find(
                    &priority_haystack,
                    PackedLiteralSetSearchLimits::unlimited(),
                )
                .unwrap()
                .0,
            Some((match_start, match_start.checked_add(2).unwrap()))
        );
    }

    #[test]
    fn shared_fragment_verification_handles_interior_offsets() {
        let interior_patterns = [
            b"aQR00".as_slice(),
            b"bQR1".as_slice(),
            b"cQR2".as_slice(),
            b"dQR3".as_slice(),
            b"eQR4".as_slice(),
            b"fQR5".as_slice(),
            b"gQR6".as_slice(),
            b"hQR7".as_slice(),
        ];
        let Some(interior) = plan(&interior_patterns) else {
            return;
        };
        let PackedLiteralEngine::NativeSharedFragment {
            shared_fragment,
            ..
        } = &interior.engine
        else {
            panic!("shared-interior language did not retain its common fragment")
        };
        let interior_budget = shared_fragment.native_start_budget;
        let decoy_start = interior_budget.checked_add(32).unwrap();
        let decoy_end = decoy_start.checked_add(4).unwrap();
        let match_start = interior_budget.checked_add(72).unwrap();
        let match_end = match_start.checked_add(4).unwrap();
        let mut interior_haystack = vec![b'.'; match_end.checked_add(48).unwrap()];
        interior_haystack[decoy_start..decoy_end].copy_from_slice(b"aQRx");
        interior_haystack[match_start..match_end].copy_from_slice(b"bQR1");
        assert_eq!(
            interior
                .find(
                    &interior_haystack,
                    PackedLiteralSetSearchLimits::unlimited(),
                )
                .unwrap()
                .0,
            Some((match_start, match_end))
        );
    }

    #[test]
    fn leftmost_first_and_window_offsets_match_the_contract() {
        let Some(short_first) = plan(&[b"a", b"ab"]) else {
            return;
        };
        assert_eq!(
            short_first
                .find_window(
                    b"zzabxx",
                    Window::new(2, 6),
                    PackedLiteralSetSearchLimits::unlimited(),
                )
                .unwrap()
                .0,
            Some((2, 3))
        );
        let Some(long_first) = plan(&[b"ab", b"a"]) else {
            return;
        };
        assert_eq!(
            long_first
                .find(b"zzab", PackedLiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            Some((2, 4))
        );

        let mut long_haystack = vec![b'.'; 160];
        long_haystack[64] = b'a';
        long_haystack[65] = b'b';
        assert_eq!(
            short_first
                .find(&long_haystack, PackedLiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            Some((64, 65))
        );
        assert_eq!(
            long_first
                .find(&long_haystack, PackedLiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            Some((64, 66))
        );
        assert_native_anchor_matches_unfiltered(&short_first, &long_haystack);
        assert_native_anchor_matches_unfiltered(&long_first, &long_haystack);
    }

    #[test]
    #[cfg(not(feature = "static-dispatch"))]
    fn uniform_word64_admission_accounting_and_incumbent_fallback_are_explicit() {
        let common = [b"agggtaaa".as_slice(), b"tttaccct".as_slice()];
        let uniform = PackedLiteralSetPlan::new(&common, PackedLiteralSetBuildLimits::default())
            .expect("common equal-width language");
        assert!(matches!(
            uniform.engine,
            PackedLiteralEngine::UniformWord64(_)
        ));
        assert_eq!(
            uniform.runtime_implementation_id(),
            UNIFORM_WORD64_RUNTIME_IMPLEMENTATION_ID
        );
        let build = uniform.build_accounting();
        assert_eq!(build.persistent_bytes, UNIFORM_WORD64_MASK_BYTES);
        assert_eq!(
            build.build_work_upper_bound,
            packed_literal_set_build_work_upper_bound_from_dimensions(
                build.patterns,
                build.pattern_bytes,
            )
            .unwrap()
        );
        assert!(uniform.search_cursor(b"").is_none());
        assert_eq!(build.simd_minimum_haystack_bytes, 0);
        let haystack = b"xxagggtaaayytttaccct";
        let (matched, accounting) = uniform
            .find(haystack, PackedLiteralSetSearchLimits::unlimited())
            .unwrap();
        assert_eq!(matched, Some((2, 10)));
        assert!(!accounting.factored_columns);
        assert!(!accounting.simd_eligible_length);
        assert_eq!(
            accounting.work_upper_bound,
            (haystack.len() + 1) * (build.pattern_bytes + build.patterns)
        );

        let exact_cap = PackedLiteralSetPlan::new(
            &common,
            PackedLiteralSetBuildLimits {
                max_persistent_bytes: UNIFORM_WORD64_MASK_BYTES,
                ..PackedLiteralSetBuildLimits::default()
            },
        )
        .unwrap();
        assert_eq!(
            exact_cap.runtime_implementation_id(),
            UNIFORM_WORD64_RUNTIME_IMPLEMENTATION_ID
        );
        assert!(exact_cap.search_cursor(b"").is_none());

        let retained = PackedLiteralSetPlan::new_retained_iter(
            &common,
            PackedLiteralSetBuildLimits::default(),
            usize::MAX,
        )
        .unwrap();
        let retained_build = retained.build_accounting();
        assert_eq!(
            retained_build.build_work_upper_bound,
            build.build_work_upper_bound.checked_mul(2).unwrap()
        );
        assert!(retained_build.build_bytes_upper_bound > build.build_bytes_upper_bound);
        assert!(retained_build.persistent_bytes > build.persistent_bytes);
        assert_eq!(
            retained.retained_iter_build_capability_id(),
            Some(RETAINED_ITER_BUILD_CAPABILITY_ID)
        );
        assert_eq!(
            retained
                .search_cursor(b"")
                .unwrap()
                .runtime_implementation_id(),
            RETAINED_ITER_RUNTIME_IMPLEMENTATION_ID
        );

        let exact_dual = PackedLiteralSetPlan::new_retained_iter(
            &common,
            PackedLiteralSetBuildLimits {
                max_build_work: retained_build.build_work_upper_bound,
                max_build_bytes: retained_build.build_bytes_upper_bound,
                max_persistent_bytes: retained_build.persistent_bytes,
                ..PackedLiteralSetBuildLimits::default()
            },
            build.build_work_upper_bound,
        )
        .unwrap();
        assert_eq!(exact_dual.build_accounting(), retained_build);
        assert!(exact_dual.search_cursor(b"").is_some());
        for one_below in [
            PackedLiteralSetBuildLimits {
                max_build_work: retained_build
                    .build_work_upper_bound
                    .checked_sub(1)
                    .unwrap(),
                ..PackedLiteralSetBuildLimits::default()
            },
            PackedLiteralSetBuildLimits {
                max_build_bytes: retained_build
                    .build_bytes_upper_bound
                    .checked_sub(1)
                    .unwrap(),
                ..PackedLiteralSetBuildLimits::default()
            },
            PackedLiteralSetBuildLimits {
                max_persistent_bytes: retained_build
                    .persistent_bytes
                    .checked_sub(1)
                    .unwrap(),
                ..PackedLiteralSetBuildLimits::default()
            },
        ] {
            let scalar_only =
                PackedLiteralSetPlan::new_retained_iter(&common, one_below, usize::MAX).unwrap();
            assert_eq!(
                scalar_only.runtime_implementation_id(),
                UNIFORM_WORD64_RUNTIME_IMPLEMENTATION_ID
            );
            assert!(scalar_only.search_cursor(b"").is_none());
        }
        let work_limited = PackedLiteralSetPlan::new_retained_iter(
            &common,
            PackedLiteralSetBuildLimits::default(),
            build.build_work_upper_bound.checked_sub(1).unwrap(),
        )
        .unwrap();
        assert_eq!(work_limited.build_accounting(), build);
        assert!(work_limited.search_cursor(b"").is_none());

        let _retained_failure = retained_iter_owner_allocation_probe::fail_next();
        let allocation_fallback = PackedLiteralSetPlan::new_retained_iter(
            &common,
            PackedLiteralSetBuildLimits::default(),
            usize::MAX,
        )
        .unwrap();
        assert_eq!(allocation_fallback.build_accounting(), build);
        assert_eq!(allocation_fallback.retained_iter_build_capability_id(), None);
        assert!(allocation_fallback.search_cursor(b"").is_none());

        let _failure = uniform_word64_allocation_probe::fail_next();
        let incumbent =
            PackedLiteralSetPlan::new(&common, PackedLiteralSetBuildLimits::default()).unwrap();
        assert_eq!(
            incumbent.runtime_implementation_id(),
            RUNTIME_IMPLEMENTATION_ID
        );
        assert_eq!(
            incumbent
                .find(haystack, PackedLiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            matched
        );
        let incumbent_bytes = incumbent.build_accounting().persistent_bytes;
        assert!(incumbent_bytes < UNIFORM_WORD64_MASK_BYTES);
        let resource_fallback = PackedLiteralSetPlan::new(
            &common,
            PackedLiteralSetBuildLimits {
                max_persistent_bytes: incumbent_bytes,
                ..PackedLiteralSetBuildLimits::default()
            },
        )
        .unwrap();
        assert_eq!(
            resource_fallback.runtime_implementation_id(),
            RUNTIME_IMPLEMENTATION_ID
        );

        for declined in [
            &[b"agggtaa".as_slice(), b"tttaccc".as_slice()][..],
            &[b"agggtaaa".as_slice(), b"tttaccctt".as_slice()][..],
            &[b"\0aaaaaaa".as_slice(), b"\x01bbbbbbb".as_slice()][..],
            &[
                b"aaaaaaaa".as_slice(),
                b"bbbbbbbb".as_slice(),
                b"cccccccc".as_slice(),
                b"defghide".as_slice(),
            ][..],
            &[b"abcdefgh".as_slice(), b"hgfedcba".as_slice()][..],
        ] {
            let plan = PackedLiteralSetPlan::new(declined, PackedLiteralSetBuildLimits::default())
                .expect("incumbent accepts declined uniform shape");
            assert_eq!(plan.runtime_implementation_id(), RUNTIME_IMPLEMENTATION_ID);
        }
        let over = [[b'a'; 33], [b't'; 33]];
        let over_refs = over.iter().map(<[u8; 33]>::as_slice).collect::<Vec<_>>();
        let over_plan =
            PackedLiteralSetPlan::new(&over_refs, PackedLiteralSetBuildLimits::default()).unwrap();
        assert_eq!(
            over_plan.runtime_implementation_id(),
            RUNTIME_IMPLEMENTATION_ID
        );
    }

    #[test]
    fn ordinary_executor_matches_checked_windows_and_skips_work_refusal() {
        let patterns = [
            b"foobar".as_slice(),
            b"foobaz".as_slice(),
            b"fooquux".as_slice(),
        ];
        let Some(plan) = plan(&patterns) else {
            return;
        };
        let ordinary = plan.ordinary_executor();
        let haystack = b"xxfoobaz/foobar/no-match";
        for start in 0..=haystack.len() {
            for end in start..=haystack.len() {
                let window = Window::new(start, end);
                let expected = plan
                    .find_window(
                        haystack,
                        window,
                        PackedLiteralSetSearchLimits::unlimited(),
                    )
                    .unwrap()
                    .0;
                assert_eq!(ordinary.find_window_value(haystack, window), Ok(expected));
                assert_eq!(
                    ordinary.exists_window_value(haystack, window),
                    Ok(expected.is_some()),
                );
                assert_eq!(
                    ordinary.selected_end_window_value(haystack, window),
                    Ok(expected.map(|(_, end)| end)),
                );
            }
        }
        let full = Window::full(haystack);
        assert!(matches!(
            plan.find_window(
                haystack,
                full,
                PackedLiteralSetSearchLimits { max_work: 0 },
            ),
            Err(PackedLiteralSetError::WorkLimit { .. }),
        ));
        assert_eq!(ordinary.find_window_value(haystack, full), Ok(Some((2, 8))));
        for window in [
            Window::new(haystack.len() + 1, haystack.len()),
            Window::new(0, haystack.len() + 1),
        ] {
            assert!(matches!(
                ordinary.find_window_value(haystack, window),
                Err(PackedLiteralSetError::InvalidWindow { .. }),
            ));
            assert!(matches!(
                ordinary.exists_window_value(haystack, window),
                Err(PackedLiteralSetError::InvalidWindow { .. }),
            ));
            assert!(matches!(
                ordinary.selected_end_window_value(haystack, window),
                Err(PackedLiteralSetError::InvalidWindow { .. }),
            ));
        }
    }

    #[test]
    #[cfg(not(feature = "static-dispatch"))]
    fn ordinary_executor_retains_adaptive_iteration_and_checked_count() {
        let patterns = [b"agggtaaa".as_slice(), b"tttaccct".as_slice()];
        let plan = PackedLiteralSetPlan::new_retained_iter(
            &patterns,
            PackedLiteralSetBuildLimits::default(),
            usize::MAX,
        )
        .unwrap();
        assert!(plan.search_cursor(b"").is_some());
        let ordinary = plan.ordinary_executor();
        for match_start in [
            0,
            super::RETAINED_ORDINARY_UNIFORM_PREFIX_STARTS - 1,
            super::RETAINED_ORDINARY_UNIFORM_PREFIX_STARTS,
            40,
        ] {
            let mut probe = vec![0xff; 96];
            probe[match_start..match_start + patterns[0].len()]
                .copy_from_slice(patterns[0]);
            let window = Window::full(&probe);
            let expected = plan
                .find_window(
                    &probe,
                    window,
                    PackedLiteralSetSearchLimits::unlimited(),
                )
                .unwrap()
                .0;
            assert_eq!(ordinary.find_window_value(&probe, window), Ok(expected));
        }
        assert_eq!(
            ordinary.find_window_value(&[0xff; 96], Window::new(0, 96)),
            Ok(None),
        );
        let mut haystack = vec![0xff; 256];
        haystack[0..8].copy_from_slice(patterns[0]);
        haystack[8..16].copy_from_slice(patterns[0]);
        haystack[16..24].copy_from_slice(patterns[1]);
        haystack[80..88].copy_from_slice(patterns[0]);

        let mut expected = Vec::new();
        let mut start = 0_usize;
        while let Some(matched) = plan
            .find_window(
                &haystack,
                Window::new(start, haystack.len()),
                PackedLiteralSetSearchLimits::unlimited(),
            )
            .unwrap()
            .0
        {
            expected.push(matched);
            start = matched.1;
        }
        let mut actual = Vec::new();
        assert_eq!(
            ordinary
                .try_visit_spans_window_value(
                    &haystack,
                    Window::full(&haystack),
                    |matched| {
                        actual.push(matched);
                        Ok::<bool, ()>(true)
                    },
                )
                .unwrap(),
            Ok(()),
        );
        assert_eq!(actual, expected);
        assert_eq!(
            ordinary.count_spans_window_value(&haystack, Window::full(&haystack)),
            Ok(u64::try_from(expected.len()).unwrap()),
        );

        let mut stopped = Vec::new();
        assert_eq!(
            ordinary
                .try_visit_spans_window_value(
                    &haystack,
                    Window::full(&haystack),
                    |matched| {
                        stopped.push(matched);
                        Ok::<bool, &'static str>(false)
                    },
                )
                .unwrap(),
            Ok(()),
        );
        assert_eq!(stopped.len(), 1);
        assert_eq!(
            ordinary
                .try_visit_spans_window_value(
                    &haystack,
                    Window::full(&haystack),
                    |_| Err::<bool, _>("callback"),
                )
                .unwrap(),
            Err("callback"),
        );
    }

    #[test]
    #[cfg(not(feature = "static-dispatch"))]
    fn retained_ordinary_hybrid_matches_every_small_window_across_its_split() {
        let split = super::RETAINED_ORDINARY_UNIFORM_PREFIX_STARTS;
        for (count, width) in [(2, 8), (8, 8), (2, 16), (4, 16), (2, 32)] {
            let owned = (0..count)
                .map(|index| {
                    let mut pattern = vec![b'a'; width];
                    let mut value = index;
                    for offset in 0..3 {
                        pattern[width - offset - 1] = b"acgt"[value & 3];
                        value >>= 2;
                    }
                    pattern
                })
                .collect::<Vec<_>>();
            let patterns = pattern_refs(&owned);
            let plan = PackedLiteralSetPlan::new_retained_iter(
                &patterns,
                PackedLiteralSetBuildLimits::default(),
                usize::MAX,
            )
            .unwrap();
            assert!(
                matches!(
                    plan.engine,
                    PackedLiteralEngine::UniformWord64Retained { .. }
                ),
                "count={count}, width={width}"
            );
            let ordinary = plan.ordinary_executor();
            let mut lengths = vec![
                0,
                width - 1,
                width,
                split - 1,
                split,
                split + 1,
                split + width - 2,
                split + width - 1,
                split + width,
                split + width + 1,
                63,
                64,
                65,
                split + width.checked_mul(2).unwrap() + 1,
            ];
            lengths.sort_unstable();
            lengths.dedup();
            for length in lengths {
                let mut haystacks = vec![vec![0xff; length]];
                for (case, start) in [
                    0,
                    split - 1,
                    split,
                    split + 1,
                    length.saturating_sub(width),
                ]
                .into_iter()
                .enumerate()
                {
                    let Some(end) = start.checked_add(width) else {
                        continue;
                    };
                    if end <= length {
                        let mut haystack = vec![0xff; length];
                        haystack[start..end].copy_from_slice(patterns[case % count]);
                        haystacks.push(haystack);
                    }
                }
                if split + width.checked_mul(2).unwrap() <= length {
                    let mut haystack = vec![0xff; length];
                    let prefix_start = split - 1;
                    let prefix_end = prefix_start + width;
                    haystack[prefix_start..prefix_end].copy_from_slice(patterns[0]);
                    let tail_start = split + width;
                    let tail_end = tail_start + width;
                    haystack[tail_start..tail_end].copy_from_slice(patterns[1]);
                    haystacks.push(haystack);
                }
                for haystack in haystacks {
                    for start in 0..=length {
                        for end in start..=length {
                            let window = Window::new(start, end);
                            let expected = fixed_width_oracle(&patterns, &haystack, window);
                            let actual = ordinary
                                .find_window_value(&haystack, window)
                                .unwrap();
                            assert_eq!(
                                actual, expected,
                                "count={count}, width={width}, length={length}, window={start}..{end}"
                            );
                            assert_eq!(
                                ordinary.exists_window_value(&haystack, window).unwrap(),
                                expected.is_some(),
                            );
                            assert_eq!(
                                ordinary
                                    .selected_end_window_value(&haystack, window)
                                    .unwrap(),
                                expected.map(|(_, selected_end)| selected_end),
                            );
                            assert_eq!(
                                plan.find_window(
                                    &haystack,
                                    window,
                                    PackedLiteralSetSearchLimits::unlimited(),
                                )
                                .unwrap()
                                .0,
                                expected,
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    #[cfg(not(feature = "static-dispatch"))]
    fn retained_iterator_preserves_nonoverlap_malformed_bytes_and_exact_work_refusal() {
        let patterns = [b"agggtaaa".as_slice(), b"tttaccct".as_slice()];
        let plan = PackedLiteralSetPlan::new_retained_iter(
            &patterns,
            PackedLiteralSetBuildLimits::default(),
            usize::MAX,
        )
        .unwrap();
        let mut haystack = vec![0xff; 256];
        haystack[0..8].copy_from_slice(patterns[0]);
        haystack[8..16].copy_from_slice(patterns[0]);
        // This third adjacent match uses the scalar engine after two native
        // observations. Its suffix overlaps the following source bytes, while
        // iterator progress must still expose every complete non-overlap span.
        haystack[16..24].copy_from_slice(patterns[1]);
        haystack[80..88].copy_from_slice(patterns[0]);

        let mut expected = Vec::new();
        let mut start = 0_usize;
        loop {
            let Some(matched) = plan
                .find_window(
                    &haystack,
                    Window::new(start, haystack.len()),
                    PackedLiteralSetSearchLimits::unlimited(),
                )
                .unwrap()
                .0
            else {
                break;
            };
            expected.push(matched);
            start = matched.1;
        }
        assert_eq!(expected, [(0, 8), (8, 16), (16, 24), (80, 88)]);

        let mut cursor = plan.search_cursor(&haystack).unwrap();
        let mut actual = Vec::new();
        let mut start = 0_usize;
        loop {
            let Some(matched) = cursor
                .find_at_value(start, PackedLiteralSetSearchLimits::unlimited())
                .unwrap()
            else {
                break;
            };
            actual.push(matched);
            start = matched.1;
        }
        assert_eq!(actual, expected);

        let work = (haystack.len() + 1)
            .checked_mul(plan.verification_bytes_per_position)
            .unwrap();
        let mut exact = plan.search_cursor(&haystack).unwrap();
        assert_eq!(
            exact
                .find_at(0, PackedLiteralSetSearchLimits { max_work: work })
                .unwrap()
                .0,
            Some((0, 8))
        );
        let mut one_below = plan.search_cursor(&haystack).unwrap();
        assert_eq!(
            one_below.find_at(
                0,
                PackedLiteralSetSearchLimits {
                    max_work: work.checked_sub(1).unwrap(),
                },
            ),
            Err(PackedLiteralSetError::WorkLimit {
                needed: work,
                limit: work.checked_sub(1).unwrap(),
            })
        );
    }

    #[test]
    #[cfg(not(feature = "static-dispatch"))]
    fn retained_iterator_preserves_matches_at_uniform_tail_boundary() {
        let threshold = super::RETAINED_ITER_UNIFORM_MIN_WINDOW_BYTES;
        assert_eq!(threshold, 32);
        for width in [8, threshold] {
            let first = vec![b'a'; width];
            let mut second = first.clone();
            second[width - 1] = b'b';
            let patterns = [first.as_slice(), second.as_slice()];
            let plan = PackedLiteralSetPlan::new_retained_iter(
                &patterns,
                PackedLiteralSetBuildLimits::default(),
                usize::MAX,
            )
            .unwrap();
            for remaining in [threshold - 1, threshold, threshold + 1] {
                let mut haystack = vec![0xff; 160];
                haystack[..width].copy_from_slice(patterns[0]);
                haystack[width..width * 2].copy_from_slice(patterns[0]);
                let tail_start = haystack.len() - remaining;
                if width <= remaining {
                    haystack[tail_start..tail_start + width].copy_from_slice(patterns[1]);
                }
                let expected = plan
                    .find_window(
                        &haystack,
                        Window::new(tail_start, haystack.len()),
                        PackedLiteralSetSearchLimits::unlimited(),
                    )
                    .unwrap()
                    .0;

                let mut unmetered = plan.search_cursor(&haystack).unwrap();
                assert_eq!(unmetered.find_at_value_unmetered(0), Ok(Some((0, width))));
                assert!(!unmetered.dense);
                assert_eq!(
                    unmetered.find_at_value_unmetered(width),
                    Ok(Some((width, width * 2))),
                );
                assert!(unmetered.dense);
                assert_eq!(unmetered.find_at_value_unmetered(tail_start), Ok(expected));

                let mut checked = plan.search_cursor(&haystack).unwrap();
                assert_eq!(
                    checked
                        .find_at(0, PackedLiteralSetSearchLimits::unlimited())
                        .unwrap()
                        .0,
                    Some((0, width)),
                );
                assert!(!checked.dense);
                assert_eq!(
                    checked
                        .find_at(width, PackedLiteralSetSearchLimits::unlimited())
                        .unwrap()
                        .0,
                    Some((width, width * 2)),
                );
                assert!(checked.dense);
                assert_eq!(
                    checked
                        .find_at(tail_start, PackedLiteralSetSearchLimits::unlimited())
                        .unwrap()
                        .0,
                    expected,
                );
            }
        }
    }

    #[test]
    #[cfg(not(feature = "static-dispatch"))]
    fn uniform_word64_matches_the_fixed_width_oracle_in_every_small_binary_window() {
        let motifs = (0_u8..4)
            .map(|bits| {
                let mut word = vec![b'a'; 8];
                word[6] = if bits & 1 == 0 { b'a' } else { b't' };
                word[7] = if bits & 2 == 0 { b'a' } else { b't' };
                word
            })
            .collect::<Vec<_>>();
        for first in &motifs {
            for second in &motifs {
                let patterns = [first.as_slice(), second.as_slice()];
                let plan = PackedLiteralSetPlan::new(
                    &patterns,
                    PackedLiteralSetBuildLimits::default(),
                )
                .unwrap();
                assert_eq!(
                    plan.runtime_implementation_id(),
                    UNIFORM_WORD64_RUNTIME_IMPLEMENTATION_ID
                );
                for length in 0_usize..=10 {
                    for bits in 0_usize..(1_usize << length) {
                        let haystack = (0..length)
                            .map(|position| {
                                if bits & (1_usize << position) == 0 {
                                    b'a'
                                } else {
                                    b't'
                                }
                            })
                            .collect::<Vec<_>>();
                        for start in 0..=length {
                            for end in start..=length {
                                let window = Window::new(start, end);
                                let expected = fixed_width_oracle(&patterns, &haystack, window);
                                let actual = plan
                                    .find_window(
                                        &haystack,
                                        window,
                                        PackedLiteralSetSearchLimits::unlimited(),
                                    )
                                    .unwrap()
                                    .0;
                                assert_eq!(
                                    actual, expected,
                                    "patterns={patterns:?}, haystack={haystack:?}, window={start}..{end}"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    #[cfg(feature = "static-dispatch")]
    fn static_dispatch_keeps_the_incumbent_packed_runtime() {
        let patterns = [b"agggtaaa".as_slice(), b"tttaccct".as_slice()];
        let plan = PackedLiteralSetPlan::new(&patterns, PackedLiteralSetBuildLimits::default())
            .expect("static incumbent packed searcher");
        assert_eq!(plan.runtime_implementation_id(), RUNTIME_IMPLEMENTATION_ID);
        assert_eq!(
            plan.find(
                b"xxagggtaaayytttaccct",
                PackedLiteralSetSearchLimits::unlimited()
            )
            .unwrap()
            .0,
            Some((2, 10))
        );
    }

    #[test]
    fn unsupported_shapes_and_work_caps_are_explicit() {
        assert!(matches!(
            PackedLiteralSetPlan::new::<&[u8]>(&[], PackedLiteralSetBuildLimits::default()),
            Err(PackedLiteralSetError::EmptyPatternSet)
        ));
        assert!(matches!(
            PackedLiteralSetPlan::new(
                &[b"a".as_slice(), b"".as_slice()],
                PackedLiteralSetBuildLimits::default()
            ),
            Err(PackedLiteralSetError::EmptyPattern { index: 1 })
        ));
        let Some(plan) = plan(&[b"foobar", b"foobaz", b"fooquux"]) else {
            return;
        };
        let (_, exact) = plan
            .find(
                b"foo-no-match/foobaz",
                PackedLiteralSetSearchLimits::unlimited(),
            )
            .unwrap();
        assert_eq!(
            plan.find(
                b"foo-no-match/foobaz",
                PackedLiteralSetSearchLimits {
                    max_work: exact.work_upper_bound - 1,
                }
            ),
            Err(PackedLiteralSetError::WorkLimit {
                needed: exact.work_upper_bound,
                limit: exact.work_upper_bound - 1,
            })
        );
    }

    #[test]
    fn selected_languages_match_rebar_aligned_rust_regex() {
        let languages: &[&[&[u8]]] = &[
            &[b"a", b"ab"],
            &[b"ab", b"a"],
            &[b"foobar", b"foobaz", b"fooquux"],
            &[b"bc", b"a", b"abc"],
        ];
        let haystacks: &[&[u8]] = &[
            b"",
            b"a",
            b"ab",
            b"zzab",
            b"foo-no-match/foobaz",
            b"ccccabc",
        ];
        for patterns in languages {
            let Some(plan) = plan(patterns) else {
                return;
            };
            let source = patterns
                .iter()
                .map(|pattern| regex::escape(core::str::from_utf8(pattern).unwrap()))
                .collect::<Vec<_>>()
                .join("|");
            let oracle = regex::bytes::RegexBuilder::new(&source)
                .unicode(false)
                .build()
                .unwrap();
            for haystack in haystacks {
                let expected = oracle
                    .find(haystack)
                    .map(|matched| (matched.start(), matched.end()));
                let actual = plan
                    .find(haystack, PackedLiteralSetSearchLimits::unlimited())
                    .unwrap()
                    .0;
                assert_eq!(actual, expected, "source={source:?}, haystack={haystack:?}");
            }
        }
    }

    #[test]
    fn cardinality_above_teddy_requires_a_complete_factored_language() {
        let patterns_64 = fixed_patterns(64, 4);
        let refs_64 = pattern_refs(&patterns_64);
        let Some(single) = plan(&refs_64) else {
            return;
        };
        assert_eq!(single.build_accounting().patterns, 64);
        let PackedLiteralEngine::NativeSharedColumns {
            shared_columns,
            ..
        } = &single.engine
        else {
            panic!("the native 64-pattern boundary lost its exact shared-column factor")
        };
        assert_eq!(shared_columns.pattern_mask, u64::MAX);
        assert_eq!(shared_columns.width, 4);
        assert!(refs_64.iter().all(|pattern| {
            pattern[shared_columns.anchor_offset] == shared_columns.anchor_byte
        }));
        let match_start = shared_columns
            .native_haystack_bytes
            .checked_add(31)
            .unwrap();
        let match_end = match_start.checked_add(4).unwrap();
        let mut haystack = vec![b'!'; match_end.checked_add(17).unwrap()];
        haystack[match_start..match_end].copy_from_slice(&patterns_64[63]);
        assert_eq!(
            single
                .find(&haystack, PackedLiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            Some((match_start, match_end))
        );
        let persistent = single.build_accounting().persistent_bytes;
        assert_eq!(
            PackedLiteralSetPlan::new(
                &refs_64,
                PackedLiteralSetBuildLimits {
                    max_persistent_bytes: persistent,
                    ..PackedLiteralSetBuildLimits::default()
                },
            )
            .unwrap()
            .build_accounting()
            .persistent_bytes,
            persistent
        );
        assert!(matches!(
            PackedLiteralSetPlan::new(
                &refs_64,
                PackedLiteralSetBuildLimits {
                    max_persistent_bytes: persistent - 1,
                    ..PackedLiteralSetBuildLimits::default()
                },
            ),
            Err(PackedLiteralSetError::PersistentBytesLimit { needed, limit })
                if needed == persistent && limit == persistent - 1
        ));

        for count in [65, 72, 128] {
            let patterns = fixed_patterns(count, 4);
            let refs = pattern_refs(&patterns);
            assert!(matches!(
                PackedLiteralSetPlan::new(&refs, PackedLiteralSetBuildLimits::default()),
                Err(PackedLiteralSetError::UnsupportedTargetOrShape)
            ));
        }
        for (rows, columns) in [(5, 13), (6, 12), (8, 16)] {
            let patterns = cartesian_grid(rows, columns);
            let refs = pattern_refs(&patterns);
            let factored =
                PackedLiteralSetPlan::new(&refs, PackedLiteralSetBuildLimits::default()).unwrap();
            assert!(matches!(&factored.engine, PackedLiteralEngine::Factored(_)));
        }

        let short_patterns = fixed_patterns(65, 3);
        let short_refs = pattern_refs(&short_patterns);
        assert!(matches!(
            PackedLiteralSetPlan::new(&short_refs, PackedLiteralSetBuildLimits::default()),
            Err(PackedLiteralSetError::UnsupportedTargetOrShape)
        ));

        let patterns_129 = fixed_patterns(129, 4);
        let refs_129 = pattern_refs(&patterns_129);
        assert!(matches!(
            PackedLiteralSetPlan::new(&refs_129, PackedLiteralSetBuildLimits::default()),
            Err(PackedLiteralSetError::PatternLimit {
                needed: 129,
                limit: 128
            })
        ));
    }

    #[test]
    fn complete_cartesian_columns_use_one_anchored_scan_and_reject_missing_tuples() {
        let patterns = cartesian_patterns();
        let refs = pattern_refs(&patterns);
        let factored = PackedLiteralSetPlan::new(&refs, PackedLiteralSetBuildLimits::default())
            .expect("complete 72-string product");
        assert!(matches!(&factored.engine, PackedLiteralEngine::Factored(_)));
        let persistent = factored.build_accounting().persistent_bytes;
        assert_eq!(
            PackedLiteralSetPlan::new(
                &refs,
                PackedLiteralSetBuildLimits {
                    max_persistent_bytes: persistent,
                    ..PackedLiteralSetBuildLimits::default()
                },
            )
            .unwrap()
            .build_accounting()
            .persistent_bytes,
            persistent
        );
        assert!(matches!(
            PackedLiteralSetPlan::new(
                &refs,
                PackedLiteralSetBuildLimits {
                    max_persistent_bytes: persistent - 1,
                    ..PackedLiteralSetBuildLimits::default()
                },
            ),
            Err(PackedLiteralSetError::PersistentBytesLimit { needed, limit })
                if needed == persistent && limit == persistent - 1
        ));

        for pattern in &patterns {
            let mut haystack = b"xx".to_vec();
            haystack.extend_from_slice(pattern);
            haystack.extend_from_slice(b"yy");
            assert_eq!(
                factored
                    .find(&haystack, PackedLiteralSetSearchLimits::unlimited())
                    .unwrap()
                    .0,
                Some((2, 6))
            );
        }
        for miss in [b"l3Tu", b"m2Tu", b"m3Su", b"m3Tw"] {
            assert_eq!(
                factored
                    .find(miss, PackedLiteralSetSearchLimits::unlimited())
                    .unwrap()
                    .0,
                None
            );
        }
        assert_eq!(
            factored
                .find_window(
                    b"badm3Tuxxr8Tv",
                    Window::new(5, 13),
                    PackedLiteralSetSearchLimits::unlimited(),
                )
                .unwrap()
                .0,
            Some((9, 13))
        );

        let mut incomplete = patterns;
        incomplete[71] = incomplete[0].clone();
        let refs = pattern_refs(&incomplete);
        assert!(matches!(
            PackedLiteralSetPlan::new(&refs, PackedLiteralSetBuildLimits::default()),
            Err(PackedLiteralSetError::UnsupportedTargetOrShape)
        ));
    }

    #[test]
    fn factored_search_covers_two_and_three_byte_anchor_classes() {
        let two_anchor: [&[u8]; 4] = [b"\x00\x01", b"abc", b"def", b"ghij"];
        let three_anchor: [&[u8]; 4] = [b"\x00\x01\x02", b"abc", b"def", b"ghi"];
        for (classes, expected_anchor_len) in [(two_anchor, 2), (three_anchor, 3)] {
            let patterns = cartesian_four(classes);
            let refs = pattern_refs(&patterns);
            let factored =
                PackedLiteralSetPlan::new(&refs, PackedLiteralSetBuildLimits::default()).unwrap();
            let PackedLiteralEngine::Factored(columns) = &factored.engine else {
                panic!("complete column product did not select the factored engine")
            };
            assert_eq!(columns.anchor_len, expected_anchor_len);

            for pattern in patterns {
                let mut haystack = b"!!".to_vec();
                haystack.extend_from_slice(&pattern);
                assert_eq!(
                    factored
                        .find(&haystack, PackedLiteralSetSearchLimits::unlimited())
                        .unwrap()
                        .0,
                    Some((2, 6))
                );
            }
            assert_eq!(
                factored
                    .find(b"!!!!", PackedLiteralSetSearchLimits::unlimited())
                    .unwrap()
                    .0,
                None
            );
        }
    }
}
