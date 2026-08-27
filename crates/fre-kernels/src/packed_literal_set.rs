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
const SHARED_FRAGMENT_DISPATCH_GROUPS: usize = 256;
const SHARED_FRAGMENT_DISPATCH_TABLE_BYTES: usize =
    SHARED_FRAGMENT_DISPATCH_GROUPS * size_of::<u16>();
const SHARED_FRAGMENT_DISPATCH_WORK_SHIFT: u32 = u16::BITS;
const SHARED_FRAGMENT_DISPATCH_WORK_MASK: u32 = 0x3f;
const SHARED_FRAGMENT_DISPATCH_BUDGET_SHIFT: u32 =
    SHARED_FRAGMENT_DISPATCH_WORK_SHIFT + SHARED_FRAGMENT_DISPATCH_WORK_MASK.count_ones();
const SHARED_FRAGMENT_DISPATCH_BUDGET_MASK: u32 = 0xff;
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
const RETAINED_ITER_DENSE_GAP_BYTES: usize = 16;
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

#[derive(Clone, Copy, Debug)]
struct PackedLiteralSetSearchPreflight {
    searched_bytes: usize,
    positions_upper_bound: usize,
    work_upper_bound: usize,
}

#[inline]
fn search_work_upper_bound(
    searched_bytes: usize,
    verification_bytes_per_position: usize,
) -> Option<(usize, usize)> {
    let positions_upper_bound = searched_bytes.checked_add(1)?;
    let work_upper_bound = positions_upper_bound.checked_mul(verification_bytes_per_position)?;
    Some((positions_upper_bound, work_upper_bound))
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
    minimum_pattern_width: u16,
    maximum_candidate_verification_work: usize,
    // Exclusive start boundary proved by the native prefix search.
    native_start_budget: usize,
    // Maximum source length kept wholly on the native engine and, on longer
    // sources, the prefix byte extent. This includes the exact right overlap
    // needed to prove every start below `native_start_budget`. Construction
    // computes it once so an early native match has no arithmetic tail.
    native_prefix_bytes: usize,
    finder: Finder<'static>,
    // Packed exact dispatch certificate. Zero keeps the incumbent verifier.
    // Otherwise the low u16 is offset + 1, followed by six bits of worst
    // bucket work and eight bits of derived candidate budget. This occupies
    // the same four-byte slot as R20's `Option<u16>` dispatch offset.
    dispatch_metadata: u32,
    // Patterns encoded as a little-endian u16 width followed by the bytes.
    // With dispatch they retain source order within each byte bucket and are
    // followed by 256 cumulative u16 group ends. Without dispatch they retain
    // global source order.
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
    #[allow(
        clippy::as_conversions,
        reason = "every retained pattern width is proved to fit u16 before construction"
    )]
    const fn minimum_pattern_width(&self) -> usize {
        self.minimum_pattern_width as usize
    }

    fn dispatch_offset(&self) -> Option<usize> {
        let encoded = u16::try_from(self.dispatch_metadata & u32::from(u16::MAX)).ok()?;
        Some(usize::from(encoded.checked_sub(1)?))
    }

    #[cfg(any(debug_assertions, test))]
    fn maximum_dispatch_candidate_verification_work(&self) -> usize {
        usize::try_from(
            (self.dispatch_metadata >> SHARED_FRAGMENT_DISPATCH_WORK_SHIFT)
                & SHARED_FRAGMENT_DISPATCH_WORK_MASK,
        )
        .expect("the dispatch work field fits usize")
    }

    fn retained_dispatch_candidate_budget(&self) -> usize {
        usize::try_from(
            (self.dispatch_metadata >> SHARED_FRAGMENT_DISPATCH_BUDGET_SHIFT)
                & SHARED_FRAGMENT_DISPATCH_BUDGET_MASK,
        )
        .expect("the dispatch budget field fits usize")
    }

    fn dispatch_candidate_budget(&self) -> usize {
        if self.dispatch_metadata == 0 {
            return NATIVE_FILTER_CANDIDATE_BUDGET;
        }
        let dispatch_budget = self.retained_dispatch_candidate_budget();
        #[cfg(debug_assertions)]
        {
            let dispatch_work = self.maximum_dispatch_candidate_verification_work();
            let incumbent_envelope = self
                .maximum_candidate_verification_work
                .checked_mul(NATIVE_FILTER_CANDIDATE_BUDGET)
                .expect("the shared-fragment construction caps candidate work");
            debug_assert!(dispatch_work <= self.maximum_candidate_verification_work);
            debug_assert!(dispatch_budget >= NATIVE_FILTER_CANDIDATE_BUDGET);
            debug_assert!(dispatch_work.checked_mul(dispatch_budget) <= Some(incumbent_envelope));
        }
        dispatch_budget
    }

    fn dispatch_parts(&self) -> Option<(usize, &[u8], &[u8])> {
        let dispatch_offset = self.dispatch_offset()?;
        let trailer_start = self
            .patterns
            .len()
            .checked_sub(SHARED_FRAGMENT_DISPATCH_TABLE_BYTES)?;
        let encoded = self.patterns.get(..trailer_start)?;
        let group_ends = self.patterns.get(trailer_start..)?;
        Some((dispatch_offset, encoded, group_ends))
    }

    fn dispatch_group_end(group_ends: &[u8], group: usize) -> Option<usize> {
        let byte_start = group.checked_mul(size_of::<u16>())?;
        let &[low, high] = group_ends.get(byte_start..byte_start.checked_add(2)?)? else {
            return None;
        };
        Some(usize::from(u16::from_le_bytes([low, high])))
    }

    fn dispatch_group_at<'a>(&'a self, haystack: &[u8], start: usize) -> Option<&'a [u8]> {
        let (dispatch_offset, encoded, group_ends) = self.dispatch_parts()?;
        let byte = *haystack.get(start.checked_add(dispatch_offset)?)?;
        let group = usize::from(byte);
        let group_start = if group == 0 {
            0
        } else {
            Self::dispatch_group_end(group_ends, group.checked_sub(1)?)?
        };
        let group_end = Self::dispatch_group_end(group_ends, group)?;
        encoded.get(group_start..group_end)
    }

    fn earliest_possible_start_from(&self, haystack: &[u8], minimum_start: usize) -> Option<usize> {
        let last_start = haystack.len().checked_sub(self.minimum_pattern_width())?;
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
        let dispatch = self.dispatch_parts();
        let mut encoded = if let Some((dispatch_offset, encoded, group_ends)) = dispatch {
            let byte = *haystack.get(start.checked_add(dispatch_offset)?)?;
            let group = usize::from(byte);
            let group_start = if group == 0 {
                0
            } else {
                Self::dispatch_group_end(group_ends, group.checked_sub(1)?)?
            };
            let group_end = Self::dispatch_group_end(group_ends, group)?;
            if group_start == group_end {
                return None;
            }
            encoded.get(group_start..group_end)?
        } else {
            self.patterns.as_ref()
        };
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
            let matches = if let Some((dispatch_offset, _, _)) = dispatch {
                if dispatch_offset < self.offset {
                    candidate.get(..dispatch_offset) == pattern.get(..dispatch_offset)
                        && candidate.get(dispatch_offset.checked_add(1)?..self.offset)
                            == pattern.get(dispatch_offset.checked_add(1)?..self.offset)
                        && candidate.get(fragment_end..) == pattern.get(fragment_end..)
                } else {
                    debug_assert!(dispatch_offset >= fragment_end);
                    candidate.get(..self.offset) == pattern.get(..self.offset)
                        && candidate.get(fragment_end..dispatch_offset)
                            == pattern.get(fragment_end..dispatch_offset)
                        && candidate.get(dispatch_offset.checked_add(1)?..)
                            == pattern.get(dispatch_offset.checked_add(1)?..)
                }
            } else {
                candidate.get(..self.offset) == pattern.get(..self.offset)
                    && candidate.get(fragment_end..) == pattern.get(fragment_end..)
            };
            if matches {
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
    uniform: &'p UniformWord64,
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
        #[cfg_attr(
            feature = "static-dispatch",
            allow(unused_variables, reason = "retained native iteration is unavailable")
        )]
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
            if patterns.len() <= TEDDY_PATTERNS_PER_SEARCHER
                && let Some(native_searcher) = Searcher::new(patterns.iter().map(AsRef::as_ref))
            {
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
                    let maximum_sidecar_bytes = limits
                        .max_persistent_bytes
                        .saturating_sub(native_searcher.memory_usage());
                    select_shared_fragment_with_max_persistent_bytes(
                        patterns,
                        native_searcher.minimum_len(),
                        maximum_sidecar_bytes,
                    )
                    .map(Box::new)
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
            minimum_pattern_bytes: shared_fragment.minimum_pattern_width(),
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

    /// Bind the direct ordinary-search engine for a complete source only when
    /// the finite search's conservative work arithmetic is representable.
    ///
    /// This admission is source-free and does not enforce a caller-selected
    /// work cap. A decline must replay the finite value path so its canonical
    /// preflight reports the arithmetic failure before source access.
    #[doc(hidden)]
    #[must_use]
    pub fn try_ordinary_full_window_executor(
        &self,
        haystack_len: usize,
    ) -> Option<PackedLiteralSetOrdinaryExecutor<'_>> {
        search_work_upper_bound(haystack_len, self.verification_bytes_per_position)?;
        Some(self.ordinary_executor())
    }

    /// Return an allocation-free adaptive cursor when both uniform and native
    /// packed engines were admitted during construction.
    #[cfg(not(feature = "static-dispatch"))]
    #[must_use]
    pub fn search_cursor<'p, 'h>(
        &'p self,
        haystack: &'h [u8],
    ) -> Option<PackedLiteralSetSearchCursor<'p, 'h>> {
        let PackedLiteralEngine::UniformWord64Retained { uniform, native } =
            &self.engine
        else {
            return None;
        };
        Some(PackedLiteralSetSearchCursor {
            plan: self,
            uniform,
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

    /// Return only the selected span inside a byte range.
    ///
    /// This compact projection performs the accounted search's identical
    /// window, arithmetic, and work-limit preflight without retaining its
    /// diagnostic accounting receipt.
    ///
    /// # Errors
    ///
    /// Returns the same checked window, arithmetic, or work-limit error as
    /// [`Self::find_window`].
    #[inline]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the validated slice and packed engine contracts prove these window-relative additions"
    )]
    pub fn find_window_value(
        &self,
        haystack: &[u8],
        window: Window,
        limits: PackedLiteralSetSearchLimits,
    ) -> Result<Option<(usize, usize)>, PackedLiteralSetError> {
        self.search_preflight(haystack.len(), window, limits)?;
        let window_bytes = &haystack[window.start()..window.end()];
        Ok(self
            .find_relative(window_bytes, None)
            .map(|(relative_start, relative_end)| {
                (
                    window.start() + relative_start,
                    window.start() + relative_end,
                )
            }))
    }

    /// Return only whether a selected span exists inside a byte range.
    ///
    /// This is the boolean projection of [`Self::find_window_value`] and
    /// therefore preserves its exact validation and resource contract.
    #[inline]
    pub fn is_match_window_value(
        &self,
        haystack: &[u8],
        window: Window,
        limits: PackedLiteralSetSearchLimits,
    ) -> Result<bool, PackedLiteralSetError> {
        self.find_window_value(haystack, window, limits)
            .map(|matched| matched.is_some())
    }

    #[inline]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "a validated byte-slice window proves the subtraction"
    )]
    fn search_preflight(
        &self,
        haystack_len: usize,
        window: Window,
        limits: PackedLiteralSetSearchLimits,
    ) -> Result<PackedLiteralSetSearchPreflight, PackedLiteralSetError> {
        if window.start() > window.end() || window.end() > haystack_len {
            return Err(PackedLiteralSetError::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len,
            });
        }
        let searched_bytes = window.end() - window.start();
        let (positions_upper_bound, work_upper_bound) =
            search_work_upper_bound(searched_bytes, self.verification_bytes_per_position).ok_or(
                PackedLiteralSetError::ArithmeticOverflow {
                    computation: "packed literal search work",
                },
            )?;
        if work_upper_bound > limits.max_work {
            return Err(PackedLiteralSetError::WorkLimit {
                needed: work_upper_bound,
                limit: limits.max_work,
            });
        }
        Ok(PackedLiteralSetSearchPreflight {
            searched_bytes,
            positions_upper_bound,
            work_upper_bound,
        })
    }

    #[inline]
    fn find_window_value_unmetered_with_native(
        &self,
        haystack: &[u8],
        window: Window,
        iterator_native: Option<&Searcher>,
    ) -> Result<Option<(usize, usize)>, PackedLiteralSetError> {
        validate_window(window, haystack.len())?;
        Ok(self.find_window_value_unmetered_validated(haystack, window, iterator_native))
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the validated slice and packed engine contracts prove these window-relative additions"
    )]
    #[inline(never)]
    fn find_window_value_unmetered_validated(
        &self,
        haystack: &[u8],
        window: Window,
        iterator_native: Option<&Searcher>,
    ) -> Option<(usize, usize)> {
        debug_assert!(window.start() <= window.end() && window.end() <= haystack.len());
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
        matched.map(|(relative_start, relative_end)| {
            (
                window.start() + relative_start,
                window.start() + relative_end,
            )
        })
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
        let preflight = self.search_preflight(haystack.len(), window, limits)?;
        let searched_bytes = preflight.searched_bytes;
        let verification_bytes_per_position = self.verification_bytes_per_position;
        let simd_eligible_length = iterator_native.map_or_else(
            || match &self.engine {
                #[cfg(not(feature = "static-dispatch"))]
                PackedLiteralEngine::UniformWord64(_)
                | PackedLiteralEngine::UniformWord64Retained { .. } => false,
                _ => searched_bytes >= self.build.simd_minimum_haystack_bytes,
            },
            |native| searched_bytes >= native.minimum_len(),
        );
        let accounting = PackedLiteralSetAccounting {
            searched_bytes,
            positions_upper_bound: preflight.positions_upper_bound,
            verification_bytes_per_position,
            work_upper_bound: preflight.work_upper_bound,
            scratch_bytes: 0,
            factored_columns: iterator_native.is_none()
                && matches!(&self.engine, PackedLiteralEngine::Factored(_)),
            simd_eligible_length,
        };
        let window_bytes = &haystack[window.start()..window.end()];
        let matched = self.find_relative(window_bytes, iterator_native);
        let matched = matched.map(|(relative_start, relative_end)| {
            (
                window.start() + relative_start,
                window.start() + relative_end,
            )
        });
        Ok((matched, accounting))
    }

    #[inline]
    fn find_relative(
        &self,
        window_bytes: &[u8],
        iterator_native: Option<&Searcher>,
    ) -> Option<(usize, usize)> {
        if let Some(native) = iterator_native {
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
                PackedLiteralEngine::Factored(factored) => factored.find(window_bytes),
            }
        }
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
        if start > self.haystack.len() {
            self.observe_start(start);
            return Err(PackedLiteralSetError::InvalidWindow {
                start,
                end: self.haystack.len(),
                haystack_len: self.haystack.len(),
            });
        }
        self.observe_start(start);
        Ok(self.find_at_value_unmetered_forward_validated(start))
    }

    #[inline(always)]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the caller-proved suffix and retained-engine contracts prove these offsets"
    )]
    fn find_at_value_unmetered_forward_validated(
        &mut self,
        start: usize,
    ) -> Option<(usize, usize)> {
        debug_assert!(start <= self.haystack.len());
        let remaining = self.haystack.len() - start;
        let use_uniform = self.dense && remaining >= RETAINED_ITER_UNIFORM_MIN_WINDOW_BYTES;
        let window_bytes = &self.haystack[start..];
        let relative = if use_uniform {
            self.uniform.find(window_bytes)
        } else {
            self.native
                .find(window_bytes)
                .map(|matched| (matched.start(), matched.end()))
        };
        let matched = relative.map(|(matched_start, matched_end)| {
            (start + matched_start, start + matched_end)
        });
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
        matched
    }

    #[inline(always)]
    fn observe_start(&mut self, start: usize) {
        if self.last_start.is_some_and(|previous| start < previous) {
            self.close_matches = 0;
            self.dense = false;
        }
        self.last_start = Some(start);
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
                // This cursor is private to this positive-width loop, so each
                // selected endpoint strictly advances `start`; retain its
                // last-start state without repeating the backward comparison.
                debug_assert!(
                    cursor.last_start.is_none_or(|last| start > last)
                );
                cursor.last_start = Some(start);
                cursor.find_at_value_unmetered_forward_validated(start)
            } else {
                self.plan.find_window_value_unmetered_validated(
                    haystack,
                    Window::new(start, window.end()),
                    None,
                )
            };
            #[cfg(feature = "static-dispatch")]
            let matched = self.plan.find_window_value_unmetered_validated(
                haystack,
                Window::new(start, window.end()),
                None,
            );
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
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "positive-width non-overlapping spans are bounded by the validated window length"
    )]
    pub fn count_spans_window_value(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<u64, PackedLiteralSetError> {
        let mut count = 0_usize;
        let outcome = self.try_visit_spans_window_value(haystack, window, |_| {
            // Positive-width, non-overlapping spans bound the final count by
            // this already-validated window's `usize` byte length.
            count += 1;
            Ok::<bool, core::convert::Infallible>(true)
        })?;
        match outcome {
            Ok(()) => {}
            Err(never) => match never {},
        }
        u64::try_from(count).map_err(|_| PackedLiteralSetError::ArithmeticOverflow {
            computation: "packed ordinary match count",
        })
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

#[inline(never)]
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

#[inline(never)]
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
    let minimum_start = match find_selected_bounded_long_shared_fragment(fragment, haystack)? {
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

#[inline]
fn find_selected_bounded_long_shared_fragment(
    fragment: &SharedFragment,
    haystack: &[u8],
) -> Option<LongSharedFragmentFilterResult> {
    if fragment.offset == 0 && fragment.dispatch_parts().is_some() {
        return find_bounded_zero_offset_empty_dispatch(fragment, haystack);
    }
    find_bounded_long_shared_fragment(fragment, haystack)
}

#[inline(never)]
fn find_bounded_zero_offset_empty_dispatch(
    fragment: &SharedFragment,
    haystack: &[u8],
) -> Option<LongSharedFragmentFilterResult> {
    debug_assert_eq!(fragment.offset, 0);
    debug_assert!(fragment.dispatch_parts().is_some());
    let Some(first) = fragment.earliest_possible_start_from(haystack, 0) else {
        return Some(LongSharedFragmentFilterResult::Exhausted);
    };
    let after_first = first.checked_add(1)?;
    let mut verification_attempts = 0_usize;
    if !fragment.dispatch_group_at(haystack, first)?.is_empty() {
        verification_attempts = 1;
        if let Some(end) = fragment.verify_at(haystack, first) {
            return Some(LongSharedFragmentFilterResult::Match { start: first, end });
        }
    }
    let Some(second) = fragment.earliest_possible_start_from(haystack, after_first) else {
        return Some(LongSharedFragmentFilterResult::Exhausted);
    };
    if second < first.saturating_add(fragment.width) {
        return Some(LongSharedFragmentFilterResult::ResumeAt(after_first));
    }

    // Keep the incumbent occurrence-density guard, but spend the bounded
    // retained-pattern budget only on dispatch groups that can still match.
    // An empty group is already a complete exact rejection. This continuation
    // is profitable only for prefix fragments: public offset fragments leave
    // the incumbent loop unchanged because native fallback wins there.
    let dense_stream_span = fragment.width.saturating_mul(2);
    let candidate_budget = fragment.dispatch_candidate_budget();
    debug_assert!(candidate_budget >= NATIVE_FILTER_CANDIDATE_BUDGET);
    let mut pending_candidate = Some(second);
    let mut minimum_start = after_first;
    let mut previous_candidate = first;
    let mut occurrence_index = 1_usize;
    loop {
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
        if occurrence_index >= NATIVE_FILTER_CANDIDATE_BUDGET
            && candidate.saturating_sub(previous_candidate) <= dense_stream_span
        {
            return Some(LongSharedFragmentFilterResult::ResumeAt(candidate));
        }
        let after_candidate = candidate.checked_add(1)?;
        if !fragment.dispatch_group_at(haystack, candidate)?.is_empty() {
            if verification_attempts >= candidate_budget {
                return Some(LongSharedFragmentFilterResult::ResumeAt(candidate));
            }
            verification_attempts = verification_attempts.checked_add(1)?;
            if let Some(end) = fragment.verify_at(haystack, candidate) {
                return Some(LongSharedFragmentFilterResult::Match {
                    start: candidate,
                    end,
                });
            }
        }
        minimum_start = after_candidate;
        previous_candidate = candidate;
        occurrence_index = occurrence_index.checked_add(1)?;
    }
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
        // Overlapping occurrences are a saturated stream. Native resumes
        // after the one exactly disproved start instead of buying four exact
        // probes that advance only a handful of bytes.
        return Some(LongSharedFragmentFilterResult::ResumeAt(after_first));
    }

    // Keep the incumbent four exact probes for nonoverlapping occurrences.
    // Every additional dispatch probe must independently buy more than two
    // fragment widths of progress from the previous occurrence. Checking each
    // adjacent gap prevents one early sparse pair from subsidizing a later
    // dense tail, while a later sparse region is not poisoned by early density.
    let dense_stream_span = fragment.width.saturating_mul(2);
    let mut pending_candidate = Some(second);
    let mut minimum_start = after_first;
    let mut previous_candidate = first;
    let candidate_budget = fragment.dispatch_candidate_budget();
    debug_assert!(candidate_budget >= NATIVE_FILTER_CANDIDATE_BUDGET);
    for attempt in 1..candidate_budget {
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
        if attempt >= NATIVE_FILTER_CANDIDATE_BUDGET
            && candidate.saturating_sub(previous_candidate) <= dense_stream_span
        {
            return Some(LongSharedFragmentFilterResult::ResumeAt(candidate));
        }
        let after_candidate = candidate.checked_add(1)?;
        if let Some(end) = fragment.verify_at(haystack, candidate) {
            return Some(LongSharedFragmentFilterResult::Match {
                start: candidate,
                end,
            });
        }
        minimum_start = after_candidate;
        previous_candidate = candidate;
    }
    // One final lookahead stays in the same increasing fragment-occurrence
    // stream. It performs no verification work: absence proves the source is
    // exhausted, while presence leaves that candidate and every later start
    // to the unchanged native fallback.
    let Some(candidate) = fragment.earliest_possible_start_from(haystack, minimum_start) else {
        return Some(LongSharedFragmentFilterResult::Exhausted);
    };
    // The lookahead proved that every possible start before `candidate` is
    // fragment-free. Resume at the first still-unverified candidate instead
    // of making the native engine rescan that disproved gap.
    Some(LongSharedFragmentFilterResult::ResumeAt(candidate))
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

#[inline(never)]
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

#[cfg(test)]
fn select_shared_fragment<P: AsRef<[u8]>>(
    patterns: &[P],
    native_minimum_haystack_bytes: usize,
) -> Option<SharedFragment> {
    select_shared_fragment_with_max_persistent_bytes(
        patterns,
        native_minimum_haystack_bytes,
        usize::MAX,
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "shared-fragment selection keeps one bounded scoring and allocation transaction"
)]
fn select_shared_fragment_with_max_persistent_bytes<P: AsRef<[u8]>>(
    patterns: &[P],
    native_minimum_haystack_bytes: usize,
    maximum_sidecar_bytes: usize,
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

    let fragment_end = best_offset.checked_add(best_width)?;
    let incumbent_sidecar_bytes = size_of::<SharedFragment>()
        .checked_add(retained_pattern_bytes)?
        .checked_add(best_width)?;
    let dispatch_sidecar_bytes =
        incumbent_sidecar_bytes.checked_add(SHARED_FRAGMENT_DISPATCH_TABLE_BYTES)?;
    let dispatch_fits = dispatch_sidecar_bytes <= maximum_sidecar_bytes;
    let selected_dispatch_offset = if dispatch_fits {
        select_shared_fragment_dispatch_offset(
            patterns,
            minimum_pattern_width,
            best_offset,
            fragment_end,
        )
    } else {
        None
    };
    let mut retained = Vec::with_capacity(retained_pattern_bytes);
    for pattern in patterns {
        let pattern = pattern.as_ref();
        retained.extend_from_slice(&u16::try_from(pattern.len()).ok()?.to_le_bytes());
        retained.extend_from_slice(pattern);
    }
    let mut retained_dispatch = false;
    let mut maximum_dispatch_candidate_verification_work = 0_usize;
    let mut retained_dispatch_candidate_budget = 0_usize;
    if dispatch_fits && selected_dispatch_offset.is_some() {
        #[cfg(test)]
        let allocation_allowed = !shared_fragment_dispatch_allocation_probe::take_failure();
        #[cfg(not(test))]
        let allocation_allowed = true;
        retained_dispatch = allocation_allowed
            && retained
                .try_reserve_exact(SHARED_FRAGMENT_DISPATCH_TABLE_BYTES)
                .is_ok();
    }
    if retained_dispatch {
        let dispatch_offset = selected_dispatch_offset?;
        let mut group_ends = [0_u16; SHARED_FRAGMENT_DISPATCH_GROUPS];
        let mut maximum_group_work = 0_usize;
        retained.clear();
        for dispatch_byte in 0_u16..=u16::from(u8::MAX) {
            let dispatch_byte = u8::try_from(dispatch_byte).ok()?;
            let mut group_work = 0_usize;
            for pattern in patterns {
                let pattern = pattern.as_ref();
                if pattern[dispatch_offset] != dispatch_byte {
                    continue;
                }
                // One dispatch-byte load plus all comparisons outside the
                // fragment costs no more than the sum of every surviving
                // pattern's outside-fragment bytes. For a multi-pattern
                // bucket this deliberately charges the shared dispatch byte
                // once per pattern, making the bound conservative.
                group_work = group_work.checked_add(pattern.len().checked_sub(best_width)?)?;
                retained.extend_from_slice(&u16::try_from(pattern.len()).ok()?.to_le_bytes());
                retained.extend_from_slice(pattern);
            }
            maximum_group_work = maximum_group_work.max(group_work);
            group_ends[usize::from(dispatch_byte)] = u16::try_from(retained.len()).ok()?;
        }
        maximum_dispatch_candidate_verification_work = maximum_group_work;
        debug_assert!(maximum_dispatch_candidate_verification_work > 0);
        let incumbent_verification_envelope = maximum_candidate_verification_work
            .checked_mul(NATIVE_FILTER_CANDIDATE_BUDGET)?;
        retained_dispatch_candidate_budget =
            incumbent_verification_envelope.checked_div(maximum_group_work)?;
        debug_assert!(
            retained_dispatch_candidate_budget >= NATIVE_FILTER_CANDIDATE_BUDGET
        );
        debug_assert_eq!(retained.len(), retained_pattern_bytes);
        for group_end in group_ends {
            retained.extend_from_slice(&group_end.to_le_bytes());
        }
    }
    let dispatch_metadata = if retained_dispatch {
        let offset = u16::try_from(selected_dispatch_offset?.checked_add(1)?).ok()?;
        let dispatch_work = u32::try_from(maximum_dispatch_candidate_verification_work).ok()?;
        if dispatch_work > SHARED_FRAGMENT_DISPATCH_WORK_MASK {
            return None;
        }
        let dispatch_budget = u32::try_from(retained_dispatch_candidate_budget).ok()?;
        if dispatch_budget > SHARED_FRAGMENT_DISPATCH_BUDGET_MASK {
            return None;
        }
        u32::from(offset)
            | dispatch_work.checked_shl(SHARED_FRAGMENT_DISPATCH_WORK_SHIFT)?
            | dispatch_budget.checked_shl(SHARED_FRAGMENT_DISPATCH_BUDGET_SHIFT)?
    } else {
        0
    };
    let mut needle = Vec::with_capacity(best_width);
    needle.extend_from_slice(first.get(best_offset..fragment_end)?);
    Some(SharedFragment {
        offset: best_offset,
        width: best_width,
        minimum_pattern_width: u16::try_from(minimum_pattern_width).ok()?,
        maximum_candidate_verification_work,
        native_start_budget,
        native_prefix_bytes,
        finder: FinderBuilder::new().build_forward_owned(needle),
        dispatch_metadata,
        patterns: retained.into_boxed_slice(),
    })
}

fn select_shared_fragment_dispatch_offset<P: AsRef<[u8]>>(
    patterns: &[P],
    minimum_pattern_width: usize,
    fragment_start: usize,
    fragment_end: usize,
) -> Option<usize> {
    #[cfg(test)]
    shared_fragment_dispatch_selection_probe::record();
    if patterns.is_empty() {
        return None;
    }
    let mut best = None;
    let mut best_score = (usize::MAX, usize::MAX, u64::MAX, usize::MAX);
    let mut bucket_counts = [0_usize; SHARED_FRAGMENT_DISPATCH_GROUPS];
    let mut touched = [0_u8; SHARED_FRAGMENT_DISPATCH_GROUPS];
    for offset in 0..minimum_pattern_width {
        if (fragment_start..fragment_end).contains(&offset) {
            continue;
        }
        let mut touched_len = 0_usize;
        let mut maximum_bucket = 0_usize;
        let mut collision_work = 0_usize;
        let mut frequency_score = 0_u64;
        for pattern in patterns {
            let byte = *pattern.as_ref().get(offset)?;
            let bucket = &mut bucket_counts[usize::from(byte)];
            let previous = *bucket;
            *bucket = previous.checked_add(1)?;
            maximum_bucket = maximum_bucket.max(*bucket);
            collision_work = collision_work
                .checked_add(previous.checked_mul(2)?.checked_add(1)?)?;
            if previous == 0 {
                *touched.get_mut(touched_len)? = byte;
                touched_len = touched_len.checked_add(1)?;
                frequency_score = frequency_score.checked_add(
                    u64::from(crate::packed_ordered_literal_aggregate::byte_frequency_rank(byte))
                        .checked_add(1)?,
                )?;
            }
        }
        for &byte in touched.get(..touched_len)? {
            bucket_counts[usize::from(byte)] = 0;
        }
        // Minimize the worst surviving bucket first, then the average
        // source-alternative work under a uniform source-pattern prior. When
        // two columns partition the language equally, prefer the rarer byte
        // set and finally the lower fixed offset.
        let score = (maximum_bucket, collision_work, frequency_score, offset);
        if score < best_score {
            best_score = score;
            best = Some(offset);
        }
    }
    if best_score.0 < patterns.len() {
        best
    } else {
        None
    }
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
mod shared_fragment_dispatch_allocation_probe {
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
mod shared_fragment_dispatch_selection_probe {
    use std::cell::Cell;

    thread_local! {
        static CALLS: Cell<usize> = const { Cell::new(0) };
    }

    pub(super) fn record() {
        CALLS.with(|calls| calls.set(calls.get().checked_add(1).unwrap()));
    }

    pub(super) fn reset() {
        CALLS.with(|calls| calls.set(0));
    }

    pub(super) fn calls() -> usize {
        CALLS.with(Cell::get)
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
        find_selected_bounded_long_shared_fragment,
        packed_literal_set_build_work_upper_bound_from_dimensions, select_shared_columns,
        search_work_upper_bound, select_shared_fragment, select_sparse_anchor,
        shared_fragment_dispatch_allocation_probe, shared_fragment_dispatch_selection_probe,
        shared_fragment_native_start_budget,
    };
    #[cfg(not(feature = "static-dispatch"))]
    use super::{
        RETAINED_ITER_BUILD_CAPABILITY_ID, RETAINED_ITER_RUNTIME_IMPLEMENTATION_ID,
        UNIFORM_WORD64_MASK_BYTES, UNIFORM_WORD64_RUNTIME_IMPLEMENTATION_ID,
        retained_iter_owner_allocation_probe, uniform_word64_allocation_probe,
    };
    use crate::Window;

    #[allow(
        dead_code,
        reason = "exact e030 SharedFragment layout witness for fallback accounting compatibility"
    )]
    struct E030SharedFragmentLayout {
        offset: usize,
        width: usize,
        minimum_pattern_width: usize,
        maximum_candidate_verification_work: usize,
        native_start_budget: usize,
        native_prefix_bytes: usize,
        finder: super::Finder<'static>,
        patterns: Box<[u8]>,
    }

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

    fn reference_shared_fragment_dispatch_offset(
        patterns: &[&[u8]],
        minimum_pattern_width: usize,
        fragment_start: usize,
        fragment_end: usize,
    ) -> Option<usize> {
        if patterns.is_empty() {
            return None;
        }
        let mut best = None;
        let mut best_score = (usize::MAX, usize::MAX, u64::MAX, usize::MAX);
        for offset in 0..minimum_pattern_width {
            if (fragment_start..fragment_end).contains(&offset) {
                continue;
            }
            let mut bucket_counts = [0_usize; super::SHARED_FRAGMENT_DISPATCH_GROUPS];
            for pattern in patterns {
                let byte = *pattern.get(offset)?;
                bucket_counts[usize::from(byte)] =
                    bucket_counts[usize::from(byte)].checked_add(1)?;
            }
            let (maximum_bucket, collision_work, frequency_score) =
                bucket_counts.iter().enumerate().try_fold(
                    (0_usize, 0_usize, 0_u64),
                    |(maximum, collisions, frequency), (byte, &bucket)| {
                        if bucket == 0 {
                            return Some((maximum, collisions, frequency));
                        }
                        Some((
                            maximum.max(bucket),
                            collisions.checked_add(bucket.checked_mul(bucket)?)?,
                            frequency.checked_add(
                                u64::from(
                                    crate::packed_ordered_literal_aggregate::byte_frequency_rank(
                                        u8::try_from(byte).ok()?,
                                    ),
                                )
                                .checked_add(1)?,
                            )?,
                        ))
                    },
                )?;
            let score = (maximum_bucket, collision_work, frequency_score, offset);
            if score < best_score {
                best_score = score;
                best = Some(offset);
            }
        }
        if best_score.0 < patterns.len() {
            best
        } else {
            None
        }
    }

    fn shared_prefix_patterns() -> [&'static [u8]; 8] {
        [
            b"aa00x", b"aa11", b"aa22", b"aa33", b"aa44", b"aa55", b"aa66", b"aa77",
        ]
    }

    #[derive(Clone, Copy)]
    struct PublicLongFragmentFamily {
        id: &'static str,
        patterns: &'static [&'static [u8]],
        decoy: &'static [u8],
        hit: &'static [u8],
        maximum_candidate_verification_work: usize,
        maximum_dispatch_candidate_verification_work: usize,
        dispatch_candidate_budget: usize,
    }

    fn public_long_fragment_families() -> [PublicLongFragmentFamily; 6] {
        const PREFIX8: &[&[u8]] =
            &[b"longpref0", b"longpref11", b"longpref222", b"longpref3333"];
        const OFFSET4_WIDTH8: &[&[u8]] = &[
            b"A000longpref0",
            b"B111longpref11",
            b"C222longpref222",
            b"D333longpref3333",
        ];
        const PREFIX12: &[&[u8]] = &[
            b"sharedfrag120",
            b"sharedfrag1211",
            b"sharedfrag12222",
            b"sharedfrag123333",
        ];
        const OFFSET1_WIDTH16: &[&[u8]] = &[
            b"ASHAREDFRAGMENT160",
            b"BSHAREDFRAGMENT1611",
            b"CSHAREDFRAGMENT162",
            b"DSHAREDFRAGMENT1633",
            b"ESHAREDFRAGMENT164",
            b"FSHAREDFRAGMENT1655",
            b"GSHAREDFRAGMENT166",
            b"HSHAREDFRAGMENT1677",
        ];
        const OFFSET1_WIDTH8_PRIORITY: &[&[u8]] = &[
            b"Alongpref00",
            b"Alongpref0",
            b"Blongpref11",
            b"Clongpref22",
            b"Dlongpref33",
        ];
        const SATURATED_WIDTH8: &[&[u8]] =
            &[b"aaaaaaaa0", b"aaaaaaaa11", b"aaaaaaaa222", b"aaaaaaaa3333"];

        [
            PublicLongFragmentFamily {
                id: "prefix8_c4_v14",
                patterns: PREFIX8,
                decoy: b"longprefx",
                hit: b"longpref3333",
                maximum_candidate_verification_work: 14,
                maximum_dispatch_candidate_verification_work: 4,
                dispatch_candidate_budget: 14,
            },
            PublicLongFragmentFamily {
                id: "offset4_width8_c4_v30",
                patterns: OFFSET4_WIDTH8,
                decoy: b"Z999longprefx",
                hit: b"D333longpref3333",
                maximum_candidate_verification_work: 30,
                maximum_dispatch_candidate_verification_work: 8,
                dispatch_candidate_budget: 15,
            },
            PublicLongFragmentFamily {
                id: "prefix12_c4_v14",
                patterns: PREFIX12,
                decoy: b"sharedfrag12x",
                hit: b"sharedfrag123333",
                maximum_candidate_verification_work: 14,
                maximum_dispatch_candidate_verification_work: 4,
                dispatch_candidate_budget: 14,
            },
            PublicLongFragmentFamily {
                id: "offset1_width16_c8_v28",
                patterns: OFFSET1_WIDTH16,
                decoy: b"ZSHAREDFRAGMENT16x",
                hit: b"HSHAREDFRAGMENT1677",
                maximum_candidate_verification_work: 28,
                maximum_dispatch_candidate_verification_work: 3,
                dispatch_candidate_budget: 37,
            },
            PublicLongFragmentFamily {
                id: "offset1_width8_c5_priority_v19",
                patterns: OFFSET1_WIDTH8_PRIORITY,
                decoy: b"Zlongprefx",
                hit: b"Alongpref00",
                maximum_candidate_verification_work: 19,
                maximum_dispatch_candidate_verification_work: 5,
                dispatch_candidate_budget: 15,
            },
            PublicLongFragmentFamily {
                id: "saturated_width8_c4_v14",
                patterns: SATURATED_WIDTH8,
                decoy: b"aaaaaaaaaaaaaaaa",
                hit: b"aaaaaaaa0",
                maximum_candidate_verification_work: 14,
                maximum_dispatch_candidate_verification_work: 4,
                dispatch_candidate_budget: 14,
            },
        ]
    }

    fn shared_fragment_dispatch_group(fragment: &super::SharedFragment, byte: u8) -> &[u8] {
        let (_, encoded, group_ends) = fragment
            .dispatch_parts()
            .expect("shared fragment has no dispatch table");
        let group = usize::from(byte);
        let start = if group == 0 {
            0
        } else {
            super::SharedFragment::dispatch_group_end(group_ends, group.checked_sub(1).unwrap())
                .unwrap()
        };
        let end = super::SharedFragment::dispatch_group_end(group_ends, group).unwrap();
        &encoded[start..end]
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
        let reversed = PackedLiteralSetError::InvalidWindow {
            start: 1,
            end: 0,
            haystack_len: haystack.len(),
        };
        assert_eq!(
            plan.find_window(haystack, Window::new(1, 0), zero_work),
            Err(reversed.clone())
        );
        assert_eq!(
            plan.find_window_value(haystack, Window::new(1, 0), zero_work),
            Err(reversed.clone())
        );
        assert_eq!(
            plan.is_match_window_value(haystack, Window::new(1, 0), zero_work),
            Err(reversed)
        );
        let past_end = haystack.len().checked_add(1).unwrap();
        let outside = PackedLiteralSetError::InvalidWindow {
            start: 0,
            end: past_end,
            haystack_len: haystack.len(),
        };
        assert_eq!(
            plan.find_window(haystack, Window::new(0, past_end), zero_work),
            Err(outside.clone())
        );
        assert_eq!(
            plan.find_window_value(haystack, Window::new(0, past_end), zero_work),
            Err(outside.clone())
        );
        assert_eq!(
            plan.is_match_window_value(haystack, Window::new(0, past_end), zero_work),
            Err(outside)
        );
    }

    fn assert_value_projection(
        plan: &PackedLiteralSetPlan,
        haystack: &[u8],
        window: Window,
        expected_match: Option<(usize, usize)>,
    ) {
        let (accounted, accounting) = plan
            .find_window(haystack, window, PackedLiteralSetSearchLimits::unlimited())
            .unwrap();
        assert_eq!(accounted, expected_match);
        let exact = PackedLiteralSetSearchLimits {
            max_work: accounting.work_upper_bound,
        };
        assert_eq!(
            plan.find_window_value(haystack, window, exact),
            Ok(expected_match)
        );
        assert_eq!(
            plan.is_match_window_value(haystack, window, exact),
            Ok(expected_match.is_some())
        );

        let one_below = accounting.work_upper_bound.checked_sub(1).unwrap();
        let expected_error = PackedLiteralSetError::WorkLimit {
            needed: accounting.work_upper_bound,
            limit: one_below,
        };
        let refused = PackedLiteralSetSearchLimits {
            max_work: one_below,
        };
        assert_eq!(
            plan.find_window_value(haystack, window, refused),
            Err(expected_error.clone())
        );
        assert_eq!(
            plan.is_match_window_value(haystack, window, refused),
            Err(expected_error)
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
    fn value_projection_preserves_every_engine_dispatch_and_exact_work_limit() {
        let native_patterns = [
            b"a".as_slice(),
            b"bb".as_slice(),
            b"ccc".as_slice(),
            b"dddd".as_slice(),
        ];
        let Some(native) = plan(&native_patterns) else {
            return;
        };
        assert!(matches!(&native.engine, PackedLiteralEngine::Native(_)));
        assert_value_projection(&native, b"--ccc--", Window::new(1, 6), Some((2, 5)));
        assert_value_projection(&native, b"-------", Window::new(1, 6), None);

        let Some(sparse) = plan(&[b"aQ", b"bQ", b"cQ"]) else {
            return;
        };
        assert!(matches!(
            &sparse.engine,
            PackedLiteralEngine::NativeSparse { .. }
        ));
        assert_value_projection(&sparse, b"--cQ--", Window::new(1, 5), Some((2, 4)));
        assert_value_projection(&sparse, b"------", Window::new(1, 5), None);

        let shared_column_patterns = [
            b"qbma".as_slice(),
            b"qbdb".as_slice(),
            b"qbuc".as_slice(),
            b"qbld".as_slice(),
            b"qbce".as_slice(),
            b"qbtf".as_slice(),
            b"qbkg".as_slice(),
            b"qbbh".as_slice(),
        ];
        let Some(shared_columns) = plan(&shared_column_patterns) else {
            return;
        };
        assert!(matches!(
            &shared_columns.engine,
            PackedLiteralEngine::NativeSharedColumns { .. }
        ));
        assert_value_projection(
            &shared_columns,
            b"--qbkg--",
            Window::new(1, 7),
            Some((2, 6)),
        );
        assert_value_projection(&shared_columns, b"--------", Window::new(1, 7), None);

        let Some(shared_fragment) = plan(&shared_prefix_patterns()) else {
            return;
        };
        assert!(matches!(
            &shared_fragment.engine,
            PackedLiteralEngine::NativeSharedFragment { .. }
        ));
        assert_value_projection(
            &shared_fragment,
            b"--aa77--",
            Window::new(1, 7),
            Some((2, 6)),
        );
        assert_value_projection(&shared_fragment, b"--------", Window::new(1, 7), None);

        let factored_patterns = cartesian_patterns();
        let factored_refs = pattern_refs(&factored_patterns);
        let factored =
            PackedLiteralSetPlan::new(&factored_refs, PackedLiteralSetBuildLimits::default())
                .unwrap();
        assert!(matches!(&factored.engine, PackedLiteralEngine::Factored(_)));
        assert_value_projection(
            &factored,
            b"--r8Tv--",
            Window::new(1, 7),
            Some((2, 6)),
        );
        assert_value_projection(&factored, b"--------", Window::new(1, 7), None);

        #[cfg(not(feature = "static-dispatch"))]
        {
            let uniform_patterns = [b"agggtaaa".as_slice(), b"tttaccct".as_slice()];
            let uniform = PackedLiteralSetPlan::new(
                &uniform_patterns,
                PackedLiteralSetBuildLimits::default(),
            )
            .unwrap();
            assert!(matches!(
                &uniform.engine,
                PackedLiteralEngine::UniformWord64(_)
            ));
            assert_value_projection(
                &uniform,
                b"--tttaccct--",
                Window::new(1, 11),
                Some((2, 10)),
            );
            assert_value_projection(&uniform, b"------------", Window::new(1, 11), None);

            let retained = PackedLiteralSetPlan::new_retained_iter(
                &uniform_patterns,
                PackedLiteralSetBuildLimits::default(),
                usize::MAX,
            )
            .unwrap();
            assert!(matches!(
                &retained.engine,
                PackedLiteralEngine::UniformWord64Retained { .. }
            ));
            assert_value_projection(
                &retained,
                b"--agggtaaa--",
                Window::new(1, 11),
                Some((2, 10)),
            );
            assert_value_projection(&retained, b"------------", Window::new(1, 11), None);
        }
    }

    #[test]
    fn value_projection_matches_accounted_in_every_short_binary_window() {
        let Some(plan) = plan(&[b"aa", b"bt", b"ta"]) else {
            return;
        };
        for length in 0_usize..=7 {
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
                        let expected = plan
                            .find_window(
                                &haystack,
                                window,
                                PackedLiteralSetSearchLimits::unlimited(),
                            )
                            .unwrap()
                            .0;
                        assert_eq!(
                            plan.find_window_value(
                                &haystack,
                                window,
                                PackedLiteralSetSearchLimits::unlimited(),
                            ),
                            Ok(expected),
                            "haystack={haystack:?}, window={start}..{end}",
                        );
                        assert_eq!(
                            plan.is_match_window_value(
                                &haystack,
                                window,
                                PackedLiteralSetSearchLimits::unlimited(),
                            ),
                            Ok(expected.is_some()),
                            "haystack={haystack:?}, window={start}..{end}",
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn value_projection_preserves_arithmetic_error_chronology() {
        let Some(mut plan) = plan(&[b"aQ", b"bQ", b"cQ"]) else {
            return;
        };
        plan.verification_bytes_per_position = usize::MAX;
        let haystack = b"x";
        assert!(
            plan.try_ordinary_full_window_executor(haystack.len())
                .is_none(),
            "ordinary admission must decline before the canonical preflight reports overflow",
        );
        assert_invalid_windows_precede_work(&plan, haystack);
        let expected = PackedLiteralSetError::ArithmeticOverflow {
            computation: "packed literal search work",
        };
        assert_eq!(
            plan.find_window(
                haystack,
                Window::full(haystack),
                PackedLiteralSetSearchLimits::unlimited(),
            ),
            Err(expected.clone())
        );
        assert_eq!(
            plan.find_window_value(
                haystack,
                Window::full(haystack),
                PackedLiteralSetSearchLimits::unlimited(),
            ),
            Err(expected.clone())
        );
        assert_eq!(
            plan.is_match_window_value(
                haystack,
                Window::full(haystack),
                PackedLiteralSetSearchLimits::unlimited(),
            ),
            Err(expected)
        );
    }

    #[test]
    fn ordinary_full_window_admission_is_exact_at_address_space_edges() {
        let patterns = [b"alpha".as_slice(), b"beta".as_slice(), b"gamma".as_slice()];
        let verification_bytes_per_position = patterns
            .iter()
            .map(|pattern| pattern.len())
            .sum::<usize>()
            .checked_add(patterns.len())
            .unwrap();
        assert_eq!(verification_bytes_per_position, 17);

        let admitted_len = usize::MAX
            .checked_div(verification_bytes_per_position)
            .unwrap()
            .checked_sub(1)
            .unwrap();
        let admitted_positions = admitted_len.checked_add(1).unwrap();
        let admitted_work = admitted_positions
            .checked_mul(verification_bytes_per_position)
            .unwrap();
        assert_eq!(
            search_work_upper_bound(admitted_len, verification_bytes_per_position),
            Some((admitted_positions, admitted_work)),
        );
        let declined_len = admitted_len.checked_add(1).unwrap();
        assert_eq!(
            search_work_upper_bound(declined_len, verification_bytes_per_position),
            None,
        );
        assert_eq!(
            search_work_upper_bound(usize::MAX - 1, 1),
            Some((usize::MAX, usize::MAX)),
        );
        assert_eq!(search_work_upper_bound(usize::MAX, 1), None);

        let Some(plan) = plan(&patterns) else {
            return;
        };
        assert_eq!(
            plan.verification_bytes_per_position,
            verification_bytes_per_position,
        );
        assert!(
            plan.try_ordinary_full_window_executor(admitted_len)
                .is_some(),
        );
        assert!(
            plan.try_ordinary_full_window_executor(declined_len)
                .is_none(),
        );
        assert!(
            plan.try_ordinary_full_window_executor(usize::MAX)
                .is_none(),
        );
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
        assert_eq!(
            super::select_shared_fragment_dispatch_offset(
                &[b"abX0".as_slice(), b"abX1".as_slice()],
                3,
                0,
                2,
            ),
            None,
        );
    }

    #[test]
    fn shared_fragment_dispatch_incremental_score_matches_reference() {
        const REPERTOIRE: &[u8] = b"aZ09_:/?[]{}!@#$%^&*+-=xy";
        for count in [2_usize, 3, 4, 8, 16, 32] {
            for width in [3_usize, 4, 8, 17, 33] {
                let patterns = (0..count)
                    .map(|pattern| {
                        (0..width + pattern % 3)
                            .map(|offset| {
                                if offset % 11 == 0 {
                                    b'q'
                                } else {
                                    let index = pattern
                                        .checked_mul(29)
                                        .unwrap()
                                        .checked_add(offset.checked_mul(17).unwrap())
                                        .unwrap()
                                        .checked_add((pattern ^ offset).checked_mul(7).unwrap())
                                        .unwrap()
                                        % REPERTOIRE.len();
                                    REPERTOIRE[index]
                                }
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();
                let refs = pattern_refs(&patterns);
                for fragment_start in [0, width / 3, width.saturating_sub(2)] {
                    let fragment_end = fragment_start.checked_add(2).unwrap().min(width);
                    assert_eq!(
                        super::select_shared_fragment_dispatch_offset(
                            &refs,
                            width,
                            fragment_start,
                            fragment_end,
                        ),
                        reference_shared_fragment_dispatch_offset(
                            &refs,
                            width,
                            fragment_start,
                            fragment_end,
                        ),
                        "count={count}, width={width}, fragment={fragment_start}..{fragment_end}",
                    );
                }
            }
        }
    }

    #[test]
    fn shared_fragment_dispatch_selects_the_strongest_column_for_variable_widths() {
        let patterns = [
            b"common__C1q".as_slice(),
            b"common__A0q0".as_slice(),
            b"common__A0q11".as_slice(),
            b"common__B0q222".as_slice(),
            b"common__B1q3333".as_slice(),
        ];
        let fragment = select_shared_fragment(&patterns, 1).unwrap();
        assert_eq!((fragment.offset, fragment.width), (0, 8));
        let (dispatch_offset, _, group_ends) = fragment.dispatch_parts().unwrap();
        assert_eq!(dispatch_offset, 8);
        assert_eq!(group_ends.len(), 256 * core::mem::size_of::<u16>());
        // Offset 8 has buckets 2/2/1. Offset 9 has buckets 3/2 and offset 10
        // is constant, so the worst-bucket and collision score is unique.
        assert_eq!(shared_fragment_dispatch_group(&fragment, b'A').len(), 29);
        assert_eq!(shared_fragment_dispatch_group(&fragment, b'B').len(), 33);
        assert_eq!(shared_fragment_dispatch_group(&fragment, b'C').len(), 13);
        assert!(shared_fragment_dispatch_group(&fragment, b'Z').is_empty());

        for pattern in patterns {
            let expected = patterns
                .iter()
                .find(|candidate| pattern.starts_with(candidate))
                .map(|candidate| candidate.len());
            assert_eq!(fragment.verify_at(pattern, 0), expected, "{pattern:?}");
        }
        // The common fragment is present, but an absent dispatch byte is an
        // exact zero-mask rejection before any retained pattern comparison.
        assert_eq!(fragment.verify_at(b"common__Z0q999", 0), None);
        assert_eq!(fragment.verify_at(b"common__", 0), None);
        assert_eq!(fragment.verify_at(b"common__A", 0), None);
        assert_eq!(fragment.verify_at(b"xxcommon__A0q0", 2), Some(14));
    }

    #[test]
    fn shared_fragment_dispatch_preserves_four_pattern_source_priority() {
        let long_first_patterns = [
            b"common__A0".as_slice(),
            b"common__A".as_slice(),
            b"common__B1".as_slice(),
            b"common__C22".as_slice(),
        ];
        let long_first = select_shared_fragment(&long_first_patterns, 1).unwrap();
        assert_eq!(long_first.dispatch_parts().unwrap().0, 8);
        assert_eq!(shared_fragment_dispatch_group(&long_first, b'A').len(), 23);
        assert_eq!(long_first.verify_at(b"common__A0", 0), Some(10));

        let short_first_patterns = [
            b"common__A".as_slice(),
            b"common__A0".as_slice(),
            b"common__B1".as_slice(),
            b"common__C22".as_slice(),
        ];
        let short_first = select_shared_fragment(&short_first_patterns, 1).unwrap();
        assert_eq!(short_first.verify_at(b"common__A0", 0), Some(9));
        for pattern in short_first_patterns {
            let expected = short_first_patterns
                .iter()
                .find(|candidate| pattern.starts_with(candidate))
                .map(|candidate| candidate.len());
            assert_eq!(short_first.verify_at(pattern, 0), expected, "{pattern:?}");
        }
    }

    #[test]
    fn shared_fragment_dispatch_handles_64k_windows_seams_and_dense_decoys() {
        const BUFFER_BYTES: usize = 64 * 1024;

        let patterns = shared_prefix_patterns();
        let Some(plan) = plan(&patterns) else {
            return;
        };
        let PackedLiteralEngine::NativeSharedFragment {
            searcher,
            shared_fragment,
        } = &plan.engine
        else {
            panic!("eight-pattern variable-width language lost its shared fragment")
        };
        let (dispatch_offset, _, group_ends) = shared_fragment.dispatch_parts().unwrap();
        assert_eq!(dispatch_offset, 2);
        assert_eq!(group_ends.len(), 256 * core::mem::size_of::<u16>());
        for pattern in patterns {
            assert_eq!(
                shared_fragment_dispatch_group(shared_fragment, pattern[2]).len(),
                pattern.len().checked_add(2).unwrap()
            );
            assert_eq!(shared_fragment.verify_at(pattern, 0), Some(pattern.len()));
        }
        assert!(shared_fragment_dispatch_group(shared_fragment, b'a').is_empty());

        let match_pattern = patterns[6];
        let match_start = BUFFER_BYTES.checked_sub(match_pattern.len()).unwrap();
        let mut dense = vec![b'a'; BUFFER_BYTES];
        dense[match_start..].copy_from_slice(match_pattern);
        let expected = searcher
            .find(&dense)
            .map(|matched| (matched.start(), matched.end()));
        assert_eq!(expected, Some((match_start, BUFFER_BYTES)));
        assert_eq!(
            plan.find(&dense, PackedLiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            expected
        );

        let seam = BUFFER_BYTES / 2;
        let seam_pattern = patterns[3];
        let seam_start = seam.checked_sub(2).unwrap();
        let seam_end = seam_start.checked_add(seam_pattern.len()).unwrap();
        let mut seam_haystack = vec![b'.'; BUFFER_BYTES];
        seam_haystack[seam_start..seam_end].copy_from_slice(seam_pattern);
        assert_eq!(
            plan.find(&seam_haystack, PackedLiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            Some((seam_start, seam_end))
        );
        for window in [Window::new(0, seam), Window::new(seam, BUFFER_BYTES)] {
            assert_eq!(
                plan.find_window(
                    &seam_haystack,
                    window,
                    PackedLiteralSetSearchLimits::unlimited(),
                )
                .unwrap()
                .0,
                None
            );
        }
        assert_eq!(
            plan.find_window(
                &dense,
                Window::new(seam, BUFFER_BYTES),
                PackedLiteralSetSearchLimits::unlimited(),
            )
            .unwrap()
            .0,
            Some((match_start, BUFFER_BYTES))
        );
        assert_eq!(
            plan.find_window(
                &dense,
                Window::new(seam, BUFFER_BYTES - 1),
                PackedLiteralSetSearchLimits::unlimited(),
            )
            .unwrap()
            .0,
            None
        );
    }

    #[test]
    fn long_shared_fragment_dispatch_budgets_fit_the_incumbent_envelope() {
        for family in public_long_fragment_families() {
            let fragment = select_shared_fragment(family.patterns, 1)
                .unwrap_or_else(|| panic!("{} lost its shared fragment", family.id));
            assert!(fragment.width >= LONG_SHARED_FRAGMENT_RECEIPT_MIN_BYTES);
            assert!(fragment.dispatch_parts().is_some());
            assert_eq!(
                fragment.maximum_candidate_verification_work,
                family.maximum_candidate_verification_work,
                "{}",
                family.id,
            );
            let dispatch_work = fragment.maximum_dispatch_candidate_verification_work();
            assert_eq!(
                dispatch_work,
                family.maximum_dispatch_candidate_verification_work,
                "{}",
                family.id,
            );
            let candidate_budget = fragment.dispatch_candidate_budget();
            assert_eq!(
                candidate_budget, family.dispatch_candidate_budget,
                "{}",
                family.id,
            );
            assert!(candidate_budget > NATIVE_FILTER_CANDIDATE_BUDGET);
            let incumbent_envelope = fragment
                .maximum_candidate_verification_work
                .checked_mul(NATIVE_FILTER_CANDIDATE_BUDGET)
                .unwrap();
            assert!(
                dispatch_work.checked_mul(candidate_budget).unwrap() <= incumbent_envelope,
                "{}",
                family.id,
            );
            assert!(
                dispatch_work
                    .checked_mul(candidate_budget.checked_add(1).unwrap())
                    .unwrap()
                    > incumbent_envelope,
                "{}",
                family.id,
            );

            let Some(plan) = plan(family.patterns) else {
                return;
            };
            let receipt = plan
                .long_shared_fragment_build_receipt()
                .unwrap_or_else(|| panic!("{} lost its public route receipt", family.id));
            assert_eq!(
                receipt.maximum_candidate_verification_work,
                family.maximum_candidate_verification_work,
                "{}",
                family.id,
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one proof covers every public sparse family and the bounded fallback seam"
    )]
    fn long_shared_fragment_dispatch_covers_eight_64k_candidates_and_fallback_seams() {
        const BUFFER_BYTES: usize = 64 * 1024;
        const CANDIDATES: usize = 8;
        const FIRST_START: usize = 1_024;
        const CANDIDATE_GAP: usize = 8_000;

        for family in public_long_fragment_families().into_iter().take(5) {
            let Some(plan) = plan(family.patterns) else {
                return;
            };
            let PackedLiteralEngine::NativeSharedFragment {
                searcher,
                shared_fragment,
            } = &plan.engine
            else {
                panic!("{} lost its long shared-fragment route", family.id)
            };
            assert!(shared_fragment.dispatch_candidate_budget() >= CANDIDATES);

            let starts = core::array::from_fn::<_, CANDIDATES, _>(|index| {
                FIRST_START
                    .checked_add(index.checked_mul(CANDIDATE_GAP).unwrap())
                    .unwrap()
            });
            let mut exhausted = vec![b'.'; BUFFER_BYTES];
            for start in starts {
                let end = start.checked_add(family.decoy.len()).unwrap();
                exhausted[start..end].copy_from_slice(family.decoy);
            }
            assert_eq!(
                find_bounded_long_shared_fragment(shared_fragment, &exhausted),
                Some(LongSharedFragmentFilterResult::Exhausted),
                "{}",
                family.id,
            );
            assert_eq!(
                plan.find(&exhausted, PackedLiteralSetSearchLimits::unlimited())
                    .unwrap()
                    .0,
                searcher
                    .find(&exhausted)
                    .map(|matched| (matched.start(), matched.end())),
                "{}",
                family.id,
            );

            let mut hit = vec![b'.'; BUFFER_BYTES];
            for start in starts[..CANDIDATES - 1].iter().copied() {
                let end = start.checked_add(family.decoy.len()).unwrap();
                hit[start..end].copy_from_slice(family.decoy);
            }
            let hit_start = starts[CANDIDATES - 1];
            let hit_end = hit_start.checked_add(family.hit.len()).unwrap();
            hit[hit_start..hit_end].copy_from_slice(family.hit);
            assert_eq!(
                find_bounded_long_shared_fragment(shared_fragment, &hit),
                Some(LongSharedFragmentFilterResult::Match {
                    start: hit_start,
                    end: hit_end,
                }),
                "{}",
                family.id,
            );
            assert_eq!(
                plan.find(&hit, PackedLiteralSetSearchLimits::unlimited())
                    .unwrap()
                    .0,
                searcher
                    .find(&hit)
                    .map(|matched| (matched.start(), matched.end())),
                "{}",
                family.id,
            );
            assert_search_certificate(
                &plan,
                false,
                &hit,
                Window::full(&hit),
                Some((hit_start, hit_end)),
            );
            assert_invalid_windows_precede_work(&plan, &hit);
        }

        let family = public_long_fragment_families()[0];
        let Some(plan) = plan(family.patterns) else {
            return;
        };
        let PackedLiteralEngine::NativeSharedFragment {
            searcher,
            shared_fragment,
        } = &plan.engine
        else {
            panic!("fallback family lost its long shared-fragment route")
        };
        let candidate_budget = shared_fragment.dispatch_candidate_budget();
        let fallback_gap = 4_096_usize;
        let fallback_first = 512_usize;
        let mut fallback = vec![b'.'; BUFFER_BYTES];
        for index in 0..candidate_budget {
            let start = fallback_first
                .checked_add(index.checked_mul(fallback_gap).unwrap())
                .unwrap();
            let end = start.checked_add(family.decoy.len()).unwrap();
            fallback[start..end].copy_from_slice(family.decoy);
        }
        let last_verified_start = fallback_first
            .checked_add(
                candidate_budget
                    .checked_sub(1)
                    .unwrap()
                    .checked_mul(fallback_gap)
                    .unwrap(),
            )
            .unwrap();
        let fallback_match_start = fallback_first
            .checked_add(candidate_budget.checked_mul(fallback_gap).unwrap())
            .unwrap();
        let fallback_match_end = fallback_match_start.checked_add(family.hit.len()).unwrap();
        fallback[fallback_match_start..fallback_match_end].copy_from_slice(family.hit);
        assert_eq!(
            find_bounded_long_shared_fragment(shared_fragment, &fallback),
            Some(LongSharedFragmentFilterResult::ResumeAt(fallback_match_start)),
        );
        assert!(fallback_match_start > last_verified_start.checked_add(1).unwrap());
        let expected = searcher
            .find(&fallback)
            .map(|matched| (matched.start(), matched.end()));
        assert_eq!(expected, Some((fallback_match_start, fallback_match_end)));
        assert_eq!(
            plan.find(&fallback, PackedLiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            expected,
        );
    }

    #[test]
    fn zero_offset_empty_dispatch_exhausts_and_finds_late_matches() {
        for family_index in [0_usize, 2] {
            let family = public_long_fragment_families()[family_index];
            let Some(plan) = plan(family.patterns) else {
                return;
            };
            let PackedLiteralEngine::NativeSharedFragment {
                searcher,
                shared_fragment,
            } = &plan.engine
            else {
                panic!("{} lost its long shared-fragment route", family.id)
            };
            assert_eq!(shared_fragment.offset, 0, "{}", family.id);
            let candidates = shared_fragment
                .dispatch_candidate_budget()
                .checked_mul(4)
                .unwrap();
            let gap = shared_fragment
                .width
                .checked_mul(2)
                .unwrap()
                .checked_add(1)
                .unwrap();
            let first_start = shared_fragment.native_prefix_bytes.checked_add(64).unwrap();
            let hit_start = first_start
                .checked_add(candidates.checked_mul(gap).unwrap())
                .unwrap();
            let hit_end = hit_start.checked_add(family.hit.len()).unwrap();
            let mut absent = vec![b'.'; hit_end.checked_add(64).unwrap()];
            for index in 0..candidates {
                let start = first_start
                    .checked_add(index.checked_mul(gap).unwrap())
                    .unwrap();
                let end = start.checked_add(family.decoy.len()).unwrap();
                absent[start..end].copy_from_slice(family.decoy);
            }
            assert_eq!(
                find_selected_bounded_long_shared_fragment(shared_fragment, &absent),
                Some(LongSharedFragmentFilterResult::Exhausted),
                "{}",
                family.id,
            );

            let mut hit = absent;
            hit[hit_start..hit_end].copy_from_slice(family.hit);
            assert_eq!(
                find_selected_bounded_long_shared_fragment(shared_fragment, &hit),
                Some(LongSharedFragmentFilterResult::Match {
                    start: hit_start,
                    end: hit_end,
                }),
                "{}",
                family.id,
            );
            let expected = searcher
                .find(&hit)
                .map(|matched| (matched.start(), matched.end()));
            assert_eq!(expected, Some((hit_start, hit_end)), "{}", family.id);
            assert_eq!(
                plan.find(&hit, PackedLiteralSetSearchLimits::unlimited())
                    .unwrap()
                    .0,
                expected,
                "{}",
                family.id,
            );
        }
    }

    #[test]
    fn nonzero_offset_empty_dispatch_keeps_incumbent_budget() {
        for family_index in [1_usize, 3, 4] {
            let family = public_long_fragment_families()[family_index];
            let Some(plan) = plan(family.patterns) else {
                return;
            };
            let PackedLiteralEngine::NativeSharedFragment {
                searcher,
                shared_fragment,
            } = &plan.engine
            else {
                panic!("{} lost its long shared-fragment route", family.id)
            };
            assert_ne!(shared_fragment.offset, 0, "{}", family.id);
            let candidate_budget = shared_fragment.dispatch_candidate_budget();
            let gap = shared_fragment
                .width
                .checked_mul(2)
                .unwrap()
                .checked_add(17)
                .unwrap();
            let first_start = shared_fragment.native_prefix_bytes.checked_add(64).unwrap();
            let hit_start = first_start
                .checked_add(candidate_budget.checked_mul(gap).unwrap())
                .unwrap();
            let hit_end = hit_start.checked_add(family.hit.len()).unwrap();
            let mut haystack = vec![b'.'; hit_end.checked_add(64).unwrap()];
            for index in 0..candidate_budget {
                let start = first_start
                    .checked_add(index.checked_mul(gap).unwrap())
                    .unwrap();
                let end = start.checked_add(family.decoy.len()).unwrap();
                haystack[start..end].copy_from_slice(family.decoy);
            }
            haystack[hit_start..hit_end].copy_from_slice(family.hit);
            let incumbent = find_bounded_long_shared_fragment(shared_fragment, &haystack);
            assert_eq!(
                incumbent,
                Some(LongSharedFragmentFilterResult::ResumeAt(hit_start)),
                "{}",
                family.id,
            );
            assert_eq!(
                find_selected_bounded_long_shared_fragment(shared_fragment, &haystack),
                incumbent,
                "{}",
                family.id,
            );
            let expected = searcher
                .find(&haystack)
                .map(|matched| (matched.start(), matched.end()));
            assert_eq!(expected, Some((hit_start, hit_end)), "{}", family.id);
        }
    }

    #[test]
    fn zero_offset_empty_dispatch_keeps_dense_and_nonempty_budget_seams() {
        let family = public_long_fragment_families()[0];
        let Some(plan) = plan(family.patterns) else {
            return;
        };
        let PackedLiteralEngine::NativeSharedFragment {
            searcher,
            shared_fragment,
        } = &plan.engine
        else {
            panic!("prefix family lost its long shared-fragment route")
        };
        assert_eq!(shared_fragment.offset, 0);
        let first_start = shared_fragment.native_prefix_bytes.checked_add(64).unwrap();
        let dense_gap = shared_fragment.width.checked_add(1).unwrap();
        let dense_fallback = first_start
            .checked_add(
                NATIVE_FILTER_CANDIDATE_BUDGET
                    .checked_mul(dense_gap)
                    .unwrap(),
            )
            .unwrap();
        let mut dense = vec![b'.'; dense_fallback.checked_add(64).unwrap()];
        for index in 0_usize..6 {
            let start = first_start
                .checked_add(index.checked_mul(dense_gap).unwrap())
                .unwrap();
            let end = start.checked_add(family.decoy.len()).unwrap();
            dense[start..end].copy_from_slice(family.decoy);
        }
        assert_eq!(
            find_selected_bounded_long_shared_fragment(shared_fragment, &dense),
            Some(LongSharedFragmentFilterResult::ResumeAt(dense_fallback)),
        );

        let candidate_budget = shared_fragment.dispatch_candidate_budget();
        let sparse_gap = shared_fragment
            .width
            .checked_mul(2)
            .unwrap()
            .checked_add(1)
            .unwrap();
        let hit_index = candidate_budget
            .checked_mul(2)
            .unwrap()
            .checked_add(3)
            .unwrap();
        let hit_start = first_start
            .checked_add(hit_index.checked_mul(sparse_gap).unwrap())
            .unwrap();
        let hit_end = hit_start.checked_add(family.hit.len()).unwrap();
        let mut mixed = vec![b'.'; hit_end.checked_add(64).unwrap()];
        for index in 0..candidate_budget {
            let empty_start = first_start
                .checked_add(
                    index
                        .checked_mul(2)
                        .unwrap()
                        .checked_mul(sparse_gap)
                        .unwrap(),
                )
                .unwrap();
            let empty_end = empty_start.checked_add(family.decoy.len()).unwrap();
            mixed[empty_start..empty_end].copy_from_slice(family.decoy);
            let nonempty_start = empty_start.checked_add(sparse_gap).unwrap();
            let nonempty_end = nonempty_start.checked_add(b"longpref1x".len()).unwrap();
            mixed[nonempty_start..nonempty_end].copy_from_slice(b"longpref1x");
        }
        for index in candidate_budget.checked_mul(2).unwrap()..hit_index {
            let start = first_start
                .checked_add(index.checked_mul(sparse_gap).unwrap())
                .unwrap();
            let end = start.checked_add(family.decoy.len()).unwrap();
            mixed[start..end].copy_from_slice(family.decoy);
        }
        mixed[hit_start..hit_end].copy_from_slice(family.hit);
        assert_eq!(
            find_selected_bounded_long_shared_fragment(shared_fragment, &mixed),
            Some(LongSharedFragmentFilterResult::ResumeAt(hit_start)),
        );
        let expected = searcher
            .find(&mixed)
            .map(|matched| (matched.start(), matched.end()));
        assert_eq!(expected, Some((hit_start, hit_end)));
        assert_eq!(
            plan.find(&mixed, PackedLiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            expected,
        );
    }

    #[test]
    fn long_shared_fragment_dispatch_keeps_dense_64k_fallback() {
        let family = public_long_fragment_families()[5];
        let Some(plan) = plan(family.patterns) else {
            return;
        };
        let PackedLiteralEngine::NativeSharedFragment {
            searcher,
            shared_fragment,
        } = &plan.engine
        else {
            panic!("saturated public family lost its long shared-fragment route")
        };
        assert_eq!(
            shared_fragment.dispatch_candidate_budget(),
            family.dispatch_candidate_budget,
        );
        let saturated = vec![b'a'; 64 * 1024];
        assert_eq!(
            find_bounded_long_shared_fragment(shared_fragment, &saturated),
            Some(LongSharedFragmentFilterResult::ResumeAt(1)),
        );
        assert_eq!(
            plan.find(&saturated, PackedLiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            searcher
                .find(&saturated)
                .map(|matched| (matched.start(), matched.end())),
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one proof covers dense-gap containment and both exact budget seams"
    )]
    fn long_shared_fragment_dispatch_bounds_each_dense_gap_and_exact_budget_seam() {
        let patterns = [
            b"longprefA".as_slice(),
            b"longprefB".as_slice(),
            b"longprefC".as_slice(),
            b"longprefD".as_slice(),
            b"longprefE".as_slice(),
            b"longprefF".as_slice(),
            b"longprefG".as_slice(),
            b"longprefH".as_slice(),
            b"longprefI".as_slice(),
            b"longprefJ".as_slice(),
            b"longprefK".as_slice(),
            b"longprefL".as_slice(),
            b"longprefM".as_slice(),
            b"longprefN".as_slice(),
            b"longprefOZ".as_slice(),
        ];
        let Some(plan) = plan(&patterns) else {
            return;
        };
        let PackedLiteralEngine::NativeSharedFragment {
            searcher,
            shared_fragment,
        } = &plan.engine
        else {
            panic!("budget-corner language lost its long shared-fragment route")
        };
        assert_eq!(shared_fragment.offset, 0);
        assert_eq!(shared_fragment.width, 8);
        assert_eq!(shared_fragment.maximum_candidate_verification_work, 31);
        assert_eq!(
            shared_fragment.maximum_dispatch_candidate_verification_work(),
            2,
        );
        assert_eq!(shared_fragment.dispatch_candidate_budget(), 62);

        let first_start = shared_fragment.native_prefix_bytes.checked_add(64).unwrap();
        for gap in [8_usize, 9, 10, 16] {
            let mut haystack = vec![
                b'.';
                first_start
                    .checked_add(6_usize.checked_mul(gap).unwrap())
                    .unwrap()
                    .checked_add(64)
                    .unwrap()
            ];
            for index in 0_usize..6 {
                let start = first_start
                    .checked_add(index.checked_mul(gap).unwrap())
                    .unwrap();
                haystack[start..start + 8].copy_from_slice(b"longpref");
            }
            assert_eq!(
                find_bounded_long_shared_fragment(shared_fragment, &haystack),
                Some(LongSharedFragmentFilterResult::ResumeAt(
                    first_start
                        .checked_add(4_usize.checked_mul(gap).unwrap())
                        .unwrap(),
                )),
                "gap={gap}",
            );
            assert_eq!(
                plan.find(&haystack, PackedLiteralSetSearchLimits::unlimited())
                    .unwrap()
                    .0,
                searcher
                    .find(&haystack)
                    .map(|matched| (matched.start(), matched.end())),
                "gap={gap}",
            );
        }

        let mut dense_tail = vec![b'.'; first_start.checked_add(128).unwrap()];
        for offset in [0_usize, 17, 25, 33, 41, 49] {
            let start = first_start.checked_add(offset).unwrap();
            dense_tail[start..start + 8].copy_from_slice(b"longpref");
        }
        assert_eq!(
            find_bounded_long_shared_fragment(shared_fragment, &dense_tail),
            Some(LongSharedFragmentFilterResult::ResumeAt(
                first_start.checked_add(41).unwrap(),
            )),
        );

        // Admit the first guarded candidate on a sparse gap, then preserve a
        // real match at the next, dense gap for the unchanged native fallback.
        // This distinguishes the adjacent-gap guard from a one-shot decision
        // and proves that resumption includes the unverified candidate itself.
        let late_dense_match_start = first_start.checked_add(84).unwrap();
        let late_dense_match_end = late_dense_match_start.checked_add(10).unwrap();
        let mut late_dense_match = vec![b'.'; late_dense_match_end.checked_add(64).unwrap()];
        for offset in [0_usize, 17, 34, 51, 68] {
            let start = first_start.checked_add(offset).unwrap();
            late_dense_match[start..start + 10].copy_from_slice(b"longprefOx");
        }
        late_dense_match[late_dense_match_start..late_dense_match_end]
            .copy_from_slice(b"longprefOZ");
        assert_eq!(
            find_bounded_long_shared_fragment(shared_fragment, &late_dense_match),
            Some(LongSharedFragmentFilterResult::ResumeAt(
                late_dense_match_start,
            )),
        );
        let expected = searcher
            .find(&late_dense_match)
            .map(|matched| (matched.start(), matched.end()));
        assert_eq!(expected, Some((late_dense_match_start, late_dense_match_end)));
        assert_eq!(
            plan.find(
                &late_dense_match,
                PackedLiteralSetSearchLimits::unlimited(),
            )
            .unwrap()
            .0,
            expected,
        );

        let sparse_gap = 4_096_usize;
        let sparse_tail_starts = [
            first_start,
            first_start.checked_add(8).unwrap(),
            first_start.checked_add(8 + sparse_gap).unwrap(),
            first_start.checked_add(8 + 2 * sparse_gap).unwrap(),
            first_start.checked_add(8 + 3 * sparse_gap).unwrap(),
            first_start.checked_add(8 + 4 * sparse_gap).unwrap(),
        ];
        let mut sparse_tail = vec![
            b'.';
            sparse_tail_starts[5].checked_add(64).unwrap()
        ];
        for start in sparse_tail_starts {
            sparse_tail[start..start + 8].copy_from_slice(b"longpref");
        }
        assert_eq!(
            find_bounded_long_shared_fragment(shared_fragment, &sparse_tail),
            Some(LongSharedFragmentFilterResult::Exhausted),
        );

        const EXACT_CANDIDATES: usize = 63;
        const EXACT_GAP: usize = 17;
        let exact_last_start = first_start
            .checked_add(
                EXACT_CANDIDATES
                    .checked_sub(1)
                    .unwrap()
                    .checked_mul(EXACT_GAP)
                    .unwrap(),
            )
            .unwrap();
        let mut exact_false = vec![b'.'; exact_last_start.checked_add(64).unwrap()];
        for index in 0..EXACT_CANDIDATES {
            let start = first_start
                .checked_add(index.checked_mul(EXACT_GAP).unwrap())
                .unwrap();
            exact_false[start..start + 10].copy_from_slice(b"longprefOx");
        }
        assert_eq!(
            find_bounded_long_shared_fragment(shared_fragment, &exact_false),
            Some(LongSharedFragmentFilterResult::ResumeAt(exact_last_start)),
        );

        let direct_match_start = first_start
            .checked_add(61_usize.checked_mul(EXACT_GAP).unwrap())
            .unwrap();
        let direct_match_end = direct_match_start.checked_add(10).unwrap();
        let mut direct_match = exact_false.clone();
        direct_match[direct_match_start..direct_match_end].copy_from_slice(b"longprefOZ");
        assert_eq!(
            find_bounded_long_shared_fragment(shared_fragment, &direct_match),
            Some(LongSharedFragmentFilterResult::Match {
                start: direct_match_start,
                end: direct_match_end,
            }),
        );
        let expected = searcher
            .find(&direct_match)
            .map(|matched| (matched.start(), matched.end()));
        assert_eq!(expected, Some((direct_match_start, direct_match_end)));
        assert_eq!(
            plan.find(
                &direct_match,
                PackedLiteralSetSearchLimits::unlimited(),
            )
            .unwrap()
            .0,
            expected,
        );

        let mut fallback_match = exact_false;
        let fallback_match_end = exact_last_start.checked_add(10).unwrap();
        fallback_match[exact_last_start..fallback_match_end].copy_from_slice(b"longprefOZ");
        assert_eq!(
            find_bounded_long_shared_fragment(shared_fragment, &fallback_match),
            Some(LongSharedFragmentFilterResult::ResumeAt(exact_last_start)),
        );
        let expected = searcher
            .find(&fallback_match)
            .map(|matched| (matched.start(), matched.end()));
        assert_eq!(expected, Some((exact_last_start, fallback_match_end)));
        assert_eq!(
            plan.find(
                &fallback_match,
                PackedLiteralSetSearchLimits::unlimited(),
            )
            .unwrap()
            .0,
            expected,
        );
    }

    #[test]
    fn shared_fragment_dispatch_allocation_failure_keeps_incumbent_fallback() {
        let patterns = [
            b"longpref0".as_slice(),
            b"longpref11".as_slice(),
            b"longpref222".as_slice(),
            b"longpref3333".as_slice(),
        ];
        let _failure = shared_fragment_dispatch_allocation_probe::fail_next();
        let Some(plan) = plan(&patterns) else {
            return;
        };
        let PackedLiteralEngine::NativeSharedFragment {
            searcher,
            shared_fragment,
        } = &plan.engine
        else {
            panic!("dispatch allocation failure changed the incumbent engine")
        };
        assert!(shared_fragment.dispatch_parts().is_none());
        assert_eq!(
            shared_fragment.maximum_dispatch_candidate_verification_work(),
            0,
        );
        assert_eq!(
            shared_fragment.dispatch_candidate_budget(),
            NATIVE_FILTER_CANDIDATE_BUDGET,
        );
        let first_start = shared_fragment.native_prefix_bytes.checked_add(64).unwrap();
        let gap = shared_fragment
            .width
            .checked_mul(2)
            .unwrap()
            .checked_add(17)
            .unwrap();
        let hit_start = first_start
            .checked_add(8_usize.checked_mul(gap).unwrap())
            .unwrap();
        let hit_end = hit_start.checked_add(b"longpref3333".len()).unwrap();
        let mut gated = vec![b'.'; hit_end.checked_add(64).unwrap()];
        for index in 0_usize..8 {
            let start = first_start
                .checked_add(index.checked_mul(gap).unwrap())
                .unwrap();
            let end = start.checked_add(b"longprefx".len()).unwrap();
            gated[start..end].copy_from_slice(b"longprefx");
        }
        gated[hit_start..hit_end].copy_from_slice(b"longpref3333");
        assert_eq!(
            find_selected_bounded_long_shared_fragment(shared_fragment, &gated),
            find_bounded_long_shared_fragment(shared_fragment, &gated),
        );
        for haystack in [
            b"longprefx..longpref3333".as_slice(),
            b"no shared fragment here".as_slice(),
            b"longpref".as_slice(),
        ] {
            let expected = searcher
                .find(haystack)
                .map(|matched| (matched.start(), matched.end()));
            assert_eq!(
                plan.find(haystack, PackedLiteralSetSearchLimits::unlimited())
                    .unwrap()
                    .0,
                expected
            );
        }
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
        let (dispatch_offset, _, group_ends) = shared_fragment.dispatch_parts().unwrap();
        assert_eq!(dispatch_offset, 8);
        assert_eq!(group_ends.len(), 256 * core::mem::size_of::<u16>());
        assert!(shared_fragment_dispatch_group(shared_fragment, b'x').is_empty());
        assert_eq!(shared_fragment.verify_at(b"longprefx", 0), None);
        for pattern in patterns {
            assert_eq!(shared_fragment.verify_at(pattern, 0), Some(pattern.len()));
        }
        assert_eq!(
            plan.long_shared_fragment_build_receipt(),
            Some(PackedLiteralSetLongSharedFragmentBuildReceipt {
                capability_id: LONG_SHARED_FRAGMENT_BUILD_CAPABILITY_ID,
                fragment_offset: shared_fragment.offset,
                fragment_bytes: shared_fragment.width,
                minimum_pattern_bytes: shared_fragment.minimum_pattern_width(),
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
    #[allow(
        clippy::too_many_lines,
        reason = "one test closes coupled cost, persistence, downgrade, and refusal boundaries"
    )]
    fn native_shared_fragment_cost_and_persistence_are_bounded() {
        assert_eq!(
            core::mem::size_of::<super::SharedFragment>(),
            core::mem::size_of::<E030SharedFragmentLayout>(),
        );
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
        let (dispatch_offset, _, group_ends) = fragment.dispatch_parts().unwrap();
        assert_eq!(dispatch_offset, 2);
        assert!(
            fragment.maximum_dispatch_candidate_verification_work()
                <= fragment.maximum_candidate_verification_work
        );
        assert!(fragment.dispatch_candidate_budget() > NATIVE_FILTER_CANDIDATE_BUDGET);
        assert_eq!(
            group_ends.len(),
            super::SHARED_FRAGMENT_DISPATCH_TABLE_BYTES
        );
        let encoded_pattern_bytes = patterns
            .iter()
            .map(|pattern| {
                pattern
                    .len()
                    .checked_add(core::mem::size_of::<u16>())
                    .unwrap()
            })
            .sum::<usize>();
        assert_eq!(
            fragment.patterns.len(),
            encoded_pattern_bytes
                .checked_add(super::SHARED_FRAGMENT_DISPATCH_TABLE_BYTES)
                .unwrap()
        );
        let exact_sidecar_bytes = core::mem::size_of::<super::SharedFragment>()
            .checked_add(fragment.patterns.len())
            .and_then(|bytes| bytes.checked_add(fragment.width))
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
        let incumbent_persistent = persistent
            .checked_sub(super::SHARED_FRAGMENT_DISPATCH_TABLE_BYTES)
            .unwrap();
        shared_fragment_dispatch_selection_probe::reset();
        let downgraded = PackedLiteralSetPlan::new(
            &patterns,
            PackedLiteralSetBuildLimits {
                max_persistent_bytes: persistent - 1,
                ..PackedLiteralSetBuildLimits::default()
            },
        )
        .unwrap();
        let PackedLiteralEngine::NativeSharedFragment {
            shared_fragment: downgraded_fragment,
            ..
        } = &downgraded.engine
        else {
            panic!("tight cap did not retain the incumbent shared-fragment plan")
        };
        assert!(downgraded_fragment.dispatch_parts().is_none());
        assert_eq!(
            downgraded_fragment.maximum_dispatch_candidate_verification_work(),
            0,
        );
        assert_eq!(
            downgraded_fragment.dispatch_candidate_budget(),
            NATIVE_FILTER_CANDIDATE_BUDGET,
        );
        assert_eq!(
            downgraded.build_accounting().persistent_bytes,
            incumbent_persistent
        );
        assert_eq!(shared_fragment_dispatch_selection_probe::calls(), 0);
        shared_fragment_dispatch_selection_probe::reset();
        assert_eq!(
            PackedLiteralSetPlan::new(
                &patterns,
                PackedLiteralSetBuildLimits {
                    max_persistent_bytes: incumbent_persistent,
                    ..PackedLiteralSetBuildLimits::default()
                },
            )
            .unwrap()
            .build_accounting()
            .persistent_bytes,
            incumbent_persistent
        );
        assert_eq!(shared_fragment_dispatch_selection_probe::calls(), 0);
        assert!(matches!(
            PackedLiteralSetPlan::new(
                &patterns,
                PackedLiteralSetBuildLimits {
                    max_persistent_bytes: incumbent_persistent - 1,
                    ..PackedLiteralSetBuildLimits::default()
                },
            ),
            Err(PackedLiteralSetError::PersistentBytesLimit { needed, limit })
                if needed == incumbent_persistent && limit == incumbent_persistent - 1
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
        assert_eq!((shared_fragment.offset, shared_fragment.width), (1, 2));
        let dispatch_offset = shared_fragment
            .dispatch_parts()
            .expect("interior shared fragment lost its outside-byte dispatch")
            .0;
        assert!(!(1..3).contains(&dispatch_offset));
        assert!(shared_fragment_dispatch_group(shared_fragment, b'!').is_empty());
        assert_eq!(shared_fragment.verify_at(b"!QRx", 0), None);
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
    fn ordinary_executor_native_span_loop_preserves_windows_and_count() {
        let patterns = [b"ab".as_slice(), b"a".as_slice(), b"ba".as_slice()];
        let Some(plan) = plan(&patterns) else {
            return;
        };
        let ordinary = plan.ordinary_executor();
        let haystack = b"zababaq";
        for (window, expected) in [
            (Window::full(haystack), &[(1, 3), (3, 5), (5, 6)][..]),
            (Window::new(2, 6), &[(2, 4), (4, 6)][..]),
        ] {
            let mut actual = Vec::new();
            ordinary
                .try_visit_spans_window_value(haystack, window, |matched| {
                    actual.push(matched);
                    Ok::<bool, ()>(true)
                })
                .unwrap()
                .unwrap();
            assert_eq!(actual, expected, "window={window:?}");
            assert_eq!(
                ordinary.count_spans_window_value(haystack, window),
                Ok(u64::try_from(expected.len()).unwrap()),
            );
        }

        let dense = [b'a'; 257];
        let dense_window = Window::new(7, 250);
        assert_eq!(
            ordinary.count_spans_window_value(&dense, dense_window),
            Ok(u64::try_from(dense_window.end() - dense_window.start()).unwrap()),
        );
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

        let invalid_start = haystack.len().checked_add(1).unwrap();
        let invalid_error = PackedLiteralSetError::InvalidWindow {
            start: invalid_start,
            end: haystack.len(),
            haystack_len: haystack.len(),
        };
        let mut invalid_unmetered = plan.search_cursor(&haystack).unwrap();
        let mut invalid_checked = plan.search_cursor(&haystack).unwrap();
        for start in [0, 8] {
            let unmetered_match = invalid_unmetered
                .find_at_value_unmetered(start)
                .unwrap();
            let checked_match = invalid_checked
                .find_at(start, PackedLiteralSetSearchLimits::unlimited())
                .unwrap()
                .0;
            assert_eq!(unmetered_match, checked_match);
        }
        assert!(invalid_unmetered.dense);
        assert_eq!(
            invalid_unmetered.find_at_value_unmetered(invalid_start),
            Err(invalid_error.clone()),
        );
        assert_eq!(
            invalid_checked.find_at_value(
                invalid_start,
                PackedLiteralSetSearchLimits::unlimited(),
            ),
            Err(invalid_error),
        );
        assert_eq!(
            invalid_unmetered.find_at_value_unmetered(80),
            Ok(Some((80, 88))),
        );
        assert_eq!(
            invalid_checked
                .find_at_value(80, PackedLiteralSetSearchLimits::unlimited()),
            Ok(Some((80, 88))),
        );
        assert_eq!(invalid_unmetered.close_matches, 1);
        assert!(!invalid_unmetered.dense);
        assert_eq!(
            invalid_checked.close_matches,
            invalid_unmetered.close_matches,
        );
        assert_eq!(invalid_checked.dense, invalid_unmetered.dense);

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
    fn retained_iterator_density_gap_boundary_preserves_checked_state() {
        let width = 8;
        let patterns = [b"agggtaaa".as_slice(), b"tttaccct".as_slice()];
        let dense_gap = super::RETAINED_ITER_DENSE_GAP_BYTES;
        assert_eq!(dense_gap, 16);
        for gap in [dense_gap - 1, dense_gap, dense_gap + 1] {
            let first = (gap, gap + width);
            let second = (first.1 + gap, first.1 + gap + width);
            let third = (second.1, second.1 + width);
            let mut haystack = vec![0xff; third.1 + 40];
            for matched in [first, second, third] {
                haystack[matched.0..matched.1].copy_from_slice(patterns[0]);
            }
            let plan = PackedLiteralSetPlan::new_retained_iter(
                &patterns,
                PackedLiteralSetBuildLimits::default(),
                usize::MAX,
            )
            .unwrap();
            let mut unmetered = plan.search_cursor(&haystack).unwrap();
            let mut checked = plan.search_cursor(&haystack).unwrap();

            for (request, expected) in [(0, first), (first.1, second)] {
                let unmetered_match = unmetered.find_at_value_unmetered(request).unwrap();
                let checked_match = checked
                    .find_at(request, PackedLiteralSetSearchLimits::unlimited())
                    .unwrap()
                    .0;
                assert_eq!(unmetered_match, Some(expected));
                assert_eq!(checked_match, unmetered_match);
                assert_eq!(checked.close_matches, unmetered.close_matches);
                assert_eq!(checked.dense, unmetered.dense);
                if request == 0 {
                    assert_eq!(unmetered.close_matches, u8::from(gap <= dense_gap));
                    assert!(!unmetered.dense);
                }
            }
            if gap <= dense_gap {
                assert_eq!(unmetered.close_matches, 2);
                assert!(unmetered.dense);
            } else {
                assert_eq!(unmetered.close_matches, 0);
                assert!(!unmetered.dense);
            }

            let unmetered_match = unmetered.find_at_value_unmetered(second.1).unwrap();
            let checked_match = checked
                .find_at(second.1, PackedLiteralSetSearchLimits::unlimited())
                .unwrap()
                .0;
            assert_eq!(unmetered_match, Some(third));
            assert_eq!(checked_match, unmetered_match);
            assert_eq!(checked.close_matches, unmetered.close_matches);
            assert_eq!(checked.dense, unmetered.dense);
            assert_eq!(unmetered.dense, gap <= dense_gap);
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
