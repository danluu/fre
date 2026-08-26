//! Complete-column search for finite ASCII words between word boundaries.
//!
//! Guarded finite extraction has already proved that every nonempty source
//! path is an ASCII-word byte string with a left word-start boundary and a
//! right word-end boundary. A match is therefore exactly one complete maximal
//! ASCII word. The established route selects a fixed word column whose byte
//! set fits a native one-to-three-byte scan. Languages without such a sparse
//! column can retain an exact ASCII byte-set classifier, full-byte nonmember
//! scanner, and one admitted packed-literal probe. A fixed-width sparse route
//! may retain the same exact packed owner, but enters it only after complete
//! rejected words have accumulated one native service quantum of dictionary
//! work. Fixed-width languages may additionally retain exact pattern-identity
//! columns for dense candidate streams. Every route either intersects all
//! fixed columns or authenticates the complete maximal word in the
//! source-order dictionary. In particular, `a|ab` on `ab` cannot be lost:
//! lookup is performed on the complete word `ab`.

use core::fmt;
use core::mem::size_of;

use memchr::{memchr, memchr2, memchr3};

use fre_kernels::{
    ASCII_CLASSIFIER_BUILD_WORK, ASCII_NARROW_BYTES, ASCII_RUN_SCANNER_BUILD_WORK,
    ASCII_WIDE_BYTES, AsciiByteSet, AsciiByteSetClassifier, AsciiByteSetRunScanner,
    DispatchPolicy,
    PACKED_LITERAL_SET_CERTIFIED_MAX_PATTERNS, PackedLiteralSetBuildLimits,
    PackedLiteralSetError, PackedLiteralSetPlan, PackedLiteralSetSearchLimits,
    SimdDispatchContext, VectorKind, Window as PackedWindow, classify_byte_delta_16,
    packed_literal_anchor_frequency_rank,
    packed_literal_set_build_work_upper_bound_from_dimensions,
};
#[cfg(target_arch = "aarch64")]
use fre_kernels::{ASCII_NONMEMBER_RUN_SCANNER_BUILD_WORK, AsciiByteSetNonMemberScanner};

use crate::{
    Match, SearchLimits, SearchWindow, finite,
    guarded_ascii_word::{
        BuildLimits as DictionaryBuildLimits, Dictionary, LookupActual,
        ReduceError as DictionaryReduceError, ReduceErrorKind as DictionaryReduceErrorKind,
    },
};

/// Stable identity for the guarded fixed-column/dictionary composition.
pub(crate) const PLAN_ID: &str = "guarded-ascii-word-literal-set.fixed-column-dictionary.v4";
pub(crate) const FIXED_PACKED_PLAN_ID: &str =
    "guarded-ascii-word-literal-set.fixed-column-packed-hybrid.v1";
pub(crate) const ONE_BYTE_PLAN_ID: &str =
    "guarded-ascii-word-literal-set.one-byte-boundary-mask.v1";
pub(crate) const WIDE_PACKED_PLAN_ID: &str =
    "guarded-ascii-word-literal-set.wide-column-packed-dictionary.v1";

#[cfg(test)]
pub(crate) mod value_path_probe {
    use core::cell::Cell;

    std::thread_local! {
        static FIND_CALLS: Cell<usize> = const { Cell::new(0) };
    }

    pub(crate) fn reset() {
        FIND_CALLS.set(0);
    }

    pub(crate) fn calls() -> usize {
        FIND_CALLS.get()
    }

    pub(super) fn record_find() {
        FIND_CALLS.set(FIND_CALLS.get().saturating_add(1));
    }
}

/// Source-independent ceiling closed before the first haystack read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchUpperBounds {
    /// Candidate anchor positions charged by the selected complete column.
    pub anchor_positions: usize,
    /// Logical anchor-byte classifications for those positions.
    pub anchor_work: usize,
    /// Bytes available to maximal-word inspection, including assertion
    /// context to the right of the search window.
    pub contextual_bytes: usize,
    /// Maximum complete maximal words that can be inspected.
    pub candidate_words: usize,
    /// Maximum dictionary fingerprint, binary-search and equality work.
    pub lookup_steps: usize,
    /// Combined candidate-filter, segmentation and dictionary work.
    pub total_work: usize,
    /// Search performs no heap allocation and borrows no external scratch.
    pub scratch_bytes: usize,
}

/// Exact logical events observed by one successful invocation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SearchActual {
    pub anchor_calls: usize,
    pub anchor_positions: usize,
    pub anchor_work: usize,
    pub predecessor_reads: usize,
    pub word_scan_bytes: usize,
    pub candidate_words: usize,
    pub fingerprint_bytes: usize,
    pub binary_search_comparisons: usize,
    pub collision_slots: usize,
    pub full_equality_checks: usize,
    pub full_equality_bytes: usize,
    pub lookup_steps: usize,
    pub total_work: usize,
}

/// Complete preflight bound and exact successful-search counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchAccounting {
    pub upper_bounds: SearchUpperBounds,
    pub actual: SearchActual,
}

enum PackedProbeResult {
    Exhausted,
    Match(Match),
    ResumeAt(usize),
}

enum WideFindResult {
    Exhausted,
    Anchor(usize),
    DenseHighResume(usize),
}

#[cfg(target_arch = "aarch64")]
#[derive(Debug, Eq, PartialEq)]
enum SingleByteMemberResult {
    Exhausted,
    Match(usize),
    BoundaryResume(usize),
}

/// Allocation-free search failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SearchError {
    InvalidWindow {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
    WorkLimit {
        needed: u64,
        limit: u64,
    },
    ScratchLimit {
        needed: usize,
        limit: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    Dictionary(DictionaryReduceErrorKind),
    InternalInvariant {
        detail: &'static str,
    },
}

impl fmt::Display for SearchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidWindow {
                start,
                end,
                haystack_len,
            } => write!(
                formatter,
                "invalid guarded literal-set window {start}..{end} for haystack length {haystack_len}",
            ),
            Self::WorkLimit { needed, limit } => write!(
                formatter,
                "guarded literal-set work {needed} exceeds limit {limit}",
            ),
            Self::ScratchLimit { needed, limit } => write!(
                formatter,
                "guarded literal-set scratch {needed} exceeds limit {limit}",
            ),
            Self::ArithmeticOverflow { computation } => {
                write!(formatter, "guarded literal-set {computation} overflowed")
            }
            Self::Dictionary(error) => {
                write!(formatter, "guarded dictionary search failed: {error:?}")
            }
            Self::InternalInvariant { detail } => {
                write!(formatter, "guarded literal-set invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for SearchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidWindow { .. }
            | Self::WorkLimit { .. }
            | Self::ScratchLimit { .. }
            | Self::ArithmeticOverflow { .. }
            | Self::Dictionary(_)
            | Self::InternalInvariant { .. } => None,
        }
    }
}

impl From<DictionaryReduceError> for SearchError {
    fn from(error: DictionaryReduceError) -> Self {
        Self::Dictionary(error.kind)
    }
}

/// A complete byte set at one fixed offset in every retained word. The
/// bounded representation admits exactly the cardinalities serviced by the
/// shared `memchr` family.
#[derive(Clone, Copy, Debug)]
struct FixedByteAnchor {
    offset: usize,
    bytes: [u8; 3],
    len: u8,
}

const WIDE_SCALAR_PREFIX_BYTES: usize = 8;
const WIDE_BULK_SKIP_MIN_BYTES: usize = 64;
const WIDE_DENSE_HIGH_BYTES: u32 = 8;
const WIDE_REJECTION_PACKED_PROBE_BYTES: usize = 1024;
const WIDE_REJECTION_SAMPLE_MIN_CANDIDATES: usize = 2;
const WIDE_CORRELATED_SAMPLE_BYTES: usize = 128;
const WIDE_CORRELATED_SAMPLE_MIN_REMAINDER_BYTES: usize = WIDE_BULK_SKIP_MIN_BYTES;
const WIDE_CORRELATED_SHORT_MIN_CANDIDATES: usize = 4;
const WIDE_CORRELATED_LONG_MIN_CANDIDATES: usize = 2;
const WIDE_CORRELATED_LONG_WORD_BYTES: usize = 16;
const WIDE_PACKED_PREFIX_BYTES: usize = 4;
const WIDE_SECONDARY_COLUMN_LIMIT: usize = 4;
const WIDE_RANKED_COLUMN_LIMIT: usize = WIDE_SECONDARY_COLUMN_LIMIT + 1;
const WIDE_BATCHED_SECONDARY_MIN_PATTERNS: usize = 16;
const WIDE_CORRELATED_MIN_WORD_BYTES: usize = 5;
const WIDE_CORRELATED_MAX_WORD_BYTES: usize = 32;
const WIDE_CORRELATED_MAX_PATTERNS: usize = u64::BITS as usize;
const WIDE_ASCII_BYTES: usize = 128;
const WIDE_CORRELATED_BOUNDARY_COLUMNS: usize = 2;
const WIDE_CORRELATED_DIRECT_EXACT_MAX_CANDIDATES: u32 = 2;
const ONE_BYTE_SCALAR_PREFIX_BYTES: usize = 8;
const ONE_BYTE_SCALAR_MEMBER_LIMIT: u32 = 4;
#[cfg(target_arch = "aarch64")]
const ONE_BYTE_DENSE_REJECTION_WORDS: usize = 4;
#[cfg(target_arch = "aarch64")]
const ONE_BYTE_DENSE_REJECTION_BYTES: usize = 64;
const ASCII_WORD_MEMBERS: AsciiByteSet = AsciiByteSet::from_words([
    0x03ff_0000_0000_0000,
    0x07ff_fffe_87ff_fffe,
]);

#[derive(Clone, Copy, Debug)]
struct WideColumn {
    offset: usize,
    members: AsciiByteSet,
    classifier: Option<AsciiByteSetClassifier>,
}

#[derive(Clone, Debug)]
struct CorrelatedColumn {
    by_byte: [u64; WIDE_ASCII_BYTES],
}

#[derive(Clone, Debug)]
struct CorrelatedColumns {
    pattern_mask: u64,
    verification_order: [u8; WIDE_CORRELATED_MAX_WORD_BYTES],
    columns: Box<[CorrelatedColumn]>,
    word_members: AsciiByteSetClassifier,
    // Narrow pairs add a complete correlated verifier, but turning that fact
    // into an unbounded packed-child handoff still has to amortize one native
    // service quantum for every retained pattern byte and entry. Established
    // wide dictionaries keep their prior zero-threshold policy.
    minimum_batched_remainder_bytes: usize,
}

impl CorrelatedColumns {
    fn admits_batched_remainder(&self, bytes: usize) -> bool {
        bytes >= self.minimum_batched_remainder_bytes
    }

    fn sample_minimum_candidates(&self) -> usize {
        if self.columns.len() >= WIDE_CORRELATED_LONG_WORD_BYTES {
            WIDE_CORRELATED_LONG_MIN_CANDIDATES
        } else {
            WIDE_CORRELATED_SHORT_MIN_CANDIDATES
        }
    }

    fn matches(&self, candidate: &[u8]) -> bool {
        let mut matching = self.pattern_mask;
        for &offset in &self.verification_order[..self.columns.len()] {
            let offset = usize::from(offset);
            let Some(&members) = candidate.get(offset).and_then(|&byte| {
                self.columns
                    .get(offset)
                    .and_then(|column| column.by_byte.get(usize::from(byte)))
            })
            else {
                return false;
            };
            matching &= members;
            if matching == 0 {
                return false;
            }
        }
        true
    }

    fn packed_prefix_matches(&self, candidate: &[u8]) -> bool {
        let mut matching = self.pattern_mask;
        for offset in 0..candidate.len().min(WIDE_PACKED_PREFIX_BYTES) {
            let Some(&members) = candidate.get(offset).and_then(|&byte| {
                self.columns
                    .get(offset)
                    .and_then(|column| column.by_byte.get(usize::from(byte)))
            })
            else {
                return false;
            };
            matching &= members;
            if matching == 0 {
                return false;
            }
        }
        true
    }

    fn fixed_word_boundary_candidates_32(
        &self,
        haystack: &[u8],
        position: usize,
        word_bytes: usize,
        mut candidates: u32,
    ) -> Option<u32> {
        if candidates == 0 {
            return Some(0);
        }

        let left_word_mask = if position == 0 {
            let block_end = position.checked_add(ASCII_WIDE_BYTES)?;
            let block: &[u8; ASCII_WIDE_BYTES] =
                haystack.get(position..block_end)?.try_into().ok()?;
            self.word_members.classify_32(block).member_mask() << 1
        } else {
            let block_start = position.checked_sub(1)?;
            let block_end = block_start.checked_add(ASCII_WIDE_BYTES)?;
            let block: &[u8; ASCII_WIDE_BYTES] =
                haystack.get(block_start..block_end)?.try_into().ok()?;
            self.word_members.classify_32(block).member_mask()
        };
        candidates &= !left_word_mask;
        if candidates == 0 {
            return Some(0);
        }

        let block_start = position.checked_add(word_bytes)?;
        let remaining = haystack.len().checked_sub(block_start)?;
        let right_word_mask = if remaining >= ASCII_WIDE_BYTES {
            let block_end = block_start.checked_add(ASCII_WIDE_BYTES)?;
            let block: &[u8; ASCII_WIDE_BYTES] =
                haystack.get(block_start..block_end)?.try_into().ok()?;
            self.word_members.classify_32(block).member_mask()
        } else {
            // A complete 32-start block has at least 31 real right-context
            // bytes. When its final word ends at the haystack end, classify
            // one byte to the left and shift that lane away. The new high lane
            // is zero, exactly representing the synthetic nonword context at
            // `haystack.len()`.
            if remaining != ASCII_WIDE_BYTES.saturating_sub(1) {
                return None;
            }
            let shifted_start = block_start.checked_sub(1)?;
            let shifted_end = shifted_start.checked_add(ASCII_WIDE_BYTES)?;
            let shifted: &[u8; ASCII_WIDE_BYTES] =
                haystack.get(shifted_start..shifted_end)?.try_into().ok()?;
            self.word_members.classify_32(shifted).member_mask() >> 1
        };
        Some(candidates & !right_word_mask)
    }

    fn should_filter_secondary_columns(candidates: u32) -> bool {
        candidates.count_ones() > WIDE_CORRELATED_DIRECT_EXACT_MAX_CANDIDATES
    }

    fn sample_has_packed_prefix_candidates(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
    ) -> bool {
        if end.saturating_sub(start) <= WIDE_CORRELATED_SAMPLE_MIN_REMAINDER_BYTES {
            return false;
        }
        let sample_end = start
            .saturating_add(WIDE_CORRELATED_SAMPLE_BYTES)
            .min(end);
        let word_bytes = self.columns.len();
        let minimum_candidates = self.sample_minimum_candidates();
        let Some(candidate_starts) = sample_end
            .checked_sub(start)
            .and_then(|bytes| bytes.checked_sub(word_bytes))
            .and_then(|starts| starts.checked_add(1))
        else {
            return false;
        };
        let mut candidates = 0_usize;
        for relative in 0..candidate_starts {
            let candidate_start = start + relative;
            let candidate_end = candidate_start + word_bytes;
            let has_left_boundary = candidate_start == 0
                || !is_ascii_word(haystack[candidate_start - 1]);
            let has_right_boundary = candidate_end == haystack.len()
                || !is_ascii_word(haystack[candidate_end]);
            if has_left_boundary
                && has_right_boundary
                && self.packed_prefix_matches(&haystack[candidate_start..candidate_end])
            {
                candidates = candidates.saturating_add(1);
                if candidates >= minimum_candidates {
                    return true;
                }
            }
        }
        false
    }

    fn persistent_bytes(&self) -> usize {
        size_of::<Self>()
            .checked_add(
                self.columns
                    .len()
                    .checked_mul(size_of::<CorrelatedColumn>())
                    .expect("correlated-column dimensions were admitted"),
            )
            .expect("correlated-column dimensions were admitted")
    }
}

#[derive(Debug)]
struct WideByteAnchor {
    members: AsciiByteSetClassifier,
    nonmembers: AsciiByteSetRunScanner,
    range: Option<(u8, u8)>,
    secondary_columns: [Option<WideColumn>; WIDE_SECONDARY_COLUMN_LIMIT],
    correlated_columns: Option<Box<CorrelatedColumns>>,
    packed: Box<PackedLiteralSetPlan>,
}

#[derive(Debug)]
struct SingleByteWordSet {
    members: AsciiByteSetClassifier,
    words: AsciiByteSetClassifier,
    #[cfg(target_arch = "aarch64")]
    candidate_nonmembers: AsciiByteSetNonMemberScanner,
    #[cfg(target_arch = "aarch64")]
    word_runs: AsciiByteSetRunScanner,
    #[cfg(target_arch = "aarch64")]
    run_scanners_vector: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SingleBytePrimary {
    Members,
    ClassifiedMembers,
    Boundaries,
}

impl SingleByteWordSet {
    fn complete_word_set(&self) -> bool {
        self.members.set() == ASCII_WORD_MEMBERS
    }

    fn block_context_work(haystack: &[u8], position: usize, lanes: usize) -> usize {
        usize::from(position != 0) + usize::from(position + lanes < haystack.len())
    }

    fn isolated_mask_16(
        &self,
        haystack: &[u8],
        position: usize,
        block: &[u8; ASCII_NARROW_BYTES],
    ) -> u16 {
        let words = self.words.classify_16(block).member_mask();
        Self::isolated_mask_from_words_16(haystack, position, words)
    }

    fn isolated_mask_from_words_16(
        haystack: &[u8],
        position: usize,
        words: u16,
    ) -> u16 {
        let left = u16::from(position != 0 && is_ascii_word(haystack[position - 1]));
        let block_end = position + ASCII_NARROW_BYTES;
        let right = u16::from(
            block_end < haystack.len() && is_ascii_word(haystack[block_end]),
        ) << (u16::BITS - 1);
        words & !(words << 1 | left) & !(words >> 1 | right)
    }

    fn isolated_mask_32(
        &self,
        haystack: &[u8],
        position: usize,
        block: &[u8; ASCII_WIDE_BYTES],
    ) -> u32 {
        let words = self.words.classify_32(block).member_mask();
        Self::isolated_mask_from_words_32(haystack, position, words)
    }

    fn isolated_mask_from_words_32(
        haystack: &[u8],
        position: usize,
        words: u32,
    ) -> u32 {
        let left = u32::from(position != 0 && is_ascii_word(haystack[position - 1]));
        let block_end = position + ASCII_WIDE_BYTES;
        let right = u32::from(
            block_end < haystack.len() && is_ascii_word(haystack[block_end]),
        ) << (u32::BITS - 1);
        words & !(words << 1 | left) & !(words >> 1 | right)
    }

    fn member_mask_16(
        &self,
        block: &[u8; ASCII_NARROW_BYTES],
        mut isolated: u16,
        complete_word_set: bool,
    ) -> u16 {
        if complete_word_set || isolated == 0 {
            return isolated;
        }
        if isolated.count_ones() > ONE_BYTE_SCALAR_MEMBER_LIMIT {
            return isolated & self.members.classify_16(block).member_mask();
        }
        let mut members = 0_u16;
        while isolated != 0 {
            let lane = isolated.trailing_zeros();
            let lane_index = usize::try_from(lane).expect("a 16-byte lane fits usize");
            if self.members.set().contains(block[lane_index]) {
                members |= 1_u16 << lane;
            }
            isolated &= isolated - 1;
        }
        members
    }

    fn member_mask_32(
        &self,
        block: &[u8; ASCII_WIDE_BYTES],
        mut isolated: u32,
        complete_word_set: bool,
    ) -> u32 {
        if complete_word_set || isolated == 0 {
            return isolated;
        }
        if isolated.count_ones() > ONE_BYTE_SCALAR_MEMBER_LIMIT {
            return isolated & self.members.classify_32(block).member_mask();
        }
        let mut members = 0_u32;
        while isolated != 0 {
            let lane = isolated.trailing_zeros();
            let lane_index = usize::try_from(lane).expect("a 32-byte lane fits usize");
            if self.members.set().contains(block[lane_index]) {
                members |= 1_u32 << lane;
            }
            isolated &= isolated - 1;
        }
        members
    }

    fn classify_block_16(
        &self,
        haystack: &[u8],
        position: usize,
        block: &[u8; ASCII_NARROW_BYTES],
        primary: &mut Option<SingleBytePrimary>,
        complete_word_set: bool,
    ) -> (u16, usize) {
        if complete_word_set {
            let masks = self.words.classify_16(block);
            let words = masks.member_mask();
            if masks.ascii_mask() != u16::MAX {
                *primary = Some(SingleBytePrimary::ClassifiedMembers);
            } else if words == 0 {
                *primary = Some(SingleBytePrimary::Members);
            }
            return (
                Self::isolated_mask_from_words_16(haystack, position, words),
                ASCII_NARROW_BYTES
                    + Self::block_context_work(haystack, position, ASCII_NARROW_BYTES),
            );
        }
        match primary {
            None => {
                let masks = self.members.classify_16(block);
                let members = masks.member_mask();
                if members == 0 {
                    *primary = Some(if masks.ascii_mask() == u16::MAX {
                        SingleBytePrimary::Members
                    } else {
                        SingleBytePrimary::ClassifiedMembers
                    });
                    return (0, ASCII_NARROW_BYTES);
                }
                let words = self.words.classify_16(block).member_mask();
                let isolated =
                    Self::isolated_mask_from_words_16(haystack, position, words);
                *primary = Some(SingleBytePrimary::Boundaries);
                (
                    isolated & members,
                    ASCII_NARROW_BYTES * 2
                        + Self::block_context_work(
                            haystack,
                            position,
                            ASCII_NARROW_BYTES,
                        ),
                )
            }
            Some(SingleBytePrimary::Members) => {
                let members = self.members.classify_16(block).member_mask();
                if members == 0 {
                    (0, ASCII_NARROW_BYTES)
                } else {
                    let candidates =
                        members & self.isolated_mask_16(haystack, position, block);
                    if candidates == 0 {
                        *primary = Some(SingleBytePrimary::Boundaries);
                    }
                    (
                        candidates,
                        ASCII_NARROW_BYTES * 2
                            + Self::block_context_work(
                                haystack,
                                position,
                                ASCII_NARROW_BYTES,
                            ),
                    )
                }
            }
            Some(SingleBytePrimary::ClassifiedMembers) => {
                let masks = self.members.classify_16(block);
                let members = masks.member_mask();
                if members == 0 {
                    if masks.ascii_mask() == u16::MAX {
                        *primary = Some(SingleBytePrimary::Members);
                    }
                    return (0, ASCII_NARROW_BYTES);
                }
                let words = self.words.classify_16(block).member_mask();
                let isolated =
                    Self::isolated_mask_from_words_16(haystack, position, words);
                let candidates = members & isolated;
                if candidates == 0 && masks.ascii_mask() == u16::MAX {
                    *primary = Some(SingleBytePrimary::Boundaries);
                }
                (
                    candidates,
                    ASCII_NARROW_BYTES * 2
                        + Self::block_context_work(
                            haystack,
                            position,
                            ASCII_NARROW_BYTES,
                        ),
                )
            }
            Some(SingleBytePrimary::Boundaries) => {
                let word_masks = self.words.classify_16(block);
                let words = word_masks.member_mask();
                let isolated = Self::isolated_mask_from_words_16(
                    haystack,
                    position,
                    words,
                );
                let member_work = if isolated == 0 {
                    0
                } else if isolated.count_ones() > ONE_BYTE_SCALAR_MEMBER_LIMIT {
                    ASCII_NARROW_BYTES
                } else {
                    usize::try_from(isolated.count_ones())
                        .expect("a narrow isolated population fits usize")
                };
                let candidates = self.member_mask_16(block, isolated, false);
                if word_masks.ascii_mask() != u16::MAX {
                    *primary = Some(SingleBytePrimary::ClassifiedMembers);
                } else if words == 0 {
                    *primary = Some(SingleBytePrimary::Members);
                } else if isolated != 0 && candidates == 0 {
                    *primary = Some(SingleBytePrimary::Members);
                }
                (
                    candidates,
                    ASCII_NARROW_BYTES
                        + member_work
                        + Self::block_context_work(
                            haystack,
                            position,
                            ASCII_NARROW_BYTES,
                        ),
                )
            }
        }
    }

    fn classify_block_32(
        &self,
        haystack: &[u8],
        position: usize,
        block: &[u8; ASCII_WIDE_BYTES],
        primary: &mut Option<SingleBytePrimary>,
        complete_word_set: bool,
    ) -> (u32, usize) {
        if complete_word_set {
            let masks = self.words.classify_32(block);
            let words = masks.member_mask();
            if masks.ascii_mask() != u32::MAX {
                *primary = Some(SingleBytePrimary::ClassifiedMembers);
            } else if words == 0 {
                *primary = Some(SingleBytePrimary::Members);
            }
            return (
                Self::isolated_mask_from_words_32(haystack, position, words),
                ASCII_WIDE_BYTES
                    + Self::block_context_work(haystack, position, ASCII_WIDE_BYTES),
            );
        }
        match primary {
            None => {
                let masks = self.members.classify_32(block);
                let members = masks.member_mask();
                if members == 0 {
                    *primary = Some(if masks.ascii_mask() == u32::MAX {
                        SingleBytePrimary::Members
                    } else {
                        SingleBytePrimary::ClassifiedMembers
                    });
                    return (0, ASCII_WIDE_BYTES);
                }
                let words = self.words.classify_32(block).member_mask();
                let isolated =
                    Self::isolated_mask_from_words_32(haystack, position, words);
                *primary = Some(SingleBytePrimary::Boundaries);
                (
                    isolated & members,
                    ASCII_WIDE_BYTES * 2
                        + Self::block_context_work(haystack, position, ASCII_WIDE_BYTES),
                )
            }
            Some(SingleBytePrimary::Members) => {
                let members = self.members.classify_32(block).member_mask();
                if members == 0 {
                    (0, ASCII_WIDE_BYTES)
                } else {
                    let candidates =
                        members & self.isolated_mask_32(haystack, position, block);
                    if candidates == 0 {
                        *primary = Some(SingleBytePrimary::Boundaries);
                    }
                    (
                        candidates,
                        ASCII_WIDE_BYTES * 2
                            + Self::block_context_work(haystack, position, ASCII_WIDE_BYTES),
                    )
                }
            }
            Some(SingleBytePrimary::ClassifiedMembers) => {
                let masks = self.members.classify_32(block);
                let members = masks.member_mask();
                if members == 0 {
                    if masks.ascii_mask() == u32::MAX {
                        *primary = Some(SingleBytePrimary::Members);
                    }
                    return (0, ASCII_WIDE_BYTES);
                }
                let words = self.words.classify_32(block).member_mask();
                let isolated =
                    Self::isolated_mask_from_words_32(haystack, position, words);
                let candidates = members & isolated;
                if candidates == 0 && masks.ascii_mask() == u32::MAX {
                    *primary = Some(SingleBytePrimary::Boundaries);
                }
                (
                    candidates,
                    ASCII_WIDE_BYTES * 2
                        + Self::block_context_work(haystack, position, ASCII_WIDE_BYTES),
                )
            }
            Some(SingleBytePrimary::Boundaries) => {
                let word_masks = self.words.classify_32(block);
                let words = word_masks.member_mask();
                let isolated = Self::isolated_mask_from_words_32(
                    haystack,
                    position,
                    words,
                );
                let member_work = if isolated == 0 {
                    0
                } else if isolated.count_ones() > ONE_BYTE_SCALAR_MEMBER_LIMIT {
                    ASCII_WIDE_BYTES
                } else {
                    usize::try_from(isolated.count_ones())
                        .expect("a wide isolated population fits usize")
                };
                let candidates = self.member_mask_32(block, isolated, false);
                if word_masks.ascii_mask() != u32::MAX {
                    *primary = Some(SingleBytePrimary::ClassifiedMembers);
                } else if words == 0 {
                    *primary = Some(SingleBytePrimary::Members);
                } else if isolated != 0 && candidates == 0 {
                    *primary = Some(SingleBytePrimary::Members);
                }
                (
                    candidates,
                    ASCII_WIDE_BYTES
                        + member_work
                        + Self::block_context_work(haystack, position, ASCII_WIDE_BYTES),
                )
            }
        }
    }

    fn scalar_matches(&self, haystack: &[u8], position: usize) -> bool {
        self.members.set().contains(haystack[position])
            && (position == 0 || !is_ascii_word(haystack[position - 1]))
            && (position + 1 == haystack.len() || !is_ascii_word(haystack[position + 1]))
    }

    #[cfg(target_arch = "aarch64")]
    fn find_members_value(
        &self,
        haystack: &[u8],
        mut position: usize,
        end: usize,
    ) -> SingleByteMemberResult {
        debug_assert!(self.run_scanners_vector);
        let mut rejection_sample_start = position;
        let mut rejected_words = 0_usize;
        while position < end {
            let skipped = self
                .candidate_nonmembers
                .scan_forward(&haystack[position..end])
                .nonmember_run_len();
            position += skipped;
            if position == end {
                return SingleByteMemberResult::Exhausted;
            }
            debug_assert!(self.members.set().contains(haystack[position]));
            if self.scalar_matches(haystack, position) {
                return SingleByteMemberResult::Match(position);
            }
            let word_bytes = self
                .word_runs
                .scan_forward(&haystack[position..end])
                .member_run_len();
            debug_assert!(word_bytes != 0);
            position += word_bytes;
            rejected_words += 1;
            if rejected_words == ONE_BYTE_DENSE_REJECTION_WORDS {
                if position.saturating_sub(rejection_sample_start)
                    <= ONE_BYTE_DENSE_REJECTION_BYTES
                {
                    return SingleByteMemberResult::BoundaryResume(position);
                }
                rejection_sample_start = position;
                rejected_words = 0;
            }
        }
        SingleByteMemberResult::Exhausted
    }

    fn find_value(&self, haystack: &[u8], window: SearchWindow) -> Option<usize> {
        let complete_word_set = self.complete_word_set();
        #[cfg(target_arch = "aarch64")]
        let mut primary = (complete_word_set && self.run_scanners_vector)
            .then_some(SingleBytePrimary::Members);
        #[cfg(not(target_arch = "aarch64"))]
        let mut primary = None;
        let mut position = window.start();
        let scalar_end = position
            .saturating_add(ONE_BYTE_SCALAR_PREFIX_BYTES)
            .min(window.end());
        while position < scalar_end {
            if self.scalar_matches(haystack, position) {
                return Some(position);
            }
            position += 1;
        }
        while window.end().saturating_sub(position) >= ASCII_WIDE_BYTES {
            #[cfg(target_arch = "aarch64")]
            if self.run_scanners_vector
                && matches!(
                    primary,
                    Some(
                        SingleBytePrimary::Members | SingleBytePrimary::ClassifiedMembers
                    )
                )
            {
                match self.find_members_value(haystack, position, window.end()) {
                    SingleByteMemberResult::Exhausted => return None,
                    SingleByteMemberResult::Match(position) => return Some(position),
                    SingleByteMemberResult::BoundaryResume(resume) => {
                        position = resume;
                        primary = Some(SingleBytePrimary::Boundaries);
                        continue;
                    }
                }
            }
            let block_end = position + ASCII_WIDE_BYTES;
            let block: &[u8; ASCII_WIDE_BYTES] = haystack[position..block_end]
                .try_into()
                .expect("a one-byte wide block was proved complete");
            let (members, _) = self.classify_block_32(
                haystack,
                position,
                block,
                &mut primary,
                complete_word_set,
            );
            if members != 0 {
                let lane = usize::try_from(members.trailing_zeros())
                    .expect("a 32-byte lane fits usize");
                return Some(position + lane);
            }
            position = block_end;
        }
        if window.end().saturating_sub(position) >= ASCII_NARROW_BYTES {
            let block_end = position + ASCII_NARROW_BYTES;
            let block: &[u8; ASCII_NARROW_BYTES] = haystack[position..block_end]
                .try_into()
                .expect("a one-byte narrow block was proved complete");
            let (members, _) = self.classify_block_16(
                haystack,
                position,
                block,
                &mut primary,
                complete_word_set,
            );
            if members != 0 {
                let lane = usize::try_from(members.trailing_zeros())
                    .expect("a 16-byte lane fits usize");
                return Some(position + lane);
            }
            position = block_end;
        }
        while position < window.end() {
            if self.scalar_matches(haystack, position) {
                return Some(position);
            }
            position += 1;
        }
        None
    }

    fn scalar_matches_counted(
        &self,
        haystack: &[u8],
        position: usize,
        actual: &mut SearchActual,
    ) -> Result<bool, SearchError> {
        actual.anchor_calls = checked_add(actual.anchor_calls, 1, "one-byte scalar calls")?;
        actual.anchor_positions = checked_add(
            actual.anchor_positions,
            1,
            "one-byte scalar positions",
        )?;
        actual.anchor_work = checked_add(actual.anchor_work, 1, "one-byte membership work")?;
        if !self.members.set().contains(haystack[position]) {
            return Ok(false);
        }
        actual.anchor_work = checked_add(actual.anchor_work, 1, "one-byte left-boundary work")?;
        if position != 0 && is_ascii_word(haystack[position - 1]) {
            return Ok(false);
        }
        actual.anchor_work = checked_add(actual.anchor_work, 1, "one-byte right-boundary work")?;
        if position + 1 != haystack.len() && is_ascii_word(haystack[position + 1]) {
            return Ok(false);
        }
        actual.candidate_words = checked_add(
            actual.candidate_words,
            1,
            "one-byte isolated candidates",
        )?;
        Ok(true)
    }

    fn charge_block(
        actual: &mut SearchActual,
        lanes: usize,
        members: u32,
        block_work: usize,
    ) -> Result<(), SearchError> {
        actual.anchor_calls = checked_add(actual.anchor_calls, 1, "one-byte block calls")?;
        actual.anchor_positions = checked_add(
            actual.anchor_positions,
            lanes,
            "one-byte block positions",
        )?;
        actual.anchor_work = checked_add(
            actual.anchor_work,
            block_work,
            "one-byte block-classification work",
        )?;
        let member_count = usize::try_from(members.count_ones())
            .expect("one-byte block population fits usize");
        actual.candidate_words = checked_add(
            actual.candidate_words,
            member_count,
            "one-byte exact candidates",
        )?;
        Ok(())
    }

    fn find_counted(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        upper_bounds: SearchUpperBounds,
    ) -> Result<(Option<Match>, SearchAccounting), SearchError> {
        let complete_word_set = self.complete_word_set();
        let mut primary = None;
        let mut actual = SearchActual::default();
        let mut position = window.start();
        let scalar_end = position
            .saturating_add(ONE_BYTE_SCALAR_PREFIX_BYTES)
            .min(window.end());
        while position < scalar_end {
            if self.scalar_matches_counted(haystack, position, &mut actual)? {
                let end = position + 1;
                return close_search_accounting(
                    Some(Match {
                        start: position,
                        end,
                    }),
                    upper_bounds,
                    actual,
                );
            }
            position += 1;
        }
        while window.end().saturating_sub(position) >= ASCII_WIDE_BYTES {
            let block_end = position + ASCII_WIDE_BYTES;
            let block: &[u8; ASCII_WIDE_BYTES] = haystack[position..block_end]
                .try_into()
                .expect("a counted one-byte wide block was proved complete");
            let (members, block_work) = self.classify_block_32(
                haystack,
                position,
                block,
                &mut primary,
                complete_word_set,
            );
            Self::charge_block(&mut actual, ASCII_WIDE_BYTES, members, block_work)?;
            if members != 0 {
                let lane = usize::try_from(members.trailing_zeros())
                    .expect("a 32-byte lane fits usize");
                let start = position + lane;
                return close_search_accounting(
                    Some(Match {
                        start,
                        end: start + 1,
                    }),
                    upper_bounds,
                    actual,
                );
            }
            position = block_end;
        }
        if window.end().saturating_sub(position) >= ASCII_NARROW_BYTES {
            let block_end = position + ASCII_NARROW_BYTES;
            let block: &[u8; ASCII_NARROW_BYTES] = haystack[position..block_end]
                .try_into()
                .expect("a counted one-byte narrow block was proved complete");
            let (members, block_work) = self.classify_block_16(
                haystack,
                position,
                block,
                &mut primary,
                complete_word_set,
            );
            Self::charge_block(
                &mut actual,
                ASCII_NARROW_BYTES,
                u32::from(members),
                block_work,
            )?;
            if members != 0 {
                let lane = usize::try_from(members.trailing_zeros())
                    .expect("a 16-byte lane fits usize");
                let start = position + lane;
                return close_search_accounting(
                    Some(Match {
                        start,
                        end: start + 1,
                    }),
                    upper_bounds,
                    actual,
                );
            }
            position = block_end;
        }
        while position < window.end() {
            if self.scalar_matches_counted(haystack, position, &mut actual)? {
                return close_search_accounting(
                    Some(Match {
                        start: position,
                        end: position + 1,
                    }),
                    upper_bounds,
                    actual,
                );
            }
            position += 1;
        }
        close_search_accounting(None, upper_bounds, actual)
    }
}

impl WideByteAnchor {
    fn storage_bytes(&self) -> usize {
        size_of::<Self>()
            .checked_add(size_of::<PackedLiteralSetPlan>())
            .and_then(|bytes| {
                bytes.checked_add(self.packed.build_accounting().persistent_bytes)
            })
            .and_then(|bytes| {
                self.correlated_columns.as_ref().map_or(Some(bytes), |columns| {
                    bytes.checked_add(columns.persistent_bytes())
                })
            })
            .expect("a published wide anchor proved its packed storage")
    }

    fn find_range(&self, haystack: &[u8]) -> Option<usize> {
        let (start, end) = self.range?;
        let width = end.wrapping_sub(start);
        let mut position = 0_usize;
        let prefix_end = haystack.len().min(ASCII_NARROW_BYTES);
        while position < prefix_end {
            if haystack[position].wrapping_sub(start) <= width {
                return Some(position);
            }
            position = position.checked_add(1)?;
        }
        while haystack.len().saturating_sub(position) >= ASCII_NARROW_BYTES {
            let block_end = position.checked_add(ASCII_NARROW_BYTES)?;
            let block: &[u8; ASCII_NARROW_BYTES] =
                haystack[position..block_end].try_into().ok()?;
            let candidates = classify_byte_delta_16(start, width, block).member_mask();
            if candidates != 0 {
                let offset = usize::try_from(candidates.trailing_zeros()).ok()?;
                return position.checked_add(offset);
            }
            position = block_end;
        }
        while position < haystack.len() {
            if haystack[position].wrapping_sub(start) <= width {
                return Some(position);
            }
            position = position.checked_add(1)?;
        }
        None
    }

    fn rejection_sample_is_dense(&self, haystack: &[u8]) -> bool {
        self.rejection_sample_has_candidates(
            haystack,
            WIDE_REJECTION_SAMPLE_MIN_CANDIDATES,
        )
    }

    fn rejection_sample_has_candidates(
        &self,
        haystack: &[u8],
        minimum_candidates: usize,
    ) -> bool {
        let sampled = &haystack[..haystack.len().min(WIDE_REJECTION_PACKED_PROBE_BYTES)];
        let mut candidates = 0_usize;
        let mut position = 0_usize;
        while sampled.len().saturating_sub(position) >= ASCII_WIDE_BYTES {
            let block_end = position + ASCII_WIDE_BYTES;
            let block: &[u8; ASCII_WIDE_BYTES] = sampled[position..block_end]
                .try_into()
                .expect("a rejection sample retains complete classifier blocks");
            candidates = candidates.saturating_add(
                usize::try_from(self.members.classify_32(block).member_mask().count_ones())
                    .expect("a 32-lane population fits usize"),
            );
            if candidates >= minimum_candidates {
                return true;
            }
            position = block_end;
        }
        sampled[position..].iter().any(|&byte| {
            if self.members.set().contains(byte) {
                candidates = candidates.saturating_add(1);
            }
            candidates >= minimum_candidates
        })
    }

    fn secondary_columns_match(&self, candidate: &[u8]) -> bool {
        self.secondary_columns.iter().flatten().all(|column| {
            candidate
                .get(column.offset)
                .is_some_and(|&byte| column.members.contains(byte))
        })
    }

    fn has_secondary_columns(&self) -> bool {
        self.secondary_columns[0].is_some()
    }

    fn admits_correlated_remainder(&self, bytes: usize) -> bool {
        self.correlated_columns
            .as_ref()
            .is_some_and(|columns| columns.admits_batched_remainder(bytes))
    }

    fn find_correlated_start(
        &self,
        haystack: &[u8],
        cursor: usize,
        window_end: usize,
        primary_offset: usize,
        word_bytes: usize,
    ) -> Option<usize> {
        let scan_end = window_end.checked_sub(word_bytes)?.checked_add(1)?;
        let correlated = self
            .correlated_columns
            .as_ref()
            .expect("a correlated scan retains its exact columns");
        let mut position = cursor;
        while scan_end.saturating_sub(position) >= ASCII_WIDE_BYTES {
            let primary_start = position.checked_add(primary_offset)?;
            let primary_end = primary_start.checked_add(ASCII_WIDE_BYTES)?;
            let primary: &[u8; ASCII_WIDE_BYTES] =
                haystack.get(primary_start..primary_end)?.try_into().ok()?;
            let mut candidates = self.members.classify_32(primary).member_mask();
            candidates = correlated.fixed_word_boundary_candidates_32(
                haystack,
                position,
                word_bytes,
                candidates,
            )?;
            // Once exact whole-word boundaries compact a block to at most two
            // starts, direct identity checks are bounded by 64 column reads.
            // Four 32-lane marginal filters would do twice that logical work
            // and cannot distinguish cross-pattern byte recombinations.
            if CorrelatedColumns::should_filter_secondary_columns(candidates) {
                for column in self.secondary_columns.iter().flatten() {
                    let block_start = position.checked_add(column.offset)?;
                    let block_end = block_start.checked_add(ASCII_WIDE_BYTES)?;
                    let block: &[u8; ASCII_WIDE_BYTES] =
                        haystack.get(block_start..block_end)?.try_into().ok()?;
                    let classifier = column
                        .classifier
                        .as_ref()
                        .expect("a published secondary column retains its classifier");
                    candidates &= classifier.classify_32(block).member_mask();
                    if candidates == 0 {
                        break;
                    }
                }
            }
            if candidates != 0 {
                while candidates != 0 {
                    let relative = usize::try_from(candidates.trailing_zeros()).ok()?;
                    let start = position.checked_add(relative)?;
                    let end = start.checked_add(word_bytes)?;
                    if correlated.matches(haystack.get(start..end)?) {
                        return Some(start);
                    }
                    candidates &= candidates.checked_sub(1)?;
                }
            }
            position = position.checked_add(ASCII_WIDE_BYTES)?;
        }
        while position < scan_end {
            let primary = *haystack.get(position.checked_add(primary_offset)?)?;
            let marginal_match = self.members.set().contains(primary)
                && self.secondary_columns.iter().flatten().all(|column| {
                    haystack
                        .get(position.saturating_add(column.offset))
                        .is_some_and(|&byte| column.members.contains(byte))
                });
            if marginal_match {
                let end = position.checked_add(word_bytes)?;
                let possible_boundaries = (position == 0
                    || position
                        .checked_sub(1)
                        .and_then(|before| haystack.get(before))
                        .is_some_and(|&byte| !is_ascii_word(byte)))
                    && (end == haystack.len()
                        || haystack.get(end).is_some_and(|&byte| !is_ascii_word(byte)));
                let exact_match = possible_boundaries
                    && haystack
                        .get(position..end)
                        .is_some_and(|candidate| correlated.matches(candidate));
                if exact_match {
                    return Some(position);
                }
            }
            position = position.checked_add(1)?;
        }
        None
    }
}

impl WideByteAnchor {
    #[inline]
    fn use_bulk_nonmember_scanner(&self) -> bool {
        prefer_bulk_nonmember_scanner(
            self.nonmembers.selection().vector,
            self.members.selection().wide().vector,
        )
    }
}

#[inline]
fn prefer_bulk_nonmember_scanner(
    scanner: VectorKind,
    classifier: VectorKind,
) -> bool {
    // A scalar run leaf would discard an already-authenticated wide
    // classifier after the first rejected block. Keep the run primitive
    // when it is itself vectorized, or when there is no vector alternative.
    !matches!(scanner, VectorKind::Scalar) || matches!(classifier, VectorKind::Scalar)
}

impl WideByteAnchor {
    fn find(&self, haystack: &[u8]) -> Option<usize> {
        match self.find_internal(haystack, false) {
            WideFindResult::Anchor(position) => Some(position),
            WideFindResult::Exhausted | WideFindResult::DenseHighResume(_) => None,
        }
    }

    fn find_adaptive(&self, haystack: &[u8]) -> WideFindResult {
        self.find_internal(haystack, true)
    }

    fn find_internal(&self, haystack: &[u8], signal_dense_high: bool) -> WideFindResult {
        let mut position = 0_usize;
        let use_bulk_nonmember_scanner = self.use_bulk_nonmember_scanner();
        let prefix_end = haystack.len().min(WIDE_SCALAR_PREFIX_BYTES);
        while position < prefix_end {
            if self.members.set().contains(haystack[position]) {
                return WideFindResult::Anchor(position);
            }
            let Some(next) = position.checked_add(1) else {
                return WideFindResult::Exhausted;
            };
            position = next;
        }

        let mut fixed_block_proved = false;
        let mut high_byte_cooldown = 0_u8;
        while haystack.len().saturating_sub(position) >= ASCII_WIDE_BYTES {
            if use_bulk_nonmember_scanner
                && fixed_block_proved
                && high_byte_cooldown == 0
                && haystack.len().saturating_sub(position) >= WIDE_BULK_SKIP_MIN_BYTES
            {
                let skipped = self
                    .nonmembers
                    .scan_forward(&haystack[position..])
                    .member_run_len();
                let Some(next) = position.checked_add(skipped) else {
                    return WideFindResult::Exhausted;
                };
                position = next;
                if position == haystack.len() {
                    return WideFindResult::Exhausted;
                }
                let byte = haystack[position];
                if byte.is_ascii() {
                    debug_assert!(self.members.set().contains(byte));
                    return WideFindResult::Anchor(position);
                }
                if haystack.len().saturating_sub(position) < ASCII_WIDE_BYTES {
                    break;
                }
            }

            let Some(block_end) = position.checked_add(ASCII_WIDE_BYTES) else {
                return WideFindResult::Exhausted;
            };
            let Ok(block) = <&[u8; ASCII_WIDE_BYTES]>::try_from(&haystack[position..block_end])
            else {
                return WideFindResult::Exhausted;
            };
            let masks = self.members.classify_32(block);
            if masks.ascii_mask() == u32::MAX {
                high_byte_cooldown = high_byte_cooldown.saturating_sub(1);
            } else {
                // An ASCII run scanner must stop at every high byte. Prefer a
                // few exact all-byte blocks after observing one, then retry
                // the long-run path once the source becomes ASCII again.
                high_byte_cooldown = 4;
            }
            let candidates = masks.member_mask();
            if candidates != 0 {
                let Ok(offset) = usize::try_from(candidates.trailing_zeros()) else {
                    return WideFindResult::Exhausted;
                };
                return position
                    .checked_add(offset)
                    .map_or(WideFindResult::Exhausted, WideFindResult::Anchor);
            }
            if signal_dense_high
                && masks.ascii_mask().count_zeros() >= WIDE_DENSE_HIGH_BYTES
            {
                return WideFindResult::DenseHighResume(block_end);
            }
            position = block_end;
            fixed_block_proved = true;
        }

        if haystack.len().saturating_sub(position) >= ASCII_NARROW_BYTES {
            let Some(block_end) = position.checked_add(ASCII_NARROW_BYTES) else {
                return WideFindResult::Exhausted;
            };
            let Ok(block) = <&[u8; ASCII_NARROW_BYTES]>::try_from(&haystack[position..block_end])
            else {
                return WideFindResult::Exhausted;
            };
            let candidates = self.members.classify_16(block).member_mask();
            if candidates != 0 {
                let Ok(offset) = usize::try_from(candidates.trailing_zeros()) else {
                    return WideFindResult::Exhausted;
                };
                return position
                    .checked_add(offset)
                    .map_or(WideFindResult::Exhausted, WideFindResult::Anchor);
            }
            position = block_end;
        }

        while position < haystack.len() {
            if self.members.set().contains(haystack[position]) {
                return WideFindResult::Anchor(position);
            }
            let Some(next) = position.checked_add(1) else {
                return WideFindResult::Exhausted;
            };
            position = next;
        }
        WideFindResult::Exhausted
    }
}

impl FixedByteAnchor {
    fn find(self, haystack: &[u8]) -> Option<usize> {
        match self.len {
            1 => memchr(self.bytes[0], haystack),
            2 => memchr2(self.bytes[0], self.bytes[1], haystack),
            3 => memchr3(self.bytes[0], self.bytes[1], self.bytes[2], haystack),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct WordDimensions {
    minimum_word_bytes: usize,
    maximum_word_bytes: usize,
}

fn select_word_dimensions(
    dictionary: &Dictionary,
    patterns: usize,
    max_build_work: usize,
) -> Result<WordDimensions, PackedLiteralSetError> {
    if patterns > max_build_work {
        return Err(PackedLiteralSetError::BuildWorkLimit {
            needed: patterns,
            limit: max_build_work,
        });
    }
    let mut minimum_word_bytes = usize::MAX;
    let mut maximum_word_bytes = 0_usize;
    for index in 0..patterns {
        let word = dictionary
            .source_word(index)
            .expect("a published guarded dictionary retains every source word");
        minimum_word_bytes = minimum_word_bytes.min(word.bytes.len());
        maximum_word_bytes = maximum_word_bytes.max(word.bytes.len());
    }
    if minimum_word_bytes == usize::MAX || minimum_word_bytes == 0 {
        return Err(PackedLiteralSetError::UnsupportedTargetOrShape);
    }
    Ok(WordDimensions {
        minimum_word_bytes,
        maximum_word_bytes,
    })
}

fn select_fixed_byte_anchor(
    dictionary: &Dictionary,
    patterns: usize,
    dimensions: WordDimensions,
    max_build_work: usize,
) -> Result<(FixedByteAnchor, usize, Option<usize>, usize), PackedLiteralSetError> {
    let work_per_column =
        patterns
            .checked_add(3)
            .ok_or(PackedLiteralSetError::ArithmeticOverflow {
                computation: "guarded fixed-column work per column",
            })?;
    let selection_work = dimensions
        .minimum_word_bytes
        .checked_mul(work_per_column)
        .and_then(|work| work.checked_add(patterns))
        .ok_or(PackedLiteralSetError::ArithmeticOverflow {
            computation: "guarded fixed-column construction work",
        })?;
    if selection_work > max_build_work {
        return Err(PackedLiteralSetError::BuildWorkLimit {
            needed: selection_work,
            limit: max_build_work,
        });
    }

    let mut best: Option<((u64, usize, usize), FixedByteAnchor)> = None;
    for offset in 0..dimensions.minimum_word_bytes {
        let mut bytes = [0_u8; 3];
        let mut len = 0_usize;
        let mut complete = true;
        for index in 0..patterns {
            let byte = dictionary
                .source_word(index)
                .expect("a published guarded dictionary retains every source word")
                .bytes[offset];
            if bytes[..len].contains(&byte) {
                continue;
            }
            let Some(slot) = bytes.get_mut(len) else {
                complete = false;
                break;
            };
            *slot = byte;
            len = len
                .checked_add(1)
                .ok_or(PackedLiteralSetError::ArithmeticOverflow {
                    computation: "guarded fixed-column cardinality",
                })?;
        }
        if !complete || len == 0 {
            continue;
        }
        let frequency_score = bytes[..len].iter().try_fold(0_u64, |score, &byte| {
            score.checked_add(u64::from(packed_literal_anchor_frequency_rank(byte)) + 1)
        });
        let Some(frequency_score) = frequency_score else {
            return Err(PackedLiteralSetError::ArithmeticOverflow {
                computation: "guarded fixed-column frequency score",
            });
        };
        let score = (frequency_score, len, offset);
        let anchor = FixedByteAnchor {
            offset,
            bytes,
            len: u8::try_from(len).map_err(|_| {
                PackedLiteralSetError::ArithmeticOverflow {
                    computation: "guarded fixed-column cardinality representation",
                }
            })?,
        };
        if best
            .as_ref()
            .is_none_or(|(incumbent, _)| score < *incumbent)
        {
            best = Some((score, anchor));
        }
    }
    best.map(|(_, anchor)| {
        (
            anchor,
            dimensions.maximum_word_bytes,
            (dimensions.minimum_word_bytes == dimensions.maximum_word_bytes)
                .then_some(dimensions.minimum_word_bytes),
            selection_work,
        )
    })
    .ok_or(PackedLiteralSetError::UnsupportedTargetOrShape)
}

fn select_wide_byte_anchor(
    dictionary: &Dictionary,
    patterns: usize,
    dimensions: WordDimensions,
    max_build_work: usize,
) -> Result<
    (
        FixedByteAnchor,
        AsciiByteSet,
        [Option<WideColumn>; WIDE_SECONDARY_COLUMN_LIMIT],
        usize,
        Option<usize>,
        usize,
    ),
    PackedLiteralSetError,
>
{
    let fixed_work = dimensions
        .minimum_word_bytes
        .checked_mul(patterns.checked_add(3).ok_or(
            PackedLiteralSetError::ArithmeticOverflow {
                computation: "guarded failed fixed-column work per column",
            },
        )?)
        .and_then(|work| work.checked_add(patterns))
        .ok_or(PackedLiteralSetError::ArithmeticOverflow {
            computation: "guarded failed fixed-column construction work",
        })?;
    let wide_work = dimensions
        .minimum_word_bytes
        .checked_mul(
            patterns
                .checked_add(128)
                .and_then(|work| work.checked_add(WIDE_RANKED_COLUMN_LIMIT))
                .ok_or(PackedLiteralSetError::ArithmeticOverflow {
                    computation: "guarded wide-column work per column",
                })?,
        )
        .ok_or(PackedLiteralSetError::ArithmeticOverflow {
            computation: "guarded wide-column construction work",
        })?;
    let selection_work = fixed_work.checked_add(wide_work).ok_or(
        PackedLiteralSetError::ArithmeticOverflow {
            computation: "combined guarded column construction work",
        },
    )?;
    if selection_work > max_build_work {
        return Err(PackedLiteralSetError::BuildWorkLimit {
            needed: selection_work,
            limit: max_build_work,
        });
    }

    let mut ranked: [Option<((u64, usize, usize), WideColumn)>;
        WIDE_RANKED_COLUMN_LIMIT] = [None; WIDE_RANKED_COLUMN_LIMIT];
    let mut special = [None; 3];
    let middle_offset = dimensions.minimum_word_bytes / 2;
    let last_offset = dimensions.minimum_word_bytes - 1;
    for offset in 0..dimensions.minimum_word_bytes {
        let mut member_words = [0_u64; 2];
        let mut cardinality = 0_usize;
        let mut frequency_score = 0_u64;
        for index in 0..patterns {
            let byte = dictionary
                .source_word(index)
                .expect("a published guarded dictionary retains every source word")
                .bytes[offset];
            let word = usize::from(byte / 64);
            let bit = 1_u64 << u32::from(byte % 64);
            if member_words[word] & bit != 0 {
                continue;
            }
            member_words[word] |= bit;
            cardinality = cardinality.checked_add(1).ok_or(
                PackedLiteralSetError::ArithmeticOverflow {
                    computation: "guarded wide-column cardinality",
                },
            )?;
            frequency_score = frequency_score
                .checked_add(u64::from(packed_literal_anchor_frequency_rank(byte)) + 1)
                .ok_or(PackedLiteralSetError::ArithmeticOverflow {
                    computation: "guarded wide-column frequency score",
                })?;
        }
        if cardinality <= 3 {
            return Err(PackedLiteralSetError::UnsupportedTargetOrShape);
        }
        let score = (frequency_score, cardinality, offset);
        let column = WideColumn {
            offset,
            members: AsciiByteSet::from_words(member_words),
            classifier: None,
        };
        if offset == 0 {
            special[0] = Some(column);
        }
        if offset == middle_offset {
            special[1] = Some(column);
        }
        if offset == last_offset {
            special[2] = Some(column);
        }
        let insert_at = ranked
            .iter()
            .position(|candidate| candidate.is_none_or(|(incumbent, _)| score < incumbent));
        if let Some(insert_at) = insert_at {
            for index in (insert_at + 1..WIDE_RANKED_COLUMN_LIMIT).rev() {
                ranked[index] = ranked[index - 1];
            }
            ranked[insert_at] = Some((score, column));
        }
    }
    let ((_, _, offset), primary) =
        ranked[0].ok_or(PackedLiteralSetError::UnsupportedTargetOrShape)?;
    let mut secondary_columns: [Option<WideColumn>; WIDE_SECONDARY_COLUMN_LIMIT] =
        [None; WIDE_SECONDARY_COLUMN_LIMIT];
    for column in special
        .into_iter()
        .flatten()
        .rev()
        .chain(ranked.into_iter().flatten().map(|(_, column)| column))
    {
        if column.offset == offset
            || secondary_columns
                .iter()
                .flatten()
                .any(|retained| retained.offset == column.offset)
        {
            continue;
        }
        let Some(slot) = secondary_columns.iter_mut().find(|slot| slot.is_none()) else {
            break;
        };
        *slot = Some(column);
    }
    Ok((
        FixedByteAnchor {
            offset,
            bytes: [0; 3],
            len: 0,
        },
        primary.members,
        secondary_columns,
        dimensions.maximum_word_bytes,
        (dimensions.minimum_word_bytes == dimensions.maximum_word_bytes)
            .then_some(dimensions.minimum_word_bytes),
        selection_work,
    ))
}

fn correlated_columns_dimensions(
    patterns: usize,
    word_bytes: usize,
) -> Result<Option<(usize, usize)>, PackedLiteralSetError> {
    // A two-byte wide language needs both columns to preserve row identity,
    // and exact boundary masks make its complete verifier especially small.
    // Wider languages retain the established admission threshold: enabling
    // their full column stream for small dictionaries costs more than the
    // incumbent packed search on common short-word inputs.
    let narrow_pair = word_bytes == 2 && patterns >= 4;
    let established_wide = patterns >= WIDE_BATCHED_SECONDARY_MIN_PATTERNS
        && word_bytes >= WIDE_CORRELATED_MIN_WORD_BYTES;
    if (!narrow_pair && !established_wide)
        || patterns > WIDE_CORRELATED_MAX_PATTERNS
        || word_bytes > WIDE_CORRELATED_MAX_WORD_BYTES
    {
        return Ok(None);
    }
    // Each column initializes and scores 128 buckets, records every source
    // pattern, and performs at most `word_bytes` insertion comparisons plus
    // two moves per comparison. The final terms record the pattern mask and
    // compile the exact ASCII-word boundary classifier.
    let per_column_work = WIDE_ASCII_BYTES
        .checked_mul(2)
        .and_then(|work| work.checked_add(patterns))
        .and_then(|work| work.checked_add(word_bytes.checked_mul(3)?))
        .ok_or(PackedLiteralSetError::ArithmeticOverflow {
            computation: "guarded correlated-column construction work",
        })?;
    let initialization_work = per_column_work
        .checked_mul(word_bytes)
        .and_then(|work| work.checked_add(patterns))
        .and_then(|work| work.checked_add(ASCII_CLASSIFIER_BUILD_WORK))
        .and_then(|work| work.checked_add(if narrow_pair { 3 } else { 0 }))
        .ok_or(PackedLiteralSetError::ArithmeticOverflow {
            computation: "guarded correlated-column construction work",
        })?;
    let persistent_bytes = word_bytes
        .checked_mul(size_of::<CorrelatedColumn>())
        .and_then(|bytes| bytes.checked_add(size_of::<CorrelatedColumns>()))
        .ok_or(PackedLiteralSetError::ArithmeticOverflow {
            computation: "guarded correlated-column persistent bytes",
        })?;
    Ok(Some((initialization_work, persistent_bytes)))
}

fn build_correlated_columns(
    dictionary: &Dictionary,
    patterns: usize,
    word_bytes: usize,
    word_members: AsciiByteSetClassifier,
) -> CorrelatedColumns {
    let mut columns = Vec::with_capacity(word_bytes);
    let mut verification_order = [0_u8; WIDE_CORRELATED_MAX_WORD_BYTES];
    let mut verification_scores = [(0_u32, 0_u32, 0_u8); WIDE_CORRELATED_MAX_WORD_BYTES];
    for offset in 0..word_bytes {
        let mut by_byte = [0_u64; WIDE_ASCII_BYTES];
        for pattern_index in 0..patterns {
            let byte = dictionary
                .source_word(pattern_index)
                .expect("a guarded dictionary retains every source word")
                .bytes[offset];
            by_byte[usize::from(byte)] |= 1_u64 << pattern_index;
        }
        let mut largest_bucket = 0_u32;
        let mut collision_score = 0_u32;
        for &members in &by_byte {
            let bucket = members.count_ones();
            largest_bucket = largest_bucket.max(bucket);
            collision_score = collision_score.saturating_add(bucket.saturating_mul(bucket));
        }
        let score = (
            largest_bucket,
            collision_score,
            u8::try_from(offset).expect("correlated word widths fit u8"),
        );
        let mut insertion = offset;
        while insertion != 0 && score < verification_scores[insertion - 1] {
            verification_scores[insertion] = verification_scores[insertion - 1];
            verification_order[insertion] = verification_order[insertion - 1];
            insertion -= 1;
        }
        verification_scores[insertion] = score;
        verification_order[insertion] =
            u8::try_from(offset).expect("correlated word widths fit u8");
        columns.push(CorrelatedColumn { by_byte });
    }
    let mut pattern_mask = 0_u64;
    for pattern_index in 0..patterns {
        pattern_mask |= 1_u64 << pattern_index;
    }
    let minimum_batched_remainder_bytes = if word_bytes == 2 {
        word_bytes
            .checked_add(1)
            .and_then(|per_pattern| patterns.checked_mul(per_pattern))
            .and_then(|coefficient| {
                coefficient.checked_mul(WIDE_REJECTION_PACKED_PROBE_BYTES)
            })
            .expect("correlated-column dimensions bound the packed service threshold")
    } else {
        0
    };
    CorrelatedColumns {
        pattern_mask,
        verification_order,
        columns: columns.into_boxed_slice(),
        word_members,
        minimum_batched_remainder_bytes,
    }
}

fn build_optional_fixed_packed(
    dictionary: &Dictionary,
    patterns: usize,
    pattern_bytes: usize,
    fixed_word_bytes: Option<usize>,
    base_build_work: usize,
    plan_bytes: usize,
    limits: PackedLiteralSetBuildLimits,
    composite_persistent_limit: usize,
) -> Result<Option<Box<PackedLiteralSetPlan>>, PackedLiteralSetError> {
    if !fixed_word_bytes.is_some_and(|bytes| bytes >= 2)
        || patterns > PACKED_LITERAL_SET_CERTIFIED_MAX_PATTERNS
    {
        return Ok(None);
    }
    let publication_work = patterns;
    let child_build_work =
        packed_literal_set_build_work_upper_bound_from_dimensions(patterns, pattern_bytes)?;
    let combined_build_work = base_build_work
        .checked_add(publication_work)
        .and_then(|work| work.checked_add(child_build_work))
        .ok_or(PackedLiteralSetError::ArithmeticOverflow {
            computation: "guarded fixed-column packed construction work",
        })?;
    if combined_build_work > limits.max_build_work {
        return Ok(None);
    }
    let packed_plan_bytes = plan_bytes
        .checked_add(size_of::<PackedLiteralSetPlan>())
        .ok_or(PackedLiteralSetError::ArithmeticOverflow {
            computation: "guarded fixed-column packed owner bytes",
        })?;
    if packed_plan_bytes > composite_persistent_limit
        || packed_plan_bytes > limits.max_build_bytes
    {
        return Ok(None);
    }
    let child_work = limits
        .max_build_work
        .checked_sub(base_build_work)
        .and_then(|work| work.checked_sub(publication_work))
        .expect("the optional fixed packed work was admitted prospectively");
    let child_persistent_bytes = composite_persistent_limit
        .checked_sub(packed_plan_bytes)
        .expect("the optional fixed packed owner fits its persistent limit");
    let child_build_bytes = limits
        .max_build_bytes
        .checked_sub(packed_plan_bytes)
        .expect("the optional fixed packed owner fits its build-byte limit");
    let mut pattern_refs = [&[][..]; PACKED_LITERAL_SET_CERTIFIED_MAX_PATTERNS];
    for (index, slot) in pattern_refs[..patterns].iter_mut().enumerate() {
        *slot = dictionary
            .source_word(index)
            .expect("a guarded dictionary retains every source word")
            .bytes;
    }
    match PackedLiteralSetPlan::new(
        &pattern_refs[..patterns],
        PackedLiteralSetBuildLimits {
            max_build_work: child_work,
            max_build_bytes: child_build_bytes,
            max_persistent_bytes: child_persistent_bytes,
            ..limits
        },
    ) {
        Ok(packed) => Ok(Some(Box::new(packed))),
        Err(
            PackedLiteralSetError::BuildWorkLimit { .. }
            | PackedLiteralSetError::BuildBytesLimit { .. }
            | PackedLiteralSetError::PersistentBytesLimit { .. }
            | PackedLiteralSetError::UnsupportedTargetOrShape,
        ) => Ok(None),
        Err(error) => Err(error),
    }
}

fn inclusive_ascii_range(set: AsciiByteSet) -> Option<(u8, u8)> {
    let words = set.words();
    let first_word = usize::from(words[0] == 0);
    let last_word = usize::from(words[1] != 0);
    let first = *words.get(first_word)?;
    let last = *words.get(last_word)?;
    if first == 0 || last == 0 {
        return None;
    }
    let start = first_word
        .checked_mul(64)?
        .checked_add(usize::try_from(first.trailing_zeros()).ok()?)?;
    let end = last_word
        .checked_mul(64)?
        .checked_add(usize::try_from(63_u32.checked_sub(last.leading_zeros())?).ok()?)?;
    let members = words.into_iter().map(u64::count_ones).sum::<u32>();
    (end.checked_sub(start)?.checked_add(1)? == usize::try_from(members).ok()?)
        .then_some((u8::try_from(start).ok()?, u8::try_from(end).ok()?))
}

/// Immutable composite owner. The selected anchor is a complete candidate
/// source. The dictionary remains the exact authority except when every
/// retained fixed column has already proved one source-pattern identity.
#[derive(Debug)]
pub(crate) struct Plan {
    anchor: FixedByteAnchor,
    maximum_word_bytes: usize,
    fixed_word_bytes: Option<usize>,
    dictionary: Dictionary,
    one_byte: Option<Box<SingleByteWordSet>>,
    fixed_packed: Option<Box<PackedLiteralSetPlan>>,
    wide_anchor: Option<Box<WideByteAnchor>>,
}

impl Plan {
    const fn inline_storage_bytes() -> usize {
        size_of::<Self>() - size_of::<Dictionary>()
    }

    pub(crate) fn build(
        dictionary: Dictionary,
        limits: PackedLiteralSetBuildLimits,
        max_persistent_bytes: usize,
    ) -> Result<Self, PackedLiteralSetError> {
        let composite_persistent_limit = limits.max_persistent_bytes.min(max_persistent_bytes);
        let dictionary_build = dictionary.build_accounting();
        let dictionary_bytes = dictionary_build.actual.persistent_bytes;
        let plan_bytes = dictionary_bytes.checked_add(Self::inline_storage_bytes()).ok_or(
            PackedLiteralSetError::ArithmeticOverflow {
                computation: "guarded fixed-column persistent bytes",
            },
        )?;
        if plan_bytes > composite_persistent_limit {
            return Err(PackedLiteralSetError::PersistentBytesLimit {
                needed: plan_bytes,
                limit: composite_persistent_limit,
            });
        }
        // Guarded extraction releases its source/expansion temporaries before
        // this wrapper is formed. The completed plan is itself the remaining
        // peak that must fit the packed construction-byte ceiling.
        if plan_bytes > limits.max_build_bytes {
            return Err(PackedLiteralSetError::BuildBytesLimit {
                needed: plan_bytes,
                limit: limits.max_build_bytes,
            });
        }
        let identity = dictionary.identity();
        let patterns = identity.entries.len();
        let pattern_bytes = identity.packed_bytes.len();
        if patterns > limits.max_patterns {
            return Err(PackedLiteralSetError::PatternLimit {
                needed: patterns,
                limit: limits.max_patterns,
            });
        }
        if pattern_bytes > limits.max_pattern_bytes {
            return Err(PackedLiteralSetError::PatternBytesLimit {
                needed: pattern_bytes,
                limit: limits.max_pattern_bytes,
            });
        }
        let dictionary_work =
            usize::try_from(dictionary_build.actual.build_work).unwrap_or(usize::MAX);
        let remaining_build_work = limits.max_build_work.checked_sub(dictionary_work).ok_or(
            PackedLiteralSetError::BuildWorkLimit {
                needed: dictionary_work,
                limit: limits.max_build_work,
            },
        )?;
        let dimensions =
            select_word_dimensions(&dictionary, patterns, remaining_build_work)?;
        let (
            anchor,
            wide_members,
            secondary_columns,
            maximum_word_bytes,
            fixed_word_bytes,
            selection_work,
        ) =
            match select_fixed_byte_anchor(
                &dictionary,
                patterns,
                dimensions,
                remaining_build_work,
            ) {
                Ok((anchor, maximum_word_bytes, fixed_word_bytes, selection_work)) => {
                    (
                        anchor,
                        None,
                        [None; WIDE_SECONDARY_COLUMN_LIMIT],
                        maximum_word_bytes,
                        fixed_word_bytes,
                        selection_work,
                    )
                }
                Err(PackedLiteralSetError::UnsupportedTargetOrShape) => {
                    let (
                        anchor,
                        members,
                        secondary_columns,
                        maximum_word_bytes,
                        fixed_word_bytes,
                        selection_work,
                    ) = select_wide_byte_anchor(
                        &dictionary,
                        patterns,
                        dimensions,
                        remaining_build_work,
                    )?;
                    (
                        anchor,
                        Some(members),
                        secondary_columns,
                        maximum_word_bytes,
                        fixed_word_bytes,
                        selection_work,
                    )
                }
                Err(error) => return Err(error),
            };
        if fixed_word_bytes == Some(1) {
            if let Some(members) = wide_members {
                let classifier_work = ASCII_CLASSIFIER_BUILD_WORK.checked_mul(2).ok_or(
                    PackedLiteralSetError::ArithmeticOverflow {
                        computation: "guarded one-byte classifier construction work",
                    },
                )?;
                let route_work = classifier_work;
                #[cfg(target_arch = "aarch64")]
                let route_work = route_work
                    .checked_add(ASCII_NONMEMBER_RUN_SCANNER_BUILD_WORK)
                    .and_then(|work| work.checked_add(ASCII_RUN_SCANNER_BUILD_WORK))
                    .ok_or(PackedLiteralSetError::ArithmeticOverflow {
                        computation: "guarded one-byte route construction work",
                    })?;
                let total_build_work = dictionary_work
                    .checked_add(selection_work)
                    .and_then(|work| work.checked_add(route_work))
                    .ok_or(PackedLiteralSetError::ArithmeticOverflow {
                        computation: "guarded one-byte construction work",
                    })?;
                if total_build_work > limits.max_build_work {
                    return Err(PackedLiteralSetError::BuildWorkLimit {
                        needed: total_build_work,
                        limit: limits.max_build_work,
                    });
                }
                let one_byte_plan_bytes = plan_bytes
                    .checked_add(size_of::<SingleByteWordSet>())
                    .ok_or(PackedLiteralSetError::ArithmeticOverflow {
                        computation: "guarded one-byte persistent bytes",
                    })?;
                if one_byte_plan_bytes > composite_persistent_limit {
                    return Err(PackedLiteralSetError::PersistentBytesLimit {
                        needed: one_byte_plan_bytes,
                        limit: composite_persistent_limit,
                    });
                }
                if one_byte_plan_bytes > limits.max_build_bytes {
                    return Err(PackedLiteralSetError::BuildBytesLimit {
                        needed: one_byte_plan_bytes,
                        limit: limits.max_build_bytes,
                    });
                }
                let dispatch = SimdDispatchContext::capture();
                let member_classifier = dispatch
                    .ascii_byte_set_classifier(members, DispatchPolicy::Auto)
                    .expect(
                        "automatic one-byte member dispatch retains a scalar fallback",
                    );
                let word_classifier = dispatch
                    .ascii_byte_set_classifier(ASCII_WORD_MEMBERS, DispatchPolicy::Auto)
                    .expect("automatic ASCII-word dispatch retains a scalar fallback");
                #[cfg(target_arch = "aarch64")]
                let candidate_nonmember_scanner = dispatch
                    .ascii_byte_set_nonmember_scanner(members, DispatchPolicy::Auto)
                    .expect("automatic one-byte run dispatch retains a scalar fallback");
                #[cfg(target_arch = "aarch64")]
                let word_run_scanner = dispatch
                    .ascii_byte_set_run_scanner(
                        ASCII_WORD_MEMBERS,
                        DispatchPolicy::Auto,
                    )
                    .expect("automatic ASCII-word run dispatch retains a scalar fallback");
                #[cfg(target_arch = "aarch64")]
                let run_scanners_vector = !matches!(
                    candidate_nonmember_scanner.selection().vector,
                    VectorKind::Scalar
                ) && !matches!(
                    word_run_scanner.selection().vector,
                    VectorKind::Scalar
                );
                return Ok(Self {
                    anchor,
                    maximum_word_bytes,
                    fixed_word_bytes,
                    dictionary,
                    one_byte: Some(Box::new(SingleByteWordSet {
                        members: member_classifier,
                        words: word_classifier,
                        #[cfg(target_arch = "aarch64")]
                        candidate_nonmembers: candidate_nonmember_scanner,
                        #[cfg(target_arch = "aarch64")]
                        word_runs: word_run_scanner,
                        #[cfg(target_arch = "aarch64")]
                        run_scanners_vector,
                    })),
                    fixed_packed: None,
                    wide_anchor: None,
                });
            }
        }
        let base_build_work = dictionary_work
            .checked_add(selection_work)
            .ok_or(PackedLiteralSetError::ArithmeticOverflow {
                computation: "guarded fixed-column construction work",
            })?;
        let fixed_packed = if wide_members.is_none() {
            build_optional_fixed_packed(
                &dictionary,
                patterns,
                pattern_bytes,
                fixed_word_bytes,
                base_build_work,
                plan_bytes,
                limits,
                composite_persistent_limit,
            )?
        } else {
            None
        };
        let wide_anchor = if let Some(members) = wide_members {
            let total_build_work = dictionary_work
                .checked_add(selection_work)
                .and_then(|work| work.checked_add(ASCII_CLASSIFIER_BUILD_WORK))
                .and_then(|work| {
                    ASCII_CLASSIFIER_BUILD_WORK
                        .checked_mul(WIDE_SECONDARY_COLUMN_LIMIT)
                        .and_then(|secondary| work.checked_add(secondary))
                })
                .and_then(|work| work.checked_add(ASCII_RUN_SCANNER_BUILD_WORK))
                .ok_or(PackedLiteralSetError::ArithmeticOverflow {
                    computation: "guarded wide-column construction work",
                })?;
            if patterns > PACKED_LITERAL_SET_CERTIFIED_MAX_PATTERNS {
                return Err(PackedLiteralSetError::UnsupportedTargetOrShape);
            }
            let publication_work = patterns;
            let child_build_work =
                packed_literal_set_build_work_upper_bound_from_dimensions(
                    patterns,
                    pattern_bytes,
                )?;
            let combined_build_work = total_build_work
                .checked_add(publication_work)
                .and_then(|work| work.checked_add(child_build_work))
                .ok_or(PackedLiteralSetError::ArithmeticOverflow {
                    computation: "guarded wide-column packed construction work",
                })?;
            if combined_build_work > limits.max_build_work {
                return Err(PackedLiteralSetError::BuildWorkLimit {
                    needed: combined_build_work,
                    limit: limits.max_build_work,
                });
            }
            let wide_plan_bytes = plan_bytes
                .checked_add(size_of::<WideByteAnchor>())
                .ok_or(PackedLiteralSetError::ArithmeticOverflow {
                    computation: "guarded wide-column persistent bytes",
                })?;
            if wide_plan_bytes > composite_persistent_limit {
                return Err(PackedLiteralSetError::PersistentBytesLimit {
                    needed: wide_plan_bytes,
                    limit: composite_persistent_limit,
                });
            }
            if wide_plan_bytes > limits.max_build_bytes {
                return Err(PackedLiteralSetError::BuildBytesLimit {
                    needed: wide_plan_bytes,
                    limit: limits.max_build_bytes,
                });
            }
            let child_owner_bytes = size_of::<PackedLiteralSetPlan>();
            let packed_plan_bytes = wide_plan_bytes
                .checked_add(child_owner_bytes)
                .ok_or(PackedLiteralSetError::ArithmeticOverflow {
                    computation: "guarded wide-column packed owner bytes",
                })?;
            if packed_plan_bytes > composite_persistent_limit {
                return Err(PackedLiteralSetError::PersistentBytesLimit {
                    needed: packed_plan_bytes,
                    limit: composite_persistent_limit,
                });
            }
            if packed_plan_bytes > limits.max_build_bytes {
                return Err(PackedLiteralSetError::BuildBytesLimit {
                    needed: packed_plan_bytes,
                    limit: limits.max_build_bytes,
                });
            }
            let child_work = limits
                .max_build_work
                .checked_sub(total_build_work)
                .and_then(|work| work.checked_sub(publication_work))
                .expect("the packed child work was admitted prospectively");
            let child_persistent_bytes = composite_persistent_limit
                .checked_sub(packed_plan_bytes)
                .expect("the packed child owner fits its persistent limit");
            let child_build_bytes = limits
                .max_build_bytes
                .checked_sub(packed_plan_bytes)
                .expect("the packed child owner fits its build-byte limit");
            let member_words = members.words();
            let nonmembers = AsciiByteSet::from_words([!member_words[0], !member_words[1]]);
            let dispatch = SimdDispatchContext::capture();
            let classifier = dispatch
                .ascii_byte_set_classifier(members, DispatchPolicy::Auto)
                .expect("automatic wide-column classifier dispatch retains a scalar fallback");
            let mut secondary_columns = secondary_columns;
            for column in secondary_columns.iter_mut().flatten() {
                column.classifier = Some(
                    dispatch
                        .ascii_byte_set_classifier(column.members, DispatchPolicy::Auto)
                        .expect(
                            "automatic secondary-column dispatch retains a scalar fallback",
                        ),
                );
            }
            let scanner = dispatch
                .ascii_byte_set_run_scanner(nonmembers, DispatchPolicy::Auto)
                .expect("automatic wide-column dispatch retains a scalar fallback");
            let mut pattern_refs = [&[][..]; PACKED_LITERAL_SET_CERTIFIED_MAX_PATTERNS];
            for (index, slot) in pattern_refs[..patterns].iter_mut().enumerate() {
                *slot = dictionary
                    .source_word(index)
                    .expect("a guarded dictionary retains every source word")
                    .bytes;
            }
            let packed = PackedLiteralSetPlan::new(
                &pattern_refs[..patterns],
                PackedLiteralSetBuildLimits {
                    max_build_work: child_work,
                    max_build_bytes: child_build_bytes,
                    max_persistent_bytes: child_persistent_bytes,
                    ..limits
                },
            )?;
            let correlated_columns = if let Some(word_bytes) = fixed_word_bytes {
                if let Some((correlated_work, correlated_bytes)) =
                    correlated_columns_dimensions(patterns, word_bytes)?
                {
                    let admitted_work = combined_build_work
                        .checked_add(correlated_work)
                        .is_some_and(|work| work <= limits.max_build_work);
                    let retained_bytes = packed_plan_bytes
                        .checked_add(packed.build_accounting().persistent_bytes)
                        .and_then(|bytes| bytes.checked_add(correlated_bytes));
                    let admitted_persistent = retained_bytes
                        .is_some_and(|bytes| bytes <= composite_persistent_limit);
                    let admitted_build =
                        retained_bytes.is_some_and(|bytes| bytes <= limits.max_build_bytes);
                    (admitted_work && admitted_persistent && admitted_build).then(|| {
                        let word_members = dispatch
                            .ascii_byte_set_classifier(ASCII_WORD_MEMBERS, DispatchPolicy::Auto)
                            .expect(
                                "automatic ASCII-word dispatch retains a scalar fallback",
                            );
                        Box::new(build_correlated_columns(
                            &dictionary,
                            patterns,
                            word_bytes,
                            word_members,
                        ))
                    })
                } else {
                    None
                }
            } else {
                None
            };
            Some(Box::new(WideByteAnchor {
                members: classifier,
                nonmembers: scanner,
                range: inclusive_ascii_range(members),
                secondary_columns,
                correlated_columns,
                packed: Box::new(packed),
            }))
        } else {
            None
        };
        Ok(Self {
            anchor,
            maximum_word_bytes,
            fixed_word_bytes,
            dictionary,
            one_byte: None,
            fixed_packed,
            wide_anchor,
        })
    }

    pub(crate) fn storage_bytes(&self) -> usize {
        let base = self
            .dictionary
            .build_accounting()
            .actual
            .persistent_bytes
            .checked_add(Self::inline_storage_bytes())
            .expect("successful guarded plan construction proved its persistent bytes");
        let base = self.one_byte.as_ref().map_or(base, |_| {
            base.checked_add(size_of::<SingleByteWordSet>())
                .expect("one-byte storage fits after successful construction")
        });
        let base = self.fixed_packed.as_ref().map_or(base, |packed| {
            base.checked_add(size_of::<PackedLiteralSetPlan>())
                .and_then(|bytes| bytes.checked_add(packed.build_accounting().persistent_bytes))
                .expect("fixed packed storage fits after successful construction")
        });
        self.wide_anchor.as_ref().map_or(base, |wide| {
            base.checked_add(wide.storage_bytes())
                .expect("wide-column storage fits after successful construction")
        })
    }

    pub(crate) const fn plan_id(&self) -> &'static str {
        if self.one_byte.is_some() {
            ONE_BYTE_PLAN_ID
        } else if self.wide_anchor.is_some() {
            WIDE_PACKED_PLAN_ID
        } else if self.fixed_packed.is_some() {
            FIXED_PACKED_PLAN_ID
        } else {
            PLAN_ID
        }
    }

    pub(crate) fn find_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, SearchAccounting), SearchError> {
        self.search_window(haystack, window, limits)
    }

    pub(crate) fn shortest_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        self.search_window(haystack, window, limits)
            .map(|(matched, accounting)| (matched.map(Match::end), accounting))
    }

    pub(crate) fn find_window_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<Option<Match>, SearchError> {
        #[cfg(test)]
        value_path_probe::record_find();
        self.search_window_value(haystack, window, limits)
    }

    fn fixed_word_range(
        &self,
        anchor_position: usize,
        window: SearchWindow,
    ) -> Option<(usize, usize)> {
        let width = self.fixed_word_bytes?;
        let start = anchor_position.checked_sub(self.anchor.offset)?;
        if start < window.start() {
            return None;
        }
        let end = start.checked_add(width)?;
        (end <= window.end()).then_some((start, end))
    }

    fn find_anchor(&self, haystack: &[u8], prefer_range: bool) -> Option<usize> {
        let Some(wide) = self.wide_anchor.as_ref() else {
            return self.anchor.find(haystack);
        };
        if prefer_range && wide.range.is_some() {
            return wide.find_range(haystack);
        }
        wide.find(haystack)
    }

    fn search_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, SearchAccounting), SearchError> {
        let upper_bounds = self.search_upper_bounds(haystack, window)?;
        enforce_limits(upper_bounds, limits)?;
        if let Some(one_byte) = self.one_byte.as_ref() {
            one_byte.find_counted(haystack, window, upper_bounds)
        } else {
            self.search_window_anchor(haystack, window, upper_bounds)
        }
    }

    fn search_window_anchor(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        upper_bounds: SearchUpperBounds,
    ) -> Result<(Option<Match>, SearchAccounting), SearchError> {
        let anchor = &self.anchor;
        let mut actual = SearchActual::default();
        let mut cursor = window.start();
        let matched = loop {
            actual.anchor_calls = checked_add(actual.anchor_calls, 1, "anchor calls")?;
            let scan_start =
                cursor
                    .checked_add(anchor.offset)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "fixed-column scan start",
                    })?;
            if scan_start > window.end() {
                break None;
            }
            let remaining = haystack.get(scan_start..window.end()).ok_or(
                SearchError::InternalInvariant {
                    detail: "fixed-column cursor escaped its admitted window",
                },
            )?;
            let Some(relative) = self.find_anchor(remaining, false) else {
                let positions = window
                    .end()
                    .checked_sub(scan_start)
                    .and_then(|width| width.checked_add(1))
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "terminal fixed-column positions",
                    })?;
                charge_anchor(&mut actual, positions)?;
                break None;
            };
            let anchor_position = scan_start.checked_add(relative).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "fixed-column anchor position",
                },
            )?;
            let positions = relative
                .checked_add(1)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "successful fixed-column positions",
                })?;
            charge_anchor(&mut actual, positions)?;

            let (word_start, is_word_start) =
                scan_ascii_word_start(haystack, anchor_position, window.start(), &mut actual)?;
            let Some(word_end) =
                scan_ascii_word_end(haystack, anchor_position, window.end(), &mut actual)?
            else {
                break None;
            };
            if word_end <= anchor_position {
                return Err(SearchError::InternalInvariant {
                    detail: "a fixed-column anchor did not advance through its word",
                });
            }
            let word_bytes =
                word_end
                    .checked_sub(word_start)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "fixed-column maximal-word width",
                    })?;
            if is_word_start && word_bytes <= self.maximum_word_bytes {
                actual.candidate_words = checked_add(actual.candidate_words, 1, "candidate words")?;
                let (found, lookup) = self
                    .dictionary
                    .lookup_counted(&haystack[word_start..word_end])?;
                add_lookup(&mut actual, lookup)?;
                if found {
                    break Some(Match {
                        start: word_start,
                        end: word_end,
                    });
                }
            }
            // The complete containing word is rejected, so interior repeats
            // cannot create a dense restart stream.
            cursor = word_end;
        };
        close_search_accounting(matched, upper_bounds, actual)
    }

    fn search_window_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<Option<Match>, SearchError> {
        let upper_bounds = self.search_upper_bounds(haystack, window)?;
        enforce_limits(upper_bounds, limits)?;
        if let Some(one_byte) = self.one_byte.as_ref() {
            Ok(one_byte.find_value(haystack, window).map(|start| Match {
                start,
                end: start + 1,
            }))
        } else if self.wide_anchor.is_some() {
            let packed_probe_work =
                self.value_packed_probe_work(window, upper_bounds, limits);
            self.search_window_value_wide(haystack, window, packed_probe_work)
        } else {
            self.search_window_value_fixed(haystack, window, upper_bounds, limits)
        }
    }

    fn admit_fixed_value_packed_probe(
        &self,
        window: SearchWindow,
        upper_bounds: SearchUpperBounds,
        limits: SearchLimits,
    ) -> Option<(&PackedLiteralSetPlan, usize, usize, usize)> {
        let packed = self.fixed_packed.as_ref()?;
        let build = packed.build_accounting();
        let coefficient = build.pattern_bytes.checked_add(build.patterns)?;
        let positions = window
            .end()
            .checked_sub(window.start())?
            .checked_add(1)?;
        let packed_work = positions.checked_mul(coefficient)?;
        let total_work = upper_bounds.total_work.checked_add(packed_work)?;
        u64::try_from(total_work)
            .is_ok_and(|needed| needed <= limits.max_work)
            .then_some((
                packed.as_ref(),
                packed_work,
                build.patterns,
                build.simd_minimum_haystack_bytes.max(1),
            ))
    }

    fn value_packed_probe_work(
        &self,
        window: SearchWindow,
        upper_bounds: SearchUpperBounds,
        limits: SearchLimits,
    ) -> Option<usize> {
        let Some(packed) = self
            .wide_anchor
            .as_ref()
            .map(|wide| wide.packed.as_ref())
        else {
            return None;
        };
        let build = packed.build_accounting();
        let Some(coefficient) = build.pattern_bytes.checked_add(build.patterns) else {
            return None;
        };
        let Some(positions) = window
            .end()
            .checked_sub(window.start())
            .and_then(|bytes| bytes.checked_add(1))
        else {
            return None;
        };
        let packed_work = positions.checked_mul(coefficient)?;
        let rejection_sample_work = window
            .end()
            .checked_sub(window.start())?
            .min(WIDE_CORRELATED_SAMPLE_BYTES)
            .checked_mul(WIDE_PACKED_PREFIX_BYTES.checked_add(3)?)?;
        let secondary_work = upper_bounds
            .anchor_positions
            .checked_mul(WIDE_SECONDARY_COLUMN_LIMIT)?;
        let boundary_work = if self
            .wide_anchor
            .as_ref()
            .is_some_and(|wide| wide.correlated_columns.is_some())
        {
            upper_bounds
                .anchor_positions
                .checked_mul(WIDE_CORRELATED_BOUNDARY_COLUMNS)?
        } else {
            0
        };
        let Some(total) = packed_work
            .checked_add(upper_bounds.total_work)
            .and_then(|work| work.checked_add(rejection_sample_work))
            .and_then(|work| work.checked_add(secondary_work))
            .and_then(|work| work.checked_add(boundary_work))
        else {
            return None;
        };
        u64::try_from(total)
            .is_ok_and(|needed| needed <= limits.max_work)
            .then_some(packed_work)
    }

    fn search_window_value_fixed(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        upper_bounds: SearchUpperBounds,
        limits: SearchLimits,
    ) -> Result<Option<Match>, SearchError> {
        let anchor = &self.anchor;
        let mut packed = None;
        let mut packed_admission_checked = false;
        let mut rejected_word_work = 0_usize;
        let mut cursor = window.start();
        loop {
            let scan_start =
                cursor
                    .checked_add(anchor.offset)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "value fixed-column scan start",
                    })?;
            if scan_start > window.end() {
                return Ok(None);
            }
            let remaining = haystack.get(scan_start..window.end()).ok_or(
                SearchError::InternalInvariant {
                    detail: "value fixed-column cursor escaped its admitted window",
                },
            )?;
            let Some(relative) = anchor.find(remaining) else {
                return Ok(None);
            };
            let anchor_position = scan_start.checked_add(relative).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "value fixed-column anchor position",
                },
            )?;
            if let Some((word_start, word_end)) =
                self.fixed_word_range(anchor_position, window)
            {
                let has_left_boundary = word_start == 0
                    || !is_ascii_word(
                        haystack[word_start
                            .checked_sub(1)
                            .expect("a positive fixed word start has a predecessor")],
                    );
                let has_right_boundary = word_end == haystack.len()
                    || !is_ascii_word(haystack[word_end]);
                if has_left_boundary && has_right_boundary {
                    let candidate = &haystack[word_start..word_end];
                    if self.dictionary.lookup_at_or_after(candidate, 0).is_some() {
                        return Ok(Some(Match {
                            start: word_start,
                            end: word_end,
                        }));
                    }
                    cursor = word_end;
                    if !packed_admission_checked {
                        packed = self.admit_fixed_value_packed_probe(
                            window,
                            upper_bounds,
                            limits,
                        );
                        packed_admission_checked = true;
                    }
                    if let Some((probe, max_work, patterns, service_quantum)) = packed {
                        let comparison_work = usize::try_from(
                            usize::BITS.checked_sub(patterns.leading_zeros()).ok_or(
                                SearchError::ArithmeticOverflow {
                                    computation: "fixed packed rejection comparisons",
                                },
                            )?,
                        )
                        .map_err(|_| SearchError::ArithmeticOverflow {
                            computation: "fixed packed rejection comparisons",
                        })?;
                        let rejection_work = candidate
                            .len()
                            .checked_mul(2)
                            .and_then(|work| work.checked_add(comparison_work))
                            .ok_or(SearchError::ArithmeticOverflow {
                                computation: "fixed packed rejection work",
                            })?;
                        rejected_word_work = rejected_word_work
                            .checked_add(rejection_work)
                            .ok_or(SearchError::ArithmeticOverflow {
                                computation: "accumulated fixed packed rejection work",
                            })?;
                        if rejected_word_work >= service_quantum
                            && window.end().saturating_sub(cursor) >= service_quantum
                        {
                            packed = None;
                            match self.probe_packed_value(
                                probe,
                                haystack,
                                window,
                                cursor,
                                max_work,
                                None,
                            )? {
                                PackedProbeResult::Exhausted => return Ok(None),
                                PackedProbeResult::Match(matched) => return Ok(Some(matched)),
                                PackedProbeResult::ResumeAt(resume) => cursor = resume,
                            }
                        }
                    }
                    continue;
                }
            }
            let (word_start, is_word_start) =
                scan_ascii_word_start_value(haystack, anchor_position, window.start());
            let Some(word_end) =
                scan_ascii_word_end_value(haystack, anchor_position, window.end())?
            else {
                return Ok(None);
            };
            if word_end <= anchor_position {
                return Err(SearchError::InternalInvariant {
                    detail: "a value fixed-column anchor did not advance",
                });
            }
            let word_bytes =
                word_end
                    .checked_sub(word_start)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "value fixed-column maximal-word width",
                    })?;
            if is_word_start
                && word_bytes <= self.maximum_word_bytes
                && self
                    .dictionary
                    .lookup_at_or_after(&haystack[word_start..word_end], 0)
                    .is_some()
            {
                return Ok(Some(Match {
                    start: word_start,
                    end: word_end,
                }));
            }
            cursor = word_end;
        }
    }

    fn search_window_value_wide(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        packed_probe_work: Option<usize>,
    ) -> Result<Option<Match>, SearchError> {
        let anchor = &self.anchor;
        let mut packed = packed_probe_work.and_then(|work| {
            self.wide_anchor
                .as_ref()
                .map(|wide| (wide.packed.as_ref(), work))
        });
        let mut cursor = window.start();
        let mut prefer_range = false;
        let secondary_available = packed_probe_work.is_some()
            && self.fixed_word_bytes.is_some()
            && self
                .wide_anchor
                .as_ref()
                .is_some_and(|wide| wide.has_secondary_columns());
        let batched_secondary_available = secondary_available
            && self.wide_anchor.as_ref().is_some_and(|wide| {
                wide.correlated_columns.is_some()
            });
        let mut secondary_active = false;
        let mut correlated_secondary_active = false;
        let mut correlated_sample_available = batched_secondary_available;
        loop {
            if correlated_secondary_active {
                let wide = self
                    .wide_anchor
                    .as_ref()
                    .expect("an active correlated filter belongs to a wide anchor");
                let word_bytes = self
                    .fixed_word_bytes
                    .expect("an active correlated filter belongs to fixed-width words");
                let Some(word_start) = wide.find_correlated_start(
                    haystack,
                    cursor,
                    window.end(),
                    anchor.offset,
                    word_bytes,
                ) else {
                    return Ok(None);
                };
                let word_end = word_start.checked_add(word_bytes).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "correlated fixed-word match end",
                    },
                )?;
                return Ok(Some(Match {
                    start: word_start,
                    end: word_end,
                }));
            }
            let scan_start =
                cursor
                    .checked_add(anchor.offset)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "value fixed-column scan start",
                    })?;
            if scan_start > window.end() {
                return Ok(None);
            }
            let remaining = haystack.get(scan_start..window.end()).ok_or(
                SearchError::InternalInvariant {
                    detail: "value fixed-column cursor escaped its admitted window",
                },
            )?;
            let relative = if prefer_range {
                let Some(relative) = self.find_anchor(remaining, true) else {
                    return Ok(None);
                };
                relative
            } else if packed.is_some() {
                let wide = self
                    .wide_anchor
                    .as_ref()
                    .expect("an admitted packed probe belongs to a wide anchor");
                match wide.find_adaptive(remaining) {
                    WideFindResult::Exhausted => return Ok(None),
                    WideFindResult::Anchor(relative) => relative,
                    WideFindResult::DenseHighResume(relative) => {
                        cursor = cursor.checked_add(relative).ok_or(
                            SearchError::ArithmeticOverflow {
                                computation: "dense-high wide-column resume",
                            },
                        )?;
                        if wide.range.is_some() {
                            prefer_range = true;
                        } else {
                            let (probe, max_work) = packed
                                .take()
                                .expect("a dense-high signal retained its packed owner");
                            match self.probe_packed_value(
                                probe,
                                haystack,
                                window,
                                cursor,
                                max_work,
                                None,
                            )? {
                                PackedProbeResult::Exhausted => return Ok(None),
                                PackedProbeResult::Match(matched) => return Ok(Some(matched)),
                                PackedProbeResult::ResumeAt(resume) => {
                                    cursor = resume;
                                    secondary_active = secondary_available;
                                    correlated_secondary_active = batched_secondary_available
                                        && wide.admits_correlated_remainder(
                                            window.end().saturating_sub(cursor),
                                        );
                                }
                            }
                        }
                        continue;
                    }
                }
            } else {
                let Some(relative) = self.find_anchor(remaining, false) else {
                    return Ok(None);
                };
                relative
            };
            let anchor_position = scan_start.checked_add(relative).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "value fixed-column anchor position",
                },
            )?;
            if let Some((word_start, word_end)) =
                self.fixed_word_range(anchor_position, window)
            {
                let has_left_boundary = word_start == 0
                    || !is_ascii_word(
                        haystack[word_start
                            .checked_sub(1)
                            .expect("a positive fixed word start has a predecessor")],
                    );
                let has_right_boundary = word_end == haystack.len()
                    || !is_ascii_word(haystack[word_end]);
                if has_left_boundary && has_right_boundary {
                    let candidate = &haystack[word_start..word_end];
                    let rejected_by_secondary = secondary_active
                        && self.wide_anchor.as_ref().is_some_and(|wide| {
                            !wide.secondary_columns_match(candidate)
                        });
                    if !rejected_by_secondary
                        && self.dictionary.lookup_at_or_after(candidate, 0).is_some()
                    {
                        return Ok(Some(Match {
                            start: word_start,
                            end: word_end,
                        }));
                    }
                    // This complete fixed-width maximal word is not in the
                    // dictionary. Skip it as one unit without a separate
                    // backward/forward segmentation pass.
                    cursor = word_end;
                    let batched_secondary = batched_secondary_available
                        && self.wide_anchor.as_ref().is_some_and(|wide| {
                            wide.admits_correlated_remainder(
                                window.end().saturating_sub(cursor),
                            )
                        });
                    let packed_sample_is_dense = batched_secondary
                        || self.wide_anchor.as_ref().is_some_and(|wide| {
                            wide.rejection_sample_is_dense(
                                &haystack[cursor..window.end()],
                            )
                        });
                    let correlated_sample_is_dense = batched_secondary
                        && correlated_sample_available
                        && self.wide_anchor.as_ref().is_some_and(|wide| {
                            wide.correlated_columns.as_ref().is_some_and(|columns| {
                                columns.sample_has_packed_prefix_candidates(
                                    haystack,
                                    cursor,
                                    window.end(),
                                )
                            })
                        });
                    correlated_sample_available = false;
                    let probe_after_rejection = if batched_secondary {
                        secondary_active || !correlated_sample_is_dense
                    } else {
                        !secondary_available || secondary_active
                    };
                    secondary_active = secondary_available
                        && (!batched_secondary || correlated_sample_is_dense);
                    correlated_secondary_active = secondary_active && batched_secondary;
                    if probe_after_rejection
                        && let Some((probe, max_work)) = packed.take()
                    {
                        let maximum_probe_bytes = (!packed_sample_is_dense)
                            .then_some(WIDE_REJECTION_PACKED_PROBE_BYTES);
                        match self.probe_packed_value(
                            probe,
                            haystack,
                            window,
                            cursor,
                            max_work,
                            maximum_probe_bytes,
                        )? {
                            PackedProbeResult::Exhausted => return Ok(None),
                            PackedProbeResult::Match(matched) => return Ok(Some(matched)),
                            PackedProbeResult::ResumeAt(resume) => {
                                cursor = resume;
                                secondary_active = secondary_available && !batched_secondary;
                                correlated_secondary_active = false;
                            }
                        }
                    }
                    continue;
                }
            }
            let (word_start, is_word_start) =
                scan_ascii_word_start_value(haystack, anchor_position, window.start());
            let Some(word_end) =
                scan_ascii_word_end_value(haystack, anchor_position, window.end())?
            else {
                return Ok(None);
            };
            if word_end <= anchor_position {
                return Err(SearchError::InternalInvariant {
                    detail: "a value fixed-column anchor did not advance",
                });
            }
            let word_bytes =
                word_end
                    .checked_sub(word_start)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "value fixed-column maximal-word width",
                    })?;
            if is_word_start
                && word_bytes <= self.maximum_word_bytes
                && self
                    .dictionary
                    .lookup_at_or_after(&haystack[word_start..word_end], 0)
                    .is_some()
            {
                return Ok(Some(Match {
                    start: word_start,
                    end: word_end,
                }));
            }
            cursor = word_end;
            let batched_secondary = batched_secondary_available
                && self.wide_anchor.as_ref().is_some_and(|wide| {
                    wide.admits_correlated_remainder(window.end().saturating_sub(cursor))
                });
            let correlated_sample_is_dense = batched_secondary
                && correlated_sample_available
                && !secondary_active
                && self.wide_anchor.as_ref().is_some_and(|wide| {
                    wide.correlated_columns.as_ref().is_some_and(|columns| {
                        columns.sample_has_packed_prefix_candidates(
                            haystack,
                            cursor,
                            window.end(),
                        )
                    })
                });
            correlated_sample_available = false;
            if correlated_sample_is_dense {
                secondary_active = true;
                correlated_secondary_active = true;
                continue;
            }
            if let Some((probe, max_work)) = packed.take() {
                let maximum_probe_bytes = (!batched_secondary
                    && self.wide_anchor.as_ref().is_none_or(|wide| {
                        !wide.rejection_sample_is_dense(&haystack[cursor..window.end()])
                    }))
                .then_some(WIDE_REJECTION_PACKED_PROBE_BYTES);
                match self.probe_packed_value(
                    probe,
                    haystack,
                    window,
                    cursor,
                    max_work,
                    maximum_probe_bytes,
                )? {
                    PackedProbeResult::Exhausted => return Ok(None),
                    PackedProbeResult::Match(matched) => return Ok(Some(matched)),
                    PackedProbeResult::ResumeAt(resume) => {
                        cursor = resume;
                        secondary_active = secondary_available && !batched_secondary;
                        correlated_secondary_active = false;
                    }
                }
            }
        }
    }

    fn probe_packed_value(
        &self,
        packed: &PackedLiteralSetPlan,
        haystack: &[u8],
        window: SearchWindow,
        cursor: usize,
        max_work: usize,
        maximum_probe_bytes: Option<usize>,
    ) -> Result<PackedProbeResult, SearchError> {
        if cursor >= window.end() {
            return Ok(PackedProbeResult::Exhausted);
        }
        let packed_build = packed.build_accounting();
        let probe_end = if let Some(maximum_probe_bytes) = maximum_probe_bytes {
            let probe_bytes = maximum_probe_bytes.max(packed_build.max_pattern_bytes);
            cursor
                .checked_add(probe_bytes)
                .map_or(window.end(), |end| end.min(window.end()))
        } else {
            window.end()
        };
        let attempt = packed.find_window(
            haystack,
            PackedWindow::new(cursor, probe_end),
            PackedLiteralSetSearchLimits { max_work },
        );
        let (candidate, _) = match attempt {
            Ok(result) => result,
            Err(
                PackedLiteralSetError::WorkLimit { .. }
                | PackedLiteralSetError::ArithmeticOverflow { .. },
            ) => return Ok(PackedProbeResult::ResumeAt(cursor)),
            Err(_) => {
                return Err(SearchError::InternalInvariant {
                    detail:
                        "packed wide-column probe failed after construction and search preflight",
                });
            }
        };
        let Some((candidate_start, _)) = candidate else {
            if probe_end == window.end() {
                return Ok(PackedProbeResult::Exhausted);
            }
            let overlap = packed_build.max_pattern_bytes.saturating_sub(1);
            let resume = probe_end.checked_sub(overlap).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "bounded packed wide-column resume",
                },
            )?;
            if resume <= cursor {
                return Err(SearchError::InternalInvariant {
                    detail: "a bounded packed wide-column probe did not advance",
                });
            }
            return Ok(PackedProbeResult::ResumeAt(resume));
        };
        let (word_start, is_word_start) =
            scan_ascii_word_start_value(haystack, candidate_start, window.start());
        let Some(word_end) =
            scan_ascii_word_end_value(haystack, candidate_start, window.end())?
        else {
            return Ok(PackedProbeResult::Exhausted);
        };
        if word_end <= candidate_start {
            return Err(SearchError::InternalInvariant {
                detail: "a packed wide-column candidate did not advance through its word",
            });
        }
        let word_bytes =
            word_end
                .checked_sub(word_start)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "packed wide-column maximal-word width",
                })?;
        if is_word_start
            && word_bytes <= self.maximum_word_bytes
            && self
                .dictionary
                .lookup_at_or_after(&haystack[word_start..word_end], 0)
                .is_some()
        {
            return Ok(PackedProbeResult::Match(Match {
                start: word_start,
                end: word_end,
            }));
        }
        Ok(PackedProbeResult::ResumeAt(word_end))
    }

    fn search_upper_bounds(
        &self,
        haystack: &[u8],
        window: SearchWindow,
    ) -> Result<SearchUpperBounds, SearchError> {
        if window.start() > window.end() || window.end() > haystack.len() {
            return Err(SearchError::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len: haystack.len(),
            });
        }
        let window_bytes = window.end().checked_sub(window.start()).ok_or(
            SearchError::ArithmeticOverflow {
                computation: "guarded search window width",
            },
        )?;
        if self.one_byte.is_some() {
            let anchor_work = window_bytes.checked_mul(3).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "one-byte boundary-mask work bound",
                },
            )?;
            let contextual_bytes = window_bytes
                .checked_add(usize::from(window.start() != 0))
                .and_then(|bytes| {
                    bytes.checked_add(usize::from(window.end() < haystack.len()))
                })
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "one-byte boundary context bound",
                })?;
            let candidate_words = window_bytes / 2 + window_bytes % 2;
            return Ok(SearchUpperBounds {
                anchor_positions: window_bytes,
                anchor_work,
                contextual_bytes,
                candidate_words,
                lookup_steps: 0,
                total_work: anchor_work,
                scratch_bytes: 0,
            });
        }
        let filter_positions = window
            .end()
            .checked_sub(window.start())
            .and_then(|width| width.checked_add(1))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "candidate-filter position bound",
            })?;
        let anchor_positions = filter_positions;
        let anchor_work = filter_positions;
        let contextual_bytes = window
            .end()
            .checked_sub(window.start())
            .and_then(|bytes| bytes.checked_add(usize::from(window.end() < haystack.len())))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "guarded context byte bound",
            })?;
        let dictionary = self.dictionary.lookup_upper_bounds(contextual_bytes)?;
        let total_work = anchor_work.checked_add(dictionary.total_work).ok_or(
            SearchError::ArithmeticOverflow {
                computation: "combined search work bound",
            },
        )?;
        Ok(SearchUpperBounds {
            anchor_positions,
            anchor_work,
            contextual_bytes,
            candidate_words: dictionary.candidate_words,
            lookup_steps: dictionary.lookup_steps,
            total_work,
            scratch_bytes: 0,
        })
    }
}

/// Bound the guarded prerequisite construction by the same ordered-language,
/// work and memory ceilings as the fixed-column owner it is attempting to build.
/// The dictionary's persistent cap is additionally restricted to the bytes
/// still available after facade-owned source and capture-name storage.
pub(crate) fn extraction_limits(
    packed: PackedLiteralSetBuildLimits,
    max_plan_persistent_bytes: usize,
) -> finite::GuardedFiniteBuildLimits {
    let inline_storage_bytes = Plan::inline_storage_bytes();
    let dictionary_persistent_bytes = packed
        .max_persistent_bytes
        .min(max_plan_persistent_bytes)
        .saturating_sub(inline_storage_bytes);
    let dictionary_work = u64::try_from(packed.max_build_work).unwrap_or(u64::MAX);
    finite::GuardedFiniteBuildLimits {
        dictionary: DictionaryBuildLimits {
            max_words: packed.max_patterns,
            max_packed_bytes: packed.max_pattern_bytes,
            max_identity_bytes: packed.max_build_bytes,
            max_sort_comparisons: usize::MAX,
            max_allocations: usize::MAX,
            max_initialized_bytes: packed.max_build_bytes,
            max_build_work: dictionary_work,
            max_scratch_bytes: packed.max_build_bytes,
            max_persistent_bytes: dictionary_persistent_bytes,
            max_peak_bytes: packed.max_build_bytes,
        },
        max_scratch_bytes: packed.max_build_bytes,
        max_peak_bytes: packed.max_build_bytes,
    }
}

fn enforce_limits(upper: SearchUpperBounds, limits: SearchLimits) -> Result<(), SearchError> {
    if upper.scratch_bytes > limits.max_scratch_bytes {
        return Err(SearchError::ScratchLimit {
            needed: upper.scratch_bytes,
            limit: limits.max_scratch_bytes,
        });
    }
    let needed = u64::try_from(upper.total_work).map_err(|_| SearchError::WorkLimit {
        needed: u64::MAX,
        limit: limits.max_work,
    })?;
    if needed > limits.max_work {
        return Err(SearchError::WorkLimit {
            needed,
            limit: limits.max_work,
        });
    }
    Ok(())
}

fn close_search_accounting(
    matched: Option<Match>,
    upper_bounds: SearchUpperBounds,
    mut actual: SearchActual,
) -> Result<(Option<Match>, SearchAccounting), SearchError> {
    actual.total_work = actual
        .anchor_work
        .checked_add(actual.predecessor_reads)
        .and_then(|work| work.checked_add(actual.word_scan_bytes))
        .and_then(|work| work.checked_add(actual.lookup_steps))
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "actual fixed-column total work",
        })?;
    if actual.anchor_calls > upper_bounds.anchor_positions
        || actual.anchor_positions > upper_bounds.anchor_positions
        || actual.anchor_work > upper_bounds.anchor_work
        || actual.predecessor_reads > upper_bounds.candidate_words
        || actual.word_scan_bytes > upper_bounds.contextual_bytes
        || actual.candidate_words > upper_bounds.candidate_words
        || actual.lookup_steps > upper_bounds.lookup_steps
        || actual.total_work > upper_bounds.total_work
    {
        return Err(SearchError::InternalInvariant {
            detail: "fixed-column actual counters exceeded their closed upper bounds",
        });
    }
    Ok((
        matched,
        SearchAccounting {
            upper_bounds,
            actual,
        },
    ))
}

fn charge_anchor(actual: &mut SearchActual, positions: usize) -> Result<(), SearchError> {
    actual.anchor_positions =
        checked_add(actual.anchor_positions, positions, "fixed-column positions")?;
    actual.anchor_work = checked_add(
        actual.anchor_work,
        positions,
        "accumulated fixed-column work",
    )?;
    Ok(())
}

fn scan_ascii_word_start(
    haystack: &[u8],
    anchor: usize,
    window_start: usize,
    actual: &mut SearchActual,
) -> Result<(usize, bool), SearchError> {
    if !haystack
        .get(anchor)
        .is_some_and(|&byte| is_ascii_word(byte))
    {
        return Err(SearchError::InternalInvariant {
            detail: "a fixed-column member was not an ASCII-word byte",
        });
    }
    let mut start = anchor;
    while start > window_start {
        let predecessor = start
            .checked_sub(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "maximal-word predecessor",
            })?;
        if !is_ascii_word(haystack[predecessor]) {
            actual.predecessor_reads =
                checked_add(actual.predecessor_reads, 1, "predecessor reads")?;
            return Ok((start, true));
        }
        actual.word_scan_bytes =
            checked_add(actual.word_scan_bytes, 1, "backward word scan bytes")?;
        start = predecessor;
    }
    if start == 0 {
        return Ok((start, true));
    }
    actual.predecessor_reads = checked_add(actual.predecessor_reads, 1, "predecessor reads")?;
    let predecessor = start
        .checked_sub(1)
        .expect("positive maximal-word start has a predecessor");
    Ok((start, !is_ascii_word(haystack[predecessor])))
}

fn scan_ascii_word_start_value(
    haystack: &[u8],
    anchor: usize,
    window_start: usize,
) -> (usize, bool) {
    debug_assert!(
        haystack
            .get(anchor)
            .is_some_and(|&byte| is_ascii_word(byte))
    );
    let mut start = anchor;
    while start > window_start {
        let predecessor = start
            .checked_sub(1)
            .expect("positive maximal-word cursor has a predecessor");
        if !is_ascii_word(haystack[predecessor]) {
            break;
        }
        start = predecessor;
    }
    let is_word_start = if start == 0 {
        true
    } else {
        let predecessor = start
            .checked_sub(1)
            .expect("positive maximal-word start has a predecessor");
        !is_ascii_word(haystack[predecessor])
    };
    (start, is_word_start)
}

fn scan_ascii_word_end(
    haystack: &[u8],
    start: usize,
    window_end: usize,
    actual: &mut SearchActual,
) -> Result<Option<usize>, SearchError> {
    let context_end = window_end
        .checked_add(usize::from(window_end < haystack.len()))
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "right assertion context end",
        })?;
    let mut end = start;
    while end < context_end {
        actual.word_scan_bytes = checked_add(actual.word_scan_bytes, 1, "word scan bytes")?;
        if !is_ascii_word(haystack[end]) {
            return Ok(Some(end));
        }
        end = end.checked_add(1).ok_or(SearchError::ArithmeticOverflow {
            computation: "maximal word end",
        })?;
    }
    Ok((end == window_end).then_some(end))
}

fn scan_ascii_word_end_value(
    haystack: &[u8],
    start: usize,
    window_end: usize,
) -> Result<Option<usize>, SearchError> {
    let context_end = window_end
        .checked_add(usize::from(window_end < haystack.len()))
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "value right assertion context end",
        })?;
    let mut end = start;
    while end < context_end {
        if !is_ascii_word(haystack[end]) {
            return Ok(Some(end));
        }
        end = end.checked_add(1).ok_or(SearchError::ArithmeticOverflow {
            computation: "value maximal word end",
        })?;
    }
    Ok((end == window_end).then_some(end))
}

fn add_lookup(actual: &mut SearchActual, lookup: LookupActual) -> Result<(), SearchError> {
    actual.fingerprint_bytes = checked_add(
        actual.fingerprint_bytes,
        lookup.fingerprint_bytes,
        "fingerprint bytes",
    )?;
    actual.binary_search_comparisons = checked_add(
        actual.binary_search_comparisons,
        lookup.binary_search_comparisons,
        "binary-search comparisons",
    )?;
    actual.collision_slots = checked_add(
        actual.collision_slots,
        lookup.collision_slots,
        "collision slots",
    )?;
    actual.full_equality_checks = checked_add(
        actual.full_equality_checks,
        lookup.full_equality_checks,
        "full-equality checks",
    )?;
    actual.full_equality_bytes = checked_add(
        actual.full_equality_bytes,
        lookup.full_equality_bytes,
        "full-equality bytes",
    )?;
    actual.lookup_steps = checked_add(
        actual.lookup_steps,
        lookup.steps().ok_or(SearchError::ArithmeticOverflow {
            computation: "one dictionary lookup",
        })?,
        "lookup steps",
    )?;
    Ok(())
}

fn checked_add(left: usize, right: usize, computation: &'static str) -> Result<usize, SearchError> {
    left.checked_add(right)
        .ok_or(SearchError::ArithmeticOverflow { computation })
}

fn is_ascii_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::{
        ASCII_WIDE_BYTES, CorrelatedColumns, FIXED_PACKED_PLAN_ID, ONE_BYTE_PLAN_ID,
        PLAN_ID, PackedProbeResult, Plan, SearchError, SingleByteWordSet,
        WIDE_CORRELATED_BOUNDARY_COLUMNS, WIDE_PACKED_PLAN_ID, WIDE_PACKED_PREFIX_BYTES,
        WIDE_CORRELATED_SAMPLE_BYTES, WIDE_RANKED_COLUMN_LIMIT,
        WIDE_REJECTION_PACKED_PROBE_BYTES,
        WIDE_SECONDARY_COLUMN_LIMIT, WideByteAnchor, WideFindResult,
        correlated_columns_dimensions, extraction_limits, prefer_bulk_nonmember_scanner,
    };
    #[cfg(target_arch = "aarch64")]
    use super::{SingleByteMemberResult, SingleBytePrimary};
    use crate::{
        Match, SearchLimits, SearchWindow,
        guarded_ascii_word::{BuildDimensions, BuildLimits, Dictionary, Guard, SourceWord},
    };
    use fre_kernels::{
        ASCII_CLASSIFIER_BUILD_WORK, ASCII_NONMEMBER_RUN_SCANNER_BUILD_WORK,
        ASCII_RUN_SCANNER_BUILD_WORK,
        PackedLiteralSetBuildLimits, PackedLiteralSetError, PackedLiteralSetPlan, VectorKind,
    };

    fn dictionary_with_guards(words: &[&[u8]], left: Guard, right: Guard) -> Dictionary {
        let packed_bytes = words.iter().map(|word| word.len()).sum();
        Dictionary::build_precounted(
            BuildDimensions {
                words: words.len(),
                packed_bytes,
            },
            words.iter().map(|word| SourceWord {
                bytes: word,
                left,
                right,
            }),
            BuildLimits::unlimited(),
        )
        .unwrap()
    }

    fn plan_with_guards(words: &[&[u8]], left: Guard, right: Guard) -> Plan {
        let dictionary = dictionary_with_guards(words, left, right);
        Plan::build(
            dictionary,
            PackedLiteralSetBuildLimits::default(),
            usize::MAX,
        )
        .unwrap()
    }

    fn plan(words: &[&[u8]]) -> Plan {
        plan_with_guards(words, Guard::LeftBoundary, Guard::RightBoundary)
    }

    #[test]
    fn complete_word_lookup_preserves_same_start_alternative_fallback() {
        let plan = plan(&[b"a", b"ab", b"cat"]);
        let (matched, accounting) = plan
            .find_window(
                b"ab cat",
                SearchWindow::new(0, 6),
                SearchLimits::unlimited(),
            )
            .unwrap();
        assert_eq!(matched, Some(Match { start: 0, end: 2 }));
        assert!(accounting.actual.candidate_words > 0);
        assert_eq!(plan.plan_id(), PLAN_ID);
        assert_eq!(
            PLAN_ID,
            "guarded-ascii-word-literal-set.fixed-column-dictionary.v4",
        );
    }

    #[test]
    fn misaligned_early_anchor_authenticates_the_complete_containing_word() {
        // The singleton middle column is more selective than the four-member
        // first and last columns. The first `z` in `zza` is therefore a
        // deliberately misaligned occurrence before that word's proved fixed
        // column.
        let plan = plan(&[b"zza", b"azb", b"czc", b"dzd"]);
        assert_eq!(plan.anchor.offset, 1);
        assert_eq!(plan.anchor.bytes[0], b'z');
        assert_eq!(plan.fixed_word_bytes, Some(3));
        for (haystack, expected) in [
            (b"zza".as_slice(), Some(Match { start: 0, end: 3 })),
            (b"xx zza yy".as_slice(), Some(Match { start: 3, end: 6 })),
            (b"zzax zza".as_slice(), Some(Match { start: 5, end: 8 })),
        ] {
            let actual = plan
                .find_window_value(
                    haystack,
                    SearchWindow::full(haystack),
                    SearchLimits::unlimited(),
                )
                .unwrap();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn fixed_packed_hybrid_preserves_boundaries_windows_and_rejection_order() {
        let plan = plan(&[b"ya", b"yb"]);
        let Some(_) = plan.fixed_packed.as_ref() else {
            return;
        };
        assert_eq!(plan.plan_id(), FIXED_PACKED_PLAN_ID);

        let decoys = b"y9!y9!y9!y9!y9!y9!y9!y9!xyb!ybq!yb!";
        assert_eq!(
            plan.find_window_value(
                decoys,
                SearchWindow::full(decoys),
                SearchLimits::unlimited(),
            )
            .unwrap(),
            Some(Match { start: 32, end: 34 }),
        );
        for (haystack, window, expected) in [
            (
                b"!yb!".as_slice(),
                SearchWindow::new(1, 3),
                Some(Match { start: 1, end: 3 }),
            ),
            (
                b"xyb!".as_slice(),
                SearchWindow::new(1, 3),
                None,
            ),
            (
                b"!ybx".as_slice(),
                SearchWindow::new(1, 3),
                None,
            ),
        ] {
            assert_eq!(
                plan.find_window_value(haystack, window, SearchLimits::unlimited())
                    .unwrap(),
                expected,
            );
        }
        for (haystack, expected) in [
            (b"yb!".as_slice(), Some(Match { start: 0, end: 2 })),
            (b"!!!yb!".as_slice(), Some(Match { start: 3, end: 5 })),
            (b"~~~~".as_slice(), None),
        ] {
            assert_eq!(
                plan.find_window_value(
                    haystack,
                    SearchWindow::full(haystack),
                    SearchLimits::unlimited(),
                )
                .unwrap(),
                expected,
            );
        }
    }

    #[test]
    fn fixed_packed_hybrid_keeps_duplicate_source_priority() {
        let plan = plan(&[b"ya", b"ya", b"yb"]);
        let Some(_) = plan.fixed_packed.as_ref() else {
            return;
        };
        assert_eq!(plan.dictionary.lookup(b"ya").unwrap().source_index, 0);
        let haystack = b"y9!y9!y9!y9!y9!y9!ya!";
        assert_eq!(
            plan.find_window_value(
                haystack,
                SearchWindow::full(haystack),
                SearchLimits::unlimited(),
            )
            .unwrap(),
            Some(Match { start: 18, end: 20 }),
        );
    }

    #[test]
    fn fixed_packed_hybrid_storage_and_fallback_are_exact() {
        let words: &[&[u8]] = &[b"ya", b"yb"];
        let probe = plan(words);
        let Some(packed) = probe.fixed_packed.as_ref() else {
            return;
        };
        let dictionary_bytes = probe.dictionary.build_accounting().actual.persistent_bytes;
        let packed_build = packed.build_accounting();
        let exact_persistent = dictionary_bytes
            + Plan::inline_storage_bytes()
            + size_of::<PackedLiteralSetPlan>()
            + packed_build.persistent_bytes;
        assert_eq!(probe.storage_bytes(), exact_persistent);

        let dictionary = dictionary_with_guards(
            words,
            Guard::LeftBoundary,
            Guard::RightBoundary,
        );
        let dictionary_work =
            usize::try_from(dictionary.build_accounting().actual.build_work).unwrap();
        let selection_work = words.len() + words[0].len() * (words.len() + 3);
        let base_persistent = dictionary_bytes + Plan::inline_storage_bytes();
        let fallback = Plan::build(
            dictionary,
            PackedLiteralSetBuildLimits {
                max_build_work: dictionary_work + selection_work,
                max_build_bytes: base_persistent,
                max_persistent_bytes: base_persistent,
                ..PackedLiteralSetBuildLimits::default()
            },
            base_persistent,
        )
        .unwrap();
        assert!(fallback.fixed_packed.is_none());
        assert_eq!(fallback.plan_id(), PLAN_ID);
        assert_eq!(fallback.storage_bytes(), base_persistent);
    }

    #[test]
    fn fixed_packed_probe_admission_closes_at_the_first_rejection() {
        let plan = plan(&[b"ya", b"yb"]);
        let Some(packed) = plan.fixed_packed.as_ref() else {
            return;
        };
        let haystack = b"y9!y9!y9!y9!y9!y9!yb!";
        let window = SearchWindow::full(haystack);
        let upper = plan.search_upper_bounds(haystack, window).unwrap();
        let build = packed.build_accounting();
        let positions = window.end() - window.start() + 1;
        let packed_work = positions * (build.pattern_bytes + build.patterns);
        let combined_work = upper.total_work + packed_work;
        let limits = |work: usize| SearchLimits {
            max_work: u64::try_from(work).unwrap(),
            max_scratch_bytes: 0,
        };

        assert!(
            plan.admit_fixed_value_packed_probe(
                window,
                upper,
                limits(combined_work - 1),
            )
            .is_none(),
        );
        let admitted = plan
            .admit_fixed_value_packed_probe(window, upper, limits(combined_work))
            .unwrap();
        assert_eq!(admitted.1, packed_work);
        assert_eq!(admitted.2, build.patterns);
        assert_eq!(admitted.3, build.simd_minimum_haystack_bytes.max(1));

        let incumbent_only = limits(upper.total_work);
        assert_eq!(
            plan.find_window_value(haystack, window, incumbent_only)
                .unwrap(),
            Some(Match { start: 18, end: 20 }),
        );
    }

    #[test]
    fn languages_without_a_sparse_complete_column_use_the_wide_packed_route() {
        let dictionary = dictionary_with_guards(
            &[b"_x", b"x1", b"AB", b"ab", b"z9"],
            Guard::LeftBoundary,
            Guard::RightBoundary,
        );
        let plan = match Plan::build(
            dictionary,
            PackedLiteralSetBuildLimits::default(),
            usize::MAX,
        ) {
            Ok(plan) => plan,
            Err(PackedLiteralSetError::UnsupportedTargetOrShape) => return,
            Err(error) => panic!("unexpected wide guarded-plan error: {error}"),
        };
        assert_eq!(plan.plan_id(), WIDE_PACKED_PLAN_ID);
        assert!(plan.wide_anchor.is_some());
        for (haystack, expected) in [
            (b"!a!x! z9".as_slice(), Some(Match { start: 6, end: 8 })),
            (b"\xffAB\x80".as_slice(), Some(Match { start: 1, end: 3 })),
            (b"alpha beta".as_slice(), None),
        ] {
            assert_eq!(
                plan.find_window_value(
                    haystack,
                    SearchWindow::full(haystack),
                    SearchLimits::unlimited(),
                )
                .unwrap(),
                expected,
            );
        }
    }

    #[test]
    fn wide_bulk_primitive_selection_preserves_the_widest_authenticated_route() {
        let scalar = VectorKind::Scalar;
        let fixed = VectorKind::Fixed { bytes: 32 };
        let scalable = VectorKind::Scalable;

        assert!(prefer_bulk_nonmember_scanner(scalar, scalar));
        assert!(!prefer_bulk_nonmember_scanner(scalar, fixed));
        assert!(!prefer_bulk_nonmember_scanner(scalar, scalable));
        for classifier in [scalar, fixed, scalable] {
            assert!(prefer_bulk_nonmember_scanner(fixed, classifier));
            assert!(prefer_bulk_nonmember_scanner(scalable, classifier));
        }

        let plan = plan(&[b"aj", b"eq", b"tz", b"iQ"]);
        let wide = plan.wide_anchor.as_ref().unwrap();
        let scanner = wide.nonmembers.selection().vector;
        let classifier = wide.members.selection().wide().vector;
        assert_eq!(
            wide.use_bulk_nonmember_scanner(),
            prefer_bulk_nonmember_scanner(scanner, classifier),
        );
        if matches!(scanner, VectorKind::Scalar)
            && !matches!(classifier, VectorKind::Scalar)
        {
            assert!(!wide.use_bulk_nonmember_scanner());
        }
        if !matches!(scanner, VectorKind::Scalar) {
            assert!(wide.use_bulk_nonmember_scanner());
        }
    }

    #[test]
    fn selected_wide_bulk_route_matches_scalar_membership_across_blocks() {
        let plan = plan(&[b"aj", b"eq", b"tz", b"iQ"]);
        let wide = plan.wide_anchor.as_ref().unwrap();
        let members = wide.members.set();
        let reject = (u8::MIN..=0x7f)
            .find(|&byte| !members.contains(byte))
            .unwrap();
        let member = (u8::MIN..=0x7f)
            .find(|&byte| members.contains(byte))
            .unwrap();

        for alignment in 0..ASCII_WIDE_BYTES {
            for len in 0..=ASCII_WIDE_BYTES * 6 {
                let mut storage = vec![reject; alignment + len];
                let haystack = &mut storage[alignment..];
                if alignment % 2 != 0 {
                    for position in (17..len).step_by(47) {
                        haystack[position] = 0x80;
                    }
                }
                if len % 2 != 0 {
                    haystack[len - 1] = member;
                }
                let expected = haystack.iter().position(|&byte| members.contains(byte));
                assert_eq!(
                    wide.find(haystack),
                    expected,
                    "alignment={alignment} len={len}",
                );
            }
        }
    }

    #[test]
    fn wide_one_byte_sets_complete_boundaries_before_returning_members() {
        let plan = plan(&[b"a", b"B", b"7", b"_"]);
        assert_eq!(plan.plan_id(), ONE_BYTE_PLAN_ID);
        assert!(plan.one_byte.is_some());
        assert!(plan.wide_anchor.is_none());
        let one_byte = plan.one_byte.as_ref().unwrap();
        #[cfg(target_arch = "aarch64")]
        {
            assert_eq!(
                one_byte.find_members_value(b"aa!aa!aa!aa!aa!", 0, 15),
                SingleByteMemberResult::BoundaryResume(11),
            );
            assert_eq!(
                one_byte.find_members_value(
                    &[0x80, 0xff, b'!', 0x00, 0xc1, b'!', b'a', b'!'],
                    0,
                    8,
                ),
                SingleByteMemberResult::Match(6),
            );
            assert_eq!(
                one_byte.find_members_value(&[0x80, 0xff, b'!', 0x00, 0xc1], 0, 5),
                SingleByteMemberResult::Exhausted,
            );
            let high_block = [0xff; 32];
            let mut primary = None;
            assert_eq!(
                one_byte.classify_block_32(
                    &high_block,
                    0,
                    &high_block,
                    &mut primary,
                    false,
                ),
                (0, 32),
            );
            assert_eq!(primary, Some(SingleBytePrimary::ClassifiedMembers));
            let punctuation_block = [b'!'; 32];
            assert_eq!(
                one_byte.classify_block_32(
                    &punctuation_block,
                    0,
                    &punctuation_block,
                    &mut primary,
                    false,
                ),
                (0, 32),
            );
            assert_eq!(primary, Some(SingleBytePrimary::Members));
        }
        let mut cutover_block = [b'z'; 32];
        cutover_block[6] = b'a';
        let isolated_four =
            (1_u32 << 0) | (1_u32 << 2) | (1_u32 << 4) | (1_u32 << 6);
        let isolated_five = isolated_four | (1_u32 << 8);
        assert_eq!(
            one_byte.member_mask_32(&cutover_block, isolated_four, false),
            1_u32 << 6,
        );
        assert_eq!(
            one_byte.member_mask_32(&cutover_block, isolated_five, false),
            1_u32 << 6,
        );

        for (haystack, window, expected) in [
            (b"a".as_slice(), SearchWindow::new(0, 1), Some(Match { start: 0, end: 1 })),
            (b"xa!".as_slice(), SearchWindow::new(1, 2), None),
            (b"!ax".as_slice(), SearchWindow::new(1, 2), None),
            (
                b"x!a!".as_slice(),
                SearchWindow::new(2, 3),
                Some(Match { start: 2, end: 3 }),
            ),
            (
                b"\xffa\x80".as_slice(),
                SearchWindow::new(1, 2),
                Some(Match { start: 1, end: 2 }),
            ),
        ] {
            let value = plan
                .find_window_value(haystack, window, SearchLimits::unlimited())
                .unwrap();
            let (accounted, accounting) = plan
                .find_window(haystack, window, SearchLimits::unlimited())
                .unwrap();
            assert_eq!(value, expected);
            assert_eq!(accounted, expected);
            assert_eq!(accounting.actual.lookup_steps, 0);
            assert_eq!(accounting.upper_bounds.lookup_steps, 0);
        }

        for lane in [7_usize, 8, 15, 16, 31, 32, 63, 64, 95, 96] {
            let mut haystack = vec![b'!'; 129];
            haystack[lane] = b'a';
            assert_eq!(
                plan.find_window_value(
                    &haystack,
                    SearchWindow::full(&haystack),
                    SearchLimits::unlimited(),
                )
                .unwrap(),
                Some(Match {
                    start: lane,
                    end: lane + 1,
                }),
            );
            let (accounted, accounting) = plan
                .find_window(
                    &haystack,
                    SearchWindow::full(&haystack),
                    SearchLimits::unlimited(),
                )
                .unwrap();
            assert_eq!(
                accounted,
                Some(Match {
                    start: lane,
                    end: lane + 1,
                }),
            );
            assert!(accounting.actual.total_work <= accounting.upper_bounds.total_work);
        }

        let mut haystack = vec![b'!'; 129];
        let address = haystack.as_ptr();
        for positions in [&[9_usize, 17, 25, 33][..], &[9_usize, 17, 25, 33, 41][..]] {
            haystack.fill(b'!');
            for &position in positions {
                haystack[position] = b'z';
            }
            haystack[96] = b'_';
            assert_eq!(haystack.as_ptr(), address);
            assert_eq!(
                plan.find_window_value(
                    &haystack,
                    SearchWindow::full(&haystack),
                    SearchLimits::unlimited(),
                )
                .unwrap(),
                Some(Match { start: 96, end: 97 }),
            );
        }

        let mut phase_change = vec![b'!'; 129];
        phase_change[40..80].fill(b'a');
        phase_change[96] = b'_';
        let expected = Some(Match { start: 96, end: 97 });
        assert_eq!(
            plan.find_window_value(
                &phase_change,
                SearchWindow::full(&phase_change),
                SearchLimits::unlimited(),
            )
            .unwrap(),
            expected,
        );
        assert_eq!(
            plan.find_window(
                &phase_change,
                SearchWindow::full(&phase_change),
                SearchLimits::unlimited(),
            )
            .unwrap()
            .0,
            expected,
        );

        let mut short_word_phase = vec![b'!'; 161];
        for word_start in (40..104).step_by(3) {
            short_word_phase[word_start..word_start + 2].fill(b'a');
        }
        short_word_phase[128] = b'_';
        let expected = Some(Match {
            start: 128,
            end: 129,
        });
        assert_eq!(
            plan.find_window_value(
                &short_word_phase,
                SearchWindow::full(&short_word_phase),
                SearchLimits::unlimited(),
            )
            .unwrap(),
            expected,
        );
        assert_eq!(
            plan.find_window(
                &short_word_phase,
                SearchWindow::full(&short_word_phase),
                SearchLimits::unlimited(),
            )
            .unwrap()
            .0,
            expected,
        );

        for (haystack, expected) in [
            {
                let mut haystack = vec![b'!'; 129];
                haystack[40] = 0xff;
                haystack[48] = b'a';
                (haystack, Some(Match { start: 48, end: 49 }))
            },
            {
                let mut haystack = vec![b'!'; 129];
                haystack[40..80].fill(0xff);
                haystack[96] = b'a';
                (haystack, Some(Match { start: 96, end: 97 }))
            },
            {
                let mut haystack = vec![b'!'; 52];
                haystack[40] = 0xff;
                haystack[50] = b'a';
                (haystack, Some(Match { start: 50, end: 51 }))
            },
        ] {
            assert_eq!(
                plan.find_window_value(
                    &haystack,
                    SearchWindow::full(&haystack),
                    SearchLimits::unlimited(),
                )
                .unwrap(),
                expected,
            );
            assert_eq!(
                plan.find_window(
                    &haystack,
                    SearchWindow::full(&haystack),
                    SearchLimits::unlimited(),
                )
                .unwrap()
                .0,
                expected,
            );
        }

        let all_word_storage = (0_u8..=127)
            .filter(|&byte| super::is_ascii_word(byte))
            .map(|byte| [byte])
            .collect::<Vec<_>>();
        let all_word_refs = all_word_storage
            .iter()
            .map(|word| word.as_slice())
            .collect::<Vec<_>>();
        let all_words = self::plan(&all_word_refs);
        assert_eq!(all_words.plan_id(), ONE_BYTE_PLAN_ID);
        assert!(
            all_words
                .one_byte
                .as_ref()
                .is_some_and(|one_byte| one_byte.complete_word_set()),
        );
        assert_eq!(
            all_words
                .find_window_value(
                    b"x!Z!",
                    SearchWindow::new(2, 3),
                    SearchLimits::unlimited(),
                )
                .unwrap(),
            Some(Match { start: 2, end: 3 }),
        );
    }

    #[test]
    fn wide_packed_route_preserves_short_first_source_masking() {
        let dictionary = dictionary_with_guards(
            &[b"a", b"ab", b"cde", b"fghi", b"jklmn"],
            Guard::LeftBoundary,
            Guard::RightBoundary,
        );
        let plan = match Plan::build(
            dictionary,
            PackedLiteralSetBuildLimits::default(),
            usize::MAX,
        ) {
            Ok(plan) => plan,
            Err(PackedLiteralSetError::UnsupportedTargetOrShape) => return,
            Err(error) => panic!("unexpected wide guarded-plan error: {error}"),
        };
        assert_eq!(plan.plan_id(), WIDE_PACKED_PLAN_ID);
        for (haystack, expected) in [
            (b"ab".as_slice(), Some(Match { start: 0, end: 2 })),
            (b"xa ab".as_slice(), Some(Match { start: 3, end: 5 })),
            (b"\xffcde\x80".as_slice(), Some(Match { start: 1, end: 4 })),
        ] {
            let window = SearchWindow::full(haystack);
            let (accounted, accounting) = plan
                .find_window(haystack, window, SearchLimits::unlimited())
                .unwrap();
            assert_eq!(accounted, expected);
            let exact = u64::try_from(accounting.upper_bounds.total_work).unwrap();
            assert_eq!(
                plan.find_window_value(
                    haystack,
                    window,
                    SearchLimits {
                        max_work: exact,
                        max_scratch_bytes: 0,
                    },
                )
                .unwrap(),
                expected,
            );
        }
    }

    #[test]
    fn wide_packed_search_admission_closes_exactly() {
        let plan = plan(&[b"aj", b"eq", b"tz", b"iQ"]);
        assert_eq!(plan.plan_id(), WIDE_PACKED_PLAN_ID);
        assert_eq!(plan.anchor.offset, 1);
        let wide = plan.wide_anchor.as_ref().unwrap();
        assert!(wide.secondary_columns_match(b"ej"));
        assert!(!wide.secondary_columns_match(b"Xj"));

        let haystack = b"ej!Xj!tz!";
        let window = SearchWindow::full(haystack);
        let upper = plan.search_upper_bounds(haystack, window).unwrap();
        let packed_build = wide.packed.build_accounting();
        let positions = window.end() - window.start() + 1;
        let packed_work = positions * (packed_build.pattern_bytes + packed_build.patterns);
        let sample_work = (window.end() - window.start())
            .min(WIDE_CORRELATED_SAMPLE_BYTES)
            * (WIDE_PACKED_PREFIX_BYTES + 3);
        let secondary_work = upper.anchor_positions * WIDE_SECONDARY_COLUMN_LIMIT;
        let boundary_work = upper.anchor_positions * WIDE_CORRELATED_BOUNDARY_COLUMNS;
        let threshold =
            upper.total_work + packed_work + sample_work + secondary_work + boundary_work;
        let limits = |work: usize| SearchLimits {
            max_work: u64::try_from(work).unwrap(),
            max_scratch_bytes: 0,
        };

        assert_eq!(
            plan.value_packed_probe_work(window, upper, limits(threshold)),
            Some(packed_work),
        );
        assert_eq!(
            plan.value_packed_probe_work(window, upper, limits(threshold - 1)),
            None,
        );
        let expected = Some(Match { start: 6, end: 8 });
        for work in [threshold, threshold - 1, upper.total_work] {
            assert_eq!(
                plan.find_window_value(haystack, window, limits(work))
                    .unwrap(),
                expected,
            );
        }
        assert!(matches!(
            plan.find_window_value(haystack, window, limits(upper.total_work - 1)),
            Err(SearchError::WorkLimit { needed, limit })
                if needed == u64::try_from(upper.total_work).unwrap()
                    && limit + 1 == needed,
        ));
    }

    #[test]
    fn bounded_packed_probe_preserves_first_crossing_start() {
        let plan = plan(&[b"aj", b"eqbbb", b"tzccccc", b"iQxxxxxxx"]);
        assert_eq!(plan.anchor.offset, 1);
        assert_eq!(plan.maximum_word_bytes, 9);
        assert_eq!(plan.fixed_word_bytes, None);

        fn fixture(start: usize) -> Vec<u8> {
            let mut haystack = vec![b'!'; 1028];
            haystack[..2].copy_from_slice(b"ej");
            haystack[start..start + 9].copy_from_slice(b"iQxxxxxxx");
            haystack
        }

        let proved = fixture(1017);
        let resumed = fixture(1018);
        let window = SearchWindow::full(&proved);
        let upper = plan.search_upper_bounds(&proved, window).unwrap();
        let max_work = plan
            .value_packed_probe_work(window, upper, SearchLimits::unlimited())
            .unwrap();
        let wide = plan.wide_anchor.as_ref().unwrap();
        assert!(!wide.rejection_sample_is_dense(&proved[2..]));
        assert!(!wide.rejection_sample_is_dense(&resumed[2..]));

        match plan
            .probe_packed_value(
                wide.packed.as_ref(),
                &proved,
                window,
                2,
                max_work,
                Some(WIDE_REJECTION_PACKED_PROBE_BYTES),
            )
            .unwrap()
        {
            PackedProbeResult::Match(matched) => {
                assert_eq!(matched, Match { start: 1017, end: 1026 });
            }
            _ => panic!("E-L must be proved by the bounded packed prefix"),
        }
        match plan
            .probe_packed_value(
                wide.packed.as_ref(),
                &resumed,
                window,
                2,
                max_work,
                Some(WIDE_REJECTION_PACKED_PROBE_BYTES),
            )
            .unwrap()
        {
            PackedProbeResult::ResumeAt(resume) => assert_eq!(resume, 1018),
            _ => panic!("E-L+1 must remain visible to the wide continuation"),
        }
        assert_eq!(
            plan.find_window_value(&resumed, window, SearchLimits::unlimited())
                .unwrap(),
            Some(Match {
                start: 1018,
                end: 1027,
            }),
        );
    }

    #[test]
    fn dense_high_resume_preserves_nonzero_anchor_offset() {
        let plan = plan(&[b"aj", b"eq", b"tz", b"iQ"]);
        assert_eq!(plan.anchor.offset, 1);
        let wide = plan.wide_anchor.as_ref().unwrap();
        assert!(wide.range.is_none());

        fn fixture(high_bytes: usize) -> Vec<u8> {
            let mut haystack = vec![b'!'; 43];
            haystack[9..9 + high_bytes].fill(0xff);
            haystack[40..42].copy_from_slice(b"aj");
            haystack
        }

        let seven = fixture(7);
        assert!(matches!(
            wide.find_adaptive(&seven[1..]),
            WideFindResult::Anchor(40),
        ));
        let eight = fixture(8);
        assert!(matches!(
            wide.find_adaptive(&eight[1..]),
            WideFindResult::DenseHighResume(40),
        ));
        assert_eq!(
            plan.find_window_value(
                &eight,
                SearchWindow::full(&eight),
                SearchLimits::unlimited(),
            )
            .unwrap(),
            Some(Match { start: 40, end: 42 }),
        );
    }

    #[test]
    fn correlated_columns_preserve_block_lanes_and_exact_identity() {
        let words: &[&[u8]] = &[
            b"aaaaa", b"bbbbb", b"ccccc", b"ddddd", b"eeeee", b"fffff", b"ggggg",
            b"hhhhh", b"iiiii", b"jjjjj", b"kkkkk", b"lllll", b"mmmmm", b"nnnnn",
            b"ooooo", b"ppppp",
        ];
        let plan = plan(words);
        assert_eq!(plan.plan_id(), WIDE_PACKED_PLAN_ID);
        let wide = plan.wide_anchor.as_ref().unwrap();
        let correlated = wide.correlated_columns.as_ref().unwrap();
        assert!(correlated.matches(b"aaaaa"));
        assert!(correlated.matches(b"ppppp"));
        assert!(correlated.packed_prefix_matches(b"aaaab"));
        assert!(!correlated.matches(b"aaaab"));
        assert!(!correlated.packed_prefix_matches(b"aQaab"));
        for start in [15_usize, 16, 31, 32] {
            let mut haystack = vec![b'!'; 96];
            haystack[1..6].copy_from_slice(b"aaaab");
            haystack[start..start + 5].copy_from_slice(b"ppppp");
            assert_eq!(
                wide.find_correlated_start(
                    &haystack,
                    0,
                    haystack.len(),
                    plan.anchor.offset,
                    5,
                ),
                Some(start),
            );
        }
        assert_eq!(
            wide.find_correlated_start(b"xaaaaa!ppppp!", 1, 13, plan.anchor.offset, 5),
            Some(7),
        );
        assert_eq!(
            wide.find_correlated_start(b"!pppppx!aaaaa!", 0, 14, plan.anchor.offset, 5),
            Some(8),
        );
    }

    #[test]
    fn correlated_boundary_candidates_match_scalar_real_context() {
        let words: &[&[u8]] = &[
            b"aaaaa", b"bbbbb", b"ccccc", b"ddddd", b"eeeee", b"fffff", b"ggggg",
            b"hhhhh", b"iiiii", b"jjjjj", b"kkkkk", b"lllll", b"mmmmm", b"nnnnn",
            b"ooooo", b"ppppp",
        ];
        let plan = plan(words);
        let correlated = plan
            .wide_anchor
            .as_ref()
            .and_then(|wide| wide.correlated_columns.as_ref())
            .unwrap();
        for byte in u8::MIN..=u8::MAX {
            assert_eq!(
                correlated.word_members.set().contains(byte),
                super::is_ascii_word(byte),
            );
        }
        let haystack = (0_usize..38)
            .map(|index| match index % 6 {
                0 => b'a',
                1 => b'!',
                2 => 0x80,
                3 => b'_',
                4 => b'9',
                _ => 0xff,
            })
            .collect::<Vec<_>>();

        for (position, initial) in [(0_usize, u32::MAX), (2, 0xa5a5_5a5a)] {
            let mut expected = 0_u32;
            for lane in 0..ASCII_WIDE_BYTES {
                let lane_bit = 1_u32 << u32::try_from(lane).unwrap();
                if initial & lane_bit == 0 {
                    continue;
                }
                let start = position + lane;
                let end = start + 5;
                let left = start == 0 || !super::is_ascii_word(haystack[start - 1]);
                let right = end == haystack.len() || !super::is_ascii_word(haystack[end]);
                if left && right {
                    expected |= lane_bit;
                }
            }
            assert_eq!(
                correlated.fixed_word_boundary_candidates_32(
                    &haystack,
                    position,
                    5,
                    initial,
                ),
                Some(expected),
            );
        }

        assert!(!CorrelatedColumns::should_filter_secondary_columns(0));
        assert!(!CorrelatedColumns::should_filter_secondary_columns(0b11));
        assert!(CorrelatedColumns::should_filter_secondary_columns(0b111));
    }

    #[test]
    fn correlated_boundary_scan_uses_context_outside_the_window() {
        let words: &[&[u8]] = &[
            b"aaaaa", b"bbbbb", b"ccccc", b"ddddd", b"eeeee", b"fffff", b"ggggg",
            b"hhhhh", b"iiiii", b"jjjjj", b"kkkkk", b"lllll", b"mmmmm", b"nnnnn",
            b"ooooo", b"ppppp",
        ];
        let plan = plan(words);
        let wide = plan.wide_anchor.as_ref().unwrap();
        let mut haystack = vec![b'!'; 96];
        haystack[31..36].copy_from_slice(b"ppppp");

        haystack[30] = 0x80;
        haystack[36] = 0xff;
        assert_eq!(
            wide.find_correlated_start(&haystack, 0, 36, plan.anchor.offset, 5),
            Some(31),
        );

        haystack[36] = b'x';
        assert_eq!(
            wide.find_correlated_start(&haystack, 0, 36, plan.anchor.offset, 5),
            None,
        );
        haystack[36] = 0xff;
        haystack[30] = b'x';
        assert_eq!(
            wide.find_correlated_start(&haystack, 0, 36, plan.anchor.offset, 5),
            None,
        );
    }

    #[test]
    fn correlated_boundary_work_is_admitted_exactly() {
        let words: &[&[u8]] = &[
            b"aaaaa", b"bbbbb", b"ccccc", b"ddddd", b"eeeee", b"fffff", b"ggggg",
            b"hhhhh", b"iiiii", b"jjjjj", b"kkkkk", b"lllll", b"mmmmm", b"nnnnn",
            b"ooooo", b"ppppp",
        ];
        let plan = plan(words);
        let wide = plan.wide_anchor.as_ref().unwrap();
        let haystack = vec![b'!'; 256];
        let window = SearchWindow::full(&haystack);
        let upper = plan.search_upper_bounds(&haystack, window).unwrap();
        let packed_build = wide.packed.build_accounting();
        let positions = window.end() - window.start() + 1;
        let packed_work = positions * (packed_build.pattern_bytes + packed_build.patterns);
        let sample_work = (window.end() - window.start())
            .min(WIDE_CORRELATED_SAMPLE_BYTES)
            * (WIDE_PACKED_PREFIX_BYTES + 3);
        let secondary_work = upper.anchor_positions * WIDE_SECONDARY_COLUMN_LIMIT;
        let boundary_work = upper.anchor_positions * WIDE_CORRELATED_BOUNDARY_COLUMNS;
        let threshold = upper.total_work
            + packed_work
            + sample_work
            + secondary_work
            + boundary_work;
        let limits = |work: usize| SearchLimits {
            max_work: u64::try_from(work).unwrap(),
            max_scratch_bytes: 0,
        };

        assert_eq!(
            plan.value_packed_probe_work(window, upper, limits(threshold)),
            Some(packed_work),
        );
        assert_eq!(
            plan.value_packed_probe_work(window, upper, limits(threshold - 1)),
            None,
        );
    }

    #[test]
    fn correlated_columns_use_one_mask_word_through_pattern_64() {
        assert!(correlated_columns_dimensions(4, 2).unwrap().is_some());
        assert!(correlated_columns_dimensions(64, 2).unwrap().is_some());
        assert!(correlated_columns_dimensions(16, 5).unwrap().is_some());
        assert!(correlated_columns_dimensions(3, 2).unwrap().is_none());
        assert!(correlated_columns_dimensions(4, 1).unwrap().is_none());
        assert!(correlated_columns_dimensions(15, 5).unwrap().is_none());
        assert!(correlated_columns_dimensions(16, 4).unwrap().is_none());
        assert!(correlated_columns_dimensions(65, 2).unwrap().is_none());
        assert!(correlated_columns_dimensions(4, 33).unwrap().is_none());

        let words = (0_usize..64)
            .map(|index| {
                [
                    b'a' + u8::try_from(index & 3).unwrap(),
                    b'e' + u8::try_from((index >> 2) & 3).unwrap(),
                    b'i' + u8::try_from((index >> 4) & 3).unwrap(),
                    b'm' + u8::try_from((index ^ (index >> 2)) & 3).unwrap(),
                    b'q' + u8::try_from((index + (index >> 4)) & 3).unwrap(),
                ]
            })
            .collect::<Vec<_>>();
        let references = words
            .iter()
            .map(|word| word.as_slice())
            .collect::<Vec<_>>();
        let plan = plan(&references);
        let wide = plan.wide_anchor.as_ref().unwrap();
        let correlated = wide.correlated_columns.as_ref().unwrap();
        assert!(correlated.admits_batched_remainder(0));
        assert_eq!(correlated.pattern_mask, u64::MAX);
        assert!(correlated.matches(&words[63]));
        let mut recombined = words[63];
        recombined[4] = if recombined[4] == b'q' { b'r' } else { b'q' };
        assert!(!correlated.matches(&recombined));

        let narrow_words: &[&[u8]] = &[b"aa", b"bc", b"ce", b"dg"];
        let narrow = self::plan(narrow_words);
        let narrow_correlated = narrow
            .wide_anchor
            .as_ref()
            .and_then(|wide| wide.correlated_columns.as_ref())
            .unwrap();
        let exact_threshold = narrow_words.len() * 3 * WIDE_REJECTION_PACKED_PROBE_BYTES;
        assert!(!narrow_correlated.admits_batched_remainder(exact_threshold - 1));
        assert!(narrow_correlated.admits_batched_remainder(exact_threshold));
    }

    #[test]
    fn one_byte_build_and_search_limits_close_exactly() {
        let words: &[&[u8]] = &[b"a", b"B", b"7", b"_"];
        assert_eq!(plan(&words[..3]).plan_id(), PLAN_ID);
        let dictionary = dictionary_with_guards(words, Guard::LeftBoundary, Guard::RightBoundary);
        let dictionary_work =
            usize::try_from(dictionary.build_accounting().actual.build_work).unwrap();
        let dictionary_bytes = dictionary.build_accounting().actual.persistent_bytes;
        let patterns = words.len();
        let fixed_selection = patterns + patterns + 3;
        let wide_selection = patterns + 128 + WIDE_RANKED_COLUMN_LIMIT;
        let exact_work = dictionary_work
            + fixed_selection
            + wide_selection
            + ASCII_CLASSIFIER_BUILD_WORK * 2
            + if cfg!(target_arch = "aarch64") {
                ASCII_NONMEMBER_RUN_SCANNER_BUILD_WORK + ASCII_RUN_SCANNER_BUILD_WORK
            } else {
                0
            };
        let exact_persistent = dictionary_bytes
            + Plan::inline_storage_bytes()
            + size_of::<SingleByteWordSet>();
        let exact_limits = PackedLiteralSetBuildLimits {
            max_build_work: exact_work,
            max_build_bytes: exact_persistent,
            max_persistent_bytes: exact_persistent,
            ..PackedLiteralSetBuildLimits::default()
        };
        let exact = Plan::build(dictionary, exact_limits, exact_persistent).unwrap();
        assert_eq!(exact.plan_id(), ONE_BYTE_PLAN_ID);
        assert_eq!(exact.storage_bytes(), exact_persistent);
        assert!(exact.one_byte.is_some());
        assert!(exact.wide_anchor.is_none());

        for (limits, plan_limit, expected) in [
            (
                PackedLiteralSetBuildLimits {
                    max_build_work: exact_work - 1,
                    ..exact_limits
                },
                exact_persistent,
                "work",
            ),
            (
                PackedLiteralSetBuildLimits {
                    max_build_bytes: exact_persistent - 1,
                    ..exact_limits
                },
                exact_persistent,
                "build bytes",
            ),
            (
                PackedLiteralSetBuildLimits {
                    max_persistent_bytes: exact_persistent - 1,
                    ..exact_limits
                },
                exact_persistent,
                "persistent bytes",
            ),
            (exact_limits, exact_persistent - 1, "plan persistent bytes"),
        ] {
            let error = Plan::build(
                dictionary_with_guards(words, Guard::LeftBoundary, Guard::RightBoundary),
                limits,
                plan_limit,
            )
            .unwrap_err();
            assert!(
                matches!(
                    (&error, expected),
                    (PackedLiteralSetError::BuildWorkLimit { .. }, "work")
                        | (PackedLiteralSetError::BuildBytesLimit { .. }, "build bytes")
                        | (
                            PackedLiteralSetError::PersistentBytesLimit { .. },
                            "persistent bytes" | "plan persistent bytes",
                        )
                ),
                "unexpected {expected} error: {error}",
            );
        }

        let haystack = b"x!z!z!z!z!z!_!";
        let window = SearchWindow::new(1, haystack.len() - 1);
        let upper = exact.search_upper_bounds(haystack, window).unwrap();
        let window_bytes = window.end() - window.start();
        assert_eq!(upper.anchor_positions, window_bytes);
        assert_eq!(upper.anchor_work, window_bytes * 3);
        assert_eq!(upper.total_work, window_bytes * 3);
        assert_eq!(upper.candidate_words, window_bytes / 2 + window_bytes % 2);
        assert_eq!(upper.contextual_bytes, window_bytes + 2);
        assert_eq!(upper.lookup_steps, 0);
        assert_eq!(upper.scratch_bytes, 0);
        let limits = |work: usize| SearchLimits {
            max_work: u64::try_from(work).unwrap(),
            max_scratch_bytes: 0,
        };
        let expected = Some(Match {
            start: haystack.len() - 2,
            end: haystack.len() - 1,
        });
        assert_eq!(
            exact.find_window_value(haystack, window, limits(upper.total_work))
                .unwrap(),
            expected,
        );
        let (accounted, accounting) = exact
            .find_window(haystack, window, limits(upper.total_work))
            .unwrap();
        assert_eq!(accounted, expected);
        assert!(accounting.actual.total_work <= upper.total_work);
        assert_eq!(accounting.actual.lookup_steps, 0);
        assert!(matches!(
            exact.find_window_value(haystack, window, limits(upper.total_work - 1)),
            Err(SearchError::WorkLimit { needed, limit })
                if needed == u64::try_from(upper.total_work).unwrap() && limit + 1 == needed,
        ));
    }

    #[test]
    fn wide_packed_build_limits_close_exactly() {
        let words: &[&[u8]] = &[b"ax0", b"cy1", b"f2A", b"j5B"];
        let dictionary = dictionary_with_guards(words, Guard::LeftBoundary, Guard::RightBoundary);
        let dictionary_work =
            usize::try_from(dictionary.build_accounting().actual.build_work).unwrap();
        let dictionary_bytes = dictionary.build_accounting().actual.persistent_bytes;
        let probe = match Plan::build(
            dictionary,
            PackedLiteralSetBuildLimits::default(),
            usize::MAX,
        ) {
            Ok(plan) => plan,
            Err(PackedLiteralSetError::UnsupportedTargetOrShape) => return,
            Err(error) => panic!("unexpected wide guarded-plan error: {error}"),
        };
        let packed_build = probe
            .wide_anchor
            .as_ref()
            .expect("the four-column language needs a wide anchor")
            .packed
            .build_accounting();
        assert!(
            probe
                .wide_anchor
                .as_ref()
                .is_some_and(|wide| wide.correlated_columns.is_none()),
            "the mandatory-wide limit fixture must not retain the optional correlated sidecar",
        );
        let patterns = words.len();
        let minimum_word_bytes = words.iter().map(|word| word.len()).min().unwrap();
        let fixed_selection = patterns
            .checked_add(minimum_word_bytes.checked_mul(patterns + 3).unwrap())
            .unwrap();
        let wide_selection = minimum_word_bytes
            .checked_mul(patterns + 128 + WIDE_RANKED_COLUMN_LIMIT)
            .unwrap();
        let exact_work = dictionary_work
            .checked_add(fixed_selection)
            .and_then(|work| work.checked_add(wide_selection))
            .and_then(|work| work.checked_add(ASCII_CLASSIFIER_BUILD_WORK))
            .and_then(|work| {
                ASCII_CLASSIFIER_BUILD_WORK
                    .checked_mul(WIDE_SECONDARY_COLUMN_LIMIT)
                    .and_then(|secondary| work.checked_add(secondary))
            })
            .and_then(|work| work.checked_add(ASCII_RUN_SCANNER_BUILD_WORK))
            .and_then(|work| work.checked_add(patterns))
            .and_then(|work| work.checked_add(packed_build.build_work_upper_bound))
            .unwrap();
        let retained_owner_bytes = dictionary_bytes
            .checked_add(Plan::inline_storage_bytes())
            .and_then(|bytes| bytes.checked_add(size_of::<WideByteAnchor>()))
            .and_then(|bytes| bytes.checked_add(size_of::<PackedLiteralSetPlan>()))
            .unwrap();
        let exact_persistent = retained_owner_bytes
            .checked_add(packed_build.persistent_bytes)
            .unwrap();
        let exact_build_bytes = retained_owner_bytes
            .checked_add(packed_build.build_bytes_upper_bound)
            .unwrap();
        assert_eq!(probe.storage_bytes(), exact_persistent);

        let exact_limits = PackedLiteralSetBuildLimits {
            max_build_work: exact_work,
            max_build_bytes: exact_build_bytes,
            max_persistent_bytes: exact_persistent,
            ..PackedLiteralSetBuildLimits::default()
        };
        let exact = Plan::build(
            dictionary_with_guards(words, Guard::LeftBoundary, Guard::RightBoundary),
            exact_limits,
            exact_persistent,
        )
        .unwrap();
        assert_eq!(exact.plan_id(), WIDE_PACKED_PLAN_ID);
        assert_eq!(exact.storage_bytes(), exact_persistent);

        for (limits, plan_limit, expected) in [
            (
                PackedLiteralSetBuildLimits {
                    max_build_work: exact_work - 1,
                    ..exact_limits
                },
                exact_persistent,
                "work",
            ),
            (
                PackedLiteralSetBuildLimits {
                    max_build_bytes: exact_build_bytes - 1,
                    ..exact_limits
                },
                exact_persistent,
                "build bytes",
            ),
            (
                PackedLiteralSetBuildLimits {
                    max_persistent_bytes: exact_persistent - 1,
                    ..exact_limits
                },
                exact_persistent,
                "persistent bytes",
            ),
            (exact_limits, exact_persistent - 1, "plan persistent bytes"),
        ] {
            let error = Plan::build(
                dictionary_with_guards(words, Guard::LeftBoundary, Guard::RightBoundary),
                limits,
                plan_limit,
            )
            .unwrap_err();
            assert!(
                matches!(
                    (&error, expected),
                    (PackedLiteralSetError::BuildWorkLimit { .. }, "work")
                        | (PackedLiteralSetError::BuildBytesLimit { .. }, "build bytes")
                        | (
                            PackedLiteralSetError::PersistentBytesLimit { .. },
                            "persistent bytes" | "plan persistent bytes",
                        )
                ),
                "unexpected {expected} error: {error}",
            );
        }
    }

    #[test]
    fn correlated_sidecar_admission_closes_without_blocking_packed_fallback() {
        let words: &[&[u8]] = &[
            b"aaaaa", b"bbbbb", b"ccccc", b"ddddd", b"eeeee", b"fffff", b"ggggg",
            b"hhhhh", b"iiiii", b"jjjjj", b"kkkkk", b"lllll", b"mmmmm", b"nnnnn",
            b"ooooo", b"ppppp",
        ];
        let probe = plan(words);
        let dictionary_bytes = probe.dictionary.build_accounting().actual.persistent_bytes;
        let dictionary_work =
            usize::try_from(probe.dictionary.build_accounting().actual.build_work).unwrap();
        let wide = probe.wide_anchor.as_ref().unwrap();
        let packed_build = wide.packed.build_accounting();
        let patterns = words.len();
        let word_bytes = words[0].len();
        let fixed_selection = patterns + word_bytes * (patterns + 3);
        let wide_selection = word_bytes * (patterns + 128 + WIDE_RANKED_COLUMN_LIMIT);
        let mandatory_work = dictionary_work
            + fixed_selection
            + wide_selection
            + ASCII_CLASSIFIER_BUILD_WORK * (WIDE_SECONDARY_COLUMN_LIMIT + 1)
            + ASCII_RUN_SCANNER_BUILD_WORK
            + patterns
            + packed_build.build_work_upper_bound;
        let (correlated_work, correlated_bytes) =
            correlated_columns_dimensions(patterns, word_bytes)
                .unwrap()
                .unwrap();
        assert_eq!(
            wide.correlated_columns.as_ref().unwrap().persistent_bytes(),
            correlated_bytes,
        );
        let exact_work = mandatory_work + correlated_work;
        let retained_owner_bytes = dictionary_bytes
            + Plan::inline_storage_bytes()
            + size_of::<WideByteAnchor>()
            + size_of::<PackedLiteralSetPlan>();
        let mandatory_persistent = retained_owner_bytes + packed_build.persistent_bytes;
        let exact_persistent = mandatory_persistent + correlated_bytes;
        let mandatory_build_bytes = retained_owner_bytes + packed_build.build_bytes_upper_bound;
        let exact_build_bytes = mandatory_build_bytes.max(exact_persistent);
        assert_eq!(probe.storage_bytes(), exact_persistent);

        let exact_limits = PackedLiteralSetBuildLimits {
            max_build_work: exact_work,
            max_build_bytes: exact_build_bytes,
            max_persistent_bytes: exact_persistent,
            ..PackedLiteralSetBuildLimits::default()
        };
        let exact = Plan::build(
            dictionary_with_guards(words, Guard::LeftBoundary, Guard::RightBoundary),
            exact_limits,
            exact_persistent,
        )
        .unwrap();
        assert!(
            exact
                .wide_anchor
                .as_ref()
                .and_then(|wide| wide.correlated_columns.as_ref())
                .is_some(),
        );
        assert_eq!(exact.storage_bytes(), exact_persistent);

        for (limits, plan_limit) in [
            (
                PackedLiteralSetBuildLimits {
                    max_build_work: exact_work - 1,
                    ..exact_limits
                },
                exact_persistent,
            ),
            (
                PackedLiteralSetBuildLimits {
                    max_persistent_bytes: exact_persistent - 1,
                    ..exact_limits
                },
                exact_persistent - 1,
            ),
        ] {
            let fallback = Plan::build(
                dictionary_with_guards(words, Guard::LeftBoundary, Guard::RightBoundary),
                limits,
                plan_limit,
            )
            .unwrap();
            assert_eq!(fallback.plan_id(), WIDE_PACKED_PLAN_ID);
            assert!(
                fallback
                    .wide_anchor
                    .as_ref()
                    .and_then(|wide| wide.correlated_columns.as_ref())
                    .is_none(),
            );
            assert_eq!(fallback.storage_bytes(), mandatory_persistent);
        }
        if exact_build_bytes > mandatory_build_bytes {
            let fallback = Plan::build(
                dictionary_with_guards(words, Guard::LeftBoundary, Guard::RightBoundary),
                PackedLiteralSetBuildLimits {
                    max_build_bytes: exact_build_bytes - 1,
                    ..exact_limits
                },
                exact_persistent,
            )
            .unwrap();
            assert_eq!(fallback.plan_id(), WIDE_PACKED_PLAN_ID);
            assert!(
                fallback
                    .wide_anchor
                    .as_ref()
                    .and_then(|wide| wide.correlated_columns.as_ref())
                    .is_none(),
            );
            assert_eq!(fallback.storage_bytes(), mandatory_persistent);
        }
    }

    #[test]
    fn fixed_column_build_and_search_limits_close_exactly() {
        let words: &[&[u8]] = &[b"zza", b"azb", b"czc", b"dzd"];
        let dictionary = dictionary_with_guards(words, Guard::LeftBoundary, Guard::RightBoundary);
        let dictionary_work =
            usize::try_from(dictionary.build_accounting().actual.build_work).unwrap();
        let selection_work = words
            .len()
            .checked_add(words[0].len().checked_mul(words.len() + 3).unwrap())
            .unwrap();
        let mut exact_build = PackedLiteralSetBuildLimits::default();
        exact_build.max_build_work = dictionary_work.checked_add(selection_work).unwrap();
        let plan = Plan::build(dictionary, exact_build, usize::MAX).unwrap();

        let dictionary = dictionary_with_guards(words, Guard::LeftBoundary, Guard::RightBoundary);
        let mut below_build = exact_build;
        below_build.max_build_work = below_build.max_build_work.checked_sub(1).unwrap();
        assert!(matches!(
            Plan::build(dictionary, below_build, usize::MAX),
            Err(fre_kernels::PackedLiteralSetError::BuildWorkLimit {
                needed,
                limit,
            }) if needed == selection_work && limit == selection_work - 1,
        ));

        let haystack = b"xx zzax zza";
        let (_, accounting) = plan
            .find_window(
                haystack,
                SearchWindow::full(haystack),
                SearchLimits::unlimited(),
            )
            .unwrap();
        assert!(accounting.actual.anchor_calls > 0);
        assert!(accounting.actual.anchor_positions <= accounting.upper_bounds.anchor_positions);
        assert_eq!(accounting.upper_bounds.scratch_bytes, 0);
        let exact_work = u64::try_from(accounting.upper_bounds.total_work).unwrap();
        assert!(
            plan.find_window(
                haystack,
                SearchWindow::full(haystack),
                SearchLimits {
                    max_work: exact_work,
                    max_scratch_bytes: 0,
                },
            )
            .is_ok()
        );
        assert!(matches!(
            plan.find_window(
                haystack,
                SearchWindow::full(haystack),
                SearchLimits {
                    max_work: exact_work - 1,
                    max_scratch_bytes: 0,
                },
            ),
            Err(SearchError::WorkLimit { needed, limit })
                if needed == exact_work && limit == exact_work - 1,
        ));
    }

    #[test]
    fn directional_and_half_boundaries_share_the_maximal_word_theorem() {
        for (left, right) in [
            (Guard::LeftBoundary, Guard::RightBoundary),
            (Guard::LeftStart, Guard::RightEnd),
            (Guard::LeftStartHalf, Guard::RightEndHalf),
        ] {
            let plan = plan_with_guards(&[b"a", b"ab"], left, right);
            assert_eq!(
                plan.find_window_value(
                    b"x ab y",
                    SearchWindow::full(b"x ab y"),
                    SearchLimits::unlimited(),
                )
                .unwrap(),
                Some(Match { start: 2, end: 4 }),
            );
        }
    }

    #[test]
    fn composite_persistent_limit_includes_the_retained_dictionary() {
        let words: &[&[u8]] = &[b"cat", b"dog"];
        let dictionary = dictionary_with_guards(words, Guard::LeftBoundary, Guard::RightBoundary);
        let plan_bytes = dictionary
            .build_accounting()
            .actual
            .persistent_bytes
            .checked_add(Plan::inline_storage_bytes())
            .unwrap();
        let limit = plan_bytes.checked_sub(1).unwrap();
        assert!(matches!(
            Plan::build(
                dictionary,
                PackedLiteralSetBuildLimits::default(),
                limit,
            ),
            Err(fre_kernels::PackedLiteralSetError::PersistentBytesLimit {
                needed,
                limit: actual_limit,
            }) if needed == plan_bytes && actual_limit == limit,
        ));

        let dictionary = dictionary_with_guards(words, Guard::LeftBoundary, Guard::RightBoundary);
        let mut exact = PackedLiteralSetBuildLimits::default();
        exact.max_persistent_bytes = plan_bytes;
        exact.max_build_bytes = plan_bytes;
        let plan = Plan::build(dictionary, exact, plan_bytes).unwrap();
        assert_eq!(plan.storage_bytes(), plan_bytes);

        let dictionary = dictionary_with_guards(words, Guard::LeftBoundary, Guard::RightBoundary);
        let mut below_build = PackedLiteralSetBuildLimits::default();
        below_build.max_build_bytes = plan_bytes.checked_sub(1).unwrap();
        assert!(matches!(
            Plan::build(dictionary, below_build, usize::MAX),
            Err(fre_kernels::PackedLiteralSetError::BuildBytesLimit {
                needed,
                limit: actual_limit,
            }) if needed == plan_bytes && actual_limit == plan_bytes - 1,
        ));
    }

    #[test]
    fn extraction_reserves_only_persistent_wrapper_storage() {
        let packed = PackedLiteralSetBuildLimits::default();
        let limits = extraction_limits(packed, usize::MAX);
        assert_eq!(
            limits.dictionary.max_persistent_bytes,
            packed
                .max_persistent_bytes
                .checked_sub(Plan::inline_storage_bytes())
                .unwrap(),
        );
        assert_eq!(limits.dictionary.max_peak_bytes, packed.max_build_bytes);
        assert_eq!(limits.max_peak_bytes, packed.max_build_bytes);

        let wrapper = Plan::inline_storage_bytes();
        for plan_limit in [wrapper.saturating_sub(1), wrapper, wrapper + 1] {
            let limits = extraction_limits(packed, plan_limit);
            assert_eq!(
                limits.dictionary.max_persistent_bytes,
                plan_limit.saturating_sub(wrapper),
            );
        }
    }

    #[test]
    fn interior_occurrences_skip_their_complete_word() {
        let plan = plan(&[b"cat", b"dog"]);
        let (matched, _) = plan
            .find_window(
                b"bobcat dogmatic dog",
                SearchWindow::new(0, 19),
                SearchLimits::unlimited(),
            )
            .unwrap();
        assert_eq!(matched, Some(Match { start: 16, end: 19 }));
    }

    #[test]
    fn fixed_width_rejection_with_internal_boundaries_keeps_later_words_visible() {
        let plan = plan(&[b"cat", b"dog"]);
        let haystack = b"!c!t! dog";
        let expected = Some(Match { start: 6, end: 9 });
        assert_eq!(
            plan.find_window_value(
                haystack,
                SearchWindow::full(haystack),
                SearchLimits::unlimited(),
            )
            .unwrap(),
            expected,
        );
        assert_eq!(
            plan.find_window(
                haystack,
                SearchWindow::full(haystack),
                SearchLimits::unlimited(),
            )
            .unwrap()
            .0,
            expected,
        );
    }

    #[test]
    fn one_byte_fixed_words_skip_larger_maximal_words_once() {
        let plan = plan(&[b"a", b"b", b"c"]);
        assert_eq!(plan.fixed_word_bytes, Some(1));
        let expected = Some(Match { start: 3, end: 4 });
        assert_eq!(
            plan.find_window_value(
                b"ab c",
                SearchWindow::full(b"ab c"),
                SearchLimits::unlimited(),
            )
            .unwrap(),
            expected,
        );
        assert_eq!(
            plan.find_window(
                b"ab c",
                SearchWindow::full(b"ab c"),
                SearchLimits::unlimited(),
            )
            .unwrap()
            .0,
            expected,
        );
    }

    #[test]
    fn windows_retain_original_context_and_reject_crossing_words() {
        let plan = plan(&[b"cat"]);
        assert_eq!(
            plan.find_window_value(b"catz", SearchWindow::new(0, 3), SearchLimits::unlimited(),)
                .unwrap(),
            None,
        );
        assert_eq!(
            plan.find_window_value(b"cat ", SearchWindow::new(0, 3), SearchLimits::unlimited(),)
                .unwrap(),
            Some(Match { start: 0, end: 3 }),
        );
        assert_eq!(
            plan.find_window_value(
                b"xcat catz cat",
                SearchWindow::new(1, 12),
                SearchLimits::unlimited(),
            )
            .unwrap(),
            None,
        );
        assert_eq!(
            plan.find_window_value(
                b"xcat catz cat",
                SearchWindow::new(1, 13),
                SearchLimits::unlimited(),
            )
            .unwrap(),
            Some(Match { start: 10, end: 13 }),
        );
        assert_eq!(
            plan.find_window_value(
                b"\xffcat\xff",
                SearchWindow::new(1, 4),
                SearchLimits::unlimited(),
            )
            .unwrap(),
            Some(Match { start: 1, end: 4 }),
        );
    }

    #[test]
    fn one_owner_observes_same_address_mutation_without_retained_cursor_state() {
        let plan = plan(&[b"cat", b"dog"]);
        let mut haystack = b"cat".to_vec();
        assert_eq!(
            plan.find_window_value(
                &haystack,
                SearchWindow::full(&haystack),
                SearchLimits::unlimited(),
            )
            .unwrap(),
            Some(Match { start: 0, end: 3 }),
        );
        haystack.copy_from_slice(b"dog");
        assert_eq!(
            plan.find_window_value(
                &haystack,
                SearchWindow::full(&haystack),
                SearchLimits::unlimited(),
            )
            .unwrap(),
            Some(Match { start: 0, end: 3 }),
        );
        haystack.copy_from_slice(b"fog");
        assert_eq!(
            plan.find_window_value(
                &haystack,
                SearchWindow::full(&haystack),
                SearchLimits::unlimited(),
            )
            .unwrap(),
            None,
        );
    }

    #[test]
    fn correlated_owner_observes_same_address_mutation() {
        let lower = plan(&[
            b"aaaaa", b"bbbbb", b"ccccc", b"ddddd", b"eeeee", b"fffff", b"ggggg",
            b"hhhhh", b"iiiii", b"jjjjj", b"kkkkk", b"lllll", b"mmmmm", b"nnnnn",
            b"ooooo", b"ppppp",
        ]);
        let upper = plan(&[
            b"AAAAA", b"BBBBB", b"CCCCC", b"DDDDD", b"EEEEE", b"FFFFF", b"GGGGG",
            b"HHHHH", b"IIIII", b"JJJJJ", b"KKKKK", b"LLLLL", b"MMMMM", b"NNNNN",
            b"OOOOO", b"PPPPP",
        ]);
        assert!(
            lower
                .wide_anchor
                .as_ref()
                .and_then(|wide| wide.correlated_columns.as_ref())
                .is_some(),
        );
        assert!(
            upper
                .wide_anchor
                .as_ref()
                .and_then(|wide| wide.correlated_columns.as_ref())
                .is_some(),
        );

        fn fill_decoys(haystack: &mut [u8], decoy: &[u8; 5]) {
            haystack.fill(b'!');
            for start in (1..121).step_by(6) {
                haystack[start..start + decoy.len()].copy_from_slice(decoy);
            }
        }

        let mut haystack = vec![b'!'; 2048];
        let address = haystack.as_ptr();
        for state in 0..4 {
            match state {
                0 => {
                    fill_decoys(&mut haystack, b"aaaab");
                    haystack[1300..1305].copy_from_slice(b"ppppp");
                }
                1 => {
                    fill_decoys(&mut haystack, b"AAAAB");
                    haystack[1300..1305].copy_from_slice(b"PPPPP");
                }
                2 => fill_decoys(&mut haystack, b"aaaab"),
                _ => {
                    haystack.fill(0xff);
                    haystack[1299] = b'!';
                    haystack[1300..1305].copy_from_slice(b"hhhhh");
                    haystack[1305] = b'!';
                }
            }
            assert_eq!(haystack.as_ptr(), address);
            for plan in [&lower, &upper] {
                let expected = match (state, core::ptr::eq(plan, &lower)) {
                    (0, true) | (3, true) | (1, false) => {
                        Some(Match {
                            start: 1300,
                            end: 1305,
                        })
                    }
                    _ => None,
                };
                assert_eq!(
                    plan.find_window_value(
                        &haystack,
                        SearchWindow::full(&haystack),
                        SearchLimits::unlimited(),
                    )
                    .unwrap(),
                    expected,
                );
            }
        }
    }

    #[test]
    fn invalid_windows_precede_work_limits() {
        let plan = plan(&[b"cat"]);
        assert!(matches!(
            plan.find_window(
                b"cat",
                SearchWindow::new(2, 1),
                SearchLimits {
                    max_work: 0,
                    max_scratch_bytes: 0,
                },
            ),
            Err(SearchError::InvalidWindow { .. }),
        ));
    }
}
