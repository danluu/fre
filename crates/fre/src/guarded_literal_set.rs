//! Fixed-column search for finite ASCII words between word boundaries.
//!
//! Guarded finite extraction has already proved that every nonempty source
//! path is an ASCII-word byte string with a left word-start boundary and a
//! right word-end boundary. A match is therefore exactly one complete maximal
//! ASCII word. The plan selects one fixed word column whose complete byte set
//! fits a native one-to-three-byte scan, inspects each containing maximal word
//! at most once, and confirms it in the source-order dictionary. Fixed-width
//! words can be checked directly from the anchor without first rediscovering
//! their maximal-word extent. In particular, `a|ab` on `ab` cannot be lost:
//! lookup is performed on the complete word `ab`.

use core::fmt;
use core::mem::size_of;

use memchr::{memchr, memchr2, memchr3};

use fre_kernels::{
    PackedLiteralSetBuildLimits, PackedLiteralSetError, packed_literal_anchor_frequency_rank,
};

use crate::{
    Match, SearchLimits, SearchWindow, finite,
    guarded_ascii_word::{
        BuildLimits as DictionaryBuildLimits, Dictionary, LookupActual,
        ReduceError as DictionaryReduceError, ReduceErrorKind as DictionaryReduceErrorKind,
    },
};

/// Stable identity for the guarded fixed-column/dictionary composition.
pub(crate) const PLAN_ID: &str = "guarded-ascii-word-literal-set.fixed-column-dictionary.v4";

/// Source-independent ceiling closed before the first haystack read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchUpperBounds {
    /// Candidate anchor positions charged by the complete fixed column.
    pub anchor_positions: usize,
    /// Logical fixed-column byte classifications for those positions.
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

fn select_fixed_byte_anchor(
    dictionary: &Dictionary,
    patterns: usize,
    max_build_work: usize,
) -> Result<(FixedByteAnchor, usize, Option<usize>), PackedLiteralSetError> {
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
    let work_per_column =
        patterns
            .checked_add(3)
            .ok_or(PackedLiteralSetError::ArithmeticOverflow {
                computation: "guarded fixed-column work per column",
            })?;
    let selection_work = minimum_word_bytes
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
    for offset in 0..minimum_word_bytes {
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
            maximum_word_bytes,
            (minimum_word_bytes == maximum_word_bytes).then_some(minimum_word_bytes),
        )
    })
    .ok_or(PackedLiteralSetError::UnsupportedTargetOrShape)
}

/// Immutable composite owner. The fixed-column anchor is a complete candidate
/// source and the dictionary is the final exact authority.
#[derive(Debug)]
pub(crate) struct Plan {
    anchor: FixedByteAnchor,
    maximum_word_bytes: usize,
    fixed_word_bytes: Option<usize>,
    dictionary: Dictionary,
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
        if patterns > limits.max_patterns {
            return Err(PackedLiteralSetError::PatternLimit {
                needed: patterns,
                limit: limits.max_patterns,
            });
        }
        if identity.packed_bytes.len() > limits.max_pattern_bytes {
            return Err(PackedLiteralSetError::PatternBytesLimit {
                needed: identity.packed_bytes.len(),
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
        let (anchor, maximum_word_bytes, fixed_word_bytes) =
            select_fixed_byte_anchor(&dictionary, patterns, remaining_build_work)?;
        Ok(Self {
            anchor,
            maximum_word_bytes,
            fixed_word_bytes,
            dictionary,
        })
    }

    pub(crate) fn storage_bytes(&self) -> usize {
        self.dictionary
            .build_accounting()
            .actual
            .persistent_bytes
            .checked_add(Self::inline_storage_bytes())
            .expect("successful guarded plan construction proved its persistent bytes")
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

    fn search_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, SearchAccounting), SearchError> {
        let upper_bounds = self.search_upper_bounds(haystack, window)?;
        enforce_limits(upper_bounds, limits)?;
        self.search_window_anchor(haystack, window, upper_bounds)
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
            let Some(relative) = anchor.find(remaining) else {
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
        self.search_window_value_anchor(haystack, window)
    }

    fn search_window_value_anchor(
        &self,
        haystack: &[u8],
        window: SearchWindow,
    ) -> Result<Option<Match>, SearchError> {
        let anchor = &self.anchor;
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
                    // This complete fixed-width maximal word is not in the
                    // dictionary. Skip it as one unit without a separate
                    // backward/forward segmentation pass.
                    cursor = word_end;
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
    use super::{PLAN_ID, Plan, SearchError, extraction_limits};
    use crate::{
        Match, SearchLimits, SearchWindow,
        guarded_ascii_word::{BuildDimensions, BuildLimits, Dictionary, Guard, SourceWord},
    };
    use fre_kernels::PackedLiteralSetBuildLimits;

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
    fn languages_without_a_bounded_complete_column_keep_k0() {
        let dictionary = dictionary_with_guards(
            &[b"_x", b"x1", b"AB", b"ab", b"z9"],
            Guard::LeftBoundary,
            Guard::RightBoundary,
        );
        assert!(matches!(
            Plan::build(
                dictionary,
                PackedLiteralSetBuildLimits::default(),
                usize::MAX,
            ),
            Err(fre_kernels::PackedLiteralSetError::UnsupportedTargetOrShape),
        ));
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
