//! Eager, bounded dictionaries for already-proved maximal ASCII-word paths.
//!
//! This module is a construction prerequisite only. It does not inspect HIR,
//! select an aggregate route or scan a haystack. A caller supplies exact source
//! dimensions plus an exact-size stream of nonempty ASCII-word byte strings.
//! The dictionary retains the exact bytes, endpoint guards, source order and
//! duplicates for identity, while building a separate sorted fingerprint index
//! for eager lookup. Fingerprints are only a filter: lookup always confirms a
//! candidate with full-byte equality before returning a source entry.

#![allow(
    clippy::result_large_err,
    reason = "reducer failures retain complete allocation-free prospective/actual evidence"
)]

use core::{cmp::Ordering, fmt, mem::size_of};

use fre_exact_alloc::{CopyError, ExactVec};

/// Stable identity for this prerequisite representation.
pub const PLAN_ID: &str = "guarded-ascii-word-dictionary.exact-packed.v1";
/// Stable identity for the source-order byte and entry encoding.
pub const PACKING_ID: &str = "guarded-ascii-word-dictionary.packed-ranges.v1";
/// Stable identity for the derived lookup representation.
pub const LOOKUP_ID: &str = "guarded-ascii-word-dictionary.sorted-fingerprint-full-equality.v1";
/// Stable identity for the non-authoritative lookup fingerprint.
pub const FINGERPRINT_ID: &str = "guarded-ascii-word-dictionary.length-byte-sum.v1";

const FIXED_BUILD_WORK: u64 = 64;
const SOURCE_LEN_CALL_WORK: u64 = 4;
const SOURCE_NEXT_CALL_WORK: u64 = 8;
const SOURCE_WORD_WORK: u64 = 2;
const UNEXPECTED_SOURCE_YIELD_WORK: u64 = 2;
const GUARD_CHECK_WORK: u64 = 1;
const ASCII_BYTE_CHECK_WORK: u64 = 1;
const BYTE_COPY_WORK: u64 = 4;
const ENTRY_WRITE_WORK: u64 = 4;
const LOOKUP_SLOT_WRITE_WORK: u64 = 4;
const SORT_COMPARISON_WORK: u64 = 2;
const SORT_SWAP_WORK: u64 = 4;
const ENTRY_IDENTITY_BYTES: usize = 10;

/// One accepted directional ASCII word-boundary assertion.
///
/// The direction is retained even for the full boundary assertion so the
/// identity records the exact semantic role proved by the HIR extractor. The
/// directional validation remains part of construction so an invalid proof
/// cannot be published as a dictionary identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Guard {
    LeftBoundary,
    LeftStart,
    LeftStartHalf,
    RightBoundary,
    RightEnd,
    RightEndHalf,
}

impl Guard {
    const fn valid_left(self) -> bool {
        matches!(
            self,
            Self::LeftBoundary | Self::LeftStart | Self::LeftStartHalf
        )
    }

    const fn valid_right(self) -> bool {
        matches!(
            self,
            Self::RightBoundary | Self::RightEnd | Self::RightEndHalf
        )
    }
}

/// One finite source path supplied by the HIR-side prerequisite proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceWord<'a> {
    pub bytes: &'a [u8],
    pub left: Guard,
    pub right: Guard,
}

/// Exact dimensions computed by the finite-language prerequisite before the
/// dictionary consumes its source iterator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildDimensions {
    pub words: usize,
    pub packed_bytes: usize,
}

/// Independently bounded construction resources.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub max_words: usize,
    pub max_packed_bytes: usize,
    pub max_identity_bytes: usize,
    pub max_sort_comparisons: usize,
    pub max_allocations: usize,
    pub max_initialized_bytes: usize,
    pub max_build_work: u64,
    pub max_scratch_bytes: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl BuildLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_words: usize::MAX,
            max_packed_bytes: usize::MAX,
            max_identity_bytes: usize::MAX,
            max_sort_comparisons: usize::MAX,
            max_allocations: usize::MAX,
            max_initialized_bytes: usize::MAX,
            max_build_work: u64::MAX,
            max_scratch_bytes: usize::MAX,
            max_persistent_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            max_words: 4_096,
            max_packed_bytes: 4 << 20,
            max_identity_bytes: 8 << 20,
            max_sort_comparisons: 16 << 20,
            max_allocations: 3,
            max_initialized_bytes: 8 << 20,
            max_build_work: 64 << 20,
            max_scratch_bytes: 0,
            max_persistent_bytes: 64 << 20,
            max_peak_bytes: 64 << 20,
        }
    }
}

/// A construction resource refused before the first source `next` call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildResource {
    Words,
    PackedBytes,
    IdentityBytes,
    SortComparisons,
    Allocations,
    InitializedBytes,
    Work,
    ScratchBytes,
    PersistentBytes,
    PeakBytes,
}

/// Complete construction envelope derived from declared dimensions before
/// allocating storage or consuming the source iterator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildProspective {
    pub dimensions: BuildDimensions,
    pub source_len_calls: usize,
    pub source_next_calls: usize,
    pub unexpected_source_yields: usize,
    pub guard_checks: usize,
    pub ascii_byte_checks: usize,
    pub byte_copies: usize,
    pub entry_writes: usize,
    pub lookup_slot_writes: usize,
    pub sort_comparisons: usize,
    pub sort_swaps: usize,
    pub allocations: usize,
    pub initialized_bytes: usize,
    pub identity_bytes: usize,
    pub build_work: u64,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Exact resources observed through transactional construction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BuildActual {
    pub source_len_calls: usize,
    pub source_next_calls: usize,
    pub unexpected_source_yields: usize,
    pub source_words: usize,
    pub guard_checks: usize,
    pub ascii_byte_checks: usize,
    pub byte_copies: usize,
    pub entry_writes: usize,
    pub lookup_slot_writes: usize,
    pub sort_comparisons: usize,
    pub sort_swaps: usize,
    pub allocations: usize,
    pub initialized_bytes: usize,
    pub identity_bytes: usize,
    pub build_work: u64,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
    pub published: bool,
}

/// Prospective and actual construction receipts retained by the dictionary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub prospective: BuildProspective,
    pub actual: BuildActual,
}

/// Compact, lossless accounting for a successfully published dictionary.
///
/// Every successful construction counter except heap-sort work is fixed by
/// [`BuildProspective`]. Retaining the two variable sort counters and the
/// independently checked work total therefore reconstructs the complete
/// [`BuildActual`] without enlarging aggregate facade reports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishedBuildAccounting {
    pub prospective: BuildProspective,
    pub sort_comparisons: usize,
    pub sort_swaps: usize,
    pub build_work: u64,
}

impl BuildAccounting {
    /// Compact a complete receipt only when it is the exact successful
    /// publication implied by its prospective envelope.
    #[must_use]
    pub fn published(self) -> Option<PublishedBuildAccounting> {
        let published = PublishedBuildAccounting {
            prospective: self.prospective,
            sort_comparisons: self.actual.sort_comparisons,
            sort_swaps: self.actual.sort_swaps,
            build_work: self.actual.build_work,
        };
        (published.actual() == Some(self.actual)).then_some(published)
    }
}

impl PublishedBuildAccounting {
    /// Reconstruct every exact successful construction counter.
    #[must_use]
    pub fn actual(self) -> Option<BuildActual> {
        let prospective = self.prospective;
        let actual = BuildActual {
            source_len_calls: prospective.source_len_calls,
            source_next_calls: prospective.source_next_calls,
            unexpected_source_yields: 0,
            source_words: prospective.dimensions.words,
            guard_checks: prospective.guard_checks,
            ascii_byte_checks: prospective.ascii_byte_checks,
            byte_copies: prospective.byte_copies,
            entry_writes: prospective.entry_writes,
            lookup_slot_writes: prospective.lookup_slot_writes,
            sort_comparisons: self.sort_comparisons,
            sort_swaps: self.sort_swaps,
            allocations: prospective.allocations,
            initialized_bytes: prospective.initialized_bytes,
            identity_bytes: prospective.identity_bytes,
            build_work: self.build_work,
            scratch_bytes: prospective.scratch_bytes,
            persistent_bytes: prospective.persistent_bytes,
            peak_bytes: prospective.peak_bytes,
            published: true,
        };
        verify_actual(prospective, actual).ok()?;
        (actual_build_work(actual).ok()? == self.build_work).then_some(actual)
    }

    /// Expand the compact successful receipt into the general P/A form.
    #[must_use]
    pub fn expand(self) -> Option<BuildAccounting> {
        Some(BuildAccounting {
            prospective: self.prospective,
            actual: self.actual()?,
        })
    }
}

/// One exact source-order entry in the borrowed dictionary identity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EntryIdentity {
    pub start: u32,
    pub end: u32,
    pub left: Guard,
    pub right: Guard,
}

/// Exact borrowed semantic identity. Packed bytes and entries retain source
/// order and duplicates; the derived lookup slots are intentionally excluded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity<'a> {
    pub plan_id: &'static str,
    pub packing_id: &'static str,
    pub lookup_id: &'static str,
    pub fingerprint_id: &'static str,
    pub packed_bytes: &'a [u8],
    pub entries: &'a [EntryIdentity],
}

/// A collision-confirmed dictionary result in original source order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LookupMatch {
    pub source_index: usize,
    pub left: Guard,
    pub right: Guard,
}

/// Typed construction failure with allocation-free compact accounting.
///
/// [`Self::prospective`] is present once complete declared dimensions have
/// been closed. [`Self::actual`] reconstructs every counter observed before
/// refusal. Keeping the snapshot compact prevents error propagation itself
/// from requiring another allocation after an allocation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildError {
    pub kind: BuildErrorKind,
    dimensions: Option<BuildDimensions>,
    actual: ErrorActual,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuildErrorKind {
    EmptyDictionary,
    ImpossibleDimensions {
        words: usize,
        packed_bytes: usize,
    },
    SourceLengthMismatch {
        expected: usize,
        actual: usize,
    },
    PackedBytesMismatch {
        expected: usize,
        actual: usize,
    },
    EmptyWord {
        source_index: usize,
    },
    InvalidLeftGuard {
        source_index: usize,
        guard: Guard,
    },
    InvalidRightGuard {
        source_index: usize,
        guard: Guard,
    },
    NonAsciiWordByte {
        source_index: usize,
        byte_index: usize,
        byte: u8,
    },
    RepresentationLimit {
        structure: &'static str,
        needed: usize,
    },
    ResourceLimit {
        resource: BuildResource,
        needed: usize,
        limit: usize,
    },
    WorkLimit {
        needed: u64,
        limit: u64,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    AllocationFailed {
        structure: &'static str,
        additional: usize,
    },
    InternalInvariant {
        detail: &'static str,
    },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ErrorActual {
    source_next_calls: u64,
    guard_checks: u64,
    sort_comparisons: u64,
    sort_swaps: u64,
    source_words: u32,
    ascii_byte_checks: u32,
    byte_copies: u32,
    entry_writes: u32,
    lookup_slot_writes: u32,
    source_len_calls: u8,
    unexpected_source_yields: u8,
    allocations: u8,
    work_started: bool,
    identity_complete: bool,
    published: bool,
}

impl BuildError {
    /// Reconstruct the complete admitted envelope, if dimension closure
    /// succeeded before the error.
    #[must_use]
    pub fn prospective(&self) -> Option<BuildProspective> {
        self.dimensions
            .and_then(|dimensions| close_prospective(dimensions).ok())
    }

    /// Reconstruct exact work and storage observed before the error.
    #[must_use]
    pub fn actual(&self) -> BuildActual {
        self.actual.expand(self.prospective())
    }
}

impl ErrorActual {
    fn capture(actual: BuildActual) -> Self {
        Self {
            source_next_calls: compact_u64(actual.source_next_calls),
            guard_checks: compact_u64(actual.guard_checks),
            sort_comparisons: compact_u64(actual.sort_comparisons),
            sort_swaps: compact_u64(actual.sort_swaps),
            source_words: compact_u32(actual.source_words),
            ascii_byte_checks: compact_u32(actual.ascii_byte_checks),
            byte_copies: compact_u32(actual.byte_copies),
            entry_writes: compact_u32(actual.entry_writes),
            lookup_slot_writes: compact_u32(actual.lookup_slot_writes),
            source_len_calls: compact_u8(actual.source_len_calls),
            unexpected_source_yields: compact_u8(actual.unexpected_source_yields),
            allocations: compact_u8(actual.allocations),
            work_started: true,
            identity_complete: actual.identity_bytes != 0,
            published: actual.published,
        }
    }

    fn expand(self, prospective: Option<BuildProspective>) -> BuildActual {
        let mut actual = BuildActual {
            source_len_calls: expand_usize(self.source_len_calls),
            source_next_calls: expand_usize(self.source_next_calls),
            unexpected_source_yields: expand_usize(self.unexpected_source_yields),
            source_words: expand_usize(self.source_words),
            guard_checks: expand_usize(self.guard_checks),
            ascii_byte_checks: expand_usize(self.ascii_byte_checks),
            byte_copies: expand_usize(self.byte_copies),
            entry_writes: expand_usize(self.entry_writes),
            lookup_slot_writes: expand_usize(self.lookup_slot_writes),
            sort_comparisons: expand_usize(self.sort_comparisons),
            sort_swaps: expand_usize(self.sort_swaps),
            allocations: usize::from(self.allocations),
            initialized_bytes: 0,
            identity_bytes: 0,
            build_work: 0,
            scratch_bytes: 0,
            persistent_bytes: 0,
            peak_bytes: 0,
            published: self.published,
        };
        actual.initialized_bytes = initialized_bytes_from_actual(actual).unwrap_or(usize::MAX);
        if let Some(envelope) = prospective {
            actual.persistent_bytes =
                partial_persistent_bytes(envelope, actual.allocations).unwrap_or(usize::MAX);
            actual.peak_bytes = actual.persistent_bytes;
            if self.identity_complete {
                actual.identity_bytes = envelope.identity_bytes;
            }
        }
        if self.work_started {
            actual.build_work = actual_build_work(actual).unwrap_or(u64::MAX);
        }
        actual
    }
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "guarded ASCII-word dictionary build failed: {:?}",
            self.kind
        )
    }
}

impl std::error::Error for BuildError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LookupSlot {
    fingerprint: u64,
    source_index: u32,
}

/// Immutable exact source identity plus a derived eager lookup index.
#[derive(Debug)]
pub struct Dictionary {
    packed: ExactVec<u8>,
    entries: ExactVec<EntryIdentity>,
    lookup: ExactVec<LookupSlot>,
    accounting_dimensions: BuildDimensions,
    accounting_actual: ErrorActual,
}

struct BuildState {
    packed: ExactVec<u8>,
    entries: ExactVec<EntryIdentity>,
    lookup: ExactVec<LookupSlot>,
    actual: BuildActual,
}

impl Dictionary {
    /// Close the allocation-free dictionary envelope from exact source
    /// dimensions. Callers can reserve these resources before materializing
    /// or traversing their source representation.
    pub fn prospective(dimensions: BuildDimensions) -> Result<BuildProspective, BuildError> {
        close_prospective(dimensions).map_err(preflight_error)
    }

    /// Build from dimensions already counted by the finite-language planner.
    ///
    /// Every dimension-dependent limit, exact allocation and worst-case sort
    /// comparison is admitted before the first call to `source.next()`.
    pub fn build_precounted<'a, I>(
        dimensions: BuildDimensions,
        mut source: I,
        limits: BuildLimits,
    ) -> Result<Self, BuildError>
    where
        I: ExactSizeIterator<Item = SourceWord<'a>>,
    {
        let prospective = Self::prospective(dimensions)?;
        enforce_limits(prospective, limits).map_err(|kind| admission_error(kind, prospective))?;
        let actual = BuildActual {
            source_len_calls: 1,
            ..BuildActual::default()
        };
        let reported_words = source.len();
        if reported_words != dimensions.words {
            return Err(construction_error(
                BuildErrorKind::SourceLengthMismatch {
                    expected: dimensions.words,
                    actual: reported_words,
                },
                prospective,
                actual,
            ));
        }

        let mut state = allocate_build_state(dimensions, prospective, actual)?;
        for source_index in 0..dimensions.words {
            let word = next_source_word(
                &mut source,
                source_index,
                dimensions.words,
                prospective,
                &mut state.actual,
            )?;
            publish_source_word(dimensions, source_index, word, prospective, &mut state)?;
        }
        probe_source_exhaustion(dimensions, &mut source, prospective, &mut state)?;
        state.actual.identity_bytes = prospective.identity_bytes;
        state.actual.scratch_bytes = 0;
        heap_sort(state.lookup.as_mut_slice(), prospective, &mut state.actual)?;
        state.actual.build_work = actual_build_work(state.actual)
            .map_err(|kind| construction_error(kind, prospective, state.actual))?;
        verify_actual(prospective, state.actual)
            .map_err(|kind| construction_error(kind, prospective, state.actual))?;
        state.actual.published = true;

        Ok(Self {
            packed: state.packed,
            entries: state.entries,
            lookup: state.lookup,
            accounting_dimensions: dimensions,
            accounting_actual: ErrorActual::capture(state.actual),
        })
    }

    #[must_use]
    pub fn build_accounting(&self) -> BuildAccounting {
        let Ok(prospective) = close_prospective(self.accounting_dimensions) else {
            unreachable!("a published dictionary's admitted dimensions remain valid");
        };
        BuildAccounting {
            prospective,
            actual: self.accounting_actual.expand(Some(prospective)),
        }
    }

    #[must_use]
    pub fn identity(&self) -> Identity<'_> {
        Identity {
            plan_id: PLAN_ID,
            packing_id: PACKING_ID,
            lookup_id: LOOKUP_ID,
            fingerprint_id: FINGERPRINT_ID,
            packed_bytes: self.packed.as_slice(),
            entries: self.entries.as_slice(),
        }
    }

    /// Look up one complete maximal ASCII-word candidate.
    ///
    /// Fingerprint equality only narrows the persistent index. A result is
    /// returned only after exact comparison with the retained source bytes.
    #[must_use]
    pub fn lookup(&self, candidate: &[u8]) -> Option<LookupMatch> {
        self.lookup_at_or_after(candidate, 0)
    }

    /// Look up the first complete candidate whose original source index is at
    /// least `minimum_source_index`.
    ///
    /// Repeating this operation after a caller rejects one entry's guards
    /// preserves priority among duplicate byte strings carrying different
    /// guard pairs.
    #[must_use]
    pub fn lookup_at_or_after(
        &self,
        candidate: &[u8],
        minimum_source_index: usize,
    ) -> Option<LookupMatch> {
        if candidate.is_empty() || !candidate.iter().copied().all(is_ascii_word) {
            return None;
        }
        let fingerprint = fingerprint(candidate).ok()?;
        let slots = self.lookup.as_slice();
        let mut low = 0_usize;
        let mut high = slots.len();
        while low < high {
            let width = high.checked_sub(low)?;
            let middle = low.checked_add(width.checked_div(2)?)?;
            if slots[middle].fingerprint < fingerprint {
                low = middle.checked_add(1)?;
            } else {
                high = middle;
            }
        }
        for slot in &slots[low..] {
            if slot.fingerprint != fingerprint {
                break;
            }
            let source_index = usize::try_from(slot.source_index).ok()?;
            if source_index < minimum_source_index {
                continue;
            }
            let entry = *self.entries.as_slice().get(source_index)?;
            let start = usize::try_from(entry.start).ok()?;
            let end = usize::try_from(entry.end).ok()?;
            if self.packed.as_slice().get(start..end) == Some(candidate) {
                return Some(LookupMatch {
                    source_index,
                    left: entry.left,
                    right: entry.right,
                });
            }
        }
        None
    }
}

fn allocate_build_state(
    dimensions: BuildDimensions,
    prospective: BuildProspective,
    mut actual: BuildActual,
) -> Result<BuildState, BuildError> {
    let packed = allocate_exact::<u8>(dimensions.packed_bytes, "packed bytes")
        .map_err(|kind| construction_error(kind, prospective, actual))?;
    actual.allocations = 1;
    refresh_memory_actual(&mut actual, &packed, None, None)
        .map_err(|kind| construction_error(kind, prospective, actual))?;

    let entries = allocate_exact::<EntryIdentity>(dimensions.words, "entries")
        .map_err(|kind| construction_error(kind, prospective, actual))?;
    actual.allocations = 2;
    refresh_memory_actual(&mut actual, &packed, Some(&entries), None)
        .map_err(|kind| construction_error(kind, prospective, actual))?;

    let lookup = allocate_exact::<LookupSlot>(dimensions.words, "lookup slots")
        .map_err(|kind| construction_error(kind, prospective, actual))?;
    actual.allocations = 3;
    refresh_memory_actual(&mut actual, &packed, Some(&entries), Some(&lookup))
        .map_err(|kind| construction_error(kind, prospective, actual))?;
    Ok(BuildState {
        packed,
        entries,
        lookup,
        actual,
    })
}

fn next_source_word<'a, I>(
    source: &mut I,
    source_index: usize,
    expected_words: usize,
    prospective: BuildProspective,
    actual: &mut BuildActual,
) -> Result<SourceWord<'a>, BuildError>
where
    I: Iterator<Item = SourceWord<'a>>,
{
    actual.source_next_calls = actual
        .source_next_calls
        .checked_add(1)
        .ok_or_else(|| overflow_error("source next calls", prospective, *actual))?;
    let Some(word) = source.next() else {
        return Err(construction_error(
            BuildErrorKind::SourceLengthMismatch {
                expected: expected_words,
                actual: source_index,
            },
            prospective,
            *actual,
        ));
    };
    actual.source_words = actual
        .source_words
        .checked_add(1)
        .ok_or_else(|| overflow_error("actual source words", prospective, *actual))?;
    Ok(word)
}

fn publish_source_word(
    dimensions: BuildDimensions,
    source_index: usize,
    word: SourceWord<'_>,
    prospective: BuildProspective,
    state: &mut BuildState,
) -> Result<(), BuildError> {
    validate_guards(source_index, word, prospective, &mut state.actual)?;
    if word.bytes.is_empty() {
        return Err(construction_error(
            BuildErrorKind::EmptyWord { source_index },
            prospective,
            state.actual,
        ));
    }
    let start = state.packed.len();
    let end = start
        .checked_add(word.bytes.len())
        .ok_or_else(|| overflow_error("packed source end", prospective, state.actual))?;
    if end > dimensions.packed_bytes {
        return Err(construction_error(
            BuildErrorKind::PackedBytesMismatch {
                expected: dimensions.packed_bytes,
                actual: end,
            },
            prospective,
            state.actual,
        ));
    }
    let byte_sum = copy_source_bytes(source_index, word.bytes, prospective, state)?;
    publish_entry(start, end, source_index, word, byte_sum, prospective, state)
}

fn copy_source_bytes(
    source_index: usize,
    bytes: &[u8],
    prospective: BuildProspective,
    state: &mut BuildState,
) -> Result<u64, BuildError> {
    let mut byte_sum = 0_u64;
    for (byte_index, &byte) in bytes.iter().enumerate() {
        state.actual.ascii_byte_checks = state
            .actual
            .ascii_byte_checks
            .checked_add(1)
            .ok_or_else(|| overflow_error("actual ASCII byte checks", prospective, state.actual))?;
        if !is_ascii_word(byte) {
            return Err(construction_error(
                BuildErrorKind::NonAsciiWordByte {
                    source_index,
                    byte_index,
                    byte,
                },
                prospective,
                state.actual,
            ));
        }
        byte_sum = byte_sum.checked_add(u64::from(byte)).ok_or_else(|| {
            overflow_error("lookup fingerprint byte sum", prospective, state.actual)
        })?;
        state.packed.try_push(byte).map_err(|_| {
            construction_error(
                BuildErrorKind::InternalInvariant {
                    detail: "precounted packed byte capacity was exhausted",
                },
                prospective,
                state.actual,
            )
        })?;
        state.actual.byte_copies = state
            .actual
            .byte_copies
            .checked_add(1)
            .ok_or_else(|| overflow_error("actual byte copies", prospective, state.actual))?;
        refresh_initialized_actual(
            &mut state.actual,
            &state.packed,
            &state.entries,
            &state.lookup,
        )
        .map_err(|kind| construction_error(kind, prospective, state.actual))?;
    }
    Ok(byte_sum)
}

fn publish_entry(
    start: usize,
    end: usize,
    source_index: usize,
    word: SourceWord<'_>,
    byte_sum: u64,
    prospective: BuildProspective,
    state: &mut BuildState,
) -> Result<(), BuildError> {
    let entry = EntryIdentity {
        start: u32::try_from(start).map_err(|_| {
            construction_error(
                BuildErrorKind::RepresentationLimit {
                    structure: "entry start",
                    needed: start,
                },
                prospective,
                state.actual,
            )
        })?,
        end: u32::try_from(end).map_err(|_| {
            construction_error(
                BuildErrorKind::RepresentationLimit {
                    structure: "entry end",
                    needed: end,
                },
                prospective,
                state.actual,
            )
        })?,
        left: word.left,
        right: word.right,
    };
    state.entries.try_push(entry).map_err(|_| {
        construction_error(
            BuildErrorKind::InternalInvariant {
                detail: "precounted entry capacity was exhausted",
            },
            prospective,
            state.actual,
        )
    })?;
    state.actual.entry_writes = state
        .actual
        .entry_writes
        .checked_add(1)
        .ok_or_else(|| overflow_error("actual entry writes", prospective, state.actual))?;
    refresh_initialized_actual(
        &mut state.actual,
        &state.packed,
        &state.entries,
        &state.lookup,
    )
    .map_err(|kind| construction_error(kind, prospective, state.actual))?;
    publish_lookup(source_index, word.bytes.len(), byte_sum, prospective, state)
}

fn publish_lookup(
    source_index: usize,
    word_bytes: usize,
    byte_sum: u64,
    prospective: BuildProspective,
    state: &mut BuildState,
) -> Result<(), BuildError> {
    let fingerprint = finish_fingerprint(word_bytes, byte_sum)
        .map_err(|kind| construction_error(kind, prospective, state.actual))?;
    let source_index = u32::try_from(source_index).map_err(|_| {
        construction_error(
            BuildErrorKind::RepresentationLimit {
                structure: "lookup source index",
                needed: source_index,
            },
            prospective,
            state.actual,
        )
    })?;
    state
        .lookup
        .try_push(LookupSlot {
            fingerprint,
            source_index,
        })
        .map_err(|_| {
            construction_error(
                BuildErrorKind::InternalInvariant {
                    detail: "precounted lookup capacity was exhausted",
                },
                prospective,
                state.actual,
            )
        })?;
    state.actual.lookup_slot_writes = state
        .actual
        .lookup_slot_writes
        .checked_add(1)
        .ok_or_else(|| overflow_error("actual lookup slot writes", prospective, state.actual))?;
    refresh_initialized_actual(
        &mut state.actual,
        &state.packed,
        &state.entries,
        &state.lookup,
    )
    .map_err(|kind| construction_error(kind, prospective, state.actual))
}

fn probe_source_exhaustion<'a, I>(
    dimensions: BuildDimensions,
    source: &mut I,
    prospective: BuildProspective,
    state: &mut BuildState,
) -> Result<(), BuildError>
where
    I: Iterator<Item = SourceWord<'a>>,
{
    state.actual.source_next_calls = state
        .actual
        .source_next_calls
        .checked_add(1)
        .ok_or_else(|| overflow_error("source exhaustion probe", prospective, state.actual))?;
    if source.next().is_some() {
        state.actual.unexpected_source_yields = state
            .actual
            .unexpected_source_yields
            .checked_add(1)
            .ok_or_else(|| overflow_error("unexpected source yields", prospective, state.actual))?;
        let actual_words = dimensions
            .words
            .checked_add(1)
            .ok_or_else(|| overflow_error("extra source word count", prospective, state.actual))?;
        return Err(construction_error(
            BuildErrorKind::SourceLengthMismatch {
                expected: dimensions.words,
                actual: actual_words,
            },
            prospective,
            state.actual,
        ));
    }
    if state.packed.len() != dimensions.packed_bytes {
        return Err(construction_error(
            BuildErrorKind::PackedBytesMismatch {
                expected: dimensions.packed_bytes,
                actual: state.packed.len(),
            },
            prospective,
            state.actual,
        ));
    }
    Ok(())
}

fn close_prospective(dimensions: BuildDimensions) -> Result<BuildProspective, BuildErrorKind> {
    if dimensions.words == 0 {
        return Err(BuildErrorKind::EmptyDictionary);
    }
    if dimensions.packed_bytes < dimensions.words {
        return Err(BuildErrorKind::ImpossibleDimensions {
            words: dimensions.words,
            packed_bytes: dimensions.packed_bytes,
        });
    }
    if dimensions.words > usize::try_from(u32::MAX).unwrap_or(usize::MAX) {
        return Err(BuildErrorKind::RepresentationLimit {
            structure: "source indices",
            needed: dimensions.words,
        });
    }
    if dimensions.packed_bytes > usize::try_from(u32::MAX).unwrap_or(usize::MAX) {
        return Err(BuildErrorKind::RepresentationLimit {
            structure: "packed byte offsets",
            needed: dimensions.packed_bytes,
        });
    }
    let source_next_calls =
        dimensions
            .words
            .checked_add(1)
            .ok_or(BuildErrorKind::ArithmeticOverflow {
                computation: "source next calls",
            })?;
    let guard_checks =
        dimensions
            .words
            .checked_mul(2)
            .ok_or(BuildErrorKind::ArithmeticOverflow {
                computation: "guard checks",
            })?;
    let (sort_comparisons, sort_swaps) = heap_sort_bounds(dimensions.words)?;
    let (initialized_bytes, identity_bytes, persistent_bytes) = storage_bounds(dimensions)?;
    let source_len_calls = 1;
    let unexpected_source_yields = 1;
    let build_work = build_work(BuildWorkCounts {
        source_len_calls,
        source_next_calls,
        unexpected_source_yields,
        source_words: dimensions.words,
        guard_checks,
        ascii_byte_checks: dimensions.packed_bytes,
        byte_copies: dimensions.packed_bytes,
        entry_writes: dimensions.words,
        lookup_slot_writes: dimensions.words,
        sort_comparisons,
        sort_swaps,
    })?;
    Ok(BuildProspective {
        dimensions,
        source_len_calls,
        source_next_calls,
        unexpected_source_yields,
        guard_checks,
        ascii_byte_checks: dimensions.packed_bytes,
        byte_copies: dimensions.packed_bytes,
        entry_writes: dimensions.words,
        lookup_slot_writes: dimensions.words,
        sort_comparisons,
        sort_swaps,
        allocations: 3,
        initialized_bytes,
        identity_bytes,
        build_work,
        scratch_bytes: 0,
        persistent_bytes,
        peak_bytes: persistent_bytes,
    })
}

fn storage_bounds(dimensions: BuildDimensions) -> Result<(usize, usize, usize), BuildErrorKind> {
    let entry_heap_bytes = dimensions
        .words
        .checked_mul(size_of::<EntryIdentity>())
        .ok_or(BuildErrorKind::ArithmeticOverflow {
            computation: "entry heap bytes",
        })?;
    let lookup_heap_bytes = dimensions
        .words
        .checked_mul(size_of::<LookupSlot>())
        .ok_or(BuildErrorKind::ArithmeticOverflow {
            computation: "lookup heap bytes",
        })?;
    let initialized_bytes = dimensions
        .packed_bytes
        .checked_add(entry_heap_bytes)
        .and_then(|bytes| bytes.checked_add(lookup_heap_bytes))
        .ok_or(BuildErrorKind::ArithmeticOverflow {
            computation: "initialized bytes",
        })?;
    let identity_bytes = dimensions
        .words
        .checked_mul(ENTRY_IDENTITY_BYTES)
        .and_then(|bytes| bytes.checked_add(dimensions.packed_bytes))
        .ok_or(BuildErrorKind::ArithmeticOverflow {
            computation: "identity bytes",
        })?;
    let persistent_bytes = size_of::<Dictionary>()
        .checked_add(initialized_bytes)
        .ok_or(BuildErrorKind::ArithmeticOverflow {
            computation: "persistent bytes",
        })?;
    Ok((initialized_bytes, identity_bytes, persistent_bytes))
}

#[derive(Clone, Copy)]
struct BuildWorkCounts {
    source_len_calls: usize,
    source_next_calls: usize,
    unexpected_source_yields: usize,
    source_words: usize,
    guard_checks: usize,
    ascii_byte_checks: usize,
    byte_copies: usize,
    entry_writes: usize,
    lookup_slot_writes: usize,
    sort_comparisons: usize,
    sort_swaps: usize,
}

fn build_work(counts: BuildWorkCounts) -> Result<u64, BuildErrorKind> {
    let source_len_work = weighted_work(
        counts.source_len_calls,
        SOURCE_LEN_CALL_WORK,
        "source-len-call work",
    )?;
    let source_next_work = weighted_work(
        counts.source_next_calls,
        SOURCE_NEXT_CALL_WORK,
        "source-next-call work",
    )?;
    let source_word_work =
        weighted_work(counts.source_words, SOURCE_WORD_WORK, "source-word work")?;
    let unexpected_yield_work = weighted_work(
        counts.unexpected_source_yields,
        UNEXPECTED_SOURCE_YIELD_WORK,
        "unexpected-source-yield work",
    )?;
    let guard_check_work =
        weighted_work(counts.guard_checks, GUARD_CHECK_WORK, "guard-check work")?;
    let ascii_check_work = weighted_work(
        counts.ascii_byte_checks,
        ASCII_BYTE_CHECK_WORK,
        "ASCII-byte-check work",
    )?;
    let byte_copy_work = weighted_work(counts.byte_copies, BYTE_COPY_WORK, "byte-copy work")?;
    let entry_write_work =
        weighted_work(counts.entry_writes, ENTRY_WRITE_WORK, "entry-write work")?;
    let lookup_write_work = weighted_work(
        counts.lookup_slot_writes,
        LOOKUP_SLOT_WRITE_WORK,
        "lookup-slot-write work",
    )?;
    let comparison_work = weighted_work(
        counts.sort_comparisons,
        SORT_COMPARISON_WORK,
        "sort-comparison work",
    )?;
    let swap_work = weighted_work(counts.sort_swaps, SORT_SWAP_WORK, "sort-swap work")?;
    FIXED_BUILD_WORK
        .checked_add(source_len_work)
        .and_then(|work| work.checked_add(source_next_work))
        .and_then(|work| work.checked_add(source_word_work))
        .and_then(|work| work.checked_add(unexpected_yield_work))
        .and_then(|work| work.checked_add(guard_check_work))
        .and_then(|work| work.checked_add(ascii_check_work))
        .and_then(|work| work.checked_add(byte_copy_work))
        .and_then(|work| work.checked_add(entry_write_work))
        .and_then(|work| work.checked_add(lookup_write_work))
        .and_then(|work| work.checked_add(comparison_work))
        .and_then(|work| work.checked_add(swap_work))
        .ok_or(BuildErrorKind::ArithmeticOverflow {
            computation: "build work",
        })
}

fn weighted_work(
    count: usize,
    weight: u64,
    computation: &'static str,
) -> Result<u64, BuildErrorKind> {
    as_u64(count, "build-work count as u64")?
        .checked_mul(weight)
        .ok_or(BuildErrorKind::ArithmeticOverflow { computation })
}

fn actual_build_work(actual: BuildActual) -> Result<u64, BuildErrorKind> {
    build_work(BuildWorkCounts {
        source_len_calls: actual.source_len_calls,
        source_next_calls: actual.source_next_calls,
        unexpected_source_yields: actual.unexpected_source_yields,
        source_words: actual.source_words,
        guard_checks: actual.guard_checks,
        ascii_byte_checks: actual.ascii_byte_checks,
        byte_copies: actual.byte_copies,
        entry_writes: actual.entry_writes,
        lookup_slot_writes: actual.lookup_slot_writes,
        sort_comparisons: actual.sort_comparisons,
        sort_swaps: actual.sort_swaps,
    })
}

fn initialized_bytes_from_actual(actual: BuildActual) -> Result<usize, BuildErrorKind> {
    let entry_bytes = actual
        .entry_writes
        .checked_mul(size_of::<EntryIdentity>())
        .ok_or(BuildErrorKind::ArithmeticOverflow {
            computation: "error-ledger initialized entry bytes",
        })?;
    let lookup_bytes = actual
        .lookup_slot_writes
        .checked_mul(size_of::<LookupSlot>())
        .ok_or(BuildErrorKind::ArithmeticOverflow {
            computation: "error-ledger initialized lookup bytes",
        })?;
    actual
        .byte_copies
        .checked_add(entry_bytes)
        .and_then(|bytes| bytes.checked_add(lookup_bytes))
        .ok_or(BuildErrorKind::ArithmeticOverflow {
            computation: "error-ledger initialized bytes",
        })
}

fn partial_persistent_bytes(
    prospective: BuildProspective,
    allocations: usize,
) -> Result<usize, BuildErrorKind> {
    if allocations == 0 {
        return Ok(0);
    }
    let dimensions = prospective.dimensions;
    let mut bytes = size_of::<Dictionary>()
        .checked_add(dimensions.packed_bytes)
        .ok_or(BuildErrorKind::ArithmeticOverflow {
            computation: "error-ledger packed persistent bytes",
        })?;
    if allocations >= 2 {
        bytes = dimensions
            .words
            .checked_mul(size_of::<EntryIdentity>())
            .and_then(|entry_bytes| bytes.checked_add(entry_bytes))
            .ok_or(BuildErrorKind::ArithmeticOverflow {
                computation: "error-ledger entry persistent bytes",
            })?;
    }
    if allocations >= 3 {
        bytes = dimensions
            .words
            .checked_mul(size_of::<LookupSlot>())
            .and_then(|lookup_bytes| bytes.checked_add(lookup_bytes))
            .ok_or(BuildErrorKind::ArithmeticOverflow {
                computation: "error-ledger lookup persistent bytes",
            })?;
    }
    Ok(bytes)
}

fn compact_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn compact_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn compact_u8(value: usize) -> u8 {
    u8::try_from(value).unwrap_or(u8::MAX)
}

fn expand_usize<T>(value: T) -> usize
where
    usize: TryFrom<T>,
{
    usize::try_from(value).unwrap_or(usize::MAX)
}

/// Bound bottom-up heap construction plus root extraction before source use.
///
/// Floyd heap construction descends at most
/// `E - popcount(E) = sum(floor(E / 2^k), k >= 1)` total levels. Extraction
/// descends at most `sum(floor(log2(h)), h = 1..E - 1)` more. Each descended
/// level performs at most two comparisons and one swap; every extraction adds
/// one root/tail swap. Thus both returned bounds are O(E log E), independent
/// of source bytes and comparison outcomes.
fn heap_sort_bounds(entries: usize) -> Result<(usize, usize), BuildErrorKind> {
    if entries <= 1 {
        return Ok((0, 0));
    }
    let populated_bits =
        usize::try_from(entries.count_ones()).map_err(|_| BuildErrorKind::ArithmeticOverflow {
            computation: "heap-sort populated-bit count",
        })?;
    let heapify_descents =
        entries
            .checked_sub(populated_bits)
            .ok_or(BuildErrorKind::ArithmeticOverflow {
                computation: "heap-sort heapify descent bound",
            })?;
    let extractions = entries
        .checked_sub(1)
        .ok_or(BuildErrorKind::ArithmeticOverflow {
            computation: "heap-sort extraction count",
        })?;
    let extraction_descents = log2_floor_sum(extractions)?;
    let descent_bound = heapify_descents.checked_add(extraction_descents).ok_or(
        BuildErrorKind::ArithmeticOverflow {
            computation: "heap-sort total descent bound",
        },
    )?;
    let comparisons = descent_bound
        .checked_mul(2)
        .ok_or(BuildErrorKind::ArithmeticOverflow {
            computation: "heap-sort comparison bound",
        })?;
    let swaps =
        descent_bound
            .checked_add(extractions)
            .ok_or(BuildErrorKind::ArithmeticOverflow {
                computation: "heap-sort swap bound",
            })?;
    Ok((comparisons, swaps))
}

fn log2_floor_sum(value: usize) -> Result<usize, BuildErrorKind> {
    if value == 0 {
        return Ok(0);
    }
    let (levels, power) = floor_log2_and_power(value)?;
    let lower_levels = if levels <= 1 {
        0
    } else {
        levels
            .checked_sub(2)
            .and_then(|factor| factor.checked_mul(power))
            .and_then(|subtotal| subtotal.checked_add(2))
            .ok_or(BuildErrorKind::ArithmeticOverflow {
                computation: "heap-sort lower complete levels",
            })?
    };
    let top_level_items = value
        .checked_sub(power)
        .and_then(|items| items.checked_add(1))
        .ok_or(BuildErrorKind::ArithmeticOverflow {
            computation: "heap-sort top-level item count",
        })?;
    levels
        .checked_mul(top_level_items)
        .and_then(|top| top.checked_add(lower_levels))
        .ok_or(BuildErrorKind::ArithmeticOverflow {
            computation: "heap-sort extraction descent bound",
        })
}

fn floor_log2_and_power(mut value: usize) -> Result<(usize, usize), BuildErrorKind> {
    let mut levels = 0_usize;
    let mut power = 1_usize;
    while value > 1 {
        value = value
            .checked_div(2)
            .ok_or(BuildErrorKind::ArithmeticOverflow {
                computation: "heap-sort logarithm division",
            })?;
        levels = levels
            .checked_add(1)
            .ok_or(BuildErrorKind::ArithmeticOverflow {
                computation: "heap-sort logarithm",
            })?;
        power = power
            .checked_mul(2)
            .ok_or(BuildErrorKind::ArithmeticOverflow {
                computation: "heap-sort logarithm power",
            })?;
    }
    Ok((levels, power))
}

fn enforce_limits(
    prospective: BuildProspective,
    limits: BuildLimits,
) -> Result<(), BuildErrorKind> {
    enforce(
        BuildResource::Words,
        prospective.dimensions.words,
        limits.max_words,
    )?;
    enforce(
        BuildResource::PackedBytes,
        prospective.dimensions.packed_bytes,
        limits.max_packed_bytes,
    )?;
    enforce(
        BuildResource::IdentityBytes,
        prospective.identity_bytes,
        limits.max_identity_bytes,
    )?;
    enforce(
        BuildResource::SortComparisons,
        prospective.sort_comparisons,
        limits.max_sort_comparisons,
    )?;
    enforce(
        BuildResource::Allocations,
        prospective.allocations,
        limits.max_allocations,
    )?;
    enforce(
        BuildResource::InitializedBytes,
        prospective.initialized_bytes,
        limits.max_initialized_bytes,
    )?;
    if prospective.build_work > limits.max_build_work {
        return Err(BuildErrorKind::WorkLimit {
            needed: prospective.build_work,
            limit: limits.max_build_work,
        });
    }
    enforce(
        BuildResource::ScratchBytes,
        prospective.scratch_bytes,
        limits.max_scratch_bytes,
    )?;
    enforce(
        BuildResource::PersistentBytes,
        prospective.persistent_bytes,
        limits.max_persistent_bytes,
    )?;
    enforce(
        BuildResource::PeakBytes,
        prospective.peak_bytes,
        limits.max_peak_bytes,
    )
}

fn enforce(resource: BuildResource, needed: usize, limit: usize) -> Result<(), BuildErrorKind> {
    if needed > limit {
        Err(BuildErrorKind::ResourceLimit {
            resource,
            needed,
            limit,
        })
    } else {
        Ok(())
    }
}

fn allocate_exact<T>(
    capacity: usize,
    structure: &'static str,
) -> Result<ExactVec<T>, BuildErrorKind> {
    ExactVec::try_with_capacity(capacity).map_err(|error| match error {
        CopyError::LayoutOverflow => BuildErrorKind::ArithmeticOverflow {
            computation: "exact allocation layout",
        },
        CopyError::AllocationFailed => BuildErrorKind::AllocationFailed {
            structure,
            additional: capacity,
        },
    })
}

fn validate_guards(
    source_index: usize,
    word: SourceWord<'_>,
    prospective: BuildProspective,
    actual: &mut BuildActual,
) -> Result<(), BuildError> {
    actual.guard_checks = actual
        .guard_checks
        .checked_add(1)
        .ok_or_else(|| overflow_error("left guard checks", prospective, *actual))?;
    if !word.left.valid_left() {
        return Err(construction_error(
            BuildErrorKind::InvalidLeftGuard {
                source_index,
                guard: word.left,
            },
            prospective,
            *actual,
        ));
    }
    actual.guard_checks = actual
        .guard_checks
        .checked_add(1)
        .ok_or_else(|| overflow_error("right guard checks", prospective, *actual))?;
    if !word.right.valid_right() {
        return Err(construction_error(
            BuildErrorKind::InvalidRightGuard {
                source_index,
                guard: word.right,
            },
            prospective,
            *actual,
        ));
    }
    Ok(())
}

fn refresh_memory_actual(
    actual: &mut BuildActual,
    packed: &ExactVec<u8>,
    entries: Option<&ExactVec<EntryIdentity>>,
    lookup: Option<&ExactVec<LookupSlot>>,
) -> Result<(), BuildErrorKind> {
    let packed_bytes = packed.capacity();
    let entry_bytes = entries.map_or(Ok(0), |values| {
        values
            .capacity()
            .checked_mul(size_of::<EntryIdentity>())
            .ok_or(BuildErrorKind::ArithmeticOverflow {
                computation: "actual entry capacity bytes",
            })
    })?;
    let lookup_bytes = lookup.map_or(Ok(0), |values| {
        values
            .capacity()
            .checked_mul(size_of::<LookupSlot>())
            .ok_or(BuildErrorKind::ArithmeticOverflow {
                computation: "actual lookup capacity bytes",
            })
    })?;
    actual.persistent_bytes = size_of::<Dictionary>()
        .checked_add(packed_bytes)
        .and_then(|bytes| bytes.checked_add(entry_bytes))
        .and_then(|bytes| bytes.checked_add(lookup_bytes))
        .ok_or(BuildErrorKind::ArithmeticOverflow {
            computation: "actual persistent bytes",
        })?;
    actual.peak_bytes = actual.persistent_bytes;
    Ok(())
}

fn refresh_initialized_actual(
    actual: &mut BuildActual,
    packed: &ExactVec<u8>,
    entries: &ExactVec<EntryIdentity>,
    lookup: &ExactVec<LookupSlot>,
) -> Result<(), BuildErrorKind> {
    let entry_bytes = entries
        .len()
        .checked_mul(size_of::<EntryIdentity>())
        .ok_or(BuildErrorKind::ArithmeticOverflow {
            computation: "actual initialized entry bytes",
        })?;
    let lookup_bytes = lookup.len().checked_mul(size_of::<LookupSlot>()).ok_or(
        BuildErrorKind::ArithmeticOverflow {
            computation: "actual initialized lookup bytes",
        },
    )?;
    actual.initialized_bytes = packed
        .len()
        .checked_add(entry_bytes)
        .and_then(|bytes| bytes.checked_add(lookup_bytes))
        .ok_or(BuildErrorKind::ArithmeticOverflow {
            computation: "actual initialized bytes",
        })?;
    Ok(())
}

fn heap_sort(
    slots: &mut [LookupSlot],
    prospective: BuildProspective,
    actual: &mut BuildActual,
) -> Result<(), BuildError> {
    let length = slots.len();
    let mut start = length
        .checked_div(2)
        .ok_or_else(|| overflow_error("heap-sort heapify start", prospective, *actual))?;
    while start > 0 {
        start = start
            .checked_sub(1)
            .ok_or_else(|| overflow_error("heap-sort heapify index", prospective, *actual))?;
        sift_down(slots, start, length, prospective, actual)?;
    }

    let mut end = length;
    while end > 1 {
        end = end
            .checked_sub(1)
            .ok_or_else(|| overflow_error("heap-sort extraction end", prospective, *actual))?;
        swap_counted(slots, 0, end, prospective, actual)?;
        sift_down(slots, 0, end, prospective, actual)?;
    }
    Ok(())
}

fn sift_down(
    slots: &mut [LookupSlot],
    mut root: usize,
    end: usize,
    prospective: BuildProspective,
    actual: &mut BuildActual,
) -> Result<(), BuildError> {
    let parent_limit = end
        .checked_div(2)
        .ok_or_else(|| overflow_error("heap-sort parent limit", prospective, *actual))?;
    while root < parent_limit {
        let left = root
            .checked_mul(2)
            .and_then(|index| index.checked_add(1))
            .ok_or_else(|| overflow_error("heap-sort left child", prospective, *actual))?;
        let right = left
            .checked_add(1)
            .ok_or_else(|| overflow_error("heap-sort right child", prospective, *actual))?;
        let mut greater_child = left;
        if right < end
            && compare_counted(slots[right], slots[left], prospective, actual)? == Ordering::Greater
        {
            greater_child = right;
        }
        if compare_counted(slots[root], slots[greater_child], prospective, actual)?
            != Ordering::Less
        {
            break;
        }
        swap_counted(slots, root, greater_child, prospective, actual)?;
        root = greater_child;
    }
    Ok(())
}

fn compare_counted(
    left: LookupSlot,
    right: LookupSlot,
    prospective: BuildProspective,
    actual: &mut BuildActual,
) -> Result<Ordering, BuildError> {
    let comparisons = actual
        .sort_comparisons
        .checked_add(1)
        .ok_or_else(|| overflow_error("actual sort comparisons", prospective, *actual))?;
    if comparisons > prospective.sort_comparisons {
        return Err(construction_error(
            BuildErrorKind::InternalInvariant {
                detail: "heap sort exceeded its admitted comparison bound",
            },
            prospective,
            *actual,
        ));
    }
    actual.sort_comparisons = comparisons;
    Ok(compare_slot(left, right))
}

fn swap_counted(
    slots: &mut [LookupSlot],
    left: usize,
    right: usize,
    prospective: BuildProspective,
    actual: &mut BuildActual,
) -> Result<(), BuildError> {
    let swaps = actual
        .sort_swaps
        .checked_add(1)
        .ok_or_else(|| overflow_error("actual sort swaps", prospective, *actual))?;
    if swaps > prospective.sort_swaps {
        return Err(construction_error(
            BuildErrorKind::InternalInvariant {
                detail: "heap sort exceeded its admitted swap bound",
            },
            prospective,
            *actual,
        ));
    }
    actual.sort_swaps = swaps;
    slots.swap(left, right);
    Ok(())
}

fn compare_slot(left: LookupSlot, right: LookupSlot) -> Ordering {
    left.fingerprint
        .cmp(&right.fingerprint)
        .then(left.source_index.cmp(&right.source_index))
}

fn fingerprint(bytes: &[u8]) -> Result<u64, BuildErrorKind> {
    let mut sum = 0_u64;
    for &byte in bytes {
        sum = sum
            .checked_add(u64::from(byte))
            .ok_or(BuildErrorKind::ArithmeticOverflow {
                computation: "lookup fingerprint byte sum",
            })?;
    }
    finish_fingerprint(bytes.len(), sum)
}

fn finish_fingerprint(bytes: usize, sum: u64) -> Result<u64, BuildErrorKind> {
    let length = as_u64(bytes, "fingerprint length as u64")?;
    Ok(length.rotate_left(32) ^ sum)
}

fn is_ascii_word(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn verify_actual(prospective: BuildProspective, actual: BuildActual) -> Result<(), BuildErrorKind> {
    let dimensions = prospective.dimensions;
    if actual.source_len_calls > prospective.source_len_calls
        || actual.source_next_calls > prospective.source_next_calls
        || actual.unexpected_source_yields > prospective.unexpected_source_yields
        || actual.source_words > dimensions.words
        || actual.guard_checks > prospective.guard_checks
        || actual.ascii_byte_checks > prospective.ascii_byte_checks
        || actual.byte_copies > prospective.byte_copies
        || actual.entry_writes > prospective.entry_writes
        || actual.lookup_slot_writes > prospective.lookup_slot_writes
        || actual.sort_comparisons > prospective.sort_comparisons
        || actual.sort_swaps > prospective.sort_swaps
        || actual.allocations > prospective.allocations
        || actual.initialized_bytes > prospective.initialized_bytes
        || actual.identity_bytes > prospective.identity_bytes
        || actual.build_work > prospective.build_work
        || actual.scratch_bytes > prospective.scratch_bytes
        || actual.persistent_bytes > prospective.persistent_bytes
        || actual.peak_bytes > prospective.peak_bytes
    {
        return Err(BuildErrorKind::InternalInvariant {
            detail: "actual construction counter exceeded its prospective bound",
        });
    }
    Ok(())
}

fn as_u64(value: usize, computation: &'static str) -> Result<u64, BuildErrorKind> {
    u64::try_from(value).map_err(|_| BuildErrorKind::ArithmeticOverflow { computation })
}

fn preflight_error(kind: BuildErrorKind) -> BuildError {
    BuildError {
        kind,
        dimensions: None,
        actual: ErrorActual::default(),
    }
}

fn admission_error(kind: BuildErrorKind, prospective: BuildProspective) -> BuildError {
    BuildError {
        kind,
        dimensions: Some(prospective.dimensions),
        actual: ErrorActual::default(),
    }
}

fn construction_error(
    kind: BuildErrorKind,
    prospective: BuildProspective,
    mut actual: BuildActual,
) -> BuildError {
    let kind = match actual_build_work(actual) {
        Ok(work) => {
            actual.build_work = work;
            kind
        }
        Err(work_error) => work_error,
    };
    BuildError {
        kind,
        dimensions: Some(prospective.dimensions),
        actual: ErrorActual::capture(actual),
    }
}

fn overflow_error(
    computation: &'static str,
    prospective: BuildProspective,
    actual: BuildActual,
) -> BuildError {
    construction_error(
        BuildErrorKind::ArithmeticOverflow { computation },
        prospective,
        actual,
    )
}

/// Stable identity for the allocation-free maximal ASCII-word count reducer.
pub const COUNT_OPERATION_ID: &str = "guarded-ascii-word-dictionary.maximal-word-count.v1";
/// Stable identity for the allocation-free maximal ASCII-word span-sum reducer.
pub const SPAN_SUM_OPERATION_ID: &str = "guarded-ascii-word-dictionary.maximal-word-span-sum.v1";

/// Per-invocation ceilings checked before the reducer reads the haystack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceLimits {
    pub max_haystack_bytes: usize,
    pub max_candidate_words: usize,
    pub max_count: u64,
    pub max_span_sum: u64,
    pub max_lookup_steps: usize,
    pub max_total_work: usize,
    pub max_peak_bytes: usize,
}

impl ReduceLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_haystack_bytes: usize::MAX,
            max_candidate_words: usize::MAX,
            max_count: u64::MAX,
            max_span_sum: u64::MAX,
            max_lookup_steps: usize::MAX,
            max_total_work: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for ReduceLimits {
    fn default() -> Self {
        Self {
            max_haystack_bytes: 128 << 20,
            max_candidate_words: 64 << 20,
            max_count: 64 << 20,
            max_span_sum: 128 << 20,
            max_lookup_steps: 320 << 20,
            max_total_work: 512 << 20,
            max_peak_bytes: 64 << 20,
        }
    }
}

/// One independently enforced reducer resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReduceResource {
    HaystackBytes,
    CandidateWords,
    Count,
    SpanSum,
    LookupSteps,
    TotalWork,
    PeakBytes,
}

/// Complete allocation-free envelope closed from input length and dictionary
/// dimensions before the first haystack byte is read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceUpperBounds {
    pub haystack_bytes: usize,
    pub candidate_words: usize,
    pub fingerprint_bytes: usize,
    pub binary_search_comparisons: usize,
    pub collision_slots: usize,
    pub full_equality_checks: usize,
    pub full_equality_bytes: usize,
    pub lookup_steps: usize,
    pub matches: u64,
    pub span_sum: u64,
    pub total_work: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Exact counters observed by one successful count or span-sum operation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReduceActual {
    pub bytes_classified: usize,
    pub candidate_words: usize,
    pub fingerprint_bytes: usize,
    pub binary_search_comparisons: usize,
    pub collision_slots: usize,
    pub full_equality_checks: usize,
    pub full_equality_bytes: usize,
    pub matches: u64,
    pub span_sum: u64,
    pub total_work: usize,
}

/// Prospective and exact execution evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceAccounting {
    pub upper_bounds: ReduceUpperBounds,
    pub actual: ReduceActual,
    pub operation_id: &'static str,
}

/// Successful guarded maximal-word count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountResult {
    pub count: u64,
    pub accounting: ReduceAccounting,
}

/// Successful guarded maximal-word span sum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanSumResult {
    pub span_sum: u64,
    pub accounting: ReduceAccounting,
}

/// Typed preflight or invariant failure. Resource refusals have zero actual
/// counters because all caller-selected limits are checked before source
/// access.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReduceError {
    pub kind: ReduceErrorKind,
    pub upper_bounds: Option<ReduceUpperBounds>,
    pub actual: ReduceActual,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReduceErrorKind {
    ResourceLimit {
        resource: ReduceResource,
        needed: u64,
        limit: u64,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    InternalInvariant {
        detail: &'static str,
    },
}

impl fmt::Display for ReduceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "guarded ASCII-word reduction failed: {:?}",
            self.kind
        )
    }
}

impl std::error::Error for ReduceError {}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct LookupActual {
    fingerprint_bytes: usize,
    binary_search_comparisons: usize,
    collision_slots: usize,
    full_equality_checks: usize,
    full_equality_bytes: usize,
}

impl LookupActual {
    fn steps(self) -> Option<usize> {
        self.fingerprint_bytes
            .checked_add(self.binary_search_comparisons)?
            .checked_add(self.collision_slots)?
            .checked_add(self.full_equality_checks)?
            .checked_add(self.full_equality_bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReduceOperation {
    Count,
    SpanSum,
}

impl ReduceOperation {
    const fn identity(self) -> &'static str {
        match self {
            Self::Count => COUNT_OPERATION_ID,
            Self::SpanSum => SPAN_SUM_OPERATION_ID,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Reduction {
    accounting: ReduceAccounting,
}

impl Dictionary {
    /// Count complete non-overlapping matches of the proved guarded language.
    ///
    /// Every admitted body is a nonempty ASCII word with a left and right
    /// directional ASCII-word boundary. Consequently, its matches are exactly
    /// the maximal ASCII-word runs whose complete bytes occur in this
    /// dictionary. Non-ASCII bytes are non-word bytes under the admitted
    /// Unicode-off Rust-byte profile.
    pub fn count(&self, haystack: &[u8], limits: ReduceLimits) -> Result<CountResult, ReduceError> {
        let reduction = self.reduce(haystack, ReduceOperation::Count, limits)?;
        Ok(CountResult {
            count: reduction.accounting.actual.matches,
            accounting: reduction.accounting,
        })
    }

    /// Sum the byte lengths of complete non-overlapping matches of the proved
    /// guarded language.
    ///
    /// The same maximal-word proof used by [`Self::count`] makes every
    /// successful candidate's complete byte range the exact Rust match span.
    pub fn span_sum(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<SpanSumResult, ReduceError> {
        let reduction = self.reduce(haystack, ReduceOperation::SpanSum, limits)?;
        Ok(SpanSumResult {
            span_sum: reduction.accounting.actual.span_sum,
            accounting: reduction.accounting,
        })
    }

    fn reduce(
        &self,
        haystack: &[u8],
        operation: ReduceOperation,
        limits: ReduceLimits,
    ) -> Result<Reduction, ReduceError> {
        let upper_bounds = reduce_upper_bounds(self.build_accounting(), haystack.len())?;
        enforce_reduce_limits(upper_bounds, operation, limits)?;

        let mut actual = ReduceActual::default();
        let mut index = 0_usize;
        while index < haystack.len() {
            increment(&mut actual.bytes_classified, "classified haystack bytes")?;
            if !is_ascii_word(haystack[index]) {
                index = index.checked_add(1).ok_or_else(|| {
                    reduce_invariant(actual, "non-word cursor overflowed admitted haystack")
                })?;
                continue;
            }

            let start = index;
            index = index.checked_add(1).ok_or_else(|| {
                reduce_invariant(actual, "word cursor overflowed admitted haystack")
            })?;
            while index < haystack.len() && is_ascii_word(haystack[index]) {
                increment(&mut actual.bytes_classified, "classified haystack bytes")?;
                index = index.checked_add(1).ok_or_else(|| {
                    reduce_invariant(actual, "word cursor overflowed admitted haystack")
                })?;
            }
            increment(&mut actual.candidate_words, "candidate words")?;
            let (found, lookup) = self.lookup_counted(&haystack[start..index])?;
            actual.fingerprint_bytes = add(
                actual.fingerprint_bytes,
                lookup.fingerprint_bytes,
                "fingerprint bytes",
            )?;
            actual.binary_search_comparisons = add(
                actual.binary_search_comparisons,
                lookup.binary_search_comparisons,
                "binary-search comparisons",
            )?;
            actual.collision_slots = add(
                actual.collision_slots,
                lookup.collision_slots,
                "collision slots",
            )?;
            actual.full_equality_checks = add(
                actual.full_equality_checks,
                lookup.full_equality_checks,
                "full-equality checks",
            )?;
            actual.full_equality_bytes = add(
                actual.full_equality_bytes,
                lookup.full_equality_bytes,
                "full-equality bytes",
            )?;
            if found {
                actual.matches = actual.matches.checked_add(1).ok_or_else(|| {
                    reduce_invariant(actual, "match count overflowed admitted envelope")
                })?;
                let span_bytes = index
                    .checked_sub(start)
                    .and_then(|bytes| u64::try_from(bytes).ok())
                    .ok_or_else(|| {
                        reduce_invariant(actual, "matched span length does not fit u64")
                    })?;
                actual.span_sum = actual.span_sum.checked_add(span_bytes).ok_or_else(|| {
                    reduce_invariant(actual, "span sum overflowed admitted envelope")
                })?;
            }
        }
        let lookup_steps = LookupActual {
            fingerprint_bytes: actual.fingerprint_bytes,
            binary_search_comparisons: actual.binary_search_comparisons,
            collision_slots: actual.collision_slots,
            full_equality_checks: actual.full_equality_checks,
            full_equality_bytes: actual.full_equality_bytes,
        }
        .steps()
        .ok_or_else(|| reduce_invariant(actual, "actual lookup work overflowed"))?;
        actual.total_work = actual
            .bytes_classified
            .checked_add(actual.candidate_words)
            .and_then(|work| work.checked_add(lookup_steps))
            .and_then(|work| work.checked_add(usize::try_from(actual.matches).ok()?))
            .ok_or_else(|| reduce_invariant(actual, "actual total work overflowed"))?;
        if !reduce_actual_fits(actual, upper_bounds) {
            return Err(reduce_invariant(
                actual,
                "actual counters escaped the preflight envelope",
            ));
        }
        Ok(Reduction {
            accounting: ReduceAccounting {
                upper_bounds,
                actual,
                operation_id: operation.identity(),
            },
        })
    }

    fn lookup_counted(&self, candidate: &[u8]) -> Result<(bool, LookupActual), ReduceError> {
        let mut actual = LookupActual::default();
        let mut sum = 0_u64;
        for &byte in candidate {
            increment(&mut actual.fingerprint_bytes, "lookup fingerprint bytes")?;
            sum = sum
                .checked_add(u64::from(byte))
                .ok_or_else(|| reduce_preflight_overflow("lookup fingerprint byte sum"))?;
        }
        let fingerprint = finish_fingerprint(candidate.len(), sum)
            .map_err(|_| reduce_preflight_overflow("lookup fingerprint"))?;
        let slots = self.lookup.as_slice();
        let mut low = 0_usize;
        let mut high = slots.len();
        while low < high {
            increment(
                &mut actual.binary_search_comparisons,
                "lookup binary-search comparisons",
            )?;
            let middle = low
                .checked_add(
                    high.checked_sub(low)
                        .and_then(|width| width.checked_div(2))
                        .ok_or_else(|| {
                            reduce_preflight_overflow("lookup binary-search midpoint")
                        })?,
                )
                .ok_or_else(|| reduce_preflight_overflow("lookup binary-search midpoint"))?;
            if slots[middle].fingerprint < fingerprint {
                low = middle
                    .checked_add(1)
                    .ok_or_else(|| reduce_preflight_overflow("lookup binary-search successor"))?;
            } else {
                high = middle;
            }
        }
        for slot in &slots[low..] {
            if slot.fingerprint != fingerprint {
                break;
            }
            increment(&mut actual.collision_slots, "lookup collision slots")?;
            increment(
                &mut actual.full_equality_checks,
                "lookup full-equality checks",
            )?;
            let source_index = usize::try_from(slot.source_index)
                .map_err(|_| reduce_preflight_overflow("lookup source index"))?;
            let entry = *self
                .entries
                .as_slice()
                .get(source_index)
                .ok_or_else(|| reduce_preflight_overflow("lookup source entry"))?;
            let start = usize::try_from(entry.start)
                .map_err(|_| reduce_preflight_overflow("lookup byte start"))?;
            let end = usize::try_from(entry.end)
                .map_err(|_| reduce_preflight_overflow("lookup byte end"))?;
            let stored = self
                .packed
                .as_slice()
                .get(start..end)
                .ok_or_else(|| reduce_preflight_overflow("lookup packed-byte range"))?;
            if equal_counted(stored, candidate, &mut actual.full_equality_bytes)? {
                return Ok((true, actual));
            }
        }
        Ok((false, actual))
    }
}

/// Close the reducer envelope used by [`Dictionary::count`] and
/// [`Dictionary::span_sum`] from the
/// immutable build receipt alone. Adapter layers can therefore derive exact
/// invocation limits without inspecting input bytes or borrowing the
/// dictionary representation.
pub fn reduce_upper_bounds(
    build: BuildAccounting,
    haystack_bytes: usize,
) -> Result<ReduceUpperBounds, ReduceError> {
    if !build.actual.published
        || build.actual.persistent_bytes != build.prospective.persistent_bytes
        || build.actual.source_words != build.prospective.dimensions.words
    {
        return Err(reduce_preflight_invariant(
            "dictionary build receipt is not a published exact identity",
        ));
    }
    let fingerprint_sum_bound = u64::try_from(haystack_bytes)
        .ok()
        .and_then(|bytes| bytes.checked_mul(u64::from(u8::MAX)));
    if fingerprint_sum_bound.is_none() {
        return Err(reduce_preflight_overflow(
            "maximal candidate fingerprint sum",
        ));
    }
    let candidate_words = haystack_bytes
        .checked_add(1)
        .map(|value| value / 2)
        .ok_or_else(|| reduce_preflight_overflow("candidate-word upper bound"))?;
    let entries = build.prospective.dimensions.words;
    let binary_per_candidate = binary_search_comparison_bound(entries)?;
    let binary_search_comparisons = candidate_words
        .checked_mul(binary_per_candidate)
        .ok_or_else(|| reduce_preflight_overflow("binary-search comparison upper bound"))?;
    let collision_slots = candidate_words
        .checked_mul(entries)
        .ok_or_else(|| reduce_preflight_overflow("collision-slot upper bound"))?;
    let full_equality_checks = collision_slots;
    let full_equality_bytes = candidate_words
        .checked_mul(build.prospective.dimensions.packed_bytes)
        .ok_or_else(|| reduce_preflight_overflow("full-equality byte upper bound"))?;
    let fingerprint_bytes = haystack_bytes;
    let lookup_steps = fingerprint_bytes
        .checked_add(binary_search_comparisons)
        .and_then(|work| work.checked_add(collision_slots))
        .and_then(|work| work.checked_add(full_equality_checks))
        .and_then(|work| work.checked_add(full_equality_bytes))
        .ok_or_else(|| reduce_preflight_overflow("lookup-work upper bound"))?;
    let matches = u64::try_from(candidate_words)
        .map_err(|_| reduce_preflight_overflow("match-count upper bound"))?;
    let span_sum = u64::try_from(haystack_bytes)
        .map_err(|_| reduce_preflight_overflow("span-sum upper bound"))?;
    let total_work = haystack_bytes
        .checked_add(candidate_words)
        .and_then(|work| work.checked_add(lookup_steps))
        .and_then(|work| work.checked_add(candidate_words))
        .ok_or_else(|| reduce_preflight_overflow("total-work upper bound"))?;
    let persistent_bytes = build.actual.persistent_bytes;
    Ok(ReduceUpperBounds {
        haystack_bytes,
        candidate_words,
        fingerprint_bytes,
        binary_search_comparisons,
        collision_slots,
        full_equality_checks,
        full_equality_bytes,
        lookup_steps,
        matches,
        span_sum,
        total_work,
        scratch_bytes: 0,
        persistent_bytes,
        peak_bytes: persistent_bytes,
    })
}

/// Backward-compatible count-oriented name for [`reduce_upper_bounds`].
pub fn count_upper_bounds(
    build: BuildAccounting,
    haystack_bytes: usize,
) -> Result<ReduceUpperBounds, ReduceError> {
    reduce_upper_bounds(build, haystack_bytes)
}

/// Close reducer bounds from the compact published construction receipt used
/// by aggregate facade reports.
pub fn published_reduce_upper_bounds(
    build: PublishedBuildAccounting,
    haystack_bytes: usize,
) -> Result<ReduceUpperBounds, ReduceError> {
    let build = build.expand().ok_or_else(|| {
        reduce_preflight_invariant("compact dictionary build receipt is not an exact publication")
    })?;
    reduce_upper_bounds(build, haystack_bytes)
}

fn equal_counted(left: &[u8], right: &[u8], compared: &mut usize) -> Result<bool, ReduceError> {
    if left.len() != right.len() {
        return Ok(false);
    }
    for (&left, &right) in left.iter().zip(right) {
        increment(compared, "full-equality bytes")?;
        if left != right {
            return Ok(false);
        }
    }
    Ok(true)
}

fn binary_search_comparison_bound(entries: usize) -> Result<usize, ReduceError> {
    let mut width = entries;
    let mut comparisons = 0_usize;
    while width > 0 {
        comparisons = comparisons
            .checked_add(1)
            .ok_or_else(|| reduce_preflight_overflow("binary-search comparison bound"))?;
        width /= 2;
    }
    Ok(comparisons)
}

fn reduce_actual_fits(actual: ReduceActual, upper: ReduceUpperBounds) -> bool {
    let lookup_steps = LookupActual {
        fingerprint_bytes: actual.fingerprint_bytes,
        binary_search_comparisons: actual.binary_search_comparisons,
        collision_slots: actual.collision_slots,
        full_equality_checks: actual.full_equality_checks,
        full_equality_bytes: actual.full_equality_bytes,
    }
    .steps();
    actual.bytes_classified <= upper.haystack_bytes
        && actual.candidate_words <= upper.candidate_words
        && actual.fingerprint_bytes <= upper.fingerprint_bytes
        && actual.binary_search_comparisons <= upper.binary_search_comparisons
        && actual.collision_slots <= upper.collision_slots
        && actual.full_equality_checks <= upper.full_equality_checks
        && actual.full_equality_bytes <= upper.full_equality_bytes
        && actual.matches <= upper.matches
        && actual.span_sum <= upper.span_sum
        && lookup_steps.is_some_and(|steps| steps <= upper.lookup_steps)
        && actual.total_work <= upper.total_work
}

fn enforce_reduce_limits(
    upper: ReduceUpperBounds,
    operation: ReduceOperation,
    limits: ReduceLimits,
) -> Result<(), ReduceError> {
    let span_sum_needed = match operation {
        ReduceOperation::Count => 0,
        ReduceOperation::SpanSum => upper.span_sum,
    };
    let resources = [
        (
            ReduceResource::HaystackBytes,
            u64_from_usize(upper.haystack_bytes, "haystack bytes")?,
            u64_from_usize(limits.max_haystack_bytes, "haystack-byte limit")?,
        ),
        (
            ReduceResource::CandidateWords,
            u64_from_usize(upper.candidate_words, "candidate words")?,
            u64_from_usize(limits.max_candidate_words, "candidate-word limit")?,
        ),
        (ReduceResource::Count, upper.matches, limits.max_count),
        (
            ReduceResource::SpanSum,
            span_sum_needed,
            limits.max_span_sum,
        ),
        (
            ReduceResource::LookupSteps,
            u64_from_usize(upper.lookup_steps, "lookup steps")?,
            u64_from_usize(limits.max_lookup_steps, "lookup-step limit")?,
        ),
        (
            ReduceResource::TotalWork,
            u64_from_usize(upper.total_work, "total work")?,
            u64_from_usize(limits.max_total_work, "total-work limit")?,
        ),
        (
            ReduceResource::PeakBytes,
            u64_from_usize(upper.peak_bytes, "peak bytes")?,
            u64_from_usize(limits.max_peak_bytes, "peak-byte limit")?,
        ),
    ];
    for (resource, needed, limit) in resources {
        if needed > limit {
            return Err(ReduceError {
                kind: ReduceErrorKind::ResourceLimit {
                    resource,
                    needed,
                    limit,
                },
                upper_bounds: Some(upper),
                actual: ReduceActual::default(),
            });
        }
    }
    Ok(())
}

fn u64_from_usize(value: usize, computation: &'static str) -> Result<u64, ReduceError> {
    u64::try_from(value).map_err(|_| reduce_preflight_overflow(computation))
}

fn increment(value: &mut usize, computation: &'static str) -> Result<(), ReduceError> {
    *value = value
        .checked_add(1)
        .ok_or_else(|| reduce_preflight_overflow(computation))?;
    Ok(())
}

fn add(left: usize, right: usize, computation: &'static str) -> Result<usize, ReduceError> {
    left.checked_add(right)
        .ok_or_else(|| reduce_preflight_overflow(computation))
}

const fn reduce_preflight_overflow(computation: &'static str) -> ReduceError {
    ReduceError {
        kind: ReduceErrorKind::ArithmeticOverflow { computation },
        upper_bounds: None,
        actual: ReduceActual {
            bytes_classified: 0,
            candidate_words: 0,
            fingerprint_bytes: 0,
            binary_search_comparisons: 0,
            collision_slots: 0,
            full_equality_checks: 0,
            full_equality_bytes: 0,
            matches: 0,
            span_sum: 0,
            total_work: 0,
        },
    }
}

const fn reduce_preflight_invariant(detail: &'static str) -> ReduceError {
    ReduceError {
        kind: ReduceErrorKind::InternalInvariant { detail },
        upper_bounds: None,
        actual: ReduceActual {
            bytes_classified: 0,
            candidate_words: 0,
            fingerprint_bytes: 0,
            binary_search_comparisons: 0,
            collision_slots: 0,
            full_equality_checks: 0,
            full_equality_bytes: 0,
            matches: 0,
            span_sum: 0,
            total_work: 0,
        },
    }
}

const fn reduce_invariant(actual: ReduceActual, detail: &'static str) -> ReduceError {
    ReduceError {
        kind: ReduceErrorKind::InternalInvariant { detail },
        upper_bounds: None,
        actual,
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, rc::Rc};

    use super::*;

    const LEFT: Guard = Guard::LeftBoundary;
    const RIGHT: Guard = Guard::RightBoundary;

    fn word(bytes: &[u8]) -> SourceWord<'_> {
        SourceWord {
            bytes,
            left: LEFT,
            right: RIGHT,
        }
    }

    fn dimensions(words: &[SourceWord<'_>]) -> BuildDimensions {
        BuildDimensions {
            words: words.len(),
            packed_bytes: words.iter().map(|word| word.bytes.len()).sum(),
        }
    }

    fn build(words: &[SourceWord<'_>], limits: BuildLimits) -> Result<Dictionary, BuildError> {
        Dictionary::build_precounted(dimensions(words), words.iter().copied(), limits)
    }

    #[test]
    fn maximal_word_count_matches_unicode_off_rust_bytes_exhaustively() {
        let words = [
            word(b"as"),
            word(b"break"),
            word(b"Self"),
            word(b"ab"),
            word(b"ba"),
            word(b"as"),
        ];
        let dictionary = build(&words, BuildLimits::unlimited()).unwrap();
        let oracle = regex::bytes::Regex::new(r"(?-u:\b(?:as|break|Self|ab|ba|as)\b)").unwrap();
        let alphabet = [b'a', b's', b'b', b'_', b' ', 0xFF];
        let mut haystack = Vec::new();
        for length in 0..=5 {
            let cases = alphabet.len().pow(length);
            for mut case in 0..cases {
                haystack.clear();
                for _ in 0..length {
                    haystack.push(alphabet[case % alphabet.len()]);
                    case /= alphabet.len();
                }
                let expected = u64::try_from(oracle.find_iter(&haystack).count()).unwrap();
                let expected_span_sum = oracle
                    .find_iter(&haystack)
                    .try_fold(0_u64, |sum, matched| {
                        sum.checked_add(u64::try_from(matched.len()).unwrap())
                    })
                    .unwrap();
                let result = dictionary
                    .count(&haystack, ReduceLimits::unlimited())
                    .unwrap();
                assert_eq!(
                    result.count, expected,
                    "haystack={haystack:?} accounting={:?}",
                    result.accounting
                );
                assert!(reduce_actual_fits(
                    result.accounting.actual,
                    result.accounting.upper_bounds
                ));
                assert_eq!(result.accounting.operation_id, COUNT_OPERATION_ID);
                assert_eq!(result.accounting.actual.bytes_classified, haystack.len());
                assert_eq!(result.accounting.actual.span_sum, expected_span_sum);
                let span_sum = dictionary
                    .span_sum(&haystack, ReduceLimits::unlimited())
                    .unwrap();
                assert_eq!(span_sum.span_sum, expected_span_sum);
                assert_eq!(span_sum.accounting.operation_id, SPAN_SUM_OPERATION_ID);
                assert_eq!(span_sum.accounting.actual.matches, expected);
                assert_eq!(span_sum.accounting.actual.bytes_classified, haystack.len());
            }
        }
    }

    #[test]
    fn compact_published_accounting_is_lossless_and_fail_closed() {
        let dictionary = build(
            &[word(b"as"), word(b"break"), word(b"Self")],
            BuildLimits::unlimited(),
        )
        .unwrap();
        let complete = dictionary.build_accounting();
        let published = complete.published().unwrap();
        assert_eq!(published.expand(), Some(complete));

        let forged = PublishedBuildAccounting {
            build_work: published.build_work + 1,
            ..published
        };
        assert_eq!(forged.actual(), None);
        assert_eq!(forged.expand(), None);
    }

    #[test]
    fn count_limits_are_preflighted_exactly_before_source_access() {
        let words = [word(b"as"), word(b"break"), word(b"Self")];
        let dictionary = build(&words, BuildLimits::unlimited()).unwrap();
        let haystack = b"as break other Self";
        let exact = dictionary
            .count(haystack, ReduceLimits::unlimited())
            .unwrap()
            .accounting
            .upper_bounds;
        let exact_limits = ReduceLimits {
            max_haystack_bytes: exact.haystack_bytes,
            max_candidate_words: exact.candidate_words,
            max_count: exact.matches,
            max_span_sum: exact.span_sum,
            max_lookup_steps: exact.lookup_steps,
            max_total_work: exact.total_work,
            max_peak_bytes: exact.peak_bytes,
        };
        let result = dictionary.count(haystack, exact_limits).unwrap();
        assert_eq!(result.count, 3);
        assert!(result.accounting.actual.total_work <= exact.total_work);

        let cases = [
            (
                ReduceResource::HaystackBytes,
                ReduceLimits {
                    max_haystack_bytes: exact.haystack_bytes - 1,
                    ..exact_limits
                },
            ),
            (
                ReduceResource::CandidateWords,
                ReduceLimits {
                    max_candidate_words: exact.candidate_words - 1,
                    ..exact_limits
                },
            ),
            (
                ReduceResource::Count,
                ReduceLimits {
                    max_count: exact.matches - 1,
                    ..exact_limits
                },
            ),
            (
                ReduceResource::LookupSteps,
                ReduceLimits {
                    max_lookup_steps: exact.lookup_steps - 1,
                    ..exact_limits
                },
            ),
            (
                ReduceResource::TotalWork,
                ReduceLimits {
                    max_total_work: exact.total_work - 1,
                    ..exact_limits
                },
            ),
            (
                ReduceResource::PeakBytes,
                ReduceLimits {
                    max_peak_bytes: exact.peak_bytes - 1,
                    ..exact_limits
                },
            ),
        ];
        for (resource, limits) in cases {
            let error = dictionary.count(haystack, limits).unwrap_err();
            assert!(matches!(
                error.kind,
                ReduceErrorKind::ResourceLimit {
                    resource: actual,
                    ..
                } if actual == resource
            ));
            assert_eq!(error.actual, ReduceActual::default());
            assert_eq!(error.upper_bounds, Some(exact));
        }
    }

    #[test]
    fn span_sum_limit_is_operation_specific_and_preflighted() {
        let words = [word(b"as"), word(b"break"), word(b"Self")];
        let dictionary = build(&words, BuildLimits::unlimited()).unwrap();
        let haystack = b"as break other Self";
        let exact = reduce_upper_bounds(dictionary.build_accounting(), haystack.len()).unwrap();
        let limits = ReduceLimits {
            max_haystack_bytes: exact.haystack_bytes,
            max_candidate_words: exact.candidate_words,
            max_count: exact.matches,
            max_span_sum: exact.span_sum - 1,
            max_lookup_steps: exact.lookup_steps,
            max_total_work: exact.total_work,
            max_peak_bytes: exact.peak_bytes,
        };
        let error = dictionary.span_sum(haystack, limits).unwrap_err();
        assert!(matches!(
            error.kind,
            ReduceErrorKind::ResourceLimit {
                resource: ReduceResource::SpanSum,
                needed,
                limit,
            } if needed == exact.span_sum && limit == exact.span_sum - 1
        ));
        assert_eq!(error.actual, ReduceActual::default());
        assert_eq!(error.upper_bounds, Some(exact));

        let count = dictionary.count(haystack, limits).unwrap();
        assert_eq!(count.count, 3);
    }

    #[derive(Clone)]
    struct Probe<'a> {
        words: &'a [SourceWord<'a>],
        reported_words: usize,
        index: usize,
        next_calls: Rc<Cell<usize>>,
        len_calls: Rc<Cell<usize>>,
    }

    impl<'a> Iterator for Probe<'a> {
        type Item = SourceWord<'a>;

        fn next(&mut self) -> Option<Self::Item> {
            self.next_calls.set(
                self.next_calls
                    .get()
                    .checked_add(1)
                    .expect("probe call count fits"),
            );
            let value = self.words.get(self.index).copied();
            if value.is_some() {
                self.index = self.index.checked_add(1).expect("probe index fits");
            }
            value
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            let remaining = self
                .reported_words
                .checked_sub(self.index.min(self.reported_words))
                .expect("probe index is within words");
            (remaining, Some(remaining))
        }
    }

    impl ExactSizeIterator for Probe<'_> {
        fn len(&self) -> usize {
            self.len_calls.set(
                self.len_calls
                    .get()
                    .checked_add(1)
                    .expect("probe length call count fits"),
            );
            self.reported_words
                .checked_sub(self.index.min(self.reported_words))
                .expect("probe index is within words")
        }
    }

    fn probe<'a>(words: &'a [SourceWord<'a>]) -> (Probe<'a>, Rc<Cell<usize>>, Rc<Cell<usize>>) {
        let next_calls = Rc::new(Cell::new(0));
        let len_calls = Rc::new(Cell::new(0));
        (
            Probe {
                words,
                reported_words: words.len(),
                index: 0,
                next_calls: Rc::clone(&next_calls),
                len_calls: Rc::clone(&len_calls),
            },
            next_calls,
            len_calls,
        )
    }

    fn extra_probe<'a>(
        words: &'a [SourceWord<'a>],
        reported_words: usize,
    ) -> (Probe<'a>, Rc<Cell<usize>>, Rc<Cell<usize>>) {
        let (mut source, next_calls, len_calls) = probe(words);
        source.reported_words = reported_words;
        (source, next_calls, len_calls)
    }

    #[test]
    fn exact_identity_retains_source_order_duplicates_ranges_and_guards() {
        let words = [
            SourceWord {
                bytes: b"ab",
                left: Guard::LeftStart,
                right: Guard::RightEnd,
            },
            SourceWord {
                bytes: b"ba",
                left: Guard::LeftStartHalf,
                right: Guard::RightEndHalf,
            },
            word(b"ab"),
        ];
        let dictionary = build(&words, BuildLimits::default()).unwrap();
        let identity = dictionary.identity();
        assert_eq!(identity.plan_id, PLAN_ID);
        assert_eq!(identity.packing_id, PACKING_ID);
        assert_eq!(identity.lookup_id, LOOKUP_ID);
        assert_eq!(identity.fingerprint_id, FINGERPRINT_ID);
        assert_eq!(identity.packed_bytes, b"abbaab");
        assert_eq!(
            identity.entries,
            &[
                EntryIdentity {
                    start: 0,
                    end: 2,
                    left: Guard::LeftStart,
                    right: Guard::RightEnd,
                },
                EntryIdentity {
                    start: 2,
                    end: 4,
                    left: Guard::LeftStartHalf,
                    right: Guard::RightEndHalf,
                },
                EntryIdentity {
                    start: 4,
                    end: 6,
                    left: Guard::LeftBoundary,
                    right: Guard::RightBoundary,
                },
            ]
        );
    }

    #[test]
    fn lookup_confirms_full_bytes_across_fingerprint_collision_and_duplicates() {
        assert_eq!(fingerprint(b"ab").unwrap(), fingerprint(b"ba").unwrap());
        let words = [
            word(b"ab"),
            word(b"ba"),
            SourceWord {
                bytes: b"ab",
                left: Guard::LeftStart,
                right: Guard::RightEnd,
            },
        ];
        let dictionary = build(&words, BuildLimits::default()).unwrap();
        assert_eq!(
            dictionary.lookup(b"ab"),
            Some(LookupMatch {
                source_index: 0,
                left: LEFT,
                right: RIGHT,
            })
        );
        assert_eq!(
            dictionary.lookup_at_or_after(b"ab", 1),
            Some(LookupMatch {
                source_index: 2,
                left: Guard::LeftStart,
                right: Guard::RightEnd,
            })
        );
        assert_eq!(dictionary.lookup_at_or_after(b"ab", 3), None);
        assert_eq!(dictionary.lookup(b"ba").unwrap().source_index, 1);
        assert_eq!(dictionary.lookup(b"zz"), None);
        assert_eq!(dictionary.lookup(b"a-"), None);
        assert_eq!(dictionary.lookup(b""), None);
    }

    #[test]
    fn every_positive_limit_is_exact_and_one_below_refuses_before_source() {
        let words = [word(b"ab"), word(b"ba"), word(b"cat")];
        let baseline = build(&words, BuildLimits::unlimited()).unwrap();
        let prospective = baseline.build_accounting().prospective;
        assert_eq!(prospective.source_len_calls, 1);
        assert_eq!(prospective.unexpected_source_yields, 1);
        assert!(prospective.dimensions.words > 0);
        assert!(prospective.dimensions.packed_bytes > 0);
        assert!(prospective.identity_bytes > 0);
        assert!(prospective.sort_comparisons > 0);
        assert!(prospective.allocations > 0);
        assert!(prospective.initialized_bytes > 0);
        assert!(prospective.build_work > 0);
        assert_eq!(prospective.scratch_bytes, 0);
        assert!(prospective.persistent_bytes > 0);
        assert!(prospective.peak_bytes > 0);
        assert_eq!(
            (prospective.sort_comparisons, prospective.sort_swaps),
            heap_sort_bounds(words.len()).unwrap()
        );
        let exact = exact_limits(prospective);
        assert_exact_admission(&words, prospective, exact);
        assert_every_one_below_refuses_before_source(&words, exact);
    }

    const fn exact_limits(prospective: BuildProspective) -> BuildLimits {
        BuildLimits {
            max_words: prospective.dimensions.words,
            max_packed_bytes: prospective.dimensions.packed_bytes,
            max_identity_bytes: prospective.identity_bytes,
            max_sort_comparisons: prospective.sort_comparisons,
            max_allocations: prospective.allocations,
            max_initialized_bytes: prospective.initialized_bytes,
            max_build_work: prospective.build_work,
            max_scratch_bytes: prospective.scratch_bytes,
            max_persistent_bytes: prospective.persistent_bytes,
            max_peak_bytes: prospective.peak_bytes,
        }
    }

    fn assert_exact_admission(
        words: &[SourceWord<'_>],
        prospective: BuildProspective,
        exact: BuildLimits,
    ) {
        let (source, next_calls, len_calls) = probe(words);
        let exact_dictionary =
            Dictionary::build_precounted(dimensions(words), source, exact).unwrap();
        assert_eq!(
            next_calls.get(),
            words.len().checked_add(1).expect("probe call count fits")
        );
        assert_eq!(len_calls.get(), 1);
        let actual = exact_dictionary.build_accounting().actual;
        assert_eq!(actual.source_len_calls, prospective.source_len_calls);
        assert_eq!(actual.source_next_calls, prospective.source_next_calls);
        assert_eq!(actual.unexpected_source_yields, 0);
        assert_eq!(actual.source_words, prospective.dimensions.words);
        assert_eq!(actual.guard_checks, prospective.guard_checks);
        assert_eq!(actual.ascii_byte_checks, prospective.ascii_byte_checks);
        assert_eq!(actual.byte_copies, prospective.byte_copies);
        assert_eq!(actual.entry_writes, prospective.entry_writes);
        assert_eq!(actual.lookup_slot_writes, prospective.lookup_slot_writes);
        assert!(actual.sort_comparisons <= prospective.sort_comparisons);
        assert!(actual.sort_swaps <= prospective.sort_swaps);
        assert_eq!(actual.allocations, prospective.allocations);
        assert_eq!(actual.initialized_bytes, prospective.initialized_bytes);
        assert_eq!(actual.identity_bytes, prospective.identity_bytes);
        assert_eq!(actual.build_work, actual_build_work(actual).unwrap());
        assert!(actual.build_work <= prospective.build_work);
        assert_eq!(actual.scratch_bytes, prospective.scratch_bytes);
        assert_eq!(actual.persistent_bytes, prospective.persistent_bytes);
        assert_eq!(actual.peak_bytes, prospective.peak_bytes);
        assert!(actual.published);
    }

    fn assert_every_one_below_refuses_before_source(words: &[SourceWord<'_>], exact: BuildLimits) {
        let cases = [
            (
                BuildLimits {
                    max_words: one_below(exact.max_words),
                    ..exact
                },
                BuildResource::Words,
            ),
            (
                BuildLimits {
                    max_packed_bytes: one_below(exact.max_packed_bytes),
                    ..exact
                },
                BuildResource::PackedBytes,
            ),
            (
                BuildLimits {
                    max_identity_bytes: one_below(exact.max_identity_bytes),
                    ..exact
                },
                BuildResource::IdentityBytes,
            ),
            (
                BuildLimits {
                    max_sort_comparisons: one_below(exact.max_sort_comparisons),
                    ..exact
                },
                BuildResource::SortComparisons,
            ),
            (
                BuildLimits {
                    max_allocations: one_below(exact.max_allocations),
                    ..exact
                },
                BuildResource::Allocations,
            ),
            (
                BuildLimits {
                    max_initialized_bytes: one_below(exact.max_initialized_bytes),
                    ..exact
                },
                BuildResource::InitializedBytes,
            ),
            (
                BuildLimits {
                    max_build_work: one_below_u64(exact.max_build_work),
                    ..exact
                },
                BuildResource::Work,
            ),
            (
                BuildLimits {
                    max_persistent_bytes: one_below(exact.max_persistent_bytes),
                    ..exact
                },
                BuildResource::PersistentBytes,
            ),
            (
                BuildLimits {
                    max_peak_bytes: one_below(exact.max_peak_bytes),
                    ..exact
                },
                BuildResource::PeakBytes,
            ),
        ];
        for (limits, expected) in cases {
            let (source, next_calls, len_calls) = probe(words);
            let error =
                Dictionary::build_precounted(dimensions(words), source, limits).unwrap_err();
            assert_eq!(next_calls.get(), 0, "resource={expected:?}");
            assert_eq!(len_calls.get(), 0, "resource={expected:?}");
            assert_eq!(error.actual(), BuildActual::default());
            assert!(error.prospective().is_some());
            match (expected, error.kind) {
                (BuildResource::Work, BuildErrorKind::WorkLimit { .. }) => {}
                (
                    resource,
                    BuildErrorKind::ResourceLimit {
                        resource: actual, ..
                    },
                ) => assert_eq!(actual, resource),
                (_, other) => panic!("unexpected one-below error: {other:?}"),
            }
        }
    }

    #[test]
    fn one_entry_has_zero_sort_work_and_exact_deterministic_accounting() {
        let words = [word(b"solo")];
        let dictionary = build(&words, BuildLimits::unlimited()).unwrap();
        let accounting = dictionary.build_accounting();
        assert_eq!(heap_sort_bounds(1).unwrap(), (0, 0));
        assert_eq!(accounting.prospective.sort_comparisons, 0);
        assert_eq!(accounting.prospective.sort_swaps, 0);
        assert_eq!(accounting.actual.sort_comparisons, 0);
        assert_eq!(accounting.actual.sort_swaps, 0);
        assert_eq!(accounting.actual.source_len_calls, 1);
        assert_eq!(accounting.actual.source_next_calls, 2);
        assert_eq!(accounting.actual.unexpected_source_yields, 0);
        assert_eq!(accounting.actual.source_words, 1);
        assert_eq!(accounting.actual.guard_checks, 2);
        assert_eq!(accounting.actual.ascii_byte_checks, 4);
        assert_eq!(accounting.actual.byte_copies, 4);
        assert_eq!(accounting.actual.entry_writes, 1);
        assert_eq!(accounting.actual.lookup_slot_writes, 1);
        assert_eq!(
            accounting.actual.initialized_bytes,
            accounting.prospective.initialized_bytes
        );
        assert_eq!(
            accounting.actual.build_work,
            actual_build_work(accounting.actual).unwrap()
        );
        assert!(accounting.actual.published);
    }

    #[test]
    fn heap_sort_bounds_follow_the_checked_logarithmic_formula() {
        assert_eq!(heap_sort_bounds(2).unwrap(), (2, 2));
        assert_eq!(heap_sort_bounds(3).unwrap(), (4, 4));
        assert_eq!(heap_sort_bounds(4).unwrap(), (10, 8));
        assert_eq!(heap_sort_bounds(5).unwrap(), (14, 11));
        assert_eq!(log2_floor_sum(0).unwrap(), 0);
        assert_eq!(log2_floor_sum(1).unwrap(), 0);
        assert_eq!(log2_floor_sum(2).unwrap(), 1);
        assert_eq!(log2_floor_sum(3).unwrap(), 2);
        assert_eq!(log2_floor_sum(4).unwrap(), 4);
    }

    #[test]
    fn overdeclared_bytes_preserve_the_complete_partial_ledger() {
        let words = [word(b"ab")];
        let error = Dictionary::build_precounted(
            BuildDimensions {
                words: 1,
                packed_bytes: 3,
            },
            words.into_iter(),
            BuildLimits::unlimited(),
        )
        .unwrap_err();
        assert!(matches!(
            &error.kind,
            BuildErrorKind::PackedBytesMismatch {
                expected: 3,
                actual: 2
            }
        ));
        let prospective = error.prospective().unwrap();
        let actual = error.actual();
        assert_eq!(actual.source_len_calls, 1);
        assert_eq!(actual.source_next_calls, 2);
        assert_eq!(actual.unexpected_source_yields, 0);
        assert_eq!(actual.source_words, 1);
        assert_eq!(actual.guard_checks, 2);
        assert_eq!(actual.ascii_byte_checks, 2);
        assert_eq!(actual.byte_copies, 2);
        assert_eq!(actual.entry_writes, 1);
        assert_eq!(actual.lookup_slot_writes, 1);
        assert_eq!(actual.sort_comparisons, 0);
        assert_eq!(actual.sort_swaps, 0);
        assert_eq!(actual.allocations, 3);
        assert_eq!(actual.initialized_bytes, initialized_bytes_for(2, 1, 1));
        assert_eq!(actual.identity_bytes, 0);
        assert_eq!(actual.build_work, actual_build_work(actual).unwrap());
        assert_eq!(actual.persistent_bytes, prospective.persistent_bytes);
        assert_eq!(actual.peak_bytes, prospective.peak_bytes);
        assert!(!actual.published);
    }

    #[test]
    fn malformed_word_after_valid_prefix_preserves_partial_bytes_and_work() {
        let words = [word(b"ab-")];
        let error = build(&words, BuildLimits::unlimited()).unwrap_err();
        assert!(matches!(
            &error.kind,
            BuildErrorKind::NonAsciiWordByte {
                source_index: 0,
                byte_index: 2,
                byte: b'-'
            }
        ));
        let prospective = error.prospective().unwrap();
        let actual = error.actual();
        assert_eq!(actual.source_len_calls, 1);
        assert_eq!(actual.source_next_calls, 1);
        assert_eq!(actual.unexpected_source_yields, 0);
        assert_eq!(actual.source_words, 1);
        assert_eq!(actual.guard_checks, 2);
        assert_eq!(actual.ascii_byte_checks, 3);
        assert_eq!(actual.byte_copies, 2);
        assert_eq!(actual.entry_writes, 0);
        assert_eq!(actual.lookup_slot_writes, 0);
        assert_eq!(actual.sort_comparisons, 0);
        assert_eq!(actual.sort_swaps, 0);
        assert_eq!(actual.allocations, 3);
        assert_eq!(actual.initialized_bytes, 2);
        assert_eq!(actual.identity_bytes, 0);
        assert_eq!(actual.build_work, actual_build_work(actual).unwrap());
        assert_eq!(actual.persistent_bytes, prospective.persistent_bytes);
        assert_eq!(actual.peak_bytes, prospective.peak_bytes);
        assert!(!actual.published);
    }

    #[test]
    fn exact_size_length_probe_is_charged_and_can_refuse_before_allocation() {
        let words = [word(b"ab")];
        let (source, next_calls, len_calls) = probe(&words);
        let error = Dictionary::build_precounted(
            BuildDimensions {
                words: 2,
                packed_bytes: 2,
            },
            source,
            BuildLimits::unlimited(),
        )
        .unwrap_err();
        assert!(matches!(
            &error.kind,
            BuildErrorKind::SourceLengthMismatch {
                expected: 2,
                actual: 1
            }
        ));
        assert_eq!(next_calls.get(), 0);
        assert_eq!(len_calls.get(), 1);
        let actual = error.actual();
        assert_eq!(actual.source_len_calls, 1);
        assert_eq!(actual.source_next_calls, 0);
        assert_eq!(actual.unexpected_source_yields, 0);
        assert_eq!(actual.source_words, 0);
        assert_eq!(actual.allocations, 0);
        assert_eq!(actual.initialized_bytes, 0);
        assert_eq!(actual.persistent_bytes, 0);
        assert_eq!(actual.build_work, actual_build_work(actual).unwrap());
        assert!(!actual.published);
    }

    #[test]
    fn prospective_closes_the_same_envelope_without_a_source() {
        let dimensions = BuildDimensions {
            words: 3,
            packed_bytes: 7,
        };
        let direct = Dictionary::prospective(dimensions).unwrap();
        let words = [word(b"ab"), word(b"ba"), word(b"cat")];
        let built = build(&words, BuildLimits::unlimited()).unwrap();
        assert_eq!(direct, built.build_accounting().prospective);
        assert_eq!(direct.source_len_calls, 1);
        assert_eq!(direct.source_next_calls, 4);
        assert_eq!(direct.unexpected_source_yields, 1);
        assert_eq!(
            (direct.sort_comparisons, direct.sort_swaps),
            heap_sort_bounds(3).unwrap()
        );
    }

    #[test]
    fn unexpected_exhaustion_yield_has_distinct_counter_and_work() {
        let words = [word(b"ab"), word(b"extra")];
        let (source, next_calls, len_calls) = extra_probe(&words, 1);
        let error = Dictionary::build_precounted(
            BuildDimensions {
                words: 1,
                packed_bytes: 2,
            },
            source,
            BuildLimits::unlimited(),
        )
        .unwrap_err();
        assert!(matches!(
            &error.kind,
            BuildErrorKind::SourceLengthMismatch {
                expected: 1,
                actual: 2
            }
        ));
        assert_eq!(next_calls.get(), 2);
        assert_eq!(len_calls.get(), 1);
        let actual = error.actual();
        assert_eq!(actual.source_len_calls, 1);
        assert_eq!(actual.source_next_calls, 2);
        assert_eq!(actual.source_words, 1);
        assert_eq!(actual.unexpected_source_yields, 1);
        assert_eq!(actual.entry_writes, 1);
        assert_eq!(actual.lookup_slot_writes, 1);
        assert_eq!(actual.sort_comparisons, 0);
        assert_eq!(actual.sort_swaps, 0);
        assert_eq!(actual.build_work, actual_build_work(actual).unwrap());
        assert!(!actual.published);
    }

    #[test]
    fn structural_refusals_are_typed_and_never_publish() {
        let empty: [SourceWord<'_>; 0] = [];
        assert!(matches!(
            build(&empty, BuildLimits::unlimited()).unwrap_err().kind,
            BuildErrorKind::EmptyDictionary
        ));
        let empty_word = [word(b"")];
        assert!(matches!(
            Dictionary::build_precounted(
                BuildDimensions {
                    words: 1,
                    packed_bytes: 1,
                },
                empty_word.iter().copied(),
                BuildLimits::unlimited(),
            )
            .unwrap_err()
            .kind,
            BuildErrorKind::EmptyWord { source_index: 0 }
        ));
        let nonword = [word(b"a-b")];
        assert!(matches!(
            build(&nonword, BuildLimits::unlimited()).unwrap_err().kind,
            BuildErrorKind::NonAsciiWordByte {
                source_index: 0,
                byte_index: 1,
                byte: b'-'
            }
        ));
        let bad_left = [SourceWord {
            bytes: b"word",
            left: Guard::RightEnd,
            right: RIGHT,
        }];
        assert!(matches!(
            build(&bad_left, BuildLimits::unlimited()).unwrap_err().kind,
            BuildErrorKind::InvalidLeftGuard { .. }
        ));
        let bad_right = [SourceWord {
            bytes: b"word",
            left: LEFT,
            right: Guard::LeftStart,
        }];
        assert!(matches!(
            build(&bad_right, BuildLimits::unlimited())
                .unwrap_err()
                .kind,
            BuildErrorKind::InvalidRightGuard { .. }
        ));
        let words = [word(b"ab")];
        assert!(matches!(
            Dictionary::build_precounted(
                BuildDimensions {
                    words: 1,
                    packed_bytes: 1,
                },
                words.into_iter(),
                BuildLimits::unlimited(),
            )
            .unwrap_err()
            .kind,
            BuildErrorKind::PackedBytesMismatch {
                expected: 1,
                actual: 2
            }
        ));
        assert!(matches!(
            Dictionary::build_precounted(
                BuildDimensions {
                    words: 2,
                    packed_bytes: 2,
                },
                [word(b"ab")].into_iter(),
                BuildLimits::unlimited(),
            )
            .unwrap_err()
            .kind,
            BuildErrorKind::SourceLengthMismatch {
                expected: 2,
                actual: 1
            }
        ));
    }

    #[test]
    fn dimension_overflow_or_representation_failure_happens_before_source_probe() {
        let words = [word(b"ab")];
        let (source, next_calls, len_calls) = probe(&words);
        let error = Dictionary::build_precounted(
            BuildDimensions {
                words: usize::MAX,
                packed_bytes: usize::MAX,
            },
            source,
            BuildLimits::unlimited(),
        )
        .unwrap_err();
        assert_eq!(next_calls.get(), 0);
        assert_eq!(len_calls.get(), 0);
        assert_eq!(error.actual(), BuildActual::default());
        assert!(error.prospective().is_none());
        assert!(matches!(
            error.kind,
            BuildErrorKind::RepresentationLimit { .. } | BuildErrorKind::ArithmeticOverflow { .. }
        ));
    }

    fn one_below(value: usize) -> usize {
        value.checked_sub(1).expect("resource is positive")
    }

    fn one_below_u64(value: u64) -> u64 {
        value.checked_sub(1).expect("resource is positive")
    }

    fn initialized_bytes_for(bytes: usize, entries: usize, slots: usize) -> usize {
        entries
            .checked_mul(size_of::<EntryIdentity>())
            .and_then(|entry_bytes| bytes.checked_add(entry_bytes))
            .and_then(|subtotal| {
                slots
                    .checked_mul(size_of::<LookupSlot>())
                    .and_then(|slot_bytes| subtotal.checked_add(slot_bytes))
            })
            .expect("focused initialized-byte fixture fits")
    }
}
