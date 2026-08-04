//! SIMD packed ordered finite-literal search with explicit refusal.

use core::{fmt, mem::size_of};

use aho_corasick::packed::Searcher;
use memchr::{memchr, memchr2, memchr3};

use crate::Window;

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
// A sparse anchor verifies a bounded number of candidates itself. If those
// candidates are all decoys, the native packed searcher resumes after the
// last start already disproved. Thus sparse inputs need only one source pass,
// while dense decoys pay bounded work and never restart from byte zero.
const SPARSE_ANCHOR_CANDIDATE_BUDGET: usize = 4;
const SPARSE_ANCHOR_MAX_RETAINED_PATTERN_BYTES: usize = 4 * 1024;
// Retain only anchor groups whose exact source-order verification fits in two
// 16-byte blocks. After a rejection, another candidate is attempted only when
// the proved skip amortizes all exact verification performed so far.
const SPARSE_ANCHOR_MAX_CANDIDATE_VERIFICATION_WORK: usize = 32;

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
    /// Minimum haystack length at which the SIMD searcher is used.
    pub simd_minimum_haystack_bytes: usize,
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

#[derive(Clone, Debug)]
enum PackedLiteralEngine {
    Native(Searcher),
    NativeSparse {
        searcher: Searcher,
        sparse_anchor: Box<SparseAnchor>,
    },
    Factored(Box<FactoredColumns>),
}

/// Immutable SIMD packed ordered-literal plan.
///
/// This is a shared native primitive, not pattern-specialized JIT code. The
/// pinned implementation uses Teddy on supported x86-64/AArch64 haystacks and
/// a bounded Rabin-Karp path for short inputs. Larger complete byte-column
/// products use one native byte-set scan plus exact column verification.
/// Construction refuses unsupported targets/shapes and search never changes
/// plan after selection.
#[derive(Clone, Debug)]
pub struct PackedLiteralSetPlan {
    engine: PackedLiteralEngine,
    build: PackedLiteralSetBuildAccounting,
    verification_bytes_per_position: usize,
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
        let mut build = preflight(patterns, limits)?;
        let engine =
            if let Some(native_searcher) = Searcher::new(patterns.iter().map(AsRef::as_ref)) {
                let sparse_anchor = select_sparse_anchor(patterns).map(Box::new);
                build.persistent_bytes = native_searcher
                    .memory_usage()
                    .checked_add(
                        sparse_anchor
                            .as_ref()
                            .map_or(0, |anchor| anchor.persistent_bytes()),
                    )
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
        let mut accounting = PackedLiteralSetAccounting {
            searched_bytes,
            positions_upper_bound,
            verification_bytes_per_position,
            work_upper_bound,
            scratch_bytes: 0,
            factored_columns: false,
            simd_eligible_length: searched_bytes >= self.build.simd_minimum_haystack_bytes,
        };
        let window_bytes = &haystack[window.start()..window.end()];
        let matched = match &self.engine {
            PackedLiteralEngine::Native(searcher) => searcher
                .find(window_bytes)
                .map(|matched| (matched.start(), matched.end())),
            PackedLiteralEngine::NativeSparse {
                searcher,
                sparse_anchor,
            } => find_native(searcher, sparse_anchor, window_bytes),
            PackedLiteralEngine::Factored(factored) => {
                accounting.factored_columns = true;
                factored.find(window_bytes)
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

#[inline]
fn find_native(
    searcher: &Searcher,
    anchor: &SparseAnchor,
    haystack: &[u8],
) -> Option<(usize, usize)> {
    let mut minimum_start = 0_usize;
    for attempt in 0..SPARSE_ANCHOR_CANDIDATE_BUDGET {
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
    if retained_pattern_bytes > SPARSE_ANCHOR_MAX_RETAINED_PATTERN_BYTES {
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
    if maximum_candidate_verification_work > SPARSE_ANCHOR_MAX_CANDIDATE_VERIFICATION_WORK {
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
    let build_work_upper_bound = pattern_bytes
        .checked_add(patterns.len())
        .and_then(|work| work.checked_mul(BUILD_FACTOR))
        .ok_or(PackedLiteralSetError::ArithmeticOverflow {
            computation: "packed literal build work",
        })?;
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

#[cfg(test)]
mod tests {
    use super::{
        BUILD_FACTOR, PackedLiteralEngine, PackedLiteralSetAccounting, PackedLiteralSetBuildLimits,
        PackedLiteralSetError, PackedLiteralSetPlan, PackedLiteralSetSearchLimits,
        select_sparse_anchor,
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
            PackedLiteralEngine::Native(searcher)
            | PackedLiteralEngine::NativeSparse { searcher, .. } => searcher,
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
        assert!(matches!(&single.engine, PackedLiteralEngine::Native(_)));

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
