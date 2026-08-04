//! SIMD packed ordered finite-literal search with explicit refusal.

use core::{fmt, mem::size_of};

use aho_corasick::packed::Searcher;
use memchr::{
    memchr, memchr2, memchr3,
    memmem::{Finder, FinderBuilder},
};

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
// A native side filter verifies a bounded number of candidates itself. If
// those candidates are all decoys, the packed searcher resumes after the last
// start already disproved. Thus sparse inputs need only one source pass, while
// dense decoys pay bounded work and never restart from byte zero.
const NATIVE_FILTER_CANDIDATE_BUDGET: usize = 4;
const NATIVE_FILTER_MAX_RETAINED_PATTERN_BYTES: usize = 4 * 1024;
// Retain only filters whose exact source-order verification fits in two
// 16-byte blocks. After a rejection, another candidate is attempted only when
// the proved skip amortizes all exact verification performed so far.
const NATIVE_FILTER_MAX_CANDIDATE_VERIFICATION_WORK: usize = 32;
// A one-byte common fragment is already represented by `SparseAnchor`. Two
// bytes are the smallest exact fragment whose occurrence stream can prove
// strictly more impossible starts than that byte-set route.
const SHARED_FRAGMENT_MIN_BYTES: usize = 2;

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
    NativeSharedFragment {
        searcher: Searcher,
        shared_fragment: Box<SharedFragment>,
    },
    Factored(Box<FactoredColumns>),
}

/// Immutable SIMD packed ordered-literal plan.
///
/// This is a shared native primitive, not pattern-specialized JIT code. The
/// pinned implementation uses Teddy on supported x86-64/AArch64 haystacks and
/// a bounded Rabin-Karp path for short inputs. Native sets may first scan a
/// proved shared fixed-offset fragment before source-order tail verification.
/// Larger complete byte-column products use one native byte-set scan plus exact
/// column verification. Construction refuses unsupported targets/shapes and
/// search never changes plan after selection.
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
                // Preserve an already-admitted sparse anchor: a rare byte at
                // another offset can be more selective than a common fragment.
                // The fragment route expands only native sets whose byte
                // anchor could not bound source-order candidate verification.
                let sparse_anchor = select_sparse_anchor(patterns).map(Box::new);
                let shared_fragment = if sparse_anchor.is_some() {
                    None
                } else {
                    select_shared_fragment(patterns, native_searcher.minimum_len()).map(Box::new)
                };
                build.persistent_bytes = native_searcher
                    .memory_usage()
                    .checked_add(
                        sparse_anchor.as_ref().map_or_else(
                            || {
                                shared_fragment
                                    .as_ref()
                                    .map_or(0, |fragment| fragment.persistent_bytes())
                            },
                            |anchor| anchor.persistent_bytes(),
                        ),
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
            PackedLiteralEngine::NativeSharedFragment {
                searcher,
                shared_fragment,
            } => find_native_shared_fragment(searcher, shared_fragment, window_bytes),
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
fn find_native_shared_fragment(
    searcher: &Searcher,
    fragment: &SharedFragment,
    haystack: &[u8],
) -> Option<(usize, usize)> {
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
        BUILD_FACTOR, NATIVE_FILTER_CANDIDATE_BUDGET, PackedLiteralEngine,
        PackedLiteralSetAccounting, PackedLiteralSetBuildLimits, PackedLiteralSetError,
        PackedLiteralSetPlan, PackedLiteralSetSearchLimits, select_shared_fragment,
        select_sparse_anchor, shared_fragment_native_start_budget,
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
            b"aa00", b"aa11", b"aa22", b"aa33", b"aa44", b"aa55", b"aa66", b"aa77",
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
            | PackedLiteralEngine::NativeSparse { searcher, .. }
            | PackedLiteralEngine::NativeSharedFragment { searcher, .. } => searcher,
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
            b"aQR0".as_slice(),
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
