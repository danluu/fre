//! A bounded required-literal candidate/confirmation plan laboratory.
//!
//! The plan in this crate recognizes exactly one deliberately narrow shape:
//! `CLASS+ SUFFIX`, with optional `\A` and `\z` anchors. `SUFFIX` must be
//! non-empty, its first byte must not belong to `CLASS`, and it must be
//! unbordered (no non-empty proper prefix is also a suffix). Those admission
//! checks are semantic proof obligations, not performance guesses.
//!
//! The disjoint first byte makes every suffix candidate a barrier between
//! class runs. The unbordered condition proves that two suffix occurrences
//! cannot overlap, so `memchr`'s non-overlapping, SIMD-aware `memmem` iterator
//! enumerates every candidate. Backward confirmation intervals are disjoint.
//! The first confirmed candidate therefore gives the same leftmost-first,
//! greedy span as the source regular expression. Construction and search are
//! explicitly limited, and an ineligible plan is refused without fallback.

#![forbid(unsafe_code)]

use core::{fmt, mem::size_of};

use memchr::memmem::{Finder, FinderBuilder};

/// Stable identity of the proof and execution strategy.
pub const PLAN_ID: &str = "required-literal.class-plus-unbordered-suffix.v1";

/// A 256-bit byte class.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ByteClass {
    words: [u64; 4],
}

impl ByteClass {
    /// Construct a class containing every byte in `bytes`.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut class = Self::default();
        for &byte in bytes {
            let word = usize::from(byte) >> 6;
            let bit = u32::from(byte) & 63;
            class.words[word] |= 1_u64 << bit;
        }
        class
    }

    /// Construct an inclusive byte range. A reversed range is empty.
    #[must_use]
    pub fn inclusive(start: u8, end: u8) -> Self {
        if start > end {
            return Self::default();
        }
        let mut class = Self::default();
        for byte in start..=end {
            let word = usize::from(byte) >> 6;
            let bit = u32::from(byte) & 63;
            class.words[word] |= 1_u64 << bit;
        }
        class
    }

    /// Whether `byte` belongs to this class.
    #[must_use]
    pub fn contains(self, byte: u8) -> bool {
        let word = usize::from(byte) >> 6;
        let bit = u32::from(byte) & 63;
        self.words[word] & (1_u64 << bit) != 0
    }

    /// Number of distinct bytes in this class.
    #[must_use]
    pub fn cardinality(self) -> usize {
        self.words.iter().fold(0_usize, |total, word| {
            let count = usize::try_from(word.count_ones()).unwrap_or(usize::MAX);
            total.saturating_add(count)
        })
    }

    /// Whether the class contains no byte.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.words == [0; 4]
    }
}

/// Absolute anchors interpreted against the original haystack.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Anchors {
    /// Require the match to start at byte zero of the original haystack.
    pub start: bool,
    /// Require the match to end at the original haystack length.
    pub end: bool,
}

/// A half-open range within the original haystack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Window {
    start: usize,
    end: usize,
}

impl Window {
    /// Construct a window. Search validates it against the haystack.
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    /// The full original haystack.
    #[must_use]
    pub const fn full(haystack: &[u8]) -> Self {
        Self {
            start: 0,
            end: haystack.len(),
        }
    }

    /// Inclusive start byte.
    #[must_use]
    pub const fn start(self) -> usize {
        self.start
    }

    /// Exclusive end byte.
    #[must_use]
    pub const fn end(self) -> usize {
        self.end
    }
}

/// A selected non-empty match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Match {
    start: usize,
    end: usize,
}

impl Match {
    /// Inclusive match start.
    #[must_use]
    pub const fn start(self) -> usize {
        self.start
    }

    /// Exclusive match end.
    #[must_use]
    pub const fn end(self) -> usize {
        self.end
    }
}

/// Limits applied before constructing a plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    /// Maximum suffix bytes copied into the native finder.
    pub max_suffix_bytes: usize,
    /// Maximum conservative construction work units.
    pub max_build_work: u64,
    /// Maximum temporary bytes used by the linear border proof.
    pub max_scratch_bytes: usize,
    /// Maximum persistent plan bytes, including the Rust plan object.
    pub max_persistent_bytes: usize,
    /// Maximum conservative peak of persistent plus temporary bytes.
    pub max_peak_bytes: usize,
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            max_suffix_bytes: 32 * 1024 * 1024,
            max_build_work: 512 * 1024 * 1024,
            max_scratch_bytes: 256 * 1024 * 1024,
            max_persistent_bytes: 64 * 1024 * 1024,
            max_peak_bytes: 320 * 1024 * 1024,
        }
    }
}

/// Limits applied before invoking the native finder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchLimits {
    /// Maximum conservative work upper bound.
    pub max_work_upper_bound: u64,
    /// Maximum possible suffix candidates in the window.
    pub max_candidate_visits: usize,
    /// Maximum search scratch bytes. This plan requires zero.
    pub max_scratch_bytes: usize,
}

impl SearchLimits {
    /// Disable caller-selected limits while retaining checked arithmetic.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_work_upper_bound: u64::MAX,
            max_candidate_visits: usize::MAX,
            max_scratch_bytes: usize::MAX,
        }
    }
}

impl Default for SearchLimits {
    fn default() -> Self {
        Self {
            max_work_upper_bound: 512 * 1024 * 1024,
            max_candidate_visits: 64 * 1024 * 1024,
            max_scratch_bytes: 0,
        }
    }
}

/// Auditable construction certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    /// Suffix bytes admitted and copied.
    pub suffix_bytes: usize,
    /// Number of members of the byte class.
    pub class_cardinality: usize,
    /// Conservative linear construction-work certificate.
    pub work_upper_bound: u64,
    /// Temporary prefix-function bytes used by the overlap proof.
    pub scratch_bytes: usize,
    /// Plan object plus owned suffix payload.
    pub persistent_bytes: usize,
    /// Conservative persistent-plus-scratch peak.
    pub peak_bytes: usize,
}

/// Auditable search certificate and actual structural counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchAccounting {
    /// Bytes in the caller-selected search window.
    pub window_bytes: usize,
    /// Maximum non-overlapping candidates in the window.
    pub candidate_visits_upper_bound: usize,
    /// Maximum finder iterator calls, including its final exhaustion call.
    pub finder_calls_upper_bound: usize,
    /// Window scan plus a suffix-length charge per finder call.
    pub finder_work_upper_bound: u64,
    /// Maximum total backward class-membership examinations.
    pub backward_work_upper_bound: usize,
    /// Complete conservative search work bound.
    pub work_upper_bound: u64,
    /// Search scratch required by this plan.
    pub scratch_bytes: usize,
    /// Suffix candidates actually visited.
    pub candidate_visits: usize,
    /// Finder iterator calls actually made.
    pub finder_calls: usize,
    /// Bytes actually examined during backward confirmation.
    pub backward_bytes_examined: usize,
}

/// Construction refusal or resource failure. There is no fallback.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    /// `CLASS+` can never match, so this optimizer does not admit it.
    EmptyClass,
    /// Required literals must consume at least one byte.
    EmptySuffix,
    /// The suffix boundary is not provably disjoint from the class run.
    FirstSuffixByteInClass { byte: u8 },
    /// A bordered suffix may have overlapping occurrences that `find_iter`
    /// deliberately skips.
    OverlappingSuffix { longest_border: usize },
    /// Suffix input exceeds its configured cap.
    SuffixLimit { needed: usize, limit: usize },
    /// Conservative compile work exceeds its configured cap.
    WorkLimit { needed: u64, limit: u64 },
    /// Border-proof temporary memory exceeds its configured cap.
    ScratchLimit { needed: usize, limit: usize },
    /// Persistent plan memory exceeds its configured cap.
    PersistentLimit { needed: usize, limit: usize },
    /// Conservative compile peak exceeds its configured cap.
    PeakLimit { needed: usize, limit: usize },
    /// A checked buffer reservation failed.
    AllocationFailed {
        structure: &'static str,
        additional: usize,
    },
    /// Size/work arithmetic was not representable.
    ArithmeticOverflow { computation: &'static str },
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyClass => write!(f, "required-literal class is empty"),
            Self::EmptySuffix => write!(f, "required-literal suffix is empty"),
            Self::FirstSuffixByteInClass { byte } => write!(
                f,
                "suffix first byte 0x{byte:02X} belongs to the preceding class"
            ),
            Self::OverlappingSuffix { longest_border } => write!(
                f,
                "suffix has a proper border of {longest_border} bytes and may overlap"
            ),
            Self::SuffixLimit { needed, limit } => {
                write!(f, "suffix needs {needed} bytes, exceeding {limit}")
            }
            Self::WorkLimit { needed, limit } => {
                write!(f, "build needs {needed} work units, exceeding {limit}")
            }
            Self::ScratchLimit { needed, limit } => {
                write!(f, "build needs {needed} scratch bytes, exceeding {limit}")
            }
            Self::PersistentLimit { needed, limit } => {
                write!(f, "plan needs {needed} persistent bytes, exceeding {limit}")
            }
            Self::PeakLimit { needed, limit } => {
                write!(f, "build peak is {needed} bytes, exceeding {limit}")
            }
            Self::AllocationFailed {
                structure,
                additional,
            } => write!(f, "failed to reserve {additional} items for {structure}"),
            Self::ArithmeticOverflow { computation } => {
                write!(f, "arithmetic overflow while computing {computation}")
            }
        }
    }
}

impl std::error::Error for BuildError {}

/// Search refusal or resource failure. There is no fallback.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SearchError {
    /// The range is not contained in the original haystack.
    InvalidWindow {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
    /// Conservative suffix candidate count exceeds its cap.
    CandidateLimit { needed: usize, limit: usize },
    /// Conservative whole-search work exceeds its cap.
    WorkLimit { needed: u64, limit: u64 },
    /// Search scratch exceeds its cap.
    ScratchLimit { needed: usize, limit: usize },
    /// Size/work arithmetic was not representable.
    ArithmeticOverflow { computation: &'static str },
}

impl fmt::Display for SearchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidWindow {
                start,
                end,
                haystack_len,
            } => write!(
                f,
                "required-literal window {start}..{end} is invalid for {haystack_len} bytes"
            ),
            Self::CandidateLimit { needed, limit } => {
                write!(f, "search may visit {needed} candidates, exceeding {limit}")
            }
            Self::WorkLimit { needed, limit } => {
                write!(f, "search needs at most {needed} work, exceeding {limit}")
            }
            Self::ScratchLimit { needed, limit } => {
                write!(f, "search needs {needed} scratch bytes, exceeding {limit}")
            }
            Self::ArithmeticOverflow { computation } => {
                write!(f, "arithmetic overflow while computing {computation}")
            }
        }
    }
}

impl std::error::Error for SearchError {}

/// Immutable forced plan for `CLASS+ SUFFIX`.
#[derive(Debug)]
pub struct RequiredLiteralPlan {
    class: ByteClass,
    finder: Finder<'static>,
    anchors: Anchors,
    build: BuildAccounting,
}

impl RequiredLiteralPlan {
    /// Prove eligibility and construct a native candidate finder.
    ///
    /// # Errors
    ///
    /// Returns a typed semantic refusal or checked resource failure. No other
    /// execution plan is selected.
    pub fn build(
        class: ByteClass,
        suffix: &[u8],
        anchors: Anchors,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        if class.is_empty() {
            return Err(BuildError::EmptyClass);
        }
        let Some(&first) = suffix.first() else {
            return Err(BuildError::EmptySuffix);
        };
        if class.contains(first) {
            return Err(BuildError::FirstSuffixByteInClass { byte: first });
        }
        if suffix.len() > limits.max_suffix_bytes {
            return Err(BuildError::SuffixLimit {
                needed: suffix.len(),
                limit: limits.max_suffix_bytes,
            });
        }

        let suffix_u64 =
            u64::try_from(suffix.len()).map_err(|_| BuildError::ArithmeticOverflow {
                computation: "suffix length as u64",
            })?;
        // Covers prefix-function initialization/comparisons, class facts and
        // native finder preprocessing with deliberately generous constants.
        let work_upper_bound = suffix_u64
            .checked_mul(12)
            .and_then(|work| work.checked_add(32))
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "build work upper bound",
            })?;
        if work_upper_bound > limits.max_build_work {
            return Err(BuildError::WorkLimit {
                needed: work_upper_bound,
                limit: limits.max_build_work,
            });
        }
        let scratch_bytes =
            suffix
                .len()
                .checked_mul(size_of::<usize>())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "border proof scratch bytes",
                })?;
        if scratch_bytes > limits.max_scratch_bytes {
            return Err(BuildError::ScratchLimit {
                needed: scratch_bytes,
                limit: limits.max_scratch_bytes,
            });
        }
        let persistent_bytes =
            size_of::<Self>()
                .checked_add(suffix.len())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "persistent plan bytes",
                })?;
        if persistent_bytes > limits.max_persistent_bytes {
            return Err(BuildError::PersistentLimit {
                needed: persistent_bytes,
                limit: limits.max_persistent_bytes,
            });
        }
        let peak_bytes =
            persistent_bytes
                .checked_add(scratch_bytes)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "construction peak bytes",
                })?;
        if peak_bytes > limits.max_peak_bytes {
            return Err(BuildError::PeakLimit {
                needed: peak_bytes,
                limit: limits.max_peak_bytes,
            });
        }

        let longest_border = longest_border(suffix)?;
        if longest_border != 0 {
            return Err(BuildError::OverlappingSuffix { longest_border });
        }
        let mut owned_suffix = Vec::new();
        owned_suffix
            .try_reserve_exact(suffix.len())
            .map_err(|_| BuildError::AllocationFailed {
                structure: "owned suffix",
                additional: suffix.len(),
            })?;
        owned_suffix.extend_from_slice(suffix);
        let build = BuildAccounting {
            suffix_bytes: suffix.len(),
            class_cardinality: class.cardinality(),
            work_upper_bound,
            scratch_bytes,
            persistent_bytes,
            peak_bytes,
        };
        Ok(Self {
            class,
            finder: FinderBuilder::new().build_forward_owned(owned_suffix),
            anchors,
            build,
        })
    }

    /// Stable forced-plan identifier.
    #[must_use]
    pub const fn plan_id(&self) -> &'static str {
        PLAN_ID
    }

    /// Optional absolute anchors carried by this plan.
    #[must_use]
    pub const fn anchors(&self) -> Anchors {
        self.anchors
    }

    /// The admitted suffix.
    #[must_use]
    pub fn suffix(&self) -> &[u8] {
        self.finder.needle()
    }

    /// The admitted byte class.
    #[must_use]
    pub const fn class(&self) -> ByteClass {
        self.class
    }

    /// Construction resource certificate.
    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.build
    }

    /// Find the selected span in the complete haystack.
    ///
    /// # Errors
    ///
    /// Returns a checked search resource failure before native search begins.
    pub fn find(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<Match>, SearchAccounting), SearchError> {
        self.find_window(haystack, Window::full(haystack), limits)
    }

    /// Find the selected span wholly within `window`.
    ///
    /// Absolute anchors continue to refer to the original haystack. An
    /// unanchored class run may begin at the window boundary, matching the
    /// semantics of a search whose allowed starts are restricted to the
    /// window.
    ///
    /// # Errors
    ///
    /// Returns a checked range or resource error. Search never falls back.
    pub fn find_window(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, SearchAccounting), SearchError> {
        if window.start > window.end || window.end > haystack.len() {
            return Err(SearchError::InvalidWindow {
                start: window.start,
                end: window.end,
                haystack_len: haystack.len(),
            });
        }
        check_search_scratch(0, limits.max_scratch_bytes)?;
        // An absolute anchor outside the permitted span makes the result
        // impossible without invoking the candidate finder.
        if (self.anchors.start && window.start != 0)
            || (self.anchors.end && window.end != haystack.len())
        {
            let window_bytes =
                window
                    .end
                    .checked_sub(window.start)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "impossible anchored window bytes",
                    })?;
            return Ok((None, zero_search_accounting(window_bytes)));
        }

        let mut accounting = self.preflight(window, limits)?;
        let slice = &haystack[window.start..window.end];
        let mut candidates = self.finder.find_iter(slice);
        loop {
            accounting.finder_calls =
                accounting
                    .finder_calls
                    .checked_add(1)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "actual finder calls",
                    })?;
            let Some(relative) = candidates.next() else {
                return Ok((None, accounting));
            };
            accounting.candidate_visits = accounting.candidate_visits.checked_add(1).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "actual candidate visits",
                },
            )?;
            let candidate =
                window
                    .start
                    .checked_add(relative)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "absolute suffix candidate",
                    })?;
            let Some(previous) = candidate.checked_sub(1) else {
                continue;
            };
            if candidate == window.start || !self.class.contains(haystack[previous]) {
                continue;
            }

            let mut start = candidate;
            while start > window.start {
                let previous = start
                    .checked_sub(1)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "backward confirmation position",
                    })?;
                accounting.backward_bytes_examined = accounting
                    .backward_bytes_examined
                    .checked_add(1)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "actual backward examinations",
                    })?;
                if !self.class.contains(haystack[previous]) {
                    break;
                }
                start = previous;
            }
            let end = candidate.checked_add(self.suffix().len()).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "selected match end",
                },
            )?;
            if self.anchors.start && start != 0 {
                continue;
            }
            if self.anchors.end && end != haystack.len() {
                continue;
            }
            return Ok((Some(Match { start, end }), accounting));
        }
    }

    fn preflight(
        &self,
        window: Window,
        limits: SearchLimits,
    ) -> Result<SearchAccounting, SearchError> {
        let window_bytes =
            window
                .end
                .checked_sub(window.start)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "search window bytes",
                })?;
        let suffix_bytes = self.suffix().len();
        let candidate_visits_upper_bound =
            window_bytes
                .checked_div(suffix_bytes)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "candidate count upper bound",
                })?;
        if candidate_visits_upper_bound > limits.max_candidate_visits {
            return Err(SearchError::CandidateLimit {
                needed: candidate_visits_upper_bound,
                limit: limits.max_candidate_visits,
            });
        }
        let finder_calls_upper_bound =
            candidate_visits_upper_bound
                .checked_add(1)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "finder calls upper bound",
                })?;
        let finder_repeated_needle_terms = finder_calls_upper_bound
            .checked_mul(suffix_bytes)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "repeated finder needle terms",
            })?;
        let finder_work_usize = window_bytes
            .checked_add(finder_repeated_needle_terms)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "finder work upper bound",
            })?;
        let candidate_structure =
            candidate_visits_upper_bound
                .checked_mul(6)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "candidate structural work",
                })?;
        let work_usize = finder_work_usize
            .checked_add(window_bytes)
            .and_then(|work| work.checked_add(candidate_structure))
            .and_then(|work| work.checked_add(2))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "complete search work upper bound",
            })?;
        let finder_work_upper_bound =
            u64::try_from(finder_work_usize).map_err(|_| SearchError::ArithmeticOverflow {
                computation: "finder work as u64",
            })?;
        let work_upper_bound =
            u64::try_from(work_usize).map_err(|_| SearchError::ArithmeticOverflow {
                computation: "search work as u64",
            })?;
        if work_upper_bound > limits.max_work_upper_bound {
            return Err(SearchError::WorkLimit {
                needed: work_upper_bound,
                limit: limits.max_work_upper_bound,
            });
        }
        Ok(SearchAccounting {
            window_bytes,
            candidate_visits_upper_bound,
            finder_calls_upper_bound,
            finder_work_upper_bound,
            backward_work_upper_bound: window_bytes,
            work_upper_bound,
            scratch_bytes: 0,
            candidate_visits: 0,
            finder_calls: 0,
            backward_bytes_examined: 0,
        })
    }
}

fn zero_search_accounting(window_bytes: usize) -> SearchAccounting {
    SearchAccounting {
        window_bytes,
        candidate_visits_upper_bound: 0,
        finder_calls_upper_bound: 0,
        finder_work_upper_bound: 0,
        backward_work_upper_bound: 0,
        work_upper_bound: 0,
        scratch_bytes: 0,
        candidate_visits: 0,
        finder_calls: 0,
        backward_bytes_examined: 0,
    }
}

fn check_search_scratch(needed: usize, limit: usize) -> Result<(), SearchError> {
    if needed > limit {
        return Err(SearchError::ScratchLimit { needed, limit });
    }
    Ok(())
}

fn longest_border(suffix: &[u8]) -> Result<usize, BuildError> {
    let mut prefix = Vec::new();
    prefix
        .try_reserve_exact(suffix.len())
        .map_err(|_| BuildError::AllocationFailed {
            structure: "suffix prefix function",
            additional: suffix.len(),
        })?;
    prefix.push(0);
    let mut matched = 0_usize;
    for index in 1..suffix.len() {
        while matched != 0 && suffix[index] != suffix[matched] {
            let previous = matched
                .checked_sub(1)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "prefix fallback index",
                })?;
            matched = prefix[previous];
        }
        if suffix[index] == suffix[matched] {
            matched = matched
                .checked_add(1)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "prefix matched length",
                })?;
        }
        prefix.push(matched);
    }
    prefix
        .last()
        .copied()
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "non-empty suffix prefix result",
        })
}

#[cfg(test)]
mod tests {
    use super::{
        Anchors, BuildError, BuildLimits, ByteClass, Match, RequiredLiteralPlan, SearchError,
        SearchLimits, Window,
    };
    use regex::bytes::RegexBuilder;
    use std::fmt::Write as _;

    fn plan(class: ByteClass, suffix: &[u8], anchors: Anchors) -> RequiredLiteralPlan {
        RequiredLiteralPlan::build(class, suffix, anchors, BuildLimits::default()).unwrap()
    }

    #[test]
    fn positive_negative_and_greedy_spans() {
        let plan = plan(ByteClass::inclusive(b'a', b'z'), b"Z", Anchors::default());
        let (matched, accounting) = plan
            .find(b"--abcZ--xyZ", SearchLimits::unlimited())
            .unwrap();
        assert_eq!(matched, Some(Match { start: 2, end: 6 }));
        assert_eq!(accounting.candidate_visits, 1);
        assert_eq!(accounting.backward_bytes_examined, 4);
        assert_eq!(plan.plan_id(), super::PLAN_ID);

        assert_eq!(
            plan.find(b"--Z--", SearchLimits::unlimited()).unwrap().0,
            None
        );
    }

    #[test]
    fn windows_restrict_starts_but_anchors_remain_absolute() {
        let class = ByteClass::from_bytes(b"ab");
        let unanchored = plan(class, b"Z", Anchors::default());
        assert_eq!(
            unanchored
                .find_window(b"aaaZbbZ", Window::new(1, 7), SearchLimits::unlimited())
                .unwrap()
                .0,
            Some(Match { start: 1, end: 4 })
        );

        let start = plan(
            class,
            b"Z",
            Anchors {
                start: true,
                end: false,
            },
        );
        assert_eq!(
            start
                .find_window(b"aaaZ", Window::new(1, 4), SearchLimits::unlimited())
                .unwrap()
                .0,
            None
        );
        let both = plan(
            class,
            b"Z",
            Anchors {
                start: true,
                end: true,
            },
        );
        assert_eq!(
            both.find(b"aaaZ", SearchLimits::unlimited()).unwrap().0,
            Some(Match { start: 0, end: 4 })
        );
    }

    #[test]
    fn semantic_proof_obligations_refuse_unsafe_shapes() {
        assert_eq!(
            RequiredLiteralPlan::build(
                ByteClass::default(),
                b"Z",
                Anchors::default(),
                BuildLimits::default()
            )
            .unwrap_err(),
            BuildError::EmptyClass
        );
        assert_eq!(
            RequiredLiteralPlan::build(
                ByteClass::from_bytes(b"a"),
                b"aZ",
                Anchors::default(),
                BuildLimits::default()
            )
            .unwrap_err(),
            BuildError::FirstSuffixByteInClass { byte: b'a' }
        );
        assert_eq!(
            RequiredLiteralPlan::build(
                ByteClass::from_bytes(b"b"),
                b"aba",
                Anchors::default(),
                BuildLimits::default()
            )
            .unwrap_err(),
            BuildError::OverlappingSuffix { longest_border: 1 }
        );
    }

    #[test]
    fn linear_border_proof_matches_naive_exhaustive_oracle() {
        for suffix in non_empty_words(b"abc", 7) {
            let expected = (1..suffix.len())
                .rev()
                .find(|&length| {
                    let start = suffix.len().checked_sub(length).unwrap();
                    suffix[..length] == suffix[start..]
                })
                .unwrap_or(0);
            assert_eq!(
                super::longest_border(&suffix).unwrap(),
                expected,
                "{suffix:?}"
            );
        }
    }

    #[test]
    fn overlap_refusal_preserves_a_real_skipped_candidate_counterexample() {
        // Non-overlapping `find_iter("ababa", "aba")` reports only offset 0.
        // The skipped overlap at 2 has a preceding `b` and would confirm b+aba.
        let class = ByteClass::from_bytes(b"b");
        assert!(matches!(
            RequiredLiteralPlan::build(class, b"aba", Anchors::default(), BuildLimits::default()),
            Err(BuildError::OverlappingSuffix { .. })
        ));
        let regex = RegexBuilder::new(r"(?-u:[\x62]+\x61\x62\x61)")
            .unicode(false)
            .build()
            .unwrap();
        assert_eq!(
            regex.find(b"ababa").map(|m| (m.start(), m.end())),
            Some((1, 5))
        );
    }

    #[test]
    fn build_limits_are_checked_and_exact_bound_succeeds() {
        let class = ByteClass::from_bytes(b"a");
        let scratch_limited = BuildLimits {
            max_scratch_bytes: 0,
            ..BuildLimits::default()
        };
        assert!(matches!(
            RequiredLiteralPlan::build(class, b"Z", Anchors::default(), scratch_limited),
            Err(BuildError::ScratchLimit { .. })
        ));

        let plan = plan(class, b"Z", Anchors::default());
        let baseline = plan.build_accounting();
        for (limits, expected) in [
            (
                BuildLimits {
                    max_suffix_bytes: 0,
                    ..BuildLimits::default()
                },
                BuildError::SuffixLimit {
                    needed: 1,
                    limit: 0,
                },
            ),
            (
                BuildLimits {
                    max_build_work: baseline.work_upper_bound.saturating_sub(1),
                    ..BuildLimits::default()
                },
                BuildError::WorkLimit {
                    needed: baseline.work_upper_bound,
                    limit: baseline.work_upper_bound.saturating_sub(1),
                },
            ),
            (
                BuildLimits {
                    max_persistent_bytes: baseline.persistent_bytes.saturating_sub(1),
                    ..BuildLimits::default()
                },
                BuildError::PersistentLimit {
                    needed: baseline.persistent_bytes,
                    limit: baseline.persistent_bytes.saturating_sub(1),
                },
            ),
            (
                BuildLimits {
                    max_peak_bytes: baseline.peak_bytes.saturating_sub(1),
                    ..BuildLimits::default()
                },
                BuildError::PeakLimit {
                    needed: baseline.peak_bytes,
                    limit: baseline.peak_bytes.saturating_sub(1),
                },
            ),
        ] {
            assert_eq!(
                RequiredLiteralPlan::build(class, b"Z", Anchors::default(), limits).unwrap_err(),
                expected
            );
        }
        let exact_build_limits = BuildLimits {
            max_suffix_bytes: baseline.suffix_bytes,
            max_build_work: baseline.work_upper_bound,
            max_scratch_bytes: baseline.scratch_bytes,
            max_persistent_bytes: baseline.persistent_bytes,
            max_peak_bytes: baseline.peak_bytes,
        };
        assert!(
            RequiredLiteralPlan::build(class, b"Z", Anchors::default(), exact_build_limits).is_ok()
        );
    }

    #[test]
    fn search_limits_are_checked_and_exact_bound_succeeds() {
        let class = ByteClass::from_bytes(b"a");
        let plan = plan(class, b"Z", Anchors::default());
        let exact = plan.find(b"aaaaZ", SearchLimits::unlimited()).unwrap().1;
        let limited = SearchLimits {
            max_work_upper_bound: exact.work_upper_bound.saturating_sub(1),
            ..SearchLimits::unlimited()
        };
        assert_eq!(
            plan.find(b"aaaaZ", limited).unwrap_err(),
            SearchError::WorkLimit {
                needed: exact.work_upper_bound,
                limit: exact.work_upper_bound.saturating_sub(1),
            }
        );
        let candidate_limited = SearchLimits {
            max_candidate_visits: exact.candidate_visits_upper_bound.saturating_sub(1),
            ..SearchLimits::unlimited()
        };
        assert_eq!(
            plan.find(b"aaaaZ", candidate_limited).unwrap_err(),
            SearchError::CandidateLimit {
                needed: exact.candidate_visits_upper_bound,
                limit: exact.candidate_visits_upper_bound.saturating_sub(1),
            }
        );
        let exact_search_limits = SearchLimits {
            max_work_upper_bound: exact.work_upper_bound,
            max_candidate_visits: exact.candidate_visits_upper_bound,
            max_scratch_bytes: exact.scratch_bytes,
        };
        assert!(plan.find(b"aaaaZ", exact_search_limits).is_ok());
        assert!(matches!(
            plan.find_window(b"abc", Window::new(2, 4), SearchLimits::unlimited()),
            Err(SearchError::InvalidWindow { .. })
        ));
    }

    #[test]
    fn arbitrary_bytes_are_not_utf8_dependent() {
        let plan = plan(
            ByteClass::from_bytes(&[0, 0x80, 0xFF]),
            &[0x7F, 0xFE],
            Anchors::default(),
        );
        assert_eq!(
            plan.find(&[9, 0x80, 0xFF, 0x7F, 0xFE], SearchLimits::unlimited())
                .unwrap()
                .0,
            Some(Match { start: 1, end: 5 })
        );
    }

    #[test]
    fn exhaustive_small_languages_match_rebar_regex() {
        let alphabet = [b'a', b'b', b'Z'];
        let haystacks = words(&alphabet, 6);
        let suffixes = non_empty_words(&alphabet, 3);
        let mut comparisons = 0_usize;
        for mask in 1_u8..4 {
            let class_bytes: Vec<u8> = [b'a', b'b']
                .into_iter()
                .enumerate()
                .filter_map(|(bit, byte)| (mask & (1_u8 << bit) != 0).then_some(byte))
                .collect();
            let class = ByteClass::from_bytes(&class_bytes);
            for suffix in &suffixes {
                for start in [false, true] {
                    for end in [false, true] {
                        let anchors = Anchors { start, end };
                        let Ok(plan) = RequiredLiteralPlan::build(
                            class,
                            suffix,
                            anchors,
                            BuildLimits::default(),
                        ) else {
                            continue;
                        };
                        let regex = RegexBuilder::new(&pattern(&class_bytes, suffix, anchors))
                            .unicode(false)
                            .build()
                            .unwrap();
                        for haystack in &haystacks {
                            let (actual, accounting) =
                                plan.find(haystack, SearchLimits::unlimited()).unwrap();
                            assert!(
                                accounting.candidate_visits
                                    <= accounting.candidate_visits_upper_bound
                            );
                            assert!(accounting.finder_calls <= accounting.finder_calls_upper_bound);
                            assert!(
                                accounting.backward_bytes_examined
                                    <= accounting.backward_work_upper_bound
                            );
                            let actual = actual.map(|matched| (matched.start(), matched.end()));
                            let expected = regex.find(haystack).map(|m| (m.start(), m.end()));
                            assert_eq!(
                                actual,
                                expected,
                                "pattern={} haystack={haystack:?}",
                                pattern(&class_bytes, suffix, anchors)
                            );
                            comparisons = comparisons.saturating_add(1);
                        }
                    }
                }
            }
        }
        assert_eq!(comparisons, 196_740);
    }

    #[test]
    fn exhaustive_small_windows_match_find_at_semantics() {
        let alphabet = [b'a', b'Z'];
        let haystacks = words(&alphabet, 4);
        let suffixes = non_empty_words(&alphabet, 2);
        let class_bytes = [b'a'];
        let class = ByteClass::from_bytes(&class_bytes);
        let mut comparisons = 0_usize;
        for suffix in &suffixes {
            for start_anchor in [false, true] {
                for end_anchor in [false, true] {
                    let anchors = Anchors {
                        start: start_anchor,
                        end: end_anchor,
                    };
                    let Ok(plan) =
                        RequiredLiteralPlan::build(class, suffix, anchors, BuildLimits::default())
                    else {
                        continue;
                    };
                    let regex = RegexBuilder::new(&pattern(&class_bytes, suffix, anchors))
                        .unicode(false)
                        .build()
                        .unwrap();
                    for haystack in &haystacks {
                        for window_start in 0..=haystack.len() {
                            for window_end in window_start..=haystack.len() {
                                let actual = plan
                                    .find_window(
                                        haystack,
                                        Window::new(window_start, window_end),
                                        SearchLimits::unlimited(),
                                    )
                                    .unwrap()
                                    .0
                                    .map(|matched| (matched.start(), matched.end()));
                                let expected = regex
                                    .find_at(haystack, window_start)
                                    .filter(|matched| matched.end() <= window_end)
                                    .map(|matched| (matched.start(), matched.end()));
                                assert_eq!(
                                    actual, expected,
                                    "{haystack:?} {window_start}..{window_end}"
                                );
                                comparisons = comparisons.saturating_add(1);
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(comparisons, 2_808);
    }

    fn pattern(class: &[u8], suffix: &[u8], anchors: Anchors) -> String {
        let mut pattern = String::from("(?-u:");
        if anchors.start {
            pattern.push_str(r"\A");
        }
        pattern.push('[');
        for &byte in class {
            write!(pattern, r"\x{byte:02X}").unwrap();
        }
        pattern.push_str("]+");
        for &byte in suffix {
            write!(pattern, r"\x{byte:02X}").unwrap();
        }
        if anchors.end {
            pattern.push_str(r"\z");
        }
        pattern.push(')');
        pattern
    }

    fn words(alphabet: &[u8], max_len: usize) -> Vec<Vec<u8>> {
        let mut all = vec![Vec::new()];
        let mut frontier = vec![Vec::new()];
        for _ in 0..max_len {
            let mut next = Vec::new();
            for prefix in &frontier {
                for &byte in alphabet {
                    let mut word = prefix.clone();
                    word.push(byte);
                    next.push(word);
                }
            }
            all.extend(next.iter().cloned());
            frontier = next;
        }
        all
    }

    fn non_empty_words(alphabet: &[u8], max_len: usize) -> Vec<Vec<u8>> {
        words(alphabet, max_len)
            .into_iter()
            .filter(|word| !word.is_empty())
            .collect()
    }
}
