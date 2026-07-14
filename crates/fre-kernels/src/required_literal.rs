//! Proof-restricted candidate/confirmation search for `CLASS+ SUFFIX`.
//!
//! Admission requires a non-empty byte class, a non-empty suffix whose first
//! byte is outside that class, and an unbordered suffix. Those facts make
//! non-overlapping suffix occurrences complete candidates and make all
//! backward class-confirmation intervals disjoint. Search is therefore
//! worst-case linear and uses no scratch allocation.

use core::{fmt, mem::size_of};

use memchr::memmem::{Finder, FinderBuilder};

use crate::Window;

/// Stable identity of this exact proof and execution strategy.
pub const PLAN_ID: &str = "required-literal.class-plus-unbordered-suffix.v1";

/// A normalized 256-bit byte class.
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

    /// Add one inclusive byte range to this class.
    pub fn insert_inclusive(&mut self, start: u8, end: u8) {
        if start > end {
            return;
        }
        for byte in start..=end {
            let word = usize::from(byte) >> 6;
            let bit = u32::from(byte) & 63;
            self.words[word] |= 1_u64 << bit;
        }
    }

    /// Construct one inclusive byte range. A reversed range is empty.
    #[must_use]
    pub fn inclusive(start: u8, end: u8) -> Self {
        let mut class = Self::default();
        class.insert_inclusive(start, end);
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
            total.saturating_add(usize::try_from(word.count_ones()).unwrap_or(usize::MAX))
        })
    }

    /// Whether this class contains no byte.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.words[0] == 0 && self.words[1] == 0 && self.words[2] == 0 && self.words[3] == 0
    }

    /// Canonical words for cache and explanation identity.
    #[must_use]
    pub const fn words(self) -> [u64; 4] {
        self.words
    }
}

/// Absolute anchors interpreted against the original haystack.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Anchors {
    /// Require the selected match to start at byte zero.
    pub start: bool,
    /// Require the selected match to end at the original haystack length.
    pub end: bool,
}

/// Limits checked before plan construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub max_suffix_bytes: usize,
    pub max_build_work: u64,
    pub max_scratch_bytes: usize,
    pub max_persistent_bytes: usize,
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

/// Limits checked before invoking the native suffix finder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchLimits {
    pub max_work_upper_bound: u64,
    pub max_candidate_visits: usize,
    pub max_scratch_bytes: usize,
}

impl SearchLimits {
    /// Disable caller-selected caps while retaining checked arithmetic.
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
    pub suffix_bytes: usize,
    pub class_cardinality: usize,
    pub work_upper_bound: u64,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Auditable search certificate and actual structural counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchAccounting {
    pub window_bytes: usize,
    pub candidate_visits_upper_bound: usize,
    pub finder_calls_upper_bound: usize,
    pub finder_work_upper_bound: u64,
    pub backward_work_upper_bound: usize,
    pub work_upper_bound: u64,
    pub scratch_bytes: usize,
    pub candidate_visits: usize,
    pub finder_calls: usize,
    pub backward_bytes_examined: usize,
}

/// A semantic refusal or checked construction-resource failure.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    EmptyClass,
    EmptySuffix,
    FirstSuffixByteInClass {
        byte: u8,
    },
    OverlappingSuffix {
        longest_border: usize,
    },
    SuffixLimit {
        needed: usize,
        limit: usize,
    },
    WorkLimit {
        needed: u64,
        limit: u64,
    },
    ScratchLimit {
        needed: usize,
        limit: usize,
    },
    PersistentLimit {
        needed: usize,
        limit: usize,
    },
    PeakLimit {
        needed: usize,
        limit: usize,
    },
    AllocationFailed {
        structure: &'static str,
        additional: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl BuildError {
    /// Whether this error says the theorem does not admit the proposed shape.
    #[must_use]
    pub const fn is_semantic_refusal(&self) -> bool {
        matches!(
            self,
            Self::EmptyClass
                | Self::EmptySuffix
                | Self::FirstSuffixByteInClass { .. }
                | Self::OverlappingSuffix { .. }
        )
    }
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyClass => f.write_str("required-literal class is empty"),
            Self::EmptySuffix => f.write_str("required-literal suffix is empty"),
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

/// A checked search-resource or range failure.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SearchError {
    InvalidWindow {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
    CandidateLimit {
        needed: usize,
        limit: usize,
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

/// Immutable, deliberately non-`Clone` plan for `CLASS+ SUFFIX`.
#[derive(Debug)]
pub struct RequiredLiteralPlan {
    class: ByteClass,
    finder: Finder<'static>,
    anchors: Anchors,
    build: BuildAccounting,
}

impl RequiredLiteralPlan {
    /// Prove eligibility and construct the owned native finder.
    ///
    /// # Errors
    ///
    /// Returns a typed proof refusal or checked resource failure. It never
    /// substitutes a different search plan.
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
        Ok(Self {
            class,
            finder: FinderBuilder::new().build_forward_owned(owned_suffix),
            anchors,
            build: BuildAccounting {
                suffix_bytes: suffix.len(),
                class_cardinality: class.cardinality(),
                work_upper_bound,
                scratch_bytes,
                persistent_bytes,
                peak_bytes,
            },
        })
    }

    /// Stable proof/implementation identity.
    #[must_use]
    pub const fn plan_id(&self) -> &'static str {
        PLAN_ID
    }

    #[must_use]
    pub const fn anchors(&self) -> Anchors {
        self.anchors
    }

    #[must_use]
    pub const fn class(&self) -> ByteClass {
        self.class
    }

    #[must_use]
    pub fn suffix(&self) -> &[u8] {
        self.finder.needle()
    }

    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.build
    }

    /// Find the selected span in the full haystack.
    ///
    /// # Errors
    ///
    /// Returns a checked resource failure before native search begins.
    pub fn find(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        self.find_window(haystack, Window::full(haystack), limits)
    }

    /// Find the selected span wholly within `window`; anchors remain absolute.
    ///
    /// # Errors
    ///
    /// Returns a checked range/resource failure. Search never falls back.
    pub fn find_window(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        if window.start() > window.end() || window.end() > haystack.len() {
            return Err(SearchError::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len: haystack.len(),
            });
        }
        check_search_scratch(0, limits.max_scratch_bytes)?;
        if (self.anchors.start && window.start() != 0)
            || (self.anchors.end && window.end() != haystack.len())
        {
            let window_bytes = window.end().checked_sub(window.start()).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "impossible anchored window bytes",
                },
            )?;
            return Ok((None, zero_accounting(window_bytes)));
        }

        let mut accounting = self.preflight(window, limits)?;
        let slice = &haystack[window.start()..window.end()];
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
                    .start()
                    .checked_add(relative)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "absolute suffix candidate",
                    })?;
            if candidate == window.start() {
                continue;
            }
            let previous = candidate
                .checked_sub(1)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "candidate predecessor",
                })?;
            if !self.class.contains(haystack[previous]) {
                continue;
            }

            let mut start = candidate;
            while start > window.start() {
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
            return Ok((Some((start, end)), accounting));
        }
    }

    fn preflight(
        &self,
        window: Window,
        limits: SearchLimits,
    ) -> Result<SearchAccounting, SearchError> {
        let window_bytes =
            window
                .end()
                .checked_sub(window.start())
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
        let repeated = finder_calls_upper_bound.checked_mul(suffix_bytes).ok_or(
            SearchError::ArithmeticOverflow {
                computation: "repeated finder needle terms",
            },
        )?;
        let finder_work =
            window_bytes
                .checked_add(repeated)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "finder work upper bound",
                })?;
        let structural =
            candidate_visits_upper_bound
                .checked_mul(6)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "candidate structural work",
                })?;
        let work = finder_work
            .checked_add(window_bytes)
            .and_then(|value| value.checked_add(structural))
            .and_then(|value| value.checked_add(2))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "complete search work upper bound",
            })?;
        let finder_work_upper_bound =
            u64::try_from(finder_work).map_err(|_| SearchError::ArithmeticOverflow {
                computation: "finder work as u64",
            })?;
        let work_upper_bound =
            u64::try_from(work).map_err(|_| SearchError::ArithmeticOverflow {
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

fn zero_accounting(window_bytes: usize) -> SearchAccounting {
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
    use super::{Anchors, BuildError, BuildLimits, ByteClass, RequiredLiteralPlan, SearchLimits};
    use crate::Window;

    #[test]
    fn spans_windows_and_accounting_are_exact() {
        let plan = RequiredLiteralPlan::build(
            ByteClass::inclusive(b'a', b'z'),
            b"Z",
            Anchors::default(),
            BuildLimits::default(),
        )
        .unwrap();
        let (matched, accounting) = plan
            .find_window(
                b"--abcZ--xyZ",
                Window::new(2, 11),
                SearchLimits::unlimited(),
            )
            .unwrap();
        assert_eq!(matched, Some((2, 6)));
        assert!(accounting.candidate_visits <= accounting.candidate_visits_upper_bound);
        assert!(accounting.finder_calls <= accounting.finder_calls_upper_bound);
        assert!(accounting.backward_bytes_examined <= accounting.backward_work_upper_bound);
        assert_eq!(plan.plan_id(), super::PLAN_ID);
    }

    #[test]
    fn anchors_keep_original_haystack_context() {
        let plan = RequiredLiteralPlan::build(
            ByteClass::from_bytes(b"ab"),
            b"Z",
            Anchors {
                start: true,
                end: true,
            },
            BuildLimits::default(),
        )
        .unwrap();
        assert_eq!(
            plan.find(b"aaaZ", SearchLimits::unlimited()).unwrap().0,
            Some((0, 4))
        );
        assert_eq!(
            plan.find_window(b"aaaZ", Window::new(1, 4), SearchLimits::unlimited())
                .unwrap()
                .0,
            None
        );
    }

    #[test]
    fn proof_refusals_retain_counterexamples() {
        assert!(matches!(
            RequiredLiteralPlan::build(
                ByteClass::from_bytes(b"a"),
                b"aZ",
                Anchors::default(),
                BuildLimits::default()
            ),
            Err(BuildError::FirstSuffixByteInClass { .. })
        ));
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
    fn every_limit_has_an_exact_success_boundary() {
        let class = ByteClass::from_bytes(b"a");
        let baseline =
            RequiredLiteralPlan::build(class, b"Z", Anchors::default(), BuildLimits::default())
                .unwrap();
        let build = baseline.build_accounting();
        let exact = BuildLimits {
            max_suffix_bytes: build.suffix_bytes,
            max_build_work: build.work_upper_bound,
            max_scratch_bytes: build.scratch_bytes,
            max_persistent_bytes: build.persistent_bytes,
            max_peak_bytes: build.peak_bytes,
        };
        assert!(RequiredLiteralPlan::build(class, b"Z", Anchors::default(), exact).is_ok());
        let search = baseline
            .find(b"aaaaZ", SearchLimits::unlimited())
            .unwrap()
            .1;
        let exact = SearchLimits {
            max_work_upper_bound: search.work_upper_bound,
            max_candidate_visits: search.candidate_visits_upper_bound,
            max_scratch_bytes: search.scratch_bytes,
        };
        assert!(baseline.find(b"aaaaZ", exact).is_ok());
        assert!(matches!(
            baseline.find(
                b"aaaaZ",
                SearchLimits {
                    max_work_upper_bound: search.work_upper_bound - 1,
                    ..SearchLimits::unlimited()
                }
            ),
            Err(super::SearchError::WorkLimit { .. })
        ));
    }

    #[test]
    fn arbitrary_bytes_are_not_utf8_dependent() {
        let plan = RequiredLiteralPlan::build(
            ByteClass::from_bytes(&[0, 0x80, 0xFF]),
            &[0x7F, 0xFE],
            Anchors::default(),
            BuildLimits::default(),
        )
        .unwrap();
        assert_eq!(
            plan.find(&[9, 0x80, 0xFF, 0x7F, 0xFE], SearchLimits::unlimited())
                .unwrap()
                .0,
            Some((1, 5))
        );
    }
}
