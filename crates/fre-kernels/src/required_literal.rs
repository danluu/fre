//! Proof-restricted candidate/confirmation search for `CLASS+ SUFFIX`.
//!
//! Admission requires a non-empty byte class, a non-empty suffix whose first
//! byte is outside that class, and an unbordered suffix. Those facts make
//! non-overlapping suffix occurrences complete candidates and make all
//! backward class-confirmation intervals disjoint. Search is therefore
//! worst-case linear and uses no scratch allocation.
//! A caller-captured dispatch context may retain one automatic directional
//! scanner for an all-ASCII class on a host with OS-usable SVE. Its exact
//! physical classifications, including failed-block recovery, are charged;
//! every other construction retains the established scalar owner and loop.

use core::{fmt, mem::size_of};

use fre_simd_kernels::{
    ASCII_RUN_MAX_CLASSIFICATION_OVERHEAD, AsciiByteSet, AsciiByteSetRunScanner, DispatchPolicy,
    Feature, SelectionReceipt, SimdDispatchContext,
};
use memchr::memmem::{Finder, FinderBuilder};

use crate::Window;

/// Stable identity of this exact proof and execution strategy.
pub const PLAN_ID: &str = "required-literal.class-plus-unbordered-suffix.v1";

/// Stable identity of the opt-in all-ASCII backward run implementation.
pub const ASCII_BACKWARD_RUN_PLAN_ID: &str =
    "required-literal.class-plus-unbordered-suffix.v1.ascii-backward-run16.v1";

// The scanner builds both table representations in one 128-value pass,
// makes one paired-direction selection, and records one immutable receipt.
const SIMD_RUN_SCANNER_BUILD_WORK: u64 = 128 + 1 + 1;

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

    const fn is_ascii(self) -> bool {
        self.words[2] == 0 && self.words[3] == 0
    }

    const fn ascii_set(self) -> AsciiByteSet {
        AsciiByteSet::from_words([self.words[0], self.words[1]])
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

/// Required-literal owner with one construction-selected backward run scanner.
///
/// The wrapper is separate so the legacy plan's storage and build receipts do
/// not change on non-SVE hosts or for classes containing non-ASCII bytes.
#[derive(Debug)]
pub struct DispatchedRequiredLiteralPlan {
    plan: RequiredLiteralPlan,
    backward_scanner: Option<AsciiByteSetRunScanner>,
}

impl RequiredLiteralPlan {
    /// Whether this host and class select the opt-in backward run scanner.
    ///
    /// This is the same predicate used by [`Self::build_with_dispatch`].
    /// Callers can retain the legacy owner type whenever it returns false.
    #[must_use]
    pub fn run_scanner_eligible(dispatch: SimdDispatchContext, class: ByteClass) -> bool {
        !class.is_empty()
            && class.is_ascii()
            && dispatch.capabilities().usable().contains(Feature::ArmSve)
    }

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
        let (plan, scanner) =
            Self::build_inner(class, suffix, anchors, limits, size_of::<Self>(), None)?;
        debug_assert!(scanner.is_none());
        Ok(plan)
    }

    /// Prove eligibility while retaining an automatic scanner on OS-usable SVE.
    ///
    /// The returned wrapper preserves the scalar search path when the class or
    /// host is ineligible. Its exact inline storage and the scanner's 130
    /// construction work units are included before any allocation.
    ///
    /// # Errors
    ///
    /// Returns the same typed proof, arithmetic, resource, or allocation
    /// refusals as [`Self::build`].
    pub fn build_with_dispatch(
        dispatch: SimdDispatchContext,
        class: ByteClass,
        suffix: &[u8],
        anchors: Anchors,
        limits: BuildLimits,
    ) -> Result<DispatchedRequiredLiteralPlan, BuildError> {
        let (plan, backward_scanner) = Self::build_inner(
            class,
            suffix,
            anchors,
            limits,
            size_of::<DispatchedRequiredLiteralPlan>(),
            Some((dispatch, DispatchPolicy::Auto)),
        )?;
        Ok(DispatchedRequiredLiteralPlan {
            plan,
            backward_scanner,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "construction keeps proof refusals and every resource boundary explicit"
    )]
    fn build_inner(
        class: ByteClass,
        suffix: &[u8],
        anchors: Anchors,
        limits: BuildLimits,
        retained_owner_bytes: usize,
        dispatch: Option<(SimdDispatchContext, DispatchPolicy)>,
    ) -> Result<(Self, Option<AsciiByteSetRunScanner>), BuildError> {
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
        let scanner_eligible =
            dispatch.is_some_and(|(context, _)| Self::run_scanner_eligible(context, class));

        let suffix_u64 =
            u64::try_from(suffix.len()).map_err(|_| BuildError::ArithmeticOverflow {
                computation: "suffix length as u64",
            })?;
        let work_upper_bound = suffix_u64
            .checked_mul(12)
            .and_then(|work| work.checked_add(32))
            .and_then(|work| {
                work.checked_add(if scanner_eligible {
                    SIMD_RUN_SCANNER_BUILD_WORK
                } else {
                    0
                })
            })
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
        let persistent_bytes = retained_owner_bytes.checked_add(suffix.len()).ok_or(
            BuildError::ArithmeticOverflow {
                computation: "persistent plan bytes",
            },
        )?;
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
        let backward_scanner = if scanner_eligible {
            let (dispatch, policy) =
                dispatch.expect("scanner eligibility requires one dispatch context");
            Some(
                dispatch
                    .ascii_byte_set_run_scanner(class.ascii_set(), policy)
                    .expect("the retained policy was derived from this authentic host snapshot"),
            )
        } else {
            None
        };
        Ok((
            Self {
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
            },
            backward_scanner,
        ))
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
        self.find_window_with_run_scanner(haystack, window, limits, None)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the scalar and scanner confirmations stay adjacent so their candidate and anchor control remains visibly identical"
    )]
    fn find_window_with_run_scanner(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
        backward_scanner: Option<&AsciiByteSetRunScanner>,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        debug_assert!(backward_scanner.is_none() || self.class.is_ascii());
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

        let mut accounting = self.preflight(window, limits, backward_scanner)?;
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

            let start = if let Some(scanner) = backward_scanner {
                let backward =
                    scanner.scan_backward(haystack.get(window.start()..candidate).ok_or(
                        SearchError::ArithmeticOverflow {
                            computation: "backward confirmation slice",
                        },
                    )?);
                accounting.backward_bytes_examined = accounting
                    .backward_bytes_examined
                    .checked_add(backward.examined_bytes())
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "actual backward examinations",
                    })?;
                candidate.checked_sub(backward.member_run_len()).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "backward confirmation start",
                    },
                )?
            } else {
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
                start
            };
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
        backward_scanner: Option<&AsciiByteSetRunScanner>,
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
        let scanner_overhead = if backward_scanner.is_some() {
            candidate_visits_upper_bound
                .checked_mul(ASCII_RUN_MAX_CLASSIFICATION_OVERHEAD)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "backward scanner overhead upper bound",
                })?
        } else {
            0
        };
        let backward_work =
            window_bytes
                .checked_add(scanner_overhead)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "backward work upper bound",
                })?;
        let work = finder_work
            .checked_add(backward_work)
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
            backward_work_upper_bound: backward_work,
            work_upper_bound,
            scratch_bytes: 0,
            candidate_visits: 0,
            finder_calls: 0,
            backward_bytes_examined: 0,
        })
    }
}

impl DispatchedRequiredLiteralPlan {
    /// Stable authenticated execution identity.
    #[must_use]
    pub const fn plan_id(&self) -> &'static str {
        if self.backward_scanner.is_some() {
            ASCII_BACKWARD_RUN_PLAN_ID
        } else {
            PLAN_ID
        }
    }

    #[must_use]
    pub const fn anchors(&self) -> Anchors {
        self.plan.anchors()
    }

    #[must_use]
    pub const fn class(&self) -> ByteClass {
        self.plan.class()
    }

    #[must_use]
    pub fn suffix(&self) -> &[u8] {
        self.plan.suffix()
    }

    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.plan.build_accounting()
    }

    /// Exact immutable selection receipt for the optional backward scanner.
    #[must_use]
    pub const fn run_scanner_selection(&self) -> Option<SelectionReceipt> {
        match self.backward_scanner {
            Some(scanner) => Some(scanner.selection()),
            None => None,
        }
    }

    /// Find the selected span in the full haystack.
    ///
    /// # Errors
    ///
    /// Returns a checked resource failure before scanning begins.
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
        self.plan.find_window_with_run_scanner(
            haystack,
            window,
            limits,
            self.backward_scanner.as_ref(),
        )
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
    use super::{
        ASCII_BACKWARD_RUN_PLAN_ID, ASCII_RUN_MAX_CLASSIFICATION_OVERHEAD, Anchors, BuildError,
        BuildLimits, ByteClass, DispatchedRequiredLiteralPlan, PLAN_ID, RequiredLiteralPlan,
        SIMD_RUN_SCANNER_BUILD_WORK, SearchError, SearchLimits,
    };
    use crate::Window;
    use core::mem::size_of;
    use fre_simd_kernels::{DispatchPolicy, Feature, SimdDispatchContext};

    const ASCII_MEMBERS: &[u8] = b"0_aceg";

    fn ascii_class() -> ByteClass {
        ByteClass::from_bytes(ASCII_MEMBERS)
    }

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

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the test keeps opt-in identity, owner accounting, boundary semantics, and exclusions together"
    )]
    fn public_dispatch_is_confined_to_sve_ascii_classes() {
        let class = ascii_class();
        let anchors = Anchors::default();
        let legacy =
            RequiredLiteralPlan::build(class, b"Z", anchors, BuildLimits::default()).unwrap();
        let dispatch = SimdDispatchContext::capture();
        let dispatched = RequiredLiteralPlan::build_with_dispatch(
            dispatch,
            class,
            b"Z",
            anchors,
            BuildLimits::default(),
        )
        .unwrap();
        let sve_usable = dispatch.capabilities().usable().contains(Feature::ArmSve);
        assert_eq!(dispatched.run_scanner_selection().is_some(), sve_usable);
        assert_eq!(
            dispatched.plan_id(),
            if sve_usable {
                ASCII_BACKWARD_RUN_PLAN_ID
            } else {
                PLAN_ID
            }
        );
        assert_eq!(legacy.plan_id(), PLAN_ID);
        assert_eq!(dispatched.class(), class);
        assert_eq!(dispatched.suffix(), b"Z");
        assert_eq!(dispatched.anchors(), anchors);
        assert_eq!(
            dispatched.build_accounting().work_upper_bound,
            legacy.build_accounting().work_upper_bound
                + u64::from(sve_usable) * SIMD_RUN_SCANNER_BUILD_WORK
        );
        assert_eq!(
            legacy.build_accounting().persistent_bytes,
            size_of::<RequiredLiteralPlan>() + 1
        );
        assert_eq!(
            dispatched.build_accounting().persistent_bytes,
            size_of::<DispatchedRequiredLiteralPlan>() + 1
        );

        for run_len in [0_usize, 1, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65, 257] {
            let mut haystack = b"Z!".to_vec();
            haystack.extend((0..run_len).map(|index| ASCII_MEMBERS[index % ASCII_MEMBERS.len()]));
            haystack.push(b'Z');
            let legacy_result = legacy.find(&haystack, SearchLimits::unlimited()).unwrap();
            let dispatched_result = dispatched
                .find(&haystack, SearchLimits::unlimited())
                .unwrap();
            assert_eq!(dispatched_result.0, legacy_result.0, "run_len={run_len}");
            assert_eq!(
                dispatched_result.1.candidate_visits,
                legacy_result.1.candidate_visits
            );
            assert_eq!(
                dispatched_result.1.finder_calls,
                legacy_result.1.finder_calls
            );
            assert!(
                dispatched_result.1.backward_bytes_examined
                    <= dispatched_result.1.backward_work_upper_bound
            );
            if sve_usable {
                assert!(
                    dispatched_result.1.backward_bytes_examined
                        <= legacy_result.1.backward_bytes_examined.saturating_add(
                            dispatched_result
                                .1
                                .candidate_visits
                                .saturating_mul(ASCII_RUN_MAX_CLASSIFICATION_OVERHEAD)
                        )
                );
            } else {
                assert_eq!(dispatched_result.1, legacy_result.1);
            }
        }

        let non_ascii = ByteClass::from_bytes(&[0, 2, 4, 0x80, 0xff]);
        assert!(!RequiredLiteralPlan::run_scanner_eligible(
            dispatch, non_ascii
        ));
        let non_ascii_legacy =
            RequiredLiteralPlan::build(non_ascii, b"Z", anchors, BuildLimits::default()).unwrap();
        let non_ascii_dispatched = RequiredLiteralPlan::build_with_dispatch(
            dispatch,
            non_ascii,
            b"Z",
            anchors,
            BuildLimits::default(),
        )
        .unwrap();
        assert!(non_ascii_dispatched.run_scanner_selection().is_none());
        assert_eq!(non_ascii_dispatched.plan_id(), PLAN_ID);
        assert_eq!(
            non_ascii_dispatched
                .find(&[9, 0x80, 0xff, b'Z'], SearchLimits::unlimited())
                .unwrap(),
            non_ascii_legacy
                .find(&[9, 0x80, 0xff, b'Z'], SearchLimits::unlimited())
                .unwrap()
        );
    }

    #[test]
    fn backward_scanner_path_preserves_anchors_and_charges_physical_work() {
        let class = ascii_class();
        let plan =
            RequiredLiteralPlan::build(class, b"Z", Anchors::default(), BuildLimits::default())
                .unwrap();
        let scanner = SimdDispatchContext::capture()
            .ascii_byte_set_run_scanner(class.ascii_set(), DispatchPolicy::Portable)
            .unwrap();
        let haystack = b"Z!0_aZ";
        let scalar = plan.find(haystack, SearchLimits::unlimited()).unwrap();
        let accelerated = plan
            .find_window_with_run_scanner(
                haystack,
                Window::full(haystack),
                SearchLimits::unlimited(),
                Some(&scanner),
            )
            .unwrap();
        assert_eq!(accelerated.0, scalar.0);
        assert_eq!(accelerated.0, Some((2, 6)));
        let leaf = scanner.scan_backward(&haystack[..5]);
        assert_eq!(leaf.member_run_len(), 3);
        assert_eq!(accelerated.1.backward_bytes_examined, leaf.examined_bytes());
        assert_eq!(
            accelerated.1.backward_work_upper_bound,
            scalar
                .1
                .backward_work_upper_bound
                .checked_add(
                    accelerated
                        .1
                        .candidate_visits_upper_bound
                        .checked_mul(ASCII_RUN_MAX_CLASSIFICATION_OVERHEAD)
                        .unwrap()
                )
                .unwrap()
        );
        assert_eq!(
            accelerated.1.work_upper_bound,
            scalar
                .1
                .work_upper_bound
                .checked_add(
                    u64::try_from(
                        accelerated
                            .1
                            .candidate_visits_upper_bound
                            .checked_mul(ASCII_RUN_MAX_CLASSIFICATION_OVERHEAD)
                            .unwrap()
                    )
                    .unwrap()
                )
                .unwrap()
        );

        for anchors in [
            Anchors {
                start: true,
                end: false,
            },
            Anchors {
                start: false,
                end: true,
            },
            Anchors {
                start: true,
                end: true,
            },
        ] {
            let anchored =
                RequiredLiteralPlan::build(class, b"Z", anchors, BuildLimits::default()).unwrap();
            let scalar = anchored
                .find_window(b"0_aZtail", Window::new(0, 4), SearchLimits::unlimited())
                .unwrap();
            let accelerated = anchored
                .find_window_with_run_scanner(
                    b"0_aZtail",
                    Window::new(0, 4),
                    SearchLimits::unlimited(),
                    Some(&scanner),
                )
                .unwrap();
            assert_eq!(accelerated.0, scalar.0, "anchors={anchors:?}");
            let scalar_window = anchored
                .find_window(b"0_aZ", Window::new(1, 4), SearchLimits::unlimited())
                .unwrap();
            let accelerated_window = anchored
                .find_window_with_run_scanner(
                    b"0_aZ",
                    Window::new(1, 4),
                    SearchLimits::unlimited(),
                    Some(&scanner),
                )
                .unwrap();
            assert_eq!(accelerated_window.0, scalar_window.0, "anchors={anchors:?}");
            if anchors.start {
                assert_eq!(accelerated_window.0, None);
            }
        }
    }

    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the bounded base-four corpus has at most five bytes"
    )]
    fn portable_scanner_matches_scalar_across_bounded_windows_and_anchors() {
        let dispatch = SimdDispatchContext::capture();
        let classes = [
            ByteClass::from_bytes(b"a"),
            ByteClass::from_bytes(b"ab"),
            ascii_class(),
        ];
        let anchors = [
            Anchors {
                start: false,
                end: false,
            },
            Anchors {
                start: true,
                end: false,
            },
            Anchors {
                start: false,
                end: true,
            },
            Anchors {
                start: true,
                end: true,
            },
        ];
        let alphabet = [b'a', b'!', b'Z', 0xff];

        for class in classes {
            let scanner = dispatch
                .ascii_byte_set_run_scanner(class.ascii_set(), DispatchPolicy::Portable)
                .unwrap();
            for anchors in anchors {
                let plan = RequiredLiteralPlan::build(class, b"Z", anchors, BuildLimits::default())
                    .unwrap();
                for len in 0_u32..=5 {
                    for mut encoded in 0..alphabet.len().pow(len) {
                        let mut haystack = vec![0_u8; usize::try_from(len).unwrap()];
                        for byte in &mut haystack {
                            *byte = alphabet[encoded % alphabet.len()];
                            encoded /= alphabet.len();
                        }
                        for start in 0..=haystack.len() {
                            for end in start..=haystack.len() {
                                let window = Window::new(start, end);
                                let scalar = plan
                                    .find_window(&haystack, window, SearchLimits::unlimited())
                                    .unwrap();
                                let accelerated = plan
                                    .find_window_with_run_scanner(
                                        &haystack,
                                        window,
                                        SearchLimits::unlimited(),
                                        Some(&scanner),
                                    )
                                    .unwrap();
                                assert_eq!(
                                    accelerated.0, scalar.0,
                                    "class={class:?} anchors={anchors:?} haystack={haystack:?} window={start}..{end}"
                                );
                                assert_eq!(
                                    accelerated.1.candidate_visits,
                                    scalar.1.candidate_visits
                                );
                                assert_eq!(accelerated.1.finder_calls, scalar.1.finder_calls);
                                assert_eq!(
                                    accelerated.1.backward_bytes_examined,
                                    scalar.1.backward_bytes_examined
                                );
                                assert!(
                                    accelerated.1.backward_bytes_examined
                                        <= accelerated.1.backward_work_upper_bound
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn dispatched_limits_close_over_owner_and_per_candidate_overhead() {
        let dispatch = SimdDispatchContext::capture();
        let class = ascii_class();
        let permissive = BuildLimits {
            max_suffix_bytes: usize::MAX,
            max_build_work: u64::MAX,
            max_scratch_bytes: usize::MAX,
            max_persistent_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        };
        let baseline = RequiredLiteralPlan::build_with_dispatch(
            dispatch,
            class,
            b"Z",
            Anchors::default(),
            permissive,
        )
        .unwrap();
        let build = baseline.build_accounting();
        assert_eq!(
            build.persistent_bytes,
            size_of::<DispatchedRequiredLiteralPlan>() + 1
        );
        assert_eq!(
            build.peak_bytes,
            build.persistent_bytes + build.scratch_bytes
        );
        let exact = BuildLimits {
            max_suffix_bytes: build.suffix_bytes,
            max_build_work: build.work_upper_bound,
            max_scratch_bytes: build.scratch_bytes,
            max_persistent_bytes: build.persistent_bytes,
            max_peak_bytes: build.peak_bytes,
        };
        assert!(
            RequiredLiteralPlan::build_with_dispatch(
                dispatch,
                class,
                b"Z",
                Anchors::default(),
                exact
            )
            .is_ok()
        );
        assert!(matches!(
            RequiredLiteralPlan::build_with_dispatch(
                dispatch,
                class,
                b"Z",
                Anchors::default(),
                BuildLimits {
                    max_build_work: exact.max_build_work - 1,
                    ..exact
                }
            ),
            Err(BuildError::WorkLimit { .. })
        ));
        assert!(matches!(
            RequiredLiteralPlan::build_with_dispatch(
                dispatch,
                class,
                b"Z",
                Anchors::default(),
                BuildLimits {
                    max_persistent_bytes: exact.max_persistent_bytes - 1,
                    ..exact
                }
            ),
            Err(BuildError::PersistentLimit { .. })
        ));

        let mut haystack: Vec<u8> = ASCII_MEMBERS.iter().copied().cycle().take(65).collect();
        haystack.push(b'Z');
        let (_, search) = baseline.find(&haystack, SearchLimits::unlimited()).unwrap();
        assert!(search.backward_bytes_examined <= search.backward_work_upper_bound);
        let exact_search = SearchLimits {
            max_work_upper_bound: search.work_upper_bound,
            max_candidate_visits: search.candidate_visits_upper_bound,
            max_scratch_bytes: search.scratch_bytes,
        };
        assert!(baseline.find(&haystack, exact_search).is_ok());
        assert!(matches!(
            baseline.find(
                &haystack,
                SearchLimits {
                    max_work_upper_bound: search.work_upper_bound - 1,
                    ..exact_search
                }
            ),
            Err(SearchError::WorkLimit { .. })
        ));
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
    #[test]
    #[ignore = "native release qualification benchmark; requires OS-usable SVE"]
    #[allow(
        clippy::arithmetic_side_effects,
        clippy::too_many_lines,
        reason = "the ignored benchmark keeps alternating end-to-end samples and its authenticated receipt together"
    )]
    fn benchmark_required_literal_backward_scalar_against_auto() {
        use std::{hint::black_box, time::Instant};

        fn measure_scalar(
            plan: &RequiredLiteralPlan,
            haystack: &[u8],
            iterations: u32,
        ) -> (f64, usize) {
            let started = Instant::now();
            let mut checksum = 0_usize;
            for _ in 0..iterations {
                let (matched, accounting) = black_box(plan)
                    .find(black_box(haystack), SearchLimits::unlimited())
                    .unwrap();
                checksum ^= matched.map_or(0, |(_, end)| end.rotate_left(7))
                    ^ accounting.backward_bytes_examined;
            }
            black_box(checksum);
            (
                started.elapsed().as_secs_f64() * 1_000_000_000.0 / f64::from(iterations),
                checksum,
            )
        }

        fn measure_auto(
            plan: &DispatchedRequiredLiteralPlan,
            haystack: &[u8],
            iterations: u32,
        ) -> (f64, usize) {
            let started = Instant::now();
            let mut checksum = 0_usize;
            for _ in 0..iterations {
                let (matched, accounting) = black_box(plan)
                    .find(black_box(haystack), SearchLimits::unlimited())
                    .unwrap();
                checksum ^= matched.map_or(0, |(_, end)| end.rotate_left(7))
                    ^ accounting.backward_bytes_examined;
            }
            black_box(checksum);
            (
                started.elapsed().as_secs_f64() * 1_000_000_000.0 / f64::from(iterations),
                checksum,
            )
        }

        fn median(samples: &[f64]) -> f64 {
            let mut sorted = samples.to_vec();
            sorted.sort_by(f64::total_cmp);
            sorted[sorted.len() / 2]
        }

        fn serialize(samples: &[f64]) -> String {
            samples
                .iter()
                .map(|sample| format!("{sample:.9}"))
                .collect::<Vec<_>>()
                .join(",")
        }

        let dispatch = SimdDispatchContext::capture();
        assert!(
            dispatch.capabilities().usable().contains(Feature::ArmSve),
            "benchmark requires OS-usable SVE"
        );
        let class = ascii_class();
        let scalar =
            RequiredLiteralPlan::build(class, b"Z", Anchors::default(), BuildLimits::default())
                .unwrap();
        let auto = RequiredLiteralPlan::build_with_dispatch(
            dispatch,
            class,
            b"Z",
            Anchors::default(),
            BuildLimits::default(),
        )
        .unwrap();
        let candidate_variant = auto
            .run_scanner_selection()
            .expect("an SVE host retains an automatic backward scanner")
            .variant_id;
        let mut haystack: Vec<u8> = ASCII_MEMBERS
            .iter()
            .copied()
            .cycle()
            .take(256 << 10)
            .collect();
        haystack.push(b'Z');
        assert_eq!(
            scalar.find(&haystack, SearchLimits::unlimited()).unwrap().0,
            auto.find(&haystack, SearchLimits::unlimited()).unwrap().0
        );

        let iterations = std::env::var("FRE_REQUIRED_LITERAL_RUN_BENCH_ITERS").map_or(128, |raw| {
            raw.parse::<u32>()
                .unwrap_or_else(|error| panic!("FRE_REQUIRED_LITERAL_RUN_BENCH_ITERS: {error}"))
        });
        let samples = std::env::var("FRE_REQUIRED_LITERAL_RUN_BENCH_SAMPLES").map_or(16, |raw| {
            raw.parse::<usize>()
                .unwrap_or_else(|error| panic!("FRE_REQUIRED_LITERAL_RUN_BENCH_SAMPLES: {error}"))
        });
        assert!(iterations > 0);
        assert!(samples >= 16 && samples.is_multiple_of(2));
        let _ = measure_scalar(&scalar, &haystack, iterations / 8 + 1);
        let _ = measure_auto(&auto, &haystack, iterations / 8 + 1);

        let mut scalar_samples = Vec::with_capacity(samples);
        let mut auto_samples = Vec::with_capacity(samples);
        let mut orders = Vec::with_capacity(samples);
        for sample in 0..samples {
            if sample & 1 == 0 {
                scalar_samples.push(measure_scalar(&scalar, &haystack, iterations).0);
                auto_samples.push(measure_auto(&auto, &haystack, iterations).0);
                orders.push("scalar>auto");
            } else {
                auto_samples.push(measure_auto(&auto, &haystack, iterations).0);
                scalar_samples.push(measure_scalar(&scalar, &haystack, iterations).0);
                orders.push("auto>scalar");
            }
        }
        let scalar_median = median(&scalar_samples);
        let auto_median = median(&auto_samples);
        let receipt = format!(
            "REQUIRED_LITERAL_BACKWARD_RUN_BENCH iterations={iterations} samples={samples} \
             bytes={} candidate_variant={candidate_variant} scalar_ns={scalar_median:.9} \
             auto_ns={auto_median:.9} auto_over_scalar={:.9} orders={} \
             scalar_samples={} auto_samples={}",
            haystack.len(),
            auto_median / scalar_median,
            orders.join(","),
            serialize(&scalar_samples),
            serialize(&auto_samples),
        );
        assert_eq!(receipt.matches('\n').count(), 0);
        eprintln!("{receipt}");
    }
}
