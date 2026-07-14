//! Forward boundary search for `\A CLASS+ SUFFIX (?:\z)?`.
//!
//! The proof is deliberately separate from the required-literal candidate.
//! Absolute start fixes the repetition start at byte zero. Because the first
//! suffix byte is outside `CLASS`, the first non-class byte is the only
//! possible repetition boundary. Suffix borders are therefore irrelevant.
//! Search is worst-case linear and allocates no memory.

use core::{fmt, mem::size_of};

use memchr::memchr;

use crate::Window;

/// Stable identity of this exact proof and execution strategy.
pub const PLAN_ID: &str = "anchored-class-suffix.forward.v1";

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
            class.insert(byte);
        }
        class
    }

    /// Add one inclusive byte range to this class.
    pub fn insert_inclusive(&mut self, start: u8, end: u8) {
        if start > end {
            return;
        }
        for byte in start..=end {
            self.insert(byte);
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

    fn insert(&mut self, byte: u8) {
        let word = usize::from(byte) >> 6;
        let bit = u32::from(byte) & 63;
        self.words[word] |= 1_u64 << bit;
    }

    fn single_inclusive_range(self) -> Option<(u8, u8)> {
        let first_word = self.words.iter().position(|&word| word != 0)?;
        let last_word = self.words.iter().rposition(|&word| word != 0)?;
        let first_bit = usize::try_from(self.words[first_word].trailing_zeros()).ok()?;
        let last_bit =
            63_usize.checked_sub(usize::try_from(self.words[last_word].leading_zeros()).ok()?)?;
        let first = first_word.checked_mul(64)?.checked_add(first_bit)?;
        let last = last_word.checked_mul(64)?.checked_add(last_bit)?;
        let span = last.checked_sub(first)?.checked_add(1)?;
        if self.cardinality() != span {
            return None;
        }
        Some((u8::try_from(first).ok()?, u8::try_from(last).ok()?))
    }

    fn canonical_members<const N: usize>(self) -> Option<[u8; N]> {
        let mut members = [0_u8; N];
        let mut member_count = 0_usize;
        for (word_index, &word) in self.words.iter().enumerate() {
            let mut remaining = word;
            while remaining != 0 {
                if member_count == N {
                    return None;
                }
                let bit_index = usize::try_from(remaining.trailing_zeros()).ok()?;
                let byte_index = word_index.checked_mul(64)?.checked_add(bit_index)?;
                members[member_count] = u8::try_from(byte_index).ok()?;
                member_count = member_count.checked_add(1)?;
                remaining &= remaining.wrapping_sub(1);
            }
        }
        (member_count == N).then_some(members)
    }
}

/// Absolute anchors interpreted against the original haystack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Anchors {
    /// Must be true for this theorem.
    pub start: bool,
    /// Require the selected match to end at the original haystack length.
    pub end: bool,
}

/// The selected safe prefix-membership implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClassImplementation {
    /// Arbitrary 256-bit class membership floor.
    Bitset,
    /// One inclusive range, scanned in fixed blocks before a scalar tail.
    InclusiveRange { start: u8, end: u8 },
    /// Two canonical, ascending members scanned with a fixed equality network.
    Pair { first: u8, second: u8 },
    /// Three canonical, ascending members scanned with a fixed equality network.
    Triple { first: u8, second: u8, third: u8 },
    /// Four canonical, ascending members scanned with a fixed equality network.
    Quad {
        first: u8,
        second: u8,
        third: u8,
        fourth: u8,
    },
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
            max_build_work: 128 * 1024 * 1024,
            max_scratch_bytes: 0,
            max_persistent_bytes: 64 * 1024 * 1024,
            max_peak_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Limits checked before scanning any haystack byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchLimits {
    pub max_work_upper_bound: u64,
    pub max_examined_bytes_upper_bound: usize,
    pub max_scratch_bytes: usize,
}

impl SearchLimits {
    /// Disable caller-selected caps while retaining checked arithmetic.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_work_upper_bound: u64::MAX,
            max_examined_bytes_upper_bound: usize::MAX,
            max_scratch_bytes: usize::MAX,
        }
    }
}

impl Default for SearchLimits {
    fn default() -> Self {
        Self {
            max_work_upper_bound: 256 * 1024 * 1024,
            max_examined_bytes_upper_bound: 256 * 1024 * 1024,
            max_scratch_bytes: 0,
        }
    }
}

/// Auditable construction certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub suffix_bytes: usize,
    /// Actual retained allocation capacity after `try_reserve_exact`.
    pub suffix_capacity_bytes: usize,
    pub class_cardinality: usize,
    pub implementation: ClassImplementation,
    pub work_upper_bound: u64,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Auditable search certificate and structural counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchAccounting {
    pub window_bytes: usize,
    pub implementation: ClassImplementation,
    pub prefilter_bytes_upper_bound: usize,
    pub prefix_bytes_upper_bound: usize,
    pub suffix_bytes_upper_bound: usize,
    pub examined_bytes_upper_bound: usize,
    pub work_upper_bound: u64,
    pub scratch_bytes: usize,
    pub prefilter_calls: usize,
    pub prefix_bytes_examined: usize,
    pub suffix_confirmation_attempted: bool,
}

/// A semantic refusal or checked construction-resource failure.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    MissingAbsoluteStart,
    EmptyClass,
    EmptySuffix,
    FirstSuffixByteInClass {
        byte: u8,
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
            Self::MissingAbsoluteStart
                | Self::EmptyClass
                | Self::EmptySuffix
                | Self::FirstSuffixByteInClass { .. }
        )
    }
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingAbsoluteStart => {
                f.write_str("forward anchored plan requires absolute start")
            }
            Self::EmptyClass => f.write_str("forward anchored class is empty"),
            Self::EmptySuffix => f.write_str("forward anchored suffix is empty"),
            Self::FirstSuffixByteInClass { byte } => write!(
                f,
                "suffix first byte 0x{byte:02X} belongs to the preceding class"
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
    ExaminedBytesLimit {
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
                "forward anchored window {start}..{end} is invalid for {haystack_len} bytes"
            ),
            Self::ExaminedBytesLimit { needed, limit } => write!(
                f,
                "search may examine {needed} byte positions, exceeding {limit}"
            ),
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

/// Immutable, deliberately non-`Clone` plan for the unique forward boundary.
#[derive(Debug)]
pub struct ForwardAnchoredPlan {
    class: ByteClass,
    suffix: Vec<u8>,
    anchors: Anchors,
    implementation: ClassImplementation,
    build: BuildAccounting,
}

impl ForwardAnchoredPlan {
    /// Prove eligibility and copy the fixed suffix.
    ///
    /// # Errors
    ///
    /// Returns a typed proof refusal or checked resource failure. It never
    /// substitutes a different search plan.
    #[allow(
        clippy::too_many_lines,
        reason = "construction keeps proof refusals and every resource boundary explicit"
    )]
    pub fn build(
        class: ByteClass,
        suffix: &[u8],
        anchors: Anchors,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        if !anchors.start {
            return Err(BuildError::MissingAbsoluteStart);
        }
        if class.is_empty() {
            return Err(BuildError::EmptyClass);
        }
        let Some(&first) = suffix.first() else {
            return Err(BuildError::EmptySuffix);
        };
        if class.contains(first) {
            return Err(BuildError::FirstSuffixByteInClass { byte: first });
        }

        let class_cardinality = class.cardinality();
        let implementation =
            match class.single_inclusive_range() {
                Some((start, end)) => ClassImplementation::InclusiveRange { start, end },
                None => match class_cardinality {
                    2 => {
                        let [first, second] = class.canonical_members::<2>().ok_or(
                            BuildError::ArithmeticOverflow {
                                computation: "canonical pair extraction",
                            },
                        )?;
                        ClassImplementation::Pair { first, second }
                    }
                    3 => {
                        let [first, second, third] = class.canonical_members::<3>().ok_or(
                            BuildError::ArithmeticOverflow {
                                computation: "canonical triple extraction",
                            },
                        )?;
                        ClassImplementation::Triple {
                            first,
                            second,
                            third,
                        }
                    }
                    4 => {
                        let [first, second, third, fourth] = class.canonical_members::<4>().ok_or(
                            BuildError::ArithmeticOverflow {
                                computation: "canonical quad extraction",
                            },
                        )?;
                        ClassImplementation::Quad {
                            first,
                            second,
                            third,
                            fourth,
                        }
                    }
                    _ => ClassImplementation::Bitset,
                },
            };
        let suffix_u64 =
            u64::try_from(suffix.len()).map_err(|_| BuildError::ArithmeticOverflow {
                computation: "suffix length as u64",
            })?;
        let work_upper_bound = suffix_u64
            .checked_mul(2)
            .and_then(|work| work.checked_add(64))
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "build work upper bound",
            })?;
        let scratch_bytes = 0_usize;
        let persistent_lower_bound =
            size_of::<Self>()
                .checked_add(suffix.len())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "persistent plan lower bound",
                })?;
        let peak_lower_bound = persistent_lower_bound.checked_add(scratch_bytes).ok_or(
            BuildError::ArithmeticOverflow {
                computation: "construction peak lower bound",
            },
        )?;

        if suffix.len() > limits.max_suffix_bytes {
            return Err(BuildError::SuffixLimit {
                needed: suffix.len(),
                limit: limits.max_suffix_bytes,
            });
        }
        if work_upper_bound > limits.max_build_work {
            return Err(BuildError::WorkLimit {
                needed: work_upper_bound,
                limit: limits.max_build_work,
            });
        }
        if scratch_bytes > limits.max_scratch_bytes {
            return Err(BuildError::ScratchLimit {
                needed: scratch_bytes,
                limit: limits.max_scratch_bytes,
            });
        }
        if persistent_lower_bound > limits.max_persistent_bytes {
            return Err(BuildError::PersistentLimit {
                needed: persistent_lower_bound,
                limit: limits.max_persistent_bytes,
            });
        }
        if peak_lower_bound > limits.max_peak_bytes {
            return Err(BuildError::PeakLimit {
                needed: peak_lower_bound,
                limit: limits.max_peak_bytes,
            });
        }

        let mut owned_suffix = Vec::new();
        owned_suffix
            .try_reserve_exact(suffix.len())
            .map_err(|_| BuildError::AllocationFailed {
                structure: "forward anchored suffix",
                additional: suffix.len(),
            })?;
        owned_suffix.extend_from_slice(suffix);
        let persistent_bytes = size_of::<Self>()
            .checked_add(owned_suffix.capacity())
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "persistent plan bytes from allocated capacity",
            })?;
        let peak_bytes =
            persistent_bytes
                .checked_add(scratch_bytes)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "construction peak bytes from allocated capacity",
                })?;
        if persistent_bytes > limits.max_persistent_bytes {
            return Err(BuildError::PersistentLimit {
                needed: persistent_bytes,
                limit: limits.max_persistent_bytes,
            });
        }
        if peak_bytes > limits.max_peak_bytes {
            return Err(BuildError::PeakLimit {
                needed: peak_bytes,
                limit: limits.max_peak_bytes,
            });
        }
        let suffix_capacity_bytes = owned_suffix.capacity();
        Ok(Self {
            class,
            suffix: owned_suffix,
            anchors,
            implementation,
            build: BuildAccounting {
                suffix_bytes: suffix.len(),
                suffix_capacity_bytes,
                class_cardinality,
                implementation,
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
        &self.suffix
    }

    #[must_use]
    pub const fn implementation(&self) -> ClassImplementation {
        self.implementation
    }

    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.build
    }

    /// Find the selected span in the full haystack.
    ///
    /// # Errors
    ///
    /// Returns a checked resource failure before scanning begins.
    #[inline]
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
    #[inline]
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
        if window.start() != 0 || (self.anchors.end && window.end() != haystack.len()) {
            let window_bytes = window.end().checked_sub(window.start()).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "impossible anchored window bytes",
                },
            )?;
            return Ok((None, zero_accounting(window_bytes, self.implementation)));
        }

        let mut accounting = self.preflight(window, limits)?;
        let searched = &haystack[..window.end()];
        let boundary = if searched.len() < RANGE_BLOCK {
            let (boundary, examined) = self.scan_prefix(searched)?;
            accounting.prefix_bytes_examined = examined;
            if boundary == 0 || boundary == searched.len() {
                return Ok((None, accounting));
            }
            boundary
        } else {
            let Some(&first_byte) = searched.first() else {
                return Ok((None, accounting));
            };
            accounting.prefix_bytes_examined = 1;
            if !self.class.contains(first_byte) {
                return Ok((None, accounting));
            }
            accounting.prefilter_calls = 1;
            let Some(relative_candidate) = memchr(self.suffix[0], &searched[1..]) else {
                return Ok((None, accounting));
            };
            let candidate =
                relative_candidate
                    .checked_add(1)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "native prefilter candidate",
                    })?;
            // `candidate` is already known to contain `suffix[0]`, which is
            // outside the class by construction. Validate only the prefix
            // before it so a valid candidate never enters failed-block
            // recovery merely to rediscover that known boundary.
            let (boundary, examined) = self.scan_prefix(&searched[..candidate])?;
            accounting.prefix_bytes_examined = accounting
                .prefix_bytes_examined
                .checked_add(examined)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "actual prefix examinations",
                })?;
            if boundary != candidate {
                return Ok((None, accounting));
            }
            boundary
        };

        let end =
            boundary
                .checked_add(self.suffix.len())
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "selected match end",
                })?;
        if end > window.end() {
            return Ok((None, accounting));
        }
        accounting.suffix_confirmation_attempted = true;
        if haystack.get(boundary..end) != Some(self.suffix()) {
            return Ok((None, accounting));
        }
        if self.anchors.end && end != haystack.len() {
            return Ok((None, accounting));
        }
        Ok((Some((0, end)), accounting))
    }

    fn scan_prefix(&self, bytes: &[u8]) -> Result<(usize, usize), SearchError> {
        match self.implementation {
            ClassImplementation::Bitset => Ok(scan_bitset_prefix(bytes, self.class)),
            ClassImplementation::InclusiveRange { start, end } => {
                scan_range_prefix(bytes, start, end)
            }
            ClassImplementation::Pair { first, second } => scan_pair_prefix(bytes, first, second),
            ClassImplementation::Triple {
                first,
                second,
                third,
            } => scan_triple_prefix(bytes, first, second, third),
            ClassImplementation::Quad {
                first,
                second,
                third,
                fourth,
            } => scan_quad_prefix(bytes, first, second, third, fourth),
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
        let uses_prefilter = window_bytes >= RANGE_BLOCK;
        let block_scanner = matches!(
            self.implementation,
            ClassImplementation::InclusiveRange { .. }
                | ClassImplementation::Pair { .. }
                | ClassImplementation::Triple { .. }
                | ClassImplementation::Quad { .. }
        );
        let rescan_margin = if block_scanner && window_bytes >= RANGE_BLOCK {
            RANGE_BLOCK
        } else {
            0
        };
        let prefilter_bytes_upper_bound = if uses_prefilter {
            window_bytes.saturating_sub(1)
        } else {
            0
        };
        let prefix_bytes_upper_bound =
            window_bytes
                .checked_add(rescan_margin)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "prefix examinations upper bound",
                })?;
        let suffix_bytes_upper_bound = self.suffix.len().min(window_bytes);
        let examined_bytes_upper_bound = prefilter_bytes_upper_bound
            .checked_add(prefix_bytes_upper_bound)
            .and_then(|value| value.checked_add(suffix_bytes_upper_bound))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "examined bytes upper bound",
            })?;
        let work_upper_bound = u64::try_from(examined_bytes_upper_bound).map_err(|_| {
            SearchError::ArithmeticOverflow {
                computation: "search work upper bound",
            }
        })?;
        let scratch_bytes = 0_usize;
        if examined_bytes_upper_bound > limits.max_examined_bytes_upper_bound {
            return Err(SearchError::ExaminedBytesLimit {
                needed: examined_bytes_upper_bound,
                limit: limits.max_examined_bytes_upper_bound,
            });
        }
        if work_upper_bound > limits.max_work_upper_bound {
            return Err(SearchError::WorkLimit {
                needed: work_upper_bound,
                limit: limits.max_work_upper_bound,
            });
        }
        if scratch_bytes > limits.max_scratch_bytes {
            return Err(SearchError::ScratchLimit {
                needed: scratch_bytes,
                limit: limits.max_scratch_bytes,
            });
        }
        Ok(SearchAccounting {
            window_bytes,
            implementation: self.implementation,
            prefilter_bytes_upper_bound,
            prefix_bytes_upper_bound,
            suffix_bytes_upper_bound,
            examined_bytes_upper_bound,
            work_upper_bound,
            scratch_bytes,
            prefilter_calls: 0,
            prefix_bytes_examined: 0,
            suffix_confirmation_attempted: false,
        })
    }
}

fn zero_accounting(window_bytes: usize, implementation: ClassImplementation) -> SearchAccounting {
    SearchAccounting {
        window_bytes,
        implementation,
        prefilter_bytes_upper_bound: 0,
        prefix_bytes_upper_bound: 0,
        suffix_bytes_upper_bound: 0,
        examined_bytes_upper_bound: 0,
        work_upper_bound: 0,
        scratch_bytes: 0,
        prefilter_calls: 0,
        prefix_bytes_examined: 0,
        suffix_confirmation_attempted: false,
    }
}

fn scan_bitset_prefix(bytes: &[u8], class: ByteClass) -> (usize, usize) {
    let boundary = bytes
        .iter()
        .position(|&byte| !class.contains(byte))
        .unwrap_or(bytes.len());
    let examined = boundary.saturating_add(usize::from(boundary < bytes.len()));
    (boundary, examined)
}

/// Fixed blocks expose branch-free membership reductions to LLVM. These are
/// safe scalar source loops, not SIMD claims; retained assembly decides which
/// label is justified for a particular compiler/target stamp.
const RANGE_BLOCK: usize = 32;

fn scan_pair_prefix(bytes: &[u8], first: u8, second: u8) -> Result<(usize, usize), SearchError> {
    let mut consumed = 0_usize;
    let mut blocks = bytes.chunks_exact(RANGE_BLOCK);
    for block in &mut blocks {
        let (low, high) = block.split_at(RANGE_BLOCK / 2);
        let low_outside = low.iter().fold(0_u8, |outside, &byte| {
            let inside = u8::from(byte == first) | u8::from(byte == second);
            outside | (inside ^ 1)
        });
        let high_outside = high.iter().fold(0_u8, |outside, &byte| {
            let inside = u8::from(byte == first) | u8::from(byte == second);
            outside | (inside ^ 1)
        });
        if low_outside | high_outside != 0 {
            let within_block = block
                .iter()
                .position(|&byte| byte != first && byte != second)
                .unwrap_or(RANGE_BLOCK);
            let boundary =
                consumed
                    .checked_add(within_block)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "pair boundary",
                    })?;
            let examined = consumed
                .checked_add(RANGE_BLOCK)
                .and_then(|value| value.checked_add(within_block))
                .and_then(|value| value.checked_add(1))
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "failed pair block examinations",
                })?;
            return Ok((boundary, examined));
        }
        consumed = consumed
            .checked_add(RANGE_BLOCK)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "completed pair blocks",
            })?;
    }
    let remainder = blocks.remainder();
    let within_remainder = remainder
        .iter()
        .position(|&byte| byte != first && byte != second)
        .unwrap_or(remainder.len());
    let boundary =
        consumed
            .checked_add(within_remainder)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "pair remainder boundary",
            })?;
    let examined = boundary
        .checked_add(usize::from(within_remainder < remainder.len()))
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "pair remainder examinations",
        })?;
    Ok((boundary, examined))
}

fn scan_triple_prefix(
    bytes: &[u8],
    first: u8,
    second: u8,
    third: u8,
) -> Result<(usize, usize), SearchError> {
    let mut consumed = 0_usize;
    let mut blocks = bytes.chunks_exact(RANGE_BLOCK);
    for block in &mut blocks {
        let (low, high) = block.split_at(RANGE_BLOCK / 2);
        let low_outside = low.iter().fold(0_u8, |outside, &byte| {
            let inside =
                u8::from(byte == first) | u8::from(byte == second) | u8::from(byte == third);
            outside | (inside ^ 1)
        });
        let high_outside = high.iter().fold(0_u8, |outside, &byte| {
            let inside =
                u8::from(byte == first) | u8::from(byte == second) | u8::from(byte == third);
            outside | (inside ^ 1)
        });
        if low_outside | high_outside != 0 {
            let within_block = block
                .iter()
                .position(|&byte| byte != first && byte != second && byte != third)
                .unwrap_or(RANGE_BLOCK);
            let boundary =
                consumed
                    .checked_add(within_block)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "triple boundary",
                    })?;
            let examined = consumed
                .checked_add(RANGE_BLOCK)
                .and_then(|value| value.checked_add(within_block))
                .and_then(|value| value.checked_add(1))
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "failed triple block examinations",
                })?;
            return Ok((boundary, examined));
        }
        consumed = consumed
            .checked_add(RANGE_BLOCK)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "completed triple blocks",
            })?;
    }
    let remainder = blocks.remainder();
    let within_remainder = remainder
        .iter()
        .position(|&byte| byte != first && byte != second && byte != third)
        .unwrap_or(remainder.len());
    let boundary =
        consumed
            .checked_add(within_remainder)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "triple remainder boundary",
            })?;
    let examined = boundary
        .checked_add(usize::from(within_remainder < remainder.len()))
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "triple remainder examinations",
        })?;
    Ok((boundary, examined))
}

fn scan_quad_prefix(
    bytes: &[u8],
    first: u8,
    second: u8,
    third: u8,
    fourth: u8,
) -> Result<(usize, usize), SearchError> {
    let mut consumed = 0_usize;
    let mut blocks = bytes.chunks_exact(RANGE_BLOCK);
    for block in &mut blocks {
        let (low, high) = block.split_at(RANGE_BLOCK / 2);
        let low_outside = low.iter().fold(0_u8, |outside, &byte| {
            let inside = u8::from(byte == first)
                | u8::from(byte == second)
                | u8::from(byte == third)
                | u8::from(byte == fourth);
            outside | (inside ^ 1)
        });
        let high_outside = high.iter().fold(0_u8, |outside, &byte| {
            let inside = u8::from(byte == first)
                | u8::from(byte == second)
                | u8::from(byte == third)
                | u8::from(byte == fourth);
            outside | (inside ^ 1)
        });
        if low_outside | high_outside != 0 {
            let within_block = block
                .iter()
                .position(|&byte| {
                    byte != first && byte != second && byte != third && byte != fourth
                })
                .unwrap_or(RANGE_BLOCK);
            let boundary =
                consumed
                    .checked_add(within_block)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "quad boundary",
                    })?;
            let examined = consumed
                .checked_add(RANGE_BLOCK)
                .and_then(|value| value.checked_add(within_block))
                .and_then(|value| value.checked_add(1))
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "failed quad block examinations",
                })?;
            return Ok((boundary, examined));
        }
        consumed = consumed
            .checked_add(RANGE_BLOCK)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "completed quad blocks",
            })?;
    }
    let remainder = blocks.remainder();
    let within_remainder = remainder
        .iter()
        .position(|&byte| byte != first && byte != second && byte != third && byte != fourth)
        .unwrap_or(remainder.len());
    let boundary =
        consumed
            .checked_add(within_remainder)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "quad remainder boundary",
            })?;
    let examined = boundary
        .checked_add(usize::from(within_remainder < remainder.len()))
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "quad remainder examinations",
        })?;
    Ok((boundary, examined))
}

fn scan_range_prefix(bytes: &[u8], start: u8, end: u8) -> Result<(usize, usize), SearchError> {
    let width = end.wrapping_sub(start);
    let mut consumed = 0_usize;
    let mut blocks = bytes.chunks_exact(RANGE_BLOCK);
    for block in &mut blocks {
        let (low, high) = block.split_at(RANGE_BLOCK / 2);
        let low_outside = low.iter().fold(0_u8, |count, &byte| {
            count | u8::from(byte.wrapping_sub(start) > width)
        });
        let high_outside = high.iter().fold(0_u8, |count, &byte| {
            count | u8::from(byte.wrapping_sub(start) > width)
        });
        if low_outside | high_outside != 0 {
            let within_block = block
                .iter()
                .position(|&byte| byte.wrapping_sub(start) > width)
                .unwrap_or(RANGE_BLOCK);
            let boundary =
                consumed
                    .checked_add(within_block)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "range boundary",
                    })?;
            let examined = consumed
                .checked_add(RANGE_BLOCK)
                .and_then(|value| value.checked_add(within_block))
                .and_then(|value| value.checked_add(1))
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "failed block examinations",
                })?;
            return Ok((boundary, examined));
        }
        consumed = consumed
            .checked_add(RANGE_BLOCK)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "completed range blocks",
            })?;
    }
    let remainder = blocks.remainder();
    let within_remainder = remainder
        .iter()
        .position(|&byte| byte.wrapping_sub(start) > width)
        .unwrap_or(remainder.len());
    let boundary =
        consumed
            .checked_add(within_remainder)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "range remainder boundary",
            })?;
    let examined = boundary
        .checked_add(usize::from(within_remainder < remainder.len()))
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "range remainder examinations",
        })?;
    Ok((boundary, examined))
}

#[cfg(test)]
mod tests {
    use super::{
        Anchors, BuildError, BuildLimits, ByteClass, ClassImplementation, ForwardAnchoredPlan,
        SearchError, SearchLimits,
    };
    use crate::Window;

    fn plan(class: ByteClass, suffix: &[u8], end: bool) -> ForwardAnchoredPlan {
        ForwardAnchoredPlan::build(
            class,
            suffix,
            Anchors { start: true, end },
            BuildLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn theorem_accepts_bordered_suffix_and_rejects_disjointness_failures() {
        let bordered = plan(ByteClass::from_bytes(b"b"), b"aba", false);
        assert_eq!(
            bordered
                .find(b"bbbaba", SearchLimits::unlimited())
                .unwrap()
                .0,
            Some((0, 6))
        );
        assert!(matches!(
            ForwardAnchoredPlan::build(
                ByteClass::from_bytes(b"a"),
                b"aba",
                Anchors {
                    start: true,
                    end: false
                },
                BuildLimits::default()
            ),
            Err(BuildError::FirstSuffixByteInClass { byte: b'a' })
        ));
        assert!(matches!(
            ForwardAnchoredPlan::build(
                ByteClass::from_bytes(b"a"),
                b"Z",
                Anchors {
                    start: false,
                    end: false
                },
                BuildLimits::default()
            ),
            Err(BuildError::MissingAbsoluteStart)
        ));
    }

    #[test]
    fn selects_canonical_small_sets_and_unchanged_floors() {
        let range = plan(ByteClass::inclusive(b'a', b'z'), b"Z", false);
        assert_eq!(
            range.implementation(),
            ClassImplementation::InclusiveRange {
                start: b'a',
                end: b'z'
            }
        );
        let contiguous_pair = plan(ByteClass::from_bytes(b"baa"), b"Z", false);
        assert_eq!(
            contiguous_pair.implementation(),
            ClassImplementation::InclusiveRange {
                start: b'a',
                end: b'b'
            }
        );

        let pair = plan(ByteClass::from_bytes(b" \t \t"), b"Z", false);
        assert_eq!(
            pair.implementation(),
            ClassImplementation::Pair {
                first: b'\t',
                second: b' '
            }
        );
        let triple = plan(
            ByteClass::from_bytes(&[0xFF, 0x80, 0x00, 0xFF]),
            b"Z",
            false,
        );
        assert_eq!(
            triple.implementation(),
            ClassImplementation::Triple {
                first: 0x00,
                second: 0x80,
                third: 0xFF
            }
        );
        let quad = plan(ByteClass::from_bytes(b"geacg"), b"Z", false);
        assert_eq!(
            quad.implementation(),
            ClassImplementation::Quad {
                first: b'a',
                second: b'c',
                third: b'e',
                fourth: b'g'
            }
        );

        let bitset = plan(
            ByteClass::from_bytes(&[0x00, 0x02, 0x04, 0x80, 0xFF]),
            b"Z",
            false,
        );
        assert_eq!(bitset.implementation(), ClassImplementation::Bitset);
        assert_eq!(
            bitset
                .find(&[0, 2, 4, 0x80, 0xFF, b'Z'], SearchLimits::unlimited())
                .unwrap()
                .0,
            Some((0, 6))
        );
    }

    #[test]
    fn empty_one_byte_mismatch_and_anchor_cases_are_exact() {
        let start_only = plan(ByteClass::from_bytes(b"a"), b"Z", false);
        for (haystack, expected) in [
            (b"".as_slice(), None),
            (b"a".as_slice(), None),
            (b"Z".as_slice(), None),
            (b"aZ".as_slice(), Some((0, 2))),
            (b"aaQ".as_slice(), None),
            (b"aaZZ".as_slice(), Some((0, 3))),
        ] {
            assert_eq!(
                start_only
                    .find(haystack, SearchLimits::unlimited())
                    .unwrap()
                    .0,
                expected
            );
        }
        let both = plan(ByteClass::from_bytes(b"a"), b"Z", true);
        assert_eq!(
            both.find(b"aaZZ", SearchLimits::unlimited()).unwrap().0,
            None
        );
        assert_eq!(
            both.find(b"aaZ", SearchLimits::unlimited()).unwrap().0,
            Some((0, 3))
        );
    }

    #[test]
    fn windows_keep_original_anchor_context_and_validate_first() {
        let start_only = plan(ByteClass::from_bytes(b"a"), b"Z", false);
        assert_eq!(
            start_only
                .find_window(b"aaZx", Window::new(1, 3), SearchLimits::unlimited())
                .unwrap()
                .0,
            None
        );
        assert_eq!(
            start_only
                .find_window(b"aaZx", Window::new(0, 3), SearchLimits::unlimited())
                .unwrap()
                .0,
            Some((0, 3))
        );
        let both = plan(ByteClass::from_bytes(b"a"), b"Z", true);
        assert_eq!(
            both.find_window(b"aaZx", Window::new(0, 3), SearchLimits::unlimited())
                .unwrap()
                .0,
            None
        );
        assert!(matches!(
            both.find_window(b"aaZx", Window::new(3, 2), SearchLimits::unlimited()),
            Err(SearchError::InvalidWindow { .. })
        ));
        assert!(matches!(
            both.find_window(b"aaZx", Window::new(0, 5), SearchLimits::unlimited()),
            Err(SearchError::InvalidWindow { .. })
        ));
    }

    #[test]
    fn every_nonzero_build_limit_has_exact_and_one_below_behavior() {
        let baseline = plan(ByteClass::from_bytes(b"a"), b"borderedaba", false);
        let accounting = baseline.build_accounting();
        let exact = BuildLimits {
            max_suffix_bytes: accounting.suffix_bytes,
            max_build_work: accounting.work_upper_bound,
            max_scratch_bytes: accounting.scratch_bytes,
            max_persistent_bytes: accounting.persistent_bytes,
            max_peak_bytes: accounting.peak_bytes,
        };
        assert!(
            ForwardAnchoredPlan::build(
                ByteClass::from_bytes(b"a"),
                b"borderedaba",
                Anchors {
                    start: true,
                    end: false
                },
                exact
            )
            .is_ok()
        );
        for limits in [
            BuildLimits {
                max_suffix_bytes: accounting.suffix_bytes - 1,
                ..exact
            },
            BuildLimits {
                max_build_work: accounting.work_upper_bound - 1,
                ..exact
            },
            BuildLimits {
                max_persistent_bytes: accounting.persistent_bytes - 1,
                ..exact
            },
            BuildLimits {
                max_peak_bytes: accounting.peak_bytes - 1,
                ..exact
            },
        ] {
            assert!(
                ForwardAnchoredPlan::build(
                    ByteClass::from_bytes(b"a"),
                    b"borderedaba",
                    Anchors {
                        start: true,
                        end: false
                    },
                    limits
                )
                .is_err()
            );
        }
        assert_eq!(accounting.scratch_bytes, 0);
    }

    #[test]
    fn search_limits_are_checked_before_scanning() {
        let plan = plan(ByteClass::from_bytes(b"a"), b"Z", false);
        let (_, accounting) = plan.find(b"aaaaZ", SearchLimits::unlimited()).unwrap();
        let exact = SearchLimits {
            max_work_upper_bound: accounting.work_upper_bound,
            max_examined_bytes_upper_bound: accounting.examined_bytes_upper_bound,
            max_scratch_bytes: accounting.scratch_bytes,
        };
        assert!(plan.find(b"aaaaZ", exact).is_ok());
        assert!(matches!(
            plan.find(
                b"aaaaZ",
                SearchLimits {
                    max_work_upper_bound: accounting.work_upper_bound - 1,
                    ..exact
                }
            ),
            Err(SearchError::WorkLimit { .. })
        ));
        assert!(matches!(
            plan.find(
                b"aaaaZ",
                SearchLimits {
                    max_examined_bytes_upper_bound: accounting.examined_bytes_upper_bound - 1,
                    ..exact
                }
            ),
            Err(SearchError::ExaminedBytesLimit { .. })
        ));
        assert_eq!(accounting.scratch_bytes, 0);
    }

    #[test]
    fn late_full_block_mismatch_charges_the_rescan_before_execution() {
        let plan = plan(ByteClass::inclusive(b'a', b'z'), b"Z", false);
        let mut haystack = vec![b'a'; 64];
        haystack[31] = b'!';
        haystack[63] = b'Z';
        let (_, accounting) = plan.find(&haystack, SearchLimits::unlimited()).unwrap();
        assert_eq!(accounting.prefilter_calls, 1);
        assert_eq!(accounting.prefix_bytes_examined, 65);
        assert_eq!(
            accounting.prefix_bytes_upper_bound,
            haystack.len().checked_add(32).unwrap()
        );
        assert!(accounting.prefix_bytes_examined <= accounting.prefix_bytes_upper_bound);

        let exact = SearchLimits {
            max_work_upper_bound: accounting.work_upper_bound,
            max_examined_bytes_upper_bound: accounting.examined_bytes_upper_bound,
            max_scratch_bytes: 0,
        };
        assert!(plan.find(&haystack, exact).is_ok());
        assert!(matches!(
            plan.find(
                &haystack,
                SearchLimits {
                    max_examined_bytes_upper_bound: accounting.examined_bytes_upper_bound - 1,
                    ..exact
                }
            ),
            Err(SearchError::ExaminedBytesLimit { .. })
        ));
    }

    #[test]
    fn small_set_scanners_cover_block_lanes_tails_and_arbitrary_bytes() {
        let cases: [(ByteClass, &[u8]); 3] = [
            (ByteClass::from_bytes(&[0x00, 0x80]), &[0x00, 0x80]),
            (
                ByteClass::from_bytes(&[0x00, 0x80, 0xFF]),
                &[0x00, 0x80, 0xFF],
            ),
            (
                ByteClass::from_bytes(&[0x00, 0x02, 0x80, 0xFF]),
                &[0x00, 0x02, 0x80, 0xFF],
            ),
        ];
        let lengths = [0_usize, 1, 15, 16, 31, 32, 33, 63, 64, 65];
        for (class, members) in cases {
            let plan = plan(class, b"Z", false);
            for length in lengths {
                let all_members: Vec<u8> = (0..length)
                    .map(|index| members[index % members.len()])
                    .collect();
                assert_eq!(plan.scan_prefix(&all_members).unwrap(), (length, length));
            }

            for block_start in [0_usize, 32] {
                for lane in [0_usize, 15, 16, 31] {
                    let outsider = block_start.checked_add(lane).unwrap();
                    let mut bytes = vec![0x00; 65];
                    bytes[outsider] = b'Z';
                    let expected_examined = block_start
                        .checked_add(32)
                        .and_then(|value| value.checked_add(lane))
                        .and_then(|value| value.checked_add(1))
                        .unwrap();
                    assert_eq!(
                        plan.scan_prefix(&bytes).unwrap(),
                        (outsider, expected_examined)
                    );
                }
            }
        }
    }

    #[test]
    fn pair_triple_and_quad_confirm_suffix_at_the_first_outsider() {
        for class in [
            ByteClass::from_bytes(b"ac"),
            ByteClass::from_bytes(b"ace"),
            ByteClass::from_bytes(b"aceg"),
        ] {
            let plan = plan(class, b"END", false);
            let mut haystack: Vec<u8> = [b'a', b'c'].into_iter().cycle().take(40).collect();
            haystack.extend_from_slice(b"END");
            assert_eq!(
                plan.find(&haystack, SearchLimits::unlimited()).unwrap().0,
                Some((0, 43))
            );

            assert_eq!(
                plan.find(b"ENDac", SearchLimits::unlimited()).unwrap().0,
                None
            );
        }
    }

    #[test]
    fn valid_equality_candidate_excludes_the_known_outsider() {
        for class in [
            ByteClass::from_bytes(b"ac"),
            ByteClass::from_bytes(b"ace"),
            ByteClass::from_bytes(b"aceg"),
        ] {
            let plan = plan(class, b"Z", false);
            let mut haystack = vec![b'a'; 64];
            haystack[31] = b'Z';
            let (span, accounting) = plan.find(&haystack, SearchLimits::unlimited()).unwrap();
            assert_eq!(span, Some((0, 32)));
            assert_eq!(accounting.prefilter_calls, 1);
            assert_eq!(accounting.prefix_bytes_examined, 32);
            assert_eq!(
                accounting.prefix_bytes_upper_bound,
                haystack.len().checked_add(32).unwrap()
            );
            assert!(accounting.prefix_bytes_examined <= accounting.prefix_bytes_upper_bound);

            let exact = SearchLimits {
                max_work_upper_bound: accounting.work_upper_bound,
                max_examined_bytes_upper_bound: accounting.examined_bytes_upper_bound,
                max_scratch_bytes: accounting.scratch_bytes,
            };
            assert!(plan.find(&haystack, exact).is_ok());
            assert!(matches!(
                plan.find(
                    &haystack,
                    SearchLimits {
                        max_examined_bytes_upper_bound: accounting.examined_bytes_upper_bound - 1,
                        ..exact
                    }
                ),
                Err(SearchError::ExaminedBytesLimit { .. })
            ));
            assert!(matches!(
                plan.find(
                    &haystack,
                    SearchLimits {
                        max_work_upper_bound: accounting.work_upper_bound - 1,
                        ..exact
                    }
                ),
                Err(SearchError::WorkLimit { .. })
            ));
        }
    }

    #[test]
    fn candidate_prefix_accounting_is_exact_across_equality_block_edges() {
        let cases: [(ByteClass, &[u8]); 3] = [
            (ByteClass::from_bytes(&[0x00, 0x80]), &[0x00, 0x80]),
            (
                ByteClass::from_bytes(&[0x00, 0x80, 0xFF]),
                &[0x00, 0x80, 0xFF],
            ),
            (
                ByteClass::from_bytes(&[0x00, 0x02, 0x80, 0xFF]),
                &[0x00, 0x02, 0x80, 0xFF],
            ),
        ];
        let suffix = [0x7F, 0x11, 0x7F];
        for (class, members) in cases {
            let plan = plan(class, &suffix, false);
            for candidate in [1_usize, 4, 31, 32, 33, 63, 64, 65] {
                let mut haystack: Vec<u8> = (0..candidate)
                    .map(|index| members[index % members.len()])
                    .collect();
                haystack.extend_from_slice(&suffix);

                let (span, accounting) = plan.find(&haystack, SearchLimits::unlimited()).unwrap();
                assert_eq!(span, Some((0, haystack.len())));
                assert_eq!(
                    accounting.prefilter_calls,
                    usize::from(haystack.len() >= 32)
                );
                assert!(accounting.suffix_confirmation_attempted);
                assert_eq!(
                    accounting.prefix_bytes_examined,
                    candidate.checked_add(1).unwrap()
                );
                let rescan_margin = usize::from(haystack.len() >= 32) * 32;
                assert_eq!(
                    accounting.prefix_bytes_upper_bound,
                    haystack.len().checked_add(rescan_margin).unwrap()
                );
                assert!(accounting.prefix_bytes_examined <= accounting.prefix_bytes_upper_bound);

                let exact = SearchLimits {
                    max_work_upper_bound: accounting.work_upper_bound,
                    max_examined_bytes_upper_bound: accounting.examined_bytes_upper_bound,
                    max_scratch_bytes: accounting.scratch_bytes,
                };
                assert_eq!(plan.find(&haystack, exact).unwrap().0, span);
                assert!(matches!(
                    plan.find(
                        &haystack,
                        SearchLimits {
                            max_examined_bytes_upper_bound: accounting
                                .examined_bytes_upper_bound
                                .checked_sub(1)
                                .unwrap(),
                            ..exact
                        }
                    ),
                    Err(SearchError::ExaminedBytesLimit { .. })
                ));
                assert!(matches!(
                    plan.find(
                        &haystack,
                        SearchLimits {
                            max_work_upper_bound: accounting
                                .work_upper_bound
                                .checked_sub(1)
                                .unwrap(),
                            ..exact
                        }
                    ),
                    Err(SearchError::WorkLimit { .. })
                ));
            }
        }
    }

    #[test]
    fn equality_candidate_search_handles_absence_and_earlier_outsiders() {
        let cases: [(ByteClass, &[u8]); 3] = [
            (ByteClass::from_bytes(&[0x00, 0x80]), &[0x00, 0x80]),
            (
                ByteClass::from_bytes(&[0x00, 0x80, 0xFF]),
                &[0x00, 0x80, 0xFF],
            ),
            (
                ByteClass::from_bytes(&[0x00, 0x02, 0x80, 0xFF]),
                &[0x00, 0x02, 0x80, 0xFF],
            ),
        ];
        let suffix = [0x7F, 0x11, 0x7F];
        for (class, members) in cases {
            let plan = plan(class, &suffix, false);

            for length in [31_usize, 32, 33, 63, 64, 65] {
                let haystack: Vec<u8> = (0..length)
                    .map(|index| members[index % members.len()])
                    .collect();
                let (span, accounting) = plan.find(&haystack, SearchLimits::unlimited()).unwrap();
                assert_eq!(span, None);
                assert!(!accounting.suffix_confirmation_attempted);
                if length < 32 {
                    assert_eq!(accounting.prefilter_calls, 0);
                    assert_eq!(accounting.prefix_bytes_examined, length);
                } else {
                    assert_eq!(accounting.prefilter_calls, 1);
                    assert_eq!(accounting.prefix_bytes_examined, 1);
                }
            }

            for (wrong_outsider, later_candidate) in
                [(31_usize, 32_usize), (32, 63), (33, 64), (63, 65)]
            {
                let mut haystack: Vec<u8> = (0..later_candidate)
                    .map(|index| members[index % members.len()])
                    .collect();
                haystack[wrong_outsider] = 0x40;
                haystack.extend_from_slice(&suffix);
                let (span, accounting) = plan.find(&haystack, SearchLimits::unlimited()).unwrap();
                assert_eq!(span, None);
                assert_eq!(accounting.prefilter_calls, 1);
                assert!(!accounting.suffix_confirmation_attempted);
                assert!(accounting.prefix_bytes_examined > wrong_outsider);
                assert!(accounting.prefix_bytes_examined <= accounting.prefix_bytes_upper_bound);
            }
        }
    }

    #[test]
    fn first_suffix_byte_candidate_is_the_only_possible_boundary() {
        let suffix = [0x7F, 0x11, 0x7F];
        for class in [
            ByteClass::from_bytes(&[0x00, 0x80]),
            ByteClass::from_bytes(&[0x00, 0x80, 0xFF]),
            ByteClass::from_bytes(&[0x00, 0x02, 0x80, 0xFF]),
        ] {
            let plan = plan(class, &suffix, false);
            let first_candidate = 33_usize;
            let mut haystack = vec![0x00; first_candidate];
            haystack.extend_from_slice(&[suffix[0], 0x40, suffix[2]]);
            haystack.extend_from_slice(&[0x00, 0x80]);
            haystack.extend_from_slice(&suffix);

            let (span, accounting) = plan.find(&haystack, SearchLimits::unlimited()).unwrap();
            assert_eq!(span, None);
            assert!(accounting.suffix_confirmation_attempted);
            assert_eq!(
                accounting.prefix_bytes_examined,
                first_candidate.checked_add(1).unwrap()
            );

            haystack[first_candidate + 1] = suffix[1];
            assert_eq!(
                plan.find(&haystack, SearchLimits::unlimited()).unwrap().0,
                Some((0, first_candidate + suffix.len()))
            );
        }
    }

    #[test]
    fn equality_candidate_search_preserves_windows_and_absolute_anchors() {
        let suffix = [0x7F, 0x11, 0x7F];
        for class in [
            ByteClass::from_bytes(&[0x00, 0x80]),
            ByteClass::from_bytes(&[0x00, 0x80, 0xFF]),
            ByteClass::from_bytes(&[0x00, 0x02, 0x80, 0xFF]),
        ] {
            let mut matched = vec![0x00; 33];
            matched.extend_from_slice(&suffix);
            let match_end = matched.len();

            let start_only = plan(class, &suffix, false);
            let mut with_trailing = matched.clone();
            with_trailing.push(0x40);
            assert_eq!(
                start_only
                    .find_window(
                        &with_trailing,
                        Window::new(0, match_end),
                        SearchLimits::unlimited()
                    )
                    .unwrap()
                    .0,
                Some((0, match_end))
            );
            assert_eq!(
                start_only
                    .find_window(
                        &with_trailing,
                        Window::new(1, match_end),
                        SearchLimits::unlimited()
                    )
                    .unwrap()
                    .0,
                None
            );
            assert_eq!(
                start_only
                    .find_window(
                        &with_trailing,
                        Window::new(0, match_end - 1),
                        SearchLimits::unlimited()
                    )
                    .unwrap()
                    .0,
                None
            );

            let both = plan(class, &suffix, true);
            assert_eq!(
                both.find(&matched, SearchLimits::unlimited()).unwrap().0,
                Some((0, match_end))
            );
            assert_eq!(
                both.find(&with_trailing, SearchLimits::unlimited())
                    .unwrap()
                    .0,
                None
            );
            assert_eq!(
                both.find_window(
                    &with_trailing,
                    Window::new(0, match_end),
                    SearchLimits::unlimited()
                )
                .unwrap()
                .0,
                None
            );
        }
    }

    #[test]
    fn candidate_prefix_change_preserves_range_and_bitset_paths() {
        let cases: [(ForwardAnchoredPlan, &[u8], u8); 2] = [
            (
                plan(ByteClass::inclusive(b'a', b'z'), b"ZAZ", false),
                b"az",
                b'!',
            ),
            (
                plan(
                    ByteClass::from_bytes(&[0x00, 0x02, 0x04, 0x80, 0xFF]),
                    &[0x7F, 0x11, 0x7F],
                    false,
                ),
                &[0x00, 0x02, 0x04, 0x80, 0xFF],
                0x40,
            ),
        ];
        assert!(matches!(
            cases[0].0.implementation(),
            ClassImplementation::InclusiveRange { .. }
        ));
        assert_eq!(cases[1].0.implementation(), ClassImplementation::Bitset);

        for (plan, members, wrong) in cases {
            for candidate in [1_usize, 4, 31, 32, 33, 63, 64, 65] {
                let mut haystack: Vec<u8> = (0..candidate)
                    .map(|index| members[index % members.len()])
                    .collect();
                haystack.extend_from_slice(plan.suffix());
                let (span, accounting) = plan.find(&haystack, SearchLimits::unlimited()).unwrap();
                assert_eq!(span, Some((0, haystack.len())));
                assert_eq!(accounting.prefix_bytes_examined, candidate + 1);
            }

            let absent: Vec<u8> = (0..65)
                .map(|index| members[index % members.len()])
                .collect();
            assert_eq!(
                plan.find(&absent, SearchLimits::unlimited()).unwrap().0,
                None
            );

            let mut earlier_wrong: Vec<u8> = (0..64)
                .map(|index| members[index % members.len()])
                .collect();
            earlier_wrong[31] = wrong;
            earlier_wrong.extend_from_slice(plan.suffix());
            let (span, accounting) = plan
                .find(&earlier_wrong, SearchLimits::unlimited())
                .unwrap();
            assert_eq!(span, None);
            assert!(!accounting.suffix_confirmation_attempted);
        }
    }

    #[test]
    fn exhaustive_kernel_differential_covers_arbitrary_classes_and_suffix_borders() {
        let alphabet = [0_u8, 1, 2];
        let haystacks = words(&alphabet, 6, true);
        let suffixes = words(&alphabet, 3, false);
        let mut comparisons = 0_usize;
        for mask in 1_u8..8 {
            let class_bytes: Vec<u8> = alphabet
                .into_iter()
                .enumerate()
                .filter_map(|(bit, byte)| (mask & (1_u8 << bit) != 0).then_some(byte))
                .collect();
            let class = ByteClass::from_bytes(&class_bytes);
            for suffix in &suffixes {
                if class.contains(suffix[0]) {
                    continue;
                }
                for end_anchor in [false, true] {
                    let plan = plan(class, suffix, end_anchor);
                    for haystack in &haystacks {
                        let boundary = haystack.iter().position(|byte| !class.contains(*byte));
                        let expected = boundary.and_then(|boundary| {
                            (boundary != 0)
                                .then(|| boundary.checked_add(suffix.len()))
                                .flatten()
                                .filter(|&end| end <= haystack.len())
                                .filter(|&end| {
                                    haystack.get(boundary..end) == Some(suffix.as_slice())
                                })
                                .filter(|&end| !end_anchor || end == haystack.len())
                                .map(|end| (0, end))
                        });
                        assert_eq!(
                            plan.find(haystack, SearchLimits::unlimited()).unwrap().0,
                            expected
                        );
                        comparisons += 1;
                    }
                }
            }
        }
        assert_eq!(comparisons, 255_762);
    }

    fn words(alphabet: &[u8], max_len: usize, include_empty: bool) -> Vec<Vec<u8>> {
        let mut output = if include_empty {
            vec![Vec::new()]
        } else {
            Vec::new()
        };
        let mut frontier = vec![Vec::new()];
        for _ in 0..max_len {
            let mut next = Vec::new();
            for prefix in &frontier {
                for &byte in alphabet {
                    let mut word = prefix.clone();
                    word.push(byte);
                    output.push(word.clone());
                    next.push(word);
                }
            }
            frontier = next;
        }
        output
    }
}
