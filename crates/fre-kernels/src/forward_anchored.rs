//! Forward boundary search for `\A CLASS+ SUFFIX (?:\z)?`.
//!
//! The proof is deliberately separate from the required-literal candidate.
//! Absolute start fixes the repetition start at byte zero. Because the first
//! suffix byte is outside `CLASS`, the first non-class byte is the only
//! possible repetition boundary. Suffix borders are therefore irrelevant.
//! Search is worst-case linear and allocates no memory.

use core::{alloc::Layout, fmt, mem::size_of, ptr};
use std::alloc::alloc;

use memchr::{memchr, memrchr};

use crate::Window;

/// Stable identity of this exact proof and execution strategy.
pub const PLAN_ID: &str = "anchored-class-suffix.asymmetric-scalar8-reverse32-inline.v1";

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
    /// Maximum logical byte examinations across the prefilter, prefix scan,
    /// and suffix confirmation. This is not a bound on primitive equality
    /// comparisons, native instructions, or CPU work.
    pub max_work_upper_bound: u64,
    /// Maximum logical byte examinations expressed as a `usize`.
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
    /// Exact retained allocation capacity of the suffix copy.
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
    /// Logical byte examinations, including a repeated examination when a
    /// failed fixed block is rescanned to recover its first outsider.
    pub examined_bytes_upper_bound: usize,
    /// The same logical-byte-examination bound represented as `u64`; one
    /// logical examination can contain several equality comparisons.
    pub work_upper_bound: u64,
    pub scratch_bytes: usize,
    /// Native prefilter calls actually issued by this search. Fixed scalar
    /// comparisons in the asymmetric front probe are not native calls.
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

/// Copy `suffix` into a fallible allocation whose reported capacity is exact.
fn copy_suffix_exact(suffix: &[u8]) -> Result<Vec<u8>, BuildError> {
    // SAFETY: `alloc` either returns null or a fresh allocation from the global
    // allocator for exactly the requested layout, and it does not unwind after
    // returning ownership. These are precisely the callback requirements.
    #[allow(
        unsafe_code,
        reason = "the audited exact-layout helper requires the global allocator"
    )]
    unsafe {
        copy_suffix_exact_with(suffix, |layout| alloc(layout))
    }
}

/// The allocation seam used by [`copy_suffix_exact`] and its failure tests.
///
/// # Safety
///
/// If `allocate` returns non-null, its pointer must be a fresh, uniquely owned
/// allocation from the global allocator for the supplied layout. The callback
/// must not unwind after obtaining that allocation. `suffix` must not overlap
/// the returned allocation.
#[allow(
    unsafe_code,
    reason = "constructing a Vec from an exact global-allocation layout is the audited primitive"
)]
unsafe fn copy_suffix_exact_with<A>(suffix: &[u8], allocate: A) -> Result<Vec<u8>, BuildError>
where
    A: FnOnce(Layout) -> *mut u8,
{
    if suffix.is_empty() {
        return Err(BuildError::EmptySuffix);
    }
    let layout = Layout::array::<u8>(suffix.len()).map_err(|_| BuildError::ArithmeticOverflow {
        computation: "exact suffix allocation layout",
    })?;

    #[cfg(test)]
    exact_suffix_copy_probe::record();
    let allocation = allocate(layout);
    if allocation.is_null() {
        return Err(BuildError::AllocationFailed {
            structure: "forward anchored suffix",
            additional: suffix.len(),
        });
    }

    // SAFETY: the function contract gives a fresh global allocation with
    // `layout == Layout::array::<u8>(suffix.len())`. Every u8 alignment is
    // valid, the allocation is disjoint from `suffix`, and all `len` bytes are
    // initialized by the non-overlapping copy. No panicking operation occurs
    // between allocation and `Vec` ownership. `len == capacity`, so `Vec` will
    // later deallocate using the identical layout.
    unsafe {
        ptr::copy_nonoverlapping(suffix.as_ptr(), allocation, suffix.len());
        Ok(Vec::from_raw_parts(allocation, suffix.len(), suffix.len()))
    }
}

#[cfg(test)]
mod exact_suffix_copy_probe {
    use std::cell::Cell;

    std::thread_local! {
        static CALLS: Cell<usize> = const { Cell::new(0) };
    }

    pub(super) fn record() {
        CALLS.set(CALLS.get().checked_add(1).expect("test probe overflow"));
    }

    pub(super) fn reset() {
        CALLS.set(0);
    }

    pub(super) fn calls() -> usize {
        CALLS.get()
    }
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
        let persistent_bytes =
            size_of::<Self>()
                .checked_add(suffix.len())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "persistent plan bytes",
                })?;
        let peak_bytes =
            persistent_bytes
                .checked_add(scratch_bytes)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "construction peak bytes",
                })?;

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

        let owned_suffix = copy_suffix_exact(suffix)?;
        debug_assert_eq!(owned_suffix.len(), owned_suffix.capacity());
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
            // Small exact classes can use any suffix-first witness as an
            // upper bound on the first outsider. The helper partitions long
            // tails into an asymmetric scalar front, reverse back, and
            // untouched middle without overlap; controls retain their
            // first-candidate forward search.
            let uses_edge_witness = matches!(
                self.implementation,
                ClassImplementation::Pair { .. }
                    | ClassImplementation::Triple { .. }
                    | ClassImplementation::Quad { .. }
            );
            let (relative_candidate, prefilter_calls) = if uses_edge_witness {
                asymmetric_suffix_witness(self.suffix[0], &searched[1..])?
            } else {
                (memchr(self.suffix[0], &searched[1..]), 1)
            };
            accounting.prefilter_calls = prefilter_calls;
            let Some(relative_candidate) = relative_candidate else {
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
            // A forward witness is the first suffix-first byte, so an earlier
            // outsider cannot begin the suffix. An edge witness may be later;
            // there the scanner's returned first outsider is authoritative.
            if !uses_edge_witness && boundary != candidate {
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
const EDGE_WITNESS_FRONT: usize = 8;
const EDGE_WITNESS_BACK: usize = 32;
const EDGE_WITNESS_DISJOINT: usize = EDGE_WITNESS_FRONT + EDGE_WITNESS_BACK;

#[cfg(test)]
std::thread_local! {
    static EDGE_WITNESS_VISITS: std::cell::RefCell<Option<Vec<usize>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn begin_edge_witness_trace() {
    EDGE_WITNESS_VISITS.with(|trace| {
        assert!(trace.borrow_mut().replace(Vec::new()).is_none());
    });
}

#[cfg(test)]
fn record_edge_witness_region(start: usize, end: usize, reverse: bool) {
    EDGE_WITNESS_VISITS.with(|trace| {
        let mut trace = trace.borrow_mut();
        let Some(visits) = trace.as_mut() else {
            return;
        };
        if reverse {
            visits.extend((start..end).rev());
        } else {
            visits.extend(start..end);
        }
    });
}

#[cfg(test)]
fn finish_edge_witness_trace() -> Vec<usize> {
    EDGE_WITNESS_VISITS.with(|trace| trace.borrow_mut().take().unwrap())
}

/// Find any suffix-first witness while searching each logical byte at most
/// once on absence. Short tails use one forward search. Long tails search a
/// fixed eight-byte front with unrolled scalar comparisons, a disjoint fixed
/// 32-byte back in reverse, and the untouched middle. The returned call count
/// includes only native `memchr`/`memrchr` calls, not scalar comparisons.
#[allow(
    clippy::inline_always,
    reason = "release linked AArch64 code otherwise retains this helper on the near-front route"
)]
#[inline(always)]
fn asymmetric_suffix_witness(
    needle: u8,
    bytes: &[u8],
) -> Result<(Option<usize>, usize), SearchError> {
    if bytes.len() < EDGE_WITNESS_DISJOINT {
        #[cfg(test)]
        record_edge_witness_region(0, bytes.len(), false);
        return Ok((memchr(needle, bytes), 1));
    }

    #[cfg(test)]
    record_edge_witness_region(0, EDGE_WITNESS_FRONT, false);
    let front_candidate = if bytes[0] == needle {
        Some(0)
    } else if bytes[1] == needle {
        Some(1)
    } else if bytes[2] == needle {
        Some(2)
    } else if bytes[3] == needle {
        Some(3)
    } else if bytes[4] == needle {
        Some(4)
    } else if bytes[5] == needle {
        Some(5)
    } else if bytes[6] == needle {
        Some(6)
    } else if bytes[7] == needle {
        Some(7)
    } else {
        None
    };
    if front_candidate.is_some() {
        return Ok((front_candidate, 0));
    }

    let back_start =
        bytes
            .len()
            .checked_sub(EDGE_WITNESS_BACK)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "edge witness back partition",
            })?;
    #[cfg(test)]
    record_edge_witness_region(back_start, bytes.len(), true);
    if let Some(relative_candidate) = memrchr(needle, &bytes[back_start..]) {
        let candidate =
            back_start
                .checked_add(relative_candidate)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "edge witness back candidate",
                })?;
        return Ok((Some(candidate), 1));
    }

    let middle_start = EDGE_WITNESS_FRONT;
    let middle_end = back_start;
    let middle = &bytes[middle_start..middle_end];
    if middle.is_empty() {
        return Ok((None, 1));
    }
    #[cfg(test)]
    record_edge_witness_region(middle_start, middle_end, false);
    let relative_candidate = memchr(needle, middle);
    let candidate = relative_candidate
        .map(|relative| {
            middle_start
                .checked_add(relative)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "edge witness middle candidate",
                })
        })
        .transpose()?;
    Ok((candidate, 2))
}

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
        SearchError, SearchLimits, asymmetric_suffix_witness, begin_edge_witness_trace,
        copy_suffix_exact, copy_suffix_exact_with, exact_suffix_copy_probe,
        finish_edge_witness_trace,
    };
    use crate::Window;
    use core::mem::size_of;

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
            pair.plan_id(),
            "anchored-class-suffix.asymmetric-scalar8-reverse32-inline.v1"
        );
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
    #[allow(
        unsafe_code,
        reason = "the test injects a null result into the audited allocation seam"
    )]
    fn exact_suffix_copy_has_exact_capacity_and_typed_failure() {
        for len in [1_usize, 2, 3, 7, 8, 15, 16, 31, 32, 255, 256, 4096] {
            let suffix: Vec<u8> = (0_u8..=u8::MAX).cycle().take(len).collect();
            exact_suffix_copy_probe::reset();
            let owned = copy_suffix_exact(&suffix).unwrap();
            assert_eq!(exact_suffix_copy_probe::calls(), 1);
            assert_eq!(owned, suffix);
            assert_eq!(owned.len(), len);
            assert_eq!(owned.capacity(), len);
        }

        exact_suffix_copy_probe::reset();
        assert_eq!(copy_suffix_exact(b""), Err(BuildError::EmptySuffix));
        assert_eq!(exact_suffix_copy_probe::calls(), 0);

        exact_suffix_copy_probe::reset();
        let error = unsafe {
            copy_suffix_exact_with(b"forced allocation failure", |_| core::ptr::null_mut())
        }
        .unwrap_err();
        assert_eq!(
            error,
            BuildError::AllocationFailed {
                structure: "forward anchored suffix",
                additional: b"forced allocation failure".len(),
            }
        );
        assert_eq!(exact_suffix_copy_probe::calls(), 1);
    }

    #[test]
    fn persistent_and_peak_caps_precede_suffix_copy_and_allocation() {
        let class = ByteClass::from_bytes(b"a");
        let suffix = b"Zallocator-independent-borderedaba";
        let anchors = Anchors {
            start: true,
            end: false,
        };
        let exact_bytes = size_of::<ForwardAnchoredPlan>()
            .checked_add(suffix.len())
            .unwrap();
        let permissive = BuildLimits {
            max_suffix_bytes: usize::MAX,
            max_build_work: u64::MAX,
            max_scratch_bytes: usize::MAX,
            max_persistent_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        };

        exact_suffix_copy_probe::reset();
        let persistent_exact = ForwardAnchoredPlan::build(
            class,
            suffix,
            anchors,
            BuildLimits {
                max_persistent_bytes: exact_bytes,
                ..permissive
            },
        )
        .unwrap();
        assert_eq!(exact_suffix_copy_probe::calls(), 1);
        assert_eq!(
            persistent_exact.build_accounting().suffix_bytes,
            suffix.len()
        );
        assert_eq!(
            persistent_exact.build_accounting().suffix_capacity_bytes,
            suffix.len()
        );
        assert_eq!(
            persistent_exact.build_accounting().persistent_bytes,
            exact_bytes
        );

        exact_suffix_copy_probe::reset();
        let persistent_error = ForwardAnchoredPlan::build(
            class,
            suffix,
            anchors,
            BuildLimits {
                max_persistent_bytes: exact_bytes.checked_sub(1).unwrap(),
                ..permissive
            },
        )
        .unwrap_err();
        assert_eq!(
            persistent_error,
            BuildError::PersistentLimit {
                needed: exact_bytes,
                limit: exact_bytes.checked_sub(1).unwrap(),
            }
        );
        assert_eq!(exact_suffix_copy_probe::calls(), 0);

        exact_suffix_copy_probe::reset();
        let peak_exact = ForwardAnchoredPlan::build(
            class,
            suffix,
            anchors,
            BuildLimits {
                max_peak_bytes: exact_bytes,
                ..permissive
            },
        )
        .unwrap();
        assert_eq!(exact_suffix_copy_probe::calls(), 1);
        assert_eq!(peak_exact.build_accounting().peak_bytes, exact_bytes);

        exact_suffix_copy_probe::reset();
        let peak_error = ForwardAnchoredPlan::build(
            class,
            suffix,
            anchors,
            BuildLimits {
                max_peak_bytes: exact_bytes.checked_sub(1).unwrap(),
                ..permissive
            },
        )
        .unwrap_err();
        assert_eq!(
            peak_error,
            BuildError::PeakLimit {
                needed: exact_bytes,
                limit: exact_bytes.checked_sub(1).unwrap(),
            }
        );
        assert_eq!(exact_suffix_copy_probe::calls(), 0);
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
            assert_eq!(accounting.prefilter_calls, 2);
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
        let suffix = [0x7F, 0x11, 0x22];
        for (class, members) in cases {
            let plan = plan(class, &suffix, false);
            for candidate in [1_usize, 4, 31, 32, 33, 63, 64, 65] {
                let mut haystack: Vec<u8> = (0..candidate)
                    .map(|index| members[index % members.len()])
                    .collect();
                haystack.extend_from_slice(&suffix);

                let (span, accounting) = plan.find(&haystack, SearchLimits::unlimited()).unwrap();
                assert_eq!(span, Some((0, haystack.len())));
                let expected_prefilter_calls = usize::from(haystack.len() >= 32);
                assert_eq!(accounting.prefilter_calls, expected_prefilter_calls);
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
        let suffix = [0x7F, 0x11, 0x22];
        for (class, members) in cases {
            let plan = plan(class, &suffix, false);

            for length in [31_usize, 32, 33, 40, 41, 42, 63, 64, 65, 66] {
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
                    let expected_prefilter_calls = usize::from(length >= 42) + 1;
                    assert_eq!(accounting.prefilter_calls, expected_prefilter_calls);
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
                assert!(accounting.suffix_confirmation_attempted);
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
            assert_eq!(accounting.prefilter_calls, 1);
            assert!(accounting.suffix_confirmation_attempted);
            // At the exact disjoint threshold, reverse search selects the
            // final border byte. The class scan still recovers the first
            // outsider and charges that bounded recovery exactly.
            assert_eq!(
                accounting.prefix_bytes_examined,
                first_candidate.checked_add(2).unwrap()
            );

            haystack[first_candidate + 1] = suffix[1];
            assert_eq!(
                plan.find(&haystack, SearchLimits::unlimited()).unwrap().0,
                Some((0, first_candidate + suffix.len()))
            );
        }
    }

    #[test]
    fn asymmetric_witness_threshold_is_exact_and_overlap_uses_forward() {
        for (length, expected_calls) in [(39_usize, 1_usize), (40, 1), (41, 2)] {
            let bytes = vec![0x00; length];
            assert_eq!(
                asymmetric_suffix_witness(0x7F, &bytes).unwrap(),
                (None, expected_calls)
            );
        }

        let mut overlapping = vec![0x00; 39];
        overlapping[7] = 0x7F;
        overlapping[38] = 0x7F;
        assert_eq!(
            asymmetric_suffix_witness(0x7F, &overlapping).unwrap(),
            (Some(7), 1)
        );

        let mut adjacent = vec![0x00; 40];
        adjacent[8] = 0x7F;
        adjacent[39] = 0x7F;
        assert_eq!(
            asymmetric_suffix_witness(0x7F, &adjacent).unwrap(),
            (Some(39), 1)
        );
    }

    #[test]
    fn asymmetric_witness_partitions_and_call_counts_are_exact() {
        for (candidate, expected_calls) in [
            (0_usize, 0_usize),
            (3, 0),
            (7, 0),
            (8, 2),
            (66, 2),
            (67, 1),
            (98, 1),
        ] {
            let mut bytes = vec![0x00; 99];
            bytes[candidate] = 0x7F;
            assert_eq!(
                asymmetric_suffix_witness(0x7F, &bytes).unwrap(),
                (Some(candidate), expected_calls)
            );
        }

        let mut middle_and_back = vec![0x00; 99];
        middle_and_back[8] = 0x7F;
        middle_and_back[67] = 0x7F;
        middle_and_back[98] = 0x7F;
        assert_eq!(
            asymmetric_suffix_witness(0x7F, &middle_and_back).unwrap(),
            (Some(98), 1)
        );

        middle_and_back[3] = 0x7F;
        assert_eq!(
            asymmetric_suffix_witness(0x7F, &middle_and_back).unwrap(),
            (Some(3), 0)
        );
    }

    fn independent_asymmetric_witness_model(needle: u8, bytes: &[u8]) -> (Option<usize>, usize) {
        // These literals intentionally do not reference production constants
        // or the production partition descriptor: mutations must not move the
        // test oracle with the implementation.
        if bytes.len() < 40 {
            return (bytes.iter().position(|&byte| byte == needle), 1);
        }
        if let Some(candidate) = (0..8).find(|&index| bytes[index] == needle) {
            return (Some(candidate), 0);
        }
        let back_start = bytes.len().checked_sub(32).unwrap();
        if let Some(candidate) = (back_start..bytes.len())
            .rev()
            .find(|&index| bytes[index] == needle)
        {
            return (Some(candidate), 1);
        }
        if let Some(candidate) = (8..back_start).find(|&index| bytes[index] == needle) {
            return (Some(candidate), 2);
        }
        (None, if back_start == 8 { 1 } else { 2 })
    }

    #[test]
    fn asymmetric_witness_matches_independent_model_at_every_directed_position() {
        for length in [39_usize, 40, 41, 42, 99, 4096] {
            let absent = vec![0x11; length];
            let expected_absent = independent_asymmetric_witness_model(0x7F, &absent);
            let expected_absent_calls = if length <= 40 { 1 } else { 2 };
            assert_eq!(expected_absent, (None, expected_absent_calls));
            assert_eq!(
                asymmetric_suffix_witness(0x7F, &absent).unwrap(),
                expected_absent,
                "absence length={length}"
            );

            for candidate in 0..length {
                let mut singleton = absent.clone();
                singleton[candidate] = 0x7F;
                let expected = independent_asymmetric_witness_model(0x7F, &singleton);
                let expected_calls = if length < 40 {
                    1
                } else if candidate < 8 {
                    0
                } else if candidate >= length.checked_sub(32).unwrap() {
                    1
                } else {
                    2
                };
                assert_eq!(expected, (Some(candidate), expected_calls));
                assert_eq!(
                    asymmetric_suffix_witness(0x7F, &singleton).unwrap(),
                    expected,
                    "singleton length={length} candidate={candidate}"
                );
            }
        }
    }

    fn trace_proves_ordered_disjoint_complete_partition(length: usize, visits: &[usize]) -> bool {
        let expected: Vec<usize> = if length < 40 {
            (0..length).collect()
        } else {
            let back_start = length.checked_sub(32).unwrap();
            (0..8)
                .chain((back_start..length).rev())
                .chain(8..back_start)
                .collect()
        };
        if visits != expected || visits.len() != length {
            return false;
        }
        let mut visits = vec![0_u8; length];
        for &index in &expected {
            let Some(count) = visits.get_mut(index) else {
                return false;
            };
            *count = count.saturating_add(1);
        }
        visits.into_iter().all(|count| count == 1)
    }

    #[test]
    fn asymmetric_partition_is_ordered_disjoint_complete_and_mutation_effective() {
        for length in [39_usize, 40, 41, 42, 99, 4096] {
            let absent = vec![0x11; length];
            begin_edge_witness_trace();
            let result = asymmetric_suffix_witness(0x7F, &absent).unwrap();
            let visits = finish_edge_witness_trace();
            assert_eq!(result.0, None);
            assert!(trace_proves_ordered_disjoint_complete_partition(
                length, &visits
            ));

            if length > 40 {
                let back_start = length.checked_sub(32).unwrap();
                let front_middle_overlap: Vec<usize> = (0..8)
                    .chain((back_start..length).rev())
                    .chain(7..back_start)
                    .collect();
                assert!(
                    !trace_proves_ordered_disjoint_complete_partition(
                        length,
                        &front_middle_overlap
                    ),
                    "guarded front/middle overlap survived at length={length}"
                );

                let middle_back_overlap: Vec<usize> = (0..8)
                    .chain((back_start..length).rev())
                    .chain(8..back_start.checked_add(1).unwrap())
                    .collect();
                assert!(
                    !trace_proves_ordered_disjoint_complete_partition(length, &middle_back_overlap),
                    "guarded middle/back overlap survived at length={length}"
                );
            }
        }
    }

    #[test]
    fn asymmetric_witness_plan_preserves_partition_boundary_semantics() {
        let suffix = [0x7F, 0x11, 0x22];
        for class in [
            ByteClass::from_bytes(&[0x00, 0x80]),
            ByteClass::from_bytes(&[0x00, 0x80, 0xFF]),
            ByteClass::from_bytes(&[0x00, 0x02, 0x80, 0xFF]),
        ] {
            let plan = plan(class, &suffix, false);
            for (candidate, expected_calls) in [
                (1_usize, 0_usize),
                (4, 0),
                (8, 0),
                (9, 2),
                (67, 2),
                (68, 1),
                (97, 1),
            ] {
                let mut haystack = vec![0x00; 100];
                haystack[candidate..candidate + suffix.len()].copy_from_slice(&suffix);
                let (span, accounting) = plan.find(&haystack, SearchLimits::unlimited()).unwrap();
                assert_eq!(span, Some((0, candidate + suffix.len())));
                assert_eq!(accounting.prefilter_calls, expected_calls);
                assert_eq!(accounting.prefix_bytes_examined, candidate + 1);
                assert!(accounting.suffix_confirmation_attempted);
            }
        }
    }

    #[test]
    fn asymmetric_witness_confirms_the_returned_first_outsider() {
        let suffix = [0x7F, 0x11, 0x22];
        for class in [
            ByteClass::from_bytes(&[0x00, 0x80]),
            ByteClass::from_bytes(&[0x00, 0x80, 0xFF]),
            ByteClass::from_bytes(&[0x00, 0x02, 0x80, 0xFF]),
        ] {
            let plan = plan(class, &suffix, false);

            let mut earlier_valid = vec![0x00; 100];
            earlier_valid[40..43].copy_from_slice(&suffix);
            earlier_valid[90..93].copy_from_slice(&suffix);
            let (span, accounting) = plan
                .find(&earlier_valid, SearchLimits::unlimited())
                .unwrap();
            assert_eq!(span, Some((0, 43)));
            assert_eq!(accounting.prefilter_calls, 1);
            assert!(accounting.suffix_confirmation_attempted);

            let mut earlier_wrong = vec![0x00; 100];
            earlier_wrong[40] = 0x40;
            earlier_wrong[90..93].copy_from_slice(&suffix);
            let (span, accounting) = plan
                .find(&earlier_wrong, SearchLimits::unlimited())
                .unwrap();
            assert_eq!(span, None);
            assert_eq!(accounting.prefilter_calls, 1);
            assert!(accounting.suffix_confirmation_attempted);

            let mut earlier_mismatching_candidate = vec![0x00; 100];
            earlier_mismatching_candidate[40] = suffix[0];
            earlier_mismatching_candidate[41] = 0x40;
            earlier_mismatching_candidate[90..93].copy_from_slice(&suffix);
            assert_eq!(
                plan.find(&earlier_mismatching_candidate, SearchLimits::unlimited())
                    .unwrap()
                    .0,
                None
            );
        }
    }

    #[test]
    fn reverse_asymmetric_witness_handles_a_bordered_suffix() {
        let suffix = [0x7F, 0x11, 0x7F];
        for class in [
            ByteClass::from_bytes(&[0x00, 0x80]),
            ByteClass::from_bytes(&[0x00, 0x80, 0xFF]),
            ByteClass::from_bytes(&[0x00, 0x02, 0x80, 0xFF]),
        ] {
            let plan = plan(class, &suffix, false);
            let mut haystack = vec![0x00; 100];
            haystack[94..97].copy_from_slice(&suffix);
            let (span, accounting) = plan.find(&haystack, SearchLimits::unlimited()).unwrap();
            assert_eq!(span, Some((0, 97)));
            assert_eq!(accounting.prefilter_calls, 1);
            assert_eq!(accounting.prefix_bytes_examined, 128);
            assert!(accounting.suffix_confirmation_attempted);
            assert!(accounting.prefix_bytes_examined <= accounting.prefix_bytes_upper_bound);
        }
    }

    #[test]
    fn overlapping_asymmetric_regions_use_one_forward_prefilter() {
        let suffix = [0x7F, 0x11, 0x22];
        for class in [
            ByteClass::from_bytes(&[0x00, 0x80]),
            ByteClass::from_bytes(&[0x00, 0x80, 0xFF]),
            ByteClass::from_bytes(&[0x00, 0x02, 0x80, 0xFF]),
        ] {
            let plan = plan(class, &suffix, false);
            let mut haystack = vec![0x00; 40];
            haystack[10] = suffix[0];
            haystack[11] = 0x40;
            haystack[35..38].copy_from_slice(&suffix);
            let (span, accounting) = plan.find(&haystack, SearchLimits::unlimited()).unwrap();
            assert_eq!(span, None);
            assert_eq!(accounting.prefilter_calls, 1);
            assert!(accounting.suffix_confirmation_attempted);

            haystack[11] = suffix[1];
            haystack[12] = suffix[2];
            assert_eq!(
                plan.find(&haystack, SearchLimits::unlimited()).unwrap().0,
                Some((0, 13))
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
                assert_eq!(
                    accounting.prefilter_calls,
                    usize::from(haystack.len() >= 32)
                );
            }

            let absent: Vec<u8> = (0..65)
                .map(|index| members[index % members.len()])
                .collect();
            let (span, accounting) = plan.find(&absent, SearchLimits::unlimited()).unwrap();
            assert_eq!(span, None);
            assert_eq!(accounting.prefilter_calls, 1);

            let mut earlier_wrong: Vec<u8> = (0..64)
                .map(|index| members[index % members.len()])
                .collect();
            earlier_wrong[31] = wrong;
            earlier_wrong.extend_from_slice(plan.suffix());
            let (span, accounting) = plan
                .find(&earlier_wrong, SearchLimits::unlimited())
                .unwrap();
            assert_eq!(span, None);
            assert_eq!(accounting.prefilter_calls, 1);
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
