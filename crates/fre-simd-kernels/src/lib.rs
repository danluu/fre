//! Reusable, runtime-dispatched SIMD kernels for FRE.
//!
//! [`AsciiByteSetClassifier`] turns one 128-bit ASCII byte set into nibble
//! lookup tables and chooses its 16-byte and 32-byte implementations once.
//! [`AsciiByteSetRunScanner`] retains a separate operation-specific choice and
//! finds maximal member prefixes or suffixes without materializing positional
//! lane masks. Calls do not detect CPU features or make dispatch decisions from
//! varying haystack lengths. Private target-feature leaves are reachable only
//! through handles built from [`fre_target_features::host`] facts.

#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::fmt;

use fre_target_features::{
    Architecture, ArchitectureRequirement, KernelVariant, SelectedKernel, VectorKind, host,
    select_kernel,
};
pub use fre_target_features::{
    CpuCapabilities, DispatchPolicy, DispatchProfile, Feature, FeatureSet, SelectionReceipt,
    TuningClass, UnsupportedRequiredFeatures, dispatch_profile,
};

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
mod aarch64_sve2;
mod scalar;
#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(test)]
mod tests;

/// Number of bytes consumed by the narrow classifier operation.
pub const ASCII_NARROW_BYTES: usize = 16;

/// Number of bytes consumed by the wide classifier operation.
pub const ASCII_WIDE_BYTES: usize = 32;

const ASCII_WORD_SET: AsciiByteSet =
    AsciiByteSet::from_words([0x03ff_0000_0000_0000, 0x07ff_fffe_87ff_fffe]);
const ASCII_SPACE_VALUES: [u8; ASCII_NARROW_BYTES] = [
    b'\t', b'\n', 0x0b, 0x0c, b'\r', b' ', b'\t', b'\t', b'\t', b'\t', b'\t', b'\t', b'\t', b'\t',
    b'\t', b'\t',
];

/// Maximum physical classification work beyond the logically necessary run.
///
/// On failure, the logical minimum is `member_run_len + 1`; on an all-member
/// input it is `member_run_len`. Scalar adds no overhead. SVE/SVE2 classify
/// every active lane in the failed predicated load and therefore add at most
/// 15. NEON adds exactly 16 when it scalar-recovers a failed full block and
/// otherwise adds none.
pub const ASCII_RUN_MAX_CLASSIFICATION_OVERHEAD: usize = ASCII_NARROW_BYTES;

const ASCII_NARROW_VECTOR_BYTES: u16 = 16;
#[cfg(target_arch = "x86_64")]
const ASCII_WIDE_VECTOR_BYTES: u16 = 32;

const HIGH_NIBBLE_BITS: [u8; ASCII_NARROW_BYTES] = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0, 0, 0, 0, 0, 0, 0, 0,
];

#[cfg(target_arch = "aarch64")]
const LANE_WEIGHTS: [u8; ASCII_NARROW_BYTES] = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
];

/// Immutable, non-forgeable SIMD dispatch context captured from the host.
///
/// Resource-accounted callers can capture this context before entering their
/// transaction, then construct one or more classifiers from the exact same
/// capability snapshot without hidden feature detection.
///
/// ```
/// use fre_simd_kernels::{
///     AsciiByteSet, DispatchPolicy, SimdDispatchContext,
/// };
///
/// let dispatch = SimdDispatchContext::capture();
/// // A bounded accounting transaction can begin after the host read above.
/// let classifier = dispatch
///     .ascii_byte_set_classifier(AsciiByteSet::ALL, DispatchPolicy::Auto)
///     .unwrap();
/// assert_eq!(classifier.set(), AsciiByteSet::ALL);
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SimdDispatchContext {
    capabilities: CpuCapabilities,
}

impl SimdDispatchContext {
    /// Capture the process-wide host capability snapshot.
    #[must_use]
    pub fn capture() -> Self {
        Self {
            capabilities: *host(),
        }
    }

    /// Return the immutable capability snapshot held by this context.
    #[must_use]
    pub const fn capabilities(self) -> CpuCapabilities {
        self.capabilities
    }

    /// Build an ASCII byte-set classifier from this captured snapshot.
    pub fn ascii_byte_set_classifier(
        self,
        set: AsciiByteSet,
        policy: DispatchPolicy,
    ) -> Result<AsciiByteSetClassifier, UnsupportedRequiredFeatures> {
        AsciiByteSetClassifier::with_capabilities(set, self.capabilities, policy)
    }

    /// Build a forward/backward ASCII byte-set run scanner from this snapshot.
    pub fn ascii_byte_set_run_scanner(
        self,
        set: AsciiByteSet,
        policy: DispatchPolicy,
    ) -> Result<AsciiByteSetRunScanner, UnsupportedRequiredFeatures> {
        AsciiByteSetRunScanner::with_capabilities(set, self.capabilities, policy)
    }

    /// Build the token-phrase three-class classifier from this snapshot.
    pub fn ascii_word_space_classifier(
        self,
        policy: DispatchPolicy,
    ) -> Result<AsciiWordSpaceClassifier, UnsupportedRequiredFeatures> {
        AsciiWordSpaceClassifier::with_capabilities(self.capabilities, policy)
    }
}

/// A set over the 128 ASCII byte values.
///
/// Bit `b` represents byte `b`; the first word contains `0..=63` and the
/// second contains `64..=127`.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AsciiByteSet([u64; 2]);

impl AsciiByteSet {
    /// The empty ASCII byte set.
    pub const EMPTY: Self = Self([0, 0]);

    /// The set containing every ASCII byte.
    pub const ALL: Self = Self([u64::MAX, u64::MAX]);

    /// Build a set from its two exact bitmap words.
    #[must_use]
    pub const fn from_words(words: [u64; 2]) -> Self {
        Self(words)
    }

    /// Return the two exact bitmap words.
    #[must_use]
    pub const fn words(self) -> [u64; 2] {
        self.0
    }

    /// Test membership. Bytes above `0x7f` are never members.
    #[must_use]
    pub const fn contains(self, byte: u8) -> bool {
        if byte < 64 {
            self.0[0] & (1_u64 << byte) != 0
        } else if byte < 128 {
            self.0[1] & (1_u64 << byte.wrapping_sub(64)) != 0
        } else {
            false
        }
    }

    fn nibble_columns(self) -> [u8; ASCII_NARROW_BYTES] {
        let mut columns = [0_u8; ASCII_NARROW_BYTES];
        for byte in 0_u8..=0x7f {
            if self.contains(byte) {
                let low_nibble = usize::from(byte & 0x0f);
                let high_bit = HIGH_NIBBLE_BITS[usize::from(byte >> 4)];
                columns[low_nibble] |= high_bit;
            }
        }
        columns
    }

    fn run_tables(self) -> (AsciiRunTables, bool) {
        let mut columns = [0_u8; ASCII_NARROW_BYTES];
        let mut values = [0_u8; ASCII_NARROW_BYTES];
        let mut values_len = 0_usize;
        let mut values_overflowed = false;
        for byte in 0_u8..=0x7f {
            if !self.contains(byte) {
                continue;
            }
            let low_nibble = usize::from(byte & 0x0f);
            let high_bit = HIGH_NIBBLE_BITS[usize::from(byte >> 4)];
            columns[low_nibble] |= high_bit;

            if let Some(slot) = values.get_mut(values_len) {
                *slot = byte;
                values_len = values_len
                    .checked_add(1)
                    .expect("an ASCII set cardinality fits in usize");
            } else {
                values_overflowed = true;
            }
        }
        let match_eligible = values_len != 0 && !values_overflowed;
        if match_eligible {
            let duplicate = values[0];
            values[values_len..].fill(duplicate);
        }
        (
            AsciiRunTables {
                set: self,
                columns,
                match_values: values,
            },
            match_eligible,
        )
    }
}

/// Result of scanning one maximal ASCII byte-set member run.
///
/// For [`AsciiByteSetRunScanner::scan_forward`], `member_run_len` is the
/// member prefix length. For [`AsciiByteSetRunScanner::scan_backward`], it is
/// the member suffix length. `examined_bytes` counts physical byte
/// classifications, including a vector-width probe and scalar recovery of the
/// same failed block when the selected implementation requires both.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AsciiRunResult {
    member_run_len: usize,
    examined_bytes: usize,
}

impl AsciiRunResult {
    const fn new(member_run_len: usize, examined_bytes: usize) -> Self {
        debug_assert!(member_run_len <= examined_bytes);
        Self {
            member_run_len,
            examined_bytes,
        }
    }

    /// Length of the maximal member prefix or suffix.
    #[must_use]
    pub const fn member_run_len(self) -> usize {
        self.member_run_len
    }

    /// Exact number of physical byte classifications performed by the leaf.
    ///
    /// This may exceed the source length when NEON classifies a failed block
    /// once as a vector and again during scalar recovery. The excess over the
    /// logically necessary run is bounded by
    /// [`ASCII_RUN_MAX_CLASSIFICATION_OVERHEAD`].
    #[must_use]
    pub const fn examined_bytes(self) -> usize {
        self.examined_bytes
    }
}

/// Per-lane ASCII and byte-set membership masks for 16 input bytes.
///
/// Bit `i` corresponds to input byte `i`. Membership is always a subset of
/// the ASCII mask.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AsciiMasks16 {
    ascii: u16,
    members: u16,
}

impl AsciiMasks16 {
    fn new(ascii: u16, members: u16) -> Self {
        debug_assert_eq!(members & !ascii, 0);
        Self { ascii, members }
    }

    /// Mask of input lanes whose bytes are ASCII.
    #[must_use]
    pub const fn ascii_mask(self) -> u16 {
        self.ascii
    }

    /// Mask of input lanes whose bytes belong to the classifier's set.
    #[must_use]
    pub const fn member_mask(self) -> u16 {
        self.members
    }

    /// Number of member lanes.
    #[must_use]
    pub fn member_count(self) -> u8 {
        u8::try_from(self.members.count_ones()).expect("a 16-bit mask count fits in u8")
    }

    /// Length of the initial all-ASCII prefix.
    #[must_use]
    pub fn leading_ascii_len(self) -> u8 {
        u8::try_from(self.ascii.trailing_ones()).expect("a 16-bit mask width fits in u8")
    }

    /// Member mask restricted to the initial all-ASCII prefix.
    #[must_use]
    pub fn ascii_prefix_member_mask(self) -> u16 {
        self.members & low_u16_mask(self.ascii.trailing_ones())
    }
}

/// Per-lane ASCII and byte-set membership masks for 32 input bytes.
///
/// Bit `i` corresponds to input byte `i`. Membership is always a subset of
/// the ASCII mask.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AsciiMasks32 {
    ascii: u32,
    members: u32,
}

/// Three-way word, whitespace, and other masks for exactly 16 bytes.
///
/// Word and whitespace masks are disjoint. Every lane absent from both masks
/// belongs to the `other` class, including every non-ASCII byte.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AsciiWordSpaceMasks16 {
    words: u16,
    spaces: u16,
}

impl AsciiWordSpaceMasks16 {
    fn new(words: u16, spaces: u16) -> Self {
        debug_assert_eq!(words & spaces, 0);
        Self { words, spaces }
    }

    /// Mask of ASCII word lanes (`[0-9A-Z_a-z]`).
    #[must_use]
    pub const fn word_mask(self) -> u16 {
        self.words
    }

    /// Mask of ASCII whitespace lanes (`[\t-\r ]`).
    #[must_use]
    pub const fn space_mask(self) -> u16 {
        self.spaces
    }

    /// Mask of lanes in neither ASCII class.
    #[must_use]
    pub const fn other_mask(self) -> u16 {
        !(self.words | self.spaces)
    }
}

/// Three-way word, whitespace, and other masks for exactly 32 bytes.
///
/// This is the wide companion to [`AsciiWordSpaceMasks16`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AsciiWordSpaceMasks32 {
    words: u32,
    spaces: u32,
}

impl AsciiWordSpaceMasks32 {
    fn new(words: u32, spaces: u32) -> Self {
        debug_assert_eq!(words & spaces, 0);
        Self { words, spaces }
    }

    /// Mask of ASCII word lanes (`[0-9A-Z_a-z]`).
    #[must_use]
    pub const fn word_mask(self) -> u32 {
        self.words
    }

    /// Mask of ASCII whitespace lanes (`[\t-\r ]`).
    #[must_use]
    pub const fn space_mask(self) -> u32 {
        self.spaces
    }

    /// Mask of lanes in neither ASCII class.
    #[must_use]
    pub const fn other_mask(self) -> u32 {
        !(self.words | self.spaces)
    }
}

impl AsciiMasks32 {
    fn new(ascii: u32, members: u32) -> Self {
        debug_assert_eq!(members & !ascii, 0);
        Self { ascii, members }
    }

    fn from_halves(first: AsciiMasks16, second: AsciiMasks16) -> Self {
        let ascii = u32::from(first.ascii) | (u32::from(second.ascii) << 16);
        let members = u32::from(first.members) | (u32::from(second.members) << 16);
        Self::new(ascii, members)
    }

    /// Mask of input lanes whose bytes are ASCII.
    #[must_use]
    pub const fn ascii_mask(self) -> u32 {
        self.ascii
    }

    /// Mask of input lanes whose bytes belong to the classifier's set.
    #[must_use]
    pub const fn member_mask(self) -> u32 {
        self.members
    }

    /// Number of member lanes.
    #[must_use]
    pub fn member_count(self) -> u8 {
        u8::try_from(self.members.count_ones()).expect("a 32-bit mask count fits in u8")
    }

    /// Length of the initial all-ASCII prefix.
    #[must_use]
    pub fn leading_ascii_len(self) -> u8 {
        u8::try_from(self.ascii.trailing_ones()).expect("a 32-bit mask width fits in u8")
    }

    /// Member mask restricted to the initial all-ASCII prefix.
    #[must_use]
    pub fn ascii_prefix_member_mask(self) -> u32 {
        self.members & low_u32_mask(self.ascii.trailing_ones())
    }
}

fn low_u16_mask(bits: u32) -> u16 {
    if bits == u16::BITS {
        u16::MAX
    } else {
        1_u16
            .checked_shl(bits)
            .expect("a trailing-one count is within the mask width")
            .wrapping_sub(1)
    }
}

fn low_u32_mask(bits: u32) -> u32 {
    if bits == u32::BITS {
        u32::MAX
    } else {
        1_u32
            .checked_shl(bits)
            .expect("a trailing-one count is within the mask width")
            .wrapping_sub(1)
    }
}

/// Auditable receipts for both fixed-width selections in one classifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AsciiSelection {
    narrow: SelectionReceipt,
    wide: SelectionReceipt,
}

impl AsciiSelection {
    /// Receipt for the exact 16-byte operation.
    #[must_use]
    pub const fn narrow(self) -> SelectionReceipt {
        self.narrow
    }

    /// Receipt for the exact 32-byte operation.
    #[must_use]
    pub const fn wide(self) -> SelectionReceipt {
        self.wide
    }
}

#[derive(Clone, Copy, Debug)]
struct AsciiRunTables {
    set: AsciiByteSet,
    columns: [u8; ASCII_NARROW_BYTES],
    #[cfg_attr(
        not(all(target_arch = "aarch64", target_os = "linux", target_endian = "little")),
        allow(
            dead_code,
            reason = "the compiled MATCH table is retained on every target so scanner layout and construction accounting remain target-independent"
        )
    )]
    match_values: [u8; ASCII_NARROW_BYTES],
}

#[allow(
    unsafe_code,
    reason = "the private function-pointer type represents a target-feature proof retained by a successfully constructed run scanner"
)]
type ScanRunEntry = unsafe fn(&AsciiRunTables, &[u8]) -> AsciiRunResult;

#[derive(Clone, Copy, Debug)]
struct AsciiRunEntries {
    forward: ScanRunEntry,
    backward: ScanRunEntry,
}

/// A compiled ASCII byte-set run scanner with immutable one-time dispatch.
///
/// The scanner accepts arbitrary slice lengths. Dispatch nevertheless uses the
/// invariant 16-byte kernel block shape at construction, never a caller's
/// varying slice length.
#[derive(Clone, Copy)]
pub struct AsciiByteSetRunScanner {
    tables: AsciiRunTables,
    entries: AsciiRunEntries,
    selection: SelectionReceipt,
}

impl fmt::Debug for AsciiByteSetRunScanner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AsciiByteSetRunScanner")
            .field("set", &self.tables.set)
            .field("selection", &self.selection)
            .finish_non_exhaustive()
    }
}

impl AsciiByteSetRunScanner {
    /// Build a run scanner using all OS-usable host features.
    #[must_use]
    pub fn new(set: AsciiByteSet) -> Self {
        Self::with_policy(set, DispatchPolicy::Auto)
            .expect("automatic dispatch always retains a scalar fallback")
    }

    /// Build a run scanner under an authentic host-feature policy.
    pub fn with_policy(
        set: AsciiByteSet,
        policy: DispatchPolicy,
    ) -> Result<Self, UnsupportedRequiredFeatures> {
        SimdDispatchContext::capture().ascii_byte_set_run_scanner(set, policy)
    }

    /// Build a scanner from one already-captured capability snapshot.
    ///
    /// Both table representations are compiled together in exactly one pass
    /// over the 128 possible ASCII values.
    pub fn with_capabilities(
        set: AsciiByteSet,
        capabilities: CpuCapabilities,
        policy: DispatchPolicy,
    ) -> Result<Self, UnsupportedRequiredFeatures> {
        // One complete 128-byte-domain pass builds both representations so
        // resource-accounted callers can charge exactly 128 membership probes.
        let (tables, match_eligible) = set.run_tables();
        let selected = select_run(capabilities, policy, match_eligible)?;
        Ok(Self {
            tables,
            entries: selected.entry(),
            selection: selected.receipt(),
        })
    }

    /// The byte set compiled into this scanner.
    #[must_use]
    pub const fn set(&self) -> AsciiByteSet {
        self.tables.set
    }

    /// Stable receipt for the paired forward/backward implementation.
    #[must_use]
    pub const fn selection(&self) -> SelectionReceipt {
        self.selection
    }

    /// Scan the maximal member prefix.
    ///
    /// The returned run length is in `0..=bytes.len()`. A nonempty slice with
    /// a zero run still examines the first nonmember. The selected leaf may
    /// inspect a complete vector block before recovering the exact boundary;
    /// [`AsciiRunResult::examined_bytes`] reports that work exactly.
    #[must_use]
    #[allow(
        unsafe_code,
        reason = "construction retained this private entry only after proving every required target feature against immutable host facts"
    )]
    pub fn scan_forward(&self, bytes: &[u8]) -> AsciiRunResult {
        // SAFETY: callers cannot forge or replace the retained entry or tables.
        // The slice proves the source extent for every scalar, fixed-width, or
        // predicated load performed by the selected private leaf.
        unsafe { (self.entries.forward)(&self.tables, bytes) }
    }

    /// Scan the maximal member suffix.
    ///
    /// The result's run length is subtracted from `bytes.len()` to obtain the
    /// suffix start. Examination accounting follows [`Self::scan_forward`].
    #[must_use]
    #[allow(
        unsafe_code,
        reason = "construction retained this private entry only after proving every required target feature against immutable host facts"
    )]
    pub fn scan_backward(&self, bytes: &[u8]) -> AsciiRunResult {
        // SAFETY: identical retained-entry and source-extent proof to the
        // forward operation.
        unsafe { (self.entries.backward)(&self.tables, bytes) }
    }
}

#[allow(
    unsafe_code,
    reason = "the private function-pointer type represents a target-feature proof retained by a successfully constructed classifier"
)]
type Classify16Entry =
    unsafe fn(&[u8; ASCII_NARROW_BYTES], &[u8; ASCII_NARROW_BYTES]) -> AsciiMasks16;

#[allow(
    unsafe_code,
    reason = "the private function-pointer type represents a target-feature proof retained by a successfully constructed classifier"
)]
#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "linux", target_endian = "little")
))]
type Classify32Entry =
    unsafe fn(&[u8; ASCII_NARROW_BYTES], &[u8; ASCII_WIDE_BYTES]) -> AsciiMasks32;

#[derive(Clone, Copy, Debug)]
enum WideEntry {
    SplitNarrow,
    #[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
    Sve2(Classify32Entry),
    #[cfg(target_arch = "x86_64")]
    Avx2(Classify32Entry),
    #[cfg(target_arch = "x86_64")]
    Avx512(Classify32Entry),
}

/// A compiled ASCII byte-set classifier with immutable one-time dispatch.
#[derive(Clone, Copy)]
pub struct AsciiByteSetClassifier {
    set: AsciiByteSet,
    columns: [u8; ASCII_NARROW_BYTES],
    narrow_entry: Classify16Entry,
    wide_entry: WideEntry,
    selection: AsciiSelection,
}

impl fmt::Debug for AsciiByteSetClassifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AsciiByteSetClassifier")
            .field("set", &self.set)
            .field("selection", &self.selection)
            .finish_non_exhaustive()
    }
}

impl AsciiByteSetClassifier {
    /// Build a classifier using all OS-usable host features.
    #[must_use]
    pub fn new(set: AsciiByteSet) -> Self {
        Self::with_policy(set, DispatchPolicy::Auto)
            .expect("automatic dispatch always retains a scalar fallback")
    }

    /// Build a classifier under a policy that can only remove real host
    /// features or require that real host features are present.
    pub fn with_policy(
        set: AsciiByteSet,
        policy: DispatchPolicy,
    ) -> Result<Self, UnsupportedRequiredFeatures> {
        SimdDispatchContext::capture().ascii_byte_set_classifier(set, policy)
    }

    /// Build a classifier from an already-captured host capability snapshot.
    ///
    /// This lets bounded callers acquire immutable host context before entering
    /// a resource-accounting transaction. [`CpuCapabilities`] cannot be
    /// synthesized outside `fre-target-features`; callers can only pass a real
    /// [`SimdDispatchContext`] snapshot or a view that removes features from
    /// that snapshot.
    pub fn with_capabilities(
        set: AsciiByteSet,
        capabilities: CpuCapabilities,
        policy: DispatchPolicy,
    ) -> Result<Self, UnsupportedRequiredFeatures> {
        // Both fixed-width decisions use precisely the same immutable facts and
        // policy supplied by the caller.
        let narrow = select_narrow(capabilities, policy)?;
        let wide = select_wide(capabilities, policy)?;
        let narrow_receipt = narrow.receipt();
        let wide_entry = wide.entry();
        let wide_receipt = match wide_entry {
            WideEntry::SplitNarrow => SelectionReceipt {
                // The 32-byte implementation delegates every instruction to
                // the already-selected 16-byte leaf. Preserve the outer
                // operation width/threshold while making the effective ISA,
                // vector shape, and exact child implementation self-contained
                // in this receipt.
                delegate_variant_id: Some(narrow_receipt.variant_id),
                required: narrow_receipt.required,
                vector: narrow_receipt.vector,
                ..wide.receipt()
            },
            #[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
            WideEntry::Sve2(_) => wide.receipt(),
            #[cfg(target_arch = "x86_64")]
            WideEntry::Avx2(_) => wide.receipt(),
            #[cfg(target_arch = "x86_64")]
            WideEntry::Avx512(_) => wide.receipt(),
        };
        Ok(Self {
            set,
            columns: set.nibble_columns(),
            narrow_entry: narrow.entry(),
            wide_entry,
            selection: AsciiSelection {
                narrow: narrow_receipt,
                wide: wide_receipt,
            },
        })
    }

    /// The byte set compiled into this handle.
    #[must_use]
    pub const fn set(&self) -> AsciiByteSet {
        self.set
    }

    /// Stable receipts for the handle's two construction-time decisions.
    #[must_use]
    pub const fn selection(&self) -> AsciiSelection {
        self.selection
    }

    /// Classify exactly 16 bytes.
    #[must_use]
    #[allow(
        unsafe_code,
        reason = "the private entry is retained only after construction proved its exact target features against the immutable host snapshot"
    )]
    pub fn classify_16(&self, bytes: &[u8; ASCII_NARROW_BYTES]) -> AsciiMasks16 {
        // SAFETY: no caller can provide or replace `narrow_entry`.
        // Construction selected it only when its feature requirements were a
        // subset of OS-usable host facts, and policy application cannot add
        // features. The fixed-array argument proves the leaf's load width.
        unsafe { (self.narrow_entry)(&self.columns, bytes) }
    }

    /// Classify exactly 32 bytes.
    #[must_use]
    #[allow(
        unsafe_code,
        reason = "each private direct wide entry is retained only after construction proved its exact target features; the split fallback calls the already-qualified narrow entry"
    )]
    pub fn classify_32(&self, bytes: &[u8; ASCII_WIDE_BYTES]) -> AsciiMasks32 {
        match self.wide_entry {
            WideEntry::SplitNarrow => {
                let first: &[u8; ASCII_NARROW_BYTES] = bytes[..ASCII_NARROW_BYTES]
                    .try_into()
                    .expect("the first half has exactly 16 bytes");
                let second: &[u8; ASCII_NARROW_BYTES] = bytes[ASCII_NARROW_BYTES..]
                    .try_into()
                    .expect("the second half has exactly 16 bytes");
                AsciiMasks32::from_halves(self.classify_16(first), self.classify_16(second))
            }
            #[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
            WideEntry::Sve2(entry) => {
                // SAFETY: no caller can provide or replace `wide_entry`.
                // Construction retained this variant only after proving both
                // SVE and SVE2 OS-usable. The array argument proves the exact
                // 32-byte input extent for every predicated load.
                unsafe { entry(&self.columns, bytes) }
            }
            #[cfg(target_arch = "x86_64")]
            WideEntry::Avx2(entry) => {
                // SAFETY: no caller can provide or replace `wide_entry`.
                // Construction retained this variant only after proving AVX2
                // OS-usable. The array argument proves the 32-byte load width.
                unsafe { entry(&self.columns, bytes) }
            }
            #[cfg(target_arch = "x86_64")]
            WideEntry::Avx512(entry) => {
                // SAFETY: no caller can provide or replace `wide_entry`.
                // Construction retained this variant only after proving
                // AVX-512F, AVX-512BW and AVX-512VL OS-usable. AVX-512VL keeps
                // every data operation at the exact 32-byte array width.
                unsafe { entry(&self.columns, bytes) }
            }
        }
    }

    /// Count set members among exactly 16 bytes.
    #[must_use]
    pub fn count_16(&self, bytes: &[u8; ASCII_NARROW_BYTES]) -> u8 {
        self.classify_16(bytes).member_count()
    }

    /// Count set members among exactly 32 bytes.
    #[must_use]
    pub fn count_32(&self, bytes: &[u8; ASCII_WIDE_BYTES]) -> u8 {
        self.classify_32(bytes).member_count()
    }
}

#[derive(Clone, Copy, Debug)]
#[cfg_attr(
    not(all(target_arch = "aarch64", target_os = "linux", target_endian = "little")),
    allow(
        dead_code,
        reason = "fixed tables keep classifier layout target-independent while only the reviewed Linux/AArch64 leaf reads them directly"
    )
)]
struct AsciiWordSpaceTables {
    word_columns: [u8; ASCII_NARROW_BYTES],
    space_values: [u8; ASCII_NARROW_BYTES],
}

impl AsciiWordSpaceTables {
    fn new() -> Self {
        Self {
            word_columns: ASCII_WORD_SET.nibble_columns(),
            space_values: ASCII_SPACE_VALUES,
        }
    }
}

#[allow(
    unsafe_code,
    reason = "the private function-pointer type represents a retained target-feature proof"
)]
type ClassifyWordSpace16Entry =
    unsafe fn(&AsciiWordSpaceTables, &[u8; ASCII_NARROW_BYTES]) -> AsciiWordSpaceMasks16;

#[allow(
    unsafe_code,
    reason = "the private function-pointer type represents a retained target-feature proof"
)]
type ClassifyWordSpace32Entry =
    unsafe fn(&AsciiWordSpaceTables, &[u8; ASCII_WIDE_BYTES]) -> AsciiWordSpaceMasks32;

#[derive(Clone, Copy, Debug)]
struct AsciiWordSpaceEntries {
    narrow: ClassifyWordSpace16Entry,
    wide: ClassifyWordSpace32Entry,
}

/// Retained fixed-block classifier for token-phrase byte classes.
///
/// Construction chooses one paired 16/32-byte implementation from immutable
/// host facts. The production token-phrase scanner does not construct this
/// handle automatically; callers must opt into the block path explicitly.
#[derive(Clone, Copy)]
pub struct AsciiWordSpaceClassifier {
    tables: AsciiWordSpaceTables,
    entries: AsciiWordSpaceEntries,
    selection: SelectionReceipt,
}

impl fmt::Debug for AsciiWordSpaceClassifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AsciiWordSpaceClassifier")
            .field("selection", &self.selection)
            .finish_non_exhaustive()
    }
}

impl AsciiWordSpaceClassifier {
    /// Build under a policy that can only remove or require authentic features.
    pub fn with_policy(policy: DispatchPolicy) -> Result<Self, UnsupportedRequiredFeatures> {
        SimdDispatchContext::capture().ascii_word_space_classifier(policy)
    }

    /// Build from an already captured, non-forgeable host snapshot.
    pub fn with_capabilities(
        capabilities: CpuCapabilities,
        policy: DispatchPolicy,
    ) -> Result<Self, UnsupportedRequiredFeatures> {
        let selected = select_word_space(capabilities, policy)?;
        Ok(Self {
            tables: AsciiWordSpaceTables::new(),
            entries: selected.entry(),
            selection: selected.receipt(),
        })
    }

    /// Require the reviewed Linux/AArch64 SVE2 fixed-16 implementation.
    #[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
    pub fn require_sve2_fixed16() -> Result<Self, UnsupportedRequiredFeatures> {
        let required = FeatureSet::EMPTY
            .with(Feature::ArmSve)
            .with(Feature::ArmSve2);
        Self::with_policy(DispatchPolicy::Require(required))
    }

    /// Stable receipt for the paired fixed-block implementation.
    #[must_use]
    pub const fn selection(&self) -> SelectionReceipt {
        self.selection
    }

    /// Classify exactly 16 bytes into word, ASCII whitespace, and other.
    #[must_use]
    #[allow(
        unsafe_code,
        reason = "construction retained the private entry only after proving its feature requirements against authentic host facts"
    )]
    pub fn classify_16(&self, bytes: &[u8; ASCII_NARROW_BYTES]) -> AsciiWordSpaceMasks16 {
        // SAFETY: callers cannot replace the entry or fixed tables, and the
        // exact array proves every source load extent.
        unsafe { (self.entries.narrow)(&self.tables, bytes) }
    }

    /// Classify exactly 32 bytes as two fixed active-16 groups.
    #[must_use]
    #[allow(
        unsafe_code,
        reason = "construction retained the private entry only after proving its feature requirements against authentic host facts"
    )]
    pub fn classify_32(&self, bytes: &[u8; ASCII_WIDE_BYTES]) -> AsciiWordSpaceMasks32 {
        // SAFETY: the retained entry and exact source extent establish the
        // same invariants as `classify_16`.
        unsafe { (self.entries.wide)(&self.tables, bytes) }
    }
}

#[allow(
    unsafe_code,
    reason = "the scalar function uses the uniform private entry ABI but executes no unsafe operation or target-specific instruction"
)]
unsafe fn scan_run_forward_scalar_entry(tables: &AsciiRunTables, bytes: &[u8]) -> AsciiRunResult {
    scalar::scan_run_forward(tables.set, bytes)
}

#[allow(
    unsafe_code,
    reason = "the scalar function uses the uniform private entry ABI but executes no unsafe operation or target-specific instruction"
)]
unsafe fn scan_run_backward_scalar_entry(tables: &AsciiRunTables, bytes: &[u8]) -> AsciiRunResult {
    scalar::scan_run_backward(tables.set, bytes)
}

const SCALAR_RUN_ENTRIES: AsciiRunEntries = AsciiRunEntries {
    forward: scan_run_forward_scalar_entry,
    backward: scan_run_backward_scalar_entry,
};

const SCALAR_RUN: KernelVariant<AsciiRunEntries> = KernelVariant::new(
    "ascii-byte-set.run.scalar.v1",
    ArchitectureRequirement::Any,
    FeatureSet::EMPTY,
    VectorKind::Scalar,
    0,
    0,
    SCALAR_RUN_ENTRIES,
);

#[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
const RUN_VARIANTS: [KernelVariant<AsciiRunEntries>; 3] = [
    SCALAR_RUN,
    // Base SVE remains independently force-selectable for qualification.
    // Generic automatic policy retains NEON until paired direct-run and
    // end-to-end consumer measurements justify a narrower tuning promotion.
    KernelVariant::new(
        "ascii-byte-set.run.sve.v1",
        ArchitectureRequirement::Exact(Architecture::Aarch64),
        FeatureSet::of(Feature::ArmSve),
        VectorKind::Scalable,
        ASCII_NARROW_BYTES,
        50,
        AsciiRunEntries {
            forward: aarch64_sve2::scan_run_forward_sve,
            backward: aarch64_sve2::scan_run_backward_sve,
        },
    ),
    KernelVariant::new(
        "ascii-byte-set.run.neon.v1",
        ArchitectureRequirement::Exact(Architecture::Aarch64),
        FeatureSet::of(Feature::ArmNeon),
        VectorKind::Fixed {
            bytes: ASCII_NARROW_VECTOR_BYTES,
        },
        ASCII_NARROW_BYTES,
        100,
        AsciiRunEntries {
            forward: aarch64::scan_run_forward_neon,
            backward: aarch64::scan_run_backward_neon,
        },
    ),
];

#[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
const RUN_MATCH_VARIANTS: [KernelVariant<AsciiRunEntries>; 5] = [
    SCALAR_RUN,
    KernelVariant::new(
        "ascii-byte-set.run.sve.v1",
        ArchitectureRequirement::Exact(Architecture::Aarch64),
        FeatureSet::of(Feature::ArmSve),
        VectorKind::Scalable,
        ASCII_NARROW_BYTES,
        50,
        AsciiRunEntries {
            forward: aarch64_sve2::scan_run_forward_sve,
            backward: aarch64_sve2::scan_run_backward_sve,
        },
    ),
    KernelVariant::new(
        "ascii-byte-set.run.sve2-match16.v1",
        ArchitectureRequirement::Exact(Architecture::Aarch64),
        FeatureSet::EMPTY
            .with(Feature::ArmSve)
            .with(Feature::ArmSve2),
        VectorKind::Scalable,
        ASCII_NARROW_BYTES,
        60,
        AsciiRunEntries {
            forward: aarch64_sve2::scan_run_forward_sve2,
            backward: aarch64_sve2::scan_run_backward_sve2,
        },
    ),
    // See RUN_VARIANTS: unqualified hardware availability authorizes entry but
    // does not itself establish that either SVE implementation beats NEON.
    KernelVariant::new(
        "ascii-byte-set.run.neon.v1",
        ArchitectureRequirement::Exact(Architecture::Aarch64),
        FeatureSet::of(Feature::ArmNeon),
        VectorKind::Fixed {
            bytes: ASCII_NARROW_VECTOR_BYTES,
        },
        ASCII_NARROW_BYTES,
        100,
        AsciiRunEntries {
            forward: aarch64::scan_run_forward_neon,
            backward: aarch64::scan_run_backward_neon,
        },
    ),
    // Neoverse V3 qualification found SVE2 decisively ahead once a run
    // survives its first block, while NEON retains the lower failed-first-block
    // cost. This composite keeps NEON's exact recovery for short runs and
    // hands only sustained runs to the fixed-16 SVE2 leaf.
    KernelVariant::new(
        "ascii-byte-set.run.neon-sve2.arm-41-d84.v1",
        ArchitectureRequirement::Exact(Architecture::Aarch64),
        FeatureSet::EMPTY
            .with(Feature::ArmNeon)
            .with(Feature::ArmSve)
            .with(Feature::ArmSve2),
        VectorKind::Scalable,
        ASCII_NARROW_BYTES,
        150,
        AsciiRunEntries {
            forward: aarch64_sve2::scan_run_forward_neon_sve2,
            backward: aarch64_sve2::scan_run_backward_neon_sve2,
        },
    )
    .when_tuning(is_neoverse_v3),
];

#[cfg(all(
    target_arch = "aarch64",
    not(all(target_os = "linux", target_endian = "little"))
))]
const RUN_VARIANTS: [KernelVariant<AsciiRunEntries>; 2] = [
    SCALAR_RUN,
    KernelVariant::new(
        "ascii-byte-set.run.neon.v1",
        ArchitectureRequirement::Exact(Architecture::Aarch64),
        FeatureSet::of(Feature::ArmNeon),
        VectorKind::Fixed {
            bytes: ASCII_NARROW_VECTOR_BYTES,
        },
        ASCII_NARROW_BYTES,
        100,
        AsciiRunEntries {
            forward: aarch64::scan_run_forward_neon,
            backward: aarch64::scan_run_backward_neon,
        },
    ),
];

#[cfg(all(
    target_arch = "aarch64",
    not(all(target_os = "linux", target_endian = "little"))
))]
const RUN_MATCH_VARIANTS: [KernelVariant<AsciiRunEntries>; 2] = RUN_VARIANTS;

#[cfg(not(target_arch = "aarch64"))]
const RUN_VARIANTS: [KernelVariant<AsciiRunEntries>; 1] = [SCALAR_RUN];

#[cfg(not(target_arch = "aarch64"))]
const RUN_MATCH_VARIANTS: [KernelVariant<AsciiRunEntries>; 1] = [SCALAR_RUN];

#[allow(
    unsafe_code,
    reason = "the scalar function uses the uniform private entry ABI but executes no unsafe operation or target-specific instruction"
)]
unsafe fn classify_16_scalar_entry(
    columns: &[u8; ASCII_NARROW_BYTES],
    bytes: &[u8; ASCII_NARROW_BYTES],
) -> AsciiMasks16 {
    scalar::classify_16(columns, bytes)
}

#[allow(
    unsafe_code,
    reason = "the scalar function uses the uniform private entry ABI but executes no unsafe operation or target-specific instruction"
)]
unsafe fn classify_word_space_16_scalar_entry(
    _tables: &AsciiWordSpaceTables,
    bytes: &[u8; ASCII_NARROW_BYTES],
) -> AsciiWordSpaceMasks16 {
    scalar::classify_word_space_16(bytes)
}

#[allow(
    unsafe_code,
    reason = "the scalar function uses the uniform private entry ABI but executes no unsafe operation or target-specific instruction"
)]
unsafe fn classify_word_space_32_scalar_entry(
    _tables: &AsciiWordSpaceTables,
    bytes: &[u8; ASCII_WIDE_BYTES],
) -> AsciiWordSpaceMasks32 {
    scalar::classify_word_space_32(bytes)
}

const SCALAR_WORD_SPACE: KernelVariant<AsciiWordSpaceEntries> = KernelVariant::new(
    "ascii-word-space.mask16x32.scalar.v1",
    ArchitectureRequirement::Any,
    FeatureSet::EMPTY,
    VectorKind::Scalar,
    ASCII_NARROW_BYTES,
    0,
    AsciiWordSpaceEntries {
        narrow: classify_word_space_16_scalar_entry,
        wide: classify_word_space_32_scalar_entry,
    },
);

#[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
const WORD_SPACE_VARIANTS: [KernelVariant<AsciiWordSpaceEntries>; 2] = [
    SCALAR_WORD_SPACE,
    KernelVariant::new(
        "ascii-word-space.mask16x32.sve2-vl16.v1",
        ArchitectureRequirement::Exact(Architecture::Aarch64),
        FeatureSet::EMPTY
            .with(Feature::ArmSve)
            .with(Feature::ArmSve2),
        VectorKind::Scalable,
        ASCII_NARROW_BYTES,
        100,
        AsciiWordSpaceEntries {
            narrow: aarch64_sve2::classify_word_space_16_sve2,
            wide: aarch64_sve2::classify_word_space_32_sve2,
        },
    ),
];

#[cfg(not(all(target_arch = "aarch64", target_os = "linux", target_endian = "little")))]
const WORD_SPACE_VARIANTS: [KernelVariant<AsciiWordSpaceEntries>; 1] = [SCALAR_WORD_SPACE];

const SCALAR_16: KernelVariant<Classify16Entry> = KernelVariant::new(
    "ascii-byte-set.mask16.scalar.v1",
    ArchitectureRequirement::Any,
    FeatureSet::EMPTY,
    VectorKind::Scalar,
    ASCII_NARROW_BYTES,
    0,
    classify_16_scalar_entry,
);

#[cfg(target_arch = "aarch64")]
const NARROW_VARIANTS: [KernelVariant<Classify16Entry>; 2] = [
    SCALAR_16,
    KernelVariant::new(
        "ascii-byte-set.mask16.neon.v1",
        ArchitectureRequirement::Exact(Architecture::Aarch64),
        FeatureSet::of(Feature::ArmNeon),
        VectorKind::Fixed {
            bytes: ASCII_NARROW_VECTOR_BYTES,
        },
        ASCII_NARROW_BYTES,
        100,
        aarch64::classify_16_neon,
    ),
];

#[cfg(target_arch = "x86_64")]
const NARROW_VARIANTS: [KernelVariant<Classify16Entry>; 3] = [
    SCALAR_16,
    KernelVariant::new(
        "ascii-byte-set.mask16.sse2.v1",
        ArchitectureRequirement::Exact(Architecture::X86_64),
        FeatureSet::of(Feature::X86Sse2),
        VectorKind::Fixed {
            bytes: ASCII_NARROW_VECTOR_BYTES,
        },
        ASCII_NARROW_BYTES,
        50,
        x86_64::classify_16_sse2,
    ),
    KernelVariant::new(
        "ascii-byte-set.mask16.ssse3.v1",
        ArchitectureRequirement::Exact(Architecture::X86_64),
        FeatureSet::of(Feature::X86Ssse3),
        VectorKind::Fixed {
            bytes: ASCII_NARROW_VECTOR_BYTES,
        },
        ASCII_NARROW_BYTES,
        100,
        x86_64::classify_16_ssse3,
    ),
];

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
const NARROW_VARIANTS: [KernelVariant<Classify16Entry>; 1] = [SCALAR_16];

const SPLIT_32: KernelVariant<WideEntry> = KernelVariant::new(
    "ascii-byte-set.mask32.split16.v1",
    ArchitectureRequirement::Any,
    FeatureSet::EMPTY,
    VectorKind::Fixed {
        bytes: ASCII_NARROW_VECTOR_BYTES,
    },
    ASCII_WIDE_BYTES,
    0,
    WideEntry::SplitNarrow,
);

#[cfg(any(
    test,
    all(target_arch = "aarch64", target_os = "linux", target_endian = "little")
))]
fn is_neoverse_v3(tuning: TuningClass) -> bool {
    matches!(
        tuning,
        TuningClass::ArmServer { cpu: Some(cpu) }
            if cpu.implementer == 0x41 && cpu.part == 0xd84
    )
}

#[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
const WIDE_VARIANTS: [KernelVariant<WideEntry>; 4] = [
    SPLIT_32,
    KernelVariant::new(
        "ascii-byte-set.mask32.sve2.v1",
        ArchitectureRequirement::Exact(Architecture::Aarch64),
        FeatureSet::EMPTY
            .with(Feature::ArmSve)
            .with(Feature::ArmSve2),
        VectorKind::Scalable,
        ASCII_WIDE_BYTES,
        50,
        WideEntry::Sve2(aarch64_sve2::classify_32_sve2),
    ),
    KernelVariant::new(
        "ascii-byte-set.mask32.split16-neon.v1",
        ArchitectureRequirement::Exact(Architecture::Aarch64),
        FeatureSet::of(Feature::ArmNeon),
        VectorKind::Fixed {
            bytes: ASCII_NARROW_VECTOR_BYTES,
        },
        ASCII_WIDE_BYTES,
        100,
        WideEntry::SplitNarrow,
    ),
    // Native c9g qualification measured this exact leaf ahead of the delegated
    // NEON composition on Neoverse V3. The tuning identity changes only
    // preference: SVE and SVE2 remain independent mandatory authorization
    // facts, and every other Arm server retains the conservative NEON winner.
    KernelVariant::new(
        "ascii-byte-set.mask32.sve2.arm-41-d84.v1",
        ArchitectureRequirement::Exact(Architecture::Aarch64),
        FeatureSet::EMPTY
            .with(Feature::ArmSve)
            .with(Feature::ArmSve2),
        VectorKind::Scalable,
        ASCII_WIDE_BYTES,
        150,
        WideEntry::Sve2(aarch64_sve2::classify_32_sve2),
    )
    .when_tuning(is_neoverse_v3),
];

#[cfg(target_arch = "x86_64")]
const X86_AVX512_MASK_FEATURES: FeatureSet = FeatureSet::EMPTY
    .with(Feature::X86Avx512F)
    .with(Feature::X86Avx512Bw)
    .with(Feature::X86Avx512Vl);

#[cfg(target_arch = "x86_64")]
const WIDE_VARIANTS: [KernelVariant<WideEntry>; 3] = [
    SPLIT_32,
    // The AVX-512 implementation is independently available to forced
    // qualification and to a future tuned entry. Generic automatic dispatch
    // conservatively retains AVX2 until fresh hardware measurements justify a
    // narrower tuning predicate with a higher preference.
    KernelVariant::new(
        "ascii-byte-set.mask32.avx512f-bw-vl.v1",
        ArchitectureRequirement::Exact(Architecture::X86_64),
        X86_AVX512_MASK_FEATURES,
        VectorKind::Fixed {
            bytes: ASCII_WIDE_VECTOR_BYTES,
        },
        ASCII_WIDE_BYTES,
        50,
        WideEntry::Avx512(x86_64::classify_32_avx512),
    ),
    KernelVariant::new(
        "ascii-byte-set.mask32.avx2.v1",
        ArchitectureRequirement::Exact(Architecture::X86_64),
        FeatureSet::of(Feature::X86Avx2),
        VectorKind::Fixed {
            bytes: ASCII_WIDE_VECTOR_BYTES,
        },
        ASCII_WIDE_BYTES,
        100,
        WideEntry::Avx2(x86_64::classify_32_avx2),
    ),
];

#[cfg(not(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "linux", target_endian = "little")
)))]
const WIDE_VARIANTS: [KernelVariant<WideEntry>; 1] = [SPLIT_32];

fn select_narrow(
    capabilities: CpuCapabilities,
    policy: DispatchPolicy,
) -> Result<SelectedKernel<Classify16Entry>, UnsupportedRequiredFeatures> {
    // The input size is the operation's invariant fixed width, never a
    // caller's or haystack's varying length.
    Ok(
        select_kernel(capabilities, policy, ASCII_NARROW_BYTES, &NARROW_VARIANTS)?
            .expect("the private table always contains its scalar fallback"),
    )
}

fn select_wide(
    capabilities: CpuCapabilities,
    policy: DispatchPolicy,
) -> Result<SelectedKernel<WideEntry>, UnsupportedRequiredFeatures> {
    // The input size is the operation's invariant fixed width, never a
    // caller's or haystack's varying length.
    Ok(
        select_kernel(capabilities, policy, ASCII_WIDE_BYTES, &WIDE_VARIANTS)?
            .expect("the private table always contains its split-narrow fallback"),
    )
}

fn select_word_space(
    capabilities: CpuCapabilities,
    policy: DispatchPolicy,
) -> Result<SelectedKernel<AsciiWordSpaceEntries>, UnsupportedRequiredFeatures> {
    Ok(select_kernel(
        capabilities,
        policy,
        ASCII_NARROW_BYTES,
        &WORD_SPACE_VARIANTS,
    )?
    .expect("the private table always contains its scalar fallback"))
}

fn select_run(
    capabilities: CpuCapabilities,
    policy: DispatchPolicy,
    match_eligible: bool,
) -> Result<SelectedKernel<AsciiRunEntries>, UnsupportedRequiredFeatures> {
    let variants = if match_eligible {
        &RUN_MATCH_VARIANTS[..]
    } else {
        &RUN_VARIANTS[..]
    };
    // Sixteen bytes is the retained implementation's invariant block shape.
    // Calls may contain any number of bytes and never participate in selection.
    Ok(
        select_kernel(capabilities, policy, ASCII_NARROW_BYTES, variants)?
            .expect("the private table always contains its scalar fallback"),
    )
}
