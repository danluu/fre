//! Scanning a maximal prefix outside one compiled ASCII byte set.
//!
//! Unlike an ASCII-complement run, high bytes are ordinary nonmembers and do
//! not stop this scanner. This makes the primitive suitable for advancing to
//! the first byte that could belong to an ASCII candidate class in arbitrary
//! byte streams.

use core::fmt;

#[cfg(feature = "static-dispatch")]
use crate::require_static_selection;
use crate::{
    ASCII_NARROW_BYTES, ASCII_WIDE_BYTES, Architecture, ArchitectureRequirement, AsciiByteSet,
    AsciiRunTableMode, AsciiRunTables, CpuCapabilities, DispatchPolicy, Feature, FeatureSet,
    HIGH_NIBBLE_BITS, KernelVariant, SelectedKernel, SelectionReceipt,
    UnsupportedRequiredFeatures, VectorKind, select_kernel,
};

/// Exact abstract work used to compile one ASCII-set nonmember scanner.
///
/// Construction traverses all 128 ASCII values once, selects one leaf, and
/// publishes one immutable handle. No haystack length participates in that
/// selection.
pub const ASCII_NONMEMBER_RUN_SCANNER_BUILD_WORK: usize = 128 + 1 + 1;

/// Maximum physical classification work beyond the logically required work.
///
/// AVX2 classifies a complete 32-byte block containing the first member. The
/// two-vector NEON loop can classify the following 16-byte half before it
/// scalar-recovers a member in the first half. Other leaves have no larger
/// excess: 16 speculative second-half lanes plus at most 16 reclassified
/// recovery lanes make the tight global bound 32.
pub const ASCII_NONMEMBER_RUN_MAX_CLASSIFICATION_OVERHEAD: usize = ASCII_WIDE_BYTES;

const SELECTION_INPUT_BYTES: usize = ASCII_WIDE_BYTES;
const NARROW_VECTOR_BYTES: u16 = 16;
#[cfg(target_arch = "x86_64")]
const WIDE_VECTOR_BYTES: u16 = 32;

const SCALAR_VARIANT_ID: &str = "ascii-byte-set.nonmember-run.scalar.v1";
#[cfg(target_arch = "aarch64")]
const NEON_VARIANT_ID: &str = "ascii-byte-set.nonmember-run.neon2x16.v1";
#[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
const SVE2_MATCH16_VARIANT_ID: &str = "ascii-byte-set.nonmember-run.sve2-match16.v1";
#[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
const SVE2_MATCH16_ARM_41_D84_VARIANT_ID: &str =
    "ascii-byte-set.nonmember-run.sve2-match16.arm-41-d84.v1";
#[cfg(target_arch = "x86_64")]
const SSE2_MATCH16_VARIANT_ID: &str = "ascii-byte-set.nonmember-run.sse2-match16.v1";
#[cfg(target_arch = "x86_64")]
const AVX2_VARIANT_ID: &str = "ascii-byte-set.nonmember-run.avx2.v1";

/// Result of scanning one maximal prefix outside a compiled ASCII byte set.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AsciiNonMemberRunResult {
    nonmember_run_len: usize,
    examined_bytes: usize,
}

impl AsciiNonMemberRunResult {
    pub(crate) const fn new(nonmember_run_len: usize, examined_bytes: usize) -> Self {
        debug_assert!(nonmember_run_len <= examined_bytes);
        Self {
            nonmember_run_len,
            examined_bytes,
        }
    }

    /// Length of the maximal prefix containing no byte in the compiled set.
    #[must_use]
    pub const fn nonmember_run_len(self) -> usize {
        self.nonmember_run_len
    }

    /// Exact number of physical byte classifications performed by the leaf.
    ///
    /// This may exceed the source length when NEON classifies a failed block
    /// and then scalar-recovers the exact member lane. The excess over the
    /// logically necessary work is bounded by
    /// [`ASCII_NONMEMBER_RUN_MAX_CLASSIFICATION_OVERHEAD`].
    #[must_use]
    pub const fn examined_bytes(self) -> usize {
        self.examined_bytes
    }
}

#[allow(
    unsafe_code,
    reason = "the private function-pointer type retains a target-feature proof selected from immutable host facts"
)]
#[cfg(not(feature = "static-dispatch"))]
type ScanEntry = unsafe fn(&AsciiRunTables, &[u8]) -> AsciiNonMemberRunResult;

#[cfg(feature = "static-dispatch")]
type ScanEntry = ();

macro_rules! scan_entry {
    ($entry:path) => {{
        #[cfg(not(feature = "static-dispatch"))]
        {
            $entry
        }
        #[cfg(feature = "static-dispatch")]
        {
            ()
        }
    }};
}

#[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
const SVE2_MATCH16_ENTRY: ScanEntry =
    scan_entry!(crate::aarch64_sve2::scan_nonmember_run_forward_sve2);

/// Compiled ASCII-set nonmember-prefix scanner with immutable one-time
/// dispatch.
///
/// The scanner accepts arbitrary slice lengths. Construction uses a fixed
/// 32-byte operation shape and never dispatches on a caller's haystack length.
#[derive(Clone, Copy)]
pub struct AsciiByteSetNonMemberScanner {
    tables: AsciiRunTables,
    #[cfg(not(feature = "static-dispatch"))]
    entry: ScanEntry,
    #[cfg(feature = "static-dispatch")]
    table_mode: AsciiRunTableMode,
    #[cfg(not(feature = "static-dispatch"))]
    selection: SelectionReceipt,
}

impl fmt::Debug for AsciiByteSetNonMemberScanner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AsciiByteSetNonMemberScanner")
            .field("set", &self.set())
            .field("selection", &self.selection())
            .finish_non_exhaustive()
    }
}

impl AsciiByteSetNonMemberScanner {
    /// Build a scanner using all OS-usable host features.
    #[must_use]
    pub fn new(set: AsciiByteSet) -> Self {
        Self::with_policy(set, DispatchPolicy::Auto)
            .expect("automatic nonmember-run dispatch always retains a scalar fallback")
    }

    /// Build a scanner under an authentic host-feature policy.
    pub fn with_policy(
        set: AsciiByteSet,
        policy: DispatchPolicy,
    ) -> Result<Self, UnsupportedRequiredFeatures> {
        crate::SimdDispatchContext::capture().ascii_byte_set_nonmember_scanner(set, policy)
    }

    pub(crate) fn with_capabilities(
        set: AsciiByteSet,
        capabilities: CpuCapabilities,
        policy: DispatchPolicy,
    ) -> Result<Self, UnsupportedRequiredFeatures> {
        #[cfg(feature = "static-dispatch")]
        if policy == DispatchPolicy::Auto && capabilities == *crate::host() {
            return Ok(Self::from_static_profile(set));
        }
        let (tables, table_mode) = set.run_tables(false);
        debug_assert_ne!(table_mode, AsciiRunTableMode::SmallComplement);
        let selected = select(capabilities, policy, table_mode)?;
        #[cfg(feature = "static-dispatch")]
        {
            let compiler_fixed = automatic_selection(table_mode);
            require_static_selection(
                selected.receipt(),
                compiler_fixed,
                static_variant_id(table_mode),
            )?;
        }
        Ok(Self {
            tables,
            #[cfg(not(feature = "static-dispatch"))]
            entry: selected.entry(),
            #[cfg(feature = "static-dispatch")]
            table_mode,
            #[cfg(not(feature = "static-dispatch"))]
            selection: selected.receipt(),
        })
    }

    #[cfg(feature = "static-dispatch")]
    pub(crate) fn from_static_profile(set: AsciiByteSet) -> Self {
        let (tables, table_mode) = set.run_tables(false);
        debug_assert_ne!(table_mode, AsciiRunTableMode::SmallComplement);
        Self { tables, table_mode }
    }

    /// ASCII byte set whose members terminate the scan.
    #[must_use]
    pub const fn set(&self) -> AsciiByteSet {
        self.tables.set
    }

    /// Stable selection receipt for the retained leaf.
    #[must_use]
    #[cfg(not(feature = "static-dispatch"))]
    pub const fn selection(&self) -> SelectionReceipt {
        self.selection
    }

    /// Compiler-fixed selection receipt.
    #[must_use]
    #[cfg(feature = "static-dispatch")]
    pub const fn selection(&self) -> SelectionReceipt {
        automatic_selection(self.table_mode)
    }

    /// Scan the maximal prefix containing no byte in the compiled ASCII set.
    ///
    /// Every high byte is a nonmember and therefore extends the prefix. The
    /// returned run length is the first possible member position, or
    /// `bytes.len()` when no member occurs.
    #[must_use]
    #[allow(
        unsafe_code,
        reason = "construction retained this private entry only after authenticating its target-feature requirements"
    )]
    pub fn scan_forward(&self, bytes: &[u8]) -> AsciiNonMemberRunResult {
        #[cfg(not(feature = "static-dispatch"))]
        {
            // SAFETY: construction authenticated the immutable retained entry,
            // and the slice proves every scalar or exact-vector load extent.
            unsafe { (self.entry)(&self.tables, bytes) }
        }
        #[cfg(feature = "static-dispatch")]
        {
            // SAFETY: construction admitted only the compiler-fixed direct
            // leaf and the slice proves every source extent.
            unsafe { static_scan(&self.tables, self.table_mode, bytes) }
        }
    }
}

fn scan_scalar(set: AsciiByteSet, bytes: &[u8]) -> AsciiNonMemberRunResult {
    for (index, &byte) in bytes.iter().enumerate() {
        if set.contains(byte) {
            return AsciiNonMemberRunResult::new(
                index,
                index
                    .checked_add(1)
                    .expect("a live slice index is below usize::MAX"),
            );
        }
    }
    AsciiNonMemberRunResult::new(bytes.len(), bytes.len())
}

#[allow(
    unsafe_code,
    reason = "the scalar leaf shares the retained-entry ABI but performs no unsafe operation"
)]
#[cfg_attr(
    feature = "static-dispatch",
    allow(
        dead_code,
        reason = "compiler-fixed builds call their direct leaf instead of retaining the runtime scalar entry"
    )
)]
unsafe fn scan_scalar_entry(
    tables: &AsciiRunTables,
    bytes: &[u8],
) -> AsciiNonMemberRunResult {
    scan_scalar(tables.set, bytes)
}

#[cfg(target_arch = "aarch64")]
#[allow(
    unsafe_code,
    reason = "this private helper performs one exact NEON load after its caller proves NEON usable"
)]
#[target_feature(enable = "neon")]
#[inline]
unsafe fn member_lanes_neon(
    columns: core::arch::aarch64::uint8x16_t,
    high_nibble_bits: core::arch::aarch64::uint8x16_t,
    bytes: &[u8; ASCII_NARROW_BYTES],
) -> core::arch::aarch64::uint8x16_t {
    use core::arch::aarch64::{
        vandq_u8, vcgtq_u8, vdupq_n_u8, vld1q_u8, vqtbl1q_u8, vshrq_n_u8,
    };

    // SAFETY: the array contains exactly the sixteen initialized bytes loaded.
    let input = unsafe { vld1q_u8(bytes.as_ptr()) };
    let low_nibbles = vandq_u8(input, vdupq_n_u8(0x0f));
    let high_nibbles = vshrq_n_u8::<4>(input);
    let selected_columns = vqtbl1q_u8(columns, low_nibbles);
    let selected_high_bits = vqtbl1q_u8(high_nibble_bits, high_nibbles);
    let selected_bits = vandq_u8(selected_columns, selected_high_bits);
    vcgtq_u8(selected_bits, vdupq_n_u8(0))
}

#[cfg(target_arch = "aarch64")]
#[allow(
    unsafe_code,
    reason = "this private target-feature leaf performs exact NEON loads only after retained dispatch proves NEON usable"
)]
#[target_feature(enable = "neon")]
#[inline(never)]
unsafe fn scan_neon(tables: &AsciiRunTables, bytes: &[u8]) -> AsciiNonMemberRunResult {
    use core::arch::aarch64::{vld1q_u8, vmaxvq_u8, vorrq_u8};

    if bytes.len() < ASCII_NARROW_BYTES {
        return scan_scalar(tables.set, bytes);
    }
    // SAFETY: both lookup tables contain exactly sixteen initialized bytes,
    // and retained/static dispatch proved NEON before entering this leaf.
    let (columns, high_nibble_bits) = unsafe {
        (
            vld1q_u8(tables.columns.as_ptr()),
            vld1q_u8(HIGH_NIBBLE_BITS.as_ptr()),
        )
    };
    let mut nonmember_run_len = 0_usize;
    let mut examined_bytes = 0_usize;
    let mut groups = bytes.chunks_exact(ASCII_WIDE_BYTES);
    for group in &mut groups {
        let first: &[u8; ASCII_NARROW_BYTES] = group[..ASCII_NARROW_BYTES]
            .try_into()
            .expect("a two-vector group has one exact first NEON block");
        let second: &[u8; ASCII_NARROW_BYTES] = group[ASCII_NARROW_BYTES..]
            .try_into()
            .expect("a two-vector group has one exact second NEON block");
        // SAFETY: both array references prove their exact load extents and
        // this leaf is itself entered only after NEON authorization.
        let (first_members, second_members) = unsafe {
            (
                member_lanes_neon(columns, high_nibble_bits, first),
                member_lanes_neon(columns, high_nibble_bits, second),
            )
        };
        examined_bytes = examined_bytes
            .checked_add(ASCII_WIDE_BYTES)
            .expect("a slice's two-vector group count fits in usize");
        if vmaxvq_u8(vorrq_u8(first_members, second_members)) != 0 {
            let (block_offset, block) = if vmaxvq_u8(first_members) != 0 {
                (0_usize, first)
            } else {
                (ASCII_NARROW_BYTES, second)
            };
            let recovery = scan_scalar(tables.set, block);
            return AsciiNonMemberRunResult::new(
                nonmember_run_len
                    .checked_add(block_offset)
                    .and_then(|length| length.checked_add(recovery.nonmember_run_len()))
                    .expect("a member lane stays within its two-vector group"),
                examined_bytes
                    .checked_add(recovery.examined_bytes())
                    .expect("two-vector probing plus one scalar block fits in usize"),
            );
        }
        nonmember_run_len = nonmember_run_len
            .checked_add(ASCII_WIDE_BYTES)
            .expect("a completed two-vector group stays within its slice");
    }

    let remainder = groups.remainder();
    let mut tail = remainder;
    if remainder.len() >= ASCII_NARROW_BYTES {
        let block: &[u8; ASCII_NARROW_BYTES] = remainder[..ASCII_NARROW_BYTES]
            .try_into()
            .expect("a wide remainder has one exact NEON block");
        // SAFETY: the block reference proves the exact load extent and this
        // leaf is entered only after NEON authorization.
        let member_lanes = unsafe { member_lanes_neon(columns, high_nibble_bits, block) };
        examined_bytes = examined_bytes
            .checked_add(ASCII_NARROW_BYTES)
            .expect("a trailing vector probe fits in usize");
        if vmaxvq_u8(member_lanes) != 0 {
            let recovery = scan_scalar(tables.set, block);
            return AsciiNonMemberRunResult::new(
                nonmember_run_len
                    .checked_add(recovery.nonmember_run_len())
                    .expect("a block boundary stays within its slice"),
                examined_bytes
                    .checked_add(recovery.examined_bytes())
                    .expect("vector probing plus one scalar block fits in usize"),
            );
        }
        nonmember_run_len = nonmember_run_len
            .checked_add(ASCII_NARROW_BYTES)
            .expect("a completed vector block stays within its slice");
        tail = &remainder[ASCII_NARROW_BYTES..];
    }

    let tail = scan_scalar(tables.set, tail);
    AsciiNonMemberRunResult::new(
        nonmember_run_len
            .checked_add(tail.nonmember_run_len())
            .expect("the vector prefix and scalar tail partition the slice"),
        examined_bytes
            .checked_add(tail.examined_bytes())
            .expect("the vector prefix and scalar tail partition the slice"),
    )
}

#[cfg(target_arch = "x86_64")]
#[allow(
    unsafe_code,
    reason = "this private target-feature leaf performs exact SSE2 loads only after retained dispatch proves SSE2 usable"
)]
#[allow(
    clippy::cast_ptr_alignment,
    reason = "_mm_loadu_si128 explicitly accepts an unaligned byte-backed address"
)]
#[cfg_attr(
    all(feature = "static-dispatch", target_feature = "avx2"),
    allow(
        dead_code,
        reason = "compiler-fixed AVX2 profiles prune the force-selectable SSE2 small-set leaf"
    )
)]
#[target_feature(enable = "sse2")]
#[inline(never)]
unsafe fn scan_sse2_match16(
    tables: &AsciiRunTables,
    bytes: &[u8],
) -> AsciiNonMemberRunResult {
    use core::arch::x86_64::{
        __m128i, _mm_cmpeq_epi8, _mm_loadu_si128, _mm_movemask_epi8, _mm_or_si128,
        _mm_set1_epi8, _mm_setzero_si128,
    };

    let [low, high] = tables.set.words();
    let member_count = usize::try_from(
        low.count_ones()
            .checked_add(high.count_ones())
            .expect("an ASCII cardinality fits in u32"),
    )
    .expect("an ASCII cardinality fits in usize");
    debug_assert!((1..=ASCII_NARROW_BYTES).contains(&member_count));
    let members = &tables.match_values[..member_count];
    let mut nonmember_run_len = 0_usize;
    let mut examined_bytes = 0_usize;
    let mut blocks = bytes.chunks_exact(ASCII_NARROW_BYTES);
    for block in &mut blocks {
        // SAFETY: `block` contains exactly 16 initialized bytes and this leaf
        // is reachable only with SSE2 authenticated.
        let input = unsafe { _mm_loadu_si128(block.as_ptr().cast::<__m128i>()) };
        let mut member_lanes = _mm_setzero_si128();
        for &member in members {
            member_lanes = _mm_or_si128(
                member_lanes,
                _mm_cmpeq_epi8(input, _mm_set1_epi8(i8::from_ne_bytes([member]))),
            );
        }
        let member_mask = u16::try_from(_mm_movemask_epi8(member_lanes))
            .expect("a 16-lane movemask has exactly 16 significant bits");
        examined_bytes = examined_bytes
            .checked_add(ASCII_NARROW_BYTES)
            .expect("a slice's vector block count fits in usize");
        if member_mask != 0 {
            let lane = usize::try_from(member_mask.trailing_zeros())
                .expect("a 16-bit lane index fits in usize");
            return AsciiNonMemberRunResult::new(
                nonmember_run_len
                    .checked_add(lane)
                    .expect("a member lane stays within its slice"),
                examined_bytes,
            );
        }
        nonmember_run_len = nonmember_run_len
            .checked_add(ASCII_NARROW_BYTES)
            .expect("a completed vector block stays within its slice");
    }
    let tail = scan_scalar(tables.set, blocks.remainder());
    AsciiNonMemberRunResult::new(
        nonmember_run_len
            .checked_add(tail.nonmember_run_len())
            .expect("the vector prefix and scalar tail partition the slice"),
        examined_bytes
            .checked_add(tail.examined_bytes())
            .expect("the vector prefix and scalar tail partition the slice"),
    )
}

#[cfg(target_arch = "x86_64")]
#[allow(
    unsafe_code,
    reason = "this private target-feature leaf performs exact AVX2 loads only after retained dispatch proves AVX2 usable"
)]
#[allow(
    clippy::cast_ptr_alignment,
    reason = "_mm256_loadu_si256 explicitly accepts an unaligned byte-backed address"
)]
#[cfg_attr(
    all(feature = "static-dispatch", not(target_feature = "avx2")),
    allow(
        dead_code,
        reason = "compiler-fixed non-AVX2 profiles prune the runtime AVX2 leaf"
    )
)]
#[target_feature(enable = "avx2")]
#[inline(never)]
unsafe fn scan_avx2(tables: &AsciiRunTables, bytes: &[u8]) -> AsciiNonMemberRunResult {
    use core::arch::x86_64::{
        __m128i, __m256i, _mm_loadu_si128, _mm256_and_si256, _mm256_broadcastsi128_si256,
        _mm256_cmpeq_epi8, _mm256_loadu_si256, _mm256_movemask_epi8, _mm256_set1_epi8,
        _mm256_setzero_si256, _mm256_shuffle_epi8, _mm256_srli_epi16,
    };

    // SAFETY: both lookup arrays contain exactly 16 initialized bytes. AVX2
    // dispatch proves the broadcast/load instructions usable.
    let (columns, high_nibble_bits) = unsafe {
        (
            _mm_loadu_si128(tables.columns.as_ptr().cast::<__m128i>()),
            _mm_loadu_si128(HIGH_NIBBLE_BITS.as_ptr().cast::<__m128i>()),
        )
    };
    let columns = _mm256_broadcastsi128_si256(columns);
    let high_nibble_bits = _mm256_broadcastsi128_si256(high_nibble_bits);
    let nibble_mask = _mm256_set1_epi8(0x0f);
    let mut nonmember_run_len = 0_usize;
    let mut examined_bytes = 0_usize;
    let mut blocks = bytes.chunks_exact(ASCII_WIDE_BYTES);
    for block in &mut blocks {
        // SAFETY: `block` contains exactly 32 initialized bytes.
        let input = unsafe { _mm256_loadu_si256(block.as_ptr().cast::<__m256i>()) };
        let low_nibbles = _mm256_and_si256(input, nibble_mask);
        let high_nibbles = _mm256_and_si256(_mm256_srli_epi16::<4>(input), nibble_mask);
        let selected_columns = _mm256_shuffle_epi8(columns, low_nibbles);
        let selected_high_bits = _mm256_shuffle_epi8(high_nibble_bits, high_nibbles);
        let selected_bits = _mm256_and_si256(selected_columns, selected_high_bits);
        let zero_lanes = _mm256_cmpeq_epi8(selected_bits, _mm256_setzero_si256());
        let member_mask = !_mm256_movemask_epi8(zero_lanes).cast_unsigned();
        examined_bytes = examined_bytes
            .checked_add(ASCII_WIDE_BYTES)
            .expect("a slice's vector block count fits in usize");
        if member_mask != 0 {
            let lane = usize::try_from(member_mask.trailing_zeros())
                .expect("a 32-bit lane index fits in usize");
            return AsciiNonMemberRunResult::new(
                nonmember_run_len
                    .checked_add(lane)
                    .expect("a member lane stays within its slice"),
                examined_bytes,
            );
        }
        nonmember_run_len = nonmember_run_len
            .checked_add(ASCII_WIDE_BYTES)
            .expect("a completed vector block stays within its slice");
    }
    let tail = scan_scalar(tables.set, blocks.remainder());
    AsciiNonMemberRunResult::new(
        nonmember_run_len
            .checked_add(tail.nonmember_run_len())
            .expect("the vector prefix and scalar tail partition the slice"),
        examined_bytes
            .checked_add(tail.examined_bytes())
            .expect("the vector prefix and scalar tail partition the slice"),
    )
}

const SCALAR: KernelVariant<ScanEntry> = KernelVariant::new(
    SCALAR_VARIANT_ID,
    ArchitectureRequirement::Any,
    FeatureSet::EMPTY,
    VectorKind::Scalar,
    0,
    0,
    scan_entry!(scan_scalar_entry),
);

#[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
const GENERIC_VARIANTS: [KernelVariant<ScanEntry>; 2] = [
    SCALAR,
    KernelVariant::new(
        NEON_VARIANT_ID,
        ArchitectureRequirement::Exact(Architecture::Aarch64),
        FeatureSet::of(Feature::ArmNeon),
        VectorKind::Fixed {
            bytes: NARROW_VECTOR_BYTES,
        },
        ASCII_WIDE_BYTES,
        100,
        scan_entry!(scan_neon),
    ),
];

#[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
const SMALL_MEMBER_VARIANTS: [KernelVariant<ScanEntry>; 4] = [
    SCALAR,
    KernelVariant::new(
        SVE2_MATCH16_VARIANT_ID,
        ArchitectureRequirement::Exact(Architecture::Aarch64),
        FeatureSet::EMPTY
            .with(Feature::ArmSve)
            .with(Feature::ArmSve2),
        VectorKind::Scalable,
        ASCII_NARROW_BYTES,
        60,
        SVE2_MATCH16_ENTRY,
    ),
    KernelVariant::new(
        NEON_VARIANT_ID,
        ArchitectureRequirement::Exact(Architecture::Aarch64),
        FeatureSet::of(Feature::ArmNeon),
        VectorKind::Fixed {
            bytes: NARROW_VECTOR_BYTES,
        },
        ASCII_WIDE_BYTES,
        100,
        scan_entry!(scan_neon),
    ),
    KernelVariant::new(
        SVE2_MATCH16_ARM_41_D84_VARIANT_ID,
        ArchitectureRequirement::Exact(Architecture::Aarch64),
        FeatureSet::EMPTY
            .with(Feature::ArmSve)
            .with(Feature::ArmSve2),
        VectorKind::Scalable,
        ASCII_NARROW_BYTES,
        150,
        SVE2_MATCH16_ENTRY,
    )
    .when_tuning(crate::is_neoverse_v3),
];

#[cfg(all(
    target_arch = "aarch64",
    not(all(target_os = "linux", target_endian = "little"))
))]
const GENERIC_VARIANTS: [KernelVariant<ScanEntry>; 2] = [
    SCALAR,
    KernelVariant::new(
        NEON_VARIANT_ID,
        ArchitectureRequirement::Exact(Architecture::Aarch64),
        FeatureSet::of(Feature::ArmNeon),
        VectorKind::Fixed {
            bytes: NARROW_VECTOR_BYTES,
        },
        ASCII_WIDE_BYTES,
        100,
        scan_entry!(scan_neon),
    ),
];

#[cfg(all(
    target_arch = "aarch64",
    not(all(target_os = "linux", target_endian = "little"))
))]
const SMALL_MEMBER_VARIANTS: [KernelVariant<ScanEntry>; 2] = GENERIC_VARIANTS;

#[cfg(target_arch = "x86_64")]
const GENERIC_VARIANTS: [KernelVariant<ScanEntry>; 2] = [
    SCALAR,
    KernelVariant::new(
        AVX2_VARIANT_ID,
        ArchitectureRequirement::Exact(Architecture::X86_64),
        FeatureSet::of(Feature::X86Avx2),
        VectorKind::Fixed {
            bytes: WIDE_VECTOR_BYTES,
        },
        ASCII_WIDE_BYTES,
        100,
        scan_entry!(scan_avx2),
    ),
];

#[cfg(target_arch = "x86_64")]
const SMALL_MEMBER_VARIANTS: [KernelVariant<ScanEntry>; 3] = [
    SCALAR,
    KernelVariant::new(
        SSE2_MATCH16_VARIANT_ID,
        ArchitectureRequirement::Exact(Architecture::X86_64),
        FeatureSet::of(Feature::X86Sse2),
        VectorKind::Fixed {
            bytes: NARROW_VECTOR_BYTES,
        },
        ASCII_NARROW_BYTES,
        50,
        scan_entry!(scan_sse2_match16),
    ),
    KernelVariant::new(
        AVX2_VARIANT_ID,
        ArchitectureRequirement::Exact(Architecture::X86_64),
        FeatureSet::of(Feature::X86Avx2),
        VectorKind::Fixed {
            bytes: WIDE_VECTOR_BYTES,
        },
        ASCII_WIDE_BYTES,
        100,
        scan_entry!(scan_avx2),
    ),
];

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
const GENERIC_VARIANTS: [KernelVariant<ScanEntry>; 1] = [SCALAR];

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
const SMALL_MEMBER_VARIANTS: [KernelVariant<ScanEntry>; 1] = [SCALAR];

fn select(
    capabilities: CpuCapabilities,
    policy: DispatchPolicy,
    table_mode: AsciiRunTableMode,
) -> Result<SelectedKernel<ScanEntry>, UnsupportedRequiredFeatures> {
    let variants = match table_mode {
        AsciiRunTableMode::SmallMembers => &SMALL_MEMBER_VARIANTS[..],
        AsciiRunTableMode::Generic | AsciiRunTableMode::SmallComplement => &GENERIC_VARIANTS[..],
    };
    Ok(
        select_kernel(capabilities, policy, SELECTION_INPUT_BYTES, variants)?
            .expect("the nonmember-run table always contains its scalar fallback"),
    )
}

#[cfg(all(feature = "static-dispatch-arm-41-d84", feature = "static-dispatch"))]
const fn automatic_selection(table_mode: AsciiRunTableMode) -> SelectionReceipt {
    match table_mode {
        AsciiRunTableMode::SmallMembers => crate::compiler_selection_receipt(
            SVE2_MATCH16_ARM_41_D84_VARIANT_ID,
            None,
            FeatureSet::EMPTY
                .with(Feature::ArmSve)
                .with(Feature::ArmSve2),
            VectorKind::Scalable,
            SELECTION_INPUT_BYTES,
            ASCII_NARROW_BYTES,
        ),
        AsciiRunTableMode::Generic | AsciiRunTableMode::SmallComplement => {
            crate::compiler_selection_receipt(
                NEON_VARIANT_ID,
                None,
                FeatureSet::of(Feature::ArmNeon),
                VectorKind::Fixed {
                    bytes: NARROW_VECTOR_BYTES,
                },
                SELECTION_INPUT_BYTES,
                ASCII_WIDE_BYTES,
            )
        }
    }
}

#[cfg(all(
    feature = "static-dispatch",
    not(feature = "static-dispatch-arm-41-d84"),
    target_arch = "aarch64",
    target_feature = "neon"
))]
const fn automatic_selection(_table_mode: AsciiRunTableMode) -> SelectionReceipt {
    crate::compiler_selection_receipt(
        NEON_VARIANT_ID,
        None,
        FeatureSet::of(Feature::ArmNeon),
        VectorKind::Fixed {
            bytes: NARROW_VECTOR_BYTES,
        },
        SELECTION_INPUT_BYTES,
        ASCII_WIDE_BYTES,
    )
}

#[cfg(all(
    feature = "static-dispatch",
    not(feature = "static-dispatch-arm-41-d84"),
    target_arch = "aarch64",
    target_os = "linux",
    target_endian = "little",
    not(target_feature = "neon"),
    target_feature = "sve",
    target_feature = "sve2"
))]
const fn automatic_selection(table_mode: AsciiRunTableMode) -> SelectionReceipt {
    match table_mode {
        AsciiRunTableMode::SmallMembers => crate::compiler_selection_receipt(
            SVE2_MATCH16_VARIANT_ID,
            None,
            FeatureSet::EMPTY
                .with(Feature::ArmSve)
                .with(Feature::ArmSve2),
            VectorKind::Scalable,
            SELECTION_INPUT_BYTES,
            ASCII_NARROW_BYTES,
        ),
        AsciiRunTableMode::Generic | AsciiRunTableMode::SmallComplement => {
            crate::compiler_selection_receipt(
                SCALAR_VARIANT_ID,
                None,
                FeatureSet::EMPTY,
                VectorKind::Scalar,
                SELECTION_INPUT_BYTES,
                0,
            )
        }
    }
}

#[cfg(all(
    feature = "static-dispatch",
    target_arch = "x86_64",
    target_feature = "avx2"
))]
const fn automatic_selection(_table_mode: AsciiRunTableMode) -> SelectionReceipt {
    crate::compiler_selection_receipt(
        AVX2_VARIANT_ID,
        None,
        FeatureSet::of(Feature::X86Avx2),
        VectorKind::Fixed {
            bytes: WIDE_VECTOR_BYTES,
        },
        SELECTION_INPUT_BYTES,
        ASCII_WIDE_BYTES,
    )
}

#[cfg(all(
    feature = "static-dispatch",
    target_arch = "x86_64",
    not(target_feature = "avx2"),
    target_feature = "sse2"
))]
const fn automatic_selection(table_mode: AsciiRunTableMode) -> SelectionReceipt {
    match table_mode {
        AsciiRunTableMode::SmallMembers => crate::compiler_selection_receipt(
            SSE2_MATCH16_VARIANT_ID,
            None,
            FeatureSet::of(Feature::X86Sse2),
            VectorKind::Fixed {
                bytes: NARROW_VECTOR_BYTES,
            },
            SELECTION_INPUT_BYTES,
            ASCII_NARROW_BYTES,
        ),
        AsciiRunTableMode::Generic | AsciiRunTableMode::SmallComplement => {
            crate::compiler_selection_receipt(
                SCALAR_VARIANT_ID,
                None,
                FeatureSet::EMPTY,
                VectorKind::Scalar,
                SELECTION_INPUT_BYTES,
                0,
            )
        }
    }
}

#[cfg(all(
    feature = "static-dispatch",
    not(any(
        feature = "static-dispatch-arm-41-d84",
        all(target_arch = "aarch64", target_feature = "neon"),
        all(
            target_arch = "aarch64",
            target_os = "linux",
            target_endian = "little",
            not(target_feature = "neon"),
            target_feature = "sve",
            target_feature = "sve2"
        ),
        all(target_arch = "x86_64", target_feature = "avx2"),
        all(
            target_arch = "x86_64",
            not(target_feature = "avx2"),
            target_feature = "sse2"
        )
    ))
))]
const fn automatic_selection(_table_mode: AsciiRunTableMode) -> SelectionReceipt {
    crate::compiler_selection_receipt(
        SCALAR_VARIANT_ID,
        None,
        FeatureSet::EMPTY,
        VectorKind::Scalar,
        SELECTION_INPUT_BYTES,
        0,
    )
}

#[cfg(feature = "static-dispatch")]
const fn static_variant_id(table_mode: AsciiRunTableMode) -> &'static str {
    automatic_selection(table_mode).variant_id
}

#[cfg(all(feature = "static-dispatch-arm-41-d84", feature = "static-dispatch"))]
#[allow(
    unsafe_code,
    reason = "the Arm 0x41/d84 profile proves NEON, SVE and SVE2 before either direct leaf is reachable"
)]
unsafe fn static_scan(
    tables: &AsciiRunTables,
    table_mode: AsciiRunTableMode,
    bytes: &[u8],
) -> AsciiNonMemberRunResult {
    match table_mode {
        AsciiRunTableMode::SmallMembers => {
            // SAFETY: the profile proves SVE/SVE2 and construction produced a
            // nonempty exact MATCH table.
            unsafe { crate::aarch64_sve2::scan_nonmember_run_forward_sve2(tables, bytes) }
        }
        AsciiRunTableMode::Generic | AsciiRunTableMode::SmallComplement => {
            // SAFETY: the profile independently proves NEON.
            unsafe { scan_neon(tables, bytes) }
        }
    }
}

#[cfg(all(
    feature = "static-dispatch",
    not(feature = "static-dispatch-arm-41-d84"),
    target_arch = "aarch64",
    target_feature = "neon"
))]
#[allow(
    unsafe_code,
    reason = "the compiler-fixed profile proves NEON before the direct leaf is reachable"
)]
unsafe fn static_scan(
    tables: &AsciiRunTables,
    _table_mode: AsciiRunTableMode,
    bytes: &[u8],
) -> AsciiNonMemberRunResult {
    // SAFETY: NEON is compiler-enabled and required by the accepted receipt.
    unsafe { scan_neon(tables, bytes) }
}

#[cfg(all(
    feature = "static-dispatch",
    not(feature = "static-dispatch-arm-41-d84"),
    target_arch = "aarch64",
    target_os = "linux",
    target_endian = "little",
    not(target_feature = "neon"),
    target_feature = "sve",
    target_feature = "sve2"
))]
#[allow(
    unsafe_code,
    reason = "the compiler-fixed profile proves SVE/SVE2 before the direct small-set leaf is reachable"
)]
unsafe fn static_scan(
    tables: &AsciiRunTables,
    table_mode: AsciiRunTableMode,
    bytes: &[u8],
) -> AsciiNonMemberRunResult {
    match table_mode {
        AsciiRunTableMode::SmallMembers => {
            // SAFETY: construction produced a nonempty exact MATCH table.
            unsafe { crate::aarch64_sve2::scan_nonmember_run_forward_sve2(tables, bytes) }
        }
        AsciiRunTableMode::Generic | AsciiRunTableMode::SmallComplement => {
            scan_scalar(tables.set, bytes)
        }
    }
}

#[cfg(all(
    feature = "static-dispatch",
    target_arch = "x86_64",
    target_feature = "avx2"
))]
#[allow(
    unsafe_code,
    reason = "the compiler-fixed profile proves AVX2 before the direct leaf is reachable"
)]
unsafe fn static_scan(
    tables: &AsciiRunTables,
    _table_mode: AsciiRunTableMode,
    bytes: &[u8],
) -> AsciiNonMemberRunResult {
    // SAFETY: AVX2 is compiler-enabled and required by the accepted receipt.
    unsafe { scan_avx2(tables, bytes) }
}

#[cfg(all(
    feature = "static-dispatch",
    target_arch = "x86_64",
    not(target_feature = "avx2"),
    target_feature = "sse2"
))]
#[allow(
    unsafe_code,
    reason = "the compiler-fixed profile proves SSE2 before the direct small-set leaf is reachable"
)]
unsafe fn static_scan(
    tables: &AsciiRunTables,
    table_mode: AsciiRunTableMode,
    bytes: &[u8],
) -> AsciiNonMemberRunResult {
    match table_mode {
        AsciiRunTableMode::SmallMembers => {
            // SAFETY: SSE2 is compiler-enabled and construction produced a
            // nonempty MATCH table.
            unsafe { scan_sse2_match16(tables, bytes) }
        }
        AsciiRunTableMode::Generic | AsciiRunTableMode::SmallComplement => {
            scan_scalar(tables.set, bytes)
        }
    }
}

#[cfg(all(
    feature = "static-dispatch",
    not(any(
        feature = "static-dispatch-arm-41-d84",
        all(target_arch = "aarch64", target_feature = "neon"),
        all(
            target_arch = "aarch64",
            target_os = "linux",
            target_endian = "little",
            not(target_feature = "neon"),
            target_feature = "sve",
            target_feature = "sve2"
        ),
        all(target_arch = "x86_64", target_feature = "avx2"),
        all(
            target_arch = "x86_64",
            not(target_feature = "avx2"),
            target_feature = "sse2"
        )
    ))
))]
#[allow(
    unsafe_code,
    reason = "the scalar function shares the compiler-fixed ABI but performs no unsafe operation"
)]
unsafe fn static_scan(
    tables: &AsciiRunTables,
    _table_mode: AsciiRunTableMode,
    bytes: &[u8],
) -> AsciiNonMemberRunResult {
    scan_scalar(tables.set, bytes)
}

#[cfg(test)]
mod tests {
    use super::{
        ASCII_NARROW_BYTES, ASCII_NONMEMBER_RUN_MAX_CLASSIFICATION_OVERHEAD,
        ASCII_NONMEMBER_RUN_SCANNER_BUILD_WORK, AsciiByteSetNonMemberScanner,
        ASCII_WIDE_BYTES, AsciiNonMemberRunResult, SCALAR_VARIANT_ID, SELECTION_INPUT_BYTES,
        scan_scalar,
    };
    use crate::{AsciiByteSet, DispatchPolicy, Feature, VectorKind};
    #[cfg(any(not(feature = "static-dispatch"), target_arch = "aarch64"))]
    use crate::FeatureSet;
    #[cfg(not(feature = "static-dispatch"))]
    use crate::SimdDispatchContext;

    fn singleton(byte: u8) -> AsciiByteSet {
        assert!(byte.is_ascii());
        if byte < 64 {
            AsciiByteSet::from_words([1_u64 << byte, 0])
        } else {
            AsciiByteSet::from_words([0, 1_u64 << byte.wrapping_sub(64)])
        }
    }

    fn first_member(set: AsciiByteSet) -> Option<u8> {
        (0_u8..=0x7f).find(|&byte| set.contains(byte))
    }

    fn nonmember(set: AsciiByteSet, index: usize) -> u8 {
        const VALUES: [u8; 10] = [
            0x80, 0xff, b'!', 0x00, 0xc1, b'a', b'9', 0x7f, 0x90, b' ',
        ];
        for offset in 0..VALUES.len() {
            let candidate = VALUES[(index + offset) % VALUES.len()];
            if !set.contains(candidate) {
                return candidate;
            }
        }
        0x80
    }

    fn next_random(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[cfg(not(feature = "static-dispatch"))]
    #[test]
    fn scalar_exhausts_every_ascii_terminator_length_boundary_and_alignment() {
        for member in 0_u8..=0x7f {
            let set = singleton(member);
            let scanner = AsciiByteSetNonMemberScanner::with_policy(
                set,
                DispatchPolicy::Portable,
            )
            .expect("portable scalar scanner");
            assert_eq!(scanner.selection().variant_id, SCALAR_VARIANT_ID);
            assert!(scanner.selection().required.is_empty());
            assert_eq!(scanner.selection().vector, VectorKind::Scalar);
            for len in 0_usize..=65 {
                for offset in 0_usize..=7 {
                    let mut storage = vec![0_u8; offset + len];
                    let bytes = &mut storage[offset..];
                    for boundary in 0..=len {
                        for (index, byte) in bytes.iter_mut().enumerate() {
                            *byte = nonmember(set, index);
                        }
                        if boundary < len {
                            bytes[boundary] = member;
                        }
                        assert_eq!(
                            scanner.scan_forward(bytes),
                            AsciiNonMemberRunResult::new(
                                boundary,
                                boundary + usize::from(boundary < len),
                            ),
                            "member={member:#04x} len={len} offset={offset} boundary={boundary}",
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn automatic_exhausts_vector_boundaries_alignments_and_table_shapes() {
        let sets = [
            AsciiByteSet::EMPTY,
            singleton(b'!'),
            AsciiByteSet::from_words([0x8000_0000_0000_0001, 0x8000_0000_0000_0001]),
            AsciiByteSet::from_words([0xaaaa_aaaa_aaaa_aaaa, 0x5555_5555_5555_5555]),
            AsciiByteSet::ALL,
        ];
        for set in sets {
            let scanner = AsciiByteSetNonMemberScanner::new(set);
            for len in 0_usize..=97 {
                for offset in 0_usize..=31 {
                    let mut storage = vec![0_u8; offset + len];
                    let bytes = &mut storage[offset..];
                    let boundaries: Vec<usize> = match first_member(set) {
                        Some(_) => (0..=len).collect(),
                        None => vec![len],
                    };
                    for boundary in boundaries {
                        for (index, byte) in bytes.iter_mut().enumerate() {
                            *byte = nonmember(set, index);
                        }
                        if boundary < len {
                            bytes[boundary] = first_member(set).expect("nonempty set");
                        }
                        let observed = scanner.scan_forward(bytes);
                        assert_eq!(observed.nonmember_run_len(), boundary);
                        let logical = boundary + usize::from(boundary < len);
                        assert!(observed.examined_bytes() >= logical);
                        assert!(
                            observed.examined_bytes()
                                <= logical + ASCII_NONMEMBER_RUN_MAX_CLASSIFICATION_OVERHEAD,
                            "set={set:?} len={len} offset={offset} boundary={boundary} observed={observed:?}",
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn automatic_matches_an_independent_oracle_for_arbitrary_sets_and_bytes() {
        let mut state = 0xa916_85d3_4c72_0bf1_u64;
        for _ in 0..10_000 {
            let set = AsciiByteSet::from_words([
                next_random(&mut state),
                next_random(&mut state),
            ]);
            let scanner = AsciiByteSetNonMemberScanner::new(set);
            let len = usize::from(next_random(&mut state).to_le_bytes()[0]);
            let offset = usize::from(next_random(&mut state).to_le_bytes()[0] & 0x3f);
            let mut storage = vec![0_u8; offset + len];
            for byte in &mut storage[offset..] {
                *byte = next_random(&mut state).to_le_bytes()[0];
            }
            let bytes = &storage[offset..];
            let expected = bytes
                .iter()
                .position(|&byte| set.contains(byte))
                .unwrap_or(bytes.len());
            let observed = scanner.scan_forward(bytes);
            assert_eq!(observed.nonmember_run_len(), expected);
            let logical = expected + usize::from(expected < bytes.len());
            assert!(observed.examined_bytes() >= logical);
            assert!(
                observed.examined_bytes()
                    <= logical + ASCII_NONMEMBER_RUN_MAX_CLASSIFICATION_OVERHEAD,
            );
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn neon_two_vector_groups_preserve_exact_boundary_and_work_accounting() {
        if !crate::host().usable().contains(Feature::ArmNeon) {
            return;
        }
        let set = AsciiByteSet::from_words([0x0000_0000_0001_ffff, 0]);
        let scanner = AsciiByteSetNonMemberScanner::with_policy(
            set,
            DispatchPolicy::AllowOnly(FeatureSet::of(Feature::ArmNeon)),
        )
        .expect("the authentic AArch64 host supports the NEON scanner");
        assert_eq!(
            scanner.selection().variant_id,
            "ascii-byte-set.nonmember-run.neon2x16.v1",
        );
        assert_eq!(scanner.selection().minimum_input_bytes, ASCII_WIDE_BYTES);

        for len in 0_usize..=97 {
            for boundary in 0..=len {
                let mut bytes = vec![0x80; len];
                if boundary < len {
                    bytes[boundary] = 0;
                }
                let observed = scanner.scan_forward(&bytes);
                assert_eq!(observed.nonmember_run_len(), boundary);
                assert_eq!(
                    observed.examined_bytes(),
                    expected_neon_examined_bytes(len, boundary),
                    "len={len} boundary={boundary}",
                );
            }
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn expected_neon_examined_bytes(len: usize, boundary: usize) -> usize {
        if boundary == len {
            return len;
        }
        let group_start = (boundary / ASCII_WIDE_BYTES) * ASCII_WIDE_BYTES;
        if group_start + ASCII_WIDE_BYTES <= len {
            return group_start
                + ASCII_WIDE_BYTES
                + (boundary - group_start) % ASCII_NARROW_BYTES
                + 1;
        }
        if len - group_start >= ASCII_NARROW_BYTES
            && boundary < group_start + ASCII_NARROW_BYTES
        {
            return group_start + ASCII_NARROW_BYTES + (boundary - group_start) + 1;
        }
        boundary + 1
    }

    #[test]
    fn mixed_high_and_ascii_nonmembers_continue_until_an_actual_member() {
        let bytes = [0x80, 0xff, b'!', 0x00, 0xc1];
        let zero = AsciiByteSetNonMemberScanner::new(singleton(0x00));
        assert_eq!(zero.scan_forward(&bytes).nonmember_run_len(), 3);
        let bang = AsciiByteSetNonMemberScanner::new(singleton(b'!'));
        assert_eq!(bang.scan_forward(&bytes).nonmember_run_len(), 2);
        let absent = AsciiByteSetNonMemberScanner::new(singleton(b'z'));
        assert_eq!(absent.scan_forward(&bytes).nonmember_run_len(), bytes.len());
    }

    #[test]
    fn scalar_oracle_handles_empty_full_and_arbitrary_high_bytes() {
        assert_eq!(
            scan_scalar(AsciiByteSet::EMPTY, &[0x80, b'a', 0xff]),
            AsciiNonMemberRunResult::new(3, 3),
        );
        assert_eq!(
            scan_scalar(AsciiByteSet::ALL, &[0x80, 0xff, b'a']),
            AsciiNonMemberRunResult::new(2, 3),
        );
        assert_eq!(
            scan_scalar(AsciiByteSet::ALL, &[0x80, 0xff]),
            AsciiNonMemberRunResult::new(2, 2),
        );
    }

    #[cfg(not(feature = "static-dispatch"))]
    #[test]
    fn receipts_use_fixed_shape_and_are_stable_across_clones_and_threads() {
        let context = SimdDispatchContext::capture();
        let portable = context
            .ascii_byte_set_nonmember_scanner(singleton(b'x'), DispatchPolicy::Portable)
            .expect("portable scanner");
        let receipt = portable.selection();
        assert_eq!(receipt.variant_id, SCALAR_VARIANT_ID);
        assert_eq!(receipt.delegate_variant_id, None);
        assert_eq!(receipt.selection_input_bytes, SELECTION_INPUT_BYTES);
        assert_eq!(receipt.minimum_input_bytes, 0);
        assert_eq!(receipt.required, FeatureSet::EMPTY);
        assert_eq!(receipt.vector, VectorKind::Scalar);

        let scanner = AsciiByteSetNonMemberScanner::new(singleton(b'x'));
        let expected = scanner.selection();
        let cloned = scanner;
        assert_eq!(cloned.selection(), expected);
        let observed = std::thread::spawn(move || {
            assert_eq!(cloned.scan_forward(b"abcx").nonmember_run_len(), 3);
            cloned.selection()
        })
        .join()
        .expect("scanner thread");
        assert_eq!(observed, expected);
    }

    #[test]
    fn automatic_receipt_exactly_describes_the_direct_leaf() {
        let receipt = AsciiByteSetNonMemberScanner::new(singleton(b'x')).selection();
        let capabilities = *crate::host();
        assert_eq!(receipt.delegate_variant_id, None);
        assert_eq!(receipt.policy, DispatchPolicy::Auto);
        assert_eq!(receipt.architecture, capabilities.architecture());
        assert_eq!(receipt.host_tuning, capabilities.tuning());
        assert_eq!(receipt.host_evidence, capabilities.evidence());
        assert_eq!(receipt.host_reported, capabilities.reported());
        assert_eq!(receipt.policy_usable, capabilities.usable());
        assert_eq!(receipt.selection_input_bytes, SELECTION_INPUT_BYTES);
        match receipt.variant_id {
            SCALAR_VARIANT_ID => {
                assert_eq!(receipt.required, crate::FeatureSet::EMPTY);
                assert_eq!(receipt.vector, VectorKind::Scalar);
                assert_eq!(receipt.minimum_input_bytes, 0);
            }
            "ascii-byte-set.nonmember-run.neon2x16.v1" => {
                assert_eq!(receipt.required, crate::FeatureSet::of(Feature::ArmNeon));
                assert_eq!(receipt.vector, VectorKind::Fixed { bytes: 16 });
                assert_eq!(receipt.minimum_input_bytes, 32);
            }
            "ascii-byte-set.nonmember-run.sse2-match16.v1" => {
                assert_eq!(receipt.required, crate::FeatureSet::of(Feature::X86Sse2));
                assert_eq!(receipt.vector, VectorKind::Fixed { bytes: 16 });
                assert_eq!(receipt.minimum_input_bytes, 16);
            }
            "ascii-byte-set.nonmember-run.avx2.v1" => {
                assert_eq!(receipt.required, crate::FeatureSet::of(Feature::X86Avx2));
                assert_eq!(receipt.vector, VectorKind::Fixed { bytes: 32 });
                assert_eq!(receipt.minimum_input_bytes, 32);
            }
            "ascii-byte-set.nonmember-run.sve2-match16.v1"
            | "ascii-byte-set.nonmember-run.sve2-match16.arm-41-d84.v1" => {
                assert_eq!(
                    receipt.required,
                    crate::FeatureSet::EMPTY
                        .with(Feature::ArmSve)
                        .with(Feature::ArmSve2),
                );
                assert_eq!(receipt.vector, VectorKind::Scalable);
                assert_eq!(receipt.minimum_input_bytes, 16);
            }
            other => panic!("unexpected nonmember scanner variant {other}"),
        }
    }

    #[test]
    fn construction_work_and_result_layout_are_exact() {
        assert_eq!(ASCII_NONMEMBER_RUN_SCANNER_BUILD_WORK, 130);
        assert_eq!(ASCII_NONMEMBER_RUN_MAX_CLASSIFICATION_OVERHEAD, 32);
        assert_eq!(
            core::mem::size_of::<AsciiNonMemberRunResult>(),
            2 * core::mem::size_of::<usize>(),
        );
    }

    #[cfg(all(feature = "static-dispatch", target_pointer_width = "64"))]
    #[test]
    fn compiler_fixed_handle_retains_only_exact_tables_and_mode() {
        assert_eq!(core::mem::size_of::<AsciiByteSetNonMemberScanner>(), 56);
    }

    #[cfg(all(not(feature = "static-dispatch"), target_pointer_width = "64"))]
    #[test]
    fn runtime_handle_retains_exact_tables_entry_and_receipt() {
        assert_eq!(core::mem::size_of::<AsciiByteSetNonMemberScanner>(), 224);
    }

    #[cfg(feature = "static-dispatch")]
    #[test]
    fn compiler_fixed_receipts_match_runtime_selection_contract() {
        for set in [singleton(b'x'), AsciiByteSet::ALL] {
            let scanner = AsciiByteSetNonMemberScanner::new(set);
            let (_, table_mode) = set.run_tables(false);
            assert_eq!(
                scanner.selection(),
                super::select(*crate::host(), DispatchPolicy::Auto, table_mode)
                    .expect("automatic selection")
                    .receipt(),
            );
            assert_eq!(scanner.selection().policy, DispatchPolicy::Auto);
            assert_eq!(scanner.selection().variant_id, super::static_variant_id(table_mode));
        }
    }

    #[cfg(feature = "static-dispatch")]
    #[test]
    fn compiler_fixed_vector_profile_rejects_portable_retargeting() {
        let automatic = AsciiByteSetNonMemberScanner::new(singleton(b'x'));
        if automatic.selection().variant_id != SCALAR_VARIANT_ID {
            let error = AsciiByteSetNonMemberScanner::with_policy(
                singleton(b'x'),
                DispatchPolicy::Portable,
            )
            .expect_err("portable policy cannot retarget a fixed vector leaf");
            assert!(!error.required.is_empty());
            assert!(error.usable.is_empty());
        }
    }
}
