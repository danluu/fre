//! Compact exact classification for one arbitrary 256-bit byte set.
//!
//! A byte's low nibble selects one byte from each of two 16-byte tables. The
//! selected byte contains membership bits for high nibbles `0..=7` or
//! `8..=15`; the input high bit selects the table half. This is the one-column
//! specialization of the general byte-bucket kernel, retaining only 32 table
//! bytes instead of its four-column capacity.

use core::fmt;

#[cfg(feature = "static-dispatch")]
use crate::require_static_selection;
#[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
use crate::TuningClass;
use crate::{
    Architecture, ArchitectureRequirement, CpuCapabilities, DispatchPolicy, Feature, FeatureSet,
    KernelVariant, SelectedKernel, SelectionReceipt, UnsupportedRequiredFeatures, VectorKind,
    select_kernel,
};

/// Bytes classified by one fixed-width invocation.
pub const BYTE_SET_BLOCK_BYTES: usize = 16;
/// Bytes classified by the optional wide candidate-stream operation.
pub const BYTE_SET_WIDE_BLOCK_BYTES: usize = 32;
/// Candidate-stream width authenticated entirely by the compiler profile.
///
/// Ordinary portable and runtime-dispatched builds deliberately retain the
/// 16-byte operation. A 32-byte operation is admitted only for a static
/// profile with a reviewed native leaf; callers never infer width from a
/// varying input or perform feature detection in the operation loop.
#[cfg(any(
    all(
        feature = "static-dispatch-arm-41-d84",
        target_arch = "aarch64",
        target_os = "linux",
        target_endian = "little",
        target_feature = "sve",
        target_feature = "sve2"
    ),
    all(
        feature = "static-dispatch",
        target_arch = "x86_64",
        target_feature = "avx2"
    )
))]
pub const BYTE_SET_CANDIDATE_BLOCK_BYTES: usize = BYTE_SET_WIDE_BLOCK_BYTES;
/// Portable candidate streams retain the narrow, split-safe operation.
#[cfg(not(any(
    all(
        feature = "static-dispatch-arm-41-d84",
        target_arch = "aarch64",
        target_os = "linux",
        target_endian = "little",
        target_feature = "sve",
        target_feature = "sve2"
    ),
    all(
        feature = "static-dispatch",
        target_arch = "x86_64",
        target_feature = "avx2"
    )
)))]
pub const BYTE_SET_CANDIDATE_BLOCK_BYTES: usize = BYTE_SET_BLOCK_BYTES;
/// Exact abstract work to visit all byte values and bind both immutable leaves.
#[cfg(any(
    feature = "static-dispatch",
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "linux", target_endian = "little")
))]
pub const BYTE_SET_CLASSIFIER_BUILD_WORK: usize = 256 + 2;
/// Exact abstract work when this target has no direct wide runtime tier.
#[cfg(not(any(
    feature = "static-dispatch",
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "linux", target_endian = "little")
)))]
pub const BYTE_SET_CLASSIFIER_BUILD_WORK: usize = 256 + 1;

const BYTE_SET_VECTOR_BYTES: u16 = 16;
#[cfg(target_arch = "x86_64")]
const BYTE_SET_WIDE_VECTOR_BYTES: u16 = 32;
const SCALAR_VARIANT_ID: &str = "byte-set.mask16.scalar.v1";
#[cfg_attr(
    any(
        all(
            feature = "static-dispatch-arm-41-d84",
            target_arch = "aarch64",
            target_os = "linux",
            target_endian = "little",
            target_feature = "sve",
            target_feature = "sve2"
        ),
        all(
            feature = "static-dispatch",
            target_arch = "x86_64",
            target_feature = "avx2"
        )
    ),
    allow(
        dead_code,
        reason = "authenticated native 32-lane static profiles do not retain the portable split-16 receipt"
    )
)]
const SPLIT_MASK32_VARIANT_ID: &str = "byte-set.mask32.split16.v1";
#[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
const SVE2_MASK32_VARIANT_ID: &str = "byte-set.mask32.sve2.v1";
#[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
const SVE2_ARM_41_D84_MASK32_VARIANT_ID: &str = "byte-set.mask32.sve2.arm-41-d84.v1";
#[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
const SPLIT_NEON_MASK32_VARIANT_ID: &str = "byte-set.mask32.split16-neon.v1";
#[cfg(target_arch = "x86_64")]
const AVX2_MASK32_VARIANT_ID: &str = "byte-set.mask32.avx2.v1";
#[cfg(target_arch = "aarch64")]
const NEON_VARIANT_ID: &str = "byte-set.mask16.neon.v1";
#[cfg(target_arch = "x86_64")]
const SSSE3_VARIANT_ID: &str = "byte-set.mask16.ssse3.v1";

/// Canonical 256-bit byte membership set.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ByteSet256([u64; 4]);

impl ByteSet256 {
    /// Bind four canonical little-byte-order bitmap words.
    #[must_use]
    pub const fn from_words(words: [u64; 4]) -> Self {
        Self(words)
    }

    /// Canonical bitmap words, where bit `b` represents byte `b`.
    #[must_use]
    pub const fn words(self) -> [u64; 4] {
        self.0
    }

    /// Whether this set contains `byte`.
    #[must_use]
    pub fn contains(self, byte: u8) -> bool {
        let word = usize::from(byte >> 6);
        let bit = u32::from(byte & 63);
        self.0[word] & (1_u64 << bit) != 0
    }

    fn tables(self) -> ByteSetTables {
        let mut lower = [0_u8; 16];
        let mut upper = [0_u8; 16];
        for byte in 0_u16..=u16::from(u8::MAX) {
            let byte = u8::try_from(byte).expect("the fixed byte domain fits in u8");
            if !self.contains(byte) {
                continue;
            }
            let low = usize::from(byte & 0x0f);
            let high = byte >> 4;
            if high < 8 {
                lower[low] |= 1_u8 << high;
            } else {
                upper[low] |= 1_u8
                    << high
                        .checked_sub(8)
                        .expect("the upper high-nibble half starts at eight");
            }
        }
        ByteSetTables { lower, upper }
    }

    #[cfg(all(
        target_arch = "aarch64",
        target_os = "linux",
        target_endian = "little",
        target_feature = "sve",
        target_feature = "sve2"
    ))]
    fn match_values16(self) -> Option<[u8; 16]> {
        let word_bits = usize::try_from(u64::BITS).ok()?;
        let mut values = [0_u8; 16];
        let mut members = 0_usize;
        for (word_index, mut word) in self.0.into_iter().enumerate() {
            while word != 0 {
                if members == values.len() {
                    return None;
                }
                let bit = word.trailing_zeros();
                let byte = word_index
                    .checked_mul(word_bits)?
                    .checked_add(usize::try_from(bit).ok()?)?;
                values[members] = u8::try_from(byte).ok()?;
                members = members.checked_add(1)?;
                word &= word.wrapping_sub(1);
            }
        }
        if members == 0 {
            return None;
        }
        let first = values[0];
        values[members..].fill(first);
        Some(values)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ByteSetTables {
    pub(super) lower: [u8; 16],
    pub(super) upper: [u8; 16],
}

/// Membership lanes for one exact 16-byte block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteSetMask16(u16);

impl ByteSetMask16 {
    pub(crate) const fn new(member_mask: u16) -> Self {
        Self(member_mask)
    }

    /// Bit `i` is set exactly when source byte `i` belongs to the set.
    #[must_use]
    pub const fn member_mask(self) -> u16 {
        self.0
    }
}

/// Membership lanes for one exact 32-byte block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteSetMask32(u32);

impl ByteSetMask32 {
    pub(crate) const fn new(member_mask: u32) -> Self {
        Self(member_mask)
    }

    #[cfg_attr(
        any(
            all(
                feature = "static-dispatch-arm-41-d84",
                target_arch = "aarch64",
                target_os = "linux",
                target_endian = "little",
                target_feature = "sve",
                target_feature = "sve2"
            ),
            all(
                feature = "static-dispatch",
                target_arch = "x86_64",
                target_feature = "avx2"
            )
        ),
        allow(
            dead_code,
            reason = "authenticated native-wide profiles do not execute the portable split operation"
        )
    )]
    pub(crate) fn from_halves(first: ByteSetMask16, second: ByteSetMask16) -> Self {
        Self::new(u32::from(first.member_mask()) | (u32::from(second.member_mask()) << 16))
    }

    /// Bit `i` is set exactly when source byte `i` belongs to the set.
    #[must_use]
    pub const fn member_mask(self) -> u32 {
        self.0
    }
}

#[allow(
    unsafe_code,
    reason = "the private function-pointer type retains a target-feature proof selected from immutable host facts"
)]
#[cfg(not(feature = "static-dispatch"))]
type ByteSetEntry = unsafe fn(&ByteSetTables, &[u8; BYTE_SET_BLOCK_BYTES]) -> ByteSetMask16;

#[cfg(feature = "static-dispatch")]
type ByteSetEntry = ();

macro_rules! byte_set_entry {
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

/// Compiled arbitrary byte-set classifier with one immutable dispatch choice.
#[derive(Clone, Copy)]
pub struct ByteSetClassifier {
    set: ByteSet256,
    tables: ByteSetTables,
    #[cfg(not(feature = "static-dispatch"))]
    entry: ByteSetEntry,
    #[cfg(not(feature = "static-dispatch"))]
    selection: SelectionReceipt,
}

impl fmt::Debug for ByteSetClassifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ByteSetClassifier")
            .field("set", &self.set)
            .field("selection", &self.selection())
            .field("wide_selection", &self.wide_selection())
            .finish_non_exhaustive()
    }
}

impl ByteSetClassifier {
    /// Build under all OS-usable host features.
    #[must_use]
    pub fn new(set: ByteSet256) -> Self {
        Self::with_policy(set, DispatchPolicy::Auto)
            .expect("automatic byte-set dispatch always retains a scalar fallback")
    }

    /// Build under an authentic host-feature policy.
    pub fn with_policy(
        set: ByteSet256,
        policy: DispatchPolicy,
    ) -> Result<Self, UnsupportedRequiredFeatures> {
        crate::SimdDispatchContext::capture().byte_set_classifier(set, policy)
    }

    pub(crate) fn with_capabilities(
        set: ByteSet256,
        capabilities: CpuCapabilities,
        policy: DispatchPolicy,
    ) -> Result<Self, UnsupportedRequiredFeatures> {
        #[cfg(feature = "static-dispatch")]
        if policy == DispatchPolicy::Auto && capabilities == *crate::host() {
            return Ok(Self::from_static_profile(set));
        }
        let selected = select(capabilities, policy)?;
        #[cfg(any(
            feature = "static-dispatch",
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_os = "linux", target_endian = "little")
        ))]
        let wide = select_wide(capabilities, policy)?;
        #[cfg(all(
            not(feature = "static-dispatch"),
            any(
                target_arch = "x86_64",
                all(target_arch = "aarch64", target_os = "linux", target_endian = "little")
            )
        ))]
        assert_eq!(
            wide.receipt().variant_id,
            runtime_wide_selection(selected.receipt()).variant_id,
            "the compact wide receipt must reproduce table selection"
        );
        #[cfg(feature = "static-dispatch")]
        {
            require_static_selection(
                selected.receipt(),
                automatic_selection(),
                static_variant_id(),
            )?;
            require_static_selection(
                wide.receipt(),
                automatic_wide_selection(automatic_selection()),
                static_wide_variant_id(),
            )?;
        }
        Ok(Self {
            set,
            tables: set.tables(),
            #[cfg(not(feature = "static-dispatch"))]
            entry: selected.entry(),
            #[cfg(not(feature = "static-dispatch"))]
            selection: selected.receipt(),
        })
    }

    #[cfg(feature = "static-dispatch")]
    pub(crate) fn from_static_profile(set: ByteSet256) -> Self {
        Self {
            set,
            tables: set.tables(),
        }
    }

    /// The exact byte set compiled into this classifier.
    #[must_use]
    pub const fn set(&self) -> ByteSet256 {
        self.set
    }

    #[cfg(all(
        not(feature = "static-dispatch"),
        target_arch = "aarch64",
        target_os = "linux",
        target_endian = "little",
        target_feature = "sve",
        target_feature = "sve2"
    ))]
    const fn supports_small_mixed_whole_slice_sve2(&self) -> bool {
        self.selection.policy_usable.contains(Feature::ArmSve)
            && self.selection.policy_usable.contains(Feature::ArmSve2)
    }

    #[cfg(all(
        feature = "static-dispatch-arm-41-d84",
        target_arch = "aarch64",
        target_os = "linux",
        target_endian = "little",
        target_feature = "sve",
        target_feature = "sve2"
    ))]
    const fn supports_small_mixed_whole_slice_sve2(&self) -> bool {
        true
    }

    #[cfg(all(
        feature = "static-dispatch",
        not(feature = "static-dispatch-arm-41-d84"),
        target_arch = "aarch64",
        target_os = "linux",
        target_endian = "little",
        target_feature = "sve",
        target_feature = "sve2"
    ))]
    const fn supports_small_mixed_whole_slice_sve2(&self) -> bool {
        false
    }

    /// Stable selection receipt for this fixed-width operation.
    #[must_use]
    #[cfg(not(feature = "static-dispatch"))]
    pub const fn selection(&self) -> SelectionReceipt {
        self.selection
    }

    /// Compiler-fixed selection receipt.
    #[must_use]
    #[cfg(feature = "static-dispatch")]
    pub const fn selection(&self) -> SelectionReceipt {
        automatic_selection()
    }

    /// Stable receipt for the actual candidate-stream loop operation.
    ///
    /// Split-wide implementations retain the authenticated 16-byte leaf;
    /// runtime or compiler-static native-wide implementations report 32 bytes.
    #[must_use]
    pub const fn candidate_selection(&self) -> SelectionReceipt {
        if self.candidate_block_bytes() == BYTE_SET_WIDE_BLOCK_BYTES {
            self.wide_selection()
        } else {
            self.selection()
        }
    }

    /// Width of the direct candidate-stream leaf selected at construction.
    ///
    /// Split-wide implementations retain the authenticated 16-byte child;
    /// native SVE2 and AVX2 leaves expose their direct 32-byte width.
    #[must_use]
    pub const fn candidate_block_bytes(&self) -> usize {
        #[cfg(not(feature = "static-dispatch"))]
        {
            if runtime_has_direct_wide(self.selection) {
                return BYTE_SET_WIDE_BLOCK_BYTES;
            }
        }
        BYTE_SET_CANDIDATE_BLOCK_BYTES
    }

    /// Stable receipt for the explicit 32-byte classification operation.
    #[must_use]
    #[cfg(not(feature = "static-dispatch"))]
    pub const fn wide_selection(&self) -> SelectionReceipt {
        runtime_wide_selection(self.selection)
    }

    /// Compiler-fixed receipt for the explicit 32-byte operation.
    #[must_use]
    #[cfg(feature = "static-dispatch")]
    pub const fn wide_selection(&self) -> SelectionReceipt {
        automatic_wide_selection(automatic_selection())
    }

    /// Classify exactly sixteen bytes.
    #[must_use]
    #[allow(
        unsafe_code,
        reason = "construction retained this private entry only after proving its target features; the fixed array proves the complete source extent"
    )]
    pub fn classify_16(&self, bytes: &[u8; BYTE_SET_BLOCK_BYTES]) -> ByteSetMask16 {
        #[cfg(not(feature = "static-dispatch"))]
        {
            // SAFETY: immutable construction authenticated the retained leaf,
            // and the fixed array proves its exact input extent.
            unsafe { (self.entry)(&self.tables, bytes) }
        }
        #[cfg(feature = "static-dispatch")]
        {
            // SAFETY: the compiler profile proves the direct static leaf.
            unsafe { static_classify(&self.tables, bytes) }
        }
    }

    /// Classify exactly 32 bytes.
    ///
    /// The general fallback is exactly two already-authenticated 16-byte
    /// operations. Runtime and compiler-static profiles may replace that
    /// composition with one construction-authenticated native wide leaf.
    #[must_use]
    #[allow(
        unsafe_code,
        reason = "immutable runtime or compiler-static dispatch proves every native wide leaf; the fixed array proves its complete source extent"
    )]
    pub fn classify_32(&self, bytes: &[u8; BYTE_SET_WIDE_BLOCK_BYTES]) -> ByteSetMask32 {
        #[cfg(all(not(feature = "static-dispatch"), target_arch = "x86_64"))]
        {
            if runtime_has_direct_wide(self.selection) {
                // SAFETY: the immutable narrow receipt contains the authentic
                // policy-visible AVX2 fact used to reconstruct wide selection.
                return unsafe { classify_32_avx2(&self.tables, bytes) };
            }
            let first: &[u8; BYTE_SET_BLOCK_BYTES] = bytes[..BYTE_SET_BLOCK_BYTES]
                .try_into()
                .expect("the first wide half is exactly sixteen bytes");
            let second: &[u8; BYTE_SET_BLOCK_BYTES] = bytes[BYTE_SET_BLOCK_BYTES..]
                .try_into()
                .expect("the second wide half is exactly sixteen bytes");
            ByteSetMask32::from_halves(self.classify_16(first), self.classify_16(second))
        }
        #[cfg(all(
            not(feature = "static-dispatch"),
            target_arch = "aarch64",
            target_os = "linux",
            target_endian = "little"
        ))]
        {
            if runtime_has_direct_wide(self.selection) {
                // SAFETY: the immutable narrow receipt contains the authentic
                // policy-visible SVE/SVE2 and V3 tuning facts used to
                // reconstruct wide selection.
                return unsafe {
                    crate::aarch64_sve2::classify_byte_set_32_sve2(&self.tables, bytes)
                };
            }
            let first: &[u8; BYTE_SET_BLOCK_BYTES] = bytes[..BYTE_SET_BLOCK_BYTES]
                .try_into()
                .expect("the first wide half is exactly sixteen bytes");
            let second: &[u8; BYTE_SET_BLOCK_BYTES] = bytes[BYTE_SET_BLOCK_BYTES..]
                .try_into()
                .expect("the second wide half is exactly sixteen bytes");
            ByteSetMask32::from_halves(self.classify_16(first), self.classify_16(second))
        }
        #[cfg(all(
            not(feature = "static-dispatch"),
            not(any(
                target_arch = "x86_64",
                all(target_arch = "aarch64", target_os = "linux", target_endian = "little")
            ))
        ))]
        {
            let first: &[u8; BYTE_SET_BLOCK_BYTES] = bytes[..BYTE_SET_BLOCK_BYTES]
                .try_into()
                .expect("the first wide half is exactly sixteen bytes");
            let second: &[u8; BYTE_SET_BLOCK_BYTES] = bytes[BYTE_SET_BLOCK_BYTES..]
                .try_into()
                .expect("the second wide half is exactly sixteen bytes");
            ByteSetMask32::from_halves(self.classify_16(first), self.classify_16(second))
        }
        #[cfg(all(
            feature = "static-dispatch",
            feature = "static-dispatch-arm-41-d84",
            target_arch = "aarch64",
            target_os = "linux",
            target_endian = "little",
            target_feature = "sve",
            target_feature = "sve2"
        ))]
        {
            // SAFETY: the authenticated static profile proves SVE/SVE2, and
            // the fixed source array proves the complete 32-byte extent.
            unsafe { crate::aarch64_sve2::classify_byte_set_32_sve2(&self.tables, bytes) }
        }
        #[cfg(all(
            feature = "static-dispatch",
            target_arch = "x86_64",
            target_feature = "avx2"
        ))]
        {
            // SAFETY: the authenticated static profile proves AVX2, and the
            // fixed source array proves the complete 32-byte extent.
            unsafe { classify_32_avx2(&self.tables, bytes) }
        }
        #[cfg(all(
            feature = "static-dispatch",
            not(any(
                all(
                    feature = "static-dispatch-arm-41-d84",
                    target_arch = "aarch64",
                    target_os = "linux",
                    target_endian = "little",
                    target_feature = "sve",
                    target_feature = "sve2"
                ),
                all(target_arch = "x86_64", target_feature = "avx2")
            ))
        ))]
        {
            let first: &[u8; BYTE_SET_BLOCK_BYTES] = bytes[..BYTE_SET_BLOCK_BYTES]
                .try_into()
                .expect("the first wide half is exactly sixteen bytes");
            let second: &[u8; BYTE_SET_BLOCK_BYTES] = bytes[BYTE_SET_BLOCK_BYTES..]
                .try_into()
                .expect("the second wide half is exactly sixteen bytes");
            ByteSetMask32::from_halves(self.classify_16(first), self.classify_16(second))
        }
    }

    /// Find the first byte belonging to this compiled set.
    ///
    /// Runtime builds independently admit whole-slice vector leaves from their
    /// retained policy-visible features before entering a loop; compiler-static
    /// builds call their fixed leaves directly. Thus a long scan does not
    /// repeat indirect dispatch for every classified block.
    #[must_use]
    #[allow(
        unsafe_code,
        reason = "the retained or compiler-fixed receipt proves the target features for the selected whole-slice leaf"
    )]
    pub fn find_first_member(&self, bytes: &[u8]) -> Option<usize> {
        #[cfg(all(
            target_arch = "aarch64",
            target_os = "linux",
            target_endian = "little",
            target_feature = "sve",
            target_feature = "sve2"
        ))]
        {
            let [lower_low, lower_high, upper_low, upper_high] = self.set().words();
            if self.supports_small_mixed_whole_slice_sve2()
                && (lower_low != 0 || lower_high != 0)
                && (upper_low != 0 || upper_high != 0)
                && let Some(match_values) = self.set().match_values16()
            {
                return find_first_member_values16_sve2(match_values, self.set(), bytes);
            }
        }
        #[cfg(not(feature = "static-dispatch"))]
        {
            #[cfg(target_arch = "x86_64")]
            if runtime_has_direct_wide(self.selection) {
                // SAFETY: the retained wide selection reconstructs AVX2 only
                // from the immutable authenticated policy-visible features.
                return unsafe { find_first_member_avx2(self, bytes) };
            }
            #[cfg(all(
                target_arch = "aarch64",
                target_os = "linux",
                target_endian = "little"
            ))]
            if runtime_has_direct_wide(self.selection)
                && bytes.len() >= BYTE_SET_WIDE_BLOCK_BYTES
            {
                // SAFETY: the retained wide selection reconstructs SVE2 only
                // from immutable authenticated policy-visible SVE and SVE2
                // features. The whole-slice leaf proves every fixed load from
                // complete chunks, then delegates one complete narrow tail
                // block through this classifier's retained authority.
                return unsafe {
                    find_first_member_sve2(self, bytes)
                };
            }
            if matches!(self.selection.vector, VectorKind::Scalar) {
                return find_first_member_scalar(self.set(), bytes);
            }
            #[cfg(target_arch = "aarch64")]
            {
                // SAFETY: the only non-scalar narrow AArch64 variant requires
                // NEON in the immutable retained receipt.
                if is_ascii_set(self.set()) {
                    return unsafe {
                        find_first_ascii_member_neon(&self.tables, self.set(), bytes)
                    };
                }
                if is_high_only_set(self.set()) {
                    return unsafe {
                        find_first_high_member_neon(&self.tables, self.set(), bytes)
                    };
                }
                unsafe { find_first_member_neon(&self.tables, self.set(), bytes) }
            }
            #[cfg(target_arch = "x86_64")]
            {
                // SAFETY: the only non-scalar narrow x86-64 variant requires
                // SSSE3 in the immutable retained receipt.
                unsafe { find_first_member_ssse3(&self.tables, self.set(), bytes) }
            }
            #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
            find_first_member_scalar(self.set(), bytes)
        }
        #[cfg(feature = "static-dispatch")]
        {
            #[cfg(all(
                feature = "static-dispatch-arm-41-d84",
                target_arch = "aarch64",
                target_os = "linux",
                target_endian = "little",
                target_feature = "sve",
                target_feature = "sve2"
            ))]
            {
                if bytes.len() >= BYTE_SET_WIDE_BLOCK_BYTES {
                    // SAFETY: SVE2 is fixed in the authenticated compiler
                    // profile. The whole-slice leaf proves every fixed load
                    // from complete chunks, then delegates one complete
                    // narrow tail block through this classifier.
                    return unsafe {
                        find_first_member_sve2(self, bytes)
                    };
                }
            }
            #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
            {
                // SAFETY: AVX2 is fixed in the authenticated compiler profile.
                unsafe { find_first_member_avx2(self, bytes) }
            }
            #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
            {
                // SAFETY: NEON is fixed in the authenticated compiler profile.
                if is_ascii_set(self.set()) {
                    return unsafe {
                        find_first_ascii_member_neon(&self.tables, self.set(), bytes)
                    };
                }
                if is_high_only_set(self.set()) {
                    return unsafe {
                        find_first_high_member_neon(&self.tables, self.set(), bytes)
                    };
                }
                unsafe { find_first_member_neon(&self.tables, self.set(), bytes) }
            }
            #[cfg(all(
                target_arch = "x86_64",
                not(target_feature = "avx2"),
                target_feature = "ssse3"
            ))]
            {
                // SAFETY: SSSE3 is fixed in the authenticated compiler profile.
                unsafe { find_first_member_ssse3(&self.tables, self.set(), bytes) }
            }
            #[cfg(not(any(
                all(target_arch = "x86_64", target_feature = "avx2"),
                all(target_arch = "aarch64", target_feature = "neon"),
                all(
                    target_arch = "x86_64",
                    not(target_feature = "avx2"),
                    target_feature = "ssse3"
                )
            )))]
            find_first_member_scalar(self.set(), bytes)
        }
    }

    /// Find the last byte belonging to this compiled set.
    ///
    /// Runtime builds choose one whole-slice leaf from the immutable retained
    /// dispatch receipt before entering the reverse block loop. Compiler-static
    /// builds call their fixed leaf directly. Complete blocks are anchored at
    /// the end of the slice, so only the prefix shorter than one vector remains
    /// scalar.
    #[must_use]
    #[allow(
        unsafe_code,
        reason = "the retained or compiler-fixed receipt proves the target features for the selected whole-slice leaf"
    )]
    pub fn find_last_member(&self, bytes: &[u8]) -> Option<usize> {
        #[cfg(not(feature = "static-dispatch"))]
        {
            #[cfg(target_arch = "x86_64")]
            if runtime_has_direct_wide(self.selection) {
                // SAFETY: the retained wide selection reconstructs AVX2 only
                // from the immutable authenticated policy-visible features.
                return unsafe { find_last_member_avx2(self, bytes) };
            }
            #[cfg(all(
                target_arch = "aarch64",
                target_os = "linux",
                target_endian = "little"
            ))]
            if runtime_has_direct_wide(self.selection)
                && bytes.len() >= BYTE_SET_WIDE_BLOCK_BYTES
            {
                // SAFETY: the retained wide selection reconstructs SVE2 only
                // from immutable authenticated policy-visible SVE and SVE2
                // features. Every complete reverse block has an exact extent.
                return unsafe { find_last_member_sve2(self, bytes) };
            }
            if matches!(self.selection.vector, VectorKind::Scalar) {
                return find_last_member_scalar(self.set(), bytes);
            }
            #[cfg(target_arch = "aarch64")]
            {
                // SAFETY: the only non-scalar narrow AArch64 variant requires
                // NEON in the immutable retained receipt.
                unsafe { find_last_member_neon(&self.tables, self.set(), bytes) }
            }
            #[cfg(target_arch = "x86_64")]
            {
                // SAFETY: the only non-scalar narrow x86-64 variant requires
                // SSSE3 in the immutable retained receipt.
                unsafe { find_last_member_ssse3(&self.tables, self.set(), bytes) }
            }
            #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
            find_last_member_scalar(self.set(), bytes)
        }
        #[cfg(feature = "static-dispatch")]
        {
            #[cfg(all(
                feature = "static-dispatch-arm-41-d84",
                target_arch = "aarch64",
                target_os = "linux",
                target_endian = "little",
                target_feature = "sve",
                target_feature = "sve2"
            ))]
            {
                if bytes.len() >= BYTE_SET_WIDE_BLOCK_BYTES {
                    // SAFETY: SVE2 is fixed in the authenticated compiler
                    // profile and every complete reverse block is exact.
                    return unsafe { find_last_member_sve2(self, bytes) };
                }
            }
            #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
            {
                // SAFETY: AVX2 is fixed in the authenticated compiler profile.
                unsafe { find_last_member_avx2(self, bytes) }
            }
            #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
            {
                // SAFETY: NEON is fixed in the authenticated compiler profile.
                unsafe { find_last_member_neon(&self.tables, self.set(), bytes) }
            }
            #[cfg(all(
                target_arch = "x86_64",
                not(target_feature = "avx2"),
                target_feature = "ssse3"
            ))]
            {
                // SAFETY: SSSE3 is fixed in the authenticated compiler profile.
                unsafe { find_last_member_ssse3(&self.tables, self.set(), bytes) }
            }
            #[cfg(not(any(
                all(target_arch = "x86_64", target_feature = "avx2"),
                all(target_arch = "aarch64", target_feature = "neon"),
                all(
                    target_arch = "x86_64",
                    not(target_feature = "avx2"),
                    target_feature = "ssse3"
                )
            )))]
            find_last_member_scalar(self.set(), bytes)
        }
    }
}

#[cfg(all(not(feature = "static-dispatch"), target_arch = "x86_64"))]
const fn runtime_has_direct_wide(narrow: SelectionReceipt) -> bool {
    narrow.policy_usable.contains(Feature::X86Avx2)
}

#[cfg(all(not(feature = "static-dispatch"), target_arch = "x86_64"))]
const fn runtime_wide_selection(narrow: SelectionReceipt) -> SelectionReceipt {
    if runtime_has_direct_wide(narrow) {
        SelectionReceipt {
            variant_id: AVX2_MASK32_VARIANT_ID,
            delegate_variant_id: None,
            required: FeatureSet::of(Feature::X86Avx2),
            vector: VectorKind::Fixed {
                bytes: BYTE_SET_WIDE_VECTOR_BYTES,
            },
            selection_input_bytes: BYTE_SET_WIDE_BLOCK_BYTES,
            minimum_input_bytes: BYTE_SET_WIDE_BLOCK_BYTES,
            ..narrow
        }
    } else {
        SelectionReceipt {
            variant_id: SPLIT_MASK32_VARIANT_ID,
            delegate_variant_id: Some(narrow.variant_id),
            selection_input_bytes: BYTE_SET_WIDE_BLOCK_BYTES,
            minimum_input_bytes: BYTE_SET_WIDE_BLOCK_BYTES,
            ..narrow
        }
    }
}

#[cfg(all(
    not(feature = "static-dispatch"),
    target_arch = "aarch64",
    target_os = "linux",
    target_endian = "little"
))]
const fn runtime_has_direct_wide(narrow: SelectionReceipt) -> bool {
    let sve2 = narrow.policy_usable.contains(Feature::ArmSve)
        && narrow.policy_usable.contains(Feature::ArmSve2);
    let neoverse_v3 = matches!(
        narrow.host_tuning,
        TuningClass::ArmServer { cpu: Some(cpu) }
            if cpu.implementer == 0x41 && cpu.part == 0xd84
    );
    sve2 && (neoverse_v3 || !narrow.policy_usable.contains(Feature::ArmNeon))
}

#[cfg(all(
    not(feature = "static-dispatch"),
    target_arch = "aarch64",
    target_os = "linux",
    target_endian = "little"
))]
const fn runtime_wide_selection(narrow: SelectionReceipt) -> SelectionReceipt {
    if runtime_has_direct_wide(narrow) {
        let variant_id = match narrow.host_tuning {
            TuningClass::ArmServer { cpu: Some(cpu) }
                if cpu.implementer == 0x41 && cpu.part == 0xd84 =>
            {
                SVE2_ARM_41_D84_MASK32_VARIANT_ID
            }
            _ => SVE2_MASK32_VARIANT_ID,
        };
        SelectionReceipt {
            variant_id,
            delegate_variant_id: None,
            required: FeatureSet::EMPTY
                .with(Feature::ArmSve)
                .with(Feature::ArmSve2),
            vector: VectorKind::Scalable,
            selection_input_bytes: BYTE_SET_WIDE_BLOCK_BYTES,
            minimum_input_bytes: BYTE_SET_WIDE_BLOCK_BYTES,
            ..narrow
        }
    } else {
        let variant_id = if narrow.policy_usable.contains(Feature::ArmNeon) {
            SPLIT_NEON_MASK32_VARIANT_ID
        } else {
            SPLIT_MASK32_VARIANT_ID
        };
        SelectionReceipt {
            variant_id,
            delegate_variant_id: Some(narrow.variant_id),
            selection_input_bytes: BYTE_SET_WIDE_BLOCK_BYTES,
            minimum_input_bytes: BYTE_SET_WIDE_BLOCK_BYTES,
            ..narrow
        }
    }
}

#[cfg(all(
    not(feature = "static-dispatch"),
    not(any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_os = "linux", target_endian = "little")
    ))
))]
const fn runtime_has_direct_wide(_narrow: SelectionReceipt) -> bool {
    false
}

#[cfg(all(
    not(feature = "static-dispatch"),
    not(any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_os = "linux", target_endian = "little")
    ))
))]
const fn runtime_wide_selection(narrow: SelectionReceipt) -> SelectionReceipt {
    SelectionReceipt {
        variant_id: SPLIT_MASK32_VARIANT_ID,
        delegate_variant_id: Some(narrow.variant_id),
        selection_input_bytes: BYTE_SET_WIDE_BLOCK_BYTES,
        minimum_input_bytes: BYTE_SET_WIDE_BLOCK_BYTES,
        ..narrow
    }
}

#[allow(
    unsafe_code,
    reason = "the scalar leaf shares the retained-entry ABI but performs no unsafe operation"
)]
#[cfg_attr(
    feature = "static-dispatch",
    allow(
        dead_code,
        reason = "compiler-fixed builds call their direct static leaf instead of retaining the runtime scalar entry"
    )
)]
unsafe fn classify_scalar_entry(
    tables: &ByteSetTables,
    bytes: &[u8; BYTE_SET_BLOCK_BYTES],
) -> ByteSetMask16 {
    classify_scalar(tables, bytes)
}

#[cfg_attr(
    all(feature = "static-dispatch", not(test)),
    allow(
        dead_code,
        reason = "compiler-fixed vector profiles retain the scalar oracle only in tests"
    )
)]
fn classify_scalar(tables: &ByteSetTables, bytes: &[u8; BYTE_SET_BLOCK_BYTES]) -> ByteSetMask16 {
    let mut members = 0_u16;
    for (lane, &byte) in bytes.iter().enumerate() {
        let high = byte >> 4;
        let columns = if high < 8 {
            &tables.lower
        } else {
            &tables.upper
        };
        if columns[usize::from(byte & 0x0f)] & (1_u8 << (high & 7)) != 0 {
            members |= 1_u16 << lane;
        }
    }
    ByteSetMask16(members)
}

fn find_first_member_scalar(set: ByteSet256, bytes: &[u8]) -> Option<usize> {
    bytes.iter().position(|&byte| set.contains(byte))
}

fn find_last_member_scalar(set: ByteSet256, bytes: &[u8]) -> Option<usize> {
    bytes.iter().rposition(|&byte| set.contains(byte))
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
#[cfg_attr(
    feature = "static-dispatch",
    allow(
        dead_code,
        reason = "a compiler-static scalar profile does not use vector lane recovery"
    )
)]
fn last_member_lane16(member_mask: u16) -> usize {
    usize::try_from(member_mask.ilog2()).expect("a 16-bit lane index fits in usize")
}

#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "linux", target_endian = "little")
))]
#[cfg_attr(
    feature = "static-dispatch",
    allow(
        dead_code,
        reason = "a compiler-static narrow profile does not use wide lane recovery"
    )
)]
fn last_member_lane32(member_mask: u32) -> usize {
    usize::try_from(member_mask.ilog2()).expect("a 32-bit lane index fits in usize")
}

#[cfg(all(
    target_arch = "aarch64",
    target_os = "linux",
    target_endian = "little",
    any(
        not(feature = "static-dispatch"),
        all(
            feature = "static-dispatch-arm-41-d84",
            target_feature = "sve",
            target_feature = "sve2"
        )
    )
))]
#[allow(
    unsafe_code,
    reason = "the caller authenticates SVE plus SVE2 once before this whole-slice leaf performs exact fixed-width loads"
)]
#[inline(never)]
unsafe fn find_first_member_sve2(
    classifier: &ByteSetClassifier,
    bytes: &[u8],
) -> Option<usize> {
    let complete_len = bytes
        .len()
        .checked_sub(bytes.len() % BYTE_SET_WIDE_BLOCK_BYTES)
        .expect("a remainder cannot exceed its source length");
    for (block_index, block) in bytes[..complete_len]
        .chunks_exact(BYTE_SET_WIDE_BLOCK_BYTES)
        .enumerate()
    {
        let block: &[u8; BYTE_SET_WIDE_BLOCK_BYTES] = block
            .try_into()
            .expect("an exact wide chunk has the fixed block extent");
        // SAFETY: the caller authenticated SVE plus SVE2, and the array
        // reference proves the exact 32-byte load extent.
        let member_mask = unsafe {
            crate::aarch64_sve2::classify_byte_set_32_sve2(&classifier.tables, block)
        }
        .member_mask();
        if member_mask != 0 {
            let block_start = block_index
                .checked_mul(BYTE_SET_WIDE_BLOCK_BYTES)
                .expect("a complete block index is bounded by the source slice");
            return block_start.checked_add(
                usize::try_from(member_mask.trailing_zeros())
                    .expect("a 32-bit lane index fits in usize"),
            );
        }
    }
    let tail = &bytes[complete_len..];
    let scalar_start = if tail.len() >= BYTE_SET_BLOCK_BYTES {
        let block: &[u8; BYTE_SET_BLOCK_BYTES] = tail[..BYTE_SET_BLOCK_BYTES]
            .try_into()
            .expect("the guarded SVE2 tail has one complete narrow block");
        let member_mask = classifier.classify_16(block).member_mask();
        if member_mask != 0 {
            return complete_len.checked_add(
                usize::try_from(member_mask.trailing_zeros())
                    .expect("a 16-bit lane index fits in usize"),
            );
        }
        complete_len
            .checked_add(BYTE_SET_BLOCK_BYTES)
            .expect("the complete narrow tail stays within its source slice")
    } else {
        complete_len
    };
    find_first_member_scalar(classifier.set(), &bytes[scalar_start..])
        .and_then(|relative| scalar_start.checked_add(relative))
}

#[cfg(all(
    target_arch = "aarch64",
    target_os = "linux",
    target_endian = "little",
    any(
        not(feature = "static-dispatch"),
        all(
            feature = "static-dispatch-arm-41-d84",
            target_feature = "sve",
            target_feature = "sve2"
        )
    )
))]
#[allow(
    unsafe_code,
    reason = "the caller authenticates SVE plus SVE2 once before this reverse whole-slice leaf performs exact fixed-width loads"
)]
#[inline(never)]
unsafe fn find_last_member_sve2(
    classifier: &ByteSetClassifier,
    bytes: &[u8],
) -> Option<usize> {
    let head_len = bytes.len() % BYTE_SET_WIDE_BLOCK_BYTES;
    let mut block_end = bytes.len();
    while block_end != head_len {
        let block_start = block_end
            .checked_sub(BYTE_SET_WIDE_BLOCK_BYTES)
            .expect("a complete reverse SVE2 block starts within its source slice");
        let block: &[u8; BYTE_SET_WIDE_BLOCK_BYTES] = bytes[block_start..block_end]
            .try_into()
            .expect("an exact reverse SVE2 chunk has the fixed block extent");
        // SAFETY: the caller authenticated SVE plus SVE2, and the array
        // reference proves the exact 32-byte load extent.
        let member_mask = unsafe {
            crate::aarch64_sve2::classify_byte_set_32_sve2(&classifier.tables, block)
        }
        .member_mask();
        if member_mask != 0 {
            return block_start.checked_add(last_member_lane32(member_mask));
        }
        block_end = block_start;
    }
    let scalar_head_len = if head_len >= BYTE_SET_BLOCK_BYTES {
        let block_start = head_len
            .checked_sub(BYTE_SET_BLOCK_BYTES)
            .expect("a guarded reverse SVE2 narrow block starts within its prefix");
        let block: &[u8; BYTE_SET_BLOCK_BYTES] = bytes[block_start..head_len]
            .try_into()
            .expect("the guarded reverse SVE2 prefix has one complete narrow block");
        let member_mask = classifier.classify_16(block).member_mask();
        if member_mask != 0 {
            return block_start.checked_add(last_member_lane16(member_mask));
        }
        block_start
    } else {
        head_len
    };
    find_last_member_scalar(classifier.set(), &bytes[..scalar_head_len])
}

#[cfg(all(
    target_arch = "aarch64",
    target_os = "linux",
    target_endian = "little",
    target_feature = "sve",
    target_feature = "sve2"
))]
#[allow(
    unsafe_code,
    reason = "compiler target features prove SVE2 before the private complete-group scan is called"
)]
fn find_first_member_values16_sve2(
    match_values: [u8; 16],
    set: ByteSet256,
    bytes: &[u8],
) -> Option<usize> {
    const GROUP_BYTES: usize = BYTE_SET_WIDE_BLOCK_BYTES * 4;
    let complete_group_len = bytes
        .len()
        .checked_sub(bytes.len() % GROUP_BYTES)
        .expect("a remainder cannot exceed its source length");
    let group_start = if complete_group_len == 0 {
        0
    } else {
        // SAFETY: compiler target features prove SVE2, and the nonempty prefix
        // contains only complete 128-byte groups.
        unsafe {
            crate::aarch64_sve2::find_byte_values16_128_group_sve2(
                &match_values,
                &bytes[..complete_group_len],
            )
        }
    };
    if group_start != complete_group_len {
        let group_end = group_start
            .checked_add(GROUP_BYTES)
            .expect("a complete group end stays within its source slice");
        return find_first_member_scalar(set, &bytes[group_start..group_end])
            .and_then(|relative| group_start.checked_add(relative));
    }

    let tail = &bytes[complete_group_len..];
    if tail.len() >= BYTE_SET_WIDE_BLOCK_BYTES
        && let Some((block_start, mask)) = crate::find_byte_values16_32_block(&match_values, tail)
    {
        return complete_group_len.checked_add(block_start)?.checked_add(
            usize::try_from(mask.member_mask().trailing_zeros())
                .expect("a 32-bit lane index fits in usize"),
        );
    }
    let complete_tail_len = tail
        .len()
        .checked_sub(tail.len() % BYTE_SET_WIDE_BLOCK_BYTES)
        .expect("a remainder cannot exceed its source length");
    let scalar_start = complete_group_len
        .checked_add(complete_tail_len)
        .expect("complete groups and blocks partition the source slice");
    find_first_member_scalar(set, &bytes[scalar_start..])
        .and_then(|relative| scalar_start.checked_add(relative))
}

#[cfg(all(
    target_arch = "aarch64",
    any(not(feature = "static-dispatch"), target_feature = "neon")
))]
const fn is_ascii_set(set: ByteSet256) -> bool {
    let [_, _, upper_low, upper_high] = set.words();
    upper_low == 0 && upper_high == 0
}

#[cfg(all(
    target_arch = "aarch64",
    any(not(feature = "static-dispatch"), target_feature = "neon")
))]
const fn is_high_only_set(set: ByteSet256) -> bool {
    let [lower_low, lower_high, upper_low, upper_high] = set.words();
    lower_low == 0 && lower_high == 0 && (upper_low != 0 || upper_high != 0)
}

#[cfg(all(
    target_arch = "aarch64",
    any(not(feature = "static-dispatch"), target_feature = "neon")
))]
#[allow(
    unsafe_code,
    reason = "the caller authenticates NEON once before this ASCII-specialized whole-slice leaf performs exact loads"
)]
#[target_feature(enable = "neon")]
#[inline(never)]
unsafe fn find_first_ascii_member_neon(
    tables: &ByteSetTables,
    set: ByteSet256,
    bytes: &[u8],
) -> Option<usize> {
    debug_assert!(is_ascii_set(set));
    let [low, high, _, _] = set.words();
    // SAFETY: this enclosing leaf already has NEON enabled; the classifier's
    // exact ASCII columns and words describe the same immutable set.
    unsafe {
        crate::aarch64::find_ascii_members_neon(
            &tables.lower,
            crate::AsciiByteSet::from_words([low, high]),
            bytes,
        )
    }
}

#[cfg(all(
    target_arch = "aarch64",
    any(not(feature = "static-dispatch"), target_feature = "neon")
))]
#[allow(
    unsafe_code,
    unsafe_op_in_unsafe_fn,
    reason = "the private NEON leaf is reachable only through authenticated dispatch and exact fixed extents"
)]
#[target_feature(enable = "neon")]
#[inline]
unsafe fn classify_neon(
    tables: &ByteSetTables,
    bytes: &[u8; BYTE_SET_BLOCK_BYTES],
) -> ByteSetMask16 {
    use core::arch::aarch64::{
        vaddv_u8, vandq_u8, vbslq_u8, vceqq_u8, vcltq_u8, vdupq_n_u8, vget_high_u8, vget_low_u8,
        vld1q_u8, vmulq_u8, vmvnq_u8, vqtbl1q_u8, vshrq_n_u8,
    };

    const BITS: [u8; 16] = [1, 2, 4, 8, 16, 32, 64, 128, 1, 2, 4, 8, 16, 32, 64, 128];
    const WEIGHTS: [u8; 16] = [1, 2, 4, 8, 16, 32, 64, 128, 1, 2, 4, 8, 16, 32, 64, 128];

    let input = vld1q_u8(bytes.as_ptr());
    let lower = vld1q_u8(tables.lower.as_ptr());
    let upper = vld1q_u8(tables.upper.as_ptr());
    let bits = vld1q_u8(BITS.as_ptr());
    let weights = vld1q_u8(WEIGHTS.as_ptr());
    let nibble_mask = vdupq_n_u8(0x0f);
    let low_nibbles = vandq_u8(input, nibble_mask);
    let high_nibbles = vandq_u8(vshrq_n_u8::<4>(input), nibble_mask);
    let lower_columns = vqtbl1q_u8(lower, low_nibbles);
    let upper_columns = vqtbl1q_u8(upper, low_nibbles);
    let lower_half = vcltq_u8(high_nibbles, vdupq_n_u8(8));
    let columns = vbslq_u8(lower_half, lower_columns, upper_columns);
    let selected_bits = vandq_u8(columns, vqtbl1q_u8(bits, high_nibbles));
    let member_lanes = vmvnq_u8(vceqq_u8(selected_bits, vdupq_n_u8(0)));
    let weighted = vmulq_u8(vshrq_n_u8::<7>(member_lanes), weights);
    let members = u16::from(vaddv_u8(vget_low_u8(weighted)))
        | (u16::from(vaddv_u8(vget_high_u8(weighted))) << 8);
    ByteSetMask16(members)
}

#[cfg(all(
    target_arch = "aarch64",
    any(not(feature = "static-dispatch"), target_feature = "neon")
))]
#[allow(
    unsafe_code,
    reason = "the caller authenticates NEON once before this whole-slice leaf performs exact fixed-width loads"
)]
#[allow(
    clippy::too_many_lines,
    reason = "one auditable loop keeps four-vector groups, vector-pair and vector-block tails, and exact scalar recovery under the same preloaded classifier"
)]
#[target_feature(enable = "neon")]
#[inline(never)]
unsafe fn find_first_member_neon(
    tables: &ByteSetTables,
    set: ByteSet256,
    bytes: &[u8],
) -> Option<usize> {
    const GROUP_BYTES: usize = BYTE_SET_WIDE_BLOCK_BYTES * 2;
    const BITS: [u8; BYTE_SET_BLOCK_BYTES] = [
        1, 2, 4, 8, 16, 32, 64, 128, 1, 2, 4, 8, 16, 32, 64, 128,
    ];
    use core::arch::aarch64::{
        vandq_u8, vbslq_u8, vceqq_u8, vcltq_u8, vdupq_n_u8, vld1q_u8, vmaxvq_u8, vmvnq_u8,
        vorrq_u8, vqtbl1q_u8, vshrq_n_u8,
    };

    // SAFETY: both tables contain exactly sixteen initialized bytes and this
    // enclosing leaf already has NEON enabled.
    let (lower, upper) = unsafe {
        (
            vld1q_u8(tables.lower.as_ptr()),
            vld1q_u8(tables.upper.as_ptr()),
        )
    };
    // SAFETY: the constant has exactly sixteen initialized bytes.
    let bits = unsafe { vld1q_u8(BITS.as_ptr()) };
    let nibble_mask = vdupq_n_u8(0x0f);
    let classify_members = |input| {
        let low_nibbles = vandq_u8(input, nibble_mask);
        let high_nibbles = vandq_u8(vshrq_n_u8::<4>(input), nibble_mask);
        let lower_columns = vqtbl1q_u8(lower, low_nibbles);
        let upper_columns = vqtbl1q_u8(upper, low_nibbles);
        let lower_half = vcltq_u8(high_nibbles, vdupq_n_u8(8));
        let columns = vbslq_u8(lower_half, lower_columns, upper_columns);
        let selected_bits = vandq_u8(columns, vqtbl1q_u8(bits, high_nibbles));
        vmvnq_u8(vceqq_u8(selected_bits, vdupq_n_u8(0)))
    };

    let mut block_start = 0_usize;
    let mut groups = bytes.chunks_exact(GROUP_BYTES);
    for group in &mut groups {
        let first: &[u8; BYTE_SET_BLOCK_BYTES] = group[..BYTE_SET_BLOCK_BYTES]
            .try_into()
            .expect("a four-vector group has one exact first NEON block");
        let second: &[u8; BYTE_SET_BLOCK_BYTES] =
            group[BYTE_SET_BLOCK_BYTES..BYTE_SET_WIDE_BLOCK_BYTES]
            .try_into()
            .expect("a four-vector group has one exact second NEON block");
        let third: &[u8; BYTE_SET_BLOCK_BYTES] = group
            [BYTE_SET_WIDE_BLOCK_BYTES..BYTE_SET_WIDE_BLOCK_BYTES + BYTE_SET_BLOCK_BYTES]
            .try_into()
            .expect("a four-vector group has one exact third NEON block");
        let fourth: &[u8; BYTE_SET_BLOCK_BYTES] = group
            [BYTE_SET_WIDE_BLOCK_BYTES + BYTE_SET_BLOCK_BYTES..GROUP_BYTES]
            .try_into()
            .expect("a four-vector group has one exact fourth NEON block");
        // SAFETY: all four array references prove their exact load extents.
        let (first_input, second_input, third_input, fourth_input) = unsafe {
            (
                vld1q_u8(first.as_ptr()),
                vld1q_u8(second.as_ptr()),
                vld1q_u8(third.as_ptr()),
                vld1q_u8(fourth.as_ptr()),
            )
        };
        let first_pair = vorrq_u8(
            classify_members(first_input),
            classify_members(second_input),
        );
        let second_pair = vorrq_u8(
            classify_members(third_input),
            classify_members(fourth_input),
        );
        if vmaxvq_u8(vorrq_u8(first_pair, second_pair)) != 0 {
            return find_first_member_scalar(set, group)
                .and_then(|relative| block_start.checked_add(relative));
        }
        block_start = block_start
            .checked_add(GROUP_BYTES)
            .expect("a complete group stays within its source slice");
    }

    let remainder = groups.remainder();
    let mut tail = remainder;
    if remainder.len() >= BYTE_SET_WIDE_BLOCK_BYTES {
        let first: &[u8; BYTE_SET_BLOCK_BYTES] = remainder[..BYTE_SET_BLOCK_BYTES]
            .try_into()
            .expect("a four-vector remainder has one exact first NEON block");
        let second: &[u8; BYTE_SET_BLOCK_BYTES] =
            remainder[BYTE_SET_BLOCK_BYTES..BYTE_SET_WIDE_BLOCK_BYTES]
            .try_into()
            .expect("a four-vector remainder has one exact second NEON block");
        // SAFETY: both array references prove their exact load extents.
        let (first_input, second_input) = unsafe {
            (
                vld1q_u8(first.as_ptr()),
                vld1q_u8(second.as_ptr()),
            )
        };
        if vmaxvq_u8(vorrq_u8(
            classify_members(first_input),
            classify_members(second_input),
        )) != 0
        {
            return find_first_member_scalar(set, &remainder[..BYTE_SET_WIDE_BLOCK_BYTES])
                .and_then(|relative| block_start.checked_add(relative));
        }
        block_start = block_start
            .checked_add(BYTE_SET_WIDE_BLOCK_BYTES)
            .expect("a trailing vector pair stays within its source slice");
        tail = &remainder[BYTE_SET_WIDE_BLOCK_BYTES..];
    }
    if tail.len() >= BYTE_SET_BLOCK_BYTES {
        let block: &[u8; BYTE_SET_BLOCK_BYTES] = tail[..BYTE_SET_BLOCK_BYTES]
            .try_into()
            .expect("a wide remainder has one exact NEON block");
        // SAFETY: the array reference proves the exact load extent.
        let input = unsafe { vld1q_u8(block.as_ptr()) };
        if vmaxvq_u8(classify_members(input)) != 0 {
            return find_first_member_scalar(set, block)
                .and_then(|relative| block_start.checked_add(relative));
        }
        block_start = block_start
            .checked_add(BYTE_SET_BLOCK_BYTES)
            .expect("a trailing vector block stays within its source slice");
        tail = &tail[BYTE_SET_BLOCK_BYTES..];
    }
    find_first_member_scalar(set, tail)
        .and_then(|relative| block_start.checked_add(relative))
}

#[cfg(all(
    target_arch = "aarch64",
    any(not(feature = "static-dispatch"), target_feature = "neon")
))]
#[allow(
    unsafe_code,
    reason = "the caller authenticates NEON once before this reverse whole-slice leaf performs exact fixed-width loads"
)]
#[target_feature(enable = "neon")]
#[inline(never)]
unsafe fn find_last_member_neon(
    tables: &ByteSetTables,
    set: ByteSet256,
    bytes: &[u8],
) -> Option<usize> {
    let head_len = bytes.len() % BYTE_SET_BLOCK_BYTES;
    let mut block_end = bytes.len();
    while block_end != head_len {
        let block_start = block_end
            .checked_sub(BYTE_SET_BLOCK_BYTES)
            .expect("a complete reverse NEON block starts within its source slice");
        let block: &[u8; BYTE_SET_BLOCK_BYTES] = bytes[block_start..block_end]
            .try_into()
            .expect("an exact reverse NEON chunk has the fixed block extent");
        // SAFETY: this enclosing leaf already has NEON enabled and the array
        // reference proves the exact 16-byte load extent.
        let member_mask = unsafe { classify_neon(tables, block) }.member_mask();
        if member_mask != 0 {
            return block_start.checked_add(last_member_lane16(member_mask));
        }
        block_end = block_start;
    }
    find_last_member_scalar(set, &bytes[..head_len])
}

#[cfg(all(
    target_arch = "aarch64",
    any(not(feature = "static-dispatch"), target_feature = "neon")
))]
#[allow(
    unsafe_code,
    reason = "the caller authenticates NEON once before this high-byte whole-slice gate performs bounded vector loads"
)]
#[target_feature(enable = "neon")]
#[inline(never)]
unsafe fn find_first_high_member_neon(
    tables: &ByteSetTables,
    set: ByteSet256,
    bytes: &[u8],
) -> Option<usize> {
    use core::arch::aarch64::{vld1q_u8, vmaxvq_u8, vorrq_u8};

    const GROUP_BYTES: usize = BYTE_SET_WIDE_BLOCK_BYTES * 4;
    let mut block_start = 0_usize;
    let mut consecutive_high_groups = 0_u8;
    let mut groups = bytes.chunks_exact(GROUP_BYTES);
    for group in &mut groups {
        let pointer = group.as_ptr();
        // SAFETY: the exact 128-byte group proves all eight vector loads.
        let high_lanes = unsafe {
            let first_pair = vorrq_u8(vld1q_u8(pointer), vld1q_u8(pointer.add(16)));
            let second_pair = vorrq_u8(vld1q_u8(pointer.add(32)), vld1q_u8(pointer.add(48)));
            let third_pair = vorrq_u8(vld1q_u8(pointer.add(64)), vld1q_u8(pointer.add(80)));
            let fourth_pair = vorrq_u8(vld1q_u8(pointer.add(96)), vld1q_u8(pointer.add(112)));
            vorrq_u8(
                vorrq_u8(first_pair, second_pair),
                vorrq_u8(third_pair, fourth_pair),
            )
        };
        if vmaxvq_u8(high_lanes) < 0x80 {
            consecutive_high_groups = 0;
            block_start = block_start
                .checked_add(GROUP_BYTES)
                .expect("a complete group stays within its source slice");
            continue;
        }
        // SAFETY: this enclosing leaf already has NEON enabled.
        if let Some(relative) = unsafe { find_first_member_neon(tables, set, group) } {
            return block_start.checked_add(relative);
        }
        consecutive_high_groups = consecutive_high_groups
            .checked_add(1)
            .expect("the fallback threshold is reached after two groups");
        block_start = block_start
            .checked_add(GROUP_BYTES)
            .expect("a complete group stays within its source slice");
        if consecutive_high_groups == 2 {
            // SAFETY: this enclosing leaf already has NEON enabled, and the
            // remaining suffix starts after the two completely serviced groups.
            return unsafe { find_first_member_neon(tables, set, &bytes[block_start..]) }
                .and_then(|relative| block_start.checked_add(relative));
        }
    }
    // SAFETY: this enclosing leaf already has NEON enabled.
    unsafe { find_first_member_neon(tables, set, groups.remainder()) }
        .and_then(|relative| block_start.checked_add(relative))
}

#[cfg(all(
    target_arch = "x86_64",
    any(not(feature = "static-dispatch"), target_feature = "ssse3")
))]
#[allow(
    unsafe_code,
    unsafe_op_in_unsafe_fn,
    reason = "the private SSSE3 leaf is reachable only through authenticated dispatch and exact fixed extents"
)]
#[target_feature(enable = "ssse3")]
#[inline]
unsafe fn classify_ssse3(
    tables: &ByteSetTables,
    bytes: &[u8; BYTE_SET_BLOCK_BYTES],
) -> ByteSetMask16 {
    use core::arch::x86_64::{
        __m128i, _mm_and_si128, _mm_andnot_si128, _mm_cmpeq_epi8, _mm_loadu_si128,
        _mm_movemask_epi8, _mm_or_si128, _mm_set1_epi8, _mm_setzero_si128, _mm_shuffle_epi8,
        _mm_srli_epi16,
    };

    const BITS: [u8; 16] = [1, 2, 4, 8, 16, 32, 64, 128, 1, 2, 4, 8, 16, 32, 64, 128];
    let input = _mm_loadu_si128(bytes.as_ptr().cast::<__m128i>());
    let lower = _mm_loadu_si128(tables.lower.as_ptr().cast::<__m128i>());
    let upper = _mm_loadu_si128(tables.upper.as_ptr().cast::<__m128i>());
    let bits = _mm_loadu_si128(BITS.as_ptr().cast::<__m128i>());
    let nibble_mask = _mm_set1_epi8(0x0f);
    let low_nibbles = _mm_and_si128(input, nibble_mask);
    let high_nibbles = _mm_and_si128(_mm_srli_epi16::<4>(input), nibble_mask);
    let lower_columns = _mm_shuffle_epi8(lower, low_nibbles);
    let upper_columns = _mm_shuffle_epi8(upper, low_nibbles);
    let upper_half = _mm_cmpeq_epi8(
        _mm_and_si128(input, _mm_set1_epi8(i8::MIN)),
        _mm_set1_epi8(i8::MIN),
    );
    let columns = _mm_or_si128(
        _mm_andnot_si128(upper_half, lower_columns),
        _mm_and_si128(upper_half, upper_columns),
    );
    let selected_bits = _mm_and_si128(columns, _mm_shuffle_epi8(bits, high_nibbles));
    let zero_lanes = _mm_cmpeq_epi8(selected_bits, _mm_setzero_si128());
    ByteSetMask16(
        u16::try_from((!_mm_movemask_epi8(zero_lanes)) & 0xffff)
            .expect("a sixteen-lane movemask fits in u16"),
    )
}

#[cfg(all(
    target_arch = "x86_64",
    any(
        not(feature = "static-dispatch"),
        all(not(target_feature = "avx2"), target_feature = "ssse3")
    )
))]
#[allow(
    unsafe_code,
    reason = "the caller authenticates SSSE3 once before this whole-slice leaf performs exact fixed-width loads"
)]
#[target_feature(enable = "ssse3")]
#[inline(never)]
unsafe fn find_first_member_ssse3(
    tables: &ByteSetTables,
    set: ByteSet256,
    bytes: &[u8],
) -> Option<usize> {
    let complete_len = bytes
        .len()
        .checked_sub(bytes.len() % BYTE_SET_BLOCK_BYTES)
        .expect("a remainder cannot exceed its source length");
    for (block_index, block) in bytes[..complete_len]
        .chunks_exact(BYTE_SET_BLOCK_BYTES)
        .enumerate()
    {
        let block: &[u8; BYTE_SET_BLOCK_BYTES] = block
            .try_into()
            .expect("an exact chunk has the fixed block extent");
        // SAFETY: this enclosing leaf already has SSSE3 enabled and the array
        // proves the exact load extent.
        let member_mask = unsafe { classify_ssse3(tables, block) }.member_mask();
        if member_mask != 0 {
            let block_start = block_index
                .checked_mul(BYTE_SET_BLOCK_BYTES)
                .expect("a complete block index is bounded by the source slice");
            return block_start.checked_add(
                usize::try_from(member_mask.trailing_zeros())
                    .expect("a 16-bit lane index fits in usize"),
            );
        }
    }
    find_first_member_scalar(set, &bytes[complete_len..])
        .and_then(|relative| complete_len.checked_add(relative))
}

#[cfg(all(
    target_arch = "x86_64",
    any(
        not(feature = "static-dispatch"),
        all(not(target_feature = "avx2"), target_feature = "ssse3")
    )
))]
#[allow(
    unsafe_code,
    reason = "the caller authenticates SSSE3 once before this reverse whole-slice leaf performs exact fixed-width loads"
)]
#[target_feature(enable = "ssse3")]
#[inline(never)]
unsafe fn find_last_member_ssse3(
    tables: &ByteSetTables,
    set: ByteSet256,
    bytes: &[u8],
) -> Option<usize> {
    let head_len = bytes.len() % BYTE_SET_BLOCK_BYTES;
    let mut block_end = bytes.len();
    while block_end != head_len {
        let block_start = block_end
            .checked_sub(BYTE_SET_BLOCK_BYTES)
            .expect("a complete reverse SSSE3 block starts within its source slice");
        let block: &[u8; BYTE_SET_BLOCK_BYTES] = bytes[block_start..block_end]
            .try_into()
            .expect("an exact reverse SSSE3 chunk has the fixed block extent");
        // SAFETY: this enclosing leaf already has SSSE3 enabled and the array
        // reference proves the exact 16-byte load extent.
        let member_mask = unsafe { classify_ssse3(tables, block) }.member_mask();
        if member_mask != 0 {
            return block_start.checked_add(last_member_lane16(member_mask));
        }
        block_end = block_start;
    }
    find_last_member_scalar(set, &bytes[..head_len])
}

const SCALAR: KernelVariant<ByteSetEntry> = KernelVariant::new(
    SCALAR_VARIANT_ID,
    ArchitectureRequirement::Any,
    FeatureSet::EMPTY,
    VectorKind::Scalar,
    BYTE_SET_BLOCK_BYTES,
    0,
    byte_set_entry!(classify_scalar_entry),
);

#[cfg(target_arch = "aarch64")]
const VARIANTS: [KernelVariant<ByteSetEntry>; 2] = [
    SCALAR,
    KernelVariant::new(
        NEON_VARIANT_ID,
        ArchitectureRequirement::Exact(Architecture::Aarch64),
        FeatureSet::of(Feature::ArmNeon),
        VectorKind::Fixed {
            bytes: BYTE_SET_VECTOR_BYTES,
        },
        BYTE_SET_BLOCK_BYTES,
        100,
        byte_set_entry!(classify_neon),
    ),
];

#[cfg(target_arch = "x86_64")]
const VARIANTS: [KernelVariant<ByteSetEntry>; 2] = [
    SCALAR,
    KernelVariant::new(
        SSSE3_VARIANT_ID,
        ArchitectureRequirement::Exact(Architecture::X86_64),
        FeatureSet::of(Feature::X86Ssse3),
        VectorKind::Fixed {
            bytes: BYTE_SET_VECTOR_BYTES,
        },
        BYTE_SET_BLOCK_BYTES,
        100,
        byte_set_entry!(classify_ssse3),
    ),
];

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
const VARIANTS: [KernelVariant<ByteSetEntry>; 1] = [SCALAR];

#[cfg(any(
    feature = "static-dispatch",
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "linux", target_endian = "little")
))]
const SPLIT_32: KernelVariant<()> = KernelVariant::new(
    SPLIT_MASK32_VARIANT_ID,
    ArchitectureRequirement::Any,
    FeatureSet::EMPTY,
    VectorKind::Fixed {
        bytes: BYTE_SET_VECTOR_BYTES,
    },
    BYTE_SET_WIDE_BLOCK_BYTES,
    0,
    (),
);

#[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
const SVE2_PREFERENCE: u16 = if cfg!(feature = "static-dispatch-arm-41-d84") {
    200
} else {
    50
};

#[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
const SPLIT_NEON_PREFERENCE: u16 = if cfg!(feature = "static-dispatch") {
    0
} else {
    100
};

#[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
const WIDE_VARIANTS: [KernelVariant<()>; 4] = [
    SPLIT_32,
    KernelVariant::new(
        SVE2_MASK32_VARIANT_ID,
        ArchitectureRequirement::Exact(Architecture::Aarch64),
        FeatureSet::EMPTY
            .with(Feature::ArmSve)
            .with(Feature::ArmSve2),
        VectorKind::Scalable,
        BYTE_SET_WIDE_BLOCK_BYTES,
        SVE2_PREFERENCE,
        (),
    ),
    KernelVariant::new(
        SPLIT_NEON_MASK32_VARIANT_ID,
        ArchitectureRequirement::Exact(Architecture::Aarch64),
        FeatureSet::of(Feature::ArmNeon),
        VectorKind::Fixed {
            bytes: BYTE_SET_VECTOR_BYTES,
        },
        BYTE_SET_WIDE_BLOCK_BYTES,
        SPLIT_NEON_PREFERENCE,
        (),
    ),
    KernelVariant::new(
        SVE2_ARM_41_D84_MASK32_VARIANT_ID,
        ArchitectureRequirement::Exact(Architecture::Aarch64),
        FeatureSet::EMPTY
            .with(Feature::ArmSve)
            .with(Feature::ArmSve2),
        VectorKind::Scalable,
        BYTE_SET_WIDE_BLOCK_BYTES,
        150,
        (),
    )
    .when_tuning(is_neoverse_v3),
];

#[cfg(target_arch = "x86_64")]
const WIDE_VARIANTS: [KernelVariant<()>; 2] = [
    SPLIT_32,
    // AVX-512 hosts retain this AVX2 leaf until a separately qualified
    // AVX-512 byte-table implementation beats it. The explicit wide table
    // keeps that future tier independent of scanner semantics.
    KernelVariant::new(
        AVX2_MASK32_VARIANT_ID,
        ArchitectureRequirement::Exact(Architecture::X86_64),
        FeatureSet::of(Feature::X86Avx2),
        VectorKind::Fixed {
            bytes: BYTE_SET_WIDE_VECTOR_BYTES,
        },
        BYTE_SET_WIDE_BLOCK_BYTES,
        100,
        (),
    ),
];

#[cfg(all(
    feature = "static-dispatch",
    not(any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_os = "linux", target_endian = "little")
    ))
))]
const WIDE_VARIANTS: [KernelVariant<()>; 1] = [SPLIT_32];

#[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
fn is_neoverse_v3(tuning: TuningClass) -> bool {
    matches!(
        tuning,
        TuningClass::ArmServer { cpu: Some(cpu) }
            if cpu.implementer == 0x41 && cpu.part == 0xd84
    )
}

fn select(
    capabilities: CpuCapabilities,
    policy: DispatchPolicy,
) -> Result<SelectedKernel<ByteSetEntry>, UnsupportedRequiredFeatures> {
    Ok(
        select_kernel(capabilities, policy, BYTE_SET_BLOCK_BYTES, &VARIANTS)?
            .expect("the byte-set table always contains its scalar fallback"),
    )
}

#[cfg(any(
    feature = "static-dispatch",
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "linux", target_endian = "little")
))]
fn select_wide(
    capabilities: CpuCapabilities,
    policy: DispatchPolicy,
) -> Result<SelectedKernel<()>, UnsupportedRequiredFeatures> {
    Ok(select_kernel(
        capabilities,
        policy,
        BYTE_SET_WIDE_BLOCK_BYTES,
        &WIDE_VARIANTS,
    )?
    .expect("the byte-set wide table always contains its split fallback"))
}

#[cfg(feature = "static-dispatch")]
const fn automatic_selection() -> SelectionReceipt {
    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    let (variant_id, required, vector) = (
        NEON_VARIANT_ID,
        FeatureSet::of(Feature::ArmNeon),
        VectorKind::Fixed {
            bytes: BYTE_SET_VECTOR_BYTES,
        },
    );
    #[cfg(all(target_arch = "x86_64", target_feature = "ssse3"))]
    let (variant_id, required, vector) = (
        SSSE3_VARIANT_ID,
        FeatureSet::of(Feature::X86Ssse3),
        VectorKind::Fixed {
            bytes: BYTE_SET_VECTOR_BYTES,
        },
    );
    #[cfg(not(any(
        all(target_arch = "aarch64", target_feature = "neon"),
        all(target_arch = "x86_64", target_feature = "ssse3")
    )))]
    let (variant_id, required, vector) = (SCALAR_VARIANT_ID, FeatureSet::EMPTY, VectorKind::Scalar);
    crate::compiler_selection_receipt(
        variant_id,
        None,
        required,
        vector,
        BYTE_SET_BLOCK_BYTES,
        BYTE_SET_BLOCK_BYTES,
    )
}

#[cfg(feature = "static-dispatch")]
const fn automatic_wide_selection(_narrow: SelectionReceipt) -> SelectionReceipt {
    #[cfg(all(
        feature = "static-dispatch-arm-41-d84",
        target_arch = "aarch64",
        target_os = "linux",
        target_endian = "little",
        target_feature = "sve",
        target_feature = "sve2"
    ))]
    let receipt = crate::compiler_selection_receipt(
        SVE2_MASK32_VARIANT_ID,
        None,
        FeatureSet::EMPTY
            .with(Feature::ArmSve)
            .with(Feature::ArmSve2),
        VectorKind::Scalable,
        BYTE_SET_WIDE_BLOCK_BYTES,
        BYTE_SET_WIDE_BLOCK_BYTES,
    );
    #[cfg(all(
        feature = "static-dispatch",
        target_arch = "x86_64",
        target_feature = "avx2"
    ))]
    let receipt = crate::compiler_selection_receipt(
        AVX2_MASK32_VARIANT_ID,
        None,
        FeatureSet::of(Feature::X86Avx2),
        VectorKind::Fixed {
            bytes: BYTE_SET_WIDE_VECTOR_BYTES,
        },
        BYTE_SET_WIDE_BLOCK_BYTES,
        BYTE_SET_WIDE_BLOCK_BYTES,
    );
    #[cfg(not(any(
        all(
            feature = "static-dispatch-arm-41-d84",
            target_arch = "aarch64",
            target_os = "linux",
            target_endian = "little",
            target_feature = "sve",
            target_feature = "sve2"
        ),
        all(
            feature = "static-dispatch",
            target_arch = "x86_64",
            target_feature = "avx2"
        )
    )))]
    let receipt = SelectionReceipt {
        variant_id: SPLIT_MASK32_VARIANT_ID,
        delegate_variant_id: Some(_narrow.variant_id),
        selection_input_bytes: BYTE_SET_WIDE_BLOCK_BYTES,
        minimum_input_bytes: BYTE_SET_WIDE_BLOCK_BYTES,
        .._narrow
    };
    receipt
}

#[cfg(all(
    feature = "static-dispatch-arm-41-d84",
    target_arch = "aarch64",
    target_os = "linux",
    target_endian = "little",
    target_feature = "sve",
    target_feature = "sve2"
))]
const fn static_wide_variant_id() -> &'static str {
    SVE2_MASK32_VARIANT_ID
}

#[cfg(all(
    feature = "static-dispatch",
    target_arch = "x86_64",
    target_feature = "avx2"
))]
const fn static_wide_variant_id() -> &'static str {
    AVX2_MASK32_VARIANT_ID
}

#[cfg(all(
    feature = "static-dispatch",
    not(any(
        all(
            feature = "static-dispatch-arm-41-d84",
            target_arch = "aarch64",
            target_os = "linux",
            target_endian = "little",
            target_feature = "sve",
            target_feature = "sve2"
        ),
        all(target_arch = "x86_64", target_feature = "avx2")
    ))
))]
const fn static_wide_variant_id() -> &'static str {
    SPLIT_MASK32_VARIANT_ID
}

#[cfg(all(
    target_arch = "x86_64",
    any(not(feature = "static-dispatch"), target_feature = "avx2")
))]
#[allow(
    unsafe_code,
    unsafe_op_in_unsafe_fn,
    reason = "the compiler-static profile proves AVX2 and the fixed arrays prove each unaligned load extent"
)]
#[allow(
    clippy::cast_ptr_alignment,
    reason = "AVX2 unaligned loads explicitly accept byte-backed addresses"
)]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn classify_32_avx2(
    tables: &ByteSetTables,
    bytes: &[u8; BYTE_SET_WIDE_BLOCK_BYTES],
) -> ByteSetMask32 {
    use core::arch::x86_64::{
        __m128i, __m256i, _mm_loadu_si128, _mm256_and_si256, _mm256_andnot_si256,
        _mm256_broadcastsi128_si256, _mm256_cmpeq_epi8, _mm256_loadu_si256, _mm256_movemask_epi8,
        _mm256_or_si256, _mm256_set1_epi8, _mm256_setzero_si256, _mm256_shuffle_epi8,
        _mm256_srli_epi16,
    };

    const BITS: [u8; BYTE_SET_WIDE_BLOCK_BYTES] = [
        1, 2, 4, 8, 16, 32, 64, 128, 1, 2, 4, 8, 16, 32, 64, 128, 1, 2, 4, 8, 16, 32, 64, 128, 1,
        2, 4, 8, 16, 32, 64, 128,
    ];
    let input = unsafe { _mm256_loadu_si256(bytes.as_ptr().cast::<__m256i>()) };
    let lower = unsafe {
        _mm256_broadcastsi128_si256(_mm_loadu_si128(tables.lower.as_ptr().cast::<__m128i>()))
    };
    let upper = unsafe {
        _mm256_broadcastsi128_si256(_mm_loadu_si128(tables.upper.as_ptr().cast::<__m128i>()))
    };
    let bits = unsafe { _mm256_loadu_si256(BITS.as_ptr().cast::<__m256i>()) };
    let nibble_mask = _mm256_set1_epi8(0x0f);
    let low_nibbles = _mm256_and_si256(input, nibble_mask);
    let high_nibbles = _mm256_and_si256(_mm256_srli_epi16::<4>(input), nibble_mask);
    let lower_columns = _mm256_shuffle_epi8(lower, low_nibbles);
    let upper_columns = _mm256_shuffle_epi8(upper, low_nibbles);
    let upper_half = _mm256_cmpeq_epi8(
        _mm256_and_si256(input, _mm256_set1_epi8(i8::MIN)),
        _mm256_set1_epi8(i8::MIN),
    );
    let columns = _mm256_or_si256(
        _mm256_andnot_si256(upper_half, lower_columns),
        _mm256_and_si256(upper_half, upper_columns),
    );
    let selected_bits = _mm256_and_si256(columns, _mm256_shuffle_epi8(bits, high_nibbles));
    let zero_lanes = _mm256_cmpeq_epi8(selected_bits, _mm256_setzero_si256());
    ByteSetMask32::new(u32::from_ne_bytes(
        (!_mm256_movemask_epi8(zero_lanes)).to_ne_bytes(),
    ))
}

#[cfg(all(
    target_arch = "x86_64",
    any(not(feature = "static-dispatch"), target_feature = "avx2")
))]
#[allow(
    unsafe_code,
    reason = "the caller authenticates AVX2 once before this whole-slice leaf performs exact fixed-width loads"
)]
#[target_feature(enable = "avx2")]
#[inline(never)]
unsafe fn find_first_member_avx2(
    classifier: &ByteSetClassifier,
    bytes: &[u8],
) -> Option<usize> {
    let complete_len = bytes
        .len()
        .checked_sub(bytes.len() % BYTE_SET_WIDE_BLOCK_BYTES)
        .expect("a remainder cannot exceed its source length");
    for (block_index, block) in bytes[..complete_len]
        .chunks_exact(BYTE_SET_WIDE_BLOCK_BYTES)
        .enumerate()
    {
        let block: &[u8; BYTE_SET_WIDE_BLOCK_BYTES] = block
            .try_into()
            .expect("an exact wide chunk has the fixed block extent");
        // SAFETY: this enclosing leaf already has AVX2 enabled and the array
        // proves the exact load extent.
        let member_mask = unsafe { classify_32_avx2(&classifier.tables, block) }.member_mask();
        if member_mask != 0 {
            let block_start = block_index
                .checked_mul(BYTE_SET_WIDE_BLOCK_BYTES)
                .expect("a complete block index is bounded by the source slice");
            return block_start.checked_add(
                usize::try_from(member_mask.trailing_zeros())
                    .expect("a 32-bit lane index fits in usize"),
            );
        }
    }
    let tail = &bytes[complete_len..];
    let scalar_start = if tail.len() >= BYTE_SET_BLOCK_BYTES {
        let block: &[u8; BYTE_SET_BLOCK_BYTES] = tail[..BYTE_SET_BLOCK_BYTES]
            .try_into()
            .expect("the guarded AVX2 tail has one complete narrow block");
        let member_mask = classifier.classify_16(block).member_mask();
        if member_mask != 0 {
            return complete_len.checked_add(
                usize::try_from(member_mask.trailing_zeros())
                    .expect("a 16-bit lane index fits in usize"),
            );
        }
        complete_len
            .checked_add(BYTE_SET_BLOCK_BYTES)
            .expect("the complete narrow tail stays within its source slice")
    } else {
        complete_len
    };
    find_first_member_scalar(classifier.set(), &bytes[scalar_start..])
        .and_then(|relative| scalar_start.checked_add(relative))
}

#[cfg(all(
    target_arch = "x86_64",
    any(not(feature = "static-dispatch"), target_feature = "avx2")
))]
#[allow(
    unsafe_code,
    reason = "the caller authenticates AVX2 once before this reverse whole-slice leaf performs exact fixed-width loads"
)]
#[target_feature(enable = "avx2")]
#[inline(never)]
unsafe fn find_last_member_avx2(
    classifier: &ByteSetClassifier,
    bytes: &[u8],
) -> Option<usize> {
    let head_len = bytes.len() % BYTE_SET_WIDE_BLOCK_BYTES;
    let mut block_end = bytes.len();
    while block_end != head_len {
        let block_start = block_end
            .checked_sub(BYTE_SET_WIDE_BLOCK_BYTES)
            .expect("a complete reverse AVX2 block starts within its source slice");
        let block: &[u8; BYTE_SET_WIDE_BLOCK_BYTES] = bytes[block_start..block_end]
            .try_into()
            .expect("an exact reverse AVX2 chunk has the fixed block extent");
        // SAFETY: this enclosing leaf already has AVX2 enabled and the array
        // reference proves the exact 32-byte load extent.
        let member_mask = unsafe { classify_32_avx2(&classifier.tables, block) }.member_mask();
        if member_mask != 0 {
            return block_start.checked_add(last_member_lane32(member_mask));
        }
        block_end = block_start;
    }
    let scalar_head_len = if head_len >= BYTE_SET_BLOCK_BYTES {
        let block_start = head_len
            .checked_sub(BYTE_SET_BLOCK_BYTES)
            .expect("a guarded reverse AVX2 narrow block starts within its prefix");
        let block: &[u8; BYTE_SET_BLOCK_BYTES] = bytes[block_start..head_len]
            .try_into()
            .expect("the guarded reverse AVX2 prefix has one complete narrow block");
        let member_mask = classifier.classify_16(block).member_mask();
        if member_mask != 0 {
            return block_start.checked_add(last_member_lane16(member_mask));
        }
        block_start
    } else {
        head_len
    };
    find_last_member_scalar(classifier.set(), &bytes[..scalar_head_len])
}

#[cfg(all(
    feature = "static-dispatch",
    target_arch = "aarch64",
    target_feature = "neon"
))]
const fn static_variant_id() -> &'static str {
    NEON_VARIANT_ID
}

#[cfg(all(
    feature = "static-dispatch",
    target_arch = "x86_64",
    target_feature = "ssse3"
))]
const fn static_variant_id() -> &'static str {
    SSSE3_VARIANT_ID
}

#[cfg(all(
    feature = "static-dispatch",
    not(any(
        all(target_arch = "aarch64", target_feature = "neon"),
        all(target_arch = "x86_64", target_feature = "ssse3")
    ))
))]
const fn static_variant_id() -> &'static str {
    SCALAR_VARIANT_ID
}

#[cfg(all(
    feature = "static-dispatch",
    target_arch = "aarch64",
    target_feature = "neon"
))]
#[allow(
    unsafe_code,
    reason = "the compiler-fixed profile proves NEON and the caller supplies one exact block"
)]
unsafe fn static_classify(
    tables: &ByteSetTables,
    bytes: &[u8; BYTE_SET_BLOCK_BYTES],
) -> ByteSetMask16 {
    unsafe { classify_neon(tables, bytes) }
}

#[cfg(all(
    feature = "static-dispatch",
    target_arch = "x86_64",
    target_feature = "ssse3"
))]
#[allow(
    unsafe_code,
    reason = "the compiler-fixed profile proves SSSE3 and the caller supplies one exact block"
)]
unsafe fn static_classify(
    tables: &ByteSetTables,
    bytes: &[u8; BYTE_SET_BLOCK_BYTES],
) -> ByteSetMask16 {
    unsafe { classify_ssse3(tables, bytes) }
}

#[cfg(all(
    feature = "static-dispatch",
    not(any(
        all(target_arch = "aarch64", target_feature = "neon"),
        all(target_arch = "x86_64", target_feature = "ssse3")
    ))
))]
#[allow(
    unsafe_code,
    reason = "the scalar function shares the compiler-fixed leaf ABI but performs no unsafe operation"
)]
unsafe fn static_classify(
    tables: &ByteSetTables,
    bytes: &[u8; BYTE_SET_BLOCK_BYTES],
) -> ByteSetMask16 {
    classify_scalar(tables, bytes)
}

#[cfg(test)]
mod tests {
    use super::{
        BYTE_SET_BLOCK_BYTES, BYTE_SET_WIDE_BLOCK_BYTES, ByteSet256, ByteSetClassifier,
        classify_scalar,
    };
    use crate::{DispatchPolicy, SimdDispatchContext};

    fn next_random(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[test]
    fn automatic_leaf_matches_scalar_for_arbitrary_sets_and_alignments() {
        let context = SimdDispatchContext::capture();
        let mut random = 0xa076_1d64_78bd_642f_u64;
        let mut source = [0_u8; BYTE_SET_BLOCK_BYTES + 31];
        for _ in 0..256 {
            let set = ByteSet256::from_words(core::array::from_fn(|_| next_random(&mut random)));
            let classifier = context
                .byte_set_classifier(set, DispatchPolicy::Auto)
                .unwrap();
            for (index, byte) in source.iter_mut().enumerate() {
                *byte = u8::try_from(
                    next_random(&mut random).wrapping_add(u64::try_from(index * 197).unwrap())
                        & 255,
                )
                .unwrap();
            }
            for alignment in 0..=31 {
                let block: &[u8; BYTE_SET_BLOCK_BYTES] = source
                    [alignment..alignment + BYTE_SET_BLOCK_BYTES]
                    .try_into()
                    .unwrap();
                assert_eq!(
                    classifier.classify_16(block),
                    classify_scalar(&set.tables(), block)
                );
                for lane in 0..BYTE_SET_BLOCK_BYTES {
                    assert_eq!(
                        classifier.classify_16(block).member_mask() & (1_u16 << lane) != 0,
                        set.contains(block[lane])
                    );
                }
            }
        }
    }

    #[test]
    fn whole_slice_finder_matches_scalar_for_sets_boundaries_and_alignments() {
        let sets = [
            ByteSet256::from_words([1, 0, 0, 0]),
            ByteSet256::from_words([0, 1_u64 << 63, 1, 1_u64 << 63]),
            ByteSet256::from_words([
                0,
                0,
                0x0000_0000_0001_ffff,
                (1_u64 << 3) | (1_u64 << 63),
            ]),
            ByteSet256::from_words([
                0x0101_0101_0101_0101,
                0x8040_2010_0804_0201,
                0x1111_1111_1111_1111,
                0x8000_0000_0000_0001,
            ]),
        ];
        for set in sets {
            let classifier = ByteSetClassifier::new(set);
            let members = [
                (0_u8..0x80).find(|&byte| set.contains(byte)),
                (0x80_u8..=u8::MAX).find(|&byte| set.contains(byte)),
            ];
            for member in members.into_iter().flatten() {
                let nonmembers = [
                    (0_u8..0x80).find(|&byte| !set.contains(byte)),
                    (0x80_u8..=u8::MAX).find(|&byte| !set.contains(byte)),
                ];
                for nonmember in nonmembers.into_iter().flatten() {
                    for alignment in 0..=31 {
                        for len in [
                            0_usize, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129,
                            255, 256, 257, 383, 384, 385,
                        ] {
                            let mut source = vec![nonmember; alignment + len];
                            assert_eq!(classifier.find_first_member(&source[alignment..]), None);
                            assert_eq!(classifier.find_last_member(&source[alignment..]), None);
                            for position in [
                                0_usize, 1, 15, 16, 17, 31, 32, 63, 64, 127, 128, 255, 256,
                                383, 384,
                            ] {
                                if position >= len {
                                    continue;
                                }
                                source[alignment + position] = member;
                                let bytes = &source[alignment..];
                                assert_eq!(
                                    classifier.find_first_member(bytes),
                                    bytes.iter().position(|&byte| set.contains(byte)),
                                    "set={set:?} member={member} nonmember={nonmember} alignment={alignment} len={len} position={position}",
                                );
                                assert_eq!(
                                    classifier.find_last_member(bytes),
                                    bytes.iter().rposition(|&byte| set.contains(byte)),
                                    "reverse set={set:?} member={member} nonmember={nonmember} alignment={alignment} len={len} position={position}",
                                );
                                source[alignment + position] = nonmember;
                            }
                        }
                    }
                }
            }
        }

        let dense_mixed = ByteSetClassifier::new(ByteSet256::from_words([
            0x5555_5555_5555_5555,
            0,
            0x5555_5555_5555_5555,
            0,
        ]));
        assert_whole_slice_tail_boundaries(&dense_mixed, 0, 1);
        assert_whole_slice_tail_boundaries(&dense_mixed, 0x80, 1);
    }

    #[test]
    fn reverse_whole_slice_finder_matches_scalar_for_arbitrary_sets_and_slices() {
        let context = SimdDispatchContext::capture();
        let mut random = 0x243f_6a88_85a3_08d3_u64;
        let mut source = [0_u8; 31 + 385];
        let lengths = [
            0_usize, 1, 2, 3, 14, 15, 16, 17, 30, 31, 32, 33, 47, 48, 49, 63, 64,
            65, 95, 96, 97, 127, 128, 129, 255, 256, 257, 383, 384, 385,
        ];
        for case in 0..=130 {
            let set = match case {
                0 => ByteSet256::from_words([0; 4]),
                1 => ByteSet256::from_words([u64::MAX; 4]),
                2 => ByteSet256::from_words([
                    0x5555_5555_5555_5555,
                    0xaaaa_aaaa_aaaa_aaaa,
                    0x8000_0000_0000_0001,
                    0x0101_0101_0101_0101,
                ]),
                _ => ByteSet256::from_words(core::array::from_fn(|_| {
                    next_random(&mut random)
                })),
            };
            let classifier = context
                .byte_set_classifier(set, DispatchPolicy::Auto)
                .unwrap();
            for (index, byte) in source.iter_mut().enumerate() {
                *byte = u8::try_from(
                    next_random(&mut random)
                        .wrapping_add(u64::try_from(index.wrapping_mul(197)).unwrap())
                        & 255,
                )
                .unwrap();
            }
            for alignment in 0..=31 {
                for len in lengths {
                    let bytes = &source[alignment..alignment + len];
                    assert_eq!(
                        classifier.find_last_member(bytes),
                        bytes.iter().rposition(|&byte| set.contains(byte)),
                        "case={case} set={set:?} alignment={alignment} len={len}",
                    );
                }
            }
        }
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "fixed test lengths and alignments remain within the bounded source allocation"
    )]
    fn assert_whole_slice_tail_boundaries(
        classifier: &ByteSetClassifier,
        member: u8,
        nonmember: u8,
    ) {
        assert!(classifier.set().contains(member));
        assert!(!classifier.set().contains(nonmember));
        for alignment in [0_usize, 1, 15, 16, 31] {
            for len in [16_usize, 17, 31, 32, 33, 47, 48, 49, 63, 64] {
                let mut source = vec![nonmember; alignment + len];
                assert_eq!(
                    classifier.find_first_member(&source[alignment..]),
                    None,
                    "alignment={alignment} len={len} no-match"
                );
                assert_eq!(
                    classifier.find_last_member(&source[alignment..]),
                    None,
                    "reverse alignment={alignment} len={len} no-match"
                );
                for position in 0..len {
                    source[alignment + position] = member;
                    assert_eq!(
                        classifier.find_first_member(&source[alignment..]),
                        Some(position),
                        "alignment={alignment} len={len} position={position}"
                    );
                    assert_eq!(
                        classifier.find_last_member(&source[alignment..]),
                        Some(position),
                        "reverse alignment={alignment} len={len} position={position}"
                    );
                    source[alignment + position] = nonmember;
                }
                if len != 0 {
                    source[alignment] = member;
                    for position in 0..len {
                        source[alignment + position] = member;
                        let bytes = &source[alignment..];
                        assert_eq!(
                            classifier.find_last_member(bytes),
                            bytes.iter().rposition(|&byte| classifier.set().contains(byte)),
                            "reverse multiple alignment={alignment} len={len} position={position}"
                        );
                        if position != 0 {
                            source[alignment + position] = nonmember;
                        }
                    }
                    source[alignment] = nonmember;
                }
            }
        }
    }

    #[cfg(all(not(feature = "static-dispatch"), target_arch = "x86_64"))]
    #[test]
    fn forced_avx2_whole_slice_uses_authenticated_ssse3_tail() {
        use crate::{Feature, FeatureSet};

        let context = SimdDispatchContext::capture();
        let usable = context.capabilities().usable();
        if !usable.contains(Feature::X86Ssse3) || !usable.contains(Feature::X86Avx2) {
            return;
        }

        let mut words = [0_u64; 4];
        for member in [b'Q', 0xe3] {
            words[usize::from(member >> 6)] |= 1_u64 << (member & 63);
        }
        let set = ByteSet256::from_words(words);
        let scalar_tail = context
            .byte_set_classifier(
                set,
                DispatchPolicy::AllowOnly(FeatureSet::of(Feature::X86Avx2)),
            )
            .unwrap();
        assert_eq!(
            scalar_tail.selection().variant_id,
            "byte-set.mask16.scalar.v1"
        );
        assert_eq!(
            scalar_tail.wide_selection().variant_id,
            "byte-set.mask32.avx2.v1"
        );
        assert_eq!(scalar_tail.wide_selection().delegate_variant_id, None);
        assert_whole_slice_tail_boundaries(&scalar_tail, b'Q', b'x');
        assert_whole_slice_tail_boundaries(&scalar_tail, 0xe3, b'x');

        let classifier = context
            .byte_set_classifier(
                set,
                DispatchPolicy::AllowOnly(
                    FeatureSet::of(Feature::X86Ssse3).with(Feature::X86Avx2),
                ),
            )
            .unwrap();
        assert_eq!(
            classifier.selection().variant_id,
            "byte-set.mask16.ssse3.v1"
        );
        assert_eq!(
            classifier.wide_selection().variant_id,
            "byte-set.mask32.avx2.v1"
        );
        assert_eq!(classifier.wide_selection().delegate_variant_id, None);
        assert_eq!(
            classifier.candidate_block_bytes(),
            BYTE_SET_WIDE_BLOCK_BYTES
        );

        assert_whole_slice_tail_boundaries(&classifier, b'Q', b'x');
        assert_whole_slice_tail_boundaries(&classifier, 0xe3, b'x');
    }

    #[cfg(all(not(feature = "static-dispatch"), target_arch = "x86_64"))]
    #[test]
    fn forced_ssse3_whole_slice_finder_is_exact_on_avx2_hosts() {
        use crate::{Feature, FeatureSet};

        let context = SimdDispatchContext::capture();
        let usable = context.capabilities().usable();
        if !usable.contains(Feature::X86Ssse3) {
            return;
        }

        let mut words = [0_u64; 4];
        for member in [b'Q', 0xe3] {
            words[usize::from(member >> 6)] |= 1_u64 << (member & 63);
        }
        let set = ByteSet256::from_words(words);
        let classifier = context
            .byte_set_classifier(
                set,
                DispatchPolicy::AllowOnly(FeatureSet::of(Feature::X86Ssse3)),
            )
            .unwrap();
        assert_eq!(classifier.selection().variant_id, "byte-set.mask16.ssse3.v1");
        assert_eq!(classifier.candidate_block_bytes(), BYTE_SET_BLOCK_BYTES);
        assert_eq!(
            classifier.wide_selection().delegate_variant_id,
            Some("byte-set.mask16.ssse3.v1")
        );
        assert!(!classifier
            .selection()
            .policy_usable
            .contains(Feature::X86Avx2));
        if usable.contains(Feature::X86Avx2) {
            assert_eq!(
                classifier.candidate_selection().variant_id,
                "byte-set.mask16.ssse3.v1",
                "AllowOnly must exercise SSSE3 even on an AVX2-capable host"
            );
        }

        for alignment in [0_usize, 1, 15, 16, 31] {
            let mut source = vec![b'x'; alignment + 289];
            assert_eq!(classifier.find_first_member(&source[alignment..]), None);
            for position in [
                0_usize, 1, 15, 16, 17, 31, 32, 63, 64, 127, 128, 255, 256,
                287, 288,
            ] {
                source[alignment + position] = if position & 1 == 0 { b'Q' } else { 0xe3 };
                assert_eq!(
                    classifier.find_first_member(&source[alignment..]),
                    Some(position),
                    "alignment={alignment} position={position}"
                );
                source[alignment + position] = b'x';
            }
        }
    }

    #[test]
    fn every_byte_and_singleton_is_exact() {
        for member in 0_u8..=u8::MAX {
            let mut words = [0_u64; 4];
            words[usize::from(member >> 6)] |= 1_u64 << (member & 63);
            let set = ByteSet256::from_words(words);
            let classifier = ByteSetClassifier::new(set);
            for base in (0_u16..=u16::from(u8::MAX)).step_by(BYTE_SET_BLOCK_BYTES) {
                let block = core::array::from_fn(|lane| {
                    u8::try_from(base + u16::try_from(lane).unwrap()).unwrap()
                });
                let expected = if usize::from(member) / BYTE_SET_BLOCK_BYTES
                    == usize::from(base) / BYTE_SET_BLOCK_BYTES
                {
                    1_u16 << (usize::from(member) % BYTE_SET_BLOCK_BYTES)
                } else {
                    0
                };
                assert_eq!(classifier.classify_16(&block).member_mask(), expected);
            }
        }
    }

    #[test]
    fn wide_classifier_matches_arbitrary_sets_for_every_alignment() {
        let mut random = 0x243f_6a88_85a3_08d3_u64;
        let mut source = [0_u8; BYTE_SET_WIDE_BLOCK_BYTES + 31];
        for _ in 0..256 {
            let set = ByteSet256::from_words(core::array::from_fn(|_| next_random(&mut random)));
            let classifier = ByteSetClassifier::new(set);
            for byte in &mut source {
                *byte = next_random(&mut random).to_le_bytes()[0];
            }
            for alignment in 0..=31 {
                let block: &[u8; BYTE_SET_WIDE_BLOCK_BYTES] = source
                    [alignment..alignment + BYTE_SET_WIDE_BLOCK_BYTES]
                    .try_into()
                    .unwrap();
                let expected = block.iter().enumerate().fold(0_u32, |mask, (lane, &byte)| {
                    mask | (u32::from(set.contains(byte)) << lane)
                });
                assert_eq!(classifier.classify_32(block).member_mask(), expected);
            }
            let receipt = classifier.wide_selection();
            assert_eq!(receipt.selection_input_bytes, BYTE_SET_WIDE_BLOCK_BYTES);
            assert_eq!(receipt.minimum_input_bytes, BYTE_SET_WIDE_BLOCK_BYTES);
            let candidate = classifier.candidate_selection();
            assert_eq!(
                candidate.selection_input_bytes,
                classifier.candidate_block_bytes()
            );
            assert_eq!(
                candidate.minimum_input_bytes,
                classifier.candidate_block_bytes()
            );
        }
    }

    #[cfg(not(feature = "static-dispatch"))]
    #[test]
    fn portable_policy_retains_the_authenticated_narrow_candidate_leaf() {
        let classifier = ByteSetClassifier::with_policy(
            ByteSet256::from_words([
                0x0123_4567_89ab_cdef,
                0xfedc_ba98_7654_3210,
                0xaaaa_5555_ffff_0000,
                0x1357_9bdf_2468_ace0,
            ]),
            DispatchPolicy::Portable,
        )
        .unwrap();
        assert_eq!(classifier.candidate_block_bytes(), BYTE_SET_BLOCK_BYTES);
        assert_eq!(
            classifier.candidate_selection().variant_id,
            "byte-set.mask16.scalar.v1"
        );
        assert_eq!(
            classifier.wide_selection().variant_id,
            "byte-set.mask32.split16.v1"
        );
        assert_eq!(
            classifier.wide_selection().delegate_variant_id,
            Some("byte-set.mask16.scalar.v1")
        );
    }

    #[cfg(all(
        target_arch = "aarch64",
        target_os = "linux",
        target_endian = "little",
        target_feature = "sve",
        target_feature = "sve2"
    ))]
    #[test]
    fn small_mixed_whole_slice_sve2_respects_dispatch_authority() {
        let set = ByteSet256::from_words([1, 0, 1, 0]);
        #[cfg(not(feature = "static-dispatch"))]
        {
            use crate::{Feature, FeatureSet};

            let portable = ByteSetClassifier::with_policy(set, DispatchPolicy::Portable).unwrap();
            assert!(!portable.supports_small_mixed_whole_slice_sve2());

            let neon_only = ByteSetClassifier::with_policy(
                set,
                DispatchPolicy::AllowOnly(FeatureSet::of(Feature::ArmNeon)),
            )
            .unwrap();
            assert!(!neon_only.supports_small_mixed_whole_slice_sve2());

            let sve2_only = ByteSetClassifier::with_policy(
                set,
                DispatchPolicy::AllowOnly(
                    FeatureSet::of(Feature::ArmSve).with(Feature::ArmSve2),
                ),
            )
            .unwrap();

            let automatic = ByteSetClassifier::new(set);
            let usable = automatic.selection().policy_usable;
            if usable.contains(Feature::ArmSve) && usable.contains(Feature::ArmSve2) {
                assert!(sve2_only.supports_small_mixed_whole_slice_sve2());
                assert!(automatic.supports_small_mixed_whole_slice_sve2());
            } else {
                assert!(!sve2_only.supports_small_mixed_whole_slice_sve2());
                assert!(!automatic.supports_small_mixed_whole_slice_sve2());
            }
        }
        #[cfg(feature = "static-dispatch")]
        {
            let automatic = ByteSetClassifier::new(set);
            assert_eq!(
                automatic.supports_small_mixed_whole_slice_sve2(),
                cfg!(feature = "static-dispatch-arm-41-d84")
            );
        }
    }

    #[cfg(all(
        not(feature = "static-dispatch"),
        target_arch = "aarch64",
        target_os = "linux",
        target_endian = "little"
    ))]
    #[test]
    fn forced_sve2_whole_slice_uses_authenticated_narrow_tail() {
        use crate::{Feature, FeatureSet, TuningClass};

        let context = SimdDispatchContext::capture();
        let usable = context.capabilities().usable();
        if !usable.contains(Feature::ArmSve) || !usable.contains(Feature::ArmSve2) {
            return;
        }

        let mut words = [0_u64; 4];
        for member in (0_u8..=16).chain([b'Q', 0xe3]) {
            words[usize::from(member >> 6)] |= 1_u64 << (member & 63);
        }
        let set = ByteSet256::from_words(words);
        let sve2_features = FeatureSet::of(Feature::ArmSve).with(Feature::ArmSve2);
        let scalar_tail = context
            .byte_set_classifier(set, DispatchPolicy::AllowOnly(sve2_features))
            .unwrap();
        assert_eq!(
            scalar_tail.selection().variant_id,
            "byte-set.mask16.scalar.v1"
        );
        assert_eq!(
            scalar_tail.candidate_block_bytes(),
            BYTE_SET_WIDE_BLOCK_BYTES
        );
        assert_eq!(scalar_tail.wide_selection().delegate_variant_id, None);
        assert_whole_slice_tail_boundaries(&scalar_tail, b'Q', b'x');
        assert_whole_slice_tail_boundaries(&scalar_tail, 0xe3, b'x');

        let neoverse_v3 = matches!(
            context.capabilities().tuning(),
            TuningClass::ArmServer { cpu: Some(cpu) }
                if cpu.implementer == 0x41 && cpu.part == 0xd84
        );
        if usable.contains(Feature::ArmNeon) && neoverse_v3 {
            let asimd_tail = context
                .byte_set_classifier(
                    set,
                    DispatchPolicy::AllowOnly(sve2_features.with(Feature::ArmNeon)),
                )
                .unwrap();
            assert_eq!(
                asimd_tail.selection().variant_id,
                "byte-set.mask16.neon.v1"
            );
            assert_eq!(
                asimd_tail.wide_selection().variant_id,
                "byte-set.mask32.sve2.arm-41-d84.v1"
            );
            assert_eq!(asimd_tail.wide_selection().delegate_variant_id, None);
            assert_whole_slice_tail_boundaries(&asimd_tail, b'Q', b'x');
            assert_whole_slice_tail_boundaries(&asimd_tail, 0xe3, b'x');
        }
    }

    #[cfg(all(not(feature = "static-dispatch"), target_arch = "x86_64"))]
    #[test]
    fn x86_automatic_wide_tier_uses_avx2_and_keeps_avx512_policy_explicit() {
        use crate::Feature;

        let context = SimdDispatchContext::capture();
        let classifier = context
            .byte_set_classifier(ByteSet256::from_words([u64::MAX; 4]), DispatchPolicy::Auto)
            .unwrap();
        if context.capabilities().usable().contains(Feature::X86Avx2) {
            assert_eq!(
                classifier.candidate_block_bytes(),
                BYTE_SET_WIDE_BLOCK_BYTES
            );
            assert_eq!(
                classifier.candidate_selection().variant_id,
                "byte-set.mask32.avx2.v1"
            );
            if context
                .capabilities()
                .usable()
                .contains(Feature::X86Avx512F)
                && context
                    .capabilities()
                    .usable()
                    .contains(Feature::X86Avx512Bw)
                && context
                    .capabilities()
                    .usable()
                    .contains(Feature::X86Avx512Vl)
            {
                assert_eq!(
                    classifier.candidate_selection().variant_id,
                    "byte-set.mask32.avx2.v1",
                    "AVX-512 remains an explicit future tier until independently qualified"
                );
            }
        } else {
            assert_eq!(classifier.candidate_block_bytes(), BYTE_SET_BLOCK_BYTES);
            assert!(classifier.wide_selection().delegate_variant_id.is_some());
        }
    }

    #[cfg(all(
        not(feature = "static-dispatch"),
        target_arch = "aarch64",
        target_os = "linux",
        target_endian = "little"
    ))]
    #[test]
    fn aarch64_automatic_wide_tier_and_whole_slice_follow_host_policy() {
        use crate::{Feature, TuningClass};

        let context = SimdDispatchContext::capture();
        let classifier = context
            .byte_set_classifier(ByteSet256::from_words([u64::MAX; 4]), DispatchPolicy::Auto)
            .unwrap();
        let usable = context.capabilities().usable();
        let sve2 = usable.contains(Feature::ArmSve) && usable.contains(Feature::ArmSve2);
        let neoverse_v3 = matches!(
            context.capabilities().tuning(),
            TuningClass::ArmServer { cpu: Some(cpu) }
                if cpu.implementer == 0x41 && cpu.part == 0xd84
        );
        if sve2 && neoverse_v3 {
            assert_eq!(
                classifier.candidate_block_bytes(),
                BYTE_SET_WIDE_BLOCK_BYTES
            );
            assert_eq!(
                classifier.candidate_selection().variant_id,
                "byte-set.mask32.sve2.arm-41-d84.v1"
            );
        } else if usable.contains(Feature::ArmNeon) {
            assert_eq!(classifier.candidate_block_bytes(), BYTE_SET_BLOCK_BYTES);
            assert_eq!(
                classifier.wide_selection().variant_id,
                "byte-set.mask32.split16-neon.v1"
            );
            assert!(classifier.wide_selection().delegate_variant_id.is_some());
        } else if sve2 {
            assert_eq!(
                classifier.candidate_block_bytes(),
                BYTE_SET_WIDE_BLOCK_BYTES
            );
            assert_eq!(
                classifier.candidate_selection().variant_id,
                "byte-set.mask32.sve2.v1"
            );
        } else {
            assert_eq!(classifier.candidate_block_bytes(), BYTE_SET_BLOCK_BYTES);
        }

        if classifier.candidate_block_bytes() == BYTE_SET_WIDE_BLOCK_BYTES {
            let general_set = ByteSet256::from_words([
                0x5555_5555_5555_5555,
                0,
                0x5555_5555_5555_5555,
                0,
            ]);
            let general = context
                .byte_set_classifier(general_set, DispatchPolicy::Auto)
                .unwrap();
            assert_eq!(
                general.candidate_selection().variant_id,
                classifier.candidate_selection().variant_id
            );
            let mut source = vec![1_u8; 258];
            source[255] = 0x80;
            assert_eq!(general.find_first_member(&source), Some(255));
            source[255] = 1;
            source[256] = 0x80;
            assert_eq!(general.find_first_member(&source), Some(256));
            source[256] = 1;
            assert_eq!(general.find_first_member(&source), None);
        }
    }

    #[cfg(all(
        feature = "static-dispatch-arm-41-d84",
        target_arch = "aarch64",
        target_os = "linux",
        target_endian = "little",
        target_feature = "sve",
        target_feature = "sve2"
    ))]
    #[test]
    #[allow(
        unsafe_code,
        reason = "the authenticated static profile proves SVE usable before the test reads its effective vector length"
    )]
    fn static_sve2_wide_classifier_attests_vector_length_and_two_chunk_boundaries() {
        let mut words = [0_u64; 4];
        let members = [0_u8, 7, 31, 63, 64, 95, 127, 128, 191, 200, 255];
        for member in members {
            words[usize::from(member >> 6)] |= 1_u64 << (member & 63);
        }
        let set = ByteSet256::from_words(words);
        let classifier = ByteSetClassifier::new(set);
        assert_eq!(
            classifier.candidate_selection().variant_id,
            "byte-set.mask32.sve2.v1"
        );

        let vector_bytes: usize;
        // SAFETY: this test is compiled only when the authenticated static
        // target enables SVE. CNTB reads thread-local architectural state and
        // has no memory or stack effects.
        unsafe {
            core::arch::asm!(
                "cntb {vector_bytes}",
                vector_bytes = out(reg) vector_bytes,
                options(nomem, nostack, preserves_flags)
            );
        }
        assert!((16..=256).contains(&vector_bytes));
        assert_eq!(vector_bytes % 16, 0);
        eprintln!("FRE_EFFECTIVE_SVE_VL_BYTES={vector_bytes}");

        for rotation in 0..BYTE_SET_WIDE_BLOCK_BYTES {
            let block = core::array::from_fn(|lane| {
                if lane % 3 == 0 {
                    members[(lane + rotation) % members.len()]
                } else {
                    0xfe
                }
            });
            let expected = block.iter().enumerate().fold(0_u32, |mask, (lane, &byte)| {
                mask | (u32::from(set.contains(byte)) << lane)
            });
            assert_eq!(classifier.classify_32(&block).member_mask(), expected);
            assert_ne!(expected & 0x0000_ffff, 0);
            assert_ne!(expected & 0xffff_0000, 0);
        }

        let general_set = ByteSet256::from_words([
            0x5555_5555_5555_5555,
            0,
            0x5555_5555_5555_5555,
            0,
        ]);
        let general = ByteSetClassifier::new(general_set);
        assert_eq!(
            general.candidate_selection().variant_id,
            "byte-set.mask32.sve2.v1"
        );
        assert_whole_slice_tail_boundaries(&general, 0x80, 1);
        let mut source = vec![1_u8; 258];
        source[255] = 0x80;
        assert_eq!(general.find_first_member(&source), Some(255));
        source[255] = 1;
        source[256] = 0x80;
        assert_eq!(general.find_first_member(&source), Some(256));
        source[256] = 1;
        assert_eq!(general.find_first_member(&source), None);
    }

    #[cfg(not(feature = "static-dispatch"))]
    #[test]
    fn portable_scalar_fallback_matches_every_byte() {
        let set = ByteSet256::from_words([
            0x0123_4567_89ab_cdef,
            0xfedc_ba98_7654_3210,
            0xaaaa_5555_ffff_0000,
            0x1357_9bdf_2468_ace0,
        ]);
        let classifier = ByteSetClassifier::with_policy(set, DispatchPolicy::Portable).unwrap();
        let source: [[u8; BYTE_SET_BLOCK_BYTES]; 16] = core::array::from_fn(|block| {
            core::array::from_fn(|lane| u8::try_from(block * BYTE_SET_BLOCK_BYTES + lane).unwrap())
        });
        for block in source {
            let expected = block.iter().enumerate().fold(0_u16, |mask, (lane, &byte)| {
                mask | (u16::from(set.contains(byte)) << lane)
            });
            assert_eq!(classifier.classify_16(&block).member_mask(), expected);
        }
    }
}
