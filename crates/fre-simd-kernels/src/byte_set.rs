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
/// Exact abstract work to visit all byte values and bind one immutable leaf.
pub const BYTE_SET_CLASSIFIER_BUILD_WORK: usize = 256 + 1;

const BYTE_SET_VECTOR_BYTES: u16 = 16;
#[cfg(all(
    feature = "static-dispatch",
    target_arch = "x86_64",
    target_feature = "avx2"
))]
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
        #[cfg(feature = "static-dispatch")]
        require_static_selection(
            selected.receipt(),
            automatic_selection(),
            static_variant_id(),
        )?;
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
    /// Portable and runtime-dispatched loops retain the authenticated 16-byte
    /// leaf. Only compiler-static profiles with a reviewed native wide leaf
    /// report 32 bytes.
    #[must_use]
    pub const fn candidate_selection(&self) -> SelectionReceipt {
        if BYTE_SET_CANDIDATE_BLOCK_BYTES == BYTE_SET_WIDE_BLOCK_BYTES {
            self.wide_selection()
        } else {
            self.selection()
        }
    }

    /// Stable receipt for the explicit 32-byte classification operation.
    #[must_use]
    #[cfg(not(feature = "static-dispatch"))]
    pub const fn wide_selection(&self) -> SelectionReceipt {
        SelectionReceipt {
            variant_id: SPLIT_MASK32_VARIANT_ID,
            delegate_variant_id: Some(self.selection.variant_id),
            selection_input_bytes: BYTE_SET_WIDE_BLOCK_BYTES,
            minimum_input_bytes: BYTE_SET_WIDE_BLOCK_BYTES,
            ..self.selection
        }
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
    /// operations. Only compiler-static profiles with a reviewed native leaf
    /// replace that split operation.
    #[must_use]
    #[allow(
        unsafe_code,
        reason = "the compiler-static cfg and fixed array jointly prove every native wide leaf; other builds execute two safe narrow calls"
    )]
    pub fn classify_32(&self, bytes: &[u8; BYTE_SET_WIDE_BLOCK_BYTES]) -> ByteSetMask32 {
        #[cfg(all(
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

#[cfg(target_arch = "aarch64")]
#[allow(
    unsafe_code,
    unsafe_op_in_unsafe_fn,
    reason = "the private NEON leaf is reachable only through authenticated dispatch and exact fixed extents"
)]
#[target_feature(enable = "neon")]
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

#[cfg(target_arch = "x86_64")]
#[allow(
    unsafe_code,
    unsafe_op_in_unsafe_fn,
    reason = "the private SSSE3 leaf is reachable only through authenticated dispatch and exact fixed extents"
)]
#[target_feature(enable = "ssse3")]
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

fn select(
    capabilities: CpuCapabilities,
    policy: DispatchPolicy,
) -> Result<SelectedKernel<ByteSetEntry>, UnsupportedRequiredFeatures> {
    Ok(
        select_kernel(capabilities, policy, BYTE_SET_BLOCK_BYTES, &VARIANTS)?
            .expect("the byte-set table always contains its scalar fallback"),
    )
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
    feature = "static-dispatch",
    target_arch = "x86_64",
    target_feature = "avx2"
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
        BYTE_SET_BLOCK_BYTES, BYTE_SET_CANDIDATE_BLOCK_BYTES, BYTE_SET_WIDE_BLOCK_BYTES,
        ByteSet256, ByteSetClassifier, classify_scalar,
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
                BYTE_SET_CANDIDATE_BLOCK_BYTES
            );
            assert_eq!(
                candidate.minimum_input_bytes,
                BYTE_SET_CANDIDATE_BLOCK_BYTES
            );
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
