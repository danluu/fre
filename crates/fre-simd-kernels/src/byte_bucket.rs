//! Fixed-capacity full-byte bucket classification.
//!
//! This is the reusable SIMD leaf needed by small packed multi-literal
//! searchers. Each pattern column owns two 16-byte nibble tables. Every output
//! byte is an eight-bit bucket set for one candidate start. Multiple columns
//! are correlated by intersecting those bucket sets before returning them.

use core::fmt;

#[cfg(feature = "static-dispatch")]
use crate::require_static_selection;
use crate::{
    Architecture, ArchitectureRequirement, CpuCapabilities, DispatchPolicy, Feature, FeatureSet,
    KernelVariant, SelectedKernel, SelectionReceipt, UnsupportedRequiredFeatures, VectorKind,
    select_kernel,
};

/// Candidate starts classified by one narrow operation.
pub const BYTE_BUCKET_BLOCK_BYTES: usize = 16;
/// Number of correlated buckets represented in every output lane.
pub const BYTE_BUCKET_COUNT: usize = 8;
/// Largest admitted number of byte columns.
pub const BYTE_BUCKET_MAX_COLUMNS: usize = 4;

const BYTE_BUCKET_VECTOR_BYTES: u16 = 16;
const SCALAR_VARIANT_ID: &str = "byte-bucket.mask16.scalar.v1";
#[cfg(target_arch = "aarch64")]
const NEON_VARIANT_ID: &str = "byte-bucket.mask16.neon.v1";

/// Invalid fixed table shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteBucketTableError {
    pub columns: usize,
}

impl fmt::Display for ByteBucketTableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "byte-bucket column count {} is outside 1..={BYTE_BUCKET_MAX_COLUMNS}",
            self.columns
        )
    }
}

impl std::error::Error for ByteBucketTableError {}

/// Fixed low/high-nibble lookup tables for up to four correlated columns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteBucketTables {
    columns: u8,
    low: [[u8; 16]; BYTE_BUCKET_MAX_COLUMNS],
    high: [[u8; 16]; BYTE_BUCKET_MAX_COLUMNS],
}

impl ByteBucketTables {
    /// Bind already-accounted fixed lookup tables to an admitted column count.
    pub fn new(
        columns: usize,
        low: [[u8; 16]; BYTE_BUCKET_MAX_COLUMNS],
        high: [[u8; 16]; BYTE_BUCKET_MAX_COLUMNS],
    ) -> Result<Self, ByteBucketTableError> {
        if !(1..=BYTE_BUCKET_MAX_COLUMNS).contains(&columns) {
            return Err(ByteBucketTableError { columns });
        }
        Ok(Self {
            columns: u8::try_from(columns).expect("the certified column count fits in u8"),
            low,
            high,
        })
    }

    /// Number of correlated source columns.
    #[must_use]
    pub fn columns(self) -> usize {
        usize::from(self.columns)
    }

    /// Exact source extent required to classify sixteen candidate starts.
    #[must_use]
    pub fn required_input_bytes(self) -> usize {
        BYTE_BUCKET_BLOCK_BYTES
            .checked_add(self.columns())
            .and_then(|bytes| bytes.checked_sub(1))
            .expect("the fixed block and column extents fit in usize")
    }
}

/// Eight-bit bucket sets for sixteen candidate starts, packed little-endian
/// into two words. Byte `i` is the bucket set for candidate lane `i`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteBucketMasks16 {
    chunks: [u64; 2],
}

impl ByteBucketMasks16 {
    fn from_lanes(lanes: [u8; BYTE_BUCKET_BLOCK_BYTES]) -> Self {
        let first = u64::from_le_bytes(
            lanes[..8]
                .try_into()
                .expect("the first bucket-mask chunk has eight lanes"),
        );
        let second = u64::from_le_bytes(
            lanes[8..]
                .try_into()
                .expect("the second bucket-mask chunk has eight lanes"),
        );
        Self {
            chunks: [first, second],
        }
    }

    /// Two little-endian groups of eight per-lane bucket bytes.
    #[must_use]
    pub const fn chunks(self) -> [u64; 2] {
        self.chunks
    }
}

#[allow(
    unsafe_code,
    reason = "the private function-pointer type retains a target-feature proof selected from immutable host facts"
)]
#[cfg(not(feature = "static-dispatch"))]
type ByteBucketEntry = unsafe fn(&ByteBucketTables, &[u8]) -> ByteBucketMasks16;

#[cfg(feature = "static-dispatch")]
type ByteBucketEntry = ();

macro_rules! byte_bucket_entry {
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

/// Compiled full-byte bucket classifier with one immutable dispatch choice.
#[derive(Clone, Copy)]
pub struct ByteBucketClassifier {
    tables: ByteBucketTables,
    #[cfg(not(feature = "static-dispatch"))]
    entry: ByteBucketEntry,
    #[cfg(not(feature = "static-dispatch"))]
    selection: SelectionReceipt,
}

impl fmt::Debug for ByteBucketClassifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ByteBucketClassifier")
            .field("columns", &self.tables.columns())
            .field("selection", &self.selection())
            .finish_non_exhaustive()
    }
}

impl ByteBucketClassifier {
    /// Build under all OS-usable host features.
    #[must_use]
    pub fn new(tables: ByteBucketTables) -> Self {
        Self::with_policy(tables, DispatchPolicy::Auto)
            .expect("automatic bucket dispatch always retains a scalar fallback")
    }

    /// Build under an authentic host-feature policy.
    pub fn with_policy(
        tables: ByteBucketTables,
        policy: DispatchPolicy,
    ) -> Result<Self, UnsupportedRequiredFeatures> {
        crate::SimdDispatchContext::capture().byte_bucket_classifier(tables, policy)
    }

    pub(crate) fn with_capabilities(
        tables: ByteBucketTables,
        capabilities: CpuCapabilities,
        policy: DispatchPolicy,
    ) -> Result<Self, UnsupportedRequiredFeatures> {
        #[cfg(feature = "static-dispatch")]
        if policy == DispatchPolicy::Auto && capabilities == *crate::host() {
            return Ok(Self::from_static_profile(tables));
        }
        let selected = select(capabilities, policy)?;
        #[cfg(feature = "static-dispatch")]
        require_static_selection(
            selected.receipt(),
            automatic_selection(),
            static_variant_id(),
        )?;
        Ok(Self {
            tables,
            #[cfg(not(feature = "static-dispatch"))]
            entry: selected.entry(),
            #[cfg(not(feature = "static-dispatch"))]
            selection: selected.receipt(),
        })
    }

    #[cfg(feature = "static-dispatch")]
    pub(crate) const fn from_static_profile(tables: ByteBucketTables) -> Self {
        Self { tables }
    }

    /// Fixed tables retained by this classifier.
    #[must_use]
    pub const fn tables(&self) -> ByteBucketTables {
        self.tables
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
        automatic_selection()
    }

    /// Classify sixteen starts. Returns `None` before entering a leaf when the
    /// source does not cover all compiled columns.
    #[must_use]
    #[allow(
        unsafe_code,
        reason = "construction retained this private entry only after proving its target features; the extent check proves every shifted fixed load"
    )]
    pub fn classify_16(&self, bytes: &[u8]) -> Option<ByteBucketMasks16> {
        if bytes.len() < self.tables.required_input_bytes() {
            return None;
        }
        #[cfg(not(feature = "static-dispatch"))]
        {
            // SAFETY: selection authenticated the entry, and the source check
            // above covers sixteen bytes at every compiled column.
            Some(unsafe { (self.entry)(&self.tables, bytes) })
        }
        #[cfg(feature = "static-dispatch")]
        {
            // SAFETY: construction admitted only the compiler-fixed leaf and
            // the source extent is proved above.
            Some(unsafe { static_classify(&self.tables, bytes) })
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
unsafe fn classify_scalar_entry(tables: &ByteBucketTables, bytes: &[u8]) -> ByteBucketMasks16 {
    classify_scalar(tables, bytes)
}

#[cfg_attr(
    all(feature = "static-dispatch", not(test)),
    allow(
        dead_code,
        reason = "AArch64 compiler-fixed production builds select the direct NEON leaf; tests retain the scalar oracle"
    )
)]
fn classify_scalar(tables: &ByteBucketTables, bytes: &[u8]) -> ByteBucketMasks16 {
    let mut lanes = [u8::MAX; BYTE_BUCKET_BLOCK_BYTES];
    for column in 0..tables.columns() {
        for lane in 0..BYTE_BUCKET_BLOCK_BYTES {
            let byte = bytes[column
                .checked_add(lane)
                .expect("fixed column and lane extents fit in usize")];
            lanes[lane] &= tables.low[column][usize::from(byte & 0x0f)]
                & tables.high[column][usize::from(byte >> 4)];
        }
    }
    ByteBucketMasks16::from_lanes(lanes)
}

#[cfg(target_arch = "aarch64")]
#[allow(
    unsafe_code,
    unsafe_op_in_unsafe_fn,
    reason = "the private NEON leaf is reachable only through authenticated dispatch and fixed source/table extents"
)]
#[target_feature(enable = "neon")]
unsafe fn classify_neon(tables: &ByteBucketTables, bytes: &[u8]) -> ByteBucketMasks16 {
    use core::arch::aarch64::{vandq_u8, vdupq_n_u8, vld1q_u8, vqtbl1q_u8, vshrq_n_u8, vst1q_u8};

    let mut candidates = vdupq_n_u8(u8::MAX);
    let nibble_mask = vdupq_n_u8(0x0f);
    for column in 0..tables.columns() {
        let input = vld1q_u8(bytes.as_ptr().add(column));
        let low_nibbles = vandq_u8(input, nibble_mask);
        let high_nibbles = vshrq_n_u8::<4>(input);
        let low_table = vld1q_u8(tables.low[column].as_ptr());
        let high_table = vld1q_u8(tables.high[column].as_ptr());
        let low_buckets = vqtbl1q_u8(low_table, low_nibbles);
        let high_buckets = vqtbl1q_u8(high_table, high_nibbles);
        candidates = vandq_u8(candidates, vandq_u8(low_buckets, high_buckets));
    }
    let mut lanes = [0_u8; BYTE_BUCKET_BLOCK_BYTES];
    vst1q_u8(lanes.as_mut_ptr(), candidates);
    ByteBucketMasks16::from_lanes(lanes)
}

const SCALAR: KernelVariant<ByteBucketEntry> = KernelVariant::new(
    SCALAR_VARIANT_ID,
    ArchitectureRequirement::Any,
    FeatureSet::EMPTY,
    VectorKind::Scalar,
    BYTE_BUCKET_BLOCK_BYTES,
    0,
    byte_bucket_entry!(classify_scalar_entry),
);

#[cfg(target_arch = "aarch64")]
const VARIANTS: [KernelVariant<ByteBucketEntry>; 2] = [
    SCALAR,
    KernelVariant::new(
        NEON_VARIANT_ID,
        ArchitectureRequirement::Exact(Architecture::Aarch64),
        FeatureSet::of(Feature::ArmNeon),
        VectorKind::Fixed {
            bytes: BYTE_BUCKET_VECTOR_BYTES,
        },
        BYTE_BUCKET_BLOCK_BYTES,
        100,
        byte_bucket_entry!(classify_neon),
    ),
];

#[cfg(not(target_arch = "aarch64"))]
const VARIANTS: [KernelVariant<ByteBucketEntry>; 1] = [SCALAR];

fn select(
    capabilities: CpuCapabilities,
    policy: DispatchPolicy,
) -> Result<SelectedKernel<ByteBucketEntry>, UnsupportedRequiredFeatures> {
    Ok(
        select_kernel(capabilities, policy, BYTE_BUCKET_BLOCK_BYTES, &VARIANTS)?
            .expect("the byte-bucket table always contains its scalar fallback"),
    )
}

#[cfg(feature = "static-dispatch")]
const fn automatic_selection() -> SelectionReceipt {
    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    let (variant_id, required, vector) = (
        NEON_VARIANT_ID,
        FeatureSet::of(Feature::ArmNeon),
        VectorKind::Fixed {
            bytes: BYTE_BUCKET_VECTOR_BYTES,
        },
    );
    #[cfg(not(all(target_arch = "aarch64", target_feature = "neon")))]
    let (variant_id, required, vector) = (SCALAR_VARIANT_ID, FeatureSet::EMPTY, VectorKind::Scalar);
    crate::compiler_selection_receipt(
        variant_id,
        None,
        required,
        vector,
        BYTE_BUCKET_BLOCK_BYTES,
        BYTE_BUCKET_BLOCK_BYTES,
    )
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
    not(all(target_arch = "aarch64", target_feature = "neon"))
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
    reason = "the compiler-fixed profile proves NEON and the caller proves every source/table extent"
)]
unsafe fn static_classify(tables: &ByteBucketTables, bytes: &[u8]) -> ByteBucketMasks16 {
    // SAFETY: this static leaf is compiled with NEON and classify_16 proved
    // the complete shifted source extent.
    unsafe { classify_neon(tables, bytes) }
}

#[cfg(all(
    feature = "static-dispatch",
    not(all(target_arch = "aarch64", target_feature = "neon"))
))]
#[allow(
    unsafe_code,
    reason = "the scalar function shares the compiler-fixed leaf ABI but performs no unsafe operation"
)]
unsafe fn static_classify(tables: &ByteBucketTables, bytes: &[u8]) -> ByteBucketMasks16 {
    classify_scalar(tables, bytes)
}

#[cfg(test)]
mod tests {
    use super::{
        BYTE_BUCKET_BLOCK_BYTES, BYTE_BUCKET_MAX_COLUMNS, ByteBucketClassifier, ByteBucketTables,
        classify_scalar,
    };
    use crate::{DispatchPolicy, Feature, FeatureSet, SimdDispatchContext};

    fn tables(columns: usize) -> ByteBucketTables {
        let mut low = [[0_u8; 16]; BYTE_BUCKET_MAX_COLUMNS];
        let mut high = [[0_u8; 16]; BYTE_BUCKET_MAX_COLUMNS];
        for column in 0..columns {
            for byte in 0_u16..=255 {
                let byte = u8::try_from(byte).unwrap();
                let bucket = usize::from(
                    byte.wrapping_mul(29)
                        .wrapping_add(u8::try_from(column.checked_mul(17).unwrap()).unwrap())
                        & 7,
                );
                low[column][usize::from(byte & 0x0f)] |= 1_u8 << bucket;
                high[column][usize::from(byte >> 4)] |= 1_u8 << bucket;
            }
        }
        ByteBucketTables::new(columns, low, high).unwrap()
    }

    #[test]
    fn shape_and_extent_are_checked_before_dispatch() {
        let zero = ByteBucketTables::new(
            0,
            [[0; 16]; BYTE_BUCKET_MAX_COLUMNS],
            [[0; 16]; BYTE_BUCKET_MAX_COLUMNS],
        );
        assert!(zero.is_err());
        let too_many = ByteBucketTables::new(
            BYTE_BUCKET_MAX_COLUMNS + 1,
            [[0; 16]; BYTE_BUCKET_MAX_COLUMNS],
            [[0; 16]; BYTE_BUCKET_MAX_COLUMNS],
        );
        assert!(too_many.is_err());
        for columns in 1..=BYTE_BUCKET_MAX_COLUMNS {
            let classifier = ByteBucketClassifier::new(tables(columns));
            let needed = BYTE_BUCKET_BLOCK_BYTES + columns - 1;
            assert!(classifier.classify_16(&vec![0; needed - 1]).is_none());
            assert!(classifier.classify_16(&vec![0; needed]).is_some());
        }
    }

    #[test]
    fn automatic_leaf_matches_scalar_for_columns_alignments_and_full_bytes() {
        let context = SimdDispatchContext::capture();
        let mut source = [0_u8; BYTE_BUCKET_BLOCK_BYTES + BYTE_BUCKET_MAX_COLUMNS + 31];
        for (index, byte) in source.iter_mut().enumerate() {
            *byte = u8::try_from((index * 197 + 131) & 255).unwrap();
        }
        for columns in 1..=BYTE_BUCKET_MAX_COLUMNS {
            let tables = tables(columns);
            let classifier = context
                .byte_bucket_classifier(tables, DispatchPolicy::Auto)
                .unwrap();
            for alignment in 0..=31 {
                let bytes = &source[alignment..];
                assert_eq!(
                    classifier.classify_16(bytes).unwrap(),
                    classify_scalar(&tables, bytes)
                );
            }
        }
    }

    #[test]
    fn forced_neon_matches_scalar_when_available() {
        let context = SimdDispatchContext::capture();
        if !context.capabilities().usable().contains(Feature::ArmNeon) {
            return;
        }
        let mut source = [0_u8; BYTE_BUCKET_BLOCK_BYTES + BYTE_BUCKET_MAX_COLUMNS - 1];
        for seed in 0_u16..=255 {
            for (index, byte) in source.iter_mut().enumerate() {
                *byte = u8::try_from((usize::from(seed) + index * 113 + (index >> 1) * 29) & 255)
                    .unwrap();
            }
            for columns in 1..=BYTE_BUCKET_MAX_COLUMNS {
                let tables = tables(columns);
                let classifier = context
                    .byte_bucket_classifier(
                        tables,
                        DispatchPolicy::Require(FeatureSet::of(Feature::ArmNeon)),
                    )
                    .unwrap();
                assert_eq!(
                    classifier.classify_16(&source).unwrap(),
                    classify_scalar(&tables, &source)
                );
            }
        }
    }
}
