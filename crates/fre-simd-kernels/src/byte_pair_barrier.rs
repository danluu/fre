//! Scanning for a byte barrier or an adjacent delimiter/suffix-head pair.
//!
//! This is a reusable state-machine primitive for topologies where ordinary
//! delimiter bytes can be counted in bulk until either a barrier resets state
//! or a delimiter followed by a distinguished byte requires scalar handling.

use core::fmt;

#[cfg(feature = "static-dispatch")]
use crate::require_static_selection;
use crate::{
    Architecture, ArchitectureRequirement, CpuCapabilities, DispatchPolicy, Feature, FeatureSet,
    KernelVariant, SelectedKernel, SelectionReceipt, UnsupportedRequiredFeatures, VectorKind,
    select_kernel,
};

/// Minimum logical bytes covered by one vector fast-path group.
pub const BYTE_PAIR_BARRIER_GROUP_BYTES: usize = 64;

const BYTE_PAIR_BARRIER_VECTOR_BYTES: u16 = 16;
#[cfg(target_arch = "aarch64")]
const NEON_SCAN_GROUP_BYTES: usize = 256;
#[cfg(target_arch = "aarch64")]
const NEON_SCAN_GROUP_BLOCKS: usize = 16;
#[cfg(target_arch = "aarch64")]
const NEON_DELIMITER_REDUCTION_GROUPS: usize = 15;
#[cfg(target_arch = "x86_64")]
const SSE2_SCAN_GROUP_BYTES: usize = 64;
#[cfg(target_arch = "x86_64")]
const SSE2_DELIMITER_REDUCTION_GROUPS: usize = 63;
const SCALAR_VARIANT_ID: &str = "byte-pair-barrier.scan.scalar.v1";
#[cfg(target_arch = "aarch64")]
const NEON_VARIANT_ID: &str = "byte-pair-barrier.scan.neon.v1";
#[cfg(target_arch = "x86_64")]
const SSE2_VARIANT_ID: &str = "byte-pair-barrier.scan.sse2.v1";

/// Complete result of one byte-pair/barrier scan.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BytePairBarrierScan {
    /// Earliest delimiter/suffix-head pair, indexed at its delimiter.
    pub pair_index: Option<usize>,
    /// Last barrier strictly before the returned pair, or the last barrier in
    /// the complete source when `pair_index` is `None`.
    pub last_barrier: Option<usize>,
    /// Delimiters after `last_barrier`, through the returned pair delimiter or
    /// through the complete source when `pair_index` is `None`.
    pub delimiter_count: usize,
    /// All delimiters through the returned pair delimiter, or in the complete
    /// source when `pair_index` is `None`, independent of barriers.
    pub total_delimiter_count: usize,
}

#[allow(
    unsafe_code,
    reason = "the private function-pointer type retains a target-feature proof selected from immutable host facts"
)]
#[cfg(not(feature = "static-dispatch"))]
type BytePairBarrierEntry = unsafe fn([u8; 3], &[u8]) -> BytePairBarrierScan;

#[cfg(feature = "static-dispatch")]
type BytePairBarrierEntry = ();

macro_rules! byte_pair_barrier_entry {
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

/// Reusable delimiter/pair/barrier scanner with immutable one-time dispatch.
///
/// Signals are ordered as delimiter, suffix head, and barrier. When the
/// barrier also equals the delimiter, barrier precedence resets the delimiter
/// count and prevents a pair from beginning at that byte.
#[derive(Clone, Copy)]
pub struct BytePairBarrierScanner {
    signals: [u8; 3],
    #[cfg(not(feature = "static-dispatch"))]
    entry: BytePairBarrierEntry,
    #[cfg(not(feature = "static-dispatch"))]
    selection: SelectionReceipt,
}

impl fmt::Debug for BytePairBarrierScanner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BytePairBarrierScanner")
            .field("delimiter", &self.delimiter())
            .field("suffix_head", &self.suffix_head())
            .field("barrier", &self.barrier())
            .field("selection", &self.selection())
            .finish_non_exhaustive()
    }
}

impl BytePairBarrierScanner {
    /// Build under all OS-usable host features.
    #[must_use]
    pub fn new(delimiter: u8, suffix_head: u8, barrier: u8) -> Self {
        Self::with_policy(delimiter, suffix_head, barrier, DispatchPolicy::Auto)
            .expect("automatic byte-pair/barrier dispatch always retains a scalar fallback")
    }

    /// Build under an authentic host-feature policy.
    pub fn with_policy(
        delimiter: u8,
        suffix_head: u8,
        barrier: u8,
        policy: DispatchPolicy,
    ) -> Result<Self, UnsupportedRequiredFeatures> {
        crate::SimdDispatchContext::capture().byte_pair_barrier_scanner(
            delimiter,
            suffix_head,
            barrier,
            policy,
        )
    }

    pub(crate) fn with_capabilities(
        signals: [u8; 3],
        capabilities: CpuCapabilities,
        policy: DispatchPolicy,
    ) -> Result<Self, UnsupportedRequiredFeatures> {
        #[cfg(feature = "static-dispatch")]
        if policy == DispatchPolicy::Auto && capabilities == *crate::host() {
            return Ok(Self::from_static_profile(signals));
        }
        let selected = select(capabilities, policy)?;
        #[cfg(feature = "static-dispatch")]
        require_static_selection(
            selected.receipt(),
            automatic_selection(),
            static_variant_id(),
        )?;
        Ok(Self {
            signals,
            #[cfg(not(feature = "static-dispatch"))]
            entry: selected.entry(),
            #[cfg(not(feature = "static-dispatch"))]
            selection: selected.receipt(),
        })
    }

    #[cfg(feature = "static-dispatch")]
    pub(crate) const fn from_static_profile(signals: [u8; 3]) -> Self {
        Self { signals }
    }

    /// Configured delimiter byte.
    #[must_use]
    pub const fn delimiter(&self) -> u8 {
        self.signals[0]
    }

    /// Configured byte required immediately after a delimiter.
    #[must_use]
    pub const fn suffix_head(&self) -> u8 {
        self.signals[1]
    }

    /// Configured state-reset barrier byte.
    #[must_use]
    pub const fn barrier(&self) -> u8 {
        self.signals[2]
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

    /// Scan an arbitrary byte slice for its earliest delimiter/suffix pair.
    ///
    /// A pair event is indexed at its delimiter. The suffix-head byte is only
    /// observed as lookahead and is not included in `delimiter_count`.
    /// Barriers are absorbed into `last_barrier` and reset `delimiter_count`;
    /// scanning continues after them until a pair or the end.
    #[must_use]
    #[allow(
        unsafe_code,
        reason = "construction retained this private entry only after authenticating its target-feature requirements"
    )]
    pub fn scan(&self, bytes: &[u8]) -> BytePairBarrierScan {
        #[cfg(not(feature = "static-dispatch"))]
        {
            // SAFETY: construction authenticated the immutable retained entry.
            unsafe { (self.entry)(self.signals, bytes) }
        }
        #[cfg(feature = "static-dispatch")]
        {
            // SAFETY: construction admitted only the compiler-fixed leaf.
            unsafe { static_scan(self.signals, bytes) }
        }
    }
}

fn scan_scalar(signals: [u8; 3], bytes: &[u8]) -> BytePairBarrierScan {
    scan_scalar_prefix_from(signals, bytes, bytes.len(), 0, None, 0, 0)
}

fn scan_scalar_prefix_from(
    signals: [u8; 3],
    bytes: &[u8],
    logical_bytes: usize,
    index_base: usize,
    mut last_barrier: Option<usize>,
    mut delimiter_count: usize,
    mut total_delimiter_count: usize,
) -> BytePairBarrierScan {
    let [delimiter, suffix_head, barrier] = signals;
    let logical = bytes
        .get(..logical_bytes)
        .expect("the scalar logical prefix must fit in its source");
    for (relative, &byte) in logical.iter().enumerate() {
        let index = index_base
            .checked_add(relative)
            .expect("a subslice-relative index fits in its source slice");
        if byte == delimiter {
            total_delimiter_count = total_delimiter_count
                .checked_add(1)
                .expect("a total delimiter count cannot exceed its source slice length");
        }
        if byte == barrier {
            last_barrier = Some(index);
            delimiter_count = 0;
            continue;
        }
        if byte == delimiter {
            delimiter_count = delimiter_count
                .checked_add(1)
                .expect("a delimiter count cannot exceed its source slice length");
            if bytes.get(relative.saturating_add(1)) == Some(&suffix_head) {
                return BytePairBarrierScan {
                    pair_index: Some(index),
                    last_barrier,
                    delimiter_count,
                    total_delimiter_count,
                };
            }
        }
    }
    BytePairBarrierScan {
        pair_index: None,
        last_barrier,
        delimiter_count,
        total_delimiter_count,
    }
}

fn scan_scalar_from(
    signals: [u8; 3],
    bytes: &[u8],
    index_base: usize,
    last_barrier: Option<usize>,
    delimiter_count: usize,
    total_delimiter_count: usize,
) -> BytePairBarrierScan {
    scan_scalar_prefix_from(
        signals,
        bytes,
        bytes.len(),
        index_base,
        last_barrier,
        delimiter_count,
        total_delimiter_count,
    )
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
unsafe fn scan_scalar_entry(signals: [u8; 3], bytes: &[u8]) -> BytePairBarrierScan {
    scan_scalar(signals, bytes)
}

fn add_delimiters(total: usize, added: usize) -> usize {
    total
        .checked_add(added)
        .expect("a delimiter count cannot exceed its source slice length")
}

fn resolve_pending_barrier_group(
    signals: [u8; 3],
    bytes: &[u8],
    group_bytes: usize,
    pending_group: &mut Option<usize>,
    last_barrier: &mut Option<usize>,
    delimiter_count: &mut usize,
) {
    let Some(group_start) = pending_group.take() else {
        return;
    };
    let recovered = scan_scalar_prefix_from(
        signals,
        &bytes[group_start..],
        group_bytes,
        group_start,
        None,
        0,
        0,
    );
    debug_assert!(recovered.pair_index.is_none());
    debug_assert!(recovered.last_barrier.is_some());
    *last_barrier = recovered.last_barrier;
    *delimiter_count = recovered.delimiter_count;
}

#[cfg(target_arch = "aarch64")]
#[allow(
    unsafe_code,
    reason = "the private NEON leaf is reachable only through authenticated dispatch and uses bounded unaligned loads"
)]
#[allow(
    clippy::too_many_lines,
    reason = "the explicit fixed supergroup keeps cross-block lookahead, deferred barriers, and delayed lane reductions in one auditable target-feature leaf"
)]
#[target_feature(enable = "neon")]
unsafe fn scan_neon(signals: [u8; 3], bytes: &[u8]) -> BytePairBarrierScan {
    use core::arch::aarch64::{
        vaddlvq_u8, vaddq_u8, vandq_u8, vceqq_u8, vdupq_n_u8, vextq_u8, vld1q_u8, vmaxvq_u8,
        vorrq_u8, vshrq_n_u8,
    };

    if bytes.len() < NEON_SCAN_GROUP_BYTES.saturating_add(16) {
        return scan_scalar(signals, bytes);
    }

    let [delimiter, suffix_head, barrier] = signals;
    let delimiter_vector = vdupq_n_u8(delimiter);
    let suffix_vector = vdupq_n_u8(suffix_head);
    let barrier_vector = vdupq_n_u8(barrier);
    let zero = vdupq_n_u8(0);
    let mut delimiter_lanes = zero;
    let mut delimiter_count = 0_usize;
    let mut total_delimiter_lanes = zero;
    let mut total_delimiter_count = 0_usize;
    let mut last_barrier = None;
    let mut pending_barrier_group = None;
    let mut groups_since_reduction = 0_usize;
    let mut total_groups_since_reduction = 0_usize;
    let mut offset = 0_usize;
    // SAFETY: the length gate proves the initial complete 16-byte load.
    let mut block0 = unsafe { vld1q_u8(bytes.as_ptr()) };

    while bytes.len().saturating_sub(offset) >= NEON_SCAN_GROUP_BYTES.saturating_add(16) {
        // The current block is carried from the preceding supergroup. Load
        // every successor block through the supergroup end, so every possible
        // pair start has exact one-byte lookahead.
        let mut block = block0;
        // SAFETY: the loop gate proves every load through the supergroup end.
        let mut next_ptr = unsafe { bytes.as_ptr().add(offset).add(16) };
        let mut encoded_control = zero;
        let mut group_delimiters = zero;
        for _ in 0..NEON_SCAN_GROUP_BLOCKS {
            // SAFETY: next_ptr advances over the bounded load sequence proved
            // by the supergroup-plus-lookahead loop gate.
            let next = unsafe { vld1q_u8(next_ptr) };
            let delimiter_lanes = vceqq_u8(block, delimiter_vector);
            let barrier_lanes = vceqq_u8(block, barrier_vector);
            let successors = vextq_u8::<1>(block, next);
            let pair_lanes = vandq_u8(delimiter_lanes, vceqq_u8(successors, suffix_vector));
            encoded_control = vorrq_u8(
                encoded_control,
                vorrq_u8(vshrq_n_u8::<7>(barrier_lanes), pair_lanes),
            );
            group_delimiters = vaddq_u8(group_delimiters, vshrq_n_u8::<7>(delimiter_lanes));
            block = next;
            // SAFETY: the final increment forms the valid one-past pointer.
            next_ptr = unsafe { next_ptr.add(16) };
        }
        let control_code = vmaxvq_u8(encoded_control);

        if control_code == u8::MAX {
            resolve_pending_barrier_group(
                signals,
                bytes,
                NEON_SCAN_GROUP_BYTES,
                &mut pending_barrier_group,
                &mut last_barrier,
                &mut delimiter_count,
            );
            delimiter_count =
                add_delimiters(delimiter_count, usize::from(vaddlvq_u8(delimiter_lanes)));
            total_delimiter_count = add_delimiters(
                total_delimiter_count,
                usize::from(vaddlvq_u8(total_delimiter_lanes)),
            );
            let recovered = scan_scalar_prefix_from(
                signals,
                &bytes[offset..],
                NEON_SCAN_GROUP_BYTES,
                offset,
                last_barrier,
                delimiter_count,
                total_delimiter_count,
            );
            if recovered.pair_index.is_some() {
                return recovered;
            }
            // Duplicate signals can make a syntactic pair begin on a barrier.
            // Scalar recovery applies barrier precedence and keeps scanning.
            last_barrier = recovered.last_barrier;
            delimiter_count = recovered.delimiter_count;
            total_delimiter_count = recovered.total_delimiter_count;
            delimiter_lanes = zero;
            total_delimiter_lanes = zero;
            groups_since_reduction = 0;
            total_groups_since_reduction = 0;
        } else if control_code != 0 {
            // Exact state before this group is dead after its last barrier.
            // Defer locating that barrier: later barrier groups supersede it,
            // so at most one barrier group is recovered for the whole scan.
            pending_barrier_group = Some(offset);
            last_barrier = None;
            delimiter_count = 0;
            delimiter_lanes = zero;
            groups_since_reduction = 0;
        } else {
            delimiter_lanes = vaddq_u8(delimiter_lanes, group_delimiters);
            groups_since_reduction = groups_since_reduction.saturating_add(1);
        }
        if control_code != u8::MAX {
            total_delimiter_lanes = vaddq_u8(total_delimiter_lanes, group_delimiters);
            total_groups_since_reduction = total_groups_since_reduction.saturating_add(1);
        }

        offset = offset
            .checked_add(NEON_SCAN_GROUP_BYTES)
            .expect("vector traversal stays within its source slice");
        block0 = block;

        if groups_since_reduction == NEON_DELIMITER_REDUCTION_GROUPS {
            delimiter_count =
                add_delimiters(delimiter_count, usize::from(vaddlvq_u8(delimiter_lanes)));
            delimiter_lanes = zero;
            groups_since_reduction = 0;
        }
        if total_groups_since_reduction == NEON_DELIMITER_REDUCTION_GROUPS {
            total_delimiter_count = add_delimiters(
                total_delimiter_count,
                usize::from(vaddlvq_u8(total_delimiter_lanes)),
            );
            total_delimiter_lanes = zero;
            total_groups_since_reduction = 0;
        }
    }

    resolve_pending_barrier_group(
        signals,
        bytes,
        NEON_SCAN_GROUP_BYTES,
        &mut pending_barrier_group,
        &mut last_barrier,
        &mut delimiter_count,
    );
    delimiter_count = add_delimiters(delimiter_count, usize::from(vaddlvq_u8(delimiter_lanes)));
    total_delimiter_count = add_delimiters(
        total_delimiter_count,
        usize::from(vaddlvq_u8(total_delimiter_lanes)),
    );
    scan_scalar_from(
        signals,
        &bytes[offset..],
        offset,
        last_barrier,
        delimiter_count,
        total_delimiter_count,
    )
}

#[cfg(target_arch = "x86_64")]
#[allow(
    unsafe_code,
    reason = "the private SSE2 leaf is reachable only through authenticated dispatch and uses bounded unaligned loads"
)]
#[allow(
    clippy::cast_ptr_alignment,
    reason = "_mm_loadu_si128 explicitly accepts unaligned byte-backed addresses"
)]
#[allow(
    clippy::too_many_lines,
    reason = "the explicit four-register group keeps cross-block lookahead, sparse gating, and delayed lane reductions in one auditable target-feature leaf"
)]
#[allow(
    clippy::similar_names,
    reason = "numbered register names make the four fixed source blocks and their pairwise unions auditable"
)]
#[target_feature(enable = "sse2")]
unsafe fn scan_sse2(signals: [u8; 3], bytes: &[u8]) -> BytePairBarrierScan {
    use core::arch::x86_64::{
        __m128i, _mm_add_epi8, _mm_and_si128, _mm_cmpeq_epi8, _mm_loadu_si128, _mm_movemask_epi8,
        _mm_or_si128, _mm_set1_epi8, _mm_setzero_si128, _mm_slli_si128, _mm_srli_si128,
    };

    if bytes.len() < SSE2_SCAN_GROUP_BYTES.saturating_add(16) {
        return scan_scalar(signals, bytes);
    }

    let [delimiter, suffix_head, barrier] = signals;
    let delimiter_vector = _mm_set1_epi8(i8::from_ne_bytes([delimiter]));
    let suffix_vector = _mm_set1_epi8(i8::from_ne_bytes([suffix_head]));
    let barrier_vector = _mm_set1_epi8(i8::from_ne_bytes([barrier]));
    let one = _mm_set1_epi8(1);
    let zero = _mm_setzero_si128();
    let mut delimiter_lanes = zero;
    let mut delimiter_count = 0_usize;
    let mut total_delimiter_lanes = zero;
    let mut total_delimiter_count = 0_usize;
    let mut last_barrier = None;
    let mut pending_barrier_group = None;
    let mut groups_since_reduction = 0_usize;
    let mut total_groups_since_reduction = 0_usize;
    let mut offset = 0_usize;
    // SAFETY: the length gate proves the initial complete unaligned load.
    let mut block0 = unsafe { _mm_loadu_si128(bytes.as_ptr().cast::<__m128i>()) };

    while bytes.len().saturating_sub(offset) >= SSE2_SCAN_GROUP_BYTES.saturating_add(16) {
        // SAFETY: the loop gate proves 80 readable bytes from `offset`.
        let (block1, block2, block3, block4) = unsafe {
            let base = bytes.as_ptr().add(offset);
            (
                _mm_loadu_si128(base.add(16).cast::<__m128i>()),
                _mm_loadu_si128(base.add(32).cast::<__m128i>()),
                _mm_loadu_si128(base.add(48).cast::<__m128i>()),
                _mm_loadu_si128(base.add(64).cast::<__m128i>()),
            )
        };
        let delimiter0 = _mm_cmpeq_epi8(block0, delimiter_vector);
        let delimiter1 = _mm_cmpeq_epi8(block1, delimiter_vector);
        let delimiter2 = _mm_cmpeq_epi8(block2, delimiter_vector);
        let delimiter3 = _mm_cmpeq_epi8(block3, delimiter_vector);
        let barrier0 = _mm_cmpeq_epi8(block0, barrier_vector);
        let barrier1 = _mm_cmpeq_epi8(block1, barrier_vector);
        let barrier2 = _mm_cmpeq_epi8(block2, barrier_vector);
        let barrier3 = _mm_cmpeq_epi8(block3, barrier_vector);
        let suffix0 = _mm_cmpeq_epi8(block0, suffix_vector);
        let suffix1 = _mm_cmpeq_epi8(block1, suffix_vector);
        let suffix2 = _mm_cmpeq_epi8(block2, suffix_vector);
        let suffix3 = _mm_cmpeq_epi8(block3, suffix_vector);
        let suffix4 = _mm_cmpeq_epi8(block4, suffix_vector);
        let pair0 = _mm_and_si128(
            delimiter0,
            _mm_or_si128(_mm_srli_si128::<1>(suffix0), _mm_slli_si128::<15>(suffix1)),
        );
        let pair1 = _mm_and_si128(
            delimiter1,
            _mm_or_si128(_mm_srli_si128::<1>(suffix1), _mm_slli_si128::<15>(suffix2)),
        );
        let pair2 = _mm_and_si128(
            delimiter2,
            _mm_or_si128(_mm_srli_si128::<1>(suffix2), _mm_slli_si128::<15>(suffix3)),
        );
        let pair3 = _mm_and_si128(
            delimiter3,
            _mm_or_si128(_mm_srli_si128::<1>(suffix3), _mm_slli_si128::<15>(suffix4)),
        );
        let pair01 = _mm_or_si128(pair0, pair1);
        let pair23 = _mm_or_si128(pair2, pair3);
        let count01 = _mm_add_epi8(
            _mm_and_si128(delimiter0, one),
            _mm_and_si128(delimiter1, one),
        );
        let count23 = _mm_add_epi8(
            _mm_and_si128(delimiter2, one),
            _mm_and_si128(delimiter3, one),
        );
        let group_delimiters = _mm_add_epi8(count01, count23);

        if _mm_movemask_epi8(_mm_or_si128(pair01, pair23)) != 0 {
            resolve_pending_barrier_group(
                signals,
                bytes,
                SSE2_SCAN_GROUP_BYTES,
                &mut pending_barrier_group,
                &mut last_barrier,
                &mut delimiter_count,
            );
            // SAFETY: this register-only helper inherits the authenticated
            // SSE2 boundary.
            delimiter_count = add_delimiters(delimiter_count, unsafe {
                reduce_sse2_delimiters(delimiter_lanes)
            });
            total_delimiter_count = add_delimiters(total_delimiter_count, unsafe {
                reduce_sse2_delimiters(total_delimiter_lanes)
            });
            let group_end = offset
                .checked_add(SSE2_SCAN_GROUP_BYTES)
                .expect("one vector group fits in its source slice");
            let recovered = scan_scalar_prefix_from(
                signals,
                &bytes[offset..],
                SSE2_SCAN_GROUP_BYTES,
                offset,
                last_barrier,
                delimiter_count,
                total_delimiter_count,
            );
            if recovered.pair_index.is_some() {
                return recovered;
            }
            // Duplicate signals can make a syntactic pair begin on a barrier.
            // Scalar recovery applies barrier precedence and keeps scanning.
            last_barrier = recovered.last_barrier;
            delimiter_count = recovered.delimiter_count;
            total_delimiter_count = recovered.total_delimiter_count;
            delimiter_lanes = zero;
            total_delimiter_lanes = zero;
            groups_since_reduction = 0;
            total_groups_since_reduction = 0;
            offset = group_end;
            block0 = block4;
            continue;
        }
        total_delimiter_lanes = _mm_add_epi8(total_delimiter_lanes, group_delimiters);
        total_groups_since_reduction = total_groups_since_reduction.saturating_add(1);
        if total_groups_since_reduction == SSE2_DELIMITER_REDUCTION_GROUPS {
            // SAFETY: this register-only helper inherits the authenticated
            // SSE2 boundary.
            total_delimiter_count = add_delimiters(total_delimiter_count, unsafe {
                reduce_sse2_delimiters(total_delimiter_lanes)
            });
            total_delimiter_lanes = zero;
            total_groups_since_reduction = 0;
        }
        let barrier01 = _mm_or_si128(barrier0, barrier1);
        let barrier23 = _mm_or_si128(barrier2, barrier3);
        if _mm_movemask_epi8(_mm_or_si128(barrier01, barrier23)) != 0 {
            pending_barrier_group = Some(offset);
            last_barrier = None;
            delimiter_count = 0;
            delimiter_lanes = zero;
            groups_since_reduction = 0;
            offset = offset
                .checked_add(SSE2_SCAN_GROUP_BYTES)
                .expect("vector traversal stays within its source slice");
            block0 = block4;
            continue;
        }

        delimiter_lanes = _mm_add_epi8(delimiter_lanes, group_delimiters);
        groups_since_reduction = groups_since_reduction.saturating_add(1);
        offset = offset
            .checked_add(SSE2_SCAN_GROUP_BYTES)
            .expect("vector traversal stays within its source slice");
        block0 = block4;

        if groups_since_reduction == SSE2_DELIMITER_REDUCTION_GROUPS {
            // SAFETY: this register-only helper inherits the authenticated
            // SSE2 boundary.
            delimiter_count = add_delimiters(delimiter_count, unsafe {
                reduce_sse2_delimiters(delimiter_lanes)
            });
            delimiter_lanes = zero;
            groups_since_reduction = 0;
        }
    }

    resolve_pending_barrier_group(
        signals,
        bytes,
        SSE2_SCAN_GROUP_BYTES,
        &mut pending_barrier_group,
        &mut last_barrier,
        &mut delimiter_count,
    );
    // SAFETY: this register-only helper inherits the authenticated SSE2
    // boundary.
    delimiter_count = add_delimiters(delimiter_count, unsafe {
        reduce_sse2_delimiters(delimiter_lanes)
    });
    total_delimiter_count = add_delimiters(total_delimiter_count, unsafe {
        reduce_sse2_delimiters(total_delimiter_lanes)
    });
    scan_scalar_from(
        signals,
        &bytes[offset..],
        offset,
        last_barrier,
        delimiter_count,
        total_delimiter_count,
    )
}

#[cfg(target_arch = "x86_64")]
#[allow(
    unsafe_code,
    reason = "this private helper reduces one initialized SSE2 register into a bounded scalar delimiter count"
)]
#[allow(
    clippy::cast_ptr_alignment,
    reason = "_mm_storeu_si128 explicitly accepts an unaligned byte-backed destination"
)]
#[target_feature(enable = "sse2")]
unsafe fn reduce_sse2_delimiters(lanes: core::arch::x86_64::__m128i) -> usize {
    use core::arch::x86_64::{__m128i, _mm_sad_epu8, _mm_setzero_si128, _mm_storeu_si128};

    let sums = _mm_sad_epu8(lanes, _mm_setzero_si128());
    let mut words = [0_u64; 2];
    // SAFETY: the unaligned store writes exactly the initialized 16-byte
    // destination array.
    unsafe { _mm_storeu_si128(words.as_mut_ptr().cast::<__m128i>(), sums) };
    usize::try_from(
        words[0]
            .checked_add(words[1])
            .expect("two bounded lane sums fit in u64"),
    )
    .expect("one 4,032-byte reduction count fits in usize")
}

const SCALAR: KernelVariant<BytePairBarrierEntry> = KernelVariant::new(
    SCALAR_VARIANT_ID,
    ArchitectureRequirement::Any,
    FeatureSet::EMPTY,
    VectorKind::Scalar,
    0,
    0,
    byte_pair_barrier_entry!(scan_scalar_entry),
);

#[cfg(target_arch = "aarch64")]
const VARIANTS: [KernelVariant<BytePairBarrierEntry>; 2] = [
    SCALAR,
    KernelVariant::new(
        NEON_VARIANT_ID,
        ArchitectureRequirement::Exact(Architecture::Aarch64),
        FeatureSet::of(Feature::ArmNeon),
        VectorKind::Fixed {
            bytes: BYTE_PAIR_BARRIER_VECTOR_BYTES,
        },
        BYTE_PAIR_BARRIER_GROUP_BYTES,
        100,
        byte_pair_barrier_entry!(scan_neon),
    ),
];

#[cfg(target_arch = "x86_64")]
const VARIANTS: [KernelVariant<BytePairBarrierEntry>; 2] = [
    SCALAR,
    KernelVariant::new(
        SSE2_VARIANT_ID,
        ArchitectureRequirement::Exact(Architecture::X86_64),
        FeatureSet::of(Feature::X86Sse2),
        VectorKind::Fixed {
            bytes: BYTE_PAIR_BARRIER_VECTOR_BYTES,
        },
        BYTE_PAIR_BARRIER_GROUP_BYTES,
        100,
        byte_pair_barrier_entry!(scan_sse2),
    ),
];

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
const VARIANTS: [KernelVariant<BytePairBarrierEntry>; 1] = [SCALAR];

fn select(
    capabilities: CpuCapabilities,
    policy: DispatchPolicy,
) -> Result<SelectedKernel<BytePairBarrierEntry>, UnsupportedRequiredFeatures> {
    Ok(select_kernel(
        capabilities,
        policy,
        BYTE_PAIR_BARRIER_GROUP_BYTES,
        &VARIANTS,
    )?
    .expect("the byte-pair/barrier table always contains its scalar fallback"))
}

#[cfg(feature = "static-dispatch")]
const fn automatic_selection() -> SelectionReceipt {
    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    let (variant_id, required, vector, minimum_input_bytes) = (
        NEON_VARIANT_ID,
        FeatureSet::of(Feature::ArmNeon),
        VectorKind::Fixed {
            bytes: BYTE_PAIR_BARRIER_VECTOR_BYTES,
        },
        BYTE_PAIR_BARRIER_GROUP_BYTES,
    );
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    let (variant_id, required, vector, minimum_input_bytes) = (
        SSE2_VARIANT_ID,
        FeatureSet::of(Feature::X86Sse2),
        VectorKind::Fixed {
            bytes: BYTE_PAIR_BARRIER_VECTOR_BYTES,
        },
        BYTE_PAIR_BARRIER_GROUP_BYTES,
    );
    #[cfg(not(any(
        all(target_arch = "aarch64", target_feature = "neon"),
        all(target_arch = "x86_64", target_feature = "sse2")
    )))]
    let (variant_id, required, vector, minimum_input_bytes) =
        (SCALAR_VARIANT_ID, FeatureSet::EMPTY, VectorKind::Scalar, 0);
    crate::compiler_selection_receipt(
        variant_id,
        None,
        required,
        vector,
        BYTE_PAIR_BARRIER_GROUP_BYTES,
        minimum_input_bytes,
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
    target_arch = "x86_64",
    target_feature = "sse2"
))]
const fn static_variant_id() -> &'static str {
    SSE2_VARIANT_ID
}

#[cfg(all(
    feature = "static-dispatch",
    not(any(
        all(target_arch = "aarch64", target_feature = "neon"),
        all(target_arch = "x86_64", target_feature = "sse2")
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
    reason = "the compiler-fixed profile proves NEON before the private direct leaf is reachable"
)]
unsafe fn static_scan(signals: [u8; 3], bytes: &[u8]) -> BytePairBarrierScan {
    // SAFETY: this static leaf is compiled with NEON enabled.
    unsafe { scan_neon(signals, bytes) }
}

#[cfg(all(
    feature = "static-dispatch",
    target_arch = "x86_64",
    target_feature = "sse2"
))]
#[allow(
    unsafe_code,
    reason = "the compiler-fixed profile proves SSE2 before the private direct leaf is reachable"
)]
unsafe fn static_scan(signals: [u8; 3], bytes: &[u8]) -> BytePairBarrierScan {
    // SAFETY: this static leaf is compiled with SSE2 enabled.
    unsafe { scan_sse2(signals, bytes) }
}

#[cfg(all(
    feature = "static-dispatch",
    not(any(
        all(target_arch = "aarch64", target_feature = "neon"),
        all(target_arch = "x86_64", target_feature = "sse2")
    ))
))]
#[allow(
    unsafe_code,
    reason = "the scalar function shares the compiler-fixed leaf ABI but performs no unsafe operation"
)]
unsafe fn static_scan(signals: [u8; 3], bytes: &[u8]) -> BytePairBarrierScan {
    scan_scalar(signals, bytes)
}

#[cfg(test)]
mod tests {
    use super::{
        BYTE_PAIR_BARRIER_GROUP_BYTES, BytePairBarrierScan, BytePairBarrierScanner, scan_scalar,
    };
    use crate::{DispatchPolicy, Feature, FeatureSet, SimdDispatchContext, VectorKind};

    fn oracle(signals: [u8; 3], bytes: &[u8]) -> BytePairBarrierScan {
        let [delimiter, suffix_head, barrier] = signals;
        let mut last_barrier = None;
        let mut delimiter_count = 0_usize;
        let mut total_delimiter_count = 0_usize;
        for (index, &byte) in bytes.iter().enumerate() {
            if byte == delimiter {
                total_delimiter_count = total_delimiter_count.saturating_add(1);
            }
            if byte == barrier {
                last_barrier = Some(index);
                delimiter_count = 0;
                continue;
            }
            if byte == delimiter {
                delimiter_count = delimiter_count.saturating_add(1);
                if bytes.get(index.saturating_add(1)) == Some(&suffix_head) {
                    return BytePairBarrierScan {
                        pair_index: Some(index),
                        last_barrier,
                        delimiter_count,
                        total_delimiter_count,
                    };
                }
            }
        }
        BytePairBarrierScan {
            pair_index: None,
            last_barrier,
            delimiter_count,
            total_delimiter_count,
        }
    }

    fn fill_source(source: &mut [u8], seed: u8) {
        let mut state = u64::from(seed).wrapping_add(0x517c_c1b7_2722_0a95);
        for (index, byte) in source.iter_mut().enumerate() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let index_byte = u8::try_from(index & 0xff)
                .expect("the low eight index bits fit in u8")
                .wrapping_mul(197);
            *byte = state.to_le_bytes()[0].wrapping_add(index_byte);
        }
    }

    fn signal_sets(seed: u8) -> [[u8; 3]; 7] {
        [
            [b',', b'z', b'|'],
            [seed, seed, seed],
            [seed, seed.wrapping_add(1), seed],
            [seed, seed, seed.wrapping_add(1)],
            [seed, seed.wrapping_add(1), seed.wrapping_add(1)],
            [0x00, 0xff, 0x80],
            [
                seed.wrapping_mul(29),
                seed.wrapping_mul(71).wrapping_add(3),
                seed.wrapping_mul(151).wrapping_add(11),
            ],
        ]
    }

    #[test]
    fn scalar_semantics_absorb_barriers_and_define_duplicate_precedence() {
        assert_eq!(
            scan_scalar([b',', b'z', b'|'], b"a,ab|c,,z"),
            BytePairBarrierScan {
                pair_index: Some(7),
                last_barrier: Some(4),
                delimiter_count: 2,
                total_delimiter_count: 3,
            }
        );
        assert_eq!(
            scan_scalar([b'x', b'x', b'x'], b"xxxx"),
            BytePairBarrierScan {
                pair_index: None,
                last_barrier: Some(3),
                delimiter_count: 0,
                total_delimiter_count: 4,
            }
        );
        assert_eq!(
            scan_scalar([b'x', b'x', b'!'], b"xx"),
            BytePairBarrierScan {
                pair_index: Some(0),
                last_barrier: None,
                delimiter_count: 1,
                total_delimiter_count: 1,
            }
        );
        assert_eq!(
            scan_scalar([b'x', b'!', b'!'], b"x!"),
            BytePairBarrierScan {
                pair_index: Some(0),
                last_barrier: None,
                delimiter_count: 1,
                total_delimiter_count: 1,
            }
        );
        assert_eq!(
            scan_scalar([b'x', b'y', b'x'], b"xy"),
            BytePairBarrierScan {
                pair_index: None,
                last_barrier: Some(0),
                delimiter_count: 0,
                total_delimiter_count: 1,
            }
        );
    }

    #[test]
    fn automatic_matches_independent_oracle_for_lengths_alignments_and_arbitrary_bytes() {
        const SOURCE_BYTES: usize = 8_223;
        let lengths = [
            0_usize, 1, 2, 15, 16, 17, 62, 63, 64, 65, 79, 80, 81, 127, 128, 129, 255, 256, 1_023,
            4_031, 4_032, 4_033, 8_192,
        ];
        let alignments = [0_usize, 1, 2, 7, 15, 16, 17, 31];
        let mut source = [0_u8; SOURCE_BYTES];
        for seed in [0_u8, 1, 63, 255] {
            fill_source(&mut source, seed);
            for alignment in alignments {
                for length in lengths {
                    let end = alignment
                        .checked_add(length)
                        .expect("test source extents fit in usize");
                    let bytes = &source[alignment..end];
                    for signals in signal_sets(seed) {
                        let scanner =
                            BytePairBarrierScanner::new(signals[0], signals[1], signals[2]);
                        assert_eq!(scanner.scan(bytes), oracle(signals, bytes));
                    }
                }
            }
        }
    }

    #[test]
    fn long_delimiter_accumulation_and_dense_barrier_recovery_match_oracle() {
        let mut no_control = vec![b'a'; 16_417];
        for index in (3..no_control.len()).step_by(5) {
            no_control[index] = b',';
        }
        let scanner = BytePairBarrierScanner::new(b',', b'z', b'|');
        assert_eq!(
            scanner.scan(&no_control),
            oracle([b',', b'z', b'|'], &no_control)
        );

        let mut barriers = vec![b'a'; 8_257];
        for index in (7..barriers.len()).step_by(19) {
            barriers[index] = b'|';
        }
        for index in (11..barriers.len()).step_by(23) {
            if barriers[index] == b'a' {
                barriers[index] = b',';
            }
        }
        assert_eq!(
            scanner.scan(&barriers),
            oracle([b',', b'z', b'|'], &barriers)
        );

        let mut deferred = vec![b'a'; 1_025];
        for barrier in [5_usize, 70, 130] {
            deferred[barrier] = b'|';
        }
        for delimiter in [143_usize, 191, 250, 300] {
            deferred[delimiter] = b',';
        }
        deferred[301] = b'z';
        assert_eq!(
            scanner.scan(&deferred),
            BytePairBarrierScan {
                pair_index: Some(300),
                last_barrier: Some(130),
                delimiter_count: 4,
                total_delimiter_count: 4,
            }
        );
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    #[test]
    fn forced_vector_cross_lane_and_cross_group_pairs_use_exact_lookahead() {
        let context = SimdDispatchContext::capture();
        #[cfg(target_arch = "aarch64")]
        let feature = Feature::ArmNeon;
        #[cfg(target_arch = "x86_64")]
        let feature = Feature::X86Sse2;
        if !context.capabilities().usable().contains(feature) {
            return;
        }

        let scanner = context
            .byte_pair_barrier_scanner(
                b',',
                b'z',
                b'|',
                DispatchPolicy::Require(FeatureSet::of(feature)),
            )
            .unwrap();
        assert_eq!(scanner.selection().vector, VectorKind::Fixed { bytes: 16 });
        let mut padded = [b'a'; 351];
        for alignment in 0_usize..=31 {
            for pair_index in [15_usize, 63, 255] {
                let source = &mut padded[alignment..alignment.saturating_add(320)];
                source.fill(b'a');
                source[3] = b',';
                source[7] = b'|';
                source[11] = b',';
                source[pair_index] = b',';
                source[pair_index.saturating_add(1)] = b'z';
                assert_eq!(
                    scanner.scan(source),
                    BytePairBarrierScan {
                        pair_index: Some(pair_index),
                        last_barrier: Some(7),
                        delimiter_count: 2,
                        total_delimiter_count: 3,
                    }
                );
            }
        }
    }

    #[test]
    fn selection_uses_an_invariant_group_shape() {
        let scanner = BytePairBarrierScanner::new(1, 2, 3);
        let receipt = scanner.selection();
        assert_eq!(receipt.selection_input_bytes, BYTE_PAIR_BARRIER_GROUP_BYTES);
        if !matches!(receipt.vector, VectorKind::Scalar) {
            assert_eq!(receipt.minimum_input_bytes, BYTE_PAIR_BARRIER_GROUP_BYTES);
        }
    }
}
