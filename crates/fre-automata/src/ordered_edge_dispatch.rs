//! Canonical priority-preserving dispatch for wide consuming rows.
//!
//! A Thompson consuming state may have many ordered byte-range edges even
//! though only a small subset can match any one byte. The universal K0 path
//! must preserve that edge order, but it need not inspect the nonmatching
//! edges on an unlimited invocation. This sidecar partitions each admitted
//! row into its exact local byte segments. Common graphs pack each matching
//! transition's target and exact scalar edge-inspection delta into one `u32`;
//! wider graphs use one `u64`. A legacy edge-ordinal form is retained only
//! when direct records would cross the fixed retained-byte ceiling, preserving
//! every graph accepted by the stable V5 marker. Runtime direct forms preserve
//! priority and abstract work without returning to source edge arrays.

use core::{fmt, mem::size_of};

use crate::plan::{plan_index, Automaton, EdgeKind, StateRole};

const BYTE_DOMAIN: usize = 256;
const BOUNDARY_DOMAIN: usize = BYTE_DOMAIN + 1;
const DISPATCH_OVERHEAD: usize = 4;
// One row pass may initialize and scan both fixed byte-domain tables, plus
// emit the admitted row's byte map. Four boundary-domain units conservatively
// cover those fixed operations; the variable edge and segment scans are
// charged separately.
const ROW_FIXED_SCAN_WORK: usize = BOUNDARY_DOMAIN * 4;
const RESERVED_ROW_PASSES: usize = 3;
// Shape discovery, descriptor initialization, and sidecar emission each
// touch the complete state domain once.
const RESERVED_STATE_PASSES: usize = 3;

// Sidecar construction is optional but canonical. Fixed graph-independent
// ceilings keep both compilation and untrusted artifact reconstruction
// bounded. Reaching either ceiling declines the optimization for the whole
// graph; no caller resource limit or target property participates.
const MAX_DERIVATION_WORK: usize = 64 * 1024 * 1024;
const MAX_RETAINED_BYTES: usize = 64 * 1024 * 1024;
// The ed690 V5 owner retained four slice boxes and one `usize`: nine machine
// words including every fat-pointer header and its struct padding.
const LEGACY_OWNER_WORDS: usize = 9;
const LEGACY_OWNER_BYTES: usize = LEGACY_OWNER_WORDS * size_of::<usize>();

// An admitted sidecar necessarily spends at least four retained bytes per
// segment metadata word plus nonempty owner and row storage. Its metadata
// index and admitted-row ordinal are therefore strictly below 2^24 under the
// fixed 64 MiB ceiling. The two spare descriptor bytes carry the graph-global
// direct-u32 target width and row-local final segment without growing the
// eight-byte row descriptor used by V5.
const SEGMENT_BASE_BITS: u32 = 24;
const SEGMENT_BASE_MASK: u32 = (1_u32 << SEGMENT_BASE_BITS) - 1;
const SEGMENT_BASE_LIMIT: usize = 0x00ff_ffff;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RowDescriptor {
    segment_base: u32,
    row_ordinal: u32,
}

impl RowDescriptor {
    const ABSENT: Self = Self {
        segment_base: u32::MAX,
        row_ordinal: 0,
    };

    const fn is_present(self) -> bool {
        self.segment_base != u32::MAX
    }

    fn present(
        segment_base: usize,
        row_ordinal: usize,
        last_segment: usize,
        target_bits: u32,
    ) -> Self {
        debug_assert!(segment_base <= SEGMENT_BASE_LIMIT);
        debug_assert!(row_ordinal <= SEGMENT_BASE_LIMIT);
        debug_assert!(last_segment < BYTE_DOMAIN);
        debug_assert!(target_bits <= u8::MAX.into());
        let segment_base = u32::try_from(segment_base)
            .expect("bounded dispatch metadata index fits u32");
        let row_ordinal = u32::try_from(row_ordinal)
            .expect("bounded dispatch row count fits u32");
        let last_segment = u32::try_from(last_segment)
            .expect("local byte-segment ordinal fits u32");
        Self {
            segment_base: segment_base | (target_bits << SEGMENT_BASE_BITS),
            row_ordinal: row_ordinal | (last_segment << SEGMENT_BASE_BITS),
        }
    }

    const fn segment_base(self) -> u32 {
        self.segment_base & SEGMENT_BASE_MASK
    }

    const fn target_bits(self) -> u32 {
        self.segment_base >> SEGMENT_BASE_BITS
    }

    const fn row_ordinal(self) -> u32 {
        self.row_ordinal & SEGMENT_BASE_MASK
    }

    const fn last_segment(self) -> u32 {
        self.row_ordinal >> SEGMENT_BASE_BITS
    }
}

/// One runtime-ready matching transition.
///
/// The low half is the direct graph target and the high half is the exact
/// number of scalar row edges inspected through this match. Both source
/// fields are validated `u32`s, so the representation is lossless even at
/// their maximum encodings and is target-width independent.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct PackedOrderedTransition(u64);

impl PackedOrderedTransition {
    fn new(target: u32, work: u32) -> Self {
        Self(u64::from(target) | (u64::from(work) << u32::BITS))
    }

    pub(crate) const fn target(self) -> u32 {
        self.0 as u32
    }

    pub(crate) const fn work(self) -> u32 {
        (self.0 >> u32::BITS) as u32
    }

    /// Exact canonical target/work word retained by the graph sidecar.
    #[doc(hidden)]
    #[must_use]
    pub const fn compiler_private_encoded(self) -> u64 {
        self.0
    }
}

/// One common direct transition. The low `target_bits` bits retain the direct
/// graph target and the remaining high bits retain the positive scalar work
/// delta through that transition.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct PackedOrderedTransition32(u32);

impl PackedOrderedTransition32 {
    fn new(target: u32, work: u32, target_bits: u32) -> Self {
        debug_assert!(bits_required(target) <= target_bits);
        debug_assert!(work != 0);
        debug_assert!(bits_required(work).checked_add(target_bits) <= Some(u32::BITS));
        Self(target | (work << target_bits))
    }

    pub(crate) const fn target(self, target_mask: u32) -> u32 {
        self.0 & target_mask
    }

    pub(crate) const fn work(self, target_bits: u32) -> u32 {
        self.0 >> target_bits
    }

    /// Exact canonical target/work word retained by the graph sidecar.
    #[doc(hidden)]
    #[must_use]
    pub const fn compiler_private_encoded(self) -> u32 {
        self.0
    }
}

/// Compiler-private decoded descriptor for one graph state.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeOrderedEdgeRowDescriptor {
    encoded: [u32; 2],
}

impl NativeOrderedEdgeRowDescriptor {
    /// Exact two-word canonical row record used by the retained sidecar.
    #[doc(hidden)]
    #[must_use]
    pub const fn compiler_private_encoded(self) -> [u32; 2] {
        self.encoded
    }

    #[doc(hidden)]
    #[must_use]
    pub const fn segment_base(self) -> u32 {
        self.encoded[0] & SEGMENT_BASE_MASK
    }

    #[doc(hidden)]
    #[must_use]
    pub const fn target_bits(self) -> u32 {
        self.encoded[0] >> SEGMENT_BASE_BITS
    }

    #[doc(hidden)]
    #[must_use]
    pub const fn row_ordinal(self) -> u32 {
        self.encoded[1] & SEGMENT_BASE_MASK
    }

    #[doc(hidden)]
    #[must_use]
    pub const fn last_segment(self) -> u32 {
        self.encoded[1] >> SEGMENT_BASE_BITS
    }
}

/// Exact canonical transition storage retained by an ordered-edge sidecar.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub enum NativeOrderedEdgeTransitions<'a> {
    Direct32 {
        transitions: &'a [PackedOrderedTransition32],
        target_bits: u32,
    },
    Direct64(&'a [PackedOrderedTransition]),
    Legacy(&'a [u32]),
}

impl NativeOrderedEdgeTransitions<'_> {
    #[doc(hidden)]
    #[must_use]
    pub const fn len(self) -> usize {
        match self {
            Self::Direct32 { transitions, .. } => transitions.len(),
            Self::Direct64(transitions) => transitions.len(),
            Self::Legacy(edges) => edges.len(),
        }
    }

    #[doc(hidden)]
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len() == 0
    }
}

/// Borrowed compiler-only view of the already-derived canonical sidecar.
///
/// Native lowering copies these exact arrays into its relocation-free object
/// image. It must not re-run graph analysis or invent a target-specific row
/// admission policy.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct NativeOrderedEdgeDispatchView<'a> {
    dispatch: &'a OrderedEdgeDispatch,
}

impl<'a> NativeOrderedEdgeDispatchView<'a> {
    #[doc(hidden)]
    #[must_use]
    pub fn state_count(self) -> usize {
        self.dispatch.0[0].rows.len()
    }

    #[doc(hidden)]
    #[must_use]
    pub fn admitted_rows(self) -> usize {
        self.dispatch.0[0]
            .rows
            .iter()
            .filter(|row| row.is_present())
            .count()
    }

    #[doc(hidden)]
    #[must_use]
    pub fn retained_bytes(self) -> usize {
        self.dispatch.retained_bytes()
    }

    #[doc(hidden)]
    #[must_use]
    pub fn row(self, state: usize) -> Option<NativeOrderedEdgeRowDescriptor> {
        let descriptor = *self.dispatch.0[0].rows.get(state)?;
        descriptor
            .is_present()
            .then_some(NativeOrderedEdgeRowDescriptor {
                encoded: [descriptor.segment_base, descriptor.row_ordinal],
            })
    }

    #[doc(hidden)]
    #[must_use]
    pub fn segment_by_byte(self) -> &'a [u8] {
        &self.dispatch.0[0].segment_by_byte
    }

    #[doc(hidden)]
    #[must_use]
    pub fn segment_metadata(self) -> &'a [u32] {
        &self.dispatch.0[0].segment_metadata
    }

    #[doc(hidden)]
    #[must_use]
    pub fn transitions(self) -> NativeOrderedEdgeTransitions<'a> {
        match &self.dispatch.0[0].transitions {
            EncodedTransitions::Direct32(transitions) => {
                let target_bits = self
                    .dispatch
                    .0[0]
                    .rows
                    .iter()
                    .find(|row| row.is_present())
                    .map_or(0, |row| row.target_bits());
                NativeOrderedEdgeTransitions::Direct32 {
                    transitions,
                    target_bits,
                }
            }
            EncodedTransitions::Direct64(transitions) => {
                NativeOrderedEdgeTransitions::Direct64(transitions)
            }
            EncodedTransitions::Legacy(edges) => NativeOrderedEdgeTransitions::Legacy(edges),
        }
    }
}

/// Borrowed runtime view for one byte in one admitted consuming row.
pub(crate) struct OrderedEdgeSegment<'a> {
    pub(crate) transitions: OrderedEdgeTransitions<'a>,
    pub(crate) row_work: u32,
}

pub(crate) enum OrderedEdgeTransitions<'a> {
    Direct32 {
        transitions: &'a [PackedOrderedTransition32],
        target_bits: u32,
        target_mask: u32,
    },
    Direct64(&'a [PackedOrderedTransition]),
    Legacy(&'a [u32]),
}

/// Allocation failure after a graph has deterministically qualified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderedEdgeDispatchAllocationError {
    requested_bytes: usize,
}

impl OrderedEdgeDispatchAllocationError {
    /// Exact logical extent whose bounded allocation failed.
    #[must_use]
    pub const fn requested_bytes(self) -> usize {
        self.requested_bytes
    }
}

impl fmt::Display for OrderedEdgeDispatchAllocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "could not allocate {0} bytes for ordered-edge dispatch",
            self.requested_bytes
        )
    }
}

impl std::error::Error for OrderedEdgeDispatchAllocationError {}

/// Immutable local-segment CSR for all structurally profitable rows.
///
/// The thin, one-element owner keeps the optional sidecar to one pointer in
/// [`Automaton`]. Its allocation is still fallible and exactly sized, unlike
/// an infallible `Box::new` around this payload.
#[derive(Clone, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub(crate) struct OrderedEdgeDispatch(Box<[OrderedEdgeDispatchData; 1]>);

#[derive(Clone, Debug, Eq, PartialEq)]
struct OrderedEdgeDispatchData {
    rows: Box<[RowDescriptor]>,
    segment_by_byte: Box<[u8]>,
    // For each admitted row, one degree word immediately precedes that row's
    // segment transition bases. This costs S+R u32s: exactly the legacy V5
    // per-row offset count, while giving direct iterators their complete work
    // without another allocation or a larger row descriptor.
    segment_metadata: Box<[u32]>,
    transitions: EncodedTransitions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum EncodedTransitions {
    Direct32(Box<[PackedOrderedTransition32]>),
    Direct64(Box<[PackedOrderedTransition]>),
    Legacy(Box<[u32]>),
}

// Legacy fallback must never need more owner storage than the V5 layout whose
// eligibility it preserves. Array payloads are exactly equal by construction.
const _: () = assert!(size_of::<OrderedEdgeDispatchData>() <= LEGACY_OWNER_BYTES);

impl EncodedTransitions {
    fn len(&self) -> usize {
        match self {
            Self::Direct32(transitions) => transitions.len(),
            Self::Direct64(transitions) => transitions.len(),
            Self::Legacy(edges) => edges.len(),
        }
    }

    fn retained_bytes(&self) -> usize {
        match self {
            Self::Direct32(transitions) => transitions
                .len()
                .checked_mul(size_of::<PackedOrderedTransition32>()),
            Self::Direct64(transitions) => transitions
                .len()
                .checked_mul(size_of::<PackedOrderedTransition>()),
            Self::Legacy(edges) => edges.len().checked_mul(size_of::<u32>()),
        }
        .expect("bounded ordered-edge transition bytes remain representable")
    }
}

#[derive(Clone, Copy)]
struct RowShape {
    segments: usize,
    matching_edges: usize,
    maximum_target: u32,
    maximum_delta: u32,
    admitted: bool,
    work: usize,
}

#[derive(Clone, Copy)]
struct Shape {
    admitted_rows: usize,
    segments: usize,
    matching_edges: usize,
    encoding: TransitionEncoding,
    retained_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransitionEncoding {
    Direct32 { target_bits: u32 },
    Direct64,
    Legacy,
}

impl TransitionEncoding {
    const fn target_bits(self) -> u32 {
        match self {
            Self::Direct32 { target_bits } => target_bits,
            Self::Direct64 | Self::Legacy => 0,
        }
    }
}

enum MutableTransitions {
    Direct32 {
        transitions: Vec<PackedOrderedTransition32>,
        target_bits: u32,
    },
    Direct64(Vec<PackedOrderedTransition>),
    Legacy(Vec<u32>),
}

impl MutableTransitions {
    fn new(
        encoding: TransitionEncoding,
        length: usize,
        requested_bytes: usize,
    ) -> Result<Self, OrderedEdgeDispatchAllocationError> {
        match encoding {
            TransitionEncoding::Direct32 { target_bits } => Ok(Self::Direct32 {
                transitions: exact_vec(length, requested_bytes)?,
                target_bits,
            }),
            TransitionEncoding::Direct64 => {
                Ok(Self::Direct64(exact_vec(length, requested_bytes)?))
            }
            TransitionEncoding::Legacy => {
                Ok(Self::Legacy(exact_vec(length, requested_bytes)?))
            }
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Direct32 { transitions, .. } => transitions.len(),
            Self::Direct64(transitions) => transitions.len(),
            Self::Legacy(edges) => edges.len(),
        }
    }

    fn push(&mut self, target: u32, work: u32, edge: u32) {
        match self {
            Self::Direct32 {
                transitions,
                target_bits,
            } => transitions.push(PackedOrderedTransition32::new(
                target,
                work,
                *target_bits,
            )),
            Self::Direct64(transitions) => {
                transitions.push(PackedOrderedTransition::new(target, work));
            }
            Self::Legacy(edges) => edges.push(edge),
        }
    }

    fn freeze(self) -> EncodedTransitions {
        match self {
            Self::Direct32 { transitions, .. } => {
                EncodedTransitions::Direct32(transitions.into_boxed_slice())
            }
            Self::Direct64(transitions) => {
                EncodedTransitions::Direct64(transitions.into_boxed_slice())
            }
            Self::Legacy(edges) => EncodedTransitions::Legacy(edges.into_boxed_slice()),
        }
    }
}

#[derive(Clone, Copy)]
struct SegmentRepresentatives {
    bytes: [u8; BYTE_DOMAIN],
    len: usize,
}

impl SegmentRepresentatives {
    fn iter(&self) -> impl Iterator<Item = u8> + '_ {
        self.bytes[..self.len].iter().copied()
    }
}

impl OrderedEdgeDispatch {
    pub(crate) const fn native_view(&self) -> NativeOrderedEdgeDispatchView<'_> {
        NativeOrderedEdgeDispatchView { dispatch: self }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "fallible exact-size emission keeps all sidecar arrays in one auditable pass"
    )]
    pub(crate) fn derive(
        automaton: &Automaton,
    ) -> Result<Option<Self>, OrderedEdgeDispatchAllocationError> {
        let Some(shape) = derive_shape(automaton) else {
            return Ok(None);
        };
        if shape.admitted_rows == 0 {
            return Ok(None);
        }

        let mut rows = exact_vec(automaton.roles.len(), shape.retained_bytes)?;
        rows.resize(automaton.roles.len(), RowDescriptor::ABSENT);
        let byte_map_len = shape
            .admitted_rows
            .checked_mul(BYTE_DOMAIN)
            .expect("bounded ordered-edge dispatch byte-map length was checked during derivation");
        let mut segment_by_byte = exact_vec(byte_map_len, shape.retained_bytes)?;
        let segment_metadata_count = shape
            .segments
            .checked_add(shape.admitted_rows)
            .expect("bounded ordered-edge metadata count was checked during derivation");
        let mut segment_metadata = exact_vec(segment_metadata_count, shape.retained_bytes)?;
        let mut transitions = MutableTransitions::new(
            shape.encoding,
            shape.matching_edges,
            shape.retained_bytes,
        )?;

        let mut row_ordinal = 0usize;
        for (state, (&role, descriptor)) in automaton.roles.iter().zip(&mut rows).enumerate() {
            if role != StateRole::Consume {
                continue;
            }
            let range = state_edges(automaton, state);
            let row_shape = analyze_row(automaton, range.clone());
            if !row_shape.admitted {
                continue;
            }

            segment_metadata.push(
                u32::try_from(range.len()).expect("validated consuming-row degree fits u32"),
            );
            let segment_base = segment_metadata.len();
            *descriptor = RowDescriptor::present(
                segment_base,
                row_ordinal,
                row_shape
                    .segments
                    .checked_sub(1)
                    .expect("every consuming row has one byte segment"),
                shape.encoding.target_bits(),
            );

            let boundaries = row_boundaries(automaton, range.clone());
            let mut segment = 0usize;
            for (byte, &boundary) in boundaries[..BYTE_DOMAIN].iter().enumerate() {
                if byte != 0 && boundary {
                    segment = segment
                        .checked_add(1)
                        .expect("at most 256 local byte segments");
                }
                segment_by_byte
                    .push(u8::try_from(segment).expect("local byte-segment ordinal fits u8"));
            }
            debug_assert_eq!(segment.checked_add(1), Some(row_shape.segments));

            for representative in segment_representatives(&boundaries).iter() {
                let transition_base = transitions.len();
                segment_metadata.push(
                    u32::try_from(transition_base)
                        .expect("bounded dispatch transition count fits u32"),
                );
                let mut next_unaccounted = range.start;
                for edge in range.clone() {
                    if automaton.byte_starts[edge] <= representative
                        && representative <= automaton.byte_ends[edge]
                    {
                        // Iterating the source CSR is the priority proof. The
                        // exact local delta charges skipped nonmatches through
                        // this match before a possible early acceptance. The
                        // target is lowered now so runtime never reloads the
                        // source edge arrays.
                        let through = edge
                            .checked_add(1)
                            .and_then(|end| end.checked_sub(next_unaccounted))
                            .expect("increasing edges remain within their source row");
                        transitions.push(
                            automaton.edge_targets[edge],
                            u32::try_from(through)
                                .expect("validated consuming-row degree fits u32"),
                            u32::try_from(edge).expect("validated edge index fits u32"),
                        );
                        next_unaccounted = edge
                            .checked_add(1)
                            .expect("validated edge index has a representable successor");
                    }
                }
            }
            row_ordinal = row_ordinal
                .checked_add(1)
                .expect("bounded dispatch row count");
        }

        debug_assert_eq!(row_ordinal, shape.admitted_rows);
        debug_assert_eq!(segment_by_byte.len(), byte_map_len);
        debug_assert_eq!(segment_metadata.len(), segment_metadata_count);
        debug_assert_eq!(transitions.len(), shape.matching_edges);

        let data = OrderedEdgeDispatchData {
            rows: rows.into_boxed_slice(),
            segment_by_byte: segment_by_byte.into_boxed_slice(),
            segment_metadata: segment_metadata.into_boxed_slice(),
            transitions: transitions.freeze(),
        };
        debug_assert_eq!(retained_bytes(&data), shape.retained_bytes);
        let mut owner = exact_vec(1, shape.retained_bytes)?;
        owner.push(data);
        let owner: Box<[OrderedEdgeDispatchData]> = owner.into_boxed_slice();
        let owner = owner
            .try_into()
            .map_err(|_| OrderedEdgeDispatchAllocationError {
                requested_bytes: shape.retained_bytes,
            })?;
        Ok(Some(Self(owner)))
    }

    #[allow(
        clippy::inline_always,
        reason = "bounded sidecar loads replace one admitted source-row scan and target lookup"
    )]
    #[inline(always)]
    pub(crate) fn segment(&self, state: u32, byte: u8) -> Option<OrderedEdgeSegment<'_>> {
        let data = &self.0[0];
        let state = plan_index(state);
        let descriptor = data.rows[state];
        if !descriptor.is_present() {
            return None;
        }
        let row = plan_index(descriptor.row_ordinal());
        let map_base = row
            .checked_mul(BYTE_DOMAIN)
            .expect("validated dispatch byte-map row");
        let map = map_base
            .checked_add(usize::from(byte))
            .expect("validated dispatch byte-map index");
        let segment = usize::from(data.segment_by_byte[map]);
        let last_segment = plan_index(descriptor.last_segment());
        let segment_base = plan_index(descriptor.segment_base());
        let degree_index = segment_base
            .checked_sub(1)
            .expect("admitted row metadata has a preceding degree");
        let row_work = data.segment_metadata[degree_index];
        let segment_index = segment_base
            .checked_add(segment)
            .expect("validated dispatch segment index");
        let begin = plan_index(data.segment_metadata[segment_index]);
        let admitted_rows = data.segment_by_byte.len() / BYTE_DOMAIN;
        let end = if segment < last_segment {
            let next = segment_index
                .checked_add(1)
                .expect("validated dispatch next local segment index");
            plan_index(data.segment_metadata[next])
        } else if row
            .checked_add(1)
            .is_some_and(|next_row| next_row < admitted_rows)
        {
            // The next word is the following row's degree and the word after
            // that is its first transition base, which is also this row's
            // terminal base.
            let next_row_first = segment_index
                .checked_add(2)
                .expect("validated dispatch next-row segment index");
            plan_index(data.segment_metadata[next_row_first])
        } else {
            data.transitions.len()
        };
        let transitions = match &data.transitions {
            EncodedTransitions::Direct32(transitions) => {
                let target_bits = descriptor.target_bits();
                OrderedEdgeTransitions::Direct32 {
                    transitions: &transitions[begin..end],
                    target_bits,
                    target_mask: low_mask(target_bits),
                }
            }
            EncodedTransitions::Direct64(transitions) => {
                OrderedEdgeTransitions::Direct64(&transitions[begin..end])
            }
            EncodedTransitions::Legacy(edges) => {
                OrderedEdgeTransitions::Legacy(&edges[begin..end])
            }
        };
        Some(OrderedEdgeSegment {
            transitions,
            row_work,
        })
    }

    pub(crate) fn retained_bytes(&self) -> usize {
        retained_bytes(&self.0[0])
    }

    #[cfg(test)]
    pub(crate) fn admitted_rows(&self) -> usize {
        self.0[0].rows.iter().filter(|row| row.is_present()).count()
    }

    #[cfg(test)]
    fn encoding(&self) -> TransitionEncoding {
        match &self.0[0].transitions {
            EncodedTransitions::Direct32(_) => TransitionEncoding::Direct32 {
                target_bits: self.0[0]
                    .rows
                    .iter()
                    .find(|row| row.is_present())
                    .map_or(0, |row| row.target_bits()),
            },
            EncodedTransitions::Direct64(_) => TransitionEncoding::Direct64,
            EncodedTransitions::Legacy(_) => TransitionEncoding::Legacy,
        }
    }
}

fn retained_bytes(data: &OrderedEdgeDispatchData) -> usize {
    data.rows
        .len()
        .checked_mul(size_of::<RowDescriptor>())
        .and_then(|bytes| bytes.checked_add(data.segment_by_byte.len()))
        .and_then(|bytes| {
            data.segment_metadata
                .len()
                .checked_mul(size_of::<u32>())
                .and_then(|metadata| bytes.checked_add(metadata))
        })
        .and_then(|bytes| bytes.checked_add(data.transitions.retained_bytes()))
        .and_then(|bytes| bytes.checked_add(size_of::<OrderedEdgeDispatchData>()))
        .expect("bounded ordered-edge retained bytes remain representable")
}

const fn low_mask(bits: u32) -> u32 {
    if bits == 0 {
        0
    } else {
        u32::MAX >> u32::BITS.abs_diff(bits)
    }
}

fn exact_vec<T>(
    length: usize,
    requested_bytes: usize,
) -> Result<Vec<T>, OrderedEdgeDispatchAllocationError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(length)
        .map_err(|_| OrderedEdgeDispatchAllocationError { requested_bytes })?;
    if values.capacity() != length {
        return Err(OrderedEdgeDispatchAllocationError { requested_bytes });
    }
    Ok(values)
}

fn derive_shape(automaton: &Automaton) -> Option<Shape> {
    let mut admitted_rows = 0usize;
    let mut segments = 0usize;
    let mut matching_edges = 0usize;
    let mut maximum_target = 0u32;
    let mut maximum_delta = 0u32;
    let mut derivation_work = automaton.roles.len().checked_mul(RESERVED_STATE_PASSES)?;
    if derivation_work > MAX_DERIVATION_WORK {
        return None;
    }

    for state in 0..automaton.roles.len() {
        if automaton.roles[state] != StateRole::Consume {
            continue;
        }
        let row = state_edges(automaton, state);
        let remaining = MAX_DERIVATION_WORK.checked_sub(derivation_work)?;
        let shape = analyze_row_with_budget(automaton, row, remaining)?;
        // Exact sizing repeats classification after allocation, and admitted
        // rows then repeat the segment traversal while emitting their CSR.
        // Reserve all three passes for every row; this overcounts a declining
        // row by one pass but keeps the untrusted-graph ceiling simple and
        // hard.
        let reserved = shape.work.checked_mul(RESERVED_ROW_PASSES)?;
        derivation_work = derivation_work.checked_add(reserved)?;
        if shape.admitted {
            admitted_rows = admitted_rows.checked_add(1)?;
            segments = segments.checked_add(shape.segments)?;
            matching_edges = matching_edges.checked_add(shape.matching_edges)?;
            maximum_target = maximum_target.max(shape.maximum_target);
            maximum_delta = maximum_delta.max(shape.maximum_delta);
        }
        if derivation_work > MAX_DERIVATION_WORK {
            return None;
        }
    }

    if admitted_rows == 0 {
        return Some(Shape {
            admitted_rows: 0,
            segments: 0,
            matching_edges: 0,
            encoding: TransitionEncoding::Direct32 { target_bits: 0 },
            retained_bytes: 0,
        });
    }

    let metadata = segments.checked_add(admitted_rows)?;
    if admitted_rows > SEGMENT_BASE_LIMIT
        || metadata > SEGMENT_BASE_LIMIT
        || u32::try_from(matching_edges).is_err()
        || maximum_delta == 0
    {
        return None;
    }
    let (encoding, retained_bytes) = select_encoding(
        automaton.roles.len(),
        admitted_rows,
        segments,
        matching_edges,
        maximum_target,
        maximum_delta,
        MAX_RETAINED_BYTES,
    )?;
    Some(Shape {
        admitted_rows,
        segments,
        matching_edges,
        encoding,
        retained_bytes,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "the canonical encoding decision is an exact graph-shape calculation"
)]
fn select_encoding(
    states: usize,
    admitted_rows: usize,
    segments: usize,
    matching_edges: usize,
    maximum_target: u32,
    maximum_delta: u32,
    retained_limit: usize,
) -> Option<(TransitionEncoding, usize)> {
    let metadata = segments.checked_add(admitted_rows)?;
    let common_payload = states
        .checked_mul(size_of::<RowDescriptor>())?
        .checked_add(admitted_rows.checked_mul(BYTE_DOMAIN)?)?
        .checked_add(metadata.checked_mul(size_of::<u32>())?)?;
    let actual_common = common_payload.checked_add(size_of::<OrderedEdgeDispatchData>())?;
    let narrow_bytes = actual_common
        .checked_add(matching_edges.checked_mul(size_of::<u32>())?)?;
    let target_bits = bits_required(maximum_target);
    let delta_bits = bits_required(maximum_delta);
    if delta_bits != 0
        && target_bits
            .checked_add(delta_bits)
            .is_some_and(|bits| bits <= u32::BITS)
        && narrow_bytes <= retained_limit
    {
        return Some((
            TransitionEncoding::Direct32 { target_bits },
            narrow_bytes,
        ));
    }

    let wide_bytes = actual_common.checked_add(
        matching_edges.checked_mul(size_of::<PackedOrderedTransition>())?,
    )?;
    if wide_bytes <= retained_limit {
        return Some((TransitionEncoding::Direct64, wide_bytes));
    }

    // Preserve every stable V5 marker whose exact ed690 edge-ID layout fit.
    // The current legacy variant has the same payload arrays and an owner no
    // larger than that canonical nine-word owner (enforced above).
    let legacy_bytes = common_payload
        .checked_add(LEGACY_OWNER_BYTES)?
        .checked_add(matching_edges.checked_mul(size_of::<u32>())?)?;
    if legacy_bytes <= retained_limit && narrow_bytes <= retained_limit {
        return Some((TransitionEncoding::Legacy, narrow_bytes));
    }
    None
}

const fn bits_required(value: u32) -> u32 {
    u32::BITS.abs_diff(value.leading_zeros())
}

fn analyze_row(automaton: &Automaton, row: core::ops::Range<usize>) -> RowShape {
    let degree = row.len();
    let boundaries = row_boundaries(automaton, row.clone());
    let representatives = segment_representatives(&boundaries);
    let segments = representatives.len;
    let work = degree
        .checked_add(ROW_FIXED_SCAN_WORK)
        .and_then(|value| {
            segments
                .checked_mul(degree)
                .and_then(|comparisons| value.checked_add(comparisons))
        })
        .unwrap_or(usize::MAX);
    analyze_row_with_representatives(automaton, row, &representatives, work)
}

fn analyze_row_with_budget(
    automaton: &Automaton,
    row: core::ops::Range<usize>,
    remaining_work: usize,
) -> Option<RowShape> {
    let degree = row.len();
    // Check the edge scan and all fixed byte-domain work before traversing an
    // untrusted row. Reserving all future passes here makes the 64 MiB work
    // ceiling a hard preflight rather than a post-hoc observation.
    let fixed = degree.checked_add(ROW_FIXED_SCAN_WORK)?;
    if fixed.checked_mul(RESERVED_ROW_PASSES)? > remaining_work {
        return None;
    }
    let boundaries = row_boundaries(automaton, row.clone());
    let representatives = segment_representatives(&boundaries);
    let work = fixed.checked_add(representatives.len.checked_mul(degree)?)?;
    if work.checked_mul(RESERVED_ROW_PASSES)? > remaining_work {
        return None;
    }
    Some(analyze_row_with_representatives(
        automaton,
        row,
        &representatives,
        work,
    ))
}

fn analyze_row_with_representatives(
    automaton: &Automaton,
    row: core::ops::Range<usize>,
    representatives: &SegmentRepresentatives,
    work: usize,
) -> RowShape {
    let degree = row.len();
    let segments = representatives.len;
    let mut maximum_matching = 0usize;
    let mut matching_edges = 0usize;
    let mut maximum_target = 0u32;
    let mut maximum_delta = 0u32;
    for representative in representatives.iter() {
        let mut matching = 0usize;
        let mut next_unaccounted = row.start;
        for edge in row.clone() {
            if automaton.byte_starts[edge] <= representative
                && representative <= automaton.byte_ends[edge]
            {
                matching = matching.saturating_add(1);
                maximum_target = maximum_target.max(automaton.edge_targets[edge]);
                let through = edge
                    .checked_add(1)
                    .and_then(|end| end.checked_sub(next_unaccounted))
                    .expect("increasing matching edges remain within their source row");
                maximum_delta = maximum_delta.max(
                    u32::try_from(through)
                        .expect("validated consuming-row degree fits u32"),
                );
                next_unaccounted = edge
                    .checked_add(1)
                    .expect("validated edge index has a representable successor");
            }
        }
        maximum_matching = maximum_matching.max(matching);
        matching_edges = matching_edges.saturating_add(matching);
    }
    RowShape {
        segments,
        matching_edges,
        maximum_target,
        maximum_delta,
        admitted: maximum_matching
            .checked_add(DISPATCH_OVERHEAD)
            .is_some_and(|cost| cost < degree),
        work,
    }
}

fn row_boundaries(automaton: &Automaton, row: core::ops::Range<usize>) -> [bool; BOUNDARY_DOMAIN] {
    let mut boundaries = [false; BOUNDARY_DOMAIN];
    boundaries[0] = true;
    for edge in row {
        debug_assert_eq!(automaton.edge_kinds[edge], EdgeKind::ByteRange);
        boundaries[usize::from(automaton.byte_starts[edge])] = true;
        if automaton.byte_ends[edge] != u8::MAX {
            boundaries[usize::from(automaton.byte_ends[edge]) + 1] = true;
        }
    }
    boundaries
}

fn segment_representatives(boundaries: &[bool; BOUNDARY_DOMAIN]) -> SegmentRepresentatives {
    let mut representatives = [0_u8; BYTE_DOMAIN];
    let mut len = 0usize;
    for (byte, &boundary) in boundaries[..BYTE_DOMAIN].iter().enumerate() {
        if boundary {
            representatives[len] = u8::try_from(byte).expect("byte domain fits u8");
            len = len.checked_add(1).expect("at most 256 byte segments");
        }
    }
    SegmentRepresentatives {
        bytes: representatives,
        len,
    }
}

fn state_edges(automaton: &Automaton, state: usize) -> core::ops::Range<usize> {
    let next = state
        .checked_add(1)
        .expect("validated automaton state has a following CSR offset");
    plan_index(automaton.edge_offsets[state])..plan_index(automaton.edge_offsets[next])
}

#[cfg(test)]
mod tests {
    use crate::{Automaton, CompileLimits, EdgeKind, Exists, RawPlan, SearchLimits, StateRole};

    fn one_row(ranges: &[(u8, u8)]) -> Automaton {
        let edges = u32::try_from(ranges.len()).unwrap();
        let mut roles = vec![StateRole::Consume];
        roles.resize(ranges.len().checked_add(1).unwrap(), StateRole::Accept);
        let mut edge_offsets = vec![0, edges];
        edge_offsets.resize(ranges.len().checked_add(2).unwrap(), edges);
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles,
                edge_offsets,
                edge_targets: (1..=ranges.len())
                    .map(|target| u32::try_from(target).unwrap())
                    .collect(),
                edge_kinds: vec![EdgeKind::ByteRange; ranges.len()],
                byte_starts: ranges.iter().map(|&(start, _)| start).collect(),
                byte_ends: ranges.iter().map(|&(_, end)| end).collect(),
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn scalar_targets(automaton: &Automaton, state: u32, byte: u8) -> Vec<u32> {
        automaton
            .state_edges(state)
            .filter(|&edge| {
                automaton.byte_starts[edge] <= byte && byte <= automaton.byte_ends[edge]
            })
            .map(|edge| automaton.edge_targets[edge])
            .collect()
    }

    fn dispatched_targets_and_work(
        automaton: &Automaton,
        state: u32,
        byte: u8,
    ) -> (Vec<u32>, u64) {
        let segment = automaton
            .ordered_edge_dispatch
            .as_ref()
            .unwrap()
            .segment(state, byte)
            .unwrap();
        let (targets, matched_work) = match segment.transitions {
            super::OrderedEdgeTransitions::Direct32 {
                transitions,
                target_bits,
                target_mask,
            } => (
                transitions
                    .iter()
                    .map(|&transition| transition.target(target_mask))
                    .collect(),
                transitions
                    .iter()
                    .map(|&transition| u64::from(transition.work(target_bits)))
                    .sum::<u64>(),
            ),
            super::OrderedEdgeTransitions::Direct64(transitions) => (
                transitions
                    .iter()
                    .map(|&transition| transition.target())
                    .collect(),
                transitions
                    .iter()
                    .map(|&transition| u64::from(transition.work()))
                    .sum::<u64>(),
            ),
            super::OrderedEdgeTransitions::Legacy(edges) => {
                let mut next_unaccounted = automaton.state_edges(state).start;
                let mut work = 0u64;
                let targets = edges
                    .iter()
                    .map(|&encoded| {
                        let edge = crate::plan::plan_index(encoded);
                        let next = edge.checked_add(1).unwrap();
                        work = work
                            .checked_add(
                                u64::try_from(next.checked_sub(next_unaccounted).unwrap()).unwrap(),
                            )
                            .unwrap();
                        next_unaccounted = next;
                        automaton.edge_targets[edge]
                    })
                    .collect();
                (targets, work)
            }
        };
        assert!(matched_work <= u64::from(segment.row_work));
        (targets, u64::from(segment.row_work))
    }

    #[test]
    fn strict_profitability_boundary_is_graph_only() {
        let mut five = one_row(&[(1, 1), (3, 3), (5, 5), (7, 7), (9, 9)]);
        assert!(!five.try_enable_ordered_edge_dispatch().unwrap());

        let mut six = one_row(&[(1, 1), (3, 3), (5, 5), (7, 7), (9, 9), (11, 11)]);
        assert!(six.try_enable_ordered_edge_dispatch().unwrap());
        assert_eq!(
            six.ordered_edge_dispatch.as_ref().unwrap().admitted_rows(),
            1
        );

        let mut overlapping = one_row(&[(1, 9); 8]);
        assert!(!overlapping.try_enable_ordered_edge_dispatch().unwrap());
    }

    #[test]
    fn generated_local_segments_preserve_every_matching_edge_and_priority() {
        let mut admitted = 0usize;
        for mask in 0_u16..256 {
            let mut ranges = Vec::new();
            for edge in 0_u8..8 {
                let base = edge.saturating_mul(16);
                let range = if mask & (1_u16 << edge) == 0 {
                    (base, base.saturating_add(3))
                } else {
                    (base.saturating_add(2), base.saturating_add(11))
                };
                ranges.push(range);
            }
            // Retain duplicates and overlaps at both ends of the row. Their
            // target order must survive the CSR unchanged.
            ranges[6] = ranges[0];
            ranges[7] = (2, 20);
            let mut automaton = one_row(&ranges);
            if !automaton.try_enable_ordered_edge_dispatch().unwrap() {
                continue;
            }
            admitted = admitted.saturating_add(1);
            for byte in u8::MIN..=u8::MAX {
                let (targets, work) = dispatched_targets_and_work(&automaton, 0, byte);
                assert_eq!(
                    targets,
                    scalar_targets(&automaton, 0, byte),
                    "mask={mask:#x}, byte={byte:#x}"
                );
                assert_eq!(
                    work,
                    u64::try_from(ranges.len()).unwrap(),
                    "mask={mask:#x}, byte={byte:#x}"
                );
            }
        }
        assert!(admitted > 0);
    }

    #[test]
    fn packed_entries_are_direct_targets_with_exact_empty_and_overlapping_tails() {
        let ranges = [
            (1, 4),
            (3, 7),
            (9, 9),
            (11, 14),
            (13, 18),
            (32, 63),
            (128, 191),
            (255, 255),
        ];
        let targets = [8, 3, 7, 1, 6, 2, 5, 4];
        let mut automaton = one_row(&ranges);
        automaton.edge_targets.copy_from_slice(&targets);
        assert!(automaton.try_enable_ordered_edge_dispatch().unwrap());

        for byte in u8::MIN..=u8::MAX {
            let (packed_targets, work) = dispatched_targets_and_work(&automaton, 0, byte);
            assert_eq!(
                packed_targets,
                scalar_targets(&automaton, 0, byte),
                "byte={byte}"
            );
            assert_eq!(work, u64::try_from(ranges.len()).unwrap(), "byte={byte}");
        }
        let empty = automaton
            .ordered_edge_dispatch
            .as_ref()
            .unwrap()
            .segment(0, 200)
            .unwrap();
        assert!(match empty.transitions {
            super::OrderedEdgeTransitions::Direct32 { transitions, .. } => {
                transitions.is_empty()
            }
            super::OrderedEdgeTransitions::Direct64(transitions) => transitions.is_empty(),
            super::OrderedEdgeTransitions::Legacy(edges) => edges.is_empty(),
        });
        assert_eq!(empty.row_work, u32::try_from(ranges.len()).unwrap());
    }

    #[test]
    fn packed_transition_preserves_maximum_target_and_work_encodings() {
        let packed = super::PackedOrderedTransition::new(u32::MAX, u32::MAX);
        assert_eq!(packed.target(), u32::MAX);
        assert_eq!(packed.work(), u32::MAX);
        assert_eq!(core::mem::size_of_val(&packed), core::mem::size_of::<u64>());

        let zero_target = super::PackedOrderedTransition32::new(0, u32::MAX, 0);
        assert_eq!(zero_target.target(super::low_mask(0)), 0);
        assert_eq!(zero_target.work(0), u32::MAX);
        let full = super::PackedOrderedTransition32::new(u16::MAX.into(), u16::MAX.into(), 16);
        assert_eq!(full.target(super::low_mask(16)), u16::MAX.into());
        assert_eq!(full.work(16), u16::MAX.into());
        assert_eq!(core::mem::size_of_val(&full), core::mem::size_of::<u32>());
    }

    #[test]
    fn adaptive_width_and_exact_retained_boundaries_are_canonical() {
        use super::{TransitionEncoding, select_encoding};

        let selected = |target, delta, limit| {
            select_encoding(2, 1, 1, 1, target, delta, limit)
        };
        assert!(matches!(
            selected(0, u32::MAX, usize::MAX),
            Some((TransitionEncoding::Direct32 { target_bits: 0 }, _))
        ));
        assert!(matches!(
            selected((1 << 15) - 1, (1 << 16) - 1, usize::MAX),
            Some((TransitionEncoding::Direct32 { target_bits: 15 }, _))
        ));
        assert!(matches!(
            selected((1 << 16) - 1, (1 << 16) - 1, usize::MAX),
            Some((TransitionEncoding::Direct32 { target_bits: 16 }, _))
        ));
        assert!(matches!(
            selected(1_u32 << 30, 1, usize::MAX),
            Some((TransitionEncoding::Direct32 { target_bits: 31 }, _))
        ));
        assert!(matches!(
            selected(1_u32 << 31, 1, usize::MAX),
            Some((TransitionEncoding::Direct64, _))
        ));

        let states = 65_537usize;
        let rows = 1usize;
        let segments = 1usize;
        let matching = 17usize;
        let common = states * core::mem::size_of::<super::RowDescriptor>()
            + rows * super::BYTE_DOMAIN
            + (segments + rows) * core::mem::size_of::<u32>()
            + core::mem::size_of::<super::OrderedEdgeDispatchData>();
        let legacy = common + matching * core::mem::size_of::<u32>();
        let wide = common + matching * core::mem::size_of::<super::PackedOrderedTransition>();
        let target = 1 << 16;
        let delta = 1 << 15;
        assert_eq!(super::bits_required(target) + super::bits_required(delta), 33);
        let capped = |limit| {
            select_encoding(states, rows, segments, matching, target, delta, limit)
        };
        assert_eq!(
            capped(wide),
            Some((TransitionEncoding::Direct64, wide))
        );
        assert_eq!(
            capped(wide - 1),
            Some((TransitionEncoding::Legacy, legacy))
        );
        assert_eq!(capped(legacy - 1), None);
        assert_eq!(
            core::mem::size_of::<super::OrderedEdgeDispatchData>(),
            super::LEGACY_OWNER_BYTES
        );

        let mut zero_target = one_row(&[(1, 1), (3, 3), (5, 5), (7, 7), (9, 9), (11, 11)]);
        zero_target.edge_targets.fill(0);
        assert!(zero_target.try_enable_ordered_edge_dispatch().unwrap());
        assert_eq!(
            zero_target
                .ordered_edge_dispatch
                .as_ref()
                .unwrap()
                .encoding(),
            TransitionEncoding::Direct32 { target_bits: 0 }
        );
        assert_eq!(
            dispatched_targets_and_work(&zero_target, 0, 11),
            (vec![0], 6)
        );
    }

    fn high_target_graph(grouped_singletons: bool) -> Automaton {
        const STATES: usize = 65_537;
        const HIGH_TARGET: u32 = 65_536;
        let (starts, ends) = if grouped_singletons {
            let starts: Vec<u8> = (u8::MIN..=u8::MAX)
                .flat_map(|byte| core::iter::repeat(byte).take(256))
                .collect();
            (starts.clone(), starts)
        } else {
            const BROAD: usize = 32_650;
            let mut starts = vec![0; BROAD];
            let mut ends = vec![254; BROAD];
            starts.extend(u8::MIN..=254);
            ends.extend(u8::MIN..=254);
            starts.extend(core::iter::repeat(255).take(6));
            ends.extend(core::iter::repeat(255).take(6));
            (starts, ends)
        };
        let edges = starts.len();
        let encoded_edges = u32::try_from(edges).unwrap();
        let mut roles = vec![StateRole::Consume];
        roles.resize(STATES, StateRole::Accept);
        let mut edge_offsets = vec![0, encoded_edges];
        edge_offsets.resize(STATES + 1, encoded_edges);
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles,
                edge_offsets,
                edge_targets: vec![HIGH_TARGET; edges],
                edge_kinds: vec![EdgeKind::ByteRange; edges],
                byte_starts: starts,
                byte_ends: ends,
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn direct_u64_executes_when_the_exact_thirty_three_bit_shape_fits() {
        let scalar = high_target_graph(true);
        let mut automaton = high_target_graph(true);
        assert!(automaton.try_enable_ordered_edge_dispatch().unwrap());
        let dispatch = automaton.ordered_edge_dispatch.as_ref().unwrap();
        assert_eq!(dispatch.encoding(), super::TransitionEncoding::Direct64);
        for byte in u8::MIN..=u8::MAX {
            let (targets, work) = dispatched_targets_and_work(&automaton, 0, byte);
            assert_eq!(targets, vec![65_536; 256]);
            assert_eq!(work, 65_536);
        }
        let want = scalar
            .prepare::<Exists>()
            .search(b"\xff", SearchLimits::unlimited())
            .unwrap();
        let got = automaton
            .prepare::<Exists>()
            .search(b"\xff", SearchLimits::unlimited())
            .unwrap();
        assert_eq!(got.output(), want.output());
        assert_eq!(got.accounting(), want.accounting());
    }

    #[test]
    fn old_v5_fit_falls_back_to_legacy_before_the_direct_u64_ceiling() {
        let scalar = high_target_graph(false);
        let mut automaton = high_target_graph(false);
        assert!(automaton.try_enable_ordered_edge_dispatch().unwrap());
        let dispatch = automaton.ordered_edge_dispatch.as_ref().unwrap();
        assert_eq!(dispatch.encoding(), super::TransitionEncoding::Legacy);
        let expected = 8 * 65_537
            + super::BYTE_DOMAIN
            + 4 * (256 + 1)
            + 4 * 8_326_011
            + super::LEGACY_OWNER_BYTES;
        assert_eq!(dispatch.retained_bytes(), expected);
        assert!(expected < super::MAX_RETAINED_BYTES);
        let direct_u64 = expected + 4 * 8_326_011;
        assert!(direct_u64 > super::MAX_RETAINED_BYTES);
        for byte in [0, 1, 127, 254, 255] {
            let (targets, work) = dispatched_targets_and_work(&automaton, 0, byte);
            assert_eq!(targets, scalar_targets(&automaton, 0, byte));
            assert_eq!(work, 32_911);
        }
        let want = scalar
            .prepare::<Exists>()
            .search(b"\xff", SearchLimits::unlimited())
            .unwrap();
        let got = automaton
            .prepare::<Exists>()
            .search(b"\xff", SearchLimits::unlimited())
            .unwrap();
        assert_eq!(got.output(), want.output());
        assert_eq!(got.accounting(), want.accounting());
    }

    #[test]
    fn packed_segment_bases_are_exact_across_multiple_admitted_rows() {
        let first = [
            (0, 0),
            (2, 2),
            (4, 4),
            (6, 6),
            (8, 8),
            (10, 10),
            (12, 12),
            (14, 14),
        ];
        let second = [
            (1, 5),
            (3, 7),
            (16, 31),
            (32, 47),
            (64, 95),
            (127, 127),
            (128, 191),
            (255, 255),
        ];
        let mut edge_offsets = vec![0, 8, 16];
        edge_offsets.resize(11, 16);
        let mut automaton = Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: [StateRole::Consume, StateRole::Consume]
                    .into_iter()
                    .chain(core::iter::repeat(StateRole::Accept).take(8))
                    .collect(),
                edge_offsets,
                edge_targets: (2_u32..10).chain((2_u32..10).rev()).collect(),
                edge_kinds: vec![EdgeKind::ByteRange; 16],
                byte_starts: first
                    .iter()
                    .chain(&second)
                    .map(|&(start, _)| start)
                    .collect(),
                byte_ends: first
                    .iter()
                    .chain(&second)
                    .map(|&(_, end)| end)
                    .collect(),
            },
            CompileLimits::default(),
        )
        .unwrap();
        assert!(automaton.try_enable_ordered_edge_dispatch().unwrap());
        assert_eq!(
            automaton
                .ordered_edge_dispatch
                .as_ref()
                .unwrap()
                .admitted_rows(),
            2
        );
        let dispatch = automaton.ordered_edge_dispatch.as_ref().unwrap();
        assert!(matches!(
            dispatch.encoding(),
            super::TransitionEncoding::Direct32 { .. }
        ));
        let data = &dispatch.0[0];
        for (row, descriptor) in data.rows.iter().filter(|row| row.is_present()).enumerate() {
            assert_eq!(super::plan_index(descriptor.row_ordinal()), row);
            assert_eq!(
                super::plan_index(descriptor.last_segment()),
                usize::from(data.segment_by_byte[row * super::BYTE_DOMAIN + 255])
            );
        }
        let direct_entries = match &data.transitions {
            super::EncodedTransitions::Direct32(transitions) => transitions.len(),
            _ => unreachable!(),
        };
        let legacy_formula = data.rows.len() * core::mem::size_of::<super::RowDescriptor>()
            + data.segment_by_byte.len()
            + data.segment_metadata.len() * core::mem::size_of::<u32>()
            + direct_entries * core::mem::size_of::<u32>()
            + super::LEGACY_OWNER_BYTES;
        assert_eq!(dispatch.retained_bytes(), legacy_formula);

        for state in [0_u32, 1] {
            for byte in u8::MIN..=u8::MAX {
                let (targets, work) = dispatched_targets_and_work(&automaton, state, byte);
                assert_eq!(targets, scalar_targets(&automaton, state, byte));
                assert_eq!(work, 8, "state={state}, byte={byte}");
            }
        }
    }

    #[test]
    fn derivation_is_canonical_and_clone_retains_the_immutable_sidecar() {
        let ranges = [
            (0, 0),
            (2, 4),
            (9, 9),
            (16, 31),
            (64, 95),
            (127, 127),
            (128, 191),
            (255, 255),
        ];
        let mut left = one_row(&ranges);
        let mut right = one_row(&ranges);
        assert!(left.try_enable_ordered_edge_dispatch().unwrap());
        assert!(right.try_enable_ordered_edge_dispatch().unwrap());
        assert_eq!(left.ordered_edge_dispatch, right.ordered_edge_dispatch);
        assert!(left.ordered_edge_dispatch_retained_bytes() > 0);

        let cloned = left.clone();
        assert!(cloned.has_ordered_edge_dispatch());
        assert_eq!(left.ordered_edge_dispatch, cloned.ordered_edge_dispatch);
    }
}
