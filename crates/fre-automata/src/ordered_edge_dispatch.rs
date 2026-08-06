//! Canonical priority-preserving dispatch for wide consuming rows.
//!
//! A Thompson consuming state may have many ordered byte-range edges even
//! though only a small subset can match any one byte. The universal K0 path
//! must preserve that edge order, but it need not inspect the nonmatching
//! edges on an unlimited invocation. This sidecar partitions each admitted
//! row into its exact local byte segments. Each matching transition retains
//! its target and the exact scalar edge-inspection delta in one packed word;
//! each segment separately retains the terminal nonmatching tail. Runtime can
//! therefore preserve priority and abstract work without returning to the
//! source graph for edge ordinals, targets, or row bounds.

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
}

/// One runtime-ready matching transition.
///
/// The low half is the direct graph target and the high half is the exact
/// number of scalar row edges inspected through this match. Both source
/// fields are validated `u32`s, so the representation is lossless even at
/// their maximum encodings and is target-width independent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub(crate) struct PackedOrderedTransition(u64);

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
}

/// Start of one local byte segment's packed transition run and the exact
/// scalar work remaining after that run. A final sentinel supplies the end
/// offset for the last real segment in the graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SegmentDescriptor {
    transition_base: u32,
    tail_work: u32,
}

/// Borrowed runtime view for one byte in one admitted consuming row.
pub(crate) struct OrderedEdgeSegment<'a> {
    pub(crate) transitions: &'a [PackedOrderedTransition],
    pub(crate) tail_work: u32,
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
    segments: Box<[SegmentDescriptor]>,
    transitions: Box<[PackedOrderedTransition]>,
    retained_bytes: usize,
}

#[derive(Clone, Copy)]
struct RowShape {
    segments: usize,
    matching_edges: usize,
    admitted: bool,
    work: usize,
}

#[derive(Clone, Copy)]
struct Shape {
    admitted_rows: usize,
    segments: usize,
    matching_edges: usize,
    retained_bytes: usize,
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
        let segment_descriptor_count = shape
            .segments
            .checked_add(1)
            .expect("bounded ordered-edge segment count has one sentinel");
        let mut segments = exact_vec(segment_descriptor_count, shape.retained_bytes)?;
        let mut transitions = exact_vec(shape.matching_edges, shape.retained_bytes)?;

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

            let segment_base = segments.len();
            *descriptor = RowDescriptor {
                segment_base: u32::try_from(segment_base)
                    .expect("bounded dispatch segment count fits u32"),
                row_ordinal: u32::try_from(row_ordinal)
                    .expect("bounded dispatch row count fits u32"),
            };

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
                        transitions.push(PackedOrderedTransition::new(
                            automaton.edge_targets[edge],
                            u32::try_from(through)
                                .expect("validated consuming-row degree fits u32"),
                        ));
                        next_unaccounted = edge
                            .checked_add(1)
                            .expect("validated edge index has a representable successor");
                    }
                }
                let tail_work = range
                    .end
                    .checked_sub(next_unaccounted)
                    .expect("matching edges remain within their source row");
                segments.push(SegmentDescriptor {
                    transition_base: u32::try_from(transition_base)
                        .expect("bounded dispatch transition count fits u32"),
                    tail_work: u32::try_from(tail_work)
                        .expect("validated consuming-row degree fits u32"),
                });
            }
            row_ordinal = row_ordinal
                .checked_add(1)
                .expect("bounded dispatch row count");
        }

        segments.push(SegmentDescriptor {
            transition_base: u32::try_from(transitions.len())
                .expect("bounded dispatch transition count fits u32"),
            tail_work: 0,
        });

        debug_assert_eq!(row_ordinal, shape.admitted_rows);
        debug_assert_eq!(segment_by_byte.len(), byte_map_len);
        debug_assert_eq!(segments.len(), segment_descriptor_count);
        debug_assert_eq!(transitions.len(), shape.matching_edges);

        let data = OrderedEdgeDispatchData {
            rows: rows.into_boxed_slice(),
            segment_by_byte: segment_by_byte.into_boxed_slice(),
            segments: segments.into_boxed_slice(),
            transitions: transitions.into_boxed_slice(),
            retained_bytes: shape.retained_bytes,
        };
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
        let row = plan_index(descriptor.row_ordinal);
        let map = row
            .checked_mul(BYTE_DOMAIN)
            .and_then(|base| base.checked_add(usize::from(byte)))
            .expect("validated dispatch byte-map index");
        let segment = usize::from(data.segment_by_byte[map]);
        let segment_index = plan_index(descriptor.segment_base)
            .checked_add(segment)
            .expect("validated dispatch segment index");
        let current = data.segments[segment_index];
        let next_segment = segment_index
            .checked_add(1)
            .expect("validated dispatch next segment index");
        let next = data.segments[next_segment];
        let begin = plan_index(current.transition_base);
        let end = plan_index(next.transition_base);
        Some(OrderedEdgeSegment {
            transitions: &data.transitions[begin..end],
            tail_work: current.tail_work,
        })
    }

    pub(crate) const fn retained_bytes(&self) -> usize {
        self.0[0].retained_bytes
    }

    #[cfg(test)]
    pub(crate) fn admitted_rows(&self) -> usize {
        self.0[0].rows.iter().filter(|row| row.is_present()).count()
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
            retained_bytes: 0,
        });
    }

    let retained_bytes = automaton
        .roles
        .len()
        .checked_mul(size_of::<RowDescriptor>())?
        .checked_add(admitted_rows.checked_mul(BYTE_DOMAIN)?)?
        .checked_add(
            segments
                .checked_add(1)?
                .checked_mul(size_of::<SegmentDescriptor>())?,
        )?
        .checked_add(
            matching_edges.checked_mul(size_of::<PackedOrderedTransition>())?,
        )?
        .checked_add(size_of::<OrderedEdgeDispatchData>())?;
    if retained_bytes > MAX_RETAINED_BYTES
        || u32::try_from(admitted_rows).is_err()
        || u32::try_from(segments.checked_add(1)?).is_err()
        || u32::try_from(matching_edges).is_err()
    {
        return None;
    }
    Some(Shape {
        admitted_rows,
        segments,
        matching_edges,
        retained_bytes,
    })
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
    for representative in representatives.iter() {
        let mut matching = 0usize;
        for edge in row.clone() {
            if automaton.byte_starts[edge] <= representative
                && representative <= automaton.byte_ends[edge]
            {
                matching = matching.saturating_add(1);
            }
        }
        maximum_matching = maximum_matching.max(matching);
        matching_edges = matching_edges.saturating_add(matching);
    }
    RowShape {
        segments,
        matching_edges,
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
    use crate::{Automaton, CompileLimits, EdgeKind, RawPlan, StateRole};

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
        let targets = segment
            .transitions
            .iter()
            .map(|&transition| transition.target())
            .collect();
        let work = segment
            .transitions
            .iter()
            .map(|transition| u64::from(transition.work()))
            .sum::<u64>()
            .checked_add(u64::from(segment.tail_work))
            .unwrap();
        (targets, work)
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
        assert!(empty.transitions.is_empty());
        assert_eq!(empty.tail_work, u32::try_from(ranges.len()).unwrap());
    }

    #[test]
    fn packed_transition_preserves_maximum_target_and_work_encodings() {
        let packed = super::PackedOrderedTransition::new(u32::MAX, u32::MAX);
        assert_eq!(packed.target(), u32::MAX);
        assert_eq!(packed.work(), u32::MAX);
        assert_eq!(core::mem::size_of_val(&packed), core::mem::size_of::<u64>());
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
