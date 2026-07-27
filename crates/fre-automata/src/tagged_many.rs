//! Bounded owner-tagged quotient for ordered Build-Many value reduction.
//!
//! Each source pattern retains a distinct owner bit. States with the same
//! local ordered shape and zero-width rank share one physical state, while
//! edge shards retain the exact owners for which that edge exists. Projecting
//! the quotient through any one owner bit is therefore edge-order-isomorphic
//! to that source plan. Execution computes one endpoint per owner with two
//! compact outcome-map rows and retains only the source-ordered root outcome
//! for each input boundary.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    reason = "checked resource transactions keep their proof dimensions adjacent; remaining index arithmetic is guarded by validated CSR and fixed-capacity invariants"
)]

use core::{fmt, marker::PhantomData, mem::size_of};

use crate::{
    k0::zero_width_edge_enabled_with_line_terminator, plan::plan_index, Automaton, CompileError,
    CompileLimits, DirectReduceLimits, DirectReduceReport, DirectReduceTraceReport,
    DirectReduceValue, EdgeKind, ExecutionActual, ExecutionProspective, PatternOrdinal,
    PriorityMatch, RawPlan, ReduceError, StateRole,
};

/// Stable identity for the shared owner-tagged Build-Many implementation.
pub const TAGGED_MANY_ACCOUNTING_ID: &str = "fre.automata.tagged-many.v2";
const MAX_OWNERS: usize = 128;
const EMPTY_INDEX: u32 = u32::MAX;
/// Exact builder-owned allocation attempts for one published quotient.
pub const TAGGED_MANY_BUILD_ALLOCATION_ATTEMPTS: usize = 16;
const RUN_ALLOCATION_ATTEMPTS: usize = 7;
const SHARED_FRONTIER_RUN_ALLOCATION_ATTEMPTS: usize = 0;
const MAX_SIGNATURE_PROBES: usize = 64;
const MAX_SIGNATURE_CHAIN: usize = 256;

/// Hard construction limits checked before publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaggedManyBuildLimits {
    pub max_patterns: usize,
    pub max_source_states: usize,
    pub max_source_edges: usize,
    pub max_shared_states: usize,
    pub max_shared_edges: usize,
    pub max_owner_state_memberships: usize,
    pub max_owner_edge_memberships: usize,
    pub max_work: u64,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
    pub max_allocation_attempts: usize,
}

impl TaggedManyBuildLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_patterns: MAX_OWNERS,
            max_source_states: usize::MAX,
            max_source_edges: usize::MAX,
            max_shared_states: usize::MAX,
            max_shared_edges: usize::MAX,
            max_owner_state_memberships: usize::MAX,
            max_owner_edge_memberships: usize::MAX,
            max_work: u64::MAX,
            max_persistent_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
            max_allocation_attempts: usize::MAX,
        }
    }
}

impl Default for TaggedManyBuildLimits {
    fn default() -> Self {
        Self {
            max_patterns: MAX_OWNERS,
            max_source_states: 1_048_576,
            max_source_edges: 4_194_304,
            max_shared_states: 262_144,
            max_shared_edges: 1_048_576,
            max_owner_state_memberships: 1_048_576,
            max_owner_edge_memberships: 4_194_304,
            max_work: 4_000_000_000,
            max_persistent_bytes: 128 * 1_048_576,
            max_peak_bytes: 128 * 1_048_576,
            max_allocation_attempts: TAGGED_MANY_BUILD_ALLOCATION_ATTEMPTS,
        }
    }
}

/// Authenticated execution architecture selected while the tagged graph is
/// still inside its bounded construction transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TaggedManyExecutionClass {
    /// The general owner-tagged evaluator and its per-boundary outcome maps.
    Generic,
    /// One shared fixed-width byte-range chain evaluated as an ordered
    /// frontier. All owners project to this exact physical chain.
    SharedFrontierUniformRangeChain {
        depth: usize,
        byte_start: u8,
        byte_end: u8,
    },
}

/// Immutable dimensions of one owner-tagged quotient.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaggedManyStats {
    patterns: usize,
    source_states: usize,
    source_edges: usize,
    shared_states: usize,
    shared_edges: usize,
    owner_state_memberships: usize,
    owner_edge_memberships: usize,
    zero_width_edges: usize,
    consuming_edges: usize,
    maximum_zero_width_rank: u32,
    persistent_bytes: usize,
    execution_class: TaggedManyExecutionClass,
}

impl TaggedManyStats {
    #[must_use]
    pub const fn patterns(self) -> usize {
        self.patterns
    }

    #[must_use]
    pub const fn source_states(self) -> usize {
        self.source_states
    }

    #[must_use]
    pub const fn source_edges(self) -> usize {
        self.source_edges
    }

    #[must_use]
    pub const fn states(self) -> usize {
        self.shared_states
    }

    #[must_use]
    pub const fn edges(self) -> usize {
        self.shared_edges
    }

    #[must_use]
    pub const fn owner_state_memberships(self) -> usize {
        self.owner_state_memberships
    }

    #[must_use]
    pub const fn owner_edge_memberships(self) -> usize {
        self.owner_edge_memberships
    }

    #[must_use]
    pub const fn zero_width_edges(self) -> usize {
        self.zero_width_edges
    }

    #[must_use]
    pub const fn consuming_edges(self) -> usize {
        self.consuming_edges
    }

    #[must_use]
    pub const fn maximum_zero_width_rank(self) -> u32 {
        self.maximum_zero_width_rank
    }

    #[must_use]
    pub const fn persistent_bytes(self) -> usize {
        self.persistent_bytes
    }

    #[must_use]
    pub const fn execution_class(self) -> TaggedManyExecutionClass {
        self.execution_class
    }
}

/// Exact successful quotient construction ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaggedManyBuildAccounting {
    pub accounting_id: &'static str,
    pub prospective_work: u64,
    pub actual_work: u64,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
    pub allocation_attempts: usize,
    pub signature_probes: usize,
    pub signature_full_comparisons: usize,
    pub projection_checks: usize,
    pub projection_edge_visits: usize,
    /// Conservative owner/state/edge classification work admitted before
    /// construction starts.
    pub classification_work_upper_bound: u64,
    /// Exact classification work charged before this receipt is frozen.
    pub classification_work: u64,
    pub classification_owner_checks: usize,
    pub classification_state_checks: usize,
    pub classification_edge_checks: usize,
}

impl TaggedManyBuildAccounting {
    #[must_use]
    pub fn closes(self, limits: TaggedManyBuildLimits) -> bool {
        self.accounting_id == TAGGED_MANY_ACCOUNTING_ID
            && self.actual_work <= self.prospective_work
            && self.actual_work <= limits.max_work
            && self.prospective_work <= limits.max_work
            && self.persistent_bytes <= limits.max_persistent_bytes
            && self.peak_bytes <= limits.max_peak_bytes
            && self.allocation_attempts == TAGGED_MANY_BUILD_ALLOCATION_ATTEMPTS
            && self.allocation_attempts <= limits.max_allocation_attempts
            && self.classification_work <= self.classification_work_upper_bound
            && self.classification_work <= self.actual_work
            && self.classification_work_upper_bound <= self.prospective_work
            && u64::try_from(self.classification_owner_checks)
                .ok()
                .and_then(|owners| {
                    u64::try_from(self.classification_state_checks)
                        .ok()
                        .and_then(|states| owners.checked_add(states))
                })
                .and_then(|checks| {
                    u64::try_from(self.classification_edge_checks)
                        .ok()
                        .and_then(|edges| checks.checked_add(edges))
                })
                .and_then(|checks| checks.checked_add(2))
                == Some(self.classification_work)
            && self.classification_owner_checks <= limits.max_patterns
            && self.classification_state_checks <= limits.max_shared_states
            && self.classification_edge_checks <= limits.max_shared_edges
    }
}

/// Typed terminal construction refusal. No partially built plan is returned.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TaggedManyBuildError {
    EmptyPatternSet,
    PatternLimit {
        needed: usize,
        limit: usize,
    },
    SourceStatesLimit {
        needed: usize,
        limit: usize,
    },
    SourceEdgesLimit {
        needed: usize,
        limit: usize,
    },
    SharedStatesLimit {
        needed: usize,
        limit: usize,
    },
    SharedEdgesLimit {
        needed: usize,
        limit: usize,
    },
    OwnerStateMembershipLimit {
        needed: usize,
        limit: usize,
    },
    OwnerEdgeMembershipLimit {
        needed: usize,
        limit: usize,
    },
    WorkLimit {
        needed: u64,
        limit: u64,
    },
    PersistentLimit {
        needed: usize,
        limit: usize,
    },
    PeakLimit {
        needed: usize,
        limit: usize,
    },
    AllocationAttemptsLimit {
        needed: usize,
        limit: usize,
    },
    SourceCompile {
        pattern: usize,
        source: CompileError,
    },
    NonExactSourceCollectionCapacity {
        length: usize,
        capacity: usize,
    },
    NonExactSourceCapacity {
        pattern: usize,
        table: &'static str,
        length: usize,
        capacity: usize,
    },
    MalformedSourceShape {
        pattern: usize,
        table: &'static str,
        expected: usize,
        actual: usize,
    },
    ZeroWidthCycle {
        pattern: usize,
    },
    InvalidAcceptTerminalCount {
        pattern: usize,
        terminals: usize,
    },
    ProjectionMismatch {
        pattern: usize,
        state: usize,
        edge: Option<usize>,
    },
    SignatureCollisionLimit {
        probes: usize,
        chain: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    AllocationFailed {
        structure: &'static str,
        entries: usize,
    },
    InternalInvariant {
        detail: &'static str,
    },
}

impl fmt::Display for TaggedManyBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPatternSet => formatter.write_str("tagged Build-Many requires a pattern"),
            Self::PatternLimit { needed, limit } => {
                write!(formatter, "tagged Build-Many needs {needed} patterns, limit is {limit}")
            }
            Self::SourceStatesLimit { needed, limit } => write!(
                formatter,
                "tagged Build-Many needs {needed} source states, limit is {limit}"
            ),
            Self::SourceEdgesLimit { needed, limit } => write!(
                formatter,
                "tagged Build-Many needs {needed} source edges, limit is {limit}"
            ),
            Self::SharedStatesLimit { needed, limit } => write!(
                formatter,
                "tagged Build-Many needs {needed} shared states, limit is {limit}"
            ),
            Self::SharedEdgesLimit { needed, limit } => write!(
                formatter,
                "tagged Build-Many needs {needed} shared edges, limit is {limit}"
            ),
            Self::OwnerStateMembershipLimit { needed, limit } => write!(
                formatter,
                "tagged Build-Many needs {needed} owner-state memberships, limit is {limit}"
            ),
            Self::OwnerEdgeMembershipLimit { needed, limit } => write!(
                formatter,
                "tagged Build-Many needs {needed} owner-edge memberships, limit is {limit}"
            ),
            Self::WorkLimit { needed, limit } => {
                write!(formatter, "tagged Build-Many needs {needed} work, limit is {limit}")
            }
            Self::PersistentLimit { needed, limit } => write!(
                formatter,
                "tagged Build-Many retains {needed} bytes, limit is {limit}"
            ),
            Self::PeakLimit { needed, limit } => {
                write!(formatter, "tagged Build-Many peaks at {needed} bytes, limit is {limit}")
            }
            Self::AllocationAttemptsLimit { needed, limit } => write!(
                formatter,
                "tagged Build-Many needs {needed} allocations, limit is {limit}"
            ),
            Self::SourceCompile { pattern, source } => {
                write!(formatter, "tagged Build-Many pattern {pattern}: {source}")
            }
            Self::NonExactSourceCollectionCapacity { length, capacity } => write!(
                formatter,
                "tagged Build-Many source collection has length {length} but capacity {capacity}"
            ),
            Self::NonExactSourceCapacity {
                pattern,
                table,
                length,
                capacity,
            } => write!(
                formatter,
                "tagged Build-Many pattern {pattern} {table} has length {length} but capacity {capacity}"
            ),
            Self::MalformedSourceShape {
                pattern,
                table,
                expected,
                actual,
            } => write!(
                formatter,
                "tagged Build-Many pattern {pattern} {table} has length {actual}, expected {expected}"
            ),
            Self::ZeroWidthCycle { pattern } => write!(
                formatter,
                "tagged Build-Many pattern {pattern} has a zero-width cycle"
            ),
            Self::InvalidAcceptTerminalCount { pattern, terminals } => write!(
                formatter,
                "tagged Build-Many pattern {pattern} has {terminals} accept terminals"
            ),
            Self::ProjectionMismatch {
                pattern,
                state,
                edge,
            } => write!(
                formatter,
                "tagged Build-Many projection mismatch at pattern {pattern}, state {state}, edge {edge:?}"
            ),
            Self::SignatureCollisionLimit { probes, chain } => write!(
                formatter,
                "tagged Build-Many signature interner exceeded {probes} probes or {chain} full-collision entries"
            ),
            Self::ArithmeticOverflow { computation } => {
                write!(formatter, "tagged Build-Many overflow computing {computation}")
            }
            Self::AllocationFailed { structure, entries } => write!(
                formatter,
                "tagged Build-Many could not reserve {entries} entries for {structure}"
            ),
            Self::InternalInvariant { detail } => {
                write!(formatter, "tagged Build-Many invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for TaggedManyBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SourceCompile { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TaggedState {
    role: StateRole,
    owners: u128,
    start_owners: u128,
    edge_start: u32,
    edge_end: u32,
    zero_width_rank: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TaggedEdge {
    target: u32,
    owners: u128,
    kind: EdgeKind,
    byte_start: u8,
    byte_end: u8,
    priority_slot: u32,
}

#[derive(Clone, Copy, Debug)]
struct GroupBuilder {
    role: StateRole,
    rank: u32,
    owners: u128,
    representative_owner: u8,
    representative_state: u32,
    lane_head: u32,
    signature_next: u32,
}

#[derive(Clone, Copy, Debug)]
struct Lane {
    owner: u8,
    state: u32,
    next: u32,
}

#[derive(Clone, Copy, Debug)]
struct SignatureSlot {
    hash: u64,
    head: u32,
}

impl SignatureSlot {
    const EMPTY: Self = Self {
        hash: 0,
        head: EMPTY_INDEX,
    };
}

/// Immutable shared plan with one statically selected direct reducer.
#[derive(Clone, Debug)]
pub struct TaggedManyPlan<O: DirectReduceValue> {
    states: Box<[TaggedState]>,
    edges: Box<[TaggedEdge]>,
    starts: Box<[u32]>,
    evaluation_order: Box<[u32]>,
    line_terminator: u8,
    stats: TaggedManyStats,
    accounting: TaggedManyBuildAccounting,
    operation: PhantomData<O>,
}

struct BuildMeter {
    limit: u64,
    consumed: u64,
    signature_probes: usize,
    signature_full_comparisons: usize,
    projection_checks: usize,
    projection_edge_visits: usize,
    classification_owner_checks: usize,
    classification_state_checks: usize,
    classification_edge_checks: usize,
}

impl BuildMeter {
    const fn new(limit: u64) -> Self {
        Self {
            limit,
            consumed: 0,
            signature_probes: 0,
            signature_full_comparisons: 0,
            projection_checks: 0,
            projection_edge_visits: 0,
            classification_owner_checks: 0,
            classification_state_checks: 0,
            classification_edge_checks: 0,
        }
    }

    fn charge(&mut self, requested: u64) -> Result<(), TaggedManyBuildError> {
        let needed = self.consumed.checked_add(requested).ok_or(
            TaggedManyBuildError::ArithmeticOverflow {
                computation: "tagged construction work",
            },
        )?;
        if needed > self.limit {
            return Err(TaggedManyBuildError::WorkLimit {
                needed,
                limit: self.limit,
            });
        }
        self.consumed = needed;
        Ok(())
    }

    fn charge_usize(&mut self, requested: usize) -> Result<(), TaggedManyBuildError> {
        self.charge(u64::try_from(requested).map_err(|_| {
            TaggedManyBuildError::ArithmeticOverflow {
                computation: "tagged construction work conversion",
            }
        })?)
    }
}

impl<O: DirectReduceValue> TaggedManyPlan<O> {
    /// Validate independent source plans, quotient their owner-tagged local
    /// shapes, prove every owner projection, and publish one immutable plan.
    pub fn from_raw(
        raw_plans: Vec<RawPlan>,
        line_terminator: u8,
        compile_limits: CompileLimits,
        limits: TaggedManyBuildLimits,
    ) -> Result<Self, TaggedManyBuildError> {
        let patterns = raw_plans.len();
        if patterns == 0 {
            return Err(TaggedManyBuildError::EmptyPatternSet);
        }
        if raw_plans.capacity() != patterns {
            return Err(TaggedManyBuildError::NonExactSourceCollectionCapacity {
                length: patterns,
                capacity: raw_plans.capacity(),
            });
        }
        enforce_build(patterns, limits.max_patterns, |needed, limit| {
            TaggedManyBuildError::PatternLimit { needed, limit }
        })?;
        enforce_build(patterns, MAX_OWNERS, |needed, limit| {
            TaggedManyBuildError::PatternLimit { needed, limit }
        })?;
        enforce_build(
            TAGGED_MANY_BUILD_ALLOCATION_ATTEMPTS,
            limits.max_allocation_attempts,
            |needed, limit| TaggedManyBuildError::AllocationAttemptsLimit { needed, limit },
        )?;

        let mut source_states = 0usize;
        let mut source_edges = 0usize;
        let mut source_storage_bytes = 0usize;
        let mut source_validation_work = 0u64;
        let mut maximum_degree = 0usize;
        let mut source_zero_width_edges = 0usize;
        for (pattern, raw) in raw_plans.iter().enumerate() {
            for (table, length, capacity) in [
                ("roles", raw.roles.len(), raw.roles.capacity()),
                (
                    "edge offsets",
                    raw.edge_offsets.len(),
                    raw.edge_offsets.capacity(),
                ),
                (
                    "edge targets",
                    raw.edge_targets.len(),
                    raw.edge_targets.capacity(),
                ),
                (
                    "edge kinds",
                    raw.edge_kinds.len(),
                    raw.edge_kinds.capacity(),
                ),
                (
                    "byte starts",
                    raw.byte_starts.len(),
                    raw.byte_starts.capacity(),
                ),
                ("byte ends", raw.byte_ends.len(), raw.byte_ends.capacity()),
            ] {
                if length != capacity {
                    return Err(TaggedManyBuildError::NonExactSourceCapacity {
                        pattern,
                        table,
                        length,
                        capacity,
                    });
                }
            }
            let offset_entries =
                raw.roles
                    .len()
                    .checked_add(1)
                    .ok_or(TaggedManyBuildError::ArithmeticOverflow {
                        computation: "tagged source offset shape",
                    })?;
            for (table, expected, actual) in [
                ("edge offsets", offset_entries, raw.edge_offsets.len()),
                ("edge kinds", raw.edge_targets.len(), raw.edge_kinds.len()),
                ("byte starts", raw.edge_targets.len(), raw.byte_starts.len()),
                ("byte ends", raw.edge_targets.len(), raw.byte_ends.len()),
            ] {
                if actual != expected {
                    return Err(TaggedManyBuildError::MalformedSourceShape {
                        pattern,
                        table,
                        expected,
                        actual,
                    });
                }
            }
            source_states = checked_add(source_states, raw.roles.len(), "tagged source state sum")?;
            source_edges = checked_add(
                source_edges,
                raw.edge_targets.len(),
                "tagged source edge sum",
            )?;
            source_storage_bytes = checked_add(
                source_storage_bytes,
                raw_capacity_bytes(raw)?,
                "tagged source storage sum",
            )?;
            source_validation_work = source_validation_work
                .checked_add(raw_validation_work(
                    raw.roles.len(),
                    raw.edge_targets.len(),
                )?)
                .ok_or(TaggedManyBuildError::ArithmeticOverflow {
                    computation: "tagged source validation work",
                })?;
        }
        enforce_build(source_states, limits.max_source_states, |needed, limit| {
            TaggedManyBuildError::SourceStatesLimit { needed, limit }
        })?;
        enforce_build(source_edges, limits.max_source_edges, |needed, limit| {
            TaggedManyBuildError::SourceEdgesLimit { needed, limit }
        })?;
        enforce_build(
            source_states,
            limits.max_owner_state_memberships,
            |needed, limit| TaggedManyBuildError::OwnerStateMembershipLimit { needed, limit },
        )?;
        enforce_build(
            source_edges,
            limits.max_owner_edge_memberships,
            |needed, limit| TaggedManyBuildError::OwnerEdgeMembershipLimit { needed, limit },
        )?;
        if source_validation_work > limits.max_work {
            return Err(TaggedManyBuildError::WorkLimit {
                needed: source_validation_work,
                limit: limits.max_work,
            });
        }
        let mut meter = BuildMeter::new(limits.max_work);
        meter.charge(source_validation_work)?;
        for raw in &raw_plans {
            source_zero_width_edges = checked_add(
                source_zero_width_edges,
                raw.edge_kinds
                    .iter()
                    .filter(|kind| kind.is_zero_width())
                    .count(),
                "tagged source zero-width edge sum",
            )?;
            for offsets in raw.edge_offsets.windows(2) {
                let begin = usize::try_from(offsets[0]).map_err(|_| {
                    TaggedManyBuildError::ArithmeticOverflow {
                        computation: "tagged raw edge begin",
                    }
                })?;
                let end = usize::try_from(offsets[1]).map_err(|_| {
                    TaggedManyBuildError::ArithmeticOverflow {
                        computation: "tagged raw edge end",
                    }
                })?;
                maximum_degree = maximum_degree.max(end.saturating_sub(begin));
            }
        }
        let signature_capacity = signature_table_capacity(source_states)?;
        let classification_work_upper_bound =
            prospective_classification_work(patterns, source_states, source_edges)?;
        let prospective_work = prospective_build_work(
            patterns,
            source_states,
            source_edges,
            maximum_degree,
            signature_capacity,
            source_validation_work,
            classification_work_upper_bound,
        )?;
        if prospective_work > limits.max_work {
            return Err(TaggedManyBuildError::WorkLimit {
                needed: prospective_work,
                limit: limits.max_work,
            });
        }
        let build_scratch = build_scratch_bytes(
            patterns,
            source_states,
            source_zero_width_edges,
            signature_capacity,
        )?;
        let input_descriptors = patterns.checked_mul(size_of::<RawPlan>()).ok_or(
            TaggedManyBuildError::ArithmeticOverflow {
                computation: "tagged input descriptor bytes",
            },
        )?;
        let validation_peak = source_storage_bytes
            .checked_add(input_descriptors)
            .and_then(|bytes| {
                patterns
                    .checked_mul(size_of::<Automaton>())
                    .and_then(|descriptors| bytes.checked_add(descriptors))
            })
            .and_then(|bytes| {
                patterns
                    .checked_add(1)
                    .and_then(|entries| entries.checked_mul(size_of::<usize>()))
                    .and_then(|bases| bytes.checked_add(bases))
            })
            .ok_or(TaggedManyBuildError::ArithmeticOverflow {
                computation: "tagged validation peak",
            })?;
        let unavoidable_peak = source_storage_bytes.checked_add(build_scratch).ok_or(
            TaggedManyBuildError::ArithmeticOverflow {
                computation: "tagged construction unavoidable peak",
            },
        )?;
        let prepublication_peak = unavoidable_peak.max(validation_peak);
        if prepublication_peak > limits.max_peak_bytes {
            return Err(TaggedManyBuildError::PeakLimit {
                needed: prepublication_peak,
                limit: limits.max_peak_bytes,
            });
        }
        let mut automata = reserve_build(patterns, "validated source automata")?;
        let mut bases = reserve_build(
            patterns
                .checked_add(1)
                .ok_or(TaggedManyBuildError::ArithmeticOverflow {
                    computation: "tagged owner base entries",
                })?,
            "owner state bases",
        )?;
        bases.push(0usize);
        let mut running_base = 0usize;
        for (pattern, raw) in raw_plans.into_iter().enumerate() {
            let automaton = Automaton::from_raw(raw, compile_limits)
                .map_err(|source| TaggedManyBuildError::SourceCompile { pattern, source })?
                .with_line_terminator(line_terminator);
            let terminals = automaton
                .roles
                .iter()
                .filter(|&&role| role == StateRole::Accept)
                .count();
            if terminals != 1 {
                return Err(TaggedManyBuildError::InvalidAcceptTerminalCount {
                    pattern,
                    terminals,
                });
            }
            running_base = checked_add(
                running_base,
                automaton.stats().states(),
                "tagged owner state base",
            )?;
            automata.push(automaton);
            bases.push(running_base);
        }
        if running_base != source_states {
            return Err(TaggedManyBuildError::InternalInvariant {
                detail: "validated source state sum changed",
            });
        }

        let mut ranks = reserve_and_fill(source_states, 0u32, "zero-width ranks")?;
        let mut reverse_counts =
            reserve_and_fill(source_states, 0usize, "zero-width reverse counts")?;
        let mut reverse_offsets = reserve_and_fill(
            source_states
                .checked_add(1)
                .ok_or(TaggedManyBuildError::ArithmeticOverflow {
                    computation: "zero-width reverse offsets",
                })?,
            0usize,
            "zero-width reverse offsets",
        )?;
        let zero_width_edges =
            count_zero_width_edges(&automata, &bases, &mut reverse_counts, &mut meter)?;
        if zero_width_edges != source_zero_width_edges {
            return Err(TaggedManyBuildError::InternalInvariant {
                detail: "validated zero-width edge census changed",
            });
        }
        let mut reverse_parents =
            reserve_and_fill(zero_width_edges, 0u32, "zero-width reverse parents")?;
        let mut remaining = reserve_and_fill(source_states, 0usize, "zero-width remaining")?;
        let mut queue = reserve_build(source_states, "zero-width rank queue")?;
        derive_zero_width_ranks(
            &automata,
            &bases,
            &mut ranks,
            &reverse_counts,
            &mut reverse_offsets,
            &mut reverse_parents,
            &mut remaining,
            &mut queue,
            &mut meter,
        )?;

        let mut mapping = reserve_and_fill(source_states, EMPTY_INDEX, "owner-state mapping")?;
        let mut groups = reserve_build(source_states, "tagged state groups")?;
        let mut lanes = reserve_build(source_states, "tagged state lanes")?;
        let mut signatures =
            reserve_and_fill(signature_capacity, SignatureSlot::EMPTY, "signature table")?;
        build_state_groups(
            &automata,
            &bases,
            &ranks,
            &mut mapping,
            &mut groups,
            &mut lanes,
            &mut signatures,
            &mut meter,
        )?;
        let shared_states = groups.len();
        enforce_build(shared_states, limits.max_shared_states, |needed, limit| {
            TaggedManyBuildError::SharedStatesLimit { needed, limit }
        })?;

        let shared_edges =
            count_shared_edges(&automata, &bases, &mapping, &groups, &lanes, &mut meter)?;
        enforce_build(shared_edges, limits.max_shared_edges, |needed, limit| {
            TaggedManyBuildError::SharedEdgesLimit { needed, limit }
        })?;
        let persistent = persistent_bytes(shared_states, shared_edges, patterns, shared_states)?;
        if persistent > limits.max_persistent_bytes {
            return Err(TaggedManyBuildError::PersistentLimit {
                needed: persistent,
                limit: limits.max_persistent_bytes,
            });
        }
        let construction_peak = unavoidable_peak.checked_add(persistent).ok_or(
            TaggedManyBuildError::ArithmeticOverflow {
                computation: "tagged construction exact peak",
            },
        )?;
        let peak = construction_peak.max(validation_peak);
        if peak > limits.max_peak_bytes {
            return Err(TaggedManyBuildError::PeakLimit {
                needed: peak,
                limit: limits.max_peak_bytes,
            });
        }
        let mut edges = reserve_build(shared_edges, "tagged edge shards")?;
        let mut states = reserve_build(shared_states, "tagged states")?;
        fill_shared_graph(
            &automata,
            &bases,
            &mapping,
            &groups,
            &lanes,
            &mut states,
            &mut edges,
            &mut meter,
        )?;
        let mut starts = reserve_build(patterns, "tagged owner starts")?;
        for (owner, automaton) in automata.iter().enumerate() {
            meter.charge(2)?;
            let index = checked_add(
                bases[owner],
                plan_index(automaton.start),
                "tagged owner start index",
            )?;
            let start = mapping[index];
            states[plan_index(start)].start_owners |= 1u128 << owner;
            starts.push(start);
        }
        meter.charge_usize(ranks.len())?;
        let maximum_zero_width_rank = ranks.iter().copied().max().unwrap_or(0);
        let evaluation_order = build_evaluation_order(
            &groups,
            maximum_zero_width_rank,
            &mut reverse_counts,
            &mut reverse_offsets,
            &mut meter,
        )?;
        if evaluation_order.len() != shared_states {
            return Err(TaggedManyBuildError::InternalInvariant {
                detail: "tagged evaluation order omitted a state",
            });
        }
        validate_projection(&automata, &bases, &mapping, &states, &edges, &mut meter)?;

        meter.charge_usize(edges.len())?;
        let zero_width_shared = edges
            .iter()
            .filter(|edge| edge.kind.is_zero_width())
            .count();
        let consuming_shared = edges.len().saturating_sub(zero_width_shared);
        let classification_start = meter.consumed;
        let execution_class = classify_execution(&states, &edges, &starts, &mut meter)?;
        let classification_work = meter.consumed.checked_sub(classification_start).ok_or(
            TaggedManyBuildError::InternalInvariant {
                detail: "tagged classification work moved backwards",
            },
        )?;
        if classification_work > classification_work_upper_bound
            || meter.consumed > prospective_work
        {
            return Err(TaggedManyBuildError::InternalInvariant {
                detail: "tagged construction exceeded its prospective work",
            });
        }
        if persistent
            != persistent_bytes(
                states.len(),
                edges.len(),
                starts.len(),
                evaluation_order.len(),
            )?
        {
            return Err(TaggedManyBuildError::InternalInvariant {
                detail: "tagged persistent census changed after prepublication admission",
            });
        }
        let plan_stats = TaggedManyStats {
            patterns,
            source_states,
            source_edges,
            shared_states,
            shared_edges,
            owner_state_memberships: source_states,
            owner_edge_memberships: source_edges,
            zero_width_edges: zero_width_shared,
            consuming_edges: consuming_shared,
            maximum_zero_width_rank,
            persistent_bytes: persistent,
            execution_class,
        };
        let accounting = TaggedManyBuildAccounting {
            accounting_id: TAGGED_MANY_ACCOUNTING_ID,
            prospective_work,
            actual_work: meter.consumed,
            persistent_bytes: persistent,
            peak_bytes: peak,
            allocation_attempts: TAGGED_MANY_BUILD_ALLOCATION_ATTEMPTS,
            signature_probes: meter.signature_probes,
            signature_full_comparisons: meter.signature_full_comparisons,
            projection_checks: meter.projection_checks,
            projection_edge_visits: meter.projection_edge_visits,
            classification_work_upper_bound,
            classification_work,
            classification_owner_checks: meter.classification_owner_checks,
            classification_state_checks: meter.classification_state_checks,
            classification_edge_checks: meter.classification_edge_checks,
        };
        let projection_edge_bound =
            source_edges
                .checked_mul(patterns)
                .ok_or(TaggedManyBuildError::ArithmeticOverflow {
                    computation: "tagged projection edge visit bound",
                })?;
        if accounting.projection_checks != source_states
            || accounting.projection_edge_visits > projection_edge_bound
            || accounting.classification_work_upper_bound
                != prospective_classification_work(patterns, source_states, source_edges)?
            || !accounting.closes(limits)
        {
            return Err(TaggedManyBuildError::InternalInvariant {
                detail: "tagged construction receipt did not close",
            });
        }
        Ok(Self {
            states: states.into_boxed_slice(),
            edges: edges.into_boxed_slice(),
            starts: starts.into_boxed_slice(),
            evaluation_order: evaluation_order.into_boxed_slice(),
            line_terminator,
            stats: plan_stats,
            accounting,
            operation: PhantomData,
        })
    }

    #[must_use]
    pub const fn stats(&self) -> TaggedManyStats {
        self.stats
    }

    #[must_use]
    pub const fn build_accounting(&self) -> TaggedManyBuildAccounting {
        self.accounting
    }
}

fn classify_execution(
    states: &[TaggedState],
    edges: &[TaggedEdge],
    starts: &[u32],
    meter: &mut BuildMeter,
) -> Result<TaggedManyExecutionClass, TaggedManyBuildError> {
    fn publish(
        meter: &mut BuildMeter,
        class: TaggedManyExecutionClass,
    ) -> Result<TaggedManyExecutionClass, TaggedManyBuildError> {
        meter.charge(1)?;
        Ok(class)
    }

    meter.charge(1)?;
    let depth = edges.len();
    if depth == 0 || depth.checked_add(1) != Some(states.len()) || starts.is_empty() {
        return publish(meter, TaggedManyExecutionClass::Generic);
    }
    let owner_mask = if starts.len() == MAX_OWNERS {
        u128::MAX
    } else {
        (1u128 << starts.len()) - 1
    };
    for start in starts {
        meter.charge(1)?;
        meter.classification_owner_checks = checked_add(
            meter.classification_owner_checks,
            1,
            "tagged classification owner checks",
        )?;
        // The iterator yields only a reference; dereference the owner record
        // after its inspection charge has succeeded.
        if *start != 0 {
            return publish(meter, TaggedManyExecutionClass::Generic);
        }
    }
    let mut byte_range = None;
    for index in 0..states.len() {
        meter.charge(1)?;
        meter.classification_state_checks = checked_add(
            meter.classification_state_checks,
            1,
            "tagged classification state checks",
        )?;
        let state = &states[index];
        if index == depth {
            if state.role != StateRole::Accept
                || state.owners != owner_mask
                || state.start_owners != 0
                || plan_index(state.edge_start) != depth
                || state.edge_start != state.edge_end
            {
                return publish(meter, TaggedManyExecutionClass::Generic);
            }
            continue;
        }
        if state.role != StateRole::Consume
            || state.owners != owner_mask
            || state.start_owners != if index == 0 { owner_mask } else { 0 }
            || plan_index(state.edge_start) != index
            || index.checked_add(1).and_then(|end| u32::try_from(end).ok()) != Some(state.edge_end)
        {
            return publish(meter, TaggedManyExecutionClass::Generic);
        }
        meter.charge(1)?;
        meter.classification_edge_checks = checked_add(
            meter.classification_edge_checks,
            1,
            "tagged classification edge checks",
        )?;
        let edge = edges[index];
        if edge.target
            != index
                .checked_add(1)
                .and_then(|target| u32::try_from(target).ok())
                .ok_or(TaggedManyBuildError::ArithmeticOverflow {
                    computation: "tagged classification edge target",
                })?
            || edge.owners != owner_mask
            || edge.kind != EdgeKind::ByteRange
            || edge.priority_slot != 0
        {
            return publish(meter, TaggedManyExecutionClass::Generic);
        }
        match byte_range {
            None if edge.byte_start < edge.byte_end => {
                byte_range = Some((edge.byte_start, edge.byte_end));
            }
            Some((byte_start, byte_end))
                if edge.byte_start == byte_start && edge.byte_end == byte_end => {}
            _ => return publish(meter, TaggedManyExecutionClass::Generic),
        }
    }
    let (byte_start, byte_end) = byte_range.ok_or(TaggedManyBuildError::InternalInvariant {
        detail: "nonempty tagged chain lost its byte range",
    })?;
    publish(
        meter,
        TaggedManyExecutionClass::SharedFrontierUniformRangeChain {
            depth,
            byte_start,
            byte_end,
        },
    )
}

fn enforce_build(
    needed: usize,
    limit: usize,
    error: impl FnOnce(usize, usize) -> TaggedManyBuildError,
) -> Result<(), TaggedManyBuildError> {
    if needed > limit {
        Err(error(needed, limit))
    } else {
        Ok(())
    }
}

fn checked_add(
    left: usize,
    right: usize,
    computation: &'static str,
) -> Result<usize, TaggedManyBuildError> {
    left.checked_add(right)
        .ok_or(TaggedManyBuildError::ArithmeticOverflow { computation })
}

fn checked_mul(
    left: usize,
    right: usize,
    computation: &'static str,
) -> Result<usize, TaggedManyBuildError> {
    left.checked_mul(right)
        .ok_or(TaggedManyBuildError::ArithmeticOverflow { computation })
}

fn reserve_build<T>(
    entries: usize,
    structure: &'static str,
) -> Result<Vec<T>, TaggedManyBuildError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(entries)
        .map_err(|_| TaggedManyBuildError::AllocationFailed { structure, entries })?;
    if values.capacity() != entries {
        return Err(TaggedManyBuildError::AllocationFailed {
            structure,
            entries: values.capacity(),
        });
    }
    Ok(values)
}

fn reserve_and_fill<T: Clone>(
    entries: usize,
    value: T,
    structure: &'static str,
) -> Result<Vec<T>, TaggedManyBuildError> {
    let mut values = reserve_build(entries, structure)?;
    values.resize(entries, value);
    Ok(values)
}

fn signature_table_capacity(states: usize) -> Result<usize, TaggedManyBuildError> {
    states
        .checked_add(1)
        .and_then(|value| value.checked_mul(2))
        .and_then(usize::checked_next_power_of_two)
        .ok_or(TaggedManyBuildError::ArithmeticOverflow {
            computation: "tagged signature table capacity",
        })
}

fn raw_validation_work(states: usize, edges: usize) -> Result<u64, TaggedManyBuildError> {
    let states = u64::try_from(states).map_err(|_| TaggedManyBuildError::ArithmeticOverflow {
        computation: "tagged validation state work",
    })?;
    let edges = u64::try_from(edges).map_err(|_| TaggedManyBuildError::ArithmeticOverflow {
        computation: "tagged validation edge work",
    })?;
    states
        .checked_mul(4)
        .and_then(|work| edges.checked_mul(4).and_then(|tail| work.checked_add(tail)))
        .and_then(|work| work.checked_add(4))
        .ok_or(TaggedManyBuildError::ArithmeticOverflow {
            computation: "tagged validation work",
        })
}

fn prospective_classification_work(
    patterns: usize,
    source_states: usize,
    source_edges: usize,
) -> Result<u64, TaggedManyBuildError> {
    u64::try_from(patterns)
        .ok()
        .and_then(|owners| {
            u64::try_from(source_states)
                .ok()
                .and_then(|states| owners.checked_add(states))
        })
        .and_then(|checks| {
            u64::try_from(source_edges)
                .ok()
                .and_then(|edges| checks.checked_add(edges))
        })
        // One shape check and one authenticated class publication.
        .and_then(|checks| checks.checked_add(2))
        .ok_or(TaggedManyBuildError::ArithmeticOverflow {
            computation: "tagged prospective classification work",
        })
}

fn prospective_build_work(
    patterns: usize,
    states: usize,
    edges: usize,
    maximum_degree: usize,
    signature_capacity: usize,
    validation_work: u64,
    classification_work: u64,
) -> Result<u64, TaggedManyBuildError> {
    let patterns =
        u64::try_from(patterns).map_err(|_| TaggedManyBuildError::ArithmeticOverflow {
            computation: "tagged prospective pattern work",
        })?;
    let states = u64::try_from(states).map_err(|_| TaggedManyBuildError::ArithmeticOverflow {
        computation: "tagged prospective state work",
    })?;
    let edges = u64::try_from(edges).map_err(|_| TaggedManyBuildError::ArithmeticOverflow {
        computation: "tagged prospective edge work",
    })?;
    let degree =
        u64::try_from(maximum_degree).map_err(|_| TaggedManyBuildError::ArithmeticOverflow {
            computation: "tagged prospective degree work",
        })?;
    let signatures = u64::try_from(signature_capacity).map_err(|_| {
        TaggedManyBuildError::ArithmeticOverflow {
            computation: "tagged prospective signature work",
        }
    })?;
    let owner_cap = patterns.min(u64::try_from(MAX_OWNERS).unwrap_or(u64::MAX));
    let grouping_per_state = u64::try_from(MAX_SIGNATURE_PROBES)
        .ok()
        .and_then(|probes| {
            u64::try_from(MAX_SIGNATURE_CHAIN).ok().and_then(|chain| {
                degree
                    .checked_mul(8)
                    .and_then(|value| value.checked_add(24))
                    .and_then(|compare| chain.checked_mul(compare))
                    .and_then(|compare| probes.checked_add(compare))
            })
        })
        .ok_or(TaggedManyBuildError::ArithmeticOverflow {
            computation: "tagged prospective grouping work",
        })?;
    let grouping =
        states
            .checked_mul(grouping_per_state)
            .ok_or(TaggedManyBuildError::ArithmeticOverflow {
                computation: "tagged prospective total grouping work",
            })?;
    let rank = states
        .checked_add(edges)
        .and_then(|value| value.checked_mul(32))
        .ok_or(TaggedManyBuildError::ArithmeticOverflow {
            computation: "tagged prospective rank work",
        })?;
    let edge_passes = edges
        .checked_mul(
            owner_cap
                .checked_mul(8)
                .and_then(|v| v.checked_add(32))
                .ok_or(TaggedManyBuildError::ArithmeticOverflow {
                    computation: "tagged prospective edge factor",
                })?,
        )
        .and_then(|value| value.checked_mul(3))
        .ok_or(TaggedManyBuildError::ArithmeticOverflow {
            computation: "tagged prospective edge work",
        })?;
    let evaluation_order = states
        .checked_mul(5)
        .and_then(|value| value.checked_add(2))
        .ok_or(TaggedManyBuildError::ArithmeticOverflow {
            computation: "tagged prospective evaluation order",
        })?;
    validation_work
        .checked_add(rank)
        .and_then(|value| value.checked_add(grouping))
        .and_then(|value| value.checked_add(edge_passes))
        .and_then(|value| value.checked_add(evaluation_order))
        .and_then(|value| value.checked_add(signatures))
        .and_then(|value| value.checked_add(patterns.checked_mul(16)?))
        .and_then(|value| value.checked_add(classification_work))
        .and_then(|value| value.checked_add(1_024))
        .ok_or(TaggedManyBuildError::ArithmeticOverflow {
            computation: "tagged prospective construction work",
        })
}

fn raw_capacity_bytes(raw: &RawPlan) -> Result<usize, TaggedManyBuildError> {
    let mut total = checked_mul(
        raw.roles.capacity(),
        size_of::<StateRole>(),
        "tagged raw role bytes",
    )?;
    for bytes in [
        checked_mul(
            raw.edge_offsets.capacity(),
            size_of::<u32>(),
            "tagged raw offset bytes",
        )?,
        checked_mul(
            raw.edge_targets.capacity(),
            size_of::<u32>(),
            "tagged raw target bytes",
        )?,
        checked_mul(
            raw.edge_kinds.capacity(),
            size_of::<EdgeKind>(),
            "tagged raw kind bytes",
        )?,
        raw.byte_starts.capacity(),
        raw.byte_ends.capacity(),
    ] {
        total = checked_add(total, bytes, "tagged raw capacity bytes")?;
    }
    Ok(total)
}

fn build_scratch_bytes(
    patterns: usize,
    source_states: usize,
    zero_width_edges: usize,
    signature_capacity: usize,
) -> Result<usize, TaggedManyBuildError> {
    let mut total = checked_mul(
        patterns,
        size_of::<Automaton>(),
        "tagged automata descriptor bytes",
    )?;
    for bytes in [
        checked_mul(
            patterns
                .checked_add(1)
                .ok_or(TaggedManyBuildError::ArithmeticOverflow {
                    computation: "tagged base bytes",
                })?,
            size_of::<usize>(),
            "tagged base bytes",
        )?,
        checked_mul(source_states, size_of::<u32>(), "tagged rank bytes")?,
        checked_mul(
            source_states,
            size_of::<usize>(),
            "tagged reverse count bytes",
        )?,
        checked_mul(
            source_states
                .checked_add(1)
                .ok_or(TaggedManyBuildError::ArithmeticOverflow {
                    computation: "tagged reverse offset entries",
                })?,
            size_of::<usize>(),
            "tagged reverse offset bytes",
        )?,
        checked_mul(
            zero_width_edges,
            size_of::<u32>(),
            "tagged reverse parent bytes",
        )?,
        checked_mul(source_states, size_of::<usize>(), "tagged remaining bytes")?,
        checked_mul(source_states, size_of::<u32>(), "tagged queue bytes")?,
        checked_mul(source_states, size_of::<u32>(), "tagged mapping bytes")?,
        checked_mul(
            source_states,
            size_of::<GroupBuilder>(),
            "tagged group scratch bytes",
        )?,
        checked_mul(
            source_states,
            size_of::<Lane>(),
            "tagged lane scratch bytes",
        )?,
        checked_mul(
            signature_capacity,
            size_of::<SignatureSlot>(),
            "tagged signature scratch bytes",
        )?,
    ] {
        total = checked_add(total, bytes, "tagged build scratch bytes")?;
    }
    Ok(total)
}

fn persistent_bytes(
    states: usize,
    edges: usize,
    starts: usize,
    evaluation_order: usize,
) -> Result<usize, TaggedManyBuildError> {
    let mut total = checked_mul(
        states,
        size_of::<TaggedState>(),
        "tagged persistent state bytes",
    )?;
    for bytes in [
        checked_mul(
            edges,
            size_of::<TaggedEdge>(),
            "tagged persistent edge bytes",
        )?,
        checked_mul(starts, size_of::<u32>(), "tagged persistent start bytes")?,
        checked_mul(
            evaluation_order,
            size_of::<u32>(),
            "tagged persistent evaluation-order bytes",
        )?,
    ] {
        total = checked_add(total, bytes, "tagged persistent bytes")?;
    }
    Ok(total)
}

fn count_zero_width_edges(
    automata: &[Automaton],
    bases: &[usize],
    reverse_counts: &mut [usize],
    meter: &mut BuildMeter,
) -> Result<usize, TaggedManyBuildError> {
    let mut zero_edges = 0usize;
    for (owner, automaton) in automata.iter().enumerate() {
        for state in 0..automaton.stats().states() {
            meter.charge(1)?;
            let state_u32 =
                u32::try_from(state).map_err(|_| TaggedManyBuildError::ArithmeticOverflow {
                    computation: "zero-width source state index",
                })?;
            for edge in automaton.state_edges(state_u32) {
                meter.charge(1)?;
                if automaton.edge_kinds[edge].is_zero_width() {
                    zero_edges = checked_add(zero_edges, 1, "tagged zero-width edge count")?;
                    let target = checked_add(
                        bases[owner],
                        plan_index(automaton.edge_targets[edge]),
                        "tagged reverse target",
                    )?;
                    reverse_counts[target] =
                        checked_add(reverse_counts[target], 1, "tagged reverse parent count")?;
                }
            }
        }
    }
    Ok(zero_edges)
}

#[allow(clippy::too_many_arguments)]
fn derive_zero_width_ranks(
    automata: &[Automaton],
    bases: &[usize],
    ranks: &mut [u32],
    reverse_counts: &[usize],
    reverse_offsets: &mut [usize],
    reverse_parents: &mut [u32],
    remaining: &mut [usize],
    queue: &mut Vec<u32>,
    meter: &mut BuildMeter,
) -> Result<(), TaggedManyBuildError> {
    for state in 0..reverse_counts.len() {
        meter.charge(1)?;
        reverse_offsets[state + 1] = checked_add(
            reverse_offsets[state],
            reverse_counts[state],
            "tagged reverse offset",
        )?;
        remaining[state] = reverse_offsets[state];
    }
    for (owner, automaton) in automata.iter().enumerate() {
        for state in 0..automaton.stats().states() {
            let state_u32 =
                u32::try_from(state).map_err(|_| TaggedManyBuildError::ArithmeticOverflow {
                    computation: "tagged rank source state",
                })?;
            let global_parent = checked_add(bases[owner], state, "tagged rank parent index")?;
            for edge in automaton.state_edges(state_u32) {
                meter.charge(1)?;
                if !automaton.edge_kinds[edge].is_zero_width() {
                    continue;
                }
                let target = checked_add(
                    bases[owner],
                    plan_index(automaton.edge_targets[edge]),
                    "tagged rank target index",
                )?;
                let slot = remaining[target];
                let end = reverse_offsets[target + 1];
                if slot >= end {
                    return Err(TaggedManyBuildError::InternalInvariant {
                        detail: "tagged reverse edge fill exceeded its census",
                    });
                }
                reverse_parents[slot] = u32::try_from(global_parent).map_err(|_| {
                    TaggedManyBuildError::ArithmeticOverflow {
                        computation: "tagged reverse parent index space",
                    }
                })?;
                remaining[target] =
                    checked_add(remaining[target], 1, "tagged reverse fill cursor")?;
            }
        }
    }
    remaining.fill(0);
    for (owner, automaton) in automata.iter().enumerate() {
        for state in 0..automaton.stats().states() {
            let state_u32 =
                u32::try_from(state).map_err(|_| TaggedManyBuildError::ArithmeticOverflow {
                    computation: "tagged remaining source state",
                })?;
            let mut children = 0usize;
            for edge in automaton.state_edges(state_u32) {
                meter.charge(1)?;
                children = children
                    .checked_add(usize::from(automaton.edge_kinds[edge].is_zero_width()))
                    .ok_or(TaggedManyBuildError::ArithmeticOverflow {
                        computation: "tagged remaining child count",
                    })?;
            }
            let global = checked_add(bases[owner], state, "tagged remaining state")?;
            remaining[global] = children;
            if children == 0 {
                queue.push(u32::try_from(global).map_err(|_| {
                    TaggedManyBuildError::ArithmeticOverflow {
                        computation: "tagged rank queue index space",
                    }
                })?);
            }
        }
    }
    let mut head = 0usize;
    while head < queue.len() {
        meter.charge(1)?;
        let child = plan_index(queue[head]);
        head = checked_add(head, 1, "tagged rank queue head")?;
        for &parent in &reverse_parents[reverse_offsets[child]..reverse_offsets[child + 1]] {
            meter.charge(1)?;
            let parent = plan_index(parent);
            let candidate =
                ranks[child]
                    .checked_add(1)
                    .ok_or(TaggedManyBuildError::ArithmeticOverflow {
                        computation: "tagged zero-width rank",
                    })?;
            ranks[parent] = ranks[parent].max(candidate);
            remaining[parent] = remaining[parent].checked_sub(1).ok_or(
                TaggedManyBuildError::InternalInvariant {
                    detail: "tagged zero-width dependency underflow",
                },
            )?;
            if remaining[parent] == 0 {
                queue.push(u32::try_from(parent).map_err(|_| {
                    TaggedManyBuildError::ArithmeticOverflow {
                        computation: "tagged rank parent index space",
                    }
                })?);
            }
        }
    }
    if queue.len() != ranks.len() {
        let state = remaining.iter().position(|&value| value != 0).ok_or(
            TaggedManyBuildError::InternalInvariant {
                detail: "zero-width rank census disagreed without a residual",
            },
        )?;
        let pattern = bases
            .windows(2)
            .position(|window| window[0] <= state && state < window[1])
            .ok_or(TaggedManyBuildError::InternalInvariant {
                detail: "zero-width cycle state has no owner",
            })?;
        return Err(TaggedManyBuildError::ZeroWidthCycle { pattern });
    }
    Ok(())
}

fn build_evaluation_order(
    groups: &[GroupBuilder],
    maximum_rank: u32,
    rank_counts: &mut [usize],
    rank_offsets: &mut [usize],
    meter: &mut BuildMeter,
) -> Result<Vec<u32>, TaggedManyBuildError> {
    let buckets = plan_index(maximum_rank).checked_add(1).ok_or(
        TaggedManyBuildError::ArithmeticOverflow {
            computation: "tagged evaluation rank buckets",
        },
    )?;
    if buckets > rank_counts.len() || buckets + 1 > rank_offsets.len() {
        return Err(TaggedManyBuildError::InternalInvariant {
            detail: "tagged evaluation rank escaped source-state scratch",
        });
    }
    meter.charge(u64::try_from(buckets).map_err(|_| {
        TaggedManyBuildError::ArithmeticOverflow {
            computation: "tagged evaluation bucket work",
        }
    })?)?;
    rank_counts[..buckets].fill(0);
    for group in groups {
        meter.charge(1)?;
        let rank = plan_index(group.rank);
        rank_counts[rank] = checked_add(rank_counts[rank], 1, "tagged evaluation rank count")?;
    }
    rank_offsets[0] = 0;
    for rank in 0..buckets {
        meter.charge(1)?;
        rank_offsets[rank + 1] = checked_add(
            rank_offsets[rank],
            rank_counts[rank],
            "tagged evaluation rank offset",
        )?;
        rank_counts[rank] = rank_offsets[rank];
    }
    let mut order = reserve_and_fill(groups.len(), EMPTY_INDEX, "tagged evaluation order")?;
    for (state, group) in groups.iter().enumerate() {
        meter.charge(1)?;
        let rank = plan_index(group.rank);
        let slot = rank_counts[rank];
        order[slot] =
            u32::try_from(state).map_err(|_| TaggedManyBuildError::ArithmeticOverflow {
                computation: "tagged evaluation state index",
            })?;
        rank_counts[rank] = checked_add(slot, 1, "tagged evaluation rank cursor")?;
    }
    meter.charge_usize(order.len())?;
    if rank_offsets[buckets] != groups.len() || order.contains(&EMPTY_INDEX) {
        return Err(TaggedManyBuildError::InternalInvariant {
            detail: "tagged evaluation order omitted a state",
        });
    }
    Ok(order)
}

fn signature_hash(
    automaton: &Automaton,
    state: usize,
    rank: u32,
    meter: &mut BuildMeter,
) -> Result<u64, TaggedManyBuildError> {
    meter.charge(2)?;
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    let role = match automaton.roles[state] {
        StateRole::Split => 1u64,
        StateRole::Consume => 2,
        StateRole::Accept => 3,
    };
    hash ^= role;
    hash = hash.wrapping_mul(0x1000_0000_01b3);
    hash ^= u64::from(rank);
    hash = hash.wrapping_mul(0x1000_0000_01b3);
    let state = u32::try_from(state).unwrap_or(u32::MAX);
    for edge in automaton.state_edges(state) {
        meter.charge(2)?;
        let kind = edge_kind_code(automaton.edge_kinds[edge]);
        hash ^= kind;
        hash = hash.wrapping_mul(0x1000_0000_01b3);
        hash ^=
            u64::from(automaton.byte_starts[edge]) | (u64::from(automaton.byte_ends[edge]) << 8);
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    Ok(hash)
}

const fn edge_kind_code(kind: EdgeKind) -> u64 {
    match kind {
        EdgeKind::Epsilon => 1,
        EdgeKind::ByteRange => 2,
        EdgeKind::AssertHaystackStart => 3,
        EdgeKind::AssertHaystackEnd => 4,
        EdgeKind::AssertLineStartLf => 5,
        EdgeKind::AssertLineEndLf => 6,
        EdgeKind::AssertLineStartCrlf => 7,
        EdgeKind::AssertLineEndCrlf => 8,
        EdgeKind::AssertWordAscii => 9,
        EdgeKind::AssertWordAsciiNegate => 10,
        EdgeKind::AssertWordStartAscii => 11,
        EdgeKind::AssertWordEndAscii => 12,
        EdgeKind::AssertWordStartHalfAscii => 13,
        EdgeKind::AssertWordEndHalfAscii => 14,
        EdgeKind::AssertWordUnicode => 15,
        EdgeKind::AssertWordUnicodeNegate => 16,
        EdgeKind::AssertWordStartUnicode => 17,
        EdgeKind::AssertWordEndUnicode => 18,
        EdgeKind::AssertWordStartHalfUnicode => 19,
        EdgeKind::AssertWordEndHalfUnicode => 20,
    }
}

fn signatures_equal(
    left: &Automaton,
    left_state: usize,
    right: &Automaton,
    right_state: usize,
    meter: &mut BuildMeter,
) -> Result<bool, TaggedManyBuildError> {
    meter.signature_full_comparisons = checked_add(
        meter.signature_full_comparisons,
        1,
        "tagged signature comparison count",
    )?;
    meter.charge(2)?;
    if left.roles[left_state] != right.roles[right_state] {
        return Ok(false);
    }
    let left_state_u32 =
        u32::try_from(left_state).map_err(|_| TaggedManyBuildError::ArithmeticOverflow {
            computation: "tagged left signature state",
        })?;
    let right_state_u32 =
        u32::try_from(right_state).map_err(|_| TaggedManyBuildError::ArithmeticOverflow {
            computation: "tagged right signature state",
        })?;
    let left_edges = left.state_edges(left_state_u32);
    let right_edges = right.state_edges(right_state_u32);
    if left_edges.len() != right_edges.len() {
        return Ok(false);
    }
    for (left_edge, right_edge) in left_edges.zip(right_edges) {
        meter.charge(4)?;
        if left.edge_kinds[left_edge] != right.edge_kinds[right_edge]
            || left.byte_starts[left_edge] != right.byte_starts[right_edge]
            || left.byte_ends[left_edge] != right.byte_ends[right_edge]
        {
            return Ok(false);
        }
    }
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
fn build_state_groups(
    automata: &[Automaton],
    bases: &[usize],
    ranks: &[u32],
    mapping: &mut [u32],
    groups: &mut Vec<GroupBuilder>,
    lanes: &mut Vec<Lane>,
    signatures: &mut [SignatureSlot],
    meter: &mut BuildMeter,
) -> Result<(), TaggedManyBuildError> {
    let mask = signatures
        .len()
        .checked_sub(1)
        .ok_or(TaggedManyBuildError::InternalInvariant {
            detail: "tagged signature table is empty",
        })?;
    for (owner, automaton) in automata.iter().enumerate() {
        let owner_bit = 1u128
            .checked_shl(u32::try_from(owner).map_err(|_| {
                TaggedManyBuildError::ArithmeticOverflow {
                    computation: "tagged owner bit",
                }
            })?)
            .ok_or(TaggedManyBuildError::ArithmeticOverflow {
                computation: "tagged owner bit shift",
            })?;
        for state in 0..automaton.stats().states() {
            meter.charge(4)?;
            let global = checked_add(bases[owner], state, "tagged grouping source state")?;
            let hash = signature_hash(automaton, state, ranks[global], meter)?;
            let mut slot_index = usize::try_from(hash).unwrap_or(0) & mask;
            let mut selected = None::<usize>;
            let mut probes = 0usize;
            loop {
                probes = checked_add(probes, 1, "tagged signature probes")?;
                meter.signature_probes =
                    checked_add(meter.signature_probes, 1, "tagged signature probe count")?;
                meter.charge(1)?;
                if probes > MAX_SIGNATURE_PROBES {
                    return Err(TaggedManyBuildError::SignatureCollisionLimit {
                        probes: MAX_SIGNATURE_PROBES,
                        chain: MAX_SIGNATURE_CHAIN,
                    });
                }
                let slot = signatures[slot_index];
                if slot.head == EMPTY_INDEX {
                    break;
                }
                if slot.hash == hash {
                    let mut group_index = slot.head;
                    let mut chain = 0usize;
                    while group_index != EMPTY_INDEX {
                        chain = checked_add(chain, 1, "tagged signature chain")?;
                        if chain > MAX_SIGNATURE_CHAIN {
                            return Err(TaggedManyBuildError::SignatureCollisionLimit {
                                probes: MAX_SIGNATURE_PROBES,
                                chain: MAX_SIGNATURE_CHAIN,
                            });
                        }
                        let group = groups[plan_index(group_index)];
                        meter.charge(2)?;
                        if group.rank == ranks[global]
                            && group.owners & owner_bit == 0
                            && signatures_equal(
                                automaton,
                                state,
                                &automata[usize::from(group.representative_owner)],
                                plan_index(group.representative_state),
                                meter,
                            )?
                        {
                            let candidate = plan_index(group_index);
                            selected =
                                Some(selected.map_or(candidate, |current| current.min(candidate)));
                        }
                        group_index = group.signature_next;
                    }
                    break;
                }
                slot_index = slot_index.checked_add(1).map(|value| value & mask).ok_or(
                    TaggedManyBuildError::ArithmeticOverflow {
                        computation: "tagged signature probe index",
                    },
                )?;
            }
            let group_index = if let Some(group_index) = selected {
                group_index
            } else {
                let group_index = groups.len();
                let group_u32 = u32::try_from(group_index).map_err(|_| {
                    TaggedManyBuildError::ArithmeticOverflow {
                        computation: "tagged group index space",
                    }
                })?;
                let previous = if signatures[slot_index].head == EMPTY_INDEX {
                    signatures[slot_index].hash = hash;
                    EMPTY_INDEX
                } else {
                    signatures[slot_index].head
                };
                groups.push(GroupBuilder {
                    role: automaton.roles[state],
                    rank: ranks[global],
                    owners: 0,
                    representative_owner: u8::try_from(owner).map_err(|_| {
                        TaggedManyBuildError::ArithmeticOverflow {
                            computation: "tagged representative owner",
                        }
                    })?,
                    representative_state: u32::try_from(state).map_err(|_| {
                        TaggedManyBuildError::ArithmeticOverflow {
                            computation: "tagged representative state",
                        }
                    })?,
                    lane_head: EMPTY_INDEX,
                    signature_next: previous,
                });
                signatures[slot_index].head = group_u32;
                group_index
            };
            let lane_index = lanes.len();
            let previous_lane = groups[group_index].lane_head;
            lanes.push(Lane {
                owner: u8::try_from(owner).map_err(|_| {
                    TaggedManyBuildError::ArithmeticOverflow {
                        computation: "tagged lane owner",
                    }
                })?,
                state: u32::try_from(state).map_err(|_| {
                    TaggedManyBuildError::ArithmeticOverflow {
                        computation: "tagged lane state",
                    }
                })?,
                next: previous_lane,
            });
            groups[group_index].lane_head = u32::try_from(lane_index).map_err(|_| {
                TaggedManyBuildError::ArithmeticOverflow {
                    computation: "tagged lane index space",
                }
            })?;
            groups[group_index].owners |= owner_bit;
            mapping[global] = u32::try_from(group_index).map_err(|_| {
                TaggedManyBuildError::ArithmeticOverflow {
                    computation: "tagged mapping index space",
                }
            })?;
        }
    }
    if groups.is_empty() || lanes.len() != mapping.len() {
        return Err(TaggedManyBuildError::InternalInvariant {
            detail: "tagged grouping did not cover every source state",
        });
    }
    Ok(())
}

fn owner_bit(owner: u8) -> u128 {
    1u128 << u32::from(owner)
}

#[allow(clippy::too_many_arguments)]
fn group_shards_with_lanes(
    automata: &[Automaton],
    bases: &[usize],
    mapping: &[u32],
    lanes: &[Lane],
    group: GroupBuilder,
    priority_slot: usize,
    targets: &mut [u32; MAX_OWNERS],
    owners: &mut [u128; MAX_OWNERS],
    meter: &mut BuildMeter,
) -> Result<usize, TaggedManyBuildError> {
    let mut shard_count = 0usize;
    let mut lane_index = group.lane_head;
    while lane_index != EMPTY_INDEX {
        meter.charge(2)?;
        let lane = lanes[plan_index(lane_index)];
        let automaton = &automata[usize::from(lane.owner)];
        let edge = automaton.state_edges(lane.state).nth(priority_slot).ok_or(
            TaggedManyBuildError::InternalInvariant {
                detail: "tagged lane signature lost an edge slot",
            },
        )?;
        let target_global = checked_add(
            bases[usize::from(lane.owner)],
            plan_index(automaton.edge_targets[edge]),
            "tagged shard target mapping",
        )?;
        let target = mapping[target_global];
        let mut shard = None::<usize>;
        for (index, &candidate) in targets[..shard_count].iter().enumerate() {
            meter.charge(1)?;
            if candidate == target {
                shard = Some(index);
                break;
            }
        }
        let shard = if let Some(index) = shard {
            index
        } else {
            let index = shard_count;
            targets[index] = target;
            owners[index] = 0;
            shard_count = checked_add(shard_count, 1, "tagged shard count")?;
            index
        };
        owners[shard] |= owner_bit(lane.owner);
        lane_index = lane.next;
    }
    Ok(shard_count)
}

fn count_shared_edges(
    automata: &[Automaton],
    bases: &[usize],
    mapping: &[u32],
    groups: &[GroupBuilder],
    lanes: &[Lane],
    meter: &mut BuildMeter,
) -> Result<usize, TaggedManyBuildError> {
    let mut count = 0usize;
    let mut targets = [EMPTY_INDEX; MAX_OWNERS];
    let mut owners = [0u128; MAX_OWNERS];
    for group in groups {
        let representative = &automata[usize::from(group.representative_owner)];
        let edge_count = representative.state_edges(group.representative_state).len();
        for slot in 0..edge_count {
            let shards = group_shards_with_lanes(
                automata,
                bases,
                mapping,
                lanes,
                *group,
                slot,
                &mut targets,
                &mut owners,
                meter,
            )?;
            count = checked_add(count, shards, "tagged shared edge count")?;
        }
    }
    Ok(count)
}

#[allow(clippy::too_many_arguments)]
fn fill_shared_graph(
    automata: &[Automaton],
    bases: &[usize],
    mapping: &[u32],
    groups: &[GroupBuilder],
    lanes: &[Lane],
    states: &mut Vec<TaggedState>,
    edges: &mut Vec<TaggedEdge>,
    meter: &mut BuildMeter,
) -> Result<(), TaggedManyBuildError> {
    let mut targets = [EMPTY_INDEX; MAX_OWNERS];
    let mut owners = [0u128; MAX_OWNERS];
    for group in groups {
        let edge_start =
            u32::try_from(edges.len()).map_err(|_| TaggedManyBuildError::ArithmeticOverflow {
                computation: "tagged edge offset",
            })?;
        let representative = &automata[usize::from(group.representative_owner)];
        let edge_range = representative.state_edges(group.representative_state);
        for (slot, representative_edge) in edge_range.enumerate() {
            let shards = group_shards_with_lanes(
                automata,
                bases,
                mapping,
                lanes,
                *group,
                slot,
                &mut targets,
                &mut owners,
                meter,
            )?;
            for shard in 0..shards {
                meter.charge(1)?;
                edges.push(TaggedEdge {
                    target: targets[shard],
                    owners: owners[shard],
                    kind: representative.edge_kinds[representative_edge],
                    byte_start: representative.byte_starts[representative_edge],
                    byte_end: representative.byte_ends[representative_edge],
                    priority_slot: u32::try_from(slot).map_err(|_| {
                        TaggedManyBuildError::ArithmeticOverflow {
                            computation: "tagged edge priority slot",
                        }
                    })?,
                });
            }
        }
        let edge_end =
            u32::try_from(edges.len()).map_err(|_| TaggedManyBuildError::ArithmeticOverflow {
                computation: "tagged edge terminal offset",
            })?;
        states.push(TaggedState {
            role: group.role,
            owners: group.owners,
            start_owners: 0,
            edge_start,
            edge_end,
            zero_width_rank: group.rank,
        });
    }
    Ok(())
}

fn validate_projection(
    automata: &[Automaton],
    bases: &[usize],
    mapping: &[u32],
    states: &[TaggedState],
    edges: &[TaggedEdge],
    meter: &mut BuildMeter,
) -> Result<(), TaggedManyBuildError> {
    for (owner, automaton) in automata.iter().enumerate() {
        let bit = 1u128 << owner;
        for state in 0..automaton.stats().states() {
            meter.charge(3)?;
            meter.projection_checks =
                checked_add(meter.projection_checks, 1, "tagged projection check count")?;
            let global = checked_add(bases[owner], state, "tagged projection state")?;
            let physical = plan_index(mapping[global]);
            let tagged = states[physical];
            if tagged.role != automaton.roles[state] || tagged.owners & bit == 0 {
                return Err(TaggedManyBuildError::ProjectionMismatch {
                    pattern: owner,
                    state,
                    edge: None,
                });
            }
            let state_u32 =
                u32::try_from(state).map_err(|_| TaggedManyBuildError::ArithmeticOverflow {
                    computation: "tagged projection source state",
                })?;
            let source_edges = automaton.state_edges(state_u32);
            let mut tagged_edge = plan_index(tagged.edge_start);
            let tagged_end = plan_index(tagged.edge_end);
            for (slot, source_edge) in source_edges.enumerate() {
                while tagged_edge < tagged_end
                    && plan_index(edges[tagged_edge].priority_slot) < slot
                {
                    meter.charge(1)?;
                    meter.projection_edge_visits = checked_add(
                        meter.projection_edge_visits,
                        1,
                        "tagged projection edge visit count",
                    )?;
                    if edges[tagged_edge].owners & bit != 0 {
                        return Err(TaggedManyBuildError::ProjectionMismatch {
                            pattern: owner,
                            state,
                            edge: Some(source_edge),
                        });
                    }
                    tagged_edge = checked_add(tagged_edge, 1, "tagged projection shard cursor")?;
                }
                let mut found = None::<TaggedEdge>;
                while tagged_edge < tagged_end
                    && plan_index(edges[tagged_edge].priority_slot) == slot
                {
                    meter.charge(1)?;
                    meter.projection_edge_visits = checked_add(
                        meter.projection_edge_visits,
                        1,
                        "tagged projection edge visit count",
                    )?;
                    let candidate = edges[tagged_edge];
                    if candidate.owners & bit != 0 && found.replace(candidate).is_some() {
                        return Err(TaggedManyBuildError::ProjectionMismatch {
                            pattern: owner,
                            state,
                            edge: Some(source_edge),
                        });
                    }
                    tagged_edge = checked_add(tagged_edge, 1, "tagged projection shard cursor")?;
                }
                let Some(candidate) = found else {
                    return Err(TaggedManyBuildError::ProjectionMismatch {
                        pattern: owner,
                        state,
                        edge: Some(source_edge),
                    });
                };
                let target_global = checked_add(
                    bases[owner],
                    plan_index(automaton.edge_targets[source_edge]),
                    "tagged projection target",
                )?;
                if candidate.kind != automaton.edge_kinds[source_edge]
                    || candidate.byte_start != automaton.byte_starts[source_edge]
                    || candidate.byte_end != automaton.byte_ends[source_edge]
                    || candidate.target != mapping[target_global]
                {
                    return Err(TaggedManyBuildError::ProjectionMismatch {
                        pattern: owner,
                        state,
                        edge: Some(source_edge),
                    });
                }
                if candidate.kind.is_zero_width()
                    && states[plan_index(candidate.target)].zero_width_rank
                        >= tagged.zero_width_rank
                {
                    return Err(TaggedManyBuildError::ProjectionMismatch {
                        pattern: owner,
                        state,
                        edge: Some(source_edge),
                    });
                }
            }
            while tagged_edge < tagged_end {
                meter.charge(1)?;
                meter.projection_edge_visits = checked_add(
                    meter.projection_edge_visits,
                    1,
                    "tagged projection edge visit count",
                )?;
                if edges[tagged_edge].owners & bit != 0 {
                    return Err(TaggedManyBuildError::ProjectionMismatch {
                        pattern: owner,
                        state,
                        edge: None,
                    });
                }
                tagged_edge = checked_add(tagged_edge, 1, "tagged projection terminal cursor")?;
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TaggedOutcome {
    ordinal: PatternOrdinal,
    end: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OutcomeGroup {
    owners: u128,
    end: usize,
}

impl OutcomeGroup {
    const EMPTY: Self = Self { owners: 0, end: 0 };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MapDesc {
    group_start: u32,
    group_len: u32,
}

impl MapDesc {
    const EMPTY: Self = Self {
        group_start: 0,
        group_len: 0,
    };
}

#[derive(Debug)]
struct OutcomePool {
    maps: Vec<MapDesc>,
    groups: Vec<OutcomeGroup>,
    map_capacity: usize,
    group_capacity: usize,
}

impl OutcomePool {
    fn new(map_capacity: usize, group_capacity: usize) -> Result<Self, ReduceError> {
        Ok(Self {
            maps: reserve_run(map_capacity, "tagged outcome maps")?,
            groups: reserve_run(group_capacity, "tagged outcome groups")?,
            map_capacity,
            group_capacity,
        })
    }

    fn reset(&mut self, meter: &mut RunMeter) -> Result<(), ReduceError> {
        meter.charge(1)?;
        self.maps.clear();
        self.groups.clear();
        self.maps.push(MapDesc::EMPTY);
        Ok(())
    }

    fn has_exact_capacity(&self) -> bool {
        self.maps.capacity() == self.map_capacity && self.groups.capacity() == self.group_capacity
    }

    fn map_groups(&self, map: u32) -> Result<&[OutcomeGroup], ReduceError> {
        let descriptor = *self
            .maps
            .get(plan_index(map))
            .ok_or(ReduceError::InternalInvariant {
                detail: "tagged row referenced an unknown outcome map",
            })?;
        let start = plan_index(descriptor.group_start);
        let end = start.checked_add(plan_index(descriptor.group_len)).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "tagged outcome map range",
            },
        )?;
        self.groups
            .get(start..end)
            .ok_or(ReduceError::InternalInvariant {
                detail: "tagged outcome map range escaped its pool",
            })
    }

    fn publish(
        &mut self,
        candidate: &[OutcomeGroup],
        meter: &mut RunMeter,
        actual: &mut ExecutionActual,
    ) -> Result<u32, ReduceError> {
        if candidate.is_empty() {
            return Ok(0);
        }
        if self.maps.len() == self.map_capacity {
            return Err(ReduceError::InternalInvariant {
                detail: "tagged outcome map census was exceeded",
            });
        }
        let group_end = self.groups.len().checked_add(candidate.len()).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "tagged outcome group publication",
            },
        )?;
        if group_end > self.group_capacity {
            return Err(ReduceError::InternalInvariant {
                detail: "tagged outcome group census was exceeded",
            });
        }
        meter.charge_usize(candidate.len().checked_add(2).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "tagged outcome map publication work",
            },
        )?)?;
        let map = u32::try_from(self.maps.len()).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "tagged outcome map index space",
        })?;
        let group_start =
            u32::try_from(self.groups.len()).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "tagged outcome group index space",
            })?;
        self.groups.extend_from_slice(candidate);
        self.maps.push(MapDesc {
            group_start,
            group_len: u32::try_from(candidate.len()).map_err(|_| {
                ReduceError::ArithmeticOverflow {
                    computation: "tagged outcome group length",
                }
            })?,
        });
        actual.tagged_map_publications = actual.tagged_map_publications.checked_add(1).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "tagged outcome map publications",
            },
        )?;
        actual.tagged_group_publications = actual
            .tagged_group_publications
            .checked_add(candidate.len())
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "tagged outcome group publications",
            })?;
        actual.tagged_peak_maps = actual.tagged_peak_maps.max(self.maps.len());
        actual.tagged_peak_groups = actual.tagged_peak_groups.max(self.groups.len());
        Ok(map)
    }
}

struct OutcomeCandidate {
    groups: [OutcomeGroup; MAX_OWNERS],
    len: usize,
    covered_owners: u128,
}

impl OutcomeCandidate {
    const fn new() -> Self {
        Self {
            groups: [OutcomeGroup::EMPTY; MAX_OWNERS],
            len: 0,
            covered_owners: 0,
        }
    }

    fn clear(&mut self) {
        self.len = 0;
        self.covered_owners = 0;
    }

    fn insert(
        &mut self,
        owners: u128,
        end: usize,
        meter: &mut RunMeter,
    ) -> Result<(), ReduceError> {
        if owners == 0 {
            return Ok(());
        }
        meter.charge(1)?;
        if self.covered_owners & owners != 0 {
            return Err(ReduceError::InternalInvariant {
                detail: "tagged outcome owner was published more than once",
            });
        }
        if self.len == MAX_OWNERS {
            return Err(ReduceError::InternalInvariant {
                detail: "tagged outcome candidate exceeded owner cardinality",
            });
        }
        self.groups[self.len] = OutcomeGroup { owners, end };
        self.covered_owners |= owners;
        self.len = self
            .len
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "tagged outcome candidate length",
            })?;
        Ok(())
    }

    fn as_slice(&self) -> &[OutcomeGroup] {
        &self.groups[..self.len]
    }
}

struct RunMeter {
    limit: u64,
    consumed: u64,
}

impl RunMeter {
    const fn new(limit: u64) -> Self {
        Self { limit, consumed: 0 }
    }

    fn charge(&mut self, requested: u64) -> Result<(), ReduceError> {
        let next = self
            .consumed
            .checked_add(requested)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "tagged execution work",
            })?;
        if next > self.limit {
            return Err(ReduceError::WorkLimit {
                consumed: self.consumed,
                requested,
                limit: self.limit,
            });
        }
        self.consumed = next;
        Ok(())
    }

    fn charge_usize(&mut self, requested: usize) -> Result<(), ReduceError> {
        self.charge(
            u64::try_from(requested).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "tagged execution work conversion",
            })?,
        )
    }
}

fn reserve_run<T>(entries: usize, _structure: &'static str) -> Result<Vec<T>, ReduceError> {
    // `Vec::try_reserve_exact(0)` is deliberately skipped. It cannot obtain
    // storage, and trace-session setup receipts count only real dynamic
    // allocation attempts. Keeping this branch here also makes the
    // zero-capacity arithmetic agree with the workspace that is actually
    // retained.
    if entries == 0 {
        return Ok(Vec::new());
    }
    let mut values = Vec::new();
    values
        .try_reserve_exact(entries)
        .map_err(|_| ReduceError::AllocationFailed {
            bytes: entries.saturating_mul(size_of::<T>()),
        })?;
    if values.capacity() != entries {
        return Err(ReduceError::AllocationFailed {
            bytes: values.capacity().saturating_mul(size_of::<T>()),
        });
    }
    Ok(values)
}

fn reserve_and_fill_run<T: Clone>(
    entries: usize,
    value: T,
    structure: &'static str,
) -> Result<Vec<T>, ReduceError> {
    let mut values = reserve_run(entries, structure)?;
    values.resize(entries, value);
    Ok(values)
}

/// Exact one-time resources retained by a reusable tagged trace session.
///
/// This is intentionally separate from [`ExecutionProspective`]. The latter
/// describes one source operation, whereas this receipt describes the
/// caller-owned storage allocated before the first operation. In particular,
/// [`Self::allocation_attempts`] counts only non-empty reservations and
/// [`Self::initialization_work`] counts only the reservations and fills made
/// during session construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaggedManyTraceSessionSetupProspective {
    /// Fixed source length to which the retained workspace is bound.
    pub source_bytes: usize,
    /// Exact bytes retained by the session's rows, pools, and trace buffer.
    pub persistent_bytes: usize,
    /// Exact initialization work performed while preparing the session.
    pub initialization_work: u64,
    /// Exact non-empty dynamic allocation attempts made during preparation.
    pub allocation_attempts: usize,
    /// Exact ordinal-trace capacity retained during preparation.
    pub trace_capacity: usize,
    /// Allocation-free envelope for the same source operation without an
    /// ordinal trace.
    pub steady_untraced_prospective: ExecutionProspective,
    /// Allocation-free envelope for a repeated ordinal-trace operation.
    pub steady_traced_prospective: ExecutionProspective,
}

impl TaggedManyTraceSessionSetupProspective {
    /// Validate the arithmetic relationship between the retained-session
    /// receipt and its allocation-free operation envelopes.
    #[must_use]
    pub fn closes(self) -> bool {
        trace_session_setup_formula(
            self.source_bytes,
            self.steady_untraced_prospective,
            self.steady_traced_prospective,
        )
        .is_ok_and(
            |(persistent_bytes, initialization_work, allocation_attempts)| {
                self.persistent_bytes == persistent_bytes
                    && self.initialization_work == initialization_work
                    && self.allocation_attempts == allocation_attempts
                    && self.trace_capacity
                        == self.steady_traced_prospective.match_events_upper_bound
            },
        )
    }
}

fn count_nonempty_reservations(entries: &[usize]) -> Result<usize, ReduceError> {
    entries.iter().try_fold(0usize, |count, &entries| {
        count
            .checked_add(usize::from(entries != 0))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "tagged trace-session allocation attempts",
            })
    })
}

fn trace_session_setup_formula(
    source_bytes: usize,
    steady_untraced_prospective: ExecutionProspective,
    steady_traced_prospective: ExecutionProspective,
) -> Result<(usize, u64, usize), ReduceError> {
    let boundary_rows = source_bytes
        .checked_add(1)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "tagged trace-session boundary rows",
        })?;
    let trace_capacity = steady_traced_prospective.match_events_upper_bound;
    let trace_bytes = trace_capacity
        .checked_mul(size_of::<PriorityMatch>())
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "tagged trace-session trace bytes",
        })?;
    let trace_work = u64::try_from(trace_capacity)
        .map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "tagged trace-session trace work",
        })?
        .checked_add(1)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "tagged trace-session trace work",
        })?;
    let mut expected_traced = steady_untraced_prospective;
    expected_traced.scratch_bytes = expected_traced
        .scratch_bytes
        .checked_add(trace_bytes)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "tagged trace-session traced scratch",
        })?;
    expected_traced.work_upper_bound = expected_traced
        .work_upper_bound
        .checked_add(trace_work)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "tagged trace-session traced work",
        })?;
    expected_traced.allocation_attempts = 0;
    if steady_untraced_prospective.allocation_attempts != 0
        || steady_traced_prospective.allocation_attempts != 0
        || steady_untraced_prospective.boundary_rows != boundary_rows
        || steady_traced_prospective.boundary_rows != boundary_rows
        || steady_untraced_prospective.match_events_upper_bound != boundary_rows
        || steady_traced_prospective.match_events_upper_bound != boundary_rows
        || steady_traced_prospective != expected_traced
    {
        return Err(ReduceError::InternalInvariant {
            detail: "tagged trace-session steady prospectives did not close",
        });
    }

    match steady_traced_prospective.tagged_execution_class {
        Some(TaggedManyExecutionClass::Generic) => {
            let map_capacity = steady_traced_prospective.tagged_map_capacity;
            let states = map_capacity
                .checked_sub(1)
                .ok_or(ReduceError::InternalInvariant {
                    detail: "generic tagged trace-session omitted its empty outcome map",
                })?;
            let group_capacity = steady_traced_prospective.tagged_group_capacity;
            let persistent_bytes =
                tagged_run_scratch(states, boundary_rows, map_capacity, group_capacity)?
                    .checked_add(trace_bytes)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "tagged trace-session persistent bytes",
                    })?;
            let allocation_attempts = count_nonempty_reservations(&[
                states,
                states,
                boundary_rows,
                map_capacity,
                group_capacity,
                map_capacity,
                group_capacity,
                trace_capacity,
            ])?;
            let initialized_entries = states
                .checked_mul(2)
                .and_then(|entries| entries.checked_add(boundary_rows))
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "tagged trace-session initialized entries",
                })?;
            let initialization_work = u64::try_from(initialized_entries)
                .map_err(|_| ReduceError::ArithmeticOverflow {
                    computation: "tagged trace-session initialization work",
                })?
                .checked_add(u64::try_from(allocation_attempts).map_err(|_| {
                    ReduceError::ArithmeticOverflow {
                        computation: "tagged trace-session allocation work",
                    }
                })?)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "tagged trace-session initialization work",
                })?;
            if steady_traced_prospective.scratch_bytes != persistent_bytes {
                return Err(ReduceError::InternalInvariant {
                    detail:
                        "generic tagged trace-session scratch did not describe retained storage",
                });
            }
            Ok((persistent_bytes, initialization_work, allocation_attempts))
        }
        Some(TaggedManyExecutionClass::SharedFrontierUniformRangeChain { .. }) => {
            let allocation_attempts = count_nonempty_reservations(&[trace_capacity])?;
            let initialization_work = u64::try_from(allocation_attempts).map_err(|_| {
                ReduceError::ArithmeticOverflow {
                    computation: "tagged shared-frontier trace-session initialization work",
                }
            })?;
            if steady_untraced_prospective.scratch_bytes != 0
                || steady_traced_prospective.scratch_bytes != trace_bytes
            {
                return Err(ReduceError::InternalInvariant {
                    detail:
                        "shared-frontier trace-session scratch did not describe retained storage",
                });
            }
            Ok((trace_bytes, initialization_work, allocation_attempts))
        }
        None => Err(ReduceError::InternalInvariant {
            detail: "tagged trace-session prospective omitted its execution class",
        }),
    }
}

fn trace_session_steady_prospectives<O: DirectReduceValue>(
    plan: &TaggedManyPlan<O>,
    source_bytes: usize,
    limits: DirectReduceLimits,
) -> Result<(ExecutionProspective, ExecutionProspective), ReduceError> {
    // A retained session has no operation-time allocations. Relax the
    // one-shot allocation field while deriving the work/scratch envelopes,
    // then admit the exact construction allocation census separately.
    let allocation_relaxed = DirectReduceLimits {
        max_allocation_attempts: usize::MAX,
        ..limits
    };
    let mut untraced = tagged_prospective(plan, source_bytes, allocation_relaxed, false)?;
    let mut traced = tagged_prospective(plan, source_bytes, allocation_relaxed, true)?;
    untraced.allocation_attempts = 0;
    traced.allocation_attempts = 0;
    Ok((untraced, traced))
}

fn trace_session_setup_prospective<O: DirectReduceValue>(
    plan: &TaggedManyPlan<O>,
    source_bytes: usize,
    limits: DirectReduceLimits,
) -> Result<TaggedManyTraceSessionSetupProspective, ReduceError> {
    let (steady_untraced_prospective, steady_traced_prospective) =
        trace_session_steady_prospectives(plan, source_bytes, limits)?;
    let (persistent_bytes, initialization_work, allocation_attempts) = trace_session_setup_formula(
        source_bytes,
        steady_untraced_prospective,
        steady_traced_prospective,
    )?;
    if persistent_bytes > limits.max_scratch_bytes {
        return Err(ReduceError::ScratchLimit {
            needed: persistent_bytes,
            limit: limits.max_scratch_bytes,
        });
    }
    if initialization_work > limits.max_work {
        return Err(ReduceError::WorkLimit {
            consumed: 0,
            requested: initialization_work,
            limit: limits.max_work,
        });
    }
    if allocation_attempts > limits.max_allocation_attempts {
        return Err(ReduceError::AllocationAttemptsLimit {
            needed: allocation_attempts,
            limit: limits.max_allocation_attempts,
        });
    }
    let setup = TaggedManyTraceSessionSetupProspective {
        source_bytes,
        persistent_bytes,
        initialization_work,
        allocation_attempts,
        trace_capacity: steady_traced_prospective.match_events_upper_bound,
        steady_untraced_prospective,
        steady_traced_prospective,
    };
    if !setup.closes() {
        return Err(ReduceError::InternalInvariant {
            detail: "tagged trace-session setup prospective did not close",
        });
    }
    Ok(setup)
}

/// Caller-owned reusable trace workspace for one fixed-length tagged run.
///
/// Construction admits and reserves every row, outcome pool, and trace entry
/// before the first source byte is read. Repeated [`Self::execute_trace`]
/// calls retain that storage and return a borrowing receipt, so the trace
/// cannot outlive the workspace that owns it.
#[derive(Debug)]
pub struct TaggedManyTraceSession<'plan, O: DirectReduceValue> {
    plan: &'plan TaggedManyPlan<O>,
    source_bytes: usize,
    limits: DirectReduceLimits,
    /// Exact construction receipt for retained caller-owned storage.
    setup: TaggedManyTraceSessionSetupProspective,
    /// Legacy one-shot comparison envelopes retained for API compatibility.
    /// Exact retained-session construction accounting lives in [`Self::setup`].
    setup_untraced_prospective: ExecutionProspective,
    setup_traced_prospective: ExecutionProspective,
    /// The repeated-operation envelopes retain the same scratch/work bounds
    /// but report no fresh dynamic allocations.
    untraced_prospective: ExecutionProspective,
    prospective: ExecutionProspective,
    workspace: TaggedManyTraceWorkspace,
}

#[derive(Debug)]
enum TaggedManyTraceWorkspace {
    Generic(TaggedManyGenericTraceWorkspace),
    SharedFrontier { trace: Vec<PriorityMatch> },
}

#[derive(Debug)]
struct TaggedManyGenericTraceWorkspace {
    current_rows: Vec<u32>,
    next_rows: Vec<u32>,
    roots: Vec<Option<TaggedOutcome>>,
    current_pool: OutcomePool,
    next_pool: OutcomePool,
    trace: Vec<PriorityMatch>,
}

/// Borrowing result of one reusable tagged trace execution.
///
/// Unlike [`DirectReduceTraceReport`], this receipt cannot be detached from
/// its session: the caller must drop it before executing that session again.
/// This lets the session retain the trace allocation while preserving the
/// same ordinal/span observation surface.
#[derive(Debug)]
pub struct TaggedManyTraceSessionReport<'session, T> {
    report: DirectReduceReport<T>,
    setup: TaggedManyTraceSessionSetupProspective,
    untraced_prospective: ExecutionProspective,
    setup_untraced_prospective: ExecutionProspective,
    setup_traced_prospective: ExecutionProspective,
    matches: &'session [PriorityMatch],
    trace_capacity: usize,
}

impl<T> TaggedManyTraceSessionReport<'_, T> {
    /// The direct-reducer receipt for this allocation-free steady execution.
    #[must_use]
    pub const fn report(&self) -> &DirectReduceReport<T> {
        &self.report
    }

    /// Exact one-time retained-session construction receipt.
    #[must_use]
    pub const fn setup(&self) -> TaggedManyTraceSessionSetupProspective {
        self.setup
    }

    /// Alias for [`Self::setup`] that makes the preflight relationship
    /// explicit at call sites.
    #[must_use]
    pub const fn setup_prospective_receipt(&self) -> TaggedManyTraceSessionSetupProspective {
        self.setup()
    }

    /// The source-free steady-operation envelope before trace storage.
    #[must_use]
    pub const fn untraced_prospective(&self) -> ExecutionProspective {
        self.untraced_prospective
    }

    /// Legacy untraced one-shot comparison envelope.
    ///
    /// For exact retained-session construction accounting, use [`Self::setup`].
    #[must_use]
    pub const fn setup_untraced_prospective(&self) -> ExecutionProspective {
        self.setup_untraced_prospective
    }

    /// Legacy traced one-shot comparison envelope.
    ///
    /// For exact retained-session construction accounting, use [`Self::setup`].
    #[must_use]
    pub const fn setup_prospective(&self) -> ExecutionProspective {
        self.setup_traced_prospective
    }

    /// Exact trace capacity reserved during session preparation.
    #[must_use]
    pub const fn trace_capacity(&self) -> usize {
        self.trace_capacity
    }

    /// Selected pattern ordinals and spans in source order.
    #[must_use]
    pub const fn matches(&self) -> &[PriorityMatch] {
        self.matches
    }

    /// Check the setup-to-steady transition and the borrowing trace receipt.
    #[must_use]
    pub fn closes(&self) -> bool {
        let trace_bytes = self.trace_capacity.checked_mul(size_of::<PriorityMatch>());
        let trace_work = u64::try_from(self.trace_capacity)
            .ok()
            .and_then(|work| work.checked_add(1));
        let setup_trace_closes = trace_bytes.zip(trace_work).is_some_and(|(bytes, work)| {
            let mut expected = self.setup_untraced_prospective;
            let Some(scratch_bytes) = expected.scratch_bytes.checked_add(bytes) else {
                return false;
            };
            let Some(allocation_attempts) = expected.allocation_attempts.checked_add(1) else {
                return false;
            };
            let Some(work_upper_bound) = expected.work_upper_bound.checked_add(work) else {
                return false;
            };
            expected.scratch_bytes = scratch_bytes;
            expected.allocation_attempts = allocation_attempts;
            expected.work_upper_bound = work_upper_bound;
            expected == self.setup_traced_prospective
        });
        let mut expected_untraced = self.setup_untraced_prospective;
        expected_untraced.allocation_attempts = 0;
        let mut expected_traced = self.setup_traced_prospective;
        expected_traced.allocation_attempts = 0;
        let traced = self.report.prospective();
        let actual = self.report.actual();
        setup_trace_closes
            && self.setup.closes()
            && self.setup.steady_untraced_prospective == self.untraced_prospective
            && self.setup.steady_traced_prospective == traced
            && self.setup.trace_capacity == self.trace_capacity
            && self.trace_capacity == self.setup_untraced_prospective.match_events_upper_bound
            && self.untraced_prospective == expected_untraced
            && traced == expected_traced
            && traced.tagged_execution_class == self.untraced_prospective.tagged_execution_class
            && traced.boundary_rows == self.untraced_prospective.boundary_rows
            && traced.match_events_upper_bound == self.untraced_prospective.match_events_upper_bound
            && actual.scratch_bytes == traced.scratch_bytes
            && actual.allocation_attempts == 0
            && actual.work <= traced.work_upper_bound
            && self.matches.len() == actual.match_events
            && actual.match_events <= self.trace_capacity
    }
}

impl<O: DirectReduceValue> TaggedManyPlan<O> {
    /// Compute source-independent run bounds before reading source bytes.
    pub fn prospective(
        &self,
        haystack_bytes: usize,
        limits: DirectReduceLimits,
    ) -> Result<ExecutionProspective, ReduceError> {
        tagged_prospective(self, haystack_bytes, limits, false)
    }

    /// Execute the fixed shared tagged route without retaining a trace.
    pub fn execute(
        &self,
        haystack: &[u8],
        limits: DirectReduceLimits,
    ) -> Result<DirectReduceReport<O::Output>, ReduceError> {
        let prospective = tagged_prospective(self, haystack.len(), limits, false)?;
        let (output, actual, trace) = execute_tagged(self, haystack, limits, prospective, None)?;
        if trace.is_some() {
            return Err(ReduceError::InternalInvariant {
                detail: "untraced tagged execution retained a trace",
            });
        }
        finish_tagged_report(haystack.len(), output, prospective, &actual)
    }

    /// Execute with an independently admitted ordinal/span trace.
    pub fn execute_trace(
        &self,
        haystack: &[u8],
        limits: DirectReduceLimits,
    ) -> Result<DirectReduceTraceReport<O::Output>, ReduceError> {
        let untraced = tagged_prospective(self, haystack.len(), limits, false)?;
        let traced = tagged_prospective(self, haystack.len(), limits, true)?;
        let (output, actual, trace) = execute_tagged(
            self,
            haystack,
            limits,
            traced,
            Some(untraced.match_events_upper_bound),
        )?;
        let report = finish_tagged_report(haystack.len(), output, traced, &actual)?;
        let trace = trace.ok_or(ReduceError::InternalInvariant {
            detail: "traced tagged execution omitted its trace",
        })?;
        let report = DirectReduceTraceReport::from_parts(report, untraced, trace);
        if !report.closes() {
            return Err(ReduceError::InternalInvariant {
                detail: "tagged trace receipt did not close",
            });
        }
        Ok(report)
    }

    /// Prepare one caller-owned ordinal trace session for a fixed source
    /// length. All trace and tagged-frontier storage is reserved here, before
    /// any source bytes are supplied. Repeated executions of the returned
    /// session perform no fresh workspace or trace allocation.
    pub fn prepare_trace_session(
        &self,
        source_bytes: usize,
        limits: DirectReduceLimits,
    ) -> Result<TaggedManyTraceSession<'_, O>, ReduceError> {
        TaggedManyTraceSession::new(self, source_bytes, limits)
    }

    /// Preflight the exact one-time storage and initialization census for a
    /// reusable ordinal trace session without allocating its workspace.
    ///
    /// Unlike [`Self::trace_session_prospective`], this receipt distinguishes
    /// retained-session construction from a one-shot direct operation and
    /// excludes zero-capacity `Vec` reservations from its allocation count.
    pub fn trace_session_setup_prospective(
        &self,
        source_bytes: usize,
        limits: DirectReduceLimits,
    ) -> Result<TaggedManyTraceSessionSetupProspective, ReduceError> {
        trace_session_setup_prospective(self, source_bytes, limits)
    }

    /// Return the untraced and traced one-time envelopes needed to prepare a
    /// reusable trace session, without allocating its workspace.
    ///
    /// This compatibility API retains its historical one-shot
    /// [`ExecutionProspective`] values. New code that needs exact retained
    /// workspace accounting should use [`Self::trace_session_setup_prospective`].
    pub fn trace_session_prospective(
        &self,
        source_bytes: usize,
        limits: DirectReduceLimits,
    ) -> Result<(ExecutionProspective, ExecutionProspective), ReduceError> {
        Ok((
            tagged_prospective(self, source_bytes, limits, false)?,
            tagged_prospective(self, source_bytes, limits, true)?,
        ))
    }
}

impl<'plan, O: DirectReduceValue> TaggedManyTraceSession<'plan, O> {
    fn new(
        plan: &'plan TaggedManyPlan<O>,
        source_bytes: usize,
        limits: DirectReduceLimits,
    ) -> Result<Self, ReduceError> {
        let setup = plan.trace_session_setup_prospective(source_bytes, limits)?;
        // Keep the old one-shot values available to existing callers, but do
        // not let their fixed one-shot allocation census reject a session
        // whose exact construction census has already been admitted above.
        let allocation_relaxed = DirectReduceLimits {
            max_allocation_attempts: usize::MAX,
            ..limits
        };
        let (setup_untraced_prospective, setup_traced_prospective) =
            plan.trace_session_prospective(source_bytes, allocation_relaxed)?;
        let trace_capacity = setup.trace_capacity;
        let workspace = match plan.stats.execution_class {
            TaggedManyExecutionClass::Generic => {
                let states = plan.states.len();
                let map_capacity =
                    states
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "tagged session map capacity",
                        })?;
                let group_capacity = plan.stats.owner_state_memberships;
                TaggedManyTraceWorkspace::Generic(TaggedManyGenericTraceWorkspace {
                    current_rows: reserve_and_fill_run(
                        states,
                        0u32,
                        "tagged trace session current rows",
                    )?,
                    next_rows: reserve_and_fill_run(
                        states,
                        0u32,
                        "tagged trace session next rows",
                    )?,
                    roots: reserve_and_fill_run(
                        setup.steady_traced_prospective.boundary_rows,
                        None::<TaggedOutcome>,
                        "tagged trace session roots",
                    )?,
                    current_pool: OutcomePool::new(map_capacity, group_capacity)?,
                    next_pool: OutcomePool::new(map_capacity, group_capacity)?,
                    trace: reserve_run(trace_capacity, "tagged trace session entries")?,
                })
            }
            TaggedManyExecutionClass::SharedFrontierUniformRangeChain { .. } => {
                TaggedManyTraceWorkspace::SharedFrontier {
                    trace: reserve_run(trace_capacity, "tagged shared-frontier session entries")?,
                }
            }
        };
        let session = Self {
            plan,
            source_bytes,
            limits,
            setup,
            setup_untraced_prospective,
            setup_traced_prospective,
            untraced_prospective: setup.steady_untraced_prospective,
            prospective: setup.steady_traced_prospective,
            workspace,
        };
        if !session.closes() {
            return Err(ReduceError::InternalInvariant {
                detail: "reusable tagged trace-session setup did not close",
            });
        }
        Ok(session)
    }

    /// Source length to which this retained workspace is bound.
    #[must_use]
    pub const fn source_bytes(&self) -> usize {
        self.source_bytes
    }

    /// Immutable run limits admitted when this session was prepared.
    #[must_use]
    pub const fn limits(&self) -> DirectReduceLimits {
        self.limits
    }

    /// Exact preflight receipt for the retained caller-owned workspace.
    #[must_use]
    pub const fn setup(&self) -> TaggedManyTraceSessionSetupProspective {
        self.setup
    }

    /// Alias for [`Self::setup`] that makes the preflight relationship
    /// explicit at call sites.
    #[must_use]
    pub const fn setup_prospective_receipt(&self) -> TaggedManyTraceSessionSetupProspective {
        self.setup()
    }

    /// Legacy traced one-shot comparison envelope.
    ///
    /// For exact retained-session construction accounting, use [`Self::setup`].
    #[must_use]
    pub const fn setup_prospective(&self) -> ExecutionProspective {
        self.setup_traced_prospective
    }

    /// Repeated-operation trace envelope. Its allocation count is always zero:
    /// construction allocations are represented only by [`Self::setup_prospective`].
    #[must_use]
    pub const fn prospective(&self) -> ExecutionProspective {
        self.prospective
    }

    /// Validate the retained workspace against its exact setup receipt.
    #[must_use]
    pub fn closes(&self) -> bool {
        if !self.setup.closes()
            || self.setup.source_bytes != self.source_bytes
            || self.setup.steady_untraced_prospective != self.untraced_prospective
            || self.setup.steady_traced_prospective != self.prospective
            || self.setup.trace_capacity != self.prospective.match_events_upper_bound
            || self.setup.persistent_bytes != self.prospective.scratch_bytes
        {
            return false;
        }
        match &self.workspace {
            TaggedManyTraceWorkspace::Generic(workspace) => {
                if self.plan.stats.execution_class != TaggedManyExecutionClass::Generic {
                    return false;
                }
                let states = self.plan.states.len();
                let Some(map_capacity) = states.checked_add(1) else {
                    return false;
                };
                let group_capacity = self.plan.stats.owner_state_memberships;
                workspace.current_rows.len() == states
                    && workspace.current_rows.capacity() == states
                    && workspace.next_rows.len() == states
                    && workspace.next_rows.capacity() == states
                    && workspace.roots.len() == self.prospective.boundary_rows
                    && workspace.roots.capacity() == self.prospective.boundary_rows
                    && workspace.current_pool.has_exact_capacity()
                    && workspace.next_pool.has_exact_capacity()
                    && workspace.current_pool.map_capacity == map_capacity
                    && workspace.current_pool.group_capacity == group_capacity
                    && workspace.next_pool.map_capacity == map_capacity
                    && workspace.next_pool.group_capacity == group_capacity
                    && workspace.trace.capacity() == self.setup.trace_capacity
            }
            TaggedManyTraceWorkspace::SharedFrontier { trace } => {
                matches!(
                    self.plan.stats.execution_class,
                    TaggedManyExecutionClass::SharedFrontierUniformRangeChain { .. }
                ) && trace.capacity() == self.setup.trace_capacity
            }
        }
    }

    /// Execute one ordinal trace without rebuilding its fixed-length workspace.
    pub fn execute_trace(
        &mut self,
        haystack: &[u8],
    ) -> Result<TaggedManyTraceSessionReport<'_, O::Output>, ReduceError> {
        if haystack.len() != self.source_bytes {
            return Err(ReduceError::InternalInvariant {
                detail: "tagged trace session haystack length differs from its admitted workspace",
            });
        }
        if !self.closes() {
            return Err(ReduceError::InternalInvariant {
                detail: "reusable tagged trace-session setup receipt did not close",
            });
        }
        let plan = self.plan;
        let limits = self.limits;
        let prospective = self.prospective;
        let (output, actual, matches) = match &mut self.workspace {
            TaggedManyTraceWorkspace::Generic(workspace) => {
                let (output, actual) =
                    execute_tagged_generic_reused(plan, haystack, limits, prospective, workspace)?;
                (output, actual, workspace.trace.as_slice())
            }
            TaggedManyTraceWorkspace::SharedFrontier { trace } => {
                let (output, actual) =
                    execute_shared_frontier_reused(plan, haystack, limits, prospective, trace)?;
                (output, actual, trace.as_slice())
            }
        };
        let report = finish_tagged_report(haystack.len(), output, prospective, &actual)?;
        let receipt = TaggedManyTraceSessionReport {
            report,
            setup: self.setup,
            untraced_prospective: self.untraced_prospective,
            setup_untraced_prospective: self.setup_untraced_prospective,
            setup_traced_prospective: self.setup_traced_prospective,
            matches,
            trace_capacity: self.setup_untraced_prospective.match_events_upper_bound,
        };
        if !receipt.closes() {
            return Err(ReduceError::InternalInvariant {
                detail: "reusable tagged trace session receipt did not close",
            });
        }
        Ok(receipt)
    }
}

fn tagged_prospective<O: DirectReduceValue>(
    plan: &TaggedManyPlan<O>,
    haystack_bytes: usize,
    limits: DirectReduceLimits,
    trace: bool,
) -> Result<ExecutionProspective, ReduceError> {
    let boundary_rows = haystack_bytes
        .checked_add(1)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "tagged boundary rows",
        })?;
    if boundary_rows > limits.max_boundary_rows {
        return Err(ReduceError::BoundaryRowsLimit {
            needed: boundary_rows,
            limit: limits.max_boundary_rows,
        });
    }
    if boundary_rows > limits.max_match_events {
        return Err(ReduceError::MatchEventsLimit {
            needed: boundary_rows,
            limit: limits.max_match_events,
        });
    }
    match plan.stats.execution_class {
        TaggedManyExecutionClass::SharedFrontierUniformRangeChain { .. } => {
            return shared_frontier_prospective(plan, haystack_bytes, boundary_rows, limits, trace);
        }
        TaggedManyExecutionClass::Generic => {}
    }
    let states = plan.states.len();
    let patterns = plan.starts.len();
    let map_capacity = states
        .checked_add(1)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "tagged map capacity",
        })?;
    let group_capacity = plan.stats.owner_state_memberships;
    let mut scratch_bytes =
        tagged_run_scratch(states, boundary_rows, map_capacity, group_capacity)?;
    let mut allocation_attempts = RUN_ALLOCATION_ATTEMPTS;
    let mut work_upper_bound = tagged_run_work(plan, boundary_rows, map_capacity, group_capacity)?;
    if trace {
        let trace_bytes = boundary_rows
            .checked_mul(size_of::<PriorityMatch>())
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "tagged trace bytes",
            })?;
        scratch_bytes =
            scratch_bytes
                .checked_add(trace_bytes)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "tagged traced scratch",
                })?;
        allocation_attempts =
            allocation_attempts
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "tagged traced allocation attempts",
                })?;
        work_upper_bound = work_upper_bound
            .checked_add(
                u64::try_from(boundary_rows)
                    .map_err(|_| ReduceError::ArithmeticOverflow {
                        computation: "tagged trace work conversion",
                    })?
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "tagged trace work",
                    })?,
            )
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "tagged traced work upper bound",
            })?;
    }
    if scratch_bytes > limits.max_scratch_bytes {
        return Err(ReduceError::ScratchLimit {
            needed: scratch_bytes,
            limit: limits.max_scratch_bytes,
        });
    }
    if allocation_attempts > limits.max_allocation_attempts {
        return Err(ReduceError::AllocationAttemptsLimit {
            needed: allocation_attempts,
            limit: limits.max_allocation_attempts,
        });
    }
    if work_upper_bound > limits.max_work {
        return Err(ReduceError::WorkLimit {
            consumed: 0,
            requested: work_upper_bound,
            limit: limits.max_work,
        });
    }
    Ok(ExecutionProspective {
        tagged_execution_class: Some(plan.stats.execution_class),
        work_upper_bound,
        scratch_bytes,
        boundary_rows,
        match_events_upper_bound: boundary_rows,
        dfa_states_capacity: 0,
        dfa_cells_capacity: 0,
        subset_items_capacity: 0,
        tagged_state_evaluations_upper_bound: boundary_rows.checked_mul(states).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "tagged state evaluation bound",
            },
        )?,
        tagged_edge_visits_upper_bound: boundary_rows.checked_mul(plan.edges.len()).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "tagged edge visit bound",
            },
        )?,
        tagged_map_capacity: map_capacity,
        tagged_group_capacity: group_capacity,
        tagged_group_publications_upper_bound: boundary_rows.checked_mul(group_capacity).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "tagged group publication bound",
            },
        )?,
        tagged_owner_capacity: patterns,
        tagged_dispatch_states_capacity: 0,
        tagged_dispatch_cells_capacity: 0,
        tagged_candidate_items_capacity: 0,
        tagged_cache_cells_capacity: 0,
        allocation_attempts,
    })
}

fn shared_frontier_prospective<O: DirectReduceValue>(
    plan: &TaggedManyPlan<O>,
    haystack_bytes: usize,
    boundary_rows: usize,
    limits: DirectReduceLimits,
    trace: bool,
) -> Result<ExecutionProspective, ReduceError> {
    let mut scratch_bytes = 0usize;
    let mut allocation_attempts = SHARED_FRONTIER_RUN_ALLOCATION_ATTEMPTS;
    let mut work_upper_bound = shared_frontier_run_work(haystack_bytes, boundary_rows, false)?;
    if trace {
        let trace_bytes = boundary_rows
            .checked_mul(size_of::<PriorityMatch>())
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "tagged shared-frontier trace bytes",
            })?;
        scratch_bytes = trace_bytes;
        allocation_attempts =
            allocation_attempts
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "tagged shared-frontier allocation attempts",
                })?;
        work_upper_bound = shared_frontier_run_work(haystack_bytes, boundary_rows, true)?;
    }
    if scratch_bytes > limits.max_scratch_bytes {
        return Err(ReduceError::ScratchLimit {
            needed: scratch_bytes,
            limit: limits.max_scratch_bytes,
        });
    }
    if allocation_attempts > limits.max_allocation_attempts {
        return Err(ReduceError::AllocationAttemptsLimit {
            needed: allocation_attempts,
            limit: limits.max_allocation_attempts,
        });
    }
    if work_upper_bound > limits.max_work {
        return Err(ReduceError::WorkLimit {
            consumed: 0,
            requested: work_upper_bound,
            limit: limits.max_work,
        });
    }
    Ok(ExecutionProspective {
        tagged_execution_class: Some(plan.stats.execution_class),
        work_upper_bound,
        scratch_bytes,
        boundary_rows,
        match_events_upper_bound: boundary_rows,
        dfa_states_capacity: 0,
        dfa_cells_capacity: 0,
        subset_items_capacity: 0,
        // The event-driven chain evaluates one physical class predicate per
        // input byte. It never revisits every shared state for a boundary.
        tagged_state_evaluations_upper_bound: haystack_bytes,
        tagged_edge_visits_upper_bound: haystack_bytes,
        tagged_map_capacity: 0,
        tagged_group_capacity: 0,
        tagged_group_publications_upper_bound: 0,
        tagged_owner_capacity: plan.starts.len(),
        tagged_dispatch_states_capacity: 0,
        tagged_dispatch_cells_capacity: 0,
        tagged_candidate_items_capacity: 0,
        tagged_cache_cells_capacity: 0,
        allocation_attempts,
    })
}

fn shared_frontier_run_work(
    haystack_bytes: usize,
    boundary_rows: usize,
    trace: bool,
) -> Result<u64, ReduceError> {
    let byte_events =
        u64::try_from(haystack_bytes).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "tagged shared-frontier byte work",
        })?;
    let boundary_events =
        u64::try_from(boundary_rows).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "tagged shared-frontier boundary work",
        })?;
    let mut work =
        byte_events
            .checked_add(boundary_events)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "tagged shared-frontier match work",
            })?;
    if trace {
        work =
            work.checked_add(boundary_events.checked_add(1).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "tagged shared-frontier trace allocation work",
                },
            )?)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "tagged shared-frontier trace work",
            })?;
    }
    Ok(work)
}

fn tagged_run_scratch(
    states: usize,
    boundaries: usize,
    map_capacity: usize,
    group_capacity: usize,
) -> Result<usize, ReduceError> {
    let mut total = states
        .checked_mul(size_of::<u32>())
        .and_then(|bytes| bytes.checked_mul(2))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "tagged row scratch",
        })?;
    for bytes in [
        boundaries
            .checked_mul(size_of::<Option<TaggedOutcome>>())
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "tagged root scratch",
            })?,
        map_capacity
            .checked_mul(size_of::<MapDesc>())
            .and_then(|bytes| bytes.checked_mul(2))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "tagged map scratch",
            })?,
        group_capacity
            .checked_mul(size_of::<OutcomeGroup>())
            .and_then(|bytes| bytes.checked_mul(2))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "tagged group scratch",
            })?,
    ] {
        total = total
            .checked_add(bytes)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "tagged total run scratch",
            })?;
    }
    Ok(total)
}

fn tagged_run_work<O: DirectReduceValue>(
    plan: &TaggedManyPlan<O>,
    boundaries: usize,
    map_capacity: usize,
    group_capacity: usize,
) -> Result<u64, ReduceError> {
    let states = u64::try_from(plan.states.len()).map_err(|_| ReduceError::ArithmeticOverflow {
        computation: "tagged run state work",
    })?;
    let edges = u64::try_from(plan.edges.len()).map_err(|_| ReduceError::ArithmeticOverflow {
        computation: "tagged run edge work",
    })?;
    let patterns =
        u64::try_from(plan.starts.len()).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "tagged run owner work",
        })?;
    let boundaries = u64::try_from(boundaries).map_err(|_| ReduceError::ArithmeticOverflow {
        computation: "tagged run boundary work",
    })?;
    let owner_memberships = u64::try_from(plan.stats.owner_state_memberships).map_err(|_| {
        ReduceError::ArithmeticOverflow {
            computation: "tagged run owner-membership work",
        }
    })?;
    let per_boundary = edges
        .checked_mul(
            patterns
                .checked_mul(2)
                .and_then(|v| v.checked_add(2))
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "tagged run owner work",
                })?,
        )
        .and_then(|value| {
            states
                .checked_mul(6)
                .and_then(|tail| value.checked_add(tail))
        })
        .and_then(|value| {
            owner_memberships
                .checked_mul(3)
                .and_then(|tail| value.checked_add(tail))
        })
        .and_then(|value| value.checked_add(patterns))
        .and_then(|value| value.checked_add(64))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "tagged per-boundary work upper bound",
        })?;
    let setup = u64::try_from(
        plan.states
            .len()
            .checked_mul(2)
            .and_then(|value| value.checked_add(map_capacity.checked_mul(2)?))
            .and_then(|value| value.checked_add(group_capacity.checked_mul(2)?))
            .and_then(|value| value.checked_add(plan.starts.len()))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "tagged run setup slots",
            })?,
    )
    .map_err(|_| ReduceError::ArithmeticOverflow {
        computation: "tagged run setup work conversion",
    })?;
    boundaries
        .checked_mul(per_boundary)
        .and_then(|value| value.checked_add(setup))
        .and_then(|value| value.checked_add(boundaries))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "tagged run work upper bound",
        })
}

#[allow(clippy::type_complexity, clippy::too_many_lines)]
fn execute_tagged<O: DirectReduceValue>(
    plan: &TaggedManyPlan<O>,
    haystack: &[u8],
    limits: DirectReduceLimits,
    prospective: ExecutionProspective,
    trace_capacity: Option<usize>,
) -> Result<(O::Output, ExecutionActual, Option<Vec<PriorityMatch>>), ReduceError> {
    if prospective.tagged_execution_class != Some(plan.stats.execution_class)
        || prospective.tagged_dispatch_states_capacity != 0
        || prospective.tagged_dispatch_cells_capacity != 0
        || prospective.tagged_candidate_items_capacity != 0
        || prospective.tagged_cache_cells_capacity != 0
    {
        return Err(ReduceError::InternalInvariant {
            detail: "tagged execution prospective crossed the ordinary-kernel schema boundary",
        });
    }
    match plan.stats.execution_class {
        TaggedManyExecutionClass::SharedFrontierUniformRangeChain {
            depth,
            byte_start,
            byte_end,
        } => {
            return execute_shared_frontier::<O>(
                depth,
                byte_start,
                byte_end,
                haystack,
                limits,
                prospective,
                trace_capacity,
            );
        }
        TaggedManyExecutionClass::Generic => {}
    }
    let states = plan.states.len();
    let map_capacity = states
        .checked_add(1)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "tagged execution map capacity",
        })?;
    let group_capacity = plan.stats.owner_state_memberships;
    let mut meter = RunMeter::new(limits.max_work);
    let setup_slots = states
        .checked_mul(2)
        .and_then(|value| value.checked_add(prospective.boundary_rows))
        .and_then(|value| value.checked_add(map_capacity.checked_mul(2)?))
        .and_then(|value| value.checked_add(group_capacity.checked_mul(2)?))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "tagged execution setup slots",
        })?;
    meter.charge_usize(setup_slots)?;
    let mut current_rows = reserve_and_fill_run(states, 0u32, "tagged current rows")?;
    let mut next_rows = reserve_and_fill_run(states, 0u32, "tagged next rows")?;
    let mut roots = reserve_and_fill_run(
        prospective.boundary_rows,
        None::<TaggedOutcome>,
        "tagged roots",
    )?;
    let mut current_pool = OutcomePool::new(map_capacity, group_capacity)?;
    let mut next_pool = OutcomePool::new(map_capacity, group_capacity)?;
    next_pool.reset(&mut meter)?;
    let mut trace = match trace_capacity {
        Some(capacity) => {
            meter.charge(1)?;
            Some(reserve_run(capacity, "tagged trace")?)
        }
        None => None,
    };
    let mut actual = ExecutionActual::zero(haystack.len());
    actual.scratch_bytes = prospective.scratch_bytes;
    actual.allocation_attempts = prospective.allocation_attempts;
    let mut candidate = OutcomeCandidate::new();

    for position in (0..=haystack.len()).rev() {
        meter.charge(1)?;
        actual.boundary_rows =
            actual
                .boundary_rows
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "tagged boundary rows",
                })?;
        current_pool.reset(&mut meter)?;
        meter.charge_usize(states)?;
        current_rows.fill(0);
        let byte = haystack.get(position).copied();
        for &state_u32 in plan.evaluation_order.iter() {
            meter.charge(1)?;
            actual.tagged_state_evaluations = actual
                .tagged_state_evaluations
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "tagged state evaluations",
                })?;
            let state_index = plan_index(state_u32);
            let state = plan.states[state_index];
            candidate.clear();
            let mut remaining = state.owners;
            match state.role {
                StateRole::Accept => {
                    candidate.insert(remaining, position, &mut meter)?;
                }
                StateRole::Consume => {
                    if let Some(byte) = byte {
                        for edge_index in plan_index(state.edge_start)..plan_index(state.edge_end) {
                            meter.charge(1)?;
                            actual.tagged_edge_visits = actual
                                .tagged_edge_visits
                                .checked_add(1)
                                .ok_or(ReduceError::ArithmeticOverflow {
                                    computation: "tagged consuming edge visits",
                                })?;
                            let edge = plan.edges[edge_index];
                            if byte < edge.byte_start || byte > edge.byte_end {
                                continue;
                            }
                            let allowed = remaining & edge.owners;
                            if allowed == 0 {
                                continue;
                            }
                            let target_map = next_rows[plan_index(edge.target)];
                            let mut matched = 0u128;
                            for group in next_pool.map_groups(target_map)? {
                                meter.charge(1)?;
                                let owners = allowed & group.owners;
                                if owners != 0 {
                                    candidate.insert(owners, group.end, &mut meter)?;
                                    matched |= owners;
                                }
                            }
                            remaining &= !matched;
                            if remaining == 0 {
                                break;
                            }
                        }
                    }
                }
                StateRole::Split => {
                    for edge_index in plan_index(state.edge_start)..plan_index(state.edge_end) {
                        meter.charge(1)?;
                        actual.tagged_edge_visits = actual
                            .tagged_edge_visits
                            .checked_add(1)
                            .ok_or(ReduceError::ArithmeticOverflow {
                                computation: "tagged zero-width edge visits",
                            })?;
                        let edge = plan.edges[edge_index];
                        let allowed = remaining & edge.owners;
                        if allowed == 0 {
                            continue;
                        }
                        let enabled = zero_width_edge_enabled_with_line_terminator(
                            plan.line_terminator,
                            edge.kind,
                            haystack,
                            position,
                        )
                        .map_err(|_| ReduceError::InternalInvariant {
                            detail: "tagged zero-width assertion evaluation failed",
                        })?;
                        if !enabled {
                            continue;
                        }
                        let target_map = current_rows[plan_index(edge.target)];
                        let mut matched = 0u128;
                        for group in current_pool.map_groups(target_map)? {
                            meter.charge(1)?;
                            let owners = allowed & group.owners;
                            if owners != 0 {
                                candidate.insert(owners, group.end, &mut meter)?;
                                matched |= owners;
                            }
                        }
                        remaining &= !matched;
                        if remaining == 0 {
                            break;
                        }
                    }
                }
            }
            if state.start_owners != 0 {
                for group in candidate.as_slice() {
                    meter.charge(1)?;
                    let owners = group.owners & state.start_owners;
                    if owners == 0 {
                        continue;
                    }
                    let ordinal = owners.trailing_zeros();
                    let replace =
                        roots[position].map_or(true, |selected| ordinal < selected.ordinal.get());
                    if replace {
                        roots[position] = Some(TaggedOutcome {
                            ordinal: PatternOrdinal::new(ordinal),
                            end: group.end,
                        });
                    }
                }
            }
            current_rows[state_index] =
                current_pool.publish(candidate.as_slice(), &mut meter, &mut actual)?;
        }
        if let Some(selected) = roots[position] {
            let start = plan.starts[usize::try_from(selected.ordinal.get()).map_err(|_| {
                ReduceError::ArithmeticOverflow {
                    computation: "tagged selected start ordinal",
                }
            })?];
            let map = current_rows[plan_index(start)];
            let mut authenticated = false;
            for group in current_pool.map_groups(map)? {
                meter.charge(1)?;
                if group.owners & (1u128 << selected.ordinal.get()) != 0
                    && group.end == selected.end
                {
                    authenticated = true;
                    break;
                }
            }
            if !authenticated {
                return Err(ReduceError::InternalInvariant {
                    detail: "tagged start-owner selection did not authenticate its row",
                });
            }
        }
        core::mem::swap(&mut current_rows, &mut next_rows);
        core::mem::swap(&mut current_pool, &mut next_pool);
    }

    let mut output = O::zero();
    let mut position = 0usize;
    let mut suppress_empty_at = None::<usize>;
    while position <= haystack.len() {
        meter.charge(1)?;
        let Some(outcome) = roots[position] else {
            if position == haystack.len() {
                break;
            }
            position = position
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "tagged reducer progress",
                })?;
            continue;
        };
        if outcome.end == position && suppress_empty_at == Some(position) {
            if position == haystack.len() {
                break;
            }
            position = position
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "tagged suppressed empty progress",
                })?;
            continue;
        }
        if trace.is_some() {
            meter.charge(1)?;
        }
        record_tagged_match(&mut actual, outcome, position, limits.max_match_events)?;
        output = O::append(output, position, outcome.end, outcome.ordinal)?;
        if let Some(trace) = trace.as_mut() {
            trace.push(PriorityMatch::from_parts(
                outcome.ordinal,
                position,
                outcome.end,
            ));
        }
        if outcome.end == position {
            if position == haystack.len() {
                break;
            }
            position = position
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "tagged empty-match progress",
                })?;
        } else {
            suppress_empty_at = Some(outcome.end);
            position = outcome.end;
        }
    }
    actual.work = meter.consumed;
    Ok((output, actual, trace))
}

/// Re-run the generic tagged kernel using storage admitted by a
/// [`TaggedManyTraceSession`]. The fixed vectors are cleared/reset in place;
/// no call in this function can grow them.
#[allow(clippy::too_many_lines)]
fn execute_tagged_generic_reused<O: DirectReduceValue>(
    plan: &TaggedManyPlan<O>,
    haystack: &[u8],
    limits: DirectReduceLimits,
    prospective: ExecutionProspective,
    workspace: &mut TaggedManyGenericTraceWorkspace,
) -> Result<(O::Output, ExecutionActual), ReduceError> {
    if prospective.tagged_execution_class != Some(TaggedManyExecutionClass::Generic)
        || prospective.tagged_dispatch_states_capacity != 0
        || prospective.tagged_dispatch_cells_capacity != 0
        || prospective.tagged_candidate_items_capacity != 0
        || prospective.tagged_cache_cells_capacity != 0
        || plan.stats.execution_class != TaggedManyExecutionClass::Generic
    {
        return Err(ReduceError::InternalInvariant {
            detail: "reusable tagged trace session crossed the generic-kernel schema boundary",
        });
    }
    let states = plan.states.len();
    let map_capacity = states
        .checked_add(1)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "reusable tagged session map capacity",
        })?;
    let group_capacity = plan.stats.owner_state_memberships;
    let trace_capacity = prospective.match_events_upper_bound;
    if workspace.current_rows.len() != states
        || workspace.current_rows.capacity() != states
        || workspace.next_rows.len() != states
        || workspace.next_rows.capacity() != states
        || workspace.roots.len() != prospective.boundary_rows
        || workspace.roots.capacity() != prospective.boundary_rows
        || !workspace.current_pool.has_exact_capacity()
        || !workspace.next_pool.has_exact_capacity()
        || workspace.current_pool.map_capacity != map_capacity
        || workspace.current_pool.group_capacity != group_capacity
        || workspace.next_pool.map_capacity != map_capacity
        || workspace.next_pool.group_capacity != group_capacity
        || workspace.trace.capacity() != trace_capacity
    {
        return Err(ReduceError::InternalInvariant {
            detail: "reusable tagged trace session workspace no longer matches its admission",
        });
    }

    let mut meter = RunMeter::new(limits.max_work);
    let setup_slots = states
        .checked_mul(2)
        .and_then(|value| value.checked_add(prospective.boundary_rows))
        .and_then(|value| value.checked_add(map_capacity.checked_mul(2)?))
        .and_then(|value| value.checked_add(group_capacity.checked_mul(2)?))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "reusable tagged session setup slots",
        })?;
    meter.charge_usize(setup_slots)?;
    // These fills are the retained-storage equivalent of one-shot exact
    // initialization. Their work is already covered by `setup_slots`.
    workspace.roots.fill(None);
    workspace.next_rows.fill(0);
    workspace.next_pool.reset(&mut meter)?;
    workspace.trace.clear();
    // Preserve the existing trace-sidecar work charge. It now covers reset of
    // the admitted trace buffer rather than a fresh allocation.
    meter.charge(1)?;

    let mut actual = ExecutionActual::zero(haystack.len());
    actual.scratch_bytes = prospective.scratch_bytes;
    actual.allocation_attempts = prospective.allocation_attempts;
    let mut candidate = OutcomeCandidate::new();

    for position in (0..=haystack.len()).rev() {
        meter.charge(1)?;
        actual.boundary_rows =
            actual
                .boundary_rows
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "reusable tagged session boundary rows",
                })?;
        workspace.current_pool.reset(&mut meter)?;
        meter.charge_usize(states)?;
        workspace.current_rows.fill(0);
        let byte = haystack.get(position).copied();
        for &state_u32 in plan.evaluation_order.iter() {
            meter.charge(1)?;
            actual.tagged_state_evaluations = actual
                .tagged_state_evaluations
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "reusable tagged session state evaluations",
                })?;
            let state_index = plan_index(state_u32);
            let state = plan.states[state_index];
            candidate.clear();
            let mut remaining = state.owners;
            match state.role {
                StateRole::Accept => {
                    candidate.insert(remaining, position, &mut meter)?;
                }
                StateRole::Consume => {
                    if let Some(byte) = byte {
                        for edge_index in plan_index(state.edge_start)..plan_index(state.edge_end) {
                            meter.charge(1)?;
                            actual.tagged_edge_visits = actual
                                .tagged_edge_visits
                                .checked_add(1)
                                .ok_or(ReduceError::ArithmeticOverflow {
                                    computation: "reusable tagged session consuming edge visits",
                                })?;
                            let edge = plan.edges[edge_index];
                            if byte < edge.byte_start || byte > edge.byte_end {
                                continue;
                            }
                            let allowed = remaining & edge.owners;
                            if allowed == 0 {
                                continue;
                            }
                            let target_map = workspace.next_rows[plan_index(edge.target)];
                            let mut matched = 0u128;
                            for group in workspace.next_pool.map_groups(target_map)? {
                                meter.charge(1)?;
                                let owners = allowed & group.owners;
                                if owners != 0 {
                                    candidate.insert(owners, group.end, &mut meter)?;
                                    matched |= owners;
                                }
                            }
                            remaining &= !matched;
                            if remaining == 0 {
                                break;
                            }
                        }
                    }
                }
                StateRole::Split => {
                    for edge_index in plan_index(state.edge_start)..plan_index(state.edge_end) {
                        meter.charge(1)?;
                        actual.tagged_edge_visits = actual
                            .tagged_edge_visits
                            .checked_add(1)
                            .ok_or(ReduceError::ArithmeticOverflow {
                                computation: "reusable tagged session zero-width edge visits",
                            })?;
                        let edge = plan.edges[edge_index];
                        let allowed = remaining & edge.owners;
                        if allowed == 0 {
                            continue;
                        }
                        let enabled = zero_width_edge_enabled_with_line_terminator(
                            plan.line_terminator,
                            edge.kind,
                            haystack,
                            position,
                        )
                        .map_err(|_| ReduceError::InternalInvariant {
                            detail:
                                "reusable tagged session zero-width assertion evaluation failed",
                        })?;
                        if !enabled {
                            continue;
                        }
                        let target_map = workspace.current_rows[plan_index(edge.target)];
                        let mut matched = 0u128;
                        for group in workspace.current_pool.map_groups(target_map)? {
                            meter.charge(1)?;
                            let owners = allowed & group.owners;
                            if owners != 0 {
                                candidate.insert(owners, group.end, &mut meter)?;
                                matched |= owners;
                            }
                        }
                        remaining &= !matched;
                        if remaining == 0 {
                            break;
                        }
                    }
                }
            }
            if state.start_owners != 0 {
                for group in candidate.as_slice() {
                    meter.charge(1)?;
                    let owners = group.owners & state.start_owners;
                    if owners == 0 {
                        continue;
                    }
                    let ordinal = owners.trailing_zeros();
                    let replace = workspace.roots[position]
                        .map_or(true, |selected| ordinal < selected.ordinal.get());
                    if replace {
                        workspace.roots[position] = Some(TaggedOutcome {
                            ordinal: PatternOrdinal::new(ordinal),
                            end: group.end,
                        });
                    }
                }
            }
            workspace.current_rows[state_index] =
                workspace
                    .current_pool
                    .publish(candidate.as_slice(), &mut meter, &mut actual)?;
        }
        if let Some(selected) = workspace.roots[position] {
            let start = plan.starts[usize::try_from(selected.ordinal.get()).map_err(|_| {
                ReduceError::ArithmeticOverflow {
                    computation: "reusable tagged session selected start ordinal",
                }
            })?];
            let map = workspace.current_rows[plan_index(start)];
            let mut authenticated = false;
            for group in workspace.current_pool.map_groups(map)? {
                meter.charge(1)?;
                if group.owners & (1u128 << selected.ordinal.get()) != 0
                    && group.end == selected.end
                {
                    authenticated = true;
                    break;
                }
            }
            if !authenticated {
                return Err(ReduceError::InternalInvariant {
                    detail:
                        "reusable tagged session start-owner selection did not authenticate its row",
                });
            }
        }
        core::mem::swap(&mut workspace.current_rows, &mut workspace.next_rows);
        core::mem::swap(&mut workspace.current_pool, &mut workspace.next_pool);
    }

    let mut output = O::zero();
    let mut position = 0usize;
    let mut suppress_empty_at = None::<usize>;
    while position <= haystack.len() {
        meter.charge(1)?;
        let Some(outcome) = workspace.roots[position] else {
            if position == haystack.len() {
                break;
            }
            position = position
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "reusable tagged session reducer progress",
                })?;
            continue;
        };
        if outcome.end == position && suppress_empty_at == Some(position) {
            if position == haystack.len() {
                break;
            }
            position = position
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "reusable tagged session suppressed empty progress",
                })?;
            continue;
        }
        meter.charge(1)?;
        record_tagged_match(&mut actual, outcome, position, limits.max_match_events)?;
        output = O::append(output, position, outcome.end, outcome.ordinal)?;
        if workspace.trace.len() == workspace.trace.capacity() {
            return Err(ReduceError::InternalInvariant {
                detail: "reusable tagged session trace capacity was exceeded",
            });
        }
        workspace.trace.push(PriorityMatch::from_parts(
            outcome.ordinal,
            position,
            outcome.end,
        ));
        if outcome.end == position {
            if position == haystack.len() {
                break;
            }
            position = position
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "reusable tagged session empty-match progress",
                })?;
        } else {
            suppress_empty_at = Some(outcome.end);
            position = outcome.end;
        }
    }
    actual.work = meter.consumed;
    Ok((output, actual))
}

#[allow(
    clippy::type_complexity,
    reason = "the executor returns the same receipt-bearing direct-reducer tuple as the generic tagged path"
)]
fn execute_shared_frontier<O: DirectReduceValue>(
    depth: usize,
    byte_start: u8,
    byte_end: u8,
    haystack: &[u8],
    limits: DirectReduceLimits,
    prospective: ExecutionProspective,
    trace_capacity: Option<usize>,
) -> Result<(O::Output, ExecutionActual, Option<Vec<PriorityMatch>>), ReduceError> {
    let expected_boundary_rows =
        haystack
            .len()
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "tagged shared-frontier boundary rows",
            })?;
    if prospective.boundary_rows != expected_boundary_rows
        || prospective.tagged_state_evaluations_upper_bound != haystack.len()
        || prospective.tagged_edge_visits_upper_bound != haystack.len()
        || prospective.tagged_map_capacity != 0
        || prospective.tagged_group_capacity != 0
        || prospective.tagged_group_publications_upper_bound != 0
        || prospective.tagged_dispatch_states_capacity != 0
        || prospective.tagged_dispatch_cells_capacity != 0
        || prospective.tagged_candidate_items_capacity != 0
        || prospective.tagged_cache_cells_capacity != 0
    {
        return Err(ReduceError::InternalInvariant {
            detail: "tagged shared-frontier prospective did not describe its chain",
        });
    }
    let mut meter = RunMeter::new(limits.max_work);
    let mut trace = match trace_capacity {
        Some(capacity) => {
            meter.charge(1)?;
            Some(reserve_run(capacity, "tagged shared-frontier trace")?)
        }
        None => None,
    };
    let mut actual = ExecutionActual::zero(haystack.len());
    actual.boundary_rows = prospective.boundary_rows;
    actual.scratch_bytes = prospective.scratch_bytes;
    actual.allocation_attempts = prospective.allocation_attempts;
    let mut output = O::zero();
    let mut consecutive = 0usize;

    for (index, &byte) in haystack.iter().enumerate() {
        meter.charge(1)?;
        actual.tagged_state_evaluations = actual.tagged_state_evaluations.checked_add(1).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "tagged shared-frontier state evaluations",
            },
        )?;
        actual.tagged_edge_visits =
            actual
                .tagged_edge_visits
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "tagged shared-frontier edge visits",
                })?;
        if byte < byte_start || byte > byte_end {
            consecutive = 0;
            continue;
        }
        consecutive = consecutive
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "tagged shared-frontier run length",
            })?;
        if consecutive != depth {
            continue;
        }
        let end = index
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "tagged shared-frontier match end",
            })?;
        let start = end
            .checked_sub(depth)
            .ok_or(ReduceError::InternalInvariant {
                detail: "tagged shared-frontier chain ended before it started",
            })?;
        let outcome = TaggedOutcome {
            ordinal: PatternOrdinal::new(0),
            end,
        };
        meter.charge(1)?;
        record_tagged_match(&mut actual, outcome, start, limits.max_match_events)?;
        output = O::append(output, start, end, outcome.ordinal)?;
        if let Some(trace) = trace.as_mut() {
            meter.charge(1)?;
            if trace.len() == trace.capacity() {
                return Err(ReduceError::InternalInvariant {
                    detail: "tagged shared-frontier trace capacity was exceeded",
                });
            }
            trace.push(PriorityMatch::from_parts(outcome.ordinal, start, end));
        }
        // A selected fixed-width match advances the leftmost-first reducer to
        // its endpoint. Resetting here makes the next byte the only eligible
        // new start, without retaining a row for every prior boundary.
        consecutive = 0;
    }
    actual.work = meter.consumed;
    Ok((output, actual, trace))
}

/// Re-run the specialized shared-frontier kernel with its trace sidecar owned
/// by a fixed-length [`TaggedManyTraceSession`].
fn execute_shared_frontier_reused<O: DirectReduceValue>(
    plan: &TaggedManyPlan<O>,
    haystack: &[u8],
    limits: DirectReduceLimits,
    prospective: ExecutionProspective,
    trace: &mut Vec<PriorityMatch>,
) -> Result<(O::Output, ExecutionActual), ReduceError> {
    let TaggedManyExecutionClass::SharedFrontierUniformRangeChain {
        depth,
        byte_start,
        byte_end,
    } = plan.stats.execution_class
    else {
        return Err(ReduceError::InternalInvariant {
            detail: "reusable tagged trace session selected the wrong execution class",
        });
    };
    let expected_boundary_rows =
        haystack
            .len()
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "reusable shared-frontier boundary rows",
            })?;
    if prospective.tagged_execution_class != Some(plan.stats.execution_class)
        || prospective.boundary_rows != expected_boundary_rows
        || prospective.tagged_state_evaluations_upper_bound != haystack.len()
        || prospective.tagged_edge_visits_upper_bound != haystack.len()
        || prospective.tagged_map_capacity != 0
        || prospective.tagged_group_capacity != 0
        || prospective.tagged_group_publications_upper_bound != 0
        || prospective.tagged_dispatch_states_capacity != 0
        || prospective.tagged_dispatch_cells_capacity != 0
        || prospective.tagged_candidate_items_capacity != 0
        || prospective.tagged_cache_cells_capacity != 0
        || trace.capacity() != prospective.match_events_upper_bound
    {
        return Err(ReduceError::InternalInvariant {
            detail:
                "reusable tagged trace session prospective did not describe its shared frontier",
        });
    }

    let mut meter = RunMeter::new(limits.max_work);
    trace.clear();
    // Preserve the one-shot trace-sidecar work charge while resetting the
    // already admitted vector in place.
    meter.charge(1)?;
    let mut actual = ExecutionActual::zero(haystack.len());
    actual.boundary_rows = prospective.boundary_rows;
    actual.scratch_bytes = prospective.scratch_bytes;
    actual.allocation_attempts = prospective.allocation_attempts;
    let mut output = O::zero();
    let mut consecutive = 0usize;

    for (index, &byte) in haystack.iter().enumerate() {
        meter.charge(1)?;
        actual.tagged_state_evaluations = actual.tagged_state_evaluations.checked_add(1).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "reusable shared-frontier state evaluations",
            },
        )?;
        actual.tagged_edge_visits =
            actual
                .tagged_edge_visits
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "reusable shared-frontier edge visits",
                })?;
        if byte < byte_start || byte > byte_end {
            consecutive = 0;
            continue;
        }
        consecutive = consecutive
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "reusable shared-frontier run length",
            })?;
        if consecutive != depth {
            continue;
        }
        let end = index
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "reusable shared-frontier match end",
            })?;
        let start = end
            .checked_sub(depth)
            .ok_or(ReduceError::InternalInvariant {
                detail: "reusable shared-frontier chain ended before it started",
            })?;
        let outcome = TaggedOutcome {
            ordinal: PatternOrdinal::new(0),
            end,
        };
        meter.charge(1)?;
        record_tagged_match(&mut actual, outcome, start, limits.max_match_events)?;
        output = O::append(output, start, end, outcome.ordinal)?;
        meter.charge(1)?;
        if trace.len() == trace.capacity() {
            return Err(ReduceError::InternalInvariant {
                detail: "reusable shared-frontier trace capacity was exceeded",
            });
        }
        trace.push(PriorityMatch::from_parts(outcome.ordinal, start, end));
        // A selected fixed-width match advances the leftmost-first reducer to
        // its endpoint. Resetting here makes the next byte the only eligible
        // new start, without retaining a row for every prior boundary.
        consecutive = 0;
    }
    actual.work = meter.consumed;
    Ok((output, actual))
}

fn record_tagged_match(
    actual: &mut ExecutionActual,
    outcome: TaggedOutcome,
    start: usize,
    max_match_events: usize,
) -> Result<(), ReduceError> {
    if actual.match_events == max_match_events {
        return Err(ReduceError::MatchEventsLimit {
            needed: actual.match_events.saturating_add(1),
            limit: max_match_events,
        });
    }
    actual.match_events =
        actual
            .match_events
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "tagged match events",
            })?;
    actual.empty_match_events = actual
        .empty_match_events
        .checked_add(usize::from(outcome.end == start))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "tagged empty events",
        })?;
    let span = outcome
        .end
        .checked_sub(start)
        .ok_or(ReduceError::InternalInvariant {
            detail: "tagged selected endpoint precedes its start",
        })?;
    actual.selected_span_bytes = actual
        .selected_span_bytes
        .checked_add(
            u64::try_from(span).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "tagged selected span conversion",
            })?,
        )
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "tagged selected span bytes",
        })?;
    actual.selected_ordinal_sum = actual
        .selected_ordinal_sum
        .checked_add(u64::from(outcome.ordinal.get()))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "tagged selected ordinal sum",
        })?;
    Ok(())
}

fn finish_tagged_report<T>(
    source_bytes: usize,
    output: T,
    prospective: ExecutionProspective,
    actual: &ExecutionActual,
) -> Result<DirectReduceReport<T>, ReduceError> {
    if actual.source_bytes != source_bytes
        || actual.boundary_rows != prospective.boundary_rows
        || actual.work > prospective.work_upper_bound
        || actual.scratch_bytes != prospective.scratch_bytes
        || actual.match_events > prospective.match_events_upper_bound
        || actual.dfa_states != 0
        || actual.dfa_cells != 0
        || actual.subset_items != 0
        || actual.dfa_transitions != 0
        || actual.lazy_cache_hits != 0
        || actual.lazy_cache_misses != 0
        || actual.lazy_cache_inserts != 0
        || actual.lazy_cache_evictions != 0
        || actual.generation_resets != 0
        || actual.sparse_root_evaluations != 0
        || actual.sparse_closure_visits != 0
        || actual.sparse_edge_visits != 0
        || actual.suffix_reducer_steps != 0
        || prospective.tagged_dispatch_states_capacity != 0
        || prospective.tagged_dispatch_cells_capacity != 0
        || prospective.tagged_candidate_items_capacity != 0
        || prospective.tagged_cache_cells_capacity != 0
        || actual.tagged_dispatch_states != 0
        || actual.tagged_dispatch_cells != 0
        || actual.tagged_candidate_items != 0
        || actual.tagged_cache_cells != 0
        || actual.tagged_cache_hits != 0
        || actual.tagged_cache_misses != 0
        || actual.tagged_cache_inserts != 0
        || actual.tagged_cache_evictions != 0
        || actual.tagged_state_evaluations != prospective.tagged_state_evaluations_upper_bound
        || actual.tagged_edge_visits > prospective.tagged_edge_visits_upper_bound
        || actual.tagged_map_publications > prospective.tagged_state_evaluations_upper_bound
        || actual.tagged_group_publications > prospective.tagged_group_publications_upper_bound
        || actual.tagged_peak_maps > prospective.tagged_map_capacity
        || actual.tagged_peak_groups > prospective.tagged_group_capacity
        || prospective.tagged_owner_capacity == 0
        || prospective.tagged_owner_capacity > MAX_OWNERS
        || actual.allocation_attempts != prospective.allocation_attempts
    {
        return Err(ReduceError::InternalInvariant {
            detail: "tagged execution receipt did not close",
        });
    }
    Ok(DirectReduceReport::from_parts(output, prospective, actual))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DirectCount, DirectSpanSum};

    fn compile_limits() -> CompileLimits {
        CompileLimits {
            max_states: usize::MAX,
            max_edges: usize::MAX,
            max_storage_bytes: usize::MAX,
            max_validation_work: usize::MAX,
        }
    }

    fn literal(bytes: &[u8]) -> RawPlan {
        let states = bytes.len() + 1;
        let mut roles = Vec::with_capacity(states);
        let mut offsets = Vec::with_capacity(states + 1);
        let mut targets = Vec::with_capacity(bytes.len());
        let mut kinds = Vec::with_capacity(bytes.len());
        let mut starts = Vec::with_capacity(bytes.len());
        let mut ends = Vec::with_capacity(bytes.len());
        offsets.push(0);
        for (index, &byte) in bytes.iter().enumerate() {
            roles.push(StateRole::Consume);
            targets.push(u32::try_from(index + 1).unwrap());
            kinds.push(EdgeKind::ByteRange);
            starts.push(byte);
            ends.push(byte);
            offsets.push(u32::try_from(targets.len()).unwrap());
        }
        roles.push(StateRole::Accept);
        offsets.push(u32::try_from(targets.len()).unwrap());
        RawPlan {
            start: 0,
            roles,
            edge_offsets: offsets,
            edge_targets: targets,
            edge_kinds: kinds,
            byte_starts: starts,
            byte_ends: ends,
        }
    }

    fn uniform_nonliteral_chain(depth: usize) -> RawPlan {
        let states = depth.checked_add(1).unwrap();
        let mut roles = Vec::with_capacity(states);
        let mut offsets = Vec::with_capacity(states.checked_add(1).unwrap());
        let mut targets = Vec::with_capacity(depth);
        let mut kinds = Vec::with_capacity(depth);
        let mut starts = Vec::with_capacity(depth);
        let mut ends = Vec::with_capacity(depth);
        offsets.push(0);
        for index in 0..depth {
            roles.push(StateRole::Consume);
            targets.push(u32::try_from(index.checked_add(1).unwrap()).unwrap());
            kinds.push(EdgeKind::ByteRange);
            starts.push(b'a');
            ends.push(b'z');
            offsets.push(u32::try_from(targets.len()).unwrap());
        }
        roles.push(StateRole::Accept);
        offsets.push(u32::try_from(targets.len()).unwrap());
        RawPlan {
            start: 0,
            roles,
            edge_offsets: offsets,
            edge_targets: targets,
            edge_kinds: kinds,
            byte_starts: starts,
            byte_ends: ends,
        }
    }

    fn empty() -> RawPlan {
        RawPlan {
            start: 0,
            roles: vec![StateRole::Accept],
            edge_offsets: vec![0, 0],
            edge_targets: vec![],
            edge_kinds: vec![],
            byte_starts: vec![],
            byte_ends: vec![],
        }
    }

    fn alternate(short_first: bool) -> RawPlan {
        // State 0 branches to `a` or `ab`; both converge on accept state 2.
        let branches = if short_first { vec![1, 3] } else { vec![3, 1] };
        RawPlan {
            start: 0,
            roles: vec![
                StateRole::Split,
                StateRole::Consume,
                StateRole::Accept,
                StateRole::Consume,
                StateRole::Consume,
            ],
            edge_offsets: vec![0, 2, 3, 3, 4, 5],
            edge_targets: vec![branches[0], branches[1], 2, 4, 2],
            edge_kinds: vec![
                EdgeKind::Epsilon,
                EdgeKind::Epsilon,
                EdgeKind::ByteRange,
                EdgeKind::ByteRange,
                EdgeKind::ByteRange,
            ],
            byte_starts: vec![0, 0, b'a', b'a', b'b'],
            byte_ends: vec![0, 0, b'a', b'a', b'b'],
        }
    }

    fn cycle() -> RawPlan {
        RawPlan {
            start: 0,
            roles: vec![StateRole::Split, StateRole::Accept],
            edge_offsets: vec![0, 2, 2],
            edge_targets: vec![0, 1],
            edge_kinds: vec![EdgeKind::Epsilon, EdgeKind::Epsilon],
            byte_starts: vec![0, 0],
            byte_ends: vec![0, 0],
        }
    }

    fn ordered_choice(first: u8, second: u8) -> RawPlan {
        RawPlan {
            start: 0,
            roles: vec![
                StateRole::Split,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Accept,
            ],
            edge_offsets: vec![0, 2, 3, 4, 4],
            edge_targets: vec![1, 2, 3, 3],
            edge_kinds: vec![
                EdgeKind::Epsilon,
                EdgeKind::Epsilon,
                EdgeKind::ByteRange,
                EdgeKind::ByteRange,
            ],
            byte_starts: vec![0, 0, first, second],
            byte_ends: vec![0, 0, first, second],
        }
    }

    fn trace_ids<T>(trace: &DirectReduceTraceReport<T>) -> Vec<(u32, usize, usize)> {
        trace
            .matches()
            .iter()
            .map(|entry| (entry.ordinal().get(), entry.start(), entry.end()))
            .collect()
    }

    fn session_trace_ids<T>(
        trace: &TaggedManyTraceSessionReport<'_, T>,
    ) -> Vec<(u32, usize, usize)> {
        trace
            .matches()
            .iter()
            .map(|entry| (entry.ordinal().get(), entry.start(), entry.end()))
            .collect()
    }

    #[test]
    fn owner_projection_preserves_source_order_and_internal_priority() {
        let short = TaggedManyPlan::<DirectCount>::from_raw(
            vec![alternate(true), literal(b".")],
            b'\n',
            compile_limits(),
            TaggedManyBuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(
            vec![(0, 0, 1)],
            trace_ids(
                &short
                    .execute_trace(b"ab", DirectReduceLimits::unlimited())
                    .unwrap()
            )
        );

        let long = TaggedManyPlan::<DirectSpanSum>::from_raw(
            vec![alternate(false), literal(b".")],
            b'\n',
            compile_limits(),
            TaggedManyBuildLimits::unlimited(),
        )
        .unwrap();
        let trace = long
            .execute_trace(b"ab", DirectReduceLimits::unlimited())
            .unwrap();
        assert_eq!(vec![(0, 0, 2)], trace_ids(&trace));
        assert_eq!(&2, trace.report().output());
    }

    #[test]
    fn reusable_trace_session_matches_one_shot_generic_runs_without_new_allocations() {
        let plan = TaggedManyPlan::<DirectCount>::from_raw(
            vec![literal(b"aa"), literal(b"a")],
            b'\n',
            compile_limits(),
            TaggedManyBuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(
            TaggedManyExecutionClass::Generic,
            plan.stats().execution_class()
        );
        let limits = DirectReduceLimits::unlimited();
        let first_one_shot = plan.execute_trace(b"aabb", limits).unwrap();
        let second_one_shot = plan.execute_trace(b"bbaa", limits).unwrap();
        let mut session = plan.prepare_trace_session(4, limits).unwrap();
        assert_eq!(0, session.prospective().allocation_attempts);
        assert!(session.setup_prospective().allocation_attempts > 0);

        {
            let first = session.execute_trace(b"aabb").unwrap();
            assert_eq!(trace_ids(&first_one_shot), session_trace_ids(&first));
            assert_eq!(first_one_shot.report().output(), first.report().output());
            assert_eq!(0, first.report().actual().allocation_attempts);
            assert!(first.closes());
        }
        {
            let second = session.execute_trace(b"bbaa").unwrap();
            assert_eq!(trace_ids(&second_one_shot), session_trace_ids(&second));
            assert_eq!(second_one_shot.report().output(), second.report().output());
            assert_eq!(0, second.report().actual().allocation_attempts);
            assert!(second.closes());
        }
    }

    #[test]
    fn reusable_trace_session_reuses_shared_frontier_trace_and_enforces_length() {
        let plan = TaggedManyPlan::<DirectCount>::from_raw(
            vec![uniform_nonliteral_chain(2); 2],
            b'\n',
            compile_limits(),
            TaggedManyBuildLimits::unlimited(),
        )
        .unwrap();
        assert!(matches!(
            plan.stats().execution_class(),
            TaggedManyExecutionClass::SharedFrontierUniformRangeChain { depth: 2, .. }
        ));
        let limits = DirectReduceLimits::unlimited();
        let expected = plan.execute_trace(b"ababab", limits).unwrap();
        let mut session = plan.prepare_trace_session(6, limits).unwrap();
        assert_eq!(1, session.setup_prospective().allocation_attempts);
        assert_eq!(0, session.prospective().allocation_attempts);

        {
            let run = session.execute_trace(b"ababab").unwrap();
            assert_eq!(trace_ids(&expected), session_trace_ids(&run));
            assert_eq!(&3, run.report().output());
            assert_eq!(0, run.report().actual().allocation_attempts);
            assert!(run.closes());
        }
        {
            let empty = session.execute_trace(b"!!!!!!").unwrap();
            assert!(empty.matches().is_empty());
            assert_eq!(&0, empty.report().output());
            assert_eq!(0, empty.report().actual().allocation_attempts);
            assert!(empty.closes());
        }
        assert!(matches!(
            session.execute_trace(b"short"),
            Err(ReduceError::InternalInvariant { detail })
                if detail == "tagged trace session haystack length differs from its admitted workspace"
        ));
    }

    #[test]
    fn trace_session_setup_preflight_is_exact_for_generic_retained_storage() {
        let plan = TaggedManyPlan::<DirectCount>::from_raw(
            vec![literal(b"aa"), literal(b"a")],
            b'\n',
            compile_limits(),
            TaggedManyBuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(
            TaggedManyExecutionClass::Generic,
            plan.stats().execution_class()
        );
        let setup = plan
            .trace_session_setup_prospective(4, DirectReduceLimits::unlimited())
            .unwrap();
        assert!(setup.closes());
        assert_eq!(0, setup.steady_untraced_prospective.allocation_attempts);
        assert_eq!(0, setup.steady_traced_prospective.allocation_attempts);
        assert_eq!(
            setup.persistent_bytes,
            setup.steady_traced_prospective.scratch_bytes
        );
        let states = setup.steady_traced_prospective.tagged_map_capacity - 1;
        let initialized_entries = states * 2 + setup.steady_traced_prospective.boundary_rows;
        assert_eq!(8, setup.allocation_attempts);
        assert_eq!(
            u64::try_from(initialized_entries + setup.allocation_attempts).unwrap(),
            setup.initialization_work
        );

        let mut session = plan
            .prepare_trace_session(4, DirectReduceLimits::unlimited())
            .unwrap();
        assert_eq!(setup, session.setup());
        assert_eq!(setup, session.setup_prospective_receipt());
        assert!(session.closes());
        {
            let run = session.execute_trace(b"aabb").unwrap();
            assert_eq!(setup, run.setup());
            assert_eq!(setup, run.setup_prospective_receipt());
            assert!(run.closes());
        }

        session.setup.allocation_attempts += 1;
        assert!(!session.closes());
        assert!(matches!(
            session.execute_trace(b"aabb"),
            Err(ReduceError::InternalInvariant { detail })
                if detail == "reusable tagged trace-session setup receipt did not close"
        ));
    }

    #[test]
    fn trace_session_setup_excludes_zero_capacity_shared_frontier_reservations() {
        let plan = TaggedManyPlan::<DirectCount>::from_raw(
            vec![uniform_nonliteral_chain(2); 2],
            b'\n',
            compile_limits(),
            TaggedManyBuildLimits::unlimited(),
        )
        .unwrap();
        assert!(matches!(
            plan.stats().execution_class(),
            TaggedManyExecutionClass::SharedFrontierUniformRangeChain { .. }
        ));
        let setup = plan
            .trace_session_setup_prospective(0, DirectReduceLimits::unlimited())
            .unwrap();
        assert!(setup.closes());
        assert_eq!(1, setup.trace_capacity);
        assert_eq!(size_of::<PriorityMatch>(), setup.persistent_bytes);
        // The shared frontier owns only the non-empty trace vector. Its
        // absent rows and outcome pools do not count as allocation attempts.
        assert_eq!(1, setup.allocation_attempts);
        assert_eq!(1, setup.initialization_work);

        let exact = DirectReduceLimits {
            max_work: setup.steady_traced_prospective.work_upper_bound,
            max_scratch_bytes: setup.persistent_bytes,
            max_boundary_rows: setup.steady_traced_prospective.boundary_rows,
            max_match_events: setup.steady_traced_prospective.match_events_upper_bound,
            max_dfa_states: 0,
            max_dfa_cells: 0,
            max_subset_items: 0,
            max_tagged_dispatch_states: 0,
            max_tagged_dispatch_cells: 0,
            max_tagged_candidate_items: 0,
            max_tagged_cache_cells: 0,
            max_allocation_attempts: setup.allocation_attempts,
        };
        assert_eq!(
            setup,
            plan.trace_session_setup_prospective(0, exact).unwrap()
        );
        assert!(plan.prepare_trace_session(0, exact).is_ok());
        assert!(matches!(
            plan.trace_session_setup_prospective(
                0,
                DirectReduceLimits {
                    max_allocation_attempts: 0,
                    ..exact
                },
            ),
            Err(ReduceError::AllocationAttemptsLimit {
                needed: 1,
                limit: 0
            })
        ));
    }

    #[test]
    fn duplicate_nonliteral_graph_is_cardinality_invariant() {
        let mut expected = None::<(usize, usize)>;
        let mut unit_work = None::<u64>;
        let mut unit_scratch = None::<usize>;
        let mut unit_actual_work = None::<u64>;
        for count in [1usize, 8, 16, 32, 64, 128] {
            let plan = TaggedManyPlan::<DirectCount>::from_raw(
                vec![alternate(false); count],
                b'\n',
                compile_limits(),
                TaggedManyBuildLimits::unlimited(),
            )
            .unwrap();
            let dimensions = (plan.stats().states(), plan.stats().edges());
            assert_eq!(*expected.get_or_insert(dimensions), dimensions);
            assert_eq!(5, plan.stats().states());
            assert_eq!(5, plan.stats().edges());
            let prospective = plan
                .prospective(2, DirectReduceLimits::unlimited())
                .unwrap();
            let report = plan
                .execute(b"ab", DirectReduceLimits::unlimited())
                .unwrap();
            let base_work = *unit_work.get_or_insert(prospective.work_upper_bound);
            let base_scratch = *unit_scratch.get_or_insert(prospective.scratch_bytes);
            let base_actual = *unit_actual_work.get_or_insert(report.actual().work);
            assert!(prospective.work_upper_bound <= base_work * u64::try_from(count).unwrap());
            assert!(prospective.scratch_bytes <= base_scratch * count);
            assert!(report.actual().work <= base_actual * u64::try_from(count).unwrap());
            assert_eq!(count, prospective.tagged_owner_capacity);
            assert_eq!(6, prospective.tagged_map_capacity);
            assert_eq!(5 * count, prospective.tagged_group_capacity);
            assert_eq!(
                prospective.tagged_state_evaluations_upper_bound,
                report.actual().tagged_state_evaluations
            );
            assert!(
                report.actual().tagged_edge_visits <= prospective.tagged_edge_visits_upper_bound
            );
            let trace = plan
                .execute_trace(b"ab", DirectReduceLimits::unlimited())
                .unwrap();
            assert_eq!(vec![(0, 0, 2)], trace_ids(&trace));
        }
    }

    #[test]
    fn shared_frontier_receipt_is_linear_for_deep_duplicate_nonliteral_chains() {
        for owners in [1usize, 8, MAX_OWNERS] {
            for depth in [8usize, 32, 128] {
                let raws = vec![uniform_nonliteral_chain(depth); owners];
                let plan = TaggedManyPlan::<DirectCount>::from_raw(
                    raws.clone(),
                    b'\n',
                    compile_limits(),
                    TaggedManyBuildLimits::unlimited(),
                )
                .unwrap();
                assert_eq!(depth + 1, plan.stats().states());
                assert_eq!(depth, plan.stats().edges());
                assert!(matches!(
                    plan.stats().execution_class(),
                    TaggedManyExecutionClass::SharedFrontierUniformRangeChain {
                        depth: class_depth,
                        byte_start: b'a',
                        byte_end: b'z',
                    } if class_depth == depth
                ));
                let accounting = plan.build_accounting();
                assert_eq!(owners, accounting.classification_owner_checks);
                assert_eq!(depth + 1, accounting.classification_state_checks);
                assert_eq!(depth, accounting.classification_edge_checks);
                assert_eq!(
                    u64::try_from(owners + (depth + 1) + depth + 2).unwrap(),
                    accounting.classification_work
                );
                assert_eq!(
                    u64::try_from(
                        owners + plan.stats().source_states() + plan.stats().source_edges() + 2
                    )
                    .unwrap(),
                    accounting.classification_work_upper_bound
                );
                assert_eq!(
                    Some(plan.stats().execution_class()),
                    plan.prospective(0, DirectReduceLimits::unlimited())
                        .unwrap()
                        .tagged_execution_class
                );
                if owners == 8 && depth == 32 {
                    let exact = TaggedManyBuildLimits {
                        max_work: accounting.prospective_work,
                        ..TaggedManyBuildLimits::unlimited()
                    };
                    assert!(TaggedManyPlan::<DirectCount>::from_raw(
                        raws.clone(),
                        b'\n',
                        compile_limits(),
                        exact
                    )
                    .unwrap()
                    .build_accounting()
                    .closes(exact));
                    assert!(matches!(
                        TaggedManyPlan::<DirectCount>::from_raw(
                            raws.clone(),
                            b'\n',
                            compile_limits(),
                            TaggedManyBuildLimits {
                                max_work: accounting.prospective_work - 1,
                                ..exact
                            }
                        ),
                        Err(TaggedManyBuildError::WorkLimit { needed, limit })
                            if needed == accounting.prospective_work && limit + 1 == needed
                    ));
                }

                let span_plan = TaggedManyPlan::<DirectSpanSum>::from_raw(
                    raws,
                    b'\n',
                    compile_limits(),
                    TaggedManyBuildLimits::unlimited(),
                )
                .unwrap();
                assert_eq!(plan.stats(), span_plan.stats());
                assert_eq!(plan.build_accounting(), span_plan.build_accounting());

                for input_bytes in [8usize, 256, 1_024] {
                    let prospective = plan
                        .prospective(input_bytes, DirectReduceLimits::unlimited())
                        .unwrap();
                    let no_match = plan
                        .execute(&vec![b'!'; input_bytes], DirectReduceLimits::unlimited())
                        .unwrap();
                    let actual = no_match.actual();
                    assert_eq!(input_bytes, actual.tagged_state_evaluations);
                    assert_eq!(input_bytes, actual.tagged_edge_visits);
                    assert_eq!(
                        prospective.tagged_state_evaluations_upper_bound,
                        actual.tagged_state_evaluations
                    );
                    assert_eq!(
                        prospective.tagged_edge_visits_upper_bound,
                        actual.tagged_edge_visits
                    );
                    assert_eq!(0, prospective.tagged_map_capacity);
                    assert_eq!(0, prospective.tagged_group_capacity);
                    assert_eq!(0, actual.tagged_map_publications);
                    assert_eq!(0, actual.tagged_group_publications);
                    assert_ne!(
                        prospective.boundary_rows * plan.stats().states(),
                        actual.tagged_state_evaluations
                    );
                    assert_eq!(
                        u64::try_from(input_bytes * 2 + 1).unwrap(),
                        prospective.work_upper_bound
                    );
                    assert!(actual.work <= prospective.work_upper_bound);

                    let dense = vec![b'a'; input_bytes];
                    let matched = plan
                        .execute(&dense, DirectReduceLimits::unlimited())
                        .unwrap();
                    assert_eq!(
                        &u64::try_from(input_bytes / depth).unwrap(),
                        matched.output()
                    );
                    assert_eq!(input_bytes, matched.actual().tagged_state_evaluations);
                    assert_eq!(input_bytes, matched.actual().tagged_edge_visits);

                    let trace = plan
                        .execute_trace(&dense, DirectReduceLimits::unlimited())
                        .unwrap();
                    assert_eq!(
                        (0..input_bytes / depth)
                            .map(|index| (0, index * depth, (index + 1) * depth))
                            .collect::<Vec<_>>(),
                        trace_ids(&trace)
                    );
                    if owners == 8 && depth == 32 && input_bytes == 8 {
                        let exact = DirectReduceLimits {
                            max_work: prospective.work_upper_bound,
                            max_scratch_bytes: prospective.scratch_bytes,
                            max_boundary_rows: prospective.boundary_rows,
                            max_match_events: prospective.match_events_upper_bound,
                            max_dfa_states: 0,
                            max_dfa_cells: 0,
                            max_subset_items: 0,
                            max_tagged_dispatch_states: 0,
                            max_tagged_dispatch_cells: 0,
                            max_tagged_candidate_items: 0,
                            max_tagged_cache_cells: 0,
                            max_allocation_attempts: prospective.allocation_attempts,
                        };
                        assert!(plan.execute(&dense, exact).is_ok());
                        assert!(matches!(
                            plan.execute(
                                &dense,
                                DirectReduceLimits {
                                    max_work: prospective.work_upper_bound - 1,
                                    ..exact
                                }
                            ),
                            Err(ReduceError::WorkLimit {
                                requested,
                                limit,
                                ..
                            }) if requested == prospective.work_upper_bound
                                && limit + 1 == requested
                        ));

                        let traced = trace.report().prospective();
                        let exact_trace = DirectReduceLimits {
                            max_work: traced.work_upper_bound,
                            max_scratch_bytes: traced.scratch_bytes,
                            max_boundary_rows: traced.boundary_rows,
                            max_match_events: traced.match_events_upper_bound,
                            max_dfa_states: 0,
                            max_dfa_cells: 0,
                            max_subset_items: 0,
                            max_tagged_dispatch_states: 0,
                            max_tagged_dispatch_cells: 0,
                            max_tagged_candidate_items: 0,
                            max_tagged_cache_cells: 0,
                            max_allocation_attempts: traced.allocation_attempts,
                        };
                        assert!(plan.execute_trace(&dense, exact_trace).is_ok());
                        assert!(matches!(
                            plan.execute_trace(
                                &dense,
                                DirectReduceLimits {
                                    max_scratch_bytes: traced.scratch_bytes - 1,
                                    ..exact_trace
                                }
                            ),
                            Err(ReduceError::ScratchLimit { needed, limit })
                                if needed == traced.scratch_bytes && limit + 1 == needed
                        ));
                        assert!(matches!(
                            plan.execute_trace(
                                &dense,
                                DirectReduceLimits {
                                    max_allocation_attempts: traced.allocation_attempts - 1,
                                    ..exact_trace
                                }
                            ),
                            Err(ReduceError::AllocationAttemptsLimit { needed, limit })
                                if needed == traced.allocation_attempts && limit + 1 == needed
                        ));
                    }

                    let span = span_plan
                        .execute(&dense, DirectReduceLimits::unlimited())
                        .unwrap();
                    assert_eq!(
                        &u64::try_from((input_bytes / depth) * depth).unwrap(),
                        span.output()
                    );
                    assert_eq!(matched.actual(), span.actual());
                    let span_trace = span_plan
                        .execute_trace(&dense, DirectReduceLimits::unlimited())
                        .unwrap();
                    assert_eq!(trace.report().actual(), span_trace.report().actual());
                    assert_eq!(trace_ids(&trace), trace_ids(&span_trace));
                }
            }
        }
    }

    #[test]
    fn execution_classification_charges_every_inspected_owner_state_and_edge() {
        let plan = TaggedManyPlan::<DirectCount>::from_raw(
            vec![uniform_nonliteral_chain(8); 8],
            b'\n',
            compile_limits(),
            TaggedManyBuildLimits::unlimited(),
        )
        .unwrap();
        let accounting = plan.build_accounting();
        let mut malformed_actual = accounting;
        malformed_actual.actual_work = malformed_actual.classification_work - 1;
        assert!(!malformed_actual.closes(TaggedManyBuildLimits::unlimited()));
        let mut malformed_prospective = accounting;
        malformed_prospective.prospective_work =
            malformed_prospective.classification_work_upper_bound - 1;
        malformed_prospective.actual_work = malformed_prospective.classification_work;
        assert!(!malformed_prospective.closes(TaggedManyBuildLimits::unlimited()));
        assert!(!accounting.closes(TaggedManyBuildLimits {
            max_work: accounting.prospective_work - 1,
            ..TaggedManyBuildLimits::unlimited()
        }));
        let states = plan.states.to_vec();
        let edges = plan.edges.to_vec();
        let starts = plan.starts.to_vec();

        let classify = |states: &[TaggedState], edges: &[TaggedEdge], starts: &[u32]| {
            let mut meter = BuildMeter::new(u64::MAX);
            let class = classify_execution(states, edges, starts, &mut meter).unwrap();
            (
                class,
                meter.consumed,
                meter.classification_owner_checks,
                meter.classification_state_checks,
                meter.classification_edge_checks,
            )
        };
        let eligible = classify(&states, &edges, &starts);
        assert!(matches!(
            eligible.0,
            TaggedManyExecutionClass::SharedFrontierUniformRangeChain { depth: 8, .. }
        ));
        assert_eq!(
            (27, 8, 9, 8),
            (eligible.1, eligible.2, eligible.3, eligible.4)
        );

        let mut late_owner = starts.clone();
        late_owner[7] = 1;
        let late_owner = classify(&states, &edges, &late_owner);
        assert_eq!(TaggedManyExecutionClass::Generic, late_owner.0);
        assert_eq!(
            (10, 8, 0, 0),
            (late_owner.1, late_owner.2, late_owner.3, late_owner.4)
        );

        let mut late_edge = edges.clone();
        late_edge[7].byte_start = b'b';
        let late_edge = classify(&states, &late_edge, &starts);
        assert_eq!(TaggedManyExecutionClass::Generic, late_edge.0);
        assert_eq!(
            (26, 8, 8, 8),
            (late_edge.1, late_edge.2, late_edge.3, late_edge.4)
        );

        let mut terminal = states;
        terminal[8].role = StateRole::Consume;
        let terminal = classify(&terminal, &edges, &starts);
        assert_eq!(TaggedManyExecutionClass::Generic, terminal.0);
        assert_eq!(
            (27, 8, 9, 8),
            (terminal.1, terminal.2, terminal.3, terminal.4)
        );
    }

    #[test]
    fn empty_progress_and_duplicate_owners_match_build_many_rules() {
        let plan = TaggedManyPlan::<DirectCount>::from_raw(
            vec![literal(b"a"), empty()],
            b'\n',
            compile_limits(),
            TaggedManyBuildLimits::unlimited(),
        )
        .unwrap();
        let trace = plan
            .execute_trace(b"ab", DirectReduceLimits::unlimited())
            .unwrap();
        assert_eq!(vec![(0, 0, 1), (1, 2, 2)], trace_ids(&trace));

        let duplicates = TaggedManyPlan::<DirectCount>::from_raw(
            vec![empty(), empty(), literal(b"a")],
            b'\n',
            compile_limits(),
            TaggedManyBuildLimits::unlimited(),
        )
        .unwrap();
        let trace = duplicates
            .execute_trace(&[0xff, b'a'], DirectReduceLimits::unlimited())
            .unwrap();
        assert_eq!(vec![(0, 0, 0), (0, 1, 1), (0, 2, 2)], trace_ids(&trace));
    }

    #[test]
    fn merged_continuation_is_not_promoted_to_a_lower_ordinal_root() {
        let plan = TaggedManyPlan::<DirectCount>::from_raw(
            vec![literal(b"ab"), literal(b"b")],
            b'\n',
            compile_limits(),
            TaggedManyBuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(5, plan.stats().source_states());
        assert_eq!(3, plan.stats().states());
        let shared_b = plan
            .states
            .iter()
            .find(|state| state.role == StateRole::Consume && state.owners == 0b11)
            .unwrap();
        assert_eq!(0b10, shared_b.start_owners);
        let trace = plan
            .execute_trace(b"b", DirectReduceLimits::unlimited())
            .unwrap();
        assert_eq!(vec![(1, 0, 1)], trace_ids(&trace));
        let actual = trace.report().actual();
        let prospective = trace.report().prospective();
        assert_eq!(0, actual.sparse_root_evaluations);
        assert_eq!(0, actual.sparse_closure_visits);
        assert_eq!(0, actual.sparse_edge_visits);
        assert_eq!(0, actual.dfa_transitions);
        assert_eq!(0, actual.generation_resets);
        assert!(actual.tagged_map_publications > 0);
        assert!(actual.tagged_group_publications > 0);
        assert!(actual.tagged_peak_maps <= prospective.tagged_map_capacity);
        assert!(actual.tagged_peak_groups <= prospective.tagged_group_capacity);
        assert!(
            actual.tagged_group_publications <= prospective.tagged_group_publications_upper_bound
        );
        assert_eq!(
            TaggedManyExecutionClass::Generic,
            plan.stats().execution_class()
        );
    }

    #[test]
    fn owner_shards_preserve_later_internal_success_and_bit_127() {
        let plan = TaggedManyPlan::<DirectCount>::from_raw(
            vec![ordered_choice(b'b', b'a'), ordered_choice(b'a', b'b')],
            b'\n',
            compile_limits(),
            TaggedManyBuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(
            vec![(0, 0, 1)],
            trace_ids(
                &plan
                    .execute_trace(b"a", DirectReduceLimits::unlimited())
                    .unwrap()
            )
        );

        let mut owners = Vec::with_capacity(MAX_OWNERS);
        owners.extend((0..MAX_OWNERS - 1).map(|_| literal(b"b")));
        owners.push(literal(b"a"));
        let bit_127 = TaggedManyPlan::<DirectCount>::from_raw(
            owners,
            b'\n',
            compile_limits(),
            TaggedManyBuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(
            vec![(127, 0, 1)],
            trace_ids(
                &bit_127
                    .execute_trace(b"a", DirectReduceLimits::unlimited())
                    .unwrap()
            )
        );
    }

    #[test]
    fn construction_and_execution_limits_are_exact_and_one_below() {
        let raws = vec![literal(b"aa"), literal(b"a")];
        let probe = TaggedManyPlan::<DirectCount>::from_raw(
            raws.clone(),
            b'\n',
            compile_limits(),
            TaggedManyBuildLimits::unlimited(),
        )
        .unwrap();
        let stats = probe.stats();
        let accounting = probe.build_accounting();
        let exact = TaggedManyBuildLimits {
            max_patterns: stats.patterns(),
            max_source_states: stats.source_states(),
            max_source_edges: stats.source_edges(),
            max_shared_states: stats.states(),
            max_shared_edges: stats.edges(),
            max_owner_state_memberships: stats.owner_state_memberships(),
            max_owner_edge_memberships: stats.owner_edge_memberships(),
            max_work: accounting.prospective_work,
            max_persistent_bytes: accounting.persistent_bytes,
            max_peak_bytes: accounting.peak_bytes,
            max_allocation_attempts: accounting.allocation_attempts,
        };
        let plan =
            TaggedManyPlan::<DirectCount>::from_raw(raws.clone(), b'\n', compile_limits(), exact)
                .unwrap();
        assert!(plan.build_accounting().closes(exact));
        let below = TaggedManyBuildLimits {
            max_persistent_bytes: accounting.persistent_bytes - 1,
            ..exact
        };
        assert!(matches!(
            TaggedManyPlan::<DirectCount>::from_raw(
                raws,
                b'\n',
                compile_limits(),
                below
            ),
            Err(TaggedManyBuildError::PersistentLimit { needed, limit })
                if needed == accounting.persistent_bytes && limit + 1 == needed
        ));
        assert!(matches!(
            TaggedManyPlan::<DirectCount>::from_raw(
                vec![literal(b"aa"), literal(b"a")],
                b'\n',
                compile_limits(),
                TaggedManyBuildLimits {
                    max_work: accounting.prospective_work - 1,
                    ..exact
                }
            ),
            Err(TaggedManyBuildError::WorkLimit { needed, limit })
                if needed == accounting.prospective_work && limit + 1 == needed
        ));
        assert!(matches!(
            TaggedManyPlan::<DirectCount>::from_raw(
                vec![literal(b"aa"), literal(b"a")],
                b'\n',
                compile_limits(),
                TaggedManyBuildLimits {
                    max_peak_bytes: accounting.peak_bytes - 1,
                    ..exact
                }
            ),
            Err(TaggedManyBuildError::PeakLimit { needed, limit })
                if needed == accounting.peak_bytes && limit + 1 == needed
        ));

        let prospective = plan
            .prospective(3, DirectReduceLimits::unlimited())
            .unwrap();
        let exact_run = DirectReduceLimits {
            max_work: prospective.work_upper_bound,
            max_scratch_bytes: prospective.scratch_bytes,
            max_boundary_rows: prospective.boundary_rows,
            max_match_events: prospective.match_events_upper_bound,
            max_dfa_states: 0,
            max_dfa_cells: 0,
            max_subset_items: 0,
            max_tagged_dispatch_states: 0,
            max_tagged_dispatch_cells: 0,
            max_tagged_candidate_items: 0,
            max_tagged_cache_cells: 0,
            max_allocation_attempts: prospective.allocation_attempts,
        };
        assert_eq!(&2, plan.execute(b"aaa", exact_run).unwrap().output());
        assert!(matches!(
            plan.execute(
                b"aaa",
                DirectReduceLimits {
                    max_scratch_bytes: prospective.scratch_bytes - 1,
                    ..exact_run
                }
            ),
            Err(ReduceError::ScratchLimit { needed, limit })
                if needed == prospective.scratch_bytes && limit + 1 == needed
        ));
        assert!(matches!(
            plan.execute(
                b"aaa",
                DirectReduceLimits {
                    max_work: prospective.work_upper_bound - 1,
                    ..exact_run
                }
            ),
            Err(ReduceError::WorkLimit {
                consumed: 0,
                requested,
                limit
            }) if requested == prospective.work_upper_bound && limit + 1 == requested
        ));
    }

    #[test]
    fn p128_consuming_duplicates_replay_exact_peak_before_publication() {
        let raws = vec![literal(b"ab"); MAX_OWNERS];
        let probe = TaggedManyPlan::<DirectCount>::from_raw(
            raws.clone(),
            b'\n',
            compile_limits(),
            TaggedManyBuildLimits::unlimited(),
        )
        .unwrap();
        let stats = probe.stats();
        let accounting = probe.build_accounting();
        assert_eq!(3, stats.states());
        assert_eq!(2, stats.edges());
        assert_eq!(MAX_OWNERS * 3, stats.owner_state_memberships());
        assert_eq!(MAX_OWNERS * 2, stats.owner_edge_memberships());
        assert_eq!(stats.source_states(), accounting.projection_checks);
        assert!(
            accounting.projection_edge_visits
                <= stats.source_edges().checked_mul(stats.patterns()).unwrap()
        );
        let exact = TaggedManyBuildLimits {
            max_patterns: stats.patterns(),
            max_source_states: stats.source_states(),
            max_source_edges: stats.source_edges(),
            max_shared_states: stats.states(),
            max_shared_edges: stats.edges(),
            max_owner_state_memberships: stats.owner_state_memberships(),
            max_owner_edge_memberships: stats.owner_edge_memberships(),
            max_work: accounting.prospective_work,
            max_persistent_bytes: accounting.persistent_bytes,
            max_peak_bytes: accounting.peak_bytes,
            max_allocation_attempts: accounting.allocation_attempts,
        };
        let replay =
            TaggedManyPlan::<DirectCount>::from_raw(raws.clone(), b'\n', compile_limits(), exact)
                .unwrap();
        assert_eq!(accounting, replay.build_accounting());
        assert!(matches!(
            TaggedManyPlan::<DirectCount>::from_raw(
                raws,
                b'\n',
                compile_limits(),
                TaggedManyBuildLimits {
                    max_peak_bytes: accounting.peak_bytes - 1,
                    ..exact
                }
            ),
            Err(TaggedManyBuildError::PeakLimit { needed, limit })
                if needed == accounting.peak_bytes && limit + 1 == needed
        ));
    }

    #[test]
    fn source_collection_capacity_is_authenticated_before_construction() {
        let mut raws = Vec::with_capacity(2);
        raws.push(literal(b"a"));
        assert!(matches!(
            TaggedManyPlan::<DirectCount>::from_raw(
                raws,
                b'\n',
                compile_limits(),
                TaggedManyBuildLimits::unlimited()
            ),
            Err(TaggedManyBuildError::NonExactSourceCollectionCapacity {
                length: 1,
                capacity: 2
            })
        ));
    }

    #[test]
    fn malformed_cross_table_shape_refuses_before_bounded_scans() {
        let malformed = RawPlan {
            start: 0,
            roles: vec![StateRole::Accept],
            edge_offsets: vec![0, 0],
            edge_targets: vec![],
            edge_kinds: vec![EdgeKind::Epsilon; 32],
            byte_starts: vec![],
            byte_ends: vec![],
        };
        assert!(matches!(
            TaggedManyPlan::<DirectCount>::from_raw(
                vec![malformed],
                b'\n',
                compile_limits(),
                TaggedManyBuildLimits {
                    max_work: 1,
                    ..TaggedManyBuildLimits::unlimited()
                }
            ),
            Err(TaggedManyBuildError::MalformedSourceShape {
                pattern: 0,
                table: "edge kinds",
                expected: 0,
                actual: 32
            })
        ));
    }

    #[test]
    fn owner_cap_and_zero_width_cycle_refuse_before_publication() {
        assert!(matches!(
            TaggedManyPlan::<DirectCount>::from_raw(
                vec![empty(); 129],
                b'\n',
                compile_limits(),
                TaggedManyBuildLimits::unlimited()
            ),
            Err(TaggedManyBuildError::PatternLimit {
                needed: 129,
                limit: 128
            })
        ));
        assert!(matches!(
            TaggedManyPlan::<DirectCount>::from_raw(
                vec![cycle()],
                b'\n',
                compile_limits(),
                TaggedManyBuildLimits::unlimited()
            ),
            Err(TaggedManyBuildError::ZeroWidthCycle { pattern: 0 })
        ));
    }
}
