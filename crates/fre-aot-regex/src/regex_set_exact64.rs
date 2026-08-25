//! Opt-in shared-scan substrate for small exact byte regex sets.
//!
//! This module deliberately does not change [`crate::compile_regex_set`]. The
//! reported entry below first compiles that complete incumbent, then selects a
//! shared Aho-Corasick graph only when every row's current authenticated HIR
//! facts prove one nonempty, assertion-free byte string. The target-neutral
//! oracle publishes its single caller-owned result word transactionally.

use core::fmt;

use fre_lower::{
    CANONICAL_EXACT_LITERAL_ACCOUNTING_VERSION, CANONICAL_EXACT_LITERAL_ALGORITHM_VERSION,
    HIR_FACT_ACCOUNTING_VERSION, HIR_FACT_ALGORITHM_VERSION,
};
use sha2::{Digest, Sha256};

use crate::{
    CompileMode, SearchWindow,
    regex_set::{
        RegexSetArtifactIdentity, RegexSetCompileError, RegexSetCompileRequest,
        RegexSetExact64WitnessDecline, RegexSetProgram, compile_regex_set,
        compile_regex_set_with_exact64_witnesses,
    },
};

/// Stable schema for the target-neutral exact-set receipt and graph digest.
pub const REGEX_SET_EXACT64_SCHEMA_VERSION: u32 = 1;
/// Smallest source cardinality for which a shared set scan is meaningful.
pub const REGEX_SET_EXACT64_MIN_PATTERNS: usize = 2;
/// Representation ceiling imposed by the transactional `u64` result mask.
pub const REGEX_SET_EXACT64_MAX_PATTERNS: usize = 64;

const REGEX_SET_EXACT64_SOURCE_DOMAIN: &[u8] = b"FRE-AOT-REGEX-SET-EXACT64-SOURCE\0";
const REGEX_SET_EXACT64_ARTIFACT_DOMAIN: &[u8] = b"FRE-AOT-REGEX-SET-EXACT64\0";

/// Explicit construction ceilings for the opt-in shared exact-set graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegexSetExact64Limits {
    /// Maximum sum of authenticated literal bytes.
    pub max_literal_bytes: usize,
    /// Maximum number of trie states, including the root.
    pub max_states: usize,
    /// Maximum number of explicit trie edges.
    pub max_transition_cells: usize,
    /// Maximum failure-link probes during Aho-Corasick construction.
    pub max_failure_steps: u64,
}

impl Default for RegexSetExact64Limits {
    fn default() -> Self {
        Self {
            max_literal_bytes: 1_048_576,
            max_states: 1 << 20,
            max_transition_cells: 1 << 20,
            max_failure_steps: 64_000_000,
        }
    }
}

/// Numeric construction resource that can decline to the already-compiled
/// independent-row incumbent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RegexSetExact64Resource {
    LiteralBytes,
    States,
    TransitionCells,
    FailureSteps,
}

impl fmt::Display for RegexSetExact64Resource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LiteralBytes => "literal bytes",
            Self::States => "states",
            Self::TransitionCells => "transition cells",
            Self::FailureSteps => "failure-link steps",
        })
    }
}

/// Auditable reason why the opt-in exact-set candidate was not selected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RegexSetExact64Decline {
    /// Only optimizing compilation may select an aggregate optimizer.
    RequiresOptimizing { actual: CompileMode },
    /// The source count is outside the exact `u64` representation envelope.
    PatternCount {
        needed: usize,
        minimum: usize,
        maximum: usize,
    },
    /// One indexed row lacked the required authenticated exact-language proof.
    RowNotExactSingleton { pattern: usize },
    /// An explicit numeric construction ceiling was crossed.
    Resource {
        resource: RegexSetExact64Resource,
        needed: u64,
        limit: u64,
    },
}

impl fmt::Display for RegexSetExact64Decline {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequiresOptimizing { actual } => write!(
                formatter,
                "shared exact regex-set scan requires Optimizing mode, got {actual:?}"
            ),
            Self::PatternCount {
                needed,
                minimum,
                maximum,
            } => write!(
                formatter,
                "shared exact regex-set scan needs {minimum}..={maximum} patterns, got {needed}"
            ),
            Self::RowNotExactSingleton { pattern } => write!(
                formatter,
                "regex-set row {pattern} is not an authenticated nonempty assertion-free exact singleton"
            ),
            Self::Resource {
                resource,
                needed,
                limit,
            } => write!(
                formatter,
                "shared exact regex-set scan needs {needed} {resource}, limit is {limit}"
            ),
        }
    }
}

impl std::error::Error for RegexSetExact64Decline {}

/// Stable identity of one source-ordered shared exact-set graph.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct RegexSetExact64ArtifactIdentity([u8; 32]);

impl RegexSetExact64ArtifactIdentity {
    /// Return the SHA-256 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Copy the SHA-256 bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Authenticated dimensions of one selected target-neutral shared graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegexSetExact64Receipt {
    schema_version: u32,
    exact_literal_algorithm_version: u32,
    exact_literal_accounting_version: u32,
    fact_algorithm_version: u32,
    fact_accounting_version: u32,
    source_artifact: RegexSetArtifactIdentity,
    artifact: RegexSetExact64ArtifactIdentity,
    source_mapping_digest: [u8; 32],
    pattern_count: u8,
    all_pattern_mask: u64,
    literal_bytes: u64,
    state_count: u32,
    transition_count: u32,
    failure_steps: u64,
}

impl RegexSetExact64Receipt {
    /// Receipt schema version.
    #[must_use]
    pub const fn schema_version(self) -> u32 {
        self.schema_version
    }

    /// Allocation-free canonical exact-literal algorithm used as the
    /// semantic/resource-order preflight.
    #[must_use]
    pub const fn exact_literal_algorithm_version(self) -> u32 {
        self.exact_literal_algorithm_version
    }

    /// Exact work-accounting envelope for canonical literal preflight.
    #[must_use]
    pub const fn exact_literal_accounting_version(self) -> u32 {
        self.exact_literal_accounting_version
    }

    /// Canonical-HIR fact algorithm that proved every exact row.
    #[must_use]
    pub const fn fact_algorithm_version(self) -> u32 {
        self.fact_algorithm_version
    }

    /// Canonical-HIR fact accounting envelope used by every proof.
    #[must_use]
    pub const fn fact_accounting_version(self) -> u32 {
        self.fact_accounting_version
    }

    /// Stable identity of the authoritative independent-row program.
    #[must_use]
    pub const fn source_artifact(self) -> RegexSetArtifactIdentity {
        self.source_artifact
    }

    /// Stable identity of this exact source mapping and shared graph.
    #[must_use]
    pub const fn artifact_identity(self) -> RegexSetExact64ArtifactIdentity {
        self.artifact
    }

    /// Independent digest of source ordinals, literal widths, and exact proof
    /// bytes. Construction authenticates those bytes against the retained
    /// terminal-state mapping before publication.
    #[must_use]
    pub const fn source_mapping_digest(self) -> [u8; 32] {
        self.source_mapping_digest
    }

    /// Number of source rows represented by the result word.
    #[must_use]
    pub const fn pattern_count(self) -> u8 {
        self.pattern_count
    }

    /// Mask containing every valid source bit.
    #[must_use]
    pub const fn all_pattern_mask(self) -> u64 {
        self.all_pattern_mask
    }

    /// Sum of authenticated exact-literal bytes.
    #[must_use]
    pub const fn literal_bytes(self) -> u64 {
        self.literal_bytes
    }

    /// Number of retained shared trie states, including the root.
    #[must_use]
    pub const fn state_count(self) -> u32 {
        self.state_count
    }

    /// Number of retained explicit trie transitions.
    #[must_use]
    pub const fn transition_count(self) -> u32 {
        self.transition_count
    }

    /// Failure-link probes charged during construction.
    #[must_use]
    pub const fn failure_steps(self) -> u64 {
        self.failure_steps
    }
}

#[derive(Clone, Copy, Debug)]
struct Exact64State {
    failure: u32,
    parent: u32,
    edge_start: u32,
    edge_count: u16,
    incoming_byte: u8,
    depth: u32,
    direct_output_mask: u64,
    output_mask: u64,
}

#[derive(Clone, Copy, Debug)]
struct Exact64Edge {
    byte: u8,
    target: u32,
}

// Long exact literals make almost every trie state degree one. Keep that edge
// inline so construction allocates only for actual branch states.
#[derive(Debug)]
enum BuildEdges {
    Empty,
    Inline((u8, u32)),
    Spill(Vec<(u8, u32)>),
}

impl BuildEdges {
    fn as_slice(&self) -> &[(u8, u32)] {
        match self {
            Self::Empty => &[],
            Self::Inline(edge) => core::slice::from_ref(edge),
            Self::Spill(edges) => edges,
        }
    }

    fn insert(&mut self, index: usize, edge: (u8, u32)) -> Result<(), RegexSetExact64CompileError> {
        match self {
            Self::Empty => {
                if index != 0 {
                    return Err(RegexSetExact64CompileError::InternalInvariant(
                        "exact64 empty edge set received a nonzero insertion index",
                    ));
                }
                *self = Self::Inline(edge);
            }
            Self::Inline(retained) => {
                let ordered = match index {
                    0 => edge.0 < retained.0,
                    1 => retained.0 < edge.0,
                    _ => false,
                };
                if !ordered {
                    return Err(RegexSetExact64CompileError::InternalInvariant(
                        "exact64 inline edge insertion was not strictly ordered",
                    ));
                }
                let retained = *retained;
                let mut edges = Vec::new();
                reserve(&mut edges, 2, "exact64 trie branch edges")?;
                if index == 0 {
                    edges.push(edge);
                    edges.push(retained);
                } else {
                    edges.push(retained);
                    edges.push(edge);
                }
                *self = Self::Spill(edges);
            }
            Self::Spill(edges) => {
                if index > edges.len()
                    || (index > 0 && edges[index - 1].0 >= edge.0)
                    || (index < edges.len() && edge.0 >= edges[index].0)
                {
                    return Err(RegexSetExact64CompileError::InternalInvariant(
                        "exact64 spilled edge insertion was not strictly ordered",
                    ));
                }
                reserve_geometric(
                    edges,
                    REGEX_SET_EXACT64_MAX_PATTERNS,
                    "exact64 trie branch edges",
                    "exact64 trie branch edge count",
                )?;
                edges.insert(index, edge);
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
struct BuildState {
    edges: BuildEdges,
    failure: u32,
    parent: u32,
    incoming_byte: u8,
    depth: u32,
    direct_output_mask: u64,
    output_mask: u64,
}

impl BuildState {
    const fn new(depth: u32, parent: u32, incoming_byte: u8) -> Self {
        Self {
            edges: BuildEdges::Empty,
            failure: 0,
            parent,
            incoming_byte,
            depth,
            direct_output_mask: 0,
            output_mask: 0,
        }
    }
}

/// Immutable target-neutral shared exact-set program and its authoritative
/// independent-row fallback.
#[derive(Clone, Debug)]
pub struct RegexSetExact64Program {
    fallback: RegexSetProgram,
    receipt: RegexSetExact64Receipt,
    source_terminals: [u32; REGEX_SET_EXACT64_MAX_PATTERNS],
    // Retain the fallibly reserved vectors. Converting either one into a
    // boxed slice may first perform an infallible shrink allocation when the
    // allocator granted excess capacity, which would bypass the typed
    // `AllocationFailed` compile transaction.
    states: Vec<Exact64State>,
    edges: Vec<Exact64Edge>,
}

/// Borrowed, already-authenticated graph surface consumed by optional native
/// lowerings. Keeping the concrete state and edge records private prevents a
/// target backend from accidentally treating their in-memory Rust layout as
/// a wire format.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RegexSetExact64GraphView<'a> {
    program: &'a RegexSetExact64Program,
}

impl RegexSetExact64GraphView<'_> {
    pub(crate) fn state_count(&self) -> usize {
        self.program.states.len()
    }

    pub(crate) const fn receipt(&self) -> RegexSetExact64Receipt {
        self.program.receipt
    }

    pub(crate) fn state_depth(&self, state: usize) -> Option<u32> {
        self.program.states.get(state).map(|state| state.depth)
    }

    pub(crate) fn failure_state(&self, state: usize) -> Option<u32> {
        self.program.states.get(state).map(|state| state.failure)
    }

    pub(crate) fn output_mask(&self, state: usize) -> Option<u64> {
        self.program
            .states
            .get(state)
            .map(|state| state.output_mask)
    }

    pub(crate) fn direct_transition(&self, state: usize, byte: u8) -> Option<u32> {
        let state = self.program.states.get(state)?;
        let start = usize::try_from(state.edge_start).ok()?;
        let end = start.checked_add(usize::from(state.edge_count))?;
        let edges = self.program.edges.get(start..end)?;
        edges
            .binary_search_by_key(&byte, |edge| edge.byte)
            .ok()
            .map(|edge| edges[edge].target)
    }

    /// Rebuild the exact set of bytes that leave the root.
    ///
    /// This is the only safe skip predicate for a shared first-any scan: while
    /// the AC state is zero, every byte outside this set both fails to finish
    /// a match and returns to zero. Deriving it from the authenticated root
    /// edges avoids retaining a second source-derived membership witness.
    pub(crate) fn root_membership(&self) -> [u64; 4] {
        let mut membership = [0_u64; 4];
        for byte in u8::MIN..=u8::MAX {
            if self.direct_transition(0, byte).is_some() {
                let byte = usize::from(byte);
                membership[byte / 64] |= 1_u64 << (byte % 64);
            }
        }
        membership
    }

    /// Return the first source ordinal whose authenticated exact singleton
    /// contains `byte`.
    ///
    /// The complete graph authentication performed before this view is lent
    /// proves that every source terminal has a strictly depth-decreasing
    /// parent chain to the root. Walking those chains therefore inspects the
    /// exact proof bytes without retaining or reparsing source spelling.
    pub(crate) fn first_source_literal_containing(
        &self,
        byte: u8,
    ) -> Result<Option<usize>, RegexSetExact64AuthenticationError> {
        let pattern_count = usize::from(self.program.receipt.pattern_count);
        for ordinal in 0..pattern_count {
            let mut state = *self.program.source_terminals.get(ordinal).ok_or(
                RegexSetExact64AuthenticationError::Shape(
                    "source-byte proof omitted one source terminal",
                ),
            )?;
            while state != 0 {
                let state_index = usize::try_from(state).map_err(|_| {
                    RegexSetExact64AuthenticationError::Shape(
                        "source-byte proof state does not fit usize",
                    )
                })?;
                let record = self.program.states.get(state_index).ok_or(
                    RegexSetExact64AuthenticationError::Shape(
                        "source-byte proof state is outside the graph",
                    ),
                )?;
                if record.incoming_byte == byte {
                    return Ok(Some(ordinal));
                }
                state = record.parent;
            }
        }
        Ok(None)
    }
}

impl RegexSetExact64Program {
    /// Complete independently compiled semantic incumbent.
    #[must_use]
    pub const fn fallback(&self) -> &RegexSetProgram {
        &self.fallback
    }

    /// Authenticated source mapping and graph dimensions.
    #[must_use]
    pub const fn receipt(&self) -> RegexSetExact64Receipt {
        self.receipt
    }

    /// Authenticate the complete target-neutral graph before lending its
    /// abstract topology to an optional target backend.
    pub(crate) fn authenticated_graph(
        &self,
    ) -> Result<RegexSetExact64GraphView<'_>, RegexSetExact64AuthenticationError> {
        self.authenticate()?;
        Ok(RegexSetExact64GraphView { program: self })
    }

    /// Revalidate the target-neutral graph and its binding to the incumbent.
    #[allow(
        clippy::too_many_lines,
        reason = "authentication validates the complete receipt, graph partition, transitions, failure links, masks, and digest before publication"
    )]
    pub fn authenticate(&self) -> Result<(), RegexSetExact64AuthenticationError> {
        if self.receipt.schema_version != REGEX_SET_EXACT64_SCHEMA_VERSION {
            return Err(RegexSetExact64AuthenticationError::SchemaVersion {
                expected: REGEX_SET_EXACT64_SCHEMA_VERSION,
                actual: self.receipt.schema_version,
            });
        }
        if self.receipt.exact_literal_algorithm_version != CANONICAL_EXACT_LITERAL_ALGORITHM_VERSION
            || self.receipt.exact_literal_accounting_version
                != CANONICAL_EXACT_LITERAL_ACCOUNTING_VERSION
        {
            return Err(RegexSetExact64AuthenticationError::ExactLiteralIdentity {
                expected_algorithm: CANONICAL_EXACT_LITERAL_ALGORITHM_VERSION,
                actual_algorithm: self.receipt.exact_literal_algorithm_version,
                expected_accounting: CANONICAL_EXACT_LITERAL_ACCOUNTING_VERSION,
                actual_accounting: self.receipt.exact_literal_accounting_version,
            });
        }
        if self.receipt.fact_algorithm_version != HIR_FACT_ALGORITHM_VERSION
            || self.receipt.fact_accounting_version != HIR_FACT_ACCOUNTING_VERSION
        {
            return Err(RegexSetExact64AuthenticationError::FactIdentity {
                expected_algorithm: HIR_FACT_ALGORITHM_VERSION,
                actual_algorithm: self.receipt.fact_algorithm_version,
                expected_accounting: HIR_FACT_ACCOUNTING_VERSION,
                actual_accounting: self.receipt.fact_accounting_version,
            });
        }
        if self.fallback.artifact_identity() != self.receipt.source_artifact {
            return Err(RegexSetExact64AuthenticationError::SourceArtifact {
                expected: self.receipt.source_artifact,
                actual: self.fallback.artifact_identity(),
            });
        }
        let pattern_count = usize::from(self.receipt.pattern_count);
        if self.fallback.mode() != CompileMode::Optimizing
            || self.fallback.len() != pattern_count
            || !(REGEX_SET_EXACT64_MIN_PATTERNS..=REGEX_SET_EXACT64_MAX_PATTERNS)
                .contains(&pattern_count)
            || self.fallback.required_words() != 1
            || self.receipt.all_pattern_mask != all_pattern_mask(pattern_count)
        {
            return Err(RegexSetExact64AuthenticationError::Shape(
                "source program and result-mask dimensions disagree",
            ));
        }
        if usize::try_from(self.receipt.state_count).ok() != Some(self.states.len())
            || usize::try_from(self.receipt.transition_count).ok() != Some(self.edges.len())
            || self.states.is_empty()
            || self.states.len().checked_sub(1) != Some(self.edges.len())
        {
            return Err(RegexSetExact64AuthenticationError::Shape(
                "receipt graph dimensions disagree with retained storage",
            ));
        }

        let mut next_edge = 0usize;
        let mut direct_mask = 0_u64;
        let mut published_mask = 0_u64;
        for (state_index, state) in self.states.iter().enumerate() {
            let edge_start = usize::try_from(state.edge_start).map_err(|_| {
                RegexSetExact64AuthenticationError::Shape("state edge offset does not fit usize")
            })?;
            let edge_count = usize::from(state.edge_count);
            let edge_end = edge_start.checked_add(edge_count).ok_or(
                RegexSetExact64AuthenticationError::Shape("state edge range overflowed"),
            )?;
            if edge_start != next_edge || edge_end > self.edges.len() {
                return Err(RegexSetExact64AuthenticationError::Shape(
                    "state edge ranges are not one canonical partition",
                ));
            }
            if (state.direct_output_mask | state.output_mask) & !self.receipt.all_pattern_mask != 0
            {
                return Err(RegexSetExact64AuthenticationError::Shape(
                    "state publishes a bit outside the source set",
                ));
            }
            if direct_mask & state.direct_output_mask != 0 {
                return Err(RegexSetExact64AuthenticationError::Shape(
                    "one source bit is direct at more than one terminal state",
                ));
            }
            direct_mask |= state.direct_output_mask;
            published_mask |= state.output_mask;
            let failure = usize::try_from(state.failure).map_err(|_| {
                RegexSetExact64AuthenticationError::Shape("failure token does not fit usize")
            })?;
            if state_index == 0 {
                if state.failure != 0
                    || state.parent != 0
                    || state.incoming_byte != 0
                    || state.depth != 0
                    || state.direct_output_mask != 0
                    || state.output_mask != 0
                {
                    return Err(RegexSetExact64AuthenticationError::Shape(
                        "nonempty exact-set root state is malformed",
                    ));
                }
            } else if failure >= self.states.len() || self.states[failure].depth >= state.depth {
                return Err(RegexSetExact64AuthenticationError::Shape(
                    "failure link does not point to a shallower state",
                ));
            }
            let mut previous = None;
            for edge in &self.edges[edge_start..edge_end] {
                if previous.is_some_and(|byte| byte >= edge.byte) {
                    return Err(RegexSetExact64AuthenticationError::Shape(
                        "state edges are not strictly byte-sorted",
                    ));
                }
                previous = Some(edge.byte);
                let target = usize::try_from(edge.target).map_err(|_| {
                    RegexSetExact64AuthenticationError::Shape(
                        "transition target does not fit usize",
                    )
                })?;
                let target_depth =
                    state
                        .depth
                        .checked_add(1)
                        .ok_or(RegexSetExact64AuthenticationError::Shape(
                            "transition source depth overflowed",
                        ))?;
                if target >= self.states.len() || self.states[target].depth != target_depth {
                    return Err(RegexSetExact64AuthenticationError::Shape(
                        "transition target is not the next trie depth",
                    ));
                }
            }
            next_edge = edge_end;
        }
        if next_edge != self.edges.len() {
            return Err(RegexSetExact64AuthenticationError::Shape(
                "canonical state ranges did not consume every edge",
            ));
        }
        if direct_mask != self.receipt.all_pattern_mask
            || published_mask != self.receipt.all_pattern_mask
        {
            return Err(RegexSetExact64AuthenticationError::Shape(
                "graph does not publish every source bit",
            ));
        }

        let mut authenticated_failure_steps = 0_u64;
        for (state_index, state) in self.states.iter().enumerate().skip(1) {
            let parent = usize::try_from(state.parent).map_err(|_| {
                RegexSetExact64AuthenticationError::Shape("parent token does not fit usize")
            })?;
            let expected_depth = self
                .states
                .get(parent)
                .and_then(|parent| parent.depth.checked_add(1))
                .ok_or(RegexSetExact64AuthenticationError::Shape(
                    "parent token or depth is invalid",
                ))?;
            if state.depth != expected_depth
                || self.direct_transition(state.parent, state.incoming_byte)?
                    != Some(u32::try_from(state_index).map_err(|_| {
                        RegexSetExact64AuthenticationError::Shape(
                            "state index does not fit its token representation",
                        )
                    })?)
            {
                return Err(RegexSetExact64AuthenticationError::Shape(
                    "state parent edge does not authenticate",
                ));
            }

            let expected_failure = if parent == 0 {
                0
            } else {
                let mut fallback = self.states[parent].failure;
                loop {
                    authenticated_failure_steps = authenticated_failure_steps
                        .checked_add(1)
                        .ok_or(RegexSetExact64AuthenticationError::Shape(
                            "failure-link authentication work overflowed",
                        ))?;
                    if let Some(target) = self.direct_transition(fallback, state.incoming_byte)? {
                        break target;
                    }
                    if fallback == 0 {
                        break 0;
                    }
                    fallback = self
                        .states
                        .get(usize::try_from(fallback).map_err(|_| {
                            RegexSetExact64AuthenticationError::Shape(
                                "nested failure token does not fit usize",
                            )
                        })?)
                        .ok_or(RegexSetExact64AuthenticationError::Shape(
                            "nested failure token is outside the graph",
                        ))?
                        .failure;
                }
            };
            if state.failure != expected_failure {
                return Err(RegexSetExact64AuthenticationError::Shape(
                    "failure link is not the longest proper trie suffix",
                ));
            }
            let inherited_mask = self
                .states
                .get(usize::try_from(expected_failure).map_err(|_| {
                    RegexSetExact64AuthenticationError::Shape(
                        "authenticated failure token does not fit usize",
                    )
                })?)
                .ok_or(RegexSetExact64AuthenticationError::Shape(
                    "authenticated failure token is outside the graph",
                ))?
                .output_mask;
            if state.output_mask != state.direct_output_mask | inherited_mask {
                return Err(RegexSetExact64AuthenticationError::Shape(
                    "state output mask does not inherit its failure output",
                ));
            }
        }
        if authenticated_failure_steps != self.receipt.failure_steps {
            return Err(RegexSetExact64AuthenticationError::Shape(
                "failure-link work receipt does not authenticate",
            ));
        }

        let mut mapped_literal_bytes = 0_u64;
        for ordinal in 0..self.receipt.pattern_count {
            let terminal = self.source_terminals[usize::from(ordinal)];
            let terminal_state = self
                .states
                .get(usize::try_from(terminal).map_err(|_| {
                    RegexSetExact64AuthenticationError::Shape(
                        "source terminal token does not fit usize",
                    )
                })?)
                .ok_or(RegexSetExact64AuthenticationError::Shape(
                    "source terminal token is outside the graph",
                ))?;
            let bit = 1_u64 << u32::from(ordinal);
            if terminal == 0 || terminal_state.direct_output_mask & bit == 0 {
                return Err(RegexSetExact64AuthenticationError::Shape(
                    "source ordinal does not map to its direct terminal",
                ));
            }
            mapped_literal_bytes = mapped_literal_bytes
                .checked_add(u64::from(terminal_state.depth))
                .ok_or(RegexSetExact64AuthenticationError::Shape(
                    "mapped literal byte census overflowed",
                ))?;
        }
        if self.source_terminals[pattern_count..]
            .iter()
            .any(|&terminal| terminal != u32::MAX)
            || mapped_literal_bytes != self.receipt.literal_bytes
        {
            return Err(RegexSetExact64AuthenticationError::Shape(
                "source-to-terminal mapping does not authenticate",
            ));
        }

        let actual = artifact_identity(
            self.receipt.source_artifact,
            self.receipt.source_mapping_digest,
            self.receipt.exact_literal_algorithm_version,
            self.receipt.exact_literal_accounting_version,
            self.receipt.fact_algorithm_version,
            self.receipt.fact_accounting_version,
            self.receipt.pattern_count,
            self.receipt.all_pattern_mask,
            self.receipt.literal_bytes,
            self.receipt.failure_steps,
            self.receipt.state_count,
            self.receipt.transition_count,
            &self.source_terminals,
            &self.states,
            &self.edges,
        );
        if actual != self.receipt.artifact {
            return Err(RegexSetExact64AuthenticationError::ArtifactIdentity {
                expected: self.receipt.artifact,
                actual,
            });
        }
        Ok(())
    }

    fn authenticate_against_witnesses(
        &self,
        witnesses: &[Option<Vec<u8>>],
    ) -> Result<(), RegexSetExact64CompileError> {
        if witnesses.len() != usize::from(self.receipt.pattern_count)
            || source_mapping_digest(witnesses)? != self.receipt.source_mapping_digest
        {
            return Err(RegexSetExact64CompileError::InternalInvariant(
                "exact64 proof-byte mapping changed before publication",
            ));
        }
        let mut literal_bytes = 0_u64;
        for (ordinal, witness) in witnesses.iter().enumerate() {
            let literal =
                witness
                    .as_ref()
                    .ok_or(RegexSetExact64CompileError::InternalInvariant(
                        "exact64 construction authentication lost a witness",
                    ))?;
            let mut state = 0_u32;
            for &byte in literal {
                state = self
                    .direct_transition(state, byte)
                    .map_err(RegexSetExact64CompileError::Authentication)?
                    .ok_or(RegexSetExact64CompileError::InternalInvariant(
                        "exact64 trie path disagrees with its proof bytes",
                    ))?;
            }
            let bit = 1_u64
                .checked_shl(u32::try_from(ordinal).map_err(|_| {
                    RegexSetExact64CompileError::ArithmeticOverflow {
                        computation: "construction-authentication source bit",
                    }
                })?)
                .ok_or(RegexSetExact64CompileError::ArithmeticOverflow {
                    computation: "construction-authentication source mask",
                })?;
            let terminal = self.source_terminals[ordinal];
            let terminal_state = self
                .states
                .get(usize::try_from(terminal).map_err(|_| {
                    RegexSetExact64CompileError::ArithmeticOverflow {
                        computation: "construction-authentication terminal index",
                    }
                })?)
                .ok_or(RegexSetExact64CompileError::InternalInvariant(
                    "exact64 construction terminal is outside the graph",
                ))?;
            if state != terminal || terminal_state.direct_output_mask & bit == 0 {
                return Err(RegexSetExact64CompileError::InternalInvariant(
                    "exact64 proof bytes do not reach their direct source terminal",
                ));
            }
            literal_bytes = literal_bytes
                .checked_add(usize_to_u64(
                    literal.len(),
                    "construction-authentication literal width",
                )?)
                .ok_or(RegexSetExact64CompileError::ArithmeticOverflow {
                    computation: "construction-authentication literal byte sum",
                })?;
        }
        if literal_bytes != self.receipt.literal_bytes {
            return Err(RegexSetExact64CompileError::InternalInvariant(
                "exact64 construction literal byte census changed",
            ));
        }
        Ok(())
    }

    fn direct_transition(
        &self,
        state: u32,
        byte: u8,
    ) -> Result<Option<u32>, RegexSetExact64AuthenticationError> {
        let state = self
            .states
            .get(usize::try_from(state).map_err(|_| {
                RegexSetExact64AuthenticationError::Shape(
                    "direct-transition state does not fit usize",
                )
            })?)
            .ok_or(RegexSetExact64AuthenticationError::Shape(
                "direct-transition state is outside the graph",
            ))?;
        let start = usize::try_from(state.edge_start).map_err(|_| {
            RegexSetExact64AuthenticationError::Shape(
                "direct-transition edge offset does not fit usize",
            )
        })?;
        let end = start.checked_add(usize::from(state.edge_count)).ok_or(
            RegexSetExact64AuthenticationError::Shape("direct-transition edge range overflowed"),
        )?;
        let edges = self
            .edges
            .get(start..end)
            .ok_or(RegexSetExact64AuthenticationError::Shape(
                "direct-transition edge range is outside the graph",
            ))?;
        Ok(edges
            .binary_search_by_key(&byte, |edge| edge.byte)
            .ok()
            .map(|edge| edges[edge].target))
    }

    /// Scan one window once and publish all matching source IDs as a `u64`.
    ///
    /// The caller word is unchanged on every error. Exact source ordinals are
    /// retained, including duplicate literals. Matches must be wholly inside
    /// the supplied half-open window.
    pub fn fill_matches(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        output: &mut u64,
    ) -> Result<RegexSetExact64FillReport, RegexSetExact64RunError> {
        self.authenticate()
            .map_err(RegexSetExact64RunError::Authentication)?;
        if window.start() > window.end() || window.end() > haystack.len() {
            return Err(RegexSetExact64RunError::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len: haystack.len(),
            });
        }

        let mut state = 0_u32;
        let mut matched = 0_u64;
        for &byte in &haystack[window.start()..window.end()] {
            state = self
                .next_state(state, byte)
                .map_err(RegexSetExact64RunError::Authentication)?;
            let state_index = usize::try_from(state).map_err(|_| {
                RegexSetExact64RunError::Authentication(RegexSetExact64AuthenticationError::Shape(
                    "runtime state token does not fit usize",
                ))
            })?;
            let output_mask = self
                .states
                .get(state_index)
                .ok_or(RegexSetExact64RunError::Authentication(
                    RegexSetExact64AuthenticationError::Shape(
                        "runtime state token is outside the graph",
                    ),
                ))?
                .output_mask;
            matched |= output_mask;
            if matched == self.receipt.all_pattern_mask {
                break;
            }
        }
        *output = matched;
        Ok(RegexSetExact64FillReport {
            matched_count: matched.count_ones(),
            matched_mask: matched,
        })
    }

    fn next_state(
        &self,
        mut state: u32,
        byte: u8,
    ) -> Result<u32, RegexSetExact64AuthenticationError> {
        loop {
            let index = usize::try_from(state).map_err(|_| {
                RegexSetExact64AuthenticationError::Shape(
                    "runtime transition state does not fit usize",
                )
            })?;
            let current =
                self.states
                    .get(index)
                    .ok_or(RegexSetExact64AuthenticationError::Shape(
                        "runtime transition state is outside the graph",
                    ))?;
            let start = usize::try_from(current.edge_start).map_err(|_| {
                RegexSetExact64AuthenticationError::Shape("runtime edge offset does not fit usize")
            })?;
            let end = start.checked_add(usize::from(current.edge_count)).ok_or(
                RegexSetExact64AuthenticationError::Shape("runtime edge range overflowed"),
            )?;
            let edges =
                self.edges
                    .get(start..end)
                    .ok_or(RegexSetExact64AuthenticationError::Shape(
                        "runtime edge range is outside the graph",
                    ))?;
            if let Ok(edge) = edges.binary_search_by_key(&byte, |edge| edge.byte) {
                return Ok(edges[edge].target);
            }
            if state == 0 {
                return Ok(0);
            }
            state = current.failure;
        }
    }
}

/// Successful target-neutral oracle report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegexSetExact64FillReport {
    matched_count: u32,
    matched_mask: u64,
}

impl RegexSetExact64FillReport {
    /// Number of distinct source IDs whose bits were published.
    #[must_use]
    pub const fn matched_count(self) -> u32 {
        self.matched_count
    }

    /// Exact published source-ID mask.
    #[must_use]
    pub const fn matched_mask(self) -> u64 {
        self.matched_mask
    }

    /// Whether at least one source row matched.
    #[must_use]
    pub const fn any(self) -> bool {
        self.matched_mask != 0
    }
}

/// Result of the explicit exact-set selection attempt.
#[derive(Clone, Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "boxing either outcome would add an allocation after the selected compiler transaction"
)]
pub enum RegexSetExact64CompileDisposition {
    Selected(RegexSetExact64Program),
    Declined {
        program: RegexSetProgram,
        reason: RegexSetExact64Decline,
    },
}

impl RegexSetExact64CompileDisposition {
    /// Return the authoritative independent-row program in either outcome.
    #[must_use]
    pub const fn fallback(&self) -> &RegexSetProgram {
        match self {
            Self::Selected(program) => program.fallback(),
            Self::Declined { program, .. } => program,
        }
    }
}

/// Terminal failure of the opt-in exact-set compile transaction.
#[derive(Debug)]
#[non_exhaustive]
pub enum RegexSetExact64CompileError {
    RegexSet(RegexSetCompileError),
    AllocationFailed {
        structure: &'static str,
        additional: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    InternalInvariant(&'static str),
    Authentication(RegexSetExact64AuthenticationError),
}

impl fmt::Display for RegexSetExact64CompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegexSet(source) => write!(formatter, "regex-set compilation: {source}"),
            Self::AllocationFailed {
                structure,
                additional,
            } => write!(
                formatter,
                "shared exact regex-set construction could not reserve {additional} entries for {structure}"
            ),
            Self::ArithmeticOverflow { computation } => write!(
                formatter,
                "shared exact regex-set construction overflow computing {computation}"
            ),
            Self::InternalInvariant(detail) => {
                write!(
                    formatter,
                    "shared exact regex-set invariant failed: {detail}"
                )
            }
            Self::Authentication(source) => {
                write!(formatter, "shared exact regex-set authentication: {source}")
            }
        }
    }
}

impl std::error::Error for RegexSetExact64CompileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RegexSet(source) => Some(source),
            Self::Authentication(source) => Some(source),
            Self::AllocationFailed { .. }
            | Self::ArithmeticOverflow { .. }
            | Self::InternalInvariant(_) => None,
        }
    }
}

impl From<RegexSetCompileError> for RegexSetExact64CompileError {
    fn from(source: RegexSetCompileError) -> Self {
        Self::RegexSet(source)
    }
}

/// Failure authenticating a retained target-neutral exact-set graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RegexSetExact64AuthenticationError {
    SchemaVersion {
        expected: u32,
        actual: u32,
    },
    ExactLiteralIdentity {
        expected_algorithm: u32,
        actual_algorithm: u32,
        expected_accounting: u32,
        actual_accounting: u32,
    },
    FactIdentity {
        expected_algorithm: u32,
        actual_algorithm: u32,
        expected_accounting: u32,
        actual_accounting: u32,
    },
    SourceArtifact {
        expected: RegexSetArtifactIdentity,
        actual: RegexSetArtifactIdentity,
    },
    Shape(&'static str),
    ArtifactIdentity {
        expected: RegexSetExact64ArtifactIdentity,
        actual: RegexSetExact64ArtifactIdentity,
    },
}

impl fmt::Display for RegexSetExact64AuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SchemaVersion { expected, actual } => {
                write!(formatter, "schema version {actual}, expected {expected}")
            }
            Self::ExactLiteralIdentity {
                expected_algorithm,
                actual_algorithm,
                expected_accounting,
                actual_accounting,
            } => write!(
                formatter,
                "exact-literal identity algorithm/accounting {actual_algorithm}/{actual_accounting}, expected {expected_algorithm}/{expected_accounting}"
            ),
            Self::FactIdentity {
                expected_algorithm,
                actual_algorithm,
                expected_accounting,
                actual_accounting,
            } => write!(
                formatter,
                "HIR-fact identity algorithm/accounting {actual_algorithm}/{actual_accounting}, expected {expected_algorithm}/{expected_accounting}"
            ),
            Self::SourceArtifact { .. } => {
                formatter.write_str("source artifact identity does not match the incumbent")
            }
            Self::Shape(detail) => write!(formatter, "invalid graph shape: {detail}"),
            Self::ArtifactIdentity { .. } => {
                formatter.write_str("graph artifact identity does not authenticate")
            }
        }
    }
}

impl std::error::Error for RegexSetExact64AuthenticationError {}

/// Failure from the allocation-free target-neutral oracle. The caller's
/// output word is unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RegexSetExact64RunError {
    Authentication(RegexSetExact64AuthenticationError),
    InvalidWindow {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
}

impl fmt::Display for RegexSetExact64RunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authentication(source) => write!(formatter, "authentication: {source}"),
            Self::InvalidWindow {
                start,
                end,
                haystack_len,
            } => write!(
                formatter,
                "invalid exact-set search window {start}..{end} for haystack length {haystack_len}"
            ),
        }
    }
}

impl std::error::Error for RegexSetExact64RunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Authentication(source) => Some(source),
            Self::InvalidWindow { .. } => None,
        }
    }
}

/// Compile the authoritative independent rows and report whether a shared
/// exact-set target-neutral graph was selected.
///
/// This is the only entry that requests exact64 witnesses. The existing
/// [`crate::compile_regex_set`] entry and all of its defaults remain unchanged.
pub fn compile_regex_set_exact64_reported(
    request: RegexSetCompileRequest,
    limits: RegexSetExact64Limits,
) -> Result<RegexSetExact64CompileDisposition, RegexSetExact64CompileError> {
    let pattern_count = request.patterns.len();
    let preliminary_decline = if request.mode != CompileMode::Optimizing {
        Some(RegexSetExact64Decline::RequiresOptimizing {
            actual: request.mode,
        })
    } else if !(REGEX_SET_EXACT64_MIN_PATTERNS..=REGEX_SET_EXACT64_MAX_PATTERNS)
        .contains(&pattern_count)
    {
        Some(RegexSetExact64Decline::PatternCount {
            needed: pattern_count,
            minimum: REGEX_SET_EXACT64_MIN_PATTERNS,
            maximum: REGEX_SET_EXACT64_MAX_PATTERNS,
        })
    } else {
        None
    };
    if let Some(reason) = preliminary_decline {
        let program = compile_regex_set(request)?;
        return Ok(RegexSetExact64CompileDisposition::Declined { program, reason });
    }

    let compiled = compile_regex_set_with_exact64_witnesses(request, limits.max_literal_bytes)?;
    let witness_decline = compiled.witness_decline;
    let program = compiled.program;
    let witnesses = compiled.witnesses;
    if let Some(decline) = witness_decline {
        let reason = match decline {
            RegexSetExact64WitnessDecline::RowNotExactSingleton { pattern } => {
                RegexSetExact64Decline::RowNotExactSingleton { pattern }
            }
            RegexSetExact64WitnessDecline::LiteralBytes { needed, limit } => {
                RegexSetExact64Decline::Resource {
                    resource: RegexSetExact64Resource::LiteralBytes,
                    needed,
                    limit,
                }
            }
        };
        return Ok(RegexSetExact64CompileDisposition::Declined { program, reason });
    }
    if witnesses.iter().any(Option::is_none) {
        return Err(RegexSetExact64CompileError::InternalInvariant(
            "exact64 witness table declined without a reason",
        ));
    }
    build_exact64(program, &witnesses, limits)
}

#[allow(
    clippy::too_many_lines,
    reason = "the trie, failure links, canonical storage, receipt, and final authentication are one fail-closed construction transaction"
)]
fn build_exact64(
    fallback: RegexSetProgram,
    witnesses: &[Option<Vec<u8>>],
    limits: RegexSetExact64Limits,
) -> Result<RegexSetExact64CompileDisposition, RegexSetExact64CompileError> {
    let pattern_count = witnesses.len();
    if fallback.len() != pattern_count
        || fallback.mode() != CompileMode::Optimizing
        || !(REGEX_SET_EXACT64_MIN_PATTERNS..=REGEX_SET_EXACT64_MAX_PATTERNS)
            .contains(&pattern_count)
    {
        return Err(RegexSetExact64CompileError::InternalInvariant(
            "exact64 builder received an ineligible incumbent",
        ));
    }
    let mut literal_bytes = 0usize;
    let mut maximum_literal_width = 0usize;
    for witness in witnesses {
        let literal = witness
            .as_ref()
            .ok_or(RegexSetExact64CompileError::InternalInvariant(
                "selected exact64 builder received a missing witness",
            ))?;
        if literal.is_empty() {
            return Err(RegexSetExact64CompileError::InternalInvariant(
                "selected exact64 builder received an empty witness",
            ));
        }
        literal_bytes = literal_bytes.checked_add(literal.len()).ok_or(
            RegexSetExact64CompileError::ArithmeticOverflow {
                computation: "literal byte sum",
            },
        )?;
        maximum_literal_width = maximum_literal_width.max(literal.len());
    }
    if literal_bytes > limits.max_literal_bytes {
        return Ok(decline_resource(
            fallback,
            RegexSetExact64Resource::LiteralBytes,
            usize_to_u64(literal_bytes, "literal byte requirement")?,
            usize_to_u64(limits.max_literal_bytes, "literal byte limit")?,
        ));
    }
    let minimum_states = maximum_literal_width.checked_add(1).ok_or(
        RegexSetExact64CompileError::ArithmeticOverflow {
            computation: "minimum trie states",
        },
    )?;
    let representation_state_limit = limits
        .max_states
        .min(usize::try_from(u32::MAX).unwrap_or(usize::MAX));
    if minimum_states > representation_state_limit {
        return Ok(decline_resource(
            fallback,
            RegexSetExact64Resource::States,
            usize_to_u64(minimum_states, "minimum state requirement")?,
            usize_to_u64(representation_state_limit, "state limit")?,
        ));
    }
    if maximum_literal_width > limits.max_transition_cells {
        return Ok(decline_resource(
            fallback,
            RegexSetExact64Resource::TransitionCells,
            usize_to_u64(maximum_literal_width, "minimum transition requirement")?,
            usize_to_u64(limits.max_transition_cells, "transition limit")?,
        ));
    }
    if maximum_literal_width > 1 && limits.max_failure_steps == 0 {
        return Ok(decline_resource(
            fallback,
            RegexSetExact64Resource::FailureSteps,
            1,
            0,
        ));
    }

    let prospective_states =
        literal_bytes
            .checked_add(1)
            .ok_or(RegexSetExact64CompileError::ArithmeticOverflow {
                computation: "prospective trie states",
            })?;
    let state_storage_limit = prospective_states
        .min(representation_state_limit)
        .min(limits.max_transition_cells.saturating_add(1));
    let mut states = Vec::new();
    reserve(
        &mut states,
        state_storage_limit.min(1_024),
        "exact64 build states",
    )?;
    states.push(BuildState::new(0, 0, 0));
    let mut transition_count = 0usize;
    let mut source_terminals = [u32::MAX; REGEX_SET_EXACT64_MAX_PATTERNS];

    for (ordinal, witness) in witnesses.iter().enumerate() {
        let literal = witness
            .as_ref()
            .ok_or(RegexSetExact64CompileError::InternalInvariant(
                "exact64 witness disappeared during trie construction",
            ))?;
        let bit = 1_u64
            .checked_shl(u32::try_from(ordinal).map_err(|_| {
                RegexSetExact64CompileError::ArithmeticOverflow {
                    computation: "source ordinal mask shift",
                }
            })?)
            .ok_or(RegexSetExact64CompileError::ArithmeticOverflow {
                computation: "source ordinal mask",
            })?;
        let mut state = 0usize;
        for &byte in literal {
            let edge = states[state]
                .edges
                .as_slice()
                .binary_search_by_key(&byte, |&(edge_byte, _)| edge_byte);
            state = match edge {
                Ok(edge) => {
                    usize::try_from(states[state].edges.as_slice()[edge].1).map_err(|_| {
                        RegexSetExact64CompileError::ArithmeticOverflow {
                            computation: "trie target index",
                        }
                    })?
                }
                Err(edge) => {
                    let needed_states = states.len().checked_add(1).ok_or(
                        RegexSetExact64CompileError::ArithmeticOverflow {
                            computation: "trie state count",
                        },
                    )?;
                    if needed_states > representation_state_limit {
                        return Ok(decline_resource(
                            fallback,
                            RegexSetExact64Resource::States,
                            usize_to_u64(needed_states, "state requirement")?,
                            usize_to_u64(representation_state_limit, "state limit")?,
                        ));
                    }
                    let needed_transitions = transition_count.checked_add(1).ok_or(
                        RegexSetExact64CompileError::ArithmeticOverflow {
                            computation: "transition count",
                        },
                    )?;
                    if needed_transitions > limits.max_transition_cells {
                        return Ok(decline_resource(
                            fallback,
                            RegexSetExact64Resource::TransitionCells,
                            usize_to_u64(needed_transitions, "transition requirement")?,
                            usize_to_u64(limits.max_transition_cells, "transition limit")?,
                        ));
                    }
                    reserve_geometric(
                        &mut states,
                        state_storage_limit,
                        "exact64 build states",
                        "exact64 build state count",
                    )?;
                    let next = u32::try_from(states.len()).map_err(|_| {
                        RegexSetExact64CompileError::ArithmeticOverflow {
                            computation: "trie state token",
                        }
                    })?;
                    let depth = states[state].depth.checked_add(1).ok_or(
                        RegexSetExact64CompileError::ArithmeticOverflow {
                            computation: "trie depth",
                        },
                    )?;
                    let parent = u32::try_from(state).map_err(|_| {
                        RegexSetExact64CompileError::ArithmeticOverflow {
                            computation: "trie parent token",
                        }
                    })?;
                    states.push(BuildState::new(depth, parent, byte));
                    states[state].edges.insert(edge, (byte, next))?;
                    transition_count = needed_transitions;
                    usize::try_from(next).map_err(|_| {
                        RegexSetExact64CompileError::ArithmeticOverflow {
                            computation: "new trie state index",
                        }
                    })?
                }
            };
        }
        source_terminals[ordinal] =
            u32::try_from(state).map_err(|_| RegexSetExact64CompileError::ArithmeticOverflow {
                computation: "source terminal token",
            })?;
        states[state].direct_output_mask |= bit;
        states[state].output_mask |= bit;
    }

    let mut breadth_first = Vec::new();
    reserve(
        &mut breadth_first,
        states.len(),
        "exact64 breadth-first states",
    )?;
    breadth_first.push(0_u32);
    for &(_, target) in states[0].edges.as_slice() {
        breadth_first.push(target);
    }
    let mut cursor = 1usize;
    let mut failure_steps = 0_u64;
    while cursor < breadth_first.len() {
        let state = usize::try_from(breadth_first[cursor]).map_err(|_| {
            RegexSetExact64CompileError::ArithmeticOverflow {
                computation: "breadth-first state index",
            }
        })?;
        cursor = cursor
            .checked_add(1)
            .ok_or(RegexSetExact64CompileError::ArithmeticOverflow {
                computation: "breadth-first cursor",
            })?;
        for edge_index in 0..states[state].edges.as_slice().len() {
            let (byte, next_token) = states[state].edges.as_slice()[edge_index];
            let next = usize::try_from(next_token).map_err(|_| {
                RegexSetExact64CompileError::ArithmeticOverflow {
                    computation: "failure child index",
                }
            })?;
            let mut fallback_state = usize::try_from(states[state].failure).map_err(|_| {
                RegexSetExact64CompileError::ArithmeticOverflow {
                    computation: "failure state index",
                }
            })?;
            let failure = loop {
                failure_steps = failure_steps.checked_add(1).ok_or(
                    RegexSetExact64CompileError::ArithmeticOverflow {
                        computation: "failure-link work",
                    },
                )?;
                if failure_steps > limits.max_failure_steps {
                    return Ok(decline_resource(
                        fallback,
                        RegexSetExact64Resource::FailureSteps,
                        failure_steps,
                        limits.max_failure_steps,
                    ));
                }
                if let Some(target) = edge_target(states[fallback_state].edges.as_slice(), byte) {
                    break target;
                }
                if fallback_state == 0 {
                    break 0;
                }
                fallback_state = usize::try_from(states[fallback_state].failure).map_err(|_| {
                    RegexSetExact64CompileError::ArithmeticOverflow {
                        computation: "nested failure state index",
                    }
                })?;
            };
            let inherited = usize::try_from(failure).map_err(|_| {
                RegexSetExact64CompileError::ArithmeticOverflow {
                    computation: "inherited output state index",
                }
            })?;
            let inherited_mask = states[inherited].output_mask;
            states[next].failure = failure;
            states[next].output_mask |= inherited_mask;
            breadth_first.push(next_token);
        }
    }
    if breadth_first.len() != states.len() {
        return Err(RegexSetExact64CompileError::InternalInvariant(
            "breadth-first traversal missed trie states",
        ));
    }

    let mut frozen_states = Vec::new();
    reserve(&mut frozen_states, states.len(), "exact64 frozen states")?;
    let mut frozen_edges = Vec::new();
    reserve(&mut frozen_edges, transition_count, "exact64 frozen edges")?;
    for state in &states {
        let edge_start = u32::try_from(frozen_edges.len()).map_err(|_| {
            RegexSetExact64CompileError::ArithmeticOverflow {
                computation: "frozen edge offset",
            }
        })?;
        let edge_count = u16::try_from(state.edges.as_slice().len()).map_err(|_| {
            RegexSetExact64CompileError::ArithmeticOverflow {
                computation: "frozen state edge count",
            }
        })?;
        frozen_edges.extend(
            state
                .edges
                .as_slice()
                .iter()
                .map(|&(byte, target)| Exact64Edge { byte, target }),
        );
        frozen_states.push(Exact64State {
            failure: state.failure,
            parent: state.parent,
            edge_start,
            edge_count,
            incoming_byte: state.incoming_byte,
            depth: state.depth,
            direct_output_mask: state.direct_output_mask,
            output_mask: state.output_mask,
        });
    }
    if frozen_edges.len() != transition_count {
        return Err(RegexSetExact64CompileError::InternalInvariant(
            "frozen transition census changed",
        ));
    }

    let pattern_count_u8 = u8::try_from(pattern_count).map_err(|_| {
        RegexSetExact64CompileError::ArithmeticOverflow {
            computation: "receipt pattern count",
        }
    })?;
    let literal_bytes_u64 = usize_to_u64(literal_bytes, "receipt literal bytes")?;
    let state_count = u32::try_from(frozen_states.len()).map_err(|_| {
        RegexSetExact64CompileError::ArithmeticOverflow {
            computation: "receipt state count",
        }
    })?;
    let transition_count_u32 = u32::try_from(frozen_edges.len()).map_err(|_| {
        RegexSetExact64CompileError::ArithmeticOverflow {
            computation: "receipt transition count",
        }
    })?;
    let source_artifact = fallback.artifact_identity();
    let source_mapping_digest = source_mapping_digest(witnesses)?;
    let all_pattern_mask = all_pattern_mask(pattern_count);
    let artifact = artifact_identity(
        source_artifact,
        source_mapping_digest,
        CANONICAL_EXACT_LITERAL_ALGORITHM_VERSION,
        CANONICAL_EXACT_LITERAL_ACCOUNTING_VERSION,
        HIR_FACT_ALGORITHM_VERSION,
        HIR_FACT_ACCOUNTING_VERSION,
        pattern_count_u8,
        all_pattern_mask,
        literal_bytes_u64,
        failure_steps,
        state_count,
        transition_count_u32,
        &source_terminals,
        &frozen_states,
        &frozen_edges,
    );
    let program = RegexSetExact64Program {
        fallback,
        receipt: RegexSetExact64Receipt {
            schema_version: REGEX_SET_EXACT64_SCHEMA_VERSION,
            exact_literal_algorithm_version: CANONICAL_EXACT_LITERAL_ALGORITHM_VERSION,
            exact_literal_accounting_version: CANONICAL_EXACT_LITERAL_ACCOUNTING_VERSION,
            fact_algorithm_version: HIR_FACT_ALGORITHM_VERSION,
            fact_accounting_version: HIR_FACT_ACCOUNTING_VERSION,
            source_artifact,
            artifact,
            source_mapping_digest,
            pattern_count: pattern_count_u8,
            all_pattern_mask,
            literal_bytes: literal_bytes_u64,
            state_count,
            transition_count: transition_count_u32,
            failure_steps,
        },
        source_terminals,
        states: frozen_states,
        edges: frozen_edges,
    };
    program
        .authenticate()
        .map_err(RegexSetExact64CompileError::Authentication)?;
    program.authenticate_against_witnesses(witnesses)?;
    Ok(RegexSetExact64CompileDisposition::Selected(program))
}

fn decline_resource(
    program: RegexSetProgram,
    resource: RegexSetExact64Resource,
    needed: u64,
    limit: u64,
) -> RegexSetExact64CompileDisposition {
    RegexSetExact64CompileDisposition::Declined {
        program,
        reason: RegexSetExact64Decline::Resource {
            resource,
            needed,
            limit,
        },
    }
}

// Return the next allocation target rather than an additional element count.
// This makes the number of outer-trie reservations logarithmic while ensuring
// every request remains at or below the already authenticated logical limit.
fn next_geometric_capacity(
    len: usize,
    capacity: usize,
    logical_limit: usize,
    computation: &'static str,
) -> Result<Option<usize>, RegexSetExact64CompileError> {
    let needed = len
        .checked_add(1)
        .ok_or(RegexSetExact64CompileError::ArithmeticOverflow { computation })?;
    if needed > logical_limit {
        return Err(RegexSetExact64CompileError::InternalInvariant(
            "exact64 geometric reservation crossed its logical limit",
        ));
    }
    if needed <= capacity {
        return Ok(None);
    }
    let doubled = capacity.checked_mul(2).unwrap_or(logical_limit);
    let target = doubled.max(needed).min(logical_limit);
    if target < needed {
        return Err(RegexSetExact64CompileError::InternalInvariant(
            "exact64 geometric reservation did not cover its next entry",
        ));
    }
    Ok(Some(target))
}

fn reserve_geometric<T>(
    values: &mut Vec<T>,
    logical_limit: usize,
    structure: &'static str,
    computation: &'static str,
) -> Result<(), RegexSetExact64CompileError> {
    let Some(target) =
        next_geometric_capacity(values.len(), values.capacity(), logical_limit, computation)?
    else {
        return Ok(());
    };
    let additional =
        target
            .checked_sub(values.len())
            .ok_or(RegexSetExact64CompileError::InternalInvariant(
                "exact64 geometric reservation target preceded its length",
            ))?;
    reserve(values, additional, structure)
}

fn reserve<T>(
    values: &mut Vec<T>,
    additional: usize,
    structure: &'static str,
) -> Result<(), RegexSetExact64CompileError> {
    values.try_reserve_exact(additional).map_err(|_| {
        RegexSetExact64CompileError::AllocationFailed {
            structure,
            additional,
        }
    })
}

fn edge_target(edges: &[(u8, u32)], byte: u8) -> Option<u32> {
    edges
        .binary_search_by_key(&byte, |&(edge_byte, _)| edge_byte)
        .ok()
        .map(|edge| edges[edge].1)
}

const fn all_pattern_mask(pattern_count: usize) -> u64 {
    if pattern_count == REGEX_SET_EXACT64_MAX_PATTERNS {
        u64::MAX
    } else {
        (1_u64 << pattern_count).saturating_sub(1)
    }
}

fn usize_to_u64(
    value: usize,
    computation: &'static str,
) -> Result<u64, RegexSetExact64CompileError> {
    u64::try_from(value)
        .map_err(|_| RegexSetExact64CompileError::ArithmeticOverflow { computation })
}

fn source_mapping_digest(
    witnesses: &[Option<Vec<u8>>],
) -> Result<[u8; 32], RegexSetExact64CompileError> {
    let mut digest = Sha256::new();
    digest.update(REGEX_SET_EXACT64_SOURCE_DOMAIN);
    digest.update(REGEX_SET_EXACT64_SCHEMA_VERSION.to_le_bytes());
    digest.update(CANONICAL_EXACT_LITERAL_ALGORITHM_VERSION.to_le_bytes());
    digest.update(CANONICAL_EXACT_LITERAL_ACCOUNTING_VERSION.to_le_bytes());
    digest.update(HIR_FACT_ALGORITHM_VERSION.to_le_bytes());
    digest.update(HIR_FACT_ACCOUNTING_VERSION.to_le_bytes());
    digest.update(usize_to_u64(witnesses.len(), "source digest row count")?.to_le_bytes());
    for (ordinal, witness) in witnesses.iter().enumerate() {
        let literal = witness
            .as_ref()
            .ok_or(RegexSetExact64CompileError::InternalInvariant(
                "source digest received a missing literal witness",
            ))?;
        digest.update(usize_to_u64(ordinal, "source digest ordinal")?.to_le_bytes());
        digest.update(usize_to_u64(literal.len(), "source digest literal width")?.to_le_bytes());
        digest.update(literal);
    }
    Ok(<[u8; 32]>::from(digest.finalize()))
}

#[allow(
    clippy::too_many_arguments,
    reason = "all authenticated receipt and graph fields are explicit digest inputs"
)]
fn artifact_identity(
    source_artifact: RegexSetArtifactIdentity,
    source_mapping_digest: [u8; 32],
    exact_literal_algorithm_version: u32,
    exact_literal_accounting_version: u32,
    fact_algorithm_version: u32,
    fact_accounting_version: u32,
    pattern_count: u8,
    all_pattern_mask: u64,
    literal_bytes: u64,
    failure_steps: u64,
    state_count: u32,
    transition_count: u32,
    source_terminals: &[u32; REGEX_SET_EXACT64_MAX_PATTERNS],
    states: &[Exact64State],
    edges: &[Exact64Edge],
) -> RegexSetExact64ArtifactIdentity {
    let mut digest = Sha256::new();
    digest.update(REGEX_SET_EXACT64_ARTIFACT_DOMAIN);
    digest.update(REGEX_SET_EXACT64_SCHEMA_VERSION.to_le_bytes());
    digest.update(exact_literal_algorithm_version.to_le_bytes());
    digest.update(exact_literal_accounting_version.to_le_bytes());
    digest.update(fact_algorithm_version.to_le_bytes());
    digest.update(fact_accounting_version.to_le_bytes());
    digest.update(source_artifact.as_bytes());
    digest.update(source_mapping_digest);
    digest.update([pattern_count]);
    digest.update(all_pattern_mask.to_le_bytes());
    digest.update(literal_bytes.to_le_bytes());
    digest.update(failure_steps.to_le_bytes());
    digest.update(u64::from(state_count).to_le_bytes());
    digest.update(u64::from(transition_count).to_le_bytes());
    for terminal in &source_terminals[..usize::from(pattern_count)] {
        digest.update(terminal.to_le_bytes());
    }
    for state in states {
        digest.update(state.failure.to_le_bytes());
        digest.update(state.parent.to_le_bytes());
        digest.update(state.edge_start.to_le_bytes());
        digest.update(state.edge_count.to_le_bytes());
        digest.update([state.incoming_byte]);
        digest.update(state.depth.to_le_bytes());
        digest.update(state.direct_output_mask.to_le_bytes());
        digest.update(state.output_mask.to_le_bytes());
    }
    for edge in edges {
        digest.update([edge.byte]);
        digest.update(edge.target.to_le_bytes());
    }
    RegexSetExact64ArtifactIdentity(<[u8; 32]>::from(digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selected(patterns: &[&str]) -> RegexSetExact64Program {
        let request = RegexSetCompileRequest::new(
            patterns
                .iter()
                .map(|pattern| (*pattern).to_owned())
                .collect(),
        );
        match compile_regex_set_exact64_reported(request, RegexSetExact64Limits::default())
            .expect("exact64 compile")
        {
            RegexSetExact64CompileDisposition::Selected(program) => program,
            RegexSetExact64CompileDisposition::Declined { reason, .. } => {
                panic!("unexpected decline: {reason}")
            }
        }
    }

    fn witnesses(patterns: &[&str]) -> Vec<Option<Vec<u8>>> {
        patterns
            .iter()
            .map(|pattern| Some(pattern.as_bytes().to_vec()))
            .collect()
    }

    #[test]
    fn build_state_growth_is_geometric_and_logically_bounded() {
        let logical_limit = 1_usize << 20;
        let mut capacity = 1_024_usize;
        let mut reservations = 0_usize;
        while capacity < logical_limit {
            let target = next_geometric_capacity(
                capacity,
                capacity,
                logical_limit,
                "synthetic exact64 state growth",
            )
            .expect("valid growth plan")
            .expect("full capacity needs another reservation");
            assert!(target > capacity);
            assert!(target <= logical_limit);
            capacity = target;
            reservations += 1;
        }
        assert_eq!(logical_limit, capacity);
        assert_eq!(10, reservations);
        assert_eq!(
            None,
            next_geometric_capacity(
                logical_limit - 1,
                logical_limit,
                logical_limit,
                "synthetic exact64 state growth",
            )
            .unwrap()
        );
        assert!(matches!(
            next_geometric_capacity(
                logical_limit,
                logical_limit,
                logical_limit,
                "synthetic exact64 state growth",
            ),
            Err(RegexSetExact64CompileError::InternalInvariant(
                "exact64 geometric reservation crossed its logical limit"
            ))
        ));

        let truncated_limit = 1_000_000;
        assert_eq!(
            Some(truncated_limit),
            next_geometric_capacity(
                1 << 19,
                1 << 19,
                truncated_limit,
                "synthetic exact64 truncated growth",
            )
            .unwrap()
        );
    }

    #[test]
    fn first_build_edge_stays_inline_and_spill_remains_sorted() {
        let mut edges = BuildEdges::Empty;
        edges.insert(0, (b'm', 1)).unwrap();
        assert!(matches!(&edges, BuildEdges::Inline((b'm', 1))));
        assert_eq!(&[(b'm', 1)], edges.as_slice());

        edges.insert(0, (b'a', 2)).unwrap();
        assert!(matches!(&edges, BuildEdges::Spill(_)));
        assert_eq!(&[(b'a', 2), (b'm', 1)], edges.as_slice());
        edges.insert(2, (b'z', 3)).unwrap();
        assert_eq!(&[(b'a', 2), (b'm', 1), (b'z', 3)], edges.as_slice());
    }

    fn rehash_after_internal_mutation(program: &mut RegexSetExact64Program) {
        program.receipt.artifact = artifact_identity(
            program.receipt.source_artifact,
            program.receipt.source_mapping_digest,
            program.receipt.exact_literal_algorithm_version,
            program.receipt.exact_literal_accounting_version,
            program.receipt.fact_algorithm_version,
            program.receipt.fact_accounting_version,
            program.receipt.pattern_count,
            program.receipt.all_pattern_mask,
            program.receipt.literal_bytes,
            program.receipt.failure_steps,
            program.receipt.state_count,
            program.receipt.transition_count,
            &program.source_terminals,
            &program.states,
            &program.edges,
        );
    }

    #[test]
    fn corrupt_graph_fails_authentication_without_publication() {
        let mut program = selected(&["ab", "bc"]);
        program.states[0].edge_start = 1;
        let sentinel = 0xfeed_face_dead_beef;
        let mut output = sentinel;
        assert!(matches!(
            program.fill_matches(b"abc", SearchWindow::new(0, 3), &mut output),
            Err(RegexSetExact64RunError::Authentication(_))
        ));
        assert_eq!(sentinel, output);
    }

    #[test]
    fn missing_failure_output_fails_even_with_rehashed_artifact() {
        let mut program = selected(&["he", "she"]);
        let terminal = usize::try_from(program.source_terminals[1]).unwrap();
        assert_eq!(0b11, program.states[terminal].output_mask);
        assert_eq!(0b10, program.states[terminal].direct_output_mask);
        program.states[terminal].output_mask = program.states[terminal].direct_output_mask;
        rehash_after_internal_mutation(&mut program);

        let sentinel = 0xfeed_face_dead_beef;
        let mut output = sentinel;
        assert!(matches!(
            program.fill_matches(b"she", SearchWindow::new(0, 3), &mut output),
            Err(RegexSetExact64RunError::Authentication(
                RegexSetExact64AuthenticationError::Shape(
                    "state output mask does not inherit its failure output"
                )
            ))
        ));
        assert_eq!(sentinel, output);
    }

    #[test]
    fn transformed_trie_byte_fails_independent_witness_authentication() {
        let patterns = ["ab", "cd"];
        let mut program = selected(&patterns);
        let terminal = usize::try_from(program.source_terminals[0]).unwrap();
        let parent = usize::try_from(program.states[terminal].parent).unwrap();
        let start = usize::try_from(program.states[parent].edge_start).unwrap();
        let end = start + usize::from(program.states[parent].edge_count);
        let edge = program.edges[start..end]
            .iter()
            .position(|edge| usize::try_from(edge.target).ok() == Some(terminal))
            .map(|edge| start + edge)
            .unwrap();
        program.edges[edge].byte = b'x';
        program.states[terminal].incoming_byte = b'x';
        rehash_after_internal_mutation(&mut program);
        program
            .authenticate()
            .expect("transformed trie remains internally consistent");
        assert!(matches!(
            program.authenticate_against_witnesses(&witnesses(&patterns)),
            Err(RegexSetExact64CompileError::InternalInvariant(
                "exact64 trie path disagrees with its proof bytes"
            ))
        ));
    }

    #[test]
    fn swapped_duplicate_ordinals_and_terminal_masks_fail_witness_authentication() {
        let patterns = ["ab", "cd", "ab"];
        let mut program = selected(&patterns);
        let first = usize::try_from(program.source_terminals[0]).unwrap();
        let second = usize::try_from(program.source_terminals[1]).unwrap();
        assert_eq!(program.source_terminals[0], program.source_terminals[2]);
        assert_eq!(0b101, program.states[first].direct_output_mask);
        assert_eq!(0b010, program.states[second].direct_output_mask);

        program.source_terminals[0] = u32::try_from(second).unwrap();
        program.source_terminals[1] = u32::try_from(first).unwrap();
        program.source_terminals[2] = u32::try_from(second).unwrap();
        program.states[first].direct_output_mask = 0b010;
        program.states[first].output_mask = 0b010;
        program.states[second].direct_output_mask = 0b101;
        program.states[second].output_mask = 0b101;
        rehash_after_internal_mutation(&mut program);
        program
            .authenticate()
            .expect("coordinated ordinal and terminal-mask swap is internally consistent");
        assert!(matches!(
            program.authenticate_against_witnesses(&witnesses(&patterns)),
            Err(RegexSetExact64CompileError::InternalInvariant(
                "exact64 proof bytes do not reach their direct source terminal"
            ))
        ));
    }

    #[test]
    fn isolated_source_terminal_corruption_fails_before_publication() {
        let mut program = selected(&["ab", "bc"]);
        program.source_terminals[0] = program.source_terminals[1];
        rehash_after_internal_mutation(&mut program);

        let sentinel = 0xfeed_face_dead_beef;
        let mut output = sentinel;
        assert!(matches!(
            program.fill_matches(b"abc", SearchWindow::new(0, 3), &mut output),
            Err(RegexSetExact64RunError::Authentication(
                RegexSetExact64AuthenticationError::Shape(
                    "source ordinal does not map to its direct terminal"
                )
            ))
        ));
        assert_eq!(sentinel, output);
    }

    #[test]
    fn stale_fact_identity_fails_without_publication() {
        let mut program = selected(&["ab", "bc"]);
        program.receipt.fact_algorithm_version =
            program.receipt.fact_algorithm_version.wrapping_add(1);
        let sentinel = 0xfeed_face_dead_beef;
        let mut output = sentinel;
        assert!(matches!(
            program.fill_matches(b"abc", SearchWindow::new(0, 3), &mut output),
            Err(RegexSetExact64RunError::Authentication(
                RegexSetExact64AuthenticationError::FactIdentity { .. }
            ))
        ));
        assert_eq!(sentinel, output);
    }

    #[test]
    fn stale_exact_literal_identity_fails_without_publication() {
        let mut program = selected(&["ab", "bc"]);
        program.receipt.exact_literal_algorithm_version = program
            .receipt
            .exact_literal_algorithm_version
            .wrapping_add(1);
        let sentinel = 0xfeed_face_dead_beef;
        let mut output = sentinel;
        assert!(matches!(
            program.fill_matches(b"abc", SearchWindow::new(0, 3), &mut output),
            Err(RegexSetExact64RunError::Authentication(
                RegexSetExact64AuthenticationError::ExactLiteralIdentity { .. }
            ))
        ));
        assert_eq!(sentinel, output);
    }
}
