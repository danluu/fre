//! Opt-in one-scan substrate for small complete finite byte regex sets.
//!
//! Every source row is still compiled into the authoritative independent-row
//! [`crate::RegexSetProgram`]. This reported entry additionally selects one
//! Aho-Corasick scan when current checked HIR facts prove that every row is a
//! complete, nonempty, assertion-free finite byte language. A `u64` publishes
//! every matching source ordinal; leftmost ordering is deliberately irrelevant
//! to this Exists-only contract.

use core::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(test)]
use std::cell::Cell;

use fre_lower::{FactResource, HIR_FACT_ACCOUNTING_VERSION, HIR_FACT_ALGORITHM_VERSION};
use sha2::{Digest, Sha256};

use crate::{
    CompileMode, SearchWindow,
    finite_language::NativeFiniteLanguageCandidate,
    regex_set::{
        RegexSetArtifactIdentity, RegexSetCompileError, RegexSetCompileRequest,
        RegexSetFinite64WitnessDecline, RegexSetFinite64WitnessLimits, RegexSetProgram,
        compile_regex_set, compile_regex_set_with_finite64_witnesses,
    },
};

/// Stable target-neutral receipt and graph schema.
pub const REGEX_SET_FINITE64_SCHEMA_VERSION: u32 = 1;
/// Smallest source count for which one aggregate scan is useful.
pub const REGEX_SET_FINITE64_MIN_PATTERNS: usize = 2;
/// Result-mask representation ceiling.
pub const REGEX_SET_FINITE64_MAX_PATTERNS: usize = 64;

const SOURCE_DOMAIN: &[u8] = b"FRE-AOT-REGEX-SET-FINITE64-SOURCE\0";
const ARTIFACT_DOMAIN: &[u8] = b"FRE-AOT-REGEX-SET-FINITE64\0";
const MAX_EDGES_PER_STATE: usize = 256;
static NEXT_FINITE64_INSTANCE: AtomicU64 = AtomicU64::new(1);

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestReserveFault {
    Disabled,
    Armed(&'static str),
    Failed,
}

#[cfg(test)]
thread_local! {
    static TEST_RESERVE_FAULT: Cell<TestReserveFault> = const {
        Cell::new(TestReserveFault::Disabled)
    };
}

#[cfg(test)]
struct TestReserveFaultGuard;

#[cfg(test)]
impl TestReserveFaultGuard {
    fn arm(structure: &'static str) -> Self {
        TEST_RESERVE_FAULT.with(|fault| {
            assert_eq!(
                TestReserveFault::Disabled,
                fault.replace(TestReserveFault::Armed(structure))
            );
        });
        Self
    }
}

#[cfg(test)]
impl Drop for TestReserveFaultGuard {
    fn drop(&mut self) {
        TEST_RESERVE_FAULT.with(|fault| fault.set(TestReserveFault::Disabled));
    }
}

#[cfg(test)]
fn injected_reserve_failure(structure: &'static str) -> bool {
    TEST_RESERVE_FAULT.with(|fault| match fault.get() {
        TestReserveFault::Disabled => false,
        TestReserveFault::Armed(expected) if expected != structure => false,
        TestReserveFault::Armed(_) => {
            fault.set(TestReserveFault::Failed);
            true
        }
        TestReserveFault::Failed => {
            panic!("finite64 attempted another graph allocation after allocator failure")
        }
    })
}

/// Explicit proof and graph construction ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegexSetFinite64Limits {
    /// Maximum aggregate number of finite strings across every source row.
    pub max_finite_strings: usize,
    /// Maximum aggregate bytes across every finite string.
    pub max_literal_bytes: usize,
    /// Maximum trie states, including the root.
    pub max_states: usize,
    /// Maximum explicit trie edges.
    pub max_transition_cells: usize,
    /// Maximum failure-link probes during graph construction.
    pub max_failure_steps: u64,
}

impl Default for RegexSetFinite64Limits {
    fn default() -> Self {
        Self {
            max_finite_strings: 4_096,
            max_literal_bytes: 1_048_576,
            max_states: 1 << 20,
            max_transition_cells: 1 << 20,
            max_failure_steps: 64_000_000,
        }
    }
}

/// Bounded proof or graph resource that can decline to the exact incumbent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RegexSetFinite64Resource {
    FiniteStrings,
    LiteralBytes,
    States,
    TransitionCells,
    FailureSteps,
    FactWork,
    FactStackItems,
    FactHirNodes,
    FactRetainedBytes,
    FactTemporaryBytes,
    FactPeakBytes,
    FactAllocationAttempts,
    FactRequiredGroups,
    FactRequiredAlternatives,
    FactRequiredBytes,
    FactAssertions,
    FactDeterministicStates,
}

impl fmt::Display for RegexSetFinite64Resource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::FiniteStrings => "finite-language strings",
            Self::LiteralBytes => "finite-language bytes",
            Self::States => "states",
            Self::TransitionCells => "transition cells",
            Self::FailureSteps => "failure-link steps",
            Self::FactWork => "HIR-fact work",
            Self::FactStackItems => "HIR-fact stack items",
            Self::FactHirNodes => "HIR nodes",
            Self::FactRetainedBytes => "retained HIR-fact bytes",
            Self::FactTemporaryBytes => "temporary HIR-fact bytes",
            Self::FactPeakBytes => "peak HIR-fact bytes",
            Self::FactAllocationAttempts => "HIR-fact allocation attempts",
            Self::FactRequiredGroups => "required groups",
            Self::FactRequiredAlternatives => "required alternatives",
            Self::FactRequiredBytes => "required bytes",
            Self::FactAssertions => "assertions",
            Self::FactDeterministicStates => "deterministic states",
        })
    }
}

/// Auditable reason why the explicit finite-set candidate was not selected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RegexSetFinite64Decline {
    RequiresOptimizing {
        actual: CompileMode,
    },
    PatternCount {
        needed: usize,
        minimum: usize,
        maximum: usize,
    },
    RowNotFiniteLanguage {
        pattern: usize,
    },
    Resource {
        /// Source row for a proof limit, or `None` for aggregate graph work.
        pattern: Option<usize>,
        resource: RegexSetFinite64Resource,
        needed: u64,
        limit: u64,
    },
}

impl fmt::Display for RegexSetFinite64Decline {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequiresOptimizing { actual } => write!(
                formatter,
                "shared finite regex-set scan requires Optimizing mode, got {actual:?}"
            ),
            Self::PatternCount {
                needed,
                minimum,
                maximum,
            } => write!(
                formatter,
                "shared finite regex-set scan needs {minimum}..={maximum} patterns, got {needed}"
            ),
            Self::RowNotFiniteLanguage { pattern } => write!(
                formatter,
                "regex-set row {pattern} lacks a complete nonempty assertion-free finite-language proof"
            ),
            Self::Resource {
                pattern,
                resource,
                needed,
                limit,
            } => {
                if let Some(pattern) = pattern {
                    write!(
                        formatter,
                        "regex-set row {pattern} needs {needed} {resource}, limit is {limit}"
                    )
                } else {
                    write!(
                        formatter,
                        "shared finite regex-set scan needs {needed} {resource}, limit is {limit}"
                    )
                }
            }
        }
    }
}

impl std::error::Error for RegexSetFinite64Decline {}

/// Stable identity of one source-ordered finite-language graph.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct RegexSetFinite64ArtifactIdentity([u8; 32]);

impl RegexSetFinite64ArtifactIdentity {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Authenticated source mapping and graph dimensions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegexSetFinite64Receipt {
    schema_version: u32,
    fact_algorithm_version: u32,
    fact_accounting_version: u32,
    source_artifact: RegexSetArtifactIdentity,
    artifact: RegexSetFinite64ArtifactIdentity,
    source_mapping_digest: [u8; 32],
    pattern_count: u8,
    all_pattern_mask: u64,
    finite_string_count: u32,
    literal_bytes: u64,
    maximum_literal_width: u32,
    state_count: u32,
    transition_count: u32,
    failure_steps: u64,
}

impl RegexSetFinite64Receipt {
    #[must_use]
    pub const fn schema_version(self) -> u32 {
        self.schema_version
    }
    #[must_use]
    pub const fn fact_algorithm_version(self) -> u32 {
        self.fact_algorithm_version
    }
    #[must_use]
    pub const fn fact_accounting_version(self) -> u32 {
        self.fact_accounting_version
    }
    #[must_use]
    pub const fn source_artifact(self) -> RegexSetArtifactIdentity {
        self.source_artifact
    }
    #[must_use]
    pub const fn artifact_identity(self) -> RegexSetFinite64ArtifactIdentity {
        self.artifact
    }
    #[must_use]
    pub const fn source_mapping_digest(self) -> [u8; 32] {
        self.source_mapping_digest
    }
    #[must_use]
    pub const fn pattern_count(self) -> u8 {
        self.pattern_count
    }
    #[must_use]
    pub const fn all_pattern_mask(self) -> u64 {
        self.all_pattern_mask
    }
    #[must_use]
    pub const fn finite_string_count(self) -> u32 {
        self.finite_string_count
    }
    #[must_use]
    pub const fn literal_bytes(self) -> u64 {
        self.literal_bytes
    }
    #[must_use]
    pub const fn maximum_literal_width(self) -> u32 {
        self.maximum_literal_width
    }
    #[must_use]
    pub const fn state_count(self) -> u32 {
        self.state_count
    }
    #[must_use]
    pub const fn transition_count(self) -> u32 {
        self.transition_count
    }
    #[must_use]
    pub const fn failure_steps(self) -> u64 {
        self.failure_steps
    }
}

#[derive(Clone, Copy, Debug)]
struct Finite64State {
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
struct Finite64Edge {
    byte: u8,
    target: u32,
}

#[derive(Clone, Copy, Debug)]
struct Finite64SourceMap {
    pattern: u8,
    language_ordinal: u32,
    terminal: u32,
    width: u32,
}

// Most finite-language trie states have one outgoing edge. Keeping that edge
// inline avoids one allocator transaction per state while still preserving a
// fully fallible transition to the uncommon branch representation.
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

    fn insert(
        &mut self,
        index: usize,
        edge: (u8, u32),
    ) -> Result<(), RegexSetFinite64CompileError> {
        match self {
            Self::Empty => {
                if index != 0 {
                    return Err(RegexSetFinite64CompileError::InternalInvariant(
                        "finite64 empty edge set received a nonzero insertion index",
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
                    return Err(RegexSetFinite64CompileError::InternalInvariant(
                        "finite64 inline edge insertion was not strictly ordered",
                    ));
                }
                let retained = *retained;
                let mut edges = Vec::new();
                reserve(&mut edges, 2, "finite64 trie branch edges")?;
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
                    return Err(RegexSetFinite64CompileError::InternalInvariant(
                        "finite64 spilled edge insertion was not strictly ordered",
                    ));
                }
                reserve_geometric(
                    edges,
                    MAX_EDGES_PER_STATE,
                    "finite64 trie branch edges",
                    "finite64 trie branch edge count",
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Finite64Identity {
    artifact: RegexSetFinite64ArtifactIdentity,
    instance: u64,
}

/// Immutable target-neutral shared finite-set program and exact fallback.
#[derive(Clone, Debug)]
pub struct RegexSetFinite64Program {
    fallback: RegexSetProgram,
    receipt: RegexSetFinite64Receipt,
    identity: Finite64Identity,
    source_mapping: Vec<Finite64SourceMap>,
    states: Vec<Finite64State>,
    edges: Vec<Finite64Edge>,
}

/// Reusable authentication receipt for allocation-free warm scans.
#[derive(Clone, Copy, Debug)]
pub struct RegexSetFinite64Session {
    identity: Finite64Identity,
    max_source_bytes: usize,
}

impl RegexSetFinite64Session {
    #[must_use]
    pub const fn max_source_bytes(&self) -> usize {
        self.max_source_bytes
    }
}

/// Successful transactional fill report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegexSetFinite64FillReport {
    matched_count: u32,
    matched_mask: u64,
}

impl RegexSetFinite64FillReport {
    #[must_use]
    pub const fn matched_count(self) -> u32 {
        self.matched_count
    }
    #[must_use]
    pub const fn matched_mask(self) -> u64 {
        self.matched_mask
    }
    #[must_use]
    pub const fn any(self) -> bool {
        self.matched_mask != 0
    }
}

/// Result of the explicit optimizer selection attempt.
#[derive(Clone, Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "boxing would add an allocation after the compile transaction"
)]
pub enum RegexSetFinite64CompileDisposition {
    Selected(RegexSetFinite64Program),
    Declined {
        program: RegexSetProgram,
        reason: RegexSetFinite64Decline,
    },
}

impl RegexSetFinite64CompileDisposition {
    #[must_use]
    pub const fn fallback(&self) -> &RegexSetProgram {
        match self {
            Self::Selected(program) => program.fallback(),
            Self::Declined { program, .. } => program,
        }
    }
}

/// Terminal failure of the finite-set compile transaction.
#[derive(Debug)]
#[non_exhaustive]
pub enum RegexSetFinite64CompileError {
    RegexSet(RegexSetCompileError),
    AllocationFailed {
        structure: &'static str,
        additional: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    InternalInvariant(&'static str),
    Authentication(RegexSetFinite64AuthenticationError),
}

impl fmt::Display for RegexSetFinite64CompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegexSet(source) => write!(formatter, "regex-set compilation: {source}"),
            Self::AllocationFailed {
                structure,
                additional,
            } => write!(
                formatter,
                "shared finite regex-set construction could not reserve {additional} entries for {structure}"
            ),
            Self::ArithmeticOverflow { computation } => write!(
                formatter,
                "shared finite regex-set construction overflow computing {computation}"
            ),
            Self::InternalInvariant(detail) => {
                write!(
                    formatter,
                    "shared finite regex-set invariant failed: {detail}"
                )
            }
            Self::Authentication(source) => {
                write!(
                    formatter,
                    "shared finite regex-set authentication: {source}"
                )
            }
        }
    }
}

impl std::error::Error for RegexSetFinite64CompileError {
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

impl From<RegexSetCompileError> for RegexSetFinite64CompileError {
    fn from(source: RegexSetCompileError) -> Self {
        Self::RegexSet(source)
    }
}

/// Failure authenticating a retained target-neutral graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RegexSetFinite64AuthenticationError {
    SchemaVersion {
        expected: u32,
        actual: u32,
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
        expected: RegexSetFinite64ArtifactIdentity,
        actual: RegexSetFinite64ArtifactIdentity,
    },
}

impl fmt::Display for RegexSetFinite64AuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SchemaVersion { expected, actual } => {
                write!(formatter, "schema version {actual}, expected {expected}")
            }
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

impl std::error::Error for RegexSetFinite64AuthenticationError {}

/// Failure from a target-neutral scan. The caller output is unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RegexSetFinite64RunError {
    Authentication(RegexSetFinite64AuthenticationError),
    SessionProgramMismatch {
        expected_artifact: RegexSetFinite64ArtifactIdentity,
        actual_artifact: RegexSetFinite64ArtifactIdentity,
        clone_lineage_matches: bool,
    },
    SourceBytesLimit {
        needed: usize,
        limit: usize,
    },
    InvalidWindow {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
}

impl fmt::Display for RegexSetFinite64RunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authentication(source) => write!(formatter, "authentication: {source}"),
            Self::SessionProgramMismatch { .. } => {
                formatter.write_str("finite-set session belongs to a different program")
            }
            Self::SourceBytesLimit { needed, limit } => write!(
                formatter,
                "finite-set scan needs {needed} source bytes, session limit is {limit}"
            ),
            Self::InvalidWindow {
                start,
                end,
                haystack_len,
            } => write!(
                formatter,
                "invalid finite-set search window {start}..{end} for haystack length {haystack_len}"
            ),
        }
    }
}

impl std::error::Error for RegexSetFinite64RunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Authentication(source) => Some(source),
            Self::SessionProgramMismatch { .. }
            | Self::SourceBytesLimit { .. }
            | Self::InvalidWindow { .. } => None,
        }
    }
}

impl RegexSetFinite64Program {
    /// Complete independently compiled semantic incumbent.
    #[must_use]
    pub const fn fallback(&self) -> &RegexSetProgram {
        &self.fallback
    }

    /// Authenticated source mapping and graph dimensions.
    #[must_use]
    pub const fn receipt(&self) -> RegexSetFinite64Receipt {
        self.receipt
    }

    /// Authenticate once and create an allocation-free reusable scan session.
    pub fn prepare_session(
        &self,
        max_source_bytes: usize,
    ) -> Result<RegexSetFinite64Session, RegexSetFinite64AuthenticationError> {
        self.authenticate()?;
        Ok(RegexSetFinite64Session {
            identity: self.identity,
            max_source_bytes,
        })
    }

    /// Authenticate and scan once. Prefer a prepared session for repeated use.
    pub fn fill_matches(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        output: &mut u64,
    ) -> Result<RegexSetFinite64FillReport, RegexSetFinite64RunError> {
        self.authenticate()
            .map_err(RegexSetFinite64RunError::Authentication)?;
        self.fill_after_preflight(haystack, window, output)
    }

    /// Scan once using a reusable authentication receipt.
    pub fn fill_matches_with_session(
        &self,
        session: &RegexSetFinite64Session,
        haystack: &[u8],
        window: SearchWindow,
        output: &mut u64,
    ) -> Result<RegexSetFinite64FillReport, RegexSetFinite64RunError> {
        if session.identity != self.identity {
            return Err(RegexSetFinite64RunError::SessionProgramMismatch {
                expected_artifact: self.identity.artifact,
                actual_artifact: session.identity.artifact,
                clone_lineage_matches: session.identity.instance == self.identity.instance,
            });
        }
        if haystack.len() > session.max_source_bytes {
            return Err(RegexSetFinite64RunError::SourceBytesLimit {
                needed: haystack.len(),
                limit: session.max_source_bytes,
            });
        }
        self.fill_after_preflight(haystack, window, output)
    }

    fn fill_after_preflight(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        output: &mut u64,
    ) -> Result<RegexSetFinite64FillReport, RegexSetFinite64RunError> {
        if window.start() > window.end() || window.end() > haystack.len() {
            return Err(RegexSetFinite64RunError::InvalidWindow {
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
                .map_err(RegexSetFinite64RunError::Authentication)?;
            let state = self
                .states
                .get(usize::try_from(state).map_err(|_| {
                    RegexSetFinite64RunError::Authentication(
                        RegexSetFinite64AuthenticationError::Shape(
                            "runtime state token does not fit usize",
                        ),
                    )
                })?)
                .ok_or(RegexSetFinite64RunError::Authentication(
                    RegexSetFinite64AuthenticationError::Shape(
                        "runtime state token is outside the graph",
                    ),
                ))?;
            matched |= state.output_mask;
            if matched == self.receipt.all_pattern_mask {
                break;
            }
        }
        *output = matched;
        Ok(RegexSetFinite64FillReport {
            matched_count: matched.count_ones(),
            matched_mask: matched,
        })
    }

    fn next_state(
        &self,
        mut state: u32,
        byte: u8,
    ) -> Result<u32, RegexSetFinite64AuthenticationError> {
        loop {
            if let Some(target) = self.direct_transition(state, byte)? {
                return Ok(target);
            }
            if state == 0 {
                return Ok(0);
            }
            state = self
                .states
                .get(usize::try_from(state).map_err(|_| {
                    RegexSetFinite64AuthenticationError::Shape(
                        "runtime transition state does not fit usize",
                    )
                })?)
                .ok_or(RegexSetFinite64AuthenticationError::Shape(
                    "runtime transition state is outside the graph",
                ))?
                .failure;
        }
    }

    fn direct_transition(
        &self,
        state: u32,
        byte: u8,
    ) -> Result<Option<u32>, RegexSetFinite64AuthenticationError> {
        self.direct_transition_usize(
            usize::try_from(state).map_err(|_| {
                RegexSetFinite64AuthenticationError::Shape(
                    "direct-transition state does not fit usize",
                )
            })?,
            byte,
        )
    }

    fn direct_transition_usize(
        &self,
        state: usize,
        byte: u8,
    ) -> Result<Option<u32>, RegexSetFinite64AuthenticationError> {
        let state = self
            .states
            .get(state)
            .ok_or(RegexSetFinite64AuthenticationError::Shape(
                "direct-transition state is outside the graph",
            ))?;
        let start = usize::try_from(state.edge_start).map_err(|_| {
            RegexSetFinite64AuthenticationError::Shape(
                "direct-transition edge offset does not fit usize",
            )
        })?;
        let end = start.checked_add(usize::from(state.edge_count)).ok_or(
            RegexSetFinite64AuthenticationError::Shape("direct-transition edge range overflowed"),
        )?;
        let edges =
            self.edges
                .get(start..end)
                .ok_or(RegexSetFinite64AuthenticationError::Shape(
                    "direct-transition edge range is outside the graph",
                ))?;
        Ok(edges
            .binary_search_by_key(&byte, |edge| edge.byte)
            .ok()
            .map(|index| edges[index].target))
    }

    /// Revalidate the receipt, source mapping, trie, failure links, masks,
    /// and stable artifact identity without allocating.
    #[allow(
        clippy::too_many_lines,
        reason = "complete fail-closed graph authentication is one transaction"
    )]
    pub fn authenticate(&self) -> Result<(), RegexSetFinite64AuthenticationError> {
        if self.receipt.schema_version != REGEX_SET_FINITE64_SCHEMA_VERSION {
            return Err(RegexSetFinite64AuthenticationError::SchemaVersion {
                expected: REGEX_SET_FINITE64_SCHEMA_VERSION,
                actual: self.receipt.schema_version,
            });
        }
        if self.receipt.fact_algorithm_version != HIR_FACT_ALGORITHM_VERSION
            || self.receipt.fact_accounting_version != HIR_FACT_ACCOUNTING_VERSION
        {
            return Err(RegexSetFinite64AuthenticationError::FactIdentity {
                expected_algorithm: HIR_FACT_ALGORITHM_VERSION,
                actual_algorithm: self.receipt.fact_algorithm_version,
                expected_accounting: HIR_FACT_ACCOUNTING_VERSION,
                actual_accounting: self.receipt.fact_accounting_version,
            });
        }
        if self.fallback.artifact_identity() != self.receipt.source_artifact {
            return Err(RegexSetFinite64AuthenticationError::SourceArtifact {
                expected: self.receipt.source_artifact,
                actual: self.fallback.artifact_identity(),
            });
        }
        let pattern_count = usize::from(self.receipt.pattern_count);
        if self.fallback.mode() != CompileMode::Optimizing
            || self.fallback.len() != pattern_count
            || !(REGEX_SET_FINITE64_MIN_PATTERNS..=REGEX_SET_FINITE64_MAX_PATTERNS)
                .contains(&pattern_count)
            || self.fallback.required_words() != 1
            || self.receipt.all_pattern_mask != all_pattern_mask(pattern_count)
        {
            return Err(RegexSetFinite64AuthenticationError::Shape(
                "source program and result-mask dimensions disagree",
            ));
        }
        if usize::try_from(self.receipt.finite_string_count).ok() != Some(self.source_mapping.len())
            || usize::try_from(self.receipt.state_count).ok() != Some(self.states.len())
            || usize::try_from(self.receipt.transition_count).ok() != Some(self.edges.len())
            || self.source_mapping.is_empty()
            || self.states.is_empty()
            || self.states.len().checked_sub(1) != Some(self.edges.len())
        {
            return Err(RegexSetFinite64AuthenticationError::Shape(
                "receipt dimensions disagree with retained storage",
            ));
        }

        let mut next_edge = 0usize;
        let mut published_mask = 0_u64;
        for (state_index, state) in self.states.iter().enumerate() {
            let edge_start = usize::try_from(state.edge_start).map_err(|_| {
                RegexSetFinite64AuthenticationError::Shape("state edge offset does not fit usize")
            })?;
            let edge_end = edge_start
                .checked_add(usize::from(state.edge_count))
                .ok_or(RegexSetFinite64AuthenticationError::Shape(
                    "state edge range overflowed",
                ))?;
            if edge_start != next_edge || edge_end > self.edges.len() {
                return Err(RegexSetFinite64AuthenticationError::Shape(
                    "state edge ranges are not one canonical partition",
                ));
            }
            if (state.direct_output_mask | state.output_mask) & !self.receipt.all_pattern_mask != 0
            {
                return Err(RegexSetFinite64AuthenticationError::Shape(
                    "state publishes a bit outside the source set",
                ));
            }
            published_mask |= state.output_mask;
            let failure = usize::try_from(state.failure).map_err(|_| {
                RegexSetFinite64AuthenticationError::Shape("failure token does not fit usize")
            })?;
            if state_index == 0 {
                if state.failure != 0
                    || state.parent != 0
                    || state.incoming_byte != 0
                    || state.depth != 0
                    || state.direct_output_mask != 0
                    || state.output_mask != 0
                {
                    return Err(RegexSetFinite64AuthenticationError::Shape(
                        "nonempty finite-set root state is malformed",
                    ));
                }
            } else if failure >= self.states.len() || self.states[failure].depth >= state.depth {
                return Err(RegexSetFinite64AuthenticationError::Shape(
                    "failure link does not point to a shallower state",
                ));
            }
            let mut previous = None;
            for edge in &self.edges[edge_start..edge_end] {
                if previous.is_some_and(|byte| byte >= edge.byte) {
                    return Err(RegexSetFinite64AuthenticationError::Shape(
                        "state edges are not strictly byte-sorted",
                    ));
                }
                previous = Some(edge.byte);
                let target = usize::try_from(edge.target).map_err(|_| {
                    RegexSetFinite64AuthenticationError::Shape(
                        "transition target does not fit usize",
                    )
                })?;
                let target_depth = state.depth.checked_add(1).ok_or(
                    RegexSetFinite64AuthenticationError::Shape(
                        "transition source depth overflowed",
                    ),
                )?;
                if target >= self.states.len() || self.states[target].depth != target_depth {
                    return Err(RegexSetFinite64AuthenticationError::Shape(
                        "transition target is not the next trie depth",
                    ));
                }
            }
            next_edge = edge_end;
        }
        if next_edge != self.edges.len() || published_mask != self.receipt.all_pattern_mask {
            return Err(RegexSetFinite64AuthenticationError::Shape(
                "canonical graph does not publish every source bit",
            ));
        }

        let mut authenticated_failure_steps = 0_u64;
        for (state_index, state) in self.states.iter().enumerate().skip(1) {
            let parent = usize::try_from(state.parent).map_err(|_| {
                RegexSetFinite64AuthenticationError::Shape("parent token does not fit usize")
            })?;
            let expected_depth = self
                .states
                .get(parent)
                .and_then(|parent| parent.depth.checked_add(1))
                .ok_or(RegexSetFinite64AuthenticationError::Shape(
                    "parent token or depth is invalid",
                ))?;
            if state.depth != expected_depth
                || self.direct_transition(state.parent, state.incoming_byte)?
                    != Some(u32::try_from(state_index).map_err(|_| {
                        RegexSetFinite64AuthenticationError::Shape(
                            "state index does not fit its token representation",
                        )
                    })?)
            {
                return Err(RegexSetFinite64AuthenticationError::Shape(
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
                        .ok_or(RegexSetFinite64AuthenticationError::Shape(
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
                            RegexSetFinite64AuthenticationError::Shape(
                                "nested failure token does not fit usize",
                            )
                        })?)
                        .ok_or(RegexSetFinite64AuthenticationError::Shape(
                            "nested failure token is outside the graph",
                        ))?
                        .failure;
                }
            };
            if state.failure != expected_failure {
                return Err(RegexSetFinite64AuthenticationError::Shape(
                    "failure link is not the longest proper trie suffix",
                ));
            }
            let inherited = self
                .states
                .get(usize::try_from(expected_failure).map_err(|_| {
                    RegexSetFinite64AuthenticationError::Shape(
                        "authenticated failure token does not fit usize",
                    )
                })?)
                .ok_or(RegexSetFinite64AuthenticationError::Shape(
                    "authenticated failure token is outside the graph",
                ))?
                .output_mask;
            if state.output_mask != state.direct_output_mask | inherited {
                return Err(RegexSetFinite64AuthenticationError::Shape(
                    "state output mask does not inherit its failure output",
                ));
            }
        }
        if authenticated_failure_steps != self.receipt.failure_steps {
            return Err(RegexSetFinite64AuthenticationError::Shape(
                "failure-link work receipt does not authenticate",
            ));
        }

        let mut literal_bytes = 0_u64;
        let mut maximum_width = 0_u32;
        let mut mapped_mask = 0_u64;
        let mut previous_mapping: Option<&Finite64SourceMap> = None;
        for mapping in &self.source_mapping {
            let canonical = match previous_mapping {
                None => mapping.pattern == 0 && mapping.language_ordinal == 0,
                Some(previous) if mapping.pattern == previous.pattern => previous
                    .language_ordinal
                    .checked_add(1)
                    .is_some_and(|ordinal| mapping.language_ordinal == ordinal),
                Some(previous) => {
                    previous
                        .pattern
                        .checked_add(1)
                        .is_some_and(|pattern| mapping.pattern == pattern)
                        && mapping.language_ordinal == 0
                }
            };
            if !canonical {
                return Err(RegexSetFinite64AuthenticationError::Shape(
                    "source mapping is not canonical source/language order",
                ));
            }
            let terminal = self
                .states
                .get(usize::try_from(mapping.terminal).map_err(|_| {
                    RegexSetFinite64AuthenticationError::Shape(
                        "source terminal token does not fit usize",
                    )
                })?)
                .ok_or(RegexSetFinite64AuthenticationError::Shape(
                    "source terminal token is outside the graph",
                ))?;
            let bit = 1_u64.checked_shl(u32::from(mapping.pattern)).ok_or(
                RegexSetFinite64AuthenticationError::Shape(
                    "source pattern bit is outside the result word",
                ),
            )?;
            if mapping.terminal == 0
                || mapping.width == 0
                || mapping.width != terminal.depth
                || terminal.direct_output_mask & bit == 0
            {
                return Err(RegexSetFinite64AuthenticationError::Shape(
                    "source mapping does not reach its direct terminal",
                ));
            }
            literal_bytes = literal_bytes.checked_add(u64::from(mapping.width)).ok_or(
                RegexSetFinite64AuthenticationError::Shape("mapped literal byte census overflowed"),
            )?;
            maximum_width = maximum_width.max(mapping.width);
            mapped_mask |= bit;
            previous_mapping = Some(mapping);
        }
        if previous_mapping.map(|mapping| mapping.pattern)
            != Some(self.receipt.pattern_count.saturating_sub(1))
            || mapped_mask != self.receipt.all_pattern_mask
            || literal_bytes != self.receipt.literal_bytes
            || maximum_width != self.receipt.maximum_literal_width
        {
            return Err(RegexSetFinite64AuthenticationError::Shape(
                "source mapping census does not authenticate",
            ));
        }
        for (state_index, state) in self.states.iter().enumerate() {
            let mut bits = state.direct_output_mask;
            while bits != 0 {
                let pattern = bits.trailing_zeros();
                let bit = 1_u64 << pattern;
                if !self.source_mapping.iter().any(|mapping| {
                    u32::from(mapping.pattern) == pattern
                        && usize::try_from(mapping.terminal).ok() == Some(state_index)
                }) {
                    return Err(RegexSetFinite64AuthenticationError::Shape(
                        "direct terminal bit lacks a source mapping",
                    ));
                }
                bits &= !bit;
            }
        }

        let actual = artifact_identity(
            self.receipt,
            &self.source_mapping,
            &self.states,
            &self.edges,
        );
        if actual != self.receipt.artifact {
            return Err(RegexSetFinite64AuthenticationError::ArtifactIdentity {
                expected: self.receipt.artifact,
                actual,
            });
        }
        Ok(())
    }

    fn authenticate_against_witnesses(
        &self,
        witnesses: &[Option<NativeFiniteLanguageCandidate>],
    ) -> Result<(), RegexSetFinite64CompileError> {
        if witnesses.len() != usize::from(self.receipt.pattern_count)
            || source_mapping_digest(witnesses)? != self.receipt.source_mapping_digest
        {
            return Err(RegexSetFinite64CompileError::InternalInvariant(
                "finite64 proof-byte mapping changed before publication",
            ));
        }
        let mut mapping_index = 0usize;
        let mut literal_bytes = 0_u64;
        for (pattern, witness) in witnesses.iter().enumerate() {
            let witness =
                witness
                    .as_ref()
                    .ok_or(RegexSetFinite64CompileError::InternalInvariant(
                        "finite64 construction authentication lost a witness",
                    ))?;
            for (language_ordinal, literal) in witness.regex_set_strings().iter().enumerate() {
                if literal.is_empty() {
                    return Err(RegexSetFinite64CompileError::InternalInvariant(
                        "finite64 construction authentication received an empty string",
                    ));
                }
                let mapping = self.source_mapping.get(mapping_index).ok_or(
                    RegexSetFinite64CompileError::InternalInvariant(
                        "finite64 construction source mapping ended early",
                    ),
                )?;
                let expected_pattern = u8::try_from(pattern).map_err(|_| {
                    RegexSetFinite64CompileError::ArithmeticOverflow {
                        computation: "finite64 authenticated source ordinal",
                    }
                })?;
                let expected_language = u32::try_from(language_ordinal).map_err(|_| {
                    RegexSetFinite64CompileError::ArithmeticOverflow {
                        computation: "finite64 authenticated language ordinal",
                    }
                })?;
                let expected_width = u32::try_from(literal.len()).map_err(|_| {
                    RegexSetFinite64CompileError::ArithmeticOverflow {
                        computation: "finite64 authenticated literal width",
                    }
                })?;
                if mapping.pattern != expected_pattern
                    || mapping.language_ordinal != expected_language
                    || mapping.width != expected_width
                {
                    return Err(RegexSetFinite64CompileError::InternalInvariant(
                        "finite64 proof order disagrees with its source mapping",
                    ));
                }
                let mut state = 0_u32;
                for &byte in literal {
                    state = self
                        .direct_transition(state, byte)
                        .map_err(RegexSetFinite64CompileError::Authentication)?
                        .ok_or(RegexSetFinite64CompileError::InternalInvariant(
                            "finite64 trie path disagrees with its proof bytes",
                        ))?;
                }
                if state != mapping.terminal {
                    return Err(RegexSetFinite64CompileError::InternalInvariant(
                        "finite64 proof bytes do not reach their mapped terminal",
                    ));
                }
                literal_bytes = literal_bytes
                    .checked_add(usize_to_u64(
                        literal.len(),
                        "finite64 authenticated literal byte sum",
                    )?)
                    .ok_or(RegexSetFinite64CompileError::ArithmeticOverflow {
                        computation: "finite64 authenticated literal byte sum",
                    })?;
                mapping_index = mapping_index.checked_add(1).ok_or(
                    RegexSetFinite64CompileError::ArithmeticOverflow {
                        computation: "finite64 authenticated mapping cursor",
                    },
                )?;
            }
        }
        if mapping_index != self.source_mapping.len() || literal_bytes != self.receipt.literal_bytes
        {
            return Err(RegexSetFinite64CompileError::InternalInvariant(
                "finite64 construction source census changed",
            ));
        }
        Ok(())
    }
}

/// Compile the authoritative independent-row set and report whether one
/// shared finite-language scan was selected.
///
/// This is an explicit Optimizing+Exists entry. [`crate::compile_regex_set`]
/// and its defaults do not request finite-language witnesses and remain
/// unchanged.
pub fn compile_regex_set_finite64_reported(
    request: RegexSetCompileRequest,
    limits: RegexSetFinite64Limits,
) -> Result<RegexSetFinite64CompileDisposition, RegexSetFinite64CompileError> {
    let pattern_count = request.patterns.len();
    let preliminary_decline = if request.mode != CompileMode::Optimizing {
        Some(RegexSetFinite64Decline::RequiresOptimizing {
            actual: request.mode,
        })
    } else if !(REGEX_SET_FINITE64_MIN_PATTERNS..=REGEX_SET_FINITE64_MAX_PATTERNS)
        .contains(&pattern_count)
    {
        Some(RegexSetFinite64Decline::PatternCount {
            needed: pattern_count,
            minimum: REGEX_SET_FINITE64_MIN_PATTERNS,
            maximum: REGEX_SET_FINITE64_MAX_PATTERNS,
        })
    } else {
        None
    };
    if let Some(reason) = preliminary_decline {
        let program = compile_regex_set(request)?;
        return Ok(RegexSetFinite64CompileDisposition::Declined { program, reason });
    }

    let compiled = compile_regex_set_with_finite64_witnesses(
        request,
        RegexSetFinite64WitnessLimits {
            max_finite_strings: limits.max_finite_strings,
            max_literal_bytes: limits.max_literal_bytes,
        },
    )?;
    let witness_decline = compiled.witness_decline;
    let program = compiled.program;
    let witnesses = compiled.witnesses;
    if let Some(decline) = witness_decline {
        let reason = match decline {
            RegexSetFinite64WitnessDecline::RowNotFiniteLanguage { pattern } => {
                RegexSetFinite64Decline::RowNotFiniteLanguage { pattern }
            }
            RegexSetFinite64WitnessDecline::Resource {
                pattern,
                resource,
                needed,
                limit,
            } => RegexSetFinite64Decline::Resource {
                pattern: Some(pattern),
                resource: map_fact_resource(resource)?,
                needed,
                limit,
            },
        };
        return Ok(RegexSetFinite64CompileDisposition::Declined { program, reason });
    }
    if witnesses.iter().any(Option::is_none) {
        return Err(RegexSetFinite64CompileError::InternalInvariant(
            "finite64 witness table declined without a reason",
        ));
    }
    build_finite64(program, &witnesses, limits)
}

#[allow(
    clippy::too_many_lines,
    reason = "trie construction, failure closure, canonical freezing, and final authentication are one fail-closed transaction"
)]
fn build_finite64(
    fallback: RegexSetProgram,
    witnesses: &[Option<NativeFiniteLanguageCandidate>],
    limits: RegexSetFinite64Limits,
) -> Result<RegexSetFinite64CompileDisposition, RegexSetFinite64CompileError> {
    let pattern_count = witnesses.len();
    if fallback.mode() != CompileMode::Optimizing
        || fallback.len() != pattern_count
        || !(REGEX_SET_FINITE64_MIN_PATTERNS..=REGEX_SET_FINITE64_MAX_PATTERNS)
            .contains(&pattern_count)
    {
        return Err(RegexSetFinite64CompileError::InternalInvariant(
            "finite64 builder received an ineligible incumbent",
        ));
    }

    let mut finite_string_count = 0usize;
    let mut literal_bytes = 0usize;
    let mut maximum_literal_width = 0usize;
    for witness in witnesses {
        let witness = witness
            .as_ref()
            .ok_or(RegexSetFinite64CompileError::InternalInvariant(
                "selected finite64 builder received a missing witness",
            ))?;
        if witness.regex_set_strings().is_empty() {
            return Err(RegexSetFinite64CompileError::InternalInvariant(
                "selected finite64 builder received an empty language",
            ));
        }
        finite_string_count = finite_string_count
            .checked_add(witness.regex_set_language_len())
            .ok_or(RegexSetFinite64CompileError::ArithmeticOverflow {
                computation: "finite64 language count",
            })?;
        literal_bytes = literal_bytes
            .checked_add(witness.regex_set_language_bytes())
            .ok_or(RegexSetFinite64CompileError::ArithmeticOverflow {
                computation: "finite64 literal byte sum",
            })?;
        for literal in witness.regex_set_strings() {
            if literal.is_empty() {
                return Err(RegexSetFinite64CompileError::InternalInvariant(
                    "selected finite64 builder received an empty string",
                ));
            }
            maximum_literal_width = maximum_literal_width.max(literal.len());
        }
    }
    if finite_string_count > limits.max_finite_strings {
        return Ok(decline_resource(
            fallback,
            RegexSetFinite64Resource::FiniteStrings,
            finite_string_count,
            limits.max_finite_strings,
        )?);
    }
    if literal_bytes > limits.max_literal_bytes {
        return Ok(decline_resource(
            fallback,
            RegexSetFinite64Resource::LiteralBytes,
            literal_bytes,
            limits.max_literal_bytes,
        )?);
    }
    let minimum_states = maximum_literal_width.checked_add(1).ok_or(
        RegexSetFinite64CompileError::ArithmeticOverflow {
            computation: "finite64 minimum trie states",
        },
    )?;
    let representation_state_limit = limits
        .max_states
        .min(usize::try_from(u32::MAX).unwrap_or(usize::MAX));
    if minimum_states > representation_state_limit {
        return Ok(decline_resource(
            fallback,
            RegexSetFinite64Resource::States,
            minimum_states,
            representation_state_limit,
        )?);
    }
    if maximum_literal_width > limits.max_transition_cells {
        return Ok(decline_resource(
            fallback,
            RegexSetFinite64Resource::TransitionCells,
            maximum_literal_width,
            limits.max_transition_cells,
        )?);
    }
    if maximum_literal_width > 1 && limits.max_failure_steps == 0 {
        return Ok(decline_resource(
            fallback,
            RegexSetFinite64Resource::FailureSteps,
            1,
            0,
        )?);
    }

    let prospective_states =
        literal_bytes
            .checked_add(1)
            .ok_or(RegexSetFinite64CompileError::ArithmeticOverflow {
                computation: "finite64 prospective trie states",
            })?;
    let state_storage_limit = prospective_states
        .min(representation_state_limit)
        .min(limits.max_transition_cells.saturating_add(1));
    let mut states = Vec::new();
    reserve(
        &mut states,
        state_storage_limit.min(1_024),
        "finite64 build states",
    )?;
    states.push(BuildState::new(0, 0, 0));
    let mut source_mapping = Vec::new();
    reserve(
        &mut source_mapping,
        finite_string_count,
        "finite64 source mapping",
    )?;
    let mut transition_count = 0usize;

    for (pattern, witness) in witnesses.iter().enumerate() {
        let witness = witness
            .as_ref()
            .ok_or(RegexSetFinite64CompileError::InternalInvariant(
                "finite64 witness disappeared during trie construction",
            ))?;
        let pattern_u8 = u8::try_from(pattern).map_err(|_| {
            RegexSetFinite64CompileError::ArithmeticOverflow {
                computation: "finite64 source ordinal",
            }
        })?;
        let bit = 1_u64.checked_shl(u32::from(pattern_u8)).ok_or(
            RegexSetFinite64CompileError::ArithmeticOverflow {
                computation: "finite64 source ordinal mask",
            },
        )?;
        for (language_ordinal, literal) in witness.regex_set_strings().iter().enumerate() {
            let mut state = 0usize;
            for &byte in literal {
                let edge = states[state]
                    .edges
                    .as_slice()
                    .binary_search_by_key(&byte, |&(edge_byte, _)| edge_byte);
                state =
                    match edge {
                        Ok(edge) => usize::try_from(states[state].edges.as_slice()[edge].1)
                            .map_err(|_| RegexSetFinite64CompileError::ArithmeticOverflow {
                                computation: "finite64 trie target index",
                            })?,
                        Err(edge) => {
                            let needed_states = states.len().checked_add(1).ok_or(
                                RegexSetFinite64CompileError::ArithmeticOverflow {
                                    computation: "finite64 trie state count",
                                },
                            )?;
                            if needed_states > representation_state_limit {
                                return Ok(decline_resource(
                                    fallback,
                                    RegexSetFinite64Resource::States,
                                    needed_states,
                                    representation_state_limit,
                                )?);
                            }
                            let needed_transitions = transition_count.checked_add(1).ok_or(
                                RegexSetFinite64CompileError::ArithmeticOverflow {
                                    computation: "finite64 transition count",
                                },
                            )?;
                            if needed_transitions > limits.max_transition_cells {
                                return Ok(decline_resource(
                                    fallback,
                                    RegexSetFinite64Resource::TransitionCells,
                                    needed_transitions,
                                    limits.max_transition_cells,
                                )?);
                            }
                            reserve_geometric(
                                &mut states,
                                state_storage_limit,
                                "finite64 build states",
                                "finite64 build state count",
                            )?;
                            let next = u32::try_from(states.len()).map_err(|_| {
                                RegexSetFinite64CompileError::ArithmeticOverflow {
                                    computation: "finite64 trie state token",
                                }
                            })?;
                            let depth = states[state].depth.checked_add(1).ok_or(
                                RegexSetFinite64CompileError::ArithmeticOverflow {
                                    computation: "finite64 trie depth",
                                },
                            )?;
                            let parent = u32::try_from(state).map_err(|_| {
                                RegexSetFinite64CompileError::ArithmeticOverflow {
                                    computation: "finite64 trie parent token",
                                }
                            })?;
                            states.push(BuildState::new(depth, parent, byte));
                            states[state].edges.insert(edge, (byte, next))?;
                            transition_count = needed_transitions;
                            usize::try_from(next).map_err(|_| {
                                RegexSetFinite64CompileError::ArithmeticOverflow {
                                    computation: "finite64 new trie state index",
                                }
                            })?
                        }
                    };
            }
            states[state].direct_output_mask |= bit;
            states[state].output_mask |= bit;
            source_mapping.push(Finite64SourceMap {
                pattern: pattern_u8,
                language_ordinal: u32::try_from(language_ordinal).map_err(|_| {
                    RegexSetFinite64CompileError::ArithmeticOverflow {
                        computation: "finite64 language ordinal",
                    }
                })?,
                terminal: u32::try_from(state).map_err(|_| {
                    RegexSetFinite64CompileError::ArithmeticOverflow {
                        computation: "finite64 source terminal",
                    }
                })?,
                width: u32::try_from(literal.len()).map_err(|_| {
                    RegexSetFinite64CompileError::ArithmeticOverflow {
                        computation: "finite64 literal width",
                    }
                })?,
            });
        }
    }
    if source_mapping.len() != finite_string_count {
        return Err(RegexSetFinite64CompileError::InternalInvariant(
            "finite64 source mapping census changed",
        ));
    }

    let mut breadth_first = Vec::new();
    reserve(
        &mut breadth_first,
        states.len(),
        "finite64 breadth-first states",
    )?;
    breadth_first.push(0_u32);
    for &(_, target) in states[0].edges.as_slice() {
        breadth_first.push(target);
    }
    let mut cursor = 1usize;
    let mut failure_steps = 0_u64;
    while cursor < breadth_first.len() {
        let state = usize::try_from(breadth_first[cursor]).map_err(|_| {
            RegexSetFinite64CompileError::ArithmeticOverflow {
                computation: "finite64 breadth-first state index",
            }
        })?;
        cursor = cursor
            .checked_add(1)
            .ok_or(RegexSetFinite64CompileError::ArithmeticOverflow {
                computation: "finite64 breadth-first cursor",
            })?;
        for edge_index in 0..states[state].edges.as_slice().len() {
            let (byte, next_token) = states[state].edges.as_slice()[edge_index];
            let next = usize::try_from(next_token).map_err(|_| {
                RegexSetFinite64CompileError::ArithmeticOverflow {
                    computation: "finite64 failure child index",
                }
            })?;
            let mut fallback_state = usize::try_from(states[state].failure).map_err(|_| {
                RegexSetFinite64CompileError::ArithmeticOverflow {
                    computation: "finite64 failure state index",
                }
            })?;
            let failure = loop {
                failure_steps = failure_steps.checked_add(1).ok_or(
                    RegexSetFinite64CompileError::ArithmeticOverflow {
                        computation: "finite64 failure-link work",
                    },
                )?;
                if failure_steps > limits.max_failure_steps {
                    return Ok(RegexSetFinite64CompileDisposition::Declined {
                        program: fallback,
                        reason: RegexSetFinite64Decline::Resource {
                            pattern: None,
                            resource: RegexSetFinite64Resource::FailureSteps,
                            needed: failure_steps,
                            limit: limits.max_failure_steps,
                        },
                    });
                }
                if let Some(target) = edge_target(states[fallback_state].edges.as_slice(), byte) {
                    break target;
                }
                if fallback_state == 0 {
                    break 0;
                }
                fallback_state = usize::try_from(states[fallback_state].failure).map_err(|_| {
                    RegexSetFinite64CompileError::ArithmeticOverflow {
                        computation: "finite64 nested failure state index",
                    }
                })?;
            };
            let inherited = usize::try_from(failure).map_err(|_| {
                RegexSetFinite64CompileError::ArithmeticOverflow {
                    computation: "finite64 inherited output state index",
                }
            })?;
            let inherited_mask = states[inherited].output_mask;
            states[next].failure = failure;
            states[next].output_mask |= inherited_mask;
            breadth_first.push(next_token);
        }
    }
    if breadth_first.len() != states.len() {
        return Err(RegexSetFinite64CompileError::InternalInvariant(
            "finite64 breadth-first traversal missed trie states",
        ));
    }

    let mut frozen_states = Vec::new();
    reserve(&mut frozen_states, states.len(), "finite64 frozen states")?;
    let mut frozen_edges = Vec::new();
    reserve(&mut frozen_edges, transition_count, "finite64 frozen edges")?;
    for state in &states {
        let edge_start = u32::try_from(frozen_edges.len()).map_err(|_| {
            RegexSetFinite64CompileError::ArithmeticOverflow {
                computation: "finite64 frozen edge offset",
            }
        })?;
        let edge_count = u16::try_from(state.edges.as_slice().len()).map_err(|_| {
            RegexSetFinite64CompileError::ArithmeticOverflow {
                computation: "finite64 frozen state edge count",
            }
        })?;
        frozen_edges.extend(
            state
                .edges
                .as_slice()
                .iter()
                .map(|&(byte, target)| Finite64Edge { byte, target }),
        );
        frozen_states.push(Finite64State {
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
        return Err(RegexSetFinite64CompileError::InternalInvariant(
            "finite64 frozen transition census changed",
        ));
    }

    let source_artifact = fallback.artifact_identity();
    let source_mapping_digest = source_mapping_digest(witnesses)?;
    let pattern_count = u8::try_from(pattern_count).map_err(|_| {
        RegexSetFinite64CompileError::ArithmeticOverflow {
            computation: "finite64 receipt pattern count",
        }
    })?;
    let finite_string_count = u32::try_from(finite_string_count).map_err(|_| {
        RegexSetFinite64CompileError::ArithmeticOverflow {
            computation: "finite64 receipt language count",
        }
    })?;
    let literal_bytes = usize_to_u64(literal_bytes, "finite64 receipt literal bytes")?;
    let maximum_literal_width = u32::try_from(maximum_literal_width).map_err(|_| {
        RegexSetFinite64CompileError::ArithmeticOverflow {
            computation: "finite64 receipt maximum literal width",
        }
    })?;
    let state_count = u32::try_from(frozen_states.len()).map_err(|_| {
        RegexSetFinite64CompileError::ArithmeticOverflow {
            computation: "finite64 receipt state count",
        }
    })?;
    let transition_count = u32::try_from(frozen_edges.len()).map_err(|_| {
        RegexSetFinite64CompileError::ArithmeticOverflow {
            computation: "finite64 receipt transition count",
        }
    })?;
    let mut receipt = RegexSetFinite64Receipt {
        schema_version: REGEX_SET_FINITE64_SCHEMA_VERSION,
        fact_algorithm_version: HIR_FACT_ALGORITHM_VERSION,
        fact_accounting_version: HIR_FACT_ACCOUNTING_VERSION,
        source_artifact,
        artifact: RegexSetFinite64ArtifactIdentity([0; 32]),
        source_mapping_digest,
        pattern_count,
        all_pattern_mask: all_pattern_mask(usize::from(pattern_count)),
        finite_string_count,
        literal_bytes,
        maximum_literal_width,
        state_count,
        transition_count,
        failure_steps,
    };
    receipt.artifact = artifact_identity(receipt, &source_mapping, &frozen_states, &frozen_edges);
    let identity = Finite64Identity {
        artifact: receipt.artifact,
        instance: next_instance()?,
    };
    let program = RegexSetFinite64Program {
        fallback,
        receipt,
        identity,
        source_mapping,
        states: frozen_states,
        edges: frozen_edges,
    };
    program
        .authenticate()
        .map_err(RegexSetFinite64CompileError::Authentication)?;
    program.authenticate_against_witnesses(witnesses)?;
    Ok(RegexSetFinite64CompileDisposition::Selected(program))
}

fn decline_resource(
    program: RegexSetProgram,
    resource: RegexSetFinite64Resource,
    needed: usize,
    limit: usize,
) -> Result<RegexSetFinite64CompileDisposition, RegexSetFinite64CompileError> {
    Ok(RegexSetFinite64CompileDisposition::Declined {
        program,
        reason: RegexSetFinite64Decline::Resource {
            pattern: None,
            resource,
            needed: usize_to_u64(needed, "finite64 resource requirement")?,
            limit: usize_to_u64(limit, "finite64 resource limit")?,
        },
    })
}

fn map_fact_resource(
    resource: FactResource,
) -> Result<RegexSetFinite64Resource, RegexSetFinite64CompileError> {
    Ok(match resource {
        FactResource::FiniteStrings => RegexSetFinite64Resource::FiniteStrings,
        FactResource::FiniteStringBytes => RegexSetFinite64Resource::LiteralBytes,
        FactResource::Work => RegexSetFinite64Resource::FactWork,
        FactResource::StackItems => RegexSetFinite64Resource::FactStackItems,
        FactResource::HirNodes => RegexSetFinite64Resource::FactHirNodes,
        FactResource::RetainedBytes => RegexSetFinite64Resource::FactRetainedBytes,
        FactResource::TemporaryBytes => RegexSetFinite64Resource::FactTemporaryBytes,
        FactResource::PeakBytes => RegexSetFinite64Resource::FactPeakBytes,
        FactResource::AllocationAttempts => RegexSetFinite64Resource::FactAllocationAttempts,
        FactResource::RequiredGroups => RegexSetFinite64Resource::FactRequiredGroups,
        FactResource::RequiredAlternatives => RegexSetFinite64Resource::FactRequiredAlternatives,
        FactResource::RequiredBytes => RegexSetFinite64Resource::FactRequiredBytes,
        FactResource::Assertions => RegexSetFinite64Resource::FactAssertions,
        FactResource::DeterministicStates => RegexSetFinite64Resource::FactDeterministicStates,
        _ => {
            return Err(RegexSetFinite64CompileError::InternalInvariant(
                "finite64 proof returned an unknown resource kind",
            ));
        }
    })
}

fn next_geometric_capacity(
    len: usize,
    capacity: usize,
    logical_limit: usize,
    computation: &'static str,
) -> Result<Option<usize>, RegexSetFinite64CompileError> {
    let needed = len
        .checked_add(1)
        .ok_or(RegexSetFinite64CompileError::ArithmeticOverflow { computation })?;
    if needed > logical_limit {
        return Err(RegexSetFinite64CompileError::InternalInvariant(
            "finite64 geometric reservation crossed its logical limit",
        ));
    }
    if needed <= capacity {
        return Ok(None);
    }
    let doubled = capacity.checked_mul(2).unwrap_or(logical_limit);
    let target = doubled.max(needed).min(logical_limit);
    if target < needed {
        return Err(RegexSetFinite64CompileError::InternalInvariant(
            "finite64 geometric reservation did not cover its next entry",
        ));
    }
    Ok(Some(target))
}

fn reserve_geometric<T>(
    values: &mut Vec<T>,
    logical_limit: usize,
    structure: &'static str,
    computation: &'static str,
) -> Result<(), RegexSetFinite64CompileError> {
    let Some(target) =
        next_geometric_capacity(values.len(), values.capacity(), logical_limit, computation)?
    else {
        return Ok(());
    };
    let additional =
        target
            .checked_sub(values.len())
            .ok_or(RegexSetFinite64CompileError::InternalInvariant(
                "finite64 geometric reservation target preceded its length",
            ))?;
    reserve(values, additional, structure)
}

fn reserve<T>(
    values: &mut Vec<T>,
    additional: usize,
    structure: &'static str,
) -> Result<(), RegexSetFinite64CompileError> {
    #[cfg(test)]
    if injected_reserve_failure(structure) {
        return Err(RegexSetFinite64CompileError::AllocationFailed {
            structure,
            additional,
        });
    }
    values.try_reserve_exact(additional).map_err(|_| {
        RegexSetFinite64CompileError::AllocationFailed {
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
    if pattern_count == REGEX_SET_FINITE64_MAX_PATTERNS {
        u64::MAX
    } else {
        (1_u64 << pattern_count).saturating_sub(1)
    }
}

fn usize_to_u64(
    value: usize,
    computation: &'static str,
) -> Result<u64, RegexSetFinite64CompileError> {
    u64::try_from(value)
        .map_err(|_| RegexSetFinite64CompileError::ArithmeticOverflow { computation })
}

fn source_mapping_digest(
    witnesses: &[Option<NativeFiniteLanguageCandidate>],
) -> Result<[u8; 32], RegexSetFinite64CompileError> {
    let mut digest = Sha256::new();
    digest.update(SOURCE_DOMAIN);
    digest.update(REGEX_SET_FINITE64_SCHEMA_VERSION.to_le_bytes());
    digest.update(HIR_FACT_ALGORITHM_VERSION.to_le_bytes());
    digest.update(HIR_FACT_ACCOUNTING_VERSION.to_le_bytes());
    digest.update(usize_to_u64(witnesses.len(), "finite64 source row count")?.to_le_bytes());
    for (pattern, witness) in witnesses.iter().enumerate() {
        let witness = witness
            .as_ref()
            .ok_or(RegexSetFinite64CompileError::InternalInvariant(
                "finite64 source digest received a missing witness",
            ))?;
        digest.update(usize_to_u64(pattern, "finite64 source ordinal")?.to_le_bytes());
        digest.update(
            usize_to_u64(
                witness.regex_set_strings().len(),
                "finite64 source language count",
            )?
            .to_le_bytes(),
        );
        for (language_ordinal, literal) in witness.regex_set_strings().iter().enumerate() {
            digest
                .update(usize_to_u64(language_ordinal, "finite64 language ordinal")?.to_le_bytes());
            digest.update(
                usize_to_u64(literal.len(), "finite64 source literal width")?.to_le_bytes(),
            );
            digest.update(literal);
        }
    }
    Ok(<[u8; 32]>::from(digest.finalize()))
}

fn artifact_identity(
    receipt: RegexSetFinite64Receipt,
    source_mapping: &[Finite64SourceMap],
    states: &[Finite64State],
    edges: &[Finite64Edge],
) -> RegexSetFinite64ArtifactIdentity {
    let mut digest = Sha256::new();
    digest.update(ARTIFACT_DOMAIN);
    digest.update(receipt.schema_version.to_le_bytes());
    digest.update(receipt.fact_algorithm_version.to_le_bytes());
    digest.update(receipt.fact_accounting_version.to_le_bytes());
    digest.update(receipt.source_artifact.as_bytes());
    digest.update(receipt.source_mapping_digest);
    digest.update([receipt.pattern_count]);
    digest.update(receipt.all_pattern_mask.to_le_bytes());
    digest.update(receipt.finite_string_count.to_le_bytes());
    digest.update(receipt.literal_bytes.to_le_bytes());
    digest.update(receipt.maximum_literal_width.to_le_bytes());
    digest.update(receipt.state_count.to_le_bytes());
    digest.update(receipt.transition_count.to_le_bytes());
    digest.update(receipt.failure_steps.to_le_bytes());
    for mapping in source_mapping {
        digest.update([mapping.pattern]);
        digest.update(mapping.language_ordinal.to_le_bytes());
        digest.update(mapping.terminal.to_le_bytes());
        digest.update(mapping.width.to_le_bytes());
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
    RegexSetFinite64ArtifactIdentity(<[u8; 32]>::from(digest.finalize()))
}

fn next_instance() -> Result<u64, RegexSetFinite64CompileError> {
    NEXT_FINITE64_INSTANCE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |identity| {
            identity.checked_add(1)
        })
        .map_err(|_| {
            RegexSetFinite64CompileError::InternalInvariant("finite64 instance identity exhausted")
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RegexSetSessionLimits, compile_regex_set};

    fn request(patterns: &[&str]) -> RegexSetCompileRequest {
        RegexSetCompileRequest::new(
            patterns
                .iter()
                .map(|pattern| (*pattern).to_owned())
                .collect(),
        )
    }

    fn selected(patterns: &[&str]) -> RegexSetFinite64Program {
        match compile_regex_set_finite64_reported(
            request(patterns),
            RegexSetFinite64Limits::default(),
        )
        .expect("finite64 compile")
        {
            RegexSetFinite64CompileDisposition::Selected(program) => program,
            RegexSetFinite64CompileDisposition::Declined { reason, .. } => {
                panic!("unexpected finite64 decline: {reason}")
            }
        }
    }

    fn assert_fallback_equivalent(
        program: &RegexSetFinite64Program,
        fallback_session: &mut crate::RegexSetSession,
        finite_session: &RegexSetFinite64Session,
        haystack: &[u8],
        window: SearchWindow,
    ) {
        let mut expected = [0xfeed_face_dead_beef];
        let expected_report = program
            .fallback()
            .fill_matches_with_session(fallback_session, haystack, window, &mut expected)
            .expect("authoritative row-loop fill");
        let mut actual = 0x0123_4567_89ab_cdef;
        let actual_report = program
            .fill_matches_with_session(finite_session, haystack, window, &mut actual)
            .expect("shared finite fill");
        assert_eq!(
            expected[0], actual,
            "haystack={haystack:?}, window={window:?}"
        );
        assert_eq!(
            expected_report.matched_count(),
            actual_report.matched_count() as usize
        );
        assert_eq!(expected_report.any(), actual_report.any());
        assert_eq!(actual, actual_report.matched_mask());
    }

    fn rehash_after_internal_mutation(program: &mut RegexSetFinite64Program) {
        program.receipt.artifact = artifact_identity(
            program.receipt,
            &program.source_mapping,
            &program.states,
            &program.edges,
        );
        program.identity.artifact = program.receipt.artifact;
    }

    #[test]
    fn selects_complete_finite_rows_and_publishes_duplicate_owners() {
        let program = selected(&["(?:he|she)", "he", "(?:she|hers)", "he"]);
        let receipt = program.receipt();
        assert_eq!(4, receipt.pattern_count());
        assert_eq!(0b1111, receipt.all_pattern_mask());
        assert_eq!(6, receipt.finite_string_count());
        assert!(receipt.state_count() > 1);
        assert_eq!(receipt.state_count() - 1, receipt.transition_count());
        program.authenticate().unwrap();

        let session = program.prepare_session(64).unwrap();
        let mut output = 0;
        let report = program
            .fill_matches_with_session(&session, b"ushers", SearchWindow::new(0, 6), &mut output)
            .unwrap();
        assert_eq!(0b1111, output);
        assert_eq!(4, report.matched_count());
    }

    #[test]
    fn exhaustive_small_language_and_window_differential() {
        let program = selected(&[
            "(?:a|ab|ba)",
            "[a-c]b",
            "(?:b|ca){1,2}",
            "(?i:ac)",
            "(?:he|she)",
            "(?:she|hers|he)",
        ]);
        let mut fallback_session = program
            .fallback()
            .prepare_session(RegexSetSessionLimits::unlimited())
            .unwrap();
        let finite_session = program.prepare_session(6).unwrap();
        let alphabet = [b'a', b'b', b'c'];

        for len in 0_u32..=6 {
            let cases = 3_usize.pow(len);
            for encoded in 0..cases {
                let mut value = encoded;
                let mut haystack = vec![0_u8; usize::try_from(len).unwrap()];
                for byte in &mut haystack {
                    *byte = alphabet[value % alphabet.len()];
                    value /= alphabet.len();
                }
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        assert_fallback_equivalent(
                            &program,
                            &mut fallback_session,
                            &finite_session,
                            &haystack,
                            SearchWindow::new(start, end),
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn generated_binary_and_shape_differential() {
        let program = selected(&[
            "(?:ab|aba|ba)",
            "[a-c]x",
            "(?:xy|z){1,2}",
            "(?i:qu)",
            "(?:he|she)",
            "(?:she|hers|he)",
            r"(?-u:\xFFa|b\x80)",
            "(?:ab|ab)",
        ]);
        let mut fallback_session = program
            .fallback()
            .prepare_session(RegexSetSessionLimits::unlimited())
            .unwrap();
        let finite_session = program.prepare_session(96).unwrap();
        let alphabet = b"abcdehqrsuvwxyzQU\x80\xff";
        let mut seed = 0xd1b5_4a32_7c91_e8f0_u64;
        for case in 0..512_usize {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let len = usize::try_from(seed % 97).unwrap();
            let mut haystack = Vec::with_capacity(len);
            for _ in 0..len {
                seed = seed
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                haystack.push(alphabet[usize::try_from(seed).unwrap() % alphabet.len()]);
            }
            let start = if len == 0 { 0 } else { case % (len + 1) };
            let remaining = len - start;
            let end = start
                + if remaining == 0 {
                    0
                } else {
                    (case * 7) % (remaining + 1)
                };
            assert_fallback_equivalent(
                &program,
                &mut fallback_session,
                &finite_session,
                &haystack,
                SearchWindow::new(start, end),
            );
        }
    }

    #[test]
    fn full_sixty_four_bit_result_is_source_ordered() {
        let patterns: Vec<String> = (0..64).map(|index| format!("p{index:02}")).collect();
        let request = RegexSetCompileRequest::new(patterns.clone());
        let program =
            match compile_regex_set_finite64_reported(request, RegexSetFinite64Limits::default())
                .unwrap()
            {
                RegexSetFinite64CompileDisposition::Selected(program) => program,
                RegexSetFinite64CompileDisposition::Declined { reason, .. } => {
                    panic!("unexpected 64-row decline: {reason}")
                }
            };
        let haystack = patterns.join("/");
        let session = program.prepare_session(haystack.len()).unwrap();
        let mut output = 0;
        let report = program
            .fill_matches_with_session(
                &session,
                haystack.as_bytes(),
                SearchWindow::new(0, haystack.len()),
                &mut output,
            )
            .unwrap();
        assert_eq!(u64::MAX, output);
        assert_eq!(64, report.matched_count());
    }

    #[test]
    fn one_state_can_represent_the_complete_byte_alphabet() {
        let program = selected(&[r"(?-u:[\x00-\xFF])", "zz"]);
        assert_eq!(257, program.receipt().finite_string_count());
        assert_eq!(256, program.states[0].edge_count);
        let session = program.prepare_session(256).unwrap();

        let all_bytes: Vec<u8> = (u8::MIN..=u8::MAX).collect();
        let mut output = 0;
        program
            .fill_matches_with_session(
                &session,
                &all_bytes,
                SearchWindow::new(0, all_bytes.len()),
                &mut output,
            )
            .unwrap();
        assert_eq!(0b01, output);

        program
            .fill_matches_with_session(&session, b"zz", SearchWindow::new(0, 2), &mut output)
            .unwrap();
        assert_eq!(0b11, output);
    }

    #[test]
    fn semantic_and_shape_declines_return_the_exact_incumbent() {
        let cases = [
            (vec!["^ab", "cd"], Some(0)),
            (vec!["a*", "cd"], Some(0)),
            (vec!["", "cd"], Some(0)),
        ];
        for (patterns, expected_pattern) in cases {
            let request = request(&patterns);
            let expected = compile_regex_set(request.clone())
                .unwrap()
                .artifact_identity();
            let disposition =
                compile_regex_set_finite64_reported(request, RegexSetFinite64Limits::default())
                    .unwrap();
            let RegexSetFinite64CompileDisposition::Declined { program, reason } = disposition
            else {
                panic!("semantically ineligible set was selected")
            };
            assert_eq!(expected, program.artifact_identity());
            assert!(matches!(
                reason,
                RegexSetFinite64Decline::RowNotFiniteLanguage { pattern }
                    if Some(pattern) == expected_pattern
            ));
        }

        for count in [0_usize, 1, 65] {
            let patterns = vec!["x".to_owned(); count];
            let mut request = RegexSetCompileRequest::new(patterns);
            request.limits.max_patterns = request.limits.max_patterns.max(count);
            let expected = compile_regex_set(request.clone())
                .unwrap()
                .artifact_identity();
            let RegexSetFinite64CompileDisposition::Declined { program, reason } =
                compile_regex_set_finite64_reported(request, RegexSetFinite64Limits::default())
                    .unwrap()
            else {
                panic!("out-of-range source count was selected")
            };
            assert_eq!(expected, program.artifact_identity());
            assert!(matches!(
                reason,
                RegexSetFinite64Decline::PatternCount { needed, .. } if needed == count
            ));
        }

        let mut fast = request(&["ab", "cd"]);
        fast.mode = CompileMode::Fast;
        let expected = compile_regex_set(fast.clone()).unwrap().artifact_identity();
        let RegexSetFinite64CompileDisposition::Declined { program, reason } =
            compile_regex_set_finite64_reported(fast, RegexSetFinite64Limits::default()).unwrap()
        else {
            panic!("Fast mode was selected")
        };
        assert_eq!(expected, program.artifact_identity());
        assert_eq!(CompileMode::Fast, program.mode());
        assert!(matches!(
            reason,
            RegexSetFinite64Decline::RequiresOptimizing {
                actual: CompileMode::Fast
            }
        ));
    }

    #[test]
    fn proof_resources_decline_in_source_order_with_exact_fallback() {
        let cases = [
            (
                RegexSetFinite64Limits {
                    max_finite_strings: 2,
                    ..RegexSetFinite64Limits::default()
                },
                RegexSetFinite64Resource::FiniteStrings,
                3_u64,
                2_u64,
            ),
            (
                RegexSetFinite64Limits {
                    max_literal_bytes: 2,
                    ..RegexSetFinite64Limits::default()
                },
                RegexSetFinite64Resource::LiteralBytes,
                3_u64,
                2_u64,
            ),
        ];
        for (limits, expected_resource, expected_needed, expected_limit) in cases {
            let patterns = if expected_resource == RegexSetFinite64Resource::FiniteStrings {
                ["(?:a|b)", "c"]
            } else {
                ["ab", "c"]
            };
            let request = request(&patterns);
            let expected = compile_regex_set(request.clone())
                .unwrap()
                .artifact_identity();
            let RegexSetFinite64CompileDisposition::Declined { program, reason } =
                compile_regex_set_finite64_reported(request, limits).unwrap()
            else {
                panic!("proof cap unexpectedly selected")
            };
            assert_eq!(expected, program.artifact_identity());
            assert!(matches!(
                reason,
                RegexSetFinite64Decline::Resource {
                    pattern: Some(1),
                    resource,
                    needed,
                    limit,
                } if resource == expected_resource
                    && needed == expected_needed
                    && limit == expected_limit
            ));
        }

        let limits = RegexSetFinite64Limits {
            max_finite_strings: 1,
            ..RegexSetFinite64Limits::default()
        };
        let RegexSetFinite64CompileDisposition::Declined { reason, .. } =
            compile_regex_set_finite64_reported(request(&["(?:a|b)", "z*"]), limits).unwrap()
        else {
            panic!("source-ordered resource refusal unexpectedly selected")
        };
        assert!(matches!(
            reason,
            RegexSetFinite64Decline::Resource {
                pattern: Some(0),
                resource: RegexSetFinite64Resource::FiniteStrings,
                ..
            }
        ));
    }

    #[test]
    fn earlier_optional_decline_never_hides_a_later_compile_failure() {
        let limits = RegexSetFinite64Limits {
            max_finite_strings: 1,
            ..RegexSetFinite64Limits::default()
        };
        for patterns in [["(?:a|b)", "("], ["a*", "("]] {
            assert!(matches!(
                compile_regex_set_finite64_reported(request(&patterns), limits),
                Err(RegexSetFinite64CompileError::RegexSet(
                    RegexSetCompileError::Pattern { pattern: 1, .. }
                ))
            ));
        }
    }

    #[test]
    fn graph_resource_caps_decline_without_changing_the_fallback() {
        let cases = [
            (
                RegexSetFinite64Limits {
                    max_states: 2,
                    ..RegexSetFinite64Limits::default()
                },
                RegexSetFinite64Resource::States,
                3_u64,
                2_u64,
            ),
            (
                RegexSetFinite64Limits {
                    max_states: 3,
                    ..RegexSetFinite64Limits::default()
                },
                RegexSetFinite64Resource::States,
                4_u64,
                3_u64,
            ),
            (
                RegexSetFinite64Limits {
                    max_transition_cells: 2,
                    ..RegexSetFinite64Limits::default()
                },
                RegexSetFinite64Resource::TransitionCells,
                3_u64,
                2_u64,
            ),
            (
                RegexSetFinite64Limits {
                    max_failure_steps: 0,
                    ..RegexSetFinite64Limits::default()
                },
                RegexSetFinite64Resource::FailureSteps,
                1_u64,
                0_u64,
            ),
        ];
        for (limits, expected_resource, expected_needed, expected_limit) in cases {
            let request = request(&["ab", "ac"]);
            let expected = compile_regex_set(request.clone())
                .unwrap()
                .artifact_identity();
            let RegexSetFinite64CompileDisposition::Declined { program, reason } =
                compile_regex_set_finite64_reported(request, limits).unwrap()
            else {
                panic!("graph cap unexpectedly selected")
            };
            assert_eq!(expected, program.artifact_identity());
            assert!(matches!(
                reason,
                RegexSetFinite64Decline::Resource {
                    pattern: None,
                    resource,
                    needed,
                    limit,
                } if resource == expected_resource
                    && needed == expected_needed
                    && limit == expected_limit
            ));
        }
    }

    #[test]
    fn allocator_failure_is_terminal_and_allocation_stops_immediately() {
        let request = request(&["(?:ab|ac)", "(?:bc|bd)"]);
        let _fault = TestReserveFaultGuard::arm("finite64 source mapping");
        assert!(matches!(
            compile_regex_set_finite64_reported(request, RegexSetFinite64Limits::default()),
            Err(RegexSetFinite64CompileError::AllocationFailed {
                structure: "finite64 source mapping",
                ..
            })
        ));
    }

    #[test]
    fn arithmetic_and_invariant_failures_are_terminal() {
        assert!(matches!(
            next_geometric_capacity(
                usize::MAX,
                usize::MAX,
                usize::MAX,
                "synthetic finite64 overflow"
            ),
            Err(RegexSetFinite64CompileError::ArithmeticOverflow {
                computation: "synthetic finite64 overflow"
            })
        ));
        assert!(matches!(
            next_geometric_capacity(2, 2, 2, "synthetic finite64 invariant"),
            Err(RegexSetFinite64CompileError::InternalInvariant(
                "finite64 geometric reservation crossed its logical limit"
            ))
        ));
    }

    #[test]
    fn authentication_and_run_errors_never_publish_partial_output() {
        let mut program = selected(&["he", "she"]);
        let inherited = program
            .states
            .iter()
            .position(|state| state.output_mask != state.direct_output_mask)
            .expect("failure output state");
        program.states[inherited].output_mask = program.states[inherited].direct_output_mask;
        rehash_after_internal_mutation(&mut program);
        let sentinel = 0xfeed_face_dead_beef;
        let mut output = sentinel;
        assert!(matches!(
            program.fill_matches(b"she", SearchWindow::new(0, 3), &mut output),
            Err(RegexSetFinite64RunError::Authentication(
                RegexSetFinite64AuthenticationError::Shape(
                    "state output mask does not inherit its failure output"
                )
            ))
        ));
        assert_eq!(sentinel, output);

        let mut program = selected(&["ab|ac", "bc|bd"]);
        program.source_mapping[0].language_ordinal = 1;
        rehash_after_internal_mutation(&mut program);
        let mut output = sentinel;
        assert!(matches!(
            program.fill_matches(b"abcd", SearchWindow::new(0, 4), &mut output),
            Err(RegexSetFinite64RunError::Authentication(
                RegexSetFinite64AuthenticationError::Shape(
                    "source mapping is not canonical source/language order"
                )
            ))
        ));
        assert_eq!(sentinel, output);

        let mut program = selected(&["ab", "bc"]);
        program.receipt.fact_algorithm_version =
            program.receipt.fact_algorithm_version.wrapping_add(1);
        let mut output = sentinel;
        assert!(matches!(
            program.fill_matches(b"abc", SearchWindow::new(0, 3), &mut output),
            Err(RegexSetFinite64RunError::Authentication(
                RegexSetFinite64AuthenticationError::FactIdentity { .. }
            ))
        ));
        assert_eq!(sentinel, output);
    }

    #[test]
    fn session_mismatch_limits_and_windows_are_transactional() {
        let first = selected(&["ab", "bc"]);
        let second = selected(&["ab", "bc"]);
        assert_eq!(
            first.receipt().artifact_identity(),
            second.receipt().artifact_identity()
        );
        let foreign = second.prepare_session(16).unwrap();
        let sentinel = 0xfeed_face_dead_beef;
        let mut output = sentinel;
        assert!(matches!(
            first
                .fill_matches_with_session(&foreign, b"abc", SearchWindow::new(0, 3), &mut output,),
            Err(RegexSetFinite64RunError::SessionProgramMismatch {
                clone_lineage_matches: false,
                ..
            })
        ));
        assert_eq!(sentinel, output);

        let short = first.prepare_session(2).unwrap();
        assert!(matches!(
            first.fill_matches_with_session(&short, b"abc", SearchWindow::new(0, 3), &mut output,),
            Err(RegexSetFinite64RunError::SourceBytesLimit {
                needed: 3,
                limit: 2
            })
        ));
        assert_eq!(sentinel, output);

        let session = first.prepare_session(8).unwrap();
        assert!(matches!(
            first
                .fill_matches_with_session(&session, b"abc", SearchWindow::new(2, 4), &mut output,),
            Err(RegexSetFinite64RunError::InvalidWindow { .. })
        ));
        assert_eq!(sentinel, output);
    }
}
