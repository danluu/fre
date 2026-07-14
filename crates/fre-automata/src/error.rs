use core::fmt;

/// A resource dimension checked before compilation or search work begins.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ResourceKind {
    States,
    Edges,
    StorageBytes,
    ValidationWork,
    ScratchBytes,
}

impl fmt::Display for ResourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::States => "states",
            Self::Edges => "edges",
            Self::StorageBytes => "storage bytes",
            Self::ValidationWork => "validation work",
            Self::ScratchBytes => "scratch bytes",
        };
        f.write_str(name)
    }
}

/// A structural error in a proposed structure-of-arrays automaton.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MalformedPlan {
    EmptyStateTable,
    IndexSpaceExceeded {
        resource: ResourceKind,
        count: usize,
    },
    StartOutOfBounds {
        start: u32,
        states: usize,
    },
    OffsetCount {
        expected: usize,
        actual: usize,
    },
    EdgeArrayLength {
        array: &'static str,
        expected: usize,
        actual: usize,
    },
    FirstOffsetNotZero {
        actual: u32,
    },
    OffsetDecreases {
        state: usize,
        from: u32,
        to: u32,
    },
    OffsetOutOfBounds {
        state: usize,
        offset: u32,
        edges: usize,
    },
    FinalOffsetMismatch {
        final_offset: u32,
        edges: usize,
    },
    TargetOutOfBounds {
        edge: usize,
        target: u32,
        states: usize,
    },
    EdgeKindForState {
        state: usize,
        edge: usize,
        role: &'static str,
        kind: &'static str,
    },
    AcceptHasEdges {
        state: usize,
        edges: usize,
    },
    InvalidByteRange {
        edge: usize,
        start: u8,
        end: u8,
    },
    NonCanonicalByteBounds {
        edge: usize,
        start: u8,
        end: u8,
    },
    MissingAcceptState,
}

impl fmt::Display for MalformedPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyStateTable => f.write_str("the state table is empty"),
            Self::IndexSpaceExceeded { resource, count } => {
                write!(
                    f,
                    "{resource} count {count} exceeds the u32 plan index space"
                )
            }
            Self::StartOutOfBounds { start, states } => {
                write!(f, "start state {start} is outside {states} states")
            }
            Self::OffsetCount { expected, actual } => write!(
                f,
                "edge offset table has length {actual}, expected {expected}"
            ),
            Self::EdgeArrayLength {
                array,
                expected,
                actual,
            } => write!(
                f,
                "edge array {array} has length {actual}, expected {expected}"
            ),
            Self::FirstOffsetNotZero { actual } => {
                write!(f, "first edge offset is {actual}, expected zero")
            }
            Self::OffsetDecreases { state, from, to } => {
                write!(f, "edge offsets decrease at state {state}: {from} to {to}")
            }
            Self::OffsetOutOfBounds {
                state,
                offset,
                edges,
            } => write!(
                f,
                "edge offset {offset} for state {state} exceeds {edges} edges"
            ),
            Self::FinalOffsetMismatch {
                final_offset,
                edges,
            } => write!(
                f,
                "final edge offset is {final_offset}, but there are {edges} edges"
            ),
            Self::TargetOutOfBounds {
                edge,
                target,
                states,
            } => write!(
                f,
                "edge {edge} targets state {target}, outside {states} states"
            ),
            Self::EdgeKindForState {
                state,
                edge,
                role,
                kind,
            } => write!(
                f,
                "{role} state {state} has incompatible {kind} edge {edge}"
            ),
            Self::AcceptHasEdges { state, edges } => {
                write!(f, "accept state {state} has {edges} outgoing edges")
            }
            Self::InvalidByteRange { edge, start, end } => write!(
                f,
                "byte edge {edge} has descending range {start:#04x}..={end:#04x}"
            ),
            Self::NonCanonicalByteBounds { edge, start, end } => write!(
                f,
                "zero-width edge {edge} has non-zero byte bounds {start:#04x}, {end:#04x}"
            ),
            Self::MissingAcceptState => f.write_str("the automaton has no accept state"),
        }
    }
}

/// A checked failure while validating and freezing an automaton.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CompileError {
    Malformed(MalformedPlan),
    ResourceLimit {
        resource: ResourceKind,
        needed: usize,
        limit: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(error) => write!(f, "malformed automaton: {error}"),
            Self::ResourceLimit {
                resource,
                needed,
                limit,
            } => write!(
                f,
                "automaton requires {needed} {resource}, exceeding limit {limit}"
            ),
            Self::ArithmeticOverflow { computation } => {
                write!(f, "arithmetic overflow while computing {computation}")
            }
        }
    }
}

impl std::error::Error for CompileError {}

impl From<MalformedPlan> for CompileError {
    fn from(value: MalformedPlan) -> Self {
        Self::Malformed(value)
    }
}

/// A checked failure during a K0 search.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SearchError {
    InvalidWindow {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
    ResourceLimit {
        resource: ResourceKind,
        needed: usize,
        limit: usize,
    },
    WorkspaceSetupWorkLimitExceeded {
        limit: u64,
        needed: u64,
    },
    WorkspaceLayoutMismatch {
        required_states: usize,
        actual_states: usize,
        required_edges: usize,
        actual_edges: usize,
        required_zero_width_edges: usize,
        actual_zero_width_edges: usize,
    },
    WorkLimitExceeded {
        limit: u64,
        consumed: u64,
        requested: u64,
        position: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    ScratchAllocationFailed {
        requested: usize,
    },
    InternalInvariant {
        detail: &'static str,
    },
}

impl fmt::Display for SearchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidWindow {
                start,
                end,
                haystack_len,
            } => write!(
                f,
                "search window {start}..{end} is invalid for a {haystack_len}-byte haystack"
            ),
            Self::ResourceLimit {
                resource,
                needed,
                limit,
            } => write!(
                f,
                "search requires {needed} {resource}, exceeding limit {limit}"
            ),
            Self::WorkspaceSetupWorkLimitExceeded { limit, needed } => write!(
                f,
                "workspace construction requires {needed} setup work, exceeding limit {limit}"
            ),
            Self::WorkspaceLayoutMismatch {
                required_states,
                actual_states,
                required_edges,
                actual_edges,
                required_zero_width_edges,
                actual_zero_width_edges,
            } => write!(
                f,
                "workspace layout mismatch: plan needs {required_states} states, {required_edges} \
                 edges, and {required_zero_width_edges} zero-width edges; workspace has \
                 {actual_states} states, {actual_edges} edges, and {actual_zero_width_edges} \
                 zero-width edges"
            ),
            Self::WorkLimitExceeded {
                limit,
                consumed,
                requested,
                position,
            } => write!(
                f,
                "search work limit {limit} exceeded at byte boundary {position}: \
                 {consumed} consumed and {requested} more requested"
            ),
            Self::ArithmeticOverflow { computation } => {
                write!(f, "arithmetic overflow while computing {computation}")
            }
            Self::ScratchAllocationFailed { requested } => {
                write!(f, "failed to allocate {requested} bytes of search scratch")
            }
            Self::InternalInvariant { detail } => {
                write!(
                    f,
                    "validated automaton invariant failed during search: {detail}"
                )
            }
        }
    }
}

impl std::error::Error for SearchError {}
