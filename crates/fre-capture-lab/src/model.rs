//! Canonical capture records and execution reports.

/// A half-open byte span in the original haystack.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Span {
    /// Inclusive start offset.
    pub start: usize,
    /// Exclusive end offset.
    pub end: usize,
}

/// A logical search window in the original haystack.
///
/// Anchors refer to these boundaries, while returned offsets remain absolute.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Window {
    /// Inclusive first byte eligible for matching.
    pub start: usize,
    /// Exclusive end boundary.
    pub end: usize,
}

impl Window {
    /// The entire haystack.
    #[must_use]
    pub const fn all(haystack: &[u8]) -> Self {
        Self {
            start: 0,
            end: haystack.len(),
        }
    }
}

/// One canonical group entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupRecord {
    /// Numeric group index. Group zero is the whole match.
    pub index: u32,
    /// Optional capture name.
    pub name: Option<String>,
    /// Last participating span, or `None` when unmatched.
    pub span: Option<Span>,
}

/// Canonical captures, including group zero.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureRecord {
    /// Groups in numeric index order.
    pub groups: Vec<GroupRecord>,
}

impl CaptureRecord {
    /// Whole-match span from group zero.
    #[must_use]
    pub fn overall(&self) -> Option<Span> {
        self.groups.first().and_then(|group| group.span)
    }
}

/// Candidate executor identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateKind {
    /// Ordered Pike-style threads with inline capture vectors.
    InlineSlots,
    /// Ordered Pike-style threads with persistent capture histories.
    PersistentHistory,
}

/// Checked resource accounting for one search.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunReport {
    /// Candidate formulation used.
    pub candidate: CandidateKind,
    /// Thompson state visits.
    pub state_visits: usize,
    /// Logical slot copies performed by the inline formulation.
    pub slot_copies: usize,
    /// Persistent history nodes allocated.
    pub history_nodes: usize,
    /// Nodes walked to materialize the winner.
    pub history_walk: usize,
    /// Candidate starts injected into the ordered frontier.
    pub starts_injected: usize,
    /// Input bytes advanced over.
    pub bytes_examined: usize,
    /// Maximum live consuming/match threads in one generation.
    pub peak_threads: usize,
    /// Conservative scratch admission bound.
    pub admitted_scratch_bytes: usize,
}

/// Result of one bounded search.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchOutcome {
    /// Canonical captures, or `None` when there is no match.
    pub captures: Option<CaptureRecord>,
    /// Exact logical accounting plus the conservative scratch bound.
    pub report: RunReport,
}

/// Result of bounded repeated-search aggregate iteration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateOutcome {
    /// All non-overlapping canonical records.
    pub captures: Vec<CaptureRecord>,
    /// Number of independently bounded searches.
    pub searches: usize,
    /// Total state visits.
    pub total_state_visits: usize,
    /// Total slot copies.
    pub total_slot_copies: usize,
    /// Total persistent history nodes.
    pub total_history_nodes: usize,
}
