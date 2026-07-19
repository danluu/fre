//! Canonical capture records and execution reports.

/// A half-open byte span in the original haystack.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Span {
    /// Inclusive start offset.
    pub start: usize,
    /// Exclusive end offset.
    pub end: usize,
}

/// A half-open search span in the original haystack.
///
/// Consuming transitions and returned matches are clipped to these bounds,
/// while zero-width assertions retain the surrounding context of the original
/// haystack. Returned offsets remain absolute.
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

/// Match-selection policy for one capture search.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchKind {
    /// Preserve the highest-priority leftmost match until it is irrevocable.
    Leftmost,
    /// Stop at the first input boundary with any accepting thread.
    Earliest,
}

/// Match-priority policy for one capture search.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatchKind {
    /// Report the last accepting match, ignoring match-end priority.
    All,
    /// Preserve ordered alternation and greediness priority.
    LeftmostFirst,
}

/// Explicit selection and start-injection policy for one capture search.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchConfig {
    /// End-boundary selection policy.
    pub kind: SearchKind,
    /// Match-priority policy.
    pub match_kind: MatchKind,
    /// When true, inject a start only at the requested search offset.
    pub anchored: bool,
}

impl SearchConfig {
    /// Ordinary unanchored leftmost-first search.
    pub const LEFTMOST: Self = Self {
        kind: SearchKind::Leftmost,
        match_kind: MatchKind::LeftmostFirst,
        anchored: false,
    };

    /// Unanchored earliest-end search.
    pub const EARLIEST: Self = Self {
        kind: SearchKind::Earliest,
        match_kind: MatchKind::LeftmostFirst,
        anchored: false,
    };

    /// Return this policy with the requested match-priority semantics.
    #[must_use]
    pub const fn match_kind(mut self, match_kind: MatchKind) -> Self {
        self.match_kind = match_kind;
        self
    }

    /// Return this policy with start injection restricted to the search offset.
    #[must_use]
    pub const fn anchored(mut self, anchored: bool) -> Self {
        self.anchored = anchored;
        self
    }
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self::LEFTMOST
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

/// Result of a capture-participation reduction over non-empty matches.
///
/// Unlike [`AggregateOutcome`], this does not retain one capture record per
/// match. Each selected winner is materialized once, reduced immediately and
/// then dropped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureCountOutcome {
    /// Sum of participating groups, including group zero.
    pub count: usize,
    /// Number of selected non-overlapping matches.
    pub matches: usize,
    /// Number of independently bounded searches or exact-span replays. The
    /// legacy restarted reducer includes its final miss; selector-driven
    /// replay has one invocation per certified non-empty match and no miss.
    pub searches: usize,
    /// Total Thompson state visits.
    pub total_state_visits: usize,
    /// Total persistent history nodes allocated.
    pub total_history_nodes: usize,
    /// Total history nodes walked while materializing winners.
    pub total_history_walk: usize,
    /// Maximum live consuming/match threads in any search.
    pub peak_threads: usize,
}
