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

/// Immutable structural shape of the persistent-history program.
///
/// The capture facade binds this shape into its construction-owned
/// capture-array seal. It is sufficient to reproduce the restarted-session
/// prospective without inspecting source bytes or exposing program contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryProgramShape {
    /// Thompson instruction count.
    pub states: usize,
    /// Tagged-save instruction count.
    pub save_states: usize,
    /// Internal tagged slot count.
    pub slots: usize,
    /// Canonical capture schema entries, including group zero.
    pub groups: usize,
    /// UTF-8 payload bytes cloned for named groups in each canonical record.
    pub name_payload_bytes: usize,
}

/// One source-independent persistent-history search envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistorySearchProspective {
    /// Maximum Thompson state visits.
    pub state_visits: usize,
    /// Maximum persistent-history nodes.
    pub history_nodes: usize,
    /// Maximum winning-history reconstruction steps.
    pub history_walk: usize,
    /// Maximum input bytes advanced over.
    pub bytes_examined: usize,
    /// Maximum candidate starts injected.
    pub starts_injected: usize,
    /// Maximum simultaneously live threads.
    pub peak_threads: usize,
    /// Conservative dynamic scratch bound.
    pub scratch_bytes: usize,
}

/// Complete pre-source envelope for restarted persistent-history iteration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestartedHistoryProspective {
    /// Logical capture window used to derive this envelope.
    pub window: Window,
    /// Construction-proved whole-match lower bound. Zero selects the nullable
    /// empty-progress envelope.
    pub minimum_match_bytes: usize,
    /// Largest single-search envelope in this session.
    pub largest_search: HistorySearchProspective,
    /// Maximum independently bounded searches.
    pub searches: usize,
    /// Maximum winners materialized, including nullable winners later
    /// suppressed by iterator progression.
    pub materialized_records: usize,
    /// Maximum capture records retained by the returned output.
    pub results: usize,
    /// Maximum cumulative Thompson state visits.
    pub total_state_visits: usize,
    /// Persistent-history execution performs no inline slot copies.
    pub total_slot_copies: usize,
    /// Maximum cumulative persistent-history nodes.
    pub total_history_nodes: usize,
    /// Maximum cumulative winning-history reconstruction steps.
    pub total_history_walk: usize,
    /// Maximum complete-schema capture entries materialized, including an
    /// empty winner later suppressed by iterator progress.
    pub capture_events: usize,
    /// Maximum cumulative input bytes advanced over.
    pub bytes_examined: usize,
    /// Maximum cumulative candidate starts injected.
    pub starts_injected: usize,
    /// Maximum simultaneously live threads in one search.
    pub peak_threads: usize,
    /// Maximum conservative dynamic scratch for one search.
    pub scratch_bytes: usize,
    /// Maximum versioned logical bytes retained by the returned capture
    /// vector. Allocator capacity slack is deliberately outside this model.
    pub retained_output_bytes: usize,
    /// Maximum logical retained/current materialization bytes plus the
    /// charged scratch envelope of the current search.
    pub combined_peak_bytes: usize,
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
