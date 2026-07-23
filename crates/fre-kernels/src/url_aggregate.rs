//! Bounded aggregate execution for the certified Rebar URL grammar.
//!
//! This kernel does not recognize the grammar from source text. Its caller
//! must first certify the complete HIR factorization documented by
//! [`UrlAggregatePlan::build`], then pass the ordered finite TLD language.
//! The finite island is only a candidate proof. Exact reverse-prefix and
//! forward-suffix validators below preserve leftmost-first, root-alternative,
//! repetition and literal-alternative priority without replaying the large
//! continuation NFA.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "unchecked cursor arithmetic is dominated by explicit slice/range bounds; externally sized resource totals use checked helpers"
)]

use core::{fmt, mem::size_of, ops::Range};

use fre_exact_alloc::{CopyError, ExactVec};

pub const PLAN_ID: &str = "url-aggregate.certified-factor.v1";
pub const SPAN_SUM_OPERATION_ID: &str = "url-aggregate.span-sum.v1";

const ALPHABET: usize = 37;
const UNSET: u32 = u32::MAX;
const NONE: usize = usize::MAX;
const MAX_TLD_BYTES: usize = 24;
const LABEL_REPETITIONS: usize = 62;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub max_tlds: usize,
    pub max_tld_bytes: usize,
    pub max_states: usize,
    pub max_table_cells: usize,
    pub max_work: usize,
    pub max_persistent_bytes: usize,
    pub max_scratch_bytes: usize,
    pub max_peak_bytes: usize,
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            max_tlds: 4_096,
            max_tld_bytes: 1 << 16,
            max_states: 1 << 16,
            max_table_cells: 1 << 21,
            max_work: 1 << 24,
            max_persistent_bytes: 16 << 20,
            max_scratch_bytes: 0,
            max_peak_bytes: 16 << 20,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub tlds: usize,
    pub tld_bytes: usize,
    pub states_upper_bound: usize,
    pub states: usize,
    pub table_cells: usize,
    pub initialized_cells: usize,
    pub priority_comparisons: usize,
    pub trie_transitions: usize,
    pub work: usize,
    pub persistent_bytes: usize,
    pub scratch_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceLimits {
    pub max_input_bytes: usize,
    pub max_boundaries: usize,
    pub max_candidates: usize,
    pub max_match_events: usize,
    pub max_output_matches: usize,
    pub max_span_sum: usize,
    pub max_sequential_bytes: usize,
    /// Cumulative backward/random source reads. This is work-like logical I/O,
    /// not retained random-access storage.
    pub max_random_access_bytes: usize,
    pub max_random_access_storage_bytes: usize,
    pub max_work: usize,
    pub max_scratch_bytes: usize,
    pub max_peak_bytes: usize,
}

impl Default for ReduceLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 128 << 20,
            max_boundaries: (128 << 20) + 1,
            max_candidates: 4 << 20,
            max_match_events: 1 << 20,
            max_output_matches: 1 << 20,
            max_span_sum: usize::MAX,
            max_sequential_bytes: 512 << 20,
            max_random_access_bytes: 512 << 20,
            max_random_access_storage_bytes: 256 << 20,
            max_work: 1 << 29,
            max_scratch_bytes: 256 << 20,
            max_peak_bytes: 512 << 20,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReduceAccounting {
    pub input_bytes: usize,
    pub boundaries: usize,
    pub segments: usize,
    pub segment_peak_bytes: usize,
    pub dot_probes: usize,
    pub tld_transitions: usize,
    pub tld_candidates: usize,
    pub scheme_probes: usize,
    pub ipv4_candidates: usize,
    pub prefix_steps: usize,
    pub suffix_steps: usize,
    pub candidate_insertions: usize,
    pub candidate_visits: usize,
    pub matches: usize,
    pub span_sum: usize,
    pub sequential_bytes: usize,
    pub random_access_bytes: usize,
    pub random_access_storage_bytes: usize,
    pub work: usize,
    pub scratch_bytes: usize,
    pub peak_bytes: usize,
}

/// Conservative input-only authorization envelope for URL reduction.
///
/// The kernel still allocates records only for the longest delimiter-bounded
/// segment. This envelope deliberately authorizes the worst case of one
/// segment spanning the complete input, without exposing or duplicating the
/// private candidate-record layout outside this module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceUpperBounds {
    pub input_bytes: usize,
    pub boundaries: usize,
    pub candidate_records: usize,
    pub candidate_record_bytes: usize,
    pub random_access_storage_bytes: usize,
    pub scratch_bytes: usize,
    pub peak_bytes: usize,
    pub sequential_bytes: usize,
    pub match_events: usize,
    pub output_matches: usize,
    pub span_sum: usize,
}

/// Derive the authoritative input-only URL reduction envelope without
/// constructing a plan.
pub fn reduce_upper_bounds(input_bytes: usize) -> Result<ReduceUpperBounds, ReduceError> {
    UrlAggregatePlan::reduce_upper_bounds(input_bytes)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanSumResult {
    pub value: usize,
    pub matches: usize,
    pub accounting: ReduceAccounting,
}

/// Terminal URL-reduction refusal together with every effect committed before
/// that refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReduceAttemptError {
    pub source: ReduceError,
    pub accounting: ReduceAccounting,
    pub actual_allocations: usize,
}

impl fmt::Display for ReduceAttemptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.source, formatter)
    }
}

impl std::error::Error for ReduceAttemptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    EmptyLanguage,
    EmptyTld {
        index: usize,
    },
    InvalidTld {
        index: usize,
        offset: usize,
    },
    TldLength {
        index: usize,
        length: usize,
    },
    DuplicateTld {
        first: usize,
        second: usize,
    },
    PriorityConflict {
        shorter: usize,
        longer: usize,
    },
    Resource {
        resource: &'static str,
        needed: usize,
        limit: usize,
    },
    Overflow(&'static str),
    Allocation {
        resource: &'static str,
        items: usize,
    },
    Invariant(&'static str),
}

/// Authoritative owner of compile work and retained construction bytes.
///
/// The aggregate compiler implements this adapter with its single
/// `CompileBudget`; consequently no source traversal or trie action can occur
/// under a private meter and be charged only after the fact.
///
/// `retain_bytes` must be failure-atomic: an error leaves the authority's
/// retained-byte total unchanged. A successful reservation is transferred to
/// the returned plan, or released exactly once before an error is returned.
pub trait UrlAggregateBuildAuthority {
    fn charge_work(&mut self, amount: usize) -> Result<(), BuildError>;
    fn retain_bytes(&mut self, amount: usize) -> Result<(), BuildError>;
    fn release_bytes(&mut self, amount: usize) -> Result<(), BuildError>;
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "URL aggregate build refusal: {self:?}")
    }
}

impl std::error::Error for BuildError {}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReduceError {
    InvalidRange {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
    Resource {
        resource: &'static str,
        needed: usize,
        limit: usize,
    },
    Overflow(&'static str),
    Allocation {
        resource: &'static str,
        items: usize,
    },
    Invariant(&'static str),
}

impl fmt::Display for ReduceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "URL aggregate reduction refusal: {self:?}")
    }
}

impl std::error::Error for ReduceError {}

/// Retained finite-island trie for one strictly certified URL factorization.
#[derive(Debug)]
pub struct UrlAggregatePlan {
    transitions: ExactVec<u32>,
    terminal: ExactVec<bool>,
    max_tld_bytes: usize,
    build: BuildAccounting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CandidateRecord {
    domain_end: usize,
    ipv4_end: usize,
}

impl CandidateRecord {
    const EMPTY: Self = Self {
        domain_end: NONE,
        ipv4_end: NONE,
    };
}

#[derive(Debug)]
struct Meter {
    limits: ReduceLimits,
    accounting: ReduceAccounting,
}

impl Meter {
    fn new(limits: ReduceLimits, input_bytes: usize, boundaries: usize) -> Self {
        Self {
            limits,
            accounting: ReduceAccounting {
                input_bytes,
                boundaries,
                ..ReduceAccounting::default()
            },
        }
    }

    fn work(&mut self, amount: usize) -> Result<(), ReduceError> {
        self.accounting.work = reduce_add(self.accounting.work, amount, "work")?;
        reduce_enforce("work", self.accounting.work, self.limits.max_work)
    }

    fn sequential(&mut self, amount: usize) -> Result<(), ReduceError> {
        self.accounting.sequential_bytes =
            reduce_add(self.accounting.sequential_bytes, amount, "sequential bytes")?;
        reduce_enforce(
            "sequential bytes",
            self.accounting.sequential_bytes,
            self.limits.max_sequential_bytes,
        )?;
        self.work(amount)
    }

    fn random(&mut self, amount: usize) -> Result<(), ReduceError> {
        self.accounting.random_access_bytes = reduce_add(
            self.accounting.random_access_bytes,
            amount,
            "random access bytes",
        )?;
        reduce_enforce(
            "random access bytes",
            self.accounting.random_access_bytes,
            self.limits.max_random_access_bytes,
        )?;
        self.work(amount)
    }
}

fn sequential_read(source: &[u8], index: usize, meter: &mut Meter) -> Result<u8, ReduceError> {
    meter.sequential(1)?;
    source.get(index).copied().ok_or(ReduceError::Invariant(
        "charged sequential source index is out of bounds",
    ))
}

fn random_read(source: &[u8], index: usize, meter: &mut Meter) -> Result<u8, ReduceError> {
    meter.random(1)?;
    source.get(index).copied().ok_or(ReduceError::Invariant(
        "charged random source index is out of bounds",
    ))
}

impl UrlAggregatePlan {
    /// Derive a safe resource envelope from input length alone.
    ///
    /// Source access consists of one complete segment-size census, one
    /// complete delimiter scan, and at most one additional scan of every
    /// non-delimiter byte. Thus `3 * input_bytes` is a checked upper bound;
    /// observed access is normally smaller. Candidate workspace is bounded by
    /// the single-segment case and uses this module's exact private record
    /// size.
    pub fn reduce_upper_bounds(input_bytes: usize) -> Result<ReduceUpperBounds, ReduceError> {
        let boundaries = reduce_add(input_bytes, 1, "boundaries")?;
        let candidate_record_bytes = size_of::<CandidateRecord>();
        let workspace = reduce_mul(boundaries, candidate_record_bytes, "candidate record bytes")?;
        let sequential_bytes = reduce_mul(input_bytes, 3, "sequential bytes")?;
        Ok(ReduceUpperBounds {
            input_bytes,
            boundaries,
            candidate_records: boundaries,
            candidate_record_bytes,
            random_access_storage_bytes: workspace,
            scratch_bytes: workspace,
            peak_bytes: workspace,
            sequential_bytes,
            match_events: boundaries,
            output_matches: boundaries,
            span_sum: input_bytes,
        })
    }

    /// Build the finite TLD island after the caller has certified all of these
    /// HIR invariants:
    ///
    /// * ASCII case-insensitive byte semantics and transparent outer captures;
    /// * root order `scheme+IPv4 | optional-scheme+optional-auth+domain+TLD`;
    /// * the exact bounded label/auth grammars used by this module;
    /// * the exact common optional port/path/query suffix used by this module;
    /// * ASCII whitespace is precisely the globally unconsumable delimiter set;
    /// * `tlds` retains source alternation order.
    ///
    /// Construction additionally proves that choosing the longest matching TLD
    /// preserves source priority for every prefix-related pair.
    #[allow(
        clippy::too_many_lines,
        reason = "one construction transaction keeps validation, exact allocation, initialization and publication accounting adjacent"
    )]
    pub fn build(
        packed_tlds: &[u8],
        tld_ends: &[usize],
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        let mut authority = LocalBuildAuthority::new(limits);
        Self::build_with_authority(packed_tlds, tld_ends, limits, &mut authority)
    }

    /// Build while every action is charged to the caller's authoritative
    /// compile budget before that action occurs.
    #[allow(
        clippy::too_many_lines,
        reason = "one construction transaction keeps validation, exact allocation, initialization and publication accounting adjacent"
    )]
    pub fn build_with_authority(
        packed_tlds: &[u8],
        tld_ends: &[usize],
        limits: BuildLimits,
        authority: &mut impl UrlAggregateBuildAuthority,
    ) -> Result<Self, BuildError> {
        if tld_ends.is_empty() {
            return Err(BuildError::EmptyLanguage);
        }
        build_enforce("TLDs", tld_ends.len(), limits.max_tlds)?;
        let tld_count = tld_ends.len();
        let mut work = 0_usize;
        charge_build(authority, &mut work, tld_ends.len(), limits.max_work)?;
        let tld_bytes = packed_tlds.len();
        build_enforce("TLD bytes", tld_bytes, limits.max_tld_bytes)?;
        let mut max_tld_bytes = 0_usize;
        for index in 0..tld_ends.len() {
            charge_build(authority, &mut work, 1, limits.max_work)?;
            let tld = packed_tld(packed_tlds, tld_ends, index)?;
            if tld.is_empty() {
                return Err(BuildError::EmptyTld { index });
            }
            if !(2..=MAX_TLD_BYTES).contains(&tld.len()) {
                return Err(BuildError::TldLength {
                    index,
                    length: tld.len(),
                });
            }
            max_tld_bytes = max_tld_bytes.max(tld.len());
            for offset in 0..tld.len() {
                charge_build(authority, &mut work, 1, limits.max_work)?;
                let byte = *tld.get(offset).ok_or(BuildError::Invariant(
                    "validated TLD offset disappeared before byte inspection",
                ))?;
                if alphabet(byte.to_ascii_lowercase()).is_none() {
                    return Err(BuildError::InvalidTld { index, offset });
                }
            }
        }

        let mut priority_comparisons = 0_usize;
        for first in 0..tld_ends.len() {
            charge_build(authority, &mut work, 1, limits.max_work)?;
            let first_tld = packed_tld(packed_tlds, tld_ends, first)?;
            for second in first + 1..tld_ends.len() {
                charge_build(authority, &mut work, 1, limits.max_work)?;
                let second_tld = packed_tld(packed_tlds, tld_ends, second)?;
                let compared = first_tld.len().min(second_tld.len());
                let mut equal_prefix = true;
                for offset in 0..compared {
                    charge_build(authority, &mut work, 1, limits.max_work)?;
                    let left = *first_tld.get(offset).ok_or(BuildError::Invariant(
                        "priority left byte disappeared before comparison",
                    ))?;
                    let right = *second_tld.get(offset).ok_or(BuildError::Invariant(
                        "priority right byte disappeared before comparison",
                    ))?;
                    priority_comparisons =
                        build_add(priority_comparisons, 1, "priority comparisons")?;
                    if !left.eq_ignore_ascii_case(&right) {
                        equal_prefix = false;
                        break;
                    }
                }
                if equal_prefix && first_tld.len() == second_tld.len() {
                    return Err(BuildError::DuplicateTld { first, second });
                }
                if equal_prefix && first_tld.len() < second_tld.len() {
                    return Err(BuildError::PriorityConflict {
                        shorter: first,
                        longer: second,
                    });
                }
            }
        }

        let states_upper_bound = build_add(tld_bytes, 1, "states")?;
        build_enforce("states", states_upper_bound, limits.max_states)?;
        let table_cells = build_mul(states_upper_bound, ALPHABET, "table cells")?;
        build_enforce("table cells", table_cells, limits.max_table_cells)?;
        let transition_bytes = build_mul(table_cells, size_of::<u32>(), "transition bytes")?;
        let terminal_bytes = build_mul(states_upper_bound, size_of::<bool>(), "terminal bytes")?;
        let persistent_bytes = build_add(
            size_of::<Self>(),
            build_add(transition_bytes, terminal_bytes, "persistent arrays")?,
            "persistent bytes",
        )?;
        build_enforce(
            "persistent bytes",
            persistent_bytes,
            limits.max_persistent_bytes,
        )?;
        build_enforce("scratch bytes", 0, limits.max_scratch_bytes)?;
        build_enforce("peak bytes", persistent_bytes, limits.max_peak_bytes)?;

        charge_build(
            authority,
            &mut work,
            build_add(
                build_add(table_cells, states_upper_bound, "initialization work")?,
                4, // two allocator calls and their eventual deallocations
                "initialization work",
            )?,
            limits.max_work,
        )?;
        authority.retain_bytes(persistent_bytes)?;
        let result = (|| {
            let mut transitions = exact_build_vec(table_cells, "transition table")?;
            for _ in 0..table_cells {
                transitions.try_push(UNSET).map_err(|_| {
                    BuildError::Invariant("transition initialization exceeded exact capacity")
                })?;
            }
            let mut terminal = exact_build_vec(states_upper_bound, "terminal states")?;
            for _ in 0..states_upper_bound {
                terminal.try_push(false).map_err(|_| {
                    BuildError::Invariant("terminal initialization exceeded exact capacity")
                })?;
            }

            let mut states = 1_usize;
            let mut trie_transitions = 0_usize;
            for index in 0..tld_ends.len() {
                charge_build(authority, &mut work, 1, limits.max_work)?;
                let tld = packed_tld(packed_tlds, tld_ends, index)?;
                let mut state = 0_usize;
                for offset in 0..tld.len() {
                    charge_build(authority, &mut work, 4, limits.max_work)?; // fold, alphabet map, lookup/branch, selected-state write
                    let source = *tld.get(offset).ok_or(BuildError::Invariant(
                        "validated trie byte disappeared before transition",
                    ))?;
                    trie_transitions = build_add(trie_transitions, 1, "trie transitions")?;
                    let symbol = alphabet(source.to_ascii_lowercase())
                        .ok_or(BuildError::Invariant("validated TLD left trie alphabet"))?;
                    let cell = build_add(
                        build_mul(state, ALPHABET, "trie cell")?,
                        symbol,
                        "trie cell",
                    )?;
                    let target = transitions[cell];
                    if target == UNSET {
                        let represented = u32::try_from(states)
                            .map_err(|_| BuildError::Overflow("represented state"))?;
                        transitions[cell] = represented;
                        state = states;
                        states = build_add(states, 1, "states")?;
                    } else {
                        state = usize::try_from(target)
                            .map_err(|_| BuildError::Invariant("state does not fit usize"))?;
                    }
                }
                charge_build(authority, &mut work, 1, limits.max_work)?;
                terminal[state] = true;
            }
            if states > states_upper_bound {
                return Err(BuildError::Invariant(
                    "trie exceeded prospective state bound",
                ));
            }
            Ok(Self {
                transitions,
                terminal,
                max_tld_bytes,
                build: BuildAccounting {
                    tlds: tld_count,
                    tld_bytes,
                    states_upper_bound,
                    states,
                    table_cells,
                    initialized_cells: build_add(
                        table_cells,
                        states_upper_bound,
                        "initialized cells",
                    )?,
                    priority_comparisons,
                    trie_transitions,
                    work,
                    persistent_bytes,
                    scratch_bytes: 0,
                    peak_bytes: persistent_bytes,
                },
            })
        })();
        if result.is_err() {
            authority.release_bytes(persistent_bytes)?;
        }
        result
    }

    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.build
    }

    /// Return count and matched-byte sum for the certified grammar.
    #[allow(
        clippy::too_many_lines,
        reason = "one transaction keeps exact candidate ordering, metering and output publication auditable"
    )]
    pub fn span_sum(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        limits: ReduceLimits,
    ) -> Result<SpanSumResult, ReduceError> {
        self.span_sum_attempt(haystack, range, limits)
            .map_err(|error| error.source)
    }

    /// Return count and matched-byte sum while retaining exact terminal
    /// accounting when execution refuses after source access or allocation.
    #[allow(
        clippy::too_many_lines,
        reason = "one transaction keeps exact candidate ordering, metering, output publication and terminal accounting auditable"
    )]
    pub fn span_sum_attempt(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        limits: ReduceLimits,
    ) -> Result<SpanSumResult, ReduceAttemptError> {
        if range.start > range.end || range.end > haystack.len() {
            return Err(ReduceAttemptError {
                source: ReduceError::InvalidRange {
                    start: range.start,
                    end: range.end,
                    haystack_len: haystack.len(),
                },
                accounting: ReduceAccounting::default(),
                actual_allocations: 0,
            });
        }
        let input_bytes = range.end - range.start;
        reduce_enforce("input bytes", input_bytes, limits.max_input_bytes).map_err(|source| {
            ReduceAttemptError {
                source,
                accounting: ReduceAccounting::default(),
                actual_allocations: 0,
            }
        })?;
        let boundaries =
            reduce_add(input_bytes, 1, "boundaries").map_err(|source| ReduceAttemptError {
                source,
                accounting: ReduceAccounting::default(),
                actual_allocations: 0,
            })?;
        reduce_enforce("boundaries", boundaries, limits.max_boundaries).map_err(|source| {
            ReduceAttemptError {
                source,
                accounting: ReduceAccounting::default(),
                actual_allocations: 0,
            }
        })?;
        let mut meter = Meter::new(limits, input_bytes, boundaries);
        let mut actual_allocations = 0_usize;

        let result = (|| {
            // First pass determines the one exact reusable per-segment workspace.
            let mut segment_bytes = 0_usize;
            let mut segment_peak = 0_usize;
            for position in range.clone() {
                let byte = sequential_read(haystack, position, &mut meter)?;
                if is_delimiter(byte) {
                    segment_peak = segment_peak.max(segment_bytes);
                    segment_bytes = 0;
                } else {
                    segment_bytes = reduce_add(segment_bytes, 1, "segment bytes")?;
                }
            }
            segment_peak = segment_peak.max(segment_bytes);
            meter.accounting.segment_peak_bytes = segment_peak;
            let record_count = reduce_add(segment_peak, 1, "candidate records")?;
            let scratch_bytes =
                reduce_mul(record_count, size_of::<CandidateRecord>(), "scratch bytes")?;
            reduce_enforce(
                "random access storage bytes",
                scratch_bytes,
                limits.max_random_access_storage_bytes,
            )?;
            reduce_enforce("scratch bytes", scratch_bytes, limits.max_scratch_bytes)?;
            let peak_bytes = scratch_bytes;
            reduce_enforce("peak bytes", peak_bytes, limits.max_peak_bytes)?;
            // Prepay the allocator call and eventual deallocation before the
            // exact candidate-record allocation is attempted.
            meter.work(2)?;
            let mut records = exact_reduce_vec(record_count, "candidate records")?;
            actual_allocations = usize::from(record_count != 0);
            meter.accounting.scratch_bytes = scratch_bytes;
            meter.accounting.random_access_storage_bytes = scratch_bytes;
            meter.accounting.peak_bytes = peak_bytes;
            for _ in 0..record_count {
                meter.work(1)?;
                records.try_push(CandidateRecord::EMPTY).map_err(|_| {
                    ReduceError::Invariant("candidate initialization exceeded exact capacity")
                })?;
            }

            let mut cursor = range.start;
            let mut segment_start = range.start;
            let mut position = range.start;
            while position <= range.end {
                let at_end = position == range.end;
                let byte = if at_end {
                    None
                } else {
                    Some(sequential_read(haystack, position, &mut meter)?)
                };
                if at_end || byte.is_some_and(is_delimiter) {
                    if segment_start < position {
                        meter.accounting.segments =
                            reduce_add(meter.accounting.segments, 1, "segments")?;
                        self.process_segment(
                            haystack,
                            segment_start,
                            position,
                            &mut cursor,
                            &mut records,
                            &mut meter,
                        )?;
                    }
                    segment_start = reduce_add(position, usize::from(!at_end), "segment start")?;
                }
                position = reduce_add(position, 1, "input cursor")?;
            }
            Ok(SpanSumResult {
                value: meter.accounting.span_sum,
                matches: meter.accounting.matches,
                accounting: meter.accounting,
            })
        })();
        result.map_err(|source| ReduceAttemptError {
            source,
            accounting: meter.accounting,
            actual_allocations,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "segment transaction keeps its authenticated absolute bounds explicit"
    )]
    fn process_segment(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
        cursor: &mut usize,
        records: &mut ExactVec<CandidateRecord>,
        meter: &mut Meter,
    ) -> Result<(), ReduceError> {
        let length = end - start;
        if length + 1 > records.len() {
            return Err(ReduceError::Invariant(
                "segment exceeded preflight workspace",
            ));
        }
        for record in &mut records[..=length] {
            meter.work(1)?;
            *record = CandidateRecord::EMPTY;
        }
        for position in start..end {
            let byte = sequential_read(haystack, position, meter)?;
            if byte == b'.' {
                meter.accounting.dot_probes =
                    reduce_add(meter.accounting.dot_probes, 1, "dot probes")?;
                if let Some(tld_end) = self.longest_tld(haystack, position + 1, end, meter)? {
                    meter.accounting.tld_candidates =
                        reduce_add(meter.accounting.tld_candidates, 1, "TLD candidates")?;
                    domain_candidates(haystack, start, position, tld_end, records, meter)?;
                }
            }
            if matches!(byte.to_ascii_lowercase(), b'f' | b'h') {
                meter.accounting.scheme_probes =
                    reduce_add(meter.accounting.scheme_probes, 1, "scheme probes")?;
                if let Some(ip_end) = ipv4_end(haystack, position, end, meter)? {
                    let record = &mut records[position - start];
                    meter.work(1)?;
                    record.ipv4_end = ip_end;
                    meter.accounting.ipv4_candidates =
                        reduce_add(meter.accounting.ipv4_candidates, 1, "IPv4 candidates")?;
                    meter.accounting.candidate_insertions = reduce_add(
                        meter.accounting.candidate_insertions,
                        1,
                        "candidate insertions",
                    )?;
                }
            }
        }

        let first = cursor.saturating_sub(start).min(length);
        for (relative, record) in records[first..length].iter().enumerate() {
            meter.work(1)?;
            let absolute = start + first + relative;
            if absolute < *cursor {
                continue;
            }
            let core_end = if record.ipv4_end == NONE {
                record.domain_end
            } else {
                // The mandatory-scheme IPv4 root alternative has source priority.
                record.ipv4_end
            };
            if core_end == NONE {
                continue;
            }
            meter.accounting.candidate_visits =
                reduce_add(meter.accounting.candidate_visits, 1, "candidate visits")?;
            let match_end = suffix_end(haystack, core_end, end, meter)?;
            if match_end <= absolute {
                return Err(ReduceError::Invariant(
                    "URL candidate produced an empty match",
                ));
            }
            let width = match_end - absolute;
            let span_sum = reduce_add(meter.accounting.span_sum, width, "span sum")?;
            reduce_enforce("span sum", span_sum, meter.limits.max_span_sum)?;
            let matches = reduce_add(meter.accounting.matches, 1, "matches")?;
            reduce_enforce("match events", matches, meter.limits.max_match_events)?;
            reduce_enforce("output matches", matches, meter.limits.max_output_matches)?;
            reduce_enforce(
                "candidates",
                meter.accounting.candidate_visits,
                meter.limits.max_candidates,
            )?;
            meter.accounting.span_sum = span_sum;
            meter.accounting.matches = matches;
            *cursor = match_end;
        }
        Ok(())
    }

    fn longest_tld(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
        meter: &mut Meter,
    ) -> Result<Option<usize>, ReduceError> {
        let mut state = 0_usize;
        let mut longest = None;
        let limit = end.min(reduce_add(start, self.max_tld_bytes, "TLD bound")?);
        for position in start..limit {
            let source = random_read(haystack, position, meter)?;
            meter.accounting.tld_transitions =
                reduce_add(meter.accounting.tld_transitions, 1, "TLD transitions")?;
            let Some(symbol) = alphabet(source.to_ascii_lowercase()) else {
                break;
            };
            meter.work(2)?; // table lookup and missing-edge branch
            let target = self.transitions[state * ALPHABET + symbol];
            if target == UNSET {
                break;
            }
            state = usize::try_from(target)
                .map_err(|_| ReduceError::Invariant("TLD state does not fit usize"))?;
            meter.work(1)?;
            if self.terminal[state] {
                longest = Some(position + 1);
            }
        }
        Ok(longest)
    }
}

fn domain_candidates(
    source: &[u8],
    segment: usize,
    dot: usize,
    tld_end: usize,
    records: &mut [CandidateRecord],
    meter: &mut Meter,
) -> Result<(), ReduceError> {
    let (base_starts, base_count) = regular_suffixes(source, segment, dot, false, meter)?;
    let mut extension_start = None;
    for &start in &base_starts[..base_count] {
        publish_domain_candidate(source, segment, start, tld_end, records, meter)?;
    }
    if base_count > 0 {
        let earliest = base_starts[base_count - 1];
        if earliest > segment && random_read(source, earliest - 1, meter)? == b'.' {
            extension_start = Some(earliest);
        }
    }

    let mut lower = dot;
    while lower > segment {
        let byte = random_read(source, lower - 1, meter)?;
        meter.accounting.prefix_steps =
            reduce_add(meter.accounting.prefix_steps, 1, "prefix steps")?;
        if !is_xn_body(byte) {
            break;
        }
        lower -= 1;
    }
    let mut candidate = lower;
    while candidate + 5 <= dot {
        meter.work(1)?;
        if folded_equal(source, candidate, b"xn--", meter)? {
            publish_domain_candidate(source, segment, candidate, tld_end, records, meter)?;
            if candidate > segment && random_read(source, candidate - 1, meter)? == b'.' {
                extension_start = Some(candidate);
            }
        }
        candidate += 1;
    }

    // Once a complete base label begins immediately after a dot, every valid
    // suffix of the preceding subdomain label is a distinct restart candidate.
    // Only a candidate covering that complete preceding label can extend again.
    let mut current = extension_start;
    while let Some(start) = current {
        let previous_end = start - 1;
        let (sub_starts, sub_count) = regular_suffixes(source, segment, previous_end, true, meter)?;
        for &sub_start in &sub_starts[..sub_count] {
            publish_domain_candidate(source, segment, sub_start, tld_end, records, meter)?;
        }
        current = if sub_count > 0 {
            let earliest = sub_starts[sub_count - 1];
            if earliest > segment {
                (random_read(source, earliest - 1, meter)? == b'.').then_some(earliest)
            } else {
                None
            }
        } else {
            None
        };
    }
    Ok(())
}

fn regular_suffixes(
    source: &[u8],
    segment: usize,
    end: usize,
    subdomain: bool,
    meter: &mut Meter,
) -> Result<([usize; LABEL_REPETITIONS + 1], usize), ReduceError> {
    let mut starts = [NONE; LABEL_REPETITIONS + 1];
    if end <= segment {
        return Ok((starts, 0));
    }
    if !is_alnum(random_read(source, end - 1, meter)?) {
        return Ok((starts, 0));
    }
    let mut position = end - 1;
    let mut count = 1_usize;
    starts[0] = position;
    for _ in 0..LABEL_REPETITIONS {
        if position >= segment + 2 {
            let hyphen = random_read(source, position - 1, meter)?;
            let atom = random_read(source, position - 2, meter)?;
            meter.accounting.prefix_steps =
                reduce_add(meter.accounting.prefix_steps, 1, "prefix steps")?;
            if hyphen == b'-' && is_label_atom(atom, subdomain) {
                position -= 2;
                starts[count] = position;
                count += 1;
                continue;
            }
        }
        if position > segment {
            let atom = random_read(source, position - 1, meter)?;
            meter.accounting.prefix_steps =
                reduce_add(meter.accounting.prefix_steps, 1, "prefix steps")?;
            if is_label_atom(atom, subdomain) {
                position -= 1;
                starts[count] = position;
                count += 1;
                continue;
            }
        }
        break;
    }
    Ok((starts, count))
}

fn publish_domain_candidate(
    source: &[u8],
    segment: usize,
    start: usize,
    tld_end: usize,
    records: &mut [CandidateRecord],
    meter: &mut Meter,
) -> Result<(), ReduceError> {
    publish_domain_record(segment, start, tld_end, records, meter)?;

    // Optional auth has an unambiguous reverse parse because ':' and '@' are
    // excluded from both nonempty auth fields. The unextended start remains a
    // candidate because matching is unanchored.
    if start > segment && random_read(source, start - 1, meter)? == b'@' {
        let at = start - 1;
        let mut password = at;
        while password > segment {
            let byte = random_read(source, password - 1, meter)?;
            meter.accounting.prefix_steps =
                reduce_add(meter.accounting.prefix_steps, 1, "prefix steps")?;
            if !is_password(byte) {
                break;
            }
            password -= 1;
        }
        let has_colon = if password < at && password > segment {
            random_read(source, password - 1, meter)? == b':'
        } else {
            false
        };
        if has_colon {
            let colon = password - 1;
            let mut user = colon;
            while user > segment {
                let byte = random_read(source, user - 1, meter)?;
                meter.accounting.prefix_steps =
                    reduce_add(meter.accounting.prefix_steps, 1, "prefix steps")?;
                if !is_user(byte) {
                    break;
                }
                user -= 1;
                publish_domain_record(segment, user, tld_end, records, meter)?;
                publish_scheme_extension(source, segment, user, tld_end, records, meter)?;
            }
        }
    }
    publish_scheme_extension(source, segment, start, tld_end, records, meter)?;
    Ok(())
}

fn publish_scheme_extension(
    source: &[u8],
    segment: usize,
    start: usize,
    tld_end: usize,
    records: &mut [CandidateRecord],
    meter: &mut Meter,
) -> Result<(), ReduceError> {
    for scheme in [
        b"https://".as_slice(),
        b"http://".as_slice(),
        b"ftp://".as_slice(),
    ] {
        meter.work(1)?;
        if start - segment >= scheme.len()
            && folded_equal(source, start - scheme.len(), scheme, meter)?
        {
            publish_domain_record(segment, start - scheme.len(), tld_end, records, meter)?;
            break;
        }
    }
    Ok(())
}

fn publish_domain_record(
    segment: usize,
    start: usize,
    tld_end: usize,
    records: &mut [CandidateRecord],
    meter: &mut Meter,
) -> Result<(), ReduceError> {
    let relative = start
        .checked_sub(segment)
        .ok_or(ReduceError::Invariant("domain candidate precedes segment"))?;
    let record = records.get_mut(relative).ok_or(ReduceError::Invariant(
        "domain candidate exceeds segment workspace",
    ))?;
    meter.work(2)?;
    record.domain_end = if record.domain_end == NONE {
        tld_end
    } else {
        record.domain_end.max(tld_end)
    };
    meter.accounting.candidate_insertions = reduce_add(
        meter.accounting.candidate_insertions,
        1,
        "candidate insertions",
    )?;
    reduce_enforce(
        "candidates",
        meter.accounting.candidate_insertions,
        meter.limits.max_candidates,
    )
}

fn ipv4_end(
    source: &[u8],
    start: usize,
    end: usize,
    meter: &mut Meter,
) -> Result<Option<usize>, ReduceError> {
    let mut position = None;
    for scheme in [
        b"https://".as_slice(),
        b"http://".as_slice(),
        b"ftp://".as_slice(),
    ] {
        meter.work(1)?;
        if end - start >= scheme.len() && folded_equal(source, start, scheme, meter)? {
            position = Some(start + scheme.len());
            break;
        }
    }
    let Some(mut position) = position else {
        return Ok(None);
    };
    for ordinal in 0..4 {
        let require_dot = ordinal < 3;
        let Some(octet_end) = octet_end(source, position, end, require_dot, meter)? else {
            return Ok(None);
        };
        position = octet_end;
        if require_dot {
            position += 1;
        }
    }
    Ok(Some(position))
}

fn octet_end(
    source: &[u8],
    start: usize,
    end: usize,
    require_dot: bool,
    meter: &mut Meter,
) -> Result<Option<usize>, ReduceError> {
    if start + 3 <= end {
        let first = random_read(source, start, meter)?;
        let second = random_read(source, start + 1, meter)?;
        let third = random_read(source, start + 2, meter)?;
        if first == b'2'
            && second == b'5'
            && matches!(third, b'0'..=b'5')
            && octet_context(source, start + 3, end, require_dot, meter)?
        {
            return Ok(Some(start + 3));
        }
        let first = random_read(source, start, meter)?;
        let second = random_read(source, start + 1, meter)?;
        let third = random_read(source, start + 2, meter)?;
        if first == b'2'
            && matches!(second, b'0'..=b'4')
            && third.is_ascii_digit()
            && octet_context(source, start + 3, end, require_dot, meter)?
        {
            return Ok(Some(start + 3));
        }
    }
    for length in [3_usize, 2, 1] {
        if start + length > end {
            continue;
        }
        let mut digits = true;
        let mut first = 0_u8;
        for offset in 0..length {
            let byte = random_read(source, start + offset, meter)?;
            if offset == 0 {
                first = byte;
            }
            digits &= byte.is_ascii_digit();
        }
        let represented = length < 3 || matches!(first, b'0' | b'1');
        if digits && represented && octet_context(source, start + length, end, require_dot, meter)?
        {
            return Ok(Some(start + length));
        }
    }
    Ok(None)
}

fn octet_context(
    source: &[u8],
    candidate: usize,
    end: usize,
    require_dot: bool,
    meter: &mut Meter,
) -> Result<bool, ReduceError> {
    if !require_dot || candidate >= end {
        return Ok(!require_dot);
    }
    Ok(random_read(source, candidate, meter)? == b'.')
}

fn suffix_end(
    source: &[u8],
    mut position: usize,
    end: usize,
    meter: &mut Meter,
) -> Result<usize, ReduceError> {
    let mut current = if position < end {
        Some(random_read(source, position, meter)?)
    } else {
        None
    };
    if current == Some(b':') {
        let first = position + 1;
        let mut digits = first;
        while digits < end && digits - first < 5 {
            let byte = random_read(source, digits, meter)?;
            meter.accounting.suffix_steps =
                reduce_add(meter.accounting.suffix_steps, 1, "suffix steps")?;
            if !byte.is_ascii_digit() {
                break;
            }
            digits += 1;
        }
        if digits - first >= 2 {
            position = digits;
        }
    }
    current = if position < end {
        Some(random_read(source, position, meter)?)
    } else {
        None
    };
    if current == Some(b'/') {
        position += 1;
        while position < end {
            let byte = random_read(source, position, meter)?;
            meter.accounting.suffix_steps =
                reduce_add(meter.accounting.suffix_steps, 1, "suffix steps")?;
            if !is_path(byte) {
                break;
            }
            position += 1;
        }
    }
    current = if position < end {
        Some(random_read(source, position, meter)?)
    } else {
        None
    };
    if matches!(current, Some(b'?' | b'#')) {
        // The segment was split on the exact complement of `\S`, so the
        // greedy non-space tail consumes the complete remainder.
        let tail = end - position;
        meter.work(tail)?;
        meter.accounting.suffix_steps =
            reduce_add(meter.accounting.suffix_steps, tail, "suffix steps")?;
        position = end;
    }
    Ok(position)
}

fn folded_equal(
    source: &[u8],
    start: usize,
    expected: &[u8],
    meter: &mut Meter,
) -> Result<bool, ReduceError> {
    for (offset, &right) in expected.iter().enumerate() {
        let left = random_read(source, start + offset, meter)?;
        meter.accounting.prefix_steps =
            reduce_add(meter.accounting.prefix_steps, 1, "prefix steps")?;
        if !left.eq_ignore_ascii_case(&right) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn alphabet(byte: u8) -> Option<usize> {
    match byte {
        b'-' => Some(0),
        b'0'..=b'9' => Some(1 + usize::from(byte - b'0')),
        b'a'..=b'z' => Some(11 + usize::from(byte - b'a')),
        _ => None,
    }
}

const fn is_alnum(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
}

const fn is_label_atom(byte: u8, subdomain: bool) -> bool {
    is_alnum(byte) || (subdomain && matches!(byte, b'_' | b'~'))
}

const fn is_xn_body(byte: u8) -> bool {
    is_alnum(byte) || byte == b'-'
}

const fn is_user(byte: u8) -> bool {
    is_alnum(byte) || matches!(byte, b'%' | b'.')
}

const fn is_password(byte: u8) -> bool {
    is_alnum(byte) || byte == b'%'
}

const fn is_delimiter(byte: u8) -> bool {
    matches!(byte, b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | b' ')
}

const fn is_path(byte: u8) -> bool {
    is_alnum(byte)
        || matches!(
            byte,
            b'/' | b'-'
                | b'_'
                | b'%'
                | b'$'
                | b'@'
                | b'&'
                | b'('
                | b')'
                | b'!'
                | b'?'
                | b'\''
                | b'='
                | b'~'
                | b'*'
                | b'+'
                | b':'
                | b';'
                | b','
                | b'.'
        )
}

#[derive(Debug)]
struct LocalBuildAuthority {
    limits: BuildLimits,
    work: usize,
    retained: usize,
}

impl LocalBuildAuthority {
    const fn new(limits: BuildLimits) -> Self {
        Self {
            limits,
            work: 0,
            retained: 0,
        }
    }
}

impl UrlAggregateBuildAuthority for LocalBuildAuthority {
    fn charge_work(&mut self, amount: usize) -> Result<(), BuildError> {
        let required = build_add(self.work, amount, "work")?;
        build_enforce("work", required, self.limits.max_work)?;
        self.work = required;
        Ok(())
    }

    fn retain_bytes(&mut self, amount: usize) -> Result<(), BuildError> {
        let required = build_add(self.retained, amount, "persistent bytes")?;
        build_enforce(
            "persistent bytes",
            required,
            self.limits.max_persistent_bytes,
        )?;
        build_enforce("peak bytes", required, self.limits.max_peak_bytes)?;
        self.retained = required;
        Ok(())
    }

    fn release_bytes(&mut self, amount: usize) -> Result<(), BuildError> {
        self.retained = self
            .retained
            .checked_sub(amount)
            .ok_or(BuildError::Invariant("retained byte release underflowed"))?;
        Ok(())
    }
}

fn charge_build(
    authority: &mut impl UrlAggregateBuildAuthority,
    observed: &mut usize,
    amount: usize,
    limit: usize,
) -> Result<(), BuildError> {
    let required = build_add(*observed, amount, "work")?;
    build_enforce("work", required, limit)?;
    authority.charge_work(amount)?;
    *observed = required;
    Ok(())
}

fn packed_tld<'a>(packed: &'a [u8], ends: &[usize], index: usize) -> Result<&'a [u8], BuildError> {
    let end = *ends.get(index).ok_or(BuildError::Invariant(
        "TLD index exceeds authenticated ends",
    ))?;
    let start = if index == 0 {
        0
    } else {
        *ends
            .get(index - 1)
            .ok_or(BuildError::Invariant("TLD predecessor end is absent"))?
    };
    if start > end || end > packed.len() || (index + 1 == ends.len() && end != packed.len()) {
        return Err(BuildError::Invariant(
            "packed TLD ends do not exactly partition source bytes",
        ));
    }
    Ok(&packed[start..end])
}

fn exact_build_vec<T>(capacity: usize, resource: &'static str) -> Result<ExactVec<T>, BuildError> {
    #[cfg(test)]
    allocation_probe::record_build();
    ExactVec::try_with_capacity(capacity).map_err(|error| match error {
        CopyError::LayoutOverflow => BuildError::Overflow(resource),
        CopyError::AllocationFailed => BuildError::Allocation {
            resource,
            items: capacity,
        },
    })
}

fn exact_reduce_vec<T>(
    capacity: usize,
    resource: &'static str,
) -> Result<ExactVec<T>, ReduceError> {
    #[cfg(test)]
    allocation_probe::record_reduce();
    ExactVec::try_with_capacity(capacity).map_err(|error| match error {
        CopyError::LayoutOverflow => ReduceError::Overflow(resource),
        CopyError::AllocationFailed => ReduceError::Allocation {
            resource,
            items: capacity,
        },
    })
}

#[cfg(test)]
mod allocation_probe {
    use core::cell::Cell;

    std::thread_local! {
        static BUILD: Cell<usize> = const { Cell::new(0) };
        static REDUCE: Cell<usize> = const { Cell::new(0) };
    }

    pub(super) fn record_build() {
        BUILD.set(BUILD.get().saturating_add(1));
    }

    pub(super) fn record_reduce() {
        REDUCE.set(REDUCE.get().saturating_add(1));
    }

    pub(super) fn reset_build() {
        BUILD.set(0);
    }

    pub(super) fn reset_reduce() {
        REDUCE.set(0);
    }

    pub(super) fn build_calls() -> usize {
        BUILD.get()
    }

    pub(super) fn reduce_calls() -> usize {
        REDUCE.get()
    }
}

fn build_add(left: usize, right: usize, resource: &'static str) -> Result<usize, BuildError> {
    left.checked_add(right)
        .ok_or(BuildError::Overflow(resource))
}

fn build_mul(left: usize, right: usize, resource: &'static str) -> Result<usize, BuildError> {
    left.checked_mul(right)
        .ok_or(BuildError::Overflow(resource))
}

fn build_enforce(resource: &'static str, needed: usize, limit: usize) -> Result<(), BuildError> {
    if needed > limit {
        Err(BuildError::Resource {
            resource,
            needed,
            limit,
        })
    } else {
        Ok(())
    }
}

fn reduce_add(left: usize, right: usize, resource: &'static str) -> Result<usize, ReduceError> {
    left.checked_add(right)
        .ok_or(ReduceError::Overflow(resource))
}

fn reduce_mul(left: usize, right: usize, resource: &'static str) -> Result<usize, ReduceError> {
    left.checked_mul(right)
        .ok_or(ReduceError::Overflow(resource))
}

fn reduce_enforce(resource: &'static str, needed: usize, limit: usize) -> Result<(), ReduceError> {
    if needed > limit {
        Err(ReduceError::Resource {
            resource,
            needed,
            limit,
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::bytes::RegexBuilder;
    use std::fs;

    #[allow(
        clippy::struct_excessive_bools,
        reason = "independent injected authority failures are clearer as orthogonal test switches"
    )]
    #[derive(Debug, Default)]
    struct TestAuthority {
        work: usize,
        retained: usize,
        reservation_seen: bool,
        work_at_reservation: usize,
        releases: usize,
        refuse_retain: bool,
        refuse_post_retain_work: bool,
        refuse_release: bool,
    }

    impl UrlAggregateBuildAuthority for TestAuthority {
        fn charge_work(&mut self, amount: usize) -> Result<(), BuildError> {
            if self.refuse_post_retain_work && self.reservation_seen {
                return Err(BuildError::Invariant(
                    "injected post-reservation work refusal",
                ));
            }
            self.work = build_add(self.work, amount, "test authority work")?;
            Ok(())
        }

        fn retain_bytes(&mut self, amount: usize) -> Result<(), BuildError> {
            if self.refuse_retain {
                return Err(BuildError::Invariant("injected reservation refusal"));
            }
            self.retained = build_add(self.retained, amount, "test retained bytes")?;
            self.reservation_seen = true;
            self.work_at_reservation = self.work;
            Ok(())
        }

        fn release_bytes(&mut self, amount: usize) -> Result<(), BuildError> {
            if self.refuse_release {
                return Err(BuildError::Invariant("injected release refusal"));
            }
            self.retained = self
                .retained
                .checked_sub(amount)
                .ok_or(BuildError::Invariant("test release underflowed"))?;
            self.releases = build_add(self.releases, 1, "test releases")?;
            Ok(())
        }
    }

    fn pattern(tlds: &[&str]) -> String {
        format!(
            r"((?:(?:(?:https?|ftp)://(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){{3}}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|(?:(?:https?|ftp)://)?(?:[a-z0-9%.]+:[a-z0-9%]+@)?(?:(?:[a-z0-9_~]\-?){{0,62}}[a-z0-9]\.)*(?:(?:(?:[a-z0-9]\-?){{0,62}}[a-z0-9])|(?:xn--[a-z0-9\-]+))\.(?:{}))(?::\d{{2,5}})?(?:/[a-z0-9/\-_%$@&()!?'=~*+:;,.]+)*/?(?:[?#]\S*)*/?)",
            tlds.join("|")
        )
    }

    fn plan(tlds: &[&str]) -> UrlAggregatePlan {
        let mut packed = Vec::new();
        let mut ends = Vec::new();
        for tld in tlds {
            packed.extend_from_slice(tld.as_bytes());
            ends.push(packed.len());
        }
        UrlAggregatePlan::build(&packed, &ends, BuildLimits::default()).unwrap()
    }

    fn check(tlds: &[&str], haystack: &[u8]) -> SpanSumResult {
        let plan = plan(tlds);
        let actual = plan
            .span_sum(haystack, 0..haystack.len(), ReduceLimits::default())
            .unwrap();
        let reference = RegexBuilder::new(&pattern(tlds))
            .unicode(false)
            .case_insensitive(true)
            .build()
            .unwrap();
        let spans = reference.find_iter(haystack).collect::<Vec<_>>();
        assert_eq!(actual.matches, spans.len(), "haystack={haystack:?}");
        assert_eq!(
            actual.value,
            spans
                .iter()
                .map(|span| span.end() - span.start())
                .sum::<usize>(),
            "haystack={haystack:?}"
        );
        actual
    }

    #[test]
    fn adversarial_priority_and_prefix_cases_match_oracle() {
        let tlds = ["EXAMPLECOM", "COM", "CO", "ORG"];
        for haystack in [
            b"!a.com".as_slice(),
            b"https://a.com",
            b"xhttps://a.com",
            b"http://999.999.999.999/a.com",
            b"http://1.2.3.4.com",
            b"http://1.2.3.4x.com",
            b"https://1.2.3.4x.com",
            b"ftp://1.2.3.4x.com",
            b"a.com,b.org",
            b"a.com/b.org?x",
            b"a.comx.com",
            b"a.co.com",
            b"u:p@a.com",
            b"a.b:c@d.com",
            b"https://u:p@a.b.com",
            b"_a.b.com",
            b"a-.b.com",
            b"xxn--a.com xn--a.com",
            b"xn--a.coma.com",
            b"u:p@a.comu:p@a.com",
            b"x.comdef.a.com",
            b"a.com!def.a.com",
            b"A.CoM\tb.ORG\nc.com\x0bd.com\x0ce.com\rf.com",
        ] {
            check(&tlds, haystack);
        }
    }

    #[test]
    fn extension_and_ipv4_context_source_accesses_are_exactly_bounded() {
        let plan = plan(&["COM", "ORG"]);
        for haystack in [
            b"a.b.com".as_slice(),
            b"a.xn--b.com",
            b"a.b.c.com",
            b"http://1.22.255.4",
            b"http://12.3.44.255",
            b"http://255x.example",
        ] {
            let exact = plan
                .span_sum(haystack, 0..haystack.len(), ReduceLimits::default())
                .unwrap();
            assert!(exact.accounting.random_access_bytes > 0);
            let below = ReduceLimits {
                max_random_access_bytes: exact.accounting.random_access_bytes - 1,
                ..ReduceLimits::default()
            };
            assert!(matches!(
                plan.span_sum(haystack, 0..haystack.len(), below),
                Err(ReduceError::Resource {
                    resource: "random access bytes",
                    ..
                })
            ));
        }
    }

    #[test]
    fn input_only_upper_bounds_cover_long_segments_and_scratch_one_below() {
        let plan = plan(&["COM", "ORG"]);
        let mut long = vec![b'a'; 4_096];
        long.extend_from_slice(b".com");
        let upper = UrlAggregatePlan::reduce_upper_bounds(long.len()).unwrap();
        assert_eq!(upper.boundaries, long.len() + 1);
        assert_eq!(upper.candidate_records, upper.boundaries);
        assert_eq!(upper.candidate_record_bytes, size_of::<CandidateRecord>());
        assert_eq!(
            upper.scratch_bytes,
            upper.boundaries * size_of::<CandidateRecord>()
        );
        assert_eq!(upper.random_access_storage_bytes, upper.scratch_bytes);
        assert_eq!(upper.peak_bytes, upper.scratch_bytes);
        assert_eq!(upper.sequential_bytes, long.len() * 3);

        let exact = ReduceLimits {
            max_input_bytes: long.len(),
            max_boundaries: upper.boundaries,
            max_candidates: usize::MAX,
            max_match_events: upper.match_events,
            max_output_matches: upper.output_matches,
            max_span_sum: upper.span_sum,
            max_sequential_bytes: upper.sequential_bytes,
            max_random_access_bytes: usize::MAX,
            max_random_access_storage_bytes: upper.random_access_storage_bytes,
            max_work: usize::MAX,
            max_scratch_bytes: upper.scratch_bytes,
            max_peak_bytes: upper.peak_bytes,
        };
        let result = plan.span_sum(&long, 0..long.len(), exact).unwrap();
        assert_eq!(result.accounting.scratch_bytes, upper.scratch_bytes);
        assert_eq!(
            result.accounting.random_access_storage_bytes,
            upper.random_access_storage_bytes
        );
        assert_eq!(result.accounting.peak_bytes, upper.peak_bytes);
        assert_eq!(result.accounting.sequential_bytes, upper.sequential_bytes);
        assert!(result.matches <= upper.match_events);
        assert!(result.value <= upper.span_sum);

        assert!(matches!(
            plan.span_sum(
                &long,
                0..long.len(),
                ReduceLimits {
                    max_scratch_bytes: upper.scratch_bytes - 1,
                    ..exact
                }
            ),
            Err(ReduceError::Resource {
                resource: "scratch bytes",
                needed,
                limit,
            }) if needed == upper.scratch_bytes && limit == upper.scratch_bytes - 1
        ));

        for separated in [b"".as_slice(), b" \t\n", b"a.com b.org"] {
            let separated_upper = UrlAggregatePlan::reduce_upper_bounds(separated.len()).unwrap();
            let observed = plan
                .span_sum(separated, 0..separated.len(), ReduceLimits::default())
                .unwrap()
                .accounting;
            assert!(observed.scratch_bytes <= separated_upper.scratch_bytes);
            assert!(
                observed.random_access_storage_bytes <= separated_upper.random_access_storage_bytes
            );
            assert!(observed.peak_bytes <= separated_upper.peak_bytes);
            assert!(observed.sequential_bytes <= separated_upper.sequential_bytes);
            assert!(observed.matches <= separated_upper.output_matches);
            assert!(observed.span_sum <= separated_upper.span_sum);
        }

        assert!(matches!(
            UrlAggregatePlan::reduce_upper_bounds(usize::MAX),
            Err(ReduceError::Overflow("boundaries"))
        ));
        assert!(matches!(
            UrlAggregatePlan::reduce_upper_bounds(usize::MAX / 3 + 1),
            Err(ReduceError::Overflow(
                "candidate record bytes" | "sequential bytes"
            ))
        ));
    }

    #[test]
    fn exact_observed_limits_fail_one_below() {
        let plan = plan(&["EXAMPLECOM", "COM", "CO"]);
        let haystack = b"https://u:p@a.examplecom/path?q a.co http://1.2.3.4.com";
        let exact = plan
            .span_sum(haystack, 0..haystack.len(), ReduceLimits::default())
            .unwrap();
        let limits = ReduceLimits {
            max_input_bytes: haystack.len(),
            max_boundaries: haystack.len() + 1,
            max_candidates: exact
                .accounting
                .candidate_insertions
                .max(exact.accounting.candidate_visits),
            max_match_events: exact.matches,
            max_output_matches: exact.matches,
            max_span_sum: exact.value,
            max_sequential_bytes: exact.accounting.sequential_bytes,
            max_random_access_bytes: exact.accounting.random_access_bytes,
            max_random_access_storage_bytes: exact.accounting.random_access_storage_bytes,
            max_work: exact.accounting.work,
            max_scratch_bytes: exact.accounting.scratch_bytes,
            max_peak_bytes: exact.accounting.peak_bytes,
        };
        assert_eq!(
            plan.span_sum(haystack, 0..haystack.len(), limits).unwrap(),
            exact
        );
        for below in [
            ReduceLimits {
                max_work: limits.max_work - 1,
                ..limits
            },
            ReduceLimits {
                max_sequential_bytes: limits.max_sequential_bytes - 1,
                ..limits
            },
            ReduceLimits {
                max_random_access_bytes: limits.max_random_access_bytes - 1,
                ..limits
            },
            ReduceLimits {
                max_random_access_storage_bytes: limits.max_random_access_storage_bytes - 1,
                ..limits
            },
            ReduceLimits {
                max_scratch_bytes: limits.max_scratch_bytes - 1,
                ..limits
            },
            ReduceLimits {
                max_peak_bytes: limits.max_peak_bytes - 1,
                ..limits
            },
            ReduceLimits {
                max_span_sum: limits.max_span_sum - 1,
                ..limits
            },
            ReduceLimits {
                max_match_events: limits.max_match_events - 1,
                ..limits
            },
            ReduceLimits {
                max_output_matches: limits.max_output_matches - 1,
                ..limits
            },
        ] {
            assert!(matches!(
                plan.span_sum(haystack, 0..haystack.len(), below),
                Err(ReduceError::Resource { .. })
            ));
        }
    }

    #[test]
    fn terminal_attempt_retains_reads_and_committed_workspace_allocation() {
        let plan = plan(&["COM"]);
        let haystack = b"a.com";
        // The first census costs one work unit per byte, allocator
        // bookkeeping costs two, and this ceiling admits exactly one record
        // initialization before the next one refuses.
        let limits = ReduceLimits {
            max_work: haystack.len() + 3,
            ..ReduceLimits::default()
        };
        let legacy = plan
            .span_sum(haystack, 0..haystack.len(), limits)
            .expect_err("record initialization must hit the work ceiling");
        let failure = plan
            .span_sum_attempt(haystack, 0..haystack.len(), limits)
            .expect_err("audited attempt must preserve the same refusal");
        assert_eq!(failure.source, legacy);
        assert_eq!(failure.actual_allocations, 1);
        assert_eq!(failure.accounting.sequential_bytes, haystack.len());
        assert!(failure.accounting.work > haystack.len());
        assert!(failure.accounting.scratch_bytes > 0);
        assert_eq!(
            failure.accounting.random_access_storage_bytes,
            failure.accounting.scratch_bytes
        );
        assert_eq!(
            failure.accounting.peak_bytes,
            failure.accounting.scratch_bytes
        );
    }

    #[test]
    fn build_rejects_priority_conflict_and_duplicates() {
        assert!(matches!(
            UrlAggregatePlan::build(b"COCOM", &[2, 5], BuildLimits::default()),
            Err(BuildError::PriorityConflict { .. })
        ));
        assert!(matches!(
            UrlAggregatePlan::build(b"COMcom", &[3, 6], BuildLimits::default()),
            Err(BuildError::DuplicateTld { .. })
        ));
    }

    #[test]
    fn external_build_authority_is_transactional_and_limit_precedes_action() {
        let limits = BuildLimits::default();
        let successful = UrlAggregatePlan::build(b"EXAMPLECOMORG", &[10, 13], limits).unwrap();
        let exact_work = successful.build_accounting().work;
        let persistent = successful.build_accounting().persistent_bytes;

        let mut refused = TestAuthority {
            retained: 17,
            refuse_retain: true,
            ..TestAuthority::default()
        };
        assert!(matches!(
            UrlAggregatePlan::build_with_authority(
                b"EXAMPLECOMORG",
                &[10, 13],
                limits,
                &mut refused
            ),
            Err(BuildError::Invariant("injected reservation refusal"))
        ));
        assert_eq!(refused.retained, 17);
        assert_eq!(refused.releases, 0);

        let mut rolled_back = TestAuthority {
            retained: 19,
            refuse_post_retain_work: true,
            ..TestAuthority::default()
        };
        assert!(matches!(
            UrlAggregatePlan::build_with_authority(
                b"EXAMPLECOMORG",
                &[10, 13],
                limits,
                &mut rolled_back
            ),
            Err(BuildError::Invariant(
                "injected post-reservation work refusal"
            ))
        ));
        assert_eq!(rolled_back.retained, 19);
        assert_eq!(rolled_back.releases, 1);

        let mut release_failed = TestAuthority {
            retained: 23,
            refuse_post_retain_work: true,
            refuse_release: true,
            ..TestAuthority::default()
        };
        assert!(matches!(
            UrlAggregatePlan::build_with_authority(
                b"EXAMPLECOMORG",
                &[10, 13],
                limits,
                &mut release_failed
            ),
            Err(BuildError::Invariant("injected release refusal"))
        ));
        assert_eq!(release_failed.retained, 23 + persistent);
        assert_eq!(release_failed.releases, 0);

        let one_below = BuildLimits {
            max_work: exact_work - 1,
            ..limits
        };
        let mut bounded = TestAuthority::default();
        let Err(BuildError::Resource {
            resource: "work",
            needed,
            limit,
        }) = UrlAggregatePlan::build_with_authority(
            b"EXAMPLECOMORG",
            &[10, 13],
            one_below,
            &mut bounded,
        )
        else {
            panic!("one-below work limit did not refuse before the triggering action");
        };
        assert_eq!(limit, exact_work - 1);
        assert!(needed > limit);
        assert!(bounded.work <= limit);
        assert_eq!(bounded.retained, 0);
    }

    #[test]
    fn allocation_and_deallocation_actions_are_prepaid() {
        allocation_probe::reset_build();
        let mut authority = TestAuthority::default();
        let plan = UrlAggregatePlan::build_with_authority(
            b"COMORG",
            &[3, 6],
            BuildLimits::default(),
            &mut authority,
        )
        .unwrap();
        assert_eq!(allocation_probe::build_calls(), 2);
        let preallocation_work = authority.work_at_reservation;
        allocation_probe::reset_build();
        assert!(matches!(
            UrlAggregatePlan::build(
                b"COMORG",
                &[3, 6],
                BuildLimits {
                    max_work: preallocation_work - 1,
                    ..BuildLimits::default()
                }
            ),
            Err(BuildError::Resource {
                resource: "work",
                ..
            })
        ));
        assert_eq!(allocation_probe::build_calls(), 0);

        allocation_probe::reset_reduce();
        assert!(matches!(
            plan.span_sum(
                b"",
                0..0,
                ReduceLimits {
                    max_work: 1,
                    ..ReduceLimits::default()
                }
            ),
            Err(ReduceError::Resource {
                resource: "work",
                ..
            })
        ));
        assert_eq!(allocation_probe::reduce_calls(), 0);
        assert!(matches!(
            plan.span_sum(
                b"",
                0..0,
                ReduceLimits {
                    max_work: 2,
                    ..ReduceLimits::default()
                }
            ),
            Err(ReduceError::Resource {
                resource: "work",
                ..
            })
        ));
        assert_eq!(allocation_probe::reduce_calls(), 1);
    }

    #[test]
    #[ignore = "authenticated external Rebar URL canary"]
    fn authenticated_rebar_url_span_sum() {
        const REBAR: &str =
            "/private/tmp/fre-control/grapheme-source-code-88ee1806-current-row-canary-r1/rebar";
        let source =
            fs::read_to_string(format!("{REBAR}/benchmarks/regexes/wild/url.txt")).unwrap();
        let source = source.trim_end();
        let start = source.find(r")\.(?:").unwrap() + r")\.(?:".len();
        let end = source[start..].find(r"))(?::\d{2,5})?").unwrap() + start;
        let tlds = source[start..end].split('|').collect::<Vec<_>>();
        assert_eq!(tlds.len(), 1_498);
        let plan = plan(&tlds);
        let haystack = fs::read(format!(
            "{REBAR}/benchmarks/haystacks/rust-src-tools-3b0d4813.txt"
        ))
        .unwrap();
        let actual = plan
            .span_sum(&haystack, 0..haystack.len(), ReduceLimits::default())
            .unwrap();
        eprintln!(
            "URL authenticated result={actual:?} build={:?}",
            plan.build_accounting()
        );
        assert_eq!(actual.value, 234_965);
        assert!(actual.accounting.work < 429_496_730);
    }
}
