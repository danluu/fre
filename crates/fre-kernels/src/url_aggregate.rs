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
    pub max_matches: usize,
    pub max_span_sum: usize,
    pub max_sequential_bytes: usize,
    pub max_random_access_bytes: usize,
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
            max_matches: 1 << 20,
            max_span_sum: usize::MAX,
            max_sequential_bytes: 512 << 20,
            max_random_access_bytes: 512 << 20,
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
    pub work: usize,
    pub scratch_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanSumResult {
    pub value: usize,
    pub matches: usize,
    pub accounting: ReduceAccounting,
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

impl UrlAggregatePlan {
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
    pub fn build(tlds: Vec<&[u8]>, limits: BuildLimits) -> Result<Self, BuildError> {
        if tlds.is_empty() {
            return Err(BuildError::EmptyLanguage);
        }
        build_enforce("TLDs", tlds.len(), limits.max_tlds)?;
        let tld_count = tlds.len();
        let mut meter = BuildMeter::new(limits.max_work);
        meter.charge(tlds.len())?;
        let mut tld_bytes = 0_usize;
        let mut max_tld_bytes = 0_usize;
        for (index, tld) in tlds.iter().enumerate() {
            meter.charge(1)?;
            if tld.is_empty() {
                return Err(BuildError::EmptyTld { index });
            }
            if !(2..=MAX_TLD_BYTES).contains(&tld.len()) {
                return Err(BuildError::TldLength {
                    index,
                    length: tld.len(),
                });
            }
            tld_bytes = build_add(tld_bytes, tld.len(), "TLD bytes")?;
            build_enforce("TLD bytes", tld_bytes, limits.max_tld_bytes)?;
            max_tld_bytes = max_tld_bytes.max(tld.len());
            for (offset, &byte) in tld.iter().enumerate() {
                meter.charge(1)?;
                if alphabet(byte.to_ascii_lowercase()).is_none() {
                    return Err(BuildError::InvalidTld { index, offset });
                }
            }
        }

        let mut priority_comparisons = 0_usize;
        for first in 0..tlds.len() {
            for second in first + 1..tlds.len() {
                meter.charge(1)?;
                let compared = tlds[first].len().min(tlds[second].len());
                let mut equal_prefix = true;
                for (&left, &right) in tlds[first].iter().zip(tlds[second]).take(compared) {
                    meter.charge(1)?;
                    priority_comparisons =
                        build_add(priority_comparisons, 1, "priority comparisons")?;
                    if !left.eq_ignore_ascii_case(&right) {
                        equal_prefix = false;
                        break;
                    }
                }
                if equal_prefix && tlds[first].len() == tlds[second].len() {
                    return Err(BuildError::DuplicateTld { first, second });
                }
                if equal_prefix && tlds[first].len() < tlds[second].len() {
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

        meter.charge(build_add(
            table_cells,
            states_upper_bound,
            "initialization work",
        )?)?;
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
        for tld in tlds {
            let mut state = 0_usize;
            for source in tld {
                meter.charge(4)?; // fold, alphabet map, lookup/branch, selected-state write
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
            meter.charge(1)?;
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
                initialized_cells: build_add(table_cells, states_upper_bound, "initialized cells")?,
                priority_comparisons,
                trie_transitions,
                work: meter.work,
                persistent_bytes,
                scratch_bytes: 0,
                peak_bytes: persistent_bytes,
            },
        })
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
        if range.start > range.end || range.end > haystack.len() {
            return Err(ReduceError::InvalidRange {
                start: range.start,
                end: range.end,
                haystack_len: haystack.len(),
            });
        }
        let input_bytes = range.end - range.start;
        reduce_enforce("input bytes", input_bytes, limits.max_input_bytes)?;
        let boundaries = reduce_add(input_bytes, 1, "boundaries")?;
        reduce_enforce("boundaries", boundaries, limits.max_boundaries)?;
        let mut meter = Meter::new(limits, input_bytes, boundaries);

        // First pass determines the one exact reusable per-segment workspace.
        let mut segment_bytes = 0_usize;
        let mut segment_peak = 0_usize;
        for &byte in &haystack[range.clone()] {
            meter.sequential(1)?;
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
        reduce_enforce("scratch bytes", scratch_bytes, limits.max_scratch_bytes)?;
        let peak_bytes = reduce_add(scratch_bytes, self.build.persistent_bytes, "peak bytes")?;
        reduce_enforce("peak bytes", peak_bytes, limits.max_peak_bytes)?;
        let mut records = exact_reduce_vec(record_count, "candidate records")?;
        for _ in 0..record_count {
            meter.work(1)?;
            records.try_push(CandidateRecord::EMPTY).map_err(|_| {
                ReduceError::Invariant("candidate initialization exceeded exact capacity")
            })?;
        }
        meter.accounting.scratch_bytes = scratch_bytes;
        meter.accounting.peak_bytes = peak_bytes;

        let mut cursor = range.start;
        let mut segment_start = range.start;
        let mut position = range.start;
        while position <= range.end {
            let at_end = position == range.end;
            if !at_end {
                meter.sequential(1)?;
            }
            if at_end || is_delimiter(haystack[position]) {
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
            meter.sequential(1)?;
            let byte = haystack[position];
            if byte == b'.' {
                meter.accounting.dot_probes =
                    reduce_add(meter.accounting.dot_probes, 1, "dot probes")?;
                if let Some(tld_end) = self.longest_tld(haystack, position + 1, end, meter)? {
                    meter.accounting.tld_candidates =
                        reduce_add(meter.accounting.tld_candidates, 1, "TLD candidates")?;
                    if let Some(prefix_start) =
                        domain_prefix_start(haystack, start, position, meter)?
                    {
                        let record = &mut records[prefix_start - start];
                        meter.work(2)?; // record lookup and max publication
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
                    }
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
            reduce_enforce("matches", matches, meter.limits.max_matches)?;
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
        for (relative, &source) in haystack[start..limit].iter().enumerate() {
            let position = start + relative;
            meter.random(1)?;
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

fn domain_prefix_start(
    source: &[u8],
    segment: usize,
    dot: usize,
    meter: &mut Meter,
) -> Result<Option<usize>, ReduceError> {
    let regular = regular_suffix(source, segment, dot, false, meter)?;
    let xn = xn_suffix(source, segment, dot, meter)?;
    let Some(mut start) = min_option(regular, xn) else {
        return Ok(None);
    };
    while start > segment {
        meter.random(1)?;
        meter.accounting.prefix_steps =
            reduce_add(meter.accounting.prefix_steps, 1, "prefix steps")?;
        if source[start - 1] != b'.' {
            break;
        }
        let Some(previous) = regular_suffix(source, segment, start - 1, true, meter)? else {
            break;
        };
        start = previous;
    }

    // Optional auth has an unambiguous reverse parse because ':' and '@' are
    // excluded from both nonempty auth fields.
    if start > segment {
        meter.random(1)?;
        if source[start - 1] == b'@' {
            let at = start - 1;
            let mut password = at;
            while password > segment {
                meter.random(1)?;
                meter.accounting.prefix_steps =
                    reduce_add(meter.accounting.prefix_steps, 1, "prefix steps")?;
                if !is_password(source[password - 1]) {
                    break;
                }
                password -= 1;
            }
            if password < at && password > segment && source[password - 1] == b':' {
                let colon = password - 1;
                let mut user = colon;
                while user > segment {
                    meter.random(1)?;
                    meter.accounting.prefix_steps =
                        reduce_add(meter.accounting.prefix_steps, 1, "prefix steps")?;
                    if !is_user(source[user - 1]) {
                        break;
                    }
                    user -= 1;
                }
                if user < colon {
                    start = user;
                }
            }
        }
    }

    for scheme in [
        b"https://".as_slice(),
        b"http://".as_slice(),
        b"ftp://".as_slice(),
    ] {
        meter.work(1)?;
        if start - segment >= scheme.len()
            && folded_equal(source, start - scheme.len(), scheme, meter)?
        {
            start -= scheme.len();
            break;
        }
    }
    Ok(Some(start))
}

fn regular_suffix(
    source: &[u8],
    segment: usize,
    end: usize,
    subdomain: bool,
    meter: &mut Meter,
) -> Result<Option<usize>, ReduceError> {
    if end <= segment {
        return Ok(None);
    }
    meter.random(1)?;
    if !is_alnum(source[end - 1]) {
        return Ok(None);
    }
    let mut position = end - 1;
    for _ in 0..LABEL_REPETITIONS {
        if position >= segment + 2 {
            meter.random(2)?;
            meter.accounting.prefix_steps =
                reduce_add(meter.accounting.prefix_steps, 1, "prefix steps")?;
            if source[position - 1] == b'-' && is_label_atom(source[position - 2], subdomain) {
                position -= 2;
                continue;
            }
        }
        if position > segment {
            meter.random(1)?;
            meter.accounting.prefix_steps =
                reduce_add(meter.accounting.prefix_steps, 1, "prefix steps")?;
            if is_label_atom(source[position - 1], subdomain) {
                position -= 1;
                continue;
            }
        }
        break;
    }
    Ok(Some(position))
}

fn xn_suffix(
    source: &[u8],
    segment: usize,
    end: usize,
    meter: &mut Meter,
) -> Result<Option<usize>, ReduceError> {
    let mut lower = end;
    while lower > segment {
        meter.random(1)?;
        meter.accounting.prefix_steps =
            reduce_add(meter.accounting.prefix_steps, 1, "prefix steps")?;
        if !is_xn_body(source[lower - 1]) {
            break;
        }
        lower -= 1;
    }
    let mut candidate = lower;
    while candidate + 5 <= end {
        meter.work(1)?;
        if folded_equal(source, candidate, b"xn--", meter)? {
            return Ok(Some(candidate));
        }
        candidate += 1;
    }
    Ok(None)
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
    let context = |candidate: usize| !require_dot || (candidate < end && source[candidate] == b'.');
    if start + 3 <= end {
        meter.random(3)?;
        if source[start] == b'2'
            && source[start + 1] == b'5'
            && matches!(source[start + 2], b'0'..=b'5')
            && context(start + 3)
        {
            return Ok(Some(start + 3));
        }
        meter.random(3)?;
        if source[start] == b'2'
            && matches!(source[start + 1], b'0'..=b'4')
            && source[start + 2].is_ascii_digit()
            && context(start + 3)
        {
            return Ok(Some(start + 3));
        }
    }
    for length in [3_usize, 2, 1] {
        if start + length > end {
            continue;
        }
        meter.random(length)?;
        let digits = source[start..start + length].iter().all(u8::is_ascii_digit);
        let represented = length < 3 || matches!(source[start], b'0' | b'1');
        if digits && represented && context(start + length) {
            return Ok(Some(start + length));
        }
    }
    Ok(None)
}

fn suffix_end(
    source: &[u8],
    mut position: usize,
    end: usize,
    meter: &mut Meter,
) -> Result<usize, ReduceError> {
    if position < end {
        meter.random(1)?;
    }
    if position < end && source[position] == b':' {
        let first = position + 1;
        let mut digits = first;
        while digits < end && digits - first < 5 {
            meter.random(1)?;
            meter.accounting.suffix_steps =
                reduce_add(meter.accounting.suffix_steps, 1, "suffix steps")?;
            if !source[digits].is_ascii_digit() {
                break;
            }
            digits += 1;
        }
        if digits - first >= 2 {
            position = digits;
        }
    }
    if position < end {
        meter.random(1)?;
    }
    if position < end && source[position] == b'/' {
        position += 1;
        while position < end {
            meter.random(1)?;
            meter.accounting.suffix_steps =
                reduce_add(meter.accounting.suffix_steps, 1, "suffix steps")?;
            if !is_path(source[position]) {
                break;
            }
            position += 1;
        }
    }
    if position < end {
        meter.random(1)?;
    }
    if position < end && matches!(source[position], b'?' | b'#') {
        // The segment was split on the exact complement of `\S`, so the
        // greedy non-space tail consumes the complete remainder.
        let tail = end - position;
        meter.random(tail)?;
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
        meter.random(1)?;
        meter.accounting.prefix_steps =
            reduce_add(meter.accounting.prefix_steps, 1, "prefix steps")?;
        if !source[start + offset].eq_ignore_ascii_case(&right) {
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

const fn min_option(left: Option<usize>, right: Option<usize>) -> Option<usize> {
    match (left, right) {
        (Some(left), Some(right)) => Some(if left < right { left } else { right }),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

#[derive(Debug)]
struct BuildMeter {
    limit: usize,
    work: usize,
}

impl BuildMeter {
    const fn new(limit: usize) -> Self {
        Self { limit, work: 0 }
    }

    fn charge(&mut self, amount: usize) -> Result<(), BuildError> {
        self.work = build_add(self.work, amount, "work")?;
        build_enforce("work", self.work, self.limit)
    }
}

fn exact_build_vec<T>(capacity: usize, resource: &'static str) -> Result<ExactVec<T>, BuildError> {
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
    ExactVec::try_with_capacity(capacity).map_err(|error| match error {
        CopyError::LayoutOverflow => ReduceError::Overflow(resource),
        CopyError::AllocationFailed => ReduceError::Allocation {
            resource,
            items: capacity,
        },
    })
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

    fn pattern(tlds: &[&str]) -> String {
        format!(
            r"((?:(?:(?:https?|ftp)://(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){{3}}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|(?:(?:https?|ftp)://)?(?:[a-z0-9%.]+:[a-z0-9%]+@)?(?:(?:[a-z0-9_~]\-?){{0,62}}[a-z0-9]\.)*(?:(?:(?:[a-z0-9]\-?){{0,62}}[a-z0-9])|(?:xn--[a-z0-9\-]+))\.(?:{}))(?::\d{{2,5}})?(?:/[a-z0-9/\-_%$@&()!?'=~*+:;,.]+)*/?(?:[?#]\S*)*/?)",
            tlds.join("|")
        )
    }

    fn plan(tlds: &[&str]) -> UrlAggregatePlan {
        UrlAggregatePlan::build(
            tlds.iter().map(|tld| tld.as_bytes()).collect(),
            BuildLimits::default(),
        )
        .unwrap()
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
            b"A.CoM\tb.ORG\nc.com\x0bd.com\x0ce.com\rf.com",
        ] {
            check(&tlds, haystack);
        }
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
            max_candidates: exact.accounting.candidate_visits,
            max_matches: exact.matches,
            max_span_sum: exact.value,
            max_sequential_bytes: exact.accounting.sequential_bytes,
            max_random_access_bytes: exact.accounting.random_access_bytes,
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
        ] {
            assert!(matches!(
                plan.span_sum(haystack, 0..haystack.len(), below),
                Err(ReduceError::Resource { .. })
            ));
        }
    }

    #[test]
    fn build_rejects_priority_conflict_and_duplicates() {
        assert!(matches!(
            UrlAggregatePlan::build(vec![b"CO", b"COM"], BuildLimits::default()),
            Err(BuildError::PriorityConflict { .. })
        ));
        assert!(matches!(
            UrlAggregatePlan::build(vec![b"COM", b"com"], BuildLimits::default()),
            Err(BuildError::DuplicateTld { .. })
        ));
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
