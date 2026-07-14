//! Bounded adapters and comparison orchestration.

use fre_automata::{
    Automaton, CompileLimits, EdgeKind, Exists, RawPlan, ResourceKind, SearchError, SearchLimits,
    SearchWindow, SelectedEnd, Span, StateRole,
};
use fre_reference::{Ast as ReferenceAst, Limits as ReferenceLimits, ReferenceRegex};

use crate::{
    Agreement, ByteRange, CanonicalSpan, CaseAst, CaseLimits, EngineRecord, Greed, Outcome,
    RefusalKind, SearchRecord, UnsupportedFeature,
};

/// Complete, reproducible input to one comparison.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceCase {
    pub id: String,
    pub seed: u64,
    pub ordinal: u64,
    pub ast: CaseAst,
    pub haystack: Vec<u8>,
    pub window_start: usize,
    pub window_end: usize,
}

impl ConformanceCase {
    /// A full-haystack query with stable reproduction metadata.
    #[must_use]
    pub fn full(
        id: impl Into<String>,
        seed: u64,
        ordinal: u64,
        ast: CaseAst,
        haystack: Vec<u8>,
    ) -> Self {
        let window_end = haystack.len();
        Self {
            id: id.into(),
            seed,
            ordinal,
            ast,
            haystack,
            window_start: 0,
            window_end,
        }
    }
}

/// Hard bounds for every phase of one comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HarnessLimits {
    pub cases: CaseLimits,
    pub max_cases: u64,
    pub max_haystack_bytes: usize,
    pub max_plan_states: usize,
    pub max_plan_edges: usize,
    pub max_repeat_copies: u32,
    /// Hard work budget passed to each independent search call.
    pub max_search_work_per_search: u64,
    /// Conservative cap across all oracle and production search calls in one
    /// comparison.
    pub max_total_search_work: u64,
    pub max_scratch_bytes: usize,
    pub max_results: usize,
}

impl Default for HarnessLimits {
    fn default() -> Self {
        Self {
            cases: CaseLimits::default(),
            max_cases: 100_000,
            max_haystack_bytes: 64,
            max_plan_states: 4_096,
            max_plan_edges: 16_384,
            max_repeat_copies: 64,
            max_search_work_per_search: 10_000_000,
            max_total_search_work: 3_000_000_000,
            max_scratch_bytes: 8 * 1024 * 1024,
            max_results: 128,
        }
    }
}

/// Deterministic conformance runner.
#[derive(Clone, Copy, Debug)]
pub struct Harness {
    limits: HarnessLimits,
}

impl Harness {
    #[must_use]
    pub const fn new(limits: HarnessLimits) -> Self {
        Self { limits }
    }

    /// Compare the independent direct-AST oracle with the direct K0 automata
    /// adapter. A non-value outcome is always `NotComparable`, never a pass.
    #[must_use]
    pub fn compare(&self, case: &ConformanceCase) -> EngineRecord {
        let early = self.preflight(case);
        let (oracle, production) = if let Some(outcome) = early {
            let record = uniform_record(&outcome);
            (record.clone(), record)
        } else {
            (self.run_reference(case), self.run_production(case))
        };
        let agreement = compare_records(&oracle, &production);
        EngineRecord {
            case_id: case.id.clone(),
            seed: case.seed,
            ordinal: case.ordinal,
            haystack: case.haystack.clone(),
            window_start: case.window_start,
            window_end: case.window_end,
            oracle,
            production,
            agreement,
        }
    }

    fn preflight(&self, case: &ConformanceCase) -> Option<Outcome<()>> {
        if case.ordinal >= self.limits.max_cases {
            return Some(Outcome::Refused(RefusalKind::Cases));
        }
        if case.haystack.len() > self.limits.max_haystack_bytes {
            return Some(Outcome::Refused(RefusalKind::HaystackBytes));
        }
        if case.window_start > case.window_end || case.window_end > case.haystack.len() {
            return Some(Outcome::Fault("invalid search window".to_owned()));
        }
        let boundaries = case
            .window_end
            .checked_sub(case.window_start)
            .and_then(|length| length.checked_add(1));
        let global_calls = boundaries
            .and_then(|value| value.checked_mul(2))
            .and_then(|value| value.checked_add(1));
        // One reference first-result call, three typed production calls, and
        // two repeated-search adapters whose calls are bounded by `global_calls`.
        let total_calls = global_calls
            .and_then(|value| value.checked_mul(2))
            .and_then(|value| value.checked_add(4));
        let total_work = total_calls.and_then(|calls| {
            u64::try_from(calls)
                .ok()
                .and_then(|calls| calls.checked_mul(self.limits.max_search_work_per_search))
        });
        let Some(total_work) = total_work else {
            return Some(Outcome::Refused(RefusalKind::Arithmetic));
        };
        if total_work > self.limits.max_total_search_work {
            return Some(Outcome::Refused(RefusalKind::SearchWork));
        }
        validate_ast(&case.ast, self.limits.cases, self.limits.max_repeat_copies).err()
    }

    fn run_reference(&self, case: &ConformanceCase) -> SearchRecord {
        if case.window_end != case.haystack.len() {
            return uniform_record(&Outcome::<()>::Unsupported(
                UnsupportedFeature::TruncatedReferenceWindow,
            ));
        }
        let ast = to_reference(&case.ast);
        let limits = ReferenceLimits {
            max_ast_nodes: self.limits.cases.max_ast_nodes,
            max_ast_depth: self.limits.cases.max_ast_depth,
            max_capture_index: 0,
            max_steps: self.limits.max_search_work_per_search,
            max_results: self.limits.max_results,
        };
        let regex = match ReferenceRegex::new(ast, limits) {
            Ok(regex) => regex,
            Err(error) => return uniform_record(&reference_error::<()>(&error)),
        };
        let first = match regex.find_at(&case.haystack, case.window_start) {
            Ok(found) => {
                found.map(|matched| CanonicalSpan::new(matched.span.start, matched.span.end))
            }
            Err(error) => return uniform_record(&reference_error::<()>(&error)),
        };
        let global = reference_global(
            &regex,
            &case.haystack,
            case.window_start,
            self.limits.max_results,
        );
        SearchRecord {
            exists: Outcome::Value(first.is_some()),
            selected_end: Outcome::Value(first.map(|span| span.end)),
            span: Outcome::Value(first),
            global,
        }
    }

    fn run_production(&self, case: &ConformanceCase) -> SearchRecord {
        if has_nullable_unbounded_repeat(&case.ast) {
            return uniform_record(&Outcome::<()>::Unsupported(
                UnsupportedFeature::NullableUnboundedRepeat,
            ));
        }
        let automaton = match compile_automaton(&case.ast, self.limits) {
            Ok(automaton) => automaton,
            Err(outcome) => return uniform_record(&outcome),
        };
        let limits = SearchLimits {
            max_work: self.limits.max_search_work_per_search,
            max_scratch_bytes: self.limits.max_scratch_bytes,
        };
        let window = SearchWindow::new(case.window_start, case.window_end);
        let exists = map_search(
            automaton
                .prepare::<Exists>()
                .search_window(&case.haystack, window, limits)
                .map(fre_automata::SearchReport::into_output),
        );
        let selected_end = map_search(
            automaton
                .prepare::<SelectedEnd>()
                .search_window(&case.haystack, window, limits)
                .map(fre_automata::SearchReport::into_output),
        );
        let span = map_search(
            automaton
                .prepare::<Span>()
                .search_window(&case.haystack, window, limits)
                .map(|report| {
                    report
                        .into_output()
                        .map(|value| CanonicalSpan::new(value.start(), value.end()))
                }),
        );
        let global = production_global(
            &automaton,
            &case.haystack,
            window,
            limits,
            self.limits.max_results,
        );
        SearchRecord {
            exists,
            selected_end,
            span,
            global,
        }
    }
}

fn compare_records(left: &SearchRecord, right: &SearchRecord) -> Agreement {
    if record_is_complete(left) && record_is_complete(right) {
        if left == right {
            Agreement::Equal
        } else {
            Agreement::Mismatch
        }
    } else {
        Agreement::NotComparable
    }
}

fn record_is_complete(record: &SearchRecord) -> bool {
    matches!(record.exists, Outcome::Value(_))
        && matches!(record.selected_end, Outcome::Value(_))
        && matches!(record.span, Outcome::Value(_))
        && matches!(record.global, Outcome::Value(_))
}

fn uniform_record<T>(outcome: &Outcome<T>) -> SearchRecord {
    SearchRecord {
        exists: copy_non_value(outcome),
        selected_end: copy_non_value(outcome),
        span: copy_non_value(outcome),
        global: copy_non_value(outcome),
    }
}

fn copy_non_value<T, U>(outcome: &Outcome<T>) -> Outcome<U> {
    match outcome {
        Outcome::Value(_) => Outcome::Fault("invalid uniform value".to_owned()),
        Outcome::Unsupported(feature) => Outcome::Unsupported(*feature),
        Outcome::Refused(kind) => Outcome::Refused(*kind),
        Outcome::Fault(message) => Outcome::Fault(message.clone()),
    }
}

fn validate_ast(
    ast: &CaseAst,
    limits: CaseLimits,
    max_repeat_copies: u32,
) -> Result<(), Outcome<()>> {
    let mut stack = vec![(ast, 1_usize)];
    let mut nodes = 0_usize;
    while let Some((node, depth)) = stack.pop() {
        nodes = nodes
            .checked_add(1)
            .ok_or(Outcome::Refused(RefusalKind::Arithmetic))?;
        if nodes > limits.max_ast_nodes {
            return Err(Outcome::Refused(RefusalKind::AstNodes));
        }
        if depth > limits.max_ast_depth {
            return Err(Outcome::Refused(RefusalKind::AstDepth));
        }
        let child_depth = depth
            .checked_add(1)
            .ok_or(Outcome::Refused(RefusalKind::Arithmetic))?;
        match node {
            CaseAst::Empty | CaseAst::Byte(_) | CaseAst::StartText | CaseAst::EndText => {}
            CaseAst::Class(ranges) => {
                if ranges.is_empty() || ranges.iter().any(|range| range.start > range.end) {
                    return Err(Outcome::Fault("invalid byte class".to_owned()));
                }
            }
            CaseAst::Concat(children) => {
                stack.extend(children.iter().map(|child| (child, child_depth)));
            }
            CaseAst::Alt(children) => {
                if children.is_empty() {
                    return Err(Outcome::Fault("empty alternation".to_owned()));
                }
                stack.extend(children.iter().map(|child| (child, child_depth)));
            }
            CaseAst::Repeat {
                child, min, max, ..
            } => {
                if max.is_some_and(|maximum| maximum < *min) {
                    return Err(Outcome::Fault("repeat maximum below minimum".to_owned()));
                }
                if *min > max_repeat_copies || max.is_some_and(|value| value > max_repeat_copies) {
                    return Err(Outcome::Refused(RefusalKind::PlanStates));
                }
                stack.push((child, child_depth));
            }
        }
    }
    Ok(())
}

fn to_reference(ast: &CaseAst) -> ReferenceAst {
    match ast {
        CaseAst::Empty => ReferenceAst::Empty,
        CaseAst::Byte(byte) => ReferenceAst::Byte(*byte),
        CaseAst::Class(ranges) => ReferenceAst::Class(
            ranges
                .iter()
                .map(|range| {
                    fre_reference::ByteRange::new(range.start, range.end).expect("validated")
                })
                .collect(),
        ),
        CaseAst::Concat(children) => {
            ReferenceAst::Concat(children.iter().map(to_reference).collect())
        }
        CaseAst::Alt(children) => ReferenceAst::Alt(children.iter().map(to_reference).collect()),
        CaseAst::Repeat {
            child,
            min,
            max,
            greed,
        } => ReferenceAst::Repeat {
            child: Box::new(to_reference(child)),
            min: *min,
            max: *max,
            greed: match greed {
                Greed::Greedy => fre_reference::Greed::Greedy,
                Greed::Lazy => fre_reference::Greed::Lazy,
            },
        },
        CaseAst::StartText => ReferenceAst::StartText,
        CaseAst::EndText => ReferenceAst::EndText,
    }
}

fn reference_global(
    regex: &ReferenceRegex,
    haystack: &[u8],
    start: usize,
    max_results: usize,
) -> Outcome<Vec<CanonicalSpan>> {
    let mut at = start;
    let mut previous_end = None;
    let mut matches = Vec::new();
    loop {
        let found = match regex.find_at(haystack, at) {
            Ok(value) => value,
            Err(error) => return reference_error(&error),
        };
        let Some(found) = found else { break };
        let span = CanonicalSpan::new(found.span.start, found.span.end);
        if span.is_empty() && previous_end == Some(span.start) {
            let Some(next) = next_byte_boundary(span.end, haystack.len()) else {
                break;
            };
            at = next;
            continue;
        }
        previous_end = Some(span.end);
        matches.push(span);
        if matches.len() > max_results {
            return Outcome::Refused(RefusalKind::Results);
        }
        let next = if span.is_empty() {
            next_byte_boundary(span.end, haystack.len())
        } else {
            Some(span.end)
        };
        let Some(next) = next else { break };
        at = next;
    }
    Outcome::Value(matches)
}

fn production_global(
    automaton: &Automaton,
    haystack: &[u8],
    window: SearchWindow,
    limits: SearchLimits,
    max_results: usize,
) -> Outcome<Vec<CanonicalSpan>> {
    let mut at = window.start();
    let mut previous_end = None;
    let mut matches = Vec::new();
    loop {
        let found = match automaton.prepare::<Span>().search_window(
            haystack,
            SearchWindow::new(at, window.end()),
            limits,
        ) {
            Ok(report) => report.into_output(),
            Err(error) => return search_error(&error),
        };
        let Some(found) = found else { break };
        let span = CanonicalSpan::new(found.start(), found.end());
        if span.is_empty() && previous_end == Some(span.start) {
            let Some(next) = next_byte_boundary(span.end, window.end()) else {
                break;
            };
            at = next;
            continue;
        }
        previous_end = Some(span.end);
        matches.push(span);
        if matches.len() > max_results {
            return Outcome::Refused(RefusalKind::Results);
        }
        let next = if span.is_empty() {
            next_byte_boundary(span.end, window.end())
        } else {
            Some(span.end)
        };
        let Some(next) = next else { break };
        at = next;
    }
    Outcome::Value(matches)
}

fn next_byte_boundary(position: usize, end: usize) -> Option<usize> {
    (position < end).then(|| position.checked_add(1)).flatten()
}

fn reference_error<T>(error: &fre_reference::ReferenceError) -> Outcome<T> {
    match error {
        fre_reference::ReferenceError::ResourceLimit(resource) => {
            if *resource == "result count" {
                Outcome::Refused(RefusalKind::Results)
            } else {
                Outcome::Refused(RefusalKind::SearchWork)
            }
        }
        fre_reference::ReferenceError::InvalidAst(message) => Outcome::Fault((*message).to_owned()),
        fre_reference::ReferenceError::InvalidStart => Outcome::Fault("invalid start".to_owned()),
    }
}

fn map_search<T>(result: Result<T, SearchError>) -> Outcome<T> {
    match result {
        Ok(value) => Outcome::Value(value),
        Err(error) => search_error(&error),
    }
}

fn search_error<T>(error: &SearchError) -> Outcome<T> {
    match error {
        SearchError::ResourceLimit { resource, .. } => match resource {
            ResourceKind::ScratchBytes => Outcome::Refused(RefusalKind::ScratchBytes),
            _ => Outcome::Refused(RefusalKind::SearchWork),
        },
        SearchError::WorkLimitExceeded { .. } => Outcome::Refused(RefusalKind::SearchWork),
        SearchError::ArithmeticOverflow { .. } => Outcome::Refused(RefusalKind::Arithmetic),
        _ => Outcome::Fault(error.to_string()),
    }
}

#[derive(Clone, Copy)]
struct Edge {
    target: u32,
    kind: EdgeKind,
    start: u8,
    end: u8,
}

struct State {
    role: StateRole,
    edges: Vec<Edge>,
}

struct Builder {
    states: Vec<State>,
    max_states: usize,
    max_edges: usize,
    edges: usize,
}

impl Builder {
    fn add_state(&mut self, role: StateRole, edges: Vec<Edge>) -> Result<u32, Outcome<()>> {
        let next_edges = self
            .edges
            .checked_add(edges.len())
            .ok_or(Outcome::Refused(RefusalKind::Arithmetic))?;
        if next_edges > self.max_edges {
            return Err(Outcome::Refused(RefusalKind::PlanEdges));
        }
        if self.states.len() >= self.max_states {
            return Err(Outcome::Refused(RefusalKind::PlanStates));
        }
        let index = u32::try_from(self.states.len())
            .map_err(|_| Outcome::Refused(RefusalKind::PlanStates))?;
        self.states.push(State { role, edges });
        self.edges = next_edges;
        Ok(index)
    }

    fn compile(&mut self, ast: &CaseAst, continuation: u32) -> Result<u32, Outcome<()>> {
        match ast {
            CaseAst::Empty => Ok(continuation),
            CaseAst::Byte(byte) => self.add_state(
                StateRole::Consume,
                vec![Edge::byte(continuation, ByteRange::new(*byte, *byte))],
            ),
            CaseAst::Class(ranges) => self.add_state(
                StateRole::Consume,
                ranges
                    .iter()
                    .map(|range| Edge::byte(continuation, *range))
                    .collect(),
            ),
            CaseAst::StartText => self.add_state(
                StateRole::Split,
                vec![Edge::assertion(continuation, EdgeKind::AssertHaystackStart)],
            ),
            CaseAst::EndText => self.add_state(
                StateRole::Split,
                vec![Edge::assertion(continuation, EdgeKind::AssertHaystackEnd)],
            ),
            CaseAst::Concat(children) => {
                let mut next = continuation;
                for child in children.iter().rev() {
                    next = self.compile(child, next)?;
                }
                Ok(next)
            }
            CaseAst::Alt(children) => {
                let mut starts = Vec::with_capacity(children.len());
                for child in children {
                    starts.push(self.compile(child, continuation)?);
                }
                self.add_state(
                    StateRole::Split,
                    starts.into_iter().map(Edge::epsilon).collect(),
                )
            }
            CaseAst::Repeat {
                child,
                min,
                max,
                greed,
            } => {
                let mut next = continuation;
                if let Some(maximum) = max {
                    for _ in 0..maximum.saturating_sub(*min) {
                        let child_start = self.compile(child, next)?;
                        next = self.choice(child_start, next, *greed)?;
                    }
                } else {
                    let split = self.add_state(StateRole::Split, Vec::new())?;
                    let child_start = self.compile(child, split)?;
                    let edges = ordered_edges(child_start, next, *greed);
                    self.edges = self
                        .edges
                        .checked_add(edges.len())
                        .ok_or(Outcome::Refused(RefusalKind::Arithmetic))?;
                    if self.edges > self.max_edges {
                        return Err(Outcome::Refused(RefusalKind::PlanEdges));
                    }
                    self.states[usize::try_from(split).expect("u32 index")].edges = edges;
                    next = split;
                }
                for _ in 0..*min {
                    next = self.compile(child, next)?;
                }
                Ok(next)
            }
        }
    }

    fn choice(&mut self, preferred: u32, fallback: u32, greed: Greed) -> Result<u32, Outcome<()>> {
        self.add_state(StateRole::Split, ordered_edges(preferred, fallback, greed))
    }

    fn finish(self, start: u32) -> Result<RawPlan, Outcome<()>> {
        let offset_count = self
            .states
            .len()
            .checked_add(1)
            .ok_or(Outcome::Refused(RefusalKind::Arithmetic))?;
        let mut edge_offsets = Vec::new();
        let mut edge_targets = Vec::new();
        let mut edge_kinds = Vec::new();
        let mut byte_starts = Vec::new();
        let mut byte_ends = Vec::new();
        let mut roles = Vec::new();
        for (vector, capacity) in [
            (&mut edge_offsets, offset_count),
            (&mut edge_targets, self.edges),
        ] {
            vector
                .try_reserve_exact(capacity)
                .map_err(|_| Outcome::Refused(RefusalKind::Allocation))?;
        }
        edge_kinds
            .try_reserve_exact(self.edges)
            .map_err(|_| Outcome::Refused(RefusalKind::Allocation))?;
        byte_starts
            .try_reserve_exact(self.edges)
            .map_err(|_| Outcome::Refused(RefusalKind::Allocation))?;
        byte_ends
            .try_reserve_exact(self.edges)
            .map_err(|_| Outcome::Refused(RefusalKind::Allocation))?;
        roles
            .try_reserve_exact(self.states.len())
            .map_err(|_| Outcome::Refused(RefusalKind::Allocation))?;
        edge_offsets.push(0);
        for state in self.states {
            roles.push(state.role);
            for edge in state.edges {
                edge_targets.push(edge.target);
                edge_kinds.push(edge.kind);
                byte_starts.push(edge.start);
                byte_ends.push(edge.end);
            }
            edge_offsets.push(u32::try_from(edge_targets.len()).expect("bounded edge count"));
        }
        Ok(RawPlan {
            start,
            roles,
            edge_offsets,
            edge_targets,
            edge_kinds,
            byte_starts,
            byte_ends,
        })
    }
}

impl Edge {
    const fn epsilon(target: u32) -> Self {
        Self {
            target,
            kind: EdgeKind::Epsilon,
            start: 0,
            end: 0,
        }
    }

    const fn assertion(target: u32, kind: EdgeKind) -> Self {
        Self {
            target,
            kind,
            start: 0,
            end: 0,
        }
    }

    const fn byte(target: u32, range: ByteRange) -> Self {
        Self {
            target,
            kind: EdgeKind::ByteRange,
            start: range.start,
            end: range.end,
        }
    }
}

fn ordered_edges(preferred: u32, fallback: u32, greed: Greed) -> Vec<Edge> {
    match greed {
        Greed::Greedy => vec![Edge::epsilon(preferred), Edge::epsilon(fallback)],
        Greed::Lazy => vec![Edge::epsilon(fallback), Edge::epsilon(preferred)],
    }
}

fn compile_automaton(ast: &CaseAst, limits: HarnessLimits) -> Result<Automaton, Outcome<()>> {
    let mut builder = Builder {
        states: Vec::new(),
        max_states: limits.max_plan_states,
        max_edges: limits.max_plan_edges,
        edges: 0,
    };
    let accept = builder.add_state(StateRole::Accept, Vec::new())?;
    let start = builder.compile(ast, accept)?;
    Automaton::from_raw(
        builder.finish(start)?,
        CompileLimits {
            max_states: limits.max_plan_states,
            max_edges: limits.max_plan_edges,
            max_storage_bytes: limits.max_scratch_bytes,
            max_validation_work: limits.max_plan_edges.saturating_mul(4),
        },
    )
    .map_err(|error| match error {
        fre_automata::CompileError::ResourceLimit { resource, .. } => match resource {
            ResourceKind::States => Outcome::Refused(RefusalKind::PlanStates),
            ResourceKind::Edges => Outcome::Refused(RefusalKind::PlanEdges),
            _ => Outcome::Refused(RefusalKind::ScratchBytes),
        },
        fre_automata::CompileError::ArithmeticOverflow { .. } => {
            Outcome::Refused(RefusalKind::Arithmetic)
        }
        fre_automata::CompileError::Malformed(error) => Outcome::Fault(error.to_string()),
        _ => Outcome::Fault(error.to_string()),
    })
}

fn nullable(ast: &CaseAst) -> bool {
    match ast {
        CaseAst::Empty | CaseAst::StartText | CaseAst::EndText => true,
        CaseAst::Byte(_) | CaseAst::Class(_) => false,
        CaseAst::Concat(children) => children.iter().all(nullable),
        CaseAst::Alt(children) => children.iter().any(nullable),
        CaseAst::Repeat { child, min, .. } => *min == 0 || nullable(child),
    }
}

fn has_nullable_unbounded_repeat(ast: &CaseAst) -> bool {
    match ast {
        CaseAst::Repeat { child, max, .. } => {
            (max.is_none() && nullable(child)) || has_nullable_unbounded_repeat(child)
        }
        CaseAst::Concat(children) | CaseAst::Alt(children) => {
            children.iter().any(has_nullable_unbounded_repeat)
        }
        _ => false,
    }
}
