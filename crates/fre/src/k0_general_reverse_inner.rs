//! General capture-free K0 reverse-inner acceleration for value-only Exists.
//!
//! Admission recognizes `Concat([P..., S, tail...])`, where the borrowed
//! prefix `P...` has positive minimum width and `S` is the first eligible
//! nonempty literal or literal-only alternation. The prefix is lowered from
//! its original concat slice, without an unreceipted HIR clone.
//! A leftmost-first literal matcher enumerates every distinct split boundary
//! in increasing start order. A separate reverse-capable K0 session
//! authenticates `P` ending at that boundary, and the original full K0
//! session then replays an exact-start existence search. No source position or
//! result survives a call.

use core::mem;

use fre_automata::{
    Automaton, K0PositiveEndLimits, K0PositiveEndStartOutcome, K0SearchSession,
    SearchError as K0SearchError, SearchLimits, SearchWindow,
};
use fre_kernels::{
    LiteralSetBuildAccounting, LiteralSetBuildLimits, LiteralSetError, LiteralSetPlan,
    LiteralSetMatchSemantics, LiteralSetSearchLimits, Window as LiteralWindow,
};
use fre_lower::{LowerStats, OperationSemantics};
use regex_syntax::hir::{Hir, HirKind, Look};

use crate::{BuildError, BuildLimits, SearchError, SearchSessionLimits};

const MAX_LITERALS: usize = 16;
const MIN_LITERAL_BYTES: usize = 2;
const MAX_LITERAL_BYTES: usize = 4 * 1024;
const SIZE_CLASS_STATES: usize = 4;
const MAX_BACKOFF_CALLS: u8 = 64;
const MAX_CANDIDATES: usize = 8;
// A candidate route necessarily adds a literal pass, at least one reverse
// proof and one exact-start replay. Tiny inputs keep the single-pass incumbent;
// larger inputs still require a measured incumbent win before any trial.
const MIN_TRIAL_WINDOW_BYTES: usize = 256;
const SESSION_OWNER_PUBLICATION_WORK: u64 = 1;
const NODE_WORK: u64 = 1;
const LITERAL_BYTE_WORK: u64 = 1;
const ARITHMETIC_WORK: u64 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InspectionError {
    WorkLimit {
        actual: u64,
        needed: u64,
        limit: u64,
    },
    ArithmeticOverflow,
}

pub(crate) enum InspectionOutcome<'hir> {
    Eligible(Inspection<'hir>),
    Ineligible { planner_work: u64 },
}

impl InspectionOutcome<'_> {
    pub(crate) const fn planner_work(&self) -> u64 {
        match self {
            Self::Eligible(inspection) => inspection.planner_work,
            Self::Ineligible { planner_work } => *planner_work,
        }
    }
}

pub(crate) struct Inspection<'hir> {
    prefix_parts: &'hir [Hir],
    literals: [&'hir [u8]; MAX_LITERALS],
    literal_count: usize,
    literal_bytes: usize,
    planner_work: u64,
}

/// Construction facts retained with the exact sidecar owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BuildAccounting {
    /// Cumulative facade planner work after this final optional inspection.
    pub(crate) cumulative_planner_work: u64,
    /// Independent literal-DFA construction receipt under the caller's one
    /// literal-set build invocation limits.
    pub(crate) literal_set: LiteralSetBuildAccounting,
    /// Independent prefix lowering receipt under the caller's one-lowering-
    /// invocation limits.
    pub(crate) prefix_lowering: LowerStats,
    pub(crate) prefix_storage_bytes: usize,
    pub(crate) owner_bytes: usize,
    pub(crate) persistent_bytes: usize,
}

#[derive(Debug)]
pub(crate) struct Plan {
    literals: LiteralSetPlan,
    prefix: Automaton,
    full_automaton_identity: u64,
    build: BuildAccounting,
}

impl Plan {
    pub(crate) const fn prefix(&self) -> &Automaton {
        &self.prefix
    }

    pub(crate) const fn storage_bytes(&self) -> usize {
        self.build.persistent_bytes
    }

    pub(crate) const fn build_accounting(&self) -> BuildAccounting {
        self.build
    }
}

/// One immutable-plan-bound secondary workspace. It contains no source state
/// and is boxed so the facade's hot session enum does not embed a second K0
/// workspace owner inline.
#[derive(Debug)]
pub(crate) struct SearchSession<'a> {
    plan: &'a Plan,
    full: &'a Automaton,
    prefix: K0SearchSession<'a>,
    exists_route_state: RouteState,
}

impl<'a> SearchSession<'a> {
    pub(crate) fn try_new(
        plan: &'a Plan,
        full: &'a Automaton,
        primary: &K0SearchSession<'_>,
        limits: SearchSessionLimits,
    ) -> Result<Option<Box<Self>>, K0SearchError> {
        Self::try_new_with(plan, full, primary, limits, fre_exact_alloc::try_box_preserve)
    }

    fn try_new_with(
        plan: &'a Plan,
        full: &'a Automaton,
        primary: &K0SearchSession<'_>,
        limits: SearchSessionLimits,
        allocate: impl FnOnce(
            Self,
        ) -> Result<Box<Self>, (fre_exact_alloc::CopyError, Self)>,
    ) -> Result<Option<Box<Self>>, K0SearchError> {
        if plan.full_automaton_identity != full.identity() || !primary.is_bound_to(full) {
            return Err(K0SearchError::InvalidResumeState {
                detail: "reverse-inner sidecar belongs to another full automaton",
            });
        }
        let owner_bytes = mem::size_of::<Self>();
        let Some(prefix_limits) = limits
            .max_setup_work
            .checked_sub(SESSION_OWNER_PUBLICATION_WORK)
            .zip(limits.max_scratch_bytes.checked_sub(owner_bytes))
            .map(|(max_setup_work, max_scratch_bytes)| SearchSessionLimits {
                max_setup_work,
                max_scratch_bytes,
            })
        else {
            return Ok(None);
        };
        let Some(prefix) = K0SearchSession::try_new_reverse_required(plan.prefix(), prefix_limits)?
        else {
            return Ok(None);
        };
        if !prefix.is_bound_to(plan.prefix()) {
            return Err(K0SearchError::InvalidResumeState {
                detail: "reverse-inner prefix workspace belongs to another automaton",
            });
        }
        let session = Self {
            plan,
            full,
            prefix,
            exists_route_state: RouteState::default(),
        };
        match allocate(session) {
            Ok(owner) => Ok(Some(owner)),
            // Prefix construction has already completed. Publishing a
            // primary-only session here would omit that physical setup work
            // from the successful receipt, so owner allocation failure is a
            // construction error rather than an optional decline.
            Err((fre_exact_alloc::CopyError::AllocationFailed, _)) => {
                Err(K0SearchError::ScratchAllocationFailed {
                    requested: owner_bytes,
                })
            }
            Err((fre_exact_alloc::CopyError::LayoutOverflow, _)) => {
                Err(K0SearchError::InternalInvariant {
                    detail: "reverse-inner search-session owner layout overflowed",
                })
            }
        }
    }

    pub(crate) const fn prefix_session(&self) -> &K0SearchSession<'a> {
        &self.prefix
    }

    pub(crate) const fn owner_bytes() -> usize {
        mem::size_of::<Self>()
    }

    pub(crate) const fn owner_publication_work() -> u64 {
        SESSION_OWNER_PUBLICATION_WORK
    }

    pub(crate) const fn staged_exists_route_state(&self) -> RouteState {
        self.exists_route_state
    }

    pub(crate) fn publish_exists_route_state(&mut self, state: RouteState) {
        self.exists_route_state = state;
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RouteClassState {
    window_size_class: Option<u32>,
    incumbent_work: u64,
    learned: bool,
    prefer_candidate: bool,
    disabled_calls: u8,
    backoff: u8,
    candidate_epoch: u8,
    candidate_remaining: u8,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RouteState {
    classes: [RouteClassState; SIZE_CLASS_STATES],
    next_replacement: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Route {
    Bypass,
    Learn { class_index: usize },
    Candidate {
        class_index: usize,
        incumbent_work: u64,
    },
}

impl RouteState {
    pub(crate) fn select(&mut self, window_bytes: usize) -> Route {
        if window_bytes < MIN_TRIAL_WINDOW_BYTES {
            return Route::Bypass;
        }
        let size_class = usize::BITS - window_bytes.leading_zeros();
        let class_index = self.class_for(size_class);
        let class = &mut self.classes[class_index];
        if class.disabled_calls != 0 {
            class.disabled_calls = class.disabled_calls.saturating_sub(1);
            return Route::Bypass;
        }
        if !class.learned {
            return Route::Learn { class_index };
        }
        if class.prefer_candidate {
            Route::Candidate {
                class_index,
                incumbent_work: class.incumbent_work,
            }
        } else {
            Route::Learn { class_index }
        }
    }

    pub(crate) fn observe_incumbent(
        &mut self,
        class_index: usize,
        window_bytes: usize,
        incumbent_work: u64,
    ) {
        let class = &mut self.classes[class_index];
        class.learned = true;
        class.incumbent_work = incumbent_work;
        let source_pass = u64::try_from(window_bytes).unwrap_or(u64::MAX);
        class.prefer_candidate = incumbent_work > source_pass.saturating_add(1);
        if class.prefer_candidate {
            class.candidate_epoch = if class.candidate_epoch == 0 {
                1
            } else {
                class.candidate_epoch.saturating_mul(2).min(MAX_BACKOFF_CALLS)
            };
            class.candidate_remaining = class.candidate_epoch;
            class.backoff = 0;
            class.disabled_calls = 0;
        } else {
            class.candidate_epoch = 0;
            class.candidate_remaining = 0;
            class.backoff = if class.backoff == 0 {
                1
            } else {
                class.backoff.saturating_mul(2).min(MAX_BACKOFF_CALLS)
            };
            class.disabled_calls = class.backoff;
        }
    }

    pub(crate) fn observe_candidate_complete(&mut self, class_index: usize, won: bool) {
        let class = &mut self.classes[class_index];
        if won {
            class.candidate_remaining = class.candidate_remaining.saturating_sub(1);
            if class.candidate_remaining == 0 {
                class.learned = false;
                class.incumbent_work = 0;
                class.prefer_candidate = false;
            } else {
                class.prefer_candidate = true;
            }
            class.backoff = 0;
            class.disabled_calls = 0;
        } else {
            class.prefer_candidate = false;
            class.candidate_epoch = 0;
            class.candidate_remaining = 0;
            class.backoff = if class.backoff == 0 {
                1
            } else {
                class.backoff.saturating_mul(2).min(MAX_BACKOFF_CALLS)
            };
            class.disabled_calls = class.backoff;
        }
    }

    fn class_for(&mut self, size_class: u32) -> usize {
        if let Some(index) = self
            .classes
            .iter()
            .position(|state| state.window_size_class == Some(size_class))
        {
            return index;
        }
        if let Some(index) = self
            .classes
            .iter()
            .position(|state| state.window_size_class.is_none())
        {
            self.classes[index].window_size_class = Some(size_class);
            return index;
        }
        let index = usize::from(self.next_replacement) % self.classes.len();
        self.next_replacement = self.next_replacement.wrapping_add(1)
            % u8::try_from(self.classes.len()).expect("size-class count fits u8");
        self.classes[index] = RouteClassState {
            window_size_class: Some(size_class),
            ..RouteClassState::default()
        };
        index
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Attempt {
    Complete { output: bool, won: bool },
    Fallback,
}

#[cold]
pub(crate) fn inspect(
    hir: &Hir,
    explicit_captures: usize,
    initial_work: u64,
    max_planner_work: u64,
) -> Result<InspectionOutcome<'_>, InspectionError> {
    let mut work = initial_work;
    charge(&mut work, NODE_WORK, max_planner_work)?;
    if explicit_captures != 0
        || hir.properties().explicit_captures_len() != 0
        || !matches!(hir.properties().minimum_len(), Some(minimum) if minimum > 0)
        || hir.properties().look_set().contains(Look::Start)
    {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    }
    let HirKind::Concat(parts) = hir.kind() else {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    };
    if parts.len() < 2 {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    }
    let first = &parts[0];
    charge(&mut work, NODE_WORK, max_planner_work)?;
    if !matches!(first.properties().minimum_len(), Some(minimum) if minimum > 0) {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    }
    for split_index in 1..parts.len() {
        let split = &parts[split_index];
        charge(&mut work, NODE_WORK, max_planner_work)?;
        if let Some((literals, literal_count, literal_bytes)) =
            inspect_literal_split(split, &mut work, max_planner_work)?
        {
            return Ok(InspectionOutcome::Eligible(Inspection {
                prefix_parts: &parts[..split_index],
                literals,
                literal_count,
                literal_bytes,
                planner_work: work,
            }));
        }
    }
    Ok(InspectionOutcome::Ineligible { planner_work: work })
}

impl Inspection<'_> {
    pub(crate) fn build(
        self,
        full_automaton: &Automaton,
        line_terminator: u8,
        limits: BuildLimits,
        available_persistent_bytes: usize,
    ) -> Result<Option<Box<Plan>>, BuildError> {
        self.build_with(
            full_automaton,
            line_terminator,
            limits,
            available_persistent_bytes,
            fre_exact_alloc::try_box_preserve,
        )
    }

    fn build_with(
        self,
        full_automaton: &Automaton,
        line_terminator: u8,
        limits: BuildLimits,
        available_persistent_bytes: usize,
        allocate: impl FnOnce(Plan) -> Result<Box<Plan>, (fre_exact_alloc::CopyError, Plan)>,
    ) -> Result<Option<Box<Plan>>, BuildError> {
        let owner_bytes = mem::size_of::<Plan>();
        let Some(component_budget) = available_persistent_bytes.checked_sub(owner_bytes) else {
            return Ok(None);
        };

        let mut literal_limits: LiteralSetBuildLimits = limits.literal_set;
        literal_limits.max_pattern_bytes = literal_limits.max_pattern_bytes.min(MAX_LITERAL_BYTES);
        // `available_persistent_bytes` is a retained-storage allowance. Do not
        // also treat it as a transient construction allowance: the literal
        // builder's separately supplied `max_build_bytes` already accounts for
        // that resource, and its conservative build envelope may exceed the
        // finished literal and prefix plans even when both fit exactly.
        literal_limits.max_persistent_bytes = literal_limits
            .max_persistent_bytes
            .min(component_budget);
        let literal_set = match LiteralSetPlan::new(
            &self.literals[..self.literal_count],
            literal_limits,
        ) {
            Ok(plan) => plan,
            Err(
                LiteralSetError::PatternLimit { .. }
                | LiteralSetError::PatternBytesLimit { .. }
                | LiteralSetError::BuildWorkLimit { .. }
                | LiteralSetError::BuildBytesLimit { .. }
                | LiteralSetError::PersistentBytesLimit { .. },
            ) => return Ok(None),
            Err(error @ LiteralSetError::AutomatonBuild { .. }) => {
                return Err(BuildError::LiteralSet(error));
            }
            Err(LiteralSetError::ArithmeticOverflow { .. }) => {
                return Err(BuildError::InternalInvariant(
                    "reverse-inner literal-set construction overflowed its inspected envelope",
                ));
            }
            Err(_) => {
                return Err(BuildError::InternalInvariant(
                    "reverse-inner literal-set construction rejected inspected literals",
                ));
            }
        };
        let literal_build = literal_set.build_accounting();
        if literal_build.patterns != self.literal_count
            || literal_build.pattern_bytes != self.literal_bytes
            || literal_build.minimum_pattern_bytes < MIN_LITERAL_BYTES
            || literal_build.match_semantics != LiteralSetMatchSemantics::LeftmostFirst
            || literal_build.build_work_upper_bound > literal_limits.max_build_work
            || literal_build.build_bytes_upper_bound > literal_limits.max_build_bytes
            || literal_build.persistent_bytes > literal_limits.max_persistent_bytes
        {
            return Err(BuildError::InternalInvariant(
                "reverse-inner literal-set receipt disagrees with inspection",
            ));
        }
        let Some(prefix_budget) = component_budget.checked_sub(literal_build.persistent_bytes)
        else {
            return Ok(None);
        };
        let mut prefix_limits = limits.lowering;
        prefix_limits.automata.max_storage_bytes = prefix_limits
            .automata
            .max_storage_bytes
            .min(prefix_budget);
        let lowered = match fre_lower::lower_hir_concat_slice(
            self.prefix_parts,
            OperationSemantics::CaptureFree,
            prefix_limits,
        ) {
            Ok(lowered) => lowered,
            Err(
                fre_lower::LowerError::ResourceLimit { .. }
                | fre_lower::LowerError::Automata(
                    fre_automata::CompileError::ResourceLimit { .. },
                ),
            ) => return Ok(None),
            Err(error) => return Err(BuildError::Lower(error)),
        };
        let prefix_lowering = lowered.stats();
        if prefix_lowering.erased_captures() != 0 {
            return Err(BuildError::InternalInvariant(
                "capture-free reverse-inner prefix lowering erased a capture",
            ));
        }
        let prefix = lowered
            .into_automaton()
            .with_line_terminator(line_terminator);
        let prefix_stats = prefix.stats();
        if prefix_lowering.work() > prefix_limits.max_work
            || prefix_lowering.peak_stack_items() > prefix_limits.max_stack_items
            || prefix_lowering.states() != prefix_stats.states()
            || prefix_lowering.edges() != prefix_stats.edges()
            || prefix_stats.states() > prefix_limits.automata.max_states
            || prefix_stats.edges() > prefix_limits.automata.max_edges
            || prefix_stats.storage_bytes() > prefix_limits.automata.max_storage_bytes
            || prefix_stats.validation_work() > prefix_limits.automata.max_validation_work
        {
            return Err(BuildError::InternalInvariant(
                "reverse-inner prefix lowering receipt exceeded its enforced limits",
            ));
        }
        let prefix_storage_bytes = prefix_stats.storage_bytes();
        let persistent_bytes = owner_bytes
            .checked_add(literal_build.persistent_bytes)
            .and_then(|bytes| bytes.checked_add(prefix_storage_bytes))
            .ok_or(BuildError::PersistentBytesOverflow)?;
        if persistent_bytes > available_persistent_bytes {
            return Err(BuildError::InternalInvariant(
                "reverse-inner prepublication census exceeded its enforced budget",
            ));
        }
        let build = BuildAccounting {
            cumulative_planner_work: self.planner_work,
            literal_set: literal_build,
            prefix_lowering,
            prefix_storage_bytes,
            owner_bytes,
            persistent_bytes,
        };
        let plan = Plan {
            literals: literal_set,
            prefix,
            full_automaton_identity: full_automaton.identity(),
            build,
        };
        match allocate(plan) {
            Ok(plan) => Ok(Some(plan)),
            // Literal-set and prefix construction have both completed. A
            // silent optional decline would lose their physical work from
            // the published base-plan receipt.
            Err((fre_exact_alloc::CopyError::AllocationFailed, _)) => {
                Err(BuildError::AllocationFailed {
                    structure: "reverse-inner sidecar owner",
                    additional: 1,
                })
            }
            Err((fre_exact_alloc::CopyError::LayoutOverflow, _)) => Err(
                BuildError::InternalInvariant("reverse-inner sidecar owner layout overflowed"),
            ),
        }
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn try_exists(
    full: &mut K0SearchSession<'_>,
    sidecar: &mut SearchSession<'_>,
    haystack: &[u8],
    window: SearchWindow,
    incumbent_work: u64,
) -> Result<Attempt, SearchError> {
    if sidecar.plan.full_automaton_identity != sidecar.full.identity()
        || !full.is_bound_to(sidecar.full)
        || !sidecar.prefix.is_bound_to(sidecar.plan.prefix())
    {
        return Err(SearchError::K0(K0SearchError::InvalidResumeState {
            detail: "reverse-inner execution crossed an immutable-plan binding",
        }));
    }
    if incumbent_work == 0
        || window.start() > window.end()
        || window.end() > haystack.len()
        || window.start() == window.end()
    {
        return Ok(Attempt::Fallback);
    }
    let mut remaining_work = incumbent_work;
    let mut completed_work = 0u64;
    let mut next_start = window.start();
    let mut candidates = 0usize;

    while next_start < window.end() {
        let remaining_usize = usize::try_from(remaining_work).unwrap_or(usize::MAX);
        let found = match sidecar.plan.literals.find_window(
            haystack,
            LiteralWindow::new(next_start, window.end()),
            LiteralSetSearchLimits {
                max_transitions: remaining_usize,
            },
        ) {
            Ok((found, accounting)) => {
                let work = u64::try_from(accounting.transitions_upper_bound)
                    .map_err(|_| SearchError::K0(K0SearchError::ArithmeticOverflow {
                        computation: "reverse-inner literal work conversion",
                    }))?;
                remaining_work = remaining_work.checked_sub(work).ok_or_else(|| {
                    SearchError::K0(K0SearchError::InternalInvariant {
                        detail: "admitted reverse-inner literal work exceeded its budget",
                    })
                })?;
                completed_work = completed_work.checked_add(work).ok_or_else(|| {
                    SearchError::K0(K0SearchError::ArithmeticOverflow {
                        computation: "reverse-inner completed literal work",
                    })
                })?;
                found
            }
            Err(LiteralSetError::TransitionLimit { .. }) => return Ok(Attempt::Fallback),
            Err(LiteralSetError::ArithmeticOverflow { computation }) => {
                return Err(SearchError::K0(K0SearchError::ArithmeticOverflow {
                    computation,
                }));
            }
            Err(LiteralSetError::InvalidWindow { .. }) => return Ok(Attempt::Fallback),
            Err(_) => {
                return Err(SearchError::K0(K0SearchError::InternalInvariant {
                    detail: "reverse-inner literal search violated its construction contract",
                }));
            }
        };
        let Some((candidate, _literal_end)) = found else {
            return Ok(Attempt::Complete {
                output: false,
                won: completed_work < incumbent_work,
            });
        };
        candidates = candidates.saturating_add(1);
        if candidates > MAX_CANDIDATES || remaining_work == 0 {
            return Ok(Attempt::Fallback);
        }

        let reverse_limit = usize::try_from(remaining_work).unwrap_or(usize::MAX);
        let verification = sidecar.prefix.try_earliest_start_ending_at(
            haystack,
            window,
            candidate,
            K0PositiveEndLimits::new(remaining_work, reverse_limit),
        )?;
        let reverse_work = verification.receipt().work();
        remaining_work = remaining_work.checked_sub(reverse_work).ok_or_else(|| {
            SearchError::K0(K0SearchError::InternalInvariant {
                detail: "admitted reverse-inner verifier work exceeded its budget",
            })
        })?;
        completed_work = completed_work.checked_add(reverse_work).ok_or_else(|| {
            SearchError::K0(K0SearchError::ArithmeticOverflow {
                computation: "reverse-inner completed verifier work",
            })
        })?;
        let start = match verification.outcome() {
            K0PositiveEndStartOutcome::Matched { start } => start,
            K0PositiveEndStartOutcome::Rejected => {
                next_start = candidate.checked_add(1).ok_or_else(|| {
                    SearchError::K0(K0SearchError::ArithmeticOverflow {
                        computation: "reverse-inner overlapping candidate progress",
                    })
                })?;
                continue;
            }
            K0PositiveEndStartOutcome::Declined => return Ok(Attempt::Fallback),
        };
        if remaining_work == 0 {
            return Ok(Attempt::Fallback);
        }
        let exact = full.search_exact_start_exists_value(
            haystack,
            SearchWindow::new(start, window.end()),
            SearchLimits {
                max_work: remaining_work,
                max_scratch_bytes: usize::MAX,
            },
        );
        let (output, exact_work) = match exact {
            Ok(result) => result,
            Err(K0SearchError::WorkLimitExceeded { limit, .. }) if limit == remaining_work => {
                return Ok(Attempt::Fallback);
            }
            Err(error) => return Err(SearchError::from(error)),
        };
        remaining_work = remaining_work.checked_sub(exact_work).ok_or_else(|| {
            SearchError::K0(K0SearchError::InternalInvariant {
                detail: "admitted reverse-inner exact-start work exceeded its budget",
            })
        })?;
        completed_work = completed_work.checked_add(exact_work).ok_or_else(|| {
            SearchError::K0(K0SearchError::ArithmeticOverflow {
                computation: "reverse-inner completed exact-start work",
            })
        })?;
        if output {
            return Ok(Attempt::Complete {
                output: true,
                won: completed_work < incumbent_work,
            });
        }
        next_start = candidate.checked_add(1).ok_or_else(|| {
            SearchError::K0(K0SearchError::ArithmeticOverflow {
                computation: "reverse-inner overlapping candidate progress",
            })
        })?;
    }
    Ok(Attempt::Complete {
        output: false,
        won: completed_work < incumbent_work,
    })
}

fn inspect_literal_split<'hir>(
    split: &'hir Hir,
    work: &mut u64,
    max_work: u64,
) -> Result<Option<([&'hir [u8]; MAX_LITERALS], usize, usize)>, InspectionError> {
    let mut literals = [&[][..]; MAX_LITERALS];
    let mut literal_count = 0usize;
    let mut literal_bytes = 0usize;
    match split.kind() {
        HirKind::Literal(literal) => {
            if !record_literal(
                literal.0.as_ref(),
                &mut literals,
                &mut literal_count,
                &mut literal_bytes,
                work,
                max_work,
            )? {
                return Ok(None);
            }
        }
        HirKind::Alternation(branches) if (1..=MAX_LITERALS).contains(&branches.len()) => {
            for branch in branches {
                charge(work, NODE_WORK, max_work)?;
                let HirKind::Literal(literal) = branch.kind() else {
                    return Ok(None);
                };
                if !record_literal(
                    literal.0.as_ref(),
                    &mut literals,
                    &mut literal_count,
                    &mut literal_bytes,
                    work,
                    max_work,
                )? {
                    return Ok(None);
                }
            }
        }
        _ => return Ok(None),
    }
    if literal_count == 0 || literal_bytes == 0 || literal_bytes > MAX_LITERAL_BYTES {
        return Ok(None);
    }
    Ok(Some((literals, literal_count, literal_bytes)))
}

fn record_literal<'hir>(
    bytes: &'hir [u8],
    literals: &mut [&'hir [u8]; MAX_LITERALS],
    literal_count: &mut usize,
    literal_bytes: &mut usize,
    work: &mut u64,
    max_work: u64,
) -> Result<bool, InspectionError> {
    if bytes.len() < MIN_LITERAL_BYTES || *literal_count >= literals.len() {
        return Ok(false);
    }
    let byte_work = u64::try_from(bytes.len()).map_err(|_| InspectionError::ArithmeticOverflow)?;
    let byte_work = byte_work
        .checked_mul(LITERAL_BYTE_WORK)
        .ok_or(InspectionError::ArithmeticOverflow)?;
    charge(work, byte_work, max_work)?;
    charge(work, ARITHMETIC_WORK, max_work)?;
    *literal_bytes = literal_bytes
        .checked_add(bytes.len())
        .ok_or(InspectionError::ArithmeticOverflow)?;
    if *literal_bytes > MAX_LITERAL_BYTES {
        return Ok(false);
    }
    literals[*literal_count] = bytes;
    *literal_count = literal_count
        .checked_add(1)
        .ok_or(InspectionError::ArithmeticOverflow)?;
    Ok(true)
}

fn charge(work: &mut u64, amount: u64, limit: u64) -> Result<(), InspectionError> {
    let needed = work
        .checked_add(amount)
        .ok_or(InspectionError::ArithmeticOverflow)?;
    if needed > limit {
        return Err(InspectionError::WorkLimit {
            actual: *work,
            needed,
            limit,
        });
    }
    *work = needed;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        Attempt, InspectionOutcome, Plan, Route, RouteState, SearchSession, inspect, try_exists,
    };
    use crate::{
        BuildError, BuildLimits, CompatibilityProfile, K0MandatoryCutPlan, K0MandatorySuffixPlan,
        K0NegativePrefilterPlan, K0NegativePrefilterState, PortableBuilder, PortablePlan,
        PortableSearchSessionPlan, SearchLimits, SearchSessionLimits, SearchWindow,
    };
    use fre_automata::{Automaton, K0SearchSession, SearchError as K0SearchError};
    use fre_syntax::{CanonicalPattern, ParseRequest};

    fn parsed_with(
        pattern: &str,
        unicode: bool,
    ) -> (fre_syntax::RustParsed, BuildLimits, u8) {
        let builder = PortableBuilder::new(pattern).unicode(unicode);
        let request = ParseRequest::rust(
            pattern,
            CompatibilityProfile::RustBytes(builder.profile.clone()),
        )
        .with_admission(builder.limits.admission)
        .with_safety_envelope(builder.limits.syntax_safety);
        let parsed = fre_syntax::parse(request).expect("focused reverse-inner pattern parses");
        let CanonicalPattern::Rust(rust) = parsed.pattern else {
            panic!("Rust request produced a non-Rust pattern");
        };
        (rust, builder.limits, builder.profile.options.line_terminator)
    }

    fn parsed(pattern: &str) -> fre_syntax::RustParsed {
        parsed_with(pattern, false).0
    }

    fn full_automaton(
        rust: &fre_syntax::RustParsed,
        limits: BuildLimits,
        line_terminator: u8,
    ) -> Automaton {
        fre_lower::lower_hir(
            &rust.hir,
            fre_lower::OperationSemantics::CaptureFree,
            limits.lowering,
        )
        .expect("focused reverse-inner pattern lowers through K0")
        .into_automaton()
        .with_line_terminator(line_terminator)
    }

    fn plans(pattern: &str, unicode: bool) -> (Automaton, Box<Plan>) {
        let (rust, limits, line_terminator) = parsed_with(pattern, unicode);
        let full = full_automaton(&rust, limits, line_terminator);
        let inspection = match inspect(&rust.hir, 0, 0, u64::MAX).unwrap() {
            InspectionOutcome::Eligible(inspection) => inspection,
            InspectionOutcome::Ineligible { .. } => {
                panic!("focused reverse-inner pattern was not admitted")
            }
        };
        let sidecar = inspection
            .build(&full, line_terminator, limits, usize::MAX)
            .unwrap()
            .expect("focused reverse-inner owner fits unlimited resources");
        (full, sidecar)
    }

    fn attempt(
        pattern: &str,
        unicode: bool,
        haystack: &[u8],
        window: SearchWindow,
        incumbent_work: u64,
    ) -> Attempt {
        let (full, sidecar) = plans(pattern, unicode);
        let mut full_session = K0SearchSession::new_selected(
            &full,
            SearchSessionLimits::unlimited(),
            true,
            true,
        )
        .unwrap();
        let mut sidecar_session = SearchSession::try_new(
            &sidecar,
            &full,
            &full_session,
            SearchSessionLimits::unlimited(),
        )
        .unwrap()
        .expect("focused prefix admits a reverse workspace");
        try_exists(
            &mut full_session,
            &mut sidecar_session,
            haystack,
            window,
            incumbent_work,
        )
        .unwrap()
    }

    #[test]
    fn inspector_requires_a_capture_free_positive_prefix_and_exact_split() {
        for pattern in [
            "q+(?:abcd|bc)Z",
            "[a-z]+needle.*tail",
            "q+[0-9]+needleZ",
            "q+[0-9]+(?:needle|marker)Z",
        ] {
            let rust = parsed(pattern);
            assert!(matches!(
                inspect(&rust.hir, 0, 0, u64::MAX).unwrap(),
                InspectionOutcome::Eligible(_)
            ));
        }
        for pattern in [
            "(?:q+)(?:a|b)Z",
            "(?P<x>q+)(?:abcd|bc)Z",
            "\\Aq+(?:abcd|bc)Z",
            "q*(?:abcd|bc)Z",
            "q+(?:a|bc)Z",
            "q+(?:ab|b[cd])Z",
            "q+[0-9]+[A-Z]+",
        ] {
            let rust = parsed(pattern);
            assert!(matches!(
                inspect(
                    &rust.hir,
                    rust.hir.properties().explicit_captures_len(),
                    0,
                    u64::MAX,
                )
                .unwrap(),
                InspectionOutcome::Ineligible { .. }
            ));
        }
    }

    #[test]
    fn inspector_selects_the_first_eligible_later_split_and_receipts_rejections() {
        let first = parsed("q+[0-9]+needle(?:marker|signal)Z");
        let InspectionOutcome::Eligible(first) =
            inspect(&first.hir, 0, 0, u64::MAX).unwrap()
        else {
            panic!("later exact literal must be admitted");
        };
        assert_eq!(first.prefix_parts.len(), 2);
        assert_eq!(first.literal_count, 1);
        assert_eq!(first.literals[0], b"needle");

        let alternation = parsed("q+[0-9]+(?:needle|marker)Z");
        let InspectionOutcome::Eligible(alternation) =
            inspect(&alternation.hir, 0, 0, u64::MAX).unwrap()
        else {
            panic!("later literal alternation must be admitted");
        };
        assert_eq!(alternation.prefix_parts.len(), 2);
        assert_eq!(alternation.literal_count, 2);
        assert_eq!(alternation.literals[0], b"needle");
        assert_eq!(alternation.literals[1], b"marker");

        let direct = parsed("q+needle(?:marker|signal)Z");
        let direct_work = inspect(&direct.hir, 0, 0, u64::MAX)
            .unwrap()
            .planner_work();
        let rejected = parsed("q+(?:a+|b[cd])needle(?:marker|signal)Z");
        let InspectionOutcome::Eligible(rejected) =
            inspect(&rejected.hir, 0, 0, u64::MAX).unwrap()
        else {
            panic!("inspection must continue beyond an ineligible child");
        };
        assert_eq!(rejected.prefix_parts.len(), 2);
        assert_eq!(rejected.literals[0], b"needle");
        assert!(rejected.planner_work > direct_work);
    }

    #[test]
    fn inspector_work_limit_closes_before_overrun() {
        let rust = parsed("q+(?:abcd|bc)Z");
        let exact = inspect(&rust.hir, 0, 0, u64::MAX)
            .unwrap()
            .planner_work();
        assert_eq!(exact, 13);
        assert_eq!(
            inspect(&rust.hir, 0, 0, exact).unwrap().planner_work(),
            exact
        );
        assert!(inspect(&rust.hir, 0, 0, exact - 1).is_err());
    }

    #[test]
    fn declined_candidate_enters_bounded_backoff_before_relearning() {
        let mut state = RouteState::default();
        let Route::Learn { class_index } = state.select(4_096) else {
            panic!("fresh reverse-inner class must learn its incumbent");
        };
        state.observe_incumbent(class_index, 4_096, 16_384);
        assert!(matches!(
            state.select(4_096),
            Route::Candidate {
                class_index: observed,
                ..
            } if observed == class_index
        ));

        state.observe_candidate_complete(class_index, false);
        assert_eq!(state.select(4_096), Route::Bypass);
        assert_eq!(state.select(4_096), Route::Learn { class_index });
    }

    #[test]
    fn leftmost_start_enumeration_keeps_the_streaming_any_counterexample() {
        assert!(matches!(
            attempt(
                "q+(?:abcd|bc)Z",
                false,
                b"qabcdZ",
                SearchWindow::new(0, 6),
                u64::MAX / 4,
            ),
            Attempt::Complete { output: true, .. }
        ));
    }

    #[test]
    fn later_split_authenticates_the_whole_prefix_tail_overlaps_and_window() {
        let pattern = "q+[0-9]+(?:abab|bab)Z";
        for (haystack, window, expected) in [
            (
                &b"xxqq12ababZyy"[..],
                SearchWindow::new(2, 11),
                true,
            ),
            (
                &b"xxqq12ababZyy"[..],
                SearchWindow::new(4, 11),
                false,
            ),
            (
                &b"xxqq12ababZyy"[..],
                SearchWindow::new(2, 10),
                false,
            ),
            (
                &b"qq12XababZ"[..],
                SearchWindow::new(0, 10),
                false,
            ),
            (
                &b"qq12ababQ"[..],
                SearchWindow::new(0, 9),
                false,
            ),
        ] {
            assert!(matches!(
                attempt(pattern, false, haystack, window, u64::MAX / 4),
                Attempt::Complete { output, .. } if output == expected
            ));
        }
    }

    #[test]
    fn later_split_candidate_exhaustion_falls_back_without_publishing_a_result() {
        let haystack = b"needle".repeat(9);
        assert_eq!(
            attempt(
                "q+[0-9]+needle[A-Z]",
                false,
                &haystack,
                SearchWindow::full(&haystack),
                u64::MAX / 4,
            ),
            Attempt::Fallback,
        );
    }

    #[test]
    fn later_split_candidate_matches_authoritative_k0_on_bounded_inputs() {
        const ALPHABET: &[u8] = b"q1abZ";
        let (full, sidecar) = plans("q+[0-9]+(?:ab|ba)Z", false);
        let mut full_session = K0SearchSession::new_selected(
            &full,
            SearchSessionLimits::unlimited(),
            true,
            true,
        )
        .unwrap();
        let mut sidecar_session = SearchSession::try_new(
            &sidecar,
            &full,
            &full_session,
            SearchSessionLimits::unlimited(),
        )
        .unwrap()
        .unwrap();
        let mut complete = 0usize;
        let mut matched = 0usize;
        for len in 0..=5usize {
            let cases = ALPHABET.len().pow(u32::try_from(len).unwrap());
            for mut encoded in 0..cases {
                let mut haystack = vec![0u8; len];
                for byte in &mut haystack {
                    *byte = ALPHABET[encoded % ALPHABET.len()];
                    encoded /= ALPHABET.len();
                }
                for start in 0..=len {
                    for end in start..=len {
                        let window = SearchWindow::new(start, end);
                        let expected = full_session
                            .search_exists_value(
                                &haystack,
                                window,
                                SearchLimits::unlimited(),
                            )
                            .unwrap();
                        match try_exists(
                            &mut full_session,
                            &mut sidecar_session,
                            &haystack,
                            window,
                            u64::MAX / 4,
                        )
                        .unwrap()
                        {
                            Attempt::Complete { output, .. } => {
                                assert_eq!(
                                    output, expected,
                                    "haystack={haystack:?}, start={start}, end={end}",
                                );
                                complete += 1;
                                matched += usize::from(output);
                            }
                            Attempt::Fallback => {}
                        }
                    }
                }
            }
        }
        assert!(complete > 0);
        assert!(matched > 0);
    }

    #[test]
    fn original_window_and_line_assertion_context_are_preserved() {
        let pattern = "(?m:(?:q+$|r+$))(?:\\nZ|ab)K";
        let haystack = b"xxq\nZKyy";
        assert!(matches!(
            attempt(
                pattern,
                false,
                haystack,
                SearchWindow::new(2, 6),
                u64::MAX / 4,
            ),
            Attempt::Complete { output: true, .. }
        ));
        assert!(matches!(
            attempt(
                pattern,
                false,
                haystack,
                SearchWindow::new(3, 6),
                u64::MAX / 4,
            ),
            Attempt::Complete { output: false, .. }
        ));
        assert!(matches!(
            attempt(
                pattern,
                false,
                haystack,
                SearchWindow::new(2, 5),
                u64::MAX / 4,
            ),
            Attempt::Complete { output: false, .. }
        ));
    }

    #[test]
    fn exact_unicode_literals_are_admitted_without_admitting_unicode_classes() {
        let pattern = "[a-z]+(?:éé|øø)Z";
        let haystack = "qqééZ".as_bytes();
        assert!(matches!(
            attempt(
                pattern,
                true,
                haystack,
                SearchWindow::full(haystack),
                u64::MAX / 4,
            ),
            Attempt::Complete { output: true, .. }
        ));
        let (class, _, _) = parsed_with("[a-z]+(?:\\pL\\pL|ab)Z", true);
        assert!(matches!(
            inspect(&class.hir, 0, 0, u64::MAX).unwrap(),
            InspectionOutcome::Ineligible { .. }
        ));
    }

    #[test]
    fn source_state_is_fresh_across_same_address_mutation() {
        let (full, sidecar) = plans("q+(?:abcd|bc)Z", false);
        let mut full_session = K0SearchSession::new_selected(
            &full,
            SearchSessionLimits::unlimited(),
            true,
            true,
        )
        .unwrap();
        let mut sidecar_session = SearchSession::try_new(
            &sidecar,
            &full,
            &full_session,
            SearchSessionLimits::unlimited(),
        )
        .unwrap()
        .unwrap();
        let mut haystack = vec![b'x'; 512];
        let address = haystack.as_ptr();
        assert!(matches!(
            try_exists(
                &mut full_session,
                &mut sidecar_session,
                &haystack,
                SearchWindow::full(&haystack),
                u64::MAX / 4,
            )
            .unwrap(),
            Attempt::Complete { output: false, .. }
        ));
        haystack[..6].copy_from_slice(b"qabcdZ");
        assert_eq!(haystack.as_ptr(), address);
        assert!(matches!(
            try_exists(
                &mut full_session,
                &mut sidecar_session,
                &haystack,
                SearchWindow::full(&haystack),
                u64::MAX / 4,
            )
            .unwrap(),
            Attempt::Complete { output: true, .. }
        ));

        haystack[..6].fill(b'x');
        haystack[200..204].copy_from_slice(b"qbcZ");
        assert_eq!(haystack.as_ptr(), address);
        assert!(matches!(
            try_exists(
                &mut full_session,
                &mut sidecar_session,
                &haystack,
                SearchWindow::full(&haystack),
                u64::MAX / 4,
            )
            .unwrap(),
            Attempt::Complete { output: true, .. }
        ));

        haystack[200..204].fill(b'x');
        assert_eq!(haystack.as_ptr(), address);
        assert!(matches!(
            try_exists(
                &mut full_session,
                &mut sidecar_session,
                &haystack,
                SearchWindow::full(&haystack),
                u64::MAX / 4,
            )
            .unwrap(),
            Attempt::Complete { output: false, .. }
        ));
    }

    #[test]
    fn immutable_full_plan_binding_rejects_cross_plan_execution() {
        let (first_full, first_sidecar) = plans("q+(?:abcd|bc)Z", false);
        let cloned_full = first_full.clone();
        let (second_full, _) = plans("r+(?:wxyz|xy)Q", false);
        let first_primary = K0SearchSession::new_selected(
            &first_full,
            SearchSessionLimits::unlimited(),
            true,
            true,
        )
        .unwrap();
        let mut first_sidecar_session = SearchSession::try_new(
            &first_sidecar,
            &first_full,
            &first_primary,
            SearchSessionLimits::unlimited(),
        )
        .unwrap()
        .unwrap();
        let mut cloned_primary = K0SearchSession::new_selected(
            &cloned_full,
            SearchSessionLimits::unlimited(),
            true,
            true,
        )
        .unwrap();
        let mut second_primary = K0SearchSession::new_selected(
            &second_full,
            SearchSessionLimits::unlimited(),
            true,
            true,
        )
        .unwrap();
        let first_haystack = b"qabcdZ";
        assert!(matches!(
            try_exists(
                &mut cloned_primary,
                &mut first_sidecar_session,
                first_haystack,
                SearchWindow::full(first_haystack),
                u64::MAX / 4,
            ),
            Err(crate::SearchError::K0(K0SearchError::InvalidResumeState { .. }))
        ));
        assert!(matches!(
            SearchSession::try_new(
                &first_sidecar,
                &cloned_full,
                &cloned_primary,
                SearchSessionLimits::unlimited(),
            ),
            Err(K0SearchError::InvalidResumeState { .. })
        ));
        let haystack = b"rwxyzQ";
        assert!(matches!(
            try_exists(
                &mut second_primary,
                &mut first_sidecar_session,
                haystack,
                SearchWindow::full(haystack),
                u64::MAX / 4,
            ),
            Err(crate::SearchError::K0(K0SearchError::InvalidResumeState { .. }))
        ));
        assert!(matches!(
            SearchSession::try_new(
                &first_sidecar,
                &second_full,
                &second_primary,
                SearchSessionLimits::unlimited(),
            ),
            Err(K0SearchError::InvalidResumeState { .. })
        ));
    }

    #[test]
    fn transplanted_policy_state_cannot_change_cross_plan_results() {
        let mut first = RouteState::default();
        let Route::Learn { class_index } = first.select(512) else {
            panic!("fresh size class must learn the incumbent");
        };
        first.observe_incumbent(class_index, 512, 16_384);
        let mut transplanted = first;
        let Route::Candidate {
            incumbent_work, ..
        } = transplanted.select(512)
        else {
            panic!("learned state must select a candidate trial");
        };
        let mut haystack = vec![b'x'; 512];
        haystack[..6].copy_from_slice(b"rwxyzQ");
        assert!(matches!(
            attempt(
                "r+(?:wxyz|xy)Q",
                false,
                &haystack,
                SearchWindow::full(&haystack),
                incumbent_work,
            ),
            Attempt::Complete { output: true, .. }
        ));
    }

    #[test]
    fn resource_decline_keeps_full_k0_authoritative() {
        let (full, sidecar) = plans("q+(?:abcd|bc)Z", false);
        assert!(K0SearchSession::try_new_reverse_required(
            sidecar.prefix(),
            SearchSessionLimits {
                max_setup_work: 0,
                max_scratch_bytes: 0,
            },
        )
        .unwrap()
        .is_none());

        let mut full_session = K0SearchSession::new_selected(
            &full,
            SearchSessionLimits::unlimited(),
            true,
            true,
        )
        .unwrap();
        let mut sidecar_session = SearchSession::try_new(
            &sidecar,
            &full,
            &full_session,
            SearchSessionLimits::unlimited(),
        )
        .unwrap()
        .unwrap();
        let haystack = b"qabcdZ";
        assert_eq!(
            try_exists(
                &mut full_session,
                &mut sidecar_session,
                haystack,
                SearchWindow::full(haystack),
                1,
            )
            .unwrap(),
            Attempt::Fallback
        );
        assert!(full_session
            .search_exists_value(
                haystack,
                SearchWindow::full(haystack),
                SearchLimits::unlimited(),
            )
            .unwrap());
    }

    #[test]
    fn search_session_limits_decline_but_owner_allocation_failure_propagates() {
        let (full, sidecar) = plans("q+(?:abcd|bc)Z", false);
        let mut primary = K0SearchSession::new_selected(
            &full,
            SearchSessionLimits::unlimited(),
            true,
            true,
        )
        .unwrap();
        assert!(SearchSession::try_new(
            &sidecar,
            &full,
            &primary,
            SearchSessionLimits {
                max_setup_work: 0,
                max_scratch_bytes: usize::MAX,
            },
        )
        .unwrap()
        .is_none());
        assert!(SearchSession::try_new(
            &sidecar,
            &full,
            &primary,
            SearchSessionLimits {
                max_setup_work: u64::MAX,
                max_scratch_bytes: SearchSession::owner_bytes().saturating_sub(1),
            },
        )
        .unwrap()
        .is_none());
        let failure = SearchSession::try_new_with(
            &sidecar,
            &full,
            &primary,
            SearchSessionLimits::unlimited(),
            |session| {
                Err((
                    fre_exact_alloc::CopyError::AllocationFailed,
                    session,
                ))
            },
        );
        assert!(matches!(
            failure,
            Err(K0SearchError::ScratchAllocationFailed { requested })
                if requested == SearchSession::owner_bytes()
        ));
        // The failed optional owner never publishes state into the primary.
        assert!(primary
            .search_exists_value(
                b"qabcdZ",
                SearchWindow::new(0, 6),
                SearchLimits::unlimited(),
            )
            .unwrap());
    }

    #[test]
    fn component_build_receipts_close_exact_and_one_below_limits() {
        let pattern = "q+[0-9]+(?:abcd|bc)Z";
        let (rust, limits, line_terminator) = parsed_with(pattern, false);
        let full = full_automaton(&rust, limits, line_terminator);
        let InspectionOutcome::Eligible(inspection) =
            inspect(&rust.hir, 0, 17, u64::MAX).unwrap()
        else {
            panic!("fixture must be eligible");
        };
        assert_eq!(inspection.prefix_parts.len(), 2);
        let expected_prefix_lowering = fre_lower::lower_hir_concat_slice(
            inspection.prefix_parts,
            fre_lower::OperationSemantics::CaptureFree,
            limits.lowering,
        )
        .expect("borrowed prefix lowers independently")
        .stats();
        let cumulative_planner_work = inspection.planner_work;
        let plan = inspection
            .build(&full, line_terminator, limits, usize::MAX)
            .unwrap()
            .unwrap();
        let accounting = plan.build_accounting();
        assert_eq!(accounting.cumulative_planner_work, cumulative_planner_work);
        assert!(accounting.literal_set.build_work_upper_bound > 0);
        assert_eq!(accounting.prefix_lowering, expected_prefix_lowering);
        assert_eq!(accounting.prefix_lowering.erased_captures(), 0);
        assert_eq!(
            accounting.prefix_storage_bytes,
            plan.prefix().stats().storage_bytes(),
        );

        let (rust, mut exact_limits, line_terminator) = parsed_with(pattern, false);
        let full = full_automaton(&rust, exact_limits, line_terminator);
        exact_limits.literal_set.max_build_work = accounting.literal_set.build_work_upper_bound;
        exact_limits.lowering.max_work = accounting.prefix_lowering.work();
        let InspectionOutcome::Eligible(inspection) =
            inspect(&rust.hir, 0, 0, u64::MAX).unwrap()
        else {
            panic!("fixture must stay eligible");
        };
        assert!(inspection
            .build(&full, line_terminator, exact_limits, usize::MAX)
            .unwrap()
            .is_some());

        let (rust, mut literal_limited, line_terminator) = parsed_with(pattern, false);
        let full = full_automaton(&rust, literal_limited, line_terminator);
        literal_limited.literal_set.max_build_work = accounting
            .literal_set
            .build_work_upper_bound
            .checked_sub(1)
            .unwrap();
        let InspectionOutcome::Eligible(inspection) =
            inspect(&rust.hir, 0, 0, u64::MAX).unwrap()
        else {
            panic!("fixture must stay eligible");
        };
        assert!(inspection
            .build(&full, line_terminator, literal_limited, usize::MAX)
            .unwrap()
            .is_none());

        let (rust, mut lowering_limited, line_terminator) = parsed_with(pattern, false);
        let full = full_automaton(&rust, lowering_limited, line_terminator);
        lowering_limited.lowering.max_work = accounting
            .prefix_lowering
            .work()
            .checked_sub(1)
            .unwrap();
        let InspectionOutcome::Eligible(inspection) =
            inspect(&rust.hir, 0, 0, u64::MAX).unwrap()
        else {
            panic!("fixture must stay eligible");
        };
        assert!(inspection
            .build(&full, line_terminator, lowering_limited, usize::MAX)
            .unwrap()
            .is_none());
    }

    #[test]
    fn plan_owner_allocation_failure_propagates_after_component_builds() {
        let (rust, limits, line_terminator) = parsed_with("q+(?:abcd|bc)Z", false);
        let full = full_automaton(&rust, limits, line_terminator);
        let InspectionOutcome::Eligible(inspection) =
            inspect(&rust.hir, 0, 0, u64::MAX).unwrap()
        else {
            panic!("fixture must be eligible");
        };
        let failure = inspection.build_with(
            &full,
            line_terminator,
            limits,
            usize::MAX,
            |plan| Err((fre_exact_alloc::CopyError::AllocationFailed, plan)),
        );
        assert!(matches!(
            failure,
            Err(BuildError::AllocationFailed {
                structure: "reverse-inner sidecar owner",
                additional: 1,
            })
        ));
        // The already-live authoritative full plan remains independently
        // usable, but callers cannot publish a false successful build receipt.
        let mut primary = K0SearchSession::new_selected(
            &full,
            SearchSessionLimits::unlimited(),
            true,
            true,
        )
        .unwrap();
        assert!(primary
            .search_exists_value(
                b"qabcdZ",
                SearchWindow::new(0, 6),
                SearchLimits::unlimited(),
            )
            .unwrap());
    }

    #[test]
    fn persistent_census_accepts_exact_and_refuses_one_below() {
        let pattern = "q+[0-9]+(?:abcd|bc)Z";
        let (rust, limits, line_terminator) = parsed_with(pattern, false);
        let full = full_automaton(&rust, limits, line_terminator);
        let inspection = match inspect(&rust.hir, 0, 0, u64::MAX).unwrap() {
            InspectionOutcome::Eligible(inspection) => inspection,
            InspectionOutcome::Ineligible { .. } => panic!("fixture must be eligible"),
        };
        let plan = inspection
            .build(&full, line_terminator, limits, usize::MAX)
            .unwrap()
            .unwrap();
        let exact = plan.build_accounting().persistent_bytes;

        let (rust, limits, line_terminator) = parsed_with(pattern, false);
        let full = full_automaton(&rust, limits, line_terminator);
        let InspectionOutcome::Eligible(inspection) =
            inspect(&rust.hir, 0, 0, u64::MAX).unwrap()
        else {
            panic!("fixture must stay eligible");
        };
        assert!(inspection
            .build(&full, line_terminator, limits, exact)
            .unwrap()
            .is_some());
        let (rust, limits, line_terminator) = parsed_with(pattern, false);
        let full = full_automaton(&rust, limits, line_terminator);
        let InspectionOutcome::Eligible(inspection) =
            inspect(&rust.hir, 0, 0, u64::MAX).unwrap()
        else {
            panic!("fixture must stay eligible");
        };
        assert!(inspection
            .build(&full, line_terminator, limits, exact - 1)
            .unwrap()
            .is_none());
    }

    #[test]
    fn absolute_end_proof_excludes_reverse_inner_from_plan_and_session() {
        let regex = PortableBuilder::new(r"[a-z]+(?:needle|marker)[0-9]+\z")
            .unicode(false)
            .build()
            .expect("absolute-end reverse-inner shape builds");
        let PortablePlan::K0(plan) = &regex.plan else {
            panic!("absolute-end fixture must retain generic K0");
        };
        assert!(plan.absolute_end_proof.is_some());
        assert!(plan.correlated_terminal().is_none());
        assert!(plan.reverse_inner.is_none());

        let mut session = regex
            .search_session(SearchSessionLimits::unlimited())
            .expect("absolute-end fixture session constructs");
        let PortableSearchSessionPlan::K0 {
            session: primary,
            aggregate_setup,
            reverse_inner,
            ..
        } = &session.plan
        else {
            panic!("absolute-end session must retain K0");
        };
        assert!(reverse_inner.is_none());
        assert_eq!(*aggregate_setup, primary.construction_accounting());

        let haystack = b"xxabcneedle123";
        assert!(session
            .is_match_window_value(
                haystack,
                SearchWindow::full(haystack),
                SearchLimits::unlimited(),
            )
            .unwrap());
        assert!(!session
            .is_match_window_value(
                haystack,
                SearchWindow::new(0, haystack.len() - 1),
                SearchLimits::unlimited(),
            )
            .unwrap());
    }

    #[test]
    fn facade_retains_the_sidecar_only_for_full_reused_sessions() {
        let regex = PortableBuilder::new("[a-z]+(?:needle|marker)[0-9]+")
            .unicode(false)
            .build()
            .expect("general reverse-inner fixture builds");
        let PortablePlan::K0(plan) = &regex.plan else {
            panic!("general reverse-inner fixture must retain generic K0");
        };
        assert!(plan.absolute_end_proof.is_none());
        assert!(plan.reverse_inner.is_some());

        let endpoint = regex
            .endpoint_search_session(SearchSessionLimits::unlimited())
            .unwrap();
        let PortableSearchSessionPlan::K0 { reverse_inner, .. } = &endpoint.plan else {
            panic!("endpoint fixture must retain K0");
        };
        assert!(reverse_inner.is_none());

        let mut session = regex
            .search_session(SearchSessionLimits::unlimited())
            .unwrap();
        let PortableSearchSessionPlan::K0 {
            session: primary,
            k0_plan,
            reverse_inner,
            aggregate_setup,
            ..
        } = &session.plan
        else {
            panic!("reused fixture must retain K0");
        };
        let reverse_inner = reverse_inner
            .as_ref()
            .expect("full reused session retains its boxed sidecar");
        assert!(core::ptr::eq(reverse_inner.full, &k0_plan.automaton));
        assert_eq!(
            reverse_inner.plan.full_automaton_identity,
            k0_plan.automaton.identity(),
        );
        let primary_setup = primary.construction_accounting();
        let prefix_setup = reverse_inner.prefix_session().construction_accounting();
        assert_eq!(
            aggregate_setup.work(),
            primary_setup
                .work()
                .checked_add(prefix_setup.work())
                .and_then(|work| work.checked_add(SearchSession::owner_publication_work()))
                .unwrap(),
        );
        assert_eq!(
            aggregate_setup.retained_bytes(),
            primary_setup
                .retained_bytes()
                .checked_add(prefix_setup.retained_bytes())
                .and_then(|bytes| bytes.checked_add(SearchSession::owner_bytes()))
                .unwrap(),
        );
        assert_eq!(
            aggregate_setup.allocated_bytes(),
            primary_setup
                .allocated_bytes()
                .checked_add(prefix_setup.allocated_bytes())
                .and_then(|bytes| bytes.checked_add(SearchSession::owner_bytes()))
                .unwrap(),
        );
        assert_eq!(
            aggregate_setup.initialized_bytes(),
            primary_setup
                .initialized_bytes()
                .checked_add(prefix_setup.initialized_bytes())
                .and_then(|bytes| bytes.checked_add(SearchSession::owner_bytes()))
                .unwrap(),
        );
        let exact_limits = SearchSessionLimits {
            max_setup_work: aggregate_setup.work(),
            max_scratch_bytes: aggregate_setup.retained_bytes(),
        };
        let exact_session = regex
            .search_session(exact_limits)
            .expect("exact aggregate session limits admit both owners");
        let PortableSearchSessionPlan::K0 {
            session: exact_primary,
            aggregate_setup: exact_setup,
            reverse_inner: Some(_),
            ..
        } = &exact_session.plan
        else {
            panic!("exact aggregate limits must retain the sidecar");
        };
        // A finite setup-work cap can decline an optional root-run inspection
        // whose conservative prospective envelope fit under the unlimited
        // construction. The same primary and sidecar storage must remain
        // admitted, while actual setup work may consequently decrease.
        assert!(exact_setup.work() <= aggregate_setup.work());
        assert_eq!(
            exact_setup.retained_bytes(),
            aggregate_setup.retained_bytes()
        );
        assert_eq!(
            exact_setup.allocated_bytes(),
            aggregate_setup.allocated_bytes()
        );
        assert_eq!(
            exact_setup.initialized_bytes(),
            aggregate_setup.initialized_bytes()
        );

        let exact_primary_setup = exact_primary.construction_accounting();
        assert!(exact_primary_setup.work() < exact_limits.max_setup_work);
        let one_below = regex
            .search_session(SearchSessionLimits {
                // This leaves zero work after the primary receipt, one below
                // even the sidecar owner's mandatory publication charge.
                max_setup_work: exact_primary_setup.work(),
                max_scratch_bytes: exact_limits.max_scratch_bytes,
            })
            .expect("optional sidecar decline preserves the primary session");
        let PortableSearchSessionPlan::K0 {
            session: one_below_primary,
            aggregate_setup: one_below_setup,
            reverse_inner: None,
            ..
        } = &one_below.plan
        else {
            panic!("one-below setup work must decline only the optional sidecar");
        };
        assert_eq!(*one_below_setup, one_below_primary.construction_accounting());

        let mut haystack = vec![b'0'; 4_096];
        haystack[128..135].copy_from_slice(b"needleX");
        haystack[4_084..4_096].copy_from_slice(b"abcmarker123");
        assert!(session
            .is_match_value(&haystack, SearchLimits::unlimited())
            .unwrap());
        assert!(session
            .is_match_value(&haystack, SearchLimits::unlimited())
            .unwrap());
    }

    #[test]
    fn facade_retains_and_executes_a_later_split_sidecar() {
        let mut regex = PortableBuilder::new("q+[0-9]+(?:needle|marker)[A-Z]+")
            .unicode(false)
            .build()
            .expect("later-split facade fixture builds");
        let PortablePlan::K0(plan) = &mut regex.plan else {
            panic!("later-split fixture must retain generic K0");
        };
        assert!(plan.reverse_inner.is_some());
        plan.mandatory_suffix = None;
        plan.mandatory_cut = None;
        plan.negative_prefilter = None;

        let mut session = regex
            .search_session(SearchSessionLimits::unlimited())
            .expect("later-split facade session constructs");
        let mut haystack = vec![b'!'; 512];
        assert!(!session
            .is_match_value(&haystack, SearchLimits::unlimited())
            .unwrap());
        haystack[400..411].copy_from_slice(b"qq12needleA");
        assert!(session
            .is_match_value(&haystack, SearchLimits::unlimited())
            .unwrap());
        assert!(session
            .is_match_value(&haystack, SearchLimits::unlimited())
            .unwrap());
    }

    #[test]
    fn facade_rescans_same_address_mutation_without_retained_source_state() {
        let mut regex = PortableBuilder::new("[a-z]+(?:needle|marker)[0-9]+")
            .unicode(false)
            .build()
            .expect("facade mutation fixture builds");
        let PortablePlan::K0(plan) = &mut regex.plan else {
            panic!("facade mutation fixture must retain generic K0");
        };
        assert!(plan.reverse_inner.is_some());
        plan.mandatory_suffix = None;
        plan.mandatory_cut = None;
        plan.negative_prefilter = None;

        let mut session = regex
            .search_session(SearchSessionLimits::unlimited())
            .expect("facade mutation session constructs");
        let mut haystack = vec![b'!'; 512];
        let address = haystack.as_ptr();
        assert!(!session
            .is_match_window_value(
                &haystack,
                SearchWindow::full(&haystack),
                SearchLimits::unlimited(),
            )
            .unwrap());
        assert!(!session
            .is_match_window_value(
                &haystack,
                SearchWindow::full(&haystack),
                SearchLimits::unlimited(),
            )
            .unwrap());

        haystack[100..108].copy_from_slice(b"aneedle1");
        assert_eq!(haystack.as_ptr(), address);
        assert!(session
            .is_match_window_value(
                &haystack,
                SearchWindow::full(&haystack),
                SearchLimits::unlimited(),
            )
            .unwrap());
        haystack[100..108].fill(b'!');
        assert_eq!(haystack.as_ptr(), address);
        assert!(!session
            .is_match_window_value(
                &haystack,
                SearchWindow::full(&haystack),
                SearchLimits::unlimited(),
            )
            .unwrap());
    }

    fn bounded_facade_composition_fixture() -> crate::PortableRegex {
        // Spell every finite run without repetition combinators so the
        // fixture's selected graph cut structurally retains the finite root
        // distance required by the composition test below.
        let pattern =
            r"(?:[a-h][a-h]|[m-z][m-z][m-z])(?:ca|delta|echo777|foxtrot99)(?:_[A-Z][A-Z]|:[0-9][0-9][0-9])Z";
        let regex = PortableBuilder::new(pattern)
            .unicode(false)
            .build()
            .expect("bounded facade-composition fixture builds");
        let PortablePlan::K0(plan) = &regex.plan else {
            panic!("bounded facade-composition fixture must retain generic K0");
        };
        assert!(plan.absolute_end_proof.is_none());
        assert!(plan.correlated_terminal().is_none());
        assert!(plan.reverse_inner.is_some());
        regex
    }

    #[test]
    fn finite_suffix_precedes_reverse_inner_for_its_fresh_size_class() {
        let regex = bounded_facade_composition_fixture();
        let PortablePlan::K0(plan) = &regex.plan else {
            unreachable!("fixture routing was checked during construction");
        };
        let suffix = plan
            .mandatory_suffix
            .as_ref()
            .expect("bounded fixture retains its mandatory suffix");
        assert!(suffix.finite_exists_maximum_match_bytes().is_some());

        let mut session = regex
            .search_session(SearchSessionLimits::unlimited())
            .expect("bounded facade-composition session constructs");
        let initial_reverse = match &session.plan {
            PortableSearchSessionPlan::K0 {
                reverse_inner: Some(reverse_inner),
                ..
            } => reverse_inner.staged_exists_route_state(),
            _ => panic!("full bounded K0 session must retain reverse-inner state"),
        };
        let haystack = vec![b'x'; 4_096];
        assert!(!session
            .is_match_window_value(
                &haystack,
                SearchWindow::full(&haystack),
                SearchLimits::unlimited(),
            )
            .unwrap());
        let PortableSearchSessionPlan::K0 {
            reverse_inner: Some(reverse_inner),
            mandatory_suffix_exists_state,
            ..
        } = &session.plan
        else {
            panic!("bounded K0 session lost composition state");
        };
        assert_eq!(reverse_inner.staged_exists_route_state(), initial_reverse);
        assert_ne!(
            *mandatory_suffix_exists_state,
            K0NegativePrefilterState::default(),
        );
    }

    #[test]
    fn candidate_floor_skips_reverse_while_no_floor_publishes_transactionally() {
        let mut floored = bounded_facade_composition_fixture();
        let (cut, bytes, count) = {
            let PortablePlan::K0(plan) = &mut floored.plan else {
                unreachable!("fixture routing was checked during construction");
            };
            plan.mandatory_suffix = None;
            plan.negative_prefilter = None;
            let cut = plan
                .mandatory_cut
                .expect("bounded fixture retains its mandatory cut");
            assert!(matches!(
                cut.maximum_before_root(),
                crate::MaximumConsumedDistance::Finite(_)
            ));
            let (bytes, count) = cut.bytes();
            (cut, bytes, count)
        };
        let mut haystack = vec![b'x'; 4_096];
        for (offset, byte) in bytes[..usize::from(count)].iter().copied().enumerate() {
            haystack[3_072 + offset] = byte;
        }
        let window = SearchWindow::full(&haystack);
        let floor_attempt = crate::run_k0_negative_prefilter(
            Some(&cut),
            None,
            K0NegativePrefilterState::default(),
            &haystack,
            window,
            SearchLimits::unlimited(),
        );
        assert!(floor_attempt.candidate_floor.is_some());

        let mut floored_session = floored
            .search_session(SearchSessionLimits::unlimited())
            .expect("floored composition session constructs");
        let floor_reverse_before = match &floored_session.plan {
            PortableSearchSessionPlan::K0 {
                reverse_inner: Some(reverse_inner),
                ..
            } => reverse_inner.staged_exists_route_state(),
            _ => panic!("floored full session must retain reverse-inner state"),
        };
        assert!(!floored_session
            .is_match_window_value(&haystack, window, SearchLimits::unlimited())
            .unwrap());
        let floor_reverse_after = match &floored_session.plan {
            PortableSearchSessionPlan::K0 {
                reverse_inner: Some(reverse_inner),
                ..
            } => reverse_inner.staged_exists_route_state(),
            _ => unreachable!("session plan is immutable"),
        };
        assert_eq!(floor_reverse_after, floor_reverse_before);

        let mut no_floor = bounded_facade_composition_fixture();
        let PortablePlan::K0(plan) = &mut no_floor.plan else {
            unreachable!("fixture routing was checked during construction");
        };
        plan.mandatory_suffix = None;
        plan.mandatory_cut = None;
        plan.negative_prefilter = None;
        let mut no_floor_session = no_floor
            .search_session(SearchSessionLimits::unlimited())
            .expect("no-floor composition session constructs");
        let route_before = match &no_floor_session.plan {
            PortableSearchSessionPlan::K0 {
                reverse_inner: Some(reverse_inner),
                ..
            } => reverse_inner.staged_exists_route_state(),
            _ => panic!("no-floor full session must retain reverse-inner state"),
        };
        assert!(!no_floor_session
            .is_match_window_value(&haystack, window, SearchLimits::unlimited())
            .unwrap());
        let learned = match &no_floor_session.plan {
            PortableSearchSessionPlan::K0 {
                reverse_inner: Some(reverse_inner),
                ..
            } => reverse_inner.staged_exists_route_state(),
            _ => unreachable!("session plan is immutable"),
        };
        assert_ne!(learned, route_before);
        assert!(!no_floor_session
            .is_match_window_value(&haystack, window, SearchLimits::unlimited())
            .unwrap());
        let completed = match &no_floor_session.plan {
            PortableSearchSessionPlan::K0 {
                reverse_inner: Some(reverse_inner),
                ..
            } => reverse_inner.staged_exists_route_state(),
            _ => unreachable!("session plan is immutable"),
        };
        assert_ne!(completed, learned);

        let forced_fallback = {
            let mut state = RouteState::default();
            let Route::Learn { class_index } = state.select(haystack.len()) else {
                panic!("fresh fallback class must learn");
            };
            state.observe_incumbent(class_index, haystack.len(), 1);
            state
        };
        let PortableSearchSessionPlan::K0 {
            reverse_inner: Some(reverse_inner),
            ..
        } = &mut no_floor_session.plan
        else {
            unreachable!("session plan is immutable");
        };
        reverse_inner.publish_exists_route_state(forced_fallback);
        assert!(!no_floor_session
            .is_match_window_value(&haystack, window, SearchLimits::unlimited())
            .unwrap());
        let fallback_published = match &no_floor_session.plan {
            PortableSearchSessionPlan::K0 {
                reverse_inner: Some(reverse_inner),
                ..
            } => reverse_inner.staged_exists_route_state(),
            _ => unreachable!("session plan is immutable"),
        };
        assert_ne!(fallback_published, forced_fallback);

        let state_before_error = match &no_floor_session.plan {
            PortableSearchSessionPlan::K0 {
                reverse_inner: Some(reverse_inner),
                mandatory_suffix_exists_state,
                negative_prefilter_exists_state,
                ..
            } => (
                reverse_inner.staged_exists_route_state(),
                *mandatory_suffix_exists_state,
                *negative_prefilter_exists_state,
            ),
            _ => unreachable!("session plan is immutable"),
        };
        assert!(no_floor_session
            .is_match_window_value(
                &haystack,
                window,
                SearchLimits {
                    max_work: 0,
                    max_scratch_bytes: usize::MAX,
                },
            )
            .is_err());
        let state_after_error = match &no_floor_session.plan {
            PortableSearchSessionPlan::K0 {
                reverse_inner: Some(reverse_inner),
                mandatory_suffix_exists_state,
                negative_prefilter_exists_state,
                ..
            } => (
                reverse_inner.staged_exists_route_state(),
                *mandatory_suffix_exists_state,
                *negative_prefilter_exists_state,
            ),
            _ => unreachable!("session plan is immutable"),
        };
        assert_eq!(state_after_error, state_before_error);
    }

    #[test]
    fn boxed_secondary_owner_keeps_hot_layout_growth_bounded() {
        #[allow(dead_code)]
        struct PortableK0PlanBeforeReverseInner {
            automaton: Automaton,
            absolute_end_proof: Option<crate::K0AbsoluteEndProof>,
            exclusive: crate::K0ExclusivePlan,
            reverse_inner: Option<Box<Plan>>,
            mandatory_suffix: Option<K0MandatorySuffixPlan>,
            mandatory_cut: Option<K0MandatoryCutPlan>,
            negative_prefilter: Option<Box<K0NegativePrefilterPlan>>,
        }

        #[allow(dead_code, clippy::large_enum_variant)]
        enum PortableSearchSessionPlanBeforeReverseInner<'a> {
            Native(&'a crate::PortableRegex),
            K0 {
                session: K0SearchSession<'a>,
                k0_plan: &'a crate::PortableK0Plan,
                mandatory_suffix: Option<&'a K0MandatorySuffixPlan>,
                mandatory_cut: Option<&'a K0MandatoryCutPlan>,
                negative_prefilter: Option<&'a K0NegativePrefilterPlan>,
                mandatory_suffix_exists_state: K0NegativePrefilterState,
                mandatory_suffix_span_state: K0NegativePrefilterState,
                negative_prefilter_exists_state: K0NegativePrefilterState,
                negative_prefilter_span_state: K0NegativePrefilterState,
                exclusive_route_state: crate::K0ExclusiveRouteState,
            },
        }

        let plan_growth = core::mem::size_of::<crate::PortableK0Plan>()
            .saturating_sub(core::mem::size_of::<PortableK0PlanBeforeReverseInner>());
        assert!(
            plan_growth == 0,
            "the ordinary-search pool may not grow the immutable K0 facade: growth={plan_growth}, current={}, baseline={}",
            core::mem::size_of::<crate::PortableK0Plan>(),
            core::mem::size_of::<PortableK0PlanBeforeReverseInner>(),
        );
        let session_growth = core::mem::size_of::<PortableSearchSessionPlan<'static>>()
            .saturating_sub(core::mem::size_of::<
                PortableSearchSessionPlanBeforeReverseInner<'static>,
            >());
        let boxed_sidecar_and_receipt =
            core::mem::size_of::<Option<Box<SearchSession<'static>>>>()
                .checked_add(core::mem::size_of::<
                    crate::SearchSessionSetupAccounting,
                >())
                .and_then(|bytes| {
                    bytes.checked_add(
                        core::mem::align_of::<PortableSearchSessionPlan<'static>>()
                            .saturating_sub(1),
                    )
                })
                .unwrap();
        assert!(
            session_growth <= boxed_sidecar_and_receipt,
            "the facade session may grow only by one sidecar pointer, its aggregate receipt, \
             and alignment padding",
        );
        assert!(
            session_growth < core::mem::size_of::<K0SearchSession<'static>>(),
            "the hot facade session must not embed its secondary K0 owner inline",
        );
        assert_eq!(
            core::mem::size_of::<Option<Box<SearchSession<'static>>>>(),
            core::mem::size_of::<usize>(),
        );
    }
}
