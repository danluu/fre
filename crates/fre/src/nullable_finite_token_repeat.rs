//! Direct search for a nullable bounded finite-token prefix and required tail.
//!
//! The admitted HIR is exactly `(?:T0|...|Tn){0,max} S`, where every token
//! and `S` are nonempty exact byte literals. The first byte of `S` must occur
//! nowhere in any token. This tail-head barrier means a repeated token cannot
//! cross an earlier occurrence of `S`: the first literal hit is therefore the
//! endpoint selected by both upstream shortest search and leftmost-first
//! search.
//!
//! Span recovery is bounded independently of the number of finite strings.
//! A reverse trie recognizes tokens ending at each reachable boundary, while
//! one bitset per byte offset carries every feasible repetition count in
//! parallel. The furthest reachable boundary is the leftmost match start.
//! Alternation priority and repetition greediness can only distinguish paths
//! with that same start and tail endpoint under the barrier. Portable match
//! operations erase those capture histories, while explicit capture reads
//! retain their existing typed refusal.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "unchecked indexing and shifts stay within admitted fixed domains"
)]

use fre_exact_alloc::{CopyError, ExactVec};
use fre_kernels::{LiteralBuildLimits, LiteralError, LiteralPlan, LiteralSearchLimits};
use regex_syntax::hir::{Hir, HirKind};

use crate::nullable_optional_chain::{Accounting, Error, Operation};
use crate::{BuildError, Match, SearchLimits, SearchWindow, charge_planner, reserve_planner};

pub const PLAN_ID: &str = "nullable-finite-token-repeat-required-tail.reverse-trie.v1";

const MAX_TOKENS: usize = 32;
const MAX_TOKEN_BYTES: usize = 64;
const MAX_TOTAL_TOKEN_BYTES: usize = 256;
const MAX_REPETITIONS: usize = 63;
const MAX_PREFIX_BYTES: usize = 512;
const NO_TERMINAL: u8 = u8::MAX;
const SHORT_PREFIX_BYTES: usize = 16;
const SHORT_REACHABILITY_CELLS: usize = SHORT_PREFIX_BYTES + 1;
const SHORT_REACHABILITY_SCRATCH_BYTES: usize =
    core::mem::size_of::<[u64; SHORT_REACHABILITY_CELLS]>();
const REACHABILITY_CELLS: usize = MAX_PREFIX_BYTES + 1;
const REACHABILITY_SCRATCH_BYTES: usize =
    core::mem::size_of::<[u64; REACHABILITY_CELLS]>();

#[derive(Clone, Copy, Debug)]
struct TrieNode {
    first_edge: u16,
    edge_count: u8,
    first_source_token: u8,
}

#[derive(Clone, Copy, Debug)]
struct TrieEdge {
    byte: u8,
    target: u16,
}

struct BuildNode {
    first_edge: Option<usize>,
    first_source_token: Option<u8>,
}

struct BuildEdge {
    byte: u8,
    target: usize,
    next: Option<usize>,
}

struct TrieBuilder {
    nodes: Vec<BuildNode>,
    edges: Vec<BuildEdge>,
}

pub(crate) struct Inspection {
    nodes: Vec<TrieNode>,
    edges: Vec<TrieEdge>,
    token_count: usize,
    maximum_repetitions: usize,
    maximum_token_bytes: usize,
    maximum_prefix_bytes: usize,
    tail: Vec<u8>,
    planner_work: u64,
}

pub(crate) enum InspectionOutcome {
    Eligible(Inspection),
    Ineligible { planner_work: u64 },
}

impl InspectionOutcome {
    pub(crate) const fn planner_work(&self) -> u64 {
        match self {
            Self::Eligible(inspection) => inspection.planner_work,
            Self::Ineligible { planner_work } => *planner_work,
        }
    }
}

#[derive(Debug)]
pub(crate) struct Plan {
    nodes: ExactVec<TrieNode>,
    edges: ExactVec<TrieEdge>,
    token_count: u8,
    maximum_repetitions: u8,
    maximum_token_bytes: u8,
    maximum_prefix_bytes: u16,
    tail: LiteralPlan,
}

#[derive(Default)]
struct Actual {
    candidate_visits: usize,
    finder_calls: usize,
    finder_linear_terms: u64,
    backward_steps: usize,
    replay_cells: usize,
    scratch_bytes: usize,
}

impl Inspection {
    pub(crate) fn plan_storage_bytes(&self) -> Result<usize, BuildError> {
        projected_plan_storage_bytes(self.nodes.len(), self.edges.len(), self.tail.len())
    }

    pub(crate) fn build(self, limits: LiteralBuildLimits) -> Result<Plan, fre_kernels::LiteralError> {
        let nodes = retain_exact(self.nodes, "finite-token trie nodes")?;
        let edges = retain_exact(self.edges, "finite-token trie edges")?;
        let tail = LiteralPlan::new(&self.tail, limits)?;
        Ok(Plan {
            nodes,
            edges,
            token_count: u8::try_from(self.token_count)
                .expect("admitted finite token count fits u8"),
            maximum_repetitions: u8::try_from(self.maximum_repetitions)
                .expect("admitted finite repetition maximum fits u8"),
            maximum_token_bytes: u8::try_from(self.maximum_token_bytes)
                .expect("admitted finite token length fits u8"),
            maximum_prefix_bytes: u16::try_from(self.maximum_prefix_bytes)
                .expect("admitted finite prefix horizon fits u16"),
            tail,
        })
    }
}

impl Plan {
    pub(crate) fn storage_bytes(&self) -> Result<usize, BuildError> {
        projected_plan_storage_bytes(
            self.nodes.len(),
            self.edges.len(),
            self.tail.storage_bytes(),
        )
    }

    /// Try the Rust-compatible full-input existence projection without
    /// constructing the facade's diagnostic execution counters.
    ///
    /// The outer `Option` declines before source access whenever the
    /// canonical literal-only work expression is not representable. The
    /// ordinary facade then replays the unchanged checked path and preserves
    /// its exact error chronology.
    #[inline]
    pub(crate) fn is_match_full_unlimited_value(
        &self,
        haystack: &[u8],
    ) -> Option<Result<bool, Error>> {
        ordinary_exists_work_is_representable(haystack.len(), self.tail.needle().len())?;
        Some(
            self.tail
                .find(haystack, LiteralSearchLimits::unlimited())
                .map(|(matched, _)| matched.is_some())
                .map_err(Error::from),
        )
    }

    pub(crate) fn is_match_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(bool, Accounting), Error> {
        let (tail, actual, upper) = self.first_tail(haystack, window, limits)?;
        let accounting = self.accounting(Operation::Exists, window, actual, upper)?;
        Ok((tail.is_some(), accounting))
    }

    pub(crate) fn is_match_window_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<bool, Error> {
        self.first_tail(haystack, window, limits)
            .map(|(tail, _, _)| tail.is_some())
    }

    pub(crate) fn earliest_end_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, Accounting), Error> {
        let (tail, actual, upper) = self.first_tail(haystack, window, limits)?;
        let accounting = self.accounting(Operation::EarliestEnd, window, actual, upper)?;
        Ok((tail.map(|(_, end)| end), accounting))
    }

    pub(crate) fn earliest_end_window_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<Option<usize>, Error> {
        self.first_tail(haystack, window, limits)
            .map(|(tail, _, _)| tail.map(|(_, end)| end))
    }

    pub(crate) fn selected_end_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, Accounting), Error> {
        let (matched, actual, upper) = self.search_span(haystack, window, limits)?;
        let accounting = self.accounting(Operation::SelectedEnd, window, actual, upper)?;
        Ok((matched.map(|matched| matched.end), accounting))
    }

    pub(crate) fn find_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, Accounting), Error> {
        let (matched, actual, upper) = self.search_span(haystack, window, limits)?;
        let accounting = self.accounting(Operation::Span, window, actual, upper)?;
        Ok((matched, accounting))
    }

    pub(crate) fn find_window_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<Option<Match>, Error> {
        self.search_span(haystack, window, limits)
            .map(|(matched, _, _)| matched)
    }

    /// Execute the ordinary full-input span projection. Shape dispatch is
    /// deliberately deferred until after a tail hit so the common miss path
    /// retains the incumbent work and branch structure.
    pub(crate) fn find_full_ordinary_value(
        &self,
        haystack: &[u8],
    ) -> Result<Option<Match>, Error> {
        let window = SearchWindow::full(haystack);
        validate_window(haystack, window)?;
        let upper = self.work_upper_bound(window)?;
        enforce_work(upper, SearchLimits::unlimited())?;
        enforce_scratch(REACHABILITY_SCRATCH_BYTES, SearchLimits::unlimited())?;
        let mut actual = Actual::default();
        let Some((tail_start, tail_end)) =
            self.find_tail(haystack, window.start(), window.end(), &mut actual)?
        else {
            return Ok(None);
        };
        actual.candidate_visits = 1;
        let start = if self.maximum_repetitions == 1 && self.token_count == 1 {
            self.ordinary_single_token_start(haystack, tail_start)?
        } else if self.token_count == 1 {
            self.ordinary_repeated_single_token_start(haystack, tail_start)?
        } else {
            self.earliest_start_for_tail_dispatch(
                haystack,
                window.start(),
                tail_start,
                &mut actual,
            )?
        };
        Ok(Some(Match {
            start,
            end: tail_end,
        }))
    }

    #[inline(never)]
    fn ordinary_single_token_start(
        &self,
        haystack: &[u8],
        tail_start: usize,
    ) -> Result<usize, Error> {
        let token_bytes = usize::from(self.maximum_token_bytes);
        let walk_limit = tail_start.min(token_bytes);
        let edges = match self.edges.get(..walk_limit) {
            Some(edges) => edges,
            None => {
                return Err(Error::InternalInvariant {
                    detail: "finite-token linear trie escaped its edge pool",
                });
            }
        };
        for (offset, edge) in edges.iter().enumerate() {
            if edge.byte != haystack[tail_start - offset - 1] {
                return Ok(tail_start);
            }
        }
        Ok(if walk_limit == token_bytes {
            tail_start - token_bytes
        } else {
            tail_start
        })
    }

    #[inline(never)]
    fn ordinary_repeated_single_token_start(
        &self,
        haystack: &[u8],
        tail_start: usize,
    ) -> Result<usize, Error> {
        let token_bytes = usize::from(self.maximum_token_bytes);
        let edges = match self.edges.get(..token_bytes) {
            Some(edges) => edges,
            None => {
                return Err(Error::InternalInvariant {
                    detail: "finite-token linear trie escaped its edge pool",
                });
            }
        };
        let mut start = tail_start;
        for _ in 0..self.maximum_repetitions {
            if start < token_bytes {
                break;
            }
            for (offset, edge) in edges.iter().enumerate() {
                if edge.byte != haystack[start - offset - 1] {
                    return Ok(start);
                }
            }
            start -= token_bytes;
        }
        Ok(start)
    }

    fn first_tail(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<(usize, usize)>, Actual, u64), Error> {
        validate_window(haystack, window)?;
        let upper = self.literal_work_upper_bound(window)?;
        enforce_work(upper, limits)?;
        let mut actual = Actual::default();
        let found = self.find_tail(haystack, window.start(), window.end(), &mut actual)?;
        Ok((found, actual, upper))
    }

    fn search_span(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, Actual, u64), Error> {
        validate_window(haystack, window)?;
        let upper = self.work_upper_bound(window)?;
        enforce_work(upper, limits)?;
        enforce_scratch(REACHABILITY_SCRATCH_BYTES, limits)?;
        let mut actual = Actual::default();
        let Some((tail_start, tail_end)) =
            self.find_tail(haystack, window.start(), window.end(), &mut actual)?
        else {
            return Ok((None, actual, upper));
        };
        actual.candidate_visits = 1;
        let start = self.earliest_start_for_tail_dispatch(
            haystack,
            window.start(),
            tail_start,
            &mut actual,
        )?;
        Ok((Some(Match { start, end: tail_end }), actual, upper))
    }

    fn find_tail(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
        actual: &mut Actual,
    ) -> Result<Option<(usize, usize)>, Error> {
        actual.finder_calls = actual.finder_calls.saturating_add(1);
        let (matched, accounting) = self.tail.find_window(
            haystack,
            fre_kernels::Window::new(start, end),
            LiteralSearchLimits::unlimited(),
        )?;
        actual.finder_linear_terms = actual
            .finder_linear_terms
            .checked_add(u64::try_from(accounting.linear_terms).map_err(|_| {
                Error::ArithmeticOverflow {
                    computation: "finite-token finder linear terms conversion",
                }
            })?)
            .ok_or(Error::ArithmeticOverflow {
                computation: "cumulative finite-token finder linear terms",
            })?;
        Ok(matched)
    }

    // Keep the short allocation out of both the caller and the incumbent
    // maximum-sized replay frame. Dispatch only after a tail hit so misses and
    // every source-independent admission check retain their existing path.
    #[inline(never)]
    fn earliest_start_for_tail_dispatch(
        &self,
        haystack: &[u8],
        window_start: usize,
        tail_start: usize,
        actual: &mut Actual,
    ) -> Result<usize, Error> {
        if usize::from(self.maximum_prefix_bytes) <= SHORT_PREFIX_BYTES {
            return self.earliest_start_for_tail_short(
                haystack,
                window_start,
                tail_start,
                actual,
            );
        }
        self.earliest_start_for_tail(haystack, window_start, tail_start, actual)
    }

    // This deliberately remains separate from `earliest_start_for_tail` so
    // plans above the short horizon keep the incumbent replay code and frame.
    #[inline(never)]
    fn earliest_start_for_tail_short(
        &self,
        haystack: &[u8],
        window_start: usize,
        tail_start: usize,
        actual: &mut Actual,
    ) -> Result<usize, Error> {
        let horizon = tail_start
            .saturating_sub(window_start)
            .min(usize::from(self.maximum_prefix_bytes));
        debug_assert!(horizon <= SHORT_PREFIX_BYTES);
        let mut reachable_counts = [0_u64; SHORT_REACHABILITY_CELLS];
        actual.replay_cells = actual
            .replay_cells
            .checked_add(SHORT_REACHABILITY_CELLS)
            .ok_or(Error::ArithmeticOverflow {
                computation: "finite-token reachability initialization work",
            })?;
        actual.scratch_bytes = SHORT_REACHABILITY_SCRATCH_BYTES;
        reachable_counts[0] = 1;
        let count_mask = low_count_mask(usize::from(self.maximum_repetitions));
        let mut best_offset = 0usize;
        let mut furthest_pending = 0usize;
        let mut offset = 0usize;
        while offset <= furthest_pending {
            actual.replay_cells = actual.replay_cells.saturating_add(1);
            let counts = reachable_counts[offset] & count_mask;
            let next_counts = (counts << 1) & count_mask;
            if next_counts != 0 {
                let boundary = tail_start.checked_sub(offset).ok_or(
                    Error::InternalInvariant {
                        detail: "finite-token reverse boundary crossed the tail window",
                    },
                )?;
                let available = boundary.saturating_sub(window_start);
                let walk_limit = available
                    .min(usize::from(self.maximum_token_bytes))
                    .min(horizon.saturating_sub(offset));
                let mut node = 0usize;
                for depth in 1..=walk_limit {
                    actual.backward_steps = actual.backward_steps.saturating_add(1);
                    let byte = haystack[boundary - depth];
                    let Some(target) = self.find_child(node, byte, actual)? else {
                        break;
                    };
                    node = target;
                    let terminal = self.nodes.get(node).ok_or(Error::InternalInvariant {
                        detail: "finite-token reverse trie target escaped its nodes",
                    })?;
                    if terminal.first_source_token == NO_TERMINAL {
                        continue;
                    }
                    let target_offset = offset.checked_add(depth).ok_or(
                        Error::ArithmeticOverflow {
                            computation: "finite-token reverse target offset",
                        },
                    )?;
                    if target_offset > horizon {
                        continue;
                    }
                    actual.replay_cells = actual.replay_cells.saturating_add(1);
                    reachable_counts[target_offset] |= next_counts;
                    best_offset = best_offset.max(target_offset);
                    furthest_pending = furthest_pending.max(target_offset);
                }
            }
            offset = offset.saturating_add(1);
        }
        tail_start
            .checked_sub(best_offset)
            .ok_or(Error::InternalInvariant {
                detail: "finite-token recovered start crossed zero",
            })
    }

    #[inline(never)]
    fn earliest_start_for_tail(
        &self,
        haystack: &[u8],
        window_start: usize,
        tail_start: usize,
        actual: &mut Actual,
    ) -> Result<usize, Error> {
        let horizon = tail_start
            .saturating_sub(window_start)
            .min(usize::from(self.maximum_prefix_bytes));
        let mut reachable_counts = [0_u64; REACHABILITY_CELLS];
        actual.replay_cells = actual.replay_cells.checked_add(REACHABILITY_CELLS).ok_or(
            Error::ArithmeticOverflow {
                computation: "finite-token reachability initialization work",
            },
        )?;
        actual.scratch_bytes = REACHABILITY_SCRATCH_BYTES;
        reachable_counts[0] = 1;
        let count_mask = low_count_mask(usize::from(self.maximum_repetitions));
        let mut best_offset = 0usize;
        let mut furthest_pending = 0usize;
        let mut offset = 0usize;
        while offset <= furthest_pending {
            actual.replay_cells = actual.replay_cells.saturating_add(1);
            let counts = reachable_counts[offset] & count_mask;
            let next_counts = (counts << 1) & count_mask;
            if next_counts != 0 {
                let boundary = tail_start.checked_sub(offset).ok_or(
                    Error::InternalInvariant {
                        detail: "finite-token reverse boundary crossed the tail window",
                    },
                )?;
                let available = boundary.saturating_sub(window_start);
                let walk_limit = available
                    .min(usize::from(self.maximum_token_bytes))
                    .min(horizon.saturating_sub(offset));
                let mut node = 0usize;
                for depth in 1..=walk_limit {
                    actual.backward_steps = actual.backward_steps.saturating_add(1);
                    let byte = haystack[boundary - depth];
                    let Some(target) = self.find_child(node, byte, actual)? else {
                        break;
                    };
                    node = target;
                    let terminal = self.nodes.get(node).ok_or(Error::InternalInvariant {
                        detail: "finite-token reverse trie target escaped its nodes",
                    })?;
                    if terminal.first_source_token == NO_TERMINAL {
                        continue;
                    }
                    let target_offset = offset.checked_add(depth).ok_or(
                        Error::ArithmeticOverflow {
                            computation: "finite-token reverse target offset",
                        },
                    )?;
                    if target_offset > horizon {
                        continue;
                    }
                    actual.replay_cells = actual.replay_cells.saturating_add(1);
                    reachable_counts[target_offset] |= next_counts;
                    best_offset = best_offset.max(target_offset);
                    furthest_pending = furthest_pending.max(target_offset);
                }
            }
            offset = offset.saturating_add(1);
        }
        tail_start
            .checked_sub(best_offset)
            .ok_or(Error::InternalInvariant {
                detail: "finite-token recovered start crossed zero",
            })
    }

    fn find_child(
        &self,
        node: usize,
        byte: u8,
        actual: &mut Actual,
    ) -> Result<Option<usize>, Error> {
        let node = self.nodes.get(node).ok_or(Error::InternalInvariant {
            detail: "finite-token reverse trie source escaped its nodes",
        })?;
        let first = usize::from(node.first_edge);
        let end = first
            .checked_add(usize::from(node.edge_count))
            .ok_or(Error::ArithmeticOverflow {
                computation: "finite-token trie edge range",
            })?;
        let edges = self.edges.get(first..end).ok_or(Error::InternalInvariant {
            detail: "finite-token reverse trie edge range escaped its pool",
        })?;
        for edge in edges {
            actual.replay_cells = actual.replay_cells.saturating_add(1);
            if edge.byte == byte {
                return Ok(Some(usize::from(edge.target)));
            }
        }
        Ok(None)
    }

    fn work_upper_bound(&self, window: SearchWindow) -> Result<u64, Error> {
        let input = window
            .end()
            .checked_sub(window.start())
            .ok_or(Error::InvalidWindow)?;
        let finder = input
            .checked_add(self.tail.needle().len())
            .ok_or(Error::ArithmeticOverflow {
                computation: "finite-token finder work bound",
            })?;
        let horizon = input.min(usize::from(self.maximum_prefix_bytes));
        let positions = horizon.checked_add(1).ok_or(Error::ArithmeticOverflow {
            computation: "finite-token DP position bound",
        })?;
        let walk = positions
            .checked_mul(usize::from(self.maximum_token_bytes))
            .ok_or(Error::ArithmeticOverflow {
                computation: "finite-token reverse walk bound",
            })?;
        let structural = walk
            .checked_mul(usize::from(self.token_count).saturating_add(2))
            .and_then(|work| work.checked_add(positions))
            .and_then(|work| work.checked_add(REACHABILITY_CELLS))
            .ok_or(Error::ArithmeticOverflow {
                computation: "finite-token structural work bound",
            })?;
        u64::try_from(finder)
            .ok()
            .and_then(|finder| {
                u64::try_from(structural)
                    .ok()
                    .and_then(|structural| finder.checked_add(structural))
            })
            .ok_or(Error::ArithmeticOverflow {
                computation: "finite-token total work bound",
            })
    }

    fn literal_work_upper_bound(&self, window: SearchWindow) -> Result<u64, Error> {
        let input = window
            .end()
            .checked_sub(window.start())
            .ok_or(Error::InvalidWindow)?;
        let terms = input
            .checked_add(self.tail.needle().len())
            .ok_or(Error::ArithmeticOverflow {
                computation: "finite-token literal-only work bound",
            })?;
        u64::try_from(terms).map_err(|_| Error::ArithmeticOverflow {
            computation: "finite-token literal-only work conversion",
        })
    }

    fn accounting(
        &self,
        operation: Operation,
        window: SearchWindow,
        actual: Actual,
        work_upper_bound: u64,
    ) -> Result<Accounting, Error> {
        let structural = actual
            .backward_steps
            .checked_add(actual.replay_cells)
            .ok_or(Error::ArithmeticOverflow {
                computation: "finite-token actual structural work",
            })?;
        let actual_work = actual
            .finder_linear_terms
            .checked_add(u64::try_from(structural).map_err(|_| {
                Error::ArithmeticOverflow {
                    computation: "finite-token actual structural work conversion",
                }
            })?)
            .ok_or(Error::ArithmeticOverflow {
                computation: "finite-token actual search work",
            })?;
        if actual_work > work_upper_bound {
            return Err(Error::InternalInvariant {
                detail: "finite-token actual work exceeded its source-independent bound",
            });
        }
        let scratch_bytes = if matches!(operation, Operation::SelectedEnd | Operation::Span) {
            REACHABILITY_SCRATCH_BYTES
        } else {
            0
        };
        if actual.scratch_bytes > scratch_bytes {
            return Err(Error::InternalInvariant {
                detail: "finite-token actual scratch exceeded its admitted bound",
            });
        }
        let scratch_bytes = u16::try_from(scratch_bytes).map_err(|_| {
            Error::ArithmeticOverflow {
                computation: "finite-token scratch accounting conversion",
            }
        })?;
        let actual_scratch_bytes = u16::try_from(actual.scratch_bytes).map_err(|_| {
            Error::ArithmeticOverflow {
                computation: "finite-token actual scratch accounting conversion",
            }
        })?;
        Ok(Accounting {
            plan_id: PLAN_ID,
            operation,
            input_bytes: window.end().saturating_sub(window.start()),
            optional_stages: usize::from(self.maximum_repetitions),
            tail_bytes: self.tail.needle().len(),
            candidate_visits: actual.candidate_visits,
            finder_calls: actual.finder_calls,
            finder_linear_terms: actual.finder_linear_terms,
            backward_steps: actual.backward_steps,
            replay_cells: actual.replay_cells,
            scratch_bytes,
            actual_scratch_bytes,
            work_upper_bound,
            actual_work,
        })
    }
}

fn retain_exact<T>(values: Vec<T>, structure: &'static str) -> Result<ExactVec<T>, LiteralError> {
    let additional = values
        .len()
        .checked_mul(core::mem::size_of::<T>())
        .ok_or(LiteralError::ArithmeticOverflow {
            computation: "finite-token retained vector byte count",
        })?;
    let mut retained = ExactVec::try_with_capacity(values.len()).map_err(|error| match error {
        CopyError::LayoutOverflow => LiteralError::ArithmeticOverflow {
            computation: "finite-token retained vector layout",
        },
        CopyError::AllocationFailed => LiteralError::AllocationFailed {
            structure,
            additional,
        },
    })?;
    for value in values {
        retained
            .try_push(value)
            .map_err(|_| LiteralError::ArithmeticOverflow {
                computation: "finite-token retained vector exact capacity",
            })?;
    }
    Ok(retained)
}

pub(crate) fn inspect(
    hir: &Hir,
    initial_work: u64,
    max_planner_work: u64,
) -> Result<InspectionOutcome, BuildError> {
    let mut work = initial_work;
    let root = peel_captures(hir, &mut work, max_planner_work)?;
    let HirKind::Concat(parts) = root.kind() else {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    };
    if parts.len() < 2 {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    }
    charge_planner(
        &mut work,
        u64::try_from(parts.len()).unwrap_or(u64::MAX),
        max_planner_work,
    )?;
    let repetition = peel_captures(&parts[0], &mut work, max_planner_work)?;
    let HirKind::Repetition(repetition) = repetition.kind() else {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    };
    charge_planner(&mut work, 1, max_planner_work)?;
    let Some(maximum) = repetition.max else {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    };
    let maximum = usize::try_from(maximum).map_err(|_| {
        BuildError::InternalInvariant("finite-token repetition maximum does not fit usize")
    })?;
    if repetition.min != 0 || maximum == 0 || maximum > MAX_REPETITIONS {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    }

    let mut tail = Vec::new();
    for part in &parts[1..] {
        if !append_exact_literal(
            part,
            &mut tail,
            usize::MAX,
            &mut work,
            max_planner_work,
            "nullable finite-token tail",
        )? {
            return Ok(InspectionOutcome::Ineligible { planner_work: work });
        }
    }
    if tail.is_empty() {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    }
    let tail_head = tail[0];

    let body = peel_captures(&repetition.sub, &mut work, max_planner_work)?;
    let branches: &[Hir] = match body.kind() {
        HirKind::Alternation(branches) => branches,
        _ => core::slice::from_ref(body),
    };
    if branches.is_empty() || branches.len() > MAX_TOKENS {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    }
    charge_planner(
        &mut work,
        u64::try_from(branches.len()).unwrap_or(u64::MAX),
        max_planner_work,
    )?;

    let mut trie = TrieBuilder::new(&mut work, max_planner_work)?;
    let mut total_token_bytes = 0usize;
    let mut maximum_token_bytes = 0usize;
    for (source_token, branch) in branches.iter().enumerate() {
        let mut token = Vec::new();
        if !append_exact_literal(
            branch,
            &mut token,
            MAX_TOKEN_BYTES,
            &mut work,
            max_planner_work,
            "nullable finite token",
        )? || token.is_empty()
        {
            return Ok(InspectionOutcome::Ineligible { planner_work: work });
        }
        total_token_bytes = total_token_bytes
            .checked_add(token.len())
            .ok_or(BuildError::PersistentBytesOverflow)?;
        charge_planner(
            &mut work,
            u64::try_from(token.len()).unwrap_or(u64::MAX),
            max_planner_work,
        )?;
        if total_token_bytes > MAX_TOTAL_TOKEN_BYTES || token.contains(&tail_head) {
            return Ok(InspectionOutcome::Ineligible { planner_work: work });
        }
        maximum_token_bytes = maximum_token_bytes.max(token.len());
        trie.insert(
            &token,
            u8::try_from(source_token).expect("admitted token count fits u8"),
            &mut work,
            max_planner_work,
        )?;
    }
    let maximum_prefix_bytes = maximum
        .checked_mul(maximum_token_bytes)
        .ok_or(BuildError::PersistentBytesOverflow)?;
    if maximum_prefix_bytes > MAX_PREFIX_BYTES {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    }
    let (nodes, edges) = trie.finish(&mut work, max_planner_work)?;
    Ok(InspectionOutcome::Eligible(Inspection {
        nodes,
        edges,
        token_count: branches.len(),
        maximum_repetitions: maximum,
        maximum_token_bytes,
        maximum_prefix_bytes,
        tail,
        planner_work: work,
    }))
}

impl TrieBuilder {
    fn new(work: &mut u64, limit: u64) -> Result<Self, BuildError> {
        let mut nodes = Vec::new();
        reserve_planner(&mut nodes, 1, work, limit, "finite-token trie root")?;
        nodes.push(BuildNode {
            first_edge: None,
            first_source_token: None,
        });
        Ok(Self {
            nodes,
            edges: Vec::new(),
        })
    }

    fn insert(
        &mut self,
        token: &[u8],
        source_token: u8,
        work: &mut u64,
        limit: u64,
    ) -> Result<(), BuildError> {
        let mut node = 0usize;
        for &byte in token.iter().rev() {
            let mut edge = self.nodes[node].first_edge;
            let mut target = None;
            while let Some(index) = edge {
                charge_planner(work, 1, limit)?;
                let candidate = self.edges.get(index).ok_or(BuildError::InternalInvariant(
                    "finite-token build edge escaped its pool",
                ))?;
                if candidate.byte == byte {
                    target = Some(candidate.target);
                    break;
                }
                edge = candidate.next;
            }
            node = if let Some(target) = target {
                target
            } else {
                reserve_planner(
                    &mut self.nodes,
                    1,
                    work,
                    limit,
                    "finite-token trie nodes",
                )?;
                reserve_planner(
                    &mut self.edges,
                    1,
                    work,
                    limit,
                    "finite-token trie edges",
                )?;
                let target = self.nodes.len();
                self.nodes.push(BuildNode {
                    first_edge: None,
                    first_source_token: None,
                });
                let next = self.nodes[node].first_edge;
                self.edges.push(BuildEdge {
                    byte,
                    target,
                    next,
                });
                self.nodes[node].first_edge = Some(self.edges.len().saturating_sub(1));
                target
            };
        }
        if self.nodes[node].first_source_token.is_none() {
            self.nodes[node].first_source_token = Some(source_token);
        }
        Ok(())
    }

    fn finish(
        self,
        work: &mut u64,
        limit: u64,
    ) -> Result<(Vec<TrieNode>, Vec<TrieEdge>), BuildError> {
        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        reserve_planner(
            &mut nodes,
            self.nodes.len(),
            work,
            limit,
            "flattened finite-token trie nodes",
        )?;
        reserve_planner(
            &mut edges,
            self.edges.len(),
            work,
            limit,
            "flattened finite-token trie edges",
        )?;
        for source in &self.nodes {
            let first_edge = edges.len();
            let mut edge_count = 0usize;
            let mut edge = source.first_edge;
            while let Some(index) = edge {
                charge_planner(work, 1, limit)?;
                let source_edge = self.edges.get(index).ok_or(BuildError::InternalInvariant(
                    "finite-token flatten edge escaped its pool",
                ))?;
                edges.push(TrieEdge {
                    byte: source_edge.byte,
                    target: u16::try_from(source_edge.target).map_err(|_| {
                        BuildError::InternalInvariant("finite-token trie target does not fit u16")
                    })?,
                });
                edge_count = edge_count
                    .checked_add(1)
                    .ok_or(BuildError::PersistentBytesOverflow)?;
                edge = source_edge.next;
            }
            nodes.push(TrieNode {
                first_edge: u16::try_from(first_edge).map_err(|_| {
                    BuildError::InternalInvariant("finite-token edge offset does not fit u16")
                })?,
                edge_count: u8::try_from(edge_count).map_err(|_| {
                    BuildError::InternalInvariant("finite-token node degree does not fit u8")
                })?,
                first_source_token: source.first_source_token.unwrap_or(NO_TERMINAL),
            });
        }
        Ok((nodes, edges))
    }
}

fn append_exact_literal(
    hir: &Hir,
    bytes: &mut Vec<u8>,
    maximum: usize,
    work: &mut u64,
    max_planner_work: u64,
    structure: &'static str,
) -> Result<bool, BuildError> {
    let hir = peel_captures(hir, work, max_planner_work)?;
    match hir.kind() {
        HirKind::Literal(literal) => {
            let Some(next_len) = bytes.len().checked_add(literal.0.len()) else {
                return Ok(false);
            };
            if next_len > maximum {
                return Ok(false);
            }
            reserve_planner(
                bytes,
                literal.0.len(),
                work,
                max_planner_work,
                structure,
            )?;
            bytes.extend_from_slice(&literal.0);
            Ok(true)
        }
        HirKind::Concat(parts) => {
            charge_planner(
                work,
                u64::try_from(parts.len()).unwrap_or(u64::MAX),
                max_planner_work,
            )?;
            for part in parts {
                if !append_exact_literal(
                    part,
                    bytes,
                    maximum,
                    work,
                    max_planner_work,
                    structure,
                )? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn peel_captures<'a>(
    mut hir: &'a Hir,
    work: &mut u64,
    max_planner_work: u64,
) -> Result<&'a Hir, BuildError> {
    loop {
        charge_planner(work, 1, max_planner_work)?;
        let HirKind::Capture(capture) = hir.kind() else {
            return Ok(hir);
        };
        hir = &capture.sub;
    }
}

fn projected_plan_storage_bytes(
    nodes: usize,
    edges: usize,
    tail_bytes: usize,
) -> Result<usize, BuildError> {
    core::mem::size_of::<Plan>()
        .checked_add(
            nodes
                .checked_mul(core::mem::size_of::<TrieNode>())
                .ok_or(BuildError::PersistentBytesOverflow)?,
        )
        .and_then(|bytes| {
            edges
                .checked_mul(core::mem::size_of::<TrieEdge>())
                .and_then(|edge_bytes| bytes.checked_add(edge_bytes))
        })
        .and_then(|bytes| bytes.checked_add(tail_bytes))
        .ok_or(BuildError::PersistentBytesOverflow)
}

fn low_count_mask(maximum: usize) -> u64 {
    if maximum >= u64::BITS as usize - 1 {
        u64::MAX
    } else {
        (1_u64 << (maximum + 1)).saturating_sub(1)
    }
}

fn ordinary_exists_work_is_representable(input_bytes: usize, tail_bytes: usize) -> Option<()> {
    let finder_terms = input_bytes.checked_add(tail_bytes)?;
    u64::try_from(finder_terms).ok().map(|_| ())
}

fn validate_window(haystack: &[u8], window: SearchWindow) -> Result<(), Error> {
    if window.start() > window.end() || window.end() > haystack.len() {
        return Err(Error::InvalidWindow);
    }
    Ok(())
}

fn enforce_work(needed: u64, limits: SearchLimits) -> Result<(), Error> {
    if needed > limits.max_work {
        return Err(Error::WorkLimit {
            needed,
            limit: limits.max_work,
        });
    }
    Ok(())
}

fn enforce_scratch(needed: usize, limits: SearchLimits) -> Result<(), Error> {
    if needed > limits.max_scratch_bytes {
        return Err(Error::ScratchLimit {
            needed,
            limit: limits.max_scratch_bytes,
        });
    }
    Ok(())
}

#[cfg(test)]
mod ordinary_exists_value_tests {
    use super::ordinary_exists_work_is_representable;

    #[test]
    fn admission_matches_the_canonical_literal_bound_at_address_space_edges() {
        assert!(ordinary_exists_work_is_representable(0, 1).is_some());
        assert!(ordinary_exists_work_is_representable(4096, 8).is_some());
        assert!(ordinary_exists_work_is_representable(usize::MAX - 1, 1).is_some());
        assert!(ordinary_exists_work_is_representable(usize::MAX, 1).is_none());
    }
}
