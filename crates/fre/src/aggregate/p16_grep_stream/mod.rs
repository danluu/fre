//! Whole-input plain-grep facade over the G-owned line-state engines.
//!
//! This module is intentionally leaf-owned. The integration owner declares it
//! from the shared aggregate root and wires the Rebar runner only after the G
//! review. Construction allocates one exact operation session outside the
//! public operation; each execution then reuses its selected fixed G slot.

use core::fmt::Write as _;

mod literal;
mod word;

pub use literal::Error as PortableGrepLiteralError;
pub use word::Error as PortableGrepWordError;

use fre_automata::p16_grep_stream::{self as k0_grep, GrepStreamProspective as K0Prospective};

use crate::{
    PortablePlan, PortableRegex,
    operation_session::{
        OperationSession, OperationSessionAdmission, OperationSessionAttemptError,
        OperationSessionAttemptReceipt, OperationSessionConstructionLimits,
        OperationSessionConstructionReceipt, OperationSessionError,
        OperationSessionExecutionActual, OperationSessionExecutionProspective,
        OperationSessionInvocation, OperationSessionLeaf, OperationSessionResetLimits,
        OperationSessionRunLimits,
        grep::{
            AutomatonSlotLayout, AutomatonSlotLayoutError, GrepStreamBeginError,
            GrepStreamCommitError, GrepStreamExecutionReport, GrepStreamFailure, GrepStreamMatch,
            GrepStreamOrderError, GrepStreamOrderProof, SlotAdmission,
        },
        hot, multi_capture, search,
    },
};

/// Stable public facade identity for one whole-input plain-grep operation.
pub const ACCOUNTING_ID: &str = "fre.portable.grep-stream.v1";
/// Algorithm version bound by [`ACCOUNTING_ID`].
pub const ALGORITHM_VERSION: u32 = 1;
/// Accounting version bound by [`ACCOUNTING_ID`].
pub const ACCOUNTING_VERSION: u32 = 1;

/// Failure while constructing one caller-owned reusable grep session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PortableGrepBuildError {
    /// The selected portable runtime has no reviewed whole-input reducer.
    UnsupportedRuntime {
        /// Structural runtime identity selected at regex construction.
        runtime: &'static str,
    },
    /// The fixed K0 slot shape was not representable.
    SlotLayout(AutomatonSlotLayoutError),
    /// The common four-leaf session refused construction.
    Session(OperationSessionError),
}

impl core::fmt::Display for PortableGrepBuildError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "portable grep-stream build failed: {self:?}")
    }
}

impl std::error::Error for PortableGrepBuildError {}

impl From<AutomatonSlotLayoutError> for PortableGrepBuildError {
    fn from(error: AutomatonSlotLayoutError) -> Self {
        Self::SlotLayout(error)
    }
}

impl From<OperationSessionError> for PortableGrepBuildError {
    fn from(error: OperationSessionError) -> Self {
        Self::Session(error)
    }
}

/// Source-independent engine and common-session envelope for one source size.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortableGrepProspective {
    engine: EngineProspective,
    execution: OperationSessionExecutionProspective,
    required_generations: u64,
}

impl PortableGrepProspective {
    /// Complete common execution envelope.
    #[must_use]
    pub const fn execution(self) -> OperationSessionExecutionProspective {
        self.execution
    }

    /// Generation interval reserved atomically before source access.
    #[must_use]
    pub const fn required_generations(self) -> u64 {
        self.required_generations
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EngineProspective {
    Literal(literal::Prospective),
    K0(K0Prospective),
    Word(word::Prospective),
}

/// One selected line and absolute selected match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortableGrepMatch {
    /// Zero-based ByteSlice-compatible line ordinal.
    pub line_ordinal: usize,
    /// Absolute first content byte.
    pub line_start: usize,
    /// Absolute exclusive content end after optional CR stripping.
    pub line_content_end: usize,
    /// Absolute exclusive source end, including the closing LF when present.
    pub line_source_end: usize,
    /// Absolute selected-match start.
    pub match_start: usize,
    /// Absolute selected-match end.
    pub match_end: usize,
}

/// Successful whole-input Count result and its closed common receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortableGrepResult {
    count: u64,
    /// Number of semantic source lines examined.
    pub source_line_domains: usize,
    /// First matching line, if any.
    pub first_match: Option<PortableGrepMatch>,
    /// Last matching line, if any.
    pub last_match: Option<PortableGrepMatch>,
    /// Closed common operation-session receipt.
    pub receipt: OperationSessionAttemptReceipt,
}

impl PortableGrepResult {
    /// Selected/matching line count.
    #[must_use]
    pub const fn count(&self) -> u64 {
        self.count
    }
}

/// Failure before source access or from one selected whole-input engine.
#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "the common attempt variant deliberately retains its closed allocation-free receipt by value"
)]
#[non_exhaustive]
pub enum PortableGrepError {
    /// The caller supplied an envelope for another source length or plan.
    AdmissionMismatch {
        /// Re-derived exact prospective.
        required: PortableGrepProspective,
        /// Caller-supplied prospective.
        admitted: PortableGrepProspective,
    },
    /// Source-independent prospective arithmetic failed.
    Prospective {
        /// Stable failing computation.
        computation: &'static str,
    },
    /// The common operation attempt refused with its closed receipt.
    Attempt(OperationSessionAttemptError),
    /// The K0 line-state engine refused or found an internal invariant error.
    K0(k0_grep::GrepStreamError),
    /// The native word line-state engine refused or found an invariant error.
    Word(PortableGrepWordError),
    /// The shared exact-literal line adapter refused before begin.
    Literal(PortableGrepLiteralError),
    /// A selected engine failed after begin and returned a closed attempt.
    Execution {
        /// Exact engine or observer failure.
        source: PortableGrepExecutionError,
        /// Closed common-session terminal through the failure.
        attempt: OperationSessionAttemptError,
    },
    /// A trusted engine/common-session seam violated its reviewed invariant.
    InternalInvariant {
        /// Stable invariant description.
        detail: &'static str,
    },
}

/// Selected-engine failure after the common G attempt began.
#[derive(Debug)]
#[non_exhaustive]
pub enum PortableGrepExecutionError {
    /// The generic portable automaton engine failed.
    K0(k0_grep::GrepStreamError),
    /// The native ASCII/Unicode word-run engine failed.
    Word(PortableGrepWordError),
    /// The shared exact-literal adapter failed.
    Literal(PortableGrepLiteralError),
    /// The selected engine emitted an invalid line-event sequence.
    ObserverOrder {
        /// Stable observer-order invariant description.
        detail: &'static str,
    },
    /// The selected engine and common-session protocol diverged.
    Protocol {
        /// Stable protocol invariant description.
        detail: &'static str,
    },
}

impl core::fmt::Display for PortableGrepError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "portable grep-stream execution failed: {self:?}")
    }
}

impl std::error::Error for PortableGrepError {}

impl From<k0_grep::GrepStreamError> for PortableGrepError {
    fn from(error: k0_grep::GrepStreamError) -> Self {
        Self::K0(error)
    }
}

impl From<word::Error> for PortableGrepError {
    fn from(error: word::Error) -> Self {
        Self::Word(error)
    }
}

impl From<literal::Error> for PortableGrepError {
    fn from(error: literal::Error) -> Self {
        Self::Literal(error)
    }
}

/// One caller-owned, allocation-free-after-construction plain-grep session.
#[derive(Debug)]
pub struct PortableGrepSession<'r> {
    regex: &'r PortableRegex,
    operation: OperationSession,
    compiled_plan_id: [u8; 16],
}

impl PortableRegex {
    /// Construct one reusable whole-input plain-grep session.
    ///
    /// Construction occurs outside the public operation and allocates only
    /// the exact fixed G workspace selected from immutable plan facts.
    ///
    /// # Errors
    ///
    /// Refuses unsupported portable runtime classes, checked layout failure,
    /// construction limits, or allocation failure.
    pub fn grep_stream_session(&self) -> Result<PortableGrepSession<'_>, PortableGrepBuildError> {
        PortableGrepSession::new(self)
    }
}

impl<'r> PortableGrepSession<'r> {
    fn new(regex: &'r PortableRegex) -> Result<Self, PortableGrepBuildError> {
        let grep = match &regex.plan {
            PortablePlan::ExactLiteral(_) => SlotAdmission {
                line_state_cells: 0,
                generation_cells: 0,
                candidate_cells: 0,
                cache_cells: 0,
                history_cells: 0,
            },
            PortablePlan::K0(automaton) => AutomatonSlotLayout::for_automaton(
                automaton.stats().states(),
                automaton.stats().edges(),
                automaton.stats().zero_width_edges(),
            )?
            .admission(),
            PortablePlan::UnicodeWordRun(plan) if word::supports(*plan) => SlotAdmission {
                line_state_cells: 0,
                generation_cells: 0,
                candidate_cells: 0,
                cache_cells: 0,
                history_cells: 0,
            },
            _ => {
                return Err(PortableGrepBuildError::UnsupportedRuntime {
                    runtime: regex.runtime_implementation_id(),
                });
            }
        };
        let admission = OperationSessionAdmission {
            search: search::SlotAdmission {
                frontier_cells: 0,
                next_frontier_cells: 0,
                generation_cells: 0,
                candidate_cells: 0,
                cache_cells: 0,
                history_cells: 0,
            },
            hot: hot::SlotAdmission {
                state_cells: 0,
                generation_cells: 0,
                candidate_cells: 0,
                cache_cells: 0,
                history_cells: 0,
            },
            multi_capture: multi_capture::SlotAdmission {
                frontier_cells: 0,
                next_frontier_cells: 0,
                generation_cells: 0,
                tagged_candidate_cells: 0,
                tagged_cache_cells: 0,
                history_cells: 0,
                participation_cells: 0,
            },
            grep,
        };
        let prospective = OperationSession::prospective(&admission)?;
        let operation = OperationSession::try_new(
            admission,
            OperationSessionConstructionLimits::exact(&prospective),
        )?;
        Ok(Self {
            regex,
            operation,
            compiled_plan_id: compiled_plan_id(regex),
        })
    }

    /// Stable runtime identity inherited from the immutable matcher.
    #[must_use]
    pub const fn runtime_implementation_id(&self) -> &'static str {
        self.regex.runtime_implementation_id()
    }

    /// Closed exact fixed-session construction receipt.
    #[must_use]
    pub const fn construction_receipt(&self) -> &OperationSessionConstructionReceipt {
        self.operation.construction_receipt()
    }

    /// Derive the complete source-independent operation envelope.
    ///
    /// # Errors
    ///
    /// Refuses only checked arithmetic or a violated immutable plan class.
    #[allow(
        clippy::result_large_err,
        reason = "typed common-session refusals retain their closed receipt by value"
    )]
    pub fn prospective(
        &self,
        haystack_len: usize,
    ) -> Result<PortableGrepProspective, PortableGrepError> {
        let engine = match &self.regex.plan {
            PortablePlan::ExactLiteral(plan) => {
                EngineProspective::Literal(literal::prospective(plan, haystack_len)?)
            }
            PortablePlan::K0(automaton) => {
                EngineProspective::K0(k0_grep::prospective(automaton, haystack_len)?)
            }
            PortablePlan::UnicodeWordRun(plan) if word::supports(*plan) => {
                EngineProspective::Word(word::prospective(*plan, haystack_len)?)
            }
            _ => {
                return Err(PortableGrepError::InternalInvariant {
                    detail: "constructed grep session changed runtime class",
                });
            }
        };
        let (execution, required_generations) = operation_prospective(engine);
        Ok(PortableGrepProspective {
            engine,
            execution,
            required_generations,
        })
    }

    /// Derive exact reset and execution limits for the current session state.
    ///
    /// This is source-independent and may be called outside a measured public
    /// operation.
    #[allow(
        clippy::result_large_err,
        reason = "typed common-session refusals retain their closed receipt by value"
    )]
    pub fn exact_limits(
        &self,
        prospective: PortableGrepProspective,
    ) -> Result<(OperationSessionResetLimits, OperationSessionRunLimits), PortableGrepError> {
        let reset = self
            .operation
            .reset_prospective(OperationSessionLeaf::Grep, prospective.required_generations)
            .map_err(|_| PortableGrepError::Prospective {
                computation: "grep reset prospective",
            })?;
        let reset =
            OperationSessionResetLimits::exact(&reset).ok_or(PortableGrepError::Prospective {
                computation: "grep exact reset limits",
            })?;
        Ok((
            reset,
            OperationSessionRunLimits::exact(prospective.execution),
        ))
    }

    /// Execute one complete whole-input plain-grep Count operation.
    ///
    /// `admitted`, reset limits, and run limits are all checked before the
    /// first source read. No unsupported post-source fallback exists.
    #[allow(
        clippy::result_large_err,
        reason = "typed common-session refusals retain their closed receipt by value"
    )]
    pub fn count_matching_lines(
        &mut self,
        haystack: &[u8],
        admitted: PortableGrepProspective,
        reset_limits: OperationSessionResetLimits,
        run_limits: OperationSessionRunLimits,
    ) -> Result<PortableGrepResult, PortableGrepError> {
        let required = self.prospective(haystack.len())?;
        if admitted != required {
            return Err(PortableGrepError::AdmissionMismatch { required, admitted });
        }
        match (&self.regex.plan, required.engine) {
            (PortablePlan::ExactLiteral(plan), EngineProspective::Literal(engine)) => {
                Self::execute_literal(
                    &mut self.operation,
                    self.compiled_plan_id,
                    plan,
                    haystack,
                    engine,
                    required,
                    reset_limits,
                    run_limits,
                )
            }
            (PortablePlan::K0(automaton), EngineProspective::K0(engine)) => Self::execute_k0(
                &mut self.operation,
                self.compiled_plan_id,
                automaton,
                haystack,
                engine,
                required,
                reset_limits,
                run_limits,
            ),
            (PortablePlan::UnicodeWordRun(plan), EngineProspective::Word(engine))
                if word::supports(*plan) =>
            {
                Self::execute_word(
                    &mut self.operation,
                    self.compiled_plan_id,
                    *plan,
                    haystack,
                    engine,
                    required,
                    reset_limits,
                    run_limits,
                )
            }
            _ => Err(PortableGrepError::InternalInvariant {
                detail: "grep prospective runtime class changed before execution",
            }),
        }
    }

    /// Execute one whole-input Count operation with exact derived limits.
    ///
    /// This is the normal convenience entry point. It performs no allocation
    /// and does not select a forced compiler identity.
    #[allow(
        clippy::result_large_err,
        reason = "typed common-session refusals retain their closed receipt by value"
    )]
    pub fn count(&mut self, haystack: &[u8]) -> Result<PortableGrepResult, PortableGrepError> {
        let prospective = self.prospective(haystack.len())?;
        let (reset, run) = self.exact_limits(prospective)?;
        self.count_matching_lines(haystack, prospective, reset, run)
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::result_large_err,
        reason = "engine admission and common limits are separate authenticated inputs"
    )]
    fn execute_literal(
        operation: &mut OperationSession,
        compiled_plan_id: [u8; 16],
        plan: &crate::LiteralPlan,
        haystack: &[u8],
        engine: literal::Prospective,
        common: PortableGrepProspective,
        reset_limits: OperationSessionResetLimits,
        run_limits: OperationSessionRunLimits,
    ) -> Result<PortableGrepResult, PortableGrepError> {
        let invocation = OperationSessionInvocation {
            haystack_len: haystack.len(),
            range: 0..haystack.len(),
            required_generations: common.required_generations,
        };
        let mut forced = operation.forced_grep();
        let attempt = forced
            .begin_stream_count(
                compiled_plan_id,
                invocation,
                common.execution,
                reset_limits,
                run_limits,
            )
            .map_err(map_begin_error)?;
        let mut order = attempt.stream_order_verifier();
        let result =
            literal::count_matching_lines_with_observer(plan, haystack, engine, |matched| {
                order.observe(common_match(literal_match(matched)))
            });
        let report = match result {
            Ok(report) => report,
            Err(literal::ObservedError::Execution { error, partial }) => {
                return Err(close_execution(
                    attempt,
                    literal_actual(partial),
                    order.finish(),
                    GrepStreamFailure::Engine,
                    PortableGrepExecutionError::Literal(error),
                ));
            }
            Err(literal::ObservedError::Observer { error, partial }) => {
                return Err(close_execution(
                    attempt,
                    literal_actual(partial),
                    order.finish(),
                    GrepStreamFailure::Observer,
                    observer_execution_error(error),
                ));
            }
        };
        if report.prospective() != engine {
            return Err(close_execution(
                attempt,
                literal_actual(report.actual()),
                order.finish(),
                GrepStreamFailure::Protocol,
                PortableGrepExecutionError::Protocol {
                    detail: "literal engine report changed its admitted prospective",
                },
            ));
        }
        finish_literal(attempt, report, order.finish())
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::result_large_err,
        reason = "engine admission and common limits are separate authenticated inputs"
    )]
    fn execute_k0(
        operation: &mut OperationSession,
        compiled_plan_id: [u8; 16],
        automaton: &fre_automata::Automaton,
        haystack: &[u8],
        engine: K0Prospective,
        common: PortableGrepProspective,
        reset_limits: OperationSessionResetLimits,
        run_limits: OperationSessionRunLimits,
    ) -> Result<PortableGrepResult, PortableGrepError> {
        let invocation = OperationSessionInvocation {
            haystack_len: haystack.len(),
            range: 0..haystack.len(),
            required_generations: common.required_generations,
        };
        let mut forced = operation.forced_grep();
        let mut attempt = forced
            .begin_stream_count(
                compiled_plan_id,
                invocation,
                common.execution,
                reset_limits,
                run_limits,
            )
            .map_err(map_begin_error)?;
        let mut order = attempt.stream_order_verifier();
        let first_generation = if engine.required_generations() == 0 {
            1
        } else {
            match attempt.reserved_first_generation() {
                Ok(generation) => generation,
                Err(_) => {
                    return Err(close_execution(
                        attempt,
                        OperationSessionExecutionActual::default(),
                        order.finish(),
                        GrepStreamFailure::Protocol,
                        PortableGrepExecutionError::Protocol {
                            detail: "common reset did not reserve the K0 generation interval",
                        },
                    ));
                }
            }
        };
        let storage_valid = {
            let storage = attempt.stream_storage();
            storage.cache.is_empty() && storage.history.is_empty()
        };
        if !storage_valid {
            return Err(close_execution(
                attempt,
                OperationSessionExecutionActual::default(),
                order.finish(),
                GrepStreamFailure::Protocol,
                PortableGrepExecutionError::Protocol {
                    detail: "K0 grep slot retained unrequested cache/history cells",
                },
            ));
        }
        let result = {
            let storage = attempt.stream_storage();
            k0_grep::count_matching_lines_with_observer(
                automaton,
                haystack,
                engine,
                first_generation,
                storage.line_state,
                storage.generation,
                storage.candidates,
                |matched| order.observe(common_match(k0_match(matched))),
            )
        };
        let report = match result {
            Ok(report) => report,
            Err(k0_grep::GrepStreamObservedError::Execution { error, partial }) => {
                return Err(close_execution(
                    attempt,
                    k0_actual(partial),
                    order.finish(),
                    GrepStreamFailure::Engine,
                    PortableGrepExecutionError::K0(error),
                ));
            }
            Err(k0_grep::GrepStreamObservedError::Observer { error, partial }) => {
                return Err(close_execution(
                    attempt,
                    k0_actual(partial),
                    order.finish(),
                    GrepStreamFailure::Observer,
                    observer_execution_error(error),
                ));
            }
        };
        if report.prospective() != engine {
            return Err(close_execution(
                attempt,
                k0_actual(report.actual()),
                order.finish(),
                GrepStreamFailure::Protocol,
                PortableGrepExecutionError::Protocol {
                    detail: "K0 engine report changed its admitted prospective",
                },
            ));
        }
        finish_k0(attempt, report, order.finish())
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::result_large_err,
        reason = "engine admission and common limits are separate authenticated inputs"
    )]
    fn execute_word(
        operation: &mut OperationSession,
        compiled_plan_id: [u8; 16],
        plan: crate::unicode_word_run::Plan,
        haystack: &[u8],
        engine: word::Prospective,
        common: PortableGrepProspective,
        reset_limits: OperationSessionResetLimits,
        run_limits: OperationSessionRunLimits,
    ) -> Result<PortableGrepResult, PortableGrepError> {
        let invocation = OperationSessionInvocation {
            haystack_len: haystack.len(),
            range: 0..haystack.len(),
            required_generations: common.required_generations,
        };
        let mut forced = operation.forced_grep();
        let attempt = forced
            .begin_stream_count(
                compiled_plan_id,
                invocation,
                common.execution,
                reset_limits,
                run_limits,
            )
            .map_err(map_begin_error)?;
        let mut order = attempt.stream_order_verifier();
        let result = word::count_matching_lines_with_observer(plan, haystack, engine, |matched| {
            order.observe(common_match(word_match(matched)))
        });
        let report = match result {
            Ok(report) => report,
            Err(word::ObservedError::Execution { error, partial }) => {
                return Err(close_execution(
                    attempt,
                    word_actual(partial),
                    order.finish(),
                    GrepStreamFailure::Engine,
                    PortableGrepExecutionError::Word(error),
                ));
            }
            Err(word::ObservedError::Observer { error, partial }) => {
                return Err(close_execution(
                    attempt,
                    word_actual(partial),
                    order.finish(),
                    GrepStreamFailure::Observer,
                    observer_execution_error(error),
                ));
            }
        };
        if report.prospective() != engine {
            return Err(close_execution(
                attempt,
                word_actual(report.actual()),
                order.finish(),
                GrepStreamFailure::Protocol,
                PortableGrepExecutionError::Protocol {
                    detail: "word engine report changed its admitted prospective",
                },
            ));
        }
        finish_word(attempt, report, order.finish())
    }
}

fn operation_prospective(engine: EngineProspective) -> (OperationSessionExecutionProspective, u64) {
    let (work, source_accesses, transitions, candidates, line_domains, required_generations) =
        match engine {
            EngineProspective::Literal(value) => (
                value.work(),
                value.source_accesses(),
                value.transitions(),
                value.candidates(),
                value.line_domains(),
                0,
            ),
            EngineProspective::K0(value) => (
                value.work(),
                value.source_accesses(),
                value.transitions(),
                value.candidates(),
                value.line_domains(),
                value.required_generations(),
            ),
            EngineProspective::Word(value) => (
                value.work(),
                value.source_accesses(),
                value.transitions(),
                value.candidates(),
                value.line_domains(),
                0,
            ),
        };
    (
        OperationSessionExecutionProspective {
            work,
            source_accesses,
            transitions,
            candidates,
            cache_misses: 0,
            history_nodes: 0,
            line_domains,
            output_events: line_domains,
            selected_span_bytes: 0,
            participation_entries: 0,
            allocations: 0,
        },
        required_generations,
    )
}

#[allow(
    clippy::result_large_err,
    reason = "typed common-session refusals retain their closed allocation-free receipt by value"
)]
fn finish_literal(
    attempt: crate::operation_session::OperationSessionAttempt<
        '_,
        crate::operation_session::grep::Slot,
    >,
    report: literal::Report,
    order: GrepStreamOrderProof,
) -> Result<PortableGrepResult, PortableGrepError> {
    let actual = report.actual();
    let first_match = report.first_match().map(literal_match);
    let last_match = report.last_match().map(literal_match);
    let common_report = GrepStreamExecutionReport {
        source_line_domains: actual.domains_examined(),
        actual: literal_actual(actual),
        first_match: first_match.map(common_match),
        last_match: last_match.map(common_match),
    };
    let receipt = attempt
        .finish_stream_count(common_report, order)
        .map_err(map_commit_error)?;
    Ok(PortableGrepResult {
        count: actual.matching_lines(),
        source_line_domains: common_report.source_line_domains,
        first_match,
        last_match,
        receipt,
    })
}

#[allow(
    clippy::result_large_err,
    clippy::large_types_passed_by_value,
    reason = "typed common-session refusals retain their closed receipt by value"
)]
fn finish_k0(
    attempt: crate::operation_session::OperationSessionAttempt<
        '_,
        crate::operation_session::grep::Slot,
    >,
    report: k0_grep::GrepStreamReport,
    order: GrepStreamOrderProof,
) -> Result<PortableGrepResult, PortableGrepError> {
    let actual = report.actual();
    let matched = report.matched();
    let first_match = matched.first().map(k0_match);
    let last_match = matched.last().map(k0_match);
    let source_line_domains = match usize::try_from(actual.domains_examined()) {
        Ok(value) => value,
        Err(_) => {
            return Err(close_execution(
                attempt,
                k0_actual(actual),
                order,
                GrepStreamFailure::Protocol,
                PortableGrepExecutionError::Protocol {
                    detail: "K0 source-domain count does not fit usize",
                },
            ));
        }
    };
    let common_report = GrepStreamExecutionReport {
        source_line_domains,
        actual: OperationSessionExecutionActual {
            work: actual.work(),
            source_accesses: actual.source_accesses(),
            transitions: actual.transitions(),
            candidates: actual.candidates(),
            cache_misses: actual.cache_misses(),
            history_nodes: actual.history_nodes(),
            line_domains: actual.line_domains(),
            output_events: actual.output_events(),
            selected_span_bytes: 0,
            participation_entries: 0,
            allocations: actual.allocations(),
        },
        first_match: first_match.map(common_match),
        last_match: last_match.map(common_match),
    };
    let receipt = attempt
        .finish_stream_count(common_report, order)
        .map_err(map_commit_error)?;
    Ok(PortableGrepResult {
        count: actual.output_events(),
        source_line_domains: common_report.source_line_domains,
        first_match,
        last_match,
        receipt,
    })
}

#[allow(
    clippy::result_large_err,
    reason = "typed common-session refusals retain their closed receipt by value"
)]
fn finish_word(
    attempt: crate::operation_session::OperationSessionAttempt<
        '_,
        crate::operation_session::grep::Slot,
    >,
    report: word::Report,
    order: GrepStreamOrderProof,
) -> Result<PortableGrepResult, PortableGrepError> {
    let first_match = report.first_match().map(word_match);
    let last_match = report.last_match().map(word_match);
    let common_report = GrepStreamExecutionReport {
        source_line_domains: report.domains_examined(),
        actual: OperationSessionExecutionActual {
            work: report.work(),
            source_accesses: report.source_accesses(),
            transitions: report.transitions(),
            candidates: report.candidates(),
            cache_misses: 0,
            history_nodes: 0,
            line_domains: report.matching_lines(),
            output_events: report.matching_lines(),
            selected_span_bytes: 0,
            participation_entries: 0,
            allocations: 0,
        },
        first_match: first_match.map(common_match),
        last_match: last_match.map(common_match),
    };
    let receipt = attempt
        .finish_stream_count(common_report, order)
        .map_err(map_commit_error)?;
    Ok(PortableGrepResult {
        count: report.matching_lines(),
        source_line_domains: common_report.source_line_domains,
        first_match,
        last_match,
        receipt,
    })
}

fn literal_match(value: literal::MatchedLine) -> PortableGrepMatch {
    PortableGrepMatch {
        line_ordinal: value.ordinal(),
        line_start: value.line_start(),
        line_content_end: value.content_end(),
        line_source_end: value.source_end(),
        match_start: value.match_start(),
        match_end: value.match_end(),
    }
}

fn k0_match(value: k0_grep::MatchedLine) -> PortableGrepMatch {
    let selected = value.selected_match();
    PortableGrepMatch {
        line_ordinal: value.ordinal(),
        line_start: value.line_start(),
        line_content_end: value.content_end(),
        line_source_end: value.source_end(),
        match_start: selected.start(),
        match_end: selected.end(),
    }
}

fn word_match(value: word::MatchedLine) -> PortableGrepMatch {
    PortableGrepMatch {
        line_ordinal: value.ordinal(),
        line_start: value.line_start(),
        line_content_end: value.content_end(),
        line_source_end: value.source_end(),
        match_start: value.match_start(),
        match_end: value.match_end(),
    }
}

fn literal_actual(value: literal::Actual) -> OperationSessionExecutionActual {
    OperationSessionExecutionActual {
        work: value.work(),
        source_accesses: value.source_accesses(),
        transitions: value.transitions(),
        candidates: value.candidates(),
        cache_misses: 0,
        history_nodes: 0,
        line_domains: value.matching_lines(),
        output_events: value.matching_lines(),
        selected_span_bytes: 0,
        participation_entries: 0,
        allocations: 0,
    }
}

fn k0_actual(value: k0_grep::GrepStreamActual) -> OperationSessionExecutionActual {
    OperationSessionExecutionActual {
        work: value.work(),
        source_accesses: value.source_accesses(),
        transitions: value.transitions(),
        candidates: value.candidates(),
        cache_misses: value.cache_misses(),
        history_nodes: value.history_nodes(),
        line_domains: value.line_domains(),
        output_events: value.output_events(),
        selected_span_bytes: 0,
        participation_entries: 0,
        allocations: value.allocations(),
    }
}

fn word_actual(value: word::Actual) -> OperationSessionExecutionActual {
    OperationSessionExecutionActual {
        work: value.work(),
        source_accesses: value.source_accesses(),
        transitions: value.transitions(),
        candidates: value.candidates(),
        cache_misses: 0,
        history_nodes: 0,
        line_domains: value.matching_lines(),
        output_events: value.matching_lines(),
        selected_span_bytes: 0,
        participation_entries: 0,
        allocations: 0,
    }
}

const fn common_match(value: PortableGrepMatch) -> GrepStreamMatch {
    GrepStreamMatch {
        line_ordinal: value.line_ordinal,
        line_start: value.line_start,
        line_content_end: value.line_content_end,
        line_source_end: value.line_source_end,
        match_start: value.match_start,
        match_end: value.match_end,
    }
}

fn order_error_detail(error: GrepStreamOrderError) -> &'static str {
    match error {
        GrepStreamOrderError::InvalidCoordinates => {
            "engine observer emitted invalid selected-line coordinates"
        }
        GrepStreamOrderError::InvalidOrder => {
            "engine observer emitted a non-increasing selected-line sequence"
        }
        GrepStreamOrderError::ArithmeticOverflow => {
            "engine observer selected-line count overflowed"
        }
    }
}

fn observer_execution_error(error: GrepStreamOrderError) -> PortableGrepExecutionError {
    PortableGrepExecutionError::ObserverOrder {
        detail: order_error_detail(error),
    }
}

fn close_execution(
    attempt: crate::operation_session::OperationSessionAttempt<
        '_,
        crate::operation_session::grep::Slot,
    >,
    actual: OperationSessionExecutionActual,
    order: GrepStreamOrderProof,
    failure: GrepStreamFailure,
    source: PortableGrepExecutionError,
) -> PortableGrepError {
    PortableGrepError::Execution {
        source,
        attempt: attempt.fail_stream_count(actual, order, failure),
    }
}

fn map_begin_error(error: GrepStreamBeginError) -> PortableGrepError {
    match error {
        GrepStreamBeginError::InvalidCompiledPlanIdentity => PortableGrepError::InternalInvariant {
            detail: "derived compiled grep plan identity was zero",
        },
        GrepStreamBeginError::Attempt(error) => PortableGrepError::Attempt(error),
    }
}

fn map_commit_error(error: GrepStreamCommitError) -> PortableGrepError {
    match error {
        GrepStreamCommitError::GenerationReservationInvariant => {
            PortableGrepError::InternalInvariant {
                detail: "common reset did not reserve the grep generation interval",
            }
        }
        GrepStreamCommitError::ReportInvariant(_) => PortableGrepError::InternalInvariant {
            detail: "engine report did not close the common grep receipt",
        },
        GrepStreamCommitError::Attempt(error) => PortableGrepError::Attempt(error),
    }
}

fn compiled_plan_id(regex: &PortableRegex) -> [u8; 16] {
    let mut digest = CompiledPlanDigest::new();
    digest.tagged_bytes(0x01, regex.runtime_implementation_id().as_bytes());
    digest.tagged_bytes(0x02, regex.as_str().as_bytes());
    digest.byte(0x03);
    write!(
        &mut digest,
        "{:?};{:?};{:?};{:?}",
        regex.profile, regex.limits, regex.selection, regex.report.plan
    )
    .expect("compiled-plan identity writer is infallible");
    match &regex.plan {
        PortablePlan::ExactLiteral(plan) => {
            digest.tagged_bytes(0x0f, plan.needle());
        }
        PortablePlan::K0(automaton) => {
            digest.tagged_bytes(0x10, &k0_grep::structural_plan_identity(automaton));
        }
        PortablePlan::UnicodeWordRun(plan) if word::supports(*plan) => {
            digest.byte(0x11);
            write!(&mut digest, "{plan:?}").expect("compiled-plan identity writer is infallible");
        }
        _ => {
            digest.byte(0xff);
        }
    }
    digest.finish()
}

struct CompiledPlanDigest {
    left: u64,
    right: u64,
}

impl CompiledPlanDigest {
    const fn new() -> Self {
        Self {
            left: 0xcbf2_9ce4_8422_2325,
            right: 0x8422_2325_cbf2_9ce4,
        }
    }

    fn byte(&mut self, byte: u8) {
        self.left ^= u64::from(byte);
        self.left = self.left.wrapping_mul(0x0000_0100_0000_01b3);
        self.right ^= u64::from(byte).rotate_left(1);
        self.right = self
            .right
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .rotate_left(7);
    }

    fn tagged_bytes(&mut self, tag: u8, bytes: &[u8]) {
        self.byte(tag);
        for byte in bytes.len().to_le_bytes() {
            self.byte(byte);
        }
        for byte in bytes.iter().copied() {
            self.byte(byte);
        }
    }

    fn finish(self) -> [u8; 16] {
        let mut identity = [0_u8; 16];
        identity[..8].copy_from_slice(&self.left.to_le_bytes());
        identity[8..].copy_from_slice(&self.right.to_le_bytes());
        if identity == [0; 16] {
            identity[0] = 1;
        }
        identity
    }
}

impl core::fmt::Write for CompiledPlanDigest {
    fn write_str(&mut self, value: &str) -> core::fmt::Result {
        for byte in value.as_bytes().iter().copied() {
            self.byte(byte);
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    reason = "small adversarial fixtures exercise every line and one-below resource dimension"
)]
mod tests {
    use super::*;
    use crate::{
        SearchLimits,
        operation_session::{OperationSessionResource, OperationSessionTerminal},
    };

    fn semantic_lines(source: &[u8]) -> Vec<(usize, usize, usize)> {
        let mut lines = Vec::new();
        let mut line_start = 0;
        for (index, byte) in source.iter().copied().enumerate() {
            if byte != b'\n' {
                continue;
            }
            let content_end = if index > line_start && source[index - 1] == b'\r' {
                index - 1
            } else {
                index
            };
            lines.push((line_start, content_end, index + 1));
            line_start = index + 1;
        }
        if line_start < source.len() {
            lines.push((line_start, source.len(), source.len()));
        }
        lines
    }

    fn repeated_search_trace(regex: &PortableRegex, source: &[u8]) -> Vec<PortableGrepMatch> {
        semantic_lines(source)
            .into_iter()
            .enumerate()
            .filter_map(
                |(line_ordinal, (line_start, line_content_end, line_source_end))| {
                    let line = &source[line_start..line_content_end];
                    let (selected, _) = regex
                        .find(line, SearchLimits::unlimited())
                        .expect("repeated current-plan search");
                    selected.map(|selected| PortableGrepMatch {
                        line_ordinal,
                        line_start,
                        line_content_end,
                        line_source_end,
                        match_start: line_start + selected.start(),
                        match_end: line_start + selected.end(),
                    })
                },
            )
            .collect()
    }

    fn execute(session: &mut PortableGrepSession<'_>, source: &[u8]) -> PortableGrepResult {
        let prospective = session.prospective(source.len()).expect("prospective");
        let (reset, run) = session.exact_limits(prospective).expect("exact limits");
        session
            .count_matching_lines(source, prospective, reset, run)
            .expect("grep stream")
    }

    fn assert_matches_repeated(regex: &PortableRegex, source: &[u8]) {
        let expected = repeated_search_trace(regex, source);
        let expected_domains = semantic_lines(source).len();
        let mut session = regex.grep_stream_session().expect("grep session");
        assert!(session.construction_receipt().closes());
        let first = execute(&mut session, source);
        assert!(first.receipt.closes());
        assert_eq!(first.source_line_domains, expected_domains);
        assert_eq!(first.count(), u64::try_from(expected.len()).expect("count"));
        assert_eq!(first.first_match, expected.first().copied());
        assert_eq!(first.last_match, expected.last().copied());
        assert_eq!(
            first.receipt.value,
            Some(crate::operation_session::OperationSessionValue::Count(
                first.count()
            ))
        );
        assert_eq!(first.receipt.actual.allocations, 0);

        let second = execute(&mut session, source);
        assert!(second.receipt.closes());
        assert_eq!(second.count(), first.count());
        assert_eq!(second.first_match, first.first_match);
        assert_eq!(second.last_match, first.last_match);
        assert!(second.reset_invocations_after() > first.reset_invocations_after());
    }

    impl PortableGrepResult {
        fn reset_invocations_after(&self) -> u64 {
            self.receipt.reset.actual.counters_after.reset_invocations
        }
    }

    #[test]
    fn shared_exact_literal_plan_is_reached_by_the_normal_grep_api() {
        let regex = PortableRegex::new("ab").expect("portable exact literal");
        assert_eq!(regex.build_report().plan, crate::PlanKind::ExactLiteral);
        assert_eq!(regex.runtime_implementation_id(), "exact-literal");
        let source = b"xxab\r\nmiss\nab\rstill\nab";
        assert_matches_repeated(&regex, source);

        let mut session = regex.grep_stream_session().expect("normal grep session");
        let result = session.count(source).expect("normal whole-input count");
        assert!(result.receipt.closes());
        assert_eq!(result.count(), 3);
        assert_eq!(result.source_line_domains, 4);
        assert_eq!(
            result.first_match,
            Some(PortableGrepMatch {
                line_ordinal: 0,
                line_start: 0,
                line_content_end: 4,
                line_source_end: 6,
                match_start: 2,
                match_end: 4,
            })
        );
        assert_eq!(
            result.last_match,
            Some(PortableGrepMatch {
                line_ordinal: 3,
                line_start: 20,
                line_content_end: 22,
                line_source_end: 22,
                match_start: 20,
                match_end: 22,
            })
        );
    }

    #[test]
    fn k0_facade_preserves_line_local_anchors_crlf_offsets_and_reuse() {
        let regex = PortableRegex::new(r"(?-u)^(?:ab|a[cd]+?)[^\n]*z$").expect("portable regex");
        assert_eq!(regex.runtime_implementation_id(), "k0");
        assert_matches_repeated(&regex, b"\nabz\r\nacccqz\nno\nadzz");
        assert_matches_repeated(&regex, b"");
        assert_matches_repeated(&regex, b"\n\n");
    }

    #[test]
    fn native_word_facade_matches_current_plan_on_unicode_and_malformed_bytes() {
        let regex = PortableRegex::new(r"\b\w{2,}\b").expect("portable regex");
        assert_eq!(
            regex.runtime_implementation_id(),
            crate::unicode_word_run::UNICODE_PLAN_ID
        );
        let source = [
            b'\n', 0xCE, 0xB1, 0xCE, 0xB2, b'\r', b'\n', b'x', b'\n', b'a', 0x80, b'a', b'a',
            b'\n', b'z', b'_',
        ];
        assert_matches_repeated(&regex, &source);
    }

    #[test]
    fn literal_k0_and_word_positive_dimensions_refuse_one_below_before_execution() {
        for regex in [
            PortableRegex::new("ab").expect("literal regex"),
            PortableRegex::new(r"(?-u)^(?:ab|a[cd]+?)[^\n]*z$").expect("K0 regex"),
            PortableRegex::new(r"\b\w{2,}\b").expect("word regex"),
        ] {
            let source = b"abz\nmiss\nacdz";
            let mut session = regex.grep_stream_session().expect("grep session");
            let prospective = session.prospective(source.len()).expect("prospective");
            let (reset_limits, exact) = session.exact_limits(prospective).expect("exact limits");
            for resource in [
                OperationSessionResource::ExecutionWork,
                OperationSessionResource::SourceAccesses,
                OperationSessionResource::Transitions,
                OperationSessionResource::Candidates,
                OperationSessionResource::LineDomains,
                OperationSessionResource::OutputEvents,
            ] {
                let mut one_below = exact;
                let limit = match resource {
                    OperationSessionResource::ExecutionWork => &mut one_below.max_work,
                    OperationSessionResource::SourceAccesses => &mut one_below.max_source_accesses,
                    OperationSessionResource::Transitions => &mut one_below.max_transitions,
                    OperationSessionResource::Candidates => &mut one_below.max_candidates,
                    OperationSessionResource::LineDomains => &mut one_below.max_line_domains,
                    OperationSessionResource::OutputEvents => &mut one_below.max_output_events,
                    _ => unreachable!("fixed positive-dimension matrix"),
                };
                assert!(*limit > 0);
                *limit -= 1;
                let error = session
                    .count_matching_lines(source, prospective, reset_limits, one_below)
                    .expect_err("one-below limit must refuse");
                let receipt = match error {
                    PortableGrepError::Attempt(
                        OperationSessionAttemptError::Refused(receipt)
                        | OperationSessionAttemptError::ReceiptNotClosed(receipt),
                    ) => receipt,
                    other => panic!("unexpected one-below error: {other:?}"),
                };
                assert!(receipt.closes());
                assert_eq!(
                    receipt.terminal,
                    OperationSessionTerminal::Refused(resource)
                );
                assert_eq!(receipt.actual, OperationSessionExecutionActual::default());
            }

            if reset_limits.max_work != 0 {
                let mut one_below_reset = reset_limits;
                one_below_reset.max_work -= 1;
                let error = session
                    .count_matching_lines(source, prospective, one_below_reset, exact)
                    .expect_err("reset one-below must refuse");
                let receipt = match error {
                    PortableGrepError::Attempt(
                        OperationSessionAttemptError::Refused(receipt)
                        | OperationSessionAttemptError::ReceiptNotClosed(receipt),
                    ) => receipt,
                    other => panic!("unexpected reset error: {other:?}"),
                };
                assert!(receipt.closes());
                assert_eq!(
                    receipt.terminal,
                    OperationSessionTerminal::Refused(OperationSessionResource::ResetWork)
                );
                assert_eq!(receipt.actual, OperationSessionExecutionActual::default());
            }
        }
    }

    #[test]
    fn compiled_identity_is_replay_stable_and_separates_graphs_and_native_plans() {
        let first = PortableRegex::new(r"(?-u)^(?:ab|a[cd]+?)[^\n]*z$").expect("first K0 regex");
        let replay = first.clone();
        let second = PortableRegex::new(r"(?-u)^(?:ab|a[ef]+?)[^\n]*z$").expect("second K0 regex");
        let word = PortableRegex::new(r"\b\w{2,}\b").expect("word regex");
        let literal = PortableRegex::new("ab").expect("literal regex");
        let other_literal = PortableRegex::new("ac").expect("other literal regex");
        assert_ne!(compiled_plan_id(&first), [0; 16]);
        assert_eq!(compiled_plan_id(&first), compiled_plan_id(&replay));
        assert_ne!(compiled_plan_id(&first), compiled_plan_id(&second));
        assert_ne!(compiled_plan_id(&first), compiled_plan_id(&word));
        assert_ne!(compiled_plan_id(&literal), compiled_plan_id(&other_literal));
        assert_ne!(compiled_plan_id(&literal), compiled_plan_id(&first));
    }
}
