//! Deterministic line-domain-plan-backed whole-input grep reduction.
//!
//! The grep facade defines source domains with `ByteSlice` LF/CRLF semantics.
//! Each already-partitioned content slice is therefore searched through the
//! immutable line-domain plan. This is intentionally different from running
//! the plan once over the original source: the grep partition strips a CR
//! immediately before LF, while the plan's own configured terminator remains
//! meaningful inside each content slice.

use core::convert::Infallible;

use fre_kernels::{
    LINE_DOMAIN_BYTE_ATOMS_PLAN_ID,
    LineDomainByteAtomsOperation as Operation,
    LineDomainByteAtomsSearchActual as SharedActual,
    LineDomainByteAtomsSearchError as SharedError,
};

use crate::{SearchLimits, SearchWindow, line_domain_byte_atoms::OwnedPlan};

/// Source-free envelope for one immutable plan and source length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Prospective {
    plan_instance: usize,
    haystack_len: usize,
    work: u64,
    source_accesses: u64,
    transitions: u64,
    candidates: u64,
    line_domains: u64,
}

impl Prospective {
    #[must_use]
    pub(crate) const fn work(self) -> u64 {
        self.work
    }

    #[must_use]
    pub(crate) const fn source_accesses(self) -> u64 {
        self.source_accesses
    }

    #[must_use]
    pub(crate) const fn transitions(self) -> u64 {
        self.transitions
    }

    #[must_use]
    pub(crate) const fn candidates(self) -> u64 {
        self.candidates
    }

    #[must_use]
    pub(crate) const fn line_domains(self) -> u64 {
        self.line_domains
    }

    const fn contains(self, actual: Actual) -> bool {
        actual.work <= self.work
            && actual.source_accesses <= self.source_accesses
            && actual.transitions <= self.transitions
            && actual.candidates <= self.candidates
            && actual.matching_lines <= self.line_domains
            && actual.domains_examined <= self.haystack_len
    }
}

/// Exact completed or partial execution counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Actual {
    work: u64,
    source_accesses: u64,
    transitions: u64,
    candidates: u64,
    domains_examined: usize,
    matching_lines: u64,
}

impl Actual {
    #[must_use]
    pub(crate) const fn work(self) -> u64 {
        self.work
    }

    #[must_use]
    pub(crate) const fn source_accesses(self) -> u64 {
        self.source_accesses
    }

    #[must_use]
    pub(crate) const fn transitions(self) -> u64 {
        self.transitions
    }

    #[must_use]
    pub(crate) const fn candidates(self) -> u64 {
        self.candidates
    }

    #[must_use]
    pub(crate) const fn domains_examined(self) -> usize {
        self.domains_examined
    }

    #[must_use]
    pub(crate) const fn matching_lines(self) -> u64 {
        self.matching_lines
    }
}

/// One matching semantic line and its selected plan span.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MatchedLine {
    ordinal: usize,
    line_start: usize,
    content_end: usize,
    source_end: usize,
    match_start: usize,
    match_end: usize,
}

impl MatchedLine {
    #[must_use]
    pub(crate) const fn ordinal(self) -> usize {
        self.ordinal
    }

    #[must_use]
    pub(crate) const fn line_start(self) -> usize {
        self.line_start
    }

    #[must_use]
    pub(crate) const fn content_end(self) -> usize {
        self.content_end
    }

    #[must_use]
    pub(crate) const fn source_end(self) -> usize {
        self.source_end
    }

    #[must_use]
    pub(crate) const fn match_start(self) -> usize {
        self.match_start
    }

    #[must_use]
    pub(crate) const fn match_end(self) -> usize {
        self.match_end
    }
}

/// Successful constant-space whole-input result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Report {
    prospective: Prospective,
    actual: Actual,
    first_match: Option<MatchedLine>,
    last_match: Option<MatchedLine>,
}

impl Report {
    #[must_use]
    pub(crate) const fn prospective(self) -> Prospective {
        self.prospective
    }

    #[must_use]
    pub(crate) const fn actual(self) -> Actual {
        self.actual
    }

    #[must_use]
    pub(crate) const fn first_match(self) -> Option<MatchedLine> {
        self.first_match
    }

    #[must_use]
    pub(crate) const fn last_match(self) -> Option<MatchedLine> {
        self.last_match
    }
}

/// Line-domain grep preflight, shared-plan, or accounting failure.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Checked prospective or execution arithmetic overflowed.
    ArithmeticOverflow {
        /// Stable failing computation.
        computation: &'static str,
    },
    /// The supplied source-free envelope differs from the exact requirement.
    AdmissionMismatch,
    /// The shared immutable line-domain plan refused a content slice.
    SharedPlan(SharedError),
    /// Exact execution accounting exceeded its source-free envelope.
    AccountingBoundExceeded {
        /// Stable resource name.
        resource: &'static str,
        /// Admitted maximum.
        limit: u64,
        /// First value beyond the admitted maximum.
        attempted: u64,
    },
    /// Shared-plan evidence and line reduction evidence diverged.
    InternalInvariant {
        /// Stable invariant description.
        detail: &'static str,
    },
}

impl core::fmt::Display for Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "grep line-domain reducer failed: {self:?}")
    }
}

impl std::error::Error for Error {}

/// Failure with exact accounting through the terminal.
#[derive(Debug)]
pub(crate) enum ObservedError<E> {
    Execution { error: Error, partial: Actual },
    Observer { error: E, partial: Actual },
}

/// Derive complete source-free maxima without reading the source.
pub(crate) fn prospective(
    plan: &OwnedPlan,
    haystack_len: usize,
) -> Result<Prospective, Error> {
    let plan_instance = plan.instance_identity();
    if haystack_len == 0 {
        return Ok(Prospective {
            plan_instance,
            haystack_len,
            work: 0,
            source_accesses: 0,
            transitions: 0,
            candidates: 0,
            line_domains: 0,
        });
    }
    let input = u64::try_from(haystack_len).map_err(|_| Error::ArithmeticOverflow {
        computation: "input length conversion",
    })?;
    let shared = plan
        .grep_full_window_upper_bounds(haystack_len)
        .map_err(Error::SharedPlan)?;

    // Across ByteSlice-compatible semantic lines, total content bytes are at
    // most n and the number of searches is at most n. Every shared-kernel
    // bound is monotone affine in content bytes and `content + searches`.
    // Twice the full-n bound therefore dominates all restarted line searches
    // (including its two extra candidate units) without copying kernel math.
    let shared_work = doubled(shared.work, "shared work bound")?;
    let shared_source_accesses = doubled(shared.source_reads, "shared source-access bound")?;
    let shared_transitions = shared
        .delimiter_steps
        .checked_add(shared.atom_transitions)
        .and_then(|value| value.checked_mul(2))
        .ok_or(Error::ArithmeticOverflow {
            computation: "shared transition bound",
        })?;
    let shared_candidates = doubled(shared.candidate_events, "shared candidate bound")?;
    let partition_work = input.checked_mul(5).ok_or(Error::ArithmeticOverflow {
        computation: "line partition work bound",
    })?;
    let partition_source_accesses =
        input.checked_mul(2).ok_or(Error::ArithmeticOverflow {
            computation: "line partition source-access bound",
        })?;
    let work = shared_work
        .checked_add(partition_work)
        .ok_or(Error::ArithmeticOverflow {
            computation: "complete work bound",
        })?;
    let source_accesses = shared_source_accesses
        .checked_add(partition_source_accesses)
        .ok_or(Error::ArithmeticOverflow {
            computation: "complete source-access bound",
        })?;
    let transitions = shared_transitions
        .checked_add(input)
        .ok_or(Error::ArithmeticOverflow {
            computation: "complete transition bound",
        })?;
    let candidates = shared_candidates
        .checked_add(input)
        .ok_or(Error::ArithmeticOverflow {
            computation: "complete candidate bound",
        })?;
    Ok(Prospective {
        plan_instance,
        haystack_len,
        work,
        source_accesses,
        transitions,
        candidates,
        line_domains: input,
    })
}

/// Count matching lines without observing the selected sequence.
#[allow(dead_code, reason = "the facade uses the observer form")]
pub(crate) fn count_matching_lines(
    plan: &OwnedPlan,
    haystack: &[u8],
    admitted: Prospective,
) -> Result<Report, Error> {
    match count_matching_lines_with_observer(plan, haystack, admitted, |_| {
        Ok::<(), Infallible>(())
    }) {
        Ok(report) => Ok(report),
        Err(ObservedError::Execution { error, .. }) => Err(error),
        Err(ObservedError::Observer { error, .. }) => match error {},
    }
}

/// Count matching lines through the shared plan and observe each selected hit.
#[allow(
    clippy::too_many_lines,
    reason = "one shared-plan traversal keeps CRLF partition state and every terminal ledger in one audit scope"
)]
pub(crate) fn count_matching_lines_with_observer<E, F>(
    plan: &OwnedPlan,
    haystack: &[u8],
    admitted: Prospective,
    mut observer: F,
) -> Result<Report, ObservedError<E>>
where
    F: FnMut(MatchedLine) -> Result<(), E>,
{
    let required = prospective(plan, haystack.len()).map_err(|error| ObservedError::Execution {
        error,
        partial: Actual::default(),
    })?;
    if admitted != required {
        return Err(ObservedError::Execution {
            error: Error::AdmissionMismatch,
            partial: Actual::default(),
        });
    }

    let mut meter = Meter::new(required);
    let mut first_match = None;
    let mut last_match = None;
    let mut line_start = 0_usize;
    let mut line_ordinal = 0_usize;
    let mut previous_is_cr = false;
    let mut source_index = 0_usize;

    while source_index < haystack.len() {
        meter
            .scan_byte()
            .map_err(|error| ObservedError::Execution {
                error,
                partial: meter.actual,
            })?;
        let byte = haystack[source_index];
        if byte == b'\n' {
            let content_end = if previous_is_cr && source_index > line_start {
                source_index
                    .checked_sub(1)
                    .ok_or_else(|| ObservedError::Execution {
                        error: Error::ArithmeticOverflow {
                            computation: "CRLF content end",
                        },
                        partial: meter.actual,
                    })?
            } else {
                source_index
            };
            let source_end =
                source_index
                    .checked_add(1)
                    .ok_or_else(|| ObservedError::Execution {
                        error: Error::ArithmeticOverflow {
                            computation: "LF source end",
                        },
                        partial: meter.actual,
                    })?;
            finish_line(
                plan,
                haystack,
                line_ordinal,
                line_start,
                content_end,
                source_end,
                &mut meter,
                &mut first_match,
                &mut last_match,
                &mut observer,
            )?;
            line_start = source_end;
            line_ordinal =
                line_ordinal
                    .checked_add(1)
                    .ok_or_else(|| ObservedError::Execution {
                        error: Error::ArithmeticOverflow {
                            computation: "line ordinal",
                        },
                        partial: meter.actual,
                    })?;
            previous_is_cr = false;
        } else {
            previous_is_cr = byte == b'\r';
        }
        source_index =
            source_index
                .checked_add(1)
                .ok_or_else(|| ObservedError::Execution {
                    error: Error::ArithmeticOverflow {
                        computation: "source index",
                    },
                    partial: meter.actual,
                })?;
    }

    if line_start < haystack.len() {
        finish_line(
            plan,
            haystack,
            line_ordinal,
            line_start,
            haystack.len(),
            haystack.len(),
            &mut meter,
            &mut first_match,
            &mut last_match,
            &mut observer,
        )?;
    }

    let actual = meter.actual;
    verify_report(required, actual, first_match, last_match).map_err(|error| {
        ObservedError::Execution {
            error,
            partial: actual,
        }
    })?;
    Ok(Report {
        prospective: required,
        actual,
        first_match,
        last_match,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "one semantic line owns exact source and selected-match boundaries"
)]
fn finish_line<E, F>(
    plan: &OwnedPlan,
    haystack: &[u8],
    ordinal: usize,
    line_start: usize,
    content_end: usize,
    source_end: usize,
    meter: &mut Meter,
    first_match: &mut Option<MatchedLine>,
    last_match: &mut Option<MatchedLine>,
    observer: &mut F,
) -> Result<(), ObservedError<E>>
where
    F: FnMut(MatchedLine) -> Result<(), E>,
{
    meter
        .candidate()
        .map_err(|error| ObservedError::Execution {
            error,
            partial: meter.actual,
        })?;
    let line = haystack
        .get(line_start..content_end)
        .ok_or_else(|| ObservedError::Execution {
            error: Error::InternalInvariant {
                detail: "semantic line content range was invalid",
            },
            partial: meter.actual,
        })?;
    let (selected, accounting) = plan
        .find_window(
            line,
            SearchWindow::full(line),
            SearchLimits::unlimited(),
            Operation::Span,
        )
        .map_err(|error| ObservedError::Execution {
            error: Error::SharedPlan(error),
            partial: meter.actual,
        })?;
    if accounting.plan_id != LINE_DOMAIN_BYTE_ATOMS_PLAN_ID
        || accounting.operation != Operation::Span
        || accounting.window_start != 0
        || accounting.window_end != line.len()
        || !accounting.upper_bounds.contains(accounting.actual)
        || selected.is_some() != (accounting.actual.match_events != 0)
        || accounting.actual.match_events > 1
    {
        return Err(ObservedError::Execution {
            error: Error::InternalInvariant {
                detail: "shared plan returned an invalid line-search receipt",
            },
            partial: meter.actual,
        });
    }
    meter
        .shared(accounting.actual)
        .map_err(|error| ObservedError::Execution {
            error,
            partial: meter.actual,
        })?;

    if let Some(selected) = selected {
        let match_start = line_start.checked_add(selected.start()).ok_or_else(|| {
            ObservedError::Execution {
                error: Error::ArithmeticOverflow {
                    computation: "absolute selected-match start",
                },
                partial: meter.actual,
            }
        })?;
        let match_end =
            line_start
                .checked_add(selected.end())
                .ok_or_else(|| ObservedError::Execution {
                    error: Error::ArithmeticOverflow {
                        computation: "absolute selected-match end",
                    },
                    partial: meter.actual,
                })?;
        if selected.start() >= selected.end()
            || selected.end() > line.len()
            || match_start >= match_end
            || match_end > content_end
        {
            return Err(ObservedError::Execution {
                error: Error::InternalInvariant {
                    detail: "shared plan returned a span outside its semantic line",
                },
                partial: meter.actual,
            });
        }
        meter
            .selected()
            .map_err(|error| ObservedError::Execution {
                error,
                partial: meter.actual,
            })?;
        let matched = MatchedLine {
            ordinal,
            line_start,
            content_end,
            source_end,
            match_start,
            match_end,
        };
        first_match.get_or_insert(matched);
        *last_match = Some(matched);
        if let Err(error) = observer(matched) {
            return Err(ObservedError::Observer {
                error,
                partial: meter.actual,
            });
        }
    }
    Ok(())
}

fn verify_report(
    prospective: Prospective,
    actual: Actual,
    first_match: Option<MatchedLine>,
    last_match: Option<MatchedLine>,
) -> Result<(), Error> {
    if !prospective.contains(actual) {
        return Err(Error::InternalInvariant {
            detail: "line-domain actual escaped its prospective",
        });
    }
    let domains = u64::try_from(actual.domains_examined).map_err(|_| {
        Error::InternalInvariant {
            detail: "semantic line-domain count does not fit u64",
        }
    })?;
    if actual.matching_lines > domains {
        return Err(Error::InternalInvariant {
            detail: "matching-line count exceeded examined line domains",
        });
    }
    if first_match.is_some() != (actual.matching_lines != 0)
        || last_match.is_some() != (actual.matching_lines != 0)
    {
        return Err(Error::InternalInvariant {
            detail: "line-domain match endpoints and count diverged",
        });
    }
    Ok(())
}

struct Meter {
    prospective: Prospective,
    actual: Actual,
}

impl Meter {
    const fn new(prospective: Prospective) -> Self {
        Self {
            prospective,
            actual: Actual {
                work: 0,
                source_accesses: 0,
                transitions: 0,
                candidates: 0,
                domains_examined: 0,
                matching_lines: 0,
            },
        }
    }

    fn scan_byte(&mut self) -> Result<(), Error> {
        self.add_source_accesses(1)?;
        self.add_transitions(1)?;
        self.add_work(2)
    }

    fn candidate(&mut self) -> Result<(), Error> {
        self.actual.domains_examined = self.actual.domains_examined.checked_add(1).ok_or(
            Error::ArithmeticOverflow {
                computation: "examined line domains",
            },
        )?;
        self.add_candidates(1)?;
        self.add_work(1)
    }

    fn shared(&mut self, actual: SharedActual) -> Result<(), Error> {
        if actual.allocations != 0 || actual.scratch_bytes != 0 {
            return Err(Error::InternalInvariant {
                detail: "shared line-domain search used unadmitted operation storage",
            });
        }
        let transitions = actual
            .delimiter_steps
            .checked_add(actual.atom_transitions)
            .ok_or(Error::ArithmeticOverflow {
                computation: "shared transition actual",
            })?;
        self.add_source_accesses(actual.source_reads)?;
        self.add_transitions(transitions)?;
        self.add_candidates(actual.candidate_events)?;
        self.add_work(actual.work)
    }

    fn selected(&mut self) -> Result<(), Error> {
        let attempted = self.actual.matching_lines.checked_add(1).ok_or(
            Error::ArithmeticOverflow {
                computation: "matching-line count",
            },
        )?;
        if attempted > self.prospective.line_domains {
            return Err(Error::AccountingBoundExceeded {
                resource: "matching lines",
                limit: self.prospective.line_domains,
                attempted,
            });
        }
        self.actual.matching_lines = attempted;
        self.add_work(1)
    }

    fn add_work(&mut self, amount: u64) -> Result<(), Error> {
        checked_add(
            &mut self.actual.work,
            amount,
            self.prospective.work,
            "work",
        )
    }

    fn add_source_accesses(&mut self, amount: u64) -> Result<(), Error> {
        checked_add(
            &mut self.actual.source_accesses,
            amount,
            self.prospective.source_accesses,
            "source accesses",
        )
    }

    fn add_transitions(&mut self, amount: u64) -> Result<(), Error> {
        checked_add(
            &mut self.actual.transitions,
            amount,
            self.prospective.transitions,
            "transitions",
        )
    }

    fn add_candidates(&mut self, amount: u64) -> Result<(), Error> {
        checked_add(
            &mut self.actual.candidates,
            amount,
            self.prospective.candidates,
            "candidates",
        )
    }
}

fn doubled(value: u64, computation: &'static str) -> Result<u64, Error> {
    value
        .checked_mul(2)
        .ok_or(Error::ArithmeticOverflow { computation })
}

fn checked_add(
    current: &mut u64,
    amount: u64,
    limit: u64,
    resource: &'static str,
) -> Result<(), Error> {
    let attempted = current
        .checked_add(amount)
        .ok_or(Error::ArithmeticOverflow {
            computation: resource,
        })?;
    if attempted > limit {
        return Err(Error::AccountingBoundExceeded {
            resource,
            limit,
            attempted,
        });
    }
    *current = attempted;
    Ok(())
}
