//! Exact-literal-backed whole-input grep reduction.
//!
//! This adapter deliberately consumes the immutable [`LiteralPlan`] selected
//! by the normal portable constructor. It does not implement another literal
//! searcher. One allocation-free line partition pass supplies semantic
//! LF/CRLF windows to the shared preprocessed literal plan.

use core::convert::Infallible;

use crate::{LiteralError, LiteralPlan, LiteralSearchLimits, LiteralWindow};

/// Source-free exact envelope for one plan and haystack length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Prospective {
    needle_bytes: usize,
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

/// One matching semantic line and its selected exact-literal occurrence.
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

/// Exact-literal grep preflight, shared-plan, or invariant failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Checked prospective or execution arithmetic overflowed.
    ArithmeticOverflow {
        /// Stable failing computation.
        computation: &'static str,
    },
    /// The supplied source-free envelope differs from the exact requirement.
    AdmissionMismatch,
    /// The shared literal plan refused the requested line window.
    SharedLiteral(LiteralError),
    /// Exact execution accounting exceeded its source-free envelope.
    AccountingBoundExceeded {
        /// Stable resource name.
        resource: &'static str,
        /// Admitted maximum.
        limit: u64,
        /// First value beyond the admitted maximum.
        attempted: u64,
    },
    /// Shared-plan result and line reduction evidence diverged.
    InternalInvariant {
        /// Stable invariant description.
        detail: &'static str,
    },
}

impl core::fmt::Display for Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "grep exact-literal reducer failed: {self:?}")
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
pub(crate) fn prospective(plan: &LiteralPlan, haystack_len: usize) -> Result<Prospective, Error> {
    let input = u64::try_from(haystack_len).map_err(|_| Error::ArithmeticOverflow {
        computation: "input length conversion",
    })?;
    let needle = u64::try_from(plan.needle().len()).map_err(|_| Error::ArithmeticOverflow {
        computation: "needle length conversion",
    })?;
    let repeated_needles = input.checked_mul(needle).ok_or(Error::ArithmeticOverflow {
        computation: "per-line literal terms",
    })?;
    let source_accesses = input.checked_mul(2).ok_or(Error::ArithmeticOverflow {
        computation: "source-access bound",
    })?;
    let fixed_work = input.checked_mul(5).ok_or(Error::ArithmeticOverflow {
        computation: "partition and publication work bound",
    })?;
    let work = fixed_work
        .checked_add(repeated_needles)
        .ok_or(Error::ArithmeticOverflow {
            computation: "work bound",
        })?;
    Ok(Prospective {
        needle_bytes: plan.needle().len(),
        haystack_len,
        work,
        source_accesses,
        transitions: input,
        candidates: input,
        line_domains: input,
    })
}

/// Count matching lines without observing the selected sequence.
#[allow(dead_code, reason = "the facade uses the observer form")]
pub(crate) fn count_matching_lines(
    plan: &LiteralPlan,
    haystack: &[u8],
    admitted: Prospective,
) -> Result<Report, Error> {
    match count_matching_lines_with_observer(plan, haystack, admitted, |_| Ok::<(), Infallible>(()))
    {
        Ok(report) => Ok(report),
        Err(ObservedError::Execution { error, .. }) => Err(error),
        Err(ObservedError::Observer { error, .. }) => match error {},
    }
}

/// Count matching lines through the shared literal plan and observe each hit.
#[allow(
    clippy::too_many_lines,
    reason = "one shared literal traversal keeps CRLF state and every terminal ledger in one audit scope"
)]
pub(crate) fn count_matching_lines_with_observer<E, F>(
    plan: &LiteralPlan,
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

    let execution = (|| -> Result<(), ObservedError<E>> {
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
            source_index = source_index
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
        Ok(())
    })();
    execution?;

    let actual = meter.actual;
    if first_match.is_some() != (actual.matching_lines != 0)
        || last_match.is_some() != (actual.matching_lines != 0)
    {
        return Err(ObservedError::Execution {
            error: Error::InternalInvariant {
                detail: "literal match endpoints and count diverged",
            },
            partial: actual,
        });
    }
    Ok(Report {
        prospective: required,
        actual,
        first_match,
        last_match,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "one semantic line owns exact boundaries"
)]
fn finish_line<E, F>(
    plan: &LiteralPlan,
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
    let window = LiteralWindow::new(line_start, content_end);
    let (selected, accounting) = plan
        .find_window(haystack, window, LiteralSearchLimits::unlimited())
        .map_err(|error| ObservedError::Execution {
            error: Error::SharedLiteral(error),
            partial: meter.actual,
        })?;
    meter
        .literal(accounting.searched_bytes, accounting.linear_terms)
        .map_err(|error| ObservedError::Execution {
            error,
            partial: meter.actual,
        })?;
    if let Some((match_start, match_end)) = selected {
        meter.selected().map_err(|error| ObservedError::Execution {
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
        self.actual.domains_examined =
            self.actual
                .domains_examined
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow {
                    computation: "examined line domains",
                })?;
        self.add_candidates(1)?;
        self.add_work(1)
    }

    fn literal(&mut self, searched_bytes: usize, linear_terms: usize) -> Result<(), Error> {
        let searched = u64::try_from(searched_bytes).map_err(|_| Error::ArithmeticOverflow {
            computation: "literal searched-byte conversion",
        })?;
        let terms = u64::try_from(linear_terms).map_err(|_| Error::ArithmeticOverflow {
            computation: "literal linear-term conversion",
        })?;
        self.add_source_accesses(searched)?;
        self.add_work(terms)
    }

    fn selected(&mut self) -> Result<(), Error> {
        let attempted =
            self.actual
                .matching_lines
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow {
                    computation: "matching line count",
                })?;
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
        checked_add(&mut self.actual.work, amount, self.prospective.work, "work")
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LiteralBuildLimits;

    fn plan(needle: &[u8]) -> LiteralPlan {
        LiteralPlan::new(needle, LiteralBuildLimits::default()).expect("literal plan")
    }

    #[test]
    fn shared_literal_plan_preserves_lf_crlf_and_absolute_spans() {
        let plan = plan(b"ab");
        let source = b"xxab\r\nno\nab\rstill\nab";
        let prospective = prospective(&plan, source.len()).expect("prospective");
        let mut observed = Vec::new();
        let report = count_matching_lines_with_observer(&plan, source, prospective, |matched| {
            observed.push(matched);
            Ok::<(), Infallible>(())
        })
        .expect("literal grep");
        assert_eq!(report.actual().domains_examined(), 4);
        assert_eq!(report.actual().matching_lines(), 3);
        assert_eq!(
            observed
                .iter()
                .map(|matched| (
                    matched.ordinal(),
                    matched.line_start(),
                    matched.content_end(),
                    matched.source_end(),
                    matched.match_start(),
                    matched.match_end(),
                ))
                .collect::<Vec<_>>(),
            vec![
                (0, 0, 4, 6, 2, 4),
                (2, 9, 17, 18, 9, 11),
                (3, 18, 20, 20, 18, 20),
            ]
        );
    }

    #[test]
    fn empty_literal_matches_each_real_line_but_not_empty_input() {
        let plan = plan(b"");
        for (source, expected) in [
            (b"".as_slice(), 0),
            (b"\n".as_slice(), 1),
            (b"\n\n".as_slice(), 2),
            (b"x\n".as_slice(), 1),
            (b"x".as_slice(), 1),
        ] {
            let prospective = prospective(&plan, source.len()).expect("prospective");
            let report =
                count_matching_lines(&plan, source, prospective).expect("literal grep result");
            assert_eq!(report.actual().matching_lines(), expected);
        }
    }

    #[test]
    fn admission_mismatch_refuses_before_observation() {
        let plan = plan(b"x");
        let source = b"x\n";
        let mut admitted = prospective(&plan, source.len()).expect("prospective");
        admitted.work -= 1;
        let error = count_matching_lines_with_observer(
            &plan,
            source,
            admitted,
            |_| -> Result<(), Infallible> { panic!("observer must not run") },
        )
        .expect_err("mismatch");
        assert!(matches!(
            error,
            ObservedError::Execution {
                error: Error::AdmissionMismatch,
                partial: Actual {
                    work: 0,
                    source_accesses: 0,
                    ..
                },
            }
        ));
    }
}
