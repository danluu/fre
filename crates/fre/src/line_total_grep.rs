//! Construction-certified whole-line grep reduction.
//!
//! A retained [`Plan`] proves that the canonical HIR selects every byte of
//! every LF-delimited `ByteSlice` line. Execution therefore needs only the
//! line partition pass; it does not interpret the generic automaton again.

use core::convert::Infallible;

use memchr::memchr_iter;
use regex_syntax::hir::{Class, Hir, HirKind, Look};

/// Immutable proof that a canonical HIR greedily selects one complete line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Plan {
    start: Look,
    end: Look,
}

impl Plan {
    /// Stable structural identity retained in the compiled grep receipt.
    pub(crate) const fn identity(self) -> [u8; 4] {
        [1, look_identity(self.start), look_identity(self.end), 1]
    }
}

/// Prove the exact complete-line language from canonical HIR structure.
///
/// `ByteSlice::lines` never includes LF in a line-content domain, but every
/// other byte, including a lone CR and malformed UTF-8, is possible. The
/// repeated byte class must therefore cover all bytes except LF. A class that
/// also covers LF is harmless because execution evaluates the expression on
/// one already-partitioned line at a time.
pub(crate) fn prove(hir: &Hir) -> Option<Plan> {
    let HirKind::Concat(parts) = hir.kind() else {
        return None;
    };
    let [start_hir, repeated_hir, end_hir] = parts.as_slice() else {
        return None;
    };
    let HirKind::Look(start) = start_hir.kind() else {
        return None;
    };
    if !matches!(start, Look::Start | Look::StartLF | Look::StartCRLF) {
        return None;
    }
    let HirKind::Repetition(repetition) = repeated_hir.kind() else {
        return None;
    };
    if repetition.min != 0 || repetition.max.is_some() || !repetition.greedy {
        return None;
    }
    let HirKind::Class(Class::Bytes(class)) = repetition.sub.kind() else {
        return None;
    };
    if !covers_every_line_byte(class.ranges()) {
        return None;
    }
    let HirKind::Look(end) = end_hir.kind() else {
        return None;
    };
    if !matches!(end, Look::End | Look::EndLF | Look::EndCRLF) {
        return None;
    }
    Some(Plan {
        start: *start,
        end: *end,
    })
}

fn covers_every_line_byte(ranges: &[regex_syntax::hir::ClassBytesRange]) -> bool {
    match ranges {
        [all] => all.start() == u8::MIN && all.end() == u8::MAX,
        [before_lf, after_lf] => {
            before_lf.start() == u8::MIN
                && before_lf.end() == b'\n' - 1
                && after_lf.start() == b'\n' + 1
                && after_lf.end() == u8::MAX
        }
        _ => false,
    }
}

const fn look_identity(look: Look) -> u8 {
    match look {
        Look::Start => 1,
        Look::End => 2,
        Look::StartLF => 3,
        Look::EndLF => 4,
        Look::StartCRLF => 5,
        Look::EndCRLF => 6,
        _ => 0xff,
    }
}

/// Source-independent execution maxima bound to one construction proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Prospective {
    plan: Plan,
    haystack_len: usize,
    work: u64,
    source_accesses: u64,
    candidates: u64,
    line_domains: u64,
}

impl Prospective {
    pub(crate) const fn work(self) -> u64 {
        self.work
    }

    pub(crate) const fn source_accesses(self) -> u64 {
        self.source_accesses
    }

    #[allow(
        clippy::unused_self,
        reason = "the common engine envelope reads a uniform prospective interface"
    )]
    pub(crate) const fn transitions(self) -> u64 {
        0
    }

    pub(crate) const fn candidates(self) -> u64 {
        self.candidates
    }

    pub(crate) const fn line_domains(self) -> u64 {
        self.line_domains
    }

    const fn contains(self, actual: Actual) -> bool {
        actual.work <= self.work
            && actual.source_accesses <= self.source_accesses
            && actual.candidates <= self.candidates
            && actual.matching_lines <= self.line_domains
    }
}

/// Exact charged execution counters through a successful or refused terminal.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Actual {
    work: u64,
    source_accesses: u64,
    candidates: u64,
    domains_examined: usize,
    matching_lines: u64,
}

impl Actual {
    pub(crate) const fn work(self) -> u64 {
        self.work
    }

    pub(crate) const fn source_accesses(self) -> u64 {
        self.source_accesses
    }

    #[allow(
        clippy::unused_self,
        reason = "the common engine receipt reads a uniform actual interface"
    )]
    pub(crate) const fn transitions(self) -> u64 {
        0
    }

    pub(crate) const fn candidates(self) -> u64 {
        self.candidates
    }

    pub(crate) const fn domains_examined(self) -> usize {
        self.domains_examined
    }

    pub(crate) const fn matching_lines(self) -> u64 {
        self.matching_lines
    }
}

/// One construction-proved whole-line match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MatchedLine {
    ordinal: usize,
    line_start: usize,
    content_end: usize,
    source_end: usize,
}

impl MatchedLine {
    pub(crate) const fn ordinal(self) -> usize {
        self.ordinal
    }

    pub(crate) const fn line_start(self) -> usize {
        self.line_start
    }

    pub(crate) const fn content_end(self) -> usize {
        self.content_end
    }

    pub(crate) const fn source_end(self) -> usize {
        self.source_end
    }
}

/// Constant-space successful reduction report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Report {
    prospective: Prospective,
    actual: Actual,
    first_match: Option<MatchedLine>,
    last_match: Option<MatchedLine>,
}

impl Report {
    pub(crate) const fn prospective(self) -> Prospective {
        self.prospective
    }

    pub(crate) const fn actual(self) -> Actual {
        self.actual
    }

    pub(crate) const fn first_match(self) -> Option<MatchedLine> {
        self.first_match
    }

    pub(crate) const fn last_match(self) -> Option<MatchedLine> {
        self.last_match
    }
}

/// Checked construction-certified line reducer failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Checked prospective or execution arithmetic overflowed.
    ArithmeticOverflow {
        /// Stable failing computation.
        computation: &'static str,
    },
    /// The supplied proof/length envelope was not the exact requirement.
    AdmissionMismatch,
    /// Exact execution accounting exceeded its source-independent envelope.
    AccountingBoundExceeded,
    /// Complete-line evidence and accounting diverged.
    InternalInvariant {
        /// Stable invariant description.
        detail: &'static str,
    },
}

impl core::fmt::Display for Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "grep line-total reducer failed: {self:?}")
    }
}

impl std::error::Error for Error {}

/// Failure retaining exact accounting through the terminal.
#[derive(Debug)]
pub(crate) enum ObservedError<E> {
    Execution { error: Error, partial: Actual },
    Observer { error: E, partial: Actual },
}

impl<E> From<Error> for ObservedError<E> {
    fn from(error: Error) -> Self {
        Self::Execution {
            error,
            partial: Actual::default(),
        }
    }
}

/// Derive complete source-independent maxima without source access.
pub(crate) fn prospective(plan: Plan, haystack_len: usize) -> Result<Prospective, Error> {
    let input = u64::try_from(haystack_len).map_err(|_| Error::ArithmeticOverflow {
        computation: "input length conversion",
    })?;
    let source_accesses = input.checked_mul(2).ok_or(Error::ArithmeticOverflow {
        computation: "delimiter and CR source-access bound",
    })?;
    let work = input.checked_mul(5).ok_or(Error::ArithmeticOverflow {
        computation: "delimiter and publication work bound",
    })?;
    Ok(Prospective {
        plan,
        haystack_len,
        work,
        source_accesses,
        candidates: input,
        line_domains: input,
    })
}

/// Count every semantic line and observe its complete selected span.
pub(crate) fn count_matching_lines_with_observer<E, F>(
    plan: Plan,
    haystack: &[u8],
    admitted: Prospective,
    mut observer: F,
) -> Result<Report, ObservedError<E>>
where
    F: FnMut(MatchedLine) -> Result<(), E>,
{
    let required = prospective(plan, haystack.len())?;
    if admitted != required {
        return Err(Error::AdmissionMismatch.into());
    }
    let input = u64::try_from(haystack.len()).map_err(|_| Error::ArithmeticOverflow {
        computation: "charged source scan",
    })?;
    let mut actual = Actual {
        work: input,
        source_accesses: input,
        ..Actual::default()
    };
    let mut first_match = None;
    let mut last_match = None;
    let mut line_start = 0_usize;
    let mut line_ordinal = 0_usize;

    for lf_index in memchr_iter(b'\n', haystack) {
        let content_end = if lf_index > line_start {
            charge_cr_probe(&mut actual)?;
            let prior = lf_index.checked_sub(1).ok_or(Error::ArithmeticOverflow {
                computation: "CR probe index",
            })?;
            if haystack[prior] == b'\r' {
                prior
            } else {
                lf_index
            }
        } else {
            lf_index
        };
        let source_end = lf_index.checked_add(1).ok_or(Error::ArithmeticOverflow {
            computation: "LF source end",
        })?;
        finish_line(
            line_ordinal,
            line_start,
            content_end,
            source_end,
            &mut actual,
            &mut first_match,
            &mut last_match,
            &mut observer,
        )?;
        line_start = source_end;
        line_ordinal = line_ordinal
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow {
                computation: "line ordinal",
            })?;
    }
    if line_start < haystack.len() {
        finish_line(
            line_ordinal,
            line_start,
            haystack.len(),
            haystack.len(),
            &mut actual,
            &mut first_match,
            &mut last_match,
            &mut observer,
        )?;
    }
    verify_report(required, actual, first_match, last_match)?;
    Ok(Report {
        prospective: required,
        actual,
        first_match,
        last_match,
    })
}

#[allow(dead_code, reason = "the facade uses the observer form")]
pub(crate) fn count_matching_lines(
    plan: Plan,
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

fn charge_cr_probe(actual: &mut Actual) -> Result<(), Error> {
    actual.source_accesses =
        actual
            .source_accesses
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow {
                computation: "CR probe source access",
            })?;
    actual.work = actual
        .work
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow {
            computation: "CR probe work",
        })?;
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "line close binds all semantic boundaries and constant-space evidence"
)]
fn finish_line<E, F>(
    ordinal: usize,
    line_start: usize,
    content_end: usize,
    source_end: usize,
    actual: &mut Actual,
    first_match: &mut Option<MatchedLine>,
    last_match: &mut Option<MatchedLine>,
    observer: &mut F,
) -> Result<(), ObservedError<E>>
where
    F: FnMut(MatchedLine) -> Result<(), E>,
{
    actual.domains_examined =
        actual
            .domains_examined
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow {
                computation: "line-domain count",
            })?;
    actual.candidates = actual
        .candidates
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow {
            computation: "candidate count",
        })?;
    actual.matching_lines =
        actual
            .matching_lines
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow {
                computation: "matching-line count",
            })?;
    actual.work = actual
        .work
        .checked_add(3)
        .ok_or(Error::ArithmeticOverflow {
            computation: "line publication work",
        })?;
    let matched = MatchedLine {
        ordinal,
        line_start,
        content_end,
        source_end,
    };
    first_match.get_or_insert(matched);
    *last_match = Some(matched);
    observer(matched).map_err(|error| ObservedError::Observer {
        error,
        partial: *actual,
    })
}

fn verify_report(
    prospective: Prospective,
    actual: Actual,
    first_match: Option<MatchedLine>,
    last_match: Option<MatchedLine>,
) -> Result<(), Error> {
    if !prospective.contains(actual) {
        return Err(Error::AccountingBoundExceeded);
    }
    let domains = u64::try_from(actual.domains_examined).map_err(|_| Error::InternalInvariant {
        detail: "line-domain count does not fit u64",
    })?;
    if domains != actual.matching_lines {
        return Err(Error::InternalInvariant {
            detail: "line-total domain and output counts differ",
        });
    }
    if first_match.is_some() != (actual.matching_lines != 0)
        || last_match.is_some() != (actual.matching_lines != 0)
    {
        return Err(Error::InternalInvariant {
            detail: "line-total first/last evidence presence differs from output count",
        });
    }
    Ok(())
}
