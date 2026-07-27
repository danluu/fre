//! Allocation-free whole-input grep reduction for native word-run plans.
//!
//! The semantic domains are exactly those yielded by `bstr`'s
//! `ByteSlice::lines`: LF terminates a domain, one CR immediately before LF
//! is excluded from its content, lone CR bytes remain content, empty input
//! has no domains, and a trailing LF has no synthetic empty tail.

use core::convert::Infallible;

use crate::unicode_word_run::{Plan, WordMode};

/// Source-independent execution maxima for one exact word plan and source
/// length.
///
/// The plan identity is retained privately so an admission for another word
/// mode or repetition minimum cannot be replayed even though their numeric
/// envelopes are equal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Prospective {
    plan: Plan,
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

    /// Maximum matching line domains and output events.
    #[must_use]
    pub(crate) const fn line_domains(self) -> u64 {
        self.line_domains
    }

    const fn contains_actual(self, actual: Actual) -> bool {
        actual.work <= self.work
            && actual.source_accesses <= self.source_accesses
            && actual.transitions <= self.transitions
            && actual.candidates <= self.candidates
            && actual.matching_lines <= self.line_domains
    }
}

/// Exact counters at successful completion or observer refusal.
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

/// One matching line and its leftmost-first greedy word-run match.
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
    /// Zero-based ordinal among all semantic line domains.
    #[must_use]
    pub(crate) const fn ordinal(self) -> usize {
        self.ordinal
    }

    #[must_use]
    pub(crate) const fn line_start(self) -> usize {
        self.line_start
    }

    /// Exclusive content end after the optional CR strip.
    #[must_use]
    pub(crate) const fn content_end(self) -> usize {
        self.content_end
    }

    /// Exclusive source end, including a closing LF when present.
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

/// Constant-space successful reduction report.
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
    pub(crate) const fn work(self) -> u64 {
        self.actual.work()
    }

    #[must_use]
    pub(crate) const fn source_accesses(self) -> u64 {
        self.actual.source_accesses()
    }

    #[must_use]
    pub(crate) const fn transitions(self) -> u64 {
        self.actual.transitions()
    }

    #[must_use]
    pub(crate) const fn candidates(self) -> u64 {
        self.actual.candidates()
    }

    #[must_use]
    pub(crate) const fn domains_examined(self) -> usize {
        self.actual.domains_examined()
    }

    #[must_use]
    pub(crate) const fn matching_lines(self) -> u64 {
        self.actual.matching_lines()
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

/// Checked refusal or invariant failure from the native word reducer.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// The supplied plan is not a native word-run plan.
    UnsupportedPlan,
    /// One source-free or exact counter computation was not representable.
    ArithmeticOverflow { computation: &'static str },
    /// The caller supplied an envelope for another plan or source length.
    AdmissionMismatch,
    /// Runtime metering exceeded the source-free proof.
    AccountingBoundExceeded {
        resource: &'static str,
        limit: u64,
        attempted: u64,
    },
    /// A trusted internal relationship did not close.
    InternalInvariant { detail: &'static str },
}

impl core::fmt::Display for Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedPlan => {
                formatter.write_str("grep word reducer does not support this plan")
            }
            Self::ArithmeticOverflow { computation } => {
                write!(
                    formatter,
                    "arithmetic overflow while computing grep word {computation}"
                )
            }
            Self::AdmissionMismatch => formatter
                .write_str("grep word admission does not match the exact source-free prospective"),
            Self::AccountingBoundExceeded {
                resource,
                limit,
                attempted,
            } => write!(
                formatter,
                "grep word {resource} attempted {attempted}, exceeding prospective {limit}"
            ),
            Self::InternalInvariant { detail } => {
                write!(formatter, "grep word internal invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for Error {}

/// Failure from the optional complete matched-line observer.
#[derive(Debug)]
#[allow(
    dead_code,
    reason = "the non-observer wrapper and integration facade intentionally consume different exact terminal fields"
)]
pub(crate) enum ObservedError<E> {
    /// Native execution refusal or invariant failure.
    Execution { error: Error, partial: Actual },
    /// Observer refusal after the contained exact partial accounting.
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

/// Whether `plan` is handled by this reducer.
#[must_use]
pub(crate) const fn supports(plan: Plan) -> bool {
    matches!(
        plan,
        Plan::Word {
            minimum_scalars,
            ..
        } if minimum_scalars > 0
    )
}

/// Derive complete source-free maxima for `plan` and `haystack_len`.
///
/// The line partition pass reads every source byte once. Word evaluation may
/// read every content byte once more. Every content unit creates at most one
/// transition, every semantic line creates one candidate, and every candidate
/// may be selected once. Therefore:
///
/// * source accesses are bounded by `2N`;
/// * transitions, candidates, and matching lines are each bounded by `N`;
/// * work, their exact sum, is bounded by `5N`.
pub(crate) fn prospective(plan: Plan, haystack_len: usize) -> Result<Prospective, Error> {
    if !supports(plan) {
        return Err(Error::UnsupportedPlan);
    }
    let input = u64::try_from(haystack_len).map_err(|_| Error::ArithmeticOverflow {
        computation: "input length conversion",
    })?;
    let source_accesses = input.checked_mul(2).ok_or(Error::ArithmeticOverflow {
        computation: "source-access bound",
    })?;
    let work = input.checked_mul(5).ok_or(Error::ArithmeticOverflow {
        computation: "work bound",
    })?;
    Ok(Prospective {
        plan,
        haystack_len,
        work,
        source_accesses,
        transitions: input,
        candidates: input,
        line_domains: input,
    })
}

/// Count matching lines without retaining or observing every selected event.
///
/// Admission is re-derived and compared before the first source access.
#[allow(
    dead_code,
    reason = "the integration facade uses the observer form while this symmetric engine entry remains testable"
)]
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

/// Count matching lines and observe the complete ordered selected-line trace.
///
/// The callback runs exactly once for every matching domain, in strict
/// increasing ordinal order. Plan support and exact admission are checked
/// before any source access or callback.
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
    let Plan::Word {
        minimum_scalars,
        mode,
    } = plan
    else {
        return Err(Error::UnsupportedPlan.into());
    };

    let mut meter = Meter::new(required);
    let mut first_match = None;
    let mut last_match = None;
    let mut line_start = 0_usize;
    let mut line_ordinal = 0_usize;
    let mut previous_is_cr = false;
    let mut source_index = 0_usize;

    let execution = (|| -> Result<(), ObservedError<E>> {
        while source_index < haystack.len() {
            meter.source_access()?;
            let byte = haystack[source_index];
            if byte == b'\n' {
                let content_end = if previous_is_cr && source_index > line_start {
                    source_index
                        .checked_sub(1)
                        .ok_or(Error::ArithmeticOverflow {
                            computation: "CRLF content end",
                        })?
                } else {
                    source_index
                };
                let source_end = source_index
                    .checked_add(1)
                    .ok_or(Error::ArithmeticOverflow {
                        computation: "LF source end",
                    })?;
                finish_line(
                    haystack,
                    mode,
                    minimum_scalars,
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
                line_ordinal = line_ordinal
                    .checked_add(1)
                    .ok_or(Error::ArithmeticOverflow {
                        computation: "line ordinal",
                    })?;
                previous_is_cr = false;
            } else {
                previous_is_cr = byte == b'\r';
            }
            source_index = source_index
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow {
                    computation: "source index",
                })?;
        }

        if line_start < haystack.len() {
            finish_line(
                haystack,
                mode,
                minimum_scalars,
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
    if let Err(error) = execution {
        return Err(match error {
            ObservedError::Execution { error, .. } => ObservedError::Execution {
                error,
                partial: meter.actual,
            },
            observer @ ObservedError::Observer { .. } => observer,
        });
    }

    let actual = meter.actual;
    verify_report(required, actual, first_match, last_match, haystack.len())?;
    Ok(Report {
        prospective: required,
        actual,
        first_match,
        last_match,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "line close binds semantic and source boundaries plus constant-space report state"
)]
fn finish_line<E, F>(
    haystack: &[u8],
    mode: WordMode,
    minimum_scalars: usize,
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
    meter.domain()?;
    let selected = find_first_word(
        haystack,
        line_start,
        content_end,
        minimum_scalars,
        mode,
        meter,
    )?;
    if let Some((match_start, match_end)) = selected {
        meter.selected_line()?;
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

fn find_first_word(
    haystack: &[u8],
    start: usize,
    end: usize,
    minimum_scalars: usize,
    mode: WordMode,
    meter: &mut Meter,
) -> Result<Option<(usize, usize)>, Error> {
    match mode {
        WordMode::Ascii => find_first_ascii_word(haystack, start, end, minimum_scalars, meter),
        WordMode::Unicode => find_first_unicode_word(haystack, start, end, minimum_scalars, meter),
    }
}

fn find_first_ascii_word(
    haystack: &[u8],
    start: usize,
    end: usize,
    minimum_scalars: usize,
    meter: &mut Meter,
) -> Result<Option<(usize, usize)>, Error> {
    let mut position = start;
    let mut run_start = None;
    let mut run_scalars = 0_usize;
    while position < end {
        meter.source_access()?;
        let byte = haystack[position];
        meter.transition()?;
        if is_ascii_word(byte) {
            if run_start.is_none() {
                run_start = Some(position);
            }
            run_scalars = run_scalars
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow {
                    computation: "ASCII run scalar count",
                })?;
        } else if let Some(selected_start) = run_start.take() {
            if run_scalars >= minimum_scalars {
                return Ok(Some((selected_start, position)));
            }
            run_scalars = 0;
        }
        position = position.checked_add(1).ok_or(Error::ArithmeticOverflow {
            computation: "ASCII content position",
        })?;
    }
    Ok(run_start
        .filter(|_| run_scalars >= minimum_scalars)
        .map(|selected_start| (selected_start, end)))
}

fn find_first_unicode_word(
    haystack: &[u8],
    start: usize,
    end: usize,
    minimum_scalars: usize,
    meter: &mut Meter,
) -> Result<Option<(usize, usize)>, Error> {
    let mut units = UnicodeUnits::new(start, end);
    let mut run_start = None;
    let mut run_scalars = 0_usize;
    while let Some(unit) = units.next(haystack, meter)? {
        meter.transition()?;
        if unit.is_word {
            if run_start.is_none() {
                run_start = Some(unit.start);
            }
            run_scalars = run_scalars
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow {
                    computation: "Unicode run scalar count",
                })?;
        } else if let Some(selected_start) = run_start.take() {
            if run_scalars >= minimum_scalars {
                return Ok(Some((selected_start, unit.start)));
            }
            run_scalars = 0;
        }
    }
    Ok(run_start
        .filter(|_| run_scalars >= minimum_scalars)
        .map(|selected_start| (selected_start, end)))
}

#[derive(Clone, Copy, Debug)]
struct Unit {
    start: usize,
    is_word: bool,
}

/// Streaming UTF-8 decoder with a four-byte fixed pushback queue.
///
/// A malformed candidate consumes one invalid byte, exactly like
/// `unicode_word_run::decode_first`. Bytes read while validating that
/// candidate remain in this local queue, so no content byte is ever fetched
/// from the source twice.
struct UnicodeUnits {
    cursor: usize,
    end: usize,
    pending: [u8; 4],
    pending_len: usize,
    pending_start: usize,
}

impl UnicodeUnits {
    const fn new(start: usize, end: usize) -> Self {
        Self {
            cursor: start,
            end,
            pending: [0; 4],
            pending_len: 0,
            pending_start: start,
        }
    }

    fn next(&mut self, haystack: &[u8], meter: &mut Meter) -> Result<Option<Unit>, Error> {
        if self.pending_len == 0 {
            if self.cursor == self.end {
                return Ok(None);
            }
            self.read_one(haystack, meter)?;
        }

        let start = self.pending_start;
        let Some(width) = utf8_width(self.pending[0]) else {
            self.drop_prefix(1)?;
            return Ok(Some(Unit {
                start,
                is_word: false,
            }));
        };
        while self.pending_len < width && self.cursor < self.end {
            self.read_one(haystack, meter)?;
        }

        let scalar = (self.pending_len >= width)
            .then(|| core::str::from_utf8(&self.pending[..width]).ok())
            .flatten()
            .and_then(|valid| valid.chars().next());
        let Some(scalar) = scalar else {
            self.drop_prefix(1)?;
            return Ok(Some(Unit {
                start,
                is_word: false,
            }));
        };
        self.drop_prefix(width)?;
        Ok(Some(Unit {
            start,
            is_word: is_unicode_word(scalar)?,
        }))
    }

    fn read_one(&mut self, haystack: &[u8], meter: &mut Meter) -> Result<(), Error> {
        if self.cursor >= self.end || self.pending_len >= self.pending.len() {
            return Err(Error::InternalInvariant {
                detail: "Unicode decoder read exceeded its fixed queue",
            });
        }
        meter.source_access()?;
        self.pending[self.pending_len] = haystack[self.cursor];
        self.pending_len = self
            .pending_len
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow {
                computation: "Unicode pending length",
            })?;
        self.cursor = self
            .cursor
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow {
                computation: "Unicode content cursor",
            })?;
        Ok(())
    }

    fn drop_prefix(&mut self, width: usize) -> Result<(), Error> {
        if width == 0 || width > self.pending_len {
            return Err(Error::InternalInvariant {
                detail: "Unicode decoder dropped an invalid queue prefix",
            });
        }
        self.pending.copy_within(width..self.pending_len, 0);
        self.pending_len =
            self.pending_len
                .checked_sub(width)
                .ok_or(Error::ArithmeticOverflow {
                    computation: "Unicode pending removal",
                })?;
        self.pending_start =
            self.pending_start
                .checked_add(width)
                .ok_or(Error::ArithmeticOverflow {
                    computation: "Unicode pending start",
                })?;
        if self.pending_len == 0 {
            self.pending_start = self.cursor;
        }
        Ok(())
    }
}

struct Meter {
    limit: Prospective,
    actual: Actual,
}

impl Meter {
    const fn new(limit: Prospective) -> Self {
        Self {
            limit,
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

    fn source_access(&mut self) -> Result<(), Error> {
        checked_meter(
            &mut self.actual.source_accesses,
            1,
            self.limit.source_accesses,
            "source accesses",
        )?;
        self.work()
    }

    fn transition(&mut self) -> Result<(), Error> {
        checked_meter(
            &mut self.actual.transitions,
            1,
            self.limit.transitions,
            "transitions",
        )?;
        self.work()
    }

    fn domain(&mut self) -> Result<(), Error> {
        checked_meter(
            &mut self.actual.candidates,
            1,
            self.limit.candidates,
            "candidates",
        )?;
        self.actual.domains_examined =
            self.actual
                .domains_examined
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow {
                    computation: "domains examined",
                })?;
        self.work()
    }

    fn selected_line(&mut self) -> Result<(), Error> {
        checked_meter(
            &mut self.actual.matching_lines,
            1,
            self.limit.line_domains,
            "line domains",
        )?;
        self.work()
    }

    fn work(&mut self) -> Result<(), Error> {
        checked_meter(&mut self.actual.work, 1, self.limit.work, "execution work")
    }
}

fn checked_meter(
    value: &mut u64,
    amount: u64,
    limit: u64,
    resource: &'static str,
) -> Result<(), Error> {
    let attempted = value.checked_add(amount).ok_or(Error::ArithmeticOverflow {
        computation: "actual counter",
    })?;
    if attempted > limit {
        return Err(Error::AccountingBoundExceeded {
            resource,
            limit,
            attempted,
        });
    }
    *value = attempted;
    Ok(())
}

fn verify_report(
    prospective: Prospective,
    actual: Actual,
    first_match: Option<MatchedLine>,
    last_match: Option<MatchedLine>,
    haystack_len: usize,
) -> Result<(), Error> {
    let domains =
        u64::try_from(actual.domains_examined).map_err(|_| Error::ArithmeticOverflow {
            computation: "domain count conversion",
        })?;
    let exact_work = actual
        .source_accesses
        .checked_add(actual.transitions)
        .and_then(|value| value.checked_add(actual.candidates))
        .and_then(|value| value.checked_add(actual.matching_lines))
        .ok_or(Error::ArithmeticOverflow {
            computation: "exact work closure",
        })?;
    let endpoints_close = first_match.is_some() == (actual.matching_lines != 0)
        && last_match.is_some() == (actual.matching_lines != 0);
    let coordinates_close = first_match.zip(last_match).is_none_or(|(first, last)| {
        first.ordinal <= last.ordinal
            && (actual.matching_lines <= 1 || first.ordinal < last.ordinal)
            && last.ordinal < actual.domains_examined
            && matched_line_closes(first, haystack_len)
            && matched_line_closes(last, haystack_len)
    });
    if prospective.haystack_len != haystack_len
        || !prospective.contains_actual(actual)
        || domains != actual.candidates
        || actual.work != exact_work
        || actual.matching_lines > domains
        || !endpoints_close
        || !coordinates_close
    {
        return Err(Error::InternalInvariant {
            detail: "successful report did not close its prospective",
        });
    }
    Ok(())
}

const fn matched_line_closes(matched: MatchedLine, haystack_len: usize) -> bool {
    matched.line_start <= matched.content_end
        && matched.content_end <= matched.source_end
        && matched.source_end <= haystack_len
        && matched.match_start >= matched.line_start
        && matched.match_start < matched.match_end
        && matched.match_end <= matched.content_end
}

const fn is_ascii_word(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn is_unicode_word(scalar: char) -> Result<bool, Error> {
    if scalar.is_ascii() {
        return Ok(scalar == '_' || scalar.is_ascii_alphanumeric());
    }
    regex_syntax::try_is_word_character(scalar).map_err(|_| Error::InternalInvariant {
        detail: "Unicode Perl word table is unavailable",
    })
}

const fn utf8_width(first: u8) -> Option<usize> {
    match first {
        0x00..=0x7F => Some(1),
        0xC2..=0xDF => Some(2),
        0xE0..=0xEF => Some(3),
        0xF0..=0xF4 => Some(4),
        _ => None,
    }
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "test fixtures use small statically bounded offsets and counters"
)]
mod tests {
    use core::cell::Cell;

    use super::*;
    use crate::{SearchLimits, SearchWindow};

    const fn ascii(minimum_scalars: usize) -> Plan {
        Plan::Word {
            minimum_scalars,
            mode: WordMode::Ascii,
        }
    }

    const fn unicode(minimum_scalars: usize) -> Plan {
        Plan::Word {
            minimum_scalars,
            mode: WordMode::Unicode,
        }
    }

    #[test]
    fn prospective_is_exactly_the_documented_linear_envelope() {
        let value = prospective(ascii(2), 7).expect("prospective");
        assert_eq!(value.work(), 35);
        assert_eq!(value.source_accesses(), 14);
        assert_eq!(value.transitions(), 7);
        assert_eq!(value.candidates(), 7);
        assert_eq!(value.line_domains(), 7);
        let doubled = prospective(ascii(2), 14).expect("doubled prospective");
        assert_eq!(doubled.work(), value.work() * 2);
        assert_eq!(doubled.source_accesses(), value.source_accesses() * 2);
        assert_eq!(doubled.transitions(), value.transitions() * 2);
        assert_eq!(doubled.candidates(), value.candidates() * 2);
        assert_eq!(doubled.line_domains(), value.line_domains() * 2);
    }

    #[test]
    fn nullable_word_plan_is_refused_before_execution() {
        let error = prospective(unicode(0), 4).expect_err("nullable plan");
        assert_eq!(error, Error::UnsupportedPlan);
        assert!(!supports(ascii(0)));
        assert!(!supports(unicode(0)));
    }

    #[test]
    fn byte_slice_lines_and_first_last_absolute_spans_close() {
        let haystack = b"aa x\r\n!\r\nbbb\ncc\rdd\nz\n";
        let admitted = prospective(ascii(2), haystack.len()).expect("prospective");
        let mut trace = [None; 3];
        let mut next = 0;
        let report = count_matching_lines_with_observer(ascii(2), haystack, admitted, |matched| {
            trace[next] = Some(matched);
            next += 1;
            Ok::<(), Infallible>(())
        })
        .expect("count");

        assert_eq!(report.domains_examined(), 5);
        assert_eq!(report.matching_lines(), 3);
        assert_eq!(trace[0], report.first_match());
        assert_eq!(trace[2], report.last_match());
        assert_eq!(
            trace,
            [
                Some(MatchedLine {
                    ordinal: 0,
                    line_start: 0,
                    content_end: 4,
                    source_end: 6,
                    match_start: 0,
                    match_end: 2,
                }),
                Some(MatchedLine {
                    ordinal: 2,
                    line_start: 9,
                    content_end: 12,
                    source_end: 13,
                    match_start: 9,
                    match_end: 12,
                }),
                Some(MatchedLine {
                    ordinal: 3,
                    line_start: 13,
                    content_end: 18,
                    source_end: 19,
                    match_start: 13,
                    match_end: 15,
                }),
            ]
        );
        assert_eq!(
            report.work(),
            report.source_accesses()
                + report.transitions()
                + report.candidates()
                + report.matching_lines()
        );
        assert!(report.work() <= admitted.work());
        assert!(report.source_accesses() <= admitted.source_accesses());
    }

    #[test]
    fn empty_trailing_lf_and_cr_rules_have_no_synthetic_domains() {
        let empty = prospective(ascii(1), 0).expect("empty prospective");
        let report = count_matching_lines(ascii(1), b"", empty).expect("empty count");
        assert_eq!(report.domains_examined(), 0);

        let bytes = b"\r\n\r";
        let admitted = prospective(ascii(1), bytes.len()).expect("prospective");
        let report = count_matching_lines(ascii(1), bytes, admitted).expect("count");
        assert_eq!(report.domains_examined(), 2);
        assert_eq!(report.matching_lines(), 0);

        let bytes = b"a\n";
        let admitted = prospective(ascii(1), bytes.len()).expect("prospective");
        let report = count_matching_lines(ascii(1), bytes, admitted).expect("count");
        assert_eq!(report.domains_examined(), 1);
        assert_eq!(report.matching_lines(), 1);
    }

    #[test]
    fn unicode_decoder_preserves_valid_scalars_after_malformed_bytes() {
        let haystack = [
            0xE2, b'a', b'b', b'\n', 0xCE, 0xB1, 0xCE, 0xB2, b'\r', b'\n', 0xE2, 0xC3, 0xA9, b'x',
        ];
        let admitted = prospective(unicode(2), haystack.len()).expect("prospective");
        let report = count_matching_lines(unicode(2), &haystack, admitted).expect("count");
        assert_eq!(report.domains_examined(), 3);
        assert_eq!(report.matching_lines(), 3);
        assert_eq!(
            report.first_match(),
            Some(MatchedLine {
                ordinal: 0,
                line_start: 0,
                content_end: 3,
                source_end: 4,
                match_start: 1,
                match_end: 3,
            })
        );
        assert_eq!(
            report.last_match(),
            Some(MatchedLine {
                ordinal: 2,
                line_start: 10,
                content_end: 14,
                source_end: 14,
                match_start: 11,
                match_end: 14,
            })
        );
        // The delimiter pass plus the streaming decoder fetch each byte at
        // most once apiece, including malformed lookahead.
        assert!(report.source_accesses() <= admitted.source_accesses());
        assert!(report.transitions() <= admitted.transitions());
    }

    #[test]
    fn admission_binds_the_exact_plan_before_observer_or_source_work() {
        let haystack = b"abc\n";
        let wrong = prospective(ascii(2), haystack.len()).expect("prospective");
        let calls = Cell::new(0);
        let error = count_matching_lines_with_observer(ascii(3), haystack, wrong, |_| {
            calls.set(calls.get() + 1);
            Ok::<(), Infallible>(())
        })
        .expect_err("plan identity must be bound");
        assert!(matches!(
            error,
            ObservedError::Execution {
                error: Error::AdmissionMismatch,
                ..
            }
        ));
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn observer_refusal_returns_exact_selected_partial() {
        let haystack = b"aa\nbb\ncc\n";
        let admitted = prospective(ascii(2), haystack.len()).expect("prospective");
        let calls = Cell::new(0);
        let error = count_matching_lines_with_observer(ascii(2), haystack, admitted, |_| {
            let call = calls.get() + 1;
            calls.set(call);
            if call == 2 { Err("stop") } else { Ok(()) }
        })
        .expect_err("observer refusal");
        let ObservedError::Observer { error, partial } = error else {
            panic!("expected observer error");
        };
        assert_eq!(error, "stop");
        assert_eq!(partial.domains_examined(), 2);
        assert_eq!(partial.matching_lines(), 2);
        assert_eq!(calls.get(), 2);
    }

    fn current_plan_trace(plan: Plan, haystack: &[u8]) -> (usize, Vec<MatchedLine>) {
        fn examine(
            plan: Plan,
            haystack: &[u8],
            ordinal: usize,
            line_start: usize,
            content_end: usize,
            source_end: usize,
            trace: &mut Vec<MatchedLine>,
        ) {
            let line = &haystack[line_start..content_end];
            let (selected, _) = plan
                .find_window(line, SearchWindow::full(line), SearchLimits::unlimited())
                .expect("current plan search");
            if let Some(selected) = selected {
                trace.push(MatchedLine {
                    ordinal,
                    line_start,
                    content_end,
                    source_end,
                    match_start: line_start + selected.start,
                    match_end: line_start + selected.end,
                });
            }
        }

        let mut trace = Vec::new();
        let mut domains = 0_usize;
        let mut line_start = 0_usize;
        for (index, byte) in haystack.iter().copied().enumerate() {
            if byte != b'\n' {
                continue;
            }
            let content_end = if index > line_start && haystack[index - 1] == b'\r' {
                index - 1
            } else {
                index
            };
            examine(
                plan,
                haystack,
                domains,
                line_start,
                content_end,
                index + 1,
                &mut trace,
            );
            domains += 1;
            line_start = index + 1;
        }
        if line_start < haystack.len() {
            examine(
                plan,
                haystack,
                domains,
                line_start,
                haystack.len(),
                haystack.len(),
                &mut trace,
            );
            domains += 1;
        }
        (domains, trace)
    }

    #[test]
    fn exhaustive_short_arbitrary_bytes_match_current_plan_per_line() {
        let alphabet = [
            b'a', b'B', b'_', b'0', b'!', b'\r', b'\n', 0x80, 0xA9, 0xC2, 0xCE, 0xE2, 0xF0,
        ];
        for mode in [WordMode::Ascii, WordMode::Unicode] {
            for minimum_scalars in 1..=3 {
                for length in 0_u32..=4 {
                    let cases = alphabet.len().pow(length);
                    for mut encoded in 0..cases {
                        let mut haystack =
                            Vec::with_capacity(usize::try_from(length).expect("small length"));
                        for _ in 0..length {
                            haystack.push(alphabet[encoded % alphabet.len()]);
                            encoded /= alphabet.len();
                        }
                        let plan = Plan::Word {
                            minimum_scalars,
                            mode,
                        };
                        let admitted = prospective(plan, haystack.len()).expect("prospective");
                        let mut actual_trace = Vec::new();
                        let report = count_matching_lines_with_observer(
                            plan,
                            &haystack,
                            admitted,
                            |matched| {
                                actual_trace.push(matched);
                                Ok::<(), Infallible>(())
                            },
                        )
                        .expect("native grep count");
                        let (expected_domains, expected_trace) =
                            current_plan_trace(plan, &haystack);
                        assert_eq!(
                            report.domains_examined(),
                            expected_domains,
                            "{mode:?}, minimum={minimum_scalars}, haystack={haystack:?}"
                        );
                        assert_eq!(
                            actual_trace, expected_trace,
                            "{mode:?}, minimum={minimum_scalars}, haystack={haystack:?}"
                        );
                        assert_eq!(
                            report.matching_lines(),
                            u64::try_from(expected_trace.len()).expect("short trace")
                        );
                        assert!(report.work() <= admitted.work());
                        assert!(report.source_accesses() <= admitted.source_accesses());
                        assert!(report.transitions() <= admitted.transitions());
                    }
                }
            }
        }
    }
}
