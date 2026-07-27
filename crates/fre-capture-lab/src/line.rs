//! Allocation-free semantic boundary and whole-input line partitioning.
//!
//! A [`SemanticBoundary`] retains the original haystack context even when a
//! regex search is clipped to a smaller window. A prepared [`LineScanner`]
//! admits a source-independent upper bound before reading the haystack, then
//! emits absolute partitions in one forward traversal.

use core::fmt;

use crate::{Assertion, SearchError, Window};

/// Semantic treatment of line terminators.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LineMode {
    /// LF is the only line terminator.
    Lf,
    /// CRLF is one terminator; lone CR and lone LF are terminators.
    Crlf,
    /// One caller-selected byte is the line terminator.
    Byte(u8),
}

impl LineMode {
    const fn delimiter_check_bound(self, haystack_bytes: usize) -> Option<usize> {
        let checks_per_byte = match self {
            Self::Lf | Self::Byte(_) => 1,
            Self::Crlf => 3,
        };
        haystack_bytes.checked_mul(checks_per_byte)
    }
}

/// One absolute line partition.
///
/// `start..content_end` excludes the terminator. `content_end..end` is the
/// terminator and is empty only for the final unterminated partition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinePartition {
    /// First byte of line content.
    pub start: usize,
    /// Boundary immediately after content and before its terminator.
    pub content_end: usize,
    /// Boundary immediately after the terminator.
    pub end: usize,
}

/// One independently limited line-scan resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LineScanResource {
    /// Bytes in the complete source.
    SourceBytes,
    /// Partitions emitted to the caller.
    Partitions,
    /// Logical forward-scan work.
    Work,
}

/// A line scanner admission or execution failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LineScanError {
    /// A checked resource ceiling would be exceeded.
    Resource {
        /// Limited resource.
        resource: LineScanResource,
        /// Required amount.
        required: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// Arithmetic needed to prove a bound overflowed.
    Overflow(LineScanResource),
    /// The source length differs from the length admitted at construction.
    SourceLength {
        /// Length admitted without reading the source.
        expected: usize,
        /// Length supplied for execution.
        actual: usize,
    },
}

impl fmt::Display for LineScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "capture line scanner error: {self:?}")
    }
}

impl std::error::Error for LineScanError {}

/// Resource ceilings for one prepared whole-input line scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LineScanLimits {
    /// Maximum complete source bytes.
    pub max_source_bytes: usize,
    /// Maximum emitted line partitions.
    pub max_partitions: usize,
    /// Maximum logical forward-scan work.
    pub max_work: usize,
}

impl Default for LineScanLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: 1 << 30,
            max_partitions: 1 << 30,
            max_work: usize::MAX,
        }
    }
}

/// Source-independent upper bound admitted before a line scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LineScanProspective {
    /// Complete source bytes.
    pub source_bytes: usize,
    /// Maximum possible partitions, including the final partition.
    pub partitions: usize,
    /// Exact source-read bound: every byte is fetched once.
    pub source_reads: usize,
    /// Loop-condition bound, including the terminal check.
    pub loop_checks: usize,
    /// Mode-specific delimiter-comparison bound.
    pub delimiter_checks: usize,
    /// Two logical writes per possible partition: publication and line reset.
    pub partition_writes: usize,
    /// Sum of every charged work category.
    pub work: usize,
    /// Dynamic execution allocations.
    pub allocations: usize,
    /// Dynamic execution scratch bytes.
    pub scratch_bytes: usize,
}

/// Exact logical counters from one line scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LineScanReport {
    /// Admitted source-independent envelope.
    pub prospective: LineScanProspective,
    /// Partitions actually emitted.
    pub partitions: usize,
    /// Source bytes actually fetched.
    pub source_reads: usize,
    /// Loop conditions actually evaluated.
    pub loop_checks: usize,
    /// Delimiter comparisons actually evaluated.
    pub delimiter_checks: usize,
    /// Partition publication and line-reset writes.
    pub partition_writes: usize,
    /// Sum of actual charged work.
    pub work: usize,
    /// Dynamic execution allocations.
    pub allocations: usize,
    /// Dynamic execution scratch bytes.
    pub scratch_bytes: usize,
}

impl LineScanReport {
    /// Whether every actual counter closes its admitted upper bound.
    #[must_use]
    pub const fn closes_prospective(self) -> bool {
        self.partitions <= self.prospective.partitions
            && self.source_reads <= self.prospective.source_reads
            && self.loop_checks <= self.prospective.loop_checks
            && self.delimiter_checks <= self.prospective.delimiter_checks
            && self.partition_writes <= self.prospective.partition_writes
            && self.work <= self.prospective.work
            && self.allocations == self.prospective.allocations
            && self.scratch_bytes == self.prospective.scratch_bytes
    }
}

/// Reusable, allocation-free line scanner admitted for one source length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LineScanner {
    mode: LineMode,
    prospective: LineScanProspective,
}

impl LineScanner {
    /// Derive the complete line-scan envelope without reading a source.
    pub fn prospective(
        haystack_bytes: usize,
        mode: LineMode,
    ) -> Result<LineScanProspective, LineScanError> {
        let partitions = haystack_bytes
            .checked_add(1)
            .ok_or(LineScanError::Overflow(LineScanResource::Partitions))?;
        let loop_checks = partitions;
        let delimiter_checks = mode
            .delimiter_check_bound(haystack_bytes)
            .ok_or(LineScanError::Overflow(LineScanResource::Work))?;
        let partition_writes = partitions
            .checked_mul(2)
            .ok_or(LineScanError::Overflow(LineScanResource::Work))?;
        let work = haystack_bytes
            .checked_add(loop_checks)
            .and_then(|value| value.checked_add(delimiter_checks))
            .and_then(|value| value.checked_add(partition_writes))
            .ok_or(LineScanError::Overflow(LineScanResource::Work))?;
        Ok(LineScanProspective {
            source_bytes: haystack_bytes,
            partitions,
            source_reads: haystack_bytes,
            loop_checks,
            delimiter_checks,
            partition_writes,
            work,
            allocations: 0,
            scratch_bytes: 0,
        })
    }

    /// Admit and prepare a scanner before reading the source.
    pub fn new(
        haystack_bytes: usize,
        mode: LineMode,
        limits: LineScanLimits,
    ) -> Result<Self, LineScanError> {
        let prospective = Self::prospective(haystack_bytes, mode)?;
        check_line_limit(
            LineScanResource::SourceBytes,
            prospective.source_bytes,
            limits.max_source_bytes,
        )?;
        check_line_limit(
            LineScanResource::Partitions,
            prospective.partitions,
            limits.max_partitions,
        )?;
        check_line_limit(LineScanResource::Work, prospective.work, limits.max_work)?;
        Ok(Self { mode, prospective })
    }

    /// Admitted source-independent envelope.
    #[must_use]
    pub const fn admitted(&self) -> LineScanProspective {
        self.prospective
    }

    /// Emit absolute partitions in one forward traversal.
    ///
    /// The callback is invoked once for each semantic line, including the
    /// final empty line after a trailing terminator. It must not retain a
    /// reference into scanner state; the scanner itself allocates no memory.
    pub fn scan(
        &self,
        haystack: &[u8],
        mut emit: impl FnMut(LinePartition),
    ) -> Result<LineScanReport, LineScanError> {
        if haystack.len() != self.prospective.source_bytes {
            return Err(LineScanError::SourceLength {
                expected: self.prospective.source_bytes,
                actual: haystack.len(),
            });
        }
        let mut counters = LineCounters::default();
        match self.mode {
            LineMode::Lf => {
                scan_single_byte(haystack, b'\n', &mut counters, &mut emit)?;
            }
            LineMode::Byte(terminator) => {
                scan_single_byte(haystack, terminator, &mut counters, &mut emit)?;
            }
            LineMode::Crlf => scan_crlf(haystack, &mut counters, &mut emit)?,
        }
        let report = counters.report(self.prospective)?;
        if report.closes_prospective() {
            Ok(report)
        } else {
            Err(LineScanError::Overflow(LineScanResource::Work))
        }
    }
}

#[derive(Default)]
struct LineCounters {
    partitions: usize,
    source_reads: usize,
    loop_checks: usize,
    delimiter_checks: usize,
    partition_writes: usize,
}

impl LineCounters {
    fn checked_increment(
        value: &mut usize,
        resource: LineScanResource,
    ) -> Result<(), LineScanError> {
        *value = value
            .checked_add(1)
            .ok_or(LineScanError::Overflow(resource))?;
        Ok(())
    }

    fn source_read(&mut self) -> Result<(), LineScanError> {
        Self::checked_increment(&mut self.source_reads, LineScanResource::Work)
    }

    fn loop_check(&mut self) -> Result<(), LineScanError> {
        Self::checked_increment(&mut self.loop_checks, LineScanResource::Work)
    }

    fn delimiter_check(&mut self) -> Result<(), LineScanError> {
        Self::checked_increment(&mut self.delimiter_checks, LineScanResource::Work)
    }

    fn emit(
        &mut self,
        partition: LinePartition,
        emit: &mut impl FnMut(LinePartition),
    ) -> Result<(), LineScanError> {
        Self::checked_increment(&mut self.partitions, LineScanResource::Partitions)?;
        self.partition_writes = self
            .partition_writes
            .checked_add(2)
            .ok_or(LineScanError::Overflow(LineScanResource::Work))?;
        emit(partition);
        Ok(())
    }

    fn report(self, prospective: LineScanProspective) -> Result<LineScanReport, LineScanError> {
        let work = self
            .source_reads
            .checked_add(self.loop_checks)
            .and_then(|value| value.checked_add(self.delimiter_checks))
            .and_then(|value| value.checked_add(self.partition_writes))
            .ok_or(LineScanError::Overflow(LineScanResource::Work))?;
        Ok(LineScanReport {
            prospective,
            partitions: self.partitions,
            source_reads: self.source_reads,
            loop_checks: self.loop_checks,
            delimiter_checks: self.delimiter_checks,
            partition_writes: self.partition_writes,
            work,
            allocations: 0,
            scratch_bytes: 0,
        })
    }
}

fn scan_single_byte(
    haystack: &[u8],
    terminator: u8,
    counters: &mut LineCounters,
    emit: &mut impl FnMut(LinePartition),
) -> Result<(), LineScanError> {
    let mut line_start = 0;
    for (index, byte) in haystack.iter().copied().enumerate() {
        counters.loop_check()?;
        counters.source_read()?;
        counters.delimiter_check()?;
        if byte == terminator {
            let end = index
                .checked_add(1)
                .ok_or(LineScanError::Overflow(LineScanResource::Partitions))?;
            counters.emit(
                LinePartition {
                    start: line_start,
                    content_end: index,
                    end,
                },
                emit,
            )?;
            line_start = end;
        }
    }
    counters.loop_check()?;
    counters.emit(
        LinePartition {
            start: line_start,
            content_end: haystack.len(),
            end: haystack.len(),
        },
        emit,
    )
}

fn scan_crlf(
    haystack: &[u8],
    counters: &mut LineCounters,
    emit: &mut impl FnMut(LinePartition),
) -> Result<(), LineScanError> {
    let mut line_start = 0;
    let mut pending_cr = None;
    for (index, byte) in haystack.iter().copied().enumerate() {
        counters.loop_check()?;
        counters.source_read()?;
        if let Some(cr_index) = pending_cr {
            counters.delimiter_check()?;
            if byte == b'\n' {
                let end = index
                    .checked_add(1)
                    .ok_or(LineScanError::Overflow(LineScanResource::Partitions))?;
                counters.emit(
                    LinePartition {
                        start: line_start,
                        content_end: cr_index,
                        end,
                    },
                    emit,
                )?;
                line_start = end;
                pending_cr = None;
                continue;
            }
            counters.emit(
                LinePartition {
                    start: line_start,
                    content_end: cr_index,
                    end: index,
                },
                emit,
            )?;
            line_start = index;
            pending_cr = None;
        }
        counters.delimiter_check()?;
        if byte == b'\r' {
            pending_cr = Some(index);
            continue;
        }
        counters.delimiter_check()?;
        if byte == b'\n' {
            let end = index
                .checked_add(1)
                .ok_or(LineScanError::Overflow(LineScanResource::Partitions))?;
            counters.emit(
                LinePartition {
                    start: line_start,
                    content_end: index,
                    end,
                },
                emit,
            )?;
            line_start = end;
        }
    }
    counters.loop_check()?;
    if let Some(cr_index) = pending_cr {
        counters.emit(
            LinePartition {
                start: line_start,
                content_end: cr_index,
                end: haystack.len(),
            },
            emit,
        )?;
        line_start = haystack.len();
    }
    counters.emit(
        LinePartition {
            start: line_start,
            content_end: haystack.len(),
            end: haystack.len(),
        },
        emit,
    )
}

/// Cached original-haystack context for one zero-width semantic boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SemanticBoundary<'a> {
    position: usize,
    logical_start: usize,
    logical_end: usize,
    left_byte: Option<u8>,
    right_byte: Option<u8>,
    before: &'a [u8],
    after: &'a [u8],
}

impl<'a> SemanticBoundary<'a> {
    /// Validate a search boundary and cache its original-haystack context.
    pub fn new(haystack: &'a [u8], window: Window, position: usize) -> Result<Self, SearchError> {
        if position < window.start || position > window.end || window.end > haystack.len() {
            return Err(SearchError::InvalidWindow);
        }
        let left_byte = position
            .checked_sub(1)
            .and_then(|index| haystack.get(index))
            .copied();
        let right_byte = haystack.get(position).copied();
        let before = haystack.get(..position).ok_or(SearchError::InvalidWindow)?;
        let after = haystack.get(position..).ok_or(SearchError::InvalidWindow)?;
        Ok(Self {
            position,
            logical_start: 0,
            logical_end: haystack.len(),
            left_byte,
            right_byte,
            before,
            after,
        })
    }

    /// Validate a boundary whose assertion context is clipped to `window`.
    ///
    /// This reproduces applying a regex to a borrowed line slice while
    /// retaining absolute offsets. Bytes outside the line do not participate
    /// in anchors or word-boundary predicates.
    pub fn new_clipped(
        haystack: &'a [u8],
        window: Window,
        position: usize,
    ) -> Result<Self, SearchError> {
        if position < window.start || position > window.end || window.end > haystack.len() {
            return Err(SearchError::InvalidWindow);
        }
        let left_byte = position
            .checked_sub(1)
            .filter(|index| *index >= window.start)
            .and_then(|index| haystack.get(index))
            .copied();
        let right_byte = if position < window.end {
            haystack.get(position).copied()
        } else {
            None
        };
        let before = haystack
            .get(window.start..position)
            .ok_or(SearchError::InvalidWindow)?;
        let after = haystack
            .get(position..window.end)
            .ok_or(SearchError::InvalidWindow)?;
        Ok(Self {
            position,
            logical_start: window.start,
            logical_end: window.end,
            left_byte,
            right_byte,
            before,
            after,
        })
    }

    /// Absolute byte boundary.
    #[must_use]
    pub const fn position(self) -> usize {
        self.position
    }

    /// Evaluate one assertion against cached original-haystack context.
    pub fn matches(self, assertion: Assertion) -> Result<bool, SearchError> {
        let left_ascii_word = self.left_byte.is_some_and(is_ascii_word);
        let right_ascii_word = self.right_byte.is_some_and(is_ascii_word);
        Ok(match assertion {
            Assertion::Start => self.position == self.logical_start,
            Assertion::End => self.position == self.logical_end,
            Assertion::StartLf => {
                self.position == self.logical_start || self.left_byte == Some(b'\n')
            }
            Assertion::EndLf => self.position == self.logical_end || self.right_byte == Some(b'\n'),
            Assertion::StartLine(terminator) => {
                self.position == self.logical_start || self.left_byte == Some(terminator)
            }
            Assertion::EndLine(terminator) => {
                self.position == self.logical_end || self.right_byte == Some(terminator)
            }
            Assertion::StartCrlf => {
                self.position == self.logical_start
                    || self.left_byte == Some(b'\n')
                    || (self.left_byte == Some(b'\r') && self.right_byte != Some(b'\n'))
            }
            Assertion::EndCrlf => {
                self.position == self.logical_end
                    || self.right_byte == Some(b'\r')
                    || (self.right_byte == Some(b'\n') && self.left_byte != Some(b'\r'))
            }
            Assertion::WordAscii => left_ascii_word != right_ascii_word,
            Assertion::WordAsciiNegate => left_ascii_word == right_ascii_word,
            Assertion::WordStartAscii => !left_ascii_word && right_ascii_word,
            Assertion::WordEndAscii => left_ascii_word && !right_ascii_word,
            Assertion::WordStartHalfAscii => !left_ascii_word,
            Assertion::WordEndHalfAscii => !right_ascii_word,
            assertion @ (Assertion::WordUnicode
            | Assertion::WordUnicodeNegate
            | Assertion::WordStartUnicode
            | Assertion::WordEndUnicode
            | Assertion::WordStartHalfUnicode
            | Assertion::WordEndHalfUnicode) => {
                unicode_assertion_matches(assertion, self.before, self.after)?
            }
        })
    }
}

const fn is_ascii_word(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn unicode_word(scalar: Option<char>) -> Result<bool, SearchError> {
    let Some(scalar) = scalar else {
        return Ok(false);
    };
    regex_syntax::try_is_word_character(scalar).map_err(|_| SearchError::InvalidProgram)
}

fn unicode_assertion_matches(
    assertion: Assertion,
    before: &[u8],
    after: &[u8],
) -> Result<bool, SearchError> {
    let left_scalar = decode_last_scalar(before);
    let right_scalar = decode_first_scalar(after);
    let left_valid = before.is_empty() || left_scalar.is_some();
    let right_valid = after.is_empty() || right_scalar.is_some();
    let left_word = unicode_word(left_scalar)?;
    let right_word = unicode_word(right_scalar)?;
    Ok(match assertion {
        Assertion::WordUnicode => left_word != right_word,
        Assertion::WordUnicodeNegate => left_valid && right_valid && left_word == right_word,
        Assertion::WordStartUnicode => !left_word && right_word,
        Assertion::WordEndUnicode => left_word && !right_word,
        Assertion::WordStartHalfUnicode => left_valid && !left_word,
        Assertion::WordEndHalfUnicode => right_valid && !right_word,
        _ => return Err(SearchError::InvalidProgram),
    })
}

fn decode_first_scalar(bytes: &[u8]) -> Option<char> {
    let first = *bytes.first()?;
    let width = match first {
        0x00..=0x7F => 1,
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => return None,
    };
    core::str::from_utf8(bytes.get(..width)?)
        .ok()?
        .chars()
        .next()
}

fn decode_last_scalar(bytes: &[u8]) -> Option<char> {
    let end = bytes.len();
    let mut start = end.checked_sub(1)?;
    let limit = end.saturating_sub(4);
    while start > limit && matches!(bytes[start], 0x80..=0xBF) {
        start = start.checked_sub(1)?;
    }
    let encoded = bytes.get(start..end)?;
    let scalar = decode_first_scalar(encoded)?;
    (scalar.len_utf8() == encoded.len()).then_some(scalar)
}

fn check_line_limit(
    resource: LineScanResource,
    required: usize,
    limit: usize,
) -> Result<(), LineScanError> {
    if required > limit {
        Err(LineScanError::Resource {
            resource,
            required,
            limit,
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact_limits(prospective: LineScanProspective) -> LineScanLimits {
        LineScanLimits {
            max_source_bytes: prospective.source_bytes,
            max_partitions: prospective.partitions,
            max_work: prospective.work,
        }
    }

    fn partitions(haystack: &[u8], mode: LineMode) -> (Vec<LinePartition>, LineScanReport) {
        let prospective = LineScanner::prospective(haystack.len(), mode).expect("prospective");
        let scanner =
            LineScanner::new(haystack.len(), mode, exact_limits(prospective)).expect("scanner");
        let mut partitions = Vec::new();
        let report = scanner
            .scan(haystack, |partition| partitions.push(partition))
            .expect("scan");
        (partitions, report)
    }

    fn enumerate_haystacks(
        remaining: usize,
        haystack: &mut Vec<u8>,
        visit: &mut impl FnMut(&[u8]),
    ) {
        visit(haystack);
        if remaining == 0 {
            return;
        }
        for byte in [b'\r', b'\n', b'x', 0xFF] {
            haystack.push(byte);
            enumerate_haystacks(
                remaining.checked_sub(1).expect("positive depth"),
                haystack,
                visit,
            );
            haystack.pop();
        }
    }

    #[test]
    fn line_modes_emit_absolute_content_and_terminator_ranges() {
        let (lf, lf_report) = partitions(b"a\n\nb", LineMode::Lf);
        assert_eq!(
            lf,
            [
                LinePartition {
                    start: 0,
                    content_end: 1,
                    end: 2,
                },
                LinePartition {
                    start: 2,
                    content_end: 2,
                    end: 3,
                },
                LinePartition {
                    start: 3,
                    content_end: 4,
                    end: 4,
                },
            ]
        );
        assert!(lf_report.closes_prospective());
        assert_eq!(lf_report.source_reads, 4);
        assert_eq!(lf_report.allocations, 0);
        assert_eq!(lf_report.scratch_bytes, 0);

        let (configured, _) = partitions(b"a\0b\0", LineMode::Byte(0));
        assert_eq!(
            configured,
            [
                LinePartition {
                    start: 0,
                    content_end: 1,
                    end: 2,
                },
                LinePartition {
                    start: 2,
                    content_end: 3,
                    end: 4,
                },
                LinePartition {
                    start: 4,
                    content_end: 4,
                    end: 4,
                },
            ]
        );

        let (crlf, report) = partitions(b"a\r\nb\rc\n", LineMode::Crlf);
        assert_eq!(
            crlf,
            [
                LinePartition {
                    start: 0,
                    content_end: 1,
                    end: 3,
                },
                LinePartition {
                    start: 3,
                    content_end: 4,
                    end: 5,
                },
                LinePartition {
                    start: 5,
                    content_end: 6,
                    end: 7,
                },
                LinePartition {
                    start: 7,
                    content_end: 7,
                    end: 7,
                },
            ]
        );
        assert!(report.closes_prospective());
        assert_eq!(report.source_reads, 7);
    }

    #[test]
    fn crlf_partitions_equal_every_semantic_start_and_end_boundary() {
        enumerate_haystacks(5, &mut Vec::new(), &mut |haystack| {
            let (partitions, report) = partitions(haystack, LineMode::Crlf);
            assert!(report.closes_prospective(), "haystack={haystack:?}");
            let window = Window::all(haystack);
            let starts = (0..=haystack.len())
                .filter(|position| {
                    SemanticBoundary::new(haystack, window, *position)
                        .expect("boundary")
                        .matches(Assertion::StartCrlf)
                        .expect("assertion")
                })
                .collect::<Vec<_>>();
            let ends = (0..=haystack.len())
                .filter(|position| {
                    SemanticBoundary::new(haystack, window, *position)
                        .expect("boundary")
                        .matches(Assertion::EndCrlf)
                        .expect("assertion")
                })
                .collect::<Vec<_>>();
            assert_eq!(
                partitions
                    .iter()
                    .map(|partition| partition.start)
                    .collect::<Vec<_>>(),
                starts,
                "start boundaries: haystack={haystack:?}"
            );
            assert_eq!(
                partitions
                    .iter()
                    .map(|partition| partition.content_end)
                    .collect::<Vec<_>>(),
                ends,
                "end boundaries: haystack={haystack:?}"
            );
        });
    }

    #[test]
    fn single_byte_modes_equal_every_semantic_start_and_end_boundary() {
        let modes = [
            (LineMode::Lf, Assertion::StartLf, Assertion::EndLf),
            (
                LineMode::Byte(0),
                Assertion::StartLine(0),
                Assertion::EndLine(0),
            ),
            (
                LineMode::Byte(b'\r'),
                Assertion::StartLine(b'\r'),
                Assertion::EndLine(b'\r'),
            ),
            (
                LineMode::Byte(b'\n'),
                Assertion::StartLine(b'\n'),
                Assertion::EndLine(b'\n'),
            ),
            (
                LineMode::Byte(b'x'),
                Assertion::StartLine(b'x'),
                Assertion::EndLine(b'x'),
            ),
            (
                LineMode::Byte(0xFF),
                Assertion::StartLine(0xFF),
                Assertion::EndLine(0xFF),
            ),
        ];
        enumerate_haystacks(4, &mut Vec::new(), &mut |haystack| {
            for (mode, start_assertion, end_assertion) in modes {
                let (partitions, report) = partitions(haystack, mode);
                assert!(report.closes_prospective(), "haystack={haystack:?}");
                let window = Window::all(haystack);
                let starts = (0..=haystack.len())
                    .filter(|position| {
                        SemanticBoundary::new(haystack, window, *position)
                            .expect("boundary")
                            .matches(start_assertion)
                            .expect("assertion")
                    })
                    .collect::<Vec<_>>();
                let ends = (0..=haystack.len())
                    .filter(|position| {
                        SemanticBoundary::new(haystack, window, *position)
                            .expect("boundary")
                            .matches(end_assertion)
                            .expect("assertion")
                    })
                    .collect::<Vec<_>>();
                assert_eq!(
                    partitions
                        .iter()
                        .map(|partition| partition.start)
                        .collect::<Vec<_>>(),
                    starts,
                    "start boundaries: mode={mode:?}, haystack={haystack:?}"
                );
                assert_eq!(
                    partitions
                        .iter()
                        .map(|partition| partition.content_end)
                        .collect::<Vec<_>>(),
                    ends,
                    "end boundaries: mode={mode:?}, haystack={haystack:?}"
                );
            }
        });
    }

    #[test]
    fn line_admission_has_exact_and_one_below_gates() {
        let prospective = LineScanner::prospective(7, LineMode::Crlf).expect("prospective");
        let exact = exact_limits(prospective);
        let scanner = LineScanner::new(7, LineMode::Crlf, exact).expect("exact limits");
        assert_eq!(scanner.admitted(), prospective);

        let mut one_below = exact;
        one_below.max_source_bytes = prospective
            .source_bytes
            .checked_sub(1)
            .expect("positive source");
        assert_eq!(
            LineScanner::new(7, LineMode::Crlf, one_below),
            Err(LineScanError::Resource {
                resource: LineScanResource::SourceBytes,
                required: prospective.source_bytes,
                limit: one_below.max_source_bytes,
            })
        );

        one_below = exact;
        one_below.max_partitions = prospective
            .partitions
            .checked_sub(1)
            .expect("positive partitions");
        assert_eq!(
            LineScanner::new(7, LineMode::Crlf, one_below),
            Err(LineScanError::Resource {
                resource: LineScanResource::Partitions,
                required: prospective.partitions,
                limit: one_below.max_partitions,
            })
        );

        one_below = exact;
        one_below.max_work = prospective.work.checked_sub(1).expect("positive work");
        assert_eq!(
            LineScanner::new(7, LineMode::Crlf, one_below),
            Err(LineScanError::Resource {
                resource: LineScanResource::Work,
                required: prospective.work,
                limit: one_below.max_work,
            })
        );
        assert_eq!(
            LineScanner::prospective(usize::MAX, LineMode::Lf),
            Err(LineScanError::Overflow(LineScanResource::Partitions))
        );
        assert_eq!(
            LineScanner::prospective(
                usize::MAX.checked_sub(1).expect("one below maximum"),
                LineMode::Lf
            ),
            Err(LineScanError::Overflow(LineScanResource::Work))
        );
        assert_eq!(
            LineScanner::prospective(
                usize::MAX.checked_sub(1).expect("one below maximum"),
                LineMode::Crlf
            ),
            Err(LineScanError::Overflow(LineScanResource::Work))
        );
    }

    #[test]
    fn source_length_mismatch_refuses_before_callback_and_scanner_reuses() {
        let prospective = LineScanner::prospective(3, LineMode::Lf).expect("prospective");
        let scanner =
            LineScanner::new(3, LineMode::Lf, exact_limits(prospective)).expect("scanner");
        let mut calls = 0_usize;
        assert_eq!(
            scanner.scan(b"xx", |_| {
                calls = calls.checked_add(1).expect("bounded calls");
            }),
            Err(LineScanError::SourceLength {
                expected: 3,
                actual: 2,
            })
        );
        assert_eq!(calls, 0);
        assert_eq!(
            scanner.scan(b"xxxx", |_| {
                calls = calls.checked_add(1).expect("bounded calls");
            }),
            Err(LineScanError::SourceLength {
                expected: 3,
                actual: 4,
            })
        );
        assert_eq!(calls, 0);

        for haystack in [b"a\nb".as_slice(), b"\n\n\n", b"\xFF\0x"] {
            let mut emitted = 0_usize;
            let report = scanner
                .scan(haystack, |_| {
                    emitted = emitted.checked_add(1).expect("bounded events");
                })
                .expect("reused scan");
            assert_eq!(emitted, report.partitions);
            assert!(report.closes_prospective());
            assert_eq!(report.source_reads, haystack.len());
            assert_eq!(report.allocations, 0);
        }
    }

    #[test]
    fn semantic_boundaries_keep_original_context_across_windows() {
        let haystack = b"x\ny";
        let window = Window { start: 2, end: 3 };
        let boundary = SemanticBoundary::new(haystack, window, 2).expect("boundary");
        assert_eq!(boundary.position(), 2);
        assert!(!boundary.matches(Assertion::Start).expect("assertion"));
        assert!(boundary.matches(Assertion::StartLf).expect("assertion"));
        assert!(
            boundary
                .matches(Assertion::StartLine(b'\n'))
                .expect("assertion")
        );
        assert!(
            boundary
                .matches(Assertion::WordStartAscii)
                .expect("assertion")
        );
        assert_eq!(
            SemanticBoundary::new(haystack, window, 1),
            Err(SearchError::InvalidWindow)
        );
        assert_eq!(
            SemanticBoundary::new(haystack, Window { start: 3, end: 2 }, 2),
            Err(SearchError::InvalidWindow)
        );
        assert_eq!(
            SemanticBoundary::new(haystack, Window { start: 0, end: 4 }, 2),
            Err(SearchError::InvalidWindow)
        );
        assert_eq!(
            SemanticBoundary::new(haystack, window, 4),
            Err(SearchError::InvalidWindow)
        );
    }

    #[test]
    fn semantic_boundaries_preserve_unicode_and_invalid_byte_rules() {
        let haystack = b"x\xFF\xC3\xA9_";
        let window = Window::all(haystack);

        let before_invalid = SemanticBoundary::new(haystack, window, 1).expect("boundary");
        assert!(
            before_invalid
                .matches(Assertion::WordUnicode)
                .expect("assertion")
        );
        assert!(
            !before_invalid
                .matches(Assertion::WordUnicodeNegate)
                .expect("assertion")
        );
        assert!(
            !before_invalid
                .matches(Assertion::WordEndHalfUnicode)
                .expect("assertion")
        );

        let after_invalid = SemanticBoundary::new(haystack, window, 2).expect("boundary");
        assert!(
            after_invalid
                .matches(Assertion::WordUnicode)
                .expect("assertion")
        );
        assert!(
            !after_invalid
                .matches(Assertion::WordStartHalfUnicode)
                .expect("assertion")
        );

        let inside_scalar = SemanticBoundary::new(haystack, window, 3).expect("boundary");
        assert!(
            !inside_scalar
                .matches(Assertion::WordUnicode)
                .expect("assertion")
        );
        assert!(
            !inside_scalar
                .matches(Assertion::WordUnicodeNegate)
                .expect("assertion")
        );
        assert!(
            !inside_scalar
                .matches(Assertion::WordStartHalfUnicode)
                .expect("assertion")
        );
        assert!(
            !inside_scalar
                .matches(Assertion::WordEndHalfUnicode)
                .expect("assertion")
        );

        let after_scalar = SemanticBoundary::new(haystack, window, 4).expect("boundary");
        assert!(
            !after_scalar
                .matches(Assertion::WordUnicode)
                .expect("assertion")
        );
        assert!(
            after_scalar
                .matches(Assertion::WordUnicodeNegate)
                .expect("assertion")
        );
    }

    #[test]
    fn configured_invalid_byte_terminator_is_byte_exact() {
        let (partitions, report) = partitions(b"a\xFFb\xFF", LineMode::Byte(0xFF));
        assert_eq!(
            partitions,
            [
                LinePartition {
                    start: 0,
                    content_end: 1,
                    end: 2,
                },
                LinePartition {
                    start: 2,
                    content_end: 3,
                    end: 4,
                },
                LinePartition {
                    start: 4,
                    content_end: 4,
                    end: 4,
                },
            ]
        );
        assert!(report.closes_prospective());
        assert_eq!(report.delimiter_checks, 4);
    }
}
