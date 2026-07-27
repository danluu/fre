//! Allocation-free whole-haystack grep reduction for capture-free automata.
//!
//! The executor in this module preserves the semantics of calling the K0
//! searcher once for each item yielded by `ByteSlice::lines`, but it performs
//! one ordered pass over the source and reuses caller-owned fixed storage.
//! Line domains are terminated by LF. A single CR immediately before LF is
//! excluded from the line; every other CR is content. Empty input and the
//! position after a trailing LF do not create synthetic domains.

use core::{convert::Infallible, fmt};

use regex_syntax::hir::Look;

use crate::{Automaton, EdgeKind, MatchSpan, StateRole};

/// Stable accounting identity for the whole-input K0 grep reducer.
pub const ACCOUNTING_ID: &str = "fre.automata.p16-grep-stream.k0.v1";
/// Algorithm version bound by [`ACCOUNTING_ID`].
pub const ALGORITHM_VERSION: u32 = 1;
/// Accounting version bound by [`ACCOUNTING_ID`].
pub const ACCOUNTING_VERSION: u32 = 1;

/// Allocation-free structural identity of one completely validated K0 graph.
///
/// This is an artifact identity, not a lookup fingerprint. Every immutable
/// structure-of-arrays field that can affect execution participates, including
/// state and edge order, payload bytes, the start state, and the configured
/// line terminator. The caller combines this identity with its exact syntax
/// and compatibility-profile owner when sealing an operation receipt.
#[must_use]
pub fn structural_plan_identity(automaton: &Automaton) -> [u8; 16] {
    let mut digest = StructuralPlanDigest::new();
    digest.tagged_bytes(0x01, &automaton.start.to_le_bytes());
    digest.tagged_bytes(0x02, &[automaton.line_terminator()]);
    digest.tagged_len(0x10, automaton.roles.len());
    for role in automaton.roles.iter().copied() {
        digest.byte(match role {
            StateRole::Split => 0x01,
            StateRole::Consume => 0x02,
            StateRole::Accept => 0x03,
        });
    }
    digest.tagged_len(0x11, automaton.edge_offsets.len());
    for value in automaton.edge_offsets.iter().copied() {
        digest.bytes(&value.to_le_bytes());
    }
    digest.tagged_len(0x12, automaton.edge_targets.len());
    for value in automaton.edge_targets.iter().copied() {
        digest.bytes(&value.to_le_bytes());
    }
    digest.tagged_len(0x13, automaton.edge_kinds.len());
    for kind in automaton.edge_kinds.iter().copied() {
        digest.byte(edge_kind_identity_tag(kind));
    }
    digest.tagged_bytes(0x14, &automaton.byte_starts);
    digest.tagged_bytes(0x15, &automaton.byte_ends);
    digest.finish()
}

const fn edge_kind_identity_tag(kind: EdgeKind) -> u8 {
    match kind {
        EdgeKind::Epsilon => 0x01,
        EdgeKind::ByteRange => 0x02,
        EdgeKind::AssertHaystackStart => 0x03,
        EdgeKind::AssertHaystackEnd => 0x04,
        EdgeKind::AssertLineStartLf => 0x05,
        EdgeKind::AssertLineEndLf => 0x06,
        EdgeKind::AssertLineStartCrlf => 0x07,
        EdgeKind::AssertLineEndCrlf => 0x08,
        EdgeKind::AssertWordAscii => 0x09,
        EdgeKind::AssertWordAsciiNegate => 0x0a,
        EdgeKind::AssertWordStartAscii => 0x0b,
        EdgeKind::AssertWordEndAscii => 0x0c,
        EdgeKind::AssertWordStartHalfAscii => 0x0d,
        EdgeKind::AssertWordEndHalfAscii => 0x0e,
        EdgeKind::AssertWordUnicode => 0x0f,
        EdgeKind::AssertWordUnicodeNegate => 0x10,
        EdgeKind::AssertWordStartUnicode => 0x11,
        EdgeKind::AssertWordEndUnicode => 0x12,
        EdgeKind::AssertWordStartHalfUnicode => 0x13,
        EdgeKind::AssertWordEndHalfUnicode => 0x14,
    }
}

struct StructuralPlanDigest {
    left: u64,
    right: u64,
}

impl StructuralPlanDigest {
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

    fn bytes(&mut self, bytes: &[u8]) {
        for byte in bytes.iter().copied() {
            self.byte(byte);
        }
    }

    fn tagged_len(&mut self, tag: u8, length: usize) {
        self.byte(tag);
        self.bytes(&length.to_le_bytes());
    }

    fn tagged_bytes(&mut self, tag: u8, bytes: &[u8]) {
        self.tagged_len(tag, bytes.len());
        self.bytes(bytes);
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

/// Source-independent storage and execution maxima for one haystack length.
///
/// Every field is derived before source inspection. Execution refuses an
/// unequal admission, a wrong workspace shape, or an unusable generation
/// range before reading `haystack`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrepStreamProspective {
    line_state_cells: usize,
    generation_cells: usize,
    candidate_cells: usize,
    required_generations: u64,
    work: u64,
    source_accesses: u64,
    transitions: u64,
    candidates: u64,
    boundaries: u64,
    consume_events: u64,
    domains_examined: u64,
    line_domains: u64,
    output_events: u64,
    cache_misses: u64,
    history_nodes: u64,
    allocations: u64,
}

impl GrepStreamProspective {
    #[must_use]
    pub const fn line_state_cells(self) -> usize {
        self.line_state_cells
    }

    #[must_use]
    pub const fn generation_cells(self) -> usize {
        self.generation_cells
    }

    #[must_use]
    pub const fn candidate_cells(self) -> usize {
        self.candidate_cells
    }

    #[must_use]
    pub const fn required_generations(self) -> u64 {
        self.required_generations
    }

    #[must_use]
    pub const fn work(self) -> u64 {
        self.work
    }

    #[must_use]
    pub const fn source_accesses(self) -> u64 {
        self.source_accesses
    }

    #[must_use]
    pub const fn transitions(self) -> u64 {
        self.transitions
    }

    #[must_use]
    pub const fn candidates(self) -> u64 {
        self.candidates
    }

    #[must_use]
    pub const fn boundaries(self) -> u64 {
        self.boundaries
    }

    #[must_use]
    pub const fn consume_events(self) -> u64 {
        self.consume_events
    }

    #[must_use]
    pub const fn domains_examined(self) -> u64 {
        self.domains_examined
    }

    /// Maximum selected line domains. This is also the output-event maximum.
    #[must_use]
    pub const fn line_domains(self) -> u64 {
        self.line_domains
    }

    #[must_use]
    pub const fn output_events(self) -> u64 {
        self.output_events
    }

    #[must_use]
    pub const fn cache_misses(self) -> u64 {
        self.cache_misses
    }

    #[must_use]
    pub const fn history_nodes(self) -> u64 {
        self.history_nodes
    }

    #[must_use]
    pub const fn allocations(self) -> u64 {
        self.allocations
    }
}

/// Exact execution counters for a successful whole-input reduction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GrepStreamActual {
    work: u64,
    source_accesses: u64,
    transitions: u64,
    candidates: u64,
    boundaries: u64,
    consume_events: u64,
    domains_examined: u64,
    line_domains: u64,
    output_events: u64,
    cache_misses: u64,
    history_nodes: u64,
    allocations: u64,
    generations_used: u64,
}

impl GrepStreamActual {
    #[must_use]
    pub const fn work(self) -> u64 {
        self.work
    }

    #[must_use]
    pub const fn source_accesses(self) -> u64 {
        self.source_accesses
    }

    #[must_use]
    pub const fn transitions(self) -> u64 {
        self.transitions
    }

    #[must_use]
    pub const fn candidates(self) -> u64 {
        self.candidates
    }

    #[must_use]
    pub const fn boundaries(self) -> u64 {
        self.boundaries
    }

    #[must_use]
    pub const fn consume_events(self) -> u64 {
        self.consume_events
    }

    #[must_use]
    pub const fn domains_examined(self) -> u64 {
        self.domains_examined
    }

    #[must_use]
    pub const fn line_domains(self) -> u64 {
        self.line_domains
    }

    #[must_use]
    pub const fn output_events(self) -> u64 {
        self.output_events
    }

    #[must_use]
    pub const fn cache_misses(self) -> u64 {
        self.cache_misses
    }

    #[must_use]
    pub const fn history_nodes(self) -> u64 {
        self.history_nodes
    }

    #[must_use]
    pub const fn allocations(self) -> u64 {
        self.allocations
    }

    #[must_use]
    pub const fn generations_used(self) -> u64 {
        self.generations_used
    }
}

/// One selected line and its leftmost-first match, all in absolute offsets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatchedLine {
    ordinal: usize,
    line_start: usize,
    content_end: usize,
    source_end: usize,
    selected_match: MatchSpan,
}

impl MatchedLine {
    /// Zero-based ordinal among every semantic line domain, including
    /// non-matching domains.
    #[must_use]
    pub const fn ordinal(self) -> usize {
        self.ordinal
    }

    #[must_use]
    pub const fn line_start(self) -> usize {
        self.line_start
    }

    /// Exclusive end after stripping one CR immediately before LF.
    #[must_use]
    pub const fn content_end(self) -> usize {
        self.content_end
    }

    /// Exclusive end in the original source, including a closing LF and its
    /// stripped CR when present.
    #[must_use]
    pub const fn source_end(self) -> usize {
        self.source_end
    }

    #[must_use]
    pub const fn selected_match(self) -> MatchSpan {
        self.selected_match
    }
}

/// Constant-space summary retained by the fast execution report.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MatchedLineSummary {
    count: u64,
    first: Option<MatchedLine>,
    last: Option<MatchedLine>,
}

impl MatchedLineSummary {
    #[must_use]
    pub const fn count(self) -> u64 {
        self.count
    }

    #[must_use]
    pub const fn first(self) -> Option<MatchedLine> {
        self.first
    }

    #[must_use]
    pub const fn last(self) -> Option<MatchedLine> {
        self.last
    }
}

/// Successful execution result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrepStreamReport {
    prospective: GrepStreamProspective,
    actual: GrepStreamActual,
    matched: MatchedLineSummary,
}

impl GrepStreamReport {
    #[must_use]
    pub const fn prospective(self) -> GrepStreamProspective {
        self.prospective
    }

    #[must_use]
    pub const fn actual(self) -> GrepStreamActual {
        self.actual
    }

    #[must_use]
    pub const fn matched(self) -> MatchedLineSummary {
        self.matched
    }
}

/// Checked refusal or invariant failure from the grep executor.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GrepStreamError {
    ArithmeticOverflow {
        computation: &'static str,
    },
    AdmissionMismatch,
    WorkspaceShape {
        storage: &'static str,
        needed_cells: usize,
        actual_cells: usize,
    },
    GenerationRange {
        first: u64,
        required: u64,
    },
    AccountingBoundExceeded {
        resource: &'static str,
        limit: u64,
        attempted: u64,
    },
    InternalInvariant {
        detail: &'static str,
    },
}

impl fmt::Display for GrepStreamError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArithmeticOverflow { computation } => {
                write!(
                    formatter,
                    "arithmetic overflow while computing {computation}"
                )
            }
            Self::AdmissionMismatch => {
                formatter.write_str("grep stream admission does not match the exact prospective")
            }
            Self::WorkspaceShape {
                storage,
                needed_cells,
                actual_cells,
            } => write!(
                formatter,
                "{storage} has {actual_cells} cells, expected exactly {needed_cells}"
            ),
            Self::GenerationRange { first, required } => write!(
                formatter,
                "generation range beginning at {first} cannot reserve {required} generations"
            ),
            Self::AccountingBoundExceeded {
                resource,
                limit,
                attempted,
            } => write!(
                formatter,
                "grep stream {resource} attempted {attempted}, exceeding prospective {limit}"
            ),
            Self::InternalInvariant { detail } => {
                write!(formatter, "grep stream internal invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for GrepStreamError {}

/// Failure from the optional full-event observer.
#[derive(Debug)]
pub enum GrepStreamObservedError<E> {
    /// Executor refusal or invariant failure.
    Execution {
        error: GrepStreamError,
        partial: GrepStreamActual,
    },
    /// Observer refusal after the contained exact partial accounting.
    Observer { error: E, partial: GrepStreamActual },
}

impl<E> From<GrepStreamError> for GrepStreamObservedError<E> {
    fn from(error: GrepStreamError) -> Self {
        Self::Execution {
            error,
            partial: GrepStreamActual::default(),
        }
    }
}

/// Derive the complete source-independent prospective for `haystack_len`.
///
/// No source bytes are needed. Bounds cover one primary read per source byte,
/// at most three bounded right-context reads per Unicode assertion, all
/// ordered closure and consuming-edge inspections, line reduction, and
/// selected-line publication.
#[allow(
    clippy::too_many_lines,
    reason = "the source-free proof computes every independently metered dimension in one audit scope"
)]
pub fn prospective(
    automaton: &Automaton,
    haystack_len: usize,
) -> Result<GrepStreamProspective, GrepStreamError> {
    let states = automaton.stats().states();
    let edges = automaton.stats().edges();
    let zero_width_edges = automaton.stats().zero_width_edges();
    let closure_slots =
        zero_width_edges
            .checked_add(1)
            .ok_or(GrepStreamError::ArithmeticOverflow {
                computation: "grep closure slots",
            })?;
    let line_threads =
        states
            .checked_add(closure_slots)
            .ok_or(GrepStreamError::ArithmeticOverflow {
                computation: "grep line thread slots",
            })?;
    let line_state_cells =
        line_threads
            .checked_mul(2)
            .ok_or(GrepStreamError::ArithmeticOverflow {
                computation: "grep line-state cells",
            })?;
    let candidate_cells = edges
        .checked_mul(2)
        .ok_or(GrepStreamError::ArithmeticOverflow {
            computation: "grep candidate cells",
        })?;

    let input = u64::try_from(haystack_len).map_err(|_| GrepStreamError::ArithmeticOverflow {
        computation: "grep input length conversion",
    })?;
    let boundaries = if haystack_len == 0 {
        0
    } else {
        input
            .checked_add(1)
            .ok_or(GrepStreamError::ArithmeticOverflow {
                computation: "grep boundary bound",
            })?
    };
    let edge_bound = u64::try_from(edges).map_err(|_| GrepStreamError::ArithmeticOverflow {
        computation: "grep edge count conversion",
    })?;
    let zero_bound =
        u64::try_from(zero_width_edges).map_err(|_| GrepStreamError::ArithmeticOverflow {
            computation: "grep zero-width edge count conversion",
        })?;

    // Left Unicode context is retained in four stack bytes. Right context
    // consumes at most three additional source bytes after its already-read
    // first byte.
    let unicode_context_accesses = boundaries
        .checked_mul(zero_bound)
        .and_then(|value| value.checked_mul(3))
        .ok_or(GrepStreamError::ArithmeticOverflow {
            computation: "grep Unicode source-access bound",
        })?;
    let source_accesses =
        input
            .checked_add(unicode_context_accesses)
            .ok_or(GrepStreamError::ArithmeticOverflow {
                computation: "grep source-access bound",
            })?;

    // Per boundary: at most E+1 root pops, Z closure-child pops, Z
    // zero-width edge inspections, and E consuming-edge inspections.
    let transitions_per_boundary = edge_bound
        .checked_mul(2)
        .and_then(|value| zero_bound.checked_mul(2).and_then(|z| value.checked_add(z)))
        .and_then(|value| value.checked_add(1))
        .ok_or(GrepStreamError::ArithmeticOverflow {
            computation: "grep transition bound per boundary",
        })?;
    let transitions = boundaries.checked_mul(transitions_per_boundary).ok_or(
        GrepStreamError::ArithmeticOverflow {
            computation: "grep transition bound",
        },
    )?;

    // Root attempts, successful consuming roots, and at most one accepting
    // candidate per examined boundary.
    let candidates_per_boundary = edge_bound
        .checked_mul(2)
        .and_then(|value| value.checked_add(2))
        .ok_or(GrepStreamError::ArithmeticOverflow {
            computation: "grep candidate bound per boundary",
        })?;
    let candidates = boundaries.checked_mul(candidates_per_boundary).ok_or(
        GrepStreamError::ArithmeticOverflow {
            computation: "grep candidate bound",
        },
    )?;

    // Work is charged exactly as the sum of source accesses, transitions,
    // candidates, boundary events, consume events, domain-close events, and
    // selected-line events. Each of the final three classes is bounded by N.
    let work = source_accesses
        .checked_add(transitions)
        .and_then(|value| value.checked_add(candidates))
        .and_then(|value| value.checked_add(boundaries))
        .and_then(|value| {
            input
                .checked_mul(3)
                .and_then(|tail| value.checked_add(tail))
        })
        .ok_or(GrepStreamError::ArithmeticOverflow {
            computation: "grep total work bound",
        })?;

    Ok(GrepStreamProspective {
        line_state_cells,
        generation_cells: states,
        candidate_cells,
        required_generations: boundaries,
        work,
        source_accesses,
        transitions,
        candidates,
        boundaries,
        consume_events: input,
        domains_examined: input,
        line_domains: input,
        output_events: input,
        cache_misses: 0,
        history_nodes: 0,
        allocations: 0,
    })
}

/// Count matching lines without retaining or observing every selected event.
///
/// This function allocates nothing. All refusal checks precede source access.
#[allow(
    clippy::too_many_arguments,
    reason = "the explicit fixed stores and generation range are independently authenticated"
)]
pub fn count_matching_lines(
    automaton: &Automaton,
    haystack: &[u8],
    admitted: GrepStreamProspective,
    first_generation: u64,
    line_state: &mut [u64],
    generations: &mut [u64],
    candidates: &mut [u64],
) -> Result<GrepStreamReport, GrepStreamError> {
    match count_matching_lines_with_observer(
        automaton,
        haystack,
        admitted,
        first_generation,
        line_state,
        generations,
        candidates,
        |_| Ok::<(), Infallible>(()),
    ) {
        Ok(report) => Ok(report),
        Err(GrepStreamObservedError::Execution { error, .. }) => Err(error),
        Err(GrepStreamObservedError::Observer { error, .. }) => match error {},
    }
}

/// Count matching lines and observe the complete ordered selected-line trace.
///
/// The observer is called once for each matching domain, in strictly
/// increasing zero-based line ordinal order. An observer error terminates the
/// operation without fallback and returns exact partial accounting. No
/// observer call can occur before admission and workspace preflight.
#[allow(
    clippy::too_many_arguments,
    reason = "the explicit fixed stores and generation range are independently authenticated"
)]
#[allow(
    clippy::too_many_lines,
    reason = "the single source traversal keeps CRLF state and every terminal path in one audit scope"
)]
pub fn count_matching_lines_with_observer<E, F>(
    automaton: &Automaton,
    haystack: &[u8],
    admitted: GrepStreamProspective,
    first_generation: u64,
    line_state: &mut [u64],
    generations: &mut [u64],
    candidates: &mut [u64],
    mut observer: F,
) -> Result<GrepStreamReport, GrepStreamObservedError<E>>
where
    F: FnMut(MatchedLine) -> Result<(), E>,
{
    let required = prospective(automaton, haystack.len())?;
    if admitted != required {
        return Err(GrepStreamError::AdmissionMismatch.into());
    }
    check_shape("line state", line_state.len(), required.line_state_cells)?;
    check_shape(
        "generation table",
        generations.len(),
        required.generation_cells,
    )?;
    check_shape(
        "candidate state",
        candidates.len(),
        required.candidate_cells,
    )?;
    check_generation_range(first_generation, required.required_generations)?;

    let state_cells =
        automaton
            .stats()
            .states()
            .checked_mul(2)
            .ok_or(GrepStreamError::ArithmeticOverflow {
                computation: "grep current-state cells",
            })?;
    let (current_cells, stack_cells) = line_state.split_at_mut(state_cells);
    let mut workspace = Workspace {
        seen_at: generations,
        current: ThreadCells::new(current_cells),
        roots: ThreadCells::new(candidates),
        stack: ThreadCells::new(stack_cells),
        first_generation,
    };
    let mut meter = Meter::new(required);
    let mut summary = MatchedLineSummary::default();
    let mut line = LineRuntime::new();
    let mut pending_cr = None;
    let mut source_index = 0usize;

    let execution = (|| -> Result<(), GrepStreamObservedError<E>> {
        while source_index < haystack.len() {
            meter.source_access(1)?;
            let byte = haystack[source_index];
            if let Some(cr_index) = pending_cr.take() {
                if byte == b'\n' {
                    finish_line(
                        automaton,
                        haystack,
                        &mut workspace,
                        &mut meter,
                        &mut line,
                        cr_index,
                        source_index
                            .checked_add(1)
                            .ok_or(GrepStreamError::ArithmeticOverflow {
                                computation: "grep CRLF source end",
                            })?,
                        &mut summary,
                        &mut observer,
                    )?;
                } else {
                    process_content_byte(
                        automaton,
                        haystack,
                        &mut workspace,
                        &mut meter,
                        &mut line,
                        cr_index,
                        b'\r',
                    )?;
                    if byte == b'\r' {
                        pending_cr = Some(source_index);
                    } else {
                        process_content_byte(
                            automaton,
                            haystack,
                            &mut workspace,
                            &mut meter,
                            &mut line,
                            source_index,
                            byte,
                        )?;
                    }
                }
            } else if byte == b'\r' {
                pending_cr = Some(source_index);
            } else if byte == b'\n' {
                finish_line(
                    automaton,
                    haystack,
                    &mut workspace,
                    &mut meter,
                    &mut line,
                    source_index,
                    source_index
                        .checked_add(1)
                        .ok_or(GrepStreamError::ArithmeticOverflow {
                            computation: "grep LF source end",
                        })?,
                    &mut summary,
                    &mut observer,
                )?;
            } else {
                process_content_byte(
                    automaton,
                    haystack,
                    &mut workspace,
                    &mut meter,
                    &mut line,
                    source_index,
                    byte,
                )?;
            }
            source_index =
                source_index
                    .checked_add(1)
                    .ok_or(GrepStreamError::ArithmeticOverflow {
                        computation: "grep source index",
                    })?;
        }

        if let Some(cr_index) = pending_cr {
            process_content_byte(
                automaton,
                haystack,
                &mut workspace,
                &mut meter,
                &mut line,
                cr_index,
                b'\r',
            )?;
        }
        if line.line_start < haystack.len() {
            finish_line(
                automaton,
                haystack,
                &mut workspace,
                &mut meter,
                &mut line,
                haystack.len(),
                haystack.len(),
                &mut summary,
                &mut observer,
            )?;
        }
        Ok(())
    })();
    if let Err(error) = execution {
        return Err(match error {
            GrepStreamObservedError::Execution { error, .. } => {
                GrepStreamObservedError::Execution {
                    error,
                    partial: meter.actual,
                }
            }
            observer @ GrepStreamObservedError::Observer { .. } => observer,
        });
    }

    let actual = meter.actual;
    if summary.count != actual.line_domains || actual.line_domains != actual.output_events {
        return Err(GrepStreamError::InternalInvariant {
            detail: "selected-line summary and output counters diverged",
        }
        .into());
    }
    Ok(GrepStreamReport {
        prospective: required,
        actual,
        matched: summary,
    })
}

fn check_shape(
    storage: &'static str,
    actual_cells: usize,
    needed_cells: usize,
) -> Result<(), GrepStreamError> {
    if actual_cells != needed_cells {
        return Err(GrepStreamError::WorkspaceShape {
            storage,
            needed_cells,
            actual_cells,
        });
    }
    Ok(())
}

fn check_generation_range(first: u64, required: u64) -> Result<(), GrepStreamError> {
    if required == 0 {
        return Ok(());
    }
    if first == 0 || first.checked_add(required.saturating_sub(1)).is_none() {
        return Err(GrepStreamError::GenerationRange { first, required });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default)]
struct Thread {
    state: u32,
    start: usize,
}

struct ThreadCells<'a> {
    cells: &'a mut [u64],
    len: usize,
}

impl<'a> ThreadCells<'a> {
    const fn new(cells: &'a mut [u64]) -> Self {
        Self { cells, len: 0 }
    }

    fn get(&self, index: usize) -> Result<Thread, GrepStreamError> {
        if index >= self.len {
            return Err(GrepStreamError::InternalInvariant {
                detail: "thread read exceeded logical length",
            });
        }
        let cell = index
            .checked_mul(2)
            .ok_or(GrepStreamError::ArithmeticOverflow {
                computation: "grep thread cell index",
            })?;
        let last = cell
            .checked_add(1)
            .ok_or(GrepStreamError::ArithmeticOverflow {
                computation: "grep thread final cell index",
            })?;
        let state =
            u32::try_from(self.cells[cell]).map_err(|_| GrepStreamError::InternalInvariant {
                detail: "stored grep state does not fit u32",
            })?;
        let start =
            usize::try_from(self.cells[last]).map_err(|_| GrepStreamError::InternalInvariant {
                detail: "stored grep offset does not fit usize",
            })?;
        Ok(Thread { state, start })
    }

    fn push(&mut self, thread: Thread) -> Result<(), GrepStreamError> {
        let cell = self
            .len
            .checked_mul(2)
            .ok_or(GrepStreamError::ArithmeticOverflow {
                computation: "grep thread push cell",
            })?;
        let last = cell
            .checked_add(1)
            .ok_or(GrepStreamError::ArithmeticOverflow {
                computation: "grep thread push final cell",
            })?;
        if last >= self.cells.len() {
            return Err(GrepStreamError::InternalInvariant {
                detail: "grep thread set exceeded admitted capacity",
            });
        }
        self.cells[cell] = u64::from(thread.state);
        self.cells[last] =
            u64::try_from(thread.start).map_err(|_| GrepStreamError::ArithmeticOverflow {
                computation: "grep absolute offset conversion",
            })?;
        self.len = self
            .len
            .checked_add(1)
            .ok_or(GrepStreamError::ArithmeticOverflow {
                computation: "grep thread logical length",
            })?;
        Ok(())
    }

    fn pop(&mut self) -> Result<Option<Thread>, GrepStreamError> {
        let Some(index) = self.len.checked_sub(1) else {
            return Ok(None);
        };
        let thread = self.get(index)?;
        self.len = index;
        Ok(Some(thread))
    }

    fn clear(&mut self) {
        self.len = 0;
    }
}

struct Workspace<'a> {
    seen_at: &'a mut [u64],
    current: ThreadCells<'a>,
    roots: ThreadCells<'a>,
    stack: ThreadCells<'a>,
    first_generation: u64,
}

#[derive(Clone, Copy)]
struct LineRuntime {
    ordinal: usize,
    line_start: usize,
    pending: Option<MatchSpan>,
    selected: Option<MatchSpan>,
    left: [u8; 4],
    left_len: usize,
}

impl LineRuntime {
    const fn new() -> Self {
        Self {
            ordinal: 0,
            line_start: 0,
            pending: None,
            selected: None,
            left: [0; 4],
            left_len: 0,
        }
    }

    fn push_left(&mut self, byte: u8) {
        if self.left_len < self.left.len() {
            self.left[self.left_len] = byte;
            self.left_len = self.left_len.saturating_add(1);
        } else {
            self.left.copy_within(1.., 0);
            self.left[3] = byte;
        }
    }

    fn reset_for_next(&mut self, next_start: usize) -> Result<(), GrepStreamError> {
        self.ordinal = self
            .ordinal
            .checked_add(1)
            .ok_or(GrepStreamError::ArithmeticOverflow {
                computation: "grep line ordinal",
            })?;
        self.line_start = next_start;
        self.pending = None;
        self.selected = None;
        self.left_len = 0;
        Ok(())
    }
}

struct Meter {
    limit: GrepStreamProspective,
    actual: GrepStreamActual,
}

impl Meter {
    const fn new(limit: GrepStreamProspective) -> Self {
        Self {
            limit,
            actual: GrepStreamActual {
                work: 0,
                source_accesses: 0,
                transitions: 0,
                candidates: 0,
                boundaries: 0,
                consume_events: 0,
                domains_examined: 0,
                line_domains: 0,
                output_events: 0,
                cache_misses: 0,
                history_nodes: 0,
                allocations: 0,
                generations_used: 0,
            },
        }
    }

    fn work(&mut self, amount: u64) -> Result<(), GrepStreamError> {
        checked_meter(
            &mut self.actual.work,
            amount,
            self.limit.work,
            "execution work",
        )
    }

    fn source_access(&mut self, amount: u64) -> Result<(), GrepStreamError> {
        checked_meter(
            &mut self.actual.source_accesses,
            amount,
            self.limit.source_accesses,
            "source accesses",
        )?;
        self.work(amount)
    }

    fn transition(&mut self) -> Result<(), GrepStreamError> {
        checked_meter(
            &mut self.actual.transitions,
            1,
            self.limit.transitions,
            "transitions",
        )?;
        self.work(1)
    }

    fn candidate(&mut self) -> Result<(), GrepStreamError> {
        checked_meter(
            &mut self.actual.candidates,
            1,
            self.limit.candidates,
            "candidates",
        )?;
        self.work(1)
    }

    fn boundary(&mut self) -> Result<(), GrepStreamError> {
        checked_meter(
            &mut self.actual.boundaries,
            1,
            self.limit.boundaries,
            "boundaries",
        )?;
        checked_meter(
            &mut self.actual.generations_used,
            1,
            self.limit.required_generations,
            "generations",
        )?;
        self.work(1)
    }

    fn consume(&mut self) -> Result<(), GrepStreamError> {
        checked_meter(
            &mut self.actual.consume_events,
            1,
            self.limit.consume_events,
            "consume events",
        )?;
        self.work(1)
    }

    fn domain(&mut self) -> Result<(), GrepStreamError> {
        checked_meter(
            &mut self.actual.domains_examined,
            1,
            self.limit.domains_examined,
            "domains examined",
        )?;
        self.work(1)
    }

    fn selected_line(&mut self) -> Result<(), GrepStreamError> {
        checked_meter(
            &mut self.actual.line_domains,
            1,
            self.limit.line_domains,
            "line domains",
        )?;
        checked_meter(
            &mut self.actual.output_events,
            1,
            self.limit.output_events,
            "output events",
        )?;
        self.work(1)
    }
}

fn checked_meter(
    value: &mut u64,
    amount: u64,
    limit: u64,
    resource: &'static str,
) -> Result<(), GrepStreamError> {
    let attempted = value
        .checked_add(amount)
        .ok_or(GrepStreamError::ArithmeticOverflow {
            computation: "grep actual counter",
        })?;
    if attempted > limit {
        return Err(GrepStreamError::AccountingBoundExceeded {
            resource,
            limit,
            attempted,
        });
    }
    *value = attempted;
    Ok(())
}

fn process_content_byte(
    automaton: &Automaton,
    haystack: &[u8],
    workspace: &mut Workspace<'_>,
    meter: &mut Meter,
    line: &mut LineRuntime,
    position: usize,
    byte: u8,
) -> Result<(), GrepStreamError> {
    if line.selected.is_some() {
        return Ok(());
    }
    begin_boundary(
        automaton,
        haystack,
        workspace,
        meter,
        line,
        position,
        Some(byte),
        false,
    )?;
    if line.selected.is_none() {
        consume_current(automaton, workspace, meter, byte)?;
        line.push_left(byte);
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "line close binds both source and semantic boundaries plus fixed execution state"
)]
fn finish_line<E, F>(
    automaton: &Automaton,
    haystack: &[u8],
    workspace: &mut Workspace<'_>,
    meter: &mut Meter,
    line: &mut LineRuntime,
    content_end: usize,
    source_end: usize,
    summary: &mut MatchedLineSummary,
    observer: &mut F,
) -> Result<(), GrepStreamObservedError<E>>
where
    F: FnMut(MatchedLine) -> Result<(), E>,
{
    if line.selected.is_none() {
        begin_boundary(
            automaton,
            haystack,
            workspace,
            meter,
            line,
            content_end,
            None,
            true,
        )?;
        if line.selected.is_none() {
            line.selected = line.pending;
        }
    }
    meter.domain()?;
    if let Some(selected_match) = line.selected {
        meter.selected_line()?;
        let matched = MatchedLine {
            ordinal: line.ordinal,
            line_start: line.line_start,
            content_end,
            source_end,
            selected_match,
        };
        summary.count =
            summary
                .count
                .checked_add(1)
                .ok_or(GrepStreamError::ArithmeticOverflow {
                    computation: "grep matched-line summary count",
                })?;
        summary.first.get_or_insert(matched);
        summary.last = Some(matched);
        if let Err(error) = observer(matched) {
            return Err(GrepStreamObservedError::Observer {
                error,
                partial: meter.actual,
            });
        }
    }

    workspace.current.clear();
    workspace.roots.clear();
    workspace.stack.clear();
    line.reset_for_next(source_end)?;
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the boundary context is explicit to prove slice-local assertion semantics"
)]
fn begin_boundary(
    automaton: &Automaton,
    haystack: &[u8],
    workspace: &mut Workspace<'_>,
    meter: &mut Meter,
    line: &mut LineRuntime,
    position: usize,
    right: Option<u8>,
    at_end: bool,
) -> Result<(), GrepStreamError> {
    meter.boundary()?;
    workspace.current.clear();
    let generation = workspace
        .first_generation
        .checked_add(meter.actual.generations_used.saturating_sub(1))
        .ok_or(GrepStreamError::InternalInvariant {
            detail: "preflighted generation range overflowed",
        })?;

    let root_count = workspace.roots.len;
    let mut root_index = 0usize;
    while root_index < root_count {
        let root = workspace.roots.get(root_index)?;
        meter.candidate()?;
        if let Some(found) = expand_root(
            automaton, haystack, workspace, meter, line, position, right, at_end, generation, root,
        )? {
            meter.candidate()?;
            line.pending = Some(found);
            break;
        }
        root_index = root_index
            .checked_add(1)
            .ok_or(GrepStreamError::ArithmeticOverflow {
                computation: "grep root index",
            })?;
    }
    workspace.roots.clear();

    if line.pending.is_none() {
        meter.candidate()?;
        if let Some(found) = expand_root(
            automaton,
            haystack,
            workspace,
            meter,
            line,
            position,
            right,
            at_end,
            generation,
            Thread {
                state: automaton.start,
                start: position,
            },
        )? {
            meter.candidate()?;
            line.pending = Some(found);
        }
    }

    if line.pending.is_some() && (workspace.current.len == 0 || at_end) {
        line.selected = line.pending;
    }
    Ok(())
}

fn consume_current(
    automaton: &Automaton,
    workspace: &mut Workspace<'_>,
    meter: &mut Meter,
    byte: u8,
) -> Result<(), GrepStreamError> {
    meter.consume()?;
    let current_len = workspace.current.len;
    for index in 0..current_len {
        let thread = workspace.current.get(index)?;
        for edge in automaton.state_edges(thread.state) {
            meter.transition()?;
            if automaton.byte_starts[edge] <= byte && byte <= automaton.byte_ends[edge] {
                meter.candidate()?;
                workspace.roots.push(Thread {
                    state: automaton.edge_targets[edge],
                    start: thread.start,
                })?;
            }
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the boundary context is explicit to prove slice-local assertion semantics"
)]
fn expand_root(
    automaton: &Automaton,
    haystack: &[u8],
    workspace: &mut Workspace<'_>,
    meter: &mut Meter,
    line: &LineRuntime,
    position: usize,
    right: Option<u8>,
    at_end: bool,
    generation: u64,
    root: Thread,
) -> Result<Option<MatchSpan>, GrepStreamError> {
    workspace.stack.clear();
    workspace.stack.push(root)?;
    while let Some(thread) = workspace.stack.pop()? {
        meter.transition()?;
        let state =
            usize::try_from(thread.state).map_err(|_| GrepStreamError::InternalInvariant {
                detail: "validated grep state does not fit usize",
            })?;
        if workspace.seen_at[state] == generation {
            continue;
        }
        workspace.seen_at[state] = generation;

        match automaton.roles[state] {
            StateRole::Accept => return Ok(Some(MatchSpan::new(thread.start, position))),
            StateRole::Consume => workspace.current.push(thread)?,
            StateRole::Split => {
                for edge in automaton.state_edges(thread.state).rev() {
                    meter.transition()?;
                    if assertion_enabled(
                        automaton,
                        automaton.edge_kinds[edge],
                        haystack,
                        meter,
                        line,
                        position,
                        right,
                        at_end,
                    )? {
                        workspace.stack.push(Thread {
                            state: automaton.edge_targets[edge],
                            start: thread.start,
                        })?;
                    }
                }
            }
        }
    }
    Ok(None)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the boundary context is explicit to prove slice-local assertion semantics"
)]
fn assertion_enabled(
    automaton: &Automaton,
    kind: EdgeKind,
    haystack: &[u8],
    meter: &mut Meter,
    line: &LineRuntime,
    position: usize,
    right: Option<u8>,
    at_end: bool,
) -> Result<bool, GrepStreamError> {
    let before = line.left_len.checked_sub(1).map(|index| line.left[index]);
    match kind {
        EdgeKind::Epsilon => Ok(true),
        EdgeKind::AssertHaystackStart => Ok(position == line.line_start),
        EdgeKind::AssertHaystackEnd => Ok(at_end),
        EdgeKind::AssertLineStartLf => {
            Ok(position == line.line_start || before == Some(automaton.line_terminator()))
        }
        EdgeKind::AssertLineEndLf => Ok(at_end || right == Some(automaton.line_terminator())),
        EdgeKind::AssertLineStartCrlf => Ok(position == line.line_start
            || before == Some(b'\n')
            || (before == Some(b'\r') && right != Some(b'\n'))),
        EdgeKind::AssertLineEndCrlf => {
            Ok(at_end || right == Some(b'\r') || (right == Some(b'\n') && before != Some(b'\r')))
        }
        EdgeKind::AssertWordAscii
        | EdgeKind::AssertWordAsciiNegate
        | EdgeKind::AssertWordStartAscii
        | EdgeKind::AssertWordEndAscii
        | EdgeKind::AssertWordStartHalfAscii
        | EdgeKind::AssertWordEndHalfAscii => {
            let left_word = before.is_some_and(is_ascii_word);
            let right_word = right.is_some_and(is_ascii_word);
            Ok(match kind {
                EdgeKind::AssertWordAscii => left_word != right_word,
                EdgeKind::AssertWordAsciiNegate => left_word == right_word,
                EdgeKind::AssertWordStartAscii => !left_word && right_word,
                EdgeKind::AssertWordEndAscii => left_word && !right_word,
                EdgeKind::AssertWordStartHalfAscii => !left_word,
                EdgeKind::AssertWordEndHalfAscii => !right_word,
                _ => unreachable!("ASCII assertion dispatch is exhaustive"),
            })
        }
        unicode_kind @ (EdgeKind::AssertWordUnicode
        | EdgeKind::AssertWordUnicodeNegate
        | EdgeKind::AssertWordStartUnicode
        | EdgeKind::AssertWordEndUnicode
        | EdgeKind::AssertWordStartHalfUnicode
        | EdgeKind::AssertWordEndHalfUnicode) => unicode_assertion(
            unicode_kind,
            haystack,
            meter,
            &line.left[..line.left_len],
            position,
            right,
        ),
        EdgeKind::ByteRange => Err(GrepStreamError::InternalInvariant {
            detail: "split state contained a consuming edge",
        }),
    }
}

fn is_ascii_word(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn unicode_assertion(
    kind: EdgeKind,
    haystack: &[u8],
    meter: &mut Meter,
    left: &[u8],
    position: usize,
    right: Option<u8>,
) -> Result<bool, GrepStreamError> {
    let left_scalar = decode_last_utf8(left);
    let right_scalar = decode_right_utf8(haystack, meter, position, right)?;
    let left_valid = left.is_empty() || left_scalar.is_some();
    let right_valid = right.is_none() || right_scalar.is_some();
    let left_word = left_scalar.is_some_and(is_unicode_word_character);
    let right_word = right_scalar.is_some_and(is_unicode_word_character);
    let look = match kind {
        EdgeKind::AssertWordUnicode => Look::WordUnicode,
        EdgeKind::AssertWordUnicodeNegate => Look::WordUnicodeNegate,
        EdgeKind::AssertWordStartUnicode => Look::WordStartUnicode,
        EdgeKind::AssertWordEndUnicode => Look::WordEndUnicode,
        EdgeKind::AssertWordStartHalfUnicode => Look::WordStartHalfUnicode,
        EdgeKind::AssertWordEndHalfUnicode => Look::WordEndHalfUnicode,
        _ => {
            return Err(GrepStreamError::InternalInvariant {
                detail: "non-Unicode edge in Unicode assertion dispatch",
            });
        }
    };
    Ok(match look {
        Look::WordUnicode => left_word != right_word,
        Look::WordUnicodeNegate => left_valid && right_valid && left_word == right_word,
        Look::WordStartUnicode => !left_word && right_word,
        Look::WordEndUnicode => left_word && !right_word,
        Look::WordStartHalfUnicode => left_valid && !left_word,
        Look::WordEndHalfUnicode => right_valid && !right_word,
        _ => unreachable!("Unicode look mapping is exhaustive"),
    })
}

fn is_unicode_word_character(character: char) -> bool {
    regex_syntax::try_is_word_character(character)
        .expect("fre-automata enables regex-syntax's Unicode Perl tables")
}

fn decode_right_utf8(
    haystack: &[u8],
    meter: &mut Meter,
    position: usize,
    first: Option<u8>,
) -> Result<Option<char>, GrepStreamError> {
    let Some(first) = first else {
        return Ok(None);
    };
    let width = utf8_width(first);
    if width == 0 {
        return Ok(None);
    }
    let mut bytes = [0_u8; 4];
    bytes[0] = first;
    for (offset, slot) in bytes.iter_mut().enumerate().take(width).skip(1) {
        let Some(index) = position.checked_add(offset) else {
            return Ok(None);
        };
        if index >= haystack.len() {
            return Ok(None);
        }
        meter.source_access(1)?;
        let byte = haystack[index];
        if !matches!(byte, 0x80..=0xBF) {
            return Ok(None);
        }
        *slot = byte;
    }
    Ok(core::str::from_utf8(&bytes[..width])
        .ok()
        .and_then(|valid| valid.chars().next()))
}

fn decode_last_utf8(bytes: &[u8]) -> Option<char> {
    let last = bytes.len().checked_sub(1)?;
    let lower = bytes.len().saturating_sub(4);
    let mut start = last;
    while start > lower && matches!(bytes[start], 0x80..=0xBF) {
        start = start.checked_sub(1)?;
    }
    let width = utf8_width(bytes[start]);
    if width == 0 {
        return None;
    }
    let end = start.checked_add(width)?;
    core::str::from_utf8(bytes.get(start..end)?)
        .ok()
        .and_then(|valid| valid.chars().next())
}

const fn utf8_width(first: u8) -> usize {
    match first {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF7 => 4,
        _ => 0,
    }
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "test fixtures use small, statically bounded offsets and counter sums"
)]
mod tests {
    use core::cell::Cell;

    use super::{
        count_matching_lines, count_matching_lines_with_observer, prospective,
        structural_plan_identity, GrepStreamError, GrepStreamObservedError, MatchedLine,
    };
    use crate::{
        Automaton, CompileLimits, EdgeKind, MatchSpan, RawPlan, SearchLimits, Span, StateRole,
    };

    fn compile(
        roles: &[StateRole],
        offsets: &[u32],
        targets: &[u32],
        kinds: &[EdgeKind],
        starts: &[u8],
        ends: &[u8],
    ) -> Automaton {
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: roles.to_vec(),
                edge_offsets: offsets.to_vec(),
                edge_targets: targets.to_vec(),
                edge_kinds: kinds.to_vec(),
                byte_starts: starts.to_vec(),
                byte_ends: ends.to_vec(),
            },
            CompileLimits::default(),
        )
        .expect("test automaton is valid")
    }

    fn literal(byte: u8) -> Automaton {
        compile(
            &[StateRole::Consume, StateRole::Accept],
            &[0, 1, 1],
            &[1],
            &[EdgeKind::ByteRange],
            &[byte],
            &[byte],
        )
    }

    #[test]
    fn structural_identity_binds_graph_bytes_order_and_line_terminator() {
        let a = literal(b'a');
        let b = literal(b'b');
        let alternate_terminator = literal(b'a').with_line_terminator(0);
        assert_eq!(structural_plan_identity(&a), structural_plan_identity(&a));
        assert_ne!(structural_plan_identity(&a), structural_plan_identity(&b));
        assert_ne!(
            structural_plan_identity(&a),
            structural_plan_identity(&alternate_terminator)
        );
        assert_ne!(
            structural_plan_identity(&higher_ab_before_a()),
            structural_plan_identity(&a)
        );
    }

    fn empty() -> Automaton {
        compile(
            &[StateRole::Split, StateRole::Accept],
            &[0, 1, 1],
            &[1],
            &[EdgeKind::Epsilon],
            &[0],
            &[0],
        )
    }

    fn anchored_literal(byte: u8) -> Automaton {
        look_anchored_literal(
            EdgeKind::AssertHaystackStart,
            EdgeKind::AssertHaystackEnd,
            byte,
            b'\n',
        )
    }

    fn look_anchored_literal(
        start: EdgeKind,
        end: EdgeKind,
        byte: u8,
        line_terminator: u8,
    ) -> Automaton {
        compile(
            &[
                StateRole::Split,
                StateRole::Consume,
                StateRole::Split,
                StateRole::Accept,
            ],
            &[0, 1, 2, 3, 3],
            &[1, 2, 3],
            &[start, EdgeKind::ByteRange, end],
            &[0, byte, 0],
            &[0, byte, 0],
        )
        .with_line_terminator(line_terminator)
    }

    fn unicode_word_then(byte: u8) -> Automaton {
        compile(
            &[StateRole::Split, StateRole::Consume, StateRole::Accept],
            &[0, 1, 2, 2],
            &[1, 2],
            &[EdgeKind::AssertWordUnicode, EdgeKind::ByteRange],
            &[0, byte],
            &[0, byte],
        )
    }

    fn unicode_nonword_empty() -> Automaton {
        compile(
            &[StateRole::Split, StateRole::Accept],
            &[0, 1, 1],
            &[1],
            &[EdgeKind::AssertWordUnicodeNegate],
            &[0],
            &[0],
        )
    }

    fn higher_ab_before_a() -> Automaton {
        // (?:ab|a), with the two consuming `a` states kept distinct so the
        // priority order remains observable at the second boundary.
        compile(
            &[
                StateRole::Split,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Accept,
                StateRole::Consume,
                StateRole::Accept,
            ],
            &[0, 2, 3, 4, 4, 5, 5],
            &[1, 4, 2, 3, 5],
            &[
                EdgeKind::Epsilon,
                EdgeKind::Epsilon,
                EdgeKind::ByteRange,
                EdgeKind::ByteRange,
                EdgeKind::ByteRange,
            ],
            &[0, 0, b'a', b'b', b'a'],
            &[0, 0, b'a', b'b', b'a'],
        )
    }

    fn execute(
        automaton: &Automaton,
        haystack: &[u8],
    ) -> (super::GrepStreamReport, Vec<MatchedLine>) {
        let admitted = prospective(automaton, haystack.len()).expect("prospective");
        let mut line_state = vec![0; admitted.line_state_cells()];
        let mut generations = vec![0; admitted.generation_cells()];
        let mut candidates = vec![0; admitted.candidate_cells()];
        let mut trace = Vec::new();
        let first_generation = u64::from(admitted.required_generations() != 0);
        let report = count_matching_lines_with_observer(
            automaton,
            haystack,
            admitted,
            first_generation,
            &mut line_state,
            &mut generations,
            &mut candidates,
            |matched| {
                trace.push(matched);
                Ok::<(), ()>(())
            },
        )
        .expect("grep stream execution");
        (report, trace)
    }

    fn reference(automaton: &Automaton, haystack: &[u8]) -> Vec<MatchedLine> {
        let mut selected = Vec::new();
        let mut line_start = 0usize;
        let mut ordinal = 0usize;
        for lf in 0..haystack.len() {
            if haystack[lf] != b'\n' {
                continue;
            }
            let content_end = if lf > line_start && haystack[lf - 1] == b'\r' {
                lf - 1
            } else {
                lf
            };
            reference_line(
                automaton,
                haystack,
                ordinal,
                line_start,
                content_end,
                lf + 1,
                &mut selected,
            );
            ordinal += 1;
            line_start = lf + 1;
        }
        if line_start < haystack.len() {
            reference_line(
                automaton,
                haystack,
                ordinal,
                line_start,
                haystack.len(),
                haystack.len(),
                &mut selected,
            );
        }
        selected
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the test reference spells out the complete semantic line identity"
    )]
    fn reference_line(
        automaton: &Automaton,
        haystack: &[u8],
        ordinal: usize,
        line_start: usize,
        content_end: usize,
        source_end: usize,
        selected: &mut Vec<MatchedLine>,
    ) {
        let report = automaton
            .prepare::<Span>()
            .search(
                &haystack[line_start..content_end],
                SearchLimits::unlimited(),
            )
            .expect("reference K0 search");
        if let Some(relative) = *report.output() {
            selected.push(MatchedLine {
                ordinal,
                line_start,
                content_end,
                source_end,
                selected_match: MatchSpan::new(
                    line_start + relative.start(),
                    line_start + relative.end(),
                ),
            });
        }
    }

    fn assert_reference(automaton: &Automaton, haystack: &[u8]) {
        let (report, actual) = execute(automaton, haystack);
        let expected = reference(automaton, haystack);
        assert_eq!(actual, expected, "haystack={haystack:?}");
        assert_eq!(
            report.matched().count(),
            u64::try_from(expected.len()).unwrap()
        );
        assert_eq!(report.matched().first(), expected.first().copied());
        assert_eq!(report.matched().last(), expected.last().copied());
        assert_eq!(report.actual().line_domains(), report.matched().count());
        assert_eq!(
            report.actual().work(),
            report.actual().source_accesses()
                + report.actual().transitions()
                + report.actual().candidates()
                + report.actual().boundaries()
                + report.actual().consume_events()
                + report.actual().domains_examined()
                + report.actual().output_events()
        );
        assert!(report.actual().work() <= report.prospective().work());
        assert!(report.actual().source_accesses() <= report.prospective().source_accesses());
        assert!(report.actual().transitions() <= report.prospective().transitions());
        assert!(report.actual().candidates() <= report.prospective().candidates());
        assert!(report.actual().generations_used() <= report.prospective().required_generations());
        assert_eq!(report.actual().cache_misses(), 0);
        assert_eq!(report.actual().history_nodes(), 0);
        assert_eq!(report.actual().allocations(), 0);
    }

    #[test]
    fn byte_lines_match_repeated_k0_without_synthetic_domains() {
        let automata = [literal(b'a'), empty(), anchored_literal(b'a')];
        let haystacks: &[&[u8]] = &[
            b"",
            b"\n",
            b"\n\n",
            b"a",
            b"a\n",
            b"a\n\n",
            b"\na",
            b"a\nb\na",
            b"\r",
            b"\r\n",
            b"a\r\n",
            b"\r\r\n",
            b"a\rb",
            b"a\r\nb\r\nc",
            b"\xff\n\0\r\n",
        ];
        for automaton in &automata {
            for &haystack in haystacks {
                assert_reference(automaton, haystack);
            }
        }
    }

    #[test]
    fn priority_and_absolute_selected_offsets_match_k0() {
        let automaton = higher_ab_before_a();
        for haystack in [
            b"ab\na\nzab\r\naba".as_slice(),
            b"ab\r\nab\n".as_slice(),
            b"a\nab".as_slice(),
        ] {
            assert_reference(&automaton, haystack);
        }
        let (_, trace) = execute(&automaton, b"x\nab\r\na");
        assert_eq!(trace[0].ordinal(), 1);
        assert_eq!(trace[0].line_start(), 2);
        assert_eq!(trace[0].content_end(), 4);
        assert_eq!(trace[0].source_end(), 6);
        assert_eq!(trace[0].selected_match(), MatchSpan::new(2, 4));
        assert_eq!(trace[1].selected_match(), MatchSpan::new(6, 7));
    }

    #[test]
    fn unicode_and_malformed_context_is_clipped_to_each_line() {
        let boundary = unicode_word_then(b'a');
        let nonword = unicode_nonword_empty();
        let haystacks: &[&[u8]] = &[
            b"a",
            b"\xffa",
            b"\xc2a",
            b"\xe2\x82\xaca",
            b"\xe2\x82a",
            b"a\r\n\xffa\n",
            b"\xf0\x9f\x92\xa9a\n\xc0a",
            b"\x80a\r\n",
        ];
        for &haystack in haystacks {
            assert_reference(&boundary, haystack);
            assert_reference(&nonword, haystack);
        }
    }

    #[test]
    fn multiline_anchor_context_is_line_local_and_keeps_configured_terminator() {
        let configured = look_anchored_literal(
            EdgeKind::AssertLineStartLf,
            EdgeKind::AssertLineEndLf,
            b'a',
            0,
        );
        let crlf = look_anchored_literal(
            EdgeKind::AssertLineStartCrlf,
            EdgeKind::AssertLineEndCrlf,
            b'a',
            b'\n',
        );
        let haystacks: &[&[u8]] = &[
            b"a",
            b"x\0a",
            b"a\0x",
            b"x\0a\0y",
            b"x\0a\r\n",
            b"x\ra",
            b"a\rx",
            b"x\ra\ry",
            b"a\r\nx\ra",
        ];
        for &haystack in haystacks {
            assert_reference(&configured, haystack);
            assert_reference(&crlf, haystack);
        }
    }

    #[test]
    fn exhaustive_short_sources_match_repeated_k0() {
        let automata = [
            literal(b'a'),
            empty(),
            anchored_literal(b'a'),
            unicode_word_then(b'a'),
            unicode_nonword_empty(),
            higher_ab_before_a(),
        ];
        let alphabet = [b'a', b'b', b'\r', b'\n', 0xFF, 0xC2, 0x80];
        let mut source = [0_u8; 4];
        for length in 0..=source.len() {
            let cases = alphabet.len().pow(u32::try_from(length).unwrap());
            for mut encoded in 0..cases {
                for slot in source.iter_mut().take(length) {
                    *slot = alphabet[encoded % alphabet.len()];
                    encoded /= alphabet.len();
                }
                for automaton in &automata {
                    assert_reference(automaton, &source[..length]);
                }
            }
        }
    }

    #[test]
    fn fixed_program_prospective_counters_are_near_linear_under_input_doubling() {
        let automaton = higher_ab_before_a();
        let small = prospective(&automaton, 257).expect("small prospective");
        let large = prospective(&automaton, 514).expect("large prospective");
        assert_eq!(large.line_state_cells(), small.line_state_cells());
        assert_eq!(large.generation_cells(), small.generation_cells());
        assert_eq!(large.candidate_cells(), small.candidate_cells());
        for (name, small_counter, large_counter) in [
            ("work", small.work(), large.work()),
            (
                "source accesses",
                small.source_accesses(),
                large.source_accesses(),
            ),
            ("transitions", small.transitions(), large.transitions()),
            ("candidates", small.candidates(), large.candidates()),
            ("boundaries", small.boundaries(), large.boundaries()),
            (
                "consume events",
                small.consume_events(),
                large.consume_events(),
            ),
            (
                "required generations",
                small.required_generations(),
                large.required_generations(),
            ),
            ("line domains", small.line_domains(), large.line_domains()),
            (
                "output events",
                small.output_events(),
                large.output_events(),
            ),
        ] {
            assert!(
                large_counter <= small_counter * 2,
                "{name}: {large_counter} exceeded twice {small_counter}"
            );
        }
    }

    #[test]
    fn exact_workspace_reuses_distinct_generation_ranges() {
        let automaton = literal(b'a');
        let haystack = b"a\nb\na";
        let admitted = prospective(&automaton, haystack.len()).unwrap();
        let mut line_state = vec![0; admitted.line_state_cells()];
        let mut generations = vec![0; admitted.generation_cells()];
        let mut candidates = vec![0; admitted.candidate_cells()];
        let first = 7;
        let first_report = count_matching_lines(
            &automaton,
            haystack,
            admitted,
            first,
            &mut line_state,
            &mut generations,
            &mut candidates,
        )
        .unwrap();
        let second_first = first + admitted.required_generations();
        let second_report = count_matching_lines(
            &automaton,
            haystack,
            admitted,
            second_first,
            &mut line_state,
            &mut generations,
            &mut candidates,
        )
        .unwrap();
        assert_eq!(first_report.matched(), second_report.matched());
        assert_eq!(first_report.actual(), second_report.actual());
    }

    #[test]
    fn every_preflight_refusal_precedes_observation() {
        let automaton = literal(b'a');
        let haystack = b"a\n";
        let admitted = prospective(&automaton, haystack.len()).unwrap();
        let mut line_state = vec![0; admitted.line_state_cells() - 1];
        let mut generations = vec![0; admitted.generation_cells()];
        let mut candidates = vec![0; admitted.candidate_cells()];
        let observations = Cell::new(0usize);
        let error = count_matching_lines_with_observer(
            &automaton,
            haystack,
            admitted,
            1,
            &mut line_state,
            &mut generations,
            &mut candidates,
            |_| {
                observations.set(observations.get() + 1);
                Ok::<(), ()>(())
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            GrepStreamObservedError::Execution {
                error: GrepStreamError::WorkspaceShape {
                    storage: "line state",
                    ..
                },
                ..
            }
        ));
        assert_eq!(observations.get(), 0);
        assert!(generations.iter().all(|&generation| generation == 0));

        let mut wrong = admitted;
        wrong.output_events -= 1;
        let mut exact_line_state = vec![0; admitted.line_state_cells()];
        let error = count_matching_lines(
            &automaton,
            haystack,
            wrong,
            1,
            &mut exact_line_state,
            &mut generations,
            &mut candidates,
        )
        .unwrap_err();
        assert!(matches!(error, GrepStreamError::AdmissionMismatch));
        assert!(generations.iter().all(|&generation| generation == 0));

        let error = count_matching_lines(
            &automaton,
            haystack,
            admitted,
            0,
            &mut exact_line_state,
            &mut generations,
            &mut candidates,
        )
        .unwrap_err();
        assert!(matches!(error, GrepStreamError::GenerationRange { .. }));
        assert!(generations.iter().all(|&generation| generation == 0));
    }

    #[test]
    fn observer_failure_returns_exact_terminal_prefix() {
        let automaton = literal(b'a');
        let haystack = b"a\na\na";
        let admitted = prospective(&automaton, haystack.len()).unwrap();
        let mut line_state = vec![0; admitted.line_state_cells()];
        let mut generations = vec![0; admitted.generation_cells()];
        let mut candidates = vec![0; admitted.candidate_cells()];
        let error = count_matching_lines_with_observer(
            &automaton,
            haystack,
            admitted,
            1,
            &mut line_state,
            &mut generations,
            &mut candidates,
            |matched| {
                if matched.ordinal() == 1 {
                    Err("stop")
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
        match error {
            GrepStreamObservedError::Observer { error, partial } => {
                assert_eq!(error, "stop");
                assert_eq!(partial.line_domains(), 2);
                assert_eq!(partial.output_events(), 2);
                assert_eq!(partial.domains_examined(), 2);
            }
            GrepStreamObservedError::Execution { error, .. } => {
                panic!("unexpected execution error: {error}")
            }
        }
    }
}
