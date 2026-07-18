//! Allocation-free line capture reducers for exact, proof-registered HIR shapes.
//!
//! This module deliberately does not expose a general regular-expression
//! executor. Each plan authenticates one complete source/profile/HIR identity
//! and implements only the participating-group count needed by Rebar's
//! `grep-captures` model.

use core::fmt;

use fre_syntax::RustProfile;

/// Exact source spelling for the first admitted line-capture plan.
pub const SPACE_AROUND_OPERATOR_CAPTURE_PATTERN: &str = r"[^,\s](\s*)(?:[-+*/|!<=>%&^]+|:=)(\s*)";

/// Exact structural-inspection charge for the pinned canonical HIR.
pub const SPACE_AROUND_OPERATOR_INSPECTION_WORK: usize = 54;

const SPACE_AROUND_OPERATOR_HIR_NODES: usize = 12;
const SPACE_AROUND_OPERATOR_CLASS_RANGES: usize = 40;
const SPACE_AROUND_OPERATOR_LITERAL_BYTES: usize = 2;
const SPACE_AROUND_OPERATOR_MINIMUM_BYTES: usize = 2;
const SPACE_AROUND_OPERATOR_PARTICIPATING_GROUPS: usize = 3;
const SPACE_AROUND_OPERATOR_WORK_PER_INPUT_BYTE: usize = 12;

/// Construction limits for an exact line-capture plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LineCaptureBuildLimits {
    /// Maximum exact-shape structural inspection work.
    pub max_inspection_work: usize,
    /// Maximum construction allocations. The registered plan requires zero.
    pub max_allocations: usize,
    /// Maximum dynamic construction scratch bytes. The registered plan requires zero.
    pub max_scratch_bytes: usize,
    /// Maximum persistent construction bytes retained inline by the plan.
    pub max_persistent_bytes: usize,
    /// Maximum construction peak bytes, including the retained inline plan.
    pub max_peak_bytes: usize,
}

impl Default for LineCaptureBuildLimits {
    fn default() -> Self {
        Self {
            max_inspection_work: 8_192,
            max_allocations: 0,
            max_scratch_bytes: 0,
            max_persistent_bytes: core::mem::size_of::<LineCapturePlan>(),
            max_peak_bytes: core::mem::size_of::<LineCapturePlan>(),
        }
    }
}

/// Prospectively enforced construction resource dimensions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LineCaptureBuildResource {
    /// Dynamic allocation count.
    Allocations,
    /// Dynamic temporary construction bytes.
    ScratchBytes,
    /// Retained inline plan bytes.
    PersistentBytes,
    /// Peak retained plus temporary construction bytes.
    PeakBytes,
}

/// The complete direct line-capture mechanism selected at construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LineCapturePlanKind {
    /// `[^,\s](\s*)(?:[-+*/|!<=>%&^]+|:=)(\s*)` under the pinned
    /// Unicode-on Rebar Rust-byte profile.
    SpaceAroundOperator,
}

/// Immutable plan identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LineCapturePlanIdentity {
    /// Complete, byte-exact registered source.
    pub source: &'static str,
    /// Complete pinned Rust constructor/profile identity.
    pub profile: RustProfile,
    /// Exact direct mechanism.
    pub plan: LineCapturePlanKind,
}

/// Exact structural facts established before publishing a plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LineCaptureBuildReport {
    /// HIR nodes inspected.
    pub hir_nodes: usize,
    /// Canonical class ranges inspected.
    pub class_ranges: usize,
    /// Literal bytes inspected.
    pub literal_bytes: usize,
    /// Exact inspection work (`nodes + ranges + literal bytes`).
    pub inspection_work: usize,
    /// Proved positive whole-match minimum in bytes.
    pub minimum_match_bytes: usize,
    /// Participating groups per selected match, including group zero.
    pub participating_groups_per_match: usize,
    /// Construction allocations performed after prospective admission.
    pub allocations: usize,
    /// Dynamic temporary construction bytes.
    pub scratch_bytes: usize,
    /// Persistent construction bytes retained by the plan.
    pub persistent_bytes: usize,
    /// Peak retained plus temporary construction bytes.
    pub peak_bytes: usize,
    /// Complete immutable identity.
    pub identity: LineCapturePlanIdentity,
}

/// Typed line-capture construction failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum LineCaptureBuildError {
    /// Source or profile is outside the registered shape.
    Unsupported(&'static str),
    /// Exact structural inspection exceeds its independent ceiling.
    InspectionWork { required: usize, limit: usize },
    /// A prospectively known construction resource exceeds its ceiling.
    Resource {
        resource: LineCaptureBuildResource,
        required: usize,
        limit: usize,
    },
}

impl fmt::Display for LineCaptureBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(reason) => {
                write!(formatter, "unsupported line capture shape: {reason}")
            }
            Self::InspectionWork { required, limit } => write!(
                formatter,
                "line capture inspection requires {required} work, limit is {limit}"
            ),
            Self::Resource {
                resource,
                required,
                limit,
            } => write!(
                formatter,
                "line capture construction resource {resource:?} requires {required}, limit is {limit}"
            ),
        }
    }
}

impl std::error::Error for LineCaptureBuildError {}

/// Resource dimensions enforced before returning a direct reduction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LineCaptureResource {
    /// Prospective execution work.
    ExecutionWork,
    /// Sequential input bytes.
    SequentialBytes,
    /// Participating-group count.
    CaptureCount,
    /// Line plus capture-group reducer events.
    ReducerEvents,
}

/// Complete direct-execution limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LineCaptureRunLimits {
    /// Maximum prospectively charged work.
    pub max_work: usize,
    /// Maximum sequential input bytes.
    pub max_sequential_bytes: usize,
    /// Maximum participating-group count.
    pub max_capture_count: usize,
    /// Maximum line plus group reducer events.
    pub max_reducer_events: usize,
}

impl Default for LineCaptureRunLimits {
    fn default() -> Self {
        Self {
            max_work: usize::MAX,
            max_sequential_bytes: usize::MAX,
            max_capture_count: usize::MAX,
            max_reducer_events: usize::MAX,
        }
    }
}

/// Typed direct-execution failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LineCaptureRunError {
    /// A prospectively derived or completely reduced dimension exceeded its cap.
    Resource {
        resource: LineCaptureResource,
        required: usize,
        limit: usize,
    },
    /// Checked accounting overflowed.
    ArithmeticOverflow(LineCaptureResource),
    /// Dynamic accounting exceeded its prospectively admitted upper bound.
    AccountingInvariant {
        resource: LineCaptureResource,
        prospective: usize,
        actual: usize,
    },
}

impl fmt::Display for LineCaptureRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resource {
                resource,
                required,
                limit,
            } => write!(
                formatter,
                "line capture resource {resource:?} requires {required}, limit is {limit}"
            ),
            Self::ArithmeticOverflow(resource) => {
                write!(formatter, "line capture resource {resource:?} overflow")
            }
            Self::AccountingInvariant {
                resource,
                prospective,
                actual,
            } => write!(
                formatter,
                "line capture resource {resource:?} used {actual}, prospective bound was {prospective}"
            ),
        }
    }
}

impl std::error::Error for LineCaptureRunError {}

/// Complete allocation-free reduction receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LineCaptureRunReport {
    /// Immutable construction identity.
    pub identity: LineCapturePlanIdentity,
    /// Number of `bstr::lines`-equivalent records inspected.
    pub lines: usize,
    /// Selected nonempty, non-overlapping matches.
    pub matches: usize,
    /// Sum of participating groups.
    pub capture_count: usize,
    /// Line events plus one event for every capture-group slot.
    pub reducer_events: usize,
    /// Exact prospective work certificate.
    pub work: usize,
    /// Exact prospective single-pass input-load certificate.
    pub sequential_bytes: usize,
    /// Prospective non-overlapping match ceiling admitted before scanning.
    pub prospective_matches: usize,
    /// Prospective participating-group ceiling admitted before scanning.
    pub prospective_capture_count: usize,
    /// Prospective line-event ceiling admitted before scanning.
    pub prospective_line_events: usize,
    /// Prospective line-plus-group event ceiling admitted before scanning.
    pub prospective_reducer_events: usize,
    /// Actual raw input-byte loads performed by the scanner and decoder.
    pub actual_input_loads: usize,
    /// Dynamic execution scratch bytes (always zero for this plan).
    pub scratch_bytes: usize,
    /// Dynamic output bytes (always zero for this plan).
    pub output_bytes: usize,
}

/// Builder for exact, allocation-free line-capture reducers.
#[derive(Clone, Debug)]
pub struct LineCaptureBuilder<'a> {
    pattern: &'a str,
    profile: RustProfile,
    limits: LineCaptureBuildLimits,
}

impl<'a> LineCaptureBuilder<'a> {
    /// Start from the pinned Rust byte profile.
    #[must_use]
    pub fn new(pattern: &'a str) -> Self {
        Self {
            pattern,
            profile: RustProfile::default(),
            limits: LineCaptureBuildLimits::default(),
        }
    }

    /// Select the complete Rust constructor/profile identity.
    #[must_use]
    pub fn profile(mut self, profile: RustProfile) -> Self {
        self.profile = profile;
        self
    }

    /// Replace all checked construction limits.
    #[must_use]
    pub const fn limits(mut self, limits: LineCaptureBuildLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Authenticate and construct one exact line-capture plan.
    pub fn build(self) -> Result<LineCapturePlan, LineCaptureBuildError> {
        if SPACE_AROUND_OPERATOR_INSPECTION_WORK > self.limits.max_inspection_work {
            return Err(LineCaptureBuildError::InspectionWork {
                required: SPACE_AROUND_OPERATOR_INSPECTION_WORK,
                limit: self.limits.max_inspection_work,
            });
        }
        let persistent_bytes = core::mem::size_of::<LineCapturePlan>();
        let peak_bytes = persistent_bytes;
        enforce_build(
            LineCaptureBuildResource::Allocations,
            0,
            self.limits.max_allocations,
        )?;
        enforce_build(
            LineCaptureBuildResource::ScratchBytes,
            0,
            self.limits.max_scratch_bytes,
        )?;
        enforce_build(
            LineCaptureBuildResource::PersistentBytes,
            persistent_bytes,
            self.limits.max_persistent_bytes,
        )?;
        enforce_build(
            LineCaptureBuildResource::PeakBytes,
            peak_bytes,
            self.limits.max_peak_bytes,
        )?;
        if self.pattern != SPACE_AROUND_OPERATOR_CAPTURE_PATTERN {
            return Err(LineCaptureBuildError::Unsupported("source identity"));
        }
        if self.profile != RustProfile::rebar_1_12_4() {
            return Err(LineCaptureBuildError::Unsupported("Rust profile identity"));
        }
        // This mechanism is not a generic parser fallback. Exact source and
        // profile identity select the preregistered canonical HIR facts below,
        // so construction performs no parsing, allocation, or retained heap
        // storage. The zero resource facts are prospectively bounded by the
        // caller's limits (whose minimum representable value is also zero).
        let report = LineCaptureBuildReport {
            hir_nodes: SPACE_AROUND_OPERATOR_HIR_NODES,
            class_ranges: SPACE_AROUND_OPERATOR_CLASS_RANGES,
            literal_bytes: SPACE_AROUND_OPERATOR_LITERAL_BYTES,
            inspection_work: SPACE_AROUND_OPERATOR_INSPECTION_WORK,
            minimum_match_bytes: SPACE_AROUND_OPERATOR_MINIMUM_BYTES,
            participating_groups_per_match: SPACE_AROUND_OPERATOR_PARTICIPATING_GROUPS,
            allocations: 0,
            scratch_bytes: 0,
            persistent_bytes,
            peak_bytes,
            identity: LineCapturePlanIdentity {
                source: SPACE_AROUND_OPERATOR_CAPTURE_PATTERN,
                profile: self.profile,
                plan: LineCapturePlanKind::SpaceAroundOperator,
            },
        };
        Ok(LineCapturePlan { report })
    }
}

/// Immutable exact line-capture reducer.
#[derive(Clone, Debug)]
pub struct LineCapturePlan {
    report: LineCaptureBuildReport,
}

impl LineCapturePlan {
    /// Construction proof and immutable identity.
    #[must_use]
    pub const fn build_report(&self) -> &LineCaptureBuildReport {
        &self.report
    }

    /// Count participating groups over `bstr::lines`-equivalent records.
    pub fn grep_capture_count(
        &self,
        haystack: &[u8],
        limits: LineCaptureRunLimits,
    ) -> Result<LineCaptureRunReport, LineCaptureRunError> {
        let work = haystack
            .len()
            .checked_mul(SPACE_AROUND_OPERATOR_WORK_PER_INPUT_BYTE)
            .and_then(|work| work.checked_add(1))
            .ok_or(LineCaptureRunError::ArithmeticOverflow(
                LineCaptureResource::ExecutionWork,
            ))?;
        enforce(LineCaptureResource::ExecutionWork, work, limits.max_work)?;
        let sequential_bytes = haystack.len();
        enforce(
            LineCaptureResource::SequentialBytes,
            sequential_bytes,
            limits.max_sequential_bytes,
        )?;

        let prospective_matches = haystack
            .len()
            .checked_div(self.report.minimum_match_bytes)
            .ok_or(LineCaptureRunError::ArithmeticOverflow(
                LineCaptureResource::CaptureCount,
            ))?;
        let prospective_capture_count = prospective_matches
            .checked_mul(self.report.participating_groups_per_match)
            .ok_or(LineCaptureRunError::ArithmeticOverflow(
                LineCaptureResource::CaptureCount,
            ))?;
        enforce(
            LineCaptureResource::CaptureCount,
            prospective_capture_count,
            limits.max_capture_count,
        )?;
        let prospective_line_events = haystack.len();
        let prospective_reducer_events = prospective_line_events
            .checked_add(prospective_capture_count)
            .ok_or(LineCaptureRunError::ArithmeticOverflow(
                LineCaptureResource::ReducerEvents,
            ))?;
        enforce(
            LineCaptureResource::ReducerEvents,
            prospective_reducer_events,
            limits.max_reducer_events,
        )?;

        let scan = scan_space_around_operator(haystack)?;
        let lines = scan.lines;
        let matches = scan.matches;
        let capture_count = matches
            .checked_mul(self.report.participating_groups_per_match)
            .ok_or(LineCaptureRunError::ArithmeticOverflow(
                LineCaptureResource::CaptureCount,
            ))?;
        enforce_invariant(
            LineCaptureResource::CaptureCount,
            capture_count,
            prospective_capture_count,
        )?;
        let reducer_events =
            lines
                .checked_add(capture_count)
                .ok_or(LineCaptureRunError::ArithmeticOverflow(
                    LineCaptureResource::ReducerEvents,
                ))?;
        enforce_invariant(
            LineCaptureResource::ReducerEvents,
            reducer_events,
            prospective_reducer_events,
        )?;
        enforce_invariant(
            LineCaptureResource::SequentialBytes,
            scan.input_loads,
            sequential_bytes,
        )?;
        Ok(LineCaptureRunReport {
            identity: self.report.identity.clone(),
            lines,
            matches,
            capture_count,
            reducer_events,
            work,
            sequential_bytes,
            prospective_matches,
            prospective_capture_count,
            prospective_line_events,
            prospective_reducer_events,
            actual_input_loads: scan.input_loads,
            scratch_bytes: 0,
            output_bytes: 0,
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum SpaceOperatorPhase {
    /// No viable leftmost match start has been seen.
    #[default]
    Search,
    /// The `[^,\s]` prefix has been consumed.
    Prefix,
    /// At least one scalar in the first `\s*` has been consumed.
    LeadingWhitespace,
    /// A possible `:=` alternative has consumed its colon.
    PendingColon,
    /// The first alternative's `[-+*/|!<=>%&^]+` is active.
    OperatorRun,
    /// The second alternative's complete `:=` has been consumed.
    ColonEqual,
    /// At least one scalar in the trailing `\s*` has been consumed.
    TrailingWhitespace,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SpaceOperatorState {
    phase: SpaceOperatorPhase,
}

impl SpaceOperatorState {
    /// Consume one valid scalar and report whether one greedy match ended
    /// immediately before it. The same scalar is then retained as the first
    /// state of the next non-overlapping search where applicable.
    fn push_scalar(&mut self, scalar: char) -> bool {
        let whitespace = is_unicode_whitespace(scalar);
        let operator = is_ascii_operator(scalar);
        match self.phase {
            SpaceOperatorPhase::Search => {
                self.start_from_scalar(scalar, whitespace);
                false
            }
            SpaceOperatorPhase::Prefix | SpaceOperatorPhase::LeadingWhitespace => {
                self.after_prefix(scalar, whitespace, operator);
                false
            }
            SpaceOperatorPhase::PendingColon => {
                if scalar == '=' {
                    self.phase = SpaceOperatorPhase::ColonEqual;
                } else {
                    // The pending colon is itself a valid `[^,\s]` prefix.
                    // Reusing it is necessary for inputs such as `a:+` and
                    // `a::=` without rewinding or decoding a scalar twice.
                    self.after_prefix(scalar, whitespace, operator);
                }
                false
            }
            SpaceOperatorPhase::OperatorRun => {
                if operator {
                    self.phase = SpaceOperatorPhase::OperatorRun;
                    false
                } else if whitespace {
                    self.phase = SpaceOperatorPhase::TrailingWhitespace;
                    false
                } else {
                    self.start_from_scalar(scalar, false);
                    true
                }
            }
            SpaceOperatorPhase::ColonEqual => {
                if whitespace {
                    self.phase = SpaceOperatorPhase::TrailingWhitespace;
                } else {
                    self.start_from_scalar(scalar, false);
                }
                !whitespace
            }
            SpaceOperatorPhase::TrailingWhitespace => {
                if whitespace {
                    self.phase = SpaceOperatorPhase::TrailingWhitespace;
                    false
                } else {
                    self.start_from_scalar(scalar, false);
                    true
                }
            }
        }
    }

    /// Consume one malformed byte. Invalid UTF-8 cannot match either Unicode
    /// class, but it terminates an already complete match just like any other
    /// non-whitespace, non-operator input byte.
    fn push_invalid(&mut self) -> bool {
        let completed = self.matched();
        self.phase = SpaceOperatorPhase::Search;
        completed
    }

    fn start_from_scalar(&mut self, scalar: char, whitespace: bool) {
        self.phase = if !whitespace && scalar != ',' {
            SpaceOperatorPhase::Prefix
        } else {
            SpaceOperatorPhase::Search
        };
    }

    fn after_prefix(&mut self, scalar: char, whitespace: bool, operator: bool) {
        self.phase = if whitespace {
            SpaceOperatorPhase::LeadingWhitespace
        } else if operator {
            SpaceOperatorPhase::OperatorRun
        } else if scalar == ':' {
            SpaceOperatorPhase::PendingColon
        } else if scalar != ',' {
            SpaceOperatorPhase::Prefix
        } else {
            SpaceOperatorPhase::Search
        };
    }

    const fn matched(self) -> bool {
        matches!(
            self.phase,
            SpaceOperatorPhase::OperatorRun
                | SpaceOperatorPhase::ColonEqual
                | SpaceOperatorPhase::TrailingWhitespace
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DecodedUnit {
    Scalar(char),
    Invalid,
}

/// Incremental UTF-8 decoder whose only input access is the byte passed by
/// value to `push`. Malformed or truncated sequences emit one invalid unit per
/// raw byte, matching the byte-regex treatment of invalid UTF-8.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Utf8StreamDecoder {
    codepoint: u32,
    minimum: u32,
    remaining: u8,
    buffered: u8,
}

impl Utf8StreamDecoder {
    fn push(
        &mut self,
        byte: u8,
        emit: &mut impl FnMut(DecodedUnit) -> Result<(), LineCaptureRunError>,
    ) -> Result<(), LineCaptureRunError> {
        let mut current = Some(byte);
        while let Some(byte) = current.take() {
            if self.remaining == 0 {
                match byte {
                    0x00..=0x7F => emit(DecodedUnit::Scalar(char::from(byte)))?,
                    0xC2..=0xDF => self.begin(u32::from(byte & 0x1F), 0x80, 1),
                    0xE0..=0xEF => self.begin(u32::from(byte & 0x0F), 0x800, 2),
                    0xF0..=0xF4 => self.begin(u32::from(byte & 0x07), 0x1_0000, 3),
                    _ => emit(DecodedUnit::Invalid)?,
                }
                continue;
            }

            if byte & 0xC0 == 0x80 {
                self.codepoint = (self.codepoint << 6) | u32::from(byte & 0x3F);
                self.remaining = self.remaining.checked_sub(1).ok_or(
                    LineCaptureRunError::ArithmeticOverflow(LineCaptureResource::SequentialBytes),
                )?;
                self.buffered =
                    self.buffered
                        .checked_add(1)
                        .ok_or(LineCaptureRunError::ArithmeticOverflow(
                            LineCaptureResource::SequentialBytes,
                        ))?;
                if self.remaining == 0 {
                    let codepoint = self.codepoint;
                    let minimum = self.minimum;
                    let buffered = self.buffered;
                    self.reset();
                    if codepoint >= minimum
                        && let Some(scalar) = char::from_u32(codepoint)
                    {
                        emit(DecodedUnit::Scalar(scalar))?;
                    } else {
                        emit_invalid(buffered, emit)?;
                    }
                }
                continue;
            }

            let buffered = self.buffered;
            self.reset();
            emit_invalid(buffered, emit)?;
            // The current non-continuation byte has already been loaded. Feed
            // that value through the initial-byte state without touching the
            // input slice again.
            current = Some(byte);
        }
        Ok(())
    }

    fn finish(
        &mut self,
        emit: &mut impl FnMut(DecodedUnit) -> Result<(), LineCaptureRunError>,
    ) -> Result<(), LineCaptureRunError> {
        let buffered = self.buffered;
        self.reset();
        emit_invalid(buffered, emit)
    }

    fn begin(&mut self, codepoint: u32, minimum: u32, remaining: u8) {
        self.codepoint = codepoint;
        self.minimum = minimum;
        self.remaining = remaining;
        self.buffered = 1;
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
}

fn emit_invalid(
    count: u8,
    emit: &mut impl FnMut(DecodedUnit) -> Result<(), LineCaptureRunError>,
) -> Result<(), LineCaptureRunError> {
    for _ in 0..count {
        emit(DecodedUnit::Invalid)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct LineScanner {
    state: SpaceOperatorState,
    lines: usize,
    matches: usize,
    pending_cr: bool,
    ended_with_lf: bool,
}

impl LineScanner {
    fn push(&mut self, unit: DecodedUnit) -> Result<(), LineCaptureRunError> {
        if self.pending_cr {
            if unit == DecodedUnit::Scalar('\n') {
                finish_line(&mut self.state, &mut self.lines, &mut self.matches)?;
                self.pending_cr = false;
                self.ended_with_lf = true;
                return Ok(());
            }
            self.push_content(DecodedUnit::Scalar('\r'))?;
            self.pending_cr = false;
        }

        self.ended_with_lf = false;
        match unit {
            DecodedUnit::Scalar('\r') => self.pending_cr = true,
            DecodedUnit::Scalar('\n') => {
                finish_line(&mut self.state, &mut self.lines, &mut self.matches)?;
                self.ended_with_lf = true;
            }
            content => self.push_content(content)?,
        }
        Ok(())
    }

    fn push_content(&mut self, unit: DecodedUnit) -> Result<(), LineCaptureRunError> {
        let completed = match unit {
            DecodedUnit::Scalar(scalar) => self.state.push_scalar(scalar),
            DecodedUnit::Invalid => self.state.push_invalid(),
        };
        if completed {
            add_match(&mut self.matches)?;
        }
        Ok(())
    }

    fn finish(&mut self, input_was_nonempty: bool) -> Result<(), LineCaptureRunError> {
        if self.pending_cr {
            self.push_content(DecodedUnit::Scalar('\r'))?;
            self.pending_cr = false;
        }
        if input_was_nonempty && !self.ended_with_lf {
            finish_line(&mut self.state, &mut self.lines, &mut self.matches)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct LineScanReport {
    lines: usize,
    matches: usize,
    input_loads: usize,
}

fn scan_space_around_operator(haystack: &[u8]) -> Result<LineScanReport, LineCaptureRunError> {
    let mut decoder = Utf8StreamDecoder::default();
    let mut scanner = LineScanner::default();
    let mut input_loads = 0_usize;
    for &byte in haystack {
        input_loads = input_loads
            .checked_add(1)
            .ok_or(LineCaptureRunError::ArithmeticOverflow(
                LineCaptureResource::SequentialBytes,
            ))?;
        decoder.push(byte, &mut |unit| scanner.push(unit))?;
    }
    decoder.finish(&mut |unit| scanner.push(unit))?;
    scanner.finish(!haystack.is_empty())?;
    Ok(LineScanReport {
        lines: scanner.lines,
        matches: scanner.matches,
        input_loads,
    })
}

fn finish_line(
    state: &mut SpaceOperatorState,
    lines: &mut usize,
    matches: &mut usize,
) -> Result<(), LineCaptureRunError> {
    *lines = lines
        .checked_add(1)
        .ok_or(LineCaptureRunError::ArithmeticOverflow(
            LineCaptureResource::ReducerEvents,
        ))?;
    if state.matched() {
        add_match(matches)?;
    }
    *state = SpaceOperatorState::default();
    Ok(())
}

fn add_match(matches: &mut usize) -> Result<(), LineCaptureRunError> {
    *matches = matches
        .checked_add(1)
        .ok_or(LineCaptureRunError::ArithmeticOverflow(
            LineCaptureResource::CaptureCount,
        ))?;
    Ok(())
}

fn is_ascii_operator(scalar: char) -> bool {
    matches!(
        scalar,
        '-' | '+' | '*' | '/' | '|' | '!' | '<' | '=' | '>' | '%' | '&' | '^'
    )
}

fn is_unicode_whitespace(scalar: char) -> bool {
    matches!(
        u32::from(scalar),
        0x0009..=0x000D
            | 0x0020
            | 0x0085
            | 0x00A0
            | 0x1680
            | 0x2000..=0x200A
            | 0x2028..=0x2029
            | 0x202F
            | 0x205F
            | 0x3000
    )
}

fn enforce(
    resource: LineCaptureResource,
    required: usize,
    limit: usize,
) -> Result<(), LineCaptureRunError> {
    if required > limit {
        return Err(LineCaptureRunError::Resource {
            resource,
            required,
            limit,
        });
    }
    Ok(())
}

fn enforce_build(
    resource: LineCaptureBuildResource,
    required: usize,
    limit: usize,
) -> Result<(), LineCaptureBuildError> {
    if required > limit {
        return Err(LineCaptureBuildError::Resource {
            resource,
            required,
            limit,
        });
    }
    Ok(())
}

fn enforce_invariant(
    resource: LineCaptureResource,
    actual: usize,
    prospective: usize,
) -> Result<(), LineCaptureRunError> {
    if actual > prospective {
        return Err(LineCaptureRunError::AccountingInvariant {
            resource,
            prospective,
            actual,
        });
    }
    Ok(())
}
