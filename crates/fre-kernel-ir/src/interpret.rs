use crate::{
    ArithmeticSite, BlockId, BlockOp, DataBlob, ExecuteError, MatchSpan, Operation, SearchWindow,
    ValidatedProgram,
};

/// Runtime work budget for the safe portable semantic oracle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionLimits {
    pub max_work: u64,
}

impl ExecutionLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self { max_work: u64::MAX }
    }
}

impl Default for ExecutionLimits {
    fn default() -> Self {
        Self {
            max_work: 100_000_000,
        }
    }
}

/// Typed oracle output plus its exact charged work.
#[derive(Debug, Eq, PartialEq)]
pub struct ExecutionReport<T> {
    output: T,
    work: u64,
}

impl<T> ExecutionReport<T> {
    #[must_use]
    pub const fn output(&self) -> &T {
        &self.output
    }

    #[must_use]
    pub const fn work(&self) -> u64 {
        self.work
    }

    #[must_use]
    pub fn into_output(self) -> T {
        self.output
    }
}

impl<O: Operation> ValidatedProgram<O> {
    /// Execute the safe portable oracle. Native backends must differential-test
    /// against this result but must not dispatch through this interpreter.
    pub fn execute(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: ExecutionLimits,
    ) -> Result<ExecutionReport<O::Output>, ExecuteError> {
        if !window.validate(haystack.len()) {
            return Err(ExecuteError::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len: haystack.len(),
            });
        }
        let mut machine = Machine {
            program: self,
            haystack,
            window,
            pc: self.raw.entry,
            state: State::Initial,
            meter: WorkMeter::new(limits.max_work),
        };
        let found = machine.run()?;
        Ok(ExecutionReport {
            output: O::project(found),
            work: machine.meter.consumed,
        })
    }
}

#[derive(Clone, Copy, Debug)]
enum State {
    Initial,
    Cursor(usize),
    Run { start: usize, end: usize },
    Match(MatchSpan),
    Exhausted,
    Rejected { resume: usize },
}

struct Machine<'a, O: Operation> {
    program: &'a ValidatedProgram<O>,
    haystack: &'a [u8],
    window: SearchWindow,
    pc: BlockId,
    state: State,
    meter: WorkMeter,
}

impl<O: Operation> Machine<'_, O> {
    fn run(&mut self) -> Result<Option<MatchSpan>, ExecuteError> {
        loop {
            self.meter.tick()?;
            if let Control::Return(found) = self.step()? {
                return Ok(found);
            }
        }
    }

    fn step(&mut self) -> Result<Control, ExecuteError> {
        let index = usize::try_from(self.pc.0).map_err(|_| self.invariant())?;
        let op = self
            .program
            .raw
            .blocks
            .get(index)
            .ok_or_else(|| self.invariant())?
            .op
            .clone();
        match op {
            BlockOp::Entry { next } => {
                if !matches!(self.state, State::Initial) {
                    return Err(self.invariant());
                }
                self.state = State::Cursor(self.window.start());
                self.pc = next;
            }
            BlockOp::ScanLiteral {
                needle,
                anchors,
                matched,
                exhausted,
            } => self.scan_literal(needle.0, anchors, matched, exhausted)?,
            BlockOp::ScanClassStart {
                class,
                anchored_start,
                run,
                exhausted,
            } => self.scan_class(class.0, anchored_start, run, exhausted)?,
            BlockOp::ExtendClassRun { class, next } => self.extend_class(class.0, next)?,
            BlockOp::ConfirmSuffix {
                suffix,
                anchored_end,
                matched,
                rejected,
            } => self.confirm_suffix(suffix.0, anchored_end, matched, rejected)?,
            BlockOp::AdvanceAfterReject { next } => {
                let State::Rejected { resume } = self.state else {
                    return Err(self.invariant());
                };
                self.state = State::Cursor(resume);
                self.pc = next;
            }
            BlockOp::ReturnFound => {
                let State::Match(span) = self.state else {
                    return Err(self.invariant());
                };
                return Ok(Control::Return(Some(span)));
            }
            BlockOp::ReturnNone => {
                if !matches!(self.state, State::Exhausted) {
                    return Err(self.invariant());
                }
                return Ok(Control::Return(None));
            }
        }
        Ok(Control::Continue)
    }

    fn scan_literal(
        &mut self,
        needle: u32,
        anchors: crate::AnchorFlags,
        matched: BlockId,
        exhausted: BlockId,
    ) -> Result<(), ExecuteError> {
        let State::Cursor(cursor) = self.state else {
            return Err(self.invariant());
        };
        let needle = program_bytes(self.program, needle, self.pc)?;
        if let Some(span) = find_literal(
            self.haystack,
            self.window,
            cursor,
            needle,
            anchors,
            &mut self.meter,
        )? {
            self.state = State::Match(span);
            self.pc = matched;
        } else {
            self.state = State::Exhausted;
            self.pc = exhausted;
        }
        Ok(())
    }

    fn scan_class(
        &mut self,
        class: u32,
        anchored_start: bool,
        run: BlockId,
        exhausted: BlockId,
    ) -> Result<(), ExecuteError> {
        let State::Cursor(cursor) = self.state else {
            return Err(self.invariant());
        };
        let class = self.class(class)?;
        if let Some(start) = find_class_start(
            self.haystack,
            self.window,
            cursor,
            class,
            anchored_start,
            &mut self.meter,
        )? {
            let end = start
                .checked_add(1)
                .ok_or(ExecuteError::ArithmeticOverflow {
                    site: ArithmeticSite::SearchPosition,
                })?;
            self.state = State::Run { start, end };
            self.pc = run;
        } else {
            self.state = State::Exhausted;
            self.pc = exhausted;
        }
        Ok(())
    }

    fn extend_class(&mut self, class: u32, next: BlockId) -> Result<(), ExecuteError> {
        let State::Run { start, mut end } = self.state else {
            return Err(self.invariant());
        };
        let class = self.class(class)?;
        while end < self.window.end() {
            self.meter.tick()?;
            if !class.contains(self.haystack[end]) {
                break;
            }
            end = end.checked_add(1).ok_or(ExecuteError::ArithmeticOverflow {
                site: ArithmeticSite::SearchPosition,
            })?;
        }
        self.state = State::Run { start, end };
        self.pc = next;
        Ok(())
    }

    fn confirm_suffix(
        &mut self,
        suffix: u32,
        anchored_end: bool,
        matched: BlockId,
        rejected: BlockId,
    ) -> Result<(), ExecuteError> {
        let State::Run { start, end } = self.state else {
            return Err(self.invariant());
        };
        let suffix = program_bytes(self.program, suffix, self.pc)?;
        if matches_at(self.haystack, self.window, end, suffix, &mut self.meter)? {
            let match_end =
                end.checked_add(suffix.len())
                    .ok_or(ExecuteError::ArithmeticOverflow {
                        site: ArithmeticSite::SearchPosition,
                    })?;
            if !anchored_end || match_end == self.haystack.len() {
                self.state = State::Match(MatchSpan::new(start, match_end));
                self.pc = matched;
                return Ok(());
            }
        }
        self.state = State::Rejected { resume: end };
        self.pc = rejected;
        Ok(())
    }

    fn class(&self, id: u32) -> Result<crate::ByteClass, ExecuteError> {
        let index = usize::try_from(id).map_err(|_| self.invariant())?;
        match self.program.raw.data.get(index) {
            Some(DataBlob::ByteClass(class)) => Ok(*class),
            _ => Err(self.invariant()),
        }
    }

    const fn invariant(&self) -> ExecuteError {
        ExecuteError::InternalInvariant { block: self.pc.0 }
    }
}

#[derive(Clone, Copy)]
enum Control {
    Continue,
    Return(Option<MatchSpan>),
}

fn program_bytes<O: Operation>(
    program: &ValidatedProgram<O>,
    id: u32,
    block: BlockId,
) -> Result<&[u8], ExecuteError> {
    let index =
        usize::try_from(id).map_err(|_| ExecuteError::InternalInvariant { block: block.0 })?;
    match program.raw.data.get(index) {
        Some(DataBlob::Bytes(bytes)) => Ok(bytes),
        _ => Err(ExecuteError::InternalInvariant { block: block.0 }),
    }
}

#[derive(Clone, Copy)]
struct WorkMeter {
    limit: u64,
    consumed: u64,
}

impl WorkMeter {
    const fn new(limit: u64) -> Self {
        Self { limit, consumed: 0 }
    }

    fn tick(&mut self) -> Result<(), ExecuteError> {
        if self.consumed == self.limit {
            return Err(ExecuteError::WorkLimitExceeded {
                limit: self.limit,
                consumed: self.consumed,
            });
        }
        self.consumed = self
            .consumed
            .checked_add(1)
            .ok_or(ExecuteError::ArithmeticOverflow {
                site: ArithmeticSite::SearchWorkBound,
            })?;
        Ok(())
    }
}

fn find_literal(
    haystack: &[u8],
    window: SearchWindow,
    cursor: usize,
    needle: &[u8],
    anchors: crate::AnchorFlags,
    meter: &mut WorkMeter,
) -> Result<Option<MatchSpan>, ExecuteError> {
    if anchors.start {
        if cursor != 0 || window.start() != 0 {
            return Ok(None);
        }
        if matches_at(haystack, window, 0, needle, meter)? {
            let end = needle.len();
            if !anchors.end || end == haystack.len() {
                return Ok(Some(MatchSpan::new(0, end)));
            }
        }
        return Ok(None);
    }
    if anchors.end {
        let Some(start) = haystack.len().checked_sub(needle.len()) else {
            return Ok(None);
        };
        if start < cursor || start < window.start() {
            return Ok(None);
        }
        return if matches_at(haystack, window, start, needle, meter)? {
            Ok(Some(MatchSpan::new(start, haystack.len())))
        } else {
            Ok(None)
        };
    }
    let Some(last) = window.end().checked_sub(needle.len()) else {
        return Ok(None);
    };
    let mut candidate = cursor.max(window.start());
    while candidate <= last {
        meter.tick()?;
        if matches_at(haystack, window, candidate, needle, meter)? {
            let end =
                candidate
                    .checked_add(needle.len())
                    .ok_or(ExecuteError::ArithmeticOverflow {
                        site: ArithmeticSite::SearchPosition,
                    })?;
            return Ok(Some(MatchSpan::new(candidate, end)));
        }
        candidate = candidate
            .checked_add(1)
            .ok_or(ExecuteError::ArithmeticOverflow {
                site: ArithmeticSite::SearchPosition,
            })?;
    }
    Ok(None)
}

fn find_class_start(
    haystack: &[u8],
    window: SearchWindow,
    cursor: usize,
    class: crate::ByteClass,
    anchored_start: bool,
    meter: &mut WorkMeter,
) -> Result<Option<usize>, ExecuteError> {
    if anchored_start {
        if cursor != 0 || window.start() != 0 || window.end() == 0 {
            return Ok(None);
        }
        meter.tick()?;
        return Ok(class.contains(haystack[0]).then_some(0));
    }
    let mut position = cursor.max(window.start());
    while position < window.end() {
        meter.tick()?;
        if class.contains(haystack[position]) {
            return Ok(Some(position));
        }
        position = position
            .checked_add(1)
            .ok_or(ExecuteError::ArithmeticOverflow {
                site: ArithmeticSite::SearchPosition,
            })?;
    }
    Ok(None)
}

fn matches_at(
    haystack: &[u8],
    window: SearchWindow,
    start: usize,
    needle: &[u8],
    meter: &mut WorkMeter,
) -> Result<bool, ExecuteError> {
    let Some(end) = start.checked_add(needle.len()) else {
        return Ok(false);
    };
    if start < window.start() || end > window.end() {
        return Ok(false);
    }
    for (offset, expected) in needle.iter().copied().enumerate() {
        meter.tick()?;
        let position = start
            .checked_add(offset)
            .ok_or(ExecuteError::ArithmeticOverflow {
                site: ArithmeticSite::SearchPosition,
            })?;
        if haystack.get(position).copied() != Some(expected) {
            return Ok(false);
        }
    }
    Ok(true)
}
