//! Bounded uniform capture-participation proof paired with general lowering.
//!
//! The proof consumes the same canonical [`RustParsed`] HIR as the selector
//! lowering. It never parses source text or reconstructs selector semantics.

use core::{fmt, num::NonZeroUsize};

use fre_syntax::RustParsed;
use regex_syntax::hir::{Hir, HirKind};

use crate::{LowerError, LowerLimits, LoweredRaw, OperationSemantics, lower_raw_general};

/// Semantic identity of the canonical-HIR uniform-participation theorem.
///
/// Version 1 proves one source-independent participating-user-capture
/// cardinality across captures, concatenation, equal-cardinality
/// alternatives, and repetitions whose participating capture set is stable.
pub const UNIFORM_CAPTURE_PARTICIPATION_ALGORITHM_VERSION: u32 = 1;

/// Exact accounting identity of the uniform-participation theorem.
///
/// Version 1 charges every canonical HIR visit and every child combination,
/// and bounds the combined explicit task/result stack.
pub const UNIFORM_CAPTURE_PARTICIPATION_ACCOUNTING_VERSION: u32 = 1;

/// Stable semantic and accounting identity carried by every positive proof.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UniformCaptureParticipationIdentity {
    algorithm_version: u32,
    accounting_version: u32,
}

impl UniformCaptureParticipationIdentity {
    /// Current identity implemented by this crate.
    #[must_use]
    pub const fn current() -> Self {
        Self {
            algorithm_version: UNIFORM_CAPTURE_PARTICIPATION_ALGORITHM_VERSION,
            accounting_version: UNIFORM_CAPTURE_PARTICIPATION_ACCOUNTING_VERSION,
        }
    }

    #[must_use]
    pub const fn algorithm_version(self) -> u32 {
        self.algorithm_version
    }

    #[must_use]
    pub const fn accounting_version(self) -> u32 {
        self.accounting_version
    }

    /// Whether this identity names the exact theorem in the linked crate.
    #[must_use]
    pub const fn authenticates_current(self) -> bool {
        self.algorithm_version == UNIFORM_CAPTURE_PARTICIPATION_ALGORITHM_VERSION
            && self.accounting_version == UNIFORM_CAPTURE_PARTICIPATION_ACCOUNTING_VERSION
    }
}

/// Independent hard limits for one uniform-participation proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UniformCaptureParticipationLimits {
    /// Maximum exact abstract proof work.
    pub max_work: u64,
    /// Maximum combined explicit task and result stack occupancy.
    pub max_stack_items: usize,
}

impl Default for UniformCaptureParticipationLimits {
    fn default() -> Self {
        Self {
            max_work: 8_000_000,
            max_stack_items: 1_000_000,
        }
    }
}

/// A bounded resource owned by the uniform-participation proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum UniformCaptureParticipationResource {
    Work,
    StackItems,
}

impl fmt::Display for UniformCaptureParticipationResource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Work => "uniform capture-participation work",
            Self::StackItems => "uniform capture-participation explicit stack items",
        })
    }
}

/// A terminal proof failure, distinct from a conservative semantic decline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum UniformCaptureParticipationError {
    ResourceLimit {
        resource: UniformCaptureParticipationResource,
        needed: u64,
        limit: u64,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    AllocationFailed {
        structure: &'static str,
        additional: usize,
    },
    InternalInvariant {
        detail: &'static str,
    },
}

impl fmt::Display for UniformCaptureParticipationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResourceLimit {
                resource,
                needed,
                limit,
            } => write!(
                formatter,
                "uniform capture-participation proof needs {needed} {resource}, exceeding limit {limit}"
            ),
            Self::ArithmeticOverflow { computation } => write!(
                formatter,
                "arithmetic overflow while computing uniform capture-participation {computation}"
            ),
            Self::AllocationFailed {
                structure,
                additional,
            } => write!(
                formatter,
                "failed to reserve {additional} additional items for {structure}"
            ),
            Self::InternalInvariant { detail } => write!(
                formatter,
                "uniform capture-participation invariant failed: {detail}"
            ),
        }
    }
}

impl std::error::Error for UniformCaptureParticipationError {}

/// Conservative reason why no positive receipt was published.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum UniformCaptureParticipationDecline {
    /// Canonical HIR reported no representable matching-string minimum.
    EmptyLanguageOrUnknownMinimum,
    /// The complete language includes an empty match.
    Nullable,
    /// Successful paths do not have one proved participating-capture count.
    NonUniform,
    /// Capture indices were not nonzero and strictly increasing in canonical
    /// source order, so the distinct-capture premise was not authenticated.
    NonCanonicalCaptureIndices,
}

/// Exact positive theorem and construction accounting.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UniformCaptureParticipationReceipt {
    identity: UniformCaptureParticipationIdentity,
    minimum_match_bytes: NonZeroUsize,
    participating_user_captures: usize,
    participating_groups_per_match: NonZeroUsize,
    canonical_capture_annotations: usize,
    work: u64,
    peak_stack_items: usize,
}

impl UniformCaptureParticipationReceipt {
    #[must_use]
    pub const fn identity(self) -> UniformCaptureParticipationIdentity {
        self.identity
    }

    /// Proved positive minimum byte width of every semantic match.
    #[must_use]
    pub const fn minimum_match_bytes(self) -> NonZeroUsize {
        self.minimum_match_bytes
    }

    /// Participating user capture groups on every semantic match.
    #[must_use]
    pub const fn participating_user_captures(self) -> usize {
        self.participating_user_captures
    }

    /// Participating groups including the always-present overall group zero.
    #[must_use]
    pub const fn participating_groups_per_match(self) -> NonZeroUsize {
        self.participating_groups_per_match
    }

    /// Capture annotations retained by canonical HIR and erased by selector
    /// lowering. This is not a reconstruction of a source-level schema.
    #[must_use]
    pub const fn canonical_capture_annotations(self) -> usize {
        self.canonical_capture_annotations
    }

    #[must_use]
    pub const fn work(self) -> u64 {
        self.work
    }

    #[must_use]
    pub const fn peak_stack_items(self) -> usize {
        self.peak_stack_items
    }
}

/// Positive proof or conservative semantic decline for the paired selector.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum UniformCaptureParticipationDisposition {
    Proven(UniformCaptureParticipationReceipt),
    Declined(UniformCaptureParticipationDecline),
}

impl UniformCaptureParticipationDisposition {
    #[must_use]
    pub const fn proof(self) -> Option<UniformCaptureParticipationReceipt> {
        match self {
            Self::Proven(proof) => Some(proof),
            Self::Declined(_) => None,
        }
    }

    #[must_use]
    pub const fn decline(self) -> Option<UniformCaptureParticipationDecline> {
        match self {
            Self::Proven(_) => None,
            Self::Declined(decline) => Some(decline),
        }
    }
}

/// One unchanged general selector lowering and its same-HIR proof disposition.
#[derive(Debug)]
pub struct UniformCaptureLoweredRaw {
    lowered: LoweredRaw,
    participation: UniformCaptureParticipationDisposition,
}

impl UniformCaptureLoweredRaw {
    #[must_use]
    pub const fn lowered(&self) -> &LoweredRaw {
        &self.lowered
    }

    #[must_use]
    pub const fn participation(&self) -> UniformCaptureParticipationDisposition {
        self.participation
    }

    /// Split the transaction after both results have been constructed and
    /// their shared canonical capture census has been checked.
    #[must_use]
    pub fn into_parts(self) -> (LoweredRaw, UniformCaptureParticipationDisposition) {
        (self.lowered, self.participation)
    }
}

/// Terminal failure of the paired proof/lowering transaction.
#[derive(Debug)]
#[non_exhaustive]
pub enum UniformCaptureLoweringError {
    Participation(UniformCaptureParticipationError),
    Lower(LowerError),
}

impl fmt::Display for UniformCaptureLoweringError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Participation(error) => error.fmt(formatter),
            Self::Lower(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for UniformCaptureLoweringError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Participation(error) => Some(error),
            Self::Lower(error) => Some(error),
        }
    }
}

/// Prove uniform capture participation and lower the exact same parsed HIR.
///
/// A semantic proof decline is returned inside a successful transaction, so
/// an optimizer can retain the unchanged general selector. Proof resource,
/// allocation, arithmetic, and invariant failures are terminal and distinct
/// from [`LowerError`]. Proof construction runs first; an allocator failure
/// therefore cannot be followed by a fresh selector allocation.
///
/// # Errors
///
/// Returns [`UniformCaptureLoweringError::Participation`] for a terminal proof
/// failure or [`UniformCaptureLoweringError::Lower`] for the incumbent general
/// lowering failure.
pub fn lower_raw_general_with_uniform_capture_participation(
    parsed: &RustParsed,
    operation: OperationSemantics,
    lower_limits: LowerLimits,
    proof_limits: UniformCaptureParticipationLimits,
) -> Result<UniformCaptureLoweredRaw, UniformCaptureLoweringError> {
    let participation = Analyzer::new(proof_limits)
        .run(&parsed.hir)
        .map_err(UniformCaptureLoweringError::Participation)?;
    let lowered = lower_raw_general(parsed, operation, lower_limits)
        .map_err(UniformCaptureLoweringError::Lower)?;
    if let UniformCaptureParticipationDisposition::Proven(proof) = participation
        && proof.canonical_capture_annotations() != lowered.stats().erased_captures()
    {
        return Err(UniformCaptureLoweringError::Participation(
            UniformCaptureParticipationError::InternalInvariant {
                detail: "proof and selector capture censuses diverged",
            },
        ));
    }
    Ok(UniformCaptureLoweredRaw {
        lowered,
        participation,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParticipationShape {
    uniform: Option<usize>,
    stable_set: bool,
    can_participate: bool,
}

impl ParticipationShape {
    const CAPTURE_FREE: Self = Self {
        uniform: Some(0),
        stable_set: true,
        can_participate: false,
    };
}

#[derive(Clone, Copy)]
enum Task<'h> {
    Visit(&'h Hir),
    FinishCapture,
    FinishRepetition { min: u32, max: Option<u32> },
    FinishConcat(usize),
    FinishAlternation(usize),
}

struct Analyzer<'h> {
    limits: UniformCaptureParticipationLimits,
    tasks: Vec<Task<'h>>,
    results: Vec<ParticipationShape>,
    work: u64,
    peak_stack_items: usize,
    captures_seen: usize,
    last_capture_index: Option<u32>,
    canonical_capture_indices: bool,
}

impl<'h> Analyzer<'h> {
    const fn new(limits: UniformCaptureParticipationLimits) -> Self {
        Self {
            limits,
            tasks: Vec::new(),
            results: Vec::new(),
            work: 0,
            peak_stack_items: 0,
            captures_seen: 0,
            last_capture_index: None,
            canonical_capture_indices: true,
        }
    }

    fn run(
        mut self,
        hir: &'h Hir,
    ) -> Result<UniformCaptureParticipationDisposition, UniformCaptureParticipationError> {
        let minimum_match_bytes = match hir.properties().minimum_len() {
            None => {
                return Ok(UniformCaptureParticipationDisposition::Declined(
                    UniformCaptureParticipationDecline::EmptyLanguageOrUnknownMinimum,
                ));
            }
            Some(0) => {
                return Ok(UniformCaptureParticipationDisposition::Declined(
                    UniformCaptureParticipationDecline::Nullable,
                ));
            }
            Some(minimum) => NonZeroUsize::new(minimum).ok_or(
                UniformCaptureParticipationError::InternalInvariant {
                    detail: "positive minimum did not construct NonZeroUsize",
                },
            )?,
        };

        self.push_task(Task::Visit(hir))?;
        while let Some(task) = self.tasks.pop() {
            match task {
                Task::Visit(node) => self.visit(node)?,
                Task::FinishCapture => self.finish_capture()?,
                Task::FinishRepetition { min, max } => self.finish_repetition(min, max)?,
                Task::FinishConcat(count) => self.finish_concat(count)?,
                Task::FinishAlternation(count) => self.finish_alternation(count)?,
            }
        }
        if self.results.len() != 1 {
            return Err(UniformCaptureParticipationError::InternalInvariant {
                detail: "postorder proof did not produce exactly one result",
            });
        }
        let shape =
            self.results
                .pop()
                .ok_or(UniformCaptureParticipationError::InternalInvariant {
                    detail: "uniform participation root disappeared",
                })?;
        let canonical_capture_annotations = hir.properties().explicit_captures_len();
        if self.captures_seen != canonical_capture_annotations {
            return Err(UniformCaptureParticipationError::InternalInvariant {
                detail: "proof capture census disagreed with canonical HIR properties",
            });
        }
        if !self.canonical_capture_indices {
            return Ok(UniformCaptureParticipationDisposition::Declined(
                UniformCaptureParticipationDecline::NonCanonicalCaptureIndices,
            ));
        }
        let Some(participating_user_captures) = shape.uniform else {
            return Ok(UniformCaptureParticipationDisposition::Declined(
                UniformCaptureParticipationDecline::NonUniform,
            ));
        };
        if participating_user_captures > canonical_capture_annotations {
            return Err(UniformCaptureParticipationError::InternalInvariant {
                detail: "participating count exceeded canonical capture census",
            });
        }
        let participating_groups_per_match = participating_user_captures
            .checked_add(1)
            .and_then(NonZeroUsize::new)
            .ok_or(UniformCaptureParticipationError::ArithmeticOverflow {
                computation: "group-zero-inclusive participation count",
            })?;
        Ok(UniformCaptureParticipationDisposition::Proven(
            UniformCaptureParticipationReceipt {
                identity: UniformCaptureParticipationIdentity::current(),
                minimum_match_bytes,
                participating_user_captures,
                participating_groups_per_match,
                canonical_capture_annotations,
                work: self.work,
                peak_stack_items: self.peak_stack_items,
            },
        ))
    }

    fn visit(&mut self, hir: &'h Hir) -> Result<(), UniformCaptureParticipationError> {
        self.charge(1)?;
        match hir.kind() {
            HirKind::Empty | HirKind::Literal(_) | HirKind::Class(_) | HirKind::Look(_) => {
                self.push_result(ParticipationShape::CAPTURE_FREE)
            }
            HirKind::Capture(capture) => {
                self.captures_seen = self.captures_seen.checked_add(1).ok_or(
                    UniformCaptureParticipationError::ArithmeticOverflow {
                        computation: "capture census",
                    },
                )?;
                if capture.index == 0
                    || self
                        .last_capture_index
                        .is_some_and(|previous| capture.index <= previous)
                {
                    self.canonical_capture_indices = false;
                }
                self.last_capture_index = Some(capture.index);
                self.push_task(Task::FinishCapture)?;
                self.push_task(Task::Visit(&capture.sub))
            }
            HirKind::Repetition(repetition) => {
                self.push_task(Task::FinishRepetition {
                    min: repetition.min,
                    max: repetition.max,
                })?;
                self.push_task(Task::Visit(&repetition.sub))
            }
            HirKind::Concat(children) => {
                self.push_task(Task::FinishConcat(children.len()))?;
                for child in children.iter().rev() {
                    self.push_task(Task::Visit(child))?;
                }
                Ok(())
            }
            HirKind::Alternation(children) => {
                self.push_task(Task::FinishAlternation(children.len()))?;
                for child in children.iter().rev() {
                    self.push_task(Task::Visit(child))?;
                }
                Ok(())
            }
        }
    }

    fn finish_capture(&mut self) -> Result<(), UniformCaptureParticipationError> {
        let child = self.pop_result()?;
        let uniform = child
            .uniform
            .map(|count| {
                count
                    .checked_add(1)
                    .ok_or(UniformCaptureParticipationError::ArithmeticOverflow {
                        computation: "participating capture count",
                    })
            })
            .transpose()?;
        self.push_result(ParticipationShape {
            uniform,
            stable_set: child.stable_set,
            can_participate: true,
        })
    }

    fn finish_repetition(
        &mut self,
        min: u32,
        max: Option<u32>,
    ) -> Result<(), UniformCaptureParticipationError> {
        let child = self.pop_result()?;
        let shape = if max == Some(0) || !child.can_participate {
            ParticipationShape::CAPTURE_FREE
        } else {
            let can_repeat = max.is_none_or(|maximum| maximum > 1);
            if min == 0 || can_repeat && !child.stable_set {
                ParticipationShape {
                    uniform: None,
                    stable_set: false,
                    can_participate: true,
                }
            } else {
                child
            }
        };
        self.push_result(shape)
    }

    fn finish_concat(&mut self, count: usize) -> Result<(), UniformCaptureParticipationError> {
        let mut combined = ParticipationShape::CAPTURE_FREE;
        for _ in 0..count {
            let child = self.pop_result()?;
            self.charge(1)?;
            combined = ParticipationShape {
                uniform: match (combined.uniform, child.uniform) {
                    (Some(left), Some(right)) => Some(left.checked_add(right).ok_or(
                        UniformCaptureParticipationError::ArithmeticOverflow {
                            computation: "concatenated participation count",
                        },
                    )?),
                    _ => None,
                },
                stable_set: combined.stable_set && child.stable_set,
                can_participate: combined.can_participate || child.can_participate,
            };
        }
        self.push_result(combined)
    }

    fn finish_alternation(&mut self, count: usize) -> Result<(), UniformCaptureParticipationError> {
        let mut uniform = None;
        let mut first = true;
        let mut can_participate = false;
        for _ in 0..count {
            let child = self.pop_result()?;
            self.charge(1)?;
            uniform = if first || uniform == child.uniform {
                child.uniform
            } else {
                None
            };
            first = false;
            can_participate |= child.can_participate;
        }
        self.push_result(ParticipationShape {
            uniform,
            // Canonical capture IDs are unique HIR nodes. Distinct branches
            // therefore have one stable set only when every arm is capture-free.
            stable_set: !can_participate,
            can_participate,
        })
    }

    fn charge(&mut self, amount: u64) -> Result<(), UniformCaptureParticipationError> {
        let needed = self.work.checked_add(amount).ok_or(
            UniformCaptureParticipationError::ArithmeticOverflow {
                computation: "work",
            },
        )?;
        if needed > self.limits.max_work {
            return Err(UniformCaptureParticipationError::ResourceLimit {
                resource: UniformCaptureParticipationResource::Work,
                needed,
                limit: self.limits.max_work,
            });
        }
        self.work = needed;
        Ok(())
    }

    fn push_task(&mut self, task: Task<'h>) -> Result<(), UniformCaptureParticipationError> {
        self.check_stack_push()?;
        self.tasks.try_reserve(1).map_err(|_| {
            UniformCaptureParticipationError::AllocationFailed {
                structure: "uniform participation task stack",
                additional: 1,
            }
        })?;
        self.tasks.push(task);
        self.record_stack_peak()
    }

    fn push_result(
        &mut self,
        result: ParticipationShape,
    ) -> Result<(), UniformCaptureParticipationError> {
        self.check_stack_push()?;
        self.results.try_reserve(1).map_err(|_| {
            UniformCaptureParticipationError::AllocationFailed {
                structure: "uniform participation result stack",
                additional: 1,
            }
        })?;
        self.results.push(result);
        self.record_stack_peak()
    }

    fn pop_result(&mut self) -> Result<ParticipationShape, UniformCaptureParticipationError> {
        self.results
            .pop()
            .ok_or(UniformCaptureParticipationError::InternalInvariant {
                detail: "postorder proof result stack underflowed",
            })
    }

    fn check_stack_push(&self) -> Result<(), UniformCaptureParticipationError> {
        let occupied = self.tasks.len().checked_add(self.results.len()).ok_or(
            UniformCaptureParticipationError::ArithmeticOverflow {
                computation: "stack occupancy",
            },
        )?;
        let needed = occupied.checked_add(1).ok_or(
            UniformCaptureParticipationError::ArithmeticOverflow {
                computation: "stack push occupancy",
            },
        )?;
        if needed > self.limits.max_stack_items {
            return Err(UniformCaptureParticipationError::ResourceLimit {
                resource: UniformCaptureParticipationResource::StackItems,
                needed: u64::try_from(needed).unwrap_or(u64::MAX),
                limit: u64::try_from(self.limits.max_stack_items).unwrap_or(u64::MAX),
            });
        }
        Ok(())
    }

    fn record_stack_peak(&mut self) -> Result<(), UniformCaptureParticipationError> {
        let occupied = self.tasks.len().checked_add(self.results.len()).ok_or(
            UniformCaptureParticipationError::ArithmeticOverflow {
                computation: "stack peak occupancy",
            },
        )?;
        self.peak_stack_items = self.peak_stack_items.max(occupied);
        Ok(())
    }
}
