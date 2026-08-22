//! Authenticated construction view for helper-free exact-span participation.
//!
//! The view deliberately exposes no executor. It is a borrowed, allocation-
//! free projection of one already validated [`CaptureProgramV1`] owner for an
//! AOT backend that will replay an independently selected exact span. The
//! ordinary selector remains authoritative for leftmost-first span choice.
//! Native replay retains only `(pc, open, participated)` and must reject any
//! dynamically malformed tag path before publishing a result.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "all variable layout arithmetic is checked before a view is published"
)]

use core::{fmt, mem::size_of};

use crate::ast::Assertion;
use crate::compile::{Program, State};
use crate::model::PARTICIPATION_QUOTIENT_MASK_BITS;
use crate::program_v1::{CaptureProgramV1, CaptureProgramV1Usage};

/// Stable semantic identity of the exact-span participation construction
/// projection.
pub const EXACT_SPAN_PARTICIPATION_NATIVE_V1_ALGORITHM_ID: &str =
    "fre-capture-lab.exact-span-participation-native.v1";

/// Stable identity of the V1 scratch and lowering-work accounting below.
pub const EXACT_SPAN_PARTICIPATION_NATIVE_V1_ACCOUNTING_ID: &str =
    "fre-capture-lab.exact-span-participation-native-accounting.v1";

/// Fixed target ABI size of one `(pc, open, participated)` thread record.
pub const EXACT_SPAN_PARTICIPATION_NATIVE_V1_THREAD_BYTES: usize = 24;

/// Fixed target ABI alignment of one participation thread record.
pub const EXACT_SPAN_PARTICIPATION_NATIVE_V1_THREAD_ALIGN: usize = 8;

/// Fixed target ABI size of one generation mark.
pub const EXACT_SPAN_PARTICIPATION_NATIVE_V1_SEEN_BYTES: usize = 4;

/// Fixed target ABI alignment of one generation mark.
pub const EXACT_SPAN_PARTICIPATION_NATIVE_V1_SEEN_ALIGN: usize = 4;

#[repr(C)]
struct NativeThreadV1LayoutProof {
    pc: u32,
    reserved: u32,
    open: u64,
    participated: u64,
}

const _: () = assert!(
    size_of::<NativeThreadV1LayoutProof>() == EXACT_SPAN_PARTICIPATION_NATIVE_V1_THREAD_BYTES
);
const _: () = assert!(
    core::mem::align_of::<NativeThreadV1LayoutProof>()
        == EXACT_SPAN_PARTICIPATION_NATIVE_V1_THREAD_ALIGN
);

/// One independently limited construction dimension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExactSpanParticipationNativeV1Resource {
    /// Prioritized Thompson instructions.
    States,
    /// Aggregate inclusive byte ranges.
    ByteRanges,
    /// Capture groups including group zero.
    Groups,
    /// Exact caller-owned replay scratch bytes.
    ScratchBytes,
    /// Versioned source-independent projection work.
    LoweringWork,
}

/// Source-independent ceilings for publishing a V1 construction view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExactSpanParticipationNativeV1Limits {
    pub max_states: usize,
    pub max_byte_ranges: usize,
    pub max_groups: usize,
    pub max_scratch_bytes: usize,
    pub max_lowering_work: usize,
}

impl Default for ExactSpanParticipationNativeV1Limits {
    fn default() -> Self {
        Self {
            max_states: 65_536,
            max_byte_ranges: 1_000_000,
            max_groups: usize::from(PARTICIPATION_QUOTIENT_MASK_BITS),
            max_scratch_bytes: 64 * 1_024 * 1_024,
            max_lowering_work: 4_000_000,
        }
    }
}

/// Fail-closed construction-view error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExactSpanParticipationNativeV1Error {
    /// One independent caller ceiling would be exceeded.
    Resource {
        resource: ExactSpanParticipationNativeV1Resource,
        required: usize,
        limit: usize,
    },
    /// Checked layout or work arithmetic overflowed.
    ArithmeticOverflow(ExactSpanParticipationNativeV1Resource),
    /// A supposedly sealed capture owner no longer closes its invariants.
    InvalidOwner(&'static str),
}

impl fmt::Display for ExactSpanParticipationNativeV1Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ExactSpanParticipationNativeV1Error {}

/// Stable V1 assertion operation used by native construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ExactSpanParticipationNativeAssertionKindV1 {
    Start = 1,
    End = 2,
    StartLf = 3,
    EndLf = 4,
    StartLine = 5,
    EndLine = 6,
    StartCrlf = 7,
    EndCrlf = 8,
    WordAscii = 9,
    WordAsciiNegate = 10,
    WordStartAscii = 11,
    WordEndAscii = 12,
    WordStartHalfAscii = 13,
    WordEndHalfAscii = 14,
    WordUnicode = 15,
    WordUnicodeNegate = 16,
    WordStartUnicode = 17,
    WordEndUnicode = 18,
    WordStartHalfUnicode = 19,
    WordEndHalfUnicode = 20,
}

/// One assertion kind plus its optional byte operand.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExactSpanParticipationNativeAssertionV1 {
    kind: ExactSpanParticipationNativeAssertionKindV1,
    data: u8,
}

impl ExactSpanParticipationNativeAssertionV1 {
    #[must_use]
    pub const fn kind(self) -> ExactSpanParticipationNativeAssertionKindV1 {
        self.kind
    }

    /// Operand for `StartLine`/`EndLine`; zero for every other V1 kind.
    #[must_use]
    pub const fn data(self) -> u8 {
        self.data
    }
}

/// One borrowed, already validated Thompson instruction.
///
/// State indices and slots are narrowed only after the complete owner shape
/// has been checked. Byte ranges remain sorted, disjoint inclusive pairs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExactSpanParticipationNativeStateV1<'a> {
    Byte {
        ranges: &'a [(u8, u8)],
        next: u32,
    },
    Split {
        first: u32,
        second: u32,
    },
    Save {
        slot: u8,
        next: u32,
    },
    Assert {
        assertion: ExactSpanParticipationNativeAssertionV1,
        next: u32,
    },
    Epsilon {
        next: u32,
    },
    Match,
    Fail,
}

/// Exact source-independent geometry for a helper-free V1 replay owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExactSpanParticipationNativeV1Layout {
    state_count: usize,
    byte_range_count: usize,
    group_count: usize,
    slot_count: usize,
    current_offset: usize,
    next_offset: usize,
    stack_offset: usize,
    seen_offset: usize,
    scratch_bytes: usize,
    lowering_work: usize,
}

impl ExactSpanParticipationNativeV1Layout {
    #[must_use]
    pub const fn state_count(self) -> usize {
        self.state_count
    }

    #[must_use]
    pub const fn byte_range_count(self) -> usize {
        self.byte_range_count
    }

    /// Capture groups including group zero.
    #[must_use]
    pub const fn group_count(self) -> usize {
        self.group_count
    }

    #[must_use]
    pub const fn slot_count(self) -> usize {
        self.slot_count
    }

    #[must_use]
    pub const fn current_offset(self) -> usize {
        self.current_offset
    }

    #[must_use]
    pub const fn next_offset(self) -> usize {
        self.next_offset
    }

    #[must_use]
    pub const fn stack_offset(self) -> usize {
        self.stack_offset
    }

    #[must_use]
    pub const fn seen_offset(self) -> usize {
        self.seen_offset
    }

    #[must_use]
    pub const fn scratch_bytes(self) -> usize {
        self.scratch_bytes
    }

    #[must_use]
    pub const fn lowering_work(self) -> usize {
        self.lowering_work
    }

    /// Conservative state-dispatch envelope shared with the portable
    /// participation quotient for one exact span of `span_bytes` bytes.
    #[must_use]
    pub fn maximum_state_visits(self, span_bytes: usize) -> Option<usize> {
        span_bytes
            .checked_add(1)?
            .checked_mul(self.state_count)?
            .checked_mul(4)
    }
}

/// Borrowed, allocation-free projection of one sealed V1 capture owner.
///
/// The canonical capture-program digest is the construction identity an AOT
/// artifact must bind alongside its selector identity. A byte-identical,
/// independently restored owner authenticates the same view identity.
#[derive(Clone, Copy, Debug)]
pub struct ExactSpanParticipationNativeV1View<'a> {
    program: &'a Program,
    usage: CaptureProgramV1Usage,
    semantic_digest: &'a [u8; 32],
    layout: ExactSpanParticipationNativeV1Layout,
    start: u32,
}

impl<'a> ExactSpanParticipationNativeV1View<'a> {
    #[must_use]
    pub const fn algorithm_id(self) -> &'static str {
        EXACT_SPAN_PARTICIPATION_NATIVE_V1_ALGORITHM_ID
    }

    #[must_use]
    pub const fn accounting_id(self) -> &'static str {
        EXACT_SPAN_PARTICIPATION_NATIVE_V1_ACCOUNTING_ID
    }

    #[must_use]
    pub const fn semantic_digest(self) -> &'a [u8; 32] {
        self.semantic_digest
    }

    #[must_use]
    pub const fn layout(self) -> ExactSpanParticipationNativeV1Layout {
        self.layout
    }

    #[must_use]
    pub const fn start_state(self) -> u32 {
        self.start
    }

    #[must_use]
    pub const fn state_count(self) -> usize {
        self.layout.state_count
    }

    /// Recheck a separately restored immutable owner against this semantic
    /// identity and every exposed geometry dimension.
    #[must_use]
    pub fn authenticates(self, owner: &CaptureProgramV1) -> bool {
        owner.semantic_digest() == self.semantic_digest
            && owner.usage() == self.usage
            && owner.program().states.len() == self.layout.state_count
            && owner.program().groups.len() == self.layout.group_count
            && owner.program().slot_count == self.layout.slot_count
    }

    #[must_use]
    pub fn state(self, index: usize) -> Option<ExactSpanParticipationNativeStateV1<'a>> {
        self.program.states.get(index).map(project_state)
    }

    #[must_use]
    pub fn states(
        self,
    ) -> impl ExactSizeIterator<Item = ExactSpanParticipationNativeStateV1<'a>> + 'a {
        self.program.states.iter().map(project_state)
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the fixed decline/resource order and complete scratch projection remain locally auditable"
)]
pub(crate) fn native_v1_view<'a>(
    owner: &'a CaptureProgramV1,
    program: &'a Program,
    usage: CaptureProgramV1Usage,
    semantic_digest: &'a [u8; 32],
    limits: ExactSpanParticipationNativeV1Limits,
) -> Result<Option<ExactSpanParticipationNativeV1View<'a>>, ExactSpanParticipationNativeV1Error> {
    if !program.build_report_closes()
        || program.states.len() != usage.states
        || program.groups.len() != usage.groups
        || program.slot_count != usage.slots
        || owner.program().states.len() != program.states.len()
    {
        return Err(ExactSpanParticipationNativeV1Error::InvalidOwner(
            "capture-program owner accounting does not close",
        ));
    }
    let group_count = program.groups.len();
    let Some(expected_slots) = group_count.checked_mul(2) else {
        return Err(ExactSpanParticipationNativeV1Error::ArithmeticOverflow(
            ExactSpanParticipationNativeV1Resource::Groups,
        ));
    };
    // This is a stable semantic decline. V1 uses one u64 for group zero plus
    // at most 63 user groups and a u8 slot index.
    if group_count == 0
        || group_count > usize::from(PARTICIPATION_QUOTIENT_MASK_BITS)
        || program.slot_count != expected_slots
        || program.slot_count > usize::from(u8::MAX) + 1
    {
        return Ok(None);
    }

    check(
        ExactSpanParticipationNativeV1Resource::States,
        program.states.len(),
        limits.max_states,
    )?;
    let byte_range_count = program.states.iter().try_fold(0_usize, |count, state| {
        let ranges = match state {
            State::Byte { ranges, .. } => ranges.len(),
            _ => 0,
        };
        count
            .checked_add(ranges)
            .ok_or(ExactSpanParticipationNativeV1Error::ArithmeticOverflow(
                ExactSpanParticipationNativeV1Resource::ByteRanges,
            ))
    })?;
    check(
        ExactSpanParticipationNativeV1Resource::ByteRanges,
        byte_range_count,
        limits.max_byte_ranges,
    )?;
    check(
        ExactSpanParticipationNativeV1Resource::Groups,
        group_count,
        limits.max_groups,
    )?;

    let state_count_u32 = u32::try_from(program.states.len()).map_err(|_| {
        ExactSpanParticipationNativeV1Error::Resource {
            resource: ExactSpanParticipationNativeV1Resource::States,
            required: program.states.len(),
            limit: usize::try_from(u32::MAX).unwrap_or(usize::MAX),
        }
    })?;
    let start = u32::try_from(program.start).map_err(|_| {
        ExactSpanParticipationNativeV1Error::InvalidOwner("start state is not V1-representable")
    })?;
    if start >= state_count_u32 || program.states.iter().any(state_has_unrepresentable_target) {
        return Err(ExactSpanParticipationNativeV1Error::InvalidOwner(
            "state target is not V1-representable",
        ));
    }

    let frontier_bytes = program
        .states
        .len()
        .checked_mul(EXACT_SPAN_PARTICIPATION_NATIVE_V1_THREAD_BYTES)
        .ok_or(ExactSpanParticipationNativeV1Error::ArithmeticOverflow(
            ExactSpanParticipationNativeV1Resource::ScratchBytes,
        ))?;
    let current_offset = 0;
    let next_offset = frontier_bytes;
    let stack_offset = next_offset.checked_add(frontier_bytes).ok_or(
        ExactSpanParticipationNativeV1Error::ArithmeticOverflow(
            ExactSpanParticipationNativeV1Resource::ScratchBytes,
        ),
    )?;
    let seen_offset = stack_offset.checked_add(frontier_bytes).ok_or(
        ExactSpanParticipationNativeV1Error::ArithmeticOverflow(
            ExactSpanParticipationNativeV1Resource::ScratchBytes,
        ),
    )?;
    let seen_bytes = program
        .states
        .len()
        .checked_mul(EXACT_SPAN_PARTICIPATION_NATIVE_V1_SEEN_BYTES)
        .ok_or(ExactSpanParticipationNativeV1Error::ArithmeticOverflow(
            ExactSpanParticipationNativeV1Resource::ScratchBytes,
        ))?;
    let raw_scratch_bytes = seen_offset.checked_add(seen_bytes).ok_or(
        ExactSpanParticipationNativeV1Error::ArithmeticOverflow(
            ExactSpanParticipationNativeV1Resource::ScratchBytes,
        ),
    )?;
    let scratch_bytes = align_up(
        raw_scratch_bytes,
        EXACT_SPAN_PARTICIPATION_NATIVE_V1_THREAD_ALIGN,
    )?;
    check(
        ExactSpanParticipationNativeV1Resource::ScratchBytes,
        scratch_bytes,
        limits.max_scratch_bytes,
    )?;

    // V1 projection visits every instruction once and copies every inclusive
    // byte range once. Authentication reuses the owner's retained digest and
    // therefore adds no source- or graph-sized work here.
    let lowering_work = program.states.len().checked_add(byte_range_count).ok_or(
        ExactSpanParticipationNativeV1Error::ArithmeticOverflow(
            ExactSpanParticipationNativeV1Resource::LoweringWork,
        ),
    )?;
    check(
        ExactSpanParticipationNativeV1Resource::LoweringWork,
        lowering_work,
        limits.max_lowering_work,
    )?;

    Ok(Some(ExactSpanParticipationNativeV1View {
        program,
        usage,
        semantic_digest,
        layout: ExactSpanParticipationNativeV1Layout {
            state_count: program.states.len(),
            byte_range_count,
            group_count,
            slot_count: program.slot_count,
            current_offset,
            next_offset,
            stack_offset,
            seen_offset,
            scratch_bytes,
            lowering_work,
        },
        start,
    }))
}

fn align_up(value: usize, alignment: usize) -> Result<usize, ExactSpanParticipationNativeV1Error> {
    let mask =
        alignment
            .checked_sub(1)
            .ok_or(ExactSpanParticipationNativeV1Error::ArithmeticOverflow(
                ExactSpanParticipationNativeV1Resource::ScratchBytes,
            ))?;
    value
        .checked_add(mask)
        .map(|rounded| rounded & !mask)
        .ok_or(ExactSpanParticipationNativeV1Error::ArithmeticOverflow(
            ExactSpanParticipationNativeV1Resource::ScratchBytes,
        ))
}

fn check(
    resource: ExactSpanParticipationNativeV1Resource,
    required: usize,
    limit: usize,
) -> Result<(), ExactSpanParticipationNativeV1Error> {
    if required > limit {
        return Err(ExactSpanParticipationNativeV1Error::Resource {
            resource,
            required,
            limit,
        });
    }
    Ok(())
}

fn state_has_unrepresentable_target(state: &State) -> bool {
    match state {
        State::Byte { next, .. }
        | State::Save { next, .. }
        | State::Assert { next, .. }
        | State::Epsilon { next } => u32::try_from(*next).is_err(),
        State::Split { first, second } => {
            u32::try_from(*first).is_err() || u32::try_from(*second).is_err()
        }
        State::Match | State::Fail => false,
    }
}

fn project_state(state: &State) -> ExactSpanParticipationNativeStateV1<'_> {
    let index = |value: usize| {
        u32::try_from(value)
            .unwrap_or_else(|_| unreachable!("V1 view construction checked every state target"))
    };
    match state {
        State::Byte { ranges, next } => ExactSpanParticipationNativeStateV1::Byte {
            ranges,
            next: index(*next),
        },
        State::Split { first, second } => ExactSpanParticipationNativeStateV1::Split {
            first: index(*first),
            second: index(*second),
        },
        State::Save { slot, next, .. } => ExactSpanParticipationNativeStateV1::Save {
            slot: u8::try_from(*slot)
                .unwrap_or_else(|_| unreachable!("V1 view construction checked every slot")),
            next: index(*next),
        },
        State::Assert { assertion, next } => ExactSpanParticipationNativeStateV1::Assert {
            assertion: project_assertion(*assertion),
            next: index(*next),
        },
        State::Epsilon { next } => {
            ExactSpanParticipationNativeStateV1::Epsilon { next: index(*next) }
        }
        State::Match => ExactSpanParticipationNativeStateV1::Match,
        State::Fail => ExactSpanParticipationNativeStateV1::Fail,
    }
}

fn project_assertion(assertion: Assertion) -> ExactSpanParticipationNativeAssertionV1 {
    use ExactSpanParticipationNativeAssertionKindV1 as Kind;
    let (kind, data) = match assertion {
        Assertion::Start => (Kind::Start, 0),
        Assertion::End => (Kind::End, 0),
        Assertion::StartLf => (Kind::StartLf, 0),
        Assertion::EndLf => (Kind::EndLf, 0),
        Assertion::StartLine(byte) => (Kind::StartLine, byte),
        Assertion::EndLine(byte) => (Kind::EndLine, byte),
        Assertion::StartCrlf => (Kind::StartCrlf, 0),
        Assertion::EndCrlf => (Kind::EndCrlf, 0),
        Assertion::WordAscii => (Kind::WordAscii, 0),
        Assertion::WordAsciiNegate => (Kind::WordAsciiNegate, 0),
        Assertion::WordStartAscii => (Kind::WordStartAscii, 0),
        Assertion::WordEndAscii => (Kind::WordEndAscii, 0),
        Assertion::WordStartHalfAscii => (Kind::WordStartHalfAscii, 0),
        Assertion::WordEndHalfAscii => (Kind::WordEndHalfAscii, 0),
        Assertion::WordUnicode => (Kind::WordUnicode, 0),
        Assertion::WordUnicodeNegate => (Kind::WordUnicodeNegate, 0),
        Assertion::WordStartUnicode => (Kind::WordStartUnicode, 0),
        Assertion::WordEndUnicode => (Kind::WordEndUnicode, 0),
        Assertion::WordStartHalfUnicode => (Kind::WordStartHalfUnicode, 0),
        Assertion::WordEndHalfUnicode => (Kind::WordEndHalfUnicode, 0),
    };
    ExactSpanParticipationNativeAssertionV1 { kind, data }
}
