use regex_syntax::hir::{Class, Hir, HirKind};

use super::{
    CapturePolicy, CompileBudget, PlanId, RustByteProfile, StableHash, inclusive_byte_width,
};
use crate::error::{add, mul};
use crate::program::ByteSet;
use crate::{Error, Resource};

pub(crate) const MAX_ORDERED_BOUNDED_ANCHOR_BYTES: usize = 32;
pub(crate) const MAX_ORDERED_BOUNDED_CHUNKS: usize = 32;

/// Canonical-HIR proof for the mirrored language
/// `A(?:S*D+S*){0,K}B | B(?:S*D+S*){0,K}A`.
///
/// `S` and `D` are nonempty byte classes, both anchors are nonempty fixed
/// D-only literals, and every repetition is greedy. Bytes in `S ∩ D` retain
/// both assignments; the executor's bounded Thompson phase frontier preserves
/// those alternatives. Its `3K + 1` middle states depend only on finite `K`.
/// The retained proof preserves root-arm priority and greedy terminal choice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OrderedBoundedSpanSumPlan {
    first_anchor: [u8; MAX_ORDERED_BOUNDED_ANCHOR_BYTES],
    second_anchor: [u8; MAX_ORDERED_BOUNDED_ANCHOR_BYTES],
    first_anchor_len: u8,
    second_anchor_len: u8,
    separators: ByteSet,
    data: ByteSet,
    max_chunks: u8,
}

impl OrderedBoundedSpanSumPlan {
    pub(crate) fn first_anchor(&self) -> &[u8] {
        &self.first_anchor[..usize::from(self.first_anchor_len)]
    }

    pub(crate) fn second_anchor(&self) -> &[u8] {
        &self.second_anchor[..usize::from(self.second_anchor_len)]
    }

    pub(crate) const fn separators(&self) -> ByteSet {
        self.separators
    }

    pub(crate) const fn data(&self) -> ByteSet {
        self.data
    }

    pub(crate) fn max_chunks(&self) -> usize {
        usize::from(self.max_chunks)
    }

    pub(crate) const fn retained_bytes() -> usize {
        core::mem::size_of::<Self>()
    }
}

struct Arm<'a> {
    start: &'a [u8],
    end: &'a [u8],
    separators: ByteSet,
    data: ByteSet,
    max_chunks: usize,
}

pub(super) fn build_plan(
    hir: &Hir,
    profile: RustByteProfile,
    capture_policy: CapturePolicy,
    budget: &mut CompileBudget,
) -> Result<Option<OrderedBoundedSpanSumPlan>, Error> {
    let start_work = budget.accounting.work;
    budget.charge(1)?;
    if profile.unicode || capture_policy != CapturePolicy::EraseForWholeMatch {
        return Ok(None);
    }
    let root = transparent(hir, budget)?;
    let HirKind::Alternation(arms) = root.kind() else {
        return Ok(None);
    };
    budget.charge(1)?;
    if arms.len() != 2 {
        return Ok(None);
    }
    let Some(first) = parse_arm(&arms[0], budget)? else {
        return Ok(None);
    };
    let Some(second) = parse_arm(&arms[1], budget)? else {
        return Ok(None);
    };
    budget.charge(8)?;
    if first.start != second.end
        || first.end != second.start
        || first.separators != second.separators
        || first.data != second.data
        || first.max_chunks != second.max_chunks
        || first.start.is_empty()
        || first.end.is_empty()
        || first.start.len() > MAX_ORDERED_BOUNDED_ANCHOR_BYTES
        || first.end.len() > MAX_ORDERED_BOUNDED_ANCHOR_BYTES
        || first.max_chunks == 0
        || first.max_chunks > MAX_ORDERED_BOUNDED_CHUNKS
    {
        return Ok(None);
    }
    budget.charge(add(
        add(first.start.len(), first.end.len(), Resource::CompileWork)?,
        8,
        Resource::CompileWork,
    )?)?;
    if byte_set_is_empty(first.separators)
        || byte_set_is_empty(first.data)
        || !first
            .start
            .iter()
            .chain(first.end)
            .copied()
            .all(|byte| first.data.contains(byte))
    {
        return Ok(None);
    }

    let retained_bytes = OrderedBoundedSpanSumPlan::retained_bytes();
    let anchor_bytes = add(first.start.len(), first.end.len(), Resource::CompileWork)?;
    budget.preflight_receipt_construction_bytes(retained_bytes)?;
    budget.charge(add(retained_bytes, anchor_bytes, Resource::CompileWork)?)?;
    budget.acquire_checked_construction_bytes(retained_bytes)?;
    let mut first_anchor = [0_u8; MAX_ORDERED_BOUNDED_ANCHOR_BYTES];
    let mut second_anchor = [0_u8; MAX_ORDERED_BOUNDED_ANCHOR_BYTES];
    first_anchor[..first.start.len()].copy_from_slice(first.start);
    second_anchor[..first.end.len()].copy_from_slice(first.end);
    budget.record_initialization(retained_bytes, false)?;
    budget.record_copy(anchor_bytes)?;
    let plan = OrderedBoundedSpanSumPlan {
        first_anchor,
        second_anchor,
        first_anchor_len: u8::try_from(first.start.len()).map_err(|_| {
            Error::InternalInvariant("ordered bounded-span anchor length exceeds its encoding")
        })?,
        second_anchor_len: u8::try_from(first.end.len()).map_err(|_| {
            Error::InternalInvariant("ordered bounded-span anchor length exceeds its encoding")
        })?,
        separators: first.separators,
        data: first.data,
        max_chunks: u8::try_from(first.max_chunks).map_err(|_| {
            Error::InternalInvariant("ordered bounded-span chunk limit exceeds its encoding")
        })?,
    };
    budget.accounting.ordered_bounded_span_sum_plans = 1;
    budget.accounting.ordered_bounded_span_sum_anchor_bytes = anchor_bytes;
    budget.accounting.ordered_bounded_span_sum_max_chunks = first.max_chunks;
    budget.accounting.ordered_bounded_span_sum_build_work = budget
        .accounting
        .work
        .checked_sub(start_work)
        .ok_or(Error::InternalInvariant(
            "ordered bounded-span build work underflow",
        ))?;
    budget.accounting.ordered_bounded_span_sum_persistent_bytes = retained_bytes;
    Ok(Some(plan))
}

fn parse_arm<'a>(hir: &'a Hir, budget: &mut CompileBudget) -> Result<Option<Arm<'a>>, Error> {
    let hir = transparent(hir, budget)?;
    let HirKind::Concat(parts) = hir.kind() else {
        return Ok(None);
    };
    budget.charge(1)?;
    if parts.len() != 3 {
        return Ok(None);
    }
    let Some(start) = literal(&parts[0], budget)? else {
        return Ok(None);
    };
    let Some((separators, data, max_chunks)) = middle(&parts[1], budget)? else {
        return Ok(None);
    };
    let Some(end) = literal(&parts[2], budget)? else {
        return Ok(None);
    };
    Ok(Some(Arm {
        start,
        end,
        separators,
        data,
        max_chunks,
    }))
}

fn middle(
    hir: &Hir,
    budget: &mut CompileBudget,
) -> Result<Option<(ByteSet, ByteSet, usize)>, Error> {
    let hir = transparent(hir, budget)?;
    let HirKind::Repetition(outer) = hir.kind() else {
        return Ok(None);
    };
    budget.charge(4)?;
    let Some(max) = outer.max else {
        return Ok(None);
    };
    if outer.min != 0 || !outer.greedy {
        return Ok(None);
    }
    let sub = transparent(&outer.sub, budget)?;
    let HirKind::Concat(parts) = sub.kind() else {
        return Ok(None);
    };
    budget.charge(1)?;
    if parts.len() != 3 {
        return Ok(None);
    }
    let Some(first) = repeated_byte_set(&parts[0], 0, budget)? else {
        return Ok(None);
    };
    let Some(data) = repeated_byte_set(&parts[1], 1, budget)? else {
        return Ok(None);
    };
    let Some(last) = repeated_byte_set(&parts[2], 0, budget)? else {
        return Ok(None);
    };
    budget.charge(1)?;
    if first != last {
        return Ok(None);
    }
    Ok(Some((
        first,
        data,
        usize::try_from(max).map_err(|_| Error::ArithmeticOverflow {
            resource: Resource::CompileWork,
        })?,
    )))
}

fn repeated_byte_set(
    hir: &Hir,
    minimum: u32,
    budget: &mut CompileBudget,
) -> Result<Option<ByteSet>, Error> {
    let hir = transparent(hir, budget)?;
    let HirKind::Repetition(repetition) = hir.kind() else {
        return Ok(None);
    };
    budget.charge(4)?;
    if repetition.min != minimum || repetition.max.is_some() || !repetition.greedy {
        return Ok(None);
    }
    byte_set(&repetition.sub, budget)
}

fn byte_set(hir: &Hir, budget: &mut CompileBudget) -> Result<Option<ByteSet>, Error> {
    let hir = transparent(hir, budget)?;
    budget.charge(1)?;
    match hir.kind() {
        HirKind::Class(Class::Bytes(class)) => {
            let mut set = ByteSet::empty();
            for range in class.ranges() {
                let width = inclusive_byte_width(range.start(), range.end())?;
                budget.charge(add(width, 1, Resource::CompileWork)?)?;
                set.insert_range(range.start(), range.end());
            }
            Ok(Some(set))
        }
        HirKind::Literal(regex_syntax::hir::Literal(bytes)) if bytes.len() == 1 => {
            budget.charge(1)?;
            let mut set = ByteSet::empty();
            set.insert(bytes[0]);
            Ok(Some(set))
        }
        _ => Ok(None),
    }
}

fn literal<'a>(hir: &'a Hir, budget: &mut CompileBudget) -> Result<Option<&'a [u8]>, Error> {
    let hir = transparent(hir, budget)?;
    budget.charge(1)?;
    match hir.kind() {
        HirKind::Literal(regex_syntax::hir::Literal(bytes)) => {
            budget.charge(bytes.len())?;
            Ok(Some(bytes))
        }
        _ => Ok(None),
    }
}

fn transparent<'a>(mut hir: &'a Hir, budget: &mut CompileBudget) -> Result<&'a Hir, Error> {
    loop {
        budget.charge(1)?;
        match hir.kind() {
            HirKind::Capture(capture) => hir = &capture.sub,
            _ => return Ok(hir),
        }
    }
}

fn byte_set_is_empty(set: ByteSet) -> bool {
    set.0.iter().all(|&word| word == 0)
}

pub(super) fn bind_plan_identity(
    program: PlanId,
    plan: &OrderedBoundedSpanSumPlan,
    budget: &mut CompileBudget,
) -> Result<PlanId, Error> {
    let domain = b"fre.aggregate.ordered-bounded-span-sum-plan.v1";
    let operation = b"fre.aggregate.ordered-bounded-span-sum-operation.v1";
    let class_bytes = mul(8, core::mem::size_of::<u64>(), Resource::CompileWork)?;
    let anchor_bytes = add(
        plan.first_anchor().len(),
        plan.second_anchor().len(),
        Resource::CompileWork,
    )?;
    let payload = add(
        add(
            add(program.0.len(), domain.len(), Resource::CompileWork)?,
            operation.len(),
            Resource::CompileWork,
        )?,
        add(
            add(class_bytes, anchor_bytes, Resource::CompileWork)?,
            3,
            Resource::CompileWork,
        )?,
        Resource::CompileWork,
    )?;
    budget.charge(mul(2, payload, Resource::CompileWork)?)?;
    let mut first = StableHash::new(0x8d6c_3f25_a917_40eb);
    let mut second = StableHash::new(0x40eb_a917_3f25_8d6c);
    for hash in [&mut first, &mut second] {
        hash.bytes(&program.0);
        hash.bytes(domain);
        hash.bytes(operation);
        hash.byte(plan.first_anchor_len);
        hash.bytes(plan.first_anchor());
        hash.byte(plan.second_anchor_len);
        hash.bytes(plan.second_anchor());
        for word in plan.separators.0 {
            hash.bytes(&word.to_le_bytes());
        }
        for word in plan.data.0 {
            hash.bytes(&word.to_le_bytes());
        }
        hash.byte(plan.max_chunks);
    }
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&first.finish().to_le_bytes());
    bytes[8..].copy_from_slice(&second.finish().to_le_bytes());
    Ok(PlanId(bytes))
}
