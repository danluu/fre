//! HIR-certified candidate scheduling for large ordered byte programs.
//!
//! Compilation proves that every match owned by an entry consumes a byte from
//! one retained bucket at an offset in a closed interval. Execution scans the
//! source once, schedules only those bounded start intervals, and verifies
//! each possible owner with the original prioritized program. The certificate
//! is an execution hint: the program remains the sole semantic authority.

use core::{mem::size_of, ops::Range};

use fre_exact_alloc::{CopyError, ExactVec};

use crate::accounting::ExecutionAccounting;
use crate::error::{add, enforce, mul};
use crate::program::{Assertion, AssertionContext, ByteSet, Inst, Program, StartDomain};
use crate::{Error, OperationLimits, Resource};

pub(crate) const MAX_ENTRIES: usize = 128;
pub(crate) const MAX_OFFSET: usize = 4_096;
const BUCKETS: usize = 256;
pub(crate) const MAX_FILTER_CHECKS: usize = 7;
const SHAPE_OFFSET_RADIX: usize = 8_192;
#[cfg(target_pointer_width = "64")]
const SHAPE_LENGTH_RADIX: usize = SHAPE_OFFSET_RADIX;
#[cfg(target_pointer_width = "64")]
const SHAPE_BYTE_RADICES: [usize; 3] = [32_768, 8_388_608, 2_147_483_648];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FilterCheck {
    pub(crate) relative: i8,
    pub(crate) bytes: ByteSet,
}

pub(crate) const EMPTY_FILTER_CHECK: FilterCheck = FilterCheck {
    relative: 0,
    bytes: ByteSet::empty(),
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Draft {
    pub(crate) bytes: ByteSet,
    pub(crate) min_offset: usize,
    pub(crate) max_offset: usize,
    pub(crate) checks: [FilterCheck; MAX_FILTER_CHECKS],
    pub(crate) check_len: usize,
    pub(crate) leading_assertion: Option<Assertion>,
    pub(crate) global_bytes: ByteSet,
    pub(crate) global_checks: [FilterCheck; MAX_FILTER_CHECKS],
    pub(crate) global_check_len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Entry {
    pub(crate) pc: usize,
    pub(crate) min_offset: usize,
    pub(crate) max_offset: usize,
    pub(crate) checks: [FilterCheck; MAX_FILTER_CHECKS],
    pub(crate) check_len: usize,
    pub(crate) leading_assertion: Option<Assertion>,
    pub(crate) global_checks: [FilterCheck; MAX_FILTER_CHECKS],
    pub(crate) global_check_len: usize,
}

#[derive(Debug)]
pub(crate) struct Plan {
    pub(crate) entries: ExactVec<Entry>,
    pub(crate) buckets: ExactVec<u128>,
    pub(crate) global_buckets: ExactVec<u128>,
    pub(crate) shape: usize,
}

impl Plan {
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "construction proves the packed shape is a sum of disjoint fields below the nonzero offset radix"
    )]
    pub(crate) const fn max_offset(&self) -> usize {
        self.shape % SHAPE_OFFSET_RADIX
    }

    pub(crate) const fn has_shared_fixed(&self) -> bool {
        self.shape >= SHAPE_OFFSET_RADIX
    }

    fn shared_fixed(&self) -> Result<Option<SharedFixedAnchors>, Error> {
        if !self.has_shared_fixed() {
            return Ok(None);
        }
        #[cfg(not(target_pointer_width = "64"))]
        {
            return Err(Error::InternalInvariant(
                "shared fixed candidate flag is not supported on this pointer width",
            ));
        }
        #[cfg(target_pointer_width = "64")]
        {
            let len = self
                .shape
                .checked_div(SHAPE_LENGTH_RADIX)
                .and_then(|value| value.checked_rem(4))
                .ok_or(Error::InternalInvariant(
                    "shared fixed candidate length field is invalid",
                ))?;
            if !(1..=3).contains(&len) {
                return Err(Error::InternalInvariant(
                    "shared fixed candidate length outside memchr support",
                ));
            }
            let mut bytes = [0_u8; 3];
            for (byte, radix) in bytes.iter_mut().zip(SHAPE_BYTE_RADICES) {
                let value = self
                    .shape
                    .checked_div(radix)
                    .and_then(|value| value.checked_rem(256))
                    .ok_or(Error::InternalInvariant(
                        "shared fixed candidate byte field is invalid",
                    ))?;
                *byte = u8::try_from(value).map_err(|_| {
                    Error::InternalInvariant("shared fixed candidate byte exceeds u8")
                })?;
            }
            Ok(Some(SharedFixedAnchors {
                bytes,
                len,
                offset: self.max_offset(),
                owners: complete_owner_mask(self.entries.len())?,
            }))
        }
    }

    pub(crate) fn retained_bytes(&self) -> Result<usize, Error> {
        let buckets = add(
            self.buckets.len(),
            self.global_buckets.len(),
            Resource::ProgramBytes,
        )?;
        add(
            mul(
                self.entries.len(),
                size_of::<Entry>(),
                Resource::ProgramBytes,
            )?,
            mul(buckets, size_of::<u128>(), Resource::ProgramBytes)?,
            Resource::ProgramBytes,
        )
    }
}

/// Whether a one-owner plan has the complete fixed-prefix proof needed by the
/// shared `memchr` scheduler.
///
/// Uniform capture Count uses this construction-retained shape to choose
/// between otherwise valid executors before source access. Requiring the full
/// filter window keeps that choice limited to plans whose candidate density is
/// bounded by a strong eight-byte prefix. The construction-retained shared
/// anchor descriptor already proves the scheduler's one-to-three-byte anchor
/// requirement, so route selection does not repeat the bucket census.
pub(crate) fn has_complete_shared_fixed_filter(plan: &Plan) -> bool {
    let [entry] = &*plan.entries else {
        return false;
    };
    entry.min_offset == entry.max_offset
        && entry.check_len == MAX_FILTER_CHECKS
        && plan.has_shared_fixed()
}

pub(crate) fn exact_drafts(capacity: usize) -> Result<ExactVec<Draft>, Error> {
    ExactVec::try_with_capacity(capacity)
        .map_err(|error| allocation_error(error, Resource::ProgramBytes, capacity))
}

pub(crate) fn exact_entries(capacity: usize) -> Result<ExactVec<Entry>, Error> {
    ExactVec::try_with_capacity(capacity)
        .map_err(|error| allocation_error(error, Resource::ProgramBytes, capacity))
}

pub(crate) fn exact_buckets() -> Result<ExactVec<u128>, Error> {
    ExactVec::try_with_capacity(BUCKETS)
        .map_err(|error| allocation_error(error, Resource::ProgramBytes, BUCKETS))
}

pub(crate) const fn bucket_count() -> usize {
    BUCKETS
}

pub(crate) fn executable_for(program: &Program) -> bool {
    executable_shape(
        program.insts.len(),
        program.contains_scalar_transition(),
        program.contains_unicode_word_boundary(),
    )
}

fn executable_shape(states: usize, scalar: bool, unicode_word: bool) -> bool {
    u16::try_from(states).is_ok() && !scalar && !unicode_word
}

fn owner_bit(ordinal: usize) -> Result<u128, Error> {
    let shift = u32::try_from(ordinal)
        .map_err(|_| Error::InternalInvariant("candidate owner ordinal exceeds shift width"))?;
    1_u128
        .checked_shl(shift)
        .ok_or(Error::InternalInvariant("candidate owner outside mask"))
}

fn take_owner(owners: &mut u128) -> Result<usize, Error> {
    if *owners == 0 {
        return Err(Error::InternalInvariant("candidate owner mask is empty"));
    }
    let ordinal = usize::try_from(owners.trailing_zeros())
        .map_err(|_| Error::InternalInvariant("candidate owner ordinal does not fit usize"))?;
    *owners &= owners.saturating_sub(1);
    Ok(ordinal)
}

fn ring_slot(index: usize, length: usize) -> Result<usize, Error> {
    index.checked_rem(length).ok_or(Error::InternalInvariant(
        "candidate schedule ring has zero length",
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReductionKind {
    Count,
    SpanSum,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReductionResult {
    pub(crate) matches: usize,
    pub(crate) span_sum: usize,
    pub(crate) candidates: usize,
    pub(crate) accounting: ExecutionAccounting,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReductionAttemptError {
    pub(crate) source: Error,
    pub(crate) accounting: ExecutionAccounting,
    pub(crate) actual_allocations: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StartDomainResult {
    pub(crate) matches: usize,
    pub(crate) events: usize,
    pub(crate) suppressed: usize,
    pub(crate) span_sum: usize,
    pub(crate) accounting: ExecutionAccounting,
    pub(crate) actual_allocations: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StartDomainAttemptError {
    pub(crate) source: Error,
    pub(crate) accounting: ExecutionAccounting,
    pub(crate) actual_allocations: usize,
}

pub(crate) const START_DOMAIN_EXECUTION_ALLOCATIONS: usize = 4;

#[allow(
    clippy::too_many_lines,
    reason = "candidate execution keeps validation, metering, scheduling and ordered draining visible"
)]
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "the legacy internal entry point remains as a compatibility delegate"
    )
)]
pub(crate) fn count(
    plan: &Plan,
    program: &Program,
    haystack: &[u8],
    range: Range<usize>,
    limits: OperationLimits,
) -> Result<ReductionResult, Error> {
    count_attempt(plan, program, haystack, range, limits).map_err(|error| error.source)
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "the Count-specific internal entry point remains as a compatibility delegate"
    )
)]
#[allow(
    clippy::result_large_err,
    reason = "the compatibility entry point preserves the complete terminal execution ledger"
)]
pub(crate) fn count_attempt(
    plan: &Plan,
    program: &Program,
    haystack: &[u8],
    range: Range<usize>,
    limits: OperationLimits,
) -> Result<ReductionResult, ReductionAttemptError> {
    reduce_attempt(ReductionKind::Count, plan, program, haystack, range, limits)
}

#[allow(
    clippy::result_large_err,
    clippy::too_many_lines,
    reason = "candidate execution and its deliberate full-ledger error keep validation, metering, scheduling, ordered draining and terminal accounting visible"
)]
pub(crate) fn reduce_attempt(
    kind: ReductionKind,
    plan: &Plan,
    program: &Program,
    haystack: &[u8],
    range: Range<usize>,
    limits: OperationLimits,
) -> Result<ReductionResult, ReductionAttemptError> {
    if range.start > range.end || range.end > haystack.len() {
        return Err(ReductionAttemptError {
            source: Error::InvalidRange {
                start: range.start,
                end: range.end,
                haystack_len: haystack.len(),
            },
            accounting: ExecutionAccounting::default(),
            actual_allocations: 0,
        });
    }
    if plan.entries.is_empty()
        || plan.entries.len() > MAX_ENTRIES
        || plan.buckets.len() != BUCKETS
        || plan.global_buckets.len() != BUCKETS
        || !executable_for(program)
    {
        return Err(ReductionAttemptError {
            source: Error::InternalInvariant(
                "candidate plan no longer matches its byte-program proof",
            ),
            accounting: ExecutionAccounting::default(),
            actual_allocations: 0,
        });
    }
    let local = &haystack[range.clone()];
    let boundaries =
        add(local.len(), 1, Resource::Boundaries).map_err(|source| ReductionAttemptError {
            source,
            accounting: ExecutionAccounting::default(),
            actual_allocations: 0,
        })?;
    enforce(boundaries, limits.max_boundaries, Resource::Boundaries).map_err(|source| {
        ReductionAttemptError {
            source,
            accounting: ExecutionAccounting::default(),
            actual_allocations: 0,
        }
    })?;
    let assertions =
        AssertionContext::new(haystack, range.start, local.len()).map_err(|source| {
            ReductionAttemptError {
                source,
                accounting: ExecutionAccounting::default(),
                actual_allocations: 0,
            }
        })?;
    let mut meter = Meter::new(limits);
    let mut allocations = AllocationLedger::default();
    let mut matches = 0_usize;
    let mut span_sum = 0_usize;
    let mut candidates = 0_usize;
    let result = (|| {
        let shared_fixed = plan.shared_fixed()?;
        // A shared fixed anchor is drained immediately and therefore has only
        // one live start. Retain the offset-sized ring solely for the generic
        // interval scheduler, where starts remain live until its safe
        // frontier advances.
        let schedule = if shared_fixed.is_some() {
            1
        } else {
            add(plan.max_offset(), 1, Resource::ScratchBytes)?
        };
        let mut workspace =
            Workspace::new(program.insts.len(), schedule, &mut meter, &mut allocations)?;
        let mut cursor = 0_usize;

        if let Some(fixed) = shared_fixed {
            // Preserve the mandatory global proof used by the generic
            // scheduler. A strong fixed prefix can still occur densely while
            // another byte sequence required by every match is absent. In
            // that case, proving the owner absent before the anchor scan
            // avoids pointless (and potentially long) program verification.
            let eligible = globally_present_owners(plan, local, &mut meter)?;
            if eligible == 0 {
                if workspace.bytes != allocations.bytes {
                    return Err(Error::InternalInvariant(
                        "shared fixed candidate workspace diverged from allocation ledger",
                    ));
                }
                return Ok(());
            }
            // The whole source scan is admitted before memchr can touch the
            // source. Each returned position then retains the same fixed
            // filter, assertion, candidate-event and verifier accounting as
            // the generic scheduler. Owners sharing a fixed offset and at
            // most three anchor bytes also share monotonically increasing
            // starts, so absent starts are never materialized or drained.
            meter.charge_work(local.len())?;
            meter.charge_sequential(local.len())?;
            let mut scan = 0_usize;
            while let Some(position) = fixed.find(local, scan)? {
                scan = add(position, 1, Resource::Boundaries)?;
                let byte = *local.get(position).ok_or(Error::InternalInvariant(
                    "shared fixed anchor outside source",
                ))?;
                let mut owners =
                    *plan
                        .buckets
                        .get(usize::from(byte))
                        .ok_or(Error::InternalInvariant(
                            "shared fixed anchor outside bucket table",
                        ))?
                        & fixed.owners
                        & eligible;
                let mut scheduled_owners = 0_u128;
                while owners != 0 {
                    meter.charge_work(1)?; // one owner selection
                    let ordinal = take_owner(&mut owners)?;
                    let entry = plan.entries.get(ordinal).ok_or(Error::InternalInvariant(
                        "shared fixed candidate owner outside entries",
                    ))?;
                    if !filter_matches(entry, local, position, &mut meter)?
                        || position < entry.min_offset
                    {
                        continue;
                    }
                    meter.charge_work(1)?; // one fixed candidate publication
                    let start =
                        position
                            .checked_sub(entry.min_offset)
                            .ok_or(Error::InternalInvariant(
                                "shared fixed candidate offset underflow",
                            ))?;
                    if let Some(assertion) = entry.leading_assertion {
                        meter.charge_assertion()?;
                        meter
                            .charge_random(assertions.candidate_source_bytes(assertion, start)?)?;
                        if !assertions.is_match(assertion, start)? {
                            continue;
                        }
                    }
                    let required = add(candidates, 1, Resource::MatchEvents)?;
                    enforce(required, limits.max_match_events, Resource::MatchEvents)?;
                    candidates = required;
                    scheduled_owners |= owner_bit(ordinal)?;
                }
                if scheduled_owners == 0 {
                    continue;
                }
                let start = position
                    .checked_sub(fixed.offset)
                    .ok_or(Error::InternalInvariant(
                        "shared fixed candidate offset underflow",
                    ))?;
                let slot = ring_slot(start, workspace.schedule.len())?;
                let scheduled =
                    workspace
                        .schedule
                        .get_mut(slot)
                        .ok_or(Error::InternalInvariant(
                            "shared fixed candidate schedule slot outside ring",
                        ))?;
                if *scheduled != 0 {
                    return Err(Error::InternalInvariant(
                        "shared fixed candidate reused a live schedule slot",
                    ));
                }
                *scheduled = scheduled_owners;
                process_start(
                    plan,
                    program,
                    local,
                    assertions,
                    start,
                    &mut cursor,
                    &mut matches,
                    &mut span_sum,
                    kind,
                    &mut workspace,
                    &mut meter,
                )?;
            }
            if workspace.bytes != allocations.bytes {
                return Err(Error::InternalInvariant(
                    "shared fixed candidate workspace diverged from allocation ledger",
                ));
            }
            return Ok(());
        }

        let mut next_start = 0_usize;
        let eligible = globally_present_owners(plan, local, &mut meter)?;

        for position in 0..local.len() {
            meter.charge_work(1)?; // one source/bucket visit
            meter.charge_sequential(1)?;
            let byte = *local.get(position).ok_or(Error::InternalInvariant(
                "candidate source position outside range",
            ))?;
            let mut owners = *plan
                .buckets
                .get(usize::from(byte))
                .ok_or(Error::InternalInvariant("candidate bucket outside table"))?;
            owners &= eligible;
            while owners != 0 {
                meter.charge_work(1)?; // one owner selection
                let ordinal = take_owner(&mut owners)?;
                let entry = plan
                    .entries
                    .get(ordinal)
                    .ok_or(Error::InternalInvariant("candidate owner outside entries"))?;
                if !filter_matches(entry, local, position, &mut meter)? {
                    continue;
                }
                if position < entry.min_offset {
                    continue;
                }
                let first = position.saturating_sub(entry.max_offset);
                let last =
                    position
                        .checked_sub(entry.min_offset)
                        .ok_or(Error::InternalInvariant(
                            "candidate minimum offset underflow",
                        ))?;
                for start in first.max(next_start)..=last {
                    meter.charge_work(1)?; // one candidate-interval publication attempt
                    if let Some(assertion) = entry.leading_assertion {
                        meter.charge_assertion()?;
                        meter
                            .charge_random(assertions.candidate_source_bytes(assertion, start)?)?;
                        if !assertions.is_match(assertion, start)? {
                            continue;
                        }
                    }
                    let slot = ring_slot(start, workspace.schedule.len())?;
                    let owner = owner_bit(ordinal)?;
                    let scheduled =
                        workspace
                            .schedule
                            .get_mut(slot)
                            .ok_or(Error::InternalInvariant(
                                "candidate schedule slot outside ring",
                            ))?;
                    if *scheduled & owner == 0 {
                        let required = add(candidates, 1, Resource::MatchEvents)?;
                        enforce(required, limits.max_match_events, Resource::MatchEvents)?;
                        candidates = required;
                        *scheduled |= owner;
                    }
                }
            }
            if position >= plan.max_offset() {
                let safe_through =
                    position
                        .checked_sub(plan.max_offset())
                        .ok_or(Error::InternalInvariant(
                            "candidate safe frontier underflow",
                        ))?;
                while next_start <= safe_through {
                    process_start(
                        plan,
                        program,
                        local,
                        assertions,
                        next_start,
                        &mut cursor,
                        &mut matches,
                        &mut span_sum,
                        kind,
                        &mut workspace,
                        &mut meter,
                    )?;
                    next_start = add(next_start, 1, Resource::Boundaries)?;
                }
            }
        }
        while next_start < local.len() {
            process_start(
                plan,
                program,
                local,
                assertions,
                next_start,
                &mut cursor,
                &mut matches,
                &mut span_sum,
                kind,
                &mut workspace,
                &mut meter,
            )?;
            next_start = add(next_start, 1, Resource::Boundaries)?;
        }
        if workspace.bytes != allocations.bytes {
            return Err(Error::InternalInvariant(
                "candidate workspace diverged from allocation ledger",
            ));
        }
        Ok(())
    })();
    let accounting = candidate_attempt_accounting(&meter, allocations.bytes, candidates, matches);
    match result {
        Ok(()) => Ok(ReductionResult {
            matches,
            span_sum,
            candidates,
            accounting,
        }),
        Err(source) => Err(ReductionAttemptError {
            source,
            accounting,
            actual_allocations: allocations.count,
        }),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SharedFixedAnchors {
    bytes: [u8; 3],
    len: usize,
    offset: usize,
    owners: u128,
}

impl SharedFixedAnchors {
    fn find(self, haystack: &[u8], start: usize) -> Result<Option<usize>, Error> {
        let remaining = haystack.get(start..).ok_or(Error::InternalInvariant(
            "shared fixed scan cursor outside source",
        ))?;
        let relative = match self.len {
            1 => memchr::memchr(self.bytes[0], remaining),
            2 => memchr::memchr2(self.bytes[0], self.bytes[1], remaining),
            3 => memchr::memchr3(self.bytes[0], self.bytes[1], self.bytes[2], remaining),
            _ => {
                return Err(Error::InternalInvariant(
                    "shared fixed anchor count outside memchr support",
                ));
            }
        };
        relative
            .map(|relative| add(start, relative, Resource::Boundaries))
            .transpose()
    }
}

fn complete_owner_mask(entries: usize) -> Result<u128, Error> {
    if entries == MAX_ENTRIES {
        Ok(u128::MAX)
    } else {
        Ok(owner_bit(entries)?.saturating_sub(1))
    }
}

pub(crate) fn shared_fixed_anchors(
    entries: &[Entry],
    buckets: &[u128],
) -> Result<Option<SharedFixedAnchors>, Error> {
    let Some(entry) = entries.first() else {
        return Ok(None);
    };
    let fixed_offset = entry.min_offset;
    if entries
        .iter()
        .any(|entry| entry.min_offset != fixed_offset || entry.max_offset != fixed_offset)
    {
        return Ok(None);
    }
    let all = complete_owner_mask(entries.len())?;
    let mut bytes = [0_u8; 3];
    let mut len = 0_usize;
    let mut observed_owners = 0_u128;
    for (byte, &owners) in buckets.iter().enumerate() {
        if owners == 0 {
            continue;
        }
        if owners & !all != 0 || len == bytes.len() {
            return Ok(None);
        }
        bytes[len] = u8::try_from(byte)
            .map_err(|_| Error::InternalInvariant("candidate bucket byte exceeds u8"))?;
        len = add(len, 1, Resource::ExecutionWork)?;
        observed_owners |= owners;
    }
    if observed_owners != all || len == 0 {
        return Ok(None);
    }
    Ok(Some(SharedFixedAnchors {
        bytes,
        len,
        offset: fixed_offset,
        owners: all,
    }))
}

#[allow(
    clippy::result_large_err,
    clippy::too_many_lines,
    reason = "start-domain execution keeps range validation, exact metering, empty-match suppression and terminal accounting in one auditable scope"
)]
pub(crate) fn start_domain_attempt(
    program: &Program,
    haystack: &[u8],
    range: Range<usize>,
    start_domain: StartDomain,
    enforce_span_sum: bool,
    limits: OperationLimits,
) -> Result<StartDomainResult, StartDomainAttemptError> {
    if range.start > range.end || range.end > haystack.len() {
        return Err(StartDomainAttemptError {
            source: Error::InvalidRange {
                start: range.start,
                end: range.end,
                haystack_len: haystack.len(),
            },
            accounting: ExecutionAccounting::default(),
            actual_allocations: 0,
        });
    }
    if !start_domain.is_sparse() || !executable_for(program) {
        return Err(StartDomainAttemptError {
            source: Error::InternalInvariant(
                "start-domain route requires a sparse byte-program proof",
            ),
            accounting: ExecutionAccounting::default(),
            actual_allocations: 0,
        });
    }
    let local = &haystack[range.clone()];
    let boundaries =
        add(local.len(), 1, Resource::Boundaries).map_err(|source| StartDomainAttemptError {
            source,
            accounting: ExecutionAccounting::default(),
            actual_allocations: 0,
        })?;
    enforce(boundaries, limits.max_boundaries, Resource::Boundaries).map_err(|source| {
        StartDomainAttemptError {
            source,
            accounting: ExecutionAccounting::default(),
            actual_allocations: 0,
        }
    })?;
    let assertions =
        AssertionContext::new(haystack, range.start, local.len()).map_err(|source| {
            StartDomainAttemptError {
                source,
                accounting: ExecutionAccounting::default(),
                actual_allocations: 0,
            }
        })?;
    let mut meter = Meter::new(limits);
    let mut allocations = AllocationLedger::default();
    let mut root_probes = 0_usize;
    let mut events = 0_usize;
    let mut matches = 0_usize;
    let mut suppressed = 0_usize;
    let mut span_sum = 0_usize;
    let result = (|| {
        let mut workspace = Workspace::new(program.insts.len(), 0, &mut meter, &mut allocations)?;
        let mut cursor = 0_usize;
        let mut previous_end = None;
        while cursor <= local.len() {
            let Some(start) =
                next_domain_start(start_domain, assertions, cursor, local.len(), &mut meter)?
            else {
                break;
            };
            meter.charge_work(1)?; // one admitted root service
            root_probes = add(root_probes, 1, Resource::ExecutionWork)?;
            let Some(end) = verify_entry_at(
                program,
                local,
                assertions,
                program.entry,
                start,
                &mut workspace,
                &mut meter,
            )?
            else {
                cursor = add(start, 1, Resource::Boundaries)?;
                continue;
            };
            if end < start || end > local.len() {
                return Err(Error::InternalInvariant(
                    "start-domain verifier published an endpoint outside its range",
                ));
            }
            meter.charge_work(1)?; // one match-event service
            let required_events = add(events, 1, Resource::MatchEvents)?;
            enforce(
                required_events,
                limits.max_match_events,
                Resource::MatchEvents,
            )?;
            events = required_events;
            if start == end && previous_end == Some(start) {
                suppressed = add(suppressed, 1, Resource::MatchEvents)?;
                cursor = add(start, 1, Resource::Boundaries)?;
                continue;
            }
            let required_matches = add(matches, 1, Resource::OutputMatches)?;
            enforce(
                required_matches,
                limits.max_output_matches,
                Resource::OutputMatches,
            )?;
            matches = required_matches;
            let width = end.checked_sub(start).ok_or(Error::InternalInvariant(
                "start-domain endpoint precedes its start",
            ))?;
            let required_span_sum = add(span_sum, width, Resource::SpanSum)?;
            if enforce_span_sum {
                enforce(required_span_sum, limits.max_span_sum, Resource::SpanSum)?;
            }
            span_sum = required_span_sum;
            previous_end = Some(end);
            cursor = end;
        }
        if workspace.bytes != allocations.bytes {
            return Err(Error::InternalInvariant(
                "start-domain workspace diverged from allocation ledger",
            ));
        }
        if allocations.count != START_DOMAIN_EXECUTION_ALLOCATIONS {
            return Err(Error::InternalInvariant(
                "start-domain workspace changed its allocation census",
            ));
        }
        Ok(())
    })();
    let accounting = start_domain_attempt_accounting(
        &meter,
        allocations.bytes,
        root_probes,
        events,
        matches,
        suppressed,
    );
    match result {
        Ok(()) => Ok(StartDomainResult {
            matches,
            events,
            suppressed,
            span_sum,
            accounting,
            actual_allocations: allocations.count,
        }),
        Err(source) => Err(StartDomainAttemptError {
            source,
            accounting,
            actual_allocations: allocations.count,
        }),
    }
}

fn next_domain_start(
    start_domain: StartDomain,
    assertions: AssertionContext<'_>,
    from: usize,
    local_len: usize,
    meter: &mut Meter,
) -> Result<Option<usize>, Error> {
    let assertion = start_domain.assertion().ok_or(Error::InternalInvariant(
        "start-domain scan received the unrestricted domain",
    ))?;
    if start_domain == StartDomain::AbsoluteStart && from > 0 {
        return Ok(None);
    }
    let mut position = from;
    while position <= local_len {
        meter.charge_work(1)?; // one proof-domain boundary visit
        meter.charge_assertion()?;
        let matched =
            assertions.is_match_with_source_accesses(assertion, position, |source_bytes| {
                meter.charge_random(source_bytes)
            })?;
        if matched {
            return Ok(Some(position));
        }
        if start_domain == StartDomain::AbsoluteStart {
            return Ok(None);
        }
        position = add(position, 1, Resource::Boundaries)?;
    }
    Ok(None)
}

fn start_domain_attempt_accounting(
    meter: &Meter,
    workspace_bytes: usize,
    root_probes: usize,
    events: usize,
    matches: usize,
    suppressed: usize,
) -> ExecutionAccounting {
    ExecutionAccounting {
        root_probes,
        successful_paths: events,
        suppressed_empty: suppressed,
        emitted_matches: matches,
        sequential_bytes_read: meter.sequential,
        random_access_bytes_read: meter.random,
        random_access_peak_bytes: workspace_bytes,
        scratch_peak_bytes: workspace_bytes,
        peak_bytes: workspace_bytes,
        state_evaluations: meter.states,
        transition_checks: meter.transitions,
        assertion_checks: meter.assertions,
        work: meter.work,
        ..ExecutionAccounting::default()
    }
}

pub(crate) fn start_domain_workspace_bytes(program: &Program) -> Result<usize, Error> {
    workspace_bytes(program.insts.len(), 0)
}

pub(crate) fn packed_shape(
    max_offset: usize,
    shared_fixed: Option<SharedFixedAnchors>,
) -> Result<usize, Error> {
    if max_offset > MAX_OFFSET {
        return Err(Error::InternalInvariant(
            "candidate maximum offset exceeds packed shape",
        ));
    }
    #[cfg(not(target_pointer_width = "64"))]
    {
        let _ = shared_fixed;
        Ok(max_offset)
    }
    #[cfg(target_pointer_width = "64")]
    {
        let Some(fixed) = shared_fixed else {
            return Ok(max_offset);
        };
        if fixed.offset != max_offset
            || !(1..=fixed.bytes.len()).contains(&fixed.len)
            || fixed.owners == 0
        {
            return Err(Error::InternalInvariant(
                "shared fixed candidate cannot be packed",
            ));
        }
        let mut shape = add(
            max_offset,
            mul(fixed.len, SHAPE_LENGTH_RADIX, Resource::ProgramBytes)?,
            Resource::ProgramBytes,
        )?;
        for (&byte, radix) in fixed.bytes.iter().zip(SHAPE_BYTE_RADICES) {
            shape = add(
                shape,
                mul(usize::from(byte), radix, Resource::ProgramBytes)?,
                Resource::ProgramBytes,
            )?;
        }
        Ok(shape)
    }
}

fn filter_matches(
    entry: &Entry,
    haystack: &[u8],
    anchor: usize,
    meter: &mut Meter,
) -> Result<bool, Error> {
    filter_checks(&entry.checks, entry.check_len, haystack, anchor, meter)
}

fn globally_present_owners(plan: &Plan, haystack: &[u8], meter: &mut Meter) -> Result<u128, Error> {
    meter.charge_work(2)?; // owner census validation and complete-mask derivation
    let all = if plan.entries.len() == MAX_ENTRIES {
        u128::MAX
    } else {
        owner_bit(plan.entries.len())?.saturating_sub(1)
    };
    let mut present = 0_u128;
    for position in 0..haystack.len() {
        meter.charge_work(1)?;
        meter.charge_sequential(1)?;
        let byte = *haystack.get(position).ok_or(Error::InternalInvariant(
            "candidate global source position outside range",
        ))?;
        let mut owners =
            *plan
                .global_buckets
                .get(usize::from(byte))
                .ok_or(Error::InternalInvariant(
                    "candidate global bucket outside table",
                ))?
                & !present;
        while owners != 0 {
            meter.charge_work(1)?;
            let ordinal = take_owner(&mut owners)?;
            let owner = owner_bit(ordinal)?;
            let entry = plan.entries.get(ordinal).ok_or(Error::InternalInvariant(
                "candidate global owner outside entries",
            ))?;
            if filter_checks(
                &entry.global_checks,
                entry.global_check_len,
                haystack,
                position,
                meter,
            )? {
                present |= owner;
                if present == all {
                    return Ok(present);
                }
            }
        }
    }
    Ok(present)
}

fn filter_checks(
    checks: &[FilterCheck; MAX_FILTER_CHECKS],
    check_len: usize,
    haystack: &[u8],
    anchor: usize,
    meter: &mut Meter,
) -> Result<bool, Error> {
    if check_len > checks.len() {
        return Err(Error::InternalInvariant(
            "candidate filter length outside fixed checks",
        ));
    }
    for check in &checks[..check_len] {
        meter.charge_work(2)?; // signed position and membership comparison
        let position = if check.relative < 0 {
            anchor.checked_sub(usize::from(check.relative.unsigned_abs()))
        } else {
            anchor.checked_add(usize::from(check.relative.unsigned_abs()))
        };
        let Some(position) = position else {
            return Ok(false);
        };
        if position >= haystack.len() {
            return Ok(false);
        }
        meter.charge_random(1)?;
        if !check.bytes.contains(haystack[position]) {
            return Ok(false);
        }
    }
    Ok(true)
}

#[allow(
    clippy::too_many_arguments,
    reason = "candidate start processing keeps every mutable resource ledger explicit"
)]
fn process_start(
    plan: &Plan,
    program: &Program,
    haystack: &[u8],
    assertions: AssertionContext<'_>,
    start: usize,
    cursor: &mut usize,
    matches: &mut usize,
    span_sum: &mut usize,
    kind: ReductionKind,
    workspace: &mut Workspace,
    meter: &mut Meter,
) -> Result<(), Error> {
    meter.charge_work(1)?; // one scheduled-start visit
    let slot = ring_slot(start, workspace.schedule.len())?;
    let owners = *workspace
        .schedule
        .get(slot)
        .ok_or(Error::InternalInvariant(
            "candidate drain outside schedule ring",
        ))?;
    *workspace
        .schedule
        .get_mut(slot)
        .ok_or(Error::InternalInvariant(
            "candidate clear outside schedule ring",
        ))? = 0;
    if start < *cursor {
        return Ok(());
    }
    let mut remaining = owners;
    while remaining != 0 {
        meter.charge_work(1)?;
        let ordinal = take_owner(&mut remaining)?;
        let entry = plan.entries.get(ordinal).ok_or(Error::InternalInvariant(
            "candidate verifier owner outside entries",
        ))?;
        if let Some(end) = verify_entry_at(
            program, haystack, assertions, entry.pc, start, workspace, meter,
        )? {
            if end <= start || end > haystack.len() {
                return Err(Error::InternalInvariant(
                    "candidate verifier published an invalid nonempty span",
                ));
            }
            let required = add(*matches, 1, Resource::OutputMatches)?;
            enforce(
                required,
                meter.limits.max_output_matches,
                Resource::OutputMatches,
            )?;
            let required_span_sum = match kind {
                ReductionKind::Count => *span_sum,
                ReductionKind::SpanSum => {
                    let width = end.checked_sub(start).ok_or(Error::InternalInvariant(
                        "candidate match endpoint precedes start",
                    ))?;
                    let required = add(*span_sum, width, Resource::SpanSum)?;
                    enforce(required, meter.limits.max_span_sum, Resource::SpanSum)?;
                    required
                }
            };
            *matches = required;
            *span_sum = required_span_sum;
            *cursor = end;
            return Ok(());
        }
    }
    Ok(())
}

#[derive(Default)]
struct AllocationLedger {
    count: usize,
    bytes: usize,
}

impl AllocationLedger {
    fn record<T>(&mut self, capacity: usize) -> Result<(), Error> {
        if capacity == 0 {
            return Ok(());
        }
        self.count = add(self.count, 1, Resource::Allocations)?;
        self.bytes = add(
            self.bytes,
            mul(capacity, size_of::<T>(), Resource::ScratchBytes)?,
            Resource::ScratchBytes,
        )?;
        Ok(())
    }
}

fn candidate_attempt_accounting(
    meter: &Meter,
    workspace_bytes: usize,
    candidates: usize,
    matches: usize,
) -> ExecutionAccounting {
    ExecutionAccounting {
        root_probes: candidates,
        successful_paths: matches,
        emitted_matches: matches,
        sequential_bytes_read: meter.sequential,
        random_access_bytes_read: meter.random,
        random_access_peak_bytes: workspace_bytes,
        scratch_peak_bytes: workspace_bytes,
        peak_bytes: workspace_bytes,
        state_evaluations: meter.states,
        transition_checks: meter.transitions,
        assertion_checks: meter.assertions,
        work: meter.work,
        ..ExecutionAccounting::default()
    }
}

struct Workspace {
    schedule: ExactVec<u128>,
    stack: ExactVec<u16>,
    current: ExactVec<u16>,
    next: ExactVec<u16>,
    seen: ExactVec<u32>,
    generation: u32,
    bytes: usize,
}

fn workspace_shape(states: usize, schedule: usize) -> Result<(usize, usize), Error> {
    if states == 0 || states > usize::from(u16::MAX) {
        return Err(Error::InternalInvariant(
            "candidate verifier state count outside compact workspace",
        ));
    }
    let stack = add(
        mul(states, 2, Resource::ScratchBytes)?,
        1,
        Resource::ScratchBytes,
    )?;
    let bytes = add(
        mul(schedule, size_of::<u128>(), Resource::ScratchBytes)?,
        add(
            mul(
                add(
                    stack,
                    mul(states, 2, Resource::ScratchBytes)?,
                    Resource::ScratchBytes,
                )?,
                size_of::<u16>(),
                Resource::ScratchBytes,
            )?,
            mul(states, size_of::<u32>(), Resource::ScratchBytes)?,
            Resource::ScratchBytes,
        )?,
        Resource::ScratchBytes,
    )?;
    Ok((stack, bytes))
}

fn workspace_bytes(states: usize, schedule: usize) -> Result<usize, Error> {
    workspace_shape(states, schedule).map(|(_, bytes)| bytes)
}

impl Workspace {
    fn new(
        states: usize,
        schedule: usize,
        meter: &mut Meter,
        allocations: &mut AllocationLedger,
    ) -> Result<Self, Error> {
        let (stack, bytes) = workspace_shape(states, schedule)?;
        enforce(
            bytes,
            meter.limits.max_scratch_bytes,
            Resource::ScratchBytes,
        )?;
        enforce(bytes, meter.limits.max_peak_bytes, Resource::PeakBytes)?;
        enforce(
            bytes,
            meter.limits.max_random_access_bytes,
            Resource::RandomAccessBytes,
        )?;
        let initialized = add(
            add(schedule, stack, Resource::ExecutionWork)?,
            mul(states, 3, Resource::ExecutionWork)?,
            Resource::ExecutionWork,
        )?;
        meter.charge_work(initialized)?;
        Ok(Self {
            schedule: exact_filled(schedule, 0_u128, Resource::ScratchBytes, allocations)?,
            stack: exact_filled(stack, 0_u16, Resource::ScratchBytes, allocations)?,
            current: exact_filled(states, 0_u16, Resource::ScratchBytes, allocations)?,
            next: exact_filled(states, 0_u16, Resource::ScratchBytes, allocations)?,
            seen: exact_filled(states, 0_u32, Resource::ScratchBytes, allocations)?,
            generation: 0,
            bytes,
        })
    }

    fn next_generation(&mut self, meter: &mut Meter) -> Result<u32, Error> {
        if self.generation == u32::MAX {
            meter.charge_work(self.seen.len())?;
            self.seen.fill(0);
            self.generation = 0;
        }
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow {
                resource: Resource::ExecutionWork,
            })?;
        Ok(self.generation)
    }
}

fn exact_filled<T: Copy>(
    length: usize,
    value: T,
    resource: Resource,
    allocations: &mut AllocationLedger,
) -> Result<ExactVec<T>, Error> {
    let mut output = ExactVec::try_with_capacity(length)
        .map_err(|error| allocation_error(error, resource, length))?;
    allocations.record::<T>(output.capacity())?;
    for _ in 0..length {
        output
            .try_push(value)
            .map_err(|_| Error::InternalInvariant("candidate exact allocation filled early"))?;
    }
    Ok(output)
}

fn allocation_error(error: CopyError, resource: Resource, items: usize) -> Error {
    match error {
        CopyError::LayoutOverflow => Error::ArithmeticOverflow { resource },
        CopyError::AllocationFailed => Error::AllocationFailed { resource, items },
    }
}

fn push(buffer: &mut [u16], length: &mut usize, value: usize) -> Result<(), Error> {
    let slot = buffer.get_mut(*length).ok_or(Error::InternalInvariant(
        "candidate traversal stack exceeded its exact census",
    ))?;
    *slot = u16::try_from(value).map_err(|_| Error::ArithmeticOverflow {
        resource: Resource::ProgramStates,
    })?;
    *length = add(*length, 1, Resource::ProgramStates)?;
    Ok(())
}

fn verify_entry_at(
    program: &Program,
    haystack: &[u8],
    assertions: AssertionContext<'_>,
    entry_pc: usize,
    start: usize,
    workspace: &mut Workspace,
    meter: &mut Meter,
) -> Result<Option<usize>, Error> {
    let mut current_len = 0_usize;
    let generation = workspace.next_generation(meter)?;
    add_closure(
        program,
        assertions,
        entry_pc,
        start,
        ClosureBuffers {
            output: &mut workspace.current,
            output_len: &mut current_len,
            stack: &mut workspace.stack,
            seen: &mut workspace.seen,
            generation,
        },
        meter,
    )?;
    let mut position = start;
    let mut pending = None;
    loop {
        meter.charge_work(1)?;
        let source = if position < haystack.len() {
            meter.charge_work(1)?;
            meter.charge_random(1)?;
            Some(haystack[position])
        } else {
            None
        };
        let generation = workspace.next_generation(meter)?;
        let mut next_len = 0_usize;
        for index in 0..current_len {
            meter.charge_state()?;
            meter.charge_work(1)?; // instruction dispatch
            let pc = usize::from(workspace.current[index]);
            match program.instruction(pc)? {
                Inst::Match => {
                    pending = Some(position);
                    break;
                }
                Inst::Consume { bytes, next } => {
                    meter.charge_transition()?;
                    if source.is_some_and(|byte| bytes.contains(byte)) {
                        let next_position = add(position, 1, Resource::Boundaries)?;
                        add_closure(
                            program,
                            assertions,
                            *next,
                            next_position,
                            ClosureBuffers {
                                output: &mut workspace.next,
                                output_len: &mut next_len,
                                stack: &mut workspace.stack,
                                seen: &mut workspace.seen,
                                generation,
                            },
                            meter,
                        )?;
                    }
                }
                Inst::ConsumeScalar { .. } => {
                    return Err(Error::InternalInvariant(
                        "candidate verifier reached a scalar transition",
                    ));
                }
                Inst::Unfilled
                | Inst::Fail
                | Inst::Assert { .. }
                | Inst::Split { .. }
                | Inst::RootSplit { .. } => {
                    return Err(Error::InternalInvariant(
                        "candidate closure published an epsilon state",
                    ));
                }
            }
        }
        if next_len == 0 {
            return Ok(pending);
        }
        position = add(position, 1, Resource::Boundaries)?;
        core::mem::swap(&mut workspace.current, &mut workspace.next);
        current_len = next_len;
    }
}

struct ClosureBuffers<'a> {
    output: &'a mut [u16],
    output_len: &'a mut usize,
    stack: &'a mut [u16],
    seen: &'a mut [u32],
    generation: u32,
}

fn add_closure(
    program: &Program,
    assertions: AssertionContext<'_>,
    initial: usize,
    position: usize,
    buffers: ClosureBuffers<'_>,
    meter: &mut Meter,
) -> Result<(), Error> {
    let ClosureBuffers {
        output,
        output_len,
        stack,
        seen,
        generation,
    } = buffers;
    let mut stack_len = 0_usize;
    meter.charge_work(1)?;
    push(stack, &mut stack_len, initial)?;
    while stack_len != 0 {
        meter.charge_work(1)?; // stack pop and seen comparison
        stack_len = stack_len.checked_sub(1).ok_or(Error::InternalInvariant(
            "candidate closure stack underflowed",
        ))?;
        let pc = usize::from(stack[stack_len]);
        let marker = seen.get_mut(pc).ok_or(Error::InternalInvariant(
            "candidate closure PC outside program",
        ))?;
        if *marker == generation {
            continue;
        }
        *marker = generation;
        meter.charge_state()?;
        match program.instruction(pc)? {
            Inst::Unfilled => {
                return Err(Error::InternalInvariant(
                    "candidate closure reached unfilled state",
                ));
            }
            Inst::Fail => {}
            Inst::Match | Inst::Consume { .. } => {
                meter.charge_work(1)?;
                push(output, output_len, pc)?;
            }
            Inst::ConsumeScalar { .. } => {
                return Err(Error::InternalInvariant(
                    "candidate closure reached scalar transition",
                ));
            }
            Inst::Assert { assertion, next } => {
                meter.charge_assertion()?;
                meter.charge_work(1)?; // predicate branch/publication
                let matched = assertions.is_match_with_source_accesses(
                    *assertion,
                    position,
                    |source_bytes| meter.charge_random(source_bytes),
                )?;
                if matched {
                    push(stack, &mut stack_len, *next)?;
                }
            }
            Inst::Split {
                preferred,
                fallback,
            }
            | Inst::RootSplit {
                preferred,
                fallback,
            } => {
                meter.charge_transition()?;
                meter.charge_work(1)?; // second successor publication
                push(stack, &mut stack_len, *fallback)?;
                push(stack, &mut stack_len, *preferred)?;
            }
        }
    }
    Ok(())
}

struct Meter {
    limits: OperationLimits,
    work: usize,
    sequential: usize,
    random: usize,
    states: usize,
    transitions: usize,
    assertions: usize,
}

impl Meter {
    const fn new(limits: OperationLimits) -> Self {
        Self {
            limits,
            work: 0,
            sequential: 0,
            random: 0,
            states: 0,
            transitions: 0,
            assertions: 0,
        }
    }

    fn charge_work(&mut self, amount: usize) -> Result<(), Error> {
        let required = add(self.work, amount, Resource::ExecutionWork)?;
        enforce(required, self.limits.max_work, Resource::ExecutionWork)?;
        self.work = required;
        Ok(())
    }

    fn charge_sequential(&mut self, amount: usize) -> Result<(), Error> {
        let required = add(self.sequential, amount, Resource::SequentialBytes)?;
        enforce(
            required,
            self.limits.max_sequential_bytes,
            Resource::SequentialBytes,
        )?;
        self.sequential = required;
        Ok(())
    }

    fn charge_random(&mut self, amount: usize) -> Result<(), Error> {
        self.random = add(self.random, amount, Resource::RandomAccessBytes)?;
        Ok(())
    }

    fn charge_state(&mut self) -> Result<(), Error> {
        self.charge_work(1)?;
        self.states = add(self.states, 1, Resource::ExecutionWork)?;
        Ok(())
    }

    fn charge_transition(&mut self) -> Result<(), Error> {
        self.charge_transitions(1)
    }

    fn charge_transitions(&mut self, amount: usize) -> Result<(), Error> {
        self.charge_work(amount)?;
        self.transitions = add(self.transitions, amount, Resource::ExecutionWork)?;
        Ok(())
    }

    fn charge_assertion(&mut self) -> Result<(), Error> {
        self.charge_transition()?;
        self.assertions = add(self.assertions, 1, Resource::ExecutionWork)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use regex::bytes::RegexBuilder;
    use regex_syntax::ParserBuilder;

    use super::*;
    use crate::{CompileLimits, CompiledRegex, RustByteProfile, Strategy};

    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the fixed field count restates the object-neutral candidate plan layout"
    )]
    fn candidate_plan_keeps_route_metadata_in_the_existing_shape_word() {
        assert_eq!(
            size_of::<Plan>(),
            size_of::<ExactVec<Entry>>() * 3 + size_of::<usize>()
        );
    }

    fn compiled(pattern: &str) -> CompiledRegex {
        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(pattern)
            .unwrap();
        let compiled = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        assert!(compiled.candidate.is_some());
        compiled
    }

    fn reference(pattern: &str, haystack: &[u8]) -> usize {
        RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap()
            .find_iter(haystack)
            .count()
    }

    fn reference_span_sum(pattern: &str, haystack: &[u8]) -> usize {
        RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap()
            .find_iter(haystack)
            .map(|matched| matched.end().checked_sub(matched.start()).unwrap())
            .sum()
    }

    #[test]
    fn candidate_intervals_preserve_priority_and_invalid_byte_semantics() {
        let patterns = [
            "a|ab|x{1,3}z|q.r|[0-9]+-x",
            "ab|a|x(?:yz|y)|[0-9]{1,3}-x",
            r"\btoken.{0,3}[0-9]{2}\b|key-[a-z]+|z+",
        ];
        let alphabet = [b'a', b'b', b'x', b'y', b'z', b'q', b'r', b'0', b'-', 0xFF];
        for pattern in patterns {
            let compiled = compiled(pattern);
            let reference = RegexBuilder::new(pattern).unicode(false).build().unwrap();
            let mut haystack = Vec::new();
            for encoded in 0_usize..4_000 {
                haystack.clear();
                let mut value = encoded;
                let length = encoded % 6;
                for _ in 0..length {
                    haystack.push(alphabet[value % alphabet.len()]);
                    value /= alphabet.len();
                }
                let (expected_count, expected_span_sum) = reference.find_iter(&haystack).fold(
                    (0_usize, 0_usize),
                    |(count, sum), matched| {
                        let width = matched.end().checked_sub(matched.start()).unwrap();
                        (
                            count.checked_add(1).unwrap(),
                            sum.checked_add(width).unwrap(),
                        )
                    },
                );
                let actual_count = compiled
                    .count_value(
                        &haystack,
                        0..haystack.len(),
                        Strategy::ReverseSequentialRows,
                        OperationLimits::default(),
                    )
                    .unwrap();
                assert_eq!(
                    actual_count, expected_count,
                    "Count pattern={pattern:?} haystack={haystack:?}"
                );
                let actual_span_sum = compiled
                    .span_sum_value(
                        &haystack,
                        0..haystack.len(),
                        Strategy::ReverseSequentialRows,
                        OperationLimits::default(),
                    )
                    .unwrap();
                assert_eq!(
                    actual_span_sum, expected_span_sum,
                    "pattern={pattern:?} haystack={haystack:?}"
                );
            }
        }
        let repeated = compiled("(ab+){2}|probe");
        assert_eq!(
            repeated
                .count_value(
                    b"abbbab",
                    0..6,
                    Strategy::ReverseSequentialRows,
                    OperationLimits::default(),
                )
                .unwrap(),
            1
        );
        for (pattern, haystack) in [
            (r"\bage1[a-z]+|probe", b" age1token".as_slice()),
            (r".?\bX|probe", b" X".as_slice()),
        ] {
            let compiled = compiled(pattern);
            assert_eq!(
                compiled
                    .count_value(
                        haystack,
                        0..haystack.len(),
                        Strategy::ReverseSequentialRows,
                        OperationLimits::default(),
                    )
                    .unwrap(),
                reference(pattern, haystack),
                "leading assertion counterexample pattern={pattern:?}"
            );
        }
    }

    #[test]
    fn candidate_dispatch_falls_back_for_unsupported_program_shapes() {
        assert!(executable_shape(usize::from(u16::MAX), false, false));
        assert!(!executable_shape(usize::from(u16::MAX) + 1, false, false));
        assert!(!executable_shape(8, true, false));
        assert!(!executable_shape(8, false, true));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one table drives every exact and one-below execution resource assertion"
    )]
    fn candidate_execution_resources_are_exact_and_one_below() {
        let compiled = compiled(r"\bprefix.{0,4}Z|[0-9]{1,3}-x|ab+");
        let plan = compiled.candidate.as_ref().unwrap();
        let haystack = b"xxprefix12Z 123-x abbb no prefix----Z";
        let exact = count(
            plan,
            &compiled.program,
            haystack,
            0..haystack.len(),
            OperationLimits::default(),
        )
        .unwrap();
        assert_eq!(
            exact.matches,
            reference(r"\bprefix.{0,4}Z|[0-9]{1,3}-x|ab+", haystack)
        );
        assert!(exact.candidates > exact.matches);
        assert!(exact.accounting.state_evaluations > 0);
        assert!(exact.accounting.transition_checks > 0);
        assert!(exact.accounting.assertion_checks > 0);
        assert!(exact.accounting.transition_checks >= exact.accounting.assertion_checks);
        assert_eq!(
            exact.accounting.random_access_peak_bytes,
            plan_workspace_bytes(plan, &compiled.program)
        );
        assert!(exact.accounting.random_access_bytes_read > 0);

        let exact_limits = OperationLimits {
            max_boundaries: haystack.len() + 1,
            max_random_access_bytes: exact.accounting.random_access_peak_bytes,
            max_scratch_bytes: exact.accounting.scratch_peak_bytes,
            max_sequential_bytes: exact.accounting.sequential_bytes_read,
            max_match_events: exact.candidates,
            max_output_matches: exact.matches,
            max_peak_bytes: exact.accounting.peak_bytes,
            max_work: exact.accounting.work,
            ..OperationLimits::default()
        };
        assert_eq!(
            count(
                plan,
                &compiled.program,
                haystack,
                0..haystack.len(),
                exact_limits,
            )
            .unwrap(),
            exact
        );

        let exact_span_sum = reduce_attempt(
            ReductionKind::SpanSum,
            plan,
            &compiled.program,
            haystack,
            0..haystack.len(),
            OperationLimits::default(),
        )
        .unwrap();
        assert_eq!(exact_span_sum.matches, exact.matches);
        assert_eq!(exact_span_sum.candidates, exact.candidates);
        assert_eq!(exact_span_sum.accounting, exact.accounting);
        assert_eq!(
            exact_span_sum.span_sum,
            reference_span_sum(r"\bprefix.{0,4}Z|[0-9]{1,3}-x|ab+", haystack)
        );
        let exact_span_sum_limits = OperationLimits {
            max_span_sum: exact_span_sum.span_sum,
            ..exact_limits
        };
        assert_eq!(
            reduce_attempt(
                ReductionKind::SpanSum,
                plan,
                &compiled.program,
                haystack,
                0..haystack.len(),
                exact_span_sum_limits,
            )
            .unwrap(),
            exact_span_sum
        );
        let span_sum_one_below = OperationLimits {
            max_span_sum: exact_span_sum.span_sum - 1,
            ..exact_span_sum_limits
        };
        assert!(matches!(
            reduce_attempt(
                ReductionKind::SpanSum,
                plan,
                &compiled.program,
                haystack,
                0..haystack.len(),
                span_sum_one_below,
            ),
            Err(ReductionAttemptError {
                source: Error::ResourceLimit {
                    resource: Resource::SpanSum,
                    required,
                    limit,
                },
                ..
            }) if required == exact_span_sum.span_sum && limit == exact_span_sum.span_sum - 1
        ));

        for (resource, limits) in [
            (
                Resource::Boundaries,
                OperationLimits {
                    max_boundaries: haystack.len(),
                    ..exact_limits
                },
            ),
            (
                Resource::RandomAccessBytes,
                OperationLimits {
                    max_random_access_bytes: exact.accounting.random_access_peak_bytes - 1,
                    ..exact_limits
                },
            ),
            (
                Resource::ScratchBytes,
                OperationLimits {
                    max_scratch_bytes: exact.accounting.scratch_peak_bytes - 1,
                    ..exact_limits
                },
            ),
            (
                Resource::SequentialBytes,
                OperationLimits {
                    max_sequential_bytes: exact.accounting.sequential_bytes_read - 1,
                    ..exact_limits
                },
            ),
            (
                Resource::MatchEvents,
                OperationLimits {
                    max_match_events: exact.candidates - 1,
                    ..exact_limits
                },
            ),
            (
                Resource::OutputMatches,
                OperationLimits {
                    max_output_matches: exact.matches - 1,
                    ..exact_limits
                },
            ),
            (
                Resource::PeakBytes,
                OperationLimits {
                    max_peak_bytes: exact.accounting.peak_bytes - 1,
                    ..exact_limits
                },
            ),
            (
                Resource::ExecutionWork,
                OperationLimits {
                    max_work: exact.accounting.work - 1,
                    ..exact_limits
                },
            ),
        ] {
            assert!(
                matches!(
                    count(
                        plan,
                        &compiled.program,
                        haystack,
                        0..haystack.len(),
                        limits,
                    ),
                    Err(Error::ResourceLimit { resource: got, .. }) if got == resource
                ),
                "one-below {resource:?} did not refuse"
            );
        }
    }

    #[test]
    fn terminal_attempt_retains_all_workspace_allocations_and_legacy_error() {
        let compiled = compiled(r"\bprefix.{0,4}Z|[0-9]{1,3}-x|ab+");
        let plan = compiled.candidate.as_ref().unwrap();
        let haystack = b"prefix12Z";
        let limits = OperationLimits {
            max_sequential_bytes: 0,
            ..OperationLimits::default()
        };
        let legacy = count(plan, &compiled.program, haystack, 0..haystack.len(), limits)
            .expect_err("first source census must hit the sequential ceiling");
        let failure = count_attempt(plan, &compiled.program, haystack, 0..haystack.len(), limits)
            .expect_err("audited attempt must preserve the same refusal");
        assert_eq!(failure.source, legacy);
        assert_eq!(failure.actual_allocations, 5);
        assert!(failure.accounting.work > 0);
        assert!(failure.accounting.random_access_peak_bytes > 0);
        assert_eq!(
            failure.accounting.random_access_peak_bytes,
            failure.accounting.scratch_peak_bytes
        );
        assert_eq!(
            failure.accounting.peak_bytes,
            failure.accounting.scratch_peak_bytes
        );
    }

    #[test]
    fn candidate_value_route_does_not_weaken_prospective_admission() {
        let pattern = r"very-rare-prefix-[0-9]+|another-rare-prefix-[a-z]+|third-rare-prefix";
        let compiled = compiled(pattern);
        let mut haystack = vec![b'x'; 32_768];
        haystack.extend_from_slice(b" very-rare-prefix-42");
        let plan = compiled.candidate.as_ref().unwrap();
        let observed = count(
            plan,
            &compiled.program,
            &haystack,
            0..haystack.len(),
            OperationLimits::default(),
        )
        .unwrap();
        let limits = OperationLimits {
            max_work: observed.accounting.work,
            ..OperationLimits::default()
        };
        assert_eq!(
            compiled
                .count_value(
                    &haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    limits,
                )
                .unwrap(),
            observed.matches
        );
        assert!(matches!(
            compiled.admit_count(
                &haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                limits,
            ),
            Err(Error::ResourceLimit {
                resource: Resource::ExecutionWork,
                ..
            })
        ));
    }

    #[test]
    fn convergent_epsilon_pops_are_bookkeeping_not_state_evaluations() {
        let compiled = compiled(r"(?:a|a)b|probe");
        let plan = compiled.candidate.as_ref().unwrap();
        let result = count(
            plan,
            &compiled.program,
            b"ab",
            0..2,
            OperationLimits::default(),
        )
        .unwrap();
        assert_eq!(result.matches, 1);
        assert!(result.accounting.state_evaluations > 0);
        assert!(result.accounting.transition_checks > 0);
        assert!(result.accounting.work > result.accounting.state_evaluations);
    }

    #[test]
    fn fixed_prefix_filter_does_not_count_an_absent_edge_byte() {
        let mut bytes = ByteSet::empty();
        bytes.insert(b'a');
        let mut checks = [EMPTY_FILTER_CHECK; MAX_FILTER_CHECKS];
        checks[0] = FilterCheck { relative: 1, bytes };
        let entry = Entry {
            pc: 0,
            min_offset: 0,
            max_offset: 0,
            checks,
            check_len: 1,
            leading_assertion: None,
            global_checks: [EMPTY_FILTER_CHECK; MAX_FILTER_CHECKS],
            global_check_len: 0,
        };
        let mut meter = Meter::new(OperationLimits::default());
        assert!(!filter_matches(&entry, b"z", 0, &mut meter).unwrap());
        assert_eq!(meter.random, 0);
    }

    #[test]
    fn single_fixed_candidate_scans_once_and_skips_absent_starts() {
        let pattern = r"cargo/registry/src/[^/]+/([a-z]+)-([0-9]+\.[0-9]+\.[0-9]+)/";
        let compiled = compiled(pattern);
        assert_eq!(compiled.candidate.as_ref().unwrap().entries.len(), 1);
        let mut haystack = vec![b'x'; 32_768];
        haystack.extend_from_slice(b" cargo/registry/src/hash/name-1.2.3/");
        let plan = compiled.candidate.as_ref().unwrap();
        let result = count(
            plan,
            &compiled.program,
            &haystack,
            0..haystack.len(),
            OperationLimits::default(),
        )
        .unwrap();
        assert_eq!(result.matches, reference(pattern, &haystack));
        assert!((1..=16).contains(&result.candidates));
        assert!(
            (haystack.len()..=haystack.len().checked_mul(2).unwrap())
                .contains(&result.accounting.sequential_bytes_read)
        );
        assert!(
            result.accounting.work < haystack.len().checked_mul(3).unwrap(),
            "single fixed scheduling must not drain every absent start"
        );
        let span_sum = reduce_attempt(
            ReductionKind::SpanSum,
            plan,
            &compiled.program,
            &haystack,
            0..haystack.len(),
            OperationLimits::default(),
        )
        .unwrap();
        assert_eq!(span_sum.matches, result.matches);
        assert_eq!(span_sum.candidates, result.candidates);
        assert_eq!(span_sum.accounting, result.accounting);
        assert_eq!(span_sum.span_sum, reference_span_sum(pattern, &haystack));
    }

    #[test]
    fn equal_weight_class_anchor_retains_the_stronger_fixed_filter() {
        let pattern = r"cargo[\\/]registry[\\/]src[\\/][^\\/]+[\\/]([a-z]+)-([0-9.]+)[\\/]";
        let compiled = compiled(pattern);
        let plan = compiled.candidate.as_ref().unwrap();
        assert_eq!(plan.entries.len(), 1);
        assert_eq!(plan.entries[0].check_len, MAX_FILTER_CHECKS);
        assert!(plan.has_shared_fixed());
        assert!(has_complete_shared_fixed_filter(plan));

        let mut haystack = vec![b'\\'; 32_768];
        haystack.extend_from_slice(b" cargo/registry/src/hash/name-1.2/");
        let result = count(
            plan,
            &compiled.program,
            &haystack,
            0..haystack.len(),
            OperationLimits::default(),
        )
        .unwrap();
        assert_eq!(result.matches, reference(pattern, &haystack));
        assert_eq!(result.candidates, 1);
        assert!(
            (haystack.len()..=haystack.len().checked_mul(2).unwrap())
                .contains(&result.accounting.sequential_bytes_read)
        );
        let span_sum = reduce_attempt(
            ReductionKind::SpanSum,
            plan,
            &compiled.program,
            &haystack,
            0..haystack.len(),
            OperationLimits::default(),
        )
        .unwrap();
        assert_eq!(span_sum.matches, result.matches);
        assert_eq!(span_sum.candidates, result.candidates);
        assert_eq!(span_sum.accounting, result.accounting);
        assert_eq!(span_sum.span_sum, reference_span_sum(pattern, &haystack));
    }

    #[test]
    fn ordered_fixed_owners_share_one_monotone_anchor_scan() {
        let pattern = r"cargo/registry/src/[^/]+/([a-z]+)-([0-9]+\.[0-9]+\.[0-9]+)/|cargo\\registry\\src\\[^\\]+\\([a-z]+)-([0-9]+\.[0-9]+\.[0-9]+)\\";
        let compiled = compiled(pattern);
        let plan = compiled.candidate.as_ref().unwrap();
        assert_eq!(plan.entries.len(), 2);
        assert!(plan.has_shared_fixed());
        assert!(!has_complete_shared_fixed_filter(plan));

        let mut haystack = vec![b'x'; 32_768];
        haystack.extend_from_slice(
            b" cargo\\registry\\src\\hash\\win-2.0.1\\ cargo/registry/src/hash/unix-1.2.3/",
        );
        let result = count(
            plan,
            &compiled.program,
            &haystack,
            0..haystack.len(),
            OperationLimits::default(),
        )
        .unwrap();
        assert_eq!(result.matches, reference(pattern, &haystack));
        assert!(
            (haystack.len()..=haystack.len().checked_mul(2).unwrap())
                .contains(&result.accounting.sequential_bytes_read)
        );
        assert!(
            result.accounting.work < haystack.len().checked_mul(3).unwrap(),
            "shared fixed scheduling must not drain every absent start"
        );
        let span_sum = reduce_attempt(
            ReductionKind::SpanSum,
            plan,
            &compiled.program,
            &haystack,
            0..haystack.len(),
            OperationLimits::default(),
        )
        .unwrap();
        assert_eq!(span_sum.matches, result.matches);
        assert_eq!(span_sum.candidates, result.candidates);
        assert_eq!(span_sum.accounting, result.accounting);
        assert_eq!(span_sum.span_sum, reference_span_sum(pattern, &haystack));
    }

    #[test]
    fn shared_fixed_candidate_skips_dense_prefix_when_global_suffix_is_absent() {
        let pattern = r".efghijklmnopq[a-z]+[A-Z]";
        let compiled = compiled(pattern);
        let plan = compiled.candidate.as_ref().unwrap();
        assert!(plan.has_shared_fixed());
        // The start-relative scheduler uses the dense trailing `q` from the
        // fixed prefix, while the complementary source-wide proof retains the
        // mandatory uppercase suffix. Keeping both assertions here proves
        // that the early-out below is not merely an absent-anchor shortcut.
        assert_ne!(plan.buckets[usize::from(b'q')], 0);
        assert_eq!(plan.global_buckets[usize::from(b'q')], 0);
        assert_ne!(plan.global_buckets[usize::from(b'A')], 0);
        assert_ne!(plan.global_buckets[usize::from(b'Z')], 0);
        let haystack = b"bcdefghijklmnopq".repeat(500);

        let result = reduce_attempt(
            ReductionKind::SpanSum,
            plan,
            &compiled.program,
            &haystack,
            0..haystack.len(),
            OperationLimits::default(),
        )
        .unwrap();
        assert_eq!(result.matches, 0);
        assert_eq!(result.span_sum, 0);
        assert_eq!(result.candidates, 0);
        assert_eq!(result.accounting.sequential_bytes_read, haystack.len());
        assert!(result.accounting.work < haystack.len().checked_mul(2).unwrap());

        let exact = OperationLimits {
            max_work: result.accounting.work,
            ..OperationLimits::default()
        };
        assert_eq!(
            reduce_attempt(
                ReductionKind::SpanSum,
                plan,
                &compiled.program,
                &haystack,
                0..haystack.len(),
                exact,
            )
            .unwrap(),
            result
        );
    }

    #[test]
    fn shared_fixed_anchor_ranges_match_ordered_byte_oracle_exhaustively() {
        let pattern = r"abx|acy";
        let compiled = compiled(pattern);
        let plan = compiled.candidate.as_ref().unwrap();
        assert!(plan.has_shared_fixed());
        let reference = RegexBuilder::new(pattern).unicode(false).build().unwrap();
        let alphabet = [b'a', b'b', b'c', b'x', b'y', 0xFF];
        let mut haystack = Vec::new();
        for encoded in 0_usize..4_000 {
            haystack.clear();
            let mut value = encoded;
            let length = encoded % 7;
            for _ in 0..length {
                haystack.push(alphabet[value % alphabet.len()]);
                value /= alphabet.len();
            }
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let expected = reference.find_iter(&haystack[start..end]).count();
                    let actual = count(
                        plan,
                        &compiled.program,
                        &haystack,
                        start..end,
                        OperationLimits::default(),
                    )
                    .unwrap()
                    .matches;
                    assert_eq!(
                        actual, expected,
                        "range={start}..{end} haystack={haystack:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn mandatory_global_probe_suppresses_only_impossible_owners() {
        let pattern = r"\b(?:[a-z]+\.)*myshopify\.com\b|probe";
        let compiled = compiled(pattern);
        let absent = b"alpha beta gamma";
        let result = count(
            compiled.candidate.as_ref().unwrap(),
            &compiled.program,
            absent,
            0..absent.len(),
            OperationLimits::default(),
        )
        .unwrap();
        assert_eq!(result.matches, 0);
        assert_eq!(result.candidates, 0);
        assert_eq!(
            result.accounting.sequential_bytes_read,
            absent.len().checked_mul(2).unwrap()
        );

        let present_but_not_matching = b"myshopify.comX";
        let result = count(
            compiled.candidate.as_ref().unwrap(),
            &compiled.program,
            present_but_not_matching,
            0..present_but_not_matching.len(),
            OperationLimits::default(),
        )
        .unwrap();
        assert_eq!(result.matches, reference(pattern, present_but_not_matching));
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "small test fixtures independently restate the checked production formula"
    )]
    fn plan_workspace_bytes(plan: &Plan, program: &Program) -> usize {
        let schedule = plan.max_offset() + 1;
        let states = program.insts.len();
        let stack = states * 2 + 1;
        schedule * size_of::<u128>()
            + (stack + states * 2) * size_of::<u16>()
            + states * size_of::<u32>()
    }

    #[test]
    #[ignore = "requires the exact NoseyParker pattern and CPython corpus files"]
    fn exact_nosey_single_and_multi_candidate_canary() {
        let patterns_path = PathBuf::from(
            std::env::var_os("FRE_TEST_NOSEY_PATTERNS")
                .expect("FRE_TEST_NOSEY_PATTERNS must name noseyparker.txt"),
        );
        let haystack_path = PathBuf::from(
            std::env::var_os("FRE_TEST_NOSEY_HAYSTACK")
                .expect("FRE_TEST_NOSEY_HAYSTACK must name cpython-226484e4.py"),
        );
        let pattern_bytes = fs::read(patterns_path).unwrap();
        let pattern_source = std::str::from_utf8(&pattern_bytes).unwrap();
        let sources = pattern_source.lines().collect::<Vec<_>>();
        assert_eq!(sources.len(), 96);
        let raw_haystack = fs::read(haystack_path).unwrap();
        let haystack = String::from_utf8_lossy(&raw_haystack)
            .into_owned()
            .into_bytes();
        assert_eq!(haystack.len(), 32_514_634);

        let compile_limits = CompileLimits {
            max_hir_nodes: 1 << 16,
            max_hir_stack_items: 1 << 16,
            max_repeat_bound: 1 << 10,
            max_program_states: 1 << 16,
            max_work: 16 << 20,
            max_program_bytes: 16 << 20,
            ..CompileLimits::default()
        };
        let run_limits = OperationLimits {
            max_boundaries: haystack.len() + 1,
            max_table_cells: 0,
            max_random_access_bytes: 256 << 20,
            max_scratch_bytes: 256 << 20,
            max_log_bytes: 128 << 20,
            max_sequential_bytes: 512 << 20,
            max_match_events: (haystack.len() + 1) * 2,
            max_output_matches: haystack.len() + 1,
            max_output_bytes: 0,
            max_span_sum: haystack.len(),
            max_peak_bytes: 512 << 20,
            max_work: 1 << 29,
        };
        let parser = || ParserBuilder::new().unicode(false).utf8(false).build();

        let mut hirs = Vec::with_capacity(sources.len());
        for (ordinal, source) in sources.iter().enumerate() {
            let hir = parser().parse(source).unwrap();
            let probe = CompiledRegex::from_hir_erasing_captures_for_whole_match(
                &regex_syntax::hir::Hir::alternation(vec![
                    hir.clone(),
                    parser().parse("candidate-probe-literal").unwrap(),
                ]),
                RustByteProfile::PINNED_1_12_4,
                compile_limits,
            )
            .unwrap();
            assert_eq!(
                probe.compile_accounting().candidate_entries,
                2,
                "Nosey source {ordinal} lacks a candidate proof: {source}"
            );
            hirs.push(hir);
        }
        let multi = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &regex_syntax::hir::Hir::alternation(hirs),
            RustByteProfile::PINNED_1_12_4,
            compile_limits,
        )
        .unwrap();
        assert_eq!(multi.compile_accounting().candidate_entries, 96);
        let multi_plan = multi.candidate.as_ref().unwrap();
        let multi_result = count(
            multi_plan,
            &multi.program,
            &haystack,
            0..haystack.len(),
            run_limits,
        )
        .unwrap();
        assert_eq!(multi_result.matches, 55);

        let single_source = sources
            .iter()
            .map(|source| format!("(?:{source})"))
            .collect::<Vec<_>>()
            .join("|");
        let single_hir = parser().parse(&single_source).unwrap();
        let single = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &single_hir,
            RustByteProfile::PINNED_1_12_4,
            compile_limits,
        )
        .unwrap();
        assert_eq!(single.compile_accounting().candidate_entries, 96);
        let single_count = single
            .count_value(
                &haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                run_limits,
            )
            .unwrap();
        assert_eq!(single_count, 55);
    }
}
