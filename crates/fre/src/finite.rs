//! Checked finite-language extraction for operation-specific literal plans.

#![allow(
    clippy::similar_names,
    reason = "word and work are distinct domain quantities throughout this checked planner"
)]

use core::{
    cell::RefCell,
    mem::size_of,
    ops::{Deref, DerefMut},
};

use fre_exact_alloc::{CopyError, ExactVec};
use regex_syntax::hir::{Class, Hir, HirKind, Look};

use crate::BuildError;
use crate::guarded_ascii_word::{
    BuildActual as GuardedBuildActual, BuildDimensions as GuardedBuildDimensions,
    BuildError as GuardedBuildError, BuildLimits as GuardedBuildLimits,
    BuildProspective as GuardedBuildProspective, Dictionary as GuardedDictionary, Guard,
    PublishedBuildAccounting as GuardedPublishedBuild, SourceWord,
};

const FIXED_PREDICATE_WORD64_MIN_WIDTH: usize = 1;
const FIXED_PREDICATE_WORD64_MAX_WIDTH: usize = 64;
const FIXED_PREDICATE_MAX_RANGES: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FiniteExtractionTerminal {
    Fits,
    GuardedFiniteBody,
    TooLargeFixedSequence,
    Unsupported,
    ResourceFailure,
    GuardedResourceFailure,
}

/// Exact effects owned directly by the general finite extractor.
///
/// Guarded-dictionary effects remain in their native nested receipt and are
/// never flattened into these counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct FiniteExtractionLocalActual {
    pub(crate) allocations: usize,
    pub(crate) reallocations: usize,
    pub(crate) allocated_bytes: usize,
    pub(crate) copied_bytes: usize,
    pub(crate) initialized_bytes: usize,
    pub(crate) released_persistent_bytes: usize,
    pub(crate) released_scratch_bytes: usize,
    pub(crate) live_persistent_bytes: usize,
    pub(crate) live_scratch_bytes: usize,
    pub(crate) high_water_bytes: usize,
}

/// Native guarded-dictionary evidence nested without copying its counters into
/// [`FiniteExtractionLocalActual`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FiniteExtractionGuardedEvidence {
    Succeeded {
        accounting: GuardedPublishedBuild,
        co_live_local_scratch_bytes: usize,
        retained: bool,
    },
    Failed {
        accounting: GuardedBuildActual,
        co_live_local_scratch_bytes: usize,
    },
}

/// Cumulative observed effects through one finite-extraction terminal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FiniteExtractionActual {
    pub(crate) work: u64,
    pub(crate) local: FiniteExtractionLocalActual,
    pub(crate) guarded: Option<FiniteExtractionGuardedEvidence>,
}

/// Closed receipt retained by every general finite-extraction outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FiniteExtractionAttemptReceipt {
    initial_work: u64,
    work_limit: u64,
    actual: FiniteExtractionActual,
    terminal: FiniteExtractionTerminal,
    closed: bool,
}

/// Exact construction boundary composed from the finite extractor's local
/// ledger and the guarded dictionary's native terminal receipt.
///
/// Nested dictionary counters remain authoritative in
/// [`FiniteExtractionGuardedEvidence`]; this is a checked projection for the
/// aggregate construction transaction, not a second independently maintained
/// ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FiniteExtractionBoundaryActual {
    pub(crate) work: u64,
    pub(crate) allocations: usize,
    pub(crate) allocated_bytes: usize,
    pub(crate) copied_bytes: usize,
    pub(crate) initialized_bytes: usize,
    pub(crate) live_persistent_bytes: usize,
    pub(crate) high_water_bytes: usize,
    pub(crate) abandonable_bytes: usize,
}

#[allow(
    dead_code,
    reason = "the aggregate construction transaction consumes these crate-private projections"
)]
impl FiniteExtractionAttemptReceipt {
    pub(crate) const fn actual(self) -> FiniteExtractionActual {
        self.actual
    }

    pub(crate) const fn terminal(self) -> FiniteExtractionTerminal {
        self.terminal
    }

    pub(crate) const fn is_closed(self) -> bool {
        self.closed
    }

    pub(crate) fn boundary_actual(&self) -> Option<FiniteExtractionBoundaryActual> {
        if !(*self).has_basic_closure() {
            return None;
        }
        let local = self.actual.local;
        let work = self.actual.work.checked_sub(self.initial_work)?;
        let mut allocations = local.allocations;
        let mut allocated_bytes = local.allocated_bytes;
        let mut copied_bytes = local.copied_bytes;
        let mut initialized_bytes = local.initialized_bytes;
        let mut live_persistent_bytes = local.live_persistent_bytes;
        let mut high_water_bytes = local.high_water_bytes;
        let mut guarded_abandonable_bytes = 0_usize;
        if let Some(guarded) = self.actual.guarded {
            let (actual, co_live_local_scratch_bytes, retained) = match guarded {
                FiniteExtractionGuardedEvidence::Succeeded {
                    accounting,
                    co_live_local_scratch_bytes,
                    retained,
                } => (accounting.actual()?, co_live_local_scratch_bytes, retained),
                FiniteExtractionGuardedEvidence::Failed {
                    accounting,
                    co_live_local_scratch_bytes,
                } => (accounting, co_live_local_scratch_bytes, false),
            };
            let dictionary_allocated_bytes = guarded_allocated_bytes(actual)?;
            allocations = allocations.checked_add(actual.allocations)?;
            allocated_bytes = allocated_bytes.checked_add(dictionary_allocated_bytes)?;
            copied_bytes = copied_bytes.checked_add(actual.byte_copies)?;
            initialized_bytes = initialized_bytes
                .checked_add(actual.initialized_bytes)?
                .checked_add(
                    usize::from(actual.published).checked_mul(size_of::<GuardedDictionary>())?,
                )?;
            let guarded_co_live = co_live_local_scratch_bytes.checked_add(actual.peak_bytes)?;
            high_water_bytes = high_water_bytes.max(guarded_co_live);
            if retained {
                live_persistent_bytes =
                    live_persistent_bytes.checked_add(actual.persistent_bytes)?;
            } else {
                guarded_abandonable_bytes = if actual.published {
                    actual.persistent_bytes
                } else {
                    dictionary_allocated_bytes
                };
            }
        }
        let successful_terminal = matches!(
            self.terminal,
            FiniteExtractionTerminal::Fits | FiniteExtractionTerminal::GuardedFiniteBody
        );
        let abandonable_bytes = if successful_terminal {
            0
        } else {
            local
                .released_persistent_bytes
                .checked_add(local.released_scratch_bytes)?
                .checked_add(guarded_abandonable_bytes)?
        };
        Some(FiniteExtractionBoundaryActual {
            work,
            allocations,
            allocated_bytes,
            copied_bytes,
            initialized_bytes,
            live_persistent_bytes,
            high_water_bytes,
            abandonable_bytes,
        })
    }

    fn has_basic_closure(self) -> bool {
        let local_capacity_closes = self
            .actual
            .local
            .released_persistent_bytes
            .checked_add(self.actual.local.released_scratch_bytes)
            .and_then(|bytes| bytes.checked_add(self.actual.local.live_persistent_bytes))
            .and_then(|bytes| bytes.checked_add(self.actual.local.live_scratch_bytes))
            == Some(self.actual.local.allocated_bytes);
        self.closed
            && self.actual.work >= self.initial_work
            && (self.actual.work <= self.work_limit
                || self.initial_work > self.work_limit && self.actual.work == self.initial_work)
            && self.actual.local.live_scratch_bytes == 0
            && self.actual.local.reallocations <= self.actual.local.allocations
            && self.actual.local.copied_bytes <= self.actual.local.initialized_bytes
            && local_capacity_closes
            && self.actual.local.live_persistent_bytes <= self.actual.local.high_water_bytes
            && self.actual.local.high_water_bytes <= self.actual.local.allocated_bytes
    }
}

fn guarded_allocated_bytes(actual: GuardedBuildActual) -> Option<usize> {
    if actual.allocations == 0 {
        (actual.persistent_bytes == 0).then_some(0)
    } else {
        actual
            .persistent_bytes
            .checked_sub(size_of::<GuardedDictionary>())
    }
}

/// Exhaustive finite-language planner disposition with one closed receipt.
///
/// In particular, a semantic refusal never resets the work charged by an
/// earlier proof attempt. Callers can therefore continue with another
/// bounded route without silently restarting the construction quota.
pub(crate) enum FiniteOutcome {
    Fits {
        words: Vec<Vec<u8>>,
        receipt: FiniteExtractionAttemptReceipt,
    },
    GuardedFiniteBody {
        dictionary: GuardedDictionary,
        accounting: GuardedFiniteAccounting,
        receipt: FiniteExtractionAttemptReceipt,
    },
    TooLargeFixedSequence {
        receipt: FiniteExtractionAttemptReceipt,
    },
    Unsupported {
        receipt: FiniteExtractionAttemptReceipt,
    },
    ResourceFailure {
        error: BuildError,
        receipt: FiniteExtractionAttemptReceipt,
    },
    GuardedResourceFailure {
        error: GuardedFiniteBuildError,
        receipt: FiniteExtractionAttemptReceipt,
    },
}

#[derive(Clone, Copy)]
enum FiniteStorage {
    Persistent,
    Scratch,
}

struct FiniteExtractionState {
    work: u64,
    local: FiniteExtractionLocalActual,
    guarded: Option<FiniteExtractionGuardedEvidence>,
}

struct FiniteExtractionContext {
    initial_work: u64,
    work_limit: u64,
    state: RefCell<FiniteExtractionState>,
}

impl FiniteExtractionContext {
    fn new(initial_work: u64, work_limit: u64) -> Self {
        Self {
            initial_work,
            work_limit,
            state: RefCell::new(FiniteExtractionState {
                work: initial_work,
                local: FiniteExtractionLocalActual::default(),
                guarded: None,
            }),
        }
    }

    fn work(&self) -> u64 {
        self.state.borrow().work
    }

    fn live_scratch_bytes(&self) -> usize {
        self.state.borrow().local.live_scratch_bytes
    }

    fn charge(&self, amount: u64) -> Result<(), BuildError> {
        let mut state = self.state.borrow_mut();
        let needed = state
            .work
            .checked_add(amount)
            .ok_or(BuildError::PlannerWorkLimit {
                needed: u64::MAX,
                limit: self.work_limit,
            })?;
        if needed > self.work_limit {
            return Err(BuildError::PlannerWorkLimit {
                needed,
                limit: self.work_limit,
            });
        }
        state.work = needed;
        Ok(())
    }

    fn record_capacity_change<T>(
        &self,
        old_capacity: usize,
        new_capacity: usize,
        storage: FiniteStorage,
    ) -> Result<(), BuildError> {
        if old_capacity == new_capacity || size_of::<T>() == 0 {
            return Ok(());
        }
        let old_bytes = old_capacity
            .checked_mul(size_of::<T>())
            .ok_or(BuildError::PersistentBytesOverflow)?;
        let new_bytes = new_capacity
            .checked_mul(size_of::<T>())
            .ok_or(BuildError::PersistentBytesOverflow)?;
        let mut state = self.state.borrow_mut();
        let local = &mut state.local;
        let allocations = local
            .allocations
            .checked_add(1)
            .ok_or(BuildError::PersistentBytesOverflow)?;
        let reallocations = local
            .reallocations
            .checked_add(usize::from(old_capacity != 0))
            .ok_or(BuildError::PersistentBytesOverflow)?;
        let allocated_bytes = local
            .allocated_bytes
            .checked_add(new_bytes)
            .ok_or(BuildError::PersistentBytesOverflow)?;
        let (current_live, current_released, other_live) = match storage {
            FiniteStorage::Persistent => (
                local.live_persistent_bytes,
                local.released_persistent_bytes,
                local.live_scratch_bytes,
            ),
            FiniteStorage::Scratch => (
                local.live_scratch_bytes,
                local.released_scratch_bytes,
                local.live_persistent_bytes,
            ),
        };
        let next_live = current_live
            .checked_sub(old_bytes)
            .and_then(|bytes| bytes.checked_add(new_bytes))
            .ok_or(BuildError::InternalInvariant(
                "finite capacity transition lost live-byte closure",
            ))?;
        let next_released = current_released
            .checked_add(old_bytes)
            .ok_or(BuildError::PersistentBytesOverflow)?;
        let total_live = next_live
            .checked_add(other_live)
            .ok_or(BuildError::PersistentBytesOverflow)?;
        local.allocations = allocations;
        local.reallocations = reallocations;
        local.allocated_bytes = allocated_bytes;
        match storage {
            FiniteStorage::Persistent => {
                local.live_persistent_bytes = next_live;
                local.released_persistent_bytes = next_released;
            }
            FiniteStorage::Scratch => {
                local.live_scratch_bytes = next_live;
                local.released_scratch_bytes = next_released;
            }
        }
        local.high_water_bytes = local.high_water_bytes.max(total_live);
        Ok(())
    }

    fn record_initialization<T>(&self, count: usize, copied: bool) -> Result<(), BuildError> {
        if count == 0 || size_of::<T>() == 0 {
            return Ok(());
        }
        let bytes = count
            .checked_mul(size_of::<T>())
            .ok_or(BuildError::PersistentBytesOverflow)?;
        let mut state = self.state.borrow_mut();
        state.local.initialized_bytes = state
            .local
            .initialized_bytes
            .checked_add(bytes)
            .ok_or(BuildError::PersistentBytesOverflow)?;
        if copied {
            state.local.copied_bytes = state
                .local
                .copied_bytes
                .checked_add(bytes)
                .ok_or(BuildError::PersistentBytesOverflow)?;
        }
        Ok(())
    }

    fn release_capacity<T>(&self, capacity: usize, storage: FiniteStorage) {
        if capacity == 0 || size_of::<T>() == 0 {
            return;
        }
        let bytes = capacity
            .checked_mul(size_of::<T>())
            .expect("a previously recorded finite capacity remains representable");
        let mut state = self.state.borrow_mut();
        let local = &mut state.local;
        let (live, released) = match storage {
            FiniteStorage::Persistent => (
                &mut local.live_persistent_bytes,
                &mut local.released_persistent_bytes,
            ),
            FiniteStorage::Scratch => (
                &mut local.live_scratch_bytes,
                &mut local.released_scratch_bytes,
            ),
        };
        *live = live
            .checked_sub(bytes)
            .expect("a finite buffer releases only its recorded live capacity");
        *released = released
            .checked_add(bytes)
            .expect("finite released-byte accounting remains representable");
    }

    fn bind_guarded(&self, evidence: &FiniteExtractionGuardedEvidence) -> Result<(), BuildError> {
        let mut state = self.state.borrow_mut();
        if state.guarded.replace(*evidence).is_some() {
            return Err(BuildError::InternalInvariant(
                "finite extraction bound guarded evidence twice",
            ));
        }
        Ok(())
    }

    fn retain_guarded(&self) -> Result<(), BuildError> {
        let mut state = self.state.borrow_mut();
        let Some(FiniteExtractionGuardedEvidence::Succeeded { retained, .. }) =
            state.guarded.as_mut()
        else {
            return Err(BuildError::InternalInvariant(
                "finite extraction retained missing guarded success evidence",
            ));
        };
        if core::mem::replace(retained, true) {
            return Err(BuildError::InternalInvariant(
                "finite extraction retained guarded evidence twice",
            ));
        }
        Ok(())
    }

    fn close(&self, terminal: FiniteExtractionTerminal) -> FiniteExtractionAttemptReceipt {
        let state = self.state.borrow();
        FiniteExtractionAttemptReceipt {
            initial_work: self.initial_work,
            work_limit: self.work_limit,
            actual: FiniteExtractionActual {
                work: state.work,
                local: state.local,
                guarded: state.guarded,
            },
            terminal,
            closed: true,
        }
    }

    fn close_fixed_predicate(
        &self,
        terminal: FixedPredicateInspectionTerminal,
    ) -> FixedPredicateInspectionAttemptReceipt {
        let state = self.state.borrow();
        FixedPredicateInspectionAttemptReceipt {
            initial_work: self.initial_work,
            work_limit: self.work_limit,
            actual: FixedPredicateInspectionActual {
                work: state.work,
                local: state.local,
            },
            terminal,
            closed: state.guarded.is_none(),
        }
    }
}

struct AccountedVec<'context, T> {
    values: Vec<T>,
    context: &'context FiniteExtractionContext,
    storage: FiniteStorage,
    accounted_capacity: usize,
}

impl<'context, T> AccountedVec<'context, T> {
    fn new(context: &'context FiniteExtractionContext, storage: FiniteStorage) -> Self {
        Self {
            values: Vec::new(),
            context,
            storage,
            accounted_capacity: 0,
        }
    }

    fn reserve_planner(
        &mut self,
        additional: usize,
        structure: &'static str,
    ) -> Result<(), BuildError> {
        let needed =
            self.values
                .len()
                .checked_add(additional)
                .ok_or(BuildError::PlannerWorkLimit {
                    needed: u64::MAX,
                    limit: self.context.work_limit,
                })?;
        if needed > self.values.capacity() {
            self.context
                .charge(u64::try_from(self.values.len()).unwrap_or(u64::MAX))?;
        }
        self.context
            .charge(u64::try_from(additional).unwrap_or(u64::MAX))?;
        let old_capacity = self.values.capacity();
        self.values
            .try_reserve(additional)
            .map_err(|_| BuildError::AllocationFailed {
                structure,
                additional,
            })?;
        let new_capacity = self.values.capacity();
        self.context
            .record_capacity_change::<T>(old_capacity, new_capacity, self.storage)?;
        self.accounted_capacity = new_capacity;
        Ok(())
    }

    fn push_reserved(&mut self, value: T) -> Result<(), BuildError> {
        debug_assert!(size_of::<T>() == 0 || self.values.len() < self.values.capacity());
        self.values.push(value);
        self.context.record_initialization::<T>(1, false)
    }

    fn extend_reserved<I>(&mut self, values: I, count: usize) -> Result<(), BuildError>
    where
        I: IntoIterator<Item = T>,
    {
        debug_assert!(
            size_of::<T>() == 0
                || self.values.len().saturating_add(count) <= self.values.capacity()
        );
        self.values.extend(values);
        self.context.record_initialization::<T>(count, true)
    }

    fn pop(&mut self) -> Option<T> {
        self.values.pop()
    }

    fn len(&self) -> usize {
        self.values.len()
    }

    fn reverse(&mut self) {
        self.values.reverse();
    }

    fn into_inner_kept(mut self) -> Vec<T> {
        self.accounted_capacity = 0;
        core::mem::take(&mut self.values)
    }
}

impl<T> Deref for AccountedVec<'_, T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.values.as_slice()
    }
}

impl<T> DerefMut for AccountedVec<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.values.as_mut_slice()
    }
}

impl<'a, T> IntoIterator for &'a AccountedVec<'_, T> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.values.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut AccountedVec<'_, T> {
    type Item = &'a mut T;
    type IntoIter = core::slice::IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.values.iter_mut()
    }
}

impl<T> Drop for AccountedVec<'_, T> {
    fn drop(&mut self) {
        self.context
            .release_capacity::<T>(self.accounted_capacity, self.storage);
    }
}

struct AccountedExactVec<'context, T> {
    values: ExactVec<T>,
    context: &'context FiniteExtractionContext,
    storage: FiniteStorage,
    accounted_capacity: usize,
}

impl<'context, T> AccountedExactVec<'context, T> {
    fn empty(context: &'context FiniteExtractionContext, storage: FiniteStorage) -> Self {
        Self {
            values: ExactVec::default(),
            context,
            storage,
            accounted_capacity: 0,
        }
    }

    fn try_with_capacity(
        context: &'context FiniteExtractionContext,
        storage: FiniteStorage,
        capacity: usize,
        structure: &'static str,
    ) -> Result<Self, BuildError> {
        let values = ExactVec::try_with_capacity(capacity)
            .map_err(|error| map_guarded_source_allocation(error, structure, capacity))?;
        let observed = values.capacity();
        context.record_capacity_change::<T>(0, observed, storage)?;
        Ok(Self {
            values,
            context,
            storage,
            accounted_capacity: observed,
        })
    }

    fn push_accounted(
        &mut self,
        value: T,
        copied: bool,
        capacity_detail: &'static str,
    ) -> Result<(), BuildError> {
        self.values
            .try_push(value)
            .map_err(|_| BuildError::InternalInvariant(capacity_detail))?;
        self.context.record_initialization::<T>(1, copied)
    }

    fn capacity(&self) -> usize {
        self.values.capacity()
    }

    fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    fn into_inner_kept(mut self) -> ExactVec<T> {
        self.accounted_capacity = 0;
        core::mem::take(&mut self.values)
    }
}

impl<T> Deref for AccountedExactVec<'_, T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.values.as_slice()
    }
}

impl<T> DerefMut for AccountedExactVec<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.values.as_mut_slice()
    }
}

impl<'a, T> IntoIterator for &'a AccountedExactVec<'_, T> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.values.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut AccountedExactVec<'_, T> {
    type Item = &'a mut T;
    type IntoIter = core::slice::IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.values.iter_mut()
    }
}

impl<T> Drop for AccountedExactVec<'_, T> {
    fn drop(&mut self) {
        self.context
            .release_capacity::<T>(self.accounted_capacity, self.storage);
    }
}

#[allow(
    dead_code,
    reason = "legacy crate-private projection remains for compatibility and focused parity tests"
)]
pub(crate) struct FixedPredicateInspection {
    pub(crate) source: Option<FixedPredicateWord64Source>,
    pub(crate) work: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FixedPredicateInspectionTerminal {
    Succeeded,
    Refused,
    ResourceFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FixedPredicateInspectionActual {
    pub(crate) work: u64,
    pub(crate) local: FiniteExtractionLocalActual,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FixedPredicateInspectionAttemptReceipt {
    initial_work: u64,
    work_limit: u64,
    actual: FixedPredicateInspectionActual,
    terminal: FixedPredicateInspectionTerminal,
    closed: bool,
}

#[allow(
    dead_code,
    reason = "the aggregate construction transaction consumes these crate-private projections"
)]
impl FixedPredicateInspectionAttemptReceipt {
    pub(crate) const fn initial_work(self) -> u64 {
        self.initial_work
    }

    pub(crate) const fn work_limit(self) -> u64 {
        self.work_limit
    }

    pub(crate) const fn actual(self) -> FixedPredicateInspectionActual {
        self.actual
    }

    pub(crate) const fn terminal(self) -> FixedPredicateInspectionTerminal {
        self.terminal
    }

    pub(crate) const fn is_closed(self) -> bool {
        self.closed
    }

    fn has_basic_closure(self) -> bool {
        let local = self.actual.local;
        let local_capacity_closes = local
            .released_persistent_bytes
            .checked_add(local.released_scratch_bytes)
            .and_then(|bytes| bytes.checked_add(local.live_persistent_bytes))
            .and_then(|bytes| bytes.checked_add(local.live_scratch_bytes))
            == Some(local.allocated_bytes);
        self.closed
            && self.actual.work >= self.initial_work
            && (self.actual.work <= self.work_limit
                || self.initial_work > self.work_limit && self.actual.work == self.initial_work)
            && local.live_persistent_bytes == 0
            && local.live_scratch_bytes == 0
            && local.reallocations <= local.allocations
            && local.copied_bytes <= local.initialized_bytes
            && local.high_water_bytes <= local.allocated_bytes
            && local_capacity_closes
    }
}

pub(crate) enum FixedPredicateInspectionAttempt {
    Succeeded {
        source: FixedPredicateWord64Source,
        receipt: FixedPredicateInspectionAttemptReceipt,
    },
    Refused {
        receipt: FixedPredicateInspectionAttemptReceipt,
    },
    ResourceFailure {
        error: BuildError,
        receipt: FixedPredicateInspectionAttemptReceipt,
    },
}

impl FixedPredicateInspectionAttempt {
    pub(crate) const fn receipt(&self) -> FixedPredicateInspectionAttemptReceipt {
        match self {
            Self::Succeeded { receipt, .. }
            | Self::Refused { receipt }
            | Self::ResourceFailure { receipt, .. } => *receipt,
        }
    }

    pub(crate) fn has_closed_receipt(&self) -> bool {
        let receipt = self.receipt();
        let terminal_matches = matches!(
            (self, receipt.terminal),
            (
                Self::Succeeded { .. },
                FixedPredicateInspectionTerminal::Succeeded
            ) | (
                Self::Refused { .. },
                FixedPredicateInspectionTerminal::Refused
            ) | (
                Self::ResourceFailure { .. },
                FixedPredicateInspectionTerminal::ResourceFailure
            )
        );
        terminal_matches && receipt.has_basic_closure()
    }

    #[allow(
        dead_code,
        reason = "legacy crate-private projection remains for compatibility and focused parity tests"
    )]
    pub(crate) fn into_legacy(self) -> Result<FixedPredicateInspection, BuildError> {
        if !self.has_closed_receipt() {
            return Err(BuildError::InternalInvariant(
                "fixed-predicate inspection lost its attempt closure",
            ));
        }
        match self {
            Self::Succeeded { source, receipt } => Ok(FixedPredicateInspection {
                source: Some(source),
                work: receipt.actual.work,
            }),
            Self::Refused { receipt } => Ok(FixedPredicateInspection {
                source: None,
                work: receipt.actual.work,
            }),
            Self::ResourceFailure { error, .. } => Err(error),
        }
    }
}

/// Inline proof source for a fixed-width byte Cartesian predicate word or a
/// lazy repetition whose every match is exactly one such byte predicate.
///
/// The source is a structural byte-predicate proof. Its caller owns plan
/// precedence: search uses it before enumerating a finite product, while
/// aggregate integrations may retain the legacy after-refusal ordering.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FixedPredicateWord64Source {
    positions: [FixedPredicate; FIXED_PREDICATE_WORD64_MAX_WIDTH],
    width: usize,
    variable_predicates: usize,
    non_universal_predicates: usize,
    cartesian_product: Option<usize>,
    finite_incumbent: Analysis,
    lazy_unit_repetition: bool,
    hir_nodes: usize,
    captures: usize,
}

impl FixedPredicateWord64Source {
    const EMPTY: Self = Self {
        positions: [FixedPredicate::EMPTY; FIXED_PREDICATE_WORD64_MAX_WIDTH],
        width: 0,
        variable_predicates: 0,
        non_universal_predicates: 0,
        cartesian_product: Some(1),
        finite_incumbent: Analysis::Unsupported,
        lazy_unit_repetition: false,
        hir_nodes: 0,
        captures: 0,
    };

    pub(crate) fn positions(&self) -> impl ExactSizeIterator<Item = FixedPredicateRanges> + '_ {
        self.positions[..self.width()]
            .iter()
            .copied()
            .map(FixedPredicate::ranges)
    }

    pub(crate) const fn width(&self) -> usize {
        self.width
    }

    pub(crate) const fn variable_predicates(&self) -> usize {
        self.variable_predicates
    }

    /// Whether at least one position rejects a byte from the full domain.
    pub(crate) const fn has_non_universal_predicate(&self) -> bool {
        self.non_universal_predicates != 0
    }

    /// Exact Cartesian count for the retained physical predicate columns, or
    /// `None` after authenticated `usize` overflow. For a lazy unit source,
    /// this is the one-byte reducer alphabet rather than the unbounded regex
    /// language; its finite incumbent is always `Unsupported`.
    pub(crate) const fn cartesian_product(&self) -> Option<usize> {
        self.cartesian_product
    }

    /// Whether the finite extractor cannot retain this language inside the
    /// caller's complete construction envelope, including transient peaks.
    pub(crate) const fn finite_incumbent_cannot_fit(
        &self,
        max_patterns: usize,
        max_pattern_bytes: usize,
    ) -> bool {
        match self.finite_incumbent {
            Analysis::Fits(shape) => !shape.fits(max_patterns, max_pattern_bytes),
            Analysis::TooLargeFixedSequence | Analysis::Unsupported => true,
        }
    }

    /// Whether this source proves a root, capture-transparent, lazy
    /// one-or-more repetition over its sole byte predicate. Every
    /// non-overlapping match then consumes exactly one accepted byte, so
    /// Count and SpanSum have the same scalar reduction as a width-one word.
    pub(crate) const fn is_lazy_unit_repetition(&self) -> bool {
        self.lazy_unit_repetition
    }

    pub(crate) const fn hir_nodes(&self) -> usize {
        self.hir_nodes
    }

    pub(crate) const fn captures(&self) -> usize {
        self.captures
    }

    fn push(&mut self, predicate: FixedPredicate) -> Result<bool, BuildError> {
        let index = self.width();
        if index == FIXED_PREDICATE_WORD64_MAX_WIDTH {
            return Ok(false);
        }
        let member_count = predicate.member_count();
        if member_count == 0 {
            return Err(BuildError::InternalInvariant(
                "fixed predicate lost its member cardinality",
            ));
        }
        let width = self
            .width
            .checked_add(1)
            .ok_or(BuildError::InternalInvariant(
                "fixed-predicate width accounting overflow",
            ))?;
        let variable_predicates = self
            .variable_predicates
            .checked_add(usize::from(member_count > 1))
            .ok_or(BuildError::InternalInvariant(
                "fixed-predicate variable-position accounting overflow",
            ))?;
        let non_universal_predicates = self
            .non_universal_predicates
            .checked_add(usize::from(!predicate.is_universal()))
            .ok_or(BuildError::InternalInvariant(
                "fixed-predicate non-universal-position accounting overflow",
            ))?;
        let cartesian_product = self
            .cartesian_product
            .and_then(|product| product.checked_mul(member_count));
        // Every caller has already charged this predicate insertion. Retain
        // the finite-incumbent facts here so admission needs neither an
        // uncharged post-receipt scan nor a second HIR traversal.
        self.positions[index] = predicate;
        self.width = width;
        self.variable_predicates = variable_predicates;
        self.non_universal_predicates = non_universal_predicates;
        self.cartesian_product = cartesian_product;
        Ok(true)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FixedPredicate {
    ranges: [(u8, u8); FIXED_PREDICATE_MAX_RANGES],
    range_count: u8,
    member_count: u16,
}

impl FixedPredicate {
    const EMPTY: Self = Self {
        ranges: [(0, 0); FIXED_PREDICATE_MAX_RANGES],
        range_count: 0,
        member_count: 0,
    };

    fn singleton(byte: u8) -> Self {
        let mut ranges = [(0, 0); FIXED_PREDICATE_MAX_RANGES];
        ranges[0] = (byte, byte);
        Self {
            ranges,
            range_count: 1,
            member_count: 1,
        }
    }

    fn from_byte_class(class: &regex_syntax::hir::ClassBytes) -> Option<Self> {
        let ranges = class.ranges();
        if ranges.is_empty() || ranges.len() > FIXED_PREDICATE_MAX_RANGES {
            return None;
        }
        let mut normalized = [(0, 0); FIXED_PREDICATE_MAX_RANGES];
        let mut members = 0_usize;
        for (index, range) in ranges.iter().enumerate() {
            let start = range.start();
            let end = range.end();
            *normalized.get_mut(index)? = (start, end);
            let inclusive_members = usize::from(end)
                .checked_sub(usize::from(start))?
                .checked_add(1)?;
            members = members.checked_add(inclusive_members)?;
        }
        if members > 256 {
            return None;
        }
        Some(Self {
            ranges: normalized,
            range_count: u8::try_from(ranges.len()).ok()?,
            member_count: u16::try_from(members).ok()?,
        })
    }

    fn ranges(self) -> FixedPredicateRanges {
        FixedPredicateRanges {
            ranges: self.ranges,
            range_count: self.range_count,
        }
    }

    const fn member_count(self) -> usize {
        self.member_count as usize
    }

    const fn is_universal(self) -> bool {
        self.member_count == 256
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FixedPredicateRanges {
    ranges: [(u8, u8); FIXED_PREDICATE_MAX_RANGES],
    range_count: u8,
}

impl FixedPredicateRanges {
    pub(crate) const EMPTY: Self = Self {
        ranges: [(0, 0); FIXED_PREDICATE_MAX_RANGES],
        range_count: 0,
    };

    pub(crate) fn ranges(&self) -> &[(u8, u8)] {
        &self.ranges[..usize::from(self.range_count)]
    }
}

type IncumbentFiniteResult = Result<(Option<Vec<Vec<u8>>>, u64), BuildError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GuardedFiniteBuildLimits {
    pub dictionary: GuardedBuildLimits,
    pub max_scratch_bytes: usize,
    pub max_peak_bytes: usize,
}

/// Endpoint assertion family accepted by guarded finite extraction.
///
/// Keeping this choice explicit prevents a Unicode-enabled profile containing
/// an inline ASCII boundary (or the converse) from borrowing the wrong
/// dictionary execution theorem.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GuardedFiniteBoundarySemantics {
    Ascii,
    UnicodeFull,
}

impl GuardedFiniteBuildLimits {
    pub(crate) const fn unlimited() -> Self {
        Self {
            dictionary: GuardedBuildLimits::unlimited(),
            max_scratch_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GuardedFiniteBuildResource {
    ScratchBytes,
    PeakBytes,
}

#[derive(Debug)]
pub(crate) enum GuardedFiniteBuildError {
    Dictionary(GuardedBuildError),
    ConstructionLimit {
        resource: GuardedFiniteBuildResource,
        needed: usize,
        limit: usize,
    },
}

enum GuardedAttemptError {
    Planner(BuildError),
    Build(GuardedFiniteBuildError),
}

impl From<BuildError> for GuardedAttemptError {
    fn from(error: BuildError) -> Self {
        Self::Planner(error)
    }
}

impl FiniteOutcome {
    pub(crate) const fn work(&self) -> u64 {
        self.receipt().actual.work
    }

    pub(crate) const fn receipt(&self) -> &FiniteExtractionAttemptReceipt {
        match self {
            Self::Fits { receipt, .. }
            | Self::GuardedFiniteBody { receipt, .. }
            | Self::TooLargeFixedSequence { receipt }
            | Self::Unsupported { receipt }
            | Self::ResourceFailure { receipt, .. }
            | Self::GuardedResourceFailure { receipt, .. } => receipt,
        }
    }

    pub(crate) fn has_closed_receipt(&self) -> bool {
        let receipt = *self.receipt();
        if !receipt.has_basic_closure() {
            return false;
        }
        match self {
            Self::Fits { words, .. } => {
                receipt.terminal == FiniteExtractionTerminal::Fits
                    && receipt.actual.guarded.is_none()
                    && finite_words_capacity_bytes(words)
                        == Some(receipt.actual.local.live_persistent_bytes)
            }
            Self::GuardedFiniteBody {
                dictionary,
                accounting,
                ..
            } => {
                receipt.terminal == FiniteExtractionTerminal::GuardedFiniteBody
                    && receipt.actual.local.live_persistent_bytes == 0
                    && accounting.is_consistent(dictionary)
                    && receipt.actual.guarded
                        == Some(FiniteExtractionGuardedEvidence::Succeeded {
                            accounting: match dictionary.build_accounting().published() {
                                Some(accounting) => accounting,
                                None => return false,
                            },
                            co_live_local_scratch_bytes: receipt
                                .actual
                                .guarded
                                .and_then(|evidence| match evidence {
                                    FiniteExtractionGuardedEvidence::Succeeded {
                                        co_live_local_scratch_bytes,
                                        ..
                                    } => Some(co_live_local_scratch_bytes),
                                    FiniteExtractionGuardedEvidence::Failed { .. } => None,
                                })
                                .unwrap_or(usize::MAX),
                            retained: true,
                        })
            }
            Self::TooLargeFixedSequence { .. } => {
                receipt.terminal == FiniteExtractionTerminal::TooLargeFixedSequence
                    && receipt.actual.guarded.is_none()
                    && receipt.actual.local.live_persistent_bytes == 0
            }
            Self::Unsupported { .. } => {
                receipt.terminal == FiniteExtractionTerminal::Unsupported
                    && receipt.actual.guarded.is_none()
                    && receipt.actual.local.live_persistent_bytes == 0
            }
            Self::ResourceFailure { .. } => {
                let guarded_released = !matches!(
                    receipt.actual.guarded,
                    Some(FiniteExtractionGuardedEvidence::Succeeded { retained: true, .. })
                );
                receipt.terminal == FiniteExtractionTerminal::ResourceFailure
                    && receipt.actual.local.live_persistent_bytes == 0
                    && guarded_released
            }
            Self::GuardedResourceFailure { error, .. } => {
                let guarded_closes = match error {
                    GuardedFiniteBuildError::Dictionary(error) => {
                        receipt.actual.guarded
                            == Some(FiniteExtractionGuardedEvidence::Failed {
                                accounting: error.actual(),
                                co_live_local_scratch_bytes: receipt
                                    .actual
                                    .guarded
                                    .and_then(|evidence| match evidence {
                                        FiniteExtractionGuardedEvidence::Failed {
                                            co_live_local_scratch_bytes,
                                            ..
                                        } => Some(co_live_local_scratch_bytes),
                                        FiniteExtractionGuardedEvidence::Succeeded { .. } => None,
                                    })
                                    .unwrap_or(usize::MAX),
                            })
                    }
                    GuardedFiniteBuildError::ConstructionLimit { .. } => {
                        receipt.actual.guarded.is_none()
                    }
                };
                receipt.terminal == FiniteExtractionTerminal::GuardedResourceFailure
                    && receipt.actual.local.live_persistent_bytes == 0
                    && guarded_closes
            }
        }
    }

    pub(crate) fn into_incumbent_words(self) -> IncumbentFiniteResult {
        if !self.has_closed_receipt() {
            return Err(BuildError::InternalInvariant(
                "finite outcome lost its extraction-attempt closure",
            ));
        }
        let cumulative_work = self.work();
        match self {
            Self::Fits { words, .. } => Ok((Some(words), cumulative_work)),
            Self::GuardedFiniteBody {
                dictionary,
                accounting,
                ..
            } => {
                if !accounting.is_consistent(&dictionary) {
                    return Err(BuildError::InternalInvariant(
                        "guarded finite outcome lost its accounting invariant",
                    ));
                }
                Ok((None, cumulative_work))
            }
            Self::TooLargeFixedSequence { .. } | Self::Unsupported { .. } => {
                Ok((None, cumulative_work))
            }
            Self::ResourceFailure { error, .. } => Err(error),
            Self::GuardedResourceFailure { .. } => Err(BuildError::InternalInvariant(
                "guarded finite failure escaped an incumbent-only extraction",
            )),
        }
    }
}

fn finite_words_capacity_bytes(words: &Vec<Vec<u8>>) -> Option<usize> {
    words
        .capacity()
        .checked_mul(size_of::<Vec<u8>>())?
        .checked_add(
            words
                .iter()
                .try_fold(0_usize, |bytes, word| bytes.checked_add(word.capacity()))?,
        )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Analysis {
    Fits(Shape),
    TooLargeFixedSequence,
    Unsupported,
}

#[derive(Clone, Copy)]
enum Task<'a> {
    Visit(&'a Hir),
    FinishConcat(usize),
    FinishAlternation(usize),
}

struct Language<'context> {
    words: Vec<Vec<u8>>,
    bytes: usize,
    context: &'context FiniteExtractionContext,
    accounted_outer_capacity: usize,
}

impl<'context> Language<'context> {
    fn empty(context: &'context FiniteExtractionContext, bytes: usize) -> Self {
        Self {
            words: Vec::new(),
            bytes,
            context,
            accounted_outer_capacity: 0,
        }
    }

    fn reserve_words(
        &mut self,
        additional: usize,
        structure: &'static str,
    ) -> Result<(), BuildError> {
        let needed =
            self.words
                .len()
                .checked_add(additional)
                .ok_or(BuildError::PlannerWorkLimit {
                    needed: u64::MAX,
                    limit: self.context.work_limit,
                })?;
        if needed > self.words.capacity() {
            self.context
                .charge(u64::try_from(self.words.len()).unwrap_or(u64::MAX))?;
        }
        self.context
            .charge(u64::try_from(additional).unwrap_or(u64::MAX))?;
        let old_capacity = self.words.capacity();
        self.words
            .try_reserve(additional)
            .map_err(|_| BuildError::AllocationFailed {
                structure,
                additional,
            })?;
        let new_capacity = self.words.capacity();
        self.context.record_capacity_change::<Vec<u8>>(
            old_capacity,
            new_capacity,
            FiniteStorage::Persistent,
        )?;
        self.accounted_outer_capacity = new_capacity;
        Ok(())
    }

    fn push_word(&mut self, word: AccountedVec<'context, u8>) -> Result<(), BuildError> {
        debug_assert!(self.words.len() < self.words.capacity());
        self.words.push(word.into_inner_kept());
        self.context.record_initialization::<Vec<u8>>(1, false)
    }

    fn append_words(&mut self, source: &mut Self) -> Result<(), BuildError> {
        let count = source.words.len();
        debug_assert!(self.words.len().saturating_add(count) <= self.words.capacity());
        self.words.append(&mut source.words);
        self.context.record_initialization::<Vec<u8>>(count, true)
    }

    fn into_words(mut self) -> Vec<Vec<u8>> {
        self.accounted_outer_capacity = 0;
        core::mem::take(&mut self.words)
    }
}

impl Drop for Language<'_> {
    fn drop(&mut self) {
        self.context
            .release_capacity::<Vec<u8>>(self.accounted_outer_capacity, FiniteStorage::Persistent);
        for word in &self.words {
            self.context
                .release_capacity::<u8>(word.capacity(), FiniteStorage::Persistent);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Shape {
    words: usize,
    bytes: usize,
    peak_words: usize,
    peak_bytes: usize,
}

#[allow(
    clippy::too_many_lines,
    reason = "the iterative task machine keeps every HIR case and early resource refusal visible"
)]
pub(crate) fn extract(
    hir: &Hir,
    max_words: usize,
    max_bytes: usize,
    initial_work: u64,
    work_limit: u64,
    derive_guarded_dictionary: bool,
    guarded_limits: GuardedFiniteBuildLimits,
) -> FiniteOutcome {
    extract_with_guarded_semantics(
        hir,
        max_words,
        max_bytes,
        initial_work,
        work_limit,
        derive_guarded_dictionary.then_some(GuardedFiniteBoundarySemantics::Ascii),
        guarded_limits,
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "the iterative task machine keeps every HIR case and early resource refusal visible"
)]
pub(crate) fn extract_with_guarded_semantics(
    hir: &Hir,
    max_words: usize,
    max_bytes: usize,
    initial_work: u64,
    work_limit: u64,
    guarded_semantics: Option<GuardedFiniteBoundarySemantics>,
    guarded_limits: GuardedFiniteBuildLimits,
) -> FiniteOutcome {
    let context = FiniteExtractionContext::new(initial_work, work_limit);
    match extract_plain(hir, max_words, max_bytes, &context) {
        Ok(Some(words)) => FiniteOutcome::Fits {
            words,
            receipt: context.close(FiniteExtractionTerminal::Fits),
        },
        Ok(None) if guarded_semantics.is_some() => {
            match extract_guarded_dictionary(
                hir,
                max_words,
                max_bytes,
                &context,
                guarded_semantics.expect("guarded semantics checked above"),
                guarded_limits,
            ) {
                Ok(Ok((dictionary, accounting))) => FiniteOutcome::GuardedFiniteBody {
                    dictionary,
                    accounting,
                    receipt: context.close(FiniteExtractionTerminal::GuardedFiniteBody),
                },
                Ok(Err(GuardedRefusal::TooLargeFixedSequence)) => {
                    FiniteOutcome::TooLargeFixedSequence {
                        receipt: context.close(FiniteExtractionTerminal::TooLargeFixedSequence),
                    }
                }
                Ok(Err(GuardedRefusal::Unsupported)) => FiniteOutcome::Unsupported {
                    receipt: context.close(FiniteExtractionTerminal::Unsupported),
                },
                Err(GuardedAttemptError::Planner(error)) => FiniteOutcome::ResourceFailure {
                    error,
                    receipt: context.close(FiniteExtractionTerminal::ResourceFailure),
                },
                Err(GuardedAttemptError::Build(error)) => FiniteOutcome::GuardedResourceFailure {
                    error,
                    receipt: context.close(FiniteExtractionTerminal::GuardedResourceFailure),
                },
            }
        }
        Ok(None) => FiniteOutcome::Unsupported {
            receipt: context.close(FiniteExtractionTerminal::Unsupported),
        },
        Err(PlainFailure::TooLargeFixedSequence) => FiniteOutcome::TooLargeFixedSequence {
            receipt: context.close(FiniteExtractionTerminal::TooLargeFixedSequence),
        },
        Err(PlainFailure::Resource(error)) => FiniteOutcome::ResourceFailure {
            error,
            receipt: context.close(FiniteExtractionTerminal::ResourceFailure),
        },
    }
}

/// Inspect the compact predicate proof inside a cumulative planner
/// transaction. `initial_work` is completed incumbent work, so changing the
/// relative ordering of this bounded inspection cannot reset or launder the
/// shared planner quota.
pub(crate) fn inspect_fixed_predicate_word64_attempt(
    hir: &Hir,
    initial_work: u64,
    work_limit: u64,
) -> FixedPredicateInspectionAttempt {
    let context = FiniteExtractionContext::new(initial_work, work_limit);
    inspect_fixed_predicate_word64_with_context(hir, &context, false)
}

/// Inspect the additional root lazy-unit equivalence used only by aggregate
/// Compile, Count and SpanSum. Keeping this opt-in out of the shared search
/// and complete-span inspector preserves their incumbent refusal accounting.
pub(crate) fn inspect_fixed_predicate_word64_scalar_aggregate_attempt(
    hir: &Hir,
    initial_work: u64,
    work_limit: u64,
) -> FixedPredicateInspectionAttempt {
    let context = FiniteExtractionContext::new(initial_work, work_limit);
    inspect_fixed_predicate_word64_with_context(hir, &context, true)
}

fn inspect_fixed_predicate_word64_with_context(
    hir: &Hir,
    context: &FiniteExtractionContext,
    allow_lazy_unit_repetition: bool,
) -> FixedPredicateInspectionAttempt {
    match inspect_fixed_predicate_word64(hir, context, allow_lazy_unit_repetition) {
        Ok(Some(source)) => FixedPredicateInspectionAttempt::Succeeded {
            source,
            receipt: context.close_fixed_predicate(FixedPredicateInspectionTerminal::Succeeded),
        },
        Ok(None) => FixedPredicateInspectionAttempt::Refused {
            receipt: context.close_fixed_predicate(FixedPredicateInspectionTerminal::Refused),
        },
        Err(error) => FixedPredicateInspectionAttempt::ResourceFailure {
            error,
            receipt: context
                .close_fixed_predicate(FixedPredicateInspectionTerminal::ResourceFailure),
        },
    }
}

/// Compatibility entry point for integrations that inspect only after finite
/// extraction refuses.
pub(crate) fn inspect_fixed_predicate_word64_after_finite_refusal_attempt(
    hir: &Hir,
    initial_work: u64,
    work_limit: u64,
) -> FixedPredicateInspectionAttempt {
    inspect_fixed_predicate_word64_attempt(hir, initial_work, work_limit)
}

/// Legacy projection of
/// [`inspect_fixed_predicate_word64_after_finite_refusal_attempt`].
#[allow(
    dead_code,
    reason = "legacy crate-private projection remains for compatibility and focused parity tests"
)]
pub(crate) fn inspect_fixed_predicate_word64_after_finite_refusal(
    hir: &Hir,
    initial_work: u64,
    work_limit: u64,
) -> Result<FixedPredicateInspection, BuildError> {
    inspect_fixed_predicate_word64_after_finite_refusal_attempt(hir, initial_work, work_limit)
        .into_legacy()
}

fn inspect_fixed_predicate_word64(
    hir: &Hir,
    context: &FiniteExtractionContext,
    allow_lazy_unit_repetition: bool,
) -> Result<Option<FixedPredicateWord64Source>, BuildError> {
    let mut tasks = AccountedVec::new(context, FiniteStorage::Scratch);
    tasks.reserve_planner(1, "fixed-predicate task stack")?;
    tasks.push_reserved(FixedPredicateTask::Visit(hir))?;
    let mut source = FixedPredicateWord64Source::EMPTY;
    let mut finite_analyses = FixedPredicateAnalysisStack::new();
    while let Some(task) = tasks.pop() {
        context.charge(1)?;
        let node = match task {
            FixedPredicateTask::Visit(node) => node,
            FixedPredicateTask::FinishConcat(children) => {
                finite_analyses.finish_concat(children, context)?;
                continue;
            }
            FixedPredicateTask::FinishExactRepetition { start, repetitions } => {
                if !repeat_fixed_predicate_suffix(&mut source, start, repetitions, context)? {
                    return Ok(None);
                }
                finite_analyses.mark_top_unsupported()?;
                continue;
            }
            FixedPredicateTask::FinishLazyUnitRepetition { start } => {
                if start != 0 || source.width() != 1 || source.lazy_unit_repetition {
                    return Ok(None);
                }
                source.lazy_unit_repetition = true;
                finite_analyses.mark_top_unsupported()?;
                continue;
            }
        };
        source.hir_nodes = source
            .hir_nodes
            .checked_add(1)
            .ok_or(BuildError::InternalInvariant(
                "fixed-predicate HIR-node accounting overflow",
            ))?;
        match node.kind() {
            HirKind::Capture(capture) => {
                source.captures =
                    source
                        .captures
                        .checked_add(1)
                        .ok_or(BuildError::InternalInvariant(
                            "fixed-predicate capture accounting overflow",
                        ))?;
                tasks.reserve_planner(1, "fixed-predicate task stack")?;
                tasks.push_reserved(FixedPredicateTask::Visit(capture.sub.as_ref()))?;
            }
            HirKind::Concat(children) if !children.is_empty() => {
                let additional = children.len().checked_add(1).ok_or(
                    BuildError::PlannerWorkLimit {
                        needed: u64::MAX,
                        limit: context.work_limit,
                    },
                )?;
                tasks.reserve_planner(additional, "fixed-predicate task stack")?;
                tasks.push_reserved(FixedPredicateTask::FinishConcat(children.len()))?;
                tasks.extend_reserved(
                    children.iter().rev().map(FixedPredicateTask::Visit),
                    children.len(),
                )?;
            }
            HirKind::Repetition(repetition)
                if repetition.max == Some(repetition.min) && repetition.min > 0 =>
            {
                let repetitions = usize::try_from(repetition.min).map_err(|_| {
                    BuildError::InternalInvariant(
                        "fixed-predicate exact repetition does not fit usize",
                    )
                })?;
                if repetitions > FIXED_PREDICATE_WORD64_MAX_WIDTH {
                    return Ok(None);
                }
                tasks.reserve_planner(2, "fixed-predicate exact repetition tasks")?;
                tasks.push_reserved(FixedPredicateTask::FinishExactRepetition {
                    start: source.width(),
                    repetitions,
                })?;
                tasks.push_reserved(FixedPredicateTask::Visit(repetition.sub.as_ref()))?;
            }
            HirKind::Repetition(repetition)
                if allow_lazy_unit_repetition
                    && source.width() == 0
                    && finite_analyses.is_empty()
                    && tasks.is_empty()
                    && repetition.min == 1
                    && repetition.max.is_none()
                    && !repetition.greedy =>
            {
                tasks.reserve_planner(2, "fixed-predicate lazy unit repetition tasks")?;
                tasks.push_reserved(FixedPredicateTask::FinishLazyUnitRepetition {
                    start: source.width(),
                })?;
                tasks.push_reserved(FixedPredicateTask::Visit(repetition.sub.as_ref()))?;
            }
            HirKind::Literal(literal) if !literal.0.is_empty() => {
                if !push_fixed_byte_literal(&mut source, &literal.0, context)? {
                    return Ok(None);
                }
                finite_analyses.push(Analysis::Fits(Shape::leaf(1, literal.0.len())))?;
            }
            HirKind::Class(Class::Bytes(class)) => {
                let index = source.width();
                if !push_fixed_byte_class(&mut source, class, context)? {
                    return Ok(None);
                }
                let members = source.positions[index].member_count();
                finite_analyses.push(Analysis::Fits(Shape::leaf(members, members)))?;
            }
            _ => return Ok(None),
        }
    }
    if source.width() < FIXED_PREDICATE_WORD64_MIN_WIDTH || source.variable_predicates() == 0 {
        return Ok(None);
    }
    let finite_incumbent = finite_analyses.into_single()?;
    if let Analysis::Fits(shape) = finite_incumbent {
        let words = source
            .cartesian_product()
            .ok_or(BuildError::InternalInvariant(
                "finite-incumbent shape fit after Cartesian overflow",
            ))?;
        let bytes = words
            .checked_mul(source.width())
            .ok_or(BuildError::InternalInvariant(
                "finite-incumbent bytes fit after Cartesian-byte overflow",
            ))?;
        if shape.words != words || shape.bytes != bytes {
            return Err(BuildError::InternalInvariant(
                "finite-incumbent shape differs from fixed-predicate Cartesian source",
            ));
        }
    }
    source.finite_incumbent = finite_incumbent;
    Ok(Some(source))
}

#[derive(Clone, Copy)]
enum FixedPredicateTask<'hir> {
    Visit(&'hir Hir),
    FinishConcat(usize),
    FinishExactRepetition { start: usize, repetitions: usize },
    FinishLazyUnitRepetition { start: usize },
}

struct FixedPredicateAnalysisStack {
    values: [Analysis; FIXED_PREDICATE_WORD64_MAX_WIDTH],
    len: usize,
}

impl FixedPredicateAnalysisStack {
    const fn new() -> Self {
        Self {
            values: [Analysis::Unsupported; FIXED_PREDICATE_WORD64_MAX_WIDTH],
            len: 0,
        }
    }

    const fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn push(&mut self, analysis: Analysis) -> Result<(), BuildError> {
        let Some(slot) = self.values.get_mut(self.len) else {
            return Err(BuildError::InternalInvariant(
                "fixed-predicate finite-analysis stack exceeded word width",
            ));
        };
        *slot = analysis;
        self.len = self
            .len
            .checked_add(1)
            .ok_or(BuildError::InternalInvariant(
                "fixed-predicate finite-analysis stack length overflow",
            ))?;
        Ok(())
    }

    fn finish_concat(
        &mut self,
        children: usize,
        context: &FiniteExtractionContext,
    ) -> Result<(), BuildError> {
        let start = self
            .len
            .checked_sub(children)
            .ok_or(BuildError::InternalInvariant(
                "fixed-predicate concat analysis stack underflow",
            ))?;
        context.charge(u64::try_from(children).unwrap_or(u64::MAX))?;
        let combined = combine_analysis(
            &self.values[start..self.len],
            true,
            usize::MAX,
            usize::MAX,
        );
        self.len = start;
        self.push(combined)
    }

    fn mark_top_unsupported(&mut self) -> Result<(), BuildError> {
        let Some(index) = self.len.checked_sub(1) else {
            return Err(BuildError::InternalInvariant(
                "fixed-predicate repetition analysis stack underflow",
            ));
        };
        self.values[index] = Analysis::Unsupported;
        Ok(())
    }

    fn into_single(self) -> Result<Analysis, BuildError> {
        if self.len != 1 {
            return Err(BuildError::InternalInvariant(
                "fixed-predicate inspection did not produce one finite analysis",
            ));
        }
        Ok(self.values[0])
    }
}

fn repeat_fixed_predicate_suffix(
    source: &mut FixedPredicateWord64Source,
    start: usize,
    repetitions: usize,
    context: &FiniteExtractionContext,
) -> Result<bool, BuildError> {
    let end = source.width();
    let Some(width) = end.checked_sub(start) else {
        return Err(BuildError::InternalInvariant(
            "fixed-predicate repetition suffix start exceeded current width",
        ));
    };
    if width == 0 || repetitions == 0 {
        return Ok(false);
    }
    let Some(total_width) = width
        .checked_mul(repetitions)
        .and_then(|repeated| start.checked_add(repeated))
    else {
        return Err(BuildError::InternalInvariant(
            "fixed-predicate exact repetition width overflow",
        ));
    };
    if total_width > FIXED_PREDICATE_WORD64_MAX_WIDTH {
        return Ok(false);
    }
    let additional = total_width
        .checked_sub(end)
        .ok_or(BuildError::InternalInvariant(
            "fixed-predicate exact repetition shrank its source",
        ))?;
    context.charge(u64::try_from(additional).unwrap_or(u64::MAX))?;
    for _ in 1..repetitions {
        for index in start..end {
            let predicate = source.positions[index];
            if !source.push(predicate)? {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn push_fixed_byte_literal(
    source: &mut FixedPredicateWord64Source,
    literal: &[u8],
    context: &FiniteExtractionContext,
) -> Result<bool, BuildError> {
    let width = source
        .width()
        .checked_add(literal.len())
        .ok_or(BuildError::InternalInvariant(
            "fixed-predicate width accounting overflow",
        ))?;
    if width > FIXED_PREDICATE_WORD64_MAX_WIDTH {
        return Ok(false);
    }
    context.charge(u64::try_from(literal.len()).unwrap_or(u64::MAX))?;
    for &byte in literal {
        context.charge(1)?;
        if !source.push(FixedPredicate::singleton(byte))? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn push_fixed_byte_class(
    source: &mut FixedPredicateWord64Source,
    class: &regex_syntax::hir::ClassBytes,
    context: &FiniteExtractionContext,
) -> Result<bool, BuildError> {
    if source.width() == FIXED_PREDICATE_WORD64_MAX_WIDTH {
        return Ok(false);
    }
    if class.ranges().is_empty() || class.ranges().len() > FIXED_PREDICATE_MAX_RANGES {
        return Ok(false);
    }
    context.charge(u64::try_from(class.ranges().len()).unwrap_or(u64::MAX))?;
    let Some(predicate) = FixedPredicate::from_byte_class(class) else {
        return Ok(false);
    };
    context.charge(1)?;
    source.push(predicate)
}

enum PlainFailure {
    TooLargeFixedSequence,
    Resource(BuildError),
}

#[derive(Clone, Copy)]
enum GuardedSymbol {
    Byte(u8),
    Look(Look),
}

struct GuardedPath {
    symbols: ExactVec<GuardedSymbol>,
}

struct GuardedPathLease<'context> {
    path: GuardedPath,
    context: &'context FiniteExtractionContext,
}

impl<'context> GuardedPathLease<'context> {
    fn new(path: GuardedPath, context: &'context FiniteExtractionContext) -> Self {
        Self { path, context }
    }
}

impl Deref for GuardedPathLease<'_> {
    type Target = GuardedPath;

    fn deref(&self) -> &Self::Target {
        &self.path
    }
}

impl Drop for GuardedPathLease<'_> {
    fn drop(&mut self) {
        self.context.release_capacity::<GuardedSymbol>(
            self.path.symbols.capacity(),
            FiniteStorage::Scratch,
        );
    }
}

struct GuardedLanguage<'context> {
    paths: ExactVec<GuardedPath>,
    bytes: usize,
    context: &'context FiniteExtractionContext,
    accounted: bool,
}

impl<'context> GuardedLanguage<'context> {
    fn from_paths(paths: AccountedExactVec<'context, GuardedPath>, bytes: usize) -> Self {
        let context = paths.context;
        Self {
            paths: paths.into_inner_kept(),
            bytes,
            context,
            accounted: true,
        }
    }

    fn empty(context: &'context FiniteExtractionContext) -> Self {
        Self {
            paths: ExactVec::default(),
            bytes: 0,
            context,
            accounted: true,
        }
    }
}

impl Drop for GuardedLanguage<'_> {
    fn drop(&mut self) {
        if !self.accounted {
            return;
        }
        self.context
            .release_capacity::<GuardedPath>(self.paths.capacity(), FiniteStorage::Scratch);
        for path in &self.paths {
            self.context
                .release_capacity::<GuardedSymbol>(path.symbols.capacity(), FiniteStorage::Scratch);
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct GuardedExpansionActual {
    allocations: usize,
    initialized_bytes: usize,
}

struct GuardedSourceWord {
    bytes: ExactVec<u8>,
    left: Guard,
    right: Guard,
}

struct GuardedSource<'context> {
    words: ExactVec<GuardedSourceWord>,
    accounting: GuardedSourceAccounting,
    dictionary_prospective: GuardedBuildProspective,
    context: &'context FiniteExtractionContext,
}

impl Drop for GuardedSource<'_> {
    fn drop(&mut self) {
        self.context
            .release_capacity::<GuardedSourceWord>(self.words.capacity(), FiniteStorage::Scratch);
        for word in &self.words {
            self.context
                .release_capacity::<u8>(word.bytes.capacity(), FiniteStorage::Scratch);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GuardedSourceAccounting {
    words: usize,
    word_bytes: usize,
    allocations: usize,
    storage_bytes: usize,
    expansion_allocations_upper_bound: usize,
    expansion_allocations_actual: usize,
    expansion_initialized_bytes_upper_bound: usize,
    expansion_initialized_bytes_actual: usize,
    expansion_peak_bytes_upper_bound: usize,
    source_transition_peak_bytes_upper_bound: usize,
    construction_allocations_upper_bound: usize,
    construction_initialized_bytes_upper_bound: usize,
    construction_peak_bytes_upper_bound: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GuardedFiniteAccounting {
    source: GuardedSourceAccounting,
    allocations_upper_bound: usize,
    allocations_actual: usize,
    initialized_bytes_upper_bound: usize,
    initialized_bytes_actual: usize,
    peak_bytes_actual_upper_bound: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GuardedFiniteAccountingSummary {
    pub allocations_upper_bound: usize,
    pub allocations_actual: usize,
    pub initialized_bytes_upper_bound: usize,
    pub initialized_bytes_actual: usize,
    pub peak_bytes_upper_bound: usize,
    pub peak_bytes_actual_upper_bound: usize,
}

impl GuardedFiniteAccounting {
    fn is_consistent(self, dictionary: &GuardedDictionary) -> bool {
        let dictionary = dictionary.build_accounting();
        let allocations_upper_bound = self
            .source
            .expansion_allocations_upper_bound
            .checked_add(self.source.allocations)
            .and_then(|total| total.checked_add(dictionary.prospective.allocations));
        let allocations_actual = self
            .source
            .expansion_allocations_actual
            .checked_add(self.source.allocations)
            .and_then(|total| total.checked_add(dictionary.actual.allocations));
        let initialized_bytes_upper_bound = self
            .source
            .expansion_initialized_bytes_upper_bound
            .checked_add(self.source.storage_bytes)
            .and_then(|total| total.checked_add(dictionary.prospective.initialized_bytes));
        let initialized_bytes_actual = self
            .source
            .expansion_initialized_bytes_actual
            .checked_add(self.source.storage_bytes)
            .and_then(|total| total.checked_add(dictionary.actual.initialized_bytes));
        self.source.words > 0
            && self.source.word_bytes >= self.source.words
            && self.source.allocations == self.source.words.saturating_add(1)
            && self.source.expansion_allocations_actual
                <= self.source.expansion_allocations_upper_bound
            && self.source.expansion_initialized_bytes_actual
                <= self.source.expansion_initialized_bytes_upper_bound
            && dictionary.prospective.dimensions.words == self.source.words
            && dictionary.prospective.dimensions.packed_bytes == self.source.word_bytes
            && dictionary.actual.published
            && allocations_upper_bound == Some(self.allocations_upper_bound)
            && allocations_actual == Some(self.allocations_actual)
            && initialized_bytes_upper_bound == Some(self.initialized_bytes_upper_bound)
            && initialized_bytes_actual == Some(self.initialized_bytes_actual)
            && self.allocations_upper_bound == self.source.construction_allocations_upper_bound
            && self.initialized_bytes_upper_bound
                == self.source.construction_initialized_bytes_upper_bound
            && self.allocations_actual <= self.allocations_upper_bound
            && self.initialized_bytes_actual <= self.initialized_bytes_upper_bound
            && self.peak_bytes_actual_upper_bound <= self.source.construction_peak_bytes_upper_bound
    }

    pub(crate) fn summary(
        self,
        dictionary: &GuardedDictionary,
    ) -> Option<GuardedFiniteAccountingSummary> {
        self.is_consistent(dictionary)
            .then_some(GuardedFiniteAccountingSummary {
                allocations_upper_bound: self.allocations_upper_bound,
                allocations_actual: self.allocations_actual,
                initialized_bytes_upper_bound: self.initialized_bytes_upper_bound,
                initialized_bytes_actual: self.initialized_bytes_actual,
                peak_bytes_upper_bound: self.source.construction_peak_bytes_upper_bound,
                peak_bytes_actual_upper_bound: self.peak_bytes_actual_upper_bound,
            })
    }
}

#[derive(Clone, Copy)]
enum GuardedRefusal {
    TooLargeFixedSequence,
    Unsupported,
}

type GuardedSourceResult<'context> = Result<GuardedSource<'context>, GuardedRefusal>;
type GuardedDictionaryResult = Result<(GuardedDictionary, GuardedFiniteAccounting), GuardedRefusal>;

fn extract_plain(
    hir: &Hir,
    max_words: usize,
    max_bytes: usize,
    context: &FiniteExtractionContext,
) -> Result<Option<Vec<Vec<u8>>>, PlainFailure> {
    match analyze(hir, max_words, max_bytes, context).map_err(PlainFailure::Resource)? {
        Analysis::Fits(_) => {}
        Analysis::TooLargeFixedSequence => return Err(PlainFailure::TooLargeFixedSequence),
        Analysis::Unsupported => return Ok(None),
    }
    let mut tasks = AccountedVec::new(context, FiniteStorage::Scratch);
    tasks
        .reserve_planner(1, "finite-language task stack")
        .map_err(PlainFailure::Resource)?;
    tasks
        .push_reserved(Task::Visit(hir))
        .map_err(PlainFailure::Resource)?;
    let mut values = AccountedVec::new(context, FiniteStorage::Scratch);
    while let Some(task) = tasks.pop() {
        context.charge(1).map_err(PlainFailure::Resource)?;
        execute_plain_task(task, &mut tasks, &mut values, max_words, max_bytes, context)?;
    }
    if values.len() != 1 {
        return Err(PlainFailure::Resource(BuildError::InternalInvariant(
            "finite-language stack did not produce one value",
        )));
    }
    let language = values
        .pop()
        .ok_or(PlainFailure::Resource(BuildError::InternalInvariant(
            "finite-language value disappeared",
        )))?;
    Ok(Some(language.into_words()))
}

fn execute_plain_task<'hir, 'context>(
    task: Task<'hir>,
    tasks: &mut AccountedVec<'context, Task<'hir>>,
    values: &mut AccountedVec<'context, Language<'context>>,
    max_words: usize,
    max_bytes: usize,
    context: &'context FiniteExtractionContext,
) -> Result<(), PlainFailure> {
    match task {
        Task::Visit(node) => visit_plain_node(node, tasks, values, max_words, max_bytes, context),
        Task::FinishConcat(children) => {
            finish_plain_languages(values, children, true, max_words, max_bytes, context)
        }
        Task::FinishAlternation(children) => {
            finish_plain_languages(values, children, false, max_words, max_bytes, context)
        }
    }
}

fn visit_plain_node<'hir, 'context>(
    node: &'hir Hir,
    tasks: &mut AccountedVec<'context, Task<'hir>>,
    values: &mut AccountedVec<'context, Language<'context>>,
    max_words: usize,
    max_bytes: usize,
    context: &'context FiniteExtractionContext,
) -> Result<(), PlainFailure> {
    let language = match node.kind() {
        HirKind::Empty => Some(
            singleton_language(
                AccountedVec::new(context, FiniteStorage::Persistent),
                context,
            )
            .map_err(PlainFailure::Resource)?,
        ),
        HirKind::Literal(literal) => {
            if literal.0.len() > max_bytes || max_words == 0 {
                return Err(plain_invariant(
                    "finite literal exceeded successful analysis",
                ));
            }
            let mut word = AccountedVec::new(context, FiniteStorage::Persistent);
            word.reserve_planner(literal.0.len(), "finite-language literal bytes")
                .map_err(PlainFailure::Resource)?;
            word.extend_reserved(literal.0.iter().copied(), literal.0.len())
                .map_err(PlainFailure::Resource)?;
            Some(singleton_language(word, context).map_err(PlainFailure::Resource)?)
        }
        HirKind::Class(Class::Bytes(class)) => Some(
            byte_class(class, max_words, max_bytes, context)
                .map_err(PlainFailure::Resource)?
                .ok_or_else(|| plain_invariant("finite byte class exceeded successful analysis"))?,
        ),
        HirKind::Class(Class::Unicode(class)) => Some(
            unicode_class(class, max_words, max_bytes, context)
                .map_err(PlainFailure::Resource)?
                .ok_or_else(|| {
                    plain_invariant("finite Unicode class exceeded successful analysis")
                })?,
        ),
        HirKind::Capture(capture) => {
            push_visit(tasks, &capture.sub).map_err(PlainFailure::Resource)?;
            None
        }
        HirKind::Concat(children) => {
            push_children(tasks, children, Task::FinishConcat(children.len()))
                .map_err(PlainFailure::Resource)?;
            None
        }
        HirKind::Alternation(children) => {
            push_children(tasks, children, Task::FinishAlternation(children.len()))
                .map_err(PlainFailure::Resource)?;
            None
        }
        HirKind::Look(_) | HirKind::Repetition(_) => {
            return Err(plain_invariant(
                "unsupported finite node passed successful analysis",
            ));
        }
    };
    if let Some(language) = language {
        push_language(values, language).map_err(PlainFailure::Resource)?;
    }
    Ok(())
}

fn finish_plain_languages<'context>(
    values: &mut AccountedVec<'context, Language<'context>>,
    children: usize,
    concatenate: bool,
    max_words: usize,
    max_bytes: usize,
    context: &'context FiniteExtractionContext,
) -> Result<(), PlainFailure> {
    let child_languages =
        pop_languages(values, children, context).map_err(PlainFailure::Resource)?;
    let language = if concatenate {
        concat_languages(child_languages, max_words, max_bytes, context)
    } else {
        alternate_languages(child_languages, max_words, max_bytes, context)
    }
    .map_err(PlainFailure::Resource)?
    .ok_or_else(|| plain_invariant("finite combination exceeded successful analysis"))?;
    push_language(values, language).map_err(PlainFailure::Resource)
}

const fn plain_invariant(detail: &'static str) -> PlainFailure {
    PlainFailure::Resource(BuildError::InternalInvariant(detail))
}

fn extract_guarded_source<'context>(
    hir: &Hir,
    max_words: usize,
    max_bytes: usize,
    context: &'context FiniteExtractionContext,
    semantics: GuardedFiniteBoundarySemantics,
    guarded_limits: GuardedFiniteBuildLimits,
) -> Result<GuardedSourceResult<'context>, GuardedAttemptError> {
    let materialization = match prove_guarded_materialization(
        hir,
        max_words,
        max_bytes,
        context,
        semantics,
        guarded_limits,
    )? {
        Ok(materialization) => materialization,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let plan = materialization.plan;
    admit_guarded_source_work(plan, context.work(), context.work_limit)?;
    publish_guarded_source(materialization, plan, semantics, context).map_err(Into::into)
}

struct GuardedMaterialization<'context> {
    language: GuardedLanguage<'context>,
    expansion_actual: GuardedExpansionActual,
    plan: GuardedSourcePlan,
}

type GuardedMaterializationResult<'context> =
    Result<GuardedMaterialization<'context>, GuardedRefusal>;

fn prove_guarded_materialization<'context>(
    hir: &Hir,
    max_words: usize,
    max_bytes: usize,
    context: &'context FiniteExtractionContext,
    semantics: GuardedFiniteBoundarySemantics,
    guarded_limits: GuardedFiniteBuildLimits,
) -> Result<GuardedMaterializationResult<'context>, GuardedAttemptError> {
    if !guarded_structure_supported(hir, semantics, context)? {
        return Ok(Err(GuardedRefusal::Unsupported));
    }
    let Some(shape) = guarded_shape(hir, context)? else {
        return Ok(Err(GuardedRefusal::TooLargeFixedSequence));
    };
    if !shape.fits(max_words, max_bytes) {
        return Ok(Err(GuardedRefusal::TooLargeFixedSequence));
    }
    let expected_symbols = shape
        .paths
        .checked_mul(2)
        .and_then(|guards| guards.checked_add(shape.bytes))
        .ok_or(BuildError::PersistentBytesOverflow)?;
    if shape.symbols != expected_symbols {
        return Err(BuildError::InternalInvariant(
            "guarded finite shape does not contain exactly two endpoint guards per word",
        )
        .into());
    }
    let plan = close_guarded_source_plan(shape, guarded_limits, context)?;
    admit_guarded_source_work(plan, context.work(), context.work_limit)?;
    let mut expansion = GuardedExpansionContext {
        max_words,
        max_bytes,
        attempt: context,
        actual: GuardedExpansionActual::default(),
    };
    let language = match expand_guarded(hir, &mut expansion)? {
        GuardedExpansion::Fits(language) => language,
        GuardedExpansion::TooLargeFixedSequence => {
            return Ok(Err(GuardedRefusal::TooLargeFixedSequence));
        }
        GuardedExpansion::Unsupported => return Ok(Err(GuardedRefusal::Unsupported)),
    };
    let expansion_actual = expansion.actual;
    if language.paths.is_empty() {
        return Ok(Err(GuardedRefusal::Unsupported));
    }
    if language.paths.len() != shape.paths || language.bytes != shape.bytes {
        return Err(BuildError::InternalInvariant(
            "guarded finite materialization differs from its shape theorem",
        )
        .into());
    }
    if expansion_actual.allocations > shape.construction_allocations_upper_bound
        || expansion_actual.initialized_bytes > shape.construction_initialized_bytes_upper_bound
    {
        return Err(BuildError::InternalInvariant(
            "guarded finite expansion exceeded its prospective construction envelope",
        )
        .into());
    }
    Ok(Ok(GuardedMaterialization {
        language,
        expansion_actual,
        plan,
    }))
}

#[derive(Clone, Copy)]
struct GuardedSourcePlan {
    words: usize,
    word_bytes: usize,
    allocations: usize,
    storage_bytes: usize,
    expansion_allocations_upper_bound: usize,
    expansion_initialized_bytes_upper_bound: usize,
    expansion_peak_bytes_upper_bound: usize,
    source_transition_peak_bytes_upper_bound: usize,
    construction_allocations_upper_bound: usize,
    construction_initialized_bytes_upper_bound: usize,
    construction_peak_bytes_upper_bound: usize,
    source_publication_work: u64,
    dictionary_prospective: GuardedBuildProspective,
}

fn close_guarded_source_plan(
    shape: GuardedShape,
    limits: GuardedFiniteBuildLimits,
    context: &FiniteExtractionContext,
) -> Result<GuardedSourcePlan, GuardedAttemptError> {
    let source_words = shape.paths;
    let source_word_bytes = shape.bytes;
    let expansion_final_bytes = shape
        .final_heap_bytes()
        .ok_or(BuildError::PersistentBytesOverflow)?;
    let expansion_peak_bytes_upper_bound = shape
        .peak_heap_bytes_upper_bound()
        .ok_or(BuildError::PersistentBytesOverflow)?;
    let source_entry_bytes = source_words
        .checked_mul(size_of::<GuardedSourceWord>())
        .ok_or(BuildError::PersistentBytesOverflow)?;
    let source_storage_bytes = source_entry_bytes
        .checked_add(source_word_bytes)
        .ok_or(BuildError::PersistentBytesOverflow)?;
    let source_allocations = source_words
        .checked_add(1)
        .ok_or(BuildError::PersistentBytesOverflow)?;
    let source_transition_peak_bytes_upper_bound = expansion_final_bytes
        .checked_add(source_storage_bytes)
        .ok_or(BuildError::PersistentBytesOverflow)?;
    let dictionary_dimensions = GuardedBuildDimensions {
        words: source_words,
        packed_bytes: source_word_bytes,
    };
    let dictionary_prospective =
        match GuardedDictionary::preflight(dictionary_dimensions, limits.dictionary) {
            Ok(prospective) => prospective,
            Err(error) => {
                context.bind_guarded(&FiniteExtractionGuardedEvidence::Failed {
                    accounting: error.actual(),
                    co_live_local_scratch_bytes: context.live_scratch_bytes(),
                })?;
                return Err(GuardedAttemptError::Build(
                    GuardedFiniteBuildError::Dictionary(error),
                ));
            }
        };
    let dictionary_peak_bytes_upper_bound = source_storage_bytes
        .checked_add(dictionary_prospective.peak_bytes)
        .ok_or(BuildError::PersistentBytesOverflow)?;
    let construction_allocations_upper_bound = shape
        .construction_allocations_upper_bound
        .checked_add(source_allocations)
        .and_then(|total| total.checked_add(dictionary_prospective.allocations))
        .ok_or(BuildError::PersistentBytesOverflow)?;
    let construction_initialized_bytes_upper_bound = shape
        .construction_initialized_bytes_upper_bound
        .checked_add(source_storage_bytes)
        .and_then(|total| total.checked_add(dictionary_prospective.initialized_bytes))
        .ok_or(BuildError::PersistentBytesOverflow)?;
    let construction_peak_bytes_upper_bound = expansion_peak_bytes_upper_bound
        .max(source_transition_peak_bytes_upper_bound)
        .max(dictionary_peak_bytes_upper_bound);
    let construction_scratch_bytes_upper_bound =
        expansion_peak_bytes_upper_bound.max(source_transition_peak_bytes_upper_bound);
    enforce_guarded_construction_limit(
        GuardedFiniteBuildResource::ScratchBytes,
        construction_scratch_bytes_upper_bound,
        limits.max_scratch_bytes,
    )?;
    enforce_guarded_construction_limit(
        GuardedFiniteBuildResource::PeakBytes,
        construction_peak_bytes_upper_bound,
        limits.max_peak_bytes,
    )?;
    let source_publication_work = source_words
        .checked_mul(2)
        .and_then(|amount| source_word_bytes.checked_mul(2)?.checked_add(amount))
        .and_then(|amount| u64::try_from(amount).ok())
        .ok_or(BuildError::PlannerWorkLimit {
            needed: u64::MAX,
            limit: u64::MAX,
        })?;
    Ok(GuardedSourcePlan {
        words: source_words,
        word_bytes: source_word_bytes,
        allocations: source_allocations,
        storage_bytes: source_storage_bytes,
        expansion_allocations_upper_bound: shape.construction_allocations_upper_bound,
        expansion_initialized_bytes_upper_bound: shape.construction_initialized_bytes_upper_bound,
        expansion_peak_bytes_upper_bound,
        source_transition_peak_bytes_upper_bound,
        construction_allocations_upper_bound,
        construction_initialized_bytes_upper_bound,
        construction_peak_bytes_upper_bound,
        source_publication_work,
        dictionary_prospective,
    })
}

fn enforce_guarded_construction_limit(
    resource: GuardedFiniteBuildResource,
    needed: usize,
    limit: usize,
) -> Result<(), GuardedAttemptError> {
    if needed > limit {
        return Err(GuardedAttemptError::Build(
            GuardedFiniteBuildError::ConstructionLimit {
                resource,
                needed,
                limit,
            },
        ));
    }
    Ok(())
}

fn admit_guarded_source_work(
    plan: GuardedSourcePlan,
    work: u64,
    work_limit: u64,
) -> Result<(), BuildError> {
    let admitted_work = work
        .checked_add(plan.source_publication_work)
        .and_then(|needed| needed.checked_add(plan.dictionary_prospective.build_work))
        .ok_or(BuildError::PlannerWorkLimit {
            needed: u64::MAX,
            limit: work_limit,
        })?;
    if admitted_work > work_limit {
        return Err(BuildError::PlannerWorkLimit {
            needed: admitted_work,
            limit: work_limit,
        });
    }
    Ok(())
}

fn publish_guarded_source<'context>(
    materialization: GuardedMaterialization<'context>,
    plan: GuardedSourcePlan,
    semantics: GuardedFiniteBoundarySemantics,
    context: &'context FiniteExtractionContext,
) -> Result<GuardedSourceResult<'context>, BuildError> {
    let GuardedMaterialization {
        mut language,
        expansion_actual,
        plan: _,
    } = materialization;
    context.charge(u64::try_from(plan.words).unwrap_or(u64::MAX))?;
    let mut source = AccountedExactVec::try_with_capacity(
        context,
        FiniteStorage::Scratch,
        plan.words,
        "guarded finite source words",
    )?;
    language.paths.as_mut_slice().reverse();
    while let Some(path) = language.paths.pop() {
        let path = GuardedPathLease::new(path, context);
        context.charge(1)?;
        let Some((first, middle)) = path.symbols.split_first() else {
            return Ok(Err(GuardedRefusal::Unsupported));
        };
        let Some((last, body)) = middle.split_last() else {
            return Ok(Err(GuardedRefusal::Unsupported));
        };
        let GuardedSymbol::Look(left) = first else {
            return Ok(Err(GuardedRefusal::Unsupported));
        };
        let GuardedSymbol::Look(right) = last else {
            return Ok(Err(GuardedRefusal::Unsupported));
        };
        let Some(left) = map_left_guard(*left, semantics) else {
            return Ok(Err(GuardedRefusal::Unsupported));
        };
        let Some(right) = map_right_guard(*right, semantics) else {
            return Ok(Err(GuardedRefusal::Unsupported));
        };
        context.charge(u64::try_from(body.len()).unwrap_or(u64::MAX))?;
        let mut bytes = AccountedExactVec::try_with_capacity(
            context,
            FiniteStorage::Scratch,
            body.len(),
            "guarded finite word bytes",
        )?;
        for symbol in body {
            context.charge(1)?;
            let GuardedSymbol::Byte(byte) = symbol else {
                return Ok(Err(GuardedRefusal::Unsupported));
            };
            if !is_ascii_word_byte(*byte) {
                return Ok(Err(GuardedRefusal::Unsupported));
            }
            bytes.push_accounted(*byte, true, "exact guarded word capacity changed")?;
        }
        if bytes.is_empty() {
            return Ok(Err(GuardedRefusal::Unsupported));
        }
        source.push_accounted(
            GuardedSourceWord {
                bytes: bytes.into_inner_kept(),
                left,
                right,
            },
            false,
            "exact guarded source capacity changed",
        )?;
    }
    Ok(Ok(GuardedSource {
        words: source.into_inner_kept(),
        accounting: GuardedSourceAccounting {
            words: plan.words,
            word_bytes: plan.word_bytes,
            allocations: plan.allocations,
            storage_bytes: plan.storage_bytes,
            expansion_allocations_upper_bound: plan.expansion_allocations_upper_bound,
            expansion_allocations_actual: expansion_actual.allocations,
            expansion_initialized_bytes_upper_bound: plan.expansion_initialized_bytes_upper_bound,
            expansion_initialized_bytes_actual: expansion_actual.initialized_bytes,
            expansion_peak_bytes_upper_bound: plan.expansion_peak_bytes_upper_bound,
            source_transition_peak_bytes_upper_bound: plan.source_transition_peak_bytes_upper_bound,
            construction_allocations_upper_bound: plan.construction_allocations_upper_bound,
            construction_initialized_bytes_upper_bound: plan
                .construction_initialized_bytes_upper_bound,
            construction_peak_bytes_upper_bound: plan.construction_peak_bytes_upper_bound,
        },
        dictionary_prospective: plan.dictionary_prospective,
        context,
    }))
}

const fn map_guarded_source_allocation(
    error: CopyError,
    structure: &'static str,
    additional: usize,
) -> BuildError {
    match error {
        CopyError::LayoutOverflow => BuildError::PersistentBytesOverflow,
        CopyError::AllocationFailed => BuildError::AllocationFailed {
            structure,
            additional,
        },
    }
}

fn guarded_structure_supported(
    hir: &Hir,
    semantics: GuardedFiniteBoundarySemantics,
    context: &FiniteExtractionContext,
) -> Result<bool, BuildError> {
    let Some(relation) = guarded_relation(hir, semantics, context)? else {
        return Ok(false);
    };
    Ok(relation.rows[GUARDED_START_STATE] == GUARDED_ACCEPT_BIT)
}

const GUARDED_STATES: usize = 5;
const GUARDED_START_STATE: usize = 0;
const GUARDED_AFTER_LEFT_STATE: usize = 1;
const GUARDED_IN_WORD_STATE: usize = 2;
const GUARDED_ACCEPT_STATE: usize = 3;
const GUARDED_DEAD_STATE: usize = 4;
const GUARDED_ACCEPT_BIT: u8 = 1 << GUARDED_ACCEPT_STATE;

#[derive(Clone, Copy)]
struct GuardedRelation {
    rows: [u8; GUARDED_STATES],
}

impl GuardedRelation {
    const fn empty_language() -> Self {
        Self {
            rows: [0; GUARDED_STATES],
        }
    }

    const fn identity() -> Self {
        Self {
            rows: [1, 2, 4, 8, 16],
        }
    }

    fn union(self, other: Self) -> Self {
        let mut rows = [0_u8; GUARDED_STATES];
        for (index, row) in rows.iter_mut().enumerate() {
            *row = self.rows[index] | other.rows[index];
        }
        Self { rows }
    }

    fn then(self, other: Self) -> Self {
        let mut rows = [0_u8; GUARDED_STATES];
        for (start, row) in rows.iter_mut().enumerate() {
            let mut destinations = 0_u8;
            for middle in 0..GUARDED_STATES {
                if self.rows[start] & (1_u8 << middle) != 0 {
                    destinations |= other.rows[middle];
                }
            }
            *row = destinations;
        }
        Self { rows }
    }
}

fn guarded_relation(
    hir: &Hir,
    semantics: GuardedFiniteBoundarySemantics,
    context: &FiniteExtractionContext,
) -> Result<Option<GuardedRelation>, BuildError> {
    context.charge(1)?;
    match hir.kind() {
        HirKind::Empty => Ok(Some(GuardedRelation::identity())),
        HirKind::Literal(literal) => {
            let mut relation = GuardedRelation::identity();
            for &byte in &literal.0 {
                context.charge(1)?;
                if !is_ascii_word_byte(byte) {
                    return Ok(None);
                }
                relation = relation.then(guarded_byte_relation());
            }
            Ok(Some(relation))
        }
        HirKind::Class(Class::Bytes(class)) => {
            let mut has_member = false;
            for range in class.ranges() {
                for byte in range.start()..=range.end() {
                    context.charge(1)?;
                    if !is_ascii_word_byte(byte) {
                        return Ok(None);
                    }
                    has_member = true;
                }
            }
            Ok(has_member.then_some(guarded_byte_relation()))
        }
        HirKind::Class(Class::Unicode(class)) => {
            let mut has_member = false;
            for range in class.ranges() {
                for scalar in range.start()..=range.end() {
                    context.charge(1)?;
                    let Ok(byte) = u8::try_from(u32::from(scalar)) else {
                        return Ok(None);
                    };
                    if !is_ascii_word_byte(byte) {
                        return Ok(None);
                    }
                    has_member = true;
                }
            }
            Ok(has_member.then_some(guarded_byte_relation()))
        }
        HirKind::Look(look) => Ok(guarded_look_relation(*look, semantics)),
        HirKind::Capture(capture) => guarded_relation(&capture.sub, semantics, context),
        HirKind::Concat(children) => {
            let mut relation = GuardedRelation::identity();
            for child in children {
                let Some(child) = guarded_relation(child, semantics, context)? else {
                    return Ok(None);
                };
                relation = relation.then(child);
            }
            Ok(Some(relation))
        }
        HirKind::Alternation(children) => {
            let mut relation = GuardedRelation::empty_language();
            for child in children {
                let Some(child) = guarded_relation(child, semantics, context)? else {
                    return Ok(None);
                };
                relation = relation.union(child);
            }
            Ok(Some(relation))
        }
        HirKind::Repetition(repetition) => {
            let Some(maximum) = repetition.max else {
                return Ok(None);
            };
            if maximum < repetition.min {
                return Ok(None);
            }
            let Some(sub) = guarded_relation(&repetition.sub, semantics, context)? else {
                return Ok(None);
            };
            let mut result = GuardedRelation::empty_language();
            let mut power = GuardedRelation::identity();
            let mut count = 0_u32;
            loop {
                context.charge(1)?;
                if count >= repetition.min {
                    result = result.union(power);
                }
                if count == maximum {
                    break;
                }
                power = power.then(sub);
                count = count.checked_add(1).ok_or(BuildError::InternalInvariant(
                    "bounded guarded relation count overflow",
                ))?;
            }
            Ok(Some(result))
        }
    }
}

const fn guarded_byte_relation() -> GuardedRelation {
    GuardedRelation {
        rows: [
            1 << GUARDED_DEAD_STATE,
            1 << GUARDED_IN_WORD_STATE,
            1 << GUARDED_IN_WORD_STATE,
            1 << GUARDED_DEAD_STATE,
            1 << GUARDED_DEAD_STATE,
        ],
    }
}

const fn guarded_look_relation(
    look: Look,
    semantics: GuardedFiniteBoundarySemantics,
) -> Option<GuardedRelation> {
    let dead = 1 << GUARDED_DEAD_STATE;
    match (look, semantics) {
        (Look::WordAscii, GuardedFiniteBoundarySemantics::Ascii)
        | (Look::WordUnicode, GuardedFiniteBoundarySemantics::UnicodeFull) => {
            Some(GuardedRelation {
                rows: [
                    1 << GUARDED_AFTER_LEFT_STATE,
                    dead,
                    1 << GUARDED_ACCEPT_STATE,
                    dead,
                    dead,
                ],
            })
        }
        (
            Look::WordStartAscii | Look::WordStartHalfAscii,
            GuardedFiniteBoundarySemantics::Ascii,
        ) => Some(GuardedRelation {
            rows: [1 << GUARDED_AFTER_LEFT_STATE, dead, dead, dead, dead],
        }),
        (Look::WordEndAscii | Look::WordEndHalfAscii, GuardedFiniteBoundarySemantics::Ascii) => {
            Some(GuardedRelation {
                rows: [dead, dead, 1 << GUARDED_ACCEPT_STATE, dead, dead],
            })
        }
        _ => None,
    }
}

#[derive(Clone, Copy)]
struct GuardedShape {
    paths: usize,
    bytes: usize,
    symbols: usize,
    peak_paths: usize,
    peak_bytes: usize,
    peak_symbols: usize,
    construction_allocations_upper_bound: usize,
    construction_initialized_bytes_upper_bound: usize,
}

impl GuardedShape {
    const fn empty_language() -> Self {
        Self {
            paths: 0,
            bytes: 0,
            symbols: 0,
            peak_paths: 0,
            peak_bytes: 0,
            peak_symbols: 0,
            construction_allocations_upper_bound: 0,
            construction_initialized_bytes_upper_bound: 0,
        }
    }

    fn leaf(paths: usize, bytes: usize, symbols: usize) -> Option<Self> {
        let storage_bytes = guarded_expansion_storage_bytes(paths, symbols)?;
        Some(Self {
            paths,
            bytes,
            symbols,
            peak_paths: paths,
            peak_bytes: bytes,
            peak_symbols: symbols,
            construction_allocations_upper_bound: guarded_output_allocation_upper_bound(paths)?,
            construction_initialized_bytes_upper_bound: storage_bytes,
        })
    }

    const fn fits(self, max_words: usize, max_bytes: usize) -> bool {
        self.paths <= max_words
            && self.bytes <= max_bytes
            && self.peak_paths <= max_words
            && self.peak_bytes <= max_bytes
    }

    fn final_heap_bytes(self) -> Option<usize> {
        guarded_expansion_storage_bytes(self.paths, self.symbols)
    }

    fn peak_heap_bytes_upper_bound(self) -> Option<usize> {
        guarded_expansion_storage_bytes(self.peak_paths, self.peak_symbols)
    }
}

fn guarded_output_allocation_upper_bound(paths: usize) -> Option<usize> {
    usize::from(paths != 0).checked_add(paths)
}

fn guarded_expansion_storage_bytes(paths: usize, symbols: usize) -> Option<usize> {
    paths
        .checked_mul(size_of::<GuardedPath>())?
        .checked_add(symbols.checked_mul(size_of::<GuardedSymbol>())?)
}

fn guarded_shape(
    hir: &Hir,
    context: &FiniteExtractionContext,
) -> Result<Option<GuardedShape>, BuildError> {
    context.charge(1)?;
    match hir.kind() {
        HirKind::Empty => Ok(GuardedShape::leaf(1, 0, 0)),
        HirKind::Literal(literal) => Ok(GuardedShape::leaf(1, literal.0.len(), literal.0.len())),
        HirKind::Class(Class::Bytes(class)) => {
            let Some(count) = byte_class_count(class) else {
                return Ok(None);
            };
            Ok(GuardedShape::leaf(count, count, count))
        }
        HirKind::Class(Class::Unicode(class)) => {
            let Some((count, bytes)) = unicode_class_count(class, usize::MAX, usize::MAX) else {
                return Ok(None);
            };
            Ok(GuardedShape::leaf(count, bytes, count))
        }
        HirKind::Look(_) => Ok(GuardedShape::leaf(1, 0, 1)),
        HirKind::Capture(capture) => guarded_shape(&capture.sub, context),
        HirKind::Concat(children) => {
            let Some(mut output) = GuardedShape::leaf(1, 0, 0) else {
                return Ok(None);
            };
            for child in children {
                let Some(child) = guarded_shape(child, context)? else {
                    return Ok(None);
                };
                let Some(next) = concat_guarded_shape(output, child) else {
                    return Ok(None);
                };
                output = next;
            }
            Ok(Some(output))
        }
        HirKind::Alternation(children) => {
            let mut output = GuardedShape::empty_language();
            for child in children {
                let Some(child) = guarded_shape(child, context)? else {
                    return Ok(None);
                };
                let Some(next) = alternate_guarded_shape(output, child) else {
                    return Ok(None);
                };
                output = next;
            }
            Ok(Some(output))
        }
        HirKind::Repetition(repetition) => guarded_repetition_shape(repetition, context),
    }
}

fn guarded_repetition_shape(
    repetition: &regex_syntax::hir::Repetition,
    context: &FiniteExtractionContext,
) -> Result<Option<GuardedShape>, BuildError> {
    let Some(maximum) = repetition.max else {
        return Ok(None);
    };
    let Some(optional) = maximum.checked_sub(repetition.min) else {
        return Ok(None);
    };
    let Some(sub) = guarded_shape(&repetition.sub, context)? else {
        return Ok(None);
    };
    let Some(mut output) = GuardedShape::leaf(1, 0, 0) else {
        return Ok(None);
    };
    let Some(co_live_paths) = sub.paths.checked_add(output.peak_paths) else {
        return Ok(None);
    };
    let Some(co_live_bytes) = sub.bytes.checked_add(output.peak_bytes) else {
        return Ok(None);
    };
    let Some(co_live_symbols) = sub.symbols.checked_add(output.peak_symbols) else {
        return Ok(None);
    };
    output.peak_paths = sub.peak_paths.max(co_live_paths);
    output.peak_bytes = sub.peak_bytes.max(co_live_bytes);
    output.peak_symbols = sub.peak_symbols.max(co_live_symbols);
    let Some(allocations) = output
        .construction_allocations_upper_bound
        .checked_add(sub.construction_allocations_upper_bound)
    else {
        return Ok(None);
    };
    output.construction_allocations_upper_bound = allocations;
    let Some(initialized_bytes) = output
        .construction_initialized_bytes_upper_bound
        .checked_add(sub.construction_initialized_bytes_upper_bound)
    else {
        return Ok(None);
    };
    output.construction_initialized_bytes_upper_bound = initialized_bytes;
    for _ in 0..repetition.min {
        context.charge(1)?;
        let Some(next) = concat_guarded_shape(output, sub) else {
            return Ok(None);
        };
        output = next;
    }
    for _ in 0..optional {
        context.charge(1)?;
        let Some(next) = optional_guarded_shape(output, sub) else {
            return Ok(None);
        };
        output = next;
    }
    Ok(Some(output))
}

fn concat_guarded_shape(left: GuardedShape, right: GuardedShape) -> Option<GuardedShape> {
    let paths = left.paths.checked_mul(right.paths)?;
    let bytes = left
        .bytes
        .checked_mul(right.paths)?
        .checked_add(right.bytes.checked_mul(left.paths)?)?;
    let symbols = left
        .symbols
        .checked_mul(right.paths)?
        .checked_add(right.symbols.checked_mul(left.paths)?)?;
    let output_storage = guarded_expansion_storage_bytes(paths, symbols)?;
    Some(GuardedShape {
        paths,
        bytes,
        symbols,
        peak_paths: left
            .peak_paths
            .max(left.paths.checked_add(right.peak_paths)?)
            .max(left.paths.checked_add(right.paths)?.checked_add(paths)?),
        peak_bytes: left
            .peak_bytes
            .max(left.bytes.checked_add(right.peak_bytes)?)
            .max(left.bytes.checked_add(right.bytes)?.checked_add(bytes)?),
        peak_symbols: left
            .peak_symbols
            .max(left.symbols.checked_add(right.peak_symbols)?)
            .max(
                left.symbols
                    .checked_add(right.symbols)?
                    .checked_add(symbols)?,
            ),
        construction_allocations_upper_bound: left
            .construction_allocations_upper_bound
            .checked_add(right.construction_allocations_upper_bound)?
            .checked_add(guarded_output_allocation_upper_bound(paths)?)?,
        construction_initialized_bytes_upper_bound: left
            .construction_initialized_bytes_upper_bound
            .checked_add(right.construction_initialized_bytes_upper_bound)?
            .checked_add(output_storage)?,
    })
}

fn alternate_guarded_shape(left: GuardedShape, right: GuardedShape) -> Option<GuardedShape> {
    let paths = left.paths.checked_add(right.paths)?;
    let bytes = left.bytes.checked_add(right.bytes)?;
    let symbols = left.symbols.checked_add(right.symbols)?;
    let output_storage = guarded_expansion_storage_bytes(paths, symbols)?;
    Some(GuardedShape {
        paths,
        bytes,
        symbols,
        peak_paths: left
            .peak_paths
            .max(left.paths.checked_add(right.peak_paths)?)
            .max(left.paths.checked_add(right.paths)?.checked_add(paths)?),
        peak_bytes: left
            .peak_bytes
            .max(left.bytes.checked_add(right.peak_bytes)?)
            .max(left.bytes.checked_add(right.bytes)?.checked_add(bytes)?),
        peak_symbols: left
            .peak_symbols
            .max(left.symbols.checked_add(right.peak_symbols)?)
            .max(
                left.symbols
                    .checked_add(right.symbols)?
                    .checked_add(symbols)?,
            ),
        construction_allocations_upper_bound: left
            .construction_allocations_upper_bound
            .checked_add(right.construction_allocations_upper_bound)?
            .checked_add(guarded_output_allocation_upper_bound(paths)?)?,
        construction_initialized_bytes_upper_bound: left
            .construction_initialized_bytes_upper_bound
            .checked_add(right.construction_initialized_bytes_upper_bound)?
            .checked_add(output_storage)?,
    })
}

fn optional_guarded_shape(prefixes: GuardedShape, sub: GuardedShape) -> Option<GuardedShape> {
    let choices = sub.paths.checked_add(1)?;
    let paths = prefixes.paths.checked_mul(choices)?;
    let bytes = prefixes
        .bytes
        .checked_mul(choices)?
        .checked_add(sub.bytes.checked_mul(prefixes.paths)?)?;
    let symbols = prefixes
        .symbols
        .checked_mul(choices)?
        .checked_add(sub.symbols.checked_mul(prefixes.paths)?)?;
    let output_storage = guarded_expansion_storage_bytes(paths, symbols)?;
    Some(GuardedShape {
        paths,
        bytes,
        symbols,
        peak_paths: prefixes
            .peak_paths
            .max(prefixes.paths.checked_add(sub.peak_paths)?)
            .max(prefixes.paths.checked_add(sub.paths)?.checked_add(paths)?),
        peak_bytes: prefixes
            .peak_bytes
            .max(prefixes.bytes.checked_add(sub.peak_bytes)?)
            .max(prefixes.bytes.checked_add(sub.bytes)?.checked_add(bytes)?),
        peak_symbols: prefixes
            .peak_symbols
            .max(prefixes.symbols.checked_add(sub.peak_symbols)?)
            .max(
                prefixes
                    .symbols
                    .checked_add(sub.symbols)?
                    .checked_add(symbols)?,
            ),
        construction_allocations_upper_bound: prefixes
            .construction_allocations_upper_bound
            .checked_add(sub.construction_allocations_upper_bound)?
            .checked_add(guarded_output_allocation_upper_bound(paths)?)?,
        construction_initialized_bytes_upper_bound: prefixes
            .construction_initialized_bytes_upper_bound
            .checked_add(sub.construction_initialized_bytes_upper_bound)?
            .checked_add(output_storage)?,
    })
}

fn extract_guarded_dictionary(
    hir: &Hir,
    max_words: usize,
    max_bytes: usize,
    context: &FiniteExtractionContext,
    semantics: GuardedFiniteBoundarySemantics,
    limits: GuardedFiniteBuildLimits,
) -> Result<GuardedDictionaryResult, GuardedAttemptError> {
    let source =
        match extract_guarded_source(hir, max_words, max_bytes, context, semantics, limits)? {
            Ok(source) => source,
            Err(refusal) => return Ok(Err(refusal)),
        };
    let dimensions = GuardedBuildDimensions {
        words: source.accounting.words,
        packed_bytes: source.accounting.word_bytes,
    };
    let words = source.words.iter().map(|word| SourceWord {
        bytes: word.bytes.as_slice(),
        left: word.left,
        right: word.right,
    });
    let dictionary = match GuardedDictionary::build_precounted(dimensions, words, limits.dictionary)
    {
        Ok(dictionary) => dictionary,
        Err(error) => {
            let evidence = FiniteExtractionGuardedEvidence::Failed {
                accounting: error.actual(),
                co_live_local_scratch_bytes: context.live_scratch_bytes(),
            };
            context.bind_guarded(&evidence)?;
            context.charge(error.actual().build_work)?;
            return Err(GuardedAttemptError::Build(
                GuardedFiniteBuildError::Dictionary(error),
            ));
        }
    };
    let dictionary_accounting = dictionary.build_accounting();
    let published = dictionary_accounting
        .published()
        .ok_or(BuildError::InternalInvariant(
            "guarded dictionary lost its native published receipt",
        ))?;
    context.bind_guarded(&FiniteExtractionGuardedEvidence::Succeeded {
        accounting: published,
        co_live_local_scratch_bytes: context.live_scratch_bytes(),
        retained: false,
    })?;
    if dictionary_accounting.prospective != source.dictionary_prospective {
        return Err(BuildError::InternalInvariant(
            "guarded dictionary prospective changed after source publication",
        )
        .into());
    }
    context.charge(dictionary_accounting.actual.build_work)?;
    let allocations_actual = source
        .accounting
        .expansion_allocations_actual
        .checked_add(source.accounting.allocations)
        .and_then(|total| total.checked_add(dictionary_accounting.actual.allocations))
        .ok_or(BuildError::PersistentBytesOverflow)?;
    let initialized_bytes_actual = source
        .accounting
        .expansion_initialized_bytes_actual
        .checked_add(source.accounting.storage_bytes)
        .and_then(|total| total.checked_add(dictionary_accounting.actual.initialized_bytes))
        .ok_or(BuildError::PersistentBytesOverflow)?;
    let dictionary_peak_bytes_actual = source
        .accounting
        .storage_bytes
        .checked_add(dictionary_accounting.actual.peak_bytes)
        .ok_or(BuildError::PersistentBytesOverflow)?;
    let peak_bytes_actual_upper_bound = source
        .accounting
        .expansion_peak_bytes_upper_bound
        .max(source.accounting.source_transition_peak_bytes_upper_bound)
        .max(dictionary_peak_bytes_actual);
    if allocations_actual > source.accounting.construction_allocations_upper_bound
        || initialized_bytes_actual > source.accounting.construction_initialized_bytes_upper_bound
        || peak_bytes_actual_upper_bound > source.accounting.construction_peak_bytes_upper_bound
    {
        return Err(BuildError::InternalInvariant(
            "guarded finite construction exceeded its prospective bound",
        )
        .into());
    }
    let accounting = GuardedFiniteAccounting {
        source: source.accounting,
        allocations_upper_bound: source.accounting.construction_allocations_upper_bound,
        allocations_actual,
        initialized_bytes_upper_bound: source.accounting.construction_initialized_bytes_upper_bound,
        initialized_bytes_actual,
        peak_bytes_actual_upper_bound,
    };
    if !accounting.is_consistent(&dictionary) {
        return Err(BuildError::InternalInvariant(
            "guarded finite composed accounting is inconsistent",
        )
        .into());
    }
    context.retain_guarded()?;
    Ok(Ok((dictionary, accounting)))
}

const fn map_left_guard(look: Look, semantics: GuardedFiniteBoundarySemantics) -> Option<Guard> {
    match (look, semantics) {
        (Look::WordAscii, GuardedFiniteBoundarySemantics::Ascii)
        | (Look::WordUnicode, GuardedFiniteBoundarySemantics::UnicodeFull) => {
            Some(Guard::LeftBoundary)
        }
        (Look::WordStartAscii, GuardedFiniteBoundarySemantics::Ascii) => Some(Guard::LeftStart),
        (Look::WordStartHalfAscii, GuardedFiniteBoundarySemantics::Ascii) => {
            Some(Guard::LeftStartHalf)
        }
        _ => None,
    }
}

const fn map_right_guard(look: Look, semantics: GuardedFiniteBoundarySemantics) -> Option<Guard> {
    match (look, semantics) {
        (Look::WordAscii, GuardedFiniteBoundarySemantics::Ascii)
        | (Look::WordUnicode, GuardedFiniteBoundarySemantics::UnicodeFull) => {
            Some(Guard::RightBoundary)
        }
        (Look::WordEndAscii, GuardedFiniteBoundarySemantics::Ascii) => Some(Guard::RightEnd),
        (Look::WordEndHalfAscii, GuardedFiniteBoundarySemantics::Ascii) => {
            Some(Guard::RightEndHalf)
        }
        _ => None,
    }
}

enum GuardedExpansion<'context> {
    Fits(GuardedLanguage<'context>),
    TooLargeFixedSequence,
    Unsupported,
}

struct GuardedExpansionContext<'context> {
    max_words: usize,
    max_bytes: usize,
    attempt: &'context FiniteExtractionContext,
    actual: GuardedExpansionActual,
}

impl<'context> GuardedExpansionContext<'context> {
    fn charge(&mut self, amount: usize) -> Result<(), BuildError> {
        self.attempt
            .charge(u64::try_from(amount).unwrap_or(u64::MAX))
    }

    fn allocate<T>(
        &mut self,
        capacity: usize,
        structure: &'static str,
    ) -> Result<AccountedExactVec<'context, T>, BuildError> {
        self.charge(capacity)?;
        let values = AccountedExactVec::try_with_capacity(
            self.attempt,
            FiniteStorage::Scratch,
            capacity,
            structure,
        )?;
        if values.capacity() != 0 {
            self.actual.allocations = self
                .actual
                .allocations
                .checked_add(1)
                .ok_or(BuildError::PersistentBytesOverflow)?;
        }
        Ok(values)
    }

    fn push<T>(
        &mut self,
        target: &mut AccountedExactVec<'context, T>,
        value: T,
        copied: bool,
    ) -> Result<(), BuildError> {
        target.push_accounted(value, copied, "exact guarded expansion capacity changed")?;
        let bytes = size_of::<T>();
        self.actual.initialized_bytes = self
            .actual
            .initialized_bytes
            .checked_add(bytes)
            .ok_or(BuildError::PersistentBytesOverflow)?;
        Ok(())
    }
}

fn expand_guarded<'context>(
    hir: &Hir,
    context: &mut GuardedExpansionContext<'context>,
) -> Result<GuardedExpansion<'context>, BuildError> {
    context.charge(1)?;
    match hir.kind() {
        HirKind::Empty => guarded_singleton(
            AccountedExactVec::empty(context.attempt, FiniteStorage::Scratch),
            context,
        ),
        HirKind::Literal(literal) => expand_guarded_literal(&literal.0, context),
        HirKind::Class(Class::Bytes(class)) => expand_guarded_byte_class(class, context),
        HirKind::Class(Class::Unicode(class)) => expand_guarded_unicode_class(class, context),
        HirKind::Look(look) => guarded_look_singleton(*look, context),
        HirKind::Capture(capture) => expand_guarded(&capture.sub, context),
        HirKind::Concat(children) => expand_guarded_concat(children, context),
        HirKind::Alternation(children) => expand_guarded_alternation(children, context),
        HirKind::Repetition(repetition) => expand_guarded_repetition(repetition, context),
    }
}

fn expand_guarded_literal<'context>(
    literal: &[u8],
    context: &mut GuardedExpansionContext<'context>,
) -> Result<GuardedExpansion<'context>, BuildError> {
    if context.max_words == 0 || literal.len() > context.max_bytes {
        return Ok(GuardedExpansion::TooLargeFixedSequence);
    }
    let mut symbols = context.allocate(literal.len(), "guarded finite literal symbols")?;
    for &byte in literal {
        context.push(&mut symbols, GuardedSymbol::Byte(byte), true)?;
    }
    guarded_singleton(symbols, context)
}

fn expand_guarded_byte_class<'context>(
    class: &regex_syntax::hir::ClassBytes,
    context: &mut GuardedExpansionContext<'context>,
) -> Result<GuardedExpansion<'context>, BuildError> {
    let mut count = 0_usize;
    for range in class.ranges() {
        for byte in range.start()..=range.end() {
            context.charge(1)?;
            if !is_ascii_word_byte(byte) {
                return Ok(GuardedExpansion::Unsupported);
            }
            count = count.checked_add(1).ok_or(BuildError::PlannerWorkLimit {
                needed: u64::MAX,
                limit: context.attempt.work_limit,
            })?;
        }
    }
    if count > context.max_words || count > context.max_bytes {
        return Ok(GuardedExpansion::TooLargeFixedSequence);
    }
    let mut paths = context.allocate(count, "guarded finite byte-class paths")?;
    for range in class.ranges() {
        for byte in range.start()..=range.end() {
            let mut symbols = context.allocate(1, "guarded finite byte-class symbol")?;
            context.push(&mut symbols, GuardedSymbol::Byte(byte), false)?;
            context.push(
                &mut paths,
                GuardedPath {
                    symbols: symbols.into_inner_kept(),
                },
                false,
            )?;
        }
    }
    Ok(GuardedExpansion::Fits(GuardedLanguage::from_paths(
        paths, count,
    )))
}

fn expand_guarded_unicode_class<'context>(
    class: &regex_syntax::hir::ClassUnicode,
    context: &mut GuardedExpansionContext<'context>,
) -> Result<GuardedExpansion<'context>, BuildError> {
    let mut count = 0_usize;
    for range in class.ranges() {
        for scalar in range.start()..=range.end() {
            context.charge(1)?;
            let Ok(byte) = u8::try_from(u32::from(scalar)) else {
                return Ok(GuardedExpansion::Unsupported);
            };
            if !is_ascii_word_byte(byte) {
                return Ok(GuardedExpansion::Unsupported);
            }
            count = count.checked_add(1).ok_or(BuildError::PlannerWorkLimit {
                needed: u64::MAX,
                limit: context.attempt.work_limit,
            })?;
        }
    }
    if count > context.max_words || count > context.max_bytes {
        return Ok(GuardedExpansion::TooLargeFixedSequence);
    }
    let mut paths = context.allocate(count, "guarded finite Unicode-class paths")?;
    for range in class.ranges() {
        for scalar in range.start()..=range.end() {
            let byte = u8::try_from(u32::from(scalar)).map_err(|_| {
                BuildError::InternalInvariant(
                    "proved ASCII Unicode class contained a non-byte scalar",
                )
            })?;
            let mut symbols = context.allocate(1, "guarded finite Unicode-class symbol")?;
            context.push(&mut symbols, GuardedSymbol::Byte(byte), false)?;
            context.push(
                &mut paths,
                GuardedPath {
                    symbols: symbols.into_inner_kept(),
                },
                false,
            )?;
        }
    }
    Ok(GuardedExpansion::Fits(GuardedLanguage::from_paths(
        paths, count,
    )))
}

fn expand_guarded_concat<'context>(
    children: &[Hir],
    context: &mut GuardedExpansionContext<'context>,
) -> Result<GuardedExpansion<'context>, BuildError> {
    let mut accumulator = match guarded_singleton(
        AccountedExactVec::empty(context.attempt, FiniteStorage::Scratch),
        context,
    )? {
        GuardedExpansion::Fits(language) => language,
        other => return Ok(other),
    };
    for child in children {
        let right = match expand_guarded(child, context)? {
            GuardedExpansion::Fits(language) => language,
            other => return Ok(other),
        };
        accumulator = match concat_guarded(&accumulator, &right, context)? {
            GuardedExpansion::Fits(language) => language,
            other => return Ok(other),
        };
    }
    Ok(GuardedExpansion::Fits(accumulator))
}

fn expand_guarded_alternation<'context>(
    children: &[Hir],
    context: &mut GuardedExpansionContext<'context>,
) -> Result<GuardedExpansion<'context>, BuildError> {
    let mut accumulator = GuardedLanguage::empty(context.attempt);
    for child in children {
        let language = match expand_guarded(child, context)? {
            GuardedExpansion::Fits(language) => language,
            other => return Ok(other),
        };
        accumulator = match append_guarded(accumulator, language, context)? {
            GuardedExpansion::Fits(language) => language,
            other => return Ok(other),
        };
    }
    Ok(GuardedExpansion::Fits(accumulator))
}

fn expand_guarded_repetition<'context>(
    repetition: &regex_syntax::hir::Repetition,
    context: &mut GuardedExpansionContext<'context>,
) -> Result<GuardedExpansion<'context>, BuildError> {
    let Some(maximum) = repetition.max else {
        return Ok(GuardedExpansion::Unsupported);
    };
    let sub = match expand_guarded(&repetition.sub, context)? {
        GuardedExpansion::Fits(language) => language,
        other => return Ok(other),
    };
    expand_bounded_repetition(&sub, repetition.min, maximum, repetition.greedy, context)
}

fn guarded_singleton<'context>(
    symbols: AccountedExactVec<'context, GuardedSymbol>,
    context: &mut GuardedExpansionContext<'context>,
) -> Result<GuardedExpansion<'context>, BuildError> {
    if context.max_words == 0 {
        return Ok(GuardedExpansion::TooLargeFixedSequence);
    }
    let bytes = symbols
        .iter()
        .filter(|symbol| matches!(symbol, GuardedSymbol::Byte(_)))
        .count();
    let mut paths = context.allocate(1, "guarded finite singleton path")?;
    context.push(
        &mut paths,
        GuardedPath {
            symbols: symbols.into_inner_kept(),
        },
        false,
    )?;
    Ok(GuardedExpansion::Fits(GuardedLanguage::from_paths(
        paths, bytes,
    )))
}

fn guarded_look_singleton<'context>(
    look: Look,
    context: &mut GuardedExpansionContext<'context>,
) -> Result<GuardedExpansion<'context>, BuildError> {
    let mut symbols = context.allocate(1, "guarded finite look symbol")?;
    context.push(&mut symbols, GuardedSymbol::Look(look), false)?;
    guarded_singleton(symbols, context)
}

fn concat_guarded<'context>(
    left: &GuardedLanguage<'context>,
    right: &GuardedLanguage<'context>,
    context: &mut GuardedExpansionContext<'context>,
) -> Result<GuardedExpansion<'context>, BuildError> {
    let Some(path_count) = left.paths.len().checked_mul(right.paths.len()) else {
        return Ok(GuardedExpansion::TooLargeFixedSequence);
    };
    let Some(left_bytes) = left.bytes.checked_mul(right.paths.len()) else {
        return Ok(GuardedExpansion::TooLargeFixedSequence);
    };
    let Some(right_bytes) = right.bytes.checked_mul(left.paths.len()) else {
        return Ok(GuardedExpansion::TooLargeFixedSequence);
    };
    let Some(bytes) = left_bytes.checked_add(right_bytes) else {
        return Ok(GuardedExpansion::TooLargeFixedSequence);
    };
    if path_count > context.max_words || bytes > context.max_bytes {
        return Ok(GuardedExpansion::TooLargeFixedSequence);
    }
    let mut paths = context.allocate(path_count, "guarded finite concatenation paths")?;
    for left_path in &left.paths {
        for right_path in &right.paths {
            let symbol_count = left_path
                .symbols
                .len()
                .checked_add(right_path.symbols.len())
                .ok_or(BuildError::PlannerWorkLimit {
                    needed: u64::MAX,
                    limit: context.attempt.work_limit,
                })?;
            let mut symbols =
                context.allocate(symbol_count, "guarded finite concatenation symbols")?;
            push_guarded_symbols(&mut symbols, &left_path.symbols, context)?;
            push_guarded_symbols(&mut symbols, &right_path.symbols, context)?;
            context.push(
                &mut paths,
                GuardedPath {
                    symbols: symbols.into_inner_kept(),
                },
                false,
            )?;
        }
    }
    Ok(GuardedExpansion::Fits(GuardedLanguage::from_paths(
        paths, bytes,
    )))
}

fn append_guarded<'context>(
    mut accumulator: GuardedLanguage<'context>,
    mut language: GuardedLanguage<'context>,
    context: &mut GuardedExpansionContext<'context>,
) -> Result<GuardedExpansion<'context>, BuildError> {
    let Some(path_count) = accumulator.paths.len().checked_add(language.paths.len()) else {
        return Ok(GuardedExpansion::TooLargeFixedSequence);
    };
    let Some(bytes) = accumulator.bytes.checked_add(language.bytes) else {
        return Ok(GuardedExpansion::TooLargeFixedSequence);
    };
    if path_count > context.max_words || bytes > context.max_bytes {
        return Ok(GuardedExpansion::TooLargeFixedSequence);
    }
    let mut paths = context.allocate(path_count, "guarded finite alternation paths")?;
    move_guarded_paths(&mut accumulator.paths, &mut paths, context)?;
    move_guarded_paths(&mut language.paths, &mut paths, context)?;
    Ok(GuardedExpansion::Fits(GuardedLanguage::from_paths(
        paths, bytes,
    )))
}

fn push_guarded_symbols<'context>(
    target: &mut AccountedExactVec<'context, GuardedSymbol>,
    source: &[GuardedSymbol],
    context: &mut GuardedExpansionContext<'context>,
) -> Result<(), BuildError> {
    for &symbol in source {
        context.push(target, symbol, true)?;
    }
    Ok(())
}

fn move_guarded_paths<'context>(
    source: &mut ExactVec<GuardedPath>,
    target: &mut AccountedExactVec<'context, GuardedPath>,
    context: &mut GuardedExpansionContext<'context>,
) -> Result<(), BuildError> {
    source.as_mut_slice().reverse();
    while let Some(path) = source.pop() {
        context.push(target, path, true)?;
    }
    Ok(())
}

fn expand_bounded_repetition<'context>(
    sub: &GuardedLanguage<'context>,
    minimum: u32,
    maximum: u32,
    greedy: bool,
    context: &mut GuardedExpansionContext<'context>,
) -> Result<GuardedExpansion<'context>, BuildError> {
    let Some(optional_count) = maximum.checked_sub(minimum) else {
        return Ok(GuardedExpansion::Unsupported);
    };
    let mut output = match repeat_guarded_exact(sub, minimum, context)? {
        GuardedExpansion::Fits(language) => language,
        other => return Ok(other),
    };
    for _ in 0..optional_count {
        context.charge(1)?;
        output = match append_optional_guarded(&output, sub, greedy, context)? {
            GuardedExpansion::Fits(language) => language,
            other => return Ok(other),
        };
    }
    Ok(GuardedExpansion::Fits(output))
}

fn append_optional_guarded<'context>(
    prefixes: &GuardedLanguage<'context>,
    sub: &GuardedLanguage<'context>,
    greedy: bool,
    context: &mut GuardedExpansionContext<'context>,
) -> Result<GuardedExpansion<'context>, BuildError> {
    let Some(choices) = sub.paths.len().checked_add(1) else {
        return Ok(GuardedExpansion::TooLargeFixedSequence);
    };
    let Some(path_count) = prefixes.paths.len().checked_mul(choices) else {
        return Ok(GuardedExpansion::TooLargeFixedSequence);
    };
    let Some(prefix_bytes) = prefixes.bytes.checked_mul(choices) else {
        return Ok(GuardedExpansion::TooLargeFixedSequence);
    };
    let Some(suffix_bytes) = sub.bytes.checked_mul(prefixes.paths.len()) else {
        return Ok(GuardedExpansion::TooLargeFixedSequence);
    };
    let Some(bytes) = prefix_bytes.checked_add(suffix_bytes) else {
        return Ok(GuardedExpansion::TooLargeFixedSequence);
    };
    if path_count > context.max_words || bytes > context.max_bytes {
        return Ok(GuardedExpansion::TooLargeFixedSequence);
    }
    let mut paths = context.allocate(path_count, "guarded finite optional paths")?;
    for prefix in &prefixes.paths {
        if !greedy {
            push_guarded_path_copy(&mut paths, prefix, context)?;
        }
        for suffix in &sub.paths {
            push_guarded_path_concat(&mut paths, prefix, suffix, context)?;
        }
        if greedy {
            push_guarded_path_copy(&mut paths, prefix, context)?;
        }
    }
    Ok(GuardedExpansion::Fits(GuardedLanguage::from_paths(
        paths, bytes,
    )))
}

fn push_guarded_path_copy<'context>(
    paths: &mut AccountedExactVec<'context, GuardedPath>,
    path: &GuardedPath,
    context: &mut GuardedExpansionContext<'context>,
) -> Result<(), BuildError> {
    let mut symbols = context.allocate(
        path.symbols.len(),
        "guarded finite optional skipped symbols",
    )?;
    push_guarded_symbols(&mut symbols, &path.symbols, context)?;
    context.push(
        paths,
        GuardedPath {
            symbols: symbols.into_inner_kept(),
        },
        true,
    )?;
    Ok(())
}

fn push_guarded_path_concat<'context>(
    paths: &mut AccountedExactVec<'context, GuardedPath>,
    prefix: &GuardedPath,
    suffix: &GuardedPath,
    context: &mut GuardedExpansionContext<'context>,
) -> Result<(), BuildError> {
    let symbol_count = prefix
        .symbols
        .len()
        .checked_add(suffix.symbols.len())
        .ok_or(BuildError::PlannerWorkLimit {
            needed: u64::MAX,
            limit: context.attempt.work_limit,
        })?;
    let mut symbols =
        context.allocate(symbol_count, "guarded finite optional continued symbols")?;
    push_guarded_symbols(&mut symbols, &prefix.symbols, context)?;
    push_guarded_symbols(&mut symbols, &suffix.symbols, context)?;
    context.push(
        paths,
        GuardedPath {
            symbols: symbols.into_inner_kept(),
        },
        true,
    )?;
    Ok(())
}

fn repeat_guarded_exact<'context>(
    sub: &GuardedLanguage<'context>,
    count: u32,
    context: &mut GuardedExpansionContext<'context>,
) -> Result<GuardedExpansion<'context>, BuildError> {
    let mut output = match guarded_singleton(
        AccountedExactVec::empty(context.attempt, FiniteStorage::Scratch),
        context,
    )? {
        GuardedExpansion::Fits(language) => language,
        other => return Ok(other),
    };
    for _ in 0..count {
        context.charge(1)?;
        output = match concat_guarded(&output, sub, context)? {
            GuardedExpansion::Fits(language) => language,
            other => return Ok(other),
        };
    }
    Ok(GuardedExpansion::Fits(output))
}

const fn is_ascii_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn analyze(
    hir: &Hir,
    max_words: usize,
    max_bytes: usize,
    context: &FiniteExtractionContext,
) -> Result<Analysis, BuildError> {
    let mut tasks = AccountedVec::new(context, FiniteStorage::Scratch);
    tasks.reserve_planner(1, "finite-language analysis tasks")?;
    tasks.push_reserved(Task::Visit(hir))?;
    let mut values = AccountedVec::new(context, FiniteStorage::Scratch);
    while let Some(task) = tasks.pop() {
        context.charge(1)?;
        match task {
            Task::Visit(node) => {
                let analysis = match node.kind() {
                    HirKind::Empty => bounded_shape(Shape::leaf(1, 0), max_words, max_bytes),
                    HirKind::Literal(literal) => {
                        bounded_shape(Shape::leaf(1, literal.0.len()), max_words, max_bytes)
                    }
                    HirKind::Class(Class::Bytes(class)) => {
                        let Some(count) = byte_class_count(class) else {
                            push_analysis(&mut values, Analysis::TooLargeFixedSequence)?;
                            continue;
                        };
                        bounded_shape(Shape::leaf(count, count), max_words, max_bytes)
                    }
                    HirKind::Class(Class::Unicode(class)) => {
                        let Some((words, bytes)) = unicode_class_count(class, max_words, max_bytes)
                        else {
                            push_analysis(&mut values, Analysis::TooLargeFixedSequence)?;
                            continue;
                        };
                        bounded_shape(Shape::leaf(words, bytes), max_words, max_bytes)
                    }
                    HirKind::Capture(capture) => {
                        push_visit(&mut tasks, &capture.sub)?;
                        continue;
                    }
                    HirKind::Concat(children) => {
                        push_children(&mut tasks, children, Task::FinishConcat(children.len()))?;
                        continue;
                    }
                    HirKind::Alternation(children) => {
                        push_children(
                            &mut tasks,
                            children,
                            Task::FinishAlternation(children.len()),
                        )?;
                        continue;
                    }
                    HirKind::Look(_) | HirKind::Repetition(_) => Analysis::Unsupported,
                };
                push_analysis(&mut values, analysis)?;
            }
            Task::FinishConcat(count) | Task::FinishAlternation(count) => {
                let children = pop_analyses(&mut values, count, context)?;
                let analysis = combine_analysis(
                    &children,
                    matches!(task, Task::FinishConcat(_)),
                    max_words,
                    max_bytes,
                );
                push_analysis(&mut values, analysis)?;
            }
        }
    }
    if values.len() != 1 {
        return Err(BuildError::InternalInvariant(
            "finite-language analysis did not produce one shape",
        ));
    }
    values.pop().ok_or(BuildError::InternalInvariant(
        "finite-language analysis value disappeared",
    ))
}

impl Shape {
    const fn leaf(words: usize, bytes: usize) -> Self {
        Self {
            words,
            bytes,
            peak_words: words,
            peak_bytes: bytes,
        }
    }

    const fn fits(self, max_words: usize, max_bytes: usize) -> bool {
        self.words <= max_words
            && self.bytes <= max_bytes
            && self.peak_words <= max_words
            && self.peak_bytes <= max_bytes
    }
}

fn byte_class_count(class: &regex_syntax::hir::ClassBytes) -> Option<usize> {
    class
        .ranges()
        .iter()
        .try_fold(0_usize, |count, range| count.checked_add(range.len()))
}

fn unicode_class_count(
    class: &regex_syntax::hir::ClassUnicode,
    max_words: usize,
    max_bytes: usize,
) -> Option<(usize, usize)> {
    let words = class
        .ranges()
        .iter()
        .try_fold(0_usize, |count, range| count.checked_add(range.len()))?;
    if words > max_words {
        return None;
    }
    let mut bytes = 0_usize;
    for range in class.ranges() {
        for scalar in range.start()..=range.end() {
            bytes = bytes.checked_add(scalar.len_utf8())?;
            if bytes > max_bytes {
                return None;
            }
        }
    }
    Some((words, bytes))
}

const fn bounded_shape(shape: Shape, max_words: usize, max_bytes: usize) -> Analysis {
    if shape.fits(max_words, max_bytes) {
        Analysis::Fits(shape)
    } else {
        Analysis::TooLargeFixedSequence
    }
}

fn push_analysis(
    values: &mut AccountedVec<'_, Analysis>,
    analysis: Analysis,
) -> Result<(), BuildError> {
    values.reserve_planner(1, "finite-language analysis values")?;
    values.push_reserved(analysis)
}

fn pop_analyses<'context>(
    values: &mut AccountedVec<'context, Analysis>,
    count: usize,
    context: &'context FiniteExtractionContext,
) -> Result<AccountedVec<'context, Analysis>, BuildError> {
    if values.len() < count {
        return Err(BuildError::InternalInvariant(
            "finite-language analysis value stack underflow",
        ));
    }
    let mut children = AccountedVec::new(context, FiniteStorage::Scratch);
    children.reserve_planner(count, "finite-language analysis children")?;
    for _ in 0..count {
        children.push_reserved(values.pop().ok_or(BuildError::InternalInvariant(
            "finite-language analysis disposition disappeared",
        ))?)?;
    }
    context.charge(u64::try_from(count).unwrap_or(u64::MAX))?;
    children.reverse();
    Ok(children)
}

fn combine_analysis(
    children: &[Analysis],
    concat: bool,
    max_words: usize,
    max_bytes: usize,
) -> Analysis {
    if children
        .iter()
        .any(|child| matches!(child, Analysis::Unsupported))
    {
        return Analysis::Unsupported;
    }
    if children
        .iter()
        .any(|child| matches!(child, Analysis::TooLargeFixedSequence))
    {
        return Analysis::TooLargeFixedSequence;
    }
    let combined = if concat {
        concat_analysis_shape(children)
    } else {
        alternation_analysis_shape(children)
    };
    combined.map_or(Analysis::TooLargeFixedSequence, |shape| {
        bounded_shape(shape, max_words, max_bytes)
    })
}

fn alternation_analysis_shape(children: &[Analysis]) -> Option<Shape> {
    let mut words = 0_usize;
    let mut bytes = 0_usize;
    for child in children {
        let Analysis::Fits(shape) = child else {
            return None;
        };
        words = words.checked_add(shape.words)?;
        bytes = bytes.checked_add(shape.bytes)?;
    }
    analysis_shape_with_evaluation_peak(children, words, bytes)
}

fn concat_analysis_shape(children: &[Analysis]) -> Option<Shape> {
    let mut words = 1_usize;
    let mut bytes = 0_usize;
    for child in children {
        let Analysis::Fits(shape) = child else {
            return None;
        };
        let next_words = words.checked_mul(shape.words)?;
        let left_bytes = bytes.checked_mul(shape.words)?;
        let right_bytes = shape.bytes.checked_mul(words)?;
        bytes = left_bytes.checked_add(right_bytes)?;
        words = next_words;
    }
    analysis_shape_with_evaluation_peak(children, words, bytes)
}

fn analysis_shape_with_evaluation_peak(
    children: &[Analysis],
    words: usize,
    bytes: usize,
) -> Option<Shape> {
    let mut live_words = 0_usize;
    let mut live_bytes = 0_usize;
    let mut peak_words = 0_usize;
    let mut peak_bytes = 0_usize;
    for child in children {
        let Analysis::Fits(shape) = child else {
            return None;
        };
        peak_words = peak_words.max(live_words.checked_add(shape.peak_words)?);
        peak_bytes = peak_bytes.max(live_bytes.checked_add(shape.peak_bytes)?);
        live_words = live_words.checked_add(shape.words)?;
        live_bytes = live_bytes.checked_add(shape.bytes)?;
    }
    peak_words = peak_words.max(live_words.checked_add(words)?);
    peak_bytes = peak_bytes.max(live_bytes.checked_add(bytes)?);
    Some(Shape {
        words,
        bytes,
        peak_words,
        peak_bytes,
    })
}

fn unicode_class<'context>(
    class: &regex_syntax::hir::ClassUnicode,
    max_words: usize,
    max_bytes: usize,
    context: &'context FiniteExtractionContext,
) -> Result<Option<Language<'context>>, BuildError> {
    let count = class.ranges().iter().try_fold(0_usize, |count, range| {
        count
            .checked_add(range.len())
            .ok_or(BuildError::PlannerWorkLimit {
                needed: u64::MAX,
                limit: context.work_limit,
            })
    })?;
    if count > max_words {
        return Ok(None);
    }
    let mut language = Language::empty(context, 0);
    language.reserve_words(count, "finite-language Unicode-class words")?;
    let mut bytes = 0_usize;
    for range in class.ranges() {
        for scalar in range.start()..=range.end() {
            let mut buffer = [0_u8; 4];
            let encoded = scalar.encode_utf8(&mut buffer).as_bytes();
            bytes = match bytes.checked_add(encoded.len()) {
                Some(bytes) if bytes <= max_bytes => bytes,
                _ => return Ok(None),
            };
            let mut word = AccountedVec::new(context, FiniteStorage::Persistent);
            word.reserve_planner(encoded.len(), "finite-language Unicode scalar bytes")?;
            word.extend_reserved(encoded.iter().copied(), encoded.len())?;
            language.push_word(word)?;
        }
    }
    language.bytes = bytes;
    Ok(Some(language))
}

fn byte_class<'context>(
    class: &regex_syntax::hir::ClassBytes,
    max_words: usize,
    max_bytes: usize,
    context: &'context FiniteExtractionContext,
) -> Result<Option<Language<'context>>, BuildError> {
    let count = class.ranges().iter().try_fold(0_usize, |count, range| {
        count
            .checked_add(range.len())
            .ok_or(BuildError::PlannerWorkLimit {
                needed: u64::MAX,
                limit: context.work_limit,
            })
    })?;
    if count > max_words || count > max_bytes {
        return Ok(None);
    }
    let mut language = Language::empty(context, count);
    language.reserve_words(count, "finite-language byte-class words")?;
    for range in class.ranges() {
        for byte in range.start()..=range.end() {
            let mut word = AccountedVec::new(context, FiniteStorage::Persistent);
            word.reserve_planner(1, "finite-language byte-class byte")?;
            word.push_reserved(byte)?;
            language.push_word(word)?;
        }
    }
    Ok(Some(language))
}

fn push_visit<'hir>(
    tasks: &mut AccountedVec<'_, Task<'hir>>,
    node: &'hir Hir,
) -> Result<(), BuildError> {
    tasks.reserve_planner(1, "finite-language task stack")?;
    tasks.push_reserved(Task::Visit(node))
}

fn push_children<'hir>(
    tasks: &mut AccountedVec<'_, Task<'hir>>,
    children: &'hir [Hir],
    finish: Task<'hir>,
) -> Result<(), BuildError> {
    let additional = children
        .len()
        .checked_add(1)
        .ok_or(BuildError::PlannerWorkLimit {
            needed: u64::MAX,
            limit: tasks.context.work_limit,
        })?;
    tasks.reserve_planner(additional, "finite-language task stack")?;
    tasks.push_reserved(finish)?;
    tasks.extend_reserved(children.iter().rev().map(Task::Visit), children.len())
}

fn push_language<'context>(
    values: &mut AccountedVec<'context, Language<'context>>,
    language: Language<'context>,
) -> Result<(), BuildError> {
    values.reserve_planner(1, "finite-language value stack")?;
    values.push_reserved(language)
}

fn singleton_language<'context>(
    word: AccountedVec<'context, u8>,
    context: &'context FiniteExtractionContext,
) -> Result<Language<'context>, BuildError> {
    let bytes = word.len();
    let mut language = Language::empty(context, bytes);
    language.reserve_words(1, "finite-language singleton word")?;
    language.push_word(word)?;
    Ok(language)
}

fn pop_languages<'context>(
    values: &mut AccountedVec<'context, Language<'context>>,
    count: usize,
    context: &'context FiniteExtractionContext,
) -> Result<AccountedVec<'context, Language<'context>>, BuildError> {
    if values.len() < count {
        return Err(BuildError::InternalInvariant(
            "finite-language value stack underflow",
        ));
    }
    let mut children = AccountedVec::new(context, FiniteStorage::Scratch);
    children.reserve_planner(count, "finite-language child values")?;
    for _ in 0..count {
        children.push_reserved(values.pop().ok_or(BuildError::InternalInvariant(
            "finite-language value disappeared while popping children",
        ))?)?;
    }
    context.charge(u64::try_from(count).unwrap_or(u64::MAX))?;
    Ok(children)
}

fn alternate_languages<'context>(
    mut children: AccountedVec<'context, Language<'context>>,
    max_words: usize,
    max_bytes: usize,
    context: &'context FiniteExtractionContext,
) -> Result<Option<Language<'context>>, BuildError> {
    let mut word_count = 0_usize;
    let mut byte_count = 0_usize;
    for child in &children {
        word_count = match word_count.checked_add(child.words.len()) {
            Some(count) => count,
            None => return Ok(None),
        };
        byte_count = match byte_count.checked_add(child.bytes) {
            Some(count) => count,
            None => return Ok(None),
        };
    }
    if word_count > max_words || byte_count > max_bytes {
        return Ok(None);
    }
    let mut language = Language::empty(context, byte_count);
    language.reserve_words(word_count, "finite-language alternation words")?;
    while let Some(mut child) = children.pop() {
        language.append_words(&mut child)?;
    }
    Ok(Some(language))
}

fn concat_languages<'context>(
    mut children: AccountedVec<'context, Language<'context>>,
    max_words: usize,
    max_bytes: usize,
    context: &'context FiniteExtractionContext,
) -> Result<Option<Language<'context>>, BuildError> {
    let mut accumulator = singleton_language(
        AccountedVec::new(context, FiniteStorage::Persistent),
        context,
    )?;
    while let Some(child) = children.pop() {
        let Some(next) = concat_pair(&accumulator, &child, max_words, max_bytes, context)? else {
            return Ok(None);
        };
        accumulator = next;
    }
    Ok(Some(accumulator))
}

fn concat_pair<'context>(
    left: &Language<'context>,
    right: &Language<'context>,
    max_words: usize,
    max_bytes: usize,
    context: &'context FiniteExtractionContext,
) -> Result<Option<Language<'context>>, BuildError> {
    let Some(word_count) = left.words.len().checked_mul(right.words.len()) else {
        return Ok(None);
    };
    let Some(left_bytes) = left.bytes.checked_mul(right.words.len()) else {
        return Ok(None);
    };
    let Some(right_bytes) = right.bytes.checked_mul(left.words.len()) else {
        return Ok(None);
    };
    let Some(byte_count) = left_bytes.checked_add(right_bytes) else {
        return Ok(None);
    };
    if word_count > max_words || byte_count > max_bytes {
        return Ok(None);
    }
    let mut language = Language::empty(context, byte_count);
    language.reserve_words(word_count, "finite-language concatenation words")?;
    for left_word in &left.words {
        for right_word in &right.words {
            let length = left_word.len().checked_add(right_word.len()).ok_or(
                BuildError::PlannerWorkLimit {
                    needed: u64::MAX,
                    limit: context.work_limit,
                },
            )?;
            let mut word = AccountedVec::new(context, FiniteStorage::Persistent);
            word.reserve_planner(length, "finite-language concatenated bytes")?;
            word.extend_reserved(left_word.iter().copied(), left_word.len())?;
            word.extend_reserved(right_word.iter().copied(), right_word.len())?;
            language.push_word(word)?;
        }
    }
    Ok(Some(language))
}

#[cfg(test)]
mod tests {
    use regex_syntax::ParserBuilder;

    use super::{
        BuildError, FiniteOutcome, Guard, GuardedDictionary, GuardedFiniteBuildError,
        GuardedFiniteBuildLimits, GuardedFiniteBuildResource, guarded_allocated_bytes,
    };
    use crate::guarded_ascii_word::{
        BuildErrorKind as GuardedBuildErrorKind, BuildLimits as GuardedBuildLimits,
        BuildResource as GuardedBuildResource, LOOKUP_ID, PACKING_ID, PLAN_ID,
    };

    const RAW_KEYWORD_FORM: &str = r"(?:\b(as)\b)|(?:\b(break)\b)|(?:\b(const)\b)|(?:\b(continue)\b)|(?:\b(crate)\b)|(?:\b(else)\b)|(?:\b(enum)\b)|(?:\b(extern)\b)|(?:\b(false)\b)|(?:\b(fn)\b)|(?:\b(for)\b)|(?:\b(if)\b)|(?:\b(impl)\b)|(?:\b(in)\b)|(?:\b(let)\b)|(?:\b(loop)\b)|(?:\b(match)\b)|(?:\b(mod)\b)|(?:\b(move)\b)|(?:\b(mut)\b)|(?:\b(pub)\b)|(?:\b(ref)\b)|(?:\b(return)\b)|(?:\b(self)\b)|(?:\b(Self)\b)|(?:\b(static)\b)|(?:\b(struct)\b)|(?:\b(super)\b)|(?:\b(trait)\b)|(?:\b(true)\b)|(?:\b(type)\b)|(?:\b(unsafe)\b)|(?:\b(use)\b)|(?:\b(where)\b)|(?:\b(while)\b)|(?:\b(abstract)\b)|(?:\b(become)\b)|(?:\b(box)\b)|(?:\b(do)\b)|(?:\b(final)\b)|(?:\b(macro)\b)|(?:\b(override)\b)|(?:\b(priv)\b)|(?:\b(typeof)\b)|(?:\b(unsized)\b)|(?:\b(virtual)\b)|(?:\b(yield)\b)|(?:\b(try)\b)|(?:\b(i8)\b)|(?:\b(i16)\b)|(?:\b(i32)\b)|(?:\b(i64)\b)|(?:\b(i128)\b)|(?:\b(isize)\b)|(?:\b(u8)\b)|(?:\b(u16)\b)|(?:\b(u32)\b)|(?:\b(u64)\b)|(?:\b(u128)\b)|(?:\b(usize)\b)|(?:\b(bool)\b)|(?:\b(char)\b)|(?:\b(str)\b)|(?:\b(f32)\b)|(?:\b(f64)\b)";
    const FACTORED_KEYWORD_FORM: &str = r"\b(Self|a(?:bstract|s)|b(?:ecome|o(?:ol|x)|reak)|c(?:har|on(?:st|tinue)|rate)|do|e(?:lse|num|xtern)|f(?:32|64|alse|inal|n|or)|i(?:1(?:28|6)|32|64|mpl|size|[8fn])|l(?:et|oop)|m(?:a(?:cro|tch)|o(?:d|ve)|ut)|override|p(?:riv|ub)|re(?:f|turn)|s(?:elf|t(?:atic|r(?:(?:uct)?))|uper)|t(?:r(?:ait|ue|y)|ype(?:(?:of)?))|u(?:1(?:28|6)|32|64|8|ns(?:afe|ized)|s(?:(?:(?:iz)?)e))|virtual|wh(?:(?:er|il)e)|yield)\b";

    fn parse(pattern: &str) -> regex_syntax::hir::Hir {
        ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(pattern)
            .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error}"))
    }

    fn parse_case_insensitive(pattern: &str) -> regex_syntax::hir::Hir {
        ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .case_insensitive(true)
            .build()
            .parse(pattern)
            .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error}"))
    }

    fn extract(
        hir: &regex_syntax::hir::Hir,
        max_words: usize,
        max_bytes: usize,
        initial_work: u64,
        work_limit: u64,
        derive_guarded_dictionary: bool,
    ) -> FiniteOutcome {
        super::extract(
            hir,
            max_words,
            max_bytes,
            initial_work,
            work_limit,
            derive_guarded_dictionary,
            GuardedFiniteBuildLimits::unlimited(),
        )
    }

    fn guarded(pattern: &str, max_words: usize, max_bytes: usize) -> (GuardedDictionary, u64) {
        match extract(&parse(pattern), max_words, max_bytes, 0, u64::MAX, true) {
            FiniteOutcome::GuardedFiniteBody {
                dictionary,
                receipt,
                ..
            } => (dictionary, receipt.actual.work),
            other => panic!("expected guarded finite body, work={}", other.work()),
        }
    }

    fn identity_words(dictionary: &GuardedDictionary) -> Vec<&[u8]> {
        let identity = dictionary.identity();
        identity
            .entries
            .iter()
            .map(|entry| {
                let start = usize::try_from(entry.start).unwrap();
                let end = usize::try_from(entry.end).unwrap();
                &identity.packed_bytes[start..end]
            })
            .collect()
    }

    #[test]
    fn raw_and_factored_keyword_hir_derive_the_same_exact_dictionary() {
        let raw = r"(?:\b(as)\b)|(?:\b(async)\b)|(?:\b(Self)\b)";
        let factored = r"\b(a(?:s|sync)|Self)\b";
        let (raw, _) = guarded(raw, 16, 128);
        let (factored, _) = guarded(factored, 16, 128);
        assert_eq!(
            identity_words(&raw),
            [b"as".as_slice(), b"async".as_slice(), b"Self".as_slice()]
        );
        assert_eq!(
            raw.identity().packed_bytes,
            factored.identity().packed_bytes
        );
        assert_eq!(raw.identity().entries, factored.identity().entries);
        assert_eq!(raw.identity().plan_id, PLAN_ID);
        assert_eq!(raw.identity().packing_id, PACKING_ID);
        assert_eq!(raw.identity().lookup_id, LOOKUP_ID);
    }

    #[test]
    fn complete_raw_and_factored_keyword_forms_preserve_order_and_language() {
        let (raw, _) = guarded(RAW_KEYWORD_FORM, 1_024, 1 << 20);
        let (factored, _) = guarded(FACTORED_KEYWORD_FORM, 1_024, 1 << 20);
        assert_eq!(raw.identity().entries.len(), 65);
        assert_eq!(factored.identity().entries.len(), 65);
        let mut raw_words = identity_words(&raw);
        let mut factored_words = identity_words(&factored);
        assert_eq!(raw_words[0], b"as");
        assert_eq!(factored_words[0], b"Self");
        raw_words.sort_unstable();
        factored_words.sort_unstable();
        assert_eq!(raw_words, factored_words);
    }

    #[test]
    fn bounded_optionals_ranges_duplicates_and_guards_keep_hir_priority() {
        let pattern = r"\b(a(?:s|sync)|f[8n]?|uct?|as)\b";
        let (dictionary, _) = guarded(pattern, 32, 256);
        assert_eq!(
            identity_words(&dictionary),
            [
                b"as".as_slice(),
                b"async".as_slice(),
                b"f8".as_slice(),
                b"fn".as_slice(),
                b"f".as_slice(),
                b"uct".as_slice(),
                b"uc".as_slice(),
                b"as".as_slice(),
            ]
        );
        for entry in dictionary.identity().entries {
            assert_eq!(entry.left, Guard::LeftBoundary);
            assert_eq!(entry.right, Guard::RightBoundary);
        }
        assert_eq!(dictionary.lookup(b"as").unwrap().source_index, 0);
        assert_eq!(
            dictionary
                .lookup_at_or_after(b"as", 1)
                .unwrap()
                .source_index,
            7
        );
        assert!(dictionary.lookup(b"f9").is_none());
    }

    #[test]
    fn directional_ascii_word_guards_remain_in_source_identity() {
        for (pattern, left, right) in [
            (r"\b{start}alpha\b{end}", Guard::LeftStart, Guard::RightEnd),
            (
                r"\b{start-half}alpha\b{end-half}",
                Guard::LeftStartHalf,
                Guard::RightEndHalf,
            ),
        ] {
            let (dictionary, _) = guarded(pattern, 8, 64);
            let [entry] = dictionary.identity().entries else {
                panic!("directional guard pattern must have one source entry");
            };
            assert_eq!(entry.left, left);
            assert_eq!(entry.right, right);
        }
    }

    #[test]
    fn bounded_repetition_interleaves_greedy_and_lazy_exits_per_prefix() {
        let (greedy, _) = guarded(r"\b(?:a|aa){1,2}\b", 64, 512);
        assert_eq!(
            identity_words(&greedy),
            [
                b"aa".as_slice(),
                b"aaa".as_slice(),
                b"a".as_slice(),
                b"aaa".as_slice(),
                b"aaaa".as_slice(),
                b"aa".as_slice(),
            ]
        );
        let (lazy, _) = guarded(r"\b(?:a|aa){1,2}?\b", 64, 512);
        assert_eq!(
            identity_words(&lazy),
            [
                b"a".as_slice(),
                b"aa".as_slice(),
                b"aaa".as_slice(),
                b"aa".as_slice(),
                b"aaa".as_slice(),
                b"aaaa".as_slice(),
            ]
        );
        let (optional_twice, _) = guarded(r"\bz(?:a|aa){0,2}\b", 64, 512);
        assert_eq!(
            identity_words(&optional_twice),
            [
                b"zaa".as_slice(),
                b"zaaa".as_slice(),
                b"za".as_slice(),
                b"zaaa".as_slice(),
                b"zaaaa".as_slice(),
                b"zaa".as_slice(),
                b"za".as_slice(),
                b"zaa".as_slice(),
                b"z".as_slice(),
            ]
        );
        assert!(matches!(
            extract(&parse(r"\bz(?:a|aa){0,2}\b"), 8, 128, 0, u64::MAX, true,),
            FiniteOutcome::TooLargeFixedSequence { .. }
        ));
    }

    #[test]
    fn outcomes_are_typed_and_guarded_work_never_resets() {
        let plain = parse("a|bb");
        let FiniteOutcome::Fits { words, receipt } = extract(&plain, 16, 16, 7, u64::MAX, false)
        else {
            panic!("ordinary finite language should fit");
        };
        let work = receipt.actual.work;
        assert_eq!(words, [b"a".to_vec(), b"bb".to_vec()]);
        assert!(work > 7);
        assert!(matches!(
            extract(&plain, 1, 16, 7, u64::MAX, false),
            FiniteOutcome::TooLargeFixedSequence { receipt } if receipt.actual.work > 7
        ));

        let guarded_hir = parse(r"\b(a(?:s|sync)|Self)\b");
        let FiniteOutcome::Unsupported { receipt } =
            extract(&guarded_hir, 16, 128, 0, u64::MAX, false)
        else {
            panic!("incumbent finite callers must not derive U5 eagerly");
        };
        let incumbent_work = receipt.actual.work;
        let FiniteOutcome::GuardedFiniteBody {
            dictionary,
            accounting,
            receipt,
        } = extract(&guarded_hir, 16, 128, 0, u64::MAX, true)
        else {
            panic!("guarded baseline should fit");
        };
        let baseline_work = receipt.actual.work;
        assert!(baseline_work > incumbent_work);
        assert!(accounting.is_consistent(&dictionary));
        assert!(accounting.source.expansion_allocations_actual > 0);
        assert!(
            accounting.source.expansion_allocations_actual
                <= accounting.source.expansion_allocations_upper_bound
        );
        assert!(
            accounting.source.expansion_initialized_bytes_actual
                <= accounting.source.expansion_initialized_bytes_upper_bound
        );
        assert!(accounting.allocations_actual <= accounting.allocations_upper_bound);
        assert!(accounting.initialized_bytes_actual <= accounting.initialized_bytes_upper_bound);
        assert!(
            accounting.source.construction_peak_bytes_upper_bound
                >= accounting.source.expansion_peak_bytes_upper_bound
        );
        assert!(
            accounting.source.construction_peak_bytes_upper_bound
                >= accounting.source.source_transition_peak_bytes_upper_bound
        );
        assert!(
            accounting.peak_bytes_actual_upper_bound
                <= accounting.source.construction_peak_bytes_upper_bound
        );
        let build = dictionary.build_accounting();
        let prospective_slack = build
            .prospective
            .build_work
            .checked_sub(build.actual.build_work)
            .unwrap();
        let initial = 11_u64;
        let expected_actual = baseline_work.checked_add(initial).unwrap();
        let exact_limit = expected_actual.checked_add(prospective_slack).unwrap();
        assert!(matches!(
            extract(&guarded_hir, 16, 128, initial, exact_limit, true),
            FiniteOutcome::GuardedFiniteBody { receipt, .. }
                if receipt.actual.work == expected_actual
        ));
        let one_below = exact_limit.checked_sub(1).unwrap();
        assert!(matches!(
            extract(&guarded_hir, 16, 128, initial, one_below, true),
            FiniteOutcome::ResourceFailure {
                error: BuildError::PlannerWorkLimit { limit, .. },
                receipt,
            } if limit == one_below
                && receipt.actual.work >= initial
                && receipt.actual.work <= one_below
        ));
    }

    #[test]
    fn finite_attempt_receipts_close_success_refusals_and_legacy_projection() {
        let hir = parse("a|bb");
        let success = extract(&hir, 16, 16, 7, u64::MAX, false);
        assert!(success.has_closed_receipt());
        assert!(success.receipt().is_closed());
        assert_eq!(
            success.receipt().terminal(),
            super::FiniteExtractionTerminal::Fits
        );
        let actual = success.receipt().actual();
        assert!(actual.work > 7);
        assert!(actual.local.allocations > 0);
        assert!(actual.local.allocated_bytes > 0);
        assert!(actual.local.initialized_bytes > 0);
        assert_eq!(actual.local.live_scratch_bytes, 0);
        assert!(actual.local.live_persistent_bytes > 0);
        assert!(actual.local.high_water_bytes >= actual.local.live_persistent_bytes);

        let (legacy_words, legacy_work) = extract(&hir, 16, 16, 7, u64::MAX, false)
            .into_incumbent_words()
            .unwrap();
        assert_eq!(legacy_words.unwrap(), [b"a".to_vec(), b"bb".to_vec()]);
        assert_eq!(legacy_work, actual.work);

        let unsupported = extract(&parse("a*"), 16, 16, 0, u64::MAX, false);
        assert!(matches!(unsupported, FiniteOutcome::Unsupported { .. }));
        assert!(unsupported.has_closed_receipt());
        assert_eq!(
            unsupported.receipt().terminal(),
            super::FiniteExtractionTerminal::Unsupported
        );
        let unsupported_actual = unsupported.receipt().actual();
        assert!(unsupported_actual.work > 0);
        assert_eq!(unsupported_actual.local.live_persistent_bytes, 0);
        assert_eq!(unsupported_actual.local.live_scratch_bytes, 0);
        assert!(unsupported_actual.local.released_scratch_bytes > 0);

        let too_large = extract(&hir, 1, 16, 0, u64::MAX, false);
        assert!(matches!(
            too_large,
            FiniteOutcome::TooLargeFixedSequence { .. }
        ));
        assert!(too_large.has_closed_receipt());
        assert_eq!(
            too_large.receipt().terminal(),
            super::FiniteExtractionTerminal::TooLargeFixedSequence
        );
        assert_eq!(too_large.receipt().actual().local.live_persistent_bytes, 0);
    }

    #[test]
    fn finite_attempt_retains_partial_work_and_allocations_on_failure() {
        let hir = parse("(ab|cd)(ef|gh)");
        let baseline = extract(&hir, 32, 256, 0, u64::MAX, false);
        assert!(baseline.has_closed_receipt());
        let exact_work = baseline.work();
        let one_below = exact_work.checked_sub(1).unwrap();
        let refused = extract(&hir, 32, 256, 0, one_below, false);
        assert!(matches!(refused, FiniteOutcome::ResourceFailure { .. }));
        assert!(refused.has_closed_receipt());
        let actual = refused.receipt().actual();
        assert!(actual.work <= one_below);
        assert!(actual.work > 0);
        assert!(actual.local.allocations > 0);
        assert!(actual.local.initialized_bytes > 0);
        assert_eq!(actual.local.live_persistent_bytes, 0);
        assert_eq!(actual.local.live_scratch_bytes, 0);

        let before_first_effect = extract(&hir, 32, 256, 0, 0, false);
        assert!(matches!(
            before_first_effect,
            FiniteOutcome::ResourceFailure {
                error: BuildError::PlannerWorkLimit { .. },
                ..
            }
        ));
        assert!(before_first_effect.has_closed_receipt());
        let actual = before_first_effect.receipt().actual();
        assert_eq!(actual.work, 0);
        assert_eq!(actual.local.allocations, 0);
        assert_eq!(actual.local.allocated_bytes, 0);
        assert_eq!(actual.local.initialized_bytes, 0);

        let already_over_limit = extract(&hir, 32, 256, 2, 1, false);
        assert!(already_over_limit.has_closed_receipt());
        assert_eq!(already_over_limit.work(), 2);
        let projected = already_over_limit.into_incumbent_words();
        assert!(
            matches!(
                projected,
                Err(BuildError::PlannerWorkLimit {
                    needed: 2,
                    limit: 1
                })
            ),
            "projected={projected:?}"
        );
    }

    #[test]
    fn finite_allocation_failure_closes_with_observed_partial_actual() {
        let context = super::FiniteExtractionContext::new(0, u64::MAX);
        let mut values = super::AccountedVec::new(&context, super::FiniteStorage::Scratch);
        values
            .reserve_planner(1, "finite allocation-failure fixture")
            .unwrap();
        values.push_reserved(17_u64).unwrap();
        let impossible = usize::try_from(isize::MAX)
            .unwrap()
            .checked_div(core::mem::size_of::<u64>())
            .unwrap()
            .checked_add(1)
            .unwrap();
        let error = values
            .reserve_planner(impossible, "finite allocation-failure fixture")
            .unwrap_err();
        assert!(matches!(error, BuildError::AllocationFailed { .. }));
        drop(values);
        let outcome = FiniteOutcome::ResourceFailure {
            error,
            receipt: context.close(super::FiniteExtractionTerminal::ResourceFailure),
        };
        assert!(outcome.has_closed_receipt());
        let actual = outcome.receipt().actual();
        assert_eq!(actual.local.allocations, 1);
        assert_eq!(actual.local.reallocations, 0);
        assert!(actual.local.allocated_bytes >= core::mem::size_of::<u64>());
        assert_eq!(actual.local.initialized_bytes, core::mem::size_of::<u64>());
        assert_eq!(actual.local.live_scratch_bytes, 0);
        assert_eq!(
            actual.local.released_scratch_bytes,
            actual.local.allocated_bytes
        );
    }

    #[test]
    fn guarded_dictionary_receipt_stays_nested_and_captures_co_live_peak() {
        let outcome = extract(
            &parse(r"\b(a(?:s|sync)|Self)\b"),
            16,
            128,
            0,
            u64::MAX,
            true,
        );
        assert!(outcome.has_closed_receipt());
        let FiniteOutcome::GuardedFiniteBody {
            dictionary,
            accounting: finite_accounting,
            receipt,
            ..
        } = &outcome
        else {
            panic!("guarded finite extraction should publish");
        };
        let nested = dictionary.build_accounting();
        let super::FiniteExtractionGuardedEvidence::Succeeded {
            accounting,
            co_live_local_scratch_bytes,
            retained,
        } = receipt.actual().guarded.unwrap()
        else {
            panic!("guarded dictionary evidence must remain nested");
        };
        assert_eq!(Some(accounting), nested.published());
        assert!(retained);
        assert_eq!(
            co_live_local_scratch_bytes,
            finite_accounting.source.storage_bytes
        );
        let actual = receipt.actual();
        let nested_actual = accounting.actual().unwrap();
        assert!(nested_actual.allocations > 0);
        assert!(nested_actual.persistent_bytes > 0);
        let nested_co_live = co_live_local_scratch_bytes
            .checked_add(nested_actual.peak_bytes)
            .unwrap();
        assert!(nested_co_live > co_live_local_scratch_bytes);
        assert!(actual.local.high_water_bytes > 0);
        let boundary = receipt.boundary_actual().unwrap();
        assert_eq!(boundary.work, receipt.actual().work);
        assert_eq!(
            boundary.allocations,
            actual.local.allocations + nested_actual.allocations
        );
        assert_eq!(
            boundary.allocated_bytes,
            actual.local.allocated_bytes + guarded_allocated_bytes(nested_actual).unwrap()
        );
        assert_eq!(
            boundary.copied_bytes,
            actual.local.copied_bytes + nested_actual.byte_copies
        );
        assert_eq!(
            boundary.initialized_bytes,
            actual.local.initialized_bytes
                + nested_actual.initialized_bytes
                + core::mem::size_of::<GuardedDictionary>()
        );
        assert_eq!(
            boundary.live_persistent_bytes,
            nested_actual.persistent_bytes
        );
        assert_eq!(
            boundary.high_water_bytes,
            actual.local.high_water_bytes.max(nested_co_live)
        );
        assert_eq!(boundary.abandonable_bytes, 0);
    }

    #[test]
    fn finite_receipt_mutations_break_closure() {
        let hir = parse("a|bb");
        let FiniteOutcome::Fits { words, receipt } = extract(&hir, 16, 16, 0, u64::MAX, false)
        else {
            panic!("finite fixture should fit");
        };

        let mut bad = receipt;
        bad.closed = false;
        assert!(
            !FiniteOutcome::Fits {
                words: words.clone(),
                receipt: bad,
            }
            .has_closed_receipt()
        );

        let mut bad = receipt;
        bad.terminal = super::FiniteExtractionTerminal::Unsupported;
        assert!(
            !FiniteOutcome::Fits {
                words: words.clone(),
                receipt: bad,
            }
            .has_closed_receipt()
        );

        let mut bad = receipt;
        bad.actual.local.allocated_bytes = bad.actual.local.allocated_bytes.checked_add(1).unwrap();
        assert!(
            !FiniteOutcome::Fits {
                words,
                receipt: bad,
            }
            .has_closed_receipt()
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one exact/one-below matrix keeps every guarded construction cap and receipt closure adjacent"
    )]
    fn guarded_build_caps_admit_exactly_and_refuse_one_below_before_expansion() {
        let hir = parse(r"\b(a(?:s|sync)|Self)\b");
        let FiniteOutcome::GuardedFiniteBody {
            dictionary,
            accounting,
            ..
        } = extract(&hir, 16, 128, 0, u64::MAX, true)
        else {
            panic!("guarded baseline should fit");
        };
        let prospective = dictionary.build_accounting().prospective;
        let scratch_bytes = accounting
            .source
            .expansion_peak_bytes_upper_bound
            .max(accounting.source.source_transition_peak_bytes_upper_bound);
        let peak_bytes = accounting.source.construction_peak_bytes_upper_bound;
        let exact = GuardedFiniteBuildLimits {
            dictionary: GuardedBuildLimits {
                max_words: prospective.dimensions.words,
                max_packed_bytes: prospective.dimensions.packed_bytes,
                max_identity_bytes: prospective.identity_bytes,
                max_sort_comparisons: prospective.sort_comparisons,
                max_allocations: prospective.allocations,
                max_initialized_bytes: prospective.initialized_bytes,
                max_build_work: prospective.build_work,
                max_scratch_bytes: prospective.scratch_bytes,
                max_persistent_bytes: prospective.persistent_bytes,
                max_peak_bytes: prospective.peak_bytes,
            },
            max_scratch_bytes: scratch_bytes,
            max_peak_bytes: peak_bytes,
        };
        let outcome = super::extract(&hir, 16, 128, 0, u64::MAX, true, exact);
        assert!(outcome.has_closed_receipt());
        assert!(matches!(outcome, FiniteOutcome::GuardedFiniteBody { .. }));

        let mut one_below = exact;
        one_below.dictionary.max_identity_bytes = prospective.identity_bytes - 1;
        let outcome = super::extract(&hir, 16, 128, 0, u64::MAX, true, one_below);
        assert!(outcome.has_closed_receipt());
        let failure_actual = match &outcome {
            FiniteOutcome::GuardedResourceFailure {
                error: GuardedFiniteBuildError::Dictionary(error),
                ..
            } => error.actual(),
            _ => panic!("identity cap should retain a dictionary failure"),
        };
        let super::FiniteExtractionGuardedEvidence::Failed {
            accounting,
            co_live_local_scratch_bytes: _,
        } = outcome.receipt().actual().guarded.unwrap()
        else {
            panic!("guarded failure must retain its native partial actual");
        };
        assert_eq!(accounting, failure_actual);
        let boundary = outcome.receipt().boundary_actual().unwrap();
        assert_eq!(
            boundary.allocations,
            outcome.receipt().actual().local.allocations + failure_actual.allocations
        );
        assert_eq!(boundary.live_persistent_bytes, 0);
        assert_eq!(
            boundary.abandonable_bytes,
            outcome.receipt().actual().local.released_persistent_bytes
                + outcome.receipt().actual().local.released_scratch_bytes
                + guarded_allocated_bytes(failure_actual).unwrap()
        );
        assert!(matches!(
            outcome,
            FiniteOutcome::GuardedResourceFailure {
                error: GuardedFiniteBuildError::Dictionary(error),
                ..
            } if matches!(
                error.kind,
                GuardedBuildErrorKind::ResourceLimit {
                        resource: GuardedBuildResource::IdentityBytes,
                        ..
                }
            )
        ));

        let mut one_below = exact;
        one_below.dictionary.max_build_work = prospective.build_work - 1;
        let outcome = super::extract(&hir, 16, 128, 0, u64::MAX, true, one_below);
        assert!(outcome.has_closed_receipt());
        assert!(matches!(
            outcome,
            FiniteOutcome::GuardedResourceFailure {
                error: GuardedFiniteBuildError::Dictionary(error),
                ..
            } if matches!(error.kind, GuardedBuildErrorKind::WorkLimit { .. })
        ));

        let mut one_below = exact;
        one_below.max_scratch_bytes = scratch_bytes - 1;
        let outcome = super::extract(&hir, 16, 128, 0, u64::MAX, true, one_below);
        assert!(outcome.has_closed_receipt());
        assert!(matches!(
            outcome,
            FiniteOutcome::GuardedResourceFailure {
                error: GuardedFiniteBuildError::ConstructionLimit {
                    resource: GuardedFiniteBuildResource::ScratchBytes,
                    ..
                },
                ..
            }
        ));

        let mut one_below = exact;
        one_below.dictionary.max_persistent_bytes = prospective.persistent_bytes - 1;
        let outcome = super::extract(&hir, 16, 128, 0, u64::MAX, true, one_below);
        assert!(outcome.has_closed_receipt());
        assert!(matches!(
            outcome,
            FiniteOutcome::GuardedResourceFailure {
                error: GuardedFiniteBuildError::Dictionary(error),
                ..
            } if matches!(
                error.kind,
                GuardedBuildErrorKind::ResourceLimit {
                        resource: GuardedBuildResource::PersistentBytes,
                        ..
                }
            )
        ));

        let mut one_below = exact;
        one_below.max_peak_bytes = peak_bytes - 1;
        let outcome = super::extract(&hir, 16, 128, 0, u64::MAX, true, one_below);
        assert!(outcome.has_closed_receipt());
        assert!(matches!(
            outcome,
            FiniteOutcome::GuardedResourceFailure {
                error: GuardedFiniteBuildError::ConstructionLimit {
                    resource: GuardedFiniteBuildResource::PeakBytes,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn missing_negative_or_unicode_guards_and_nonwords_stay_unsupported() {
        assert!(matches!(
            extract(&parse(r"(?:aaaaaaaa|a*)"), 1, 1, 0, u64::MAX, false),
            FiniteOutcome::Unsupported { .. }
        ));
        for pattern in [r"\B(alpha)\B", r"\b(alpha-beta)\b", r"\b{start}(alpha)"] {
            assert!(matches!(
                extract(&parse(pattern), 16, 128, 0, u64::MAX, true),
                FiniteOutcome::Unsupported { .. }
            ));
        }
        let unicode = regex_syntax::Parser::new().parse(r"\b(alpha)\b").unwrap();
        assert!(matches!(
            extract(&unicode, 16, 128, 0, u64::MAX, true),
            FiniteOutcome::Unsupported { .. }
        ));
        for pattern in [
            r"(?:\b(aaaaaaaa)\b)|(?:\b(a*)\b)",
            r"\b{end}(aaaaaaaa)\b",
            r"\b(aaaa-aaaa)\b",
        ] {
            assert!(matches!(
                extract(&parse(pattern), 1, 1, 0, u64::MAX, true),
                FiniteOutcome::Unsupported { .. }
            ));
        }
    }

    #[test]
    fn fixed_predicate_attempt_receipts_close_success_refusal_and_partial_failure() {
        let hir = parse_case_insensitive("Sherlock Holmes");
        let successful =
            super::inspect_fixed_predicate_word64_after_finite_refusal_attempt(&hir, 17, u64::MAX);
        assert!(successful.has_closed_receipt());
        let success_receipt = successful.receipt();
        assert_eq!(success_receipt.initial_work(), 17);
        assert_eq!(success_receipt.work_limit(), u64::MAX);
        assert_eq!(
            success_receipt.terminal(),
            super::FixedPredicateInspectionTerminal::Succeeded
        );
        assert!(success_receipt.is_closed());
        let success_actual = success_receipt.actual();
        assert!(success_actual.work > 17);
        assert!(success_actual.local.allocations > 0);
        assert!(success_actual.local.reallocations > 0);
        assert!(success_actual.local.allocated_bytes > 0);
        assert!(success_actual.local.copied_bytes > 0);
        assert!(success_actual.local.initialized_bytes >= success_actual.local.copied_bytes);
        assert!(success_actual.local.high_water_bytes > 0);
        assert_eq!(success_actual.local.live_persistent_bytes, 0);
        assert_eq!(success_actual.local.live_scratch_bytes, 0);
        assert!(matches!(
            successful,
            super::FixedPredicateInspectionAttempt::Succeeded { ref source, .. }
                if source.width() == 15
        ));

        let legacy =
            super::inspect_fixed_predicate_word64_after_finite_refusal(&hir, 17, u64::MAX).unwrap();
        assert_eq!(legacy.work, success_actual.work);
        assert_eq!(legacy.source.unwrap().width(), 15);

        let refused_hir = parse("ab");
        let refused = super::inspect_fixed_predicate_word64_after_finite_refusal_attempt(
            &refused_hir,
            3,
            u64::MAX,
        );
        assert!(refused.has_closed_receipt());
        assert!(matches!(
            &refused,
            super::FixedPredicateInspectionAttempt::Refused { .. }
        ));
        assert_eq!(
            refused.receipt().terminal(),
            super::FixedPredicateInspectionTerminal::Refused
        );
        assert_eq!(refused.receipt().initial_work(), 3);
        assert!(refused.receipt().actual().work > 3);
        assert_eq!(refused.receipt().actual().local.live_scratch_bytes, 0);

        let one_below = success_actual.work.checked_sub(1).unwrap();
        let failed =
            super::inspect_fixed_predicate_word64_after_finite_refusal_attempt(&hir, 17, one_below);
        assert!(failed.has_closed_receipt());
        let failure_receipt = failed.receipt();
        assert_eq!(
            failure_receipt.terminal(),
            super::FixedPredicateInspectionTerminal::ResourceFailure
        );
        let failure_actual = failure_receipt.actual();
        assert!(failure_actual.work > 17);
        assert!(failure_actual.work <= one_below);
        assert!(failure_actual.local.allocations > 0);
        assert!(failure_actual.local.reallocations > 0);
        assert!(failure_actual.local.allocated_bytes > 0);
        assert!(failure_actual.local.copied_bytes > 0);
        assert!(failure_actual.local.initialized_bytes > 0);
        assert!(failure_actual.local.high_water_bytes > 0);
        assert_eq!(failure_actual.local.live_persistent_bytes, 0);
        assert_eq!(failure_actual.local.live_scratch_bytes, 0);
        assert!(matches!(
            failed,
            super::FixedPredicateInspectionAttempt::ResourceFailure {
                error: BuildError::PlannerWorkLimit { needed, limit },
                ..
            } if needed == success_actual.work && limit == one_below
        ));

        let initially_over_limit =
            super::inspect_fixed_predicate_word64_after_finite_refusal_attempt(&hir, 2, 1);
        assert!(initially_over_limit.has_closed_receipt());
        assert_eq!(initially_over_limit.receipt().initial_work(), 2);
        assert_eq!(initially_over_limit.receipt().actual().work, 2);
        assert_eq!(
            initially_over_limit.receipt().actual().local,
            super::FiniteExtractionLocalActual::default()
        );
        assert!(matches!(
            initially_over_limit,
            super::FixedPredicateInspectionAttempt::ResourceFailure {
                error: BuildError::PlannerWorkLimit {
                    needed: 2,
                    limit: 1
                },
                ..
            }
        ));
    }

    #[test]
    fn typed_finite_refusal_can_continue_into_exact_inline_predicates() {
        let hir = parse_case_insensitive("Sherlock Holmes");
        let FiniteOutcome::TooLargeFixedSequence { receipt } =
            extract(&hir, 4_096, usize::MAX, 17, u64::MAX, true)
        else {
            panic!("Sherlock closure should reach the typed finite refusal");
        };
        let refusal_work = receipt.actual.work;
        let inspected = super::inspect_fixed_predicate_word64_after_finite_refusal(
            &hir,
            refusal_work,
            u64::MAX,
        )
        .unwrap();
        let source = inspected
            .source
            .expect("typed refusal should retain the compact predicate proof");
        assert_eq!(source.width(), 15);
        assert_eq!(source.variable_predicates(), 14);
        assert_eq!(source.captures(), 0);
        assert!(source.hir_nodes() >= source.width());
        assert!(inspected.work > refusal_work);

        let positions = source.positions().collect::<Vec<_>>();
        assert_eq!(positions.len(), 15);
        assert!(positions[0].ranges().contains(&(b'S', b'S')));
        assert!(positions[0].ranges().contains(&(b's', b's')));
        assert_eq!(positions[8].ranges(), &[(b' ', b' ')]);
        assert!(positions[14].ranges().contains(&(b'S', b'S')));
        assert!(positions[14].ranges().contains(&(b's', b's')));

        let one_below = inspected.work.checked_sub(1).unwrap();
        assert!(matches!(
            super::inspect_fixed_predicate_word64_after_finite_refusal(
                &hir,
                refusal_work,
                one_below,
            ),
            Err(BuildError::PlannerWorkLimit { needed, limit })
                if needed == inspected.work && limit == one_below
        ));
    }

    #[test]
    fn compact_predicate_inspection_is_narrow_and_capture_aware() {
        let captured = parse_case_insensitive("(?P<phrase>Ab)");
        let inspected =
            super::inspect_fixed_predicate_word64_after_finite_refusal(&captured, 0, u64::MAX)
                .unwrap();
        let source = inspected.source.unwrap();
        assert_eq!(source.width(), 2);
        assert_eq!(source.variable_predicates(), 2);
        assert_eq!(source.captures(), 1);

        let width_64 = parse_case_insensitive(&"a".repeat(64));
        assert_eq!(
            super::inspect_fixed_predicate_word64_after_finite_refusal(&width_64, 0, u64::MAX,)
                .unwrap()
                .source
                .unwrap()
                .width(),
            64
        );
        let one = super::inspect_fixed_predicate_word64_after_finite_refusal(
            &parse_case_insensitive("a"),
            0,
            u64::MAX,
        )
        .unwrap()
        .source
        .expect("one variable byte predicate is a complete fixed word");
        assert_eq!(one.width(), 1);
        assert_eq!(one.variable_predicates(), 1);

        for (pattern, hir) in [
            (
                "case-insensitive width 65",
                parse_case_insensitive(&"a".repeat(65)),
            ),
            ("exact literal", parse("ab")),
            ("unbounded repetition", parse_case_insensitive("a+")),
            ("look assertion", parse_case_insensitive(r"\ba")),
            ("exact high byte", parse(r"\xFFa")),
        ] {
            assert!(
                super::inspect_fixed_predicate_word64_after_finite_refusal(&hir, 0, u64::MAX,)
                    .unwrap()
                    .source
                    .is_none(),
                "{pattern}"
            );
        }
        let ranged = super::inspect_fixed_predicate_word64_after_finite_refusal(
            &parse("[a-z]shing"),
            0,
            u64::MAX,
        )
        .unwrap()
        .source
        .expect("one bounded ASCII range is a compact fixed predicate");
        assert_eq!(ranged.width(), 6);
        assert_eq!(ranged.variable_predicates(), 1);
        assert_eq!(ranged.positions().next().unwrap().ranges(), &[(b'a', b'z')]);
        let two_ranged = super::inspect_fixed_predicate_word64_after_finite_refusal(
            &parse("[A-Za-z]x"),
            0,
            u64::MAX,
        )
        .unwrap()
        .source
        .expect("two bounded ASCII ranges remain inline");
        assert_eq!(
            two_ranged.positions().next().unwrap().ranges(),
            &[(b'A', b'Z'), (b'a', b'z')]
        );
        let full_byte = super::inspect_fixed_predicate_word64_after_finite_refusal(
            &parse(r"[\x80-\xFF]"),
            0,
            u64::MAX,
        )
        .unwrap()
        .source
        .expect("one full-byte-domain range remains inline");
        assert_eq!(full_byte.width(), 1);
        assert_eq!(
            full_byte.positions().next().unwrap().ranges(),
            &[(0x80, 0xFF)]
        );
        let four_ranged = super::inspect_fixed_predicate_word64_after_finite_refusal(
            &parse("[aceg]x"),
            0,
            u64::MAX,
        );
        assert_eq!(
            four_ranged
                .unwrap()
                .source
                .expect("four bounded ASCII ranges remain inline")
                .positions()
                .next()
                .unwrap()
                .ranges(),
            &[(b'a', b'a'), (b'c', b'c'), (b'e', b'e'), (b'g', b'g')]
        );
        assert!(
            super::inspect_fixed_predicate_word64_after_finite_refusal(
                &parse("[acegi]x"),
                0,
                u64::MAX,
            )
            .unwrap()
            .source
            .is_none()
        );
    }

    #[test]
    fn compact_predicate_inspection_admits_only_root_lazy_unit_repetitions() {
        let lazy = parse(r"(?P<byte>[a-z]+?)");
        assert!(
            super::inspect_fixed_predicate_word64_after_finite_refusal(&lazy, 0, u64::MAX)
                .unwrap()
                .source
                .is_none(),
            "shared search/complete-span inspection preserves incumbent refusal"
        );
        let admitted = super::inspect_fixed_predicate_word64_scalar_aggregate_attempt(
            &lazy,
            0,
            u64::MAX,
        );
        assert!(admitted.has_closed_receipt());
        let admitted_work = admitted.receipt().actual().work;
        let source = match admitted {
            super::FixedPredicateInspectionAttempt::Succeeded { source, .. } => source,
            _ => panic!("root lazy byte class must have a scalar aggregate proof"),
        };
        assert_eq!(source.width(), 1);
        assert_eq!(source.variable_predicates(), 1);
        assert_eq!(source.captures(), 1);
        assert!(source.is_lazy_unit_repetition());
        assert!(source.finite_incumbent_cannot_fit(usize::MAX, usize::MAX));

        let one_below = admitted_work.checked_sub(1).unwrap();
        let failed = super::inspect_fixed_predicate_word64_scalar_aggregate_attempt(
            &lazy,
            0,
            one_below,
        );
        assert!(failed.has_closed_receipt());
        assert!(matches!(
            failed,
            super::FixedPredicateInspectionAttempt::ResourceFailure {
                error: BuildError::PlannerWorkLimit { needed, limit },
                ..
            } if needed == admitted_work && limit == one_below
        ));

        let ordinary = super::inspect_fixed_predicate_word64_after_finite_refusal(
            &parse(r"[a-z]"),
            0,
            u64::MAX,
        )
        .unwrap()
        .source
        .expect("ordinary fixed byte predicate remains supported");
        assert!(!ordinary.is_lazy_unit_repetition());

        for pattern in [
            r"[a-z]+",
            r"[a-z]*?",
            r"[a-z]{2,}?",
            r"x[a-z]+?",
            r"[a-z]+?x",
            r"(?:[a-z]+?|x)",
            r"(?:[a-z][0-9])+?",
        ] {
            let refused = super::inspect_fixed_predicate_word64_scalar_aggregate_attempt(
                &parse(pattern),
                0,
                u64::MAX,
            );
            assert!(refused.has_closed_receipt(), "{pattern}");
            assert!(
                matches!(
                    refused,
                    super::FixedPredicateInspectionAttempt::Refused { .. }
                ),
                "{pattern} must remain outside the lazy unit theorem"
            );
        }
    }

    #[test]
    fn compact_predicate_inspection_retains_exact_finite_incumbent_shape() {
        let finite = super::inspect_fixed_predicate_word64_after_finite_refusal(
            &parse("[abc][def]"),
            0,
            u64::MAX,
        )
        .unwrap()
        .source
        .expect("small Cartesian language has a compact predicate proof");
        assert_eq!(finite.width(), 2);
        assert_eq!(finite.cartesian_product(), Some(9));
        assert!(finite.has_non_universal_predicate());
        assert!(!finite.finite_incumbent_cannot_fit(15, 24));
        assert!(finite.finite_incumbent_cannot_fit(14, 24));
        assert!(finite.finite_incumbent_cannot_fit(15, 23));
        assert!(finite.finite_incumbent_cannot_fit(9, 18));

        let four_by_eight = super::inspect_fixed_predicate_word64_after_finite_refusal(
            &parse("[abcdefgh][abcdefgh][abcdefgh][abcdefgh]"),
            0,
            u64::MAX,
        )
        .unwrap()
        .source
        .expect("four eight-member columns have a compact predicate proof");
        assert_eq!(four_by_eight.cartesian_product(), Some(4_096));
        assert!(!four_by_eight.finite_incumbent_cannot_fit(4_128, 16_416));
        assert!(four_by_eight.finite_incumbent_cannot_fit(4_127, 16_416));
        assert!(four_by_eight.finite_incumbent_cannot_fit(4_128, 16_415));
        assert!(four_by_eight.finite_incumbent_cannot_fit(4_096, 16_384));

        let universal = super::inspect_fixed_predicate_word64_after_finite_refusal(
            &parse(r"[\x00-\xFF][\x00-\xFF]"),
            0,
            u64::MAX,
        )
        .unwrap()
        .source
        .expect("all-universal positions remain a valid compact kernel source");
        assert_eq!(universal.cartesian_product(), Some(65_536));
        assert!(!universal.has_non_universal_predicate());
        assert!(universal.finite_incumbent_cannot_fit(4_096, usize::MAX));

        let overflow_pattern = r"[\x00-\xFE]".repeat(64);
        let overflow = super::inspect_fixed_predicate_word64_after_finite_refusal(
            &parse(&overflow_pattern),
            0,
            u64::MAX,
        )
        .unwrap()
        .source
        .expect("width-64 Cartesian overflow retains its compact predicate proof");
        assert_eq!(overflow.width(), 64);
        assert_eq!(overflow.cartesian_product(), None);
        assert!(overflow.has_non_universal_predicate());
        assert!(overflow.finite_incumbent_cannot_fit(usize::MAX, usize::MAX));

        let repetition = super::inspect_fixed_predicate_word64_after_finite_refusal(
            &parse("[ab]{2}"),
            0,
            u64::MAX,
        )
        .unwrap()
        .source
        .expect("exact repetition remains a compact predicate proof");
        assert!(repetition.finite_incumbent_cannot_fit(usize::MAX, usize::MAX));
    }

    #[test]
    fn compact_predicate_inspection_expands_exact_repetitions_within_word_width() {
        let source = super::inspect_fixed_predicate_word64_after_finite_refusal(
            &parse(r"[A-Za-z0-9_]{5}[ \t\n\r\u{B}\u{C}]\w{6}\s\w{7}"),
            0,
            u64::MAX,
        )
        .unwrap()
        .source
        .expect("exact ASCII class repetitions form one fixed predicate word");
        assert_eq!(source.width(), 20);
        assert_eq!(source.variable_predicates(), 20);
        assert_eq!(
            source.positions().next().unwrap().ranges(),
            &[(b'0', b'9'), (b'A', b'Z'), (b'_', b'_'), (b'a', b'z')]
        );

        for pattern in [r"[ab]{0}", r"[ab]{2,3}", r"[ab]{65}", r"(?:[ab]{8}){9}"] {
            assert!(
                super::inspect_fixed_predicate_word64_after_finite_refusal(
                    &parse(pattern),
                    0,
                    u64::MAX,
                )
                .unwrap()
                .source
                .is_none(),
                "{pattern} must remain outside the fixed-width word"
            );
        }
    }
}
