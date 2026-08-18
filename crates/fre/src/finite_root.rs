//! Allocation-free proof for large root literal alternatives.
//!
//! The general finite-language planner deliberately supports composition and
//! therefore owns an expanded `Vec<Vec<u8>>`. A flat root alternative does not
//! need that representation: its canonical HIR already owns every word in
//! exact leftmost-first order. This proof lets a sparse finite kernel traverse
//! those borrowed literals directly when the dense DFA's frozen cell cap is
//! the only failed structural bound.

use core::mem::size_of;

use fre_exact_alloc::{CopyError, ExactVec};
use fre_kernels::OrderedLiteralAggregateBuildLimits;
use regex_syntax::hir::{Hir, HirKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InspectionError {
    WorkLimit { needed: u64, limit: u64 },
    Overflow,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RootLiteralInspectionActual {
    pub(crate) work: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RootLiteralInspectionAttemptReceipt {
    actual: RootLiteralInspectionActual,
    closed: bool,
}

impl RootLiteralInspectionAttemptReceipt {
    pub(crate) const fn actual(self) -> RootLiteralInspectionActual {
        self.actual
    }

    pub(crate) const fn is_closed(self) -> bool {
        self.closed
    }
}

pub(crate) struct RootLiteralInspectionAttempt<'a> {
    pub(crate) outcome: Inspection<'a>,
    pub(crate) receipt: RootLiteralInspectionAttemptReceipt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RootLiteralInspectionAttemptError {
    source: InspectionError,
    receipt: RootLiteralInspectionAttemptReceipt,
}

impl RootLiteralInspectionAttemptError {
    pub(crate) const fn source(self) -> InspectionError {
        self.source
    }

    pub(crate) const fn receipt(self) -> RootLiteralInspectionAttemptReceipt {
        self.receipt
    }

    #[allow(dead_code, reason = "legacy projection retained for compatibility")]
    pub(crate) const fn into_source(self) -> InspectionError {
        self.source
    }
}

#[derive(Debug)]
pub(crate) enum MaterializationError {
    WorkLimit { needed: u64, limit: u64 },
    ScratchLimit { needed: usize, limit: usize },
    PeakLimit { needed: usize, limit: usize },
    AllocationFailed { additional: usize },
    Overflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RootLiteralMaterializationProspective {
    pub(crate) final_work: u64,
    pub(crate) allocations: usize,
    pub(crate) initialized_bytes: usize,
    pub(crate) scratch_bytes_limit: usize,
    pub(crate) peak_bytes_limit: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RootLiteralMaterializationActual {
    pub(crate) work: u64,
    pub(crate) allocations: usize,
    pub(crate) allocated_bytes: usize,
    pub(crate) initialized_bytes: usize,
    pub(crate) live_scratch_bytes: usize,
    pub(crate) peak_bytes: usize,
    pub(crate) abandoned_allocations: usize,
    pub(crate) abandoned_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RootLiteralMaterializationAttemptReceipt {
    prospective: Option<RootLiteralMaterializationProspective>,
    actual: RootLiteralMaterializationActual,
    closed: bool,
}

impl RootLiteralMaterializationAttemptReceipt {
    const fn open(actual_work: u64) -> Self {
        Self {
            prospective: None,
            actual: RootLiteralMaterializationActual {
                work: actual_work,
                allocations: 0,
                allocated_bytes: 0,
                initialized_bytes: 0,
                live_scratch_bytes: 0,
                peak_bytes: 0,
                abandoned_allocations: 0,
                abandoned_bytes: 0,
            },
            closed: false,
        }
    }

    pub(crate) const fn prospective(self) -> Option<RootLiteralMaterializationProspective> {
        self.prospective
    }

    pub(crate) const fn actual(self) -> RootLiteralMaterializationActual {
        self.actual
    }

    pub(crate) const fn is_closed(self) -> bool {
        self.closed
    }
}

#[derive(Debug)]
pub(crate) struct RootLiteralMaterializationAttemptError {
    source: MaterializationError,
    receipt: RootLiteralMaterializationAttemptReceipt,
}

impl RootLiteralMaterializationAttemptError {
    pub(crate) const fn source(&self) -> &MaterializationError {
        &self.source
    }

    pub(crate) const fn receipt(&self) -> RootLiteralMaterializationAttemptReceipt {
        self.receipt
    }

    #[allow(dead_code, reason = "legacy projection retained for compatibility")]
    pub(crate) fn into_source(self) -> MaterializationError {
        self.source
    }
}

pub(crate) enum Inspection<'a> {
    Eligible(RootLiteralAlternation<'a>),
    Ineligible { work: u64 },
}

/// Borrowed canonical root alternative plus exact construction-selection
/// dimensions. No word, byte or HIR-node buffer is allocated by inspection.
pub(crate) struct RootLiteralAlternation<'a> {
    children: &'a [Hir],
    /// Whether inspection validated every borrowed literal as complete UTF-8.
    /// This seal is required before the facade may omit a second Unicode
    /// boundary scan while constructing from the borrowed source.
    unicode_validated: bool,
    /// Exact abstract selection work: root/child visits, one alphabet-census
    /// visit per literal byte, and one additional UTF-8 validation visit per
    /// literal byte when Unicode syntax is enabled.
    pub(crate) work: u64,
    pub(crate) hir_nodes: usize,
    pub(crate) pattern_bytes: usize,
    pub(crate) identity_bytes: usize,
    pub(crate) trie_states_upper_bound: usize,
    pub(crate) dense_cells_upper_bound: usize,
}

impl RootLiteralAlternation<'_> {
    pub(crate) const fn pattern_count(&self) -> usize {
        self.children.len()
    }

    pub(crate) fn should_use_sparse(&self, limits: OrderedLiteralAggregateBuildLimits) -> bool {
        self.pattern_count() <= limits.max_patterns
            && self.pattern_bytes <= limits.max_pattern_bytes
            && self.identity_bytes <= limits.max_identity_bytes
            && self.trie_states_upper_bound <= limits.max_trie_states
            && self.dense_cells_upper_bound > limits.max_dfa_cells
    }

    /// Whether the incumbent general extractor is structurally proved to
    /// finish with `Fits` for this exact flat alternation.
    ///
    /// The owned extractor evaluates every child language before allocating
    /// the combined result, so its exact logical evaluation peak is twice the
    /// final word and byte counts. Keeping that established admission rule
    /// here prevents the borrowed source from changing a too-large semantic
    /// disposition into a packed or dense build attempt.
    pub(crate) fn supports_borrowed_general(
        &self,
        unicode: bool,
        limits: OrderedLiteralAggregateBuildLimits,
    ) -> bool {
        (!unicode || self.unicode_validated)
            && self
                .pattern_count()
                .checked_mul(2)
                .is_some_and(|peak| peak <= limits.max_patterns)
            && self
                .pattern_bytes
                .checked_mul(2)
                .is_some_and(|peak| peak <= limits.max_pattern_bytes)
    }

    /// Materialize only borrowed slice pointers after exact work and capacity
    /// preflight. The returned concrete vector is the sparse builder's entire
    /// dynamic input; its observed capacity is checked again there.
    #[allow(dead_code, reason = "legacy projection retained for compatibility")]
    pub(crate) fn materialize_patterns(
        &self,
        work_limit: u64,
        scratch_limit: usize,
        peak_limit: usize,
    ) -> Result<RootLiteralMaterialization<Vec<&[u8]>>, MaterializationError> {
        self.materialize_patterns_attempt(work_limit, scratch_limit, peak_limit)
            .map_err(RootLiteralMaterializationAttemptError::into_source)
    }

    /// Receipt-bearing form of [`Self::materialize_patterns`].
    ///
    /// The prospective envelope is published before the pointer-vector
    /// allocation. On a post-allocation limit refusal, the closed error
    /// receipt retains the observed allocation and marks it abandoned.
    #[allow(
        clippy::result_large_err,
        reason = "the exact closed failure receipt must remain inline and allocation-free"
    )]
    #[allow(
        clippy::too_many_lines,
        reason = "the linear materialization transaction keeps every charged step adjacent"
    )]
    pub(crate) fn materialize_patterns_attempt(
        &self,
        work_limit: u64,
        scratch_limit: usize,
        peak_limit: usize,
    ) -> Result<RootLiteralMaterialization<Vec<&[u8]>>, RootLiteralMaterializationAttemptError>
    {
        self.materialize_patterns_attempt_with::<Vec<&[u8]>>(
            work_limit,
            scratch_limit,
            peak_limit,
        )
    }

    /// Materialize the borrowed pointer staging used by general Compile into
    /// allocator-independent exact-capacity storage.
    ///
    /// The pre-existing sparse route consumes a `Vec` and closes any observed
    /// allocator overcapacity in its materialization receipt. General Compile
    /// instead retains this staging across packed/dense construction, so its
    /// candidate-owned capacity must equal the prospective pointer count.
    pub(crate) fn materialize_patterns_exact_attempt(
        &self,
        work_limit: u64,
        scratch_limit: usize,
        peak_limit: usize,
    ) -> Result<RootLiteralMaterialization<ExactVec<&[u8]>>, RootLiteralMaterializationAttemptError>
    {
        self.materialize_patterns_attempt_with::<ExactVec<&[u8]>>(
            work_limit,
            scratch_limit,
            peak_limit,
        )
    }

    fn materialize_patterns_attempt_with<'a, Storage>(
        &'a self,
        work_limit: u64,
        scratch_limit: usize,
        peak_limit: usize,
    ) -> Result<RootLiteralMaterialization<Storage>, RootLiteralMaterializationAttemptError>
    where
        Storage: RootLiteralPatternStorage<'a>,
    {
        let mut receipt = RootLiteralMaterializationAttemptReceipt::open(self.work);
        let projection_work = u64::try_from(self.children.len()).map_err(|_| {
            close_materialization_error(&mut receipt, MaterializationError::Overflow)
        })?;
        let final_work = self.work.checked_add(projection_work).ok_or_else(|| {
            close_materialization_error(&mut receipt, MaterializationError::Overflow)
        })?;
        let initialized_bytes = self
            .children
            .len()
            .checked_mul(size_of::<&[u8]>())
            .ok_or_else(|| {
                close_materialization_error(&mut receipt, MaterializationError::Overflow)
            })?;
        receipt.prospective = Some(RootLiteralMaterializationProspective {
            final_work,
            allocations: usize::from(!self.children.is_empty()),
            initialized_bytes,
            scratch_bytes_limit: scratch_limit,
            peak_bytes_limit: peak_limit,
        });
        if final_work > work_limit {
            return Err(close_materialization_error(
                &mut receipt,
                MaterializationError::WorkLimit {
                    needed: final_work,
                    limit: work_limit,
                },
            ));
        }
        let requested = initialized_bytes;
        if let Err(error) = check_source_capacity(requested, scratch_limit, peak_limit) {
            return Err(close_materialization_error(&mut receipt, error));
        }
        let mut patterns = Storage::try_with_capacity(self.children.len()).map_err(|source| {
            close_materialization_error(&mut receipt, source)
        })?;
        let observed = patterns
            .capacity()
            .checked_mul(size_of::<&[u8]>())
            .ok_or_else(|| {
                close_materialization_error(&mut receipt, MaterializationError::Overflow)
            })?;
        if patterns.capacity() != 0 {
            receipt.actual.allocations = 1;
            receipt.actual.allocated_bytes = observed;
            receipt.actual.live_scratch_bytes = observed;
            receipt.actual.peak_bytes = observed;
        }
        if let Err(error) = check_source_capacity(observed, scratch_limit, peak_limit) {
            abandon_materialization(&mut receipt);
            return Err(close_materialization_error(&mut receipt, error));
        }

        let mut work = self.work;
        for child in self.children {
            let needed = work.checked_add(1).ok_or_else(|| {
                abandon_materialization(&mut receipt);
                close_materialization_error(&mut receipt, MaterializationError::Overflow)
            })?;
            if needed > work_limit {
                abandon_materialization(&mut receipt);
                return Err(close_materialization_error(
                    &mut receipt,
                    MaterializationError::WorkLimit {
                        needed,
                        limit: work_limit,
                    },
                ));
            }
            work = needed;
            receipt.actual.work = work;
            let HirKind::Literal(literal) = child.kind() else {
                unreachable!("proved root literal alternative changed during construction")
            };
            patterns.push(literal.0.as_ref());
            let Some(initialized_bytes) = receipt
                .actual
                .initialized_bytes
                .checked_add(size_of::<&[u8]>())
            else {
                abandon_materialization(&mut receipt);
                return Err(close_materialization_error(
                    &mut receipt,
                    MaterializationError::Overflow,
                ));
            };
            receipt.actual.initialized_bytes = initialized_bytes;
        }
        debug_assert_eq!(work, final_work);
        receipt.closed = true;
        Ok(RootLiteralMaterialization {
            patterns,
            work,
            receipt,
        })
    }
}

pub(crate) struct RootLiteralMaterialization<Storage> {
    pub(crate) patterns: Storage,
    pub(crate) work: u64,
    pub(crate) receipt: RootLiteralMaterializationAttemptReceipt,
}

trait RootLiteralPatternStorage<'a>: Sized {
    fn try_with_capacity(capacity: usize) -> Result<Self, MaterializationError>;

    fn capacity(&self) -> usize;

    fn push(&mut self, pattern: &'a [u8]);
}

impl<'a> RootLiteralPatternStorage<'a> for Vec<&'a [u8]> {
    fn try_with_capacity(capacity: usize) -> Result<Self, MaterializationError> {
        let mut patterns = Self::new();
        patterns.try_reserve_exact(capacity).map_err(|_| {
            MaterializationError::AllocationFailed {
                additional: capacity,
            }
        })?;
        Ok(patterns)
    }

    fn capacity(&self) -> usize {
        Vec::capacity(self)
    }

    fn push(&mut self, pattern: &'a [u8]) {
        Vec::push(self, pattern);
    }
}

impl<'a> RootLiteralPatternStorage<'a> for ExactVec<&'a [u8]> {
    fn try_with_capacity(capacity: usize) -> Result<Self, MaterializationError> {
        ExactVec::try_with_capacity(capacity).map_err(|error| match error {
            CopyError::LayoutOverflow => MaterializationError::Overflow,
            CopyError::AllocationFailed => MaterializationError::AllocationFailed {
                additional: capacity,
            },
        })
    }

    fn capacity(&self) -> usize {
        ExactVec::capacity(self)
    }

    fn push(&mut self, pattern: &'a [u8]) {
        if self.try_push(pattern).is_err() {
            unreachable!("root literal proof initialized more pointers than its exact capacity");
        }
    }
}

fn abandon_materialization(receipt: &mut RootLiteralMaterializationAttemptReceipt) {
    receipt.actual.abandoned_allocations = receipt.actual.allocations;
    receipt.actual.abandoned_bytes = receipt.actual.allocated_bytes;
    receipt.actual.live_scratch_bytes = 0;
}

fn close_materialization_error(
    receipt: &mut RootLiteralMaterializationAttemptReceipt,
    source: MaterializationError,
) -> RootLiteralMaterializationAttemptError {
    receipt.closed = true;
    RootLiteralMaterializationAttemptError {
        source,
        receipt: *receipt,
    }
}

fn check_source_capacity(
    needed: usize,
    scratch_limit: usize,
    peak_limit: usize,
) -> Result<(), MaterializationError> {
    if needed > scratch_limit {
        return Err(MaterializationError::ScratchLimit {
            needed,
            limit: scratch_limit,
        });
    }
    if needed > peak_limit {
        return Err(MaterializationError::PeakLimit {
            needed,
            limit: peak_limit,
        });
    }
    Ok(())
}

#[allow(dead_code, reason = "legacy projection retained for compatibility")]
pub(crate) fn inspect(
    hir: &Hir,
    unicode: bool,
    work_limit: u64,
) -> Result<Inspection<'_>, InspectionError> {
    inspect_attempt(hir, unicode, work_limit)
        .map(|attempt| attempt.outcome)
        .map_err(RootLiteralInspectionAttemptError::into_source)
}

pub(crate) fn inspect_attempt(
    hir: &Hir,
    unicode: bool,
    work_limit: u64,
) -> Result<RootLiteralInspectionAttempt<'_>, RootLiteralInspectionAttemptError> {
    let mut work = 0_u64;
    charge(&mut work, 1, work_limit).map_err(|source| close_inspection_error(source, work))?;
    let HirKind::Alternation(children) = hir.kind() else {
        return Ok(close_inspection(Inspection::Ineligible { work }, work));
    };
    if children.is_empty() {
        return Ok(close_inspection(Inspection::Ineligible { work }, work));
    }

    let mut pattern_bytes = 0_usize;
    let mut used = [false; 256];
    let mut used_count = 0_usize;
    for child in children {
        charge(&mut work, 1, work_limit).map_err(|source| close_inspection_error(source, work))?;
        let HirKind::Literal(literal) = child.kind() else {
            return Ok(close_inspection(Inspection::Ineligible { work }, work));
        };
        let bytes = literal.0.as_ref();
        if bytes.is_empty() {
            return Ok(close_inspection(Inspection::Ineligible { work }, work));
        }
        let byte_work = u64::try_from(bytes.len())
            .map_err(|_| close_inspection_error(InspectionError::Overflow, work))?;
        if unicode {
            charge(&mut work, byte_work, work_limit)
                .map_err(|source| close_inspection_error(source, work))?;
            if core::str::from_utf8(bytes).is_err() {
                return Ok(close_inspection(Inspection::Ineligible { work }, work));
            }
        }
        charge(&mut work, byte_work, work_limit)
            .map_err(|source| close_inspection_error(source, work))?;
        pattern_bytes = pattern_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| close_inspection_error(InspectionError::Overflow, work))?;
        for &byte in bytes {
            let slot = &mut used[usize::from(byte)];
            if !*slot {
                *slot = true;
                used_count = used_count
                    .checked_add(1)
                    .ok_or_else(|| close_inspection_error(InspectionError::Overflow, work))?;
            }
        }
    }

    let pattern_count = children.len();
    let identity_bytes = size_of::<u64>()
        .checked_add(
            pattern_count
                .checked_mul(size_of::<u64>())
                .ok_or_else(|| close_inspection_error(InspectionError::Overflow, work))?,
        )
        .and_then(|bytes| bytes.checked_add(pattern_bytes))
        .ok_or_else(|| close_inspection_error(InspectionError::Overflow, work))?;
    let trie_states_upper_bound = pattern_bytes
        .checked_add(1)
        .ok_or_else(|| close_inspection_error(InspectionError::Overflow, work))?;
    let alphabet_classes = if used_count == 256 {
        256
    } else {
        used_count
            .checked_add(1)
            .ok_or_else(|| close_inspection_error(InspectionError::Overflow, work))?
    };
    let dense_cells_upper_bound = trie_states_upper_bound
        .checked_mul(alphabet_classes)
        .ok_or_else(|| close_inspection_error(InspectionError::Overflow, work))?;
    let hir_nodes = pattern_count
        .checked_add(1)
        .ok_or_else(|| close_inspection_error(InspectionError::Overflow, work))?;
    Ok(close_inspection(
        Inspection::Eligible(RootLiteralAlternation {
            children,
            unicode_validated: unicode,
            work,
            hir_nodes,
            pattern_bytes,
            identity_bytes,
            trie_states_upper_bound,
            dense_cells_upper_bound,
        }),
        work,
    ))
}

fn charge(work: &mut u64, amount: u64, limit: u64) -> Result<(), InspectionError> {
    let needed = work.checked_add(amount).ok_or(InspectionError::Overflow)?;
    if needed > limit {
        return Err(InspectionError::WorkLimit { needed, limit });
    }
    *work = needed;
    Ok(())
}

const fn close_inspection(outcome: Inspection<'_>, work: u64) -> RootLiteralInspectionAttempt<'_> {
    RootLiteralInspectionAttempt {
        outcome,
        receipt: RootLiteralInspectionAttemptReceipt {
            actual: RootLiteralInspectionActual { work },
            closed: true,
        },
    }
}

const fn close_inspection_error(
    source: InspectionError,
    work: u64,
) -> RootLiteralInspectionAttemptError {
    RootLiteralInspectionAttemptError {
        source,
        receipt: RootLiteralInspectionAttemptReceipt {
            actual: RootLiteralInspectionActual { work },
            closed: true,
        },
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        reason = "exact one-below fixtures subtract from values proved positive in the same test"
    )]

    use super::{
        Inspection, InspectionError, MaterializationError, inspect, inspect_attempt, size_of,
    };
    use fre_kernels::OrderedLiteralAggregateBuildLimits;
    use regex_syntax::ParserBuilder;

    fn parse(pattern: &str) -> regex_syntax::hir::Hir {
        ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(pattern)
            .unwrap()
    }

    #[test]
    fn root_literal_inspection_is_exact_and_allocation_free() {
        let hir = regex_syntax::hir::Hir::alternation(vec![
            regex_syntax::hir::Hir::literal(b"ab".as_slice()),
            regex_syntax::hir::Hir::literal(b"a".as_slice()),
            regex_syntax::hir::Hir::literal(b"ab".as_slice()),
            regex_syntax::hir::Hir::literal(b"xyz".as_slice()),
        ]);
        let Inspection::Eligible(proof) = inspect(&hir, false, u64::MAX).unwrap() else {
            panic!("literal root should be eligible");
        };
        let materialized = proof
            .materialize_patterns_attempt(u64::MAX, usize::MAX, usize::MAX)
            .unwrap();
        assert_eq!(
            materialized.patterns,
            vec![
                b"ab".as_slice(),
                b"a".as_slice(),
                b"ab".as_slice(),
                b"xyz".as_slice()
            ]
        );
        assert_eq!(materialized.work, 17);
        let prospective = materialized.receipt.prospective().unwrap();
        let actual = materialized.receipt.actual();
        assert!(materialized.receipt.is_closed());
        assert_eq!(prospective.final_work, 17);
        assert_eq!(prospective.allocations, 1);
        assert_eq!(prospective.initialized_bytes, 4 * size_of::<&[u8]>());
        assert_eq!(actual.work, 17);
        assert_eq!(actual.allocations, 1);
        assert!(actual.allocated_bytes >= prospective.initialized_bytes);
        assert_eq!(actual.initialized_bytes, prospective.initialized_bytes);
        assert_eq!(actual.live_scratch_bytes, actual.allocated_bytes);
        assert_eq!(actual.peak_bytes, actual.allocated_bytes);
        assert_eq!(actual.abandoned_allocations, 0);
        assert_eq!(actual.abandoned_bytes, 0);
        let replayed = proof
            .materialize_patterns_attempt(
                materialized.work,
                actual.allocated_bytes,
                actual.allocated_bytes,
            )
            .unwrap();
        assert_eq!(
            replayed.receipt.actual().allocated_bytes,
            actual.allocated_bytes
        );
        let exact = proof
            .materialize_patterns_exact_attempt(
                materialized.work,
                prospective.initialized_bytes,
                prospective.initialized_bytes,
            )
            .unwrap();
        assert_eq!(exact.patterns.as_slice(), materialized.patterns.as_slice());
        assert_eq!(
            exact.receipt.actual().allocated_bytes,
            prospective.initialized_bytes
        );
        assert_eq!(
            exact.receipt.actual().live_scratch_bytes,
            prospective.initialized_bytes
        );
        let Err(exact_preflight_refused) = proof.materialize_patterns_exact_attempt(
            materialized.work,
            prospective.initialized_bytes - 1,
            prospective.initialized_bytes,
        ) else {
            panic!("one-below exact staging scratch must refuse");
        };
        assert!(exact_preflight_refused.receipt().is_closed());
        assert_eq!(exact_preflight_refused.receipt().actual().allocations, 0);
        assert!(matches!(
            exact_preflight_refused.source(),
            MaterializationError::ScratchLimit { needed, limit }
                if *needed == prospective.initialized_bytes
                    && *limit == prospective.initialized_bytes - 1
        ));
        let Err(refused) = proof.materialize_patterns_attempt(proof.work, usize::MAX, usize::MAX)
        else {
            panic!("one-below materialization work limit should refuse");
        };
        assert!(refused.receipt().is_closed());
        assert_eq!(refused.receipt().actual().work, proof.work);
        assert_eq!(refused.receipt().actual().allocations, 0);
        assert!(matches!(
            refused.source(),
            MaterializationError::WorkLimit { needed, limit }
                if *needed == 17 && *limit == proof.work
        ));
        assert!(matches!(
            proof.materialize_patterns(proof.work, usize::MAX, usize::MAX),
            Err(MaterializationError::WorkLimit { needed, limit })
                if needed == 17 && limit == proof.work
        ));
        let pointer_bytes = 4 * size_of::<&[u8]>();
        assert!(matches!(
            proof.materialize_patterns(u64::MAX, pointer_bytes - 1, usize::MAX),
            Err(MaterializationError::ScratchLimit { needed, limit })
                if needed == pointer_bytes && limit == pointer_bytes - 1
        ));
        assert!(matches!(
            proof.materialize_patterns(u64::MAX, usize::MAX, pointer_bytes - 1),
            Err(MaterializationError::PeakLimit { needed, limit })
                if needed == pointer_bytes && limit == pointer_bytes - 1
        ));
        assert_eq!(proof.pattern_count(), 4);
        assert_eq!(proof.pattern_bytes, 8);
        assert_eq!(proof.hir_nodes, 5);
        assert_eq!(proof.work, 13);
        // Five distinct bytes plus the catch-all alphabet class, across the
        // independently calculated nine-state trie upper bound.
        assert_eq!(proof.dense_cells_upper_bound, 9 * 6);
        assert!(matches!(
            inspect(&hir, false, proof.work - 1),
            Err(InspectionError::WorkLimit { needed, limit })
                if needed == proof.work && limit == proof.work - 1
        ));
        let Err(inspection_refused) = inspect_attempt(&hir, false, proof.work - 1) else {
            panic!("one-below inspection work limit should refuse");
        };
        assert!(inspection_refused.receipt().is_closed());
        assert_eq!(inspection_refused.receipt().actual().work, 10);
        assert!(matches!(
            inspection_refused.source(),
            InspectionError::WorkLimit { needed, limit }
                if needed == proof.work && limit == proof.work - 1
        ));

        let mut dense = OrderedLiteralAggregateBuildLimits::unlimited();
        dense.max_patterns = proof.pattern_count() * 2;
        dense.max_pattern_bytes = proof.pattern_bytes * 2;
        assert!(proof.supports_borrowed_general(false, dense));
        assert!(!proof.supports_borrowed_general(true, dense));
        dense.max_patterns = proof.pattern_count() * 2 - 1;
        assert!(!proof.supports_borrowed_general(false, dense));
        dense.max_patterns = proof.pattern_count() * 2;
        dense.max_pattern_bytes = proof.pattern_bytes * 2 - 1;
        assert!(!proof.supports_borrowed_general(false, dense));
        dense.max_pattern_bytes = usize::MAX;
        dense.max_dfa_cells = proof.dense_cells_upper_bound;
        assert!(!proof.should_use_sparse(dense));
        dense.max_dfa_cells -= 1;
        assert!(proof.should_use_sparse(dense));

        let Inspection::Eligible(unicode_proof) = inspect(&hir, true, u64::MAX).unwrap() else {
            panic!("valid UTF-8 literal root should be Unicode eligible");
        };
        assert_eq!(unicode_proof.work, 21);
        assert!(
            unicode_proof
                .supports_borrowed_general(true, OrderedLiteralAggregateBuildLimits::unlimited())
        );
        assert!(matches!(
            inspect(&hir, true, unicode_proof.work - 1),
            Err(InspectionError::WorkLimit { needed, limit })
                if needed == unicode_proof.work && limit == unicode_proof.work - 1
        ));
    }

    #[test]
    fn composed_or_invalid_unicode_languages_stay_outside_the_fast_proof() {
        assert!(matches!(
            inspect(&parse("(?:ab)+|cd"), false, u64::MAX).unwrap(),
            Inspection::Ineligible { .. }
        ));
        let invalid = regex_syntax::hir::Hir::alternation(vec![
            regex_syntax::hir::Hir::literal([0xFF]),
            regex_syntax::hir::Hir::literal(b"ok".as_slice()),
        ]);
        assert!(matches!(
            inspect(&invalid, true, u64::MAX).unwrap(),
            Inspection::Ineligible { .. }
        ));
        let captured = regex_syntax::hir::Hir::alternation(vec![
            regex_syntax::hir::Hir::capture(regex_syntax::hir::Capture {
                index: 1,
                name: None,
                sub: Box::new(regex_syntax::hir::Hir::literal(b"ab".as_slice())),
            }),
            regex_syntax::hir::Hir::literal(b"cd".as_slice()),
        ]);
        assert!(matches!(
            inspect(&captured, false, u64::MAX).unwrap(),
            Inspection::Ineligible { .. }
        ));
    }
}
