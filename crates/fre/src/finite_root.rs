//! Allocation-free proof for large root literal alternatives.
//!
//! The general finite-language planner deliberately supports composition and
//! therefore owns an expanded `Vec<Vec<u8>>`. A flat root alternative does not
//! need that representation: its canonical HIR already owns every word in
//! exact leftmost-first order. This proof lets a sparse finite kernel traverse
//! those borrowed literals directly when the dense DFA's frozen cell cap is
//! the only failed structural bound.

use core::mem::size_of;

use fre_kernels::OrderedLiteralAggregateBuildLimits;
use regex_syntax::hir::{Hir, HirKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InspectionError {
    WorkLimit { needed: u64, limit: u64 },
    Overflow,
}

#[derive(Debug)]
pub(crate) enum MaterializationError {
    WorkLimit { needed: u64, limit: u64 },
    ScratchLimit { needed: usize, limit: usize },
    PeakLimit { needed: usize, limit: usize },
    AllocationFailed { additional: usize },
    Overflow,
}

pub(crate) enum Inspection<'a> {
    Eligible(RootLiteralAlternation<'a>),
    Ineligible { work: u64 },
}

/// Borrowed canonical root alternative plus exact construction-selection
/// dimensions. No word, byte or HIR-node buffer is allocated by inspection.
pub(crate) struct RootLiteralAlternation<'a> {
    children: &'a [Hir],
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

    /// Materialize only borrowed slice pointers after exact work and capacity
    /// preflight. The returned concrete vector is the sparse builder's entire
    /// dynamic input; its observed capacity is checked again there.
    pub(crate) fn materialize_patterns(
        &self,
        work_limit: u64,
        scratch_limit: usize,
        peak_limit: usize,
    ) -> Result<RootLiteralMaterialization<'_>, MaterializationError> {
        let requested = self
            .children
            .len()
            .checked_mul(size_of::<&[u8]>())
            .ok_or(MaterializationError::Overflow)?;
        check_source_capacity(requested, scratch_limit, peak_limit)?;
        let mut patterns = Vec::new();
        patterns
            .try_reserve_exact(self.children.len())
            .map_err(|_| MaterializationError::AllocationFailed {
                additional: self.children.len(),
            })?;
        let observed = patterns
            .capacity()
            .checked_mul(size_of::<&[u8]>())
            .ok_or(MaterializationError::Overflow)?;
        check_source_capacity(observed, scratch_limit, peak_limit)?;

        let mut work = self.work;
        for child in self.children {
            let needed = work.checked_add(1).ok_or(MaterializationError::Overflow)?;
            if needed > work_limit {
                return Err(MaterializationError::WorkLimit {
                    needed,
                    limit: work_limit,
                });
            }
            work = needed;
            let HirKind::Literal(literal) = child.kind() else {
                unreachable!("proved root literal alternative changed during construction")
            };
            patterns.push(literal.0.as_ref());
        }
        Ok(RootLiteralMaterialization { patterns, work })
    }
}

pub(crate) struct RootLiteralMaterialization<'a> {
    pub(crate) patterns: Vec<&'a [u8]>,
    pub(crate) work: u64,
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

pub(crate) fn inspect(
    hir: &Hir,
    unicode: bool,
    work_limit: u64,
) -> Result<Inspection<'_>, InspectionError> {
    let mut work = 0_u64;
    charge(&mut work, 1, work_limit)?;
    let HirKind::Alternation(children) = hir.kind() else {
        return Ok(Inspection::Ineligible { work });
    };
    if children.is_empty() {
        return Ok(Inspection::Ineligible { work });
    }

    let mut pattern_bytes = 0_usize;
    let mut used = [false; 256];
    let mut used_count = 0_usize;
    for child in children {
        charge(&mut work, 1, work_limit)?;
        let HirKind::Literal(literal) = child.kind() else {
            return Ok(Inspection::Ineligible { work });
        };
        let bytes = literal.0.as_ref();
        if bytes.is_empty() {
            return Ok(Inspection::Ineligible { work });
        }
        let byte_work = u64::try_from(bytes.len()).map_err(|_| InspectionError::Overflow)?;
        if unicode {
            charge(&mut work, byte_work, work_limit)?;
            if core::str::from_utf8(bytes).is_err() {
                return Ok(Inspection::Ineligible { work });
            }
        }
        charge(&mut work, byte_work, work_limit)?;
        pattern_bytes = pattern_bytes
            .checked_add(bytes.len())
            .ok_or(InspectionError::Overflow)?;
        for &byte in bytes {
            let slot = &mut used[usize::from(byte)];
            if !*slot {
                *slot = true;
                used_count = used_count.checked_add(1).ok_or(InspectionError::Overflow)?;
            }
        }
    }

    let pattern_count = children.len();
    let identity_bytes = size_of::<u64>()
        .checked_add(
            pattern_count
                .checked_mul(size_of::<u64>())
                .ok_or(InspectionError::Overflow)?,
        )
        .and_then(|bytes| bytes.checked_add(pattern_bytes))
        .ok_or(InspectionError::Overflow)?;
    let trie_states_upper_bound = pattern_bytes
        .checked_add(1)
        .ok_or(InspectionError::Overflow)?;
    let alphabet_classes = if used_count == 256 {
        256
    } else {
        used_count.checked_add(1).ok_or(InspectionError::Overflow)?
    };
    let dense_cells_upper_bound = trie_states_upper_bound
        .checked_mul(alphabet_classes)
        .ok_or(InspectionError::Overflow)?;
    let hir_nodes = pattern_count
        .checked_add(1)
        .ok_or(InspectionError::Overflow)?;
    Ok(Inspection::Eligible(RootLiteralAlternation {
        children,
        work,
        hir_nodes,
        pattern_bytes,
        identity_bytes,
        trie_states_upper_bound,
        dense_cells_upper_bound,
    }))
}

fn charge(work: &mut u64, amount: u64, limit: u64) -> Result<(), InspectionError> {
    let needed = work.checked_add(amount).ok_or(InspectionError::Overflow)?;
    if needed > limit {
        return Err(InspectionError::WorkLimit { needed, limit });
    }
    *work = needed;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        reason = "exact one-below fixtures subtract from values proved positive in the same test"
    )]

    use super::{Inspection, InspectionError, MaterializationError, inspect, size_of};
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
            .materialize_patterns(u64::MAX, usize::MAX, usize::MAX)
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
        assert!(matches!(
            proof.materialize_patterns(proof.work, usize::MAX, usize::MAX),
            Err(MaterializationError::WorkLimit { needed, limit })
                if needed == proof.work + 1 && limit == proof.work
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

        let mut dense = OrderedLiteralAggregateBuildLimits::unlimited();
        dense.max_dfa_cells = proof.dense_cells_upper_bound;
        assert!(!proof.should_use_sparse(dense));
        dense.max_dfa_cells -= 1;
        assert!(proof.should_use_sparse(dense));

        let Inspection::Eligible(unicode_proof) = inspect(&hir, true, u64::MAX).unwrap() else {
            panic!("valid UTF-8 literal root should be Unicode eligible");
        };
        assert_eq!(unicode_proof.work, 21);
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
    }
}
