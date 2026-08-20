//! Construction proof for deterministic byte bodies bounded by line anchors.
//!
//! [`crate::PortableBuilder`] considers this proof only after every established
//! native search family has declined and immediately before generic K0
//! lowering. Production admission is based only on canonical HIR structure;
//! it contains no source, size, benchmark-name, or operation-name policy.

use fre_kernels::{
    AnchoredLineCaptureAtom as Atom, AnchoredLineCaptureByteMask as ByteMask,
    ANCHORED_LINE_CAPTURE_MAX_ATOMS as MAX_ATOMS,
    LineDomainByteAtomsBuildAccounting as KernelBuildAccounting,
    LineDomainByteAtomsBuildLimits as KernelBuildLimits,
    LineDomainByteAtomsOperation as Operation, LineDomainByteAtomsPlan as KernelPlan,
    LineDomainByteAtomsSearchAccounting as SearchAccounting,
    LineDomainByteAtomsSearchError as SearchError,
    LineDomainByteAtomsSearchLimits as KernelSearchLimits, LineDomainMode as LineMode,
};
use regex_syntax::hir::{Class, Hir, HirKind, Look};
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::{Match, SearchLimits, SearchWindow};

const NODE_INSPECTION_WORK: u64 = 1;
const RANGE_INSPECTION_WORK: u64 = 1;
const MEMBER_INSERTION_WORK: u64 = 1;
const ATOM_PROOF_WORK: u64 = 1;
const BOUNDARY_PROOF_WORD_WORK: u64 = 1;
const OWNER_PUBLICATION_WORK: u64 = 1;
const MAX_MATCH_BYTES: usize = 256;

// A prospective grep envelope may outlive the regex that produced it. A
// monotone, non-wrapping generation therefore distinguishes a replacement
// owner even when the allocator reuses exactly the same address. This is not
// part of compiled-plan identity and is never consulted by ordinary search.
static NEXT_OWNER_INSTANCE: AtomicUsize = AtomicUsize::new(1);

/// Bounded planner refusal while inspecting canonical HIR.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InspectionError {
    WorkLimit { actual: u64, needed: u64, limit: u64 },
    ArithmeticOverflow,
}

/// Complete facade ownership receipt for one published boxed plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BuildAccounting {
    pub(crate) kernel: KernelBuildAccounting,
    pub(crate) cumulative_planner_work: u64,
    pub(crate) owner_allocations: usize,
    pub(crate) persistent_bytes: usize,
}

/// One large immutable owner retained behind a single facade pointer.
#[derive(Debug)]
pub(crate) struct OwnedPlan {
    kernel: KernelPlan,
    build: BuildAccounting,
    instance_identity: usize,
}

/// Compact plan-and-haystack-bound iterator capability.
///
/// Line-domain matches end at the next retained line boundary, so there is no
/// candidate block to carry across positive matches. Binding both immutable
/// inputs here still hoists facade plan dispatch out of the iterator loop and
/// prevents continuation state from being replayed with another plan or source.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SearchCursor<'plan, 'haystack> {
    plan: &'plan OwnedPlan,
    haystack: &'haystack [u8],
}

/// Optional final-fallback publication result.
#[derive(Debug)]
pub(crate) enum PublicationOutcome {
    Published(Box<OwnedPlan>),
    Declined { planner_work: u64 },
}

/// An eligible proof and exact kernel projection disagreed internally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicationError {
    ArithmeticOverflow,
    KernelInvariant,
    OwnerLayoutOverflow,
}

/// One fully checked facade-to-kernel construction handoff.
#[derive(Debug)]
pub(crate) struct Inspection {
    atoms: [Atom; MAX_ATOMS],
    atom_count: usize,
    line_mode: LineMode,
    planner_work: u64,
    projected_kernel_work: u64,
}

impl Inspection {
    /// Build and publish the large immutable owner only after all source-free
    /// work and persistent-byte gates have accepted it. Allocation failure is
    /// an optional-plan decline; layout overflow is an invariant failure.
    pub(crate) fn try_publish(
        self,
        max_planner_work: u64,
        available_persistent_bytes: usize,
    ) -> Result<PublicationOutcome, PublicationError> {
        let completed_work = self
            .planner_work
            .checked_add(self.projected_kernel_work)
            .and_then(|work| work.checked_add(OWNER_PUBLICATION_WORK))
            .ok_or(PublicationError::ArithmeticOverflow)?;
        if completed_work > max_planner_work
            || core::mem::size_of::<OwnedPlan>() > available_persistent_bytes
        {
            return Ok(PublicationOutcome::Declined {
                planner_work: self.planner_work,
            });
        }
        let kernel_limits = KernelBuildLimits {
            max_atoms: MAX_ATOMS,
            max_match_bytes: MAX_MATCH_BYTES,
            max_work: self.projected_kernel_work,
            max_persistent_bytes: core::mem::size_of::<KernelPlan>(),
        };
        let (kernel, kernel_build) = KernelPlan::new(
            self.line_mode,
            &self.atoms[..self.atom_count],
            kernel_limits,
        )
        .map_err(|_| PublicationError::KernelInvariant)?;
        if kernel_build.work != self.projected_kernel_work {
            return Err(PublicationError::KernelInvariant);
        }
        let instance_identity = NEXT_OWNER_INSTANCE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| PublicationError::ArithmeticOverflow)?;
        let build = BuildAccounting {
            kernel: kernel_build,
            cumulative_planner_work: completed_work,
            owner_allocations: 1,
            persistent_bytes: core::mem::size_of::<OwnedPlan>(),
        };
        let owner = OwnedPlan {
            kernel,
            build,
            instance_identity,
        };
        match fre_exact_alloc::try_box_preserve(owner) {
            Ok(owner) => Ok(PublicationOutcome::Published(owner)),
            Err((fre_exact_alloc::CopyError::AllocationFailed, _)) => {
                Ok(PublicationOutcome::Declined {
                    planner_work: completed_work,
                })
            }
            Err((fre_exact_alloc::CopyError::LayoutOverflow, _)) => {
                Err(PublicationError::OwnerLayoutOverflow)
            }
        }
    }
}

impl OwnedPlan {
    pub(crate) const fn build_accounting(&self) -> BuildAccounting {
        self.build
    }

    pub(crate) const fn storage_bytes(&self) -> usize {
        self.build.persistent_bytes
    }

    pub(crate) const fn search_cursor<'plan, 'haystack>(
        &'plan self,
        haystack: &'haystack [u8],
    ) -> SearchCursor<'plan, 'haystack> {
        SearchCursor {
            plan: self,
            haystack,
        }
    }

    pub(crate) const fn instance_identity(&self) -> usize {
        self.instance_identity
    }

    pub(crate) fn visit_identity_words(&self, visit: impl FnMut(u64)) {
        self.kernel.visit_identity_words(visit);
    }

    pub(crate) fn grep_full_window_upper_bounds(
        &self,
        haystack_len: usize,
    ) -> Result<fre_kernels::LineDomainByteAtomsSearchUpperBounds, SearchError> {
        self.kernel
            .search_upper_bounds(haystack_len, 0, haystack_len)
    }

    pub(crate) fn is_match_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(bool, SearchAccounting), SearchError> {
        let (matched, accounting) = self.kernel.is_match(
            haystack,
            window.start(),
            window.end(),
            kernel_search_limits(limits),
        )?;
        Ok((matched, self.complete_search_accounting(accounting)))
    }

    pub(crate) fn is_match_window_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        self.kernel.is_match_value(
            haystack,
            window.start(),
            window.end(),
            kernel_search_limits(limits),
        )
    }

    pub(crate) fn find_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
        operation: Operation,
    ) -> Result<(Option<Match>, SearchAccounting), SearchError> {
        let (matched, mut accounting) = self.kernel.find(
            haystack,
            window.start(),
            window.end(),
            kernel_search_limits(limits),
        )?;
        accounting.operation = operation;
        accounting = self.complete_search_accounting(accounting);
        Ok((
            matched.map(|span| Match {
                start: span.start(),
                end: span.end(),
            }),
            accounting,
        ))
    }

    pub(crate) fn find_window_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<Option<Match>, SearchError> {
        self.kernel
            .find_value(
                haystack,
                window.start(),
                window.end(),
                kernel_search_limits(limits),
            )
            .map(|matched| {
                matched.map(|span| Match {
                    start: span.start(),
                    end: span.end(),
                })
            })
    }

    fn complete_search_accounting(&self, mut accounting: SearchAccounting) -> SearchAccounting {
        accounting.upper_bounds.persistent_bytes = self.build.persistent_bytes;
        accounting.actual.persistent_bytes = self.build.persistent_bytes;
        accounting
    }
}

impl SearchCursor<'_, '_> {
    pub(crate) fn find_at(
        &self,
        start: usize,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, SearchAccounting), SearchError> {
        self.plan.find_window(
            self.haystack,
            SearchWindow::new(start, self.haystack.len()),
            limits,
            Operation::Iterate,
        )
    }

    pub(crate) fn find_at_value(
        &self,
        start: usize,
        limits: SearchLimits,
    ) -> Result<Option<Match>, SearchError> {
        self.plan.find_window_value(
            self.haystack,
            SearchWindow::new(start, self.haystack.len()),
            limits,
        )
    }
}

const fn kernel_search_limits(limits: SearchLimits) -> KernelSearchLimits {
    KernelSearchLimits {
        max_work: limits.max_work,
    }
}

/// Structural inspection outcome with charged work preserved on fallback.
#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "eligible inspection retains the allocation-free inline kernel handoff until publication gates pass"
)]
pub(crate) enum InspectionOutcome {
    Eligible(Inspection),
    Ineligible { planner_work: u64 },
}

/// Prove an exact line-domain byte program from canonical HIR.
///
/// The admitted root, after capture erasure, is exactly
/// `StartLF BODY EndLF` or `StartCRLF BODY EndCRLF`. The ordinary mode retains
/// the builder's configured terminator byte; CRLF mode has its fixed two-byte
/// semantics. `BODY` is a positive finite sequence of byte literals/classes
/// and greedy finite repetitions of one byte literal/class. Every atom is
/// positive, every possible consumed byte excludes the selected mode's line
/// terminators, and every variable nonterminal atom is disjoint from its
/// immediate required successor.
#[cold]
#[allow(
    clippy::too_many_lines,
    reason = "the structural proof keeps HIR admission, deterministic-boundary validation, and work projection in one auditable transaction"
)]
pub(crate) fn inspect(
    hir: &Hir,
    line_terminator: u8,
    initial_work: u64,
    max_planner_work: u64,
) -> Result<InspectionOutcome, InspectionError> {
    let mut work = initial_work;
    let root = peel_captures(hir, &mut work, max_planner_work)?;
    let HirKind::Concat(parts) = root.kind() else {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    };
    if parts.len() < 3 {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    }
    let last = parts
        .len()
        .checked_sub(1)
        .expect("a line-domain concatenation has at least three parts");
    let Some(line_mode) = matching_line_mode(
        &parts[0],
        &parts[last],
        line_terminator,
        &mut work,
        max_planner_work,
    )? else {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    };

    let mut atoms = [Atom::default(); MAX_ATOMS];
    let mut atom_count = 0_usize;
    for part in &parts[1..last] {
        if !append_body(
            part,
            &mut atoms,
            &mut atom_count,
            &mut work,
            max_planner_work,
        )? {
            return Ok(InspectionOutcome::Ineligible { planner_work: work });
        }
    }
    if atom_count == 0 {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    }

    let mut total_maximum = 0_usize;
    let mut variable_nonterminal_atoms = 0_u64;
    for index in 0..atom_count {
        charge_planner(&mut work, ATOM_PROOF_WORK, max_planner_work)?;
        let atom = atoms[index];
        let Some(maximum) = atom.maximum() else {
            return Ok(InspectionOutcome::Ineligible { planner_work: work });
        };
        if atom.minimum() == 0 || maximum < atom.minimum() || atom.mask().is_empty() {
            return Ok(InspectionOutcome::Ineligible { planner_work: work });
        }
        let Ok(maximum_usize) = usize::try_from(maximum) else {
            return Ok(InspectionOutcome::Ineligible { planner_work: work });
        };
        let Some(next_total_maximum) = total_maximum.checked_add(maximum_usize) else {
            return Ok(InspectionOutcome::Ineligible { planner_work: work });
        };
        total_maximum = next_total_maximum;
        if total_maximum > MAX_MATCH_BYTES {
            return Ok(InspectionOutcome::Ineligible { planner_work: work });
        }
        let admits_terminator = match line_mode {
            LineMode::Lf { terminator } => atom.mask().contains(terminator),
            LineMode::Crlf => atom.mask().contains(b'\r') || atom.mask().contains(b'\n'),
        };
        if admits_terminator {
            return Ok(InspectionOutcome::Ineligible { planner_work: work });
        }
        if maximum != atom.minimum() {
            let successor_index = index
                .checked_add(1)
                .expect("an atom index within the fixed array advances once");
            let Some(successor) = atoms
                .get(successor_index)
                .copied()
                .filter(|_| successor_index < atom_count)
            else {
                continue;
            };
            variable_nonterminal_atoms = variable_nonterminal_atoms
                .checked_add(1)
                .ok_or(InspectionError::ArithmeticOverflow)?;
            for (left, right) in atom.mask().words().into_iter().zip(successor.mask().words()) {
                charge_planner(
                    &mut work,
                    BOUNDARY_PROOF_WORD_WORK,
                    max_planner_work,
                )?;
                if left & right != 0 {
                    return Ok(InspectionOutcome::Ineligible { planner_work: work });
                }
            }
        }
    }

    let atom_count_work = u64::try_from(atom_count)
        .map_err(|_| InspectionError::ArithmeticOverflow)?;
    let projected_prefilter_work = KernelPlan::projected_value_prefilter_build_work(
        &atoms[..atom_count],
    )
    .map_err(|_| InspectionError::ArithmeticOverflow)?;
    let projected_kernel_work = 1_u64
        .checked_add(
            atom_count_work
                .checked_mul(2)
                .ok_or(InspectionError::ArithmeticOverflow)?,
        )
        .and_then(|work| {
            variable_nonterminal_atoms
                .checked_mul(4)
                .and_then(|boundary_work| work.checked_add(boundary_work))
        })
        .and_then(|work| work.checked_add(projected_prefilter_work))
        .ok_or(InspectionError::ArithmeticOverflow)?;

    Ok(InspectionOutcome::Eligible(Inspection {
        atoms,
        atom_count,
        line_mode,
        planner_work: work,
        projected_kernel_work,
    }))
}

fn matching_line_mode(
    start: &Hir,
    end: &Hir,
    line_terminator: u8,
    work: &mut u64,
    max_planner_work: u64,
) -> Result<Option<LineMode>, InspectionError> {
    let start = peel_captures(start, work, max_planner_work)?;
    let end = peel_captures(end, work, max_planner_work)?;
    Ok(match (start.kind(), end.kind()) {
        (HirKind::Look(Look::StartLF), HirKind::Look(Look::EndLF)) => {
            Some(LineMode::Lf {
                terminator: line_terminator,
            })
        }
        (HirKind::Look(Look::StartCRLF), HirKind::Look(Look::EndCRLF)) => {
            Some(LineMode::Crlf)
        }
        _ => None,
    })
}

fn append_body(
    hir: &Hir,
    atoms: &mut [Atom; MAX_ATOMS],
    atom_count: &mut usize,
    work: &mut u64,
    max_planner_work: u64,
) -> Result<bool, InspectionError> {
    let hir = peel_captures(hir, work, max_planner_work)?;
    match hir.kind() {
        HirKind::Concat(parts) => {
            for part in parts {
                if !append_body(part, atoms, atom_count, work, max_planner_work)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        HirKind::Literal(literal) if !literal.0.is_empty() => {
            for &byte in &literal.0 {
                charge_planner(work, MEMBER_INSERTION_WORK, max_planner_work)?;
                if !push_atom(
                    atoms,
                    atom_count,
                    Atom::new(ByteMask::singleton(byte), 1, Some(1)),
                ) {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        HirKind::Class(Class::Bytes(class)) => {
            let Some(mask) = class_mask(class.ranges(), work, max_planner_work)? else {
                return Ok(false);
            };
            Ok(push_atom(
                atoms,
                atom_count,
                Atom::new(mask, 1, Some(1)),
            ))
        }
        HirKind::Repetition(repetition) => {
            let Some(maximum) = repetition.max else {
                return Ok(false);
            };
            if repetition.min == 0 || maximum < repetition.min || !repetition.greedy {
                return Ok(false);
            }
            let body = peel_captures(&repetition.sub, work, max_planner_work)?;
            let mask = match body.kind() {
                HirKind::Literal(literal) if literal.0.len() == 1 => {
                    charge_planner(work, MEMBER_INSERTION_WORK, max_planner_work)?;
                    ByteMask::singleton(literal.0[0])
                }
                HirKind::Class(Class::Bytes(class)) => {
                    let Some(mask) = class_mask(class.ranges(), work, max_planner_work)? else {
                        return Ok(false);
                    };
                    mask
                }
                _ => return Ok(false),
            };
            Ok(push_atom(
                atoms,
                atom_count,
                Atom::new(mask, repetition.min, Some(maximum)),
            ))
        }
        _ => Ok(false),
    }
}

fn class_mask(
    ranges: &[regex_syntax::hir::ClassBytesRange],
    work: &mut u64,
    max_planner_work: u64,
) -> Result<Option<ByteMask>, InspectionError> {
    let mut mask = ByteMask::empty();
    for range in ranges {
        charge_planner(work, RANGE_INSPECTION_WORK, max_planner_work)?;
        let width = u64::from(range.end())
            .checked_sub(u64::from(range.start()))
            .and_then(|difference| difference.checked_add(1))
            .ok_or(InspectionError::ArithmeticOverflow)?;
        charge_planner(work, width, max_planner_work)?;
        mask.insert_range(range.start(), range.end())
            .map_err(|_| InspectionError::ArithmeticOverflow)?;
    }
    Ok((!mask.is_empty()).then_some(mask))
}

fn push_atom(
    atoms: &mut [Atom; MAX_ATOMS],
    atom_count: &mut usize,
    atom: Atom,
) -> bool {
    let Some(slot) = atoms.get_mut(*atom_count) else {
        return false;
    };
    *slot = atom;
    *atom_count = atom_count
        .checked_add(1)
        .expect("an available fixed atom slot advances the count once");
    true
}

fn peel_captures<'h>(
    mut hir: &'h Hir,
    work: &mut u64,
    max_planner_work: u64,
) -> Result<&'h Hir, InspectionError> {
    loop {
        charge_planner(work, NODE_INSPECTION_WORK, max_planner_work)?;
        let HirKind::Capture(capture) = hir.kind() else {
            return Ok(hir);
        };
        hir = &capture.sub;
    }
}

fn charge_planner(
    work: &mut u64,
    additional: u64,
    limit: u64,
) -> Result<(), InspectionError> {
    let needed = work
        .checked_add(additional)
        .ok_or(InspectionError::ArithmeticOverflow)?;
    if needed > limit {
        return Err(InspectionError::WorkLimit {
            actual: *work,
            needed,
            limit,
        });
    }
    *work = needed;
    Ok(())
}

#[cfg(test)]
mod tests {
    use fre_kernels::LineDomainByteAtomsSearchLimits as KernelSearchLimits;
    use regex_syntax::ParserBuilder;

    use super::{InspectionOutcome, LineMode, PublicationOutcome, inspect};
    use crate::{
        PlanKind, PlanSelection, PortableBuilder, PortableFindIterLimits, PortablePlan,
        PortableSearchSessionPlan, SearchAccounting, SearchLimits, SearchSessionLimits,
        SearchWindow,
    };

    const LF: LineMode = LineMode::Lf { terminator: b'\n' };

    fn parse_bytes(pattern: &str) -> regex_syntax::hir::Hir {
        ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(pattern)
            .unwrap()
    }

    fn plan(pattern: &str) -> Box<super::OwnedPlan> {
        let hir = parse_bytes(pattern);
        let InspectionOutcome::Eligible(inspection) =
            inspect(&hir, b'\n', 0, u64::MAX).unwrap()
        else {
            panic!("line-domain proof declined {pattern:?}");
        };
        let PublicationOutcome::Published(plan) = inspection
            .try_publish(u64::MAX, usize::MAX)
            .unwrap()
        else {
            panic!("line-domain owner publication declined {pattern:?}");
        };
        plan
    }

    fn eligible(pattern: &str) -> bool {
        matches!(
            inspect(&parse_bytes(pattern), b'\n', 0, u64::MAX).unwrap(),
            InspectionOutcome::Eligible(_)
        )
    }

    fn tuple(span: Option<fre_kernel_ir::MatchSpan>) -> Option<(usize, usize)> {
        span.map(|span| (span.start(), span.end()))
    }

    fn identity_words(plan: &super::OwnedPlan) -> Vec<u64> {
        let mut words = Vec::new();
        plan.visit_identity_words(|word| words.push(word));
        words
    }

    #[test]
    fn canonical_lf_and_crlf_forms_are_admitted_without_source_policy() {
        let lf = plan(r"(?m)^(?-u:[A-Z][a-z]{2,8})$");
        let crlf = plan(r"(?Rm)^(?-u:[A-Z][a-z]{2,8})$");
        assert_eq!(lf.kernel.line_mode(), LF);
        assert_eq!(crlf.kernel.line_mode(), LineMode::Crlf);
        assert_eq!(
            (
                lf.kernel.minimum_match_bytes(),
                lf.kernel.maximum_match_bytes()
            ),
            (3, 9)
        );
        assert_eq!(lf.kernel.maximum_match_bytes(), crlf.kernel.maximum_match_bytes());
        assert_ne!(identity_words(&lf), identity_words(&crlf));
        assert_eq!(lf.build.owner_allocations, 1);
        assert_eq!(lf.build.persistent_bytes, core::mem::size_of::<super::OwnedPlan>());
    }

    #[test]
    fn ordinary_mode_retains_the_builder_line_terminator() {
        let pattern = r"(?m)^(?-u:[A-Z][a-z]{2,8})$";
        let regex = PortableBuilder::new(pattern)
            .line_terminator(b'|')
            .build()
            .unwrap();
        assert_eq!(regex.build_report().plan, PlanKind::LineDomainByteAtoms);
        let PortablePlan::LineDomainByteAtoms(owner) = &regex.plan else {
            panic!("line-domain report and owner disagree");
        };
        assert_eq!(
            owner.kernel.line_mode(),
            LineMode::Lf { terminator: b'|' }
        );
        let haystack = b"..|Alpha|Beta\n|Gamma|";
        assert_eq!(
            regex
                .find_value(haystack, SearchLimits::unlimited())
                .unwrap()
                .map(|span| (span.start(), span.end())),
            Some((3, 8))
        );
        assert!(matches!(
            inspect(
                &parse_bytes(r"(?m)^foo\|bar$"),
                b'|',
                0,
                u64::MAX,
            )
            .unwrap(),
            InspectionOutcome::Ineligible { .. }
        ));
    }

    #[test]
    fn admission_refuses_cross_line_nullable_unbounded_and_ambiguous_bodies() {
        for pattern in [
            r"(?m)^(?-u:[^x]+)$",
            r"(?Rm)^(?-u:[^x]+)$",
            r"(?m)^(?-u:[^x]{1,8})$",
            r"(?Rm)^(?-u:[^x]{1,8})$",
            r"(?m)^(?-u:[a-z]*)$",
            r"(?m)^(?-u:[a-z]+)$",
            r"(?m)^(?-u:[a-z]{2,8}?)$",
            r"(?m)^(?-u:[a-z]{2,8}[a-z])$",
            r"(?m)^(?-u:(?:Alpha|Beta))$",
            r"\A(?-u:[A-Z][a-z]{2,8})\z",
        ] {
            assert!(!eligible(pattern), "unexpectedly admitted {pattern:?}");
        }
    }

    #[test]
    fn find_at_uses_original_haystack_assertion_context() {
        let lf = plan(r"(?m)^(?-u:[A-Z][a-z]{2,8})$");
        let haystack = b"..\nAlpha\nBeta\n";
        assert_eq!(
            tuple(
                lf.kernel
                    .find_value(
                        haystack,
                        0,
                        haystack.len(),
                        KernelSearchLimits::unlimited(),
                    )
                    .unwrap()
            ),
            Some((3, 8))
        );
        assert_eq!(
            tuple(
                lf.kernel
                    .find_value(
                        haystack,
                        4,
                        haystack.len(),
                        KernelSearchLimits::unlimited(),
                    )
                    .unwrap()
            ),
            Some((9, 13))
        );
        assert_eq!(
            tuple(
                lf.kernel
                    .find_value(haystack, 9, 12, KernelSearchLimits::unlimited())
                    .unwrap()
            ),
            None
        );
    }

    #[test]
    fn dense_iteration_is_source_ordered_for_both_line_modes() {
        for (pattern, haystack, expected) in [
            (
                r"(?m)^(?-u:[A-Z][a-z]{2,8})$",
                b"\nAlpha\nBeta\n".as_slice(),
                &[(1, 6), (7, 11)][..],
            ),
            (
                r"(?Rm)^(?-u:[A-Z][a-z]{2,8})$",
                b"\r\nBravo\r\nDelta\r\n".as_slice(),
                &[(2, 7), (9, 14)][..],
            ),
        ] {
            let plan = plan(pattern);
            let mut cursor = plan
                .kernel
                .cursor(
                    haystack,
                    0,
                    haystack.len(),
                    KernelSearchLimits::unlimited(),
                )
                .unwrap();
            let mut actual = Vec::new();
            while let Some(span) = cursor.next_match().unwrap() {
                actual.push((span.start(), span.end()));
            }
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn compact_cursor_binds_one_plan_and_immutable_haystack() {
        let words = plan(r"(?m)^(?-u:[A-Z][a-z]{2,8})$");
        let digits = plan(r"(?m)^(?-u:[0-9]{3})$");
        let source = b"Alpha\n123\n";
        let word_cursor = words.search_cursor(source);
        let digit_cursor = digits.search_cursor(source);
        assert_eq!(
            word_cursor
                .find_at_value(0, crate::SearchLimits::unlimited())
                .unwrap()
                .map(|matched| (matched.start(), matched.end())),
            Some((0, 5)),
        );
        assert_eq!(
            digit_cursor
                .find_at_value(0, crate::SearchLimits::unlimited())
                .unwrap()
                .map(|matched| (matched.start(), matched.end())),
            Some((6, 9)),
        );
        let exact_work = words
            .kernel
            .search_upper_bounds(source.len(), 0, source.len())
            .unwrap()
            .work;
        let one_below = crate::SearchLimits {
            max_work: exact_work - 1,
            max_scratch_bytes: usize::MAX,
        };
        assert!(matches!(
            word_cursor.find_at(0, one_below),
            Err(fre_kernels::LineDomainByteAtomsSearchError::WorkLimit {
                needed,
                limit,
            }) if needed == exact_work && limit == exact_work - 1
        ));
        assert!(matches!(
            word_cursor.find_at_value(0, one_below),
            Err(fre_kernels::LineDomainByteAtomsSearchError::WorkLimit {
                needed,
                limit,
            }) if needed == exact_work && limit == exact_work - 1
        ));
        assert_eq!(
            word_cursor
                .find_at(
                    0,
                    crate::SearchLimits {
                        max_work: exact_work,
                        max_scratch_bytes: usize::MAX,
                    },
                )
                .unwrap()
                .0
                .map(|matched| (matched.start(), matched.end())),
            Some((0, 5)),
        );
        assert!(
            core::mem::size_of::<super::SearchCursor<'static, 'static>>()
                <= 3 * core::mem::size_of::<usize>()
        );

        let mut reused_address = b"Alpha\n".to_vec();
        let original_address = reused_address.as_ptr();
        {
            let cursor = words.search_cursor(&reused_address);
            assert!(
                cursor
                    .find_at_value(0, crate::SearchLimits::unlimited())
                    .unwrap()
                    .is_some()
            );
        }
        reused_address.copy_from_slice(b"xxxxx\n");
        assert_eq!(reused_address.as_ptr(), original_address);
        let cursor = words.search_cursor(&reused_address);
        assert!(
            cursor
                .find_at_value(0, crate::SearchLimits::unlimited())
                .unwrap()
                .is_none(),
            "a new immutable borrow at the same address must not reuse old bytes",
        );
    }

    #[test]
    fn every_byte_and_window_matches_pinned_lf_custom_and_crlf_semantics() {
        for case in 0..3 {
            let pattern = if case == 2 {
                r"(?Rm)^(?-u:A[bc]{1,3}[0-9])$"
            } else {
                r"(?m)^(?-u:A[bc]{1,3}[0-9])$"
            };
            let mut fre_builder = PortableBuilder::new(pattern).unicode(false);
            let mut upstream_builder = regex::bytes::RegexBuilder::new(pattern);
            upstream_builder.unicode(false);
            if case == 1 {
                fre_builder = fre_builder.line_terminator(b'|');
                upstream_builder.line_terminator(b'|');
            }
            let fre = fre_builder.build().expect("line-domain differential plan");
            let upstream = upstream_builder.build().expect("pinned differential plan");
            assert_eq!(fre.build_report().plan, PlanKind::LineDomainByteAtoms);

            for byte in u8::MIN..=u8::MAX {
                let mut haystack = match case {
                    0 => b"bad\nAc".to_vec(),
                    1 => b"bad|Ac".to_vec(),
                    2 => b"bad\r\nAc".to_vec(),
                    _ => unreachable!(),
                };
                haystack.push(byte);
                match case {
                    0 => haystack.extend_from_slice(b"\nAd7\n"),
                    1 => haystack.extend_from_slice(b"|Ad7|"),
                    2 => haystack.extend_from_slice(b"\r\nAd7\rX\nAe8"),
                    _ => unreachable!(),
                }

                let upstream_spans: Vec<_> = upstream
                    .find_iter(&haystack)
                    .map(|matched| (matched.start(), matched.end()))
                    .collect();
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        let expected = upstream_spans
                            .iter()
                            .copied()
                            .find(|&(match_start, match_end)| {
                                match_start >= start && match_end <= end
                            });
                        let (actual, accounting) = fre
                            .find_window(
                                &haystack,
                                SearchWindow::new(start, end),
                                SearchLimits::unlimited(),
                            )
                            .unwrap_or_else(|error| {
                                panic!(
                                    "case={case}, byte={byte}, window={start}..{end}: {error}"
                                )
                            });
                        assert_eq!(
                            actual.map(|matched| (matched.start(), matched.end())),
                            expected,
                            "case={case}, byte={byte}, window={start}..{end}",
                        );
                        let value = fre
                            .find_window_value(
                                &haystack,
                                SearchWindow::new(start, end),
                                SearchLimits::unlimited(),
                            )
                            .unwrap_or_else(|error| {
                                panic!(
                                    "value case={case}, byte={byte}, window={start}..{end}: {error}"
                                )
                            });
                        assert_eq!(
                            value.map(|matched| (matched.start(), matched.end())),
                            expected,
                            "value case={case}, byte={byte}, window={start}..{end}",
                        );
                        let SearchAccounting::LineDomainByteAtoms(accounting) = accounting else {
                            panic!("line-domain differential search lost its accounting type");
                        };
                        assert!(accounting.upper_bounds.contains(accounting.actual));
                    }
                }
            }
        }
    }

    #[test]
    fn end_relative_value_source_matches_pinned_every_byte_and_window() {
        for case in 0..3 {
            let pattern = if case == 2 {
                r"(?Rm)^(?-u:[a-z]{1,3}X)$"
            } else {
                r"(?m)^(?-u:[a-z]{1,3}X)$"
            };
            let mut fre_builder = PortableBuilder::new(pattern).unicode(false);
            let mut upstream_builder = regex::bytes::RegexBuilder::new(pattern);
            upstream_builder.unicode(false);
            if case == 1 {
                fre_builder = fre_builder.line_terminator(b'|');
                upstream_builder.line_terminator(b'|');
            }
            let fre = fre_builder.build().expect("end-relative line-domain plan");
            let upstream = upstream_builder.build().expect("pinned end-relative plan");
            assert_eq!(fre.build_report().plan, PlanKind::LineDomainByteAtoms);

            for byte in u8::MIN..=u8::MAX {
                let mut haystack = match case {
                    0 => b"noiseXnoise\nab".to_vec(),
                    1 => b"noiseXnoise|ab".to_vec(),
                    2 => b"noiseXnoise\r\nab".to_vec(),
                    _ => unreachable!(),
                };
                haystack.push(byte);
                match case {
                    0 => haystack.extend_from_slice(b"X\nXinsideX\ncX\n"),
                    1 => haystack.extend_from_slice(b"X|XinsideX|cX|"),
                    2 => haystack.extend_from_slice(b"X\rXinsideX\ncX\r\n"),
                    _ => unreachable!(),
                }

                let upstream_spans: Vec<_> = upstream
                    .find_iter(&haystack)
                    .map(|matched| (matched.start(), matched.end()))
                    .collect();
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        let expected = upstream_spans
                            .iter()
                            .copied()
                            .find(|&(match_start, match_end)| {
                                match_start >= start && match_end <= end
                            });
                        let actual = fre
                            .find_window_value(
                                &haystack,
                                SearchWindow::new(start, end),
                                SearchLimits::unlimited(),
                            )
                            .unwrap_or_else(|error| {
                                panic!(
                                    "end value case={case}, byte={byte}, window={start}..{end}: {error}"
                                )
                            });
                        assert_eq!(
                            actual.map(|matched| (matched.start(), matched.end())),
                            expected,
                            "end value case={case}, byte={byte}, window={start}..{end}",
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn auto_routing_is_final_before_k0_and_forced_k0_stays_forced() {
        let pattern = r"(?m)^(?-u:[A-Z][a-z]{2,8})$";
        let regex = PortableBuilder::new(pattern).build().unwrap();
        assert_eq!(regex.build_report().plan, PlanKind::LineDomainByteAtoms);
        assert_eq!(regex.build_report().lowering, None);
        let PortablePlan::LineDomainByteAtoms(owner) = &regex.plan else {
            panic!("line-domain report and owner disagree");
        };
        assert_eq!(
            regex.build_report().plan_storage_bytes,
            core::mem::size_of::<super::OwnedPlan>()
        );
        assert_eq!(owner.build_accounting().owner_allocations, 1);

        let forced = PortableBuilder::new(pattern)
            .plan_selection(PlanSelection::ForceK0)
            .build()
            .unwrap();
        assert_eq!(forced.build_report().plan, PlanKind::K0);
        assert!(matches!(forced.plan, PortablePlan::K0(_)));

        // An established earlier specialization remains earlier in the
        // builder even though the final fallback proof is now available.
        let literal = PortableBuilder::new("Alpha").build().unwrap();
        assert_eq!(literal.build_report().plan, PlanKind::ExactLiteral);
    }

    #[test]
    fn facade_operations_and_native_session_share_exact_window_semantics() {
        let regex = PortableBuilder::new(r"(?Rm)^(?-u:[A-Z][a-z]{2,8})$")
            .build()
            .unwrap();
        let haystack = b"..\r\nBravo\r\nbad\rDelta\nEcho";
        let (matched, accounting) = regex
            .find_accounted(haystack, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(matched.map(|span| (span.start(), span.end())), Some((4, 9)));
        let SearchAccounting::LineDomainByteAtoms(accounting) = accounting else {
            panic!("line-domain result lost its accounting type");
        };
        assert_eq!(
            accounting.upper_bounds.persistent_bytes,
            core::mem::size_of::<super::OwnedPlan>()
        );
        assert_eq!(
            accounting.actual.persistent_bytes,
            core::mem::size_of::<super::OwnedPlan>()
        );
        assert_eq!(
            regex
                .find_at_value(haystack, 5, SearchLimits::unlimited())
                .unwrap()
                .map(|span| (span.start(), span.end())),
            Some((15, 20))
        );
        assert!(
            regex
                .is_match_at(haystack, 5, SearchLimits::unlimited())
                .unwrap()
                .0
        );

        let session = regex
            .search_session(SearchSessionLimits::unlimited())
            .unwrap();
        assert!(matches!(
            session.plan,
            PortableSearchSessionPlan::Native(_)
        ));
        assert!(matches!(
            regex.native_search_cursor(haystack),
            Some(crate::PortableNativeSearchCursor::LineDomainByteAtoms(_))
        ));
        let spans: Vec<_> = regex
            .find_iter(haystack, PortableFindIterLimits::unlimited())
            .unwrap()
            .map(|matched| {
                let matched = matched.unwrap();
                (matched.start(), matched.end())
            })
            .collect();
        assert_eq!(spans, [(4, 9), (15, 20), (21, 25)]);
    }

    #[test]
    fn boxed_owner_does_not_set_the_facade_or_session_layout() {
        assert_eq!(
            core::mem::size_of::<Box<super::OwnedPlan>>(),
            core::mem::size_of::<usize>()
        );
        assert!(
            core::mem::size_of::<super::OwnedPlan>()
                > core::mem::size_of::<Box<super::OwnedPlan>>()
        );
        assert!(
            core::mem::size_of::<PortablePlan>()
                <= core::mem::size_of::<crate::PortableK0Plan>()
                    .saturating_add(core::mem::align_of::<crate::PortableK0Plan>()),
            "a pointer-sized line-domain variant must leave PortablePlan K0-led",
        );
    }
}
