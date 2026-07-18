use std::collections::VecDeque;

use fre_exact_alloc::{CopyError, ExactVec};
use regex_syntax::hir::{Class, Hir, HirKind, Repetition};
use regex_syntax::utf8::Utf8Sequences;

use crate::accounting::CompileAccounting;
use crate::error::{add, enforce, mul};
use crate::program::{Assertion, ByteSet, Inst, NO_SPLIT_RANK, Program, ScalarSet};
use crate::required_internal_anchor;
use crate::{CompileLimits, Error, Resource, Unsupported};

/// Explicit semantic profile asserted by direct HIR callers.
///
/// HIR intentionally does not retain every parser option. In particular, an
/// empty HIR cannot reveal whether Unicode mode was enabled. Passing this
/// token asserts both the pinned parser configuration and the empty-match
/// boundary policy. Unicode-on callers receive literals, byte classes, Unicode
/// scalar classes retained as bounded scalar-consuming transitions, every pinned look
/// assertion, and their regular composition.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RustByteProfile {
    unicode: bool,
}

impl RustByteProfile {
    /// Pinned Unicode-off production profile for regex 1.12.4 /
    /// regex-syntax 0.8.11 with byte-boundary empty matches.
    pub const PINNED_1_12_4: Self = Self { unicode: false };

    /// Pinned Unicode-on Rust-bytes profile with `utf8(false)` and
    /// `utf8_empty(false)`, with scalar classes matched at canonical UTF-8 boundaries.
    /// Positive Unicode word boundaries additionally require valid UTF-8 at
    /// operation admission.
    pub const PINNED_1_12_4_UNICODE_ON_BYTE_STABLE: Self = Self { unicode: true };

    const fn identity_domain(self) -> &'static [u8] {
        if self.unicode {
            b"fre.aggregate.rust.bytes.unicode-on-utf8-scalar.v2"
        } else {
            // Preserve the pre-existing Unicode-off identities exactly.
            b"fre.aggregate.rust.bytes.unicode-off.v2"
        }
    }
}

/// Stable identity of the semantic continuation program.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PlanId(pub(crate) [u8; 16]);

impl PlanId {
    #[must_use]
    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }
}

impl core::fmt::Display for PlanId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Validated capture-free continuation program.
#[derive(Debug)]
pub struct CompiledRegex {
    pub(crate) program: Program,
    pub(crate) required_suffixes: RequiredSuffixes,
    pub(crate) required_internal_anchor: Option<fre_kernels::RequiredInternalAnchorPlan>,
    pub(crate) terminal_frontier: TerminalFrontierSeed,
    plan_id: PlanId,
    accounting: CompileAccounting,
}

/// A small construction-proved set: every match ends with one of these
/// nonempty byte strings. It is only an execution hint; an ineligible HIR
/// retains the dense continuation route.
#[derive(Debug)]
pub(crate) struct RequiredSuffixes {
    bytes: ExactVec<u8>,
    ends: ExactVec<usize>,
}

impl Default for RequiredSuffixes {
    fn default() -> Self {
        Self {
            bytes: ExactVec::try_with_capacity(0).expect("u8 has a valid empty exact allocation"),
            ends: ExactVec::try_with_capacity(0).expect("usize has a valid empty exact allocation"),
        }
    }
}

impl RequiredSuffixes {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &[u8]> {
        let mut start = 0_usize;
        self.ends.iter().map(move |&end| {
            let suffix = &self.bytes[start..end];
            start = end;
            suffix
        })
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.ends.is_empty()
    }

    fn retained_bytes(&self) -> Result<usize, Error> {
        add(
            self.bytes.len(),
            mul(
                self.ends.len(),
                core::mem::size_of::<usize>(),
                Resource::ProgramBytes,
            )?,
            Resource::ProgramBytes,
        )
    }
}

const MAX_TERMINAL_FRONTIER_PREFIX_BYTES: usize = 32;
const MIN_TERMINAL_FRONTIER_PREFIX_BYTES: usize = 2;

/// Construction-proved hints for the unbounded terminal-frontier route.
///
/// Every admitted match starts with `prefix` and ends immediately after one
/// byte in `terminals`. Both facts come from the same canonical HIR used to
/// build the continuation program. Fixed inline storage makes the proof
/// immutable without introducing a second allocation or allocator-dependent
/// capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TerminalFrontierSeed {
    prefix: [u8; MAX_TERMINAL_FRONTIER_PREFIX_BYTES],
    prefix_len: usize,
    terminals: TerminalByteSet,
}

impl TerminalFrontierSeed {
    const fn empty() -> Self {
        Self {
            prefix: [0; MAX_TERMINAL_FRONTIER_PREFIX_BYTES],
            prefix_len: 0,
            terminals: TerminalByteSet::empty(),
        }
    }

    pub(crate) const fn is_empty(self) -> bool {
        self.prefix_len == 0 || self.terminals.len == 0
    }

    pub(crate) fn prefix_bytes(&self) -> &[u8] {
        &self.prefix[..self.prefix_len]
    }

    pub(crate) const fn prefix_len(self) -> usize {
        self.prefix_len
    }

    pub(crate) fn terminal_bytes(self) -> impl Iterator<Item = u8> {
        self.terminals.iter()
    }

    #[cfg(test)]
    pub(crate) fn terminal_matches(self, byte: u8) -> bool {
        self.terminal_bytes().any(|terminal| terminal == byte)
    }

    #[cfg(test)]
    pub(crate) const fn terminal_count(self) -> usize {
        self.terminals.len
    }

    const fn retained_bytes() -> usize {
        // The certificate is retained inline in every compiled artifact. Its
        // complete fixed representation, including an empty/ineligible seed,
        // is therefore persistent program storage. Logical prefix/terminal
        // lengths must not under-report the zero-filled arrays or metadata.
        core::mem::size_of::<Self>()
    }
}

impl CompiledRegex {
    /// Compile canonical HIR for the explicit pinned byte profile.
    ///
    /// Validation first proves a depth bound. Lowering recursion is therefore
    /// bounded by `limits.max_hir_depth`; repetition expansion itself is
    /// iterative and separately limited.
    pub fn from_hir(
        hir: &Hir,
        profile: RustByteProfile,
        limits: CompileLimits,
    ) -> Result<Self, Error> {
        Self::compile(hir, profile, limits, CapturePolicy::Reject)
    }

    /// Compile canonical HIR for an API that exposes whole-match values only.
    ///
    /// Capture annotations are semantically transparent for whole-match spans,
    /// counts and matched-byte sums. This entry point handles them directly in
    /// the already bounded validation and lowering traversals: it neither
    /// clones the HIR nor allocates a capture-free copy. The exact number of
    /// annotations and transparent traversal steps is reported in
    /// [`CompileAccounting`]. Callers must not use this plan to implement a
    /// capture group API.
    pub fn from_hir_erasing_captures_for_whole_match(
        hir: &Hir,
        profile: RustByteProfile,
        limits: CompileLimits,
    ) -> Result<Self, Error> {
        Self::compile(hir, profile, limits, CapturePolicy::EraseForWholeMatch)
    }

    fn compile(
        hir: &Hir,
        profile: RustByteProfile,
        limits: CompileLimits,
        capture_policy: CapturePolicy,
    ) -> Result<Self, Error> {
        let mut budget = CompileBudget::new(limits);
        validate_hir(hir, profile, capture_policy, &mut budget)?;
        let (
            required_suffixes,
            required_internal_anchor,
            terminal_frontier,
            retained_program_bytes,
        ) = build_retained_components(hir, profile, limits, &mut budget)?;
        let mut builder = Builder::new(
            limits.max_program_states,
            profile,
            capture_policy,
            retained_program_bytes,
            &mut budget,
        );
        let accept = builder.push(Inst::Match)?;
        let entry = builder.compile_node(hir, accept, 1)?;
        let scalar_range_bytes = builder.scalar_range_bytes;
        let insts = builder.finish()?;
        enforce(
            insts.len(),
            limits.max_program_states,
            Resource::ProgramStates,
        )?;
        let certificate = certify_program(
            &insts,
            scalar_range_bytes,
            retained_program_bytes,
            &mut budget,
        )?;
        // `program_bytes` visits every instruction to include each deeply
        // owned scalar-range box in the exact retained-byte total.
        budget.charge(insts.len())?;
        let program_bytes = add(
            program_bytes(
                &insts,
                insts.len(),
                certificate.epsilon_order.len(),
                certificate.split_rank.len(),
            )?,
            retained_program_bytes,
            Resource::ProgramBytes,
        )?;
        enforce(
            program_bytes,
            limits.max_program_bytes,
            Resource::ProgramBytes,
        )?;
        budget.accounting.program_states = insts.len();
        budget.accounting.program_bytes = program_bytes;
        budget.accounting.execution_state_work = certificate.execution_state_work;
        budget.accounting.predecessor_edges = certificate.predecessor_edges;
        budget.accounting.has_scalar_transitions = certificate.has_scalar_transition;
        budget.accounting.max_scalar_search_checks = certificate.max_scalar_search_checks;
        let mut program = Program {
            insts,
            entry,
            epsilon_order: certificate.epsilon_order,
            split_rank: certificate.split_rank,
            split_count: certificate.split_count,
            execution_state_work: certificate.execution_state_work,
            predecessor_edges: certificate.predecessor_edges,
            has_scalar_transition: certificate.has_scalar_transition,
            max_scalar_search_checks: certificate.max_scalar_search_checks,
            has_unicode_word_boundary: false,
        };
        let mut plan_id = finalize_program(&mut program, profile, terminal_frontier, &mut budget)?;
        if let Some(plan) = &required_internal_anchor {
            plan_id = bind_required_internal_anchor_identity(plan_id, plan, &mut budget)?;
        }
        if budget.current_construction_bytes != program_bytes {
            return Err(Error::InternalInvariant(
                "compiler retained bytes differ from construction accounting",
            ));
        }
        let accounting = budget.finish();
        Ok(Self {
            program,
            required_suffixes,
            required_internal_anchor,
            terminal_frontier,
            plan_id,
            accounting,
        })
    }

    #[must_use]
    pub const fn plan_id(&self) -> PlanId {
        self.plan_id
    }

    #[must_use]
    pub const fn compile_accounting(&self) -> CompileAccounting {
        self.accounting
    }

    #[must_use]
    pub fn state_count(&self) -> usize {
        self.program.insts.len()
    }
}

fn build_retained_components(
    hir: &Hir,
    profile: RustByteProfile,
    limits: CompileLimits,
    budget: &mut CompileBudget,
) -> Result<
    (
        RequiredSuffixes,
        Option<fre_kernels::RequiredInternalAnchorPlan>,
        TerminalFrontierSeed,
        usize,
    ),
    Error,
> {
    let (required_suffixes, terminal_frontier) = execution_seeds(hir, profile, budget)?;
    budget.accounting.required_suffixes = required_suffixes.ends.len();
    budget.accounting.required_suffix_bytes = required_suffixes.bytes.len();
    budget.accounting.terminal_frontier_prefix_bytes = terminal_frontier.prefix_len;
    budget.accounting.terminal_frontier_bytes = terminal_frontier.terminals.len;
    let seed_program_bytes = add(
        required_suffixes.retained_bytes()?,
        TerminalFrontierSeed::retained_bytes(),
        Resource::ProgramBytes,
    )?;
    budget.acquire_construction_bytes(seed_program_bytes)?;
    enforce(
        budget.current_construction_bytes,
        limits.max_program_bytes,
        Resource::ProgramBytes,
    )?;
    let required_internal_anchor = if profile.unicode {
        None
    } else {
        let remaining_work = limits.max_work.checked_sub(budget.accounting.work).ok_or(
            Error::ArithmeticOverflow {
                resource: Resource::CompileWork,
            },
        )?;
        let remaining_program_bytes = limits
            .max_program_bytes
            .checked_sub(budget.current_construction_bytes)
            .ok_or(Error::ArithmeticOverflow {
                resource: Resource::ProgramBytes,
            })?;
        let inspection = required_internal_anchor::inspect(
            hir,
            remaining_work,
            limits.max_literal_bytes,
            remaining_program_bytes,
        )?;
        retain_required_internal_anchor(inspection, budget)?
    };
    let required_internal_anchor_program_bytes = required_internal_anchor
        .as_ref()
        .map_or(0, |plan| plan.build_accounting().persistent_bytes);
    let retained_program_bytes = add(
        seed_program_bytes,
        required_internal_anchor_program_bytes,
        Resource::ProgramBytes,
    )?;
    enforce(
        retained_program_bytes,
        limits.max_program_bytes,
        Resource::ProgramBytes,
    )?;
    Ok((
        required_suffixes,
        required_internal_anchor,
        terminal_frontier,
        retained_program_bytes,
    ))
}

fn retain_required_internal_anchor(
    inspection: required_internal_anchor::Inspection,
    budget: &mut CompileBudget,
) -> Result<Option<fre_kernels::RequiredInternalAnchorPlan>, Error> {
    budget.charge(inspection.inspection_work)?;
    let Some(plan) = inspection.plan else {
        return Ok(None);
    };
    let build = plan.build_accounting();
    budget.acquire_construction_bytes(build.persistent_bytes)?;
    budget.accounting.required_internal_anchors = 1;
    budget.accounting.required_internal_anchor_bytes = build.anchor_bytes;
    budget.accounting.required_internal_anchor_optional_stages = build.optional_stages;
    budget.accounting.required_internal_anchor_build_work = build.observed_structural_work;
    budget
        .accounting
        .required_internal_anchor_build_work_upper_bound = build.work_upper_bound;
    budget.accounting.required_internal_anchor_persistent_bytes = build.persistent_bytes;
    Ok(Some(plan))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CapturePolicy {
    Reject,
    EraseForWholeMatch,
}

struct CompileBudget {
    limits: CompileLimits,
    accounting: CompileAccounting,
    current_temporary_states: usize,
    current_construction_bytes: usize,
}

impl CompileBudget {
    const fn new(limits: CompileLimits) -> Self {
        Self {
            limits,
            accounting: CompileAccounting {
                hir_nodes: 0,
                hir_depth: 0,
                peak_hir_stack_items: 0,
                captures_erased: 0,
                capture_erasure_work: 0,
                literal_bytes: 0,
                class_ranges: 0,
                utf8_sequences: 0,
                utf8_byte_ranges: 0,
                look_assertions: 0,
                required_suffixes: 0,
                required_suffix_bytes: 0,
                required_internal_anchors: 0,
                required_internal_anchor_bytes: 0,
                required_internal_anchor_optional_stages: 0,
                required_internal_anchor_build_work: 0,
                required_internal_anchor_build_work_upper_bound: 0,
                required_internal_anchor_persistent_bytes: 0,
                terminal_frontier_prefix_bytes: 0,
                terminal_frontier_bytes: 0,
                program_states: 0,
                temporary_states_peak: 0,
                program_bytes: 0,
                construction_peak_bytes: 0,
                execution_state_work: 0,
                predecessor_edges: 0,
                has_scalar_transitions: false,
                max_scalar_search_checks: 0,
                unicode_word_boundary_checks: 0,
                requires_utf8_validation: false,
                work: 0,
            },
            current_temporary_states: 0,
            current_construction_bytes: 0,
        }
    }

    fn charge(&mut self, amount: usize) -> Result<(), Error> {
        let required = add(self.accounting.work, amount, Resource::CompileWork)?;
        enforce(required, self.limits.max_work, Resource::CompileWork)?;
        self.accounting.work = required;
        Ok(())
    }

    fn acquire_construction_bytes(&mut self, amount: usize) -> Result<(), Error> {
        self.current_construction_bytes = add(
            self.current_construction_bytes,
            amount,
            Resource::ProgramBytes,
        )?;
        self.accounting.construction_peak_bytes = self
            .accounting
            .construction_peak_bytes
            .max(self.current_construction_bytes);
        Ok(())
    }

    fn release_construction_bytes(&mut self, amount: usize) -> Result<(), Error> {
        self.current_construction_bytes = self
            .current_construction_bytes
            .checked_sub(amount)
            .ok_or(Error::InternalInvariant(
                "compiler construction-byte accounting underflow",
            ))?;
        Ok(())
    }

    fn acquire_state(&mut self) -> Result<(), Error> {
        let current = add(self.current_temporary_states, 1, Resource::TemporaryStates)?;
        enforce(
            current,
            self.limits.max_temporary_states,
            Resource::TemporaryStates,
        )?;
        self.charge(1)?;
        self.current_temporary_states = current;
        self.accounting.temporary_states_peak = self.accounting.temporary_states_peak.max(current);
        Ok(())
    }

    fn release_states(&mut self, count: usize) -> Result<(), Error> {
        self.current_temporary_states =
            self.current_temporary_states
                .checked_sub(count)
                .ok_or(Error::InternalInvariant(
                    "temporary state accounting underflow",
                ))?;
        Ok(())
    }

    fn record_capture_erasure(&mut self, unique_annotation: bool) -> Result<(), Error> {
        self.accounting.capture_erasure_work = add(
            self.accounting.capture_erasure_work,
            1,
            Resource::CompileWork,
        )?;
        if unique_annotation {
            self.accounting.captures_erased =
                add(self.accounting.captures_erased, 1, Resource::HirNodes)?;
        }
        Ok(())
    }

    fn record_look_assertion(&mut self) -> Result<(), Error> {
        self.accounting.look_assertions =
            add(self.accounting.look_assertions, 1, Resource::LookAssertions)?;
        enforce(
            self.accounting.look_assertions,
            self.limits.max_look_assertions,
            Resource::LookAssertions,
        )
    }

    fn finish(self) -> CompileAccounting {
        self.accounting
    }
}

const MAX_REQUIRED_SUFFIXES: usize = 8;
const MAX_REQUIRED_SUFFIX_BYTES: usize = 4_096;

#[derive(Clone, Copy)]
struct SuffixSet<'a> {
    literals: [Option<&'a [u8]>; MAX_REQUIRED_SUFFIXES],
    len: usize,
    bytes: usize,
}

impl<'a> SuffixSet<'a> {
    const fn empty() -> Self {
        Self {
            literals: [None; MAX_REQUIRED_SUFFIXES],
            len: 0,
            bytes: 0,
        }
    }

    fn insert(&mut self, literal: &'a [u8], budget: &mut CompileBudget) -> Result<bool, Error> {
        if literal.is_empty() || literal.len() > MAX_REQUIRED_SUFFIX_BYTES {
            return Ok(false);
        }
        for existing in self.literals[..self.len].iter().flatten().copied() {
            // Preflight the length check and worst-case shared byte prefix
            // before slice equality can perform either.
            let comparison_work = add(existing.len().min(literal.len()), 1, Resource::CompileWork)?;
            budget.charge(comparison_work)?;
            if existing == literal {
                return Ok(true);
            }
        }
        if self.len == MAX_REQUIRED_SUFFIXES {
            return Ok(false);
        }
        let Some(bytes) = self.bytes.checked_add(literal.len()) else {
            return Ok(false);
        };
        if bytes > MAX_REQUIRED_SUFFIX_BYTES {
            return Ok(false);
        }
        self.literals[self.len] = Some(literal);
        self.len = self.len.saturating_add(1);
        self.bytes = bytes;
        Ok(true)
    }

    fn iter(&self) -> impl Iterator<Item = &'a [u8]> + '_ {
        self.literals[..self.len].iter().flatten().copied()
    }
}

#[derive(Clone, Copy)]
enum SuffixAnalysis<'a> {
    /// This HIR consumes no bytes, so a containing concatenation must continue
    /// looking to its left.
    ZeroWidth,
    /// No bounded nonempty suffix theorem was proved.
    None,
    Literals(SuffixSet<'a>),
    /// Every match ends in one member of this small canonical byte class.
    TerminalBytes(TerminalByteSet),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TerminalByteSet {
    bytes: [u8; MAX_REQUIRED_SUFFIXES],
    len: usize,
}

impl TerminalByteSet {
    const fn empty() -> Self {
        Self {
            bytes: [0; MAX_REQUIRED_SUFFIXES],
            len: 0,
        }
    }

    fn iter(self) -> impl Iterator<Item = u8> {
        self.bytes.into_iter().take(self.len)
    }
}

fn execution_seeds(
    hir: &Hir,
    profile: RustByteProfile,
    budget: &mut CompileBudget,
) -> Result<(RequiredSuffixes, TerminalFrontierSeed), Error> {
    let analysis = analyze_required_suffixes(hir, budget)?;
    let terminal_frontier = terminal_frontier_seed(hir, profile, &analysis, budget)?;
    let required_suffixes = materialize_required_suffixes(hir, analysis, budget)?;
    Ok((required_suffixes, terminal_frontier))
}

#[cfg(test)]
fn required_suffixes(hir: &Hir, budget: &mut CompileBudget) -> Result<RequiredSuffixes, Error> {
    let analysis = analyze_required_suffixes(hir, budget)?;
    materialize_required_suffixes(hir, analysis, budget)
}

fn materialize_required_suffixes(
    hir: &Hir,
    analysis: SuffixAnalysis<'_>,
    budget: &mut CompileBudget,
) -> Result<RequiredSuffixes, Error> {
    if matches!(&analysis, SuffixAnalysis::TerminalBytes(_)) {
        // A byte-class endpoint can occur far more often than a multi-byte
        // literal. Retain it only when the authenticated HIR proves a finite
        // predecessor window; sparse execution then naturally clears live
        // rows outside that window.
        budget.charge(1)?;
        if hir.properties().maximum_len().is_none() {
            return Ok(RequiredSuffixes::default());
        }
    }
    let (suffix_count, suffix_bytes) = match &analysis {
        SuffixAnalysis::Literals(literals) => (literals.len, literals.bytes),
        SuffixAnalysis::TerminalBytes(terminals) => (terminals.len, terminals.len),
        SuffixAnalysis::ZeroWidth | SuffixAnalysis::None => {
            return Ok(RequiredSuffixes::default());
        }
    };
    if suffix_count == 0 {
        return Ok(RequiredSuffixes::default());
    }
    let requested_program_bytes = add(
        suffix_bytes,
        mul(
            suffix_count,
            core::mem::size_of::<usize>(),
            Resource::ProgramBytes,
        )?,
        Resource::ProgramBytes,
    )?;
    enforce(
        requested_program_bytes,
        budget.limits.max_program_bytes,
        Resource::ProgramBytes,
    )?;
    // Preflight every retained endpoint and byte before allocation or copy.
    budget.charge(add(suffix_count, suffix_bytes, Resource::CompileWork)?)?;
    let mut bytes = exact_program_vec(suffix_bytes)?;
    let mut ends = exact_program_vec(suffix_count)?;
    match analysis {
        SuffixAnalysis::Literals(literals) => {
            for literal in literals.iter() {
                for &byte in literal {
                    bytes.try_push(byte).map_err(|_| {
                        Error::InternalInvariant("required suffix exceeded exact byte allocation")
                    })?;
                }
                ends.try_push(bytes.len()).map_err(|_| {
                    Error::InternalInvariant("required suffix exceeded exact endpoint allocation")
                })?;
            }
        }
        SuffixAnalysis::TerminalBytes(terminals) => {
            for byte in terminals.iter() {
                bytes.try_push(byte).map_err(|_| {
                    Error::InternalInvariant("required suffix exceeded exact byte allocation")
                })?;
                ends.try_push(bytes.len()).map_err(|_| {
                    Error::InternalInvariant("required suffix exceeded exact endpoint allocation")
                })?;
            }
        }
        SuffixAnalysis::ZeroWidth | SuffixAnalysis::None => {
            return Err(Error::InternalInvariant(
                "ineligible required suffix reached materialization",
            ));
        }
    }
    Ok(RequiredSuffixes { bytes, ends })
}

#[derive(Clone, Copy)]
enum LeadingLiteral<'a> {
    ZeroWidth,
    Literal(&'a [u8]),
    None,
}

fn terminal_frontier_seed(
    hir: &Hir,
    profile: RustByteProfile,
    suffix: &SuffixAnalysis<'_>,
    budget: &mut CompileBudget,
) -> Result<TerminalFrontierSeed, Error> {
    budget.charge(1)?;
    let properties = hir.properties();
    if profile.unicode
        || properties.maximum_len().is_some()
        || properties.minimum_len().is_none_or(|minimum| minimum == 0)
    {
        return Ok(TerminalFrontierSeed::empty());
    }
    let SuffixAnalysis::TerminalBytes(terminals) = suffix else {
        return Ok(TerminalFrontierSeed::empty());
    };
    if terminals.len < 2 || !ends_in_byte_class(hir, budget)? {
        return Ok(TerminalFrontierSeed::empty());
    }
    let LeadingLiteral::Literal(prefix) = analyze_leading_literal(hir, budget)? else {
        return Ok(TerminalFrontierSeed::empty());
    };
    if !(MIN_TERMINAL_FRONTIER_PREFIX_BYTES..=MAX_TERMINAL_FRONTIER_PREFIX_BYTES)
        .contains(&prefix.len())
    {
        return Ok(TerminalFrontierSeed::empty());
    }
    // Charge the complete inline initialization and both logical copies before
    // publishing the certificate. The fixed arrays add no heap allocation;
    // `program_bytes` below reports the complete fixed inline proof object.
    let initialization = add(
        MAX_TERMINAL_FRONTIER_PREFIX_BYTES,
        MAX_REQUIRED_SUFFIXES,
        Resource::CompileWork,
    )?;
    budget.charge(add(
        initialization,
        add(prefix.len(), terminals.len, Resource::CompileWork)?,
        Resource::CompileWork,
    )?)?;
    let mut retained = [0_u8; MAX_TERMINAL_FRONTIER_PREFIX_BYTES];
    retained[..prefix.len()].copy_from_slice(prefix);
    Ok(TerminalFrontierSeed {
        prefix: retained,
        prefix_len: prefix.len(),
        terminals: *terminals,
    })
}

fn ends_in_byte_class(mut hir: &Hir, budget: &mut CompileBudget) -> Result<bool, Error> {
    loop {
        budget.charge(1)?;
        match hir.kind() {
            HirKind::Capture(capture) => hir = &capture.sub,
            HirKind::Concat(parts) => {
                let mut last_consuming = None;
                for part in parts.iter().rev() {
                    budget.charge(1)?;
                    if part
                        .properties()
                        .minimum_len()
                        .is_some_and(|length| length > 0)
                    {
                        last_consuming = Some(part);
                        break;
                    }
                }
                let Some(last_consuming) = last_consuming else {
                    return Ok(false);
                };
                hir = last_consuming;
            }
            HirKind::Class(Class::Bytes(_)) => return Ok(true),
            _ => return Ok(false),
        }
    }
}

fn analyze_leading_literal<'a>(
    hir: &'a Hir,
    budget: &mut CompileBudget,
) -> Result<LeadingLiteral<'a>, Error> {
    budget.charge(1)?;
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => Ok(LeadingLiteral::ZeroWidth),
        HirKind::Literal(regex_syntax::hir::Literal(bytes)) => {
            if bytes.is_empty() {
                Ok(LeadingLiteral::ZeroWidth)
            } else {
                Ok(LeadingLiteral::Literal(bytes))
            }
        }
        HirKind::Capture(capture) => analyze_leading_literal(&capture.sub, budget),
        HirKind::Repetition(repetition) => {
            if repetition.min == 0 {
                Ok(LeadingLiteral::None)
            } else {
                analyze_leading_literal(&repetition.sub, budget)
            }
        }
        HirKind::Concat(parts) => {
            for part in parts {
                match analyze_leading_literal(part, budget)? {
                    LeadingLiteral::ZeroWidth => {}
                    leading => return Ok(leading),
                }
            }
            Ok(LeadingLiteral::ZeroWidth)
        }
        HirKind::Alternation(branches) => common_leading_literal(branches, budget),
        HirKind::Class(_) => Ok(LeadingLiteral::None),
    }
}

fn common_leading_literal<'a>(
    branches: &'a [Hir],
    budget: &mut CompileBudget,
) -> Result<LeadingLiteral<'a>, Error> {
    let mut common = None;
    for branch in branches {
        budget.charge(1)?;
        let LeadingLiteral::Literal(candidate) = analyze_leading_literal(branch, budget)? else {
            return Ok(LeadingLiteral::None);
        };
        let Some(expected) = common else {
            common = Some(candidate);
            continue;
        };
        budget.charge(add(
            expected.len().min(candidate.len()),
            1,
            Resource::CompileWork,
        )?)?;
        let shared_limit = expected.len().min(candidate.len());
        let mut shared = 0_usize;
        while shared < shared_limit && expected[shared] == candidate[shared] {
            shared = shared.saturating_add(1);
        }
        if shared == 0 {
            return Ok(LeadingLiteral::None);
        }
        common = Some(&expected[..shared]);
    }
    Ok(common.map_or(LeadingLiteral::None, LeadingLiteral::Literal))
}

fn analyze_required_suffixes<'a>(
    hir: &'a Hir,
    budget: &mut CompileBudget,
) -> Result<SuffixAnalysis<'a>, Error> {
    budget.charge(1)?;
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => Ok(SuffixAnalysis::ZeroWidth),
        HirKind::Literal(regex_syntax::hir::Literal(bytes)) => {
            if bytes.is_empty() {
                Ok(SuffixAnalysis::ZeroWidth)
            } else {
                let mut suffixes = SuffixSet::empty();
                if suffixes.insert(bytes, budget)? {
                    Ok(SuffixAnalysis::Literals(suffixes))
                } else {
                    Ok(SuffixAnalysis::None)
                }
            }
        }
        HirKind::Class(Class::Bytes(class)) => {
            let mut terminals = TerminalByteSet::empty();
            for range in class.ranges() {
                let width = inclusive_byte_width(range.start(), range.end())?;
                budget.charge(add(width, 1, Resource::CompileWork)?)?;
                let Some(next_len) = terminals.len.checked_add(width) else {
                    return Ok(SuffixAnalysis::None);
                };
                if next_len > MAX_REQUIRED_SUFFIXES {
                    return Ok(SuffixAnalysis::None);
                }
                for byte in range.start()..=range.end() {
                    terminals.bytes[terminals.len] = byte;
                    terminals.len = terminals.len.saturating_add(1);
                }
            }
            if terminals.len == 0 {
                Ok(SuffixAnalysis::None)
            } else {
                Ok(SuffixAnalysis::TerminalBytes(terminals))
            }
        }
        HirKind::Class(Class::Unicode(_)) => Ok(SuffixAnalysis::None),
        HirKind::Capture(capture) => analyze_required_suffixes(&capture.sub, budget),
        HirKind::Repetition(repetition) => {
            if repetition.min == 0 {
                Ok(SuffixAnalysis::None)
            } else {
                analyze_required_suffixes(&repetition.sub, budget)
            }
        }
        HirKind::Concat(parts) => {
            for part in parts.iter().rev() {
                match analyze_required_suffixes(part, budget)? {
                    SuffixAnalysis::ZeroWidth => {}
                    other => return Ok(other),
                }
            }
            Ok(SuffixAnalysis::ZeroWidth)
        }
        HirKind::Alternation(branches) => {
            let mut combined = SuffixSet::empty();
            for branch in branches {
                // Branch selection is separate from the recursive node visit.
                budget.charge(1)?;
                let SuffixAnalysis::Literals(suffixes) = analyze_required_suffixes(branch, budget)?
                else {
                    return Ok(SuffixAnalysis::None);
                };
                for suffix in suffixes.iter() {
                    if !combined.insert(suffix, budget)? {
                        return Ok(SuffixAnalysis::None);
                    }
                }
            }
            if combined.len == 0 {
                Ok(SuffixAnalysis::None)
            } else {
                Ok(SuffixAnalysis::Literals(combined))
            }
        }
    }
}

fn validate_hir(
    hir: &Hir,
    profile: RustByteProfile,
    capture_policy: CapturePolicy,
    budget: &mut CompileBudget,
) -> Result<(), Error> {
    let mut stack = Vec::new();
    stack
        .try_reserve_exact(1)
        .map_err(|_| Error::AllocationFailed {
            resource: Resource::HirStackItems,
            items: 1,
        })?;
    budget.acquire_construction_bytes(mul(
        stack.capacity(),
        core::mem::size_of::<(&Hir, usize)>(),
        Resource::ProgramBytes,
    )?)?;
    enforce(
        1,
        budget.limits.max_hir_stack_items,
        Resource::HirStackItems,
    )?;
    stack.push((hir, 1_usize));
    budget.accounting.peak_hir_stack_items = 1;
    while let Some((node, depth)) = stack.pop() {
        budget.charge(1)?;
        budget.accounting.hir_nodes = add(budget.accounting.hir_nodes, 1, Resource::HirNodes)?;
        enforce(
            budget.accounting.hir_nodes,
            budget.limits.max_hir_nodes,
            Resource::HirNodes,
        )?;
        enforce(depth, budget.limits.max_hir_depth, Resource::HirDepth)?;
        budget.accounting.hir_depth = budget.accounting.hir_depth.max(depth);
        match node.kind() {
            HirKind::Empty => {}
            HirKind::Literal(literal) => {
                budget.charge(literal.0.len())?;
                budget.accounting.literal_bytes = add(
                    budget.accounting.literal_bytes,
                    literal.0.len(),
                    Resource::LiteralBytes,
                )?;
                enforce(
                    budget.accounting.literal_bytes,
                    budget.limits.max_literal_bytes,
                    Resource::LiteralBytes,
                )?;
            }
            HirKind::Class(Class::Unicode(class)) => {
                validate_unicode_class(class, profile, budget)?;
            }
            HirKind::Class(Class::Bytes(class)) => {
                let ranges = class.ranges().len();
                budget.charge(ranges)?;
                budget.accounting.class_ranges = add(
                    budget.accounting.class_ranges,
                    ranges,
                    Resource::ClassRanges,
                )?;
                enforce(
                    budget.accounting.class_ranges,
                    budget.limits.max_class_ranges,
                    Resource::ClassRanges,
                )?;
            }
            HirKind::Look(_) => {
                budget.record_look_assertion()?;
            }
            HirKind::Capture(capture) => match capture_policy {
                CapturePolicy::Reject => return Err(Error::Unsupported(Unsupported::Capture)),
                CapturePolicy::EraseForWholeMatch => {
                    budget.record_capture_erasure(true)?;
                    push_children(&mut stack, [capture.sub.as_ref()], depth, budget)?;
                }
            },
            HirKind::Repetition(repetition) => {
                validate_repetition(repetition, budget)?;
                push_children(&mut stack, [repetition.sub.as_ref()], depth, budget)?;
            }
            HirKind::Concat(children) | HirKind::Alternation(children) => {
                if matches!(node.kind(), HirKind::Alternation(_)) && children.is_empty() {
                    return Err(Error::EmptyAlternation);
                }
                push_children(&mut stack, children.iter(), depth, budget)?;
            }
        }
    }
    budget.release_construction_bytes(mul(
        stack.capacity(),
        core::mem::size_of::<(&Hir, usize)>(),
        Resource::ProgramBytes,
    )?)?;
    Ok(())
}

fn validate_unicode_class(
    class: &regex_syntax::hir::ClassUnicode,
    profile: RustByteProfile,
    budget: &mut CompileBudget,
) -> Result<(), Error> {
    if !profile.unicode && class.ranges().iter().any(|range| !range.end().is_ascii()) {
        return Err(Error::Unsupported(Unsupported::UnicodeClass));
    }
    let ranges = class.ranges().len();
    budget.charge(ranges)?;
    budget.accounting.class_ranges = add(
        budget.accounting.class_ranges,
        ranges,
        Resource::ClassRanges,
    )?;
    enforce(
        budget.accounting.class_ranges,
        budget.limits.max_class_ranges,
        Resource::ClassRanges,
    )?;
    if profile.unicode {
        for range in class.ranges() {
            for sequence in Utf8Sequences::new(range.start(), range.end()) {
                budget.charge(1)?;
                budget.accounting.utf8_sequences =
                    add(budget.accounting.utf8_sequences, 1, Resource::Utf8Sequences)?;
                enforce(
                    budget.accounting.utf8_sequences,
                    budget.limits.max_utf8_sequences,
                    Resource::Utf8Sequences,
                )?;
                let byte_ranges = sequence.as_slice().len();
                budget.charge(byte_ranges)?;
                budget.accounting.utf8_byte_ranges = add(
                    budget.accounting.utf8_byte_ranges,
                    byte_ranges,
                    Resource::Utf8ByteRanges,
                )?;
                enforce(
                    budget.accounting.utf8_byte_ranges,
                    budget.limits.max_utf8_byte_ranges,
                    Resource::Utf8ByteRanges,
                )?;
            }
        }
    }
    Ok(())
}

fn push_children<'a>(
    stack: &mut Vec<(&'a Hir, usize)>,
    children: impl IntoIterator<Item = &'a Hir>,
    depth: usize,
    budget: &mut CompileBudget,
) -> Result<(), Error> {
    let next_depth = add(depth, 1, Resource::HirDepth)?;
    for child in children {
        let required = add(stack.len(), 1, Resource::HirStackItems)?;
        enforce(
            required,
            budget.limits.max_hir_stack_items,
            Resource::HirStackItems,
        )?;
        let old_capacity = stack.capacity();
        stack.try_reserve(1).map_err(|_| Error::AllocationFailed {
            resource: Resource::HirStackItems,
            items: 1,
        })?;
        let added_capacity =
            stack
                .capacity()
                .checked_sub(old_capacity)
                .ok_or(Error::InternalInvariant(
                    "HIR stack capacity decreased during reserve",
                ))?;
        budget.acquire_construction_bytes(mul(
            added_capacity,
            core::mem::size_of::<(&Hir, usize)>(),
            Resource::ProgramBytes,
        )?)?;
        stack.push((child, next_depth));
        budget.accounting.peak_hir_stack_items =
            budget.accounting.peak_hir_stack_items.max(stack.len());
        budget.charge(1)?;
    }
    Ok(())
}

fn validate_repetition(repetition: &Repetition, budget: &mut CompileBudget) -> Result<(), Error> {
    if repetition
        .max
        .is_some_and(|maximum| maximum < repetition.min)
    {
        return Err(Error::InvalidRepetition);
    }
    let largest = repetition.max.unwrap_or(repetition.min);
    let required = usize::try_from(largest).map_err(|_| Error::ArithmeticOverflow {
        resource: Resource::RepeatBound,
    })?;
    let limit =
        usize::try_from(budget.limits.max_repeat_bound).map_err(|_| Error::ArithmeticOverflow {
            resource: Resource::RepeatBound,
        })?;
    enforce(required, limit, Resource::RepeatBound)
}

struct Builder<'a> {
    slots: Vec<Inst>,
    scalar_range_bytes: usize,
    retained_program_bytes: usize,
    state_limit: usize,
    profile: RustByteProfile,
    capture_policy: CapturePolicy,
    budget: &'a mut CompileBudget,
}

impl<'a> Builder<'a> {
    fn new(
        state_limit: usize,
        profile: RustByteProfile,
        capture_policy: CapturePolicy,
        retained_program_bytes: usize,
        budget: &'a mut CompileBudget,
    ) -> Self {
        Self {
            slots: Vec::new(),
            scalar_range_bytes: 0,
            retained_program_bytes,
            state_limit,
            profile,
            capture_policy,
            budget,
        }
    }

    fn enforce_program_shape(&self, states: usize, scalar_range_bytes: usize) -> Result<(), Error> {
        enforce(states, self.state_limit, Resource::ProgramStates)?;
        let state_metadata_bytes = mul(2, core::mem::size_of::<usize>(), Resource::ProgramBytes)?;
        let state_bytes = mul(
            states,
            add(
                core::mem::size_of::<Inst>(),
                state_metadata_bytes,
                Resource::ProgramBytes,
            )?,
            Resource::ProgramBytes,
        )?;
        enforce(
            add(
                add(state_bytes, scalar_range_bytes, Resource::ProgramBytes)?,
                self.retained_program_bytes,
                Resource::ProgramBytes,
            )?,
            self.budget.limits.max_program_bytes,
            Resource::ProgramBytes,
        )
    }

    fn push(&mut self, inst: Inst) -> Result<usize, Error> {
        let required = add(self.slots.len(), 1, Resource::ProgramStates)?;
        let added_scalar_bytes = match &inst {
            Inst::ConsumeScalar { scalars, .. } => scalars.allocated_bytes()?,
            _ => 0,
        };
        let scalar_range_bytes = add(
            self.scalar_range_bytes,
            added_scalar_bytes,
            Resource::ProgramBytes,
        )?;
        self.enforce_program_shape(required, scalar_range_bytes)?;
        self.budget.acquire_state()?;
        let old_capacity = self.slots.capacity();
        self.slots
            .try_reserve(1)
            .map_err(|_| Error::AllocationFailed {
                resource: Resource::TemporaryStates,
                items: 1,
            })?;
        let added_capacity =
            self.slots
                .capacity()
                .checked_sub(old_capacity)
                .ok_or(Error::InternalInvariant(
                    "compiler state capacity decreased during reserve",
                ))?;
        let state_capacity_bytes = mul(
            added_capacity,
            core::mem::size_of::<Inst>(),
            Resource::ProgramBytes,
        )?;
        self.budget.acquire_construction_bytes(add(
            state_capacity_bytes,
            added_scalar_bytes,
            Resource::ProgramBytes,
        )?)?;
        let index = self.slots.len();
        self.slots.push(inst);
        self.scalar_range_bytes = scalar_range_bytes;
        Ok(index)
    }

    fn fill_unfilled(&mut self, index: usize, inst: Inst) -> Result<(), Error> {
        if !matches!(self.slots.get(index), Some(Inst::Unfilled)) {
            return Err(Error::InternalInvariant(
                "compiler attempted to replace a filled state",
            ));
        }
        let added_scalar_bytes = match &inst {
            Inst::ConsumeScalar { scalars, .. } => scalars.allocated_bytes()?,
            _ => 0,
        };
        let scalar_range_bytes = add(
            self.scalar_range_bytes,
            added_scalar_bytes,
            Resource::ProgramBytes,
        )?;
        self.enforce_program_shape(self.slots.len(), scalar_range_bytes)?;
        self.budget.acquire_construction_bytes(added_scalar_bytes)?;
        self.slots[index] = inst;
        self.scalar_range_bytes = scalar_range_bytes;
        Ok(())
    }

    /// Check both persistent space and construction work before cloning a
    /// scalar range allocation into a progress-product state.
    fn preflight_progress_fill(&mut self, index: usize, source: &Inst) -> Result<(), Error> {
        if !matches!(self.slots.get(index), Some(Inst::Unfilled)) {
            return Err(Error::InternalInvariant(
                "compiler attempted to replace a filled state",
            ));
        }
        let added_scalar_bytes = match source {
            Inst::ConsumeScalar { scalars, .. } => scalars.allocated_bytes()?,
            _ => 0,
        };
        let scalar_range_bytes = add(
            self.scalar_range_bytes,
            added_scalar_bytes,
            Resource::ProgramBytes,
        )?;
        self.enforce_program_shape(self.slots.len(), scalar_range_bytes)?;
        if let Inst::ConsumeScalar { scalars, .. } = source {
            self.budget.charge(scalars.len())?;
        }
        Ok(())
    }

    fn preflight_scalar_set(&self, range_count: usize) -> Result<(), Error> {
        let states = add(self.slots.len(), 1, Resource::ProgramStates)?;
        let scalar_range_bytes = add(
            self.scalar_range_bytes,
            ScalarSet::required_bytes(range_count)?,
            Resource::ProgramBytes,
        )?;
        self.enforce_program_shape(states, scalar_range_bytes)
    }

    fn finish(self) -> Result<ExactVec<Inst>, Error> {
        if self.slots.iter().any(|inst| matches!(inst, Inst::Unfilled)) {
            return Err(Error::InternalInvariant("unfilled compiler state"));
        }
        let retained_state_bytes = mul(
            self.slots.len(),
            core::mem::size_of::<Inst>(),
            Resource::ProgramBytes,
        )?;
        let construction_state_bytes = mul(
            self.slots.capacity(),
            core::mem::size_of::<Inst>(),
            Resource::ProgramBytes,
        )?;
        self.budget.charge(self.slots.len())?;
        self.budget
            .acquire_construction_bytes(retained_state_bytes)?;
        let retained = retain_exact_program_vec(self.slots)?;
        self.budget
            .release_construction_bytes(construction_state_bytes)?;
        Ok(retained)
    }

    fn compile_node(
        &mut self,
        hir: &Hir,
        continuation: usize,
        depth: usize,
    ) -> Result<usize, Error> {
        enforce(depth, self.budget.limits.max_hir_depth, Resource::HirDepth)?;
        self.budget.charge(1)?;
        let child_depth = add(depth, 1, Resource::HirDepth)?;
        match hir.kind() {
            HirKind::Empty => Ok(continuation),
            HirKind::Literal(literal) => {
                let mut next = continuation;
                for &byte in literal.0.iter().rev() {
                    let mut bytes = ByteSet::empty();
                    bytes.insert(byte);
                    next = self.push(Inst::Consume { bytes, next })?;
                }
                Ok(next)
            }
            HirKind::Class(Class::Bytes(class)) => {
                let mut bytes = ByteSet::empty();
                for range in class.ranges() {
                    self.budget
                        .charge(inclusive_byte_width(range.start(), range.end())?)?;
                    bytes.insert_range(range.start(), range.end());
                }
                self.push(Inst::Consume {
                    bytes,
                    next: continuation,
                })
            }
            HirKind::Class(Class::Unicode(class)) => {
                self.compile_unicode_class(class, continuation)
            }
            HirKind::Look(look) => {
                let assertion = Assertion::from_look(*look);
                self.push(Inst::Assert {
                    assertion,
                    next: continuation,
                })
            }
            HirKind::Capture(capture) => match self.capture_policy {
                CapturePolicy::Reject => Err(Error::Unsupported(Unsupported::Capture)),
                CapturePolicy::EraseForWholeMatch => {
                    self.budget.record_capture_erasure(false)?;
                    self.compile_node(capture.sub.as_ref(), continuation, child_depth)
                }
            },
            HirKind::Concat(children) => {
                let mut next = continuation;
                for child in children.iter().rev() {
                    next = self.compile_node(child, next, child_depth)?;
                }
                Ok(next)
            }
            HirKind::Alternation(children) => {
                let Some((last, preceding)) = children.split_last() else {
                    return Err(Error::EmptyAlternation);
                };
                let mut fallback = self.compile_node(last, continuation, child_depth)?;
                for child in preceding.iter().rev() {
                    let preferred = self.compile_node(child, continuation, child_depth)?;
                    fallback = self.push(Inst::Split {
                        preferred,
                        fallback,
                    })?;
                }
                Ok(fallback)
            }
            HirKind::Repetition(repetition) => {
                self.compile_repetition(repetition, continuation, child_depth)
            }
        }
    }

    fn compile_unicode_class(
        &mut self,
        class: &regex_syntax::hir::ClassUnicode,
        continuation: usize,
    ) -> Result<usize, Error> {
        if self.profile.unicode {
            self.budget.charge(class.ranges().len())?;
            let mut next_by_width = [continuation; 4];
            let mut tail = continuation;
            let maximum_width = class
                .ranges()
                .last()
                .map_or(0, |range| range.end().len_utf8());
            let mut continuation_bytes = ByteSet::empty();
            if maximum_width > 1 {
                self.budget.charge(inclusive_byte_width(0x80, 0xBF)?)?;
                continuation_bytes.insert_range(0x80, 0xBF);
            }
            for slot in next_by_width.iter_mut().take(maximum_width).skip(1) {
                tail = self.push(Inst::Consume {
                    bytes: continuation_bytes,
                    next: tail,
                })?;
                *slot = tail;
            }
            self.preflight_scalar_set(class.ranges().len())?;
            let scalars = ScalarSet::from_unicode_class(class)?;
            return self.push(Inst::ConsumeScalar {
                scalars,
                next_by_width,
            });
        }

        let mut entry = None;
        for range in class.ranges() {
            let start = u8::try_from(u32::from(range.start()))
                .map_err(|_| Error::Unsupported(Unsupported::UnicodeClass))?;
            let end = u8::try_from(u32::from(range.end()))
                .map_err(|_| Error::Unsupported(Unsupported::UnicodeClass))?;
            self.budget.charge(inclusive_byte_width(start, end)?)?;
            let mut bytes = ByteSet::empty();
            bytes.insert_range(start, end);
            let next = self.push(Inst::Consume {
                bytes,
                next: continuation,
            })?;
            entry = Some(match entry {
                None => next,
                Some(preferred) => self.push(Inst::Split {
                    preferred,
                    fallback: next,
                })?,
            });
        }
        entry.ok_or(Error::InternalInvariant("empty Unicode scalar class"))
    }

    fn compile_repetition(
        &mut self,
        repetition: &Repetition,
        continuation: usize,
        depth: usize,
    ) -> Result<usize, Error> {
        let Some(maximum) = repetition.max else {
            return self.compile_unbounded(
                repetition.sub.as_ref(),
                repetition.min,
                repetition.greedy,
                continuation,
                depth,
            );
        };
        let optional = maximum
            .checked_sub(repetition.min)
            .ok_or(Error::InvalidRepetition)?;
        let mut next = continuation;
        for _ in 0..optional {
            let child_entry = self.compile_node(repetition.sub.as_ref(), next, depth)?;
            let (preferred, fallback) = if repetition.greedy {
                (child_entry, next)
            } else {
                (next, child_entry)
            };
            next = self.push(Inst::Split {
                preferred,
                fallback,
            })?;
        }
        for _ in 0..repetition.min {
            next = self.compile_node(repetition.sub.as_ref(), next, depth)?;
        }
        Ok(next)
    }

    fn compile_unbounded(
        &mut self,
        child: &Hir,
        minimum: u32,
        greedy: bool,
        continuation: usize,
        depth: usize,
    ) -> Result<usize, Error> {
        // Rust's empty-loop guard distinguishes a repetition before and after
        // it has consumed. In the initial mode, a zero-width body exits. In
        // the progressed mode, a zero-width body path fails so lower-priority
        // consuming paths are tried before the loop exit. A single loop entry
        // gets `(?:b|(?:|a))*` on `ba` wrong.
        let fail = self.push(Inst::Fail)?;
        let initial_loop = self.push(Inst::Unfilled)?;
        let progressed_loop = self.push(Inst::Unfilled)?;
        let (fragment, fragment_entry) = {
            let mut fragment_builder = Builder::new(
                self.state_limit,
                self.profile,
                self.capture_policy,
                self.retained_program_bytes,
                self.budget,
            );
            let accept = fragment_builder.push(Inst::Match)?;
            let fragment_entry = fragment_builder.compile_node(child, accept, depth)?;
            (fragment_builder.finish()?, fragment_entry)
        };
        let fragment_len = fragment.len();
        let fragment_bytes = inst_vec_owned_bytes(&fragment)?;
        let initial_body =
            self.import_progress_product(&fragment, fragment_entry, continuation, progressed_loop)?;
        let progressed_body =
            self.import_progress_product(&fragment, fragment_entry, fail, progressed_loop)?;
        drop(fragment);
        self.budget.release_construction_bytes(fragment_bytes)?;
        self.budget.release_states(fragment_len)?;
        let (preferred, fallback) = if greedy {
            (initial_body, continuation)
        } else {
            (continuation, initial_body)
        };
        self.slots[initial_loop] = Inst::Split {
            preferred,
            fallback,
        };
        let (preferred, fallback) = if greedy {
            (progressed_body, continuation)
        } else {
            (continuation, progressed_body)
        };
        self.slots[progressed_loop] = Inst::Split {
            preferred,
            fallback,
        };
        if minimum == 0 {
            return Ok(initial_loop);
        }

        // Required iterations are finite, but their aggregate progress must
        // select the right mode for the open tail.
        let (required, required_entry) = {
            let mut fragment_builder = Builder::new(
                self.state_limit,
                self.profile,
                self.capture_policy,
                self.retained_program_bytes,
                self.budget,
            );
            let accept = fragment_builder.push(Inst::Match)?;
            let mut entry = accept;
            for _ in 0..minimum {
                entry = fragment_builder.compile_node(child, entry, depth)?;
            }
            (fragment_builder.finish()?, entry)
        };
        let required_len = required.len();
        let required_bytes = inst_vec_owned_bytes(&required)?;
        let entry =
            self.import_progress_product(&required, required_entry, initial_loop, progressed_loop)?;
        drop(required);
        self.budget.release_construction_bytes(required_bytes)?;
        self.budget.release_states(required_len)?;
        Ok(entry)
    }

    fn import_progress_product(
        &mut self,
        fragment: &[Inst],
        fragment_entry: usize,
        zero_continuation: usize,
        consumed_continuation: usize,
    ) -> Result<usize, Error> {
        let mut zero_map = reserved_vec(fragment.len(), Resource::TemporaryStates)?;
        let mut consumed_map = reserved_vec(fragment.len(), Resource::TemporaryStates)?;
        let map_bytes = add(
            mul(
                zero_map.capacity(),
                core::mem::size_of::<usize>(),
                Resource::ProgramBytes,
            )?,
            mul(
                consumed_map.capacity(),
                core::mem::size_of::<usize>(),
                Resource::ProgramBytes,
            )?,
            Resource::ProgramBytes,
        )?;
        self.budget.acquire_construction_bytes(map_bytes)?;
        for inst in fragment {
            if matches!(inst, Inst::Match) {
                zero_map.push(zero_continuation);
                consumed_map.push(consumed_continuation);
            } else {
                zero_map.push(self.push(Inst::Unfilled)?);
                consumed_map.push(self.push(Inst::Unfilled)?);
            }
        }
        for (pc, inst) in fragment.iter().enumerate() {
            self.budget.charge(1)?;
            if matches!(inst, Inst::Match) {
                continue;
            }
            self.preflight_progress_fill(zero_map[pc], inst)?;
            let zero = translate_progress(inst, &zero_map, &consumed_map, false)?;
            self.fill_unfilled(zero_map[pc], zero)?;
            self.preflight_progress_fill(consumed_map[pc], inst)?;
            let consumed = translate_progress(inst, &zero_map, &consumed_map, true)?;
            self.fill_unfilled(consumed_map[pc], consumed)?;
        }
        let entry = zero_map
            .get(fragment_entry)
            .copied()
            .ok_or(Error::InternalInvariant("fragment entry outside fragment"))?;
        drop(zero_map);
        drop(consumed_map);
        self.budget.release_construction_bytes(map_bytes)?;
        Ok(entry)
    }
}

fn translate_progress(
    inst: &Inst,
    zero: &[usize],
    consumed: &[usize],
    has_consumed: bool,
) -> Result<Inst, Error> {
    let same = if has_consumed { consumed } else { zero };
    let mapped = |map: &[usize], pc: usize| {
        map.get(pc)
            .copied()
            .ok_or(Error::InternalInvariant("fragment target outside fragment"))
    };
    match inst {
        Inst::Unfilled => Err(Error::InternalInvariant("unfilled fragment state")),
        Inst::Fail => Ok(Inst::Fail),
        Inst::Match => Err(Error::InternalInvariant("translated fragment match")),
        Inst::Consume { bytes, next } => Ok(Inst::Consume {
            bytes: *bytes,
            next: mapped(consumed, *next)?,
        }),
        Inst::ConsumeScalar {
            scalars,
            next_by_width,
        } => {
            let mut translated = [0_usize; 4];
            for (destination, source) in translated.iter_mut().zip(next_by_width) {
                *destination = mapped(consumed, *source)?;
            }
            Ok(Inst::ConsumeScalar {
                scalars: scalars.try_clone()?,
                next_by_width: translated,
            })
        }
        Inst::Assert { assertion, next } => Ok(Inst::Assert {
            assertion: *assertion,
            next: mapped(same, *next)?,
        }),
        Inst::Split {
            preferred,
            fallback,
        } => Ok(Inst::Split {
            preferred: mapped(same, *preferred)?,
            fallback: mapped(same, *fallback)?,
        }),
    }
}

struct ProgramCertificate {
    epsilon_order: ExactVec<usize>,
    split_rank: ExactVec<usize>,
    split_count: usize,
    execution_state_work: usize,
    predecessor_edges: usize,
    has_scalar_transition: bool,
    max_scalar_search_checks: usize,
}

struct EpsilonParentIndex {
    outgoing: ExactVec<usize>,
    offsets: Vec<usize>,
    parents: Vec<usize>,
    scratch_bytes: usize,
}

fn certify_program(
    insts: &[Inst],
    scalar_range_bytes: usize,
    retained_program_bytes: usize,
    budget: &mut CompileBudget,
) -> Result<ProgramCertificate, Error> {
    let states = insts.len();
    preflight_certification_program_bytes(
        states,
        states,
        scalar_range_bytes,
        retained_program_bytes,
        budget.limits.max_program_bytes,
    )?;
    certify_program_admitted(insts, budget)
}

fn build_epsilon_parent_index(
    insts: &[Inst],
    budget: &mut CompileBudget,
) -> Result<EpsilonParentIndex, Error> {
    let states = insts.len();
    let mut outgoing = zeroed_exact_program_vec(states)?;
    let mut parent_counts = zeroed_vec(states, Resource::TemporaryStates)?;
    let outgoing_bytes = exact_vector_bytes(&outgoing)?;
    let parent_counts_bytes = vector_capacity_bytes(&parent_counts)?;
    budget.acquire_construction_bytes(add(
        outgoing_bytes,
        parent_counts_bytes,
        Resource::ProgramBytes,
    )?)?;
    let mut edge_count = 0_usize;
    for (parent, inst) in insts.iter().enumerate() {
        for child in epsilon_targets(inst) {
            budget.charge(1)?;
            if child >= states {
                return Err(Error::InternalInvariant("epsilon target outside program"));
            }
            outgoing[parent] = add(outgoing[parent], 1, Resource::TemporaryStates)?;
            parent_counts[child] = add(parent_counts[child], 1, Resource::TemporaryStates)?;
            edge_count = add(edge_count, 1, Resource::TemporaryStates)?;
        }
    }
    let mut offsets = zeroed_vec(
        add(states, 1, Resource::TemporaryStates)?,
        Resource::TemporaryStates,
    )?;
    let offsets_bytes = vector_capacity_bytes(&offsets)?;
    budget.acquire_construction_bytes(offsets_bytes)?;
    for index in 0..states {
        let next_index = add(index, 1, Resource::TemporaryStates)?;
        offsets[next_index] = add(
            offsets[index],
            parent_counts[index],
            Resource::TemporaryStates,
        )?;
    }
    // Parent cardinalities are dead once their prefix offsets are frozen.
    // Reuse that exact allocation for the per-child insertion cursors.
    let mut cursor = parent_counts;
    cursor.copy_from_slice(&offsets[..states]);
    let mut parents = zeroed_vec(edge_count, Resource::TemporaryStates)?;
    let parents_bytes = vector_capacity_bytes(&parents)?;
    budget.acquire_construction_bytes(parents_bytes)?;
    for (parent, inst) in insts.iter().enumerate() {
        for child in epsilon_targets(inst) {
            let slot = cursor[child];
            parents[slot] = parent;
            cursor[child] = add(cursor[child], 1, Resource::TemporaryStates)?;
            budget.charge(1)?;
        }
    }
    drop(cursor);
    budget.release_construction_bytes(parent_counts_bytes)?;
    Ok(EpsilonParentIndex {
        outgoing,
        offsets,
        parents,
        scratch_bytes: add(offsets_bytes, parents_bytes, Resource::ProgramBytes)?,
    })
}

fn certify_program_admitted(
    insts: &[Inst],
    budget: &mut CompileBudget,
) -> Result<ProgramCertificate, Error> {
    let states = insts.len();
    let EpsilonParentIndex {
        mut outgoing,
        offsets,
        parents,
        scratch_bytes,
    } = build_epsilon_parent_index(insts, budget)?;
    let mut queue = reserved_queue(states)?;
    let queue_bytes = mul(
        queue.capacity(),
        core::mem::size_of::<usize>(),
        Resource::ProgramBytes,
    )?;
    budget.acquire_construction_bytes(queue_bytes)?;
    for (state, count) in outgoing.iter().enumerate() {
        if *count == 0 {
            queue.push_back(state);
        }
    }
    let mut order = exact_program_vec(states)?;
    let order_bytes = exact_vector_bytes(&order)?;
    budget.acquire_construction_bytes(order_bytes)?;
    while let Some(child) = queue.pop_front() {
        order.try_push(child).map_err(|_| {
            Error::InternalInvariant("certificate order exceeded exact state allocation")
        })?;
        let next_child = add(child, 1, Resource::TemporaryStates)?;
        for &parent in &parents[offsets[child]..offsets[next_child]] {
            budget.charge(1)?;
            outgoing[parent] = outgoing[parent]
                .checked_sub(1)
                .ok_or(Error::SameBoundaryCycle)?;
            if outgoing[parent] == 0 {
                queue.push_back(parent);
            }
        }
    }
    if order.len() != states {
        return Err(Error::SameBoundaryCycle);
    }
    // A successful topological drain leaves every outgoing count dead. Reuse
    // the exact state-width allocation as the persistent split-rank table.
    let mut split_rank = outgoing;
    let metadata = certify_execution_metadata(&mut split_rank, insts, budget)?;
    drop(offsets);
    drop(parents);
    drop(queue);
    budget.release_construction_bytes(add(scratch_bytes, queue_bytes, Resource::ProgramBytes)?)?;
    Ok(ProgramCertificate {
        epsilon_order: order,
        split_rank,
        split_count: metadata.split_count,
        execution_state_work: metadata.state_work,
        predecessor_edges: metadata.predecessor_edges,
        has_scalar_transition: metadata.has_scalar_transition,
        max_scalar_search_checks: metadata.max_scalar_search_checks,
    })
}

fn preflight_certification_program_bytes(
    retained_state_count: usize,
    states: usize,
    scalar_range_bytes: usize,
    retained_program_bytes: usize,
    limit: usize,
) -> Result<usize, Error> {
    let state_bytes = mul(
        retained_state_count,
        core::mem::size_of::<Inst>(),
        Resource::ProgramBytes,
    )?;
    let certificate_items = mul(2, states, Resource::ProgramBytes)?;
    let certificate_bytes = mul(
        certificate_items,
        core::mem::size_of::<usize>(),
        Resource::ProgramBytes,
    )?;
    let required = add(
        add(state_bytes, scalar_range_bytes, Resource::ProgramBytes)?,
        add(
            certificate_bytes,
            retained_program_bytes,
            Resource::ProgramBytes,
        )?,
        Resource::ProgramBytes,
    )?;
    enforce(required, limit, Resource::ProgramBytes)?;
    Ok(required)
}

struct ExecutionMetadata {
    split_count: usize,
    state_work: usize,
    predecessor_edges: usize,
    has_scalar_transition: bool,
    max_scalar_search_checks: usize,
}

fn certify_execution_metadata(
    split_rank: &mut [usize],
    insts: &[Inst],
    budget: &mut CompileBudget,
) -> Result<ExecutionMetadata, Error> {
    let mut metadata = ExecutionMetadata {
        split_count: 0,
        state_work: 0,
        predecessor_edges: 0,
        has_scalar_transition: false,
        max_scalar_search_checks: 0,
    };
    for (rank, inst) in split_rank.iter_mut().zip(insts) {
        budget.charge(1)?;
        if matches!(inst, Inst::Split { .. }) {
            *rank = metadata.split_count;
            metadata.split_count = add(metadata.split_count, 1, Resource::ProgramStates)?;
        } else {
            *rank = NO_SPLIT_RANK;
        }
        let transitions = execution_transitions(
            inst,
            &mut metadata.has_scalar_transition,
            &mut metadata.max_scalar_search_checks,
        )?;
        metadata.state_work = add(
            add(metadata.state_work, 1, Resource::ExecutionWork)?,
            transitions,
            Resource::ExecutionWork,
        )?;
        metadata.predecessor_edges = add(
            metadata.predecessor_edges,
            predecessor_edge_count(inst),
            Resource::ProgramStates,
        )?;
    }
    Ok(metadata)
}

const fn predecessor_edge_count(inst: &Inst) -> usize {
    match inst {
        Inst::Unfilled | Inst::Fail | Inst::Match => 0,
        Inst::Consume { .. } | Inst::Assert { .. } => 1,
        Inst::Split { .. } => 2,
        Inst::ConsumeScalar { .. } => 4,
    }
}

fn execution_transitions(
    inst: &Inst,
    has_scalar_transition: &mut bool,
    max_scalar_search_checks: &mut usize,
) -> Result<usize, Error> {
    match inst {
        Inst::Unfilled => Err(Error::InternalInvariant("unfilled execution state")),
        Inst::Fail | Inst::Match => Ok(0),
        Inst::Consume { .. } | Inst::Assert { .. } => Ok(1),
        Inst::ConsumeScalar { scalars, .. } => {
            *has_scalar_transition = true;
            let checks = scalars.max_search_checks();
            *max_scalar_search_checks = (*max_scalar_search_checks).max(checks);
            add(1, checks, Resource::ExecutionWork)
        }
        Inst::Split { .. } => Ok(2),
    }
}

fn epsilon_targets(inst: &Inst) -> impl Iterator<Item = usize> {
    let targets = match inst {
        Inst::Assert { next, .. } => [Some(*next), None],
        Inst::Split {
            preferred,
            fallback,
        } => [Some(*preferred), Some(*fallback)],
        Inst::Unfilled
        | Inst::Fail
        | Inst::Match
        | Inst::Consume { .. }
        | Inst::ConsumeScalar { .. } => [None, None],
    };
    targets.into_iter().flatten()
}

fn program_bytes(
    insts: &[Inst],
    retained_inst_count: usize,
    retained_order_count: usize,
    retained_rank_count: usize,
) -> Result<usize, Error> {
    let state_bytes = mul(
        retained_inst_count,
        core::mem::size_of::<Inst>(),
        Resource::ProgramBytes,
    )?;
    let scalar_bytes = insts.iter().try_fold(0_usize, |total, inst| {
        let bytes = match inst {
            Inst::ConsumeScalar { scalars, .. } => scalars.allocated_bytes()?,
            _ => 0,
        };
        add(total, bytes, Resource::ProgramBytes)
    })?;
    let insts = add(state_bytes, scalar_bytes, Resource::ProgramBytes)?;
    let order = mul(
        retained_order_count,
        core::mem::size_of::<usize>(),
        Resource::ProgramBytes,
    )?;
    let ranks = mul(
        retained_rank_count,
        core::mem::size_of::<usize>(),
        Resource::ProgramBytes,
    )?;
    add(
        add(insts, order, Resource::ProgramBytes)?,
        ranks,
        Resource::ProgramBytes,
    )
}

fn inst_vec_owned_bytes(insts: &[Inst]) -> Result<usize, Error> {
    let state_bytes = mul(
        insts.len(),
        core::mem::size_of::<Inst>(),
        Resource::ProgramBytes,
    )?;
    insts.iter().try_fold(state_bytes, |total, inst| {
        let scalar_bytes = match inst {
            Inst::ConsumeScalar { scalars, .. } => scalars.allocated_bytes()?,
            _ => 0,
        };
        add(total, scalar_bytes, Resource::ProgramBytes)
    })
}

fn finalize_program(
    program: &mut Program,
    profile: RustByteProfile,
    terminal_frontier: TerminalFrontierSeed,
    budget: &mut CompileBudget,
) -> Result<PlanId, Error> {
    let mut first = StableHash::new(0xcbf2_9ce4_8422_2325);
    let mut second = StableHash::new(0x8422_2325_cbf2_9ce4);
    first.bytes(profile.identity_domain());
    second.bytes(profile.identity_domain());
    if !terminal_frontier.is_empty() {
        let identity_payload = add(
            add(
                b"terminal-class-frontier-v1".len(),
                mul(2, core::mem::size_of::<u64>(), Resource::CompileWork)?,
                Resource::CompileWork,
            )?,
            add(
                terminal_frontier.prefix_len,
                terminal_frontier.terminals.len,
                Resource::CompileWork,
            )?,
            Resource::CompileWork,
        )?;
        let identity_work = add(
            mul(2, identity_payload, Resource::CompileWork)?,
            1,
            Resource::CompileWork,
        )?;
        budget.charge(identity_work)?;
        first.bytes(b"terminal-class-frontier-v1");
        second.bytes(b"terminal-class-frontier-v1");
        hash_usize(&mut first, terminal_frontier.prefix_len);
        hash_usize(&mut second, terminal_frontier.prefix_len);
        first.bytes(terminal_frontier.prefix_bytes());
        second.bytes(terminal_frontier.prefix_bytes());
        hash_usize(&mut first, terminal_frontier.terminals.len);
        hash_usize(&mut second, terminal_frontier.terminals.len);
        for terminal in terminal_frontier.terminals.iter() {
            first.byte(terminal);
            second.byte(terminal);
        }
    }
    hash_usize(&mut first, program.entry);
    hash_usize(&mut second, program.entry);
    let mut has_unicode_word_boundary = false;
    for inst in &program.insts {
        // This one per-instruction identity unit includes both stable hashing
        // and the immutable assertion-property classification. Classification
        // is not a second traversal or a separate uncharged unit.
        budget.charge(1)?;
        budget.accounting.unicode_word_boundary_checks = add(
            budget.accounting.unicode_word_boundary_checks,
            1,
            Resource::CompileWork,
        )?;
        has_unicode_word_boundary |= matches!(
            inst,
            Inst::Assert { assertion, .. } if assertion.is_unicode_word()
        );
        if let Inst::ConsumeScalar { scalars, .. } = inst {
            budget.charge(scalars.len())?;
        }
        hash_inst(&mut first, inst);
        hash_inst(&mut second, inst);
    }
    program.has_unicode_word_boundary = has_unicode_word_boundary;
    budget.accounting.requires_utf8_validation = has_unicode_word_boundary;
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&first.finish().to_le_bytes());
    bytes[8..].copy_from_slice(&second.finish().to_le_bytes());
    Ok(PlanId(bytes))
}

fn bind_required_internal_anchor_identity(
    program: PlanId,
    plan: &fre_kernels::RequiredInternalAnchorPlan,
    budget: &mut CompileBudget,
) -> Result<PlanId, Error> {
    let domain = fre_kernels::REQUIRED_INTERNAL_ANCHOR_PLAN_ID.as_bytes();
    let operation = fre_kernels::REQUIRED_INTERNAL_ANCHOR_COUNT_OPERATION_ID.as_bytes();
    let class_bytes = mul(4, core::mem::size_of::<u64>(), Resource::CompileWork)?;
    let class_identity_bytes = mul(7, class_bytes, Resource::CompileWork)?;
    let optional_identity_bytes = mul(
        fre_kernels::REQUIRED_INTERNAL_ANCHOR_MAX_OPTIONAL_STAGES,
        2,
        Resource::CompileWork,
    )?;
    let configuration_identity_bytes = add(
        add(
            class_identity_bytes,
            optional_identity_bytes,
            Resource::CompileWork,
        )?,
        add(1, core::mem::size_of::<u64>(), Resource::CompileWork)?,
        Resource::CompileWork,
    )?;
    budget.charge(add(
        add(
            add(program.0.len(), domain.len(), Resource::CompileWork)?,
            add(operation.len(), plan.anchor().len(), Resource::CompileWork)?,
            Resource::CompileWork,
        )?,
        configuration_identity_bytes,
        Resource::CompileWork,
    )?)?;
    let continuation = plan.continuation();
    let mut first = StableHash::new(0xa87c_19e2_d4b5_6301);
    let mut second = StableHash::new(0x6301_d4b5_19e2_a87c);
    for hash in [&mut first, &mut second] {
        hash.bytes(&program.0);
        hash.bytes(domain);
        hash.bytes(operation);
        hash_usize(hash, plan.anchor().len());
        hash.bytes(plan.anchor());
        for word in plan.prefix().words() {
            hash.bytes(&word.to_le_bytes());
        }
        for word in continuation.head.words() {
            hash.bytes(&word.to_le_bytes());
        }
        for word in continuation.tail.words() {
            hash.bytes(&word.to_le_bytes());
        }
        hash.byte(continuation.optional_count);
        for stage in continuation.optional {
            if let Some(stage) = stage {
                hash.byte(1);
                hash.byte(stage.introducer);
                for word in stage.class.words() {
                    hash.bytes(&word.to_le_bytes());
                }
            } else {
                hash.byte(0);
            }
        }
    }
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&first.finish().to_le_bytes());
    bytes[8..].copy_from_slice(&second.finish().to_le_bytes());
    Ok(PlanId(bytes))
}

fn hash_inst(hash: &mut StableHash, inst: &Inst) {
    match inst {
        Inst::Unfilled => hash.byte(0),
        Inst::Fail => hash.byte(1),
        Inst::Match => hash.byte(2),
        Inst::Consume { bytes, next } => {
            hash.byte(3);
            for word in bytes.0 {
                hash.bytes(&word.to_le_bytes());
            }
            hash_usize(hash, *next);
        }
        Inst::ConsumeScalar {
            scalars,
            next_by_width,
        } => {
            hash.byte(6);
            hash_usize(hash, scalars.len());
            for (start, end) in scalars.ranges() {
                hash.bytes(&start.to_le_bytes());
                hash.bytes(&end.to_le_bytes());
            }
            for next in next_by_width {
                hash_usize(hash, *next);
            }
        }
        Inst::Assert { assertion, next } => {
            hash.byte(4);
            hash.byte(assertion.identity_tag());
            hash_usize(hash, *next);
        }
        Inst::Split {
            preferred,
            fallback,
        } => {
            hash.byte(5);
            hash_usize(hash, *preferred);
            hash_usize(hash, *fallback);
        }
    }
}

fn hash_usize(hash: &mut StableHash, value: usize) {
    let canonical = u64::try_from(value).unwrap_or(u64::MAX);
    hash.bytes(&canonical.to_le_bytes());
}

fn inclusive_byte_width(start: u8, end: u8) -> Result<usize, Error> {
    let difference = end
        .checked_sub(start)
        .ok_or(Error::InternalInvariant("non-canonical byte class range"))?;
    add(usize::from(difference), 1, Resource::CompileWork)
}

struct StableHash(u64);

impl StableHash {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn byte(&mut self, byte: u8) {
        self.0 ^= u64::from(byte);
        self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
    }

    fn bytes(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.byte(byte);
        }
    }

    const fn finish(self) -> u64 {
        self.0
    }
}

fn reserved_vec<T>(length: usize, resource: Resource) -> Result<Vec<T>, Error> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(length)
        .map_err(|_| Error::AllocationFailed {
            resource,
            items: length,
        })?;
    Ok(values)
}

fn vector_capacity_bytes<T>(values: &Vec<T>) -> Result<usize, Error> {
    mul(
        values.capacity(),
        core::mem::size_of::<T>(),
        Resource::ProgramBytes,
    )
}

fn exact_vector_bytes<T>(values: &ExactVec<T>) -> Result<usize, Error> {
    mul(
        values.capacity(),
        core::mem::size_of::<T>(),
        Resource::ProgramBytes,
    )
}

fn reserved_queue(length: usize) -> Result<VecDeque<usize>, Error> {
    let mut queue = VecDeque::new();
    queue
        .try_reserve(length)
        .map_err(|_| Error::AllocationFailed {
            resource: Resource::TemporaryStates,
            items: length,
        })?;
    Ok(queue)
}

fn exact_program_vec<T>(capacity: usize) -> Result<ExactVec<T>, Error> {
    ExactVec::try_with_capacity(capacity).map_err(|error| match error {
        CopyError::LayoutOverflow => Error::ArithmeticOverflow {
            resource: Resource::ProgramBytes,
        },
        CopyError::AllocationFailed => Error::AllocationFailed {
            resource: Resource::ProgramBytes,
            items: capacity,
        },
    })
}

fn retain_exact_program_vec<T>(values: Vec<T>) -> Result<ExactVec<T>, Error> {
    let mut retained = exact_program_vec(values.len())?;
    for value in values {
        retained.try_push(value).map_err(|_| {
            Error::InternalInvariant("exact retained program allocation changed capacity")
        })?;
    }
    Ok(retained)
}

fn zeroed_exact_program_vec(length: usize) -> Result<ExactVec<usize>, Error> {
    let mut values = exact_program_vec(length)?;
    for _ in 0..length {
        values.try_push(0).map_err(|_| {
            Error::InternalInvariant("exact zeroed program allocation changed capacity")
        })?;
    }
    Ok(values)
}

fn zeroed_vec(length: usize, resource: Resource) -> Result<Vec<usize>, Error> {
    let mut values = reserved_vec(length, resource)?;
    values.resize(length, 0);
    Ok(values)
}

#[cfg(test)]
mod tests {
    use regex_syntax::{ParserBuilder, hir::Look};

    use super::*;

    const ADVERSARIAL_ANALYSIS_WORK: usize = 2_368;
    const ADVERSARIAL_ANALYSIS_ONE_BELOW: usize = 2_367;
    const ADVERSARIAL_RETAINED_WORK: usize = 2_888;
    const ADVERSARIAL_RETAINED_ONE_BELOW: usize = 2_887;

    fn suffix_adversary(ninth_is_duplicate: bool) -> Hir {
        let looks = [
            Look::Start,
            Look::End,
            Look::StartLF,
            Look::EndLF,
            Look::StartCRLF,
            Look::EndCRLF,
            Look::WordAscii,
            Look::WordAsciiNegate,
            Look::WordStartAscii,
        ];
        let branches = looks
            .into_iter()
            .enumerate()
            .map(|(index, look)| {
                let mut suffix = vec![b'x'; 64];
                suffix[63] = if ninth_is_duplicate && index == 8 {
                    7
                } else {
                    u8::try_from(index).expect("nine branches fit in u8")
                };
                Hir::concat(vec![Hir::look(look), Hir::literal(suffix)])
            })
            .collect();
        let hir = Hir::alternation(branches);
        assert!(matches!(
            hir.kind(),
            HirKind::Alternation(branches) if branches.len() == 9
        ));
        hir
    }

    fn suffix_budget(max_work: usize) -> CompileBudget {
        CompileBudget::new(CompileLimits {
            max_work,
            ..CompileLimits::default()
        })
    }

    fn four_range_unicode_class() -> Hir {
        ParserBuilder::new()
            .utf8(false)
            .unicode(true)
            .build()
            .parse(r"[\u{100}\u{102}\u{104}\u{106}-\u{107}]")
            .unwrap()
    }

    fn ascii_unicode_class() -> Hir {
        ParserBuilder::new()
            .utf8(false)
            .unicode(true)
            .build()
            .parse("[a-z]")
            .unwrap()
    }

    fn parse_bytes(pattern: &str) -> Hir {
        ParserBuilder::new()
            .utf8(false)
            .unicode(false)
            .build()
            .parse(pattern)
            .unwrap()
    }

    #[test]
    fn terminal_frontier_seed_is_hir_derived_capture_transparent_and_exactly_charged() {
        let hir = parse_bytes(r"(?P<root>cargo)[\\/][^/]+[\\/]");
        let mut census = suffix_budget(CompileLimits::default().max_work);
        let (suffixes, seed) =
            execution_seeds(&hir, RustByteProfile::PINNED_1_12_4, &mut census).unwrap();
        assert!(suffixes.is_empty());
        assert_eq!(seed.prefix_bytes(), b"cargo");
        assert_eq!(seed.terminal_count(), 2);
        assert!(seed.terminal_matches(b'/'));
        assert!(seed.terminal_matches(b'\\'));
        let exact_work = census.accounting.work;

        let mut exact = suffix_budget(exact_work);
        execution_seeds(&hir, RustByteProfile::PINNED_1_12_4, &mut exact).unwrap();
        assert_eq!(exact.accounting.work, exact_work);
        let mut one_below = suffix_budget(exact_work - 1);
        assert_eq!(
            execution_seeds(&hir, RustByteProfile::PINNED_1_12_4, &mut one_below,).unwrap_err(),
            Error::ResourceLimit {
                resource: Resource::CompileWork,
                required: exact_work,
                limit: exact_work - 1,
            }
        );
    }

    #[test]
    fn terminal_frontier_leading_literal_uses_common_prefix_and_refuses_nullable_or_scalar() {
        let cases = [
            (r"(?:cargo.*|cargoes.*)[\\/]", b"cargo".as_slice()),
            (r"(?:cargo.*|carpet.*)[\\/]", b"car".as_slice()),
        ];
        for (pattern, expected) in cases {
            let hir = parse_bytes(pattern);
            let mut budget = suffix_budget(CompileLimits::default().max_work);
            let (_, seed) =
                execution_seeds(&hir, RustByteProfile::PINNED_1_12_4, &mut budget).unwrap();
            assert_eq!(seed.prefix_bytes(), expected, "{pattern}");
        }

        for pattern in [
            r"(?:cargo|dog).*[\\/]",
            r"(?:cargo|).*[\\/]",
            r".*cargo[\\/]",
            r"cargo/.*/",
            r"cargo/.*/|cargo\\.*\\",
        ] {
            let hir = parse_bytes(pattern);
            let mut budget = suffix_budget(CompileLimits::default().max_work);
            let (_, seed) =
                execution_seeds(&hir, RustByteProfile::PINNED_1_12_4, &mut budget).unwrap();
            assert!(seed.is_empty(), "{pattern}");
        }

        let hir = ParserBuilder::new()
            .utf8(false)
            .unicode(true)
            .build()
            .parse(r"cargo.*[\\/]")
            .unwrap();
        let mut budget = suffix_budget(CompileLimits::default().max_work);
        let (_, seed) = execution_seeds(
            &hir,
            RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
            &mut budget,
        )
        .unwrap();
        assert!(seed.is_empty());
    }

    #[test]
    fn terminal_frontier_persistent_bytes_and_full_compile_work_are_exact() {
        let hir = parse_bytes(r"cargo[\\/]registry[\\/]src[\\/].*[\\/]");
        let compiled = CompiledRegex::from_hir(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        let accounting = compiled.compile_accounting();
        assert!(accounting.program_bytes >= core::mem::size_of::<TerminalFrontierSeed>());
        let exact = CompileLimits {
            max_program_bytes: accounting.program_bytes,
            max_work: accounting.work,
            ..CompileLimits::default()
        };
        let replay = CompiledRegex::from_hir(&hir, RustByteProfile::PINNED_1_12_4, exact).unwrap();
        assert_eq!(replay.compile_accounting(), accounting);

        assert!(matches!(
            CompiledRegex::from_hir(
                &hir,
                RustByteProfile::PINNED_1_12_4,
                CompileLimits {
                    max_program_bytes: accounting.program_bytes - 1,
                    ..exact
                },
            ),
            Err(Error::ResourceLimit {
                resource: Resource::ProgramBytes,
                ..
            })
        ));
        assert!(matches!(
            CompiledRegex::from_hir(
                &hir,
                RustByteProfile::PINNED_1_12_4,
                CompileLimits {
                    max_work: accounting.work - 1,
                    ..exact
                },
            ),
            Err(Error::ResourceLimit {
                resource: Resource::CompileWork,
                ..
            })
        ));
    }

    #[test]
    fn scalar_construction_charges_ranges_and_one_continuation_set_exactly() {
        // Four canonical-range copies, 64 continuation-byte insertions, one
        // two-byte continuation state and one scalar state: 4 + 64 + 1 + 1.
        const EXACT_WORK: usize = 70;
        let hir = four_range_unicode_class();
        let HirKind::Class(Class::Unicode(class)) = hir.kind() else {
            panic!("fixture must remain one Unicode class")
        };

        let mut exact = CompileBudget::new(CompileLimits {
            max_work: EXACT_WORK,
            ..CompileLimits::default()
        });
        {
            let mut builder = Builder::new(
                CompileLimits::default().max_program_states,
                RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
                CapturePolicy::Reject,
                0,
                &mut exact,
            );
            builder.compile_unicode_class(class, 0).unwrap();
            assert_eq!(builder.slots.len(), 2);
        }
        assert_eq!(exact.accounting.work, EXACT_WORK);

        let mut one_below = CompileBudget::new(CompileLimits {
            max_work: EXACT_WORK - 1,
            ..CompileLimits::default()
        });
        let error = Builder::new(
            CompileLimits::default().max_program_states,
            RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
            CapturePolicy::Reject,
            0,
            &mut one_below,
        )
        .compile_unicode_class(class, 0)
        .unwrap_err();
        assert_eq!(
            error,
            Error::ResourceLimit {
                resource: Resource::CompileWork,
                required: EXACT_WORK,
                limit: EXACT_WORK - 1,
            }
        );
        assert_eq!(one_below.accounting.work, EXACT_WORK - 1);
        assert_eq!(one_below.current_temporary_states, 1);

        // A one-byte class never constructs the unused continuation set.
        let ascii = ascii_unicode_class();
        let HirKind::Class(Class::Unicode(ascii)) = ascii.kind() else {
            panic!("fixture must remain one Unicode class")
        };
        let mut ascii_budget = CompileBudget::new(CompileLimits {
            max_work: 2,
            ..CompileLimits::default()
        });
        Builder::new(
            CompileLimits::default().max_program_states,
            RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
            CapturePolicy::Reject,
            0,
            &mut ascii_budget,
        )
        .compile_unicode_class(ascii, 0)
        .unwrap();
        assert_eq!(ascii_budget.accounting.work, 2);
    }

    #[test]
    fn required_suffix_ineligible_analysis_exact_limit_and_one_below() {
        // 19 visited nodes + 9 alternation branches + 36 worst-case
        // 64-byte dedup comparisons, each charged as min(lengths) + 1.
        let hir = suffix_adversary(false);
        let mut exact = suffix_budget(ADVERSARIAL_ANALYSIS_WORK);
        let suffixes = required_suffixes(&hir, &mut exact).unwrap();
        assert!(suffixes.is_empty());
        assert_eq!(ADVERSARIAL_ANALYSIS_WORK, exact.accounting.work);

        let mut one_below = suffix_budget(ADVERSARIAL_ANALYSIS_ONE_BELOW);
        assert_eq!(
            Error::ResourceLimit {
                resource: Resource::CompileWork,
                required: ADVERSARIAL_ANALYSIS_WORK,
                limit: ADVERSARIAL_ANALYSIS_ONE_BELOW,
            },
            required_suffixes(&hir, &mut one_below).unwrap_err()
        );
    }

    #[test]
    fn required_suffix_retained_copy_exact_limit_and_one_below() {
        // The same adversarial analysis retains eight 64-byte suffixes when
        // the ninth branch duplicates the eighth, adding 8 endpoint writes
        // and 512 byte copies to the preflighted work.
        let hir = suffix_adversary(true);
        let mut exact = suffix_budget(ADVERSARIAL_RETAINED_WORK);
        let suffixes = required_suffixes(&hir, &mut exact).unwrap();
        assert_eq!(8, suffixes.ends.len());
        assert_eq!(512, suffixes.bytes.len());
        assert_eq!(ADVERSARIAL_RETAINED_WORK, exact.accounting.work);

        let retained_bytes = suffixes.retained_bytes().unwrap();
        assert_eq!(retained_bytes, 512 + 8 * core::mem::size_of::<usize>());
        let mut exact_bytes = CompileBudget::new(CompileLimits {
            max_work: ADVERSARIAL_RETAINED_WORK,
            max_program_bytes: retained_bytes,
            ..CompileLimits::default()
        });
        assert_eq!(
            required_suffixes(&hir, &mut exact_bytes)
                .unwrap()
                .retained_bytes()
                .unwrap(),
            retained_bytes
        );
        let mut one_below_bytes = CompileBudget::new(CompileLimits {
            max_work: ADVERSARIAL_RETAINED_WORK,
            max_program_bytes: retained_bytes - 1,
            ..CompileLimits::default()
        });
        assert_eq!(
            required_suffixes(&hir, &mut one_below_bytes).unwrap_err(),
            Error::ResourceLimit {
                resource: Resource::ProgramBytes,
                required: retained_bytes,
                limit: retained_bytes - 1,
            }
        );
        assert_eq!(one_below_bytes.accounting.work, ADVERSARIAL_ANALYSIS_WORK);

        let mut one_below = suffix_budget(ADVERSARIAL_RETAINED_ONE_BELOW);
        assert_eq!(
            Error::ResourceLimit {
                resource: Resource::CompileWork,
                required: ADVERSARIAL_RETAINED_WORK,
                limit: ADVERSARIAL_RETAINED_ONE_BELOW,
            },
            required_suffixes(&hir, &mut one_below).unwrap_err()
        );
    }

    #[test]
    fn retained_components_preflight_general_and_certificate_bytes_before_work() {
        const SUFFIX_BYTES: usize = 17;
        const ANCHOR_BYTES: usize = 23;
        let retained_bytes = SUFFIX_BYTES + ANCHOR_BYTES;
        let state_bytes = core::mem::size_of::<Inst>() + 2 * core::mem::size_of::<usize>();
        let exact_limit = retained_bytes + state_bytes;

        let mut exact = CompileBudget::new(CompileLimits {
            max_program_bytes: exact_limit,
            ..CompileLimits::default()
        });
        let exact_insts = {
            let mut builder = Builder::new(
                CompileLimits::default().max_program_states,
                RustByteProfile::PINNED_1_12_4,
                CapturePolicy::Reject,
                retained_bytes,
                &mut exact,
            );
            assert_eq!(builder.slots.capacity(), 0);
            builder.push(Inst::Match).unwrap();
            builder.finish().unwrap()
        };
        assert_eq!(exact_insts.len(), 1);
        assert_eq!(
            core::mem::size_of_val(&*exact_insts),
            core::mem::size_of::<Inst>()
        );
        assert_eq!(exact.accounting.work, 2);
        assert_eq!(exact.current_temporary_states, 1);

        let mut one_below = CompileBudget::new(CompileLimits {
            max_program_bytes: exact_limit - 1,
            ..CompileLimits::default()
        });
        {
            let mut builder = Builder::new(
                CompileLimits::default().max_program_states,
                RustByteProfile::PINNED_1_12_4,
                CapturePolicy::Reject,
                retained_bytes,
                &mut one_below,
            );
            assert_eq!(
                builder.push(Inst::Match).unwrap_err(),
                Error::ResourceLimit {
                    resource: Resource::ProgramBytes,
                    required: exact_limit,
                    limit: exact_limit - 1,
                }
            );
            assert!(builder.slots.is_empty());
            assert_eq!(builder.slots.capacity(), 0);
        }
        assert_eq!(one_below.accounting.work, 0);
        assert_eq!(one_below.current_temporary_states, 0);

        let mut insts = exact_program_vec(1).unwrap();
        insts.try_push(Inst::Match).unwrap();
        let certificate_limit = preflight_certification_program_bytes(
            insts.len(),
            insts.len(),
            0,
            retained_bytes,
            usize::MAX,
        )
        .unwrap();
        let mut certificate_exact = CompileBudget::new(CompileLimits {
            max_program_bytes: certificate_limit,
            ..CompileLimits::default()
        });
        let certificate =
            certify_program(&insts, 0, retained_bytes, &mut certificate_exact).unwrap();
        assert_eq!(certificate.epsilon_order.len(), insts.len());
        assert_eq!(certificate.split_rank.len(), insts.len());
        assert_eq!(
            core::mem::size_of_val(&*certificate.epsilon_order),
            core::mem::size_of::<usize>()
        );
        assert_eq!(
            core::mem::size_of_val(&*certificate.split_rank),
            core::mem::size_of::<usize>()
        );
        let mut certificate_one_below = CompileBudget::new(CompileLimits {
            max_program_bytes: certificate_limit - 1,
            ..CompileLimits::default()
        });
        let Err(certificate_error) =
            certify_program(&insts, 0, retained_bytes, &mut certificate_one_below)
        else {
            panic!("one-below certificate admission must refuse");
        };
        assert_eq!(
            certificate_error,
            Error::ResourceLimit {
                resource: Resource::ProgramBytes,
                required: certificate_limit,
                limit: certificate_limit - 1,
            }
        );
        assert_eq!(certificate_one_below.accounting.work, 0);
        assert_eq!(certificate_one_below.current_temporary_states, 0);
    }

    #[test]
    fn required_anchor_combined_program_bytes_are_exact_and_one_below() {
        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(r"[\w]+://[^/\s?#]+[^\s?#]+(?:\?[^\s#]*)?(?:#[^\s]*)?")
            .unwrap();
        let baseline = CompiledRegex::from_hir(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        let accounting = baseline.compile_accounting();
        assert_eq!(accounting.required_internal_anchors, 1);
        assert!(accounting.required_internal_anchor_persistent_bytes > 0);
        let exact = CompileLimits {
            max_program_bytes: accounting.program_bytes,
            ..CompileLimits::default()
        };
        CompiledRegex::from_hir(&hir, RustByteProfile::PINNED_1_12_4, exact).unwrap();
        let one_below = CompileLimits {
            max_program_bytes: accounting.program_bytes - 1,
            ..CompileLimits::default()
        };
        assert_eq!(
            CompiledRegex::from_hir(&hir, RustByteProfile::PINNED_1_12_4, one_below).unwrap_err(),
            Error::ResourceLimit {
                resource: Resource::ProgramBytes,
                required: accounting.program_bytes,
                limit: accounting.program_bytes - 1,
            }
        );
    }

    #[test]
    fn terminal_byte_class_suffix_copy_is_exact_and_bounded() {
        const EXACT_WORK: usize = 10;
        let hir = ParserBuilder::new()
            .utf8(false)
            .unicode(false)
            .build()
            .parse(r#"["']"#)
            .unwrap();
        let mut exact = suffix_budget(EXACT_WORK);
        let suffixes = required_suffixes(&hir, &mut exact).unwrap();
        assert_eq!(
            suffixes.iter().collect::<Vec<_>>(),
            [b"\"".as_slice(), b"'".as_slice()]
        );
        assert_eq!(EXACT_WORK, exact.accounting.work);

        let mut one_below = suffix_budget(EXACT_WORK - 1);
        assert_eq!(
            Error::ResourceLimit {
                resource: Resource::CompileWork,
                required: EXACT_WORK,
                limit: EXACT_WORK - 1,
            },
            required_suffixes(&hir, &mut one_below).unwrap_err()
        );

        let too_wide = ParserBuilder::new()
            .utf8(false)
            .unicode(false)
            .build()
            .parse("[a-i]")
            .unwrap();
        let mut bounded = suffix_budget(CompileLimits::default().max_work);
        assert!(
            required_suffixes(&too_wide, &mut bounded)
                .unwrap()
                .is_empty()
        );

        let unbounded = ParserBuilder::new()
            .utf8(false)
            .unicode(false)
            .build()
            .parse(r#"[a-z]+["']"#)
            .unwrap();
        let mut bounded = suffix_budget(CompileLimits::default().max_work);
        assert!(
            required_suffixes(&unbounded, &mut bounded)
                .unwrap()
                .is_empty()
        );
    }

    fn required_anchor_plan_id(
        prefix: &[u8],
        anchor: &[u8],
        head: &[u8],
        tail: &[u8],
        optional: Option<(u8, &[u8])>,
    ) -> PlanId {
        let mut continuation = fre_kernels::RequiredInternalAnchorContinuationSource::new(
            fre_kernels::RequiredInternalAnchorByteClass::from_bytes(head),
            fre_kernels::RequiredInternalAnchorByteClass::from_bytes(tail),
        );
        if let Some((introducer, class)) = optional {
            continuation.optional[0] =
                Some(fre_kernels::RequiredInternalAnchorOptionalStageSource {
                    introducer,
                    class: fre_kernels::RequiredInternalAnchorByteClass::from_bytes(class),
                });
            continuation.optional_count = 1;
        }
        let plan = fre_kernels::RequiredInternalAnchorPlan::build(
            fre_kernels::RequiredInternalAnchorByteClass::from_bytes(prefix),
            anchor,
            continuation,
            fre_kernels::RequiredInternalAnchorBuildLimits::default(),
        )
        .expect("valid identity fixture");
        let mut budget = CompileBudget::new(CompileLimits::default());
        bind_required_internal_anchor_identity(PlanId([0x5a; 16]), &plan, &mut budget)
            .expect("bind required-anchor identity")
    }

    #[test]
    fn required_anchor_identity_binds_every_resource_bearing_configuration_field() {
        let base = required_anchor_plan_id(b"a", b"X", b"b", b"bc", None);
        for changed in [
            required_anchor_plan_id(b"d", b"X", b"b", b"bc", None),
            required_anchor_plan_id(b"a", b"Y", b"b", b"bc", None),
            required_anchor_plan_id(b"a", b"X", b"c", b"bc", None),
            required_anchor_plan_id(b"a", b"X", b"b", b"bd", None),
            required_anchor_plan_id(b"a", b"X", b"b", b"bc", Some((b'?', b"d"))),
            required_anchor_plan_id(b"a", b"X", b"b", b"bc", Some((b'!', b"d"))),
            required_anchor_plan_id(b"a", b"X", b"b", b"bc", Some((b'?', b"e"))),
        ] {
            assert_ne!(base, changed);
        }
    }
}
