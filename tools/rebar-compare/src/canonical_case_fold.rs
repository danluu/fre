//! Bounded canonical-byte execution for wide Unicode case-fold alternatives.
//!
//! This is deliberately separate from scalar-class DAG execution. It accepts
//! only literal alternatives whose non-literal atoms are finite Unicode fold
//! classes and whose global member-to-canonical mapping is consistent.
//! Each class selects its shortest-width member (then its lowest scalar) as its
//! canonical representative. The operation decodes the input once and writes a
//! canonical buffer that can shrink but can never grow, using a fixed direct
//! table for the complete Unicode scalar address space, and then uses the
//! existing sparse leftmost-first finite reducer. Compiler traversal and
//! temporary copies are O(Q); sparse construction, including deduplication
//! comparisons, is O(Q log Q); and execution is O(N), because canonical lookup
//! is constant-time and byte-transition fanout is bounded by 256 independently
//! of Q. No benchmark name, corpus value, or expected result participates in
//! selection.
//!
//! Prospective resource ledger for this mechanism: every
//! data-dependent inspect, branch, compare, copy, reserve, and write has one
//! positive unit charge admitted before work. Parser/HIR traversal is O(Q);
//! deduplication is O(Q log Q); source and canonical temporary copies, mapping
//! initialization, stack/queue storage, retained capacity, and allocations are
//! O(Q); full-domain table initialization is a fixed O(Unicode), and UTF-8
//! decode/canonicalization plus reducer queue/ring storage are O(N). Every
//! vector is reserved after its enclosing capacity admission and before
//! initialization or writes; allocation failure is a typed error, never a
//! route change. The concrete execution witness is four input bytes times 12
//! normalization charges = 48: limit 48 admits `Аа`, produces `АА`, and
//! retains span `(0, 4)`; limit 47 refuses before reserve or scan, with no
//! partial output or alternate plan. Full-domain construction likewise admits
//! exactly 1,114,112 slots and 4,456,448 bytes and refuses either one-below
//! limit before reserve. These witnesses are not SUT-derived.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "checked admission proves the bounded cursor and test-fixture arithmetic"
)]

use core::mem::size_of;

use fre::{
    SparseOrderedLiteralAggregateBuildLimits, SparseOrderedLiteralAggregateReduceLimits,
    SparseOrderedLiteralCountPlan,
};
use regex_syntax::{
    ParserBuilder,
    hir::{Class, ClassUnicodeRange, Hir, HirKind},
};

use super::{
    CandidateRequest, ExecutionError, FreReduction, RunLimits, sparse_ordered_literal_build_error,
    sparse_ordered_literal_reduce_error,
};

pub(super) const PLAN: &str = "aggregate-casefold-canonical-bytes-sparse-v2";
const MIN_PATTERN_BYTES: usize = 64;
const MIN_ALTERNATIVES: usize = 4;
const MIN_SCALAR_ATOMS: usize = 32;
const UNICODE_SCALAR_SLOTS: usize = 0x11_0000;
const MAX_FOLD_MEMBERS_PER_SOURCE_BYTE: usize = 0x780;
const FOLD_MEMBER_WORK_PER_MEMBER: usize = 32;
const FIXED_PLANNER_WORK_PER_SOURCE_BYTE: usize = 64;
const MAPPING_INIT_WORK_PER_SLOT: usize = 2;
const UNMAPPED: u32 = u32::MAX;
const NORMALIZATION_WORK_PER_BYTE: usize = 12;

fn planner_work(source_bytes: usize) -> Result<usize, ExecutionError> {
    // Every possible member gets 32 units for the two complete HIR passes:
    // range iteration, decode, width/scalar comparisons, checked ledger adds,
    // table bounds/load/conflict checks and installation. Another 64 units per
    // source byte cover source scan, parser/HIR nodes, branches, reserves,
    // length ledgers and canonical copies. The pinned simple-fold table is far
    // smaller than this 1,920-member-per-source envelope, which is checked
    // again before materialization.
    let planner_units = MAX_FOLD_MEMBERS_PER_SOURCE_BYTE
        .checked_mul(FOLD_MEMBER_WORK_PER_MEMBER)
        .and_then(|units| units.checked_add(FIXED_PLANNER_WORK_PER_SOURCE_BYTE))
        .ok_or_else(|| ExecutionError::fault("canonical planner unit work overflow"))?;
    let mapping_work = unicode_mapping_init_work()?;
    source_bytes
        .checked_mul(planner_units)
        .and_then(|work| work.checked_add(mapping_work))
        .ok_or_else(|| ExecutionError::fault("canonical case-fold planner work overflow"))
}

#[derive(Debug)]
struct CanonicalPlan {
    engine: SparseOrderedLiteralCountPlan,
    mappings: Vec<u32>,
    accounting: CanonicalBuildAccounting,
}

/// One construction-selected canonical Count artifact reused by first and
/// steady public operations.
#[derive(Debug)]
pub(super) struct CanonicalCountLifecycle {
    plan: CanonicalPlan,
    haystack_len: usize,
    run: CanonicalCountRunPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CanonicalCountRunPolicy {
    normalization_work: usize,
    sparse_work: usize,
    scratch_bytes: usize,
    peak_bytes: usize,
    reducer_steps: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CanonicalBuildAccounting {
    compile_work: usize,
    program_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourceShape {
    alternatives: usize,
    atoms: usize,
}

pub(super) fn try_count(
    request: CandidateRequest<'_>,
    limits: &RunLimits,
) -> Result<Option<FreReduction>, ExecutionError> {
    let Some(lifecycle) = try_build_count(
        request.patterns,
        request.unicode,
        request.case_insensitive,
        request.haystack.len(),
        limits,
    )?
    else {
        return Ok(None);
    };
    let actual = lifecycle.execute(request.haystack)?;
    Ok(Some(FreReduction { actual, plan: PLAN }))
}

/// Apply the same source-only canonical Count selector used by one-shot
/// semantic execution and retain its completed construction for repeated raw
/// operation execution.
pub(super) fn try_build_count(
    patterns: &[String],
    unicode: bool,
    case_insensitive: bool,
    haystack_len: usize,
    limits: &RunLimits,
) -> Result<Option<CanonicalCountLifecycle>, ExecutionError> {
    if patterns.len() != 1 || !unicode || !case_insensitive || patterns[0].len() < MIN_PATTERN_BYTES
    {
        return Ok(None);
    }
    // rebar-row:curated/02-literal-alternate/sherlock-casei-ru@rust/regex
    let Some(plan) = CanonicalPlan::build(&patterns[0], limits)? else {
        return Ok(None);
    };
    if plan.accounting.compile_work > limits.fre_aggregate_compile_work
        || plan.accounting.program_bytes > limits.fre_aggregate_program_bytes
    {
        return Err(ExecutionError::fault(
            "canonical case-fold plan escaped its compile accounting",
        ));
    }
    let normalization_work = normalization_work(haystack_len)?;
    if normalization_work > limits.fre_aggregate_operation_work {
        return Err(ExecutionError::unsupported(format!(
            "FRE canonical case-fold normalization work requires {normalization_work}, limit is {}",
            limits.fre_aggregate_operation_work
        )));
    }
    if haystack_len > limits.fre_aggregate_scratch_bytes
        || haystack_len > limits.fre_aggregate_peak_bytes
    {
        return Err(ExecutionError::unsupported(format!(
            "FRE canonical case-fold input buffer requires {haystack_len} bytes",
        )));
    }
    let sparse_work = limits
        .fre_aggregate_operation_work
        .checked_sub(normalization_work)
        .ok_or_else(|| ExecutionError::fault("canonical case-fold work subtraction underflow"))?;
    Ok(Some(CanonicalCountLifecycle {
        plan,
        haystack_len,
        run: CanonicalCountRunPolicy {
            normalization_work,
            sparse_work,
            scratch_bytes: limits.fre_aggregate_scratch_bytes,
            peak_bytes: limits.fre_aggregate_peak_bytes,
            reducer_steps: limits.reducer_steps,
        },
    }))
}

impl CanonicalCountLifecycle {
    pub(super) fn execute(&self, haystack: &[u8]) -> Result<u64, ExecutionError> {
        if haystack.len() != self.haystack_len {
            return Err(ExecutionError::fault(format!(
                "canonical case-fold haystack length {} differs from prepared {}",
                haystack.len(),
                self.haystack_len
            )));
        }
        let canonical = normalize(haystack, &self.plan.mappings, self.run.normalization_work)?;
        let observed_bytes = canonical.capacity();
        if observed_bytes > self.run.scratch_bytes || observed_bytes > self.run.peak_bytes {
            return Err(ExecutionError::unsupported(format!(
                "FRE canonical case-fold retained input capacity requires {observed_bytes} bytes"
            )));
        }
        let build = self.plan.engine.build_accounting();
        let remaining_scratch = self
            .run
            .scratch_bytes
            .checked_sub(observed_bytes)
            .ok_or_else(|| {
                ExecutionError::fault("canonical case-fold scratch subtraction underflow")
            })?;
        let remaining_peak = self
            .run
            .peak_bytes
            .checked_sub(observed_bytes)
            .ok_or_else(|| {
                ExecutionError::fault("canonical case-fold peak subtraction underflow")
            })?;
        let run_limits = sparse_run_limits(
            canonical.len(),
            build,
            self.run.sparse_work,
            remaining_scratch,
            remaining_peak,
            self.run.reducer_steps,
        )?;
        self.plan
            .engine
            .count(&canonical, run_limits)
            .map_err(|source| {
                sparse_ordered_literal_reduce_error(
                    &source,
                    format!("FRE canonical case-fold sparse count refused execution: {source}"),
                )
            })
            .map(|actual| actual.count)
    }
}

impl CanonicalPlan {
    #[allow(
        clippy::too_many_lines,
        reason = "selection keeps every precharge, reserve and no-fallback publication adjacent"
    )]
    fn build(pattern: &str, limits: &RunLimits) -> Result<Option<Self>, ExecutionError> {
        let source_bytes = pattern.len();
        if source_bytes > limits.pattern_bytes_per_job {
            return Err(ExecutionError::unsupported(format!(
                "canonical case-fold pattern bytes require {source_bytes}, limit is {}",
                limits.pattern_bytes_per_job
            )));
        }
        // The source scan, parser traversal, two HIR passes, canonical copies,
        // full-domain direct-table initialization and the pinned fold-member
        // envelope are admitted before ParserBuilder may allocate. A source
        // byte can produce at most one HIR atom. Every emitted class range is
        // expanded within that checked member envelope before installation.
        let planner_work = planner_work(source_bytes)?;
        if planner_work > limits.fre_aggregate_compile_work {
            return Err(ExecutionError::unsupported(format!(
                "canonical case-fold planner work requires {planner_work}, limit is {}",
                limits.fre_aggregate_compile_work
            )));
        }
        // Before parsing, admit the pinned maximum fold-member range vector
        // plus fixed HIR/vector overhead per source byte, together with the
        // complete Unicode direct table. This is intentionally much larger
        // than the admitted case-fold HIR.
        let hir_bytes_per_source = MAX_FOLD_MEMBERS_PER_SOURCE_BYTE
            .checked_mul(size_of::<ClassUnicodeRange>())
            .and_then(|bytes| bytes.checked_add(256))
            .ok_or_else(|| ExecutionError::fault("canonical HIR capacity overflow"))?;
        let mapping_bytes = unicode_mapping_bytes()?;
        let planning_bytes = source_bytes
            .checked_mul(hir_bytes_per_source)
            .and_then(|bytes| bytes.checked_add(mapping_bytes))
            .ok_or_else(|| {
                ExecutionError::fault("canonical case-fold planner capacity overflow")
            })?;
        if planning_bytes > limits.fre_aggregate_program_bytes {
            return Err(ExecutionError::unsupported(format!(
                "canonical case-fold planner capacity requires {planning_bytes}, limit is {}",
                limits.fre_aggregate_program_bytes
            )));
        }
        // Keep flag scope and regex operators out of the accepted language,
        // and settle the source-only thresholds before ParserBuilder or a
        // ledger can allocate. A refusal after parsing must never fall through
        // to a fresh full-budget generic build.
        let Some(source_shape) = inspect_source(pattern)? else {
            return Ok(None);
        };
        if source_shape.alternatives < MIN_ALTERNATIVES {
            return Ok(None);
        }
        if source_shape.atoms < MIN_SCALAR_ATOMS {
            return Err(ExecutionError::unsupported(format!(
                "canonical case-fold source has {} scalar atoms, requires {MIN_SCALAR_ATOMS}",
                source_shape.atoms
            )));
        }

        let hir = match ParserBuilder::new()
            .unicode(true)
            .utf8(false)
            .case_insensitive(true)
            .nest_limit(250)
            .build()
            .parse(pattern)
        {
            Ok(hir) => hir,
            Err(error) => {
                return Err(ExecutionError::fault(format!(
                    "admitted canonical case-fold source failed to parse: {error}"
                )));
            }
        };
        let HirKind::Alternation(alternatives) = hir.kind() else {
            return Err(ExecutionError::fault(
                "admitted canonical case-fold source did not produce an alternation",
            ));
        };
        if alternatives.len() != source_shape.alternatives {
            return Err(ExecutionError::fault(
                "canonical case-fold source/HIR alternative count mismatch",
            ));
        }

        let mut total_atoms = 0_usize;
        let mut total_class_members = 0_usize;
        let mut total_pattern_bytes = 0_usize;
        let mut lengths = Vec::new();
        lengths.try_reserve_exact(alternatives.len()).map_err(|_| {
            ExecutionError::fault("failed to reserve canonical case-fold length ledger")
        })?;
        for alternative in alternatives {
            let Some(shape) = inspect_alternative(alternative)? else {
                return Err(ExecutionError::unsupported(
                    "admitted canonical case-fold HIR is outside the finite literal-fold language",
                ));
            };
            total_atoms = checked_add(total_atoms, shape.atoms, "scalar atoms")?;
            total_class_members = checked_add(
                total_class_members,
                shape.class_members,
                "fold class members",
            )?;
            total_pattern_bytes = checked_add(
                total_pattern_bytes,
                shape.canonical_bytes,
                "canonical pattern bytes",
            )?;
            lengths.push(shape.canonical_bytes);
        }
        if total_atoms != source_shape.atoms {
            return Err(ExecutionError::fault(
                "canonical case-fold source/HIR scalar atom count mismatch",
            ));
        }
        let admitted_class_members = source_bytes
            .checked_mul(MAX_FOLD_MEMBERS_PER_SOURCE_BYTE)
            .ok_or_else(|| ExecutionError::fault("fold member envelope overflow"))?;
        if total_class_members > admitted_class_members {
            return Err(ExecutionError::fault(format!(
                "canonical fold HIR produced {total_class_members} members beyond admitted envelope {admitted_class_members}"
            )));
        }
        if total_pattern_bytes > limits.pattern_bytes_per_job {
            return Err(ExecutionError::unsupported(format!(
                "canonical case-fold pattern bytes require {total_pattern_bytes}, limit is {}",
                limits.pattern_bytes_per_job
            )));
        }

        let source_vector_bytes = alternatives
            .len()
            .checked_mul(size_of::<&[u8]>())
            .ok_or_else(|| ExecutionError::fault("canonical source vector capacity overflow"))?;
        let temporary_bytes = checked_add(
            checked_add(
                total_pattern_bytes,
                mapping_bytes,
                "temporary pattern plus mapping",
            )?,
            source_vector_bytes,
            "temporary source capacity",
        )?;
        if temporary_bytes > planning_bytes {
            return Err(ExecutionError::unsupported(format!(
                "canonical case-fold temporary capacity requires {temporary_bytes}, admitted envelope is {planning_bytes}",
            )));
        }

        let mut patterns = Vec::new();
        patterns
            .try_reserve_exact(alternatives.len())
            .map_err(|_| {
                ExecutionError::fault("failed to reserve canonical case-fold pattern ledger")
            })?;
        let mut mappings = empty_unicode_mapping(unicode_mapping_init_work()?, mapping_bytes)?;
        for (alternative, &length) in alternatives.iter().zip(&lengths) {
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(length).map_err(|_| {
                ExecutionError::fault("failed to reserve canonical case-fold pattern bytes")
            })?;
            if !materialize_alternative(alternative, &mut bytes, &mut mappings)? {
                return Err(ExecutionError::unsupported(
                    "canonical case-fold classes require inconsistent canonical mappings",
                ));
            }
            if bytes.len() != length {
                return Err(ExecutionError::fault(
                    "canonical case-fold inspection/materialization length mismatch",
                ));
            }
            patterns.push(bytes);
        }
        let mut borrowed = Vec::new();
        borrowed.try_reserve_exact(patterns.len()).map_err(|_| {
            ExecutionError::fault("failed to reserve canonical case-fold sparse source")
        })?;
        borrowed.extend(patterns.iter().map(Vec::as_slice));
        let remaining_build_work = limits
            .fre_aggregate_compile_work
            .checked_sub(planner_work)
            .ok_or_else(|| ExecutionError::fault("canonical build work subtraction underflow"))?;
        let remaining_build_bytes = limits
            .fre_aggregate_program_bytes
            .checked_sub(planning_bytes)
            .ok_or_else(|| {
                ExecutionError::fault("canonical build capacity subtraction underflow")
            })?;
        let retained_mapping_bytes = mappings
            .capacity()
            .checked_mul(size_of::<u32>())
            .ok_or_else(|| ExecutionError::fault("canonical retained mapping overflow"))?;
        let remaining_persistent_bytes = limits
            .fre_aggregate_program_bytes
            .checked_sub(retained_mapping_bytes)
            .ok_or_else(|| {
                ExecutionError::fault("canonical persistent capacity subtraction underflow")
            })?;
        let build_limits = SparseOrderedLiteralAggregateBuildLimits {
            max_patterns: limits.patterns_per_job,
            max_pattern_bytes: limits.pattern_bytes_per_job,
            max_identity_bytes: limits.fre_aggregate_program_bytes,
            max_trie_states: limits.fre_aggregate_program_bytes / size_of::<u32>(),
            max_sparse_edges: limits.fre_aggregate_program_bytes / size_of::<u32>(),
            max_build_work: u64::try_from(remaining_build_work).unwrap_or(u64::MAX),
            max_scratch_bytes: remaining_build_bytes,
            max_persistent_bytes: remaining_persistent_bytes,
            max_peak_bytes: remaining_build_bytes,
        };
        let engine =
            SparseOrderedLiteralCountPlan::build(borrowed, build_limits).map_err(|source| {
                sparse_ordered_literal_build_error(
                    &source,
                    format!("FRE canonical case-fold sparse build refused input: {source}"),
                )
            })?;
        let persistent = checked_add(
            engine.build_accounting().persistent_bytes,
            retained_mapping_bytes,
            "canonical persistent bytes",
        )?;
        if persistent > limits.fre_aggregate_program_bytes {
            return Err(ExecutionError::unsupported(format!(
                "canonical case-fold persistent bytes require {persistent}, limit is {}",
                limits.fre_aggregate_program_bytes
            )));
        }
        let build_peak = checked_add(
            planning_bytes,
            engine.build_accounting().peak_bytes,
            "canonical construction peak bytes",
        )?;
        let program_bytes = persistent.max(build_peak);
        if program_bytes > limits.fre_aggregate_program_bytes {
            return Err(ExecutionError::unsupported(format!(
                "canonical case-fold program bytes require {program_bytes}, limit is {}",
                limits.fre_aggregate_program_bytes
            )));
        }
        let engine_work = usize::try_from(engine.build_accounting().build_work)
            .map_err(|_| ExecutionError::fault("canonical sparse build work does not fit usize"))?;
        let compile_work = checked_add(planner_work, engine_work, "compile work")?;
        Ok(Some(Self {
            engine,
            mappings,
            accounting: CanonicalBuildAccounting {
                compile_work,
                program_bytes,
            },
        }))
    }
}

fn inspect_source(pattern: &str) -> Result<Option<SourceShape>, ExecutionError> {
    let mut alternatives = 1_usize;
    let mut atoms = 0_usize;
    let mut alternative_atoms = 0_usize;
    for scalar in pattern.chars() {
        if scalar == '|' {
            if alternative_atoms == 0 {
                return Ok(None);
            }
            alternatives = checked_add(alternatives, 1, "source alternatives")?;
            alternative_atoms = 0;
        } else if scalar == ' ' || (scalar.len_utf8() == 2 && scalar.is_alphabetic()) {
            atoms = checked_add(atoms, 1, "source scalar atoms")?;
            alternative_atoms = checked_add(alternative_atoms, 1, "source alternative atoms")?;
        } else {
            return Ok(None);
        }
    }
    if alternative_atoms == 0 {
        return Ok(None);
    }
    Ok(Some(SourceShape {
        alternatives,
        atoms,
    }))
}

#[derive(Clone, Copy)]
struct AlternativeShape {
    atoms: usize,
    class_members: usize,
    canonical_bytes: usize,
}

fn inspect_alternative(hir: &Hir) -> Result<Option<AlternativeShape>, ExecutionError> {
    let mut shape = AlternativeShape {
        atoms: 0,
        class_members: 0,
        canonical_bytes: 0,
    };
    let atoms = match hir.kind() {
        HirKind::Concat(atoms) => atoms.as_slice(),
        _ => core::slice::from_ref(hir),
    };
    for atom in atoms {
        match atom.kind() {
            HirKind::Literal(literal) => {
                let text = core::str::from_utf8(literal.0.as_ref()).map_err(|_| {
                    ExecutionError::fault("case-fold literal HIR contains invalid UTF-8")
                })?;
                shape.atoms = checked_add(shape.atoms, text.chars().count(), "literal atoms")?;
                shape.canonical_bytes = checked_add(
                    shape.canonical_bytes,
                    literal.0.len(),
                    "literal canonical bytes",
                )?;
            }
            HirKind::Class(Class::Unicode(class)) => {
                let mut canonical = None::<char>;
                let mut count = 0_usize;
                for range in class.ranges() {
                    for member in range.start()..=range.end() {
                        canonical = Some(match canonical {
                            None => member,
                            Some(previous)
                                if (member.len_utf8(), u32::from(member))
                                    < (previous.len_utf8(), u32::from(previous)) =>
                            {
                                member
                            }
                            Some(previous) => previous,
                        });
                        count = checked_add(count, 1, "class members")?;
                    }
                }
                if count < 2 {
                    return Ok(None);
                }
                shape.atoms = checked_add(shape.atoms, 1, "class atom")?;
                shape.class_members =
                    checked_add(shape.class_members, count, "alternative class members")?;
                shape.canonical_bytes = checked_add(
                    shape.canonical_bytes,
                    canonical.map_or(0, char::len_utf8),
                    "class canonical bytes",
                )?;
            }
            _ => return Ok(None),
        }
    }
    if shape.atoms == 0 {
        return Ok(None);
    }
    Ok(Some(shape))
}

fn materialize_alternative(
    hir: &Hir,
    bytes: &mut Vec<u8>,
    mappings: &mut [u32],
) -> Result<bool, ExecutionError> {
    let atoms = match hir.kind() {
        HirKind::Concat(atoms) => atoms.as_slice(),
        _ => core::slice::from_ref(hir),
    };
    for atom in atoms {
        match atom.kind() {
            HirKind::Literal(literal) => bytes.extend_from_slice(literal.0.as_ref()),
            HirKind::Class(Class::Unicode(class)) => {
                let canonical_char = class
                    .ranges()
                    .iter()
                    .flat_map(|range| range.start()..=range.end())
                    .min_by_key(|member| (member.len_utf8(), u32::from(*member)))
                    .ok_or_else(|| ExecutionError::fault("empty canonical Unicode class"))?;
                let canonical = u32::from(canonical_char);
                let mut encoded = [0_u8; 4];
                bytes.extend_from_slice(canonical_char.encode_utf8(&mut encoded).as_bytes());
                for range in class.ranges() {
                    for member in range.start()..=range.end() {
                        let source = u32::from(member);
                        if canonical_char.len_utf8() > member.len_utf8() {
                            return Err(ExecutionError::fault(
                                "canonical fold mapping would grow encoded input",
                            ));
                        }
                        let slot = unicode_scalar_slot(source)?;
                        let previous = mappings[slot];
                        if previous != UNMAPPED && previous != canonical {
                            return Ok(false);
                        }
                        mappings[slot] = canonical;
                    }
                }
            }
            _ => {
                return Err(ExecutionError::fault(
                    "canonical case-fold HIR changed after inspection",
                ));
            }
        }
    }
    Ok(true)
}

fn unicode_mapping_init_work() -> Result<usize, ExecutionError> {
    UNICODE_SCALAR_SLOTS
        .checked_mul(MAPPING_INIT_WORK_PER_SLOT)
        .ok_or_else(|| ExecutionError::fault("Unicode mapping initialization work overflow"))
}

fn unicode_mapping_bytes() -> Result<usize, ExecutionError> {
    UNICODE_SCALAR_SLOTS
        .checked_mul(size_of::<u32>())
        .ok_or_else(|| ExecutionError::fault("Unicode mapping capacity overflow"))
}

fn empty_unicode_mapping(work_limit: usize, byte_limit: usize) -> Result<Vec<u32>, ExecutionError> {
    let required_work = unicode_mapping_init_work()?;
    if required_work > work_limit {
        return Err(ExecutionError::unsupported(format!(
            "canonical full-Unicode mapping initialization requires {required_work} work, limit is {work_limit}"
        )));
    }
    let required_bytes = unicode_mapping_bytes()?;
    if required_bytes > byte_limit {
        return Err(ExecutionError::unsupported(format!(
            "canonical full-Unicode mapping requires {required_bytes} bytes, limit is {byte_limit}"
        )));
    }
    let mut mappings = Vec::new();
    mappings
        .try_reserve_exact(UNICODE_SCALAR_SLOTS)
        .map_err(|_| {
            ExecutionError::fault("failed to reserve canonical full-Unicode direct mapping table")
        })?;
    let observed_bytes = mappings
        .capacity()
        .checked_mul(size_of::<u32>())
        .ok_or_else(|| ExecutionError::fault("observed Unicode mapping capacity overflow"))?;
    if observed_bytes > byte_limit {
        return Err(ExecutionError::unsupported(format!(
            "canonical full-Unicode mapping retained capacity requires {observed_bytes} bytes, limit is {byte_limit}"
        )));
    }
    mappings.resize(UNICODE_SCALAR_SLOTS, UNMAPPED);
    Ok(mappings)
}

fn normalize(
    haystack: &[u8],
    mappings: &[u32],
    work_limit: usize,
) -> Result<Vec<u8>, ExecutionError> {
    if mappings.len() != UNICODE_SCALAR_SLOTS {
        return Err(ExecutionError::fault(
            "canonical case-fold direct mapping table has the wrong length",
        ));
    }
    let required = normalization_work(haystack.len())?;
    if required > work_limit {
        return Err(ExecutionError::unsupported(format!(
            "canonical case-fold normalization work requires {required}, limit is {work_limit}"
        )));
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(haystack.len())
        .map_err(|_| ExecutionError::fault("failed to reserve canonical case-fold input buffer"))?;
    let mut index = 0_usize;
    while index < haystack.len() {
        let byte = haystack[index];
        if byte.is_ascii() {
            let canonical = mappings[usize::from(byte)];
            if canonical == UNMAPPED {
                output.push(byte);
            } else {
                let canonical = u8::try_from(canonical).map_err(|_| {
                    ExecutionError::fault(
                        "canonical case-fold ASCII mapping is not a one-byte scalar",
                    )
                })?;
                if !canonical.is_ascii() {
                    return Err(ExecutionError::fault(
                        "canonical case-fold ASCII mapping is not ASCII",
                    ));
                }
                output.push(canonical);
            }
            index += 1;
            continue;
        }
        let Some(source) = decode_first_scalar(&haystack[index..]) else {
            output.push(byte);
            index += 1;
            continue;
        };
        let source_width = source.len_utf8();
        let canonical = mappings[unicode_scalar_slot(u32::from(source))?];
        if canonical == UNMAPPED {
            output.extend_from_slice(&haystack[index..index + source_width]);
        } else {
            let canonical = char::from_u32(canonical).ok_or_else(|| {
                ExecutionError::fault("canonical case-fold mapping is not a Unicode scalar")
            })?;
            if canonical.len_utf8() > source_width {
                return Err(ExecutionError::fault(
                    "canonical case-fold normalization would grow encoded input",
                ));
            }
            let mut encoded = [0_u8; 4];
            output.extend_from_slice(canonical.encode_utf8(&mut encoded).as_bytes());
        }
        index += source_width;
    }
    if output.len() > haystack.len() {
        return Err(ExecutionError::fault(
            "canonical case-fold normalization grew byte length",
        ));
    }
    Ok(output)
}

fn decode_first_scalar(bytes: &[u8]) -> Option<char> {
    let first = *bytes.first()?;
    let width = match first {
        0x00..=0x7F => 1,
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => return None,
    };
    let encoded = bytes.get(..width)?;
    core::str::from_utf8(encoded).ok()?.chars().next()
}

fn unicode_scalar_slot(scalar: u32) -> Result<usize, ExecutionError> {
    let slot = usize::try_from(scalar)
        .map_err(|_| ExecutionError::fault("Unicode scalar index does not fit usize"))?;
    if slot >= UNICODE_SCALAR_SLOTS {
        return Err(ExecutionError::fault(
            "Unicode scalar is outside the direct table",
        ));
    }
    Ok(slot)
}

fn normalization_work(input_bytes: usize) -> Result<usize, ExecutionError> {
    // Twelve units per input byte precharge the worst four-byte UTF-8 decode,
    // validation, scalar lookup, width check and output writes. Invalid bytes
    // consume the same envelope even though they advance only one byte.
    input_bytes
        .checked_mul(NORMALIZATION_WORK_PER_BYTE)
        .ok_or_else(|| ExecutionError::fault("normalization total work overflow"))
}

fn sparse_run_limits(
    input_bytes: usize,
    build: fre::SparseOrderedLiteralAggregateBuildAccounting,
    work_limit: usize,
    scratch_limit: usize,
    peak_limit: usize,
    reducer_steps: u64,
) -> Result<SparseOrderedLiteralAggregateReduceLimits, ExecutionError> {
    let boundaries = checked_add(input_bytes, 1, "canonical boundary count")?;
    let minimum = build
        .min_nonempty_pattern_bytes
        .ok_or_else(|| ExecutionError::fault("canonical sparse plan lacks a nonempty minimum"))?;
    let match_events = input_bytes / minimum;
    let ring = checked_add(
        build.max_pattern_bytes.min(input_bytes),
        1,
        "canonical ring",
    )?;
    let lookups = input_bytes
        .checked_mul(2)
        .ok_or_else(|| ExecutionError::fault("canonical edge lookup overflow"))?;
    let comparisons = u64::try_from(lookups)
        .ok()
        .and_then(|value| value.checked_mul(u64::try_from(build.max_edge_search_checks).ok()?))
        .ok_or_else(|| ExecutionError::fault("canonical edge comparison overflow"))?;
    let reducer_limit = usize::try_from(reducer_steps)
        .map_err(|_| ExecutionError::fault("canonical reducer limit does not fit usize"))?;
    Ok(SparseOrderedLiteralAggregateReduceLimits {
        max_transitions: input_bytes,
        max_edge_lookups: lookups,
        max_edge_search_checks: comparisons,
        max_failure_steps: input_bytes,
        max_match_events: match_events.min(reducer_limit),
        max_count: u64::try_from(match_events)
            .unwrap_or(u64::MAX)
            .min(reducer_steps),
        max_span_sum: u64::try_from(input_bytes).unwrap_or(u64::MAX),
        max_reducer_steps: boundaries.min(reducer_limit),
        max_ring_initializations: ring,
        max_total_work: u64::try_from(work_limit).unwrap_or(u64::MAX),
        max_scratch_bytes: scratch_limit,
        max_peak_bytes: peak_limit,
    })
}

fn checked_add(left: usize, right: usize, what: &str) -> Result<usize, ExecutionError> {
    left.checked_add(right)
        .ok_or_else(|| ExecutionError::fault(format!("canonical case-fold {what} overflow")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHERLOCK_PATTERN: &str =
        "Шерлок Холмс|Джон Уотсон|Ирен Адлер|инспектор Лестрейд|профессор Мориарти";

    fn mapping_table(pairs: &[(char, char)]) -> Vec<u32> {
        let mut table = vec![UNMAPPED; UNICODE_SCALAR_SLOTS];
        for &(source, canonical) in pairs {
            let slot = unicode_scalar_slot(u32::from(source)).unwrap();
            table[slot] = u32::from(canonical);
        }
        table
    }

    fn spans(pattern: &str, haystack: &[u8], case_insensitive: bool) -> Vec<(usize, usize)> {
        regex::bytes::RegexBuilder::new(pattern)
            .unicode(true)
            .case_insensitive(case_insensitive)
            .build()
            .unwrap()
            .find_iter(haystack)
            .map(|matched| (matched.start(), matched.end()))
            .collect()
    }

    fn decoded_patterns(encoded: &[u8]) -> Vec<String> {
        let read_u64 =
            |bytes: &[u8]| u64::from_le_bytes(bytes.try_into().expect("complete encoded u64"));
        let count = usize::try_from(read_u64(&encoded[..8])).unwrap();
        let mut offset = 8_usize;
        let mut patterns = Vec::with_capacity(count);
        for _ in 0..count {
            let length = usize::try_from(read_u64(&encoded[offset..offset + 8])).unwrap();
            offset += 8;
            patterns.push(
                core::str::from_utf8(&encoded[offset..offset + length])
                    .unwrap()
                    .to_string(),
            );
            offset += length;
        }
        assert_eq!(offset, encoded.len());
        patterns
    }

    fn routed_spans(pattern: &str, haystack: &[u8]) -> Vec<(usize, usize)> {
        let Some(plan) = CanonicalPlan::build(pattern, &RunLimits::default()).unwrap() else {
            return spans(pattern, haystack, true);
        };
        let canonical = normalize(haystack, &plan.mappings, usize::MAX).unwrap();
        let source = decoded_patterns(plan.engine.cache_identity().encoded_patterns)
            .iter()
            .map(|pattern| regex::escape(pattern))
            .collect::<Vec<_>>()
            .join("|");
        spans(&source, &canonical, false)
    }

    #[test]
    fn rebar_row_curated_02_literal_alternate_sherlock_casei_ru_exact_boundary() {
        // rebar-row:curated/02-literal-alternate/sherlock-casei-ru@rust/regex
        // Hand witness: N=4 bytes * 12 fixed decode/canonicalization units =
        // 48. Limit 48 accepts; 47 refuses before reserve or scan.
        let mappings = mapping_table(&[('А', 'А'), ('а', 'А')]);
        assert_eq!(normalization_work(4).unwrap(), 48);
        let exact = normalize("Аа".as_bytes(), &mappings, 48).unwrap();
        assert_eq!(exact, "АА".as_bytes());
        assert_eq!(spans("АА", &exact, false), vec![(0, 4)]);
        let one_below = normalize("Аа".as_bytes(), &mappings, 47)
            .expect_err("one-below normalization admission must refuse");
        assert_eq!(one_below.status, super::super::Status::Unsupported);
        assert!(one_below.message.contains("requires 48, limit is 47"));
    }

    #[test]
    fn full_unicode_mapping_exact_limits_refuse_before_reserve() {
        let exact_work = unicode_mapping_init_work().unwrap();
        let exact_bytes = unicode_mapping_bytes().unwrap();
        assert_eq!(exact_work, 2_228_224);
        assert_eq!(exact_bytes, 4_456_448);
        let exact = empty_unicode_mapping(exact_work, exact_bytes).unwrap();
        assert_eq!(exact.len(), UNICODE_SCALAR_SLOTS);
        drop(exact);

        let work_refusal = empty_unicode_mapping(exact_work - 1, exact_bytes)
            .expect_err("one-below initialization work must refuse");
        assert_eq!(work_refusal.status, super::super::Status::Unsupported);
        assert!(work_refusal.message.contains("requires 2228224 work"));

        let byte_refusal = empty_unicode_mapping(exact_work, exact_bytes - 1)
            .expect_err("one-below table bytes must refuse");
        assert_eq!(byte_refusal.status, super::super::Status::Unsupported);
        assert!(byte_refusal.message.contains("requires 4456448 bytes"));
    }

    #[test]
    fn full_plan_exact_compile_and_program_limits_have_one_below_refusals() {
        let pattern = "АААААААА|ББББББББ|ВВВВВВВВ|ГГГГГГГГ";
        let baseline = CanonicalPlan::build(pattern, &RunLimits::default())
            .unwrap()
            .expect("resource witness is eligible");
        let required = baseline.accounting;

        let exact = RunLimits {
            fre_aggregate_compile_work: required.compile_work,
            fre_aggregate_program_bytes: required.program_bytes,
            ..RunLimits::default()
        };
        let exact_plan = CanonicalPlan::build(pattern, &exact)
            .unwrap()
            .expect("exact compiler work and bytes admit the complete plan");
        assert_eq!(exact_plan.accounting, required);

        let mut work_below = exact.clone();
        work_below.fre_aggregate_compile_work -= 1;
        let work_refusal = CanonicalPlan::build(pattern, &work_below)
            .expect_err("one-below complete compiler work must refuse");
        assert_eq!(work_refusal.status, super::super::Status::Unsupported);

        let mut bytes_below = exact;
        bytes_below.fre_aggregate_program_bytes -= 1;
        let byte_refusal = CanonicalPlan::build(pattern, &bytes_below)
            .expect_err("one-below complete program bytes must refuse");
        assert_eq!(byte_refusal.status, super::super::Status::Unsupported);
    }

    #[test]
    fn retained_count_lifecycle_preflights_normalization_and_reuses_the_plan() {
        let pattern = "АААААААА|ББББББББ|ВВВВВВВВ|ГГГГГГГГ";
        let patterns = vec![pattern.to_string()];
        let haystack = "бббббббб".as_bytes();
        let required_work = normalization_work(haystack.len()).unwrap();
        let exact = RunLimits {
            fre_aggregate_operation_work: required_work,
            ..RunLimits::default()
        };
        let lifecycle = try_build_count(&patterns, true, true, haystack.len(), &exact)
            .unwrap()
            .expect("exact normalization admission retains the canonical plan");
        assert_eq!(lifecycle.haystack_len, haystack.len());

        let one_below = RunLimits {
            fre_aggregate_operation_work: required_work - 1,
            ..RunLimits::default()
        };
        let refusal = try_build_count(&patterns, true, true, haystack.len(), &one_below)
            .expect_err("one-below normalization work must refuse before publication");
        assert_eq!(refusal.status, super::super::Status::Unsupported);
        assert!(refusal.message.contains(&format!(
            "requires {required_work}, limit is {}",
            required_work - 1
        )));

        let lifecycle =
            try_build_count(&patterns, true, true, haystack.len(), &RunLimits::default())
                .unwrap()
                .expect("eligible retained lifecycle");
        assert_eq!(lifecycle.execute(haystack).unwrap(), 1);
        assert_eq!(lifecycle.execute(haystack).unwrap(), 1);
        assert!(
            lifecycle
                .execute(&haystack[..haystack.len() - 1])
                .unwrap_err()
                .message
                .contains("differs from prepared")
        );
    }

    #[test]
    fn rebar_row_curated_02_literal_alternate_sherlock_casei_ru_source_admission() {
        // Four nonempty two-byte alternatives with 31 atoms occupy 65 bytes:
        // 31 * 2 scalar bytes + 3 separators. Refuse that one-below shape
        // before parser/ledger allocation; admit the exact 32-atom shape.
        let one_below = "АААААААА|ББББББББ|ВВВВВВВВ|ГГГГГГГ";
        let exact = "АААААААА|ББББББББ|ВВВВВВВВ|ГГГГГГГГ";
        assert_eq!(one_below.len(), 65);
        assert_eq!(
            inspect_source(one_below).unwrap(),
            Some(SourceShape {
                alternatives: 4,
                atoms: MIN_SCALAR_ATOMS - 1,
            })
        );
        let one_below_patterns = vec![one_below.to_string()];
        let refusal = try_count(
            CandidateRequest {
                model: "count",
                patterns: &one_below_patterns,
                haystack: b"",
                unicode: true,
                case_insensitive: true,
            },
            &RunLimits::default(),
        )
        .unwrap_err();
        assert_eq!(refusal.status, super::super::Status::Unsupported);

        assert_eq!(exact.len(), 67);
        assert_eq!(
            inspect_source(exact).unwrap(),
            Some(SourceShape {
                alternatives: 4,
                atoms: MIN_SCALAR_ATOMS,
            })
        );
        let exact_patterns = vec![exact.to_string()];
        let admitted = try_count(
            CandidateRequest {
                model: "count",
                patterns: &exact_patterns,
                haystack: "бббббббб".as_bytes(),
                unicode: true,
                case_insensitive: true,
            },
            &RunLimits::default(),
        )
        .unwrap()
        .expect("exact source boundary selects the canonical plan");
        assert_eq!(admitted.actual, 1);
        assert_eq!(admitted.plan, PLAN);
    }

    #[test]
    fn rebar_row_curated_02_literal_alternate_sherlock_casei_ru_complete_spans() {
        // rebar-row:curated/02-literal-alternate/sherlock-casei-ru@rust/regex
        // This assigned-row fixture proves the selector, but no production
        // branch consults it, a benchmark name, or an expected reducer value.
        let pattern = SHERLOCK_PATTERN;
        let mut haystack = vec![0xFF, 0x80];
        haystack.extend_from_slice(
            "ШЕРЛОК ХОЛМС/джон уотсон/ИРЕН АДЛЕР/инспектор лестрейд/ПРОФЕССОР МОРИАРТИ".as_bytes(),
        );
        haystack.extend_from_slice(&[0xF4, 0x90, 0x80, 0x80]);
        let plan = CanonicalPlan::build(pattern, &RunLimits::default())
            .unwrap()
            .expect("eligible canonical plan");
        assert!(!plan.engine.cache_identity().encoded_patterns.is_empty());
        let patterns = vec![pattern.to_string()];
        let reduction = try_count(
            CandidateRequest {
                model: "count",
                patterns: &patterns,
                haystack: &haystack,
                unicode: true,
                case_insensitive: true,
            },
            &RunLimits::default(),
        )
        .unwrap()
        .expect("assigned shape selects canonical count");
        assert_eq!(reduction.actual, 5);
        assert_eq!(reduction.plan, PLAN);
        assert_eq!(
            spans(pattern, &haystack, true),
            routed_spans(pattern, &haystack),
            "malformed UTF-8 and both boundary matches retain complete byte spans"
        );
        let boundary_haystack =
            "шерлок холмс/ДЖОН УОТСОН/ирен адлер/ИНСПЕКТОР ЛЕСТРЕЙД/профессор мориарти";
        assert_eq!(
            spans(pattern, boundary_haystack.as_bytes(), true),
            routed_spans(pattern, boundary_haystack.as_bytes()),
            "matches beginning at byte zero and ending at input length retain complete spans"
        );
    }

    #[test]
    fn variable_width_cyrillic_fold_aliases_are_canonicalized_without_growth() {
        // U+1C82 and U+1C80 are three-byte aliases in the simple-fold classes
        // of ordinary two-byte Cyrillic О and В. This is the concrete defect
        // that invalidated the former fixed-width mechanism.
        let word = "ОВОВОВОВ";
        let pattern = "ОВОВОВОВ|ВОВОВОВО|ООВОВОВВ|ВВОВОВОО".to_string();
        let plan = CanonicalPlan::build(&pattern, &RunLimits::default())
            .unwrap()
            .expect("variable-width fold classes remain eligible");
        let canonical_o = plan.mappings[unicode_scalar_slot(u32::from('О')).unwrap()];
        let canonical_v = plan.mappings[unicode_scalar_slot(u32::from('В')).unwrap()];
        assert_eq!(
            plan.mappings[unicode_scalar_slot(u32::from('ᲂ')).unwrap()],
            canonical_o
        );
        assert_eq!(
            plan.mappings[unicode_scalar_slot(u32::from('ᲀ')).unwrap()],
            canonical_v
        );

        let haystack = "ᲂᲀᲂᲀᲂᲀᲂᲀ";
        let canonical = normalize(
            haystack.as_bytes(),
            &plan.mappings,
            normalization_work(haystack.len()).unwrap(),
        )
        .unwrap();
        assert_eq!(canonical, word.as_bytes());
        assert!(canonical.len() < haystack.len());

        let patterns = vec![pattern.clone()];
        let reduction = try_count(
            CandidateRequest {
                model: "count",
                patterns: &patterns,
                haystack: haystack.as_bytes(),
                unicode: true,
                case_insensitive: true,
            },
            &RunLimits::default(),
        )
        .unwrap()
        .expect("variable-width fold plan selected");
        assert_eq!(reduction.actual, 1);
        assert_eq!(
            reduction.actual,
            u64::try_from(spans(&pattern, haystack.as_bytes(), true).len()).unwrap()
        );
    }

    #[test]
    fn structural_exclusions_cover_captures_assertions_classes_and_empty_language() {
        let repeated = "АБВГДЕЖЗ";
        let cases = [
            (
                format!("({repeated})|{repeated}|{repeated}|{repeated}"),
                "АБВГДЕЖЗ/абвгдежз".as_bytes(),
            ),
            (
                format!("^{repeated}|{repeated}|{repeated}|{repeated}"),
                "АБВГДЕЖЗ/АБВГДЕЖЗ".as_bytes(),
            ),
            (
                format!(
                    "{repeated}\u{212A}|{repeated}\u{212A}|{repeated}\u{212A}|{repeated}\u{212A}"
                ),
                "абвгдежзk/АБВГДЕЖЗ\u{212A}".as_bytes(),
            ),
            (
                format!("[^а]{repeated}|{repeated}|{repeated}|{repeated}"),
                "бАБВГДЕЖЗ/АБВГДЕЖЗ".as_bytes(),
            ),
            (
                format!("[а&&б]{repeated}|{repeated}|{repeated}|{repeated}"),
                "АБВГДЕЖЗ".as_bytes(),
            ),
            (
                "[a&&b]|[a&&b]|[a&&b]|[a&&b]".to_string(),
                b"boundary windows",
            ),
        ];
        for (pattern, haystack) in cases {
            assert!(
                CanonicalPlan::build(&pattern, &RunLimits::default())
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                spans(&pattern, haystack, true),
                routed_spans(&pattern, haystack)
            );
        }
    }

    #[test]
    fn normalization_preserves_invalid_and_unmapped_multibyte_boundaries() {
        let mappings = mapping_table(&[('a', 'A'), ('а', 'А')]);
        let input = [
            b'a', b'Z', // mapped and unmapped ASCII take the direct byte path
            0xC1, 0x80, // overlong lead plus continuation: both remain invalid
            0xD0, 0xB0, // valid Cyrillic small a: canonicalized in place
            0xD0, 0x00, // truncated two-byte scalar: copied byte-for-byte
            0xE0, 0xB0, 0x90, // valid three-byte scalar: outside the table
        ];
        let expected = [
            b'A', b'Z', 0xC1, 0x80, 0xD0, 0x90, 0xD0, 0x00, 0xE0, 0xB0, 0x90,
        ];
        assert_eq!(
            normalize(&input, &mappings, normalization_work(input.len()).unwrap()).unwrap(),
            expected
        );
    }

    #[test]
    fn adversarial_n_and_q_scaling_are_structurally_bounded() {
        let n = 1_024;
        assert_eq!(
            normalization_work(2 * n).unwrap(),
            2 * normalization_work(n).unwrap()
        );
        assert_eq!(
            normalization_work(4 * n).unwrap(),
            4 * normalization_work(n).unwrap()
        );
        assert_eq!(
            normalization_work(n).unwrap(),
            NORMALIZATION_WORK_PER_BYTE * n
        );

        // Q, 2Q, and 4Q source lengths charge a hand-derived affine compiler
        // envelope: W(Q) = Q * (32 * 1,920 + 64) + 2 * 1,114,112. The fixed
        // full-domain table term makes doubling sublinear relative to twice
        // the prior charge. Sparse builder sorting/deduplication remains O(Q
        // log Q), and its byte-edge binary searches have at most 256 symbols,
        // independent of Q.
        let q = MIN_PATTERN_BYTES;
        assert_eq!(planner_work(q).unwrap(), 6_164_480);
        assert_eq!(planner_work(2 * q).unwrap(), 10_100_736);
        assert_eq!(planner_work(4 * q).unwrap(), 17_973_248);
        assert!(planner_work(2 * q).unwrap() < 2 * planner_work(q).unwrap());
        assert!(planner_work(4 * q).unwrap() < 2 * planner_work(2 * q).unwrap());
    }
}
