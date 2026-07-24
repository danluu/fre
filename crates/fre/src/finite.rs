//! Checked finite-language extraction for operation-specific literal plans.

#![allow(
    clippy::similar_names,
    reason = "word and work are distinct domain quantities throughout this checked planner"
)]

use core::mem::size_of;

use fre_exact_alloc::{CopyError, ExactVec};
use regex_syntax::hir::{Class, Hir, HirKind, Look};

use crate::guarded_ascii_word::{
    BuildDimensions as GuardedBuildDimensions, BuildError as GuardedBuildError,
    BuildErrorKind as GuardedBuildErrorKind, BuildLimits as GuardedBuildLimits,
    BuildProspective as GuardedBuildProspective, Dictionary as GuardedDictionary, Guard,
    SourceWord,
};
use crate::{BuildError, charge_planner, reserve_planner};

/// Exhaustive finite-language planner disposition with cumulative work.
///
/// In particular, a semantic refusal never resets the work charged by an
/// earlier proof attempt. Callers can therefore continue with another
/// bounded route without silently restarting the construction quota.
pub(crate) enum FiniteOutcome {
    Fits {
        words: Vec<Vec<u8>>,
        work: u64,
    },
    GuardedFiniteBody {
        dictionary: GuardedDictionary,
        accounting: GuardedFiniteAccounting,
        work: u64,
    },
    TooLargeFixedSequence {
        work: u64,
    },
    Unsupported {
        work: u64,
    },
    ResourceFailure {
        error: BuildError,
        work: u64,
    },
}

type IncumbentFiniteResult = Result<(Option<Vec<Vec<u8>>>, u64), BuildError>;

impl FiniteOutcome {
    pub(crate) const fn work(&self) -> u64 {
        match self {
            Self::Fits { work, .. }
            | Self::GuardedFiniteBody { work, .. }
            | Self::TooLargeFixedSequence { work }
            | Self::Unsupported { work }
            | Self::ResourceFailure { work, .. } => *work,
        }
    }

    pub(crate) fn into_incumbent_words(self) -> IncumbentFiniteResult {
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
        }
    }
}

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

struct Language {
    words: Vec<Vec<u8>>,
    bytes: usize,
}

#[derive(Clone, Copy)]
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
) -> FiniteOutcome {
    let mut work = initial_work;
    match extract_plain(hir, max_words, max_bytes, &mut work, work_limit) {
        Ok(Some(words)) => FiniteOutcome::Fits { words, work },
        Ok(None) if derive_guarded_dictionary => {
            match extract_guarded_dictionary(hir, max_words, max_bytes, &mut work, work_limit) {
                Ok(Ok((dictionary, accounting))) => FiniteOutcome::GuardedFiniteBody {
                    dictionary,
                    accounting,
                    work,
                },
                Ok(Err(GuardedRefusal::TooLargeFixedSequence)) => {
                    FiniteOutcome::TooLargeFixedSequence { work }
                }
                Ok(Err(GuardedRefusal::Unsupported)) => FiniteOutcome::Unsupported { work },
                Err(error) => FiniteOutcome::ResourceFailure { error, work },
            }
        }
        Ok(None) => FiniteOutcome::Unsupported { work },
        Err(PlainFailure::TooLargeFixedSequence) => FiniteOutcome::TooLargeFixedSequence { work },
        Err(PlainFailure::Resource(error)) => FiniteOutcome::ResourceFailure { error, work },
    }
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

struct GuardedLanguage {
    paths: ExactVec<GuardedPath>,
    bytes: usize,
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

struct GuardedSource {
    words: ExactVec<GuardedSourceWord>,
    accounting: GuardedSourceAccounting,
    dictionary_prospective: GuardedBuildProspective,
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

type GuardedSourceResult = Result<GuardedSource, GuardedRefusal>;
type GuardedDictionaryResult = Result<(GuardedDictionary, GuardedFiniteAccounting), GuardedRefusal>;

fn extract_plain(
    hir: &Hir,
    max_words: usize,
    max_bytes: usize,
    work: &mut u64,
    work_limit: u64,
) -> Result<Option<Vec<Vec<u8>>>, PlainFailure> {
    match analyze(hir, max_words, max_bytes, work, work_limit).map_err(PlainFailure::Resource)? {
        Analysis::Fits(_) => {}
        Analysis::TooLargeFixedSequence => return Err(PlainFailure::TooLargeFixedSequence),
        Analysis::Unsupported => return Ok(None),
    }
    let mut tasks = Vec::new();
    reserve_planner(
        &mut tasks,
        1,
        work,
        work_limit,
        "finite-language task stack",
    )
    .map_err(PlainFailure::Resource)?;
    tasks.push(Task::Visit(hir));
    let mut values = Vec::new();
    while let Some(task) = tasks.pop() {
        charge_planner(work, 1, work_limit).map_err(PlainFailure::Resource)?;
        execute_plain_task(
            task,
            &mut tasks,
            &mut values,
            max_words,
            max_bytes,
            work,
            work_limit,
        )?;
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
    Ok(Some(language.words))
}

fn execute_plain_task<'a>(
    task: Task<'a>,
    tasks: &mut Vec<Task<'a>>,
    values: &mut Vec<Language>,
    max_words: usize,
    max_bytes: usize,
    work: &mut u64,
    work_limit: u64,
) -> Result<(), PlainFailure> {
    match task {
        Task::Visit(node) => {
            visit_plain_node(node, tasks, values, max_words, max_bytes, work, work_limit)
        }
        Task::FinishConcat(children) => finish_plain_languages(
            values, children, true, max_words, max_bytes, work, work_limit,
        ),
        Task::FinishAlternation(children) => finish_plain_languages(
            values, children, false, max_words, max_bytes, work, work_limit,
        ),
    }
}

fn visit_plain_node<'a>(
    node: &'a Hir,
    tasks: &mut Vec<Task<'a>>,
    values: &mut Vec<Language>,
    max_words: usize,
    max_bytes: usize,
    work: &mut u64,
    work_limit: u64,
) -> Result<(), PlainFailure> {
    let language = match node.kind() {
        HirKind::Empty => {
            Some(singleton_language(Vec::new(), work, work_limit).map_err(PlainFailure::Resource)?)
        }
        HirKind::Literal(literal) => {
            if literal.0.len() > max_bytes || max_words == 0 {
                return Err(plain_invariant(
                    "finite literal exceeded successful analysis",
                ));
            }
            let mut word = Vec::new();
            reserve_planner(
                &mut word,
                literal.0.len(),
                work,
                work_limit,
                "finite-language literal bytes",
            )
            .map_err(PlainFailure::Resource)?;
            word.extend_from_slice(&literal.0);
            Some(singleton_language(word, work, work_limit).map_err(PlainFailure::Resource)?)
        }
        HirKind::Class(Class::Bytes(class)) => Some(
            byte_class(class, max_words, max_bytes, work, work_limit)
                .map_err(PlainFailure::Resource)?
                .ok_or_else(|| plain_invariant("finite byte class exceeded successful analysis"))?,
        ),
        HirKind::Class(Class::Unicode(class)) => Some(
            unicode_class(class, max_words, max_bytes, work, work_limit)
                .map_err(PlainFailure::Resource)?
                .ok_or_else(|| {
                    plain_invariant("finite Unicode class exceeded successful analysis")
                })?,
        ),
        HirKind::Capture(capture) => {
            push_visit(tasks, &capture.sub, work, work_limit).map_err(PlainFailure::Resource)?;
            None
        }
        HirKind::Concat(children) => {
            push_children(
                tasks,
                children,
                Task::FinishConcat(children.len()),
                work,
                work_limit,
            )
            .map_err(PlainFailure::Resource)?;
            None
        }
        HirKind::Alternation(children) => {
            push_children(
                tasks,
                children,
                Task::FinishAlternation(children.len()),
                work,
                work_limit,
            )
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
        push_language(values, language, work, work_limit).map_err(PlainFailure::Resource)?;
    }
    Ok(())
}

fn finish_plain_languages(
    values: &mut Vec<Language>,
    children: usize,
    concatenate: bool,
    max_words: usize,
    max_bytes: usize,
    work: &mut u64,
    work_limit: u64,
) -> Result<(), PlainFailure> {
    let child_languages =
        pop_languages(values, children, work, work_limit).map_err(PlainFailure::Resource)?;
    let language = if concatenate {
        concat_languages(child_languages, max_words, max_bytes, work, work_limit)
    } else {
        alternate_languages(child_languages, max_words, max_bytes, work, work_limit)
    }
    .map_err(PlainFailure::Resource)?
    .ok_or_else(|| plain_invariant("finite combination exceeded successful analysis"))?;
    push_language(values, language, work, work_limit).map_err(PlainFailure::Resource)
}

const fn plain_invariant(detail: &'static str) -> PlainFailure {
    PlainFailure::Resource(BuildError::InternalInvariant(detail))
}

fn extract_guarded_source(
    hir: &Hir,
    max_words: usize,
    max_bytes: usize,
    work: &mut u64,
    work_limit: u64,
) -> Result<GuardedSourceResult, BuildError> {
    let materialization =
        match prove_guarded_materialization(hir, max_words, max_bytes, work, work_limit)? {
            Ok(materialization) => materialization,
            Err(refusal) => return Ok(Err(refusal)),
        };
    let plan = materialization.plan;
    admit_guarded_source_work(plan, *work, work_limit)?;
    publish_guarded_source(materialization, plan, work, work_limit)
}

struct GuardedMaterialization {
    language: GuardedLanguage,
    expansion_actual: GuardedExpansionActual,
    plan: GuardedSourcePlan,
}

type GuardedMaterializationResult = Result<GuardedMaterialization, GuardedRefusal>;

fn prove_guarded_materialization(
    hir: &Hir,
    max_words: usize,
    max_bytes: usize,
    work: &mut u64,
    work_limit: u64,
) -> Result<GuardedMaterializationResult, BuildError> {
    if !guarded_structure_supported(hir, work, work_limit)? {
        return Ok(Err(GuardedRefusal::Unsupported));
    }
    let Some(shape) = guarded_shape(hir, work, work_limit)? else {
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
        ));
    }
    let plan = close_guarded_source_plan(shape)?;
    let mut context = GuardedExpansionContext {
        max_words,
        max_bytes,
        work,
        work_limit,
        actual: GuardedExpansionActual::default(),
    };
    let language = match expand_guarded(hir, &mut context)? {
        GuardedExpansion::Fits(language) => language,
        GuardedExpansion::TooLargeFixedSequence => {
            return Ok(Err(GuardedRefusal::TooLargeFixedSequence));
        }
        GuardedExpansion::Unsupported => return Ok(Err(GuardedRefusal::Unsupported)),
    };
    let expansion_actual = context.actual;
    if language.paths.is_empty() {
        return Ok(Err(GuardedRefusal::Unsupported));
    }
    if language.paths.len() != shape.paths || language.bytes != shape.bytes {
        return Err(BuildError::InternalInvariant(
            "guarded finite materialization differs from its shape theorem",
        ));
    }
    if expansion_actual.allocations > shape.construction_allocations_upper_bound
        || expansion_actual.initialized_bytes > shape.construction_initialized_bytes_upper_bound
    {
        return Err(BuildError::InternalInvariant(
            "guarded finite expansion exceeded its prospective construction envelope",
        ));
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

fn close_guarded_source_plan(shape: GuardedShape) -> Result<GuardedSourcePlan, BuildError> {
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
        GuardedDictionary::prospective(dictionary_dimensions).map_err(|_| {
            BuildError::InternalInvariant(
                "guarded dictionary dimensions rejected a proved finite shape",
            )
        })?;
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

fn publish_guarded_source(
    materialization: GuardedMaterialization,
    plan: GuardedSourcePlan,
    work: &mut u64,
    work_limit: u64,
) -> Result<GuardedSourceResult, BuildError> {
    let GuardedMaterialization {
        mut language,
        expansion_actual,
        plan: _,
    } = materialization;
    charge_planner(
        work,
        u64::try_from(plan.words).unwrap_or(u64::MAX),
        work_limit,
    )?;
    let mut source = ExactVec::try_with_capacity(plan.words).map_err(|error| {
        map_guarded_source_allocation(error, "guarded finite source words", plan.words)
    })?;
    language.paths.as_mut_slice().reverse();
    while let Some(path) = language.paths.pop() {
        charge_planner(work, 1, work_limit)?;
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
        let Some(left) = map_left_guard(*left) else {
            return Ok(Err(GuardedRefusal::Unsupported));
        };
        let Some(right) = map_right_guard(*right) else {
            return Ok(Err(GuardedRefusal::Unsupported));
        };
        charge_planner(
            work,
            u64::try_from(body.len()).unwrap_or(u64::MAX),
            work_limit,
        )?;
        let mut bytes = ExactVec::try_with_capacity(body.len()).map_err(|error| {
            map_guarded_source_allocation(error, "guarded finite word bytes", body.len())
        })?;
        for symbol in body {
            charge_planner(work, 1, work_limit)?;
            let GuardedSymbol::Byte(byte) = symbol else {
                return Ok(Err(GuardedRefusal::Unsupported));
            };
            if !is_ascii_word_byte(*byte) {
                return Ok(Err(GuardedRefusal::Unsupported));
            }
            bytes.try_push(*byte).map_err(|_| {
                BuildError::InternalInvariant("exact guarded word capacity changed")
            })?;
        }
        if bytes.is_empty() {
            return Ok(Err(GuardedRefusal::Unsupported));
        }
        source
            .try_push(GuardedSourceWord { bytes, left, right })
            .map_err(|_| BuildError::InternalInvariant("exact guarded source capacity changed"))?;
    }
    Ok(Ok(GuardedSource {
        words: source,
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
    work: &mut u64,
    work_limit: u64,
) -> Result<bool, BuildError> {
    let Some(relation) = guarded_relation(hir, work, work_limit)? else {
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
    work: &mut u64,
    work_limit: u64,
) -> Result<Option<GuardedRelation>, BuildError> {
    charge_planner(work, 1, work_limit)?;
    match hir.kind() {
        HirKind::Empty => Ok(Some(GuardedRelation::identity())),
        HirKind::Literal(literal) => {
            let mut relation = GuardedRelation::identity();
            for &byte in &literal.0 {
                charge_planner(work, 1, work_limit)?;
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
                    charge_planner(work, 1, work_limit)?;
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
                    charge_planner(work, 1, work_limit)?;
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
        HirKind::Look(look) => Ok(guarded_look_relation(*look)),
        HirKind::Capture(capture) => guarded_relation(&capture.sub, work, work_limit),
        HirKind::Concat(children) => {
            let mut relation = GuardedRelation::identity();
            for child in children {
                let Some(child) = guarded_relation(child, work, work_limit)? else {
                    return Ok(None);
                };
                relation = relation.then(child);
            }
            Ok(Some(relation))
        }
        HirKind::Alternation(children) => {
            let mut relation = GuardedRelation::empty_language();
            for child in children {
                let Some(child) = guarded_relation(child, work, work_limit)? else {
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
            let Some(sub) = guarded_relation(&repetition.sub, work, work_limit)? else {
                return Ok(None);
            };
            let mut result = GuardedRelation::empty_language();
            let mut power = GuardedRelation::identity();
            let mut count = 0_u32;
            loop {
                charge_planner(work, 1, work_limit)?;
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

const fn guarded_look_relation(look: Look) -> Option<GuardedRelation> {
    let dead = 1 << GUARDED_DEAD_STATE;
    match look {
        Look::WordAscii => Some(GuardedRelation {
            rows: [
                1 << GUARDED_AFTER_LEFT_STATE,
                dead,
                1 << GUARDED_ACCEPT_STATE,
                dead,
                dead,
            ],
        }),
        Look::WordStartAscii | Look::WordStartHalfAscii => Some(GuardedRelation {
            rows: [1 << GUARDED_AFTER_LEFT_STATE, dead, dead, dead, dead],
        }),
        Look::WordEndAscii | Look::WordEndHalfAscii => Some(GuardedRelation {
            rows: [dead, dead, 1 << GUARDED_ACCEPT_STATE, dead, dead],
        }),
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
    work: &mut u64,
    work_limit: u64,
) -> Result<Option<GuardedShape>, BuildError> {
    charge_planner(work, 1, work_limit)?;
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
        HirKind::Capture(capture) => guarded_shape(&capture.sub, work, work_limit),
        HirKind::Concat(children) => {
            let Some(mut output) = GuardedShape::leaf(1, 0, 0) else {
                return Ok(None);
            };
            for child in children {
                let Some(child) = guarded_shape(child, work, work_limit)? else {
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
                let Some(child) = guarded_shape(child, work, work_limit)? else {
                    return Ok(None);
                };
                let Some(next) = alternate_guarded_shape(output, child) else {
                    return Ok(None);
                };
                output = next;
            }
            Ok(Some(output))
        }
        HirKind::Repetition(repetition) => guarded_repetition_shape(repetition, work, work_limit),
    }
}

fn guarded_repetition_shape(
    repetition: &regex_syntax::hir::Repetition,
    work: &mut u64,
    work_limit: u64,
) -> Result<Option<GuardedShape>, BuildError> {
    let Some(maximum) = repetition.max else {
        return Ok(None);
    };
    let Some(optional) = maximum.checked_sub(repetition.min) else {
        return Ok(None);
    };
    let Some(sub) = guarded_shape(&repetition.sub, work, work_limit)? else {
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
        charge_planner(work, 1, work_limit)?;
        let Some(next) = concat_guarded_shape(output, sub) else {
            return Ok(None);
        };
        output = next;
    }
    for _ in 0..optional {
        charge_planner(work, 1, work_limit)?;
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
    work: &mut u64,
    work_limit: u64,
) -> Result<GuardedDictionaryResult, BuildError> {
    let source = match extract_guarded_source(hir, max_words, max_bytes, work, work_limit)? {
        Ok(source) => source,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let dimensions = GuardedBuildDimensions {
        words: source.accounting.words,
        packed_bytes: source.accounting.word_bytes,
    };
    let remaining_work = work_limit
        .checked_sub(*work)
        .ok_or(BuildError::PlannerWorkLimit {
            needed: *work,
            limit: work_limit,
        })?;
    let mut limits = GuardedBuildLimits::unlimited();
    limits.max_words = max_words;
    limits.max_packed_bytes = max_bytes;
    limits.max_build_work = remaining_work;
    let words = source.words.iter().map(|word| SourceWord {
        bytes: word.bytes.as_slice(),
        left: word.left,
        right: word.right,
    });
    let dictionary_start_work = *work;
    let dictionary = match GuardedDictionary::build_precounted(dimensions, words, limits) {
        Ok(dictionary) => dictionary,
        Err(error) => {
            charge_planner(work, error.actual().build_work, work_limit)?;
            return Err(map_guarded_build_error(
                &error,
                dictionary_start_work,
                work_limit,
            ));
        }
    };
    let dictionary_accounting = dictionary.build_accounting();
    if dictionary_accounting.prospective != source.dictionary_prospective {
        return Err(BuildError::InternalInvariant(
            "guarded dictionary prospective changed after source publication",
        ));
    }
    charge_planner(work, dictionary_accounting.actual.build_work, work_limit)?;
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
        ));
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
        ));
    }
    Ok(Ok((dictionary, accounting)))
}

fn map_guarded_build_error(
    error: &GuardedBuildError,
    initial_work: u64,
    work_limit: u64,
) -> BuildError {
    match error.kind {
        GuardedBuildErrorKind::WorkLimit { needed, .. } => BuildError::PlannerWorkLimit {
            needed: initial_work.saturating_add(needed),
            limit: work_limit,
        },
        GuardedBuildErrorKind::AllocationFailed {
            structure,
            additional,
        } => BuildError::AllocationFailed {
            structure,
            additional,
        },
        _ => BuildError::InternalInvariant(
            "guarded ASCII-word dictionary rejected its proved finite source",
        ),
    }
}

const fn map_left_guard(look: Look) -> Option<Guard> {
    match look {
        Look::WordAscii => Some(Guard::LeftBoundary),
        Look::WordStartAscii => Some(Guard::LeftStart),
        Look::WordStartHalfAscii => Some(Guard::LeftStartHalf),
        _ => None,
    }
}

const fn map_right_guard(look: Look) -> Option<Guard> {
    match look {
        Look::WordAscii => Some(Guard::RightBoundary),
        Look::WordEndAscii => Some(Guard::RightEnd),
        Look::WordEndHalfAscii => Some(Guard::RightEndHalf),
        _ => None,
    }
}

enum GuardedExpansion {
    Fits(GuardedLanguage),
    TooLargeFixedSequence,
    Unsupported,
}

struct GuardedExpansionContext<'a> {
    max_words: usize,
    max_bytes: usize,
    work: &'a mut u64,
    work_limit: u64,
    actual: GuardedExpansionActual,
}

impl GuardedExpansionContext<'_> {
    fn charge(&mut self, amount: usize) -> Result<(), BuildError> {
        charge_planner(
            self.work,
            u64::try_from(amount).unwrap_or(u64::MAX),
            self.work_limit,
        )
    }

    fn allocate<T>(
        &mut self,
        capacity: usize,
        structure: &'static str,
    ) -> Result<ExactVec<T>, BuildError> {
        self.charge(capacity)?;
        let values = ExactVec::try_with_capacity(capacity)
            .map_err(|error| map_guarded_source_allocation(error, structure, capacity))?;
        if capacity != 0 {
            self.actual.allocations = self
                .actual
                .allocations
                .checked_add(1)
                .ok_or(BuildError::PersistentBytesOverflow)?;
            let bytes = capacity
                .checked_mul(size_of::<T>())
                .ok_or(BuildError::PersistentBytesOverflow)?;
            self.actual.initialized_bytes = self
                .actual
                .initialized_bytes
                .checked_add(bytes)
                .ok_or(BuildError::PersistentBytesOverflow)?;
        }
        Ok(values)
    }
}

fn expand_guarded(
    hir: &Hir,
    context: &mut GuardedExpansionContext<'_>,
) -> Result<GuardedExpansion, BuildError> {
    context.charge(1)?;
    match hir.kind() {
        HirKind::Empty => guarded_singleton(ExactVec::default(), context),
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

fn expand_guarded_literal(
    literal: &[u8],
    context: &mut GuardedExpansionContext<'_>,
) -> Result<GuardedExpansion, BuildError> {
    if context.max_words == 0 || literal.len() > context.max_bytes {
        return Ok(GuardedExpansion::TooLargeFixedSequence);
    }
    let mut symbols = context.allocate(literal.len(), "guarded finite literal symbols")?;
    for &byte in literal {
        symbols
            .try_push(GuardedSymbol::Byte(byte))
            .map_err(|_| BuildError::InternalInvariant("exact guarded literal capacity changed"))?;
    }
    guarded_singleton(symbols, context)
}

fn expand_guarded_byte_class(
    class: &regex_syntax::hir::ClassBytes,
    context: &mut GuardedExpansionContext<'_>,
) -> Result<GuardedExpansion, BuildError> {
    let mut count = 0_usize;
    for range in class.ranges() {
        for byte in range.start()..=range.end() {
            context.charge(1)?;
            if !is_ascii_word_byte(byte) {
                return Ok(GuardedExpansion::Unsupported);
            }
            count = count.checked_add(1).ok_or(BuildError::PlannerWorkLimit {
                needed: u64::MAX,
                limit: context.work_limit,
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
            symbols
                .try_push(GuardedSymbol::Byte(byte))
                .map_err(|_| BuildError::InternalInvariant("exact byte-class capacity changed"))?;
            paths
                .try_push(GuardedPath { symbols })
                .map_err(|_| BuildError::InternalInvariant("exact byte-class paths changed"))?;
        }
    }
    Ok(GuardedExpansion::Fits(GuardedLanguage {
        paths,
        bytes: count,
    }))
}

fn expand_guarded_unicode_class(
    class: &regex_syntax::hir::ClassUnicode,
    context: &mut GuardedExpansionContext<'_>,
) -> Result<GuardedExpansion, BuildError> {
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
                limit: context.work_limit,
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
            symbols.try_push(GuardedSymbol::Byte(byte)).map_err(|_| {
                BuildError::InternalInvariant("exact Unicode-class capacity changed")
            })?;
            paths
                .try_push(GuardedPath { symbols })
                .map_err(|_| BuildError::InternalInvariant("exact Unicode-class paths changed"))?;
        }
    }
    Ok(GuardedExpansion::Fits(GuardedLanguage {
        paths,
        bytes: count,
    }))
}

fn expand_guarded_concat(
    children: &[Hir],
    context: &mut GuardedExpansionContext<'_>,
) -> Result<GuardedExpansion, BuildError> {
    let mut accumulator = match guarded_singleton(ExactVec::default(), context)? {
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

fn expand_guarded_alternation(
    children: &[Hir],
    context: &mut GuardedExpansionContext<'_>,
) -> Result<GuardedExpansion, BuildError> {
    let mut accumulator = GuardedLanguage {
        paths: ExactVec::default(),
        bytes: 0,
    };
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

fn expand_guarded_repetition(
    repetition: &regex_syntax::hir::Repetition,
    context: &mut GuardedExpansionContext<'_>,
) -> Result<GuardedExpansion, BuildError> {
    let Some(maximum) = repetition.max else {
        return Ok(GuardedExpansion::Unsupported);
    };
    let sub = match expand_guarded(&repetition.sub, context)? {
        GuardedExpansion::Fits(language) => language,
        other => return Ok(other),
    };
    expand_bounded_repetition(&sub, repetition.min, maximum, repetition.greedy, context)
}

fn guarded_singleton(
    symbols: ExactVec<GuardedSymbol>,
    context: &mut GuardedExpansionContext<'_>,
) -> Result<GuardedExpansion, BuildError> {
    if context.max_words == 0 {
        return Ok(GuardedExpansion::TooLargeFixedSequence);
    }
    let bytes = symbols
        .iter()
        .filter(|symbol| matches!(symbol, GuardedSymbol::Byte(_)))
        .count();
    let mut paths = context.allocate(1, "guarded finite singleton path")?;
    paths
        .try_push(GuardedPath { symbols })
        .map_err(|_| BuildError::InternalInvariant("exact singleton path capacity changed"))?;
    Ok(GuardedExpansion::Fits(GuardedLanguage { paths, bytes }))
}

fn guarded_look_singleton(
    look: Look,
    context: &mut GuardedExpansionContext<'_>,
) -> Result<GuardedExpansion, BuildError> {
    let mut symbols = context.allocate(1, "guarded finite look symbol")?;
    symbols
        .try_push(GuardedSymbol::Look(look))
        .map_err(|_| BuildError::InternalInvariant("exact look capacity changed"))?;
    guarded_singleton(symbols, context)
}

fn concat_guarded(
    left: &GuardedLanguage,
    right: &GuardedLanguage,
    context: &mut GuardedExpansionContext<'_>,
) -> Result<GuardedExpansion, BuildError> {
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
                    limit: context.work_limit,
                })?;
            let mut symbols =
                context.allocate(symbol_count, "guarded finite concatenation symbols")?;
            push_guarded_symbols(&mut symbols, &left_path.symbols)?;
            push_guarded_symbols(&mut symbols, &right_path.symbols)?;
            paths.try_push(GuardedPath { symbols }).map_err(|_| {
                BuildError::InternalInvariant("exact concatenation paths capacity changed")
            })?;
        }
    }
    Ok(GuardedExpansion::Fits(GuardedLanguage { paths, bytes }))
}

fn append_guarded(
    mut accumulator: GuardedLanguage,
    mut language: GuardedLanguage,
    context: &mut GuardedExpansionContext<'_>,
) -> Result<GuardedExpansion, BuildError> {
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
    move_guarded_paths(&mut accumulator.paths, &mut paths)?;
    move_guarded_paths(&mut language.paths, &mut paths)?;
    Ok(GuardedExpansion::Fits(GuardedLanguage { paths, bytes }))
}

fn push_guarded_symbols(
    target: &mut ExactVec<GuardedSymbol>,
    source: &[GuardedSymbol],
) -> Result<(), BuildError> {
    for &symbol in source {
        target
            .try_push(symbol)
            .map_err(|_| BuildError::InternalInvariant("exact guarded symbol capacity changed"))?;
    }
    Ok(())
}

fn move_guarded_paths(
    source: &mut ExactVec<GuardedPath>,
    target: &mut ExactVec<GuardedPath>,
) -> Result<(), BuildError> {
    source.as_mut_slice().reverse();
    while let Some(path) = source.pop() {
        target
            .try_push(path)
            .map_err(|_| BuildError::InternalInvariant("exact guarded path capacity changed"))?;
    }
    Ok(())
}

fn expand_bounded_repetition(
    sub: &GuardedLanguage,
    minimum: u32,
    maximum: u32,
    greedy: bool,
    context: &mut GuardedExpansionContext<'_>,
) -> Result<GuardedExpansion, BuildError> {
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

fn append_optional_guarded(
    prefixes: &GuardedLanguage,
    sub: &GuardedLanguage,
    greedy: bool,
    context: &mut GuardedExpansionContext<'_>,
) -> Result<GuardedExpansion, BuildError> {
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
    Ok(GuardedExpansion::Fits(GuardedLanguage { paths, bytes }))
}

fn push_guarded_path_copy(
    paths: &mut ExactVec<GuardedPath>,
    path: &GuardedPath,
    context: &mut GuardedExpansionContext<'_>,
) -> Result<(), BuildError> {
    let mut symbols = context.allocate(
        path.symbols.len(),
        "guarded finite optional skipped symbols",
    )?;
    push_guarded_symbols(&mut symbols, &path.symbols)?;
    paths
        .try_push(GuardedPath { symbols })
        .map_err(|_| BuildError::InternalInvariant("exact optional paths capacity changed"))?;
    Ok(())
}

fn push_guarded_path_concat(
    paths: &mut ExactVec<GuardedPath>,
    prefix: &GuardedPath,
    suffix: &GuardedPath,
    context: &mut GuardedExpansionContext<'_>,
) -> Result<(), BuildError> {
    let symbol_count = prefix
        .symbols
        .len()
        .checked_add(suffix.symbols.len())
        .ok_or(BuildError::PlannerWorkLimit {
            needed: u64::MAX,
            limit: context.work_limit,
        })?;
    let mut symbols =
        context.allocate(symbol_count, "guarded finite optional continued symbols")?;
    push_guarded_symbols(&mut symbols, &prefix.symbols)?;
    push_guarded_symbols(&mut symbols, &suffix.symbols)?;
    paths
        .try_push(GuardedPath { symbols })
        .map_err(|_| BuildError::InternalInvariant("exact optional paths capacity changed"))?;
    Ok(())
}

fn repeat_guarded_exact(
    sub: &GuardedLanguage,
    count: u32,
    context: &mut GuardedExpansionContext<'_>,
) -> Result<GuardedExpansion, BuildError> {
    let mut output = match guarded_singleton(ExactVec::default(), context)? {
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
    work: &mut u64,
    work_limit: u64,
) -> Result<Analysis, BuildError> {
    let mut tasks = Vec::new();
    reserve_planner(
        &mut tasks,
        1,
        work,
        work_limit,
        "finite-language analysis tasks",
    )?;
    tasks.push(Task::Visit(hir));
    let mut values = Vec::new();
    while let Some(task) = tasks.pop() {
        charge_planner(work, 1, work_limit)?;
        match task {
            Task::Visit(node) => {
                let analysis = match node.kind() {
                    HirKind::Empty => bounded_shape(Shape::leaf(1, 0), max_words, max_bytes),
                    HirKind::Literal(literal) => {
                        bounded_shape(Shape::leaf(1, literal.0.len()), max_words, max_bytes)
                    }
                    HirKind::Class(Class::Bytes(class)) => {
                        let Some(count) = byte_class_count(class) else {
                            push_analysis(
                                &mut values,
                                Analysis::TooLargeFixedSequence,
                                work,
                                work_limit,
                            )?;
                            continue;
                        };
                        bounded_shape(Shape::leaf(count, count), max_words, max_bytes)
                    }
                    HirKind::Class(Class::Unicode(class)) => {
                        let Some((words, bytes)) = unicode_class_count(class, max_words, max_bytes)
                        else {
                            push_analysis(
                                &mut values,
                                Analysis::TooLargeFixedSequence,
                                work,
                                work_limit,
                            )?;
                            continue;
                        };
                        bounded_shape(Shape::leaf(words, bytes), max_words, max_bytes)
                    }
                    HirKind::Capture(capture) => {
                        push_visit(&mut tasks, &capture.sub, work, work_limit)?;
                        continue;
                    }
                    HirKind::Concat(children) => {
                        push_children(
                            &mut tasks,
                            children,
                            Task::FinishConcat(children.len()),
                            work,
                            work_limit,
                        )?;
                        continue;
                    }
                    HirKind::Alternation(children) => {
                        push_children(
                            &mut tasks,
                            children,
                            Task::FinishAlternation(children.len()),
                            work,
                            work_limit,
                        )?;
                        continue;
                    }
                    HirKind::Look(_) | HirKind::Repetition(_) => Analysis::Unsupported,
                };
                push_analysis(&mut values, analysis, work, work_limit)?;
            }
            Task::FinishConcat(count) | Task::FinishAlternation(count) => {
                let children = pop_analyses(&mut values, count, work, work_limit)?;
                let analysis = combine_analysis(
                    &children,
                    matches!(task, Task::FinishConcat(_)),
                    max_words,
                    max_bytes,
                );
                push_analysis(&mut values, analysis, work, work_limit)?;
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
    values: &mut Vec<Analysis>,
    analysis: Analysis,
    work: &mut u64,
    limit: u64,
) -> Result<(), BuildError> {
    reserve_planner(values, 1, work, limit, "finite-language analysis values")?;
    values.push(analysis);
    Ok(())
}

fn pop_analyses(
    values: &mut Vec<Analysis>,
    count: usize,
    work: &mut u64,
    limit: u64,
) -> Result<Vec<Analysis>, BuildError> {
    if values.len() < count {
        return Err(BuildError::InternalInvariant(
            "finite-language analysis value stack underflow",
        ));
    }
    let mut children = Vec::new();
    reserve_planner(
        &mut children,
        count,
        work,
        limit,
        "finite-language analysis children",
    )?;
    for _ in 0..count {
        children.push(values.pop().ok_or(BuildError::InternalInvariant(
            "finite-language analysis disposition disappeared",
        ))?);
    }
    charge_planner(work, u64::try_from(count).unwrap_or(u64::MAX), limit)?;
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

fn unicode_class(
    class: &regex_syntax::hir::ClassUnicode,
    max_words: usize,
    max_bytes: usize,
    work: &mut u64,
    work_limit: u64,
) -> Result<Option<Language>, BuildError> {
    let count = class.ranges().iter().try_fold(0_usize, |count, range| {
        count
            .checked_add(range.len())
            .ok_or(BuildError::PlannerWorkLimit {
                needed: u64::MAX,
                limit: work_limit,
            })
    })?;
    if count > max_words {
        return Ok(None);
    }
    let mut words = Vec::new();
    reserve_planner(
        &mut words,
        count,
        work,
        work_limit,
        "finite-language Unicode-class words",
    )?;
    let mut bytes = 0_usize;
    for range in class.ranges() {
        for scalar in range.start()..=range.end() {
            let mut buffer = [0_u8; 4];
            let encoded = scalar.encode_utf8(&mut buffer).as_bytes();
            bytes = match bytes.checked_add(encoded.len()) {
                Some(bytes) if bytes <= max_bytes => bytes,
                _ => return Ok(None),
            };
            let mut word = Vec::new();
            reserve_planner(
                &mut word,
                encoded.len(),
                work,
                work_limit,
                "finite-language Unicode scalar bytes",
            )?;
            word.extend_from_slice(encoded);
            words.push(word);
        }
    }
    Ok(Some(Language { words, bytes }))
}

fn byte_class(
    class: &regex_syntax::hir::ClassBytes,
    max_words: usize,
    max_bytes: usize,
    work: &mut u64,
    work_limit: u64,
) -> Result<Option<Language>, BuildError> {
    let count = class.ranges().iter().try_fold(0_usize, |count, range| {
        count
            .checked_add(range.len())
            .ok_or(BuildError::PlannerWorkLimit {
                needed: u64::MAX,
                limit: work_limit,
            })
    })?;
    if count > max_words || count > max_bytes {
        return Ok(None);
    }
    let mut words = Vec::new();
    reserve_planner(
        &mut words,
        count,
        work,
        work_limit,
        "finite-language byte-class words",
    )?;
    for range in class.ranges() {
        for byte in range.start()..=range.end() {
            let mut word = Vec::new();
            reserve_planner(
                &mut word,
                1,
                work,
                work_limit,
                "finite-language byte-class byte",
            )?;
            word.push(byte);
            words.push(word);
        }
    }
    Ok(Some(Language {
        words,
        bytes: count,
    }))
}

fn push_visit<'a>(
    tasks: &mut Vec<Task<'a>>,
    node: &'a Hir,
    work: &mut u64,
    limit: u64,
) -> Result<(), BuildError> {
    reserve_planner(tasks, 1, work, limit, "finite-language task stack")?;
    tasks.push(Task::Visit(node));
    Ok(())
}

fn push_children<'a>(
    tasks: &mut Vec<Task<'a>>,
    children: &'a [Hir],
    finish: Task<'a>,
    work: &mut u64,
    limit: u64,
) -> Result<(), BuildError> {
    let additional = children
        .len()
        .checked_add(1)
        .ok_or(BuildError::PlannerWorkLimit {
            needed: u64::MAX,
            limit,
        })?;
    reserve_planner(tasks, additional, work, limit, "finite-language task stack")?;
    tasks.push(finish);
    tasks.extend(children.iter().rev().map(Task::Visit));
    Ok(())
}

fn push_language(
    values: &mut Vec<Language>,
    language: Language,
    work: &mut u64,
    limit: u64,
) -> Result<(), BuildError> {
    reserve_planner(values, 1, work, limit, "finite-language value stack")?;
    values.push(language);
    Ok(())
}

fn singleton_language(word: Vec<u8>, work: &mut u64, limit: u64) -> Result<Language, BuildError> {
    let bytes = word.len();
    let mut words = Vec::new();
    reserve_planner(&mut words, 1, work, limit, "finite-language singleton word")?;
    words.push(word);
    Ok(Language { words, bytes })
}

fn pop_languages(
    values: &mut Vec<Language>,
    count: usize,
    work: &mut u64,
    limit: u64,
) -> Result<Vec<Language>, BuildError> {
    if values.len() < count {
        return Err(BuildError::InternalInvariant(
            "finite-language value stack underflow",
        ));
    }
    let mut children = Vec::new();
    reserve_planner(
        &mut children,
        count,
        work,
        limit,
        "finite-language child values",
    )?;
    for _ in 0..count {
        children.push(values.pop().ok_or(BuildError::InternalInvariant(
            "finite-language value disappeared while popping children",
        ))?);
    }
    charge_planner(work, u64::try_from(count).unwrap_or(u64::MAX), limit)?;
    children.reverse();
    Ok(children)
}

fn alternate_languages(
    children: Vec<Language>,
    max_words: usize,
    max_bytes: usize,
    work: &mut u64,
    limit: u64,
) -> Result<Option<Language>, BuildError> {
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
    let mut words = Vec::new();
    reserve_planner(
        &mut words,
        word_count,
        work,
        limit,
        "finite-language alternation words",
    )?;
    for mut child in children {
        words.append(&mut child.words);
    }
    Ok(Some(Language {
        words,
        bytes: byte_count,
    }))
}

fn concat_languages(
    children: Vec<Language>,
    max_words: usize,
    max_bytes: usize,
    work: &mut u64,
    limit: u64,
) -> Result<Option<Language>, BuildError> {
    let mut accumulator = singleton_language(Vec::new(), work, limit)?;
    for child in children {
        let Some(next) = concat_pair(&accumulator, &child, max_words, max_bytes, work, limit)?
        else {
            return Ok(None);
        };
        accumulator = next;
    }
    Ok(Some(accumulator))
}

fn concat_pair(
    left: &Language,
    right: &Language,
    max_words: usize,
    max_bytes: usize,
    work: &mut u64,
    limit: u64,
) -> Result<Option<Language>, BuildError> {
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
    let mut words = Vec::new();
    reserve_planner(
        &mut words,
        word_count,
        work,
        limit,
        "finite-language concatenation words",
    )?;
    for left_word in &left.words {
        for right_word in &right.words {
            let length = left_word.len().checked_add(right_word.len()).ok_or(
                BuildError::PlannerWorkLimit {
                    needed: u64::MAX,
                    limit,
                },
            )?;
            let mut word = Vec::new();
            reserve_planner(
                &mut word,
                length,
                work,
                limit,
                "finite-language concatenated bytes",
            )?;
            word.extend_from_slice(left_word);
            word.extend_from_slice(right_word);
            words.push(word);
        }
    }
    Ok(Some(Language {
        words,
        bytes: byte_count,
    }))
}

#[cfg(test)]
mod tests {
    use regex_syntax::ParserBuilder;

    use super::{BuildError, FiniteOutcome, Guard, GuardedDictionary, extract};
    use crate::guarded_ascii_word::{LOOKUP_ID, PACKING_ID, PLAN_ID};

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

    fn guarded(pattern: &str, max_words: usize, max_bytes: usize) -> (GuardedDictionary, u64) {
        match extract(&parse(pattern), max_words, max_bytes, 0, u64::MAX, true) {
            FiniteOutcome::GuardedFiniteBody {
                dictionary, work, ..
            } => (dictionary, work),
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
        let FiniteOutcome::Fits { words, work } = extract(&plain, 16, 16, 7, u64::MAX, false)
        else {
            panic!("ordinary finite language should fit");
        };
        assert_eq!(words, [b"a".to_vec(), b"bb".to_vec()]);
        assert!(work > 7);
        assert!(matches!(
            extract(&plain, 1, 16, 7, u64::MAX, false),
            FiniteOutcome::TooLargeFixedSequence { work } if work > 7
        ));

        let guarded_hir = parse(r"\b(a(?:s|sync)|Self)\b");
        let FiniteOutcome::Unsupported {
            work: incumbent_work,
        } = extract(&guarded_hir, 16, 128, 0, u64::MAX, false)
        else {
            panic!("incumbent finite callers must not derive U5 eagerly");
        };
        let FiniteOutcome::GuardedFiniteBody {
            dictionary,
            accounting,
            work: baseline_work,
        } = extract(&guarded_hir, 16, 128, 0, u64::MAX, true)
        else {
            panic!("guarded baseline should fit");
        };
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
            FiniteOutcome::GuardedFiniteBody { work, .. } if work == expected_actual
        ));
        let one_below = exact_limit.checked_sub(1).unwrap();
        assert!(matches!(
            extract(&guarded_hir, 16, 128, initial, one_below, true),
            FiniteOutcome::ResourceFailure {
                error: BuildError::PlannerWorkLimit { limit, .. },
                work,
            } if limit == one_below && work >= initial && work <= one_below
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
}
