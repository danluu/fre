//! Bounded HIR certificate for ordered finite-anchor execution plans.
//!
//! This module does not execute a regex. It proves, without consulting a
//! pattern string or benchmark identity, that every ordered root branch can be
//! factored into an assertion-free prefix, one nonempty finite ASCII-folded
//! language, and a suffix. It also derives bytes that no match can consume.
//! A later executor may use those facts as candidate hints, but the original
//! branch order and semantic verifier remain authoritative.

use core::mem::size_of;

use fre_exact_alloc::{CopyError, ExactVec};
use regex_syntax::hir::{Class, Hir, HirKind};

use crate::compile::CompileBudget;
use crate::program::ByteSet;
use crate::{Error, Resource};

const MAX_ROOT_BRANCHES: usize = 8;
const MAX_ANCHOR_PATTERNS: usize = 4_096;
const MAX_ANCHOR_PATTERN_BYTES: usize = 1 << 20;
const MAX_ANCHOR_WORD_BYTES: usize = 64;
const MIN_ANCHOR_WORD_BYTES: usize = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Limits {
    pub(crate) max_scratch_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_scratch_bytes: 16 << 20,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Accounting {
    pub(crate) work: usize,
    pub(crate) scratch_peak_bytes: usize,
    pub(crate) retained_bytes: usize,
    pub(crate) retained_allocations: usize,
    pub(crate) branches: usize,
    pub(crate) anchor_patterns: usize,
    pub(crate) anchor_pattern_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LanguageFacts {
    count: usize,
    total_bytes: usize,
    min_bytes: usize,
    max_bytes: usize,
}

impl LanguageFacts {
    const EMPTY: Self = Self {
        count: 1,
        total_bytes: 0,
        min_bytes: 0,
        max_bytes: 0,
    };
}

#[derive(Debug)]
pub(crate) struct Branch<'a> {
    parts: ExactVec<&'a Hir>,
    anchor_start: usize,
    anchor_end: usize,
    words: ExactVec<Word>,
}

impl Branch<'_> {
    pub(crate) fn prefix(&self) -> &[&Hir] {
        &self.parts[..self.anchor_start]
    }

    pub(crate) fn suffix(&self) -> &[&Hir] {
        &self.parts[self.anchor_end..]
    }

    pub(crate) fn words(&self) -> impl Iterator<Item = &[u8]> {
        self.words.iter().map(Word::bytes)
    }
}

#[derive(Debug)]
pub(crate) struct Certificate<'a> {
    branches: ExactVec<Branch<'a>>,
    delimiters: ByteSet,
    accounting: Accounting,
}

impl Certificate<'_> {
    pub(crate) fn branches(&self) -> &[Branch<'_>] {
        &self.branches
    }

    pub(crate) const fn delimiters(&self) -> ByteSet {
        self.delimiters
    }

    pub(crate) const fn accounting(&self) -> Accounting {
        self.accounting
    }

    pub(crate) fn release(self, budget: &mut CompileBudget) -> Result<(), Error> {
        let retained_bytes = self.accounting.retained_bytes;
        drop(self);
        budget.release_construction_bytes(retained_bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Word {
    bytes: [u8; MAX_ANCHOR_WORD_BYTES],
    len: u8,
}

impl Word {
    const EMPTY: Self = Self {
        bytes: [0; MAX_ANCHOR_WORD_BYTES],
        len: 0,
    };

    fn bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    fn push(mut self, byte: u8) -> Option<Self> {
        let index = usize::from(self.len);
        let slot = self.bytes.get_mut(index)?;
        *slot = byte;
        self.len = self.len.checked_add(1)?;
        Some(self)
    }

    fn concat(self, tail: Self) -> Option<Self> {
        let mut output = self;
        for &byte in tail.bytes() {
            output = output.push(byte)?;
        }
        Some(output)
    }
}

struct Words {
    values: ExactVec<Word>,
    allocated_bytes: usize,
}

#[derive(Clone, Copy)]
struct ConsumableFacts {
    bytes: ByteSet,
    nullable: bool,
}

struct Meter<'a> {
    budget: &'a mut CompileBudget,
    max_scratch_bytes: usize,
    work: usize,
    scratch: usize,
    scratch_peak: usize,
}

impl<'a> Meter<'a> {
    const fn new(limits: Limits, budget: &'a mut CompileBudget) -> Self {
        Self {
            budget,
            max_scratch_bytes: limits.max_scratch_bytes,
            work: 0,
            scratch: 0,
            scratch_peak: 0,
        }
    }

    fn charge(&mut self, amount: usize) -> Result<(), Error> {
        self.budget.charge(amount)?;
        self.work = self
            .work
            .checked_add(amount)
            .ok_or(Error::ArithmeticOverflow {
                resource: Resource::CompileWork,
            })?;
        Ok(())
    }

    fn acquire(&mut self, bytes: usize) -> Result<(), Error> {
        let required = self
            .scratch
            .checked_add(bytes)
            .ok_or(Error::ArithmeticOverflow {
                resource: Resource::ProgramBytes,
            })?;
        enforce(required, self.max_scratch_bytes, Resource::ProgramBytes)?;
        self.budget.acquire_checked_construction_bytes(bytes)?;
        self.scratch = required;
        self.scratch_peak = self.scratch_peak.max(required);
        Ok(())
    }

    fn release(&mut self, bytes: usize) -> Result<(), Error> {
        let remaining = self
            .scratch
            .checked_sub(bytes)
            .ok_or(Error::InternalInvariant(
                "finite-anchor scratch release underflowed",
            ))?;
        self.budget.release_construction_bytes(bytes)?;
        self.scratch = remaining;
        Ok(())
    }

    fn release_all(&mut self) -> Result<(), Error> {
        let bytes = self.scratch;
        self.budget.release_construction_bytes(bytes)?;
        self.scratch = 0;
        Ok(())
    }
}

pub(crate) fn certify<'a>(
    hir: &'a Hir,
    limits: Limits,
    budget: &mut CompileBudget,
) -> Result<Option<Certificate<'a>>, Error> {
    let mut meter = Meter::new(limits, budget);
    let result = certify_inner(hir, &mut meter);
    match result {
        Ok(Some(certificate)) => Ok(Some(certificate)),
        Ok(None) => {
            meter.release_all()?;
            Ok(None)
        }
        Err(error) => {
            meter.release_all()?;
            Err(error)
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the finite-anchor transaction keeps retained-allocation and authoritative-budget accounting adjacent"
)]
fn certify_inner<'a>(
    hir: &'a Hir,
    meter: &mut Meter<'_>,
) -> Result<Option<Certificate<'a>>, Error> {
    let Some(consumable) = consumable_facts(hir, meter)? else {
        return Ok(None);
    };
    if consumable.nullable {
        return Ok(None);
    }
    meter.charge(consumable.bytes.0.len())?;
    let delimiters = complement(consumable.bytes);
    meter.charge(delimiters.0.len())?;
    if is_empty(delimiters) {
        return Ok(None);
    }

    let outer_count = flattened_count(hir, meter)?;
    let (mut outer, outer_bytes) = exact_vec(outer_count, meter)?;
    flatten(hir, &mut outer, meter)?;
    if outer.len() != outer_count {
        return Err(Error::InternalInvariant(
            "finite-anchor outer flatten census changed",
        ));
    }

    let mut root_alternation = None;
    for (index, part) in outer.iter().enumerate() {
        meter.charge(1)?;
        if let HirKind::Alternation(alternatives) = part.kind() {
            if !(2..=MAX_ROOT_BRANCHES).contains(&alternatives.len()) {
                return Ok(None);
            }
            root_alternation = Some(index);
            break;
        }
    }
    let branch_count = root_alternation.map_or(1, |index| match outer[index].kind() {
        HirKind::Alternation(branches) => branches.len(),
        _ => 1,
    });
    let (mut branches, _branch_slots_bytes) = exact_vec(branch_count, meter)?;

    if let Some(alternation_index) = root_alternation {
        let HirKind::Alternation(alternatives) = outer[alternation_index].kind() else {
            return Err(Error::InternalInvariant(
                "finite-anchor root alternation changed kind",
            ));
        };
        for alternative in alternatives {
            let suffix_start =
                alternation_index
                    .checked_add(1)
                    .ok_or(Error::ArithmeticOverflow {
                        resource: Resource::TemporaryStates,
                    })?;
            let Some(branch) = build_branch(
                &outer[..alternation_index],
                Some(alternative),
                &outer[suffix_start..],
                meter,
            )?
            else {
                return Ok(None);
            };
            meter.charge(1)?;
            branches
                .try_push(branch)
                .map_err(|_| Error::InternalInvariant("finite-anchor branch census changed"))?;
        }
    } else {
        let Some(branch) = build_branch(&outer, None, &[], meter)? else {
            return Ok(None);
        };
        meter.charge(1)?;
        branches
            .try_push(branch)
            .map_err(|_| Error::InternalInvariant("finite-anchor branch census changed"))?;
    }
    meter.release(outer_bytes)?;
    drop(outer);

    let mut anchor_patterns = 0_usize;
    let mut anchor_pattern_bytes = 0_usize;
    let mut retained_bytes = checked_mul(
        branches.len(),
        size_of::<Branch<'_>>(),
        Resource::ProgramBytes,
    )?;
    let mut retained_allocations = 1_usize;
    for branch in &branches {
        meter.charge(3)?; // branch visit and its two retained-vector censuses
        retained_bytes = checked_add(
            retained_bytes,
            checked_mul(
                branch.parts.len(),
                size_of::<&Hir>(),
                Resource::ProgramBytes,
            )?,
            Resource::ProgramBytes,
        )?;
        retained_bytes = checked_add(
            retained_bytes,
            checked_mul(
                branch.words.len(),
                size_of::<Word>(),
                Resource::ProgramBytes,
            )?,
            Resource::ProgramBytes,
        )?;
        retained_allocations = checked_add(retained_allocations, 2, Resource::TemporaryStates)?;
        anchor_patterns = checked_add(
            anchor_patterns,
            branch.words.len(),
            Resource::TemporaryStates,
        )?;
        for word in &branch.words {
            meter.charge(checked_add(1, word.bytes().len(), Resource::CompileWork)?)?;
            anchor_pattern_bytes = checked_add(
                anchor_pattern_bytes,
                word.bytes().len(),
                Resource::LiteralBytes,
            )?;
        }
    }
    if retained_bytes != meter.scratch {
        return Err(Error::InternalInvariant(
            "finite-anchor retained allocation census differs from construction bytes",
        ));
    }
    Ok(Some(Certificate {
        accounting: Accounting {
            work: meter.work,
            scratch_peak_bytes: meter.scratch_peak,
            retained_bytes,
            retained_allocations,
            branches: branches.len(),
            anchor_patterns,
            anchor_pattern_bytes,
        },
        branches,
        delimiters,
    }))
}

fn build_branch<'a>(
    before: &[&'a Hir],
    alternative: Option<&'a Hir>,
    after: &[&'a Hir],
    meter: &mut Meter<'_>,
) -> Result<Option<Branch<'a>>, Error> {
    let alternative_count = if let Some(hir) = alternative {
        flattened_count(hir, meter)?
    } else {
        0
    };
    let count = before
        .len()
        .checked_add(alternative_count)
        .and_then(|value| value.checked_add(after.len()))
        .ok_or(Error::ArithmeticOverflow {
            resource: Resource::TemporaryStates,
        })?;
    let (mut parts, _parts_bytes) = exact_vec(count, meter)?;
    for &part in before {
        meter.charge(1)?;
        push(
            &mut parts,
            part,
            "finite-anchor prefix parts exceeded census",
        )?;
    }
    if let Some(alternative) = alternative {
        flatten(alternative, &mut parts, meter)?;
    }
    for &part in after {
        meter.charge(1)?;
        push(
            &mut parts,
            part,
            "finite-anchor suffix parts exceeded census",
        )?;
    }
    if parts.len() != count {
        return Err(Error::InternalInvariant(
            "finite-anchor branch flatten census changed",
        ));
    }
    let Some((anchor_start, anchor_end, facts)) = best_anchor(&parts, meter)? else {
        return Ok(None);
    };
    let words = materialize_parts(&parts[anchor_start..anchor_end], facts, meter)?;
    let mut malformed_word = words.values.len() != facts.count;
    for word in &words.values {
        meter.charge(1)?;
        malformed_word |= word.bytes().len() < MIN_ANCHOR_WORD_BYTES
            || word.bytes().len() > MAX_ANCHOR_WORD_BYTES;
    }
    if malformed_word {
        return Err(Error::InternalInvariant(
            "finite-anchor materialization differs from census",
        ));
    }
    Ok(Some(Branch {
        parts,
        anchor_start,
        anchor_end,
        words: words.values,
    }))
}

fn best_anchor(
    parts: &[&Hir],
    meter: &mut Meter<'_>,
) -> Result<Option<(usize, usize, LanguageFacts)>, Error> {
    let mut best = None;
    for start in 0..parts.len() {
        let mut combined = LanguageFacts::EMPTY;
        for (end, part) in parts.iter().enumerate().skip(start) {
            meter.charge(1)?;
            let Some(facts) = language_facts(part, meter)? else {
                break;
            };
            let Some(next) = concat_facts(combined, facts, meter)? else {
                break;
            };
            combined = next;
            if combined.min_bytes < MIN_ANCHOR_WORD_BYTES {
                continue;
            }
            let candidate = (
                start,
                end.checked_add(1).ok_or(Error::ArithmeticOverflow {
                    resource: Resource::TemporaryStates,
                })?,
                combined,
            );
            meter.charge(1)?;
            if best.is_none_or(|(_, _, current): (_, _, LanguageFacts)| {
                candidate.2.min_bytes > current.min_bytes
                    || (candidate.2.min_bytes == current.min_bytes
                        && candidate.2.count < current.count)
            }) {
                best = Some(candidate);
            }
        }
    }
    Ok(best)
}

#[allow(
    clippy::too_many_lines,
    reason = "the finite-language census keeps each accepted HIR form and its checked arithmetic together"
)]
fn language_facts(hir: &Hir, meter: &mut Meter<'_>) -> Result<Option<LanguageFacts>, Error> {
    meter.charge(1)?;
    match hir.kind() {
        HirKind::Empty => Ok(Some(LanguageFacts::EMPTY)),
        HirKind::Literal(literal) => {
            meter.charge(literal.0.len())?;
            if literal.0.iter().any(|byte| !byte.is_ascii())
                || literal.0.len() > MAX_ANCHOR_WORD_BYTES
            {
                return Ok(None);
            }
            Ok(Some(LanguageFacts {
                count: 1,
                total_bytes: literal.0.len(),
                min_bytes: literal.0.len(),
                max_bytes: literal.0.len(),
            }))
        }
        HirKind::Class(Class::Bytes(class)) => {
            let normalized = normalized_class(class, meter)?;
            meter.charge(normalized.len())?;
            let count = normalized.iter().filter(|&&set| set).count();
            if count == 0 {
                return Ok(None);
            }
            Ok(Some(LanguageFacts {
                count,
                total_bytes: count,
                min_bytes: 1,
                max_bytes: 1,
            }))
        }
        HirKind::Class(Class::Unicode(_)) | HirKind::Look(_) => Ok(None),
        HirKind::Capture(capture) => language_facts(&capture.sub, meter),
        HirKind::Concat(parts) => {
            let mut facts = LanguageFacts::EMPTY;
            for part in parts {
                let Some(child) = language_facts(part, meter)? else {
                    return Ok(None);
                };
                let Some(next) = concat_facts(facts, child, meter)? else {
                    return Ok(None);
                };
                facts = next;
            }
            Ok(Some(facts))
        }
        HirKind::Alternation(branches) => {
            if branches.is_empty() {
                return Ok(None);
            }
            let mut facts = LanguageFacts {
                count: 0,
                total_bytes: 0,
                min_bytes: usize::MAX,
                max_bytes: 0,
            };
            for branch in branches {
                let Some(child) = language_facts(branch, meter)? else {
                    return Ok(None);
                };
                facts.count = checked_add(facts.count, child.count, Resource::TemporaryStates)?;
                facts.total_bytes =
                    checked_add(facts.total_bytes, child.total_bytes, Resource::LiteralBytes)?;
                facts.min_bytes = facts.min_bytes.min(child.min_bytes);
                facts.max_bytes = facts.max_bytes.max(child.max_bytes);
                if !facts_within_limits(facts) {
                    return Ok(None);
                }
            }
            Ok(Some(facts))
        }
        HirKind::Repetition(repetition) => {
            let Some(maximum) = repetition.max else {
                return Ok(None);
            };
            if maximum < repetition.min
                || maximum
                    > u32::try_from(MAX_ANCHOR_WORD_BYTES).map_err(|_| {
                        Error::InternalInvariant("inline anchor word bound exceeds u32")
                    })?
            {
                return Ok(None);
            }
            let Some(child) = language_facts(&repetition.sub, meter)? else {
                return Ok(None);
            };
            let mut total = LanguageFacts {
                count: 0,
                total_bytes: 0,
                min_bytes: usize::MAX,
                max_bytes: 0,
            };
            for count in repetition.min..=maximum {
                meter.charge(1)?;
                let mut repeated = LanguageFacts::EMPTY;
                for _ in 0..count {
                    let Some(next) = concat_facts(repeated, child, meter)? else {
                        return Ok(None);
                    };
                    repeated = next;
                }
                total.count = checked_add(total.count, repeated.count, Resource::TemporaryStates)?;
                total.total_bytes = checked_add(
                    total.total_bytes,
                    repeated.total_bytes,
                    Resource::LiteralBytes,
                )?;
                total.min_bytes = total.min_bytes.min(repeated.min_bytes);
                total.max_bytes = total.max_bytes.max(repeated.max_bytes);
                if !facts_within_limits(total) {
                    return Ok(None);
                }
            }
            Ok(Some(total))
        }
    }
}

fn concat_facts(
    left: LanguageFacts,
    right: LanguageFacts,
    meter: &mut Meter<'_>,
) -> Result<Option<LanguageFacts>, Error> {
    meter.charge(1)?;
    let count = checked_mul(left.count, right.count, Resource::TemporaryStates)?;
    let total_bytes = checked_add(
        checked_mul(left.total_bytes, right.count, Resource::LiteralBytes)?,
        checked_mul(right.total_bytes, left.count, Resource::LiteralBytes)?,
        Resource::LiteralBytes,
    )?;
    let facts = LanguageFacts {
        count,
        total_bytes,
        min_bytes: checked_add(left.min_bytes, right.min_bytes, Resource::LiteralBytes)?,
        max_bytes: checked_add(left.max_bytes, right.max_bytes, Resource::LiteralBytes)?,
    };
    Ok(facts_within_limits(facts).then_some(facts))
}

fn facts_within_limits(facts: LanguageFacts) -> bool {
    facts.count <= MAX_ANCHOR_PATTERNS
        && facts.total_bytes <= MAX_ANCHOR_PATTERN_BYTES
        && facts.max_bytes <= MAX_ANCHOR_WORD_BYTES
}

fn materialize_parts(
    parts: &[&Hir],
    facts: LanguageFacts,
    meter: &mut Meter<'_>,
) -> Result<Words, Error> {
    let mut accumulated = singleton_words(Word::EMPTY, meter)?;
    for part in parts {
        let child_facts = language_facts(part, meter)?.ok_or(Error::InternalInvariant(
            "selected finite-anchor part became ineligible",
        ))?;
        let child = materialize_hir(part, child_facts, meter)?;
        let combined_facts = concat_facts(
            words_facts(&accumulated.values, meter)?,
            words_facts(&child.values, meter)?,
            meter,
        )?
        .ok_or(Error::InternalInvariant(
            "selected finite-anchor product exceeded its census",
        ))?;
        let mut combined = allocate_words(combined_facts.count, meter)?;
        for &left in &*accumulated.values {
            for &right in &*child.values {
                meter.charge(checked_add(
                    1,
                    checked_add(
                        left.bytes().len(),
                        right.bytes().len(),
                        Resource::CompileWork,
                    )?,
                    Resource::CompileWork,
                )?)?;
                let word = left.concat(right).ok_or(Error::InternalInvariant(
                    "finite-anchor word exceeded inline bound",
                ))?;
                push(
                    &mut combined.values,
                    word,
                    "finite-anchor product exceeded census",
                )?;
            }
        }
        release_words(accumulated, meter)?;
        release_words(child, meter)?;
        accumulated = combined;
    }
    if accumulated.values.len() != facts.count {
        return Err(Error::InternalInvariant(
            "finite-anchor part product count differs from census",
        ));
    }
    Ok(accumulated)
}

fn materialize_hir(hir: &Hir, facts: LanguageFacts, meter: &mut Meter<'_>) -> Result<Words, Error> {
    meter.charge(1)?;
    match hir.kind() {
        HirKind::Empty => singleton_words(Word::EMPTY, meter),
        HirKind::Literal(literal) => {
            let mut word = Word::EMPTY;
            for &byte in &literal.0 {
                meter.charge(1)?;
                word = word
                    .push(byte.to_ascii_lowercase())
                    .ok_or(Error::InternalInvariant(
                        "finite-anchor literal exceeded inline word",
                    ))?;
            }
            singleton_words(word, meter)
        }
        HirKind::Class(Class::Bytes(class)) => {
            let normalized = normalized_class(class, meter)?;
            let mut output = allocate_words(facts.count, meter)?;
            meter.charge(normalized.len())?;
            for (byte, &present) in normalized.iter().enumerate() {
                if present {
                    meter.charge(1)?;
                    let word = Word::EMPTY
                        .push(u8::try_from(byte).map_err(|_| {
                            Error::InternalInvariant("normalized class byte exceeds u8")
                        })?)
                        .ok_or(Error::InternalInvariant(
                            "normalized class byte exceeded inline word",
                        ))?;
                    push(
                        &mut output.values,
                        word,
                        "finite-anchor class exceeded census",
                    )?;
                }
            }
            Ok(output)
        }
        HirKind::Capture(capture) => materialize_hir(&capture.sub, facts, meter),
        HirKind::Concat(parts) => materialize_concat(parts, facts, meter),
        HirKind::Alternation(branches) => {
            let mut output = allocate_words(facts.count, meter)?;
            for branch in branches {
                let branch_facts = language_facts(branch, meter)?.ok_or(
                    Error::InternalInvariant("finite-anchor alternative became ineligible"),
                )?;
                let words = materialize_hir(branch, branch_facts, meter)?;
                for &word in &*words.values {
                    meter.charge(checked_add(1, word.bytes().len(), Resource::CompileWork)?)?;
                    push(
                        &mut output.values,
                        word,
                        "finite-anchor alternatives exceeded census",
                    )?;
                }
                release_words(words, meter)?;
            }
            Ok(output)
        }
        HirKind::Repetition(repetition) => {
            let child_facts = language_facts(&repetition.sub, meter)?.ok_or(
                Error::InternalInvariant("finite-anchor repetition became ineligible"),
            )?;
            let child = materialize_hir(&repetition.sub, child_facts, meter)?;
            let mut output = allocate_words(facts.count, meter)?;
            let maximum = repetition.max.ok_or(Error::InternalInvariant(
                "finite-anchor repetition lost finite maximum",
            ))?;
            if repetition.greedy {
                for count in (repetition.min..=maximum).rev() {
                    emit_power(&child.values, count, Word::EMPTY, &mut output.values, meter)?;
                }
            } else {
                for count in repetition.min..=maximum {
                    emit_power(&child.values, count, Word::EMPTY, &mut output.values, meter)?;
                }
            }
            release_words(child, meter)?;
            Ok(output)
        }
        HirKind::Class(Class::Unicode(_)) | HirKind::Look(_) => Err(Error::InternalInvariant(
            "ineligible finite-anchor HIR reached materialization",
        )),
    }
}

fn emit_power(
    words: &[Word],
    remaining: u32,
    prefix: Word,
    output: &mut ExactVec<Word>,
    meter: &mut Meter<'_>,
) -> Result<(), Error> {
    meter.charge(1)?;
    if remaining == 0 {
        return push(output, prefix, "finite-anchor repetition exceeded census");
    }
    for &word in words {
        meter.charge(checked_add(1, word.bytes().len(), Resource::CompileWork)?)?;
        let combined = prefix.concat(word).ok_or(Error::InternalInvariant(
            "finite-anchor repetition exceeded inline word",
        ))?;
        emit_power(
            words,
            remaining.checked_sub(1).ok_or(Error::InternalInvariant(
                "finite-anchor repetition counter underflowed",
            ))?,
            combined,
            output,
            meter,
        )?;
    }
    Ok(())
}

fn materialize_concat(
    parts: &[Hir],
    facts: LanguageFacts,
    meter: &mut Meter<'_>,
) -> Result<Words, Error> {
    let mut accumulated = singleton_words(Word::EMPTY, meter)?;
    for part in parts {
        let child_facts = language_facts(part, meter)?.ok_or(Error::InternalInvariant(
            "selected finite-anchor concat child became ineligible",
        ))?;
        let child = materialize_hir(part, child_facts, meter)?;
        let combined_facts = concat_facts(
            words_facts(&accumulated.values, meter)?,
            words_facts(&child.values, meter)?,
            meter,
        )?
        .ok_or(Error::InternalInvariant(
            "selected finite-anchor concat product exceeded its census",
        ))?;
        let mut combined = allocate_words(combined_facts.count, meter)?;
        for &left in &*accumulated.values {
            for &right in &*child.values {
                meter.charge(checked_add(
                    1,
                    checked_add(
                        left.bytes().len(),
                        right.bytes().len(),
                        Resource::CompileWork,
                    )?,
                    Resource::CompileWork,
                )?)?;
                let word = left.concat(right).ok_or(Error::InternalInvariant(
                    "finite-anchor concat word exceeded inline bound",
                ))?;
                push(
                    &mut combined.values,
                    word,
                    "finite-anchor concat product exceeded census",
                )?;
            }
        }
        release_words(accumulated, meter)?;
        release_words(child, meter)?;
        accumulated = combined;
    }
    if accumulated.values.len() != facts.count {
        return Err(Error::InternalInvariant(
            "finite-anchor concat product count differs from census",
        ));
    }
    Ok(accumulated)
}

fn singleton_words(word: Word, meter: &mut Meter<'_>) -> Result<Words, Error> {
    let mut words = allocate_words(1, meter)?;
    meter.charge(1)?;
    push(
        &mut words.values,
        word,
        "finite-anchor singleton allocation was empty",
    )?;
    Ok(words)
}

fn allocate_words(count: usize, meter: &mut Meter<'_>) -> Result<Words, Error> {
    let (values, allocated_bytes) = exact_vec(count, meter)?;
    Ok(Words {
        values,
        allocated_bytes,
    })
}

fn release_words(words: Words, meter: &mut Meter<'_>) -> Result<(), Error> {
    let bytes = words.allocated_bytes;
    meter.charge(1)?;
    drop(words);
    meter.release(bytes)
}

fn words_facts(words: &[Word], meter: &mut Meter<'_>) -> Result<LanguageFacts, Error> {
    let mut min_bytes = usize::MAX;
    let mut max_bytes = 0_usize;
    let mut total_bytes = 0_usize;
    for word in words {
        meter.charge(checked_add(1, word.bytes().len(), Resource::CompileWork)?)?;
        min_bytes = min_bytes.min(word.bytes().len());
        max_bytes = max_bytes.max(word.bytes().len());
        total_bytes = checked_add(total_bytes, word.bytes().len(), Resource::LiteralBytes)?;
    }
    if words.is_empty() {
        min_bytes = 0;
    }
    Ok(LanguageFacts {
        count: words.len(),
        total_bytes,
        min_bytes,
        max_bytes,
    })
}

fn normalized_class(
    class: &regex_syntax::hir::ClassBytes,
    meter: &mut Meter<'_>,
) -> Result<[bool; 256], Error> {
    let mut normalized = [false; 256];
    for range in class.ranges() {
        for byte in range.start()..=range.end() {
            meter.charge(1)?;
            if !byte.is_ascii() {
                return Ok([false; 256]);
            }
            normalized[usize::from(byte.to_ascii_lowercase())] = true;
        }
    }
    Ok(normalized)
}

fn consumable_facts(hir: &Hir, meter: &mut Meter<'_>) -> Result<Option<ConsumableFacts>, Error> {
    meter.charge(1)?;
    match hir.kind() {
        HirKind::Empty => Ok(Some(ConsumableFacts {
            bytes: ByteSet::empty(),
            nullable: true,
        })),
        HirKind::Literal(literal) => {
            let mut bytes = ByteSet::empty();
            for &byte in &literal.0 {
                meter.charge(1)?;
                bytes.insert(byte);
            }
            Ok(Some(ConsumableFacts {
                bytes,
                nullable: literal.0.is_empty(),
            }))
        }
        HirKind::Class(Class::Bytes(class)) => {
            let mut bytes = ByteSet::empty();
            for range in class.ranges() {
                for byte in range.start()..=range.end() {
                    meter.charge(1)?;
                    bytes.insert(byte);
                }
            }
            Ok(Some(ConsumableFacts {
                bytes,
                nullable: false,
            }))
        }
        HirKind::Class(Class::Unicode(_)) | HirKind::Look(_) => Ok(None),
        HirKind::Capture(capture) => consumable_facts(&capture.sub, meter),
        HirKind::Concat(parts) => {
            let mut facts = ConsumableFacts {
                bytes: ByteSet::empty(),
                nullable: true,
            };
            for part in parts {
                let Some(child) = consumable_facts(part, meter)? else {
                    return Ok(None);
                };
                meter.charge(facts.bytes.0.len())?;
                facts.bytes = union(facts.bytes, child.bytes);
                facts.nullable &= child.nullable;
            }
            Ok(Some(facts))
        }
        HirKind::Alternation(branches) => {
            let Some((first, rest)) = branches.split_first() else {
                return Ok(None);
            };
            let Some(mut facts) = consumable_facts(first, meter)? else {
                return Ok(None);
            };
            for branch in rest {
                let Some(child) = consumable_facts(branch, meter)? else {
                    return Ok(None);
                };
                meter.charge(facts.bytes.0.len())?;
                facts.bytes = union(facts.bytes, child.bytes);
                facts.nullable |= child.nullable;
            }
            Ok(Some(facts))
        }
        HirKind::Repetition(repetition) => {
            let Some(mut facts) = consumable_facts(&repetition.sub, meter)? else {
                return Ok(None);
            };
            if repetition.min == 0 {
                facts.nullable = true;
            }
            Ok(Some(facts))
        }
    }
}

fn flattened_count(hir: &Hir, meter: &mut Meter<'_>) -> Result<usize, Error> {
    meter.charge(1)?;
    match hir.kind() {
        HirKind::Capture(capture) => flattened_count(&capture.sub, meter),
        HirKind::Concat(parts) => parts.iter().try_fold(0_usize, |total, part| {
            checked_add(
                total,
                flattened_count(part, meter)?,
                Resource::TemporaryStates,
            )
        }),
        _ => Ok(1),
    }
}

fn flatten<'a>(
    hir: &'a Hir,
    output: &mut ExactVec<&'a Hir>,
    meter: &mut Meter<'_>,
) -> Result<(), Error> {
    meter.charge(1)?;
    match hir.kind() {
        HirKind::Capture(capture) => flatten(&capture.sub, output, meter),
        HirKind::Concat(parts) => {
            for part in parts {
                flatten(part, output, meter)?;
            }
            Ok(())
        }
        _ => push(output, hir, "finite-anchor flatten exceeded census"),
    }
}

fn exact_vec<T>(count: usize, meter: &mut Meter<'_>) -> Result<(ExactVec<T>, usize), Error> {
    let bytes = checked_mul(count, size_of::<T>(), Resource::ProgramBytes)?;
    // Prepay the allocator call, the exact-capacity census and the eventual
    // deallocation so both successful retention and every failed transaction
    // remain inside the authoritative compile-work limit.
    meter.charge(checked_add(2, count, Resource::CompileWork)?)?;
    meter.acquire(bytes)?;
    let values = ExactVec::try_with_capacity(count).map_err(|error| match error {
        CopyError::LayoutOverflow => Error::ArithmeticOverflow {
            resource: Resource::ProgramBytes,
        },
        CopyError::AllocationFailed => Error::AllocationFailed {
            resource: Resource::ProgramBytes,
            items: count,
        },
    })?;
    Ok((values, bytes))
}

fn push<T>(values: &mut ExactVec<T>, value: T, invariant: &'static str) -> Result<(), Error> {
    values
        .try_push(value)
        .map_err(|_| Error::InternalInvariant(invariant))
}

fn union(left: ByteSet, right: ByteSet) -> ByteSet {
    ByteSet(core::array::from_fn(|index| left.0[index] | right.0[index]))
}

fn complement(bytes: ByteSet) -> ByteSet {
    ByteSet(bytes.0.map(|word| !word))
}

fn is_empty(bytes: ByteSet) -> bool {
    bytes.0.iter().all(|&word| word == 0)
}

fn checked_add(left: usize, right: usize, resource: Resource) -> Result<usize, Error> {
    left.checked_add(right)
        .ok_or(Error::ArithmeticOverflow { resource })
}

fn checked_mul(left: usize, right: usize, resource: Resource) -> Result<usize, Error> {
    left.checked_mul(right)
        .ok_or(Error::ArithmeticOverflow { resource })
}

fn enforce(required: usize, limit: usize, resource: Resource) -> Result<(), Error> {
    if required > limit {
        return Err(Error::ResourceLimit {
            resource,
            required,
            limit,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use regex_syntax::ParserBuilder;

    use super::*;
    use crate::CompileLimits;

    fn parsed(pattern: &str, case_insensitive: bool, unicode: bool) -> Hir {
        ParserBuilder::new()
            .unicode(unicode)
            .utf8(false)
            .case_insensitive(case_insensitive)
            .build()
            .parse(pattern)
            .unwrap()
    }

    fn certify_default(hir: &Hir) -> Certificate<'_> {
        let mut budget = CompileBudget::new(CompileLimits::default());
        certify(hir, Limits::default(), &mut budget)
            .unwrap()
            .unwrap()
    }

    #[test]
    fn ordered_url_shape_certifies_per_branch_folded_anchors_and_whitespace_delimiters() {
        let hir = parsed(
            r"((?:(?:(?:https?|ftp)://(?:[0-9]{1,3}\.){3}[0-9]{1,3})|(?:(?:https?|ftp)://)?(?:[a-z0-9]+\.)*[a-z0-9]+\.(?:COM|ORG|XN--P1AI))(?::[0-9]{2,5})?(?:/[a-z0-9/?#]+)*)",
            true,
            false,
        );
        let certificate = certify_default(&hir);
        assert_eq!(certificate.branches().len(), 2);
        let first = certificate.branches()[0]
            .words()
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        let second = certificate.branches()[1]
            .words()
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        assert_eq!(
            first,
            [
                b"https://".to_vec(),
                b"http://".to_vec(),
                b"ftp://".to_vec()
            ]
        );
        assert_eq!(
            second,
            [b".com".to_vec(), b".org".to_vec(), b".xn--p1ai".to_vec()]
        );
        for byte in [b' ', b'\t', b'\n', b'\x0b', b'\x0c', b'\r'] {
            assert!(certificate.delimiters().contains(byte));
        }
        for byte in [b'a', b'0', b'.', b'/', b':', b'?', b'#'] {
            assert!(!certificate.delimiters().contains(byte));
        }
        assert!(certificate.accounting().work > 0);
        assert_eq!(certificate.accounting().branches, 2);
        assert_eq!(certificate.accounting().anchor_patterns, 6);
        assert!(!certificate.branches()[0].suffix().is_empty());
        assert!(!certificate.branches()[1].prefix().is_empty());
    }

    #[test]
    fn branch_order_and_greedy_optional_word_order_are_retained() {
        let hir = parsed(r"(?:https?|ftp)://x|(?:AB|A)\.COM", true, false);
        let certificate = certify_default(&hir);
        let words = certificate
            .branches()
            .iter()
            .map(|branch| branch.words().map(<[u8]>::to_vec).collect::<Vec<_>>())
            .collect::<Vec<_>>();
        assert_eq!(
            words,
            [
                vec![
                    b"https://x".to_vec(),
                    b"http://x".to_vec(),
                    b"ftp://x".to_vec()
                ],
                vec![b"ab.com".to_vec(), b"a.com".to_vec()],
            ]
        );
    }

    #[test]
    fn nullable_asserted_unicode_and_anchorless_shapes_reject() {
        for hir in [
            parsed(r"(?:abc|)", false, false),
            parsed(r"^abc", false, false),
            parsed(r"[a-z]+", false, false),
            parsed(r"\pL+", false, true),
        ] {
            let mut budget = CompileBudget::new(CompileLimits::default());
            assert!(
                certify(&hir, Limits::default(), &mut budget)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(budget.current_construction_bytes(), 0);
        }
    }

    #[test]
    fn exact_work_and_scratch_limits_accept_exact_and_refuse_one_below() {
        let hir = parsed(r"(?:https?|ftp)://x|(?:AB|A)\.COM", true, false);
        let mut baseline_budget = CompileBudget::new(CompileLimits::default());
        let exact = certify(&hir, Limits::default(), &mut baseline_budget)
            .unwrap()
            .unwrap();
        let accounting = exact.accounting();
        exact.release(&mut baseline_budget).unwrap();
        assert_eq!(baseline_budget.current_construction_bytes(), 0);
        let mut exact_budget = CompileBudget::new(CompileLimits {
            max_work: accounting.work,
            max_program_bytes: accounting.scratch_peak_bytes,
            ..CompileLimits::default()
        });
        let retained_at_exact = certify(
            &hir,
            Limits {
                max_scratch_bytes: accounting.scratch_peak_bytes,
            },
            &mut exact_budget,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            exact_budget.current_construction_bytes(),
            accounting.retained_bytes
        );
        retained_at_exact.release(&mut exact_budget).unwrap();
        assert_eq!(exact_budget.current_construction_bytes(), 0);
        let mut work_one_below = CompileBudget::new(CompileLimits {
            max_work: accounting.work - 1,
            ..CompileLimits::default()
        });
        assert!(matches!(
            certify(
                &hir,
                Limits {
                    max_scratch_bytes: accounting.scratch_peak_bytes,
                },
                &mut work_one_below,
            ),
            Err(Error::ResourceLimit {
                resource: Resource::CompileWork,
                ..
            })
        ));
        assert_eq!(work_one_below.current_construction_bytes(), 0);
        let mut scratch_one_below = CompileBudget::new(CompileLimits::default());
        assert!(matches!(
            certify(
                &hir,
                Limits {
                    max_scratch_bytes: accounting.scratch_peak_bytes - 1,
                },
                &mut scratch_one_below,
            ),
            Err(Error::ResourceLimit {
                resource: Resource::ProgramBytes,
                ..
            })
        ));
        assert_eq!(scratch_one_below.current_construction_bytes(), 0);
        let mut construction_one_below = CompileBudget::new(CompileLimits {
            max_program_bytes: accounting.scratch_peak_bytes - 1,
            ..CompileLimits::default()
        });
        assert!(matches!(
            certify(
                &hir,
                Limits {
                    max_scratch_bytes: accounting.scratch_peak_bytes,
                },
                &mut construction_one_below,
            ),
            Err(Error::ResourceLimit {
                resource: Resource::ProgramBytes,
                ..
            })
        ));
        assert_eq!(construction_one_below.current_construction_bytes(), 0);
    }

    #[test]
    #[ignore = "requires FRE_TEST_URL_PATTERN to name the authenticated Rebar URL pattern"]
    fn authenticated_url_has_exact_ordered_anchor_certificate() {
        let path = std::env::var_os("FRE_TEST_URL_PATTERN")
            .expect("FRE_TEST_URL_PATTERN must name wild/url.txt");
        let source = std::fs::read_to_string(path).unwrap();
        let hir = parsed(source.trim_end(), true, false);
        let mut budget = CompileBudget::new(CompileLimits {
            max_work: 64 << 20,
            max_program_bytes: 64 << 20,
            ..CompileLimits::default()
        });
        let certificate = certify(
            &hir,
            Limits {
                max_scratch_bytes: 64 << 20,
            },
            &mut budget,
        )
        .unwrap()
        .unwrap();
        assert_eq!(certificate.branches().len(), 2);
        let schemes = certificate.branches()[0]
            .words()
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        assert_eq!(
            schemes,
            [
                b"https://".to_vec(),
                b"http://".to_vec(),
                b"ftp://".to_vec(),
            ]
        );
        let domains = certificate.branches()[1]
            .words()
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        assert_eq!(domains.len(), 1_498);
        assert_eq!(domains.iter().map(Vec::len).sum::<usize>(), 10_003);
        assert!(domains.iter().all(|word| word.starts_with(b".")));
        eprintln!(
            "authenticated URL anchor accounting: {:?}",
            certificate.accounting()
        );
        for byte in [b' ', b'\t', b'\n', b'\x0b', b'\x0c', b'\r'] {
            assert!(certificate.delimiters().contains(byte));
        }
        assert_eq!(certificate.accounting().branches, 2);
        assert_eq!(certificate.accounting().anchor_patterns, 1_501);
        certificate.release(&mut budget).unwrap();
        assert_eq!(budget.current_construction_bytes(), 0);
    }
}
