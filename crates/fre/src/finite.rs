//! Checked finite-language extraction for operation-specific literal plans.

#![allow(
    clippy::similar_names,
    reason = "word and work are distinct domain quantities throughout this checked planner"
)]

use regex_syntax::hir::{Class, Hir, HirKind};

use crate::{BuildError, charge_planner, reserve_planner};

pub(crate) struct FiniteExtraction {
    pub(crate) words: Option<Vec<Vec<u8>>>,
    pub(crate) work: u64,
}

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
) -> Result<FiniteExtraction, BuildError> {
    let mut work = initial_work;
    if analyze(hir, max_words, max_bytes, &mut work, work_limit)?.is_none() {
        return Ok(FiniteExtraction { words: None, work });
    }
    let mut tasks = Vec::new();
    reserve_planner(
        &mut tasks,
        1,
        &mut work,
        work_limit,
        "finite-language task stack",
    )?;
    tasks.push(Task::Visit(hir));
    let mut values = Vec::new();
    while let Some(task) = tasks.pop() {
        charge_planner(&mut work, 1, work_limit)?;
        match task {
            Task::Visit(node) => match node.kind() {
                HirKind::Empty => {
                    let language = singleton_language(Vec::new(), &mut work, work_limit)?;
                    push_language(&mut values, language, &mut work, work_limit)?;
                }
                HirKind::Literal(literal) => {
                    if literal.0.len() > max_bytes || max_words == 0 {
                        return Ok(FiniteExtraction { words: None, work });
                    }
                    let mut word = Vec::new();
                    reserve_planner(
                        &mut word,
                        literal.0.len(),
                        &mut work,
                        work_limit,
                        "finite-language literal bytes",
                    )?;
                    word.extend_from_slice(&literal.0);
                    let language = singleton_language(word, &mut work, work_limit)?;
                    push_language(&mut values, language, &mut work, work_limit)?;
                }
                HirKind::Class(Class::Bytes(class)) => {
                    let Some(language) =
                        byte_class(class, max_words, max_bytes, &mut work, work_limit)?
                    else {
                        return Ok(FiniteExtraction { words: None, work });
                    };
                    push_language(&mut values, language, &mut work, work_limit)?;
                }
                HirKind::Class(Class::Unicode(class)) => {
                    let Some(language) =
                        unicode_class(class, max_words, max_bytes, &mut work, work_limit)?
                    else {
                        return Ok(FiniteExtraction { words: None, work });
                    };
                    push_language(&mut values, language, &mut work, work_limit)?;
                }
                HirKind::Capture(capture) => {
                    push_visit(&mut tasks, &capture.sub, &mut work, work_limit)?;
                }
                HirKind::Concat(children) => push_children(
                    &mut tasks,
                    children,
                    Task::FinishConcat(children.len()),
                    &mut work,
                    work_limit,
                )?,
                HirKind::Alternation(children) => push_children(
                    &mut tasks,
                    children,
                    Task::FinishAlternation(children.len()),
                    &mut work,
                    work_limit,
                )?,
                HirKind::Look(_) | HirKind::Repetition(_) => {
                    return Ok(FiniteExtraction { words: None, work });
                }
            },
            Task::FinishConcat(children) => {
                let child_languages = pop_languages(&mut values, children, &mut work, work_limit)?;
                let Some(language) =
                    concat_languages(child_languages, max_words, max_bytes, &mut work, work_limit)?
                else {
                    return Ok(FiniteExtraction { words: None, work });
                };
                push_language(&mut values, language, &mut work, work_limit)?;
            }
            Task::FinishAlternation(children) => {
                let child_languages = pop_languages(&mut values, children, &mut work, work_limit)?;
                let Some(language) = alternate_languages(
                    child_languages,
                    max_words,
                    max_bytes,
                    &mut work,
                    work_limit,
                )?
                else {
                    return Ok(FiniteExtraction { words: None, work });
                };
                push_language(&mut values, language, &mut work, work_limit)?;
            }
        }
    }
    if values.len() != 1 {
        return Err(BuildError::InternalInvariant(
            "finite-language stack did not produce one value",
        ));
    }
    let language = values.pop().ok_or(BuildError::InternalInvariant(
        "finite-language value disappeared",
    ))?;
    Ok(FiniteExtraction {
        words: Some(language.words),
        work,
    })
}

fn analyze(
    hir: &Hir,
    max_words: usize,
    max_bytes: usize,
    work: &mut u64,
    work_limit: u64,
) -> Result<Option<Shape>, BuildError> {
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
                let shape = match node.kind() {
                    HirKind::Empty => Shape::leaf(1, 0),
                    HirKind::Literal(literal) => Shape::leaf(1, literal.0.len()),
                    HirKind::Class(Class::Bytes(class)) => {
                        let Some(count) = byte_class_count(class) else {
                            return Ok(None);
                        };
                        Shape::leaf(count, count)
                    }
                    HirKind::Class(Class::Unicode(class)) => {
                        let Some((words, bytes)) = unicode_class_count(class, max_words, max_bytes)
                        else {
                            return Ok(None);
                        };
                        Shape::leaf(words, bytes)
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
                    HirKind::Look(_) | HirKind::Repetition(_) => return Ok(None),
                };
                if !shape.fits(max_words, max_bytes) {
                    return Ok(None);
                }
                push_shape(&mut values, shape, work, work_limit)?;
            }
            Task::FinishConcat(count) | Task::FinishAlternation(count) => {
                let children = pop_shapes(&mut values, count, work, work_limit)?;
                let combined = if matches!(task, Task::FinishConcat(_)) {
                    concat_shape(&children)
                } else {
                    alternation_shape(&children)
                };
                let Some(shape) = combined else {
                    return Ok(None);
                };
                if !shape.fits(max_words, max_bytes) {
                    return Ok(None);
                }
                push_shape(&mut values, shape, work, work_limit)?;
            }
        }
    }
    if values.len() != 1 {
        return Err(BuildError::InternalInvariant(
            "finite-language analysis did not produce one shape",
        ));
    }
    Ok(values.pop())
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

fn push_shape(
    values: &mut Vec<Shape>,
    shape: Shape,
    work: &mut u64,
    limit: u64,
) -> Result<(), BuildError> {
    reserve_planner(values, 1, work, limit, "finite-language analysis values")?;
    values.push(shape);
    Ok(())
}

fn pop_shapes(
    values: &mut Vec<Shape>,
    count: usize,
    work: &mut u64,
    limit: u64,
) -> Result<Vec<Shape>, BuildError> {
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
            "finite-language analysis shape disappeared",
        ))?);
    }
    charge_planner(work, u64::try_from(count).unwrap_or(u64::MAX), limit)?;
    children.reverse();
    Ok(children)
}

fn alternation_shape(children: &[Shape]) -> Option<Shape> {
    let mut words = 0_usize;
    let mut bytes = 0_usize;
    for child in children {
        words = words.checked_add(child.words)?;
        bytes = bytes.checked_add(child.bytes)?;
    }
    shape_with_evaluation_peak(children, words, bytes)
}

fn concat_shape(children: &[Shape]) -> Option<Shape> {
    let mut words = 1_usize;
    let mut bytes = 0_usize;
    for child in children {
        let next_words = words.checked_mul(child.words)?;
        let left_bytes = bytes.checked_mul(child.words)?;
        let right_bytes = child.bytes.checked_mul(words)?;
        bytes = left_bytes.checked_add(right_bytes)?;
        words = next_words;
    }
    shape_with_evaluation_peak(children, words, bytes)
}

fn shape_with_evaluation_peak(children: &[Shape], words: usize, bytes: usize) -> Option<Shape> {
    let mut live_words = 0_usize;
    let mut live_bytes = 0_usize;
    let mut peak_words = 0_usize;
    let mut peak_bytes = 0_usize;
    for child in children {
        peak_words = peak_words.max(live_words.checked_add(child.peak_words)?);
        peak_bytes = peak_bytes.max(live_bytes.checked_add(child.peak_bytes)?);
        live_words = live_words.checked_add(child.words)?;
        live_bytes = live_bytes.checked_add(child.bytes)?;
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
