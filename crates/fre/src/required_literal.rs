//! Exact HIR shape proof for the required-literal production kernel.

use fre_kernels::{RequiredLiteralAnchors, RequiredLiteralByteClass, RequiredLiteralClassRepeat};
use regex_syntax::hir::{Class, Hir, HirKind, Look};

use crate::{BuildError, charge_planner, reserve_planner};

const NORMALIZED_BYTE_CLASS_EQUALITY_WORK: u64 = 4;
const REPEAT_BOUND_ADD_WORK: u64 = 1;

pub(crate) struct Extraction {
    pub(crate) shape: Option<Shape>,
    pub(crate) work: u64,
}

pub(crate) struct Shape {
    pub(crate) class: RequiredLiteralByteClass,
    pub(crate) repeat: RequiredLiteralClassRepeat,
    pub(crate) suffix: Vec<u8>,
    pub(crate) anchors: RequiredLiteralAnchors,
}

/// Recognize exactly
/// `[absolute-start]? BYTE_CLASS{positive greedy bounds}+ LITERAL [absolute-end]?`,
/// where every adjacent repetition has the same normalized byte class.
///
/// Capture nodes may be erased because every public operation on
/// `PortableRegex` is capture-free. No alternation, surrounding concatenation,
/// Unicode class, lazy repetition or line/word assertion is admitted.
#[allow(
    clippy::too_many_lines,
    reason = "the complete exact-shape proof keeps every admitted HIR position visible"
)]
pub(crate) fn extract(
    hir: &Hir,
    initial_work: u64,
    work_limit: u64,
) -> Result<Extraction, BuildError> {
    let mut work = initial_work;
    let root = strip_captures(hir, &mut work, work_limit)?;
    let HirKind::Concat(root_children) = root.kind() else {
        return Ok(Extraction { shape: None, work });
    };
    charge_planner(
        &mut work,
        u64::try_from(root_children.len()).unwrap_or(u64::MAX),
        work_limit,
    )?;

    let mut children = root_children.as_slice();
    let mut anchors = RequiredLiteralAnchors::default();
    let outer_start = usize::from(child_is_look(
        children,
        0,
        Look::Start,
        &mut work,
        work_limit,
    )?);
    let has_outer_end = if let Some(child) = children.last() {
        let child = strip_captures(child, &mut work, work_limit)?;
        matches!(child.kind(), HirKind::Look(Look::End))
    } else {
        false
    };
    let outer_end = if has_outer_end {
        children
            .len()
            .checked_sub(1)
            .ok_or(BuildError::InternalInvariant(
                "required-literal outer end index underflow",
            ))?
    } else {
        children.len()
    };
    let outer_core_len =
        outer_end
            .checked_sub(outer_start)
            .ok_or(BuildError::InternalInvariant(
                "required-literal outer anchor ordering",
            ))?;
    if outer_core_len == 1 {
        let core = strip_captures(&children[outer_start], &mut work, work_limit)?;
        if let HirKind::Concat(nested) = core.kind() {
            anchors.start = outer_start == 1;
            anchors.end = outer_end != children.len();
            children = nested;
            charge_planner(
                &mut work,
                u64::try_from(children.len()).unwrap_or(u64::MAX),
                work_limit,
            )?;
        }
    }

    let mut index = 0_usize;
    if child_is_look(children, index, Look::Start, &mut work, work_limit)? {
        if anchors.start {
            return Ok(Extraction { shape: None, work });
        }
        anchors.start = true;
        index = index.checked_add(1).ok_or(BuildError::InternalInvariant(
            "required-literal child index overflow",
        ))?;
    }

    let mut class = None;
    let mut repeat = RequiredLiteralClassRepeat {
        min: 0,
        max: Some(0),
    };
    let suffix_node = loop {
        let Some(node) = children.get(index) else {
            return Ok(Extraction { shape: None, work });
        };
        let node = strip_captures(node, &mut work, work_limit)?;
        let HirKind::Repetition(repetition) = node.kind() else {
            break node;
        };
        charge_planner(&mut work, 1, work_limit)?;
        if repetition.min == 0 || !repetition.greedy {
            return Ok(Extraction { shape: None, work });
        }
        let Ok(repeat_min) = usize::try_from(repetition.min) else {
            return Ok(Extraction { shape: None, work });
        };
        let repeat_max = match repetition.max {
            Some(max) => {
                let Ok(max) = usize::try_from(max) else {
                    return Ok(Extraction { shape: None, work });
                };
                Some(max)
            }
            None => None,
        };
        if repeat_max.is_some_and(|max| max < repeat_min) {
            return Ok(Extraction { shape: None, work });
        }
        let class_node = strip_captures(&repetition.sub, &mut work, work_limit)?;
        let Some(repetition_class) =
            extract_byte_class(class_node, &mut work, work_limit)?
        else {
            return Ok(Extraction { shape: None, work });
        };
        if let Some(expected) = class {
            charge_planner(
                &mut work,
                NORMALIZED_BYTE_CLASS_EQUALITY_WORK,
                work_limit,
            )?;
            if expected != repetition_class {
                return Ok(Extraction { shape: None, work });
            }
        } else {
            class = Some(repetition_class);
        }
        let Some(coalesced) = checked_sum_repeat(
            repeat,
            RequiredLiteralClassRepeat {
                min: repeat_min,
                max: repeat_max,
            },
            &mut work,
            work_limit,
        )? else {
            return Ok(Extraction { shape: None, work });
        };
        repeat = coalesced;
        index = index.checked_add(1).ok_or(BuildError::InternalInvariant(
            "required-literal child index overflow",
        ))?;
    };
    let Some(class) = class else {
        return Ok(Extraction { shape: None, work });
    };
    let HirKind::Literal(literal) = suffix_node.kind() else {
        return Ok(Extraction { shape: None, work });
    };
    if literal.0.is_empty() {
        return Ok(Extraction { shape: None, work });
    }
    let mut suffix = Vec::new();
    reserve_planner(
        &mut suffix,
        literal.0.len(),
        &mut work,
        work_limit,
        "required-literal suffix",
    )?;
    suffix.extend_from_slice(&literal.0);
    index = index.checked_add(1).ok_or(BuildError::InternalInvariant(
        "required-literal child index overflow",
    ))?;

    if child_is_look(children, index, Look::End, &mut work, work_limit)? {
        if anchors.end {
            return Ok(Extraction { shape: None, work });
        }
        anchors.end = true;
        index = index.checked_add(1).ok_or(BuildError::InternalInvariant(
            "required-literal child index overflow",
        ))?;
    }
    if index != children.len() {
        return Ok(Extraction { shape: None, work });
    }
    Ok(Extraction {
        shape: Some(Shape {
            class,
            repeat,
            suffix,
            anchors,
        }),
        work,
    })
}

fn checked_sum_repeat(
    left: RequiredLiteralClassRepeat,
    right: RequiredLiteralClassRepeat,
    work: &mut u64,
    work_limit: u64,
) -> Result<Option<RequiredLiteralClassRepeat>, BuildError> {
    charge_planner(work, REPEAT_BOUND_ADD_WORK, work_limit)?;
    let Some(min) = left.min.checked_add(right.min) else {
        return Ok(None);
    };
    let max = match (left.max, right.max) {
        (Some(left), Some(right)) => {
            charge_planner(work, REPEAT_BOUND_ADD_WORK, work_limit)?;
            let Some(max) = left.checked_add(right) else {
                return Ok(None);
            };
            Some(max)
        }
        (None, _) | (_, None) => None,
    };
    Ok(Some(RequiredLiteralClassRepeat { min, max }))
}

fn child_is_look(
    children: &[Hir],
    index: usize,
    expected: Look,
    work: &mut u64,
    limit: u64,
) -> Result<bool, BuildError> {
    let Some(child) = children.get(index) else {
        return Ok(false);
    };
    let child = strip_captures(child, work, limit)?;
    Ok(matches!(child.kind(), HirKind::Look(actual) if *actual == expected))
}

fn strip_captures<'a>(mut hir: &'a Hir, work: &mut u64, limit: u64) -> Result<&'a Hir, BuildError> {
    loop {
        charge_planner(work, 1, limit)?;
        let HirKind::Capture(capture) = hir.kind() else {
            return Ok(hir);
        };
        hir = &capture.sub;
    }
}

fn extract_byte_class(
    hir: &Hir,
    work: &mut u64,
    limit: u64,
) -> Result<Option<RequiredLiteralByteClass>, BuildError> {
    let mut output = RequiredLiteralByteClass::default();
    match hir.kind() {
        HirKind::Class(Class::Bytes(class)) => {
            for range in class.ranges() {
                let range_len = usize::from(range.end())
                    .checked_sub(usize::from(range.start()))
                    .and_then(|length| length.checked_add(1))
                    .ok_or(BuildError::InternalInvariant(
                        "canonical byte-class range length overflow",
                    ))?;
                charge_planner(work, u64::try_from(range_len).unwrap_or(u64::MAX), limit)?;
                output.insert_inclusive(range.start(), range.end());
            }
        }
        HirKind::Literal(literal) if literal.0.len() == 1 => {
            charge_planner(work, 1, limit)?;
            output.insert_inclusive(literal.0[0], literal.0[0]);
        }
        _ => return Ok(None),
    }
    if output.is_empty() {
        return Ok(None);
    }
    Ok(Some(output))
}

#[cfg(test)]
mod tests {
    use super::{checked_sum_repeat, extract};
    use fre_kernels::{RequiredLiteralByteClass, RequiredLiteralClassRepeat};
    use regex_syntax::ParserBuilder;

    fn hir(pattern: &str) -> regex_syntax::hir::Hir {
        ParserBuilder::new()
            .unicode(false)
            .build()
            .parse(pattern)
            .unwrap()
    }

    #[test]
    fn admits_only_the_exact_capture_free_shape() {
        for pattern in [
            r"[ab]+Z",
            r"[ab]{2,5}Z",
            r"[ab]{3,}Z",
            r"\A([ab]+Z)\z",
            r"(?:a)+END",
        ] {
            assert!(
                extract(&hir(pattern), 0, u64::MAX).unwrap().shape.is_some(),
                "pattern={pattern:?}"
            );
        }
        for pattern in [
            r"[ab]*Z",
            r"[ab]{0,5}Z",
            r"[ab]+?Z",
            r"[ab]{2,5}?Z",
            r"(?m:^[ab]+Z$)",
            r"x[ab]+Z",
            r"[ab]+Zx[cd]",
            r"[ab]+[ZQ]",
            r"(?:[ab]|c)+Z",
        ] {
            assert!(extract(&hir(pattern), 0, u64::MAX).unwrap().shape.is_none());
        }
    }

    #[test]
    fn coalesces_equivalent_adjacent_repetitions_and_capture_wrappers() {
        for (pattern, min, max, suffix, anchors) in [
            (
                r"[ab]{2,5}[ba]{3,7}END",
                5,
                Some(12),
                b"END".as_slice(),
                (false, false),
            ),
            (
                r"[ab]{1,2}[a-b]{3}[ba]{4,}XYZ",
                8,
                None,
                b"XYZ".as_slice(),
                (false, false),
            ),
            (
                r"[ab]{2,}[ba]{3,7}XYZ",
                5,
                None,
                b"XYZ".as_slice(),
                (false, false),
            ),
            (
                r"\A((([ab])){2,5})(([ba]){3,7})END\z",
                5,
                Some(12),
                b"END".as_slice(),
                (true, true),
            ),
        ] {
            let shape = extract(&hir(pattern), 0, u64::MAX)
                .unwrap()
                .shape
                .unwrap_or_else(|| panic!("pattern={pattern:?}"));
            assert_eq!(
                shape.class,
                RequiredLiteralByteClass::from_bytes(b"ab"),
                "pattern={pattern:?}",
            );
            assert_eq!(
                shape.repeat,
                RequiredLiteralClassRepeat { min, max },
                "pattern={pattern:?}",
            );
            assert_eq!(shape.suffix, suffix, "pattern={pattern:?}");
            assert_eq!(
                (shape.anchors.start, shape.anchors.end),
                anchors,
                "pattern={pattern:?}",
            );
        }
    }

    #[test]
    fn refuses_non_equivalent_or_non_adjacent_repetition_sequences() {
        for pattern in [
            r"[ab]{2}[ac]{3}XYZ",
            r"[ab]{2}?[ab]{3}XYZ",
            r"[ab]{2}[ab]{3}?XYZ",
            r"[ab]{2}Q[ab]{3}XYZ",
            r"[ab]{2}\b[ab]{3}XYZ",
            r"[ab]{0,2}[ab]{3}XYZ",
            r"[ab]{2}[ab]{0,3}XYZ",
            r"(?:ab){2}[ab]{3}XYZ",
            r"[ab]{2}[ab]{3}[XY]",
        ] {
            assert!(
                extract(&hir(pattern), 0, u64::MAX).unwrap().shape.is_none(),
                "pattern={pattern:?}",
            );
        }
    }

    #[test]
    fn repeat_sum_distinguishes_unbounded_from_overflow() {
        fn sum(
            left: RequiredLiteralClassRepeat,
            right: RequiredLiteralClassRepeat,
        ) -> Option<RequiredLiteralClassRepeat> {
            let mut work = 0;
            checked_sum_repeat(left, right, &mut work, u64::MAX).unwrap()
        }
        assert_eq!(
            sum(
                RequiredLiteralClassRepeat {
                    min: 2,
                    max: Some(5),
                },
                RequiredLiteralClassRepeat { min: 3, max: None },
            ),
            Some(RequiredLiteralClassRepeat { min: 5, max: None }),
        );
        assert_eq!(
            sum(
                RequiredLiteralClassRepeat {
                    min: usize::MAX,
                    max: None,
                },
                RequiredLiteralClassRepeat { min: 1, max: None },
            ),
            None,
        );
        assert_eq!(
            sum(
                RequiredLiteralClassRepeat {
                    min: 1,
                    max: Some(usize::MAX),
                },
                RequiredLiteralClassRepeat {
                    min: 1,
                    max: Some(1),
                },
            ),
            None,
        );
    }
}
