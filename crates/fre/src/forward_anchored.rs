//! Exact HIR shape proof for the unique forward-boundary kernel.

use fre_kernels::{ForwardAnchoredAnchors, ForwardAnchoredByteClass};
use regex_syntax::hir::{Class, Hir, HirKind, Look};

use crate::{BuildError, charge_planner};

pub(crate) struct Extraction<'hir> {
    pub(crate) shape: Option<Shape<'hir>>,
    pub(crate) work: u64,
}

pub(crate) struct Shape<'hir> {
    pub(crate) class: ForwardAnchoredByteClass,
    pub(crate) suffix: &'hir [u8],
    pub(crate) anchors: ForwardAnchoredAnchors,
}

/// Recognize exactly `absolute-start BYTE_CLASS+ LITERAL [absolute-end]`.
///
/// Captures may be erased because every facade operation is capture-free.
/// Greedy and lazy `+` are both exact: disjointness at kernel construction
/// proves there is only one possible repetition boundary.
#[allow(
    clippy::too_many_lines,
    reason = "the complete exact-shape proof keeps every admitted HIR position visible"
)]
pub(crate) fn extract<'hir>(
    hir: &'hir Hir,
    initial_work: u64,
    work_limit: u64,
) -> Result<Extraction<'hir>, BuildError> {
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
                "forward anchored outer end index underflow",
            ))?
    } else {
        children.len()
    };
    let outer_core_len =
        outer_end
            .checked_sub(outer_start)
            .ok_or(BuildError::InternalInvariant(
                "forward anchored outer anchor ordering",
            ))?;
    let mut inherited_start = false;
    let mut inherited_end = false;
    if outer_core_len == 1 {
        let core = strip_captures(&children[outer_start], &mut work, work_limit)?;
        if let HirKind::Concat(nested) = core.kind() {
            inherited_start = outer_start == 1;
            inherited_end = outer_end != children.len();
            children = nested;
            charge_planner(
                &mut work,
                u64::try_from(children.len()).unwrap_or(u64::MAX),
                work_limit,
            )?;
        }
    }

    let mut index = 0_usize;
    let inner_start = child_is_look(children, index, Look::Start, &mut work, work_limit)?;
    if inherited_start && inner_start {
        return Ok(Extraction { shape: None, work });
    }
    let start = inherited_start || inner_start;
    if !start {
        return Ok(Extraction { shape: None, work });
    }
    if inner_start {
        index = index.checked_add(1).ok_or(BuildError::InternalInvariant(
            "forward anchored child index overflow",
        ))?;
    }

    let Some(repetition_node) = children.get(index) else {
        return Ok(Extraction { shape: None, work });
    };
    let repetition_node = strip_captures(repetition_node, &mut work, work_limit)?;
    let HirKind::Repetition(repetition) = repetition_node.kind() else {
        return Ok(Extraction { shape: None, work });
    };
    charge_planner(&mut work, 1, work_limit)?;
    if repetition.min != 1 || repetition.max.is_some() {
        return Ok(Extraction { shape: None, work });
    }
    let class_node = strip_captures(&repetition.sub, &mut work, work_limit)?;
    let Some(class) = extract_byte_class(class_node, &mut work, work_limit)? else {
        return Ok(Extraction { shape: None, work });
    };
    index = index.checked_add(1).ok_or(BuildError::InternalInvariant(
        "forward anchored child index overflow",
    ))?;

    let Some(suffix_node) = children.get(index) else {
        return Ok(Extraction { shape: None, work });
    };
    let suffix_node = strip_captures(suffix_node, &mut work, work_limit)?;
    let HirKind::Literal(literal) = suffix_node.kind() else {
        return Ok(Extraction { shape: None, work });
    };
    if literal.0.is_empty() {
        return Ok(Extraction { shape: None, work });
    }
    charge_planner(
        &mut work,
        u64::try_from(literal.0.len()).unwrap_or(u64::MAX),
        work_limit,
    )?;
    let suffix = literal.0.as_ref();
    index = index.checked_add(1).ok_or(BuildError::InternalInvariant(
        "forward anchored child index overflow",
    ))?;

    let inner_end = child_is_look(children, index, Look::End, &mut work, work_limit)?;
    if inherited_end && inner_end {
        return Ok(Extraction { shape: None, work });
    }
    if inner_end {
        index = index.checked_add(1).ok_or(BuildError::InternalInvariant(
            "forward anchored child index overflow",
        ))?;
    }
    if index != children.len() {
        return Ok(Extraction { shape: None, work });
    }
    Ok(Extraction {
        shape: Some(Shape {
            class,
            suffix,
            anchors: ForwardAnchoredAnchors {
                start: true,
                end: inherited_end || inner_end,
            },
        }),
        work,
    })
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
) -> Result<Option<ForwardAnchoredByteClass>, BuildError> {
    let mut output = ForwardAnchoredByteClass::default();
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
    use super::extract;
    use regex_syntax::{
        ParserBuilder,
        hir::{Hir, HirKind},
    };

    fn hir(pattern: &str) -> regex_syntax::hir::Hir {
        ParserBuilder::new()
            .unicode(false)
            .build()
            .parse(pattern)
            .unwrap()
    }

    #[test]
    fn admits_only_the_exact_absolute_start_shape() {
        for pattern in [r"\A[ab]+Z", r"\A([ab]+Z)\z", r"(\A(?:a)+END)", r"\A[ab]+?Z"] {
            assert!(
                extract(&hir(pattern), 0, u64::MAX).unwrap().shape.is_some(),
                "pattern={pattern:?}"
            );
        }
        for pattern in [
            r"[ab]+Z",
            r"\A[ab]*Z",
            r"(?m:^[ab]+Z$)",
            r"x\A[ab]+Z",
            r"\A[ab]+Zx[cd]",
            r"\A[ab]+[ZQ]",
            r"\A(?:[ab]|c)+Z",
        ] {
            assert!(
                extract(&hir(pattern), 0, u64::MAX).unwrap().shape.is_none(),
                "pattern={pattern:?}"
            );
        }
    }

    fn literal_bytes(hir: &Hir) -> Option<&[u8]> {
        match hir.kind() {
            HirKind::Literal(literal) => Some(literal.0.as_ref()),
            HirKind::Capture(capture) => literal_bytes(&capture.sub),
            HirKind::Concat(children) => children.iter().find_map(literal_bytes),
            HirKind::Repetition(repetition) => literal_bytes(&repetition.sub),
            _ => None,
        }
    }

    #[test]
    fn suffix_is_borrowed_from_hir_and_literal_work_is_unchanged() {
        for pattern in [r"\A[ab]+XYZ\z", r"\A([ab]+?XYZ)\z", r"(\A(?:[ab])+XYZ\z)"] {
            let parsed = hir(pattern);
            let literal = literal_bytes(&parsed).unwrap();
            let unlimited = extract(&parsed, 0, u64::MAX).unwrap();
            let shape = unlimited.shape.unwrap();
            let _: &[u8] = shape.suffix;
            assert_eq!(shape.suffix, b"XYZ");
            assert_eq!(shape.suffix.as_ptr(), literal.as_ptr());
            assert_eq!(shape.suffix.len(), literal.len());

            let exact = extract(&parsed, 0, unlimited.work).unwrap();
            assert_eq!(exact.work, unlimited.work);
            assert!(exact.shape.is_some());
            assert!(extract(&parsed, 0, unlimited.work - 1).is_err());
        }
    }
}
