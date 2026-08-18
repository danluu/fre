//! Direct Count execution for fixed sequences of Unicode scalar classes.

use bstr::decode_utf8;
use fre::PACKED_ORDERED_LITERAL_CERTIFIED_MAX_PATTERNS;
use regex_syntax::ParserBuilder;
use regex_syntax::hir::{Class, Hir, HirKind};

pub(crate) const PLAN: &str = "aggregate-fixed-unicode-class-sequence-v1";

const MAX_WIDTH: usize = 64;
const MAX_DISTINCT_CLASSES: usize = 8;
const MAX_TOTAL_RANGES: usize = 4_096;

#[derive(Debug)]
struct UnicodeClassMask {
    ranges: Vec<(u32, u32)>,
    positions: u64,
}

#[derive(Debug)]
pub(crate) struct FixedUnicodeSequenceCount {
    ascii_masks: [u64; 128],
    classes: Vec<UnicodeClassMask>,
    accept: u64,
}

impl FixedUnicodeSequenceCount {
    pub(crate) fn try_build(pattern: &str, unicode: bool, case_insensitive: bool) -> Option<Self> {
        if !unicode || case_insensitive {
            return None;
        }
        let hir = ParserBuilder::new()
            .unicode(true)
            .utf8(false)
            .case_insensitive(false)
            .build()
            .parse(pattern)
            .ok()?;
        let mut positions = Vec::new();
        append_sequence(&hir, &mut positions)?;
        if !(2..=MAX_WIDTH).contains(&positions.len()) {
            return None;
        }
        let finite_sequences = positions.iter().try_fold(1_u64, |product, ranges| {
            let members = ranges.iter().try_fold(0_u64, |sum, &(start, end)| {
                sum.checked_add(u64::from(end) - u64::from(start) + 1)
            })?;
            product.checked_mul(members)
        });
        let packed_cap = u64::try_from(PACKED_ORDERED_LITERAL_CERTIFIED_MAX_PATTERNS).ok()?;
        if finite_sequences.is_some_and(|sequences| sequences <= packed_cap) {
            return None;
        }
        let width = positions.len();

        let mut classes: Vec<UnicodeClassMask> = Vec::new();
        let mut total_ranges = 0_usize;
        for (position, ranges) in positions.into_iter().enumerate() {
            let bit = 1_u64 << position;
            if let Some(class) = classes.iter_mut().find(|class| class.ranges == ranges) {
                class.positions |= bit;
                continue;
            }
            total_ranges = total_ranges.checked_add(ranges.len())?;
            if classes.len() == MAX_DISTINCT_CLASSES || total_ranges > MAX_TOTAL_RANGES {
                return None;
            }
            classes.push(UnicodeClassMask {
                ranges,
                positions: bit,
            });
        }
        // A single repeated predicate already has a native prepared route.
        if classes.len() < 2 {
            return None;
        }

        let mut ascii_masks = [0_u64; 128];
        for (byte, mask) in ascii_masks.iter_mut().enumerate() {
            let scalar = u32::try_from(byte).ok()?;
            for class in &classes {
                if contains(&class.ranges, scalar) {
                    *mask |= class.positions;
                }
            }
        }
        Some(Self {
            ascii_masks,
            classes,
            accept: 1_u64 << width.checked_sub(1)?,
        })
    }

    #[inline]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the cursor advances within the borrowed slice and Shift-And uses bounded u64 shifts"
    )]
    pub(crate) fn count(&self, haystack: &[u8]) -> Result<u64, &'static str> {
        let mut at = 0_usize;
        let mut state = 0_u64;
        let mut count = 0_u64;
        while at < haystack.len() {
            let byte = haystack[at];
            let mask = if byte.is_ascii() {
                at += 1;
                self.ascii_masks[usize::from(byte)]
            } else {
                let (scalar, width) = decode_utf8(&haystack[at..]);
                at += width.max(1);
                scalar.map_or(0, |scalar| self.scalar_mask(u32::from(scalar)))
            };
            state = ((state << 1) | 1) & mask;
            if state & self.accept != 0 {
                count = count
                    .checked_add(1)
                    .ok_or("fixed Unicode sequence Count overflow")?;
                state = 0;
            }
        }
        Ok(count)
    }

    #[inline]
    fn scalar_mask(&self, scalar: u32) -> u64 {
        let mut mask = 0_u64;
        for class in &self.classes {
            if contains(&class.ranges, scalar) {
                mask |= class.positions;
            }
        }
        mask
    }
}

fn append_sequence(hir: &Hir, positions: &mut Vec<Vec<(u32, u32)>>) -> Option<()> {
    match hir.kind() {
        HirKind::Concat(parts) => {
            for part in parts {
                append_sequence(part, positions)?;
            }
        }
        HirKind::Capture(capture) => append_sequence(&capture.sub, positions)?,
        HirKind::Class(Class::Unicode(class)) => push_class(class, 1, positions)?,
        HirKind::Repetition(repetition) if repetition.max == Some(repetition.min) => {
            let HirKind::Class(Class::Unicode(class)) = transparent_kind(&repetition.sub) else {
                return None;
            };
            let copies = usize::try_from(repetition.min).ok()?;
            push_class(class, copies, positions)?;
        }
        _ => return None,
    }
    Some(())
}

fn transparent_kind(mut hir: &Hir) -> &HirKind {
    while let HirKind::Capture(capture) = hir.kind() {
        hir = &capture.sub;
    }
    hir.kind()
}

fn push_class(
    class: &regex_syntax::hir::ClassUnicode,
    copies: usize,
    positions: &mut Vec<Vec<(u32, u32)>>,
) -> Option<()> {
    if copies == 0 || positions.len().checked_add(copies)? > MAX_WIDTH {
        return None;
    }
    let ranges: Vec<_> = class
        .ranges()
        .iter()
        .map(|range| (u32::from(range.start()), u32::from(range.end())))
        .collect();
    if ranges.is_empty() {
        return None;
    }
    positions.extend((0..copies).map(|_| ranges.clone()));
    Some(())
}

#[inline]
fn contains(ranges: &[(u32, u32)], scalar: u32) -> bool {
    ranges
        .binary_search_by(|&(start, end)| {
            if scalar < start {
                core::cmp::Ordering::Greater
            } else if scalar > end {
                core::cmp::Ordering::Less
            } else {
                core::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CandidateRequest, CurrentFreAggregateCounterReceiptStatus, RunLimits,
        current_fre_rebar_aggregate_operation_lifecycle, fre_aggregate_count,
    };

    #[test]
    fn exhaustive_mixed_scalar_and_malformed_oracle() {
        let pattern = r"\w\s\w";
        let plan = FixedUnicodeSequenceCount::try_build(pattern, true, false).unwrap();
        let reference = regex::bytes::RegexBuilder::new(pattern)
            .unicode(true)
            .build()
            .unwrap();
        let alphabet: [&[u8]; 7] = [
            b"a",
            b" ",
            "é".as_bytes(),
            "\u{2003}".as_bytes(),
            "☃".as_bytes(),
            b"_",
            b"\xFF",
        ];
        let mut words = vec![Vec::new()];
        for _ in 0..=5 {
            for haystack in &words {
                assert_eq!(
                    plan.count(haystack).unwrap(),
                    u64::try_from(reference.find_iter(haystack).count()).unwrap(),
                    "{haystack:?}"
                );
            }
            words = words
                .iter()
                .flat_map(|prefix| {
                    alphabet.iter().map(move |suffix| {
                        let mut word = prefix.clone();
                        word.extend_from_slice(suffix);
                        word
                    })
                })
                .collect();
        }
    }

    #[test]
    fn structural_refusals_do_not_overlap_other_routes() {
        assert!(FixedUnicodeSequenceCount::try_build(r"\w\s", false, false).is_none());
        assert!(FixedUnicodeSequenceCount::try_build(r"\w\s", true, true).is_none());
        assert!(FixedUnicodeSequenceCount::try_build(r"\w+\s", true, false).is_none());
        assert!(FixedUnicodeSequenceCount::try_build(r"\w{2}x\s", true, false).is_none());
        assert!(FixedUnicodeSequenceCount::try_build(r"\w{64}\s", true, false).is_none());
        assert!(FixedUnicodeSequenceCount::try_build(r"\w{2}", true, false).is_none());
        assert!(FixedUnicodeSequenceCount::try_build(r"[ab][cd]", true, false).is_none());
        assert!(FixedUnicodeSequenceCount::try_build(r"(?:\w\s)?", true, false).is_none());
    }

    #[test]
    fn raw_and_retained_surfaces_publish_the_structural_route() {
        let patterns = [r"\w{2}\s\w{3}".to_string()];
        let haystack = "ab cde éé xyz zz abc".as_bytes();
        let expected = regex::bytes::RegexBuilder::new(&patterns[0])
            .unicode(true)
            .build()
            .unwrap()
            .find_iter(haystack)
            .count()
            .try_into()
            .unwrap();
        let raw = fre_aggregate_count(
            CandidateRequest {
                model: "count",
                patterns: &patterns,
                haystack,
                unicode: true,
                case_insensitive: false,
            },
            &RunLimits::default(),
        )
        .unwrap();
        assert_eq!((raw.actual, raw.plan.as_str()), (expected, PLAN));

        let retained = current_fre_rebar_aggregate_operation_lifecycle(
            "count",
            &patterns,
            true,
            false,
            haystack.len(),
        )
        .unwrap();
        assert_eq!(retained.plan(), PLAN);
        assert_eq!(retained.execute(haystack).unwrap(), expected);
        let diagnostic = retained.execute_with_counters(haystack).unwrap();
        assert_eq!(diagnostic.value(), expected);
        assert_eq!(
            diagnostic.receipt_status(),
            &CurrentFreAggregateCounterReceiptStatus::DirectSelectedPlan
        );
        assert!(retained.execute(&haystack[..haystack.len() - 1]).is_err());
    }
}
