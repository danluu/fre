//! Target-neutral planning for one exact 16-byte anchored-prefix block.
//!
//! A long fixed prefix otherwise lowers to a chain of independent scalar
//! membership tests after every moving-scanner hit. Singleton columns can be
//! checked together: compare one candidate block with the graph-derived byte
//! vector, then ignore every non-singleton lane. The plan is only produced
//! when the anchored analysis proves a complete readable block and enough
//! lanes participate to amortize the load and horizontal reduction.

use crate::program::AnchoredByteSet;

pub(crate) const PREFIX_BLOCK_BYTES: usize = 16;
pub(crate) const PREFIX_BLOCK_SERIALIZED_BYTES: usize = PREFIX_BLOCK_BYTES * 2;
pub(crate) const PREFIX_BLOCK_ALIGNMENT: usize = PREFIX_BLOCK_BYTES;

/// Four scalar membership tests cost at least as much as the block check on
/// both current native backends. Keeping the threshold structural and target
/// independent also makes object selection stable across compatible CPUs.
const MIN_PREFIX_BLOCK_SINGLETONS: u32 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PrefixBlockPlan {
    expected: [u8; PREFIX_BLOCK_BYTES],
    byte_mask: [u8; PREFIX_BLOCK_BYTES],
    lane_mask: u16,
}

/// Two in-bounds machine words that cover one exact 8..=15-byte product.
///
/// The first word covers bytes `0..8`. For widths above eight, the trailing
/// word starts at `width - 8`, so it covers every remaining byte without
/// reading past the semantic match extent. These constants stay in compiler
/// layout state and are never appended to the frozen program image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExactPrefixWordPlan {
    width: u8,
    first: u64,
    trailing: u64,
}

impl ExactPrefixWordPlan {
    #[must_use]
    pub(crate) const fn width(self) -> u8 {
        self.width
    }

    #[must_use]
    pub(crate) const fn first(self) -> u64 {
        self.first
    }

    #[must_use]
    pub(crate) const fn trailing(self) -> u64 {
        self.trailing
    }

    #[must_use]
    pub(crate) const fn trailing_offset(self) -> u8 {
        self.width - 8
    }
}

/// Exact-size scalar words that cover one exact 1..=7-byte product.
///
/// Widths one through four use byte, halfword and word loads (three bytes use
/// one halfword plus one byte). Widths five through seven use two overlapping
/// words, with the second starting at `width - 4`. Thus no load extends past
/// the semantic match extent. Like the long-word plan, these constants remain
/// compiler-only and do not consume target data bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExactPrefixShortPlan {
    width: u8,
    first: u32,
    trailing: u32,
}

impl ExactPrefixShortPlan {
    #[must_use]
    pub(crate) const fn width(self) -> u8 {
        self.width
    }

    #[must_use]
    pub(crate) const fn first(self) -> u32 {
        self.first
    }

    #[must_use]
    pub(crate) const fn trailing(self) -> u32 {
        self.trailing
    }

    #[must_use]
    pub(crate) const fn trailing_offset(self) -> u8 {
        if self.width >= 5 {
            self.width - 4
        } else {
            0
        }
    }

    #[must_use]
    pub(crate) const fn is_canonical(self) -> bool {
        match self.width {
            1 => self.first <= u8::MAX as u32 && self.trailing == 0,
            2 => self.first <= u16::MAX as u32 && self.trailing == 0,
            3 => self.first <= 0x00ff_ffff && self.trailing == 0,
            4 => self.trailing == 0,
            5 => (self.first >> 8) == (self.trailing & 0x00ff_ffff),
            6 => (self.first >> 16) == (self.trailing & 0x0000_ffff),
            7 => (self.first >> 24) == (self.trailing & 0x0000_00ff),
            _ => false,
        }
    }
}

impl PrefixBlockPlan {
    #[must_use]
    pub(crate) const fn expected(self) -> [u8; PREFIX_BLOCK_BYTES] {
        self.expected
    }

    #[must_use]
    pub(crate) const fn byte_mask(self) -> [u8; PREFIX_BLOCK_BYTES] {
        self.byte_mask
    }

    #[must_use]
    pub(crate) const fn lane_mask(self) -> u16 {
        self.lane_mask
    }

    #[must_use]
    #[cfg(test)]
    fn accepts(self, bytes: [u8; PREFIX_BLOCK_BYTES]) -> bool {
        bytes
            .iter()
            .zip(self.expected)
            .enumerate()
            .all(|(lane, (&actual, expected))| {
                self.lane_mask & (1_u16 << lane) == 0 || actual == expected
            })
    }
}

fn singleton(set: AnchoredByteSet) -> Option<u8> {
    if set.cardinality() != 1 {
        return None;
    }
    for (word_index, word) in set.words().into_iter().enumerate() {
        if word == 0 {
            continue;
        }
        let bit = usize::try_from(word.trailing_zeros()).ok()?;
        return word_index
            .checked_mul(u64::BITS as usize)?
            .checked_add(bit)
            .and_then(|byte| u8::try_from(byte).ok());
    }
    None
}

/// Derive a block check solely from exact anchored-prefix byte sets.
///
/// A plan never reads beyond the proven prefix: fewer than 16 graph layers
/// decline. Non-singleton layers remain zero in `byte_mask` and continue
/// through the existing exact scalar predicate lowering.
#[must_use]
pub(crate) fn derive(sets: &[AnchoredByteSet]) -> Option<PrefixBlockPlan> {
    let block = sets.get(..PREFIX_BLOCK_BYTES)?;
    let mut expected = [0_u8; PREFIX_BLOCK_BYTES];
    let mut byte_mask = [0_u8; PREFIX_BLOCK_BYTES];
    let mut lane_mask = 0_u16;
    for (lane, &set) in block.iter().enumerate() {
        let Some(byte) = singleton(set) else {
            continue;
        };
        expected[lane] = byte;
        byte_mask[lane] = u8::MAX;
        lane_mask |= 1_u16 << lane;
    }
    if lane_mask.count_ones() < MIN_PREFIX_BLOCK_SINGLETONS {
        return None;
    }
    Some(PrefixBlockPlan {
        expected,
        byte_mask,
        lane_mask,
    })
}

/// Derive an allocation-free exact-word verifier from graph byte sets.
///
/// Every graph layer must be a singleton and the supplied width must describe
/// the complete set slice. Widths below eight cannot amortize a word compare;
/// width sixteen already has the established vector block representation.
#[must_use]
pub(crate) fn derive_exact_words(
    sets: &[AnchoredByteSet],
    width: u8,
) -> Option<ExactPrefixWordPlan> {
    let width = usize::from(width);
    if !(8..PREFIX_BLOCK_BYTES).contains(&width) || sets.len() != width {
        return None;
    }
    let mut bytes = [0_u8; PREFIX_BLOCK_BYTES - 1];
    for (slot, &set) in bytes[..width].iter_mut().zip(sets) {
        *slot = singleton(set)?;
    }
    let trailing_offset = width.checked_sub(8)?;
    Some(ExactPrefixWordPlan {
        width: u8::try_from(width).ok()?,
        first: u64::from_le_bytes(bytes[..8].try_into().ok()?),
        trailing: u64::from_le_bytes(
            bytes[trailing_offset..trailing_offset + 8]
                .try_into()
                .ok()?,
        ),
    })
}

/// Pack an independently authenticated exact short product into in-bounds
/// scalar compares.
///
/// This is deliberately separate from [`derive_exact_words`]: the ordinary
/// direct-entry prefix guard keeps its established 8..=15-byte plan and byte
/// image, while the private continuous Span-fill entry may consume this
/// cheaper survivor receipt.
#[must_use]
pub(crate) fn exact_short_from_bytes(bytes: &[u8]) -> Option<ExactPrefixShortPlan> {
    let width = bytes.len();
    if !(1..8).contains(&width) {
        return None;
    }
    let first_width = width.min(4);
    let mut first_bytes = [0_u8; 4];
    first_bytes[..first_width].copy_from_slice(&bytes[..first_width]);
    let trailing = if width >= 5 {
        let trailing_offset = width.checked_sub(4)?;
        u32::from_le_bytes(
            bytes
                .get(trailing_offset..trailing_offset + 4)?
                .try_into()
                .ok()?,
        )
    } else {
        0
    };
    Some(ExactPrefixShortPlan {
        width: u8::try_from(width).ok()?,
        first: u32::from_le_bytes(first_bytes),
        trailing,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(bytes: &[u8]) -> AnchoredByteSet {
        let mut words = [0_u64; 4];
        for &byte in bytes {
            let index = usize::from(byte);
            words[index / 64] |= 1_u64 << (index % 64);
        }
        AnchoredByteSet::from_words(words)
    }

    #[test]
    fn complete_block_selects_only_singleton_graph_columns() {
        let mut sets = [set(&[b'x', b'y']); PREFIX_BLOCK_BYTES];
        for (lane, byte) in [(0, b'a'), (3, b'd'), (8, b'i'), (15, b'p')] {
            sets[lane] = set(&[byte]);
        }
        let plan = derive(&sets).expect("four singleton lanes");
        assert_eq!(plan.lane_mask(), 0x8109);
        assert_eq!(plan.expected()[0], b'a');
        assert_eq!(plan.expected()[3], b'd');
        assert_eq!(plan.expected()[8], b'i');
        assert_eq!(plan.expected()[15], b'p');
        for lane in 0..PREFIX_BLOCK_BYTES {
            assert_eq!(
                plan.byte_mask()[lane],
                if plan.lane_mask() & (1_u16 << lane) != 0 {
                    u8::MAX
                } else {
                    0
                }
            );
        }

        let mut matching = [0_u8; PREFIX_BLOCK_BYTES];
        matching[0] = b'a';
        matching[3] = b'd';
        matching[8] = b'i';
        matching[15] = b'p';
        assert!(plan.accepts(matching));
        matching[8] = b'!';
        assert!(!plan.accepts(matching));
    }

    #[test]
    fn incomplete_or_underfilled_blocks_decline() {
        let singleton = set(&[b'q']);
        assert!(derive(&[singleton; PREFIX_BLOCK_BYTES - 1]).is_none());

        let mut sets = [set(&[b'x', b'y']); PREFIX_BLOCK_BYTES];
        for lane in 0..3 {
            sets[lane] = singleton;
        }
        assert!(derive(&sets).is_none());
    }

    #[test]
    fn exact_words_require_complete_singleton_widths_eight_through_fifteen() {
        let singleton = set(&[b'q']);
        for width in 8_usize..16 {
            let plan = derive_exact_words(&vec![singleton; width], u8::try_from(width).unwrap())
                .expect("eligible exact word plan");
            assert_eq!(usize::from(plan.width()), width);
            assert_eq!(usize::from(plan.trailing_offset()), width - 8);
        }
        assert!(derive_exact_words(&[singleton; 7], 7).is_none());
        assert!(derive_exact_words(&[singleton; 16], 16).is_none());
        assert!(derive_exact_words(&[singleton; 9], 8).is_none());

        let mut non_singleton = [singleton; 15];
        non_singleton[14] = set(&[b'q', b'r']);
        assert!(derive_exact_words(&non_singleton, 15).is_none());
    }

    #[test]
    fn exact_words_cover_every_byte_with_expected_little_endian_constants() {
        let sets =
            core::array::from_fn::<_, 15, _>(|index| set(&[b'a' + u8::try_from(index).unwrap()]));
        for width in 8_usize..16 {
            let plan = derive_exact_words(&sets[..width], u8::try_from(width).unwrap()).unwrap();
            assert_eq!(plan.first().to_le_bytes(), *b"abcdefgh");
            let trailing = plan.trailing().to_le_bytes();
            let expected_trailing =
                core::array::from_fn(|index| b'a' + u8::try_from(width - 8 + index).unwrap());
            assert_eq!(trailing, expected_trailing,);
            let mut covered = [false; 15];
            covered[..8].fill(true);
            covered[width - 8..width].fill(true);
            assert!(covered[..width].iter().all(|covered| *covered));
            assert!(covered[width..].iter().all(|covered| !*covered));
        }
    }

    #[test]
    fn short_exact_words_use_only_in_bounds_scalar_chunks() {
        let bytes = *b"abcdefg";
        for width in 1_usize..=7 {
            let plan = exact_short_from_bytes(&bytes[..width]).unwrap();
            assert!(plan.is_canonical());
            let first = plan.first().to_le_bytes();
            let first_width = width.min(4);
            assert_eq!(&first[..first_width], &b"abcdefg"[..first_width]);
            assert!(first[first_width..].iter().all(|byte| *byte == 0));
            if width >= 5 {
                let offset = width - 4;
                assert_eq!(
                    &plan.trailing().to_le_bytes()[..4],
                    &b"abcdefg"[offset..width],
                );
                assert_eq!(usize::from(plan.trailing_offset()), offset);
            } else {
                assert_eq!(plan.trailing(), 0);
            }
        }
        assert!(exact_short_from_bytes(&[]).is_none());
        assert!(exact_short_from_bytes(b"abcdefgh").is_none());
    }

    #[test]
    fn singleton_extraction_covers_every_byte() {
        for byte in u8::MIN..=u8::MAX {
            assert_eq!(singleton(set(&[byte])), Some(byte));
        }
        assert_eq!(singleton(set(&[])), None);
        assert_eq!(singleton(set(&[0, 255])), None);
    }
}
