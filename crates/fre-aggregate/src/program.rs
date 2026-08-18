use fre_exact_alloc::{CopyError, ExactVec};
use regex_syntax::hir::Look;

use crate::Error;

pub(crate) const NO_SPLIT_RANK: usize = usize::MAX;
const NO_CONTINUATION_NONACCEPTING_RUN: usize = usize::MAX;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ByteSet(pub(crate) [u64; 4]);

impl ByteSet {
    pub(crate) const fn empty() -> Self {
        Self([0; 4])
    }

    pub(crate) fn insert(&mut self, byte: u8) {
        let index = usize::from(byte) / 64;
        let bit = usize::from(byte) % 64;
        self.0[index] |= 1_u64 << bit;
    }

    pub(crate) fn insert_range(&mut self, start: u8, end: u8) {
        if start > end {
            return;
        }
        let start_word = usize::from(start >> 6);
        let end_word = usize::from(end >> 6);
        let start_bit = u32::from(start & 63);
        let end_bit = u32::from(end & 63);
        let start_mask = u64::MAX << start_bit;
        let end_mask = u64::MAX >> 63_u32.saturating_sub(end_bit);
        if start_word == end_word {
            self.0[start_word] |= start_mask & end_mask;
            return;
        }
        self.0[start_word] |= start_mask;
        self.0[start_word.saturating_add(1)..end_word].fill(u64::MAX);
        self.0[end_word] |= end_mask;
    }

    pub(crate) fn contains(self, byte: u8) -> bool {
        let index = usize::from(byte) / 64;
        let bit = usize::from(byte) % 64;
        self.0[index] & (1_u64 << bit) != 0
    }
}

#[cfg(test)]
mod byte_set_range_tests {
    use super::ByteSet;

    #[test]
    fn word_range_fill_matches_scalar_insertion_for_every_u8_endpoint_pair() {
        const SEED: [u64; 4] = [
            0x0123_4567_89AB_CDEF,
            0xFEDC_BA98_7654_3210,
            0xAA55_AA55_AA55_AA55,
            0x55AA_55AA_55AA_55AA,
        ];
        for start in u8::MIN..=u8::MAX {
            for end in u8::MIN..=u8::MAX {
                let mut expected = ByteSet(SEED);
                if start <= end {
                    for byte in start..=end {
                        expected.insert(byte);
                    }
                }
                let mut actual = ByteSet(SEED);
                actual.insert_range(start, end);
                assert_eq!(actual, expected, "start={start:#04X} end={end:#04X}");
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ScalarRange {
    start: u32,
    end: u32,
}

impl ScalarRange {
    pub(crate) fn new(start: char, end: char) -> Result<Self, Error> {
        if start > end {
            return Err(Error::InternalInvariant(
                "non-canonical Unicode scalar range",
            ));
        }
        Ok(Self {
            start: u32::from(start),
            end: u32::from(end),
        })
    }
}

/// Canonical, sorted scalar ranges owned by one consuming instruction or by
/// one immutable program-local shared owner after progress promotion.
///
/// Ordinary consuming states own this value directly. A compile-only
/// construction policy may instead move a sufficiently large progress-product
/// owner into the immutable program-local table and retain a validated owner
/// ID in each repeated state. Both representations avoid expansion into
/// hundreds of one- through four-byte UTF-8 paths. The fallible callback lets
/// execution charge every binary-search comparison before it is performed.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ScalarSet(ExactVec<ScalarRange>);

fn exact_scalar_ranges(length: usize) -> Result<ExactVec<ScalarRange>, Error> {
    ExactVec::try_with_capacity(length).map_err(|error| match error {
        CopyError::LayoutOverflow => Error::ArithmeticOverflow {
            resource: crate::Resource::ProgramBytes,
        },
        CopyError::AllocationFailed => Error::AllocationFailed {
            resource: crate::Resource::ProgramBytes,
            items: length,
        },
    })
}

impl ScalarSet {
    pub(crate) fn required_bytes(range_count: usize) -> Result<usize, Error> {
        range_count
            .checked_mul(core::mem::size_of::<ScalarRange>())
            .ok_or(Error::ArithmeticOverflow {
                resource: crate::Resource::ProgramBytes,
            })
    }

    pub(crate) fn from_unicode_class(
        class: &regex_syntax::hir::ClassUnicode,
    ) -> Result<Self, Error> {
        let mut ranges = exact_scalar_ranges(class.ranges().len())?;
        for range in class.ranges() {
            ranges
                .try_push(ScalarRange::new(range.start(), range.end())?)
                .map_err(|_| {
                    Error::InternalInvariant("Unicode scalar class exceeded exact allocation")
                })?;
        }
        if ranges.is_empty() {
            return Err(Error::InternalInvariant("empty Unicode scalar class"));
        }
        Ok(Self(ranges))
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn allocated_bytes(&self) -> Result<usize, Error> {
        Self::required_bytes(self.0.len())
    }

    pub(crate) fn try_clone(&self) -> Result<Self, Error> {
        let mut ranges = exact_scalar_ranges(self.0.len())?;
        for &range in &*self.0 {
            ranges.try_push(range).map_err(|_| {
                Error::InternalInvariant("Unicode scalar clone exceeded exact allocation")
            })?;
        }
        Ok(Self(ranges))
    }

    pub(crate) fn max_search_checks(&self) -> usize {
        scalar_search_comparison_bound(self.0.len()).0
    }

    pub(crate) fn contains_with<E>(
        &self,
        scalar: char,
        mut charge: impl FnMut() -> Result<(), E>,
    ) -> Result<bool, E> {
        let scalar = u32::from(scalar);
        let mut lower = 0_usize;
        let mut upper = self.0.len();
        while lower < upper {
            charge()?;
            let middle = lower.saturating_add(upper.saturating_sub(lower) / 2);
            let range = self.0[middle];
            if scalar < range.start {
                upper = middle;
                continue;
            }
            charge()?;
            if scalar > range.end {
                lower = middle.saturating_add(1);
            } else {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(crate) fn ranges(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        self.0.iter().map(|range| (range.start, range.end))
    }
}

/// Stable program-local reference to one immutable scalar-range owner.
///
/// Two words leave room for the enum representation while preserving the
/// established 56-byte `Inst` layout. The range count keeps every per-state
/// logical byte/work charge independent of the shared physical owner. The
/// scalar-only owner table carries the representation version once.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ScalarSetId {
    index: usize,
    ranges: usize,
}

impl ScalarSetId {
    pub(crate) const REPRESENTATION_V1: usize = 1;

    pub(crate) fn new(index: usize, ranges: usize) -> Result<Self, Error> {
        if ranges == 0 {
            return Err(Error::InternalInvariant(
                "empty shared Unicode scalar owner",
            ));
        }
        Ok(Self { index, ranges })
    }

    pub(crate) const fn len(self) -> usize {
        self.ranges
    }

    pub(crate) fn logical_bytes(self) -> Result<usize, Error> {
        ScalarSet::required_bytes(self.ranges)
    }

    pub(crate) fn resolve(self, owners: &[ScalarSet]) -> Result<&ScalarSet, Error> {
        let owner = owners.get(self.index).ok_or(Error::InternalInvariant(
            "Unicode scalar owner outside program",
        ))?;
        if owner.len() != self.ranges {
            return Err(Error::InternalInvariant(
                "Unicode scalar owner range count differs from instruction",
            ));
        }
        Ok(owner)
    }
}

/// Scalar-only construction diagnostics retained behind the optional owner
/// table. Keeping these words out of `CompileAccounting` preserves every
/// byte-only `CompiledRegex` and receipt layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ScalarSetDiagnostics {
    pub(crate) representation: usize,
    pub(crate) owner_index_allocations: usize,
    pub(crate) owner_range_bytes: usize,
    pub(crate) owner_index_bytes: usize,
    pub(crate) owner_peak_bytes: usize,
    /// Compatibility-logical range bytes of shared instructions only. Owned
    /// instruction ranges remain physically present and need no projection.
    pub(crate) logical_reference_bytes: usize,
    pub(crate) reference_copies: usize,
}

/// One fallibly published program-local owner table. Its diagnostics exist
/// only when scalar storage exists, so the ordinary artifact remains object
/// neutral.
#[derive(Debug)]
pub(crate) struct ScalarSetTable {
    pub(crate) owners: ExactVec<ScalarSet>,
    pub(crate) diagnostics: ScalarSetDiagnostics,
}

/// Return the exact worst-case number of scalar comparisons for a binary
/// search over `ranges`, together with the bound for `ranges - 1`.
///
/// A left branch performs only `scalar < start`; a match or right branch also
/// performs `scalar > end`. Computing both adjacent bounds lets the recurrence
/// run in logarithmic time without allocating a table.
fn scalar_search_comparison_bound(ranges: usize) -> (usize, usize) {
    if ranges == 0 {
        return (0, 0);
    }
    if ranges == 1 {
        return (2, 0);
    }
    let half = ranges / 2;
    let (half_bound, preceding_bound) = scalar_search_comparison_bound(half);
    if ranges.is_multiple_of(2) {
        (
            half_bound
                .saturating_add(1)
                .max(preceding_bound.saturating_add(2)),
            preceding_bound.saturating_add(2),
        )
    } else {
        (
            half_bound.saturating_add(2),
            half_bound
                .saturating_add(1)
                .max(preceding_bound.saturating_add(2)),
        )
    }
}

#[cfg(test)]
mod scalar_search_tests {
    use super::{ScalarRange, ScalarSet, exact_scalar_ranges, scalar_search_comparison_bound};

    fn four_singletons() -> ScalarSet {
        let mut ranges = exact_scalar_ranges(4).unwrap();
        for scalar in ['a', 'c', 'e', 'g'] {
            ranges
                .try_push(ScalarRange::new(scalar, scalar).unwrap())
                .unwrap();
        }
        ScalarSet(ranges)
    }

    #[test]
    fn comparison_bound_is_exact_for_hand_calculated_search_trees() {
        // Each value is the longest weighted path in the lower-midpoint tree:
        // a left edge costs one comparison and a match/right edge costs two.
        let expected = [0, 2, 3, 4, 4, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 8, 8];
        for (ranges, comparisons) in expected.into_iter().enumerate() {
            assert_eq!(
                scalar_search_comparison_bound(ranges).0,
                comparisons,
                "ranges={ranges}"
            );
        }
    }

    #[test]
    fn every_scalar_comparison_is_charged_before_exact_and_one_below() {
        let ranges = four_singletons();
        assert_eq!(ranges.max_search_checks(), 4);

        let mut exact_remaining = 4_usize;
        assert_eq!(
            ranges.contains_with('b', || {
                exact_remaining = exact_remaining.checked_sub(1).ok_or(())?;
                Ok::<(), ()>(())
            }),
            Ok(false)
        );
        assert_eq!(exact_remaining, 0);

        let mut one_below_remaining = 3_usize;
        assert_eq!(
            ranges.contains_with('b', || {
                one_below_remaining = one_below_remaining.checked_sub(1).ok_or(())?;
                Ok::<(), ()>(())
            }),
            Err(())
        );
        assert_eq!(one_below_remaining, 0);
    }
}

/// A constant-time zero-width predicate admitted by the continuation engine.
///
/// This is deliberately distinct from `regex_syntax::hir::Look`: every
/// variant here has one audited implementation below.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Assertion {
    StartText,
    EndText,
    StartLf,
    EndLf,
    StartCrlf,
    EndCrlf,
    WordAscii,
    WordAsciiNegate,
    WordStartAscii,
    WordEndAscii,
    WordStartHalfAscii,
    WordEndHalfAscii,
    WordUnicode,
    WordUnicodeNegate,
    WordStartUnicode,
    WordEndUnicode,
    WordStartHalfUnicode,
    WordEndHalfUnicode,
}

/// Construction-owned upper bound on the boundaries at which a complete
/// match may start.
///
/// This is derived from mandatory HIR prefix assertions. Line-start variants
/// additionally certify that no byte transition can consume the corresponding
/// line separator, which bounds all verifier regions without overlapping
/// suffix scans. It remains an execution hint: the continuation program is the
/// semantic authority and evaluates the retained assertion again for every
/// selected start.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StartDomain {
    AnyBoundary,
    AbsoluteStart,
    LineStartLf,
    LineStartCrlf,
}

impl StartDomain {
    pub(crate) const fn is_sparse(self) -> bool {
        !matches!(self, Self::AnyBoundary)
    }

    pub(crate) const fn assertion(self) -> Option<Assertion> {
        match self {
            Self::AnyBoundary => None,
            Self::AbsoluteStart => Some(Assertion::StartText),
            Self::LineStartLf => Some(Assertion::StartLf),
            Self::LineStartCrlf => Some(Assertion::StartCrlf),
        }
    }

    pub(crate) const fn identity_tag(self) -> u8 {
        match self {
            Self::AnyBoundary => 0,
            Self::AbsoluteStart => 1,
            Self::LineStartLf => 2,
            Self::LineStartCrlf => 3,
        }
    }
}

impl Assertion {
    pub(crate) const fn from_look(look: Look) -> Self {
        match look {
            Look::Start => Self::StartText,
            Look::End => Self::EndText,
            Look::StartLF => Self::StartLf,
            Look::EndLF => Self::EndLf,
            Look::WordAscii => Self::WordAscii,
            Look::WordAsciiNegate => Self::WordAsciiNegate,
            Look::WordStartAscii => Self::WordStartAscii,
            Look::WordEndAscii => Self::WordEndAscii,
            Look::WordStartHalfAscii => Self::WordStartHalfAscii,
            Look::WordEndHalfAscii => Self::WordEndHalfAscii,
            Look::WordUnicode => Self::WordUnicode,
            Look::StartCRLF => Self::StartCrlf,
            Look::EndCRLF => Self::EndCrlf,
            Look::WordUnicodeNegate => Self::WordUnicodeNegate,
            Look::WordStartUnicode => Self::WordStartUnicode,
            Look::WordEndUnicode => Self::WordEndUnicode,
            Look::WordStartHalfUnicode => Self::WordStartHalfUnicode,
            Look::WordEndHalfUnicode => Self::WordEndHalfUnicode,
        }
    }

    pub(crate) const fn identity_tag(self) -> u8 {
        match self {
            Self::StartText => 0,
            Self::EndText => 1,
            Self::StartLf => 2,
            Self::EndLf => 3,
            Self::WordAscii => 4,
            Self::WordAsciiNegate => 5,
            Self::WordStartAscii => 6,
            Self::WordEndAscii => 7,
            Self::WordStartHalfAscii => 8,
            Self::WordEndHalfAscii => 9,
            Self::WordUnicode => 10,
            Self::StartCrlf => 11,
            Self::EndCrlf => 12,
            Self::WordUnicodeNegate => 13,
            Self::WordStartUnicode => 14,
            Self::WordEndUnicode => 15,
            Self::WordStartHalfUnicode => 16,
            Self::WordEndHalfUnicode => 17,
        }
    }

    pub(crate) const fn is_unicode_word(self) -> bool {
        matches!(
            self,
            Self::WordUnicode
                | Self::WordUnicodeNegate
                | Self::WordStartUnicode
                | Self::WordEndUnicode
                | Self::WordStartHalfUnicode
                | Self::WordEndHalfUnicode
        )
    }
}

/// Original-haystack context for predicates evaluated at local range
/// boundaries. Consuming transitions never use this context and therefore
/// remain confined to the requested operation range.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AssertionContext<'h> {
    haystack: &'h [u8],
    base: usize,
    local_len: usize,
}

impl<'h> AssertionContext<'h> {
    pub(crate) fn new(haystack: &'h [u8], base: usize, local_len: usize) -> Result<Self, Error> {
        let end = base
            .checked_add(local_len)
            .ok_or(Error::InternalInvariant("assertion range overflow"))?;
        if end > haystack.len() {
            return Err(Error::InternalInvariant(
                "assertion range outside original haystack",
            ));
        }
        Ok(Self {
            haystack,
            base,
            local_len,
        })
    }

    #[inline]
    pub(crate) fn is_match(
        self,
        assertion: Assertion,
        local_position: usize,
    ) -> Result<bool, Error> {
        self.is_match_with_source_accesses(assertion, local_position, |_| Ok(()))
    }

    /// Evaluate one assertion and report each logical adjacent source byte as
    /// part of that same traversal. Keeping the census inside the predicate
    /// prevents receipt accounting from decoding Unicode neighbors a second
    /// time merely to discover their widths.
    #[inline]
    #[allow(
        clippy::too_many_lines,
        reason = "the exhaustive assertion dispatch keeps every source charge adjacent to its corresponding read"
    )]
    pub(crate) fn is_match_with_source_accesses(
        self,
        assertion: Assertion,
        local_position: usize,
        mut record_source_accesses: impl FnMut(usize) -> Result<(), Error>,
    ) -> Result<bool, Error> {
        if local_position > self.local_len {
            return Err(Error::InternalInvariant(
                "assertion position outside operation range",
            ));
        }
        let absolute = self
            .base
            .checked_add(local_position)
            .ok_or(Error::InternalInvariant("assertion position overflow"))?;
        // Dispatch before loading either adjacent byte. Absolute anchors need
        // neither, line anchors need at most their relevant side, and half
        // word assertions classify only one side. This is evaluated for every
        // assertion state at every admitted input boundary.
        Ok(match assertion {
            Assertion::StartText => absolute == 0,
            Assertion::EndText => absolute == self.haystack.len(),
            Assertion::StartLf => {
                if absolute == 0 {
                    true
                } else {
                    record_source_accesses(1)?;
                    absolute
                        .checked_sub(1)
                        .and_then(|index| self.haystack.get(index))
                        .is_some_and(|&byte| byte == b'\n')
                }
            }
            Assertion::EndLf => {
                if absolute == self.haystack.len() {
                    true
                } else {
                    record_source_accesses(1)?;
                    self.haystack
                        .get(absolute)
                        .is_some_and(|&byte| byte == b'\n')
                }
            }
            Assertion::StartCrlf => {
                if absolute == 0 {
                    true
                } else {
                    record_source_accesses(1)?;
                    let left_byte = absolute
                        .checked_sub(1)
                        .and_then(|index| self.haystack.get(index));
                    if left_byte == Some(&b'\n') {
                        true
                    } else if left_byte == Some(&b'\r') {
                        if absolute < self.haystack.len() {
                            record_source_accesses(1)?;
                        }
                        self.haystack.get(absolute) != Some(&b'\n')
                    } else {
                        false
                    }
                }
            }
            Assertion::EndCrlf => {
                if absolute == self.haystack.len() {
                    true
                } else {
                    record_source_accesses(1)?;
                    let right_byte = self.haystack.get(absolute);
                    if right_byte == Some(&b'\r') {
                        true
                    } else if right_byte == Some(&b'\n') {
                        if absolute > 0 {
                            record_source_accesses(1)?;
                        }
                        absolute
                            .checked_sub(1)
                            .and_then(|index| self.haystack.get(index))
                            != Some(&b'\r')
                    } else {
                        false
                    }
                }
            }
            assertion @ (Assertion::WordAscii
            | Assertion::WordAsciiNegate
            | Assertion::WordStartAscii
            | Assertion::WordEndAscii) => {
                let source_bytes = usize::from(absolute > 0)
                    .checked_add(usize::from(absolute < self.haystack.len()))
                    .ok_or(Error::ArithmeticOverflow {
                        resource: crate::Resource::RandomAccessBytes,
                    })?;
                record_source_accesses(source_bytes)?;
                let left_word = absolute
                    .checked_sub(1)
                    .and_then(|index| self.haystack.get(index))
                    .is_some_and(|&byte| is_ascii_word(byte));
                let right_word = self
                    .haystack
                    .get(absolute)
                    .is_some_and(|&byte| is_ascii_word(byte));
                match assertion {
                    Assertion::WordAscii => left_word != right_word,
                    Assertion::WordAsciiNegate => left_word == right_word,
                    Assertion::WordStartAscii => !left_word && right_word,
                    Assertion::WordEndAscii => left_word && !right_word,
                    _ => {
                        return Err(Error::InternalInvariant(
                            "non-ASCII assertion in ASCII dispatch",
                        ));
                    }
                }
            }
            Assertion::WordStartHalfAscii => {
                record_source_accesses(usize::from(absolute > 0))?;
                !absolute
                    .checked_sub(1)
                    .and_then(|index| self.haystack.get(index))
                    .is_some_and(|&byte| is_ascii_word(byte))
            }
            Assertion::WordEndHalfAscii => {
                record_source_accesses(usize::from(absolute < self.haystack.len()))?;
                !self
                    .haystack
                    .get(absolute)
                    .is_some_and(|&byte| is_ascii_word(byte))
            }
            assertion @ (Assertion::WordUnicode
            | Assertion::WordUnicodeNegate
            | Assertion::WordStartUnicode
            | Assertion::WordEndUnicode
            | Assertion::WordStartHalfUnicode
            | Assertion::WordEndHalfUnicode) => {
                let before = self
                    .haystack
                    .get(..absolute)
                    .ok_or(Error::InternalInvariant("Unicode assertion prefix missing"))?;
                let after = self
                    .haystack
                    .get(absolute..)
                    .ok_or(Error::InternalInvariant("Unicode assertion suffix missing"))?;
                let left_scalar = decode_last_scalar(before);
                let right_scalar = decode_first_scalar(after);
                let source_bytes = left_scalar
                    .map_or(0, char::len_utf8)
                    .checked_add(right_scalar.map_or(0, char::len_utf8))
                    .ok_or(Error::ArithmeticOverflow {
                        resource: crate::Resource::RandomAccessBytes,
                    })?;
                record_source_accesses(source_bytes)?;
                unicode_assertion_matches(
                    assertion,
                    before.is_empty(),
                    after.is_empty(),
                    left_scalar,
                    right_scalar,
                )?
            }
        })
    }

    /// Exact logical adjacent haystack bytes inspected by one assertion.
    /// Specialized executors use this census when their predicate and meter
    /// cannot share the generic receipt evaluator above.
    pub(crate) fn candidate_source_bytes(
        self,
        assertion: Assertion,
        local_position: usize,
    ) -> Result<usize, Error> {
        if local_position > self.local_len {
            return Err(Error::InternalInvariant(
                "assertion source census outside operation range",
            ));
        }
        let absolute = self
            .base
            .checked_add(local_position)
            .ok_or(Error::InternalInvariant("assertion position overflow"))?;
        let left = usize::from(absolute > 0);
        let right = usize::from(absolute < self.haystack.len());
        match assertion {
            Assertion::StartText | Assertion::EndText => Ok(0),
            Assertion::StartLf | Assertion::WordStartHalfAscii => Ok(left),
            Assertion::EndLf | Assertion::WordEndHalfAscii => Ok(right),
            Assertion::StartCrlf if absolute == 0 => Ok(0),
            Assertion::EndCrlf if absolute == self.haystack.len() => Ok(0),
            Assertion::StartCrlf
            | Assertion::EndCrlf
            | Assertion::WordAscii
            | Assertion::WordAsciiNegate
            | Assertion::WordStartAscii
            | Assertion::WordEndAscii => left.checked_add(right).ok_or(Error::ArithmeticOverflow {
                resource: crate::Resource::RandomAccessBytes,
            }),
            Assertion::WordUnicode
            | Assertion::WordUnicodeNegate
            | Assertion::WordStartUnicode
            | Assertion::WordEndUnicode
            | Assertion::WordStartHalfUnicode
            | Assertion::WordEndHalfUnicode => {
                let before = self
                    .haystack
                    .get(..absolute)
                    .ok_or(Error::InternalInvariant("Unicode assertion prefix missing"))?;
                let after = self
                    .haystack
                    .get(absolute..)
                    .ok_or(Error::InternalInvariant("Unicode assertion suffix missing"))?;
                let left = decode_last_scalar(before).map_or(0, char::len_utf8);
                let right = decode_first_scalar(after).map_or(0, char::len_utf8);
                left.checked_add(right).ok_or(Error::ArithmeticOverflow {
                    resource: crate::Resource::RandomAccessBytes,
                })
            }
        }
    }

    pub(crate) const fn base(self) -> usize {
        self.base
    }
}

#[cfg(test)]
mod assertion_source_tests {
    use super::{Assertion, AssertionContext};

    fn source_bytes(context: AssertionContext<'_>, assertion: Assertion, position: usize) -> usize {
        let mut bytes = 0_usize;
        context
            .is_match_with_source_accesses(assertion, position, |amount| {
                bytes = bytes.checked_add(amount).unwrap();
                Ok(())
            })
            .unwrap();
        bytes
    }

    #[test]
    fn candidate_assertion_source_bytes_are_exact_at_edges_and_interior() {
        let context = AssertionContext::new(b"ab", 0, 2).unwrap();
        for assertion in [
            Assertion::StartText,
            Assertion::EndText,
            Assertion::StartLf,
            Assertion::StartCrlf,
            Assertion::WordStartHalfAscii,
        ] {
            assert_eq!(source_bytes(context, assertion, 0), 0);
        }
        for assertion in [
            Assertion::EndLf,
            Assertion::EndCrlf,
            Assertion::WordEndHalfAscii,
        ] {
            assert_eq!(source_bytes(context, assertion, 0), 1);
        }
        assert_eq!(source_bytes(context, Assertion::WordAscii, 0), 1);
        assert_eq!(source_bytes(context, Assertion::WordAscii, 1), 2);
        for assertion in [
            Assertion::StartLf,
            Assertion::StartCrlf,
            Assertion::WordStartHalfAscii,
        ] {
            assert_eq!(source_bytes(context, assertion, 2), 1);
        }
        for assertion in [
            Assertion::StartText,
            Assertion::EndText,
            Assertion::EndLf,
            Assertion::EndCrlf,
            Assertion::WordEndHalfAscii,
        ] {
            assert_eq!(source_bytes(context, assertion, 2), 0);
        }
    }

    #[test]
    fn unicode_assertion_source_bytes_are_censused_during_one_evaluation() {
        let haystack = "aé🦀z".as_bytes();
        let context = AssertionContext::new(haystack, 0, haystack.len()).unwrap();
        let position = "aé".len();
        assert_eq!(source_bytes(context, Assertion::WordUnicode, position), 6);
    }
}

const fn is_ascii_word(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn unicode_word_scalar(scalar: Option<char>) -> Result<bool, Error> {
    let Some(scalar) = scalar else {
        return Ok(false);
    };
    regex_syntax::try_is_word_character(scalar)
        .map_err(|_| Error::InternalInvariant("pinned Unicode word table is unavailable"))
}

fn unicode_assertion_matches(
    assertion: Assertion,
    before_empty: bool,
    after_empty: bool,
    left_scalar: Option<char>,
    right_scalar: Option<char>,
) -> Result<bool, Error> {
    let left_valid = before_empty || left_scalar.is_some();
    let right_valid = after_empty || right_scalar.is_some();
    let left_word = unicode_word_scalar(left_scalar)?;
    let right_word = unicode_word_scalar(right_scalar)?;
    Ok(match assertion {
        Assertion::WordUnicode => left_word != right_word,
        Assertion::WordUnicodeNegate => left_valid && right_valid && left_word == right_word,
        Assertion::WordStartUnicode => !left_word && right_word,
        Assertion::WordEndUnicode => left_word && !right_word,
        Assertion::WordStartHalfUnicode => left_valid && !left_word,
        Assertion::WordEndHalfUnicode => right_valid && !right_word,
        _ => {
            return Err(Error::InternalInvariant(
                "non-Unicode assertion in Unicode dispatch",
            ));
        }
    })
}

pub(crate) fn decode_first_scalar(bytes: &[u8]) -> Option<char> {
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

fn decode_last_scalar(bytes: &[u8]) -> Option<char> {
    let end = bytes.len();
    let mut start = end.checked_sub(1)?;
    let limit = end.saturating_sub(4);
    while start > limit && matches!(bytes[start], 0x80..=0xBF) {
        start = start.checked_sub(1)?;
    }
    let encoded = bytes.get(start..end)?;
    let scalar = decode_first_scalar(encoded)?;
    (scalar.len_utf8() == encoded.len()).then_some(scalar)
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Inst {
    Unfilled,
    Fail,
    Match,
    Consume {
        bytes: ByteSet,
        next: usize,
    },
    /// Scalar ranges owned directly by this state. This is the incumbent
    /// representation and remains allocation/accounting exact for scalar
    /// programs that never duplicate the state through a progress product.
    ConsumeScalarOwned {
        scalars: ScalarSet,
        next_by_width: [usize; 4],
    },
    /// Program-local reference produced only when a progress product must
    /// duplicate an owned scalar state.
    ConsumeScalarShared {
        scalars: ScalarSetId,
        next_by_width: [usize; 4],
    },
    Assert {
        assertion: Assertion,
        next: usize,
    },
    Split {
        preferred: usize,
        fallback: usize,
    },
    /// A split in a compiler-proved ordered top-level alternation.
    ///
    /// Generic execution preserves ordinary split semantics. The dedicated
    /// ordered-root Count route can instead probe the complete source-ordered
    /// chain once per row without materializing these intermediate states.
    RootSplit {
        preferred: usize,
        fallback: usize,
    },
}

impl Inst {
    pub(crate) fn scalar_logical_bytes(&self) -> Result<usize, Error> {
        match self {
            Self::ConsumeScalarOwned { scalars, .. } => scalars.allocated_bytes(),
            Self::ConsumeScalarShared { scalars, .. } => scalars.logical_bytes(),
            _ => Ok(0),
        }
    }

    pub(crate) fn scalar_range_count(&self) -> usize {
        match self {
            Self::ConsumeScalarOwned { scalars, .. } => scalars.len(),
            Self::ConsumeScalarShared { scalars, .. } => scalars.len(),
            _ => 0,
        }
    }

    pub(crate) fn resolve_scalar_set<'a>(
        &'a self,
        owners: &'a [ScalarSet],
    ) -> Result<Option<&'a ScalarSet>, Error> {
        match self {
            Self::ConsumeScalarOwned { scalars, .. } => Ok(Some(scalars)),
            Self::ConsumeScalarShared { scalars, .. } => Ok(Some(scalars.resolve(owners)?)),
            _ => Ok(None),
        }
    }
}

#[derive(Debug)]
pub(crate) struct Program {
    pub(crate) insts: ExactVec<Inst>,
    /// Optional fallibly allocated owner table for immutable Unicode scalar
    /// ranges. Byte-only programs retain only this nullable word and perform
    /// no scalar-table allocation.
    pub(crate) scalar_sets: Option<Box<ScalarSetTable>>,
    pub(crate) entry: usize,
    pub(crate) epsilon_order: ExactVec<usize>,
    pub(crate) split_rank: ExactVec<usize>,
    pub(crate) split_count: usize,
    pub(crate) root_split_count: usize,
    pub(crate) root_alternation_arms: usize,
    pub(crate) execution_state_work: usize,
    pub(crate) predecessor_edges: usize,
    pub(crate) has_scalar_transition: bool,
    pub(crate) has_assertion: bool,
    pub(crate) max_scalar_search_checks: usize,
    /// Compiler-certified maximum number of non-accepting source bytes that
    /// can remain live after an ordered accepting transition. `None` means no
    /// finite byte-only certificate was published, either because the
    /// non-accepting consume graph contains a cycle or because the program
    /// contains scalar/assertion instructions outside the sweep domain.
    /// `usize::MAX` encodes the absent certificate. Every finite certificate
    /// is strictly smaller than the program state count, so the sentinel is
    /// disjoint without widening this field to `Option<usize>`.
    pub(crate) continuation_nonaccepting_run: usize,
    pub(crate) has_unicode_word_boundary: bool,
    /// Construction-proved match-start domain. Kept beside the compact
    /// program flags so this optional execution hint occupies existing
    /// structure padding instead of enlarging every compiled-regex owner.
    pub(crate) start_domain: StartDomain,
    /// Exact compiler-retained proof that the complete program is one
    /// zero-width assertion followed immediately by acceptance.
    ///
    /// This is populated during the already-budgeted identity traversal, so
    /// execution never reclassifies the program or source spelling.
    pub(crate) root_assertion: Option<Assertion>,
}

impl Program {
    pub(crate) fn encode_continuation_nonaccepting_run(
        proof: Option<usize>,
        program_states: usize,
    ) -> Result<usize, Error> {
        match proof {
            None => Ok(NO_CONTINUATION_NONACCEPTING_RUN),
            Some(run) if run < program_states => Ok(run),
            Some(_) => Err(Error::InternalInvariant(
                "finite continuation proof is not smaller than program",
            )),
        }
    }

    pub(crate) const fn contains_unicode_word_boundary(&self) -> bool {
        self.has_unicode_word_boundary
    }

    pub(crate) const fn root_assertion(&self) -> Option<Assertion> {
        self.root_assertion
    }

    pub(crate) fn instruction(&self, pc: usize) -> Result<&Inst, Error> {
        self.insts
            .get(pc)
            .ok_or(Error::InternalInvariant("program counter outside program"))
    }

    pub(crate) fn scalar_set_for_inst<'a>(
        &'a self,
        inst: &'a Inst,
    ) -> Result<&'a ScalarSet, Error> {
        match inst {
            Inst::ConsumeScalarOwned { scalars, .. } => Ok(scalars),
            Inst::ConsumeScalarShared { scalars, .. } => {
                let table = self.scalar_sets.as_deref().ok_or(Error::InternalInvariant(
                    "shared Unicode scalar state has no owner table",
                ))?;
                if table.diagnostics.representation != ScalarSetId::REPRESENTATION_V1 {
                    return Err(Error::InternalInvariant(
                        "Unicode scalar owner representation differs from program",
                    ));
                }
                scalars.resolve(&table.owners)
            }
            _ => Err(Error::InternalInvariant(
                "non-scalar instruction has no scalar set",
            )),
        }
    }

    pub(crate) fn scalar_sets(&self) -> &[ScalarSet] {
        match &self.scalar_sets {
            Some(scalar_sets) => &scalar_sets.owners[..],
            None => &[],
        }
    }

    pub(crate) fn scalar_set_diagnostics(&self) -> Option<ScalarSetDiagnostics> {
        self.scalar_sets
            .as_deref()
            .map(|scalar_sets| scalar_sets.diagnostics)
    }

    pub(crate) const fn execution_state_work(&self) -> usize {
        self.execution_state_work
    }

    pub(crate) const fn predecessor_edges(&self) -> usize {
        self.predecessor_edges
    }

    pub(crate) const fn root_split_count(&self) -> usize {
        self.root_split_count
    }

    pub(crate) const fn root_alternation_arms(&self) -> usize {
        self.root_alternation_arms
    }

    pub(crate) const fn contains_scalar_transition(&self) -> bool {
        self.has_scalar_transition
    }

    pub(crate) const fn contains_assertion(&self) -> bool {
        self.has_assertion
    }

    pub(crate) const fn max_scalar_search_checks(&self) -> usize {
        self.max_scalar_search_checks
    }

    pub(crate) const fn continuation_nonaccepting_run(&self) -> Option<usize> {
        if self.continuation_nonaccepting_run == NO_CONTINUATION_NONACCEPTING_RUN {
            None
        } else {
            Some(self.continuation_nonaccepting_run)
        }
    }
}

#[cfg(test)]
mod program_layout_tests {
    use fre_exact_alloc::ExactVec;

    use super::{
        Assertion, Inst, Program, ScalarRange, ScalarSet, ScalarSetDiagnostics, ScalarSetId,
        ScalarSetTable, StartDomain, exact_scalar_ranges,
    };
    use crate::Error;

    fn empty_exact<T>() -> ExactVec<T> {
        ExactVec::try_with_capacity(0).expect("zero-capacity exact vector")
    }

    fn empty_program() -> Program {
        Program {
            insts: empty_exact(),
            scalar_sets: None,
            entry: 0,
            epsilon_order: empty_exact(),
            split_rank: empty_exact(),
            split_count: 0,
            root_split_count: 0,
            root_alternation_arms: 0,
            execution_state_work: 0,
            predecessor_edges: 0,
            has_scalar_transition: true,
            has_assertion: false,
            max_scalar_search_checks: 0,
            continuation_nonaccepting_run: usize::MAX,
            has_unicode_word_boundary: false,
            start_domain: StartDomain::AnyBoundary,
            root_assertion: None,
        }
    }

    fn one_owner_table() -> Box<ScalarSetTable> {
        let mut ranges = exact_scalar_ranges(1).unwrap();
        ranges
            .try_push(ScalarRange::new('a', 'a').unwrap())
            .unwrap();
        let mut owners = ExactVec::try_with_capacity(1).unwrap();
        owners.try_push(ScalarSet(ranges)).unwrap();
        Box::new(ScalarSetTable {
            owners,
            diagnostics: ScalarSetDiagnostics {
                representation: ScalarSetId::REPRESENTATION_V1,
                owner_index_allocations: 0,
                owner_range_bytes: 0,
                owner_index_bytes: 0,
                owner_peak_bytes: 0,
                logical_reference_bytes: 0,
                reference_copies: 0,
            },
        })
    }

    /// Exact pre-sharing outer layout. The shared representation must reuse
    /// the word freed by the continuation sentinel instead of growing every
    /// compiled program owner.
    #[allow(dead_code)]
    struct LegacyProgramLayout {
        insts: ExactVec<Inst>,
        entry: usize,
        epsilon_order: ExactVec<usize>,
        split_rank: ExactVec<usize>,
        split_count: usize,
        root_split_count: usize,
        root_alternation_arms: usize,
        execution_state_work: usize,
        predecessor_edges: usize,
        has_scalar_transition: bool,
        has_assertion: bool,
        max_scalar_search_checks: usize,
        continuation_nonaccepting_run: Option<usize>,
        has_unicode_word_boundary: bool,
        start_domain: StartDomain,
        root_assertion: Option<Assertion>,
    }

    #[test]
    fn shared_scalar_table_preserves_ordinary_program_outer_layout() {
        assert_eq!(core::mem::size_of::<LegacyProgramLayout>(), 152);
        assert_eq!(
            core::mem::size_of::<Program>(),
            core::mem::size_of::<LegacyProgramLayout>()
        );
        assert_eq!(
            core::mem::size_of::<Option<Box<ScalarSetTable>>>(),
            core::mem::size_of::<usize>()
        );
    }

    #[test]
    fn shared_scalar_resolution_rejects_missing_table_index_and_range_count() {
        let mut program = empty_program();
        let missing = Inst::ConsumeScalarShared {
            scalars: ScalarSetId::new(0, 1).unwrap(),
            next_by_width: [0; 4],
        };
        assert!(matches!(
            program.scalar_set_for_inst(&missing),
            Err(Error::InternalInvariant(
                "shared Unicode scalar state has no owner table"
            ))
        ));

        program.scalar_sets = Some(one_owner_table());
        let outside = Inst::ConsumeScalarShared {
            scalars: ScalarSetId::new(1, 1).unwrap(),
            next_by_width: [0; 4],
        };
        assert!(matches!(
            program.scalar_set_for_inst(&outside),
            Err(Error::InternalInvariant(
                "Unicode scalar owner outside program"
            ))
        ));

        let wrong_ranges = Inst::ConsumeScalarShared {
            scalars: ScalarSetId::new(0, 2).unwrap(),
            next_by_width: [0; 4],
        };
        assert!(matches!(
            program.scalar_set_for_inst(&wrong_ranges),
            Err(Error::InternalInvariant(
                "Unicode scalar owner range count differs from instruction"
            ))
        ));
    }
}
