//! Deterministic byte-atom search over construction-certified line domains.
//!
//! This kernel deliberately knows nothing about regular-expression syntax.
//! Its constructor accepts a finite positive sequence of byte-mask atoms and
//! proves the local conditions that make a one-pass greedy evaluator exact:
//! every variable-width nonterminal atom has a first-byte mask disjoint from
//! its required successor, and no atom can consume the selected line mode's
//! terminators. A facade may therefore lower an exact
//! `line-start BODY line-end` HIR into this plan without retaining generic
//! contextual-automaton state.
//!
//! Search visits semantic line starts in source order. Ordinary multi-line
//! mode treats only its configured byte as a terminator. CRLF mode treats lone
//! CR, lone LF, and a CRLF pair as line terminators, with no assertion boundary
//! between the bytes of a pair. The search window restricts eligible match
//! spans; assertion checks still read the complete original haystack.

use core::{fmt, mem::size_of};

use fre_kernel_ir::MatchSpan;
use fre_simd_kernels::{
    BYTE_SET_WIDE_BLOCK_BYTES, classify_byte_set4_32,
};
use memchr::{memchr, memchr2, memchr3, memmem, memrchr, memrchr2};

use crate::anchored_line_capture::{Atom, ByteMask, MAX_ATOMS};

/// Immutable implementation identity for construction and search receipts.
pub const PLAN_ID: &str = "line-domain-byte-atoms-search-v4";

const BUILD_FIXED_WORK: u64 = 1;
const BUILD_ATOM_WORK: u64 = 1;
const BUILD_MASK_WORD_WORK: u64 = 1;
const BUILD_WIDTH_WORK: u64 = 1;
const BUILD_PREFILTER_FIXED_WORK: u64 = 1;
const BUILD_PREFILTER_ATOM_WORK: u64 = 1;
const BUILD_PREFILTER_MASK_WORD_WORK: u64 = 1;
const BUILD_PREFILTER_RETAINED_BYTE_WORK: u64 = 1;

// The facade currently certifies at most 256 selected bytes. Keeping that
// complete fixed literal inline makes the unlimited value executor independent
// of temporary allocation and of the source being searched. Public kernel
// callers with a larger construction ceiling still receive the delimiter
// executor when no retained prefix fits this conservative capacity.
const VALUE_PREFILTER_LITERAL_BYTES: usize = 256;
const VALUE_PREFILTER_SET_BYTES: usize = 4;
const VALUE_PREFILTER_MASK_WORDS: usize = 4;
// The endpoint probe is useful only when rejecting a wrong-width line avoids
// checking at least two established wide-block work quanta. Narrow fixed plans
// retain the branch-minimal delimiter executor.
const FIXED_WIDTH_ENDPOINT_MIN_BYTES: usize = 2 * BYTE_SET_WIDE_BLOCK_BYTES;

/// Line assertion family certified by the facade's HIR proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LineMode {
    /// `^` and `$` in ordinary multi-line mode with its configured byte.
    Lf { terminator: u8 },
    /// `^` and `$` in CRLF-aware multi-line mode.
    Crlf,
}

impl LineMode {
    fn identity(self) -> u64 {
        match self {
            Self::Lf { terminator } => 0x100_u64 | u64::from(terminator),
            Self::Crlf => 0x200_u64,
        }
    }

    fn mask_admits_terminator(self, mask: ByteMask) -> bool {
        match self {
            Self::Lf { terminator } => mask.contains(terminator),
            Self::Crlf => mask.contains(b'\r') || mask.contains(b'\n'),
        }
    }
}

/// Exact alignment of one construction-derived value-path candidate source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ValueAnchor {
    /// The retained needle begins at one exact offset from the match start.
    Start { offset: usize },
    /// The retained needle has one exact number of bytes after it before the
    /// asserted line end.
    End { trailing: usize },
}

/// Construction-derived candidate source for the branch-minimal value path.
///
/// Start anchors use the fixed-width prefix through the first variable atom.
/// End anchors symmetrically use the fixed-width suffix through the last
/// variable atom. A complete literal is preferred to a small byte set, and a
/// start anchor wins structural ties so the established path remains stable.
/// Every retained occurrence is necessary in every selected match and can
/// therefore only remove impossible line starts.
#[derive(Clone, Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "the complete literal stays inline so construction and value search remain allocation-free"
)]
enum ValuePrefilter {
    None,
    Literal {
        anchor: ValueAnchor,
        len: usize,
        bytes: [u8; VALUE_PREFILTER_LITERAL_BYTES],
    },
    SmallSet {
        anchor: ValueAnchor,
        len: usize,
        bytes: [u8; VALUE_PREFILTER_SET_BYTES],
    },
}

#[derive(Clone, Copy, Debug)]
struct LiteralCandidate {
    anchor: ValueAnchor,
    atom_start: usize,
    atom_end: usize,
    len: usize,
}

#[derive(Clone, Copy, Debug)]
struct SetCandidate {
    anchor: ValueAnchor,
    len: usize,
    mask: ByteMask,
}

#[derive(Clone, Copy, Debug)]
struct ValuePrefilterAnalysis {
    literal: Option<LiteralCandidate>,
    set: Option<SetCandidate>,
}

impl ValuePrefilterAnalysis {
    fn consider_literal(&mut self, candidate: LiteralCandidate) {
        if self
            .literal
            .is_none_or(|current| candidate.len > current.len)
        {
            self.literal = Some(candidate);
        }
    }

    fn consider_set(&mut self, candidate: SetCandidate) {
        if self.set.is_none_or(|current| candidate.len < current.len) {
            self.set = Some(candidate);
        }
    }

    fn retained_bytes(self) -> usize {
        self.literal.map_or_else(
            || self.set.map_or(0, |candidate| candidate.len),
            |candidate| candidate.len,
        )
    }
}

impl ValuePrefilter {
    fn select(
        atoms: &[Atom],
        work: &mut u64,
        work_limit: u64,
    ) -> Result<Self, BuildError> {
        let analysis = Self::analyze(atoms, work, work_limit)?;
        charge_retained_prefilter_bytes(work, analysis.retained_bytes(), work_limit)?;

        if let Some(candidate) = analysis.literal {
            let mut bytes = [0_u8; VALUE_PREFILTER_LITERAL_BYTES];
            match candidate.anchor {
                ValueAnchor::Start { .. } => {
                    let mut retained = 0_usize;
                    for atom in atoms[candidate.atom_start..candidate.atom_end]
                        .iter()
                        .copied()
                    {
                        let mut member = [0_u8; 1];
                        let retained_members = retain_mask_members(atom.mask(), &mut member);
                        debug_assert_eq!(retained_members, 1);
                        let repetitions = usize::try_from(atom.minimum())
                            .expect("construction accepted a representable width")
                            .min(candidate.len.saturating_sub(retained));
                        let retained_end = retained
                            .checked_add(repetitions)
                            .expect("one retained literal stays within its inline buffer");
                        bytes[retained..retained_end].fill(member[0]);
                        retained = retained_end;
                    }
                    debug_assert_eq!(retained, candidate.len);
                }
                ValueAnchor::End { .. } => {
                    let mut retained_start = candidate.len;
                    for atom in atoms[candidate.atom_start..candidate.atom_end]
                        .iter()
                        .rev()
                        .copied()
                    {
                        let mut member = [0_u8; 1];
                        let retained_members = retain_mask_members(atom.mask(), &mut member);
                        debug_assert_eq!(retained_members, 1);
                        let repetitions = usize::try_from(atom.minimum())
                            .expect("construction accepted a representable width")
                            .min(retained_start);
                        let next_start = retained_start
                            .checked_sub(repetitions)
                            .expect("one retained suffix stays within its inline buffer");
                        bytes[next_start..retained_start].fill(member[0]);
                        retained_start = next_start;
                    }
                    debug_assert_eq!(retained_start, 0);
                }
            }
            return Ok(Self::Literal {
                anchor: candidate.anchor,
                len: candidate.len,
                bytes,
            });
        }
        if let Some(candidate) = analysis.set {
            let mut bytes = [0_u8; VALUE_PREFILTER_SET_BYTES];
            let retained = retain_mask_members(candidate.mask, &mut bytes);
            debug_assert_eq!(retained, candidate.len);
            return Ok(Self::SmallSet {
                anchor: candidate.anchor,
                len: candidate.len,
                bytes,
            });
        }
        Ok(Self::None)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one symmetric traversal keeps start/end selection and exact construction charging visibly aligned"
    )]
    fn analyze(
        atoms: &[Atom],
        work: &mut u64,
        work_limit: u64,
    ) -> Result<ValuePrefilterAnalysis, BuildError> {
        let mut analysis = ValuePrefilterAnalysis {
            literal: None,
            set: None,
        };
        charge_build(work, BUILD_PREFILTER_FIXED_WORK, work_limit)?;
        let mut exact_offset = 0_usize;
        let mut current_literal_start = 0_usize;
        let mut current_literal_offset = 0_usize;
        let mut current_literal_len = 0_usize;

        for atom_index in 0..atoms.len() {
            let (atom, minimum, maximum, cardinality) =
                inspect_prefilter_atom(atoms, atom_index, work, work_limit)?;
            if cardinality == 1 {
                if current_literal_len == 0 {
                    current_literal_start = atom_index;
                    current_literal_offset = exact_offset;
                }
                let retained = minimum.min(
                    VALUE_PREFILTER_LITERAL_BYTES.saturating_sub(current_literal_len),
                );
                let retained_end = current_literal_len
                    .checked_add(retained)
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "retained start-anchor literal bytes",
                    })?;
                current_literal_len = retained_end;
                analysis.consider_literal(LiteralCandidate {
                    anchor: ValueAnchor::Start {
                        offset: current_literal_offset,
                    },
                    atom_start: current_literal_start,
                    atom_end: atom_index.checked_add(1).ok_or(
                        BuildError::ArithmeticOverflow {
                            computation: "start-anchor atom end",
                        },
                    )?,
                    len: current_literal_len,
                });
            } else {
                current_literal_len = 0;
                if cardinality <= VALUE_PREFILTER_SET_BYTES {
                    analysis.consider_set(SetCandidate {
                        anchor: ValueAnchor::Start {
                            offset: exact_offset,
                        },
                        len: cardinality,
                        mask: atom.mask(),
                    });
                }
            }
            if minimum != maximum {
                break;
            }
            exact_offset = exact_offset
                .checked_add(maximum)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "start-anchor exact offset",
                })?;
        }

        // The backward traversal is separately accounted. It runs through the
        // last variable atom because that atom's mandatory final bytes retain
        // exact positions relative to the asserted line end.
        charge_build(work, BUILD_PREFILTER_FIXED_WORK, work_limit)?;
        let mut exact_trailing = 0_usize;
        let mut current_literal_end = atoms.len();
        let mut current_literal_trailing = 0_usize;
        current_literal_len = 0;
        for atom_index in (0..atoms.len()).rev() {
            let (atom, minimum, maximum, cardinality) =
                inspect_prefilter_atom(atoms, atom_index, work, work_limit)?;
            if cardinality == 1 {
                if current_literal_len == 0 {
                    current_literal_end = atom_index.checked_add(1).ok_or(
                        BuildError::ArithmeticOverflow {
                            computation: "end-anchor atom end",
                        },
                    )?;
                    current_literal_trailing = exact_trailing;
                }
                let retained = minimum.min(
                    VALUE_PREFILTER_LITERAL_BYTES.saturating_sub(current_literal_len),
                );
                current_literal_len = current_literal_len.checked_add(retained).ok_or(
                    BuildError::ArithmeticOverflow {
                        computation: "retained end-anchor literal bytes",
                    },
                )?;
                analysis.consider_literal(LiteralCandidate {
                    anchor: ValueAnchor::End {
                        trailing: current_literal_trailing,
                    },
                    atom_start: atom_index,
                    atom_end: current_literal_end,
                    len: current_literal_len,
                });
            } else {
                current_literal_len = 0;
                if cardinality <= VALUE_PREFILTER_SET_BYTES {
                    analysis.consider_set(SetCandidate {
                        anchor: ValueAnchor::End {
                            trailing: exact_trailing,
                        },
                        len: cardinality,
                        mask: atom.mask(),
                    });
                }
            }
            if minimum != maximum {
                break;
            }
            exact_trailing = exact_trailing.checked_add(maximum).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "end-anchor exact trailing width",
                },
            )?;
        }
        Ok(analysis)
    }

    fn projected_work(atoms: &[Atom]) -> Result<u64, BuildError> {
        let mut work = 0;
        let analysis = Self::analyze(atoms, &mut work, u64::MAX)?;
        charge_retained_prefilter_bytes(
            &mut work,
            analysis.retained_bytes(),
            u64::MAX,
        )?;
        Ok(work)
    }

    const fn anchor(&self) -> Option<ValueAnchor> {
        match self {
            Self::None => None,
            Self::Literal { anchor, .. } | Self::SmallSet { anchor, .. } => Some(*anchor),
        }
    }

    const fn needle_width(&self) -> Option<usize> {
        match self {
            Self::None => None,
            Self::Literal { len, .. } => Some(*len),
            Self::SmallSet { .. } => Some(1),
        }
    }

    fn matches_at(&self, haystack: &[u8], position: usize) -> bool {
        match self {
            Self::None => false,
            Self::Literal { len, bytes, .. } => position
                .checked_add(*len)
                .and_then(|end| haystack.get(position..end))
                .is_some_and(|candidate| candidate == &bytes[..*len]),
            Self::SmallSet { len, bytes, .. } => haystack
                .get(position)
                .is_some_and(|candidate| bytes[..*len].contains(candidate)),
        }
    }

    fn find(&self, haystack: &[u8]) -> Option<usize> {
        match self {
            Self::None => None,
            Self::Literal { len, bytes, .. } => match *len {
                0 => None,
                1 => memchr(bytes[0], haystack),
                _ => memmem::find(haystack, &bytes[..*len]),
            },
            Self::SmallSet { len, bytes, .. } => match *len {
                1 => memchr(bytes[0], haystack),
                2 => memchr2(bytes[0], bytes[1], haystack),
                3 => memchr3(bytes[0], bytes[1], bytes[2], haystack),
                4 => find_byte_set4([bytes[0], bytes[1], bytes[2], bytes[3]], haystack),
                0 | 5.. => None,
            },
        }
    }
}

fn inspect_prefilter_atom(
    atoms: &[Atom],
    atom_index: usize,
    work: &mut u64,
    work_limit: u64,
) -> Result<(Atom, usize, usize, usize), BuildError> {
    charge_build(work, BUILD_PREFILTER_ATOM_WORK, work_limit)?;
    let atom = atoms
        .get(atom_index)
        .copied()
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "prefilter atom index",
        })?;
    let minimum = usize::try_from(atom.minimum()).map_err(|_| {
        BuildError::ArithmeticOverflow {
            computation: "prefilter minimum width",
        }
    })?;
    let maximum = usize::try_from(
        atom.maximum()
            .ok_or(BuildError::UnboundedAtom { atom: atom_index })?,
    )
    .map_err(|_| BuildError::ArithmeticOverflow {
        computation: "prefilter maximum width",
    })?;
    for _ in 0..VALUE_PREFILTER_MASK_WORDS {
        charge_build(work, BUILD_PREFILTER_MASK_WORD_WORK, work_limit)?;
    }
    let mut cardinality = 0_usize;
    for word in atom.mask().words() {
        cardinality = cardinality
            .checked_add(
                usize::try_from(word.count_ones())
                    .expect("one mask word cardinality fits usize"),
            )
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "prefilter mask cardinality",
            })?;
    }
    Ok((atom, minimum, maximum, cardinality))
}

/// Hard construction ceilings for one inline plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    /// Maximum number of retained atoms.
    pub max_atoms: usize,
    /// Maximum byte width of one match.
    pub max_match_bytes: usize,
    /// Maximum checked construction work.
    pub max_work: u64,
    /// Maximum exact persistent bytes for the inline plan.
    pub max_persistent_bytes: usize,
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            max_atoms: MAX_ATOMS,
            max_match_bytes: 256,
            max_work: 1 << 20,
            max_persistent_bytes: 1 << 20,
        }
    }
}

/// Complete source-independent construction receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    /// Stable kernel identity.
    pub plan_id: &'static str,
    /// Selected line assertion family.
    pub line_mode: LineMode,
    /// Number of retained atoms.
    pub atom_count: usize,
    /// Exact minimum selected width.
    pub minimum_match_bytes: usize,
    /// Exact maximum selected width.
    pub maximum_match_bytes: usize,
    /// Checked atom, bitmap, and width-proof work.
    pub work: u64,
    /// Dynamic construction allocations; always zero.
    pub allocations: usize,
    /// Exact retained bytes for the inline plan.
    pub persistent_bytes: usize,
}

/// Construction refusal for a proposed byte-atom program.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    /// No positive byte atom was supplied.
    Empty,
    /// The requested atom count exceeds the fixed inline representation.
    AtomLimit { needed: usize, limit: usize },
    /// One atom has an empty byte mask.
    EmptyMask { atom: usize },
    /// Every admitted atom must consume at least one byte.
    NullableAtom { atom: usize },
    /// One atom has no finite maximum.
    UnboundedAtom { atom: usize },
    /// One atom's maximum is below its minimum.
    ReversedWidth { atom: usize },
    /// The body could consume a line terminator and cross a line domain.
    TerminatorInBody { atom: usize, mode: LineMode },
    /// A greedy variable run overlaps its required successor.
    AmbiguousGreedyBoundary { atom: usize },
    /// The finite match width exceeds the construction ceiling.
    MatchWidthLimit { needed: usize, limit: usize },
    /// Checked construction work exceeds its ceiling.
    WorkLimit { needed: u64, limit: u64 },
    /// Exact retained bytes exceed their ceiling.
    PersistentBytesLimit { needed: usize, limit: usize },
    /// A checked construction quantity could not be represented.
    ArithmeticOverflow { computation: &'static str },
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("line-domain plan needs at least one atom"),
            Self::AtomLimit { needed, limit } => write!(
                formatter,
                "line-domain plan needs {needed} atoms, exceeding {limit}"
            ),
            Self::EmptyMask { atom } => {
                write!(formatter, "line-domain atom {atom} has an empty mask")
            }
            Self::NullableAtom { atom } => write!(
                formatter,
                "line-domain atom {atom} is nullable; every atom must be positive"
            ),
            Self::UnboundedAtom { atom } => {
                write!(formatter, "line-domain atom {atom} is unbounded")
            }
            Self::ReversedWidth { atom } => {
                write!(formatter, "line-domain atom {atom} has reversed widths")
            }
            Self::TerminatorInBody { atom, mode } => write!(
                formatter,
                "line-domain atom {atom} can consume a {mode:?} terminator"
            ),
            Self::AmbiguousGreedyBoundary { atom } => write!(
                formatter,
                "line-domain variable atom {atom} overlaps its successor"
            ),
            Self::MatchWidthLimit { needed, limit } => write!(
                formatter,
                "line-domain match width {needed} exceeds {limit}"
            ),
            Self::WorkLimit { needed, limit } => write!(
                formatter,
                "line-domain construction needs work {needed}, exceeding {limit}"
            ),
            Self::PersistentBytesLimit { needed, limit } => write!(
                formatter,
                "line-domain plan needs {needed} retained bytes, exceeding {limit}"
            ),
            Self::ArithmeticOverflow { computation } => {
                write!(formatter, "line-domain {computation} overflowed")
            }
        }
    }
}

impl std::error::Error for BuildError {}

/// One allocation-free deterministic line-domain program.
#[derive(Clone, Debug)]
pub struct LineDomainPlan {
    atoms: [Atom; MAX_ATOMS],
    atom_count: usize,
    minimum_match_bytes: usize,
    maximum_match_bytes: usize,
    line_mode: LineMode,
    // Construction-sealed admission for the exact-width endpoint executor.
    fixed_width_endpoint: bool,
    value_prefilter: ValuePrefilter,
}

trait ValueProjection {
    type Output;

    fn selected(start: usize, end: usize) -> Self::Output;
}

struct SpanProjection;

impl ValueProjection for SpanProjection {
    type Output = MatchSpan;

    #[inline]
    fn selected(start: usize, end: usize) -> Self::Output {
        MatchSpan::new(start, end)
    }
}

struct EndProjection;

impl ValueProjection for EndProjection {
    type Output = usize;

    #[inline]
    fn selected(_start: usize, end: usize) -> Self::Output {
        end
    }
}

impl LineDomainPlan {
    /// Exact source-independent work added by value-prefilter derivation for
    /// an atom sequence already certified by the facade.
    #[doc(hidden)]
    pub fn projected_value_prefilter_build_work(atoms: &[Atom]) -> Result<u64, BuildError> {
        ValuePrefilter::projected_work(atoms)
    }

    /// Validate and copy one finite byte-atom program into inline storage.
    #[allow(
        clippy::too_many_lines,
        reason = "one constructor keeps every byte-atom validity and exact-accounting check in proof order"
    )]
    pub fn new(
        line_mode: LineMode,
        atoms: &[Atom],
        limits: BuildLimits,
    ) -> Result<(Self, BuildAccounting), BuildError> {
        if atoms.is_empty() {
            return Err(BuildError::Empty);
        }
        let atom_limit = limits.max_atoms.min(MAX_ATOMS);
        if atoms.len() > atom_limit {
            return Err(BuildError::AtomLimit {
                needed: atoms.len(),
                limit: atom_limit,
            });
        }

        let mut work = 0;
        charge_build(&mut work, BUILD_FIXED_WORK, limits.max_work)?;
        let mut minimum_match_bytes = 0_usize;
        let mut maximum_match_bytes = 0_usize;
        for (index, atom) in atoms.iter().copied().enumerate() {
            charge_build(&mut work, BUILD_ATOM_WORK, limits.max_work)?;
            if atom.mask().is_empty() {
                return Err(BuildError::EmptyMask { atom: index });
            }
            let Ok(minimum) = usize::try_from(atom.minimum()) else {
                return Err(BuildError::ArithmeticOverflow {
                    computation: "minimum atom width",
                });
            };
            if minimum == 0 {
                return Err(BuildError::NullableAtom { atom: index });
            }
            let Some(maximum) = atom.maximum() else {
                return Err(BuildError::UnboundedAtom { atom: index });
            };
            let Ok(maximum) = usize::try_from(maximum) else {
                return Err(BuildError::ArithmeticOverflow {
                    computation: "maximum atom width",
                });
            };
            if maximum < minimum {
                return Err(BuildError::ReversedWidth { atom: index });
            }
            charge_build(&mut work, BUILD_WIDTH_WORK, limits.max_work)?;
            if line_mode.mask_admits_terminator(atom.mask()) {
                return Err(BuildError::TerminatorInBody {
                    atom: index,
                    mode: line_mode,
                });
            }
            minimum_match_bytes = minimum_match_bytes.checked_add(minimum).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "minimum match width",
                },
            )?;
            maximum_match_bytes = maximum_match_bytes.checked_add(maximum).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "maximum match width",
                },
            )?;
            if maximum != minimum
                && let Some(successor) = atoms.get(index.saturating_add(1))
            {
                for (left, right) in atom
                    .mask()
                    .words()
                    .into_iter()
                    .zip(successor.mask().words())
                {
                    charge_build(&mut work, BUILD_MASK_WORD_WORK, limits.max_work)?;
                    if left & right != 0 {
                        return Err(BuildError::AmbiguousGreedyBoundary { atom: index });
                    }
                }
            }
        }
        if maximum_match_bytes > limits.max_match_bytes {
            return Err(BuildError::MatchWidthLimit {
                needed: maximum_match_bytes,
                limit: limits.max_match_bytes,
            });
        }
        let persistent_bytes = size_of::<Self>();
        if persistent_bytes > limits.max_persistent_bytes {
            return Err(BuildError::PersistentBytesLimit {
                needed: persistent_bytes,
                limit: limits.max_persistent_bytes,
            });
        }

        let mut retained = [Atom::default(); MAX_ATOMS];
        retained[..atoms.len()].copy_from_slice(atoms);
        let value_prefilter = ValuePrefilter::select(atoms, &mut work, limits.max_work)?;
        let fixed_width_endpoint = matches!(value_prefilter, ValuePrefilter::None)
            && minimum_match_bytes == maximum_match_bytes
            && minimum_match_bytes >= FIXED_WIDTH_ENDPOINT_MIN_BYTES;
        let plan = Self {
            atoms: retained,
            atom_count: atoms.len(),
            minimum_match_bytes,
            maximum_match_bytes,
            line_mode,
            fixed_width_endpoint,
            value_prefilter,
        };
        let accounting = BuildAccounting {
            plan_id: PLAN_ID,
            line_mode,
            atom_count: atoms.len(),
            minimum_match_bytes,
            maximum_match_bytes,
            work,
            allocations: 0,
            persistent_bytes,
        };
        Ok((plan, accounting))
    }

    /// Visit one exact, canonical sequence for compiled-plan authentication.
    ///
    /// This capability is public only because the facade lives in another
    /// crate. The explicit atom count makes the emitted prefix self-delimiting;
    /// every retained width and all 256 mask bits then participate without a
    /// lossy intermediate fingerprint.
    #[doc(hidden)]
    pub fn visit_identity_words(&self, mut visit: impl FnMut(u64)) {
        visit(1);
        visit(self.line_mode.identity());
        visit(u64::try_from(self.atom_count).unwrap_or(u64::MAX));
        visit(u64::try_from(self.minimum_match_bytes).unwrap_or(u64::MAX));
        visit(u64::try_from(self.maximum_match_bytes).unwrap_or(u64::MAX));
        for atom in self.atoms().iter().copied() {
            visit(u64::from(atom.minimum()));
            visit(u64::from(atom.maximum().unwrap_or(u32::MAX)));
            for word in atom.mask().words() {
                visit(word);
            }
        }
    }

    /// Selected line assertion family.
    #[must_use]
    pub const fn line_mode(&self) -> LineMode {
        self.line_mode
    }

    /// Exact minimum selected width.
    #[must_use]
    pub const fn minimum_match_bytes(&self) -> usize {
        self.minimum_match_bytes
    }

    /// Exact maximum selected width.
    #[must_use]
    pub const fn maximum_match_bytes(&self) -> usize {
        self.maximum_match_bytes
    }

    /// Number of retained atoms.
    #[must_use]
    pub const fn atom_count(&self) -> usize {
        self.atom_count
    }

    fn atoms(&self) -> &[Atom] {
        &self.atoms[..self.atom_count]
    }

    /// Derive a complete source-independent envelope for an arbitrary window.
    pub fn search_upper_bounds(
        &self,
        haystack_len: usize,
        start: usize,
        end: usize,
    ) -> Result<SearchUpperBounds, SearchError> {
        if start > end || end > haystack_len {
            return Err(SearchError::InvalidWindow);
        }
        let input_bytes = input_bytes(start, end);
        let bytes = u64::try_from(input_bytes).map_err(|_| SearchError::ArithmeticOverflow {
            counter: "input bytes",
        })?;
        let candidates = bytes.checked_add(1).ok_or(SearchError::ArithmeticOverflow {
            counter: "candidate bound",
        })?;
        let atoms = u64::try_from(self.atom_count).map_err(|_| {
            SearchError::ArithmeticOverflow {
                counter: "atom count",
            }
        })?;

        // Primary delimiter-scan positions advance monotonically. CRLF mode
        // can inspect one lookahead byte per primary position.
        let delimiter_steps = bytes;
        let delimiter_source_reads = bytes.checked_mul(2).ok_or(
            SearchError::ArithmeticOverflow {
                counter: "delimiter source-read bound",
            },
        )?;
        // Successful content bytes belong to disjoint line domains. At most
        // one mismatch is re-probed at each atom boundary, plus one terminal
        // mismatch per candidate.
        let atom_probes = candidates
            .checked_mul(atoms.checked_add(1).ok_or(
                SearchError::ArithmeticOverflow {
                    counter: "atom-probe factor",
                },
            )?)
            .and_then(|overhead| bytes.checked_add(overhead))
            .ok_or(SearchError::ArithmeticOverflow {
                counter: "atom-probe bound",
            })?;
        let atom_transitions = candidates.checked_mul(atoms).ok_or(
            SearchError::ArithmeticOverflow {
                counter: "atom-transition bound",
            },
        )?;
        // A complete iterator can begin a new monotone search after each
        // positive match. Each search performs one initial-start check; every
        // visited candidate performs one end check.
        let start_checks = candidates;
        let end_checks = candidates;
        let boundary_checks = start_checks.checked_add(end_checks).ok_or(
            SearchError::ArithmeticOverflow {
                counter: "boundary-check bound",
            },
        )?;
        let boundary_source_reads = boundary_checks.checked_mul(2).ok_or(
            SearchError::ArithmeticOverflow {
                counter: "boundary source-read bound",
            },
        )?;
        let source_reads = delimiter_source_reads
            .checked_add(atom_probes)
            .and_then(|value| value.checked_add(boundary_source_reads))
            .ok_or(SearchError::ArithmeticOverflow {
                counter: "source-read bound",
            })?;
        let match_events = candidates;
        let work = source_reads
            .checked_add(delimiter_steps)
            .and_then(|value| value.checked_add(atom_probes))
            .and_then(|value| value.checked_add(atom_transitions))
            .and_then(|value| value.checked_add(boundary_checks))
            .and_then(|value| value.checked_add(candidates))
            .and_then(|value| value.checked_add(match_events))
            .ok_or(SearchError::ArithmeticOverflow {
                counter: "work bound",
            })?;
        Ok(SearchUpperBounds {
            input_bytes,
            source_reads,
            delimiter_steps,
            atom_probes,
            atom_transitions,
            boundary_checks,
            candidate_events: candidates,
            match_events,
            work,
            allocations: 0,
            scratch_bytes: 0,
            persistent_bytes: size_of::<Self>(),
        })
    }

    /// Construct an accounting cursor after complete prospective admission.
    pub fn cursor<'plan, 'haystack>(
        &'plan self,
        haystack: &'haystack [u8],
        start: usize,
        end: usize,
        limits: SearchLimits,
    ) -> Result<Cursor<'plan, 'haystack>, SearchError> {
        let upper_bounds = self.search_upper_bounds(haystack.len(), start, end)?;
        if upper_bounds.work > limits.max_work {
            return Err(SearchError::WorkLimit {
                needed: upper_bounds.work,
                limit: limits.max_work,
            });
        }
        Ok(Cursor {
            plan: self,
            haystack,
            window_start: start,
            window_end: end,
            next_start: start,
            upper_bounds,
            actual: SearchActual::new(input_bytes(start, end)),
            finished: false,
        })
    }

    /// Return the first selected span and complete exact accounting.
    pub fn find(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
        limits: SearchLimits,
    ) -> Result<(Option<MatchSpan>, SearchAccounting), SearchError> {
        let mut cursor = self.cursor(haystack, start, end, limits)?;
        let matched = cursor.next_match()?;
        Ok((matched, cursor.accounting(Operation::Span)))
    }

    /// Return whether a selected span exists and complete exact accounting.
    pub fn is_match(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
        limits: SearchLimits,
    ) -> Result<(bool, SearchAccounting), SearchError> {
        let mut cursor = self.cursor(haystack, start, end, limits)?;
        let matched = cursor.next_match()?.is_some();
        Ok((matched, cursor.accounting(Operation::Exists)))
    }

    /// Value-only first-span search. Unlimited calls use the branch-minimal
    /// executor; finite limits retain the exact prospective/actual path.
    pub fn find_value(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
        limits: SearchLimits,
    ) -> Result<Option<MatchSpan>, SearchError> {
        if start > end || end > haystack.len() {
            return Err(SearchError::InvalidWindow);
        }
        if limits.max_work == u64::MAX {
            return Ok(self.find_from_value::<SpanProjection>(haystack, start, end));
        }
        self.find(haystack, start, end, limits)
            .map(|(matched, _)| matched)
    }

    /// Value-only first-end search. Unlimited calls select the endpoint
    /// representation in the shared branch-minimal executor; finite limits
    /// retain the exact prospective/actual span path before projection.
    pub fn first_end_value(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
        limits: SearchLimits,
    ) -> Result<Option<usize>, SearchError> {
        if start > end || end > haystack.len() {
            return Err(SearchError::InvalidWindow);
        }
        if limits.max_work == u64::MAX {
            return Ok(self.find_from_value::<EndProjection>(haystack, start, end));
        }
        self.find(haystack, start, end, limits)
            .map(|(matched, _)| matched.map(MatchSpan::end))
    }

    /// Value-only existence projection.
    pub fn is_match_value(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        self.first_end_value(haystack, start, end, limits)
            .map(|matched| matched.is_some())
    }

    fn find_from(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
        actual: &mut SearchActual,
    ) -> Result<Option<MatchSpan>, SearchError> {
        // Line starts are the only legal starts and are visited in increasing
        // source order, so the first successful candidate is leftmost-first.
        if start >= end || input_bytes(start, end) < self.minimum_match_bytes {
            return Ok(None);
        }
        let Some(mut candidate) = self.first_line_start(haystack, start, end, actual)? else {
            return Ok(None);
        };
        loop {
            if candidate >= end || input_bytes(candidate, end) < self.minimum_match_bytes {
                return Ok(None);
            }
            actual.charge_candidate()?;
            if let Some(matched_end) = self.match_candidate(haystack, candidate, end, actual)? {
                actual.charge_match()?;
                return Ok(Some(MatchSpan::new(candidate, matched_end)));
            }
            let Some(next) = self.next_line_start(haystack, candidate, end, actual)? else {
                return Ok(None);
            };
            debug_assert!(next > candidate);
            candidate = next;
        }
    }

    fn find_from_value<P: ValueProjection>(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
    ) -> Option<P::Output> {
        if start >= end || input_bytes(start, end) < self.minimum_match_bytes {
            return None;
        }
        if let Some(anchor) = self.value_prefilter.anchor() {
            let candidate = self.first_line_start_value(haystack, start, end)?;
            if candidate >= end || input_bytes(candidate, end) < self.minimum_match_bytes {
                return None;
            }
            if let Some(matched_end) = self.match_candidate_value(haystack, candidate, end) {
                return Some(P::selected(candidate, matched_end));
            }
            // Preserve the delimiter executor's excellent first-line and
            // dense-iteration behavior. Once that unique line start fails, it
            // is safe to begin the bulk candidate source in the next domain.
            return match anchor {
                ValueAnchor::Start { offset } => {
                    let search = candidate.checked_add(offset)?.checked_add(1)?;
                    self.find_from_value_start_prefiltered::<P>(
                        haystack, start, end, offset, search,
                    )
                }
                ValueAnchor::End { trailing } => {
                    let search = self.next_line_start_value(haystack, candidate, end)?;
                    self.find_from_value_end_prefiltered::<P>(
                        haystack, start, end, trailing, search,
                    )
                }
            };
        }
        if self.uses_fixed_width_endpoint() {
            return self.find_from_value_fixed_width::<P>(
                haystack,
                start,
                end,
                self.minimum_match_bytes,
            );
        }
        let mut candidate = self.first_line_start_value(haystack, start, end)?;
        loop {
            if candidate >= end || input_bytes(candidate, end) < self.minimum_match_bytes {
                return None;
            }
            if let Some(matched_end) = self.match_candidate_value(haystack, candidate, end) {
                return Some(P::selected(candidate, matched_end));
            }
            candidate = self.next_line_start_value(haystack, candidate, end)?;
        }
    }

    fn uses_fixed_width_endpoint(&self) -> bool {
        self.fixed_width_endpoint
    }

    fn find_from_value_fixed_width<P: ValueProjection>(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
        width: usize,
    ) -> Option<P::Output> {
        // Preserve the generic executor's immediate-hit path. After a miss,
        // a false projected endpoint proves that this fixed-width candidate
        // cannot match without reading its body. A true endpoint is only
        // provisional because it may belong to a later line; validate it, and
        // permanently resume the generic executor after the first false
        // positive so exact-width workloads do not pay one probe per line.
        let mut candidate = self.first_line_start_value(haystack, start, end)?;
        if candidate >= end || input_bytes(candidate, end) < width {
            return None;
        }
        if let Some(matched_end) = self.match_candidate_value(haystack, candidate, end) {
            return Some(P::selected(candidate, matched_end));
        }
        let expected_end = candidate.checked_add(width)?;
        let exact_width = self.is_line_end_value(haystack, expected_end);
        candidate = self.next_line_start_value(haystack, candidate, end)?;
        if exact_width {
            return self.find_from_value_none_after_candidate::<P>(haystack, candidate, end);
        }

        loop {
            if candidate >= end || input_bytes(candidate, end) < width {
                return None;
            }
            let expected_end = candidate.checked_add(width)?;
            if self.is_line_end_value(haystack, expected_end) {
                if let Some(matched_end) =
                    self.match_candidate_value(haystack, candidate, end)
                {
                    return Some(P::selected(candidate, matched_end));
                }
                candidate = self.next_line_start_value(haystack, candidate, end)?;
                return self.find_from_value_none_after_candidate::<P>(haystack, candidate, end);
            }
            candidate = self.next_line_start_value(haystack, candidate, end)?;
        }
    }

    fn find_from_value_none_after_candidate<P: ValueProjection>(
        &self,
        haystack: &[u8],
        mut candidate: usize,
        end: usize,
    ) -> Option<P::Output> {
        loop {
            if candidate >= end || input_bytes(candidate, end) < self.minimum_match_bytes {
                return None;
            }
            if let Some(matched_end) = self.match_candidate_value(haystack, candidate, end) {
                return Some(P::selected(candidate, matched_end));
            }
            candidate = self.next_line_start_value(haystack, candidate, end)?;
        }
    }

    fn find_from_value_start_prefiltered<P: ValueProjection>(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
        offset: usize,
        mut search: usize,
    ) -> Option<P::Output> {
        while search < end {
            let relative = self.value_prefilter.find(haystack.get(search..end)?)?;
            let anchor = search.checked_add(relative)?;
            let candidate = anchor.checked_sub(offset)?;
            if candidate >= start
                && self.is_line_start_value(haystack, candidate)
                && input_bytes(candidate, end) >= self.minimum_match_bytes
                && let Some(matched_end) =
                    self.match_candidate_value(haystack, candidate, end)
            {
                return Some(P::selected(candidate, matched_end));
            }

            // A line-anchored expression has at most one candidate in this
            // domain. Whether the occurrence mapped to its start or into its
            // interior, a failed validation proves that the remainder of this
            // line cannot yield another match. This also prevents dense anchor
            // bytes from degenerating into one boundary check per source byte.
            let next = self.next_line_start_value(haystack, candidate, end)?;
            search = next.checked_add(offset)?;
        }
        None
    }

    fn find_from_value_end_prefiltered<P: ValueProjection>(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
        trailing: usize,
        mut search: usize,
    ) -> Option<P::Output> {
        let needle_width = self.value_prefilter.needle_width()?;
        let suffix_width = trailing.checked_add(needle_width)?;
        while search < end {
            let relative = self.value_prefilter.find(haystack.get(search..end)?)?;
            let occurrence = search.checked_add(relative)?;
            let (line_end, next_line_start) =
                self.line_end_after_value(haystack, occurrence, end)?;
            let candidate = self.line_start_for_end_value(haystack, line_end);

            if let Some(candidate) = candidate.filter(|candidate| *candidate >= start) {
                let line_width = line_end.checked_sub(candidate)?;
                if line_width >= self.minimum_match_bytes
                    && line_width <= self.maximum_match_bytes
                    && let Some(slot) = line_end.checked_sub(suffix_width)
                    && slot >= candidate
                    && self.value_prefilter.matches_at(haystack, slot)
                    && self.match_candidate_value(haystack, candidate, line_end)
                        == Some(line_end)
                {
                    return Some(P::selected(candidate, line_end));
                }
            }

            // The occurrence only discovers a semantic line. Probing the
            // unique end-relative slot above proves whether that line can
            // match, so dense or misaligned occurrences are discarded one
            // complete line at a time rather than one source byte at a time.
            search = next_line_start?;
        }
        None
    }

    fn line_end_after_value(
        &self,
        haystack: &[u8],
        occurrence: usize,
        window_end: usize,
    ) -> Option<(usize, Option<usize>)> {
        // A match span may end exactly at `window_end` while its assertion
        // reads the delimiter at that index. Include that one source byte in
        // delimiter discovery without admitting any body byte beyond the
        // window.
        let scan_end = if window_end < haystack.len() {
            window_end.checked_add(1)?
        } else {
            window_end
        };
        let searched = haystack.get(occurrence..scan_end)?;
        let relative = match self.line_mode {
            LineMode::Lf { terminator } => memchr(terminator, searched),
            LineMode::Crlf => memchr2(b'\r', b'\n', searched),
        };
        let Some(relative) = relative else {
            return (window_end == haystack.len()).then_some((window_end, None));
        };
        let line_end = occurrence.checked_add(relative)?;
        let following = line_end.checked_add(1)?;
        let next = match self.line_mode {
            LineMode::Crlf
                if haystack[line_end] == b'\r'
                    && following < haystack.len()
                    && haystack[following] == b'\n' => following.checked_add(1)?,
            LineMode::Lf { .. } | LineMode::Crlf => following,
        };
        Some((line_end, (next <= window_end).then_some(next)))
    }

    fn line_start_for_end_value(&self, haystack: &[u8], line_end: usize) -> Option<usize> {
        // Any matching line is at most the certified maximum width. Restrict
        // reverse delimiter recovery to that suffix so a selective hit in a
        // huge rejected line does not rescan the whole line prefix.
        let lower = line_end.saturating_sub(self.maximum_match_bytes);
        let searched = haystack.get(lower..line_end)?;
        let relative = match self.line_mode {
            LineMode::Lf { terminator } => memrchr(terminator, searched),
            LineMode::Crlf => memrchr2(b'\r', b'\n', searched),
        };
        if let Some(relative) = relative {
            let delimiter = lower.checked_add(relative)?;
            let following = delimiter.checked_add(1)?;
            return match self.line_mode {
                LineMode::Crlf
                    if haystack[delimiter] == b'\r'
                        && following < line_end
                        && haystack[following] == b'\n' => following.checked_add(1),
                LineMode::Lf { .. } | LineMode::Crlf => Some(following),
            };
        }
        self.is_line_start_value(haystack, lower).then_some(lower)
    }

    fn first_line_start(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
        actual: &mut SearchActual,
    ) -> Result<Option<usize>, SearchError> {
        if self.is_line_start(haystack, start, actual)? {
            return Ok(Some(start));
        }
        self.next_line_start(haystack, start, end, actual)
    }

    fn first_line_start_value(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
    ) -> Option<usize> {
        if self.is_line_start_value(haystack, start) {
            return Some(start);
        }
        self.next_line_start_value(haystack, start, end)
    }

    fn is_line_start(
        &self,
        haystack: &[u8],
        position: usize,
        actual: &mut SearchActual,
    ) -> Result<bool, SearchError> {
        // StartCRLF is true at offset zero, after LF, and after a lone CR,
        // but false between the bytes of a CRLF pair.
        actual.charge_boundary()?;
        if position == 0 {
            return Ok(true);
        }
        let before = actual.read(haystack, position.saturating_sub(1))?;
        match self.line_mode {
            LineMode::Lf { terminator } => Ok(before == terminator),
            LineMode::Crlf if before == b'\n' => Ok(true),
            LineMode::Crlf if before == b'\r' => {
                if position == haystack.len() {
                    Ok(true)
                } else {
                    Ok(actual.read(haystack, position)? != b'\n')
                }
            }
            LineMode::Crlf => Ok(false),
        }
    }

    fn is_line_start_value(&self, haystack: &[u8], position: usize) -> bool {
        if position == 0 {
            return true;
        }
        let before = haystack[position.saturating_sub(1)];
        match self.line_mode {
            LineMode::Lf { terminator } => before == terminator,
            LineMode::Crlf if before == b'\n' => true,
            LineMode::Crlf if before == b'\r' => {
                position == haystack.len() || haystack[position] != b'\n'
            }
            LineMode::Crlf => false,
        }
    }

    fn is_line_end(
        &self,
        haystack: &[u8],
        position: usize,
        actual: &mut SearchActual,
    ) -> Result<bool, SearchError> {
        // EndCRLF is true at source end, before CR, and before a lone LF,
        // but false between the bytes of a CRLF pair.
        actual.charge_boundary()?;
        if position == haystack.len() {
            return Ok(true);
        }
        let after = actual.read(haystack, position)?;
        match self.line_mode {
            LineMode::Lf { terminator } => Ok(after == terminator),
            LineMode::Crlf if after == b'\r' => Ok(true),
            LineMode::Crlf if after == b'\n' => {
                if position == 0 {
                    Ok(true)
                } else {
                    Ok(actual.read(haystack, position.saturating_sub(1))? != b'\r')
                }
            }
            LineMode::Crlf => Ok(false),
        }
    }

    fn is_line_end_value(&self, haystack: &[u8], position: usize) -> bool {
        if position == haystack.len() {
            return true;
        }
        match self.line_mode {
            LineMode::Lf { terminator } => haystack[position] == terminator,
            LineMode::Crlf if haystack[position] == b'\r' => true,
            LineMode::Crlf if haystack[position] == b'\n' => {
                position == 0 || haystack[position.saturating_sub(1)] != b'\r'
            }
            LineMode::Crlf => false,
        }
    }

    fn next_line_start(
        &self,
        haystack: &[u8],
        position: usize,
        end: usize,
        actual: &mut SearchActual,
    ) -> Result<Option<usize>, SearchError> {
        let Some(searched) = haystack.get(position..end) else {
            return Err(SearchError::InternalInvariant {
                detail: "certified delimiter scan range was out of bounds",
            });
        };
        let relative = match self.line_mode {
            LineMode::Lf { terminator } => memchr(terminator, searched),
            LineMode::Crlf => memchr2(b'\r', b'\n', searched),
        };
        let scanned = relative.map_or(searched.len(), |index| index.saturating_add(1));
        actual.charge_delimiter_scan(scanned)?;
        let Some(relative) = relative else {
            return Ok(None);
        };
        let delimiter = position
            .checked_add(relative)
            .ok_or(SearchError::ArithmeticOverflow {
                counter: "delimiter position",
            })?;
        let following = delimiter
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                counter: "delimiter successor",
            })?;
        let next = match self.line_mode {
            LineMode::Lf { .. } => following,
            LineMode::Crlf if haystack[delimiter] == b'\n' => following,
            LineMode::Crlf => {
                if following < haystack.len() && actual.read(haystack, following)? == b'\n' {
                    following
                        .checked_add(1)
                        .ok_or(SearchError::ArithmeticOverflow {
                            counter: "CRLF successor",
                        })?
                } else {
                    following
                }
            }
        };
        Ok((next <= end).then_some(next))
    }

    fn next_line_start_value(
        &self,
        haystack: &[u8],
        position: usize,
        end: usize,
    ) -> Option<usize> {
        let searched = haystack.get(position..end)?;
        let relative = match self.line_mode {
            LineMode::Lf { terminator } => memchr(terminator, searched),
            LineMode::Crlf => memchr2(b'\r', b'\n', searched),
        }?;
        let delimiter = position.checked_add(relative)?;
        let following = delimiter.checked_add(1)?;
        let next = match self.line_mode {
            LineMode::Lf { .. } => following,
            LineMode::Crlf if haystack[delimiter] == b'\n' => following,
            LineMode::Crlf => {
                if following < haystack.len() && haystack[following] == b'\n' {
                    following.checked_add(1)?
                } else {
                    following
                }
            }
        };
        (next <= end).then_some(next)
    }

    fn match_candidate(
        &self,
        haystack: &[u8],
        start: usize,
        window_end: usize,
        actual: &mut SearchActual,
    ) -> Result<Option<usize>, SearchError> {
        // Each variable nonterminal mask is disjoint from its successor's
        // first-byte mask. The first successor byte therefore ends the greedy
        // run uniquely; a terminal run can only succeed at the asserted line
        // end. No backtracking state is needed.
        let mut position = start;
        for atom in self.atoms().iter().copied() {
            let minimum = usize::try_from(atom.minimum()).map_err(|_| {
                SearchError::ArithmeticOverflow {
                    counter: "minimum atom width",
                }
            })?;
            let maximum = usize::try_from(
                atom.maximum()
                    .expect("construction rejects unbounded line-domain atoms"),
            )
            .map_err(|_| SearchError::ArithmeticOverflow {
                counter: "maximum atom width",
            })?;
            let mut consumed = 0_usize;
            while consumed < maximum && position < window_end {
                actual.charge_atom_probe()?;
                let byte = actual.read(haystack, position)?;
                if !atom.mask().contains(byte) {
                    break;
                }
                position = position.saturating_add(1);
                consumed = consumed.saturating_add(1);
            }
            if consumed < minimum {
                return Ok(None);
            }
            actual.charge_atom_transition()?;
        }
        if self.is_line_end(haystack, position, actual)? {
            Ok(Some(position))
        } else {
            Ok(None)
        }
    }

    fn match_candidate_value(
        &self,
        haystack: &[u8],
        start: usize,
        window_end: usize,
    ) -> Option<usize> {
        let mut position = start;
        for atom in self.atoms().iter().copied() {
            let minimum = usize::try_from(atom.minimum()).ok()?;
            let maximum = usize::try_from(atom.maximum()?).ok()?;
            let mut consumed = 0_usize;
            while consumed < maximum
                && position < window_end
                && atom.mask().contains(haystack[position])
            {
                position = position.saturating_add(1);
                consumed = consumed.saturating_add(1);
            }
            if consumed < minimum {
                return None;
            }
        }
        self.is_line_end_value(haystack, position).then_some(position)
    }
}

fn charge_build(work: &mut u64, amount: u64, limit: u64) -> Result<(), BuildError> {
    let needed = checked_build_work_add(*work, amount)?;
    if needed > limit {
        return Err(BuildError::WorkLimit { needed, limit });
    }
    *work = needed;
    Ok(())
}

fn checked_build_work_add(work: u64, amount: u64) -> Result<u64, BuildError> {
    work.checked_add(amount)
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "construction work",
        })
}

fn charge_retained_prefilter_bytes(
    work: &mut u64,
    retained: usize,
    limit: u64,
) -> Result<(), BuildError> {
    let retained = u64::try_from(retained).map_err(|_| BuildError::ArithmeticOverflow {
        computation: "retained prefilter bytes",
    })?;
    charge_build(
        work,
        retained
            .checked_mul(BUILD_PREFILTER_RETAINED_BYTE_WORK)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "retained prefilter work",
            })?,
        limit,
    )
}

fn retain_mask_members(mask: ByteMask, output: &mut [u8]) -> usize {
    let mut retained = 0_usize;
    for (word_index, mut word) in mask.words().into_iter().enumerate() {
        while word != 0 {
            let bit = usize::try_from(word.trailing_zeros())
                .expect("one mask-word bit index fits usize");
            let byte = word_index
                .checked_mul(usize::try_from(u64::BITS).expect("u64 bit width fits usize"))
                .and_then(|base| base.checked_add(bit))
                .and_then(|value| u8::try_from(value).ok())
                .expect("one mask member fits u8");
            if let Some(slot) = output.get_mut(retained) {
                *slot = byte;
            }
            retained = retained
                .checked_add(1)
                .expect("one byte-mask cardinality fits usize");
            word &= word.saturating_sub(1);
        }
    }
    retained
}

#[inline]
fn find_byte_set4(members: [u8; 4], haystack: &[u8]) -> Option<usize> {
    if members.contains(haystack.first()?) {
        return Some(0);
    }
    let complete_len = haystack
        .len()
        .checked_sub(haystack.len() % BYTE_SET_WIDE_BLOCK_BYTES)?;
    for (block_index, block) in haystack[..complete_len]
        .chunks_exact(BYTE_SET_WIDE_BLOCK_BYTES)
        .enumerate()
    {
        let block = <&[u8; BYTE_SET_WIDE_BLOCK_BYTES]>::try_from(block).ok()?;
        let mask = classify_byte_set4_32(members, block).member_mask();
        if mask != 0 {
            let block_start = block_index.checked_mul(BYTE_SET_WIDE_BLOCK_BYTES)?;
            let lane = usize::try_from(mask.trailing_zeros()).ok()?;
            return block_start.checked_add(lane);
        }
    }
    haystack[complete_len..]
        .iter()
        .position(|byte| members.contains(byte))
        .and_then(|relative| complete_len.checked_add(relative))
}

const fn input_bytes(start: usize, end: usize) -> usize {
    end.saturating_sub(start)
}

/// Search projection represented by an accounting receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    /// Existence only.
    Exists,
    /// First detected end. Exact line domains have the same first span.
    EarliestEnd,
    /// End of the selected leftmost-first span.
    SelectedEnd,
    /// Selected leftmost-first span.
    Span,
    /// Monotone non-overlapping span iteration.
    Iterate,
}

/// Per-invocation execution ceilings accepted before source access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchLimits {
    /// Maximum complete prospective work.
    pub max_work: u64,
}

impl SearchLimits {
    /// No work ceiling.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self { max_work: u64::MAX }
    }
}

impl Default for SearchLimits {
    fn default() -> Self {
        Self { max_work: 100_000_000 }
    }
}

/// Complete source-independent execution envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchUpperBounds {
    pub input_bytes: usize,
    pub source_reads: u64,
    pub delimiter_steps: u64,
    pub atom_probes: u64,
    pub atom_transitions: u64,
    pub boundary_checks: u64,
    pub candidate_events: u64,
    pub match_events: u64,
    pub work: u64,
    pub allocations: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
}

impl SearchUpperBounds {
    /// Whether one exact execution receipt stays within this envelope.
    #[must_use]
    pub fn contains(self, actual: SearchActual) -> bool {
        actual.input_bytes == self.input_bytes
            && actual.source_reads <= self.source_reads
            && actual.delimiter_steps <= self.delimiter_steps
            && actual.atom_probes <= self.atom_probes
            && actual.atom_transitions <= self.atom_transitions
            && actual.boundary_checks <= self.boundary_checks
            && actual.candidate_events <= self.candidate_events
            && actual.match_events <= self.match_events
            && actual.work <= self.work
            && actual.allocations == 0
            && actual.scratch_bytes == 0
            && actual.persistent_bytes == self.persistent_bytes
    }
}

/// Exact counters through the current cursor position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchActual {
    pub input_bytes: usize,
    pub source_reads: u64,
    pub delimiter_steps: u64,
    pub atom_probes: u64,
    pub atom_transitions: u64,
    pub boundary_checks: u64,
    pub candidate_events: u64,
    pub match_events: u64,
    pub work: u64,
    pub allocations: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
}

impl SearchActual {
    const fn new(input_bytes: usize) -> Self {
        Self {
            input_bytes,
            source_reads: 0,
            delimiter_steps: 0,
            atom_probes: 0,
            atom_transitions: 0,
            boundary_checks: 0,
            candidate_events: 0,
            match_events: 0,
            work: 0,
            allocations: 0,
            scratch_bytes: 0,
            persistent_bytes: size_of::<LineDomainPlan>(),
        }
    }

    fn charge(&mut self, counter: &'static str) -> Result<(), SearchError> {
        self.work = self
            .work
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow { counter })?;
        Ok(())
    }

    fn read(&mut self, haystack: &[u8], index: usize) -> Result<u8, SearchError> {
        self.source_reads = self.source_reads.checked_add(1).ok_or(
            SearchError::ArithmeticOverflow {
                counter: "source read",
            },
        )?;
        self.charge("work")?;
        haystack
            .get(index)
            .copied()
            .ok_or(SearchError::InternalInvariant {
                detail: "certified line-domain source read was out of bounds",
            })
    }

    fn charge_delimiter_scan(&mut self, scanned: usize) -> Result<(), SearchError> {
        let scanned = u64::try_from(scanned).map_err(|_| SearchError::ArithmeticOverflow {
            counter: "delimiter scan length",
        })?;
        self.delimiter_steps = self.delimiter_steps.checked_add(scanned).ok_or(
            SearchError::ArithmeticOverflow {
                counter: "delimiter step",
            },
        )?;
        self.source_reads = self.source_reads.checked_add(scanned).ok_or(
            SearchError::ArithmeticOverflow {
                counter: "delimiter source read",
            },
        )?;
        let work = scanned
            .checked_mul(2)
            .ok_or(SearchError::ArithmeticOverflow {
                counter: "delimiter scan work",
            })?;
        self.work = self
            .work
            .checked_add(work)
            .ok_or(SearchError::ArithmeticOverflow {
                counter: "delimiter scan work",
            })?;
        Ok(())
    }

    fn charge_atom_probe(&mut self) -> Result<(), SearchError> {
        self.atom_probes = self.atom_probes.checked_add(1).ok_or(
            SearchError::ArithmeticOverflow {
                counter: "atom probe",
            },
        )?;
        self.charge("work")
    }

    fn charge_atom_transition(&mut self) -> Result<(), SearchError> {
        self.atom_transitions = self.atom_transitions.checked_add(1).ok_or(
            SearchError::ArithmeticOverflow {
                counter: "atom transition",
            },
        )?;
        self.charge("work")
    }

    fn charge_boundary(&mut self) -> Result<(), SearchError> {
        self.boundary_checks = self.boundary_checks.checked_add(1).ok_or(
            SearchError::ArithmeticOverflow {
                counter: "boundary check",
            },
        )?;
        self.charge("work")
    }

    fn charge_candidate(&mut self) -> Result<(), SearchError> {
        self.candidate_events = self.candidate_events.checked_add(1).ok_or(
            SearchError::ArithmeticOverflow {
                counter: "candidate event",
            },
        )?;
        self.charge("work")
    }

    fn charge_match(&mut self) -> Result<(), SearchError> {
        self.match_events = self.match_events.checked_add(1).ok_or(
            SearchError::ArithmeticOverflow {
                counter: "match event",
            },
        )?;
        self.charge("work")
    }
}

/// Complete receipt for one first-match call or cursor prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchAccounting {
    pub plan_id: &'static str,
    pub line_mode: LineMode,
    pub operation: Operation,
    pub window_start: usize,
    pub window_end: usize,
    pub upper_bounds: SearchUpperBounds,
    pub actual: SearchActual,
}

/// Search failure before publication of a result or receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SearchError {
    InvalidWindow,
    WorkLimit { needed: u64, limit: u64 },
    ArithmeticOverflow { counter: &'static str },
    InternalInvariant { detail: &'static str },
}

impl fmt::Display for SearchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidWindow => formatter.write_str("invalid line-domain search window"),
            Self::WorkLimit { needed, limit } => write!(
                formatter,
                "line-domain search needs work {needed}, exceeding {limit}"
            ),
            Self::ArithmeticOverflow { counter } => {
                write!(formatter, "line-domain {counter} counter overflowed")
            }
            Self::InternalInvariant { detail } => {
                write!(formatter, "line-domain internal invariant: {detail}")
            }
        }
    }
}

impl std::error::Error for SearchError {}

/// Monotone cursor for exact non-overlapping iteration and `find_at` reuse.
#[derive(Debug)]
pub struct Cursor<'plan, 'haystack> {
    plan: &'plan LineDomainPlan,
    haystack: &'haystack [u8],
    window_start: usize,
    window_end: usize,
    next_start: usize,
    upper_bounds: SearchUpperBounds,
    actual: SearchActual,
    finished: bool,
}

impl Cursor<'_, '_> {
    /// Return the next positive-width line match.
    pub fn next_match(&mut self) -> Result<Option<MatchSpan>, SearchError> {
        if self.finished {
            return Ok(None);
        }
        let matched = self.plan.find_from(
            self.haystack,
            self.next_start,
            self.window_end,
            &mut self.actual,
        )?;
        match matched {
            Some(span) => {
                debug_assert!(span.end() > self.next_start);
                self.next_start = span.end();
            }
            None => self.finished = true,
        }
        if !self.upper_bounds.contains(self.actual) {
            return Err(SearchError::InternalInvariant {
                detail: "line-domain cursor accounting exceeded its admitted envelope",
            });
        }
        Ok(matched)
    }

    /// Exact cumulative accounting through the most recent cursor action.
    #[must_use]
    pub const fn accounting(&self, operation: Operation) -> SearchAccounting {
        SearchAccounting {
            plan_id: PLAN_ID,
            line_mode: self.plan.line_mode,
            operation,
            window_start: self.window_start,
            window_end: self.window_end,
            upper_bounds: self.upper_bounds,
            actual: self.actual,
        }
    }

    /// Whether the cursor has proved exhaustion.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.finished
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LF: LineMode = LineMode::Lf { terminator: b'\n' };

    fn mask(ranges: &[(u8, u8)]) -> ByteMask {
        let mut mask = ByteMask::empty();
        for &(start, end) in ranges {
            mask.insert_range(start, end).unwrap();
        }
        mask
    }

    fn word_plan(mode: LineMode) -> LineDomainPlan {
        let atoms = [
            Atom::new(mask(&[(b'A', b'Z')]), 1, Some(1)),
            Atom::new(mask(&[(b'a', b'z')]), 2, Some(8)),
        ];
        LineDomainPlan::new(mode, &atoms, BuildLimits::default())
            .unwrap()
            .0
    }

    fn tuple(span: Option<MatchSpan>) -> Option<(usize, usize)> {
        span.map(|span| (span.start(), span.end()))
    }

    fn identity_words(plan: &LineDomainPlan) -> Vec<u64> {
        let mut words = Vec::new();
        plan.visit_identity_words(|word| words.push(word));
        words
    }

    #[test]
    fn construction_seals_terminators_and_greedy_boundaries() {
        let letters = mask(&[(b'a', b'z')]);
        let newline = mask(&[(b'\n', b'\n')]);
        assert!(matches!(
            LineDomainPlan::new(
                LF,
                &[Atom::new(newline, 1, Some(1))],
                BuildLimits::default()
            ),
            Err(BuildError::TerminatorInBody {
                atom: 0,
                mode: LineMode::Lf { terminator: b'\n' },
            })
        ));
        assert!(matches!(
            LineDomainPlan::new(
                LF,
                &[
                    Atom::new(letters, 2, Some(8)),
                    Atom::new(letters, 1, Some(1)),
                ],
                BuildLimits::default()
            ),
            Err(BuildError::AmbiguousGreedyBoundary { atom: 0 })
        ));
        assert!(matches!(
            LineDomainPlan::new(
                LineMode::Crlf,
                &[Atom::new(mask(&[(b'\r', b'\r')]), 1, Some(1))],
                BuildLimits::default()
            ),
            Err(BuildError::TerminatorInBody { atom: 0, mode: LineMode::Crlf })
        ));
    }

    #[test]
    fn construction_refuses_zero_work_before_atom_inspection() {
        let error = LineDomainPlan::new(
            LF,
            &[Atom::new(mask(&[(b'a', b'z')]), 1, Some(1))],
            BuildLimits {
                max_work: 0,
                ..BuildLimits::default()
            },
        )
        .expect_err("the fixed construction unit must be admitted explicitly");
        assert_eq!(error, BuildError::WorkLimit { needed: 1, limit: 0 });
    }

    #[test]
    fn value_prefilter_retains_longest_fixed_literal_or_smallest_fixed_set() {
        let literal_atoms = [
            Atom::new(ByteMask::singleton(b'A'), 1, Some(1)),
            Atom::new(ByteMask::singleton(b'b'), 3, Some(3)),
            Atom::new(mask(&[(b'0', b'9')]), 1, Some(1)),
        ];
        let literal = LineDomainPlan::new(LF, &literal_atoms, BuildLimits::default())
            .unwrap()
            .0;
        let ValuePrefilter::Literal { anchor, len, bytes } = &literal.value_prefilter else {
            panic!("a fixed singleton run must retain a literal");
        };
        assert_eq!((*anchor, *len), (ValueAnchor::Start { offset: 0 }, 4));
        assert_eq!(&bytes[..*len], b"Abbb");

        let set_atoms = [
            Atom::new(mask(&[(b'A', b'Z')]), 1, Some(1)),
            Atom::new(mask(&[(b'0', b'3')]), 1, Some(1)),
            Atom::new(mask(&[(b'_', b'_'), (b'-', b'-')]), 1, Some(1)),
        ];
        let set = LineDomainPlan::new(LF, &set_atoms, BuildLimits::default())
            .unwrap()
            .0;
        let ValuePrefilter::SmallSet { anchor, len, bytes } = &set.value_prefilter else {
            panic!("the smallest fixed byte set must be retained");
        };
        assert_eq!((*anchor, *len), (ValueAnchor::Start { offset: 2 }, 2));
        assert_eq!(&bytes[..*len], b"-_");

        let variable = LineDomainPlan::new(
            LF,
            &[Atom::new(ByteMask::singleton(b'a'), 2, Some(32))],
            BuildLimits::default(),
        )
        .unwrap()
        .0;
        let ValuePrefilter::Literal { anchor, len, bytes } = &variable.value_prefilter else {
            panic!("the mandatory prefix of a leading variable singleton is exact");
        };
        assert_eq!((*anchor, *len), (ValueAnchor::Start { offset: 0 }, 2));
        assert_eq!(&bytes[..*len], b"aa");
    }

    #[test]
    fn value_prefilter_selects_stronger_end_literal_or_set_after_variable_prefix() {
        let literal_atoms = [
            Atom::new(mask(&[(b'a', b'z')]), 1, Some(8)),
            Atom::new(ByteMask::singleton(b'E'), 1, Some(1)),
            Atom::new(ByteMask::singleton(b'N'), 1, Some(1)),
            Atom::new(ByteMask::singleton(b'D'), 1, Some(1)),
            Atom::new(mask(&[(b'0', b'9')]), 1, Some(1)),
        ];
        let (literal, literal_build) =
            LineDomainPlan::new(LF, &literal_atoms, BuildLimits::default()).unwrap();
        let projected_prefilter =
            LineDomainPlan::projected_value_prefilter_build_work(&literal_atoms).unwrap();
        let base_work = 1_u64
            .checked_add(u64::try_from(literal_atoms.len()).unwrap().checked_mul(2).unwrap())
            .and_then(|work| work.checked_add(4))
            .unwrap();
        assert_eq!(literal_build.work, base_work + projected_prefilter);
        let ValuePrefilter::Literal { anchor, len, bytes } = &literal.value_prefilter else {
            panic!("the fixed suffix after a broad variable prefix must retain a literal");
        };
        assert_eq!((*anchor, *len), (ValueAnchor::End { trailing: 1 }, 3));
        assert_eq!(&bytes[..*len], b"END");

        let set_atoms = [
            Atom::new(mask(&[(b'a', b'z')]), 1, Some(8)),
            Atom::new(mask(&[(b'-', b'-'), (b'_', b'_')]), 1, Some(1)),
        ];
        let set = LineDomainPlan::new(LF, &set_atoms, BuildLimits::default())
            .unwrap()
            .0;
        let ValuePrefilter::SmallSet { anchor, len, bytes } = &set.value_prefilter else {
            panic!("the fixed suffix after a broad variable prefix must retain a small set");
        };
        assert_eq!((*anchor, *len), (ValueAnchor::End { trailing: 0 }, 2));
        assert_eq!(&bytes[..*len], b"-_");

        let exact_limits = BuildLimits {
            max_work: literal_build.work,
            ..BuildLimits::default()
        };
        let exact_build = LineDomainPlan::new(LF, &literal_atoms, exact_limits)
            .unwrap()
            .1;
        assert_eq!(exact_build.work, literal_build.work);
        assert!(matches!(
            LineDomainPlan::new(
                LF,
                &literal_atoms,
                BuildLimits {
                    max_work: literal_build.work.saturating_sub(1),
                    ..BuildLimits::default()
                },
            ),
            Err(BuildError::WorkLimit { needed, limit })
                if needed == literal_build.work && limit == literal_build.work.saturating_sub(1)
        ));
    }

    #[test]
    fn fixed_width_endpoint_gate_admits_only_amortizable_unfiltered_plans() {
        let broad = mask(&[(b'0', b'9'), (b'A', b'Z')]);
        let narrow_width = u32::try_from(FIXED_WIDTH_ENDPOINT_MIN_BYTES - 1).unwrap();
        let admitted_width = u32::try_from(FIXED_WIDTH_ENDPOINT_MIN_BYTES).unwrap();
        let block_width = u32::try_from(BYTE_SET_WIDE_BLOCK_BYTES).unwrap();

        let narrow = LineDomainPlan::new(
            LF,
            &[Atom::new(broad, narrow_width, Some(narrow_width))],
            BuildLimits::default(),
        )
        .unwrap()
        .0;
        assert!(matches!(narrow.value_prefilter, ValuePrefilter::None));
        assert!(!narrow.uses_fixed_width_endpoint());

        let variable = LineDomainPlan::new(
            LF,
            &[Atom::new(
                broad,
                admitted_width,
                Some(admitted_width + 1),
            )],
            BuildLimits::default(),
        )
        .unwrap()
        .0;
        assert!(matches!(variable.value_prefilter, ValuePrefilter::None));
        assert!(!variable.uses_fixed_width_endpoint());

        let literal = LineDomainPlan::new(
            LF,
            &[Atom::new(
                ByteMask::singleton(b'A'),
                admitted_width,
                Some(admitted_width),
            )],
            BuildLimits::default(),
        )
        .unwrap()
        .0;
        assert!(matches!(
            literal.value_prefilter,
            ValuePrefilter::Literal { .. }
        ));
        assert!(!literal.uses_fixed_width_endpoint());

        let small_set = LineDomainPlan::new(
            LF,
            &[Atom::new(
                mask(&[(b'A', b'B')]),
                admitted_width,
                Some(admitted_width),
            )],
            BuildLimits::default(),
        )
        .unwrap()
        .0;
        assert!(matches!(
            small_set.value_prefilter,
            ValuePrefilter::SmallSet { .. }
        ));
        assert!(!small_set.uses_fixed_width_endpoint());

        let admitted_atoms = [
            Atom::new(broad, block_width, Some(block_width)),
            Atom::new(broad, block_width, Some(block_width)),
        ];
        let (admitted, build) =
            LineDomainPlan::new(LF, &admitted_atoms, BuildLimits::default()).unwrap();
        assert!(matches!(admitted.value_prefilter, ValuePrefilter::None));
        assert!(admitted.uses_fixed_width_endpoint());
        assert_eq!(
            admitted.minimum_match_bytes,
            FIXED_WIDTH_ENDPOINT_MIN_BYTES
        );
        assert_eq!(build.plan_id, PLAN_ID);
        assert_eq!(build.persistent_bytes, size_of::<LineDomainPlan>());
        let projected =
            LineDomainPlan::projected_value_prefilter_build_work(&admitted_atoms).unwrap();
        assert_eq!(
            build.work,
            1 + 2 * u64::try_from(admitted_atoms.len()).unwrap() + projected
        );

        let exact_limits = BuildLimits {
            max_work: build.work,
            max_persistent_bytes: build.persistent_bytes,
            ..BuildLimits::default()
        };
        let exact_build = LineDomainPlan::new(LF, &admitted_atoms, exact_limits)
            .unwrap()
            .1;
        assert_eq!(exact_build, build);
        assert!(matches!(
            LineDomainPlan::new(
                LF,
                &admitted_atoms,
                BuildLimits {
                    max_work: build.work - 1,
                    ..BuildLimits::default()
                },
            ),
            Err(BuildError::WorkLimit { needed, limit })
                if needed == build.work && limit == build.work - 1
        ));
        assert!(matches!(
            LineDomainPlan::new(
                LF,
                &admitted_atoms,
                BuildLimits {
                    max_persistent_bytes: build.persistent_bytes - 1,
                    ..BuildLimits::default()
                },
            ),
            Err(BuildError::PersistentBytesLimit { needed, limit })
                if needed == build.persistent_bytes && limit == build.persistent_bytes - 1
        ));
    }

    #[test]
    fn fixed_width_domain_gate_matches_accounted_reference_for_every_window_and_line_mode() {
        let broad = mask(&[(b'0', b'9'), (b'A', b'Z')]);
        let width = FIXED_WIDTH_ENDPOINT_MIN_BYTES;
        let width_u32 = u32::try_from(width).unwrap();
        let block_width = u32::try_from(BYTE_SET_WIDE_BLOCK_BYTES).unwrap();
        let valid = vec![b'A'; width];

        let mut lf = valid.clone();
        lf[width - 1] = b'!';
        lf.push(b'\n');
        lf.extend_from_slice(&valid);

        let mut pipe = b"!|!|".to_vec();
        pipe.extend(std::iter::repeat_n(b'A', width - 2));
        pipe.push(b'|');
        pipe.extend_from_slice(&valid);

        let mut crlf = b"!\n".to_vec();
        crlf.extend(std::iter::repeat_n(b'A', width - 3));
        crlf.extend_from_slice(b"\r\n");
        let mut exact_invalid = valid.clone();
        exact_invalid[width - 1] = b'!';
        crlf.extend_from_slice(&exact_invalid);
        crlf.extend_from_slice(b"\r\nA\r");
        crlf.extend_from_slice(&valid);
        crlf.push(b'\n');

        let cases = [
            (LF, lf),
            (LineMode::Lf { terminator: b'|' }, pipe),
            (LineMode::Crlf, crlf),
        ];
        let one_atom = [Atom::new(broad, width_u32, Some(width_u32))];
        let two_atoms = [
            Atom::new(broad, block_width, Some(block_width)),
            Atom::new(broad, block_width, Some(block_width)),
        ];
        let atom_sets: [&[Atom]; 2] = [&one_atom, &two_atoms];
        for (mode, haystack) in &cases {
            for atoms in atom_sets {
                let plan = LineDomainPlan::new(*mode, atoms, BuildLimits::default())
                    .unwrap()
                    .0;
                assert!(matches!(plan.value_prefilter, ValuePrefilter::None));
                assert!(plan.uses_fixed_width_endpoint());
                assert_eq!(plan.minimum_match_bytes, plan.maximum_match_bytes);
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        let expected = plan
                            .find(haystack, start, end, SearchLimits::unlimited())
                            .unwrap()
                            .0;
                        let actual = plan
                            .find_value(haystack, start, end, SearchLimits::unlimited())
                            .unwrap();
                        let actual_end = plan
                            .first_end_value(haystack, start, end, SearchLimits::unlimited())
                            .unwrap();
                        assert_eq!(actual_end, actual.map(MatchSpan::end));
                        assert_eq!(
                            tuple(actual),
                            tuple(expected),
                            "mode={mode:?}, atoms={}, window={start}..{end}",
                            atoms.len(),
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn end_prefilter_matches_accounted_reference_for_every_window_and_line_mode() {
        let atoms = [
            Atom::new(mask(&[(b'a', b'z')]), 1, Some(3)),
            Atom::new(ByteMask::singleton(b'X'), 1, Some(1)),
        ];
        let cases: &[(LineMode, &[u8])] = &[
            (LF, b"XinsideX\nabcX\nlongXtailX\ncX\n"),
            (
                LineMode::Lf { terminator: b'|' },
                b"XinsideX|abcX|longXtailX|cX|",
            ),
            (
                LineMode::Crlf,
                b"XinsideX\r\nabcX\rlongXtailX\ncX\r\n",
            ),
        ];
        for &(mode, haystack) in cases {
            let plan = LineDomainPlan::new(mode, &atoms, BuildLimits::default())
                .unwrap()
                .0;
            assert!(matches!(
                &plan.value_prefilter,
                ValuePrefilter::Literal {
                    anchor: ValueAnchor::End { trailing: 0 },
                    len: 1,
                    ..
                }
            ));
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let expected = plan
                        .find(haystack, start, end, SearchLimits::unlimited())
                        .unwrap()
                        .0;
                    let actual = plan
                        .find_value(haystack, start, end, SearchLimits::unlimited())
                        .unwrap();
                    let actual_end = plan
                        .first_end_value(haystack, start, end, SearchLimits::unlimited())
                        .unwrap();
                    assert_eq!(actual_end, actual.map(MatchSpan::end));
                    assert_eq!(
                        tuple(actual),
                        tuple(expected),
                        "mode={mode:?}, window={start}..{end}",
                    );
                }
            }
        }
    }

    #[test]
    fn value_prefilter_deduplicates_dense_interior_hits_by_line() {
        let plan = LineDomainPlan::new(
            LF,
            &[Atom::new(ByteMask::singleton(b'A'), 1, Some(1))],
            BuildLimits::default(),
        )
        .unwrap()
        .0;
        let haystack = b"AAAAAAAAAAAAAAAA\nA\nAAAAAAAA\n";
        assert_eq!(
            tuple(
                plan.find_value(haystack, 0, haystack.len(), SearchLimits::unlimited())
                    .unwrap()
            ),
            Some((17, 18)),
        );
        assert_eq!(
            tuple(
                plan.find_value(haystack, 18, haystack.len(), SearchLimits::unlimited())
                    .unwrap()
            ),
            None,
        );
    }

    #[test]
    fn four_member_prefilter_is_single_pass_across_blocks_and_tails() {
        let members = [0x01, 0x41, 0x81, 0xc1];
        for position in 0..=2 * BYTE_SET_WIDE_BLOCK_BYTES {
            let mut haystack = vec![b'!'; 2 * BYTE_SET_WIDE_BLOCK_BYTES + 1];
            haystack[position] = members[position % members.len()];
            assert_eq!(find_byte_set4(members, &haystack), Some(position));
        }
        assert_eq!(find_byte_set4(members, &[b'!'; 65]), None);
        let mut multiple = [b'!'; 65];
        multiple[0] = members[3];
        multiple[BYTE_SET_WIDE_BLOCK_BYTES] = members[2];
        multiple[64] = members[1];
        assert_eq!(find_byte_set4(members, &multiple), Some(0));

        let plan = LineDomainPlan::new(
            LF,
            &[Atom::new(
                mask(&[(0x01, 0x01), (0x41, 0x41), (0x81, 0x81), (0xc1, 0xc1)]),
                1,
                Some(1),
            )],
            BuildLimits::default(),
        )
        .unwrap()
        .0;
        let ValuePrefilter::SmallSet { len, bytes, .. } = &plan.value_prefilter else {
            panic!("a four-member fixed mask must retain the one-pass classifier");
        };
        assert_eq!(*len, 4);
        assert_eq!(&bytes[..*len], members);
        let mut haystack = vec![b'!'; 64];
        haystack.extend_from_slice(b"\n\xc1\n");
        assert_eq!(
            tuple(
                plan.find_value(&haystack, 0, haystack.len(), SearchLimits::unlimited())
                    .unwrap()
            ),
            Some((65, 66)),
        );

        let mut multi_hit_lines = vec![members[0]; 2 * BYTE_SET_WIDE_BLOCK_BYTES + 1];
        multi_hit_lines.push(b'\n');
        multi_hit_lines.extend_from_slice(b"!\n");
        let selected = multi_hit_lines.len();
        multi_hit_lines.extend_from_slice(&[members[2], b'\n']);
        for start in 0..=multi_hit_lines.len() {
            for end in start..=multi_hit_lines.len() {
                let expected = plan
                    .find(
                        &multi_hit_lines,
                        start,
                        end,
                        SearchLimits::unlimited(),
                    )
                    .unwrap()
                    .0;
                let actual = plan
                    .find_value(
                        &multi_hit_lines,
                        start,
                        end,
                        SearchLimits::unlimited(),
                    )
                    .unwrap();
                assert_eq!(
                    tuple(actual),
                    tuple(expected),
                    "set4 window={start}..{end}",
                );
            }
        }
        assert_eq!(
            tuple(
                plan.find_value(
                    &multi_hit_lines,
                    0,
                    multi_hit_lines.len(),
                    SearchLimits::unlimited(),
                )
                .unwrap(),
            ),
            Some((selected, selected + 1)),
        );

        let line_modes: &[(LineMode, &[u8])] = &[
            (LF, b"\x01A\n!\n\xc1\n"),
            (
                LineMode::Lf { terminator: b'|' },
                b"\x01A|!|\xc1|",
            ),
            (LineMode::Crlf, b"\x01A\r\n!\r\xc1\n"),
        ];
        for &(line_mode, source) in line_modes {
            let mode_plan = LineDomainPlan::new(
                line_mode,
                &[Atom::new(
                    mask(&[(0x01, 0x01), (0x41, 0x41), (0x81, 0x81), (0xc1, 0xc1)]),
                    1,
                    Some(1),
                )],
                BuildLimits::default(),
            )
            .unwrap()
            .0;
            for start in 0..=source.len() {
                for end in start..=source.len() {
                    let expected = mode_plan
                        .find(source, start, end, SearchLimits::unlimited())
                        .unwrap()
                        .0;
                    let actual = mode_plan
                        .find_value(source, start, end, SearchLimits::unlimited())
                        .unwrap();
                    assert_eq!(
                        tuple(actual),
                        tuple(expected),
                        "set4 mode={line_mode:?}, window={start}..{end}",
                    );
                }
            }
        }
    }

    #[test]
    fn lf_search_keeps_cr_as_content_and_respects_arbitrary_windows() {
        let plan = word_plan(LF);
        let haystack = b"..\nAlpha\nBeta\r\nGamma\n";
        assert_eq!(
            tuple(plan.find_value(haystack, 0, haystack.len(), SearchLimits::unlimited()).unwrap()),
            Some((3, 8))
        );
        assert_eq!(
            tuple(plan.find_value(haystack, 4, haystack.len(), SearchLimits::unlimited()).unwrap()),
            Some((15, 20))
        );
        assert_eq!(
            tuple(plan.find_value(haystack, 8, 15, SearchLimits::unlimited()).unwrap()),
            None
        );
        assert_eq!(
            tuple(plan.find_value(haystack, 9, 15, SearchLimits::unlimited()).unwrap()),
            None
        );
    }

    #[test]
    fn ordinary_multiline_uses_its_configured_terminator() {
        let plan = word_plan(LineMode::Lf { terminator: b'|' });
        let newline_plan = word_plan(LF);
        let haystack = b"..|Alpha|Beta\n|Gamma|";
        assert_eq!(
            tuple(plan.find_value(haystack, 0, haystack.len(), SearchLimits::unlimited()).unwrap()),
            Some((3, 8))
        );
        assert_eq!(
            tuple(plan.find_value(haystack, 4, haystack.len(), SearchLimits::unlimited()).unwrap()),
            Some((15, 20))
        );
        assert_ne!(identity_words(&plan), identity_words(&newline_plan));
    }

    #[test]
    fn crlf_search_coalesces_pairs_and_splits_on_lone_terminators() {
        let plan = word_plan(LineMode::Crlf);
        let haystack = b"..\r\nBravo\r\nbad\rDelta\nEcho";
        assert_eq!(
            tuple(plan.find_value(haystack, 0, haystack.len(), SearchLimits::unlimited()).unwrap()),
            Some((4, 9))
        );
        assert_eq!(
            tuple(plan.find_value(haystack, 5, haystack.len(), SearchLimits::unlimited()).unwrap()),
            Some((15, 20))
        );
        assert_eq!(
            tuple(plan.find_value(haystack, 3, 9, SearchLimits::unlimited()).unwrap()),
            Some((4, 9))
        );
        assert_eq!(
            tuple(plan.find_value(haystack, 4, 8, SearchLimits::unlimited()).unwrap()),
            None
        );
        // Byte 3 is between CR and LF and is not a CRLF line start.
        assert!(!plan.is_line_start_value(haystack, 3));
        assert!(plan.is_line_start_value(haystack, 4));
        assert!(!plan.is_line_end_value(haystack, 3));
        assert!(plan.is_line_end_value(haystack, 2));
    }

    #[test]
    fn bulk_delimiter_scan_preserves_exact_logical_counters() {
        let lf = word_plan(LF);
        let mut lf_hit = SearchActual::new(5);
        assert_eq!(
            lf.next_line_start(b"xxxx\n", 0, 5, &mut lf_hit).unwrap(),
            Some(5),
        );
        assert_eq!(
            (lf_hit.delimiter_steps, lf_hit.source_reads, lf_hit.work),
            (5, 5, 10),
        );
        let mut lf_miss = SearchActual::new(4);
        assert_eq!(
            lf.next_line_start(b"xxxx", 0, 4, &mut lf_miss).unwrap(),
            None,
        );
        assert_eq!(
            (lf_miss.delimiter_steps, lf_miss.source_reads, lf_miss.work),
            (4, 4, 8),
        );

        let crlf = word_plan(LineMode::Crlf);
        let mut crlf_hit = SearchActual::new(4);
        assert_eq!(
            crlf
                .next_line_start(b"xx\r\n", 0, 4, &mut crlf_hit)
                .unwrap(),
            Some(4),
        );
        assert_eq!(
            (
                crlf_hit.delimiter_steps,
                crlf_hit.source_reads,
                crlf_hit.work,
            ),
            (3, 4, 7),
        );
    }

    #[test]
    fn cursor_emits_every_nonoverlapping_line_span_in_source_order() {
        let plan = word_plan(LF);
        let haystack = b"Alpha\n..\nBeta\nGamma\n";
        let mut cursor = plan
            .cursor(haystack, 0, haystack.len(), SearchLimits::unlimited())
            .unwrap();
        let mut spans = Vec::new();
        while let Some(span) = cursor.next_match().unwrap() {
            spans.push((span.start(), span.end()));
        }
        assert_eq!(spans, [(0, 5), (9, 13), (14, 19)]);
        let accounting = cursor.accounting(Operation::Iterate);
        assert!(accounting.upper_bounds.contains(accounting.actual));
        assert_eq!(accounting.actual.match_events, 3);
        assert!(cursor.next_match().unwrap().is_none());
    }

    #[test]
    fn immutable_plan_supports_interleaved_haystack_cursors() {
        let plan = word_plan(LF);
        let left_source = b"Alpha\nBeta\n";
        let right_source = b"Gamma\nDelta\n";
        let mut left = plan
            .cursor(
                left_source,
                0,
                left_source.len(),
                SearchLimits::unlimited(),
            )
            .unwrap();
        let mut right = plan
            .cursor(
                right_source,
                0,
                right_source.len(),
                SearchLimits::unlimited(),
            )
            .unwrap();
        assert_eq!(tuple(left.next_match().unwrap()), Some((0, 5)));
        assert_eq!(tuple(right.next_match().unwrap()), Some((0, 5)));
        assert_eq!(tuple(left.next_match().unwrap()), Some((6, 10)));
        assert_eq!(tuple(right.next_match().unwrap()), Some((6, 11)));
        assert!(left.accounting(Operation::Iterate).upper_bounds.contains(
            left.accounting(Operation::Iterate).actual
        ));
        assert!(right.accounting(Operation::Iterate).upper_bounds.contains(
            right.accounting(Operation::Iterate).actual
        ));
    }

    #[test]
    fn prospective_limit_refuses_before_execution_and_is_source_independent() {
        let plan = word_plan(LineMode::Crlf);
        let left = plan.search_upper_bounds(17, 3, 14).unwrap();
        let right = plan.search_upper_bounds(17, 3, 14).unwrap();
        assert_eq!(left, right);
        assert!(matches!(
            plan.find(
                b"...\r\nAlpha\r\n....",
                3,
                14,
                SearchLimits {
                    max_work: left.work.saturating_sub(1),
                }
            ),
            Err(SearchError::WorkLimit { needed, limit })
                if needed == left.work && limit == left.work.saturating_sub(1)
        ));
    }

    #[test]
    fn greedy_terminal_requires_the_actual_line_end() {
        let plan = word_plan(LF);
        let haystack = b"Alphabetic\nAlpha\n";
        assert_eq!(
            tuple(plan.find_value(haystack, 0, haystack.len(), SearchLimits::unlimited()).unwrap()),
            Some((11, 16))
        );
    }

    #[test]
    fn disjoint_successor_preserves_nonterminal_greediness() {
        let atoms = [
            Atom::new(mask(&[(b'A', b'Z')]), 1, Some(1)),
            Atom::new(mask(&[(b'a', b'z')]), 2, Some(8)),
            Atom::new(mask(&[(b'0', b'9')]), 1, Some(1)),
        ];
        let plan = LineDomainPlan::new(LF, &atoms, BuildLimits::default())
            .unwrap()
            .0;
        let haystack = b"Alphabet7\nAlpha7\n";
        assert_eq!(
            tuple(
                plan.find_value(haystack, 0, haystack.len(), SearchLimits::unlimited())
                    .unwrap()
            ),
            Some((0, 9))
        );
    }
}
