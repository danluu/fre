//! Checked AST admission and prioritized tagged Thompson lowering.

use std::collections::HashSet;
use std::mem::size_of;

use crate::ast::{Assertion, Ast, Greed};
use crate::error::{BuildError, ResourceKind};
use crate::limits::BuildLimits;
use crate::model::HistoryProgramShape;
use crate::profile::CaptureProfile;

const UNSET: usize = usize::MAX;

/// Immutable-program construction accounting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildReport {
    /// Construction route that owns the accounting below.
    pub origin: ProgramBuildOrigin,
    /// Admitted AST nodes.
    pub ast_nodes: usize,
    /// Maximum admitted AST depth.
    pub ast_depth: usize,
    /// User capture count, excluding group zero.
    pub captures: usize,
    /// Thompson state count.
    pub states: usize,
    /// Patch entries created over the complete compile.
    pub patch_entries: usize,
    /// Metered compiler operations.
    pub compile_work: usize,
    /// Conservative immutable-program bytes.
    pub program_bytes: usize,
}

/// Source of one immutable [`Program`]'s construction accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProgramBuildOrigin {
    /// Admitted AST compilation; `ast_*`, patch, and compile-work fields are
    /// populated by the compiler.
    AstCompiler,
    /// Stable V1 restoration. No AST or patch list was constructed, and the
    /// checked wire-validation work is reported here instead.
    CaptureProgramV1Restore {
        /// Versioned source-independent wire-validation work units.
        validation_work: usize,
    },
}

/// Opaque exact first-byte set produced by the capture compiler.
///
/// This proof is returned only alongside the [`Program`] built from the same
/// admitted AST. It is deliberately not retained by `Program` or encoded in
/// the stable capture-program format.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirstByteProof {
    words: [u64; 4],
    nullable: bool,
}

/// Opaque complete first-byte set for a construction-proved non-nullable
/// program.
///
/// Values are minted only from the transient [`FirstByteProof`] returned by
/// the same atomic compiler transaction as a [`Program`]. The set is not
/// retained by `Program` and is not encoded in the stable capture-program
/// format.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonNullableFirstByteMask {
    words: [u64; 4],
}

impl NonNullableFirstByteMask {
    pub(crate) const ALL: Self = Self {
        words: [u64::MAX; 4],
    };

    /// Whether `byte` belongs to the compiler-proved first-byte set.
    #[must_use]
    #[inline]
    pub fn matches(self, byte: u8) -> bool {
        let byte = usize::from(byte);
        self.words[byte / 64] & (1_u64 << (byte % 64)) != 0
    }

    /// Whether construction proved an empty first-byte domain.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.words[0] == 0 && self.words[1] == 0 && self.words[2] == 0 && self.words[3] == 0
    }

    /// Whether every byte belongs to the first-byte domain.
    #[must_use]
    pub const fn is_all(self) -> bool {
        self.words[0] == u64::MAX
            && self.words[1] == u64::MAX
            && self.words[2] == u64::MAX
            && self.words[3] == u64::MAX
    }

    /// Complete four-word set identity for a construction owner to seal.
    #[doc(hidden)]
    #[must_use]
    pub const fn words(self) -> [u64; 4] {
        self.words
    }
}

/// One caller-selected byte classifier for restricting newly injected roots.
///
/// This type does not claim full-search equivalence. The hidden low-level
/// history operation documents the restricted-start semantics explicitly;
/// construction owners must separately prove that the classifier equals the
/// complete non-nullable first-byte set before using it as an optimization.
#[doc(hidden)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaskedInclusiveRange {
    or_mask: u8,
    lower: u8,
    width: u8,
}

impl MaskedInclusiveRange {
    pub(crate) const ALL: Self = Self {
        or_mask: 0,
        lower: 0,
        width: u8::MAX,
    };

    /// Construct the classifier `(byte | or_mask) in lower..=upper`.
    ///
    /// A reversed inclusive interval is not representable.
    #[must_use]
    pub const fn new(or_mask: u8, lower: u8, upper: u8) -> Option<Self> {
        if lower <= upper {
            Some(Self {
                or_mask,
                lower,
                width: upper - lower,
            })
        } else {
            None
        }
    }

    /// Mask ORed into each candidate byte.
    #[must_use]
    pub const fn or_mask(self) -> u8 {
        self.or_mask
    }

    /// Inclusive lower endpoint after masking.
    #[must_use]
    pub const fn lower(self) -> u8 {
        self.lower
    }

    /// Inclusive upper endpoint after masking.
    #[must_use]
    pub const fn upper(self) -> u8 {
        self.lower.wrapping_add(self.width)
    }

    /// Whether `byte` belongs to this explicitly restricted start domain.
    #[must_use]
    pub const fn matches(self, byte: u8) -> bool {
        (byte | self.or_mask).wrapping_sub(self.lower) <= self.width
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ConsumedPrefixProof {
    can_match: bool,
    nullable: bool,
    bytes: [u8; 3],
    length: u8,
    exact_length: Option<u8>,
}

impl ConsumedPrefixProof {
    const EMPTY_LANGUAGE: Self = Self {
        can_match: false,
        nullable: false,
        bytes: [0; 3],
        length: 0,
        exact_length: None,
    };

    const EMPTY_MATCH: Self = Self {
        can_match: true,
        nullable: true,
        bytes: [0; 3],
        length: 0,
        exact_length: Some(0),
    };

    const fn byte(byte: u8) -> Self {
        Self {
            can_match: true,
            nullable: false,
            bytes: [byte, 0, 0],
            length: 1,
            exact_length: Some(1),
        }
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "all prefix lengths and indices are structurally bounded by the fixed three-byte proof"
    )]
    fn concat(self, suffix: Self) -> Self {
        if !self.can_match || !suffix.can_match {
            return Self::EMPTY_LANGUAGE;
        }
        if self.exact_length.is_none() {
            return Self {
                nullable: self.nullable && suffix.nullable,
                ..self
            };
        }
        let mut bytes = self.bytes;
        let mut length = usize::from(self.length);
        for &byte in &suffix.bytes[..usize::from(suffix.length)] {
            if length == bytes.len() {
                break;
            }
            bytes[length] = byte;
            length += 1;
        }
        let combined_exact_length = self.exact_length.and_then(|left| {
            suffix.exact_length.and_then(|right| {
                left.checked_add(right)
                    .filter(|&combined| usize::from(combined) <= bytes.len())
            })
        });
        Self {
            can_match: true,
            nullable: self.nullable && suffix.nullable,
            bytes,
            length: u8::try_from(length).expect("a consumed-prefix proof is at most three bytes"),
            exact_length: combined_exact_length,
        }
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "all prefix lengths and indices are structurally bounded by the fixed three-byte proof"
    )]
    fn common(self, other: Self) -> Self {
        if !self.can_match {
            return other;
        }
        if !other.can_match {
            return self;
        }
        let mut length = 0_usize;
        let limit = usize::from(self.length.min(other.length));
        while length < limit && self.bytes[length] == other.bytes[length] {
            length += 1;
        }
        let mut bytes = self.bytes;
        bytes[length..].fill(0);
        let exact_length = match (self.exact_length, other.exact_length) {
            (Some(left), Some(right))
                if left == right
                    && self.bytes[..usize::from(left)] == other.bytes[..usize::from(right)] =>
            {
                Some(left)
            }
            _ => None,
        };
        Self {
            can_match: true,
            nullable: self.nullable || other.nullable,
            bytes,
            length: u8::try_from(length).expect("a consumed-prefix proof is at most three bytes"),
            exact_length,
        }
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "only the first three bytes of the guaranteed minimum copies are materialized"
    )]
    fn repeat(self, min: u32, max: Option<u32>) -> Self {
        if max == Some(0) {
            return Self::EMPTY_MATCH;
        }
        if !self.can_match {
            return Self::EMPTY_LANGUAGE;
        }
        if self.exact_length == Some(0) {
            return Self::EMPTY_MATCH;
        }
        if min == 0 || self.nullable {
            return Self {
                can_match: true,
                nullable: true,
                bytes: [0; 3],
                length: 0,
                exact_length: None,
            };
        }
        let Some(unit_length) = self.exact_length else {
            return Self {
                can_match: true,
                nullable: false,
                exact_length: None,
                ..self
            };
        };
        let unit_length = usize::from(unit_length);
        debug_assert!(unit_length > 0);
        let guaranteed_length = usize::try_from(min)
            .unwrap_or(usize::MAX)
            .saturating_mul(unit_length)
            .min(self.bytes.len());
        let mut bytes = [0_u8; 3];
        for (index, byte) in bytes[..guaranteed_length].iter_mut().enumerate() {
            *byte = self.bytes[index % unit_length];
        }
        let exact_length = if max == Some(min) {
            u8::try_from(min)
                .ok()
                .and_then(|count| count.checked_mul(u8::try_from(unit_length).ok()?))
                .filter(|&length| usize::from(length) <= bytes.len())
        } else {
            None
        };
        Self {
            can_match: true,
            nullable: false,
            bytes,
            length: u8::try_from(guaranteed_length)
                .expect("a consumed-prefix proof is at most three bytes"),
            exact_length,
        }
    }

    const fn cannot_extend_concat(self) -> bool {
        !self.can_match || self.length == 3 || self.exact_length.is_none()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StartProof {
    first_bytes: FirstByteProof,
    consumed_prefix: ConsumedPrefixProof,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StartPrefilter {
    ByteSet { bytes: [u8; 3], length: u8 },
    ExactPrefix { bytes: [u8; 3], length: u8 },
}

const EXACT_PREFIX_2_TAG: u8 = 0x82;
const EXACT_PREFIX_3_TAG: u8 = 0x83;

impl FirstByteProof {
    const EMPTY_LANGUAGE: Self = Self {
        words: [0; 4],
        nullable: false,
    };

    const EMPTY_MATCH: Self = Self {
        words: [0; 4],
        nullable: true,
    };

    fn byte(byte: u8) -> Self {
        let mut proof = Self::EMPTY_LANGUAGE;
        proof.insert(byte);
        proof
    }

    fn insert(&mut self, byte: u8) {
        let byte = usize::from(byte);
        self.words[byte / 64] |= 1_u64 << (byte % 64);
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "validated byte intervals stay inside four fixed u64 words; masks special-case full-width endpoints before shifts"
    )]
    fn insert_range(&mut self, start: u8, end: u8) {
        let start = usize::from(start);
        let end = usize::from(end);
        let first_word = start / 64;
        let last_word = end / 64;
        for word_index in first_word..=last_word {
            let first_bit = if word_index == first_word {
                start % 64
            } else {
                0
            };
            let last_bit = if word_index == last_word {
                end % 64
            } else {
                63
            };
            let high_mask = if last_bit == 63 {
                u64::MAX
            } else {
                (1_u64 << (last_bit + 1)) - 1
            };
            let low_mask = u64::MAX << first_bit;
            self.words[word_index] |= high_mask & low_mask;
        }
    }

    fn union(&mut self, other: Self) {
        for (word, other) in self.words.iter_mut().zip(other.words) {
            *word |= other;
        }
    }

    /// Compare a predetermined non-nullable classifier image with all four
    /// exact proof words. The caller owns the fixed work transaction and must
    /// supply words already authenticated as the image of its classifier.
    ///
    /// All four comparisons are evaluated even when an earlier word differs.
    #[doc(hidden)]
    #[must_use]
    pub fn equals_nonnullable_words(self, expected: [u64; 4]) -> bool {
        let words_equal = (self.words[0] == expected[0])
            & (self.words[1] == expected[1])
            & (self.words[2] == expected[2])
            & (self.words[3] == expected[3]);
        !self.nullable && words_equal
    }

    /// Convert this transient proof into its complete opaque first-byte mask
    /// exactly when the compiled program is non-nullable.
    #[doc(hidden)]
    #[must_use]
    pub const fn nonnullable_mask(self) -> Option<NonNullableFirstByteMask> {
        if self.nullable {
            None
        } else {
            Some(NonNullableFirstByteMask { words: self.words })
        }
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the fixed four-word byte domain and at-most-three result bound every index and increment"
    )]
    fn candidates(self) -> ([u8; 3], u8) {
        if self.nullable {
            return ([0; 3], 0);
        }
        let count = self
            .words
            .iter()
            .map(|word| usize::try_from(word.count_ones()).expect("a bit count fits usize"))
            .sum::<usize>();
        if !(1..=3).contains(&count) {
            return ([0; 3], 0);
        }
        let mut bytes = [0_u8; 3];
        let mut length = 0_usize;
        for (word_index, &word) in self.words.iter().enumerate() {
            let mut remaining = word;
            while remaining != 0 {
                let bit = usize::try_from(remaining.trailing_zeros())
                    .expect("a word bit index fits usize");
                bytes[length] = u8::try_from(word_index * 64 + bit)
                    .expect("a four-word byte set contains only u8 values");
                length += 1;
                remaining &= remaining - 1;
            }
        }
        (
            bytes,
            u8::try_from(length).expect("candidate length is at most three"),
        )
    }
}

impl StartProof {
    fn pack(self) -> u32 {
        if !self.consumed_prefix.nullable {
            let length = self.consumed_prefix.length;
            let tag = match length {
                2 => Some(EXACT_PREFIX_2_TAG),
                3 => Some(EXACT_PREFIX_3_TAG),
                _ => None,
            };
            if let Some(tag) = tag {
                return u32::from_le_bytes([
                    self.consumed_prefix.bytes[0],
                    self.consumed_prefix.bytes[1],
                    self.consumed_prefix.bytes[2],
                    tag,
                ]);
            }
        }
        let (bytes, length) = self.first_bytes.candidates();
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], length])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GroupMeta {
    pub(crate) index: u32,
    pub(crate) name: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum State {
    Byte {
        ranges: Vec<(u8, u8)>,
        next: usize,
    },
    Split {
        first: usize,
        second: usize,
    },
    Save {
        slot: usize,
        next: usize,
        start_prefilter: u32,
    },
    Assert {
        assertion: Assertion,
        next: usize,
    },
    Epsilon {
        next: usize,
    },
    Match,
    Fail,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BacktrackShape {
    pub(crate) save_states: usize,
    pub(crate) frame_states: usize,
}

/// An immutable prioritized tagged Thompson program.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Program {
    pub(crate) states: Vec<State>,
    pub(crate) start: usize,
    pub(crate) slot_count: usize,
    pub(crate) groups: Vec<GroupMeta>,
    backtrack_shape: BacktrackShape,
    name_payload_bytes: usize,
    profile: CaptureProfile,
    report: BuildReport,
}

impl Program {
    /// Admit and compile a laboratory AST.
    pub fn compile(ast: &Ast, limits: BuildLimits) -> Result<Self, BuildError> {
        Self::compile_for(ast, CaptureProfile::RustRegexBytes1_12_4, limits)
    }

    /// Admit and compile for an explicit versioned semantic profile.
    pub fn compile_for(
        ast: &Ast,
        profile: CaptureProfile,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        Self::compile_for_with_first_byte_proof(ast, profile, limits).map(|(program, _)| program)
    }

    pub(crate) fn compile_for_with_first_byte_proof(
        ast: &Ast,
        profile: CaptureProfile,
        limits: BuildLimits,
    ) -> Result<(Self, FirstByteProof), BuildError> {
        if profile != CaptureProfile::RustRegexBytes1_12_4 {
            return Err(BuildError::ProfilePending(profile));
        }
        let admitted = admit(ast, limits)?;
        let name_payload_bytes = admitted.name_payload_bytes;
        let mut compiler = Compiler::new(limits, admitted.groups.len(), admitted.metadata_bytes)?;
        let start_proof = compiler.start_proof(ast)?;
        let first_byte_proof = start_proof.first_bytes;
        let inner = compiler.compile(ast)?;
        let packed_start_prefilter = start_proof.pack();

        let end_save = compiler.add_state(State::Save {
            slot: 1,
            next: UNSET,
            start_prefilter: 0,
        })?;
        compiler.register_patch()?;
        compiler.patch_all(&inner.outs, end_save)?;
        let matched = compiler.add_state(State::Match)?;
        compiler.patch(Patch::Next(end_save), matched)?;
        let start_save = compiler.add_state(State::Save {
            slot: 0,
            next: inner.start,
            start_prefilter: packed_start_prefilter,
        })?;

        let program_bytes = compiler.program_bytes()?;
        check_limit(
            ResourceKind::ProgramBytes,
            program_bytes,
            limits.max_program_bytes,
        )?;
        let captures = admitted
            .groups
            .len()
            .checked_sub(1)
            .ok_or(BuildError::BoundOverflow(ResourceKind::Captures))?;
        let report = BuildReport {
            origin: ProgramBuildOrigin::AstCompiler,
            ast_nodes: admitted.nodes,
            ast_depth: admitted.depth,
            captures,
            states: compiler.states.len(),
            patch_entries: compiler.patch_entries,
            compile_work: compiler.work,
            program_bytes,
        };
        let slot_count = admitted
            .groups
            .len()
            .checked_mul(2)
            .ok_or(BuildError::BoundOverflow(ResourceKind::Captures))?;
        Ok((
            Self {
                states: compiler.states,
                start: start_save,
                slot_count,
                groups: admitted.groups,
                backtrack_shape: compiler.backtrack_shape,
                name_payload_bytes,
                profile,
                report,
            },
            first_byte_proof,
        ))
    }

    /// Construction accounting and conservative immutable size.
    #[must_use]
    pub const fn build_report(&self) -> &BuildReport {
        &self.report
    }

    /// Whether construction accounting closes over this exact immutable
    /// graph and schema.
    #[must_use]
    pub fn build_report_closes(&self) -> bool {
        let Some(captures) = self.groups.len().checked_sub(1) else {
            return false;
        };
        let Some(slots) = self.groups.len().checked_mul(2) else {
            return false;
        };
        let minimum_program_bytes = self
            .states
            .len()
            .checked_mul(size_of::<State>())
            .and_then(|bytes| {
                self.groups
                    .len()
                    .checked_mul(size_of::<GroupMeta>())
                    .and_then(|groups| bytes.checked_add(groups))
            })
            .and_then(|bytes| {
                self.states.iter().try_fold(bytes, |bytes, state| {
                    let ranges = match state {
                        State::Byte { ranges, .. } => ranges.len(),
                        _ => 0,
                    };
                    ranges
                        .checked_mul(size_of::<(u8, u8)>())
                        .and_then(|ranges| bytes.checked_add(ranges))
                })
            })
            .and_then(|bytes| bytes.checked_add(self.name_payload_bytes));
        let shape_closes = self.report.captures == captures
            && self.report.states == self.states.len()
            && self.slot_count == slots
            && minimum_program_bytes.is_some_and(|minimum| self.report.program_bytes >= minimum)
            && self
                .groups
                .iter()
                .enumerate()
                .all(|(index, group)| usize::try_from(group.index) == Ok(index));
        if !shape_closes {
            return false;
        }
        match self.report.origin {
            ProgramBuildOrigin::AstCompiler => {
                self.report.ast_nodes > 0
                    && self.report.ast_depth > 0
                    && self.report.ast_depth <= self.report.ast_nodes
                    && self.report.compile_work > 0
            }
            ProgramBuildOrigin::CaptureProgramV1Restore { validation_work } => {
                validation_work > 0
                    && self.report.ast_nodes == 0
                    && self.report.ast_depth == 0
                    && self.report.patch_entries == 0
                    && self.report.compile_work == 0
                    && minimum_program_bytes == Some(self.report.program_bytes)
            }
        }
    }

    /// Number of instructions in the immutable program.
    #[must_use]
    pub const fn state_len(&self) -> usize {
        self.states.len()
    }

    /// Number of canonical groups, including group zero.
    #[must_use]
    pub const fn group_len(&self) -> usize {
        self.groups.len()
    }

    /// Structural identity needed to reproduce persistent-history admission
    /// without retaining or exposing the program's instruction stream.
    #[must_use]
    pub fn history_program_shape(&self) -> HistoryProgramShape {
        HistoryProgramShape {
            states: self.states.len(),
            save_states: self.backtrack_shape.save_states,
            slots: self.slot_count,
            groups: self.groups.len(),
            name_payload_bytes: self.name_payload_bytes,
        }
    }

    /// Versioned semantic profile used for compilation.
    #[must_use]
    pub const fn profile(&self) -> CaptureProfile {
        self.profile
    }

    pub(crate) fn backtrack_frame_state_len(&self) -> usize {
        self.backtrack_shape.frame_states
    }

    #[inline]
    pub(crate) fn start_prefilter(&self) -> Option<StartPrefilter> {
        let State::Save {
            start_prefilter, ..
        } = self.states.get(self.start)?
        else {
            return None;
        };
        let [first, second, third, tag] = start_prefilter.to_le_bytes();
        let bytes = [first, second, third];
        match tag {
            1..=3 => Some(StartPrefilter::ByteSet { bytes, length: tag }),
            EXACT_PREFIX_2_TAG => Some(StartPrefilter::ExactPrefix { bytes, length: 2 }),
            EXACT_PREFIX_3_TAG => Some(StartPrefilter::ExactPrefix { bytes, length: 3 }),
            _ => None,
        }
    }
}

impl Program {
    /// Reconstruct a program whose complete wire representation has already
    /// passed the V1 validator.
    ///
    /// Stable artifacts deliberately omit the original AST compiler ledger.
    /// A restored program therefore reports zero AST/patch/compiler work and
    /// rederives only the shape dimensions needed by execution accounting.
    pub(crate) fn from_validated_v1_parts(
        states: Vec<State>,
        start: usize,
        slot_count: usize,
        groups: Vec<GroupMeta>,
        profile: CaptureProfile,
        program_bytes: usize,
        validation_work: usize,
    ) -> Self {
        let save_states = states
            .iter()
            .filter(|state| matches!(state, State::Save { .. }))
            .count();
        let frame_states = states
            .iter()
            .filter(|state| matches!(state, State::Split { .. } | State::Save { .. }))
            .count();
        let name_payload_bytes = groups
            .iter()
            .map(|group| group.name.as_ref().map_or(0, String::len))
            .sum();
        let captures = groups.len().saturating_sub(1);
        let state_count = states.len();
        Self {
            states,
            start,
            slot_count,
            groups,
            backtrack_shape: BacktrackShape {
                save_states,
                frame_states,
            },
            name_payload_bytes,
            profile,
            report: BuildReport {
                origin: ProgramBuildOrigin::CaptureProgramV1Restore { validation_work },
                ast_nodes: 0,
                ast_depth: 0,
                captures,
                states: state_count,
                patch_entries: 0,
                compile_work: 0,
                program_bytes,
            },
        }
    }
}

#[derive(Debug)]
struct Admission {
    nodes: usize,
    depth: usize,
    groups: Vec<GroupMeta>,
    metadata_bytes: usize,
    name_payload_bytes: usize,
}

#[allow(
    clippy::too_many_lines,
    reason = "single iterative admission pass keeps all structural invariants together"
)]
fn admit(ast: &Ast, limits: BuildLimits) -> Result<Admission, BuildError> {
    let mut groups = Vec::new();
    groups
        .try_reserve(1)
        .map_err(|_| BuildError::Allocation(ResourceKind::Captures))?;
    groups.push(GroupMeta {
        index: 0,
        name: None,
    });
    let mut metadata_bytes = size_of::<GroupMeta>();
    let mut name_payload_bytes = 0_usize;
    check_limit(
        ResourceKind::ProgramBytes,
        metadata_bytes,
        limits.max_program_bytes,
    )?;
    let mut names = HashSet::new();
    let mut stack = Vec::new();
    stack
        .try_reserve(1)
        .map_err(|_| BuildError::Allocation(ResourceKind::AstNodes))?;
    stack.push((ast, 1_usize));
    let mut nodes = 0_usize;
    let mut max_depth = 0_usize;
    let mut next_capture = 1_u32;

    while let Some((node, depth)) = stack.pop() {
        nodes = checked_inc(nodes, ResourceKind::AstNodes)?;
        check_limit(ResourceKind::AstNodes, nodes, limits.max_ast_nodes)?;
        max_depth = max_depth.max(depth);
        check_limit(ResourceKind::AstDepth, max_depth, limits.max_ast_depth)?;
        let child_depth = depth
            .checked_add(1)
            .ok_or(BuildError::BoundOverflow(ResourceKind::AstDepth))?;
        match node {
            Ast::Empty | Ast::Byte(_) | Ast::Start | Ast::End | Ast::Assert(_) => {}
            Ast::Class(ranges) => validate_ranges(ranges)?,
            Ast::Concat(children) | Ast::Alt(children) => {
                stack
                    .try_reserve(children.len())
                    .map_err(|_| BuildError::Allocation(ResourceKind::AstNodes))?;
                for child in children.iter().rev() {
                    stack.push((child, child_depth));
                }
            }
            Ast::Repeat {
                child, min, max, ..
            } => {
                if let Some(maximum) = max {
                    if maximum < min {
                        return Err(BuildError::InvalidAst(
                            "repetition maximum is smaller than minimum",
                        ));
                    }
                    let expansion = usize::try_from(*maximum)
                        .map_err(|_| BuildError::BoundOverflow(ResourceKind::RepeatExpansion))?;
                    check_limit(
                        ResourceKind::RepeatExpansion,
                        expansion,
                        limits.max_repeat_expansion,
                    )?;
                } else {
                    let expansion = usize::try_from(*min)
                        .map_err(|_| BuildError::BoundOverflow(ResourceKind::RepeatExpansion))?;
                    check_limit(
                        ResourceKind::RepeatExpansion,
                        expansion,
                        limits.max_repeat_expansion,
                    )?;
                }
                stack
                    .try_reserve(1)
                    .map_err(|_| BuildError::Allocation(ResourceKind::AstNodes))?;
                stack.push((child, child_depth));
            }
            Ast::Capture { index, name, child } => {
                if *index < next_capture {
                    return Err(BuildError::InvalidAst(
                        "capture indices must increase in source order",
                    ));
                }
                let capture_count = usize::try_from(*index)
                    .map_err(|_| BuildError::BoundOverflow(ResourceKind::Captures))?;
                check_limit(ResourceKind::Captures, capture_count, limits.max_captures)?;
                let schema_entries = index
                    .checked_sub(next_capture)
                    .and_then(|missing| missing.checked_add(1))
                    .ok_or(BuildError::BoundOverflow(ResourceKind::Captures))?;
                let schema_entries = usize::try_from(schema_entries)
                    .map_err(|_| BuildError::BoundOverflow(ResourceKind::Captures))?;
                let schema_bytes = schema_entries
                    .checked_mul(size_of::<GroupMeta>())
                    .ok_or(BuildError::BoundOverflow(ResourceKind::ProgramBytes))?;
                let copied_name = if let Some(name) = name {
                    if !valid_name(name) {
                        return Err(BuildError::InvalidAst(
                            "capture names must be nonempty ASCII identifiers",
                        ));
                    }
                    names
                        .try_reserve(1)
                        .map_err(|_| BuildError::Allocation(ResourceKind::Captures))?;
                    if !names.insert(name.as_str()) {
                        return Err(BuildError::InvalidAst("capture names must be unique"));
                    }
                    let estimated_metadata = metadata_bytes
                        .checked_add(schema_bytes)
                        .and_then(|bytes| bytes.checked_add(name.len()))
                        .ok_or(BuildError::BoundOverflow(ResourceKind::ProgramBytes))?;
                    check_limit(
                        ResourceKind::ProgramBytes,
                        estimated_metadata,
                        limits.max_program_bytes,
                    )?;
                    let mut copied = String::new();
                    copied
                        .try_reserve_exact(name.len())
                        .map_err(|_| BuildError::Allocation(ResourceKind::ProgramBytes))?;
                    copied.push_str(name);
                    name_payload_bytes = name_payload_bytes
                        .checked_add(name.len())
                        .ok_or(BuildError::BoundOverflow(ResourceKind::RetainedOutputBytes))?;
                    Some(copied)
                } else {
                    None
                };
                metadata_bytes = metadata_bytes
                    .checked_add(schema_bytes)
                    .and_then(|bytes| {
                        bytes.checked_add(copied_name.as_ref().map_or(0, String::capacity))
                    })
                    .ok_or(BuildError::BoundOverflow(ResourceKind::ProgramBytes))?;
                check_limit(
                    ResourceKind::ProgramBytes,
                    metadata_bytes,
                    limits.max_program_bytes,
                )?;
                groups
                    .try_reserve(schema_entries)
                    .map_err(|_| BuildError::Allocation(ResourceKind::Captures))?;
                for missing_index in next_capture..*index {
                    groups.push(GroupMeta {
                        index: missing_index,
                        name: None,
                    });
                }
                groups.push(GroupMeta {
                    index: *index,
                    name: copied_name,
                });
                next_capture = index
                    .checked_add(1)
                    .ok_or(BuildError::BoundOverflow(ResourceKind::Captures))?;
                stack
                    .try_reserve(1)
                    .map_err(|_| BuildError::Allocation(ResourceKind::AstNodes))?;
                stack.push((child, child_depth));
            }
        }
    }
    Ok(Admission {
        nodes,
        depth: max_depth,
        groups,
        metadata_bytes,
        name_payload_bytes,
    })
}

fn validate_ranges(ranges: &[(u8, u8)]) -> Result<(), BuildError> {
    let mut previous_end = None;
    for &(start, end) in ranges {
        if start > end {
            return Err(BuildError::InvalidAst("class range is reversed"));
        }
        if previous_end.is_some_and(|old| old >= start) {
            return Err(BuildError::InvalidAst(
                "class ranges must be sorted and disjoint",
            ));
        }
        previous_end = Some(end);
    }
    Ok(())
}

pub(crate) fn valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !(first == b'_' || first.is_ascii_alphabetic()) {
        return false;
    }
    bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

#[derive(Clone, Copy, Debug)]
enum Patch {
    Next(usize),
    SplitFirst(usize),
    SplitSecond(usize),
}

#[derive(Debug)]
struct Fragment {
    start: usize,
    outs: Vec<Patch>,
}

#[derive(Debug)]
struct Compiler {
    limits: BuildLimits,
    states: Vec<State>,
    work: usize,
    patch_entries: usize,
    group_count: usize,
    backtrack_shape: BacktrackShape,
    auxiliary_program_bytes: usize,
}

impl Compiler {
    fn new(
        limits: BuildLimits,
        group_count: usize,
        metadata_bytes: usize,
    ) -> Result<Self, BuildError> {
        check_limit(
            ResourceKind::ProgramBytes,
            metadata_bytes,
            limits.max_program_bytes,
        )?;
        let mut states = Vec::new();
        states
            .try_reserve(group_count.min(limits.max_states))
            .map_err(|_| BuildError::Allocation(ResourceKind::States))?;
        Ok(Self {
            limits,
            states,
            work: 0,
            patch_entries: 0,
            group_count,
            backtrack_shape: BacktrackShape {
                save_states: 0,
                frame_states: 0,
            },
            auxiliary_program_bytes: metadata_bytes,
        })
    }

    fn tick(&mut self) -> Result<(), BuildError> {
        self.work = checked_inc(self.work, ResourceKind::CompileWork)?;
        check_limit(
            ResourceKind::CompileWork,
            self.work,
            self.limits.max_compile_work,
        )
    }

    fn start_proof(&mut self, ast: &Ast) -> Result<StartProof, BuildError> {
        self.tick()?;
        match ast {
            Ast::Empty | Ast::Start | Ast::End | Ast::Assert(_) => Ok(StartProof {
                first_bytes: FirstByteProof::EMPTY_MATCH,
                consumed_prefix: ConsumedPrefixProof::EMPTY_MATCH,
            }),
            Ast::Byte(byte) => Ok(StartProof {
                first_bytes: FirstByteProof::byte(*byte),
                consumed_prefix: ConsumedPrefixProof::byte(*byte),
            }),
            Ast::Class(ranges) => {
                let mut first_bytes = FirstByteProof::EMPTY_LANGUAGE;
                for &(start, end) in ranges {
                    self.tick()?;
                    first_bytes.insert_range(start, end);
                }
                let consumed_prefix = match ranges.as_slice() {
                    [] => ConsumedPrefixProof::EMPTY_LANGUAGE,
                    &[(start, end)] if start == end => ConsumedPrefixProof::byte(start),
                    _ => ConsumedPrefixProof {
                        can_match: true,
                        nullable: false,
                        bytes: [0; 3],
                        length: 0,
                        exact_length: None,
                    },
                };
                Ok(StartProof {
                    first_bytes,
                    consumed_prefix,
                })
            }
            Ast::Capture { child, .. } => self.start_proof(child),
            Ast::Concat(children) => {
                let mut proof = StartProof {
                    first_bytes: FirstByteProof::EMPTY_MATCH,
                    consumed_prefix: ConsumedPrefixProof::EMPTY_MATCH,
                };
                for child in children {
                    let child = self.start_proof(child)?;
                    if proof.first_bytes.nullable {
                        proof.first_bytes.union(child.first_bytes);
                        proof.first_bytes.nullable &= child.first_bytes.nullable;
                    }
                    proof.consumed_prefix = proof.consumed_prefix.concat(child.consumed_prefix);
                    if !proof.first_bytes.nullable && proof.consumed_prefix.cannot_extend_concat() {
                        break;
                    }
                }
                Ok(proof)
            }
            Ast::Alt(children) => {
                let mut proof = StartProof {
                    first_bytes: FirstByteProof::EMPTY_LANGUAGE,
                    consumed_prefix: ConsumedPrefixProof::EMPTY_LANGUAGE,
                };
                for child in children {
                    let child = self.start_proof(child)?;
                    proof.first_bytes.union(child.first_bytes);
                    proof.first_bytes.nullable |= child.first_bytes.nullable;
                    proof.consumed_prefix = proof.consumed_prefix.common(child.consumed_prefix);
                }
                Ok(proof)
            }
            Ast::Repeat {
                child, min, max, ..
            } => {
                if *max == Some(0) {
                    return Ok(StartProof {
                        first_bytes: FirstByteProof::EMPTY_MATCH,
                        consumed_prefix: ConsumedPrefixProof::EMPTY_MATCH,
                    });
                }
                let mut proof = self.start_proof(child)?;
                proof.first_bytes.nullable |= *min == 0;
                proof.consumed_prefix = proof.consumed_prefix.repeat(*min, *max);
                Ok(proof)
            }
        }
    }

    fn add_state(&mut self, state: State) -> Result<usize, BuildError> {
        self.tick()?;
        let required = checked_inc(self.states.len(), ResourceKind::States)?;
        check_limit(ResourceKind::States, required, self.limits.max_states)?;
        let range_bytes = match &state {
            State::Byte { ranges, .. } => ranges
                .capacity()
                .checked_mul(size_of::<(u8, u8)>())
                .ok_or(BuildError::BoundOverflow(ResourceKind::ProgramBytes))?,
            _ => 0,
        };
        let next_auxiliary = self
            .auxiliary_program_bytes
            .checked_add(range_bytes)
            .ok_or(BuildError::BoundOverflow(ResourceKind::ProgramBytes))?;
        let state_bytes = required
            .checked_mul(size_of::<State>())
            .ok_or(BuildError::BoundOverflow(ResourceKind::ProgramBytes))?;
        let next_program_bytes = state_bytes
            .checked_add(next_auxiliary)
            .ok_or(BuildError::BoundOverflow(ResourceKind::ProgramBytes))?;
        check_limit(
            ResourceKind::ProgramBytes,
            next_program_bytes,
            self.limits.max_program_bytes,
        )?;
        self.states
            .try_reserve(1)
            .map_err(|_| BuildError::Allocation(ResourceKind::States))?;
        if matches!(&state, State::Save { .. }) {
            self.backtrack_shape.save_states = self
                .backtrack_shape
                .save_states
                .checked_add(1)
                .ok_or(BuildError::BoundOverflow(ResourceKind::States))?;
        }
        if matches!(&state, State::Split { .. } | State::Save { .. }) {
            self.backtrack_shape.frame_states = self
                .backtrack_shape
                .frame_states
                .checked_add(1)
                .ok_or(BuildError::BoundOverflow(ResourceKind::States))?;
        }
        let id = self.states.len();
        self.states.push(state);
        self.auxiliary_program_bytes = next_auxiliary;
        Ok(id)
    }

    fn preflight_byte_state(&self, range_count: usize) -> Result<(), BuildError> {
        let required = checked_inc(self.states.len(), ResourceKind::States)?;
        check_limit(ResourceKind::States, required, self.limits.max_states)?;
        let range_bytes = range_count
            .checked_mul(size_of::<(u8, u8)>())
            .ok_or(BuildError::BoundOverflow(ResourceKind::ProgramBytes))?;
        let state_bytes = required
            .checked_mul(size_of::<State>())
            .ok_or(BuildError::BoundOverflow(ResourceKind::ProgramBytes))?;
        let required_bytes = state_bytes
            .checked_add(self.auxiliary_program_bytes)
            .and_then(|bytes| bytes.checked_add(range_bytes))
            .ok_or(BuildError::BoundOverflow(ResourceKind::ProgramBytes))?;
        check_limit(
            ResourceKind::ProgramBytes,
            required_bytes,
            self.limits.max_program_bytes,
        )
    }

    fn one_out(&mut self, patch: Patch) -> Result<Vec<Patch>, BuildError> {
        self.register_patch()?;
        let mut outs = Vec::new();
        outs.try_reserve(1)
            .map_err(|_| BuildError::Allocation(ResourceKind::PatchEntries))?;
        outs.push(patch);
        Ok(outs)
    }

    fn register_patch(&mut self) -> Result<(), BuildError> {
        self.patch_entries = checked_inc(self.patch_entries, ResourceKind::PatchEntries)?;
        check_limit(
            ResourceKind::PatchEntries,
            self.patch_entries,
            self.limits.max_patch_entries,
        )
    }

    fn compile(&mut self, ast: &Ast) -> Result<Fragment, BuildError> {
        self.tick()?;
        match ast {
            Ast::Empty => self.empty(),
            Ast::Byte(byte) => {
                self.preflight_byte_state(1)?;
                let mut ranges = Vec::new();
                ranges
                    .try_reserve_exact(1)
                    .map_err(|_| BuildError::Allocation(ResourceKind::ProgramBytes))?;
                ranges.push((*byte, *byte));
                self.byte(ranges)
            }
            Ast::Class(ranges) => {
                self.preflight_byte_state(ranges.len())?;
                let mut copied = Vec::new();
                copied
                    .try_reserve_exact(ranges.len())
                    .map_err(|_| BuildError::Allocation(ResourceKind::ProgramBytes))?;
                copied.extend_from_slice(ranges);
                self.byte(copied)
            }
            Ast::Start => self.assertion(Assertion::Start),
            Ast::End => self.assertion(Assertion::End),
            Ast::Assert(assertion) => self.assertion(*assertion),
            Ast::Concat(children) => self.concat(children),
            Ast::Alt(children) => self.alt(children),
            Ast::Repeat {
                child,
                min,
                max,
                greed,
            } => self.repeat(child, *min, *max, *greed),
            Ast::Capture { index, child, .. } => self.capture(*index, child),
        }
    }

    fn empty(&mut self) -> Result<Fragment, BuildError> {
        let id = self.add_state(State::Epsilon { next: UNSET })?;
        Ok(Fragment {
            start: id,
            outs: self.one_out(Patch::Next(id))?,
        })
    }

    fn fail(&mut self) -> Result<Fragment, BuildError> {
        let id = self.add_state(State::Fail)?;
        Ok(Fragment {
            start: id,
            outs: Vec::new(),
        })
    }

    fn byte(&mut self, ranges: Vec<(u8, u8)>) -> Result<Fragment, BuildError> {
        let id = self.add_state(State::Byte {
            ranges,
            next: UNSET,
        })?;
        Ok(Fragment {
            start: id,
            outs: self.one_out(Patch::Next(id))?,
        })
    }

    fn assertion(&mut self, assertion: Assertion) -> Result<Fragment, BuildError> {
        let id = self.add_state(State::Assert {
            assertion,
            next: UNSET,
        })?;
        Ok(Fragment {
            start: id,
            outs: self.one_out(Patch::Next(id))?,
        })
    }

    fn concat(&mut self, children: &[Ast]) -> Result<Fragment, BuildError> {
        let mut iter = children.iter();
        let Some(first) = iter.next() else {
            return self.empty();
        };
        let mut result = self.compile(first)?;
        for child in iter {
            let next = self.compile(child)?;
            self.patch_all(&result.outs, next.start)?;
            result.outs = next.outs;
        }
        Ok(result)
    }

    fn alt(&mut self, children: &[Ast]) -> Result<Fragment, BuildError> {
        if children.is_empty() {
            return self.fail();
        }
        let mut fragments = Vec::new();
        fragments
            .try_reserve(children.len())
            .map_err(|_| BuildError::Allocation(ResourceKind::PatchEntries))?;
        for child in children {
            fragments.push(self.compile(child)?);
        }
        let mut result = fragments
            .pop()
            .ok_or(BuildError::InvalidAst("alternation unexpectedly empty"))?;
        while let Some(first) = fragments.pop() {
            let split = self.add_state(State::Split {
                first: first.start,
                second: result.start,
            })?;
            let mut outs = first.outs;
            outs.try_reserve(result.outs.len())
                .map_err(|_| BuildError::Allocation(ResourceKind::PatchEntries))?;
            outs.extend(result.outs);
            result = Fragment { start: split, outs };
        }
        Ok(result)
    }

    fn capture(&mut self, index: u32, child: &Ast) -> Result<Fragment, BuildError> {
        let numeric = usize::try_from(index)
            .map_err(|_| BuildError::BoundOverflow(ResourceKind::Captures))?;
        if numeric >= self.group_count {
            return Err(BuildError::InvalidAst("capture index is out of schema"));
        }
        let start_slot = numeric
            .checked_mul(2)
            .ok_or(BuildError::BoundOverflow(ResourceKind::Captures))?;
        let end_slot = start_slot
            .checked_add(1)
            .ok_or(BuildError::BoundOverflow(ResourceKind::Captures))?;
        let inner = self.compile(child)?;
        let end = self.add_state(State::Save {
            slot: end_slot,
            next: UNSET,
            start_prefilter: 0,
        })?;
        self.patch_all(&inner.outs, end)?;
        let start = self.add_state(State::Save {
            slot: start_slot,
            next: inner.start,
            start_prefilter: 0,
        })?;
        Ok(Fragment {
            start,
            outs: self.one_out(Patch::Next(end))?,
        })
    }

    fn repeat(
        &mut self,
        child: &Ast,
        min: u32,
        max: Option<u32>,
        greed: Greed,
    ) -> Result<Fragment, BuildError> {
        match max {
            Some(maximum) if maximum == min => self.exact(child, min),
            Some(maximum) => self.bounded(child, min, maximum, greed),
            None => self.at_least(child, min, greed),
        }
    }

    fn exact(&mut self, child: &Ast, count: u32) -> Result<Fragment, BuildError> {
        if count == 0 {
            return self.empty();
        }
        let mut result = self.compile(child)?;
        for _ in 1..count {
            let next = self.compile(child)?;
            self.patch_all(&result.outs, next.start)?;
            result.outs = next.outs;
        }
        Ok(result)
    }

    fn bounded(
        &mut self,
        child: &Ast,
        min: u32,
        max: u32,
        greed: Greed,
    ) -> Result<Fragment, BuildError> {
        let mut result = self.exact(child, min)?;
        let mut exits = Vec::new();
        let optional = max.checked_sub(min).ok_or(BuildError::InvalidAst(
            "repetition maximum is smaller than minimum",
        ))?;
        exits
            .try_reserve(
                usize::try_from(optional)
                    .map_err(|_| BuildError::BoundOverflow(ResourceKind::PatchEntries))?,
            )
            .map_err(|_| BuildError::Allocation(ResourceKind::PatchEntries))?;
        for _ in 0..optional {
            let next = self.compile(child)?;
            let (first, second, exit_patch) = match greed {
                Greed::Greedy => (next.start, UNSET, Patch::SplitSecond(0)),
                Greed::Lazy => (UNSET, next.start, Patch::SplitFirst(0)),
            };
            let split = self.add_state(State::Split { first, second })?;
            let exit_patch = match exit_patch {
                Patch::SplitFirst(_) => Patch::SplitFirst(split),
                Patch::SplitSecond(_) => Patch::SplitSecond(split),
                Patch::Next(_) => unreachable!(),
            };
            self.patch_all(&result.outs, split)?;
            self.register_patch()?;
            exits.push(exit_patch);
            result.outs = next.outs;
        }
        exits
            .try_reserve(result.outs.len())
            .map_err(|_| BuildError::Allocation(ResourceKind::PatchEntries))?;
        exits.extend(result.outs);
        result.outs = exits;
        Ok(result)
    }

    fn at_least(&mut self, child: &Ast, min: u32, greed: Greed) -> Result<Fragment, BuildError> {
        if min == 0 {
            let child_nullable = self.nullable(child)?;
            let repeated = self.plus(child, greed)?;
            if child_nullable {
                return self.optional_fragment(repeated, greed);
            }
            return Ok(Fragment {
                start: repeated
                    .outs
                    .first()
                    .map_or(repeated.start, |patch| match patch {
                        Patch::SplitFirst(state) | Patch::SplitSecond(state) => *state,
                        Patch::Next(_) => repeated.start,
                    }),
                outs: repeated.outs,
            });
        }
        if min == 1 {
            return self.plus(child, greed);
        }
        let prefix_count = min
            .checked_sub(1)
            .ok_or(BuildError::BoundOverflow(ResourceKind::RepeatExpansion))?;
        let mut prefix = self.exact(child, prefix_count)?;
        let repeated = self.plus(child, greed)?;
        self.patch_all(&prefix.outs, repeated.start)?;
        prefix.outs = repeated.outs;
        Ok(prefix)
    }

    fn plus(&mut self, child: &Ast, greed: Greed) -> Result<Fragment, BuildError> {
        let inner = self.compile(child)?;
        let (first, second, exit_is_first) = match greed {
            Greed::Greedy => (inner.start, UNSET, false),
            Greed::Lazy => (UNSET, inner.start, true),
        };
        let split = self.add_state(State::Split { first, second })?;
        self.patch_all(&inner.outs, split)?;
        let patch = if exit_is_first {
            Patch::SplitFirst(split)
        } else {
            Patch::SplitSecond(split)
        };
        Ok(Fragment {
            start: inner.start,
            outs: self.one_out(patch)?,
        })
    }

    fn optional_fragment(&mut self, inner: Fragment, greed: Greed) -> Result<Fragment, BuildError> {
        let (first, second, exit_is_first) = match greed {
            Greed::Greedy => (inner.start, UNSET, false),
            Greed::Lazy => (UNSET, inner.start, true),
        };
        let split = self.add_state(State::Split { first, second })?;
        let mut outs = inner.outs;
        let exit = if exit_is_first {
            Patch::SplitFirst(split)
        } else {
            Patch::SplitSecond(split)
        };
        outs.try_reserve(1)
            .map_err(|_| BuildError::Allocation(ResourceKind::PatchEntries))?;
        self.register_patch()?;
        outs.push(exit);
        Ok(Fragment { start: split, outs })
    }

    fn nullable(&mut self, ast: &Ast) -> Result<bool, BuildError> {
        self.tick()?;
        match ast {
            Ast::Empty | Ast::Start | Ast::End | Ast::Assert(_) => Ok(true),
            Ast::Byte(_) | Ast::Class(_) => Ok(false),
            Ast::Capture { child, .. } => self.nullable(child),
            Ast::Repeat { child, min, .. } => {
                if *min == 0 {
                    Ok(true)
                } else {
                    self.nullable(child)
                }
            }
            Ast::Concat(children) => {
                for child in children {
                    if !self.nullable(child)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Ast::Alt(children) => {
                for child in children {
                    if self.nullable(child)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
        }
    }

    fn patch_all(&mut self, patches: &[Patch], target: usize) -> Result<(), BuildError> {
        for &patch in patches {
            self.patch(patch, target)?;
        }
        Ok(())
    }

    fn patch(&mut self, patch: Patch, target: usize) -> Result<(), BuildError> {
        self.tick()?;
        let state = match patch {
            Patch::Next(id) | Patch::SplitFirst(id) | Patch::SplitSecond(id) => self
                .states
                .get_mut(id)
                .ok_or(BuildError::InvalidAst("patch references missing state"))?,
        };
        match (patch, state) {
            (
                Patch::Next(_),
                State::Byte { next, .. }
                | State::Save { next, .. }
                | State::Assert { next, .. }
                | State::Epsilon { next },
            ) => *next = target,
            (Patch::SplitFirst(_), State::Split { first, .. }) => *first = target,
            (Patch::SplitSecond(_), State::Split { second, .. }) => *second = target,
            _ => return Err(BuildError::InvalidAst("patch kind mismatches state")),
        }
        Ok(())
    }

    fn program_bytes(&self) -> Result<usize, BuildError> {
        let state_bytes = self
            .states
            .len()
            .checked_mul(size_of::<State>())
            .ok_or(BuildError::BoundOverflow(ResourceKind::ProgramBytes))?;
        state_bytes
            .checked_add(self.auxiliary_program_bytes)
            .ok_or(BuildError::BoundOverflow(ResourceKind::ProgramBytes))
    }
}

fn checked_inc(value: usize, kind: ResourceKind) -> Result<usize, BuildError> {
    value.checked_add(1).ok_or(BuildError::BoundOverflow(kind))
}

fn check_limit(kind: ResourceKind, required: usize, limit: usize) -> Result<(), BuildError> {
    if required > limit {
        return Err(BuildError::Resource {
            kind,
            required,
            limit,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Program, StartPrefilter};
    use crate::{Assertion, Ast, BuildLimits, CaptureProfile, Greed};

    #[test]
    fn compact_start_prefilter_is_conservative_and_construction_owned() {
        for (ast, expected) in [
            (
                Ast::Byte(0),
                Some(StartPrefilter::ByteSet {
                    bytes: [0, 0, 0],
                    length: 1,
                }),
            ),
            (
                Ast::Byte(b'a'),
                Some(StartPrefilter::ByteSet {
                    bytes: [b'a', 0, 0],
                    length: 1,
                }),
            ),
            (
                Ast::alt([Ast::Byte(b'c'), Ast::Byte(b'a')]),
                Some(StartPrefilter::ByteSet {
                    bytes: [b'a', b'c', 0],
                    length: 2,
                }),
            ),
            (
                Ast::Class(vec![(b'x', b'z')]),
                Some(StartPrefilter::ByteSet {
                    bytes: [b'x', b'y', b'z'],
                    length: 3,
                }),
            ),
            (
                Ast::Class(vec![(63, 65)]),
                Some(StartPrefilter::ByteSet {
                    bytes: [63, 64, 65],
                    length: 3,
                }),
            ),
            (
                Ast::concat([Ast::Assert(Assertion::StartLf), Ast::Byte(b'q')]),
                Some(StartPrefilter::ByteSet {
                    bytes: [b'q', 0, 0],
                    length: 1,
                }),
            ),
            (
                Ast::concat([Ast::Byte(b'a'), Ast::Byte(b'b')]),
                Some(StartPrefilter::ExactPrefix {
                    bytes: [b'a', b'b', 0],
                    length: 2,
                }),
            ),
            (
                Ast::alt([
                    Ast::concat([Ast::Byte(b'a'), Ast::Byte(b'b'), Ast::Byte(b'c')]),
                    Ast::concat([Ast::Byte(b'a'), Ast::Byte(b'b'), Ast::Byte(b'd')]),
                ]),
                Some(StartPrefilter::ExactPrefix {
                    bytes: [b'a', b'b', 0],
                    length: 2,
                }),
            ),
        ] {
            assert_eq!(
                Program::compile(&ast, BuildLimits::default())
                    .unwrap()
                    .start_prefilter(),
                expected,
                "ast={ast:?}",
            );
        }

        for ast in [
            Ast::alt([
                Ast::Byte(b'a'),
                Ast::Byte(b'b'),
                Ast::Byte(b'c'),
                Ast::Byte(b'd'),
            ]),
            Ast::Byte(b'a').repeat(0, Some(1), Greed::Greedy),
            Ast::Class(vec![(0, u8::MAX)]),
            Ast::concat([
                Ast::Assert(Assertion::WordAscii),
                Ast::Assert(Assertion::WordAsciiNegate),
            ]),
        ] {
            assert_eq!(
                Program::compile(&ast, BuildLimits::default())
                    .unwrap()
                    .start_prefilter(),
                None,
                "ast={ast:?}",
            );
        }
    }

    #[test]
    fn exact_consumed_prefix_crosses_zero_width_capture_alternation_and_repeat() {
        for (ast, expected) in [
            (
                Ast::concat([Ast::Byte(0), Ast::Byte(b'b')]),
                StartPrefilter::ExactPrefix {
                    bytes: [0, b'b', 0],
                    length: 2,
                },
            ),
            (
                Ast::concat([
                    Ast::Assert(Assertion::WordAscii),
                    Ast::Byte(b'a').capture(1),
                    Ast::Class(vec![(b'b', b'b')]),
                ]),
                StartPrefilter::ExactPrefix {
                    bytes: [b'a', b'b', 0],
                    length: 2,
                },
            ),
            (
                Ast::Byte(b'a').repeat(3, None, Greed::Greedy),
                StartPrefilter::ExactPrefix {
                    bytes: [b'a', b'a', b'a'],
                    length: 3,
                },
            ),
            (
                Ast::alt([
                    Ast::concat([
                        Ast::Byte(b'a'),
                        Ast::Byte(b'b'),
                        Ast::Byte(b'c'),
                        Ast::Byte(b'x'),
                    ]),
                    Ast::concat([
                        Ast::Byte(b'a'),
                        Ast::Byte(b'b'),
                        Ast::Byte(b'c'),
                        Ast::Byte(b'y'),
                    ]),
                ]),
                StartPrefilter::ExactPrefix {
                    bytes: [b'a', b'b', b'c'],
                    length: 3,
                },
            ),
        ] {
            assert_eq!(
                Program::compile(&ast, BuildLimits::default())
                    .unwrap()
                    .start_prefilter(),
                Some(expected),
                "ast={ast:?}",
            );
        }

        let nullable =
            Ast::concat([Ast::Byte(b'a'), Ast::Byte(b'b')]).repeat(0, None, Greed::Greedy);
        assert_eq!(
            Program::compile(&nullable, BuildLimits::default())
                .unwrap()
                .start_prefilter(),
            None,
        );

        let empty_language_star = Ast::Class(Vec::new()).repeat(0, None, Greed::Greedy);
        assert_eq!(
            Program::compile(&empty_language_star, BuildLimits::default())
                .unwrap()
                .start_prefilter(),
            None,
        );
    }

    #[test]
    fn opaque_nonnullable_mask_preserves_every_arbitrary_first_byte_bit() {
        let ranges = vec![(0, 0), (2, 7), (63, 65), (127, 131), (200, 203), (254, 255)];
        let (_, proof) = Program::compile_for_with_first_byte_proof(
            &Ast::Class(ranges.clone()),
            CaptureProfile::RustRegexBytes1_12_4,
            BuildLimits::default(),
        )
        .expect("arbitrary class compile");
        let mask = proof
            .nonnullable_mask()
            .expect("a one-byte class is non-nullable");
        for byte in 0_u8..=u8::MAX {
            let expected = ranges
                .iter()
                .any(|&(start, end)| start <= byte && byte <= end);
            assert_eq!(mask.matches(byte), expected, "byte={byte}");
        }
        assert!(!mask.is_empty());
        assert!(!mask.is_all());
        assert!(proof.equals_nonnullable_words(mask.words()));

        let (_, nullable) = Program::compile_for_with_first_byte_proof(
            &Ast::Class(ranges).repeat(0, None, Greed::Greedy),
            CaptureProfile::RustRegexBytes1_12_4,
            BuildLimits::default(),
        )
        .expect("nullable class compile");
        assert_eq!(nullable.nonnullable_mask(), None);

        let (_, empty) = Program::compile_for_with_first_byte_proof(
            &Ast::Class(Vec::new()),
            CaptureProfile::RustRegexBytes1_12_4,
            BuildLimits::default(),
        )
        .expect("empty-language class compile");
        assert!(empty.nonnullable_mask().expect("non-nullable").is_empty());

        let (_, all) = Program::compile_for_with_first_byte_proof(
            &Ast::Class(vec![(0, u8::MAX)]),
            CaptureProfile::RustRegexBytes1_12_4,
            BuildLimits::default(),
        )
        .expect("all-byte class compile");
        assert!(all.nonnullable_mask().expect("non-nullable").is_all());
    }
}
