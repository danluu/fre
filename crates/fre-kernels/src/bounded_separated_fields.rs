//! Constant-frontier count reduction for bounded separator-delimited fields.
//!
//! The admitted language is `(FIELD SEP){k} FIELD`, where `SEP` is one byte,
//! every byte accepted by `FIELD` is disjoint from `SEP`, and `FIELD` is a
//! bounded prioritized alternation of fixed byte-class sequences with at most
//! one greedy optional atom per alternative. Separator disjointness makes all
//! non-final field boundaries deterministic. Consequently leftmost-first
//! matching needs no continuation rows: each candidate examines a compile-time
//! bounded window and execution is O(N) with constant storage.

use core::{fmt, mem::size_of};

use crate::{DirectBuildAttempt, DirectBuildAttemptActual, DirectBuildAttemptError};

pub const PLAN_ID: &str = "bounded-separated-fields-count.inline-byte-bitsets.v1";
pub const COUNT_OPERATION_ID: &str = "bounded-separated-fields-count.count.v1";

pub const MAX_ALTERNATIVES: usize = 8;
pub const MAX_ATOMS: usize = 4;
pub const MAX_FIELDS: u32 = 8;
const NO_OPTIONAL: u8 = u8::MAX;
const BITMAP_WORDS: usize = 4;
const FINALIZATION_WORK: usize = 8;
const STRUCTURAL_BUILD_WORK: usize = MAX_ALTERNATIVES * MAX_ATOMS * 8 + 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationIdentity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub separator: u8,
    pub fields: u32,
    pub alternatives: u8,
    pub minimum_field_width: u8,
    pub maximum_field_width: u8,
    pub greedy: bool,
    pub non_overlapping: bool,
    resources: OperationResources,
}

impl OperationIdentity {
    /// Return the immutable construction receipt that owns every resource term
    /// used to derive execution limits for this operation.
    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.resources.build
    }

    /// Return the exact-field byte comparisons charged for one field.
    #[must_use]
    pub const fn exact_field_checks(&self) -> usize {
        self.resources.exact_field_checks
    }

    /// Return the prefix-field byte comparisons charged for the final field.
    #[must_use]
    pub const fn prefix_field_checks(&self) -> usize {
        self.resources.prefix_field_checks
    }
}

#[derive(Clone, Copy, Debug)]
pub enum AtomSource<'a> {
    Ranges(&'a [(u8, u8)]),
    Range(u8, u8),
    Singleton(u8),
}

impl AtomSource<'_> {
    const fn range_count(self) -> usize {
        match self {
            Self::Ranges(ranges) => ranges.len(),
            Self::Range(_, _) | Self::Singleton(_) => 1,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct AlternativeSource<'a> {
    pub atoms: [Option<AtomSource<'a>>; MAX_ATOMS],
    pub atom_count: u8,
    pub optional_index: Option<u8>,
}

impl AlternativeSource<'_> {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            atoms: [None; MAX_ATOMS],
            atom_count: 0,
            optional_index: None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FieldSource<'a> {
    pub alternatives: [Option<AlternativeSource<'a>>; MAX_ALTERNATIVES],
    pub alternative_count: u8,
}

impl FieldSource<'_> {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            alternatives: [None; MAX_ALTERNATIVES],
            alternative_count: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub max_source_ranges: usize,
    pub max_build_work: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            max_source_ranges: 256,
            max_build_work: 1 << 20,
            max_persistent_bytes: 1 << 20,
            max_peak_bytes: 1 << 20,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub alternatives: usize,
    pub atoms: usize,
    pub optional_atoms: usize,
    pub source_ranges: usize,
    pub fields: u32,
    pub separator: u8,
    pub minimum_field_width: usize,
    pub maximum_field_width: usize,
    pub structural_work: usize,
    pub range_inspections: usize,
    pub bitmap_zero_writes: usize,
    pub bitmap_word_writes: usize,
    pub separator_comparisons: usize,
    pub work_bound: usize,
    pub allocations: usize,
    pub reserves: usize,
    pub temporary_copies: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Resource terms derived from the private plan structure. Keeping this field
/// private makes the operation identity the authority: callers can inspect a
/// copy through `OperationIdentity`, but cannot independently mutate its
/// resource terms to agree with a forged public build receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OperationResources {
    build: BuildAccounting,
    exact_field_checks: usize,
    prefix_field_checks: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceLimits {
    pub max_input_bytes: usize,
    pub max_sequential_bytes: usize,
    pub max_count: u64,
    pub max_work: usize,
    pub max_peak_bytes: usize,
}

impl Default for ReduceLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 128 << 20,
            max_sequential_bytes: 1 << 29,
            max_count: 128 << 20,
            max_work: 1 << 29,
            max_peak_bytes: 1 << 20,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceUpperBounds {
    pub input_bytes: usize,
    pub candidates: usize,
    pub separator_inspections: usize,
    pub class_comparisons: usize,
    pub sequential_bytes: usize,
    pub random_access_bytes: usize,
    pub control_charges: usize,
    pub finalization_charges: usize,
    pub work_per_candidate: usize,
    pub work: usize,
    pub match_events: u64,
    pub allocations: usize,
    pub reserves: usize,
    pub temporary_copies: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceActualCounters {
    pub input_bytes: usize,
    pub candidate_starts: usize,
    pub separator_inspections: usize,
    pub class_comparisons: usize,
    pub sequential_bytes: usize,
    pub random_access_bytes: usize,
    pub match_events: u64,
    pub matched_bytes: u64,
    pub work_charged: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceAccounting {
    pub identity: OperationIdentity,
    pub upper_bounds: ReduceUpperBounds,
    pub actual: ReduceActualCounters,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountResult {
    pub count: u64,
    pub accounting: ReduceAccounting,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    InvalidFieldCount {
        fields: u32,
    },
    InvalidAlternativeCount {
        alternatives: u8,
    },
    MissingAlternative {
        index: usize,
    },
    InvalidAtomCount {
        alternative: usize,
        atoms: u8,
    },
    MissingAtom {
        alternative: usize,
        index: usize,
    },
    InvalidOptional {
        alternative: usize,
        index: u8,
    },
    EmptyClass {
        alternative: usize,
        index: usize,
    },
    ReversedRange {
        alternative: usize,
        index: usize,
        start: u8,
        end: u8,
    },
    NonCanonicalRanges {
        alternative: usize,
        index: usize,
    },
    SeparatorInField {
        alternative: usize,
        index: usize,
        separator: u8,
    },
    RangeLimit {
        needed: usize,
        limit: usize,
    },
    WorkLimit {
        needed: usize,
        limit: usize,
    },
    PersistentLimit {
        needed: usize,
        limit: usize,
    },
    PeakLimit {
        needed: usize,
        limit: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bounded separated-field construction failed: {self:?}")
    }
}
impl std::error::Error for BuildError {}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReduceError {
    InputLimit {
        needed: usize,
        limit: usize,
    },
    SequentialLimit {
        needed: usize,
        limit: usize,
    },
    CountLimit {
        needed: u64,
        limit: u64,
    },
    WorkLimit {
        needed: usize,
        limit: usize,
    },
    PeakLimit {
        needed: usize,
        limit: usize,
    },
    AccountingInvariant {
        counter: &'static str,
        actual: usize,
        bound: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for ReduceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bounded separated-field reduction failed: {self:?}")
    }
}
impl std::error::Error for ReduceError {}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct InputAccessCounters {
    separator_inspections: usize,
    class_comparisons: usize,
}

impl InputAccessCounters {
    fn inspect_separator(&mut self) -> Result<(), ReduceError> {
        self.separator_inspections =
            self.separator_inspections
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "actual separator inspections",
                })?;
        Ok(())
    }

    fn compare_class(&mut self) -> Result<(), ReduceError> {
        self.class_comparisons =
            self.class_comparisons
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "actual class comparisons",
                })?;
        Ok(())
    }

    fn sequential_bytes(self) -> Result<usize, ReduceError> {
        self.separator_inspections
            .checked_add(self.class_comparisons)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual sequential input bytes",
            })
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct ByteClass([u64; BITMAP_WORDS]);

impl ByteClass {
    fn build(
        source: AtomSource<'_>,
        alternative: usize,
        index: usize,
        actual: &mut DirectBuildAttemptActual,
    ) -> Result<(Self, usize), BuildError> {
        let mut result = Self::default();
        let mut writes = 0_usize;
        match source {
            AtomSource::Singleton(byte) => {
                charge_attempt_work(actual, 1)?;
                result.insert(byte);
                charge_attempt_work(actual, 1)?;
                writes = 1;
            }
            AtomSource::Range(start, end) => {
                charge_attempt_work(actual, 1)?;
                charge_attempt_work(actual, 1)?;
                if start > end {
                    return Err(BuildError::ReversedRange {
                        alternative,
                        index,
                        start,
                        end,
                    });
                }
                writes = result.insert_range(start, end, actual)?;
            }
            AtomSource::Ranges(ranges) => {
                if ranges.is_empty() {
                    return Err(BuildError::EmptyClass { alternative, index });
                }
                let mut previous_end = None;
                for &(start, end) in ranges {
                    charge_attempt_work(actual, 1)?;
                    if start > end {
                        charge_attempt_work(actual, 1)?;
                        return Err(BuildError::ReversedRange {
                            alternative,
                            index,
                            start,
                            end,
                        });
                    }
                    charge_attempt_work(actual, 1)?;
                    if let Some(previous) = previous_end {
                        charge_attempt_work(actual, 1)?;
                        if previous >= start {
                            return Err(BuildError::NonCanonicalRanges { alternative, index });
                        }
                    }
                    previous_end = Some(end);
                    let words = result.insert_range(start, end, actual)?;
                    writes = writes
                        .checked_add(words)
                        .ok_or(BuildError::ArithmeticOverflow {
                            computation: "bitmap word writes",
                        })?;
                }
            }
        }
        Ok((result, writes))
    }

    fn insert_range(
        &mut self,
        start: u8,
        end: u8,
        actual: &mut DirectBuildAttemptActual,
    ) -> Result<usize, BuildError> {
        debug_assert!(start <= end);
        let first = usize::from(start) >> 6;
        let last = usize::from(end) >> 6;
        for word in first..=last {
            let first_bit = if word == first {
                u32::from(start) & 63
            } else {
                0
            };
            let last_bit = if word == last {
                u32::from(end) & 63
            } else {
                63
            };
            let first_mask =
                u64::MAX
                    .checked_shl(first_bit)
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "bitmap first shift",
                    })?;
            let last_mask = u64::MAX
                .checked_shr(63_u32.checked_sub(last_bit).ok_or(
                    BuildError::ArithmeticOverflow {
                        computation: "bitmap last shift",
                    },
                )?)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "bitmap last shift",
                })?;
            self.0[word] |= first_mask & last_mask;
            charge_attempt_work(actual, 1)?;
        }
        last.checked_sub(first)
            .and_then(|words| words.checked_add(1))
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "bitmap words per range",
            })
    }

    fn insert(&mut self, byte: u8) {
        let word = usize::from(byte) >> 6;
        self.0[word] |= 1_u64 << (u32::from(byte) & 63);
    }

    fn contains(self, byte: u8) -> bool {
        self.0[usize::from(byte) >> 6] & (1_u64 << (u32::from(byte) & 63)) != 0
    }
}

fn charge_attempt_work(
    actual: &mut DirectBuildAttemptActual,
    amount: usize,
) -> Result<(), BuildError> {
    actual.work = actual
        .work
        .checked_add(
            u64::try_from(amount).map_err(|_| BuildError::ArithmeticOverflow {
                computation: "exact build work conversion",
            })?,
        )
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "exact build work",
        })?;
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct Alternative {
    atoms: [ByteClass; MAX_ATOMS],
    atom_count: u8,
    optional_index: u8,
}

impl Alternative {
    const EMPTY: Self = Self {
        atoms: [ByteClass([0; BITMAP_WORDS]); MAX_ATOMS],
        atom_count: 0,
        optional_index: NO_OPTIONAL,
    };

    fn minimum_width(self) -> usize {
        if self.optional_index == NO_OPTIONAL {
            usize::from(self.atom_count)
        } else {
            usize::from(self.atom_count).saturating_sub(1)
        }
    }

    fn maximum_width(self) -> usize {
        usize::from(self.atom_count)
    }

    fn matches_exact(
        self,
        bytes: &[u8],
        accesses: &mut InputAccessCounters,
    ) -> Result<bool, ReduceError> {
        let optional = usize::from(self.optional_index);
        if bytes.len() == self.maximum_width() {
            for (class, &byte) in self.atoms.iter().zip(bytes).take(self.maximum_width()) {
                accesses.compare_class()?;
                if !class.contains(byte) {
                    return Ok(false);
                }
            }
            return Ok(true);
        }
        if self.optional_index != NO_OPTIONAL && bytes.len() == self.minimum_width() {
            for ((_, class), &byte) in self
                .atoms
                .iter()
                .take(self.maximum_width())
                .enumerate()
                .filter(|(index, _)| *index != optional)
                .zip(bytes)
            {
                accesses.compare_class()?;
                if !class.contains(byte) {
                    return Ok(false);
                }
            }
            return Ok(true);
        }
        Ok(false)
    }

    fn match_prefix(
        self,
        bytes: &[u8],
        accesses: &mut InputAccessCounters,
    ) -> Result<Option<usize>, ReduceError> {
        let maximum = self.maximum_width();
        if bytes.len() >= maximum {
            let mut matches = true;
            for (class, &byte) in self.atoms.iter().zip(bytes).take(maximum) {
                accesses.compare_class()?;
                if !class.contains(byte) {
                    matches = false;
                    break;
                }
            }
            if matches {
                return Ok(Some(maximum));
            }
        }
        let minimum = self.minimum_width();
        if self.optional_index != NO_OPTIONAL && bytes.len() >= minimum {
            let optional = usize::from(self.optional_index);
            let mut matches = true;
            for ((_, class), &byte) in self
                .atoms
                .iter()
                .take(maximum)
                .enumerate()
                .filter(|(index, _)| *index != optional)
                .zip(bytes)
            {
                accesses.compare_class()?;
                if !class.contains(byte) {
                    matches = false;
                    break;
                }
            }
            if matches {
                return Ok(Some(minimum));
            }
        }
        Ok(None)
    }
}

#[derive(Clone, Debug)]
pub struct BoundedSeparatedFieldsPlan {
    alternatives: [Alternative; MAX_ALTERNATIVES],
    alternative_count: u8,
    separator: u8,
    fields: u32,
    minimum_field_width: u8,
    maximum_field_width: u8,
    exact_field_checks: usize,
    prefix_field_checks: usize,
    build: BuildAccounting,
}

impl BoundedSeparatedFieldsPlan {
    #[allow(
        clippy::too_many_lines,
        reason = "all fixed-array preflight and writes remain adjacent"
    )]
    pub fn build(
        source: FieldSource<'_>,
        separator: u8,
        fields: u32,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        Self::build_attempt(source, separator, fields, limits)
            .map(DirectBuildAttempt::into_plan)
            .map_err(DirectBuildAttemptError::into_source)
    }

    /// Build while retaining exact successful or partial terminal effects.
    #[allow(
        clippy::too_many_lines,
        reason = "all fixed-array preflight and exact observed writes remain adjacent"
    )]
    pub fn build_attempt(
        source: FieldSource<'_>,
        separator: u8,
        fields: u32,
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>> {
        let scratch_bytes = size_of::<FieldSource<'_>>();
        let mut actual = DirectBuildAttemptActual {
            copied_bytes: scratch_bytes,
            initialized_bytes: scratch_bytes,
            peak_bytes: scratch_bytes,
            ..DirectBuildAttemptActual::default()
        };
        let result = (|| {
            if STRUCTURAL_BUILD_WORK > limits.max_build_work {
                return Err(BuildError::WorkLimit {
                    needed: STRUCTURAL_BUILD_WORK,
                    limit: limits.max_build_work,
                });
            }
            if !(2..=MAX_FIELDS).contains(&fields) {
                return Err(BuildError::InvalidFieldCount { fields });
            }
            let alternative_count = usize::from(source.alternative_count);
            if alternative_count == 0 || alternative_count > MAX_ALTERNATIVES {
                return Err(BuildError::InvalidAlternativeCount {
                    alternatives: source.alternative_count,
                });
            }

            let mut atoms = 0_usize;
            let mut optional_atoms = 0_usize;
            let mut source_ranges = 0_usize;
            for alternative_index in 0..alternative_count {
                let alternative = source.alternatives[alternative_index].ok_or(
                    BuildError::MissingAlternative {
                        index: alternative_index,
                    },
                )?;
                let atom_count = usize::from(alternative.atom_count);
                if atom_count == 0 || atom_count > MAX_ATOMS {
                    return Err(BuildError::InvalidAtomCount {
                        alternative: alternative_index,
                        atoms: alternative.atom_count,
                    });
                }
                if let Some(optional) = alternative.optional_index {
                    if usize::from(optional) >= atom_count {
                        return Err(BuildError::InvalidOptional {
                            alternative: alternative_index,
                            index: optional,
                        });
                    }
                    optional_atoms =
                        optional_atoms
                            .checked_add(1)
                            .ok_or(BuildError::ArithmeticOverflow {
                                computation: "optional atom count",
                            })?;
                }
                atoms = atoms
                    .checked_add(atom_count)
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "atom count",
                    })?;
                for atom_index in 0..atom_count {
                    let atom = alternative.atoms[atom_index].ok_or(BuildError::MissingAtom {
                        alternative: alternative_index,
                        index: atom_index,
                    })?;
                    source_ranges = source_ranges.checked_add(atom.range_count()).ok_or(
                        BuildError::ArithmeticOverflow {
                            computation: "source range count",
                        },
                    )?;
                }
            }
            if source_ranges > limits.max_source_ranges {
                return Err(BuildError::RangeLimit {
                    needed: source_ranges,
                    limit: limits.max_source_ranges,
                });
            }
            let work_bound = source_ranges
                .checked_mul(7)
                .and_then(|work| work.checked_add(STRUCTURAL_BUILD_WORK))
                .and_then(|work| work.checked_add(atoms))
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "build work bound",
                })?;
            if work_bound > limits.max_build_work {
                return Err(BuildError::WorkLimit {
                    needed: work_bound,
                    limit: limits.max_build_work,
                });
            }
            let persistent_bytes = size_of::<Self>();
            let peak_bytes = persistent_bytes.checked_add(scratch_bytes).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "build peak bytes",
                },
            )?;
            if persistent_bytes > limits.max_persistent_bytes {
                return Err(BuildError::PersistentLimit {
                    needed: persistent_bytes,
                    limit: limits.max_persistent_bytes,
                });
            }
            if peak_bytes > limits.max_peak_bytes {
                return Err(BuildError::PeakLimit {
                    needed: peak_bytes,
                    limit: limits.max_peak_bytes,
                });
            }

            charge_attempt_work(&mut actual, STRUCTURAL_BUILD_WORK)?;
            let mut alternatives = [Alternative::EMPTY; MAX_ALTERNATIVES];
            let mut minimum_field_width = usize::MAX;
            let mut maximum_field_width = 0_usize;
            let mut exact_field_checks = 0_usize;
            let mut prefix_field_checks = 0_usize;
            let mut bitmap_word_writes = 0_usize;
            for (alternative_index, destination) in
                alternatives.iter_mut().enumerate().take(alternative_count)
            {
                let source_alternative = source.alternatives[alternative_index].ok_or(
                    BuildError::MissingAlternative {
                        index: alternative_index,
                    },
                )?;
                let atom_count = usize::from(source_alternative.atom_count);
                let mut built = Alternative {
                    atom_count: source_alternative.atom_count,
                    optional_index: source_alternative.optional_index.unwrap_or(NO_OPTIONAL),
                    ..Alternative::EMPTY
                };
                for atom_index in 0..atom_count {
                    let atom_source =
                        source_alternative.atoms[atom_index].ok_or(BuildError::MissingAtom {
                            alternative: alternative_index,
                            index: atom_index,
                        })?;
                    let (atom, writes) =
                        ByteClass::build(atom_source, alternative_index, atom_index, &mut actual)?;
                    charge_attempt_work(&mut actual, 1)?;
                    if atom.contains(separator) {
                        return Err(BuildError::SeparatorInField {
                            alternative: alternative_index,
                            index: atom_index,
                            separator,
                        });
                    }
                    built.atoms[atom_index] = atom;
                    bitmap_word_writes = bitmap_word_writes.checked_add(writes).ok_or(
                        BuildError::ArithmeticOverflow {
                            computation: "bitmap word writes",
                        },
                    )?;
                }
                minimum_field_width = minimum_field_width.min(built.minimum_width());
                maximum_field_width = maximum_field_width.max(built.maximum_width());
                exact_field_checks = exact_field_checks.checked_add(atom_count).ok_or(
                    BuildError::ArithmeticOverflow {
                        computation: "exact field checks",
                    },
                )?;
                let absent_checks = if built.optional_index == NO_OPTIONAL {
                    0
                } else {
                    atom_count
                        .checked_sub(1)
                        .ok_or(BuildError::ArithmeticOverflow {
                            computation: "optional alternative required atoms",
                        })?
                };
                prefix_field_checks = prefix_field_checks
                    .checked_add(atom_count)
                    .and_then(|checks| checks.checked_add(absent_checks))
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "prefix field checks",
                    })?;
                *destination = built;
            }
            let minimum_field_width_u8 =
                u8::try_from(minimum_field_width).map_err(|_| BuildError::ArithmeticOverflow {
                    computation: "minimum field width",
                })?;
            let maximum_field_width_u8 =
                u8::try_from(maximum_field_width).map_err(|_| BuildError::ArithmeticOverflow {
                    computation: "maximum field width",
                })?;
            let bitmap_zero_writes = MAX_ALTERNATIVES
                .checked_mul(MAX_ATOMS)
                .and_then(|writes| writes.checked_mul(BITMAP_WORDS))
                .and_then(|writes| {
                    atoms
                        .checked_mul(BITMAP_WORDS)
                        .and_then(|atom_writes| writes.checked_add(atom_writes))
                })
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "bitmap zero writes",
                })?;
            let build = BuildAccounting {
                alternatives: alternative_count,
                atoms,
                optional_atoms,
                source_ranges,
                fields,
                separator,
                minimum_field_width,
                maximum_field_width,
                structural_work: STRUCTURAL_BUILD_WORK,
                range_inspections: source_ranges,
                bitmap_zero_writes,
                bitmap_word_writes,
                separator_comparisons: atoms,
                work_bound,
                allocations: 0,
                reserves: 0,
                temporary_copies: 1,
                scratch_bytes,
                persistent_bytes,
                peak_bytes,
            };
            debug_assert!(actual.work <= u64::try_from(work_bound).unwrap_or(u64::MAX));
            actual.initialized_bytes = actual
                .initialized_bytes
                .checked_add(persistent_bytes)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "exact initialized bytes",
                })?;
            actual.live_persistent_bytes = persistent_bytes;
            actual.peak_bytes = peak_bytes;
            Ok(Self {
                alternatives,
                alternative_count: source.alternative_count,
                separator,
                fields,
                minimum_field_width: minimum_field_width_u8,
                maximum_field_width: maximum_field_width_u8,
                exact_field_checks,
                prefix_field_checks,
                build,
            })
        })();
        match result {
            Ok(plan) => Ok(DirectBuildAttempt::new(plan, actual)),
            Err(source) => {
                actual.live_persistent_bytes = 0;
                Err(DirectBuildAttemptError::new(source, actual))
            }
        }
    }

    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.build
    }

    #[must_use]
    pub const fn count_identity(&self) -> OperationIdentity {
        OperationIdentity {
            plan_id: PLAN_ID,
            operation_id: COUNT_OPERATION_ID,
            separator: self.separator,
            fields: self.fields,
            alternatives: self.alternative_count,
            minimum_field_width: self.minimum_field_width,
            maximum_field_width: self.maximum_field_width,
            greedy: true,
            non_overlapping: true,
            resources: OperationResources {
                build: self.build,
                exact_field_checks: self.exact_field_checks,
                prefix_field_checks: self.prefix_field_checks,
            },
        }
    }

    pub fn count(&self, haystack: &[u8], limits: ReduceLimits) -> Result<CountResult, ReduceError> {
        let upper_bounds = self.preflight(haystack.len(), limits)?;
        let actual = self.execute(haystack, upper_bounds)?;
        Ok(CountResult {
            count: actual.match_events,
            accounting: ReduceAccounting {
                identity: self.count_identity(),
                upper_bounds,
                actual,
            },
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the complete execution envelope is derived before the first input read"
    )]
    fn preflight(
        &self,
        input_bytes: usize,
        limits: ReduceLimits,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        if input_bytes > limits.max_input_bytes {
            return Err(ReduceError::InputLimit {
                needed: input_bytes,
                limit: limits.max_input_bytes,
            });
        }
        let fields = usize::try_from(self.fields).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "field count as usize",
        })?;
        let nonfinal = fields
            .checked_sub(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "non-final field count",
            })?;
        // A maximum-width field is followed by its separator at offset
        // `maximum_field_width`, so the successful scan includes one more
        // byte than the field itself.
        let separator_scan_width = usize::from(self.maximum_field_width).checked_add(1).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "separator scan width",
            },
        )?;
        let separator_inspections_per_candidate = nonfinal
            .checked_mul(separator_scan_width)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "separator inspections per candidate",
            })?;
        let class_comparisons_per_candidate = nonfinal
            .checked_mul(self.exact_field_checks)
            .and_then(|checks| checks.checked_add(self.prefix_field_checks))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "class comparisons per candidate",
            })?;
        // Bounds loop tests, state updates, and checked index arithmetic. Byte
        // inspections themselves are charged in the two categories above.
        let alternative_field_checks = usize::from(self.alternative_count)
            .checked_mul(fields)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "alternative-field control charges",
            })?;
        let control_per_candidate = fields
            .checked_mul(3)
            .and_then(|charges| charges.checked_add(alternative_field_checks))
            .and_then(|charges| charges.checked_add(4))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "control charges per candidate",
            })?;
        let work_per_candidate = separator_inspections_per_candidate
            .checked_add(class_comparisons_per_candidate)
            .and_then(|work| work.checked_add(control_per_candidate))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "work per candidate",
            })?;
        let separator_inspections = input_bytes
            .checked_mul(separator_inspections_per_candidate)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "separator inspection bound",
            })?;
        let class_comparisons = input_bytes
            .checked_mul(class_comparisons_per_candidate)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "class comparison bound",
            })?;
        // Every haystack-byte visit is prospective sequential traffic. The
        // implementation owns no table, log, ring, or other random-access
        // execution storage, so its random-access byte requirement is zero.
        let sequential_bytes = separator_inspections.checked_add(class_comparisons).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "sequential input access bound",
            },
        )?;
        if sequential_bytes > limits.max_sequential_bytes {
            return Err(ReduceError::SequentialLimit {
                needed: sequential_bytes,
                limit: limits.max_sequential_bytes,
            });
        }
        let control_charges = input_bytes.checked_mul(control_per_candidate).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "control charge bound",
            },
        )?;
        let work = input_bytes
            .checked_mul(work_per_candidate)
            .and_then(|work| work.checked_add(FINALIZATION_WORK))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "execution work bound",
            })?;
        if work > limits.max_work {
            return Err(ReduceError::WorkLimit {
                needed: work,
                limit: limits.max_work,
            });
        }
        let minimum_match_width = fields
            .checked_mul(usize::from(self.minimum_field_width))
            .and_then(|width| width.checked_add(nonfinal))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "minimum match width",
            })?;
        let match_event_bound = input_bytes.checked_div(minimum_match_width).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "match event division",
            },
        )?;
        let match_events =
            u64::try_from(match_event_bound).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "match event bound",
            })?;
        if match_events > limits.max_count {
            return Err(ReduceError::CountLimit {
                needed: match_events,
                limit: limits.max_count,
            });
        }
        let persistent_bytes = self.build.persistent_bytes;
        if persistent_bytes > limits.max_peak_bytes {
            return Err(ReduceError::PeakLimit {
                needed: persistent_bytes,
                limit: limits.max_peak_bytes,
            });
        }
        Ok(ReduceUpperBounds {
            input_bytes,
            candidates: input_bytes,
            separator_inspections,
            class_comparisons,
            sequential_bytes,
            random_access_bytes: 0,
            control_charges,
            finalization_charges: FINALIZATION_WORK,
            work_per_candidate,
            work,
            match_events,
            allocations: 0,
            reserves: 0,
            temporary_copies: 0,
            scratch_bytes: 0,
            persistent_bytes,
            peak_bytes: persistent_bytes,
        })
    }

    fn execute(
        &self,
        haystack: &[u8],
        upper: ReduceUpperBounds,
    ) -> Result<ReduceActualCounters, ReduceError> {
        let mut start = 0_usize;
        let mut candidate_starts = 0_usize;
        let mut matches = 0_u64;
        let mut matched_bytes = 0_u64;
        let mut accesses = InputAccessCounters::default();
        while start < haystack.len() {
            candidate_starts =
                candidate_starts
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "candidate starts",
                    })?;
            if let Some(end) = self.match_at(haystack, start, &mut accesses)? {
                matches = matches
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "match count",
                    })?;
                let matched_width =
                    end.checked_sub(start)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "matched width subtraction",
                        })?;
                matched_bytes = matched_bytes
                    .checked_add(u64::try_from(matched_width).map_err(|_| {
                        ReduceError::ArithmeticOverflow {
                            computation: "matched width",
                        }
                    })?)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "matched byte sum",
                    })?;
                start = end;
            } else {
                start = start
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "candidate advance",
                    })?;
            }
        }
        let sequential_bytes = accesses.sequential_bytes()?;
        for (counter, actual, bound) in [
            (
                "separator inspections",
                accesses.separator_inspections,
                upper.separator_inspections,
            ),
            (
                "class comparisons",
                accesses.class_comparisons,
                upper.class_comparisons,
            ),
            ("sequential bytes", sequential_bytes, upper.sequential_bytes),
        ] {
            if actual > bound {
                return Err(ReduceError::AccountingInvariant {
                    counter,
                    actual,
                    bound,
                });
            }
        }
        Ok(ReduceActualCounters {
            input_bytes: haystack.len(),
            candidate_starts,
            separator_inspections: accesses.separator_inspections,
            class_comparisons: accesses.class_comparisons,
            sequential_bytes,
            random_access_bytes: 0,
            match_events: matches,
            matched_bytes,
            work_charged: upper.work,
        })
    }

    fn match_at(
        &self,
        haystack: &[u8],
        start: usize,
        accesses: &mut InputAccessCounters,
    ) -> Result<Option<usize>, ReduceError> {
        let mut cursor = start;
        for _ in 1..self.fields {
            let Some(remaining) = haystack.get(cursor..) else {
                return Ok(None);
            };
            let window = remaining
                .len()
                .min(usize::from(self.maximum_field_width) + 1);
            let mut separator_offset = None;
            for (offset, &byte) in remaining[..window].iter().enumerate() {
                accesses.inspect_separator()?;
                if byte == self.separator {
                    separator_offset = Some(offset);
                    break;
                }
            }
            let Some(separator_offset) = separator_offset else {
                return Ok(None);
            };
            if !self.field_matches_exact(&remaining[..separator_offset], accesses)? {
                return Ok(None);
            }
            let Some(after_field) = cursor.checked_add(separator_offset) else {
                return Ok(None);
            };
            let Some(after_separator) = after_field.checked_add(1) else {
                return Ok(None);
            };
            cursor = after_separator;
        }
        let Some(final_bytes) = haystack.get(cursor..) else {
            return Ok(None);
        };
        let Some(width) = self.field_match_prefix(final_bytes, accesses)? else {
            return Ok(None);
        };
        Ok(cursor.checked_add(width))
    }

    fn field_matches_exact(
        &self,
        bytes: &[u8],
        accesses: &mut InputAccessCounters,
    ) -> Result<bool, ReduceError> {
        for alternative in &self.alternatives[..usize::from(self.alternative_count)] {
            if alternative.matches_exact(bytes, accesses)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn field_match_prefix(
        &self,
        bytes: &[u8],
        accesses: &mut InputAccessCounters,
    ) -> Result<Option<usize>, ReduceError> {
        for alternative in &self.alternatives[..usize::from(self.alternative_count)] {
            if let Some(width) = alternative.match_prefix(bytes, accesses)? {
                return Ok(Some(width));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AlternativeSource, AtomSource, BoundedSeparatedFieldsPlan, BuildError, BuildLimits,
        FieldSource, InputAccessCounters, MAX_ALTERNATIVES, ReduceError, ReduceLimits,
    };

    const DIGIT: &[(u8, u8)] = &[(b'0', b'9')];
    const ZERO_ONE: &[(u8, u8)] = &[(b'0', b'1')];
    const ZERO_FOUR: &[(u8, u8)] = &[(b'0', b'4')];
    const ZERO_FIVE: &[(u8, u8)] = &[(b'0', b'5')];

    fn ip_source() -> FieldSource<'static> {
        let mut source = FieldSource::empty();
        let mut first = AlternativeSource::empty();
        first.atoms[..3].copy_from_slice(&[
            Some(AtomSource::Singleton(b'2')),
            Some(AtomSource::Singleton(b'5')),
            Some(AtomSource::Ranges(ZERO_FIVE)),
        ]);
        first.atom_count = 3;
        let mut second = AlternativeSource::empty();
        second.atoms[..3].copy_from_slice(&[
            Some(AtomSource::Singleton(b'2')),
            Some(AtomSource::Ranges(ZERO_FOUR)),
            Some(AtomSource::Ranges(DIGIT)),
        ]);
        second.atom_count = 3;
        let mut third = AlternativeSource::empty();
        third.atoms[..3].copy_from_slice(&[
            Some(AtomSource::Ranges(ZERO_ONE)),
            Some(AtomSource::Ranges(DIGIT)),
            Some(AtomSource::Ranges(DIGIT)),
        ]);
        third.atom_count = 3;
        third.optional_index = Some(0);
        source.alternatives[..3].copy_from_slice(&[Some(first), Some(second), Some(third)]);
        source.alternative_count = 3;
        source
    }

    fn plan() -> BoundedSeparatedFieldsPlan {
        BoundedSeparatedFieldsPlan::build(ip_source(), b'.', 4, BuildLimits::default()).unwrap()
    }

    fn two_field_source() -> FieldSource<'static> {
        const ZERO_TWO: &[(u8, u8)] = &[(b'0', b'2')];
        let mut source = FieldSource::empty();
        let mut first = AlternativeSource::empty();
        first.atoms[..2].copy_from_slice(&[
            Some(AtomSource::Singleton(b'1')),
            Some(AtomSource::Ranges(ZERO_TWO)),
        ]);
        first.atom_count = 2;
        let mut second = AlternativeSource::empty();
        second.atoms[..2].copy_from_slice(&[
            Some(AtomSource::Ranges(ZERO_ONE)),
            Some(AtomSource::Ranges(ZERO_TWO)),
        ]);
        second.atom_count = 2;
        second.optional_index = Some(0);
        source.alternatives[..2].copy_from_slice(&[Some(first), Some(second)]);
        source.alternative_count = 2;
        source
    }

    fn one_atom_source(atom: AtomSource<'static>, optional: bool) -> FieldSource<'static> {
        let mut source = FieldSource::empty();
        let mut alternative = AlternativeSource::empty();
        alternative.atoms[0] = Some(atom);
        alternative.atom_count = 1;
        alternative.optional_index = optional.then_some(0);
        source.alternatives[0] = Some(alternative);
        source.alternative_count = 1;
        source
    }

    #[test]
    fn prioritized_optional_backtracking_and_non_overlapping_count() {
        let plan = plan();
        let mut accesses = InputAccessCounters::default();
        assert!(plan.field_matches_exact(b"19", &mut accesses).unwrap());
        let mut accesses = InputAccessCounters::default();
        assert_eq!(
            plan.field_match_prefix(b"19y", &mut accesses).unwrap(),
            Some(2)
        );
        let mut accesses = InputAccessCounters::default();
        assert_eq!(
            plan.match_at(b"x19.19.19.19y19.19.19.19", 1, &mut accesses)
                .unwrap(),
            Some(12)
        );
        let mut accesses = InputAccessCounters::default();
        assert_eq!(
            plan.match_at(b"x19.19.19.19y19.19.19.19", 13, &mut accesses)
                .unwrap(),
            Some(24)
        );
        for (haystack, expected) in [
            (b"255.249.199.99".as_slice(), 1),
            (b"x19.19.19.19y19.19.19.19", 2),
            (b"999.999.999.999", 0),
            (b"25.25.25.25", 1),
            (b"255.255.255.", 0),
            (b"255x255.255.255", 0),
        ] {
            assert_eq!(
                plan.count(haystack, ReduceLimits::default()).unwrap().count,
                expected,
                "{}",
                String::from_utf8_lossy(haystack)
            );
        }
    }

    #[test]
    fn exact_work_limit_and_one_below_fail_closed() {
        let plan = plan();
        let haystack = b"255.249.199.99";
        let exact = plan
            .count(haystack, ReduceLimits::default())
            .unwrap()
            .accounting
            .upper_bounds
            .work;
        let mut limits = ReduceLimits {
            max_work: exact,
            ..ReduceLimits::default()
        };
        assert_eq!(plan.count(haystack, limits).unwrap().count, 1);
        limits.max_work = exact - 1;
        assert_eq!(
            plan.count(haystack, limits).unwrap_err(),
            ReduceError::WorkLimit {
                needed: exact,
                limit: exact - 1
            }
        );
    }

    #[test]
    fn exhaustive_small_differential_matches_regex_1_12_4() {
        fn visit(
            plan: &BoundedSeparatedFieldsPlan,
            reference: &regex::bytes::Regex,
            alphabet: &[u8],
            haystack: &mut Vec<u8>,
            remaining: usize,
        ) {
            let expected = u64::try_from(reference.find_iter(haystack).count()).unwrap();
            let actual = plan.count(haystack, ReduceLimits::default()).unwrap().count;
            assert_eq!(actual, expected, "haystack={haystack:?}");
            if remaining == 0 {
                return;
            }
            for &byte in alphabet {
                haystack.push(byte);
                visit(plan, reference, alphabet, haystack, remaining - 1);
                haystack.pop();
            }
        }

        let plan =
            BoundedSeparatedFieldsPlan::build(two_field_source(), b'.', 2, BuildLimits::default())
                .unwrap();
        let reference =
            regex::bytes::RegexBuilder::new(r"(?-u:(?:1[0-2]|[01]?[0-2])\.(?:1[0-2]|[01]?[0-2]))")
                .unicode(false)
                .build()
                .unwrap();
        visit(&plan, &reference, b"012.x", &mut Vec::new(), 7);
    }

    #[test]
    fn two_through_eight_fields_publish_exact_prospective_access_bounds() {
        for fields in 2..=8 {
            let plan = BoundedSeparatedFieldsPlan::build(
                one_atom_source(AtomSource::Singleton(b'a'), false),
                b':',
                fields,
                BuildLimits::default(),
            )
            .unwrap();
            let mut haystack = Vec::new();
            for field in 0..fields {
                if field != 0 {
                    haystack.push(b':');
                }
                haystack.push(b'a');
            }
            let result = plan.count(&haystack, ReduceLimits::default()).unwrap();
            assert_eq!(result.count, 1, "fields={fields}");
            let fields = usize::try_from(fields).unwrap();
            let per_candidate = fields
                .checked_sub(1)
                .and_then(|nonfinal| nonfinal.checked_mul(2))
                .and_then(|separators| separators.checked_add(fields))
                .unwrap();
            let exact = haystack.len().checked_mul(per_candidate).unwrap();
            assert_eq!(
                result.accounting.upper_bounds.sequential_bytes, exact,
                "fields={fields}"
            );
            assert_eq!(result.accounting.upper_bounds.random_access_bytes, 0);
            assert!(result.accounting.actual.sequential_bytes <= exact);
            assert_eq!(
                result.accounting.actual.sequential_bytes,
                result
                    .accounting
                    .actual
                    .separator_inspections
                    .checked_add(result.accounting.actual.class_comparisons)
                    .unwrap()
            );
            let mut limits = ReduceLimits {
                max_sequential_bytes: exact,
                ..ReduceLimits::default()
            };
            assert_eq!(plan.count(&haystack, limits).unwrap().count, 1);
            limits.max_sequential_bytes = exact.checked_sub(1).unwrap();
            assert_eq!(
                plan.count(&haystack, limits).unwrap_err(),
                ReduceError::SequentialLimit {
                    needed: exact,
                    limit: exact - 1,
                },
                "fields={fields}"
            );
        }

        let plan = BoundedSeparatedFieldsPlan::build(
            one_atom_source(AtomSource::Singleton(b'a'), false),
            b':',
            2,
            BuildLimits::default(),
        )
        .unwrap();
        let overlap = plan.count(b"aaaa", ReduceLimits::default()).unwrap();
        assert_eq!(overlap.count, 0);
        assert_eq!(overlap.accounting.actual.separator_inspections, 7);
        assert_eq!(overlap.accounting.actual.class_comparisons, 0);
        assert_eq!(overlap.accounting.actual.sequential_bytes, 7);
    }

    #[test]
    fn empty_capable_priority_invalid_bytes_and_crlf_remain_raw_byte_semantics() {
        let optional = BoundedSeparatedFieldsPlan::build(
            one_atom_source(AtomSource::Singleton(b'a'), true),
            b'|',
            2,
            BuildLimits::default(),
        )
        .unwrap();
        for (haystack, expected) in [
            (b"".as_slice(), 0),
            (b"|".as_slice(), 1),
            (b"||".as_slice(), 2),
            (b"a|".as_slice(), 1),
            (b"|a".as_slice(), 1),
            (b"a|a".as_slice(), 1),
            (b"aa".as_slice(), 0),
        ] {
            let result = optional.count(haystack, ReduceLimits::default()).unwrap();
            assert_eq!(result.count, expected, "haystack={haystack:?}");
            assert_eq!(result.accounting.upper_bounds.random_access_bytes, 0);
            assert_eq!(result.accounting.actual.random_access_bytes, 0);
            assert!(
                result.accounting.actual.sequential_bytes
                    <= result.accounting.upper_bounds.sequential_bytes
            );
        }

        let mut prioritized = FieldSource::empty();
        let mut optional_a = AlternativeSource::empty();
        optional_a.atoms[0] = Some(AtomSource::Singleton(b'a'));
        optional_a.atom_count = 1;
        optional_a.optional_index = Some(0);
        let mut ab = AlternativeSource::empty();
        ab.atoms[0] = Some(AtomSource::Singleton(b'a'));
        ab.atoms[1] = Some(AtomSource::Singleton(b'b'));
        ab.atom_count = 2;
        prioritized.alternatives[..2].copy_from_slice(&[Some(optional_a), Some(ab)]);
        prioritized.alternative_count = 2;
        let prioritized =
            BoundedSeparatedFieldsPlan::build(prioritized, b'|', 2, BuildLimits::default())
                .unwrap();
        let mut accesses = InputAccessCounters::default();
        assert_eq!(
            prioritized.match_at(b"ab|ab", 0, &mut accesses).unwrap(),
            Some(4),
            "the final field must retain first-alternative priority"
        );

        for separator in [b'\r', b'\n'] {
            let raw = BoundedSeparatedFieldsPlan::build(
                one_atom_source(AtomSource::Singleton(0xFF), false),
                separator,
                2,
                BuildLimits::default(),
            )
            .unwrap();
            let haystack = [0xFF, separator, 0xFF, b'x', 0xFE, separator, 0xFF];
            let result = raw.count(&haystack, ReduceLimits::default()).unwrap();
            assert_eq!(result.count, 1, "separator={separator:?}");
            assert!(result.accounting.actual.sequential_bytes > 0);
        }
    }

    #[test]
    fn every_public_resource_bound_is_checked_before_execution() {
        let accounting = plan().build_accounting();

        let mut build = BuildLimits {
            max_build_work: accounting.work_bound,
            ..BuildLimits::default()
        };
        assert!(BoundedSeparatedFieldsPlan::build(ip_source(), b'.', 4, build).is_ok());
        build.max_build_work = accounting.work_bound - 1;
        assert_eq!(
            BoundedSeparatedFieldsPlan::build(ip_source(), b'.', 4, build).unwrap_err(),
            BuildError::WorkLimit {
                needed: accounting.work_bound,
                limit: accounting.work_bound - 1,
            }
        );

        let mut build = BuildLimits {
            max_source_ranges: accounting.source_ranges,
            ..BuildLimits::default()
        };
        assert!(BoundedSeparatedFieldsPlan::build(ip_source(), b'.', 4, build).is_ok());
        build.max_source_ranges = accounting.source_ranges - 1;
        assert_eq!(
            BoundedSeparatedFieldsPlan::build(ip_source(), b'.', 4, build).unwrap_err(),
            BuildError::RangeLimit {
                needed: accounting.source_ranges,
                limit: accounting.source_ranges - 1,
            }
        );

        let mut build = BuildLimits {
            max_persistent_bytes: accounting.persistent_bytes,
            ..BuildLimits::default()
        };
        assert!(BoundedSeparatedFieldsPlan::build(ip_source(), b'.', 4, build).is_ok());
        build.max_persistent_bytes = accounting.persistent_bytes - 1;
        assert_eq!(
            BoundedSeparatedFieldsPlan::build(ip_source(), b'.', 4, build).unwrap_err(),
            BuildError::PersistentLimit {
                needed: accounting.persistent_bytes,
                limit: accounting.persistent_bytes - 1,
            }
        );

        let mut build = BuildLimits {
            max_peak_bytes: accounting.peak_bytes,
            ..BuildLimits::default()
        };
        assert!(BoundedSeparatedFieldsPlan::build(ip_source(), b'.', 4, build).is_ok());
        build.max_peak_bytes = accounting.peak_bytes - 1;
        assert_eq!(
            BoundedSeparatedFieldsPlan::build(ip_source(), b'.', 4, build).unwrap_err(),
            BuildError::PeakLimit {
                needed: accounting.peak_bytes,
                limit: accounting.peak_bytes - 1,
            }
        );

        let plan =
            BoundedSeparatedFieldsPlan::build(two_field_source(), b'.', 2, BuildLimits::default())
                .unwrap();
        let haystack = b"0.0";
        let exact = plan
            .count(haystack, ReduceLimits::default())
            .unwrap()
            .accounting
            .upper_bounds;
        let reduce = ReduceLimits {
            max_input_bytes: haystack.len(),
            max_sequential_bytes: exact.sequential_bytes,
            max_work: exact.work,
            max_count: exact.match_events,
            max_peak_bytes: exact.peak_bytes,
        };
        assert_eq!(plan.count(haystack, reduce).unwrap().count, 1);

        let mut one_below = reduce;
        one_below.max_input_bytes = one_below.max_input_bytes.checked_sub(1).unwrap();
        assert!(matches!(
            plan.count(haystack, one_below),
            Err(ReduceError::InputLimit { .. })
        ));
        one_below = reduce;
        one_below.max_sequential_bytes = one_below.max_sequential_bytes.checked_sub(1).unwrap();
        assert_eq!(
            plan.count(haystack, one_below).unwrap_err(),
            ReduceError::SequentialLimit {
                needed: exact.sequential_bytes,
                limit: exact.sequential_bytes - 1,
            }
        );
        one_below = reduce;
        one_below.max_count = one_below.max_count.checked_sub(1).unwrap();
        assert!(matches!(
            plan.count(haystack, one_below),
            Err(ReduceError::CountLimit { .. })
        ));
        one_below = reduce;
        one_below.max_peak_bytes = one_below.max_peak_bytes.checked_sub(1).unwrap();
        assert!(matches!(
            plan.count(haystack, one_below),
            Err(ReduceError::PeakLimit { .. })
        ));
    }

    #[test]
    fn imported_ip_size_fits_the_unchanged_public_work_cap() {
        const REBAR_INPUT_BYTES: usize = 6_839_410;
        const PUBLIC_WORK_CAP: usize = 536_870_912;
        const PUBLIC_SEQUENTIAL_CAP: usize = 536_870_912;
        const EXPECTED_WORK: usize = 533_473_988;
        const EXPECTED_SEQUENTIAL_BYTES: usize = 341_970_500;

        let plan = plan();
        let haystack = vec![b'x'; REBAR_INPUT_BYTES];
        let mut limits = ReduceLimits {
            max_work: PUBLIC_WORK_CAP,
            max_sequential_bytes: PUBLIC_SEQUENTIAL_CAP,
            ..ReduceLimits::default()
        };
        let result = plan.count(&haystack, limits).unwrap();
        assert_eq!(result.count, 0);
        assert_eq!(result.accounting.upper_bounds.work_per_candidate, 78);
        assert_eq!(result.accounting.upper_bounds.work, EXPECTED_WORK);
        assert_eq!(
            result.accounting.upper_bounds.sequential_bytes,
            EXPECTED_SEQUENTIAL_BYTES
        );
        assert_eq!(result.accounting.upper_bounds.random_access_bytes, 0);
        assert_eq!(
            result.accounting.actual.sequential_bytes,
            result
                .accounting
                .actual
                .separator_inspections
                .checked_add(result.accounting.actual.class_comparisons)
                .unwrap()
        );
        assert!(
            result.accounting.actual.sequential_bytes
                <= result.accounting.upper_bounds.sequential_bytes
        );
        assert_eq!(result.accounting.actual.random_access_bytes, 0);
        assert!(result.accounting.upper_bounds.work <= limits.max_work);

        limits.max_work = EXPECTED_WORK - 1;
        assert_eq!(
            plan.count(&haystack, limits).unwrap_err(),
            ReduceError::WorkLimit {
                needed: EXPECTED_WORK,
                limit: EXPECTED_WORK - 1,
            }
        );

        limits.max_work = PUBLIC_WORK_CAP;
        limits.max_sequential_bytes = EXPECTED_SEQUENTIAL_BYTES - 1;
        assert_eq!(
            plan.count(&haystack, limits).unwrap_err(),
            ReduceError::SequentialLimit {
                needed: EXPECTED_SEQUENTIAL_BYTES,
                limit: EXPECTED_SEQUENTIAL_BYTES - 1,
            }
        );
    }

    #[test]
    fn malformed_and_near_miss_sources_are_rejected() {
        for overlap in [
            AtomSource::Singleton(b'.'),
            AtomSource::Range(b'.', b'/'),
            AtomSource::Range(b'-', b'.'),
            AtomSource::Range(b'-', b'/'),
        ] {
            let mut separator_overlap = ip_source();
            separator_overlap.alternatives[0].as_mut().unwrap().atoms[0] = Some(overlap);
            assert!(matches!(
                BoundedSeparatedFieldsPlan::build(
                    separator_overlap,
                    b'.',
                    4,
                    BuildLimits::default()
                ),
                Err(BuildError::SeparatorInField { .. })
            ));
        }
        let mut malformed = ip_source();
        malformed.alternatives[1].as_mut().unwrap().atoms[1] = None;
        assert!(matches!(
            BoundedSeparatedFieldsPlan::build(malformed, b'.', 4, BuildLimits::default()),
            Err(BuildError::MissingAtom { .. })
        ));
        let mut too_many = ip_source();
        too_many.alternative_count = u8::try_from(MAX_ALTERNATIVES + 1).unwrap();
        assert!(matches!(
            BoundedSeparatedFieldsPlan::build(too_many, b'.', 4, BuildLimits::default()),
            Err(BuildError::InvalidAlternativeCount { .. })
        ));
    }

    #[test]
    fn build_attempt_reports_exact_success_and_partial_failure() {
        let attempt =
            BoundedSeparatedFieldsPlan::build_attempt(ip_source(), b'.', 4, BuildLimits::default())
                .unwrap();
        let actual = attempt.actual();
        let (plan, returned_actual) = attempt.into_parts();
        let build = plan.build_accounting();
        let source_bytes = core::mem::size_of::<FieldSource<'static>>();
        assert_eq!(returned_actual, actual);
        assert_eq!(actual.work, 353);
        assert!(actual.work < u64::try_from(build.work_bound).unwrap());
        assert_eq!(actual.allocations, 0);
        assert_eq!(actual.allocated_bytes, 0);
        assert_eq!(actual.copied_bytes, source_bytes);
        assert_eq!(
            actual.initialized_bytes,
            source_bytes + build.persistent_bytes
        );
        assert_eq!(actual.live_persistent_bytes, build.persistent_bytes);
        assert_eq!(actual.peak_bytes, build.peak_bytes);

        let error = BoundedSeparatedFieldsPlan::build_attempt(
            one_atom_source(AtomSource::Range(b'z', b'a'), false),
            b'.',
            2,
            BuildLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(error.source(), BuildError::ReversedRange { .. }));
        assert_eq!(error.actual().work, 322);
        assert_eq!(error.actual().allocations, 0);
        assert_eq!(error.actual().copied_bytes, source_bytes);
        assert_eq!(error.actual().initialized_bytes, source_bytes);
        assert_eq!(error.actual().live_persistent_bytes, 0);
        assert_eq!(error.actual().peak_bytes, source_bytes);
    }
}
