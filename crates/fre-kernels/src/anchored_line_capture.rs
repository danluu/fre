//! Allocation-free capture participation for deterministic byte-anchored lines.
//!
//! The kernel consumes a fixed inline sequence of byte-mask atoms. Greedy
//! variable-width atoms are admitted only at a deterministic boundary: they
//! are final, or the following positive-width atom has a disjoint first-byte
//! mask. This makes one forward pass sufficient and avoids retaining capture
//! spans when construction has already proved that every capture participates.

use core::{fmt, mem::size_of};

pub const PLAN_ID: &str = "anchored-line-capture.inline-byte-atoms.v2";
pub const COUNT_OPERATION_ID: &str = "anchored-line-capture.grep-participation-count.v1";
pub const MAX_ATOMS: usize = 32;

const BITMAP_WORDS: usize = 4;
const BUILD_FIXED_WORK: usize = 8;
const RUN_FIXED_WORK: usize = 1;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ByteMask {
    words: [u64; BITMAP_WORDS],
}

impl ByteMask {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            words: [0; BITMAP_WORDS],
        }
    }

    #[must_use]
    pub fn singleton(byte: u8) -> Self {
        let mut mask = Self::empty();
        mask.insert(byte);
        mask
    }

    pub fn insert(&mut self, byte: u8) {
        let index = usize::from(byte >> 6);
        let shift = u32::from(byte) % u64::BITS;
        self.words[index] |= 1_u64 << shift;
    }

    pub fn insert_range(&mut self, start: u8, end: u8) -> Result<(), BuildError> {
        if start > end {
            return Err(BuildError::ReversedRange { start, end });
        }
        for byte in start..=end {
            self.insert(byte);
        }
        Ok(())
    }

    #[must_use]
    pub fn contains(self, byte: u8) -> bool {
        let index = usize::from(byte >> 6);
        let shift = u32::from(byte) % u64::BITS;
        self.words[index] & (1_u64 << shift) != 0
    }

    #[must_use]
    pub fn is_empty(self) -> bool {
        self.words.iter().all(|word| *word == 0)
    }

    #[must_use]
    pub fn intersects(self, other: Self) -> bool {
        self.words
            .iter()
            .zip(other.words)
            .any(|(left, right)| left & right != 0)
    }

    #[must_use]
    pub const fn words(self) -> [u64; BITMAP_WORDS] {
        self.words
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Atom {
    mask: ByteMask,
    minimum: u32,
    maximum: Option<u32>,
}

impl Atom {
    #[must_use]
    pub const fn new(mask: ByteMask, minimum: u32, maximum: Option<u32>) -> Self {
        Self {
            mask,
            minimum,
            maximum,
        }
    }

    #[must_use]
    pub const fn mask(self) -> ByteMask {
        self.mask
    }

    #[must_use]
    pub const fn minimum(self) -> u32 {
        self.minimum
    }

    #[must_use]
    pub const fn maximum(self) -> Option<u32> {
        self.maximum
    }

    const fn variable(self) -> bool {
        match self.maximum {
            Some(maximum) => maximum != self.minimum,
            None => true,
        }
    }
}

impl Default for Atom {
    fn default() -> Self {
        Self::new(ByteMask::empty(), 0, Some(0))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationIdentity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub atom_count: usize,
    pub explicit_captures: usize,
    pub groups_per_match: usize,
    pub minimum_match_bytes: usize,
    pub require_line_end: bool,
    pub structural_digest: [u64; 2],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub max_atoms: usize,
    pub max_captures: usize,
    pub max_build_work: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            max_atoms: MAX_ATOMS,
            max_captures: 64,
            max_build_work: 1 << 20,
            max_persistent_bytes: 1 << 20,
            max_peak_bytes: 1 << 20,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub atom_count: usize,
    pub explicit_captures: usize,
    pub mask_word_checks: usize,
    pub boundary_checks: usize,
    pub minimum_match_bytes: usize,
    pub work: usize,
    pub allocations: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunLimits {
    pub max_input_bytes: usize,
    pub max_lines: usize,
    pub max_matches: usize,
    pub max_capture_count: usize,
    pub max_reducer_events: usize,
    pub max_work: usize,
    pub max_sequential_bytes: usize,
    pub max_peak_bytes: usize,
}

impl Default for RunLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 512 << 20,
            max_lines: 512 << 20,
            max_matches: 512 << 20,
            max_capture_count: 1_000_000_000,
            max_reducer_events: 1_000_000_000,
            max_work: 1 << 30,
            max_sequential_bytes: 512 << 20,
            max_peak_bytes: 1 << 20,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunUpperBounds {
    pub input_bytes: usize,
    pub lines: usize,
    pub matches: usize,
    pub capture_count: usize,
    pub reducer_events: usize,
    pub work: usize,
    pub sequential_bytes: usize,
    pub allocations: usize,
    pub scratch_bytes: usize,
    pub output_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RunActual {
    pub input_loads: usize,
    pub delimiter_steps: usize,
    pub atom_probes: usize,
    pub atom_transitions: usize,
    pub line_events: usize,
    pub matches: usize,
    pub capture_count: usize,
    pub reducer_events: usize,
    pub work: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountResult {
    pub capture_count: usize,
    pub identity: OperationIdentity,
    pub upper_bounds: RunUpperBounds,
    pub actual: RunActual,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    EmptyPlan,
    AtomLimit {
        needed: usize,
        limit: usize,
    },
    CaptureLimit {
        needed: usize,
        limit: usize,
    },
    EmptyMask {
        atom: usize,
    },
    InvalidRepeat {
        atom: usize,
        minimum: u32,
        maximum: u32,
    },
    ZeroWidthMatch,
    AmbiguousBoundary {
        atom: usize,
    },
    NonPositiveBoundary {
        atom: usize,
    },
    ReversedRange {
        start: u8,
        end: u8,
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
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPlan => formatter.write_str("anchored line-capture plan has no atoms"),
            Self::AtomLimit { needed, limit } => {
                write!(
                    formatter,
                    "anchored line-capture needs {needed} atoms, limit is {limit}"
                )
            }
            Self::CaptureLimit { needed, limit } => write!(
                formatter,
                "anchored line-capture needs {needed} captures, limit is {limit}"
            ),
            Self::EmptyMask { atom } => {
                write!(
                    formatter,
                    "anchored line-capture atom {atom} has an empty mask"
                )
            }
            Self::InvalidRepeat {
                atom,
                minimum,
                maximum,
            } => write!(
                formatter,
                "anchored line-capture atom {atom} has invalid repeat {minimum}..={maximum}"
            ),
            Self::ZeroWidthMatch => {
                formatter.write_str("anchored line-capture whole match is nullable")
            }
            Self::AmbiguousBoundary { atom } => write!(
                formatter,
                "anchored line-capture variable atom {atom} overlaps its successor"
            ),
            Self::NonPositiveBoundary { atom } => write!(
                formatter,
                "anchored line-capture variable atom {atom} has a nullable successor"
            ),
            Self::ReversedRange { start, end } => {
                write!(
                    formatter,
                    "anchored line-capture byte range {start:#X}..={end:#X} is reversed"
                )
            }
            Self::WorkLimit { needed, limit } => {
                write!(
                    formatter,
                    "anchored line-capture build needs {needed} work, limit is {limit}"
                )
            }
            Self::PersistentLimit { needed, limit } => write!(
                formatter,
                "anchored line-capture build needs {needed} persistent bytes, limit is {limit}"
            ),
            Self::PeakLimit { needed, limit } => write!(
                formatter,
                "anchored line-capture build needs {needed} peak bytes, limit is {limit}"
            ),
            Self::ArithmeticOverflow { computation } => write!(
                formatter,
                "anchored line-capture overflow while computing {computation}"
            ),
        }
    }
}

impl std::error::Error for BuildError {}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RunError {
    Resource {
        resource: &'static str,
        needed: usize,
        limit: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    AccountingInvariant {
        resource: &'static str,
        actual: usize,
        bound: usize,
    },
}

impl fmt::Display for RunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resource {
                resource,
                needed,
                limit,
            } => write!(
                formatter,
                "anchored line-capture {resource} needs {needed}, limit is {limit}"
            ),
            Self::ArithmeticOverflow { computation } => write!(
                formatter,
                "anchored line-capture overflow while computing {computation}"
            ),
            Self::AccountingInvariant {
                resource,
                actual,
                bound,
            } => write!(
                formatter,
                "anchored line-capture {resource} actual {actual} exceeds bound {bound}"
            ),
        }
    }
}

impl std::error::Error for RunError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchoredLineCapturePlan {
    atoms: [Atom; MAX_ATOMS],
    identity: OperationIdentity,
    build: BuildAccounting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AtomInspection {
    minimum_match_bytes: usize,
    mask_word_checks: usize,
    boundary_checks: usize,
}

fn inspect_atoms(atoms: &[Atom]) -> Result<AtomInspection, BuildError> {
    let mut minimum_match_bytes = 0_usize;
    let mut mask_word_checks = 0_usize;
    let mut boundary_checks = 0_usize;
    for (index, atom) in atoms.iter().copied().enumerate() {
        if atom.mask.is_empty() {
            return Err(BuildError::EmptyMask { atom: index });
        }
        if let Some(maximum) = atom.maximum
            && maximum < atom.minimum
        {
            return Err(BuildError::InvalidRepeat {
                atom: index,
                minimum: atom.minimum,
                maximum,
            });
        }
        minimum_match_bytes = minimum_match_bytes
            .checked_add(usize::try_from(atom.minimum).map_err(|_| {
                BuildError::ArithmeticOverflow {
                    computation: "minimum match bytes",
                }
            })?)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "minimum match bytes",
            })?;
        mask_word_checks =
            mask_word_checks
                .checked_add(BITMAP_WORDS)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "mask word checks",
                })?;
        let next_index = index.checked_add(1).ok_or(BuildError::ArithmeticOverflow {
            computation: "boundary index",
        })?;
        if atom.variable() && next_index < atoms.len() {
            let next = atoms[next_index];
            boundary_checks = boundary_checks.checked_add(BITMAP_WORDS + 1).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "boundary checks",
                },
            )?;
            if next.minimum == 0 {
                return Err(BuildError::NonPositiveBoundary { atom: index });
            }
            if atom.mask.intersects(next.mask) {
                return Err(BuildError::AmbiguousBoundary { atom: index });
            }
        }
    }
    Ok(AtomInspection {
        minimum_match_bytes,
        mask_word_checks,
        boundary_checks,
    })
}

impl AnchoredLineCapturePlan {
    pub fn new(
        atoms: [Atom; MAX_ATOMS],
        atom_count: usize,
        explicit_captures: usize,
        require_line_end: bool,
        structural_digest: [u64; 2],
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        if atom_count == 0 {
            return Err(BuildError::EmptyPlan);
        }
        let admitted_atoms = limits.max_atoms.min(MAX_ATOMS);
        if atom_count > admitted_atoms {
            return Err(BuildError::AtomLimit {
                needed: atom_count,
                limit: admitted_atoms,
            });
        }
        if explicit_captures > limits.max_captures {
            return Err(BuildError::CaptureLimit {
                needed: explicit_captures,
                limit: limits.max_captures,
            });
        }

        let inspection = inspect_atoms(&atoms[..atom_count])?;
        let AtomInspection {
            minimum_match_bytes,
            mask_word_checks,
            boundary_checks,
        } = inspection;
        if minimum_match_bytes == 0 {
            return Err(BuildError::ZeroWidthMatch);
        }
        let work = BUILD_FIXED_WORK
            .checked_add(atom_count)
            .and_then(|value| value.checked_add(mask_word_checks))
            .and_then(|value| value.checked_add(boundary_checks))
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "build work",
            })?;
        enforce_build("work", work, limits.max_build_work, |needed, limit| {
            BuildError::WorkLimit { needed, limit }
        })?;
        let persistent_bytes = size_of::<Self>();
        enforce_build(
            "persistent bytes",
            persistent_bytes,
            limits.max_persistent_bytes,
            |needed, limit| BuildError::PersistentLimit { needed, limit },
        )?;
        enforce_build(
            "peak bytes",
            persistent_bytes,
            limits.max_peak_bytes,
            |needed, limit| BuildError::PeakLimit { needed, limit },
        )?;
        let groups_per_match =
            explicit_captures
                .checked_add(1)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "groups per match",
                })?;
        let identity = OperationIdentity {
            plan_id: PLAN_ID,
            operation_id: COUNT_OPERATION_ID,
            atom_count,
            explicit_captures,
            groups_per_match,
            minimum_match_bytes,
            require_line_end,
            structural_digest,
        };
        let build = BuildAccounting {
            atom_count,
            explicit_captures,
            mask_word_checks,
            boundary_checks,
            minimum_match_bytes,
            work,
            allocations: 0,
            scratch_bytes: 0,
            persistent_bytes,
            peak_bytes: persistent_bytes,
        };
        Ok(Self {
            atoms,
            identity,
            build,
        })
    }

    #[must_use]
    pub const fn identity(&self) -> OperationIdentity {
        self.identity
    }

    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.build
    }

    #[must_use]
    pub fn atoms(&self) -> &[Atom] {
        &self.atoms[..self.identity.atom_count]
    }

    pub fn count(&self, haystack: &[u8], limits: RunLimits) -> Result<CountResult, RunError> {
        let upper_bounds = self.run_upper_bounds(haystack.len())?;
        enforce_run(
            "input bytes",
            upper_bounds.input_bytes,
            limits.max_input_bytes,
        )?;
        enforce_run("lines", upper_bounds.lines, limits.max_lines)?;
        enforce_run("matches", upper_bounds.matches, limits.max_matches)?;
        enforce_run(
            "capture count",
            upper_bounds.capture_count,
            limits.max_capture_count,
        )?;
        enforce_run(
            "reducer events",
            upper_bounds.reducer_events,
            limits.max_reducer_events,
        )?;
        enforce_run("work", upper_bounds.work, limits.max_work)?;
        enforce_run(
            "sequential bytes",
            upper_bounds.sequential_bytes,
            limits.max_sequential_bytes,
        )?;
        enforce_run("peak bytes", upper_bounds.peak_bytes, limits.max_peak_bytes)?;

        let mut scanner = LineScanner::new(
            self.atoms(),
            self.identity.groups_per_match,
            self.identity.require_line_end,
        );
        for &byte in haystack {
            scanner.load(byte)?;
        }
        scanner.finish(!haystack.is_empty())?;
        scanner.actual.work = RUN_FIXED_WORK
            .checked_add(scanner.actual.input_loads)
            .and_then(|value| value.checked_add(scanner.actual.delimiter_steps))
            .and_then(|value| value.checked_add(scanner.actual.atom_probes))
            .and_then(|value| value.checked_add(scanner.actual.atom_transitions))
            .and_then(|value| value.checked_add(scanner.actual.line_events))
            .ok_or(RunError::ArithmeticOverflow {
                computation: "actual work",
            })?;
        for (resource, actual, bound) in [
            (
                "input loads",
                scanner.actual.input_loads,
                upper_bounds.input_bytes,
            ),
            ("lines", scanner.actual.line_events, upper_bounds.lines),
            ("matches", scanner.actual.matches, upper_bounds.matches),
            (
                "capture count",
                scanner.actual.capture_count,
                upper_bounds.capture_count,
            ),
            (
                "reducer events",
                scanner.actual.reducer_events,
                upper_bounds.reducer_events,
            ),
            ("work", scanner.actual.work, upper_bounds.work),
        ] {
            if actual > bound {
                return Err(RunError::AccountingInvariant {
                    resource,
                    actual,
                    bound,
                });
            }
        }
        Ok(CountResult {
            capture_count: scanner.actual.capture_count,
            identity: self.identity,
            upper_bounds,
            actual: scanner.actual,
        })
    }

    fn run_upper_bounds(&self, input_bytes: usize) -> Result<RunUpperBounds, RunError> {
        let lines = input_bytes;
        let matches = lines;
        let capture_count = matches.checked_mul(self.identity.groups_per_match).ok_or(
            RunError::ArithmeticOverflow {
                computation: "capture count bound",
            },
        )?;
        let reducer_events =
            lines
                .checked_add(capture_count)
                .ok_or(RunError::ArithmeticOverflow {
                    computation: "reducer event bound",
                })?;
        let work_per_input = self
            .identity
            .atom_count
            .checked_mul(2)
            .and_then(|value| value.checked_add(5))
            .ok_or(RunError::ArithmeticOverflow {
                computation: "work per input byte",
            })?;
        let work = input_bytes
            .checked_mul(work_per_input)
            .and_then(|value| value.checked_add(RUN_FIXED_WORK))
            .ok_or(RunError::ArithmeticOverflow {
                computation: "work bound",
            })?;
        Ok(RunUpperBounds {
            input_bytes,
            lines,
            matches,
            capture_count,
            reducer_events,
            work,
            sequential_bytes: input_bytes,
            allocations: 0,
            scratch_bytes: 0,
            output_bytes: 0,
            persistent_bytes: self.build.persistent_bytes,
            peak_bytes: self.build.persistent_bytes,
        })
    }
}

fn enforce_build(
    _resource: &'static str,
    needed: usize,
    limit: usize,
    error: impl FnOnce(usize, usize) -> BuildError,
) -> Result<(), BuildError> {
    if needed > limit {
        return Err(error(needed, limit));
    }
    Ok(())
}

fn enforce_run(resource: &'static str, needed: usize, limit: usize) -> Result<(), RunError> {
    if needed > limit {
        return Err(RunError::Resource {
            resource,
            needed,
            limit,
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MatchState {
    Active,
    Matched,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LineMatcher<'a> {
    atoms: &'a [Atom],
    require_line_end: bool,
    atom: usize,
    repeated: u32,
    state: MatchState,
}

impl<'a> LineMatcher<'a> {
    const fn new(atoms: &'a [Atom], require_line_end: bool) -> Self {
        Self {
            atoms,
            require_line_end,
            atom: 0,
            repeated: 0,
            state: MatchState::Active,
        }
    }

    fn push(&mut self, byte: u8, actual: &mut RunActual) -> Result<(), RunError> {
        if self.require_line_end && self.state == MatchState::Matched {
            self.state = MatchState::Failed;
            return Ok(());
        }
        while self.state == MatchState::Active {
            let Some(atom) = self.atoms.get(self.atom).copied() else {
                self.state = MatchState::Matched;
                return Ok(());
            };
            actual.atom_probes =
                actual
                    .atom_probes
                    .checked_add(1)
                    .ok_or(RunError::ArithmeticOverflow {
                        computation: "atom probes",
                    })?;
            let below_maximum = atom.maximum.is_none_or(|maximum| self.repeated < maximum);
            if below_maximum && atom.mask.contains(byte) {
                self.repeated =
                    self.repeated
                        .checked_add(1)
                        .ok_or(RunError::ArithmeticOverflow {
                            computation: "atom repetition",
                        })?;
                if atom.maximum == Some(self.repeated) {
                    self.advance(actual)?;
                }
                return Ok(());
            }
            if self.repeated >= atom.minimum {
                self.advance(actual)?;
                if self.require_line_end && self.state == MatchState::Matched {
                    self.state = MatchState::Failed;
                    return Ok(());
                }
                continue;
            }
            self.state = MatchState::Failed;
        }
        Ok(())
    }

    fn finish(&mut self, actual: &mut RunActual) -> Result<bool, RunError> {
        while self.state == MatchState::Active {
            let Some(atom) = self.atoms.get(self.atom).copied() else {
                self.state = MatchState::Matched;
                break;
            };
            actual.atom_probes =
                actual
                    .atom_probes
                    .checked_add(1)
                    .ok_or(RunError::ArithmeticOverflow {
                        computation: "atom probes",
                    })?;
            if self.repeated < atom.minimum {
                self.state = MatchState::Failed;
                break;
            }
            self.advance(actual)?;
        }
        Ok(self.state == MatchState::Matched)
    }

    fn advance(&mut self, actual: &mut RunActual) -> Result<(), RunError> {
        self.atom = self
            .atom
            .checked_add(1)
            .ok_or(RunError::ArithmeticOverflow {
                computation: "atom index",
            })?;
        self.repeated = 0;
        actual.atom_transitions =
            actual
                .atom_transitions
                .checked_add(1)
                .ok_or(RunError::ArithmeticOverflow {
                    computation: "atom transitions",
                })?;
        if self.atom == self.atoms.len() {
            self.state = MatchState::Matched;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct LineScanner<'a> {
    atoms: &'a [Atom],
    groups_per_match: usize,
    require_line_end: bool,
    matcher: LineMatcher<'a>,
    pending_cr: bool,
    ended_with_lf: bool,
    actual: RunActual,
}

impl<'a> LineScanner<'a> {
    const fn new(atoms: &'a [Atom], groups_per_match: usize, require_line_end: bool) -> Self {
        Self {
            atoms,
            groups_per_match,
            require_line_end,
            matcher: LineMatcher::new(atoms, require_line_end),
            pending_cr: false,
            ended_with_lf: false,
            actual: RunActual {
                input_loads: 0,
                delimiter_steps: 0,
                atom_probes: 0,
                atom_transitions: 0,
                line_events: 0,
                matches: 0,
                capture_count: 0,
                reducer_events: 0,
                work: 0,
            },
        }
    }

    fn load(&mut self, byte: u8) -> Result<(), RunError> {
        self.actual.input_loads =
            self.actual
                .input_loads
                .checked_add(1)
                .ok_or(RunError::ArithmeticOverflow {
                    computation: "input loads",
                })?;
        self.actual.delimiter_steps =
            self.actual
                .delimiter_steps
                .checked_add(1)
                .ok_or(RunError::ArithmeticOverflow {
                    computation: "delimiter steps",
                })?;
        if self.pending_cr {
            if byte == b'\n' {
                self.finish_line()?;
                self.pending_cr = false;
                self.ended_with_lf = true;
                return Ok(());
            }
            self.matcher.push(b'\r', &mut self.actual)?;
            self.pending_cr = false;
        }
        self.ended_with_lf = false;
        match byte {
            b'\r' => self.pending_cr = true,
            b'\n' => {
                self.finish_line()?;
                self.ended_with_lf = true;
            }
            content => self.matcher.push(content, &mut self.actual)?,
        }
        Ok(())
    }

    fn finish(&mut self, input_was_nonempty: bool) -> Result<(), RunError> {
        if self.pending_cr {
            self.matcher.push(b'\r', &mut self.actual)?;
            self.pending_cr = false;
        }
        if input_was_nonempty && !self.ended_with_lf {
            self.finish_line()?;
        }
        Ok(())
    }

    fn finish_line(&mut self) -> Result<(), RunError> {
        self.actual.line_events =
            self.actual
                .line_events
                .checked_add(1)
                .ok_or(RunError::ArithmeticOverflow {
                    computation: "line events",
                })?;
        self.actual.reducer_events =
            self.actual
                .reducer_events
                .checked_add(1)
                .ok_or(RunError::ArithmeticOverflow {
                    computation: "reducer events",
                })?;
        if self.matcher.finish(&mut self.actual)? {
            self.actual.matches =
                self.actual
                    .matches
                    .checked_add(1)
                    .ok_or(RunError::ArithmeticOverflow {
                        computation: "matches",
                    })?;
            self.actual.capture_count = self
                .actual
                .capture_count
                .checked_add(self.groups_per_match)
                .ok_or(RunError::ArithmeticOverflow {
                    computation: "capture count",
                })?;
            self.actual.reducer_events = self
                .actual
                .reducer_events
                .checked_add(self.groups_per_match)
                .ok_or(RunError::ArithmeticOverflow {
                    computation: "reducer events",
                })?;
        }
        self.matcher = LineMatcher::new(self.atoms, self.require_line_end);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mask(ranges: &[(u8, u8)]) -> ByteMask {
        let mut mask = ByteMask::empty();
        for &(start, end) in ranges {
            mask.insert_range(start, end).unwrap();
        }
        mask
    }

    fn first_three_plan() -> AnchoredLineCapturePlan {
        let space = ByteMask::singleton(b' ');
        let word = mask(&[(b'0', b'9'), (b'A', b'Z'), (b'_', b'_'), (b'a', b'z')]);
        let mut atoms = [Atom::default(); MAX_ATOMS];
        for (index, atom) in [
            Atom::new(space, 0, None),
            Atom::new(word, 1, None),
            Atom::new(space, 1, None),
            Atom::new(word, 1, None),
            Atom::new(space, 1, None),
            Atom::new(word, 1, None),
        ]
        .into_iter()
        .enumerate()
        {
            atoms[index] = atom;
        }
        AnchoredLineCapturePlan::new(atoms, 6, 3, false, [7, 11], BuildLimits::default()).unwrap()
    }

    #[test]
    fn byte_masks_cover_all_bytes_and_disjointness() {
        let low = mask(&[(0, 127)]);
        let high = mask(&[(128, 255)]);
        assert!(!low.intersects(high));
        for byte in 0..=u8::MAX {
            assert_eq!(low.contains(byte), byte < 128);
            assert_eq!(high.contains(byte), byte >= 128);
        }
    }

    #[test]
    fn target_shape_matches_raw_bstr_line_rules() {
        let plan = first_three_plan();
        let haystack =
            b"one two three\n  four five six\r\nbad two\nseven eight nine tail\n\xFF x y\rz z z";
        let result = plan.count(haystack, RunLimits::default()).unwrap();
        assert_eq!(result.actual.line_events, 5);
        assert_eq!(result.actual.matches, 3);
        assert_eq!(result.capture_count, 12);
        assert_eq!(result.actual.input_loads, haystack.len());
        assert_eq!(result.upper_bounds.sequential_bytes, haystack.len());
        assert_eq!(result.upper_bounds.scratch_bytes, 0);
        assert_eq!(result.upper_bounds.output_bytes, 0);
    }

    #[test]
    fn empty_trailing_lf_crlf_and_lone_cr_are_distinct() {
        let plan = first_three_plan();
        for (haystack, lines, matches) in [
            (b"".as_slice(), 0, 0),
            (b"\n".as_slice(), 1, 0),
            (b"a b c\n".as_slice(), 1, 1),
            (b"a b c\r\n".as_slice(), 1, 1),
            (b"a b c\r".as_slice(), 1, 1),
            (b"\r\n\r\n".as_slice(), 2, 0),
        ] {
            let result = plan.count(haystack, RunLimits::default()).unwrap();
            assert_eq!(result.actual.line_events, lines, "{haystack:?}");
            assert_eq!(result.actual.matches, matches, "{haystack:?}");
            assert_eq!(result.actual.input_loads, haystack.len(), "{haystack:?}");
        }
    }

    #[test]
    fn malformed_bytes_are_ordinary_byte_content() {
        let mut any = ByteMask::empty();
        any.insert_range(0, u8::MAX).unwrap();
        let mut atoms = [Atom::default(); MAX_ATOMS];
        atoms[0] = Atom::new(any, 1, None);
        let plan = AnchoredLineCapturePlan::new(atoms, 1, 1, false, [1, 2], BuildLimits::default())
            .unwrap();
        let result = plan
            .count(b"\xFF\n\xC0\x80\r\n", RunLimits::default())
            .unwrap();
        assert_eq!(result.actual.matches, 2);
        assert_eq!(result.capture_count, 4);
    }

    #[test]
    fn terminal_end_requires_full_line_and_keeps_empty_captures() {
        let a = ByteMask::singleton(b'a');
        let semicolon = ByteMask::singleton(b';');
        let b = ByteMask::singleton(b'b');
        let mut atoms = [Atom::default(); MAX_ATOMS];
        atoms[0] = Atom::new(a, 0, None);
        atoms[1] = Atom::new(semicolon, 1, Some(1));
        atoms[2] = Atom::new(b, 0, None);
        let plan = AnchoredLineCapturePlan::new(atoms, 3, 2, true, [3, 5], BuildLimits::default())
            .unwrap();
        let result = plan
            .count(b";\naa;bb\r\naa;bbx\nxaa;bb\n", RunLimits::default())
            .unwrap();
        assert!(result.identity.require_line_end);
        assert_eq!(result.actual.matches, 2);
        assert_eq!(result.capture_count, 6);
    }

    #[test]
    fn ambiguous_and_nullable_boundaries_are_rejected() {
        let a = ByteMask::singleton(b'a');
        let b = ByteMask::singleton(b'b');
        let mut atoms = [Atom::default(); MAX_ATOMS];
        atoms[0] = Atom::new(a, 1, None);
        atoms[1] = Atom::new(a, 1, Some(1));
        assert!(matches!(
            AnchoredLineCapturePlan::new(atoms, 2, 1, false, [0; 2], BuildLimits::default()),
            Err(BuildError::AmbiguousBoundary { atom: 0 })
        ));
        atoms[1] = Atom::new(b, 0, None);
        assert!(matches!(
            AnchoredLineCapturePlan::new(atoms, 2, 1, false, [0; 2], BuildLimits::default()),
            Err(BuildError::NonPositiveBoundary { atom: 0 })
        ));
    }

    #[test]
    fn every_run_limit_has_a_one_below_boundary() {
        let plan = first_three_plan();
        let haystack = b"one two three\n";
        let exact = plan.count(haystack, RunLimits::default()).unwrap();
        for limits in [
            RunLimits {
                max_input_bytes: exact.upper_bounds.input_bytes - 1,
                ..RunLimits::default()
            },
            RunLimits {
                max_lines: exact.upper_bounds.lines - 1,
                ..RunLimits::default()
            },
            RunLimits {
                max_matches: exact.upper_bounds.matches - 1,
                ..RunLimits::default()
            },
            RunLimits {
                max_capture_count: exact.upper_bounds.capture_count - 1,
                ..RunLimits::default()
            },
            RunLimits {
                max_reducer_events: exact.upper_bounds.reducer_events - 1,
                ..RunLimits::default()
            },
            RunLimits {
                max_work: exact.upper_bounds.work - 1,
                ..RunLimits::default()
            },
            RunLimits {
                max_sequential_bytes: exact.upper_bounds.sequential_bytes - 1,
                ..RunLimits::default()
            },
            RunLimits {
                max_peak_bytes: exact.upper_bounds.peak_bytes - 1,
                ..RunLimits::default()
            },
        ] {
            assert!(matches!(
                plan.count(haystack, limits),
                Err(RunError::Resource { .. })
            ));
        }
    }
}
