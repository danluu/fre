//! Bounded byte-context classification for automaton start states.
//!
//! A plan maps every byte to one of the six start contexts used by byte DFAs:
//! non-word, ASCII word, text, LF, CR, or a custom line terminator. The text
//! context is represented explicitly but is returned only when the requested
//! forward or reverse search boundary has no adjacent byte. Construction is a
//! fixed 256-entry traversal with no heap allocation. Lookup validates and
//! admits its complete resource bound before reading at most one input byte.

use core::{fmt, mem::size_of};

/// Stable semantic identity for the byte start-map proof.
pub const PLAN_ID: &str = "byte-start-map.context-classification.v1";

const MAP_ENTRIES: usize = 256;
// Fixed work covers bound arithmetic, four limit comparisons, plan-field
// publication and return control. Per entry, 32 dominates loop/conversion (4),
// custom/LF/CR/word comparisons (12), boolean combinations (8), priority
// branches (5), indexing (1), the table write (1) and loop publication (1).
const BUILD_FIXED_WORK: usize = 32;
const BUILD_WORK_PER_ENTRY: usize = 32;
const BUILD_WORK: usize = BUILD_FIXED_WORK + MAP_ENTRIES * BUILD_WORK_PER_ENTRY;
// Base lookup work dominates window validation, direction/index selection,
// bound construction, three limit checks and result publication. Read work
// separately dominates input/map indexing, bounds checks, both reads, branch
// control and class publication.
const LOOKUP_BASE_WORK: usize = 64;
const LOOKUP_READ_WORK: usize = 16;
const LOOKUP_MAX_WORK: usize = LOOKUP_BASE_WORK + LOOKUP_READ_WORK;

/// One semantic start context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StartClass {
    NonWordByte,
    WordByte,
    Text,
    LineLf,
    LineCr,
    CustomLineTerminator,
}

/// Direction used to choose the adjacent context byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Forward,
    Reverse,
}

/// Independently limited resource dimensions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Resource {
    BuildWork,
    ScratchBytes,
    PersistentBytes,
    PeakBytes,
    InputBytes,
    LookupWork,
    RandomAccessBytes,
}

/// Hard limits for constructing a start map.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub max_work: usize,
    pub max_scratch_bytes: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            max_work: 1 << 16,
            max_scratch_bytes: 1 << 10,
            max_persistent_bytes: 1 << 10,
            max_peak_bytes: 1 << 11,
        }
    }
}

/// Prospective construction accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub initialized_entries: usize,
    pub work: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Hard limits for one boundary lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LookupLimits {
    pub max_input_bytes: usize,
    pub max_work: usize,
    pub max_random_access_bytes: usize,
}

impl Default for LookupLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 128 << 20,
            max_work: 128,
            max_random_access_bytes: 1,
        }
    }
}

/// Prospective and actual accounting for one boundary lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LookupAccounting {
    pub input_bytes: usize,
    pub prospective_work: usize,
    pub actual_work: usize,
    pub random_access_bytes: usize,
    pub map_reads: usize,
}

/// Successful context lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LookupResult {
    pub class: StartClass,
    pub accounting: LookupAccounting,
}

/// Failure before a plan is published or an input byte is read.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    InvalidWindow {
        start: usize,
        end: usize,
        input_bytes: usize,
    },
    ResourceLimit {
        resource: Resource,
        needed: usize,
        limit: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidWindow {
                start,
                end,
                input_bytes,
            } => write!(
                formatter,
                "invalid search window {start}..{end} for {input_bytes} input bytes",
            ),
            Self::ResourceLimit {
                resource,
                needed,
                limit,
            } => {
                write!(
                    formatter,
                    "{resource:?} requires {needed}, limit is {limit}"
                )
            }
        }
    }
}

impl std::error::Error for Error {}

/// Construction error alias for API clarity.
pub type BuildError = Error;
/// Lookup error alias for API clarity.
pub type LookupError = Error;

/// Inline, allocation-free start-context plan.
#[derive(Debug)]
pub struct ByteStartMap {
    classes: [StartClass; MAP_ENTRIES],
    accounting: BuildAccounting,
}

impl ByteStartMap {
    /// Compute the complete construction bound without initializing the map.
    #[must_use]
    pub fn build_requirements() -> BuildAccounting {
        let persistent_bytes = size_of::<Self>();
        let scratch_bytes = size_of::<[StartClass; MAP_ENTRIES]>();
        BuildAccounting {
            initialized_entries: MAP_ENTRIES,
            work: BUILD_WORK,
            scratch_bytes,
            persistent_bytes,
            peak_bytes: persistent_bytes.saturating_add(scratch_bytes),
        }
    }

    /// Build a map after prospectively admitting all writes and inline bytes.
    pub fn build(custom_line_terminator: u8, limits: BuildLimits) -> Result<Self, BuildError> {
        let accounting = Self::build_requirements();
        enforce_build_limits(accounting, limits)?;

        let classes = core::array::from_fn(|index| {
            classify(u8::try_from(index).unwrap(), custom_line_terminator)
        });
        Ok(Self {
            classes,
            accounting,
        })
    }

    /// Return the admitted construction accounting.
    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.accounting
    }

    /// Classify a byte directly through the constructed map.
    fn class(&self, byte: u8) -> StartClass {
        self.classes[usize::from(byte)]
    }

    /// Compute one lookup bound without reading the input.
    pub fn lookup_requirements(
        &self,
        input_bytes: usize,
        direction: Direction,
        start: usize,
        end: usize,
    ) -> Result<LookupAccounting, LookupError> {
        let (accounting, _) = lookup_preflight(input_bytes, direction, start, end)?;
        Ok(accounting)
    }

    /// Resolve the adjacent byte context after every limit has been checked.
    pub fn lookup(
        &self,
        input: &[u8],
        direction: Direction,
        start: usize,
        end: usize,
        limits: LookupLimits,
    ) -> Result<LookupResult, LookupError> {
        let (accounting, context) = lookup_preflight(input.len(), direction, start, end)?;
        enforce_lookup_limits(accounting, limits)?;
        let class = context.map_or(StartClass::Text, |index| self.class(input[index]));
        Ok(LookupResult { class, accounting })
    }
}

fn lookup_preflight(
    input_bytes: usize,
    direction: Direction,
    start: usize,
    end: usize,
) -> Result<(LookupAccounting, Option<usize>), LookupError> {
    let context = context_index(input_bytes, direction, start, end)?;
    let random_access_bytes = usize::from(context.is_some());
    let map_reads = random_access_bytes;
    let actual_work = if context.is_some() {
        LOOKUP_MAX_WORK
    } else {
        LOOKUP_BASE_WORK
    };
    let accounting = LookupAccounting {
        input_bytes,
        prospective_work: LOOKUP_MAX_WORK,
        actual_work,
        random_access_bytes,
        map_reads,
    };
    Ok((accounting, context))
}

fn classify(byte: u8, custom_line_terminator: u8) -> StartClass {
    let custom_is_distinct = !matches!(custom_line_terminator, b'\r' | b'\n');
    if custom_is_distinct && byte == custom_line_terminator {
        StartClass::CustomLineTerminator
    } else if byte == b'\n' {
        StartClass::LineLf
    } else if byte == b'\r' {
        StartClass::LineCr
    } else if byte == b'_' || byte.is_ascii_alphanumeric() {
        StartClass::WordByte
    } else {
        StartClass::NonWordByte
    }
}

fn context_index(
    input_bytes: usize,
    direction: Direction,
    start: usize,
    end: usize,
) -> Result<Option<usize>, LookupError> {
    if end > input_bytes {
        return Err(LookupError::InvalidWindow {
            start,
            end,
            input_bytes,
        });
    }
    let Some(maximum_start) = end.checked_add(1) else {
        return Err(LookupError::InvalidWindow {
            start,
            end,
            input_bytes,
        });
    };
    if start > maximum_start {
        return Err(LookupError::InvalidWindow {
            start,
            end,
            input_bytes,
        });
    }
    let index = match direction {
        Direction::Forward => start.checked_sub(1),
        Direction::Reverse => Some(end),
    };
    Ok(index.filter(|&candidate| candidate < input_bytes))
}

fn enforce_build_limits(
    accounting: BuildAccounting,
    limits: BuildLimits,
) -> Result<(), BuildError> {
    enforce(Resource::BuildWork, accounting.work, limits.max_work)?;
    enforce(
        Resource::ScratchBytes,
        accounting.scratch_bytes,
        limits.max_scratch_bytes,
    )?;
    enforce(
        Resource::PersistentBytes,
        accounting.persistent_bytes,
        limits.max_persistent_bytes,
    )?;
    enforce(
        Resource::PeakBytes,
        accounting.peak_bytes,
        limits.max_peak_bytes,
    )
}

fn enforce_lookup_limits(
    accounting: LookupAccounting,
    limits: LookupLimits,
) -> Result<(), LookupError> {
    enforce(
        Resource::InputBytes,
        accounting.input_bytes,
        limits.max_input_bytes,
    )?;
    enforce(
        Resource::LookupWork,
        accounting.prospective_work,
        limits.max_work,
    )?;
    enforce(
        Resource::RandomAccessBytes,
        accounting.random_access_bytes,
        limits.max_random_access_bytes,
    )
}

fn enforce(resource: Resource, needed: usize, limit: usize) -> Result<(), Error> {
    if needed > limit {
        Err(Error::ResourceLimit {
            resource,
            needed,
            limit,
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use regex_automata::{Input, util::start::Config};

    use super::*;

    fn plan(custom: u8) -> ByteStartMap {
        ByteStartMap::build(custom, BuildLimits::default()).unwrap()
    }

    fn exact_lookup_limits(accounting: LookupAccounting) -> LookupLimits {
        LookupLimits {
            max_input_bytes: accounting.input_bytes,
            max_work: accounting.prospective_work,
            max_random_access_bytes: accounting.random_access_bytes,
        }
    }

    fn resource(error: LookupError) -> Resource {
        match error {
            LookupError::ResourceLimit { resource, .. } => resource,
            other => panic!("expected resource limit, got {other:?}"),
        }
    }

    #[test]
    fn byte_start_map_reproduces_upstream_start_vectors() {
        let map = plan(b'\n');
        let cases: &[(Direction, &[u8], usize, usize, StartClass)] = &[
            (Direction::Forward, b"", 1, 0, StartClass::Text),
            (Direction::Reverse, b"", 1, 0, StartClass::Text),
            (Direction::Forward, b"abc", 0, 3, StartClass::Text),
            (Direction::Forward, b"\nabc", 1, 3, StartClass::LineLf),
            (Direction::Forward, b"\rabc", 1, 3, StartClass::LineCr),
            (Direction::Forward, b"abc", 1, 3, StartClass::WordByte),
            (Direction::Forward, b" abc", 1, 3, StartClass::NonWordByte),
            (Direction::Reverse, b"abc", 0, 3, StartClass::Text),
            (Direction::Reverse, b"abc\nz", 0, 3, StartClass::LineLf),
            (Direction::Reverse, b"abc\rz", 0, 3, StartClass::LineCr),
            (Direction::Reverse, b"abc", 0, 2, StartClass::WordByte),
            (Direction::Reverse, b"abc ", 0, 3, StartClass::NonWordByte),
        ];
        for &(direction, input, start, end, expected) in cases {
            let accounting = map
                .lookup_requirements(input.len(), direction, start, end)
                .unwrap();
            let result = map
                .lookup(
                    input,
                    direction,
                    start,
                    end,
                    exact_lookup_limits(accounting),
                )
                .unwrap();
            assert_eq!(result.class, expected);
            assert!(result.accounting.actual_work <= result.accounting.prospective_work);
        }
    }

    #[test]
    fn byte_start_map_exhaustive_context_matches_pinned_public_config() {
        let map = plan(b'!');
        for byte in u8::MIN..=u8::MAX {
            let forward = [byte, b'x'];
            let input = Input::new(&forward).range(1..2);
            let upstream = Config::from_input_forward(&input).get_look_behind();
            assert_eq!(upstream, Some(byte));
            assert_eq!(
                map.lookup(&forward, Direction::Forward, 1, 2, LookupLimits::default())
                    .unwrap()
                    .class,
                classify(byte, b'!'),
            );

            let reverse = [b'x', byte];
            let input = Input::new(&reverse).range(0..1);
            let upstream = Config::from_input_reverse(&input).get_look_behind();
            assert_eq!(upstream, Some(byte));
            assert_eq!(
                map.lookup(&reverse, Direction::Reverse, 0, 1, LookupLimits::default())
                    .unwrap()
                    .class,
                classify(byte, b'!'),
            );
        }
    }

    #[test]
    fn byte_start_map_custom_terminator_has_documented_precedence() {
        let word = plan(b'a');
        assert_eq!(word.class(b'a'), StartClass::CustomLineTerminator);
        assert_eq!(word.class(b'b'), StartClass::WordByte);
        assert_eq!(word.class(b'\n'), StartClass::LineLf);
        assert_eq!(word.class(b'\r'), StartClass::LineCr);

        let lf = plan(b'\n');
        assert_eq!(lf.class(b'\n'), StartClass::LineLf);
        let cr = plan(b'\r');
        assert_eq!(cr.class(b'\r'), StartClass::LineCr);
        let invalid = plan(0xFF);
        assert_eq!(invalid.class(0xFF), StartClass::CustomLineTerminator);
        assert_eq!(invalid.class(0x80), StartClass::NonWordByte);
    }

    #[test]
    fn byte_start_map_build_limits_are_exact_and_one_below() {
        let needed = ByteStartMap::build_requirements();
        assert_eq!(needed.initialized_entries, 256);
        assert_eq!(needed.work, 8_224);
        assert_eq!(needed.scratch_bytes, 256);
        assert_eq!(needed.persistent_bytes, size_of::<ByteStartMap>());
        assert_eq!(
            needed.peak_bytes,
            size_of::<ByteStartMap>().checked_add(256).unwrap(),
        );
        let exact = BuildLimits {
            max_work: needed.work,
            max_scratch_bytes: needed.scratch_bytes,
            max_persistent_bytes: needed.persistent_bytes,
            max_peak_bytes: needed.peak_bytes,
        };
        let map = ByteStartMap::build(b'\n', exact).unwrap();
        assert_eq!(map.build_accounting(), needed);

        let cases = [
            (
                BuildLimits {
                    max_work: needed.work.checked_sub(1).unwrap(),
                    ..exact
                },
                Resource::BuildWork,
            ),
            (
                BuildLimits {
                    max_scratch_bytes: needed.scratch_bytes.checked_sub(1).unwrap(),
                    ..exact
                },
                Resource::ScratchBytes,
            ),
            (
                BuildLimits {
                    max_persistent_bytes: needed.persistent_bytes.checked_sub(1).unwrap(),
                    ..exact
                },
                Resource::PersistentBytes,
            ),
            (
                BuildLimits {
                    max_peak_bytes: needed.peak_bytes.checked_sub(1).unwrap(),
                    ..exact
                },
                Resource::PeakBytes,
            ),
        ];
        for (limits, expected) in cases {
            assert!(matches!(
                ByteStartMap::build(b'\n', limits),
                Err(BuildError::ResourceLimit { resource, .. }) if resource == expected
            ));
        }
    }

    #[test]
    fn byte_start_map_lookup_limits_are_exact_and_one_below() {
        let map = plan(b'\n');
        let accounting = map
            .lookup_requirements(3, Direction::Forward, 1, 3)
            .unwrap();
        assert_eq!(accounting.random_access_bytes, 1);
        assert_eq!(accounting.map_reads, 1);
        assert_eq!(accounting.prospective_work, 80);
        assert_eq!(accounting.actual_work, 80);
        assert_eq!(accounting.actual_work, accounting.prospective_work);
        let exact = exact_lookup_limits(accounting);
        assert_eq!(
            map.lookup(b"abc", Direction::Forward, 1, 3, exact)
                .unwrap()
                .class,
            StartClass::WordByte,
        );

        let cases = [
            (
                LookupLimits {
                    max_input_bytes: accounting.input_bytes.checked_sub(1).unwrap(),
                    ..exact
                },
                Resource::InputBytes,
            ),
            (
                LookupLimits {
                    max_work: accounting.prospective_work.checked_sub(1).unwrap(),
                    ..exact
                },
                Resource::LookupWork,
            ),
            (
                LookupLimits {
                    max_random_access_bytes: accounting.random_access_bytes.checked_sub(1).unwrap(),
                    ..exact
                },
                Resource::RandomAccessBytes,
            ),
        ];
        for (limits, expected) in cases {
            let error = map
                .lookup(b"abc", Direction::Forward, 1, 3, limits)
                .unwrap_err();
            assert_eq!(resource(error), expected);
        }

        let empty = map
            .lookup_requirements(0, Direction::Forward, 1, 0)
            .unwrap();
        assert_eq!(empty.random_access_bytes, 0);
        assert_eq!(empty.map_reads, 0);
        assert_eq!(empty.prospective_work, 80);
        assert_eq!(empty.actual_work, 64);
        assert!(empty.actual_work < empty.prospective_work);
        assert_eq!(
            map.lookup(b"", Direction::Forward, 1, 0, exact_lookup_limits(empty))
                .unwrap()
                .class,
            StartClass::Text,
        );
    }

    #[test]
    fn byte_start_map_invalid_windows_fail_before_resource_admission() {
        let map = plan(b'\n');
        let no_resources = LookupLimits {
            max_input_bytes: 0,
            max_work: 0,
            max_random_access_bytes: 0,
        };
        assert!(matches!(
            map.lookup(b"abc", Direction::Forward, 0, 4, no_resources),
            Err(LookupError::InvalidWindow { .. })
        ));
        assert!(matches!(
            map.lookup(b"abc", Direction::Reverse, 3, 1, no_resources),
            Err(LookupError::InvalidWindow { .. })
        ));
    }
}
