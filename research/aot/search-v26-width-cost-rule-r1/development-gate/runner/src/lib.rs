//! Result-blind input materialization for the Search V26 development gate.
//!
//! This crate constructs exactly one fixture at a time. It contains no timing
//! entry point and cannot publish or execute native regex code.

use std::{
    error::Error,
    fmt, fs,
    fs::OpenOptions,
    io::{BufWriter, Write as _},
    path::{Path, PathBuf},
};

use fre_search_v26_synthetic_runner::{
    EXPECTED_LITERAL_COUNT, SyntheticLiteral, generate_population, hex,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

pub const EXPECTED_POPULATION_SHA256: &str =
    "a682375f2e6e051f97322396bafc46974df47baa3518bc17f5d6b71b56407b73";
pub const LONG_WINDOW_BYTES: usize = 2_097_152;
pub const HAYSTACK_SUFFIX_BYTES: usize = 64;
pub const MIDDLE_MATCH_OFFSET: usize = 1_048_581;
pub const EXPECTED_CELL_COUNT: usize = EXPECTED_LITERAL_COUNT * GateWindowShape::ALL.len();
pub const FIXTURE_IDENTITY_DOMAIN: &[u8] = b"FRE-SEARCH-V26-LONG-SCAN-FIXTURE-V1\0\x01";
pub const OUTPUT_IDENTITY_DOMAIN: &[u8] = b"FRE-SEARCH-V26-EXPECTED-OUTPUT-V1\0\x01";

#[derive(Debug)]
pub struct MaterializeError(String);

impl MaterializeError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for MaterializeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for MaterializeError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateWindowShape {
    NoMatch,
    FirstLegalPosition,
    MiddleCompleteVectorGroup,
    LastLegalPosition,
    OverlappingNearMissBeforeMatch,
    DensePrimaryByteFalseCandidates,
}

impl GateWindowShape {
    pub const ALL: [Self; 6] = [
        Self::NoMatch,
        Self::FirstLegalPosition,
        Self::MiddleCompleteVectorGroup,
        Self::LastLegalPosition,
        Self::OverlappingNearMissBeforeMatch,
        Self::DensePrimaryByteFalseCandidates,
    ];

    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::NoMatch => 0,
            Self::FirstLegalPosition => 1,
            Self::MiddleCompleteVectorGroup => 2,
            Self::LastLegalPosition => 3,
            Self::OverlappingNearMissBeforeMatch => 4,
            Self::DensePrimaryByteFalseCandidates => 5,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::NoMatch => "no_match",
            Self::FirstLegalPosition => "first_legal_position",
            Self::MiddleCompleteVectorGroup => "middle_complete_vector_group",
            Self::LastLegalPosition => "last_legal_position",
            Self::OverlappingNearMissBeforeMatch => "overlapping_near_miss_before_match",
            Self::DensePrimaryByteFalseCandidates => "dense_primary_byte_false_candidates",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GateFixture {
    pub shape: GateWindowShape,
    pub haystack: Vec<u8>,
    pub filler_byte: u8,
    pub window_start: usize,
    pub window_end: usize,
    pub expected_match: Option<(usize, usize)>,
    pub haystack_sha256: String,
    pub fixture_sha256: String,
}

#[derive(Debug, Serialize)]
pub struct CellRecord<'a> {
    pub schema: &'static str,
    pub cell_id: usize,
    pub shard_id: u8,
    pub population_sha256: &'static str,
    pub width: u16,
    pub output: &'static str,
    pub output_tag: u8,
    pub accepted_ordinal: u16,
    pub source_ordinal: u16,
    pub literal_hex: &'a str,
    pub literal_sha256: &'a str,
    pub window_shape: &'static str,
    pub window_shape_tag: u8,
    pub fixture_recipe: &'static str,
    pub filler_byte: u8,
    pub window_start: usize,
    pub window_end: usize,
    pub window_bytes: usize,
    pub haystack_len: usize,
    pub haystack_sha256: &'a str,
    pub fixture_sha256: &'a str,
    pub expected_match_start: Option<usize>,
    pub expected_match_end: Option<usize>,
    pub expected_output_sha256: String,
}

fn checked_add(left: usize, right: usize, context: &str) -> Result<usize, MaterializeError> {
    left.checked_add(right)
        .ok_or_else(|| MaterializeError::new(format!("{context} overflow")))
}

fn checked_sub(left: usize, right: usize, context: &str) -> Result<usize, MaterializeError> {
    left.checked_sub(right)
        .ok_or_else(|| MaterializeError::new(format!("{context} underflow")))
}

fn lowest_unused_byte(literal: &[u8]) -> Result<u8, MaterializeError> {
    (u16::from(u8::MIN)..=u16::from(u8::MAX))
        .filter_map(|value| u8::try_from(value).ok())
        .find(|candidate| !literal.contains(candidate))
        .ok_or_else(|| MaterializeError::new("literal unexpectedly contains all 256 byte values"))
}

fn append_usize(hasher: &mut Sha256, value: usize, context: &str) -> Result<(), MaterializeError> {
    let encoded = u64::try_from(value)
        .map_err(|_| MaterializeError::new(format!("{context} exceeds canonical u64 extent")))?;
    hasher.update(encoded.to_le_bytes());
    Ok(())
}

fn fixture_identity(
    literal_record: &SyntheticLiteral,
    shape: GateWindowShape,
    filler_byte: u8,
    window_start: usize,
    window_end: usize,
    expected_match: Option<(usize, usize)>,
    haystack: &[u8],
) -> Result<String, MaterializeError> {
    let mut hasher = Sha256::new();
    hasher.update(FIXTURE_IDENTITY_DOMAIN);
    hasher.update(literal_record.width.to_le_bytes());
    hasher.update([literal_record.output_tag]);
    hasher.update(literal_record.accepted_ordinal.to_le_bytes());
    hasher.update(literal_record.source_ordinal.to_le_bytes());
    hasher.update([shape.tag(), filler_byte]);
    append_usize(&mut hasher, window_start, "window start")?;
    append_usize(&mut hasher, window_end, "window end")?;
    append_usize(&mut hasher, haystack.len(), "haystack length")?;
    match expected_match {
        None => hasher.update([0]),
        Some((start, end)) => {
            hasher.update([1]);
            append_usize(&mut hasher, start, "expected match start")?;
            append_usize(&mut hasher, end, "expected match end")?;
        }
    }
    let literal_len = u16::try_from(literal_record.literal().len())
        .map_err(|_| MaterializeError::new("literal length exceeds canonical u16 extent"))?;
    hasher.update(literal_len.to_le_bytes());
    hasher.update(literal_record.literal());
    hasher.update(haystack);
    Ok(hex(&hasher.finalize()))
}

pub fn expected_output_identity(
    output_tag: u8,
    expected_match: Option<(usize, usize)>,
) -> Result<String, MaterializeError> {
    let mut hasher = Sha256::new();
    hasher.update(OUTPUT_IDENTITY_DOMAIN);
    hasher.update([output_tag]);
    match output_tag {
        1 => hasher.update([u8::from(expected_match.is_some())]),
        2 => match expected_match {
            None => hasher.update([0]),
            Some((_, end)) => {
                hasher.update([1]);
                append_usize(&mut hasher, end, "selected end")?;
            }
        },
        3 => match expected_match {
            None => hasher.update([0]),
            Some((start, end)) => {
                hasher.update([1]);
                append_usize(&mut hasher, start, "span start")?;
                append_usize(&mut hasher, end, "span end")?;
            }
        },
        _ => return Err(MaterializeError::new("unknown output tag")),
    }
    Ok(hex(&hasher.finalize()))
}

fn observed_first(literal: &[u8], fixture: &GateFixture) -> Option<(usize, usize)> {
    let window = &fixture.haystack[fixture.window_start..fixture.window_end];
    window
        .windows(literal.len())
        .position(|candidate| candidate == literal)
        .and_then(|offset| fixture.window_start.checked_add(offset))
        .and_then(|start| start.checked_add(literal.len()).map(|end| (start, end)))
}

#[allow(
    clippy::too_many_lines,
    reason = "the six frozen fixture geometries remain adjacent for review"
)]
pub fn build_fixture(
    literal_record: &SyntheticLiteral,
    shape: GateWindowShape,
) -> Result<GateFixture, MaterializeError> {
    let literal = literal_record.literal();
    let width = literal.len();
    if !(6..=32).contains(&width) || usize::from(literal_record.width) != width {
        return Err(MaterializeError::new(
            "literal width is outside the frozen 6..32 envelope",
        ));
    }
    let filler_byte = lowest_unused_byte(literal)?;
    let window_start = checked_add(
        32,
        usize::from(literal_record.accepted_ordinal),
        "window start",
    )?;
    let window_bytes = if shape == GateWindowShape::FirstLegalPosition {
        width
    } else {
        LONG_WINDOW_BYTES
    };
    let window_end = checked_add(window_start, window_bytes, "window end")?;
    let haystack_len = checked_add(window_end, HAYSTACK_SUFFIX_BYTES, "haystack length")?;
    let mut haystack = vec![filler_byte; haystack_len];

    let expected_match = match shape {
        GateWindowShape::NoMatch => None,
        GateWindowShape::FirstLegalPosition => Some((
            window_start,
            checked_add(window_start, width, "first legal match end")?,
        )),
        GateWindowShape::MiddleCompleteVectorGroup => {
            let start = checked_add(window_start, MIDDLE_MATCH_OFFSET, "middle match start")?;
            Some((start, checked_add(start, width, "middle match end")?))
        }
        GateWindowShape::LastLegalPosition | GateWindowShape::DensePrimaryByteFalseCandidates => {
            let start = checked_sub(window_end, width, "last legal match start")?;
            Some((start, window_end))
        }
        GateWindowShape::OverlappingNearMissBeforeMatch => {
            let exact_start = checked_add(
                window_start,
                MIDDLE_MATCH_OFFSET,
                "overlap exact-match start",
            )?;
            let near_start = checked_sub(
                exact_start,
                width.saturating_sub(1),
                "overlap near-miss start",
            )?;
            let near_end = checked_add(near_start, width, "overlap near-miss end")?;
            haystack[near_start..near_end].copy_from_slice(literal);
            haystack[near_start] = filler_byte;
            Some((
                exact_start,
                checked_add(exact_start, width, "overlap exact-match end")?,
            ))
        }
    };

    if shape == GateWindowShape::DensePrimaryByteFalseCandidates {
        let exact_start = expected_match
            .ok_or_else(|| MaterializeError::new("dense fixture has no exact match"))?
            .0;
        let step = checked_add(width, 3, "dense candidate step")?;
        let mut candidate_start = window_start;
        let mut candidate_index = 0_usize;
        loop {
            let candidate_end = checked_add(candidate_start, width, "dense candidate end")?;
            if candidate_end > exact_start {
                break;
            }
            let column = candidate_index
                .checked_rem(width)
                .ok_or_else(|| MaterializeError::new("dense candidate column has zero width"))?;
            let candidate_column = checked_add(candidate_start, column, "dense candidate column")?;
            haystack[candidate_column] = literal[column];
            candidate_start = checked_add(candidate_start, step, "dense candidate start")?;
            candidate_index = checked_add(candidate_index, 1, "dense candidate index")?;
        }
    }

    if let Some((start, end)) = expected_match {
        if start < window_start
            || end > window_end
            || checked_sub(end, start, "exact match width")? != width
        {
            return Err(MaterializeError::new(
                "exact match lies outside its frozen search window",
            ));
        }
        haystack[start..end].copy_from_slice(literal);
    }

    let haystack_sha256 = hex(&Sha256::digest(&haystack));
    let fixture_sha256 = fixture_identity(
        literal_record,
        shape,
        filler_byte,
        window_start,
        window_end,
        expected_match,
        &haystack,
    )?;
    let fixture = GateFixture {
        shape,
        haystack,
        filler_byte,
        window_start,
        window_end,
        expected_match,
        haystack_sha256,
        fixture_sha256,
    };
    if observed_first(literal, &fixture) != expected_match {
        return Err(MaterializeError::new(format!(
            "{} fixture does not have the frozen first-match semantics",
            shape.name()
        )));
    }
    Ok(fixture)
}

#[must_use]
pub const fn shard_for_width(width: u16) -> Option<u8> {
    match width {
        6..=14 => Some(0),
        15..=23 => Some(1),
        24..=32 => Some(2),
        _ => None,
    }
}

pub fn cell_record<'a>(
    cell_id: usize,
    literal_record: &'a SyntheticLiteral,
    fixture: &'a GateFixture,
) -> Result<CellRecord<'a>, MaterializeError> {
    let shard_id = shard_for_width(literal_record.width)
        .ok_or_else(|| MaterializeError::new("cell width is outside every shard"))?;
    let (expected_match_start, expected_match_end) = fixture
        .expected_match
        .map_or((None, None), |(start, end)| (Some(start), Some(end)));
    Ok(CellRecord {
        schema: "fre-search-v26-development-gate-cell-v1",
        cell_id,
        shard_id,
        population_sha256: EXPECTED_POPULATION_SHA256,
        width: literal_record.width,
        output: literal_record.output.name(),
        output_tag: literal_record.output_tag,
        accepted_ordinal: literal_record.accepted_ordinal,
        source_ordinal: literal_record.source_ordinal,
        literal_hex: &literal_record.literal_hex,
        literal_sha256: &literal_record.literal_sha256,
        window_shape: fixture.shape.name(),
        window_shape_tag: fixture.shape.tag(),
        fixture_recipe: "fre-search-v26-long-scan-fixture-v1",
        filler_byte: fixture.filler_byte,
        window_start: fixture.window_start,
        window_end: fixture.window_end,
        window_bytes: checked_sub(
            fixture.window_end,
            fixture.window_start,
            "record window bytes",
        )?,
        haystack_len: fixture.haystack.len(),
        haystack_sha256: &fixture.haystack_sha256,
        fixture_sha256: &fixture.fixture_sha256,
        expected_match_start,
        expected_match_end,
        expected_output_sha256: expected_output_identity(
            literal_record.output_tag,
            fixture.expected_match,
        )?,
    })
}

fn partial_path(destination: &Path) -> Result<PathBuf, MaterializeError> {
    let file_name = destination
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| MaterializeError::new("destination has no UTF-8 file name"))?;
    Ok(destination.with_file_name(format!(".{file_name}.partial.{}", std::process::id())))
}

pub fn materialize_cells(destination: &Path) -> Result<(), MaterializeError> {
    if destination.exists() {
        return Err(MaterializeError::new("destination already exists"));
    }
    let population = generate_population()
        .map_err(|error| MaterializeError::new(format!("population generation failed: {error}")))?;
    if population.population_sha256_hex() != EXPECTED_POPULATION_SHA256 {
        return Err(MaterializeError::new(
            "synthetic population identity drifted",
        ));
    }
    let temporary = partial_path(destination)?;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| {
            MaterializeError::new(format!("cannot create {}: {error}", temporary.display()))
        })?;
    let write_result = (|| {
        let mut writer = BufWriter::new(file);
        let mut cell_id = 0_usize;
        for literal_record in population.literals() {
            for shape in GateWindowShape::ALL {
                let fixture = build_fixture(literal_record, shape)?;
                let record = cell_record(cell_id, literal_record, &fixture)?;
                serde_json::to_writer(&mut writer, &record).map_err(|error| {
                    MaterializeError::new(format!("cannot serialize cell {cell_id}: {error}"))
                })?;
                writer.write_all(b"\n").map_err(|error| {
                    MaterializeError::new(format!("cannot terminate cell {cell_id}: {error}"))
                })?;
                cell_id = checked_add(cell_id, 1, "cell id")?;
            }
        }
        if cell_id != EXPECTED_CELL_COUNT {
            return Err(MaterializeError::new(format!(
                "materialized {cell_id} cells, expected {EXPECTED_CELL_COUNT}"
            )));
        }
        writer
            .flush()
            .map_err(|error| MaterializeError::new(format!("cannot flush manifest: {error}")))?;
        writer
            .get_ref()
            .sync_all()
            .map_err(|error| MaterializeError::new(format!("cannot sync manifest: {error}")))?;
        Ok(())
    })();
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    let mut permissions = fs::metadata(&temporary)
        .map_err(|error| {
            MaterializeError::new(format!("cannot inspect partial manifest: {error}"))
        })?
        .permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&temporary, permissions)
        .map_err(|error| MaterializeError::new(format!("cannot seal partial manifest: {error}")))?;
    fs::hard_link(&temporary, destination)
        .map_err(|error| MaterializeError::new(format!("cannot publish manifest: {error}")))?;
    fs::remove_file(&temporary).map_err(|error| {
        MaterializeError::new(format!("cannot unlink partial manifest: {error}"))
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn first_literal() -> SyntheticLiteral {
        generate_population()
            .expect("population")
            .literals()
            .first()
            .expect("first literal")
            .clone()
    }

    #[test]
    fn constants_close_the_frozen_lattice() {
        assert_eq!(EXPECTED_LITERAL_COUNT, 1_296);
        assert_eq!(EXPECTED_CELL_COUNT, 7_776);
        assert_eq!(shard_for_width(6), Some(0));
        assert_eq!(shard_for_width(14), Some(0));
        assert_eq!(shard_for_width(15), Some(1));
        assert_eq!(shard_for_width(24), Some(2));
        assert_eq!(shard_for_width(32), Some(2));
        assert_eq!(shard_for_width(33), None);
    }

    #[test]
    fn every_shape_has_exact_frozen_geometry_and_first_match() {
        let literal = first_literal();
        for shape in GateWindowShape::ALL {
            let fixture = build_fixture(&literal, shape).expect("fixture");
            assert_eq!(fixture.window_start, 32);
            let expected_window_bytes = if shape == GateWindowShape::FirstLegalPosition {
                6
            } else {
                LONG_WINDOW_BYTES
            };
            assert_eq!(
                fixture.window_end - fixture.window_start,
                expected_window_bytes
            );
            assert_eq!(
                fixture.haystack.len(),
                fixture.window_end + HAYSTACK_SUFFIX_BYTES
            );
            assert_eq!(
                observed_first(literal.literal(), &fixture),
                fixture.expected_match
            );
            assert!(!literal.literal().contains(&fixture.filler_byte));
        }
    }

    #[test]
    fn identities_are_deterministic_and_output_specific() {
        let literal = first_literal();
        let left =
            build_fixture(&literal, GateWindowShape::MiddleCompleteVectorGroup).expect("left");
        let right =
            build_fixture(&literal, GateWindowShape::MiddleCompleteVectorGroup).expect("right");
        assert_eq!(left.fixture_sha256, right.fixture_sha256);
        assert_eq!(left.haystack_sha256, right.haystack_sha256);
        let expected = left.expected_match;
        assert_ne!(
            expected_output_identity(1, expected).expect("exists"),
            expected_output_identity(3, expected).expect("span")
        );
    }

    #[test]
    fn record_binds_literal_fixture_and_expected_output() {
        let literal = first_literal();
        let fixture = build_fixture(&literal, GateWindowShape::NoMatch).expect("fixture");
        let record = cell_record(0, &literal, &fixture).expect("record");
        assert_eq!(record.cell_id, 0);
        assert_eq!(record.shard_id, 0);
        assert_eq!(record.output, "exists");
        assert_eq!(record.output_tag, 1);
        assert_eq!(record.window_shape, "no_match");
        assert_eq!(record.window_bytes, LONG_WINDOW_BYTES);
        assert_eq!(record.literal_sha256, literal.literal_sha256);
        assert_eq!(record.fixture_sha256, fixture.fixture_sha256);
    }
}
