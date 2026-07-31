//! Fresh, result-independent synthetic inputs for Search V26 qualification.
//!
//! Population admission deliberately crosses the public Search V17 emitter
//! boundary. This tool does not duplicate or weaken the cyclic-phase-unique
//! predicate, and it never reads a benchmark corpus or result file.

use std::{collections::BTreeMap, error::Error, fmt};

use fre_jit_aarch64::{
    AotLimits, AuditReport, EmitError, EmitLimits, ImageStats, NativeImage, SearchBackendPolicy,
    UnsupportedReason,
};
use fre_jit_runtime::{PublicationLimits, RuntimeOperation};
use fre_kernel_ir::{
    AnchorFlags, ExecutionLimits, Exists, MatchSpan, Operation, OutputKind, SearchWindow,
    SelectedEnd, Span, ValidateLimits, build_exact_literal,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

/// Exact preregistered literal derivation domain.
pub const SYNTHETIC_DOMAIN: &[u8] = b"FRE-V26-WIDTH-COST-SYNTHETIC-R1";
/// Domain for a compact identity over the ordered accepted population.
pub const POPULATION_IDENTITY_DOMAIN: &[u8] = b"FRE-V26-WIDTH-COST-SYNTHETIC-R1-POPULATION\0\x01";
pub const MIN_WIDTH: u16 = 6;
pub const MAX_WIDTH: u16 = 32;
pub const ACCEPTED_ORDINALS_PER_CELL: u16 = 16;
pub const OUTPUT_KINDS: usize = 3;
pub const EXPECTED_LITERAL_COUNT: usize = 27 * OUTPUT_KINDS * 16;

/// Stable output ordering named by the preregistration.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyntheticOutput {
    Exists,
    Span,
    SelectedEnd,
}

impl SyntheticOutput {
    pub const ALL: [Self; OUTPUT_KINDS] = [Self::Exists, Self::Span, Self::SelectedEnd];

    /// Kernel IR's stable public output-contract tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Exists => 1,
            Self::SelectedEnd => 2,
            Self::Span => 3,
        }
    }

    #[must_use]
    pub const fn output_kind(self) -> OutputKind {
        match self {
            Self::Exists => OutputKind::Exists,
            Self::SelectedEnd => OutputKind::SelectedEnd,
            Self::Span => OutputKind::Span,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Exists => "exists",
            Self::Span => "span",
            Self::SelectedEnd => "selected_end",
        }
    }
}

/// One accepted literal and the exact derivation coordinate that produced it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SyntheticLiteral {
    pub width: u16,
    pub output: SyntheticOutput,
    pub output_tag: u8,
    /// Dense accepted slot, always `0..16` within a width/output cell.
    pub accepted_ordinal: u16,
    /// Hash-domain ordinal. This advances through structurally refused inputs.
    pub source_ordinal: u16,
    pub literal_hex: String,
    pub literal_sha256: String,
    #[serde(skip)]
    literal: Vec<u8>,
}

impl SyntheticLiteral {
    #[must_use]
    pub fn literal(&self) -> &[u8] {
        &self.literal
    }
}

/// Complete ordered population and its binary canonical identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntheticPopulation {
    literals: Vec<SyntheticLiteral>,
    population_sha256: [u8; 32],
    rejected_candidates: u64,
}

impl SyntheticPopulation {
    #[must_use]
    pub fn literals(&self) -> &[SyntheticLiteral] {
        &self.literals
    }

    #[must_use]
    pub const fn population_sha256(&self) -> &[u8; 32] {
        &self.population_sha256
    }

    #[must_use]
    pub fn population_sha256_hex(&self) -> String {
        hex(&self.population_sha256)
    }

    #[must_use]
    pub const fn rejected_candidates(&self) -> u64 {
        self.rejected_candidates
    }

    #[must_use]
    pub fn counts(&self) -> BTreeMap<(u16, SyntheticOutput), usize> {
        let mut counts = BTreeMap::new();
        for literal in &self.literals {
            let count = counts
                .entry((literal.width, literal.output))
                .or_insert(0_usize);
            *count = (*count)
                .checked_add(1)
                .expect("the frozen cell count is at most sixteen");
        }
        counts
    }
}

#[derive(Debug)]
pub struct PopulationError(String);

impl PopulationError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for PopulationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for PopulationError {}

/// Generate the complete frozen population in width/output/accepted order.
pub fn generate_population() -> Result<SyntheticPopulation, PopulationError> {
    let mut literals = Vec::with_capacity(EXPECTED_LITERAL_COUNT);
    let mut rejected_candidates = 0_u64;
    for width in MIN_WIDTH..=MAX_WIDTH {
        for output in SyntheticOutput::ALL {
            let mut source_ordinal = 0_u16;
            for accepted_ordinal in 0..ACCEPTED_ORDINALS_PER_CELL {
                loop {
                    let literal = derive_literal(width, output.tag(), source_ordinal);
                    if publicly_admitted(output, &literal)? {
                        let literal_sha256 = Sha256::digest(&literal);
                        literals.push(SyntheticLiteral {
                            width,
                            output,
                            output_tag: output.tag(),
                            accepted_ordinal,
                            source_ordinal,
                            literal_hex: hex(&literal),
                            literal_sha256: hex(&literal_sha256),
                            literal,
                        });
                        source_ordinal = source_ordinal.checked_add(1).ok_or_else(|| {
                            PopulationError::new("synthetic source ordinal exhausted")
                        })?;
                        break;
                    }
                    rejected_candidates = rejected_candidates
                        .checked_add(1)
                        .ok_or_else(|| PopulationError::new("synthetic refusal count overflow"))?;
                    source_ordinal = source_ordinal.checked_add(1).ok_or_else(|| {
                        PopulationError::new("synthetic source ordinal exhausted")
                    })?;
                }
            }
        }
    }
    if literals.len() != EXPECTED_LITERAL_COUNT {
        return Err(PopulationError::new(format!(
            "generated {} literals, expected {EXPECTED_LITERAL_COUNT}",
            literals.len()
        )));
    }
    let population_sha256 = population_identity(&literals)?;
    Ok(SyntheticPopulation {
        literals,
        population_sha256,
        rejected_candidates,
    })
}

/// Derive one candidate exactly as specified by the frozen concatenation.
///
/// `block_counter` begins at zero and advances until `width` bytes exist.
#[must_use]
pub fn derive_literal(width: u16, output_tag: u8, source_ordinal: u16) -> Vec<u8> {
    let width_usize = usize::from(width);
    let mut literal = Vec::with_capacity(width_usize);
    let mut block_counter = 0_u32;
    while literal.len() < width_usize {
        let mut hasher = Sha256::new();
        hasher.update(SYNTHETIC_DOMAIN);
        hasher.update(width.to_le_bytes());
        hasher.update([output_tag]);
        hasher.update(source_ordinal.to_le_bytes());
        hasher.update(block_counter.to_le_bytes());
        literal.extend_from_slice(&hasher.finalize());
        block_counter = block_counter
            .checked_add(1)
            .expect("a width at most 32 uses one SHA-256 block");
    }
    literal.truncate(width_usize);
    literal
}

fn publicly_admitted(output: SyntheticOutput, literal: &[u8]) -> Result<bool, PopulationError> {
    match output {
        SyntheticOutput::Exists => publicly_admitted_typed::<Exists>(literal),
        SyntheticOutput::Span => publicly_admitted_typed::<Span>(literal),
        SyntheticOutput::SelectedEnd => publicly_admitted_typed::<SelectedEnd>(literal),
    }
}

fn publicly_admitted_typed<O: Operation>(literal: &[u8]) -> Result<bool, PopulationError> {
    let program =
        build_exact_literal::<O>(literal, AnchorFlags::default(), ValidateLimits::default())
            .map_err(|error| {
                PopulationError::new(format!("synthetic KIR construction failed: {error}"))
            })?;
    match fre_jit_aarch64::emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV17,
        EmitLimits::default(),
    ) {
        Ok(_) => Ok(true),
        Err(EmitError::Unsupported {
            reason: UnsupportedReason::KernelShape,
        }) => Ok(false),
        Err(error) => Err(PopulationError::new(format!(
            "public Search V17 admission failed unexpectedly: {error}"
        ))),
    }
}

fn population_identity(literals: &[SyntheticLiteral]) -> Result<[u8; 32], PopulationError> {
    let mut hasher = Sha256::new();
    hasher.update(POPULATION_IDENTITY_DOMAIN);
    for literal in literals {
        hasher.update(literal.width.to_le_bytes());
        hasher.update([literal.output_tag]);
        hasher.update(literal.accepted_ordinal.to_le_bytes());
        hasher.update(literal.source_ordinal.to_le_bytes());
        let literal_len = u16::try_from(literal.literal.len())
            .map_err(|_| PopulationError::new("literal width exceeds canonical u16 extent"))?;
        hasher.update(literal_len.to_le_bytes());
        hasher.update(&literal.literal);
    }
    let digest = hasher.finalize();
    let mut identity = [0_u8; 32];
    identity.copy_from_slice(&digest);
    Ok(identity)
}

#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// Frozen correctness window-shape ordering.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowShape {
    NoMatch,
    FirstLegalPosition,
    MiddleCompleteVectorGroup,
    LastLegalPosition,
    OverlappingNearMissBeforeMatch,
    DensePrimaryByteFalseCandidates,
}

impl WindowShape {
    pub const ALL: [Self; 6] = [
        Self::NoMatch,
        Self::FirstLegalPosition,
        Self::MiddleCompleteVectorGroup,
        Self::LastLegalPosition,
        Self::OverlappingNearMissBeforeMatch,
        Self::DensePrimaryByteFalseCandidates,
    ];
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorrectnessFixture {
    pub shape: WindowShape,
    pub haystack: Vec<u8>,
    pub window: SearchWindow,
    pub expected: Option<MatchSpan>,
}

/// Build all six frozen, corpus-independent correctness geometries.
#[allow(
    clippy::too_many_lines,
    reason = "the six frozen geometries stay adjacent so their exact constants remain reviewable"
)]
pub fn correctness_fixtures(literal: &[u8]) -> Result<Vec<CorrectnessFixture>, PopulationError> {
    if !(usize::from(MIN_WIDTH)..=usize::from(MAX_WIDTH)).contains(&literal.len()) {
        return Err(PopulationError::new(
            "correctness fixture literal must have width 6..32",
        ));
    }
    let filler = unused_byte(literal)?;
    let width = literal.len();
    let mut fixtures = Vec::with_capacity(WindowShape::ALL.len());

    let no_match_start = 11_usize;
    let no_match_end = no_match_start
        .checked_add(192)
        .and_then(|value| value.checked_add(width))
        .ok_or_else(|| PopulationError::new("no-match fixture extent overflow"))?;
    let no_match_haystack_len = no_match_end
        .checked_add(13)
        .ok_or_else(|| PopulationError::new("no-match haystack extent overflow"))?;
    fixtures.push(CorrectnessFixture {
        shape: WindowShape::NoMatch,
        haystack: vec![filler; no_match_haystack_len],
        window: SearchWindow::new(no_match_start, no_match_end),
        expected: None,
    });

    let first_start = 7_usize;
    let first_end = first_start
        .checked_add(width)
        .and_then(|value| value.checked_add(96))
        .ok_or_else(|| PopulationError::new("first-position fixture extent overflow"))?;
    let first_haystack_len = first_end
        .checked_add(9)
        .ok_or_else(|| PopulationError::new("first-position haystack extent overflow"))?;
    fixtures.push(fixture_with_match(
        WindowShape::FirstLegalPosition,
        literal,
        filler,
        first_start,
        first_end,
        first_start,
        first_haystack_len,
    )?);

    let middle_start = 13_usize;
    let middle_match = middle_start
        .checked_add(64)
        .and_then(|value| value.checked_add(5))
        .ok_or_else(|| PopulationError::new("middle match start overflow"))?;
    let middle_end = middle_match
        .checked_add(width)
        .and_then(|value| value.checked_add(83))
        .ok_or_else(|| PopulationError::new("middle fixture extent overflow"))?;
    let middle_haystack_len = middle_end
        .checked_add(11)
        .ok_or_else(|| PopulationError::new("middle haystack extent overflow"))?;
    fixtures.push(fixture_with_match(
        WindowShape::MiddleCompleteVectorGroup,
        literal,
        filler,
        middle_start,
        middle_end,
        middle_match,
        middle_haystack_len,
    )?);

    let last_start = 9_usize;
    let last_end = last_start
        .checked_add(257)
        .and_then(|value| value.checked_add(width))
        .ok_or_else(|| PopulationError::new("last-position fixture extent overflow"))?;
    let last_match = last_end
        .checked_sub(width)
        .ok_or_else(|| PopulationError::new("last-position match underflow"))?;
    let last_haystack_len = last_end
        .checked_add(15)
        .ok_or_else(|| PopulationError::new("last-position haystack extent overflow"))?;
    fixtures.push(fixture_with_match(
        WindowShape::LastLegalPosition,
        literal,
        filler,
        last_start,
        last_end,
        last_match,
        last_haystack_len,
    )?);

    let overlap_start = 5_usize;
    let overlap_match = overlap_start + 67;
    let overlap_end = overlap_match
        .checked_add(width)
        .and_then(|value| value.checked_add(71))
        .ok_or_else(|| PopulationError::new("overlap fixture extent overflow"))?;
    let overlap_haystack_len = overlap_end
        .checked_add(7)
        .ok_or_else(|| PopulationError::new("overlap haystack extent overflow"))?;
    let overlap_fixture = fixture_with_match(
        WindowShape::OverlappingNearMissBeforeMatch,
        literal,
        filler,
        overlap_start,
        overlap_end,
        overlap_match,
        overlap_haystack_len,
    )?;
    let near_start = overlap_match
        .checked_sub(1)
        .ok_or_else(|| PopulationError::new("overlap near-miss underflow"))?;
    let near_end = near_start
        .checked_add(width)
        .ok_or_else(|| PopulationError::new("overlap near-miss overflow"))?;
    if overlap_fixture.haystack.get(near_start..near_end) == Some(literal) {
        return Err(PopulationError::new(
            "overlapping predecessor unexpectedly matches",
        ));
    }
    fixtures.push(overlap_fixture);

    fixtures.push(dense_false_candidate_fixture(literal, filler)?);

    for fixture in &fixtures {
        if fixture.window.end() > fixture.haystack.len()
            || fixture.window.start() > fixture.window.end()
        {
            return Err(PopulationError::new(format!(
                "invalid {:?} correctness window",
                fixture.shape
            )));
        }
        let observed = naive_first(literal, &fixture.haystack, fixture.window)?;
        if observed != fixture.expected {
            return Err(PopulationError::new(format!(
                "{:?} geometry selected {observed:?}, expected {:?}",
                fixture.shape, fixture.expected
            )));
        }
    }
    Ok(fixtures)
}

fn fixture_with_match(
    shape: WindowShape,
    literal: &[u8],
    filler: u8,
    window_start: usize,
    window_end: usize,
    match_start: usize,
    haystack_len: usize,
) -> Result<CorrectnessFixture, PopulationError> {
    let match_end = match_start
        .checked_add(literal.len())
        .ok_or_else(|| PopulationError::new("fixture match extent overflow"))?;
    if match_start < window_start || match_end > window_end || window_end > haystack_len {
        return Err(PopulationError::new("fixture geometry is out of bounds"));
    }
    let mut haystack = vec![filler; haystack_len];
    haystack[match_start..match_end].copy_from_slice(literal);
    Ok(CorrectnessFixture {
        shape,
        haystack,
        window: SearchWindow::new(window_start, window_end),
        expected: Some(MatchSpan::new(match_start, match_end)),
    })
}

fn dense_false_candidate_fixture(
    literal: &[u8],
    filler: u8,
) -> Result<CorrectnessFixture, PopulationError> {
    let width = literal.len();
    let window_start = 8_usize;
    let dense_bytes = 48_usize
        .checked_add(width)
        .ok_or_else(|| PopulationError::new("dense segment extent overflow"))?;
    let gap_bytes = width
        .checked_add(3)
        .ok_or_else(|| PopulationError::new("dense gap extent overflow"))?;
    let mut haystack = vec![filler; window_start];
    for &candidate_byte in literal {
        let segment_end = haystack
            .len()
            .checked_add(dense_bytes)
            .ok_or_else(|| PopulationError::new("dense fixture extent overflow"))?;
        haystack.resize(segment_end, candidate_byte);
        let gap_end = haystack
            .len()
            .checked_add(gap_bytes)
            .ok_or_else(|| PopulationError::new("dense fixture gap overflow"))?;
        haystack.resize(gap_end, filler);
    }
    let match_start = haystack
        .len()
        .checked_add(31)
        .ok_or_else(|| PopulationError::new("dense match start overflow"))?;
    haystack.resize(match_start, filler);
    let match_end = match_start
        .checked_add(width)
        .ok_or_else(|| PopulationError::new("dense match extent overflow"))?;
    let haystack_len = match_end
        .checked_add(29)
        .ok_or_else(|| PopulationError::new("dense haystack extent overflow"))?;
    haystack.resize(haystack_len, filler);
    haystack[match_start..match_end].copy_from_slice(literal);
    let window_end = haystack
        .len()
        .checked_sub(7)
        .ok_or_else(|| PopulationError::new("dense window end underflow"))?;
    Ok(CorrectnessFixture {
        shape: WindowShape::DensePrimaryByteFalseCandidates,
        haystack,
        window: SearchWindow::new(window_start, window_end),
        expected: Some(MatchSpan::new(match_start, match_end)),
    })
}

fn unused_byte(literal: &[u8]) -> Result<u8, PopulationError> {
    (u16::from(u8::MIN)..=u16::from(u8::MAX))
        .filter_map(|value| u8::try_from(value).ok())
        .find(|candidate| !literal.contains(candidate))
        .ok_or_else(|| PopulationError::new("bounded literal unexpectedly contains every byte"))
}

fn naive_first(
    literal: &[u8],
    haystack: &[u8],
    window: SearchWindow,
) -> Result<Option<MatchSpan>, PopulationError> {
    let last_start = window
        .end()
        .checked_sub(literal.len())
        .filter(|last| *last >= window.start());
    let Some(last_start) = last_start else {
        return Ok(None);
    };
    for start in window.start()..=last_start {
        let end = start
            .checked_add(literal.len())
            .ok_or_else(|| PopulationError::new("naive search extent overflow"))?;
        if haystack.get(start..end) == Some(literal) {
            return Ok(Some(MatchSpan::new(start, end)));
        }
    }
    Ok(None)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct StaticTotals {
    pub objects: u64,
    pub code_bytes: u64,
    pub data_bytes: u64,
    pub labels: u64,
    pub relocations: u64,
    pub emission_work: u64,
    pub scratch_bytes: u64,
    pub vector_instructions: u64,
    pub audited_instructions: u64,
}

impl StaticTotals {
    fn checked_add(
        &mut self,
        stats: ImageStats,
        audit: AuditReport,
    ) -> Result<(), PopulationError> {
        self.objects = checked_sum(self.objects, 1, "static object count")?;
        self.code_bytes = checked_sum(self.code_bytes, u64::from(stats.code_bytes), "code bytes")?;
        self.data_bytes = checked_sum(self.data_bytes, u64::from(stats.data_bytes), "data bytes")?;
        self.labels = checked_sum(self.labels, u64::from(stats.labels), "labels")?;
        self.relocations = checked_sum(
            self.relocations,
            u64::from(stats.relocations),
            "relocations",
        )?;
        self.emission_work = checked_sum(self.emission_work, stats.emission_work, "emission work")?;
        self.scratch_bytes = checked_sum(self.scratch_bytes, stats.scratch_bytes, "scratch bytes")?;
        self.vector_instructions = checked_sum(
            self.vector_instructions,
            u64::from(stats.vector_instructions),
            "vector instructions",
        )?;
        self.audited_instructions = checked_sum(
            self.audited_instructions,
            u64::from(audit.instructions),
            "audited instructions",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StaticParityReport {
    pub schema: &'static str,
    pub population_sha256: String,
    pub candidate_backend: u16,
    pub short_source_backend: u16,
    pub wide_source_backend: u16,
    pub literals: usize,
    pub exact_machine_object_parities: usize,
    pub distinct_aot_identities: usize,
    pub candidate: StaticTotals,
    pub selected_source: StaticTotals,
    pub timing: &'static str,
}

/// Emit and audit candidate/source objects and enforce exact graph parity.
///
/// This is static evidence only. It never publishes or executes machine code.
pub fn static_parity(
    population: &SyntheticPopulation,
    candidate: SearchBackendPolicy,
) -> Result<StaticParityReport, PopulationError> {
    let mut candidate_totals = StaticTotals::default();
    let mut source_totals = StaticTotals::default();
    let mut exact_machine_object_parities = 0_usize;
    let mut distinct_aot_identities = 0_usize;
    for literal in population.literals() {
        let source = selected_source_policy(literal.width);
        let evidence = match literal.output {
            SyntheticOutput::Exists => {
                static_parity_typed::<Exists>(literal.literal(), candidate, source)?
            }
            SyntheticOutput::Span => {
                static_parity_typed::<Span>(literal.literal(), candidate, source)?
            }
            SyntheticOutput::SelectedEnd => {
                static_parity_typed::<SelectedEnd>(literal.literal(), candidate, source)?
            }
        };
        candidate_totals.checked_add(evidence.candidate.stats(), evidence.candidate_audit)?;
        source_totals.checked_add(evidence.source.stats(), evidence.source_audit)?;
        exact_machine_object_parities = exact_machine_object_parities
            .checked_add(1)
            .ok_or_else(|| PopulationError::new("static parity count overflow"))?;
        distinct_aot_identities = distinct_aot_identities
            .checked_add(1)
            .ok_or_else(|| PopulationError::new("AOT distinction count overflow"))?;
    }
    Ok(StaticParityReport {
        schema: "fre.aot.search-v26-local-static-parity.v1",
        population_sha256: population.population_sha256_hex(),
        candidate_backend: candidate.backend_version().0,
        short_source_backend: SearchBackendPolicy::AsimdV17.backend_version().0,
        wide_source_backend: SearchBackendPolicy::AsimdV25.backend_version().0,
        literals: population.literals().len(),
        exact_machine_object_parities,
        distinct_aot_identities,
        candidate: candidate_totals,
        selected_source: source_totals,
        timing: "not-run",
    })
}

struct StaticPair {
    candidate: NativeImage,
    source: NativeImage,
    candidate_audit: AuditReport,
    source_audit: AuditReport,
}

fn static_parity_typed<O: Operation>(
    literal: &[u8],
    candidate_policy: SearchBackendPolicy,
    source_policy: SearchBackendPolicy,
) -> Result<StaticPair, PopulationError> {
    let program =
        build_exact_literal::<O>(literal, AnchorFlags::default(), ValidateLimits::default())
            .map_err(|error| PopulationError::new(format!("static KIR build failed: {error}")))?;
    let candidate =
        fre_jit_aarch64::emit_with_backend(&program, candidate_policy, EmitLimits::default())
            .map_err(|error| PopulationError::new(format!("candidate emission failed: {error}")))?;
    let source = fre_jit_aarch64::emit_with_backend(&program, source_policy, EmitLimits::default())
        .map_err(|error| PopulationError::new(format!("source emission failed: {error}")))?;
    let candidate_audit = fre_jit_aarch64::audit(&candidate)
        .map_err(|error| PopulationError::new(format!("candidate audit failed: {error}")))?;
    let source_audit = fre_jit_aarch64::audit(&source)
        .map_err(|error| PopulationError::new(format!("source audit failed: {error}")))?;
    require_machine_object_parity(&candidate, &source, candidate_audit, source_audit)?;
    let candidate_aot = candidate
        .to_aot(AotLimits::default())
        .map_err(|error| PopulationError::new(format!("candidate AOT encoding failed: {error}")))?;
    let source_aot = source
        .to_aot(AotLimits::default())
        .map_err(|error| PopulationError::new(format!("source AOT encoding failed: {error}")))?;
    if candidate.backend_version() == source.backend_version()
        || candidate.artifact_identity() == source.artifact_identity()
        || candidate_aot == source_aot
        || candidate_aot.identity() == source_aot.identity()
    {
        return Err(PopulationError::new(
            "candidate/source AOT identities are not distinct",
        ));
    }
    Ok(StaticPair {
        candidate,
        source,
        candidate_audit,
        source_audit,
    })
}

fn require_machine_object_parity(
    candidate: &NativeImage,
    source: &NativeImage,
    candidate_audit: AuditReport,
    source_audit: AuditReport,
) -> Result<(), PopulationError> {
    let parity = candidate.target() == source.target()
        && candidate.output() == source.output()
        && candidate.source_identity() == source.source_identity()
        && candidate.layout() == source.layout()
        && candidate.code() == source.code()
        && candidate.rodata() == source.rodata()
        && candidate.labels() == source.labels()
        && candidate.symbols() == source.symbols()
        && candidate.relocations() == source.relocations()
        && candidate.stats() == source.stats()
        && candidate_audit == source_audit;
    if !parity {
        return Err(PopulationError::new(
            "candidate differs from width-selected source machine object",
        ));
    }
    Ok(())
}

#[must_use]
pub const fn selected_source_policy(width: u16) -> SearchBackendPolicy {
    if width <= 8 {
        SearchBackendPolicy::AsimdV17
    } else {
        SearchBackendPolicy::AsimdV25
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NativeCorrectnessReport {
    pub schema: &'static str,
    pub population_sha256: String,
    pub backend: u16,
    pub literals: usize,
    pub window_shapes: usize,
    pub comparisons: usize,
    pub mismatches: usize,
}

/// Differentially execute one backend against the safe KIR oracle.
pub fn native_correctness(
    population: &SyntheticPopulation,
    backend: SearchBackendPolicy,
) -> Result<NativeCorrectnessReport, PopulationError> {
    let mut comparisons = 0_usize;
    for literal in population.literals() {
        let checked = match literal.output {
            SyntheticOutput::Exists => {
                native_correctness_typed::<Exists>(literal.literal(), backend)?
            }
            SyntheticOutput::Span => native_correctness_typed::<Span>(literal.literal(), backend)?,
            SyntheticOutput::SelectedEnd => {
                native_correctness_typed::<SelectedEnd>(literal.literal(), backend)?
            }
        };
        comparisons = comparisons
            .checked_add(checked)
            .ok_or_else(|| PopulationError::new("native correctness count overflow"))?;
    }
    Ok(NativeCorrectnessReport {
        schema: "fre.aot.search-v26-local-native-correctness.v1",
        population_sha256: population.population_sha256_hex(),
        backend: backend.backend_version().0,
        literals: population.literals().len(),
        window_shapes: WindowShape::ALL.len(),
        comparisons,
        mismatches: 0,
    })
}

fn native_correctness_typed<O: RuntimeOperation>(
    literal: &[u8],
    backend: SearchBackendPolicy,
) -> Result<usize, PopulationError> {
    let program =
        build_exact_literal::<O>(literal, AnchorFlags::default(), ValidateLimits::default())
            .map_err(|error| {
                PopulationError::new(format!("correctness KIR build failed: {error}"))
            })?;
    let image =
        fre_jit_aarch64::emit_audited_with_backend(&program, backend, EmitLimits::default())
            .map_err(|error| {
                PopulationError::new(format!("correctness emission failed: {error}"))
            })?;
    let kernel = fre_jit_runtime::publish_audited::<O>(&image, PublicationLimits::default())
        .map_err(|error| {
            PopulationError::new(format!("correctness publication failed: {error}"))
        })?;
    let fixtures = correctness_fixtures(literal)?;
    for fixture in &fixtures {
        let expected = program
            .execute(
                &fixture.haystack,
                fixture.window,
                ExecutionLimits::unlimited(),
            )
            .map_err(|error| PopulationError::new(format!("KIR oracle failed: {error}")))?
            .into_output();
        let observed = kernel
            .search(&fixture.haystack, fixture.window)
            .map_err(|error| PopulationError::new(format!("native search failed: {error}")))?;
        if observed != expected {
            return Err(PopulationError::new(format!(
                "{:?} native/KIR mismatch: observed {observed:?}, expected {expected:?}",
                fixture.shape
            )));
        }
    }
    Ok(fixtures.len())
}

fn checked_sum(left: u64, right: u64, field: &str) -> Result<u64, PopulationError> {
    left.checked_add(right)
        .ok_or_else(|| PopulationError::new(format!("{field} overflow")))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn derivation_coordinate_is_stable() {
        assert_eq!(
            hex(&derive_literal(6, SyntheticOutput::Exists.tag(), 0)),
            "209e4b5ad886"
        );
        assert_eq!(
            hex(&derive_literal(32, SyntheticOutput::SelectedEnd.tag(), 15)),
            "026d460d2757573262fc077fd39d1b744f10439e53b35f832529b5b8934e40e5"
        );
    }

    #[test]
    fn population_is_deterministic_fresh_and_complete() {
        let first = generate_population().expect("first fresh population");
        let second = generate_population().expect("second fresh population");
        assert_eq!(first, second);
        assert_eq!(first.literals().len(), EXPECTED_LITERAL_COUNT);
        assert_eq!(first.counts().len(), 27 * OUTPUT_KINDS);
        assert!(first.counts().values().all(|&count| count == 16));

        let unique = first
            .literals()
            .iter()
            .map(|literal| literal.literal().to_vec())
            .collect::<BTreeSet<_>>();
        assert_eq!(unique.len(), EXPECTED_LITERAL_COUNT);

        for width in MIN_WIDTH..=MAX_WIDTH {
            for output in SyntheticOutput::ALL {
                let cell = first
                    .literals()
                    .iter()
                    .filter(|literal| literal.width == width && literal.output == output)
                    .collect::<Vec<_>>();
                assert_eq!(cell.len(), usize::from(ACCEPTED_ORDINALS_PER_CELL));
                for (accepted, literal) in cell.into_iter().enumerate() {
                    assert_eq!(usize::from(literal.accepted_ordinal), accepted);
                    assert_eq!(literal.literal().len(), usize::from(width));
                    assert_eq!(literal.output_tag, output.tag());
                    assert!(
                        publicly_admitted(output, literal.literal()).expect("public admission")
                    );
                }
            }
        }
    }

    #[test]
    fn population_identity_is_stable() {
        let population = generate_population().expect("fresh population");
        assert_eq!(
            population.population_sha256_hex(),
            "a682375f2e6e051f97322396bafc46974df47baa3518bc17f5d6b71b56407b73"
        );
    }

    #[test]
    fn output_tags_match_public_kernel_ir_contract() {
        assert_eq!(SyntheticOutput::Exists.tag(), 1);
        assert_eq!(SyntheticOutput::Exists.output_kind(), OutputKind::Exists);
        assert_eq!(SyntheticOutput::SelectedEnd.tag(), 2);
        assert_eq!(
            SyntheticOutput::SelectedEnd.output_kind(),
            OutputKind::SelectedEnd
        );
        assert_eq!(SyntheticOutput::Span.tag(), 3);
        assert_eq!(SyntheticOutput::Span.output_kind(), OutputKind::Span);
    }

    #[test]
    fn frozen_fixtures_have_exact_geometry_and_kir_semantics() {
        let population = generate_population().expect("fresh population");
        let mut comparisons = 0_usize;
        for literal in population.literals() {
            let fixtures = correctness_fixtures(literal.literal()).expect("correctness fixtures");
            assert_eq!(fixtures.len(), WindowShape::ALL.len());
            assert_eq!(
                fixtures
                    .iter()
                    .map(|fixture| fixture.shape)
                    .collect::<Vec<_>>(),
                WindowShape::ALL
            );
            match literal.output {
                SyntheticOutput::Exists => {
                    let program = build_exact_literal::<Exists>(
                        literal.literal(),
                        AnchorFlags::default(),
                        ValidateLimits::default(),
                    )
                    .expect("Exists KIR");
                    for fixture in &fixtures {
                        assert_eq!(
                            program
                                .execute(
                                    &fixture.haystack,
                                    fixture.window,
                                    ExecutionLimits::unlimited()
                                )
                                .expect("Exists oracle")
                                .into_output(),
                            fixture.expected.is_some()
                        );
                    }
                }
                SyntheticOutput::Span => {
                    let program = build_exact_literal::<Span>(
                        literal.literal(),
                        AnchorFlags::default(),
                        ValidateLimits::default(),
                    )
                    .expect("Span KIR");
                    for fixture in &fixtures {
                        assert_eq!(
                            program
                                .execute(
                                    &fixture.haystack,
                                    fixture.window,
                                    ExecutionLimits::unlimited()
                                )
                                .expect("Span oracle")
                                .into_output(),
                            fixture.expected
                        );
                    }
                }
                SyntheticOutput::SelectedEnd => {
                    let program = build_exact_literal::<SelectedEnd>(
                        literal.literal(),
                        AnchorFlags::default(),
                        ValidateLimits::default(),
                    )
                    .expect("SelectedEnd KIR");
                    for fixture in &fixtures {
                        assert_eq!(
                            program
                                .execute(
                                    &fixture.haystack,
                                    fixture.window,
                                    ExecutionLimits::unlimited()
                                )
                                .expect("SelectedEnd oracle")
                                .into_output(),
                            fixture.expected.map(MatchSpan::end)
                        );
                    }
                }
            }
            comparisons = comparisons
                .checked_add(fixtures.len())
                .expect("frozen comparison count");
        }
        assert_eq!(comparisons, EXPECTED_LITERAL_COUNT * WindowShape::ALL.len());
    }

    #[test]
    fn width_rule_selects_only_frozen_source_graphs() {
        assert_eq!(selected_source_policy(6), SearchBackendPolicy::AsimdV17);
        assert_eq!(selected_source_policy(8), SearchBackendPolicy::AsimdV17);
        assert_eq!(selected_source_policy(9), SearchBackendPolicy::AsimdV25);
        assert_eq!(selected_source_policy(32), SearchBackendPolicy::AsimdV25);
    }
}
