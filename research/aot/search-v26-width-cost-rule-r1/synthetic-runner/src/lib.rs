//! Fresh, result-independent synthetic inputs for Search V26 qualification.
//!
//! Population admission deliberately crosses the public Search V17 emitter
//! boundary. This tool does not duplicate or weaken the cyclic-phase-unique
//! predicate, and it never reads a benchmark corpus or result file.

use std::{collections::BTreeMap, error::Error, fmt};

use fre_jit_aarch64::{EmitError, EmitLimits, SearchBackendPolicy, UnsupportedReason};
use fre_kernel_ir::{
    AnchorFlags, Exists, Operation, OutputKind, SelectedEnd, Span, ValidateLimits,
    build_exact_literal,
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
}
