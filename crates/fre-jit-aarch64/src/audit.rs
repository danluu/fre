use core::fmt;

use crate::{
    BackendVersion, Condition, CpuFeatures, DataSymbolKind, DecodeError, DecodedInstruction,
    LabelKind, NativeAggregateImage, NativeImage, RelocationKind, RelocationTarget,
    decode::{canonical_word, decode},
    image::{SearchManifest, SearchShape},
};
use fre_kernel_ir::{
    AggregateOutput, AnchorFlags, ByteClass, CacheIdentity, Count, Exists,
    MAX_EXACT_AGGREGATE_LITERAL_BYTES, OutputKind, SelectedEnd, Span, SpanSum, ValidateLimits,
    build_class_suffix, build_exact_aggregate, build_exact_literal,
};

/// Independent post-emission authenticity failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditError {
    Decode(DecodeError),
    InvalidImageContract,
    InvalidLayout,
    InvalidLabel {
        offset: u32,
    },
    InvalidDataSymbol {
        id: u32,
    },
    OverlappingDataSymbols {
        first: u32,
        second: u32,
    },
    InvalidRelocation {
        offset: u32,
    },
    OverlappingRelocations {
        offset: u32,
    },
    MissingRelocation {
        offset: u32,
    },
    UnexpectedRelocation {
        offset: u32,
    },
    RelocationKindMismatch {
        offset: u32,
    },
    RelocationWordMismatch {
        offset: u32,
    },
    NonCanonicalInstruction {
        offset: u32,
    },
    BranchTargetNotLabel {
        offset: u32,
        target: i64,
    },
    AddressTargetNotData {
        offset: u32,
        target: i64,
    },
    ForbiddenStore {
        offset: u32,
        base: u8,
        displacement: u16,
    },
    ResultPointerClobber {
        offset: u32,
        register: u8,
    },
    InvalidSearchCandidateContract {
        offset: u32,
    },
    InvalidSearchManifest,
    SearchBackendVersionMismatch {
        expected: u16,
        actual: u16,
    },
    ForbiddenSearchVectorRegister {
        offset: u32,
        register: u8,
    },
    InvalidAggregateManifest,
    ForbiddenAggregateRegister {
        offset: u32,
        register: u8,
    },
    ForbiddenAggregateVectorRegister {
        offset: u32,
        register: u8,
    },
    InvalidAggregateStatus {
        offset: u32,
        status: u16,
    },
    InvalidAggregateControlFlow {
        offset: u32,
    },
    InvalidAggregateLoad {
        offset: u32,
    },
    InvalidAggregateStoreContract,
    InvalidAggregateTemplate {
        offset: u32,
    },
    ArtifactIdentityMismatch,
    FeatureMismatch,
    ArithmeticOverflow,
}

impl From<DecodeError> for AuditError {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}

impl fmt::Display for AuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "AArch64 image audit failed: {self:?}")
    }
}

impl std::error::Error for AuditError {}

/// Instruction-shape and manifest evidence produced by a successful audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditReport {
    /// Complete instruction decode passes performed by this cold audit.
    pub decode_passes: u32,
    /// Semantic source identities rebuilt from authenticated rodata.
    pub source_identity_rebuilds: u32,
    pub instructions: u32,
    pub direct_branches: u32,
    pub data_addresses: u32,
    pub vector_instructions: u32,
    pub stores: u32,
    pub returns: u32,
}

#[derive(Default)]
struct AuditWork {
    decode_passes: u32,
    source_identity_rebuilds: u32,
}

impl AuditWork {
    fn decode(&mut self, code: &[u8]) -> Result<Vec<DecodedInstruction>, AuditError> {
        let instructions = decode(code)?;
        self.decode_passes = self
            .decode_passes
            .checked_add(1)
            .ok_or(AuditError::ArithmeticOverflow)?;
        Ok(instructions)
    }

    fn record_source_identity_rebuild(&mut self) -> Result<(), AuditError> {
        self.source_identity_rebuilds = self
            .source_identity_rebuilds
            .checked_add(1)
            .ok_or(AuditError::ArithmeticOverflow)?;
        Ok(())
    }
}

/// Re-decode and authenticate a finalized image.
///
/// This pass shares no encoding helpers with the emitter. It proves that each
/// direct target is a declared label, each data address names immutable image
/// data, relocations are complete/non-overlapping, result stores follow the
/// fixed ABI, and no unknown or indirect instruction is present.
#[allow(
    clippy::too_many_lines,
    reason = "keeping the independent linear audit in one pass makes relocation completeness auditable"
)]
pub fn audit(image: &NativeImage) -> Result<AuditReport, AuditError> {
    if image.aggregate_manifest().is_some() {
        return Err(AuditError::InvalidImageContract);
    }
    // Version and sealed-container checks intentionally precede instruction
    // decoding or semantic-shape interpretation. In particular, changing a
    // v2 image's container version to v1 cannot select an older, weaker audit.
    let mut work = AuditWork::default();
    let envelope = authenticate_search_envelope(image, &mut work)?;
    let instructions = work.decode(image.code())?;
    let manifest = envelope.manifest;
    let literal = envelope.literal;
    let report = audit_impl(image, StoreContract::Search, &instructions, &work)?;
    crate::search_template::validate_search_whole_template(
        image,
        manifest,
        literal,
        &instructions,
    )?;
    if manifest.backend_version == BackendVersion::SEARCH_V3
        && manifest.shape == SearchShape::ExactLiteral
        && manifest.anchors == AnchorFlags::default()
        && !literal.is_empty()
    {
        validate_search_candidate_contract(image, manifest, literal, &instructions)?;
    }
    validate_artifact_identity(image)?;
    Ok(report)
}

/// Independently re-decode a whole-haystack aggregate image.
pub fn audit_aggregate(image: &NativeAggregateImage) -> Result<AuditReport, AuditError> {
    let mut work = AuditWork::default();
    let envelope = authenticate_aggregate_envelope(image.inner(), &mut work)?;
    let instructions = work.decode(image.code())?;
    let report = audit_impl(
        image.inner(),
        StoreContract::Aggregate,
        &instructions,
        &work,
    )?;
    audit_aggregate_contract(image.inner(), &instructions, envelope)?;
    validate_artifact_identity(image.inner())?;
    Ok(report)
}

fn validate_artifact_identity(image: &NativeImage) -> Result<(), AuditError> {
    let recomputed = image
        .compute_artifact_identity()
        .map_err(|_| AuditError::ArithmeticOverflow)?;
    if recomputed != image.artifact_identity() {
        return Err(AuditError::ArtifactIdentityMismatch);
    }
    Ok(())
}

fn validate_search_backend_version(image: &NativeImage) -> Result<BackendVersion, AuditError> {
    match image.backend_version {
        BackendVersion::SEARCH_V1
        | BackendVersion::SEARCH_V2
        | BackendVersion::SEARCH_V3
        | BackendVersion::SEARCH_V4
        | BackendVersion::SEARCH_V5
        | BackendVersion::SEARCH_V6
        | BackendVersion::SEARCH_V7
        | BackendVersion::SEARCH_SVE16_V1
        | BackendVersion::SEARCH_SVE2_16_V1 => Ok(image.backend_version),
        actual => Err(AuditError::SearchBackendVersionMismatch {
            expected: BackendVersion::SEARCH_CURRENT.0,
            actual: actual.0,
        }),
    }
}

struct AuthenticatedSearchEnvelope<'image> {
    manifest: SearchManifest,
    literal: &'image [u8],
}

fn authenticate_search_envelope<'image>(
    image: &'image NativeImage,
    work: &mut AuditWork,
) -> Result<AuthenticatedSearchEnvelope<'image>, AuditError> {
    let backend = validate_search_backend_version(image)?;
    if image.aggregate_manifest().is_some() {
        return Err(AuditError::InvalidImageContract);
    }
    if matches!(
        backend,
        BackendVersion::SEARCH_V3
            | BackendVersion::SEARCH_V4
            | BackendVersion::SEARCH_V5
            | BackendVersion::SEARCH_V6
            | BackendVersion::SEARCH_V7
            | BackendVersion::SEARCH_SVE16_V1
            | BackendVersion::SEARCH_SVE2_16_V1
    ) {
        let manifest = validate_sealed_search_manifest(image)?;
        let literal = authenticate_search_manifest(image, manifest, work)?;
        return Ok(AuthenticatedSearchEnvelope { manifest, literal });
    }
    if image.search_manifest().is_some() {
        return Err(AuditError::InvalidImageContract);
    }
    let manifest = authenticate_legacy_search_semantics(image, backend, work)?;
    let literal = authenticate_search_manifest(image, manifest, work)?;
    Ok(AuthenticatedSearchEnvelope { manifest, literal })
}

fn validate_sealed_search_manifest(image: &NativeImage) -> Result<SearchManifest, AuditError> {
    let manifest = image
        .search_manifest()
        .ok_or(AuditError::InvalidSearchManifest)?;
    if manifest.backend_version != image.backend_version
        || manifest.output != image.output
        || manifest.source_identity != image.source_identity
    {
        return Err(AuditError::InvalidSearchManifest);
    }
    Ok(manifest)
}

#[allow(
    clippy::too_many_lines,
    reason = "the legacy envelope enumerates every anchor and seals the derived compatibility context in one reviewable function"
)]
fn authenticate_legacy_search_semantics(
    image: &NativeImage,
    backend: BackendVersion,
    work: &mut AuditWork,
) -> Result<SearchManifest, AuditError> {
    let (shape, literal, class) = match image.symbols.as_ref() {
        [symbol]
            if symbol.ir_data_id == 0
                && symbol.offset == 0
                && usize::try_from(symbol.length).ok() == Some(image.rodata.len())
                && symbol.alignment == 16
                && symbol.kind == DataSymbolKind::Bytes =>
        {
            (SearchShape::ExactLiteral, image.rodata.as_ref(), None)
        }
        [class_symbol, suffix_symbol]
            if class_symbol.ir_data_id == 0
                && class_symbol.offset == 0
                && class_symbol.length == 32
                && class_symbol.alignment == 16
                && class_symbol.kind == DataSymbolKind::ByteClass
                && suffix_symbol.ir_data_id == 1
                && suffix_symbol.offset == 32
                && suffix_symbol.alignment == 16
                && suffix_symbol.kind == DataSymbolKind::Bytes
                && usize::try_from(suffix_symbol.length)
                    .ok()
                    .and_then(|length| length.checked_add(32))
                    == Some(image.rodata.len()) =>
        {
            let class_bytes = image
                .rodata
                .get(..32)
                .ok_or(AuditError::InvalidSearchManifest)?;
            (
                SearchShape::ClassSuffix,
                image
                    .rodata
                    .get(32..)
                    .ok_or(AuditError::InvalidSearchManifest)?,
                Some(decode_manifest_byte_class(class_bytes)?),
            )
        }
        _ => return Err(AuditError::InvalidSearchManifest),
    };
    let limits = search_identity_limits(image.rodata.len())?;
    let mut matched = None;
    for anchors in [
        AnchorFlags {
            start: false,
            end: false,
        },
        AnchorFlags {
            start: true,
            end: false,
        },
        AnchorFlags {
            start: false,
            end: true,
        },
        AnchorFlags {
            start: true,
            end: true,
        },
    ] {
        work.record_source_identity_rebuild()?;
        let identity = match (shape, class) {
            (SearchShape::ExactLiteral, _) => {
                rebuild_exact_search_identity(image.output, literal, anchors, limits)
            }
            (SearchShape::ClassSuffix, Some(class)) => {
                rebuild_class_search_identity(image.output, class, literal, anchors, limits)
            }
            _ => Err(AuditError::InvalidSearchManifest),
        };
        if identity.ok() == Some(image.source_identity) && matched.replace(anchors).is_some() {
            return Err(AuditError::InvalidSearchManifest);
        }
    }
    let anchors = matched.ok_or(AuditError::InvalidSearchManifest)?;
    let repeated_confirmation_too_wide = match shape {
        SearchShape::ExactLiteral => {
            !anchors.start && !anchors.end && literal.len() > MAX_EXACT_AGGREGATE_LITERAL_BYTES
        }
        SearchShape::ClassSuffix => {
            !anchors.start && literal.len() > MAX_EXACT_AGGREGATE_LITERAL_BYTES
        }
    };
    if repeated_confirmation_too_wide {
        return Err(AuditError::InvalidSearchManifest);
    }
    let selected = match shape {
        SearchShape::ExactLiteral if !anchors.start && !anchors.end && !literal.is_empty() => {
            Some(if backend == BackendVersion::SEARCH_V1 {
                (0, checked_legacy_secondary_offset(literal.len())?, None)
            } else {
                let (primary, secondary) = independent_exact_candidate_pair(literal);
                (primary, secondary, None)
            })
        }
        SearchShape::ClassSuffix if !anchors.start && !literal.is_empty() => {
            let class_bytes = image
                .rodata
                .get(..32)
                .ok_or(AuditError::InvalidSearchManifest)?;
            if independent_singleton_class_byte(class_bytes).is_some() {
                Some((0, checked_legacy_secondary_offset(literal.len())?, None))
            } else {
                None
            }
        }
        _ => None,
    };
    let (
        candidate_policy_version,
        candidate_block_width,
        primary_offset,
        secondary_offset,
        verification_offset,
    ) = selected.map_or(
        (
            SEARCH_CANDIDATE_POLICY_NONE,
            0,
            SEARCH_CANDIDATE_OFFSET_NONE,
            SEARCH_CANDIDATE_OFFSET_NONE,
            SEARCH_CANDIDATE_OFFSET_NONE,
        ),
        |(primary, secondary, verification)| {
            (
                SEARCH_CANDIDATE_POLICY_V1,
                SEARCH_CANDIDATE_BLOCK_WIDTH,
                primary,
                secondary.unwrap_or(SEARCH_CANDIDATE_OFFSET_NONE),
                verification.unwrap_or(SEARCH_CANDIDATE_OFFSET_NONE),
            )
        },
    );
    Ok(SearchManifest {
        backend_version: backend,
        shape,
        output: image.output,
        anchors,
        source_identity: image.source_identity,
        literal_bytes: u32::try_from(literal.len()).map_err(|_| AuditError::ArithmeticOverflow)?,
        candidate_policy_version,
        candidate_block_width,
        primary_offset,
        secondary_offset,
        verification_offset,
        quaternary_offset: SEARCH_CANDIDATE_OFFSET_NONE,
    })
}

fn checked_legacy_secondary_offset(literal_len: usize) -> Result<Option<u16>, AuditError> {
    if literal_len <= 1 {
        return Ok(None);
    }
    let offset = literal_len
        .checked_sub(1)
        .ok_or(AuditError::ArithmeticOverflow)?;
    Ok(Some(
        u16::try_from(offset).map_err(|_| AuditError::InvalidSearchManifest)?,
    ))
}

fn authenticate_search_manifest<'image>(
    image: &'image NativeImage,
    manifest: SearchManifest,
    work: &mut AuditWork,
) -> Result<&'image [u8], AuditError> {
    let literal_len =
        usize::try_from(manifest.literal_bytes).map_err(|_| AuditError::InvalidSearchManifest)?;
    let limits = search_identity_limits(image.rodata.len())?;
    work.record_source_identity_rebuild()?;
    let expected_identity = match manifest.shape {
        SearchShape::ExactLiteral => {
            if !manifest.anchors.start
                && !manifest.anchors.end
                && literal_len > MAX_EXACT_AGGREGATE_LITERAL_BYTES
            {
                return Err(AuditError::InvalidSearchManifest);
            }
            if matches!(
                manifest.backend_version,
                BackendVersion::SEARCH_SVE16_V1 | BackendVersion::SEARCH_SVE2_16_V1
            ) && (manifest.anchors != AnchorFlags::default() || literal_len == 0)
            {
                return Err(AuditError::InvalidSearchManifest);
            }
            let [symbol] = image.symbols.as_ref() else {
                return Err(AuditError::InvalidSearchManifest);
            };
            if symbol.ir_data_id != 0
                || symbol.offset != 0
                || usize::try_from(symbol.length).ok() != Some(literal_len)
                || symbol.alignment != 16
                || symbol.kind != DataSymbolKind::Bytes
                || image.rodata.len() != literal_len
            {
                return Err(AuditError::InvalidSearchManifest);
            }
            rebuild_exact_search_identity(manifest.output, &image.rodata, manifest.anchors, limits)?
        }
        SearchShape::ClassSuffix => {
            authenticate_class_suffix_manifest(image, manifest, literal_len, limits)?
        }
    };
    if expected_identity != manifest.source_identity {
        return Err(AuditError::InvalidSearchManifest);
    }
    authenticate_search_candidate_policy(image, manifest, literal_len)?;
    match manifest.shape {
        SearchShape::ExactLiteral => Ok(&image.rodata),
        SearchShape::ClassSuffix => authenticated_class_suffix_literal(image, literal_len),
    }
}

fn authenticate_class_suffix_manifest(
    image: &NativeImage,
    manifest: SearchManifest,
    literal_len: usize,
    limits: ValidateLimits,
) -> Result<CacheIdentity, AuditError> {
    if !manifest.anchors.start && literal_len > MAX_EXACT_AGGREGATE_LITERAL_BYTES {
        return Err(AuditError::InvalidSearchManifest);
    }
    let suffix_end = 32_usize
        .checked_add(literal_len)
        .ok_or(AuditError::ArithmeticOverflow)?;
    let class_bytes = image
        .rodata
        .get(..32)
        .ok_or(AuditError::InvalidSearchManifest)?;
    let suffix = authenticated_class_suffix_literal(image, literal_len)?;
    let class = decode_manifest_byte_class(class_bytes)?;
    let singleton = independent_singleton_class_byte(class_bytes).is_some();
    let canonical_table = independent_sve2_fixed16_ascii_class_table(class_bytes);
    let uses_sve2_table = manifest.backend_version == BackendVersion::SEARCH_SVE2_16_V1
        && !singleton
        && canonical_table.is_some();
    let fixed16_admitted =
        !manifest.anchors.start && literal_len != 0 && (singleton || uses_sve2_table);
    if matches!(
        manifest.backend_version,
        BackendVersion::SEARCH_SVE16_V1 | BackendVersion::SEARCH_SVE2_16_V1
    ) && !fixed16_admitted
    {
        return Err(AuditError::InvalidSearchManifest);
    }

    let (class_symbol, suffix_symbol, table_symbol) = match image.symbols.as_ref() {
        [class_symbol, suffix_symbol] if !uses_sve2_table => (class_symbol, suffix_symbol, None),
        [class_symbol, suffix_symbol, table_symbol] if uses_sve2_table => {
            (class_symbol, suffix_symbol, Some(table_symbol))
        }
        _ => return Err(AuditError::InvalidSearchManifest),
    };
    if class_symbol.ir_data_id != 0
        || class_symbol.offset != 0
        || class_symbol.length != 32
        || class_symbol.alignment != 16
        || class_symbol.kind != DataSymbolKind::ByteClass
        || suffix_symbol.ir_data_id != 1
        || suffix_symbol.offset != 32
        || usize::try_from(suffix_symbol.length).ok() != Some(literal_len)
        || suffix_symbol.alignment != 16
        || suffix_symbol.kind != DataSymbolKind::Bytes
    {
        return Err(AuditError::InvalidSearchManifest);
    }
    if let (Some(expected_table), Some(table_symbol)) = (canonical_table, table_symbol) {
        let table_offset = independent_sve2_class_table_offset(literal_len)?;
        let expected_rodata_len = table_offset
            .checked_add(SVE2_CLASS_TABLE_BYTES)
            .ok_or(AuditError::ArithmeticOverflow)?;
        if table_symbol.ir_data_id != SVE2_CLASS_TABLE_DATA_ID
            || usize::try_from(table_symbol.offset).ok() != Some(table_offset)
            || usize::try_from(table_symbol.length).ok() != Some(SVE2_CLASS_TABLE_BYTES)
            || table_symbol.alignment != 16
            || table_symbol.kind != DataSymbolKind::Bytes
            || image.rodata.len() != expected_rodata_len
            || image
                .rodata
                .get(suffix_end..table_offset)
                .is_none_or(|padding| padding.iter().any(|&byte| byte != 0))
            || image.rodata.get(table_offset..expected_rodata_len)
                != Some(expected_table.as_slice())
        {
            return Err(AuditError::InvalidSearchManifest);
        }
    } else if table_symbol.is_some() || image.rodata.len() != suffix_end {
        return Err(AuditError::InvalidSearchManifest);
    }
    rebuild_class_search_identity(manifest.output, class, suffix, manifest.anchors, limits)
}

const SEARCH_CANDIDATE_POLICY_NONE: u16 = 0;
const SEARCH_CANDIDATE_POLICY_V1: u16 = 1;
const SEARCH_CANDIDATE_POLICY_V2: u16 = 2;
const SEARCH_CANDIDATE_POLICY_V3: u16 = 3;
const SEARCH_CANDIDATE_POLICY_SVE16_V1: u16 = 5;
const SEARCH_CANDIDATE_POLICY_SVE2_16_V1: u16 = 6;
const SEARCH_CANDIDATE_BLOCK_WIDTH: u16 = 16;
const SEARCH_CANDIDATE_OFFSET_NONE: u16 = u16::MAX;
const SVE2_CLASS_TABLE_DATA_ID: u32 = 2;
const SVE2_CLASS_TABLE_BYTES: usize = 16;

#[allow(
    clippy::too_many_lines,
    reason = "the independent versioned policy reconstruction and every offset bound remain in one fail-closed review unit"
)]
fn authenticate_search_candidate_policy(
    image: &NativeImage,
    manifest: SearchManifest,
    literal_len: usize,
) -> Result<(), AuditError> {
    let literal = match manifest.shape {
        SearchShape::ExactLiteral => image.rodata.as_ref(),
        SearchShape::ClassSuffix => authenticated_class_suffix_literal(image, literal_len)?,
    };
    if literal.len() != literal_len {
        return Err(AuditError::InvalidSearchManifest);
    }
    let selected = match manifest.shape {
        SearchShape::ExactLiteral
            if !manifest.anchors.start && !manifest.anchors.end && !literal.is_empty() =>
        {
            Some(if manifest.backend_version == BackendVersion::SEARCH_V1 {
                (
                    0,
                    (literal.len() > 1).then(|| {
                        u16::try_from(
                            literal
                                .len()
                                .checked_sub(1)
                                .expect("non-empty legacy literal"),
                        )
                        .expect("legacy repeated-confirmation bound fits u16")
                    }),
                    None,
                    None,
                )
            } else {
                let (primary, secondary) = independent_exact_candidate_pair(literal);
                let (verification, quaternary) = if matches!(
                    manifest.backend_version,
                    BackendVersion::SEARCH_V7
                        | BackendVersion::SEARCH_SVE16_V1
                        | BackendVersion::SEARCH_SVE2_16_V1
                ) {
                    independent_ranked_verification_offsets(literal, primary, secondary)
                } else {
                    (
                        matches!(
                            manifest.backend_version,
                            BackendVersion::SEARCH_V5 | BackendVersion::SEARCH_V6
                        )
                        .then(|| independent_exact_verification_offset(literal, primary, secondary))
                        .flatten(),
                        None,
                    )
                };
                (primary, secondary, verification, quaternary)
            })
        }
        SearchShape::ClassSuffix if !manifest.anchors.start && !literal.is_empty() => {
            let class = image
                .rodata
                .get(..32)
                .ok_or(AuditError::InvalidSearchManifest)?;
            (independent_singleton_class_byte(class).is_some()
                || (manifest.backend_version == BackendVersion::SEARCH_SVE2_16_V1
                    && independent_sve2_fixed16_ascii_class_table(class).is_some()))
            .then(|| {
                (
                    0,
                    (literal.len() > 1).then(|| {
                        u16::try_from(
                            literal
                                .len()
                                .checked_sub(1)
                                .expect("non-empty legacy suffix"),
                        )
                        .expect("authenticated repeated-confirmation bound fits u16")
                    }),
                    None,
                    None,
                )
            })
        }
        _ => None,
    };
    let expected = selected.map_or(
        (
            SEARCH_CANDIDATE_POLICY_NONE,
            0,
            SEARCH_CANDIDATE_OFFSET_NONE,
            SEARCH_CANDIDATE_OFFSET_NONE,
            SEARCH_CANDIDATE_OFFSET_NONE,
            SEARCH_CANDIDATE_OFFSET_NONE,
        ),
        |(primary, secondary, verification, quaternary)| {
            (
                if manifest.backend_version == BackendVersion::SEARCH_SVE2_16_V1
                    && matches!(
                        manifest.shape,
                        SearchShape::ExactLiteral | SearchShape::ClassSuffix
                    )
                {
                    SEARCH_CANDIDATE_POLICY_SVE2_16_V1
                } else if manifest.backend_version == BackendVersion::SEARCH_SVE16_V1
                    && matches!(
                        manifest.shape,
                        SearchShape::ExactLiteral | SearchShape::ClassSuffix
                    )
                {
                    SEARCH_CANDIDATE_POLICY_SVE16_V1
                } else if manifest.backend_version == BackendVersion::SEARCH_V7
                    && manifest.shape == SearchShape::ExactLiteral
                {
                    SEARCH_CANDIDATE_POLICY_V3
                } else if matches!(
                    manifest.backend_version,
                    BackendVersion::SEARCH_V5 | BackendVersion::SEARCH_V6
                ) && manifest.shape == SearchShape::ExactLiteral
                {
                    SEARCH_CANDIDATE_POLICY_V2
                } else {
                    SEARCH_CANDIDATE_POLICY_V1
                },
                SEARCH_CANDIDATE_BLOCK_WIDTH,
                primary,
                secondary.unwrap_or(SEARCH_CANDIDATE_OFFSET_NONE),
                verification.unwrap_or(SEARCH_CANDIDATE_OFFSET_NONE),
                quaternary.unwrap_or(SEARCH_CANDIDATE_OFFSET_NONE),
            )
        },
    );
    let actual = (
        manifest.candidate_policy_version,
        manifest.candidate_block_width,
        manifest.primary_offset,
        manifest.secondary_offset,
        manifest.verification_offset,
        manifest.quaternary_offset,
    );
    if actual != expected {
        return Err(AuditError::InvalidSearchManifest);
    }
    if selected.is_some()
        && (usize::from(manifest.primary_offset) >= literal.len()
            || (manifest.secondary_offset != SEARCH_CANDIDATE_OFFSET_NONE
                && (usize::from(manifest.secondary_offset) >= literal.len()
                    || manifest.secondary_offset == manifest.primary_offset))
            || (manifest.verification_offset != SEARCH_CANDIDATE_OFFSET_NONE
                && (usize::from(manifest.verification_offset) >= literal.len()
                    || manifest.verification_offset == manifest.primary_offset
                    || manifest.verification_offset == manifest.secondary_offset))
            || (manifest.quaternary_offset != SEARCH_CANDIDATE_OFFSET_NONE
                && (usize::from(manifest.quaternary_offset) >= literal.len()
                    || manifest.quaternary_offset == manifest.primary_offset
                    || manifest.quaternary_offset == manifest.secondary_offset
                    || manifest.quaternary_offset == manifest.verification_offset)))
    {
        return Err(AuditError::InvalidSearchManifest);
    }
    Ok(())
}

fn independent_singleton_class_byte(class: &[u8]) -> Option<u8> {
    if class.len() != 32 || class.iter().map(|byte| byte.count_ones()).sum::<u32>() != 1 {
        return None;
    }
    let (index, byte) = class
        .iter()
        .copied()
        .enumerate()
        .find(|(_, byte)| *byte != 0)?;
    let bit = usize::try_from(byte.trailing_zeros()).ok()?;
    u8::try_from(index.checked_mul(8)?.checked_add(bit)?).ok()
}

pub(crate) fn independent_sve2_fixed16_ascii_class_table(
    class: &[u8],
) -> Option<[u8; SVE2_CLASS_TABLE_BYTES]> {
    if class.len() != 32 || class[16..].iter().any(|&byte| byte != 0) {
        return None;
    }
    let member_count = class[..16].iter().try_fold(0_usize, |total, byte| {
        total.checked_add(usize::try_from(byte.count_ones()).ok()?)
    })?;
    if !(2..=SVE2_CLASS_TABLE_BYTES).contains(&member_count) {
        return None;
    }
    let mut members = [0_u8; SVE2_CLASS_TABLE_BYTES];
    let mut member_index = 0_usize;
    for value in 0_u8..=127 {
        let byte = class.get(usize::from(value / 8))?;
        if byte & (1_u8 << u32::from(value % 8)) != 0 {
            members[member_index] = value;
            member_index = member_index.checked_add(1)?;
        }
    }
    if member_index != member_count {
        return None;
    }
    // Independently reproduce the emitter's ascending, cyclic table. Every
    // lane is a real member, including when NUL is not in the source class.
    let mut table = [0_u8; SVE2_CLASS_TABLE_BYTES];
    for (byte, member) in table
        .iter_mut()
        .zip(members[..member_count].iter().copied().cycle())
    {
        *byte = member;
    }
    Some(table)
}

pub(crate) fn independent_sve2_class_table_offset(literal_len: usize) -> Result<usize, AuditError> {
    let unaligned = 32_usize
        .checked_add(literal_len)
        .ok_or(AuditError::ArithmeticOverflow)?;
    unaligned
        .checked_add(SVE2_CLASS_TABLE_BYTES - 1)
        .map(|value| value & !(SVE2_CLASS_TABLE_BYTES - 1))
        .ok_or(AuditError::ArithmeticOverflow)
}

fn authenticated_class_suffix_literal(
    image: &NativeImage,
    literal_len: usize,
) -> Result<&[u8], AuditError> {
    let end = 32_usize
        .checked_add(literal_len)
        .ok_or(AuditError::ArithmeticOverflow)?;
    image
        .rodata
        .get(32..end)
        .ok_or(AuditError::InvalidSearchManifest)
}

fn independent_exact_candidate_pair(literal: &[u8]) -> (u16, Option<u16>) {
    if literal.len() == 1 {
        return (0, None);
    }
    let mut primary = 0_usize;
    let mut secondary = 1_usize;
    if INDEPENDENT_BYTE_FREQUENCY_RANK[usize::from(literal[secondary])]
        < INDEPENDENT_BYTE_FREQUENCY_RANK[usize::from(literal[primary])]
    {
        core::mem::swap(&mut primary, &mut secondary);
    }
    for index in 2..literal.len().min(255) {
        let byte = literal[index];
        if INDEPENDENT_BYTE_FREQUENCY_RANK[usize::from(byte)]
            < INDEPENDENT_BYTE_FREQUENCY_RANK[usize::from(literal[primary])]
        {
            secondary = primary;
            primary = index;
        } else if byte != literal[primary]
            && INDEPENDENT_BYTE_FREQUENCY_RANK[usize::from(byte)]
                < INDEPENDENT_BYTE_FREQUENCY_RANK[usize::from(literal[secondary])]
        {
            secondary = index;
        }
    }
    (
        u16::try_from(primary).expect("authenticated exact literal bound fits u16"),
        Some(u16::try_from(secondary).expect("authenticated exact literal bound fits u16")),
    )
}

fn independent_exact_verification_offset(
    literal: &[u8],
    primary_offset: u16,
    secondary_offset: Option<u16>,
) -> Option<u16> {
    let primary_byte = *literal.get(usize::from(primary_offset))?;
    let secondary_byte = secondary_offset
        .and_then(|offset| literal.get(usize::from(offset)))
        .copied();
    literal
        .iter()
        .position(|&byte| byte != primary_byte && Some(byte) != secondary_byte)
        .and_then(|offset| u16::try_from(offset).ok())
}

fn independent_ranked_verification_offsets(
    literal: &[u8],
    primary_offset: u16,
    secondary_offset: Option<u16>,
) -> (Option<u16>, Option<u16>) {
    let ranked = literal
        .iter()
        .copied()
        .enumerate()
        .filter_map(|(offset, byte)| {
            let offset = u16::try_from(offset).ok()?;
            (offset != primary_offset && Some(offset) != secondary_offset)
                .then_some((INDEPENDENT_BYTE_FREQUENCY_RANK[usize::from(byte)], offset))
        });
    let mut first = None;
    let mut second = None;
    for candidate in ranked {
        if first.is_none_or(|current| candidate < current) {
            second = first;
            first = Some(candidate);
        } else if second.is_none_or(|current| candidate < current) {
            second = Some(candidate);
        }
    }
    (
        first.map(|(_, offset)| offset),
        second.map(|(_, offset)| offset),
    )
}

// Frozen copy of memchr 2.8.3's default packed-pair frequency policy. The
// emitter uses `Pair::new`; the independent audit deliberately does not.
const INDEPENDENT_BYTE_FREQUENCY_RANK: [u8; 256] = [
    55, 52, 51, 50, 49, 48, 47, 46, 45, 103, 242, 66, 67, 229, 44, 43, 42, 41, 40, 39, 38, 37, 36,
    35, 34, 33, 56, 32, 31, 30, 29, 28, 255, 148, 164, 149, 136, 160, 155, 173, 221, 222, 134, 122,
    232, 202, 215, 224, 208, 220, 204, 187, 183, 179, 177, 168, 178, 200, 226, 195, 154, 184, 174,
    126, 120, 191, 157, 194, 170, 189, 162, 161, 150, 193, 142, 137, 171, 176, 185, 167, 186, 112,
    175, 192, 188, 156, 140, 143, 123, 133, 128, 147, 138, 146, 114, 223, 151, 249, 216, 238, 236,
    253, 227, 218, 230, 247, 135, 180, 241, 233, 246, 244, 231, 139, 245, 243, 251, 235, 201, 196,
    240, 214, 152, 182, 205, 181, 127, 27, 212, 211, 210, 213, 228, 197, 169, 159, 131, 172, 105,
    80, 98, 96, 97, 81, 207, 145, 116, 115, 144, 130, 153, 121, 107, 132, 109, 110, 124, 111, 82,
    108, 118, 141, 113, 129, 119, 125, 165, 117, 92, 106, 83, 72, 99, 93, 65, 79, 166, 237, 163,
    199, 190, 225, 209, 203, 198, 217, 219, 206, 234, 248, 158, 239, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255,
];

fn search_identity_limits(data_bytes: usize) -> Result<ValidateLimits, AuditError> {
    let data_bytes = u64::try_from(data_bytes).map_err(|_| AuditError::ArithmeticOverflow)?;
    let linear_bytes = data_bytes
        .checked_add(4_096)
        .ok_or(AuditError::ArithmeticOverflow)?;
    let validation_work = data_bytes
        .checked_mul(8)
        .and_then(|value| value.checked_add(8_192))
        .ok_or(AuditError::ArithmeticOverflow)?;
    let defaults = ValidateLimits::default();
    Ok(ValidateLimits {
        max_data_bytes: defaults.max_data_bytes.max(linear_bytes),
        max_serialized_bytes: defaults.max_serialized_bytes.max(linear_bytes),
        max_estimated_code_bytes: defaults.max_estimated_code_bytes.max(linear_bytes),
        max_validation_work: defaults.max_validation_work.max(validation_work),
        max_work_factor: defaults.max_work_factor.max(linear_bytes),
        ..defaults
    })
}

fn decode_manifest_byte_class(bytes: &[u8]) -> Result<ByteClass, AuditError> {
    let bytes: &[u8; 32] = bytes
        .try_into()
        .map_err(|_| AuditError::InvalidSearchManifest)?;
    let mut members = [0_u8; 256];
    let mut count = 0_usize;
    for byte in 0_u16..=u16::from(u8::MAX) {
        let value = u8::try_from(byte).map_err(|_| AuditError::ArithmeticOverflow)?;
        let lane = usize::from(value / 8);
        let bit = u32::from(value % 8);
        if bytes[lane] & (1_u8 << bit) != 0 {
            members[count] = value;
            count = count.checked_add(1).ok_or(AuditError::ArithmeticOverflow)?;
        }
    }
    Ok(ByteClass::from_bytes(&members[..count]))
}

fn rebuild_exact_search_identity(
    output: OutputKind,
    literal: &[u8],
    anchors: AnchorFlags,
    limits: ValidateLimits,
) -> Result<CacheIdentity, AuditError> {
    match output {
        OutputKind::Exists => build_exact_literal::<Exists>(literal, anchors, limits)
            .map(|program| program.cache_identity()),
        OutputKind::SelectedEnd => build_exact_literal::<SelectedEnd>(literal, anchors, limits)
            .map(|program| program.cache_identity()),
        OutputKind::Span => build_exact_literal::<Span>(literal, anchors, limits)
            .map(|program| program.cache_identity()),
    }
    .map_err(|_| AuditError::InvalidSearchManifest)
}

fn rebuild_class_search_identity(
    output: OutputKind,
    class: ByteClass,
    suffix: &[u8],
    anchors: AnchorFlags,
    limits: ValidateLimits,
) -> Result<CacheIdentity, AuditError> {
    match output {
        OutputKind::Exists => build_class_suffix::<Exists>(class, suffix, anchors, limits)
            .map(|program| program.cache_identity()),
        OutputKind::SelectedEnd => {
            build_class_suffix::<SelectedEnd>(class, suffix, anchors, limits)
                .map(|program| program.cache_identity())
        }
        OutputKind::Span => build_class_suffix::<Span>(class, suffix, anchors, limits)
            .map(|program| program.cache_identity()),
    }
    .map_err(|_| AuditError::InvalidSearchManifest)
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    reason = "the authenticated instruction template advances a cursor only after a successful bounds-checked decode lookup"
)]
fn validate_search_candidate_contract(
    image: &NativeImage,
    manifest: SearchManifest,
    literal: &[u8],
    instructions: &[DecodedInstruction],
) -> Result<(), AuditError> {
    let authenticated_candidate_shape = manifest.backend_version == BackendVersion::SEARCH_V3
        && manifest.shape == SearchShape::ExactLiteral
        && manifest.anchors == AnchorFlags::default()
        && !literal.is_empty()
        && literal.len() <= MAX_EXACT_AGGREGATE_LITERAL_BYTES;
    if !authenticated_candidate_shape {
        return Err(invalid_search_instruction(0));
    }

    let primary_index = instructions
        .windows(2)
        .position(|pair| {
            matches!(
                pair,
                [
                    DecodedInstruction::LoadByte {
                        destination: 11,
                        base: 8,
                        ..
                    },
                    DecodedInstruction::DuplicateByte16 {
                        destination: 1,
                        source: 11
                    }
                ]
            )
        })
        .ok_or_else(|| invalid_search_instruction(0))?;
    let primary_offset = manifest.primary_offset;
    let secondary_offset = (manifest.secondary_offset != SEARCH_CANDIDATE_OFFSET_NONE)
        .then_some(manifest.secondary_offset);
    let none_index = image
        .labels
        .iter()
        .find(|label| label.kind == LabelKind::ReturnNone)
        .and_then(|label| usize::try_from(label.offset / 4).ok())
        .ok_or_else(|| invalid_search_instruction(primary_index))?;
    if primary_index != 12 {
        return Err(invalid_search_instruction(primary_index));
    }
    expect_search_instruction(
        instructions,
        0,
        DecodedInstruction::MoveRegister64 {
            destination: 9,
            source: 0,
        },
    )?;
    expect_search_instruction(
        instructions,
        1,
        DecodedInstruction::CompareRegister64 { left: 2, right: 3 },
    )?;
    let invalid_window = expect_search_condition(instructions, 2, Condition::Higher)?;
    expect_search_instruction(
        instructions,
        3,
        DecodedInstruction::CompareRegister64 { left: 3, right: 1 },
    )?;
    let invalid_end = expect_search_condition(instructions, 4, Condition::Higher)?;
    expect_search_address(instructions, 5, 8)?;
    expect_search_instruction(
        instructions,
        6,
        DecodedInstruction::MoveZero64 {
            destination: 12,
            immediate: u16::try_from(literal.len()).map_err(|_| AuditError::ArithmeticOverflow)?,
            shift: 0,
        },
    )?;
    expect_search_instruction(
        instructions,
        7,
        DecodedInstruction::SubtractRegister64 {
            destination: 10,
            left: 3,
            right: 2,
        },
    )?;
    expect_search_instruction(
        instructions,
        8,
        DecodedInstruction::CompareRegister64 {
            left: 10,
            right: 12,
        },
    )?;
    let too_short = expect_search_condition(instructions, 9, Condition::CarryClear)?;
    expect_search_instruction(
        instructions,
        10,
        DecodedInstruction::SubtractRegister64 {
            destination: 6,
            left: 3,
            right: 12,
        },
    )?;
    expect_search_instruction(
        instructions,
        11,
        DecodedInstruction::MoveRegister64 {
            destination: 5,
            source: 2,
        },
    )?;
    if [invalid_window, invalid_end, too_short]
        .into_iter()
        .any(|target| target != none_index)
    {
        return Err(invalid_search_instruction(0));
    }
    let mut cursor = primary_index;

    expect_search_instruction(
        instructions,
        cursor,
        DecodedInstruction::LoadByte {
            destination: 11,
            base: 8,
            offset: primary_offset,
        },
    )?;
    cursor += 1;
    expect_search_instruction(
        instructions,
        cursor,
        DecodedInstruction::DuplicateByte16 {
            destination: 1,
            source: 11,
        },
    )?;
    cursor += 1;
    if let Some(secondary_offset) = secondary_offset {
        expect_search_instruction(
            instructions,
            cursor,
            DecodedInstruction::LoadByte {
                destination: 11,
                base: 8,
                offset: secondary_offset,
            },
        )?;
        cursor += 1;
        expect_search_instruction(
            instructions,
            cursor,
            DecodedInstruction::DuplicateByte16 {
                destination: 3,
                source: 11,
            },
        )?;
        cursor += 1;
    }
    expect_search_instruction(
        instructions,
        cursor,
        DecodedInstruction::AddRegister64 {
            destination: 15,
            left: 9,
            right: 5,
        },
    )?;
    cursor += 1;
    if primary_offset != 0 {
        expect_search_instruction(
            instructions,
            cursor,
            DecodedInstruction::AddImmediate64 {
                destination: 15,
                source: 15,
                immediate: primary_offset,
            },
        )?;
        cursor += 1;
    }
    expect_search_instruction(
        instructions,
        cursor,
        DecodedInstruction::CompareRegister64 { left: 5, right: 6 },
    )?;
    cursor += 1;
    let none_from_entry = expect_search_condition(instructions, cursor, Condition::Higher)?;
    cursor += 1;
    expect_search_instruction(
        instructions,
        cursor,
        DecodedInstruction::SubtractRegister64 {
            destination: 10,
            left: 6,
            right: 5,
        },
    )?;
    cursor += 1;
    expect_search_instruction(
        instructions,
        cursor,
        DecodedInstruction::CompareImmediate64 {
            register: 10,
            immediate: 15,
        },
    )?;
    cursor += 1;
    let scalar_from_entry = expect_search_condition(instructions, cursor, Condition::CarryClear)?;
    cursor += 1;
    expect_search_instruction(
        instructions,
        cursor,
        DecodedInstruction::SubtractImmediate64 {
            destination: 7,
            source: 6,
            immediate: 15,
        },
    )?;
    cursor += 1;

    let vector_index = cursor;
    let primary_reduction = if secondary_offset.is_some() { 2 } else { 0 };
    for expected in [
        DecodedInstruction::LoadVector128 {
            destination: 0,
            base: 15,
            offset: 0,
        },
        DecodedInstruction::CompareEqualBytes16 {
            destination: 0,
            left: 0,
            right: 1,
        },
        DecodedInstruction::UnsignedMaxPairwiseBytes16 {
            destination: primary_reduction,
            left: 0,
            right: 0,
        },
        DecodedInstruction::MoveVectorDoubleTo64 {
            destination: 10,
            source: primary_reduction,
        },
    ] {
        expect_search_instruction(instructions, cursor, expected)?;
        cursor += 1;
    }
    let secondary_from_primary = expect_search_compare_branch(instructions, cursor, true)?;
    cursor += 1;

    let advance_index = cursor;
    for expected in [
        DecodedInstruction::AddImmediate64 {
            destination: 5,
            source: 5,
            immediate: 16,
        },
        DecodedInstruction::AddImmediate64 {
            destination: 15,
            source: 15,
            immediate: 16,
        },
        DecodedInstruction::CompareRegister64 { left: 5, right: 7 },
    ] {
        expect_search_instruction(instructions, cursor, expected)?;
        cursor += 1;
    }
    let vector_from_advance =
        expect_search_condition(instructions, cursor, Condition::LowerOrSame)?;
    cursor += 1;
    expect_search_instruction(
        instructions,
        cursor,
        DecodedInstruction::CompareRegister64 { left: 5, right: 6 },
    )?;
    cursor += 1;
    let none_from_advance = expect_search_condition(instructions, cursor, Condition::Higher)?;
    cursor += 1;
    let scalar_from_advance = expect_search_branch(instructions, cursor)?;
    cursor += 1;

    let secondary_index = secondary_offset.map(|_| cursor);
    let (scalar_from_secondary, advance_from_secondary) =
        if let Some(secondary_offset) = secondary_offset {
            let secondary_delta = primary_offset.abs_diff(secondary_offset);
            let secondary_address = if secondary_offset > primary_offset {
                DecodedInstruction::AddImmediate64 {
                    destination: 10,
                    source: 15,
                    immediate: secondary_delta,
                }
            } else {
                DecodedInstruction::SubtractImmediate64 {
                    destination: 10,
                    source: 15,
                    immediate: secondary_delta,
                }
            };
            for expected in [
                secondary_address,
                DecodedInstruction::LoadVector128 {
                    destination: 2,
                    base: 10,
                    offset: 0,
                },
                DecodedInstruction::CompareEqualBytes16 {
                    destination: 2,
                    left: 2,
                    right: 3,
                },
                DecodedInstruction::AndBytes16 {
                    destination: 0,
                    left: 0,
                    right: 2,
                },
                DecodedInstruction::UnsignedMaxPairwiseBytes16 {
                    destination: 0,
                    left: 0,
                    right: 0,
                },
                DecodedInstruction::MoveVectorDoubleTo64 {
                    destination: 10,
                    source: 0,
                },
            ] {
                expect_search_instruction(instructions, cursor, expected)?;
                cursor += 1;
            }
            let scalar = expect_search_compare_branch(instructions, cursor, true)?;
            cursor += 1;
            let advance = expect_search_branch(instructions, cursor)?;
            cursor += 1;
            (Some(scalar), Some(advance))
        } else {
            (None, None)
        };
    let block_setup_index = cursor;
    for expected in [
        DecodedInstruction::MoveZero64 {
            destination: 13,
            immediate: 1,
            shift: 0,
        },
        DecodedInstruction::AddImmediate64 {
            destination: 7,
            source: 5,
            immediate: 15,
        },
    ] {
        expect_search_instruction(instructions, cursor, expected)?;
        cursor += 1;
    }
    let scalar_from_block_setup = expect_search_branch(instructions, cursor)?;
    cursor += 1;
    let tail_setup_index = cursor;
    for expected in [
        DecodedInstruction::MoveZero64 {
            destination: 13,
            immediate: 0,
            shift: 0,
        },
        DecodedInstruction::MoveRegister64 {
            destination: 7,
            source: 6,
        },
    ] {
        expect_search_instruction(instructions, cursor, expected)?;
        cursor += 1;
    }
    let scalar_index = cursor;

    for (branch, target) in [
        (none_from_entry, none_index),
        (scalar_from_entry, tail_setup_index),
        (
            secondary_from_primary,
            secondary_index.unwrap_or(block_setup_index),
        ),
        (vector_from_advance, vector_index),
        (none_from_advance, none_index),
        (scalar_from_advance, tail_setup_index),
        (scalar_from_block_setup, scalar_index),
    ] {
        if branch != target {
            return Err(invalid_search_instruction(primary_index));
        }
    }
    if scalar_from_secondary.is_some_and(|branch| branch != block_setup_index)
        || advance_from_secondary.is_some_and(|branch| branch != advance_index)
    {
        return Err(invalid_search_instruction(primary_index));
    }
    let (found_index, scalar_advance_index, recovery_index, equality_labels) =
        if literal.len() == 16 {
            let (found, advance, recovery) =
                validate_fixed_16_search_confirmation(instructions, scalar_index)?;
            (found, advance, recovery, Vec::new())
        } else {
            validate_generic_search_confirmation(instructions, scalar_index, literal.len())?
        };
    let (scalar_exhausted_index, block_resume_index, recovery_end) =
        validate_search_block_recovery(
            instructions,
            recovery_index,
            primary_offset,
            secondary_offset,
            vector_index,
            tail_setup_index,
            none_index,
        )?;
    if recovery_end != found_index {
        return Err(invalid_search_instruction(recovery_end));
    }
    validate_search_return_template(image, instructions, found_index, none_index)?;
    validate_search_label_manifest(
        image,
        found_index,
        none_index,
        vector_index,
        scalar_index,
        advance_index,
        secondary_index,
        block_setup_index,
        tail_setup_index,
        scalar_advance_index,
        scalar_exhausted_index,
        block_resume_index,
        &equality_labels,
    )?;
    Ok(())
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    reason = "the authenticated fixed-width template advances a cursor only after a successful bounds-checked decode lookup"
)]
fn validate_fixed_16_search_confirmation(
    instructions: &[DecodedInstruction],
    scalar_index: usize,
) -> Result<(usize, usize, usize), AuditError> {
    let fixed = [
        DecodedInstruction::LoadByteRegister {
            destination: 10,
            base: 9,
            index: 5,
        },
        DecodedInstruction::LoadByte {
            destination: 11,
            base: 8,
            offset: 0,
        },
        DecodedInstruction::CompareRegister32 {
            left: 10,
            right: 11,
        },
    ];
    let mut cursor = scalar_index;
    for expected in fixed {
        expect_search_instruction(instructions, cursor, expected)?;
        cursor += 1;
    }
    let advance_from_first = expect_search_condition(instructions, cursor, Condition::NotEqual)?;
    cursor += 1;
    for expected in [
        DecodedInstruction::AddRegister64 {
            destination: 15,
            left: 9,
            right: 5,
        },
        DecodedInstruction::LoadVector128 {
            destination: 0,
            base: 15,
            offset: 0,
        },
        DecodedInstruction::LoadVector128 {
            destination: 1,
            base: 8,
            offset: 0,
        },
        DecodedInstruction::CompareEqualBytes16 {
            destination: 0,
            left: 0,
            right: 1,
        },
        DecodedInstruction::UnsignedMinBytes16 {
            destination: 0,
            source: 0,
        },
        DecodedInstruction::MoveVectorByteTo32 {
            destination: 10,
            source: 0,
        },
        DecodedInstruction::CompareImmediate32 {
            register: 10,
            immediate: 255,
        },
    ] {
        expect_search_instruction(instructions, cursor, expected)?;
        cursor += 1;
    }
    let advance_from_vector = expect_search_condition(instructions, cursor, Condition::NotEqual)?;
    cursor += 1;
    for expected in [
        DecodedInstruction::MoveRegister64 {
            destination: 13,
            source: 5,
        },
        DecodedInstruction::AddRegister64 {
            destination: 14,
            left: 5,
            right: 12,
        },
    ] {
        expect_search_instruction(instructions, cursor, expected)?;
        cursor += 1;
    }
    let found_from_confirmation = expect_search_branch(instructions, cursor)?;
    cursor += 1;
    let advance_index = cursor;
    expect_search_instruction(
        instructions,
        cursor,
        DecodedInstruction::CompareRegister64 { left: 5, right: 7 },
    )?;
    cursor += 1;
    let recovery_from_advance = expect_search_condition(instructions, cursor, Condition::CarrySet)?;
    cursor += 1;
    expect_search_instruction(
        instructions,
        cursor,
        DecodedInstruction::AddImmediate64 {
            destination: 5,
            source: 5,
            immediate: 1,
        },
    )?;
    cursor += 1;
    let scalar_from_advance = expect_search_branch(instructions, cursor)?;
    cursor += 1;
    let recovery_index = cursor;
    let found_index = found_from_confirmation;
    for (branch, target) in [
        (advance_from_first, advance_index),
        (advance_from_vector, advance_index),
        (found_from_confirmation, found_index),
        (recovery_from_advance, recovery_index),
        (scalar_from_advance, scalar_index),
    ] {
        if branch != target {
            return Err(invalid_search_instruction(scalar_index));
        }
    }
    Ok((found_index, advance_index, recovery_index))
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    clippy::type_complexity,
    reason = "the independent scalar confirmation template keeps every load and backedge explicit"
)]
fn validate_generic_search_confirmation(
    instructions: &[DecodedInstruction],
    scalar_index: usize,
    literal_len: usize,
) -> Result<(usize, usize, usize, Vec<(usize, LabelKind)>), AuditError> {
    let mut cursor = scalar_index;
    for expected in [
        DecodedInstruction::LoadByteRegister {
            destination: 10,
            base: 9,
            index: 5,
        },
        DecodedInstruction::LoadByte {
            destination: 11,
            base: 8,
            offset: 0,
        },
        DecodedInstruction::CompareRegister32 {
            left: 10,
            right: 11,
        },
    ] {
        expect_search_instruction(instructions, cursor, expected)?;
        cursor += 1;
    }
    let advance_from_first = expect_search_condition(instructions, cursor, Condition::NotEqual)?;
    cursor += 1;
    for expected in [
        DecodedInstruction::AddRegister64 {
            destination: 15,
            left: 9,
            right: 5,
        },
        DecodedInstruction::MoveRegister64 {
            destination: 15,
            source: 15,
        },
        DecodedInstruction::MoveRegister64 {
            destination: 16,
            source: 8,
        },
        DecodedInstruction::MoveZero64 {
            destination: 17,
            immediate: u16::try_from(literal_len).map_err(|_| AuditError::ArithmeticOverflow)?,
            shift: 0,
        },
    ] {
        expect_search_instruction(instructions, cursor, expected)?;
        cursor += 1;
    }

    let mut vector_loop_index = None;
    let mut scalar_from_vector = None;
    let mut advance_from_vector = None;
    let mut scalar_direct = None;
    if literal_len >= 16 {
        vector_loop_index = Some(cursor);
        expect_search_instruction(
            instructions,
            cursor,
            DecodedInstruction::CompareImmediate64 {
                register: 17,
                immediate: 16,
            },
        )?;
        cursor += 1;
        scalar_from_vector = Some(expect_search_condition(
            instructions,
            cursor,
            Condition::CarryClear,
        )?);
        cursor += 1;
        for expected in [
            DecodedInstruction::LoadVector128 {
                destination: 0,
                base: 15,
                offset: 0,
            },
            DecodedInstruction::LoadVector128 {
                destination: 1,
                base: 16,
                offset: 0,
            },
            DecodedInstruction::CompareEqualBytes16 {
                destination: 0,
                left: 0,
                right: 1,
            },
            DecodedInstruction::UnsignedMinBytes16 {
                destination: 0,
                source: 0,
            },
            DecodedInstruction::MoveVectorByteTo32 {
                destination: 10,
                source: 0,
            },
            DecodedInstruction::CompareImmediate32 {
                register: 10,
                immediate: 255,
            },
        ] {
            expect_search_instruction(instructions, cursor, expected)?;
            cursor += 1;
        }
        advance_from_vector = Some(expect_search_condition(
            instructions,
            cursor,
            Condition::NotEqual,
        )?);
        cursor += 1;
        for expected in [
            DecodedInstruction::AddImmediate64 {
                destination: 15,
                source: 15,
                immediate: 16,
            },
            DecodedInstruction::AddImmediate64 {
                destination: 16,
                source: 16,
                immediate: 16,
            },
            DecodedInstruction::SubtractImmediate64 {
                destination: 17,
                source: 17,
                immediate: 16,
            },
        ] {
            expect_search_instruction(instructions, cursor, expected)?;
            cursor += 1;
        }
        let vector_backedge = expect_search_branch(instructions, cursor)?;
        if vector_backedge != vector_loop_index.unwrap_or_default() {
            return Err(invalid_search_instruction(cursor));
        }
        cursor += 1;
    } else {
        scalar_direct = Some(expect_search_branch(instructions, cursor)?);
        cursor += 1;
    }

    let equality_scalar_index = cursor;
    let equal_from_empty = expect_search_compare_branch_register(instructions, cursor, 17, false)?;
    cursor += 1;
    let equality_scalar_loop_index = cursor;
    for expected in [
        DecodedInstruction::LoadByte {
            destination: 10,
            base: 15,
            offset: 0,
        },
        DecodedInstruction::LoadByte {
            destination: 11,
            base: 16,
            offset: 0,
        },
        DecodedInstruction::CompareRegister32 {
            left: 10,
            right: 11,
        },
    ] {
        expect_search_instruction(instructions, cursor, expected)?;
        cursor += 1;
    }
    let advance_from_scalar = expect_search_condition(instructions, cursor, Condition::NotEqual)?;
    cursor += 1;
    for expected in [
        DecodedInstruction::AddImmediate64 {
            destination: 15,
            source: 15,
            immediate: 1,
        },
        DecodedInstruction::AddImmediate64 {
            destination: 16,
            source: 16,
            immediate: 1,
        },
        DecodedInstruction::SubtractImmediate64 {
            destination: 17,
            source: 17,
            immediate: 1,
        },
    ] {
        expect_search_instruction(instructions, cursor, expected)?;
        cursor += 1;
    }
    let scalar_backedge = expect_search_compare_branch_register(instructions, cursor, 17, true)?;
    cursor += 1;
    let equality_equal_index = cursor;
    for expected in [
        DecodedInstruction::MoveRegister64 {
            destination: 13,
            source: 5,
        },
        DecodedInstruction::AddRegister64 {
            destination: 14,
            left: 5,
            right: 12,
        },
    ] {
        expect_search_instruction(instructions, cursor, expected)?;
        cursor += 1;
    }
    let found_index = expect_search_branch(instructions, cursor)?;
    cursor += 1;
    let advance_index = cursor;
    expect_search_instruction(
        instructions,
        cursor,
        DecodedInstruction::CompareRegister64 { left: 5, right: 7 },
    )?;
    cursor += 1;
    let recovery_from_advance = expect_search_condition(instructions, cursor, Condition::CarrySet)?;
    cursor += 1;
    expect_search_instruction(
        instructions,
        cursor,
        DecodedInstruction::AddImmediate64 {
            destination: 5,
            source: 5,
            immediate: 1,
        },
    )?;
    cursor += 1;
    let scan_backedge = expect_search_branch(instructions, cursor)?;
    cursor += 1;
    let recovery_index = cursor;

    if advance_from_first != advance_index
        || advance_from_vector.is_some_and(|target| target != advance_index)
        || advance_from_scalar != advance_index
        || scalar_from_vector.is_some_and(|target| target != equality_scalar_index)
        || scalar_direct.is_some_and(|target| target != equality_scalar_index)
        || equal_from_empty != equality_equal_index
        || scalar_backedge != equality_scalar_loop_index
        || recovery_from_advance != recovery_index
        || scan_backedge != scalar_index
    {
        return Err(invalid_search_instruction(scalar_index));
    }

    let mut labels = vec![
        (equality_scalar_index, LabelKind::Internal),
        (equality_scalar_loop_index, LabelKind::Loop),
        (equality_equal_index, LabelKind::Internal),
    ];
    if let Some(vector_loop_index) = vector_loop_index {
        labels.push((vector_loop_index, LabelKind::Loop));
    }
    Ok((found_index, advance_index, recovery_index, labels))
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "the authenticated block-recovery template advances only after exact instruction matches"
)]
fn validate_search_block_recovery(
    instructions: &[DecodedInstruction],
    scalar_exhausted_index: usize,
    primary_offset: u16,
    secondary_offset: Option<u16>,
    vector_index: usize,
    tail_setup_index: usize,
    none_index: usize,
) -> Result<(usize, usize, usize), AuditError> {
    let mut cursor = scalar_exhausted_index;
    let block_from_exhausted =
        expect_search_compare_branch_register(instructions, cursor, 13, true)?;
    cursor += 1;
    let none_from_exhausted = expect_search_branch(instructions, cursor)?;
    cursor += 1;
    let block_resume_index = cursor;
    for expected in [
        DecodedInstruction::LoadByte {
            destination: 11,
            base: 8,
            offset: primary_offset,
        },
        DecodedInstruction::DuplicateByte16 {
            destination: 1,
            source: 11,
        },
    ] {
        expect_search_instruction(instructions, cursor, expected)?;
        cursor += 1;
    }
    if let Some(secondary_offset) = secondary_offset {
        for expected in [
            DecodedInstruction::LoadByte {
                destination: 11,
                base: 8,
                offset: secondary_offset,
            },
            DecodedInstruction::DuplicateByte16 {
                destination: 3,
                source: 11,
            },
        ] {
            expect_search_instruction(instructions, cursor, expected)?;
            cursor += 1;
        }
    }
    for expected in [
        DecodedInstruction::AddImmediate64 {
            destination: 5,
            source: 5,
            immediate: 1,
        },
        DecodedInstruction::AddRegister64 {
            destination: 15,
            left: 9,
            right: 5,
        },
    ] {
        expect_search_instruction(instructions, cursor, expected)?;
        cursor += 1;
    }
    if primary_offset != 0 {
        expect_search_instruction(
            instructions,
            cursor,
            DecodedInstruction::AddImmediate64 {
                destination: 15,
                source: 15,
                immediate: primary_offset,
            },
        )?;
        cursor += 1;
    }
    for expected in [
        DecodedInstruction::SubtractImmediate64 {
            destination: 7,
            source: 6,
            immediate: 15,
        },
        DecodedInstruction::CompareRegister64 { left: 5, right: 7 },
    ] {
        expect_search_instruction(instructions, cursor, expected)?;
        cursor += 1;
    }
    let vector_from_resume = expect_search_condition(instructions, cursor, Condition::LowerOrSame)?;
    cursor += 1;
    expect_search_instruction(
        instructions,
        cursor,
        DecodedInstruction::CompareRegister64 { left: 5, right: 6 },
    )?;
    cursor += 1;
    let none_from_resume = expect_search_condition(instructions, cursor, Condition::Higher)?;
    cursor += 1;
    let tail_from_resume = expect_search_branch(instructions, cursor)?;
    cursor += 1;
    for (branch, target) in [
        (block_from_exhausted, block_resume_index),
        (none_from_exhausted, none_index),
        (vector_from_resume, vector_index),
        (none_from_resume, none_index),
        (tail_from_resume, tail_setup_index),
    ] {
        if branch != target {
            return Err(invalid_search_instruction(scalar_exhausted_index));
        }
    }
    Ok((scalar_exhausted_index, block_resume_index, cursor))
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "the authenticated return template advances a cursor only after a successful bounds-checked decode lookup"
)]
fn validate_search_return_template(
    image: &NativeImage,
    instructions: &[DecodedInstruction],
    found_index: usize,
    none_index: usize,
) -> Result<(), AuditError> {
    let mut cursor = found_index;
    match image.output {
        fre_kernel_ir::OutputKind::Exists => {}
        fre_kernel_ir::OutputKind::SelectedEnd => {
            expect_search_instruction(
                instructions,
                cursor,
                DecodedInstruction::Store64 {
                    source: 14,
                    base: 4,
                    offset: 8,
                },
            )?;
            cursor += 1;
        }
        fre_kernel_ir::OutputKind::Span => {
            for expected in [
                DecodedInstruction::Store64 {
                    source: 13,
                    base: 4,
                    offset: 0,
                },
                DecodedInstruction::Store64 {
                    source: 14,
                    base: 4,
                    offset: 8,
                },
            ] {
                expect_search_instruction(instructions, cursor, expected)?;
                cursor += 1;
            }
        }
    }
    for expected in [
        DecodedInstruction::MoveZero64 {
            destination: 0,
            immediate: 1,
            shift: 0,
        },
        DecodedInstruction::Return,
    ] {
        expect_search_instruction(instructions, cursor, expected)?;
        cursor += 1;
    }
    if cursor != none_index {
        return Err(invalid_search_instruction(cursor));
    }
    for expected in [
        DecodedInstruction::MoveZero64 {
            destination: 0,
            immediate: 0,
            shift: 0,
        },
        DecodedInstruction::Return,
    ] {
        expect_search_instruction(instructions, cursor, expected)?;
        cursor += 1;
    }
    if cursor != instructions.len() {
        return Err(invalid_search_instruction(cursor));
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "all exact-search label roles remain explicit in the authenticated manifest"
)]
fn validate_search_label_manifest(
    image: &NativeImage,
    found_index: usize,
    none_index: usize,
    vector_index: usize,
    scalar_index: usize,
    candidate_advance_index: usize,
    secondary_index: Option<usize>,
    block_setup_index: usize,
    tail_setup_index: usize,
    scalar_advance_index: usize,
    scalar_exhausted_index: usize,
    block_resume_index: usize,
    equality_labels: &[(usize, LabelKind)],
) -> Result<(), AuditError> {
    let mut expected = vec![
        (0, LabelKind::Entry),
        (found_index, LabelKind::ReturnFound),
        (none_index, LabelKind::ReturnNone),
        (vector_index, LabelKind::Loop),
        (scalar_index, LabelKind::SlowPath),
        (candidate_advance_index, LabelKind::Internal),
        (block_setup_index, LabelKind::SlowPath),
        (tail_setup_index, LabelKind::SlowPath),
        (scalar_exhausted_index, LabelKind::Internal),
        (block_resume_index, LabelKind::Internal),
    ];
    if let Some(secondary_index) = secondary_index {
        expected.push((secondary_index, LabelKind::SlowPath));
    }
    expected.push((scalar_index, LabelKind::Loop));
    expected.push((scalar_advance_index, LabelKind::Internal));
    expected.extend_from_slice(equality_labels);
    expected.sort_unstable();
    if image.labels.len() != expected.len() {
        return Err(invalid_search_instruction(0));
    }
    for (actual, &(index, kind)) in image.labels.iter().zip(expected.iter()) {
        if actual.kind != kind || usize::try_from(actual.offset / 4).ok() != Some(index) {
            return Err(invalid_search_instruction(index));
        }
    }
    Ok(())
}

fn expect_search_instruction(
    instructions: &[DecodedInstruction],
    index: usize,
    expected: DecodedInstruction,
) -> Result<(), AuditError> {
    if instructions.get(index) != Some(&expected) {
        return Err(invalid_search_instruction(index));
    }
    Ok(())
}

fn expect_search_condition(
    instructions: &[DecodedInstruction],
    index: usize,
    expected: Condition,
) -> Result<usize, AuditError> {
    let Some(DecodedInstruction::BranchCondition {
        condition,
        displacement,
    }) = instructions.get(index)
    else {
        return Err(invalid_search_instruction(index));
    };
    if *condition != expected {
        return Err(invalid_search_instruction(index));
    }
    search_branch_target(index, *displacement, instructions.len())
}

fn expect_search_address(
    instructions: &[DecodedInstruction],
    index: usize,
    destination: u8,
) -> Result<(), AuditError> {
    if !matches!(
        instructions.get(index),
        Some(DecodedInstruction::Address {
            destination: actual,
            ..
        }) if *actual == destination
    ) {
        return Err(invalid_search_instruction(index));
    }
    Ok(())
}

fn expect_search_compare_branch(
    instructions: &[DecodedInstruction],
    index: usize,
    expected_nonzero: bool,
) -> Result<usize, AuditError> {
    expect_search_compare_branch_register(instructions, index, 10, expected_nonzero)
}

fn expect_search_compare_branch_register(
    instructions: &[DecodedInstruction],
    index: usize,
    expected_register: u8,
    expected_nonzero: bool,
) -> Result<usize, AuditError> {
    let Some(DecodedInstruction::CompareBranchZero64 {
        register,
        nonzero,
        displacement,
    }) = instructions.get(index)
    else {
        return Err(invalid_search_instruction(index));
    };
    if *register != expected_register || *nonzero != expected_nonzero {
        return Err(invalid_search_instruction(index));
    }
    search_branch_target(index, *displacement, instructions.len())
}

fn expect_search_branch(
    instructions: &[DecodedInstruction],
    index: usize,
) -> Result<usize, AuditError> {
    let Some(DecodedInstruction::Branch { displacement }) = instructions.get(index) else {
        return Err(invalid_search_instruction(index));
    };
    search_branch_target(index, *displacement, instructions.len())
}

fn search_branch_target(
    index: usize,
    displacement: i32,
    instruction_count: usize,
) -> Result<usize, AuditError> {
    let byte_offset = instruction_offset(index)?;
    let target = i64::from(byte_offset)
        .checked_add(i64::from(displacement))
        .ok_or(AuditError::ArithmeticOverflow)?;
    if target < 0 || target % 4 != 0 {
        return Err(invalid_search_instruction(index));
    }
    let target = usize::try_from(target / 4).map_err(|_| AuditError::ArithmeticOverflow)?;
    if target >= instruction_count {
        return Err(invalid_search_instruction(index));
    }
    Ok(target)
}

fn invalid_search_instruction(index: usize) -> AuditError {
    AuditError::InvalidSearchCandidateContract {
        offset: u32::try_from(index)
            .ok()
            .and_then(|value| value.checked_mul(4))
            .unwrap_or(u32::MAX),
    }
}

#[derive(Clone, Copy)]
enum StoreContract {
    Search,
    Aggregate,
}

#[allow(
    clippy::too_many_lines,
    reason = "keeping the independent linear audit in one pass makes relocation completeness auditable"
)]
fn audit_impl(
    image: &NativeImage,
    store_contract: StoreContract,
    instructions: &[DecodedInstruction],
    audit_work: &AuditWork,
) -> Result<AuditReport, AuditError> {
    validate_layout(image)?;
    validate_labels(image)?;
    validate_symbols(image)?;
    validate_relocation_order(image)?;
    let mut report = AuditReport {
        decode_passes: audit_work.decode_passes,
        source_identity_rebuilds: audit_work.source_identity_rebuilds,
        instructions: 0,
        direct_branches: 0,
        data_addresses: 0,
        vector_instructions: 0,
        stores: 0,
        returns: 0,
    };
    let mut relocation_index = 0_usize;
    let mut required_features = CpuFeatures::NONE;
    if instructions.len() != image.code.len() / 4 {
        return Err(AuditError::InvalidLayout);
    }
    for (index, (bytes, &instruction)) in image.code.chunks_exact(4).zip(instructions).enumerate() {
        let offset = u32::try_from(index)
            .ok()
            .and_then(|value| value.checked_mul(4))
            .ok_or(AuditError::ArithmeticOverflow)?;
        let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if canonical_word(instruction) != Some(word) {
            return Err(AuditError::NonCanonicalInstruction { offset });
        }
        if let Some(register) = first_forbidden_explicit_gpr(instruction) {
            return Err(AuditError::ForbiddenAggregateRegister { offset, register });
        }
        if matches!(store_contract, StoreContract::Search)
            && let Some(register) =
                first_forbidden_search_vector_register(instruction, image.backend_version)
        {
            return Err(AuditError::ForbiddenSearchVectorRegister { offset, register });
        }
        report.instructions = report
            .instructions
            .checked_add(1)
            .ok_or(AuditError::ArithmeticOverflow)?;
        if instruction.is_vector() {
            report.vector_instructions = report
                .vector_instructions
                .checked_add(1)
                .ok_or(AuditError::ArithmeticOverflow)?;
        }
        if instruction.is_asimd() {
            required_features = required_features.union(CpuFeatures::ASIMD);
        }
        if instruction.is_sve() {
            required_features = required_features.union(CpuFeatures::SVE);
        }
        if instruction.is_sve2() {
            required_features = required_features.union(CpuFeatures::SVE2);
        }
        let result_pointer = match store_contract {
            StoreContract::Search => 4,
            StoreContract::Aggregate => 2,
        };
        if instruction.written_gpr() == Some(result_pointer) {
            return Err(AuditError::ResultPointerClobber {
                offset,
                register: result_pointer,
            });
        }
        let relocation = image
            .relocations
            .get(relocation_index)
            .filter(|relocation| relocation.code_offset == offset);
        match instruction {
            DecodedInstruction::Branch { displacement }
            | DecodedInstruction::BranchCondition { displacement, .. }
            | DecodedInstruction::CompareBranchZero64 { displacement, .. } => {
                report.direct_branches = report
                    .direct_branches
                    .checked_add(1)
                    .ok_or(AuditError::ArithmeticOverflow)?;
                let relocation = relocation.ok_or(AuditError::MissingRelocation { offset })?;
                let expected_kind = match instruction {
                    DecodedInstruction::Branch { .. } => RelocationKind::Branch26,
                    DecodedInstruction::BranchCondition { .. } => {
                        RelocationKind::ConditionalBranch19
                    }
                    DecodedInstruction::CompareBranchZero64 { .. } => {
                        RelocationKind::CompareBranch19
                    }
                    _ => unreachable!("outer match fixes the instruction kind"),
                };
                if relocation.kind != expected_kind {
                    return Err(AuditError::RelocationKindMismatch { offset });
                }
                let target = i64::from(offset)
                    .checked_add(i64::from(displacement))
                    .ok_or(AuditError::ArithmeticOverflow)?;
                let target_u32 = u32::try_from(target)
                    .map_err(|_| AuditError::BranchTargetNotLabel { offset, target })?;
                if !image.labels.iter().any(|label| label.offset == target_u32) {
                    return Err(AuditError::BranchTargetNotLabel { offset, target });
                }
                if relocation.target != RelocationTarget::CodeOffset(target_u32)
                    || relocation.addend != 0
                {
                    return Err(AuditError::InvalidRelocation { offset });
                }
                validate_word(relocation.resolved_word, word, offset)?;
                relocation_index = relocation_index
                    .checked_add(1)
                    .ok_or(AuditError::ArithmeticOverflow)?;
            }
            DecodedInstruction::Address {
                displacement,
                destination: _,
            } => {
                report.data_addresses = report
                    .data_addresses
                    .checked_add(1)
                    .ok_or(AuditError::ArithmeticOverflow)?;
                let relocation = relocation.ok_or(AuditError::MissingRelocation { offset })?;
                if relocation.kind != RelocationKind::Address21 {
                    return Err(AuditError::RelocationKindMismatch { offset });
                }
                let target = i64::from(offset)
                    .checked_add(i64::from(displacement))
                    .ok_or(AuditError::ArithmeticOverflow)?;
                let rodata_base = i64::from(image.layout.rodata_from_code_start);
                let relative = target
                    .checked_sub(rodata_base)
                    .ok_or(AuditError::ArithmeticOverflow)?;
                let relative_u32 = u32::try_from(relative)
                    .map_err(|_| AuditError::AddressTargetNotData { offset, target })?;
                if !image
                    .symbols
                    .iter()
                    .any(|symbol| symbol.offset == relative_u32)
                {
                    return Err(AuditError::AddressTargetNotData { offset, target });
                }
                if relocation.target != RelocationTarget::RodataOffset(relative_u32)
                    || relocation.addend != 0
                {
                    return Err(AuditError::InvalidRelocation { offset });
                }
                validate_word(relocation.resolved_word, word, offset)?;
                relocation_index = relocation_index
                    .checked_add(1)
                    .ok_or(AuditError::ArithmeticOverflow)?;
            }
            DecodedInstruction::Store64 {
                base,
                offset: store_offset,
                ..
            } => {
                report.stores = report
                    .stores
                    .checked_add(1)
                    .ok_or(AuditError::ArithmeticOverflow)?;
                let permitted = match store_contract {
                    StoreContract::Search => base == 4 && matches!(store_offset, 0 | 8),
                    StoreContract::Aggregate => base == 2 && store_offset == 0,
                };
                if !permitted {
                    return Err(AuditError::ForbiddenStore {
                        offset,
                        base,
                        displacement: store_offset,
                    });
                }
                if relocation.is_some() {
                    return Err(AuditError::UnexpectedRelocation { offset });
                }
            }
            DecodedInstruction::Return => {
                report.returns = report
                    .returns
                    .checked_add(1)
                    .ok_or(AuditError::ArithmeticOverflow)?;
                if relocation.is_some() {
                    return Err(AuditError::UnexpectedRelocation { offset });
                }
            }
            _ => {
                if relocation.is_some() {
                    return Err(AuditError::UnexpectedRelocation { offset });
                }
            }
        }
    }
    if relocation_index != image.relocations.len() {
        let offset = image
            .relocations
            .get(relocation_index)
            .map_or(u32::MAX, |relocation| relocation.code_offset);
        return Err(AuditError::UnexpectedRelocation { offset });
    }
    if image.target.features != required_features
        || report.vector_instructions != image.stats.vector_instructions
    {
        return Err(AuditError::FeatureMismatch);
    }
    Ok(report)
}

#[allow(
    clippy::too_many_lines,
    reason = "the aggregate-only decoded contract is intentionally kept as one auditable gate"
)]
fn audit_aggregate_contract(
    image: &NativeImage,
    instructions: &[DecodedInstruction],
    envelope: AuthenticatedAggregateEnvelope,
) -> Result<(), AuditError> {
    let literal_len = envelope.literal_len;
    let output = envelope.output;

    let mut stores = Vec::new();
    let mut status_zero = None;
    let mut status_one = None;
    let mut address_count = 0_usize;
    for (index, &instruction) in instructions.iter().enumerate() {
        let offset = instruction_offset(index)?;
        if let Some(register) = first_forbidden_aggregate_vector_register(instruction) {
            return Err(AuditError::ForbiddenAggregateVectorRegister { offset, register });
        }
        validate_aggregate_critical_write(instructions, index, literal_len, output)?;
        match instruction {
            DecodedInstruction::Address { destination: 8, .. } => {
                address_count = address_count
                    .checked_add(1)
                    .ok_or(AuditError::ArithmeticOverflow)?;
            }
            DecodedInstruction::Address { .. } => {
                return Err(AuditError::InvalidAggregateControlFlow { offset });
            }
            DecodedInstruction::LoadByte { .. }
            | DecodedInstruction::LoadByteRegister { .. }
            | DecodedInstruction::Load64RegisterScaled { .. }
            | DecodedInstruction::LoadVector128 { .. }
            | DecodedInstruction::SveLoadBytes { .. } => {
                if !valid_aggregate_load(instructions, index, literal_len) {
                    return Err(AuditError::InvalidAggregateLoad { offset });
                }
            }
            DecodedInstruction::Store64 { source: 13, .. } => stores.push(index),
            DecodedInstruction::Store64 { .. } => {
                return Err(AuditError::InvalidAggregateStoreContract);
            }
            DecodedInstruction::Return => {
                let status_index = index
                    .checked_sub(1)
                    .ok_or(AuditError::InvalidAggregateControlFlow { offset })?;
                match instructions[status_index] {
                    DecodedInstruction::MoveZero64 {
                        destination: 0,
                        immediate: 0,
                        shift: 0,
                    } => {
                        if status_zero.replace((status_index, index)).is_some() {
                            return Err(AuditError::InvalidAggregateStoreContract);
                        }
                    }
                    DecodedInstruction::MoveZero64 {
                        destination: 0,
                        immediate: 1,
                        shift: 0,
                    } => {
                        if status_one.replace((status_index, index)).is_some() {
                            return Err(AuditError::InvalidAggregateStoreContract);
                        }
                    }
                    DecodedInstruction::MoveZero64 {
                        destination: 0,
                        immediate,
                        ..
                    } => {
                        return Err(AuditError::InvalidAggregateStatus {
                            offset: instruction_offset(status_index)?,
                            status: immediate,
                        });
                    }
                    _ => return Err(AuditError::InvalidAggregateControlFlow { offset }),
                }
            }
            _ => {}
        }
    }
    if address_count != usize::from(literal_len != 0) || stores.len() != 1 {
        return Err(AuditError::InvalidAggregateStoreContract);
    }
    let (success_status, success_return) =
        status_zero.ok_or(AuditError::InvalidAggregateStoreContract)?;
    let fault = status_one;
    let fault_required = literal_len != 0 || output == AggregateOutput::Count;
    if fault.is_some() != fault_required {
        return Err(AuditError::InvalidAggregateStoreContract);
    }
    let success_store = success_status
        .checked_sub(1)
        .ok_or(AuditError::InvalidAggregateStoreContract)?;
    if stores[0] != success_store
        || !matches!(
            instructions[success_store],
            DecodedInstruction::Store64 {
                source: 13,
                base: 2,
                offset: 0
            }
        )
    {
        return Err(AuditError::InvalidAggregateStoreContract);
    }

    let mut protected = vec![success_status, success_return];
    if let Some((_fault_status, fault_return)) = fault {
        protected.push(fault_return);
    }
    validate_aggregate_branches(instructions, &protected, literal_len)?;
    validate_aggregate_definite_initialization(instructions)?;
    validate_aggregate_reachability(instructions)?;
    validate_aggregate_template(image, instructions, literal_len, output)?;
    Ok(())
}

#[derive(Clone, Copy)]
struct AuthenticatedAggregateEnvelope {
    literal_len: usize,
    output: AggregateOutput,
}

fn authenticate_aggregate_envelope(
    image: &NativeImage,
    work: &mut AuditWork,
) -> Result<AuthenticatedAggregateEnvelope, AuditError> {
    if image.search_manifest().is_some() {
        return Err(AuditError::InvalidImageContract);
    }
    let manifest = image
        .aggregate_manifest()
        .ok_or(AuditError::InvalidAggregateManifest)?;
    let literal_len = usize::try_from(manifest.literal_bytes)
        .map_err(|_| AuditError::InvalidAggregateManifest)?;
    if !matches!(
        image.backend_version,
        BackendVersion::AGGREGATE_V1
            | BackendVersion::AGGREGATE_HISTORICAL_V2
            | BackendVersion::AGGREGATE_SVE2_FIXED16_COUNT_EXPERIMENTAL_V1
    ) || literal_len > MAX_EXACT_AGGREGATE_LITERAL_BYTES
        || image.rodata.len() != literal_len
        || image.symbols.len() != 1
    {
        return Err(AuditError::InvalidAggregateManifest);
    }

    let (instructions, labels, relocations, vector_instructions) =
        match (image.backend_version, manifest.output, literal_len) {
            (
                BackendVersion::AGGREGATE_SVE2_FIXED16_COUNT_EXPERIMENTAL_V1,
                AggregateOutput::Count,
                1,
            ) => (39_usize, 6_usize, 9_usize, 5_u32),
            (
                BackendVersion::AGGREGATE_V1 | BackendVersion::AGGREGATE_HISTORICAL_V2,
                output,
                literal_len,
            ) => match (output, literal_len) {
                (AggregateOutput::Count, 0) => (14_usize, 3_usize, 2_usize, 0_u32),
                (AggregateOutput::SpanSum, 0) => (5, 2, 1, 0),
                (_, 1) => (42, 6, 9, 5),
                (_, 2) => (55, 9, 13, 9),
                (_, 3..=15) => (68, 12, 17, 9),
                (_, 16..=MAX_EXACT_AGGREGATE_LITERAL_BYTES) => (80, 13, 19, 14),
                _ => return Err(AuditError::InvalidAggregateManifest),
            },
            _ => return Err(AuditError::InvalidAggregateManifest),
        };
    let code_bytes = instructions
        .checked_mul(4)
        .ok_or(AuditError::ArithmeticOverflow)?;
    if image.code.len() != code_bytes
        || image.labels.len() != labels
        || image.relocations.len() != relocations
        || image.stats.vector_instructions != vector_instructions
        || crate::image::aot_size(image).map_err(|_| AuditError::ArithmeticOverflow)? > 984
    {
        return Err(AuditError::InvalidAggregateManifest);
    }
    let symbol = image.symbols[0];
    if symbol.ir_data_id != 0
        || symbol.offset != 0
        || usize::try_from(symbol.length).ok() != Some(literal_len)
        || symbol.alignment != 16
        || symbol.kind != DataSymbolKind::Bytes
    {
        return Err(AuditError::InvalidAggregateManifest);
    }

    work.record_source_identity_rebuild()?;
    let (expected_identity, expected_search_identity) = match manifest.output {
        AggregateOutput::Count => {
            let program = build_exact_aggregate::<Count>(&image.rodata, ValidateLimits::default())
                .map_err(|_| AuditError::InvalidAggregateManifest)?;
            (program.cache_identity(), program.search_cache_identity())
        }
        AggregateOutput::SpanSum => {
            let program =
                build_exact_aggregate::<SpanSum>(&image.rodata, ValidateLimits::default())
                    .map_err(|_| AuditError::InvalidAggregateManifest)?;
            (program.cache_identity(), program.search_cache_identity())
        }
    };
    if manifest.source_identity != expected_identity
        || image.source_identity != expected_search_identity
    {
        return Err(AuditError::InvalidAggregateManifest);
    }
    Ok(AuthenticatedAggregateEnvelope {
        literal_len,
        output: manifest.output,
    })
}

struct AggregateTemplateCursor<'a> {
    instructions: &'a [DecodedInstruction],
    position: usize,
}

impl<'a> AggregateTemplateCursor<'a> {
    const fn new(instructions: &'a [DecodedInstruction]) -> Self {
        Self {
            instructions,
            position: 0,
        }
    }

    fn expect_all<const N: usize>(
        &mut self,
        expected: [DecodedInstruction; N],
    ) -> Result<(), AuditError> {
        for instruction in expected {
            if self.instructions.get(self.position) != Some(&instruction) {
                return Err(AuditError::InvalidAggregateTemplate {
                    offset: instruction_offset(self.position)?,
                });
            }
            self.position = self
                .position
                .checked_add(1)
                .ok_or(AuditError::ArithmeticOverflow)?;
        }
        Ok(())
    }

    fn finish(self) -> Result<(), AuditError> {
        if self.position != self.instructions.len() {
            return Err(AuditError::InvalidAggregateTemplate {
                offset: instruction_offset(self.position)?,
            });
        }
        Ok(())
    }
}

fn validate_aggregate_template_labels(
    image: &NativeImage,
    literal_len: usize,
    output: AggregateOutput,
) -> Result<(), AuditError> {
    const M0_COUNT: &[(u32, LabelKind)] = &[
        (0, LabelKind::Entry),
        (36, LabelKind::ReturnFound),
        (48, LabelKind::ReturnNone),
    ];
    const M0_SPAN_SUM: &[(u32, LabelKind)] = &[(0, LabelKind::Entry), (8, LabelKind::ReturnFound)];
    const M1: &[(u32, LabelKind)] = &[
        (0, LabelKind::Entry),
        (24, LabelKind::Loop),
        (100, LabelKind::SlowPath),
        (140, LabelKind::Internal),
        (148, LabelKind::ReturnFound),
        (160, LabelKind::ReturnNone),
    ];
    const M2: &[(u32, LabelKind)] = &[
        (0, LabelKind::Entry),
        (44, LabelKind::Loop),
        (104, LabelKind::Internal),
        (112, LabelKind::SlowPath),
        (120, LabelKind::SlowPath),
        (124, LabelKind::Loop),
        (192, LabelKind::Internal),
        (200, LabelKind::ReturnFound),
        (212, LabelKind::ReturnNone),
    ];
    const M3_TO_M15: &[(u32, LabelKind)] = &[
        (0, LabelKind::Entry),
        (44, LabelKind::Loop),
        (104, LabelKind::Internal),
        (112, LabelKind::SlowPath),
        (120, LabelKind::SlowPath),
        (124, LabelKind::Loop),
        (184, LabelKind::Internal),
        (188, LabelKind::Loop),
        (220, LabelKind::Internal),
        (244, LabelKind::Internal),
        (252, LabelKind::ReturnFound),
        (264, LabelKind::ReturnNone),
    ];
    const M16_TO_M32: &[(u32, LabelKind)] = &[
        (0, LabelKind::Entry),
        (44, LabelKind::Loop),
        (104, LabelKind::Internal),
        (112, LabelKind::SlowPath),
        (120, LabelKind::SlowPath),
        (124, LabelKind::Loop),
        (180, LabelKind::Loop),
        (232, LabelKind::Internal),
        (236, LabelKind::Loop),
        (268, LabelKind::Internal),
        (292, LabelKind::Internal),
        (300, LabelKind::ReturnFound),
        (312, LabelKind::ReturnNone),
    ];

    let expected = match (output, literal_len) {
        (AggregateOutput::Count, 0) => M0_COUNT,
        (AggregateOutput::SpanSum, 0) => M0_SPAN_SUM,
        (_, 1) => M1,
        (_, 2) => M2,
        (_, 3..=15) => M3_TO_M15,
        (_, 16..=32) => M16_TO_M32,
        _ => {
            return Err(AuditError::InvalidAggregateTemplate { offset: 0 });
        }
    };
    if image.labels.len() != expected.len() {
        return Err(AuditError::InvalidAggregateTemplate { offset: 0 });
    }
    for (actual, &(offset, kind)) in image.labels.iter().zip(expected) {
        if actual.offset != offset || actual.kind != kind {
            return Err(AuditError::InvalidAggregateTemplate {
                offset: actual.offset,
            });
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the v1 decoded aggregate templates deliberately expose every opcode and operand without emitter dependencies"
)]
fn validate_aggregate_template(
    image: &NativeImage,
    instructions: &[DecodedInstruction],
    literal_len: usize,
    output: AggregateOutput,
) -> Result<(), AuditError> {
    use DecodedInstruction::{
        AddAcrossBytes16, AddImmediate64, AddRegister64, Address, AndBytes16, AndLowBits64, Branch,
        BranchCondition, CompareBranchZero64, CompareEqualBytes16, CompareImmediate32,
        CompareImmediate64, CompareRegister32, CompareRegister64, DuplicateByte16, LoadByte,
        LoadByteRegister, LoadVector128, MoveKeep64, MoveRegister64, MoveVectorByteTo32,
        MoveZero64, Return, Store64, SubtractImmediate64, SubtractRegister64, UnsignedMaxBytes16,
        UnsignedMinBytes16,
    };

    if image.backend_version == BackendVersion::AGGREGATE_SVE2_FIXED16_COUNT_EXPERIMENTAL_V1 {
        return validate_aggregate_sve2_fixed16_count_experimental_template(
            image,
            instructions,
            literal_len,
            output,
        );
    }

    validate_aggregate_template_labels(image, literal_len, output)?;
    let mut cursor = AggregateTemplateCursor::new(instructions);
    if literal_len == 0 {
        match output {
            AggregateOutput::Count => cursor.expect_all([
                MoveZero64 {
                    destination: 13,
                    immediate: 0,
                    shift: 0,
                },
                MoveZero64 {
                    destination: 10,
                    immediate: u16::MAX,
                    shift: 0,
                },
                MoveKeep64 {
                    destination: 10,
                    immediate: u16::MAX,
                    shift: 16,
                },
                MoveKeep64 {
                    destination: 10,
                    immediate: u16::MAX,
                    shift: 32,
                },
                MoveKeep64 {
                    destination: 10,
                    immediate: u16::MAX,
                    shift: 48,
                },
                CompareRegister64 { left: 1, right: 10 },
                BranchCondition {
                    condition: crate::Condition::Equal,
                    displacement: 24,
                },
                AddImmediate64 {
                    destination: 13,
                    source: 1,
                    immediate: 1,
                },
                Branch { displacement: 4 },
                Store64 {
                    source: 13,
                    base: 2,
                    offset: 0,
                },
                MoveZero64 {
                    destination: 0,
                    immediate: 0,
                    shift: 0,
                },
                Return,
                MoveZero64 {
                    destination: 0,
                    immediate: 1,
                    shift: 0,
                },
                Return,
            ])?,
            AggregateOutput::SpanSum => cursor.expect_all([
                MoveZero64 {
                    destination: 13,
                    immediate: 0,
                    shift: 0,
                },
                Branch { displacement: 4 },
                Store64 {
                    source: 13,
                    base: 2,
                    offset: 0,
                },
                MoveZero64 {
                    destination: 0,
                    immediate: 0,
                    shift: 0,
                },
                Return,
            ])?,
        }
        return cursor.finish();
    }

    let width = u16::try_from(literal_len).map_err(|_| AuditError::InvalidAggregateManifest)?;
    if literal_len == 1 {
        cursor.expect_all([
            MoveZero64 {
                destination: 13,
                immediate: 0,
                shift: 0,
            },
            Address {
                destination: 8,
                displacement: 172,
            },
            MoveZero64 {
                destination: 12,
                immediate: 1,
                shift: 0,
            },
            LoadByte {
                destination: 11,
                base: 8,
                offset: 0,
            },
            DuplicateByte16 {
                destination: 1,
                source: 11,
            },
            MoveZero64 {
                destination: 5,
                immediate: 0,
                shift: 0,
            },
            CompareRegister64 { left: 5, right: 1 },
            BranchCondition {
                condition: crate::Condition::CarrySet,
                displacement: 120,
            },
            SubtractRegister64 {
                destination: 10,
                left: 1,
                right: 5,
            },
            CompareImmediate64 {
                register: 10,
                immediate: 16,
            },
            BranchCondition {
                condition: crate::Condition::CarryClear,
                displacement: 60,
            },
            AddRegister64 {
                destination: 15,
                left: 0,
                right: 5,
            },
            LoadVector128 {
                destination: 0,
                base: 15,
                offset: 0,
            },
            CompareEqualBytes16 {
                destination: 0,
                left: 0,
                right: 1,
            },
            AddAcrossBytes16 {
                destination: 0,
                source: 0,
            },
            MoveVectorByteTo32 {
                destination: 10,
                source: 0,
            },
            MoveZero64 {
                destination: 11,
                immediate: 256,
                shift: 0,
            },
            SubtractRegister64 {
                destination: 10,
                left: 11,
                right: 10,
            },
            AndLowBits64 {
                destination: 10,
                source: 10,
                bits: 8,
            },
            MoveRegister64 {
                destination: 14,
                source: 13,
            },
            AddRegister64 {
                destination: 13,
                left: 13,
                right: 10,
            },
            CompareRegister64 {
                left: 13,
                right: 14,
            },
            BranchCondition {
                condition: crate::Condition::CarryClear,
                displacement: 72,
            },
            AddImmediate64 {
                destination: 5,
                source: 5,
                immediate: 16,
            },
            Branch { displacement: -72 },
            CompareRegister64 { left: 5, right: 1 },
            BranchCondition {
                condition: crate::Condition::CarrySet,
                displacement: 44,
            },
            LoadByteRegister {
                destination: 10,
                base: 0,
                index: 5,
            },
            LoadByte {
                destination: 11,
                base: 8,
                offset: 0,
            },
            CompareRegister32 {
                left: 10,
                right: 11,
            },
            BranchCondition {
                condition: crate::Condition::NotEqual,
                displacement: 20,
            },
            MoveRegister64 {
                destination: 14,
                source: 13,
            },
            AddImmediate64 {
                destination: 13,
                source: 13,
                immediate: 1,
            },
            CompareRegister64 {
                left: 13,
                right: 14,
            },
            BranchCondition {
                condition: crate::Condition::CarryClear,
                displacement: 24,
            },
            AddImmediate64 {
                destination: 5,
                source: 5,
                immediate: 1,
            },
            Branch { displacement: -44 },
            Store64 {
                source: 13,
                base: 2,
                offset: 0,
            },
            MoveZero64 {
                destination: 0,
                immediate: 0,
                shift: 0,
            },
            Return,
            MoveZero64 {
                destination: 0,
                immediate: 1,
                shift: 0,
            },
            Return,
        ])?;
        return cursor.finish();
    }

    let last = width
        .checked_sub(1)
        .ok_or(AuditError::InvalidAggregateManifest)?;
    let (address_displacement, initial_fault_displacement, vector_fault_displacement) =
        match literal_len {
            2 => (220, 184, 152),
            3..=15 => (268, 236, 204),
            16..=32 => (316, 284, 252),
            _ => return Err(AuditError::InvalidAggregateTemplate { offset: 0 }),
        };
    let (first_miss_displacement, last_miss_displacement) = match literal_len {
        2 => (48, 28),
        3..=15 => (100, 80),
        16..=32 => (148, 128),
        _ => return Err(AuditError::InvalidAggregateTemplate { offset: 0 }),
    };
    cursor.expect_all([
        MoveZero64 {
            destination: 13,
            immediate: 0,
            shift: 0,
        },
        Address {
            destination: 8,
            displacement: address_displacement,
        },
        MoveZero64 {
            destination: 12,
            immediate: width,
            shift: 0,
        },
        CompareRegister64 { left: 1, right: 12 },
        BranchCondition {
            condition: crate::Condition::CarryClear,
            displacement: initial_fault_displacement,
        },
        SubtractRegister64 {
            destination: 6,
            left: 1,
            right: 12,
        },
        MoveZero64 {
            destination: 5,
            immediate: 0,
            shift: 0,
        },
        LoadByte {
            destination: 11,
            base: 8,
            offset: 0,
        },
        DuplicateByte16 {
            destination: 1,
            source: 11,
        },
        LoadByte {
            destination: 11,
            base: 8,
            offset: last,
        },
        DuplicateByte16 {
            destination: 3,
            source: 11,
        },
        CompareRegister64 { left: 5, right: 6 },
        BranchCondition {
            condition: crate::Condition::Higher,
            displacement: vector_fault_displacement,
        },
        SubtractRegister64 {
            destination: 10,
            left: 6,
            right: 5,
        },
        CompareImmediate64 {
            register: 10,
            immediate: 15,
        },
        BranchCondition {
            condition: crate::Condition::CarryClear,
            displacement: 60,
        },
        AddRegister64 {
            destination: 15,
            left: 0,
            right: 5,
        },
        LoadVector128 {
            destination: 0,
            base: 15,
            offset: 0,
        },
        CompareEqualBytes16 {
            destination: 0,
            left: 0,
            right: 1,
        },
        AddImmediate64 {
            destination: 10,
            source: 15,
            immediate: last,
        },
        LoadVector128 {
            destination: 2,
            base: 10,
            offset: 0,
        },
        CompareEqualBytes16 {
            destination: 2,
            left: 2,
            right: 3,
        },
        AndBytes16 {
            destination: 0,
            left: 0,
            right: 2,
        },
        UnsignedMaxBytes16 {
            destination: 0,
            source: 0,
        },
        MoveVectorByteTo32 {
            destination: 10,
            source: 0,
        },
        CompareBranchZero64 {
            register: 10,
            nonzero: true,
            displacement: 12,
        },
        AddImmediate64 {
            destination: 5,
            source: 5,
            immediate: 16,
        },
        Branch { displacement: -64 },
        AddImmediate64 {
            destination: 7,
            source: 5,
            immediate: 15,
        },
        Branch { displacement: 8 },
        MoveRegister64 {
            destination: 7,
            source: 6,
        },
        CompareRegister64 { left: 5, right: 7 },
        BranchCondition {
            condition: crate::Condition::Higher,
            displacement: -84,
        },
        LoadByteRegister {
            destination: 10,
            base: 0,
            index: 5,
        },
        LoadByte {
            destination: 11,
            base: 8,
            offset: 0,
        },
        CompareRegister32 {
            left: 10,
            right: 11,
        },
        BranchCondition {
            condition: crate::Condition::NotEqual,
            displacement: first_miss_displacement,
        },
        AddRegister64 {
            destination: 15,
            left: 0,
            right: 5,
        },
        LoadByte {
            destination: 10,
            base: 15,
            offset: last,
        },
        LoadByte {
            destination: 11,
            base: 8,
            offset: last,
        },
        CompareRegister32 {
            left: 10,
            right: 11,
        },
        BranchCondition {
            condition: crate::Condition::NotEqual,
            displacement: last_miss_displacement,
        },
    ])?;

    let reducer_delta = match output {
        AggregateOutput::Count => 1,
        AggregateOutput::SpanSum => width,
    };
    match literal_len {
        2 => cursor.expect_all([
            MoveRegister64 {
                destination: 14,
                source: 13,
            },
            AddImmediate64 {
                destination: 13,
                source: 13,
                immediate: reducer_delta,
            },
            CompareRegister64 {
                left: 13,
                right: 14,
            },
            BranchCondition {
                condition: crate::Condition::CarryClear,
                displacement: 32,
            },
            AddImmediate64 {
                destination: 5,
                source: 5,
                immediate: width,
            },
            Branch { displacement: -64 },
            AddImmediate64 {
                destination: 5,
                source: 5,
                immediate: 1,
            },
            Branch { displacement: -72 },
            Store64 {
                source: 13,
                base: 2,
                offset: 0,
            },
            MoveZero64 {
                destination: 0,
                immediate: 0,
                shift: 0,
            },
            Return,
            MoveZero64 {
                destination: 0,
                immediate: 1,
                shift: 0,
            },
            Return,
        ])?,
        3..=15 => cursor.expect_all([
            MoveRegister64 {
                destination: 15,
                source: 15,
            },
            MoveRegister64 {
                destination: 16,
                source: 8,
            },
            MoveZero64 {
                destination: 17,
                immediate: width,
                shift: 0,
            },
            Branch { displacement: 4 },
            CompareBranchZero64 {
                register: 17,
                nonzero: false,
                displacement: 36,
            },
            LoadByte {
                destination: 10,
                base: 15,
                offset: 0,
            },
            LoadByte {
                destination: 11,
                base: 16,
                offset: 0,
            },
            CompareRegister32 {
                left: 10,
                right: 11,
            },
            BranchCondition {
                condition: crate::Condition::NotEqual,
                displacement: 44,
            },
            AddImmediate64 {
                destination: 15,
                source: 15,
                immediate: 1,
            },
            AddImmediate64 {
                destination: 16,
                source: 16,
                immediate: 1,
            },
            SubtractImmediate64 {
                destination: 17,
                source: 17,
                immediate: 1,
            },
            CompareBranchZero64 {
                register: 17,
                nonzero: true,
                displacement: -28,
            },
            MoveRegister64 {
                destination: 14,
                source: 13,
            },
            AddImmediate64 {
                destination: 13,
                source: 13,
                immediate: reducer_delta,
            },
            CompareRegister64 {
                left: 13,
                right: 14,
            },
            BranchCondition {
                condition: crate::Condition::CarryClear,
                displacement: 32,
            },
            AddImmediate64 {
                destination: 5,
                source: 5,
                immediate: width,
            },
            Branch { displacement: -116 },
            AddImmediate64 {
                destination: 5,
                source: 5,
                immediate: 1,
            },
            Branch { displacement: -124 },
            Store64 {
                source: 13,
                base: 2,
                offset: 0,
            },
            MoveZero64 {
                destination: 0,
                immediate: 0,
                shift: 0,
            },
            Return,
            MoveZero64 {
                destination: 0,
                immediate: 1,
                shift: 0,
            },
            Return,
        ])?,
        16..=32 => cursor.expect_all([
            MoveRegister64 {
                destination: 15,
                source: 15,
            },
            MoveRegister64 {
                destination: 16,
                source: 8,
            },
            MoveZero64 {
                destination: 17,
                immediate: width,
                shift: 0,
            },
            CompareImmediate64 {
                register: 17,
                immediate: 16,
            },
            BranchCondition {
                condition: crate::Condition::CarryClear,
                displacement: 48,
            },
            LoadVector128 {
                destination: 4,
                base: 15,
                offset: 0,
            },
            LoadVector128 {
                destination: 5,
                base: 16,
                offset: 0,
            },
            CompareEqualBytes16 {
                destination: 4,
                left: 4,
                right: 5,
            },
            UnsignedMinBytes16 {
                destination: 4,
                source: 4,
            },
            MoveVectorByteTo32 {
                destination: 10,
                source: 4,
            },
            CompareImmediate32 {
                register: 10,
                immediate: 255,
            },
            BranchCondition {
                condition: crate::Condition::NotEqual,
                displacement: 80,
            },
            AddImmediate64 {
                destination: 15,
                source: 15,
                immediate: 16,
            },
            AddImmediate64 {
                destination: 16,
                source: 16,
                immediate: 16,
            },
            SubtractImmediate64 {
                destination: 17,
                source: 17,
                immediate: 16,
            },
            Branch { displacement: -48 },
            CompareBranchZero64 {
                register: 17,
                nonzero: false,
                displacement: 36,
            },
            LoadByte {
                destination: 10,
                base: 15,
                offset: 0,
            },
            LoadByte {
                destination: 11,
                base: 16,
                offset: 0,
            },
            CompareRegister32 {
                left: 10,
                right: 11,
            },
            BranchCondition {
                condition: crate::Condition::NotEqual,
                displacement: 44,
            },
            AddImmediate64 {
                destination: 15,
                source: 15,
                immediate: 1,
            },
            AddImmediate64 {
                destination: 16,
                source: 16,
                immediate: 1,
            },
            SubtractImmediate64 {
                destination: 17,
                source: 17,
                immediate: 1,
            },
            CompareBranchZero64 {
                register: 17,
                nonzero: true,
                displacement: -28,
            },
            MoveRegister64 {
                destination: 14,
                source: 13,
            },
            AddImmediate64 {
                destination: 13,
                source: 13,
                immediate: reducer_delta,
            },
            CompareRegister64 {
                left: 13,
                right: 14,
            },
            BranchCondition {
                condition: crate::Condition::CarryClear,
                displacement: 32,
            },
            AddImmediate64 {
                destination: 5,
                source: 5,
                immediate: width,
            },
            Branch { displacement: -164 },
            AddImmediate64 {
                destination: 5,
                source: 5,
                immediate: 1,
            },
            Branch { displacement: -172 },
            Store64 {
                source: 13,
                base: 2,
                offset: 0,
            },
            MoveZero64 {
                destination: 0,
                immediate: 0,
                shift: 0,
            },
            Return,
            MoveZero64 {
                destination: 0,
                immediate: 1,
                shift: 0,
            },
            Return,
        ])?,
        _ => return Err(AuditError::InvalidAggregateTemplate { offset: 0 }),
    }
    cursor.finish()
}

#[allow(
    clippy::too_many_lines,
    reason = "the experimental backend's complete decoded template is intentionally explicit"
)]
fn validate_aggregate_sve2_fixed16_count_experimental_template(
    image: &NativeImage,
    instructions: &[DecodedInstruction],
    literal_len: usize,
    output: AggregateOutput,
) -> Result<(), AuditError> {
    use DecodedInstruction::{
        AddImmediate64, AddRegister64, Address, Branch, BranchCondition, CompareImmediate64,
        CompareRegister32, CompareRegister64, LoadByte, LoadByteRegister, MoveRegister64,
        MoveZero64, Return, Store64, SubtractRegister64, Sve2MatchBytes, SveCountPredicateBytes,
        SveDuplicateByte, SveLoadBytes, SvePtrueBytesVl16,
    };
    const LABELS: &[(u32, LabelKind)] = &[
        (0, LabelKind::Entry),
        (28, LabelKind::Loop),
        (88, LabelKind::SlowPath),
        (128, LabelKind::Internal),
        (136, LabelKind::ReturnFound),
        (148, LabelKind::ReturnNone),
    ];

    if literal_len != 1 || output != AggregateOutput::Count {
        return Err(AuditError::InvalidAggregateTemplate { offset: 0 });
    }
    if image.labels.len() != LABELS.len()
        || image
            .labels
            .iter()
            .zip(LABELS)
            .any(|(actual, expected)| (actual.offset, actual.kind) != *expected)
    {
        return Err(AuditError::InvalidAggregateTemplate { offset: 0 });
    }

    let mut cursor = AggregateTemplateCursor::new(instructions);
    cursor.expect_all([
        MoveZero64 {
            destination: 13,
            immediate: 0,
            shift: 0,
        },
        Address {
            destination: 8,
            displacement: 156,
        },
        MoveZero64 {
            destination: 12,
            immediate: 1,
            shift: 0,
        },
        LoadByte {
            destination: 11,
            base: 8,
            offset: 0,
        },
        SvePtrueBytesVl16 { destination: 0 },
        SveDuplicateByte {
            destination: 1,
            source: 11,
        },
        MoveZero64 {
            destination: 5,
            immediate: 0,
            shift: 0,
        },
        CompareRegister64 { left: 5, right: 1 },
        BranchCondition {
            condition: crate::Condition::CarrySet,
            displacement: 104,
        },
        SubtractRegister64 {
            destination: 10,
            left: 1,
            right: 5,
        },
        CompareImmediate64 {
            register: 10,
            immediate: 16,
        },
        BranchCondition {
            condition: crate::Condition::CarryClear,
            displacement: 44,
        },
        AddRegister64 {
            destination: 15,
            left: 0,
            right: 5,
        },
        SveLoadBytes {
            destination: 0,
            predicate: 0,
            base: 15,
        },
        Sve2MatchBytes {
            destination: 1,
            predicate: 0,
            left: 0,
            right: 1,
        },
        SveCountPredicateBytes {
            destination: 10,
            predicate: 0,
            source: 1,
        },
        MoveRegister64 {
            destination: 14,
            source: 13,
        },
        AddRegister64 {
            destination: 13,
            left: 13,
            right: 10,
        },
        CompareRegister64 {
            left: 13,
            right: 14,
        },
        BranchCondition {
            condition: crate::Condition::CarryClear,
            displacement: 72,
        },
        AddImmediate64 {
            destination: 5,
            source: 5,
            immediate: 16,
        },
        Branch { displacement: -56 },
        CompareRegister64 { left: 5, right: 1 },
        BranchCondition {
            condition: crate::Condition::CarrySet,
            displacement: 44,
        },
        LoadByteRegister {
            destination: 10,
            base: 0,
            index: 5,
        },
        LoadByte {
            destination: 11,
            base: 8,
            offset: 0,
        },
        CompareRegister32 {
            left: 10,
            right: 11,
        },
        BranchCondition {
            condition: crate::Condition::NotEqual,
            displacement: 20,
        },
        MoveRegister64 {
            destination: 14,
            source: 13,
        },
        AddImmediate64 {
            destination: 13,
            source: 13,
            immediate: 1,
        },
        CompareRegister64 {
            left: 13,
            right: 14,
        },
        BranchCondition {
            condition: crate::Condition::CarryClear,
            displacement: 24,
        },
        AddImmediate64 {
            destination: 5,
            source: 5,
            immediate: 1,
        },
        Branch { displacement: -44 },
        Store64 {
            source: 13,
            base: 2,
            offset: 0,
        },
        MoveZero64 {
            destination: 0,
            immediate: 0,
            shift: 0,
        },
        Return,
        MoveZero64 {
            destination: 0,
            immediate: 1,
            shift: 0,
        },
        Return,
    ])?;
    cursor.finish()
}

fn instruction_offset(index: usize) -> Result<u32, AuditError> {
    u32::try_from(index)
        .ok()
        .and_then(|value| value.checked_mul(4))
        .ok_or(AuditError::ArithmeticOverflow)
}

fn instruction_after(
    instructions: &[DecodedInstruction],
    index: usize,
    distance: usize,
) -> Option<&DecodedInstruction> {
    index
        .checked_add(distance)
        .and_then(|next| instructions.get(next))
}

#[allow(
    clippy::match_same_arms,
    clippy::too_many_lines,
    reason = "operand arities remain grouped by decoded ISA form for security review"
)]
pub(crate) fn first_forbidden_explicit_gpr(instruction: DecodedInstruction) -> Option<u8> {
    fn forbidden(registers: &[u8]) -> Option<u8> {
        registers.iter().copied().find(|&register| register >= 18)
    }
    match instruction {
        DecodedInstruction::MoveRegister64 {
            destination,
            source,
        } => forbidden(&[destination, source]),
        DecodedInstruction::MoveZero64 { destination, .. }
        | DecodedInstruction::MoveKeep64 { destination, .. }
        | DecodedInstruction::CompareImmediate64 {
            register: destination,
            ..
        }
        | DecodedInstruction::CompareImmediate32 {
            register: destination,
            ..
        }
        | DecodedInstruction::MoveVectorByteTo32 { destination, .. }
        | DecodedInstruction::MoveVectorDoubleTo64 { destination, .. }
        | DecodedInstruction::SveCountPredicateBytes { destination, .. }
        | DecodedInstruction::Address { destination, .. }
        | DecodedInstruction::CompareBranchZero64 {
            register: destination,
            ..
        } => forbidden(&[destination]),
        DecodedInstruction::CompareRegister64 { left, right }
        | DecodedInstruction::CompareRegister32 { left, right } => forbidden(&[left, right]),
        DecodedInstruction::AddRegister64 {
            destination,
            left,
            right,
        }
        | DecodedInstruction::SubtractRegister64 {
            destination,
            left,
            right,
        }
        | DecodedInstruction::AndRegister64 {
            destination,
            left,
            right,
        } => forbidden(&[destination, left, right]),
        DecodedInstruction::AddImmediate64 {
            destination,
            source,
            ..
        }
        | DecodedInstruction::SubtractImmediate64 {
            destination,
            source,
            ..
        }
        | DecodedInstruction::AndLowBits64 {
            destination,
            source,
            ..
        }
        | DecodedInstruction::LogicalShiftRightImmediate64 {
            destination,
            source,
            ..
        }
        | DecodedInstruction::LogicalShiftLeftImmediate64 {
            destination,
            source,
            ..
        }
        | DecodedInstruction::ReverseBits64 {
            destination,
            source,
        }
        | DecodedInstruction::CountLeadingZeros64 {
            destination,
            source,
        } => forbidden(&[destination, source]),
        DecodedInstruction::LoadByte {
            destination, base, ..
        } => forbidden(&[destination, base]),
        DecodedInstruction::LoadVector128 { base, .. }
        | DecodedInstruction::SveLoadBytes { base, .. } => forbidden(&[base]),
        DecodedInstruction::LoadByteRegister {
            destination,
            base,
            index,
        }
        | DecodedInstruction::Load64RegisterScaled {
            destination,
            base,
            index,
        } => forbidden(&[destination, base, index]),
        DecodedInstruction::Store64 { source, base, .. } => forbidden(&[source, base]),
        DecodedInstruction::DuplicateByte16 { source, .. }
        | DecodedInstruction::SveDuplicateByte { source, .. } => forbidden(&[source]),
        DecodedInstruction::LogicalShiftRightVariable64 {
            destination,
            source,
            shift,
        } => forbidden(&[destination, source, shift]),
        DecodedInstruction::CompareEqualBytes16 { .. }
        | DecodedInstruction::AndBytes16 { .. }
        | DecodedInstruction::ShiftRightNarrowHalfwordsToBytes8 { .. }
        | DecodedInstruction::UnsignedMinBytes16 { .. }
        | DecodedInstruction::UnsignedMaxBytes16 { .. }
        | DecodedInstruction::UnsignedMaxPairwiseBytes16 { .. }
        | DecodedInstruction::AddAcrossBytes16 { .. }
        | DecodedInstruction::SvePtrueBytesVl16 { .. }
        | DecodedInstruction::SveCompareEqualBytes { .. }
        | DecodedInstruction::Sve2MatchBytes { .. }
        | DecodedInstruction::SveAndPredicateBytes { .. }
        | DecodedInstruction::SveTestPredicateBytes { .. }
        | DecodedInstruction::SveBreakBeforeBytes { .. }
        | DecodedInstruction::Branch { .. }
        | DecodedInstruction::BranchCondition { .. }
        | DecodedInstruction::Return => None,
    }
}

fn first_forbidden_aggregate_vector_register(instruction: DecodedInstruction) -> Option<u8> {
    fn forbidden(registers: &[u8]) -> Option<u8> {
        registers.iter().copied().find(|&register| register > 5)
    }
    match instruction {
        DecodedInstruction::LoadVector128 { destination, .. }
        | DecodedInstruction::DuplicateByte16 { destination, .. }
        | DecodedInstruction::SveDuplicateByte { destination, .. }
        | DecodedInstruction::SvePtrueBytesVl16 { destination } => forbidden(&[destination]),
        DecodedInstruction::SveLoadBytes {
            destination,
            predicate,
            ..
        } => forbidden(&[destination, predicate]),
        DecodedInstruction::CompareEqualBytes16 {
            destination,
            left,
            right,
        }
        | DecodedInstruction::AndBytes16 {
            destination,
            left,
            right,
        }
        | DecodedInstruction::UnsignedMaxPairwiseBytes16 {
            destination,
            left,
            right,
        } => forbidden(&[destination, left, right]),
        DecodedInstruction::Sve2MatchBytes {
            destination,
            predicate,
            left,
            right,
        } => forbidden(&[destination, predicate, left, right]),
        DecodedInstruction::UnsignedMinBytes16 {
            destination,
            source,
        }
        | DecodedInstruction::UnsignedMaxBytes16 {
            destination,
            source,
        }
        | DecodedInstruction::ShiftRightNarrowHalfwordsToBytes8 {
            destination,
            source,
        }
        | DecodedInstruction::AddAcrossBytes16 {
            destination,
            source,
        } => forbidden(&[destination, source]),
        DecodedInstruction::MoveVectorByteTo32 { source, .. }
        | DecodedInstruction::MoveVectorDoubleTo64 { source, .. } => forbidden(&[source]),
        DecodedInstruction::SveCountPredicateBytes {
            predicate, source, ..
        } => forbidden(&[predicate, source]),
        _ => None,
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the versioned ASIMD, SVE vector, and SVE predicate ABI policy is kept exhaustive in one gate"
)]
fn first_forbidden_search_vector_register(
    instruction: DecodedInstruction,
    backend_version: BackendVersion,
) -> Option<u8> {
    fn forbidden(registers: &[u8], backend_version: BackendVersion) -> Option<u8> {
        registers.iter().copied().find(|&register| {
            register > 7
                && !(backend_version == BackendVersion::SEARCH_V7 && matches!(register, 16 | 17))
        })
    }
    fn forbidden_predicates(registers: &[u8]) -> Option<u8> {
        registers.iter().copied().find(|&register| register > 3)
    }
    if instruction.is_sve()
        && !matches!(
            backend_version,
            BackendVersion::SEARCH_SVE16_V1 | BackendVersion::SEARCH_SVE2_16_V1
        )
    {
        return Some(0);
    }
    match instruction {
        DecodedInstruction::LoadVector128 { destination, .. }
        | DecodedInstruction::DuplicateByte16 { destination, .. }
        | DecodedInstruction::SveDuplicateByte { destination, .. } => {
            forbidden(&[destination], backend_version)
        }
        DecodedInstruction::CompareEqualBytes16 {
            destination,
            left,
            right,
        }
        | DecodedInstruction::AndBytes16 {
            destination,
            left,
            right,
        }
        | DecodedInstruction::UnsignedMaxPairwiseBytes16 {
            destination,
            left,
            right,
        } => forbidden(&[destination, left, right], backend_version),
        DecodedInstruction::UnsignedMinBytes16 {
            destination,
            source,
        }
        | DecodedInstruction::UnsignedMaxBytes16 {
            destination,
            source,
        }
        | DecodedInstruction::ShiftRightNarrowHalfwordsToBytes8 {
            destination,
            source,
        }
        | DecodedInstruction::AddAcrossBytes16 {
            destination,
            source,
        } => forbidden(&[destination, source], backend_version),
        DecodedInstruction::MoveVectorByteTo32 { source, .. }
        | DecodedInstruction::MoveVectorDoubleTo64 { source, .. } => {
            forbidden(&[source], backend_version)
        }
        DecodedInstruction::SvePtrueBytesVl16 { destination } => {
            forbidden_predicates(&[destination])
        }
        DecodedInstruction::SveLoadBytes {
            destination,
            predicate,
            ..
        } => forbidden(&[destination], backend_version)
            .or_else(|| forbidden_predicates(&[predicate])),
        DecodedInstruction::SveCompareEqualBytes {
            destination,
            predicate,
            left,
            right,
        }
        | DecodedInstruction::Sve2MatchBytes {
            destination,
            predicate,
            left,
            right,
        } => forbidden(&[left, right], backend_version)
            .or_else(|| forbidden_predicates(&[destination, predicate])),
        DecodedInstruction::SveAndPredicateBytes {
            destination,
            predicate,
            left,
            right,
        } => forbidden_predicates(&[destination, predicate, left, right]),
        DecodedInstruction::SveTestPredicateBytes { predicate, tested } => {
            forbidden_predicates(&[predicate, tested])
        }
        DecodedInstruction::SveBreakBeforeBytes {
            destination,
            predicate,
            source,
        } => forbidden_predicates(&[destination, predicate, source]),
        DecodedInstruction::SveCountPredicateBytes {
            predicate, source, ..
        } => forbidden_predicates(&[predicate, source]),
        _ => None,
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "critical-register producer forms are intentionally reviewed in one exhaustive gate"
)]
fn validate_aggregate_critical_write(
    instructions: &[DecodedInstruction],
    index: usize,
    literal_len: usize,
    output: AggregateOutput,
) -> Result<(), AuditError> {
    let instruction = instructions[index];
    let Some(destination) = instruction.written_gpr() else {
        return Ok(());
    };
    let valid = match destination {
        0 => {
            matches!(
                instruction,
                DecodedInstruction::MoveZero64 {
                    destination: 0,
                    immediate: _,
                    shift: 0
                }
            ) && matches!(
                instruction_after(instructions, index, 1),
                Some(DecodedInstruction::Return)
            )
        }
        5 => {
            matches!(
                instruction,
                DecodedInstruction::MoveZero64 {
                    destination: 5,
                    immediate: 0,
                    shift: 0
                } | DecodedInstruction::AddImmediate64 {
                    destination: 5,
                    source: 5,
                    immediate: 1 | 16,
                }
            ) || matches!(
                instruction,
                DecodedInstruction::AddImmediate64 {
                    destination: 5,
                    source: 5,
                    immediate,
                } if usize::from(immediate) == literal_len
            )
        }
        6 => matches!(
            instruction,
            DecodedInstruction::SubtractRegister64 {
                destination: 6,
                left: 1,
                right: 12
            }
        ),
        7 => matches!(
            instruction,
            DecodedInstruction::AddImmediate64 {
                destination: 7,
                source: 5,
                immediate: 15
            } | DecodedInstruction::MoveRegister64 {
                destination: 7,
                source: 6
            }
        ),
        8 => matches!(
            instruction,
            DecodedInstruction::Address { destination: 8, .. }
        ),
        12 => matches!(
            instruction,
            DecodedInstruction::MoveZero64 {
                destination: 12,
                immediate,
                shift: 0
            } if usize::from(immediate) == literal_len
        ),
        13 => valid_aggregate_accumulator_write(instructions, index, literal_len, output),
        14 => matches!(
            instruction,
            DecodedInstruction::MoveRegister64 {
                destination: 14,
                source: 13
            }
        ),
        10 => valid_aggregate_x10_write(instructions, index, literal_len),
        11 => valid_aggregate_x11_write(instructions, index, literal_len),
        15 => matches!(
            instruction,
            DecodedInstruction::AddRegister64 {
                destination: 15,
                left: 0,
                right: 5
            } | DecodedInstruction::MoveRegister64 {
                destination: 15,
                source: 15
            } | DecodedInstruction::AddImmediate64 {
                destination: 15,
                source: 15,
                immediate: 1 | 16
            }
        ),
        16 => matches!(
            instruction,
            DecodedInstruction::MoveRegister64 {
                destination: 16,
                source: 8
            } | DecodedInstruction::AddImmediate64 {
                destination: 16,
                source: 16,
                immediate: 1 | 16
            }
        ),
        17 => {
            matches!(
                instruction,
                DecodedInstruction::MoveZero64 {
                    destination: 17,
                    immediate,
                    shift: 0
                } if usize::from(immediate) == literal_len
            ) || matches!(
                instruction,
                DecodedInstruction::SubtractImmediate64 {
                    destination: 17,
                    source: 17,
                    immediate: 1 | 16
                }
            )
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(AuditError::InvalidAggregateControlFlow {
            offset: instruction_offset(index)?,
        })
    }
}

fn valid_aggregate_x10_write(
    instructions: &[DecodedInstruction],
    index: usize,
    literal_len: usize,
) -> bool {
    let instruction = instructions[index];
    if matches!(
        instruction,
        DecodedInstruction::LoadByte {
            destination: 10,
            ..
        } | DecodedInstruction::LoadByteRegister {
            destination: 10,
            ..
        }
    ) {
        return valid_aggregate_load(instructions, index, literal_len);
    }
    if literal_len == 0
        && matches!(
            instruction,
            DecodedInstruction::MoveZero64 {
                destination: 10,
                immediate: u16::MAX,
                shift: 0
            } | DecodedInstruction::MoveKeep64 {
                destination: 10,
                immediate: u16::MAX,
                shift: 16 | 32 | 48
            }
        )
    {
        return true;
    }
    let last = literal_len
        .checked_sub(1)
        .and_then(|value| u16::try_from(value).ok());
    matches!(
        instruction,
        DecodedInstruction::SubtractRegister64 {
            destination: 10,
            left: 1 | 6,
            right: 5
        } | DecodedInstruction::SubtractRegister64 {
            destination: 10,
            left: 11,
            right: 10
        } | DecodedInstruction::AndLowBits64 {
            destination: 10,
            source: 10,
            bits: 8
        } | DecodedInstruction::MoveVectorByteTo32 {
            destination: 10,
            source: 0 | 4
        } | DecodedInstruction::SveCountPredicateBytes {
            destination: 10,
            predicate: 0,
            source: 1
        }
    ) || matches!(
        instruction,
        DecodedInstruction::AddImmediate64 {
            destination: 10,
            source: 15,
            immediate,
        } if Some(immediate) == last
            && matches!(
                instruction_after(instructions, index, 1),
                Some(DecodedInstruction::LoadVector128 {
                    base: 10,
                    offset: 0,
                    ..
                })
            )
    )
}

fn valid_aggregate_x11_write(
    instructions: &[DecodedInstruction],
    index: usize,
    literal_len: usize,
) -> bool {
    matches!(
        instructions[index],
        DecodedInstruction::MoveZero64 {
            destination: 11,
            immediate: 256,
            shift: 0
        }
    ) || (matches!(
        instructions[index],
        DecodedInstruction::LoadByte {
            destination: 11,
            ..
        }
    ) && valid_aggregate_load(instructions, index, literal_len))
}

fn valid_aggregate_accumulator_write(
    instructions: &[DecodedInstruction],
    index: usize,
    literal_len: usize,
    output: AggregateOutput,
) -> bool {
    let instruction = instructions[index];
    if index == 0
        && matches!(
            instruction,
            DecodedInstruction::MoveZero64 {
                destination: 13,
                immediate: 0,
                shift: 0
            }
        )
    {
        return true;
    }
    if literal_len == 0
        && output == AggregateOutput::Count
        && matches!(
            instruction,
            DecodedInstruction::AddImmediate64 {
                destination: 13,
                source: 1,
                immediate: 1
            }
        )
    {
        return true;
    }
    let expected_delta = match output {
        AggregateOutput::Count => 1,
        AggregateOutput::SpanSum => literal_len,
    };
    let is_accumulation = (literal_len == 1
        && matches!(
            instruction,
            DecodedInstruction::AddRegister64 {
                destination: 13,
                left: 13,
                right: 10
            }
        ))
        || matches!(
            instruction,
            DecodedInstruction::AddImmediate64 {
                destination: 13,
                source: 13,
                immediate,
            } if usize::from(immediate) == expected_delta
        );
    is_accumulation
        && matches!(
            index
                .checked_sub(1)
                .and_then(|prior| instructions.get(prior)),
            Some(DecodedInstruction::MoveRegister64 {
                destination: 14,
                source: 13
            })
        )
        && matches!(
            instruction_after(instructions, index, 1),
            Some(DecodedInstruction::CompareRegister64 {
                left: 13,
                right: 14
            })
        )
        && matches!(
            instruction_after(instructions, index, 2),
            Some(DecodedInstruction::BranchCondition {
                condition: crate::Condition::CarryClear,
                ..
            })
        )
}

fn valid_aggregate_load(
    instructions: &[DecodedInstruction],
    index: usize,
    literal_len: usize,
) -> bool {
    if literal_len == 0 {
        return false;
    }
    let last = literal_len
        .checked_sub(1)
        .and_then(|value| u16::try_from(value).ok())
        .expect("nonempty aggregate literal cap fits u16");
    match instructions[index] {
        DecodedInstruction::LoadByte {
            base: 8 | 15,
            offset: 0,
            ..
        }
        | DecodedInstruction::LoadByte {
            base: 16,
            offset: 0,
            ..
        }
        | DecodedInstruction::LoadByteRegister {
            base: 0, index: 5, ..
        }
        | DecodedInstruction::LoadVector128 {
            base: 15 | 16,
            offset: 0,
            ..
        }
        | DecodedInstruction::SveLoadBytes {
            destination: 0,
            predicate: 0,
            base: 15,
        } => true,
        DecodedInstruction::LoadByte {
            base: 8 | 15,
            offset,
            ..
        } if offset == last => valid_aggregate_last_byte_filter_load(instructions, index, last),
        DecodedInstruction::LoadVector128 {
            base: 10,
            offset: 0,
            ..
        } => matches!(
            index.checked_sub(1).and_then(|prior| instructions.get(prior)),
            Some(DecodedInstruction::AddImmediate64 {
                destination: 10,
                source: 15,
                immediate,
            }) if *immediate == last
        ),
        DecodedInstruction::LoadByte { .. }
        | DecodedInstruction::LoadByteRegister { .. }
        | DecodedInstruction::Load64RegisterScaled { .. }
        | DecodedInstruction::LoadVector128 { .. }
        | DecodedInstruction::SveLoadBytes { .. } => false,
        _ => true,
    }
}

fn valid_aggregate_last_byte_filter_load(
    instructions: &[DecodedInstruction],
    index: usize,
    last: u16,
) -> bool {
    match instructions[index] {
        DecodedInstruction::LoadByte {
            destination: 10,
            base: 15,
            offset,
        } if offset == last => {
            matches!(
                index
                    .checked_sub(1)
                    .and_then(|prior| instructions.get(prior)),
                Some(DecodedInstruction::AddRegister64 {
                    destination: 15,
                    left: 0,
                    right: 5
                })
            ) && matches!(
                instruction_after(instructions, index, 1),
                Some(DecodedInstruction::LoadByte {
                    destination: 11,
                    base: 8,
                    offset
                }) if *offset == last
            ) && matches!(
                instruction_after(instructions, index, 2),
                Some(DecodedInstruction::CompareRegister32 {
                    left: 10,
                    right: 11
                })
            )
        }
        DecodedInstruction::LoadByte {
            destination: 11,
            base: 8,
            offset,
        } if offset == last => {
            let initial_filter = matches!(
                index
                    .checked_sub(2)
                    .and_then(|prior| instructions.get(prior)),
                Some(DecodedInstruction::LoadByte {
                    destination: 11,
                    base: 8,
                    offset: 0
                })
            ) && matches!(
                index
                    .checked_sub(1)
                    .and_then(|prior| instructions.get(prior)),
                Some(DecodedInstruction::DuplicateByte16 {
                    destination: 1,
                    source: 11
                })
            ) && matches!(
                instruction_after(instructions, index, 1),
                Some(DecodedInstruction::DuplicateByte16 {
                    destination: 3,
                    source: 11
                })
            );
            let scalar_filter = matches!(
                index.checked_sub(1).and_then(|prior| instructions.get(prior)),
                Some(DecodedInstruction::LoadByte {
                    destination: 10,
                    base: 15,
                    offset
                }) if *offset == last
            ) && matches!(
                instruction_after(instructions, index, 1),
                Some(DecodedInstruction::CompareRegister32 {
                    left: 10,
                    right: 11
                })
            );
            initial_filter || scalar_filter
        }
        _ => false,
    }
}

fn validate_aggregate_branches(
    instructions: &[DecodedInstruction],
    protected_targets: &[usize],
    literal_len: usize,
) -> Result<(), AuditError> {
    let vector_cursor_guard = unique_vector_cursor_guard(instructions);
    for (index, &instruction) in instructions.iter().enumerate() {
        let (DecodedInstruction::Branch { displacement }
        | DecodedInstruction::BranchCondition { displacement, .. }
        | DecodedInstruction::CompareBranchZero64 { displacement, .. }) = instruction
        else {
            continue;
        };
        let target = aggregate_branch_target(index, displacement, instructions.len())?;
        if protected_targets.contains(&target) {
            return Err(AuditError::InvalidAggregateControlFlow {
                offset: instruction_offset(index)?,
            });
        }
        let valid_edge = match target.cmp(&index) {
            core::cmp::Ordering::Less => {
                valid_aggregate_back_edge(instructions, index, target, vector_cursor_guard)
            }
            core::cmp::Ordering::Greater => {
                valid_aggregate_forward_edge(instructions, index, target, literal_len)
            }
            core::cmp::Ordering::Equal => false,
        };
        if !valid_edge {
            return Err(AuditError::InvalidAggregateControlFlow {
                offset: instruction_offset(index)?,
            });
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the complete aggregate forward-edge template belongs in one auditable allowlist"
)]
fn valid_aggregate_forward_edge(
    instructions: &[DecodedInstruction],
    index: usize,
    target: usize,
    literal_len: usize,
) -> bool {
    let prior = index
        .checked_sub(1)
        .and_then(|value| instructions.get(value));
    let target_instruction = instructions.get(target);
    match instructions[index] {
        DecodedInstruction::Branch { .. } => {
            let finish = matches!(
                prior,
                Some(
                    DecodedInstruction::MoveZero64 {
                        destination: 13,
                        immediate: 0,
                        shift: 0
                    } | DecodedInstruction::AddImmediate64 {
                        destination: 13,
                        source: 1,
                        immediate: 1
                    }
                )
            ) && matches!(
                target_instruction,
                Some(DecodedInstruction::Store64 {
                    source: 13,
                    base: 2,
                    offset: 0
                })
            );
            let enter_scalar_envelope = matches!(
                prior,
                Some(DecodedInstruction::AddImmediate64 {
                    destination: 7,
                    source: 5,
                    immediate: 15
                })
            ) && matches!(
                target_instruction,
                Some(DecodedInstruction::CompareRegister64 { left: 5, right: 7 })
            );
            let enter_confirmation = matches!(
                prior,
                Some(DecodedInstruction::MoveZero64 {
                    destination: 17,
                    immediate,
                    shift: 0
                }) if usize::from(*immediate) == literal_len
            ) && matches!(
                target_instruction,
                Some(DecodedInstruction::CompareBranchZero64 {
                    register: 17,
                    nonzero: false,
                    ..
                })
            );
            finish || enter_scalar_envelope || enter_confirmation
        }
        DecodedInstruction::BranchCondition { condition, .. } => match (prior, condition) {
            (
                Some(DecodedInstruction::CompareRegister64 { left: 1, right: 12 }),
                crate::Condition::CarryClear,
            )
            | (
                Some(DecodedInstruction::CompareRegister64 { left: 5, right: 6 }),
                crate::Condition::Higher,
            )
            | (
                Some(DecodedInstruction::CompareRegister64 { left: 5, right: 1 }),
                crate::Condition::CarrySet,
            ) => matches!(
                target_instruction,
                Some(DecodedInstruction::Store64 {
                    source: 13,
                    base: 2,
                    offset: 0
                })
            ),
            (
                Some(DecodedInstruction::CompareImmediate64 {
                    register: 10,
                    immediate: 16,
                }),
                crate::Condition::CarryClear,
            ) => matches!(
                target_instruction,
                Some(DecodedInstruction::CompareRegister64 { left: 5, right: 1 })
            ),
            (
                Some(DecodedInstruction::CompareImmediate64 {
                    register: 10,
                    immediate: 15,
                }),
                crate::Condition::CarryClear,
            ) => matches!(
                target_instruction,
                Some(DecodedInstruction::MoveRegister64 {
                    destination: 7,
                    source: 6
                })
            ),
            (
                Some(
                    DecodedInstruction::CompareRegister32 {
                        left: 10,
                        right: 11,
                    }
                    | DecodedInstruction::CompareImmediate32 {
                        register: 10,
                        immediate: 255,
                    },
                ),
                crate::Condition::NotEqual,
            ) => matches!(
                target_instruction,
                Some(DecodedInstruction::AddImmediate64 {
                    destination: 5,
                    source: 5,
                    immediate: 1
                })
            ),
            (
                Some(DecodedInstruction::CompareRegister64 {
                    left: 13,
                    right: 14,
                }),
                crate::Condition::CarryClear,
            )
            | (
                Some(DecodedInstruction::CompareRegister64 { left: 1, right: 10 }),
                crate::Condition::Equal,
            ) => matches!(
                target_instruction,
                Some(DecodedInstruction::MoveZero64 {
                    destination: 0,
                    immediate: 1,
                    shift: 0
                })
            ),
            (
                Some(DecodedInstruction::CompareImmediate64 {
                    register: 17,
                    immediate: 16,
                }),
                crate::Condition::CarryClear,
            ) => matches!(
                target_instruction,
                Some(DecodedInstruction::CompareBranchZero64 {
                    register: 17,
                    nonzero: false,
                    ..
                })
            ),
            _ => false,
        },
        DecodedInstruction::CompareBranchZero64 {
            register: 10,
            nonzero: true,
            ..
        } => matches!(
            target_instruction,
            Some(DecodedInstruction::AddImmediate64 {
                destination: 7,
                source: 5,
                immediate: 15
            })
        ),
        DecodedInstruction::CompareBranchZero64 {
            register: 17,
            nonzero: false,
            ..
        } => matches!(
            target_instruction,
            Some(DecodedInstruction::MoveRegister64 {
                destination: 14,
                source: 13
            })
        ),
        _ => false,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InitializedState {
    gpr: u32,
    vector: u32,
    predicate: u16,
}

fn validate_aggregate_definite_initialization(
    instructions: &[DecodedInstruction],
) -> Result<(), AuditError> {
    let mut states = vec![None; instructions.len()];
    let initial = InitializedState {
        gpr: register_mask(&[0, 1, 2]),
        vector: 0,
        predicate: 0,
    };
    states[0] = Some(initial);
    let mut pending = vec![0_usize];
    while let Some(index) = pending.pop() {
        let state = states[index].ok_or(AuditError::InvalidAggregateControlFlow {
            offset: instruction_offset(index)?,
        })?;
        let instruction = instructions[index];
        let required_gpr = aggregate_gpr_reads(instruction);
        let required_vector = aggregate_vector_reads(instruction);
        let required_predicate = aggregate_predicate_reads(instruction);
        if state.gpr & required_gpr != required_gpr
            || state.vector & required_vector != required_vector
            || state.predicate & required_predicate != required_predicate
        {
            return Err(AuditError::InvalidAggregateControlFlow {
                offset: instruction_offset(index)?,
            });
        }
        let mut output = state;
        if let Some(destination) = instruction.written_gpr() {
            output.gpr |= register_mask(&[destination]);
        }
        if let Some(destination) = aggregate_vector_write(instruction) {
            output.vector |= register_mask(&[destination]);
        }
        if let Some(destination) = aggregate_predicate_write(instruction) {
            output.predicate |= predicate_mask(&[destination]);
        }
        let successors = aggregate_successors(instructions, index)?;
        for successor in successors.into_iter().flatten() {
            match states[successor] {
                None => {
                    states[successor] = Some(output);
                    pending.push(successor);
                }
                Some(existing) => {
                    let intersection = InitializedState {
                        gpr: existing.gpr & output.gpr,
                        vector: existing.vector & output.vector,
                        predicate: existing.predicate & output.predicate,
                    };
                    if intersection != existing {
                        states[successor] = Some(intersection);
                        pending.push(successor);
                    }
                }
            }
        }
    }
    Ok(())
}

fn register_mask(registers: &[u8]) -> u32 {
    registers.iter().fold(0_u32, |mask, &register| {
        mask | 1_u32.checked_shl(u32::from(register)).unwrap_or(0)
    })
}

fn predicate_mask(registers: &[u8]) -> u16 {
    registers.iter().fold(0_u16, |mask, &register| {
        mask | 1_u16.checked_shl(u32::from(register)).unwrap_or(0)
    })
}

#[allow(
    clippy::match_same_arms,
    clippy::too_many_lines,
    reason = "exhaustive source-register classification is the security boundary; parallel arms preserve decoded operand roles"
)]
fn aggregate_gpr_reads(instruction: DecodedInstruction) -> u32 {
    match instruction {
        DecodedInstruction::MoveRegister64 { source, .. } => register_mask(&[source]),
        DecodedInstruction::MoveKeep64 { destination, .. } => register_mask(&[destination]),
        DecodedInstruction::CompareRegister64 { left, right }
        | DecodedInstruction::CompareRegister32 { left, right } => register_mask(&[left, right]),
        DecodedInstruction::CompareImmediate64 { register, .. }
        | DecodedInstruction::CompareImmediate32 { register, .. }
        | DecodedInstruction::CompareBranchZero64 { register, .. } => register_mask(&[register]),
        DecodedInstruction::AddRegister64 { left, right, .. }
        | DecodedInstruction::SubtractRegister64 { left, right, .. }
        | DecodedInstruction::AndRegister64 { left, right, .. } => register_mask(&[left, right]),
        DecodedInstruction::AddImmediate64 { source, .. }
        | DecodedInstruction::SubtractImmediate64 { source, .. }
        | DecodedInstruction::AndLowBits64 { source, .. }
        | DecodedInstruction::LogicalShiftRightImmediate64 { source, .. }
        | DecodedInstruction::LogicalShiftLeftImmediate64 { source, .. } => {
            register_mask(&[source])
        }
        DecodedInstruction::ReverseBits64 { source, .. }
        | DecodedInstruction::CountLeadingZeros64 { source, .. } => register_mask(&[source]),
        DecodedInstruction::LoadByte { base, .. }
        | DecodedInstruction::LoadVector128 { base, .. }
        | DecodedInstruction::SveLoadBytes { base, .. } => register_mask(&[base]),
        DecodedInstruction::LoadByteRegister { base, index, .. }
        | DecodedInstruction::Load64RegisterScaled { base, index, .. } => {
            register_mask(&[base, index])
        }
        DecodedInstruction::Store64 { source, base, .. } => register_mask(&[source, base]),
        DecodedInstruction::DuplicateByte16 { source, .. }
        | DecodedInstruction::SveDuplicateByte { source, .. } => register_mask(&[source]),
        DecodedInstruction::LogicalShiftRightVariable64 { source, shift, .. } => {
            register_mask(&[source, shift])
        }
        DecodedInstruction::MoveZero64 { .. }
        | DecodedInstruction::MoveVectorByteTo32 { .. }
        | DecodedInstruction::MoveVectorDoubleTo64 { .. }
        | DecodedInstruction::CompareEqualBytes16 { .. }
        | DecodedInstruction::AndBytes16 { .. }
        | DecodedInstruction::ShiftRightNarrowHalfwordsToBytes8 { .. }
        | DecodedInstruction::UnsignedMinBytes16 { .. }
        | DecodedInstruction::UnsignedMaxBytes16 { .. }
        | DecodedInstruction::UnsignedMaxPairwiseBytes16 { .. }
        | DecodedInstruction::AddAcrossBytes16 { .. }
        | DecodedInstruction::SvePtrueBytesVl16 { .. }
        | DecodedInstruction::SveCompareEqualBytes { .. }
        | DecodedInstruction::Sve2MatchBytes { .. }
        | DecodedInstruction::SveAndPredicateBytes { .. }
        | DecodedInstruction::SveTestPredicateBytes { .. }
        | DecodedInstruction::SveBreakBeforeBytes { .. }
        | DecodedInstruction::SveCountPredicateBytes { .. }
        | DecodedInstruction::Address { .. }
        | DecodedInstruction::Branch { .. }
        | DecodedInstruction::BranchCondition { .. }
        | DecodedInstruction::Return => 0,
    }
}

fn aggregate_vector_reads(instruction: DecodedInstruction) -> u32 {
    match instruction {
        DecodedInstruction::CompareEqualBytes16 { left, right, .. }
        | DecodedInstruction::AndBytes16 { left, right, .. }
        | DecodedInstruction::UnsignedMaxPairwiseBytes16 { left, right, .. }
        | DecodedInstruction::Sve2MatchBytes { left, right, .. } => register_mask(&[left, right]),
        DecodedInstruction::UnsignedMinBytes16 { source, .. }
        | DecodedInstruction::UnsignedMaxBytes16 { source, .. }
        | DecodedInstruction::AddAcrossBytes16 { source, .. }
        | DecodedInstruction::ShiftRightNarrowHalfwordsToBytes8 { source, .. }
        | DecodedInstruction::MoveVectorByteTo32 { source, .. }
        | DecodedInstruction::MoveVectorDoubleTo64 { source, .. } => register_mask(&[source]),
        _ => 0,
    }
}

const fn aggregate_vector_write(instruction: DecodedInstruction) -> Option<u8> {
    match instruction {
        DecodedInstruction::LoadVector128 { destination, .. }
        | DecodedInstruction::DuplicateByte16 { destination, .. }
        | DecodedInstruction::CompareEqualBytes16 { destination, .. }
        | DecodedInstruction::AndBytes16 { destination, .. }
        | DecodedInstruction::UnsignedMinBytes16 { destination, .. }
        | DecodedInstruction::UnsignedMaxBytes16 { destination, .. }
        | DecodedInstruction::UnsignedMaxPairwiseBytes16 { destination, .. }
        | DecodedInstruction::ShiftRightNarrowHalfwordsToBytes8 { destination, .. }
        | DecodedInstruction::AddAcrossBytes16 { destination, .. }
        | DecodedInstruction::SveDuplicateByte { destination, .. }
        | DecodedInstruction::SveLoadBytes { destination, .. } => Some(destination),
        _ => None,
    }
}

fn aggregate_predicate_reads(instruction: DecodedInstruction) -> u16 {
    match instruction {
        DecodedInstruction::SveLoadBytes { predicate, .. }
        | DecodedInstruction::Sve2MatchBytes { predicate, .. } => predicate_mask(&[predicate]),
        DecodedInstruction::SveCountPredicateBytes {
            predicate, source, ..
        } => predicate_mask(&[predicate, source]),
        _ => 0,
    }
}

const fn aggregate_predicate_write(instruction: DecodedInstruction) -> Option<u8> {
    match instruction {
        DecodedInstruction::SvePtrueBytesVl16 { destination }
        | DecodedInstruction::Sve2MatchBytes { destination, .. } => Some(destination),
        _ => None,
    }
}

fn aggregate_successors(
    instructions: &[DecodedInstruction],
    index: usize,
) -> Result<[Option<usize>; 2], AuditError> {
    let next = index.checked_add(1).ok_or(AuditError::ArithmeticOverflow)?;
    match instructions[index] {
        DecodedInstruction::Branch { displacement } => Ok([
            Some(aggregate_branch_target(
                index,
                displacement,
                instructions.len(),
            )?),
            None,
        ]),
        DecodedInstruction::BranchCondition { displacement, .. }
        | DecodedInstruction::CompareBranchZero64 { displacement, .. } => {
            if next >= instructions.len() {
                return Err(AuditError::InvalidAggregateControlFlow {
                    offset: instruction_offset(index)?,
                });
            }
            Ok([
                Some(next),
                Some(aggregate_branch_target(
                    index,
                    displacement,
                    instructions.len(),
                )?),
            ])
        }
        DecodedInstruction::Return => Ok([None, None]),
        _ => {
            if next >= instructions.len() {
                return Err(AuditError::InvalidAggregateControlFlow {
                    offset: instruction_offset(index)?,
                });
            }
            Ok([Some(next), None])
        }
    }
}

fn valid_aggregate_back_edge(
    instructions: &[DecodedInstruction],
    index: usize,
    target: usize,
    vector_cursor_guard: Option<usize>,
) -> bool {
    let prior = index
        .checked_sub(1)
        .and_then(|value| instructions.get(value));
    match instructions[index] {
        DecodedInstruction::Branch { .. } => {
            let cursor_progress = matches!(
                prior,
                Some(DecodedInstruction::AddImmediate64 {
                    destination: 5,
                    source: 5,
                    immediate: 1..=32
                })
            ) && guarded_cursor_loop(instructions, target);
            let confirmation_progress = matches!(
                prior,
                Some(DecodedInstruction::SubtractImmediate64 {
                    destination: 17,
                    source: 17,
                    immediate: 16
                })
            ) && matches!(
                instructions.get(target),
                Some(DecodedInstruction::CompareImmediate64 {
                    register: 17,
                    immediate: 16
                })
            );
            cursor_progress || confirmation_progress
        }
        DecodedInstruction::BranchCondition {
            condition: crate::Condition::Higher,
            ..
        } => {
            matches!(
                prior,
                Some(DecodedInstruction::CompareRegister64 { left: 5, right: 7 })
            ) && vector_cursor_guard == Some(target)
        }
        DecodedInstruction::CompareBranchZero64 {
            register: 17,
            nonzero: true,
            ..
        } => matches!(
            prior,
            Some(DecodedInstruction::SubtractImmediate64 {
                destination: 17,
                source: 17,
                immediate: 1
            })
        ),
        _ => false,
    }
}

fn unique_vector_cursor_guard(instructions: &[DecodedInstruction]) -> Option<usize> {
    let mut guards = instructions
        .iter()
        .enumerate()
        .filter_map(|(index, instruction)| {
            (matches!(
                instruction,
                DecodedInstruction::CompareRegister64 { left: 5, right: 6 }
            ) && matches!(
                instruction_after(instructions, index, 1),
                Some(DecodedInstruction::BranchCondition {
                    condition: crate::Condition::Higher,
                    ..
                })
            ))
            .then_some(index)
        });
    let guard = guards.next()?;
    guards.next().is_none().then_some(guard)
}

fn guarded_cursor_loop(instructions: &[DecodedInstruction], target: usize) -> bool {
    matches!(
        instructions.get(target),
        Some(DecodedInstruction::CompareRegister64 {
            left: 5,
            right: 1 | 6 | 7
        })
    ) && matches!(
        instruction_after(instructions, target, 1),
        Some(DecodedInstruction::BranchCondition {
            condition: crate::Condition::CarrySet | crate::Condition::Higher,
            ..
        })
    )
}

fn aggregate_branch_target(
    index: usize,
    displacement: i32,
    instruction_count: usize,
) -> Result<usize, AuditError> {
    let offset = i64::from(instruction_offset(index)?);
    let target = offset
        .checked_add(i64::from(displacement))
        .ok_or(AuditError::ArithmeticOverflow)?;
    if target < 0 || target % 4 != 0 {
        return Err(AuditError::InvalidAggregateControlFlow {
            offset: instruction_offset(index)?,
        });
    }
    let target = usize::try_from(target / 4).map_err(|_| AuditError::ArithmeticOverflow)?;
    if target >= instruction_count {
        return Err(AuditError::InvalidAggregateControlFlow {
            offset: instruction_offset(index)?,
        });
    }
    Ok(target)
}

fn validate_aggregate_reachability(instructions: &[DecodedInstruction]) -> Result<(), AuditError> {
    let mut reachable = vec![false; instructions.len()];
    let mut pending = vec![0_usize];
    while let Some(index) = pending.pop() {
        if *reachable
            .get(index)
            .ok_or(AuditError::InvalidAggregateControlFlow { offset: u32::MAX })?
        {
            continue;
        }
        reachable[index] = true;
        let mut add_successor = |successor: usize| -> Result<(), AuditError> {
            if successor >= instructions.len() {
                return Err(AuditError::InvalidAggregateControlFlow {
                    offset: instruction_offset(index)?,
                });
            }
            pending.push(successor);
            Ok(())
        };
        match instructions[index] {
            DecodedInstruction::Branch { displacement } => {
                add_successor(aggregate_branch_target(
                    index,
                    displacement,
                    instructions.len(),
                )?)?;
            }
            DecodedInstruction::BranchCondition { displacement, .. }
            | DecodedInstruction::CompareBranchZero64 { displacement, .. } => {
                add_successor(index.checked_add(1).ok_or(AuditError::ArithmeticOverflow)?)?;
                add_successor(aggregate_branch_target(
                    index,
                    displacement,
                    instructions.len(),
                )?)?;
            }
            DecodedInstruction::Return => {}
            _ => add_successor(index.checked_add(1).ok_or(AuditError::ArithmeticOverflow)?)?,
        }
    }
    if let Some(index) = reachable.iter().position(|&value| !value) {
        return Err(AuditError::InvalidAggregateControlFlow {
            offset: instruction_offset(index)?,
        });
    }
    Ok(())
}

fn validate_layout(image: &NativeImage) -> Result<(), AuditError> {
    if image.code.is_empty()
        || !image.code.len().is_multiple_of(4)
        || image.layout.code_alignment != 16
        || image.layout.rodata_alignment != 16
        || !image.layout.rodata_from_code_start.is_multiple_of(16)
    {
        return Err(AuditError::InvalidLayout);
    }
    let code_len = u32::try_from(image.code.len()).map_err(|_| AuditError::InvalidLayout)?;
    if image.layout.rodata_from_code_start < code_len {
        return Err(AuditError::InvalidLayout);
    }
    let data_len = u32::try_from(image.rodata.len()).map_err(|_| AuditError::InvalidLayout)?;
    let total = image
        .layout
        .rodata_from_code_start
        .checked_add(data_len)
        .ok_or(AuditError::ArithmeticOverflow)?;
    if total != image.layout.total_mapped_bytes
        || image.stats.code_bytes != code_len
        || image.stats.data_bytes != data_len
        || usize::try_from(image.stats.relocations).ok() != Some(image.relocations.len())
        || usize::try_from(image.stats.labels).ok() != Some(image.labels.len())
    {
        return Err(AuditError::InvalidLayout);
    }
    Ok(())
}

fn validate_labels(image: &NativeImage) -> Result<(), AuditError> {
    let code_len = u32::try_from(image.code.len()).map_err(|_| AuditError::InvalidLayout)?;
    let mut prior = None;
    let mut entries = 0_u8;
    for label in &image.labels {
        if label.offset >= code_len || label.offset % 4 != 0 {
            return Err(AuditError::InvalidLabel {
                offset: label.offset,
            });
        }
        if prior.is_some_and(|offset| offset > label.offset) {
            return Err(AuditError::InvalidLabel {
                offset: label.offset,
            });
        }
        if label.kind == LabelKind::Entry {
            entries = entries
                .checked_add(1)
                .ok_or(AuditError::ArithmeticOverflow)?;
            if label.offset != 0 {
                return Err(AuditError::InvalidLabel {
                    offset: label.offset,
                });
            }
        }
        prior = Some(label.offset);
    }
    if entries != 1 {
        return Err(AuditError::InvalidLabel { offset: 0 });
    }
    Ok(())
}

fn validate_symbols(image: &NativeImage) -> Result<(), AuditError> {
    let data_len = u32::try_from(image.rodata.len()).map_err(|_| AuditError::InvalidLayout)?;
    for (index, symbol) in image.symbols.iter().enumerate() {
        if symbol.alignment == 0
            || !symbol.alignment.is_power_of_two()
            || !symbol.offset.is_multiple_of(u32::from(symbol.alignment))
            || symbol
                .offset
                .checked_add(symbol.length)
                .is_none_or(|end| end > data_len)
        {
            return Err(AuditError::InvalidDataSymbol {
                id: symbol.ir_data_id,
            });
        }
        for prior in &image.symbols[..index] {
            let prior_end = prior
                .offset
                .checked_add(prior.length)
                .ok_or(AuditError::ArithmeticOverflow)?;
            if symbol.length != 0 && prior.length != 0 && symbol.offset < prior_end {
                return Err(AuditError::OverlappingDataSymbols {
                    first: prior.ir_data_id,
                    second: symbol.ir_data_id,
                });
            }
        }
    }
    Ok(())
}

fn validate_relocation_order(image: &NativeImage) -> Result<(), AuditError> {
    let code_len = u32::try_from(image.code.len()).map_err(|_| AuditError::InvalidLayout)?;
    let mut prior = None;
    for relocation in &image.relocations {
        if relocation.code_offset % 4 != 0
            || relocation
                .code_offset
                .checked_add(4)
                .is_none_or(|end| end > code_len)
        {
            return Err(AuditError::InvalidRelocation {
                offset: relocation.code_offset,
            });
        }
        if prior == Some(relocation.code_offset) {
            return Err(AuditError::OverlappingRelocations {
                offset: relocation.code_offset,
            });
        }
        if prior.is_some_and(|offset| offset > relocation.code_offset) {
            return Err(AuditError::InvalidRelocation {
                offset: relocation.code_offset,
            });
        }
        prior = Some(relocation.code_offset);
    }
    Ok(())
}

const fn validate_word(expected: u32, actual: u32, offset: u32) -> Result<(), AuditError> {
    if expected != actual {
        return Err(AuditError::RelocationWordMismatch { offset });
    }
    Ok(())
}
