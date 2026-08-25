//! Opt-in native first-any-position lowering for an authenticated exact64 set.
//!
//! This artifact is additive and deliberately separate from the complete-mask
//! Exact64 ABI. It accepts only graphs whose independently authenticated exact
//! singleton rows contain no LF byte. On success it returns the final byte of
//! the earliest-completing match in scan order, or [`u64::MAX`] when no row
//! matches. That byte is safe to use as a ripgrep line candidate; it is not a
//! leftmost-first span or a source-pattern priority result.

use core::fmt;

use sha2::{Digest, Sha256};

use crate::{
    Architecture, CallAbi, CompileResource, CompiledModule, CpuFeature, FeatureSet, ObjectError,
    ObjectFormat, OperatingSystem, SectionKind, Target, emit_object,
    regex_set_exact64::{RegexSetExact64Program, RegexSetExact64Receipt},
    regex_set_exact64_aot::{
        DenseBuildDisposition, REGEX_SET_EXACT64_AOT_V1_MAX_ADDRESSABLE_DATA_BYTES,
        RegexSetExact64AotErrorV1, RegexSetExact64AotLimitsV1, RegexSetExact64AotResourceV1,
        RegexSetExact64DenseLayoutV1, build_dense_layout,
    },
};

/// Stable version of the first-any raw entry ABI:
/// `u32 entry(const u8 *, usize, usize, usize, u64 *)`.
pub const REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_ABI_VERSION: u32 = 1;
/// The result word was published successfully.
pub const REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_STATUS_SUCCESS: u32 = 0;
/// A pointer, alignment, extent, or search-window boundary was invalid.
pub const REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_STATUS_INVALID_ARGUMENT: u32 = 2;
/// Successful no-match result. No valid haystack byte has this position.
pub const REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_NO_MATCH: u64 = u64::MAX;
/// The source byte excluded by the line-candidate proof.
pub const REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_LINE_TERMINATOR: u8 = b'\n';
/// Receipt code: final byte of the earliest-completing match in scan order.
pub const REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_POSITION_FINAL_BYTE: u32 = 1;
/// Stable identity domain for the source graph, line proof, target, and data.
pub const REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_IDENTITY_DOMAIN: &[u8] =
    b"fre-aot-regex/regex-set-exact64-first-any-aot-v1\0";

const REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_ARTIFACT_DOMAIN: &[u8] =
    b"fre-aot-regex/regex-set-exact64-first-any-aot-artifact-v1\0";

pub(crate) const REGEX_SET_EXACT64_FIRST_ANY_ROOT_SKIP_VECTOR_BYTES_V1: usize = 16;
const REGEX_SET_EXACT64_FIRST_ANY_ROOT_SKIP_TABLE_BYTES_V1: usize = 64;

/// Canonical ASIMD constants appended after the unchanged dense AC payload.
///
/// The first three vectors are the exact split-nibble membership classifier;
/// the fourth is the lane ramp used to recover the earliest possible start.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RegexSetExact64FirstAnyRootSkipLayoutV1 {
    pub(crate) table_offset: usize,
    pub(crate) table_bytes: usize,
    pub(crate) membership: [u64; 4],
}

/// Auditable authorization to retain the exact target-neutral program.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RegexSetExact64FirstAnyAotDeclineV1 {
    /// One exact source literal contains LF, so a returned hit byte would not
    /// prove line containment.
    SourceContainsLineFeed { pattern: usize },
    /// The target tuple is valid, but this version implements only AArch64.
    UnsupportedArchitecture { actual: Architecture },
    /// One explicit numeric representation ceiling was crossed.
    Resource {
        resource: RegexSetExact64AotResourceV1,
        required: usize,
        limit: usize,
    },
}

impl fmt::Display for RegexSetExact64FirstAnyAotDeclineV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceContainsLineFeed { pattern } => write!(
                formatter,
                "exact64 first-any source row {pattern} contains LF"
            ),
            Self::UnsupportedArchitecture { actual } => write!(
                formatter,
                "exact64 first-any native scan does not support {actual:?}"
            ),
            Self::Resource {
                resource,
                required,
                limit,
            } => write!(
                formatter,
                "exact64 first-any scan needs {required} {resource:?}, limit is {limit}"
            ),
        }
    }
}

impl std::error::Error for RegexSetExact64FirstAnyAotDeclineV1 {}

/// Complete deterministic closure of one selected first-any-position object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegexSetExact64FirstAnyAotReceiptV1 {
    abi_version: u32,
    target: Target,
    source_receipt: RegexSetExact64Receipt,
    line_terminator: u8,
    position_semantics: u32,
    no_match: u64,
    operation_identity_sha256: [u8; 32],
    artifact_identity_sha256: [u8; 32],
    dense_data_sha256: [u8; 32],
    code_sha256: [u8; 32],
    object_sha256: [u8; 32],
    entry_symbol: String,
    state_count: usize,
    dense_transition_cells: usize,
    transition_offset: usize,
    output_offset: usize,
    dense_data_bytes: usize,
    root_skip_table_offset: usize,
    root_skip_table_bytes: usize,
    root_skip_vector_bytes: usize,
    code_bytes: usize,
    object_bytes: usize,
    semantic_runtime_calls: usize,
    limits: RegexSetExact64AotLimitsV1,
}

impl RegexSetExact64FirstAnyAotReceiptV1 {
    #[must_use]
    pub const fn abi_version(&self) -> u32 {
        self.abi_version
    }

    #[must_use]
    pub const fn target(&self) -> Target {
        self.target
    }

    #[must_use]
    pub const fn source_receipt(&self) -> RegexSetExact64Receipt {
        self.source_receipt
    }

    #[must_use]
    pub const fn line_terminator(&self) -> u8 {
        self.line_terminator
    }

    #[must_use]
    pub const fn position_semantics(&self) -> u32 {
        self.position_semantics
    }

    #[must_use]
    pub const fn no_match(&self) -> u64 {
        self.no_match
    }

    #[must_use]
    pub const fn operation_identity_sha256(&self) -> [u8; 32] {
        self.operation_identity_sha256
    }

    #[must_use]
    pub const fn artifact_identity_sha256(&self) -> [u8; 32] {
        self.artifact_identity_sha256
    }

    #[must_use]
    pub const fn dense_data_sha256(&self) -> [u8; 32] {
        self.dense_data_sha256
    }

    #[must_use]
    pub const fn code_sha256(&self) -> [u8; 32] {
        self.code_sha256
    }

    #[must_use]
    pub const fn object_sha256(&self) -> [u8; 32] {
        self.object_sha256
    }

    #[must_use]
    pub fn entry_symbol(&self) -> &str {
        &self.entry_symbol
    }

    #[must_use]
    pub const fn state_count(&self) -> usize {
        self.state_count
    }

    #[must_use]
    pub const fn dense_transition_cells(&self) -> usize {
        self.dense_transition_cells
    }

    #[must_use]
    pub const fn transition_offset(&self) -> usize {
        self.transition_offset
    }

    #[must_use]
    pub const fn output_offset(&self) -> usize {
        self.output_offset
    }

    #[must_use]
    pub const fn dense_data_bytes(&self) -> usize {
        self.dense_data_bytes
    }

    /// Offset of the exact root-skip tables, or zero when this target/cap
    /// retained the scalar V1 scan.
    #[must_use]
    pub const fn root_skip_table_offset(&self) -> usize {
        self.root_skip_table_offset
    }

    /// Immutable bytes used by the exact root-skip classifier.
    #[must_use]
    pub const fn root_skip_table_bytes(&self) -> usize {
        self.root_skip_table_bytes
    }

    /// Number of haystack bytes classified per root-skip vector.
    #[must_use]
    pub const fn root_skip_vector_bytes(&self) -> usize {
        self.root_skip_vector_bytes
    }

    #[must_use]
    pub const fn code_bytes(&self) -> usize {
        self.code_bytes
    }

    #[must_use]
    pub const fn object_bytes(&self) -> usize {
        self.object_bytes
    }

    #[must_use]
    pub const fn semantic_runtime_calls(&self) -> usize {
        self.semantic_runtime_calls
    }

    #[must_use]
    pub const fn limits(&self) -> RegexSetExact64AotLimitsV1 {
        self.limits
    }
}

/// Native first-any object paired with its unchanged semantic owner.
#[derive(Clone, Debug)]
pub struct RegexSetExact64FirstAnyAotArtifactV1 {
    program: RegexSetExact64Program,
    module: CompiledModule,
    object: Vec<u8>,
    receipt: RegexSetExact64FirstAnyAotReceiptV1,
}

impl RegexSetExact64FirstAnyAotArtifactV1 {
    #[must_use]
    pub const fn program(&self) -> &RegexSetExact64Program {
        &self.program
    }

    #[must_use]
    pub const fn module(&self) -> &CompiledModule {
        &self.module
    }

    #[must_use]
    pub fn object(&self) -> &[u8] {
        &self.object
    }

    #[must_use]
    pub const fn receipt(&self) -> &RegexSetExact64FirstAnyAotReceiptV1 {
        &self.receipt
    }

    /// Rebuild and authenticate the LF proof, dense table, code, object, and
    /// every receipt identity.
    #[must_use]
    pub fn authenticates_receipt(&self) -> bool {
        authenticate_artifact(self).is_ok()
    }
}

/// Selected first-any object or the exact portable owner plus a safe decline.
#[derive(Clone, Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "boxing a decline would allocate after the completed exact64 compile transaction"
)]
pub enum RegexSetExact64FirstAnyAotCompileDispositionV1 {
    Selected(RegexSetExact64FirstAnyAotArtifactV1),
    Declined {
        program: RegexSetExact64Program,
        reason: RegexSetExact64FirstAnyAotDeclineV1,
    },
}

impl RegexSetExact64FirstAnyAotCompileDispositionV1 {
    #[must_use]
    pub const fn program(&self) -> &RegexSetExact64Program {
        match self {
            Self::Selected(artifact) => artifact.program(),
            Self::Declined { program, .. } => program,
        }
    }
}

fn arithmetic(computation: &'static str) -> RegexSetExact64AotErrorV1 {
    RegexSetExact64AotErrorV1::ArithmeticOverflow { computation }
}

fn exact_root_skip_table_bytes(membership: [u64; 4]) -> Option<[u8; 64]> {
    let cardinality = membership.iter().try_fold(0_u16, |total, word| {
        total.checked_add(u16::try_from(word.count_ones()).ok()?)
    })?;
    if !(1..=64).contains(&cardinality) {
        return None;
    }
    let mut tables = [0_u8; 64];
    for high in 0_u8..16 {
        let bit = 1_u8 << (high & 7);
        tables[32 + usize::from(high)] = bit;
        for low in 0_u8..16 {
            let byte = (high << 4) | low;
            let byte_index = usize::from(byte);
            if membership[byte_index / 64] & (1_u64 << (byte_index % 64)) != 0 {
                let row = usize::from(high >= 8) * 16 + usize::from(low);
                tables[row] |= bit;
            }
        }
    }
    for lane in 0_u8..16 {
        tables[48 + usize::from(lane)] = lane;
    }
    Some(tables)
}

pub(crate) fn authenticates_exact_root_skip_tables(
    layout: &RegexSetExact64DenseLayoutV1,
    root_skip: RegexSetExact64FirstAnyRootSkipLayoutV1,
) -> bool {
    let output_end = layout
        .state_count
        .checked_mul(core::mem::size_of::<u64>())
        .and_then(|bytes| layout.output_offset.checked_add(bytes));
    let table_end = root_skip.table_offset.checked_add(root_skip.table_bytes);
    output_end.is_some_and(|end| end <= root_skip.table_offset)
        && root_skip.table_offset.is_multiple_of(16)
        && root_skip.table_bytes == REGEX_SET_EXACT64_FIRST_ANY_ROOT_SKIP_TABLE_BYTES_V1
        && table_end == Some(layout.data.len())
        && output_end
            .and_then(|end| layout.data.get(end..root_skip.table_offset))
            .is_some_and(|padding| padding.iter().all(|&byte| byte == 0))
        && exact_root_skip_table_bytes(root_skip.membership).is_some_and(|expected| {
            layout.data.get(root_skip.table_offset..layout.data.len()) == Some(expected.as_slice())
        })
}

fn append_exact_root_skip_tables(
    layout: &mut RegexSetExact64DenseLayoutV1,
    target: Target,
    membership: [u64; 4],
    limits: RegexSetExact64AotLimitsV1,
) -> Result<Option<RegexSetExact64FirstAnyRootSkipLayoutV1>, RegexSetExact64AotErrorV1> {
    if !target
        .features
        .contains(FeatureSet::of(CpuFeature::Aarch64Asimd))
    {
        return Ok(None);
    }
    let tables = exact_root_skip_table_bytes(membership).ok_or(
        RegexSetExact64AotErrorV1::InternalInvariant(
            "exact64 root membership escaped source cardinality",
        ),
    )?;

    let table_offset = layout
        .data
        .len()
        .checked_add(15)
        .ok_or_else(|| arithmetic("first-any root-skip table alignment"))?
        & !15;
    let table_end = table_offset
        .checked_add(REGEX_SET_EXACT64_FIRST_ANY_ROOT_SKIP_TABLE_BYTES_V1)
        .ok_or_else(|| arithmetic("first-any root-skip table extent"))?;
    let addressable_limit =
        usize::try_from(REGEX_SET_EXACT64_AOT_V1_MAX_ADDRESSABLE_DATA_BYTES).unwrap_or(usize::MAX);
    if table_end > limits.max_dense_data_bytes.min(addressable_limit) {
        // This is an optional target-final accelerator. A numeric auxiliary
        // cap retains the already-built, byte-identical scalar dense owner.
        return Ok(None);
    }
    let additional = table_end
        .checked_sub(layout.data.len())
        .ok_or_else(|| arithmetic("first-any root-skip reservation"))?;
    layout.data.try_reserve_exact(additional).map_err(|_| {
        RegexSetExact64AotErrorV1::AllocationFailed {
            structure: "first-any exact root-skip tables",
            entries: additional,
        }
    })?;
    if layout.data.capacity() != table_end {
        return Err(RegexSetExact64AotErrorV1::NonExactCapacity {
            structure: "first-any exact root-skip tables",
            requested: table_end,
            actual: layout.data.capacity(),
        });
    }

    layout.data.resize(table_offset, 0);
    layout.data.extend_from_slice(&tables);
    if layout.data.len() != table_end {
        return Err(RegexSetExact64AotErrorV1::InternalInvariant(
            "first-any exact root-skip table extent changed",
        ));
    }
    let root_skip = RegexSetExact64FirstAnyRootSkipLayoutV1 {
        table_offset,
        table_bytes: REGEX_SET_EXACT64_FIRST_ANY_ROOT_SKIP_TABLE_BYTES_V1,
        membership,
    };
    if !authenticates_exact_root_skip_tables(layout, root_skip) {
        return Err(RegexSetExact64AotErrorV1::InternalInvariant(
            "first-any exact root-skip tables do not authenticate",
        ));
    }
    Ok(Some(root_skip))
}

fn update_usize(
    digest: &mut Sha256,
    value: usize,
    computation: &'static str,
) -> Result<(), RegexSetExact64AotErrorV1> {
    digest.update(
        u64::try_from(value)
            .map_err(|_| arithmetic(computation))?
            .to_le_bytes(),
    );
    Ok(())
}

fn operation_identity(
    target: Target,
    source: RegexSetExact64Receipt,
    dense_data_sha256: [u8; 32],
    layout: &RegexSetExact64DenseLayoutV1,
) -> Result<[u8; 32], RegexSetExact64AotErrorV1> {
    let mut digest = Sha256::new();
    digest.update(REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_IDENTITY_DOMAIN);
    digest.update(REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_ABI_VERSION.to_le_bytes());
    digest.update(REGEX_SET_EXACT64_AOT_V1_MAX_ADDRESSABLE_DATA_BYTES.to_le_bytes());
    digest.update([
        REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_LINE_TERMINATOR,
        match target.architecture {
            Architecture::X86_64 => 1,
            Architecture::Aarch64 => 2,
        },
        match target.operating_system {
            OperatingSystem::Linux => 1,
            OperatingSystem::Macos => 2,
        },
        match target.abi {
            CallAbi::SystemV => 1,
            CallAbi::Aapcs64 => 2,
        },
    ]);
    digest.update(REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_POSITION_FINAL_BYTE.to_le_bytes());
    digest.update(REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_NO_MATCH.to_le_bytes());
    digest.update(target.features.bits().to_le_bytes());
    digest.update(source.source_artifact().as_bytes());
    digest.update(source.artifact_identity().as_bytes());
    digest.update([source.pattern_count()]);
    digest.update(source.all_pattern_mask().to_le_bytes());
    update_usize(
        &mut digest,
        layout.state_count,
        "first-any identity state count",
    )?;
    update_usize(
        &mut digest,
        layout.transition_cells,
        "first-any identity transition cells",
    )?;
    update_usize(
        &mut digest,
        layout.transition_offset,
        "first-any identity transition offset",
    )?;
    update_usize(
        &mut digest,
        layout.output_offset,
        "first-any identity output offset",
    )?;
    update_usize(
        &mut digest,
        layout.data.len(),
        "first-any identity dense data bytes",
    )?;
    digest.update(dense_data_sha256);
    Ok(digest.finalize().into())
}

fn artifact_identity(
    receipt: &RegexSetExact64FirstAnyAotReceiptV1,
) -> Result<[u8; 32], RegexSetExact64AotErrorV1> {
    let mut digest = Sha256::new();
    digest.update(REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_ARTIFACT_DOMAIN);
    digest.update(receipt.operation_identity_sha256);
    digest.update(receipt.dense_data_sha256);
    digest.update(receipt.code_sha256);
    digest.update(receipt.object_sha256);
    update_usize(
        &mut digest,
        receipt.code_bytes,
        "first-any artifact code bytes",
    )?;
    update_usize(
        &mut digest,
        receipt.object_bytes,
        "first-any artifact object bytes",
    )?;
    if receipt.root_skip_table_bytes != 0 {
        update_usize(
            &mut digest,
            receipt.root_skip_table_offset,
            "first-any artifact root-skip table offset",
        )?;
        update_usize(
            &mut digest,
            receipt.root_skip_table_bytes,
            "first-any artifact root-skip table bytes",
        )?;
        update_usize(
            &mut digest,
            receipt.root_skip_vector_bytes,
            "first-any artifact root-skip vector bytes",
        )?;
    }
    update_usize(
        &mut digest,
        receipt.limits.max_dense_transition_cells,
        "first-any artifact transition-cell limit",
    )?;
    update_usize(
        &mut digest,
        receipt.limits.max_dense_data_bytes,
        "first-any artifact data limit",
    )?;
    update_usize(
        &mut digest,
        receipt.limits.max_code_bytes,
        "first-any artifact code limit",
    )?;
    update_usize(
        &mut digest,
        receipt.limits.max_object_bytes,
        "first-any artifact object limit",
    )?;
    Ok(digest.finalize().into())
}

fn module_text(module: &CompiledModule) -> Result<&[u8], RegexSetExact64AotErrorV1> {
    module
        .sections()
        .iter()
        .find(|section| section.kind == SectionKind::Text)
        .map(|section| section.bytes())
        .ok_or(RegexSetExact64AotErrorV1::InternalInvariant(
            "exact64 first-any module has no text section",
        ))
}

fn module_data(module: &CompiledModule) -> Result<&[u8], RegexSetExact64AotErrorV1> {
    module
        .sections()
        .iter()
        .find(|section| section.kind == SectionKind::ReadOnlyData)
        .map(|section| section.bytes())
        .ok_or(RegexSetExact64AotErrorV1::InternalInvariant(
            "exact64 first-any module has no data section",
        ))
}

fn decline(
    program: RegexSetExact64Program,
    reason: RegexSetExact64FirstAnyAotDeclineV1,
) -> RegexSetExact64FirstAnyAotCompileDispositionV1 {
    RegexSetExact64FirstAnyAotCompileDispositionV1::Declined { program, reason }
}

struct BuiltFirstAnyTargetV1 {
    module: CompiledModule,
    object: Vec<u8>,
    root_skip: Option<RegexSetExact64FirstAnyRootSkipLayoutV1>,
    dense_data_sha256: [u8; 32],
    operation_identity_sha256: [u8; 32],
    state_count: usize,
    dense_transition_cells: usize,
    transition_offset: usize,
    output_offset: usize,
    dense_data_bytes: usize,
}

enum FirstAnyTargetBuildDispositionV1 {
    Built(BuiltFirstAnyTargetV1),
    Declined {
        resource: RegexSetExact64AotResourceV1,
        required: usize,
        limit: usize,
    },
}

/// Build the optional target-final leaf while retaining the exact scalar V1
/// artifact as its resource incumbent. Only a proven numeric code/object cap
/// retries without root skip; allocation and every other object failure stay
/// terminal, so the retry cannot allocate after an allocator failure.
fn build_first_any_target_v1(
    program: &RegexSetExact64Program,
    target: Target,
    limits: RegexSetExact64AotLimitsV1,
    root_membership: [u64; 4],
) -> Result<FirstAnyTargetBuildDispositionV1, RegexSetExact64AotErrorV1> {
    let source_receipt = program.receipt();
    let mut allow_root_skip = true;
    loop {
        let mut layout = match build_dense_layout(program, limits)? {
            DenseBuildDisposition::Built(layout) => layout,
            DenseBuildDisposition::Declined {
                resource,
                required,
                limit,
            } => {
                return Ok(FirstAnyTargetBuildDispositionV1::Declined {
                    resource,
                    required,
                    limit,
                });
            }
        };
        let root_skip = if allow_root_skip {
            append_exact_root_skip_tables(&mut layout, target, root_membership, limits)?
        } else {
            None
        };
        let dense_data_sha256: [u8; 32] = Sha256::digest(&layout.data).into();
        let operation_identity_sha256 =
            operation_identity(target, source_receipt, dense_data_sha256, &layout)?;
        let state_count = layout.state_count;
        let dense_transition_cells = layout.transition_cells;
        let transition_offset = layout.transition_offset;
        let output_offset = layout.output_offset;
        let dense_data_bytes = layout.data.len();
        let module = match crate::module::lower_native_regex_set_exact64_first_any_aarch64_v1(
            target,
            operation_identity_sha256,
            source_receipt.artifact_identity(),
            source_receipt.all_pattern_mask(),
            layout,
            root_skip,
            limits.max_code_bytes,
        ) {
            Ok(module) => module,
            Err(ObjectError::Resource {
                resource: CompileResource::CodeBytes,
                ..
            }) if root_skip.is_some() => {
                allow_root_skip = false;
                continue;
            }
            Err(ObjectError::Resource {
                resource: CompileResource::CodeBytes,
                required,
                limit,
            }) => {
                return Ok(FirstAnyTargetBuildDispositionV1::Declined {
                    resource: RegexSetExact64AotResourceV1::CodeBytes,
                    required,
                    limit,
                });
            }
            Err(error) => return Err(error.into()),
        };
        let object = match emit_object(
            &module,
            ObjectFormat::for_target(target),
            limits.max_object_bytes,
        ) {
            Ok(object) => object,
            Err(ObjectError::Resource {
                resource: CompileResource::ObjectBytes,
                ..
            }) if root_skip.is_some() => {
                allow_root_skip = false;
                continue;
            }
            Err(ObjectError::Resource {
                resource: CompileResource::ObjectBytes,
                required,
                limit,
            }) => {
                return Ok(FirstAnyTargetBuildDispositionV1::Declined {
                    resource: RegexSetExact64AotResourceV1::ObjectBytes,
                    required,
                    limit,
                });
            }
            Err(error) => return Err(error.into()),
        };
        return Ok(FirstAnyTargetBuildDispositionV1::Built(
            BuiltFirstAnyTargetV1 {
                module,
                object,
                root_skip,
                dense_data_sha256,
                operation_identity_sha256,
                state_count,
                dense_transition_cells,
                transition_offset,
                output_offset,
                dense_data_bytes,
            },
        ));
    }
}

/// Lower an already-selected exact64 program to a helper-free AArch64
/// first-any-position object.
///
/// The input graph is authenticated before any decline. An LF-containing
/// source, a valid unsupported architecture, or one of the four explicit
/// numeric ceilings returns the identical program unchanged. Allocation,
/// arithmetic, authentication, target incoherence, object, and invariant
/// failures are terminal.
#[allow(
    clippy::too_many_lines,
    reason = "line proof, safe owned declines, object closure, and receipt authentication form one explicit transaction"
)]
pub fn compile_regex_set_exact64_first_any_aot_v1(
    program: RegexSetExact64Program,
    target: Target,
    limits: RegexSetExact64AotLimitsV1,
) -> Result<RegexSetExact64FirstAnyAotCompileDispositionV1, RegexSetExact64AotErrorV1> {
    program.authenticate()?;
    target.validate()?;
    // Scope the authenticated borrow before every safe decline moves the exact
    // same semantic owner back to the caller.
    let (source_with_line_feed, root_membership) = {
        let graph = program.authenticated_graph()?;
        (
            graph.first_source_literal_containing(
                REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_LINE_TERMINATOR,
            )?,
            graph.root_membership(),
        )
    };
    if let Some(pattern) = source_with_line_feed {
        return Ok(decline(
            program,
            RegexSetExact64FirstAnyAotDeclineV1::SourceContainsLineFeed { pattern },
        ));
    }
    if target.architecture != Architecture::Aarch64 {
        return Ok(decline(
            program,
            RegexSetExact64FirstAnyAotDeclineV1::UnsupportedArchitecture {
                actual: target.architecture,
            },
        ));
    }

    let built = match build_first_any_target_v1(&program, target, limits, root_membership)? {
        FirstAnyTargetBuildDispositionV1::Built(built) => built,
        FirstAnyTargetBuildDispositionV1::Declined {
            resource,
            required,
            limit,
        } => {
            return Ok(decline(
                program,
                RegexSetExact64FirstAnyAotDeclineV1::Resource {
                    resource,
                    required,
                    limit,
                },
            ));
        }
    };
    let source_receipt = program.receipt();
    let BuiltFirstAnyTargetV1 {
        module,
        object,
        root_skip,
        dense_data_sha256,
        operation_identity_sha256,
        state_count,
        dense_transition_cells,
        transition_offset,
        output_offset,
        dense_data_bytes,
    } = built;
    let text = module_text(&module)?;
    let code_sha256: [u8; 32] = Sha256::digest(text).into();
    let object_sha256: [u8; 32] = Sha256::digest(&object).into();
    let mut receipt = RegexSetExact64FirstAnyAotReceiptV1 {
        abi_version: REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_ABI_VERSION,
        target,
        source_receipt,
        line_terminator: REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_LINE_TERMINATOR,
        position_semantics: REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_POSITION_FINAL_BYTE,
        no_match: REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_NO_MATCH,
        operation_identity_sha256,
        artifact_identity_sha256: [0; 32],
        dense_data_sha256,
        code_sha256,
        object_sha256,
        entry_symbol: module.entry_symbol().to_owned(),
        state_count,
        dense_transition_cells,
        transition_offset,
        output_offset,
        dense_data_bytes,
        root_skip_table_offset: root_skip.map_or(0, |skip| skip.table_offset),
        root_skip_table_bytes: root_skip.map_or(0, |skip| skip.table_bytes),
        root_skip_vector_bytes: root_skip
            .map_or(0, |_| REGEX_SET_EXACT64_FIRST_ANY_ROOT_SKIP_VECTOR_BYTES_V1),
        code_bytes: text.len(),
        object_bytes: object.len(),
        semantic_runtime_calls: 0,
        limits,
    };
    receipt.artifact_identity_sha256 = artifact_identity(&receipt)?;
    let artifact = RegexSetExact64FirstAnyAotArtifactV1 {
        program,
        module,
        object,
        receipt,
    };
    authenticate_artifact(&artifact)?;
    Ok(RegexSetExact64FirstAnyAotCompileDispositionV1::Selected(
        artifact,
    ))
}

fn authenticate_artifact(
    artifact: &RegexSetExact64FirstAnyAotArtifactV1,
) -> Result<(), RegexSetExact64AotErrorV1> {
    artifact.program.authenticate()?;
    artifact.receipt.target.validate()?;
    if artifact.receipt.target.architecture != Architecture::Aarch64 {
        return Err(RegexSetExact64AotErrorV1::InternalInvariant(
            "selected exact64 first-any artifact is not AArch64",
        ));
    }
    let graph = artifact.program.authenticated_graph()?;
    if graph
        .first_source_literal_containing(REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_LINE_TERMINATOR)?
        .is_some()
    {
        return Err(RegexSetExact64AotErrorV1::InternalInvariant(
            "selected exact64 first-any artifact lost its LF-free proof",
        ));
    }
    let root_membership = graph.root_membership();
    let built = match build_first_any_target_v1(
        &artifact.program,
        artifact.receipt.target,
        artifact.receipt.limits,
        root_membership,
    )? {
        FirstAnyTargetBuildDispositionV1::Built(built) => built,
        FirstAnyTargetBuildDispositionV1::Declined { .. } => {
            return Err(RegexSetExact64AotErrorV1::InternalInvariant(
                "selected exact64 first-any target now declines its frozen limits",
            ));
        }
    };
    let BuiltFirstAnyTargetV1 {
        module: rebuilt,
        object: rebuilt_object,
        root_skip,
        dense_data_sha256,
        operation_identity_sha256,
        state_count,
        dense_transition_cells,
        transition_offset,
        output_offset,
        dense_data_bytes,
    } = built;
    let source_receipt = artifact.program.receipt();
    let text = module_text(&rebuilt)?;
    let data = module_data(&rebuilt)?;
    let code_sha256: [u8; 32] = Sha256::digest(text).into();
    let object_sha256: [u8; 32] = Sha256::digest(&rebuilt_object).into();
    let receipt = &artifact.receipt;
    let source_state_count = usize::try_from(source_receipt.state_count())
        .map_err(|_| arithmetic("first-any source receipt state count"))?;
    if receipt.abi_version != REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_ABI_VERSION
        || receipt.target != artifact.module.target()
        || receipt.source_receipt != source_receipt
        || receipt.line_terminator != REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_LINE_TERMINATOR
        || receipt.position_semantics != REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_POSITION_FINAL_BYTE
        || receipt.no_match != REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_NO_MATCH
        || receipt.operation_identity_sha256 != operation_identity_sha256
        || receipt.dense_data_sha256 != dense_data_sha256
        || receipt.code_sha256 != code_sha256
        || receipt.object_sha256 != object_sha256
        || receipt.entry_symbol != rebuilt.entry_symbol()
        || receipt.state_count != state_count
        || receipt.state_count != source_state_count
        || receipt.dense_transition_cells != dense_transition_cells
        || receipt.transition_offset != transition_offset
        || receipt.output_offset != output_offset
        || receipt.dense_data_bytes != dense_data_bytes
        || receipt.dense_data_bytes != data.len()
        || receipt.root_skip_table_offset != root_skip.map_or(0, |skip| skip.table_offset)
        || receipt.root_skip_table_bytes != root_skip.map_or(0, |skip| skip.table_bytes)
        || receipt.root_skip_vector_bytes
            != root_skip.map_or(0, |_| REGEX_SET_EXACT64_FIRST_ANY_ROOT_SKIP_VECTOR_BYTES_V1)
        || receipt.code_bytes != text.len()
        || receipt.object_bytes != rebuilt_object.len()
        || receipt.semantic_runtime_calls != 0
        || receipt.artifact_identity_sha256 != artifact_identity(receipt)?
        || artifact.module != rebuilt
        || artifact.object.as_slice() != rebuilt_object.as_slice()
        || module_data(&artifact.module)? != data
        || artifact.module.required_runtime_symbols().next().is_some()
        || artifact.module.required_runtime_program().is_some()
    {
        return Err(RegexSetExact64AotErrorV1::InternalInvariant(
            "deterministic exact64 first-any artifact closure",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn read_dense_u32(data: &[u8], offset: usize) -> Result<u32, RegexSetExact64AotErrorV1> {
    let end = offset
        .checked_add(core::mem::size_of::<u32>())
        .ok_or_else(|| arithmetic("first-any interpreter transition extent"))?;
    data.get(offset..end)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_le_bytes)
        .ok_or(RegexSetExact64AotErrorV1::InternalInvariant(
            "first-any interpreter transition is outside dense data",
        ))
}

#[cfg(test)]
fn interpret_dense_first_any(
    layout: &RegexSetExact64DenseLayoutV1,
    haystack: &[u8],
    start: usize,
    end: usize,
    output: &mut u64,
) -> Result<(), RegexSetExact64AotErrorV1> {
    if start > end || end > haystack.len() {
        return Err(RegexSetExact64AotErrorV1::InternalInvariant(
            "first-any interpreter window",
        ));
    }
    let mut state = 0_usize;
    let mut result = REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_NO_MATCH;
    for (position, &byte) in haystack[start..end].iter().enumerate() {
        let cell = state
            .checked_mul(256)
            .and_then(|cell| cell.checked_add(usize::from(byte)))
            .and_then(|cell| cell.checked_mul(4))
            .and_then(|bytes| layout.transition_offset.checked_add(bytes))
            .ok_or_else(|| arithmetic("first-any interpreter transition offset"))?;
        state = usize::try_from(read_dense_u32(&layout.data, cell)?)
            .map_err(|_| arithmetic("first-any interpreter state"))?;
        let output_offset = state
            .checked_mul(8)
            .and_then(|bytes| layout.output_offset.checked_add(bytes))
            .ok_or_else(|| arithmetic("first-any interpreter output offset"))?;
        let output_end = output_offset
            .checked_add(8)
            .ok_or_else(|| arithmetic("first-any interpreter output extent"))?;
        let mask = layout
            .data
            .get(output_offset..output_end)
            .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
            .map(u64::from_le_bytes)
            .ok_or(RegexSetExact64AotErrorV1::InternalInvariant(
                "first-any interpreter output is outside dense data",
            ))?;
        if mask != 0 {
            let absolute = start
                .checked_add(position)
                .ok_or_else(|| arithmetic("first-any interpreter absolute position"))?;
            result =
                u64::try_from(absolute).map_err(|_| arithmetic("first-any interpreter result"))?;
            break;
        }
    }
    *output = result;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CompileMode, CpuFeature, FeatureSet, RegexSetCompileRequest,
        RegexSetExact64CompileDisposition, RegexSetExact64Limits, StartAccelerator,
        compile_regex_set_exact64_aot_v1, compile_regex_set_exact64_reported,
    };

    fn selected(patterns: &[&str]) -> RegexSetExact64Program {
        let request = RegexSetCompileRequest::new(
            patterns
                .iter()
                .map(|pattern| (*pattern).to_owned())
                .collect(),
        )
        .mode(CompileMode::Optimizing);
        match compile_regex_set_exact64_reported(request, RegexSetExact64Limits::default())
            .expect("exact64 compile")
        {
            RegexSetExact64CompileDisposition::Selected(program) => program,
            RegexSetExact64CompileDisposition::Declined { reason, .. } => {
                panic!("unexpected exact64 decline: {reason}")
            }
        }
    }

    fn selected_artifact(patterns: &[&str]) -> RegexSetExact64FirstAnyAotArtifactV1 {
        selected_artifact_for_target(patterns, Target::aarch64_linux())
    }

    fn selected_artifact_for_target(
        patterns: &[&str],
        target: Target,
    ) -> RegexSetExact64FirstAnyAotArtifactV1 {
        match compile_regex_set_exact64_first_any_aot_v1(
            selected(patterns),
            target,
            RegexSetExact64AotLimitsV1::default(),
        )
        .expect("first-any compile")
        {
            RegexSetExact64FirstAnyAotCompileDispositionV1::Selected(artifact) => artifact,
            RegexSetExact64FirstAnyAotCompileDispositionV1::Declined { reason, .. } => {
                panic!("unexpected first-any decline: {reason}")
            }
        }
    }

    fn asimd_linux_target() -> Target {
        Target::aarch64_linux()
            .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
            .expect("valid ASIMD target")
    }

    #[test]
    fn exact_root_skip_tables_classify_every_byte_without_false_candidates() {
        let membership = [
            0x8000_0000_0000_0001,
            0x0000_0000_0000_0080,
            0x0100_0000_0000_0000,
            0x4000_0000_0000_0002,
        ];
        let tables = exact_root_skip_table_bytes(membership).expect("valid root set");
        for byte in u8::MIN..=u8::MAX {
            let high = byte >> 4;
            let row = usize::from(byte >= 0x80) * 16 + usize::from(byte & 0x0f);
            let actual = tables[row] & tables[32 + usize::from(high)] != 0;
            let byte_index = usize::from(byte);
            let expected = membership[byte_index / 64] & (1_u64 << (byte_index % 64)) != 0;
            assert_eq!(expected, actual, "classification changed byte {byte:#04x}");
        }
        assert_eq!(&tables[48..], &(0_u8..16).collect::<Vec<_>>());
    }

    #[test]
    fn explicit_asimd_target_installs_authenticated_exact_root_skip() {
        let artifact = selected_artifact_for_target(
            &["alpha", "bravo", "cider", "delta", "echo"],
            asimd_linux_target(),
        );
        let receipt = artifact.receipt();
        assert!(artifact.authenticates_receipt());
        assert_eq!(64, receipt.root_skip_table_bytes());
        assert_eq!(16, receipt.root_skip_vector_bytes());
        assert!(receipt.root_skip_table_offset() > receipt.output_offset());
        assert_eq!(
            StartAccelerator::Aarch64Asimd,
            artifact.module().start_accelerator()
        );
        assert_eq!(6, artifact.module().relocations().len());

        let words = module_text(artifact.module())
            .expect("root-skip text")
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(<[u8; 4]>::try_from(bytes).unwrap()))
            .collect::<Vec<_>>();
        assert!(words.contains(&0x4e15_0216)); // TBL V22.16B, {V16.16B}, V21.16B
        assert!(words.contains(&0x6e30_ab07)); // UMAXV B7, V24.16B
        assert!(words.contains(&0x6f09_0707)); // USHR V7.16B, V24.16B, #7
        assert!(words.contains(&0x4e31_b8e7)); // ADDV B7, V7.16B
        assert!(words.contains(&0x6e31_ab18)); // UMINV B24, V24.16B
        assert!(
            words
                .iter()
                .all(|instruction| instruction & 0xfc00_0000 != 0x9400_0000),
            "root skip remains helper-free"
        );
    }

    #[test]
    fn dense_root_backoff_has_one_incumbent_shaped_scalar_loop() {
        let artifact = selected_artifact_for_target(
            &["alpha", "bravo", "cider", "delta", "echo"],
            asimd_linux_target(),
        );
        let words = module_text(artifact.module())
            .expect("root-skip text")
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(<[u8; 4]>::try_from(bytes).unwrap()))
            .collect::<Vec<_>>();
        // The first LDRB owns an isolated possible root. The second begins
        // the dense scalar backoff and must loop directly to itself, rather
        // than returning through the vector classifier after every byte.
        let scalar_loads = words
            .iter()
            .enumerate()
            .filter_map(|(index, &instruction)| (instruction == 0x3840_14a9).then_some(index))
            .collect::<Vec<_>>();
        assert_eq!(2, scalar_loads.len());
        let dense_scan = scalar_loads[1];
        assert_eq!(Some(&0xeb0f_00bf), words.get(dense_scan + 6)); // CMP X5, X15
        let branch = *words.get(dense_scan + 7).expect("dense loop branch");
        assert_eq!(0x5400_0003, branch & 0xff00_001f); // B.LO
        let encoded = i32::try_from((branch >> 5) & 0x7ffff).expect("B.LO immediate");
        let displacement = (encoded << 13) >> 13;
        let target = isize::try_from(dense_scan + 7)
            .expect("dense branch index")
            .checked_add(isize::try_from(displacement).expect("dense branch displacement"))
            .and_then(|target| usize::try_from(target).ok())
            .expect("dense branch target");
        assert_eq!(dense_scan, target);
    }

    #[test]
    fn root_skip_numeric_cap_restores_exact_scalar_module() {
        let patterns = ["alpha", "bravo", "cider", "delta"];
        let target = asimd_linux_target();
        let program = selected(&patterns);
        let source_receipt = program.receipt();
        let layout = match build_dense_layout(&program, RegexSetExact64AotLimitsV1::default())
            .expect("dense layout")
        {
            DenseBuildDisposition::Built(layout) => layout,
            DenseBuildDisposition::Declined { .. } => panic!("dense fixture declined"),
        };
        let dense_bytes = layout.data.len();
        let limits = RegexSetExact64AotLimitsV1 {
            max_dense_data_bytes: dense_bytes,
            ..RegexSetExact64AotLimitsV1::default()
        };
        let artifact = match compile_regex_set_exact64_first_any_aot_v1(program, target, limits)
            .expect("capped first-any compile")
        {
            RegexSetExact64FirstAnyAotCompileDispositionV1::Selected(artifact) => artifact,
            RegexSetExact64FirstAnyAotCompileDispositionV1::Declined { reason, .. } => {
                panic!("dense incumbent declined: {reason}")
            }
        };
        assert_eq!(0, artifact.receipt().root_skip_table_bytes());
        assert_eq!(
            StartAccelerator::None,
            artifact.module().start_accelerator()
        );
        assert!(artifact.authenticates_receipt());

        let dense_sha256: [u8; 32] = Sha256::digest(&layout.data).into();
        let identity = operation_identity(target, source_receipt, dense_sha256, &layout)
            .expect("scalar identity");
        let expected = crate::module::lower_native_regex_set_exact64_first_any_aarch64_v1(
            target,
            identity,
            source_receipt.artifact_identity(),
            source_receipt.all_pattern_mask(),
            layout,
            None,
            limits.max_code_bytes,
        )
        .expect("scalar module");
        assert_eq!(&expected, artifact.module());
    }

    #[test]
    fn root_skip_code_and_object_caps_restore_exact_scalar_incumbent() {
        let patterns = ["alpha", "bravo", "cider", "delta"];
        let target = asimd_linux_target();
        let program = selected(&patterns);
        let dense_bytes = match build_dense_layout(&program, RegexSetExact64AotLimitsV1::default())
            .expect("dense layout")
        {
            DenseBuildDisposition::Built(layout) => layout.data.len(),
            DenseBuildDisposition::Declined { .. } => panic!("dense fixture declined"),
        };
        let scalar = match compile_regex_set_exact64_first_any_aot_v1(
            program,
            target,
            RegexSetExact64AotLimitsV1 {
                max_dense_data_bytes: dense_bytes,
                ..RegexSetExact64AotLimitsV1::default()
            },
        )
        .expect("scalar compile")
        {
            RegexSetExact64FirstAnyAotCompileDispositionV1::Selected(artifact) => artifact,
            RegexSetExact64FirstAnyAotCompileDispositionV1::Declined { reason, .. } => {
                panic!("scalar incumbent declined: {reason}")
            }
        };
        let accelerated = selected_artifact_for_target(&patterns, target);
        assert!(accelerated.receipt().code_bytes() > scalar.receipt().code_bytes());
        assert!(accelerated.receipt().object_bytes() > scalar.receipt().object_bytes());

        for limits in [
            RegexSetExact64AotLimitsV1 {
                max_code_bytes: scalar.receipt().code_bytes(),
                ..RegexSetExact64AotLimitsV1::default()
            },
            RegexSetExact64AotLimitsV1 {
                max_object_bytes: scalar.receipt().object_bytes(),
                ..RegexSetExact64AotLimitsV1::default()
            },
        ] {
            let artifact = match compile_regex_set_exact64_first_any_aot_v1(
                selected(&patterns),
                target,
                limits,
            )
            .expect("capped compile")
            {
                RegexSetExact64FirstAnyAotCompileDispositionV1::Selected(artifact) => artifact,
                RegexSetExact64FirstAnyAotCompileDispositionV1::Declined { reason, .. } => {
                    panic!("accelerator cap bypassed scalar incumbent: {reason}")
                }
            };
            assert_eq!(0, artifact.receipt().root_skip_table_bytes());
            assert_eq!(
                StartAccelerator::None,
                artifact.module().start_accelerator()
            );
            assert_eq!(scalar.module(), artifact.module());
            assert_eq!(scalar.object(), artifact.object());
            assert!(artifact.authenticates_receipt());
        }
    }

    #[test]
    fn public_first_hit_is_earliest_completion_not_leftmost_start() {
        let program = selected(&["abcd", "c", "zz"]);
        let layout = match build_dense_layout(&program, RegexSetExact64AotLimitsV1::default())
            .expect("dense layout")
        {
            DenseBuildDisposition::Built(layout) => layout,
            DenseBuildDisposition::Declined { .. } => panic!("public layout declined"),
        };
        let mut output = 0;
        interpret_dense_first_any(&layout, b"--abcd--", 0, 8, &mut output)
            .expect("first-any interpretation");
        assert_eq!(
            4, output,
            "`c` completes before the earlier-starting `abcd`"
        );

        interpret_dense_first_any(&layout, b"--abcd--", 5, 8, &mut output).expect("negative tail");
        assert_eq!(REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_NO_MATCH, output);

        interpret_dense_first_any(&layout, b"xxc", 2, 3, &mut output).expect("nonzero-window hit");
        assert_eq!(2, output, "positions are relative to the original haystack");
    }

    #[test]
    fn dense_interpreter_is_transactional_on_invalid_window() {
        let program = selected(&["alpha", "beta"]);
        let layout = match build_dense_layout(&program, RegexSetExact64AotLimitsV1::default())
            .expect("dense layout")
        {
            DenseBuildDisposition::Built(layout) => layout,
            DenseBuildDisposition::Declined { .. } => panic!("public layout declined"),
        };
        let sentinel = 0xfeed_face_dead_beef;
        let mut output = sentinel;
        assert!(interpret_dense_first_any(&layout, b"alpha", 4, 6, &mut output).is_err());
        assert_eq!(sentinel, output);
    }

    #[test]
    fn lf_source_declines_with_identical_program_owner() {
        // The regex spelling contains an escape rather than a literal source
        // LF. Admission follows the authenticated exact proof bytes.
        let program = selected(&["alpha", r"line\nbreak", "omega"]);
        let source = program.receipt();
        let fallback = program.fallback().artifact_identity();
        match compile_regex_set_exact64_first_any_aot_v1(
            program,
            Target::aarch64_linux(),
            RegexSetExact64AotLimitsV1::default(),
        )
        .expect("safe LF decline")
        {
            RegexSetExact64FirstAnyAotCompileDispositionV1::Declined {
                program,
                reason: RegexSetExact64FirstAnyAotDeclineV1::SourceContainsLineFeed { pattern: 1 },
            } => {
                assert_eq!(source, program.receipt());
                assert_eq!(fallback, program.fallback().artifact_identity());
            }
            other => panic!("unexpected LF disposition: {other:?}"),
        }
    }

    #[test]
    fn lf_proof_does_not_reject_a_literal_backslash_n() {
        let artifact = selected_artifact(&[r"literal\\ntext", "omega"]);
        assert!(artifact.authenticates_receipt());
    }

    #[test]
    fn unsupported_target_and_resource_caps_are_safe_declines() {
        let program = selected(&["alpha", "beta"]);
        let source = program.receipt();
        match compile_regex_set_exact64_first_any_aot_v1(
            program,
            Target::x86_64_linux(),
            RegexSetExact64AotLimitsV1::default(),
        )
        .expect("safe architecture decline")
        {
            RegexSetExact64FirstAnyAotCompileDispositionV1::Declined {
                program,
                reason:
                    RegexSetExact64FirstAnyAotDeclineV1::UnsupportedArchitecture {
                        actual: Architecture::X86_64,
                    },
            } => assert_eq!(source, program.receipt()),
            other => panic!("unexpected architecture disposition: {other:?}"),
        }

        for (resource, limits) in [
            (
                RegexSetExact64AotResourceV1::DenseTransitionCells,
                RegexSetExact64AotLimitsV1 {
                    max_dense_transition_cells: 0,
                    ..RegexSetExact64AotLimitsV1::default()
                },
            ),
            (
                RegexSetExact64AotResourceV1::DenseDataBytes,
                RegexSetExact64AotLimitsV1 {
                    max_dense_data_bytes: 0,
                    ..RegexSetExact64AotLimitsV1::default()
                },
            ),
            (
                RegexSetExact64AotResourceV1::CodeBytes,
                RegexSetExact64AotLimitsV1 {
                    max_code_bytes: 0,
                    ..RegexSetExact64AotLimitsV1::default()
                },
            ),
            (
                RegexSetExact64AotResourceV1::ObjectBytes,
                RegexSetExact64AotLimitsV1 {
                    max_object_bytes: 0,
                    ..RegexSetExact64AotLimitsV1::default()
                },
            ),
        ] {
            match compile_regex_set_exact64_first_any_aot_v1(
                selected(&["alpha", "beta"]),
                Target::aarch64_linux(),
                limits,
            )
            .expect("safe resource decline")
            {
                RegexSetExact64FirstAnyAotCompileDispositionV1::Declined {
                    program,
                    reason:
                        RegexSetExact64FirstAnyAotDeclineV1::Resource {
                            resource: actual,
                            required,
                            limit: 0,
                        },
                } => {
                    assert_eq!(resource, actual);
                    assert_ne!(0, required);
                    assert_eq!(source, program.receipt());
                }
                other => panic!("unexpected resource disposition: {other:?}"),
            }
        }
    }

    #[test]
    fn incoherent_target_is_terminal_before_any_safe_decline() {
        let target = Target {
            architecture: Architecture::Aarch64,
            operating_system: OperatingSystem::Linux,
            abi: CallAbi::SystemV,
            features: FeatureSet::EMPTY,
        };
        assert!(matches!(
            compile_regex_set_exact64_first_any_aot_v1(
                selected(&[r"line\nbreak", "omega"]),
                target,
                RegexSetExact64AotLimitsV1::default(),
            ),
            Err(RegexSetExact64AotErrorV1::Object(
                ObjectError::UnsupportedTarget
            ))
        ));
    }

    #[test]
    fn first_any_receipt_is_closed_and_distinct_from_mask_v1() {
        let patterns = ["he", "she", "hers", "he", "e"];
        let first_any = selected_artifact(&patterns);
        assert!(first_any.authenticates_receipt());
        assert_eq!(
            REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_ABI_VERSION,
            first_any.receipt().abi_version()
        );
        assert_eq!(
            REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_LINE_TERMINATOR,
            first_any.receipt().line_terminator()
        );
        assert_eq!(
            REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_POSITION_FINAL_BYTE,
            first_any.receipt().position_semantics()
        );
        assert_eq!(
            REGEX_SET_EXACT64_FIRST_ANY_AOT_V1_NO_MATCH,
            first_any.receipt().no_match()
        );
        assert_eq!(0, first_any.receipt().semantic_runtime_calls());
        assert!(
            first_any
                .module()
                .required_runtime_symbols()
                .next()
                .is_none()
        );
        assert!(first_any.module().required_runtime_program().is_none());

        let mask = match compile_regex_set_exact64_aot_v1(
            selected(&patterns),
            Target::aarch64_linux(),
            RegexSetExact64AotLimitsV1::default(),
        )
        .expect("mask compile")
        {
            crate::RegexSetExact64AotCompileDispositionV1::Selected(artifact) => artifact,
            crate::RegexSetExact64AotCompileDispositionV1::Declined { reason, .. } => {
                panic!("mask declined: {reason}")
            }
        };
        assert!(mask.authenticates_receipt());
        assert_ne!(
            first_any.module().entry_symbol(),
            mask.module().entry_symbol()
        );
        assert_ne!(first_any.object(), mask.object());

        let mut object_tamper = first_any.clone();
        object_tamper.object[0] ^= 1;
        assert!(!object_tamper.authenticates_receipt());

        let mut receipt_tamper = first_any;
        receipt_tamper.receipt.position_semantics ^= 1;
        assert!(!receipt_tamper.authenticates_receipt());
    }

    #[test]
    fn first_any_text_has_one_publication_store_and_no_helper_call() {
        let artifact = selected_artifact(&["alpha", "beta", "gamma"]);
        let words = module_text(artifact.module())
            .expect("first-any text")
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(<[u8; 4]>::try_from(bytes).unwrap()))
            .collect::<Vec<_>>();
        let stores = words
            .iter()
            .copied()
            .filter(|instruction| instruction & 0xffc0_0000 == 0xf900_0000)
            .collect::<Vec<_>>();
        assert_eq!(vec![0xf900_0087], stores, "STR X7, [X4] is the only store");
        assert!(
            words
                .iter()
                .all(|instruction| instruction & 0xfc00_0000 != 0x9400_0000),
            "helper-free first-any scan has no BL instruction"
        );
    }

    #[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "macos")))]
    #[test]
    #[ignore = "links and executes the first-any object on an AArch64 host"]
    #[allow(
        clippy::too_many_lines,
        reason = "the linked public differential keeps every-window semantics and raw output transaction checks together"
    )]
    fn linked_host_aarch64_matches_dense_oracle_and_preserves_invalid_output() {
        use std::{fmt::Write as _, fs, process::Command};

        let target = if cfg!(target_os = "linux") {
            Target::aarch64_linux()
        } else {
            Target::aarch64_macos()
        }
        .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
        .expect("host ASIMD target");
        let artifact = match compile_regex_set_exact64_first_any_aot_v1(
            selected(&["abcd", "c", "he", "she", "zz"]),
            target,
            RegexSetExact64AotLimitsV1::default(),
        )
        .expect("native first-any compile")
        {
            RegexSetExact64FirstAnyAotCompileDispositionV1::Selected(artifact) => artifact,
            RegexSetExact64FirstAnyAotCompileDispositionV1::Declined { reason, .. } => {
                panic!("unexpected native first-any decline: {reason}")
            }
        };
        let layout =
            match build_dense_layout(artifact.program(), RegexSetExact64AotLimitsV1::default())
                .expect("first-any oracle layout")
            {
                DenseBuildDisposition::Built(layout) => layout,
                DenseBuildDisposition::Declined { .. } => panic!("first-any oracle declined"),
            };
        let directory = std::env::temp_dir().join(format!(
            "fre-aot-regex-set-exact64-first-any-aarch64-{}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("create first-any linked fixture directory");
        let object = directory.join("regex_set_exact64_first_any.o");
        fs::write(&object, artifact.object()).expect("write first-any object");
        let symbol = artifact.module().entry_symbol();
        let mut source = format!(
            "#include <stdint.h>\n#include <stddef.h>\nextern uint32_t {symbol}(const unsigned char*,size_t,size_t,size_t,uint64_t*);\n"
        );
        let mut calls = String::from(
            "int main(void){uint64_t r;size_t i,j,k;uint32_t s;const uint64_t sentinel=UINT64_C(0xfeedfacedeadbeef);\n",
        );
        let haystacks = [
            b"".as_slice(),
            b"--abcd--".as_slice(),
            b"ushers".as_slice(),
            b"nothing".as_slice(),
            b"she-abcd-zz".as_slice(),
        ];
        for (haystack_index, haystack) in haystacks.iter().enumerate() {
            let bytes = if haystack.is_empty() {
                "0".to_owned()
            } else {
                haystack
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            };
            writeln!(
                source,
                "static const unsigned char h{haystack_index}[]={{{bytes}}};"
            )
            .unwrap();
            let mut expected = Vec::new();
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let mut output = 0;
                    interpret_dense_first_any(&layout, haystack, start, end, &mut output)
                        .expect("first-any oracle");
                    expected.push(format!("UINT64_C(0x{output:016x})"));
                }
            }
            writeln!(
                source,
                "static const uint64_t e{haystack_index}[]={{{}}};",
                expected.join(",")
            )
            .unwrap();
            writeln!(
                calls,
                "k=0;for(i=0;i<={0};i++)for(j=i;j<={0};j++){{r=sentinel;s={symbol}(h{haystack_index},{0},i,j,&r);if(s!=0||r!=e{haystack_index}[k++])return {1};}}",
                haystack.len(),
                haystack_index
                    .checked_add(10)
                    .expect("first-any fixture failure code")
            )
            .unwrap();
        }
        // Exercise the ASIMD dense-root backoff itself. The short exhaustive
        // fixtures above never reach one complete classifier vector.
        let dense_negative = (0..4096)
            .map(|index| b"ahsz"[index % 4])
            .collect::<Vec<_>>();
        let mut dense_late_positive = dense_negative.clone();
        dense_late_positive[4094..].copy_from_slice(b"he");
        for (name, haystack, failure) in [
            ("dense_negative", dense_negative.as_slice(), 70),
            ("dense_late_positive", dense_late_positive.as_slice(), 71),
        ] {
            let bytes = haystack
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            writeln!(source, "static const unsigned char {name}[]={{{bytes}}};").unwrap();
            let mut expected = 0;
            interpret_dense_first_any(&layout, haystack, 0, haystack.len(), &mut expected)
                .expect("dense-root first-any oracle");
            writeln!(
                calls,
                "r=sentinel;s={symbol}({name},{},0,{},&r);if(s!=0||r!=UINT64_C(0x{expected:016x}))return {failure};",
                haystack.len(),
                haystack.len()
            )
            .unwrap();
        }
        writeln!(
            calls,
            "r=sentinel;s={symbol}(h1,8,2,1,&r);if(s!=2||r!=sentinel)return 80;"
        )
        .unwrap();
        writeln!(
            calls,
            "r=sentinel;s={symbol}(h1,8,0,9,&r);if(s!=2||r!=sentinel)return 81;"
        )
        .unwrap();
        writeln!(
            calls,
            "s={symbol}(h1,8,0,8,(uint64_t*)0);if(s!=2)return 82;"
        )
        .unwrap();
        writeln!(
            calls,
            "r=sentinel;s={symbol}((const unsigned char*)0,0,0,0,&r);if(s!=0||r!=UINT64_MAX)return 83;"
        )
        .unwrap();
        writeln!(
            calls,
            "r=sentinel;s={symbol}((const unsigned char*)0,1,0,0,&r);if(s!=2||r!=sentinel)return 84;"
        )
        .unwrap();
        writeln!(
            calls,
            "r=sentinel;s={symbol}(h1,8,0,8,(uint64_t*)((unsigned char*)&r+1));if(s!=2||r!=sentinel)return 85;"
        )
        .unwrap();
        calls.push_str("return 0;}\n");
        source.push_str(&calls);
        let c_path = directory.join("regex_set_exact64_first_any.c");
        fs::write(&c_path, source).expect("write first-any linked harness");
        let executable = directory.join("regex_set_exact64_first_any");
        let compiler = if cfg!(target_os = "macos") {
            "clang"
        } else {
            "cc"
        };
        let link = Command::new(compiler)
            .arg("-O0")
            .arg(&c_path)
            .arg(&object)
            .arg("-o")
            .arg(&executable)
            .output()
            .expect("invoke host C compiler");
        assert!(
            link.status.success(),
            "link status={:?} stdout={} stderr={}",
            link.status.code(),
            String::from_utf8_lossy(&link.stdout),
            String::from_utf8_lossy(&link.stderr)
        );
        let run = Command::new(&executable)
            .output()
            .expect("execute first-any linked fixture");
        assert!(
            run.status.success(),
            "run status={:?} stdout={} stderr={}",
            run.status.code(),
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );
    }
}
