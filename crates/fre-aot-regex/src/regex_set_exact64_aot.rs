//! Opt-in native lowering for an authenticated exact64 regex-set graph.
//!
//! The target-neutral [`crate::RegexSetExact64Program`] remains the complete
//! semantic owner. This layer consumes that already-selected program by value
//! and either returns it unchanged with an auditable safe decline or seals a
//! deterministic dense Aho-Corasick table into one helper-free AArch64 object.
//! No existing regex-set compiler entry calls this lowering implicitly.

use core::fmt;

use sha2::{Digest, Sha256};

use crate::{
    Architecture, CallAbi, CompileResource, CompiledModule, ObjectError, ObjectFormat,
    OperatingSystem, SectionKind, Target, emit_object,
    regex_set_exact64::{
        RegexSetExact64AuthenticationError, RegexSetExact64GraphView, RegexSetExact64Program,
        RegexSetExact64Receipt,
    },
};

/// Stable native entry ABI:
/// `u32 entry(const u8 *, usize, usize, usize, u64 *)`.
pub const REGEX_SET_EXACT64_AOT_V1_ABI_VERSION: u32 = 1;
/// The output word was published successfully.
pub const REGEX_SET_EXACT64_AOT_V1_STATUS_SUCCESS: u32 = 0;
/// A pointer, alignment, extent, or search-window boundary was invalid.
pub const REGEX_SET_EXACT64_AOT_V1_STATUS_INVALID_ARGUMENT: u32 = 2;
/// Dense transition alphabet cardinality. Exact byte semantics require all
/// byte values rather than a source-derived partial alphabet.
pub const REGEX_SET_EXACT64_AOT_V1_ALPHABET_LEN: usize = 256;
/// Largest immutable data extent admitted by the scalar AArch64 ADRP/ADD
/// addressing model, independent of a caller-raised data ceiling. Keeping the
/// public bound below one signed half-range also leaves placement headroom for
/// the text section and its alignment.
pub const REGEX_SET_EXACT64_AOT_V1_MAX_ADDRESSABLE_DATA_BYTES: u64 = 2_147_483_647;
/// Stable identity domain for the source graph, target, and dense data.
pub const REGEX_SET_EXACT64_AOT_V1_IDENTITY_DOMAIN: &[u8] =
    b"fre-aot-regex/regex-set-exact64-aot-v1\0";

const REGEX_SET_EXACT64_AOT_V1_ARTIFACT_DOMAIN: &[u8] =
    b"fre-aot-regex/regex-set-exact64-aot-artifact-v1\0";
const GRAPH_IDENTITY_BYTES: usize = 32;

/// Independent numeric ceilings for the opt-in native lowering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegexSetExact64AotLimitsV1 {
    /// Maximum `state_count * 256` dense transition cells.
    pub max_dense_transition_cells: usize,
    /// Maximum immutable graph identity, dense table, and output-mask bytes.
    pub max_dense_data_bytes: usize,
    /// Maximum generated entry text bytes.
    pub max_code_bytes: usize,
    /// Maximum serialized relocatable object bytes.
    pub max_object_bytes: usize,
}

impl Default for RegexSetExact64AotLimitsV1 {
    fn default() -> Self {
        Self {
            max_dense_transition_cells: 4 * 1_024 * 1_024,
            max_dense_data_bytes: 32 * 1_024 * 1_024,
            max_code_bytes: 64 * 1_024,
            max_object_bytes: 64 * 1_024 * 1_024,
        }
    }
}

/// Explicit native representation whose numeric ceiling may retain the
/// already-compiled portable exact64 program.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RegexSetExact64AotResourceV1 {
    DenseTransitionCells,
    DenseDataBytes,
    CodeBytes,
    ObjectBytes,
}

/// Auditable authorization to retain the exact input program unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RegexSetExact64AotDeclineV1 {
    /// The target tuple is valid, but this first lowering implements only
    /// scalar AArch64. An incoherent target is a terminal error instead.
    UnsupportedArchitecture { actual: Architecture },
    /// One explicit numeric representation ceiling was crossed.
    Resource {
        resource: RegexSetExact64AotResourceV1,
        required: usize,
        limit: usize,
    },
}

impl fmt::Display for RegexSetExact64AotDeclineV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedArchitecture { actual } => {
                write!(
                    formatter,
                    "exact64 native set scan does not support {actual:?}"
                )
            }
            Self::Resource {
                resource,
                required,
                limit,
            } => write!(
                formatter,
                "exact64 native set scan needs {required} {resource:?}, limit is {limit}"
            ),
        }
    }
}

impl std::error::Error for RegexSetExact64AotDeclineV1 {}

/// Complete deterministic closure of one selected native set scan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegexSetExact64AotReceiptV1 {
    abi_version: u32,
    target: Target,
    source_receipt: RegexSetExact64Receipt,
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
    code_bytes: usize,
    object_bytes: usize,
    semantic_runtime_calls: usize,
    limits: RegexSetExact64AotLimitsV1,
}

impl RegexSetExact64AotReceiptV1 {
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

/// Native module/object paired with its unchanged target-neutral semantic
/// owner.
#[derive(Clone, Debug)]
pub struct RegexSetExact64AotArtifactV1 {
    program: RegexSetExact64Program,
    module: CompiledModule,
    object: Vec<u8>,
    receipt: RegexSetExact64AotReceiptV1,
}

impl RegexSetExact64AotArtifactV1 {
    /// The exact program supplied to the opt-in lowering.
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
    pub const fn receipt(&self) -> &RegexSetExact64AotReceiptV1 {
        &self.receipt
    }

    /// Deterministically rebuild and authenticate the graph, dense table,
    /// code, relocations, object, and receipt.
    #[must_use]
    pub fn authenticates_receipt(&self) -> bool {
        authenticate_artifact(self).is_ok()
    }
}

/// Selected AArch64 object or the exact portable owner plus a safe decline.
#[derive(Clone, Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "boxing a decline would allocate after the completed portable compile transaction"
)]
pub enum RegexSetExact64AotCompileDispositionV1 {
    Selected(RegexSetExact64AotArtifactV1),
    Declined {
        program: RegexSetExact64Program,
        reason: RegexSetExact64AotDeclineV1,
    },
}

impl RegexSetExact64AotCompileDispositionV1 {
    /// Return the authoritative portable program in either outcome.
    #[must_use]
    pub const fn program(&self) -> &RegexSetExact64Program {
        match self {
            Self::Selected(artifact) => artifact.program(),
            Self::Declined { program, .. } => program,
        }
    }
}

/// Terminal failure of native exact64 construction. These errors never
/// authorize replacement of the input program with a different fallback.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RegexSetExact64AotErrorV1 {
    Authentication(RegexSetExact64AuthenticationError),
    Object(ObjectError),
    AllocationFailed {
        structure: &'static str,
        entries: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    NonExactCapacity {
        structure: &'static str,
        requested: usize,
        actual: usize,
    },
    InternalInvariant(&'static str),
}

impl fmt::Display for RegexSetExact64AotErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authentication(source) => {
                write!(formatter, "exact64 native source authentication: {source}")
            }
            Self::Object(source) => write!(formatter, "exact64 native object: {source}"),
            Self::AllocationFailed { structure, entries } => write!(
                formatter,
                "exact64 native construction could not reserve {entries} entries for {structure}"
            ),
            Self::ArithmeticOverflow { computation } => {
                write!(
                    formatter,
                    "exact64 native arithmetic overflow computing {computation}"
                )
            }
            Self::NonExactCapacity {
                structure,
                requested,
                actual,
            } => write!(
                formatter,
                "exact64 native {structure} capacity is {actual}, requested exactly {requested}"
            ),
            Self::InternalInvariant(detail) => {
                write!(formatter, "exact64 native invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for RegexSetExact64AotErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Authentication(source) => Some(source),
            Self::Object(source) => Some(source),
            Self::AllocationFailed { .. }
            | Self::ArithmeticOverflow { .. }
            | Self::NonExactCapacity { .. }
            | Self::InternalInvariant(_) => None,
        }
    }
}

impl From<RegexSetExact64AuthenticationError> for RegexSetExact64AotErrorV1 {
    fn from(value: RegexSetExact64AuthenticationError) -> Self {
        Self::Authentication(value)
    }
}

impl From<ObjectError> for RegexSetExact64AotErrorV1 {
    fn from(value: ObjectError) -> Self {
        Self::Object(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DenseGeometry {
    state_count: usize,
    transition_cells: usize,
    transition_offset: usize,
    output_offset: usize,
    data_bytes: usize,
}

#[derive(Debug)]
pub(crate) struct RegexSetExact64DenseLayoutV1 {
    pub(crate) data: Vec<u8>,
    pub(crate) state_count: usize,
    pub(crate) transition_cells: usize,
    pub(crate) transition_offset: usize,
    pub(crate) output_offset: usize,
}

pub(crate) enum DenseBuildDisposition {
    Built(RegexSetExact64DenseLayoutV1),
    Declined {
        resource: RegexSetExact64AotResourceV1,
        required: usize,
        limit: usize,
    },
}

fn arithmetic(computation: &'static str) -> RegexSetExact64AotErrorV1 {
    RegexSetExact64AotErrorV1::ArithmeticOverflow { computation }
}

fn dense_geometry(
    graph: &RegexSetExact64GraphView<'_>,
) -> Result<DenseGeometry, RegexSetExact64AotErrorV1> {
    let state_count = graph.state_count();
    let transition_cells = state_count
        .checked_mul(REGEX_SET_EXACT64_AOT_V1_ALPHABET_LEN)
        .ok_or_else(|| arithmetic("dense transition cell count"))?;
    let transition_bytes = transition_cells
        .checked_mul(core::mem::size_of::<u32>())
        .ok_or_else(|| arithmetic("dense transition bytes"))?;
    let transition_offset = GRAPH_IDENTITY_BYTES;
    let transition_end = transition_offset
        .checked_add(transition_bytes)
        .ok_or_else(|| arithmetic("dense transition extent"))?;
    let output_offset = transition_end
        .checked_add(7)
        .map(|offset| offset & !7)
        .ok_or_else(|| arithmetic("dense output alignment"))?;
    let output_bytes = state_count
        .checked_mul(core::mem::size_of::<u64>())
        .ok_or_else(|| arithmetic("dense output bytes"))?;
    let data_bytes = output_offset
        .checked_add(output_bytes)
        .ok_or_else(|| arithmetic("dense data extent"))?;
    Ok(DenseGeometry {
        state_count,
        transition_cells,
        transition_offset,
        output_offset,
        data_bytes,
    })
}

fn write_u32(data: &mut [u8], offset: usize, value: u32) -> Result<(), RegexSetExact64AotErrorV1> {
    let end = offset
        .checked_add(core::mem::size_of::<u32>())
        .ok_or_else(|| arithmetic("dense transition write extent"))?;
    data.get_mut(offset..end)
        .ok_or(RegexSetExact64AotErrorV1::InternalInvariant(
            "dense transition write is outside its allocation",
        ))?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, RegexSetExact64AotErrorV1> {
    let end = offset
        .checked_add(core::mem::size_of::<u32>())
        .ok_or_else(|| arithmetic("dense transition read extent"))?;
    data.get(offset..end)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_le_bytes)
        .ok_or(RegexSetExact64AotErrorV1::InternalInvariant(
            "dense transition read is outside its allocation",
        ))
}

fn transition_offset(
    geometry: DenseGeometry,
    state: usize,
    byte: u8,
) -> Result<usize, RegexSetExact64AotErrorV1> {
    state
        .checked_mul(REGEX_SET_EXACT64_AOT_V1_ALPHABET_LEN)
        .and_then(|cell| cell.checked_add(usize::from(byte)))
        .and_then(|cell| cell.checked_mul(core::mem::size_of::<u32>()))
        .and_then(|bytes| geometry.transition_offset.checked_add(bytes))
        .ok_or_else(|| arithmetic("dense transition cell offset"))
}

#[allow(
    clippy::too_many_lines,
    reason = "one authenticated depth order, complete dense transition closure, and output publication table form a single fail-closed construction transaction"
)]
pub(crate) fn build_dense_layout(
    program: &RegexSetExact64Program,
    limits: RegexSetExact64AotLimitsV1,
) -> Result<DenseBuildDisposition, RegexSetExact64AotErrorV1> {
    let graph = program.authenticated_graph()?;
    let geometry = dense_geometry(&graph)?;
    if geometry.transition_cells > limits.max_dense_transition_cells {
        return Ok(DenseBuildDisposition::Declined {
            resource: RegexSetExact64AotResourceV1::DenseTransitionCells,
            required: geometry.transition_cells,
            limit: limits.max_dense_transition_cells,
        });
    }
    let addressable_data_limit =
        usize::try_from(REGEX_SET_EXACT64_AOT_V1_MAX_ADDRESSABLE_DATA_BYTES).unwrap_or(usize::MAX);
    let effective_data_limit = limits.max_dense_data_bytes.min(addressable_data_limit);
    if geometry.data_bytes > effective_data_limit {
        return Ok(DenseBuildDisposition::Declined {
            resource: RegexSetExact64AotResourceV1::DenseDataBytes,
            required: geometry.data_bytes,
            limit: effective_data_limit,
        });
    }

    let mut data = Vec::new();
    data.try_reserve_exact(geometry.data_bytes).map_err(|_| {
        RegexSetExact64AotErrorV1::AllocationFailed {
            structure: "dense AC data",
            entries: geometry.data_bytes,
        }
    })?;
    if data.capacity() != geometry.data_bytes {
        return Err(RegexSetExact64AotErrorV1::NonExactCapacity {
            structure: "dense AC data",
            requested: geometry.data_bytes,
            actual: data.capacity(),
        });
    }
    data.resize(geometry.data_bytes, 0);
    data.get_mut(..GRAPH_IDENTITY_BYTES)
        .ok_or(RegexSetExact64AotErrorV1::InternalInvariant(
            "dense AC data omitted its graph identity",
        ))?
        .copy_from_slice(graph.receipt().artifact_identity().as_bytes());

    let mut depth_order = Vec::new();
    depth_order
        .try_reserve_exact(geometry.state_count)
        .map_err(|_| RegexSetExact64AotErrorV1::AllocationFailed {
            structure: "dense AC depth order",
            entries: geometry.state_count,
        })?;
    for state in 0..geometry.state_count {
        if graph.state_depth(state).is_none()
            || graph.failure_state(state).is_none()
            || graph.output_mask(state).is_none()
        {
            return Err(RegexSetExact64AotErrorV1::InternalInvariant(
                "authenticated graph lost one indexed state",
            ));
        }
        depth_order.push(state);
    }
    depth_order.sort_unstable_by_key(|&state| graph.state_depth(state).unwrap_or(u32::MAX));
    if depth_order.first().copied() != Some(0) {
        return Err(RegexSetExact64AotErrorV1::InternalInvariant(
            "authenticated root is not the unique minimum-depth state",
        ));
    }

    for state in depth_order {
        let depth =
            graph
                .state_depth(state)
                .ok_or(RegexSetExact64AotErrorV1::InternalInvariant(
                    "dense state depth disappeared",
                ))?;
        let failure = usize::try_from(graph.failure_state(state).ok_or(
            RegexSetExact64AotErrorV1::InternalInvariant("dense failure state disappeared"),
        )?)
        .map_err(|_| arithmetic("dense failure state index"))?;
        if failure >= geometry.state_count {
            return Err(RegexSetExact64AotErrorV1::InternalInvariant(
                "dense failure state is outside the graph",
            ));
        }
        if state != 0
            && graph
                .state_depth(failure)
                .is_none_or(|failure_depth| failure_depth >= depth)
        {
            return Err(RegexSetExact64AotErrorV1::InternalInvariant(
                "dense failure row was not completed first",
            ));
        }
        for byte in u8::MIN..=u8::MAX {
            let target = if let Some(target) = graph.direct_transition(state, byte) {
                target
            } else if state == 0 {
                0
            } else {
                read_u32(&data, transition_offset(geometry, failure, byte)?)?
            };
            if usize::try_from(target).map_or(true, |target| target >= geometry.state_count) {
                return Err(RegexSetExact64AotErrorV1::InternalInvariant(
                    "dense transition target is outside the graph",
                ));
            }
            write_u32(&mut data, transition_offset(geometry, state, byte)?, target)?;
        }
        let output =
            graph
                .output_mask(state)
                .ok_or(RegexSetExact64AotErrorV1::InternalInvariant(
                    "dense output mask disappeared",
                ))?;
        let output_offset = state
            .checked_mul(core::mem::size_of::<u64>())
            .and_then(|bytes| geometry.output_offset.checked_add(bytes))
            .ok_or_else(|| arithmetic("dense output offset"))?;
        let output_end = output_offset
            .checked_add(core::mem::size_of::<u64>())
            .ok_or_else(|| arithmetic("dense output extent"))?;
        data.get_mut(output_offset..output_end)
            .ok_or(RegexSetExact64AotErrorV1::InternalInvariant(
                "dense output write is outside its allocation",
            ))?
            .copy_from_slice(&output.to_le_bytes());
    }

    Ok(DenseBuildDisposition::Built(RegexSetExact64DenseLayoutV1 {
        data,
        state_count: geometry.state_count,
        transition_cells: geometry.transition_cells,
        transition_offset: geometry.transition_offset,
        output_offset: geometry.output_offset,
    }))
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
    digest.update(REGEX_SET_EXACT64_AOT_V1_IDENTITY_DOMAIN);
    digest.update(REGEX_SET_EXACT64_AOT_V1_ABI_VERSION.to_le_bytes());
    digest.update(REGEX_SET_EXACT64_AOT_V1_MAX_ADDRESSABLE_DATA_BYTES.to_le_bytes());
    digest.update([
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
    digest.update(target.features.bits().to_le_bytes());
    digest.update(source.source_artifact().as_bytes());
    digest.update(source.artifact_identity().as_bytes());
    digest.update([source.pattern_count()]);
    digest.update(source.all_pattern_mask().to_le_bytes());
    update_usize(&mut digest, layout.state_count, "identity state count")?;
    update_usize(
        &mut digest,
        layout.transition_cells,
        "identity transition cells",
    )?;
    update_usize(
        &mut digest,
        layout.transition_offset,
        "identity transition offset",
    )?;
    update_usize(&mut digest, layout.output_offset, "identity output offset")?;
    update_usize(&mut digest, layout.data.len(), "identity dense data bytes")?;
    digest.update(dense_data_sha256);
    Ok(digest.finalize().into())
}

fn artifact_identity(
    receipt: &RegexSetExact64AotReceiptV1,
) -> Result<[u8; 32], RegexSetExact64AotErrorV1> {
    let mut digest = Sha256::new();
    digest.update(REGEX_SET_EXACT64_AOT_V1_ARTIFACT_DOMAIN);
    digest.update(receipt.operation_identity_sha256);
    digest.update(receipt.dense_data_sha256);
    digest.update(receipt.code_sha256);
    digest.update(receipt.object_sha256);
    update_usize(&mut digest, receipt.code_bytes, "artifact code bytes")?;
    update_usize(&mut digest, receipt.object_bytes, "artifact object bytes")?;
    update_usize(
        &mut digest,
        receipt.limits.max_dense_transition_cells,
        "artifact transition-cell limit",
    )?;
    update_usize(
        &mut digest,
        receipt.limits.max_dense_data_bytes,
        "artifact data limit",
    )?;
    update_usize(
        &mut digest,
        receipt.limits.max_code_bytes,
        "artifact code limit",
    )?;
    update_usize(
        &mut digest,
        receipt.limits.max_object_bytes,
        "artifact object limit",
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
            "native exact64 module has no text section",
        ))
}

fn module_data(module: &CompiledModule) -> Result<&[u8], RegexSetExact64AotErrorV1> {
    module
        .sections()
        .iter()
        .find(|section| section.kind == SectionKind::ReadOnlyData)
        .map(|section| section.bytes())
        .ok_or(RegexSetExact64AotErrorV1::InternalInvariant(
            "native exact64 module has no data section",
        ))
}

fn decline(
    program: RegexSetExact64Program,
    reason: RegexSetExact64AotDeclineV1,
) -> RegexSetExact64AotCompileDispositionV1 {
    RegexSetExact64AotCompileDispositionV1::Declined { program, reason }
}

fn map_lowering_resource(
    error: ObjectError,
) -> Result<RegexSetExact64AotDeclineV1, RegexSetExact64AotErrorV1> {
    match error {
        ObjectError::Resource {
            resource: CompileResource::CodeBytes,
            limit,
            required,
        } => Ok(RegexSetExact64AotDeclineV1::Resource {
            resource: RegexSetExact64AotResourceV1::CodeBytes,
            required,
            limit,
        }),
        other => Err(other.into()),
    }
}

/// Lower one already-selected exact64 program into a helper-free AArch64
/// object. The input program is authenticated before any decline is returned.
///
/// Default regex-set compilation remains unchanged. Allocation, arithmetic,
/// malformed target/module, graph authentication, and serialization failures
/// are terminal. Only a valid unsupported architecture and the four explicit
/// numeric ceilings can return `Declined`.
#[allow(
    clippy::too_many_lines,
    reason = "safe declines must retain the same owned portable program across dense data, code, and final-object boundaries"
)]
pub fn compile_regex_set_exact64_aot_v1(
    program: RegexSetExact64Program,
    target: Target,
    limits: RegexSetExact64AotLimitsV1,
) -> Result<RegexSetExact64AotCompileDispositionV1, RegexSetExact64AotErrorV1> {
    program.authenticate()?;
    target.validate()?;
    if target.architecture != Architecture::Aarch64 {
        return Ok(decline(
            program,
            RegexSetExact64AotDeclineV1::UnsupportedArchitecture {
                actual: target.architecture,
            },
        ));
    }

    let layout = match build_dense_layout(&program, limits)? {
        DenseBuildDisposition::Built(layout) => layout,
        DenseBuildDisposition::Declined {
            resource,
            required,
            limit,
        } => {
            return Ok(decline(
                program,
                RegexSetExact64AotDeclineV1::Resource {
                    resource,
                    required,
                    limit,
                },
            ));
        }
    };
    let source_receipt = program.receipt();
    let dense_data_sha256: [u8; 32] = Sha256::digest(&layout.data).into();
    let operation_identity_sha256 =
        operation_identity(target, source_receipt, dense_data_sha256, &layout)?;
    let state_count = layout.state_count;
    let dense_transition_cells = layout.transition_cells;
    let transition_offset = layout.transition_offset;
    let output_offset = layout.output_offset;
    let dense_data_bytes = layout.data.len();
    let module = match crate::module::lower_native_regex_set_exact64_aarch64_v1(
        target,
        operation_identity_sha256,
        source_receipt.artifact_identity(),
        source_receipt.all_pattern_mask(),
        layout,
        limits.max_code_bytes,
    ) {
        Ok(module) => module,
        Err(error @ ObjectError::Resource { .. }) => {
            return Ok(decline(program, map_lowering_resource(error)?));
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
            limit,
            required,
        }) => {
            return Ok(decline(
                program,
                RegexSetExact64AotDeclineV1::Resource {
                    resource: RegexSetExact64AotResourceV1::ObjectBytes,
                    required,
                    limit,
                },
            ));
        }
        Err(error) => return Err(error.into()),
    };
    let text = module_text(&module)?;
    let code_sha256: [u8; 32] = Sha256::digest(text).into();
    let object_sha256: [u8; 32] = Sha256::digest(&object).into();
    let mut receipt = RegexSetExact64AotReceiptV1 {
        abi_version: REGEX_SET_EXACT64_AOT_V1_ABI_VERSION,
        target,
        source_receipt,
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
        code_bytes: text.len(),
        object_bytes: object.len(),
        semantic_runtime_calls: 0,
        limits,
    };
    receipt.artifact_identity_sha256 = artifact_identity(&receipt)?;
    let artifact = RegexSetExact64AotArtifactV1 {
        program,
        module,
        object,
        receipt,
    };
    authenticate_artifact(&artifact)?;
    Ok(RegexSetExact64AotCompileDispositionV1::Selected(artifact))
}

fn authenticate_artifact(
    artifact: &RegexSetExact64AotArtifactV1,
) -> Result<(), RegexSetExact64AotErrorV1> {
    artifact.program.authenticate()?;
    artifact.receipt.target.validate()?;
    if artifact.receipt.target.architecture != Architecture::Aarch64 {
        return Err(RegexSetExact64AotErrorV1::InternalInvariant(
            "selected exact64 artifact is not AArch64",
        ));
    }
    let layout = match build_dense_layout(&artifact.program, artifact.receipt.limits)? {
        DenseBuildDisposition::Built(layout) => layout,
        DenseBuildDisposition::Declined { .. } => {
            return Err(RegexSetExact64AotErrorV1::InternalInvariant(
                "selected exact64 dense layout now declines its frozen limits",
            ));
        }
    };
    let source_receipt = artifact.program.receipt();
    let dense_data_sha256: [u8; 32] = Sha256::digest(&layout.data).into();
    let operation_identity_sha256 = operation_identity(
        artifact.receipt.target,
        source_receipt,
        dense_data_sha256,
        &layout,
    )?;
    let state_count = layout.state_count;
    let dense_transition_cells = layout.transition_cells;
    let transition_offset = layout.transition_offset;
    let output_offset = layout.output_offset;
    let dense_data_bytes = layout.data.len();
    let rebuilt = crate::module::lower_native_regex_set_exact64_aarch64_v1(
        artifact.receipt.target,
        operation_identity_sha256,
        source_receipt.artifact_identity(),
        source_receipt.all_pattern_mask(),
        layout,
        artifact.receipt.limits.max_code_bytes,
    )?;
    let rebuilt_object = emit_object(
        &rebuilt,
        ObjectFormat::for_target(artifact.receipt.target),
        artifact.receipt.limits.max_object_bytes,
    )?;
    let text = module_text(&rebuilt)?;
    let data = module_data(&rebuilt)?;
    let code_sha256: [u8; 32] = Sha256::digest(text).into();
    let object_sha256: [u8; 32] = Sha256::digest(&rebuilt_object).into();
    let receipt = &artifact.receipt;
    let source_state_count = usize::try_from(source_receipt.state_count())
        .map_err(|_| arithmetic("source receipt state count"))?;
    if receipt.abi_version != REGEX_SET_EXACT64_AOT_V1_ABI_VERSION
        || receipt.target != artifact.module.target()
        || receipt.source_receipt != source_receipt
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
            "deterministic exact64 native artifact closure",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn interpret_dense(
    layout: &RegexSetExact64DenseLayoutV1,
    all_pattern_mask: u64,
    haystack: &[u8],
    start: usize,
    end: usize,
    output: &mut u64,
) -> Result<u32, ()> {
    if start > end || end > haystack.len() {
        return Err(());
    }
    let geometry = DenseGeometry {
        state_count: layout.state_count,
        transition_cells: layout.transition_cells,
        transition_offset: layout.transition_offset,
        output_offset: layout.output_offset,
        data_bytes: layout.data.len(),
    };
    let mut state = 0usize;
    let mut matched = 0_u64;
    for &byte in &haystack[start..end] {
        state = usize::try_from(
            read_u32(
                &layout.data,
                transition_offset(geometry, state, byte).map_err(|_| ())?,
            )
            .map_err(|_| ())?,
        )
        .map_err(|_| ())?;
        let offset = layout
            .output_offset
            .checked_add(state.checked_mul(8).ok_or(())?)
            .ok_or(())?;
        matched |= layout
            .data
            .get(offset..offset + 8)
            .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
            .map(u64::from_le_bytes)
            .ok_or(())?;
        if matched == all_pattern_mask {
            break;
        }
    }
    *output = matched;
    Ok(matched.count_ones())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CompileMode, FeatureSet, RegexSetCompileRequest, RegexSetExact64CompileDisposition,
        RegexSetExact64Limits, SearchWindow, compile_regex_set_exact64_reported,
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
            .expect("portable exact64 compile")
        {
            RegexSetExact64CompileDisposition::Selected(program) => program,
            RegexSetExact64CompileDisposition::Declined { reason, .. } => {
                panic!("unexpected portable decline: {reason}")
            }
        }
    }

    #[test]
    fn dense_table_matches_portable_for_suffix_duplicate_and_overlap_shapes() {
        let program = selected(&["he", "she", "hers", "he", "a", "aa"]);
        let layout = match build_dense_layout(&program, RegexSetExact64AotLimitsV1::default())
            .expect("dense build")
        {
            DenseBuildDisposition::Built(layout) => layout,
            DenseBuildDisposition::Declined { .. } => panic!("unexpected dense decline"),
        };
        for (haystack, start, end) in [
            (b"ushers".as_slice(), 0, 6),
            (b"zaa".as_slice(), 0, 3),
            (b"zaa".as_slice(), 1, 3),
            (b"she".as_slice(), 1, 3),
            (b"nothing".as_slice(), 0, 7),
            (b"he".as_slice(), 0, 0),
        ] {
            let mut portable = u64::MAX;
            program
                .fill_matches(haystack, SearchWindow::new(start, end), &mut portable)
                .expect("portable scan");
            let mut dense = u64::MAX;
            interpret_dense(
                &layout,
                program.receipt().all_pattern_mask(),
                haystack,
                start,
                end,
                &mut dense,
            )
            .expect("dense scan");
            assert_eq!(portable, dense, "{haystack:?} {start}..{end}");
        }
    }

    #[test]
    fn dense_model_is_transactional_on_invalid_window() {
        let program = selected(&["ab", "bc"]);
        let layout = match build_dense_layout(&program, RegexSetExact64AotLimitsV1::default())
            .expect("dense build")
        {
            DenseBuildDisposition::Built(layout) => layout,
            DenseBuildDisposition::Declined { .. } => panic!("unexpected dense decline"),
        };
        let sentinel = 0xfeed_face_dead_beef;
        let mut output = sentinel;
        assert_eq!(
            Err(()),
            interpret_dense(
                &layout,
                program.receipt().all_pattern_mask(),
                b"ab",
                2,
                1,
                &mut output,
            )
        );
        assert_eq!(sentinel, output);
    }

    #[test]
    fn valid_unsupported_target_returns_identical_portable_owner() {
        let program = selected(&["ab", "bc"]);
        let receipt = program.receipt();
        let fallback = program.fallback().artifact_identity();
        match compile_regex_set_exact64_aot_v1(
            program,
            Target::x86_64_linux(),
            RegexSetExact64AotLimitsV1::default(),
        )
        .expect("safe target decline")
        {
            RegexSetExact64AotCompileDispositionV1::Declined { program, reason } => {
                assert_eq!(
                    RegexSetExact64AotDeclineV1::UnsupportedArchitecture {
                        actual: Architecture::X86_64,
                    },
                    reason
                );
                assert_eq!(receipt, program.receipt());
                assert_eq!(fallback, program.fallback().artifact_identity());
            }
            RegexSetExact64AotCompileDispositionV1::Selected(_) => {
                panic!("x86 must not select the AArch64 lowering")
            }
        }
    }

    #[test]
    fn incoherent_target_is_terminal_before_architecture_decline() {
        let program = selected(&["ab", "bc"]);
        let target = Target {
            architecture: Architecture::Aarch64,
            operating_system: OperatingSystem::Linux,
            abi: CallAbi::SystemV,
            features: FeatureSet::EMPTY,
        };
        assert!(matches!(
            compile_regex_set_exact64_aot_v1(
                program,
                target,
                RegexSetExact64AotLimitsV1::default(),
            ),
            Err(RegexSetExact64AotErrorV1::Object(
                ObjectError::UnsupportedTarget
            ))
        ));
    }

    #[test]
    fn dense_cell_cap_declines_with_identical_portable_owner() {
        let program = selected(&["ab", "bc"]);
        let receipt = program.receipt();
        let mut limits = RegexSetExact64AotLimitsV1::default();
        limits.max_dense_transition_cells = 0;
        match compile_regex_set_exact64_aot_v1(program, Target::aarch64_linux(), limits)
            .expect("safe cell decline")
        {
            RegexSetExact64AotCompileDispositionV1::Declined { program, reason } => {
                assert_eq!(receipt, program.receipt());
                assert!(matches!(
                    reason,
                    RegexSetExact64AotDeclineV1::Resource {
                        resource: RegexSetExact64AotResourceV1::DenseTransitionCells,
                        required,
                        limit: 0,
                    } if required != 0
                ));
            }
            RegexSetExact64AotCompileDispositionV1::Selected(_) => {
                panic!("zero cell limit cannot select")
            }
        }
    }

    #[test]
    fn later_numeric_caps_each_return_the_same_portable_owner() {
        let program = selected(&["ab", "bc"]);
        let receipt = program.receipt();
        for (resource, limits) in [
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
            match compile_regex_set_exact64_aot_v1(program.clone(), Target::aarch64_linux(), limits)
                .expect("safe numeric decline")
            {
                RegexSetExact64AotCompileDispositionV1::Declined {
                    program: declined,
                    reason:
                        RegexSetExact64AotDeclineV1::Resource {
                            resource: actual,
                            required,
                            limit: 0,
                        },
                } => {
                    assert_eq!(resource, actual);
                    assert_ne!(0, required);
                    assert_eq!(receipt, declined.receipt());
                }
                other => panic!("unexpected cap disposition: {other:?}"),
            }
        }
    }

    #[test]
    fn malformed_dense_target_is_terminal_not_a_safe_decline() {
        let program = selected(&["ab", "bc"]);
        let mut layout = match build_dense_layout(&program, RegexSetExact64AotLimitsV1::default())
            .expect("dense build")
        {
            DenseBuildDisposition::Built(layout) => layout,
            DenseBuildDisposition::Declined { .. } => panic!("unexpected dense decline"),
        };
        let first_cell = layout.transition_offset;
        layout.data[first_cell..first_cell + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            crate::module::lower_native_regex_set_exact64_aarch64_v1(
                Target::aarch64_linux(),
                [7; 32],
                program.receipt().artifact_identity(),
                program.receipt().all_pattern_mask(),
                layout,
                RegexSetExact64AotLimitsV1::default().max_code_bytes,
            ),
            Err(ObjectError::InvalidModule(
                "exact64 native dense target is outside the graph"
            ))
        ));
    }

    #[test]
    fn aarch64_selection_has_no_runtime_edge_and_authenticates() {
        let program = selected(&["alpha", "alphabet", "beta", "eta"]);
        let artifact = match compile_regex_set_exact64_aot_v1(
            program,
            Target::aarch64_linux(),
            RegexSetExact64AotLimitsV1::default(),
        )
        .expect("native compile")
        {
            RegexSetExact64AotCompileDispositionV1::Selected(artifact) => artifact,
            RegexSetExact64AotCompileDispositionV1::Declined { reason, .. } => {
                panic!("unexpected native decline: {reason}")
            }
        };
        assert!(artifact.authenticates_receipt());
        assert_eq!(0, artifact.receipt().semantic_runtime_calls());
        assert!(
            artifact
                .module()
                .required_runtime_symbols()
                .next()
                .is_none()
        );
        assert!(artifact.module().required_runtime_program().is_none());
        let module = artifact.module();
        let text_section = module
            .sections()
            .iter()
            .position(|section| section.kind == SectionKind::Text)
            .expect("text section");
        let data_section = module
            .sections()
            .iter()
            .position(|section| section.kind == SectionKind::ReadOnlyData)
            .expect("dense data section");
        let transition_symbol = module
            .symbols()
            .iter()
            .position(|symbol| symbol.name == ".Lfre_aot_regex_set_exact64_transitions_v1")
            .expect("dense transition symbol");
        let output_symbol = module
            .symbols()
            .iter()
            .position(|symbol| symbol.name == ".Lfre_aot_regex_set_exact64_outputs_v1")
            .expect("dense output symbol");
        let transition = &module.symbols()[transition_symbol];
        let outputs = &module.symbols()[output_symbol];
        for symbol in [transition, outputs] {
            assert_eq!(crate::SymbolBinding::Local, symbol.binding);
            assert_eq!(crate::SymbolKind::Object, symbol.kind);
            assert_eq!(Some(data_section), symbol.section);
            assert!(symbol.size != 0);
            assert!(
                symbol.offset.checked_add(symbol.size).is_some_and(|end| {
                    end <= u64::try_from(module.sections()[data_section].bytes().len())
                        .expect("dense data extent")
                }),
                "relocation target must be wholly defined by dense data"
            );
        }
        let expected_relocations = [
            (crate::RelocationKind::Aarch64Page21, transition_symbol),
            (crate::RelocationKind::Aarch64PageOff12, transition_symbol),
            (crate::RelocationKind::Aarch64Page21, output_symbol),
            (crate::RelocationKind::Aarch64PageOff12, output_symbol),
        ];
        assert_eq!(expected_relocations.len(), module.relocations().len());
        for (relocation, (kind, symbol)) in module.relocations().iter().zip(expected_relocations) {
            assert_eq!(text_section, relocation.section);
            assert_eq!(kind, relocation.kind);
            assert_eq!(symbol, relocation.symbol);
            assert_eq!(0, relocation.addend);
            assert!(relocation.offset.is_multiple_of(4));
            assert!(
                relocation.offset.checked_add(4).is_some_and(|end| {
                    end <= u64::try_from(module.sections()[text_section].bytes().len())
                        .expect("text extent")
                }),
                "relocation field must be wholly defined by text"
            );
        }
        assert_eq!(module.entry_symbol(), artifact.receipt().entry_symbol());
        let text = module_text(module).expect("native text");
        let words = text
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(<[u8; 4]>::try_from(bytes).unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(
            1,
            words
                .iter()
                .filter(|&&instruction| instruction == 0xf900_0087)
                .count(),
            "the only publication store is STR X7, [X4]"
        );
        assert!(
            words
                .iter()
                .all(|instruction| instruction & 0xfc00_0000 != 0x9400_0000),
            "helper-free scan has no BL instruction"
        );
    }

    #[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "macos")))]
    #[test]
    #[ignore = "links and executes the exact64 object on an AArch64 host"]
    #[allow(
        clippy::too_many_lines,
        reason = "the linked differential keeps the exact object, every-window expectations, and raw ABI transaction checks together"
    )]
    fn linked_host_aarch64_matches_portable_and_preserves_invalid_output() {
        use std::{fmt::Write as _, fs, process::Command};

        let target = if cfg!(target_os = "linux") {
            Target::aarch64_linux()
        } else {
            Target::aarch64_macos()
        };
        let program = selected(&["he", "she", "hers", "he", "a", "aa"]);
        let artifact = match compile_regex_set_exact64_aot_v1(
            program,
            target,
            RegexSetExact64AotLimitsV1::default(),
        )
        .expect("native exact64 compile")
        {
            RegexSetExact64AotCompileDispositionV1::Selected(artifact) => artifact,
            RegexSetExact64AotCompileDispositionV1::Declined { reason, .. } => {
                panic!("unexpected native exact64 decline: {reason}")
            }
        };
        let directory = std::env::temp_dir().join(format!(
            "fre-aot-regex-set-exact64-aarch64-{}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("create exact64 linked fixture directory");
        let object = directory.join("regex_set_exact64.o");
        fs::write(&object, artifact.object()).expect("write exact64 object");
        let symbol = artifact.module().entry_symbol();
        let mut source = format!(
            "#include <stdint.h>\n#include <stddef.h>\nextern uint32_t {symbol}(const unsigned char*,size_t,size_t,size_t,uint64_t*);\n"
        );
        let mut calls = String::from(
            "int main(void){uint64_t r;size_t i,j,k;uint32_t s;const uint64_t sentinel=UINT64_C(0xfeedfacedeadbeef);\n",
        );
        let haystacks = [
            b"".as_slice(),
            b"ushers".as_slice(),
            b"zaa".as_slice(),
            b"she".as_slice(),
            b"nothing".as_slice(),
            b"heheaa".as_slice(),
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
                    let mut output = u64::MAX;
                    artifact
                        .program()
                        .fill_matches(haystack, SearchWindow::new(start, end), &mut output)
                        .expect("portable exact64 result");
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
                    .expect("exact64 fixture failure code")
            )
            .unwrap();
        }
        writeln!(
            calls,
            "r=sentinel;s={symbol}(h1,6,2,1,&r);if(s!=2||r!=sentinel)return 80;"
        )
        .unwrap();
        writeln!(
            calls,
            "r=sentinel;s={symbol}(h1,6,0,7,&r);if(s!=2||r!=sentinel)return 81;"
        )
        .unwrap();
        writeln!(
            calls,
            "s={symbol}(h1,6,0,6,(uint64_t*)0);if(s!=2)return 82;"
        )
        .unwrap();
        writeln!(
            calls,
            "r=sentinel;s={symbol}((const unsigned char*)0,0,0,0,&r);if(s!=0||r!=0)return 83;"
        )
        .unwrap();
        writeln!(
            calls,
            "r=sentinel;s={symbol}((const unsigned char*)0,1,0,0,&r);if(s!=2||r!=sentinel)return 84;"
        )
        .unwrap();
        calls.push_str("return 0;}\n");
        source.push_str(&calls);
        let c_path = directory.join("regex_set_exact64.c");
        fs::write(&c_path, source).expect("write exact64 linked harness");
        let executable = directory.join("regex_set_exact64");
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
            .expect("execute exact64 linked fixture");
        assert!(
            run.status.success(),
            "run status={:?} stdout={} stderr={}",
            run.status.code(),
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );
    }
}
