//! Helper-free `AArch64` lowering for an authenticated finite regex-set graph.
//!
//! The public object uses a new generic graph ABI. Its fixed header binds the
//! source program and graph identities, result-mask geometry, and dense table
//! extents without exposing the private Rust graph layout. Exact64 V1 is not
//! used or modified by this explicit opt-in lowering.

use core::fmt;

#[cfg(test)]
use std::cell::Cell;

use sha2::{Digest, Sha256};

use crate::{
    Architecture, CallAbi, CompileResource, CompiledModule, ObjectError, ObjectFormat, SectionKind,
    Target, emit_object,
    regex_set_finite64::{
        RegexSetFinite64AuthenticationError, RegexSetFinite64GraphView, RegexSetFinite64Program,
        RegexSetFinite64Receipt,
    },
};

/// Stable raw entry ABI:
/// `u32 entry(const u8 *, usize, usize, usize, u64 *)`.
pub const REGEX_SET_GRAPH_EXISTS_AOT_V1_ABI_VERSION: u32 = 1;
/// Stable dense graph header/data schema.
pub const REGEX_SET_GRAPH_EXISTS_AOT_V1_DATA_SCHEMA_VERSION: u32 = 1;
/// The output word was published successfully.
pub const REGEX_SET_GRAPH_EXISTS_AOT_V1_STATUS_SUCCESS: u32 = 0;
/// A pointer, alignment, extent, or search window was invalid. The output is
/// unchanged.
pub const REGEX_SET_GRAPH_EXISTS_AOT_V1_STATUS_INVALID_ARGUMENT: u32 = 2;
/// Complete byte alphabet used by every dense transition row.
pub const REGEX_SET_GRAPH_EXISTS_AOT_V1_ALPHABET_LEN: usize = 256;
/// Largest immutable data extent supported by the scalar ADRP/ADD model.
pub const REGEX_SET_GRAPH_EXISTS_AOT_V1_MAX_ADDRESSABLE_DATA_BYTES: u64 = 2_147_483_647;
/// Operation identity domain for the generic graph ABI.
pub const REGEX_SET_GRAPH_EXISTS_AOT_V1_IDENTITY_DOMAIN: &[u8] =
    b"fre-aot-regex/regex-set-graph-exists-aot-v1\0";

const ARTIFACT_DOMAIN: &[u8] = b"fre-aot-regex/regex-set-graph-exists-artifact-v1\0";
pub(crate) const REGEX_SET_GRAPH_EXISTS_AOT_V1_HEADER_MAGIC: u64 = u64::from_le_bytes(*b"FRSGAOT1");
pub(crate) const REGEX_SET_GRAPH_EXISTS_AOT_V1_HEADER_BYTES: usize = 128;
const HEADER_MAGIC_OFFSET: usize = 0;
const HEADER_DATA_SCHEMA_OFFSET: usize = 8;
const HEADER_ENTRY_ABI_OFFSET: usize = 12;
const HEADER_GRAPH_IDENTITY_OFFSET: usize = 16;
const HEADER_SOURCE_ARTIFACT_OFFSET: usize = 48;
const HEADER_ALL_PATTERN_MASK_OFFSET: usize = 80;
const HEADER_PATTERN_COUNT_OFFSET: usize = 88;
const HEADER_STATE_COUNT_OFFSET: usize = 92;
const HEADER_TRANSITION_CELLS_OFFSET: usize = 96;
const HEADER_TRANSITION_OFFSET_OFFSET: usize = 104;
const HEADER_OUTPUT_OFFSET_OFFSET: usize = 112;
const HEADER_DATA_BYTES_OFFSET: usize = 120;

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestReserveFault {
    Disabled,
    Armed(&'static str),
    Failed,
}

#[cfg(test)]
thread_local! {
    static TEST_RESERVE_FAULT: Cell<TestReserveFault> = const {
        Cell::new(TestReserveFault::Disabled)
    };
}

#[cfg(test)]
struct TestReserveFaultGuard;

#[cfg(test)]
impl TestReserveFaultGuard {
    fn arm(structure: &'static str) -> Self {
        TEST_RESERVE_FAULT.with(|fault| {
            assert_eq!(
                TestReserveFault::Disabled,
                fault.replace(TestReserveFault::Armed(structure))
            );
        });
        Self
    }
}

#[cfg(test)]
impl Drop for TestReserveFaultGuard {
    fn drop(&mut self) {
        TEST_RESERVE_FAULT.with(|fault| fault.set(TestReserveFault::Disabled));
    }
}

#[cfg(test)]
fn injected_reserve_failure(structure: &'static str) -> bool {
    TEST_RESERVE_FAULT.with(|fault| match fault.get() {
        TestReserveFault::Disabled => false,
        TestReserveFault::Armed(expected) if expected != structure => false,
        TestReserveFault::Armed(_) => {
            fault.set(TestReserveFault::Failed);
            true
        }
        TestReserveFault::Failed => {
            panic!("graph AOT allocated after the injected allocator failure")
        }
    })
}

/// Independent numeric ceilings for the explicit native lowering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegexSetFinite64AotLimitsV1 {
    /// Maximum `state_count * 256` dense transition cells.
    pub max_dense_transition_cells: usize,
    /// Maximum authenticated dense-construction work units. One state census
    /// and one completed transition cell each consume one unit.
    pub max_dense_build_steps: u64,
    /// Maximum immutable header, transition, and output bytes.
    pub max_dense_data_bytes: usize,
    /// Maximum generated helper-free entry text bytes.
    pub max_code_bytes: usize,
    /// Maximum serialized relocatable object bytes.
    pub max_object_bytes: usize,
}

impl Default for RegexSetFinite64AotLimitsV1 {
    fn default() -> Self {
        Self {
            max_dense_transition_cells: 4 * 1_024 * 1_024,
            max_dense_build_steps: 8 * 1_024 * 1_024,
            max_dense_data_bytes: 32 * 1_024 * 1_024,
            max_code_bytes: 64 * 1_024,
            max_object_bytes: 64 * 1_024 * 1_024,
        }
    }
}

/// Numeric native representation that may retain the same portable program.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RegexSetFinite64AotResourceV1 {
    DenseTransitionCells,
    DenseBuildSteps,
    DenseDataBytes,
    CodeBytes,
    ObjectBytes,
}

/// Auditable numeric reason for retaining the exact portable owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RegexSetFinite64AotDeclineV1 {
    Resource {
        resource: RegexSetFinite64AotResourceV1,
        required: u64,
        limit: u64,
    },
}

impl fmt::Display for RegexSetFinite64AotDeclineV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resource {
                resource,
                required,
                limit,
            } => write!(
                formatter,
                "finite64 graph AOT needs {required} {resource:?}, limit is {limit}"
            ),
        }
    }
}

impl std::error::Error for RegexSetFinite64AotDeclineV1 {}

/// Generic helper-free graph/object receipt. It deliberately contains only
/// stable identities and wire geometry, not private Finite64 Rust records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegexSetGraphExistsAotReceiptV1 {
    abi_version: u32,
    data_schema_version: u32,
    target: Target,
    source_graph_schema_version: u32,
    source_artifact_identity: [u8; 32],
    source_graph_identity: [u8; 32],
    source_pattern_count: u8,
    all_pattern_mask: u64,
    operation_identity_sha256: [u8; 32],
    artifact_identity_sha256: [u8; 32],
    dense_data_sha256: [u8; 32],
    code_sha256: [u8; 32],
    object_sha256: [u8; 32],
    entry_symbol: String,
    state_count: usize,
    dense_transition_cells: usize,
    dense_build_steps: u64,
    transition_offset: usize,
    output_offset: usize,
    dense_data_bytes: usize,
    code_bytes: usize,
    object_bytes: usize,
    semantic_runtime_calls: usize,
    limits: RegexSetFinite64AotLimitsV1,
}

impl RegexSetGraphExistsAotReceiptV1 {
    #[must_use]
    pub const fn abi_version(&self) -> u32 {
        self.abi_version
    }

    #[must_use]
    pub const fn data_schema_version(&self) -> u32 {
        self.data_schema_version
    }

    #[must_use]
    pub const fn target(&self) -> Target {
        self.target
    }

    #[must_use]
    pub const fn source_graph_schema_version(&self) -> u32 {
        self.source_graph_schema_version
    }

    #[must_use]
    pub const fn source_artifact_identity(&self) -> [u8; 32] {
        self.source_artifact_identity
    }

    #[must_use]
    pub const fn source_graph_identity(&self) -> [u8; 32] {
        self.source_graph_identity
    }

    #[must_use]
    pub const fn source_pattern_count(&self) -> u8 {
        self.source_pattern_count
    }

    #[must_use]
    pub const fn all_pattern_mask(&self) -> u64 {
        self.all_pattern_mask
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
    pub const fn dense_build_steps(&self) -> u64 {
        self.dense_build_steps
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
    pub const fn limits(&self) -> RegexSetFinite64AotLimitsV1 {
        self.limits
    }
}

/// Native module/object paired with its unchanged portable semantic owner.
#[derive(Clone, Debug)]
pub struct RegexSetFinite64AotArtifactV1 {
    program: RegexSetFinite64Program,
    module: CompiledModule,
    object: Vec<u8>,
    receipt: RegexSetGraphExistsAotReceiptV1,
}

impl RegexSetFinite64AotArtifactV1 {
    #[must_use]
    pub const fn program(&self) -> &RegexSetFinite64Program {
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
    pub const fn receipt(&self) -> &RegexSetGraphExistsAotReceiptV1 {
        &self.receipt
    }

    /// Rebuild and authenticate the source graph, wire image, code,
    /// relocations, object, and receipt.
    #[must_use]
    pub fn authenticates_receipt(&self) -> bool {
        authenticate_artifact(self).is_ok()
    }
}

/// Selected native artifact or exact portable owner plus a numeric decline.
#[derive(Clone, Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "boxing would allocate after the portable compile transaction"
)]
pub enum RegexSetFinite64AotCompileDispositionV1 {
    Selected(RegexSetFinite64AotArtifactV1),
    Declined {
        program: RegexSetFinite64Program,
        reason: RegexSetFinite64AotDeclineV1,
    },
}

impl RegexSetFinite64AotCompileDispositionV1 {
    #[must_use]
    pub const fn program(&self) -> &RegexSetFinite64Program {
        match self {
            Self::Selected(artifact) => artifact.program(),
            Self::Declined { program, .. } => program,
        }
    }
}

/// Terminal native construction failure. No variant authorizes a fallback.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RegexSetFinite64AotErrorV1 {
    Authentication(RegexSetFinite64AuthenticationError),
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

impl fmt::Display for RegexSetFinite64AotErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authentication(source) => write!(formatter, "finite64 AOT source: {source}"),
            Self::Object(source) => write!(formatter, "finite64 AOT object: {source}"),
            Self::AllocationFailed { structure, entries } => write!(
                formatter,
                "finite64 AOT could not reserve {entries} entries for {structure}"
            ),
            Self::ArithmeticOverflow { computation } => {
                write!(formatter, "finite64 AOT overflow computing {computation}")
            }
            Self::NonExactCapacity {
                structure,
                requested,
                actual,
            } => write!(
                formatter,
                "finite64 AOT {structure} capacity is {actual}, requested exactly {requested}"
            ),
            Self::InternalInvariant(detail) => {
                write!(formatter, "finite64 AOT invariant: {detail}")
            }
        }
    }
}

impl std::error::Error for RegexSetFinite64AotErrorV1 {
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

impl From<RegexSetFinite64AuthenticationError> for RegexSetFinite64AotErrorV1 {
    fn from(value: RegexSetFinite64AuthenticationError) -> Self {
        Self::Authentication(value)
    }
}

impl From<ObjectError> for RegexSetFinite64AotErrorV1 {
    fn from(value: ObjectError) -> Self {
        Self::Object(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DenseGeometry {
    state_count: usize,
    transition_cells: usize,
    build_steps: u64,
    transition_offset: usize,
    output_offset: usize,
    data_bytes: usize,
}

/// Stable generic dense graph image handed to the object lowerer.
#[derive(Debug)]
pub(crate) struct RegexSetGraphDenseImageV1 {
    pub(crate) data: Vec<u8>,
    pub(crate) state_count: usize,
    pub(crate) transition_cells: usize,
    pub(crate) build_steps: u64,
    pub(crate) transition_offset: usize,
    pub(crate) output_offset: usize,
}

enum DenseBuildDisposition {
    Built(RegexSetGraphDenseImageV1),
    Declined {
        resource: RegexSetFinite64AotResourceV1,
        required: u64,
        limit: u64,
    },
}

fn arithmetic(computation: &'static str) -> RegexSetFinite64AotErrorV1 {
    RegexSetFinite64AotErrorV1::ArithmeticOverflow { computation }
}

fn usize_to_u64(
    value: usize,
    computation: &'static str,
) -> Result<u64, RegexSetFinite64AotErrorV1> {
    u64::try_from(value).map_err(|_| arithmetic(computation))
}

fn dense_geometry(
    graph: RegexSetFinite64GraphView<'_>,
) -> Result<DenseGeometry, RegexSetFinite64AotErrorV1> {
    let state_count = graph.state_count();
    let transition_cells = state_count
        .checked_mul(REGEX_SET_GRAPH_EXISTS_AOT_V1_ALPHABET_LEN)
        .ok_or_else(|| arithmetic("dense transition cell count"))?;
    let build_steps = usize_to_u64(state_count, "dense state work")?
        .checked_add(usize_to_u64(transition_cells, "dense transition work")?)
        .ok_or_else(|| arithmetic("dense build work"))?;
    let transition_bytes = transition_cells
        .checked_mul(core::mem::size_of::<u32>())
        .ok_or_else(|| arithmetic("dense transition bytes"))?;
    let transition_offset = REGEX_SET_GRAPH_EXISTS_AOT_V1_HEADER_BYTES;
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
        build_steps,
        transition_offset,
        output_offset,
        data_bytes,
    })
}

fn reserve_exact<T>(
    values: &mut Vec<T>,
    entries: usize,
    structure: &'static str,
) -> Result<(), RegexSetFinite64AotErrorV1> {
    #[cfg(test)]
    if injected_reserve_failure(structure) {
        return Err(RegexSetFinite64AotErrorV1::AllocationFailed { structure, entries });
    }
    values
        .try_reserve_exact(entries)
        .map_err(|_| RegexSetFinite64AotErrorV1::AllocationFailed { structure, entries })?;
    if values.capacity() != entries {
        return Err(RegexSetFinite64AotErrorV1::NonExactCapacity {
            structure,
            requested: entries,
            actual: values.capacity(),
        });
    }
    Ok(())
}

fn checked_range(
    offset: usize,
    width: usize,
    computation: &'static str,
) -> Result<core::ops::Range<usize>, RegexSetFinite64AotErrorV1> {
    Ok(offset
        ..offset
            .checked_add(width)
            .ok_or_else(|| arithmetic(computation))?)
}

fn write_u32(
    data: &mut [u8],
    offset: usize,
    value: u32,
    computation: &'static str,
) -> Result<(), RegexSetFinite64AotErrorV1> {
    let range = checked_range(offset, 4, computation)?;
    data.get_mut(range)
        .ok_or(RegexSetFinite64AotErrorV1::InternalInvariant(
            "dense u32 write is outside the image",
        ))?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u64(
    data: &mut [u8],
    offset: usize,
    value: u64,
    computation: &'static str,
) -> Result<(), RegexSetFinite64AotErrorV1> {
    let range = checked_range(offset, 8, computation)?;
    data.get_mut(range)
        .ok_or(RegexSetFinite64AotErrorV1::InternalInvariant(
            "dense u64 write is outside the image",
        ))?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn read_u32(
    data: &[u8],
    offset: usize,
    computation: &'static str,
) -> Result<u32, RegexSetFinite64AotErrorV1> {
    let range = checked_range(offset, 4, computation)?;
    data.get(range)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_le_bytes)
        .ok_or(RegexSetFinite64AotErrorV1::InternalInvariant(
            "dense u32 read is outside the image",
        ))
}

fn transition_cell_offset(
    geometry: DenseGeometry,
    state: usize,
    byte: u8,
) -> Result<usize, RegexSetFinite64AotErrorV1> {
    state
        .checked_mul(REGEX_SET_GRAPH_EXISTS_AOT_V1_ALPHABET_LEN)
        .and_then(|cell| cell.checked_add(usize::from(byte)))
        .and_then(|cell| cell.checked_mul(core::mem::size_of::<u32>()))
        .and_then(|bytes| geometry.transition_offset.checked_add(bytes))
        .ok_or_else(|| arithmetic("dense transition cell offset"))
}

fn decline_limit(
    resource: RegexSetFinite64AotResourceV1,
    required: usize,
    limit: usize,
) -> Result<DenseBuildDisposition, RegexSetFinite64AotErrorV1> {
    Ok(DenseBuildDisposition::Declined {
        resource,
        required: usize_to_u64(required, "dense resource requirement")?,
        limit: usize_to_u64(limit, "dense resource limit")?,
    })
}

fn write_header(
    data: &mut [u8],
    source: RegexSetFinite64Receipt,
    geometry: DenseGeometry,
) -> Result<(), RegexSetFinite64AotErrorV1> {
    write_u64(
        data,
        HEADER_MAGIC_OFFSET,
        REGEX_SET_GRAPH_EXISTS_AOT_V1_HEADER_MAGIC,
        "dense header magic",
    )?;
    write_u32(
        data,
        HEADER_DATA_SCHEMA_OFFSET,
        REGEX_SET_GRAPH_EXISTS_AOT_V1_DATA_SCHEMA_VERSION,
        "dense header schema",
    )?;
    write_u32(
        data,
        HEADER_ENTRY_ABI_OFFSET,
        REGEX_SET_GRAPH_EXISTS_AOT_V1_ABI_VERSION,
        "dense header ABI",
    )?;
    data.get_mut(HEADER_GRAPH_IDENTITY_OFFSET..HEADER_SOURCE_ARTIFACT_OFFSET)
        .ok_or(RegexSetFinite64AotErrorV1::InternalInvariant(
            "dense header omitted graph identity",
        ))?
        .copy_from_slice(source.artifact_identity().as_bytes());
    data.get_mut(HEADER_SOURCE_ARTIFACT_OFFSET..HEADER_ALL_PATTERN_MASK_OFFSET)
        .ok_or(RegexSetFinite64AotErrorV1::InternalInvariant(
            "dense header omitted source identity",
        ))?
        .copy_from_slice(source.source_artifact().as_bytes());
    write_u64(
        data,
        HEADER_ALL_PATTERN_MASK_OFFSET,
        source.all_pattern_mask(),
        "dense header result mask",
    )?;
    write_u32(
        data,
        HEADER_PATTERN_COUNT_OFFSET,
        u32::from(source.pattern_count()),
        "dense header pattern count",
    )?;
    write_u32(
        data,
        HEADER_STATE_COUNT_OFFSET,
        u32::try_from(geometry.state_count).map_err(|_| arithmetic("dense header state count"))?,
        "dense header state count",
    )?;
    write_u64(
        data,
        HEADER_TRANSITION_CELLS_OFFSET,
        usize_to_u64(geometry.transition_cells, "dense header transition cells")?,
        "dense header transition cells",
    )?;
    write_u64(
        data,
        HEADER_TRANSITION_OFFSET_OFFSET,
        usize_to_u64(geometry.transition_offset, "dense header transition offset")?,
        "dense header transition offset",
    )?;
    write_u64(
        data,
        HEADER_OUTPUT_OFFSET_OFFSET,
        usize_to_u64(geometry.output_offset, "dense header output offset")?,
        "dense header output offset",
    )?;
    write_u64(
        data,
        HEADER_DATA_BYTES_OFFSET,
        usize_to_u64(geometry.data_bytes, "dense header data extent")?,
        "dense header data extent",
    )?;
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "authenticated depth order and complete dense closure are one fail-closed transaction"
)]
fn build_dense_image(
    program: &RegexSetFinite64Program,
    limits: RegexSetFinite64AotLimitsV1,
) -> Result<DenseBuildDisposition, RegexSetFinite64AotErrorV1> {
    let graph = program.authenticated_graph()?;
    let source = graph.receipt();
    let geometry = dense_geometry(graph)?;
    if geometry.transition_cells > limits.max_dense_transition_cells {
        return decline_limit(
            RegexSetFinite64AotResourceV1::DenseTransitionCells,
            geometry.transition_cells,
            limits.max_dense_transition_cells,
        );
    }
    if geometry.build_steps > limits.max_dense_build_steps {
        return Ok(DenseBuildDisposition::Declined {
            resource: RegexSetFinite64AotResourceV1::DenseBuildSteps,
            required: geometry.build_steps,
            limit: limits.max_dense_build_steps,
        });
    }
    let addressable_limit =
        usize::try_from(REGEX_SET_GRAPH_EXISTS_AOT_V1_MAX_ADDRESSABLE_DATA_BYTES)
            .unwrap_or(usize::MAX);
    let effective_data_limit = limits.max_dense_data_bytes.min(addressable_limit);
    if geometry.data_bytes > effective_data_limit {
        return decline_limit(
            RegexSetFinite64AotResourceV1::DenseDataBytes,
            geometry.data_bytes,
            effective_data_limit,
        );
    }

    let mut data = Vec::new();
    reserve_exact(&mut data, geometry.data_bytes, "generic dense graph image")?;
    data.resize(geometry.data_bytes, 0);
    write_header(&mut data, source, geometry)?;

    let mut depth_order = Vec::new();
    reserve_exact(
        &mut depth_order,
        geometry.state_count,
        "generic dense depth order",
    )?;
    for state in 0..geometry.state_count {
        if graph.state_depth(state).is_none()
            || graph.failure_state(state).is_none()
            || graph.output_mask(state).is_none()
        {
            return Err(RegexSetFinite64AotErrorV1::InternalInvariant(
                "authenticated graph lost an indexed state",
            ));
        }
        depth_order.push(state);
    }
    depth_order.sort_unstable_by_key(|&state| graph.state_depth(state).unwrap_or(u32::MAX));
    if depth_order.first().copied() != Some(0) {
        return Err(RegexSetFinite64AotErrorV1::InternalInvariant(
            "authenticated root is not the minimum-depth state",
        ));
    }

    for state in depth_order {
        let depth =
            graph
                .state_depth(state)
                .ok_or(RegexSetFinite64AotErrorV1::InternalInvariant(
                    "dense state depth disappeared",
                ))?;
        let failure = usize::try_from(graph.failure_state(state).ok_or(
            RegexSetFinite64AotErrorV1::InternalInvariant("dense failure state disappeared"),
        )?)
        .map_err(|_| arithmetic("dense failure state index"))?;
        if failure >= geometry.state_count {
            return Err(RegexSetFinite64AotErrorV1::InternalInvariant(
                "dense failure state is outside the graph",
            ));
        }
        if state != 0
            && graph
                .state_depth(failure)
                .is_none_or(|failure_depth| failure_depth >= depth)
        {
            return Err(RegexSetFinite64AotErrorV1::InternalInvariant(
                "dense failure row was not completed first",
            ));
        }
        for byte in u8::MIN..=u8::MAX {
            let target = if let Some(target) = graph.direct_transition(state, byte) {
                target
            } else if state == 0 {
                0
            } else {
                read_u32(
                    &data,
                    transition_cell_offset(geometry, failure, byte)?,
                    "dense inherited transition read",
                )?
            };
            if usize::try_from(target).map_or(true, |target| target >= geometry.state_count) {
                return Err(RegexSetFinite64AotErrorV1::InternalInvariant(
                    "dense transition target is outside the graph",
                ));
            }
            write_u32(
                &mut data,
                transition_cell_offset(geometry, state, byte)?,
                target,
                "dense transition write",
            )?;
        }
        let output =
            graph
                .output_mask(state)
                .ok_or(RegexSetFinite64AotErrorV1::InternalInvariant(
                    "dense output mask disappeared",
                ))?;
        let output_offset = state
            .checked_mul(core::mem::size_of::<u64>())
            .and_then(|bytes| geometry.output_offset.checked_add(bytes))
            .ok_or_else(|| arithmetic("dense output offset"))?;
        write_u64(&mut data, output_offset, output, "dense output write")?;
    }

    let image = RegexSetGraphDenseImageV1 {
        data,
        state_count: geometry.state_count,
        transition_cells: geometry.transition_cells,
        build_steps: geometry.build_steps,
        transition_offset: geometry.transition_offset,
        output_offset: geometry.output_offset,
    };
    authenticate_dense_image_for_lowering(
        *source.artifact_identity().as_bytes(),
        *source.source_artifact().as_bytes(),
        source.pattern_count(),
        source.all_pattern_mask(),
        &image,
    )?;
    Ok(DenseBuildDisposition::Built(image))
}

fn object_read_u32(data: &[u8], offset: usize) -> Result<u32, ObjectError> {
    let end = offset
        .checked_add(4)
        .ok_or(ObjectError::ArithmeticOverflow(
            "generic graph header u32 extent",
        ))?;
    data.get(offset..end)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_le_bytes)
        .ok_or(ObjectError::InvalidModule(
            "generic graph header u32 is outside the image",
        ))
}

fn object_read_u64(data: &[u8], offset: usize) -> Result<u64, ObjectError> {
    let end = offset
        .checked_add(8)
        .ok_or(ObjectError::ArithmeticOverflow(
            "generic graph header u64 extent",
        ))?;
    data.get(offset..end)
        .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
        .map(u64::from_le_bytes)
        .ok_or(ObjectError::InvalidModule(
            "generic graph header u64 is outside the image",
        ))
}

const fn expected_pattern_mask(pattern_count: u8) -> u64 {
    if pattern_count == 64 {
        u64::MAX
    } else {
        (1_u64 << pattern_count).saturating_sub(1)
    }
}

/// Independently authenticate the stable graph image immediately before it
/// crosses into target code generation. No allocation or source Rust layout
/// is involved.
#[allow(
    clippy::too_many_lines,
    reason = "one complete structural validation covers the header, every extent, transition, and output"
)]
pub(crate) fn authenticate_dense_image_for_lowering(
    source_graph_identity: [u8; 32],
    source_artifact_identity: [u8; 32],
    pattern_count: u8,
    all_pattern_mask: u64,
    image: &RegexSetGraphDenseImageV1,
) -> Result<(), ObjectError> {
    let data = &image.data;
    if !(2..=64).contains(&pattern_count)
        || all_pattern_mask != expected_pattern_mask(pattern_count)
        || data.capacity() != data.len()
        || data.len() < REGEX_SET_GRAPH_EXISTS_AOT_V1_HEADER_BYTES
        || object_read_u64(data, HEADER_MAGIC_OFFSET)? != REGEX_SET_GRAPH_EXISTS_AOT_V1_HEADER_MAGIC
        || object_read_u32(data, HEADER_DATA_SCHEMA_OFFSET)?
            != REGEX_SET_GRAPH_EXISTS_AOT_V1_DATA_SCHEMA_VERSION
        || object_read_u32(data, HEADER_ENTRY_ABI_OFFSET)?
            != REGEX_SET_GRAPH_EXISTS_AOT_V1_ABI_VERSION
        || data.get(HEADER_GRAPH_IDENTITY_OFFSET..HEADER_SOURCE_ARTIFACT_OFFSET)
            != Some(source_graph_identity.as_slice())
        || data.get(HEADER_SOURCE_ARTIFACT_OFFSET..HEADER_ALL_PATTERN_MASK_OFFSET)
            != Some(source_artifact_identity.as_slice())
        || object_read_u64(data, HEADER_ALL_PATTERN_MASK_OFFSET)? != all_pattern_mask
        || object_read_u32(data, HEADER_PATTERN_COUNT_OFFSET)? != u32::from(pattern_count)
    {
        return Err(ObjectError::InvalidModule(
            "generic graph dense header identity",
        ));
    }

    let header_state_count = usize::try_from(object_read_u32(data, HEADER_STATE_COUNT_OFFSET)?)
        .map_err(|_| ObjectError::ArithmeticOverflow("generic graph header state count"))?;
    let header_transition_cells =
        usize::try_from(object_read_u64(data, HEADER_TRANSITION_CELLS_OFFSET)?).map_err(|_| {
            ObjectError::ArithmeticOverflow("generic graph header transition cells")
        })?;
    let header_transition_offset =
        usize::try_from(object_read_u64(data, HEADER_TRANSITION_OFFSET_OFFSET)?).map_err(|_| {
            ObjectError::ArithmeticOverflow("generic graph header transition offset")
        })?;
    let header_output_offset = usize::try_from(object_read_u64(data, HEADER_OUTPUT_OFFSET_OFFSET)?)
        .map_err(|_| ObjectError::ArithmeticOverflow("generic graph header output offset"))?;
    let header_data_bytes = usize::try_from(object_read_u64(data, HEADER_DATA_BYTES_OFFSET)?)
        .map_err(|_| ObjectError::ArithmeticOverflow("generic graph header data extent"))?;
    let expected_cells = image
        .state_count
        .checked_mul(REGEX_SET_GRAPH_EXISTS_AOT_V1_ALPHABET_LEN)
        .ok_or(ObjectError::ArithmeticOverflow(
            "generic graph dense transition cells",
        ))?;
    let expected_steps = u64::try_from(image.state_count)
        .ok()
        .and_then(|states| {
            u64::try_from(expected_cells)
                .ok()
                .and_then(|cells| states.checked_add(cells))
        })
        .ok_or(ObjectError::ArithmeticOverflow(
            "generic graph dense build work",
        ))?;
    let transition_bytes = expected_cells
        .checked_mul(core::mem::size_of::<u32>())
        .ok_or(ObjectError::ArithmeticOverflow(
            "generic graph dense transition bytes",
        ))?;
    let transition_end = image
        .transition_offset
        .checked_add(transition_bytes)
        .ok_or(ObjectError::ArithmeticOverflow(
            "generic graph dense transition extent",
        ))?;
    let output_bytes = image
        .state_count
        .checked_mul(core::mem::size_of::<u64>())
        .ok_or(ObjectError::ArithmeticOverflow(
            "generic graph dense output bytes",
        ))?;
    let output_end =
        image
            .output_offset
            .checked_add(output_bytes)
            .ok_or(ObjectError::ArithmeticOverflow(
                "generic graph dense output extent",
            ))?;
    if image.state_count == 0
        || image.transition_offset != REGEX_SET_GRAPH_EXISTS_AOT_V1_HEADER_BYTES
        || !image
            .output_offset
            .is_multiple_of(core::mem::align_of::<u64>())
        || image.transition_cells != expected_cells
        || image.build_steps != expected_steps
        || transition_end > image.output_offset
        || output_end != data.len()
        || header_state_count != image.state_count
        || header_transition_cells != image.transition_cells
        || header_transition_offset != image.transition_offset
        || header_output_offset != image.output_offset
        || header_data_bytes != data.len()
        || u32::try_from(image.state_count).is_err()
    {
        return Err(ObjectError::InvalidModule(
            "generic graph dense extents disagree",
        ));
    }
    if data
        .get(transition_end..image.output_offset)
        .is_none_or(|padding| padding.iter().any(|&byte| byte != 0))
    {
        return Err(ObjectError::InvalidModule(
            "generic graph dense padding is not canonical",
        ));
    }
    for cell in data[image.transition_offset..transition_end].chunks_exact(4) {
        let target = <[u8; 4]>::try_from(cell)
            .map(u32::from_le_bytes)
            .map_err(|_| ObjectError::InvalidModule("generic graph dense transition cell"))?;
        if usize::try_from(target).map_or(true, |target| target >= image.state_count) {
            return Err(ObjectError::InvalidModule(
                "generic graph dense target is outside the graph",
            ));
        }
    }
    let mut published = 0_u64;
    for (state, mask) in data[image.output_offset..output_end]
        .chunks_exact(8)
        .enumerate()
    {
        let mask = <[u8; 8]>::try_from(mask)
            .map(u64::from_le_bytes)
            .map_err(|_| ObjectError::InvalidModule("generic graph dense output cell"))?;
        if mask & !all_pattern_mask != 0 || state == 0 && mask != 0 {
            return Err(ObjectError::InvalidModule(
                "generic graph dense output mask is invalid",
            ));
        }
        published |= mask;
    }
    if published != all_pattern_mask {
        return Err(ObjectError::InvalidModule(
            "generic graph dense outputs omit a source bit",
        ));
    }
    Ok(())
}

fn update_usize(
    digest: &mut Sha256,
    value: usize,
    computation: &'static str,
) -> Result<(), RegexSetFinite64AotErrorV1> {
    digest.update(usize_to_u64(value, computation)?.to_le_bytes());
    Ok(())
}

fn update_identity_usize(
    digest: &mut Sha256,
    value: usize,
    computation: &'static str,
) -> Result<(), &'static str> {
    digest.update(u64::try_from(value).map_err(|_| computation)?.to_le_bytes());
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the stable operation identity explicitly binds every source and wire component"
)]
fn operation_identity_from_components(
    target: Target,
    source_graph_schema_version: u32,
    source_artifact_identity: [u8; 32],
    source_graph_identity: [u8; 32],
    source_pattern_count: u8,
    all_pattern_mask: u64,
    dense_data_sha256: [u8; 32],
    image: &RegexSetGraphDenseImageV1,
) -> Result<[u8; 32], &'static str> {
    let mut digest = Sha256::new();
    digest.update(REGEX_SET_GRAPH_EXISTS_AOT_V1_IDENTITY_DOMAIN);
    digest.update(REGEX_SET_GRAPH_EXISTS_AOT_V1_ABI_VERSION.to_le_bytes());
    digest.update(REGEX_SET_GRAPH_EXISTS_AOT_V1_DATA_SCHEMA_VERSION.to_le_bytes());
    digest.update(REGEX_SET_GRAPH_EXISTS_AOT_V1_MAX_ADDRESSABLE_DATA_BYTES.to_le_bytes());
    digest.update([
        match target.architecture {
            Architecture::X86_64 => 1,
            Architecture::Aarch64 => 2,
        },
        match target.operating_system {
            crate::OperatingSystem::Linux => 1,
            crate::OperatingSystem::Macos => 2,
        },
        match target.abi {
            CallAbi::SystemV => 1,
            CallAbi::Aapcs64 => 2,
        },
    ]);
    digest.update(target.features.bits().to_le_bytes());
    digest.update(source_graph_schema_version.to_le_bytes());
    digest.update(source_artifact_identity);
    digest.update(source_graph_identity);
    digest.update([source_pattern_count]);
    digest.update(all_pattern_mask.to_le_bytes());
    update_identity_usize(&mut digest, image.state_count, "identity state count")?;
    update_identity_usize(
        &mut digest,
        image.transition_cells,
        "identity transition cells",
    )?;
    digest.update(image.build_steps.to_le_bytes());
    update_identity_usize(
        &mut digest,
        image.transition_offset,
        "identity transition offset",
    )?;
    update_identity_usize(&mut digest, image.output_offset, "identity output offset")?;
    update_identity_usize(&mut digest, image.data.len(), "identity dense data bytes")?;
    digest.update(dense_data_sha256);
    Ok(<[u8; 32]>::from(digest.finalize()))
}

fn operation_identity(
    target: Target,
    source: RegexSetFinite64Receipt,
    dense_data_sha256: [u8; 32],
    image: &RegexSetGraphDenseImageV1,
) -> Result<[u8; 32], RegexSetFinite64AotErrorV1> {
    operation_identity_from_components(
        target,
        source.schema_version(),
        *source.source_artifact().as_bytes(),
        *source.artifact_identity().as_bytes(),
        source.pattern_count(),
        source.all_pattern_mask(),
        dense_data_sha256,
        image,
    )
    .map_err(arithmetic)
}

/// Authenticate the complete operation identity at the final target-lowering
/// boundary. Structural validation alone cannot distinguish one in-range
/// transition target from another, so this recomputes the dense-data digest
/// and binds it to the exact target, source identities, and wire geometry.
#[allow(
    clippy::too_many_arguments,
    reason = "the final lowering boundary must receive every independently bound identity component"
)]
pub(crate) fn authenticate_operation_identity_for_lowering(
    target: Target,
    expected_operation_identity: [u8; 32],
    source_graph_schema_version: u32,
    source_artifact_identity: [u8; 32],
    source_graph_identity: [u8; 32],
    source_pattern_count: u8,
    all_pattern_mask: u64,
    image: &RegexSetGraphDenseImageV1,
) -> Result<(), ObjectError> {
    let dense_data_sha256 = <[u8; 32]>::from(Sha256::digest(&image.data));
    let actual = operation_identity_from_components(
        target,
        source_graph_schema_version,
        source_artifact_identity,
        source_graph_identity,
        source_pattern_count,
        all_pattern_mask,
        dense_data_sha256,
        image,
    )
    .map_err(ObjectError::ArithmeticOverflow)?;
    if actual != expected_operation_identity {
        return Err(ObjectError::InvalidModule(
            "generic graph operation identity does not authenticate dense image",
        ));
    }
    Ok(())
}

fn artifact_identity(
    receipt: &RegexSetGraphExistsAotReceiptV1,
) -> Result<[u8; 32], RegexSetFinite64AotErrorV1> {
    let mut digest = Sha256::new();
    digest.update(ARTIFACT_DOMAIN);
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
    digest.update(receipt.limits.max_dense_build_steps.to_le_bytes());
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
    Ok(<[u8; 32]>::from(digest.finalize()))
}

fn module_text(module: &CompiledModule) -> Result<&[u8], RegexSetFinite64AotErrorV1> {
    module
        .sections()
        .iter()
        .find(|section| section.kind == SectionKind::Text)
        .map(crate::module::ModuleSection::bytes)
        .ok_or(RegexSetFinite64AotErrorV1::InternalInvariant(
            "generic graph module has no text section",
        ))
}

fn module_data(module: &CompiledModule) -> Result<&[u8], RegexSetFinite64AotErrorV1> {
    module
        .sections()
        .iter()
        .find(|section| section.kind == SectionKind::ReadOnlyData)
        .map(crate::module::ModuleSection::bytes)
        .ok_or(RegexSetFinite64AotErrorV1::InternalInvariant(
            "generic graph module has no data section",
        ))
}

fn decline(
    program: RegexSetFinite64Program,
    resource: RegexSetFinite64AotResourceV1,
    required: u64,
    limit: u64,
) -> RegexSetFinite64AotCompileDispositionV1 {
    RegexSetFinite64AotCompileDispositionV1::Declined {
        program,
        reason: RegexSetFinite64AotDeclineV1::Resource {
            resource,
            required,
            limit,
        },
    }
}

fn map_lowering_resource(
    error: ObjectError,
) -> Result<RegexSetFinite64AotDeclineV1, RegexSetFinite64AotErrorV1> {
    match error {
        ObjectError::Resource {
            resource: CompileResource::CodeBytes,
            limit,
            required,
        } => Ok(RegexSetFinite64AotDeclineV1::Resource {
            resource: RegexSetFinite64AotResourceV1::CodeBytes,
            required: usize_to_u64(required, "code byte requirement")?,
            limit: usize_to_u64(limit, "code byte limit")?,
        }),
        other => Err(other.into()),
    }
}

/// Lower one already-selected Finite64 program into a helper-free `AArch64`
/// generic graph object.
///
/// The source program and target are authenticated before any decline. Only
/// the five explicit numeric ceilings return `Declined`; target, allocation,
/// arithmetic, module, serialization, and authentication failures are
/// terminal. No default compiler entry invokes this API.
#[allow(
    clippy::too_many_lines,
    reason = "numeric declines retain the same owned portable program across every native boundary"
)]
pub fn compile_regex_set_finite64_aot_v1(
    program: RegexSetFinite64Program,
    target: Target,
    limits: RegexSetFinite64AotLimitsV1,
) -> Result<RegexSetFinite64AotCompileDispositionV1, RegexSetFinite64AotErrorV1> {
    program.authenticate()?;
    target.validate()?;
    if target.architecture != Architecture::Aarch64 || target.abi != CallAbi::Aapcs64 {
        return Err(ObjectError::InvalidModule(
            "generic graph AOT requires a valid AArch64 target",
        )
        .into());
    }

    let image = match build_dense_image(&program, limits)? {
        DenseBuildDisposition::Built(image) => image,
        DenseBuildDisposition::Declined {
            resource,
            required,
            limit,
        } => return Ok(decline(program, resource, required, limit)),
    };
    let source = program.receipt();
    let dense_data_sha256 = <[u8; 32]>::from(Sha256::digest(&image.data));
    let operation_identity_sha256 = operation_identity(target, source, dense_data_sha256, &image)?;
    let state_count = image.state_count;
    let dense_transition_cells = image.transition_cells;
    let dense_build_steps = image.build_steps;
    let transition_offset = image.transition_offset;
    let output_offset = image.output_offset;
    let dense_data_bytes = image.data.len();
    let module = match crate::module::lower_native_regex_set_graph_exists_aarch64_v1(
        target,
        operation_identity_sha256,
        source.schema_version(),
        *source.artifact_identity().as_bytes(),
        *source.source_artifact().as_bytes(),
        source.pattern_count(),
        source.all_pattern_mask(),
        image,
        limits.max_code_bytes,
    ) {
        Ok(module) => module,
        Err(error @ ObjectError::Resource { .. }) => {
            let reason = map_lowering_resource(error)?;
            return Ok(RegexSetFinite64AotCompileDispositionV1::Declined { program, reason });
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
                RegexSetFinite64AotResourceV1::ObjectBytes,
                usize_to_u64(required, "object byte requirement")?,
                usize_to_u64(limit, "object byte limit")?,
            ));
        }
        Err(error) => return Err(error.into()),
    };
    let text = module_text(&module)?;
    let code_sha256 = <[u8; 32]>::from(Sha256::digest(text));
    let object_sha256 = <[u8; 32]>::from(Sha256::digest(&object));
    let mut receipt = RegexSetGraphExistsAotReceiptV1 {
        abi_version: REGEX_SET_GRAPH_EXISTS_AOT_V1_ABI_VERSION,
        data_schema_version: REGEX_SET_GRAPH_EXISTS_AOT_V1_DATA_SCHEMA_VERSION,
        target,
        source_graph_schema_version: source.schema_version(),
        source_artifact_identity: *source.source_artifact().as_bytes(),
        source_graph_identity: *source.artifact_identity().as_bytes(),
        source_pattern_count: source.pattern_count(),
        all_pattern_mask: source.all_pattern_mask(),
        operation_identity_sha256,
        artifact_identity_sha256: [0; 32],
        dense_data_sha256,
        code_sha256,
        object_sha256,
        entry_symbol: module.entry_symbol().to_owned(),
        state_count,
        dense_transition_cells,
        dense_build_steps,
        transition_offset,
        output_offset,
        dense_data_bytes,
        code_bytes: text.len(),
        object_bytes: object.len(),
        semantic_runtime_calls: 0,
        limits,
    };
    receipt.artifact_identity_sha256 = artifact_identity(&receipt)?;
    let artifact = RegexSetFinite64AotArtifactV1 {
        program,
        module,
        object,
        receipt,
    };
    authenticate_artifact(&artifact)?;
    Ok(RegexSetFinite64AotCompileDispositionV1::Selected(artifact))
}

fn authenticate_artifact(
    artifact: &RegexSetFinite64AotArtifactV1,
) -> Result<(), RegexSetFinite64AotErrorV1> {
    artifact.program.authenticate()?;
    artifact.receipt.target.validate()?;
    if artifact.receipt.target.architecture != Architecture::Aarch64
        || artifact.receipt.target.abi != CallAbi::Aapcs64
    {
        return Err(RegexSetFinite64AotErrorV1::InternalInvariant(
            "selected generic graph artifact is not AArch64",
        ));
    }
    let image = match build_dense_image(&artifact.program, artifact.receipt.limits)? {
        DenseBuildDisposition::Built(image) => image,
        DenseBuildDisposition::Declined { .. } => {
            return Err(RegexSetFinite64AotErrorV1::InternalInvariant(
                "selected graph image now declines its frozen limits",
            ));
        }
    };
    let source = artifact.program.receipt();
    let dense_data_sha256 = <[u8; 32]>::from(Sha256::digest(&image.data));
    let operation_identity_sha256 =
        operation_identity(artifact.receipt.target, source, dense_data_sha256, &image)?;
    let state_count = image.state_count;
    let dense_transition_cells = image.transition_cells;
    let dense_build_steps = image.build_steps;
    let transition_offset = image.transition_offset;
    let output_offset = image.output_offset;
    let dense_data_bytes = image.data.len();
    let rebuilt = crate::module::lower_native_regex_set_graph_exists_aarch64_v1(
        artifact.receipt.target,
        operation_identity_sha256,
        source.schema_version(),
        *source.artifact_identity().as_bytes(),
        *source.source_artifact().as_bytes(),
        source.pattern_count(),
        source.all_pattern_mask(),
        image,
        artifact.receipt.limits.max_code_bytes,
    )?;
    let rebuilt_object = emit_object(
        &rebuilt,
        ObjectFormat::for_target(artifact.receipt.target),
        artifact.receipt.limits.max_object_bytes,
    )?;
    let text = module_text(&rebuilt)?;
    let data = module_data(&rebuilt)?;
    let code_sha256 = <[u8; 32]>::from(Sha256::digest(text));
    let object_sha256 = <[u8; 32]>::from(Sha256::digest(&rebuilt_object));
    let receipt = &artifact.receipt;
    if receipt.abi_version != REGEX_SET_GRAPH_EXISTS_AOT_V1_ABI_VERSION
        || receipt.data_schema_version != REGEX_SET_GRAPH_EXISTS_AOT_V1_DATA_SCHEMA_VERSION
        || receipt.target != artifact.module.target()
        || receipt.source_graph_schema_version != source.schema_version()
        || receipt.source_artifact_identity != *source.source_artifact().as_bytes()
        || receipt.source_graph_identity != *source.artifact_identity().as_bytes()
        || receipt.source_pattern_count != source.pattern_count()
        || receipt.all_pattern_mask != source.all_pattern_mask()
        || receipt.operation_identity_sha256 != operation_identity_sha256
        || receipt.dense_data_sha256 != dense_data_sha256
        || receipt.code_sha256 != code_sha256
        || receipt.object_sha256 != object_sha256
        || receipt.entry_symbol != rebuilt.entry_symbol()
        || receipt.state_count != state_count
        || usize::try_from(source.state_count()).ok() != Some(state_count)
        || receipt.dense_transition_cells != dense_transition_cells
        || receipt.dense_build_steps != dense_build_steps
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
        return Err(RegexSetFinite64AotErrorV1::InternalInvariant(
            "deterministic generic graph native artifact closure",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn interpret_dense(
    image: &RegexSetGraphDenseImageV1,
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
        state_count: image.state_count,
        transition_cells: image.transition_cells,
        build_steps: image.build_steps,
        transition_offset: image.transition_offset,
        output_offset: image.output_offset,
        data_bytes: image.data.len(),
    };
    let mut state = 0usize;
    let mut matched = 0_u64;
    for &byte in &haystack[start..end] {
        state = usize::try_from(
            read_u32(
                &image.data,
                transition_cell_offset(geometry, state, byte).map_err(|_| ())?,
                "test dense transition read",
            )
            .map_err(|_| ())?,
        )
        .map_err(|_| ())?;
        let offset = image
            .output_offset
            .checked_add(state.checked_mul(8).ok_or(())?)
            .ok_or(())?;
        matched |= image
            .data
            .get(offset..offset.checked_add(8).ok_or(())?)
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
        CompileMode, FeatureSet, OperatingSystem, RegexSetCompileRequest,
        RegexSetFinite64CompileDisposition, RegexSetFinite64Limits, SearchWindow,
        compile_regex_set_finite64_reported,
    };

    fn selected(patterns: &[&str]) -> RegexSetFinite64Program {
        selected_owned(
            patterns
                .iter()
                .map(|pattern| (*pattern).to_owned())
                .collect(),
        )
    }

    fn selected_owned(patterns: Vec<String>) -> RegexSetFinite64Program {
        let request = RegexSetCompileRequest::new(patterns).mode(CompileMode::Optimizing);
        match compile_regex_set_finite64_reported(request, RegexSetFinite64Limits::default())
            .expect("portable Finite64 compile")
        {
            RegexSetFinite64CompileDisposition::Selected(program) => program,
            RegexSetFinite64CompileDisposition::Declined { reason, .. } => {
                panic!("unexpected portable Finite64 decline: {reason}")
            }
        }
    }

    #[test]
    fn two_and_sixty_four_source_boundaries_select_and_publish_exact_masks() {
        for count in [2usize, 64] {
            let patterns = (0..count)
                .map(|index| format!("public_literal_{index:02}"))
                .collect::<Vec<_>>();
            let haystack = patterns.join("|").into_bytes();
            let program = selected_owned(patterns);
            assert_eq!(
                u8::try_from(count).unwrap(),
                program.receipt().pattern_count()
            );
            let expected = if count == 64 {
                u64::MAX
            } else {
                (1_u64 << count) - 1
            };
            assert_eq!(expected, program.receipt().all_pattern_mask());
            let image = image(&program);
            let mut dense = 0;
            interpret_dense(&image, expected, &haystack, 0, haystack.len(), &mut dense)
                .expect("boundary dense scan");
            assert_eq!(expected, dense);
            let artifact = native(program);
            assert!(artifact.authenticates_receipt());
            assert_eq!(
                u8::try_from(count).unwrap(),
                artifact.receipt().source_pattern_count()
            );
            assert_eq!(expected, artifact.receipt().all_pattern_mask());
        }
    }

    fn image(program: &RegexSetFinite64Program) -> RegexSetGraphDenseImageV1 {
        match build_dense_image(program, RegexSetFinite64AotLimitsV1::default())
            .expect("dense image build")
        {
            DenseBuildDisposition::Built(image) => image,
            DenseBuildDisposition::Declined { .. } => panic!("unexpected dense image decline"),
        }
    }

    fn native(program: RegexSetFinite64Program) -> RegexSetFinite64AotArtifactV1 {
        match compile_regex_set_finite64_aot_v1(
            program,
            Target::aarch64_linux(),
            RegexSetFinite64AotLimitsV1::default(),
        )
        .expect("generic graph native compile")
        {
            RegexSetFinite64AotCompileDispositionV1::Selected(artifact) => artifact,
            RegexSetFinite64AotCompileDispositionV1::Declined { reason, .. } => {
                panic!("unexpected generic graph native decline: {reason}")
            }
        }
    }

    #[test]
    fn dense_scan_matches_portable_for_duplicates_multiple_owners_and_failure_outputs() {
        let program = selected(&[
            "(?:he|she)",
            "(?:hers|he)",
            "he",
            "(?:a|aa)",
            "(?:she|x)",
            "(?:ers|q)",
        ]);
        let image = image(&program);
        let haystacks = [
            b"".as_slice(),
            b"ushers".as_slice(),
            b"zaa".as_slice(),
            b"she".as_slice(),
            b"nothing".as_slice(),
            b"xxhersq".as_slice(),
        ];
        for haystack in haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let mut portable = u64::MAX;
                    program
                        .fill_matches(haystack, SearchWindow::new(start, end), &mut portable)
                        .expect("portable Finite64 scan");
                    let mut dense = u64::MAX;
                    let count = interpret_dense(
                        &image,
                        program.receipt().all_pattern_mask(),
                        haystack,
                        start,
                        end,
                        &mut dense,
                    )
                    .expect("dense model scan");
                    assert_eq!(portable, dense, "{haystack:?} {start}..{end}");
                    assert_eq!(portable.count_ones(), count);
                }
            }
        }
    }

    #[test]
    fn dense_model_is_transactional_on_invalid_window() {
        let program = selected(&["ab", "bc"]);
        let image = image(&program);
        let sentinel = 0xfeed_face_dead_beef;
        let mut output = sentinel;
        assert_eq!(
            Err(()),
            interpret_dense(
                &image,
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
    fn only_explicit_numeric_caps_decline_and_retain_the_same_owner() {
        let program = selected(&["(?:ab|cab)", "(?:bc|abc)", "ab"]);
        let receipt = program.receipt();
        let cases = [
            (
                RegexSetFinite64AotResourceV1::DenseTransitionCells,
                RegexSetFinite64AotLimitsV1 {
                    max_dense_transition_cells: 0,
                    ..RegexSetFinite64AotLimitsV1::default()
                },
            ),
            (
                RegexSetFinite64AotResourceV1::DenseBuildSteps,
                RegexSetFinite64AotLimitsV1 {
                    max_dense_build_steps: 0,
                    ..RegexSetFinite64AotLimitsV1::default()
                },
            ),
            (
                RegexSetFinite64AotResourceV1::DenseDataBytes,
                RegexSetFinite64AotLimitsV1 {
                    max_dense_data_bytes: 0,
                    ..RegexSetFinite64AotLimitsV1::default()
                },
            ),
            (
                RegexSetFinite64AotResourceV1::CodeBytes,
                RegexSetFinite64AotLimitsV1 {
                    max_code_bytes: 0,
                    ..RegexSetFinite64AotLimitsV1::default()
                },
            ),
            (
                RegexSetFinite64AotResourceV1::ObjectBytes,
                RegexSetFinite64AotLimitsV1 {
                    max_object_bytes: 0,
                    ..RegexSetFinite64AotLimitsV1::default()
                },
            ),
        ];
        for (expected_resource, limits) in cases {
            match compile_regex_set_finite64_aot_v1(
                program.clone(),
                Target::aarch64_linux(),
                limits,
            )
            .expect("numeric native decline")
            {
                RegexSetFinite64AotCompileDispositionV1::Declined {
                    program: declined,
                    reason:
                        RegexSetFinite64AotDeclineV1::Resource {
                            resource,
                            required,
                            limit: 0,
                        },
                } => {
                    assert_eq!(expected_resource, resource);
                    assert_ne!(0, required);
                    assert_eq!(receipt, declined.receipt());
                }
                other => panic!("unexpected numeric-cap disposition: {other:?}"),
            }
        }
    }

    #[test]
    fn unsupported_or_incoherent_targets_are_terminal() {
        let limits = RegexSetFinite64AotLimitsV1::default();
        assert!(matches!(
            compile_regex_set_finite64_aot_v1(
                selected(&["ab", "bc"]),
                Target::x86_64_linux(),
                limits,
            ),
            Err(RegexSetFinite64AotErrorV1::Object(
                ObjectError::InvalidModule("generic graph AOT requires a valid AArch64 target")
            ))
        ));
        let incoherent = Target {
            architecture: Architecture::Aarch64,
            operating_system: OperatingSystem::Linux,
            abi: CallAbi::SystemV,
            features: FeatureSet::EMPTY,
        };
        assert!(matches!(
            compile_regex_set_finite64_aot_v1(selected(&["ab", "bc"]), incoherent, limits),
            Err(RegexSetFinite64AotErrorV1::Object(
                ObjectError::UnsupportedTarget
            ))
        ));
    }

    #[test]
    fn allocator_failures_are_terminal_and_stop_all_later_allocation() {
        for structure in ["generic dense graph image", "generic dense depth order"] {
            let guard = TestReserveFaultGuard::arm(structure);
            let error = compile_regex_set_finite64_aot_v1(
                selected(&["ab", "bc"]),
                Target::aarch64_linux(),
                RegexSetFinite64AotLimitsV1::default(),
            )
            .expect_err("injected allocator failure must be terminal");
            assert!(matches!(
                error,
                RegexSetFinite64AotErrorV1::AllocationFailed {
                    structure: actual,
                    entries,
                } if actual == structure && entries != 0
            ));
            TEST_RESERVE_FAULT.with(|fault| assert_eq!(TestReserveFault::Failed, fault.get()));
            drop(guard);
        }
        let lowering = ObjectError::Allocation("synthetic generic graph lowering allocation");
        assert_eq!(
            Err(RegexSetFinite64AotErrorV1::Object(lowering.clone())),
            map_lowering_resource(lowering),
            "lowering allocator failure cannot become a numeric decline"
        );
    }

    #[test]
    fn malformed_dense_images_are_terminal_before_codegen() {
        let program = selected(&["(?:ab|cab)", "(?:bc|abc)", "ab"]);
        let source = program.receipt();
        let pristine = image(&program);
        let dense_data_sha256 = <[u8; 32]>::from(Sha256::digest(&pristine.data));
        let operation_identity_sha256 = operation_identity(
            Target::aarch64_linux(),
            source,
            dense_data_sha256,
            &pristine,
        )
        .expect("pristine operation identity");
        let lower = |image| {
            crate::module::lower_native_regex_set_graph_exists_aarch64_v1(
                Target::aarch64_linux(),
                operation_identity_sha256,
                source.schema_version(),
                *source.artifact_identity().as_bytes(),
                *source.source_artifact().as_bytes(),
                source.pattern_count(),
                source.all_pattern_mask(),
                image,
                RegexSetFinite64AotLimitsV1::default().max_code_bytes,
            )
        };

        let mut bad_header = image(&program);
        bad_header.data[HEADER_GRAPH_IDENTITY_OFFSET] ^= 1;
        assert!(matches!(
            lower(bad_header),
            Err(ObjectError::InvalidModule(
                "generic graph dense header identity"
            ))
        ));

        let mut bad_transition = image(&program);
        let cell = bad_transition.transition_offset;
        bad_transition.data[cell..cell + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            lower(bad_transition),
            Err(ObjectError::InvalidModule(
                "generic graph dense target is outside the graph"
            ))
        ));

        let mut in_range_transition = image(&program);
        let cell = in_range_transition.transition_offset;
        let original =
            u32::from_le_bytes(in_range_transition.data[cell..cell + 4].try_into().unwrap());
        let replacement = u32::from(original == 0);
        assert!(usize::try_from(replacement).unwrap() < in_range_transition.state_count);
        in_range_transition.data[cell..cell + 4].copy_from_slice(&replacement.to_le_bytes());
        assert!(matches!(
            lower(in_range_transition),
            Err(ObjectError::InvalidModule(
                "generic graph operation identity does not authenticate dense image"
            ))
        ));

        let mut bad_output = image(&program);
        let output = bad_output.output_offset + 8;
        bad_output.data[output..output + 8].copy_from_slice(&(1_u64 << 63).to_le_bytes());
        assert!(matches!(
            lower(bad_output),
            Err(ObjectError::InvalidModule(
                "generic graph dense output mask is invalid"
            ))
        ));
    }

    #[test]
    fn selected_object_is_helper_free_internally_closed_and_receipt_bound() {
        let mut artifact = native(selected(&[
            "(?:alpha|alphabet)",
            "(?:beta|eta)",
            "alpha",
            "(?:eta|theta)",
        ]));
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
        assert!(
            artifact
                .module()
                .symbols()
                .iter()
                .all(|symbol| symbol.section.is_some()),
            "the standalone object has no undefined symbol"
        );
        assert_eq!(
            1,
            artifact
                .module()
                .symbols()
                .iter()
                .filter(|symbol| {
                    symbol.binding == crate::SymbolBinding::Global
                        && symbol.kind == crate::SymbolKind::Function
                })
                .count()
        );
        assert_eq!(4, artifact.module().relocations().len());
        assert!(artifact.module().relocations().iter().all(|relocation| {
            artifact
                .module()
                .symbols()
                .get(relocation.symbol)
                .is_some_and(|symbol| symbol.binding == crate::SymbolBinding::Local)
        }));
        let text = module_text(artifact.module()).expect("native text");
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
            "the sole publication instruction is STR X7, [X4]"
        );
        assert!(
            words
                .iter()
                .all(|instruction| instruction & 0xfc00_0000 != 0x9400_0000),
            "the helper-free entry contains no BL instruction"
        );

        artifact.object[0] ^= 1;
        assert!(!artifact.authenticates_receipt());
        artifact.object[0] ^= 1;
        assert!(artifact.authenticates_receipt());
        artifact.receipt.object_sha256[0] ^= 1;
        assert!(!artifact.authenticates_receipt());
    }

    #[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "macos")))]
    #[test]
    #[ignore = "links and executes the generic graph object on an AArch64 host"]
    #[allow(
        clippy::too_many_lines,
        reason = "one linked generated differential binds the raw ABI, every-window masks, and invalid-call transaction checks"
    )]
    fn linked_host_generated_windows_match_portable_and_preserve_invalid_output() {
        use std::{fmt::Write as _, fs, process::Command};

        let target = if cfg!(target_os = "linux") {
            Target::aarch64_linux()
        } else {
            Target::aarch64_macos()
        };
        let program = selected(&[
            "(?:ab|cab)",
            "(?:bc|abc)",
            "ab",
            "(?:a|aa)",
            "(?:bab|zz)",
            "(?:cab|ab)",
            "x[0-2]",
            "(?:aba|ba)",
            r"(?-u:\xFF(?:x|y))",
        ]);
        let artifact = match compile_regex_set_finite64_aot_v1(
            program,
            target,
            RegexSetFinite64AotLimitsV1::default(),
        )
        .expect("native generic graph compile")
        {
            RegexSetFinite64AotCompileDispositionV1::Selected(artifact) => artifact,
            RegexSetFinite64AotCompileDispositionV1::Declined { reason, .. } => {
                panic!("unexpected native decline: {reason}")
            }
        };
        let directory = std::env::temp_dir().join(format!(
            "fre-aot-regex-set-graph-exists-aarch64-{}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("create linked fixture directory");
        let object = directory.join("regex_set_graph_exists.o");
        fs::write(&object, artifact.object()).expect("write generic graph object");
        let symbol = artifact.module().entry_symbol();
        let mut source = format!(
            "#include <stdint.h>\n#include <stddef.h>\n#include <string.h>\nextern uint32_t {symbol}(const unsigned char*,size_t,size_t,size_t,uint64_t*);\n"
        );
        let mut haystacks = vec![
            Vec::new(),
            b"abcabazzx1".to_vec(),
            b"nothing".to_vec(),
            b"cabbabcaa".to_vec(),
            vec![0xff, b'x', b'a', 0xff, b'y'],
        ];
        let alphabet = b"abcxyz012";
        let mut state = 0x243f_6a88_85a3_08d3_u64;
        for length in [1usize, 2, 3, 7, 16, 31] {
            let mut generated = Vec::with_capacity(length);
            for _ in 0..length {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let random = usize::try_from(state >> 32).expect("upper u32 fits usize");
                generated.push(alphabet[random % alphabet.len()]);
            }
            haystacks.push(generated);
        }
        let mut calls = String::from(
            "int main(void){uint64_t r;size_t i,j,k;uint32_t s;const uint64_t sentinel=UINT64_C(0xfeedfacedeadbeef);\n",
        );
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
                        .expect("portable generated result");
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
                haystack_index + 10
            )
            .unwrap();
        }
        writeln!(
            calls,
            "r=sentinel;s={symbol}(h1,10,2,1,&r);if(s!=2||r!=sentinel)return 80;"
        )
        .unwrap();
        writeln!(
            calls,
            "r=sentinel;s={symbol}(h1,10,0,11,&r);if(s!=2||r!=sentinel)return 81;"
        )
        .unwrap();
        writeln!(
            calls,
            "s={symbol}(h1,10,0,10,(uint64_t*)0);if(s!=2)return 82;"
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
        writeln!(
            calls,
            "r=sentinel;s={symbol}((const unsigned char*)UINTPTR_MAX,1,0,0,&r);if(s!=2||r!=sentinel)return 85;"
        )
        .unwrap();
        writeln!(
            calls,
            "unsigned char unaligned[16];memset(unaligned,0xa5,sizeof(unaligned));s={symbol}(h1,10,0,10,(uint64_t*)(unaligned+1));if(s!=2)return 86;for(i=0;i<sizeof(unaligned);i++)if(unaligned[i]!=0xa5)return 87;"
        )
        .unwrap();
        calls.push_str("return 0;}\n");
        source.push_str(&calls);
        let c_path = directory.join("regex_set_graph_exists.c");
        fs::write(&c_path, source).expect("write linked C harness");
        let executable = directory.join("regex_set_graph_exists");
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
            .expect("execute linked generic graph fixture");
        assert!(
            run.status.success(),
            "run status={:?} stdout={} stderr={}",
            run.status.code(),
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );
    }
}
