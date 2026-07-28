use core::marker::PhantomData;

use crate::{
    AbiVersion, ArithmeticSite, Block, BlockId, BlockOp, ByteClass, CacheIdentity, DataBlob,
    DataId, InvalidProgram, Operation, RawProgram, ResourceKind, SemanticsVersion,
    SerializedProgram, ValidateError,
    serialize::{identity_inline_scratch_bytes, serialization_inline_scratch_bytes, serialize},
};

const HARD_MAX_BLOCKS: usize = 64;
const RESOURCE_ACCOUNTING_VERSION: u16 = 2;
const DEFAULT_CONSTRUCTION_BYTES: u64 = 4 << 20;
const RAW_HEADER_CHECK_WORK: u64 = 4;
// One hash can materialize a digest, a staging identity and retained identity
// storage. These constants deliberately charge the non-elided copy model.
const IDENTITY_INITIALIZATION_WORK_PER_HASH: u64 = 128;
const IDENTITY_COPY_WORK_PER_HASH: u64 = 96;

/// Hard admission limits for an untrusted raw program.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidateLimits {
    pub max_blocks: u64,
    pub max_instructions: u64,
    pub max_data_blobs: u64,
    pub max_data_bytes: u64,
    pub max_serialized_bytes: u64,
    pub max_serialized_capacity_bytes: u64,
    pub max_construction_allocation_bytes: u64,
    pub max_raw_program_capacity_bytes: u64,
    pub max_estimated_code_bytes: u64,
    pub max_validation_work: u64,
    pub max_construction_work: u64,
    pub max_validation_scratch_bytes: u64,
    pub max_validation_phase_bytes: u64,
    pub max_serialization_phase_bytes: u64,
    pub max_identity_phase_bytes: u64,
    pub max_retained_program_bytes: u64,
    pub max_work_factor: u64,
}

impl Default for ValidateLimits {
    fn default() -> Self {
        Self {
            max_blocks: 64,
            max_instructions: 64,
            max_data_blobs: 16,
            max_data_bytes: 1 << 20,
            max_serialized_bytes: (1 << 20) + 4_096,
            max_serialized_capacity_bytes: (1 << 20) + 4_096,
            max_construction_allocation_bytes: DEFAULT_CONSTRUCTION_BYTES,
            max_raw_program_capacity_bytes: 2 << 20,
            max_estimated_code_bytes: 1 << 20,
            max_validation_work: 8 << 20,
            max_construction_work: 16 << 20,
            max_validation_scratch_bytes: 4_096,
            max_validation_phase_bytes: DEFAULT_CONSTRUCTION_BYTES,
            max_serialization_phase_bytes: DEFAULT_CONSTRUCTION_BYTES,
            max_identity_phase_bytes: DEFAULT_CONSTRUCTION_BYTES,
            max_retained_program_bytes: DEFAULT_CONSTRUCTION_BYTES,
            max_work_factor: (1 << 20) + 16,
        }
    }
}

/// Versioned resource receipt for validation and fixed-shape construction.
///
/// Work is denominated in conservative logical touches: one admitted
/// initialized storage byte, one copied byte, one hashed byte, or one
/// validator step.
/// Capacity and phase fields use observed allocator capacities, not requested
/// logical lengths. `allocation_request_bytes` covers allocations performed
/// by this construction call: raw fixed-shape allocations plus serialization
/// for the builders, and serialization alone for caller-supplied raw input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceAccounting {
    version: u16,
    allocation_requests: u8,
    literal_allocation_request_bytes: usize,
    block_allocation_request_bytes: usize,
    data_table_allocation_request_bytes: usize,
    raw_allocation_request_bytes: usize,
    serialized_allocation_request_bytes: usize,
    allocation_request_bytes: usize,
    literal_capacity_bytes: usize,
    block_capacity_bytes: usize,
    data_table_capacity_bytes: usize,
    raw_program_capacity_bytes: usize,
    serialized_capacity_bytes: usize,
    planning_work: u64,
    initialization_work: u64,
    copy_work: u64,
    hash_invocations: u8,
    hash_work: u64,
    validation_work: u64,
    validation_work_upper_bound: u64,
    construction_work: u64,
    validation_scratch_bytes: usize,
    validation_phase_peak_bytes: usize,
    serialization_phase_peak_bytes: usize,
    identity_phase_peak_bytes: usize,
    retained_program_bytes: usize,
}

impl ResourceAccounting {
    /// Current construction-resource accounting contract.
    pub const VERSION: u16 = RESOURCE_ACCOUNTING_VERSION;

    #[must_use]
    pub const fn version(self) -> u16 {
        self.version
    }

    #[must_use]
    pub const fn allocation_requests(self) -> u8 {
        self.allocation_requests
    }

    #[must_use]
    pub const fn literal_allocation_request_bytes(self) -> usize {
        self.literal_allocation_request_bytes
    }

    #[must_use]
    pub const fn block_allocation_request_bytes(self) -> usize {
        self.block_allocation_request_bytes
    }

    #[must_use]
    pub const fn data_table_allocation_request_bytes(self) -> usize {
        self.data_table_allocation_request_bytes
    }

    #[must_use]
    pub const fn raw_allocation_request_bytes(self) -> usize {
        self.raw_allocation_request_bytes
    }

    #[must_use]
    pub const fn serialized_allocation_request_bytes(self) -> usize {
        self.serialized_allocation_request_bytes
    }

    #[must_use]
    pub const fn allocation_request_bytes(self) -> usize {
        self.allocation_request_bytes
    }

    #[must_use]
    pub const fn literal_capacity_bytes(self) -> usize {
        self.literal_capacity_bytes
    }

    #[must_use]
    pub const fn block_capacity_bytes(self) -> usize {
        self.block_capacity_bytes
    }

    #[must_use]
    pub const fn data_table_capacity_bytes(self) -> usize {
        self.data_table_capacity_bytes
    }

    #[must_use]
    pub const fn raw_program_capacity_bytes(self) -> usize {
        self.raw_program_capacity_bytes
    }

    #[must_use]
    pub const fn serialized_capacity_bytes(self) -> usize {
        self.serialized_capacity_bytes
    }

    #[must_use]
    pub const fn planning_work(self) -> u64 {
        self.planning_work
    }

    #[must_use]
    pub const fn initialization_work(self) -> u64 {
        self.initialization_work
    }

    #[must_use]
    pub const fn copy_work(self) -> u64 {
        self.copy_work
    }

    #[must_use]
    pub const fn hash_invocations(self) -> u8 {
        self.hash_invocations
    }

    #[must_use]
    pub const fn hash_work(self) -> u64 {
        self.hash_work
    }

    #[must_use]
    pub const fn validation_work(self) -> u64 {
        self.validation_work
    }

    #[must_use]
    pub const fn validation_work_upper_bound(self) -> u64 {
        self.validation_work_upper_bound
    }

    #[must_use]
    pub const fn construction_work(self) -> u64 {
        self.construction_work
    }

    #[must_use]
    pub const fn validation_scratch_bytes(self) -> usize {
        self.validation_scratch_bytes
    }

    #[must_use]
    pub const fn validation_phase_peak_bytes(self) -> usize {
        self.validation_phase_peak_bytes
    }

    #[must_use]
    pub const fn serialization_phase_peak_bytes(self) -> usize {
        self.serialization_phase_peak_bytes
    }

    #[must_use]
    pub const fn identity_phase_peak_bytes(self) -> usize {
        self.identity_phase_peak_bytes
    }

    #[must_use]
    pub const fn retained_program_bytes(self) -> usize {
        self.retained_program_bytes
    }
}

/// Auditable dimensions and conservative backend/search costs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProgramStats {
    blocks: usize,
    instructions: usize,
    data_blobs: usize,
    data_bytes: usize,
    serialized_bytes: usize,
    estimated_code_bytes: usize,
    work_factor: u64,
    resources: ResourceAccounting,
}

impl ProgramStats {
    #[must_use]
    pub const fn blocks(self) -> usize {
        self.blocks
    }

    /// Number of operations. Kernel IR v1 has exactly one operation per block.
    #[must_use]
    pub const fn instructions(self) -> usize {
        self.instructions
    }

    #[must_use]
    pub const fn data_blobs(self) -> usize {
        self.data_blobs
    }

    #[must_use]
    pub const fn data_bytes(self) -> usize {
        self.data_bytes
    }

    #[must_use]
    pub const fn serialized_bytes(self) -> usize {
        self.serialized_bytes
    }

    /// Retained serializer allocation, including allocator-rounded capacity.
    #[must_use]
    pub const fn serialized_capacity_bytes(self) -> usize {
        self.resources.serialized_capacity_bytes
    }

    #[must_use]
    pub const fn estimated_code_bytes(self) -> usize {
        self.estimated_code_bytes
    }

    #[must_use]
    pub const fn validation_work(self) -> u64 {
        self.resources.validation_work
    }

    #[must_use]
    pub const fn work_factor(self) -> u64 {
        self.work_factor
    }

    #[must_use]
    pub const fn resources(self) -> ResourceAccounting {
        self.resources
    }
}

/// Immutable program that passed structural, resource and flow validation.
#[derive(Debug)]
pub struct ValidatedProgram<O: Operation> {
    pub(crate) raw: RawProgram,
    stats: ProgramStats,
    serialized: SerializedProgram,
    operation: PhantomData<O>,
}

impl<O: Operation> ValidatedProgram<O> {
    #[must_use]
    pub const fn stats(&self) -> ProgramStats {
        self.stats
    }

    #[must_use]
    pub const fn raw(&self) -> &RawProgram {
        &self.raw
    }

    #[must_use]
    pub const fn serialized(&self) -> &SerializedProgram {
        &self.serialized
    }

    #[must_use]
    pub const fn cache_identity(&self) -> CacheIdentity {
        self.serialized.identity()
    }

    /// Conservative portable-oracle work bound for a window width.
    pub fn conservative_work_bound(&self, window_width: usize) -> Result<u64, ValidateError> {
        let width = u64::try_from(window_width).map_err(|_| ValidateError::ArithmeticOverflow {
            site: ArithmeticSite::SearchWorkBound,
        })?;
        width
            .checked_add(1)
            .and_then(|positions| positions.checked_mul(self.stats.work_factor))
            .and_then(|work| work.checked_add(8))
            .ok_or(ValidateError::ArithmeticOverflow {
                site: ArithmeticSite::SearchWorkBound,
            })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ConstructionSeed {
    pub(crate) raw_allocation_requests: u8,
    pub(crate) literal_allocation_request_bytes: usize,
    pub(crate) block_allocation_request_bytes: usize,
    pub(crate) data_table_allocation_request_bytes: usize,
    pub(crate) allocation_request_bytes: usize,
    pub(crate) planning_work: u64,
    pub(crate) initialization_work: u64,
    pub(crate) copy_work: u64,
    pub(crate) additional_hash_invocations: u8,
    pub(crate) additional_hash_work: u64,
    pub(crate) additional_retained_bytes: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct FixedShapeAdmission {
    dimensions: Dimensions,
    seed: ConstructionSeed,
    raw_metadata_planning_work: u64,
}

impl FixedShapeAdmission {
    #[expect(
        clippy::too_many_arguments,
        reason = "the audited fixed-shape receipt lists each independent resource component"
    )]
    pub(crate) fn new(
        blocks: usize,
        data_blobs: usize,
        serialized_bytes: usize,
        raw_allocation_requests: u8,
        literal_allocation_request_bytes: usize,
        block_allocation_request_bytes: usize,
        data_table_allocation_request_bytes: usize,
        planning_work: u64,
        raw_initialization_work: u64,
        raw_copy_work: u64,
        validation_work_upper_bound: u64,
        additional_hash_invocations: u8,
        additional_hash_work: u64,
        additional_retained_bytes: usize,
    ) -> Result<Self, ValidateError> {
        let serialized_bytes_u64 =
            u64::try_from(serialized_bytes).map_err(|_| ValidateError::ArithmeticOverflow {
                site: ArithmeticSite::SerializedBytes,
            })?;
        let raw_allocation_request_bytes = literal_allocation_request_bytes
            .checked_add(block_allocation_request_bytes)
            .and_then(|bytes| bytes.checked_add(data_table_allocation_request_bytes))
            .ok_or(ValidateError::ArithmeticOverflow {
                site: ArithmeticSite::ConstructionAllocationBytes,
            })?;
        Ok(Self {
            dimensions: Dimensions {
                data_bytes: 0,
                serialized_bytes,
                serialized_bytes_u64,
                estimated_code_bytes: 0,
                work_factor: 0,
                raw_program_capacity_bytes: raw_allocation_request_bytes,
                literal_capacity_bytes: 0,
                block_capacity_bytes: 0,
                data_table_capacity_bytes: 0,
                validation_work_upper_bound,
            },
            seed: ConstructionSeed {
                raw_allocation_requests,
                literal_allocation_request_bytes,
                block_allocation_request_bytes,
                data_table_allocation_request_bytes,
                allocation_request_bytes: raw_allocation_request_bytes,
                planning_work,
                initialization_work: raw_initialization_work,
                copy_work: raw_copy_work,
                additional_hash_invocations,
                additional_hash_work,
                additional_retained_bytes,
            },
            raw_metadata_planning_work: raw_metadata_planning_envelope(blocks, data_blobs)?
                .total()?,
        })
    }

    pub(crate) fn admit<O: Operation>(
        mut self,
        observed_raw_capacity_bytes: usize,
        limits: ValidateLimits,
    ) -> Result<(), ValidateError> {
        self.dimensions.raw_program_capacity_bytes = observed_raw_capacity_bytes;
        let mut prospective_seed = self.seed;
        prospective_seed.planning_work = prospective_seed
            .planning_work
            .checked_add(self.raw_metadata_planning_work)
            .ok_or(ValidateError::ArithmeticOverflow {
                site: ArithmeticSite::ConstructionWork,
            })?;
        let work = ConstructionWork::new(self.dimensions, prospective_seed)?;
        admit_prospective::<O>(self.dimensions, work, limits)
    }

    pub(crate) const fn seed(self) -> ConstructionSeed {
        self.seed
    }
}

pub(crate) fn fixed_shape_validation_work_upper_bound(
    blocks: usize,
    data_blobs: usize,
    comparison_work: u64,
) -> Result<u64, ValidateError> {
    let blocks = u64::try_from(blocks).map_err(|_| ValidateError::ArithmeticOverflow {
        site: ArithmeticSite::ValidationWork,
    })?;
    let data = u64::try_from(data_blobs).map_err(|_| ValidateError::ArithmeticOverflow {
        site: ArithmeticSite::ValidationWork,
    })?;
    validation_work_formula(blocks, data, comparison_work)
}

#[derive(Clone, Copy)]
struct RawMetadataPlanningEnvelope {
    header: u64,
    block_census: u64,
    data_census: u64,
    comparison_scan: u64,
    pair_planning: u64,
}

impl RawMetadataPlanningEnvelope {
    fn total(self) -> Result<u64, ValidateError> {
        self.header
            .checked_add(self.block_census)
            .and_then(|work| work.checked_add(self.data_census))
            .and_then(|work| work.checked_add(self.comparison_scan))
            .and_then(|work| work.checked_add(self.pair_planning))
            .ok_or(ValidateError::ArithmeticOverflow {
                site: ArithmeticSite::ConstructionWork,
            })
    }
}

fn raw_metadata_planning_envelope(
    blocks: usize,
    data_blobs: usize,
) -> Result<RawMetadataPlanningEnvelope, ValidateError> {
    let blocks = u64::try_from(blocks).map_err(|_| ValidateError::ArithmeticOverflow {
        site: ArithmeticSite::ConstructionWork,
    })?;
    let data = u64::try_from(data_blobs).map_err(|_| ValidateError::ArithmeticOverflow {
        site: ArithmeticSite::ConstructionWork,
    })?;
    // `blob_compare_work` reads the two data-entry headers for each unordered
    // pair. Literal contents are read only by the later admitted validator.
    let pair_planning =
        data.saturating_sub(1)
            .checked_mul(data)
            .ok_or(ValidateError::ArithmeticOverflow {
                site: ArithmeticSite::ConstructionWork,
            })?;
    Ok(RawMetadataPlanningEnvelope {
        header: RAW_HEADER_CHECK_WORK,
        block_census: blocks,
        data_census: data,
        comparison_scan: data,
        pair_planning,
    })
}

impl RawProgram {
    /// Validate an untrusted raw program for one compile-time output contract.
    pub fn validate<O: Operation>(
        self,
        limits: ValidateLimits,
    ) -> Result<ValidatedProgram<O>, ValidateError> {
        self.validate_accounted::<O>(limits, ConstructionSeed::default())
    }

    pub(crate) fn validate_accounted<O: Operation>(
        self,
        limits: ValidateLimits,
        mut seed: ConstructionSeed,
    ) -> Result<ValidatedProgram<O>, ValidateError> {
        let mut planning = PlanningMeter::new(seed.planning_work, limits.max_construction_work);
        planning.charge(RAW_HEADER_CHECK_WORK)?;
        validate_headers::<O>(&self)?;
        admit_raw_shape_counts(&self, limits)?;
        let metadata_planning = raw_metadata_planning_envelope(self.blocks.len(), self.data.len())?;
        let admitted_planning_work = seed
            .planning_work
            .checked_add(metadata_planning.total()?)
            .ok_or(ValidateError::ArithmeticOverflow {
                site: ArithmeticSite::ConstructionWork,
            })?;
        enforce_work(
            ResourceKind::ConstructionWork,
            admitted_planning_work,
            limits.max_construction_work,
        )?;
        let dimensions = preflight_dimensions(&self, limits, &mut planning)?;
        ensure_planning_complete(admitted_planning_work, planning.consumed)?;
        seed.planning_work = planning.consumed;
        let work = ConstructionWork::new(dimensions, seed)?;
        admit_prospective::<O>(dimensions, work, limits)?;

        let mut meter = WorkMeter::new(limits.max_validation_work);
        meter = Validator::new(&self, meter).run::<O>()?;
        let actual_validation_work = meter.consumed;
        let mut accounting = resource_accounting::<O>(
            dimensions,
            work,
            dimensions.serialized_bytes,
            actual_validation_work,
        )?;
        admit_accounting(accounting, limits)?;
        let serialized = serialize(
            &self,
            dimensions.serialized_bytes,
            limits.max_serialized_capacity_bytes,
            |capacity| {
                accounting =
                    resource_accounting::<O>(dimensions, work, capacity, actual_validation_work)?;
                admit_accounting(accounting, limits)
            },
        )?;
        let stats = ProgramStats {
            blocks: self.blocks.len(),
            instructions: self.blocks.len(),
            data_blobs: self.data.len(),
            data_bytes: dimensions.data_bytes,
            serialized_bytes: dimensions.serialized_bytes,
            estimated_code_bytes: dimensions.estimated_code_bytes,
            work_factor: dimensions.work_factor,
            resources: accounting,
        };
        Ok(ValidatedProgram {
            raw: self,
            stats,
            serialized,
            operation: PhantomData,
        })
    }
}

fn validate_headers<O: Operation>(raw: &RawProgram) -> Result<(), ValidateError> {
    if raw.schema_version != RawProgram::SCHEMA_VERSION {
        return Err(InvalidProgram::SchemaVersion {
            actual: raw.schema_version,
        }
        .into());
    }
    if raw.semantics != SemanticsVersion::CURRENT {
        return Err(InvalidProgram::SemanticsVersion {
            actual: raw.semantics.0,
        }
        .into());
    }
    if raw.abi != AbiVersion::CURRENT {
        return Err(InvalidProgram::AbiVersion { actual: raw.abi.0 }.into());
    }
    if raw.output != O::KIND {
        return Err(InvalidProgram::OutputContract.into());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FlowState {
    Initial,
    Cursor,
    Run,
    Match,
    Exhausted,
    Rejected,
}

struct Validator<'a> {
    raw: &'a RawProgram,
    meter: WorkMeter,
    reachable: [bool; HARD_MAX_BLOCKS],
    data_use: [u32; HARD_MAX_BLOCKS],
}

impl<'a> Validator<'a> {
    const fn new(raw: &'a RawProgram, meter: WorkMeter) -> Self {
        Self {
            raw,
            meter,
            reachable: [false; HARD_MAX_BLOCKS],
            data_use: [0; HARD_MAX_BLOCKS],
        }
    }

    fn run<O: Operation>(mut self) -> Result<WorkMeter, ValidateError> {
        self.validate_headers::<O>()?;
        self.validate_targets_and_flow()?;
        self.validate_reachability()?;
        self.validate_data()?;
        self.validate_topology_and_dominance()?;
        Ok(self.meter)
    }

    fn validate_headers<O: Operation>(&mut self) -> Result<(), ValidateError> {
        self.meter.charge(4)?;
        if self.raw.schema_version != RawProgram::SCHEMA_VERSION {
            return Err(InvalidProgram::SchemaVersion {
                actual: self.raw.schema_version,
            }
            .into());
        }
        if self.raw.semantics != SemanticsVersion::CURRENT {
            return Err(InvalidProgram::SemanticsVersion {
                actual: self.raw.semantics.0,
            }
            .into());
        }
        if self.raw.abi != AbiVersion::CURRENT {
            return Err(InvalidProgram::AbiVersion {
                actual: self.raw.abi.0,
            }
            .into());
        }
        if self.raw.output != O::KIND {
            return Err(InvalidProgram::OutputContract.into());
        }
        Ok(())
    }

    fn validate_targets_and_flow(&mut self) -> Result<(), ValidateError> {
        if self.raw.blocks.is_empty() {
            return Err(InvalidProgram::EmptyBlocks.into());
        }
        let entry = block_index(self.raw.entry)
            .filter(|index| *index < self.raw.blocks.len())
            .ok_or(InvalidProgram::EntryOutOfRange)?;
        if !matches!(self.raw.blocks[entry].op, BlockOp::Entry { .. }) {
            return Err(InvalidProgram::EntryIsNotEntry.into());
        }
        for (source, block) in self.raw.blocks.iter().enumerate() {
            self.meter.charge(1)?;
            let source_id = index_id(source)?;
            let (successors, count) = block.op.successors();
            let states = outgoing_states(&block.op);
            for edge in 0..count {
                self.meter.charge(1)?;
                let target = successors[edge].expect("successor count is exact");
                let target_index = block_index(target)
                    .filter(|index| *index < self.raw.blocks.len())
                    .ok_or(InvalidProgram::BlockTargetOutOfRange {
                        block: source_id,
                        target: target.0,
                    })?;
                if required_state(&self.raw.blocks[target_index].op) != states[edge] {
                    return Err(InvalidProgram::FlowStateMismatch { block: target.0 }.into());
                }
            }
            for data in referenced_data(&block.op).into_iter().flatten() {
                self.meter.charge(1)?;
                let data_index = data_index(data)
                    .filter(|index| *index < self.raw.data.len())
                    .ok_or(InvalidProgram::DataTargetOutOfRange {
                        block: source_id,
                        data: data.0,
                    })?;
                let usage =
                    self.data_use
                        .get_mut(data_index)
                        .ok_or(ValidateError::ResourceLimit {
                            resource: ResourceKind::DataBlobs,
                            limit: u64::try_from(HARD_MAX_BLOCKS).expect("small constant"),
                            required: u64::try_from(self.raw.data.len()).unwrap_or(u64::MAX),
                        })?;
                *usage = usage
                    .checked_add(1)
                    .ok_or(ValidateError::ArithmeticOverflow {
                        site: ArithmeticSite::ValidationWork,
                    })?;
                match (&block.op, &self.raw.data[data_index]) {
                    (
                        BlockOp::ScanLiteral { .. } | BlockOp::ConfirmSuffix { .. },
                        DataBlob::Bytes(_),
                    )
                    | (
                        BlockOp::ScanClassStart { .. } | BlockOp::ExtendClassRun { .. },
                        DataBlob::ByteClass(_),
                    ) => {}
                    _ => {
                        return Err(InvalidProgram::WrongDataKind {
                            block: source_id,
                            data: data.0,
                        }
                        .into());
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_reachability(&mut self) -> Result<(), ValidateError> {
        let mut stack = [0_usize; HARD_MAX_BLOCKS];
        let mut length = 1_usize;
        let entry =
            usize::try_from(self.raw.entry.0).map_err(|_| ValidateError::ArithmeticOverflow {
                site: ArithmeticSite::ValidationWork,
            })?;
        stack[0] = entry;
        self.reachable[entry] = true;
        while length != 0 {
            self.meter.charge(1)?;
            length = length
                .checked_sub(1)
                .expect("loop condition proves nonzero");
            let current = stack[length];
            let (successors, count) = self.raw.blocks[current].op.successors();
            for successor in successors.into_iter().take(count).flatten() {
                let index = usize::try_from(successor.0).map_err(|_| {
                    ValidateError::ArithmeticOverflow {
                        site: ArithmeticSite::ValidationWork,
                    }
                })?;
                if !self.reachable[index] {
                    self.reachable[index] = true;
                    stack[length] = index;
                    length = length
                        .checked_add(1)
                        .ok_or(ValidateError::ArithmeticOverflow {
                            site: ArithmeticSite::ValidationWork,
                        })?;
                }
            }
        }
        for (index, reachable) in self
            .reachable
            .iter()
            .copied()
            .take(self.raw.blocks.len())
            .enumerate()
        {
            self.meter.charge(1)?;
            if !reachable {
                return Err(InvalidProgram::UnreachableBlock {
                    block: index_id(index)?,
                }
                .into());
            }
        }
        Ok(())
    }

    fn validate_data(&mut self) -> Result<(), ValidateError> {
        for (index, blob) in self.raw.data.iter().enumerate() {
            self.meter.charge(1)?;
            if self.data_use[index] == 0 {
                return Err(InvalidProgram::UnusedData {
                    data: index_id(index)?,
                }
                .into());
            }
            if let DataBlob::ByteClass(class) = blob {
                self.meter.charge(4)?;
                if class.is_empty() {
                    return Err(InvalidProgram::EmptyClass {
                        data: index_id(index)?,
                    }
                    .into());
                }
            }
            for prior in 0..index {
                self.meter
                    .charge(blob_compare_work(blob, &self.raw.data[prior])?)?;
                if blob == &self.raw.data[prior] {
                    return Err(InvalidProgram::DuplicateData {
                        first: index_id(prior)?,
                        second: index_id(index)?,
                    }
                    .into());
                }
            }
        }
        Ok(())
    }

    fn validate_topology_and_dominance(&mut self) -> Result<(), ValidateError> {
        let mut entry = None;
        let mut literal = None;
        let mut scan_class = None;
        let mut extend = None;
        let mut confirm = None;
        let mut advance = None;
        let mut found = None;
        let mut none = None;
        for (index, block) in self.raw.blocks.iter().enumerate() {
            self.meter.charge(1)?;
            let id = BlockId(index_id(index)?);
            let slot = match block.op {
                BlockOp::Entry { .. } => &mut entry,
                BlockOp::ScanLiteral { .. } => &mut literal,
                BlockOp::ScanClassStart { .. } => &mut scan_class,
                BlockOp::ExtendClassRun { .. } => &mut extend,
                BlockOp::ConfirmSuffix { .. } => &mut confirm,
                BlockOp::AdvanceAfterReject { .. } => &mut advance,
                BlockOp::ReturnFound => &mut found,
                BlockOp::ReturnNone => &mut none,
            };
            if slot.replace(id).is_some() {
                return Err(InvalidProgram::NonCanonicalTopology { block: id.0 }.into());
            }
        }
        let entry = entry.ok_or(InvalidProgram::NonCanonicalTopology { block: 0 })?;
        let found = found.ok_or(InvalidProgram::NonCanonicalTopology { block: 0 })?;
        let none = none.ok_or(InvalidProgram::NonCanonicalTopology { block: 0 })?;
        if Some(entry) != Some(self.raw.entry) {
            return Err(InvalidProgram::EntryIsNotEntry.into());
        }
        if let Some(scan) = literal {
            if self.raw.blocks.len() != 4
                || scan_class.is_some()
                || extend.is_some()
                || confirm.is_some()
                || advance.is_some()
            {
                return Err(InvalidProgram::NonCanonicalTopology { block: scan.0 }.into());
            }
            self.require_literal_edges(entry, scan, found, none)?;
            self.require_dominates(scan, found)?;
            self.require_dominates(scan, none)?;
            return Ok(());
        }
        let scan = scan_class.ok_or(InvalidProgram::NonCanonicalTopology { block: entry.0 })?;
        let extend = extend.ok_or(InvalidProgram::NonCanonicalTopology { block: scan.0 })?;
        let confirm = confirm.ok_or(InvalidProgram::NonCanonicalTopology { block: extend.0 })?;
        let advance = advance.ok_or(InvalidProgram::NonCanonicalTopology { block: confirm.0 })?;
        if self.raw.blocks.len() != 7 {
            return Err(InvalidProgram::NonCanonicalTopology { block: entry.0 }.into());
        }
        self.require_class_edges(ClassShape {
            entry,
            scan,
            extend,
            confirm,
            advance,
            found,
            none,
        })?;
        self.require_dominates(scan, extend)?;
        self.require_dominates(extend, confirm)?;
        self.require_dominates(confirm, advance)?;
        self.require_dominates(confirm, found)?;
        Ok(())
    }

    fn require_literal_edges(
        &mut self,
        entry: BlockId,
        scan: BlockId,
        found: BlockId,
        none: BlockId,
    ) -> Result<(), ValidateError> {
        if !matches!(self.op(entry), BlockOp::Entry { next } if *next == scan)
            || !matches!(
                self.op(scan),
                BlockOp::ScanLiteral { matched, exhausted, .. }
                    if *matched == found && *exhausted == none
            )
        {
            return Err(InvalidProgram::NonCanonicalTopology { block: scan.0 }.into());
        }
        Ok(())
    }

    fn require_class_edges(&mut self, shape: ClassShape) -> Result<(), ValidateError> {
        let ClassShape {
            entry,
            scan,
            extend,
            confirm,
            advance,
            found,
            none,
        } = shape;
        self.meter.charge(7)?;
        if !matches!(self.op(entry), BlockOp::Entry { next } if *next == scan)
            || !matches!(
                self.op(scan),
                BlockOp::ScanClassStart { run, exhausted, .. }
                    if *run == extend && *exhausted == none
            )
            || !matches!(self.op(extend), BlockOp::ExtendClassRun { next, .. } if *next == confirm)
            || !matches!(
                self.op(confirm),
                BlockOp::ConfirmSuffix { matched, rejected, .. }
                    if *matched == found && *rejected == advance
            )
            || !matches!(self.op(advance), BlockOp::AdvanceAfterReject { next } if *next == scan)
        {
            return Err(InvalidProgram::InvalidCycle { block: advance.0 }.into());
        }
        let (scan_class, extend_class) = match (self.op(scan), self.op(extend)) {
            (
                BlockOp::ScanClassStart { class: scan, .. },
                BlockOp::ExtendClassRun { class: extend, .. },
            ) => (*scan, *extend),
            _ => unreachable!("block kinds established above"),
        };
        if scan_class != extend_class {
            return Err(InvalidProgram::NonCanonicalTopology { block: extend.0 }.into());
        }
        let suffix = match self.op(confirm) {
            BlockOp::ConfirmSuffix { suffix, .. } => *suffix,
            _ => unreachable!("block kind established above"),
        };
        let suffix_bytes = self.bytes(suffix, confirm)?;
        let Some(first) = suffix_bytes.first().copied() else {
            return Err(InvalidProgram::EmptySuffix { data: suffix.0 }.into());
        };
        let class = self.class(scan_class, scan)?;
        if class.contains(first) {
            return Err(InvalidProgram::SuffixOverlapsClass {
                class: scan_class.0,
                suffix: suffix.0,
            }
            .into());
        }
        Ok(())
    }

    fn require_dominates(
        &mut self,
        dominator: BlockId,
        target: BlockId,
    ) -> Result<(), ValidateError> {
        if self.reachable_avoiding(target, dominator)? {
            return Err(InvalidProgram::DominanceViolation {
                dominator: dominator.0,
                block: target.0,
            }
            .into());
        }
        Ok(())
    }

    fn reachable_avoiding(
        &mut self,
        target: BlockId,
        avoided: BlockId,
    ) -> Result<bool, ValidateError> {
        if self.raw.entry == avoided {
            return Ok(false);
        }
        let mut seen = [false; HARD_MAX_BLOCKS];
        let mut stack = [0_usize; HARD_MAX_BLOCKS];
        let mut length = 1_usize;
        let entry = usize::try_from(self.raw.entry.0).expect("entry index validated");
        stack[0] = entry;
        seen[entry] = true;
        while length != 0 {
            self.meter.charge(1)?;
            length = length
                .checked_sub(1)
                .expect("loop condition proves nonzero");
            let current = stack[length];
            let current_id = BlockId(index_id(current)?);
            if current_id == target {
                return Ok(true);
            }
            let (successors, count) = self.raw.blocks[current].op.successors();
            for successor in successors.into_iter().take(count).flatten() {
                let index = usize::try_from(successor.0).expect("targets validated");
                if successor != avoided && !seen[index] {
                    seen[index] = true;
                    stack[length] = index;
                    length = length
                        .checked_add(1)
                        .ok_or(ValidateError::ArithmeticOverflow {
                            site: ArithmeticSite::ValidationWork,
                        })?;
                }
            }
        }
        Ok(false)
    }

    fn op(&self, id: BlockId) -> &BlockOp {
        &self.raw.blocks[usize::try_from(id.0).expect("validated block id")].op
    }

    fn bytes(&self, id: DataId, block: BlockId) -> Result<&[u8], ValidateError> {
        match &self.raw.data[usize::try_from(id.0).expect("validated data id")] {
            DataBlob::Bytes(bytes) => Ok(bytes),
            DataBlob::ByteClass(_) => Err(InvalidProgram::WrongDataKind {
                block: block.0,
                data: id.0,
            }
            .into()),
        }
    }

    fn class(&self, id: DataId, block: BlockId) -> Result<ByteClass, ValidateError> {
        match self.raw.data[usize::try_from(id.0).expect("validated data id")] {
            DataBlob::ByteClass(class) => Ok(class),
            DataBlob::Bytes(_) => Err(InvalidProgram::WrongDataKind {
                block: block.0,
                data: id.0,
            }
            .into()),
        }
    }
}

#[derive(Clone, Copy)]
struct Dimensions {
    data_bytes: usize,
    serialized_bytes: usize,
    serialized_bytes_u64: u64,
    estimated_code_bytes: usize,
    work_factor: u64,
    raw_program_capacity_bytes: usize,
    literal_capacity_bytes: usize,
    block_capacity_bytes: usize,
    data_table_capacity_bytes: usize,
    validation_work_upper_bound: u64,
}

const SERIALIZED_HEADER_BYTES: usize = 27;

#[derive(Clone, Copy)]
struct DimensionCensus {
    serialized: Option<usize>,
    estimated_code: Option<usize>,
    longest_literal: usize,
}

impl DimensionCensus {
    const fn new() -> Self {
        Self {
            serialized: Some(SERIALIZED_HEADER_BYTES),
            estimated_code: Some(0),
            longest_literal: 0,
        }
    }

    fn observe_block(&mut self, op: &BlockOp) {
        let (serialized_bytes, estimated_code_bytes) = match op {
            BlockOp::Entry { .. } => (5, 16),
            BlockOp::ScanLiteral { .. } | BlockOp::ConfirmSuffix { .. } => (14, 160),
            BlockOp::ScanClassStart { .. } => (14, 192),
            BlockOp::ExtendClassRun { .. } => (9, 128),
            BlockOp::AdvanceAfterReject { .. } => (5, 32),
            BlockOp::ReturnFound | BlockOp::ReturnNone => (1, 32),
        };
        accumulate_checked(&mut self.serialized, Some(serialized_bytes));
        accumulate_checked(&mut self.estimated_code, Some(estimated_code_bytes));
    }

    fn observe_data(&mut self, blob: &DataBlob, payload_bytes: usize) {
        accumulate_checked(&mut self.serialized, payload_bytes.checked_add(5));
        let padded = payload_bytes.checked_add(15).map(|value| value & !15);
        accumulate_checked(&mut self.estimated_code, padded);
        if matches!(blob, DataBlob::Bytes(_)) {
            self.longest_literal = self.longest_literal.max(payload_bytes);
        }
    }

    fn finish(
        self,
        data_bytes: usize,
        limits: ValidateLimits,
    ) -> Result<Dimensions, ValidateError> {
        enforce_count(ResourceKind::DataBytes, data_bytes, limits.max_data_bytes)?;
        let serialized_bytes = self.serialized.ok_or(ValidateError::ArithmeticOverflow {
            site: ArithmeticSite::SerializedBytes,
        })?;
        let serialized_bytes_u64 = enforce_count(
            ResourceKind::SerializedBytes,
            serialized_bytes,
            limits.max_serialized_bytes,
        )?;
        enforce_count(
            ResourceKind::SerializedCapacityBytes,
            serialized_bytes,
            limits.max_serialized_capacity_bytes,
        )?;
        let estimated_code_bytes =
            self.estimated_code
                .ok_or(ValidateError::ArithmeticOverflow {
                    site: ArithmeticSite::EstimatedCodeBytes,
                })?;
        enforce_count(
            ResourceKind::EstimatedCodeBytes,
            estimated_code_bytes,
            limits.max_estimated_code_bytes,
        )?;
        let work_factor = u64::try_from(self.longest_literal)
            .ok()
            .and_then(|value| value.checked_add(8))
            .ok_or(ValidateError::ArithmeticOverflow {
                site: ArithmeticSite::WorkFactor,
            })?;
        if work_factor > limits.max_work_factor {
            return Err(ValidateError::ResourceLimit {
                resource: ResourceKind::WorkFactor,
                limit: limits.max_work_factor,
                required: work_factor,
            });
        }
        Ok(Dimensions {
            data_bytes,
            serialized_bytes,
            serialized_bytes_u64,
            estimated_code_bytes,
            work_factor,
            raw_program_capacity_bytes: 0,
            literal_capacity_bytes: 0,
            block_capacity_bytes: 0,
            data_table_capacity_bytes: 0,
            validation_work_upper_bound: 0,
        })
    }
}

fn accumulate_checked(total: &mut Option<usize>, increment: Option<usize>) {
    let Some(current) = *total else {
        return;
    };
    *total = increment.and_then(|increment| current.checked_add(increment));
}

fn admit_raw_shape_counts(raw: &RawProgram, limits: ValidateLimits) -> Result<(), ValidateError> {
    enforce_count(ResourceKind::Blocks, raw.blocks.len(), limits.max_blocks)?;
    enforce_count(
        ResourceKind::Instructions,
        raw.blocks.len(),
        limits.max_instructions,
    )?;
    enforce_count(
        ResourceKind::Blocks,
        raw.blocks.len(),
        u64::try_from(HARD_MAX_BLOCKS).expect("small constant"),
    )?;
    enforce_count(
        ResourceKind::DataBlobs,
        raw.data.len(),
        limits.max_data_blobs,
    )?;
    enforce_count(
        ResourceKind::DataBlobs,
        raw.data.len(),
        u64::try_from(HARD_MAX_BLOCKS).expect("small constant"),
    )?;
    Ok(())
}

fn preflight_dimensions(
    raw: &RawProgram,
    limits: ValidateLimits,
    planning: &mut PlanningMeter,
) -> Result<Dimensions, ValidateError> {
    enforce_count(
        ResourceKind::ValidationScratchBytes,
        validation_scratch_bytes()?,
        limits.max_validation_scratch_bytes,
    )?;
    let minimum_validation_work =
        fixed_shape_validation_work_upper_bound(raw.blocks.len(), raw.data.len(), 0)?;
    enforce_work(
        ResourceKind::ValidationWork,
        minimum_validation_work,
        limits.max_validation_work,
    )?;
    let block_capacity = raw
        .blocks
        .capacity()
        .checked_mul(core::mem::size_of::<Block>())
        .ok_or(ValidateError::ArithmeticOverflow {
            site: ArithmeticSite::PhasePeakBytes,
        })?;
    let data_table_capacity = raw
        .data
        .capacity()
        .checked_mul(core::mem::size_of::<DataBlob>())
        .ok_or(ValidateError::ArithmeticOverflow {
            site: ArithmeticSite::PhasePeakBytes,
        })?;
    let mut raw_capacity = block_capacity.checked_add(data_table_capacity).ok_or(
        ValidateError::ArithmeticOverflow {
            site: ArithmeticSite::PhasePeakBytes,
        },
    )?;
    let mut literal_capacity = 0_usize;
    enforce_count(
        ResourceKind::RawProgramCapacityBytes,
        raw_capacity,
        limits.max_raw_program_capacity_bytes,
    )?;

    // Census retained headers and payload lengths. The hard 64-slot bound
    // makes this a fixed-size metadata pass; it never reads literal contents.
    let mut census = DimensionCensus::new();
    for block in &raw.blocks {
        planning.charge(1)?;
        census.observe_block(&block.op);
    }
    let mut data_bytes = 0_usize;
    for blob in &raw.data {
        planning.charge(1)?;
        let bytes = match blob {
            DataBlob::Bytes(bytes) => {
                literal_capacity = literal_capacity.checked_add(bytes.capacity()).ok_or(
                    ValidateError::ArithmeticOverflow {
                        site: ArithmeticSite::PhasePeakBytes,
                    },
                )?;
                raw_capacity = raw_capacity.checked_add(bytes.capacity()).ok_or(
                    ValidateError::ArithmeticOverflow {
                        site: ArithmeticSite::PhasePeakBytes,
                    },
                )?;
                enforce_count(
                    ResourceKind::RawProgramCapacityBytes,
                    raw_capacity,
                    limits.max_raw_program_capacity_bytes,
                )?;
                bytes.len()
            }
            DataBlob::ByteClass(_) => 32,
        };
        enforce_count(ResourceKind::DataBytes, bytes, u64::from(u32::MAX))?;
        data_bytes = data_bytes
            .checked_add(bytes)
            .ok_or(ValidateError::ArithmeticOverflow {
                site: ArithmeticSite::DataBytes,
            })?;
        census.observe_data(blob, bytes);
    }
    let mut dimensions = census.finish(data_bytes, limits)?;
    dimensions.raw_program_capacity_bytes = raw_capacity;
    dimensions.literal_capacity_bytes = literal_capacity;
    dimensions.block_capacity_bytes = block_capacity;
    dimensions.data_table_capacity_bytes = data_table_capacity;
    dimensions.validation_work_upper_bound = validation_work_upper_bound(raw, planning)?;
    Ok(dimensions)
}

fn validation_scratch_bytes() -> Result<usize, ValidateError> {
    let traversal = HARD_MAX_BLOCKS
        .checked_mul(
            core::mem::size_of::<bool>()
                .checked_add(core::mem::size_of::<usize>())
                .ok_or(ValidateError::ArithmeticOverflow {
                    site: ArithmeticSite::PhasePeakBytes,
                })?,
        )
        .ok_or(ValidateError::ArithmeticOverflow {
            site: ArithmeticSite::PhasePeakBytes,
        })?;
    core::mem::size_of::<Validator<'static>>()
        .checked_add(traversal)
        .ok_or(ValidateError::ArithmeticOverflow {
            site: ArithmeticSite::PhasePeakBytes,
        })
}

fn validation_work_upper_bound(
    raw: &RawProgram,
    planning: &mut PlanningMeter,
) -> Result<u64, ValidateError> {
    let blocks =
        u64::try_from(raw.blocks.len()).map_err(|_| ValidateError::ArithmeticOverflow {
            site: ArithmeticSite::ValidationWork,
        })?;
    let data = u64::try_from(raw.data.len()).map_err(|_| ValidateError::ArithmeticOverflow {
        site: ArithmeticSite::ValidationWork,
    })?;
    let mut data_scan_work = 0_u64;
    for (index, blob) in raw.data.iter().enumerate() {
        planning.charge(1)?;
        if matches!(blob, DataBlob::ByteClass(_)) {
            data_scan_work =
                data_scan_work
                    .checked_add(4)
                    .ok_or(ValidateError::ArithmeticOverflow {
                        site: ArithmeticSite::ValidationWork,
                    })?;
        }
        for prior in &raw.data[..index] {
            planning.charge(2)?;
            record_pair_planning_step();
            data_scan_work = data_scan_work
                .checked_add(blob_compare_work(blob, prior)?)
                .ok_or(ValidateError::ArithmeticOverflow {
                    site: ArithmeticSite::ValidationWork,
                })?;
        }
    }
    validation_work_formula(blocks, data, data_scan_work)
}

fn validation_work_formula(
    blocks: u64,
    data_blobs: u64,
    additional_data_work: u64,
) -> Result<u64, ValidateError> {
    // Per block: target/data checks <= 4, reachability <= 2, topology 1 and at
    // most four dominance traversals. Per data entry: the primary data pass 1.
    // The fixed 11 covers the duplicate four-header validator pass and the
    // seven-edge class-shape check; literal shapes overpay it. The distinct
    // preflight census and comparison planner are construction planning work.
    blocks
        .checked_mul(11)
        .and_then(|work| work.checked_add(data_blobs))
        .and_then(|work| work.checked_add(additional_data_work))
        .and_then(|work| work.checked_add(11))
        .ok_or(ValidateError::ArithmeticOverflow {
            site: ArithmeticSite::ValidationWork,
        })
}

fn blob_compare_work(left: &DataBlob, right: &DataBlob) -> Result<u64, ValidateError> {
    let touches = match (left, right) {
        (DataBlob::Bytes(left), DataBlob::Bytes(right)) => left.len().min(right.len()),
        (DataBlob::ByteClass(_), DataBlob::ByteClass(_)) => 4,
        (DataBlob::Bytes(_), DataBlob::ByteClass(_))
        | (DataBlob::ByteClass(_), DataBlob::Bytes(_)) => 0,
    };
    u64::try_from(touches)
        .ok()
        .and_then(|touches| touches.checked_add(2))
        .ok_or(ValidateError::ArithmeticOverflow {
            site: ArithmeticSite::ValidationWork,
        })
}

#[derive(Clone, Copy)]
struct ConstructionWork {
    allocation_requests: u8,
    literal_allocation_request_bytes: usize,
    block_allocation_request_bytes: usize,
    data_table_allocation_request_bytes: usize,
    raw_allocation_request_bytes: usize,
    serialized_allocation_request_bytes: usize,
    allocation_request_bytes: usize,
    planning_work: u64,
    initialization_work: u64,
    copy_work: u64,
    hash_invocations: u8,
    hash_work: u64,
    total_upper_bound: u64,
    additional_retained_bytes: usize,
}

impl ConstructionWork {
    fn new(dimensions: Dimensions, seed: ConstructionSeed) -> Result<Self, ValidateError> {
        let allocation_requests = seed.raw_allocation_requests.checked_add(1).ok_or(
            ValidateError::ArithmeticOverflow {
                site: ArithmeticSite::ConstructionAllocationBytes,
            },
        )?;
        let allocation_request_bytes = seed
            .allocation_request_bytes
            .checked_add(dimensions.serialized_bytes)
            .ok_or(ValidateError::ArithmeticOverflow {
                site: ArithmeticSite::ConstructionAllocationBytes,
            })?;
        let hash_invocations = seed.additional_hash_invocations.checked_add(1).ok_or(
            ValidateError::ArithmeticOverflow {
                site: ArithmeticSite::ConstructionWork,
            },
        )?;
        let identity_initialization_work = u64::from(hash_invocations)
            .checked_mul(IDENTITY_INITIALIZATION_WORK_PER_HASH)
            .ok_or(ValidateError::ArithmeticOverflow {
                site: ArithmeticSite::ConstructionWork,
            })?;
        let identity_copy_work = u64::from(hash_invocations)
            .checked_mul(IDENTITY_COPY_WORK_PER_HASH)
            .ok_or(ValidateError::ArithmeticOverflow {
                site: ArithmeticSite::ConstructionWork,
            })?;
        let initialization_work = seed
            .initialization_work
            .checked_add(dimensions.serialized_bytes_u64)
            .and_then(|work| work.checked_add(identity_initialization_work))
            .ok_or(ValidateError::ArithmeticOverflow {
                site: ArithmeticSite::ConstructionWork,
            })?;
        let copy_work = seed
            .copy_work
            .checked_add(dimensions.serialized_bytes_u64)
            .and_then(|work| work.checked_add(identity_copy_work))
            .ok_or(ValidateError::ArithmeticOverflow {
                site: ArithmeticSite::ConstructionWork,
            })?;
        let hash_work = dimensions
            .serialized_bytes_u64
            .checked_add(seed.additional_hash_work)
            .ok_or(ValidateError::ArithmeticOverflow {
                site: ArithmeticSite::ConstructionWork,
            })?;
        let total_upper_bound = dimensions
            .validation_work_upper_bound
            .checked_add(seed.planning_work)
            .and_then(|work| work.checked_add(initialization_work))
            .and_then(|work| work.checked_add(copy_work))
            .and_then(|work| work.checked_add(hash_work))
            .ok_or(ValidateError::ArithmeticOverflow {
                site: ArithmeticSite::ConstructionWork,
            })?;
        Ok(Self {
            allocation_requests,
            literal_allocation_request_bytes: seed.literal_allocation_request_bytes,
            block_allocation_request_bytes: seed.block_allocation_request_bytes,
            data_table_allocation_request_bytes: seed.data_table_allocation_request_bytes,
            raw_allocation_request_bytes: seed.allocation_request_bytes,
            serialized_allocation_request_bytes: dimensions.serialized_bytes,
            allocation_request_bytes,
            planning_work: seed.planning_work,
            initialization_work,
            copy_work,
            hash_invocations,
            hash_work,
            total_upper_bound,
            additional_retained_bytes: seed.additional_retained_bytes,
        })
    }
}

#[derive(Clone, Copy)]
struct PhasePeaks {
    validation: usize,
    serialization: usize,
    identity: usize,
    retained: usize,
}

fn phase_peaks<O: Operation>(
    dimensions: Dimensions,
    serialized_capacity: usize,
    additional_retained_bytes: usize,
) -> Result<PhasePeaks, ValidateError> {
    // Heap capacities are the allocator-observed values. Inline terms name
    // the largest co-live state in each phase; retained excludes all scratch.
    let validation_scratch = validation_scratch_bytes()?;
    let control = phase_control_inline_bytes()?;
    let validation = dimensions
        .raw_program_capacity_bytes
        .checked_add(core::mem::size_of::<RawProgram>())
        .and_then(|peak| peak.checked_add(validation_scratch))
        .and_then(|peak| peak.checked_add(control))
        .ok_or(ValidateError::ArithmeticOverflow {
            site: ArithmeticSite::PhasePeakBytes,
        })?;
    let serialization = dimensions
        .raw_program_capacity_bytes
        .checked_add(serialized_capacity)
        .and_then(|peak| peak.checked_add(core::mem::size_of::<RawProgram>()))
        .and_then(|peak| peak.checked_add(serialization_inline_scratch_bytes()))
        .and_then(|peak| peak.checked_add(control))
        .ok_or(ValidateError::ArithmeticOverflow {
            site: ArithmeticSite::PhasePeakBytes,
        })?;
    let retained = dimensions
        .raw_program_capacity_bytes
        .checked_add(serialized_capacity)
        .and_then(|peak| peak.checked_add(core::mem::size_of::<ValidatedProgram<O>>()))
        .and_then(|peak| peak.checked_add(additional_retained_bytes))
        .ok_or(ValidateError::ArithmeticOverflow {
            site: ArithmeticSite::PhasePeakBytes,
        })?;
    let identity = retained
        .checked_add(identity_inline_scratch_bytes())
        .and_then(|peak| peak.checked_add(control))
        .ok_or(ValidateError::ArithmeticOverflow {
            site: ArithmeticSite::PhasePeakBytes,
        })?;
    Ok(PhasePeaks {
        validation,
        serialization,
        identity,
        retained,
    })
}

fn phase_control_inline_bytes() -> Result<usize, ValidateError> {
    core::mem::size_of::<ValidateLimits>()
        .checked_add(core::mem::size_of::<Dimensions>())
        .and_then(|bytes| bytes.checked_add(core::mem::size_of::<DimensionCensus>()))
        .and_then(|bytes| bytes.checked_add(core::mem::size_of::<RawMetadataPlanningEnvelope>()))
        .and_then(|bytes| bytes.checked_add(core::mem::size_of::<PlanningMeter>()))
        .and_then(|bytes| bytes.checked_add(core::mem::size_of::<ConstructionSeed>()))
        .and_then(|bytes| bytes.checked_add(core::mem::size_of::<ConstructionWork>()))
        .and_then(|bytes| bytes.checked_add(core::mem::size_of::<PhasePeaks>()))
        .and_then(|bytes| bytes.checked_add(core::mem::size_of::<ResourceAccounting>()))
        .and_then(|bytes| bytes.checked_add(core::mem::size_of::<[Option<BlockId>; 8]>()))
        .and_then(|bytes| bytes.checked_add(core::mem::size_of::<[Option<BlockId>; 2]>()))
        .and_then(|bytes| bytes.checked_add(core::mem::size_of::<[FlowState; 2]>()))
        .and_then(|bytes| bytes.checked_add(core::mem::size_of::<[Option<DataId>; 1]>()))
        .and_then(|bytes| bytes.checked_add(core::mem::size_of::<ClassShape>()))
        .and_then(|bytes| bytes.checked_add(8_usize.saturating_mul(core::mem::size_of::<usize>())))
        .ok_or(ValidateError::ArithmeticOverflow {
            site: ArithmeticSite::PhasePeakBytes,
        })
}

fn resource_accounting<O: Operation>(
    dimensions: Dimensions,
    work: ConstructionWork,
    serialized_capacity: usize,
    actual_validation_work: u64,
) -> Result<ResourceAccounting, ValidateError> {
    let peaks = phase_peaks::<O>(
        dimensions,
        serialized_capacity,
        work.additional_retained_bytes,
    )?;
    Ok(ResourceAccounting {
        version: RESOURCE_ACCOUNTING_VERSION,
        allocation_requests: work.allocation_requests,
        literal_allocation_request_bytes: work.literal_allocation_request_bytes,
        block_allocation_request_bytes: work.block_allocation_request_bytes,
        data_table_allocation_request_bytes: work.data_table_allocation_request_bytes,
        raw_allocation_request_bytes: work.raw_allocation_request_bytes,
        serialized_allocation_request_bytes: work.serialized_allocation_request_bytes,
        allocation_request_bytes: work.allocation_request_bytes,
        literal_capacity_bytes: dimensions.literal_capacity_bytes,
        block_capacity_bytes: dimensions.block_capacity_bytes,
        data_table_capacity_bytes: dimensions.data_table_capacity_bytes,
        raw_program_capacity_bytes: dimensions.raw_program_capacity_bytes,
        serialized_capacity_bytes: serialized_capacity,
        planning_work: work.planning_work,
        initialization_work: work.initialization_work,
        copy_work: work.copy_work,
        hash_invocations: work.hash_invocations,
        hash_work: work.hash_work,
        validation_work: actual_validation_work,
        validation_work_upper_bound: dimensions.validation_work_upper_bound,
        construction_work: work.total_upper_bound,
        validation_scratch_bytes: validation_scratch_bytes()?,
        validation_phase_peak_bytes: peaks.validation,
        serialization_phase_peak_bytes: peaks.serialization,
        identity_phase_peak_bytes: peaks.identity,
        retained_program_bytes: peaks.retained,
    })
}

fn admit_prospective<O: Operation>(
    dimensions: Dimensions,
    work: ConstructionWork,
    limits: ValidateLimits,
) -> Result<(), ValidateError> {
    let accounting = resource_accounting::<O>(dimensions, work, dimensions.serialized_bytes, 0)?;
    admit_accounting(accounting, limits)
}

fn admit_accounting(
    accounting: ResourceAccounting,
    limits: ValidateLimits,
) -> Result<(), ValidateError> {
    enforce_count(
        ResourceKind::ConstructionAllocationBytes,
        accounting.allocation_request_bytes,
        limits.max_construction_allocation_bytes,
    )?;
    enforce_count(
        ResourceKind::RawProgramCapacityBytes,
        accounting.raw_program_capacity_bytes,
        limits.max_raw_program_capacity_bytes,
    )?;
    enforce_count(
        ResourceKind::SerializedCapacityBytes,
        accounting.serialized_capacity_bytes,
        limits.max_serialized_capacity_bytes,
    )?;
    enforce_work(
        ResourceKind::ValidationWork,
        accounting.validation_work_upper_bound,
        limits.max_validation_work,
    )?;
    enforce_work(
        ResourceKind::ConstructionWork,
        accounting.construction_work,
        limits.max_construction_work,
    )?;
    enforce_count(
        ResourceKind::ValidationScratchBytes,
        accounting.validation_scratch_bytes,
        limits.max_validation_scratch_bytes,
    )?;
    enforce_count(
        ResourceKind::ValidationPhaseBytes,
        accounting.validation_phase_peak_bytes,
        limits.max_validation_phase_bytes,
    )?;
    enforce_count(
        ResourceKind::SerializationPhaseBytes,
        accounting.serialization_phase_peak_bytes,
        limits.max_serialization_phase_bytes,
    )?;
    enforce_count(
        ResourceKind::IdentityPhaseBytes,
        accounting.identity_phase_peak_bytes,
        limits.max_identity_phase_bytes,
    )?;
    enforce_count(
        ResourceKind::RetainedProgramBytes,
        accounting.retained_program_bytes,
        limits.max_retained_program_bytes,
    )?;
    Ok(())
}

#[cfg(test)]
mod dimension_census_tests {
    use super::*;

    #[test]
    fn deferred_dimension_overflow_retains_adjudication_order() {
        let both_overflowed = DimensionCensus {
            serialized: None,
            estimated_code: None,
            longest_literal: 0,
        };
        assert!(matches!(
            both_overflowed.finish(
                1,
                ValidateLimits {
                    max_data_bytes: 0,
                    ..ValidateLimits::default()
                }
            ),
            Err(ValidateError::ResourceLimit {
                resource: ResourceKind::DataBytes,
                ..
            })
        ));
        assert!(matches!(
            both_overflowed.finish(0, ValidateLimits::default()),
            Err(ValidateError::ArithmeticOverflow {
                site: ArithmeticSite::SerializedBytes,
            })
        ));

        let code_overflowed = DimensionCensus {
            serialized: Some(SERIALIZED_HEADER_BYTES),
            estimated_code: None,
            longest_literal: 0,
        };
        assert!(matches!(
            code_overflowed.finish(0, ValidateLimits::default()),
            Err(ValidateError::ArithmeticOverflow {
                site: ArithmeticSite::EstimatedCodeBytes,
            })
        ));

        let mut total = Some(usize::MAX);
        accumulate_checked(&mut total, Some(1));
        assert_eq!(total, None);
    }
}

fn enforce_count(
    resource: ResourceKind,
    required: usize,
    limit: u64,
) -> Result<u64, ValidateError> {
    let required = u64::try_from(required).map_err(|_| ValidateError::ResourceLimit {
        resource,
        limit,
        required: u64::MAX,
    })?;
    if required > limit {
        return Err(ValidateError::ResourceLimit {
            resource,
            limit,
            required,
        });
    }
    Ok(required)
}

fn enforce_work(resource: ResourceKind, required: u64, limit: u64) -> Result<(), ValidateError> {
    if required > limit {
        return Err(ValidateError::ResourceLimit {
            resource,
            limit,
            required,
        });
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct PlanningMeter {
    limit: u64,
    consumed: u64,
}

impl PlanningMeter {
    const fn new(consumed: u64, limit: u64) -> Self {
        Self { limit, consumed }
    }

    fn admit(&self, additional: u64) -> Result<(), ValidateError> {
        let required =
            self.consumed
                .checked_add(additional)
                .ok_or(ValidateError::ArithmeticOverflow {
                    site: ArithmeticSite::ConstructionWork,
                })?;
        enforce_work(ResourceKind::ConstructionWork, required, self.limit)
    }

    fn charge(&mut self, amount: u64) -> Result<(), ValidateError> {
        self.admit(amount)?;
        self.consumed =
            self.consumed
                .checked_add(amount)
                .ok_or(ValidateError::ArithmeticOverflow {
                    site: ArithmeticSite::ConstructionWork,
                })?;
        Ok(())
    }
}

fn ensure_planning_complete(expected: u64, attempted: u64) -> Result<(), ValidateError> {
    if expected == attempted {
        return Ok(());
    }
    let expected = usize::try_from(expected).map_err(|_| ValidateError::ArithmeticOverflow {
        site: ArithmeticSite::ConstructionWork,
    })?;
    let attempted = usize::try_from(attempted).map_err(|_| ValidateError::ArithmeticOverflow {
        site: ArithmeticSite::ConstructionWork,
    })?;
    Err(ValidateError::ConstructionLengthMismatch {
        resource: ResourceKind::ConstructionWork,
        expected,
        attempted,
    })
}

#[derive(Clone, Copy)]
struct WorkMeter {
    limit: u64,
    consumed: u64,
}

impl WorkMeter {
    const fn new(limit: u64) -> Self {
        Self { limit, consumed: 0 }
    }

    fn charge(&mut self, amount: u64) -> Result<(), ValidateError> {
        let required =
            self.consumed
                .checked_add(amount)
                .ok_or(ValidateError::ArithmeticOverflow {
                    site: ArithmeticSite::ValidationWork,
                })?;
        if required > self.limit {
            return Err(ValidateError::ResourceLimit {
                resource: ResourceKind::ValidationWork,
                limit: self.limit,
                required,
            });
        }
        self.consumed = required;
        Ok(())
    }
}

#[cfg(test)]
std::thread_local! {
    static PAIR_PLANNING_STEPS: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

#[cfg(test)]
fn record_pair_planning_step() {
    PAIR_PLANNING_STEPS.with(|steps| steps.set(steps.get().saturating_add(1)));
}

#[cfg(not(test))]
const fn record_pair_planning_step() {}

#[cfg(test)]
pub(crate) fn reset_pair_planning_steps() {
    PAIR_PLANNING_STEPS.with(|steps| steps.set(0));
}

#[cfg(test)]
pub(crate) fn pair_planning_steps() -> u64 {
    PAIR_PLANNING_STEPS.with(core::cell::Cell::get)
}

#[cfg(test)]
pub(crate) fn raw_metadata_planning_work_for_test(
    blocks: usize,
    data_blobs: usize,
) -> Result<u64, ValidateError> {
    raw_metadata_planning_envelope(blocks, data_blobs)?.total()
}

fn block_index(block: BlockId) -> Option<usize> {
    usize::try_from(block.0).ok()
}

fn data_index(data: DataId) -> Option<usize> {
    usize::try_from(data.0).ok()
}

fn index_id(index: usize) -> Result<u32, ValidateError> {
    u32::try_from(index).map_err(|_| ValidateError::ArithmeticOverflow {
        site: ArithmeticSite::ValidationWork,
    })
}

const fn required_state(op: &BlockOp) -> FlowState {
    match op {
        BlockOp::Entry { .. } => FlowState::Initial,
        BlockOp::ScanLiteral { .. } | BlockOp::ScanClassStart { .. } => FlowState::Cursor,
        BlockOp::ExtendClassRun { .. } | BlockOp::ConfirmSuffix { .. } => FlowState::Run,
        BlockOp::AdvanceAfterReject { .. } => FlowState::Rejected,
        BlockOp::ReturnFound => FlowState::Match,
        BlockOp::ReturnNone => FlowState::Exhausted,
    }
}

const fn outgoing_states(op: &BlockOp) -> [FlowState; 2] {
    match op {
        BlockOp::Entry { .. } | BlockOp::AdvanceAfterReject { .. } => {
            [FlowState::Cursor, FlowState::Initial]
        }
        BlockOp::ScanLiteral { .. } => [FlowState::Match, FlowState::Exhausted],
        BlockOp::ScanClassStart { .. } => [FlowState::Run, FlowState::Exhausted],
        BlockOp::ExtendClassRun { .. } => [FlowState::Run, FlowState::Initial],
        BlockOp::ConfirmSuffix { .. } => [FlowState::Match, FlowState::Rejected],
        BlockOp::ReturnFound | BlockOp::ReturnNone => [FlowState::Initial, FlowState::Initial],
    }
}

const fn referenced_data(op: &BlockOp) -> [Option<DataId>; 1] {
    match op {
        BlockOp::ScanLiteral { needle, .. } => [Some(*needle)],
        BlockOp::ScanClassStart { class, .. } | BlockOp::ExtendClassRun { class, .. } => {
            [Some(*class)]
        }
        BlockOp::ConfirmSuffix { suffix, .. } => [Some(*suffix)],
        BlockOp::Entry { .. }
        | BlockOp::AdvanceAfterReject { .. }
        | BlockOp::ReturnFound
        | BlockOp::ReturnNone => [None],
    }
}

#[derive(Clone, Copy)]
struct ClassShape {
    entry: BlockId,
    scan: BlockId,
    extend: BlockId,
    confirm: BlockId,
    advance: BlockId,
    found: BlockId,
    none: BlockId,
}
