use core::marker::PhantomData;

use crate::{
    AbiVersion, ArithmeticSite, BlockId, BlockOp, ByteClass, CacheIdentity, DataBlob, DataId,
    InvalidProgram, Operation, RawProgram, ResourceKind, SemanticsVersion, SerializedProgram,
    ValidateError,
    serialize::{serialize, serialized_size},
};

const HARD_MAX_BLOCKS: usize = 64;

/// Hard admission limits for an untrusted raw program.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidateLimits {
    pub max_blocks: u64,
    pub max_instructions: u64,
    pub max_data_blobs: u64,
    pub max_data_bytes: u64,
    pub max_serialized_bytes: u64,
    pub max_estimated_code_bytes: u64,
    pub max_validation_work: u64,
    pub max_validation_scratch_bytes: u64,
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
            max_estimated_code_bytes: 1 << 20,
            max_validation_work: 8 << 20,
            max_validation_scratch_bytes: 1 << 20,
            max_work_factor: (1 << 20) + 16,
        }
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
    validation_work: u64,
    work_factor: u64,
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

    #[must_use]
    pub const fn estimated_code_bytes(self) -> usize {
        self.estimated_code_bytes
    }

    #[must_use]
    pub const fn validation_work(self) -> u64 {
        self.validation_work
    }

    #[must_use]
    pub const fn work_factor(self) -> u64 {
        self.work_factor
    }
}

/// Immutable program that passed structural, resource and flow validation.
#[derive(Clone, Debug)]
pub struct ValidatedProgram<O: Operation> {
    pub(crate) raw: RawProgram,
    stats: ProgramStats,
    serialized: SerializedProgram,
    identity: CacheIdentity,
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
        self.identity
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

impl RawProgram {
    /// Validate an untrusted raw program for one compile-time output contract.
    pub fn validate<O: Operation>(
        self,
        limits: ValidateLimits,
    ) -> Result<ValidatedProgram<O>, ValidateError> {
        let (dimensions, mut meter) = Validator::new(&self, limits).run::<O>()?;
        // Serialization and hashing each touch every serialized byte.
        meter.charge(dimensions.serialized_bytes_u64)?;
        meter.charge(dimensions.serialized_bytes_u64)?;
        let serialized = serialize(&self, dimensions.serialized_bytes)
            .map_err(|resource| ValidateError::AllocationFailed { resource })?;
        let identity = serialized.identity();
        let stats = ProgramStats {
            blocks: self.blocks.len(),
            instructions: self.blocks.len(),
            data_blobs: self.data.len(),
            data_bytes: dimensions.data_bytes,
            serialized_bytes: dimensions.serialized_bytes,
            estimated_code_bytes: dimensions.estimated_code_bytes,
            validation_work: meter.consumed,
            work_factor: dimensions.work_factor,
        };
        Ok(ValidatedProgram {
            raw: self,
            stats,
            serialized,
            identity,
            operation: PhantomData,
        })
    }
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
    limits: ValidateLimits,
    meter: WorkMeter,
    reachable: [bool; HARD_MAX_BLOCKS],
    data_use: [u32; HARD_MAX_BLOCKS],
}

impl<'a> Validator<'a> {
    const fn new(raw: &'a RawProgram, limits: ValidateLimits) -> Self {
        Self {
            raw,
            limits,
            meter: WorkMeter::new(limits.max_validation_work),
            reachable: [false; HARD_MAX_BLOCKS],
            data_use: [0; HARD_MAX_BLOCKS],
        }
    }

    fn run<O: Operation>(mut self) -> Result<(Dimensions, WorkMeter), ValidateError> {
        self.validate_headers::<O>()?;
        let dimensions = preflight_dimensions(self.raw, self.limits, &mut self.meter)?;
        self.validate_targets_and_flow()?;
        self.validate_reachability()?;
        self.validate_data()?;
        self.validate_topology_and_dominance()?;
        Ok((dimensions, self.meter))
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
            if matches!(blob, DataBlob::ByteClass(class) if class.is_empty()) {
                return Err(InvalidProgram::EmptyClass {
                    data: index_id(index)?,
                }
                .into());
            }
            for prior in 0..index {
                self.meter.charge(1)?;
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
}

fn preflight_dimensions(
    raw: &RawProgram,
    limits: ValidateLimits,
    meter: &mut WorkMeter,
) -> Result<Dimensions, ValidateError> {
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
    let per_slot = core::mem::size_of::<bool>()
        .checked_mul(2)
        .and_then(|value| value.checked_add(core::mem::size_of::<u32>()))
        .and_then(|value| value.checked_add(core::mem::size_of::<usize>()))
        .ok_or(ValidateError::ArithmeticOverflow {
            site: ArithmeticSite::ValidationWork,
        })?;
    let scratch =
        HARD_MAX_BLOCKS
            .checked_mul(per_slot)
            .ok_or(ValidateError::ArithmeticOverflow {
                site: ArithmeticSite::ValidationWork,
            })?;
    enforce_count(
        ResourceKind::ValidationScratchBytes,
        scratch,
        limits.max_validation_scratch_bytes,
    )?;
    let mut data_bytes = 0_usize;
    for blob in &raw.data {
        meter.charge(1)?;
        let bytes = match blob {
            DataBlob::Bytes(bytes) => bytes.len(),
            DataBlob::ByteClass(_) => 32,
        };
        enforce_count(ResourceKind::DataBytes, bytes, u64::from(u32::MAX))?;
        data_bytes = data_bytes
            .checked_add(bytes)
            .ok_or(ValidateError::ArithmeticOverflow {
                site: ArithmeticSite::DataBytes,
            })?;
    }
    enforce_count(ResourceKind::DataBytes, data_bytes, limits.max_data_bytes)?;
    let serialized_bytes = serialized_size(raw).ok_or(ValidateError::ArithmeticOverflow {
        site: ArithmeticSite::SerializedBytes,
    })?;
    let serialized_bytes_u64 = enforce_count(
        ResourceKind::SerializedBytes,
        serialized_bytes,
        limits.max_serialized_bytes,
    )?;
    let estimated_code_bytes = estimate_code_bytes(raw)?;
    enforce_count(
        ResourceKind::EstimatedCodeBytes,
        estimated_code_bytes,
        limits.max_estimated_code_bytes,
    )?;
    let work_factor = compute_work_factor(raw)?;
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
    })
}

fn estimate_code_bytes(raw: &RawProgram) -> Result<usize, ValidateError> {
    let mut bytes = 0_usize;
    for block in &raw.blocks {
        let block_bytes = match block.op {
            BlockOp::Entry { .. } => 16,
            BlockOp::ScanLiteral { .. } | BlockOp::ConfirmSuffix { .. } => 160,
            BlockOp::ScanClassStart { .. } => 192,
            BlockOp::ExtendClassRun { .. } => 128,
            BlockOp::AdvanceAfterReject { .. } | BlockOp::ReturnFound | BlockOp::ReturnNone => 32,
        };
        bytes = bytes
            .checked_add(block_bytes)
            .ok_or(ValidateError::ArithmeticOverflow {
                site: ArithmeticSite::EstimatedCodeBytes,
            })?;
    }
    for blob in &raw.data {
        let length = match blob {
            DataBlob::Bytes(bytes) => bytes.len(),
            DataBlob::ByteClass(_) => 32,
        };
        let padded = length
            .checked_add(15)
            .ok_or(ValidateError::ArithmeticOverflow {
                site: ArithmeticSite::EstimatedCodeBytes,
            })?
            & !15;
        bytes = bytes
            .checked_add(padded)
            .ok_or(ValidateError::ArithmeticOverflow {
                site: ArithmeticSite::EstimatedCodeBytes,
            })?;
    }
    Ok(bytes)
}

fn compute_work_factor(raw: &RawProgram) -> Result<u64, ValidateError> {
    let mut longest = 0_usize;
    for blob in &raw.data {
        if let DataBlob::Bytes(bytes) = blob {
            longest = longest.max(bytes.len());
        }
    }
    u64::try_from(longest)
        .ok()
        .and_then(|value| value.checked_add(8))
        .ok_or(ValidateError::ArithmeticOverflow {
            site: ArithmeticSite::WorkFactor,
        })
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
