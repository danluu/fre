use crate::{
    AbiVersion, AnchorFlags, Block, BlockId, BlockOp, BuildError, ByteClass, DataBlob, DataId,
    Operation, RawProgram, ResourceKind, SemanticsVersion, ValidateError, ValidateLimits,
    ValidatedProgram,
    validate::{FixedShapeAdmission, fixed_shape_validation_work_upper_bound},
};

/// Build and validate a pattern-specialized exact-literal scan kernel.
pub fn build_exact_literal<O: Operation>(
    literal: &[u8],
    anchors: AnchorFlags,
    limits: ValidateLimits,
) -> Result<ValidatedProgram<O>, BuildError> {
    build_exact_literal_accounted::<O>(literal, anchors, limits, 0, 0, 0)
}

pub(crate) fn build_exact_literal_accounted<O: Operation>(
    literal: &[u8],
    anchors: AnchorFlags,
    limits: ValidateLimits,
    additional_hash_invocations: u8,
    additional_hash_work: u64,
    additional_retained_bytes: usize,
) -> Result<ValidatedProgram<O>, BuildError> {
    enforce(ResourceKind::DataBytes, literal.len(), u64::from(u32::MAX))?;
    enforce(
        ResourceKind::DataBytes,
        literal.len(),
        limits.max_data_bytes,
    )?;
    let padded = padded_length(literal.len())?;
    let serialized_bytes = literal
        .len()
        .checked_add(53)
        .ok_or(arithmetic(crate::ArithmeticSite::SerializedBytes))?;
    let code_bytes = padded
        .checked_add(240)
        .ok_or(arithmetic(crate::ArithmeticSite::EstimatedCodeBytes))?;
    let work_factor = work_factor(literal.len())?;
    let admission = preflight_shape::<O>(
        ShapeDimensions {
            blocks: 4,
            data_blobs: 1,
            data_bytes: literal.len(),
            literal_bytes: literal.len(),
            serialized_bytes,
            code_bytes,
            work_factor,
            data_scan_work: 0,
            planning_work: 0,
        },
        limits,
        additional_hash_invocations,
        additional_hash_work,
        additional_retained_bytes,
    )?;
    let block_request = allocation_bytes::<Block>(4)?;
    let data_request = allocation_bytes::<DataBlob>(1)?;
    let after_literal_minimum = block_request.checked_add(data_request).ok_or(arithmetic(
        crate::ArithmeticSite::ConstructionAllocationBytes,
    ))?;
    let (literal_storage, literal_capacity) =
        reserved_bytes::<O>(literal.len(), 0, after_literal_minimum, admission, limits)?;
    let (mut blocks, block_capacity) = reserved_vec::<O, Block>(
        4,
        ResourceKind::Blocks,
        literal_capacity,
        data_request,
        admission,
        limits,
    )?;
    let (mut data, _raw_capacity) = reserved_vec::<O, DataBlob>(
        1,
        ResourceKind::DataBlobs,
        block_capacity,
        0,
        admission,
        limits,
    )?;
    let literal = initialize_bytes(literal_storage, literal)?;
    blocks.push(Block {
        op: BlockOp::Entry { next: BlockId(1) },
    })?;
    blocks.push(Block {
        op: BlockOp::ScanLiteral {
            needle: DataId(0),
            anchors,
            matched: BlockId(2),
            exhausted: BlockId(3),
        },
    })?;
    blocks.push(Block {
        op: BlockOp::ReturnFound,
    })?;
    blocks.push(Block {
        op: BlockOp::ReturnNone,
    })?;
    let blocks = blocks.finish()?;
    data.push(DataBlob::Bytes(literal))?;
    let data = data.finish()?;
    Ok(raw_program::<O>(blocks, data).validate_accounted::<O>(limits, admission.seed())?)
}

/// Build and validate `[class]+suffix` with a disjoint suffix delimiter.
///
/// The suffix must be non-empty and its first byte must not belong to `class`.
/// That proof makes the maximal class run and the greedy leftmost match the
/// same candidate, allowing a monotonic native scan without backtracking.
#[expect(
    clippy::too_many_lines,
    reason = "the fixed allocation and initialization sequence stays linear for receipt auditing"
)]
pub fn build_class_suffix<O: Operation>(
    class: ByteClass,
    suffix: &[u8],
    anchors: AnchorFlags,
    limits: ValidateLimits,
) -> Result<ValidatedProgram<O>, BuildError> {
    enforce(ResourceKind::DataBytes, suffix.len(), u64::from(u32::MAX))?;
    enforce(ResourceKind::DataBytes, suffix.len(), limits.max_data_bytes)?;
    if suffix.is_empty() {
        return Err(BuildError::Validate(ValidateError::Invalid(
            crate::InvalidProgram::EmptySuffix { data: 1 },
        )));
    }
    let required = suffix.len().checked_add(32).ok_or(BuildError::Validate(
        ValidateError::ArithmeticOverflow {
            site: crate::ArithmeticSite::DataBytes,
        },
    ))?;
    let padded = padded_length(suffix.len())?;
    let serialized_bytes = suffix
        .len()
        .checked_add(118)
        .ok_or(arithmetic(crate::ArithmeticSite::SerializedBytes))?;
    let code_bytes = padded
        .checked_add(624)
        .ok_or(arithmetic(crate::ArithmeticSite::EstimatedCodeBytes))?;
    let work_factor = work_factor(suffix.len())?;
    let admission = preflight_shape::<O>(
        ShapeDimensions {
            blocks: 7,
            data_blobs: 2,
            data_bytes: required,
            literal_bytes: suffix.len(),
            serialized_bytes,
            code_bytes,
            work_factor,
            data_scan_work: 6,
            planning_work: 6,
        },
        limits,
        0,
        0,
        0,
    )?;
    if class.is_empty() {
        return Err(BuildError::Validate(ValidateError::Invalid(
            crate::InvalidProgram::EmptyClass { data: 0 },
        )));
    }
    let first = suffix[0];
    if class.contains(first) {
        return Err(BuildError::Validate(ValidateError::Invalid(
            crate::InvalidProgram::SuffixOverlapsClass {
                class: 0,
                suffix: 1,
            },
        )));
    }
    let block_request = allocation_bytes::<Block>(7)?;
    let data_request = allocation_bytes::<DataBlob>(2)?;
    let after_suffix_minimum = block_request.checked_add(data_request).ok_or(arithmetic(
        crate::ArithmeticSite::ConstructionAllocationBytes,
    ))?;
    let (suffix_storage, suffix_capacity) =
        reserved_bytes::<O>(suffix.len(), 0, after_suffix_minimum, admission, limits)?;
    let (mut blocks, block_capacity) = reserved_vec::<O, Block>(
        7,
        ResourceKind::Blocks,
        suffix_capacity,
        data_request,
        admission,
        limits,
    )?;
    let (mut data, _raw_capacity) = reserved_vec::<O, DataBlob>(
        2,
        ResourceKind::DataBlobs,
        block_capacity,
        0,
        admission,
        limits,
    )?;
    let suffix = initialize_bytes(suffix_storage, suffix)?;
    blocks.push(Block {
        op: BlockOp::Entry { next: BlockId(1) },
    })?;
    blocks.push(Block {
        op: BlockOp::ScanClassStart {
            class: DataId(0),
            anchored_start: anchors.start,
            run: BlockId(2),
            exhausted: BlockId(6),
        },
    })?;
    blocks.push(Block {
        op: BlockOp::ExtendClassRun {
            class: DataId(0),
            next: BlockId(3),
        },
    })?;
    blocks.push(Block {
        op: BlockOp::ConfirmSuffix {
            suffix: DataId(1),
            anchored_end: anchors.end,
            matched: BlockId(5),
            rejected: BlockId(4),
        },
    })?;
    blocks.push(Block {
        op: BlockOp::AdvanceAfterReject { next: BlockId(1) },
    })?;
    blocks.push(Block {
        op: BlockOp::ReturnFound,
    })?;
    blocks.push(Block {
        op: BlockOp::ReturnNone,
    })?;
    let blocks = blocks.finish()?;
    data.push(DataBlob::ByteClass(class))?;
    data.push(DataBlob::Bytes(suffix))?;
    let data = data.finish()?;
    Ok(raw_program::<O>(blocks, data).validate_accounted::<O>(limits, admission.seed())?)
}

fn raw_program<O: Operation>(blocks: Vec<Block>, data: Vec<DataBlob>) -> RawProgram {
    RawProgram {
        schema_version: RawProgram::SCHEMA_VERSION,
        semantics: SemanticsVersion::CURRENT,
        abi: AbiVersion::CURRENT,
        output: O::KIND,
        entry: BlockId(0),
        blocks,
        data,
    }
}

#[derive(Clone, Copy)]
struct ShapeDimensions {
    blocks: usize,
    data_blobs: usize,
    data_bytes: usize,
    literal_bytes: usize,
    serialized_bytes: usize,
    code_bytes: usize,
    work_factor: u64,
    data_scan_work: u64,
    planning_work: u64,
}

fn preflight_shape<O: Operation>(
    shape: ShapeDimensions,
    limits: ValidateLimits,
    additional_hash_invocations: u8,
    additional_hash_work: u64,
    additional_retained_bytes: usize,
) -> Result<FixedShapeAdmission, BuildError> {
    enforce(ResourceKind::Blocks, shape.blocks, limits.max_blocks)?;
    enforce(
        ResourceKind::Instructions,
        shape.blocks,
        limits.max_instructions,
    )?;
    enforce(
        ResourceKind::DataBlobs,
        shape.data_blobs,
        limits.max_data_blobs,
    )?;
    enforce(
        ResourceKind::DataBytes,
        shape.data_bytes,
        limits.max_data_bytes,
    )?;
    enforce(
        ResourceKind::SerializedBytes,
        shape.serialized_bytes,
        limits.max_serialized_bytes,
    )?;
    enforce(
        ResourceKind::SerializedCapacityBytes,
        shape.serialized_bytes,
        limits.max_serialized_capacity_bytes,
    )?;
    enforce(
        ResourceKind::EstimatedCodeBytes,
        shape.code_bytes,
        limits.max_estimated_code_bytes,
    )?;
    if shape.work_factor > limits.max_work_factor {
        return Err(BuildError::Validate(ValidateError::ResourceLimit {
            resource: ResourceKind::WorkFactor,
            limit: limits.max_work_factor,
            required: shape.work_factor,
        }));
    }
    let block_allocation_request_bytes = shape
        .blocks
        .checked_mul(core::mem::size_of::<Block>())
        .ok_or(arithmetic(
            crate::ArithmeticSite::ConstructionAllocationBytes,
        ))?;
    let data_table_allocation_request_bytes = shape
        .data_blobs
        .checked_mul(core::mem::size_of::<DataBlob>())
        .ok_or(arithmetic(
            crate::ArithmeticSite::ConstructionAllocationBytes,
        ))?;
    let raw_allocation_request_bytes = shape
        .literal_bytes
        .checked_add(block_allocation_request_bytes)
        .and_then(|bytes| bytes.checked_add(data_table_allocation_request_bytes))
        .ok_or(arithmetic(
            crate::ArithmeticSite::ConstructionAllocationBytes,
        ))?;
    let raw_initialization_work = u64::try_from(raw_allocation_request_bytes)
        .map_err(|_| arithmetic(crate::ArithmeticSite::ConstructionWork))?;
    let raw_copy_work = u64::try_from(shape.literal_bytes)
        .map_err(|_| arithmetic(crate::ArithmeticSite::ConstructionWork))?;
    let validation_work_upper_bound = fixed_shape_validation_work_upper_bound(
        shape.blocks,
        shape.data_blobs,
        shape.data_scan_work,
    )?;
    let admission = FixedShapeAdmission::new(
        shape.blocks,
        shape.data_blobs,
        shape.serialized_bytes,
        3,
        shape.literal_bytes,
        block_allocation_request_bytes,
        data_table_allocation_request_bytes,
        shape.planning_work,
        raw_initialization_work,
        raw_copy_work,
        validation_work_upper_bound,
        additional_hash_invocations,
        additional_hash_work,
        additional_retained_bytes,
    )?;
    admission.admit::<O>(raw_allocation_request_bytes, limits)?;
    Ok(admission)
}

fn enforce(resource: ResourceKind, value: usize, limit: u64) -> Result<(), BuildError> {
    let required = u64::try_from(value).map_err(|_| {
        BuildError::Validate(ValidateError::ResourceLimit {
            resource,
            limit,
            required: u64::MAX,
        })
    })?;
    if required > limit {
        return Err(BuildError::Validate(ValidateError::ResourceLimit {
            resource,
            limit,
            required,
        }));
    }
    Ok(())
}

fn padded_length(length: usize) -> Result<usize, BuildError> {
    Ok(length
        .checked_add(15)
        .ok_or(arithmetic(crate::ArithmeticSite::EstimatedCodeBytes))?
        & !15)
}

fn work_factor(length: usize) -> Result<u64, BuildError> {
    u64::try_from(length)
        .ok()
        .and_then(|value| value.checked_add(8))
        .ok_or(arithmetic(crate::ArithmeticSite::WorkFactor))
}

const fn arithmetic(site: crate::ArithmeticSite) -> BuildError {
    BuildError::Validate(ValidateError::ArithmeticOverflow { site })
}

fn reserved_bytes<O: Operation>(
    length: usize,
    prior_raw_capacity: usize,
    remaining_minimum_capacity: usize,
    admission: FixedShapeAdmission,
    limits: ValidateLimits,
) -> Result<(Vec<u8>, usize), BuildError> {
    let mut destination = Vec::new();
    destination
        .try_reserve_exact(length)
        .map_err(|_| BuildError::AllocationFailed {
            resource: ResourceKind::DataBytes,
        })?;
    let raw_capacity = prior_raw_capacity
        .checked_add(destination.capacity())
        .ok_or(arithmetic(crate::ArithmeticSite::PhasePeakBytes))?;
    let projected_capacity = raw_capacity
        .checked_add(remaining_minimum_capacity)
        .ok_or(arithmetic(crate::ArithmeticSite::PhasePeakBytes))?;
    admission.admit::<O>(projected_capacity, limits)?;
    if destination.capacity() < length {
        return Err(BuildError::Validate(
            ValidateError::ConstructionLengthMismatch {
                resource: ResourceKind::DataBytes,
                expected: length,
                attempted: destination.capacity(),
            },
        ));
    }
    Ok((destination, raw_capacity))
}

fn initialize_bytes(mut destination: Vec<u8>, source: &[u8]) -> Result<Vec<u8>, BuildError> {
    if destination.capacity() < source.len() {
        return Err(BuildError::Validate(
            ValidateError::ConstructionLengthMismatch {
                resource: ResourceKind::DataBytes,
                expected: source.len(),
                attempted: destination.capacity(),
            },
        ));
    }
    destination.resize(source.len(), 0);
    destination.copy_from_slice(source);
    Ok(destination)
}

fn reserved_vec<O: Operation, T>(
    length: usize,
    resource: ResourceKind,
    prior_raw_capacity: usize,
    remaining_minimum_capacity: usize,
    admission: FixedShapeAdmission,
    limits: ValidateLimits,
) -> Result<(FixedVec<T>, usize), BuildError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(length)
        .map_err(|_| BuildError::AllocationFailed { resource })?;
    let capacity_bytes = values
        .capacity()
        .checked_mul(core::mem::size_of::<T>())
        .ok_or(arithmetic(crate::ArithmeticSite::PhasePeakBytes))?;
    let raw_capacity = prior_raw_capacity
        .checked_add(capacity_bytes)
        .ok_or(arithmetic(crate::ArithmeticSite::PhasePeakBytes))?;
    let projected_capacity = raw_capacity
        .checked_add(remaining_minimum_capacity)
        .ok_or(arithmetic(crate::ArithmeticSite::PhasePeakBytes))?;
    admission.admit::<O>(projected_capacity, limits)?;
    Ok((
        FixedVec {
            values,
            expected: length,
            resource,
        },
        raw_capacity,
    ))
}

fn allocation_bytes<T>(length: usize) -> Result<usize, BuildError> {
    length
        .checked_mul(core::mem::size_of::<T>())
        .ok_or(arithmetic(
            crate::ArithmeticSite::ConstructionAllocationBytes,
        ))
}

struct FixedVec<T> {
    values: Vec<T>,
    expected: usize,
    resource: ResourceKind,
}

impl<T> FixedVec<T> {
    fn push(&mut self, value: T) -> Result<(), BuildError> {
        let attempted = self
            .values
            .len()
            .checked_add(1)
            .ok_or(arithmetic(crate::ArithmeticSite::ConstructionWork))?;
        if attempted > self.expected || attempted > self.values.capacity() {
            return Err(BuildError::Validate(
                ValidateError::ConstructionLengthMismatch {
                    resource: self.resource,
                    expected: self.expected,
                    attempted,
                },
            ));
        }
        self.values.push(value);
        Ok(())
    }

    fn finish(self) -> Result<Vec<T>, BuildError> {
        if self.values.len() != self.expected {
            return Err(BuildError::Validate(
                ValidateError::ConstructionLengthMismatch {
                    resource: self.resource,
                    expected: self.expected,
                    attempted: self.values.len(),
                },
            ));
        }
        Ok(self.values)
    }
}

#[cfg(test)]
mod fixed_vec_tests {
    use super::FixedVec;

    #[test]
    fn fixed_vec_refuses_overflow_and_underfill() {
        let mut values = Vec::new();
        values.try_reserve_exact(1).expect("small test reserve");
        let mut fixed = FixedVec {
            values,
            expected: 1,
            resource: crate::ResourceKind::Blocks,
        };
        fixed.push(1_u8).expect("one admitted element");
        let error = fixed.push(2_u8).expect_err("fixed vector cannot grow");
        assert!(matches!(
            error,
            crate::BuildError::Validate(crate::ValidateError::ConstructionLengthMismatch {
                resource: crate::ResourceKind::Blocks,
                expected: 1,
                attempted: 2
            })
        ));

        let underfill = FixedVec::<u8> {
            values: Vec::new(),
            expected: 1,
            resource: crate::ResourceKind::DataBlobs,
        };
        let error = underfill.finish().expect_err("underfill is not canonical");
        assert!(matches!(
            error,
            crate::BuildError::Validate(crate::ValidateError::ConstructionLengthMismatch {
                resource: crate::ResourceKind::DataBlobs,
                expected: 1,
                attempted: 0
            })
        ));
    }
}
