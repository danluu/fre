use crate::{
    AbiVersion, AnchorFlags, Block, BlockId, BlockOp, BuildError, ByteClass, DataBlob, DataId,
    Operation, RawProgram, ResourceKind, SemanticsVersion, ValidateError, ValidateLimits,
    ValidatedProgram,
};

/// Build and validate a pattern-specialized exact-literal scan kernel.
pub fn build_exact_literal<O: Operation>(
    literal: &[u8],
    anchors: AnchorFlags,
    limits: ValidateLimits,
) -> Result<ValidatedProgram<O>, BuildError> {
    enforce(ResourceKind::DataBytes, literal.len(), u64::from(u32::MAX))?;
    let padded = padded_length(literal.len())?;
    let serialized_bytes = literal
        .len()
        .checked_add(53)
        .ok_or(arithmetic(crate::ArithmeticSite::SerializedBytes))?;
    let code_bytes = padded
        .checked_add(240)
        .ok_or(arithmetic(crate::ArithmeticSite::EstimatedCodeBytes))?;
    let work_factor = work_factor(literal.len())?;
    preflight_shape(
        ShapeDimensions {
            blocks: 4,
            data_blobs: 1,
            data_bytes: literal.len(),
            serialized_bytes,
            code_bytes,
            work_factor,
        },
        limits,
    )?;
    let literal = copy_bytes(literal)?;
    let mut blocks = reserved_vec(4, ResourceKind::Blocks)?;
    blocks.push(Block {
        op: BlockOp::Entry { next: BlockId(1) },
    });
    blocks.push(Block {
        op: BlockOp::ScanLiteral {
            needle: DataId(0),
            anchors,
            matched: BlockId(2),
            exhausted: BlockId(3),
        },
    });
    blocks.push(Block {
        op: BlockOp::ReturnFound,
    });
    blocks.push(Block {
        op: BlockOp::ReturnNone,
    });
    let mut data = reserved_vec(1, ResourceKind::DataBlobs)?;
    data.push(DataBlob::Bytes(literal));
    Ok(raw_program::<O>(blocks, data).validate(limits)?)
}

/// Build and validate `[class]+suffix` with a disjoint suffix delimiter.
///
/// The suffix must be non-empty and its first byte must not belong to `class`.
/// That proof makes the maximal class run and the greedy leftmost match the
/// same candidate, allowing a monotonic native scan without backtracking.
pub fn build_class_suffix<O: Operation>(
    class: ByteClass,
    suffix: &[u8],
    anchors: AnchorFlags,
    limits: ValidateLimits,
) -> Result<ValidatedProgram<O>, BuildError> {
    if class.is_empty() {
        return Err(BuildError::Validate(ValidateError::Invalid(
            crate::InvalidProgram::EmptyClass { data: 0 },
        )));
    }
    let Some(first) = suffix.first().copied() else {
        return Err(BuildError::Validate(ValidateError::Invalid(
            crate::InvalidProgram::EmptySuffix { data: 1 },
        )));
    };
    if class.contains(first) {
        return Err(BuildError::Validate(ValidateError::Invalid(
            crate::InvalidProgram::SuffixOverlapsClass {
                class: 0,
                suffix: 1,
            },
        )));
    }
    enforce(ResourceKind::DataBytes, suffix.len(), u64::from(u32::MAX))?;
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
    preflight_shape(
        ShapeDimensions {
            blocks: 7,
            data_blobs: 2,
            data_bytes: required,
            serialized_bytes,
            code_bytes,
            work_factor,
        },
        limits,
    )?;
    let suffix = copy_bytes(suffix)?;
    let mut blocks = reserved_vec(7, ResourceKind::Blocks)?;
    blocks.push(Block {
        op: BlockOp::Entry { next: BlockId(1) },
    });
    blocks.push(Block {
        op: BlockOp::ScanClassStart {
            class: DataId(0),
            anchored_start: anchors.start,
            run: BlockId(2),
            exhausted: BlockId(6),
        },
    });
    blocks.push(Block {
        op: BlockOp::ExtendClassRun {
            class: DataId(0),
            next: BlockId(3),
        },
    });
    blocks.push(Block {
        op: BlockOp::ConfirmSuffix {
            suffix: DataId(1),
            anchored_end: anchors.end,
            matched: BlockId(5),
            rejected: BlockId(4),
        },
    });
    blocks.push(Block {
        op: BlockOp::AdvanceAfterReject { next: BlockId(1) },
    });
    blocks.push(Block {
        op: BlockOp::ReturnFound,
    });
    blocks.push(Block {
        op: BlockOp::ReturnNone,
    });
    let mut data = reserved_vec(2, ResourceKind::DataBlobs)?;
    data.push(DataBlob::ByteClass(class));
    data.push(DataBlob::Bytes(suffix));
    Ok(raw_program::<O>(blocks, data).validate(limits)?)
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
    serialized_bytes: usize,
    code_bytes: usize,
    work_factor: u64,
}

fn preflight_shape(shape: ShapeDimensions, limits: ValidateLimits) -> Result<(), BuildError> {
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
    Ok(())
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

fn copy_bytes(source: &[u8]) -> Result<Vec<u8>, BuildError> {
    let mut destination = Vec::new();
    destination
        .try_reserve_exact(source.len())
        .map_err(|_| BuildError::AllocationFailed {
            resource: ResourceKind::DataBytes,
        })?;
    destination.extend_from_slice(source);
    Ok(destination)
}

fn reserved_vec<T>(capacity: usize, resource: ResourceKind) -> Result<Vec<T>, BuildError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|_| BuildError::AllocationFailed { resource })?;
    Ok(values)
}
