use fre_jit_aarch64::{
    AuditedSelectedEndRegisterImageV2, CodeLabel, ImageLayout, NativeAggregateImage, NativeImage,
};

use crate::{ArithmeticSite, PublishError, ResourceKind};

/// Hard resource limits for one executable mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationLimits {
    pub max_code_bytes: u64,
    pub max_data_bytes: u64,
    pub max_payload_bytes: u64,
    pub max_mapped_bytes: u64,
    pub max_pages: u64,
}

impl Default for PublicationLimits {
    fn default() -> Self {
        Self {
            max_code_bytes: 1 << 20,
            max_data_bytes: 4 << 20,
            max_payload_bytes: 8 << 20,
            max_mapped_bytes: 16 << 20,
            max_pages: 4_096,
        }
    }
}

/// Exact resource accounting for one strict-W^X reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationAccounting {
    pub page_bytes: usize,
    pub code_bytes: usize,
    pub data_bytes: usize,
    pub alignment_gap_bytes: usize,
    pub payload_used_bytes: usize,
    pub payload_mapped_bytes: usize,
    pub guard_bytes: usize,
    pub total_mapped_bytes: usize,
    pub total_pages: usize,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct PublicationPlan {
    pub(crate) accounting: PublicationAccounting,
    pub(crate) rodata_offset: usize,
    pub(crate) entry_offset: usize,
}

impl PublicationPlan {
    pub(crate) fn new(
        image: &NativeImage,
        page_bytes: usize,
        limits: PublicationLimits,
    ) -> Result<Self, PublishError> {
        Self::from_parts(
            image.code().len(),
            image.rodata().len(),
            image.layout(),
            image.labels(),
            page_bytes,
            limits,
        )
    }

    pub(crate) fn new_aggregate(
        image: &NativeAggregateImage,
        page_bytes: usize,
        limits: PublicationLimits,
    ) -> Result<Self, PublishError> {
        Self::from_parts(
            image.code().len(),
            image.rodata().len(),
            image.layout(),
            image.labels(),
            page_bytes,
            limits,
        )
    }

    pub(crate) fn new_selected_end_register_v2(
        image: &AuditedSelectedEndRegisterImageV2,
        page_bytes: usize,
        limits: PublicationLimits,
    ) -> Result<Self, PublishError> {
        Self::from_parts(
            image.code().len(),
            image.rodata().len(),
            image.layout(),
            image.labels(),
            page_bytes,
            limits,
        )
    }

    fn from_parts(
        code_bytes: usize,
        data_bytes: usize,
        layout: ImageLayout,
        labels: &[CodeLabel],
        page_bytes: usize,
        limits: PublicationLimits,
    ) -> Result<Self, PublishError> {
        if page_bytes == 0 || !page_bytes.is_power_of_two() {
            return Err(PublishError::InvalidPageSize { bytes: page_bytes });
        }
        let rodata_offset = usize::try_from(layout.rodata_from_code_start)
            .map_err(|_| PublishError::InvalidImageLayout)?;
        let payload_used_bytes = usize::try_from(layout.total_mapped_bytes)
            .map_err(|_| PublishError::InvalidImageLayout)?;
        let expected_used =
            rodata_offset
                .checked_add(data_bytes)
                .ok_or(PublishError::ArithmeticOverflow {
                    site: ArithmeticSite::ImageLayout,
                })?;
        if rodata_offset < code_bytes || expected_used != payload_used_bytes {
            return Err(PublishError::InvalidImageLayout);
        }
        let alignment_gap_bytes = rodata_offset
            .checked_sub(code_bytes)
            .ok_or(PublishError::InvalidImageLayout)?;
        let payload_mapped_bytes = round_up(payload_used_bytes, page_bytes)?;
        let guard_bytes = page_bytes
            .checked_mul(2)
            .ok_or(PublishError::ArithmeticOverflow {
                site: ArithmeticSite::GuardPages,
            })?;
        let total_mapped_bytes = payload_mapped_bytes.checked_add(guard_bytes).ok_or(
            PublishError::ArithmeticOverflow {
                site: ArithmeticSite::GuardPages,
            },
        )?;
        let total_pages =
            total_mapped_bytes
                .checked_div(page_bytes)
                .ok_or(PublishError::ArithmeticOverflow {
                    site: ArithmeticSite::PageCount,
                })?;
        let entry_offset = labels
            .iter()
            .find(|label| label.kind == fre_jit_aarch64::LabelKind::Entry)
            .and_then(|label| usize::try_from(label.offset).ok())
            .ok_or(PublishError::InvalidImageLayout)?;
        if entry_offset >= code_bytes {
            return Err(PublishError::InvalidImageLayout);
        }
        let accounting = PublicationAccounting {
            page_bytes,
            code_bytes,
            data_bytes,
            alignment_gap_bytes,
            payload_used_bytes,
            payload_mapped_bytes,
            guard_bytes,
            total_mapped_bytes,
            total_pages,
        };
        enforce(ResourceKind::CodeBytes, code_bytes, limits.max_code_bytes)?;
        enforce(ResourceKind::DataBytes, data_bytes, limits.max_data_bytes)?;
        enforce(
            ResourceKind::PayloadBytes,
            payload_mapped_bytes,
            limits.max_payload_bytes,
        )?;
        enforce(
            ResourceKind::MappedBytes,
            total_mapped_bytes,
            limits.max_mapped_bytes,
        )?;
        enforce(ResourceKind::Pages, total_pages, limits.max_pages)?;
        Ok(Self {
            accounting,
            rodata_offset,
            entry_offset,
        })
    }
}

fn round_up(value: usize, alignment: usize) -> Result<usize, PublishError> {
    let mask = alignment
        .checked_sub(1)
        .ok_or(PublishError::InvalidPageSize { bytes: alignment })?;
    value
        .checked_add(mask)
        .map(|rounded| rounded & !mask)
        .ok_or(PublishError::ArithmeticOverflow {
            site: ArithmeticSite::PageRounding,
        })
}

fn enforce(resource: ResourceKind, required: usize, limit: u64) -> Result<(), PublishError> {
    let required = u64::try_from(required).map_err(|_| PublishError::ArithmeticOverflow {
        site: ArithmeticSite::ImageLayout,
    })?;
    if required > limit {
        return Err(PublishError::ResourceLimit {
            resource,
            limit,
            required,
        });
    }
    Ok(())
}
