//! Stable bounded-cache policy and bookkeeping charge model.

use core::marker::PhantomData;

use fre_jit_runtime::{PublicationLimits, RuntimeOperation};

use crate::{CacheCreateError, CacheResource};

const POLICY_VERSION: u16 = 1;
const BOOKKEEPING_MODEL_VERSION: u16 = 1;
pub(crate) const BASE_BOOKKEEPING_BYTES: u64 = 1_024;
pub(crate) const ENTRY_BOOKKEEPING_BYTES: u64 = 96;
pub(crate) const FLIGHT_BOOKKEEPING_BYTES: u64 = 96;
pub(crate) const LIVE_MAPPING_BOOKKEEPING_BYTES: u64 = 256;

/// Deterministic resident-entry eviction policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvictionPolicy {
    /// Least-recently-used sequence, with full identity bytes as the tie break.
    LeastRecentlyUsedV1,
}

/// Hard aggregate cache limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheLimits {
    pub max_entries: u64,
    pub max_in_flight_builds: u64,
    pub max_live_mappings: u64,
    pub max_mapped_bytes: u64,
    pub max_code_bytes: u64,
    pub max_data_bytes: u64,
    pub max_bookkeeping_bytes: u64,
}

impl Default for CacheLimits {
    fn default() -> Self {
        Self {
            max_entries: 256,
            max_in_flight_builds: 8,
            max_live_mappings: 512,
            max_mapped_bytes: 512 << 20,
            max_code_bytes: 64 << 20,
            max_data_bytes: 256 << 20,
            max_bookkeeping_bytes: 1 << 20,
        }
    }
}

impl CacheLimits {
    /// Stable conservative bookkeeping reservation required by these maxima.
    pub fn required_bookkeeping_bytes(self) -> Result<u64, CacheCreateError> {
        let entries = self
            .max_entries
            .checked_mul(ENTRY_BOOKKEEPING_BYTES)
            .ok_or(CacheCreateError::ArithmeticOverflow {
                resource: CacheResource::BookkeepingBytes,
            })?;
        let flights = self
            .max_in_flight_builds
            .checked_mul(FLIGHT_BOOKKEEPING_BYTES)
            .ok_or(CacheCreateError::ArithmeticOverflow {
                resource: CacheResource::BookkeepingBytes,
            })?;
        let mappings = self
            .max_live_mappings
            .checked_mul(LIVE_MAPPING_BOOKKEEPING_BYTES)
            .ok_or(CacheCreateError::ArithmeticOverflow {
                resource: CacheResource::BookkeepingBytes,
            })?;
        BASE_BOOKKEEPING_BYTES
            .checked_add(entries)
            .and_then(|bytes| bytes.checked_add(flights))
            .and_then(|bytes| bytes.checked_add(mappings))
            .ok_or(CacheCreateError::ArithmeticOverflow {
                resource: CacheResource::BookkeepingBytes,
            })
    }
}

/// Complete, reproducible cache-policy identity for one typed output contract.
#[derive(Debug, Eq, PartialEq)]
pub struct CachePolicyIdentity<O: RuntimeOperation> {
    pub policy_version: u16,
    pub bookkeeping_model_version: u16,
    pub eviction: EvictionPolicy,
    pub cache_limits: CacheLimits,
    pub publication_limits: PublicationLimits,
    output: PhantomData<fn() -> O>,
}

impl<O: RuntimeOperation> Copy for CachePolicyIdentity<O> {}

impl<O: RuntimeOperation> Clone for CachePolicyIdentity<O> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<O: RuntimeOperation> CachePolicyIdentity<O> {
    pub(crate) const fn new(
        cache_limits: CacheLimits,
        publication_limits: PublicationLimits,
    ) -> Self {
        Self {
            policy_version: POLICY_VERSION,
            bookkeeping_model_version: BOOKKEEPING_MODEL_VERSION,
            eviction: EvictionPolicy::LeastRecentlyUsedV1,
            cache_limits,
            publication_limits,
            output: PhantomData,
        }
    }
}
