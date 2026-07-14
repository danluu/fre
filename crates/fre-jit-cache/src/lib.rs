//! Bounded concurrent caching for typed FRE native kernels.
//!
//! The cache never owns executable-memory implementation details. It admits
//! only [`fre_jit_runtime::PublishedKernel`] values and leaves mapping, native
//! call, and final unmap lifecycle to `fre-jit-runtime`.

#![forbid(unsafe_code)]

mod cache;
mod error;
mod policy;
mod stats;

pub use cache::{KernelCache, KernelLease};
pub use error::{CacheCreateError, CacheError, CacheResource};
pub use policy::{CacheLimits, CachePolicyIdentity, EvictionPolicy};
pub use stats::{CacheSnapshot, CacheTotals, CacheUsage};

#[cfg(test)]
mod tests;
