//! Bounded concurrent caching for typed FRE native kernels.
//!
//! The cache never owns executable-memory implementation details. Its public
//! API publishes directly through `fre-jit-runtime`, takes linear ownership
//! before charging the mapping, and exposes only cache-tracked leases. Native
//! calls and the final unmap lifecycle remain owned by `fre-jit-runtime`.

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
