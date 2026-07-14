//! Bounded x86-64 native-image emission for verified FRE Kernel IR.
//!
//! The emitter is deliberately pattern-specialized: it lowers the two proven
//! Kernel IR v1 shapes to ordinary x86-64 control flow and comparisons. It is
//! not a regex bytecode interpreter. Emission is safe and deterministic, and
//! an independent, deliberately small decoder audits every emitted byte,
//! direct branch and RIP-relative data reference.
//!
//! This crate never allocates executable memory and never calls a generated
//! entry point. Publication, W^X transitions, guard pages and the unsafe call
//! boundary belong to a separate platform crate.

#![forbid(unsafe_code)]

mod abi;
mod aot;
mod audit;
mod emit;
mod error;
mod image;

pub use abi::{
    Architecture, CallingConvention, FeatureTier, NativeMatchV1, NativeStatus, TargetStamp,
};
pub use aot::{AotArtifact, AotHeader, AotLimits, inspect_aot};
pub use audit::{AuditLimits, AuditReport, InstructionShape, audit_image};
pub use emit::{EmitConfig, EmitLimits, emit, emit_raw};
pub use error::{
    AotError, AuditError, EmitError, EmitResource, UnsupportedKernel, UnsupportedTarget,
};
pub use image::{
    ImageStats, KernelShape, NativeImage, Relocation, RelocationKind, Section, X86AbiStamp,
};

#[cfg(test)]
mod tests;
