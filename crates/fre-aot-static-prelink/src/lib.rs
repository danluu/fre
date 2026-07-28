//! Build-time compiler-authority checks for Count-v2 static objects.
//!
//! This package is intentionally separate from the production static runtime.
//! Its current compatibility input is [`fre_aot_compiler::CompiledObjectV2`],
//! so its dependency graph is not evidence of a JIT-independent AOT build
//! path. C2 replaces that compatibility authority with a neutral compiler
//! package before production qualification.

#![forbid(unsafe_code)]

mod error;
mod prelink;

pub use error::{PrelinkContractFieldV2, PrelinkErrorV2};
pub use prelink::{PrelinkInspectionAccountingV2, PrelinkValidationV2, validate_prelink_count_v2};
