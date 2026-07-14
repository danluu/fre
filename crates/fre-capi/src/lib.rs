//! Stable C ABI for FRE's current portable single-search subset.
//!
//! The implemented v1 surface is deliberately smaller than the future target
//! contract: Rust-bytes profile compilation, immutable shared handles, and
//! exists/selected-end/span searches only.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(unsafe_code)]

mod abi;
mod boundary;
mod engine;

#[allow(
    unsafe_code,
    reason = "all C pointer validation, opaque Arc ownership, and versioned exports are isolated here"
)]
mod ffi;

pub use abi::*;
pub use ffi::{
    fre_v1_config_default, fre_v1_get_abi_descriptor, fre_v1_regex_compile, fre_v1_regex_exists,
    fre_v1_regex_plan, fre_v1_regex_release, fre_v1_regex_retain, fre_v1_regex_selected_end,
    fre_v1_regex_span,
};

#[cfg(test)]
mod tests;
