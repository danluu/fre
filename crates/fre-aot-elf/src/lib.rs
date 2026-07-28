//! Deterministic Linux `AArch64` ELF publication for authenticated FRE Search
//! images.
//!
//! This crate writes one deliberately small `ELF64LE` `ET_REL` shape. The
//! generated image payload remains byte-for-byte contiguous in one executable
//! section, so the JIT emitter's authenticated code-to-rodata displacement is
//! preserved by the system linker. Identity-suffixed entry, payload, and
//! metadata symbols bind final-image glue to exactly one compiler receipt.
//!
//! Object emission never invokes a linker, maps executable memory, probes the
//! build host, or grants runtime/qualification authority.

#![forbid(unsafe_code)]

mod error;
mod identity;
mod metadata;
mod object;

pub use error::{ElfObjectError, ElfObjectResource};
pub use identity::{
    BindingIdentity, BindingIdentityError, ClaimedBindingIdentity, ClaimedCompileIdentity,
    ClaimedObjectIdentity, CompileIdentity, EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V1,
    EXPORTED_SYMBOL_SCHEMA_VERSION_V1, ExportedSymbolNameV1, ExportedSymbolsV1,
    METADATA_SYMBOL_PREFIX_V1, ObjectIdentity, PAYLOAD_SYMBOL_PREFIX_V1,
    SEARCH_ENTRY_SYMBOL_PREFIX_V1,
};
pub use metadata::{
    CALL_ABI_SCHEMA_V1, ELF_CLASS_64_V1, ELF_DATA_LSB_V1, ELF_MACHINE_AARCH64_V1,
    ELF_OS_ABI_SYSV_V1, ELF_RELOCATABLE_TYPE_V1, ELF_VERSION_CURRENT_V1, ENTRY_OFFSET_V1,
    METADATA_BYTES_V1, METADATA_VERSION_V1, MetadataV1, PLATFORM_LINUX_V1, SEARCH_ABI_KIND_V1,
    STATUS_BITS_V1, inspect_metadata_v1,
};
pub use object::{
    BuiltSearchObjectV1, HARD_MAX_OBJECT_BYTES_V1, HARD_MAX_PAYLOAD_BYTES_V1,
    HARD_MAX_PERSISTENT_BYTES_V1, ObjectBuildReportV1, ObjectInspectionV1, ObjectLimitsV1,
    ObjectValidationV1, emit_search_object_v1, inspect_search_object_v1, validate_search_object_v1,
};

/// Stable C ABI layout shared by every Linux Search symbol set.
pub const C_HEADER_V1: &str = include_str!("../include/fre_aot_elf.h");

#[cfg(test)]
mod tests;
