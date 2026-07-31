//! Deterministic Linux `AArch64` ELF publication for authenticated FRE Search
//! images.
//!
//! This crate writes deliberately small, version-separated `ELF64LE` `ET_REL`
//! shapes. Each generated image payload remains byte-for-byte contiguous in
//! one executable section, so the JIT emitter's authenticated code-to-rodata
//! displacement is preserved by the system linker. Identity-suffixed entry,
//! payload, and metadata symbols bind final-image glue to exactly one compiler
//! receipt.
//!
//! Object emission never invokes a linker, maps executable memory, probes the
//! build host, or grants runtime/qualification authority.

#![forbid(unsafe_code)]

mod error;
mod identity;
mod identity_v2;
mod metadata;
mod metadata_v2;
mod object;
mod object_v2;

pub use error::{ElfObjectError, ElfObjectResource};
pub use identity::{
    BindingIdentity, BindingIdentityError, ClaimedBindingIdentity, ClaimedCompileIdentity,
    ClaimedObjectIdentity, CompileIdentity, EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V1,
    EXPORTED_SYMBOL_SCHEMA_VERSION_V1, ExportedSymbolNameV1, ExportedSymbolsV1,
    METADATA_SYMBOL_PREFIX_V1, ObjectIdentity, PAYLOAD_SYMBOL_PREFIX_V1,
    SEARCH_ENTRY_SYMBOL_PREFIX_V1,
};
pub use identity_v2::{
    EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V2, EXPORTED_SYMBOL_SCHEMA_VERSION_V2, ExportedSymbolNameV2,
    ExportedSymbolsV2, SEARCH_SELECTED_END_ENTRY_SYMBOL_PREFIX_V2,
    SELECTED_END_METADATA_SYMBOL_PREFIX_V2, SELECTED_END_PAYLOAD_SYMBOL_PREFIX_V2,
};
pub use metadata::{
    CALL_ABI_SCHEMA_V1, ELF_CLASS_64_V1, ELF_DATA_LSB_V1, ELF_MACHINE_AARCH64_V1,
    ELF_OS_ABI_SYSV_V1, ELF_RELOCATABLE_TYPE_V1, ELF_VERSION_CURRENT_V1, ENTRY_OFFSET_V1,
    METADATA_BYTES_V1, METADATA_VERSION_V1, MetadataV1, PLATFORM_LINUX_V1, SEARCH_ABI_KIND_V1,
    STATUS_BITS_V1, inspect_metadata_v1,
};
pub use metadata_v2::{
    ELF_CLASS_64_V2, ELF_DATA_LSB_V2, ELF_MACHINE_AARCH64_V2, ELF_OS_ABI_SYSV_V2,
    ELF_RELOCATABLE_TYPE_V2, ELF_SYMBOL_INFO_FUNCTION_V2, ELF_SYMBOL_INFO_OBJECT_V2,
    ELF_SYMBOL_VISIBILITY_HIDDEN_V2, ELF_VERSION_CURRENT_V2, SELECTED_END_ABI_KIND_V2,
    SELECTED_END_ARCHITECTURE_AARCH64_V2, SELECTED_END_ARGUMENT_COUNT_V2,
    SELECTED_END_BACKEND_VERSION_V2, SELECTED_END_CALL_ABI_SCHEMA_V2, SELECTED_END_ENTRY_OFFSET_V2,
    SELECTED_END_FIXED_ACTIVE_VECTOR_BYTES_V2, SELECTED_END_LITERAL_BYTES_V2,
    SELECTED_END_LITTLE_ENDIAN_V2, SELECTED_END_METADATA_BYTES_V2,
    SELECTED_END_METADATA_VERSION_V2, SELECTED_END_NO_MATCH_SENTINEL_V2,
    SELECTED_END_OUTPUT_KIND_V2, SELECTED_END_PLATFORM_LINUX_V2, SELECTED_END_POINTER_WIDTH_V2,
    SELECTED_END_REQUIRED_FEATURES_V2, SELECTED_END_RESULT_SLOT_BYTES_V2,
    SELECTED_END_RETURN_BITS_V2, SELECTED_END_RETURN_ENCODING_END_OR_ZERO_V2,
    SELECTED_END_RETURN_REGISTER_V2, SELECTED_END_TARGET_ABI_AAPCS64_V2,
    SELECTED_END_WINDOW_CONTRACT_HALF_OPEN_ABSOLUTE_END_V2, SelectedEndMetadataV2,
    inspect_selected_end_metadata_v2,
};
pub use object::{
    BuiltSearchObjectV1, HARD_MAX_OBJECT_BYTES_V1, HARD_MAX_PAYLOAD_BYTES_V1,
    HARD_MAX_PERSISTENT_BYTES_V1, ObjectBuildReportV1, ObjectInspectionV1, ObjectLimitsV1,
    ObjectValidationV1, emit_search_object_v1, inspect_search_object_v1, validate_search_object_v1,
};
pub use object_v2::{
    BuiltSelectedEndSearchObjectV2, HARD_MAX_SELECTED_END_OBJECT_BYTES_V2,
    HARD_MAX_SELECTED_END_PAYLOAD_BYTES_V2, HARD_MAX_SELECTED_END_PERSISTENT_BYTES_V2,
    SelectedEndObjectBuildReportV2, SelectedEndObjectInspectionV2, SelectedEndObjectLimitsV2,
    SelectedEndObjectValidationV2, emit_selected_end_search_object_v2,
    inspect_selected_end_search_object_v2, validate_selected_end_search_object_v2,
};

/// Stable C ABI layout shared by every Linux Search symbol set.
pub const C_HEADER_V1: &str = include_str!("../include/fre_aot_elf.h");

/// Stable C ABI layout for Linux tag21 SelectedEnd register-return V2.
pub const C_SELECTED_END_HEADER_V2: &str = include_str!("../include/fre_aot_elf_selected_end_v2.h");

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_v2;
