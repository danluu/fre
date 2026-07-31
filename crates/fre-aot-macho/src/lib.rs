//! Deterministic, bounded `MH_OBJECT` publication for audited FRE `AArch64` images.
//!
//! The native payload remains one contiguous `__TEXT,__fre_image` section:
//! emitted code, canonical zero alignment bytes, then rodata at the exact
//! image-relative offset used when ADR instructions were resolved. The object
//! has no imports or relocations. A fixed metadata record and compile identity
//! bind the payload to its target, ABI, output, planner binding, Kernel IR
//! source identity, and native artifact identity.
//!
//! This crate only creates and validates inert object bytes. It does not invoke
//! a linker, map executable memory, load a dynamic library, or publish a
//! function pointer.
//!
//! The independent Count AOT backend uses a separate 232-byte `MetadataV2` wire,
//! compile/object identity types, and a distinct private-external
//! `fre_aot_count_*_v2_<identity>` symbol family. V1 search/aggregate objects
//! retain their original metadata and cannot be inspected as V2 (or vice versa).
//!
//! Every exported name carries the full compile identity, so independently
//! generated members can coexist without process-global symbol collisions.
//! The payload section is executable and also contains rodata; this is
//! admissible only because the independent native-image audit rejects indirect
//! control flow and confines direct targets to declared code labels. A
//! final-image gate must prove RX payload. Metadata is emitted into the custom
//! `__FRE_CONST,__fre_meta` section so the final link can assign a genuinely
//! max/current read-only, non-executable segment and prove it before adoption.

#![forbid(unsafe_code)]

mod error;
mod macho;

pub use error::{ArithmeticSite, BindingIdentityError, ObjectError, ObjectResource};
pub use macho::{
    AGGREGATE_ENTRY_SYMBOL_PREFIX_V1, AbiKind, BindingIdentity, BuiltCountObjectV2, BuiltObject,
    C_HEADER, CALL_ABI_SCHEMA_V1, CALL_ABI_SCHEMA_V2, COUNT_ENTRY_SYMBOL_PREFIX_V2,
    COUNT_EXPORTED_SYMBOL_N_TYPE_V2, COUNT_METADATA_SYMBOL_PREFIX_V2,
    COUNT_PAYLOAD_SYMBOL_PREFIX_V2, ClaimedBindingIdentity, ClaimedCompileIdentity,
    ClaimedCountCompileIdentityV2, ClaimedCountObjectIdentityV2, ClaimedObjectIdentity,
    CompileIdentity, CountCompileIdentityV2, CountObjectBuildReportV2, CountObjectIdentityV2,
    CountObjectInspectionV2, CountObjectValidationV2, ENTRY_OFFSET_V1, ENTRY_OFFSET_V2,
    EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V1, EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V2,
    EXPORTED_SYMBOL_SCHEMA_VERSION_V1, EXPORTED_SYMBOL_SCHEMA_VERSION_V2, ExportedSymbolNameV1,
    ExportedSymbolNameV2, ExportedSymbolsV1, ExportedSymbolsV2, HARD_MAX_OBJECT_BYTES,
    HARD_MAX_PAYLOAD_BYTES, HARD_MAX_PERSISTENT_BYTES, HARD_MAX_SCRATCH_BYTES, HARD_MAX_SECTIONS,
    HARD_MAX_SYMBOLS, HARD_MAX_WORK, METADATA_BYTES_V1, METADATA_BYTES_V2,
    METADATA_SYMBOL_PREFIX_V1, METADATA_V2_WRITER_SCRATCH_BYTES, METADATA_VERSION,
    METADATA_VERSION_V2, MIN_MACOS_VERSION_V1, MetadataV1, MetadataV2, ObjectBuildReport,
    ObjectIdentity, ObjectInspection, ObjectLimits, ObjectValidation, PAYLOAD_SYMBOL_PREFIX_V1,
    PLATFORM_MACOS, SEARCH_ENTRY_SYMBOL_PREFIX_V1, STATUS_BITS_V1, STATUS_BITS_V2,
    emit_aggregate_object, emit_count_object_v2, emit_count_v2_object, emit_search_object,
    inspect_count_object_v2, inspect_object, validate_aggregate_object, validate_count_object_v2,
    validate_count_v2_object, validate_search_object,
};

#[cfg(test)]
mod tests;
