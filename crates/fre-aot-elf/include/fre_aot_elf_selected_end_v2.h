#ifndef FRE_AOT_ELF_SELECTED_END_V2_H
#define FRE_AOT_ELF_SELECTED_END_V2_H

#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

/*
 * One compiled symbol has the exact AAPCS64 ABI:
 *
 *   x0 = haystack base, x1 = haystack length,
 *   x2 = inclusive window start, x3 = exclusive window end,
 *   x0 = absolute match end, or zero when no match exists.
 *
 * The symbol's concrete identity-suffixed declaration is emitted by
 * ExportedSymbolsV2::write_c_declarations.
 */
typedef size_t (*fre_aot_search_selected_end_entry_v2)(
    const uint8_t *haystack,
    size_t haystack_len,
    size_t window_start,
    size_t window_end);

struct fre_aot_search_selected_end_metadata_v2 {
  uint8_t magic[8];
  uint16_t format_version;
  uint16_t record_bytes;
  uint16_t backend_version;
  uint8_t abi_kind;
  uint8_t output_kind;
  uint8_t architecture;
  uint8_t little_endian;
  uint8_t pointer_width;
  uint8_t target_abi;
  uint8_t platform;
  uint8_t return_bits;
  uint16_t abi_schema;
  uint8_t return_encoding;
  uint8_t window_contract;
  uint16_t fixed_active_vector_bytes;
  uint32_t reserved_zero;
  uint64_t features;
  uint32_t payload_bytes;
  uint32_t entry_offset;
  uint32_t code_bytes;
  uint32_t rodata_offset;
  uint32_t rodata_bytes;
  uint32_t literal_bytes;
  uint8_t source_identity[32];
  uint8_t artifact_identity[32];
  uint8_t binding_identity[32];
  uint8_t payload_sha256[32];
  uint8_t compile_identity[32];
};

#if defined(__cplusplus)
}

#define FRE_AOT_SELECTED_END_V2_STATIC_ASSERT(condition, message) \
  static_assert(condition, message)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define FRE_AOT_SELECTED_END_V2_STATIC_ASSERT(condition, message) \
  _Static_assert(condition, message)
#else
#define FRE_AOT_SELECTED_END_V2_STATIC_ASSERT(condition, message)
#endif

FRE_AOT_SELECTED_END_V2_STATIC_ASSERT(
    sizeof(struct fre_aot_search_selected_end_metadata_v2) == 224,
    "SelectedEnd-v2 metadata must remain exactly 224 bytes");
FRE_AOT_SELECTED_END_V2_STATIC_ASSERT(
    offsetof(struct fre_aot_search_selected_end_metadata_v2, format_version) == 8,
    "SelectedEnd-v2 format_version offset");
FRE_AOT_SELECTED_END_V2_STATIC_ASSERT(
    offsetof(struct fre_aot_search_selected_end_metadata_v2, backend_version) == 12,
    "SelectedEnd-v2 backend_version offset");
FRE_AOT_SELECTED_END_V2_STATIC_ASSERT(
    offsetof(struct fre_aot_search_selected_end_metadata_v2, abi_schema) == 22,
    "SelectedEnd-v2 abi_schema offset");
FRE_AOT_SELECTED_END_V2_STATIC_ASSERT(
    offsetof(struct fre_aot_search_selected_end_metadata_v2,
             fixed_active_vector_bytes) == 26,
    "SelectedEnd-v2 fixed_active_vector_bytes offset");
FRE_AOT_SELECTED_END_V2_STATIC_ASSERT(
    offsetof(struct fre_aot_search_selected_end_metadata_v2, reserved_zero) == 28,
    "SelectedEnd-v2 reserved_zero offset");
FRE_AOT_SELECTED_END_V2_STATIC_ASSERT(
    offsetof(struct fre_aot_search_selected_end_metadata_v2, features) == 32,
    "SelectedEnd-v2 features offset");
FRE_AOT_SELECTED_END_V2_STATIC_ASSERT(
    offsetof(struct fre_aot_search_selected_end_metadata_v2, payload_bytes) == 40,
    "SelectedEnd-v2 payload_bytes offset");
FRE_AOT_SELECTED_END_V2_STATIC_ASSERT(
    offsetof(struct fre_aot_search_selected_end_metadata_v2, source_identity) == 64,
    "SelectedEnd-v2 source_identity offset");
FRE_AOT_SELECTED_END_V2_STATIC_ASSERT(
    offsetof(struct fre_aot_search_selected_end_metadata_v2, artifact_identity) == 96,
    "SelectedEnd-v2 artifact_identity offset");
FRE_AOT_SELECTED_END_V2_STATIC_ASSERT(
    offsetof(struct fre_aot_search_selected_end_metadata_v2, binding_identity) == 128,
    "SelectedEnd-v2 binding_identity offset");
FRE_AOT_SELECTED_END_V2_STATIC_ASSERT(
    offsetof(struct fre_aot_search_selected_end_metadata_v2, payload_sha256) == 160,
    "SelectedEnd-v2 payload_sha256 offset");
FRE_AOT_SELECTED_END_V2_STATIC_ASSERT(
    offsetof(struct fre_aot_search_selected_end_metadata_v2, compile_identity) == 192,
    "SelectedEnd-v2 compile_identity offset");

#undef FRE_AOT_SELECTED_END_V2_STATIC_ASSERT

#endif
