#ifndef FRE_AOT_ELF_H
#define FRE_AOT_ELF_H

#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

struct fre_aot_search_result_v1 {
  size_t start;
  size_t end;
};

struct fre_aot_metadata_v1 {
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
  uint8_t status_bits;
  uint16_t abi_schema;
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
#endif

#endif
