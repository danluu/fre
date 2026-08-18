#ifndef FRE_AOT_REGEX_RUNTIME_V3_H
#define FRE_AOT_REGEX_RUNTIME_V3_H

#include "fre_aot_regex_runtime_v2.h"

#define FRE_AOT_REGEX_PREPARE_CONFIG_V3_SIZE 112u
#define FRE_AOT_REGEX_PREPARE_CONFIG_V3_VERSION 3u
#define FRE_AOT_REGEX_DEFAULT_ORDERED_NFA_MAX_HANDLE_BYTES UINT64_C(8388608)
#define FRE_AOT_REGEX_DEFAULT_ORDERED_NFA_MAX_SCRATCH_BYTES UINT64_C(8388608)
#define FRE_AOT_REGEX_DEFAULT_ORDERED_NFA_MAX_SETUP_WORK UINT64_C(2000000)
#define FRE_AOT_REGEX_PREPARE_CAPABILITY_ORDERED_NFA_V15 UINT64_C(1)
#define FRE_AOT_REGEX_PREPARE_CAPABILITY_KNOWN_FLAGS UINT64_C(1)

/*
 * Additive preparation for native Ordered-TNFA aggregate/fill objects.
 *
 * Bytes 0..64 repeat the complete V2 layout, including four reserved zero
 * words. V3 fields begin at byte 64; no V2 reserved word is reinterpreted.
 * When required_capabilities selects ORDERED_NFA_V15, COUNT or SPAN_SUM
 * requires exact scratch admission. Structural, allocation, or cap refusal
 * then fails without writing handle_out. Without the bit, V2 behavior remains.
 * The handle cap charges only the fixed-layout scratch descriptor and four
 * Pike payloads; immutable graph tables remain authenticated object rodata.
 */
typedef struct FreAotRegexPrepareConfigV3 {
    uint32_t struct_size;
    uint32_t config_version;
    uint64_t operation_flags;
    uint64_t max_start_filter_setup_work;
    uint64_t max_grep_count_workspace_bytes;
    uint64_t v2_reserved[4];
    uint64_t max_handle_bytes;
    uint64_t max_ordered_nfa_scratch_bytes;
    uint64_t max_ordered_nfa_setup_work;
    uint64_t required_capabilities;
    uint64_t reserved[2];
} FreAotRegexPrepareConfigV3;

#if defined(__cplusplus) && __cplusplus >= 201103L
static_assert(sizeof(FreAotRegexPrepareConfigV3) == 112, "V3 config size");
static_assert(alignof(FreAotRegexPrepareConfigV3) == alignof(uint64_t), "V3 config alignment");
static_assert(offsetof(FreAotRegexPrepareConfigV3, struct_size) == 0, "V3 struct_size offset");
static_assert(offsetof(FreAotRegexPrepareConfigV3, config_version) == 4, "V3 config_version offset");
static_assert(offsetof(FreAotRegexPrepareConfigV3, operation_flags) == 8, "V3 operation_flags offset");
static_assert(offsetof(FreAotRegexPrepareConfigV3, max_start_filter_setup_work) == 16, "V3 start work offset");
static_assert(offsetof(FreAotRegexPrepareConfigV3, max_grep_count_workspace_bytes) == 24, "V3 grep bytes offset");
static_assert(offsetof(FreAotRegexPrepareConfigV3, v2_reserved) == 32, "V3 V2-reserved offset");
static_assert(offsetof(FreAotRegexPrepareConfigV3, max_handle_bytes) == 64, "V3 handle cap offset");
static_assert(offsetof(FreAotRegexPrepareConfigV3, max_ordered_nfa_scratch_bytes) == 72, "V3 scratch cap offset");
static_assert(offsetof(FreAotRegexPrepareConfigV3, max_ordered_nfa_setup_work) == 80, "V3 setup cap offset");
static_assert(offsetof(FreAotRegexPrepareConfigV3, required_capabilities) == 88, "V3 capabilities offset");
static_assert(offsetof(FreAotRegexPrepareConfigV3, reserved) == 96, "V3 reserved offset");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(FreAotRegexPrepareConfigV3) == 112, "V3 config size");
_Static_assert(_Alignof(FreAotRegexPrepareConfigV3) == _Alignof(uint64_t), "V3 config alignment");
_Static_assert(offsetof(FreAotRegexPrepareConfigV3, struct_size) == 0, "V3 struct_size offset");
_Static_assert(offsetof(FreAotRegexPrepareConfigV3, config_version) == 4, "V3 config_version offset");
_Static_assert(offsetof(FreAotRegexPrepareConfigV3, operation_flags) == 8, "V3 operation_flags offset");
_Static_assert(offsetof(FreAotRegexPrepareConfigV3, max_start_filter_setup_work) == 16, "V3 start work offset");
_Static_assert(offsetof(FreAotRegexPrepareConfigV3, max_grep_count_workspace_bytes) == 24, "V3 grep bytes offset");
_Static_assert(offsetof(FreAotRegexPrepareConfigV3, v2_reserved) == 32, "V3 V2-reserved offset");
_Static_assert(offsetof(FreAotRegexPrepareConfigV3, max_handle_bytes) == 64, "V3 handle cap offset");
_Static_assert(offsetof(FreAotRegexPrepareConfigV3, max_ordered_nfa_scratch_bytes) == 72, "V3 scratch cap offset");
_Static_assert(offsetof(FreAotRegexPrepareConfigV3, max_ordered_nfa_setup_work) == 80, "V3 setup cap offset");
_Static_assert(offsetof(FreAotRegexPrepareConfigV3, required_capabilities) == 88, "V3 capabilities offset");
_Static_assert(offsetof(FreAotRegexPrepareConfigV3, reserved) == 96, "V3 reserved offset");
#endif

#ifdef __cplusplus
extern "C" {
#endif

uint32_t fre_aot_regex_runtime_prepare_exclusive_v3(
    const uint8_t *program_ptr,
    size_t program_len,
    const FreAotRegexPrepareConfigV3 *config_ptr,
    FreAotRegexExclusiveHandleV1 *handle_out);

#ifdef __cplusplus
}
#endif

#endif
