#ifndef FRE_AOT_REGEX_RUNTIME_V2_H
#define FRE_AOT_REGEX_RUNTIME_V2_H

#include "fre_aot_regex_runtime_v1.h"

#define FRE_AOT_REGEX_PREPARE_CONFIG_V2_SIZE 64u
#define FRE_AOT_REGEX_PREPARE_CONFIG_V2_VERSION 2u
#define FRE_AOT_REGEX_DEFAULT_START_FILTER_SETUP_WORK UINT64_C(100000000)
#define FRE_AOT_REGEX_DEFAULT_GREP_COUNT_WORKSPACE_BYTES UINT64_C(67108864)

#define FRE_AOT_REGEX_PREPARE_OPERATION_SEARCH UINT64_C(1)
#define FRE_AOT_REGEX_PREPARE_OPERATION_COUNT UINT64_C(2)
#define FRE_AOT_REGEX_PREPARE_OPERATION_SPAN_SUM UINT64_C(4)
#define FRE_AOT_REGEX_PREPARE_OPERATION_GREP_COUNT UINT64_C(8)
#define FRE_AOT_REGEX_PREPARE_OPERATION_KNOWN_FLAGS UINT64_C(15)

/*
 * Operation-aware preparation for the existing exclusive V1 handle.
 *
 * struct_size must be 64, config_version must be 2, every reserved word must
 * be zero, and operation_flags must contain no bits outside KNOWN_FLAGS.
 * COUNT and SPAN_SUM require a Span-output program. A declared SEARCH, COUNT,
 * or SPAN_SUM settles the immutable start-filter policy before source access.
 * If max_start_filter_setup_work cannot admit the complete graph-only proof,
 * preparation succeeds with permanent ordinary K0. A
 * declared GREP_COUNT eagerly owns its fixed workspace and preparation fails
 * if max_grep_count_workspace_bytes cannot admit its three logical u64
 * payload stores. Vec owners and allocator overhead are not charged to that
 * logical fixed-store cap.
 *
 * These guarantees cover the V1 runtime handle search and reducer functions;
 * compiler-produced native-fused object entries may require additional
 * object-descriptor setup in a later ABI. Undeclared operations retain the V1
 * lazy setup behavior. On every failure, handle_out is untouched. A successful
 * handle uses the V1 exclusive search, reducer, and destruction functions.
 */
typedef struct FreAotRegexPrepareConfigV2 {
    uint32_t struct_size;
    uint32_t config_version;
    uint64_t operation_flags;
    uint64_t max_start_filter_setup_work;
    uint64_t max_grep_count_workspace_bytes;
    uint64_t reserved[4];
} FreAotRegexPrepareConfigV2;

#if defined(__cplusplus) && __cplusplus >= 201103L
static_assert(sizeof(FreAotRegexPrepareConfigV2) == 64, "V2 config size");
static_assert(alignof(FreAotRegexPrepareConfigV2) == alignof(uint64_t), "V2 config alignment");
static_assert(offsetof(FreAotRegexPrepareConfigV2, struct_size) == 0, "V2 struct_size offset");
static_assert(offsetof(FreAotRegexPrepareConfigV2, config_version) == 4, "V2 config_version offset");
static_assert(offsetof(FreAotRegexPrepareConfigV2, operation_flags) == 8, "V2 operation_flags offset");
static_assert(offsetof(FreAotRegexPrepareConfigV2, max_start_filter_setup_work) == 16, "V2 start work offset");
static_assert(offsetof(FreAotRegexPrepareConfigV2, max_grep_count_workspace_bytes) == 24, "V2 grep bytes offset");
static_assert(offsetof(FreAotRegexPrepareConfigV2, reserved) == 32, "V2 reserved offset");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(FreAotRegexPrepareConfigV2) == 64, "V2 config size");
_Static_assert(_Alignof(FreAotRegexPrepareConfigV2) == _Alignof(uint64_t), "V2 config alignment");
_Static_assert(offsetof(FreAotRegexPrepareConfigV2, struct_size) == 0, "V2 struct_size offset");
_Static_assert(offsetof(FreAotRegexPrepareConfigV2, config_version) == 4, "V2 config_version offset");
_Static_assert(offsetof(FreAotRegexPrepareConfigV2, operation_flags) == 8, "V2 operation_flags offset");
_Static_assert(offsetof(FreAotRegexPrepareConfigV2, max_start_filter_setup_work) == 16, "V2 start work offset");
_Static_assert(offsetof(FreAotRegexPrepareConfigV2, max_grep_count_workspace_bytes) == 24, "V2 grep bytes offset");
_Static_assert(offsetof(FreAotRegexPrepareConfigV2, reserved) == 32, "V2 reserved offset");
#endif

#ifdef __cplusplus
extern "C" {
#endif

uint32_t fre_aot_regex_runtime_prepare_exclusive_v2(
    const uint8_t *program_ptr,
    size_t program_len,
    const FreAotRegexPrepareConfigV2 *config_ptr,
    FreAotRegexExclusiveHandleV1 *handle_out);

#ifdef __cplusplus
}
#endif

#endif
