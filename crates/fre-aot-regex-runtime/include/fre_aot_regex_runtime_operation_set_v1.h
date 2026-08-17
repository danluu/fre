#ifndef FRE_AOT_REGEX_RUNTIME_OPERATION_SET_V1_H
#define FRE_AOT_REGEX_RUNTIME_OPERATION_SET_V1_H

#include "fre_aot_regex_runtime_v1.h"

#define FRE_AOT_REGEX_OPERATION_SET_PREPARE_CONFIG_V1_SIZE 64u
#define FRE_AOT_REGEX_OPERATION_SET_PREPARE_CONFIG_V1_VERSION 1u
#define FRE_AOT_REGEX_DEFAULT_OPERATION_SET_MAX_HANDLE_BYTES UINT64_C(1073741824)
#define FRE_AOT_REGEX_OPERATION_SET_DEFAULT_START_FILTER_SETUP_WORK UINT64_C(100000000)
#define FRE_AOT_REGEX_OPERATION_SET_DEFAULT_GREP_COUNT_WORKSPACE_BYTES UINT64_C(67108864)

#define FRE_AOT_REGEX_OPERATION_SET_OUTPUT_SEARCH_EXISTS 1u
#define FRE_AOT_REGEX_OPERATION_SET_OUTPUT_SEARCH_SELECTED_END 2u
#define FRE_AOT_REGEX_OPERATION_SET_OUTPUT_SEARCH_SPAN 3u
#define FRE_AOT_REGEX_OPERATION_SET_OUTPUT_COUNT 4u
#define FRE_AOT_REGEX_OPERATION_SET_OUTPUT_SPAN_SUM 5u
#define FRE_AOT_REGEX_OPERATION_SET_OUTPUT_GREP_COUNT 6u

/*
 * Every cap applies once to the complete prepared handle. max_handle_bytes
 * covers retained owner payload, including final vector capacities, decoded
 * generic graphs, ordinary workspaces, optional start-filter proofs, and
 * GrepCount stores. It excludes transient construction storage, allocator
 * metadata, and the input wire, which is not retained. Admitted proof payload
 * maxima and exact GrepCount logical stores are charged before either owner is
 * allocated; actual retained capacities are rechecked before publication. The
 * start-filter cap admits all strongest-proof attempts or deterministically
 * selects ordinary K0 for every start-using member. An admitted attempt can
 * still select ordinary K0 if its optional owner allocation fails. GrepCount
 * preparation fails when the checked sum of unique-member logical fixed
 * stores exceeds its cap. Every reserved word must be zero.
 */
typedef struct FreAotRegexOperationSetPrepareConfigV1 {
    uint32_t struct_size;
    uint32_t config_version;
    uint64_t max_handle_bytes;
    uint64_t max_start_filter_setup_work;
    uint64_t max_grep_count_workspace_bytes;
    uint64_t reserved[4];
} FreAotRegexOperationSetPrepareConfigV1;

typedef void *FreAotRegexOperationSetExclusiveHandleV1;

/*
 * One root-aligned output. Search kinds bind the member output contract and
 * use status 0/1 for no-match/match. Exists keeps first/second zero;
 * SelectedEnd stores end/end; Span stores start/end. Scalar kinds use status
 * zero, store the result in first, and keep second zero.
 */
typedef struct FreAotRegexOperationSetOutputV1 {
    uint32_t kind;
    uint32_t status;
    uint64_t first;
    uint64_t second;
} FreAotRegexOperationSetOutputV1;

#if defined(__cplusplus) && __cplusplus >= 201103L
static_assert(sizeof(FreAotRegexOperationSetPrepareConfigV1) == 64, "operation-set config size");
static_assert(alignof(FreAotRegexOperationSetPrepareConfigV1) == alignof(uint64_t), "operation-set config alignment");
static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV1, struct_size) == 0, "operation-set struct_size offset");
static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV1, config_version) == 4, "operation-set config_version offset");
static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV1, max_handle_bytes) == 8, "operation-set handle cap offset");
static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV1, max_start_filter_setup_work) == 16, "operation-set start-work cap offset");
static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV1, max_grep_count_workspace_bytes) == 24, "operation-set grep cap offset");
static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV1, reserved) == 32, "operation-set reserved offset");
static_assert(sizeof(FreAotRegexOperationSetExclusiveHandleV1) == sizeof(void *), "operation-set handle size");
static_assert(sizeof(FreAotRegexOperationSetOutputV1) == 24, "operation-set output size");
static_assert(alignof(FreAotRegexOperationSetOutputV1) == alignof(uint64_t), "operation-set output alignment");
static_assert(offsetof(FreAotRegexOperationSetOutputV1, kind) == 0, "operation-set output kind offset");
static_assert(offsetof(FreAotRegexOperationSetOutputV1, status) == 4, "operation-set output status offset");
static_assert(offsetof(FreAotRegexOperationSetOutputV1, first) == 8, "operation-set output first offset");
static_assert(offsetof(FreAotRegexOperationSetOutputV1, second) == 16, "operation-set output second offset");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(FreAotRegexOperationSetPrepareConfigV1) == 64, "operation-set config size");
_Static_assert(_Alignof(FreAotRegexOperationSetPrepareConfigV1) == _Alignof(uint64_t), "operation-set config alignment");
_Static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV1, struct_size) == 0, "operation-set struct_size offset");
_Static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV1, config_version) == 4, "operation-set config_version offset");
_Static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV1, max_handle_bytes) == 8, "operation-set handle cap offset");
_Static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV1, max_start_filter_setup_work) == 16, "operation-set start-work cap offset");
_Static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV1, max_grep_count_workspace_bytes) == 24, "operation-set grep cap offset");
_Static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV1, reserved) == 32, "operation-set reserved offset");
_Static_assert(sizeof(FreAotRegexOperationSetExclusiveHandleV1) == sizeof(void *), "operation-set handle size");
_Static_assert(sizeof(FreAotRegexOperationSetOutputV1) == 24, "operation-set output size");
_Static_assert(_Alignof(FreAotRegexOperationSetOutputV1) == _Alignof(uint64_t), "operation-set output alignment");
_Static_assert(offsetof(FreAotRegexOperationSetOutputV1, kind) == 0, "operation-set output kind offset");
_Static_assert(offsetof(FreAotRegexOperationSetOutputV1, status) == 4, "operation-set output status offset");
_Static_assert(offsetof(FreAotRegexOperationSetOutputV1, first) == 8, "operation-set output first offset");
_Static_assert(offsetof(FreAotRegexOperationSetOutputV1, second) == 16, "operation-set output second offset");
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Validate and prepare the supported Stage-1 subset of one canonical
 * operation-set wire: scalar members in the canonical optimizer-free V4
 * OrderedNfa generic form and Search, Count, SpanSum, or GrepCount roots only.
 * Count and SpanSum require a Span-output member. All other member
 * representations and root axes are unsupported and fail closed.
 *
 * operation_set_ptr must be non-null and readable for exactly
 * operation_set_len bytes, including when the length is zero. config_ptr must
 * be non-null, naturally aligned, and readable for one complete config.
 * handle_out must be non-null, naturally aligned, writable for one handle,
 * and disjoint from both readable extents. Readability, writability, complete
 * extent, and non-overlap are caller safety preconditions; dangling, short,
 * read-only, or overlapping storage is not recoverably validated.
 *
 * Configuration is validated before the wire is inspected. Success returns
 * FRE_AOT_REGEX_STATUS_SUCCESS (zero) and initializes handle_out. A null
 * pointer, misaligned config/output, operation_set_len beyond the supported
 * signed pointer extent, or invalid config returns
 * FRE_AOT_REGEX_STATUS_INVALID_ARGUMENT. Malformed/unsupported wire,
 * arithmetic/resource refusal, or allocation/preparation failure returns
 * FRE_AOT_REGEX_STATUS_RUNTIME_FAILURE. Every recoverable failure leaves
 * handle_out untouched.
 *
 * The returned handle owns all retained state and borrows neither input. It is
 * an exclusive lifecycle capability: do not copy it for concurrent use, do
 * not overlap execute with execute or destroy, destroy it exactly once, and
 * do not use any copy after destruction.
 */
uint32_t fre_aot_regex_runtime_prepare_operation_set_exclusive_v1(
    const uint8_t *operation_set_ptr,
    size_t operation_set_len,
    const FreAotRegexOperationSetPrepareConfigV1 *config_ptr,
    FreAotRegexOperationSetExclusiveHandleV1 *handle_out);

/*
 * Execute every prepared root in canonical wire order.
 *
 * handle must be live and exclusively owned. haystack_ptr must be non-null
 * and readable for exactly haystack_len bytes, including when the length is
 * zero. outputs must be non-null, naturally aligned, writable for exactly
 * output_count records. The haystack extent, output extent, and handle
 * allocation together with all handle-owned storage must be pairwise
 * disjoint. The count must exactly equal the prepared root count.
 * Readability, writability, complete extent, disjointness, and exclusive
 * validity of any nonnull handle are caller safety preconditions; dangling,
 * short, read-only, overlapping, copied-concurrent, or destroyed storage is
 * not recoverably validated.
 *
 * Success returns
 * FRE_AOT_REGEX_STATUS_SUCCESS (zero) and initializes the complete array;
 * Search match/no-match is carried by each Search record's status. Every
 * recoverable failure leaves the complete caller output array untouched. A
 * null handle returns FRE_AOT_REGEX_STATUS_INVALID_HANDLE. A null source or
 * output, misaligned output, unsupported signed pointer extent, or mismatched
 * output_count returns FRE_AOT_REGEX_STATUS_INVALID_ARGUMENT. Root execution
 * failure returns FRE_AOT_REGEX_STATUS_RUNTIME_FAILURE. INVALID_ARGUMENT is
 * detected before source/workspace mutation and leaves the live handle
 * reusable. RUNTIME_FAILURE can leave handle-internal scratch/workspace
 * advanced; caller output remains untouched, but the handle is then valid
 * only for one destroy and must not be executed again.
 */
uint32_t fre_aot_regex_runtime_execute_operation_set_exclusive_v1(
    FreAotRegexOperationSetExclusiveHandleV1 handle,
    const uint8_t *haystack_ptr,
    size_t haystack_len,
    FreAotRegexOperationSetOutputV1 *outputs,
    size_t output_count);

/*
 * Destroy one live exclusively owned handle exactly once. Live ownership is a
 * caller safety precondition: a dangling, copied-concurrent, or previously
 * destroyed nonnull handle is not recoverably validated. No execute may
 * overlap this call, and no handle copy may be used afterward. A null handle
 * returns FRE_AOT_REGEX_STATUS_INVALID_HANDLE; successful destruction returns
 * FRE_AOT_REGEX_STATUS_SUCCESS, and an unexpected destruction failure returns
 * FRE_AOT_REGEX_STATUS_RUNTIME_FAILURE.
 */
uint32_t fre_aot_regex_runtime_destroy_operation_set_exclusive_v1(
    FreAotRegexOperationSetExclusiveHandleV1 handle);

#ifdef __cplusplus
}
#endif

#endif
