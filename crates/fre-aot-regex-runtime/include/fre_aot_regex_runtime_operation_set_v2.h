#ifndef FRE_AOT_REGEX_RUNTIME_OPERATION_SET_V2_H
#define FRE_AOT_REGEX_RUNTIME_OPERATION_SET_V2_H

#include "fre_aot_regex_runtime_operation_set_v1.h"

#define FRE_AOT_REGEX_OPERATION_SET_PREPARE_CONFIG_V2_SIZE 184u
#define FRE_AOT_REGEX_OPERATION_SET_PREPARE_CONFIG_V2_VERSION 2u
#define FRE_AOT_REGEX_OPERATION_SET_V2_DEFAULT_CAPTURE_VALIDATION_SCRATCH_BYTES UINT64_C(16777216)
#define FRE_AOT_REGEX_OPERATION_SET_V2_DEFAULT_CAPTURE_OWNER_BYTES UINT64_C(536870912)
#define FRE_AOT_REGEX_OPERATION_SET_V2_DEFAULT_CAPTURE_WORKSPACE_BYTES UINT64_C(536870912)
#define FRE_AOT_REGEX_OPERATION_SET_V2_DEFAULT_CAPTURE_WORK UINT64_C(1099511627776)
#define FRE_AOT_REGEX_OPERATION_SET_V2_DEFAULT_CAPTURE_EVENTS UINT64_C(1099511627776)
#define FRE_AOT_REGEX_OPERATION_SET_V2_DEFAULT_CAPTURE_COUNT UINT64_C(1099511627776)

#define FRE_AOT_REGEX_OPERATION_SET_OUTPUT_CAPTURE_PARTICIPATION_COUNT 7u

/*
 * Exact-source preparation policy for canonical operation-set wire V2.
 * Configuration is copied, all reserved words and every host-size conversion
 * are validated, and exact_source_bytes is checked against the supported
 * signed pointer domain before any byte of the candidate wire is read.
 *
 * All aggregate caps apply once to the complete handle. Capture-program
 * fields map directly to the stable CaptureProgramV1 resource dimensions.
 * max_capture_validation_scratch_bytes covers the exact transient u32 census
 * prefix and each safe owner reconstruction's same-shaped internal prefix.
 * The shared census prefix is released first, so these bounded transient
 * owners are sequential rather than co-live, and none is retained.
 * max_capture_owner_bytes covers the measured retained Program vector/string
 * capacities plus the exact inline Program payload requested for its unique
 * Box owner. This logical boundary does not claim allocator metadata or
 * usable-size rounding.
 * max_capture_workspace_bytes covers each unique CaptureStream inline value
 * and its exact allocator-requested workspace, excluding the unique immutable
 * Program charged by max_capture_owner_bytes. Duplicate roots do not multiply
 * either unique-member charge. max_capture_work, max_capture_events, and
 * max_capture_count independently cap their complete source-free envelopes.
 */
typedef struct FreAotRegexOperationSetPrepareConfigV2 {
    uint32_t struct_size;
    uint32_t config_version;
    uint64_t exact_source_bytes;
    uint64_t max_handle_bytes;
    uint64_t max_start_filter_setup_work;
    uint64_t max_grep_count_workspace_bytes;
    uint64_t max_capture_validation_scratch_bytes;
    uint64_t max_capture_owner_bytes;
    uint64_t max_capture_workspace_bytes;
    uint64_t max_capture_work;
    uint64_t max_capture_events;
    uint64_t max_capture_count;
    uint64_t capture_max_serialized_bytes;
    uint64_t capture_max_states;
    uint64_t capture_max_byte_ranges;
    uint64_t capture_max_groups;
    uint64_t capture_max_slots;
    uint64_t capture_max_name_bytes;
    uint64_t capture_max_validation_work;
    uint64_t capture_max_program_bytes;
    uint64_t reserved[4];
} FreAotRegexOperationSetPrepareConfigV2;

typedef void *FreAotRegexOperationSetExclusiveHandleV2;

/*
 * Root-aligned V2 output. Kinds 1--6 preserve V1's exact scalar/search
 * encoding. Kind 7 stores whole-domain capture-participation Count, including
 * group zero, in first with success status zero and second equal to zero.
 */
typedef struct FreAotRegexOperationSetOutputV2 {
    uint32_t kind;
    uint32_t status;
    uint64_t first;
    uint64_t second;
} FreAotRegexOperationSetOutputV2;

#if defined(__cplusplus) && __cplusplus >= 201103L
static_assert(sizeof(FreAotRegexOperationSetPrepareConfigV2) == 184, "operation-set V2 config size");
static_assert(alignof(FreAotRegexOperationSetPrepareConfigV2) == alignof(uint64_t), "operation-set V2 config alignment");
static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, struct_size) == 0, "operation-set V2 struct_size offset");
static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, config_version) == 4, "operation-set V2 config_version offset");
static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, exact_source_bytes) == 8, "operation-set V2 source offset");
static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, max_handle_bytes) == 16, "operation-set V2 handle cap offset");
static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, max_start_filter_setup_work) == 24, "operation-set V2 start-work offset");
static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, max_grep_count_workspace_bytes) == 32, "operation-set V2 grep offset");
static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, max_capture_validation_scratch_bytes) == 40, "operation-set V2 capture scratch offset");
static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, max_capture_owner_bytes) == 48, "operation-set V2 capture owner offset");
static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, max_capture_workspace_bytes) == 56, "operation-set V2 capture workspace offset");
static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, max_capture_work) == 64, "operation-set V2 capture work offset");
static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, max_capture_events) == 72, "operation-set V2 capture events offset");
static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, max_capture_count) == 80, "operation-set V2 capture count offset");
static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, capture_max_serialized_bytes) == 88, "operation-set V2 capture serialized offset");
static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, capture_max_states) == 96, "operation-set V2 capture states offset");
static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, capture_max_byte_ranges) == 104, "operation-set V2 capture ranges offset");
static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, capture_max_groups) == 112, "operation-set V2 capture groups offset");
static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, capture_max_slots) == 120, "operation-set V2 capture slots offset");
static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, capture_max_name_bytes) == 128, "operation-set V2 capture names offset");
static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, capture_max_validation_work) == 136, "operation-set V2 capture validation offset");
static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, capture_max_program_bytes) == 144, "operation-set V2 capture program offset");
static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, reserved) == 152, "operation-set V2 reserved offset");
static_assert(sizeof(FreAotRegexOperationSetExclusiveHandleV2) == sizeof(void *), "operation-set V2 handle size");
static_assert(sizeof(FreAotRegexOperationSetOutputV2) == 24, "operation-set V2 output size");
static_assert(alignof(FreAotRegexOperationSetOutputV2) == alignof(uint64_t), "operation-set V2 output alignment");
static_assert(offsetof(FreAotRegexOperationSetOutputV2, kind) == 0, "operation-set V2 output kind offset");
static_assert(offsetof(FreAotRegexOperationSetOutputV2, status) == 4, "operation-set V2 output status offset");
static_assert(offsetof(FreAotRegexOperationSetOutputV2, first) == 8, "operation-set V2 output first offset");
static_assert(offsetof(FreAotRegexOperationSetOutputV2, second) == 16, "operation-set V2 output second offset");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(FreAotRegexOperationSetPrepareConfigV2) == 184, "operation-set V2 config size");
_Static_assert(_Alignof(FreAotRegexOperationSetPrepareConfigV2) == _Alignof(uint64_t), "operation-set V2 config alignment");
_Static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, struct_size) == 0, "operation-set V2 struct_size offset");
_Static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, config_version) == 4, "operation-set V2 config_version offset");
_Static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, exact_source_bytes) == 8, "operation-set V2 source offset");
_Static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, max_handle_bytes) == 16, "operation-set V2 handle cap offset");
_Static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, max_start_filter_setup_work) == 24, "operation-set V2 start-work offset");
_Static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, max_grep_count_workspace_bytes) == 32, "operation-set V2 grep offset");
_Static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, max_capture_validation_scratch_bytes) == 40, "operation-set V2 capture scratch offset");
_Static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, max_capture_owner_bytes) == 48, "operation-set V2 capture owner offset");
_Static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, max_capture_workspace_bytes) == 56, "operation-set V2 capture workspace offset");
_Static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, max_capture_work) == 64, "operation-set V2 capture work offset");
_Static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, max_capture_events) == 72, "operation-set V2 capture events offset");
_Static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, max_capture_count) == 80, "operation-set V2 capture count offset");
_Static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, capture_max_serialized_bytes) == 88, "operation-set V2 capture serialized offset");
_Static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, capture_max_states) == 96, "operation-set V2 capture states offset");
_Static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, capture_max_byte_ranges) == 104, "operation-set V2 capture ranges offset");
_Static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, capture_max_groups) == 112, "operation-set V2 capture groups offset");
_Static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, capture_max_slots) == 120, "operation-set V2 capture slots offset");
_Static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, capture_max_name_bytes) == 128, "operation-set V2 capture names offset");
_Static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, capture_max_validation_work) == 136, "operation-set V2 capture validation offset");
_Static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, capture_max_program_bytes) == 144, "operation-set V2 capture program offset");
_Static_assert(offsetof(FreAotRegexOperationSetPrepareConfigV2, reserved) == 152, "operation-set V2 reserved offset");
_Static_assert(sizeof(FreAotRegexOperationSetExclusiveHandleV2) == sizeof(void *), "operation-set V2 handle size");
_Static_assert(sizeof(FreAotRegexOperationSetOutputV2) == 24, "operation-set V2 output size");
_Static_assert(_Alignof(FreAotRegexOperationSetOutputV2) == _Alignof(uint64_t), "operation-set V2 output alignment");
_Static_assert(offsetof(FreAotRegexOperationSetOutputV2, kind) == 0, "operation-set V2 output kind offset");
_Static_assert(offsetof(FreAotRegexOperationSetOutputV2, status) == 4, "operation-set V2 output status offset");
_Static_assert(offsetof(FreAotRegexOperationSetOutputV2, first) == 8, "operation-set V2 output first offset");
_Static_assert(offsetof(FreAotRegexOperationSetOutputV2, second) == 16, "operation-set V2 output second offset");
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Validate and prepare the exact-source scalar subset of one canonical V2
 * operation set. Compiled members retain V1 Search/Count/SpanSum/Grep
 * behavior. Capture members admit only Whole+Count+CaptureParticipation and
 * must be nonnullable. PerLine capture, capture tuples, many-pattern/native
 * composition, and future member kinds fail closed.
 *
 * operation_set_ptr must be non-null and readable for exactly
 * operation_set_len bytes, including when the length is zero. config_ptr must
 * be non-null, naturally aligned, and readable for one complete config.
 * handle_out must be non-null, naturally aligned, writable for one handle,
 * and disjoint from both readable extents. Readability, writability, complete
 * extent, liveness, and non-overlap are caller safety preconditions; dangling,
 * short, read-only, or overlapping storage is not recoverably validated.
 *
 * Configuration is validated before the wire is inspected. Success writes
 * handle_out only after the complete transaction and returns
 * FRE_AOT_REGEX_STATUS_SUCCESS (zero). A null pointer, misaligned
 * config/output, operation_set_len beyond the supported signed pointer extent,
 * or invalid config returns FRE_AOT_REGEX_STATUS_INVALID_ARGUMENT. Malformed
 * or unsupported wire, arithmetic/resource refusal, allocation/preparation
 * failure, or panic returns FRE_AOT_REGEX_STATUS_RUNTIME_FAILURE. Every
 * recoverable failure leaves handle_out untouched.
 *
 * The returned handle borrows neither config nor wire and is an exclusive
 * lifecycle capability: do not copy it for concurrent use, do not overlap
 * execute with execute or destroy, destroy it exactly once, and do not use any
 * copy after destruction.
 */
uint32_t fre_aot_regex_runtime_prepare_operation_set_exclusive_v2(
    const uint8_t *operation_set_ptr,
    size_t operation_set_len,
    const FreAotRegexOperationSetPrepareConfigV2 *config_ptr,
    FreAotRegexOperationSetExclusiveHandleV2 *handle_out);

/*
 * Execute every prepared root in canonical wire order. handle must be live and
 * exclusively owned. haystack_ptr must be non-null and readable for exactly
 * haystack_len bytes, including when the length is zero; haystack_len must
 * equal the exact_source_bytes bound at preparation. outputs must be non-null,
 * naturally aligned, and writable for exactly output_count records. The count
 * must exactly equal the prepared root count. The haystack extent, complete
 * output extent, handle allocation, and all handle-owned storage must be
 * pairwise disjoint and remain live for the call; execute and destroy may not
 * overlap. Readability, writability, complete extent, disjointness, and
 * exclusive validity of any nonnull handle are caller safety preconditions;
 * dangling, short, read-only, overlapping, copied-concurrent, stale, or
 * destroyed storage is not recoverably validated.
 *
 * Roots write private scratch and the caller array is copied only after every
 * root succeeds. A null handle returns
 * FRE_AOT_REGEX_STATUS_INVALID_HANDLE. A null source or output, misaligned
 * output, unsupported signed pointer extent, mismatched output_count, or
 * non-exact haystack_len returns FRE_AOT_REGEX_STATUS_INVALID_ARGUMENT before
 * source/workspace mutation and leaves a live reusable handle unchanged.
 * Malformed internal state, resource/execution failure, or panic returns
 * FRE_AOT_REGEX_STATUS_RUNTIME_FAILURE, leaves output untouched, and makes the
 * handle terminal/destroy-only. A later call with otherwise valid geometry
 * rejects that terminal handle with RUNTIME_FAILURE before source access,
 * workspace mutation, or output. Success returns
 * FRE_AOT_REGEX_STATUS_SUCCESS (zero) and restores reusable state.
 */
uint32_t fre_aot_regex_runtime_execute_operation_set_exclusive_v2(
    FreAotRegexOperationSetExclusiveHandleV2 handle,
    const uint8_t *haystack_ptr,
    size_t haystack_len,
    FreAotRegexOperationSetOutputV2 *outputs,
    size_t output_count);

/*
 * Destroy one live exclusively owned V2 handle exactly once. Live ownership
 * is a caller safety precondition: a dangling, copied-concurrent, stale, or
 * previously destroyed nonnull handle is not recoverably validated. No
 * execute or destroy may overlap, and no handle copy may be used afterward. A
 * null handle returns FRE_AOT_REGEX_STATUS_INVALID_HANDLE; successful
 * destruction returns FRE_AOT_REGEX_STATUS_SUCCESS, and an unexpected panic
 * returns FRE_AOT_REGEX_STATUS_RUNTIME_FAILURE.
 */
uint32_t fre_aot_regex_runtime_destroy_operation_set_exclusive_v2(
    FreAotRegexOperationSetExclusiveHandleV2 handle);

#ifdef __cplusplus
}
#endif

#endif
