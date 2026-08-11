#ifndef FRE_AOT_REGEX_RUNTIME_V1_H
#define FRE_AOT_REGEX_RUNTIME_V1_H

#include <stddef.h>
#include <stdint.h>

#define FRE_AOT_REGEX_STATUS_NO_MATCH 0u
#define FRE_AOT_REGEX_STATUS_MATCH 1u
#define FRE_AOT_REGEX_STATUS_INVALID_ARGUMENT 2u
#define FRE_AOT_REGEX_STATUS_RUNTIME_FAILURE 3u
#define FRE_AOT_REGEX_STATUS_HANDLE_BUSY 4u
#define FRE_AOT_REGEX_STATUS_INVALID_HANDLE 5u
#define FRE_AOT_REGEX_STATUS_PARTIAL_PREFLIGHT_ENTER 6u
#define FRE_AOT_REGEX_STATUS_SUCCESS 0u
#define FRE_AOT_REGEX_ARTIFACT_IDENTITY_BYTES 32u
#define FRE_AOT_REGEX_PARTIAL_ENTRY_BYPASS 0u
#define FRE_AOT_REGEX_PARTIAL_ENTRY_ENTER 1u

typedef uint64_t FreAotRegexPreparedHandleV1;
typedef void *FreAotRegexExclusiveHandleV1;

typedef struct FreAotRegexResultV1 {
    size_t start;
    size_t end;
} FreAotRegexResultV1;

typedef struct FreAotRegexSearchWindowV1 {
    size_t start;
    size_t end;
} FreAotRegexSearchWindowV1;

/* Every identity-suffixed direct or runtime-backed object entry has this ABI. */
typedef uint32_t (*FreAotRegexEntryV1)(
    const uint8_t *haystack_ptr,
    size_t haystack_len,
    size_t window_start,
    size_t window_end,
    FreAotRegexResultV1 *result_ptr);

/* Additive native retained-row entry for an exclusively prepared program. */
typedef uint32_t (*FreAotRegexExclusiveEntryV1)(
    FreAotRegexExclusiveHandleV1 handle,
    const uint8_t *haystack_ptr,
    size_t haystack_len,
    size_t window_start,
    size_t window_end,
    FreAotRegexResultV1 *result_ptr);

#ifdef __cplusplus
extern "C" {
#endif

uint32_t fre_aot_regex_runtime_search_v1(
    const uint8_t *program_ptr,
    const uint8_t *haystack_ptr,
    size_t haystack_len,
    size_t window_start,
    size_t window_end,
    FreAotRegexResultV1 *result_ptr);

/* Semantic fallback used after or instead of a generated endpoint oracle. */
uint32_t fre_aot_regex_runtime_search_without_endpoint_oracle_v1(
    const uint8_t *program_ptr,
    const uint8_t *haystack_ptr,
    size_t haystack_len,
    size_t window_start,
    size_t window_end,
    FreAotRegexResultV1 *result_ptr);

uint32_t fre_aot_regex_runtime_prepare_v1(
    const uint8_t *program_ptr,
    size_t program_len,
    FreAotRegexPreparedHandleV1 *handle_out);

uint32_t fre_aot_regex_runtime_search_prepared_v1(
    FreAotRegexPreparedHandleV1 handle,
    const uint8_t *haystack_ptr,
    size_t haystack_len,
    size_t window_start,
    size_t window_end,
    FreAotRegexResultV1 *result_ptr);

uint32_t fre_aot_regex_runtime_destroy_prepared_v1(
    FreAotRegexPreparedHandleV1 handle);

/*
 * The exclusive lifecycle avoids all per-search synchronization. Its handle
 * must remain exclusively owned, must be destroyed exactly once, and must
 * never be searched after destruction.
 */
uint32_t fre_aot_regex_runtime_prepare_exclusive_v1(
    const uint8_t *program_ptr,
    size_t program_len,
    FreAotRegexExclusiveHandleV1 *handle_out);

uint32_t fre_aot_regex_runtime_search_exclusive_v1(
    FreAotRegexExclusiveHandleV1 handle,
    const uint8_t *haystack_ptr,
    size_t haystack_len,
    size_t window_start,
    size_t window_end,
    FreAotRegexResultV1 *result_ptr);

/*
 * Legacy compiler-emitted adaptive admission, retained for old-object
 * compatibility. A bypass must be followed immediately by
 * fre_aot_regex_runtime_search_exclusive_v1 for the same search. An entry
 * decision must be followed by either a local native result or the partial
 * continuation call below. New objects use the combined preflight below.
 */
uint32_t fre_aot_regex_runtime_prepared_partial_should_enter_v1(
    FreAotRegexExclusiveHandleV1 handle,
    size_t input_bytes);

/*
 * Continue a retained partial-DFA hole without replay. The identity points to
 * exactly FRE_AOT_REGEX_ARTIFACT_IDENTITY_BYTES bytes. resume_state is a
 * compact index into that exact artifact's canonical retained frontier table;
 * no caller-provided frontier contents are accepted. pending_end_present must
 * be zero or one.
 */
uint32_t fre_aot_regex_runtime_search_exclusive_from_partial_v1(
    FreAotRegexExclusiveHandleV1 handle,
    const uint8_t *haystack_ptr,
    size_t haystack_len,
    size_t window_start,
    size_t window_end,
    FreAotRegexResultV1 *result_ptr,
    const uint8_t expected_artifact_identity[FRE_AOT_REGEX_ARTIFACT_IDENTITY_BYTES],
    size_t resume_state,
    size_t resume_position,
    uint32_t pending_end_present,
    size_t pending_end);

/*
 * Recover the selected start after a variable-width, non-nullable Span table
 * completes locally with only its endpoint. The identity and exact window
 * must match the immediately preceding successful partial preflight on this
 * exclusive session. selected_end must lie strictly inside that transaction
 * after window_start and at or before window_end. Success is always status 1
 * and initializes result_out with the exact Span; every rejection leaves it
 * untouched. Other output contracts and retained-table shapes are rejected.
 */
uint32_t fre_aot_regex_runtime_search_exclusive_recover_partial_span_v1(
    FreAotRegexExclusiveHandleV1 handle,
    const uint8_t *haystack_ptr,
    size_t haystack_len,
    size_t window_start,
    size_t window_end,
    FreAotRegexResultV1 *result_ptr,
    const uint8_t expected_artifact_identity[FRE_AOT_REGEX_ARTIFACT_IDENTITY_BYTES],
    size_t selected_end);

/*
 * Recover the selected start after a variable-width, non-nullable dynamic-row
 * scan completes locally with only its endpoint. For mutable rows and legacy
 * V1/V2 headers, the identity and exact window must match the immediately
 * preceding successful dynamic-row preflight on this exclusive session. An
 * active immutable V3--V14 owner may instead authenticate the synchronous
 * endpoint directly without a preflight ticket. selected_end must lie
 * strictly after window_start and at or before window_end. Successful
 * immutable recovery retains that owner; every rejection revokes it and
 * leaves result_out untouched.
 *
 * This is a compiler-private object-linking ABI. It is declared here so
 * embedders that resolve generated-object dependencies can provide the exact
 * versioned runtime export without duplicating its signature.
 */
uint32_t fre_aot_regex_runtime_search_exclusive_dynamic_rows_recover_span_v1(
    FreAotRegexExclusiveHandleV1 handle,
    const uint8_t *haystack_ptr,
    size_t haystack_len,
    size_t window_start,
    size_t window_end,
    FreAotRegexResultV1 *result_ptr,
    const uint8_t expected_artifact_identity[FRE_AOT_REGEX_ARTIFACT_IDENTITY_BYTES],
    size_t selected_end);

/*
 * Authenticate one native incomplete-retained search. The helper settles the
 * prior local native completion, runs suffix then cut, and consults adaptive
 * admission. Status 0 or 1 initializes result_out and completes the search.
 * FRE_AOT_REGEX_STATUS_PARTIAL_PREFLIGHT_ENTER initializes window_out with
 * the exact non-empty window on which the native table must enter. Other
 * statuses are errors and initialize neither output.
 */
uint32_t fre_aot_regex_runtime_search_exclusive_partial_preflight_v1(
    FreAotRegexExclusiveHandleV1 handle,
    const uint8_t *haystack_ptr,
    size_t haystack_len,
    size_t window_start,
    size_t window_end,
    FreAotRegexResultV1 *result_ptr,
    const uint8_t expected_artifact_identity[FRE_AOT_REGEX_ARTIFACT_IDENTITY_BYTES],
    FreAotRegexSearchWindowV1 *window_out);

/*
 * Authenticate a native-root-owned incomplete-retained search. Admission is
 * decided before the portable suffix/cut proofs. An admitted search returns
 * the unchanged semantic window, which the native table must execute exactly
 * once; a declined search runs the ordinary suffix-then-cut order and K0 to
 * completion inside this call. Status and output transactions are otherwise
 * identical to the preflight above.
 */
uint32_t fre_aot_regex_runtime_search_exclusive_partial_native_root_preflight_v1(
    FreAotRegexExclusiveHandleV1 handle,
    const uint8_t *haystack_ptr,
    size_t haystack_len,
    size_t window_start,
    size_t window_end,
    FreAotRegexResultV1 *result_ptr,
    const uint8_t expected_artifact_identity[FRE_AOT_REGEX_ARTIFACT_IDENTITY_BYTES],
    FreAotRegexSearchWindowV1 *window_out);

uint32_t fre_aot_regex_runtime_destroy_exclusive_v1(
    FreAotRegexExclusiveHandleV1 handle);

#ifdef __cplusplus
}
#endif

#endif
