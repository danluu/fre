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
#define FRE_AOT_REGEX_ITER_HAS_LAST 1u
#define FRE_AOT_REGEX_ITER_PENDING_EMPTY 2u
#define FRE_AOT_REGEX_ITER_FINISHED 4u

typedef uint64_t FreAotRegexPreparedHandleV1;
typedef void *FreAotRegexExclusiveHandleV1;

typedef struct FreAotRegexResultV1 {
    size_t start;
    size_t end;
} FreAotRegexResultV1;

/*
 * Caller-owned non-overlapping-match continuation. The all-zero value begins
 * at byte zero. Callers must preserve this exact value between refills.
 * reserved must remain zero and flags may contain only the three ITER bits.
 * next_start and an active last_match_end must be in bounds. PENDING_EMPTY
 * requires HAS_LAST and equal next/last offsets; FINISHED excludes PENDING.
 */
typedef struct FreAotRegexIterStateV1 {
    size_t next_start;
    size_t last_match_end;
    uint32_t flags;
    uint32_t reserved;
} FreAotRegexIterStateV1;

/* One independent byte haystack in a prepared Exists batch. */
typedef struct FreAotRegexHaystackV1 {
    const uint8_t *ptr;
    size_t len;
} FreAotRegexHaystackV1;

typedef struct FreAotRegexSearchWindowV1 {
    size_t start;
    size_t end;
} FreAotRegexSearchWindowV1;

#ifdef __cplusplus
extern "C" {
#endif

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

/*
 * Additive compiler-produced Span iterator for an exclusively prepared
 * program. Status 1 means the result capacity filled and another refill may
 * be needed; status 0 means the iterator is finished. written_out is required
 * and counts initialized result records. Capacity zero is a valid probe:
 * results may then be null and status is 0 only if state is already FINISHED.
 * On a later search error, written_out still publishes the completely
 * initialized prefix, state becomes FINISHED, and PENDING_EMPTY is cleared.
 *
 * Empty matches use byte-oriented Rust-regex progress. An accepted empty match
 * sets PENDING_EMPTY. The next search clears it and either advances one byte
 * or finishes at EOF. An empty match at the previous match end is suppressed
 * by the same byte advance before retrying.
 *
 * handle, haystack_ptr, state, and written_out are always nonnull; results is
 * nonnull when capacity is nonzero. State, results, and written_out have their
 * natural alignments. Read and write extents must not overlap. A null/invalid
 * handle returns INVALID_HANDLE; other raw top-level validation failures
 * return INVALID_ARGUMENT without changing any output.
 */
typedef uint32_t (*FreAotRegexExclusiveSpanFillV1)(
    FreAotRegexExclusiveHandleV1 handle,
    const uint8_t *haystack_ptr,
    size_t haystack_len,
    FreAotRegexIterStateV1 *state,
    FreAotRegexResultV1 *results,
    size_t capacity,
    size_t *written_out);

/*
 * Additive compiler-produced Exists batch for independent haystacks. Status
 * 0 means every input was processed. processed_out is required and counts
 * initialized output bytes; each initialized byte is exactly 0 or 1. A zero
 * count is valid and permits null haystacks and matched_out pointers. For a
 * nonzero count, both arrays are nonnull, the descriptor array is naturally
 * aligned, and every descriptor has a nonnull ptr even when len is zero. Read
 * and write extents must not overlap. A null/invalid handle returns
 * INVALID_HANDLE; other raw top-level validation failures change no output. A
 * later descriptor or search error preserves processed_out and the completely
 * initialized matched_out prefix.
 */
typedef uint32_t (*FreAotRegexExclusiveExistsBatchV1)(
    FreAotRegexExclusiveHandleV1 handle,
    const FreAotRegexHaystackV1 *haystacks,
    size_t count,
    uint8_t *matched_out,
    size_t *processed_out);

/*
 * Full-haystack scalar reducers for an exclusively prepared Span program.
 * Status 0 means the complete operation succeeded, including a zero result,
 * and initializes value_out. Every nonzero status leaves value_out untouched.
 * Count publishes the number of selected non-overlapping matches; SpanSum
 * publishes the sum of their byte widths. Both use the Span iterator's exact
 * byte-empty progress and repeated-empty suppression rules.
 *
 * handle must be one live exclusively owned prepared Span handle.
 * haystack_ptr is nonnull even when haystack_len is zero and remains readable
 * for haystack_len bytes. value_out is nonnull, naturally aligned, writable
 * for one uint64_t, and disjoint from the haystack. Both extents remain live
 * for the complete call.
 */
typedef uint32_t (*FreAotRegexExclusiveCountV1)(
    FreAotRegexExclusiveHandleV1 handle,
    const uint8_t *haystack_ptr,
    size_t haystack_len,
    uint64_t *value_out);

typedef uint32_t (*FreAotRegexExclusiveSpanSumV1)(
    FreAotRegexExclusiveHandleV1 handle,
    const uint8_t *haystack_ptr,
    size_t haystack_len,
    uint64_t *value_out);

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

/* Target-neutral bulk fallback used by compiler-produced RuntimeAdapters. */
uint32_t fre_aot_regex_runtime_fill_spans_exclusive_v1(
    FreAotRegexExclusiveHandleV1 handle,
    const uint8_t *haystack_ptr,
    size_t haystack_len,
    FreAotRegexIterStateV1 *state,
    FreAotRegexResultV1 *results,
    size_t capacity,
    size_t *written_out);

/* Target-neutral batch fallback used by compiler-produced RuntimeAdapters. */
uint32_t fre_aot_regex_runtime_is_match_batch_exclusive_v1(
    FreAotRegexExclusiveHandleV1 handle,
    const FreAotRegexHaystackV1 *haystacks,
    size_t count,
    uint8_t *matched_out,
    size_t *processed_out);

/* Target-neutral reducer entry points for callers owning prepared handles. */
uint32_t fre_aot_regex_runtime_count_exclusive_v1(
    FreAotRegexExclusiveHandleV1 handle,
    const uint8_t *haystack_ptr,
    size_t haystack_len,
    uint64_t *value_out);

uint32_t fre_aot_regex_runtime_span_sum_exclusive_v1(
    FreAotRegexExclusiveHandleV1 handle,
    const uint8_t *haystack_ptr,
    size_t haystack_len,
    uint64_t *value_out);

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
