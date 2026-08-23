#ifndef FRE_AOT_REGEX_RUNTIME_CAPTURES_V1_H
#define FRE_AOT_REGEX_RUNTIME_CAPTURES_V1_H

#include "fre_aot_regex_runtime_v1.h"

#define FRE_AOT_REGEX_NATIVE_CAPTURE_ABI_VERSION 1u
#define FRE_AOT_REGEX_STATUS_NATIVE_CAPTURE_UNAVAILABLE 10u
#define FRE_AOT_REGEX_CAPTURE_UNSET SIZE_MAX

/*
 * One group result, including group zero. An unmatched group is exactly
 * {SIZE_MAX, SIZE_MAX}; an empty participating group has equal in-range
 * offsets and is therefore distinct from unmatched.
 */
typedef struct FreAotRegexCaptureSlotV1 {
    size_t start;
    size_t end;
} FreAotRegexCaptureSlotV1;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Identity-suffixed, object-local exact-span materializer. match_start and
 * match_end must be a MATCH returned by this object's paired selector for the
 * same haystack and complete 0..haystack_len window. A well-formed but
 * uncertified/nonmatching span is outside this entry's contract; detection is
 * reported as RUNTIME_FAILURE without changing slots.
 *
 * MATCH initializes exactly slot_count records. INVALID_ARGUMENT,
 * RUNTIME_FAILURE, and NATIVE_CAPTURE_UNAVAILABLE leave every record
 * unchanged. Group zero must equal [match_start, match_end); every other pair
 * is either both UNSET or a contained, ordered half-open range. slot_count is
 * the exact bundle-advertised count, not a capacity. The haystack is bytes;
 * invalid UTF-8 is ordinary input.
 */
typedef uint32_t (*FreAotRegexCaptureMaterializeV1)(
    const uint8_t *haystack_ptr,
    size_t haystack_len,
    size_t match_start,
    size_t match_end,
    FreAotRegexCaptureSlotV1 *slots,
    size_t slot_count);

/*
 * Identity-suffixed, object-local non-overlapping capture iterator.
 *
 * An all-zero state begins at byte zero. MATCH publishes one complete capture
 * row and the corresponding next state. NO_MATCH publishes all-UNSET slots
 * and a fused FINISHED state. Every other status changes neither state nor
 * slots. Empty matches make one-byte progress before the next search (or fuse
 * at end of input), so progress is defined for arbitrary bytes rather than
 * UTF-8 code points. State and slots must be naturally aligned, nonwrapping,
 * and disjoint; slot_count must exactly equal the bundle schema.
 *
 * A negative entry returns NATIVE_CAPTURE_UNAVAILABLE without reading the
 * haystack or changing either output. Selected V1 entries make no semantic
 * fre_aot_regex_runtime_* call; prepare/authentication may occur before the
 * measured operation but cannot replace either entry with replay.
 */
typedef uint32_t (*FreAotRegexCaptureNextV1)(
    const uint8_t *haystack_ptr,
    size_t haystack_len,
    FreAotRegexIterStateV1 *state,
    FreAotRegexCaptureSlotV1 *slots,
    size_t slot_count);

/*
 * Identity-suffixed whole-operation capture reducer. CountCaptures owns the
 * complete haystack domain. GrepCaptures owns Rust bstr ByteSlice::lines:
 * LF-delimited, one CR immediately before LF stripped, no line for empty
 * input, and no synthetic line after final LF.
 *
 * SUCCESS publishes exactly one capture-participation total. Every other
 * status leaves value_out unchanged. Selected entries call only their paired
 * object-local ordinary Span selector plus exact-span participation closure,
 * or their paired capture_next closure. They make no semantic
 * fre_aot_regex_runtime_* call.
 */
typedef uint32_t (*FreAotRegexCaptureReducerV1)(
    const uint8_t *haystack_ptr,
    size_t haystack_len,
    uint64_t *value_out);

/*
 * Additive caller-scratch reducer ABI used only by identity-suffixed entries
 * whose receipt advertises a nonzero exact scratch extent. Scratch and output
 * must be writable, naturally aligned, nonoverlapping, and disjoint from a
 * nonempty haystack. The entry may overwrite scratch during the call but does
 * not retain it. SUCCESS alone publishes value_out.
 */
typedef uint32_t (*FreAotRegexCaptureReducerScratchV1)(
    const uint8_t *haystack_ptr,
    size_t haystack_len,
    uint8_t *scratch,
    size_t scratch_len,
    uint64_t *value_out);

#ifdef __cplusplus
}
#endif

#endif
