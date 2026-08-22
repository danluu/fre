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

#ifdef __cplusplus
}
#endif

#endif
