#ifndef FRE_AOT_REGEX_RUNTIME_PARTICIPATION_V1_H
#define FRE_AOT_REGEX_RUNTIME_PARTICIPATION_V1_H

#include "fre_aot_regex_runtime_v1.h"

#define FRE_AOT_REGEX_NATIVE_PARTICIPATION_ABI_VERSION 1u
#define FRE_AOT_REGEX_NATIVE_PARTICIPATION_SCRATCH_BYTES 16u
#define FRE_AOT_REGEX_STATUS_NATIVE_PARTICIPATION_UNAVAILABLE 10u

/*
 * Exact-span replay request for an identity-suffixed object-local entry.
 * `bundle` must name the paired bundle symbol in the same linked object.
 * `match_start..match_end` must be the MATCH returned by that object's
 * ordinary Span selector for the same haystack and complete 0..haystack_len
 * window. The haystack is bytes; invalid UTF-8 is ordinary input.
 *
 * A selected entry requires non-null, naturally aligned, nonwrapping request,
 * scratch, and count pointers. scratch_len must be exactly 16. The scratch is
 * caller-owned disposable working state; it may change after argument and
 * artifact authentication. MATCH alone publishes count_out. Every other
 * status leaves count_out untouched. A well-formed but nonmatching span is a
 * RUNTIME_FAILURE. A negative entry returns
 * FRE_AOT_REGEX_STATUS_NATIVE_PARTICIPATION_UNAVAILABLE without reading the
 * request.
 */
typedef struct FreAotRegexParticipationRequestV1 {
    const uint8_t *bundle;
    const uint8_t *haystack;
    size_t haystack_len;
    size_t match_start;
    size_t match_end;
    uint8_t *scratch;
    size_t scratch_len;
    size_t *count_out;
} FreAotRegexParticipationRequestV1;

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t (*FreAotRegexParticipationExactV1)(
    const FreAotRegexParticipationRequestV1 *request);

#ifdef __cplusplus
}
#endif

#endif
