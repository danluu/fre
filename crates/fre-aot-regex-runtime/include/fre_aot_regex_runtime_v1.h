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
#define FRE_AOT_REGEX_STATUS_SUCCESS 0u

typedef uint64_t FreAotRegexPreparedHandleV1;

typedef struct FreAotRegexResultV1 {
    size_t start;
    size_t end;
} FreAotRegexResultV1;

/* Every identity-suffixed direct or runtime-backed object entry has this ABI. */
typedef uint32_t (*FreAotRegexEntryV1)(
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

#ifdef __cplusplus
}
#endif

#endif
