#include "fre_search_v8_span.h"

int main(void) {
    static const uint8_t haystack[] = "xx0123456789abcdefyy";
    struct fre_aot_search_result_v1 result = {
        (size_t)UINT64_C(0xa5a5a5a5a5a5a5a5),
        (size_t)UINT64_C(0x5a5a5a5a5a5a5a5a)
    };
    uint64_t status = FRE_SEARCH_V8_SPAN_ENTRY(
        haystack,
        sizeof(haystack) - 1u,
        0u,
        sizeof(haystack) - 1u,
        &result
    );
    if (status != UINT64_C(1) || result.start != 2u || result.end != 18u) {
        return 10;
    }
    return 0;
}
