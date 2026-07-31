#include <stddef.h>
#include <stdint.h>

struct adoption_output {
    const void *verified;
};

typedef uint64_t (*count_entry)(const uint8_t *, size_t, uint64_t *);

extern uint32_t fre_aot_count_glue_v2_54e0fe61df0a7a21135580e950940cf1bb9917f7f209ed74a12e6728cb4b36a9(struct adoption_output *);

uint32_t fre_aot_static_count_adopt_raw_v2(
    struct adoption_output *output,
    uint32_t selector,
    const uint8_t *expectation,
    const uint8_t *entry,
    const uint8_t *payload,
    const uint8_t *metadata
) {
    static const uint8_t haystack[] = "needle hay needle";
    uint64_t result = UINT64_MAX;
    if (output == NULL || selector != 11 || expectation == NULL ||
        entry == NULL || payload == NULL || metadata == NULL ||
        entry != payload) {
        return 91;
    }
    if (expectation[0] != 'F' || expectation[7] != 2) {
        return 92;
    }
    uint64_t status = ((count_entry)entry)(
        haystack,
        sizeof(haystack) - 1,
        &result
    );
    if (status != 0 || result != 2) {
        return 93;
    }
    return 77;
}

int main(void) {
    struct adoption_output output = {0};
    return fre_aot_count_glue_v2_54e0fe61df0a7a21135580e950940cf1bb9917f7f209ed74a12e6728cb4b36a9(&output) == 77 ? 0 : 1;
}
