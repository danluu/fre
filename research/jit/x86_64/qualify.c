/*
 * External execution qualification only. This is intentionally not linked
 * into the Rust crate or a production publisher. It performs an RW -> RX
 * transition, never RWX, then calls authenticated bundle images in an x86-64
 * process (native or Rosetta) and compares them with an independent C model.
 */
#include <errno.h>
#include <inttypes.h>
#include <libkern/OSCacheControl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <unistd.h>

struct native_match {
    size_t start;
    size_t end;
};

typedef uint32_t (*entry_fn)(const uint8_t *, size_t, size_t, size_t,
                             struct native_match *);

#if defined(FRE_AOT_QUALIFICATION)
extern entry_fn fre_qualified_entries[];
extern size_t fre_qualified_entry_count;
#endif

struct record {
    uint8_t kind;
    uint8_t tier;
    uint8_t anchors;
    uint32_t pattern_len;
    uint32_t image_len;
    const uint8_t *class_bits;
    const uint8_t *pattern;
    const uint8_t *image;
};

struct expected {
    uint32_t status;
    size_t start;
    size_t end;
};

static uint64_t comparisons;

#if !defined(FRE_AOT_QUALIFICATION)
static int process_is_translated(void) {
    int translated = 0;
    size_t size = sizeof(translated);
    if (sysctlbyname("sysctl.proc_translated", &translated, &size, NULL, 0) ==
        0) {
        return translated;
    }
    return errno == ENOENT ? 0 : -1;
}
#endif

static bool checked_add_size(size_t a, size_t b, size_t *out) {
    if (a > SIZE_MAX - b) {
        return false;
    }
    *out = a + b;
    return true;
}

static bool take(const uint8_t **cursor, const uint8_t *end, size_t length,
                 const uint8_t **value) {
    size_t available = (size_t)(end - *cursor);
    if (length > available) {
        return false;
    }
    *value = *cursor;
    *cursor += length;
    return true;
}

static uint32_t little_u32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static bool class_contains(const struct record *record, uint8_t byte) {
    return (record->class_bits[byte >> 3] & (uint8_t)(1U << (byte & 7))) != 0;
}

static bool matches_at(const uint8_t *haystack, size_t window_end, size_t at,
                       const uint8_t *pattern, size_t pattern_len) {
    if (at > window_end || pattern_len > window_end - at) {
        return false;
    }
    return memcmp(haystack + at, pattern, pattern_len) == 0;
}

static struct expected reference_exact(const struct record *record,
                                       const uint8_t *haystack, size_t length,
                                       size_t start, size_t end) {
    struct expected none = {0, 0, 0};
    if (start > end || end > length) {
        none.status = 2;
        return none;
    }
    bool anchored_start = (record->anchors & 1) != 0;
    bool anchored_end = (record->anchors & 2) != 0;
    size_t n = record->pattern_len;
    if (anchored_start) {
        if (start == 0 && matches_at(haystack, end, 0, record->pattern, n) &&
            (!anchored_end || n == length)) {
            struct expected found = {1, 0, n};
            return found;
        }
        return none;
    }
    if (anchored_end) {
        if (n <= length) {
            size_t candidate = length - n;
            if (candidate >= start && matches_at(haystack, end, candidate,
                                                  record->pattern, n)) {
                struct expected found = {1, candidate, length};
                return found;
            }
        }
        return none;
    }
    for (size_t at = start; at <= end; ++at) {
        if (matches_at(haystack, end, at, record->pattern, n)) {
            struct expected found = {1, at, at + n};
            return found;
        }
    }
    return none;
}

static struct expected reference_class(const struct record *record,
                                       const uint8_t *haystack, size_t length,
                                       size_t start, size_t end) {
    struct expected none = {0, 0, 0};
    if (start > end || end > length) {
        none.status = 2;
        return none;
    }
    bool anchored_start = (record->anchors & 1) != 0;
    bool anchored_end = (record->anchors & 2) != 0;
    size_t cursor = start;
    for (;;) {
        size_t run_start = cursor;
        if (anchored_start) {
            if (cursor != 0 || cursor == end ||
                !class_contains(record, haystack[cursor])) {
                return none;
            }
        } else {
            while (run_start < end &&
                   !class_contains(record, haystack[run_start])) {
                ++run_start;
            }
            if (run_start == end) {
                return none;
            }
        }
        size_t run_end = run_start + 1;
        while (run_end < end && class_contains(record, haystack[run_end])) {
            ++run_end;
        }
        if (matches_at(haystack, end, run_end, record->pattern,
                       record->pattern_len)) {
            size_t match_end = run_end + record->pattern_len;
            if (!anchored_end || match_end == length) {
                struct expected found = {1, run_start, match_end};
                return found;
            }
        }
        cursor = run_end;
    }
}

static struct expected reference(const struct record *record,
                                 const uint8_t *haystack, size_t length,
                                 size_t start, size_t end) {
    if (record->kind == 0) {
        return reference_exact(record, haystack, length, start, end);
    }
    return reference_class(record, haystack, length, start, end);
}

static void print_hex(const uint8_t *bytes, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        fprintf(stderr, "%02x", bytes[i]);
    }
}

static bool compare_one(size_t record_index, const struct record *record,
                        entry_fn entry, const uint8_t *haystack, size_t length,
                        size_t start, size_t end) {
    struct expected expected = reference(record, haystack, length, start, end);
    struct native_match actual = {SIZE_MAX, SIZE_MAX};
    uint32_t status = entry(haystack, length, start, end, &actual);
    ++comparisons;
    if (status == expected.status && actual.start == expected.start &&
        actual.end == expected.end) {
        return true;
    }
    fprintf(stderr,
            "mismatch record=%zu kind=%u tier=%u anchors=%u window=%zu..%zu "
            "expected=%u/%zu..%zu actual=%u/%zu..%zu haystack=",
            record_index, record->kind, record->tier, record->anchors, start,
            end, expected.status, expected.start, expected.end, status,
            actual.start, actual.end);
    print_hex(haystack, length);
    fputc('\n', stderr);
    return false;
}

static bool exhaustive(size_t record_index, const struct record *record,
                       entry_fn entry) {
    static const uint8_t alphabet[] = {'a', 'b', 'X', 'Y'};
    uint8_t haystack[6];
    for (size_t length = 0; length <= 5; ++length) {
        size_t words = 1;
        for (size_t i = 0; i < length; ++i) {
            words *= sizeof(alphabet);
        }
        for (size_t word = 0; word < words; ++word) {
            size_t value = word;
            for (size_t i = 0; i < length; ++i) {
                haystack[i] = alphabet[value % sizeof(alphabet)];
                value /= sizeof(alphabet);
            }
            for (size_t start = 0; start <= length; ++start) {
                for (size_t end = start; end <= length; ++end) {
                    if (!compare_one(record_index, record, entry, haystack,
                                     length, start, end)) {
                        return false;
                    }
                }
            }
            if (!compare_one(record_index, record, entry, haystack, length,
                             length + 1, length) ||
                !compare_one(record_index, record, entry, haystack, length, 0,
                             length + 1)) {
                return false;
            }
        }
    }
    return true;
}

static uint8_t first_class_byte(const struct record *record) {
    for (unsigned value = 0; value <= UINT8_MAX; ++value) {
        if (class_contains(record, (uint8_t)value)) {
            return (uint8_t)value;
        }
    }
    return 0;
}

static bool targeted(size_t record_index, const struct record *record,
                     entry_fn entry) {
    size_t core_len = record->pattern_len;
    if (record->kind == 1 && !checked_add_size(core_len, 3, &core_len)) {
        return false;
    }
    size_t extra_start = (record->anchors & 1) == 0 ? 1 : 0;
    size_t extra_end = (record->anchors & 2) == 0 ? 1 : 0;
    size_t length;
    if (!checked_add_size(core_len, extra_start, &length) ||
        !checked_add_size(length, extra_end, &length)) {
        return false;
    }
    uint8_t *haystack = calloc(length == 0 ? 1 : length, 1);
    if (haystack == NULL) {
        return false;
    }
    memset(haystack, 0xEE, length);
    size_t at = extra_start;
    if (record->kind == 1) {
        memset(haystack + at, first_class_byte(record), 3);
        at += 3;
    }
    memcpy(haystack + at, record->pattern, record->pattern_len);
    bool ok = compare_one(record_index, record, entry, haystack, length, 0,
                          length);
    if (record->pattern_len != 0) {
        haystack[at + record->pattern_len - 1] ^= 0x5A;
        ok = ok && compare_one(record_index, record, entry, haystack, length, 0,
                               length);
    }
    free(haystack);
    return ok;
}

static bool long_scan(size_t record_index, const struct record *record,
                      entry_fn entry) {
    if (record->anchors != 0) {
        return true;
    }
    const size_t length = 4096;
    uint8_t *haystack = malloc(length);
    if (haystack == NULL) {
        return false;
    }
    memset(haystack, 0xEE, length);
    size_t at = 2000;
    if (record->kind == 1) {
        memset(haystack + at, first_class_byte(record), 7);
        at += 7;
    }
    if (record->pattern_len <= length - at) {
        memcpy(haystack + at, record->pattern, record->pattern_len);
    }
    bool ok = compare_one(record_index, record, entry, haystack, length, 0,
                          length);
    free(haystack);
    return ok;
}

static bool avx2_available(void) {
#if defined(__x86_64__)
    return __builtin_cpu_supports("avx2");
#else
    return false;
#endif
}

static bool qualify_record(size_t index, const struct record *record,
                           bool *skipped) {
    if (record->tier == 2 && !avx2_available()) {
        *skipped = true;
        return true;
    }
#if defined(FRE_AOT_QUALIFICATION)
    if (index >= fre_qualified_entry_count) {
        fprintf(stderr, "missing AOT entry=%zu\n", index);
        return false;
    }
    entry_fn entry = fre_qualified_entries[index];
    return exhaustive(index, record, entry) &&
           targeted(index, record, entry) && long_scan(index, record, entry);
#else
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        perror("sysconf");
        return false;
    }
    size_t page = (size_t)page_size;
    size_t map_len;
    if (!checked_add_size(record->image_len, page - 1, &map_len)) {
        return false;
    }
    map_len &= ~(page - 1);
    void *memory = mmap(NULL, map_len, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANON, -1, 0);
    if (memory == MAP_FAILED) {
        perror("mmap");
        return false;
    }
    memcpy(memory, record->image, record->image_len);
    if (mprotect(memory, map_len, PROT_READ | PROT_EXEC) != 0) {
        perror("mprotect");
        munmap(memory, map_len);
        return false;
    }
    sys_icache_invalidate(memory, record->image_len);
    entry_fn entry = (entry_fn)memory;
    bool ok = exhaustive(index, record, entry) &&
              targeted(index, record, entry) &&
              long_scan(index, record, entry);
    if (munmap(memory, map_len) != 0) {
        perror("munmap");
        return false;
    }
    return ok;
#endif
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s BUNDLE\n", argv[0]);
        return 2;
    }
#if !defined(FRE_AOT_QUALIFICATION)
    int translated = process_is_translated();
    if (translated != 0) {
        fprintf(stderr,
                translated < 0
                    ? "unable to determine translated-process status\n"
                    : "refusing raw mprotect JIT qualification under Rosetta; "
                      "use a qualified MAP_JIT publisher or AOT mode\n");
        return 2;
    }
#endif
    FILE *file = fopen(argv[1], "rb");
    if (file == NULL) {
        perror("fopen");
        return 2;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        perror("fseek");
        fclose(file);
        return 2;
    }
    long signed_length = ftell(file);
    if (signed_length < 0 || fseek(file, 0, SEEK_SET) != 0) {
        perror("ftell/fseek");
        fclose(file);
        return 2;
    }
    size_t length = (size_t)signed_length;
    uint8_t *bytes = malloc(length == 0 ? 1 : length);
    if (bytes == NULL || fread(bytes, 1, length, file) != length) {
        perror("read");
        free(bytes);
        fclose(file);
        return 2;
    }
    fclose(file);
    const uint8_t *cursor = bytes;
    const uint8_t *end = bytes + length;
    const uint8_t *field;
    static const uint8_t magic[8] = {'F', 'R', 'E', 'Q', 'X', '6', '4', 1};
    if (!take(&cursor, end, 8, &field) || memcmp(field, magic, 8) != 0 ||
        !take(&cursor, end, 4, &field)) {
        fprintf(stderr, "invalid bundle header\n");
        free(bytes);
        return 2;
    }
    uint32_t count = little_u32(field);
    size_t executed = 0;
    size_t skipped = 0;
    for (uint32_t index = 0; index < count; ++index) {
        const uint8_t *fixed;
        if (!take(&cursor, end, 12, &fixed)) {
            fprintf(stderr, "truncated record header\n");
            free(bytes);
            return 2;
        }
        struct record record = {0};
        record.kind = fixed[0];
        record.tier = fixed[1];
        record.anchors = fixed[2];
        record.pattern_len = little_u32(fixed + 4);
        record.image_len = little_u32(fixed + 8);
        if (fixed[3] != 0 || record.kind > 1 || record.tier > 2 ||
            (record.anchors & ~3U) != 0 ||
            !take(&cursor, end, 32, &record.class_bits) ||
            !take(&cursor, end, record.pattern_len, &record.pattern) ||
            !take(&cursor, end, record.image_len, &record.image)) {
            fprintf(stderr, "invalid record=%" PRIu32 "\n", index);
            free(bytes);
            return 2;
        }
        bool was_skipped = false;
        if (!qualify_record(index, &record, &was_skipped)) {
            free(bytes);
            return 1;
        }
        if (was_skipped) {
            ++skipped;
        } else {
            ++executed;
        }
    }
    if (cursor != end) {
        fprintf(stderr, "trailing bundle bytes\n");
        free(bytes);
        return 2;
    }
    printf("records=%" PRIu32 " executed=%zu skipped=%zu comparisons=%" PRIu64
           " avx2=%u\n",
           count, executed, skipped, comparisons, avx2_available() ? 1U : 0U);
    free(bytes);
    return 0;
}
