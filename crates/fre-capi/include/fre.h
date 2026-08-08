#ifndef FRE_V1_H_INCLUDED
#define FRE_V1_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && defined(FRE_V1_SHARED)
#  if defined(FRE_V1_BUILDING)
#    define FRE_V1_API __declspec(dllexport)
#  else
#    define FRE_V1_API __declspec(dllimport)
#  endif
#elif defined(__GNUC__) || defined(__clang__)
#  define FRE_V1_API __attribute__((visibility("default")))
#else
#  define FRE_V1_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Stable uint32_t status tags. */
typedef uint32_t fre_v1_status;
#define FRE_V1_STATUS_OK UINT32_C(0)
#define FRE_V1_STATUS_INVALID_ARGUMENT UINT32_C(1)
#define FRE_V1_STATUS_ABI_MISMATCH UINT32_C(2)
#define FRE_V1_STATUS_STRUCT_TOO_SMALL UINT32_C(3)
#define FRE_V1_STATUS_INVALID_PATTERN_ENCODING UINT32_C(4)
#define FRE_V1_STATUS_UNSUPPORTED_PROFILE UINT32_C(5)
#define FRE_V1_STATUS_UNSUPPORTED_CONFIG UINT32_C(6)
#define FRE_V1_STATUS_COMPILE_ERROR UINT32_C(7)
#define FRE_V1_STATUS_SEARCH_ERROR UINT32_C(8)
#define FRE_V1_STATUS_PANIC UINT32_C(9)
#define FRE_V1_STATUS_NULL_WITH_NONZERO_LENGTH UINT32_C(10)
#define FRE_V1_STATUS_LENGTH_OVERFLOW UINT32_C(11)

#define FRE_V1_ABI_VERSION UINT32_C(1)

/* This is the complete implemented profile/policy set, not a future promise. */
#define FRE_V1_PROFILE_RUST_BYTES UINT32_C(1)
#define FRE_V1_JIT_DENY UINT32_C(1)

#define FRE_V1_ENDIAN_LITTLE UINT32_C(1)
#define FRE_V1_ENDIAN_BIG UINT32_C(2)

#define FRE_V1_FEATURE_RUST_BYTES (UINT64_C(1) << 0)
#define FRE_V1_FEATURE_EXISTS (UINT64_C(1) << 1)
#define FRE_V1_FEATURE_SELECTED_END (UINT64_C(1) << 2)
#define FRE_V1_FEATURE_SPAN (UINT64_C(1) << 3)
#define FRE_V1_FEATURE_PLAN_INFO (UINT64_C(1) << 4)
#define FRE_V1_FEATURE_THREAD_SAFE_REGEX (UINT64_C(1) << 5)
/*
 * THREAD_SAFE_REGEX means immutable searches may run concurrently while every
 * caller owns a live reference. It does not make a race with the final release
 * valid, and retain itself requires an already-live reference.
 */

#define FRE_V1_DIAGNOSTIC_NONE UINT32_C(0)
#define FRE_V1_DIAGNOSTIC_ARGUMENT UINT32_C(1)
#define FRE_V1_DIAGNOSTIC_CONFIG UINT32_C(2)
#define FRE_V1_DIAGNOSTIC_PATTERN_ENCODING UINT32_C(3)
#define FRE_V1_DIAGNOSTIC_COMPILE UINT32_C(4)
#define FRE_V1_DIAGNOSTIC_SEARCH UINT32_C(5)
#define FRE_V1_DIAGNOSTIC_PANIC UINT32_C(6)
#define FRE_V1_DIAGNOSTIC_CAPACITY 256u

#define FRE_V1_PLAN_EXACT_LITERAL UINT32_C(1)
#define FRE_V1_PLAN_PACKED_LITERAL_SET UINT32_C(2)
#define FRE_V1_PLAN_LITERAL_SET_DFA UINT32_C(3)
#define FRE_V1_PLAN_REQUIRED_LITERAL UINT32_C(4)
#define FRE_V1_PLAN_FORWARD_ANCHORED UINT32_C(5)
#define FRE_V1_PLAN_K0 UINT32_C(6)
#define FRE_V1_PLAN_UNICODE_WORD_RUN UINT32_C(7)
#define FRE_V1_PLAN_UNICODE_FOLDED_LITERAL UINT32_C(8)
#define FRE_V1_PLAN_LITERAL_CLASS_RUN_LITERAL UINT32_C(9)
#define FRE_V1_PLAN_PURE_BYTE_CLASS_REPEAT UINT32_C(10)
#define FRE_V1_PLAN_FIXED_PREDICATE_WORD64 UINT32_C(11)
#define FRE_V1_PLAN_BOUNDED_BYTE_CLASS_SEQUENCE UINT32_C(12)
#define FRE_V1_PLAN_REVERSE_INNER UINT32_C(13)
#define FRE_V1_PLAN_PREFIX_CLASS_ALTERNATION UINT32_C(14)
#define FRE_V1_PLAN_UNICODE_SCALAR_RUN UINT32_C(15)

#define FRE_V1_ADMISSION_UPSTREAM_ORACLE_PENDING UINT32_C(1)

typedef struct fre_v1_regex fre_v1_regex;

typedef struct fre_v1_header {
  uint32_t abi_version;
  uint32_t struct_size;
} fre_v1_header;

typedef struct fre_v1_abi_descriptor {
  uint32_t abi_version;
  uint32_t struct_size;
  uint32_t abi_major;
  uint32_t abi_minor;
  uint64_t feature_bits;
  uint32_t pointer_width;
  uint32_t endian;
  uint32_t config_size;
  uint32_t diagnostic_size;
  uint32_t plan_info_size;
  uint32_t exists_result_size;
  uint32_t selected_end_result_size;
  uint32_t match_result_size;
  uint32_t status_max;
  uint32_t reserved;
} fre_v1_abi_descriptor;

/*
 * Implemented v1 config. Compile resource limits remain PortableRegex's
 * current fixed defaults because no single exact compile cap exists yet.
 * Only these real, checked fields are exposed.
 */
typedef struct fre_v1_config {
  uint32_t abi_version;
  uint32_t struct_size;
  uint32_t profile;
  uint32_t unicode;
  uint32_t jit_policy;
  uint32_t reserved;
  uint64_t search_work;
  uint64_t search_scratch_bytes;
} fre_v1_config;

typedef struct fre_v1_diagnostic {
  uint32_t abi_version;
  uint32_t struct_size;
  uint32_t category;
  uint32_t message_length;
  uint32_t message_truncated;
  uint32_t reserved;
  uint8_t message[FRE_V1_DIAGNOSTIC_CAPACITY];
} fre_v1_diagnostic;

typedef struct fre_v1_plan_info {
  uint32_t abi_version;
  uint32_t struct_size;
  uint32_t plan;
  uint32_t admission;
  uint64_t planner_work;
  uint64_t states;
  uint64_t edges;
  uint64_t plan_storage_bytes;
  uint32_t minimum_match_present;
  uint32_t reserved;
  uint64_t minimum_match_bytes;
} fre_v1_plan_info;

typedef struct fre_v1_exists_result {
  uint32_t abi_version;
  uint32_t struct_size;
  uint32_t matched;
  uint32_t reserved;
} fre_v1_exists_result;

typedef struct fre_v1_selected_end_result {
  uint32_t abi_version;
  uint32_t struct_size;
  uint32_t found;
  uint32_t reserved;
  size_t end;
} fre_v1_selected_end_result;

typedef struct fre_v1_match_result {
  uint32_t abi_version;
  uint32_t struct_size;
  uint32_t found;
  uint32_t reserved;
  size_t start;
  size_t end;
} fre_v1_match_result;

#define FRE_V1_RECORD_INIT(type) \
  { FRE_V1_ABI_VERSION, (uint32_t)sizeof(type) }

/*
 * C caller validity contract:
 *
 * - Every non-null record pointer is naturally aligned and points to readable
 *   or writable storage (as appropriate) for its advertised struct_size.
 * - Simultaneously supplied mutable records do not overlap inputs or each
 *   other, and all storage remains live for the complete call.
 * - A byte pointer may be null only when its length is zero; otherwise the
 *   complete range is readable and no larger than PTRDIFF_MAX bytes.
 * - A regex pointer was returned by this library and still owns a retained
 *   reference. Retain requires an already-live reference. Each successful
 *   compile/retain is paired with exactly one release. Arbitrary dangling
 *   pointers, double release, and racing the final release against a call
 *   cannot be detected portably and violate this contract.
 *
 * Violating these C preconditions is undefined behavior. Checked null,
 * alignment, ABI, size, length, config, compile, and search failures return a
 * status. Result/handle outputs are written only on OK; an optional diagnostic
 * is a separate complete output. Rust panics are caught in unwind builds and
 * become PANIC; panic=abort builds terminate rather than unwinding into C.
 */

FRE_V1_API fre_v1_status
fre_v1_get_abi_descriptor(fre_v1_abi_descriptor *out);

FRE_V1_API fre_v1_status
fre_v1_config_default(fre_v1_config *out);

FRE_V1_API fre_v1_status fre_v1_regex_compile(
    const fre_v1_config *config,
    const uint8_t *pattern,
    size_t pattern_length,
    fre_v1_regex **out_regex,
    fre_v1_diagnostic *diagnostic);

FRE_V1_API fre_v1_status
fre_v1_regex_retain(const fre_v1_regex *regex);

FRE_V1_API fre_v1_status
fre_v1_regex_release(const fre_v1_regex *regex);

FRE_V1_API fre_v1_status fre_v1_regex_plan(
    const fre_v1_regex *regex,
    fre_v1_plan_info *out,
    fre_v1_diagnostic *diagnostic);

FRE_V1_API fre_v1_status fre_v1_regex_exists(
    const fre_v1_regex *regex,
    const uint8_t *haystack,
    size_t haystack_length,
    fre_v1_exists_result *out,
    fre_v1_diagnostic *diagnostic);

FRE_V1_API fre_v1_status fre_v1_regex_selected_end(
    const fre_v1_regex *regex,
    const uint8_t *haystack,
    size_t haystack_length,
    fre_v1_selected_end_result *out,
    fre_v1_diagnostic *diagnostic);

FRE_V1_API fre_v1_status fre_v1_regex_span(
    const fre_v1_regex *regex,
    const uint8_t *haystack,
    size_t haystack_length,
    fre_v1_match_result *out,
    fre_v1_diagnostic *diagnostic);

#ifdef __cplusplus
} /* extern "C" */
#endif

#if defined(__cplusplus)
#  define FRE_V1_STATIC_ASSERT(condition, message) static_assert(condition, message)
#else
#  define FRE_V1_STATIC_ASSERT(condition, message) _Static_assert(condition, message)
#endif

FRE_V1_STATIC_ASSERT(sizeof(fre_v1_header) == 8u, "fre_v1_header size");
FRE_V1_STATIC_ASSERT(offsetof(fre_v1_header, struct_size) == 4u, "header offset");
FRE_V1_STATIC_ASSERT(sizeof(fre_v1_abi_descriptor) == 64u, "descriptor size");
FRE_V1_STATIC_ASSERT(sizeof(fre_v1_config) == 40u, "config size");
FRE_V1_STATIC_ASSERT(sizeof(fre_v1_diagnostic) == 280u, "diagnostic size");
FRE_V1_STATIC_ASSERT(sizeof(fre_v1_plan_info) == 64u, "plan info size");
FRE_V1_STATIC_ASSERT(sizeof(fre_v1_exists_result) == 16u, "exists size");
FRE_V1_STATIC_ASSERT(FRE_V1_PLAN_PURE_BYTE_CLASS_REPEAT == 10u,
                     "pure byte-class plan tag");
FRE_V1_STATIC_ASSERT(FRE_V1_PLAN_FIXED_PREDICATE_WORD64 == 11u,
                     "fixed-predicate plan tag");
FRE_V1_STATIC_ASSERT(FRE_V1_PLAN_BOUNDED_BYTE_CLASS_SEQUENCE == 12u,
                     "bounded byte-class sequence plan tag");
FRE_V1_STATIC_ASSERT(FRE_V1_PLAN_REVERSE_INNER == 13u,
                     "reverse-inner plan tag");
FRE_V1_STATIC_ASSERT(FRE_V1_PLAN_PREFIX_CLASS_ALTERNATION == 14u,
                     "prefix/class-alternation plan tag");
FRE_V1_STATIC_ASSERT(FRE_V1_PLAN_UNICODE_SCALAR_RUN == 15u,
                     "Unicode scalar-run plan tag");

#if SIZE_MAX == UINT64_MAX
FRE_V1_STATIC_ASSERT(sizeof(fre_v1_selected_end_result) == 24u, "end size");
FRE_V1_STATIC_ASSERT(sizeof(fre_v1_match_result) == 32u, "match size");
#elif SIZE_MAX == UINT32_MAX
FRE_V1_STATIC_ASSERT(sizeof(fre_v1_selected_end_result) == 20u, "end size");
FRE_V1_STATIC_ASSERT(sizeof(fre_v1_match_result) == 24u, "match size");
#endif

#undef FRE_V1_STATIC_ASSERT

#endif /* FRE_V1_H_INCLUDED */
