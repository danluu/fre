#ifndef FRE_AOT_MACHO_H
#define FRE_AOT_MACHO_H

#include <stddef.h>
#include <stdint.h>
#if defined(__APPLE__)
#include <TargetConditionals.h>
#endif

#if defined(__cplusplus)
extern "C" {
#endif

#define FRE_AOT_METADATA_VERSION 1u
#define FRE_AOT_METADATA_BYTES_V1 216u
#define FRE_AOT_ABI_SEARCH_V1 1u
#define FRE_AOT_ABI_AGGREGATE_V1 2u
#define FRE_AOT_PLATFORM_MACOS 1u
#define FRE_AOT_EXPORTED_SYMBOL_SCHEMA_V1 1u
#define FRE_AOT_EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V1 64u
#define FRE_AOT_METADATA_VERSION_V2 2u
#define FRE_AOT_METADATA_BYTES_V2 232u
#define FRE_AOT_ABI_COUNT_V2 2u
#define FRE_AOT_CALL_ABI_SCHEMA_V2 2u
#define FRE_AOT_EXPORTED_SYMBOL_SCHEMA_V2 3u
#define FRE_AOT_EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V2 64u
#define FRE_AOT_COUNT_STATUS_OK_V2 UINT64_C(0)
#define FRE_AOT_COUNT_STATUS_OVERFLOW_V2 UINT64_C(1)

/*
 * V1 is a target-specific raw ABI, not a portable C data format. Generated
 * code performs AAPCS64 loads/stores and metadata scalars are little-endian.
 * Fail compilation instead of accepting a layout-compatible but unsafe host.
 */
#if !defined(__APPLE__) || !defined(__MACH__) || \
    !defined(TARGET_OS_OSX) || !TARGET_OS_OSX
#error "FRE AOT Mach-O v1 requires Apple macOS"
#endif
#if !defined(__aarch64__) && !defined(__arm64__)
#error "FRE AOT Mach-O v1 requires AArch64"
#endif
#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    (__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__)
#error "FRE AOT Mach-O v1 requires little-endian byte order"
#endif
#if !defined(UINTPTR_MAX) || (UINTPTR_MAX != UINT64_MAX)
#error "FRE AOT Mach-O v1 requires 64-bit pointers"
#endif
#if !defined(SIZE_MAX) || (SIZE_MAX != UINT64_MAX)
#error "FRE AOT Mach-O v1 requires 64-bit size_t"
#endif

/*
 * Concrete entry, payload, and metadata names are emitted in this form:
 *
 *   fre_aot_{search|aggregate}_entry_v1_<64 lowercase compile-identity hex>
 *   fre_aot_payload_v1_<the same 64 hex bytes>
 *   fre_aot_metadata_v1_<the same 64 hex bytes>
 *
 * Build tooling must generate the three extern declarations from the trusted
 * compile receipt. It must not accept names discovered from an untrusted
 * object or final image as authority. Full identities avoid a truncated
 * process-global namespace and permit multiple generated regexes to coexist.
 */
struct fre_aot_search_result_v1 {
    size_t start;
    size_t end;
};

struct fre_aot_aggregate_result_v1 {
    uint64_t value;
};

/*
 * Raw pointer contract shared by both entry types:
 *
 * - haystack must be nonnull and point into one live allocation whose range
 *   [haystack, haystack + haystack_len) is readable for the complete call,
 *   including when haystack_len is zero. The one-past pointer must be
 *   representable within that allocation. No thread or signal handler may
 *   mutate or unmap the range during the call.
 * - result must be nonnull, naturally aligned, and exclusively writable for
 *   the complete result structure. It must not overlap haystack, generated
 *   payload, metadata, or any concurrently used result slot.
 * - the generated entry retains no pointer after return. Concurrent calls are
 *   permitted only when each result slot is disjoint and every haystack obeys
 *   the immutable-readable rule.
 * - callers must initialize the complete result slot to their own poison
 *   value. A result is readable only for a status documented as publishing
 *   that result. Every other status must leave the slot bitwise unchanged;
 *   a changed poison is a backend-contract violation.
 *
 * These raw symbols are not a safe API. A verified handle/trampoline must
 * authenticate metadata, identity, mapping protections, CPU features, input
 * limits, pointer ranges, and the result poison before exposing a result.
 */

/*
 * Search ABI: haystack base/length, inclusive window_start and exclusive
 * window_end. The window must satisfy window_start <= window_end <=
 * haystack_len before entry. Status 0 means no match and leaves result
 * unchanged. Status 1 publishes start/end satisfying
 * window_start <= start <= end <= window_end. Every other status is a typed
 * backend fault and leaves result unchanged.
 */
typedef uint64_t (*fre_aot_search_entry_fn_v1)(
    const uint8_t *haystack,
    size_t haystack_len,
    size_t window_start,
    size_t window_end,
    struct fre_aot_search_result_v1 *result);

/*
 * Aggregate ABI: whole haystack base/length and result slot. Status 0
 * publishes result.value. Status 1 reports checked arithmetic overflow.
 * Every nonzero status leaves result unchanged and is a typed backend fault;
 * callers must not infer a partial count from the poisoned slot.
 */
typedef uint64_t (*fre_aot_aggregate_entry_fn_v1)(
    const uint8_t *haystack,
    size_t haystack_len,
    struct fre_aot_aggregate_result_v1 *result);

/*
 * Aggregate-only V2 is a separate wire and symbol family for the independent
 * Count AOT backend. Concrete names are:
 *
 *   fre_aot_count_entry_v2_<64 lowercase V2 compile-identity hex>
 *   fre_aot_count_payload_v2_<the same 64 hex bytes>
 *   fre_aot_count_metadata_v2_<the same 64 hex bytes>
 *
 * These three definitions are private-external implementation symbols. That
 * permits identity-specific authenticated glue in another input object to
 * bind them while preventing the final application from exporting or
 * dynamically resolving them. The trusted final-image gate must reject a raw
 * Count symbol present in the final export trie or dynamic export table.
 *
 * The raw entry is never an application API. Authenticated glue may call it
 * only after verifying the expectation, complete final image, exact symbol
 * extents, payload digest, mapping protections, target features, and entry
 * address. Its complete internal call contract is:
 *
 * - haystack is nonnull and points into one live allocation whose complete
 *   [haystack, haystack + haystack_len) range is readable and immutable for
 *   the call. The addition and one-past pointer are representable within that
 *   allocation. For length zero glue supplies a nonnull sentinel, which the
 *   entry must not dereference. No thread or signal handler may mutate,
 *   unmap, or remap the range during the call.
 * - result is nonnull, naturally aligned, initialized, and uniquely writable
 *   for one complete fre_aot_count_result_v2. It is disjoint from haystack,
 *   payload, metadata, every other live result slot, and all glue state that
 *   is not explicitly the private result slot.
 * - glue initializes result.value to the reserved poison UINT64_MAX. Status
 *   FRE_AOT_COUNT_STATUS_OK_V2 publishes the mathematically exact Count and
 *   must replace poison. Status FRE_AOT_COUNT_STATUS_OVERFLOW_V2 reports
 *   checked arithmetic overflow and leaves the complete slot bitwise unchanged.
 *   Every other status is a backend fault and likewise leaves the slot
 *   unchanged. Glue validates status, poison, and the semantic Count
 *   upper bound before copying a value to application-visible storage;
 *   every refusal leaves application-visible output unpublished.
 * - the entry reads only the admitted haystack range, writes the result slot
 *   exactly once and only on successful publication, retains no pointer or
 *   derived reference after return, and never unwinds across the C ABI.
 * - The entry is reentrant. Concurrent calls are permitted only with
 *   independently writable, nonoverlapping result slots and haystacks that
 *   independently obey the immutable-readable rule. The implementation may
 *   not perform unsynchronized mutation through shared state.
 */
struct fre_aot_count_result_v2 {
    uint64_t value;
};

typedef uint64_t (*fre_aot_count_raw_entry_fn_v2)(
    const uint8_t *haystack,
    size_t haystack_len,
    struct fre_aot_count_result_v2 *result);

/*
 * Stable byte record. All multi-byte scalar fields and digest bytes are
 * emitted little-endian. This self-described record is not sufficient to
 * authenticate a final linked file. Before dlopen, a loader must hash the
 * complete final file against an externally trusted final-file identity and
 * strictly parse the final Mach-O/dylib envelope (imports, dependencies, load
 * commands, sections, symbols, protections, ranges, and initializers). After
 * identity-specific symbol resolution, it must compare compile_identity with
 * the externally trusted compile receipt, then hash payload_bytes starting at
 * that receipt-derived payload symbol and compare payload_sha256 before
 * publishing the entry through a verified handle.
 * ObjectIdentity is likewise an external receipt over the pre-link MH_OBJECT;
 * it cannot be embedded here without creating a digest self-reference.
 */
struct fre_aot_metadata_v1 {
    uint8_t magic[8];
    uint16_t format_version;
    uint16_t record_bytes;
    uint16_t backend_version;
    uint8_t abi_kind;
    uint8_t output_kind;
    uint8_t architecture;
    uint8_t little_endian;
    uint8_t pointer_width;
    uint8_t target_abi;
    uint8_t platform;
    uint8_t status_bits;
    uint16_t abi_schema;
    uint64_t features;
    uint32_t payload_bytes;
    uint32_t entry_offset;
    uint32_t code_bytes;
    uint32_t rodata_offset;
    uint32_t rodata_bytes;
    uint32_t literal_bytes;
    uint8_t source_identity[32];
    uint8_t artifact_identity[32];
    uint8_t binding_identity[32];
    uint8_t payload_sha256[32];
    uint8_t compile_identity[32];
};

/*
 * Aggregate-only V2 metadata. All scalars are canonical little-endian bytes.
 * The complete independent backend support tuple is explicit. actual_features
 * describes this payload; allowed_features is the ceiling sealed by the exact
 * supported backend row. A loader must reject either an unknown complete row
 * or actual feature bits outside that ceiling.
 */
struct fre_aot_metadata_v2 {
    uint8_t magic[8];
    uint16_t format_version;
    uint16_t record_bytes;
    uint16_t backend_version;
    uint16_t algorithm_version;
    uint16_t kir_semantics_version;
    uint16_t kir_abi_version;
    uint16_t abi_schema;
    uint16_t max_literal_bytes;
    uint8_t abi_kind;
    uint8_t output_kind;
    uint8_t architecture;
    uint8_t little_endian;
    uint8_t pointer_width;
    uint8_t target_abi;
    uint8_t platform;
    uint8_t status_bits;
    uint64_t actual_features;
    uint64_t allowed_features;
    uint32_t payload_bytes;
    uint32_t entry_offset;
    uint32_t code_bytes;
    uint32_t rodata_offset;
    uint32_t rodata_bytes;
    uint32_t literal_bytes;
    uint8_t source_identity[32];
    uint8_t artifact_identity[32];
    uint8_t binding_identity[32];
    uint8_t payload_sha256[32];
    uint8_t compile_identity[32];
};

#if defined(__cplusplus)
}
#endif

#if defined(__cplusplus)
static_assert(sizeof(struct fre_aot_metadata_v1) == FRE_AOT_METADATA_BYTES_V1,
              "unexpected FRE AOT metadata layout");
static_assert(sizeof(struct fre_aot_metadata_v2) == FRE_AOT_METADATA_BYTES_V2,
              "unexpected FRE AOT V2 metadata layout");
static_assert(sizeof(struct fre_aot_search_result_v1) == (2u * sizeof(size_t)),
              "unexpected FRE AOT search result layout");
static_assert(sizeof(void *) == 8u, "unexpected FRE AOT pointer width");
static_assert(sizeof(size_t) == 8u, "unexpected FRE AOT size_t width");
static_assert(offsetof(struct fre_aot_search_result_v1, end) == sizeof(size_t),
              "unexpected FRE AOT search end offset");
static_assert(sizeof(struct fre_aot_aggregate_result_v1) == 8u,
              "unexpected FRE AOT aggregate result layout");
static_assert(offsetof(struct fre_aot_metadata_v1, features) == 24u,
              "unexpected FRE AOT features offset");
static_assert(offsetof(struct fre_aot_metadata_v1, source_identity) == 56u,
              "unexpected FRE AOT identity offset");
static_assert(offsetof(struct fre_aot_metadata_v1, compile_identity) == 184u,
              "unexpected FRE AOT compile identity offset");
static_assert(sizeof(struct fre_aot_count_result_v2) == 8u,
              "unexpected FRE AOT Count V2 result layout");
static_assert(offsetof(struct fre_aot_metadata_v2, actual_features) == 32u,
              "unexpected FRE AOT V2 actual features offset");
static_assert(offsetof(struct fre_aot_metadata_v2, allowed_features) == 40u,
              "unexpected FRE AOT V2 allowed features offset");
static_assert(offsetof(struct fre_aot_metadata_v2, source_identity) == 72u,
              "unexpected FRE AOT V2 identity offset");
static_assert(offsetof(struct fre_aot_metadata_v2, compile_identity) == 200u,
              "unexpected FRE AOT V2 compile identity offset");
#else
_Static_assert(sizeof(struct fre_aot_metadata_v1) == FRE_AOT_METADATA_BYTES_V1,
               "unexpected FRE AOT metadata layout");
_Static_assert(sizeof(struct fre_aot_metadata_v2) == FRE_AOT_METADATA_BYTES_V2,
               "unexpected FRE AOT V2 metadata layout");
_Static_assert(sizeof(struct fre_aot_search_result_v1) == (2u * sizeof(size_t)),
               "unexpected FRE AOT search result layout");
_Static_assert(sizeof(void *) == 8u, "unexpected FRE AOT pointer width");
_Static_assert(sizeof(size_t) == 8u, "unexpected FRE AOT size_t width");
_Static_assert(offsetof(struct fre_aot_search_result_v1, end) == sizeof(size_t),
               "unexpected FRE AOT search end offset");
_Static_assert(sizeof(struct fre_aot_aggregate_result_v1) == 8u,
               "unexpected FRE AOT aggregate result layout");
_Static_assert(offsetof(struct fre_aot_metadata_v1, features) == 24u,
               "unexpected FRE AOT features offset");
_Static_assert(offsetof(struct fre_aot_metadata_v1, source_identity) == 56u,
               "unexpected FRE AOT identity offset");
_Static_assert(offsetof(struct fre_aot_metadata_v1, compile_identity) == 184u,
               "unexpected FRE AOT compile identity offset");
_Static_assert(sizeof(struct fre_aot_count_result_v2) == 8u,
               "unexpected FRE AOT Count V2 result layout");
_Static_assert(offsetof(struct fre_aot_metadata_v2, actual_features) == 32u,
               "unexpected FRE AOT V2 actual features offset");
_Static_assert(offsetof(struct fre_aot_metadata_v2, allowed_features) == 40u,
               "unexpected FRE AOT V2 allowed features offset");
_Static_assert(offsetof(struct fre_aot_metadata_v2, source_identity) == 72u,
               "unexpected FRE AOT V2 identity offset");
_Static_assert(offsetof(struct fre_aot_metadata_v2, compile_identity) == 200u,
               "unexpected FRE AOT V2 compile identity offset");
#endif

#endif
