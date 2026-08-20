# Implemented FRE C ABI v1

This document describes the code that exists today. It is intentionally
narrower than the [long-term embedding contract](C_ABI_CONTRACT.md) and makes
no claim that the underlying portable subset is compatibility-qualified. Every
strict plan record reports `FRE_V1_ADMISSION_STRICT_CHECKED`: local syntax,
configuration, and non-resource diagnostics were checked, but exact upstream
compiled-size admission is not promised. FRE applies its own typed resource
limits to its compiled representation.

## Implemented surface

The `fre-capi` crate builds `rlib`, `staticlib`, and `cdylib` artifacts and
ships the C11 header `crates/fre-capi/include/fre.h` plus the header-only C++17
wrapper `crates/fre-capi/include/fre.hpp`.

The exact exported symbol set is:

- `fre_v1_get_abi_descriptor`
- `fre_v1_config_default`
- `fre_v1_regex_compile`
- `fre_v1_regex_retain`
- `fre_v1_regex_release`
- `fre_v1_regex_plan`
- `fre_v1_regex_exists`
- `fre_v1_regex_selected_end`
- `fre_v1_regex_span`

The runtime descriptor advertises only Rust-bytes pattern syntax, immutable
thread-safe regex handles, plan information, and the three single-search
operations. Patterns are explicit byte views but must contain valid UTF-8
regex syntax, as required by the Rust parser. Haystacks are arbitrary bytes;
embedded NUL and invalid UTF-8 are not treated as terminators or rejected.
The `fre_v1_plan_info.plan` field uses append-only public tags: existing tags
1 through 9 remain fixed, `PURE_BYTE_CLASS_REPEAT` is 10, and
`FIXED_PREDICATE_WORD64` is 11.

`fre_v1_config` exposes only fields that map to real controls: the Rust-bytes
profile, Unicode mode, JIT denial, search work, and search scratch bytes. JIT
is neither implemented nor advertised. Compile resource limits use the
current `PortableRegex` fixed defaults because its facade does not yet expose
one exact compile cap.

Not implemented or advertised: Rust text and RE2 profiles, JIT, AOT,
serialization, aggregate iteration, captures, replacement, split, regex sets,
streaming, or opaque error objects. Diagnostics are instead fixed-size,
caller-owned records, with deterministic category and message bytes.

## Ownership and failure contract

A successful compile returns one opaque reference-counted handle. Each
successful retain creates one additional reference and each reference must be
released exactly once. Immutable searches may run concurrently while each
caller owns a live reference. Retain requires an already-live reference, and
racing any call with the final release is invalid. A C implementation cannot
portably detect dangling handles, double release, or use-after-release.

The detailed pointer contract is in `fre.h`. In summary, callers provide
correctly aligned, live, readable or writable storage for every advertised
record or byte range; mutable outputs do not alias inputs or each other for the
call. Null byte pointers are accepted only at length zero. Violating those
preconditions is undefined behavior. Null, alignment, record version, record
size, view length, configuration, compile, and search errors that can be
checked portably return stable status tags.

Result records and handle slots are written only on `OK`. Diagnostics are a
separate complete output. Larger records are accepted and only the known v1
prefix is written, preserving caller-owned tail bytes. There is no implicit
thread-local last error.

The boundary catches Rust unwinds and maps them to `PANIC` when the library is
built with unwinding enabled. The workspace release profile uses
`panic = "abort"`; a panic in that build terminates the process instead of
crossing into C. Production paths are written to be panic-free, but allocation
failure and other process-abort conditions are not recoverable ABI statuses.

## C++17 wrapper

`fre.hpp` provides a move-only `fre::Regex` RAII owner. Compile and search
operations are `noexcept` and return explicit status/result objects with
caller-owned diagnostics; no exception-based convenience layer is present.
It accepts `std::string_view`, including embedded NUL bytes, without copying a
haystack.

## Verification performed

`research/embedding/run-smoke.sh` builds the dynamic library, checks the exact
`fre_v1_*` exported-symbol list, compiles C11 and C++17 consumers with warnings
as errors, links them, and runs all operations. The same script accepts
`--release`, which also exercises the workspace's `panic = "abort"` artifact.

Rust unit tests cover ABI sizes, offsets, tags, descriptors, checked config,
all operations, plan identity, embedded NUL, null/zero-length views,
deterministic failures, unchanged result/handle slots on failure, preservation
of oversized-record tails, retained concurrent searches, and unwind
containment. The tests deliberately do not execute dangling-pointer,
double-release, or final-release races because those violate the C contract;
future sanitizer harnesses should cover misuse in a process that may crash.

Current host verification covers 64-bit macOS with Clang-compatible C11 and
C++17 drivers. The headers contain 32/64-bit layout assertions, and the smoke
runner has Linux shared-library support, but Windows, 32-bit, GCC-as-distinct-
from-Clang, MSVC, bindgen, sanitizer, allocation-failure, static-link, and ABI-
compliance-suite gates remain future work.
