# Stable C and C++ embedding contract

This is the long-term target ABI. It is not a statement that every item below
is implemented or compatibility-qualified. The smaller experimental surface
that exists today is recorded in [IMPLEMENTED_V1.md](IMPLEMENTED_V1.md); its
plan records deliberately report `UPSTREAM_ORACLE_PENDING`.

A target row becomes a supported contract only after its underlying Rust
operation has a complete compatibility and resource contract. Future rows are
not represented by stubs or speculative feature bits.

## ABI rules

- Every public structure begins with `abi_version` and `struct_size`; callers
  zero unknown tail bytes and the library rejects undersized mandatory fields.
- Enums cross the boundary as explicitly documented `uint32_t` tags. Byte
  lengths and offsets use `size_t`; serialized identities use fixed-width
  integers and byte arrays.
- Patterns and haystacks are `(pointer, length)` views. A null pointer is legal
  only at length zero. RE2 Latin-1 patterns therefore never pass through a C
  string API.
- Compiled regexes, iterators, capture buffers, AOT artifacts, and errors are
  opaque handles allocated and destroyed by the same library. No Rust
  allocation is freed by the embedding allocator or vice versa.
- Every function returns a stable status tag. Detailed errors are retrieved
  through an opaque error handle or caller-owned buffer; no thread-local
  implicit “last error” state.
- No Rust panic, C++ exception, signal, or generated-code fault may cross the
  ABI. Functions validate pointers before dereference and publish no partial
  output on failure.
- Compiled regex handles are immutable and thread-safe after construction.
  Iterator and mutable capture-state handles are not implicitly synchronized.
- Symbol names carry the major ABI (`fre_v1_*`). The shared library exports an
  ABI descriptor and feature bitmap so dynamic loaders can fail before using a
  mismatched header.

## Minimum v1 surface

```c
typedef struct fre_v1_regex fre_v1_regex;
typedef struct fre_v1_error fre_v1_error;

typedef struct {
  uint32_t abi_version;
  uint32_t struct_size;
  uint32_t profile;       /* Rust text, Rust bytes, or RE2 */
  uint32_t operation;     /* exists, selected end, span */
  uint64_t compile_work;
  uint64_t compile_peak_bytes;
  uint64_t search_work;
  uint64_t search_scratch_bytes;
  uint64_t code_bytes;
  uint32_t jit_policy;    /* deny, prefer, require */
  uint32_t reserved;
} fre_v1_config;

typedef struct {
  size_t start;
  size_t end;
} fre_v1_match;
```

Required functions cover library/ABI inspection, checked default config,
compile from bytes, retain/release, plan explanation, is-match, selected-end,
span, error inspection, and error release. Aggregate iterator, captures,
replacement, split, set matching, serialization/AOT, and streaming are added
only when their Rust operation contracts are complete; a stub is not reported
as a supported feature.

## Profile identity

The config embeds or points to a versioned profile-options structure. Cache and
explanation records include the pinned Rust/RE2 revision, Unicode version,
syntax options, admission policy, operation, resource limits, target/CPU/JIT
policy, and plan identity. RE2 `longest_match`, encoding, POSIX mode, and every
syntax bit remain distinguishable. A default constructor fills explicit
values; ABI zero is never interpreted as “whatever the current Rust default
happens to be.”

## C++ wrapper

The header-only C++ layer owns opaque handles with move-only RAII, returns an
explicit status/result type, accepts `std::string_view` or byte spans without
copying haystacks, and never throws unless an opt-in wrapper is used. Its API
should feel as small as RE2 while retaining FRE plan/resource diagnostics.

## Qualification

- Build and run C11 and C++17 consumers under Clang, GCC, MSVC where supported,
  and Rust bindgen-generated declarations.
- Static assertions for every public size/alignment/offset/tag on 32- and
  64-bit targets; symbol-list and ABI-compliance checks in CI.
- Null, dangling-length, misaligned, oversized, double-release, use-after-
  release under sanitizers, concurrent retain/release, allocation failure, and
  panic/fault injection tests.
- Cross-language semantic differentials for every advertised profile and
  operation, including arbitrary byte patterns/haystacks.
- Static and dynamic linking, hidden symbol visibility, LTO, versioned shared
  libraries, and embedding with JIT disabled/denied.
