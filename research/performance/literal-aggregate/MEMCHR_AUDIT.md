# Pinned `memchr` whole-iterator and ownership audit

Dependency identity:

```text
memchr 2.8.3
Cargo.lock package checksum:
cf8baf1c55e62ffcace7a9f06f4bd9cd3f0c4beb022d3b367256b91b87513d98
```

Audited registry source hashes:

```text
d869159f0d0c1915d7acc42a6a4aa3c97c049ddc043e6566afeb78ad290995d1  src/memmem/mod.rs
84f6a23bef907696cb672e6898c15fb87008058abc100dde58519d8ec5ebca5d  src/memmem/searcher.rs
2b053e393d3841f780425b3b0da5bec4f187603fa7c271b045ecb7d885b23395  src/cow.rs
```

In `src/memmem/mod.rs`, lines 89-99 specify that `find_iter` returns all
non-overlapping occurrences and guarantees worst-case
`O(needle.len() + haystack.len())` time and worst-case constant space. Lines
230-242 show that `FindIter` contains borrowed haystack state, an inline
prefilter state, a finder, and a position. Lines 244-251 construct that state
without allocation. Lines 273-285 implement `next` by searching the remaining
borrowed slice and advancing by `needle.len().max(1)`. Lines 288-301 give the
same non-overlapping event upper bounds used by FRE.

`Finder::find_iter` at lines 427-459 passes `self.as_ref()` into that iterator.
It does not call `into_owned`. Thus operation traversal borrows the already
owned needle and does not copy it.

Persistent ownership is also pinned. `Finder` is exactly a `CowBytes` plus an
inline `Searcher` (`mod.rs` lines 383-387). `FinderBuilder` constructs the
searcher before installing the owned boxed needle (lines 697-707). `cow.rs`
lines 13-20 show that the owned payload is one `Box<[u8]>`, not a `Vec` or a
second allocation. `searcher.rs` lines 24-36 explicitly explain and show the
inline function-pointer/union/Rabin-Karp representation instead of a boxed
trait object. Therefore the persistent account `size_of::<Plan>() + needle.len()`
covers the inline finder/searcher and its sole heap payload under this exact
pinned implementation.

FRE's operation path contains no allocation, fallback, or result vector:
`count`/`span_sum` preflight fixed arithmetic, empty needles execute one direct
formula, and nonempty needles construct one borrowed iterator and consume it.
No allocation-capable `into_owned` method is called. Release library assembly
for both public operation symbols contains no allocator or reallocator call.
It contains one call to the pinned iterator `next`. The emitted generic drop
glue retains a guarded deallocator branch for the impossible owned variant of
the borrowed iterator finder; the discriminant is initialized to borrowed and
the branch is not taken. This is not an operation allocation.

Assembly receipt:

```text
cargo rustc -p fre-kernels --release --lib -- --emit=asm
rustc 1.93.0 (254b59607 2026-01-19), LLVM 21.1.8
aarch64-apple-darwin
target/release/deps/fre_kernels-d4fc82cc66e33c5a.s
SHA-256 d61bce69ff342d63578119a8916b26b983a1f2ea17aa5018f2af3f52479eb279
count symbol: lines 2617-2818
span_sum symbol: lines 2821-3028
```

## Existing `LiteralPlan` audit

The older `LiteralPlan` describes `max_needle_bytes` as copied needle bytes and
`storage_bytes()` as logical persistent pattern payload bytes. Those labels do
not claim total plan memory. Its owned `Finder` has the same boxed needle and
inline searcher facts above, so no concrete false bound was found. It was not
redesigned. The new aggregate plan nevertheless has a separate non-`Clone`
identity and total inline-plus-payload persistent/peak accounting.
