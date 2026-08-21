# `fre-aot-regex-loader`

`fre-aot-regex-loader` is FRE's strict-W^X in-process linker and publisher for
self-contained general-AOT `Span` and `SelectedEnd` artifacts. It removes temporary object
files, an external linker, and `dlopen`/`dlsym` from latency-sensitive grep
integrations while preserving the normal compiler transaction: compilation
still emits and hashes the real ELF or Mach-O object.

Publication is deliberately direct-only. It rejects runtime helpers, a wrong
target or output contract, unavailable CPU features, malformed module layout,
and resource overruns. It never calls the portable executor. Callers retain
their existing matcher on any publication refusal.

```rust
use std::{sync::OnceLock, thread};

use fre_aot_regex::{CompileMode, CompileRequest, OutputContract, compile};
use fre_aot_regex_loader::{PublicationLimits, PublishedSpan, host_target, publish_span};

static NATIVE: OnceLock<PublishedSpan> = OnceLock::new();

let pattern = r"(?-u:\b(?:foo|bar)\b)".to_owned();
thread::Builder::new()
    .name("grep-fre-aot".into())
    .spawn(move || {
        let request = CompileRequest::new(&pattern, host_target()?)
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span);
        let compiled = compile(request)?;

        // Snapshot anything needed for logs/cache policy: publish consumes the
        // compiler result and drops its portable program and object bytes.
        let receipt = compiled.receipt().clone();
        let published = publish_span(compiled, PublicationLimits::default())?;
        eprintln!("published FRE object {:02x?}", &receipt.object_sha256[..8]);
        let _ = NATIVE.set(published);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })?;

// At a caller-defined safe boundary, a worker may clone the published handle.
// If it is not present, keep using the stock matcher. An in-file boundary is
// safe only when the caller can preserve iteration/metadata state and has
// ruled out query semantics that cannot be split at that boundary.
if let Some(native) = NATIVE.get().cloned() {
    if let Some(found) = native.find_at(b"prefix foo suffix", 0)? {
        assert_eq!(found.range(), 7..10);
    }
}
# Ok::<_, Box<dyn std::error::Error>>(())
```

`PublishedSpan` is `Clone + Send + Sync`. Cloning increments one `Arc`; each
search is one cached native function-pointer call with no allocation, lock,
feature probe, symbol lookup, or refcount operation. The mapping stays live
through the final clone. Text pages are RX, immutable data pages are R/NX, and
both ends are guarded by `PROT_NONE` pages.

Use `search` for an exact `SearchWindow`, `find_at` for a suffix, and
`find_iter`/`find_iter_in` for Rust-byte non-overlapping iteration including
nullable-pattern progress. Native status and span outputs are checked before
they become safe Rust results.

`SearchWindow` does not create a new logical haystack. Native calls retain the
complete haystack as assertion context, matching the same compiled artifact's
portable search: an interior `window.end()` is not `\z`, and a nonzero start is
not `\A`. A grep integration may cut over at a caller-validated in-file
boundary for splittable queries, but must retain its stock matcher for
haystack-anchor or other stateful queries whose semantics cannot be preserved
across that boundary.

The current safe publisher accepts only compiler-owned `CompiledRegex` values
with a versioned five-argument `Span` or `SelectedEnd` ABI. It does not accept
object bytes or caller-built modules and does not expose a raw entry pointer.
