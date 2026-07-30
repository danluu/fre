# Search tag25 static fail-closed smoke

This package is a non-authoritative integration test for the inert Search
V12/tag25 static path. Its build script:

- compiles one exact-literal Span object through the explicit tag25 candidate
  constructor;
- builds one neutral expectation and one private-family glue object;
- links both exact object paths into the executable; and
- uses the existing test-only selector `11`.

The production, exact-private, and family-private source tables remain
unchanged and empty. The executable passes only when the real private-family
adapter returns `NoQualifiedStaticSearchSpanRow` without executing the native
entry. It therefore proves object emission, final linking, glue relocation,
and fail-closed adoption without manufacturing routing authority.

Run on AArch64 macOS or Linux:

```sh
cargo run --release --locked \
  --manifest-path research/aot/search-tag25-static-smoke/Cargo.toml
```
