# rebar-manifest

This standalone tool converts the headerless CSV from a pinned
`rebar measure --list` invocation into a deterministic qualification
manifest. It does not depend on the workspace root and does not execute Rebar.

```sh
cargo run --manifest-path tools/rebar-manifest/Cargo.toml -- \
  generate \
  --input /tmp/rebar-list.csv \
  --output research/rebar/manifest.json \
  --summary research/rebar/README.md \
  --normalized-inventory research/rebar/inventory.csv \
  --runner-revision 463d00f31887e84c38467805b9e3122c314b9521
```

The four input columns are `full_name,model,engine,engine_version`. Quoted CSV
is supported. Records are sorted and duplicates, malformed names, empty
columns, and non-full Git revisions are rejected.

`--normalized-inventory` retains the complete, sorted, headerless CSV input
needed to reproduce the manifest without depending on later engine install
state. Running the generator with that canonical CSV produces the same
manifest bytes.

Only `rust/regex` and `re2` currently have audited adapter descriptions. Every
other adapter fact is emitted as `{"status":"unknown","value":null,...}`.
Every semantic comparator starts as `unverified`: the listing is inventory,
not evidence of equivalent output.
