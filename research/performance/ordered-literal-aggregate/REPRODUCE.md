# Reproduction commands

Run from the workspace root. `REBAR_CHECKOUT` defaults to `/tmp/rebar-fre`.

## Correctness and static gates

```sh
cargo fmt -p fre-kernels -- --check
cargo clippy -p fre-kernels --lib --tests -- -D warnings
cargo test -p fre-kernels ordered_literal_aggregate --lib
cargo test -p fre-kernels --all-targets -- --nocapture
```

## Release driver

```sh
cargo build -p fre-kernels --release \
  --example ordered_literal_aggregate_integration
```

The retained 270-row matrix was emitted by five distinct processes per group:

```sh
bin=target/release/examples/ordered_literal_aggregate_integration
for spec in \
  'rebar-sherlock 0 100' \
  'sparse 65536 100' \
  'dense 65536 100' \
  'prefix 65536 100'
do
  case_name=${spec%% *}
  rest=${spec#* }
  size=${rest%% *}
  iterations=${rest##* }
  for engine in reverse rust ac packed packed-plan
  do
    for operation in count span-sum
    do
      for run in 1 2 3 4 5
      do
        "$bin" "$engine" "$case_name" "$operation" "$size" "$iterations"
      done
    done
  done
done

for engine in reverse rust ac
do
  for operation in count span-sum
  do
    for run in 1 2 3 4 5
    do
      "$bin" "$engine" empty "$operation" 65536 100
    done
  done
done

for engine in reverse rust ac packed
do
  for operation in count span-sum
  do
    for run in 1 2 3 4 5
    do
      "$bin" "$engine" adversarial "$operation" 4096 100
    done
  done
done
```

The packed plans intentionally refuse `empty`; the bounded packed plan also
refuses the 513-byte adversarial literal. Direct `packed` adversarial rows are
retained only to study the dependency outside the local theorem.

## Joint adversarial scaling

```sh
bin=target/release/examples/ordered_literal_aggregate_integration
for size in 1024 2048 4096 8192
do
  for engine in reverse rust ac
  do
    for run in 1 2 3 4 5
    do
      "$bin" "$engine" joint-adversarial count "$size" 20
    done
  done
done
```

## Dependency authentication

```sh
p=$(find "$HOME/.cargo/registry/src" \
  -path '*/aho-corasick-1.1.4/src/packed/api.rs' -print -quit)
d=${p%/api.rs}
shasum -a 256 \
  "$d/api.rs" \
  "$d/rabinkarp.rs" \
  "$d/pattern.rs" \
  "$d/teddy/builder.rs" \
  "$d/teddy/generic.rs" \
  "$d/vector.rs"
```

See `SOURCE_AUDIT.md` for exact line ranges and the theorem-to-source mapping.
