# Composition interaction gate

This is an independently generated, candidate-blind gate rooted at accepted
cursor commit `a48a2f4439747a230c230a3b7815467d4c8435aa`. Its corpus was frozen
without inspecting either optimization candidate, their composition, their
earlier gate corpora, Rebar, or the final holdout.

The gate exercises public byte and text direct calls, owned and borrowed byte
iterators, text iterators with scalar-wise empty progress, endpoint and
bidirectional sessions, ranged/cursor-like calls, zero through four-or-more
consuming shapes, nullable priority, positive sparse self-loops, contextual
controls, and native controls. Input lengths are the independently generated
non-powers-of-two 31, 4093, and 262139 bytes.

`verify` is clock-free. It compares every comparable semantic result to pinned
Rust regex, records exact public accounting and setup facts, and authenticates
default, exact, unlimited, one-below-refusal, and post-refusal recovery
schedules. Timing uses four independently launched processes per point, a
precommitted randomized schedule, at most 96 dispatched processes, and no
affinity, cgroups, retries, or exclusions.

Typical handoff:

```text
python3 controller.py build --source BASE --label base --out BUILD
python3 controller.py build --source CANDIDATE --label candidate --out BUILD
python3 controller.py verify --binary BASE_BIN --out base-receipt.json
python3 controller.py verify --binary CANDIDATE_BIN --out candidate-receipt.json
python3 controller.py run --base-binary BASE_BIN --candidate-binary CANDIDATE_BIN \
  --workers 96 --out RUN
python3 analyze.py --timings RUN/timings.jsonl \
  --base-receipt base-receipt.json --candidate-receipt candidate-receipt.json \
  --out analysis.json
```

On the Arm benchmark host, pass
`--feature static-dispatch-arm-41-d84` to both build commands and retain the
task's established `RUSTFLAGS`. The controller only limits dispatch; it never
uses cgroups or affinity.
