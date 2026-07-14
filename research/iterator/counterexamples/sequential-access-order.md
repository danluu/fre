# Retained access counterexample: bit order within one row

For `(?:a|b)|c` on `a`, the outer split is compiled after the inner `a|b`
split. With compiler-indexed split bits, selected-path replay asks for the outer
bit first and the lower-ranked inner bit second at the same input boundary.

Therefore a bit-at-a-time stream in compiler-rank order cannot be replayed
without seeking, duplicating decisions, or buffering. This does not require the
entire log to be random access: the reverse-sequential prototype reads one
fixed boundary record at a time and buffers that row, allowing arbitrary
within-row rank order. Input positions themselves never regress.

`tests/sequential_log.rs` retains the witness and separately checks that every
physical row byte is written once and replay traverses at most the declared
store size.
