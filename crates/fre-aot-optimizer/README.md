# `fre-aot-optimizer`

This crate is the source-only Count-v3 recipe optimizer. It consumes one
sealed `ExactAggregateProgram<Count>` and an explicit target tuning class. It
has no LLVM, assembler, linker, JIT, timer, host-probing, corpus, benchmark
label, haystack, or path input.

The optimizer computes a 256-entry fixed byte-prevalence prior, exact literal
multiplicities, distinct-byte count, and KMP minimum period/self-overlap. It
then exhaustively evaluates a finite portfolio over an eight-column frontier:

- the reviewed Count-v2-compatible incumbent;
- every two-, three-, and four-column combination whose literal bytes are
  distinct;
- both endpoint orders and endpoint-plus-pattern-rare schedules; and
- one period-aware schedule whenever the KMP period is shorter than the
  literal.

Every recipe has fixed integer costs for sparse candidates, dense candidates,
false positives, matches, tails, and code size. Dominated recipes are removed.
Selection minimizes the worst normalized regret across those six dimensions,
then total regret, code size, and the canonical primitive recipe tuple. There
are no floating-point values or iteration-order-dependent maps.

The recipe binds the complete aggregate-program identity, a domain-separated
literal identity, target tuning/ISA/register/schedule IDs, all filter and
confirmation offsets, exact non-overlapping confirmation groups, strides,
costs, and its own domain-separated identity. The optimizer receipt also binds
the exact portfolio size, Pareto size, selected ordinal, regret, work, scratch,
allocation, retained-storage, and hashing accounting.

`inspect_count_recipe_v3` strictly inspects the fixed canonical encoding
without allocation or KIR. `decode_count_recipe_v3` additionally recomputes
all pattern-derived facts, legal portfolio membership, confirmation schedule,
cost vector, and identity against the supplied typed program. The current
optimizer emits only baseline AArch64 Advanced SIMD recipes. Distinct stable
IDs are reserved for fixed-VL16 SVE and SVE2 recipes; they cannot be inferred
from the host or silently substituted for the emitted recipe.

`inspect_count_v3_optimizer_receipt` separately decodes the fixed 192-byte
optimizer receipt without allocation. It rejects unknown versions and tuning
classes, nonzero padding, impossible resource/accounting fields, and an
incorrect domain-separated receipt identity before a compiler may bind the
receipt into an object.
