# fre-required-literal-lab

Experimental, forced execution plan for the proven byte-regex subset
`CLASS+ SUFFIX`, with optional absolute anchors.

This crate is intentionally independent of the FRE facade. It exposes typed
pattern components, semantic refusals, resource limits, construction/search
accounting, windows and an immutable plan identity. It never silently chooses
another engine. See
[`research/performance/required-literal`](../../research/performance/required-literal/README.md)
for the proof, retained counterexamples and measurements.

Current deliberate exclusions include nullable repetitions, captures,
Unicode classes, case folding, word/line anchors, overlapping required
literals, a suffix whose first byte belongs to the preceding class, and global
iteration. Those require separate plan identities and proofs.
