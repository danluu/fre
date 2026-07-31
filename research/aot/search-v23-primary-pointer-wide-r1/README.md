# Search V23 primary-pointer wide candidate

V23 is a fresh backend identity built on the terminally refused V22 source.
It preserves V22's persistent learned-column machinery and changes one
general pre-learning invariant: the primary-column pointer, rather than the
candidate index, drives primary-empty 64-candidate advancement.

The design removes one integer add from every primary-empty group and
reconstructs the candidate index before every exit to existing V22 code. It
does not change the admitted widths, workload lattice, thresholds, static
columns, or runtime membership. Rebar is excluded from design and gating.

The complete frozen contract is in `preregistration-v1.json`.
