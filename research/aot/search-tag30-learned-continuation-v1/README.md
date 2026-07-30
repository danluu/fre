# Search tag-30 learned-continuation freeze

This directory freezes Search V17/tag30 before any tag30 timing result exists.
Tag29 results identified a graph-level failure mode only: after learning a
necessary mismatch column, V16 abandoned that column when a later block still
had five-column survivors and fell back to the V13 retained-mask scan.

V17 keeps the learned column active. A learned block is intersected with the
same five phase-unique literal columns, every retained candidate is verified
exactly, and a miss clears only that bit. Once the retained bits are exhausted,
scanning resumes at the next learned block. There is no dynamic transition to
the V13 fallback after learning.

The selector, admission policy, literal inventory, 123,424 correctness rows,
3,078 timed cells, per-cell `< 0.80` gate, six paired repetitions, minimum
elapsed time, host requirements, and all aggregate gates are unchanged from
the tag29 freeze. The projection uses the tag29 fixture seed explicitly so
prior results cannot alter membership; only tag30 schema, route, disposition,
and backend identities change.

No generator input comes from a corpus, benchmark result, network resource, or
Rebar. Rebar cannot affect membership, thresholds, exclusions, gates, or
promotion and is permitted only as post-promotion corroboration.

Recompute the complete procedural projection and validate the checked-in
identities with:

```sh
python3 research/aot/search-tag30-learned-continuation-v1/validate_freeze.py
```

One failing correctness row or timed cell rejects the broad tag30 family. A
result cannot create a narrower exclusion or authorize production.
