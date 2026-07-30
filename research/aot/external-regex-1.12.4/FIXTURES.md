# External development fixture algorithm

`fixture-algorithm-development-v1.json` closes the byte-level choices left
implicit by the preregistration before any development timing. It does not
admit a new corpus or select a candidate from performance.

Only candidates labelled `independent` by the authenticated contamination
index, applicable to Search, and two through 32 bytes wide receive fixtures.
The algorithm produces all five preregistered scenarios for every such
candidate. No fixture can be discarded after measurement.

The background is a content-addressed SHA-256 counter stream mapped to printable
ASCII. The smallest printable byte absent from the literal is the repair and
guard sentinel. Repair is deterministic, considers overlapping occurrences,
and is followed by a scalar zero-occurrence proof. Sole-match fixtures clear
both adjacent width-minus-one guards before insertion and must have exactly one
scalar occurrence. Dense fixtures always retain a nonempty sentinel suffix.

The alignment value is not padding inside the fixture. It is the offset of the
exact 1 MiB haystack slice in an overallocated runner buffer, so the same
fixture bytes exercise a deterministic address alignment without changing
semantic positions.

Fixture generation is allowed while the AOT backend is under development.
Timing is not: the final V10 emitter source, object and linker identity, static
facade, and auto-routing policy are mandatory unresolved inputs until the
Search owner freezes them. The runner must execute the statically emitted and
linked facade; JIT publication is outside this evidence.

The development materialization produced 20 fixtures for four independent
candidates at `/private/tmp/fre-external-regex-dev-fixtures-v1`. Its manifest
SHA-256 is
`80dcf139225b506e294de158251bae5dbd7a2ffd0af87630420c695df7678c2b`.
An independent second generation was byte-identical for the manifest and all
20 one-MiB files. The manifest deliberately records
`backend_identity=required-unresolved-input` and `timing_permitted=false`.

## Endpoint-adversary successor

`fixture-algorithm-development-v2.json` is a transparent successor: it binds
the v1 algorithm, generator, and materialized manifest hashes and requires all
20 predecessor fixture bytes to remain identical. It adds two scenarios for
each independent literal of width at least two:

- `wrong-final-dense` repeats `literal[..width-1] || wrong_byte`.
- `wrong-first-dense` repeats `wrong_byte || literal[1..]`.

`wrong_byte` is the smallest printable ASCII byte absent from the complete
literal. It is derived without inspecting emitted code or filter positions.
Because blocks have the literal width and contain the absent byte at a fixed
endpoint, every literal-width window—including one crossing a block
boundary—contains that byte and cannot match. A scalar overlapping oracle must
still prove zero occurrences over the complete fixture.
