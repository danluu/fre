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
