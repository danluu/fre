# Frozen phase-unique Search selector v1

This contract freezes the structural eligibility theorem for the successor to
the rejected tag 27 learned-column experiment. It was written after narrow
tag 27 development smokes exposed periodic regressions, but before any
successor full screen, source-corpus timing, application-corpus timing,
held-out timing, or Rebar timing.

The selector is not an entropy cutoff. It uses the five offsets already
authenticated by the compiler and admits a literal only when their byte tuple
uniquely identifies cyclic phase zero. Equivalently, every nonzero cyclic
shift differs at one or more of those five offsets. This is the exact
structural property needed by the learned sixth column: periodic phase-shifted
candidates cannot survive the authenticated five-column intersection.

Eligible checked windows keep the existing authoritative portable prefix of
256 candidate starts and use the new native backend only for the disjoint
tail. Ineligible literals and windows use portable search for the full range;
the failed V13/V14 candidates are not production fallbacks.

The machine contract deliberately leaves the new wire tag and policy number
unresolved. The compiler successor must assign new identities, implement the
predicate independently in its emitter and auditor, and bind the final source
and runner before any qualification timing.

Validate the frozen contract without running an engine:

```sh
python3 research/aot/search-phase-unique-selector-v1/validate_contract.py \
  research/aot/search-phase-unique-selector-v1/selector-contract-v1.json
```
