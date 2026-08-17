#![forbid(unsafe_code)]

use std::alloc::System;

use fre_aot_regex::{
    CompileMode, CompileRequest, GenericNfaProgramCensus, OutputContract, Target, compile,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn strict_generic_nfa_census_and_identity_check_allocate_nothing() {
    let compiled = compile(
        CompileRequest::new(r"(?m:^(?:ab|c[de]+)$)", Target::x86_64_linux())
            .mode(CompileMode::Fast)
            .output(OutputContract::Span),
    )
    .unwrap();
    let bytes = compiled.program().serialize_generic_nfa().unwrap();

    let region = Region::new(GLOBAL);
    for _ in 0..32 {
        let census = GenericNfaProgramCensus::from_wire(&bytes).unwrap();
        assert!(census.authenticates_wire(&bytes));
        assert_eq!(census.output_contract(), OutputContract::Span);
    }
    assert_eq!(region.change(), Stats::default());
}
