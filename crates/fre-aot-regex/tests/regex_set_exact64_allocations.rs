#![forbid(unsafe_code)]

use std::alloc::System;

use fre_aot_regex::{
    RegexSetCompileRequest, RegexSetExact64CompileDisposition, RegexSetExact64Limits, SearchWindow,
    compile_regex_set_exact64_reported,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn exact64_shared_fill_is_allocation_free_after_warmup() {
    let disposition = compile_regex_set_exact64_reported(
        RegexSetCompileRequest::new(["he", "she", "hers", "he", "e"].map(str::to_owned).to_vec()),
        RegexSetExact64Limits::default(),
    )
    .unwrap();
    let RegexSetExact64CompileDisposition::Selected(program) = disposition else {
        panic!("exact64 allocation fixture declined");
    };
    let haystack = b"ushers";
    let window = SearchWindow::full(haystack);
    let mut output = 0_u64;
    program.fill_matches(haystack, window, &mut output).unwrap();

    let region = Region::new(GLOBAL);
    for _ in 0..32 {
        let report = program.fill_matches(haystack, window, &mut output).unwrap();
        assert_eq!(5, report.matched_count());
        assert_eq!(0b1_1111, output);
    }
    assert_eq!(Stats::default(), region.change());
}
