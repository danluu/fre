#![forbid(unsafe_code)]

use std::alloc::System;

use fre_aot_regex::{
    CompileMode, RegexSetCompileRequest, RegexSetSessionLimits, SearchWindow, compile_regex_set,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn prepared_regex_set_fill_is_allocation_free_after_warmup() {
    let program = compile_regex_set(
        RegexSetCompileRequest::new(vec![
            r"(?-u:a+)".to_owned(),
            r"(?-u:\xFF)".to_owned(),
            String::new(),
        ])
        .mode(CompileMode::Fast),
    )
    .unwrap();
    let mut session = program
        .prepare_session(RegexSetSessionLimits::unlimited())
        .unwrap();
    let haystack = b"zaaa\xffz";
    let window = SearchWindow::new(0, haystack.len());
    let mut output = [0_u64; 1];
    program
        .fill_matches_with_session(&mut session, haystack, window, &mut output)
        .unwrap();

    let region = Region::new(GLOBAL);
    for _ in 0..32 {
        let report = program
            .fill_matches_with_session(&mut session, haystack, window, &mut output)
            .unwrap();
        assert_eq!(3, report.matched_count());
        assert_eq!([7], output);
    }
    assert_eq!(Stats::default(), region.change());
}
