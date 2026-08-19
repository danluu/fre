use fre::{
    CAPTURE_BOUNDED_BACKTRACK_ITERATION_ACCOUNTING_VERSION,
    CAPTURE_BOUNDED_BACKTRACK_ITERATION_ALGORITHM_VERSION,
    CAPTURE_BOUNDED_BACKTRACK_ITERATION_MAX_SEARCH_BYTES, CaptureAggregateLimits, CaptureBuilder,
    CaptureSearchLimits,
};

const AMBIGUOUS_PATTERN: &str = r"(?P<head>a(?P<tail>b)|a(?P<other>c)?)(?P<last>d)?";
const AMBIGUOUS_HAYSTACK: &[u8] = b"ab a ac ad";

const PUBLIC_BIBLEREF_PATTERN: &str = r"(?P<Book>(([1234]|I{1,4})[\t\f\pZ]*)?\pL+\.?)[\t\f\pZ]+(?P<Locations>((?P<Chapter>1?[0-9]?[0-9])(-(?P<ChapterEnd>\d+)|,\s*(?P<ChapterNext>\\d+))*(:\s*(?P<Verse>\d+))?(-(?P<VerseEnd>\d+)|,\s*(?P<VerseNext>\d+))*\s?)+)";
const PUBLIC_BIBLEREF_HAYSTACK: &[u8] = b"Gen 1:1, 2\n3 King 1:3-4\nII Ki. 3:12-14, 25\n";

fn ambiguous_regex() -> fre::CaptureRegex {
    CaptureBuilder::new(AMBIGUOUS_PATTERN)
        .unicode(false)
        .build()
        .expect("ambiguous capture regex")
}

#[test]
fn reusable_bounded_backtrack_matches_history_and_closes_first_and_steady() {
    assert_eq!(CAPTURE_BOUNDED_BACKTRACK_ITERATION_ALGORITHM_VERSION, 1);
    assert_eq!(CAPTURE_BOUNDED_BACKTRACK_ITERATION_ACCOUNTING_VERSION, 1);
    let regex = ambiguous_regex();
    let limits = CaptureAggregateLimits::default();
    let incumbent = regex
        .captures_iter(AMBIGUOUS_HAYSTACK, limits)
        .expect("History authority");
    let mut session = regex
        .prepare_captures_iter_bounded_backtrack(AMBIGUOUS_HAYSTACK.len(), limits)
        .expect("workspace allocation")
        .expect("eligible reusable bounded backtracker");

    let first = regex
        .captures_iter_bounded_backtrack(&mut session, AMBIGUOUS_HAYSTACK, limits)
        .expect("first direct operation")
        .expect("first direct selection");
    let steady = regex
        .captures_iter_bounded_backtrack(&mut session, AMBIGUOUS_HAYSTACK, limits)
        .expect("steady direct operation")
        .expect("steady direct selection");

    assert_eq!(first.captures, incumbent.captures);
    assert_eq!(steady.captures, incumbent.captures);
    assert_eq!(first, steady);
    assert!(first.has_closed_attempt());
    assert!(steady.has_closed_attempt());
    assert_eq!(first.preparation_receipt.setup_allocations, 3);
    assert_eq!(first.attempt_receipt.operation_setup_allocations, 0);
    assert_eq!(steady.attempt_receipt.operation_setup_allocations, 0);
    assert_eq!(first.actual.total_history_nodes, 0);
    assert_eq!(first.actual.total_history_walk, 0);

    let records = &first.captures;
    assert_eq!(records.len(), 4);
    assert!(records[0].groups[2].span.is_some());
    assert!(records[0].groups[3].span.is_none());
    assert!(records[1].groups[2].span.is_none());
    assert!(records[1].groups[3].span.is_none());
    assert!(records[2].groups[2].span.is_none());
    assert!(records[2].groups[3].span.is_some());
    assert!(records[3].groups[4].span.is_some());
    assert_eq!(records[0].groups[1].name.as_deref(), Some("head"));
    assert_eq!(records[0].groups[2].name.as_deref(), Some("tail"));
    assert_eq!(records[0].groups[3].name.as_deref(), Some("other"));
}

#[test]
fn public_bibleref_short_has_exact_direct_counters_and_records() {
    assert_eq!(PUBLIC_BIBLEREF_PATTERN.len(), 216);
    assert_eq!(PUBLIC_BIBLEREF_HAYSTACK.len(), 43);
    let regex = CaptureBuilder::new(PUBLIC_BIBLEREF_PATTERN)
        .build()
        .expect("public bibleref capture regex");
    let limits = CaptureAggregateLimits::default();
    let incumbent = regex
        .captures_iter(PUBLIC_BIBLEREF_HAYSTACK, limits)
        .expect("public History authority");
    let mut session = regex
        .prepare_captures_iter_bounded_backtrack(PUBLIC_BIBLEREF_HAYSTACK.len(), limits)
        .expect("public workspace allocation")
        .expect("public bounded-backtracking selection");
    let preparation = session.preparation_receipt();
    let direct = regex
        .captures_iter_bounded_backtrack(&mut session, PUBLIC_BIBLEREF_HAYSTACK, limits)
        .expect("public direct operation")
        .expect("public direct selection");

    assert_eq!(direct.captures, incumbent.captures);
    assert!(direct.has_closed_attempt());
    assert_eq!(
        (
            direct.actual.searches,
            direct.actual.materialized_records,
            direct.actual.results,
            direct.actual.capture_events,
            direct.capture_count,
        ),
        (4, 3, 3, 45, 30)
    );
    assert_eq!(
        (
            direct.actual.total_state_visits,
            direct.actual.total_slot_copies,
            direct.actual.bytes_examined,
            direct.actual.starts_injected,
            direct.actual.peak_threads,
        ),
        (881, 112, 333, 4, 54)
    );
    assert_eq!(direct.actual.total_history_nodes, 0);
    assert_eq!(direct.actual.total_history_walk, 0);
    assert_eq!(
        direct.actual.scratch_bytes,
        preparation.usage.admitted_scratch_bytes
    );
    assert_eq!(
        direct.actual.retained_output_bytes,
        incumbent.retained_output_bytes
    );
    assert_eq!(
        direct.actual.combined_peak_bytes,
        direct.actual.retained_output_bytes + preparation.persistent_bytes
    );
    assert!(preparation.persistent_bytes > preparation.usage.persistent_bytes);
    assert_eq!(preparation.setup_allocations, 3);
    assert_eq!(direct.attempt_receipt.operation_setup_allocations, 0);
}

#[test]
fn preparation_declines_every_source_free_ineligible_or_underprovisioned_case() {
    let limits = CaptureAggregateLimits::default();
    let nullable = CaptureBuilder::new(r"(a*)")
        .unicode(false)
        .build()
        .expect("nullable capture regex");
    assert!(
        nullable
            .prepare_captures_iter_bounded_backtrack(8, limits)
            .expect("nullable preparation is source-free")
            .is_none()
    );

    let absolute = CaptureBuilder::new(r"\A(?P<value>a+)")
        .unicode(false)
        .build()
        .expect("absolute-start capture regex");
    assert!(
        absolute
            .iteration_identity(limits)
            .session_seal
            .route_identity()
            .absolute_onepass
            .is_some()
    );
    assert!(
        absolute
            .prepare_captures_iter_bounded_backtrack(8, limits)
            .expect("absolute-start preparation is source-free")
            .is_none()
    );

    let regex = ambiguous_regex();
    assert!(
        regex
            .prepare_captures_iter_bounded_backtrack(
                CAPTURE_BOUNDED_BACKTRACK_ITERATION_MAX_SEARCH_BYTES + 1,
                limits,
            )
            .expect("over-cap preparation is source-free")
            .is_none()
    );

    let incumbent = regex
        .captures_iter(AMBIGUOUS_HAYSTACK, limits)
        .expect("History prospective authority");
    let incumbent_prospective = incumbent
        .session_receipt
        .prospective
        .expect("History prospective")
        .engine;
    assert!(incumbent_prospective.total_history_nodes > 0);
    let old_refusal = CaptureAggregateLimits {
        max_total_history_nodes: incumbent_prospective.total_history_nodes - 1,
        ..limits
    };
    assert!(
        regex
            .prepare_captures_iter_bounded_backtrack(AMBIGUOUS_HAYSTACK.len(), old_refusal)
            .expect("old refusal remains source-free")
            .is_none()
    );

    let mut baseline_session = regex
        .prepare_captures_iter_bounded_backtrack(AMBIGUOUS_HAYSTACK.len(), limits)
        .expect("baseline workspace allocation")
        .expect("baseline direct preparation");
    let baseline = regex
        .captures_iter_bounded_backtrack(&mut baseline_session, AMBIGUOUS_HAYSTACK, limits)
        .expect("baseline direct operation")
        .expect("baseline direct selection");
    assert!(baseline.prospective.largest_search.slot_copies > 0);
    let slot_one_below = CaptureAggregateLimits {
        per_search: CaptureSearchLimits {
            max_slot_copies: baseline.prospective.largest_search.slot_copies - 1,
            ..limits.per_search
        },
        ..limits
    };
    assert!(
        regex
            .prepare_captures_iter_bounded_backtrack(AMBIGUOUS_HAYSTACK.len(), slot_one_below,)
            .expect("slot refusal remains source-free")
            .is_none()
    );
    let combined_one_below = CaptureAggregateLimits {
        max_combined_peak_bytes: baseline.prospective.combined_peak_bytes - 1,
        ..limits
    };
    assert!(
        regex
            .prepare_captures_iter_bounded_backtrack(AMBIGUOUS_HAYSTACK.len(), combined_one_below,)
            .expect("combined-peak refusal remains source-free")
            .is_none()
    );
}

#[test]
fn foreign_or_mismatched_session_invocation_refuses_before_selection() {
    let limits = CaptureAggregateLimits::default();
    let regex = ambiguous_regex();
    let foreign = ambiguous_regex();
    let mut session = regex
        .prepare_captures_iter_bounded_backtrack(AMBIGUOUS_HAYSTACK.len(), limits)
        .expect("workspace allocation")
        .expect("direct preparation");

    assert!(
        foreign
            .captures_iter_bounded_backtrack(&mut session, AMBIGUOUS_HAYSTACK, limits)
            .expect("foreign invocation refuses without a selected fault")
            .is_none()
    );
    let longer = [AMBIGUOUS_HAYSTACK, b"x"].concat();
    assert!(
        regex
            .captures_iter_bounded_backtrack(&mut session, &longer, limits)
            .expect("over-width invocation refuses without a selected fault")
            .is_none()
    );
    let mismatched_limits = CaptureAggregateLimits {
        max_searches: limits.max_searches - 1,
        ..limits
    };
    assert!(
        regex
            .captures_iter_bounded_backtrack(&mut session, AMBIGUOUS_HAYSTACK, mismatched_limits,)
            .expect("mismatched limits refuse without a selected fault")
            .is_none()
    );

    let selected = regex
        .captures_iter_bounded_backtrack(&mut session, AMBIGUOUS_HAYSTACK, limits)
        .expect("matching invocation remains usable")
        .expect("matching invocation selects direct");
    assert!(selected.has_closed_attempt());
}
