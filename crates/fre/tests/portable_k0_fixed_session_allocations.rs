#![forbid(unsafe_code)]

use std::{alloc::System, sync::Mutex};

use fre::{
    PlanKind, PlanSelection, PortableBuilder, SearchAccounting, SearchLimits, SearchSessionLimits,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;
static ALLOCATION_TEST_LOCK: Mutex<()> = Mutex::new(());

const PATTERN: &str = r"(?-u:a?a?a?a?aaaaaaaaaa)";
const HAYSTACK: &[u8] = b"aaaaaaaaaaaaaa";

fn k0() -> fre::PortableRegex {
    let regex = PortableBuilder::new(PATTERN)
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("focused pattern builds through K0");
    assert_eq!(regex.build_report().plan, PlanKind::K0);
    regex
}

fn assert_match_without_growth(matched: Option<fre::Match>, accounting: &SearchAccounting) {
    assert_eq!(
        matched.map(|matched| (matched.start(), matched.end())),
        Some((0, 14)),
    );
    let growth = accounting
        .cache_growth()
        .expect("forced K0 search exposes cache-growth accounting");
    assert_eq!(growth.events(), 0);
    assert_eq!(growth.allocated_bytes(), 0);
    assert_eq!(growth.initialized_bytes(), 0);
    assert_eq!(growth.retained_delta(), 0);
    assert_eq!(growth.peak_scratch_bytes(), 0);
}

#[test]
fn fixed_searches_and_seed_capped_saturation_preserve_zero_allocation_semantics() {
    let _guard = ALLOCATION_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let limits = SearchLimits::unlimited();
    let session_limits = SearchSessionLimits::default();

    // Explicit source-free preparation puts the optional immutable proof in
    // the same setup boundary as the fixed workspace. Its exact owner receipt
    // remains separate because that owner belongs to the regex, not session.
    let fixed_regex = k0();
    let mut fixed = fixed_regex
        .fixed_search_session(session_limits)
        .expect("fixed K0 session constructs");
    let proof_region = Region::new(GLOBAL);
    let proof = fixed
        .prepare_k0_start_filter(SearchSessionLimits::unlimited())
        .expect("source-free plan-proof preparation succeeds")
        .expect("forced K0 has a preparation receipt");
    let proof_allocations = proof_region.change();
    assert!(proof.work_completed() > 0);
    assert!(proof.newly_retained_owner_bytes() > 0);
    assert_eq!(proof.retained_owner_bytes(), proof.newly_retained_owner_bytes());
    assert!(proof_allocations.allocations > 0);
    assert!(proof_allocations.bytes_allocated >= proof.newly_retained_owner_bytes());
    let fixed_region = Region::new(GLOBAL);
    for _ in 0..16 {
        let (matched, accounting) = fixed.find(HAYSTACK, limits).expect("fixed search succeeds");
        assert_match_without_growth(matched, &accounting);
    }
    assert_eq!(fixed_region.change(), Stats::default());

    // A per-call cap at a fresh adaptive seed's live payload refuses every
    // attempted growth transaction. Saturation remains a performance fallback:
    // the selected value is unchanged, no allocation escapes the cap, and a
    // later unlimited call can still grow normally.
    let saturated_regex = k0();
    let mut saturated = saturated_regex
        .search_session(session_limits)
        .expect("fresh saturation fixture constructs");
    saturated
        .prepare_k0_start_filter(SearchSessionLimits::unlimited())
        .expect("saturation plan-proof preparation succeeds");
    let seed = saturated
        .workspace_setup_accounting()
        .expect("saturation setup accounting");
    let saturated_limits = SearchLimits {
        max_work: u64::MAX,
        max_scratch_bytes: seed.retained_bytes(),
    };
    let saturated_region = Region::new(GLOBAL);
    let (matched, accounting) = saturated
        .find(HAYSTACK, saturated_limits)
        .expect("growth refusal falls back semantically");
    assert_match_without_growth(matched, &accounting);
    assert_eq!(saturated_region.change(), Stats::default());

    let retry_region = Region::new(GLOBAL);
    let (matched, accounting) = saturated
        .find(HAYSTACK, limits)
        .expect("unlimited retry can grow after saturation");
    assert_eq!(
        matched.map(|matched| (matched.start(), matched.end())),
        Some((0, 14)),
    );
    let retry_growth = accounting.cache_growth().unwrap();
    assert!(retry_growth.events() > 0);
    assert!(retry_region.change().allocations > 0);
}

#[test]
fn explicit_start_filter_preparation_residualizes_total_setup_work() {
    let _guard = ALLOCATION_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let regex = k0();
    let mut fixed = regex
        .fixed_search_session(SearchSessionLimits::unlimited())
        .expect("fixed K0 session constructs");
    let setup = fixed
        .workspace_setup_accounting()
        .expect("forced K0 setup accounting");

    let one_below = setup.work().checked_sub(1).expect("nonzero setup work");
    let error = fixed
        .prepare_k0_start_filter(SearchSessionLimits {
            max_setup_work: one_below,
            max_scratch_bytes: usize::MAX,
        })
        .expect_err("a total cap below completed workspace setup must refuse");
    assert!(matches!(error, fre::SearchError::K0(_)));

    let declined = fixed
        .prepare_k0_start_filter(SearchSessionLimits {
            max_setup_work: setup.work(),
            max_scratch_bytes: usize::MAX,
        })
        .expect("an exact workspace-only cap settles ordinary K0")
        .expect("forced K0 has a preparation receipt");
    assert!(declined.cap_declined());
    assert_eq!(declined.work_completed(), 0);
    assert_eq!(declined.retained_owner_bytes(), 0);

    let first_source = Region::new(GLOBAL);
    let (matched, accounting) = fixed
        .find(HAYSTACK, SearchLimits::unlimited())
        .expect("cap-declined ordinary K0 remains complete");
    assert_match_without_growth(matched, &accounting);
    assert_eq!(first_source.change(), Stats::default());
}

#[test]
fn explicit_start_filter_preparation_enforces_exact_aggregate_scratch() {
    let _guard = ALLOCATION_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let probe_regex = k0();
    let mut probe = probe_regex
        .fixed_search_session(SearchSessionLimits::unlimited())
        .expect("proof-payload probe session constructs");
    let probe_receipt = probe
        .prepare_k0_start_filter(SearchSessionLimits::unlimited())
        .expect("proof-payload probe prepares")
        .expect("forced K0 has a preparation receipt");
    let proof_bytes = probe_receipt.newly_retained_owner_bytes();
    assert!(proof_bytes > 0);

    let declined_regex = k0();
    let mut declined = declined_regex
        .fixed_search_session(SearchSessionLimits::unlimited())
        .expect("one-below session constructs");
    let declined_setup = declined.workspace_setup_accounting().unwrap();
    let exact_scratch = declined_setup
        .retained_bytes()
        .checked_add(proof_bytes)
        .expect("aggregate scratch fits");
    let one_below = exact_scratch.checked_sub(1).expect("nonzero aggregate scratch");
    let declined_receipt = declined
        .prepare_k0_start_filter(SearchSessionLimits {
            max_setup_work: u64::MAX,
            max_scratch_bytes: one_below,
        })
        .expect("one-below scratch selects ordinary K0")
        .expect("forced K0 has a preparation receipt");
    assert!(declined_receipt.cap_declined());
    assert_eq!(declined_receipt.newly_retained_owner_bytes(), 0);
    assert_eq!(declined_receipt.retained_owner_bytes(), 0);
    assert_eq!(
        declined_receipt.aggregate_retained_bytes(),
        declined_setup.retained_bytes()
    );

    let exact_regex = k0();
    let mut exact = exact_regex
        .fixed_search_session(SearchSessionLimits::unlimited())
        .expect("exact session constructs");
    let exact_setup = exact.workspace_setup_accounting().unwrap();
    assert_eq!(exact_setup.retained_bytes(), declined_setup.retained_bytes());
    let exact_receipt = exact
        .prepare_k0_start_filter(SearchSessionLimits {
            max_setup_work: u64::MAX,
            max_scratch_bytes: exact_scratch,
        })
        .expect("exact aggregate scratch admits proof")
        .expect("forced K0 has a preparation receipt");
    assert!(!exact_receipt.cap_declined());
    assert_eq!(exact_receipt.newly_retained_owner_bytes(), proof_bytes);
    assert_eq!(exact_receipt.retained_owner_bytes(), proof_bytes);
    assert_eq!(exact_receipt.aggregate_retained_bytes(), exact_scratch);
}
