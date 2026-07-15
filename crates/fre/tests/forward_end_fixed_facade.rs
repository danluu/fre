#![forbid(unsafe_code)]

use fre::{
    BuildLimits, CaptureFreeOperation, PlanKind, PlanSelection, PortableBuilder, RustProfile,
    SearchAccounting, SearchLimits, SearchWindow,
};

const FIXED_ID: &str = "anchored-class-suffix.absolute-end-fixed-suffix-first-bitset.v1";
const ES8I_ID: &str = "anchored-class-suffix.asymmetric-scalar8-reverse32-inline.v1";

fn forced(pattern: &str) -> fre::PortableRegex {
    PortableBuilder::new(pattern)
        .unicode(false)
        .plan_selection(PlanSelection::ForceForwardAnchored)
        .build()
        .unwrap()
}

#[test]
fn red_forced_both_end_is_fixed_while_start_only_and_auto_stay_old() {
    let both = forced(r"\A[ab]+Z\z");
    let start_only = forced(r"\A[ab]+Z");
    let auto_both = PortableBuilder::new(r"\A[ab]+Z\z")
        .unicode(false)
        .build()
        .unwrap();
    let auto_start = PortableBuilder::new(r"\A[ab]+Z")
        .unicode(false)
        .build()
        .unwrap();

    assert_eq!(both.build_report().plan, PlanKind::ForwardAnchored);
    assert_eq!(both.runtime_implementation_id(), FIXED_ID);
    assert_eq!(start_only.runtime_implementation_id(), ES8I_ID);
    assert_eq!(auto_both.runtime_implementation_id(), ES8I_ID);
    assert_eq!(auto_start.runtime_implementation_id(), ES8I_ID);

    assert_eq!(
        start_only
            .find(b"aZx", SearchLimits::unlimited())
            .unwrap()
            .0
            .map(|matched| (matched.start(), matched.end())),
        Some((0, 2))
    );
}

#[test]
fn red_facade_projects_the_fixed_span_and_preserves_absolute_windows() {
    let regex = forced(r"\A[ab]+ZQ\z");
    let haystack = b"aabZQ";
    assert!(
        regex
            .is_match(haystack, SearchLimits::unlimited())
            .unwrap()
            .0
    );
    assert_eq!(
        regex
            .selected_end(haystack, SearchLimits::unlimited())
            .unwrap()
            .0,
        Some(haystack.len())
    );
    assert_eq!(
        regex
            .find(haystack, SearchLimits::unlimited())
            .unwrap()
            .0
            .map(|matched| (matched.start(), matched.end())),
        Some((0, haystack.len()))
    );

    for (bytes, window) in [
        (b"aaZQx".as_slice(), SearchWindow::new(0, 4)),
        (b"xaaZQ".as_slice(), SearchWindow::new(1, 5)),
    ] {
        let (matched, accounting) = regex
            .find_window(bytes, window, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(matched, None);
        let SearchAccounting::ForwardAnchored(accounting) = accounting else {
            panic!("forced fixed route lost forward accounting")
        };
        assert_eq!(accounting.examined_bytes_upper_bound, 0);
        assert_eq!(accounting.work_upper_bound, 0);
        assert_eq!(accounting.prefilter_calls, 0);
        assert_eq!(accounting.prefix_bytes_examined, 0);
    }
}

#[test]
fn red_build_report_runtime_and_cache_identity_all_come_from_fixed_plan() {
    let regex = forced(r"\A[aceg]+ZQ\z");
    let report = regex.build_report();
    let build = report.forward_anchored.unwrap();
    assert_eq!(report.plan, PlanKind::ForwardAnchored);
    assert_eq!(report.plan_storage_bytes, build.persistent_bytes);
    assert_eq!(regex.runtime_implementation_id(), FIXED_ID);
    assert_eq!(
        build.implementation,
        fre_kernels::ForwardClassImplementation::Bitset
    );

    let limits = SearchLimits {
        max_work: 917,
        max_scratch_bytes: 0,
    };
    let identity = regex
        .forward_anchored_cache_identity(CaptureFreeOperation::Span, limits)
        .unwrap();
    assert_eq!(identity.plan_id, FIXED_ID);
    assert_eq!(identity.anchors.start, true);
    assert_eq!(identity.anchors.end, true);
    assert_eq!(
        identity.class_words,
        fre_kernels::ForwardAnchoredByteClass::from_bytes(b"aceg").words()
    );
    assert_eq!(identity.suffix, b"ZQ");
    assert_eq!(
        identity.implementation,
        fre_kernels::ForwardClassImplementation::Bitset
    );
    assert_eq!(identity.build_limits, BuildLimits::default());
    assert_eq!(identity.search_limits, limits);
    assert_eq!(
        identity,
        regex
            .forward_anchored_cache_identity(CaptureFreeOperation::Span, limits)
            .unwrap()
    );
    assert_eq!(regex.runtime_implementation_id(), FIXED_ID);
}

#[test]
fn red_cache_key_equality_retains_every_required_field() {
    let limits = SearchLimits {
        max_work: 1234,
        max_scratch_bytes: 0,
    };
    let regex = forced(r"\A[aceg]+ZQ\z");
    let key = regex
        .forward_anchored_cache_identity(CaptureFreeOperation::Span, limits)
        .unwrap();

    let mut changed = key.clone();
    changed.schema_version = changed.schema_version.wrapping_add(1);
    assert_ne!(key, changed);
    let mut changed = key.clone();
    changed.plan_id = ES8I_ID;
    assert_ne!(key, changed);
    let mut changed = key.clone();
    changed.operation = CaptureFreeOperation::Exists;
    assert_ne!(key, changed);
    let mut changed = key.clone();
    changed.anchors.end = false;
    assert_ne!(key, changed);
    let mut changed = key.clone();
    changed.class_words[0] ^= 1;
    assert_ne!(key, changed);
    let mut changed = key.clone();
    changed.suffix.push(b'!');
    assert_ne!(key, changed);
    let mut changed = key.clone();
    changed.implementation = fre_kernels::ForwardClassImplementation::Pair {
        first: b'a',
        second: b'b',
    };
    assert_ne!(key, changed);
    let mut changed = key.clone();
    changed.build_limits.max_planner_work -= 1;
    assert_ne!(key, changed);
    let mut changed = key.clone();
    changed.search_limits.max_work -= 1;
    assert_ne!(key, changed);

    let mut alternate_profile = RustProfile::default();
    alternate_profile.options.octal = true;
    let profile_key = PortableBuilder::new(r"\A[aceg]+ZQ\z")
        .profile(alternate_profile)
        .unicode(false)
        .plan_selection(PlanSelection::ForceForwardAnchored)
        .build()
        .unwrap()
        .forward_anchored_cache_identity(CaptureFreeOperation::Span, limits)
        .unwrap();
    assert_ne!(key, profile_key);
}

#[test]
fn red_suffix_mismatch_has_fixed_upper_bounds_and_no_prefix_examinations() {
    let regex = forced(r"\A[ab]+ZQX\z");
    for offset in 0..3 {
        let mut haystack = b"abZQX".to_vec();
        haystack[2 + offset] ^= 0x20;
        let (matched, accounting) = regex.find(&haystack, SearchLimits::unlimited()).unwrap();
        assert_eq!(matched, None, "offset={offset}");
        let SearchAccounting::ForwardAnchored(accounting) = accounting else {
            panic!("forced fixed route lost forward accounting")
        };
        assert_eq!(accounting.prefilter_bytes_upper_bound, 0);
        assert_eq!(accounting.prefix_bytes_upper_bound, 2);
        assert_eq!(accounting.suffix_bytes_upper_bound, 3);
        assert_eq!(accounting.examined_bytes_upper_bound, haystack.len());
        assert_eq!(accounting.work_upper_bound, haystack.len() as u64);
        assert_eq!(accounting.prefilter_calls, 0);
        assert_eq!(accounting.prefix_bytes_examined, 0);
        assert!(accounting.suffix_confirmation_attempted);
    }
}
