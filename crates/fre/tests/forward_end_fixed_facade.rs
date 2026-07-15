#![forbid(unsafe_code)]

use fre::{
    BuildError, BuildLimits, CaptureFreeOperation, PlanKind, PlanSelection, PortableBuilder,
    RustProfile, SearchAccounting, SearchLimits, SearchWindow,
};
use std::fmt::Write as _;

const FIXED_ID: &str = "anchored-class-suffix.absolute-end-fixed-suffix-first-hybrid.v2";
const ES8I_ID: &str =
    "anchored-class-suffix.equality5-isolated-asymmetric-scalar8-reverse32-inline.v3";

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
        fre_kernels::ForwardClassImplementation::Quad {
            first: b'a',
            second: b'c',
            third: b'e',
            fourth: b'g',
        }
    );

    let limits = SearchLimits {
        max_work: 917,
        max_scratch_bytes: 0,
    };
    let identity = regex
        .forward_anchored_cache_identity(CaptureFreeOperation::Span, limits)
        .unwrap();
    assert_eq!(identity.plan_id, FIXED_ID);
    assert!(identity.anchors.start);
    assert!(identity.anchors.end);
    assert_eq!(
        identity.class_words,
        fre_kernels::ForwardAnchoredByteClass::from_bytes(b"aceg").words()
    );
    assert_eq!(identity.suffix, b"ZQ");
    assert_eq!(
        identity.implementation,
        fre_kernels::ForwardClassImplementation::Quad {
            first: b'a',
            second: b'c',
            third: b'e',
            fourth: b'g',
        }
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
    changed.anchors.start = false;
    assert_ne!(key, changed);
    for word in 0..4 {
        let mut changed = key.clone();
        changed.class_words[word] ^= 1;
        assert_ne!(key, changed, "class word={word}");
    }
    let mut changed = key.clone();
    changed.suffix.push(b'!');
    assert_ne!(key, changed);
    let mut changed = key.clone();
    changed.implementation = fre_kernels::ForwardClassImplementation::Pair {
        first: b'a',
        second: b'b',
    };
    assert_ne!(key, changed);
    for field in 0..6 {
        let mut changed = key.clone();
        match field {
            0 => changed.build_limits.forward_anchored.max_suffix_bytes -= 1,
            1 => changed.build_limits.forward_anchored.max_build_work -= 1,
            2 => changed.build_limits.forward_anchored.max_scratch_bytes += 1,
            3 => changed.build_limits.forward_anchored.max_persistent_bytes -= 1,
            4 => changed.build_limits.forward_anchored.max_peak_bytes -= 1,
            5 => changed.build_limits.max_planner_work -= 1,
            _ => unreachable!(),
        }
        assert_ne!(key, changed, "build field={field}");
    }
    for field in 0..2 {
        let mut changed = key.clone();
        match field {
            0 => changed.search_limits.max_work -= 1,
            1 => changed.search_limits.max_scratch_bytes += 1,
            _ => unreachable!(),
        }
        assert_ne!(key, changed, "search field={field}");
    }

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

    for option in 0..9 {
        let mut profile = RustProfile::default();
        match option {
            0 => profile.options.case_insensitive = true,
            1 => profile.options.multi_line = true,
            2 => profile.options.dot_matches_new_line = true,
            3 => profile.options.crlf = true,
            4 => profile.options.line_terminator = b'\r',
            5 => profile.options.swap_greed = true,
            6 => profile.options.ignore_whitespace = true,
            7 => profile.options.octal = true,
            8 => profile.options.nest_limit += 1,
            _ => unreachable!(),
        }
        profile.options.unicode = false;
        let alternate = PortableBuilder::new(r"(?-ix:\A[aceg]+ZQ\z)")
            .profile(profile)
            .plan_selection(PlanSelection::ForceForwardAnchored)
            .build()
            .unwrap()
            .forward_anchored_cache_identity(CaptureFreeOperation::Span, limits)
            .unwrap();
        assert_ne!(key, alternate, "profile option={option}");
    }
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
        assert_eq!(
            accounting.work_upper_bound,
            u64::try_from(haystack.len()).unwrap()
        );
        assert_eq!(accounting.prefilter_calls, 0);
        assert_eq!(accounting.prefix_bytes_examined, 0);
        assert!(accounting.suffix_confirmation_attempted);
    }
}

#[test]
fn fixed_facade_caps_and_semantic_refusals_never_fallback() {
    let pattern = r"\A[ab]+Zborderedaba\z";
    let baseline = forced(pattern);
    let accounting = baseline.build_report().forward_anchored.unwrap();
    let exact_kernel = fre_kernels::ForwardAnchoredBuildLimits {
        max_suffix_bytes: accounting.suffix_bytes,
        max_build_work: accounting.work_upper_bound,
        max_scratch_bytes: accounting.scratch_bytes,
        max_persistent_bytes: accounting.persistent_bytes,
        max_peak_bytes: accounting.peak_bytes,
    };
    let exact = BuildLimits {
        forward_anchored: exact_kernel,
        ..BuildLimits::default()
    };
    assert!(
        PortableBuilder::new(pattern)
            .unicode(false)
            .limits(exact)
            .plan_selection(PlanSelection::ForceForwardAnchored)
            .build()
            .is_ok()
    );
    for limited in [
        fre_kernels::ForwardAnchoredBuildLimits {
            max_suffix_bytes: accounting.suffix_bytes - 1,
            ..exact_kernel
        },
        fre_kernels::ForwardAnchoredBuildLimits {
            max_build_work: accounting.work_upper_bound - 1,
            ..exact_kernel
        },
        fre_kernels::ForwardAnchoredBuildLimits {
            max_persistent_bytes: accounting.persistent_bytes - 1,
            ..exact_kernel
        },
        fre_kernels::ForwardAnchoredBuildLimits {
            max_peak_bytes: accounting.peak_bytes - 1,
            ..exact_kernel
        },
    ] {
        assert!(matches!(
            PortableBuilder::new(pattern)
                .unicode(false)
                .limits(BuildLimits {
                    forward_anchored: limited,
                    ..BuildLimits::default()
                })
                .plan_selection(PlanSelection::ForceForwardAnchored)
                .build(),
            Err(BuildError::ForwardAnchored(_))
        ));
    }
    assert!(matches!(
        PortableBuilder::new(r"\Aa+a\z")
            .unicode(false)
            .plan_selection(PlanSelection::ForceForwardAnchored)
            .build(),
        Err(BuildError::ForwardAnchored(
            fre_kernels::ForwardAnchoredBuildError::FirstSuffixByteInClass { byte: b'a' }
        ))
    ));
}

#[test]
fn fixed_facade_matches_pinned_rust_bytes_for_greedy_lazy_and_captures() {
    fn words(alphabet: &[u8], max_len: usize) -> Vec<Vec<u8>> {
        let mut all = vec![Vec::new()];
        let mut frontier = vec![Vec::new()];
        for _ in 0..max_len {
            let mut next = Vec::new();
            for prefix in &frontier {
                for &byte in alphabet {
                    let mut word = prefix.clone();
                    word.push(byte);
                    next.push(word);
                }
            }
            all.extend(next.iter().cloned());
            frontier = next;
        }
        all
    }

    fn pattern(class: &[u8], suffix: &[u8], lazy: bool, captured: bool) -> String {
        let mut pattern = if captured {
            String::from(r"(?-u:\A([")
        } else {
            String::from(r"(?-u:\A[")
        };
        for &byte in class {
            write!(pattern, r"\x{byte:02X}").unwrap();
        }
        pattern.push_str("]+");
        if lazy {
            pattern.push('?');
        }
        for &byte in suffix {
            write!(pattern, r"\x{byte:02X}").unwrap();
        }
        if captured {
            pattern.push_str(r")\z)");
        } else {
            pattern.push_str(r"\z)");
        }
        pattern
    }

    let alphabet = [0_u8, 1, 2];
    let haystacks = words(&alphabet, 5);
    let suffixes: Vec<Vec<u8>> = words(&alphabet, 2)
        .into_iter()
        .filter(|suffix| !suffix.is_empty())
        .collect();
    let mut span_comparisons = 0_usize;
    let mut projection_comparisons = 0_usize;
    for mask in 1_u8..8 {
        let class: Vec<u8> = alphabet
            .into_iter()
            .enumerate()
            .filter_map(|(bit, byte)| (mask & (1 << bit) != 0).then_some(byte))
            .collect();
        for suffix in &suffixes {
            if class.contains(&suffix[0]) {
                continue;
            }
            for lazy in [false, true] {
                for captured in [false, true] {
                    let pattern = pattern(&class, suffix, lazy, captured);
                    let fre = forced(&pattern);
                    let rust = regex::bytes::RegexBuilder::new(&pattern)
                        .unicode(false)
                        .build()
                        .unwrap();
                    assert_eq!(fre.runtime_implementation_id(), FIXED_ID);
                    for haystack in &haystacks {
                        let expected = rust
                            .find(haystack)
                            .map(|matched| (matched.start(), matched.end()));
                        let actual = fre
                            .find(haystack, SearchLimits::unlimited())
                            .unwrap()
                            .0
                            .map(|matched| (matched.start(), matched.end()));
                        assert_eq!(
                            actual, expected,
                            "pattern={pattern:?} haystack={haystack:?}"
                        );
                        assert_eq!(
                            fre.is_match(haystack, SearchLimits::unlimited()).unwrap().0,
                            expected.is_some()
                        );
                        assert_eq!(
                            fre.selected_end(haystack, SearchLimits::unlimited())
                                .unwrap()
                                .0,
                            expected.map(|(_, end)| end)
                        );
                        span_comparisons += 1;
                        projection_comparisons += 3;
                    }
                }
            }
        }
    }
    assert_eq!(span_comparisons, 52_416);
    assert_eq!(projection_comparisons, 157_248);
}
