#![forbid(unsafe_code)]

use fre::{BuildError, BuildLimits, PlanKind, PlanSelection, PortableBuilder};

fn plan_cases() -> Vec<(&'static str, PortableBuilder, PlanKind)> {
    let dfa_limits = BuildLimits {
        packed_literal_set: fre_kernels::PackedLiteralSetBuildLimits {
            max_patterns: 0,
            ..fre_kernels::PackedLiteralSetBuildLimits::default()
        },
        ..BuildLimits::default()
    };
    vec![
        (
            "exact literal",
            PortableBuilder::new("(?P<literal>Sherlock)").unicode(false),
            PlanKind::ExactLiteral,
        ),
        (
            "packed literal set",
            PortableBuilder::new("a|ab").unicode(false),
            PlanKind::PackedLiteralSet,
        ),
        (
            "literal set DFA",
            PortableBuilder::new("foobar|foobaz|fooquux")
                .unicode(false)
                .limits(dfa_limits),
            PlanKind::LiteralSetDfa,
        ),
        (
            "required literal",
            PortableBuilder::new("[a-z]+Z").unicode(false),
            PlanKind::RequiredLiteral,
        ),
        (
            "forward anchored",
            PortableBuilder::new(r"\A[a-z]+Z").unicode(false),
            PlanKind::ForwardAnchored,
        ),
        (
            "forward fixed end",
            PortableBuilder::new(r"\A[a-z]+Z\z")
                .unicode(false)
                .plan_selection(PlanSelection::ForceForwardAnchored),
            PlanKind::ForwardAnchored,
        ),
        (
            "Unicode word run",
            PortableBuilder::new(r"\b\w{2,}\b"),
            PlanKind::UnicodeWordRun,
        ),
        (
            "forced K0",
            PortableBuilder::new("Sherlock")
                .unicode(false)
                .plan_selection(PlanSelection::ForceK0),
            PlanKind::K0,
        ),
    ]
}

#[test]
fn total_persistent_limit_is_exact_across_every_portable_plan() {
    for (name, builder, expected_plan) in plan_cases() {
        let probe = builder
            .clone()
            .build()
            .unwrap_or_else(|error| panic!("failed to build {name} probe: {error}"));
        let report = probe.build_report();
        assert_eq!(report.plan, expected_plan, "{name}");
        let needed = report
            .source_storage_bytes
            .checked_add(report.capture_name_storage_bytes)
            .and_then(|bytes| bytes.checked_add(report.plan_storage_bytes))
            .expect("small test accounting fits usize");
        assert!(needed > 0, "{name}");
        assert_eq!(report.charged_persistent_bytes, needed, "{name}");
        assert_eq!(
            report.persistent_byte_limit,
            BuildLimits::default().max_persistent_bytes,
            "{name}"
        );

        let exact = builder
            .clone()
            .max_persistent_bytes(needed)
            .build()
            .unwrap_or_else(|error| panic!("exact persistent limit rejected {name}: {error}"));
        assert_eq!(
            exact.build_report().charged_persistent_bytes,
            needed,
            "{name}"
        );
        assert_eq!(exact.build_report().persistent_byte_limit, needed, "{name}");

        let cloned = exact.clone();
        assert_eq!(cloned.build_report(), exact.build_report(), "{name}");

        let error = builder
            .max_persistent_bytes(needed - 1)
            .build()
            .unwrap_err();
        assert!(
            matches!(
                error,
                BuildError::PersistentBytesLimit {
                    needed: actual_needed,
                    limit,
                } if actual_needed == needed && limit == needed - 1
            ),
            "unexpected one-below refusal for {name}: {error}"
        );
    }
}

#[test]
fn automatic_k0_optional_persistent_refusal_preserves_the_mandatory_plan() {
    let builder = PortableBuilder::new("^a+$")
        .unicode(false)
        .multi_line(true)
        .line_terminator(b'\r');
    let probe = builder.clone().build().expect("automatic K0 probe");
    assert_eq!(probe.build_report().plan, PlanKind::K0);
    let admitted_bytes = probe.build_report().charged_persistent_bytes;

    let exact = builder
        .clone()
        .max_persistent_bytes(admitted_bytes)
        .build()
        .expect("exact automatic K0 sidecar boundary");
    assert_eq!(exact.build_report().charged_persistent_bytes, admitted_bytes);

    let declined_limit = admitted_bytes.checked_sub(1).unwrap();
    let declined = builder
        .clone()
        .max_persistent_bytes(declined_limit)
        .build()
        .expect("optional automatic K0 sidecar refusal");
    assert_eq!(declined.build_report().plan, PlanKind::K0);
    assert!(declined.build_report().charged_persistent_bytes <= declined_limit);
    assert!(
        declined.build_report().plan_storage_bytes < exact.build_report().plan_storage_bytes
    );

    let mandatory_probe = builder
        .clone()
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("mandatory K0 probe");
    let mandatory_bytes = mandatory_probe.build_report().charged_persistent_bytes;
    assert!(mandatory_bytes < admitted_bytes);

    let mandatory_exact = builder
        .clone()
        .max_persistent_bytes(mandatory_bytes)
        .build()
        .expect("exact mandatory automatic K0 boundary");
    assert_eq!(mandatory_exact.build_report().plan, PlanKind::K0);
    assert_eq!(
        mandatory_exact.build_report().charged_persistent_bytes,
        mandatory_bytes
    );
    assert_eq!(
        mandatory_exact.build_report().plan_storage_bytes,
        mandatory_probe.build_report().plan_storage_bytes
    );
    let error = builder
        .max_persistent_bytes(mandatory_bytes.checked_sub(1).unwrap())
        .build()
        .expect_err("one-below mandatory automatic K0 storage must fail");
    assert!(matches!(
        error,
        BuildError::PersistentBytesLimit {
            needed,
            limit,
        } if needed == mandatory_bytes && limit == mandatory_bytes - 1
    ));
}

#[test]
fn folded_plan_persistent_refusal_falls_through_without_exceeding_the_total_limit() {
    let builder = PortableBuilder::new("Шерлок Холмс").case_insensitive(true);
    let probe = builder.clone().build().unwrap();
    assert_eq!(probe.build_report().plan, PlanKind::UnicodeFoldedLiteral);
    let needed = probe.build_report().charged_persistent_bytes;

    let exact = builder
        .clone()
        .max_persistent_bytes(needed)
        .build()
        .unwrap();
    assert_eq!(exact.build_report().plan, PlanKind::UnicodeFoldedLiteral);
    assert_eq!(exact.build_report().charged_persistent_bytes, needed);

    let below = builder
        .max_persistent_bytes(needed.checked_sub(1).unwrap())
        .build()
        .unwrap();
    assert_ne!(below.build_report().plan, PlanKind::UnicodeFoldedLiteral);
    assert!(
        below.build_report().charged_persistent_bytes <= below.build_report().persistent_byte_limit
    );
}

#[test]
fn source_and_capture_names_are_not_hidden_from_the_total_limit() {
    let plain = PortableBuilder::new("Sherlock")
        .unicode(false)
        .build()
        .expect("plain exact literal");
    let named = PortableBuilder::new("(?P<detective>Sherlock)")
        .unicode(false)
        .build()
        .expect("named exact literal");

    assert!(plain.build_report().capture_name_storage_bytes > 0);
    assert!(
        named.build_report().capture_name_storage_bytes
            > plain.build_report().capture_name_storage_bytes
    );
    assert!(
        named.build_report().charged_persistent_bytes
            > plain.build_report().charged_persistent_bytes
    );

    let needed = named.build_report().charged_persistent_bytes;
    let error = PortableBuilder::new("(?P<detective>Sherlock)")
        .unicode(false)
        .max_persistent_bytes(needed - 1)
        .build()
        .expect_err("capture-name bytes must participate in admission");
    assert!(matches!(
        error,
        BuildError::PersistentBytesLimit {
            needed: actual_needed,
            limit,
        } if actual_needed == needed && limit == needed - 1
    ));
}
