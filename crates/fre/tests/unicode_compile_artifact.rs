use fre::{
    RustProfile, UnicodeCompileArtifactBuilder, UnicodeCompileBuildError,
    UnicodeCompileBuildLimits, UnicodeCompileResource,
};

fn build(pattern: &str) -> fre::UnicodeCompileArtifact {
    UnicodeCompileArtifactBuilder::new(pattern)
        .profile(RustProfile::rebar_1_12_4())
        .build()
        .unwrap_or_else(|error| panic!("Unicode compile artifact rejected {pattern:?}: {error}"))
}

#[test]
fn unicode_class_literal_and_line_shapes_are_complete_canonical_artifacts() {
    let cases = [
        r"[\u{80}-\u{7FF}]+",
        r"(?:é|水|😀)+",
        r"(?m:^\p{Greek}+$)",
    ];
    for pattern in cases {
        let artifact = build(pattern);
        assert!(artifact.report().artifact_bytes > 0);
        assert!(artifact.report().hir_nodes > 0);
        assert!(artifact.verify_complete().is_ok());
        let fre_syntax::CompatibilityProfile::RustBytes(profile) =
            &artifact.report().syntax_key.profile
        else {
            panic!("Unicode compile artifact retained another profile")
        };
        let mut expected_profile = RustProfile::rebar_1_12_4();
        expected_profile.options.unicode = true;
        assert_eq!(*profile, expected_profile);
        for scalar in artifact.scalar_encodings() {
            let encoded = scalar.as_bytes();
            let text = std::str::from_utf8(encoded).expect("canonical UTF-8 scalar");
            assert_eq!(text.chars().count(), 1);
            let mut roundtrip = [0_u8; 4];
            let width = text
                .chars()
                .next()
                .expect("one scalar")
                .encode_utf8(&mut roundtrip)
                .len();
            assert_eq!(encoded, &roundtrip[..width]);
        }
    }
}

#[test]
fn invalid_byte_capability_is_excluded_from_unicode_artifacts() {
    assert!(matches!(
        UnicodeCompileArtifactBuilder::new(r"(?-u:\xFF)")
            .profile(RustProfile::rebar_1_12_4())
            .build(),
        Err(
            UnicodeCompileBuildError::InvalidUtf8Literal
                | UnicodeCompileBuildError::InvalidByteClass
        )
    ));
    assert!(matches!(
        UnicodeCompileArtifactBuilder::new("α")
            .profile(RustProfile::regex_1_12_4())
            .build(),
        Err(UnicodeCompileBuildError::ProfileMismatch)
    ));
}

#[test]
fn exact_artifact_bytes_refuse_one_below_before_artifact_allocation() {
    let baseline = build(r"(?m:^\p{Greek}+$)");
    let needed = baseline.report().artifact_bytes;
    let limits = UnicodeCompileBuildLimits {
        max_artifact_bytes: needed - 1,
        ..UnicodeCompileBuildLimits::default()
    };
    assert!(matches!(
        UnicodeCompileArtifactBuilder::new(r"(?m:^\p{Greek}+$)")
            .profile(RustProfile::rebar_1_12_4())
            .limits(limits)
            .build(),
        Err(UnicodeCompileBuildError::ResourceLimit {
            resource: UnicodeCompileResource::ArtifactBytes,
            required,
            limit,
        }) if required == needed && limit == needed - 1
    ));
}

#[test]
fn one_scalar_mutation_changes_artifact_bytes_and_identity() {
    let alpha = build("α+");
    let beta = build("β+");
    assert_ne!(alpha.bytes(), beta.bytes());
    assert_ne!(alpha.report().artifact_id, beta.report().artifact_id);
}
