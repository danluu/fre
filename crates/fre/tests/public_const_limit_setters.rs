use fre::{
    BuildLimits, CompatibilityProfile, PortableBuilder, PortableRegexSetBuildLimits,
    PortableRegexSetBuilder, PortableTextBuilder, PortableTextRegexSetBuilder, RustProfile,
};
use fre_syntax::RustConstructor;

const fn portable_limits(builder: PortableBuilder, limits: BuildLimits) -> PortableBuilder {
    builder.limits(limits)
}

const fn portable_max_persistent_bytes(builder: PortableBuilder, bytes: usize) -> PortableBuilder {
    builder.max_persistent_bytes(bytes)
}

const fn byte_set_limits<'a>(
    builder: PortableRegexSetBuilder<'a>,
    limits: PortableRegexSetBuildLimits,
) -> PortableRegexSetBuilder<'a> {
    builder.limits(limits)
}

const fn text_limits(builder: PortableTextBuilder, limits: BuildLimits) -> PortableTextBuilder {
    builder.limits(limits)
}

const fn text_set_limits<'a>(
    builder: PortableTextRegexSetBuilder<'a>,
    limits: PortableRegexSetBuildLimits,
) -> PortableTextRegexSetBuilder<'a> {
    builder.limits(limits)
}

fn profile_size_limit(profile: &RustProfile) -> u64 {
    match profile.constructor {
        RustConstructor::RegexBuilder { size_limit, .. }
        | RustConstructor::RegexSetBuilder { size_limit, .. } => size_limit,
        RustConstructor::RebarMeta { .. } => panic!("expected a high-level Rust constructor"),
    }
}

fn compatibility_profile_size_limit(profile: &CompatibilityProfile) -> u64 {
    match profile {
        CompatibilityProfile::RustText(profile) | CompatibilityProfile::RustBytes(profile) => {
            profile_size_limit(profile)
        }
        CompatibilityProfile::Re2(_) => panic!("expected a Rust compatibility profile"),
    }
}

#[test]
fn public_limit_setters_remain_const_callable_and_synchronized() {
    const HIGH_LIMIT: usize = 16 * 1_048_576;
    let mut high_single = BuildLimits::default();
    high_single.max_persistent_bytes = HIGH_LIMIT;
    let mut low_single = high_single;
    low_single.max_persistent_bytes = 1;

    let portable = portable_limits(PortableBuilder::new("a").size_limit(1), high_single)
        .build()
        .expect("limits-last portable build");
    assert_eq!(HIGH_LIMIT, portable.build_report().persistent_byte_limit);
    assert_eq!(
        HIGH_LIMIT as u64,
        compatibility_profile_size_limit(&portable.build_report().profile)
    );

    let portable = portable_max_persistent_bytes(
        portable_limits(PortableBuilder::new("a"), low_single),
        HIGH_LIMIT,
    )
    .build()
    .expect("max-persistent-bytes-last portable build");
    assert_eq!(HIGH_LIMIT, portable.build_report().persistent_byte_limit);
    assert_eq!(
        HIGH_LIMIT as u64,
        compatibility_profile_size_limit(&portable.build_report().profile)
    );

    let text = text_limits(PortableTextBuilder::new("a").size_limit(1), high_single)
        .build()
        .expect("limits-last text build");
    assert_eq!(
        HIGH_LIMIT,
        text.build_report().portable.persistent_byte_limit
    );
    assert_eq!(
        HIGH_LIMIT as u64,
        compatibility_profile_size_limit(&text.build_report().profile)
    );

    let patterns = vec!["a".to_owned()];
    let mut high_set = PortableRegexSetBuildLimits::default();
    high_set.max_persistent_bytes = HIGH_LIMIT;
    let byte_set = byte_set_limits(
        PortableRegexSetBuilder::new(&patterns).size_limit(1),
        high_set,
    )
    .build()
    .expect("limits-last byte-set build");
    assert_eq!(
        HIGH_LIMIT,
        byte_set.build_report().limits.max_persistent_bytes
    );
    assert_eq!(
        HIGH_LIMIT as u64,
        profile_size_limit(&byte_set.build_report().profile)
    );

    let text_set = text_set_limits(
        PortableTextRegexSetBuilder::new(&patterns).size_limit(1),
        high_set,
    )
    .build()
    .expect("limits-last text-set build");
    assert_eq!(
        HIGH_LIMIT,
        text_set.build_report().limits.max_persistent_bytes
    );
    assert_eq!(
        HIGH_LIMIT as u64,
        profile_size_limit(&text_set.build_report().profile)
    );
}
