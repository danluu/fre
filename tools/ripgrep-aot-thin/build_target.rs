//! Pure target-feature selection shared by the build script and focused tests.

use std::ffi::OsStr;

use fre_aot_regex::{Architecture, CpuFeature, FeatureSet};

pub(crate) const CARGO_TARGET_FEATURE_ENV: &str = "CARGO_CFG_TARGET_FEATURE";
pub(crate) const FEATURES_ENV: &str = "FRE_RIPGREP_AOT_FEATURES";

/// Select the exact feature set made available to AOT lowering.
///
/// An explicit adapter feature list is authoritative, including an explicitly
/// empty list. Cargo's target features are consulted only when that override
/// is absent; unsupported Cargo vocabulary is intentionally ignored.
pub(crate) fn selected_features(
    architecture: Architecture,
    explicit: Option<&OsStr>,
    cargo: Option<&OsStr>,
) -> Result<FeatureSet, String> {
    if let Some(explicit) = explicit {
        let explicit = explicit
            .to_str()
            .ok_or_else(|| format!("{FEATURES_ENV} must be valid UTF-8"))?;
        return parse_explicit_features(explicit);
    }
    let cargo = cargo
        .map(|value| {
            value
                .to_str()
                .ok_or_else(|| format!("{CARGO_TARGET_FEATURE_ENV} must be valid UTF-8"))
        })
        .transpose()?
        .unwrap_or_default();
    Ok(parse_cargo_features(architecture, cargo))
}

fn parse_explicit_features(value: &str) -> Result<FeatureSet, String> {
    let mut features = FeatureSet::EMPTY;
    for name in value.split(',').filter(|name| !name.is_empty()) {
        let feature = match name {
            "sse2" => CpuFeature::X86Sse2,
            "avx2" => CpuFeature::X86Avx2,
            "avx512f" => CpuFeature::X86Avx512F,
            "avx512bw" => CpuFeature::X86Avx512Bw,
            "avx512vl" => CpuFeature::X86Avx512Vl,
            "asimd" => CpuFeature::Aarch64Asimd,
            "sve" => CpuFeature::Aarch64Sve,
            "sve2" => CpuFeature::Aarch64Sve2,
            _ => return Err(format!("unknown {FEATURES_ENV} value {name:?}")),
        };
        features = features.with(feature);
    }
    Ok(features)
}

fn parse_cargo_features(architecture: Architecture, value: &str) -> FeatureSet {
    let mut features = FeatureSet::EMPTY;
    for name in value.split(',') {
        let feature = match (architecture, name) {
            (Architecture::X86_64, "sse2") => Some(CpuFeature::X86Sse2),
            (Architecture::X86_64, "avx2") => Some(CpuFeature::X86Avx2),
            (Architecture::X86_64, "avx512f") => Some(CpuFeature::X86Avx512F),
            (Architecture::X86_64, "avx512bw") => Some(CpuFeature::X86Avx512Bw),
            (Architecture::X86_64, "avx512vl") => Some(CpuFeature::X86Avx512Vl),
            (Architecture::Aarch64, "neon") => Some(CpuFeature::Aarch64Asimd),
            (Architecture::Aarch64, "sve") => Some(CpuFeature::Aarch64Sve),
            (Architecture::Aarch64, "sve2") => Some(CpuFeature::Aarch64Sve2),
            _ => None,
        };
        if let Some(feature) = feature {
            features = features.with(feature);
        }
    }
    features
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bits(features: FeatureSet) -> u64 {
        features.bits()
    }

    #[test]
    fn cargo_maps_architecture_specific_baseline_vector_features() {
        let aarch64 = selected_features(
            Architecture::Aarch64,
            None,
            Some(OsStr::new("aes,neon,sha2")),
        )
        .expect("synthetic AArch64 Cargo features");
        assert_eq!(
            bits(aarch64),
            bits(FeatureSet::of(CpuFeature::Aarch64Asimd))
        );

        let x86 = selected_features(
            Architecture::X86_64,
            None,
            Some(OsStr::new("fxsr,sse,sse2,xsave")),
        )
        .expect("synthetic x86-64 Cargo features");
        assert_eq!(bits(x86), bits(FeatureSet::of(CpuFeature::X86Sse2)));
    }

    #[test]
    fn cargo_ignores_unknown_and_cross_architecture_features() {
        let features = selected_features(
            Architecture::Aarch64,
            None,
            Some(OsStr::new("future-extension,sse2,neon")),
        )
        .expect("unknown Cargo features are non-fatal");
        assert_eq!(
            bits(features),
            bits(FeatureSet::of(CpuFeature::Aarch64Asimd))
        );
    }

    #[test]
    fn absent_cargo_features_select_the_portable_scalar_target() {
        let features = selected_features(Architecture::Aarch64, None, None)
            .expect("absent Cargo target features");
        assert!(features.is_empty());
    }

    #[test]
    fn cargo_accumulates_every_supported_feature_for_only_its_architecture() {
        let cargo = OsStr::new("sse2,avx2,avx512f,avx512bw,avx512vl,neon,sve,sve2");
        let x86 = selected_features(Architecture::X86_64, None, Some(cargo))
            .expect("complete synthetic x86-64 Cargo feature list");
        let expected_x86 = FeatureSet::of(CpuFeature::X86Sse2)
            .with(CpuFeature::X86Avx2)
            .with(CpuFeature::X86Avx512F)
            .with(CpuFeature::X86Avx512Bw)
            .with(CpuFeature::X86Avx512Vl);
        assert_eq!(bits(x86), bits(expected_x86));

        let aarch64 = selected_features(Architecture::Aarch64, None, Some(cargo))
            .expect("complete synthetic AArch64 Cargo feature list");
        let expected_aarch64 = FeatureSet::of(CpuFeature::Aarch64Asimd)
            .with(CpuFeature::Aarch64Sve)
            .with(CpuFeature::Aarch64Sve2);
        assert_eq!(bits(aarch64), bits(expected_aarch64));
    }

    #[test]
    fn explicit_override_is_authoritative_including_empty_scalar() {
        let explicit = selected_features(
            Architecture::Aarch64,
            Some(OsStr::new("sve")),
            Some(OsStr::new("neon,sve2")),
        )
        .expect("explicit feature override");
        assert_eq!(
            bits(explicit),
            bits(FeatureSet::of(CpuFeature::Aarch64Sve))
        );

        let scalar = selected_features(
            Architecture::Aarch64,
            Some(OsStr::new("")),
            Some(OsStr::new("neon")),
        )
        .expect("explicit scalar override");
        assert!(scalar.is_empty());
    }

    #[test]
    fn explicit_override_rejects_unknown_vocabulary() {
        let error = selected_features(
            Architecture::X86_64,
            Some(OsStr::new("sse2,future-extension")),
            Some(OsStr::new("sse2")),
        )
        .expect_err("explicit feature spelling must stay strict");
        assert_eq!(
            error,
            "unknown FRE_RIPGREP_AOT_FEATURES value \"future-extension\""
        );
    }
}
