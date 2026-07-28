#![cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code, unused_imports)
)]

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
compile_error!("the C5 promoted correctness check requires arm64 macOS");

use std::{env, error::Error};

use fre_aot_static_runtime::{
    RawStaticCountAdoptionOutputV2, StaticAdoptionErrorV2, adopt_linked_static_count_v2,
};
use fre_kernel_ir::AggregateExecutionLimits;

const PRODUCTION_LINKED_COUNT_ENABLED: bool = cfg!(any(
    feature = "production-linked-count",
    feature = "production-hardware-matrix",
    feature = "production-all-runtime"
));

#[allow(
    unsafe_code,
    reason = "the correctness check binds one externally generated, statically linked C5 production glue object"
)]
unsafe extern "C" {
    #[link_name = "fre_aot_count_glue_v2_ed06366efaed9de023166d65fcee6dbce761bec7aa62c96ba17d5bece445831f"]
    fn linked_count_glue_v2(output: *mut RawStaticCountAdoptionOutputV2) -> u32;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpectedState {
    Candidate,
    PromotedUnavailable,
    Promoted,
}

impl ExpectedState {
    fn parse() -> Result<Self, Box<dyn Error>> {
        let mut arguments = env::args().skip(1);
        let state = match arguments.next().as_deref() {
            Some("candidate") => Self::Candidate,
            Some("promoted-unavailable") => Self::PromotedUnavailable,
            Some("promoted") => Self::Promoted,
            _ => {
                return Err(
                    "usage: fre-aot-count-promoted-correctness candidate|promoted-unavailable|promoted"
                        .into(),
                );
            }
        };
        if arguments.next().is_some() {
            return Err(
                "usage: fre-aot-count-promoted-correctness candidate|promoted-unavailable|promoted"
                    .into(),
            );
        }
        match state {
            Self::Candidate => {}
            Self::PromotedUnavailable if PRODUCTION_LINKED_COUNT_ENABLED => {
                return Err(
                    "promoted-unavailable is valid only without a production linked-count feature"
                        .into(),
                );
            }
            Self::Promoted if !PRODUCTION_LINKED_COUNT_ENABLED => {
                return Err(
                    "promoted requires a production linked-count feature; use promoted-unavailable for the feature-disabled mode"
                        .into(),
                );
            }
            Self::PromotedUnavailable | Self::Promoted => {}
        }
        Ok(state)
    }
}

#[allow(
    unsafe_code,
    reason = "the correctness check invokes only its exact statically linked C5 production glue symbol"
)]
fn main() -> Result<(), Box<dyn Error>> {
    let expected = ExpectedState::parse()?;
    let adopted = adopt_linked_static_count_v2(|output| {
        // SAFETY: the post-qualification recipe links the exact source-generated
        // C5 production glue and implementation objects for the process life.
        unsafe { linked_count_glue_v2(output) }
    });

    match expected {
        ExpectedState::Candidate => {
            if !matches!(
                adopted,
                Err(StaticAdoptionErrorV2::NoQualifiedStaticCountRow)
            ) {
                return Err("unpromoted Candidate unexpectedly adopted selector 11".into());
            }
        }
        ExpectedState::PromotedUnavailable => {
            if !matches!(adopted, Err(StaticAdoptionErrorV2::VerificationRefused)) {
                return Err(
                    "atom-promoted source did not fail closed with linked Count-v2 disabled".into(),
                );
            }
        }
        ExpectedState::Promoted => {
            let handle = adopted.map_err(|error| {
                format!("atom-promoted source did not safely adopt selector 11: {error:?}")
            })?;
            let limits = AggregateExecutionLimits::unlimited();
            for (haystack, expected_count) in [
                (&b""[..], 0_u64),
                (&b"absent"[..], 0),
                (&b"needle"[..], 1),
                (&b"needle needle"[..], 2),
                (&b"needleneedle"[..], 2),
            ] {
                let actual = handle.count(haystack, limits)?;
                if actual != expected_count {
                    return Err(format!(
                        "linked Count-v2 correctness mismatch: expected {expected_count}, got {actual}"
                    )
                    .into());
                }
            }
        }
    }

    println!(
        "C5_PROMOTION_CORRECTNESS,state={},safe_adapter=true,selector=11,linked_count={PRODUCTION_LINKED_COUNT_ENABLED}",
        match expected {
            ExpectedState::Candidate => "candidate-no-qualified-row",
            ExpectedState::PromotedUnavailable => "promoted-verification-refused",
            ExpectedState::Promoted => "promoted-qualified-row",
        }
    );
    Ok(())
}
