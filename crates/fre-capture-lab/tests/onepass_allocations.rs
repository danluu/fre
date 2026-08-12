#![forbid(unsafe_code)]

use std::{alloc::System, sync::Arc};

use fre_capture_lab::{
    Ast, BuildLimits, OnePassCaptureBuildError, OnePassCaptureBuildLimits,
    OnePassCaptureBuildResource, OnePassCapturePlan, Program,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn base_immutable_refusal_precedes_every_construction_allocation() {
    let program = Arc::new(
        Program::compile(&Ast::Byte(b'a').capture(1), BuildLimits::default())
            .expect("program build"),
    );
    let region = Region::new(GLOBAL);
    let refused = OnePassCapturePlan::try_from_program_accounted(
        Arc::clone(&program),
        OnePassCaptureBuildLimits {
            max_program_bytes: 0,
            ..OnePassCaptureBuildLimits::default()
        },
    )
    .expect_err("zero immutable bytes must refuse the base sidecar");
    let stats = region.change();
    assert_eq!(stats.allocations, 0);
    assert_eq!(stats.reallocations, 0);
    assert_eq!(refused.compile_work, 0);
    assert!(matches!(
        refused.source,
        OnePassCaptureBuildError::Resource {
            resource: OnePassCaptureBuildResource::ImmutableBytes,
            required,
            limit: 0,
        } if required > 0
    ));
}
