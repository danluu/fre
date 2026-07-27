use std::{hint::black_box, time::Instant};

use fre_jit_aarch64::{EmitLimits, SearchBackendPolicy, emit_with_backend};
use fre_jit_runtime::{PublicationLimits, PublishedKernel, publish};
use fre_kernel_ir::{
    AnchorFlags, ByteClass, SearchWindow, Span, ValidateLimits, build_class_suffix,
};
use fre_kernels::{
    DispatchedRequiredLiteralPlan, Feature, RequiredLiteralAnchors, RequiredLiteralBuildLimits,
    RequiredLiteralByteClass, RequiredLiteralPlan, RequiredLiteralSearchLimits,
    SimdDispatchContext,
};

const HAYSTACK_BYTES: usize = 1 << 20;
const CLASS_RUN_BYTES: usize = 64;
const ITERATIONS: usize = 32;
const SAMPLES: usize = 8;
const SUFFIX_ALPHABET: &[u8] = b"!bcdefghijklmnopqrstuvwxyz0123456789";

fn measure_portable(plan: &DispatchedRequiredLiteralPlan, haystack: &[u8]) -> (f64, usize) {
    let started = Instant::now();
    let mut checksum = 0_usize;
    for _ in 0..ITERATIONS {
        let found = plan
            .find(
                black_box(haystack),
                black_box(RequiredLiteralSearchLimits::unlimited()),
            )
            .expect("portable class-suffix benchmark search")
            .0
            .expect("benchmark haystack contains one match");
        checksum = checksum
            .wrapping_add(black_box(found.0))
            .wrapping_add(black_box(found.1));
    }
    (
        started.elapsed().as_secs_f64() * 1_000_000_000.0 / ITERATIONS as f64,
        checksum,
    )
}

fn measure_sve2(kernel: &PublishedKernel<Span>, haystack: &[u8]) -> (f64, usize) {
    let window = SearchWindow::new(0, haystack.len());
    let started = Instant::now();
    let mut checksum = 0_usize;
    for _ in 0..ITERATIONS {
        let found = kernel
            .search(black_box(haystack), black_box(window))
            .expect("SVE2 class-suffix benchmark call")
            .expect("benchmark haystack contains one match");
        checksum = checksum
            .wrapping_add(black_box(found.start()))
            .wrapping_add(black_box(found.end()));
    }
    (
        started.elapsed().as_secs_f64() * 1_000_000_000.0 / ITERATIONS as f64,
        checksum,
    )
}

fn median(samples: &mut [f64]) -> f64 {
    samples.sort_by(f64::total_cmp);
    samples[samples.len() / 2]
}

#[test]
#[ignore = "native qualification benchmark; requires Linux/AArch64 with OS-usable SVE2 and VL=16"]
#[allow(
    clippy::too_many_lines,
    reason = "one ignored benchmark keeps the production portable and SVE2 JIT comparison authenticated"
)]
fn benchmark_sve2_class_suffix_against_production_portable_route() {
    let dispatch = SimdDispatchContext::capture();
    assert!(
        dispatch.capabilities().usable().contains(Feature::ArmSve2),
        "benchmark requires OS-usable SVE2"
    );

    for member_count in [2_usize, 4, 8, 16] {
        let members: Vec<u8> = (0..member_count)
            .map(|index| b'A' + u8::try_from(index).expect("small ASCII class"))
            .collect();
        for suffix_len in [1_usize, 3, 16, 32] {
            let suffix = &SUFFIX_ALPHABET[..suffix_len];
            let portable = RequiredLiteralPlan::build_with_dispatch(
                dispatch,
                RequiredLiteralByteClass::from_bytes(&members),
                suffix,
                RequiredLiteralAnchors::default(),
                RequiredLiteralBuildLimits::default(),
            )
            .expect("portable dispatched class-suffix plan");
            let program = build_class_suffix::<Span>(
                ByteClass::from_bytes(&members),
                suffix,
                AnchorFlags::default(),
                ValidateLimits::default(),
            )
            .expect("class-suffix kernel IR");
            let image = emit_with_backend(
                &program,
                SearchBackendPolicy::Sve2Fixed16,
                EmitLimits::default(),
            )
            .expect("SVE2 class-suffix image");
            let kernel = publish::<Span>(&image, PublicationLimits::default())
                .expect("SVE2 class-suffix publication");

            let mut haystack = vec![b'x'; HAYSTACK_BYTES];
            let expected_start = HAYSTACK_BYTES - suffix_len - CLASS_RUN_BYTES;
            for (index, byte) in haystack[expected_start..expected_start + CLASS_RUN_BYTES]
                .iter_mut()
                .enumerate()
            {
                *byte = members[index % member_count];
            }
            haystack[expected_start + CLASS_RUN_BYTES..].copy_from_slice(suffix);

            let portable_found = portable
                .find(&haystack, RequiredLiteralSearchLimits::unlimited())
                .expect("portable correctness search")
                .0;
            let sve2_found = kernel
                .search(&haystack, SearchWindow::new(0, haystack.len()))
                .expect("SVE2 correctness search")
                .map(|found| (found.start(), found.end()));
            assert_eq!(portable_found, Some((expected_start, HAYSTACK_BYTES)));
            assert_eq!(sve2_found, portable_found);

            let mut portable_samples = Vec::with_capacity(SAMPLES);
            let mut sve2_samples = Vec::with_capacity(SAMPLES);
            for sample in 0..SAMPLES {
                let ((portable_ns, portable_checksum), (sve2_ns, sve2_checksum)) =
                    if sample % 2 == 0 {
                        (
                            measure_portable(&portable, &haystack),
                            measure_sve2(&kernel, &haystack),
                        )
                    } else {
                        let sve2 = measure_sve2(&kernel, &haystack);
                        let portable = measure_portable(&portable, &haystack);
                        (portable, sve2)
                    };
                assert_eq!(portable_checksum, sve2_checksum);
                portable_samples.push(portable_ns);
                sve2_samples.push(sve2_ns);
            }
            let portable_ns = median(&mut portable_samples);
            let sve2_ns = median(&mut sve2_samples);
            println!(
                "CLASS_SUFFIX_PRODUCTION_BENCH class_members={member_count} \
                 suffix_bytes={suffix_len} iterations={ITERATIONS} samples={SAMPLES} \
                 haystack_bytes={HAYSTACK_BYTES} portable_ns={portable_ns:.6} \
                 sve2_ns={sve2_ns:.6} sve2_over_portable={:.9}",
                sve2_ns / portable_ns
            );
        }
    }
}
