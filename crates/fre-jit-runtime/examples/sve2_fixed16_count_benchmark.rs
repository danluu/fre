//! Parseable current-ASIMD versus experimental-SVE2 Count benchmark.

#[cfg(all(
    target_arch = "aarch64",
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
))]
mod linux_aarch64 {
    use std::{env, hint::black_box, process, time::Instant};

    use fre_jit_aarch64::{
        EmitLimits, emit_exact_aggregate, emit_exact_aggregate_sve2_fixed16_count_experimental,
    };
    use fre_jit_runtime::{PublicationLimits, PublishedAggregateKernel, publish_aggregate};
    use fre_kernel_ir::{AggregateExecutionLimits, Count, ValidateLimits, build_exact_aggregate};

    const WARM_CALLS: usize = 16;

    pub(super) fn main() {
        let haystack_bytes = env_usize("FRE_SVE2_COUNT16_BENCH_BYTES", 1 << 20);
        let iterations = env_usize("FRE_SVE2_COUNT16_BENCH_ITERS", 200);
        let alignment = env_usize("FRE_SVE2_COUNT16_BENCH_ALIGNMENT", 0);
        if haystack_bytes == 0 || iterations == 0 || alignment >= 16 {
            eprintln!("bytes and iterations must be positive; alignment must be 0..15");
            process::exit(2);
        }

        let program =
            build_exact_aggregate::<Count>(b"x", ValidateLimits::default()).expect("Count IR");
        let asimd_image =
            emit_exact_aggregate(&program, EmitLimits::default()).expect("current ASIMD image");
        let sve2_image =
            emit_exact_aggregate_sve2_fixed16_count_experimental(&program, EmitLimits::default())
                .expect("experimental SVE2 image");
        let asimd = publish_aggregate::<Count>(&asimd_image, PublicationLimits::default())
            .expect("current ASIMD publication");
        let sve2 = match publish_aggregate::<Count>(&sve2_image, PublicationLimits::default()) {
            Ok(kernel) => kernel,
            Err(error) => {
                eprintln!("experimental SVE2 publication unavailable: {error}");
                process::exit(2);
            }
        };

        let storage_bytes = haystack_bytes
            .checked_add(15)
            .expect("bounded benchmark allocation");
        let end = alignment
            .checked_add(haystack_bytes)
            .expect("bounded benchmark slice");
        let mut storage = vec![b'y'; storage_bytes];
        let haystack = &mut storage[alignment..end];
        for index in (3..haystack.len()).step_by(7) {
            haystack[index] = b'x';
        }
        let limits = AggregateExecutionLimits::unlimited();
        let expected = asimd
            .aggregate(haystack, limits)
            .expect("current ASIMD result");
        assert_eq!(
            sve2.aggregate(haystack, limits).expect("SVE2 result"),
            expected
        );

        println!(
            "schema,backend,haystack_bytes,alignment_mod16,iterations,total_ns,ns_per_iter,bytes_per_second,checksum,result,code_bytes,vector_instructions"
        );
        report(
            "fre-sve2-count16-v1",
            "asimd-current",
            &asimd,
            &asimd_image,
            haystack,
            iterations,
            expected,
        );
        report(
            "fre-sve2-count16-v1",
            "sve2-fixed16-count-experimental-v1",
            &sve2,
            &sve2_image,
            haystack,
            iterations,
            expected,
        );
    }

    fn report(
        schema: &str,
        backend: &str,
        kernel: &PublishedAggregateKernel<Count>,
        image: &fre_jit_aarch64::NativeAggregateImage,
        haystack: &[u8],
        iterations: usize,
        expected: u64,
    ) {
        let limits = AggregateExecutionLimits::unlimited();
        for _ in 0..WARM_CALLS {
            black_box(
                kernel
                    .aggregate(black_box(haystack), limits)
                    .expect("warm aggregate call"),
            );
        }
        let started = Instant::now();
        let mut checksum = 0_u64;
        for _ in 0..iterations {
            let result = kernel
                .aggregate(black_box(haystack), limits)
                .expect("measured aggregate call");
            checksum = checksum.wrapping_add(black_box(result));
        }
        let total_ns = started.elapsed().as_nanos();
        let iteration_count = u128::try_from(iterations).expect("iterations fit u128");
        let total_bytes = u128::try_from(haystack.len())
            .expect("length fits u128")
            .checked_mul(iteration_count)
            .expect("bounded benchmark bytes");
        let ns_per_iter = total_ns
            .checked_div(iteration_count)
            .expect("positive iteration count");
        let bytes_per_second = total_bytes
            .checked_mul(1_000_000_000)
            .expect("bounded benchmark rate numerator")
            .checked_div(total_ns.max(1))
            .expect("nonzero elapsed denominator");
        println!(
            "{schema},{backend},{},{},{iterations},{total_ns},{ns_per_iter},{bytes_per_second},{checksum},{expected},{},{}",
            haystack.len(),
            haystack.as_ptr().addr() & 15,
            image.stats().code_bytes,
            image.stats().vector_instructions,
        );
    }

    fn env_usize(name: &str, default: usize) -> usize {
        env::var(name).map_or(default, |value| {
            value
                .parse()
                .unwrap_or_else(|error| panic!("invalid {name}={value:?}: {error}"))
        })
    }
}

#[cfg(all(
    target_arch = "aarch64",
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
))]
fn main() {
    linux_aarch64::main();
}

#[cfg(not(all(
    target_arch = "aarch64",
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
)))]
fn main() {
    eprintln!("this benchmark requires Linux/AArch64 with OS-usable SVE2");
    std::process::exit(2);
}
