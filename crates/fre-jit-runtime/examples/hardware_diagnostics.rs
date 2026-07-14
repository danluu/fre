//! One-shot native lifecycle diagnostics, not a performance benchmark.

use std::{hint::black_box, time::Instant};

use fre_jit_aarch64::{EmitLimits, emit};
use fre_jit_runtime::{PublicationLimits, PublishedKernel, publish};
use fre_kernel_ir::{
    AnchorFlags, ByteClass, SearchWindow, Span, ValidateLimits, build_class_suffix,
    build_exact_literal,
};

const WARM_CALLS: u32 = 2_000;

fn main() {
    println!(
        "shape,code_bytes,data_bytes,emit_ns,publish_ns,first_call_ns,warm_calls,warm_total_ns"
    );
    exact();
    class_suffix();
}

fn exact() {
    let program = build_exact_literal::<Span>(
        b"0123456789abcdefg",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("valid exact kernel");
    let emit_started = Instant::now();
    let image = emit(&program, EmitLimits::default()).expect("AArch64 image");
    let emit_ns = emit_started.elapsed().as_nanos();
    report("exact-17", &image, emit_ns, |kernel| {
        let mut haystack = vec![b'x'; 64 << 10];
        haystack.extend_from_slice(b"0123456789abcdefg");
        exercise(kernel, &haystack)
    });
}

fn class_suffix() {
    let program = build_class_suffix::<Span>(
        ByteClass::from_bytes(b"ac"),
        b"bcdefghijklmnopq",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("valid disjoint class+suffix kernel");
    let emit_started = Instant::now();
    let image = emit(&program, EmitLimits::default()).expect("AArch64 image");
    let emit_ns = emit_started.elapsed().as_nanos();
    report("class-ac-suffix-17", &image, emit_ns, |kernel| {
        let mut haystack = vec![b'x'; 64 << 10];
        haystack.extend_from_slice(b"aaabcdefghijklmnopq");
        exercise(kernel, &haystack)
    });
}

fn report(
    shape: &str,
    image: &fre_jit_aarch64::NativeImage,
    emit_ns: u128,
    exercise_kernel: impl FnOnce(&PublishedKernel<Span>) -> (u128, u128),
) {
    let publish_started = Instant::now();
    let kernel = publish::<Span>(image, PublicationLimits::default()).expect("strict W^X");
    let publish_ns = publish_started.elapsed().as_nanos();
    let (first_call_ns, warm_total_ns) = exercise_kernel(&kernel);
    println!(
        "{shape},{},{},{emit_ns},{publish_ns},{first_call_ns},{WARM_CALLS},{warm_total_ns}",
        image.stats().code_bytes,
        image.stats().data_bytes,
    );
}

fn exercise(kernel: &PublishedKernel<Span>, haystack: &[u8]) -> (u128, u128) {
    let window = SearchWindow::new(0, haystack.len());
    let first_started = Instant::now();
    black_box(
        kernel
            .search(black_box(haystack), window)
            .expect("first call"),
    );
    let first_call_ns = first_started.elapsed().as_nanos();

    let warm_started = Instant::now();
    for _ in 0..WARM_CALLS {
        black_box(
            kernel
                .search(black_box(haystack), window)
                .expect("warm call"),
        );
    }
    (first_call_ns, warm_started.elapsed().as_nanos())
}
