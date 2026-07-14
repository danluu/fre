use fre_jit_aarch64::{EmitLimits, audit, emit};
use fre_kernel_ir::{
    AnchorFlags, ByteClass, Span, ValidateLimits, build_class_suffix, build_exact_literal,
};

fn main() {
    println!(
        "shape,pattern_bytes,code_bytes,data_bytes,instructions,branches,relocations,labels,vector_instructions,emission_work,scratch_bytes"
    );
    for (name, literal, anchors) in [
        ("literal-empty", b"".as_slice(), AnchorFlags::default()),
        ("literal-1", b"x".as_slice(), AnchorFlags::default()),
        ("literal-6", b"needle".as_slice(), AnchorFlags::default()),
        (
            "literal-16",
            b"0123456789abcdef".as_slice(),
            AnchorFlags::default(),
        ),
        (
            "literal-17",
            b"0123456789abcdefg".as_slice(),
            AnchorFlags::default(),
        ),
        (
            "literal-32",
            &[b'x'; fre_jit_aarch64::MAX_REPEATED_CONFIRM_BYTES],
            AnchorFlags::default(),
        ),
        (
            "literal-17-both-anchors",
            b"0123456789abcdefg".as_slice(),
            AnchorFlags {
                start: true,
                end: true,
            },
        ),
    ] {
        let program = build_exact_literal::<Span>(literal, anchors, ValidateLimits::default())
            .expect("fixture is valid");
        print_image(
            name,
            literal.len(),
            &emit(&program, EmitLimits::default()).expect("emit"),
        );
    }
    for (name, suffix, anchors) in [
        ("class-suffix-1", b"Z".as_slice(), AnchorFlags::default()),
        (
            "class-suffix-7",
            b"Zsuffix".as_slice(),
            AnchorFlags::default(),
        ),
        (
            "class-suffix-17",
            b"Z123456789abcdefg".as_slice(),
            AnchorFlags::default(),
        ),
        (
            "class-suffix-17-both-anchors",
            b"Z123456789abcdefg".as_slice(),
            AnchorFlags {
                start: true,
                end: true,
            },
        ),
    ] {
        let program = build_class_suffix::<Span>(
            ByteClass::from_bytes(b"abc"),
            suffix,
            anchors,
            ValidateLimits::default(),
        )
        .expect("fixture is proved disjoint");
        print_image(
            name,
            suffix.len().checked_add(32).expect("small fixture"),
            &emit(&program, EmitLimits::default()).expect("emit"),
        );
    }
}

fn print_image(name: &str, pattern_bytes: usize, image: &fre_jit_aarch64::NativeImage) {
    let report = audit(image).expect("emitted image authenticates");
    let stats = image.stats();
    println!(
        "{name},{pattern_bytes},{},{},{},{},{},{},{},{},{}",
        stats.code_bytes,
        stats.data_bytes,
        report.instructions,
        report.direct_branches,
        stats.relocations,
        stats.labels,
        report.vector_instructions,
        stats.emission_work,
        stats.scratch_bytes,
    );
}
