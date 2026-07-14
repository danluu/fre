use fre_jit_x86_64::{AuditLimits, EmitConfig, FeatureTier, audit_image, emit};
use fre_kernel_ir::{
    AnchorFlags, ByteClass, Span, ValidateLimits, build_class_suffix, build_exact_literal,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "shape\trequested\tused\tcode\tdata\timage\trelocations\tbranches\tinstructions\tscalar_cmp\tsse2_cmp\tavx2_cmp\temit_work"
    );
    for tier in [FeatureTier::Scalar, FeatureTier::Sse2, FeatureTier::Avx2] {
        let short = build_exact_literal::<Span>(
            b"12345678",
            AnchorFlags::default(),
            ValidateLimits::default(),
        )?;
        print_row("exact-8", tier, &emit_with_tier(&short, tier)?)?;
        let long = build_exact_literal::<Span>(
            &[b'x'; 65],
            AnchorFlags::default(),
            ValidateLimits::default(),
        )?;
        print_row("exact-65", tier, &emit_with_tier(&long, tier)?)?;
        let sparse = build_class_suffix::<Span>(
            ByteClass::from_bytes(b"ab"),
            b"XYZ",
            AnchorFlags::default(),
            ValidateLimits::default(),
        )?;
        print_row("class2-suffix3", tier, &emit_with_tier(&sparse, tier)?)?;
        let dense = build_class_suffix::<Span>(
            ByteClass::from_bytes(b"abcde"),
            &[b'X'; 65],
            AnchorFlags::default(),
            ValidateLimits::default(),
        )?;
        print_row("class5-suffix65", tier, &emit_with_tier(&dense, tier)?)?;
    }
    Ok(())
}

fn emit_with_tier<O: fre_kernel_ir::Operation>(
    program: &fre_kernel_ir::ValidatedProgram<O>,
    tier: FeatureTier,
) -> Result<fre_jit_x86_64::NativeImage, fre_jit_x86_64::EmitError> {
    emit(
        program,
        EmitConfig {
            feature_tier: tier,
            ..EmitConfig::default()
        },
    )
}

fn print_row(
    name: &str,
    requested: FeatureTier,
    image: &fre_jit_x86_64::NativeImage,
) -> Result<(), fre_jit_x86_64::AuditError> {
    let stats = image.stats();
    let audit = audit_image(image, AuditLimits::default())?;
    println!(
        "{name}\t{requested:?}\t{:?}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        image.stamp().used_tier,
        stats.code_bytes,
        stats.data_bytes,
        stats.image_bytes,
        stats.relocations,
        stats.internal_branches,
        audit.shape.instructions,
        audit.shape.scalar_comparisons,
        audit.shape.sse2_comparisons,
        audit.shape.avx2_comparisons,
        stats.emit_work,
    );
    Ok(())
}
