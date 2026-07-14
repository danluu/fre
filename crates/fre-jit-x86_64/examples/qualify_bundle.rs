use std::{env, fs, path::PathBuf};

use fre_jit_x86_64::{EmitConfig, FeatureTier, NativeImage, emit};
use fre_kernel_ir::{
    AnchorFlags, ByteClass, Span, ValidateLimits, build_class_suffix, build_exact_literal,
};

const MAGIC: &[u8; 8] = b"FREQX64\x01";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: qualify_bundle OUTPUT")?;
    let mut records = Vec::new();
    for tier in tiers() {
        for anchors in anchors() {
            for length in [0, 1, 3, 8, 9, 16, 17, 32, 33] {
                let pattern = pattern(length, b'k');
                let program =
                    build_exact_literal::<Span>(&pattern, anchors, ValidateLimits::default())?;
                records.push(Record {
                    kind: 0,
                    anchors,
                    class: ByteClass::empty(),
                    pattern,
                    image: emit_with_tier(&program, tier)?,
                });
            }
            for class in [
                ByteClass::from_bytes(b"ab"),
                ByteClass::from_bytes(b"abcde"),
            ] {
                for length in [1, 3, 8, 9, 16, 17, 32, 33] {
                    let mut suffix = pattern(length, b'X');
                    suffix[0] = b'X';
                    let program = build_class_suffix::<Span>(
                        class,
                        &suffix,
                        anchors,
                        ValidateLimits::default(),
                    )?;
                    records.push(Record {
                        kind: 1,
                        anchors,
                        class,
                        pattern: suffix,
                        image: emit_with_tier(&program, tier)?,
                    });
                }
            }
        }
    }
    let bytes = serialize(&records)?;
    fs::write(path, bytes)?;
    println!("records={}", records.len());
    Ok(())
}

struct Record {
    kind: u8,
    anchors: AnchorFlags,
    class: ByteClass,
    pattern: Vec<u8>,
    image: NativeImage,
}

fn serialize(records: &[Record]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&u32::try_from(records.len())?.to_le_bytes());
    for record in records {
        bytes.push(record.kind);
        bytes.push(feature_tag(record.image.stamp().used_tier));
        bytes.push(u8::from(record.anchors.start) | (u8::from(record.anchors.end) << 1));
        bytes.push(0);
        bytes.extend_from_slice(&u32::try_from(record.pattern.len())?.to_le_bytes());
        bytes.extend_from_slice(&u32::try_from(record.image.image_bytes().len())?.to_le_bytes());
        for lane in record.class.lanes() {
            bytes.extend_from_slice(&lane.to_le_bytes());
        }
        bytes.extend_from_slice(&record.pattern);
        bytes.extend_from_slice(record.image.image_bytes());
    }
    Ok(bytes)
}

fn emit_with_tier<O: fre_kernel_ir::Operation>(
    program: &fre_kernel_ir::ValidatedProgram<O>,
    tier: FeatureTier,
) -> Result<NativeImage, fre_jit_x86_64::EmitError> {
    emit(
        program,
        EmitConfig {
            feature_tier: tier,
            ..EmitConfig::default()
        },
    )
}

fn pattern(length: usize, first: u8) -> Vec<u8> {
    (0..length)
        .map(|index| {
            if index == 0 {
                first
            } else {
                let value = index.wrapping_mul(37).wrapping_add(11) % 251;
                u8::try_from(value).expect("modulo 251 fits u8")
            }
        })
        .collect()
}

const fn feature_tag(tier: FeatureTier) -> u8 {
    match tier {
        FeatureTier::Scalar => 0,
        FeatureTier::Sse2 => 1,
        FeatureTier::Avx2 => 2,
    }
}

fn tiers() -> [FeatureTier; 3] {
    [FeatureTier::Scalar, FeatureTier::Sse2, FeatureTier::Avx2]
}

fn anchors() -> [AnchorFlags; 4] {
    [
        AnchorFlags::default(),
        AnchorFlags {
            start: true,
            end: false,
        },
        AnchorFlags {
            start: false,
            end: true,
        },
        AnchorFlags {
            start: true,
            end: true,
        },
    ]
}
