use std::{
    env,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use fre::PortableBuilder;
use fre_jit_aarch64::{
    EmitLimits, LabelKind, NativeImage, SearchBackendPolicy, audit, emit_with_backend,
};
use fre_kernel_ir::{AnchorFlags, Exists, SelectedEnd, Span, ValidateLimits, build_exact_literal};
use sha2::{Digest as _, Sha256};

const WIDTHS: std::ops::RangeInclusive<usize> = 1..=32;
const TOPOLOGIES: [&str; 4] = ["uniform", "periodic", "clustered", "phase-unique"];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").expect("target architecture");
    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("target OS");
    assert_eq!(
        target_arch, "aarch64",
        "V27 native evidence requires an AArch64 target"
    );
    assert!(
        matches!(target_os.as_str(), "macos" | "linux"),
        "V27 native evidence requires macOS or Linux"
    );

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let assembly_path = out_dir.join("v27-candidates.S");
    let object_path = out_dir.join("v27-candidates.o");
    let archive_path = out_dir.join("libfre_v27_candidates.a");
    let generated_path = out_dir.join("generated.rs");

    let mut assembly = String::with_capacity(2 * 1024 * 1024);
    let mut generated = String::with_capacity(512 * 1024);
    let mut corpus_digest = Sha256::new();
    corpus_digest.update(b"FRE-SEARCH-V27-NATIVE-EVIDENCE-CORPUS-V1\0");

    if target_os == "macos" {
        assembly.push_str(".section __TEXT,__text,regular,pure_instructions\n");
    } else {
        assembly.push_str(".section .text.fre_v27,\"ax\",@progbits\n");
    }
    let mut family_rows = Vec::new();
    for width in WIDTHS {
        for topology in TOPOLOGIES {
            let literal = literal_for(width, topology);
            let source = canonical_exact_source(&literal);
            let portable = PortableBuilder::new(&source)
                .build()
                .expect("source-first portable exact literal");
            let candidate = portable
                .exact_literal_search_aot_candidate()
                .expect("authenticated exact-literal AOT candidate");
            assert_eq!(candidate.source(), source);
            assert_eq!(candidate.literal(), literal);

            corpus_digest.update(u64::try_from(width).expect("bounded width").to_le_bytes());
            corpus_digest.update(
                u64::try_from(topology.len())
                    .expect("bounded topology")
                    .to_le_bytes(),
            );
            corpus_digest.update(topology.as_bytes());
            corpus_digest.update(
                u64::try_from(source.len())
                    .expect("bounded source")
                    .to_le_bytes(),
            );
            corpus_digest.update(source.as_bytes());
            corpus_digest.update(
                u64::try_from(literal.len())
                    .expect("bounded literal")
                    .to_le_bytes(),
            );
            corpus_digest.update(&literal);

            let exists = emit_exists(&literal);
            let selected_end = emit_selected_end(&literal);
            let span = emit_span(&literal);
            let graph = selected_v27_graph(&literal, &span);
            let family_id = format!("w{width:02}_{}", topology.replace('-', "_"));
            let symbols = [
                format!("fre_v27_{family_id}_exists"),
                format!("fre_v27_{family_id}_selected_end"),
                format!("fre_v27_{family_id}_span"),
            ];
            for (symbol, image) in symbols.iter().zip([&exists, &selected_end, &span]) {
                append_image(&mut assembly, &target_os, symbol, image);
                writeln!(
                    generated,
                    "unsafe extern \"C\" {{ fn {symbol}(haystack: *const u8, haystack_len: usize, window_start: usize, window_end: usize, result: *mut fre_jit_aarch64::NativeResult) -> u64; }}"
                )
                .expect("generated declaration");
                corpus_digest.update(image.artifact_identity().as_bytes());
            }
            family_rows.push(format!(
                "CandidateFamily {{ width: {width}, topology: Topology::{}, graph: Graph::{}, literal: &{:?}, entries: [{}, {}, {}] }}",
                rust_variant(topology),
                rust_variant(graph),
                literal,
                symbols[0],
                symbols[1],
                symbols[2],
            ));
        }
    }

    let digest = corpus_digest.finalize();
    writeln!(
        generated,
        "const CORPUS_SHA256: &str = \"{}\";",
        hex(&digest)
    )
    .expect("generated digest");
    generated.push_str("fn candidate_families() -> Vec<CandidateFamily> {\n\tvec![\n");
    for row in family_rows {
        writeln!(generated, "\t\t{row},").expect("generated family");
    }
    generated.push_str("\t]\n}\n");

    fs::write(&assembly_path, assembly).expect("write generated assembly");
    fs::write(&generated_path, generated).expect("write generated Rust");
    compile_assembly(&assembly_path, &object_path);
    archive_object(&object_path, &archive_path);
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=fre_v27_candidates");
}

fn emit_exists(literal: &[u8]) -> NativeImage {
    let program =
        build_exact_literal::<Exists>(literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("Exists Kernel IR");
    emit_v27(&program)
}

fn emit_selected_end(literal: &[u8]) -> NativeImage {
    let program = build_exact_literal::<SelectedEnd>(
        literal,
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("SelectedEnd Kernel IR");
    emit_v27(&program)
}

fn emit_span(literal: &[u8]) -> NativeImage {
    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("Span Kernel IR");
    emit_v27(&program)
}

fn emit_v27<O: fre_kernel_ir::Operation>(
    program: &fre_kernel_ir::ValidatedProgram<O>,
) -> NativeImage {
    let image = emit_with_backend(
        program,
        SearchBackendPolicy::AsimdV27,
        EmitLimits::default(),
    )
    .expect("V27 native image");
    audit(&image).expect("independent V27 image audit");
    image
}

fn selected_v27_graph(literal: &[u8], v27: &NativeImage) -> &'static str {
    if literal.len() < 6 {
        return "v8-fallback";
    }
    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("source graph comparison IR");
    let source_policy = if literal.len() <= 8 {
        SearchBackendPolicy::AsimdV17
    } else {
        SearchBackendPolicy::AsimdV25
    };
    let Ok(source) = emit_with_backend(
        &program,
        source_policy,
        EmitLimits::default(),
    )
    else {
        return "v8-fallback";
    };
    if v27.code() == source.code()
        && v27.rodata() == source.rodata()
        && v27.layout() == source.layout()
        && v27.labels() == source.labels()
        && v27.relocations() == source.relocations()
    {
        if literal.len() <= 8 {
            "v17-fast"
        } else {
            "v25-fast"
        }
    } else {
        "v8-fallback"
    }
}

fn append_image(assembly: &mut String, target_os: &str, symbol: &str, image: &NativeImage) {
    assert_eq!(
        image
            .labels()
            .iter()
            .find(|label| label.kind == LabelKind::Entry)
            .map(|label| label.offset),
        Some(0),
        "evidence linker currently requires an offset-zero entry"
    );
    let rodata_offset =
        usize::try_from(image.layout().rodata_from_code_start).expect("bounded rodata offset");
    let gap = rodata_offset
        .checked_sub(image.code().len())
        .expect("rodata follows code");
    let linker_symbol = if target_os == "macos" {
        format!("_{symbol}")
    } else {
        symbol.to_owned()
    };
    assembly.push_str(".p2align 4\n");
    writeln!(assembly, ".globl {linker_symbol}").expect("assembly symbol");
    writeln!(assembly, "{linker_symbol}:").expect("assembly label");
    append_bytes(assembly, image.code());
    if gap != 0 {
        writeln!(assembly, ".space {gap}, 0").expect("assembly gap");
    }
    append_bytes(assembly, image.rodata());
    if target_os == "linux" {
        writeln!(assembly, ".size {linker_symbol}, .-{linker_symbol}").expect("assembly size");
    }
}

fn append_bytes(assembly: &mut String, bytes: &[u8]) {
    for chunk in bytes.chunks(24) {
        assembly.push_str(".byte ");
        for (index, byte) in chunk.iter().enumerate() {
            if index != 0 {
                assembly.push(',');
            }
            write!(assembly, "0x{byte:02x}").expect("assembly byte");
        }
        assembly.push('\n');
    }
}

fn compile_assembly(source: &Path, object: &Path) {
    let compiler = env::var_os("CC").unwrap_or_else(|| "cc".into());
    let status = Command::new(compiler)
        .arg("-c")
        .arg(source)
        .arg("-o")
        .arg(object)
        .status()
        .expect("spawn C assembler");
    assert!(status.success(), "assembling V27 images failed");
}

fn archive_object(object: &Path, archive: &Path) {
    let archiver = env::var_os("AR").unwrap_or_else(|| "ar".into());
    let status = Command::new(archiver)
        .arg("crs")
        .arg(archive)
        .arg(object)
        .status()
        .expect("spawn archiver");
    assert!(status.success(), "archiving V27 images failed");
}

fn canonical_exact_source(literal: &[u8]) -> String {
    let mut source = String::with_capacity(6 + literal.len() * 4);
    source.push_str("(?-u:");
    for byte in literal {
        write!(source, "\\x{byte:02x}").expect("source byte");
    }
    source.push(')');
    source
}

fn literal_for(width: usize, topology: &str) -> Vec<u8> {
    match topology {
        "uniform" => {
            vec![0x41_u8.wrapping_add(u8::try_from(width % 13).expect("bounded width")); width]
        }
        "periodic" => (0..width)
            .map(|offset| {
                let alphabet = [0x23, 0xa7, 0x5d];
                alphabet[offset % alphabet.len()]
            })
            .collect(),
        "clustered" => (0..width)
            .map(|offset| {
                let cluster = offset
                    .checked_mul(4)
                    .expect("bounded cluster")
                    .checked_div(width)
                    .expect("nonzero width");
                [0x19, 0x67, 0xb3, 0xe1][cluster.min(3)]
            })
            .collect(),
        "phase-unique" => {
            let mut state = 0x9e37_79b9_u32
                ^ u32::try_from(width)
                    .expect("bounded width")
                    .wrapping_mul(0x85eb_ca6b);
            let mut literal = Vec::with_capacity(width);
            while literal.len() < width {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                let byte = state.to_le_bytes()[0];
                if !literal.contains(&byte) {
                    literal.push(byte);
                }
            }
            literal
        }
        _ => unreachable!("bounded topology"),
    }
}

fn rust_variant(value: &str) -> &'static str {
    match value {
        "uniform" => "Uniform",
        "periodic" => "Periodic",
        "clustered" => "Clustered",
        "phase-unique" => "PhaseUnique",
        "v8-fallback" => "V8Fallback",
        "v17-fast" => "V17Fast",
        "v25-fast" => "V25Fast",
        _ => unreachable!("bounded generated variant"),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(result, "{byte:02x}").expect("hex byte");
    }
    result
}
