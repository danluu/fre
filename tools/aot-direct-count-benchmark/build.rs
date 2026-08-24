use std::{
    env,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use fre_aot_regex::{
    CompileMode, CompileRequest, CpuFeature, FeatureSet, OutputContract,
    PreparedAggregateExports, PreparedAggregateStrategy, SectionKind, SymbolBinding, SymbolKind,
    Target, compile_with_prepared_aggregate_exports,
};

mod public_shapes;

const MOV_X0_X1: u32 = 0xaa01_03e0;
const MOV_X1_X2: u32 = 0xaa02_03e1;
const MOV_X2_X3: u32 = 0xaa03_03e2;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=public_shapes.rs");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo supplies OUT_DIR"));
    let target = host_aarch64_asimd_target().unwrap_or_else(|error| panic!("{error}"));
    let target_name = format!(
        "{}-aarch64",
        env::var("CARGO_CFG_TARGET_OS").expect("Cargo supplies target OS"),
    );
    let mut declarations = String::new();
    let mut rows = String::new();
    let mut objects = Vec::new();
    let mut common_implementation = None;

    for (&width, &pattern) in public_shapes::WIDTHS.iter().zip(&public_shapes::LITERALS) {
        assert_eq!(pattern.len(), width, "public literal width drift");
        assert_eq!(
            public_shapes::literal_for_width(width),
            Some(pattern),
            "public literal lookup drift",
        );
        let compiled = compile_with_prepared_aggregate_exports(
            CompileRequest::new(pattern, target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
            PreparedAggregateExports::COUNT,
        )
        .unwrap_or_else(|error| panic!("compile public width {width}: {error}"));
        let module = compiled.module();
        assert_eq!(
            module.prepared_aggregate_exports(),
            PreparedAggregateExports::COUNT,
            "public width {width} lost sole Count export",
        );
        assert_eq!(
            module.prepared_aggregate_strategy(),
            Some(PreparedAggregateStrategy::NativeFused),
            "public width {width} lost native-fused Count",
        );
        assert!(
            module.required_runtime_symbols().next().is_none(),
            "public width {width} unexpectedly needs a runtime search helper",
        );
        let (program_symbol, program_len) = module
            .required_runtime_program()
            .unwrap_or_else(|| panic!("public width {width} has no preparation program"));
        let count_symbol = module
            .prepared_count_symbol()
            .unwrap_or_else(|| panic!("public width {width} has no Count symbol"));
        let implementation = classify_implementation(module, count_symbol);
        if let Some(expected) = common_implementation {
            assert_eq!(
                implementation, expected,
                "public widths selected mixed Count implementations",
            );
        } else {
            common_implementation = Some(implementation);
        }

        let object = out_dir.join(format!("public_count_width_{width}.o"));
        fs::write(&object, compiled.object())
            .unwrap_or_else(|error| panic!("write {}: {error}", object.display()));
        objects.push(object);

        writeln!(
            &mut declarations,
            "    #[link_name = {count_symbol:?}]\n    fn public_count_width_{width}(handle: FreAotRegexExclusiveHandleV1, haystack: *const u8, haystack_len: usize, value_out: *mut u64) -> u32;\n    #[link_name = {program_symbol:?}]\n    static public_program_width_{width}: u8;",
        )
        .expect("write generated declarations");
        writeln!(
            &mut rows,
            "    PublicSpec {{ width: {width}, literal: {pattern:?}, program: public_program_width_{width}_ptr, program_len: {program_len}, entry: public_count_width_{width}, route: PublicRoute {{ api: \"count-v1\", mode: \"optimizing\", output: \"span\", aggregate: \"native-fused\", implementation: {implementation:?}, target: {target_name:?}, features: \"asimd\", engine: {engine:?}, reason: {reason:?} }} }},",
            engine = format!("{:?}", compiled.receipt().engine),
            reason = format!("{:?}", compiled.receipt().engine_selection_reason),
        )
        .expect("write generated registry row");
    }

    let mut generated = String::from(
        "#[allow(unsafe_code, reason = \"the generated benchmark registry binds compiler-emitted Count objects\")]\nunsafe extern \"C\" {\n",
    );
    generated.push_str(&declarations);
    generated.push_str("}\n\n");
    for width in public_shapes::WIDTHS {
        writeln!(
            &mut generated,
            "fn public_program_width_{width}_ptr() -> *const u8 {{ core::ptr::addr_of!(public_program_width_{width}) }}",
        )
        .expect("write generated program accessor");
    }
    generated.push_str("\npub(crate) const PUBLIC_SPECS: &[PublicSpec] = &[\n");
    generated.push_str(&rows);
    generated.push_str("];\n");
    fs::write(out_dir.join("registry.rs"), generated).expect("write generated registry");
    make_archive(&out_dir, &objects);
}

fn host_aarch64_asimd_target() -> Result<Target, String> {
    let architecture = env::var("CARGO_CFG_TARGET_ARCH").map_err(|error| error.to_string())?;
    let os = env::var("CARGO_CFG_TARGET_OS").map_err(|error| error.to_string())?;
    let base = match (architecture.as_str(), os.as_str()) {
        ("aarch64", "linux") => Target::aarch64_linux(),
        ("aarch64", "macos") => Target::aarch64_macos(),
        _ => {
            return Err(format!(
                "the public direct Count-v3 benchmark requires an AArch64 Linux/macOS target, got {architecture}-{os}",
            ));
        }
    };
    base.with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
        .map_err(|error| error.to_string())
}

fn classify_implementation(
    module: &fre_aot_regex::CompiledModule,
    count_name: &str,
) -> &'static str {
    let text_index = module
        .sections()
        .iter()
        .position(|section| section.kind == SectionKind::Text)
        .expect("Count module has a text section");
    let text = module.sections()[text_index].bytes();
    let count = module
        .symbols()
        .iter()
        .find(|symbol| symbol.name == count_name)
        .expect("Count accessor names a defined symbol");
    let ordinary = module
        .symbols()
        .iter()
        .find(|symbol| symbol.name == module.entry_symbol())
        .expect("ordinary entry accessor names a defined symbol");
    assert_eq!(count.binding, SymbolBinding::Global);
    assert_eq!(count.kind, SymbolKind::Function);
    assert_eq!(count.section, Some(text_index));
    assert_eq!(ordinary.binding, SymbolBinding::Global);
    assert_eq!(ordinary.kind, SymbolKind::Function);
    assert_eq!(ordinary.section, Some(text_index));
    let count_start = usize::try_from(count.offset).expect("Count offset fits usize");
    let count_size = usize::try_from(count.size).expect("Count size fits usize");
    let count_end = count_start.checked_add(count_size).expect("Count extent");
    let count_code = text
        .get(count_start..count_end)
        .expect("Count symbol is inside text");
    assert!(count_start.is_multiple_of(4));
    assert!(count_code.len().is_multiple_of(4));
    let ordinary_offset = usize::try_from(ordinary.offset).expect("ordinary offset fits usize");

    let mut direct_targets = Vec::new();
    for relative in (0..=count_code.len().saturating_sub(16)).step_by(4) {
        let words = [
            word(count_code, relative),
            word(count_code, relative + 4),
            word(count_code, relative + 8),
            word(count_code, relative + 12),
        ];
        if words[..3] == [MOV_X0_X1, MOV_X1_X2, MOV_X2_X3]
            && let Some(target) = aarch64_branch_target(count_start + relative + 12, words[3], false)
        {
            direct_targets.push(target);
        }
    }
    if direct_targets.len() == 1 {
        let target = direct_targets[0];
        let target_is_unsymbolized = !module.symbols().iter().any(|symbol| {
            if symbol.section != Some(text_index) || symbol.size == 0 {
                return false;
            }
            let Ok(start) = usize::try_from(symbol.offset) else {
                return true;
            };
            let Some(end) = usize::try_from(symbol.size)
                .ok()
                .and_then(|size| start.checked_add(size))
            else {
                return true;
            };
            (start..end).contains(&target)
        });
        assert!(
            target >= count_end && target < text.len() && target_is_unsymbolized,
            "direct Count tail does not enter the appended unsymbolized core",
        );
        return "direct-exact-singleton-count-v3";
    }
    assert!(
        direct_targets.is_empty(),
        "Count entry contains multiple candidate direct-core tails",
    );

    let ordinary_calls = (0..count_code.len())
        .step_by(4)
        .filter(|relative| {
            aarch64_branch_target(
                count_start + *relative,
                word(count_code, *relative),
                true,
            ) == Some(ordinary_offset)
        })
        .count();
    assert_eq!(
        ordinary_calls, 1,
        "incumbent Count entry must call the ordinary entry exactly once",
    );
    "incumbent-ordinary-entry-loop"
}

fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("instruction extent"),
    )
}

fn aarch64_branch_target(offset: usize, instruction: u32, link: bool) -> Option<usize> {
    let expected = if link { 0x9400_0000 } else { 0x1400_0000 };
    if instruction & 0xfc00_0000 != expected {
        return None;
    }
    let immediate = i64::from(instruction & 0x03ff_ffff);
    let signed = if immediate & (1_i64 << 25) == 0 {
        immediate
    } else {
        immediate - (1_i64 << 26)
    };
    i64::try_from(offset)
        .ok()?
        .checked_add(signed.checked_mul(4)?)?
        .try_into()
        .ok()
}

fn make_archive(out_dir: &Path, objects: &[PathBuf]) {
    let archive = out_dir.join("libfre_aot_direct_count_public.a");
    match fs::remove_file(&archive) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("remove stale {}: {error}", archive.display()),
    }
    let archiver = env::var_os("AR").unwrap_or_else(|| "ar".into());
    let output = Command::new(&archiver)
        .arg("crs")
        .arg(&archive)
        .args(objects)
        .output()
        .unwrap_or_else(|error| panic!("run {}: {error}", archiver.to_string_lossy()));
    assert!(
        output.status.success(),
        "archive public Count objects failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=fre_aot_direct_count_public");
}
