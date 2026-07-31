use std::{
    collections::BTreeMap,
    error::Error,
    fmt::Write as _,
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    process::Command,
};

use fre::RustProfile;
use fre_aot_compiler::{MacosAarch64CountManifestV2, plan_and_compile_macos_aarch64_count_v2};
use fre_aot_count_compiler::{
    CountCompileClaimsV2, CountCompileLimitsV2, CountCompileRequestV2, CountFinalImageGlueLimitsV2,
    compile_count_v2, publish_count_final_image_glue_v2,
    publish_count_qualification_final_image_glue_v2,
};
use sha2::{Digest, Sha256};

const LITERAL: &[u8] = b"needle";
const ROW_SELECTOR: u16 = 11;

#[allow(
    clippy::too_many_lines,
    reason = "one fail-closed transaction emits, links, executes, inspects, and hashes the complete evidence bundle"
)]
fn main() -> Result<(), Box<dyn Error>> {
    let (output, qualification_private) = arguments()?;
    fs::create_dir(&output)?;

    let mut profile = RustProfile::default();
    profile.options.unicode = false;
    let oracle = plan_and_compile_macos_aarch64_count_v2(
        MacosAarch64CountManifestV2::default(),
        LITERAL.to_vec(),
        profile,
    )?;
    let claim = oracle.static_count_expectation().claim();
    let claims = CountCompileClaimsV2 {
        manifest_identity: *claim.manifest_identity(),
        policy_limits_identity: *claim.policy_limits_identity(),
        semantic_binding_identity: *claim.semantic_binding_identity(),
        planning_receipt_identity: *claim.planning_receipt_identity(),
        live_literal_identity: *claim.live_literal_identity(),
        program_identity: *claim.program_identity(),
        image_identity: *claim.image_identity(),
        object_binding_identity: *claim.object_binding_identity(),
        claimed_receipt_identity: *claim.receipt_identity(),
        claimed_resource_receipt_identity: *claim.resource_receipt_identity(),
    };
    let compiled = compile_count_v2(
        CountCompileRequestV2 {
            literal: LITERAL,
            claims,
        },
        CountCompileLimitsV2::default(),
    )?;
    let glue = if qualification_private {
        publish_count_qualification_final_image_glue_v2(
            &compiled,
            ROW_SELECTOR,
            CountFinalImageGlueLimitsV2::default(),
        )?
    } else {
        publish_count_final_image_glue_v2(
            &compiled,
            ROW_SELECTOR,
            CountFinalImageGlueLimitsV2::default(),
        )?
    };

    write_new(
        &output.join("implementation.o"),
        compiled.implementation_object().as_bytes(),
    )?;
    write_new(&output.join("final-image-glue.o"), glue.object().as_bytes())?;
    write_new(&output.join("expectation.bin"), compiled.expectation())?;
    write_new(
        &output.join("unsigned-prelink-receipt.bin"),
        compiled.unsigned_prelink_receipt().canonical_bytes(),
    )?;
    write_new(
        &output.join("unsigned-final-image-receipt.bin"),
        glue.receipt().canonical_bytes(),
    )?;

    let compile_identity = hex(compiled.implementation_object().compile_identity());
    let driver = driver_source(&compile_identity, qualification_private);
    write_new(&output.join("driver.c"), driver.as_bytes())?;
    write_new(
        &output.join("link-command.txt"),
        b"/usr/bin/clang -arch arm64 driver.c final-image-glue.o implementation.o \
          -Wl,-segprot,__FRE_CONST,r,r -Wl,-reproducible -o linked-count\n",
    )?;

    let executable = output.join("linked-count");
    let link = Command::new("/usr/bin/clang")
        .args(["-arch", "arm64"])
        .arg(output.join("driver.c"))
        .arg(output.join("final-image-glue.o"))
        .arg(output.join("implementation.o"))
        .arg("-Wl,-segprot,__FRE_CONST,r,r")
        .arg("-Wl,-reproducible")
        .arg("-o")
        .arg(&executable)
        .output()?;
    if !link.status.success() {
        return Err(format!("link failed: {}", String::from_utf8_lossy(&link.stderr)).into());
    }
    let execution = Command::new(&executable).output()?;
    if !execution.status.success() {
        return Err(format!(
            "execution failed: {}",
            String::from_utf8_lossy(&execution.stderr)
        )
        .into());
    }

    let duplicate = Command::new("/usr/bin/clang")
        .args(["-arch", "arm64"])
        .arg(output.join("driver.c"))
        .arg(output.join("final-image-glue.o"))
        .arg(output.join("implementation.o"))
        .arg(output.join("implementation.o"))
        .arg("-Wl,-segprot,__FRE_CONST,r,r")
        .arg("-Wl,-reproducible")
        .arg("-o")
        .arg(output.join("duplicate-must-not-exist"))
        .output()?;
    if duplicate.status.success() {
        return Err("duplicate implementation link unexpectedly succeeded".into());
    }
    write_new(
        &output.join("duplicate-link.stderr"),
        normalize(&duplicate.stderr, &output).as_bytes(),
    )?;

    for (name, tool, arguments) in [
        ("file.txt", "/usr/bin/file", vec![executable.clone()]),
        (
            "otool-l.txt",
            "/usr/bin/otool",
            vec![PathBuf::from("-l"), executable.clone()],
        ),
        ("nm.txt", "/usr/bin/nm", vec![executable.clone()]),
    ] {
        let report = Command::new(tool).args(arguments).output()?;
        if !report.status.success() {
            return Err(format!("{tool} failed").into());
        }
        let normalized = normalize(&report.stdout, &output);
        if name == "otool-l.txt" {
            require_read_only_constant_segment(&normalized)?;
        }
        write_new(&output.join(name), normalized.as_bytes())?;
    }

    let mut evidence = String::new();
    writeln!(evidence, "literal_hex={}", hex(LITERAL))?;
    writeln!(evidence, "row_selector={ROW_SELECTOR}")?;
    writeln!(evidence, "compile_identity={compile_identity}")?;
    writeln!(
        evidence,
        "implementation_object_identity={}",
        hex(compiled.implementation_object().object_identity())
    )?;
    writeln!(
        evidence,
        "expectation_identity={}",
        hex(glue.object().expectation_identity())
    )?;
    writeln!(
        evidence,
        "prelink_content_identity={}",
        hex(compiled.unsigned_prelink_receipt().content_identity())
    )?;
    writeln!(
        evidence,
        "glue_object_identity={}",
        hex(glue.object().object_identity())
    )?;
    writeln!(
        evidence,
        "final_image_content_identity={}",
        hex(glue.receipt().content_identity())
    )?;
    writeln!(evidence, "native_count_status=0")?;
    writeln!(evidence, "native_count_value=2")?;
    writeln!(evidence, "duplicate_implementation_link=refused")?;
    writeln!(
        evidence,
        "glue_adopter={}",
        if qualification_private {
            "qualification-private"
        } else {
            "production"
        }
    )?;
    writeln!(evidence, "runtime_authority=absent")?;
    write_new(&output.join("evidence.txt"), evidence.as_bytes())?;

    write_sha_manifest(&output)?;
    Ok(())
}

fn arguments() -> Result<(PathBuf, bool), Box<dyn Error>> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let output = arguments
        .next()
        .ok_or("usage: emit_c3_evidence OUTPUT_DIRECTORY [--qualification-private]")?;
    let qualification_private = match arguments.next() {
        None => false,
        Some(mode) if mode == "--qualification-private" => true,
        Some(_) => return Err("unknown evidence adopter mode".into()),
    };
    if arguments.next().is_some() {
        return Err("usage: emit_c3_evidence OUTPUT_DIRECTORY [--qualification-private]".into());
    }
    Ok((PathBuf::from(output), qualification_private))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn normalize(bytes: &[u8], output: &Path) -> String {
    let text = String::from_utf8_lossy(bytes);
    let relative = output.to_string_lossy();
    let absolute = fs::canonicalize(output)
        .expect("canonical evidence directory")
        .to_string_lossy()
        .into_owned();
    text.replace(&absolute, ".").replace(relative.as_ref(), ".")
}

fn require_read_only_constant_segment(load_commands: &str) -> Result<(), Box<dyn Error>> {
    let segment = load_commands
        .split("Load command")
        .find(|command| {
            command.contains("cmd LC_SEGMENT_64")
                && command.lines().any(|line| line == "  segname __FRE_CONST")
        })
        .ok_or("linked image has no __FRE_CONST segment")?;
    if !segment
        .lines()
        .any(|line| line.trim() == "maxprot 0x00000001")
        || !segment
            .lines()
            .any(|line| line.trim() == "initprot 0x00000001")
    {
        return Err("linked __FRE_CONST segment is not immutable R--/R--".into());
    }
    Ok(())
}

fn write_sha_manifest(output: &Path) -> Result<(), Box<dyn Error>> {
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(output)? {
        let entry = entry?;
        if entry.file_type()?.is_file() && entry.file_name() != "SHA256SUMS" {
            files.insert(
                entry.file_name().to_string_lossy().into_owned(),
                fs::read(entry.path())?,
            );
        }
    }
    let mut manifest = String::new();
    for (name, bytes) in files {
        writeln!(manifest, "{}  {name}", hex(&Sha256::digest(bytes)))?;
    }
    write_new(&output.join("SHA256SUMS"), manifest.as_bytes())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut output, byte| {
        write!(output, "{byte:02x}").expect("write to String");
        output
    })
}

fn driver_source(compile_identity: &str, qualification_private: bool) -> String {
    let adopter = if qualification_private {
        "fre_aot_static_count_adopt_qualification_raw_v2"
    } else {
        "fre_aot_static_count_adopt_raw_v2"
    };
    r#"#include <stddef.h>
#include <stdint.h>

struct adoption_output {
    const void *verified;
};

typedef uint64_t (*count_entry)(const uint8_t *, size_t, uint64_t *);

extern uint32_t GLUE_SYMBOL(struct adoption_output *);

uint32_t RUNTIME_ADOPTER(
    struct adoption_output *output,
    uint32_t selector,
    const uint8_t *expectation,
    const uint8_t *entry,
    const uint8_t *payload,
    const uint8_t *metadata
) {
    static const uint8_t haystack[] = "needle hay needle";
    uint64_t result = UINT64_MAX;
    if (output == NULL || selector != 11 || expectation == NULL ||
        entry == NULL || payload == NULL || metadata == NULL ||
        entry != payload) {
        return 91;
    }
    if (expectation[0] != 'F' || expectation[7] != 2) {
        return 92;
    }
    uint64_t status = ((count_entry)entry)(
        haystack,
        sizeof(haystack) - 1,
        &result
    );
    if (status != 0 || result != 2) {
        return 93;
    }
    return 77;
}

int main(void) {
    struct adoption_output output = {0};
    return GLUE_SYMBOL(&output) == 77 ? 0 : 1;
}
"#
    .replace(
        "GLUE_SYMBOL",
        &format!("fre_aot_count_glue_v2_{compile_identity}"),
    )
    .replace("RUNTIME_ADOPTER", adopter)
}
