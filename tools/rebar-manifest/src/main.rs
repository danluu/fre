use std::fs;
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};

use rebar_manifest::{build_manifest, parse_inventory, render_inventory, render_summary};

struct Args {
    input: String,
    output: String,
    summary: Option<PathBuf>,
    normalized_inventory: Option<PathBuf>,
    revision: String,
}

fn usage() -> &'static str {
    "Usage: rebar-manifest generate --input <CSV|-> --output <JSON|->; \
     --runner-revision <40-hex-git-id> [--summary <MARKDOWN>] \
     [--normalized-inventory <CSV>]"
}

fn parse_args() -> Result<Args, String> {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some("generate") {
        return Err(usage().to_owned());
    }
    let (mut input, mut output, mut summary, mut normalized_inventory, mut revision) =
        (None, None, None, None, None);
    while let Some(flag) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("missing value after {flag:?}\n{}", usage()))?;
        match flag.as_str() {
            "--input" => input = Some(value),
            "--output" => output = Some(value),
            "--summary" => summary = Some(PathBuf::from(value)),
            "--normalized-inventory" => normalized_inventory = Some(PathBuf::from(value)),
            "--runner-revision" => revision = Some(value),
            _ => return Err(format!("unknown option {flag:?}\n{}", usage())),
        }
    }
    Ok(Args {
        input: input.ok_or_else(|| format!("--input is required\n{}", usage()))?,
        output: output.ok_or_else(|| format!("--output is required\n{}", usage()))?,
        summary,
        normalized_inventory,
        revision: revision.ok_or_else(|| format!("--runner-revision is required\n{}", usage()))?,
    })
}

fn read_input(path: &str) -> Result<Vec<u8>, String> {
    if path == "-" {
        let mut bytes = Vec::new();
        io::stdin()
            .read_to_end(&mut bytes)
            .map_err(|err| format!("read stdin: {err}"))?;
        Ok(bytes)
    } else {
        fs::read(path).map_err(|err| format!("read {path:?}: {err}"))
    }
}

fn write_output(path: &str, bytes: &[u8]) -> Result<(), String> {
    if path == "-" {
        io::stdout()
            .write_all(bytes)
            .map_err(|err| format!("write stdout: {err}"))
    } else {
        write_atomic(Path::new(path), bytes)
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|err| format!("create directory {}: {err}", parent.display()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("output path {} has no UTF-8 file name", path.display()))?;
    let temporary = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));
    fs::write(&temporary, bytes)
        .map_err(|err| format!("write temporary file {}: {err}", temporary.display()))?;
    fs::rename(&temporary, path).map_err(|err| {
        let _ = fs::remove_file(&temporary);
        format!(
            "rename {} to {}: {err}",
            temporary.display(),
            path.display()
        )
    })
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    if args.input == "-" && args.output == "-" {
        return Err("--input and --output cannot both be '-'".to_owned());
    }
    let inventory = read_input(&args.input)?;
    let records = parse_inventory(inventory.as_slice())?;
    if let Some(path) = args.normalized_inventory {
        write_atomic(&path, &render_inventory(&records)?)?;
    }
    let manifest = build_manifest(records, &args.revision)?;
    let mut json =
        serde_json::to_vec_pretty(&manifest).map_err(|err| format!("serialize manifest: {err}"))?;
    json.push(b'\n');
    write_output(&args.output, &json)?;
    if let Some(path) = args.summary {
        write_atomic(&path, render_summary(&manifest).as_bytes())?;
    }
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("rebar-manifest: {err}");
        std::process::exit(2);
    }
}
