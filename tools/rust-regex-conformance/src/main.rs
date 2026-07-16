use std::{env, path::PathBuf, process::ExitCode};

use rust_regex_conformance::{build_inventory, read_inventory, write_inventory};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rust-regex-conformance: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let command = args.next().ok_or(usage())?;
    match command.as_str() {
        "generate" => {
            let checkout = PathBuf::from(args.next().ok_or(usage())?);
            let output = PathBuf::from(args.next().ok_or(usage())?);
            reject_extra(&mut args)?;
            let inventory = build_inventory(&checkout)?;
            write_inventory(&output, &inventory)?;
            println!(
                "inventory revision={} files={} raw_cases={} rust_regex_cases={} obligations={} payload_sha256={}",
                inventory.payload.upstream.revision,
                inventory.payload.scope.source_files,
                inventory.payload.scope.raw_cases,
                inventory.payload.scope.rust_regex_cases,
                inventory.payload.scope.adapter_obligations,
                inventory.payload_sha256
            );
        }
        "verify" => {
            let checkout = PathBuf::from(args.next().ok_or(usage())?);
            let manifest_path = PathBuf::from(args.next().ok_or(usage())?);
            reject_extra(&mut args)?;
            let expected = read_inventory(&manifest_path)?;
            let actual = build_inventory(&checkout)?;
            if actual != expected {
                return Err(
                    "checked-in manifest differs from authenticated upstream source".into(),
                );
            }
            println!(
                "verified revision={} files={} raw_cases={} rust_regex_cases={} payload_sha256={}",
                actual.payload.upstream.revision,
                actual.payload.scope.source_files,
                actual.payload.scope.raw_cases,
                actual.payload.scope.rust_regex_cases,
                actual.payload_sha256
            );
        }
        "validate" => {
            let manifest_path = PathBuf::from(args.next().ok_or(usage())?);
            reject_extra(&mut args)?;
            let inventory = read_inventory(&manifest_path)?;
            println!(
                "valid files={} raw_cases={} rust_regex_cases={} obligations={} payload_sha256={}",
                inventory.payload.scope.source_files,
                inventory.payload.scope.raw_cases,
                inventory.payload.scope.rust_regex_cases,
                inventory.payload.scope.adapter_obligations,
                inventory.payload_sha256
            );
        }
        "-h" | "--help" | "help" => println!("{}", usage()),
        _ => return Err(usage().into()),
    }
    Ok(())
}

fn reject_extra(args: &mut impl Iterator<Item = String>) -> Result<(), String> {
    if let Some(extra) = args.next() {
        Err(format!("unexpected argument {extra:?}; {}", usage()))
    } else {
        Ok(())
    }
}

fn usage() -> &'static str {
    "usage: rust-regex-conformance generate CHECKOUT OUTPUT | verify CHECKOUT MANIFEST | validate MANIFEST"
}
