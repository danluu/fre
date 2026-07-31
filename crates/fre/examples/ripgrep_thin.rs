//! A deliberately thin grep-shaped adapter for comparing FRE with Rust regex.
//!
//! This is not intended to be a general purpose grep implementation. It
//! implements only the ripgrep benchmark suite flags used by the canonical
//! `rg` command in each workload. Everything except matcher construction and
//! matcher dispatch is shared between the two engines.

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use fre::{PortableBuilder, PortableFindIterRunLimits, SearchLimits, SearchSessionLimits};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug)]
enum Engine {
    Fre,
    RustRegex,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScanMode {
    Lines,
    WholeFile,
}

impl ScanMode {
    const fn name(self) -> &'static str {
        match self {
            Self::Lines => "lines",
            Self::WholeFile => "whole-file",
        }
    }
}

#[derive(Debug)]
struct Args {
    engine: Engine,
    scan_mode: ScanMode,
    pattern: String,
    paths: Vec<PathBuf>,
    case_insensitive: bool,
    line_number: bool,
    word: bool,
    describe_only: bool,
}

#[derive(Clone, Copy, Debug, Default)]
struct ScanStats {
    files: u64,
    matching_lines: u64,
}

struct WholeFileStats {
    files: u64,
    bytes: u64,
    matches: u64,
    matched_bytes: u64,
    current_file: Option<u64>,
    span_digest: Sha256,
}

impl WholeFileStats {
    fn new() -> Self {
        let mut span_digest = Sha256::new();
        span_digest.update(b"fre-ripgrep-thin-whole-file-spans-v1\0");
        Self {
            files: 0,
            bytes: 0,
            matches: 0,
            matched_bytes: 0,
            current_file: None,
            span_digest,
        }
    }

    fn start_file(&mut self, bytes: usize) -> Result<(), String> {
        let ordinal = self.files;
        let bytes = u64::try_from(bytes).map_err(|_| "file length exceeds u64".to_owned())?;
        self.span_digest.update([0xF0]);
        self.span_digest.update(ordinal.to_le_bytes());
        self.span_digest.update(bytes.to_le_bytes());
        self.files = self
            .files
            .checked_add(1)
            .ok_or_else(|| "file count overflow".to_owned())?;
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| "scanned byte count overflow".to_owned())?;
        self.current_file = Some(ordinal);
        Ok(())
    }

    fn record_match(&mut self, start: usize, end: usize) -> Result<(), String> {
        if end < start {
            return Err("matcher returned an inverted span".to_owned());
        }
        let ordinal = self
            .current_file
            .ok_or_else(|| "matcher returned a span before a file began".to_owned())?;
        let start = u64::try_from(start).map_err(|_| "match start exceeds u64".to_owned())?;
        let end = u64::try_from(end).map_err(|_| "match end exceeds u64".to_owned())?;
        self.span_digest.update([0x4D]);
        self.span_digest.update(ordinal.to_le_bytes());
        self.span_digest.update(start.to_le_bytes());
        self.span_digest.update(end.to_le_bytes());
        self.matches = self
            .matches
            .checked_add(1)
            .ok_or_else(|| "match count overflow".to_owned())?;
        self.matched_bytes = self
            .matched_bytes
            .checked_add(end - start)
            .ok_or_else(|| "matched byte count overflow".to_owned())?;
        Ok(())
    }

    fn span_sha256(&self) -> String {
        format!("{:x}", self.span_digest.clone().finalize())
    }
}

fn main() {
    match run() {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    }
}

fn run() -> Result<bool, String> {
    let args = parse_args(std::env::args_os().skip(1))?;
    let pattern = if args.word {
        format!(r"\b(?:{})\b", args.pattern)
    } else {
        args.pattern.clone()
    };

    match args.engine {
        Engine::Fre => {
            let regex = PortableBuilder::new(&pattern)
                .case_insensitive(args.case_insensitive)
                .build()
                .map_err(|error| format!("FRE_UNSUPPORTED build: {error}"))?;
            let plan = regex.runtime_implementation_id();
            if args.describe_only {
                println!(
                    "engine=fre\tplan={plan}\tmode={}\tpattern={pattern}",
                    args.scan_mode.name()
                );
                return Ok(true);
            }
            let mut session = regex
                .search_session(SearchSessionLimits::default())
                .map_err(|error| format!("FRE_UNSUPPORTED session: {error}"))?;
            match args.scan_mode {
                ScanMode::Lines => {
                    let limits = SearchLimits::default();
                    let stats = scan_lines(&args, |line| {
                        session
                            .is_match_value(line, limits)
                            .map_err(|error| format!("FRE_UNSUPPORTED search: {error}"))
                    })?;
                    emit_line_stats_if_requested(stats, plan);
                    Ok(stats.matching_lines != 0)
                }
                ScanMode::WholeFile => {
                    let limits = PortableFindIterRunLimits::unlimited();
                    let stats = scan_whole_files(&args, |haystack, stats| {
                        for matched in session.find_iter(haystack, limits) {
                            let matched = matched
                                .map_err(|error| format!("FRE_UNSUPPORTED search: {error}"))?;
                            stats.record_match(matched.start(), matched.end())?;
                        }
                        Ok(())
                    })?;
                    Ok(emit_whole_file_stats(stats, plan))
                }
            }
        }
        Engine::RustRegex => {
            let regex = regex::bytes::RegexBuilder::new(&pattern)
                .case_insensitive(args.case_insensitive)
                .build()
                .map_err(|error| format!("rust-regex build: {error}"))?;
            if args.describe_only {
                println!(
                    "engine=rust-regex\tplan=regex-bytes\tmode={}\tpattern={pattern}",
                    args.scan_mode.name()
                );
                return Ok(true);
            }
            match args.scan_mode {
                ScanMode::Lines => {
                    let stats = scan_lines(&args, |line| Ok(regex.is_match(line)))?;
                    emit_line_stats_if_requested(stats, "regex-bytes");
                    Ok(stats.matching_lines != 0)
                }
                ScanMode::WholeFile => {
                    let stats = scan_whole_files(&args, |haystack, stats| {
                        for matched in regex.find_iter(haystack) {
                            stats.record_match(matched.start(), matched.end())?;
                        }
                        Ok(())
                    })?;
                    Ok(emit_whole_file_stats(stats, "regex-bytes"))
                }
            }
        }
    }
}

fn emit_line_stats_if_requested(stats: ScanStats, plan: &str) {
    if std::env::var_os("FRE_THIN_STATS").is_some() {
        eprintln!(
            "plan={plan}\tfiles={}\tmatching_lines={}",
            stats.files, stats.matching_lines
        );
    }
}

fn emit_whole_file_stats(stats: WholeFileStats, plan: &str) -> bool {
    println!(
        "mode=whole-file\tfiles={}\tbytes={}\tmatches={}\tmatched_bytes={}\tspan_sha256={}",
        stats.files,
        stats.bytes,
        stats.matches,
        stats.matched_bytes,
        stats.span_sha256()
    );
    if std::env::var_os("FRE_THIN_STATS").is_some() {
        eprintln!(
            "plan={plan}\tmode=whole-file\tfiles={}\tbytes={}\tmatches={}\tmatched_bytes={}",
            stats.files, stats.bytes, stats.matches, stats.matched_bytes
        );
    }
    stats.matches != 0
}

fn parse_args<I>(arguments: I) -> Result<Args, String>
where
    I: IntoIterator<Item = OsString>,
{
    let mut arguments = arguments.into_iter();
    let mut engine = None;
    let mut pattern = None;
    let mut paths = Vec::new();
    let mut case_insensitive = false;
    let mut line_number = false;
    let mut word = false;
    let mut describe_only = false;
    let mut scan_mode = ScanMode::Lines;
    let mut options_done = false;

    while let Some(argument) = arguments.next() {
        if pattern.is_some() || options_done {
            if pattern.is_none() {
                pattern = Some(os_to_string(argument, "pattern")?);
            } else {
                paths.push(PathBuf::from(argument));
            }
            continue;
        }
        let text = os_to_string(argument.clone(), "option or pattern")?;
        match text.as_str() {
            "--" => options_done = true,
            "--engine" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--engine requires fre or rust-regex".to_owned())?;
                engine = Some(parse_engine(&os_to_string(value, "engine")?)?);
            }
            "-i" | "--ignore-case" => case_insensitive = true,
            "-n" | "--line-number" => line_number = true,
            "-w" | "--word-regexp" => word = true,
            "-in" | "-ni" => {
                case_insensitive = true;
                line_number = true;
            }
            "-nw" | "-wn" => {
                line_number = true;
                word = true;
            }
            "--describe-only" => describe_only = true,
            "--whole-file" => scan_mode = ScanMode::WholeFile,
            // The canonical non-mmap rg command is used by the runner, but
            // accepting these makes direct substitutions less surprising.
            "--mmap" | "--no-mmap" => {}
            _ if text.starts_with("--engine=") => {
                let value = text
                    .strip_prefix("--engine=")
                    .ok_or_else(|| "invalid --engine option".to_owned())?;
                engine = Some(parse_engine(value)?);
            }
            _ if text.starts_with('-') => {
                return Err(format!("unsupported ripgrep flag: {text}"));
            }
            _ => pattern = Some(text),
        }
    }

    let engine = engine.ok_or_else(|| "--engine fre|rust-regex is required".to_owned())?;
    let pattern = pattern.ok_or_else(|| "a regex pattern is required".to_owned())?;
    if paths.is_empty() {
        paths.push(PathBuf::from("."));
    }
    Ok(Args {
        engine,
        scan_mode,
        pattern,
        paths,
        case_insensitive,
        line_number,
        word,
        describe_only,
    })
}

fn parse_engine(value: &str) -> Result<Engine, String> {
    match value {
        "fre" => Ok(Engine::Fre),
        "rust-regex" | "rust" => Ok(Engine::RustRegex),
        _ => Err(format!(
            "unknown engine {value:?}; expected fre or rust-regex"
        )),
    }
}

fn os_to_string(value: OsString, label: &str) -> Result<String, String> {
    value
        .into_string()
        .map_err(|value| format!("{label} is not valid UTF-8: {value:?}"))
}

fn scan_lines<F>(args: &Args, mut is_match: F) -> Result<ScanStats, String>
where
    F: FnMut(&[u8]) -> Result<bool, String>,
{
    let files = collect_files(&args.paths)?;
    let show_path = args.paths.len() != 1 || args.paths[0].is_dir();
    let stdout = io::stdout();
    let mut output = BufWriter::new(stdout.lock());
    let mut stats = ScanStats::default();
    for file in files {
        if scan_file(
            &file,
            show_path,
            args.line_number,
            &mut is_match,
            &mut output,
            &mut stats,
        )? {
            stats.files = stats
                .files
                .checked_add(1)
                .ok_or_else(|| "file count overflow".to_owned())?;
        }
    }
    output
        .flush()
        .map_err(|error| format!("flush stdout: {error}"))?;
    Ok(stats)
}

fn scan_whole_files<F>(args: &Args, mut find_matches: F) -> Result<WholeFileStats, String>
where
    F: FnMut(&[u8], &mut WholeFileStats) -> Result<(), String>,
{
    let files = collect_files(&args.paths)?;
    let mut bytes = Vec::new();
    let mut stats = WholeFileStats::new();
    for path in files {
        let mut file = match File::open(&path) {
            Ok(file) => file,
            Err(error) => {
                eprintln!("{}: {error}", path.display());
                continue;
            }
        };
        bytes.clear();
        file.read_to_end(&mut bytes)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        if bytes[..bytes.len().min(64 * 1024)].contains(&0) {
            continue;
        }
        stats.start_file(bytes.len())?;
        find_matches(&bytes, &mut stats)?;
    }
    Ok(stats)
}

fn scan_file<F, W>(
    path: &Path,
    show_path: bool,
    line_number: bool,
    is_match: &mut F,
    output: &mut W,
    stats: &mut ScanStats,
) -> Result<bool, String>
where
    F: FnMut(&[u8]) -> Result<bool, String>,
    W: Write,
{
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("{}: {error}", path.display());
            return Ok(false);
        }
    };
    let mut reader = BufReader::with_capacity(64 * 1024, file);
    if reader
        .fill_buf()
        .map_err(|error| format!("read {}: {error}", path.display()))?
        .contains(&0)
    {
        return Ok(false);
    }

    let mut bytes = Vec::new();
    let mut line = 0_u64;
    loop {
        bytes.clear();
        let read = reader
            .read_until(b'\n', &mut bytes)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        line = line
            .checked_add(1)
            .ok_or_else(|| format!("line count overflow in {}", path.display()))?;
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
        }
        if !is_match(&bytes)? {
            continue;
        }
        stats.matching_lines = stats
            .matching_lines
            .checked_add(1)
            .ok_or_else(|| "matching line count overflow".to_owned())?;
        if show_path {
            let display_path = path.strip_prefix(".").unwrap_or(path);
            write!(output, "{}:", display_path.display())
                .map_err(|error| format!("write stdout: {error}"))?;
        }
        if line_number {
            write!(output, "{line}:").map_err(|error| format!("write stdout: {error}"))?;
        }
        output
            .write_all(&bytes)
            .and_then(|()| output.write_all(b"\n"))
            .map_err(|error| format!("write stdout: {error}"))?;
    }
    Ok(true)
}

fn collect_files(inputs: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    for input in inputs {
        if input.is_file() {
            files.push(input.clone());
        } else if input.is_dir() {
            if input.join(".git").exists() {
                match collect_git_files(input) {
                    Ok(mut git_files) => files.append(&mut git_files),
                    Err(error) => {
                        eprintln!("{error}; falling back to directory walk");
                        collect_directory(input, &mut files)?;
                    }
                }
            } else {
                collect_directory(input, &mut files)?;
            }
        } else {
            return Err(format!("input does not exist: {}", input.display()));
        }
    }
    files.sort_unstable();
    files.dedup();
    Ok(files)
}

fn collect_git_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ])
        .output()
        .map_err(|error| format!("run git in {}: {error}", root.display()))?;
    if !output.status.success() {
        return Err(format!(
            "git ls-files failed in {} with {}",
            root.display(),
            output.status
        ));
    }
    let mut files = Vec::new();
    for raw in output.stdout.split(|byte| *byte == 0) {
        if raw.is_empty() {
            continue;
        }
        let relative = std::str::from_utf8(raw)
            .map_err(|error| format!("non-UTF-8 git path in {}: {error}", root.display()))?;
        let relative = Path::new(relative);
        if is_hidden(relative) {
            continue;
        }
        let candidate = root.join(relative);
        let metadata = fs::symlink_metadata(&candidate)
            .map_err(|error| format!("stat {}: {error}", candidate.display()))?;
        if metadata.file_type().is_file() {
            files.push(candidate);
        }
    }
    Ok(files)
}

fn collect_directory(root: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let mut entries = fs::read_dir(root)
        .map_err(|error| format!("read directory {}: {error}", root.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("read directory {}: {error}", root.display()))?;
    entries.sort_unstable_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let name = entry.file_name();
        if name.as_encoded_bytes().first() == Some(&b'.') {
            continue;
        }
        let file_type = entry
            .file_type()
            .map_err(|error| format!("stat {}: {error}", entry.path().display()))?;
        if file_type.is_dir() {
            collect_directory(&entry.path(), files)?;
        } else if file_type.is_file() {
            files.push(entry.path());
        }
    }
    Ok(())
}

fn is_hidden(path: &Path) -> bool {
    path.components().any(|component| match component {
        Component::Normal(name) => name.as_encoded_bytes().first() == Some(&b'.'),
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::{ScanMode, WholeFileStats, parse_args};
    use std::ffi::OsString;

    #[test]
    fn whole_file_flag_selects_whole_file_mode() {
        let args = parse_args(
            ["--engine", "fre", "--whole-file", "a\\s+b", "sample.txt"]
                .into_iter()
                .map(OsString::from),
        )
        .expect("whole-file arguments");
        assert_eq!(args.scan_mode, ScanMode::WholeFile);
    }

    #[test]
    fn whole_file_span_digest_is_deterministic_and_file_delimited() {
        let mut left = WholeFileStats::new();
        left.start_file(8).expect("first file");
        left.record_match(1, 3).expect("first match");
        left.start_file(8).expect("second file");
        left.record_match(1, 3).expect("second match");

        let mut same = WholeFileStats::new();
        same.start_file(8).expect("first file");
        same.record_match(1, 3).expect("first match");
        same.start_file(8).expect("second file");
        same.record_match(1, 3).expect("second match");

        let mut moved = WholeFileStats::new();
        moved.start_file(8).expect("first file");
        moved.record_match(1, 3).expect("first match");
        moved.record_match(1, 3).expect("moved match");
        moved.start_file(8).expect("second file");

        assert_eq!(left.span_sha256(), same.span_sha256());
        assert_ne!(left.span_sha256(), moved.span_sha256());
    }
}
