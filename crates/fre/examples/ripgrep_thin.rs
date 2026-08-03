//! A deliberately thin grep-shaped adapter for comparing FRE with Rust regex.
//!
//! This is not intended to be a general purpose grep implementation. It
//! implements only the ripgrep benchmark suite flags used by the canonical
//! `rg` command in each workload. Everything except matcher construction and
//! matcher dispatch is shared between the two engines.

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::ops::Range;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use fre::{PortableBuilder, PortableFindIterRunLimits, SearchLimits, SearchSessionLimits};
use fre_ripgrep_aot_thin::{AotMatcher, AotMode, AotOutput};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug)]
enum Engine {
    Fre,
    RustRegex,
    FreAot(AotMode),
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
    report_scan_time: bool,
}

#[derive(Debug)]
struct LoadedFile {
    path: PathBuf,
    bytes: Vec<u8>,
    lines: Vec<Range<usize>>,
}

#[derive(Debug)]
struct LoadedCorpus {
    files: Vec<LoadedFile>,
    show_path: bool,
    file_count: u64,
    bytes: u64,
    sha256: String,
}

#[derive(Clone, Copy, Debug)]
struct MatchedLine {
    file: usize,
    line: u64,
    start: usize,
    end: usize,
}

#[derive(Debug)]
struct ScanTiming {
    elapsed: Duration,
    corpus_files: u64,
    corpus_bytes: u64,
    corpus_sha256: String,
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
    let corpus = if args.report_scan_time && !args.describe_only {
        Some(load_corpus(&args)?)
    } else {
        None
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
                    let (stats, timing) = scan_lines(&args, corpus.as_ref(), |line| {
                        session
                            .is_match_value(line, limits)
                            .map_err(|error| format!("FRE_UNSUPPORTED search: {error}"))
                    })?;
                    emit_scan_timing(timing);
                    emit_line_stats_if_requested(stats, plan);
                    Ok(stats.matching_lines != 0)
                }
                ScanMode::WholeFile => {
                    let limits = PortableFindIterRunLimits::unlimited();
                    let (stats, timing) =
                        scan_whole_files(&args, corpus.as_ref(), |haystack, stats| {
                            for matched in session.find_iter(haystack, limits) {
                                let matched = matched
                                    .map_err(|error| format!("FRE_UNSUPPORTED search: {error}"))?;
                                stats.record_match(matched.start(), matched.end())?;
                            }
                            Ok(())
                        })?;
                    emit_scan_timing(timing);
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
                    let (stats, timing) =
                        scan_lines(&args, corpus.as_ref(), |line| Ok(regex.is_match(line)))?;
                    emit_scan_timing(timing);
                    emit_line_stats_if_requested(stats, "regex-bytes");
                    Ok(stats.matching_lines != 0)
                }
                ScanMode::WholeFile => {
                    let (stats, timing) =
                        scan_whole_files(&args, corpus.as_ref(), |haystack, stats| {
                            for matched in regex.find_iter(haystack) {
                                stats.record_match(matched.start(), matched.end())?;
                            }
                            Ok(())
                        })?;
                    emit_scan_timing(timing);
                    Ok(emit_whole_file_stats(stats, "regex-bytes"))
                }
            }
        }
        Engine::FreAot(mode) => run_aot(&args, &pattern, mode, corpus.as_ref()),
    }
}

fn run_aot(
    args: &Args,
    pattern: &str,
    mode: AotMode,
    corpus: Option<&LoadedCorpus>,
) -> Result<bool, String> {
    let output = match args.scan_mode {
        ScanMode::Lines => AotOutput::Exists,
        ScanMode::WholeFile => AotOutput::Span,
    };
    let mut matcher = AotMatcher::new(mode, output, pattern, args.case_insensitive)
        .map_err(|error| format!("FRE_AOT_UNSUPPORTED build: {error}"))?;
    let engine = match mode {
        AotMode::Fast => "fre-aot-fast",
        AotMode::Optimizing => "fre-aot-optimizing",
    };
    let plan = matcher.description();
    if args.describe_only {
        println!(
            "engine={engine}\tplan={plan}\tmode={}\tpattern={pattern}",
            args.scan_mode.name()
        );
        return Ok(true);
    }
    match args.scan_mode {
        ScanMode::Lines => {
            let (stats, timing) = scan_lines(args, corpus, |line| {
                matcher
                    .is_match(line)
                    .map_err(|error| format!("FRE_AOT_UNSUPPORTED search: {error}"))
            })?;
            emit_scan_timing(timing);
            emit_line_stats_if_requested(stats, plan);
            Ok(stats.matching_lines != 0)
        }
        ScanMode::WholeFile => {
            let (stats, timing) = scan_whole_files(args, corpus, |haystack, stats| {
                let matches = matcher
                    .find_iter(haystack)
                    .map_err(|error| format!("FRE_AOT_UNSUPPORTED search: {error}"))?;
                for matched in matches {
                    let matched =
                        matched.map_err(|error| format!("FRE_AOT_UNSUPPORTED search: {error}"))?;
                    stats.record_match(matched.start(), matched.end())?;
                }
                Ok(())
            })?;
            emit_scan_timing(timing);
            Ok(emit_whole_file_stats(stats, plan))
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

fn emit_scan_timing(timing: Option<ScanTiming>) {
    if let Some(timing) = timing {
        eprintln!(
            "fre-ripgrep-thin-timing-v1\tscan_elapsed_ns={}\tboundary=preloaded-corpus-scan\tcorpus_files={}\tcorpus_bytes={}\tcorpus_sha256={}",
            timing.elapsed.as_nanos(),
            timing.corpus_files,
            timing.corpus_bytes,
            timing.corpus_sha256
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
    let mut report_scan_time = false;
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
                let value = arguments.next().ok_or_else(|| {
                    "--engine requires fre, rust-regex, fre-aot-fast, or fre-aot-optimizing"
                        .to_owned()
                })?;
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
            "--report-scan-time" => report_scan_time = true,
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

    let engine = engine.ok_or_else(|| {
        "--engine fre|rust-regex|fre-aot-fast|fre-aot-optimizing is required".to_owned()
    })?;
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
        report_scan_time,
    })
}

fn parse_engine(value: &str) -> Result<Engine, String> {
    match value {
        "fre" => Ok(Engine::Fre),
        "rust-regex" | "rust" => Ok(Engine::RustRegex),
        "fre-aot-fast" | "aot-fast" => Ok(Engine::FreAot(AotMode::Fast)),
        "fre-aot-optimizing" | "aot-optimizing" => Ok(Engine::FreAot(AotMode::Optimizing)),
        _ => Err(format!(
            "unknown engine {value:?}; expected fre, rust-regex, fre-aot-fast, or fre-aot-optimizing"
        )),
    }
}

fn os_to_string(value: OsString, label: &str) -> Result<String, String> {
    value
        .into_string()
        .map_err(|value| format!("{label} is not valid UTF-8: {value:?}"))
}

fn scan_lines<F>(
    args: &Args,
    corpus: Option<&LoadedCorpus>,
    is_match: F,
) -> Result<(ScanStats, Option<ScanTiming>), String>
where
    F: FnMut(&[u8]) -> Result<bool, String>,
{
    if let Some(corpus) = corpus {
        let (stats, timing) = scan_lines_preloaded(args, corpus, is_match)?;
        Ok((stats, Some(timing)))
    } else {
        Ok((scan_lines_streaming(args, is_match)?, None))
    }
}

fn scan_lines_preloaded<F>(
    args: &Args,
    corpus: &LoadedCorpus,
    mut is_match: F,
) -> Result<(ScanStats, ScanTiming), String>
where
    F: FnMut(&[u8]) -> Result<bool, String>,
{
    let mut stats = ScanStats {
        files: corpus.file_count,
        matching_lines: 0,
    };
    let mut matches = Vec::new();
    let started = Instant::now();
    for (file_index, file) in corpus.files.iter().enumerate() {
        for (line_index, range) in file.lines.iter().enumerate() {
            if !is_match(&file.bytes[range.clone()])? {
                continue;
            }
            stats.matching_lines = stats
                .matching_lines
                .checked_add(1)
                .ok_or_else(|| "matching line count overflow".to_owned())?;
            let line = u64::try_from(line_index)
                .map_err(|_| format!("line count overflow in {}", file.path.display()))?
                .checked_add(1)
                .ok_or_else(|| format!("line count overflow in {}", file.path.display()))?;
            matches.push(MatchedLine {
                file: file_index,
                line,
                start: range.start,
                end: range.end,
            });
        }
    }
    let elapsed = started.elapsed();

    let stdout = io::stdout();
    let mut output = BufWriter::new(stdout.lock());
    for matched in matches {
        let file = &corpus.files[matched.file];
        if corpus.show_path {
            let display_path = file.path.strip_prefix(".").unwrap_or(&file.path);
            write!(output, "{}:", display_path.display())
                .map_err(|error| format!("write stdout: {error}"))?;
        }
        if args.line_number {
            write!(output, "{}:", matched.line)
                .map_err(|error| format!("write stdout: {error}"))?;
        }
        output
            .write_all(&file.bytes[matched.start..matched.end])
            .and_then(|()| output.write_all(b"\n"))
            .map_err(|error| format!("write stdout: {error}"))?;
    }
    output
        .flush()
        .map_err(|error| format!("flush stdout: {error}"))?;
    Ok((stats, corpus.scan_timing(elapsed)))
}

fn scan_whole_files<F>(
    args: &Args,
    corpus: Option<&LoadedCorpus>,
    find_matches: F,
) -> Result<(WholeFileStats, Option<ScanTiming>), String>
where
    F: FnMut(&[u8], &mut WholeFileStats) -> Result<(), String>,
{
    if let Some(corpus) = corpus {
        let (stats, timing) = scan_whole_files_preloaded(corpus, find_matches)?;
        Ok((stats, Some(timing)))
    } else {
        Ok((scan_whole_files_streaming(args, find_matches)?, None))
    }
}

fn scan_whole_files_preloaded<F>(
    corpus: &LoadedCorpus,
    mut find_matches: F,
) -> Result<(WholeFileStats, ScanTiming), String>
where
    F: FnMut(&[u8], &mut WholeFileStats) -> Result<(), String>,
{
    let mut stats = WholeFileStats::new();
    let started = Instant::now();
    for file in &corpus.files {
        stats.start_file(file.bytes.len())?;
        find_matches(&file.bytes, &mut stats)?;
    }
    let elapsed = started.elapsed();
    Ok((stats, corpus.scan_timing(elapsed)))
}

fn load_corpus(args: &Args) -> Result<LoadedCorpus, String> {
    let paths = collect_files(&args.paths)?;
    let show_path = args.paths.len() != 1 || args.paths[0].is_dir();
    let mut files = Vec::with_capacity(paths.len());
    let mut bytes_total = 0_u64;
    let mut corpus_digest = Sha256::new();
    corpus_digest.update(b"fre-ripgrep-thin-corpus-v1\0");
    for path in paths {
        let source = match File::open(&path) {
            Ok(file) => file,
            Err(error) => {
                eprintln!("{}: {error}", path.display());
                continue;
            }
        };
        let bytes = match args.scan_mode {
            ScanMode::Lines => {
                let mut reader = BufReader::with_capacity(64 * 1024, source);
                if reader
                    .fill_buf()
                    .map_err(|error| format!("read {}: {error}", path.display()))?
                    .contains(&0)
                {
                    continue;
                }
                let mut bytes = Vec::new();
                reader
                    .read_to_end(&mut bytes)
                    .map_err(|error| format!("read {}: {error}", path.display()))?;
                bytes
            }
            ScanMode::WholeFile => {
                let mut source = source;
                let mut bytes = Vec::new();
                source
                    .read_to_end(&mut bytes)
                    .map_err(|error| format!("read {}: {error}", path.display()))?;
                if bytes[..bytes.len().min(64 * 1024)].contains(&0) {
                    continue;
                }
                bytes
            }
        };
        let path_bytes = path.as_os_str().as_encoded_bytes();
        let path_length = u64::try_from(path_bytes.len())
            .map_err(|_| format!("path length exceeds u64: {}", path.display()))?;
        let byte_length = u64::try_from(bytes.len())
            .map_err(|_| format!("file length exceeds u64: {}", path.display()))?;
        corpus_digest.update([0x46]);
        corpus_digest.update(path_length.to_le_bytes());
        corpus_digest.update(path_bytes);
        corpus_digest.update(byte_length.to_le_bytes());
        corpus_digest.update(&bytes);
        bytes_total = bytes_total
            .checked_add(byte_length)
            .ok_or_else(|| "corpus byte count overflow".to_owned())?;
        let lines = if args.scan_mode == ScanMode::Lines {
            collect_line_ranges(&bytes)
        } else {
            Vec::new()
        };
        files.push(LoadedFile { path, bytes, lines });
    }
    let file_count = u64::try_from(files.len()).map_err(|_| "file count exceeds u64".to_owned())?;
    let sha256 = format!("{:x}", corpus_digest.finalize());
    Ok(LoadedCorpus {
        files,
        show_path,
        file_count,
        bytes: bytes_total,
        sha256,
    })
}

impl LoadedCorpus {
    fn scan_timing(&self, elapsed: Duration) -> ScanTiming {
        ScanTiming {
            elapsed,
            corpus_files: self.file_count,
            corpus_bytes: self.bytes,
            corpus_sha256: self.sha256.clone(),
        }
    }
}

fn collect_line_ranges(bytes: &[u8]) -> Vec<Range<usize>> {
    let mut lines = Vec::new();
    let mut start = 0;
    for part in bytes.split_inclusive(|byte| *byte == b'\n') {
        let raw_end = start + part.len();
        let end = if part.last() == Some(&b'\n') {
            raw_end - 1
        } else {
            raw_end
        };
        lines.push(start..end);
        start = raw_end;
    }
    lines
}

fn scan_lines_streaming<F>(args: &Args, mut is_match: F) -> Result<ScanStats, String>
where
    F: FnMut(&[u8]) -> Result<bool, String>,
{
    let files = collect_files(&args.paths)?;
    let show_path = args.paths.len() != 1 || args.paths[0].is_dir();
    let stdout = io::stdout();
    let mut output = BufWriter::new(stdout.lock());
    let mut stats = ScanStats::default();
    for file in files {
        if scan_file_streaming(
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

fn scan_whole_files_streaming<F>(args: &Args, mut find_matches: F) -> Result<WholeFileStats, String>
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

fn scan_file_streaming<F, W>(
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
    use super::{ScanMode, WholeFileStats, collect_line_ranges, parse_args};
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
    fn report_scan_time_flag_is_explicit() {
        let regular = parse_args(
            ["--engine", "rust-regex", "needle", "sample.txt"]
                .into_iter()
                .map(OsString::from),
        )
        .expect("regular arguments");
        assert!(!regular.report_scan_time);

        let timed = parse_args(
            [
                "--engine",
                "rust-regex",
                "--report-scan-time",
                "needle",
                "sample.txt",
            ]
            .into_iter()
            .map(OsString::from),
        )
        .expect("timed arguments");
        assert!(timed.report_scan_time);
    }

    #[test]
    fn precomputed_lines_match_bufread_line_semantics() {
        fn split(bytes: &[u8]) -> Vec<&[u8]> {
            collect_line_ranges(bytes)
                .into_iter()
                .map(|range| &bytes[range])
                .collect()
        }

        assert_eq!(split(b""), Vec::<&[u8]>::new());
        assert_eq!(split(b"alpha"), vec![b"alpha".as_slice()]);
        assert_eq!(split(b"alpha\n"), vec![b"alpha".as_slice()]);
        assert_eq!(
            split(b"\nalpha\r\n\nbeta"),
            vec![
                b"".as_slice(),
                b"alpha\r".as_slice(),
                b"".as_slice(),
                b"beta".as_slice(),
            ]
        );
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
