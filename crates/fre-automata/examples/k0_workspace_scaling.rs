use std::{hint::black_box, time::Instant};

use fre_automata::{
    Automaton, CompileLimits, EdgeKind, K0Workspace, RawPlan, SearchAccounting, SearchLimits, Span,
    StateRole, WorkspaceLimits,
};

const SAMPLES: usize = 9;
const TARGET_BATCH_NS: u128 = 10_000_000;
const MAX_ITERATIONS: usize = 20_000;

#[derive(Clone)]
struct State {
    role: StateRole,
    edges: Vec<Edge>,
}

#[derive(Clone, Copy)]
struct Edge {
    target: u32,
    kind: EdgeKind,
    start: u8,
    end: u8,
}

#[derive(Clone, Copy)]
enum Mode {
    Cold,
    Reused,
}

impl Mode {
    const fn name(self) -> &'static str {
        match self {
            Self::Cold => "cold",
            Self::Reused => "reused",
        }
    }
}

fn main() {
    println!(
        "case,input_bytes,mode,median_ns,p10_ns,p90_ns,samples,iterations,\
         setup_work,transition_work,allocated_bytes,initialized_bytes,retained_bytes"
    );
    let cases = [
        ("literal", literal(b"needle"), b'x'),
        ("class_plus_suffix", class_plus_suffix(), b'a'),
        ("three_way_alternation", alternation(), b'x'),
    ];
    for (name, automaton, fill) in &cases {
        for input_bytes in [32_usize, 256, 2_048, 16_384] {
            let haystack = vec![*fill; input_bytes];
            for mode in [Mode::Cold, Mode::Reused] {
                let row = measure(automaton, &haystack, mode);
                println!(
                    "{name},{input_bytes},{},{},{},{},{SAMPLES},{},{},{},{},{},{}",
                    mode.name(),
                    row.median_ns,
                    row.p10_ns,
                    row.p90_ns,
                    row.iterations,
                    row.accounting.setup_work(),
                    row.accounting.transition_work(),
                    row.accounting.setup().allocated_bytes(),
                    row.accounting.setup().initialized_bytes(),
                    row.accounting.setup().retained_bytes(),
                );
            }
        }
    }
}

struct Row {
    median_ns: u128,
    p10_ns: u128,
    p90_ns: u128,
    iterations: usize,
    accounting: SearchAccounting,
}

fn measure(automaton: &Automaton, haystack: &[u8], mode: Mode) -> Row {
    let mut workspace = K0Workspace::new(automaton, WorkspaceLimits::unlimited()).unwrap();
    let accounting = invoke(automaton, haystack, mode, &mut workspace);
    let start = Instant::now();
    let _ = invoke(automaton, haystack, mode, &mut workspace);
    let estimate = start.elapsed().as_nanos().max(1);
    let iterations_u128 = TARGET_BATCH_NS
        .checked_div(estimate)
        .unwrap_or(1)
        .clamp(1, u128::try_from(MAX_ITERATIONS).unwrap());
    let iterations = usize::try_from(iterations_u128).unwrap();

    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let start = Instant::now();
        for _ in 0..iterations {
            black_box(invoke(automaton, haystack, mode, &mut workspace));
        }
        let elapsed = start.elapsed().as_nanos();
        samples.push(elapsed.checked_div(iterations_u128).unwrap());
    }
    samples.sort_unstable();
    Row {
        median_ns: samples[SAMPLES / 2],
        p10_ns: samples[0],
        p90_ns: samples[SAMPLES - 1],
        iterations,
        accounting,
    }
}

fn invoke(
    automaton: &Automaton,
    haystack: &[u8],
    mode: Mode,
    workspace: &mut K0Workspace,
) -> SearchAccounting {
    let report = match mode {
        Mode::Cold => automaton
            .prepare::<Span>()
            .search(haystack, SearchLimits::unlimited())
            .unwrap(),
        Mode::Reused => automaton
            .prepare::<Span>()
            .search_with_workspace(haystack, workspace, SearchLimits::unlimited())
            .unwrap(),
    };
    black_box(report.output());
    report.accounting()
}

fn literal(bytes: &[u8]) -> Automaton {
    let mut states = Vec::with_capacity(bytes.len().saturating_add(1));
    for (index, &byte) in bytes.iter().enumerate() {
        states.push(consume(vec![range(
            u32::try_from(index.saturating_add(1)).unwrap(),
            byte,
            byte,
        )]));
    }
    states.push(accept());
    compile(states)
}

fn class_plus_suffix() -> Automaton {
    compile(vec![
        consume(vec![range(1, b'a', b'z')]),
        split(vec![epsilon(0), epsilon(2)]),
        consume(vec![range(3, b'Z', b'Z')]),
        accept(),
    ])
}

fn alternation() -> Automaton {
    let branches: [&[u8]; 3] = [b"foobar", b"foobaz", b"quux"];
    let mut states = vec![split(Vec::new())];
    let mut starts = Vec::with_capacity(branches.len());
    for branch in branches {
        starts.push(u32::try_from(states.len()).unwrap());
        for &byte in branch {
            let target = u32::try_from(states.len().saturating_add(1)).unwrap();
            states.push(consume(vec![range(target, byte, byte)]));
        }
        states.push(accept());
    }
    states[0].edges = starts.into_iter().map(epsilon).collect();
    compile(states)
}

fn compile(states: Vec<State>) -> Automaton {
    let mut edge_offsets = Vec::with_capacity(states.len().saturating_add(1));
    let mut edge_targets = Vec::new();
    let mut edge_kinds = Vec::new();
    let mut byte_starts = Vec::new();
    let mut byte_ends = Vec::new();
    edge_offsets.push(0);
    for state in &states {
        for edge in &state.edges {
            edge_targets.push(edge.target);
            edge_kinds.push(edge.kind);
            byte_starts.push(edge.start);
            byte_ends.push(edge.end);
        }
        edge_offsets.push(u32::try_from(edge_targets.len()).unwrap());
    }
    Automaton::from_raw(
        RawPlan {
            start: 0,
            roles: states.into_iter().map(|state| state.role).collect(),
            edge_offsets,
            edge_targets,
            edge_kinds,
            byte_starts,
            byte_ends,
        },
        CompileLimits::default(),
    )
    .unwrap()
}

fn split(edges: Vec<Edge>) -> State {
    State {
        role: StateRole::Split,
        edges,
    }
}

fn consume(edges: Vec<Edge>) -> State {
    State {
        role: StateRole::Consume,
        edges,
    }
}

fn accept() -> State {
    State {
        role: StateRole::Accept,
        edges: Vec::new(),
    }
}

const fn epsilon(target: u32) -> Edge {
    Edge {
        target,
        kind: EdgeKind::Epsilon,
        start: 0,
        end: 0,
    }
}

const fn range(target: u32, start: u8, end: u8) -> Edge {
    Edge {
        target,
        kind: EdgeKind::ByteRange,
        start,
        end,
    }
}
