//! Emit reproducible logical resource scaling data for both formulations.

use std::sync::Arc;

use fre_capture_lab::{
    Ast, BuildLimits, Greed, HistoryRegex, InlineRegex, Program, SearchLimits, Window,
};

fn main() {
    let ast = Ast::alt([
        Ast::Byte(b'a').capture(1),
        Ast::concat([Ast::Byte(b'a'), Ast::Byte(b'b')]).capture(2),
    ])
    .repeat(0, None, Greed::Greedy);
    let program = Arc::new(Program::compile(&ast, BuildLimits::default()).unwrap());
    let inline = InlineRegex::from_program(Arc::clone(&program));
    let history = HistoryRegex::from_program(program);
    println!(
        "haystack_bytes,states,inline_state_visits,inline_slot_copies,inline_scratch_bound,history_state_visits,history_nodes,history_walk,history_scratch_bound"
    );
    for length in [16_usize, 32, 64, 128, 256, 512, 1_024, 2_048, 4_096] {
        let haystack = vec![b'a'; length];
        let inline_report = inline
            .captures(&haystack, Window::all(&haystack), SearchLimits::default())
            .unwrap()
            .report;
        let history_report = history
            .captures(&haystack, Window::all(&haystack), SearchLimits::default())
            .unwrap()
            .report;
        println!(
            "{length},{},{},{},{},{},{},{},{}",
            inline.program().state_len(),
            inline_report.state_visits,
            inline_report.slot_copies,
            inline_report.admitted_scratch_bytes,
            history_report.state_visits,
            history_report.history_nodes,
            history_report.history_walk,
            history_report.admitted_scratch_bytes,
        );
    }
}
