use fre_iterator_lab::{Ast, CompileLimits, CompiledRegex, Span};

#[test]
fn nested_split_replay_is_served_from_one_reverse_sequential_row() {
    // The outer split is compiled after the inner split, so the selected path
    // asks for their fixed ranks in descending order at the same boundary.
    // A bit-at-a-time forward stream cannot serve that order. A whole row
    // buffer can, while physical row positions remain reverse sequential.
    let ast = Ast::Alt(vec![
        Ast::Alt(vec![Ast::Byte(b'a'), Ast::Byte(b'b')]),
        Ast::Byte(b'c'),
    ]);
    let regex = CompiledRegex::new(&ast, CompileLimits::default()).expect("compile");
    let report = regex
        .find_all_sequential_row_log(b"a")
        .expect("sequential row log");
    assert_eq!(report.matches, vec![Span { start: 0, end: 1 }]);
    assert_eq!(
        report.accounting.sequential_log_write_bytes,
        report.accounting.sequential_log_bytes
    );
    assert!(report.accounting.sequential_log_read_bytes <= report.accounting.sequential_log_bytes);
}

#[test]
fn row_padding_and_resident_store_are_explicit() {
    let regex = CompiledRegex::new(&Ast::Empty, CompileLimits::default()).expect("compile");
    let report = regex
        .find_all_sequential_row_log(b"abc")
        .expect("sequential row log");
    // No split states: each row still carries one root-success bit and is
    // padded to one byte for reverse-sequential fixed-record access.
    assert_eq!(report.accounting.sequential_log_bytes, 4);
    assert_eq!(report.accounting.resident_log_bytes, 4);
    assert_eq!(report.accounting.sequential_log_write_bytes, 4);
    assert_eq!(report.accounting.sequential_log_read_bytes, 4);
}
