use regex_syntax::ParserBuilder;

const PROBES: &[(&str, &str)] = &[
    ("ascii", "ascii"),
    ("age", r"\p{Age:6.0}"),
    ("bool", r"\p{Alphabetic}"),
    ("case", r"(?i:\u{03B4})"),
    ("gencat", r"\pL"),
    ("perl", r"\b\w\b"),
    ("script", r"\p{Greek}"),
    ("segment", r"\p{Grapheme_Cluster_Break=Extend}"),
    ("white-space", r"\p{White_Space}"),
    ("decimal-number", r"\p{Nd}"),
    ("any", r"\p{Any}"),
    ("assigned", r"\p{Assigned}"),
    ("collision-cf", r"\p{cf}"),
    ("collision-sc", r"\p{sc}"),
    ("collision-lc", r"\p{lc}"),
    ("is-script", r"\p{IsGreek}"),
    ("is-bool", r"\p{IsAlphabetic}"),
    ("unknown", r"\p{definitely_not_a_unicode_property}"),
    ("bare-i", r"(?i)"),
    ("i-dot", r"(?i:.)"),
    ("i-assertion", r"(?i:^$)"),
    ("iu-literal", r"(?i:a)"),
    ("i-no-u-literal", r"(?i-u:a)"),
    ("no-u-perl", r"(?-u:\d\s\w\b)"),
    ("i-direct-perl", r"(?i:\w)"),
    ("i-bracket-perl", r"(?i:[\w])"),
    ("scoped-order", r"(?i)(?-u:a)(?-i:\u{03B4})"),
];

fn main() {
    for &(id, pattern) in PROBES {
        let passed = ParserBuilder::new().build().parse(pattern).is_ok();
        println!("{id}\t{}", u8::from(passed));
    }
}
