use regex_syntax::ParserBuilder;

const BOOL_PROPERTY_ALIASES: &[&str] =
    include!("../../../../../../crates/fre-syntax/src/unicode_bool_aliases.in");

const PROBES: &[(&str, &str)] = &[
    ("ascii", "ascii"),
    ("age", r"\p{Age:6.0}"),
    ("age-equal", r"\p{age=V6_0}"),
    ("age-not-equal", r"\p{Age!=6.0}"),
    ("age-negated", r"\P{Age=6.0}"),
    ("age-normalized-name", r"\p{A_g-e = 6.0}"),
    ("age-normalized-is-name", r"\p{iS_A-g e=6.0}"),
    ("age-is-prefix", r"\p{IsAge=6.0}"),
    ("age-unassigned", r"\p{Age=Unassigned}"),
    ("age-non-ascii-name", r"\p{A💥ge=6.0}"),
    ("age-invalid-value", r"\p{Age=definitely-invalid}"),
    ("age-bare-name", r"\p{Age}"),
    ("age-extra-name", r"\p{Ageish=6.0}"),
    ("age-casefold", r"(?i:\p{Age=6.0})"),
    (
        "age-set-subtraction",
        r"[\p{Age=6.0}--\p{Age=5.0}]",
    ),
    ("bool", r"\p{Alphabetic}"),
    ("bool-normalized", r"\p{P_at-tern White Space}"),
    ("bool-is-prefix", r"\p{IsAlphabetic}"),
    ("bool-non-ascii", r"\p{A💥lpha}"),
    (
        "bool-long-alias",
        r"\p{Other_Default_Ignorable_Code_Point}",
    ),
    (
        "bool-set-intersection",
        r"[\p{Uppercase}&&\p{Alphabetic}]",
    ),
    ("bool-space", r"\s"),
    ("bool-space-casefold", r"(?i:\s)"),
    ("bool-space-bracket-casefold", r"(?i:[\s])"),
    (
        "bool-property-bracket-casefold",
        r"(?i:[\p{Alphabetic}])",
    ),
    ("bool-space-no-u", r"(?-u:\s)"),
    ("bool-named-value", r"\p{Alphabetic=Yes}"),
    ("bool-near-miss", r"\p{Alphabeticish}"),
    ("bool-unreachable-incb", r"\p{InCB}"),
    ("bool-is-c-collision", r"\p{IsC}"),
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
    for (index, &alias) in BOOL_PROPERTY_ALIASES.iter().enumerate() {
        let pattern = format!(r"\p{{{alias}}}");
        let passed = ParserBuilder::new().build().parse(&pattern).is_ok();
        println!("bool-alias-{index}:{alias}\t{}", u8::from(passed));
    }
}
