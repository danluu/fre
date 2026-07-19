use regex_syntax::ParserBuilder;

const BOOL_PROPERTY_ALIASES: &[&str] =
    include!("../../../../../../crates/fre-syntax/src/unicode_bool_aliases.in");
const GENCAT_ALIASES: &[&str] =
    include!("../../../../../../crates/fre-syntax/src/unicode_gencat_aliases.in");
const SCRIPT_ALIASES: &[&str] =
    include!("../../../../../../crates/fre-syntax/src/unicode_script_aliases.in");

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
    ("case-ascii", r"(?i:a)"),
    ("case-kelvin", r"(?i:\u{212A})"),
    ("case-long-s", r"(?i:\u{017F})"),
    ("case-sigma", r"(?i:\u{03C2})"),
    ("case-unmapped", r"(?i:\u{1F600})"),
    ("case-class", r"(?i:[a-z\u{03B4}])"),
    ("case-negated-class", r"(?i:[^\u{03B4}])"),
    ("gencat", r"\pL"),
    ("gencat-normalized", r"\p{se PaRa ToR}"),
    ("gencat-named-value", r"\p{General_Category=Uppercase_Letter}"),
    ("gencat-is-property", r"\p{Is_G-C=Letter}"),
    ("gencat-not-equal", r"\P{gc!=Separator}"),
    ("gencat-surrogate-short", r"\p{cs}"),
    ("gencat-surrogate-long", r"\p{Surrogate}"),
    ("gencat-is-c-collision", r"\p{IsC}"),
    ("gencat-is-cf-collision", r"\p{IsCf}"),
    ("gencat-digit", r"\d"),
    ("gencat-digit-casefold", r"(?i:\d)"),
    ("gencat-bracket-digit-casefold", r"(?i:[\d])"),
    ("gencat-property-casefold", r"(?i:\pL)"),
    ("perl", r"\b\w\b"),
    ("perl-digit", r"\d"),
    ("perl-digit-negated", r"\D"),
    ("perl-space", r"\s"),
    ("perl-space-negated", r"\S"),
    ("perl-word", r"\w"),
    ("perl-word-negated", r"\W"),
    ("perl-space-is-prefix", r"\p{IsWhite_Space}"),
    ("perl-space-short-alias", r"\p{wspace}"),
    ("perl-decimal-named-value", r"\p{gc=Nd}"),
    ("perl-decimal-normalized", r"\p{Is_G-C=D_e-cimal Number}"),
    ("perl-binary-named-value", r"\p{White_Space=Yes}"),
    ("perl-set", r"[\w&&[\s&&\d]]"),
    ("script", r"\p{Greek}"),
    ("script-short", r"\p{Grek}"),
    ("script-is-prefix", r"\p{IsGreek}"),
    ("script-named-value", r"\p{Script=Greek}"),
    ("script-named-short", r"\p{sc=Grek}"),
    ("script-extension", r"\p{Script_Extensions=Hiragana}"),
    ("script-extension-short", r"\p{scx=Hira}"),
    ("script-normalized", r"\p{Is_S-c r i p t=G_r-e e k}"),
    ("script-invalid-value", r"\p{sc=definitely-invalid}"),
    ("script-bare-property", r"\p{Script}"),
    ("script-set", r"[\p{Greek}&&[\p{scx=Common}--\p{Latin}]]"),
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
    ("i-direct-perl-all", r"(?i:\d\s\w)"),
    ("i-bracket-perl", r"(?i:[\w])"),
    ("scoped-order", r"(?i)(?-u:a)(?-i:\u{03B4})"),
    ("nested-case-scope", r"(?i:(?-i:\u{03B4})a)"),
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
    for (index, &alias) in GENCAT_ALIASES.iter().enumerate() {
        let pattern = format!(r"\p{{{alias}}}");
        let passed = ParserBuilder::new().build().parse(&pattern).is_ok();
        println!("gencat-alias-{index}:{alias}\t{}", u8::from(passed));
    }
    for (index, &alias) in SCRIPT_ALIASES.iter().enumerate() {
        for (kind, pattern) in [
            ("bare", format!(r"\p{{{alias}}}")),
            ("sc", format!(r"\p{{sc={alias}}}")),
            ("scx", format!(r"\p{{scx={alias}}}")),
        ] {
            let passed = ParserBuilder::new().build().parse(&pattern).is_ok();
            println!(
                "script-alias-{index}:{kind}:{alias}\t{}",
                u8::from(passed)
            );
        }
    }
}
