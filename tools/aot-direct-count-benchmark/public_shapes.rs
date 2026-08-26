pub(crate) const WIDTHS: [usize; 6] = [1, 2, 4, 8, 16, 32];

pub(crate) const LITERALS: [&str; 6] = [
    "Q",
    "QQ",
    "Q7Q7",
    "Q7m2Q7m2",
    "Q7m2K9v3Q7m2K9v3",
    "Q7m2K9v3B6x4R8c5Q7m2K9v3B6x4R8c5",
];

pub(crate) fn literal_for_width(width: usize) -> Option<&'static str> {
    WIDTHS
        .iter()
        .position(|candidate| *candidate == width)
        .map(|index| LITERALS[index])
}

#[allow(
    dead_code,
    reason = "the shared shape module uses this only in the runtime half, not the build-script half"
)]
pub(crate) fn primitive_period(literal: &[u8]) -> usize {
    (1..=literal.len())
        .find(|period| {
            literal
                .iter()
                .enumerate()
                .all(|(index, byte)| *byte == literal[index % period])
        })
        .expect("a nonempty literal has its full width as a period")
}
