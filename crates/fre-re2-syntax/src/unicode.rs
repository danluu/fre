//! Names from the pinned generated `re2/unicode_groups.cc` table.

/// The generated upstream table is sorted, so lookup is logarithmic and does
/// not copy or expand its much larger range payload during syntax parsing.
pub(crate) fn is_group(name: &str) -> bool {
    UNICODE_GROUP_NAMES.binary_search(&name).is_ok()
}

#[rustfmt::skip]
const UNICODE_GROUP_NAMES: &[&str] = &[
    "Adlam", "Ahom", "Anatolian_Hieroglyphs", "Any", "Arabic", "Armenian", "Avestan",
    "Balinese", "Bamum", "Bassa_Vah", "Batak", "Bengali", "Bhaiksuki", "Bopomofo",
    "Brahmi", "Braille", "Buginese", "Buhid", "C", "Canadian_Aboriginal", "Carian",
    "Caucasian_Albanian", "Cc", "Cf", "Chakma", "Cham", "Cherokee", "Chorasmian", "Co",
    "Common", "Coptic", "Cs", "Cuneiform", "Cypriot", "Cypro_Minoan", "Cyrillic",
    "Deseret", "Devanagari", "Dives_Akuru", "Dogra", "Duployan", "Egyptian_Hieroglyphs",
    "Elbasan", "Elymaic", "Ethiopic", "Georgian", "Glagolitic", "Gothic", "Grantha",
    "Greek", "Gujarati", "Gunjala_Gondi", "Gurmukhi", "Han", "Hangul", "Hanifi_Rohingya",
    "Hanunoo", "Hatran", "Hebrew", "Hiragana", "Imperial_Aramaic", "Inherited",
    "Inscriptional_Pahlavi", "Inscriptional_Parthian", "Javanese", "Kaithi", "Kannada",
    "Katakana", "Kawi", "Kayah_Li", "Kharoshthi", "Khitan_Small_Script", "Khmer", "Khojki",
    "Khudawadi", "L", "Lao", "Latin", "Lepcha", "Limbu", "Linear_A", "Linear_B", "Lisu",
    "Ll", "Lm", "Lo", "Lt", "Lu", "Lycian", "Lydian", "M", "Mahajani", "Makasar",
    "Malayalam", "Mandaic", "Manichaean", "Marchen", "Masaram_Gondi", "Mc", "Me",
    "Medefaidrin", "Meetei_Mayek", "Mende_Kikakui", "Meroitic_Cursive",
    "Meroitic_Hieroglyphs", "Miao", "Mn", "Modi", "Mongolian", "Mro", "Multani", "Myanmar",
    "N", "Nabataean", "Nag_Mundari", "Nandinagari", "Nd", "New_Tai_Lue", "Newa", "Nko",
    "Nl", "No", "Nushu", "Nyiakeng_Puachue_Hmong", "Ogham", "Ol_Chiki", "Old_Hungarian",
    "Old_Italic", "Old_North_Arabian", "Old_Permic", "Old_Persian", "Old_Sogdian",
    "Old_South_Arabian", "Old_Turkic", "Old_Uyghur", "Oriya", "Osage", "Osmanya", "P",
    "Pahawh_Hmong", "Palmyrene", "Pau_Cin_Hau", "Pc", "Pd", "Pe", "Pf", "Phags_Pa",
    "Phoenician", "Pi", "Po", "Ps", "Psalter_Pahlavi", "Rejang", "Runic", "S", "Samaritan",
    "Saurashtra", "Sc", "Sharada", "Shavian", "Siddham", "SignWriting", "Sinhala", "Sk", "Sm",
    "So", "Sogdian", "Sora_Sompeng", "Soyombo", "Sundanese", "Syloti_Nagri", "Syriac",
    "Tagalog", "Tagbanwa", "Tai_Le", "Tai_Tham", "Tai_Viet", "Takri", "Tamil", "Tangsa",
    "Tangut", "Telugu", "Thaana", "Thai", "Tibetan", "Tifinagh", "Tirhuta", "Toto",
    "Ugaritic", "Vai", "Vithkuqi", "Wancho", "Warang_Citi", "Yezidi", "Yi", "Z",
    "Zanabazar_Square", "Zl", "Zp", "Zs",
];

#[cfg(test)]
mod tests {
    use super::{UNICODE_GROUP_NAMES, is_group};

    #[test]
    fn generated_names_remain_sorted_and_include_special_any() {
        assert_eq!(UNICODE_GROUP_NAMES.len(), 200);
        assert!(UNICODE_GROUP_NAMES.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(is_group("Any"));
        assert!(is_group("Han"));
        assert!(is_group("Zs"));
        assert!(!is_group("NotARe2Group"));
    }
}
