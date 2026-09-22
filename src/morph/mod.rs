//! Rule-based Russian morphological inflection for PII tokens.
//!
//! No external libraries or network dictionaries. All ending tables and
//! exceptions live in `const` arrays at the top of this module.

/// Grammatical case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Case {
    Nom,
    Gen,
    Dat,
    Acc,
    Ins,
    Prep,
}

impl Case {
    /// Parse a case name. Accepts Russian and Latin aliases, case-insensitive.
    pub fn parse(s: &str) -> Option<Case> {
        let s = s.trim().to_lowercase();
        match s.as_str() {
            "им" | "nom" => Some(Case::Nom),
            "род" | "gen" => Some(Case::Gen),
            "дат" | "dat" => Some(Case::Dat),
            "вин" | "acc" => Some(Case::Acc),
            "твор" | "тв" | "ins" => Some(Case::Ins),
            "пр" | "предл" | "prep" => Some(Case::Prep),
            _ => None,
        }
    }
}

/// Grammatical gender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gender {
    Male,
    Female,
    Unknown,
}

/// Kind of the value being inflected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Person,
    Place,
    Country,
    Street,
}

// ---------------------------------------------------------------------------
// Ending tables and exceptions (Cyrillic allowed only here).
// ---------------------------------------------------------------------------

/// Male surnames ending in a consonant: -ов/-ев/-ёв/-ин/-ын.
const M_SURNAME_OV: [&str; 6] = ["", "а", "у", "а", "ым", "е"];
/// Male surnames ending in -ский/-цкий/-ой/-ый.
const M_SURNAME_SKY: [&str; 6] = ["", "ого", "ому", "ого", "им", "ом"];
/// Male surnames ending in -ой/-ый (instrumental -ым).
const M_SURNAME_SKY_Y: [&str; 6] = ["", "ого", "ому", "ого", "ым", "ом"];
/// Male surnames ending in a plain consonant (Шмидт, Гусак).
const M_SURNAME_CONS: [&str; 6] = ["", "а", "у", "а", "ом", "е"];

/// Female surnames ending in -ова/-ева/-ина/-ына.
const F_SURNAME_OVA: [&str; 6] = ["", "ой", "ой", "у", "ой", "ой"];
/// Female surnames ending in -ская/-цкая/-ая.
const F_SURNAME_SKA: [&str; 6] = ["", "ой", "ой", "ую", "ой", "ой"];

/// Male given names ending in a consonant (Иван).
const M_NAME_CONS: [&str; 6] = ["", "а", "у", "а", "ом", "е"];
/// Male given names ending in -й (Андрей, Сергей).
const M_NAME_Y: [&str; 6] = ["й", "я", "ю", "я", "ем", "е"];
/// Male given names ending in -ь (Игорь).
const M_NAME_SOFT: [&str; 6] = ["ь", "я", "ю", "я", "ем", "е"];

/// Names ending in -а (Анна).
const NAME_A: [&str; 6] = ["а", "ы", "е", "у", "ой", "е"];
/// Names ending in -я (Илья).
const NAME_YA: [&str; 6] = ["я", "и", "е", "ю", "ей", "е"];
/// Names ending in -ия (Мария).
const NAME_IYA: [&str; 6] = ["ия", "ии", "ии", "ию", "ией", "ии"];

/// Patronymics ending in -ович.
const PAT_OVICH: [&str; 6] = ["", "а", "у", "а", "ем", "е"];
/// Patronymics ending in -овна.
const PAT_OVNA: [&str; 6] = ["а", "ы", "е", "у", "ой", "е"];

/// Male given-name exceptions: nominative -> full case forms.
const M_NAME_EXC: [(&str, [&str; 6]); 3] = [
    ("лев", ["лев", "льва", "льву", "льва", "львом", "льве"]),
    ("павел", ["павел", "павла", "павлу", "павла", "павлом", "павле"]),
    ("пётр", ["пётр", "петра", "петру", "петра", "петром", "петре"]),
];

/// Female given-name exceptions: nominative -> full case forms.
const F_NAME_EXC: [(&str, [&str; 6]); 1] = [
    ("любовь", ["любовь", "любови", "любови", "любовь", "любовью", "любови"]),
];

/// Feminine words ending in -ь (Тверь, Казань, Беларусь).
const F_SOFT: [&str; 6] = ["ь", "и", "и", "ь", "ью", "и"];

/// Inanimate place names ending in a consonant (Омск, Пушкин): Acc = Nom.
const PLACE_CONS: [&str; 6] = ["", "а", "у", "", "ом", "е"];

/// Reverse lookup for given-name exceptions: case form -> nominative.
const NAME_REV_EXC: [(&str, [&str; 6]); 4] = [
    ("лев", ["лев", "льва", "льву", "льва", "львом", "льве"]),
    ("павел", ["павел", "павла", "павлу", "павла", "павлом", "павле"]),
    ("пётр", ["пётр", "петра", "петру", "петра", "петром", "петре"]),
    ("любовь", ["любовь", "любови", "любови", "любовь", "любовью", "любови"]),
];

/// Male names ending in -а/-я that are masculine (Илья, Никита, ...).
const MALE_A_NAMES: [&str; 6] = ["илья", "никита", "кузьма", "фома", "лука", "савва"];

/// Prefixes preserved verbatim before a Place name.
const PLACE_PREFIXES: [&str; 5] = ["г.", "город", "с.", "пос.", "дер."];

/// Street prefixes preserved verbatim; only the following adjective inflects.
const STREET_PREFIXES: [&str; 4] = ["ул.", "улица", "проспект", "пр."];

// ---------------------------------------------------------------------------
// Dictionaries (loaded once via include_str).
// ---------------------------------------------------------------------------

static FIRST_NAMES: once_cell::sync::Lazy<std::collections::HashSet<String>> =
    once_cell::sync::Lazy::new(|| {
        include_str!("../../data/dict/first_names.txt")
            .lines()
            .map(|l| l.trim().to_lowercase())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    });

static CITIES: once_cell::sync::Lazy<std::collections::HashSet<String>> =
    once_cell::sync::Lazy::new(|| {
        include_str!("../../data/dict/cities.txt")
            .lines()
            .map(|l| l.trim().to_lowercase())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    });

static COUNTRIES: once_cell::sync::Lazy<std::collections::HashSet<String>> =
    once_cell::sync::Lazy::new(|| {
        include_str!("../../data/dict/countries.txt")
            .lines()
            .map(|l| l.trim().to_lowercase())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    });

fn is_first_name(w: &str) -> bool {
    FIRST_NAMES.contains(w)
}

fn is_city(w: &str) -> bool {
    CITIES.contains(w)
}

fn is_country(w: &str) -> bool {
    COUNTRIES.contains(w)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn is_vowel(c: char) -> bool {
    matches!(c, 'а' | 'е' | 'ё' | 'и' | 'о' | 'у' | 'ы' | 'э' | 'ю' | 'я')
}

fn is_consonant(c: char) -> bool {
    c.is_alphabetic() && !is_vowel(c)
}

fn words(value: &str) -> Vec<&str> {
    value.split_whitespace().collect()
}

/// Detect the case style of the original value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Style {
    Upper,
    Title,
    Lower,
}

fn style_of(value: &str) -> Style {
    let letters: Vec<char> = value.chars().filter(|c| c.is_alphabetic()).collect();
    if letters.is_empty() {
        return Style::Lower;
    }
    if letters.iter().all(|c| c.is_uppercase()) {
        Style::Upper
    } else if letters[0].is_uppercase() {
        Style::Title
    } else {
        Style::Lower
    }
}

fn apply_style(word: &str, style: Style) -> String {
    match style {
        Style::Upper => word.to_uppercase(),
        Style::Title => {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        }
        Style::Lower => word.to_string(),
    }
}

fn apply_style_phrase(phrase: &str, style: Style) -> String {
    let ws: Vec<&str> = phrase.split_whitespace().collect();
    match style {
        Style::Upper => ws
            .iter()
            .map(|w| w.to_uppercase())
            .collect::<Vec<_>>()
            .join(" "),
        Style::Title => {
            let mut out = Vec::with_capacity(ws.len());
            for (i, w) in ws.iter().enumerate() {
                if i == 0 {
                    out.push(apply_style(w, Style::Title));
                } else {
                    out.push(w.to_string());
                }
            }
            out.join(" ")
        }
        Style::Lower => ws.join(" "),
    }
}

/// Per-word case style of the original value.
fn word_styles(value: &str) -> Vec<Style> {
    words(value).iter().map(|w| style_of(w)).collect()
}

/// Apply per-word styles to an inflected phrase (word counts must match).
fn apply_styles(phrase: &str, styles: &[Style]) -> String {
    let ws: Vec<&str> = phrase.split_whitespace().collect();
    ws.iter()
        .zip(styles)
        .map(|(w, s)| apply_style(w, *s))
        .collect::<Vec<_>>()
        .join(" ")
}

fn case_index(case: Case) -> usize {
    match case {
        Case::Nom => 0,
        Case::Gen => 1,
        Case::Dat => 2,
        Case::Acc => 3,
        Case::Ins => 4,
        Case::Prep => 5,
    }
}

fn append(stem: &str, ending: &str) -> String {
    format!("{stem}{ending}")
}

fn inflect_word(word: &str, table: &[&str; 6], case: Case) -> Option<String> {
    if case == Case::Nom {
        return Some(word.to_string());
    }
    let stem = word.strip_suffix(table[0])?;
    Some(append(stem, table[case_index(case)]))
}

/// Inflect a word ending in -а. Genitive is -ы, but -и after к/г/х/ж/ш/щ/ч.
fn inflect_name_a(word: &str, case: Case) -> Option<String> {
    if case == Case::Nom {
        return Some(word.to_string());
    }
    let stem = word.strip_suffix('а')?;
    let ending = match case {
        Case::Gen => {
            if stem.ends_with(['к', 'г', 'х', 'ж', 'ш', 'щ', 'ч']) {
                "и"
            } else {
                "ы"
            }
        }
        Case::Dat => "е",
        Case::Acc => "у",
        Case::Ins => "ой",
        Case::Prep => "е",
        Case::Nom => "",
    };
    Some(append(stem, ending))
}

// ---------------------------------------------------------------------------
// Person inflection
// ---------------------------------------------------------------------------

fn is_patronymic(w: &str) -> bool {
    w.ends_with("ович")
        || w.ends_with("евич")
        || w.ends_with("ич")
        || w.ends_with("овна")
        || w.ends_with("евна")
        || w.ends_with("ична")
        || w.ends_with("инична")
}

/// True if `w` ends with any of the given suffixes.
fn ends_with_any(w: &str, suffixes: &[&str]) -> bool {
    suffixes.iter().any(|s| w.ends_with(s))
}

/// Strips a suffix from `w` and returns the stem when it satisfies `pred`.
fn strip_ends_with(w: &str, suffixes: &[&str], pred: impl Fn(&str) -> bool) -> Option<String> {
    for suf in suffixes {
        if let Some(stem) = w.strip_suffix(suf) {
            if pred(stem) {
                return Some(stem.to_string());
            }
        }
    }
    None
}

/// Strips a suffix and appends `nom_suf`, returning the candidate when `is_word` accepts it.
fn normalize_by_pairs(w: &str, pairs: &[(&str, &str)], is_word: impl Fn(&str) -> bool) -> Option<String> {
    for (suf, nom_suf) in pairs {
        if let Some(stem) = w.strip_suffix(suf) {
            if !stem.is_empty() {
                let cand = stem.to_string() + nom_suf;
                if is_word(&cand) {
                    return Some(cand);
                }
            }
        }
    }
    None
}

/// Strips a suffix and appends `nom_suf` without any dictionary check.
fn strip_append(w: &str, pairs: &[(&str, &str)]) -> Option<String> {
    for (suf, nom_suf) in pairs {
        if let Some(stem) = w.strip_suffix(suf) {
            if !stem.is_empty() {
                return Some(stem.to_string() + nom_suf);
            }
        }
    }
    None
}

/// Strips a suffix and returns the stem when it ends in a consonant.
fn strip_consonant(w: &str, suffixes: &[&str]) -> Option<String> {
    for suf in suffixes {
        if let Some(stem) = w.strip_suffix(suf) {
            if !stem.is_empty() && stem.ends_with(is_consonant) {
                return Some(stem.to_string());
            }
        }
    }
    None
}

/// Reverse-normalize a patronymic (any case) to nominative.
fn normalize_patronymic(w: &str) -> Option<String> {
    // -ович/-евич/-ич (masculine): strip а/у/ем/е.
    for suf in ["а", "у", "ем", "е"] {
        if let Some(stem) = w.strip_suffix(suf) {
            if is_patronymic(stem) {
                return Some(stem.to_string());
            }
        }
    }
    // -овна/-евна/-ична/-инична (feminine): strip case ending, append "а".
    for suf in ["ы", "е", "у", "ой"] {
        if let Some(stem) = w.strip_suffix(suf) {
            let cand = stem.to_string() + "а";
            if is_patronymic(&cand) {
                return Some(cand);
            }
        }
    }
    if is_patronymic(w) {
        return Some(w.to_string());
    }
    None
}

/// Reverse-normalize a given name (any case) to nominative.
fn normalize_name(w: &str) -> Option<String> {
    for (nom, forms) in NAME_REV_EXC {
        if forms.contains(&w) {
            return Some(nom.to_string());
        }
    }
    // -ия
    if let Some(cand) = normalize_by_pairs(w, &[("ии", "ия"), ("ию", "ия"), ("ией", "ия")], is_first_name) {
        return Some(cand);
    }
    // -а
    if let Some(cand) = normalize_by_pairs(w, &[("ой", "а"), ("ы", "а"), ("у", "а"), ("е", "а")], is_first_name) {
        return Some(cand);
    }
    // -я
    if let Some(cand) = normalize_by_pairs(w, &[("и", "я"), ("ю", "я"), ("ей", "я"), ("е", "я")], is_first_name) {
        return Some(cand);
    }
    // -й
    if let Some(cand) = normalize_by_pairs(w, &[("я", "й"), ("ю", "й"), ("ем", "й"), ("е", "й")], is_first_name) {
        return Some(cand);
    }
    // -ь
    if let Some(cand) = normalize_by_pairs(w, &[("я", "ь"), ("ю", "ь"), ("ем", "ь"), ("е", "ь")], is_first_name) {
        return Some(cand);
    }
    // consonant
    if let Some(stem) = strip_ends_with(w, &["а", "у", "ом", "е"], is_first_name) {
        return Some(stem);
    }
    if is_first_name(w) {
        return Some(w.to_string());
    }
    None
}

fn is_indeclinable_surname(w: &str) -> bool {
    if w.ends_with("ых") || w.ends_with("их") {
        return true;
    }
    let last = w.chars().last().unwrap_or(' ');
    if matches!(last, 'о' | 'е' | 'и' | 'у' | 'ю') {
        return true;
    }
    if w.ends_with('а') && w.len() > 1 {
        let chars: Vec<char> = w.chars().collect();
        let second_last = chars[chars.len() - 2];
        if is_vowel(second_last) {
            return true;
        }
    }
    false
}

/// Reverse-normalize a male surname (any case) to nominative.
fn normalize_surname_male(w: &str) -> Option<String> {
    // -ов/-ев/-ёв/-ин/-ын (nominative or inflected).
    if ends_with_any(w, &["ов", "ев", "ёв", "ин", "ын"]) {
        return Some(w.to_string());
    }
    if let Some(stem) = strip_ends_with(w, &["ым", "а", "у", "е"], |s| {
        ends_with_any(s, &["ов", "ев", "ёв", "ин", "ын"])
    }) {
        return Some(stem);
    }
    // -ский/-цкий (nominative or inflected).
    if w.ends_with("ский") || w.ends_with("цкий") {
        return Some(w.to_string());
    }
    if let Some(stem) = strip_ends_with(w, &["ого", "ому", "им", "ом"], |s| s.ends_with("ск")) {
        return Some(stem + "ий");
    }
    // -ой/-ый (nominative or inflected).
    if w.ends_with("ой") || w.ends_with("ый") {
        return Some(w.to_string());
    }
    if let Some(stem) = strip_ends_with(w, &["ого", "ому", "ым", "ом"], |s| s.ends_with(is_consonant)) {
        return Some(stem + "ой");
    }
    // Plain consonant (nominative or inflected).
    if w.ends_with(is_consonant) {
        return Some(w.to_string());
    }
    if let Some(stem) = strip_ends_with(w, &["ом", "а", "у", "е"], |s| s.ends_with(is_consonant)) {
        return Some(stem);
    }
    None
}

/// Reverse-normalize a female surname (any case) to nominative.
fn normalize_surname_female(w: &str) -> Option<String> {
    // -ова/-ева/-ина/-ына (nominative or inflected).
    if ends_with_any(w, &["ова", "ева", "ина", "ына"]) {
        return Some(w.to_string());
    }
    if let Some(stem) = strip_ends_with(w, &["ой", "у"], |s| {
        ends_with_any(s, &["ов", "ев", "ёв", "ин", "ын"])
    }) {
        return Some(stem + "а");
    }
    // -ская/-цкая/-ая (nominative or inflected).
    if w.ends_with("ая") {
        return Some(w.to_string());
    }
    if let Some(stem) = strip_ends_with(w, &["ой", "ую"], |s| s.ends_with("ск") || s.ends_with("цк")) {
        return Some(stem + "ая");
    }
    // Female surname ending in a consonant is indeclinable.
    if w.ends_with(is_consonant) {
        return Some(w.to_string());
    }
    None
}

/// Reverse-normalize a surname (any case) to nominative.
fn normalize_surname(w: &str, gender: Gender) -> Option<String> {
    let result = match gender {
        Gender::Male => normalize_surname_male(w),
        Gender::Female => normalize_surname_female(w),
        Gender::Unknown => {
            if let Some(m) = normalize_surname_male(w) {
                return Some(m);
            }
            normalize_surname_female(w)
        }
    };
    // Fallback: genuinely indeclinable surnames (Шевченко, Черных, ...).
    if result.is_none() && is_indeclinable_surname(w) {
        return Some(w.to_string());
    }
    result
}

/// Inflect a nominative male surname to a case.
fn inflect_surname_male(word: &str, case: Case) -> Option<String> {
    if ends_with_any(word, &["ов", "ев", "ёв", "ин", "ын"]) {
        return Some(append(word, M_SURNAME_OV[case_index(case)]));
    }
    if word.ends_with("ский") || word.ends_with("цкий") {
        let stem = word.strip_suffix("ий")?;
        return Some(append(stem, M_SURNAME_SKY[case_index(case)]));
    }
    if word.ends_with("ой") || word.ends_with("ый") {
        let stem = word.strip_suffix("ой").or_else(|| word.strip_suffix("ый"))?;
        return Some(append(stem, M_SURNAME_SKY_Y[case_index(case)]));
    }
    if word.ends_with(is_consonant) {
        return inflect_word(word, &M_SURNAME_CONS, case);
    }
    None
}

/// Inflect a nominative female surname to a case.
fn inflect_surname_female(word: &str, case: Case) -> Option<String> {
    if ends_with_any(word, &["ова", "ева", "ина", "ына"]) {
        let stem = word.strip_suffix('а')?;
        return Some(append(stem, F_SURNAME_OVA[case_index(case)]));
    }
    if word.ends_with("ая") {
        let stem = word.strip_suffix("ая")?;
        return Some(append(stem, F_SURNAME_SKA[case_index(case)]));
    }
    if word.ends_with(is_consonant) {
        return Some(word.to_string());
    }
    None
}

/// Inflect a nominative surname to a case.
fn inflect_surname(word: &str, gender: Gender, case: Case) -> Option<String> {
    if case == Case::Nom {
        return Some(word.to_string());
    }
    if is_indeclinable_surname(word) {
        return Some(word.to_string());
    }
    match gender {
        Gender::Male => inflect_surname_male(word, case),
        Gender::Female => inflect_surname_female(word, case),
        Gender::Unknown => {
            if let Some(m) = inflect_surname_male(word, case) {
                return Some(m);
            }
            inflect_surname_female(word, case)
        }
    }
}

/// Inflect a nominative given name to a case.
fn inflect_name(word: &str, gender: Gender, case: Case) -> Option<String> {
    if case == Case::Nom {
        return Some(word.to_string());
    }
    if let Some(inflected) = name_exception(word, case) {
        return Some(inflected);
    }
    if word.ends_with("ия") && word.len() > 2 {
        return inflect_word(word, &NAME_IYA, case);
    }
    if word.ends_with('а') && word.len() > 1 {
        return inflect_name_a(word, case);
    }
    if word.ends_with('я') && word.len() > 1 {
        return inflect_word(word, &NAME_YA, case);
    }
    if word.ends_with('й') && word.len() > 1 {
        return inflect_word(word, &M_NAME_Y, case);
    }
    if word.ends_with('ь') && word.len() > 1 {
        return inflect_word(word, &M_NAME_SOFT, case);
    }
    if word.ends_with(is_consonant) {
        return inflect_word(word, &M_NAME_CONS, case);
    }
    None
}

/// Looks up a given name in the male/female exception tables.
fn name_exception(word: &str, case: Case) -> Option<String> {
    for (nom, table) in M_NAME_EXC {
        if word == nom {
            return Some(table[case_index(case)].to_string());
        }
    }
    for (nom, table) in F_NAME_EXC {
        if word == nom {
            return Some(table[case_index(case)].to_string());
        }
    }
    None
}

/// Inflect a nominative patronymic to a case.
fn inflect_patronymic(word: &str, case: Case) -> Option<String> {
    if case == Case::Nom {
        return Some(word.to_string());
    }
    for suf in ["ович", "евич", "ич"] {
        if word.ends_with(suf) {
            return inflect_word(word, &PAT_OVICH, case);
        }
    }
    for suf in ["овна", "евна", "ична", "инична"] {
        if word.ends_with(suf) {
            return inflect_word(word, &PAT_OVNA, case);
        }
    }
    None
}

/// Determine gender from normalized patronymics and given names.
fn gender_of_normalized(normalized: &[String], is_patr: &[bool], is_name: &[bool]) -> Gender {
    if let Some(g) = gender_from_patronymics(normalized, is_patr) {
        return g;
    }
    gender_from_names(normalized, is_name)
}

/// Gender from a patronymic suffix ("ович"/"евич"/"ич" male, "овна"/"евна"/"ична"/"инична" female).
fn gender_from_patronymics(normalized: &[String], is_patr: &[bool]) -> Option<Gender> {
    for (i, w) in normalized.iter().enumerate() {
        if !is_patr[i] {
            continue;
        }
        if w.ends_with("ович") || w.ends_with("евич") || w.ends_with("ич") {
            return Some(Gender::Male);
        }
        if w.ends_with("овна") || w.ends_with("евна") || w.ends_with("ична") || w.ends_with("инична") {
            return Some(Gender::Female);
        }
    }
    None
}

/// Gender from a given name: male names in `MALE_A_NAMES`, names ending in 'а'/'я' female,
/// otherwise male.
fn gender_from_names(normalized: &[String], is_name: &[bool]) -> Gender {
    for (i, w) in normalized.iter().enumerate() {
        if !is_name[i] {
            continue;
        }
        if MALE_A_NAMES.contains(&w.as_str()) {
            return Gender::Male;
        }
        if w.ends_with('а') || w.ends_with('я') {
            return Gender::Female;
        }
        return Gender::Male;
    }
    Gender::Unknown
}

/// True if every word is a single-letter initial (e.g. "И. И. Иванов").
fn all_initials(ws: &[&str]) -> bool {
    ws.iter().all(|w| {
        let t = w.trim_end_matches('.');
        let mut chars = t.chars();
        match chars.next() {
            Some(c) if c.is_alphabetic() => chars.next().is_none(),
            _ => false,
        }
    })
}

/// Normalize patronymics and given names to nominative (gender-independent).
fn normalize_person_words(lower_refs: &[&str]) -> (Vec<String>, Vec<bool>, Vec<bool>) {
    let mut normalized: Vec<String> = Vec::with_capacity(lower_refs.len());
    let mut is_patr: Vec<bool> = Vec::with_capacity(lower_refs.len());
    let mut is_name: Vec<bool> = Vec::with_capacity(lower_refs.len());
    for w in lower_refs {
        let w = w.trim_end_matches('.');
        if w.chars().count() == 1 {
            normalized.push(w.to_string());
            is_patr.push(false);
            is_name.push(false);
        } else if let Some(p) = normalize_patronymic(w) {
            normalized.push(p);
            is_patr.push(true);
            is_name.push(false);
        } else if let Some(n) = normalize_name(w) {
            normalized.push(n);
            is_patr.push(false);
            is_name.push(true);
        } else {
            normalized.push(w.to_string());
            is_patr.push(false);
            is_name.push(false);
        }
    }
    (normalized, is_patr, is_name)
}

/// Normalize surnames with the resolved gender, keeping names and patronymics as-is.
fn resolve_surnames(normalized: &[String], is_patr: &[bool], is_name: &[bool], gender: Gender) -> Vec<String> {
    let mut final_nom: Vec<String> = Vec::with_capacity(normalized.len());
    for (i, w) in normalized.iter().enumerate() {
        if is_patr[i] || is_name[i] {
            final_nom.push(w.clone());
        } else if let Some(s) = normalize_surname(w, gender) {
            final_nom.push(s);
        } else {
            final_nom.push(w.clone());
        }
    }
    final_nom
}

fn inflect_person(value: &str, case: Case) -> Option<String> {
    let ws = words(value);
    if ws.is_empty() || ws.len() > 3 {
        return None;
    }
    if all_initials(&ws) {
        return Some(value.to_string());
    }

    let lower: Vec<String> = ws.iter().map(|w| w.to_lowercase()).collect();
    let lower_refs: Vec<&str> = lower.iter().map(|s| s.as_str()).collect();

    let (normalized, is_patr, is_name) = normalize_person_words(&lower_refs);
    let gender = gender_of_normalized(&normalized, &is_patr, &is_name);
    let final_nom = resolve_surnames(&normalized, &is_patr, &is_name, gender);

    let mut out: Vec<String> = Vec::with_capacity(ws.len());
    for (i, w) in final_nom.iter().enumerate() {
        let w_clean = w.trim_end_matches('.');
        let inflected = if is_patr[i] {
            inflect_patronymic(w_clean, case)?
        } else if is_name[i] {
            inflect_name(w_clean, gender, case)?
        } else {
            inflect_surname(w_clean, gender, case)?
        };
        out.push(inflected);
    }

    let joined = out.join(" ");
    let styles = word_styles(value);
    Some(apply_styles(&joined, &styles))
}

// ---------------------------------------------------------------------------
// Place inflection
// ---------------------------------------------------------------------------

/// Reverse-normalize a place word (any case) to nominative.
fn normalize_place_word(w: &str) -> Option<String> {
    if is_city(w) {
        return Some(w.to_string());
    }
    // -а
    if let Some(cand) = normalize_by_pairs(w, &[("ой", "а"), ("ы", "а"), ("у", "а"), ("е", "а")], is_city) {
        return Some(cand);
    }
    // -я
    if let Some(cand) = normalize_by_pairs(w, &[("и", "я"), ("ю", "я"), ("ей", "я"), ("е", "я")], is_city) {
        return Some(cand);
    }
    // -ь
    if let Some(cand) = normalize_by_pairs(w, &[("и", "ь"), ("ью", "ь"), ("е", "ь")], is_city) {
        return Some(cand);
    }
    // consonant
    if let Some(stem) = strip_consonant(w, &["а", "у", "ом", "е"]) {
        if is_city(&stem) {
            return Some(stem);
        }
    }
    if is_city(w) {
        return Some(w.to_string());
    }
    // Fallback for compound nouns not present in the dictionary (e.g. Новгород).
    if let Some(stem) = strip_consonant(w, &["а", "у", "ом", "е"]) {
        return Some(stem);
    }
    if let Some(cand) = strip_append(w, &[("ой", "а"), ("ы", "а"), ("у", "а"), ("е", "а")]) {
        return Some(cand);
    }
    if let Some(cand) = strip_append(w, &[("и", "ь"), ("ью", "ь"), ("е", "ь")]) {
        return Some(cand);
    }
    // Already nominative consonant word (e.g. Новгород).
    if w.ends_with(is_consonant) {
        return Some(w.to_string());
    }
    None
}

/// Inflect a nominative place word to a case.
fn inflect_place_word(w: &str, case: Case) -> Option<String> {
    if case == Case::Nom {
        return Some(w.to_string());
    }
    let last = w.chars().last().unwrap_or(' ');
    if matches!(last, 'о' | 'е' | 'и' | 'у') {
        return Some(w.to_string());
    }
    if w.ends_with('а') && w.len() > 1 {
        return inflect_name_a(w, case);
    }
    if w.ends_with('я') && w.len() > 1 {
        return inflect_word(w, &NAME_YA, case);
    }
    if w.ends_with('ь') && w.len() > 1 {
        return inflect_word(w, &F_SOFT, case);
    }
    if w.ends_with(is_consonant) {
        return inflect_word(w, &PLACE_CONS, case);
    }
    None
}

/// Reverse-normalize a masculine/feminine adjective to nominative.
fn normalize_adjective(w: &str) -> Option<String> {
    for (suf, nom_suf) in [("ой", "ая"), ("ую", "ая"), ("ее", "ая"), ("ей", "ая")] {
        if let Some(stem) = w.strip_suffix(suf) {
            if !stem.is_empty() {
                return Some(stem.to_string() + nom_suf);
            }
        }
    }
    for (suf, nom_suf) in [
        ("его", "ий"),
        ("ему", "ий"),
        ("им", "ий"),
        ("ем", "ий"),
        ("ого", "ий"),
        ("ому", "ий"),
        ("ом", "ий"),
    ] {
        if let Some(stem) = w.strip_suffix(suf) {
            if !stem.is_empty() {
                return Some(stem.to_string() + nom_suf);
            }
        }
    }
    if w.ends_with("ий") || w.ends_with("ый") || w.ends_with("ая") || w.ends_with("яя") {
        return Some(w.to_string());
    }
    None
}

/// Inflect a nominative masculine adjective to a case.
fn inflect_adjective(w: &str, case: Case) -> Option<String> {
    if case == Case::Nom || case == Case::Acc {
        return Some(w.to_string());
    }
    if w.ends_with("ий") || w.ends_with("ый") {
        let stem = w.strip_suffix("ий").or_else(|| w.strip_suffix("ый"))?;
        let (gen, dat, prep) = if stem.ends_with(['к', 'г', 'х']) {
            ("ого", "ому", "ом")
        } else {
            ("его", "ему", "ем")
        };
        let ending = match case {
            Case::Gen => gen,
            Case::Dat => dat,
            Case::Acc => "",
            Case::Ins => "им",
            Case::Prep => prep,
            Case::Nom => "",
        };
        return Some(format!("{stem}{ending}"));
    }
    None
}

/// Inflect a nominative feminine adjective to a case.
fn inflect_adjective_f(w: &str, case: Case) -> Option<String> {
    if case == Case::Nom {
        return Some(w.to_string());
    }
    if w.ends_with("ая") || w.ends_with("яя") {
        let stem = w.strip_suffix("ая").or_else(|| w.strip_suffix("яя"))?;
        let ending = match case {
            Case::Gen => "ой",
            Case::Dat => "ой",
            Case::Acc => "ую",
            Case::Ins => "ой",
            Case::Prep => "ой",
            Case::Nom => "",
        };
        return Some(format!("{stem}{ending}"));
    }
    None
}

fn inflect_place(value: &str, case: Case) -> Option<String> {
    let ws = words(value);
    if ws.is_empty() || ws.len() > 3 {
        return None;
    }

    let mut prefix: Vec<&str> = Vec::new();
    let mut name_words: Vec<&str> = Vec::new();
    for w in &ws {
        let wl = w.to_lowercase();
        if name_words.is_empty() && PLACE_PREFIXES.contains(&wl.as_str()) {
            prefix.push(w);
        } else {
            name_words.push(w);
        }
    }
    if name_words.is_empty() {
        return None;
    }

    let lower: Vec<String> = name_words.iter().map(|w| w.to_lowercase()).collect();
    let lower_refs: Vec<&str> = lower.iter().map(|s| s.as_str()).collect();

    let inflected = if lower_refs.len() == 1 {
        // Normalize to nominative, then inflect.
        let nom = normalize_place_word(lower_refs[0])?;
        inflect_place_word(&nom, case)?
    } else {
        // Multi-word: adjective + noun (Нижний Новгород).
        let adj_nom = normalize_adjective(lower_refs[0])?;
        let noun_nom = normalize_place_word(lower_refs[1])?;
        let adj_inf = inflect_adjective(&adj_nom, case)?;
        let noun_inf = inflect_place_word(&noun_nom, case)?;
        format!("{adj_inf} {noun_inf}")
    };

    let mut parts: Vec<String> = prefix.iter().map(|p| p.to_string()).collect();
    parts.push(inflected);
    let joined = parts.join(" ");
    let styles = word_styles(value);
    Some(apply_styles(&joined, &styles))
}

// ---------------------------------------------------------------------------
// Country inflection
// ---------------------------------------------------------------------------

/// Reverse-normalize a country word (any case) to nominative.
fn normalize_country_word(w: &str) -> Option<String> {
    if let Some(cand) = normalize_by_pairs(w, &[("ии", "ия"), ("ию", "ия"), ("ией", "ия")], is_country) {
        return Some(cand);
    }
    if let Some(cand) = normalize_by_pairs(w, &[("ой", "а"), ("ы", "а"), ("у", "а"), ("е", "а")], is_country) {
        return Some(cand);
    }
    if let Some(cand) = normalize_by_pairs(w, &[("и", "ь"), ("ью", "ь"), ("е", "ь")], is_country) {
        return Some(cand);
    }
    if let Some(stem) = strip_consonant(w, &["а", "у", "ом", "е"]) {
        if is_country(&stem) {
            return Some(stem);
        }
    }
    if is_country(w) {
        return Some(w.to_string());
    }
    // Fallback for compound nouns not present in the dictionary.
    if let Some(stem) = strip_consonant(w, &["а", "у", "ом", "е"]) {
        return Some(stem);
    }
    if let Some(cand) = strip_append(w, &[("ой", "а"), ("ы", "а"), ("у", "а"), ("е", "а")]) {
        return Some(cand);
    }
    if let Some(cand) = strip_append(w, &[("и", "ь"), ("ью", "ь"), ("е", "ь")]) {
        return Some(cand);
    }
    None
}

/// Inflect a nominative country word to a case.
fn inflect_country_word(w: &str, case: Case) -> Option<String> {
    if case == Case::Nom {
        return Some(w.to_string());
    }
    if w.ends_with("ия") && w.len() > 2 {
        return inflect_word(w, &NAME_IYA, case);
    }
    if w.ends_with('ь') && w.len() > 1 {
        return inflect_word(w, &F_SOFT, case);
    }
    if w.ends_with('а') && w.len() > 1 {
        return inflect_name_a(w, case);
    }
    if w.ends_with(is_consonant) {
        return inflect_word(w, &PLACE_CONS, case);
    }
    None
}

/// Reverse-normalize "республика" (any case) to nominative.
fn normalize_republic(w: &str) -> Option<String> {
    if w == "республика" {
        return Some("республика".to_string());
    }
    for suf in ["ой", "у", "е", "и"] {
        if let Some(stem) = w.strip_suffix(suf) {
            if stem == "республик" {
                return Some("республика".to_string());
            }
        }
    }
    None
}

fn inflect_country(value: &str, case: Case) -> Option<String> {
    let ws = words(value);
    if ws.is_empty() {
        return None;
    }

    let inflected = if ws.len() >= 2 {
        let first_nom = normalize_republic(&ws[0].to_lowercase());
        if first_nom.as_deref() == Some("республика") {
            let rep = inflect_country_word("республика", case)?;
            let rest = ws[1..].join(" ");
            format!("{rep} {rest}")
        } else if ws.len() == 2 {
            let adj = ws[0].to_lowercase();
            let noun = ws[1].to_lowercase();
            {
                let adj_nom = normalize_adjective(&adj)?;
                let noun_nom = normalize_country_word(&noun)?;
                let adj_inf = if adj_nom.ends_with("ая") || adj_nom.ends_with("яя") {
                    inflect_adjective_f(&adj_nom, case)?
                } else {
                    inflect_adjective(&adj_nom, case)?
                };
                let noun_inf = inflect_country_word(&noun_nom, case)?;
                format!("{adj_inf} {noun_inf}")
            }
        } else {
            return None;
        }
    } else {
        let word = ws[0].to_lowercase();
        let nom = normalize_country_word(&word)?;
        inflect_country_word(&nom, case)?
    };

    let styles = word_styles(value);
    Some(apply_styles(&inflected, &styles))
}

// ---------------------------------------------------------------------------
// Street inflection
// ---------------------------------------------------------------------------

fn inflect_street(value: &str, case: Case) -> Option<String> {
    let ws = words(value);
    if ws.is_empty() {
        return None;
    }

    let mut prefix: Vec<&str> = Vec::new();
    let mut name_words: Vec<&str> = Vec::new();
    for w in &ws {
        let wl = w.to_lowercase();
        if name_words.is_empty() && STREET_PREFIXES.contains(&wl.as_str()) {
            prefix.push(w);
        } else {
            name_words.push(w);
        }
    }
    if name_words.is_empty() {
        return None;
    }

    let lower: Vec<String> = name_words.iter().map(|w| w.to_lowercase()).collect();
    let lower_refs: Vec<&str> = lower.iter().map(|s| s.as_str()).collect();

    let first = lower_refs[0];
    let adj_nom = match normalize_adjective(first) {
        Some(a) => a,
        None => {
            // "ул. Пушкина", "ул. 8 Марта", "проспект Мира" — genitive of a
            // name, do not inflect.
            return Some(value.to_string());
        }
    };
    let adj_inf = if adj_nom.ends_with("ая") || adj_nom.ends_with("яя") {
        inflect_adjective_f(&adj_nom, case)?
    } else {
        inflect_adjective(&adj_nom, case)?
    };

    let mut parts: Vec<String> = prefix.iter().map(|p| p.to_string()).collect();
    if lower_refs.len() >= 2 {
        let noun = lower_refs[1];
        let noun_nom = normalize_place_word(noun).unwrap_or_else(|| noun.to_string());
        let noun_inf = inflect_place_word(&noun_nom, case)?;
        parts.push(format!("{adj_inf} {noun_inf}"));
    } else {
        parts.push(adj_inf);
    }
    let joined = parts.join(" ");
    let styles = word_styles(value);
    Some(apply_styles(&joined, &styles))
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// True if the value contains at least one alphabetic character and every
/// alphabetic character is Cyrillic (rejects Latin words and pure digits).
fn is_plausible_cyrillic(s: &str) -> bool {
    let mut has_alpha = false;
    for c in s.chars() {
        if c.is_alphabetic() {
            has_alpha = true;
            let l = c.to_lowercase().next().unwrap();
            if !(('а'..='я').contains(&l) || l == 'ё') {
                return false;
            }
        }
    }
    has_alpha
}

/// Inflect a value (in any case) to the requested case.
///
/// Returns `None` if the form is not confidently recognized; the caller should
/// then return the original value unchanged.
pub fn inflect(value: &str, kind: Kind, case: Case) -> Option<String> {
    if value.trim().is_empty() || !is_plausible_cyrillic(value) {
        return None;
    }
    match kind {
        Kind::Person => inflect_person(value, case),
        Kind::Place => inflect_place(value, case),
        Kind::Country => inflect_country(value, case),
        Kind::Street => inflect_street(value, case),
    }
}