use detox_proxy::mask::{mask, mask_with_seed, unmask, MaskOptions, Numbering};
use detox_proxy::registry::Registry;
use detox_proxy::types::{Entity, MaskMode, Mapping};
use std::collections::HashMap;

fn load() -> Registry {
    let yaml = std::fs::read_to_string("data/pii_types.yaml").expect("read pii_types.yaml");
    Registry::from_yaml(&yaml).expect("parse registry")
}

fn ent(type_id: &str, start: usize, end: usize) -> Entity {
    Entity {
        type_id: type_id.to_string(),
        start,
        end,
        confidence: 0.9,
    }
}

fn pseudonym_opts(overrides: &HashMap<String, MaskMode>) -> MaskOptions<'_> {
    MaskOptions {
        default_mode: MaskMode::Pseudonym,
        overrides,
        combination_rule: false,
    }
}

fn mask_pseudo(reg: &Registry, text: &str, entities: Vec<Entity>) -> String {
    let overrides = HashMap::new();
    mask(text, &entities, reg, &pseudonym_opts(&overrides)).text
}

fn luhn(digits: &str) -> bool {
    let mut sum = 0;
    let mut double = false;
    for c in digits.chars().rev() {
        let mut d = c.to_digit(10).unwrap();
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }
    sum % 10 == 0
}

fn inn_valid(digits: &str) -> bool {
    let d: Vec<u32> = digits.chars().filter(|c| c.is_ascii_digit()).map(|c| c.to_digit(10).unwrap()).collect();
    match d.len() {
        10 => {
            let coeffs = [2, 4, 10, 3, 5, 9, 4, 6, 8];
            let sum: u32 = coeffs.iter().zip(&d).map(|(&c, &x)| c * x).sum();
            (sum % 11) % 10 == d[9]
        }
        12 => {
            let c1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8];
            let c2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8];
            let s1: u32 = c1.iter().zip(&d).map(|(&c, &x)| c * x).sum();
            let s2: u32 = c2.iter().zip(&d).map(|(&c, &x)| c * x).sum();
            (s1 % 11) % 10 == d[10] && (s2 % 11) % 10 == d[11]
        }
        _ => false,
    }
}

fn snils_valid(digits: &str) -> bool {
    let d: Vec<u32> = digits.chars().filter(|c| c.is_ascii_digit()).map(|c| c.to_digit(10).unwrap()).collect();
    if d.len() != 11 {
        return false;
    }
    let sum: u32 = d[..9].iter().zip((1..=9).rev()).map(|(&x, w)| x * w).sum();
    let control = if sum < 100 {
        sum
    } else if sum == 100 || sum == 101 {
        0
    } else {
        let m = sum % 101;
        if m == 100 { 0 } else { m }
    };
    control == d[9] * 10 + d[10]
}

#[test]
fn surname_group_and_gender() {
    let reg = load();

    let text = "Сидоров";
    let s = text.find("Сидоров").unwrap();
    let out = mask_pseudo(&reg, text, vec![ent("fio", s, s + text.len())]);
    assert_ne!(out, "Сидоров", "pseudonym must differ from original");
    assert!(out.ends_with("ов"), "male surname must stay in -ов group, got {out}");

    let text = "Сидорова";
    let s = text.find("Сидорова").unwrap();
    let out = mask_pseudo(&reg, text, vec![ent("fio", s, s + text.len())]);
    assert_ne!(out, "Сидорова");
    assert!(out.ends_with("ова"), "female surname must stay in -ова group, got {out}");

    let text = "Прокопенко";
    let s = text.find("Прокопенко").unwrap();
    let out = mask_pseudo(&reg, text, vec![ent("fio", s, s + text.len())]);
    assert_ne!(out, "Прокопенко");
    assert!(out.ends_with("енко"), "surname must stay in -енко group, got {out}");
}

#[test]
fn uppercase_style_preserved() {
    let reg = load();
    let text = "ИВАНОВ";
    let s = text.find("ИВАНОВ").unwrap();
    let out = mask_pseudo(&reg, text, vec![ent("fio", s, s + text.len())]);
    assert_ne!(out, "ИВАНОВ");
    assert_eq!(out, out.to_uppercase(), "uppercase original must yield uppercase pseudonym");
}

#[test]
fn dative_case_all_three_words() {
    let reg = load();
    let text = "Сидорову Ивану Петровичу";
    let out = mask_pseudo(&reg, text, vec![ent("fio", 0, text.len())]);
    assert_ne!(out, text);
    let words: Vec<&str> = out.split_whitespace().collect();
    assert_eq!(words.len(), 3, "three words preserved");
    assert!(words[0].ends_with("ову"), "surname in dative, got {}", words[0]);
    assert!(
        words[1].ends_with('у') || words[1].ends_with('ю'),
        "name in dative, got {}",
        words[1]
    );
    assert!(
        words[2].ends_with('у') || words[2].ends_with('ю'),
        "patronymic in dative, got {}",
        words[2]
    );
}

#[test]
fn inn_snils_card_validators() {
    let reg = load();

    let text = "ИНН 7707083893";
    let s = text.find("7707083893").unwrap();
    let out = mask_pseudo(&reg, text, vec![ent("inn", s, s + 10)]);
    let digits: String = out.chars().filter(|c| c.is_ascii_digit()).collect();
    assert_eq!(digits.len(), 10);
    assert!(inn_valid(&digits), "pseudonym INN must pass validator, got {out}");

    let text = "СНИЛС 112-233-445 95";
    let s = text.find("112-233-445 95").unwrap();
    let out = mask_pseudo(&reg, text, vec![ent("snils", s, s + "112-233-445 95".len())]);
    let digits: String = out.chars().filter(|c| c.is_ascii_digit()).collect();
    assert_eq!(digits.len(), 11);
    assert!(snils_valid(&digits), "pseudonym SNILS must pass validator, got {out}");
    assert_eq!(out.chars().filter(|c| *c == '-').count(), 2, "SNILS separators preserved");

    let text = "карта 4111 1111 1111 1111";
    let s = text.find("4111 1111 1111 1111").unwrap();
    let out = mask_pseudo(&reg, text, vec![ent("card_number", s, s + "4111 1111 1111 1111".len())]);
    let card = out.strip_prefix("карта ").unwrap();
    let digits: String = card.chars().filter(|c| c.is_ascii_digit()).collect();
    assert_eq!(digits.len(), 16);
    assert!(luhn(&digits), "pseudonym card must pass Luhn, got {out}");
    assert_eq!(card.chars().filter(|c| *c == ' ').count(), 3, "card separators preserved");
}

#[test]
fn phone_prefix_and_separators() {
    let reg = load();

    let text = "+7 912 345-67-89";
    let s = text.find("+7 912 345-67-89").unwrap();
    let out = mask_pseudo(&reg, text, vec![ent("phone", s, s + text.len())]);
    assert!(out.starts_with("+7"), "must keep +7 prefix, got {out}");
    assert_eq!(out.chars().filter(|c| *c == ' ').count(), 2, "space separators preserved");
    assert_eq!(out.chars().filter(|c| *c == '-').count(), 2, "dash separators preserved");

    let text = "8-912-345-67-89";
    let s = text.find("8-912-345-67-89").unwrap();
    let out = mask_pseudo(&reg, text, vec![ent("phone", s, s + text.len())]);
    assert!(out.starts_with('8'), "must keep 8 prefix, got {out}");
    assert_eq!(out.chars().filter(|c| *c == '-').count(), 4, "dash separators preserved");
}

#[test]
fn deterministic_with_same_seed_different_with_other() {
    let reg = load();
    let text = "Сидоров";
    let s = text.find("Сидоров").unwrap();
    let entities = vec![ent("fio", s, s + text.len())];

    let empty: Vec<Mapping> = Vec::new();
    let overrides = HashMap::new();
    let r1 = mask_with_seed(text, &entities, &reg, &pseudonym_opts(&overrides), Numbering::Sequential, &empty);
    let r2 = mask_with_seed(text, &entities, &reg, &pseudonym_opts(&overrides), Numbering::Sequential, &empty);
    assert_eq!(r1.text, r2.text, "same seed must give same pseudonym");

    let other_seed = vec![Mapping {
        type_id: "fio".into(),
        original: "Сидоров".into(),
        masked: "Петров".into(),
    }];
    let r3 = mask_with_seed(text, &entities, &reg, &pseudonym_opts(&overrides), Numbering::Sequential, &other_seed);
    assert_eq!(r3.text, "Петров", "seed mapping must be reused");
    assert_ne!(r1.text, r3.text, "different seed must give different pseudonym");
}

#[test]
fn not_equal_to_original_and_not_in_text() {
    let reg = load();
    let text = "Клиент Сидоров Иван Петрович, ИНН 7707083893";
    let f = text.find("Сидоров Иван Петрович").unwrap();
    let i = text.find("7707083893").unwrap();
    let entities = vec![
        ent("fio", f, f + "Сидоров Иван Петрович".len()),
        ent("inn", i, i + 10),
    ];
    let res = mask(text, &entities, &reg, &pseudonym_opts(&HashMap::new()));
    for m in &res.mappings {
        assert_ne!(m.masked, m.original, "pseudonym must differ from original");
        assert!(!text.contains(&m.masked), "pseudonym must not appear in source text");
    }
}

#[test]
fn roundtrip_pseudonym() {
    let reg = load();
    let text = "Клиент Сидоров Иван Петрович, ИНН 7707083893, тел. +7 912 345-67-89, карта 4111 1111 1111 1111";
    let f = text.find("Сидоров Иван Петрович").unwrap();
    let i = text.find("7707083893").unwrap();
    let p = text.find("+7 912 345-67-89").unwrap();
    let c = text.find("4111 1111 1111 1111").unwrap();
    let entities = vec![
        ent("fio", f, f + "Сидоров Иван Петрович".len()),
        ent("inn", i, i + 10),
        ent("phone", p, p + "+7 912 345-67-89".len()),
        ent("card_number", c, c + "4111 1111 1111 1111".len()),
    ];
    let res = mask(text, &entities, &reg, &pseudonym_opts(&HashMap::new()));
    let restored = unmask(&res.text, &res.mappings);
    assert_eq!(restored, text, "round-trip failed");
}

fn word_case(word: &str) -> &'static str {
    let letters: Vec<char> = word.chars().filter(|c| c.is_alphabetic()).collect();
    if letters.is_empty() {
        return "none";
    }
    if letters.iter().all(|c| c.is_uppercase()) {
        "upper"
    } else if letters[0].is_uppercase() {
        "title"
    } else {
        "lower"
    }
}

fn assert_same_word_cases(original: &str, masked: &str) {
    let orig: Vec<&str> = original.split_whitespace().collect();
    let mask: Vec<&str> = masked.split_whitespace().collect();
    assert_eq!(orig.len(), mask.len(), "word count must match");
    for (o, m) in orig.iter().zip(mask.iter()) {
        assert_eq!(
            word_case(o),
            word_case(m),
            "case of {m:?} must match {o:?} in {masked:?}"
        );
    }
}

#[test]
fn per_word_case_preserved() {
    let reg = load();

    let text = "Сидоров Пётр Иванович";
    let s = text.find("Сидоров Пётр Иванович").unwrap();
    let out = mask_pseudo(&reg, text, vec![ent("fio", s, s + text.len())]);
    assert_ne!(out, text);
    assert_same_word_cases(text, &out);

    let text = "СИДОРОВ ПЁТР ИВАНОВИЧ";
    let s = text.find("СИДОРОВ ПЁТР ИВАНОВИЧ").unwrap();
    let out = mask_pseudo(&reg, text, vec![ent("fio", s, s + text.len())]);
    assert_ne!(out, text);
    assert_same_word_cases(text, &out);

    let text = "сидоров пётр иванович";
    let s = text.find("сидоров пётр иванович").unwrap();
    let out = mask_pseudo(&reg, text, vec![ent("fio", s, s + text.len())]);
    assert_ne!(out, text);
    assert_same_word_cases(text, &out);
}

#[test]
fn female_surname_stays_in_group() {
    let reg = load();

    let cases = [
        ("Сидорова", "ова"),
        ("Иванова", "ова"),
        ("Пушкина", "ина"),
        ("Петровская", "ская"),
        ("Прокопенко", "енко"),
    ];
    for (orig, ending) in cases {
        let s = orig.find(orig).unwrap();
        let out = mask_pseudo(&reg, orig, vec![ent("fio", s, s + orig.len())]);
        assert_ne!(out, orig, "pseudonym must differ from {orig}");
        assert!(
            out.ends_with(ending),
            "female surname {orig} must stay in -{ending} group, got {out}"
        );
    }
}

#[test]
fn city_prefix_and_case_preserved() {
    let reg = load();
    let text = "родился в г. Казань";
    let s = text.find("г. Казань").unwrap();
    let out = mask_pseudo(&reg, text, vec![ent("birth_place", s, s + "г. Казань".len())]);
    assert_ne!(out, text);
    let place = out.strip_prefix("родился в ").unwrap();
    assert!(place.starts_with("г. "), "prefix г. must be preserved, got {out}");
    let name = place.strip_prefix("г. ").unwrap();
    let first = name.chars().next().unwrap();
    assert!(first.is_uppercase(), "city name must be capitalized, got {out}");
}

#[test]
fn phone_mobile_code_in_9xx() {
    let reg = load();
    let text = "+7 912 345-67-89";
    let s = text.find("+7 912 345-67-89").unwrap();
    let out = mask_pseudo(&reg, text, vec![ent("phone", s, s + text.len())]);
    assert!(out.starts_with("+7"), "must keep +7 prefix, got {out}");
    let digits: Vec<char> = out.chars().filter(|c| c.is_ascii_digit()).collect();
    assert_eq!(digits.len(), 11);
    let code: u32 = digits[1..4].iter().collect::<String>().parse().unwrap();
    assert!(
        (900..=999).contains(&code),
        "mobile code must be in 900-999, got {code} in {out}"
    );
}