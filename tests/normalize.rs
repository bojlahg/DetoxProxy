use detox_proxy::config::TrapPolicy;
use detox_proxy::detect::{DetectOptions, Detector, Dictionaries};
use detox_proxy::mask::{mask, unmask, MaskOptions};
use detox_proxy::registry::Registry;
use detox_proxy::types::{Entity, MaskMode};
use std::collections::HashMap;
use std::sync::Arc;

fn detector() -> Detector {
    let yaml = std::fs::read_to_string("data/pii_types.yaml").expect("read pii_types.yaml");
    let reg = Arc::new(Registry::from_yaml(&yaml).expect("parse registry"));
    let dicts = Arc::new(Dictionaries::load_dir(std::path::Path::new("data/dict")).expect("load dicts"));
    Detector::new(reg, dicts)
}

fn detect(text: &str) -> Vec<Entity> {
    let opts = DetectOptions {
        enabled_types: None,
        min_confidence: 0.0,
        allow_substrings: &[],
        trap_policy: TrapPolicy::PreferMask,
    };
    detector().detect(text, &opts)
}

fn assert_span(text: &str, type_id: &str, expected: &str) {
    let entities = detect(text);
    let ent = entities
        .iter()
        .find(|e| e.type_id == type_id)
        .unwrap_or_else(|| panic!("type {type_id} not found in {:?} for text {text:?}", entities));
    let span = &text[ent.start..ent.end];
    assert_eq!(span, expected, "span mismatch for {type_id} in {text:?}");
    assert!(text.is_char_boundary(ent.start) && text.is_char_boundary(ent.end), "span not on char boundary");
}

fn assert_not_found(text: &str, type_id: &str) {
    let entities = detect(text);
    assert!(
        !entities.iter().any(|e| e.type_id == type_id),
        "type {type_id} should not be found in {text:?}, got {:?}",
        entities
    );
}

#[test]
fn latin_lookalike_in_cyrillic_word() {
    // Latin 'o' in "Иванoв" must be normalized so the FIO is found, and the span must
    // point back to the original text (with the Latin 'o').
    assert_span("Клиент Иванoв Иван Иванович", "fio", "Иванoв Иван Иванович");
}

#[test]
fn inn_offsets_do_not_shift() {
    // The INN is before the mixed word; its offsets must be unchanged.
    let text = "ИНН 500100732259, Клиент Петрoва Анна";
    let entities = detect(text);
    let inn = entities
        .iter()
        .find(|e| e.type_id == "inn")
        .unwrap_or_else(|| panic!("inn not found in {:?}", entities));
    assert_eq!(&text[inn.start..inn.end], "500100732259");
    let fio = entities
        .iter()
        .find(|e| e.type_id == "fio")
        .unwrap_or_else(|| panic!("fio not found in {:?}", entities));
    assert_eq!(&text[fio.start..fio.end], "Петрoва Анна");
}

#[test]
fn yo_and_e_are_equivalent() {
    assert_span("Клиент Королев Сергей Павлович", "fio", "Королев Сергей Павлович");
    assert_span("Клиент Королёв Сергей Павлович", "fio", "Королёв Сергей Павлович");
}

#[test]
fn latin_fio_with_patronymic() {
    assert_span("Ivanov Ivan Ivanovich заходил вчера", "fio", "Ivanov Ivan Ivanovich");
    assert_span("Petrova Anna Sergeevna", "fio", "Petrova Anna Sergeevna");
}

#[test]
fn latin_without_patronymic_is_not_fio() {
    assert_not_found("Apple iPhone 15 Pro Max", "fio");
    assert_not_found("Сервис Online Banking", "fio");
    assert_not_found("Apple Store Moscow", "fio");
}

#[test]
fn roundtrip_preserves_latin_lookalike() {
    let text = "Клиент Иванoв Иван Иванович, ИНН 500100732259";
    let entities = detect(text);
    let reg = Registry::from_yaml(&std::fs::read_to_string("data/pii_types.yaml").unwrap()).unwrap();
    let opts = MaskOptions {
        default_mode: MaskMode::Token,
        overrides: &HashMap::new(),
        combination_rule: false,
    };
    let res = mask(text, &entities, &reg, &opts);
    let restored = unmask(&res.text, &res.mappings);
    assert_eq!(restored, text, "round-trip failed for {text:?}");
}