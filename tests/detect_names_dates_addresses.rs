use detox_proxy::config::TrapPolicy;
use detox_proxy::detect::{DetectOptions, Detector, Dictionaries};
use detox_proxy::registry::Registry;
use detox_proxy::types::Entity;
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

fn assert_confidence_below(text: &str, type_id: &str, threshold: f32) {
    let entities = detect(text);
    let ent = entities
        .iter()
        .find(|e| e.type_id == type_id)
        .unwrap_or_else(|| panic!("type {type_id} not found in {:?} for text {text:?}", entities));
    assert!(
        ent.confidence < threshold,
        "confidence {} not below {} for {type_id} in {text:?}",
        ent.confidence,
        threshold
    );
}

#[test]
fn fio_full_forms() {
    assert_span("Иванов Иван Иванович", "fio", "Иванов Иван Иванович");
    assert_span("Иван Иванович Иванов", "fio", "Иван Иванович Иванов");
    assert_span("Смирнова Анна Сергеевна", "fio", "Смирнова Анна Сергеевна");
    assert_span("ИВАНОВ ИВАН ИВАНОВИЧ", "fio", "ИВАНОВ ИВАН ИВАНОВИЧ");
}

#[test]
fn fio_with_initials() {
    assert_span("Иванов И. И.", "fio", "Иванов И. И.");
    assert_span("И.И. Иванов", "fio", "И.И. Иванов");
    assert_span("И. И. Иванов", "fio", "И. И. Иванов");
}

#[test]
fn fio_single_with_context() {
    assert_span("клиент Петров", "fio", "Петров");
    assert_not_found("Петров", "fio");
}

#[test]
fn fio_three_words_with_context() {
    assert_span("клиент Ким Чен Ир", "fio", "Ким Чен Ир");
}

#[test]
fn fio_poet_not_detected() {
    assert_not_found("поэт Александр Пушкин", "fio");
}

#[test]
fn fio_not_address() {
    assert_span("ул. Пушкина, д. 5", "address", "ул. Пушкина, д. 5");
    assert_not_found("ул. Пушкина, д. 5", "fio");
}

#[test]
fn fio_city_homonym() {
    assert_span("г. Пушкин, ул. Ленина, 1", "address", "г. Пушкин, ул. Ленина, 1");
    assert_not_found("г. Пушкин, ул. Ленина, 1", "fio");
    assert_span("г. Пушкин И. С.", "fio", "Пушкин И. С.");
}

#[test]
fn birth_date_formats() {
    assert_span("родился 12.05.1985", "birth_date", "12.05.1985");
    assert_span("родился 12/05/1985", "birth_date", "12/05/1985");
    assert_span("родился 12-05-1985", "birth_date", "12-05-1985");
    assert_span("родился 1985-05-12", "birth_date", "1985-05-12");
    assert_span("родился 12.05.85", "birth_date", "12.05.85");
    assert_span("родился 5 мая 1985", "birth_date", "5 мая 1985");
    assert_span("родился 05 мая 1985 г.", "birth_date", "05 мая 1985 г.");
    assert_span("родился 5 мая 1985 года", "birth_date", "5 мая 1985 года");
    assert_span("родился пятого мая 1985", "birth_date", "пятого мая 1985");
}

#[test]
fn birth_date_requires_marker() {
    assert_not_found("12.05.1985", "birth_date");
}

#[test]
fn birth_date_historical_penalty() {
    assert_confidence_below("родился 6 июня 1799", "birth_date", 0.6);
}

#[test]
fn birth_date_future_rejected() {
    assert_not_found("родился 12.05.2099", "birth_date");
}

#[test]
fn passport_issue_date() {
    assert_span("выдан 12.05.2010", "passport_issue_date", "12.05.2010");
    assert_not_found("12.05.2010", "passport_issue_date");
}

#[test]
fn birth_place() {
    assert_span("место рождения: г. Москва", "birth_place", "г. Москва");
    assert_span("родился в г. Москва", "birth_place", "г. Москва");
    assert_span("уроженец г. Москвы", "birth_place", "г. Москвы");
}

#[test]
fn citizenship() {
    assert_span("гражданство: Россия", "citizenship", "Россия");
    assert_span("гражданин РФ", "citizenship", "РФ");
    assert_span("гражданка Казахстана", "citizenship", "Казахстана");
    assert_not_found("Россия", "citizenship");
}

#[test]
fn passport_issuer() {
    assert_span("выдан ОУФМС России по г. Москве 12.05.2010", "passport_issuer", "ОУФМС России по г. Москве");
    assert_span("выдано Отделом УФМС", "passport_issuer", "Отделом УФМС");
    assert_span("кем выдан ГУ МВД России по Московской области", "passport_issuer", "ГУ МВД России по Московской области");
}

#[test]
fn address_full() {
    assert_span("101000, г. Москва, ул. Ленина, д. 5, кв. 12", "address", "101000, г. Москва, ул. Ленина, д. 5, кв. 12");
    assert_span("Москва, Ленина 5", "address", "Москва, Ленина 5");
    assert_span("ул. Тверская, д. 1", "address", "ул. Тверская, д. 1");
    assert_span("проживает: Санкт-Петербург, Невский пр-т, 28", "address", "Санкт-Петербург, Невский пр-т, 28");
    assert_span("отделение банка: ул. Тверская, 1", "address", "ул. Тверская, 1");
}

#[test]
fn address_bare_index_not_entity() {
    assert_not_found("101000", "address");
}

#[test]
fn card_holder() {
    assert_span("держатель IVAN PETROV", "card_holder", "IVAN PETROV");
    assert_span("4276 3800 1234 5674 IVAN PETROV", "card_holder", "IVAN PETROV");
}

#[test]
fn complex_sentence() {
    let text = "Клиент Иванов Иван Иванович, паспорт 4509 123456 выдан ОУФМС России по г. Москве 12.05.2010, код подразделения 770-001, родился 12.05.1985 в г. Москва, проживает: г. Москва, ул. Ленина, д. 5, кв. 12, тел. +7 912 345-67-89";
    let entities = detect(text);
    let expected: &[(&str, &str)] = &[
        ("fio", "Иванов Иван Иванович"),
        ("passport", "4509 123456"),
        ("passport_issuer", "ОУФМС России по г. Москве"),
        ("passport_issue_date", "12.05.2010"),
        ("subdivision_code", "770-001"),
        ("birth_date", "12.05.1985"),
        ("birth_place", "г. Москва"),
        ("address", "г. Москва, ул. Ленина, д. 5, кв. 12"),
    ];
    for (type_id, span) in expected {
        let ent = entities
            .iter()
            .find(|e| e.type_id == *type_id)
            .unwrap_or_else(|| panic!("type {type_id} not found in {:?}", entities));
        assert_eq!(&text[ent.start..ent.end], *span, "span mismatch for {type_id}");
    }
    // No overlaps among the expected entities.
    let mut sorted: Vec<&Entity> = entities
        .iter()
        .filter(|e| expected.iter().any(|(t, _)| *t == e.type_id))
        .collect();
    sorted.sort_by_key(|e| e.start);
    for w in sorted.windows(2) {
        assert!(
            w[0].end <= w[1].start,
            "overlap between {:?} and {:?}",
            w[0],
            w[1]
        );
    }
}