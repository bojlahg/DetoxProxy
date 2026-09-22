use detox_proxy::config::TrapPolicy;
use detox_proxy::detect::{DetectOptions, Detector, Dictionaries};
use detox_proxy::registry::Registry;
use detox_proxy::types::Entity;
use std::sync::Arc;

fn detector() -> Detector {
    let yaml = std::fs::read_to_string("data/pii_types.yaml").expect("read pii_types.yaml");
    let reg = Arc::new(Registry::from_yaml(&yaml).expect("parse registry"));
    Detector::new(reg, Arc::new(Dictionaries::empty()))
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

/// Finds an entity of `type_id` and asserts its span text equals `expected`.
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
fn card_holder_all_caps_after_marker() {
    assert_span("Cardholder: НОВИКОВА ВЕРОНИКА.", "card_holder", "НОВИКОВА ВЕРОНИКА");
    assert_span("Держатель ЕЛЕНА СОКОЛОВ.", "card_holder", "ЕЛЕНА СОКОЛОВ");
    assert_span("Cardholder: Юлия Коробин.", "card_holder", "Юлия Коробин");
}

#[test]
fn card_holder_capitalized_after_marker() {
    assert_span("Владелец карты: Наталья Чернецкий.", "card_holder", "Наталья Чернецкий");
    assert_span("Держатель Данил Сидорова.", "card_holder", "Данил Сидорова");
    assert_span("Cardholder: Феофан Васильев.", "card_holder", "Феофан Васильев");
}

#[test]
fn card_holder_three_words() {
    assert_span("Cardholder: ИВАН ПЕТРОВ СЕРГЕЕВИЧ.", "card_holder", "ИВАН ПЕТРОВ СЕРГЕЕВИЧ");
}

#[test]
fn card_holder_without_marker_not_detected() {
    assert_not_found("Режиссёр фильма — Сергей Петров", "card_holder");
    assert_not_found("Герой романа — Иван Васильевич", "card_holder");
}

#[test]
fn passport_issuer_after_vydan() {
    assert_span(
        "выдан ОМВД России по району Арбат 17 марта 2020 года",
        "passport_issuer",
        "ОМВД России по району Арбат",
    );
    assert_span(
        "Паспорт 14 27 603564 выдан УФМС России по г. Москве.",
        "passport_issuer",
        "УФМС России по г. Москве",
    );
    assert_span(
        "Паспорт 48 90 234004 выдан ОВД района Преображенское.",
        "passport_issuer",
        "ОВД района Преображенское",
    );
}

#[test]
fn passport_issuer_after_kem_vydan() {
    assert_span("Кем выдан (12): ОВД района Преображенское.", "passport_issuer", "ОВД района Преображенское");
    assert_span("Кем выдан (6): ОМВД России по району Хамовники.", "passport_issuer", "ОМВД России по району Хамовники");
    assert_span("Кем выдан: УФМС России по г. Москве.", "passport_issuer", "УФМС России по г. Москве");
}

#[test]
fn passport_issuer_after_organ_vydachi() {
    assert_span("орган выдачи — Паспортный стол г. Торжка.", "passport_issuer", "Паспортный стол г. Торжка");
    assert_span("орган выдачи — Отдел полиции № 7 г. Казани.", "passport_issuer", "Отдел полиции № 7 г. Казани");
    assert_span("орган выдачи — Управа района Котловка.", "passport_issuer", "Управа района Котловка");
}

#[test]
fn passport_issuer_negative() {
    assert_not_found("Справка выдана архивом", "passport_issuer");
    assert_not_found("Документ выдан системой", "passport_issuer");
    assert_not_found("Отделение банка выдаёт кредиты", "passport_issuer");
}

#[test]
fn fio_single_surname_after_pii_marker() {
    assert_span("родился: 17-01-1974, заявитель Морозов.", "fio", "Морозов");
    assert_span("г.р.: 15/06/1993, заявитель Морозова.", "fio", "Морозова");
    assert_span("Дата рождения: 1958-12-02, заявитель Ефимов.", "fio", "Ефимов");
}

#[test]
fn fio_single_surname_after_other_markers() {
    assert_span("клиент Морозов.", "fio", "Морозов");
    assert_span("пациент Петров.", "fio", "Петров");
    assert_span("заёмщик Ефимов.", "fio", "Ефимов");
}

#[test]
fn passport_issuer_mfc() {
    assert_span("Кем выдан: МФЦ района Ясенево.", "passport_issuer", "МФЦ района Ясенево");
    assert_span("орган выдачи — МФЦ района Ясенево.", "passport_issuer", "МФЦ района Ясенево");
}