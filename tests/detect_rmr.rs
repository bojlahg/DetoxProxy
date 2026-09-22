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

/// Asserts that at least one entity of `type_id` has the given span text.
fn assert_has_span(text: &str, type_id: &str, expected: &str) {
    let entities = detect(text);
    assert!(
        entities
            .iter()
            .any(|e| e.type_id == type_id && &text[e.start..e.end] == expected),
        "no {type_id} span {expected:?} in {text:?}, got {:?}",
        entities
    );
}

fn assert_confidence(text: &str, type_id: &str, expected: f32) {
    let entities = detect(text);
    let ent = entities
        .iter()
        .find(|e| e.type_id == type_id)
        .unwrap_or_else(|| panic!("type {type_id} not found in {:?} for text {text:?}", entities));
    assert!(
        (ent.confidence - expected).abs() < 1e-4,
        "confidence {} != {} for {type_id} in {text:?}",
        ent.confidence,
        expected
    );
}

// --- SNILS: tokenized separators (spaces around dashes, dots) ---

#[test]
fn snils_dashes_with_spaces() {
    assert_span("СНИЛС 123 - 456 - 789 01", "snils", "123 - 456 - 789 01");
    assert_span("снилс 111 - 222 - 333 44", "snils", "111 - 222 - 333 44");
    assert_span("СНИЛС 123 - 456 - 789 - 01", "snils", "123 - 456 - 789 - 01");
}

#[test]
fn snils_dots() {
    assert_span("Мой снилс: 123.456.789.01", "snils", "123.456.789.01");
    assert_span("СНИЛС 111.222.333.44", "snils", "111.222.333.44");
    assert_span("снилс 333.444.555.66", "snils", "333.444.555.66");
}

#[test]
fn snils_plain_digits() {
    assert_span("снилс 11223344556", "snils", "11223344556");
    assert_span("СНИЛС 12345678901", "snils", "12345678901");
    assert_span("снилс 111222333 44", "snils", "111222333 44");
}

// --- Passport: series and number, separate or together ---

#[test]
fn passport_series_number_together() {
    assert_span("паспорт 45 03 123456", "passport", "45 03 123456");
    assert_span("паспорт 4503 123456", "passport", "4503 123456");
    assert_span("паспорт 4509123456", "passport", "4509123456");
}

#[test]
fn passport_series_number_separate() {
    assert_has_span("серия 43 21, а номер паспорта 987654", "passport", "43 21");
    assert_has_span("серия 43 21, а номер паспорта 987654", "passport", "987654");
    assert_has_span("Серия: 5555, № 667788", "passport", "5555");
    assert_has_span("Серия: 5555, № 667788", "passport", "667788");
}

#[test]
fn passport_dash_separator() {
    assert_span("паспорт 92 01 - 987654", "passport", "92 01 - 987654");
    assert_span("паспорт 4509-123456", "passport", "4509-123456");
    assert_span("паспорт 45 03 123456", "passport", "45 03 123456");
}

// --- Driver license: series and number with a driver-license marker ---

#[test]
fn driver_license_series_number() {
    assert_has_span("водительское удостоверение серия 5019, номер 004512", "driver_license", "5019");
    assert_has_span("водительское удостоверение серия 5019, номер 004512", "driver_license", "004512");
    assert_has_span("права серия 78 16 и номер 112233", "driver_license", "78 16");
    assert_has_span("права серия 78 16 и номер 112233", "driver_license", "112233");
}

#[test]
fn driver_license_glued() {
    assert_span("права 9911 223344", "driver_license", "9911 223344");
    assert_span("водительское удостоверение 44 / 33 987654", "driver_license", "44 / 33 987654");
    assert_span("водительские 9911 223344", "driver_license", "9911 223344");
}

#[test]
fn driver_license_not_passport() {
    // A series label with a driver-license marker is a driver license, not a passport.
    let entities = detect("водительское удостоверение серия 5019, номер 004512");
    assert!(
        entities.iter().any(|e| e.type_id == "driver_license"),
        "driver_license not found: {:?}",
        entities
    );
    assert!(
        !entities.iter().any(|e| e.type_id == "passport"),
        "passport should not be found: {:?}",
        entities
    );
}

// --- Email: spaces around @ and dots ---

#[test]
fn email_spaces_around_at_and_dot() {
    assert_span("Email: ugray@gmail . com", "email", "ugray@gmail . com");
    assert_span("tkut @ uraltrd . ru", "email", "tkut @ uraltrd . ru");
    assert_span("почта unlockbody @ ya . ru", "email", "unlockbody @ ya . ru");
}

#[test]
fn email_plain() {
    assert_span("почта ivan.petrov@mail.ru", "email", "ivan.petrov@mail.ru");
    assert_span("почта IVAN@EXAMPLE.COM", "email", "IVAN@EXAMPLE.COM");
    assert_span("почта a+b@sub.domain.org", "email", "a+b@sub.domain.org");
}

// --- Card: dashes with spaces ---

#[test]
fn card_dashes_with_spaces() {
    assert_span("карта 5555 - 1111 - 2222 - 3333", "card_number", "5555 - 1111 - 2222 - 3333");
    assert_span("карта 5536 - 9137 - 5000 - 4321", "card_number", "5536 - 9137 - 5000 - 4321");
    assert_span("карта 4817 - 7654 - 1111 - 9876", "card_number", "4817 - 7654 - 1111 - 9876");
}

#[test]
fn card_plain() {
    assert_span("карта 4111 1111 1111 1111", "card_number", "4111 1111 1111 1111");
    assert_span("карта 4111-1111-1111-1111", "card_number", "4111-1111-1111-1111");
    assert_span("карта 4111111111111111", "card_number", "4111111111111111");
}

// --- FIO: surname + initials ---

#[test]
fn fio_surname_initials() {
    assert_span("Лукин П. П.", "fio", "Лукин П. П.");
    assert_span("Дорохова И. И.", "fio", "Дорохова И. И.");
    assert_span("П.П. Лукин", "fio", "П.П. Лукин");
}

#[test]
fn fio_surname_initials_confidence() {
    assert_confidence("Лукин П. П.", "fio", 0.8);
    assert_confidence("Дорохова И. И.", "fio", 0.8);
    assert_confidence("П.П. Лукин", "fio", 0.8);
}

// --- FIO: Latin name near a marker ---

#[test]
fn fio_latin_near_marker() {
    assert_span("клиент Theodore Weaver", "fio", "Theodore Weaver");
    assert_span("заявитель Dorothy LANGFOrd", "fio", "Dorothy LANGFOrd");
    assert_span("держатель Theodore Weaver", "fio", "Theodore Weaver");
}

#[test]
fn fio_latin_without_marker_not_detected() {
    assert_not_found("Theodore Weaver", "fio");
    assert_not_found("Dorothy LANGFOrd", "fio");
    assert_not_found("Kelly Leonard", "fio");
}