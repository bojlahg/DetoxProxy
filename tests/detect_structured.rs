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
fn card_number_variants() {
    assert_span("карта 4111 1111 1111 1111", "card_number", "4111 1111 1111 1111");
    assert_span("карта 4111-1111-1111-1111", "card_number", "4111-1111-1111-1111");
    assert_span("карта 4111111111111111", "card_number", "4111111111111111");
}

#[test]
fn card_number_invalid_luhn_with_marker_found() {
    assert_span("карта 4276 3800 1234 5674", "card_number", "4276 3800 1234 5674");
    assert_not_found("4276 3800 1234 5674", "card_number");
}

#[test]
fn inn_valid_and_invalid() {
    assert_span("ИНН 7707083893", "inn", "7707083893");
    assert_span("инн 7707083893", "inn", "7707083893");
    assert_span("ИНН 500100732259", "inn", "500100732259");
    assert_not_found("ИНН 7707083894", "inn");
}

#[test]
fn snils_variants() {
    assert_span("СНИЛС 112-233-445 95", "snils", "112-233-445 95");
    assert_span("СНИЛС 11223344595", "snils", "11223344595");
}

#[test]
fn phone_variants() {
    assert_span("тел. +7 (912) 345-67-89", "phone", "+7 (912) 345-67-89");
    assert_span("тел. 8-912-345-67-89", "phone", "8-912-345-67-89");
    assert_span("тел. 89123456789", "phone", "89123456789");
    assert_span("тел. +7 912 345 67 89", "phone", "+7 912 345 67 89");
    assert_span("тел. (912) 345-67-89", "phone", "(912) 345-67-89");
}

#[test]
fn phone_short_not_found() {
    assert_not_found("номер 12345", "phone");
}

#[test]
fn email_variants() {
    assert_span("почта ivan.petrov@mail.ru", "email", "ivan.petrov@mail.ru");
    assert_span("почта IVAN@EXAMPLE.COM", "email", "IVAN@EXAMPLE.COM");
    assert_span("почта a+b@sub.domain.org", "email", "a+b@sub.domain.org");
}

#[test]
fn passport_variants() {
    assert_span("паспорт 4509 123456", "passport", "4509 123456");
    assert_span("серия 4509 номер 123456", "passport", "4509 номер 123456");
    assert_span("серия: 45 09, номер: 123456", "passport", "45 09, номер: 123456");
    assert_span("паспорт 4509123456", "passport", "4509123456");
}

#[test]
fn subdivision_code_requires_context() {
    assert_span("код подразделения 770-001", "subdivision_code", "770-001");
    assert_not_found("770-001", "subdivision_code");
}

#[test]
fn driver_license_requires_context() {
    assert_span("в/у 77 12 345678", "driver_license", "77 12 345678");
    assert_span("водительское удостоверение 7712 345678", "driver_license", "7712 345678");
    assert_not_found("77 12 345678", "driver_license");
}

#[test]
fn cvv_and_pin_require_context() {
    assert_span("CVV 123", "cvv", "123");
    assert_span("пин-код 1234", "card_pin", "1234");
    assert_not_found("123", "cvv");
    assert_not_found("1234", "card_pin");
}

#[test]
fn card_number_does_not_leak_inn_or_phone() {
    let entities = detect("карта 4276380012345678");
    assert!(!entities.iter().any(|e| e.type_id == "inn"), "inn leaked: {:?}", entities);
    assert!(!entities.iter().any(|e| e.type_id == "phone"), "phone leaked: {:?}", entities);
}

#[test]
fn utf8_spans_on_char_boundaries() {
    let text = "Клиент Иванов, тел. +7 912 345-67-89, email ivan@mail.ru";
    let entities = detect(text);
    assert_span(text, "phone", "+7 912 345-67-89");
    assert_span(text, "email", "ivan@mail.ru");
    for e in &entities {
        assert!(text.is_char_boundary(e.start) && text.is_char_boundary(e.end));
    }
}

#[test]
fn allow_substrings_drops_phone() {
    let allow = vec!["8 800 555-35-35".to_string()];
    let opts = DetectOptions {
        enabled_types: None,
        min_confidence: 0.0,
        allow_substrings: &allow,
        trap_policy: TrapPolicy::PreferMask,
    };
    let entities = detector().detect("горячая линия 8 800 555-35-35", &opts);
    assert!(!entities.iter().any(|e| e.type_id == "phone"), "phone not dropped: {:?}", entities);
}

#[test]
fn min_confidence_cuts_non_validated() {
    let opts = DetectOptions {
        enabled_types: None,
        min_confidence: 0.95,
        allow_substrings: &[],
        trap_policy: TrapPolicy::PreferMask,
    };
    let entities = detector().detect("паспорт 4509 123456", &opts);
    assert!(
        !entities.iter().any(|e| e.type_id == "passport"),
        "passport (no validator) should be cut at 0.95: {:?}",
        entities
    );
}

#[test]
fn case_insensitive_same_span() {
    let a = detect("ИНН 7707083893");
    let b = detect("инн 7707083893");
    let ea = a.iter().find(|e| e.type_id == "inn").unwrap();
    let eb = b.iter().find(|e| e.type_id == "inn").unwrap();
    assert_eq!(ea.start, eb.start);
    assert_eq!(ea.end, eb.end);
}

#[test]
fn detect_performance() {
    let text = "Клиент Иванов, тел. +7 912 345-67-89, email ivan@mail.ru, паспорт 4509 123456, ИНН 7707083893, карта 4111 1111 1111 1111";
    let opts = DetectOptions {
        enabled_types: None,
        min_confidence: 0.0,
        allow_substrings: &[],
        trap_policy: TrapPolicy::PreferMask,
    };
    let det = detector();
    let start = std::time::Instant::now();
    for _ in 0..1000 {
        det.detect(text, &opts);
    }
    let elapsed = start.elapsed();
    assert!(elapsed.as_secs_f64() < 2.0, "1000 detects took {:?}", elapsed);
}