use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use axum::serve::ListenerExt;
use detox_proxy::config::{Config, ConfigStore, TrapPolicy};
use detox_proxy::detect::{Allowlist, DetectOptions, Detector, Dictionaries};
use detox_proxy::registry::Registry;
use detox_proxy::server::{build_router, AppState};
use detox_proxy::store::MappingStore;
use detox_proxy::types::Entity;

fn detector() -> Detector {
    let yaml = std::fs::read_to_string("data/pii_types.yaml").expect("read pii_types.yaml");
    let reg = Arc::new(Registry::from_yaml(&yaml).expect("parse registry"));
    let dicts = Arc::new(Dictionaries::load_dir(std::path::Path::new("data/dict")).expect("load dicts"));
    let allowlist_text = std::fs::read_to_string("data/allowlist.yaml").expect("read allowlist");
    let allowlist = Allowlist::from_yaml(&allowlist_text).expect("parse allowlist");
    Detector::with_allowlist(reg, dicts, allowlist)
}

fn detect(text: &str, policy: TrapPolicy) -> Vec<Entity> {
    let opts = DetectOptions {
        enabled_types: None,
        min_confidence: 0.3,
        allow_substrings: &[],
        trap_policy: policy,
    };
    detector().detect(text, &opts)
}

fn detect_at(text: &str, min_confidence: f32) -> Vec<Entity> {
    let opts = DetectOptions {
        enabled_types: None,
        min_confidence,
        allow_substrings: &[],
        trap_policy: TrapPolicy::PreferMask,
    };
    detector().detect(text, &opts)
}

fn has_type(entities: &[Entity], type_id: &str) -> bool {
    entities.iter().any(|e| e.type_id == type_id)
}

fn confidence_of(entities: &[Entity], type_id: &str) -> Option<f32> {
    entities.iter().find(|e| e.type_id == type_id).map(|e| e.confidence)
}

fn span_of<'a>(text: &'a str, entities: &[Entity], type_id: &str) -> Option<&'a str> {
    entities
        .iter()
        .find(|e| e.type_id == type_id)
        .map(|e| &text[e.start..e.end])
}

fn spans_of<'a>(text: &'a str, entities: &[Entity], type_id: &str) -> Vec<&'a str> {
    entities
        .iter()
        .filter(|e| e.type_id == type_id)
        .map(|e| &text[e.start..e.end])
        .collect()
}

#[test]
fn poet_not_masked() {
    let entities = detect("Поэт Александр Пушкин написал Евгения Онегина", TrapPolicy::PreferMask);
    assert!(!has_type(&entities, "fio"), "fio should not be found: {:?}", entities);
}

#[test]
fn client_with_passport_masked() {
    let entities = detect("Клиент Пушкин Иван Сергеевич, паспорт 4509 123456", TrapPolicy::PreferMask);
    assert!(has_type(&entities, "fio"), "fio should be found: {:?}", entities);
    assert!(has_type(&entities, "passport"), "passport should be found: {:?}", entities);
}

#[test]
fn full_namesake_with_pii_context_masked() {
    let entities = detect(
        "Александр Сергеевич Пушкин, паспорт 4509 123456, тел. +7 912 345-67-89",
        TrapPolicy::PreferMask,
    );
    assert!(has_type(&entities, "fio"), "fio should be found: {:?}", entities);
}

#[test]
fn bare_public_person_depends_on_policy() {
    // A bare full match with a public person (no PII marker) is not a client.
    let mask = detect("Александр Сергеевич Пушкин", TrapPolicy::PreferMask);
    assert!(!has_type(&mask, "fio"), "bare public person should not be found: {:?}", mask);

    let skip = detect("Александр Сергеевич Пушкин", TrapPolicy::PreferSkip);
    assert!(!has_type(&skip, "fio"), "bare public person should not be found: {:?}", skip);

    // A full namesake with a strong PII marker is a client and is masked under both policies.
    let text = "Клиент Александр Сергеевич Пушкин, тел. +7 912 345-67-89";
    let mask = detect(text, TrapPolicy::PreferMask);
    assert!(has_type(&mask, "fio"), "client namesake should be found: {:?}", mask);

    let skip = detect(text, TrapPolicy::PreferSkip);
    assert!(has_type(&skip, "fio"), "client namesake should be found: {:?}", skip);
}

#[test]
fn monument_and_square_not_masked() {
    let entities = detect("Памятник Пушкину на площади Пушкина", TrapPolicy::PreferMask);
    assert!(!has_type(&entities, "fio"), "fio should not be found: {:?}", entities);
    assert!(!has_type(&entities, "address"), "address should not be found: {:?}", entities);
}

#[test]
fn bank_office_address_not_masked() {
    let entities = detect("Отделение банка: г. Москва, ул. Тверская, д. 1", TrapPolicy::PreferMask);
    assert!(!has_type(&entities, "address"), "address should not be found: {:?}", entities);
}

#[test]
fn resident_address_masked() {
    let entities = detect("Проживает: г. Москва, ул. Тверская, д. 1", TrapPolicy::PreferMask);
    assert!(has_type(&entities, "address"), "address should be found: {:?}", entities);
}

#[test]
fn organization_address_not_masked() {
    let entities = detect("Альфа-Банк, ул. Каланчёвская, д. 27", TrapPolicy::PreferMask);
    assert!(!has_type(&entities, "address"), "address should not be found: {:?}", entities);
}

#[test]
fn example_phone_not_masked() {
    let entities = detect("Пример телефона: +7 900 000-00-00", TrapPolicy::PreferMask);
    assert!(!has_type(&entities, "phone"), "phone should not be found: {:?}", entities);
}

#[test]
fn my_phone_masked() {
    let entities = detect("мой телефон +7 912 345-67-89", TrapPolicy::PreferMask);
    assert!(has_type(&entities, "phone"), "phone should be found: {:?}", entities);
}

#[test]
fn historical_birth_date_low_confidence() {
    let entities = detect("Пушкин родился 6 июня 1799 года", TrapPolicy::PreferMask);
    assert!(!has_type(&entities, "fio"), "fio should not be found: {:?}", entities);
    let conf = confidence_of(&entities, "birth_date");
    assert!(conf.is_some(), "birth_date should be found: {:?}", entities);
    assert!(conf.unwrap() < 0.6, "birth_date confidence should be below 0.6: {:?}", conf);
}

#[test]
fn invalid_luhn_card_with_marker_found() {
    let entities = detect("карта 1234 5678 9012 3456", TrapPolicy::PreferMask);
    let conf = confidence_of(&entities, "card_number");
    assert!(conf.is_some(), "card_number should be found: {:?}", entities);
    assert!((conf.unwrap() - 0.6).abs() < 0.01, "card_number confidence ~0.6: {:?}", conf);
}

#[test]
fn invalid_luhn_card_without_marker_not_found() {
    let entities = detect("1234 5678 9012 3456", TrapPolicy::PreferMask);
    assert!(!has_type(&entities, "card_number"), "card_number should not be found: {:?}", entities);
}

#[test]
fn nearest_label_resolves_passport_vs_internal_id() {
    let text = "Паспорт клиента: 4512 345678. Код заявки: 4512 345679.";
    let entities = detect_at(text, 0.5);
    let passports = spans_of(text, &entities, "passport");
    assert_eq!(passports, vec!["4512 345678"], "only the first number is a passport: {:?}", entities);
}

#[test]
fn nearest_label_resolves_cvv_vs_pin() {
    let text = "Для карты клиента CVV 317 и PIN 4821.";
    let entities = detect(text, TrapPolicy::PreferMask);
    assert_eq!(span_of(text, &entities, "cvv"), Some("317"), "cvv span: {:?}", entities);
    assert_eq!(span_of(text, &entities, "card_pin"), Some("4821"), "pin span: {:?}", entities);
}

#[test]
fn glued_markers_mask_only_digits() {
    let text = "Карта 4276-5500-1122-3347,CVV317,PIN4821.";
    let entities = detect(text, TrapPolicy::PreferMask);
    assert!(has_type(&entities, "card_number"), "card_number should be found: {:?}", entities);
    assert_eq!(span_of(text, &entities, "cvv"), Some("317"), "cvv span must be digits only: {:?}", entities);
    assert_eq!(span_of(text, &entities, "card_pin"), Some("4821"), "pin span must be digits only: {:?}", entities);
}

#[test]
fn version_string_not_phone() {
    let entities = detect("Версия сборки 8.900.123.45.67", TrapPolicy::PreferMask);
    assert!(!has_type(&entities, "phone"), "version must not be a phone: {:?}", entities);
    let entities = detect("телефон 8.900.123.45.67", TrapPolicy::PreferMask);
    assert!(has_type(&entities, "phone"), "phone with marker should be found: {:?}", entities);
}

#[test]
fn birth_date_with_marker_after() {
    let entities = detect("Иванов, 10.02.1982 года рождения", TrapPolicy::PreferMask);
    assert!(has_type(&entities, "birth_date"), "birth_date should be found: {:?}", entities);
    let entities = detect("06.06.1988 г.р.", TrapPolicy::PreferMask);
    assert!(has_type(&entities, "birth_date"), "birth_date should be found: {:?}", entities);
}

#[test]
fn organization_address_not_masked_nearest_marker() {
    let entities = detect("Адрес отделения банка: г. Москва, ул. Тверская, д. 1", TrapPolicy::PreferMask);
    assert!(!has_type(&entities, "address"), "organization address should not be found: {:?}", entities);
    let entities = detect("Клиент проживает по адресу: г. Москва, ул. Лесная, д. 17, кв. 42", TrapPolicy::PreferMask);
    assert!(has_type(&entities, "address"), "resident address should be found: {:?}", entities);
}

#[test]
fn internal_identifier_not_passport() {
    let entities = detect_at("внутренний идентификатор 4512345678", 0.5);
    assert!(!has_type(&entities, "passport"), "internal id must not be a passport: {:?}", entities);
}

#[test]
fn full_address_without_marker_masked() {
    let entities = detect("Доставить: г. Белгород, ул. Садовая, д. 41", TrapPolicy::PreferMask);
    assert!(has_type(&entities, "address"), "full address without marker should be found: {:?}", entities);
}

#[test]
fn cvv_far_from_marker_not_masked() {
    let entities = detect("CVV находится на обороте карты (заметка № 001/cvv)", TrapPolicy::PreferMask);
    assert!(!has_type(&entities, "cvv"), "cvv far from marker should not be found: {:?}", entities);
}

#[test]
fn passport_series_number_separated_masked() {
    let entities = detect("серия 43 21, а номер паспорта 987654", TrapPolicy::PreferMask);
    assert!(has_type(&entities, "passport"), "separated passport should be found: {:?}", entities);
    let entities = detect("Серия: 5555, № 667788", TrapPolicy::PreferMask);
    assert!(has_type(&entities, "passport"), "separated passport with № should be found: {:?}", entities);
}

#[test]
fn street_address_without_d_masked() {
    let entities = detect("на ул. Гагарина 28", TrapPolicy::PreferMask);
    assert!(has_type(&entities, "address"), "street address should be found: {:?}", entities);
    let entities = detect("ул. Строителей 17к3", TrapPolicy::PreferMask);
    assert!(has_type(&entities, "address"), "street address with letter should be found: {:?}", entities);
    let entities = detect("пр. Победы 45 кв 89", TrapPolicy::PreferMask);
    assert!(has_type(&entities, "address"), "street address with apartment should be found: {:?}", entities);
    let entities = detect("проспекте Сахарова 22", TrapPolicy::PreferMask);
    assert!(has_type(&entities, "address"), "street address in prepositional case should be found: {:?}", entities);
}

#[test]
fn street_address_with_city_masked() {
    let entities = detect("г. Москва, ул. Гагарина 28", TrapPolicy::PreferMask);
    assert!(has_type(&entities, "address"), "address with city should be found: {:?}", entities);
    let entities = detect("Хабаровск, Маршала Жукова, 188", TrapPolicy::PreferMask);
    assert!(has_type(&entities, "address"), "city word number address should be found: {:?}", entities);
    let entities = detect("Вольск, Рокоссовского, 131", TrapPolicy::PreferMask);
    assert!(has_type(&entities, "address"), "city word number address should be found: {:?}", entities);
}

#[test]
fn cvv_code_masked() {
    let entities = detect("CVV-код 317 введён", TrapPolicy::PreferMask);
    assert_eq!(span_of("CVV-код 317 введён", &entities, "cvv"), Some("317"), "cvv span: {:?}", entities);
    let entities = detect("CVC-код: 123", TrapPolicy::PreferMask);
    assert_eq!(span_of("CVC-код: 123", &entities, "cvv"), Some("123"), "cvv span: {:?}", entities);
    let entities = detect("код CVV 317", TrapPolicy::PreferMask);
    assert_eq!(span_of("код CVV 317", &entities, "cvv"), Some("317"), "cvv span: {:?}", entities);
}

#[test]
fn cvv_without_digits_not_masked() {
    let entities = detect("CVV-код находится на обратной стороне карты", TrapPolicy::PreferMask);
    assert!(!has_type(&entities, "cvv"), "cvv without digits should not be found: {:?}", entities);
}

#[test]
fn cvv_conversational_forms_masked() {
    let cases = [
        "нужен cvc, вот 123",
        "cvc был 123",
        "цвс правильный 123",
        "код на обороте карты 123",
        "cvc, хотя код 123",
        "вот мой cvc 123",
    ];
    for text in cases {
        let entities = detect(text, TrapPolicy::PreferMask);
        assert_eq!(
            span_of(text, &entities, "cvv"),
            Some("123"),
            "cvv should be found in {:?}: {:?}",
            text,
            entities
        );
    }
}

#[test]
fn cvv_not_masked_after_non_cvv_labels() {
    let cases = [
        "заметка № 001/cvv",
        "CVV находится на обороте карты",
        "ошибка 317 при вводе cvv",
    ];
    for text in cases {
        let entities = detect(text, TrapPolicy::PreferMask);
        assert!(
            !has_type(&entities, "cvv"),
            "cvv should not be found in {:?}: {:?}",
            text,
            entities
        );
    }
}

#[test]
fn passport_pair_pair_masked() {
    let entities = detect("Паспорт 48 90 234004 выдан", TrapPolicy::PreferMask);
    assert_eq!(span_of("Паспорт 48 90 234004 выдан", &entities, "passport"), Some("48 90 234004"), "passport span: {:?}", entities);
}

#[test]
fn driver_license_masked() {
    let entities = detect("водительское удостоверение 77 15 123456", TrapPolicy::PreferMask);
    assert!(has_type(&entities, "driver_license"), "driver license should be found: {:?}", entities);
}

// ---- /process and /v1/detect via HTTP ----

static METRICS: std::sync::OnceLock<metrics_exporter_prometheus::PrometheusHandle> = std::sync::OnceLock::new();

fn metrics_handle() -> metrics_exporter_prometheus::PrometheusHandle {
    METRICS
        .get_or_init(|| detox_proxy::obs::install_metrics().expect("install metrics"))
        .clone()
}

fn build_state(cfg: Config) -> Arc<AppState> {
    let pii_types = std::fs::read_to_string(&cfg.pii_types_file).expect("read pii_types.yaml");
    let registry = Arc::new(Registry::from_yaml(&pii_types).expect("parse registry"));
    let dicts = match &cfg.dictionaries_dir {
        Some(dir) if std::path::Path::new(dir).exists() => {
            Arc::new(Dictionaries::load_dir(std::path::Path::new(dir)).expect("load dicts"))
        }
        _ => Arc::new(Dictionaries::empty()),
    };
    let allowlist_text = std::fs::read_to_string(&cfg.allowlist_file).expect("read allowlist");
    let allowlist = Allowlist::from_yaml(&allowlist_text).expect("parse allowlist");
    let detector = Detector::with_allowlist(registry.clone(), dicts, allowlist);
    let store = Arc::new(MappingStore::new(
        Duration::from_secs(cfg.server.mapping_ttl_sec),
        cfg.server.mapping_max_entries,
    ));
    Arc::new(AppState {
        config: ConfigStore::new(cfg.clone()),
        registry: ArcSwap::from(registry),
        detector: ArcSwap::from_pointee(detector),
        store,
        metrics: metrics_handle(),
        inflight: Arc::new(tokio::sync::Semaphore::new(cfg.server.max_inflight)),
        heavy: Arc::new(tokio::sync::Semaphore::new(cfg.server.heavy_max_concurrency)),
        config_path: std::path::PathBuf::from("config.yaml"),
        shutting_down: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        processed: Arc::new(std::sync::atomic::AtomicU64::new(0)),
    })
}

fn load_root_config() -> Config {
    let text = std::fs::read_to_string("config.yaml").expect("read config.yaml");
    let mut cfg = Config::from_yaml(&text).expect("parse config");
    cfg.validate().expect("validate config");
    cfg
}

async fn spawn_app(state: Arc<AppState>) -> String {
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let listener = listener.tap_io(|tcp| {
        let _ = tcp.set_nodelay(true);
    });
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    format!("http://{}", addr)
}

async fn post_json(base: &str, path: &str, body: &serde_json::Value, headers: &[(&str, &str)]) -> (u16, serde_json::Value) {
    let client = reqwest::Client::new();
    let mut req = client.post(format!("{}{}", base, path)).json(body);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = req.send().await.expect("send");
    let status = resp.status().as_u16();
    let text = resp.text().await.expect("text");
    let json = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn strict_pin_alone_unchanged() {
    let cfg = load_root_config();
    let base = spawn_app(build_state(cfg)).await;
    let (st, json) = post_json(
        &base,
        "/process",
        &serde_json::json!({"payload": "пин-код 1234", "payload_id": "s1"}),
        &[("X-System-Id", "strict")],
    )
    .await;
    assert_eq!(st, 200);
    assert_eq!(json["result"].as_str().unwrap(), "пин-код 1234");
}

#[tokio::test]
async fn strict_pin_with_card_masked() {
    let cfg = load_root_config();
    let base = spawn_app(build_state(cfg)).await;
    let (st, json) = post_json(
        &base,
        "/process",
        &serde_json::json!({"payload": "карта 4276 3800 1234 5679, пин-код 1234", "payload_id": "s2"}),
        &[("X-System-Id", "strict")],
    )
    .await;
    assert_eq!(st, 200);
    let result = json["result"].as_str().unwrap();
    assert!(result.contains("<<CARD_1>>"), "card should be masked: {result}");
    assert!(result.contains("<<PIN_1>>"), "pin should be masked: {result}");
}

#[tokio::test]
async fn autotest_pin_always_masked() {
    let cfg = load_root_config();
    let base = spawn_app(build_state(cfg)).await;
    let (st, json) = post_json(
        &base,
        "/process",
        &serde_json::json!({"payload": "пин-код 1234", "payload_id": "a1"}),
        &[],
    )
    .await;
    assert_eq!(st, 200);
    assert!(json["result"].as_str().unwrap().contains("<<PIN_1>>"));
}

#[tokio::test]
async fn detect_empty_entities_field() {
    let cfg = load_root_config();
    let base = spawn_app(build_state(cfg)).await;
    let (st, json) = post_json(&base, "/v1/detect", &serde_json::json!({"text": "Погода хорошая"}), &[]).await;
    assert_eq!(st, 200);
    let s = serde_json::to_string(&json).unwrap();
    assert!(s.contains("\"entities\":[]"), "detect must include empty entities: {s}");
}

#[tokio::test]
async fn mask_empty_entities_and_mappings_fields() {
    let cfg = load_root_config();
    let base = spawn_app(build_state(cfg)).await;
    let (st, json) = post_json(&base, "/v1/mask", &serde_json::json!({"text": "Погода хорошая"}), &[]).await;
    assert_eq!(st, 200);
    let s = serde_json::to_string(&json).unwrap();
    assert!(s.contains("\"entities\":[]"), "mask must include empty entities: {s}");
    assert!(s.contains("\"mappings\":[]"), "mask must include empty mappings: {s}");
}

#[test]
fn document_number_not_address_or_passport() {
    let entities = detect("Накладная 9876 543210 оформлена утром", TrapPolicy::PreferMask);
    assert!(!has_type(&entities, "address"), "document number must not be an address: {:?}", entities);
    assert!(!has_type(&entities, "passport"), "document number must not be a passport: {:?}", entities);
    // Control: a real passport is still masked.
    let entities = detect("Паспорт клиента 45 03 123456 выдан вчера", TrapPolicy::PreferMask);
    assert!(has_type(&entities, "passport"), "real passport must be found: {:?}", entities);
}

#[test]
fn imei_not_card_number() {
    let entities = detect("IMEI 356938035643809 выбит под крышкой", TrapPolicy::PreferMask);
    assert!(!has_type(&entities, "card_number"), "IMEI must not be a card: {:?}", entities);
    // Control: a real card is still masked.
    let entities = detect("Карта 4276 5500 1122 3347 заблокирована", TrapPolicy::PreferMask);
    assert!(has_type(&entities, "card_number"), "real card must be found: {:?}", entities);
}

#[test]
fn card_case_forms_masked() {
    let cases = [
        "Оплата картой 427640003331517, полис приложен.",
        "Полис ОМС 220015550000436 — проверьте оплату картой.",
    ];
    for text in cases {
        let entities = detect(text, TrapPolicy::PreferMask);
        assert!(has_type(&entities, "card_number"), "card_number should be found in {:?}: {:?}", text, entities);
    }
    // Control: IMEI without a card marker is still not a card.
    let entities = detect("IMEI 356938035643809 выбит под крышкой", TrapPolicy::PreferMask);
    assert!(!has_type(&entities, "card_number"), "IMEI must not be a card: {:?}", entities);
}

#[test]
fn toll_free_800_not_phone() {
    let entities = detect("Горячая линия 8 800 200-00-00 работает круглосуточно", TrapPolicy::PreferMask);
    assert!(!has_type(&entities, "phone"), "8-800 must not be a phone: {:?}", entities);
    // Control: a real phone is still masked.
    let entities = detect("Телефон клиента +7 (900) 123-45-67", TrapPolicy::PreferMask);
    assert!(has_type(&entities, "phone"), "real phone must be found: {:?}", entities);
}

#[test]
fn quoted_brand_name_not_fio() {
    let entities = detect("Магазин «Мария Ра» открылся в микрорайоне", TrapPolicy::PreferMask);
    assert!(!has_type(&entities, "fio"), "brand name must not be a fio: {:?}", entities);
    // Control: a real fio is still masked.
    let entities = detect("Заявитель Морозов Андрей Петрович подписал заявление", TrapPolicy::PreferMask);
    assert!(has_type(&entities, "fio"), "real fio must be found: {:?}", entities);
}

#[test]
fn reception_address_not_masked() {
    let entities = detect("Приёмная находится на ул. Ленина, д. 10", TrapPolicy::PreferMask);
    assert!(!has_type(&entities, "address"), "reception address must not be masked: {:?}", entities);
    // Control: a real resident address is still masked.
    let entities = detect("Проживает: г. Казань, ул. Баумана, д. 14, кв. 8", TrapPolicy::PreferMask);
    assert!(has_type(&entities, "address"), "real address must be found: {:?}", entities);
}

#[test]
fn address_near_document_word_masked() {
    // A real client address next to a document word ("заказ", "тикет") is still masked.
    let cases = [
        "Привезите заказ на г. Самара, ул. Мира, д. 5, кв. 12, я дома после шести.",
        "Заказ доставьте по адресу ул. Садовая, д. 3, кв. 17.",
        "Тикет 4512: клиент просит сменить адрес на г. Тула, ул. Советская, д. 8, кв. 3.",
    ];
    for text in cases {
        let entities = detect(text, TrapPolicy::PreferMask);
        assert!(has_type(&entities, "address"), "address should be found in {:?}: {:?}", text, entities);
    }
}

#[test]
fn document_number_not_address() {
    // A span that starts with a document marker is a document number, not an address.
    let entities = detect("Накладная 9876 543210 оформлена утром", TrapPolicy::PreferMask);
    assert!(!has_type(&entities, "address"), "document number must not be an address: {:?}", entities);
    // Control: a street whose name contains a document word is still an address.
    let entities = detect("ул. Заказная, д. 5", TrapPolicy::PreferMask);
    assert!(has_type(&entities, "address"), "street with document word must be found: {:?}", entities);
}

#[test]
fn passport_not_address() {
    // A passport number after its own field word must keep its type, not become an address.
    let entities = detect("Паспорт 4509 123456, выдан ОУФМС России по г. Москве 15.06.2015.", TrapPolicy::PreferMask);
    assert!(has_type(&entities, "passport"), "passport should be found: {:?}", entities);
    assert!(!has_type(&entities, "address"), "passport must not be an address: {:?}", entities);
}

#[test]
fn birth_place_and_passport() {
    let entities = detect("Место рождения г. Казань. Паспорт 4509 123456.", TrapPolicy::PreferMask);
    assert!(has_type(&entities, "birth_place"), "birth_place should be found: {:?}", entities);
    assert!(has_type(&entities, "passport"), "passport should be found: {:?}", entities);
    assert!(!has_type(&entities, "address"), "no address should be found: {:?}", entities);
}

#[test]
fn citizenship_and_passport() {
    let entities = detect("Гражданство РФ. Паспорт 4509 123456, выдан вчера.", TrapPolicy::PreferMask);
    assert!(has_type(&entities, "passport"), "passport should be found: {:?}", entities);
    assert!(!has_type(&entities, "address"), "no address should be found: {:?}", entities);
}

#[test]
fn card_number_not_address() {
    let entities = detect("Карта 4276 5500 1122 3347, срок 12/28.", TrapPolicy::PreferMask);
    assert!(has_type(&entities, "card_number"), "card_number should be found: {:?}", entities);
    assert!(!has_type(&entities, "address"), "card must not be an address: {:?}", entities);
}

#[test]
fn city_word_number_address_kept() {
    // A city + street word + number is still an address.
    let entities = detect("Москва, Тверская 15, кв. 3", TrapPolicy::PreferMask);
    assert!(has_type(&entities, "address"), "address should be found: {:?}", entities);
}

#[test]
fn resident_address_kept() {
    let entities = detect("Проживает: г. Казань, ул. Баумана, д. 14, кв. 8", TrapPolicy::PreferMask);
    assert!(has_type(&entities, "address"), "address should be found: {:?}", entities);
}