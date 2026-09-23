use detox_proxy::config::TrapPolicy;
use detox_proxy::detect::{Allowlist, DetectOptions, Detector, Dictionaries};
use detox_proxy::registry::Registry;
use detox_proxy::types::Entity;
use std::sync::Arc;

fn detector() -> Detector {
    let yaml = std::fs::read_to_string("data/pii_types.yaml").expect("read pii_types.yaml");
    let reg = Arc::new(Registry::from_yaml(&yaml).expect("parse registry"));
    let dicts = Arc::new(Dictionaries::load_dir(std::path::Path::new("data/dict")).expect("load dicts"));
    Detector::new(reg, dicts)
}

fn detector_with_allowlist() -> Detector {
    let yaml = std::fs::read_to_string("data/pii_types.yaml").expect("read pii_types.yaml");
    let reg = Arc::new(Registry::from_yaml(&yaml).expect("parse registry"));
    let dicts = Arc::new(Dictionaries::load_dir(std::path::Path::new("data/dict")).expect("load dicts"));
    let allowlist_text = std::fs::read_to_string("data/allowlist.yaml").expect("read allowlist");
    let allowlist = Allowlist::from_yaml(&allowlist_text).expect("parse allowlist");
    Detector::with_allowlist(reg, dicts, allowlist)
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

fn detect_with_allowlist(text: &str) -> Vec<Entity> {
    let opts = DetectOptions {
        enabled_types: None,
        min_confidence: 0.0,
        allow_substrings: &[],
        trap_policy: TrapPolicy::PreferMask,
    };
    detector_with_allowlist().detect(text, &opts)
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
fn fio_mixed_case_full_span() {
    assert_span("Клиентка ИВАНОВА мария петровна обратилась", "fio", "ИВАНОВА мария петровна");
    assert_span("Клиентка Иванова мария петровна обратилась", "fio", "Иванова мария петровна");
    assert_span("Клиентка иванова Мария Петровна обратилась", "fio", "иванова Мария Петровна");
    assert_span("Клиентка ИВАНОВА МАРИЯ петровна обратилась", "fio", "ИВАНОВА МАРИЯ петровна");
    assert_span("клиент: сидоров ПЁТР иванович, тел 89123456789", "fio", "сидоров ПЁТР иванович");
    assert_span("Клиентка иВАНОВА мАРИЯ пЕТРОВНА обратилась", "fio", "иВАНОВА мАРИЯ пЕТРОВНА");
}

#[test]
fn fio_mixed_case_controls() {
    assert_span("Уважаемая Мария Петровна, ваша заявка принята", "fio", "Мария Петровна");
    assert_not_found("Отдел кадров сообщает", "fio");
}

#[test]
fn fio_greeting_marker_not_in_span() {
    assert_span("Уважаемый Блинов Сигизмунд, ваше заявление принято к рассмотрению.", "fio", "Блинов Сигизмунд");
    assert_span("Уважаемая Ксения! Ваше транспортное средство проверено специалистом.", "fio", "Ксения");
}

#[test]
fn fio_span_trims_punctuation() {
    assert_span("(Филиппова Ангелина Евгеньевна", "fio", "Филиппова Ангелина Евгеньевна");
    assert_span("\"Волков Харитон Матвеевич", "fio", "Волков Харитон Матвеевич");
    assert_span("('иванов иван иванович", "fio", "иванов иван иванович");
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
fn birth_place_hyphenated_cities_in_oblique_case() {
    // Hyphenated compound city names in an oblique case are recognized as a birth place.
    assert_span("Клиент родился в Санкт-Петербурге", "birth_place", "Санкт-Петербурге");
    assert_span("родился в Ростове-на-Дону", "birth_place", "Ростове-на-Дону");
    // The "г." marker form keeps working unchanged.
    assert_span("место рождения: г. Санкт-Петербург", "birth_place", "г. Санкт-Петербург");
}

#[test]
fn fio_hyphenated_compound_names() {
    // A hyphenated compound name is a single FIO token; the whole name is masked.
    assert_span(
        "Напиши письмо Анне-Марии Сергеевне Римской-Корсаковой",
        "fio",
        "Анне-Марии Сергеевне Римской-Корсаковой",
    );
    assert_span(
        "Клиент Салтыков-Щедрин Михаил Евграфович, тел. 89123456789",
        "fio",
        "Салтыков-Щедрин Михаил Евграфович",
    );
}

#[test]
fn citizenship() {
    assert_span("гражданство: Россия", "citizenship", "Россия");
    assert_span("гражданин РФ", "citizenship", "РФ");
    assert_span("гражданка Казахстана", "citizenship", "Казахстана");
    assert_not_found("Россия", "citizenship");
}

#[test]
fn citizenship_inflected_forms() {
    assert_span("Клиент гражданин России", "citizenship", "России");
    assert_span("Клиент, гражданин Российской Федерации", "citizenship", "Российской Федерации");
    assert_span("гражданин Республики Беларусь", "citizenship", "Республики Беларусь");
    assert_span("гражданство: Россия, гражданин РФ", "citizenship", "Россия");
}

#[test]
fn citizenship_not_part_of_fio() {
    let text = "гражданка России Иванова Мария";
    let entities = detect(text);
    let cit = entities
        .iter()
        .find(|e| e.type_id == "citizenship")
        .unwrap_or_else(|| panic!("citizenship not found in {:?}", entities));
    assert_eq!(&text[cit.start..cit.end], "России");
    let fio = entities
        .iter()
        .find(|e| e.type_id == "fio")
        .unwrap_or_else(|| panic!("fio not found in {:?}", entities));
    assert_eq!(&text[fio.start..fio.end], "Иванова Мария");
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
fn address_company_legal_address_not_detected() {
    // A legal/company address is an organization address, not a personal one, and must not
    // be masked at the production confidence threshold (0.3).
    assert_not_found_prod("Комментарий: Юридический адрес компании: г. Омск, пр. Мира, д. 1.", "address");
    assert_not_found_prod("Адрес организации: г. Омск, ул. Мира, д. 1", "address");
    assert_span("Проживает: г. Омск, пр. Мира, д. 1", "address", "г. Омск, пр. Мира, д. 1");
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

#[test]
fn public_persons_with_initials_and_cases_not_masked() {
    // Public persons written with initials or in an oblique case are biographical references,
    // not clients, and must not be masked.
    assert_not_found_with_allowlist("В свое время Пушкин А.С. написал немало рассказов и сказок.", "fio");
    assert_not_found_with_allowlist("В свое время Пушкин А. С. написал немало сказок.", "fio");
    assert_not_found_with_allowlist("В свое время А.С. Пушкин написал немало сказок.", "fio");
    assert_not_found_with_allowlist("Стихи А. С. Пушкина мы учили в школе.", "fio");
    assert_not_found_with_allowlist("Толстой Л.Н. написал «Войну и мир».", "fio");
    assert_not_found_with_allowlist("Мы читали стихи Александра Сергеевича Пушкина.", "fio");
}

#[test]
fn public_person_full_name_parts_not_masked() {
    // A full public-person name is a biographical reference; its parts ("Лев", "Николаевич")
    // must not remain as separate FIO candidates.
    assert_not_found_with_allowlist("Лев Николаевич Толстой родился в 1828 году.", "fio");
    assert_not_found_with_allowlist("Александр Сергеевич Пушкин родился в 1934 году.", "fio");
}

#[test]
fn public_person_without_surname_is_regular_fio() {
    // A name or name+patronymic that coincides with a public person's given name and patronymic
    // but lacks the surname is a regular FIO, not a known person, and must be masked.
    let entities = detect_with_allowlist("Борис Наседкин, сын Ивана Петровича, мечтал о дальних странах.");
    let spans: Vec<&str> = entities
        .iter()
        .filter(|e| e.type_id == "fio")
        .map(|e| text_span("Борис Наседкин, сын Ивана Петровича, мечтал о дальних странах.", e))
        .collect();
    assert!(
        spans.contains(&"Ивана Петровича"),
        "fio 'Ивана Петровича' should be found, got {:?}",
        spans
    );

    let entities = detect_with_allowlist("Уважаемый Лев Николаевич, ваша заявка принята.");
    let ent = entities
        .iter()
        .find(|e| e.type_id == "fio")
        .unwrap_or_else(|| panic!("fio should be found: {:?}", entities));
    assert_eq!(text_span("Уважаемый Лев Николаевич, ваша заявка принята.", ent), "Лев Николаевич");
}

fn text_span<'a>(text: &'a str, ent: &Entity) -> &'a str {
    &text[ent.start..ent.end]
}

#[test]
fn public_person_with_pii_context_still_masked() {
    // A public person with a strong PII marker ("клиент") and a confident neighbor (passport)
    // is a client and is still masked.
    let entities = detect_with_allowlist("Клиент Пушкин А.С., паспорт 4509 123456, обратился в банк.");
    assert!(
        entities.iter().any(|e| e.type_id == "fio"),
        "fio should be found: {:?}",
        entities
    );
}

#[test]
fn street_name_matching_surname_is_address_not_fio() {
    assert_span("проживает на улице Ленина, д. 5", "address", "улице Ленина, д. 5");
    assert_not_found("проживает на улице Ленина, д. 5", "fio");
    assert_span("Клиентка проживает на улице Ленина, д. 5, Екатеринбург", "address", "улице Ленина, д. 5, Екатеринбург");
    assert_not_found("Клиентка проживает на улице Ленина, д. 5, Екатеринбург", "fio");
    assert_span("живу на проспекте Гагарина 12", "address", "проспекте Гагарина 12");
    assert_not_found("живу на проспекте Гагарина 12", "fio");
    assert_span("переулок Чехова, дом 3", "address", "переулок Чехова, дом 3");
    assert_not_found("переулок Чехова, дом 3", "fio");
}

#[test]
fn street_name_matching_surname_with_fio_marker_stays_fio() {
    assert_span("Клиент Ленина Анна Петровна, тел. 89123456789", "fio", "Ленина Анна Петровна");
}

#[test]
fn street_address_extends_with_city_before() {
    // A city before the street (with or without a comma) is included in the address span.
    assert_span("адрес Московская область г. Химки ул. Победы 23", "address", "г. Химки ул. Победы 23");
    assert_span("адрес Екатеринбург ул. Ленина 99", "address", "Екатеринбург ул. Ленина 99");
    assert_span("В Коростене ул. Шевченко 12 переводят", "address", "Коростене ул. Шевченко 12");
}

#[test]
fn street_address_extends_with_city_after() {
    // A city after the street (after a comma) is included in the address span.
    assert_span("По адресу ш Щетинкина 1, Псебай", "address", "ш Щетинкина 1, Псебай");
    assert_not_found("По адресу ш Щетинкина 1, Псебай", "fio");
    assert_span("По адресу ш. Щетинкина 1, Псебай", "address", "ш. Щетинкина 1, Псебай");
    assert_not_found("По адресу ш. Щетинкина 1, Псебай", "fio");
}

#[test]
fn площадь_as_size_is_not_an_address() {
    // "площадь" as a size (общая площадь 42 кв.м) is not a street marker.
    assert_not_found("Общая площадь 42 кв.м., третий этаж", "address");
}

#[test]
fn address_hyphen_glued_and_dotless_markers() {
    // A house number with a hyphenated apartment tail (дом-квартира) is part of the address.
    let entities = detect("Живу на проспекте Мира 12-45");
    let addr = entities
        .iter()
        .find(|e| e.type_id == "address")
        .unwrap_or_else(|| panic!("address not found in {:?}", entities));
    assert!(
        text_span("Живу на проспекте Мира 12-45", addr).contains("Мира 12-45"),
        "span {:?} does not cover 'Мира 12-45'",
        text_span("Живу на проспекте Мира 12-45", addr)
    );
    // Markers with a dot need no space before the number (д.10А, кв.3).
    let entities = detect("Зарегистрирован по адресу г. Химки, ул. Мичурина, д.10А, кв.3");
    let addr = entities
        .iter()
        .find(|e| e.type_id == "address")
        .unwrap_or_else(|| panic!("address not found in {:?}", entities));
    assert!(
        text_span("Зарегистрирован по адресу г. Химки, ул. Мичурина, д.10А, кв.3", addr)
            .contains("д.10А, кв.3"),
        "span {:?} does not cover 'д.10А, кв.3'",
        text_span("Зарегистрирован по адресу г. Химки, ул. Мичурина, д.10А, кв.3", addr)
    );
    // Dotless markers (г, ул, д, кв) work as their dotted forms.
    let entities = detect("г Новосибирск ул Красный проспект д 3 кв 7");
    let addr = entities
        .iter()
        .find(|e| e.type_id == "address")
        .unwrap_or_else(|| panic!("address not found in {:?}", entities));
    assert!(
        text_span("г Новосибирск ул Красный проспект д 3 кв 7", addr)
            .contains("Новосибирск ул Красный проспект д 3 кв 7"),
        "span {:?} does not cover 'Новосибирск ул Красный проспект д 3 кв 7'",
        text_span("г Новосибирск ул Красный проспект д 3 кв 7", addr)
    );
    // "кв.м" as a size is not an address.
    assert_not_found("Общая площадь 42 кв.м., третий этаж.", "address");
}

#[test]
fn house_number_with_letter_is_included() {
    // A house number with a letter (дом 1А) is part of the address span.
    assert_span("на улице Карьерной, дом 1А,", "address", "улице Карьерной, дом 1А");
}

#[test]
fn address_span_trims_trailing_punctuation() {
    // The address span must end on a letter or digit, not on punctuation.
    assert_span("ш Королева 176, Камышин.", "address", "ш Королева 176, Камышин");
    assert_span("ул. Тверская 5, Москва?", "address", "ул. Тверская 5, Москва");
    assert_span("пер. Чкалова 21, Ершов.\"}", "address", "пер. Чкалова 21, Ершов");
}

#[test]
fn address_trailing_word_must_be_city() {
    // A non-city capitalized word after the street is not attached to the address.
    assert_span("ул. Гончарова 754 Лидия", "address", "ул. Гончарова 754");
}

#[test]
fn address_house_number_with_korpus() {
    // A house number with a корпус/строение suffix (69к3, 17к2с1, 92/3, 1А) is fully included.
    assert_span("ул. Павлова, д. 69к3, кв. 216", "address", "ул. Павлова, д. 69к3, кв. 216");
    assert_span("ул. Павлова, д. 17к2с1", "address", "ул. Павлова, д. 17к2с1");
    assert_span("ул. Павлова, д. 92/3", "address", "ул. Павлова, д. 92/3");
    assert_span("ул. Павлова, д. 1А", "address", "ул. Павлова, д. 1А");
}

#[test]
fn address_city_marker_included() {
    // The "г." marker before a city is part of the address span.
    assert_span("г. Мелеуз, пр. Мая 1, д. 39", "address", "г. Мелеуз, пр. Мая 1, д. 39");
}

fn assert_not_found_with_allowlist(text: &str, type_id: &str) {
    let entities = detect_with_allowlist(text);
    assert!(
        !entities.iter().any(|e| e.type_id == type_id),
        "type {type_id} should not be found in {text:?}, got {:?}",
        entities
    );
}

fn detect_prod(text: &str) -> Vec<Entity> {
    let opts = DetectOptions {
        enabled_types: None,
        min_confidence: 0.3,
        allow_substrings: &[],
        trap_policy: TrapPolicy::PreferMask,
    };
    detector().detect(text, &opts)
}

fn assert_not_found_prod(text: &str, type_id: &str) {
    let entities = detect_prod(text);
    assert!(
        !entities.iter().any(|e| e.type_id == type_id),
        "type {type_id} should not be found in {text:?}, got {:?}",
        entities
    );
}

#[test]
fn street_address_with_comma_before_house_number() {
    // A comma between the street name and the house number (and корпус/кв) is part of the
    // address. The street name after a street marker is a street, not a FIO or a public person.
    assert_span(
        "Адрес: улица Пушкина, 23, корпус 1. Позвоню на 89161234567",
        "address",
        "улица Пушкина, 23, корпус 1",
    );
    assert_span(
        "2014-12-01 09:00 - курс рубля упал вдвое, адрес: ул. Пушкина, 10, спад",
        "address",
        "ул. Пушкина, 10",
    );
    assert_span(
        "на чердаке старого дома на улице Пушкина, 14, внезапно",
        "address",
        "улице Пушкина, 14",
    );
    assert_span(
        "ул. Гагарина, 45, кв. 12 подьезд 2 домофон сломан поднимитесь сами",
        "address",
        "ул. Гагарина, 45, кв. 12",
    );
}

#[test]
fn street_address_public_person_surname_with_city() {
    // A street name that is a public person's surname (Маркса, Пушкина) is a street, not a
    // person; the house number, корпус and квартира after it attach as usual.
    assert_span(
        "переехал на новый адрес Новосибирск, проспект Маркса, 78, кв 91",
        "address",
        "Новосибирск, проспект Маркса, 78, кв 91",
    );
    assert_span(
        "записали вас на Санкт-Петербург, улица Пушкина, 88, кв 34",
        "address",
        "Санкт-Петербург, улица Пушкина, 88, кв 34",
    );
}

#[test]
fn address_city_that_is_part_of_fio_not_attached() {
    // A city-form word that is part of a found FIO (Гусева is the genitive of the city Гусев
    // and a surname) is a person, not a city, and must not be attached to the address.
    let text = "Дарья Гусева, ш. Ростовская 178 кв. 299 — куда везти заказ?";
    let entities = detect(text);
    let fio = entities
        .iter()
        .find(|e| e.type_id == "fio")
        .unwrap_or_else(|| panic!("fio not found in {:?}", entities));
    assert_eq!(&text[fio.start..fio.end], "Дарья Гусева");
    let addr = entities
        .iter()
        .find(|e| e.type_id == "address")
        .unwrap_or_else(|| panic!("address not found in {:?}", entities));
    assert_eq!(&text[addr.start..addr.end], "ш. Ростовская 178 кв. 299");
}

#[test]
fn biography_birth_place_and_date_not_masked() {
    // A birth place and a historical birth date whose nearest FIO to the left is a known
    // person (dropped by the biographical marker "поэт") are biographical references, not a
    // client's data, and must not be masked at all.
    assert_not_found_with_allowlist(
        "Поэт Александр Сергеевич Пушкин родился 6 июня 1799 года в Москве.",
        "birth_place",
    );
    assert_not_found_with_allowlist(
        "Поэт Александр Сергеевич Пушкин родился 6 июня 1799 года в Москве.",
        "birth_date",
    );
    assert_not_found_with_allowlist(
        "Поэт Александр Сергеевич Пушкин родился 6 июня 1799 года в Москве.",
        "fio",
    );
    // A known person dropped by the known-person rule (no biographical marker) also drops the
    // birth place and the historical date.
    assert_not_found_with_allowlist(
        "Лев Николаевич Толстой родился в Ясной Поляне в 1828 году.",
        "birth_place",
    );
    assert_not_found_with_allowlist(
        "Лев Николаевич Толстой родился в Ясной Поляне в 1828 году.",
        "birth_date",
    );
    assert_not_found_with_allowlist(
        "Лев Николаевич Толстой родился в Ясной Поляне в 1828 году.",
        "fio",
    );
}

#[test]
fn address_does_not_cross_a_date() {
    // A date is always a date: the address span must not swallow the leading number of a
    // date (e.g. "ПУШКИН АЛЕКСАНДР СЕРГЕЕВИЧ, 06" must not become an address crossing
    // "06.06.1988"). The FIO and the birth date are detected separately.
    let text = "Наш клиент ПУШКИН АЛЕКСАНДР СЕРГЕЕВИЧ, 06.06.1988 г.р.";
    let entities = detect_with_allowlist(text);
    let fio = entities
        .iter()
        .find(|e| e.type_id == "fio")
        .unwrap_or_else(|| panic!("fio not found in {:?}", entities));
    assert_eq!(&text[fio.start..fio.end], "ПУШКИН АЛЕКСАНДР СЕРГЕЕВИЧ");
    let bd = entities
        .iter()
        .find(|e| e.type_id == "birth_date")
        .unwrap_or_else(|| panic!("birth_date not found in {:?}", entities));
    assert_eq!(&text[bd.start..bd.end], "06.06.1988");
    assert!(
        !entities.iter().any(|e| e.type_id == "address"),
        "address should not be found in {:?}",
        entities
    );
}

#[test]
fn client_fio_birth_date_address() {
    // A client's FIO, birth date and address are all detected independently.
    let text = "Клиент Иванов Иван, 12.03.1985 г.р., проживает: Москва, ул. Лесная, дом 17";
    let entities = detect(text);
    let fio = entities
        .iter()
        .find(|e| e.type_id == "fio")
        .unwrap_or_else(|| panic!("fio not found in {:?}", entities));
    assert_eq!(&text[fio.start..fio.end], "Иванов Иван");
    let bd = entities
        .iter()
        .find(|e| e.type_id == "birth_date")
        .unwrap_or_else(|| panic!("birth_date not found in {:?}", entities));
    assert_eq!(&text[bd.start..bd.end], "12.03.1985");
    let addr = entities
        .iter()
        .find(|e| e.type_id == "address")
        .unwrap_or_else(|| panic!("address not found in {:?}", entities));
    assert_eq!(&text[addr.start..addr.end], "Москва, ул. Лесная, дом 17");
}

#[test]
fn birth_date_year_first_formats() {
    // Year-first formats: yyyy.dd.mm (day > 12 disambiguates), yyyy.mm.dd (otherwise), and
    // yyyy-mm-dd.
    assert_span("Дата рождения клиента: 1985.31.12", "birth_date", "1985.31.12");
    assert_span("Дата рождения клиента: 1985.12.31", "birth_date", "1985.12.31");
    assert_span("Дата рождения клиента: 1985-12-31", "birth_date", "1985-12-31");
}

#[test]
fn birth_place_for_client_not_celebrity() {
    // A client (not a known person) born in a city: the birth place is masked.
    let text = "Клиент родился в Москве, паспорт 4509 123456";
    let entities = detect(text);
    let bp = entities
        .iter()
        .find(|e| e.type_id == "birth_place")
        .unwrap_or_else(|| panic!("birth_place not found in {:?}", entities));
    assert_eq!(&text[bp.start..bp.end], "Москве");
    let pp = entities
        .iter()
        .find(|e| e.type_id == "passport")
        .unwrap_or_else(|| panic!("passport not found in {:?}", entities));
    assert_eq!(&text[pp.start..pp.end], "4509 123456");
}
