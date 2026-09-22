use detox_proxy::mask::{count_unresolved_tokens, mask, stars, unmask, MaskOptions};
use detox_proxy::registry::Registry;
use detox_proxy::types::{Entity, MaskMode, Mapping};
use std::collections::HashMap;

fn load() -> Registry {
    let yaml = std::fs::read_to_string("data/pii_types.yaml").expect("read pii_types.yaml");
    Registry::from_yaml(&yaml).expect("parse registry")
}

fn ent(type_id: &str, start: usize, end: usize, confidence: f32) -> Entity {
    Entity {
        type_id: type_id.to_string(),
        start,
        end,
        confidence,
    }
}

fn token_opts(overrides: &HashMap<String, MaskMode>) -> MaskOptions<'_> {
    MaskOptions {
        default_mode: MaskMode::Token,
        overrides,
        combination_rule: false,
    }
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

fn roundtrip(reg: &Registry, text: &str, entities: Vec<Entity>) {
    let overrides = HashMap::new();
    let res = mask(text, &entities, reg, &token_opts(&overrides));
    let restored = unmask(&res.text, &res.mappings);
    assert_eq!(restored, text, "round-trip failed for {text:?}");
}

#[test]
fn token_same_value_shared_and_mappings() {
    let reg = load();
    let text = "Клиент Иванов Иван Иванович, ИНН 7707083893, тел. +7 912 345-67-89. Иванов Иван Иванович просил перезвонить.";
    let fio = "Иванов Иван Иванович";
    let fio1 = text.find(fio).unwrap();
    let inn = text.find("7707083893").unwrap();
    let phone = text.find("+7 912 345-67-89").unwrap();
    let fio2 = text.rfind(fio).unwrap();
    let entities = vec![
        ent("fio", fio1, fio1 + fio.len(), 0.9),
        ent("inn", inn, inn + 10, 0.9),
        ent("phone", phone, phone + "+7 912 345-67-89".len(), 0.9),
        ent("fio", fio2, fio2 + fio.len(), 0.9),
    ];
    let res = mask(text, &entities, &reg, &token_opts(&HashMap::new()));
    assert_eq!(
        res.text,
        "Клиент <<FIO_1>>, ИНН <<INN_1>>, тел. <<PHONE_1>>. <<FIO_1>> просил перезвонить."
    );
    assert_eq!(res.mappings.len(), 3);
}

#[test]
fn two_inns_numbered_in_order() {
    let reg = load();
    let text = "ИНН 7707083893 и ИНН 500100732259";
    let inn1 = text.find("7707083893").unwrap();
    let inn2 = text.find("500100732259").unwrap();
    let entities = vec![
        ent("inn", inn1, inn1 + 10, 0.9),
        ent("inn", inn2, inn2 + 12, 0.9),
    ];
    let res = mask(text, &entities, &reg, &token_opts(&HashMap::new()));
    assert_eq!(res.text, "ИНН <<INN_1>> и ИНН <<INN_2>>");
}

#[test]
fn roundtrip_ten_texts() {
    let reg = load();

    let t1 = "Клиент Иванов Иван Иванович, ИНН 7707083893, тел. +7 912 345-67-89.";
    let f = t1.find("Иванов Иван Иванович").unwrap();
    let i = t1.find("7707083893").unwrap();
    let p = t1.find("+7 912 345-67-89").unwrap();
    roundtrip(
        &reg,
        t1,
        vec![
            ent("fio", f, f + "Иванов Иван Иванович".len(), 0.9),
            ent("inn", i, i + 10, 0.9),
            ent("phone", p, p + "+7 912 345-67-89".len(), 0.9),
        ],
    );

    let t2 = "Привет 👋, карта 4111 1111 1111 1111, email ivan@mail.ru";
    let c = t2.find("4111 1111 1111 1111").unwrap();
    let e = t2.find("ivan@mail.ru").unwrap();
    roundtrip(
        &reg,
        t2,
        vec![
            ent("card_number", c, c + "4111 1111 1111 1111".len(), 0.9),
            ent("email", e, e + "ivan@mail.ru".len(), 0.9),
        ],
    );

    let t3 = "Строка 1\nИНН 7707083893\nСтрока 3";
    let i = t3.find("7707083893").unwrap();
    roundtrip(&reg, t3, vec![ent("inn", i, i + 10, 0.9)]);

    let t4 = "{\"name\": \"Иванов Иван\", \"phone\": \"+7 912 345-67-89\"}";
    let f = t4.find("Иванов Иван").unwrap();
    let p = t4.find("+7 912 345-67-89").unwrap();
    roundtrip(
        &reg,
        t4,
        vec![
            ent("fio", f, f + "Иванов Иван".len(), 0.9),
            ent("phone", p, p + "+7 912 345-67-89".len(), 0.9),
        ],
    );

    let t5 = "паспорт 4509 123456";
    let s = t5.find("4509 123456").unwrap();
    roundtrip(&reg, t5, vec![ent("passport", s, s + "4509 123456".len(), 0.9)]);

    let t6 = "карта 4111 1111 1111 1111";
    let s = t6.find("4111 1111 1111 1111").unwrap();
    roundtrip(&reg, t6, vec![ent("card_number", s, s + "4111 1111 1111 1111".len(), 0.9)]);

    let t7 = "тел. 8-912-345-67-89";
    let s = t7.find("8-912-345-67-89").unwrap();
    roundtrip(&reg, t7, vec![ent("phone", s, s + "8-912-345-67-89".len(), 0.9)]);

    let t8 = "почта ivan.petrov@mail.ru";
    let s = t8.find("ivan.petrov@mail.ru").unwrap();
    roundtrip(&reg, t8, vec![ent("email", s, s + "ivan.petrov@mail.ru".len(), 0.9)]);

    let t9 = "ИНН 7707083893 и ИНН 7707083893";
    let s1 = t9.find("7707083893").unwrap();
    let s2 = t9.rfind("7707083893").unwrap();
    roundtrip(
        &reg,
        t9,
        vec![
            ent("inn", s1, s1 + 10, 0.9),
            ent("inn", s2, s2 + 10, 0.9),
        ],
    );

    let t10 = "СНИЛС 112-233-445 95";
    let s = t10.find("112-233-445 95").unwrap();
    roundtrip(&reg, t10, vec![ent("snils", s, s + "112-233-445 95".len(), 0.9)]);
}

#[test]
fn unmask_in_other_context() {
    let mappings = vec![
        Mapping {
            type_id: "fio".into(),
            original: "Иванов Иван Иванович".into(),
            masked: "<<FIO_1>>".into(),
        },
        Mapping {
            type_id: "inn".into(),
            original: "7707083893".into(),
            masked: "<<INN_1>>".into(),
        },
    ];
    let llm = "SELECT * FROM users WHERE inn = '<<INN_1>>' AND name = \"<<fio_1>>\"; -- <<INN_1>>";
    let restored = unmask(llm, &mappings);
    assert_eq!(
        restored,
        "SELECT * FROM users WHERE inn = '7707083893' AND name = \"Иванов Иван Иванович\"; -- 7707083893"
    );
}

#[test]
fn unknown_token_left_untouched() {
    let text = "токен <<CARD_9>> остаётся";
    assert_eq!(unmask(text, &[]), text);
}

#[test]
fn stars_examples() {
    assert_eq!(stars("4509 123456", "passport", 2, 2), "45** ****56");
    assert_eq!(stars("+7 (912) 345-67-89", "phone", 2, 2), "+7 (***) ***-**-89");
    assert_eq!(stars("ivan.petrov@mail.ru", "email", 1, 0), "i**********@mail.ru");
    assert_eq!(stars("Иванов Иван Иванович", "fio", 0, 0), "И. И. И.");
}

#[test]
fn stars_roundtrip() {
    let reg = load();
    let text = "паспорт 4509 123456, тел. +7 (912) 345-67-89, почта ivan.petrov@mail.ru";
    let p = text.find("4509 123456").unwrap();
    let ph = text.find("+7 (912) 345-67-89").unwrap();
    let e = text.find("ivan.petrov@mail.ru").unwrap();
    let entities = vec![
        ent("passport", p, p + "4509 123456".len(), 0.9),
        ent("phone", ph, ph + "+7 (912) 345-67-89".len(), 0.9),
        ent("email", e, e + "ivan.petrov@mail.ru".len(), 0.9),
    ];
    let overrides = HashMap::new();
    let opts = MaskOptions {
        default_mode: MaskMode::Stars,
        overrides: &overrides,
        combination_rule: false,
    };
    let res = mask(text, &entities, &reg, &opts);
    let restored = unmask(&res.text, &res.mappings);
    assert_eq!(restored, text);
}

#[test]
fn synthetic_card_luhn_and_roundtrip() {
    let reg = load();
    let text = "карта 4111 1111 1111 1111 и карта 4111 1111 1111 1111";
    let s1 = text.find("4111 1111 1111 1111").unwrap();
    let s2 = text.rfind("4111 1111 1111 1111").unwrap();
    let entities = vec![
        ent("card_number", s1, s1 + "4111 1111 1111 1111".len(), 0.9),
        ent("card_number", s2, s2 + "4111 1111 1111 1111".len(), 0.9),
    ];
    let overrides = HashMap::new();
    let opts = MaskOptions {
        default_mode: MaskMode::Synthetic,
        overrides: &overrides,
        combination_rule: false,
    };
    let res = mask(text, &entities, &reg, &opts);
    let parts: Vec<&str> = res.text.split(" и ").collect();
    assert_eq!(parts.len(), 2);
    let first = parts[0];
    let second = parts[1];
    assert_eq!(first, second, "same input gives same replacement within a call");
    assert_ne!(first, "карта 4111 1111 1111 1111", "synthetic must differ from original");
    let digits: String = first.chars().filter(|c| c.is_ascii_digit()).collect();
    assert_eq!(digits.len(), 16);
    assert!(luhn(&digits), "synthetic card must pass Luhn");
    let masked_num = first.strip_prefix("карта ").unwrap();
    assert_eq!(masked_num.chars().filter(|c| *c == ' ').count(), 3, "separator format preserved");
    let restored = unmask(&res.text, &res.mappings);
    assert_eq!(restored, text);
}

#[test]
fn overrides_cvv_stars() {
    let reg = load();
    let text = "CVV 123, карта 4111 1111 1111 1111";
    let cvv = text.find("123").unwrap();
    let card = text.find("4111 1111 1111 1111").unwrap();
    let entities = vec![
        ent("cvv", cvv, cvv + 3, 0.9),
        ent("card_number", card, card + "4111 1111 1111 1111".len(), 0.9),
    ];
    let mut overrides = HashMap::new();
    overrides.insert("cvv".to_string(), MaskMode::Stars);
    let opts = MaskOptions {
        default_mode: MaskMode::Token,
        overrides: &overrides,
        combination_rule: false,
    };
    let res = mask(text, &entities, &reg, &opts);
    assert!(res.text.contains("<<CARD_1>>"));
    assert!(res.text.contains("***"));
    assert!(!res.text.contains("<<CVV_1>>"));
}

#[test]
fn off_type_untouched() {
    let reg = load();
    let text = "ИНН 7707083893";
    let s = text.find("7707083893").unwrap();
    let entities = vec![ent("inn", s, s + 10, 0.9)];
    let mut overrides = HashMap::new();
    overrides.insert("inn".to_string(), MaskMode::Off);
    let opts = MaskOptions {
        default_mode: MaskMode::Token,
        overrides: &overrides,
        combination_rule: false,
    };
    let res = mask(text, &entities, &reg, &opts);
    assert_eq!(res.text, text);
    assert!(res.mappings.is_empty());
    assert!(res.entities.is_empty());
}

#[test]
fn combination_rule() {
    let reg = load();
    let overrides = HashMap::new();
    let opts = MaskOptions {
        default_mode: MaskMode::Token,
        overrides: &overrides,
        combination_rule: true,
    };

    let text1 = "пин-код 1234";
    let pin = text1.find("1234").unwrap();
    let entities1 = vec![ent("card_pin", pin, pin + 4, 0.9)];
    let res1 = mask(text1, &entities1, &reg, &opts);
    assert_eq!(res1.text, text1, "pin without card must not be masked");
    assert!(res1.mappings.is_empty());

    let text2 = "пин-код 1234, карта 4111 1111 1111 1111";
    let pin2 = text2.find("1234").unwrap();
    let card2 = text2.find("4111 1111 1111 1111").unwrap();
    let entities2 = vec![
        ent("card_pin", pin2, pin2 + 4, 0.9),
        ent("card_number", card2, card2 + "4111 1111 1111 1111".len(), 0.9),
    ];
    let res2 = mask(text2, &entities2, &reg, &opts);
    assert!(res2.text.contains("<<PIN_1>>"));
    assert!(res2.text.contains("<<CARD_1>>"));

    let opts_false = MaskOptions {
        default_mode: MaskMode::Token,
        overrides: &overrides,
        combination_rule: false,
    };
    let res3 = mask(text1, &entities1, &reg, &opts_false);
    assert!(res3.text.contains("<<PIN_1>>"));
}

#[test]
fn offsets_with_non_ascii() {
    let reg = load();
    let text = "Привет мир! ИНН 7707083893, конец.";
    let s = text.find("7707083893").unwrap();
    let entities = vec![ent("inn", s, s + 10, 0.9)];
    let res = mask(text, &entities, &reg, &token_opts(&HashMap::new()));
    assert_eq!(res.text, "Привет мир! ИНН <<INN_1>>, конец.");
    let restored = unmask(&res.text, &res.mappings);
    assert_eq!(restored, text);
}

#[test]
fn mask_oblique_fio_produces_token() {
    let reg = load();
    let text = "Иванову Ивану Ивановичу";
    let entities = vec![ent("fio", 0, text.len(), 0.9)];
    let res = mask(text, &entities, &reg, &token_opts(&HashMap::new()));
    assert_eq!(res.text, "<<FIO_1>>");
}

#[test]
fn unmask_case_suffix_inflects() {
    let mappings = vec![
        Mapping {
            type_id: "fio".into(),
            original: "Иванов Иван Иванович".into(),
            masked: "<<FIO_1>>".into(),
        },
        Mapping {
            type_id: "inn".into(),
            original: "7707083893".into(),
            masked: "<<INN_1>>".into(),
        },
        Mapping {
            type_id: "birth_place".into(),
            original: "Москва".into(),
            masked: "<<BPLACE_1>>".into(),
        },
    ];

    assert_eq!(
        unmask("Дорогой <<FIO_1:им>>", &mappings),
        "Дорогой Иванов Иван Иванович"
    );
    assert_eq!(unmask("<<FIO_1:дат>>", &mappings), "Иванову Ивану Ивановичу");
    assert_eq!(unmask("<<FIO_1>>", &mappings), "Иванов Иван Иванович");
    assert_eq!(unmask("<<INN_1:дат>>", &mappings), "7707083893");
    assert_eq!(unmask("родился в <<BPLACE_1:пр>>", &mappings), "родился в Москве");
}

#[test]
fn unmask_case_suffix_whitespace_and_case_tolerant() {
    let mappings = vec![Mapping {
        type_id: "fio".into(),
        original: "Иванов Иван Иванович".into(),
        masked: "<<FIO_1>>".into(),
    }];
    assert_eq!(unmask("<<fio_1 : dat>>", &mappings), "Иванову Ивану Ивановичу");
}

#[test]
fn unmask_unknown_case_suffix_left_untouched() {
    let mappings = vec![Mapping {
        type_id: "fio".into(),
        original: "Иванов Иван Иванович".into(),
        masked: "<<FIO_1>>".into(),
    }];
    assert_eq!(unmask("<<FIO_1:xyz>>", &mappings), "<<FIO_1:xyz>>");
}

#[test]
fn count_unresolved_tokens_with_case_suffix() {
    let mappings = vec![Mapping {
        type_id: "fio".into(),
        original: "Иванов Иван Иванович".into(),
        masked: "<<FIO_1>>".into(),
    }];
    assert_eq!(count_unresolved_tokens("<<FIO_1:дат>>", &mappings), 0);
    assert_eq!(count_unresolved_tokens("<<FIO_1:дат>> <<INN_1>>", &mappings), 1);
}

#[test]
fn remove_unmask_returns_text_unchanged() {
    let reg = load();
    let text = "паспорт Сидоров Пётр Иванович, ИНН 7707083893";
    let f = text.find("Сидоров Пётр Иванович").unwrap();
    let i = text.find("7707083893").unwrap();
    let entities = vec![
        ent("fio", f, f + "Сидоров Пётр Иванович".len(), 0.9),
        ent("inn", i, i + 10, 0.9),
    ];
    let overrides = HashMap::new();
    let opts = MaskOptions {
        default_mode: MaskMode::Remove,
        overrides: &overrides,
        combination_rule: false,
    };
    let res = mask(text, &entities, &reg, &opts);
    assert_eq!(res.text, "паспорт [removed], ИНН [removed]");
    let restored = unmask(&res.text, &res.mappings);
    assert_eq!(restored, res.text, "remove mode must not be reversible");
}

#[test]
fn synthetic_address_replaces_city_and_street() {
    let reg = load();
    let text = "проживает: г. Казань, ул. Баумана, д. 14, кв. 8";
    let addr = "г. Казань, ул. Баумана, д. 14, кв. 8";
    let s = text.find(addr).unwrap();
    let entities = vec![ent("address", s, s + addr.len(), 0.9)];
    let overrides = HashMap::new();
    let opts = MaskOptions {
        default_mode: MaskMode::Synthetic,
        overrides: &overrides,
        combination_rule: false,
    };
    let res = mask(text, &entities, &reg, &opts);
    assert!(!res.text.contains("Казань"), "city must be replaced, got {}", res.text);
    assert!(!res.text.contains("Баумана"), "street must be replaced, got {}", res.text);
}