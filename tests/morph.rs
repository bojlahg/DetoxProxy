use detox_proxy::morph::{inflect, Case, Gender, Kind};

const ALL_CASES: [Case; 6] = [
    Case::Nom,
    Case::Gen,
    Case::Dat,
    Case::Acc,
    Case::Ins,
    Case::Prep,
];

fn check(kind: Kind, value: &str, expected: [&str; 6]) {
    for (i, case) in ALL_CASES.iter().enumerate() {
        assert_eq!(
            inflect(value, kind, *case).as_deref(),
            Some(expected[i]),
            "inflect({value:?}, {kind:?}, {case:?})"
        );
    }
}

/// For each case form, reverse-inflecting back to nominative must reproduce
/// the nominative form.
fn check_reverse(kind: Kind, value: &str, expected: [&str; 6]) {
    for form in expected {
        assert_eq!(
            inflect(form, kind, Case::Nom).as_deref(),
            Some(value),
            "reverse inflect({form:?}, {kind:?}, Nom) == {value:?}"
        );
    }
}

fn check_both(kind: Kind, value: &str, expected: [&str; 6]) {
    check(kind, value, expected);
    check_reverse(kind, value, expected);
}

#[test]
fn case_parse() {
    assert_parse("им", Some(Case::Nom));
    assert_parse("NOM", Some(Case::Nom));
    assert_parse("род", Some(Case::Gen));
    assert_parse("gen", Some(Case::Gen));
    assert_parse("дат", Some(Case::Dat));
    assert_parse("dat", Some(Case::Dat));
    assert_parse("вин", Some(Case::Acc));
    assert_parse("acc", Some(Case::Acc));
    assert_parse("твор", Some(Case::Ins));
    assert_parse("тв", Some(Case::Ins));
    assert_parse("ins", Some(Case::Ins));
    assert_parse("пр", Some(Case::Prep));
    assert_parse("предл", Some(Case::Prep));
    assert_parse("prep", Some(Case::Prep));
    assert_parse("xyz", None);
    assert_parse("", None);
}

fn assert_parse(input: &str, expected: Option<Case>) {
    assert_eq!(Case::parse(input), expected);
}

#[test]
fn person_ivanov() {
    check_both(
        Kind::Person,
        "Иванов Иван Иванович",
        [
            "Иванов Иван Иванович",
            "Иванова Ивана Ивановича",
            "Иванову Ивану Ивановичу",
            "Иванова Ивана Ивановича",
            "Ивановым Иваном Ивановичем",
            "Иванове Иване Ивановиче",
        ],
    );
}

#[test]
fn person_ivanova() {
    check_both(
        Kind::Person,
        "Иванова Мария Петровна",
        [
            "Иванова Мария Петровна",
            "Ивановой Марии Петровны",
            "Ивановой Марии Петровне",
            "Иванову Марию Петровну",
            "Ивановой Марией Петровной",
            "Ивановой Марии Петровне",
        ],
    );
}

#[test]
fn person_petrov_ilya() {
    check_both(
        Kind::Person,
        "Петров Илья Сергеевич",
        [
            "Петров Илья Сергеевич",
            "Петрова Ильи Сергеевича",
            "Петрову Илье Сергеевичу",
            "Петрова Илью Сергеевича",
            "Петровым Ильей Сергеевичем",
            "Петрове Илье Сергеевиче",
        ],
    );
}

#[test]
fn person_kuznetsova_lyubov() {
    check_both(
        Kind::Person,
        "Кузнецова Любовь Андреевна",
        [
            "Кузнецова Любовь Андреевна",
            "Кузнецовой Любови Андреевны",
            "Кузнецовой Любови Андреевне",
            "Кузнецову Любовь Андреевну",
            "Кузнецовой Любовью Андреевной",
            "Кузнецовой Любови Андреевне",
        ],
    );
}

#[test]
fn person_smirnov_andrey() {
    check_both(
        Kind::Person,
        "Смирнов Андрей Игоревич",
        [
            "Смирнов Андрей Игоревич",
            "Смирнова Андрея Игоревича",
            "Смирнову Андрею Игоревичу",
            "Смирнова Андрея Игоревича",
            "Смирновым Андреем Игоревичем",
            "Смирнове Андрее Игоревиче",
        ],
    );
}

#[test]
fn person_tolstoy_lev() {
    check_both(
        Kind::Person,
        "Толстой Лев Николаевич",
        [
            "Толстой Лев Николаевич",
            "Толстого Льва Николаевича",
            "Толстому Льву Николаевичу",
            "Толстого Льва Николаевича",
            "Толстым Львом Николаевичем",
            "Толстом Льве Николаевиче",
        ],
    );
}

#[test]
fn person_dostoevsky() {
    check_both(
        Kind::Person,
        "Достоевский Фёдор Михайлович",
        [
            "Достоевский Фёдор Михайлович",
            "Достоевского Фёдора Михайловича",
            "Достоевскому Фёдору Михайловичу",
            "Достоевского Фёдора Михайловича",
            "Достоевским Фёдором Михайловичем",
            "Достоевском Фёдоре Михайловиче",
        ],
    );
}

#[test]
fn person_shevchenko() {
    check_both(
        Kind::Person,
        "Шевченко Тарас Григорьевич",
        [
            "Шевченко Тарас Григорьевич",
            "Шевченко Тараса Григорьевича",
            "Шевченко Тарасу Григорьевичу",
            "Шевченко Тараса Григорьевича",
            "Шевченко Тарасом Григорьевичем",
            "Шевченко Тарасе Григорьевиче",
        ],
    );
}

#[test]
fn person_sidorova_anna() {
    check_both(
        Kind::Person,
        "Сидорова Анна",
        [
            "Сидорова Анна",
            "Сидоровой Анны",
            "Сидоровой Анне",
            "Сидорову Анну",
            "Сидоровой Анной",
            "Сидоровой Анне",
        ],
    );
}

#[test]
fn person_uppercase() {
    check_both(
        Kind::Person,
        "ИВАНОВ ИВАН",
        [
            "ИВАНОВ ИВАН",
            "ИВАНОВА ИВАНА",
            "ИВАНОВУ ИВАНУ",
            "ИВАНОВА ИВАНА",
            "ИВАНОВЫМ ИВАНОМ",
            "ИВАНОВЕ ИВАНЕ",
        ],
    );
}

#[test]
fn place_moscow() {
    check_both(
        Kind::Place,
        "Москва",
        ["Москва", "Москвы", "Москве", "Москву", "Москвой", "Москве"],
    );
}

#[test]
fn place_kazan() {
    check_both(
        Kind::Place,
        "Казань",
        ["Казань", "Казани", "Казани", "Казань", "Казанью", "Казани"],
    );
}

#[test]
fn place_omsk() {
    check_both(
        Kind::Place,
        "Омск",
        ["Омск", "Омска", "Омску", "Омск", "Омском", "Омске"],
    );
}

#[test]
fn place_tver() {
    check_both(
        Kind::Place,
        "Тверь",
        ["Тверь", "Твери", "Твери", "Тверь", "Тверью", "Твери"],
    );
}

#[test]
fn place_nizhny_novgorod() {
    check_both(
        Kind::Place,
        "Нижний Новгород",
        [
            "Нижний Новгород",
            "Нижнего Новгорода",
            "Нижнему Новгороду",
            "Нижний Новгород",
            "Нижним Новгородом",
            "Нижнем Новгороде",
        ],
    );
}

#[test]
fn place_pushkin() {
    check_both(
        Kind::Place,
        "Пушкин",
        ["Пушкин", "Пушкина", "Пушкину", "Пушкин", "Пушкином", "Пушкине"],
    );
}

#[test]
fn place_sochi() {
    check_both(
        Kind::Place,
        "Сочи",
        ["Сочи", "Сочи", "Сочи", "Сочи", "Сочи", "Сочи"],
    );
}

#[test]
fn country_russia() {
    check_both(
        Kind::Country,
        "Россия",
        ["Россия", "России", "России", "Россию", "Россией", "России"],
    );
}

#[test]
fn country_russian_federation() {
    check_both(
        Kind::Country,
        "Российская Федерация",
        [
            "Российская Федерация",
            "Российской Федерации",
            "Российской Федерации",
            "Российскую Федерацию",
            "Российской Федерацией",
            "Российской Федерации",
        ],
    );
}

#[test]
fn country_belarus() {
    check_both(
        Kind::Country,
        "Беларусь",
        ["Беларусь", "Беларуси", "Беларуси", "Беларусь", "Беларусью", "Беларуси"],
    );
}

#[test]
fn country_kazakhstan() {
    check_both(
        Kind::Country,
        "Казахстан",
        [
            "Казахстан",
            "Казахстана",
            "Казахстану",
            "Казахстан",
            "Казахстаном",
            "Казахстане",
        ],
    );
}

#[test]
fn country_republic_belarus() {
    check_both(
        Kind::Country,
        "Республика Беларусь",
        [
            "Республика Беларусь",
            "Республики Беларусь",
            "Республике Беларусь",
            "Республику Беларусь",
            "Республикой Беларусь",
            "Республике Беларусь",
        ],
    );
}

#[test]
fn street_lesnaya() {
    check_both(
        Kind::Street,
        "ул. Лесная",
        [
            "ул. Лесная",
            "ул. Лесной",
            "ул. Лесной",
            "ул. Лесную",
            "ул. Лесной",
            "ул. Лесной",
        ],
    );
}

#[test]
fn street_pushkina() {
    for case in ALL_CASES {
        assert_eq!(
            inflect("ул. Пушкина", Kind::Street, case).as_deref(),
            Some("ул. Пушкина"),
            "street pushkina {case:?}"
        );
    }
}

#[test]
fn street_leninsky_prospekt() {
    check_both(
        Kind::Street,
        "Ленинский проспект",
        [
            "Ленинский проспект",
            "Ленинского проспекта",
            "Ленинскому проспекту",
            "Ленинский проспект",
            "Ленинским проспектом",
            "Ленинском проспекте",
        ],
    );
}

#[test]
fn unknown_returns_none() {
    assert_eq!(inflect("Xyz Абв", Kind::Person, Case::Gen), None);
    assert_eq!(inflect("12345", Kind::Person, Case::Gen), None);
    assert_eq!(inflect("Xyz Абв", Kind::Place, Case::Gen), None);
    assert_eq!(inflect("12345", Kind::Place, Case::Gen), None);
    assert_eq!(inflect("Xyz Абв", Kind::Country, Case::Gen), None);
    assert_eq!(inflect("12345", Kind::Country, Case::Gen), None);
    assert_eq!(inflect("Xyz Абв", Kind::Street, Case::Gen), None);
    assert_eq!(inflect("12345", Kind::Street, Case::Gen), None);
}

#[test]
fn gender_enum_is_copy_eq() {
    let g = Gender::Male;
    let g2 = g;
    assert_eq!(g, g2);
    assert_ne!(Gender::Male, Gender::Female);
    assert_eq!(Gender::Unknown, Gender::Unknown);
}