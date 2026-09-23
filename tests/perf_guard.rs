use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use detox_proxy::config::TrapPolicy;
use detox_proxy::detect::{Allowlist, DetectOptions, Detector, Dictionaries};
use detox_proxy::mask::{mask, MaskOptions};
use detox_proxy::registry::Registry;
use detox_proxy::types::MaskMode;

fn detector() -> Detector {
    let yaml = std::fs::read_to_string("data/pii_types.yaml").expect("read pii_types.yaml");
    let reg = Arc::new(Registry::from_yaml(&yaml).expect("parse registry"));
    let dicts = Arc::new(Dictionaries::load_dir(std::path::Path::new("data/dict")).expect("load dicts"));
    let allowlist_text = std::fs::read_to_string("data/allowlist.yaml").expect("read allowlist");
    let allowlist = Allowlist::from_yaml(&allowlist_text).expect("parse allowlist");
    Detector::with_allowlist(reg, dicts, allowlist)
}

#[test]
fn dense_text_detect_and_mask_within_budget() {
    if cfg!(debug_assertions) {
        return;
    }

    let opts = DetectOptions {
        enabled_types: None,
        min_confidence: 0.0,
        allow_substrings: &[],
        trap_policy: TrapPolicy::PreferMask,
    };
    let overrides = HashMap::new();
    let mask_opts = MaskOptions {
        default_mode: MaskMode::Token,
        overrides: &overrides,
        combination_rule: false,
    };

    let det = detector();
    let reg = Arc::new(Registry::from_yaml(
        &std::fs::read_to_string("data/pii_types.yaml").expect("read pii_types.yaml"),
    ).expect("parse registry"));

    fn best_time(det: &Detector, reg: &Registry, opts: &DetectOptions<'_>, mask_opts: &MaskOptions<'_>, text: &str) -> u128 {
        let mut best = u128::MAX;
        for _ in 0..5 {
            let start = Instant::now();
            let entities = det.detect(text, opts);
            let _res = mask(text, &entities, reg, mask_opts);
            let elapsed = start.elapsed().as_micros();
            if elapsed < best {
                best = elapsed;
            }
        }
        best
    }

    let t400 = best_time(&det, &reg, &opts, &mask_opts, &"Клиент ИНН 7707083893. ".repeat(400));
    let t4000 = best_time(&det, &reg, &opts, &mask_opts, &"Клиент ИНН 7707083893. ".repeat(4000));

    assert!(
        t400 <= 25_000,
        "detect+mask exceeds the absolute budget: t400={t400} us (expected <= 25000 us)"
    );
    assert!(
        t4000 <= t400 * 15,
        "detect+mask scaling is superlinear: t400={t400} us, t4000={t4000} us, ratio={:.1} (expected <= 15.0 for linear scaling)",
        t4000 as f64 / t400 as f64
    );
}

#[test]
fn dense_capitalized_text_detect_and_mask_within_budget() {
    if cfg!(debug_assertions) {
        return;
    }

    let opts = DetectOptions {
        enabled_types: None,
        min_confidence: 0.0,
        allow_substrings: &[],
        trap_policy: TrapPolicy::PreferMask,
    };
    let overrides = HashMap::new();
    let mask_opts = MaskOptions {
        default_mode: MaskMode::Token,
        overrides: &overrides,
        combination_rule: false,
    };

    let det = detector();
    let reg = Arc::new(Registry::from_yaml(
        &std::fs::read_to_string("data/pii_types.yaml").expect("read pii_types.yaml"),
    ).expect("parse registry"));

    let text = "Встреча Отдела Продаж Прошла В Москве, Обсудили Новые Условия Кредита. ".repeat(10_000);

    let mut best = u128::MAX;
    for _ in 0..3 {
        let start = Instant::now();
        let entities = det.detect(&text, &opts);
        let _res = mask(&text, &entities, &reg, &mask_opts);
        let elapsed = start.elapsed().as_micros();
        if elapsed < best {
            best = elapsed;
        }
    }

    assert!(
        best <= 1_500_000,
        "detect+mask exceeds the dense-capitalized budget: best={best} us (expected <= 1500000 us)"
    );
}

#[test]
fn large_address_text() {
    if cfg!(debug_assertions) {
        return;
    }

    let opts = DetectOptions {
        enabled_types: None,
        min_confidence: 0.0,
        allow_substrings: &[],
        trap_policy: TrapPolicy::PreferMask,
    };

    let det = detector();

    let text = "Адрес доставки: г. Казань, ул. Баумана, д. 3, кв. 15, получатель Петрова Анна Сергеевна. "
        .repeat(4445);
    assert!(text.len() >= 400_000, "text too short: {} chars", text.len());

    let mut best = u128::MAX;
    for _ in 0..3 {
        let start = Instant::now();
        let _entities = det.detect(&text, &opts);
        let elapsed = start.elapsed().as_micros();
        if elapsed < best {
            best = elapsed;
        }
    }

    assert!(
        best <= 1_500_000,
        "detect exceeds the large-address budget: best={best} us (expected <= 1500000 us)"
    );
}