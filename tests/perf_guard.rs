// Fails until T09 makes context checks linear in the number of entities.

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
#[ignore]
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
        for _ in 0..3 {
            let start = Instant::now();
            let entities = det.detect(text, opts);
            let _res = mask(text, &entities, reg, mask_opts);
            let elapsed = start.elapsed().as_millis();
            if elapsed < best {
                best = elapsed;
            }
        }
        best
    }

    let t40 = best_time(&det, &reg, &opts, &mask_opts, &"Клиент ИНН 7707083893. ".repeat(40));
    let t400 = best_time(&det, &reg, &opts, &mask_opts, &"Клиент ИНН 7707083893. ".repeat(400));
    let ratio = t400 as f64 / t40 as f64;

    assert!(
        ratio <= 20.0,
        "detect+mask scaling is superlinear: t40={t40} ms, t400={t400} ms, ratio={ratio:.1} (expected <= 20.0 for linear scaling)"
    );
}