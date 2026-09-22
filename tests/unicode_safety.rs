use std::collections::HashMap;
use std::sync::Arc;

use detox_proxy::config::TrapPolicy;
use detox_proxy::detect::{Allowlist, DetectOptions, Detector, Dictionaries};
use detox_proxy::mask::{mask, unmask, MaskOptions};
use detox_proxy::registry::Registry;
use detox_proxy::types::{Entity, MaskMode};

fn detector() -> Detector {
    let yaml = std::fs::read_to_string("data/pii_types.yaml").expect("read pii_types.yaml");
    let reg = Arc::new(Registry::from_yaml(&yaml).expect("parse registry"));
    let dicts = Arc::new(Dictionaries::load_dir(std::path::Path::new("data/dict")).expect("load dicts"));
    let allowlist_text = std::fs::read_to_string("data/allowlist.yaml").expect("read allowlist");
    let allowlist = Allowlist::from_yaml(&allowlist_text).expect("parse allowlist");
    Detector::with_allowlist(reg, dicts, allowlist)
}

fn detect(det: &Detector, text: &str) -> Vec<Entity> {
    let opts = DetectOptions {
        enabled_types: None,
        min_confidence: 0.0,
        allow_substrings: &[],
        trap_policy: TrapPolicy::PreferMask,
    };
    det.detect(text, &opts)
}

fn registry() -> Registry {
    let yaml = std::fs::read_to_string("data/pii_types.yaml").expect("read pii_types.yaml");
    Registry::from_yaml(&yaml).expect("parse registry")
}

fn check_variant(det: &Detector, text: &str, reg: &Registry) {
    let entities = detect(det, text);
    for e in &entities {
        assert!(
            text.is_char_boundary(e.start),
            "start not on char boundary: {e:?} in {text:?}"
        );
        assert!(
            text.is_char_boundary(e.end),
            "end not on char boundary: {e:?} in {text:?}"
        );
        assert!(e.start <= e.end, "inverted span: {e:?} in {text:?}");
    }
    let overrides = HashMap::new();
    let opts = MaskOptions {
        default_mode: MaskMode::Token,
        overrides: &overrides,
        combination_rule: false,
    };
    let res = mask(text, &entities, reg, &opts);
    let restored = unmask(&res.text, &res.mappings);
    assert_eq!(restored, text, "round-trip failed for {text:?}");
}

fn replace_spaces(text: &str, repl: char) -> String {
    text.chars().map(|c| if c == ' ' { repl } else { c }).collect()
}

fn check_all_variants(det: &Detector, text: &str, reg: &Registry) {
    check_variant(det, text, reg);
    check_variant(det, &replace_spaces(text, '\u{00a0}'), reg);
    check_variant(det, &replace_spaces(text, '\u{202f}'), reg);
}

fn dataset_texts() -> Vec<String> {
    let mut paths = dataset_paths();
    paths.sort();

    let mut texts = Vec::new();
    for path in paths {
        let content = std::fs::read_to_string(&path).expect("read dataset");
        let file_texts = dataset_file_texts(&content);
        let step = (file_texts.len() / 15).max(1);
        texts.extend(file_texts.iter().step_by(step).take(15).cloned());
    }
    texts
}

/// Collects the `.jsonl` dataset paths from `tests/data` and `tests/data/holdout`.
fn dataset_paths() -> Vec<std::path::PathBuf> {
    let mut paths: Vec<std::path::PathBuf> = Vec::new();
    let root = match std::fs::read_dir("tests/data") {
        Ok(root) => root,
        Err(_) => {
            println!("skipping dataset scan: tests/data is not present");
            return Vec::new();
        }
    };
    collect_jsonl_paths(root, &mut paths);
    if let Ok(holdout) = std::fs::read_dir("tests/data/holdout") {
        collect_jsonl_paths(holdout, &mut paths);
    }
    paths
}

/// Appends the `.jsonl` file paths from a directory to `paths`.
fn collect_jsonl_paths(dir: std::fs::ReadDir, paths: &mut Vec<std::path::PathBuf>) {
    for entry in dir {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let path = entry.path();
        if path.extension().map(|e| e == "jsonl").unwrap_or(false) {
            paths.push(path);
        }
    }
}

/// Extracts the `text` fields (up to 4096 chars) from a jsonl dataset file.
fn dataset_file_texts(content: &str) -> Vec<String> {
    let mut file_texts: Vec<String> = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(line).expect("parse jsonl line");
        if let Some(t) = v.get("text").and_then(|t| t.as_str()) {
            if t.len() <= 4096 {
                file_texts.push(t.to_string());
            }
        }
    }
    file_texts
}

#[test]
fn datasets_no_panic_and_roundtrip() {
    let det = detector();
    let reg = registry();
    for (i, text) in dataset_texts().iter().enumerate() {
        check_variant(&det, text, &reg);
        check_variant(&det, &replace_spaces(text, '\u{00a0}'), &reg);
        if i < 5 {
            check_variant(&det, &replace_spaces(text, '\u{202f}'), &reg);
        }
    }
}

#[test]
fn manual_unicode_strings() {
    let cases = [
        "ул.\u{202f}Лесная, д.\u{00a0}17",
        "г.\u{2009}Москва, ул.\u{202f}Тверская",
        "Клиент\u{00a0}Иванов\u{00a0}Иван",
        "CVV\u{00a0}317",
        "«Иванов Иван» — клиент 😀",
        "тел.\u{202f}+7\u{202f}912\u{202f}345-67-89",
        "Москва,\u{00a0}ул. Лесная 5",
        "\u{202f}\u{202f}\u{202f}",
        "",
    ];
    let det = detector();
    let reg = registry();
    for text in cases {
        check_all_variants(&det, text, &reg);
    }
}

#[test]
fn nbsp_works_as_regular_space() {
    let det = detector();
    let entities = detect(&det, "ул.\u{00a0}Лесная, д.\u{00a0}17, кв.\u{00a0}42");
    assert!(
        entities.iter().any(|e| e.type_id == "address"),
        "address should be found: {entities:?}"
    );

    let entities = detect(&det, "ИНН\u{00a0}7707083893");
    assert!(
        entities.iter().any(|e| e.type_id == "inn"),
        "inn should be found: {entities:?}"
    );
}