use pii_guard::registry::{Registry, RegistryError};

fn load() -> Registry {
    let yaml = std::fs::read_to_string("data/pii_types.yaml").expect("read pii_types.yaml");
    Registry::from_yaml(&yaml).expect("parse registry")
}

#[test]
fn from_yaml_loads_all_types() {
    let reg = load();
    assert!(reg.types().len() >= 18, "expected >= 18 types, got {}", reg.types().len());
}

#[test]
fn duplicate_id_is_rejected() {
    let yaml = r#"
types:
  - id: card_number
    name: Card
    token_label: CARD
    patterns: []
  - id: card_number
    name: Card again
    token_label: CARD
    patterns: []
"#;
    match Registry::from_yaml(yaml) {
        Err(RegistryError::Duplicate(id)) => assert_eq!(id, "card_number"),
        other => panic!("expected Duplicate, got {:?}", other.map(|_| ())),
    }
}

#[test]
fn broken_regex_reports_type_id() {
    let yaml = r#"
types:
  - id: phone
    name: Phone
    token_label: PHONE
    patterns: ["("]
"#;
    match Registry::from_yaml(yaml) {
        Err(RegistryError::Regex { type_id, .. }) => assert_eq!(type_id, "phone"),
        other => panic!("expected Regex error, got {:?}", other.map(|_| ())),
    }
}

#[test]
fn unknown_id_returns_empty_patterns() {
    let reg = load();
    assert!(reg.patterns("does_not_exist").is_empty());
}

#[test]
fn get_returns_spec() {
    let reg = load();
    let spec = reg.get("card_number").expect("card_number present");
    assert_eq!(spec.token_label, "CARD");
    assert!(!spec.patterns.is_empty());
}