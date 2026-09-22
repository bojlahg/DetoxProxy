use crate::{registry::Registry, types::Entity};
use std::collections::HashSet;

/// Named word lists (surnames, first names, patronymics, cities, public persons...). Lowercased.
pub struct Dictionaries {
    pub lists: std::collections::HashMap<String, HashSet<String>>,
}
impl Dictionaries {
    pub fn empty() -> Self { todo!() }
    pub fn load_dir(dir: &std::path::Path) -> std::io::Result<Self> { todo!() }
    pub fn contains(&self, list: &str, word_lower: &str) -> bool { todo!() }
}

pub struct DetectOptions<'a> {
    /// Only these type ids are detected; None = all registry types.
    pub enabled_types: Option<&'a [String]>,
    pub min_confidence: f32,
    /// Substrings that must never be reported (bank office addresses, service phones).
    pub allow_substrings: &'a [String],
}

pub struct Detector {
    registry: std::sync::Arc<Registry>,
    dicts: std::sync::Arc<Dictionaries>,
}

impl Detector {
    pub fn new(registry: std::sync::Arc<Registry>, dicts: std::sync::Arc<Dictionaries>) -> Self { todo!() }
    /// Runs all enabled types, validates, scores, drops allow-listed and overlapping spans
    /// (longer / more confident wins). Result sorted by start. Case-insensitive.
    pub fn detect(&self, text: &str, opts: &DetectOptions<'_>) -> Vec<Entity> { todo!() }
}

/// Validators are a fixed set selected by name from the registry.
pub mod validators {
    pub fn luhn(digits: &str) -> bool { todo!() }
    pub fn inn(digits: &str) -> bool { todo!() }
    pub fn snils(digits: &str) -> bool { todo!() }
    /// Accepts dd.mm.yyyy, dd/mm/yyyy, yyyy-mm-dd, mm.dd.yyyy (ambiguous both ways), and textual Russian months.
    pub fn date(s: &str) -> bool { todo!() }
    pub fn phone(s: &str) -> bool { todo!() }
    pub fn email(s: &str) -> bool { todo!() }
}