use crate::{registry::{Registry, Validator}, types::Entity};
use std::collections::{HashMap, HashSet};

/// Named word lists (surnames, first names, patronymics, cities, public persons...). Lowercased.
pub struct Dictionaries {
    pub lists: HashMap<String, HashSet<String>>,
}
impl Dictionaries {
    pub fn empty() -> Self {
        Self { lists: HashMap::new() }
    }

    pub fn load_dir(dir: &std::path::Path) -> std::io::Result<Self> {
        let mut lists = HashMap::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map(|e| e == "txt").unwrap_or(false) {
                let name = path
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let content = std::fs::read_to_string(&path)?;
                let mut words = HashSet::new();
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    words.insert(line.to_lowercase());
                }
                lists.insert(name, words);
            }
        }
        Ok(Self { lists })
    }

    pub fn contains(&self, list: &str, word_lower: &str) -> bool {
        self.lists.get(list).map(|s| s.contains(word_lower)).unwrap_or(false)
    }
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
    pub fn new(registry: std::sync::Arc<Registry>, dicts: std::sync::Arc<Dictionaries>) -> Self {
        Self { registry, dicts }
    }

    /// Runs all enabled types, validates, scores, drops allow-listed and overlapping spans
    /// (longer / more confident wins). Result sorted by start. Case-insensitive.
    pub fn detect(&self, text: &str, opts: &DetectOptions<'_>) -> Vec<Entity> {
        let enabled: Option<HashSet<&str>> = opts
            .enabled_types
            .map(|ids| ids.iter().map(|s| s.as_str()).collect());

        let mut candidates: Vec<Entity> = Vec::new();

        for spec in self.registry.types() {
            if let Some(set) = &enabled {
                if !set.contains(spec.id.as_str()) {
                    continue;
                }
            }
            let patterns = self.registry.patterns(&spec.id);
            if patterns.is_empty() {
                continue;
            }
            for re in patterns {
                for m in re.find_iter(text) {
                    let start = m.start();
                    let end = m.end();
                    let span = &text[start..end];

                    let mut conf = 0.6f32;

                    let has_context = if spec.context_words.is_empty() {
                        false
                    } else {
                        let window = context_window_before(text, start, spec.context_window);
                        let window_lower = window.to_lowercase();
                        spec.context_words.iter().any(|w| window_lower.contains(w))
                    };

                    if spec.validator != Validator::None {
                        if validator_passes(spec.validator, span) {
                            conf += 0.3;
                        } else {
                            continue;
                        }
                    }

                    if has_context {
                        conf += 0.1;
                    }
                    if spec.context_required && !has_context {
                        continue;
                    }
                    conf = conf.min(1.0);

                    if conf < opts.min_confidence {
                        continue;
                    }

                    let span_lower = span.to_lowercase();
                    let allow_listed = opts
                        .allow_substrings
                        .iter()
                        .any(|a| a.to_lowercase().contains(&span_lower));
                    if allow_listed {
                        continue;
                    }

                    candidates.push(Entity { type_id: spec.id.clone(), start, end, confidence: conf });
                }
            }
        }

        resolve_overlaps(candidates)
    }
}

fn validator_passes(v: Validator, span: &str) -> bool {
    match v {
        Validator::None => true,
        Validator::Luhn => validators::luhn(span),
        Validator::Inn => validators::inn(span),
        Validator::Snils => validators::snils(span),
        Validator::Date => validators::date(span),
        Validator::Phone => validators::phone(span),
        Validator::Email => validators::email(span),
    }
}

/// Returns the slice of up to `window` chars immediately before byte offset `start`.
fn context_window_before(text: &str, start: usize, window: usize) -> &str {
    let prefix = &text[..start];
    let mut count = 0usize;
    let mut idx = 0usize;
    for (i, _) in prefix.char_indices().rev() {
        count += 1;
        if count >= window {
            idx = i;
            break;
        }
    }
    if count < window {
        prefix
    } else {
        &text[idx..start]
    }
}

/// Sorts by start; on overlap keeps the longer span, ties broken by higher confidence.
fn resolve_overlaps(mut candidates: Vec<Entity>) -> Vec<Entity> {
    candidates.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then_with(|| (b.end - b.start).cmp(&(a.end - a.start)))
            .then_with(|| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal))
    });
    let mut result: Vec<Entity> = Vec::with_capacity(candidates.len());
    for c in candidates {
        if let Some(last) = result.last_mut() {
            if c.start < last.end {
                let c_len = c.end - c.start;
                let l_len = last.end - last.start;
                let replace = if c_len > l_len {
                    true
                } else if c_len == l_len {
                    c.confidence > last.confidence
                } else {
                    false
                };
                if replace {
                    *last = c;
                }
                continue;
            }
        }
        result.push(c);
    }
    result
}

/// Validators are a fixed set selected by name from the registry.
pub mod validators {
    /// Standard Luhn check. Operates on digits only; non-digits are ignored.
    pub fn luhn(s: &str) -> bool {
        let digits: Vec<u32> = s.chars().filter(|c| c.is_ascii_digit()).map(|c| c.to_digit(10).unwrap()).collect();
        if digits.len() < 2 {
            return false;
        }
        let mut sum = 0u32;
        let mut double = false;
        for &d in digits.iter().rev() {
            let mut v = d;
            if double {
                v *= 2;
                if v > 9 {
                    v -= 9;
                }
            }
            sum += v;
            double = !double;
        }
        sum.is_multiple_of(10)
    }

    /// Russian INN: 10 or 12 digits with FNS control digits.
    pub fn inn(s: &str) -> bool {
        let digits: Vec<u32> = s.chars().filter(|c| c.is_ascii_digit()).map(|c| c.to_digit(10).unwrap()).collect();
        match digits.len() {
            10 => {
                let coeffs = [2, 4, 10, 3, 5, 9, 4, 6, 8];
                let sum: u32 = coeffs.iter().zip(&digits).map(|(&c, &d)| c * d).sum();
                let control = (sum % 11) % 10;
                control == digits[9]
            }
            12 => {
                let c1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8];
                let c2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8];
                let s1: u32 = c1.iter().zip(&digits).map(|(&c, &d)| c * d).sum();
                let s2: u32 = c2.iter().zip(&digits).map(|(&c, &d)| c * d).sum();
                let control1 = (s1 % 11) % 10;
                let control2 = (s2 % 11) % 10;
                control1 == digits[10] && control2 == digits[11]
            }
            _ => false,
        }
    }

    /// Russian SNILS: 11 digits, control sum of first 9 with weights 9..1.
    pub fn snils(s: &str) -> bool {
        let digits: Vec<u32> = s.chars().filter(|c| c.is_ascii_digit()).map(|c| c.to_digit(10).unwrap()).collect();
        if digits.len() != 11 {
            return false;
        }
        let sum: u32 = digits[..9].iter().zip((1..=9).rev()).map(|(&d, w)| d * w).sum();
        let control = if sum < 100 {
            sum
        } else if sum == 100 || sum == 101 {
            0
        } else {
            let m = sum % 101;
            if m == 100 { 0 } else { m }
        };
        let actual = digits[9] * 10 + digits[10];
        control == actual
    }

    /// Accepts dd.mm.yyyy, dd/mm/yyyy, yyyy-mm-dd, mm.dd.yyyy (ambiguous both ways), and textual Russian months.
    pub fn date(_s: &str) -> bool {
        todo!()
    }

    /// Phone: after removing non-digits, 11 digits starting with 7/8, or 10 digits starting with 9/4/8.
    pub fn phone(s: &str) -> bool {
        let digits: Vec<char> = s.chars().filter(|c| c.is_ascii_digit()).collect();
        match digits.len() {
            11 => matches!(digits[0], '7' | '8'),
            10 => matches!(digits[0], '9' | '4' | '8'),
            _ => false,
        }
    }

    /// Email: local part, '@', domain with at least one dot.
    pub fn email(s: &str) -> bool {
        let s = s.trim();
        if s.is_empty() || s.contains(char::is_whitespace) {
            return false;
        }
        let at = match s.rfind('@') {
            Some(i) => i,
            None => return false,
        };
        let local = &s[..at];
        let domain = &s[at + 1..];
        if local.is_empty() || domain.is_empty() {
            return false;
        }
        if !domain.contains('.') {
            return false;
        }
        if domain.starts_with('.') || domain.ends_with('.') {
            return false;
        }
        true
    }
}